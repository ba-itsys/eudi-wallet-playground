# Digital Credentials API (DC API) Integration

This document explains how the OID4VP Keycloak extension integrates with the W3C Digital Credentials API for verifiable credential presentation.

## Overview

The Digital Credentials API (DC API) is a W3C browser API that enables websites to request and receive digital credentials from wallets. This extension uses DC API as one of several response modes for OID4VP (OpenID for Verifiable Presentations).

## Integration Points

There are two main integration points:

1. **Invocation** (Browser → Wallet): JavaScript code calls `navigator.credentials.get()` with digital credential parameters
2. **Response Handling** (Keycloak): Server-side code processes the wallet's response

---

## 1. DC API Invocation (Browser-Side)

**File:** `src/main/resources/theme/oid4vp/login/resources/js/oid4vp-dc-api.js`

The browser invokes the DC API using `navigator.credentials.get()` with the `digital` property. There are two protocol variants:

### Signed Request (Recommended)

When a signed JWT request object is available, the browser uses the `openid4vp-v1-signed` protocol:

```javascript
const credential = await navigator.credentials.get({
  digital: {
    requests: [{
      protocol: "openid4vp-v1-signed",
      data: { request: requestObject }  // requestObject is a JWT string
    }]
  }
});
```

The `requestObject` is a JWT signed by the verifier containing claims like:
- `client_id`: Verifier identifier
- `nonce`: Challenge for replay protection
- `response_mode`: `dc_api.jwt` (encrypted response)
- `response_uri`: Where wallet should conceptually send response
- `dcql_query`: Credential query in DCQL format
- `client_metadata`: Contains encryption keys for response

### Unsigned Request (Fallback)

When no signed request is available, the browser uses `openid4vp-v1-unsigned`:

```javascript
const credential = await navigator.credentials.get({
  digital: {
    requests: [{
      protocol: "openid4vp-v1-unsigned",
      data: {
        response_type: "vp_token",
        response_mode: "dc_api",
        nonce: "...",
        client_metadata: {},
        dcql_query: { ... }
      }
    }]
  }
});
```

### Response Handling in Browser

The browser extracts the response and submits it via form POST:

```javascript
const data = credential.data;

// Handle encrypted response (dc_api.jwt mode)
if (typeof data.response === "string") {
  responseInput.value = data.response;  // JWE-encrypted response
  form.submit();
  return;
}

// Handle unencrypted response
const vpToken = extractVpToken(credential);
vpTokenInput.value = vpToken;
form.submit();
```

The form POSTs to Keycloak's action URL with:
- `state`: Session state
- `vp_token`: The credential presentation (if unencrypted)
- `response`: JWE-encrypted response (if encrypted)
- `error` / `error_description`: Wallet error (if any)

---

## 2. Response Handling (Keycloak Server-Side)

**Files:**
- `Oid4vpIdentityProvider.java` (identity provider, handles login flow)
- `Oid4vpVerifierService.java` (verification logic)

### Request Object Generation

**File:** `Oid4vpDcApiRequestObjectService.java`

Keycloak generates a signed JWT request object with the following claims:

```java
claims.put("jti", UUID.randomUUID().toString());
claims.put("iat", issuedAt);
claims.put("exp", expiresAt);
claims.put("iss", effectiveClientId);
claims.put("expected_origins", List.of(origin));
claims.put("client_id", effectiveClientId);
claims.put("response_type", "vp_token");
claims.put("response_mode", "dc_api.jwt");
claims.put("response_uri", origin + "/");        // Important for mDoc SessionTranscript
claims.put("nonce", nonce);
claims.put("state", state);
claims.put("client_metadata", buildEncryptedResponseClientMetadata(responseEncryptionKey));
claims.put("dcql_query", parseJsonClaim(dcqlQuery));
```

The `response_uri` is set to `origin + "/"` (e.g., `https://keycloak.example.com/`).

### Processing the Response

When the form is submitted back to Keycloak:

```java
// Extract form parameters
String state = form.getFirst("state");
String vpToken = form.getFirst("vp_token");
String encryptedResponse = form.getFirst("response");

// Validate state matches session
if (!expectedState.equals(state)) {
    context.failure(AuthenticationFlowError.INVALID_CLIENT_SESSION);
    return;
}

// Decrypt encrypted response if present
if (encryptedResponse != null && !encryptedResponse.isBlank()) {
    String key = authSession.getAuthNote(Oid4vpSessionNotes.RESPONSE_ENCRYPTION_PRIVATE_JWK);
    var node = dcApiRequestObjectService.decryptEncryptedResponse(encryptedResponse, key);
    vpToken = node.get("vp_token").asText();
}

// Verify the presentation
Oid4vpVerifierService.VerifiedPresentation verified = verifierService.verify(
    vpToken,
    config.trustListId(),
    expectedClientId,    // Audience check
    expectedNonce,       // Nonce check
    responseUri,         // For mDoc SessionTranscript
    jwkThumbprint        // For mDoc DeviceAuth
);
```

---

## 3. The `response_uri` Problem with mDoc Credentials

### The Problem

mDoc credentials (ISO 18013-5) use a **SessionTranscript** to cryptographically bind the presentation to the specific request context. The SessionTranscript includes:

```
OID4VPHandover = SHA-256(
  CBOR_Array[
    client_id,           // e.g., "https://keycloak.example.com/realms/test/"
    nonce,               // Challenge
    jwk_thumbprint,      // Encryption key thumbprint (or null)
    response_uri         // Critical: Must match exactly!
  ]
)

SessionTranscript = [null, null, ["OpenID4VPHandover", OID4VPHandover]]
```

The wallet computes this hash when creating the presentation, and the verifier must compute the **exact same hash** to verify it.

### The Issue with Browser Extensions / Bridges

When using a Chrome extension to bridge DC API calls to a web wallet, the `response_uri` can get rewritten:

1. **Keycloak generates request** with `response_uri: "https://keycloak.example.com/"`
2. **Chrome extension intercepts** `navigator.credentials.get()` call
3. **Extension opens wallet** in new tab with URL params including a **different** response_uri (e.g., the extension's redirect URL)
4. **Wallet builds SessionTranscript** using the rewritten response_uri
5. **Keycloak verifies** using the original response_uri from form action URL
6. **Hash mismatch** → "Credential signature not trusted" error

### The Standards-Conformant Solution

Per the OID4VP specification, the authoritative `response_uri` is the one in the **signed JWT request object**, not any URL parameter. The solution:

1. **Include `response_uri` in signed JWT** (already done by Keycloak):
   ```java
   claims.put("response_uri", origin + "/");
   ```

2. **Store the DC API response_uri in session** for verification:
   ```java
   // Use the response_uri from the DC API request object if available
   if (requestObject != null && requestObject.responseUri() != null) {
       responseUri = requestObject.responseUri();
   }
   authSession.setAuthNote(Oid4vpSessionNotes.RESPONSE_URI, responseUri);
   ```

3. **Wallet extracts response_uri from JWT** (not URL params):
   ```java
   // In wallet: Parse JWT and extract response_uri
   if (jwtClaims.has("response_uri")) {
       sessionTranscriptResponseUri = jwtClaims.get("response_uri").asText();
   }
   ```

4. **Use separate URIs for different purposes**:
   - `response_uri` from JWT → Used in SessionTranscript computation
   - `response_uri` from URL params → Used for actual form submission (may differ due to bridge)

This approach is standards-conformant because:
- The JWT is signed by the verifier, so it cannot be tampered with
- The wallet and verifier both use the same source (JWT) for SessionTranscript
- Bridge extensions can rewrite URL params without breaking verification

---

## 4. Will This Work with Real Wallets?

### Native DC API Wallets (No Extension)

**Yes, this implementation is fully compatible with native DC API wallets.**

When a browser has native DC API support with a native wallet:

1. `navigator.credentials.get()` is called with the exact same parameters
2. Native wallet receives the signed JWT request object
3. Wallet extracts `response_uri` from JWT for SessionTranscript
4. Wallet returns response via the DC API callback
5. Browser receives response and submits form to Keycloak
6. Keycloak verifies using the same `response_uri` from the JWT

There is **no URL rewriting** because there's no intermediary extension.

### Supported Response Modes

| Mode | Description | Encryption | Real Wallet Support |
|------|-------------|------------|---------------------|
| `dc_api` | Unsigned, unencrypted | No | Yes |
| `dc_api.jwt` | Signed request, encrypted response | Yes (JWE) | Yes |

### SD-JWT vs mDoc Credentials

| Credential Type | SessionTranscript | Real Wallet Support |
|-----------------|-------------------|---------------------|
| SD-JWT | Not used (simpler audience/nonce check) | Yes |
| mDoc | Uses SessionTranscript with response_uri | Yes (with JWT-based response_uri) |

---

## 5. Code Locations Summary

### Browser-Side (DC API Invocation)

| File | Purpose |
|------|---------|
| `oid4vp-dc-api.js` | Calls `navigator.credentials.get()` and handles response |
| `login-oid4vp.ftl` | FreeMarker template with form and data attributes |
| `register-oid4vp.ftl` | Registration variant of the template |

### Server-Side (Request Generation)

| File | Purpose |
|------|---------|
| `Oid4vpDcApiRequestObjectService.java` | Builds signed JWT request object |
| `Oid4vpConfig.java` | Configuration (DCQL query, signing key, etc.) |

### Server-Side (Response Handling)

| File | Purpose |
|------|---------|
| `Oid4vpIdentityProvider.java` | Identity provider that handles login and response processing |
| `Oid4vpVerifierService.java` | Routes to SD-JWT or mDoc verifier |
| `SdJwtVerifier.java` | Verifies SD-JWT presentations |
| `MdocVerifier.java` | Verifies mDoc presentations (includes SessionTranscript) |

### Shared Components

| File | Purpose |
|------|---------|
| `MdocDeviceResponseBuilder.java` | Builds mDoc DeviceResponse with SessionTranscript |
| `Oid4vpSessionNotes.java` | Session note keys (state, nonce, response_uri, etc.) |

---

## 6. Sequence Diagram

```
┌─────────┐      ┌─────────┐      ┌──────────┐      ┌────────┐
│ Browser │      │Keycloak │      │  Wallet  │      │  User  │
└────┬────┘      └────┬────┘      └────┬─────┘      └───┬────┘
     │                │                │                │
     │  GET /login    │                │                │
     │───────────────>│                │                │
     │                │                │                │
     │  HTML + JWT    │                │                │
     │  request obj   │                │                │
     │<───────────────│                │                │
     │                │                │                │
     │  navigator.credentials.get()    │                │
     │─────────────────────────────────>│               │
     │                │                │                │
     │                │                │  Show consent  │
     │                │                │───────────────>│
     │                │                │                │
     │                │                │  Approve       │
     │                │                │<───────────────│
     │                │                │                │
     │  Credential    │                │                │
     │  (encrypted)   │                │                │
     │<─────────────────────────────────│               │
     │                │                │                │
     │  POST response │                │                │
     │  to form action│                │                │
     │───────────────>│                │                │
     │                │                │                │
     │                │ Decrypt +      │                │
     │                │ Verify         │                │
     │                │ (using JWT     │                │
     │                │  response_uri) │                │
     │                │                │                │
     │  Login success │                │                │
     │<───────────────│                │                │
     │                │                │                │
```

---

## 7. Testing

The E2E test suite includes DC API flow tests:

```java
// In KeycloakOid4vpE2eIT.java
@Test
void mdocRegistrationAndLoginFlow() {
    // Tests mDoc credential with DC API, including SessionTranscript verification
}

@Test
void dcApiSdJwtLoginFlow() {
    // Tests SD-JWT credential with DC API encrypted response
}
```

The mock wallet (`Oid4vpTestDcApiMockWalletServer.java`) simulates a real wallet, including:
- Parsing signed JWT request objects
- Extracting `response_uri` from JWT (not URL params)
- Building mDoc DeviceResponse with correct SessionTranscript
- Encrypting responses with JWE

---

## 8. References

- [W3C Digital Credentials API](https://wicg.github.io/digital-credentials/)
- [OpenID for Verifiable Presentations (OID4VP)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [OID4VP Appendix A: DC API Integration](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-A)
- [ISO 18013-5: mDL Standard](https://www.iso.org/standard/69084.html)
- [SD-JWT Specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)
