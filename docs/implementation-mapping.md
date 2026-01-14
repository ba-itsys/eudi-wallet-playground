# Implementation Mapping: Concepts to Code

This document maps the abstract concepts from the SD-JWT and mDoc documentation to their concrete implementations in this repository.

## Table of Contents

1. [Repository Structure](#repository-structure)
2. [Credential Issuance](#credential-issuance)
3. [Credential Presentation](#credential-presentation)
4. [Credential Verification](#credential-verification)
5. [Trust Management](#trust-management)
6. [Client ID Schemes](#client-id-schemes)
7. [DC API Integration](#dc-api-integration)
8. [Response Encryption](#response-encryption)
9. [Holder Binding](#holder-binding)
10. [Selective Disclosure](#selective-disclosure)

---

## Repository Structure

| Module | Purpose | Key Classes |
|--------|---------|-------------|
| `sdjwt-lib` | SD-JWT parsing, building, verification | SdJwtParser, SdJwtVerifier, SdJwtCredentialBuilder |
| `mdoc-lib` | mDoc parsing, building, verification | MdocParser, MdocVerifier, MdocCredentialBuilder, MdocDeviceResponseBuilder |
| `keycloak-oid4vp` | Keycloak OID4VP Identity Provider | Oid4vpIdentityProvider, Oid4vpVerifierService |
| `wallet` | Demo wallet application | Oid4vpController, OidcClient, PresentationService |
| `mock-issuer` | Mock credential issuer | MockIssuerController |
| `demo-app` | Integration tests | WalletIntegrationTest |
| `chrome-extension` | DC API bridge for web wallet | background.js, wallet-content-script.js |

---

## Credential Issuance

### OID4VCI Flow

| Concept | Implementation | File |
|---------|----------------|------|
| Credential Offer parsing | `OidcClient.parseCredentialOffer()` | `wallet/.../issuance/oidc/OidcClient.java` |
| Issuer metadata discovery | `OidcClient.fetchIssuerMetadata()` | `wallet/.../issuance/oidc/OidcClient.java` |
| Token request (pre-authorized) | `OidcClient.exchangePreAuthorizedCode()` | `wallet/.../issuance/oidc/OidcClient.java` |
| Proof of possession JWT | `OidcClient.createProofJwt()` | `wallet/.../issuance/oidc/OidcClient.java` |
| Credential request | `OidcClient.requestCredential()` | `wallet/.../issuance/oidc/OidcClient.java` |

### SD-JWT Building (Issuer Side)

| Concept | Implementation | File |
|---------|----------------|------|
| Build SD-JWT with disclosures | `SdJwtCredentialBuilder.build()` | `sdjwt-lib/.../SdJwtCredentialBuilder.java` |
| Compute disclosure digests | `SdJwtUtils.computeDigest()` | `sdjwt-lib/.../SdJwtUtils.java` |
| Add cnf claim (holder binding) | `SdJwtCredentialBuilder.build()` (cnf parameter) | `sdjwt-lib/.../SdJwtCredentialBuilder.java` |

### mDoc Building (Issuer Side)

| Concept | Implementation | File |
|---------|----------------|------|
| Build IssuerSigned structure | `MdocCredentialBuilder.build()` | `mdoc-lib/.../MdocCredentialBuilder.java` |
| Create IssuerSignedItems with digests | `MdocCredentialBuilder.buildIssuerSigned()` | `mdoc-lib/.../MdocCredentialBuilder.java` |
| Build MSO (Mobile Security Object) | `MdocCredentialBuilder.buildMso()` | `mdoc-lib/.../MdocCredentialBuilder.java` |
| Sign with COSE Sign1 | `MdocCredentialBuilder.signMso()` | `mdoc-lib/.../MdocCredentialBuilder.java` |
| Add deviceKeyInfo (holder binding) | `MdocCredentialBuilder.buildDeviceKeyInfo()` | `mdoc-lib/.../MdocCredentialBuilder.java` |

---

## Credential Presentation

### OID4VP Flow (Wallet Side)

| Concept | Implementation | File |
|---------|----------------|------|
| Parse authorization request | `Oid4vpController.getAuthRequest()` | `wallet/.../oid4vp/Oid4vpController.java` |
| Parse DCQL query | `DcqlParser.parse()` | `wallet/.../oid4vp/DcqlParser.java` |
| Build vp_token | `Oid4vpController.buildVpToken()` | `wallet/.../oid4vp/Oid4vpController.java` |
| Submit response (direct_post) | `Oid4vpController.submitResponse()` | `wallet/.../oid4vp/Oid4vpController.java` |

### SD-JWT Presentation

| Concept | Implementation | File |
|---------|----------------|------|
| Create KB-JWT | `SdJwtKbJwtBuilder.build()` | `sdjwt-lib/.../SdJwtKbJwtBuilder.java` |
| Compute sd_hash | `SdJwtUtils.computeSdHash()` | `sdjwt-lib/.../SdJwtUtils.java` |
| Selective disclosure | `SdJwtSelectiveDiscloser.filter()` | `sdjwt-lib/.../SdJwtSelectiveDiscloser.java` |
| Assemble presentation | `PresentationService.buildSdJwtPresentation()` | `wallet/.../oid4vp/PresentationService.java` |

### mDoc Presentation

| Concept | Implementation | File |
|---------|----------------|------|
| Build DeviceResponse | `MdocDeviceResponseBuilder.buildDeviceResponse()` | `mdoc-lib/.../MdocDeviceResponseBuilder.java` |
| Compute SessionTranscript | `MdocDeviceResponseBuilder.buildSessionTranscript()` | `mdoc-lib/.../MdocDeviceResponseBuilder.java` |
| Sign DeviceAuth | `MdocDeviceResponseBuilder.signDeviceAuth()` | `mdoc-lib/.../MdocDeviceResponseBuilder.java` |
| Selective disclosure | `MdocSelectiveDiscloser.filter()` | `mdoc-lib/.../MdocSelectiveDiscloser.java` |

---

## Credential Verification

### OID4VP Flow (Verifier Side)

| Concept | Implementation | File |
|---------|----------------|------|
| Generate authorization request | `Oid4vpVerifierService.createAuthorizationRequest()` | `keycloak-oid4vp/.../Oid4vpVerifierService.java` |
| Process response | `Oid4vpVerifierService.processResponse()` | `keycloak-oid4vp/.../Oid4vpVerifierService.java` |
| Verify vp_token | `PresentationVerificationService.verify()` | `verifier/.../PresentationVerificationService.java` |
| Decrypt JWE response | `PresentationVerificationService.decrypt()` | `verifier/.../PresentationVerificationService.java` |

### SD-JWT Verification

| Concept | Implementation | File |
|---------|----------------|------|
| Parse SD-JWT | `SdJwtParser.split()` | `sdjwt-lib/.../SdJwtParser.java` |
| Verify issuer signature | `SdJwtVerifier.verifySignature()` | `sdjwt-lib/.../SdJwtVerifier.java` |
| Verify disclosure digests | `SdJwtUtils.verifyDisclosures()` | `sdjwt-lib/.../SdJwtUtils.java` |
| Verify KB-JWT | `SdJwtVerifier.verifyHolderBinding()` | `sdjwt-lib/.../SdJwtVerifier.java` |
| Extract claims | `SdJwtUtils.extractDisclosedClaims()` | `sdjwt-lib/.../SdJwtUtils.java` |

### mDoc Verification

| Concept | Implementation | File |
|---------|----------------|------|
| Decode DeviceResponse | `MdocVerifier.decodeToken()` | `mdoc-lib/.../MdocVerifier.java` |
| Verify issuerAuth signature | `MdocVerifier.verifySignature()` | `mdoc-lib/.../MdocVerifier.java` |
| Verify MSO digests | `MdocVerifier.verifyDigests()` | `mdoc-lib/.../MdocVerifier.java` |
| Verify DeviceAuth | `MdocVerifier.verifyDeviceAuth()` | `mdoc-lib/.../MdocVerifier.java` |
| Rebuild SessionTranscript | `MdocVerifier.buildSessionTranscript()` | `mdoc-lib/.../MdocVerifier.java` |
| Extract claims | `MdocVerifier.extractClaims()` | `mdoc-lib/.../MdocVerifier.java` |

---

## Trust Management

| Concept | Implementation | File |
|---------|----------------|------|
| Trust list interface | `TrustedIssuerResolver` (interface) | `app-common/.../TrustedIssuerResolver.java` |
| Trust list service (Keycloak) | `Oid4vpTrustListService` | `keycloak-oid4vp/.../Oid4vpTrustListService.java` |
| Trust list service (Verifier) | `TrustListService` | `verifier/.../TrustListService.java` |
| X.509 chain validation | `TrustedIssuerResolver.verify()` | `app-common/.../TrustedIssuerResolver.java` |
| x5chain fallback | `TrustedIssuerResolver.allowIssuerAuthX5ChainFallback()` | `app-common/.../TrustedIssuerResolver.java` |

---

## Client ID Schemes

| Scheme | Verification Implementation | File |
|--------|----------------------------|------|
| Pre-registered | Direct client_id match | `keycloak-oid4vp/.../Oid4vpVerifierService.java` |
| origin: (DC API) | Browser provides origin | `chrome-extension/oid4vp-wallet-bridge/wallet-content-script.js` |
| x509_san_dns | `verifyX509SanDns()` | `verifier/.../RequestObjectVerifier.java` |
| x509_san_uri | `verifyX509SanUri()` | `verifier/.../RequestObjectVerifier.java` |
| x509_hash | `verifyX509Hash()` (compute SHA-256 of cert) | `verifier/.../RequestObjectVerifier.java` |
| verifier_attestation | `verifyVerifierAttestation()` | `verifier/.../RequestObjectVerifier.java` |

---

## DC API Integration

### Browser Extension (DC API Bridge)

| Component | Purpose | File |
|-----------|---------|------|
| Background script | Handle DC API requests, manage wallet connection | `chrome-extension/oid4vp-wallet-bridge/background.js` |
| Content script (wallet) | Inject into wallet page, handle form interception | `chrome-extension/oid4vp-wallet-bridge/wallet-content-script.js` |
| Content script (verifier) | Intercept navigator.credentials.get() | `chrome-extension/oid4vp-wallet-bridge/content-script.js` |

### SessionTranscript for DC API

| Parameter | Wallet Handling | File |
|-----------|-----------------|------|
| client_id | From DC API request (origin-based) | `wallet/.../Oid4vpController.java:buildVpToken()` |
| nonce | From DC API request | `wallet/.../Oid4vpController.java:buildVpToken()` |
| response_uri | Derived as origin (for DC API mode) | `wallet/.../Oid4vpController.java:deriveOriginWithTrailingSlash()` |
| jwk_thumbprint | From client_metadata.jwks (if encrypted) | `wallet/.../Oid4vpController.java:selectResponseEncryptionJwk()` |

```java
// DC API mode detection
boolean isDcApiMode = responseMode != null && responseMode.toLowerCase().startsWith("dc_api");

// For DC API: use origin of response_uri
// For regular OID4VP: use full response_uri
String sessionTranscriptResponseUri = isDcApiMode
    ? deriveOriginWithTrailingSlash(responseUri)
    : responseUri;
```

---

## Response Encryption

| Concept | Implementation | File |
|---------|----------------|------|
| Detect encrypted mode | Check for `.jwt` suffix in response_mode | `wallet/.../Oid4vpController.java` |
| Select encryption key | `selectResponseEncryptionJwk()` | `wallet/.../Oid4vpController.java` |
| Encrypt response (wallet) | `JweUtils.encrypt()` | `wallet/.../util/JweUtils.java` |
| Decrypt response (verifier) | `PresentationVerificationService.decrypt()` | `verifier/.../PresentationVerificationService.java` |
| JWK thumbprint for SessionTranscript | `jwk.computeThumbprint()` | `wallet/.../Oid4vpController.java` |

**Response mode detection:**
```java
// Both direct_post.jwt and dc_api.jwt require encryption
boolean encryptedResponse = responseMode != null
    && responseMode.toLowerCase().endsWith(".jwt");
```

---

## Holder Binding

### SD-JWT Holder Binding

| Step | Implementation | File |
|------|----------------|------|
| **Issuance:** Embed holder key | `cnf.jwk` in credential payload | `sdjwt-lib/.../SdJwtCredentialBuilder.java` |
| **Presentation:** Create KB-JWT | `SdJwtKbJwtBuilder.build()` | `sdjwt-lib/.../SdJwtKbJwtBuilder.java` |
| **Verification:** Verify KB-JWT | `SdJwtVerifier.verifyHolderBinding()` | `sdjwt-lib/.../SdJwtVerifier.java` |

### mDoc Holder Binding

| Step | Implementation | File |
|------|----------------|------|
| **Issuance:** Embed device key | `deviceKeyInfo.deviceKey` in MSO | `mdoc-lib/.../MdocCredentialBuilder.java` |
| **Presentation:** Build SessionTranscript | `buildSessionTranscript()` | `mdoc-lib/.../MdocDeviceResponseBuilder.java` |
| **Presentation:** Sign DeviceAuth | `signDeviceAuth()` | `mdoc-lib/.../MdocDeviceResponseBuilder.java` |
| **Verification:** Rebuild SessionTranscript | `buildSessionTranscript()` | `mdoc-lib/.../MdocVerifier.java` |
| **Verification:** Verify DeviceAuth | `verifyDeviceAuth()` | `mdoc-lib/.../MdocVerifier.java` |

---

## Selective Disclosure

### SD-JWT Selective Disclosure

```java
// Filter disclosures based on requested claims
SdJwtSelectiveDiscloser discloser = new SdJwtSelectiveDiscloser();
String filtered = discloser.filter(sdJwt, requestedClaims);
```

| Step | Implementation | File |
|------|----------------|------|
| Parse disclosures | `SdJwtParser.split()` | `sdjwt-lib/.../SdJwtParser.java` |
| Decode disclosure | `SdJwtUtils.decodeDisclosure()` | `sdjwt-lib/.../SdJwtUtils.java` |
| Filter by claims | `SdJwtSelectiveDiscloser.filter()` | `sdjwt-lib/.../SdJwtSelectiveDiscloser.java` |

### mDoc Selective Disclosure

```java
// Filter IssuerSignedItems based on requested claims
MdocSelectiveDiscloser discloser = new MdocSelectiveDiscloser();
String filtered = discloser.filter(mdocToken, requestedClaims);
```

| Step | Implementation | File |
|------|----------------|------|
| Decode nameSpaces | `MdocParser.extractNameSpaces()` | `mdoc-lib/.../MdocParser.java` |
| Decode IssuerSignedItem | `MdocSelectiveDiscloser.decodeIssuerItem()` | `mdoc-lib/.../MdocSelectiveDiscloser.java` |
| Filter by claims | `MdocSelectiveDiscloser.filter()` | `mdoc-lib/.../MdocSelectiveDiscloser.java` |

---

## Quick Reference: Key Code Locations

### Wallet Presentation Flow

```
wallet/src/main/java/de/arbeitsagentur/keycloak/wallet/demo/oid4vp/
├── Oid4vpController.java      # Main OID4VP controller
├── PresentationService.java   # Build presentations
├── DcqlParser.java            # Parse DCQL queries
└── ...
```

### Keycloak OID4VP Identity Provider Flow

```
keycloak-oid4vp/src/main/java/de/arbeitsagentur/keycloak/oid4vp/
├── Oid4vpVerifierService.java           # SD-JWT/mDoc verification
├── Oid4vpTrustListService.java          # Trust list management
├── Oid4vpDcApiRequestObjectService.java # DC API request building
├── Oid4vpRedirectFlowService.java       # Redirect flow orchestration
└── idp/
    ├── Oid4vpIdentityProvider.java      # Main IdP implementation (includes endpoint)
    ├── Oid4vpIdentityProviderFactory.java
    ├── Oid4vpIdentityProviderConfig.java
    ├── DcqlQueryBuilder.java            # DCQL query generation from mappers
    └── mapper/
        ├── Oid4vpClaimToUserAttributeMapper.java  # Claim-to-user-attribute mapping
        ├── Oid4vpClaimToUserSessionMapper.java    # Claim-to-session-note mapping
        └── Oid4vpMapperUtils.java                 # Shared mapper utilities

verifier/src/main/java/.../verifier/
├── PresentationVerificationService.java  # Unified verification
└── ...
```

**Identity Provider Features:**
- Uses federated identity for O(1) user lookup
- Composite lookup key: `hash(issuer + credentialType + subject)`
- Supports multiple credentials per user
- First broker login flow for account creation/linking

### Credential Libraries

```
sdjwt-lib/src/main/java/.../sdjwt/
├── SdJwtParser.java              # Parse SD-JWT
├── SdJwtVerifier.java            # Verify SD-JWT
├── SdJwtCredentialBuilder.java   # Build SD-JWT (issuer)
├── SdJwtKbJwtBuilder.java        # Build KB-JWT (wallet)
├── SdJwtSelectiveDiscloser.java  # Selective disclosure
└── SdJwtUtils.java               # Utility functions

mdoc-lib/src/main/java/.../mdoc/
├── MdocParser.java               # Parse mDoc
├── MdocVerifier.java             # Verify mDoc
├── MdocCredentialBuilder.java    # Build IssuerSigned (issuer)
├── MdocDeviceResponseBuilder.java # Build DeviceResponse (wallet)
└── MdocSelectiveDiscloser.java   # Selective disclosure

app-common/src/main/java/.../common/credential/
└── TrustedIssuerResolver.java    # Trust interface
```

---

## Common Debugging Patterns

### SessionTranscript Mismatch (mDoc)

When you see "Credential signature not trusted" or "SessionTranscript mismatch":

1. **Enable debug logging** in both wallet and verifier
2. **Compare the four inputs:**
   - client_id
   - nonce
   - response_uri (or derived origin for DC API)
   - jwk_thumbprint (null or computed from encryption key)

3. **Check response mode detection:**
```java
// Wallet: wallet/.../Oid4vpController.java
boolean encryptedResponse = responseMode.toLowerCase().endsWith(".jwt");
boolean isDcApiMode = responseMode.toLowerCase().startsWith("dc_api");

// Verifier: verifier/.../PresentationVerificationService.java
// Must use same logic for jwk_thumbprint inclusion
```

### Disclosure Verification Failed (SD-JWT)

1. Check that disclosure strings are not modified
2. Verify SHA-256 digest computation matches `_sd` array
3. Ensure disclosures are properly base64url encoded

### DeviceAuth Signature Invalid (mDoc)

1. Verify device key in MSO matches signing key
2. Check SessionTranscript is computed identically
3. Ensure CBOR encoding is consistent (tag 24 handling)
