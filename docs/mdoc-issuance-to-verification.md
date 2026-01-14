# mDoc: Complete Flow from Issuance to Verification

This document provides a comprehensive technical reference for mDoc (mobile document) credentials based on ISO 18013-5, covering the complete lifecycle from issuance through storage to presentation and verification.

## Table of Contents

1. [Overview](#overview)
2. [Credential Structure](#credential-structure)
3. [Issuance Flow (OID4VCI)](#issuance-flow-oid4vci)
4. [Wallet Storage](#wallet-storage)
5. [Presentation Flow (OID4VP)](#presentation-flow-oid4vp)
6. [DeviceResponse Structure](#deviceresponse-structure)
7. [SessionTranscript Computation](#sessiontranscript-computation)
8. [DeviceAuth Signature](#deviceauth-signature)
9. [Verification Process](#verification-process)
10. [Trust Mechanisms](#trust-mechanisms)
11. [Client ID Schemes](#client-id-schemes)
12. [DC API Integration](#dc-api-integration)
13. [Response Modes](#response-modes)
14. [Selective Disclosure](#selective-disclosure)
15. [Troubleshooting](#troubleshooting)
16. [Specification References](#specification-references)

---

## Overview

mDoc (mobile document) is a credential format defined in ISO 18013-5 (mobile Driving License) that uses CBOR (Concise Binary Object Representation) encoding and COSE (CBOR Object Signing and Encryption) for signatures.

### Key Properties

| Property | Description |
|----------|-------------|
| Format identifier | `mso_mdoc` |
| Base format | CBOR (RFC 8949) |
| Signature format | COSE Sign1 (RFC 9052) |
| Selective disclosure | Native per-claim disclosure |
| Holder binding | Via deviceKey and DeviceAuth signature |
| Hash algorithm | SHA-256 |
| Signature algorithms | ES256 (ECDSA P-256), ES384, etc. |

### Component Overview

```
+------------------------------------------------------------------+
|                        mDoc Credential                            |
+------------------------------------------------------------------+
|  IssuerSigned                                                     |
|  +-- nameSpaces                                                   |
|  |   +-- "org.iso.18013.5.1" (namespace)                         |
|  |       +-- IssuerSignedItem[] (tagged CBOR arrays)             |
|  |           +-- digestID, random, elementIdentifier, elementValue|
|  +-- issuerAuth (COSE Sign1)                                      |
|      +-- protected header: {alg, kid, x5chain}                   |
|      +-- payload: MSO (Mobile Security Object)                    |
|          +-- version, digestAlgorithm, valueDigests               |
|          +-- docType, validityInfo, deviceKeyInfo                |
|      +-- signature                                                |
+------------------------------------------------------------------+
|  DeviceSigned (added during presentation)                         |
|  +-- nameSpaces (device-attested claims, usually empty)          |
|  +-- deviceAuth (COSE Sign1 or MAC)                              |
|      +-- protected header: {alg, kid}                            |
|      +-- payload: DeviceAuthentication structure                  |
|      +-- signature (by device key)                               |
+------------------------------------------------------------------+
```

### mDoc vs SD-JWT Comparison

| Aspect | mDoc | SD-JWT |
|--------|------|--------|
| Encoding | CBOR (binary) | JSON (text) |
| Size | More compact | Larger |
| Signature | COSE Sign1 | JWS |
| Selective disclosure | Per-claim digests | Per-claim hashed disclosures |
| Holder binding | DeviceAuth signature | KB-JWT |
| Session binding | SessionTranscript | nonce + aud in KB-JWT |
| Specification | ISO 18013-5 | IETF SD-JWT |

---

## Credential Structure

### IssuerSigned

The `IssuerSigned` structure is what the wallet receives from the issuer and stores:

```cbor-diagnostic
IssuerSigned = {
  "nameSpaces": {
    "org.iso.18013.5.1": [
      24(<< {  ; bstr-wrapped IssuerSignedItem
        "digestID": 0,
        "random": h'A1B2C3D4...',
        "elementIdentifier": "given_name",
        "elementValue": "John"
      } >>),
      24(<< {
        "digestID": 1,
        "random": h'E5F6A7B8...',
        "elementIdentifier": "family_name",
        "elementValue": "Doe"
      } >>),
      ; ... more items
    ]
  },
  "issuerAuth": COSE_Sign1  ; MSO signature
}
```

### IssuerSignedItem

Each claim is encoded as a CBOR-tagged byte string (tag 24):

```cbor-diagnostic
IssuerSignedItem = 24(<< {
  "digestID": uint,           ; Index in valueDigests
  "random": bstr,             ; 16+ bytes salt
  "elementIdentifier": tstr,  ; Claim name
  "elementValue": any         ; Claim value
} >>)
```

**Important**: The `24(<<...>>)` notation means CBOR tag 24 wrapping a byte string containing the encoded inner map. This tagged structure is what gets hashed for the digest.

### Mobile Security Object (MSO)

The MSO is the signed payload in `issuerAuth`:

```cbor-diagnostic
MSO = {
  "version": "1.0",
  "digestAlgorithm": "SHA-256",
  "valueDigests": {
    "org.iso.18013.5.1": {
      0: h'ABC123...',  ; SHA-256 of IssuerSignedItem[0]
      1: h'DEF456...',  ; SHA-256 of IssuerSignedItem[1]
      ; ...
    }
  },
  "docType": "org.iso.18013.5.1.mDL",
  "validityInfo": {
    "signed": 0("2024-01-01T00:00:00Z"),    ; tdate
    "validFrom": 0("2024-01-01T00:00:00Z"), ; tdate
    "validUntil": 0("2025-01-01T00:00:00Z") ; tdate
  },
  "deviceKeyInfo": {
    "deviceKey": COSE_Key  ; Holder's public key
  }
}
```

### COSE_Key for Device Key

```cbor-diagnostic
COSE_Key = {
  1: 2,           ; kty: EC2
  -1: 1,          ; crv: P-256
  -2: h'...',     ; x coordinate (32 bytes)
  -3: h'...'      ; y coordinate (32 bytes)
}
```

### validityInfo

| Field | Type | Description |
|-------|------|-------------|
| `signed` | tdate (tag 0) | When the MSO was signed |
| `validFrom` | tdate | Credential becomes valid |
| `validUntil` | tdate | Credential expires |
| `expectedUpdate` | tdate (optional) | When update is expected |

**tdate Format**: Tag 0 wrapping an ISO 8601 date-time string.

---

## Issuance Flow (OID4VCI)

### Issuance Models: Push vs Pull

OID4VCI supports two primary issuance models:

| Model | Grant Type | User Authentication | Use Case |
|-------|------------|---------------------|----------|
| **Push (Pre-authorized)** | `urn:ietf:params:oauth:grant-type:pre-authorized_code` | Already done before offer | Issuer initiates after user authenticated elsewhere |
| **Pull (Authorization Code)** | `authorization_code` | During issuance flow | Wallet initiates, user authenticates at issuer |

### Push Model Flow (Pre-authorized Code)

```
+--------+                    +--------+                    +--------+
|  User  |                    | Wallet |                    | Issuer |
+---+----+                    +---+----+                    +---+----+
    |                             |                             |
    |  1. Receive credential offer|                             |
    |     (e.g., scan QR code)    |                             |
    |---------------------------->|                             |
    |                             |                             |
    |                             |  2. Discover metadata       |
    |                             |---------------------------->|
    |                             |                             |
    |                             |  3. Metadata (format:       |
    |                             |     mso_mdoc, doctype)      |
    |                             |<----------------------------|
    |                             |                             |
    |                             |  4. Token request           |
    |                             |     (pre-authorized_code)   |
    |                             |---------------------------->|
    |                             |                             |
    |                             |  5. Access token + c_nonce  |
    |                             |<----------------------------|
    |                             |                             |
    |                             |  6. Credential request      |
    |                             |     (with proof + device key)
    |                             |---------------------------->|
    |                             |                             |
    |                             |  7. IssuerSigned mDoc       |
    |                             |<----------------------------|
    |                             |                             |
```

### Pull Model Flow (Authorization Code)

In the pull model, the wallet initiates the issuance and the user authenticates at the issuer:

```
+--------+                    +--------+                    +--------+
|  User  |                    | Wallet |                    | Issuer |
+---+----+                    +---+----+                    +---+----+
    |                             |                             |
    |  1. User wants credential   |                             |
    |---------------------------->|                             |
    |                             |                             |
    |                             |  2. Discover metadata       |
    |                             |---------------------------->|
    |                             |                             |
    |                             |  3. Authorization request   |
    |                             |     (scope, code_challenge) |
    |                             |---------------------------->|
    |                             |                             |
    |  4. User authentication     |                             |
    |     (login at issuer)       |                             |
    |<----------------------------|---------------------------->|
    |                             |                             |
    |                             |  5. Authorization code      |
    |                             |<----------------------------|
    |                             |                             |
    |                             |  6. Token request           |
    |                             |     (code, code_verifier)   |
    |                             |---------------------------->|
    |                             |                             |
    |                             |  7. Access token + c_nonce  |
    |                             |<----------------------------|
    |                             |                             |
    |                             |  8. Credential request      |
    |                             |     (with proof + device key)
    |                             |---------------------------->|
    |                             |                             |
    |                             |  9. IssuerSigned mDoc       |
    |                             |<----------------------------|
    |                             |                             |
```

**Authorization Request (Pull Model):**
```http
GET /authorize?
  response_type=code
  &client_id=wallet-app
  &redirect_uri=eudi-wallet://callback
  &scope=openid mdl-mdoc
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
  &state=xyz123
  &authorization_details=[{
    "type": "openid_credential",
    "format": "mso_mdoc",
    "doctype": "org.iso.18013.5.1.mDL"
  }]
HTTP/1.1
Host: issuer.example.com
```

**Key Difference:** In the pull model, the user authenticates at the issuer during the flow, while in the push model, authentication happened beforehand (e.g., at a government agency counter before receiving the credential offer QR code).

### Issuer Metadata

**Request:**
```http
GET /.well-known/openid-credential-issuer HTTP/1.1
Host: issuer.example.com
```

**Response:**
```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_endpoint": "https://issuer.example.com/credential",
  "credential_configurations_supported": {
    "mdl-mdoc": {
      "format": "mso_mdoc",
      "doctype": "org.iso.18013.5.1.mDL",
      "cryptographic_binding_methods_supported": ["cose_key"],
      "credential_signing_alg_values_supported": ["ES256"],
      "proof_types_supported": {
        "jwt": {
          "proof_signing_alg_values_supported": ["ES256"]
        }
      },
      "claims": {
        "org.iso.18013.5.1": {
          "given_name": {"mandatory": true},
          "family_name": {"mandatory": true},
          "birth_date": {"mandatory": false}
        }
      }
    }
  }
}
```

### Credential Request

**Request:**
```http
POST /credential HTTP/1.1
Host: issuer.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "format": "mso_mdoc",
  "doctype": "org.iso.18013.5.1.mDL",
  "proof": {
    "proof_type": "jwt",
    "jwt": "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiVENBRVIxOVp2dTNPSEY0ajRXNHZmU1ZvSElQMUlMaWxEbHM3dkNlR2VtYyIsInkiOiJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19.eyJpc3MiOiJodHRwczovL3dhbGxldC5leGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwiaWF0IjoxNzA0MDY3MjAwLCJleHAiOjE3MDQwNjc1MDAsIm5vbmNlIjoiZkdGRjdVa2hMYSJ9.SIGNATURE"
  }
}
```

### Credential Response

The response contains the base64url-encoded `IssuerSigned` CBOR:

```json
{
  "credential": "o2luYW1lU3BhY2VzoXF...",
  "c_nonce": "newNonce123",
  "c_nonce_expires_in": 300
}
```

### Building IssuerSigned (Issuer Side)

The issuer builds IssuerSigned by:

1. Creating IssuerSignedItems for each claim (with salt, digestID, elementIdentifier, elementValue)
2. Computing SHA-256 digests of each tagged item
3. Building the MSO with valueDigests, docType, validityInfo, and deviceKeyInfo
4. Signing the MSO with COSE Sign1
5. Returning base64url-encoded CBOR

See `MdocCredentialBuilder.java` for the full implementation.

---

## Wallet Storage

### Storage Requirements

The wallet must securely store:

1. **The IssuerSigned structure** (CBOR bytes or base64url)
2. **The holder's device private key** (corresponding to `deviceKeyInfo.deviceKey`)
3. **Metadata** (docType, issuer, validity dates)

### Storage Structure Example

```json
{
  "id": "credential-uuid-123",
  "format": "mso_mdoc",
  "credential": "o2luYW1lU3BhY2VzoXFvcmcuaX...",
  "device_key_id": "wallet-key-456",
  "docType": "org.iso.18013.5.1.mDL",
  "issuer": "https://issuer.example.com",
  "issued_at": "2024-01-01T00:00:00Z",
  "valid_from": "2024-01-01T00:00:00Z",
  "valid_until": "2025-01-01T00:00:00Z",
  "claims": {
    "org.iso.18013.5.1": {
      "given_name": "John",
      "family_name": "Doe",
      "birth_date": "1990-01-15"
    }
  }
}
```

### Security Considerations

- Store device private keys in secure hardware (TEE, Secure Enclave, StrongBox)
- Encrypt credentials at rest
- Implement biometric/PIN protection for credential access
- Keys should be non-exportable when possible

---

## Presentation Flow (OID4VP)

### Protocol Overview

```
+--------+                    +--------+                    +----------+
|  User  |                    | Wallet |                    | Verifier |
+---+----+                    +---+----+                    +----+-----+
    |                             |                              |
    |                             |  1. Authorization request    |
    |                             |     (DCQL query for mDoc)    |
    |                             |<-----------------------------|
    |                             |                              |
    |  2. Consent request         |                              |
    |<----------------------------|                              |
    |                             |                              |
    |  3. User approves           |                              |
    |---------------------------->|                              |
    |                             |                              |
    |                             |  4. Build DeviceResponse     |
    |                             |     - Select claims          |
    |                             |     - Compute SessionTranscript
    |                             |     - Sign DeviceAuth        |
    |                             |                              |
    |                             |  5. Authorization response   |
    |                             |     (vp_token = DeviceResponse)
    |                             |----------------------------->|
    |                             |                              |
    |                             |  6. Verification result      |
    |                             |<-----------------------------|
    |                             |                              |
```

### Authorization Request

**DCQL Query for mDoc:**
```json
{
  "credentials": [
    {
      "id": "mdl",
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "org.iso.18013.5.1.mDL"
      },
      "claims": [
        {"namespace": "org.iso.18013.5.1", "claim_name": "given_name"},
        {"namespace": "org.iso.18013.5.1", "claim_name": "family_name"},
        {"namespace": "org.iso.18013.5.1", "claim_name": "birth_date"}
      ]
    }
  ]
}
```

**Request Parameters:**
```
GET /authorize?
  response_type=vp_token
  &client_id=https://verifier.example.com
  &response_uri=https://verifier.example.com/callback
  &response_mode=direct_post
  &nonce=n-0S6_WzA2Mj
  &state=af0ifjsldkj
  &dcql_query={...}
```

---

## DeviceResponse Structure

When presenting an mDoc, the wallet builds a `DeviceResponse`:

```cbor-diagnostic
DeviceResponse = {
  "version": "1.0",
  "documents": [
    {
      "docType": "org.iso.18013.5.1.mDL",
      "issuerSigned": IssuerSigned,  ; Original from issuer
      "deviceSigned": {
        "nameSpaces": {},            ; Usually empty
        "deviceAuth": bstr           ; COSE Sign1 bytes
      }
    }
  ],
  "status": 0
}
```

### Building DeviceResponse (Wallet Side)

The wallet builds DeviceResponse by:

1. Decoding the stored IssuerSigned and extracting docType
2. Building SessionTranscript from client_id, nonce, response_uri, and optional jwk_thumbprint
3. Creating DeviceAuth signature over DeviceAuthentication structure
4. Assembling the DeviceResponse with issuerSigned, deviceSigned, and status
5. Returning base64url-encoded CBOR

See `MdocDeviceResponseBuilder.java` for the full implementation.

---

## SessionTranscript Computation

**CRITICAL**: The SessionTranscript must be computed identically by both wallet and verifier. Any mismatch will cause verification failure.

### OID4VP SessionTranscript Structure

For OpenID4VP, the SessionTranscript is defined in Appendix B.2.5 of the OID4VP spec:

```cbor-diagnostic
SessionTranscript = [
  null,                    ; DeviceEngagementBytes (null for OID4VP)
  null,                    ; EReaderKeyBytes (null for OID4VP)
  [                        ; Handover
    "OpenID4VPHandover",   ; Handover type identifier
    OID4VPHandover         ; SHA-256 hash
  ]
]
```

### OID4VPHandover Computation

```cbor-diagnostic
OID4VPHandover = SHA-256(
  CBOR_encode([
    client_id,             ; Verifier's client_id (string)
    nonce,                 ; Request nonce (string)
    jwk_thumbprint / null, ; SHA-256 thumbprint of handover JWK, or null
    response_uri           ; Response URI (string)
  ])
)
```

### Implementation

The wallet computes SessionTranscript by:

1. Building a CBOR array: `[client_id, nonce, jwk_thumbprint or null, response_uri]`
2. Computing SHA-256 hash of the CBOR-encoded array
3. Building the handover: `["OpenID4VPHandover", hash]`
4. Returning: `[null, null, handover]`

See `MdocDeviceResponseBuilder.buildSessionTranscript()` for the full implementation.

### SessionTranscript Parameters

| Parameter | Source (Wallet) | Source (Verifier) |
|-----------|-----------------|-------------------|
| `client_id` | From authorization request | Config/request |
| `nonce` | From authorization request | Generated nonce |
| `jwk_thumbprint` | From `client_metadata.jwks` (if encrypted response) | Encryption key thumbprint |
| `response_uri` | From authorization request | Config/request |

### DC API Specific Considerations

When using the Digital Credentials API, the parameters come from:

1. **client_id**: Browser's origin or from signed request object
2. **nonce**: From the DC API request
3. **jwk_thumbprint**: From `client_metadata.jwks` if response encryption requested
4. **response_uri**: The callback URL registered with DC API

---

## DeviceAuth Signature

### Holder Binding: Why DeviceAuth is Constructed at Presentation Time

Unlike SD-JWT where the Key Binding JWT (KB-JWT) is a relatively simple proof, mDoc's DeviceAuth provides stronger session binding by incorporating the complete presentation context into the signature.

#### Comparison: SD-JWT KB-JWT vs mDoc DeviceAuth

| Aspect | SD-JWT KB-JWT | mDoc DeviceAuth |
|--------|---------------|-----------------|
| **Key embedded at issuance** | `cnf.jwk` in JWT payload | `deviceKeyInfo.deviceKey` in MSO |
| **What gets signed** | Just the KB-JWT claims | DeviceAuthentication structure (includes SessionTranscript) |
| **Session context in signature** | `aud` (client_id), `nonce` | Full SessionTranscript (client_id, nonce, response_uri, jwk_thumbprint) |
| **Replay detection** | `nonce` and `aud` claims | Entire context hashed into signature |
| **Credential integrity** | `sd_hash` covers issuer JWT + disclosures | `docType` in DeviceAuthentication |

#### Why mDoc Uses Presentation-Time Binding

1. **Stronger Session Binding**: The DeviceAuth signature covers the entire SessionTranscript, which includes:
   - `client_id`: Which verifier is requesting
   - `nonce`: Unique challenge for this session
   - `response_uri`: Where the response goes
   - `jwk_thumbprint`: Encryption key thumbprint (for encrypted responses)

2. **ISO 18013-5 Heritage**: mDoc originates from mobile driving licenses designed for in-person verification. The SessionTranscript concept comes from the NFC/BLE handshake where device engagement happens.

3. **Context-Aware Security**: If any parameter differs between wallet and verifier (even slightly), the signature verification fails. This makes it impossible to replay a presentation to a different verifier or with different parameters.

4. **No Separate Token**: Unlike SD-JWT where the KB-JWT is a separate JWT appended to the credential, mDoc's deviceAuth is an integral part of the DeviceResponse structure.

#### Both Formats Are Bound at Issuance

Despite the different mechanisms, both SD-JWT and mDoc bind credentials to holder keys **at issuance time**:

- **SD-JWT**: Issuer includes `cnf.jwk` containing the holder's public key
- **mDoc**: Issuer includes `deviceKeyInfo.deviceKey` in the MSO

The difference is in how the binding is **proven during presentation**:
- **SD-JWT**: Holder creates a KB-JWT signed by their key
- **mDoc**: Holder creates a DeviceAuth signature over the SessionTranscript

### DeviceAuthentication Structure

The data signed by the device key:

```cbor-diagnostic
DeviceAuthentication = [
  "DeviceAuthentication",   ; Context string
  SessionTranscript,        ; As computed above
  docType,                  ; e.g., "org.iso.18013.5.1.mDL"
  DeviceNameSpacesBytes     ; Usually empty map: {}
]
```

### Signing Process

The wallet signs DeviceAuth by:

1. Building DeviceAuthentication: `["DeviceAuthentication", sessionTranscript, docType, deviceNameSpaces]`
2. CBOR-encoding and wrapping with tag 24
3. Creating a COSE Sign1 message with ES256 algorithm
4. Signing with the device private key (matching deviceKeyInfo in MSO)

See `MdocDeviceResponseBuilder.signDeviceAuth()` for the full implementation.

### DeviceAuth vs detached payload

The COSE Sign1 structure for deviceAuth typically uses a **detached payload** pattern:
- The payload is not included in the COSE structure itself
- The verifier reconstructs the payload from SessionTranscript + docType + deviceNameSpaces
- Only then can the signature be verified

---

## Verification Process

### Verification Steps

```
+------------------------------------------------------------------+
|                    mDoc Verification Flow                         |
+------------------------------------------------------------------+
|                                                                   |
|  1. Decode DeviceResponse                                         |
|     +-- Decode CBOR from base64url                               |
|     +-- Extract documents array                                   |
|     +-- Get first document's issuerSigned, deviceSigned          |
|                                                                   |
|  2. Verify Issuer Signature (issuerAuth)                          |
|     +-- Decode COSE Sign1 from issuerAuth                        |
|     +-- Extract MSO from payload                                  |
|     +-- Verify signature against trust list keys                  |
|     +-- Or verify against x5chain if allowed                      |
|                                                                   |
|  3. Verify Digests                                                |
|     +-- For each IssuerSignedItem in nameSpaces:                 |
|     |   +-- Compute SHA-256 of tagged item                       |
|     |   +-- Compare with valueDigests[digestID]                  |
|     +-- All digests must match                                    |
|                                                                   |
|  4. Validate Validity                                             |
|     +-- Check validFrom <= now <= validUntil                      |
|     +-- Reject if expired or not yet valid                       |
|                                                                   |
|  5. Verify Device Binding (deviceAuth)                            |
|     +-- Extract deviceKey from MSO.deviceKeyInfo                 |
|     +-- Rebuild expected SessionTranscript                       |
|     +-- Rebuild DeviceAuthentication payload                      |
|     +-- Verify deviceAuth signature with deviceKey               |
|     +-- Verify SessionTranscript matches                         |
|                                                                   |
|  6. Extract Claims                                                |
|     +-- Decode each IssuerSignedItem                             |
|     +-- Build claims map from elementIdentifier/elementValue     |
|                                                                   |
+------------------------------------------------------------------+
```

### Implementation

See `MdocVerifier.java` for the full implementation. Key methods:
- `verify()` - main entry point
- `verifySignature()` - validates issuerAuth against trust list
- `verifyDigests()` - checks each IssuerSignedItem hash matches MSO
- `verifyDeviceAuth()` - validates holder binding and SessionTranscript

### Verification Checks Summary

| Check | Required | Failure Reason |
|-------|----------|----------------|
| issuerAuth signature | Yes | Untrusted issuer |
| MSO digests | Yes | Tampered claims |
| validityInfo | Yes | Expired or not yet valid |
| deviceAuth signature | Yes | Invalid holder binding |
| SessionTranscript | Yes | Session binding mismatch |
| docType match | Yes | Wrong credential type |

---

## Trust Mechanisms

### Trust List

A trust list contains public keys of trusted mDoc issuers:

```json
{
  "issuers": [
    {
      "id": "issuer-mdoc-es256",
      "certificate": "MIIBgTCCASegAwIBAgIU...",
      "kid": "mdoc-issuer-key-1"
    },
    {
      "id": "issuer-mdoc-iaca",
      "jwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
        "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
      }
    }
  ]
}
```

### X.509 Certificate Chain (x5chain)

mDoc issuers can embed their certificate chain in the COSE protected header:

```cbor-diagnostic
{
  1: -7,                              ; alg: ES256
  33: [                               ; x5chain (header param 33)
    h'30820...leaf certificate...',   ; Leaf (issuer) certificate
    h'30820...intermediate...',       ; Intermediate CA
    h'30820...root...'                ; Root CA
  ]
}
```

**Verification:**
1. Parse DER-encoded certificates from x5chain
2. Validate certificate chain
3. Check root against trusted anchors
4. Verify COSE signature with leaf certificate's public key

### IACA (Issuing Authority Certificate Authority)

For mDL (mobile Driving License), the trust anchor is typically:
- An IACA (Issuing Authority Certificate Authority) certificate
- Published by the issuing jurisdiction
- Used to validate the issuer's certificate chain

### TrustedIssuerResolver Interface

```java
public interface TrustedIssuerResolver {
    // Verify JWT signature against trust list
    boolean verify(SignedJWT jwt, String trustListId);

    // Get public keys for COSE verification
    List<PublicKey> publicKeys(String trustListId);

    // Allow fallback to x5chain embedded in issuerAuth
    default boolean allowIssuerAuthX5ChainFallback(String trustListId) {
        return false;
    }
}
```

---

## Client ID Schemes

OID4VP supports multiple client identification schemes:

### 1. Pre-registered

```
client_id=https://verifier.example.com
```
- Client is pre-registered with the wallet
- Simplest scheme but requires registration

### 2. Web Origin (DC API)

```
client_id=https://verifier.example.com
```
or
```
client_id=origin:https://verifier.example.com
```
- Browser provides origin as client_id
- Used with Digital Credentials API
- Browser enforces same-origin policy

### 3. x509_san_dns

```
client_id=x509_san_dns:verifier.example.com
```
- Request must be signed with X.509 certificate
- Certificate SAN dNSName must match client_id
- response_uri host must match

### 4. x509_san_uri

```
client_id=x509_san_uri:https://verifier.example.com
```
- Similar to x509_san_dns but uses URI SAN

### 5. verifier_attestation

```
client_id=verifier_attestation:https://verifier.example.com
```
- Request contains verifier attestation JWT
- Attestation signed by trusted authority
- Contains verifier's public key

### 6. x509_hash

```
client_id=x509_hash:abc123...
```
- Request must be signed with X.509 certificate
- The hash value (after the prefix) is the base64url-encoded SHA-256 hash of the leaf certificate's DER encoding
- More flexible than x509_san_dns/x509_san_uri as it doesn't require specific SAN entries
- Useful when the verifier's certificate doesn't have a matching SAN but you still want X.509-based authentication

**Hash Computation:**
```java
// Compute x509_hash client_id value
X509Certificate cert = ...; // Leaf certificate
byte[] derBytes = cert.getEncoded();
byte[] hash = MessageDigest.getInstance("SHA-256").digest(derBytes);
String x509Hash = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
String clientId = "x509_hash:" + x509Hash;
```

---

## DC API Integration

### Digital Credentials API Overview

The W3C Digital Credentials API enables browser-mediated mDoc presentation:

```javascript
const credential = await navigator.credentials.get({
  digital: {
    providers: [{
      protocol: "openid4vp",
      request: {
        client_id: "https://verifier.example.com",
        nonce: "n-0S6_WzA2Mj",
        response_mode: "dc_api",
        dcql_query: {
          credentials: [{
            id: "mdl",
            format: "mso_mdoc",
            meta: { doctype_value: "org.iso.18013.5.1.mDL" },
            claims: [
              { namespace: "org.iso.18013.5.1", claim_name: "given_name" }
            ]
          }]
        }
      }
    }]
  }
});
```

### DC API Response

The browser returns the DeviceResponse:

```javascript
{
  data: "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOB..."  // base64url DeviceResponse
}
```

### DC API vs Direct Post

| Aspect | DC API | Direct Post |
|--------|--------|-------------|
| Transport | Browser mediated | HTTP POST |
| client_id | Origin-based | From request |
| response_uri | Not used | Required |
| Encryption | Optional | Optional |
| Privacy | Enhanced (browser mediation) | Direct |

### DC API Client ID for SessionTranscript

When using DC API, the `client_id` for SessionTranscript is typically:
- The origin provided by the browser
- Or from a signed request object

**Important**: Ensure both wallet and verifier use the same `client_id` value!

---

## Response Modes

### direct_post

Wallet POSTs DeviceResponse directly to `response_uri`:

```http
POST /callback HTTP/1.1
Host: verifier.example.com
Content-Type: application/x-www-form-urlencoded

vp_token=o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOB...
&state=af0ifjsldkj
```

### direct_post.jwt

Same as direct_post but response is JWE-encrypted:

```http
POST /callback HTTP/1.1
Host: verifier.example.com
Content-Type: application/x-www-form-urlencoded

response=eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIn0...
```

### dc_api

Response via Digital Credentials API:

```javascript
// Browser returns
{
  data: "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOB..."
}
```

### dc_api.jwt

JWE-encrypted response via DC API:

```javascript
{
  data: "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIn0..."
}
```

---

## Selective Disclosure

### How mDoc Selective Disclosure Works

Unlike SD-JWT where disclosures are concatenated, mDoc selective disclosure works by:

1. **Filtering IssuerSignedItems** - Only include requested claims
2. **Maintaining integrity** - Digests in MSO still verify against included items
3. **No signature change** - issuerAuth remains unchanged

### Implementation

See `MdocSelectiveDiscloser.java` for the full implementation. The filter:
1. Decodes nameSpaces from the credential
2. Keeps only IssuerSignedItems matching requested claims
3. Re-encodes the filtered structure

### Verifier Handling of Partial Disclosure

The verifier:
1. Only verifies digests for **present** IssuerSignedItems
2. Missing items are simply not included in claims
3. MSO valueDigests may contain digests for undisclosed claims (ignored)

---

## Troubleshooting

### Common Issues

#### 1. "Credential signature not trusted"

**Causes:**
- Issuer not in trust list
- Wrong trust list ID
- Certificate chain invalid
- x5chain fallback not enabled

**Debug:**
```java
LOG.debug("verifySignature() checking {} trust list keys for trustListId: {}",
    keys.size(), trustListId);
```

**Solution:**
- Verify issuer's public key/certificate is in trust list
- Check trust list configuration
- Enable `allowIssuerAuthX5ChainFallback` if using embedded certificates

#### 2. "SessionTranscript mismatch"

**Causes:**
- client_id differs between wallet and verifier
- nonce differs
- response_uri differs
- jwk_thumbprint differs or missing on one side

**Debug:**
```java
LOG.debug("buildSessionTranscript inputs: clientId='{}', nonce='{}', " +
          "jwkThumbprint={}, responseUri='{}' -> hash={}",
    clientId, nonce,
    jwkThumbprint != null ? Base64.getUrlEncoder().withoutPadding().encodeToString(jwkThumbprint) : "null",
    responseUri,
    Base64.getUrlEncoder().withoutPadding().encodeToString(hash));
```

**Checklist:**
- [ ] client_id is exactly the same (no trailing slashes, same scheme)
- [ ] nonce is passed correctly from request to wallet
- [ ] response_uri matches exactly
- [ ] jwk_thumbprint computed same way (or both null)

##### DC API Bridging: response_uri Mismatch

When using a browser extension to bridge DC API to a native wallet via direct_post, a common issue is **response_uri mismatch** in SessionTranscript:

**Symptom:**
```
SessionTranscript MISMATCH!
  expected=g_b2gnFPcGVuSUQ0VlBIYW5kb3ZlclggOUeHTTVnNWJ-...
  actual=g_b2gnFPcGVuSUQ0VlBIYW5kb3ZlclggloSRseI41uo6...
```

**Root Cause:**
The browser extension creates a synthetic `response_uri` for form interception:
```javascript
// Extension creates:
const dcApiResponseUri = window.location.origin + "/__oid4vp_dc_api_response__/" + state;
// e.g., "http://localhost:8080/__oid4vp_dc_api_response__/abc123"

// But the verifier expects:
// e.g., "http://localhost:8080/" (the origin)
```

**OID4VP Spec (Appendix B.2.5):**
For DC API mode, the `response_uri` in SessionTranscript should be the **verifier's origin**, not a synthetic bridge URL.

**Solution:**
The wallet should derive the **origin** from the response_uri for mDoc SessionTranscript computation:

```java
// In wallet - derive origin from response_uri for SessionTranscript
private String deriveOriginWithTrailingSlash(String uri) {
    URI parsed = URI.create(uri);
    String scheme = parsed.getScheme();
    String host = parsed.getHost();
    int port = parsed.getPort();
    boolean includePort = port != -1
            && !((port == 80 && "http".equalsIgnoreCase(scheme))
            || (port == 443 && "https".equalsIgnoreCase(scheme)));
    if (includePort) {
        return "%s://%s:%d/".formatted(scheme.toLowerCase(), host, port);
    }
    return "%s://%s/".formatted(scheme.toLowerCase(), host);
}

// Use it for mDoc SessionTranscript
String sessionTranscriptResponseUri = deriveOriginWithTrailingSlash(responseUri);
mdocDeviceResponseBuilder.buildDeviceResponse(..., sessionTranscriptResponseUri, ...);
```

**Key Point:** The wallet derives the origin from whatever response_uri it receives, ensuring compatibility with both DC API bridging and regular direct_post flows. The verifier also uses the origin for SessionTranscript validation.

#### 3. "deviceAuth signature invalid"

**Causes:**
- Wrong device key used
- deviceKeyInfo doesn't match presentation key
- COSE key conversion error

**Debug:**
- Log the device public key from MSO
- Log the key used for signing
- Verify they match

#### 4. "Credential presentation expired"

**Causes:**
- validUntil timestamp is in the past
- Clock skew between systems

**Solution:**
- Check validityInfo timestamps
- Ensure server clocks are synchronized
- Increase credential TTL at issuance

#### 5. "Digest mismatch"

**Causes:**
- IssuerSignedItem was modified
- Encoding inconsistency (tag 24 handling)
- Hash algorithm mismatch

**Debug:**
```java
byte[] expectedDigest = digests.get(digestId);
byte[] actualDigest = sha.digest(element.EncodeToBytes());
LOG.debug("Digest check: id={}, expected={}, actual={}",
    digestId,
    HexUtils.encode(expectedDigest),
    HexUtils.encode(actualDigest));
```

#### 6. "Invalid mDoc payload"

**Causes:**
- Not valid CBOR
- Wrong encoding (hex vs base64url)
- Missing required fields

**Debug:**
- Check if input is hex or base64url
- Decode and inspect CBOR structure
- Verify required fields present

### Debugging SessionTranscript Step by Step

1. **Log inputs on both sides:**
   ```
   Wallet:   clientId='https://example.com', nonce='abc123',
             jwkThumbprint=null, responseUri='https://example.com/callback'
   Verifier: clientId='https://example.com', nonce='abc123',
             jwkThumbprint=null, responseUri='https://example.com/callback'
   ```

2. **Compare the hash:**
   ```
   Wallet hash:   gebOz2yL5MS-fI6rC-7EUA2eiTyTq2EUEYGBoDOjYx48
   Verifier hash: BCABCociWK2xLjWCBiSNEQFPhVZopw7LCiCHL09A6Dg
   ```

3. **If hashes differ:**
   - Check each input value character-by-character
   - Verify CBOR encoding order is consistent
   - Check for invisible characters or encoding differences

### Verification Checklist

- [ ] DeviceResponse CBOR decodes successfully
- [ ] documents array has at least one document
- [ ] issuerSigned.issuerAuth COSE signature verifies
- [ ] All present IssuerSignedItem digests match valueDigests
- [ ] validityInfo shows credential is currently valid
- [ ] deviceKeyInfo.deviceKey present in MSO
- [ ] deviceAuth signature verifies with deviceKey
- [ ] SessionTranscript matches expected value
- [ ] docType in deviceAuth matches document.docType

---

## Specification References

| Specification | URL |
|--------------|-----|
| ISO 18013-5 (mDL) | https://www.iso.org/standard/69084.html |
| OID4VCI | https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html |
| OID4VP | https://openid.net/specs/openid-4-verifiable-presentations-1_0.html |
| OID4VP Appendix B.2.5 (SessionTranscript) | https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.5 |
| DCQL | https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l |
| DC API | https://wicg.github.io/digital-credentials/ |
| CBOR (RFC 8949) | https://datatracker.ietf.org/doc/html/rfc8949 |
| COSE (RFC 9052) | https://datatracker.ietf.org/doc/html/rfc9052 |
| COSE Algorithms (RFC 9053) | https://datatracker.ietf.org/doc/html/rfc9053 |

---

## Implementation Files Reference

| Component | File |
|-----------|------|
| mDoc Parser | `mdoc-lib/src/main/java/.../MdocParser.java` |
| mDoc Verifier | `mdoc-lib/src/main/java/.../MdocVerifier.java` |
| mDoc Builder | `mdoc-lib/src/main/java/.../MdocCredentialBuilder.java` |
| DeviceResponse Builder | `mdoc-lib/src/main/java/.../MdocDeviceResponseBuilder.java` |
| Selective Discloser | `mdoc-lib/src/main/java/.../MdocSelectiveDiscloser.java` |
| Trust Resolver | `app-common/src/main/java/.../TrustedIssuerResolver.java` |
| OID4VP Verifier | `keycloak-oid4vp/src/main/java/.../Oid4vpVerifierService.java` |
| Wallet Presentation | `wallet/src/main/java/.../Oid4vpController.java` |

