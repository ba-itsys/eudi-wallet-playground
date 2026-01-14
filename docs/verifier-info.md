# Verifier Info (verifier_info)

The `verifier_info` parameter allows verifiers to include attestations about themselves in the OID4VP authorization request. This is particularly important for EUDI Wallet ecosystems where verifiers must present registration certificates to prove their authorization to request specific credentials.

## Overview

When a verifier sends an authorization request to a wallet, it can include a `verifier_info` claim containing one or more attestation objects. Each attestation object provides information about the verifier's authorization, identity, or registration status.

## Format

The `verifier_info` claim is a JSON array of attestation objects:

```json
{
  "verifier_info": [
    {
      "format": "registration_cert",
      "data": "<JWT or CWT containing the attestation>"
    }
  ]
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `format` | string | The format of the attestation (e.g., `registration_cert` for EUDI Wallet) |
| `data` | string | The attestation data, typically a signed JWT or CWT |
| `credential_ids` | array (optional) | Array of credential IDs this attestation applies to |

## EUDI Wallet Registration Certificates

For EUDI Wallet ecosystems, the registration certificate (`registration_cert` format) is a JWT that proves the verifier is registered and authorized to request specific credential types.

### Registration Certificate JWT Structure

**Header:**
```json
{
  "typ": "rc-rp+jwt",
  "alg": "ES256",
  "x5u": "https://trust-anchor.example/certs/verifier.pem",
  "x5t#s256": "<thumbprint>"
}
```

**Payload:**
```json
{
  "sub": "https://verifier.example.com",
  "iat": 1704067200,
  "exp": 1735689600,
  "contact": "support@verifier.example.com",
  "privacy_policy": "https://verifier.example.com/privacy",
  "service": "Identity Verification Service",
  "credentials": [
    {
      "format": "dc+sd-jwt",
      "vct": "eu.europa.ec.eudi.pid.1",
      "claims": ["given_name", "family_name", "birthdate"]
    }
  ],
  "entitlements": ["identity_verification", "age_verification"],
  "public_body": false,
  "status": "https://trust-anchor.example/status/verifier123"
}
```

### Obtaining a Registration Certificate

Registration certificates are issued by Trust Anchors in the EUDI Wallet ecosystem. The process typically involves:

1. **Registration**: The verifier registers with the Trust Anchor
2. **Verification**: The Trust Anchor verifies the verifier's identity and authorization
3. **Issuance**: The Trust Anchor issues a signed registration certificate JWT
4. **Configuration**: The verifier configures the certificate in their system

## Configuration

### Standalone Verifier

In the standalone verifier UI, enter the verifier_info JSON in the "Verifier Info (JSON)" field:

```json
[{"format": "registration_cert", "data": "eyJhbGciOiJFUzI1NiIsInR5cCI6InJjLXJwK2p3dCJ9..."}]
```

### Keycloak OID4VP IdP

In the Keycloak admin console, configure the OID4VP Identity Provider:

1. Navigate to **Identity Providers** > **OID4VP (Wallet Login)**
2. Scroll to **Verifier Info (JSON)**
3. Enter the JSON array with your registration certificate

Example configuration:
```json
[{"format": "registration_cert", "data": "eyJhbGciOiJFUzI1NiIsInR5cCI6InJjLXJwK2p3dCJ9..."}]
```

## Request Object Example

When `verifier_info` is configured, the authorization request object will include it:

```json
{
  "iss": "https://verifier.example.com",
  "client_id": "https://verifier.example.com",
  "response_type": "vp_token",
  "response_mode": "direct_post",
  "response_uri": "https://verifier.example.com/callback",
  "state": "abc123",
  "nonce": "xyz789",
  "dcql_query": {
    "credentials": [
      {
        "id": "cred1",
        "format": "dc+sd-jwt",
        "meta": {"vct_values": ["eu.europa.ec.eudi.pid.1"]},
        "claims": [{"path": ["given_name"]}, {"path": ["family_name"]}]
      }
    ]
  },
  "verifier_info": [
    {
      "format": "registration_cert",
      "data": "eyJhbGciOiJFUzI1NiIsInR5cCI6InJjLXJwK2p3dCJ9..."
    }
  ]
}
```

## Wallet Behavior

When a wallet receives an authorization request with `verifier_info`:

1. **Parse**: Extract the attestation objects from `verifier_info`
2. **Validate**: Verify each attestation's signature and check its validity
3. **Trust**: Check if the attestation issuer is in the wallet's trust list
4. **Authorize**: Verify the verifier is authorized to request the specified credentials
5. **Display**: Show verifier information to the user for informed consent

## References

- [EUDI Wallet Architecture - Verifier Authentication](https://bmi.usercontent.opencode.de/eudi-wallet/eidas-2.0-architekturkonzept/content/ecosystem-architecture/trust/wallet-relying-party-authentication/)
- [OpenID for Verifiable Presentations (OID4VP)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [EUDI Wallet Reference Implementation](https://github.com/eu-digital-identity-wallet)
