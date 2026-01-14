/*
 * Copyright 2026 Bundesagentur für Arbeit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.arbeitsagentur.keycloak.wallet.verification.service;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocVerifier;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtVerifier;
import de.arbeitsagentur.keycloak.wallet.common.credential.TrustedIssuerResolver;
import de.arbeitsagentur.keycloak.wallet.verification.config.VerifierProperties;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.text.ParseException;

@Service
public class PresentationVerificationService {
    private final TrustListService trustListService;
    private final VerifierProperties properties;
    private final ObjectMapper objectMapper;
    private final VerifierKeyService verifierKeyService;
    private final SdJwtVerifier sdJwtVerifier;
    private final MdocVerifier mdocVerifier;

    public PresentationVerificationService(TrustListService trustListService,
                                           VerifierProperties properties,
                                           ObjectMapper objectMapper,
                                           VerifierKeyService verifierKeyService) {
        this.trustListService = trustListService;
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.verifierKeyService = verifierKeyService;
        this.sdJwtVerifier = new SdJwtVerifier(objectMapper, trustListService);
        this.mdocVerifier = new MdocVerifier(trustListService);
    }

    public List<Map<String, Object>> verifyPresentations(List<String> vpTokens,
                                                         String expectedNonce,
                                                         String responseNonce,
                                                         String trustListId,
                                                         String expectedAudience,
                                                         String expectedResponseUri,
                                                         String expectedResponseMode,
                                                         VerificationSteps steps,
                                                         List<String> trustedIssuerJwks) throws Exception {
        List<PublicKey> additionalTrustedIssuerKeys = parseTrustedIssuerKeys(trustedIssuerJwks);
        SdJwtVerifier effectiveSdJwtVerifier = sdJwtVerifier(additionalTrustedIssuerKeys);
        MdocVerifier effectiveMdocVerifier = mdocVerifier(additionalTrustedIssuerKeys);
        List<Map<String, Object>> payloads = new ArrayList<>();
        int index = 0;
        for (String token : vpTokens) {
            steps.add("Validating vp_token " + (++index),
                    "Start processing the vp_token and verify trust, audience, nonce, and timing.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
            payloads.add(verifySinglePresentation(token, expectedNonce, responseNonce, trustListId, expectedAudience, expectedResponseUri, expectedResponseMode, steps, effectiveSdJwtVerifier, effectiveMdocVerifier));
        }
        return payloads;
    }

    public Map<String, Object> verifySinglePresentation(String vpToken,
                                                        String expectedNonce,
                                                        String responseNonce,
                                                        String trustListId,
                                                        String expectedAudience,
                                                        String expectedResponseUri,
                                                        String expectedResponseMode,
                                                        VerificationSteps steps,
                                                        SdJwtVerifier sdJwtVerifier,
                                                        MdocVerifier mdocVerifier) throws Exception {
        String audience = expectedAudience != null && !expectedAudience.isBlank()
                ? expectedAudience
                : properties.clientId();
        String decryptedToken = decryptIfEncrypted(vpToken, steps);
        Envelope envelope = unwrapEnvelope(decryptedToken);
        String keyBindingJwt = envelope != null ? envelope.kbJwt() : null;
        if (envelope != null) {
            decryptedToken = envelope.innerToken();
        } else if (expectedNonce != null && responseNonce != null && !expectedNonce.equals(responseNonce)) {
            throw new IllegalStateException("Nonce mismatch in presentation");
        }

        if (sdJwtVerifier.isSdJwt(decryptedToken)) {
            return sdJwtVerifier.verify(decryptedToken, trustListId, audience, expectedNonce, keyBindingJwt, steps);
        }
        if (mdocVerifier != null && mdocVerifier.isMdoc(decryptedToken)) {
            byte[] thumbprint = null;
            // Per OID4VP spec, encrypted responses use .jwt suffix (direct_post.jwt or dc_api.jwt)
            boolean encryptedResponse = expectedResponseMode != null && expectedResponseMode.toLowerCase().endsWith(".jwt");
            if (encryptedResponse) {
                var encKey = verifierKeyService.loadOrCreateEncryptionKey().toPublicJWK();
                thumbprint = encKey.computeThumbprint().decode();
                org.slf4j.LoggerFactory.getLogger(PresentationVerificationService.class)
                        .info("[mDoc-verify] Encrypted response mode, jwkThumbprint={}, keyId={}",
                                java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(thumbprint),
                                encKey.getKeyID());
            }
            org.slf4j.LoggerFactory.getLogger(PresentationVerificationService.class)
                    .info("[mDoc-verify] Verifying mDoc: audience={}, nonce={}, responseUri={}, hasThumbprint={}",
                            audience, expectedNonce, expectedResponseUri, thumbprint != null);
            return mdocVerifier.verify(decryptedToken, trustListId, audience, expectedNonce, expectedResponseUri, thumbprint, steps);
        }

        SignedJWT jwt = SignedJWT.parse(decryptedToken);
        steps.add("Parsed JWT presentation",
                "Parsed JWT based presentation and prepared for trust and claim validation.",
                "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
        if (!trustListService.verify(jwt, trustListId)) {
            throw new IllegalStateException("Credential signature not trusted");
        }
        steps.add("Signature verified against trust-list.json",
                "Checked JWT/SD-JWT signature against trusted issuers in the trust list.",
                "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6-2.2.2.1");
        if (jwt.getJWTClaimsSet().getExpirationTime() != null
                && jwt.getJWTClaimsSet().getExpirationTime().toInstant().isBefore(Instant.now())) {
            throw new IllegalStateException("Credential presentation expired");
        }
        if (jwt.getJWTClaimsSet().getNotBeforeTime() != null
                && jwt.getJWTClaimsSet().getNotBeforeTime().toInstant().isAfter(Instant.now())) {
            throw new IllegalStateException("Credential presentation not yet valid");
        }
        if (jwt.getJWTClaimsSet().getAudience() != null && !jwt.getJWTClaimsSet().getAudience().isEmpty()) {
            String aud = jwt.getJWTClaimsSet().getAudience().get(0);
            if (!audience.equals(aud)) {
                throw new IllegalStateException("Audience mismatch in credential");
            }
        }
        if (expectedNonce != null) {
            String nonce = jwt.getJWTClaimsSet().getStringClaim("nonce");
            if (nonce != null && !expectedNonce.equals(nonce)) {
                throw new IllegalStateException("Nonce mismatch in presentation");
            }
        }
        steps.add("Nonce and audience matched verifier session",
                "Validated presentation audience and nonce against verifier session.",
                "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-14.1.2");
        steps.add("Credential timing rules validated",
                "Checked exp/nbf timestamps to ensure presentation is currently valid.",
                "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-14.1.2");
        Map<String, Object> claims = new LinkedHashMap<>(jwt.getJWTClaimsSet().getClaims());
        if (keyBindingJwt != null && !keyBindingJwt.isBlank()) {
            sdJwtVerifier.verifyHolderBinding(keyBindingJwt, decryptedToken, audience, expectedNonce);
            steps.add("Validated holder binding",
                    "Validated KB-JWT holder binding: cnf key matches credential and signature verified.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6-2.2.2.4");
            claims.put("key_binding_jwt", keyBindingJwt);
        }
        return claims;
    }

    private String decryptIfEncrypted(String vpToken, VerificationSteps steps) {
        if (vpToken == null) {
            return null;
        }
        if (vpToken.contains("~")) {
            return vpToken;
        }
        if (vpToken.chars().filter(c -> c == '.').count() == 4 && looksLikeJwe(vpToken)) {
            steps.add("Decrypting encrypted vp_token",
                    "vp_token was JWE-encrypted; decrypted with verifier private key.",
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3");
            return verifierKeyService.decrypt(vpToken);
        }
        return vpToken;
    }

    private boolean looksLikeJwe(String token) {
        try {
            JWEObject.parse(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    Envelope unwrapEnvelope(String token) {
        try {
            SignedJWT outer = SignedJWT.parse(token);
            JsonNode claims = objectMapper.readTree(outer.getPayload().toString());
            JsonNode inner = claims.get("vp_token");
            if (inner == null || inner.asText().isBlank()) {
                return null;
            }
            return new Envelope(inner.asText(), claims.path("nonce").asText(null), firstAudience(outer), token);
        } catch (ParseException e) {
            return null;
        } catch (Exception e) {
            throw new IllegalStateException("Credential signature not trusted", e);
        }
    }

    private String firstAudience(SignedJWT outer) throws ParseException {
        if (outer.getJWTClaimsSet().getAudience() != null && !outer.getJWTClaimsSet().getAudience().isEmpty()) {
            return outer.getJWTClaimsSet().getAudience().get(0);
        }
        return null;
    }

    public record Envelope(String innerToken, String nonce, String audience, String kbJwt) {
    }

    private SdJwtVerifier sdJwtVerifier(List<PublicKey> additionalTrustedIssuerKeys) {
        if (additionalTrustedIssuerKeys == null || additionalTrustedIssuerKeys.isEmpty()) {
            return sdJwtVerifier;
        }
        TrustedIssuerResolver resolver = new CompositeTrustedIssuerResolver(trustListService, additionalTrustedIssuerKeys);
        return new SdJwtVerifier(objectMapper, resolver);
    }

    private MdocVerifier mdocVerifier(List<PublicKey> additionalTrustedIssuerKeys) {
        if (additionalTrustedIssuerKeys == null || additionalTrustedIssuerKeys.isEmpty()) {
            return mdocVerifier;
        }
        TrustedIssuerResolver resolver = new CompositeTrustedIssuerResolver(trustListService, additionalTrustedIssuerKeys);
        return new MdocVerifier(resolver);
    }

    private List<PublicKey> parseTrustedIssuerKeys(List<String> trustedIssuerJwks) {
        if (trustedIssuerJwks == null || trustedIssuerJwks.isEmpty()) {
            return List.of();
        }
        List<PublicKey> keys = new ArrayList<>();
        for (String jwkJson : trustedIssuerJwks) {
            if (jwkJson == null || jwkJson.isBlank()) {
                continue;
            }
            try {
                JWK jwk = JWK.parse(jwkJson);
                if (jwk instanceof RSAKey rsaKey && rsaKey.toRSAPublicKey() != null) {
                    keys.add(rsaKey.toRSAPublicKey());
                } else if (jwk instanceof ECKey ecKey && ecKey.toECPublicKey() != null) {
                    keys.add(ecKey.toECPublicKey());
                }
            } catch (Exception ignored) {
            }
        }
        return keys;
    }

    private static class CompositeTrustedIssuerResolver implements TrustedIssuerResolver {
        private final TrustedIssuerResolver delegate;
        private final List<PublicKey> additional;

        private CompositeTrustedIssuerResolver(TrustedIssuerResolver delegate, List<PublicKey> additional) {
            this.delegate = delegate;
            this.additional = additional != null ? List.copyOf(additional) : List.of();
        }

        @Override
        public boolean verify(SignedJWT jwt, String trustListId) {
            if (delegate.verify(jwt, trustListId)) {
                return true;
            }
            for (PublicKey key : additional) {
                if (TrustedIssuerResolver.verifyWithKey(jwt, key)) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public List<PublicKey> publicKeys(String trustListId) {
            List<PublicKey> combined = new ArrayList<>(delegate.publicKeys(trustListId));
            combined.addAll(additional);
            return List.copyOf(combined);
        }
    }

}
