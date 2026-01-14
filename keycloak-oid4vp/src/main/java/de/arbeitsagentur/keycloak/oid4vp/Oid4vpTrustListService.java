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
package de.arbeitsagentur.keycloak.oid4vp;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.credential.TrustedIssuerResolver;
import org.jboss.logging.Logger;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public final class Oid4vpTrustListService implements TrustedIssuerResolver {

    private static final Logger LOG = Logger.getLogger(Oid4vpTrustListService.class);
    private final ObjectMapper objectMapper;
    private final Map<String, TrustListKeys> trustListKeys = new ConcurrentHashMap<>();
    private final String configuredTrustListJson;

    public Oid4vpTrustListService(ObjectMapper objectMapper) {
        this(objectMapper, null);
    }

    public Oid4vpTrustListService(ObjectMapper objectMapper, String trustListJson) {
        this.objectMapper = Objects.requireNonNull(objectMapper);
        this.configuredTrustListJson = trustListJson;
    }

    @Override
    public boolean verify(SignedJWT jwt, String trustListId) {
        for (PublicKey key : publicKeys(trustListId)) {
            if (TrustedIssuerResolver.verifyWithKey(jwt, key)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public List<PublicKey> publicKeys(String trustListId) {
        String id = normalizeTrustListId(trustListId);
        LOG.infof("[OID4VP-TRUSTLIST] publicKeys() called for trustListId: %s (normalized: %s)", trustListId, id);
        TrustListKeys resolved = trustListKeys.computeIfAbsent(id, this::loadKeys);
        if (!resolved.found()) {
            throw new IllegalStateException("Trust list not found or empty: " + id);
        }
        LOG.infof("[OID4VP-TRUSTLIST] Returning %d keys from trust list %s", resolved.keys().size(), id);
        for (int i = 0; i < resolved.keys().size(); i++) {
            PublicKey key = resolved.keys().get(i);
            if (key instanceof java.security.interfaces.ECPublicKey ecKey) {
                LOG.infof("[OID4VP-TRUSTLIST] Key[%d]: EC P-256 x=%s", i,
                        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                                ecKey.getW().getAffineX().toByteArray()));
            } else {
                LOG.infof("[OID4VP-TRUSTLIST] Key[%d]: %s", i, key.getAlgorithm());
            }
        }
        return resolved.keys();
    }

    private TrustListKeys loadKeys(String trustListId) {
        if (configuredTrustListJson == null || configuredTrustListJson.isBlank()) {
            LOG.warnf("[OID4VP-TRUSTLIST] No trust list JSON configured");
            return TrustListKeys.missing();
        }
        LOG.infof("[OID4VP-TRUSTLIST] Loading trust list from configured JSON");
        return loadKeysFromJson(configuredTrustListJson);
    }

    /**
     * Dynamically register a public key to a trust list.
     * This is useful for testing where the issuer key isn't pre-configured.
     *
     * @param trustListId The trust list ID to add the key to
     * @param publicKey The public key to add
     */
    public void registerKey(String trustListId, PublicKey publicKey) {
        String id = normalizeTrustListId(trustListId);
        LOG.infof("Registering dynamic key to trust list %s: %s", id, publicKey.getAlgorithm());

        trustListKeys.compute(id, (key, existing) -> {
            List<PublicKey> keys = new ArrayList<>();
            if (existing != null && existing.found()) {
                keys.addAll(existing.keys());
            }
            keys.add(publicKey);
            return new TrustListKeys(true, List.copyOf(keys));
        });
    }

    /**
     * Dynamically register a public key from a certificate PEM to a trust list.
     *
     * @param trustListId The trust list ID to add the key to
     * @param certificatePem The certificate PEM string
     */
    public void registerCertificate(String trustListId, String certificatePem) {
        try {
            PublicKey publicKey = parsePublicKey(certificatePem);
            registerKey(trustListId, publicKey);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse certificate for trust list registration", e);
        }
    }

    private TrustListKeys loadKeysFromJson(String json) {
        try {
            JsonNode node = objectMapper.readTree(json);
            List<PublicKey> keys = new ArrayList<>();
            for (JsonNode issuer : node.path("issuers")) {
                String name = issuer.path("name").asText("unknown");
                String certPem = issuer.path("certificate").asText(null);
                if (certPem == null || certPem.isBlank()) {
                    LOG.warnf("Issuer %s has no certificate", name);
                    continue;
                }
                PublicKey publicKey = parsePublicKey(certPem);
                if (publicKey != null) {
                    keys.add(publicKey);
                    if (publicKey instanceof ECPublicKey ecKey) {
                        LOG.infof("Loaded EC key for issuer %s: x=%s, y=%s",
                                name,
                                Base64.getUrlEncoder().withoutPadding().encodeToString(ecKey.getW().getAffineX().toByteArray()),
                                Base64.getUrlEncoder().withoutPadding().encodeToString(ecKey.getW().getAffineY().toByteArray()));
                    } else {
                        LOG.infof("Loaded key for issuer %s: %s", name, publicKey.getAlgorithm());
                    }
                }
            }
            LOG.infof("Loaded %d keys from trust list JSON", keys.size());
            return new TrustListKeys(true, List.copyOf(keys));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse trust list JSON", e);
        }
    }

    private String normalizeTrustListId(String trustListId) {
        if (trustListId == null || trustListId.isBlank()) {
            return DefaultOid4vpValues.DEFAULT_TRUST_LIST_ID;
        }
        String trimmed = trustListId.trim();
        if (trimmed.endsWith(".json")) {
            trimmed = trimmed.substring(0, trimmed.length() - 5);
        }
        return trimmed.isBlank() ? DefaultOid4vpValues.DEFAULT_TRUST_LIST_ID : trimmed;
    }

    private PublicKey parsePublicKey(String pem) throws Exception {
        String sanitized = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(sanitized);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate =
                (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
        return certificate.getPublicKey();
    }

    private record TrustListKeys(boolean found, List<PublicKey> keys) {
        static TrustListKeys missing() {
            return new TrustListKeys(false, List.of());
        }
    }
}
