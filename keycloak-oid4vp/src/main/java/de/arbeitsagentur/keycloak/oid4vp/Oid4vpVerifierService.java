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

import org.jboss.logging.Logger;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocVerifier;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtVerifier;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

public final class Oid4vpVerifierService {
    private static final Logger LOG = Logger.getLogger(Oid4vpVerifierService.class);
    private final ObjectMapper objectMapper;
    private final SdJwtVerifier sdJwtVerifier;
    private final MdocVerifier mdocVerifier;

    public Oid4vpVerifierService(ObjectMapper objectMapper, Oid4vpTrustListService trustListService) {
        this.objectMapper = objectMapper;
        this.sdJwtVerifier = new SdJwtVerifier(objectMapper, trustListService);
        this.mdocVerifier = new MdocVerifier(trustListService);
    }

    public VerifiedPresentation verify(String vpToken,
                                String trustListId,
                                String expectedClientId,
                                String expectedNonce,
                                String expectedResponseUri,
                                byte[] expectedJwkThumbprint) throws Exception {
        return verify(vpToken, trustListId, expectedClientId, expectedNonce, expectedResponseUri, expectedJwkThumbprint, false);
    }

    /**
     * Verify a VP token, optionally trusting x5c certificates from the credential.
     *
     * @param trustX5cFromCredential If true, trust x5c certificates embedded in the credential
     *                                rather than requiring them to be in the trust list.
     *                                This is useful for testing but should be used with caution.
     */
    public VerifiedPresentation verify(String vpToken,
                                String trustListId,
                                String expectedClientId,
                                String expectedNonce,
                                String expectedResponseUri,
                                byte[] expectedJwkThumbprint,
                                boolean trustX5cFromCredential) throws Exception {
        String extracted = extractFirstVpToken(vpToken);
        if (extracted == null || extracted.isBlank()) {
            throw new IllegalArgumentException("Missing vp_token");
        }
        String normalized = extracted.trim();
        String expectedDcApiAudience = dcApiAudienceFromResponseUri(expectedResponseUri);
        if (sdJwtVerifier.isSdJwt(normalized)) {
            Exception firstError = null;
            try {
                Map<String, Object> claims = sdJwtVerifier.verify(normalized, trustListId, expectedClientId, expectedNonce, null, null);
                return new VerifiedPresentation(PresentationType.SD_JWT, claims);
            } catch (Exception e) {
                firstError = e;
            }
            if (expectedDcApiAudience != null
                    && !expectedDcApiAudience.isBlank()
                    && !expectedDcApiAudience.equals(expectedClientId)) {
                try {
                    Map<String, Object> claims = sdJwtVerifier.verify(normalized, trustListId, expectedDcApiAudience, expectedNonce, null, null);
                    return new VerifiedPresentation(PresentationType.SD_JWT, claims);
                } catch (Exception e) {
                    e.addSuppressed(firstError);
                    throw e;
                }
            }
            throw firstError;
        }
        if (mdocVerifier.isMdoc(normalized)) {
            LOG.debugf("Detected mDoc format: expectedClientId=%s, expectedNonce=%s, expectedResponseUri=%s, expectedDcApiAudience=%s",
                    expectedClientId, expectedNonce, expectedResponseUri, expectedDcApiAudience);
            RuntimeException firstError = null;
            try {
                Map<String, Object> claims = mdocVerifier.verify(normalized, trustListId, expectedClientId, expectedNonce, expectedResponseUri, expectedJwkThumbprint, null);
                return new VerifiedPresentation(PresentationType.MDOC, claims);
            } catch (RuntimeException e) {
                LOG.debugf("First mDoc verification attempt failed: %s", e.getMessage());
                firstError = e;
            }
            if (expectedDcApiAudience != null
                    && !expectedDcApiAudience.isBlank()
                    && !expectedDcApiAudience.equals(expectedClientId)) {
                LOG.debugf("Retrying mDoc verification with DC API audience: %s", expectedDcApiAudience);
                try {
                    Map<String, Object> claims = mdocVerifier.verify(normalized, trustListId, expectedDcApiAudience, expectedNonce, expectedResponseUri, expectedJwkThumbprint, null);
                    return new VerifiedPresentation(PresentationType.MDOC, claims);
                } catch (RuntimeException e) {
                    LOG.debugf("Second mDoc verification attempt also failed: %s", e.getMessage());
                    e.addSuppressed(firstError);
                    throw e;
                }
            }
            throw firstError;
        }
        throw new IllegalArgumentException("Unsupported vp_token format");
    }

    /**
     * Verify a multi-credential VP token containing multiple credentials keyed by credential ID.
     * The vp_token format is: {"credential_id_1": ["credential1"], "credential_id_2": ["credential2"]}
     *
     * @return A map of credential ID to VerifiedPresentation
     */
    public Map<String, VerifiedPresentation> verifyMultiCredential(String vpToken,
                                                                     String trustListId,
                                                                     String expectedClientId,
                                                                     String expectedNonce,
                                                                     String expectedResponseUri,
                                                                     byte[] expectedJwkThumbprint,
                                                                     boolean trustX5cFromCredential) throws Exception {
        Map<String, VerifiedPresentation> results = new LinkedHashMap<>();

        if (vpToken == null || vpToken.isBlank()) {
            throw new IllegalArgumentException("Missing vp_token");
        }

        String trimmed = vpToken.trim();
        if (!trimmed.startsWith("{")) {
            // Not a JSON object, treat as single credential
            VerifiedPresentation single = verify(vpToken, trustListId, expectedClientId, expectedNonce, expectedResponseUri, expectedJwkThumbprint, trustX5cFromCredential);
            results.put("single", single);
            return results;
        }

        try {
            JsonNode node = objectMapper.readTree(trimmed);
            if (!node.isObject()) {
                throw new IllegalArgumentException("vp_token must be a JSON object for multi-credential mode");
            }

            String expectedDcApiAudience = dcApiAudienceFromResponseUri(expectedResponseUri);
            LOG.infof("Verifying multi-credential VP token with %d credentials", node.size());

            for (var entry : node.properties()) {
                String credentialId = entry.getKey();
                JsonNode credentialArray = entry.getValue();

                if (!credentialArray.isArray() || credentialArray.isEmpty()) {
                    LOG.warnf("Credential '%s' has invalid format (expected array), skipping", credentialId);
                    continue;
                }

                // Get the first credential in the array
                String credential = credentialArray.get(0).asText();
                if (credential == null || credential.isBlank()) {
                    LOG.warnf("Credential '%s' is empty, skipping", credentialId);
                    continue;
                }

                LOG.infof("Verifying credential '%s' (length: %d)", credentialId, credential.length());

                try {
                    VerifiedPresentation verified = verifySingleCredential(
                            credential,
                            trustListId,
                            expectedClientId,
                            expectedDcApiAudience,
                            expectedNonce,
                            expectedResponseUri,
                            expectedJwkThumbprint,
                            trustX5cFromCredential
                    );
                    results.put(credentialId, verified);
                    LOG.infof("Credential '%s' verified successfully, type: %s", credentialId, verified.type());
                } catch (Exception e) {
                    LOG.errorf("Failed to verify credential '%s': %s", credentialId, e.getMessage());
                    throw new IllegalArgumentException("Failed to verify credential '" + credentialId + "': " + e.getMessage(), e);
                }
            }

            if (results.isEmpty()) {
                throw new IllegalArgumentException("No valid credentials found in vp_token");
            }

            return results;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse multi-credential vp_token: " + e.getMessage(), e);
        }
    }

    /**
     * Verify a single credential string (SD-JWT or mDoc).
     */
    private VerifiedPresentation verifySingleCredential(String credential,
                                                         String trustListId,
                                                         String expectedClientId,
                                                         String expectedDcApiAudience,
                                                         String expectedNonce,
                                                         String expectedResponseUri,
                                                         byte[] expectedJwkThumbprint,
                                                         boolean trustX5cFromCredential) throws Exception {
        String normalized = credential.trim();

        if (sdJwtVerifier.isSdJwt(normalized)) {
            Exception firstError = null;
            try {
                Map<String, Object> claims = sdJwtVerifier.verify(normalized, trustListId, expectedClientId, expectedNonce, null, null);
                return new VerifiedPresentation(PresentationType.SD_JWT, claims);
            } catch (Exception e) {
                firstError = e;
            }
            if (expectedDcApiAudience != null
                    && !expectedDcApiAudience.isBlank()
                    && !expectedDcApiAudience.equals(expectedClientId)) {
                try {
                    Map<String, Object> claims = sdJwtVerifier.verify(normalized, trustListId, expectedDcApiAudience, expectedNonce, null, null);
                    return new VerifiedPresentation(PresentationType.SD_JWT, claims);
                } catch (Exception e) {
                    e.addSuppressed(firstError);
                    throw e;
                }
            }
            throw firstError;
        }

        if (mdocVerifier.isMdoc(normalized)) {
            RuntimeException firstError = null;
            try {
                Map<String, Object> claims = mdocVerifier.verify(normalized, trustListId, expectedClientId, expectedNonce, expectedResponseUri, expectedJwkThumbprint, null);
                return new VerifiedPresentation(PresentationType.MDOC, claims);
            } catch (RuntimeException e) {
                firstError = e;
            }
            if (expectedDcApiAudience != null
                    && !expectedDcApiAudience.isBlank()
                    && !expectedDcApiAudience.equals(expectedClientId)) {
                try {
                    Map<String, Object> claims = mdocVerifier.verify(normalized, trustListId, expectedDcApiAudience, expectedNonce, expectedResponseUri, expectedJwkThumbprint, null);
                    return new VerifiedPresentation(PresentationType.MDOC, claims);
                } catch (RuntimeException e) {
                    e.addSuppressed(firstError);
                    throw e;
                }
            }
            throw firstError;
        }

        throw new IllegalArgumentException("Unsupported credential format");
    }

    private String dcApiAudienceFromResponseUri(String responseUri) {
        if (responseUri == null || responseUri.isBlank()) {
            return null;
        }
        URI uri;
        try {
            uri = URI.create(responseUri);
        } catch (Exception e) {
            return null;
        }
        if (uri.getScheme() == null || uri.getHost() == null) {
            return null;
        }
        String scheme = uri.getScheme().toLowerCase();
        int port = uri.getPort();
        String host = uri.getHost();
        boolean includePort = port != -1 && !((port == 80 && "http".equals(scheme)) || (port == 443 && "https".equals(scheme)));
        try {
            URI origin = new URI(scheme, null, host, includePort ? port : -1, "/", null, null);
            return "origin:" + origin.toString();
        } catch (Exception e) {
            String origin = includePort ? "%s://%s:%d".formatted(scheme, host, port) : "%s://%s".formatted(scheme, host);
            return "origin:" + origin + "/";
        }
    }

    private String extractFirstVpToken(String raw) {
        if (raw == null) {
            return null;
        }
        String trimmed = raw.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            try {
                JsonNode node = objectMapper.readTree(trimmed);
                String extracted = extractFirstStringValue(node);
                if (extracted != null) {
                    return extracted;
                }
            } catch (Exception ignored) {
            }
        }
        return trimmed;
    }

    private String extractFirstStringValue(JsonNode node) {
        if (node == null) {
            return null;
        }
        if (node.isTextual()) {
            return node.asText();
        }
        if (node.isArray()) {
            for (JsonNode entry : node) {
                String extracted = extractFirstStringValue(entry);
                if (extracted != null) {
                    return extracted;
                }
            }
            return null;
        }
        if (node.isObject()) {
            for (JsonNode value : node) {
                String extracted = extractFirstStringValue(value);
                if (extracted != null) {
                    return extracted;
                }
            }
        }
        return null;
    }

    public enum PresentationType {
        SD_JWT,
        MDOC
    }

    public record VerifiedPresentation(PresentationType type, Map<String, Object> claims) {
    }
}
