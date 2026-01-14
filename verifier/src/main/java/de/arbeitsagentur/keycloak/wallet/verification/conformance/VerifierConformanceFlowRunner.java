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
package de.arbeitsagentur.keycloak.wallet.verification.conformance;

import de.arbeitsagentur.keycloak.wallet.common.conformance.ConformanceFlowRunner;
import de.arbeitsagentur.keycloak.wallet.verification.config.VerifierProperties;
import de.arbeitsagentur.keycloak.wallet.verification.service.TrustListService;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerifierAuthService;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerifierCryptoService;
import de.arbeitsagentur.keycloak.wallet.verification.session.VerifierSession;
import de.arbeitsagentur.keycloak.wallet.verification.session.VerifierSessionStateStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.util.List;
import java.util.UUID;

@Service
public class VerifierConformanceFlowRunner implements ConformanceFlowRunner {
    private static final Logger LOG = LoggerFactory.getLogger(VerifierConformanceFlowRunner.class);
    private final VerifierAuthService verifierAuthService;
    private final VerifierCryptoService verifierCryptoService;
    private final TrustListService trustListService;
    private final VerifierSessionStateStore verifierSessionStateStore;
    private final VerifierProperties verifierProperties;
    private final ObjectMapper objectMapper;

    public VerifierConformanceFlowRunner(VerifierAuthService verifierAuthService,
                                         VerifierCryptoService verifierCryptoService,
                                         TrustListService trustListService,
                                         VerifierSessionStateStore verifierSessionStateStore,
                                         VerifierProperties verifierProperties,
                                         ObjectMapper objectMapper) {
        this.verifierAuthService = verifierAuthService;
        this.verifierCryptoService = verifierCryptoService;
        this.trustListService = trustListService;
        this.verifierSessionStateStore = verifierSessionStateStore;
        this.verifierProperties = verifierProperties;
        this.objectMapper = objectMapper;
    }

    @Override
    public ConformanceFlowStartResult startFlow(ConformanceFlowStartRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Missing conformance flow request");
        }
        URI publicBaseUri = request.publicBaseUri();
        if (publicBaseUri == null) {
            throw new IllegalArgumentException("Missing publicBaseUri");
        }
        String walletAuthEndpoint = normalizeNonBlank(request.walletAuthEndpoint(), "Missing walletAuthEndpoint");

        String authType = normalizeNonBlank(request.authType(), "Missing authType");
        String responseMode = normalizeNonBlank(request.responseMode(), "Missing responseMode");
        String requestObjectMode = normalizeNonBlank(request.requestObjectMode(), "Missing requestObjectMode");
        String requestUriMethod = normalizeNonBlank(request.requestUriMethod(), "Missing requestUriMethod");

        String providedClientId = firstNonBlank(request.walletClientId(), verifierProperties.clientId());
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();
        String walletAudience = firstNonBlank(request.walletAudience(), "https://self-issued.me/v2");

        String dcqlQuery = minify(request.dcqlQuery());

        String walletClientCert = null;
        String effectiveClientId = providedClientId;
        if ("x509_hash".equalsIgnoreCase(authType) || "x509_san_dns".equalsIgnoreCase(authType)) {
            VerifierCryptoService.X509Material x509Material = verifierCryptoService.resolveX509Material(null);
            walletClientCert = x509Material.combinedPem();
            if ("x509_hash".equalsIgnoreCase(authType)) {
                // For x509_hash, derive from certificate hash
                effectiveClientId = verifierCryptoService.deriveX509ClientId(effectiveClientId, x509Material.certificatePem());
            } else {
                // For x509_san_dns in conformance tests, use the provided hostname with prefix
                // instead of deriving from certificate SAN. This allows the client_id to match
                // what was configured in the conformance plan, while still including the
                // certificate for verification purposes.
                if (providedClientId != null && !providedClientId.isBlank()
                        && !providedClientId.startsWith("x509_san_dns:")) {
                    effectiveClientId = "x509_san_dns:" + providedClientId;
                    LOG.info("[CONFORMANCE-FLOW] Using provided client_id with prefix: {}", effectiveClientId);
                } else if (providedClientId != null && providedClientId.startsWith("x509_san_dns:")) {
                    effectiveClientId = providedClientId;
                } else {
                    // Fallback to certificate-derived client_id
                    effectiveClientId = verifierCryptoService.deriveX509SanClientId(effectiveClientId, x509Material.certificatePem());
                }
            }
        }

        LOG.info("[CONFORMANCE-FLOW] Starting flow: publicBaseUri={}, providedClientId={}, effectiveClientId={}, authType={}",
                publicBaseUri, providedClientId, effectiveClientId, authType);

        List<String> trustedIssuerJwks = request.trustedIssuerJwks() != null ? request.trustedIssuerJwks() : List.of();

        // Compute response_uri first (without query params) - this is what goes in the authorization request
        // and is used for mDoc SessionTranscript verification
        UriComponentsBuilder baseUri = UriComponentsBuilder.fromUri(publicBaseUri);
        String responseUri = baseUri.cloneBuilder().path("/verifier/callback").build().toUriString();

        VerifierSession verifierSession = new VerifierSession(
                state,
                nonce,
                dcqlQuery,
                responseMode,
                trustListService.defaultTrustListId(),
                request.clientMetadata(),
                effectiveClientId,
                authType,
                null,
                trustedIssuerJwks,
                responseUri
        );
        verifierSessionStateStore.put(verifierSession);

        // response_uri in auth request must NOT have query params (used for mDoc SessionTranscript)
        URI responseUriForAuth = URI.create(responseUri);

        VerifierAuthService.WalletAuthRequest walletAuth = verifierAuthService.buildWalletAuthorizationUrl(
                responseUriForAuth,
                state,
                nonce,
                dcqlQuery,
                walletAuthEndpoint,
                effectiveClientId,
                authType,
                request.clientMetadata(),
                walletClientCert,
                null,
                null,
                null,
                responseMode,
                requestObjectMode,
                requestUriMethod,
                walletAudience,
                null, // verifierInfo - not used in conformance tests
                baseUri
        );

        return new ConformanceFlowStartResult(walletAuth.uri(), state);
    }

    private String minify(String json) {
        if (json == null || json.isBlank()) {
            return json;
        }
        try {
            return objectMapper.writeValueAsString(objectMapper.readTree(json));
        } catch (Exception e) {
            return json;
        }
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private String normalizeNonBlank(String value, String message) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(message);
        }
        return value.trim();
    }
}
