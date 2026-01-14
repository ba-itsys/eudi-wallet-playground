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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocCredentialBuilder;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocDeviceResponseBuilder;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocVerifier;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MdocTrustListVerificationTest {
    private static final Logger LOG = LoggerFactory.getLogger(MdocTrustListVerificationTest.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    // Trust list JSON containing the mock issuer certificate
    private static final String TEST_TRUST_LIST_JSON = """
            {"issuers":[{"name":"mock-issuer-es256","certificate":"-----BEGIN CERTIFICATE-----\\nMIIBgTCCASegAwIBAgIUBjEaIhGcW5pPX7vCtXbqMyql7ewwCgYIKoZIzj0EAwIw\\nFjEUMBIGA1UEAwwLbW9jay1pc3N1ZXIwHhcNMjUxMjAxMDkzOTI2WhcNMzUxMTI5\\nMDkzOTI2WjAWMRQwEgYDVQQDDAttb2NrLWlzc3VlcjBZMBMGByqGSM49AgEGCCqG\\nSM49AwEHA0IABCSGo02fNJ4ilyIJVsnR90UMvBEhbDxpvIN/X+Rq4y9qjCA35Inb\\nwm5jF0toypoov4aagJGaRkwzmvOy1JMlamKjUzBRMB0GA1UdDgQWBBR2mOx26507\\n8nBXsRCf07e99RBlDDAfBgNVHSMEGDAWgBR2mOx265078nBXsRCf07e99RBlDDAP\\nBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQDc1Evb58VWAGTNgiad\\nstQmCL6YL3ChASt/VLhgA/ogbAIgK5DjLQuY0dVDTaDccEC9s/uaKu+z5u28ZtQj\\nVK65zFU=\\n-----END CERTIFICATE-----"}]}
            """.trim();

    @Test
    void mdocVerificationWithTrustList() throws Exception {
        // Load issuer key from test resources (same as mock wallet does)
        ECKey issuerKey;
        try (var is = getClass().getClassLoader().getResourceAsStream("mock-issuer-keys.json")) {
            assertThat(is).isNotNull();
            JsonNode node = objectMapper.readTree(is);
            issuerKey = ECKey.parse(node.get("privateJwk").toString());
        }

        // Build mDoc credential
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).keyID("holder").generate();
        ObjectNode cnf = objectMapper.createObjectNode();
        cnf.set("jwk", objectMapper.convertValue(holderKey.toPublicJWK().toJSONObject(), JsonNode.class));

        MdocCredentialBuilder credentialBuilder = new MdocCredentialBuilder(issuerKey, Duration.ofMinutes(5));
        String issuerSigned = credentialBuilder.build("mock", "urn:example:pid", "https://issuer.example",
                Map.of("personal_id", "ID-123"), cnf).encoded();

        // Build device response
        MdocDeviceResponseBuilder deviceResponseBuilder = new MdocDeviceResponseBuilder();
        String deviceResponse = deviceResponseBuilder.buildDeviceResponse(
                issuerSigned, holderKey, "client-id", "nonce-123", "https://response.uri", null);

        // Load trust list and create verifier
        Oid4vpTrustListService trustListService = new Oid4vpTrustListService(objectMapper, TEST_TRUST_LIST_JSON);
        List<PublicKey> keys = trustListService.publicKeys("trust-list");
        LOG.info("Trust list has {} keys", keys.size());
        for (PublicKey key : keys) {
            LOG.info("  Key type: {}, class: {}", key.getAlgorithm(), key.getClass().getSimpleName());
        }

        MdocVerifier verifier = new MdocVerifier(trustListService);

        // Verify
        Map<String, Object> claims = verifier.verify(deviceResponse, "trust-list", "client-id", "nonce-123",
                "https://response.uri", null, null);

        assertThat(claims).containsEntry("personal_id", "ID-123");
    }
}
