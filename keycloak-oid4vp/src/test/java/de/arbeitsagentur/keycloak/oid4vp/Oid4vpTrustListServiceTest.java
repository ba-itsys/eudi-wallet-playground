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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

class Oid4vpTrustListServiceTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // Trust list JSON containing the mock issuer certificate
    private static final String TEST_TRUST_LIST_JSON = """
            {"issuers":[{"name":"mock-issuer-es256","certificate":"-----BEGIN CERTIFICATE-----\\nMIIBgTCCASegAwIBAgIUBjEaIhGcW5pPX7vCtXbqMyql7ewwCgYIKoZIzj0EAwIw\\nFjEUMBIGA1UEAwwLbW9jay1pc3N1ZXIwHhcNMjUxMjAxMDkzOTI2WhcNMzUxMTI5\\nMDkzOTI2WjAWMRQwEgYDVQQDDAttb2NrLWlzc3VlcjBZMBMGByqGSM49AgEGCCqG\\nSM49AwEHA0IABCSGo02fNJ4ilyIJVsnR90UMvBEhbDxpvIN/X+Rq4y9qjCA35Inb\\nwm5jF0toypoov4aagJGaRkwzmvOy1JMlamKjUzBRMB0GA1UdDgQWBBR2mOx26507\\n8nBXsRCf07e99RBlDDAfBgNVHSMEGDAWgBR2mOx265078nBXsRCf07e99RBlDDAP\\nBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQDc1Evb58VWAGTNgiad\\nstQmCL6YL3ChASt/VLhgA/ogbAIgK5DjLQuY0dVDTaDccEC9s/uaKu+z5u28ZtQj\\nVK65zFU=\\n-----END CERTIFICATE-----"}]}
            """.trim();

    @Test
    void usesConfiguredTrustListJsonForSignatureVerification() throws Exception {
        Oid4vpTrustListService trustListService = new Oid4vpTrustListService(OBJECT_MAPPER, TEST_TRUST_LIST_JSON);

        ECKey issuerKey = loadMockIssuerKey();
        SignedJWT jwt = signJwt(issuerKey);

        assertThat(trustListService.verify(jwt, DefaultOid4vpValues.DEFAULT_TRUST_LIST_ID)).isTrue();
    }

    @Test
    void failsVerificationWithEmptyTrustList() throws Exception {
        Oid4vpTrustListService trustListService = new Oid4vpTrustListService(OBJECT_MAPPER, null);

        ECKey issuerKey = loadMockIssuerKey();
        SignedJWT jwt = signJwt(issuerKey);

        // Should throw because no trust list is configured
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                () -> trustListService.verify(jwt, DefaultOid4vpValues.DEFAULT_TRUST_LIST_ID));
    }

    private ECKey loadMockIssuerKey() throws Exception {
        try (var is = Oid4vpTrustListServiceTest.class.getClassLoader().getResourceAsStream("mock-issuer-keys.json")) {
            assertThat(is).isNotNull();
            JsonNode node = OBJECT_MAPPER.readTree(is);
            return ECKey.parse(node.get("privateJwk").toString());
        }
    }

    private SignedJWT signJwt(ECKey issuerKey) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://issuer.example")
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(60)))
                .claim("test", "ok")
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(issuerKey.getKeyID())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(issuerKey));
        return jwt;
    }
}

