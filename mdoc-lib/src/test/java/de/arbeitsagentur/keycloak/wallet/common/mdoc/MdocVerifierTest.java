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
package de.arbeitsagentur.keycloak.wallet.common.mdoc;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.credential.CredentialBuildResult;
import de.arbeitsagentur.keycloak.wallet.common.credential.TrustedIssuerResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MdocVerifierTest {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private ECKey issuerKey;
    private TrustedIssuerResolver resolver;

    @BeforeEach
    void setUp() throws Exception {
        issuerKey = new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256)
                .keyID("mock-issuer-es256")
                .generate();
        PublicKey issuerPublic = issuerKey.toECPublicKey();
        resolver = new TrustedIssuerResolver() {
            @Override
            public boolean verify(SignedJWT jwt, String trustListId) {
                return TrustedIssuerResolver.verifyWithKey(jwt, issuerPublic);
            }

            @Override
            public List<PublicKey> publicKeys(String trustListId) {
                return Collections.singletonList(issuerPublic);
            }
        };
    }

    @Test
    void verifiesMdocWithDeviceAuthAndSessionTranscript() throws Exception {
        ECKey holderKey = new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256)
                .keyID("wallet-es256")
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        ObjectNode cnf = objectMapper.createObjectNode();
        cnf.set("jwk", objectMapper.readTree(holderKey.toPublicJWK().toJSONString()));

        MdocCredentialBuilder builder = new MdocCredentialBuilder(issuerKey, Duration.ofMinutes(5));
        CredentialBuildResult result = builder.build("cfg-id", "urn:example:pid:mock", "https://issuer.example/mock",
                Map.of("given_name", "Alice"), cnf);
        String issuerSigned = result.encoded();

        ECKey handoverJwk = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.ENCRYPTION)
                .keyID("verifier-enc")
                .generate();
        String expectedClientId = "aud-123";
        String expectedNonce = "nonce-123";
        String expectedResponseUri = "https://verifier.example/callback";
        String deviceResponse = new MdocDeviceResponseBuilder().buildDeviceResponse(
                issuerSigned,
                holderKey,
                expectedClientId,
                expectedNonce,
                expectedResponseUri,
                handoverJwk.toPublicJWK()
        );

        MdocVerifier verifier = new MdocVerifier(resolver);
        Map<String, Object> claims = verifier.verify(deviceResponse,
                "trust-list-mock",
                expectedClientId,
                expectedNonce,
                expectedResponseUri,
                handoverJwk.toPublicJWK().computeThumbprint().decode(),
                null);

        assertThat(claims).containsEntry("given_name", "Alice");
        assertThat(claims).containsEntry("docType", "urn:example:pid:mock");
    }
}
