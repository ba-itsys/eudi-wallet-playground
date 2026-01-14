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
package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

import com.authlete.sd.Disclosure;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.credential.CredentialBuildResult;
import de.arbeitsagentur.keycloak.wallet.common.credential.TrustedIssuerResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.security.PublicKey;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SdJwtVerifierTest {
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
                return List.of(issuerPublic);
            }
        };
    }

    @Test
    void verifiesSdJwtWithKeyBinding() throws Exception {
        ECKey holderKey = new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256)
                .keyID("wallet-es256")
                .generate();
        ObjectNode cnf = objectMapper.createObjectNode();
        cnf.set("jwk", objectMapper.readTree(holderKey.toPublicJWK().toJSONString()));

        SdJwtCredentialBuilder builder = new SdJwtCredentialBuilder(objectMapper, issuerKey, Duration.ofMinutes(5));
        CredentialBuildResult built = builder.build("cfg-id", "urn:example:vct", "https://issuer.example/mock",
                Map.of("given_name", "Alice"), cnf);
        String sdJwt = built.encoded();

        String keyBindingJwt = buildKeyBinding(holderKey, sdJwt, "aud-123", "nonce-123");

        SdJwtVerifier verifier = new SdJwtVerifier(objectMapper, resolver);
        Map<String, Object> claims = verifier.verify(sdJwt, "trust-list-mock", "aud-123", "nonce-123", keyBindingJwt, null);

        assertThat(claims).containsEntry("given_name", "Alice");
        assertThat(claims).containsEntry("key_binding_jwt", keyBindingJwt);
    }

    @Test
    void verifyDisclosuresSupportsNestedArrayElements() throws Exception {
        String hashAlg = "sha-256";
        Disclosure element = new Disclosure("FR");
        String elementDigest = element.digest(hashAlg);
        Disclosure outer = new Disclosure("nationalities", List.of(Map.of("...", elementDigest)));
        String outerDigest = outer.digest(hashAlg);

        SignedJWT jwt = signPayload(Map.of(
                "_sd_alg", hashAlg,
                "_sd", List.of(outerDigest)
        ));

        SdJwtUtils.SdJwtParts parts = new SdJwtUtils.SdJwtParts(
                "ignored",
                List.of(outer.getDisclosure(), element.getDisclosure()),
                null
        );

        assertThat(SdJwtUtils.verifyDisclosures(jwt, parts, objectMapper)).isTrue();
    }

    private String buildKeyBinding(ECKey holderKey, String vpToken, String audience, String nonce) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("kb+jwt"))
                .keyID(holderKey.getKeyID())
                .build();
        String sdHash = SdJwtUtils.computeSdHash(SdJwtUtils.split(vpToken), objectMapper);
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer("did:example:wallet")
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .claim("nonce", nonce)
                .claim("sd_hash", sdHash)
                .claim("cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject()));
        if (audience != null) {
            claims.audience(audience);
        }
        SignedJWT jwt = new SignedJWT(header, claims.build());
        jwt.sign(new ECDSASigner(holderKey));
        return jwt.serialize();
    }

    private SignedJWT signPayload(Map<String, Object> claims) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dc+sd-jwt"))
                .keyID(issuerKey.getKeyID())
                .build();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            builder.claim(entry.getKey(), entry.getValue());
        }
        SignedJWT jwt = new SignedJWT(header, builder.build());
        jwt.sign(new ECDSASigner(issuerKey));
        return jwt;
    }
}
