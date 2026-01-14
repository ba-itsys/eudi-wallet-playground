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

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectBuilder;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocCredentialBuilder;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocParser;
import de.arbeitsagentur.keycloak.wallet.common.credential.CredentialBuildResult;
import de.arbeitsagentur.keycloak.wallet.common.sdjwt.SdJwtCredentialBuilder;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.time.Instant;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

class TokenViewServiceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void rendersMdocPrettyView() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("mdoc-test")
                .generate();
        MdocCredentialBuilder builder = new MdocCredentialBuilder(signingKey, Duration.ofMinutes(5));
        CredentialBuildResult built = builder.build("cfg-id", "urn:example:pid:mock", "https://issuer.example/mock",
                Map.of("given_name", "Alice", "family_name", "Holder"), null);
        assertThat(new MdocParser().prettyPrint(built.encoded())).isNotBlank();

        VerifierKeyService verifierKeyService = Mockito.mock(VerifierKeyService.class);
        when(verifierKeyService.decrypt(anyString())).thenAnswer(inv -> inv.getArgument(0));
        TokenViewService service = new TokenViewService(verifierKeyService, objectMapper);

        List<String> views = service.mdocViews(List.of(built.encoded()));
        assertThat(views).isNotEmpty();
        assertThat(views.get(0)).contains("docType").contains("given_name");
    }

    @Test
    void debugDecodingIncludesSdJwtDisclosures() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("sdjwt-test")
                .generate();
        SdJwtCredentialBuilder sdJwtBuilder = new SdJwtCredentialBuilder(objectMapper, signingKey, Duration.ofMinutes(5));
        CredentialBuildResult built = sdJwtBuilder.build(
                "cfg-id",
                "urn:example:pid:mock",
                "https://issuer.example/mock",
                Map.of("given_name", "Alice", "family_name", "Holder"),
                null);

        VerifierKeyService verifierKeyService = Mockito.mock(VerifierKeyService.class);
        when(verifierKeyService.decrypt(anyString())).thenAnswer(inv -> inv.getArgument(0));
        TokenViewService service = new TokenViewService(verifierKeyService, objectMapper);

        String decoded = service.assembleDecodedForDebug(built.encoded(), null, null);
        assertThat(decoded).contains("disclosures").contains("disclosed_claims").contains("given_name").contains("Alice");
    }

    @Test
    void debugDecodingHandlesArrayAndNestedSdClaims() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("sdjwt-nested-test")
                .generate();

        List<Disclosure> disclosures = new ArrayList<>();
        SDObjectBuilder inner = new SDObjectBuilder();
        disclosures.add(inner.putSDClaim("locality", "Berlin"));
        disclosures.add(inner.putSDClaim("country", "DE"));
        Map<String, Object> placeOfBirth = inner.build();

        SDObjectBuilder outer = new SDObjectBuilder();
        disclosures.add(outer.putSDClaim("place_of_birth", placeOfBirth));
        disclosures.add(outer.putSDClaim("nationalities", List.of("DE", "AT")));
        Map<String, Object> payload = new LinkedHashMap<>(outer.build());
        payload.put("iss", "https://issuer.example/mock");
        payload.put("vct", "urn:example:pid:mock");
        payload.put("iat", Instant.now().getEpochSecond());
        payload.put("exp", Instant.now().plus(Duration.ofMinutes(5)).getEpochSecond());

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(signingKey.getKeyID())
                .type(new JOSEObjectType("dc+sd-jwt"))
                .build();
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
        payload.forEach((key, value) -> {
            if (value != null) {
                claimsBuilder.claim(key, value);
            }
        });
        SignedJWT jwt = new SignedJWT(header, claimsBuilder.build());
        jwt.sign(new ECDSASigner(signingKey));

        String sdJwt = new SDJWT(jwt.serialize(), disclosures, null).toString();

        VerifierKeyService verifierKeyService = Mockito.mock(VerifierKeyService.class);
        when(verifierKeyService.decrypt(anyString())).thenAnswer(inv -> inv.getArgument(0));
        TokenViewService service = new TokenViewService(verifierKeyService, objectMapper);

        String decoded = service.assembleDecodedForDebug(sdJwt, null, null);
        assertThat(decoded).contains("nationalities").contains("DE").contains("AT");
        assertThat(decoded).contains("place_of_birth").contains("Berlin").contains("resolved_claim_value");
    }
}
