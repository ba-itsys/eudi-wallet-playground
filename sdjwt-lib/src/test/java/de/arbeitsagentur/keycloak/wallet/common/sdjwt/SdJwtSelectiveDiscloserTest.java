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

import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import de.arbeitsagentur.keycloak.wallet.common.credential.CredentialBuildResult;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class SdJwtSelectiveDiscloserTest {

    private SdJwtCredentialBuilder builder() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("sdjwt-test")
                .generate();
        return new SdJwtCredentialBuilder(new ObjectMapper(), signingKey, Duration.ofMinutes(5));
    }

    @Test
    void filtersOnlyRequestedClaims() throws Exception {
        CredentialBuildResult built = builder().build(
                "cfg-id",
                "urn:example:vct",
                "https://issuer.example/mock",
                Map.of("given_name", "Alice", "family_name", "Holder", "document_number", "DOC-123"),
                null
        );

        SdJwtParser parser = new SdJwtParser(new ObjectMapper());
        SdJwtSelectiveDiscloser discloser = new SdJwtSelectiveDiscloser(parser);

        String filtered = discloser.filter(
                built.encoded(),
                List.of(
                        new SdJwtSelectiveDiscloser.ClaimRequest("given_name", null),
                        new SdJwtSelectiveDiscloser.ClaimRequest("document_number", null)
                ),
                Set.of("given_name", "document_number"));

        Map<String, Object> claims = parser.extractDisclosedClaims(filtered);
        assertThat(claims)
                .containsEntry("given_name", "Alice")
                .containsEntry("document_number", "DOC-123")
                .doesNotContainKey("family_name");

        List<String> filteredDisclosures = discloser.filterDisclosures(
                SdJwtUtils.split(built.encoded()).disclosures(),
                List.of(new SdJwtSelectiveDiscloser.ClaimRequest("given_name", null)),
                Set.of("given_name"));
        assertThat(filteredDisclosures).hasSize(1);
    }
}
