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
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SdJwtCredentialBuilderTest {

    @Test
    void buildsSdJwtWithDisclosuresAndClaims() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("sdjwt-test")
                .generate();
        SdJwtCredentialBuilder builder = new SdJwtCredentialBuilder(new ObjectMapper(), signingKey, Duration.ofMinutes(5));

        CredentialBuildResult result = builder.build("cfg-id", "urn:example:vct", "https://issuer.example/mock",
                Map.of("given_name", "Alice", "family_name", "Holder"), null);

        assertThat(result.format()).isEqualTo("dc+sd-jwt");
        assertThat(result.encoded()).contains("~");
        assertThat(result.disclosures()).isNotEmpty();
        assertThat(result.decoded().get("claims")).isInstanceOf(Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = (Map<String, Object>) result.decoded().get("claims");
        assertThat(claims).containsEntry("given_name", "Alice");
    }
}
