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
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import de.arbeitsagentur.keycloak.wallet.common.credential.CredentialBuildResult;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MdocViewerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void detectsAndRendersMdoc() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("mdoc-test")
                .generate();
        MdocCredentialBuilder builder = new MdocCredentialBuilder(signingKey, Duration.ofMinutes(5));
        CredentialBuildResult built = builder.build("cfg-id", "urn:example:pid:mock", "https://issuer.example/mock",
                Map.of("given_name", "Alice"), null);

        MdocViewer viewer = new MdocViewer(objectMapper);
        assertThat(viewer.hasMdocToken(List.of(built.encoded()), t -> t)).isTrue();

        List<String> views = viewer.views(List.of(built.encoded()), t -> t);
        assertThat(views).isNotEmpty();
        assertThat(views.get(0)).contains("given_name").contains("docType");
    }
}
