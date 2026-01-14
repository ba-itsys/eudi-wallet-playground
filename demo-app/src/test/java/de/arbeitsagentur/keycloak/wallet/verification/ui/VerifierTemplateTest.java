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
package de.arbeitsagentur.keycloak.wallet.verification.ui;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class VerifierTemplateTest {

    @Test
    void formatOptionsIncludeMdocAndAll() throws Exception {
        String html = resource("templates/verifier.html");
        Document document = Jsoup.parse(html);
        List<String> datalistValues = document.select("datalist#dcql-format-options > option").eachAttr("value");
        assertThat(datalistValues).containsExactlyInAnyOrder("dc+sd-jwt", "mso_mdoc", "all");
        assertThat(html).contains("const knownFormats = [\"dc+sd-jwt\", \"mso_mdoc\", \"all\"]");
        assertThat(html).doesNotContain("jwt_vc");
        assertThat(html).doesNotContain("format-custom");
    }

    @Test
    void verifierResultDoesNotRenderTokenHints() throws Exception {
        String html = resource("templates/verifier-result.html");
        Document document = Jsoup.parse(html);
        assertThat(document.select(".token-hint")).isEmpty();
        assertThat(html).contains("Decoded mDoc");
    }

    private String resource(String path) throws Exception {
        var url = VerifierTemplateTest.class.getClassLoader().getResource(path);
        byte[] bytes = url != null ? url.openStream().readAllBytes() : null;
        return new String(Objects.requireNonNull(bytes, "Resource not found: " + path), StandardCharsets.UTF_8);
    }
}
