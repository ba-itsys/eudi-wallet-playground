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
package de.arbeitsagentur.keycloak.wallet.mockissuer;

import de.arbeitsagentur.keycloak.wallet.mockissuer.config.MockIssuerProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.web.context.support.StaticWebApplicationContext;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.spring6.templateresolver.SpringResourceTemplateResolver;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.web.servlet.IServletWebExchange;
import org.thymeleaf.web.servlet.JakartaServletWebApplication;

import java.util.Map;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class MockIssuerTemplateTest {

    @Test
    void rendersTemplateWithStringPaths() {
        SpringTemplateEngine engine = new SpringTemplateEngine();
        SpringResourceTemplateResolver resolver = new SpringResourceTemplateResolver();
        StaticWebApplicationContext appContext = new StaticWebApplicationContext();
        resolver.setApplicationContext(appContext);
        resolver.setPrefix("classpath:/templates/");
        resolver.setSuffix(".html");
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCharacterEncoding("UTF-8");
        engine.setTemplateResolver(resolver);

        MockServletContext servletContext = new MockServletContext();
        MockHttpServletRequest request = new MockHttpServletRequest(servletContext);
        MockHttpServletResponse response = new MockHttpServletResponse();
        JakartaServletWebApplication webApplication = JakartaServletWebApplication.buildApplication(servletContext);
        IServletWebExchange exchange = webApplication.buildExchange(request, response);
        WebContext ctx = new WebContext(exchange);
        ctx.setVariable("issuer", "http://localhost/mock-issuer");
        ctx.setVariable("configurations", List.of(new MockIssuerProperties.CredentialConfiguration(
                "mock",
                "dc+sd-jwt",
                "scope",
                "Mock Credential",
                "urn:example:mock",
                List.of(new MockIssuerProperties.ClaimTemplate("given_name", "Given name", "Alice", true))
        )));
        ctx.setVariable("configurationData", List.of(Map.of(
                "id", "mock",
                "format", "dc+sd-jwt",
                "scope", "scope",
                "name", "Mock Credential",
                "vct", "urn:example:mock",
                "claims", List.of(Map.of(
                        "name", "given_name",
                        "label", "Given name",
                        "defaultValue", "Alice",
                        "required", true
                ))
        )));
        ctx.setVariable("defaultConfigurationId", "mock");
        ctx.setVariable("configurationFile", "config/mock-issuer-configurations.json");
        ctx.setVariable("userConfigurationFile", "data/mock-issuer/configurations.json");

        String html = engine.process("mock-issuer", ctx);

        assertThat(html).contains("Mock Issuer");
        assertThat(html).contains("\"vct\":\"urn:example:mock\"");
        assertThat(html).contains("\"claims\":[{");
        assertThat(html).contains("\"name\":\"given_name\"");
    }
}
