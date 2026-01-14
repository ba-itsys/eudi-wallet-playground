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
package de.arbeitsagentur.keycloak.wallet.mockissuer.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

@ConfigurationProperties(prefix = "mock-issuer")
public record MockIssuerProperties(
        Boolean enabled,
        Path keyFile,
        Duration credentialTtl,
        String issuerId,
        Path configurationFile,
        List<CredentialConfiguration> configurations
) {
    public MockIssuerProperties {
        if (enabled == null) {
            enabled = Boolean.TRUE;
        }
        if (keyFile == null) {
            keyFile = Path.of("config/mock-issuer-keys.json");
        }
        if (credentialTtl == null) {
            credentialTtl = Duration.ofDays(180); // 6 months
        }
        if (configurationFile == null) {
            configurationFile = Path.of("config/mock-issuer-configurations.json");
        }
        if (configurations == null) {
            configurations = List.of();
        }
    }

    public record CredentialConfiguration(String id, String format, String scope, String name, String vct,
                                          List<ClaimTemplate> claims) {
        public CredentialConfiguration {
            if (claims == null) {
                claims = List.of();
            }
        }
    }

    public record ClaimTemplate(String name, String label, String defaultValue, Boolean required) {
        public ClaimTemplate {
            label = (label == null || label.isBlank()) ? name : label;
            required = Objects.requireNonNullElse(required, Boolean.FALSE);
        }
    }
}
