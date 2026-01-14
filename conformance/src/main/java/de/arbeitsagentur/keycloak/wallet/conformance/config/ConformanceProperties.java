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
package de.arbeitsagentur.keycloak.wallet.conformance.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "verifier.conformance")
@Validated
public record ConformanceProperties(
        String baseUrl,
        String apiKey,
        String planId
) {
    public String resolvedBaseUrl() {
        return firstNonBlank(
                baseUrl,
                System.getenv("VERIFIER_CONFORMANCE_BASE_URL"),
                System.getenv("OIDF_CONFORMANCE_BASE_URL"),
                "https://demo.certification.openid.net");
    }

    public String resolvedApiKey() {
        return firstNonBlank(
                apiKey,
                System.getenv("VERIFIER_CONFORMANCE_API_KEY"),
                System.getenv("OIDF_CONFORMANCE_API_KEY"));
    }

    public String resolvedPlanId() {
        return firstNonBlank(
                planId,
                System.getenv("VERIFIER_CONFORMANCE_PLAN_ID"),
                System.getenv("OIDF_CONFORMANCE_PLAN_ID"));
    }

    private static String firstNonBlank(String... candidates) {
        if (candidates == null) {
            return null;
        }
        for (String c : candidates) {
            if (c != null && !c.isBlank()) {
                return c;
            }
        }
        return null;
    }
}
