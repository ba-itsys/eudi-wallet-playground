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
package de.arbeitsagentur.keycloak.wallet.common.conformance;

import java.net.URI;
import java.util.Map;

/**
 * Abstraction for conformance test targets.
 * Implementations can wrap either the standalone verifier or the Keycloak OID4VP IdP.
 */
public interface ConformanceTarget extends AutoCloseable {

    /**
     * Start the target and return the public base URL.
     *
     * @param localPort The local port to bind to
     * @param publicBaseUrl The public base URL (from ngrok tunnel)
     * @return Configuration for the started target
     */
    TargetConfiguration start(int localPort, URI publicBaseUrl);

    /**
     * Get the endpoint path for creating conformance plans.
     * E.g., "/verifier/conformance/create"
     */
    String getCreatePlanPath();

    /**
     * Get the endpoint path for running conformance test modules.
     * E.g., "/verifier/conformance/run"
     */
    String getRunModulePath();

    /**
     * Get the endpoint path for starting the flow.
     * E.g., "/verifier/conformance/start-flow"
     */
    String getStartFlowPath();

    /**
     * Get the endpoint path for fetching conformance run info.
     * E.g., "/verifier/conformance/api/info/{id}"
     */
    String getRunInfoPath();

    /**
     * Get the endpoint path for fetching conformance run logs.
     * E.g., "/verifier/conformance/api/log/{id}"
     */
    String getRunLogPath();

    /**
     * Get the endpoint path for fetching flow events.
     * E.g., "/verifier/api/flow/{state}"
     */
    String getFlowEventsPath();

    /**
     * Get the endpoint path for the main conformance UI page.
     * E.g., "/verifier/conformance"
     */
    String getConformanceUiPath();

    /**
     * Get the target type identifier.
     */
    String getTargetType();

    /**
     * Get any additional form parameters needed for plan creation.
     */
    default Map<String, String> getAdditionalPlanParams() {
        return Map.of();
    }

    @Override
    void close();

    /**
     * Configuration returned after starting the target.
     */
    record TargetConfiguration(
            URI localBaseUrl,
            URI publicBaseUrl,
            String clientIdHost,
            Object applicationContext
    ) {}
}
