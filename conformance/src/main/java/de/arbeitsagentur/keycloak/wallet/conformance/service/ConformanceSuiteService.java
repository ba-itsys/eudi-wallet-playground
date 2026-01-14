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
package de.arbeitsagentur.keycloak.wallet.conformance.service;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class ConformanceSuiteService {
    private static final int MAX_INSTANCE_INFO_LOOKUP = 25;
    private final ObjectMapper objectMapper;
    private final RestTemplate restTemplate = new RestTemplate();

    public ConformanceSuiteService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public ConformancePlan loadPlan(String planId, String baseUrlOverride, String apiKeyOverride) {
        if (planId == null || planId.isBlank()) {
            throw new IllegalArgumentException("Missing conformance plan id");
        }
        String baseUrl = normalizeBaseUrl(baseUrlOverride);
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalStateException("Conformance base URL not configured");
        }
        URI uri = UriComponentsBuilder.fromUriString(trimTrailingSlash(baseUrl) + "/api/plan/{planId}")
                .buildAndExpand(planId.trim())
                .toUri();
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        String apiKey = apiKeyOverride;
        if (apiKey != null && !apiKey.isBlank()) {
            headers.setBearerAuth(apiKey);
        }
        ResponseEntity<Map> response = restTemplate.exchange(uri, HttpMethod.GET, new HttpEntity<>(headers), Map.class);
        if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
            throw new IllegalStateException("Failed to load conformance plan (HTTP " + response.getStatusCode().value() + ")");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getBody();
        return toPlan(body, baseUrl, apiKey);
    }

    public String createPlan(String planName,
                             Map<String, String> variant,
                             Map<String, Object> config,
                             String baseUrlOverride,
                             String apiKeyOverride) {
        if (planName == null || planName.isBlank()) {
            throw new IllegalArgumentException("Missing conformance plan name");
        }
        String baseUrl = normalizeBaseUrl(baseUrlOverride);
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalStateException("Conformance base URL not configured");
        }
        if (variant == null || variant.isEmpty()) {
            throw new IllegalArgumentException("Missing conformance plan variant selection");
        }
        String variantJson;
        try {
            variantJson = objectMapper.writeValueAsString(variant);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize variant selection", e);
        }

        URI uri = UriComponentsBuilder.fromUriString(trimTrailingSlash(baseUrl) + "/api/plan")
                .queryParam("planName", planName.trim())
                .queryParam("variant", variantJson)
                .build()
                .encode(StandardCharsets.UTF_8)
                .toUri();

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_JSON);
        String apiKey = apiKeyOverride;
        if (apiKey != null && !apiKey.isBlank()) {
            headers.setBearerAuth(apiKey);
        }

        ResponseEntity<Map> response = restTemplate.exchange(uri, HttpMethod.POST, new HttpEntity<>(config, headers), Map.class);
        if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
            throw new IllegalStateException("Failed to create conformance plan (HTTP " + response.getStatusCode().value() + ")");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getBody();
        String id = firstNonBlank(stringValue(body.get("id")), stringValue(body.get("_id")));
        if (id == null || id.isBlank()) {
            throw new IllegalStateException("Conformance suite did not return a plan id");
        }
        return id;
    }

    public ConformanceRunStart runTestModuleDetailed(String planId, String testModule, String baseUrlOverride, String apiKeyOverride) {
        if (planId == null || planId.isBlank()) {
            throw new IllegalArgumentException("Missing conformance plan id");
        }
        if (testModule == null || testModule.isBlank()) {
            throw new IllegalArgumentException("Missing conformance test module");
        }
        String baseUrl = normalizeBaseUrl(baseUrlOverride);
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalStateException("Conformance base URL not configured");
        }
        URI uri = UriComponentsBuilder.fromUriString(trimTrailingSlash(baseUrl) + "/api/runner")
                .queryParam("test", testModule.trim())
                .queryParam("plan", planId.trim())
                .build()
                .encode(StandardCharsets.UTF_8)
                .toUri();

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_JSON);
        String apiKey = apiKeyOverride;
        if (apiKey != null && !apiKey.isBlank()) {
            headers.setBearerAuth(apiKey);
        }

        ResponseEntity<Map> response = restTemplate.exchange(uri, HttpMethod.POST, new HttpEntity<>(headers), Map.class);
        if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
            throw new IllegalStateException("Failed to start conformance test run (HTTP " + response.getStatusCode().value() + ")");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getBody();
        String runId = firstNonBlank(stringValue(body.get("id")), stringValue(body.get("_id")));
        if (runId == null || runId.isBlank()) {
            throw new IllegalStateException("Conformance suite did not return a run id");
        }
        String runUrl = firstNonBlank(stringValue(body.get("url")), stringValue(body.get("testUrl")));
        return new ConformanceRunStart(runId, runUrl);
    }

    public Map<String, Object> loadTestInfo(String testId, String baseUrlOverride, String apiKeyOverride) {
        if (testId == null || testId.isBlank()) {
            throw new IllegalArgumentException("Missing conformance test id");
        }
        String baseUrl = normalizeBaseUrl(baseUrlOverride);
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalStateException("Conformance base URL not configured");
        }
        return fetchTestInfo(baseUrl, apiKeyOverride, testId.trim());
    }

    public List<Map<String, Object>> loadTestLog(String testId, Long since, String baseUrlOverride, String apiKeyOverride) {
        if (testId == null || testId.isBlank()) {
            throw new IllegalArgumentException("Missing conformance test id");
        }
        String baseUrl = normalizeBaseUrl(baseUrlOverride);
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalStateException("Conformance base URL not configured");
        }

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(trimTrailingSlash(baseUrl) + "/api/log/{testId}");
        Optional.ofNullable(since).filter(v -> v > 0).ifPresent(v -> builder.queryParam("since", v));
        URI uri = builder.buildAndExpand(testId.trim()).toUri();

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        String apiKey = apiKeyOverride;
        if (apiKey != null && !apiKey.isBlank()) {
            headers.setBearerAuth(apiKey);
        }

        ResponseEntity<List> response = restTemplate.exchange(uri, HttpMethod.GET, new HttpEntity<>(headers), List.class);
        if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
            throw new IllegalStateException("Failed to load conformance test log (HTTP " + response.getStatusCode().value() + ")");
        }
        List<?> items = response.getBody();
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object item : items) {
            if (item instanceof Map<?, ?> m) {
                out.add(mapValue(m));
            }
        }
        return out;
    }

    private ConformancePlan toPlan(Map<String, Object> body, String baseUrl, String apiKey) {
        String id = firstNonBlank(stringValue(body.get("id")), stringValue(body.get("_id")));
        String planName = stringValue(body.get("planName"));
        Map<String, Object> variant = mapValue(body.get("variant"));
        Map<String, Object> exported = mapValue(body.get("exported_values"));
        String authEndpoint = stringValue(exported.get("authorization_endpoint"));
        Map<String, Object> config = mapValue(body.get("config"));
        String alias = firstNonBlank(stringValue(config.get("alias")), stringValue(body.get("alias")));
        String description = firstNonBlank(stringValue(config.get("description")), stringValue(body.get("description")));
        List<Map<String, Object>> modules = listOfMaps(body.get("modules"));
        List<ConformanceModule> moduleViews = modules.stream().map(module -> toModule(module, baseUrl, apiKey)).toList();
        String raw = toPrettyJson(body);
        return new ConformancePlan(id, planName, variant, alias, description, authEndpoint, exported, moduleViews, raw);
    }

    private ConformanceModule toModule(Map<String, Object> module, String baseUrl, String apiKey) {
        String name = stringValue(module.get("testModule"));
        String summary = stringValue(module.get("testSummary"));
        Map<String, Object> variant = mapValue(module.get("variant"));
        List<Map<String, Object>> instances = listOfInstances(module.get("instances"), baseUrl, apiKey);
        return new ConformanceModule(name, summary, variant, instances, toPrettyJson(module));
    }

    private String toPrettyJson(Object value) {
        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(value);
        } catch (Exception e) {
            return String.valueOf(value);
        }
    }

    private String stringValue(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> mapValue(Object value) {
        if (value instanceof Map<?, ?> m) {
            Map<String, Object> out = new LinkedHashMap<>();
            m.forEach((k, v) -> out.put(String.valueOf(k), v));
            return out;
        }
        return Map.of();
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> listOfMaps(Object value) {
        if (value instanceof List<?> list) {
            return list.stream()
                    .filter(it -> it instanceof Map<?, ?>)
                    .map(it -> (Map<String, Object>) it)
                    .toList();
        }
        return List.of();
    }

    private List<Map<String, Object>> listOfInstances(Object value, String baseUrl, String apiKey) {
        if (value instanceof List<?> list) {
            List<Map<String, Object>> out = new ArrayList<>();
            for (Object it : list) {
                if (it instanceof Map<?, ?> m) {
                    out.add(mapValue(m));
                } else if (it != null) {
                    Map<String, Object> instance = new LinkedHashMap<>();
                    instance.put("id", String.valueOf(it));
                    out.add(instance);
                }
            }

            for (Map<String, Object> instance : out) {
                if (!instance.containsKey("id") && instance.get("_id") != null) {
                    instance.put("id", String.valueOf(instance.get("_id")));
                }
                if (!instance.containsKey("id") && instance.get("testId") != null) {
                    instance.put("id", String.valueOf(instance.get("testId")));
                }
            }

            int limit = Math.min(out.size(), MAX_INSTANCE_INFO_LOOKUP);
            for (int i = 0; i < limit; i++) {
                Map<String, Object> instance = out.get(i);
                String id = stringValue(instance.get("id"));
                if (id.isBlank()) {
                    continue;
                }
                if (instance.containsKey("status") || instance.containsKey("result") || instance.containsKey("started")) {
                    continue;
                }
                Map<String, Object> info = fetchTestInfo(baseUrl, apiKey, id);
                String status = stringValue(info.get("status"));
                String result = stringValue(info.get("result"));
                String started = stringValue(info.get("started"));
                if (!status.isBlank()) {
                    instance.put("status", status);
                }
                if (!result.isBlank()) {
                    instance.put("result", result);
                }
                if (!started.isBlank()) {
                    instance.put("started", started);
                }
            }
            return out;
        }
        return List.of();
    }

    private Map<String, Object> fetchTestInfo(String baseUrl, String apiKey, String testId) {
        if (testId == null || testId.isBlank()) {
            return Map.of();
        }
        try {
            URI uri = UriComponentsBuilder.fromUriString(trimTrailingSlash(baseUrl) + "/api/info/{testId}")
                    .buildAndExpand(testId.trim())
                    .toUri();
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            if (apiKey != null && !apiKey.isBlank()) {
                headers.setBearerAuth(apiKey);
            }
            ResponseEntity<Map> response = restTemplate.exchange(uri, HttpMethod.GET, new HttpEntity<>(headers), Map.class);
            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
                return Map.of();
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> body = (Map<String, Object>) response.getBody();
            return mapValue(body);
        } catch (Exception e) {
            return Map.of();
        }
    }

    private String trimTrailingSlash(String url) {
        if (url == null) {
            return null;
        }
        String trimmed = url.trim();
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    private String normalizeBaseUrl(String baseUrl) {
        String trimmed = trimTrailingSlash(baseUrl);
        if (trimmed == null || trimmed.isBlank()) {
            return null;
        }
        // Allow users to paste the API base URL and still build /api/plan/... correctly.
        if (trimmed.endsWith("/api")) {
            trimmed = trimTrailingSlash(trimmed.substring(0, trimmed.length() - "/api".length()));
        }
        return trimmed;
    }

    public record ConformancePlan(
            String id,
            String planName,
            Map<String, Object> variant,
            String alias,
            String description,
            String authorizationEndpoint,
            Map<String, Object> exportedValues,
            List<ConformanceModule> modules,
            String rawJson
    ) {
    }

    public record ConformanceModule(
            String testModule,
            String testSummary,
            Map<String, Object> variant,
            List<Map<String, Object>> instances,
            String rawJson
    ) {
    }

    public record ConformanceRunStart(String id, String url) {
    }
}
