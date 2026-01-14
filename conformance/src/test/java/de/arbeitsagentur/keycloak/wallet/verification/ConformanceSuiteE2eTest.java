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
package de.arbeitsagentur.keycloak.wallet.verification;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import tools.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.net.URI;
import java.net.URLEncoder;
import java.net.ServerSocket;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

class ConformanceSuiteE2eTest {
    private static final Logger LOG = LoggerFactory.getLogger(ConformanceSuiteE2eTest.class);

    private static final Duration MAX_WAIT = Duration.ofMinutes(15);
    private static final Duration POLL_INTERVAL = Duration.ofSeconds(2);
    private static final Duration NGROK_START_TIMEOUT = Duration.ofSeconds(30);

    @Test
    @Timeout(40 * 60)
    void conformancePlanCreatedAndRunFinishesSuccessfullyWhenEnabled() throws Exception {
        // Skip in CI environments - these tests require external resources (ngrok, OIDF conformance API)
        Assumptions.assumeFalse("true".equalsIgnoreCase(System.getenv("CI")),
                "Skipping conformance E2E in CI environment");

        Map<String, String> dotenv = loadDotEnv();
        String baseUrl = firstNonBlank(
                System.getenv("VERIFIER_CONFORMANCE_BASE_URL"),
                System.getenv("OIDF_CONFORMANCE_BASE_URL"),
                dotenv.get("VERIFIER_CONFORMANCE_BASE_URL"),
                "https://demo.certification.openid.net");
        String apiKey = firstNonBlank(
                System.getenv("VERIFIER_CONFORMANCE_API_KEY"),
                System.getenv("OIDF_CONFORMANCE_API_KEY"),
                dotenv.get("VERIFIER_CONFORMANCE_API_KEY"));

        Assumptions.assumeTrue(isNonBlank(apiKey),
                "Skipping OIDF conformance E2E; set VERIFIER_CONFORMANCE_API_KEY (env vars or .env file)");
        assertThat(isNgrokAvailable())
                .as("ngrok binary not found on PATH; install ngrok to run the OIDF conformance E2E test")
                .isTrue();

        int port = FreePort.find();
        try (NgrokTunnel tunnel = NgrokTunnel.start(port, NGROK_START_TIMEOUT)) {
            URI publicBaseUrl = URI.create(tunnel.publicUrl());

            Map<String, Object> appProps = new LinkedHashMap<>();
            appProps.put("server.port", String.valueOf(port));
            appProps.put("spring.main.banner-mode", "off");
            appProps.put("wallet.public-base-url", publicBaseUrl.toString());
            appProps.put("verifier.conformance.base-url", baseUrl);
            appProps.put("verifier.conformance.api-key", apiKey);

            // Minimal wallet.* config to satisfy @ConfigurationProperties validation in the demo application context.
            appProps.put("wallet.keycloak-base-url", "http://keycloak.test.invalid");
            appProps.put("wallet.realm", "wallet-demo");
            appProps.put("wallet.client-id", "wallet-mock");
            appProps.put("wallet.client-secret", "secret");
            appProps.put("wallet.wallet-did", "did:example:test-wallet");
            appProps.put("wallet.storage-dir", "target/test-wallet-storage");
            appProps.put("wallet.wallet-key-file", "target/test-wallet-keys.json");

            // Ensure a fresh key file so the generated self-signed cert includes the ngrok host as a DNS SAN.
            appProps.put("verifier.keys-file", "target/test-verifier-keys-" + UUID.randomUUID() + ".json");

            try (ConfigurableApplicationContext context = new SpringApplicationBuilder(VerifierTestApplication.class)
                    .properties(appProps)
                    .run()) {
                ObjectMapper mapper = context.getBean(ObjectMapper.class);

                String planName = firstNonBlank(
                        System.getenv("VERIFIER_CONFORMANCE_PLAN_NAME"),
                        dotenv.get("VERIFIER_CONFORMANCE_PLAN_NAME"),
                        "oid4vp-1final-verifier-test-plan");
                String clientIdHost = publicBaseUrl.getHost();
                assertThat(clientIdHost).as("ngrok public URL did not contain a host").isNotBlank();

                CookieManager cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
                HttpClient localHttp = HttpClient.newBuilder()
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .cookieHandler(cookieManager)
                        .build();
                HttpClient http = HttpClient.newBuilder()
                        .followRedirects(HttpClient.Redirect.ALWAYS)
                        .cookieHandler(cookieManager)
                        .build();

                URI verifierBase = URI.create("http://127.0.0.1:" + port);
                HttpResponse<String> conformanceInitial = http.send(
                        HttpRequest.newBuilder(verifierBase.resolve("/verifier/conformance"))
                                .header("Accept", "text/html")
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
                assertThat(conformanceInitial.statusCode()).isEqualTo(200);

                List<Permutation> permutations = List.of(
                        new Permutation("sd_jwt_vc", "x509_san_dns"),
                        new Permutation("sd_jwt_vc", "x509_hash"),
                        new Permutation("iso_mdl", "x509_san_dns"),
                        new Permutation("iso_mdl", "x509_hash")
                );

                String configuredModule = firstNonBlank(
                        System.getenv("VERIFIER_CONFORMANCE_TEST_MODULE"),
                        dotenv.get("VERIFIER_CONFORMANCE_TEST_MODULE"));

                List<String> createdPlanIds = new ArrayList<>();
                boolean allPassed = false;
                try {
                    for (Permutation permutation : permutations) {
                        String alias = "verifier-e2e-" + permutation.credentialFormat() + "-" + permutation.clientIdPrefix() + "-"
                                + Instant.now().toString().replaceAll("[^0-9A-Za-z_-]", "");

                        HttpResponse<String> createResponse = postForm(localHttp, verifierBase.resolve("/verifier/conformance/create"), Map.of(
                                "planName", planName,
                                "credentialFormat", permutation.credentialFormat(),
                                "clientIdPrefix", permutation.clientIdPrefix(),
                                "clientIdHost", clientIdHost,
                                "alias", alias
                        ));
                        assertThat(createResponse.statusCode()).isBetween(300, 399);
                        String createLocation = createResponse.headers().firstValue("Location").orElse(null);
                        assertThat(createLocation).isNotBlank();

                        HttpResponse<String> afterCreate = http.send(
                                HttpRequest.newBuilder(resolveLocation(verifierBase, createLocation))
                                        .header("Accept", "text/html")
                                        .GET()
                                        .build(),
                                HttpResponse.BodyHandlers.ofString());
                        assertThat(afterCreate.statusCode()).isEqualTo(200);
                        String createHtml = afterCreate.body();

                        String planId = extractFirstGroup(createHtml, "id=\"conformancePlanId\"[^>]*value=\"([^\"]+)\"");
                        assertThat(planId).as("Unable to extract planId from conformance UI").isNotBlank();
                        createdPlanIds.add(planId);

                        String moduleFromUi = extractFirstGroup(createHtml, "id=\"conformanceModule\"[\\s\\S]*?<option[^>]*value=\"([^\"]+)\"");
                        String module = moduleFromUi;
                        if (isNonBlank(configuredModule) && createHtml.contains("value=\"" + configuredModule + "\"")) {
                            module = configuredModule;
                        }
                        assertThat(module)
                                .as("No test module found in plan and VERIFIER_CONFORMANCE_TEST_MODULE not set (planId=%s)", planId)
                                .isNotBlank();

                        HttpResponse<String> runResponse = postForm(localHttp, verifierBase.resolve("/verifier/conformance/run"), Map.of(
                                "planId", planId,
                                "module", module
                        ));
                        assertThat(runResponse.statusCode()).isBetween(300, 399);
                        String runLocation = runResponse.headers().firstValue("Location").orElse(null);
                        assertThat(runLocation).isNotBlank();

                        HttpResponse<String> afterRun = http.send(
                                HttpRequest.newBuilder(resolveLocation(verifierBase, runLocation))
                                        .header("Accept", "text/html")
                                        .GET()
                                        .build(),
                                HttpResponse.BodyHandlers.ofString());
                        assertThat(afterRun.statusCode()).isEqualTo(200);
                        String runHtml = afterRun.body();

                        String runId = extractFirstGroup(runHtml, "data-run-id=\"([^\"]+)\"");
                        assertThat(runId).as("Unable to extract runId from conformance UI").isNotBlank();

                        String authorizeUrl = extractFirstGroup(runHtml, "id=\"conformanceAuthEndpoint\"[^>]*value=\"([^\"]+)\"");
                        assertThat(authorizeUrl).as("Unable to extract authorization endpoint from conformance UI").isNotBlank();

                        awaitWaitingState(localHttp, mapper, verifierBase, runId, Duration.ofSeconds(60));

                        HttpResponse<String> startFlowResponse = localHttp.send(
                                HttpRequest.newBuilder(verifierBase.resolve("/verifier/conformance/start-flow"))
                                        .header("Accept", "application/json")
                                        .POST(HttpRequest.BodyPublishers.noBody())
                                        .build(),
                                HttpResponse.BodyHandlers.ofString());
                        assertThat(startFlowResponse.statusCode()).isEqualTo(200);
                        Map<String, Object> startFlowJson = mapper.readValue(startFlowResponse.body(), Map.class);
                        assertThat(Boolean.TRUE.equals(startFlowJson.get("started")))
                                .as("Expected start-flow to start the verifier flow. response=%s permutation=%s", startFlowJson, permutation)
                                .isTrue();
                        String state = stringValue(startFlowJson.get("state"));
                        assertThat(state).as("Missing state in start-flow response").isNotBlank();

                        HttpResponse<String> flowResponse = localHttp.send(
                                HttpRequest.newBuilder(verifierBase.resolve("/verifier/api/flow/" + URLEncoder.encode(state, StandardCharsets.UTF_8)))
                                        .header("Accept", "application/json")
                                        .GET()
                                        .build(),
                                HttpResponse.BodyHandlers.ofString());
                        assertThat(flowResponse.statusCode()).isEqualTo(200);
                        List<Map<String, Object>> flowEntries = mapper.readValue(flowResponse.body(), List.class);
                        assertThat(flowEntries)
                                .as("Expected verifier flow entries for state=%s. body=%s", state, flowResponse.body())
                                .isNotEmpty();

                        ConformanceRunResult result = awaitRunResult(localHttp, mapper, verifierBase, runId, MAX_WAIT);
                        if (!result.passed()) {
                            String tail = result.logTail() != null && !result.logTail().isBlank()
                                    ? "\n\nLog tail:\n" + result.logTail()
                                    : "";
                            throw new AssertionError("Conformance run did not pass. permutation=" + permutation + " status=" + result.status()
                                    + " result=" + result.result() + " runId=" + runId + " module=" + module + " planId=" + planId + tail);
                        }
                    }
                    allPassed = true;
                } finally {
                    if (allPassed) {
                        deleteConformancePlans(baseUrl, apiKey, createdPlanIds);
                    } else if (!createdPlanIds.isEmpty()) {
                        LOG.error("Conformance E2E failed; keeping created plan ids for debugging: {}",
                                String.join(", ", createdPlanIds));
                    }
                }
            }
        }
    }

    private ConformanceRunResult awaitRunResult(HttpClient http,
                                                ObjectMapper mapper,
                                                URI verifierBase,
                                                String runId,
                                                Duration timeout) {
        Instant deadline = Instant.now().plus(timeout);
        String lastStatus = "";
        String lastResult = "";
        String lastError = "";

        while (Instant.now().isBefore(deadline)) {
            try {
                Map<String, Object> info = loadRunInfo(http, mapper, verifierBase, runId);
                lastStatus = stringValue(info.get("status"));
                lastResult = stringValue(info.get("result"));
                lastError = "";
            } catch (Exception e) {
                lastError = e.getMessage() != null ? e.getMessage() : String.valueOf(e);
            }

            if (isFinished(lastStatus)) {
                break;
            }

            try {
                Thread.sleep(POLL_INTERVAL.toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        boolean passed = isPassed(lastStatus, lastResult);
        String logTail = null;
        if (!passed) {
            String tail = logTail(http, mapper, verifierBase, runId, 60);
            logTail = (lastError == null || lastError.isBlank())
                    ? tail
                    : ("Last error: " + lastError + (tail == null || tail.isBlank() ? "" : "\n" + tail));
        }
        return new ConformanceRunResult(lastStatus, lastResult, passed, logTail);
    }

    private void awaitWaitingState(HttpClient http,
                                   ObjectMapper mapper,
                                   URI verifierBase,
                                   String runId,
                                   Duration timeout) {
        Instant deadline = Instant.now().plus(timeout);
        String lastStatus = "";
        String lastError = "";

        while (Instant.now().isBefore(deadline)) {
            try {
                Map<String, Object> info = loadRunInfo(http, mapper, verifierBase, runId);
                lastStatus = stringValue(info.get("status"));
                lastError = "";
            } catch (Exception e) {
                lastError = e.getMessage() != null ? e.getMessage() : String.valueOf(e);
            }
            if ("WAITING".equalsIgnoreCase(lastStatus)) {
                return;
            }
            if (isFinished(lastStatus)) {
                throw new AssertionError("Conformance run entered terminal state before verifier started. status=" + lastStatus
                        + " runId=" + runId);
            }
            try {
                Thread.sleep(250);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        String err = lastError != null && !lastError.isBlank() ? " error=" + lastError : "";
        throw new AssertionError("Conformance run did not reach WAITING state in time. status=" + lastStatus + " runId=" + runId + err);
    }

    private String logTail(HttpClient http,
                           ObjectMapper mapper,
                           URI verifierBase,
                           String runId,
                           int maxLines) {
        List<Map<String, Object>> entries = loadRunLog(http, mapper, verifierBase, runId);
        if (entries == null || entries.isEmpty()) {
            return "";
        }
        List<String> lines = new ArrayList<>();
        for (Map<String, Object> e : entries) {
            String time = stringValue(e.get("time"));
            String src = stringValue(e.get("src"));
            String result = stringValue(e.get("result"));
            String msg = stringValue(e.get("msg"));
            String line = (time.isBlank() ? "" : time + " ") + (src.isBlank() ? "" : "[" + src + "] ")
                    + (result.isBlank() ? "" : result + " ") + msg;
            lines.add(line.trim());
        }
        int start = Math.max(0, lines.size() - Math.max(1, maxLines));
        return String.join("\n", lines.subList(start, lines.size()));
    }

    private boolean isFinished(String status) {
        String s = (status == null ? "" : status).trim().toUpperCase();
        return s.equals("FINISHED") || s.equals("INTERRUPTED");
    }

    private boolean isPassed(String status, String result) {
        String s = (status == null ? "" : status).trim().toUpperCase();
        String r = (result == null ? "" : result).trim().toUpperCase();
        return s.equals("FINISHED") && (r.equals("PASSED") || r.equals("SUCCESS"));
    }

    private HttpResponse<String> postForm(HttpClient http, URI uri, Map<String, String> params) throws Exception {
        String body = encodeForm(params);
        HttpRequest request = HttpRequest.newBuilder(uri)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "text/html")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isLessThan(400);
        return response;
    }

    private void deleteConformancePlans(String baseUrl, String apiKey, List<String> planIds) throws Exception {
        if (planIds == null || planIds.isEmpty()) {
            return;
        }
        String normalized = normalizeConformanceBaseUrl(baseUrl);
        if (normalized.isBlank()) {
            throw new IllegalArgumentException("Missing conformance base URL for plan deletion");
        }
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalArgumentException("Missing conformance API key for plan deletion");
        }
        URI apiBase = URI.create(normalized);
        HttpClient http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();

        List<String> failures = new ArrayList<>();
        for (String planId : planIds) {
            if (planId == null || planId.isBlank()) {
                continue;
            }
            URI deleteUri = apiBase.resolve("/api/plan/" + urlEncode(planId));
            HttpRequest request = HttpRequest.newBuilder(deleteUri)
                    .header("Authorization", "Bearer " + apiKey)
                    .header("Accept", "application/json")
                    .DELETE()
                    .build();

            HttpResponse<String> response = null;
            Exception lastError = null;
            for (int attempt = 0; attempt < 3; attempt++) {
                try {
                    response = http.send(request, HttpResponse.BodyHandlers.ofString());
                    lastError = null;
                } catch (Exception e) {
                    lastError = e;
                }
                if (lastError == null && response != null && response.statusCode() >= 200 && response.statusCode() < 300) {
                    break;
                }
                Thread.sleep(250L * (attempt + 1));
            }

            if (lastError != null) {
                failures.add("planId=" + planId + " error=" + lastError.getMessage());
                continue;
            }
            if (response == null || response.statusCode() < 200 || response.statusCode() >= 300) {
                failures.add("planId=" + planId + " http=" + (response == null ? "null" : response.statusCode()));
            }
        }

        if (!failures.isEmpty()) {
            throw new AssertionError("Conformance plan cleanup failed: " + String.join("; ", failures));
        }
    }

    private String normalizeConformanceBaseUrl(String baseUrl) {
        String base = baseUrl == null ? "" : baseUrl.trim();
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        if (base.endsWith("/api")) {
            base = base.substring(0, base.length() - 4);
        }
        return base;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> loadRunInfo(HttpClient http, ObjectMapper mapper, URI verifierBase, String runId) throws Exception {
        URI uri = verifierBase.resolve("/verifier/conformance/api/info/" + runId);
        HttpResponse<String> response = http.send(
                HttpRequest.newBuilder(uri)
                        .header("Accept", "application/json")
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            String body = response.body();
            String message = "info endpoint failed (HTTP " + response.statusCode() + ")";
            if (body != null && !body.isBlank()) {
                try {
                    Object parsed = mapper.readValue(body, Object.class);
                    if (parsed instanceof Map<?, ?> map && map.get("error") != null) {
                        message = message + ": " + map.get("error");
                    }
                } catch (Exception ignored) {
                }
            }
            throw new IllegalStateException(message);
        }

        Object parsed = mapper.readValue(response.body(), Object.class);
        if (parsed instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            map.forEach((k, v) -> out.put(String.valueOf(k), v));
            return out;
        }
        return Map.of();
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> loadRunLog(HttpClient http, ObjectMapper mapper, URI verifierBase, String runId) {
        try {
            URI uri = verifierBase.resolve("/verifier/conformance/api/log/" + runId);
            HttpResponse<String> response = http.send(
                    HttpRequest.newBuilder(uri)
                            .header("Accept", "application/json")
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() >= 300 || response.body() == null || response.body().isBlank()) {
                return List.of(Map.of(
                        "src", "VERIFIER",
                        "result", "ERROR",
                        "msg", "log endpoint failed (HTTP " + response.statusCode() + ")"
                ));
            }
            Object parsed = mapper.readValue(response.body(), Object.class);
            if (!(parsed instanceof List<?> list)) {
                return List.of();
            }
            List<Map<String, Object>> out = new ArrayList<>();
            for (Object item : list) {
                if (item instanceof Map<?, ?> map) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    map.forEach((k, v) -> row.put(String.valueOf(k), v));
                    out.add(row);
                }
            }
            return out;
        } catch (Exception e) {
            return List.of();
        }
    }

    private String encodeForm(Map<String, String> params) {
        if (params == null || params.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : params.entrySet()) {
            if (e.getKey() == null) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append('&');
            }
            sb.append(urlEncode(e.getKey())).append('=').append(urlEncode(e.getValue()));
        }
        return sb.toString();
    }

    private String urlEncode(String value) {
        if (value == null) {
            return "";
        }
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private URI resolveLocation(URI base, String location) {
        if (location == null || location.isBlank()) {
            return base;
        }
        return location.startsWith("http") ? URI.create(location) : base.resolve(location);
    }

    private String extractFirstGroup(String input, String pattern) {
        if (input == null || input.isBlank()) {
            return "";
        }
        Pattern compiled = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
        Matcher matcher = compiled.matcher(input);
        if (!matcher.find()) {
            return "";
        }
        String value = matcher.groupCount() >= 1 ? matcher.group(1) : "";
        return value == null ? "" : value;
    }

    private boolean isNgrokAvailable() {
        String path = System.getenv("PATH");
        if (path == null || path.isBlank()) {
            return false;
        }
        for (String part : path.split(File.pathSeparator)) {
            Path candidate = Path.of(part).resolve("ngrok");
            if (Files.exists(candidate) && Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
                return true;
            }
        }
        return false;
    }

    private boolean isNonBlank(String value) {
        return value != null && !value.isBlank();
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

    private Map<String, String> loadDotEnv() {
        Path dir = Path.of(System.getProperty("user.dir", ".")).toAbsolutePath();
        for (int i = 0; i < 6; i++) {
            Path candidate = dir.resolve(".env");
            if (Files.exists(candidate) && Files.isRegularFile(candidate)) {
                return parseDotEnv(candidate);
            }
            dir = dir.getParent();
            if (dir == null) {
                break;
            }
        }
        return Map.of();
    }

    private Map<String, String> parseDotEnv(Path file) {
        Map<String, String> out = new LinkedHashMap<>();
        try {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                String trimmed = line.trim();
                if (trimmed.isBlank() || trimmed.startsWith("#")) {
                    continue;
                }
                int idx = trimmed.indexOf('=');
                if (idx <= 0) {
                    continue;
                }
                String key = trimmed.substring(0, idx).trim();
                String value = trimmed.substring(idx + 1).trim();
                out.put(key, value);
            }
        } catch (IOException ignored) {
            return Map.of();
        }
        return out;
    }

    private record ConformanceRunResult(String status, String result, boolean passed, String logTail) {
    }

    private record Permutation(String credentialFormat, String clientIdPrefix) {
    }

    private static final class FreePort {
        private FreePort() {
        }

        static int find() {
            try (ServerSocket socket = new ServerSocket(0)) {
                socket.setReuseAddress(true);
                return socket.getLocalPort();
            } catch (IOException e) {
                throw new IllegalStateException("Unable to allocate free port", e);
            }
        }
    }

    private static final class NgrokTunnel implements AutoCloseable {
        private final Process process;
        private final Path logFile;
        private final String publicUrl;
        private final URI apiBase;
        private final String tunnelUri;

        private NgrokTunnel(Process process, Path logFile, String publicUrl, URI apiBase, String tunnelUri) {
            this.process = process;
            this.logFile = logFile;
            this.publicUrl = publicUrl;
            this.apiBase = apiBase;
            this.tunnelUri = tunnelUri;
        }

        static NgrokTunnel start(int localPort, Duration timeout) {
            try {
                HttpClient http = HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(2))
                        .build();
                ObjectMapper mapper = new ObjectMapper();

                URI runningApi = findRunningNgrokApi(http, mapper);
                if (runningApi != null) {
                    String tunnelName = "verifier-e2e-" + UUID.randomUUID().toString().replace("-", "");
                    URI createUri = runningApi.resolve("/api/tunnels");
                    Map<String, Object> createBody = Map.of(
                            "name", tunnelName,
                            "addr", "http://localhost:" + localPort,
                            "proto", "http"
                    );
                    HttpResponse<String> created = http.send(
                            HttpRequest.newBuilder(createUri)
                                    .header("Accept", "application/json")
                                    .header("Content-Type", "application/json")
                                    .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(createBody)))
                                    .build(),
                            HttpResponse.BodyHandlers.ofString());
                    if (created.statusCode() < 200 || created.statusCode() >= 300) {
                        throw new IllegalStateException("Failed to create tunnel via existing ngrok agent (HTTP " + created.statusCode() + ")");
                    }
                    var node = mapper.readTree(created.body());
                    String url = node.path("public_url").asText("");
                    String uri = node.path("uri").asText("");
                    if (url == null || url.isBlank()) {
                        throw new IllegalStateException("ngrok agent did not return a public_url for tunnel " + tunnelName);
                    }
                    String resolvedUri = (uri == null || uri.isBlank()) ? ("/api/tunnels/" + tunnelName) : uri;
                    return new NgrokTunnel(null, null, url, runningApi, resolvedUri);
                }

                Path log = Files.createTempFile("ngrok-verifier-e2e-", ".log");
                ProcessBuilder pb = new ProcessBuilder(
                        "ngrok",
                        "http",
                        String.valueOf(localPort),
                        "--log=stdout",
                        "--log-format=json"
                );
                pb.redirectErrorStream(true);
                pb.redirectOutput(log.toFile());
                Process proc = pb.start();

                Instant deadline = Instant.now().plus(timeout);
                while (Instant.now().isBefore(deadline)) {
                    if (!proc.isAlive()) {
                        throw new IllegalStateException("ngrok exited early. See: " + log);
                    }
                    try {
                        HttpResponse<String> resp = http.send(
                                HttpRequest.newBuilder(URI.create("http://127.0.0.1:4040/api/tunnels"))
                                        .header("Accept", "application/json")
                                        .GET()
                                        .build(),
                                HttpResponse.BodyHandlers.ofString());
                        if (resp.statusCode() >= 200 && resp.statusCode() < 300 && resp.body() != null && !resp.body().isBlank()) {
                            String url = extractHttpsPublicUrl(mapper, resp.body());
                            if (url != null && !url.isBlank()) {
                                return new NgrokTunnel(proc, log, url, URI.create("http://127.0.0.1:4040"), null);
                            }
                        }
                    } catch (Exception ignored) {
                    }
                    Thread.sleep(250);
                }
                throw new IllegalStateException("Timed out waiting for ngrok tunnel. See: " + log);
            } catch (Exception e) {
                throw new IllegalStateException("Failed to start ngrok tunnel", e);
            }
        }

        private static URI findRunningNgrokApi(HttpClient http, ObjectMapper mapper) {
            for (int port : new int[]{4040, 4041, 4042, 4043, 4044}) {
                try {
                    URI uri = URI.create("http://127.0.0.1:" + port + "/api/tunnels");
                    HttpResponse<String> resp = http.send(
                            HttpRequest.newBuilder(uri)
                                    .header("Accept", "application/json")
                                    .GET()
                                    .build(),
                            HttpResponse.BodyHandlers.ofString());
                    if (resp.statusCode() < 200 || resp.statusCode() >= 300 || resp.body() == null || resp.body().isBlank()) {
                        continue;
                    }
                    var root = mapper.readTree(resp.body());
                    var tunnels = root.get("tunnels");
                    if (tunnels != null && tunnels.isArray()) {
                        return URI.create("http://127.0.0.1:" + port);
                    }
                } catch (Exception ignored) {
                }
            }
            return null;
        }

        private static String extractHttpsPublicUrl(ObjectMapper mapper, String json) {
            try {
                var root = mapper.readTree(json);
                var tunnels = root.get("tunnels");
                if (tunnels == null || !tunnels.isArray()) {
                    return null;
                }
                for (var t : tunnels) {
                    String proto = t.path("proto").asText("");
                    if (!"https".equalsIgnoreCase(proto)) {
                        continue;
                    }
                    String url = t.path("public_url").asText("");
                    if (url != null && !url.isBlank()) {
                        return url;
                    }
                }
                return null;
            } catch (Exception e) {
                return null;
            }
        }

        String publicUrl() {
            return publicUrl;
        }

        @Override
        public void close() {
            if (apiBase != null && tunnelUri != null && !tunnelUri.isBlank()) {
                try {
                    HttpClient http = HttpClient.newBuilder()
                            .connectTimeout(Duration.ofSeconds(2))
                            .build();
                    http.send(
                            HttpRequest.newBuilder(apiBase.resolve(tunnelUri))
                                    .DELETE()
                                    .build(),
                            HttpResponse.BodyHandlers.discarding());
                } catch (Exception ignored) {
                }
            }
            try {
                if (process != null && process.isAlive()) {
                    process.destroy();
                    process.waitFor(5, TimeUnit.SECONDS);
                }
            } catch (Exception ignored) {
            }
            try {
                if (logFile != null) {
                    Files.deleteIfExists(logFile);
                }
            } catch (IOException ignored) {
            }
        }
    }
}
