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
package de.arbeitsagentur.keycloak.wallet.common.debug;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedDeque;

@Component
public class DebugLogService {
    private static final int MAX_ENTRIES = 50;

    private final Deque<DebugEntry> issuanceLog = new ConcurrentLinkedDeque<>();
    private final Deque<DebugEntry> verificationLog = new ConcurrentLinkedDeque<>();

    public void addIssuance(String title, String method, String url, Map<String, String> requestHeaders,
                            String requestBody, Integer status, Map<String, String> responseHeaders,
                            String responseBody, String specLink, String decoded) {
        addIssuance("Issuance", null, title, method, url, requestHeaders, requestBody, status, responseHeaders, responseBody, specLink, decoded);
    }

    public void addIssuance(String group, String subgroup, String title, String method, String url,
                            Map<String, String> requestHeaders, String requestBody, Integer status,
                            Map<String, String> responseHeaders, String responseBody, String specLink,
                            String decoded) {
        addEntry(issuanceLog, group, subgroup, title, method, url, requestHeaders, requestBody, status, responseHeaders, responseBody, specLink, decoded);
    }

    public void addVerification(String title, String method, String url, Map<String, String> requestHeaders,
                                String requestBody, Integer status, Map<String, String> responseHeaders,
                                String responseBody, String specLink, String decoded) {
        addVerification("Verification", null, title, method, url, requestHeaders, requestBody, status, responseHeaders, responseBody, specLink, decoded);
    }

    public void addVerification(String group, String subgroup, String title, String method, String url,
                                Map<String, String> requestHeaders, String requestBody, Integer status,
                                Map<String, String> responseHeaders, String responseBody, String specLink,
                                String decoded) {
        addEntry(verificationLog, group, subgroup, title, method, url, requestHeaders, requestBody, status, responseHeaders, responseBody, specLink, decoded);
    }

    public void addVerificationAt(Instant timestamp,
                                  String group, String subgroup, String title, String method, String url,
                                  Map<String, String> requestHeaders, String requestBody, Integer status,
                                  Map<String, String> responseHeaders, String responseBody, String specLink,
                                  String decoded) {
        addEntry(verificationLog, group, subgroup, title, method, url, requestHeaders, requestBody, status, responseHeaders, responseBody, specLink, decoded,
                timestamp != null ? timestamp : Instant.now());
    }

    public List<DebugEntry> issuance() {
        return snapshot(issuanceLog);
    }

    public List<DebugEntry> verification() {
        return snapshot(verificationLog);
    }

    private void addEntry(Deque<DebugEntry> target, String group, String subgroup, String title, String method,
                          String url, Map<String, String> requestHeaders, String requestBody, Integer status,
                          Map<String, String> responseHeaders, String responseBody, String specLink, String decoded) {
        addEntry(target, group, subgroup, title, method, url, requestHeaders, requestBody, status, responseHeaders, responseBody, specLink, decoded,
                Instant.now());
    }

    private void addEntry(Deque<DebugEntry> target, String group, String subgroup, String title, String method,
                          String url, Map<String, String> requestHeaders, String requestBody, Integer status,
                          Map<String, String> responseHeaders, String responseBody, String specLink, String decoded,
                          Instant timestamp) {
        target.addFirst(new DebugEntry(group == null || group.isBlank() ? "General" : group,
                subgroup,
                title,
                safe(method),
                safe(url),
                copyHeaders(requestHeaders),
                safe(requestBody),
                status,
                copyHeaders(responseHeaders),
                safe(responseBody),
                specLink,
                timestamp != null ? timestamp : Instant.now(),
                safe(decoded)));
        while (target.size() > MAX_ENTRIES) {
            target.removeLast();
        }
    }

    private List<DebugEntry> snapshot(Deque<DebugEntry> source) {
        return new ArrayList<>(source);
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }

    private Map<String, String> copyHeaders(Map<String, String> headers) {
        if (headers == null || headers.isEmpty()) {
            return Map.of();
        }
        Map<String, String> copy = new LinkedHashMap<>();
        headers.forEach((k, v) -> copy.put(k, v == null ? "" : v));
        return copy;
    }

    public record DebugEntry(String group, String subgroup, String title,
                             String method, String url,
                             Map<String, String> requestHeaders, String requestBody,
                             Integer responseStatus, Map<String, String> responseHeaders, String responseBody,
                             String specLink, Instant timestamp, String decoded) {
    }
}
