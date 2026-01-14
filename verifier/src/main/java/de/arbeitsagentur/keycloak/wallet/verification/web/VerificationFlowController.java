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
package de.arbeitsagentur.keycloak.wallet.verification.web;

import de.arbeitsagentur.keycloak.wallet.common.debug.DebugLogService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Comparator;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/verifier/api")
public class VerificationFlowController {
    private final DebugLogService debugLogService;

    public VerificationFlowController(DebugLogService debugLogService) {
        this.debugLogService = debugLogService;
    }

    @GetMapping("/flow/{state}")
    public ResponseEntity<Object> flow(@PathVariable("state") String state) {
        if (state == null || state.isBlank()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .body(Map.of("error", "Missing state"));
        }

        List<DebugLogService.DebugEntry> entries = debugLogService.verification().stream()
                .filter(entry -> state.equals(entry.group()))
                .sorted(Comparator.comparing(DebugLogService.DebugEntry::timestamp))
                .toList();

        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(entries);
    }
}

