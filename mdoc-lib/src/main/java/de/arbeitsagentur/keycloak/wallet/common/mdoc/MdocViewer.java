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

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

/**
 * Utility to detect and pretty-print mDoc tokens (CBOR hex) for UI views.
 */
public class MdocViewer {
    private final ObjectMapper objectMapper;
    private final MdocParser parser;

    public MdocViewer(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.parser = new MdocParser();
    }

    public boolean hasMdocToken(List<String> tokens, Function<String, String> decryptor) {
        if (tokens == null || tokens.isEmpty()) {
            return false;
        }
        return tokens.stream().anyMatch(token -> extractMdocToken(token, decryptor) != null);
    }

    public List<String> views(List<String> tokens, Function<String, String> decryptor) {
        if (tokens == null || tokens.isEmpty()) {
            return List.of();
        }
        List<String> views = new ArrayList<>();
        for (String token : tokens) {
            String mdocToken = extractMdocToken(token, decryptor);
            if (mdocToken == null) {
                continue;
            }
            String pretty = parser.prettyPrint(mdocToken);
            if (pretty == null || pretty.isBlank()) {
                String sample = mdocToken.length() > 80 ? mdocToken.substring(0, 80) + "..." : mdocToken;
                pretty = "{ \"error\": \"Unable to decode mDoc locally\", \"sample\": \"" + sample + "\" }";
            }
            views.add(pretty);
        }
        return views.isEmpty() ? Collections.emptyList() : views;
    }

    String extractMdocToken(String token, Function<String, String> decryptor) {
        if (token == null || token.isBlank()) {
            return null;
        }
        String decrypted = decryptor != null ? decryptor.apply(token) : token;
        if (parser.isMdoc(decrypted)) {
            return decrypted;
        }
        String embedded = extractEmbeddedVpToken(decrypted);
        if (parser.isMdoc(embedded)) {
            return embedded;
        }
        try {
            JsonNode node = objectMapper.readTree(decrypted);
            if (node.isArray() && node.size() > 0 && node.get(0).isTextual()) {
                String candidate = node.get(0).asText();
                if (parser.isMdoc(candidate)) {
                    return candidate;
                }
            }
            if (node.isTextual() && parser.isMdoc(node.asText())) {
                return node.asText();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private String extractEmbeddedVpToken(String token) {
        if (token == null || token.isBlank()) {
            return null;
        }
        if (!token.contains(".")) {
            return null;
        }
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return null;
            }
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            JsonNode node = objectMapper.readTree(payload);
            JsonNode vp = node.path("vp_token");
            if (vp.isMissingNode() || vp.isNull()) {
                return null;
            }
            if (vp.isTextual()) {
                return vp.asText();
            }
            if (vp.isArray() && vp.size() > 0) {
                JsonNode first = vp.get(0);
                return first.isTextual() ? first.asText() : first.toString();
            }
            if (vp.isObject()) {
                return vp.toString();
            }
            return vp.asText(null);
        } catch (Exception e) {
            return null;
        }
    }
}
