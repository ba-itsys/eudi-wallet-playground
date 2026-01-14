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
package de.arbeitsagentur.keycloak.wallet.common.util;

import java.net.URI;

/**
 * Utility class for URL normalization operations.
 * Handles port normalization, base URL cleanup, and hostname extraction.
 */
public final class UrlNormalizer {

    private UrlNormalizer() {
        // Utility class
    }

    /**
     * Normalize a URL by removing redundant or incorrect port specifications.
     * <p>
     * Examples:
     * <ul>
     *   <li>{@code https://example.com:80/path} → {@code https://example.com/path}</li>
     *   <li>{@code https://example.com:443/path} → {@code https://example.com/path}</li>
     *   <li>{@code http://example.com:80/path} → {@code http://example.com/path}</li>
     *   <li>{@code http://example.com:443/path} → unchanged (non-standard)</li>
     * </ul>
     *
     * @param url the URL to normalize
     * @return the normalized URL, or the original if normalization fails
     */
    public static String normalizePort(String url) {
        if (url == null || url.isBlank()) {
            return url;
        }
        try {
            URI uri = URI.create(url);
            String scheme = uri.getScheme();
            int port = uri.getPort();

            if (port == -1) {
                return url;
            }

            boolean shouldRemovePort = false;
            if ("https".equalsIgnoreCase(scheme) && (port == 443 || port == 80)) {
                // HTTPS with port 443 (default) or port 80 (wrong) - remove the port
                shouldRemovePort = true;
            } else if ("http".equalsIgnoreCase(scheme) && port == 80) {
                // HTTP with port 80 (default) - remove the port
                shouldRemovePort = true;
            }

            if (shouldRemovePort) {
                return new URI(
                        uri.getScheme(),
                        uri.getUserInfo(),
                        uri.getHost(),
                        -1, // no port
                        uri.getPath(),
                        uri.getQuery(),
                        uri.getFragment()
                ).toString();
            }
            return url;
        } catch (Exception e) {
            return url;
        }
    }

    /**
     * Normalize a base URL by removing trailing slashes and /api suffix.
     *
     * @param value the base URL to normalize
     * @return the normalized base URL, or null if empty
     */
    public static String normalizeBaseUrl(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        if (trimmed.endsWith("/api")) {
            trimmed = trimmed.substring(0, trimmed.length() - "/api".length());
        }
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed.isBlank() ? null : trimmed;
    }

    /**
     * Extract and normalize a hostname from a URL or prefixed string.
     * <p>
     * This handles various input formats:
     * <ul>
     *   <li>Full URLs: {@code https://example.com/path} → {@code example.com}</li>
     *   <li>x509 prefixed: {@code x509_san_dns:example.com} → {@code example.com}</li>
     *   <li>Plain hostname: {@code example.com} → {@code example.com}</li>
     *   <li>Hostname with port: {@code example.com:8080} → {@code example.com}</li>
     * </ul>
     *
     * @param value the input string to extract hostname from
     * @return the extracted hostname, or null if empty
     */
    public static String extractHostname(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.isBlank()) {
            return null;
        }

        // Try to parse as URI first
        try {
            URI uri = URI.create(trimmed);
            if (uri.getHost() != null && !uri.getHost().isBlank()) {
                trimmed = uri.getHost();
            }
        } catch (Exception ignored) {
            // Not a valid URI, continue with string processing
        }

        // Remove known prefixes
        String[] prefixes = {"x509_san_dns:", "x509_hash:", "verifier_attestation:"};
        boolean stripped = true;
        while (stripped) {
            stripped = false;
            for (String prefix : prefixes) {
                if (trimmed.startsWith(prefix)) {
                    trimmed = trimmed.substring(prefix.length());
                    stripped = true;
                }
            }
        }

        // Remove path
        int slash = trimmed.indexOf('/');
        if (slash >= 0) {
            trimmed = trimmed.substring(0, slash);
        }

        // Remove port
        int colon = trimmed.indexOf(':');
        if (colon >= 0) {
            trimmed = trimmed.substring(0, colon);
        }

        return trimmed.isBlank() ? null : trimmed;
    }

    /**
     * Check if a port should be omitted for the given scheme.
     * <p>
     * Returns true for:
     * <ul>
     *   <li>HTTP with port 80 (default)</li>
     *   <li>HTTPS with port 443 (default)</li>
     *   <li>HTTPS with port 80 (invalid - sometimes sent by ngrok)</li>
     * </ul>
     *
     * @param scheme the URL scheme (http or https)
     * @param port the port number
     * @return true if the port should be omitted
     */
    public static boolean shouldOmitPort(String scheme, int port) {
        if (scheme == null) {
            return false;
        }
        return (scheme.equalsIgnoreCase("http") && port == 80)
                || (scheme.equalsIgnoreCase("https") && (port == 443 || port == 80));
    }

    /**
     * Parse a public base URL and ensure it ends with a trailing slash.
     *
     * @param publicBaseUrl the base URL to parse
     * @return the parsed URI, or null if invalid
     */
    public static URI parsePublicBaseUri(String publicBaseUrl) {
        if (publicBaseUrl == null || publicBaseUrl.isBlank()) {
            return null;
        }
        String normalized = publicBaseUrl.trim();
        if (!normalized.endsWith("/")) {
            normalized = normalized + "/";
        }
        try {
            return URI.create(normalized);
        } catch (Exception e) {
            return null;
        }
    }
}
