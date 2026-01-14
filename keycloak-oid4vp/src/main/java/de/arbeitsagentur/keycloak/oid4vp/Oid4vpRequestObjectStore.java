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
package de.arbeitsagentur.keycloak.oid4vp;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory store for OID4VP request objects used in same-device and cross-device flows.
 * Request objects are stored with a TTL and can be retrieved via their unique ID.
 * Supports wallet_nonce for spec-compliant request object regeneration.
 */
public class Oid4vpRequestObjectStore {

    private static final Duration DEFAULT_TTL = Duration.ofMinutes(10);

    private final Map<String, StoredRequestObject> store = new ConcurrentHashMap<>();
    private final Duration ttl;

    public Oid4vpRequestObjectStore() {
        this(DEFAULT_TTL);
    }

    public Oid4vpRequestObjectStore(Duration ttl) {
        this.ttl = ttl;
    }

    /**
     * Store a request object and return its unique ID.
     *
     * @param requestObjectJwt The signed JWT request object
     * @param encryptionKeyJson The private JWK for response decryption (JSON string), may be null
     * @param state The OAuth state parameter for correlation
     * @param nonce The nonce for verification
     * @return Unique ID for retrieving the request object
     */
    public String store(String requestObjectJwt, String encryptionKeyJson, String state, String nonce) {
        return store(requestObjectJwt, encryptionKeyJson, state, nonce, null, null);
    }

    /**
     * Store a request object with session information and return its unique ID.
     *
     * @param requestObjectJwt The signed JWT request object
     * @param encryptionKeyJson The private JWK for response decryption (JSON string), may be null
     * @param state The OAuth state parameter for correlation
     * @param nonce The nonce for verification
     * @param rootSessionId The root authentication session ID for direct_post callback lookup
     * @param clientId The client ID for the auth session
     * @return Unique ID for retrieving the request object
     */
    public String store(String requestObjectJwt, String encryptionKeyJson, String state, String nonce,
                        String rootSessionId, String clientId) {
        return store(requestObjectJwt, encryptionKeyJson, state, nonce, rootSessionId, clientId, null);
    }

    /**
     * Store a request object with rebuild parameters for wallet_nonce support.
     *
     * @param requestObjectJwt The signed JWT request object
     * @param encryptionKeyJson The private JWK for response decryption (JSON string), may be null
     * @param state The OAuth state parameter for correlation
     * @param nonce The nonce for verification
     * @param rootSessionId The root authentication session ID for direct_post callback lookup
     * @param clientId The client ID for the auth session
     * @param rebuildParams Parameters needed to rebuild the request object with wallet_nonce
     * @return Unique ID for retrieving the request object
     */
    public String store(String requestObjectJwt, String encryptionKeyJson, String state, String nonce,
                        String rootSessionId, String clientId, RebuildParams rebuildParams) {
        cleanupExpired();
        String id = UUID.randomUUID().toString();
        Instant expiresAt = Instant.now().plus(ttl);
        store.put(id, new StoredRequestObject(requestObjectJwt, encryptionKeyJson, state, nonce,
                rootSessionId, clientId, rebuildParams, expiresAt));
        return id;
    }

    /**
     * Look up a stored request object by its state parameter.
     *
     * @param state The OAuth state parameter
     * @return The stored request object, or null if not found or expired
     */
    public StoredRequestObject resolveByState(String state) {
        if (state == null || state.isBlank()) {
            return null;
        }
        cleanupExpired();
        return store.values().stream()
                .filter(obj -> state.equals(obj.state()) && !obj.isExpired())
                .findFirst()
                .orElse(null);
    }

    /**
     * Retrieve a stored request object by its ID.
     *
     * @param id The unique ID returned by store()
     * @return The stored request object, or null if not found or expired
     */
    public StoredRequestObject resolve(String id) {
        if (id == null || id.isBlank()) {
            return null;
        }
        StoredRequestObject obj = store.get(id);
        if (obj == null) {
            return null;
        }
        if (obj.isExpired()) {
            store.remove(id);
            return null;
        }
        return obj;
    }

    /**
     * Remove a request object from the store.
     *
     * @param id The unique ID to remove
     */
    public void remove(String id) {
        if (id != null) {
            store.remove(id);
        }
    }

    /**
     * Remove all request objects with the given state from the store.
     * Used for cleanup after errors to allow clean retries.
     *
     * @param state The OAuth state parameter
     */
    public void removeByState(String state) {
        if (state != null && !state.isBlank()) {
            store.entrySet().removeIf(entry -> state.equals(entry.getValue().state()));
        }
    }

    /**
     * Remove expired entries from the store.
     */
    public void cleanupExpired() {
        Instant now = Instant.now();
        store.entrySet().removeIf(entry -> entry.getValue().expiresAt().isBefore(now));
    }

    /**
     * Parameters needed to rebuild a request object with wallet_nonce.
     */
    public record RebuildParams(
            String effectiveClientId,
            String clientIdScheme,
            String responseUri,
            String dcqlQuery,
            String x509CertPem,
            String x509SigningKeyJwk,
            String encryptionPublicKeyJson
    ) {}

    /**
     * Record representing a stored request object with its associated data.
     */
    public record StoredRequestObject(
            String requestObjectJwt,
            String encryptionKeyJson,
            String state,
            String nonce,
            String rootSessionId,
            String clientId,
            RebuildParams rebuildParams,
            Instant expiresAt
    ) {
        public boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }
}
