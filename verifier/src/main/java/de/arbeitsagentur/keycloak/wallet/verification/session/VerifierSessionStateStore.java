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
package de.arbeitsagentur.keycloak.wallet.verification.session;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class VerifierSessionStateStore {
    private static final Duration TTL = Duration.ofMinutes(15);
    private final Map<String, StoredSession> store = new ConcurrentHashMap<>();

    public void put(VerifierSession session) {
        if (session == null || session.state() == null || session.state().isBlank()) {
            return;
        }
        cleanupExpired();
        store.put(session.state(), new StoredSession(session, Instant.now().plus(TTL)));
    }

    public VerifierSession get(String state) {
        if (state == null || state.isBlank()) {
            return null;
        }
        StoredSession stored = store.get(state);
        if (stored == null) {
            return null;
        }
        if (stored.expiresAt().isBefore(Instant.now())) {
            store.remove(state);
            return null;
        }
        return stored.session();
    }

    public void remove(String state) {
        if (state == null || state.isBlank()) {
            return;
        }
        store.remove(state);
    }

    private void cleanupExpired() {
        Instant now = Instant.now();
        store.entrySet().removeIf(entry -> entry.getValue().expiresAt().isBefore(now));
    }

    private record StoredSession(VerifierSession session, Instant expiresAt) {
    }
}

