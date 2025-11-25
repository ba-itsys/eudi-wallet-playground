package de.arbeitsagentur.keycloak.wallet.verification.service;

import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RequestObjectService {
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(10);
    private final Map<String, StoredRequestObject> store = new ConcurrentHashMap<>();

    public String store(String requestObject) {
        cleanupExpired();
        String id = UUID.randomUUID().toString();
        store.put(id, new StoredRequestObject(requestObject, Instant.now().plus(DEFAULT_TTL)));
        return id;
    }

    public String fetch(String id) {
        cleanupExpired();
        StoredRequestObject stored = store.get(id);
        if (stored == null) {
            return null;
        }
        if (stored.expiresAt().isBefore(Instant.now())) {
            store.remove(id);
            return null;
        }
        return stored.payload();
    }

    private void cleanupExpired() {
        Instant now = Instant.now();
        store.entrySet().removeIf(entry -> entry.getValue().expiresAt().isBefore(now));
    }

    private record StoredRequestObject(String payload, Instant expiresAt) {
    }
}
