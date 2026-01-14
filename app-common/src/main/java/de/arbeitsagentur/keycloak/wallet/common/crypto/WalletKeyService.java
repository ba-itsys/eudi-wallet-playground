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
package de.arbeitsagentur.keycloak.wallet.common.crypto;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import de.arbeitsagentur.keycloak.wallet.issuance.config.WalletProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

@Component
public class WalletKeyService {
    private final WalletProperties properties;
    private volatile ECKey cachedKey;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public WalletKeyService(WalletProperties properties) {
        this.properties = properties;
    }

    public ECKey loadOrCreateKey() {
        if (cachedKey != null) {
            return cachedKey;
        }
        synchronized (this) {
            if (cachedKey != null) {
                return cachedKey;
            }
            Path file = properties.walletKeyFile();
            try {
                if (Files.exists(file)) {
                    cachedKey = parseExistingKey(Files.readString(file));
                } else {
                    if (file.getParent() != null) {
                        Files.createDirectories(file.getParent());
                    }
                    ECKey newKey = new ECKeyGenerator(Curve.P_256)
                            .algorithm(JWSAlgorithm.ES256)
                            .keyID("wallet-es256")
                            .generate();
                    Map<String, JsonNode> payload = new HashMap<>();
                    payload.put("privateJwk", objectMapper.readTree(newKey.toJSONString()));
                    payload.put("publicJwk", objectMapper.readTree(newKey.toPublicJWK().toJSONString()));
                    objectMapper.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), payload);
                    cachedKey = newKey;
                }
            } catch (Exception e) {
                throw new IllegalStateException("Unable to load wallet key", e);
            }
            return cachedKey;
        }
    }

    private ECKey parseExistingKey(String json) throws IOException, ParseException {
        try {
            return ECKey.parse(json);
        } catch (ParseException parseException) {
            JsonNode node = objectMapper.readTree(json);
            if (node.has("privateJwk")) {
                return ECKey.parse(node.get("privateJwk").toString());
            }
            throw parseException;
        }
    }
}
