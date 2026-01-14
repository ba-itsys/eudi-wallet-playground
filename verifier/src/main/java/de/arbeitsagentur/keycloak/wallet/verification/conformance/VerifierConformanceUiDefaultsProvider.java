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
package de.arbeitsagentur.keycloak.wallet.verification.conformance;

import de.arbeitsagentur.keycloak.wallet.common.conformance.ConformanceUiDefaultsProvider;
import de.arbeitsagentur.keycloak.wallet.verification.service.DcqlService;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerifierCryptoService;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerifierKeyService;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

@Service
public class VerifierConformanceUiDefaultsProvider implements ConformanceUiDefaultsProvider {
    private final DcqlService dcqlService;
    private final VerifierCryptoService verifierCryptoService;
    private final VerifierKeyService verifierKeyService;
    private final ObjectMapper objectMapper;

    public VerifierConformanceUiDefaultsProvider(DcqlService dcqlService,
                                                 VerifierCryptoService verifierCryptoService,
                                                 VerifierKeyService verifierKeyService,
                                                 ObjectMapper objectMapper) {
        this.dcqlService = dcqlService;
        this.verifierCryptoService = verifierCryptoService;
        this.verifierKeyService = verifierKeyService;
        this.objectMapper = objectMapper;
    }

    @Override
    public ConformanceUiDefaults defaults() {
        String walletClientId = "";
        try {
            VerifierCryptoService.X509Material x509Material = verifierCryptoService.resolveX509Material(null);
            walletClientId = verifierCryptoService.deriveX509SanClientId(null, x509Material.certificatePem());
        } catch (Exception ignored) {
            walletClientId = "";
        }
        String dcql = "";
        try {
            String value = dcqlService.defaultDcqlQuery();
            dcql = value != null ? value : "";
        } catch (Exception ignored) {
            dcql = "";
        }
        return new ConformanceUiDefaults(walletClientId != null ? walletClientId : "", defaultClientMetadata(), dcql);
    }

    private String defaultClientMetadata() {
        try {
            String jwks = verifierKeyService.publicJwksJson();
            JsonNode node = objectMapper.readTree(jwks);
            ObjectNode meta = objectMapper.createObjectNode();
            meta.set("jwks", node);
            ObjectNode formats = meta.putObject("vp_formats_supported");
            ObjectNode sdJwt = objectMapper.createObjectNode();
            sdJwt.putArray("sd-jwt_alg_values").add("ES256");
            sdJwt.putArray("kb-jwt_alg_values").add("ES256");
            formats.set("dc+sd-jwt", sdJwt);
            ObjectNode mdoc = objectMapper.createObjectNode();
            mdoc.putArray("issuerauth_alg_values").add(-7);
            mdoc.putArray("deviceauth_alg_values").add(-7);
            formats.set("mso_mdoc", mdoc);
            return objectMapper.writeValueAsString(meta);
        } catch (Exception e) {
            return "";
        }
    }
}
