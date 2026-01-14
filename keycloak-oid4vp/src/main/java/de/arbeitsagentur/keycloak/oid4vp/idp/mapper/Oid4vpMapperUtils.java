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
package de.arbeitsagentur.keycloak.oid4vp.idp.mapper;

import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;

import java.util.Map;

/**
 * Shared utility methods for OID4VP identity provider mappers.
 */
public final class Oid4vpMapperUtils {

    private static final Logger LOG = Logger.getLogger(Oid4vpMapperUtils.class);

    private Oid4vpMapperUtils() {
        // Utility class
    }

    /**
     * Extract claim value from the BrokeredIdentityContext.
     * Claims are stored in context data by the OID4VP Identity Provider.
     *
     * @param context   The brokered identity context
     * @param claimPath The claim path (supports '/' for nested paths, e.g., 'address/city')
     * @return The claim value, or null if not found
     */
    @SuppressWarnings("unchecked")
    public static Object getClaimValue(BrokeredIdentityContext context, String claimPath) {
        // Claims are stored in context data by Oid4vpIdentityProvider.processCallback()
        Map<String, Object> claims = (Map<String, Object>) context.getContextData().get("oid4vp_claims");

        if (claims == null) {
            LOG.debugf("[OID4VP-MAPPER] No oid4vp_claims in context data");
            return null;
        }

        // Support nested paths like "address/city" -> claims["address"]["city"]
        // Using '/' allows dotted namespaces like "eu.europa.ec.eudi.pid.1/family_name"
        String[] pathParts = claimPath.split("/");
        Object current = claims;

        for (String part : pathParts) {
            if (current instanceof Map) {
                current = ((Map<?, ?>) current).get(part);
                if (current == null) {
                    return null;
                }
            } else {
                return null;
            }
        }

        return current;
    }
}
