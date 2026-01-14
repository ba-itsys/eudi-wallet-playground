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
package de.arbeitsagentur.keycloak.oid4vp.idp;

import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builder for DCQL (Digital Credentials Query Language) queries.
 * <p>
 * Constructs DCQL queries from credential type specifications, supporting:
 * - Multiple credential types (SD-JWT VC and mso_mdoc)
 * - Claim path specifications per credential type
 * - credential_sets for multi-credential requests (optional/all modes)
 * - claim_sets for optional claims within a credential
 */
public class DcqlQueryBuilder {

    private final ObjectMapper objectMapper;
    private final List<CredentialTypeSpec> credentialTypes = new ArrayList<>();
    private boolean allCredentialsRequired = false;
    private String purpose;

    /**
     * Specification for a single claim with optional flag.
     */
    public record ClaimSpec(String path, boolean optional) {
        public ClaimSpec(String path) {
            this(path, false);
        }
    }

    /**
     * Specification for a credential type to request.
     */
    public record CredentialTypeSpec(String format, String type, List<ClaimSpec> claimSpecs) {
        public CredentialTypeSpec(String format, String type) {
            this(format, type, List.of());
        }

        /**
         * Convenience constructor for simple claim paths (all required).
         */
        public static CredentialTypeSpec fromPaths(String format, String type, List<String> claimPaths) {
            List<ClaimSpec> specs = claimPaths.stream()
                    .map(ClaimSpec::new)
                    .toList();
            return new CredentialTypeSpec(format, type, specs);
        }
    }

    public DcqlQueryBuilder(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Add a credential type to request with claim specifications.
     */
    public DcqlQueryBuilder addCredentialType(String format, String type, List<ClaimSpec> claimSpecs) {
        credentialTypes.add(new CredentialTypeSpec(format, type, claimSpecs != null ? claimSpecs : List.of()));
        return this;
    }

    /**
     * Add a credential type to request with simple claim paths (all required).
     */
    public DcqlQueryBuilder addCredentialTypeWithPaths(String format, String type, List<String> claimPaths) {
        return addCredentialType(format, type,
                claimPaths != null ? claimPaths.stream().map(ClaimSpec::new).toList() : List.of());
    }

    /**
     * Add a credential type to request without specific claims.
     */
    public DcqlQueryBuilder addCredentialType(String format, String type) {
        return addCredentialType(format, type, List.of());
    }

    /**
     * Set whether all credentials are required (true) or any one suffices (false).
     * Only applicable when multiple credential types are added.
     */
    public DcqlQueryBuilder setAllCredentialsRequired(boolean required) {
        this.allCredentialsRequired = required;
        return this;
    }

    /**
     * Set the purpose description for the credential request.
     * This is optional and will be included in credential_sets if set.
     */
    public DcqlQueryBuilder setPurpose(String purpose) {
        this.purpose = purpose;
        return this;
    }

    /**
     * Build the DCQL query JSON string.
     * <p>
     * If optional claims are present, generates claim_sets with two options:
     * 1. All claims (required + optional)
     * 2. Only required claims
     */
    public String build() {
        if (credentialTypes.isEmpty()) {
            return buildDefaultDcql();
        }

        try {
            List<Map<String, Object>> credentials = new ArrayList<>();
            List<String> credentialIds = new ArrayList<>();
            int credIndex = 1;

            for (CredentialTypeSpec typeSpec : credentialTypes) {
                String credId = "cred" + credIndex++;
                credentialIds.add(credId);

                Map<String, Object> credential = new LinkedHashMap<>();
                credential.put("id", credId);
                credential.put("format", typeSpec.format());

                // Add type constraint in meta
                Map<String, Object> meta = new LinkedHashMap<>();
                if (Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC.equals(typeSpec.format())) {
                    meta.put("doctype_value", typeSpec.type());
                } else {
                    meta.put("vct_values", List.of(typeSpec.type()));
                }
                credential.put("meta", meta);

                // Add claims if specified
                if (!typeSpec.claimSpecs().isEmpty()) {
                    List<Map<String, Object>> claims = new ArrayList<>();
                    List<String> requiredClaimIds = new ArrayList<>();
                    List<String> allClaimIds = new ArrayList<>();
                    boolean hasOptionalClaims = false;
                    int claimIndex = 1;

                    for (ClaimSpec claimSpec : typeSpec.claimSpecs()) {
                        String claimId = "claim" + claimIndex++;
                        Map<String, Object> claim = new LinkedHashMap<>();
                        claim.put("id", claimId);

                        // Use '/' as path separator to allow dotted namespaces
                        // e.g., "eu.europa.ec.eudi.pid.1/family_name" -> ["eu.europa.ec.eudi.pid.1", "family_name"]
                        String path = claimSpec.path();
                        if (path.contains("/")) {
                            claim.put("path", Arrays.asList(path.split("/")));
                        } else {
                            claim.put("path", List.of(path));
                        }
                        claims.add(claim);

                        // Track claim IDs for claim_sets
                        allClaimIds.add(claimId);
                        if (!claimSpec.optional()) {
                            requiredClaimIds.add(claimId);
                        } else {
                            hasOptionalClaims = true;
                        }
                    }
                    credential.put("claims", claims);

                    // Add claim_sets if there are optional claims
                    // Option 1: All claims (required + optional) - preferred
                    // Option 2: Only required claims - fallback
                    if (hasOptionalClaims && !requiredClaimIds.isEmpty()) {
                        List<List<String>> claimSetOptions = new ArrayList<>();
                        claimSetOptions.add(allClaimIds);       // All claims (preferred)
                        claimSetOptions.add(requiredClaimIds);  // Required only (fallback)
                        credential.put("claim_sets", claimSetOptions);
                    }
                }

                credentials.add(credential);
            }

            Map<String, Object> dcqlQuery = new LinkedHashMap<>();
            dcqlQuery.put("credentials", credentials);

            // Add credential_sets if multiple credential types
            if (credentials.size() > 1) {
                Map<String, Object> credentialSet = new LinkedHashMap<>();

                // Add purpose if specified
                if (purpose != null && !purpose.isBlank()) {
                    credentialSet.put("purpose", purpose);
                }

                if (allCredentialsRequired) {
                    // All credentials required: single option with all IDs
                    credentialSet.put("options", List.of(credentialIds));
                } else {
                    // Any one credential satisfies: each ID as separate option
                    List<List<String>> options = new ArrayList<>();
                    for (String id : credentialIds) {
                        options.add(List.of(id));
                    }
                    credentialSet.put("options", options);
                }

                dcqlQuery.put("credential_sets", List.of(credentialSet));
            }

            return objectMapper.writeValueAsString(dcqlQuery);
        } catch (Exception e) {
            throw new RuntimeException("Failed to build DCQL query", e);
        }
    }

    private String buildDefaultDcql() {
        return "{\"credentials\":[{\"id\":\"cred1\",\"claims\":[{\"path\":[\"given_name\"]},{\"path\":[\"family_name\"]}]}]}";
    }

    /**
     * Create a builder from aggregated mapper information.
     * This is a convenience method for use with IdP mappers.
     */
    public static DcqlQueryBuilder fromMapperSpecs(ObjectMapper objectMapper,
                                                    Map<String, CredentialTypeSpec> credentialTypes,
                                                    boolean allCredentialsRequired,
                                                    String purpose) {
        DcqlQueryBuilder builder = new DcqlQueryBuilder(objectMapper);
        builder.setAllCredentialsRequired(allCredentialsRequired);
        builder.setPurpose(purpose);
        for (CredentialTypeSpec spec : credentialTypes.values()) {
            builder.credentialTypes.add(spec);
        }
        return builder;
    }

    /**
     * Create a builder from simple path lists (all claims required).
     * This is a convenience method for backward compatibility.
     */
    public static DcqlQueryBuilder fromSimplePaths(ObjectMapper objectMapper,
                                                    Map<String, List<String>> claimPathsByType,
                                                    Map<String, String> formatByType,
                                                    boolean allCredentialsRequired,
                                                    String purpose) {
        Map<String, CredentialTypeSpec> specs = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> entry : claimPathsByType.entrySet()) {
            String typeKey = entry.getKey();
            String[] parts = typeKey.split("\\|", 2);
            String format = formatByType.get(typeKey);
            String type = parts.length > 1 ? parts[1] : parts[0];
            specs.put(typeKey, CredentialTypeSpec.fromPaths(format, type, entry.getValue()));
        }
        return fromMapperSpecs(objectMapper, specs, allCredentialsRequired, purpose);
    }
}
