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
package de.arbeitsagentur.keycloak.oid4vp.idp.pidbinding;

import de.arbeitsagentur.keycloak.oid4vp.Oid4vpTrustListService;
import de.arbeitsagentur.keycloak.oid4vp.idp.DcqlQueryBuilder;
import de.arbeitsagentur.keycloak.oid4vp.idp.Oid4vpIdentityProvider;
import de.arbeitsagentur.keycloak.oid4vp.idp.Oid4vpIdentityProviderConfig;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * German PID Binding Identity Provider.
 * <p>
 * Implements a two-phase authentication flow for German PID credentials:
 * <ol>
 *   <li><b>First login</b>: User presents PID only, user is created, login credential is issued</li>
 *   <li><b>Subsequent logins</b>: User presents PID + login credential, login credential's user_id is used</li>
 * </ol>
 * <p>
 * The key insight is that German PID has no claim suitable as a persistent unique subject identifier.
 * Instead, we issue a "login credential" containing the Keycloak user ID, which becomes the
 * federated identity anchor for subsequent logins.
 * <p>
 * <b>Re-binding flow</b>: If a returning user presents only PID (lost their login credential),
 * we treat this as a re-binding flow: verify PID, create/lookup user, and issue a new login credential.
 */
public class PidBindingIdentityProvider extends Oid4vpIdentityProvider {

    private static final Logger LOG = Logger.getLogger(PidBindingIdentityProvider.class);

    // Session notes for PID binding flow
    public static final String SESSION_PID_BINDING_FLOW = "pid_binding_flow";
    public static final String SESSION_PID_BINDING_FIRST_LOGIN = "first_login";
    public static final String SESSION_PID_BINDING_RETURNING = "returning";
    public static final String SESSION_PID_BINDING_REBINDING = "rebinding";
    public static final String SESSION_NEEDS_CREDENTIAL_ISSUANCE = "pid_binding_needs_credential_issuance";
    public static final String SESSION_CREDENTIAL_OFFER_URI = "pid_binding_credential_offer_uri";

    private final PidBindingIdentityProviderConfig pidBindingConfig;

    public PidBindingIdentityProvider(KeycloakSession session,
                                       PidBindingIdentityProviderConfig config,
                                       ObjectMapper objectMapper,
                                       Oid4vpTrustListService trustListService) {
        super(session, config, objectMapper, trustListService);
        this.pidBindingConfig = config;
    }

    /**
     * Get the PID binding specific config.
     */
    @Override
    public PidBindingIdentityProviderConfig getConfig() {
        return pidBindingConfig;
    }

    /**
     * Build the DCQL query for this authentication request.
     * <p>
     * This method generates a context-aware DCQL:
     * <ul>
     *   <li>If alwaysRequestBothCredentials is true: Request both PID and login credential</li>
     *   <li>Otherwise: Request only PID (wallet will include login credential if available)</li>
     * </ul>
     * <p>
     * The actual flow detection (first login vs returning) happens in processCallback based on
     * which credentials the wallet actually presents.
     */
    @Override
    protected String buildDcqlQueryFromConfig() {
        // Check if explicit DCQL is configured
        String manualDcql = pidBindingConfig.getDcqlQuery();
        if (manualDcql != null && !manualDcql.isBlank()) {
            LOG.infof("[PID-BINDING] Using explicit DCQL query from config");
            return manualDcql;
        }

        // Build DCQL based on configuration
        DcqlQueryBuilder builder = new DcqlQueryBuilder(objectMapper);

        // Always request PID credential
        List<String> pidClaims = pidBindingConfig.getPidRequestedClaimsList();
        String pidType = pidBindingConfig.getPidCredentialType();
        builder.addCredentialTypeWithPaths(
                Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                pidType,
                pidClaims
        );
        LOG.infof("[PID-BINDING] Added PID credential request: type=%s, claims=%s", pidType, pidClaims);

        // Optionally request login credential
        if (pidBindingConfig.isAlwaysRequestBothCredentials()) {
            String loginType = pidBindingConfig.getLoginCredentialType();
            builder.addCredentialTypeWithPaths(
                    Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                    loginType,
                    List.of("user_id", "linked_at")
            );
            builder.setAllCredentialsRequired(false); // Optional - wallet presents what it has
            builder.setPurpose("Login with German PID and binding credential");
            LOG.infof("[PID-BINDING] Added login credential request: type=%s", loginType);
        } else {
            builder.setPurpose("Login with German PID");
        }

        String dcql = builder.build();
        LOG.infof("[PID-BINDING] Built DCQL query: %s", dcql);
        return dcql;
    }

    /**
     * Process the callback from the wallet.
     * <p>
     * This method determines the flow type based on which credentials were presented:
     * <ul>
     *   <li>PID + login credential with user_id → Returning user flow</li>
     *   <li>PID only → First login or re-binding flow</li>
     * </ul>
     */
    @Override
    public BrokeredIdentityContext processCallback(AuthenticationSessionModel authSession,
                                                    String state,
                                                    String vpToken,
                                                    String encryptedResponse,
                                                    String error,
                                                    String errorDescription) {
        LOG.infof("[PID-BINDING] ========== processCallback called ==========");

        // Use parent's callback processing for VP token verification
        // This decrypts the response if needed and verifies the credential(s)
        BrokeredIdentityContext context = super.processCallback(
                authSession, state, vpToken, encryptedResponse, error, errorDescription);

        // Now analyze the context to determine flow type
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = (Map<String, Object>) context.getContextData().get("oid4vp_claims");
        String credentialType = (String) context.getContextData().get("oid4vp_credential_type");

        LOG.infof("[PID-BINDING] Credential type from context: %s", credentialType);

        // Check for user_id in claims (indicates login credential was presented)
        String userId = claims != null ? extractClaimAsString(claims, "user_id") : null;
        String loginCredentialType = pidBindingConfig.getLoginCredentialType();
        boolean hasLoginCredential = userId != null && !userId.isBlank();

        LOG.infof("[PID-BINDING] Has login credential: %b, user_id from claims: %s",
                hasLoginCredential, userId);

        if (hasLoginCredential) {
            // Returning user flow - use user_id from login credential
            return processReturningUser(authSession, context, claims, userId);
        } else {
            // First login or re-binding flow
            return processFirstLoginOrRebinding(authSession, context, claims);
        }
    }

    /**
     * Process returning user flow.
     * The login credential's user_id is used as the federated identity subject.
     */
    private BrokeredIdentityContext processReturningUser(AuthenticationSessionModel authSession,
                                                          BrokeredIdentityContext context,
                                                          Map<String, Object> claims,
                                                          String userId) {
        LOG.infof("[PID-BINDING] Processing returning user flow with user_id: %s", userId);

        authSession.setAuthNote(SESSION_PID_BINDING_FLOW, SESSION_PID_BINDING_RETURNING);

        // Get the issuer from the login credential
        String issuer = extractClaimAsString(claims, "iss");
        if (issuer == null || issuer.isBlank()) {
            // Use the realm URL as issuer if not present
            issuer = session.getContext().getUri().getBaseUri().toString() +
                    "realms/" + session.getContext().getRealm().getName();
        }

        String loginCredentialType = pidBindingConfig.getLoginCredentialType();

        // Compute lookup key based on login credential
        String lookupKey = computeLookupKey(issuer, loginCredentialType, userId);
        LOG.infof("[PID-BINDING] Computed lookup key for returning user: %s", lookupKey);

        // Update context with the permanent subject
        BrokeredIdentityContext newContext = new BrokeredIdentityContext(lookupKey, getConfig());
        newContext.setIdp(this);
        newContext.setUsername(userId);

        // Copy claims and context data from original context
        newContext.getContextData().putAll(context.getContextData());

        // Store credential metadata
        String credentialMetadata = buildCredentialMetadataJson(issuer, loginCredentialType, userId, "user_id", claims);
        newContext.setToken(credentialMetadata);

        // Map PID claims to user attributes
        mapClaimsToContext(claims, newContext);

        LOG.infof("[PID-BINDING] Returning user flow completed, lookup key: %s", lookupKey);
        return newContext;
    }

    /**
     * Process first login or re-binding flow.
     * <p>
     * For first login: Create a temporary subject, mark for credential issuance.
     * For re-binding: Lookup existing user by PID attributes, issue new login credential.
     */
    private BrokeredIdentityContext processFirstLoginOrRebinding(AuthenticationSessionModel authSession,
                                                                  BrokeredIdentityContext context,
                                                                  Map<String, Object> claims) {
        LOG.infof("[PID-BINDING] Processing first login or re-binding flow");

        // Check if this might be a re-binding (user already exists with these PID attributes)
        // For now, we treat all PID-only logins as potential first logins
        // Keycloak's first broker login flow will handle user linking if the user exists

        authSession.setAuthNote(SESSION_PID_BINDING_FLOW, SESSION_PID_BINDING_FIRST_LOGIN);
        authSession.setAuthNote(SESSION_NEEDS_CREDENTIAL_ISSUANCE, "true");

        // Generate a temporary subject for first login
        // This will be replaced with the actual user_id after user creation and credential issuance
        String tempSubject = generateTemporarySubject(claims);
        LOG.infof("[PID-BINDING] Generated temporary subject: %s", tempSubject);

        // Use PID issuer and type for the lookup key
        String issuer = extractClaimAsString(claims, "iss");
        String pidType = pidBindingConfig.getPidCredentialType();
        String lookupKey = computeLookupKey(issuer, pidType, tempSubject);

        // Create context for first broker login
        BrokeredIdentityContext newContext = new BrokeredIdentityContext(lookupKey, getConfig());
        newContext.setIdp(this);
        newContext.setUsername(tempSubject);

        // Copy context data
        newContext.getContextData().putAll(context.getContextData());
        newContext.getContextData().put("pid_binding_temp_subject", tempSubject);
        newContext.getContextData().put("pid_binding_flow", SESSION_PID_BINDING_FIRST_LOGIN);

        // Map PID claims to user attributes
        mapClaimsToContext(claims, newContext);

        // Build credential offer URI for automatic redirect after login
        String credentialOfferUri = buildCredentialOfferUri(tempSubject);
        if (credentialOfferUri != null) {
            authSession.setAuthNote(SESSION_CREDENTIAL_OFFER_URI, credentialOfferUri);
            LOG.infof("[PID-BINDING] Credential offer URI stored in session: %s", credentialOfferUri);
        }

        LOG.infof("[PID-BINDING] First login flow completed, temp lookup key: %s", lookupKey);
        return newContext;
    }

    /**
     * Generate a temporary subject for first-time users.
     * This is based on a hash of PID claims to ensure uniqueness.
     */
    private String generateTemporarySubject(Map<String, Object> claims) {
        try {
            // Combine key claims for uniqueness
            StringBuilder sb = new StringBuilder();
            sb.append(extractClaimAsString(claims, "given_name"));
            sb.append("|");
            sb.append(extractClaimAsString(claims, "family_name"));
            sb.append("|");
            sb.append(extractClaimAsString(claims, "birthdate"));
            sb.append("|");
            sb.append(System.currentTimeMillis());
            sb.append("|");
            sb.append(UUID.randomUUID().toString());

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(sb.toString().getBytes(StandardCharsets.UTF_8));
            return "pid-" + Base64.getUrlEncoder().withoutPadding().encodeToString(hash).substring(0, 16);
        } catch (Exception e) {
            LOG.warnf(e, "[PID-BINDING] Failed to generate temporary subject, using UUID");
            return "pid-" + UUID.randomUUID().toString().substring(0, 16);
        }
    }

    /**
     * Build the credential offer URI for OID4VCI.
     * This URI will be used to redirect the wallet to obtain the login credential.
     */
    private String buildCredentialOfferUri(String tempSubject) {
        String issuerUrl = pidBindingConfig.getCredentialIssuerUrl();
        if (issuerUrl == null || issuerUrl.isBlank()) {
            // Auto-detect from realm
            issuerUrl = session.getContext().getUri().getBaseUri().toString() +
                    "realms/" + session.getContext().getRealm().getName();
        }

        String configId = pidBindingConfig.getCredentialConfigurationId();

        // Build credential offer URI
        // The actual offer will be created by the OID4VCI endpoint
        String offerUri = issuerUrl + "/protocol/oid4vc/credential-offer?credential_configuration_id=" + configId;

        LOG.infof("[PID-BINDING] Built credential offer URI: %s", offerUri);
        return offerUri;
    }

    /**
     * Map claims from the credential to the BrokeredIdentityContext.
     */
    private void mapClaimsToContext(Map<String, Object> claims, BrokeredIdentityContext context) {
        if (claims == null) {
            return;
        }

        // Map standard claims
        String givenName = extractClaimAsString(claims, "given_name");
        if (givenName != null && !givenName.isBlank()) {
            context.setFirstName(givenName);
        }

        String familyName = extractClaimAsString(claims, "family_name");
        if (familyName != null && !familyName.isBlank()) {
            context.setLastName(familyName);
        }

        String email = extractClaimAsString(claims, "email");
        if (email != null && !email.isBlank()) {
            context.setEmail(email);
        }

        // Store all claims for mapper access
        context.getContextData().put("oid4vp_claims", claims);
    }

    /**
     * Extract a claim value as string.
     */
    private String extractClaimAsString(Map<String, Object> claims, String claimName) {
        if (claims == null || claimName == null) {
            return null;
        }
        Object value = claims.get(claimName);
        if (value == null) {
            return null;
        }
        if (value instanceof String) {
            return (String) value;
        }
        return String.valueOf(value);
    }

    /**
     * Compute the lookup key from issuer, credential type, and subject.
     * This key is used as the federated user ID for O(1) lookup.
     */
    private String computeLookupKey(String issuer, String credentialType, String subject) {
        if (issuer == null) issuer = "unknown";
        if (credentialType == null) credentialType = "unknown";
        if (subject == null) subject = "unknown";

        String combined = issuer + "\0" + credentialType + "\0" + subject;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(combined.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            LOG.warnf(e, "[PID-BINDING] Failed to compute lookup key hash, using raw value");
            return combined.replace("\0", ":");
        }
    }

    /**
     * Build credential metadata JSON for storage in FederatedIdentity.token.
     */
    private String buildCredentialMetadataJson(String issuer, String credentialType, String subject,
                                                String userMappingClaim, Map<String, Object> claims) {
        try {
            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("issuer", issuer);
            metadata.put("credential_type", credentialType);
            metadata.put("subject", subject);
            metadata.put("user_mapping_claim", userMappingClaim);
            metadata.put("linked_at", System.currentTimeMillis());

            // Include key PID claims for reference
            if (claims != null) {
                Map<String, Object> matchedClaims = new LinkedHashMap<>();
                for (String claim : List.of("given_name", "family_name", "birthdate")) {
                    Object value = claims.get(claim);
                    if (value != null) {
                        matchedClaims.put(claim, value);
                    }
                }
                if (!matchedClaims.isEmpty()) {
                    metadata.put("matched_claims", matchedClaims);
                }
            }

            return objectMapper.writeValueAsString(metadata);
        } catch (Exception e) {
            LOG.warnf(e, "[PID-BINDING] Failed to build credential metadata JSON");
            return "{}";
        }
    }
}
