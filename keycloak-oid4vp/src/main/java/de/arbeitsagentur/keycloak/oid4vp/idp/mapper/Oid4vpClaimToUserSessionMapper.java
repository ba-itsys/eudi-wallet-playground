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

import de.arbeitsagentur.keycloak.oid4vp.idp.Oid4vpIdentityProviderConfig;
import de.arbeitsagentur.keycloak.oid4vp.idp.Oid4vpIdentityProviderFactory;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * Identity Provider Mapper that maps OID4VP credential claims to user session notes.
 * <p>
 * This mapper extracts claims from verified credentials (SD-JWT VC or mDoc) and stores them
 * as user session notes. Session notes are available during the authentication session and
 * can be included in tokens via protocol mappers (e.g., "User Session Note" token mapper).
 * <p>
 * Use this mapper when you want to:
 * - Include credential claims in access/ID tokens without persisting them as user attributes
 * - Pass transient credential data through the authentication flow
 * - Make claims available to protocol mappers for custom token claims
 * <p>
 * Example use case: Map a credential's "personal_administrative_number" claim to a session
 * note "pid", then use a "User Session Note" protocol mapper to include it in the access token.
 * <p>
 * Configuration:
 * - credential.format: The credential format (dc+sd-jwt or mso_mdoc)
 * - credential.type: The credential type (vct for SD-JWT, docType for mDoc)
 * - claim: The claim path to extract from the credential
 * - session.note: The session note key to store the claim value
 *
 * @see Oid4vpClaimToUserAttributeMapper for mapping claims to persistent user attributes
 */
public class Oid4vpClaimToUserSessionMapper extends AbstractIdentityProviderMapper {

    private static final Logger LOG = Logger.getLogger(Oid4vpClaimToUserSessionMapper.class);

    public static final String PROVIDER_ID = "oid4vp-user-session-mapper";

    public static final String CREDENTIAL_FORMAT = "credential.format";
    public static final String CREDENTIAL_TYPE = "credential.type";
    public static final String CLAIM_PATH = "claim";
    public static final String SESSION_NOTE = "session.note";
    public static final String OPTIONAL = "optional";

    private static final String[] COMPATIBLE_PROVIDERS = new String[] {
            Oid4vpIdentityProviderFactory.PROVIDER_ID
    };

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty formatProperty = new ProviderConfigProperty();
        formatProperty.setName(CREDENTIAL_FORMAT);
        formatProperty.setLabel("Credential Format");
        formatProperty.setHelpText("Format of the credential containing this claim.");
        formatProperty.setType(ProviderConfigProperty.LIST_TYPE);
        formatProperty.setDefaultValue(Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC);
        formatProperty.setOptions(List.of(
                Oid4vpIdentityProviderConfig.FORMAT_SD_JWT_VC,
                Oid4vpIdentityProviderConfig.FORMAT_MSO_MDOC
        ));
        CONFIG_PROPERTIES.add(formatProperty);

        ProviderConfigProperty typeProperty = new ProviderConfigProperty();
        typeProperty.setName(CREDENTIAL_TYPE);
        typeProperty.setLabel("Credential Type");
        typeProperty.setHelpText("Credential type identifier used in DCQL query. " +
                "For SD-JWT: use 'vct' value (e.g., 'urn:eudi:pid:1' for EU PID standard, " +
                "'https://demo.pid-provider.bundesdruckerei.de/credentials/pid/1.0' for German EUDI sandbox). " +
                "For mDoc: use 'docType' value (e.g., 'eu.europa.ec.eudi.pid.1' for PID, 'org.iso.18013.5.1.mDL' for mDL). " +
                "Check your target wallet/sandbox documentation for the exact values required.");
        typeProperty.setType(ProviderConfigProperty.STRING_TYPE);
        typeProperty.setDefaultValue(Oid4vpIdentityProviderConfig.PRESET_EUDI_PID);
        CONFIG_PROPERTIES.add(typeProperty);

        ProviderConfigProperty claimProperty = new ProviderConfigProperty();
        claimProperty.setName(CLAIM_PATH);
        claimProperty.setLabel("Claim Path");
        claimProperty.setHelpText("Path to the claim in the credential. Use '/' for nested paths (e.g., 'given_name', 'address/city', 'eu.europa.ec.eudi.pid.1/family_name').");
        claimProperty.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(claimProperty);

        ProviderConfigProperty sessionNoteProperty = new ProviderConfigProperty();
        sessionNoteProperty.setName(SESSION_NOTE);
        sessionNoteProperty.setLabel("Session Note Key");
        sessionNoteProperty.setHelpText("The key name for storing the claim value in the user session. " +
                "This value can then be included in tokens using a 'User Session Note' protocol mapper.");
        sessionNoteProperty.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(sessionNoteProperty);

        ProviderConfigProperty optionalProperty = new ProviderConfigProperty();
        optionalProperty.setName(OPTIONAL);
        optionalProperty.setLabel("Optional Claim");
        optionalProperty.setHelpText("If enabled, this claim is optional and the mapper will not fail if the claim is not present in the credential. " +
                "Use this with DCQL claim_sets to support selective disclosure where the wallet may not disclose all requested claims.");
        optionalProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        optionalProperty.setDefaultValue("false");
        CONFIG_PROPERTIES.add(optionalProperty);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "Token Mapper";
    }

    @Override
    public String getDisplayType() {
        return "OID4VP Claim to User Session";
    }

    @Override
    public String getHelpText() {
        return "Map a claim from the verifiable credential to a user session note. " +
                "Use 'User Session Note' protocol mapper to include the value in tokens.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return true;
    }

    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm,
                                             IdentityProviderMapperModel mapperModel,
                                             BrokeredIdentityContext context) {
        String claimPath = mapperModel.getConfig().get(CLAIM_PATH);
        String sessionNote = mapperModel.getConfig().get(SESSION_NOTE);
        boolean isOptional = Boolean.parseBoolean(mapperModel.getConfig().getOrDefault(OPTIONAL, "false"));

        if (claimPath == null || claimPath.isBlank() || sessionNote == null || sessionNote.isBlank()) {
            LOG.debugf("[OID4VP-SESSION-MAPPER] Skipping mapper - missing configuration");
            return;
        }

        Object claimValue = Oid4vpMapperUtils.getClaimValue(context, claimPath);
        if (claimValue == null) {
            if (isOptional) {
                LOG.debugf("[OID4VP-SESSION-MAPPER] Optional claim '%s' not found in credential - skipping", claimPath);
            } else {
                LOG.warnf("[OID4VP-SESSION-MAPPER] Required claim '%s' not found in credential", claimPath);
            }
            return;
        }

        String stringValue = claimValue.toString();
        LOG.debugf("[OID4VP-SESSION-MAPPER] Mapping claim '%s' = '%s' to session note '%s'",
                claimPath, stringValue, sessionNote);

        // Store as session note - this will be set on the user session after authentication
        context.setSessionNote(sessionNote, stringValue);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm,
                                    UserModel user, IdentityProviderMapperModel mapperModel,
                                    BrokeredIdentityContext context) {
        // Session notes are set during preprocessing, not during user update
        // This method is called when updating an existing user's attributes
        // For session notes, we just need to ensure they're set in preprocessFederatedIdentity
    }
}
