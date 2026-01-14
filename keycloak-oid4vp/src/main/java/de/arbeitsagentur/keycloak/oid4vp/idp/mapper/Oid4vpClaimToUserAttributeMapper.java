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
import java.util.Map;

/**
 * Identity Provider Mapper that maps OID4VP credential claims to Keycloak user attributes.
 * <p>
 * This mapper extracts claims from verified credentials (SD-JWT VC or mDoc) and maps them
 * to user attributes in Keycloak. It supports both standard user properties (email, firstName,
 * lastName, username) and custom user attributes.
 * <p>
 * Each mapper specifies which credential type (format + vct/docType) the claim belongs to.
 * The IdP aggregates all mappers to build the DCQL query, requesting credentials by type.
 * <p>
 * Configuration:
 * - credential.format: The credential format (dc+sd-jwt or mso_mdoc)
 * - credential.type: The credential type (vct for SD-JWT, docType for mDoc)
 * - claim: The claim path to extract from the credential (e.g., "given_name", "address.city")
 * - user.attribute: The target Keycloak user attribute (e.g., "firstName", "myCustomAttr")
 *
 * @see Oid4vpClaimToUserSessionMapper for mapping claims to user session notes
 */
public class Oid4vpClaimToUserAttributeMapper extends AbstractIdentityProviderMapper {

    private static final Logger LOG = Logger.getLogger(Oid4vpClaimToUserAttributeMapper.class);

    public static final String PROVIDER_ID = "oid4vp-user-attribute-mapper";

    public static final String CREDENTIAL_FORMAT = "credential.format";
    public static final String CREDENTIAL_TYPE = "credential.type";
    public static final String CLAIM_PATH = "claim";
    public static final String USER_ATTRIBUTE = "user.attribute";
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

        ProviderConfigProperty attributeProperty = new ProviderConfigProperty();
        attributeProperty.setName(USER_ATTRIBUTE);
        attributeProperty.setLabel("User Attribute Name");
        attributeProperty.setHelpText("Keycloak user attribute to store the claim value. Use 'email', 'firstName', 'lastName', or 'username' for standard properties, or any name for custom attributes.");
        attributeProperty.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(attributeProperty);

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
        return "Attribute Importer";
    }

    @Override
    public String getDisplayType() {
        return "OID4VP Claim to User Attribute";
    }

    @Override
    public String getHelpText() {
        return "Map a claim from the verifiable credential to a Keycloak user attribute.";
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
        String userAttribute = mapperModel.getConfig().get(USER_ATTRIBUTE);
        boolean isOptional = Boolean.parseBoolean(mapperModel.getConfig().getOrDefault(OPTIONAL, "false"));

        if (claimPath == null || claimPath.isBlank() || userAttribute == null || userAttribute.isBlank()) {
            LOG.debugf("[OID4VP-MAPPER] Skipping mapper - missing configuration");
            return;
        }

        Object claimValue = Oid4vpMapperUtils.getClaimValue(context, claimPath);
        if (claimValue == null) {
            if (isOptional) {
                LOG.debugf("[OID4VP-MAPPER] Optional claim '%s' not found in credential - skipping", claimPath);
            } else {
                LOG.warnf("[OID4VP-MAPPER] Required claim '%s' not found in credential", claimPath);
            }
            return;
        }

        String stringValue = claimValue.toString();
        LOG.debugf("[OID4VP-MAPPER] Mapping claim '%s' = '%s' to user attribute '%s'",
                claimPath, stringValue, userAttribute);

        // Handle standard user properties
        switch (userAttribute.toLowerCase()) {
            case "email":
                context.setEmail(stringValue);
                break;
            case "firstname":
            case "first_name":
            case "givenname":
            case "given_name":
                context.setFirstName(stringValue);
                break;
            case "lastname":
            case "last_name":
            case "familyname":
            case "family_name":
                context.setLastName(stringValue);
                break;
            case "username":
                context.setUsername(stringValue);
                break;
            default:
                // Custom attribute - store in context for later application to user
                context.setUserAttribute(userAttribute, stringValue);
        }
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm,
                                    UserModel user, IdentityProviderMapperModel mapperModel,
                                    BrokeredIdentityContext context) {
        String claimPath = mapperModel.getConfig().get(CLAIM_PATH);
        String userAttribute = mapperModel.getConfig().get(USER_ATTRIBUTE);
        boolean isOptional = Boolean.parseBoolean(mapperModel.getConfig().getOrDefault(OPTIONAL, "false"));

        if (claimPath == null || claimPath.isBlank() || userAttribute == null || userAttribute.isBlank()) {
            return;
        }

        Object claimValue = Oid4vpMapperUtils.getClaimValue(context, claimPath);
        if (claimValue == null) {
            if (!isOptional) {
                LOG.warnf("[OID4VP-MAPPER] Required claim '%s' not found in credential during user update", claimPath);
            }
            return;
        }

        String stringValue = claimValue.toString();
        LOG.debugf("[OID4VP-MAPPER] Updating user attribute '%s' = '%s'", userAttribute, stringValue);

        // Handle standard user properties
        switch (userAttribute.toLowerCase()) {
            case "email":
                user.setEmail(stringValue);
                break;
            case "firstname":
            case "first_name":
            case "givenname":
            case "given_name":
                user.setFirstName(stringValue);
                break;
            case "lastname":
            case "last_name":
            case "familyname":
            case "family_name":
                user.setLastName(stringValue);
                break;
            case "username":
                user.setUsername(stringValue);
                break;
            default:
                // Custom attribute
                user.setSingleAttribute(userAttribute, stringValue);
        }
    }
}
