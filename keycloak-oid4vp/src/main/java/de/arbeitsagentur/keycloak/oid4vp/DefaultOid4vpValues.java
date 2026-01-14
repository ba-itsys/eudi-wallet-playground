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

public final class DefaultOid4vpValues {
    public static final String DEFAULT_TRUST_LIST_ID = "trust-list";
    public static final String DEFAULT_USER_MAPPING_CLAIM = "document_number";
    public static final String DEFAULT_USER_MAPPING_CLAIM_MDOC = "document_number";
    public static final String DEFAULT_DC_API_REQUEST_MODE = "auto";

    private DefaultOid4vpValues() {
    }
}
