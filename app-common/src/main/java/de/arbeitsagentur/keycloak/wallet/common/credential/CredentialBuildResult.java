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
package de.arbeitsagentur.keycloak.wallet.common.credential;

import java.util.List;
import java.util.Map;

/**
 * Normalized result for building a verifiable credential (SD-JWT or mDoc).
 */
public record CredentialBuildResult(String encoded,
                                    List<String> disclosures,
                                    Map<String, Object> decoded,
                                    String vct,
                                    String format) {
}
