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
package de.arbeitsagentur.keycloak.wallet.issuance.session;

import java.util.ArrayList;
import java.util.List;

public class WalletSession {
    private PkceSession pkceSession;
    private TokenSet tokenSet;
    private UserProfile userProfile;
    private String localId;

    public PkceSession getPkceSession() {
        return pkceSession;
    }

    public void setPkceSession(PkceSession pkceSession) {
        this.pkceSession = pkceSession;
    }

    public TokenSet getTokenSet() {
        return tokenSet;
    }

    public void setTokenSet(TokenSet tokenSet) {
        this.tokenSet = tokenSet;
    }

    public UserProfile getUserProfile() {
        return userProfile;
    }

    public void setUserProfile(UserProfile userProfile) {
        this.userProfile = userProfile;
    }

    public String getLocalId() {
        return localId;
    }

    public void setLocalId(String localId) {
        this.localId = localId;
    }

    public boolean isAuthenticated() {
        return userProfile != null && tokenSet != null;
    }

    public String ownerId() {
        if (userProfile != null) {
            return userProfile.sub();
        }
        return localId;
    }

    public List<String> ownerIds() {
        List<String> ids = new ArrayList<>();
        if (userProfile != null && userProfile.sub() != null) {
            ids.add(userProfile.sub());
        }
        if (localId != null && !localId.isBlank() && (ids.isEmpty() || !ids.contains(localId))) {
            ids.add(localId);
        }
        return ids;
    }

    public List<String> ownerIdsIncluding(String... additionalOwnerIds) {
        List<String> ids = ownerIds();
        if (additionalOwnerIds != null) {
            for (String id : additionalOwnerIds) {
                if (id != null && !id.isBlank() && !ids.contains(id)) {
                    ids.add(id);
                }
            }
        }
        return ids;
    }
}
