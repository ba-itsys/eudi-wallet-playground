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
package de.arbeitsagentur.keycloak.wallet.verification.service;

import java.util.ArrayList;
import java.util.List;

/**
 * Collects verification steps for UI/debugging and implements both sd-jwt and mDoc step sinks.
 */
public class VerificationSteps implements
        de.arbeitsagentur.keycloak.wallet.common.credential.VerificationStepSink {
    private final List<String> titles = new ArrayList<>();
    private final List<StepDetail> details = new ArrayList<>();

    @Override
    public void add(String title) {
        add(title, title, null);
    }

    @Override
    public void add(String title, String description, String specLink) {
        titles.add(title);
        details.add(new StepDetail(title, description, specLink));
    }

    public List<String> titles() {
        return titles;
    }

    public List<StepDetail> details() {
        return details;
    }

    public record StepDetail(String title, String detail, String specLink) {
    }
}
