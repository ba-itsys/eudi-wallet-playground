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
package de.arbeitsagentur.keycloak.wallet.conformance.web;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import de.arbeitsagentur.keycloak.wallet.common.conformance.ConformanceSessionAttributes;
import de.arbeitsagentur.keycloak.wallet.common.conformance.ConformanceFlowRunner;
import de.arbeitsagentur.keycloak.wallet.common.conformance.ConformanceUiDefaultsProvider;
import de.arbeitsagentur.keycloak.wallet.common.debug.DebugLogService;
import de.arbeitsagentur.keycloak.wallet.common.util.CertificateUtils;
import de.arbeitsagentur.keycloak.wallet.common.util.UrlNormalizer;
import de.arbeitsagentur.keycloak.wallet.conformance.config.ConformanceProperties;
import de.arbeitsagentur.keycloak.wallet.conformance.service.ConformanceSuiteService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/verifier/conformance")
public class ConformanceController {
    private static final String SESSION_CONFORMANCE_PLAN = "conformance_plan";
    private static final String SESSION_CONFORMANCE_ERROR = "conformance_error";
    private static final String SESSION_CONFORMANCE_MESSAGE = "conformance_message";
    private static final String SESSION_CONFORMANCE_BASE_URL = "conformance_base_url";
    private static final String SESSION_CONFORMANCE_API_KEY = "conformance_api_key";
    private static final String SESSION_CONFORMANCE_LAST_RUN_ID = "conformance_last_run_id";
    private static final String SESSION_CONFORMANCE_LAST_AUTH_ENDPOINT = "conformance_last_auth_endpoint";
    private static final String SESSION_CONFORMANCE_LAST_MODULE = "conformance_last_module";
    private static final String SESSION_CONFORMANCE_FLOW_STARTED_RUN_ID = "conformance_flow_started_run_id";
    private static final String SESSION_CONFORMANCE_FLOW_LAST_STATE = "conformance_flow_last_state";

    private static final List<String> CONFORMANCE_JWK_PRIVATE_FIELDS = List.of(
            "d",
            "p",
            "q",
            "dp",
            "dq",
            "qi",
            "oth",
            "k"
    );

    /**
     * OIDF conformance suite certificate for mDL (mdoc/ISO 18013-5) credential signing.
     * This is the internal certificate used by the conformance suite to sign mDL credentials.
     *
     * <p>Note: This is DIFFERENT from the certificate published on the OIDF website.
     * The website certificate (CN=OIDF Test, C=GB) is for SD-JWT VC and verifier request signing.
     * This certificate (CN=certification.openid.net, O=OpenID Foundation) is used internally
     * by the conformance suite to sign mDL credentials.
     *
     * <p>Subject: CN=certification.openid.net, OU=IT, O=OpenID Foundation, L=San Ramon, ST=State of Utopia, C=US
     * <p>Validity: Jul 30 07:47:22 2025 GMT to Jul 30 07:47:22 2026 GMT
     *
     * <p>For SD-JWT VC, the conformance suite uses the signing_jwk we provide in the plan config.
     * For mDL/mdoc credentials, it uses this internal certificate instead.
     */
    private static final String OIDF_MDL_ISSUER_CERTIFICATE_PEM = """
            -----BEGIN CERTIFICATE-----
            MIICqTCCAlCgAwIBAgIUEmctHgzxSGqk6Z8Eb+0s97VZdpowCgYIKoZIzj0EAwIw
            gYcxCzAJBgNVBAYTAlVTMRgwFgYDVQQIDA9TdGF0ZSBvZiBVdG9waWExEjAQBgNV
            BAcMCVNhbiBSYW1vbjEaMBgGA1UECgwRT3BlbklEIEZvdW5kYXRpb24xCzAJBgNV
            BAsMAklUMSEwHwYDVQQDDBhjZXJ0aWZpY2F0aW9uLm9wZW5pZC5uZXQwHhcNMjUw
            NzMwMDc0NzIyWhcNMjYwNzMwMDc0NzIyWjCBhzELMAkGA1UEBhMCVVMxGDAWBgNV
            BAgMD1N0YXRlIG9mIFV0b3BpYTESMBAGA1UEBwwJU2FuIFJhbW9uMRowGAYDVQQK
            DBFPcGVuSUQgRm91bmRhdGlvbjELMAkGA1UECwwCSVQxITAfBgNVBAMMGGNlcnRp
            ZmljYXRpb24ub3BlbmlkLm5ldDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJ5o
            lgDBiHqNhN7rFkSy/xD34dQcOSR4KvEWMyb62jI+UGUofeAi/55RIt74pBsQz9+B
            48WXI8xhIphoNN7AejajgZcwgZQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8B
            Af8EBAMCAQYwIQYDVR0SBBowGIEWY2VydGlmaWNhdGlvbkBvaWRmLm9yZzAsBgNV
            HR8EJTAjMCGgH6AdhhtodHRwOi8vZXhhbXBsZS5jb20vbXljYS5jcmwwHQYDVR0O
            BBYEFHhk9LVVH8Gt9ZgfxgyhSl921XOhMAoGCCqGSM49BAMCA0cAMEQCICBxjCq9
            efAwMKREK+k0OXBtiQCbFD7QdpyH42LVYfdvAiAurlZwp9PtmQZzoSYDUvXpZM5v
            TvFLVc4ESGy3AtdC+g==
            -----END CERTIFICATE-----
            """;

    private final ConformanceSuiteService conformanceSuiteService;
    private final ConformanceProperties conformanceProperties;
    private final DebugLogService debugLogService;
    private final ObjectMapper objectMapper;
    private final ObjectProvider<ConformanceUiDefaultsProvider> uiDefaultsProvider;
    private final ObjectProvider<ConformanceFlowRunner> flowRunnerProvider;
    private final URI publicBaseUri;

    public ConformanceController(ConformanceSuiteService conformanceSuiteService,
                                 ConformanceProperties conformanceProperties,
                                 DebugLogService debugLogService,
                                 ObjectMapper objectMapper,
                                 ObjectProvider<ConformanceUiDefaultsProvider> uiDefaultsProvider,
                                 ObjectProvider<ConformanceFlowRunner> flowRunnerProvider,
                                 @Value("${wallet.public-base-url:}") String publicBaseUrl) {
        this.conformanceSuiteService = conformanceSuiteService;
        this.conformanceProperties = conformanceProperties;
        this.debugLogService = debugLogService;
        this.objectMapper = objectMapper;
        this.uiDefaultsProvider = uiDefaultsProvider;
        this.flowRunnerProvider = flowRunnerProvider;
        this.publicBaseUri = UrlNormalizer.parsePublicBaseUri(publicBaseUrl);
    }

    @GetMapping
    public String conformancePage(Model model, HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        ConformanceSuiteService.ConformancePlan conformancePlan = session != null
                ? (ConformanceSuiteService.ConformancePlan) session.getAttribute(SESSION_CONFORMANCE_PLAN)
                : null;

        model.addAttribute("conformancePlan", conformancePlan);
        model.addAttribute("conformanceError", stringAttr(session, SESSION_CONFORMANCE_ERROR));
        model.addAttribute("conformanceMessage", stringAttr(session, SESSION_CONFORMANCE_MESSAGE));
        model.addAttribute("conformanceLastRunId", stringAttr(session, SESSION_CONFORMANCE_LAST_RUN_ID));
        model.addAttribute("conformanceLastAuthEndpoint", stringAttr(session, SESSION_CONFORMANCE_LAST_AUTH_ENDPOINT));
        model.addAttribute("conformanceLastState", stringAttr(session, SESSION_CONFORMANCE_FLOW_LAST_STATE));

        String conformanceBaseUrl = firstNonBlank(stringAttr(session, SESSION_CONFORMANCE_BASE_URL), conformanceProperties.resolvedBaseUrl());
        model.addAttribute("conformanceBaseUrl", conformanceBaseUrl);
        model.addAttribute("conformanceConfigured", conformanceBaseUrl != null && !conformanceBaseUrl.isBlank());

        String apiKeyStatus;
        boolean apiKeyStored = stringAttr(session, SESSION_CONFORMANCE_API_KEY) != null;
        if (apiKeyStored) {
            apiKeyStatus = "API key stored in session.";
        } else if (conformanceProperties.resolvedApiKey() != null && !conformanceProperties.resolvedApiKey().isBlank()) {
            apiKeyStatus = "API key provided by server configuration.";
        } else {
            apiKeyStatus = "No API key configured.";
        }

        model.addAttribute("conformanceApiKeyStored", apiKeyStored);
        model.addAttribute("conformanceApiKeyStatus", apiKeyStatus);
        model.addAttribute("conformanceDefaultPlanId", conformanceProperties.resolvedPlanId());

        URI externalBase = baseUri(request).build().toUri();
        model.addAttribute("conformanceExternalHost", externalBase.getHost() != null ? externalBase.getHost() : "");
        model.addAttribute("conformanceExternalBaseUrl", externalBase.toString());
        model.addAttribute("conformanceCreatePlanName", "oid4vp-1final-verifier-test-plan");
        model.addAttribute("conformanceCreateClientIdHost", externalBase.getHost() != null ? externalBase.getHost() : "");
        model.addAttribute("conformanceCreateCredentialFormat", "sd_jwt_vc");
        model.addAttribute("conformanceCreateClientIdPrefix", "x509_san_dns");
        model.addAttribute("conformanceCreatePublish", "private");

        ConformanceUiDefaultsProvider provider = uiDefaultsProvider.getIfAvailable();
        ConformanceUiDefaultsProvider.ConformanceUiDefaults defaults = provider != null
                ? provider.defaults()
                : new ConformanceUiDefaultsProvider.ConformanceUiDefaults("", "", "");
        model.addAttribute("conformanceDefaultWalletClientId", defaults.walletClientId());
        model.addAttribute("conformanceDefaultClientMetadata", defaults.clientMetadata());
        model.addAttribute("conformanceDefaultDcqlQuery", defaults.dcqlQuery());
        return "verifier-conformance";
    }

    @PostMapping("/create")
    public ResponseEntity<Void> createConformancePlan(@RequestParam(name = "planName", required = false) String planName,
                                                      @RequestParam(name = "credentialFormat", required = false) String credentialFormat,
                                                      @RequestParam(name = "clientIdPrefix", required = false) String clientIdPrefix,
                                                      @RequestParam(name = "clientIdHost", required = false) String clientIdHost,
                                                      @RequestParam(name = "alias", required = false) String alias,
                                                      @RequestParam(name = "description", required = false) String description,
                                                      @RequestParam(name = "publish", required = false) String publish,
                                                      @RequestParam(name = "baseUrl", required = false) String baseUrl,
                                                      @RequestParam(name = "apiKey", required = false) String apiKey,
                                                      HttpServletRequest request) {
        HttpSession session = request.getSession(true);
        session.removeAttribute(SESSION_CONFORMANCE_ERROR);
        session.removeAttribute(SESSION_CONFORMANCE_MESSAGE);
        updateConformanceConfig(session, baseUrl, apiKey);
        try {
            String effectivePlanName = (planName == null || planName.isBlank())
                    ? "oid4vp-1final-verifier-test-plan"
                    : planName.trim();

            String host = UrlNormalizer.extractHostname(clientIdHost);
            if (host == null || host.isBlank()) {
                host = UrlNormalizer.extractHostname(baseUri(request).build().toUri().getHost());
            }
            if (host == null || host.isBlank()) {
                host = "verifier.localtest.me";
            }

            String effectiveAlias = (alias == null || alias.isBlank())
                    ? "verifier-" + Instant.now().toString().replaceAll("[^0-9A-Za-z_-]", "")
                    : alias.trim();

            String effectiveCredentialFormat = normalizeVariant(credentialFormat, "sd_jwt_vc", "iso_mdl");
            String effectiveClientIdPrefix = normalizeVariant(clientIdPrefix, "x509_san_dns", "x509_hash");
            String effectivePublish = normalizeVariant(publish, "private", "public");

            Map<String, String> variant = Map.of(
                    "credential_format", effectiveCredentialFormat,
                    "client_id_prefix", effectiveClientIdPrefix,
                    "request_method", "request_uri_signed",
                    "response_mode", "direct_post.jwt"
            );

            Map<String, Object> signingJwk = new ECKeyGenerator(Curve.P_256)
                    .keyIDFromThumbprint(true)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.ES256)
                    .generate()
                    .toJSONObject();
            Map<String, Object> config = new LinkedHashMap<>();
            config.put("alias", effectiveAlias);
            if (description != null && !description.isBlank()) {
                config.put("description", description.trim());
            }
            config.put("publish", effectivePublish);
            // Note: For x509_san_dns, the conformance suite automatically adds the prefix
            // via OID4VPSetClientIdToIncludeClientIdScheme, so we just pass the hostname
            config.put("client", Map.of("client_id", host));
            config.put("credential", Map.of(
                    "signing_jwk", signingJwk
            ));

            String createdPlanId = conformanceSuiteService.createPlan(
                    effectivePlanName,
                    variant,
                    config,
                    effectiveConformanceBaseUrl(session),
                    effectiveConformanceApiKey(session)
            );

            ConformanceSuiteService.ConformancePlan plan = conformanceSuiteService.loadPlan(
                    createdPlanId,
                    effectiveConformanceBaseUrl(session),
                    effectiveConformanceApiKey(session));
            session.setAttribute(SESSION_CONFORMANCE_PLAN, plan);
            storeTrustedIssuerKeys(session, plan);
            session.setAttribute(SESSION_CONFORMANCE_MESSAGE, "Created conformance plan '" + effectivePlanName + "' (id: " + createdPlanId + ").");
        } catch (Exception e) {
            session.setAttribute(SESSION_CONFORMANCE_ERROR, e.getMessage());
        }
        return ResponseEntity.status(302)
                .location(ServletUriComponentsBuilder.fromCurrentContextPath().path("/verifier/conformance").build().toUri())
                .build();
    }

    @PostMapping("/load")
    public ResponseEntity<Void> loadConformancePlan(@RequestParam(name = "planId", required = false) String planId,
                                                    @RequestParam(name = "baseUrl", required = false) String baseUrl,
                                                    @RequestParam(name = "apiKey", required = false) String apiKey,
                                                    HttpServletRequest request) {
        HttpSession session = request.getSession(true);
        session.removeAttribute(SESSION_CONFORMANCE_ERROR);
        session.removeAttribute(SESSION_CONFORMANCE_MESSAGE);
        updateConformanceConfig(session, baseUrl, apiKey);
        try {
            String effectivePlanId = firstNonBlank(planId, conformanceProperties.resolvedPlanId());
            ConformanceSuiteService.ConformancePlan plan = conformanceSuiteService.loadPlan(
                    effectivePlanId,
                    effectiveConformanceBaseUrl(session),
                    effectiveConformanceApiKey(session));
            session.setAttribute(SESSION_CONFORMANCE_PLAN, plan);
            storeTrustedIssuerKeys(session, plan);
            session.setAttribute(SESSION_CONFORMANCE_MESSAGE, "Loaded conformance plan '" + plan.planName() + "'.");
        } catch (Exception e) {
            session.setAttribute(SESSION_CONFORMANCE_ERROR, e.getMessage());
        }
        return ResponseEntity.status(302).location(ServletUriComponentsBuilder.fromCurrentContextPath().path("/verifier/conformance").build().toUri()).build();
    }

    @PostMapping("/refresh")
    public ResponseEntity<Void> refreshConformancePlan(@RequestParam(name = "baseUrl", required = false) String baseUrl,
                                                       @RequestParam(name = "apiKey", required = false) String apiKey,
                                                       HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return ResponseEntity.status(302).location(ServletUriComponentsBuilder.fromCurrentContextPath().path("/verifier/conformance").build().toUri()).build();
        }
        updateConformanceConfig(session, baseUrl, apiKey);
        Object existing = session.getAttribute(SESSION_CONFORMANCE_PLAN);
        if (existing instanceof ConformanceSuiteService.ConformancePlan plan) {
            return loadConformancePlan(plan.id(), baseUrl, apiKey, request);
        }
        return ResponseEntity.status(302).location(ServletUriComponentsBuilder.fromCurrentContextPath().path("/verifier/conformance").build().toUri()).build();
    }

    @PostMapping("/clear")
    public ResponseEntity<Void> clearConformancePlan(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(SESSION_CONFORMANCE_PLAN);
            session.removeAttribute(SESSION_CONFORMANCE_ERROR);
            session.removeAttribute(SESSION_CONFORMANCE_MESSAGE);
            session.removeAttribute(SESSION_CONFORMANCE_LAST_RUN_ID);
            session.removeAttribute(SESSION_CONFORMANCE_LAST_AUTH_ENDPOINT);
            session.removeAttribute(SESSION_CONFORMANCE_LAST_MODULE);
            session.removeAttribute(SESSION_CONFORMANCE_FLOW_STARTED_RUN_ID);
            session.removeAttribute(SESSION_CONFORMANCE_FLOW_LAST_STATE);
            session.removeAttribute(ConformanceSessionAttributes.TRUSTED_ISSUER_JWKS);
        }
        return ResponseEntity.status(302).location(ServletUriComponentsBuilder.fromCurrentContextPath().path("/verifier/conformance").build().toUri()).build();
    }

    @PostMapping("/clear-key")
    public ResponseEntity<Void> clearConformanceApiKey(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(SESSION_CONFORMANCE_API_KEY);
            session.removeAttribute(SESSION_CONFORMANCE_MESSAGE);
        }
        return ResponseEntity.status(302).location(ServletUriComponentsBuilder.fromCurrentContextPath().path("/verifier/conformance").build().toUri()).build();
    }

    @PostMapping("/run")
    public ResponseEntity<Void> runConformanceModule(@RequestParam(name = "planId", required = false) String planId,
                                                     @RequestParam(name = "module", required = false) String module,
                                                     @RequestParam(name = "baseUrl", required = false) String baseUrl,
                                                     @RequestParam(name = "apiKey", required = false) String apiKey,
                                                     HttpServletRequest request) {
        HttpSession session = request.getSession(true);
        session.removeAttribute(SESSION_CONFORMANCE_ERROR);
        session.removeAttribute(SESSION_CONFORMANCE_MESSAGE);
        updateConformanceConfig(session, baseUrl, apiKey);
        try {
            String effectivePlanIdInput = firstNonBlank(planId, conformanceProperties.resolvedPlanId());
            ConformanceSuiteService.ConformancePlan plan = conformanceSuiteService.loadPlan(
                    effectivePlanIdInput,
                    effectiveConformanceBaseUrl(session),
                    effectiveConformanceApiKey(session));
            session.setAttribute(SESSION_CONFORMANCE_PLAN, plan);
            storeTrustedIssuerKeys(session, plan);
            String effectivePlanId = firstNonBlank(plan.id(), effectivePlanIdInput);

            String moduleToRun = module;
            if (moduleToRun == null || moduleToRun.isBlank()) {
                moduleToRun = plan.modules() != null && !plan.modules().isEmpty() ? plan.modules().get(0).testModule() : "";
            }
            if (moduleToRun == null || moduleToRun.isBlank()) {
                throw new IllegalStateException("Conformance plan contains no test modules to run");
            }
            session.setAttribute(SESSION_CONFORMANCE_LAST_MODULE, moduleToRun);
            session.removeAttribute(SESSION_CONFORMANCE_FLOW_STARTED_RUN_ID);
            session.removeAttribute(SESSION_CONFORMANCE_FLOW_LAST_STATE);

            ConformanceSuiteService.ConformanceRunStart run = conformanceSuiteService.runTestModuleDetailed(
                    effectivePlanId,
                    moduleToRun,
                    effectiveConformanceBaseUrl(session),
                    effectiveConformanceApiKey(session));
            session.setAttribute(SESSION_CONFORMANCE_LAST_RUN_ID, run.id());
            String derivedAuthEndpoint = walletAuthEndpointFromRunUrl(run.url());
            if (derivedAuthEndpoint != null && !derivedAuthEndpoint.isBlank()) {
                session.setAttribute(SESSION_CONFORMANCE_LAST_AUTH_ENDPOINT, derivedAuthEndpoint);
            }

            ConformanceSuiteService.ConformancePlan refreshed = conformanceSuiteService.loadPlan(
                    effectivePlanId,
                    effectiveConformanceBaseUrl(session),
                    effectiveConformanceApiKey(session));
            session.setAttribute(SESSION_CONFORMANCE_PLAN, refreshed);
            storeTrustedIssuerKeys(session, refreshed);
        } catch (Exception e) {
            session.setAttribute(SESSION_CONFORMANCE_ERROR, e.getMessage());
        }
        return ResponseEntity.status(302).location(ServletUriComponentsBuilder.fromCurrentContextPath().path("/verifier/conformance").build().toUri()).build();
    }

    @PostMapping("/start-flow")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> startVerifierFlow(@RequestParam(name = "force", defaultValue = "false") boolean force,
                                                                 HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .body(Map.of("error", "No session found; load a plan and start a run first"));
        }
        String runId = stringAttr(session, SESSION_CONFORMANCE_LAST_RUN_ID);
        String walletAuthEndpoint = stringAttr(session, SESSION_CONFORMANCE_LAST_AUTH_ENDPOINT);
        if (runId == null || runId.isBlank()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .body(Map.of("error", "No conformance run id found; start a run first"));
        }
        if (walletAuthEndpoint == null || walletAuthEndpoint.isBlank()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .body(Map.of("error", "No wallet authorization endpoint found; start a run first"));
        }

        String alreadyStartedForRun = stringAttr(session, SESSION_CONFORMANCE_FLOW_STARTED_RUN_ID);
        if (!force && alreadyStartedForRun != null && alreadyStartedForRun.equals(runId)) {
            return ResponseEntity.ok()
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .body(Map.of("started", false, "alreadyStarted", true, "runId", runId));
        }

        ConformanceFlowRunner flowRunner = flowRunnerProvider.getIfAvailable();
        if (flowRunner == null) {
            return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .body(Map.of("error", "No verifier flow runner is configured"));
        }

        ConformanceUiDefaultsProvider provider = uiDefaultsProvider.getIfAvailable();
        ConformanceUiDefaultsProvider.ConformanceUiDefaults defaults = provider != null
                ? provider.defaults()
                : new ConformanceUiDefaultsProvider.ConformanceUiDefaults("", "", "");
        List<String> trustedIssuerJwks = new ArrayList<>(readStringListAttr(session, ConformanceSessionAttributes.TRUSTED_ISSUER_JWKS));

        String credentialFormat = resolveCredentialFormat(session);

        // For mDL tests, add the OIDF conformance suite's internal mDL signing certificate
        // because the suite uses a different certificate for mDL than the signing_jwk we provide
        if ("iso_mdl".equalsIgnoreCase(credentialFormat)) {
            String oidfMdlJwk = oidfMdlIssuerCertificateAsJwk();
            if (oidfMdlJwk != null && !oidfMdlJwk.isBlank()) {
                trustedIssuerJwks.add(oidfMdlJwk);
            }
        }
        String authType = resolveAuthType(session);
        URI publicBase = baseUri(request).build().toUri();
        String host = UrlNormalizer.extractHostname(publicBase.getHost());
        if (host == null || host.isBlank()) {
            host = "verifier.localtest.me";
        }
        String dcqlQuery = "iso_mdl".equalsIgnoreCase(credentialFormat)
                ? defaultMdocDcqlQuery()
                : defaults.dcqlQuery();

        ConformanceFlowRunner.ConformanceFlowStartResult flow = flowRunner.startFlow(
                new ConformanceFlowRunner.ConformanceFlowStartRequest(
                        publicBase,
                        walletAuthEndpoint,
                        host,
                        authType,
                        "direct_post.jwt",
                        "request_uri",
                        "get",
                        dcqlQuery,
                        defaults.clientMetadata(),
                        "https://self-issued.me/v2",
                        trustedIssuerJwks
                )
        );

        Instant authRequestStartedAt = Instant.now();
        int status;
        Map<String, String> requestHeaders = Map.of("Accept", MediaType.TEXT_HTML_VALUE);
        Map<String, String> responseHeaders = Map.of();
        String responseBody = "";
        try {
            HttpClient http = HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();
            HttpRequest authRequest = HttpRequest.newBuilder(flow.authorizationRequestUri())
                    .timeout(Duration.ofSeconds(20))
                    .header("Accept", MediaType.TEXT_HTML_VALUE)
                    .GET()
                    .build();
            HttpResponse<Void> response = http.send(authRequest, HttpResponse.BodyHandlers.discarding());
            status = response.statusCode();
            Map<String, List<String>> headerMap = response.headers().map();
            if (headerMap != null && !headerMap.isEmpty()) {
                Map<String, String> flattened = new LinkedHashMap<>();
                headerMap.forEach((k, values) -> flattened.put(k, values != null ? String.join(", ", values) : ""));
                responseHeaders = flattened;
            }
            responseBody = "HTTP " + status;
        } catch (Exception e) {
            debugLogService.addVerificationAt(
                    authRequestStartedAt,
                    flow.state(),
                    "Authorization",
                    "Authorization request to wallet",
                    "GET",
                    flow.authorizationRequestUri().toString(),
                    requestHeaders,
                    "",
                    null,
                    Map.of(),
                    e.getMessage() != null ? e.getMessage() : String.valueOf(e),
                    "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#vp_token_request",
                    ""
            );
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .body(Map.of(
                            "error", "Failed to call wallet authorization endpoint: " + e.getMessage(),
                            "state", flow.state()
                    ));
        }
        debugLogService.addVerificationAt(
                authRequestStartedAt,
                flow.state(),
                "Authorization",
                "Authorization request to wallet",
                "GET",
                flow.authorizationRequestUri().toString(),
                requestHeaders,
                "",
                status,
                responseHeaders,
                responseBody,
                "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#vp_token_request",
                ""
        );
        if (status >= 400) {
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .body(Map.of(
                            "error", "Wallet authorization endpoint returned HTTP " + status,
                            "state", flow.state()
                    ));
        }

        session.setAttribute(SESSION_CONFORMANCE_FLOW_STARTED_RUN_ID, runId);
        session.setAttribute(SESSION_CONFORMANCE_FLOW_LAST_STATE, flow.state());
        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(Map.of(
                        "started", true,
                        "alreadyStarted", false,
                        "runId", runId,
                        "state", flow.state(),
                        "walletAuthStatus", status
                ));
    }

    @GetMapping("/api/info/{id}")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> conformanceRunInfo(@PathVariable("id") String testId,
                                                                  HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        try {
            String baseUrl = effectiveConformanceBaseUrl(session);
            if (baseUrl == null || baseUrl.isBlank()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "Conformance base URL not configured"));
            }
            Map<String, Object> info = conformanceSuiteService.loadTestInfo(
                    testId,
                    baseUrl,
                    effectiveConformanceApiKey(session));
            return ResponseEntity.ok()
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .body(info);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/api/log/{id}")
    @ResponseBody
    public ResponseEntity<Object> conformanceRunLog(@PathVariable("id") String testId,
                                                    @RequestParam(name = "since", required = false) Long since,
                                                    HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        try {
            String baseUrl = effectiveConformanceBaseUrl(session);
            if (baseUrl == null || baseUrl.isBlank()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "Conformance base URL not configured"));
            }
            List<Map<String, Object>> log = conformanceSuiteService.loadTestLog(
                    testId,
                    since,
                    baseUrl,
                    effectiveConformanceApiKey(session));
            return ResponseEntity.ok()
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .body(log);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .body(Map.of("error", e.getMessage()));
        }
    }

    private void updateConformanceConfig(HttpSession session, String baseUrl, String apiKey) {
        if (session == null) {
            return;
        }
        if (baseUrl != null) {
            String normalized = UrlNormalizer.normalizeBaseUrl(baseUrl);
            if (normalized != null && !normalized.isBlank()) {
                session.setAttribute(SESSION_CONFORMANCE_BASE_URL, normalized);
            } else {
                session.removeAttribute(SESSION_CONFORMANCE_BASE_URL);
            }
        }
        String normalizedKey = normalizeConformanceApiKey(apiKey);
        if (normalizedKey != null && !normalizedKey.isBlank()) {
            session.setAttribute(SESSION_CONFORMANCE_API_KEY, normalizedKey);
        }
    }

    private String effectiveConformanceBaseUrl(HttpSession session) {
        String sessionValue = session != null ? (String) session.getAttribute(SESSION_CONFORMANCE_BASE_URL) : null;
        return firstNonBlank(sessionValue, conformanceProperties.resolvedBaseUrl());
    }

    private String effectiveConformanceApiKey(HttpSession session) {
        String sessionValue = session != null ? (String) session.getAttribute(SESSION_CONFORMANCE_API_KEY) : null;
        return firstNonBlank(sessionValue, conformanceProperties.resolvedApiKey());
    }

    private String normalizeConformanceApiKey(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isBlank() ? null : trimmed;
    }

    private String resolveCredentialFormat(HttpSession session) {
        String module = stringAttr(session, SESSION_CONFORMANCE_LAST_MODULE);
        Object planValue = session != null ? session.getAttribute(SESSION_CONFORMANCE_PLAN) : null;
        if (planValue instanceof ConformanceSuiteService.ConformancePlan plan) {
            String fromPlan = variantValue(plan.variant(), "credential_format");
            if ("iso_mdl".equalsIgnoreCase(fromPlan)) {
                return "iso_mdl";
            }
            if ("sd_jwt_vc".equalsIgnoreCase(fromPlan)) {
                return "sd_jwt_vc";
            }

            if (module != null && !module.isBlank() && plan.modules() != null) {
                for (ConformanceSuiteService.ConformanceModule entry : plan.modules()) {
                    if (entry != null && module.equals(entry.testModule())) {
                        String value = variantValue(entry.variant(), "credential_format");
                        if ("iso_mdl".equalsIgnoreCase(value)) {
                            return "iso_mdl";
                        }
                        if ("sd_jwt_vc".equalsIgnoreCase(value)) {
                            return "sd_jwt_vc";
                        }
                    }
                }
            }
        }
        return "sd_jwt_vc";
    }

    private String resolveAuthType(HttpSession session) {
        String module = stringAttr(session, SESSION_CONFORMANCE_LAST_MODULE);
        Object planValue = session != null ? session.getAttribute(SESSION_CONFORMANCE_PLAN) : null;
        if (planValue instanceof ConformanceSuiteService.ConformancePlan plan) {
            String planValueRaw = firstNonBlank(
                    variantValue(plan.variant(), "client_id_prefix"),
                    variantValue(plan.variant(), "client_id_scheme"));
            if ("x509_hash".equalsIgnoreCase(planValueRaw)) {
                return "x509_hash";
            }
            if ("x509_san_dns".equalsIgnoreCase(planValueRaw)) {
                return "x509_san_dns";
            }

            if (module != null && !module.isBlank() && plan.modules() != null) {
                for (ConformanceSuiteService.ConformanceModule entry : plan.modules()) {
                    if (entry != null && module.equals(entry.testModule())) {
                        String value = firstNonBlank(
                                variantValue(entry.variant(), "client_id_prefix"),
                                variantValue(entry.variant(), "client_id_scheme"));
                        if ("x509_hash".equalsIgnoreCase(value)) {
                            return "x509_hash";
                        }
                        if ("x509_san_dns".equalsIgnoreCase(value)) {
                            return "x509_san_dns";
                        }
                    }
                }
            }
        }
        return "x509_san_dns";
    }

    private String variantValue(Map<String, Object> variant, String key) {
        if (variant == null || key == null) {
            return "";
        }
        Object value = variant.get(key);
        return value == null ? "" : String.valueOf(value);
    }

    private String normalizeVariant(String value, String fallback, String alternative) {
        String trimmed = value != null ? value.trim() : "";
        if (alternative != null && !alternative.isBlank() && alternative.equalsIgnoreCase(trimmed)) {
            return alternative;
        }
        if (fallback != null && !fallback.isBlank() && fallback.equalsIgnoreCase(trimmed)) {
            return fallback;
        }
        return fallback;
    }

    private String defaultMdocDcqlQuery() {
        return """
                {"credentials":[{"id":"mdoc-proof","format":"mso_mdoc","claims":[{"path":["given_name"]},{"path":["document_number"]}]}]}""";
    }

    private String stringAttr(HttpSession session, String name) {
        if (session == null || name == null) {
            return null;
        }
        Object value = session.getAttribute(name);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value);
        return text.isBlank() ? null : text;
    }

    private List<String> readStringListAttr(HttpSession session, String name) {
        if (session == null || name == null) {
            return List.of();
        }
        Object value = session.getAttribute(name);
        if (value instanceof List<?> list) {
            List<String> out = new ArrayList<>();
            for (Object item : list) {
                if (item == null) {
                    continue;
                }
                String text = String.valueOf(item).trim();
                if (!text.isBlank()) {
                    out.add(text);
                }
            }
            return List.copyOf(out);
        }
        if (value instanceof String str) {
            String text = str.trim();
            return text.isBlank() ? List.of() : List.of(text);
        }
        return List.of();
    }

    private void storeTrustedIssuerKeys(HttpSession session, ConformanceSuiteService.ConformancePlan plan) {
        if (session == null || plan == null) {
            return;
        }
        List<String> keys = extractTrustedIssuerJwks(plan);
        if (keys.isEmpty()) {
            session.removeAttribute(ConformanceSessionAttributes.TRUSTED_ISSUER_JWKS);
        } else {
            session.setAttribute(ConformanceSessionAttributes.TRUSTED_ISSUER_JWKS, keys);
        }
    }

    private List<String> extractTrustedIssuerJwks(ConformanceSuiteService.ConformancePlan conformancePlan) {
        if (conformancePlan == null || conformancePlan.rawJson() == null || conformancePlan.rawJson().isBlank()) {
            return List.of();
        }
        try {
            JsonNode root = objectMapper.readTree(conformancePlan.rawJson());
            JsonNode signing = root.path("config").path("credential").path("signing_jwk");
            List<String> out = new ArrayList<>();
            if (signing.isObject()) {
                JsonNode keys = signing.path("keys");
                if (keys.isArray()) {
                    for (JsonNode key : keys) {
                        String jwk = toPublicJwkJson(key);
                        if (jwk != null && !jwk.isBlank()) {
                            out.add(jwk);
                        }
                    }
                } else {
                    String jwk = toPublicJwkJson(signing);
                    if (jwk != null && !jwk.isBlank()) {
                        out.add(jwk);
                    }
                }
            }
            return List.copyOf(out);
        } catch (Exception e) {
            return List.of();
        }
    }

    private String toPublicJwkJson(JsonNode key) {
        if (key == null || !key.isObject()) {
            return null;
        }
        ObjectNode publicKey = ((ObjectNode) key).deepCopy();
        for (String field : CONFORMANCE_JWK_PRIVATE_FIELDS) {
            publicKey.remove(field);
        }
        try {
            return objectMapper.writeValueAsString(publicKey);
        } catch (Exception e) {
            return null;
        }
    }

    private String walletAuthEndpointFromRunUrl(String runUrl) {
        if (runUrl == null || runUrl.isBlank()) {
            return null;
        }
        String trimmed = runUrl.trim();
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        // Normalize URL to remove non-standard ports (e.g., HTTPS with port 80)
        trimmed = UrlNormalizer.normalizePort(trimmed);
        if (trimmed.endsWith("/authorize")) {
            return trimmed;
        }
        return trimmed + "/authorize";
    }

    private UriComponentsBuilder baseUri(HttpServletRequest request) {
        if (publicBaseUri != null) {
            UriComponentsBuilder builder = UriComponentsBuilder.newInstance()
                    .scheme(publicBaseUri.getScheme())
                    .host(publicBaseUri.getHost());
            if (publicBaseUri.getPort() != -1) {
                builder.port(publicBaseUri.getPort());
            }
            if (publicBaseUri.getPath() != null && !publicBaseUri.getPath().isBlank()) {
                builder.path(publicBaseUri.getPath());
            }
            return builder;
        }
        String scheme = firstHeaderValue(request, "X-Forwarded-Proto");
        if (scheme == null || scheme.isBlank()) {
            scheme = request.getScheme();
        }
        String hostHeader = firstHeaderValue(request, "X-Forwarded-Host");
        String host = null;
        Integer port = null;
        if (hostHeader != null && !hostHeader.isBlank()) {
            String[] hostParts = hostHeader.split(",", 2)[0].trim().split(":", 2);
            host = hostParts[0];
            if (hostParts.length > 1) {
                try {
                    port = Integer.parseInt(hostParts[1]);
                } catch (NumberFormatException ignored) {
                }
            }
        }
        String portHeader = firstHeaderValue(request, "X-Forwarded-Port");
        if (port == null && portHeader != null && !portHeader.isBlank()) {
            try {
                port = Integer.parseInt(portHeader.split(",", 2)[0].trim());
            } catch (NumberFormatException ignored) {
            }
        }
        if (host == null || host.isBlank()) {
            host = request.getServerName();
        }
        if (port == null) {
            port = request.getServerPort();
        }
        UriComponentsBuilder builder = UriComponentsBuilder.newInstance()
                .scheme(scheme)
                .host(host);
        if (!UrlNormalizer.shouldOmitPort(scheme, port)) {
            builder.port(port);
        }
        String contextPath = request.getContextPath();
        if (contextPath != null && !contextPath.isBlank()) {
            builder.path(contextPath);
        }
        return builder;
    }

    private String firstHeaderValue(HttpServletRequest request, String name) {
        String value = request.getHeader(name);
        if (value == null) {
            return null;
        }
        int comma = value.indexOf(',');
        if (comma >= 0) {
            return value.substring(0, comma).trim();
        }
        return value.trim();
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }

    /**
     * Convert the OIDF mDL issuer certificate to a JWK JSON string for use as a trusted issuer key.
     */
    private String oidfMdlIssuerCertificateAsJwk() {
        try {
            var cert = CertificateUtils.parsePemCertificate(OIDF_MDL_ISSUER_CERTIFICATE_PEM);
            return CertificateUtils.toEcJwkJson(cert);
        } catch (Exception e) {
            return null;
        }
    }
}
