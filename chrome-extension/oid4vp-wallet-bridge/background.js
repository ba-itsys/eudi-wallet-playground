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
// Dynamic content script registration for custom sites
const DYNAMIC_SCRIPT_ID = "oid4vp-custom-sites";
const STORAGE_KEY_CUSTOM_SITES = "oid4vpCustomSites";

async function updateCustomSiteScripts(sites) {
  // Remove existing dynamic scripts
  try {
    await chrome.scripting.unregisterContentScripts({ ids: [DYNAMIC_SCRIPT_ID] });
  } catch (e) {
    // Ignore if not registered
  }

  if (!sites || sites.length === 0) {
    return;
  }

  // Validate and filter patterns
  const validPatterns = sites.filter((pattern) => {
    if (!pattern || typeof pattern !== "string") return false;
    // Basic validation - must contain :// or start with *://
    return pattern.includes("://") || pattern.startsWith("*");
  });

  if (validPatterns.length === 0) {
    return;
  }

  try {
    await chrome.scripting.registerContentScripts([
      {
        id: DYNAMIC_SCRIPT_ID,
        matches: validPatterns,
        js: ["content-script.js"],
        runAt: "document_start",
      },
    ]);
  } catch (e) {
    console.error("Failed to register custom site scripts:", e);
  }
}

// Load custom sites on startup
chrome.storage.local.get([STORAGE_KEY_CUSTOM_SITES], (items) => {
  const sites = items[STORAGE_KEY_CUSTOM_SITES] || [];
  updateCustomSiteScripts(sites);
});

// Listen for updates from options page
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === "oid4vp_update_custom_sites") {
    updateCustomSiteScripts(message.sites || []);
    sendResponse({ ok: true });
    return true;
  }
});

function oid4vpBridgeMain() {
  (() => {
    if (window.__oid4vpWalletBridgeInjected) {
      return;
    }
    window.__oid4vpWalletBridgeInjected = true;
    window.__oid4vpWalletBridgeInstalled = false;
    window.__oid4vpWalletBridgeInstallError = "";
    try {
      const mark = () => {
        if (document && document.documentElement) {
          document.documentElement.setAttribute("data-oid4vp-wallet-bridge-main-script", "true");
          return true;
        }
        return false;
      };
      if (!mark()) {
        try {
          document.addEventListener("DOMContentLoaded", () => mark(), { once: true });
        } catch (e) {
        }
        setTimeout(mark, 0);
      }
    } catch (e) {
    }

    const ATTR_ENABLED = "data-oid4vp-wallet-bridge-enabled";
    const ATTR_WALLET_AUTH_ENDPOINT = "data-oid4vp-wallet-bridge-wallet-auth-endpoint";
    const ATTR_POPUP_WIDTH = "data-oid4vp-wallet-bridge-popup-width";
    const ATTR_POPUP_HEIGHT = "data-oid4vp-wallet-bridge-popup-height";
    const DEFAULT_WALLET_AUTH_ENDPOINT = "http://localhost:3000/oid4vp/auth";
    const PENDING_KEY = "__oid4vpWalletBridgePending";
    const DELIVER_KEY = "__oid4vpWalletBridgeDeliver";
    const DELIVER_BY_RESPONSE_URI_KEY = "__oid4vpWalletBridgeDeliverToResponseUri";

    try {
      if (!window[PENDING_KEY]) {
        window[PENDING_KEY] = {};
      }
      if (typeof window[DELIVER_KEY] !== "function") {
        window[DELIVER_KEY] = (bridgeRequestId, data, origin) => {
          const pending = window[PENDING_KEY];
          if (!pending || !bridgeRequestId) {
            return;
          }
          const entry = pending[bridgeRequestId];
          if (!entry) {
            return;
          }
          const expected = entry.walletOrigin;
          if (expected && origin && expected !== origin) {
            return;
          }
          try {
            delete pending[bridgeRequestId];
          } catch (e) {
          }
          try {
            if (typeof entry.deliver === "function") {
              entry.deliver(data);
            }
          } catch (e) {
          }
        };
      }
      if (typeof window[DELIVER_BY_RESPONSE_URI_KEY] !== "function") {
        window[DELIVER_BY_RESPONSE_URI_KEY] = (responseUri, data, origin) => {
          console.log("[OID4VP Bridge] DeliverByResponseUri called, responseUri:", responseUri, "data:", data);
          const pending = window[PENDING_KEY];
          console.log("[OID4VP Bridge] Pending entries:", pending ? Object.keys(pending) : "none");
          if (!pending || !responseUri) {
            console.log("[OID4VP Bridge] No pending or no responseUri");
            return;
          }
          const expectedUri = String(responseUri);
          let expectedKey = expectedUri;
          try {
            const parsed = new URL(expectedUri, window.location.href);
            expectedKey = parsed.origin + parsed.pathname;
          } catch (e) {
          }
          console.log("[OID4VP Bridge] Looking for expectedKey:", expectedKey);

          // Helper to normalize URI to origin+pathname for comparison
          function normalizeUri(uri) {
            if (!uri) return "";
            try {
              const parsed = new URL(uri, window.location.href);
              return parsed.origin + parsed.pathname;
            } catch (e) {
              return String(uri);
            }
          }

          // Helper to check if a URI matches the expected key
          function uriMatches(uri) {
            if (!uri) return false;
            const normalized = normalizeUri(uri);
            return normalized === expectedKey || String(uri) === expectedUri;
          }

          for (const bridgeRequestId of Object.keys(pending)) {
            const entry = pending[bridgeRequestId];
            console.log("[OID4VP Bridge] Checking entry", bridgeRequestId, "responseUri:", entry ? entry.responseUri : "none", "jwtResponseUri:", entry ? entry.jwtResponseUri : "none");
            if (!entry) {
              continue;
            }
            // Check both the synthetic bridge URL and the JWT's response_uri
            const matchesSynthetic = entry.responseUri && uriMatches(entry.responseUri);
            const matchesJwt = entry.jwtResponseUri && uriMatches(entry.jwtResponseUri);
            if (!matchesSynthetic && !matchesJwt) {
              console.log("[OID4VP Bridge] URI mismatch, syntheticKey:", normalizeUri(entry.responseUri), "jwtKey:", normalizeUri(entry.jwtResponseUri), "expectedKey:", expectedKey);
              continue;
            }
            const expectedOrigin = entry.walletOrigin;
            if (expectedOrigin && origin && expectedOrigin !== origin) {
              console.log("[OID4VP Bridge] Origin mismatch, expected:", expectedOrigin, "got:", origin);
              continue;
            }
            console.log("[OID4VP Bridge] Found matching entry (matchesSynthetic:", matchesSynthetic, "matchesJwt:", matchesJwt, "), delivering data");
            // Debug: log the full payload being delivered
            console.log("[OID4VP Bridge] Delivering payload:", JSON.stringify(data, null, 2));
            try {
              delete pending[bridgeRequestId];
            } catch (e) {
            }
            try {
              if (typeof entry.deliver === "function") {
                entry.deliver(data);
              }
            } catch (e) {
              console.error("[OID4VP Bridge] Error delivering:", e);
            }
            return;
          }
          console.log("[OID4VP Bridge] No matching pending entry found");
        };
      }
    } catch (e) {
    }

    try {
      if (!window.__oid4vpWalletBridgeMessageListenerInstalled) {
        window.__oid4vpWalletBridgeMessageListenerInstalled = true;
        window.addEventListener(
          "message",
          (event) => {
            try {
              const msg = event && event.data;
              if (!msg) {
                return;
              }
              // Handle extension's internal delivery message
              if (msg.type === "oid4vp_wallet_bridge_deliver") {
                console.log("[OID4VP Bridge] Internal delivery message:", msg);
                const responseUri = msg.responseUri;
                const payload = msg.data || {};
                const origin = msg.walletOrigin || "";
                // Debug: log credential data
                if (payload.vp_token) {
                  console.log("[OID4VP Bridge] vp_token in internal delivery:", JSON.stringify(payload.vp_token, null, 2));
                }
                if (payload.response) {
                  console.log("[OID4VP Bridge] Encrypted response in internal delivery (length):", payload.response.length);
                }
                if (typeof window[DELIVER_BY_RESPONSE_URI_KEY] === "function") {
                  window[DELIVER_BY_RESPONSE_URI_KEY](responseUri, payload, origin);
                }
                return;
              }
              // Handle direct postMessage from wallet popup
              if (msg.type === "oid4vp_wallet_response") {
                console.log("[OID4VP Bridge] Received postMessage from wallet:", msg);
                const responseUri = msg.responseUri;
                const payload = msg.data || {};
                const origin = event.origin || "";
                // Debug: log credential data for troubleshooting
                if (payload.vp_token) {
                  console.log("[OID4VP Bridge] vp_token received:", JSON.stringify(payload.vp_token, null, 2));
                }
                if (payload.response) {
                  console.log("[OID4VP Bridge] Encrypted response received (length):", payload.response.length);
                }
                if (typeof window[DELIVER_BY_RESPONSE_URI_KEY] === "function") {
                  window[DELIVER_BY_RESPONSE_URI_KEY](responseUri, payload, origin);
                }
                return;
              }
            } catch (e) {
              console.error("[OID4VP Bridge] Error handling postMessage:", e);
            }
          },
          false
        );
      }
    } catch (e) {
    }

    function resolveOriginalGet(credentialsContainer) {
      if (!credentialsContainer || typeof credentialsContainer.get !== "function") {
        return null;
      }
      try {
        return credentialsContainer.get.bind(credentialsContainer);
      } catch (e) {
        return null;
      }
    }

    function ensureCredentialsContainer() {
      if (navigator.credentials && isObject(navigator.credentials)) {
        return navigator.credentials;
      }

      const container = {};
      try {
        Object.defineProperty(navigator, "credentials", {
          configurable: true,
          enumerable: true,
          writable: true,
          value: container,
        });
      } catch (e) {}
      if (navigator.credentials && isObject(navigator.credentials)) {
        return navigator.credentials;
      }
      try {
        navigator.credentials = container;
      } catch (e) {}
      if (navigator.credentials && isObject(navigator.credentials)) {
        return navigator.credentials;
      }

      const proto = Object.getPrototypeOf(navigator);
      if (proto) {
        try {
          Object.defineProperty(proto, "credentials", {
            configurable: true,
            enumerable: true,
            writable: true,
            value: container,
          });
        } catch (e) {}
      }
      return navigator.credentials && isObject(navigator.credentials) ? navigator.credentials : null;
    }

    function isEnabled() {
      const value = document.documentElement ? document.documentElement.getAttribute(ATTR_ENABLED) : null;
      return value !== "false";
    }

    function getPopupSize() {
      const widthRaw = document.documentElement ? document.documentElement.getAttribute(ATTR_POPUP_WIDTH) : null;
      const heightRaw = document.documentElement ? document.documentElement.getAttribute(ATTR_POPUP_HEIGHT) : null;
      const width = Number(widthRaw);
      const height = Number(heightRaw);
      return {
        width: Number.isFinite(width) && width > 0 ? width : 600,
        height: Number.isFinite(height) && height > 0 ? height : 900,
      };
    }

    function isObject(value) {
      return value !== null && typeof value === "object";
    }

    function findOid4vpRequest(options) {
      const digital = options && options.digital;
      if (!digital || !Array.isArray(digital.requests)) {
        return null;
      }
      for (const entry of digital.requests) {
        if (!entry || typeof entry.protocol !== "string") {
          continue;
        }
        const protocol = entry.protocol;
        const data = entry.data;
        if (protocol === "openid4vp-v1-unsigned") {
          if (isObject(data) && isObject(data.request)) {
            return { requestType: "unsigned", protocol, request: data.request };
          }
          if (isObject(data)) {
            return { requestType: "unsigned", protocol, request: data };
          }
          return null;
        }
        if (protocol === "openid4vp-v1-signed") {
          if (isObject(data) && typeof data.request === "string" && data.request.trim()) {
            return { requestType: "signed", protocol, request: data.request.trim() };
          }
          return null;
        }
        if (protocol === "openid4vp-v1-multisigned") {
          if (isObject(data) && isObject(data.request)) {
            return { requestType: "multisigned", protocol, request: data.request };
          }
          if (isObject(data) && typeof data.request === "string" && data.request.trim()) {
            return { requestType: "multisigned", protocol, request: data.request.trim() };
          }
          return null;
        }
      }
      return null;
    }

    function parseWalletAuthEndpointFromPage() {
      const meta = document.querySelector(
        'meta[name="oid4vp-wallet-auth-endpoint"], meta[name="oid4vp-wallet-auth-url"]'
      );
      const metaContent = meta && typeof meta.content === "string" ? meta.content.trim() : "";
      if (metaContent) {
        return metaContent;
      }

      const dataEl = document.querySelector("[data-oid4vp-wallet-auth-endpoint], [data-oid4vp-wallet-auth-url]");
      if (dataEl && typeof dataEl.getAttribute === "function") {
        const value =
          dataEl.getAttribute("data-oid4vp-wallet-auth-endpoint") ||
          dataEl.getAttribute("data-oid4vp-wallet-auth-url") ||
          "";
        if (value && String(value).trim()) {
          return String(value).trim();
        }
      }

      const anchors = document.querySelectorAll("a[href]");
      for (const anchor of anchors) {
        const href = anchor.getAttribute("href");
        if (!href) {
          continue;
        }
        try {
          const url = new URL(href, window.location.href);
          if (!url.pathname || !url.pathname.includes("/oid4vp/auth")) {
            continue;
          }
          if (!url.pathname.endsWith("/oid4vp/auth")) {
            continue;
          }
          return url.origin + url.pathname;
        } catch (e) {
        }
      }

      return null;
    }

    function getWalletAuthEndpoint() {
      const fromAttr = document.documentElement ? document.documentElement.getAttribute(ATTR_WALLET_AUTH_ENDPOINT) : null;
      if (fromAttr && String(fromAttr).trim()) {
        return String(fromAttr).trim();
      }
      const fromPage = parseWalletAuthEndpointFromPage();
      if (fromPage) {
        return fromPage.trim();
      }
      return DEFAULT_WALLET_AUTH_ENDPOINT;
    }

    function randomId() {
      if (globalThis.crypto && typeof globalThis.crypto.randomUUID === "function") {
        return globalThis.crypto.randomUUID();
      }
      const bytes = new Uint8Array(16);
      globalThis.crypto.getRandomValues(bytes);
      return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    }

    function decodeJwtPayload(jwt) {
      if (typeof jwt !== "string") {
        return null;
      }
      const parts = jwt.split(".");
      if (parts.length < 2) {
        return null;
      }
      const raw = parts[1];
      if (!raw) {
        return null;
      }
      try {
        const base64 = raw.replace(/-/g, "+").replace(/_/g, "/");
        const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
        const decoded = atob(padded);
        const json = decodeURIComponent(
          Array.from(decoded, (c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0")).join("")
        );
        const obj = JSON.parse(json);
        return isObject(obj) ? obj : null;
      } catch (e) {
        return null;
      }
    }

    // Extract context from the OID4VP request
    function resolveOid4vpContextFromRequest(oid4vp) {
      let requestData = null;
      if (oid4vp && oid4vp.requestType === "signed") {
        requestData = decodeJwtPayload(String(oid4vp.request)) || null;
      } else if (oid4vp && oid4vp.requestType === "multisigned") {
        if (isObject(oid4vp.request)) {
          requestData = oid4vp.request;
        } else {
          requestData = decodeJwtPayload(String(oid4vp.request)) || null;
        }
      } else if (oid4vp && isObject(oid4vp.request)) {
        requestData = oid4vp.request;
      }

      const state = requestData && typeof requestData.state === "string" ? requestData.state : randomId();
      const nonce = requestData && typeof requestData.nonce === "string" ? requestData.nonce : "";
      // Extract JWT's response_uri - wallet may use this for SessionTranscript and delivery
      const jwtResponseUri = requestData && typeof requestData.response_uri === "string" ? requestData.response_uri : null;

      return { state, nonce, requestData, jwtResponseUri };
    }

    // DC API mode: open wallet and return response directly as DigitalCredential
    // NOTE: This requires Chrome's DC API to be disabled, otherwise Chrome intercepts the return value
    function openWalletForDcApi(walletAuthEndpoint, oid4vp, requestContext) {
      const bridgeRequestId = randomId();
      const state = requestContext.state || bridgeRequestId;
      // Create a synthetic response_uri that the wallet will POST to
      const dcApiResponseUri = window.location.origin + "/__oid4vp_dc_api_response__/" + state;
      console.log("[OID4VP Bridge] dcApiResponseUri:", dcApiResponseUri, "bridgeRequestId:", bridgeRequestId);
      const walletUrl = buildWalletUrlForDcApi(walletAuthEndpoint, oid4vp, requestContext, state, dcApiResponseUri);
      console.log("[OID4VP Bridge] walletUrl:", walletUrl.toString());
      const walletOrigin = new URL(walletAuthEndpoint).origin;
      const size = getPopupSize();

      const popup = window.open(
        walletUrl.toString(),
        "_blank",
        `popup,width=${size.width},height=${size.height},resizable=yes,scrollbars=yes`
      );
      if (!popup) {
        console.error("[OID4VP Bridge] Popup blocked");
        return Promise.reject(new Error("Failed to open wallet window (popup blocked?)"));
      }
      console.log("[OID4VP Bridge] Popup opened successfully");

      return new Promise((resolve, reject) => {
        let finished = false;
        const pending = window[PENDING_KEY] || (window[PENDING_KEY] = {});

        function cleanup() {
          window.clearTimeout(timeoutId);
          window.clearInterval(pollInterval);
          try { delete pending[bridgeRequestId]; } catch (e) {}
        }

        function finishOk(data) {
          console.log("[OID4VP Bridge] finishOk called with data:", data);
          if (finished) {
            console.log("[OID4VP Bridge] Already finished, ignoring");
            return;
          }
          finished = true;
          cleanup();
          try { popup.close(); } catch (e) {}

          // Format as DigitalCredential for DC API
          const credential = {
            type: "digital",
            protocol: oid4vp.protocol || "openid4vp",
            data: data || {}
          };
          console.log("[OID4VP Bridge] Resolving with credential:", credential);
          resolve(credential);
        }

        function finishErr(error) {
          console.log("[OID4VP Bridge] finishErr called with error:", error);
          if (finished) return;
          finished = true;
          cleanup();
          reject(error);
        }

        // Store pending entry for delivery matching
        // Include both the synthetic bridge URL and the JWT's response_uri (if different)
        // Real wallets may use either for delivery
        const jwtResponseUri = requestContext.jwtResponseUri || null;
        pending[bridgeRequestId] = {
          walletOrigin,
          responseUri: dcApiResponseUri,
          jwtResponseUri: jwtResponseUri,
          deliver: (data) => finishOk(data),
        };
        console.log("[OID4VP Bridge] Stored pending entry:", bridgeRequestId, "responseUri:", dcApiResponseUri, "jwtResponseUri:", jwtResponseUri);

        // Timeout after 5 minutes
        const timeoutId = window.setTimeout(() => {
          finishErr(new Error("Timed out waiting for wallet response"));
        }, 5 * 60 * 1000);

        // Check if popup is closed (user cancelled)
        let popupClosedAt = null;
        const pollInterval = window.setInterval(() => {
          if (finished) return;
          if (!popup.closed) return;
          if (popupClosedAt === null) {
            popupClosedAt = Date.now();
            return;
          }
          // Wait 30 seconds after popup closes for response to arrive
          if (Date.now() - popupClosedAt >= 30000) {
            finishErr(new Error("Wallet window was closed"));
          }
        }, 500);
      });
    }

    // Map DC API response modes to direct_post equivalents
    function mapDcApiResponseModeToDirectPost(responseMode) {
      if (!responseMode || typeof responseMode !== "string") {
        return "direct_post";
      }
      const normalized = responseMode.trim().toLowerCase();
      if (normalized === "dc_api.jwt" || normalized.endsWith(".jwt")) {
        return "direct_post.jwt";
      }
      return "direct_post";
    }

    function buildWalletUrlForDcApi(walletAuthEndpoint, oid4vp, requestContext, state, responseUri) {
      const requestData = requestContext.requestData || {};
      const nonce = requestContext.nonce || "";
      const clientId = requestData.client_id || "";
      const responseType = requestData.response_type || "vp_token";
      const requestResponseMode = requestData.response_mode || "dc_api";
      const dcqlQuery = requestData.dcql_query;
      const clientMetadata = requestData.client_metadata;

      const url = new URL(walletAuthEndpoint);

      // For signed requests (x509_hash, x509_san_dns, verifier_attestation client_id schemes),
      // pass the original signed JWT as the 'request' parameter
      const isSigned = oid4vp.requestType === "signed" || oid4vp.requestType === "multisigned";
      if (isSigned && typeof oid4vp.request === "string") {
        console.log("[OID4VP Bridge] Passing signed request JWT to wallet");
        url.searchParams.set("request", oid4vp.request);
        // Override response_uri and response_mode in the signed request context
        url.searchParams.set("response_uri", responseUri);
        url.searchParams.set("response_mode", mapDcApiResponseModeToDirectPost(requestResponseMode));
        return url;
      }

      // For unsigned requests, pass individual parameters
      url.searchParams.set("response_type", responseType);
      url.searchParams.set("response_mode", mapDcApiResponseModeToDirectPost(requestResponseMode));
      url.searchParams.set("response_uri", responseUri);
      url.searchParams.set("state", state);
      if (nonce) {
        url.searchParams.set("nonce", nonce);
      }
      if (clientId) {
        url.searchParams.set("client_id", clientId);
      }
      if (dcqlQuery != null) {
        const value = typeof dcqlQuery === "string" ? dcqlQuery : JSON.stringify(dcqlQuery);
        url.searchParams.set("dcql_query", value);
      }
      if (clientMetadata != null) {
        const value = typeof clientMetadata === "string" ? clientMetadata : JSON.stringify(clientMetadata);
        url.searchParams.set("client_metadata", value);
      }
      return url;
    }

    function makePatchedGet(originalGet) {
      return function get(options) {
        console.log("[OID4VP Bridge] makePatchedGet called with options:", options);
        const oid4vp = findOid4vpRequest(options);
        console.log("[OID4VP Bridge] findOid4vpRequest returned:", oid4vp);
        if (!oid4vp || !isEnabled()) {
          console.log("[OID4VP Bridge] Falling through to originalGet, oid4vp=", oid4vp, "isEnabled=", isEnabled());
          if (originalGet) {
            return originalGet(options);
          }
          return Promise.reject(new Error("Credential Management API not available"));
        }
        const walletAuthEndpoint = getWalletAuthEndpoint();
        console.log("[OID4VP Bridge] walletAuthEndpoint:", walletAuthEndpoint);
        if (!walletAuthEndpoint) {
          return Promise.reject(new Error("Wallet bridge not configured. Set a wallet auth endpoint in the extension options."));
        }
        try {
          new URL(walletAuthEndpoint);
        } catch (e) {
          return Promise.reject(new Error("Wallet auth endpoint is not a valid URL: " + walletAuthEndpoint));
        }

        // Always use DC API mode - extract context from request
        const requestContext = resolveOid4vpContextFromRequest(oid4vp);
        console.log("[OID4VP Bridge] Opening wallet with requestContext:", requestContext);
        return openWalletForDcApi(walletAuthEndpoint, oid4vp, requestContext);
      };
    }

    function tryInstall() {
      if (window.__oid4vpWalletBridgeInstalled) {
        return true;
      }

      const credentials = ensureCredentialsContainer();
      if (!credentials) {
        window.__oid4vpWalletBridgeInstallError = "Unable to create navigator.credentials";
        return false;
      }

      const originalGet = resolveOriginalGet(credentials);
      const patched = makePatchedGet(originalGet);

      // Simple wrapper that logs and delegates to our patched implementation
      // NOTE: This extension requires Chrome's DC API to be disabled via:
      //   chrome://flags/#web-identity-digital-credentials -> Disabled
      // or by launching Chrome with:
      //   --disable-features=WebIdentityDigitalCredentials
      const wrappedGet = function(options) {
        console.log("[OID4VP Bridge] credentials.get called with options:", options);
        return patched.call(this, options);
      };

      // Install our patched get function
      let installed = false;

      // Method 1: Define property with getter on credentials object
      try {
        Object.defineProperty(credentials, "get", {
          configurable: true,
          enumerable: true,
          get: function() { return wrappedGet; },
          set: function(v) { /* ignore attempts to override */ }
        });
        installed = true;
        console.log("[OID4VP Bridge] Installed via defineProperty with getter");
      } catch (e) {
        console.log("[OID4VP Bridge] defineProperty with getter failed:", e);
      }

      // Method 2: Direct value assignment as fallback
      if (!installed) {
        try {
          Object.defineProperty(credentials, "get", {
            configurable: true,
            enumerable: true,
            writable: true,
            value: wrappedGet,
          });
          installed = true;
          console.log("[OID4VP Bridge] Installed via defineProperty with value");
        } catch (e) {
          console.log("[OID4VP Bridge] defineProperty with value failed:", e);
        }
      }

      // Method 3: Direct assignment as final fallback
      if (!installed) {
        try {
          credentials.get = wrappedGet;
          installed = true;
          console.log("[OID4VP Bridge] Installed via direct assignment");
        } catch (e) {
          console.log("[OID4VP Bridge] direct assignment failed:", e);
        }
      }

      if (installed) {
        window.__oid4vpWalletBridgeInstalled = true;
        return true;
      }

      window.__oid4vpWalletBridgeInstallError = "All installation methods failed";
      return false;
    }

    let attempts = 0;
    function scheduleInstall() {
      attempts += 1;
      if (tryInstall()) {
        return;
      }
      if (attempts >= 50) {
        return;
      }
      setTimeout(scheduleInstall, 50);
    }

    scheduleInstall();
  })();
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== "oid4vp_wallet_bridge_inject") {
    return;
  }

  const tabId = sender && sender.tab ? sender.tab.id : null;
  if (typeof tabId !== "number") {
    sendResponse({ ok: false, error: "Missing sender.tab.id" });
    return true;
  }

  const func = oid4vpBridgeMain;

  chrome.scripting.executeScript({
    target: { tabId, allFrames: false },
    world: "MAIN",
    injectImmediately: true,
    func: () => {
      window.__oid4vpWalletBridgeBackgroundPing = true;
    },
  }).catch(() => {
  }).then(() => {
    return chrome.scripting.executeScript({
      target: { tabId, allFrames: false },
      world: "MAIN",
      injectImmediately: true,
      func,
    });
  }).then(() => {
    sendResponse({ ok: true });
  }).catch((e) => {
    sendResponse({ ok: false, error: String(e && e.message ? e.message : e) });
  });

  return true;
});

// Form interception script - runs in MAIN world to catch form.submit() calls
function oid4vpFormInterceptScript() {
  if (window.__oid4vpWalletBridgeFormInterceptInstalled) {
    return;
  }
  window.__oid4vpWalletBridgeFormInterceptInstalled = true;

  const originalSubmit = HTMLFormElement.prototype.submit;

  function normalizeOrigin(value) {
    if (!value || typeof value !== "string") {
      return "";
    }
    try {
      return new URL(value).origin;
    } catch (e) {
      return "";
    }
  }

  function resolveActionOrigin(form) {
    if (!form || typeof form.getAttribute !== "function") {
      return "";
    }
    const action = form.getAttribute("action") || "";
    if (!action) {
      return "";
    }
    try {
      return new URL(action, window.location.href).origin;
    } catch (e) {
      return "";
    }
  }

  function extractFormData(form) {
    const data = {};
    if (!form) {
      return data;
    }
    try {
      const inputs = form.querySelectorAll("input, textarea, select");
      for (const input of inputs) {
        const name = input.name || input.getAttribute("name");
        if (!name) {
          continue;
        }
        const value = input.value != null ? String(input.value) : "";
        if (name in data) {
          if (Array.isArray(data[name])) {
            data[name].push(value);
          } else {
            data[name] = [data[name], value];
          }
        } else {
          data[name] = value;
        }
      }
    } catch (e) {
    }
    if (typeof data.vp_token === "string") {
      const trimmed = data.vp_token.trim();
      if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        try {
          data.vp_token = JSON.parse(trimmed);
        } catch (e) {
        }
      }
    }
    return data;
  }

  function isOid4vpDirectPostForm(form) {
    const pageOrigin = normalizeOrigin(window.location.href);
    const actionOrigin = resolveActionOrigin(form);
    // Only intercept cross-origin form submissions
    if (!actionOrigin || !pageOrigin || actionOrigin === pageOrigin) {
      return false;
    }
    const data = extractFormData(form);
    return "vp_token" in data || "response" in data || "error" in data;
  }

  HTMLFormElement.prototype.submit = function (...args) {
    try {
      if (isOid4vpDirectPostForm(this)) {
        const responseUri = this.getAttribute("action") || "";
        const data = extractFormData(this);

        // Check if this is a DC API popup (has window.opener) or same-device flow (no opener)
        // For DC API popups: intercept form and deliver response via extension
        // For same-device flow: let form submit normally to complete the redirect
        const isDcApiPopup = window.opener !== null;

        if (isDcApiPopup) {
          console.log("[OID4VP Bridge] Form intercept - DC API popup detected, intercepting form, responseUri:", responseUri);
          // Use postMessage to notify the content script (works across isolation boundary)
          window.postMessage({
            type: "__oid4vp_wallet_bridge_form_intercept__",
            responseUri,
            data
          }, "*");
          // Don't actually submit the form - the extension will handle the response
          return;
        } else {
          console.log("[OID4VP Bridge] Form intercept - same-device flow detected, allowing form submission, responseUri:", responseUri);
          // Let form submit normally - same-device flow needs the redirect to complete
        }
      }
    } catch (e) {
      console.error("[OID4VP Bridge] Form intercept error:", e);
    }
    return originalSubmit.apply(this, args);
  };
}

// Handle request to inject form interception script into MAIN world
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== "oid4vp_wallet_bridge_inject_form_intercept") {
    return;
  }

  const tabId = sender && sender.tab ? sender.tab.id : null;
  if (typeof tabId !== "number") {
    sendResponse({ ok: false, error: "Missing sender.tab.id" });
    return true;
  }

  // Inject the form interception script into MAIN world
  chrome.scripting.executeScript({
    target: { tabId, allFrames: false },
    world: "MAIN",
    injectImmediately: true,
    func: oid4vpFormInterceptScript,
  }).then(() => {
    sendResponse({ ok: true });
  }).catch((e) => {
    sendResponse({ ok: false, error: String(e && e.message ? e.message : e) });
  });

  return true;
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== "oid4vp_wallet_bridge_wallet_response") {
    return;
  }

  console.log("[OID4VP Bridge] Received wallet_response message:", message);

  const responseUri = message.responseUri;
  const data = message.data;
  const walletOrigin = message.walletOrigin;
  if (!responseUri || typeof responseUri !== "string") {
    console.log("[OID4VP Bridge] Missing responseUri in wallet_response");
    sendResponse({ ok: false, error: "Missing responseUri" });
    return true;
  }

  const openerTabId = sender && sender.tab && typeof sender.tab.openerTabId === "number" ? sender.tab.openerTabId : null;
  const tabId = sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : null;

  console.log("[OID4VP Bridge] openerTabId:", openerTabId, "tabId:", tabId);

  // Only close the tab if it's a DC API popup (has an opener)
  // For same-device flow, the tab should NOT be closed - the form needs to complete
  // and redirect the user back to the verifier
  if (typeof tabId === "number" && typeof openerTabId === "number") {
    console.log("[OID4VP Bridge] Tab has opener (DC API popup), closing tab:", tabId);
    chrome.tabs.remove(tabId, () => {
      if (chrome.runtime.lastError) {
        console.log("[OID4VP Bridge] Could not close tab:", chrome.runtime.lastError.message);
      }
    });
  } else if (typeof tabId === "number") {
    console.log("[OID4VP Bridge] Tab has no opener (same-device flow), NOT closing tab:", tabId);
    // Let the form submission complete and redirect the user
  }

  console.log("[OID4VP Bridge] Calling deliverDirectPostToVerifier with responseUri:", responseUri);
  deliverDirectPostToVerifier(responseUri, data || {}, walletOrigin || "", openerTabId)
    .then(() => {
      console.log("[OID4VP Bridge] deliverDirectPostToVerifier completed successfully");
      sendResponse({ ok: true });
    })
    .catch((e) => {
      console.error("[OID4VP Bridge] deliverDirectPostToVerifier failed:", e);
      sendResponse({ ok: false, error: String(e && e.message ? e.message : e) });
    });
  return true;
});

function normalizeWebRequestFormData(rawFormData) {
  const data = {};
  if (!rawFormData || typeof rawFormData !== "object") {
    return data;
  }
  for (const [key, value] of Object.entries(rawFormData)) {
    if (!key) {
      continue;
    }
    if (Array.isArray(value)) {
      if (value.length === 1) {
        data[key] = String(value[0]);
      } else {
        data[key] = value.map((v) => String(v));
      }
    } else if (value != null) {
      data[key] = String(value);
    }
  }
  if (typeof data.vp_token === "string") {
    const trimmed = data.vp_token.trim();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      try {
        data.vp_token = JSON.parse(trimmed);
      } catch (e) {
      }
    }
  }
  return data;
}

function parseUrlEncodedBody(rawEntries) {
  const data = {};
  if (!Array.isArray(rawEntries) || rawEntries.length === 0) {
    return data;
  }
  try {
    const chunks = [];
    let total = 0;
    for (const entry of rawEntries) {
      if (!entry || !entry.bytes) {
        continue;
      }
      const chunk = new Uint8Array(entry.bytes);
      chunks.push(chunk);
      total += chunk.length;
    }
    if (total === 0) {
      return data;
    }
    const combined = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      combined.set(chunk, offset);
      offset += chunk.length;
    }
    const text = new TextDecoder("utf-8").decode(combined);
    const params = new URLSearchParams(text);
    for (const [key, value] of params.entries()) {
      if (!key) {
        continue;
      }
      if (key in data) {
        if (Array.isArray(data[key])) {
          data[key].push(String(value));
        } else {
          data[key] = [String(data[key]), String(value)];
        }
      } else {
        data[key] = String(value);
      }
    }
  } catch (e) {
    return data;
  }
  if (typeof data.vp_token === "string") {
    const trimmed = data.vp_token.trim();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      try {
        data.vp_token = JSON.parse(trimmed);
      } catch (e) {
      }
    }
  }
  return data;
}

function originOf(url) {
  if (!url || typeof url !== "string") {
    return "";
  }
  try {
    return new URL(url).origin;
  } catch (e) {
    return "";
  }
}

function queryAllTabs() {
  return new Promise((resolve) => {
    try {
      chrome.tabs.query({}, (tabs) => resolve(tabs || []));
    } catch (e) {
      resolve([]);
    }
  });
}

async function deliverDirectPostToVerifier(responseUri, data, walletOrigin, openerTabId) {
  function deliverToTab(tabId) {
    console.log("[OID4VP Bridge] deliverToTab called for tabId:", tabId);
    return chrome.scripting.executeScript({
      target: { tabId, allFrames: false },
      world: "MAIN",
      injectImmediately: true,
      func: (uri, payload, origin) => {
        console.log("[OID4VP Bridge] Injected delivery script running in tab, uri:", uri);
        // Set diagnostic attributes for debugging/testing
        try {
          if (document && document.documentElement) {
            document.documentElement.setAttribute("data-oid4vp-wallet-bridge-last-response-uri", String(uri || ""));
            document.documentElement.setAttribute("data-oid4vp-wallet-bridge-last-response-origin", String(origin || ""));
            document.documentElement.setAttribute("data-oid4vp-wallet-bridge-last-response-ts", String(Date.now()));
          }
        } catch (e) {
          console.error("[OID4VP Bridge] Error setting diagnostic attributes:", e);
        }
        // Call the extension's internal delivery function to resolve the DC API promise
        if (typeof window.__oid4vpWalletBridgeDeliverToResponseUri === "function") {
          console.log("[OID4VP Bridge] Calling __oid4vpWalletBridgeDeliverToResponseUri");
          window.__oid4vpWalletBridgeDeliverToResponseUri(uri, payload, origin);
        } else {
          console.warn("[OID4VP Bridge] __oid4vpWalletBridgeDeliverToResponseUri not found on window");
        }
      },
      args: [responseUri, data, walletOrigin],
    }).then(result => {
      console.log("[OID4VP Bridge] executeScript completed for tab", tabId, "result:", result);
      return result;
    }).catch(err => {
      console.error("[OID4VP Bridge] executeScript failed for tab", tabId, "error:", err);
      throw err;
    });
  }

  async function deliverToAllTabs(skipTabId) {
    const tabs = await queryAllTabs();
    const ids = (tabs || [])
      .map((t) => t && typeof t.id === "number" ? t.id : null)
      .filter((id) => typeof id === "number" && id !== skipTabId);
    await Promise.all(ids.map((tabId) => deliverToTab(tabId).catch(() => {
    })));
  }

  let openerDelivered = false;
  if (typeof openerTabId === "number") {
    try {
      await deliverToTab(openerTabId);
      openerDelivered = true;
    } catch (e) {
      openerDelivered = false;
    }
  }
  await deliverToAllTabs(openerDelivered ? openerTabId : null);
}

// Log ALL requests for debugging
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    // Only log POST requests to reduce noise
    if (details && details.method === "POST") {
      console.log("[OID4VP Bridge] webRequest.onBeforeRequest - POST to:", details.url, "tabId:", details.tabId);
    }
  },
  { urls: ["<all_urls>"] }
);

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    try {
      if (!details || details.method !== "POST" || !details.url) {
        return;
      }

      const destinationOrigin = originOf(details.url);

      const requestBody = details.requestBody || null;
      console.log("[OID4VP Bridge] webRequest POST requestBody:", requestBody ? "present" : "null", "formData:", requestBody?.formData ? "yes" : "no", "raw:", requestBody?.raw ? "yes" : "no");
      const data =
        requestBody && requestBody.formData
          ? normalizeWebRequestFormData(requestBody.formData)
          : (requestBody && requestBody.raw ? parseUrlEncodedBody(requestBody.raw) : {});

      console.log("[OID4VP Bridge] webRequest intercepted POST to:", details.url, "data keys:", Object.keys(data), "data:", JSON.stringify(data).substring(0, 200));

      if (!("vp_token" in data) && !("response" in data) && !("error" in data)) {
        console.log("[OID4VP Bridge] No vp_token/response/error in data, ignoring");
        return;
      }

      const sourceUrl = details.initiator || details.documentUrl || details.originUrl || "";
      const sourceOrigin = originOf(sourceUrl);
      const isCrossOrigin = sourceOrigin && destinationOrigin && sourceOrigin !== destinationOrigin;
      const isDirectPostJwtLike = ("response" in data) && !("state" in data);

      console.log("[OID4VP Bridge] sourceOrigin:", sourceOrigin, "destinationOrigin:", destinationOrigin, "isCrossOrigin:", isCrossOrigin);

      if (!isCrossOrigin && !isDirectPostJwtLike) {
        console.log("[OID4VP Bridge] Not cross-origin and not direct_post.jwt, ignoring");
        return;
      }

      console.log("[OID4VP Bridge] Delivering response to verifier, url:", details.url);
      const tabId = typeof details.tabId === "number" ? details.tabId : -1;

      // Only close the tab if it's a DC API popup (has an opener)
      // For same-device flow, the tab should NOT be closed - the form needs to complete
      // and redirect the user back to the verifier
      if (tabId >= 0) {
        deliverDirectPostToVerifier(details.url, data, sourceOrigin, null);

        // Check if this tab has an opener (indicating it's a popup from DC API flow)
        chrome.tabs.get(tabId, (tab) => {
          if (chrome.runtime.lastError) {
            // Tab doesn't exist or error - ignore
            console.log("[OID4VP Bridge] Could not get tab info:", chrome.runtime.lastError.message);
            return;
          }

          // Only close if it's a popup (has openerTabId)
          // Same-device flow tabs don't have an opener and should stay open for redirect
          if (tab && typeof tab.openerTabId === "number") {
            console.log("[OID4VP Bridge] Tab has opener (DC API popup), closing tab:", tabId);
            chrome.tabs.remove(tabId, () => {
              if (chrome.runtime.lastError) {
                console.log("[OID4VP Bridge] Could not close tab:", chrome.runtime.lastError.message);
              }
            });
          } else {
            console.log("[OID4VP Bridge] Tab has no opener (same-device flow), NOT closing tab:", tabId);
            // Let the form submission complete and redirect the user
          }
        });
      } else {
        deliverDirectPostToVerifier(details.url, data, sourceOrigin, null);
      }
    } catch (e) {
      console.error("[OID4VP Bridge] Error in webRequest handler:", e);
      return;
    }
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);
