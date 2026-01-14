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
(() => {
  const STORAGE_KEY_WALLET_AUTH_ENDPOINT = "oid4vpWalletAuthEndpoint";
  const STORAGE_KEY_POPUP_WIDTH = "oid4vpPopupWidth";
  const STORAGE_KEY_POPUP_HEIGHT = "oid4vpPopupHeight";
  const STORAGE_KEY_ENABLE = "oid4vpEnableBridge";

  const ATTR_ENABLED = "data-oid4vp-wallet-bridge-enabled";
  const ATTR_WALLET_AUTH_ENDPOINT = "data-oid4vp-wallet-bridge-wallet-auth-endpoint";
  const ATTR_POPUP_WIDTH = "data-oid4vp-wallet-bridge-popup-width";
  const ATTR_POPUP_HEIGHT = "data-oid4vp-wallet-bridge-popup-height";

  function setDomAttr(name, value) {
    if (!document.documentElement) {
      return;
    }
    if (value === null || value === undefined || value === "") {
      document.documentElement.removeAttribute(name);
      return;
    }
    document.documentElement.setAttribute(name, String(value));
  }

  setDomAttr("data-oid4vp-wallet-bridge-content-script", "true");

  function normalizeUrl(value) {
    if (!value || typeof value !== "string") return "";
    return value.trim();
  }

  function applyConfigToDom(items) {
    if (!items || typeof items !== "object") {
      return;
    }
    setDomAttr(ATTR_ENABLED, items[STORAGE_KEY_ENABLE] === false ? "false" : "true");
    setDomAttr(ATTR_WALLET_AUTH_ENDPOINT, normalizeUrl(items[STORAGE_KEY_WALLET_AUTH_ENDPOINT]));
    const width = Number(items[STORAGE_KEY_POPUP_WIDTH]);
    const height = Number(items[STORAGE_KEY_POPUP_HEIGHT]);
    setDomAttr(ATTR_POPUP_WIDTH, Number.isFinite(width) && width > 0 ? width : "");
    setDomAttr(ATTR_POPUP_HEIGHT, Number.isFinite(height) && height > 0 ? height : "");
  }

  try {
    chrome.storage.local.get(
      [
        STORAGE_KEY_ENABLE,
        STORAGE_KEY_WALLET_AUTH_ENDPOINT,
        STORAGE_KEY_POPUP_WIDTH,
        STORAGE_KEY_POPUP_HEIGHT,
      ],
      applyConfigToDom
    );
    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName !== "local" || !changes) return;
      const patch = {};
      for (const [key, change] of Object.entries(changes)) {
        patch[key] = change && "newValue" in change ? change.newValue : undefined;
      }
      applyConfigToDom(patch);
    });
  } catch (e) {
  }

  try {
    let attempts = 0;
    const maxAttempts = 10;

    function requestInjection() {
      attempts += 1;
      setDomAttr("data-oid4vp-wallet-bridge-inject-attempt", String(attempts));
      chrome.runtime.sendMessage({ type: "oid4vp_wallet_bridge_inject" }, (response) => {
        const lastError = chrome.runtime.lastError;
        if (lastError && lastError.message) {
          setDomAttr("data-oid4vp-wallet-bridge-inject-status", "error");
          setDomAttr("data-oid4vp-wallet-bridge-inject-error", lastError.message);
        } else if (response && response.ok) {
          setDomAttr("data-oid4vp-wallet-bridge-inject-status", "ok");
          setDomAttr("data-oid4vp-wallet-bridge-inject-error", "");
        } else {
          setDomAttr("data-oid4vp-wallet-bridge-inject-status", "error");
          setDomAttr("data-oid4vp-wallet-bridge-inject-error", (response && response.error) ? String(response.error) : "Unknown error");
        }

        if (attempts < maxAttempts && (!response || !response.ok)) {
          const delayMs = Math.min(1000, 50 * attempts);
          setTimeout(requestInjection, delayMs);
        }
      });
    }

    requestInjection();
  } catch (e) {
  }

  try {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (!message || message.type !== "oid4vp_wallet_bridge_deliver") {
        return;
      }
      const responseUri = typeof message.responseUri === "string" ? message.responseUri : "";
      const walletOrigin = typeof message.walletOrigin === "string" ? message.walletOrigin : "";
      const data = message.data;

      setDomAttr("data-oid4vp-wallet-bridge-last-response-uri", responseUri);
      setDomAttr("data-oid4vp-wallet-bridge-last-response-origin", walletOrigin);
      setDomAttr("data-oid4vp-wallet-bridge-last-response-ts", String(Date.now()));

      try {
        window.postMessage(
          { type: "oid4vp_wallet_bridge_deliver", responseUri, walletOrigin, data },
          "*"
        );
      } catch (e) {
      }

      sendResponse({ ok: true });
      return true;
    });
  } catch (e) {
  }
})();
