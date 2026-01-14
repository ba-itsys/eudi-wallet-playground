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
// This content script runs on wallet pages to:
// 1. Inject form interception into MAIN world
// 2. Relay intercepted form data to the background script
(() => {
  // Mark that this content script is present
  if (document.documentElement) {
    document.documentElement.setAttribute("data-oid4vp-wallet-bridge-wallet-content-script", "true");
  }

  // Request injection of form interception script into MAIN world
  try {
    chrome.runtime.sendMessage({ type: "oid4vp_wallet_bridge_inject_form_intercept" }, (response) => {
      const lastError = chrome.runtime.lastError;
      if (lastError) {
        console.log("[OID4VP Bridge Wallet] Form intercept injection error:", lastError.message);
      } else if (response && response.ok) {
        console.log("[OID4VP Bridge Wallet] Form intercept script injected");
      } else {
        console.log("[OID4VP Bridge Wallet] Form intercept injection failed:", response);
      }
    });
  } catch (e) {
    console.error("[OID4VP Bridge Wallet] Failed to request form intercept injection:", e);
  }

  // Listen for form intercept messages from MAIN world and relay to background
  window.addEventListener("message", (event) => {
    try {
      const msg = event && event.data;
      if (!msg || msg.type !== "__oid4vp_wallet_bridge_form_intercept__") {
        return;
      }

      const responseUri = msg.responseUri;
      const data = msg.data || {};
      const walletOrigin = window.location.origin;

      console.log("[OID4VP Bridge Wallet] Form intercept received, relaying to background, responseUri:", responseUri);

      // Relay to background script
      chrome.runtime.sendMessage({
        type: "oid4vp_wallet_bridge_wallet_response",
        responseUri,
        data,
        walletOrigin
      }, (response) => {
        const lastError = chrome.runtime.lastError;
        if (lastError) {
          console.error("[OID4VP Bridge Wallet] Failed to relay to background:", lastError.message);
        } else {
          console.log("[OID4VP Bridge Wallet] Relayed to background, response:", response);
        }
      });
    } catch (e) {
      console.error("[OID4VP Bridge Wallet] Error handling form intercept message:", e);
    }
  }, false);
})();
