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
const STORAGE_KEY_WALLET_AUTH_ENDPOINT = "oid4vpWalletAuthEndpoint";
const STORAGE_KEY_POPUP_WIDTH = "oid4vpPopupWidth";
const STORAGE_KEY_POPUP_HEIGHT = "oid4vpPopupHeight";
const STORAGE_KEY_ENABLE = "oid4vpEnableBridge";
const STORAGE_KEY_CUSTOM_SITES = "oid4vpCustomSites";

function $(id) {
  return document.getElementById(id);
}

function load() {
  chrome.storage.local.get(
    [
      STORAGE_KEY_WALLET_AUTH_ENDPOINT,
      STORAGE_KEY_POPUP_WIDTH,
      STORAGE_KEY_POPUP_HEIGHT,
      STORAGE_KEY_ENABLE,
      STORAGE_KEY_CUSTOM_SITES,
    ],
    (items) => {
      $("walletAuthEndpoint").value = items[STORAGE_KEY_WALLET_AUTH_ENDPOINT] || "";
      $("popupWidth").value = items[STORAGE_KEY_POPUP_WIDTH] || 600;
      $("popupHeight").value = items[STORAGE_KEY_POPUP_HEIGHT] || 900;
      $("enabled").checked = items[STORAGE_KEY_ENABLE] !== false;
      $("customSites").value = (items[STORAGE_KEY_CUSTOM_SITES] || []).join("\n");
    }
  );
}

function save() {
  const enabled = $("enabled").checked;
  const walletAuthEndpoint = $("walletAuthEndpoint").value.trim();
  const popupWidth = Number($("popupWidth").value) || 600;
  const popupHeight = Number($("popupHeight").value) || 900;
  const customSitesRaw = $("customSites").value || "";
  const customSites = customSitesRaw
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  chrome.storage.local.set(
    {
      [STORAGE_KEY_ENABLE]: enabled,
      [STORAGE_KEY_WALLET_AUTH_ENDPOINT]: walletAuthEndpoint,
      [STORAGE_KEY_POPUP_WIDTH]: popupWidth,
      [STORAGE_KEY_POPUP_HEIGHT]: popupHeight,
      [STORAGE_KEY_CUSTOM_SITES]: customSites,
    },
    () => {
      // Notify background script to update dynamic content scripts
      chrome.runtime.sendMessage({ type: "oid4vp_update_custom_sites", sites: customSites });
      $("status").textContent = "Saved";
      setTimeout(() => {
        $("status").textContent = "";
      }, 1500);
    }
  );
}

document.addEventListener("DOMContentLoaded", () => {
  load();
  $("save").addEventListener("click", save);
});

