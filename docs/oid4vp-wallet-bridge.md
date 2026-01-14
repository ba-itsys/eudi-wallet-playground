# OID4VP Wallet Bridge (Chrome Extension)

The demo wallet in this repository is a normal web application, so it cannot act as a native wallet provider for the W3C Digital Credentials API.

To still exercise the `navigator.credentials.get({ digital: ... })` flow end-to-end in Chrome, this repo contains a small extension that intercepts OpenID4VP DC API calls and opens a configurable web wallet in a popup window.

The extension is self-contained under `chrome-extension/oid4vp-wallet-bridge` and can be extracted into a separate repository later.

## Install (unpacked)

1. Open `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select `chrome-extension/oid4vp-wallet-bridge`

If you already had an older unpacked version installed, remove it (or click **Reload**) so Chrome picks up the updated `manifest.json`.

## Configure

Open the extension’s options page and set:

- `Wallet auth endpoint` (example: `http://localhost:3000/oid4vp/auth`)

If the field is empty, the extension tries to auto-detect a wallet link on the current page. If nothing can be detected, it falls back to `http://localhost:3000/oid4vp/auth`.

## Use

1. Start the wallet (see `README.md`).
2. Start Keycloak with the `keycloak-oid4vp` provider installed and the OID4VP Identity Provider configured.
3. Trigger a Digital Credentials API request from Keycloak:
   - Visit the login page and click **Sign in with Wallet**
   - The IdP login page loads and triggers the Digital Credentials API

The extension opens the wallet, completes the consent flow, and returns the OpenID4VP response to the Keycloak page (either `vp_token` or an encrypted `response`).

## Notes

- The extension intercepts OpenID4VP DC API protocols: `openid4vp-v1-unsigned`, `openid4vp-v1-signed`, and `openid4vp-v1-multisigned`.
- This is a development bridge/polyfill; it is not a replacement for a real wallet integration.
- The wallet does not need any special bridge code; the extension captures the wallet’s standard `direct_post(.jwt)` response by intercepting the HTML response form (and, as a fallback, via `chrome.webRequest`). See `chrome-extension/oid4vp-wallet-bridge/README.md` for details.
- The extension is Manifest V3; it uses `webRequest` (non-blocking) and broad host permissions to observe the wallet’s outgoing `direct_post(.jwt)` request in the fallback mode.
