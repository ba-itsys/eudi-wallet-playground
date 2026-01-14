# DC API Bridge: Making Web Wallets Work with the Digital Credentials API

This document explains how the W3C Digital Credentials API works, why it doesn't support web-based wallets, and how our Chrome extension bridges this gap.

## Table of Contents

1. [Digital Credentials API Overview](#digital-credentials-api-overview)
2. [The Web Wallet Problem](#the-web-wallet-problem)
3. [How the Bridge Works](#how-the-bridge-works)
4. [The Hacks Explained](#the-hacks-explained)
5. [Setup and Configuration](#setup-and-configuration)
6. [Limitations](#limitations)

---

## Digital Credentials API Overview

The W3C Digital Credentials API allows websites to request verifiable credentials from users via `navigator.credentials.get()`:

```javascript
const credential = await navigator.credentials.get({
  digital: {
    requests: [{
      protocol: "openid4vp",
      data: {
        // OID4VP request parameters
        client_id: "https://verifier.example.com",
        nonce: "abc123",
        dcql_query: { ... }
      }
    }]
  }
});
```

### Standard Flow (Native Wallet)

```
┌──────────┐        ┌─────────┐        ┌───────────────┐        ┌────────────────┐
│ Verifier │        │ Browser │        │ Platform API  │        │ Native Wallet  │
│ Website  │        │         │        │ (Android/iOS) │        │    (App)       │
└────┬─────┘        └────┬────┘        └───────┬───────┘        └───────┬────────┘
     │                   │                     │                        │
     │ 1. credentials.get()                    │                        │
     │ ─────────────────>│                     │                        │
     │                   │                     │                        │
     │                   │ 2. DC API request   │                        │
     │                   │ ───────────────────>│                        │
     │                   │                     │                        │
     │                   │                     │ 3. Launch wallet       │
     │                   │                     │ ──────────────────────>│
     │                   │                     │                        │
     │                   │                     │ 4. User selects cred   │
     │                   │                     │<───────────────────────│
     │                   │                     │                        │
     │                   │ 5. Response         │                        │
     │                   │<────────────────────│                        │
     │                   │                     │                        │
     │ 6. Credential     │                     │                        │
     │<──────────────────│                     │                        │
     │                   │                     │                        │
```

Key points:
- Browser calls platform-level APIs (Android Credential Manager, iOS Wallet)
- Platform routes to registered native wallet apps
- Response flows back through the same channel
- **No HTTP requests** - everything happens via platform APIs

---

## The Web Wallet Problem

Web-based wallets cannot participate in the DC API flow because:

1. **No Platform Registration**: Web apps can't register as credential providers with the OS
2. **No Direct Communication**: DC API talks to platform APIs, not websites
3. **Response Mode Mismatch**: Web wallets use `direct_post` (HTTP POST to response_uri), but DC API expects in-band responses

### What We Need

To make web wallets work with DC API, we need to:

1. **Intercept** the `credentials.get()` call before the browser handles it
2. **Translate** the DC API request to something a web wallet understands
3. **Open** the web wallet in a popup with the translated request
4. **Capture** the wallet's response (which it tries to POST to response_uri)
5. **Deliver** the response back to the original page as if DC API returned it

---

## How the Bridge Works

The Chrome extension implements a complete bridge:

```
┌──────────┐      ┌──────────────────┐      ┌─────────────────┐      ┌─────────────┐
│ Verifier │      │ Chrome Extension │      │ Web Wallet Page │      │ Background  │
│ Website  │      │ (Content Script) │      │    (Popup)      │      │   Script    │
└────┬─────┘      └────────┬─────────┘      └────────┬────────┘      └──────┬──────┘
     │                     │                         │                      │
     │ 1. credentials.get()│                         │                      │
     │ ───────────────────>│                         │                      │
     │                     │                         │                      │
     │                     │ 2. Intercept & parse    │                      │
     │                     │    OID4VP request       │                      │
     │                     │                         │                      │
     │                     │ 3. Open wallet popup    │                      │
     │                     │ ───────────────────────>│                      │
     │                     │                         │                      │
     │                     │                         │ 4. User approves     │
     │                     │                         │    & submits         │
     │                     │                         │                      │
     │                     │                         │ 5. Form submit       │
     │                     │                         │    intercepted       │
     │                     │                         │ ───────────────────> │
     │                     │                         │                      │
     │                     │ 6. Deliver response     │                      │
     │                     │<──────────────────────────────────────────────│
     │                     │                         │                      │
     │ 7. Resolve promise  │                         │                      │
     │<────────────────────│                         │                      │
     │                     │                         │                      │
```

---

## The Hacks Explained

### Hack 1: Intercepting `navigator.credentials.get()`

The extension patches `navigator.credentials.get()` in the MAIN world:

```javascript
// background.js - injected into MAIN world
function makePatchedGet(originalGet) {
  return function get(options) {
    const oid4vp = findOid4vpRequest(options);
    if (!oid4vp || !isEnabled()) {
      // Fall through to original (or fail if no DC API)
      return originalGet ? originalGet(options) : Promise.reject(...);
    }

    // Handle OID4VP request ourselves
    return openWalletForDcApi(walletAuthEndpoint, oid4vp, requestContext);
  };
}

// Install our patched version
Object.defineProperty(credentials, "get", {
  get: function() { return wrappedGet; },
  set: function(v) { /* ignore */ }
});
```

**Why this is a hack**: We're monkey-patching a browser API. This only works because:
- Chrome's DC API must be disabled (`--disable-features=WebIdentityDigitalCredentials`)
- We inject into MAIN world to access the real `navigator.credentials`

### Hack 2: Synthetic Response URI

DC API doesn't use `response_uri` - responses flow back through the API. But web wallets need a URL to POST to.

We create a synthetic response_uri:

```javascript
// Create a fake endpoint the wallet thinks it's POSTing to
const dcApiResponseUri = window.location.origin + "/__oid4vp_dc_api_response__/" + state;

// Pass this to the wallet
url.searchParams.set("response_uri", dcApiResponseUri);
url.searchParams.set("response_mode", "direct_post");  // Map dc_api -> direct_post
```

The wallet will try to POST to this URL, which we intercept.

### Hack 3: Response Mode Translation

DC API uses `dc_api` or `dc_api.jwt` response modes. Web wallets don't understand these.

```javascript
function mapDcApiResponseModeToDirectPost(responseMode) {
  if (responseMode === "dc_api.jwt" || responseMode.endsWith(".jwt")) {
    return "direct_post.jwt";  // Encrypted
  }
  return "direct_post";  // Unencrypted
}
```

### Hack 4: Form Submission Interception

Web wallets typically submit responses via HTML form POST. We intercept this:

```javascript
// Monkey-patch HTMLFormElement.prototype.submit
HTMLFormElement.prototype.submit = function (...args) {
  if (isOid4vpDirectPostForm(this)) {
    const responseUri = this.getAttribute("action");
    const data = extractFormData(this);

    // Don't actually submit - relay to extension instead
    window.postMessage({
      type: "__oid4vp_wallet_bridge_form_intercept__",
      responseUri,
      data
    }, "*");
    return;  // Prevent actual submission
  }
  return originalSubmit.apply(this, args);
};
```

**Detection criteria**: Cross-origin form with `vp_token`, `response`, or `error` fields.

### Hack 5: WebRequest API Interception

Some wallets use `fetch()` or XHR instead of form submission. We catch these too:

```javascript
// background.js
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.method !== "POST") return;

    const data = parseRequestBody(details.requestBody);

    // Check if this looks like an OID4VP response
    if (!("vp_token" in data) && !("response" in data)) return;

    // Check if cross-origin (wallet -> verifier)
    if (!isCrossOrigin(details)) return;

    // Intercept and deliver to verifier tab
    deliverDirectPostToVerifier(details.url, data, sourceOrigin, null);

    // Close the wallet tab
    chrome.tabs.remove(details.tabId);
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);
```

### Hack 6: Cross-Tab Response Delivery

The verifier page is waiting on a Promise from `credentials.get()`. We need to resolve it from the background script:

```javascript
// Store pending requests with callbacks
window.__oid4vpWalletBridgePending = {};

pending[bridgeRequestId] = {
  walletOrigin,
  responseUri: dcApiResponseUri,
  deliver: (data) => {
    // Format as DigitalCredential and resolve promise
    resolve({
      type: "digital",
      protocol: oid4vp.protocol,
      data: data
    });
  }
};

// Background script delivers via executeScript into verifier tab
chrome.scripting.executeScript({
  target: { tabId },
  world: "MAIN",
  func: (uri, payload, origin) => {
    if (typeof window.__oid4vpWalletBridgeDeliverToResponseUri === "function") {
      window.__oid4vpWalletBridgeDeliverToResponseUri(uri, payload, origin);
    }
  },
  args: [responseUri, data, walletOrigin]
});
```

---

## Setup and Configuration

### Prerequisites

1. **Disable Chrome's DC API** (it would intercept our calls):
   ```bash
   # Via Chrome flags
   chrome://flags/#web-identity-digital-credentials -> Disabled

   # Or via command line
   chrome --disable-features=WebIdentityDigitalCredentials
   ```

2. **Install the extension** from `chrome-extension/oid4vp-wallet-bridge/`

3. **Configure wallet endpoint** in extension options:
   - Default: `http://localhost:3000/oid4vp/auth`
   - Set your wallet's OID4VP authorization endpoint

### Extension Options

| Setting | Description |
|---------|-------------|
| Wallet Auth Endpoint | URL of wallet's `/oid4vp/auth` endpoint |
| Popup Width | Wallet popup window width (default: 600) |
| Popup Height | Wallet popup window height (default: 900) |
| Custom Sites | Additional sites to inject content script |

### Verifier-Side Configuration

The extension auto-discovers wallet endpoints from the page:

```html
<!-- Option 1: Meta tag -->
<meta name="oid4vp-wallet-auth-endpoint" content="https://wallet.example.com/oid4vp/auth">

<!-- Option 2: Data attribute -->
<div data-oid4vp-wallet-auth-endpoint="https://wallet.example.com/oid4vp/auth">

<!-- Option 3: Link detection (auto-discovers /oid4vp/auth links) -->
<a href="https://wallet.example.com/oid4vp/auth">Open Wallet</a>
```

---

## Limitations

### Security Considerations

1. **Requires Disabled DC API**: The native DC API provides platform-level security guarantees we can't replicate
2. **Origin Verification**: We verify origins but can't match platform-level isolation
3. **Response Interception**: We're intercepting and relaying responses - a malicious extension could do harm

### Functional Limitations

1. **Chrome Only**: Uses Chrome extension APIs (Manifest V3)
2. **No Mobile**: Web extension APIs don't exist on mobile browsers
3. **Manual Configuration**: Users must configure wallet endpoint
4. **Pop-up Blocker**: Browser pop-up blockers may interfere

### Protocol Gaps

1. **No Device Engagement**: mDoc's NFC/BLE device engagement can't work
2. **Origin Client ID**: We use synthetic origins, not platform-verified ones
3. **SessionTranscript**: For mDoc, we derive origin from response_uri since there's no real DC API context

---

## Extension Files Reference

| File | Purpose |
|------|---------|
| `background.js` | Main orchestration, webRequest interception, tab management |
| `content-script.js` | Injected into verifier sites, triggers MAIN world injection |
| `wallet-content-script.js` | Injected into wallet site, intercepts form submissions |
| `manifest.json` | Extension configuration, permissions |
| `options.html/js` | Configuration UI for wallet endpoint |

---

## Debugging

Enable verbose logging by opening Chrome DevTools:

```
[OID4VP Bridge] credentials.get called with options: {...}
[OID4VP Bridge] findOid4vpRequest returned: {...}
[OID4VP Bridge] walletAuthEndpoint: http://localhost:3000/oid4vp/auth
[OID4VP Bridge] Opening wallet with requestContext: {...}
[OID4VP Bridge] Popup opened successfully
...
[OID4VP Bridge] Form intercept - cross-origin OID4VP form detected
[OID4VP Bridge] Delivering response to verifier
[OID4VP Bridge] Resolving with credential: {...}
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "Credential Management API not available" | Chrome DC API is enabled | Disable via `chrome://flags` |
| Popup blocked | Browser pop-up blocker | Allow pop-ups for verifier site |
| Form not intercepted | Wallet uses non-standard submission | Check console for webRequest logs |
| Response not delivered | Tab closed too early | Check background script logs |
