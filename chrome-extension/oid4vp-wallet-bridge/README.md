# OID4VP Wallet Bridge (Chrome Extension)

A development tool that bridges **OID4VP verifiers** with the **mock web wallet** for local testing.

## Intended Use

This extension is designed for **local development** with verifiers that use `response_mode=direct_post`:

- **Keycloak OID4VP Verifier** - the Keycloak extension in this project
- **Standalone Verifier** - the demo verifier app in this project
- **Any verifier using direct_post** - verifiers that POST responses to a `response_uri`

## How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│ Verifier Page (Keycloak login, Standalone verifier, etc.)           │
│                                                                     │
│  1. Page triggers OID4VP request                                    │
│  2. Extension intercepts and opens wallet popup                     │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Wallet Popup (http://localhost:3000/oid4vp/auth?...)                │
│                                                                     │
│  3. User selects credential                                         │
│  4. Wallet auto-submits form POST to response_uri                   │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Extension (webRequest interception)                                 │
│                                                                     │
│  5. Intercepts the direct_post request                              │
│  6. Extracts vp_token/response from form data                       │
│  7. Delivers response to verifier page                              │
│  8. Closes wallet popup                                             │
└─────────────────────────────────────────────────────────────────────┘
```

The extension captures wallet responses via **network interception** (`chrome.webRequest`), not by patching JavaScript return values. This makes it work reliably with `direct_post` flows.

## What This Extension Does NOT Do

**This extension cannot make Chrome's DC API return values to external websites.**

Sites like `digital-credentials.dev` that use `response_mode=dc_api` expect Chrome's native Digital Credentials API to return credentials. Chrome intercepts these requests at the browser/V8 level before JavaScript can modify return values. No Chrome extension can override this behavior.

## Installation

1. Open `chrome://extensions/`
2. Enable **Developer mode** (toggle in top right)
3. Click **Load unpacked**
4. Select this folder (`chrome-extension/oid4vp-wallet-bridge`)

## Configuration

Click the extension icon and select **Options**, or right-click → **Options**:

- **Wallet auth endpoint**: URL of your wallet (e.g., `http://localhost:3000/oid4vp/auth`)
  - If empty, auto-detects from the page or falls back to `http://localhost:3000/oid4vp/auth`

- **Custom sites**: Add URL patterns for sites where the extension should activate
  - The extension is pre-configured for `localhost` and common development URLs

## Usage with This Project

### With the Standalone Verifier

1. Start the demo app: `mvn -pl demo-app spring-boot:run`
2. Open http://localhost:3000/verifier
3. Click "Request Credential"
4. The extension opens the wallet popup
5. Select a credential → response is captured and returned

### With Keycloak

1. Start Keycloak with the OID4VP extension
2. Configure a realm with OID4VP required action
3. During login, when OID4VP is triggered:
   - Extension opens wallet popup
   - Select credential → login completes

## Wallet Requirements

The wallet endpoint must:

1. Accept OID4VP requests via query parameters
2. Support `response_mode=direct_post` or `direct_post.jwt`
3. Return an HTML page with an auto-submitting form:

```html
<form method="post" action="<response_uri>">
  <input type="hidden" name="state" value="...">
  <input type="hidden" name="vp_token" value="...">
</form>
<script>document.forms[0].submit();</script>
```

The mock wallet in this project (`wallet/`) implements this correctly.

## Permissions

The extension requires:

- `webRequest` + `webRequestBlocking` - to intercept form POST responses
- `*://*/*` host permissions - to work on any local development URL
- `scripting` - to inject the bridge script into pages
- `tabs` - to manage wallet popup and deliver responses

## Troubleshooting

### Wallet popup doesn't open
- Check the extension is enabled in `chrome://extensions/`
- Verify the wallet URL is configured correctly
- Check browser console for errors (F12 → Console)

### Response not captured
- Ensure the wallet uses `direct_post` mode (not `dc_api`)
- Check that the wallet returns an auto-submitting form
- Look for `[OID4VP Bridge]` logs in the console

### Extension not activating on a page
- Add the site's URL pattern in extension Options → Custom sites
- Reload the page after adding

## Limitations

| Scenario | Works? | Notes |
|----------|--------|-------|
| Local verifier with direct_post | ✅ Yes | Primary use case |
| Keycloak OID4VP login | ✅ Yes | Uses direct_post internally |
| External DC API sites | ❌ No | Chrome intercepts at browser level |

## For Production Testing

This extension is for **local development only**. For production testing, use real wallet implementations that support the W3C Digital Credentials API natively.
