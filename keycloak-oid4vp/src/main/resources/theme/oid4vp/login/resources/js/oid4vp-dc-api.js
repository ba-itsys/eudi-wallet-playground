(() => {
  function isObject(value) {
    return value !== null && typeof value === "object";
  }

  function getTextAttribute(element, name) {
    if (!element) {
      return "";
    }
    const value = element.getAttribute(name);
    return value ? String(value) : "";
  }

  function extractVpToken(credential) {
    if (!credential) {
      return null;
    }
    const data = credential.data || credential;
    if (typeof data === "string") {
      return data;
    }
    if (isObject(data) && data.vp_token) {
      return data.vp_token;
    }
    if (isObject(data) && isObject(data.response) && data.response.vp_token) {
      return data.response.vp_token;
    }
    return null;
  }

  function setup({ buttonId, logId, formId }) {
    const button = document.getElementById(buttonId);
    const logEl = document.getElementById(logId);
    const form = document.getElementById(formId);
    const vpTokenInput = document.getElementById("vp_token");
    const responseInput = document.getElementById("response");
    const errorInput = document.getElementById("error");
    const errorDescriptionInput = document.getElementById("error_description");
    if (!button || !logEl || !form || !vpTokenInput || !responseInput || !errorInput) {
      console.warn("[OID4VP] Missing required elements:", { button: !!button, logEl: !!logEl, form: !!form });
      return;
    }

    function log(message, obj) {
      const ts = new Date().toISOString().slice(11, 23);
      const line = obj ? `[${ts}] ${message}\n${JSON.stringify(obj, null, 2)}` : `[${ts}] ${message}`;
      logEl.textContent = (logEl.textContent ? logEl.textContent + "\n\n" : "") + line;
      logEl.scrollTop = logEl.scrollHeight;
      console.log("[OID4VP]", message, obj || "");
    }

    const nonce = getTextAttribute(form, "data-oid4vp-nonce");
    const dcqlQueryRaw = getTextAttribute(form, "data-oid4vp-dcql-query").trim();
    const requestObject = getTextAttribute(form, "data-oid4vp-request-object").trim();

    log("Page loaded");

    let dcqlQuery = {};
    if (dcqlQueryRaw) {
      try {
        dcqlQuery = JSON.parse(dcqlQueryRaw);
      } catch (e) {
        log("Failed to parse DCQL query; falling back to empty object.", e && e.message ? String(e.message) : String(e));
        dcqlQuery = {};
      }
    }

    async function run() {
      if (!navigator.credentials || !navigator.credentials.get) {
        log("Digital Credentials API not available in this browser.");
        return;
      }

      const request = {
        response_type: "vp_token",
        response_mode: "dc_api",
        nonce,
        client_metadata: {},
        dcql_query: dcqlQuery,
      };

      if (requestObject) {
        log("Starting Digital Credentials API request (signed request object)");
      } else {
        log("Starting Digital Credentials API request", request);
      }

      try {
        log("Calling navigator.credentials.get()...");
        // OID4VP DC API format (per spec appendix A):
        // - Unsigned: data IS the request object directly
        // - Signed: data contains { request: "<JWT>" }
        const credential = requestObject
          ? await navigator.credentials.get({
            digital: { requests: [{ protocol: "openid4vp-v1-signed", data: { request: requestObject } }] },
          })
          : await navigator.credentials.get({
            digital: { requests: [{ protocol: "openid4vp-v1-unsigned", data: request }] },
          });

        log("Digital Credentials API returned", credential);

        const data = credential && credential.data ? credential.data : credential;
        if (isObject(data) && data.error) {
          const code = String(data.error);
          const desc = data.error_description ? String(data.error_description) : "";
          log("Wallet returned error: " + code + (desc ? " - " + desc : ""), data);
          // For wallet errors (user denied, no matching credential, etc.),
          // don't submit the error form. This keeps the session valid and allows retry.
          // The user can simply click the button again to try with a different credential.
          log("You can click the button again to retry with a different credential.");
          return;
        }

        if (isObject(data) && typeof data.response === "string" && data.response.trim()) {
          log("Received encrypted response, submitting form...");
          responseInput.value = data.response.trim();
          form.submit();
          return;
        }

        const vpToken = extractVpToken(credential);
        if (!vpToken) {
          log("Missing vp_token in response. Raw credential:", credential);
          return;
        }

        log("Received vp_token, submitting form...");
        vpTokenInput.value = typeof vpToken === "string" ? vpToken : JSON.stringify(vpToken);
        form.submit();
      } catch (e) {
        const message = e && e.message ? String(e.message) : String(e);
        const name = e && e.name ? e.name : "Error";
        log(`Digital Credentials API failed (${name}): ${message}`);
        if (message.includes("NotAllowedError") || message.includes("not allowed")) {
          log("Hint: The user may have denied the request, or the wallet popup was blocked.");
        }
        if (message.includes("AbortError")) {
          log("Hint: The request was aborted. The wallet popup may have been closed.");
        }
      }
    }

    button.addEventListener("click", () => {
      log("Button clicked, starting DC API flow...");
      run();
    });
    log("Click handler registered for " + buttonId);
  }

  if (document.getElementById("oid4vpStartButton")) {
    setup({ buttonId: "oid4vpStartButton", logId: "oid4vpLog", formId: "oid4vpForm" });
  }
  if (document.getElementById("oid4vpRegisterButton")) {
    setup({ buttonId: "oid4vpRegisterButton", logId: "oid4vpRegisterLog", formId: "oid4vpRegisterForm" });
  }
})();
