(function (global) {
  "use strict";

  function escapeText(value) {
    if (value === null || value === undefined) {
      return "";
    }
    return String(value);
  }

  function clearElement(el) {
    if (!el) {
      return;
    }
    while (el.firstChild) {
      el.removeChild(el.firstChild);
    }
  }

  function headersToText(headers) {
    if (!headers) {
      return "";
    }
    const keys = Object.keys(headers);
    if (!keys.length) {
      return "";
    }
    keys.sort();
    const lines = [];
    for (const key of keys) {
      lines.push(`${key}: ${escapeText(headers[key])}`);
    }
    return lines.join("\n");
  }

  function urlToText(url) {
    const raw = escapeText(url).trim();
    if (!raw) {
      return "";
    }
    return raw;
  }

  function queryParamsToText(url) {
    const raw = escapeText(url).trim();
    if (!raw) {
      return "";
    }
    try {
      const parsed = new URL(raw, window.location.origin);
      if (!parsed.searchParams || [...parsed.searchParams.keys()].length === 0) {
        return "";
      }
      const lines = [];
      for (const [key, value] of parsed.searchParams.entries()) {
        lines.push(`${key}=${value}`);
      }
      return lines.length ? `Query parameters:\n${lines.join("\n")}` : "";
    } catch (e) {
      return "";
    }
  }

  function entryTimestamp(entry) {
    if (!entry || !entry.timestamp) {
      return "";
    }
    try {
      const date = new Date(entry.timestamp);
      return isNaN(date.getTime()) ? "" : date.toLocaleTimeString();
    } catch (e) {
      return "";
    }
  }

  function summarizeUrl(url) {
    const raw = escapeText(url).trim();
    if (!raw) {
      return "";
    }
    if (!raw.startsWith("/") && !raw.startsWith("http://") && !raw.startsWith("https://")) {
      return raw.length > 40 ? raw.substring(0, 39) + "…" : raw;
    }
    try {
      const parsed = new URL(raw, window.location.origin);
      const path = parsed.pathname || "";
      return path + (parsed.search ? "…" : "");
    } catch (e) {
      return raw.length > 40 ? raw.substring(0, 39) + "…" : raw;
    }
  }

  function isHttpMethod(method) {
    const normalized = escapeText(method).trim().toUpperCase();
    return ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"].includes(normalized);
  }

  function flowParticipants(entry) {
    const method = entry && entry.method ? String(entry.method) : "";
    const url = entry && entry.url ? String(entry.url).trim() : "";
    if (!isHttpMethod(method) || !url) {
      return { from: "Verifier", to: "Verifier" };
    }
    if (url.startsWith("/")) {
      return { from: "Wallet/Suite", to: "Verifier" };
    }
    return { from: "Verifier", to: "Wallet/Suite" };
  }

  function flowEntrySignature(entry) {
    if (!entry) {
      return "";
    }
    const status = entry.responseStatus !== null && entry.responseStatus !== undefined ? String(entry.responseStatus) : "";
    return [
      escapeText(entry.timestamp),
      escapeText(entry.title),
      escapeText(entry.subgroup),
      escapeText(entry.method),
      escapeText(entry.url),
      status,
      escapeText(entry.responseBody)
    ].join("|");
  }

  function flowEntriesEqual(a, b) {
    if (!Array.isArray(a) || !Array.isArray(b)) {
      return false;
    }
    if (a.length !== b.length) {
      return false;
    }
    for (let i = 0; i < a.length; i++) {
      if (flowEntrySignature(a[i]) !== flowEntrySignature(b[i])) {
        return false;
      }
    }
    return true;
  }

  function normalizeApiBase(apiBase) {
    const raw = escapeText(apiBase).trim();
    if (!raw) {
      return "";
    }
    return raw.endsWith("/") ? raw.replace(/\/+$/, "") : raw;
  }

  async function fetchJson(url, options) {
    const response = await fetch(url, {
      method: "GET",
      ...options,
      headers: {
        Accept: "application/json",
        ...(options && options.headers ? options.headers : {})
      }
    });
    const text = await response.text();
    let data = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch (e) {
        data = null;
      }
    }
    if (!response.ok) {
      const error = new Error(`HTTP ${response.status}`);
      error.status = response.status;
      error.data = data;
      error.body = text;
      throw error;
    }
    return data;
  }

  function create(options) {
    const graphEl = options && options.graphEl ? options.graphEl : null;
    const detailsEl = options && options.detailsEl ? options.detailsEl : null;
    if (!graphEl) {
      return null;
    }

    let apiBase = normalizeApiBase(options && options.apiBase ? options.apiBase : "");
    let state = escapeText(options && options.state ? options.state : "").trim();
    let entries = [];
    let selectedIndex = -1;
    let lastFetchAt = 0;
    const detailsOpen = {
      request: true,
      response: true,
      decoded: false
    };

    function renderDetails(entry) {
      if (!detailsEl) {
        return;
      }
      if (!entry) {
        detailsEl.style.display = "none";
        clearElement(detailsEl);
        return;
      }

      detailsEl.style.display = "block";
      clearElement(detailsEl);

      const header = document.createElement("div");
      header.style.display = "flex";
      header.style.gap = "0.5rem";
      header.style.flexWrap = "wrap";
      header.style.alignItems = "center";

      const title = document.createElement("div");
      title.className = "chip";
      title.style.background = "#e2e8f0";
      title.style.color = "#0f172a";
      title.textContent = escapeText(entry.title);

      const time = document.createElement("div");
      time.className = "chip";
      time.style.background = "#e2e8f0";
      time.style.color = "#0f172a";
      time.textContent = entryTimestamp(entry) ? `time=${entryTimestamp(entry)}` : "time=?";

      const method = document.createElement("div");
      method.className = "chip";
      method.style.background = "#e2e8f0";
      method.style.color = "#0f172a";
      method.textContent = escapeText(entry.method);

      const direction = document.createElement("div");
      direction.className = "chip";
      direction.style.background = "#e2e8f0";
      direction.style.color = "#0f172a";
      const participants = flowParticipants(entry);
      direction.textContent = `${participants.from} → ${participants.to}`;

      const resp = document.createElement("div");
      resp.className = "chip";
      resp.style.background = "#e2e8f0";
      resp.style.color = "#0f172a";
      const status = entry.responseStatus !== null && entry.responseStatus !== undefined ? `HTTP ${entry.responseStatus}` : "HTTP ?";
      resp.textContent = `response=${status}`;

      const rawUrl = escapeText(entry.url).trim();
      const url = document.createElement(rawUrl.startsWith("/") || rawUrl.startsWith("http://") || rawUrl.startsWith("https://") ? "a" : "div");
      url.className = "chip";
      url.style.background = "#e2e8f0";
      url.style.color = "#0f172a";
      if (url.tagName === "A") {
        url.href = rawUrl;
        url.target = "_blank";
        url.rel = "noreferrer";
      }
      url.textContent = summarizeUrl(rawUrl);

      header.appendChild(title);
      header.appendChild(time);
      if (entry.method) {
        header.appendChild(method);
      }
      header.appendChild(direction);
      header.appendChild(resp);
      if (entry.url) {
        header.appendChild(url);
      }

      detailsEl.appendChild(header);

      function addSection(key, sectionTitle, text) {
        if (!text || !String(text).trim()) {
          return;
        }
        const details = document.createElement("details");
        details.open = Boolean(detailsOpen[key]);
        details.style.marginTop = "0.5rem";
        details.addEventListener("toggle", function () {
          detailsOpen[key] = details.open;
        });

        const summary = document.createElement("summary");
        summary.textContent = sectionTitle;
        details.appendChild(summary);

        const pre = document.createElement("pre");
        pre.className = "http-body";
        pre.style.margin = "0.35rem 0 0 0";
        pre.textContent = String(text);
        details.appendChild(pre);

        detailsEl.appendChild(details);
      }

      const requestHead = [escapeText(entry.method).trim().toUpperCase(), urlToText(entry.url)].filter(Boolean).join(" ");
      const requestBlock = [
        requestHead,
        queryParamsToText(entry.url),
        headersToText(entry.requestHeaders),
        escapeText(entry.requestBody)
      ].filter(Boolean).join("\n\n");
      addSection("request", "Request", requestBlock);

      const responseHead = entry.responseStatus !== null && entry.responseStatus !== undefined ? `HTTP ${entry.responseStatus}` : "";
      const responseBlock = [responseHead, headersToText(entry.responseHeaders), escapeText(entry.responseBody)]
        .filter(Boolean)
        .join("\n\n");
      addSection("response", "Response", responseBlock);

      addSection("decoded", "Decoded tokens", escapeText(entry.decoded));
    }

    function setActiveNode(active) {
      const nodes = graphEl.querySelectorAll("[data-flow-index]");
      nodes.forEach(function (node) {
        const idx = Number(node.getAttribute("data-flow-index"));
        if (idx === active) {
          node.classList.add("active");
        } else {
          node.classList.remove("active");
        }
      });
    }

    function renderGraph() {
      clearElement(graphEl);

      if (!state) {
        graphEl.textContent = "Flow events appear once the verifier starts.";
        renderDetails(null);
        return;
      }
      if (!Array.isArray(entries) || entries.length === 0) {
        graphEl.textContent = "No verifier flow events yet.";
        renderDetails(null);
        return;
      }

      for (let i = 0; i < entries.length; i++) {
        const entry = entries[i];

        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "flow-node";
        btn.setAttribute("data-flow-index", String(i));
        btn.addEventListener("click", function () {
          selectedIndex = i;
          setActiveNode(selectedIndex);
          renderDetails(entries[selectedIndex]);
        });

        const title = document.createElement("div");
        title.className = "flow-title";
        title.textContent = escapeText(entry.title);

        const participants = flowParticipants(entry);
        const dir = document.createElement("div");
        dir.className = "flow-dir";
        dir.textContent = `${participants.from} → ${participants.to}`;

        const req = document.createElement("div");
        req.className = "flow-req";
        const method = escapeText(entry.method).trim().toUpperCase();
        const url = summarizeUrl(entry.url);
        if (method || url) {
          req.textContent = `Request: ${[method, url].filter(Boolean).join(" ")}`.trim();
        }

        const res = document.createElement("div");
        res.className = "flow-res";
        const status = entry.responseStatus !== null && entry.responseStatus !== undefined
          ? `HTTP ${entry.responseStatus}`
          : "HTTP ?";
        res.textContent = `Response: ${status}`;

        const meta = document.createElement("div");
        meta.className = "flow-meta";
        const time = entryTimestamp(entry);
        const subgroup = escapeText(entry.subgroup);
        meta.textContent = [time ? time : null, subgroup ? subgroup : null].filter(Boolean).join(" · ");

        btn.appendChild(title);
        btn.appendChild(dir);
        if (req.textContent) {
          btn.appendChild(req);
        }
        btn.appendChild(res);
        btn.appendChild(meta);
        graphEl.appendChild(btn);

        if (i < entries.length - 1) {
          const connector = document.createElement("div");
          connector.className = "flow-connector";
          connector.textContent = "→";
          graphEl.appendChild(connector);
        }
      }

      if (selectedIndex < 0 || selectedIndex >= entries.length) {
        selectedIndex = entries.length - 1;
      }
      setActiveNode(selectedIndex);
      renderDetails(entries[selectedIndex]);
    }

    function setState(nextState) {
      const normalized = escapeText(nextState).trim();
      if (normalized === state) {
        return;
      }
      state = normalized;
      entries = [];
      selectedIndex = -1;
      renderGraph();
    }

    function setEntries(nextEntries) {
      const normalized = Array.isArray(nextEntries) ? nextEntries : [];
      if (flowEntriesEqual(normalized, entries)) {
        return false;
      }
      entries = normalized;
      renderGraph();
      return true;
    }

    async function refresh(force) {
      if (!apiBase || !state) {
        renderGraph();
        return;
      }
      const now = Date.now();
      if (!force && now - lastFetchAt < 1200) {
        return;
      }
      lastFetchAt = now;
      const url = `${apiBase}/${encodeURIComponent(state)}`;
      const data = await fetchJson(url);
      setEntries(Array.isArray(data) ? data : []);
    }

    function setApiBase(nextApiBase) {
      apiBase = normalizeApiBase(nextApiBase);
    }

    renderGraph();

    return {
      setState,
      setApiBase,
      setEntries,
      refresh,
      render: renderGraph,
      getState: function () {
        return state;
      }
    };
  }

  global.VerificationFlowView = Object.freeze({
    create
  });
})(window);
