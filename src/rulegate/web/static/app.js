/* RuleGate — Change Review Operations console.
 * Security notes:
 *  - All dynamic content is rendered with DOM APIs and textContent. HTML-parsing sinks are never
 *    used, so change-request text, tool output and LLM output cannot inject markup or script.
 *  - The access token lives in sessionStorage (this tab only) and is sent as a Bearer header.
 *    It is read once from the URL fragment, which browsers never send to the server, and then
 *    removed from the address bar.
 *  - No third-party code; the page runs under a strict Content-Security-Policy.
 * Provenance: every panel and event is labeled DETERMINISTIC (Python), AI-GENERATED (agent),
 * HUMAN DECISION (reviewer) or ORCHESTRATION (flow).
 */
(() => {
  "use strict";

  // ------------------------------------------------------------------ constants

  const STEPS = [
    { id: "intake", label: "Intake", sub: "schema validation", kind: "Flow", icon: "inbox" },
    { id: "analysis", label: "Analysis engine", sub: "shadow · RG-001…016", kind: "Engine", icon: "cpu" },
    { id: "intake_task", label: "Intake Parser", sub: "cr_schema_validator", kind: "Agent", icon: "agent" },
    { id: "rulebase_analysis_task", label: "Rulebase Analyst", sub: "shadow_analyzer · rulebase_lookup", kind: "Agent", icon: "agent" },
    { id: "risk_assessment_task", label: "Risk Assessor", sub: "risk_scanner", kind: "Agent", icon: "agent" },
    { id: "compliance_task", label: "Compliance Auditor", sub: "compliance_kb", kind: "Agent", icon: "agent" },
    { id: "implementation_task", label: "Implementation Planner", sub: "config_renderer", kind: "Agent", icon: "agent" },
    { id: "cab_report_task", label: "CAB Report Writer", sub: "evidence guardrail", kind: "Agent", icon: "agent" },
    { id: "gate", label: "Approval gate", sub: "accountable reviewer", kind: "Human", icon: "shield" },
    { id: "report", label: "Decision package", sub: "review.md · staged config", kind: "Output", icon: "file" },
  ];
  const AGENT_STEPS = STEPS.filter((s) => s.kind === "Agent").map((s) => s.id);
  const STEP_BY_ID = Object.fromEntries(STEPS.map((s) => [s.id, s]));
  const STATE_WORD = { pending: "standby", active: "running", done: "complete", skipped: "skipped", failed: "failed", waiting: "awaiting" };

  const DECISION_TEXT = {
    APPROVE: "No High or Critical risk. Ready for the CAB queue.",
    APPROVE_WITH_CONDITIONS: "High-risk findings must be remediated or accepted by a reviewer.",
    REJECT: "Critical findings. Narrow the request before resubmitting.",
    REJECT_DUPLICATE: "The requested access already exists. No change required.",
  };
  const DECISION_LABEL = {
    APPROVE: "Approve", APPROVE_WITH_CONDITIONS: "Approve w/ conditions",
    REJECT: "Reject", REJECT_DUPLICATE: "Reject · duplicate",
  };
  const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
  const VENDOR_LABEL = { panos: "Palo Alto PAN-OS", ftd: "Cisco FTD (FMC)" };
  const FILTERS = [
    { id: "all", label: "All" },
    { id: "det", label: "Deterministic", test: (p) => p === "det" },
    { id: "ai", label: "AI", test: (p) => p === "ai" },
    { id: "human", label: "Human", test: (p) => p === "human" },
    { id: "flow", label: "Flow", test: (p) => p === "flow" },
  ];
  const PROV_TITLE = { det: "Deterministic", ai: "AI-generated", human: "Human decision", flow: "Orchestration" };

  const ICONS = {
    inbox: ["M4 13h4l2 3h4l2-3h4", "M4 13 6.5 5h11L20 13v6H4z"],
    cpu: ["M8 8h8v8H8z", "M4 4h16v16H4z", "M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 15h3M1 9h3M1 15h3"],
    agent: ["M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z", "M4 21a8 8 0 0 1 16 0"],
    shield: ["M12 2.5 4 5.5v6c0 5 3.4 8.7 8 10 4.6-1.3 8-5 8-10v-6z", "m8.5 12 2.5 2.5 4.5-5"],
    file: ["M14 3H6v18h12V7z", "M14 3v4h4", "M9 13h6M9 17h6"],
    check: ["m5 12.5 4.5 4.5L19 7.5"],
    x: ["M6 6l12 12M18 6 6 18"],
    alert: ["M12 3 2 20h20z", "M12 10v4M12 17h.01"],
    clock: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z", "M12 7v5l3 2"],
    flag: ["M5 21V4h12l-2 4 2 4H5"],
    copy: ["M9 9h11v11H9z", "M5 15H4V4h11v1"],
    download: ["M12 4v11", "m7 10 5 5 5-5", "M5 20h14"],
    lock: ["M5 11h14v10H5z", "M8 11V7a4 4 0 0 1 8 0v4"],
    list: ["M4 6h16M4 12h16M4 18h10"],
    chain: ["M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1", "M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"],
    dot: ["M12 12h.01"],
  };

  // ------------------------------------------------------------------ DOM helpers

  const $ = (id) => document.getElementById(id);

  function h(tag, props, ...children) {
    const el = document.createElement(tag);
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (v === undefined || v === null || v === false) continue;
        if (k === "class") el.className = v;
        else if (k === "text") el.textContent = v;
        else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
        else if (k === "dataset") Object.assign(el.dataset, v);
        else el.setAttribute(k, v === true ? "" : String(v));
      }
    }
    append(el, children);
    return el;
  }

  function append(el, children) {
    for (const c of children.flat()) {
      if (c === undefined || c === null || c === false) continue;
      el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }

  function icon(name, cls) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("class", "icon" + (cls ? " " + cls : ""));
    svg.setAttribute("aria-hidden", "true");
    for (const d of ICONS[name] || ICONS.dot) {
      const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
      p.setAttribute("d", d);
      svg.appendChild(p);
    }
    return svg;
  }

  /** Provenance tag: kind is det | ai | human | flow. */
  function prov(kind, src) {
    return h("span", { class: `prov ${kind}`, title: src ? `${PROV_TITLE[kind]}: ${src}` : PROV_TITLE[kind] },
      PROV_TITLE[kind], src ? h("span", { class: "src", text: `· ${src}` }) : null);
  }

  const pad = (n) => String(n).padStart(2, "0");
  function utc(iso) {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}Z`;
  }
  function utcFull(iso) {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${utc(iso)}`;
  }
  function duration(ms) {
    const s = Math.max(0, Math.round(ms / 1000));
    return `${pad(Math.floor(s / 60))}:${pad(s % 60)}`;
  }

  function decisionBadge(decision, large) {
    if (!decision) return null;
    const ic = decision === "APPROVE" ? "check" : decision === "APPROVE_WITH_CONDITIONS" ? "alert" : "x";
    return h("span", { class: `badge dec-${decision}${large ? " lg" : ""}` }, icon(ic), DECISION_LABEL[decision] || decision);
  }

  function sevSpan(sev) { return h("span", { class: `sev sev-${sev}` }, sev); }

  const store = {
    get(k) { try { return sessionStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { sessionStorage.setItem(k, v); } catch { /* storage unavailable */ } },
    del(k) { try { sessionStorage.removeItem(k); } catch { /* storage unavailable */ } },
    getLocal(k) { try { return localStorage.getItem(k); } catch { return null; } },
    setLocal(k, v) { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } },
  };

  // ------------------------------------------------------------------ toasts

  function toast(message, kind = "info", timeout = 6000) {
    const ic = kind === "bad" ? "alert" : kind === "ok" ? "check" : "dot";
    const close = h("button", { type: "button", "aria-label": "Dismiss" }, icon("x"));
    const el = h("div", { class: `toast ${kind}`, role: kind === "bad" ? "alert" : "status" },
      icon(ic), h("div", { class: "grow", text: message }), close);
    close.addEventListener("click", () => el.remove());
    $("toasts").appendChild(el);
    if (timeout) setTimeout(() => el.remove(), timeout);
  }

  // ------------------------------------------------------------------ API

  class ApiError extends Error {
    constructor(status, detail, errors) { super(detail); this.status = status; this.errors = errors || []; }
  }

  let token = null;

  async function api(path, { method = "GET", body, signal } = {}) {
    const headers = { Authorization: `Bearer ${token}`, Accept: "application/json" };
    const init = { method, headers, signal, credentials: "omit", cache: "no-store", redirect: "error" };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    const res = await fetch(path, init);
    if (res.status === 401) { lockConsole("Your access token was rejected. Paste the token printed by rulegate serve."); throw new ApiError(401, "Unauthorized"); }
    let data = null;
    try { data = await res.json(); } catch { /* empty or non-JSON body */ }
    if (!res.ok) throw new ApiError(res.status, (data && data.detail) || `Request failed (${res.status})`, data && data.errors);
    return data;
  }

  // ------------------------------------------------------------------ state

  const state = {
    config: null,
    samples: [],
    selectedSample: null,
    source: "sample",
    job: null,
    jobId: null,
    lastSeq: 0,
    events: [],
    steps: {},
    stepCounts: {},
    thinkingShown: new Set(),
    filter: "all",
    stepFilter: null,
    stream: null,
    link: "idle",
    approvalOpenedFor: null,
  };

  // ------------------------------------------------------------------ auth

  function initToken() {
    const m = /(?:^|&)token=([^&]+)/.exec(location.hash.slice(1));
    if (m) {
      store.set("rulegate.token", decodeURIComponent(m[1]));
      history.replaceState(null, "", location.pathname + location.search);
    }
    token = store.get("rulegate.token");
  }

  function lockConsole(message) {
    store.del("rulegate.token");
    token = null;
    if (state.stream) state.stream.abort();
    $("app").hidden = true;
    $("auth-screen").hidden = false;
    const err = $("auth-error");
    err.hidden = !message;
    err.textContent = message || "";
    $("auth-token").focus();
  }

  $("auth-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const value = $("auth-token").value.trim();
    const err = $("auth-error");
    if (value.length < 24) { err.hidden = false; err.textContent = "The token is at least 24 characters long."; return; }
    token = value;
    try {
      await boot();
      store.set("rulegate.token", value);
      $("auth-token").value = "";
    } catch (e) {
      if (!(e instanceof ApiError && e.status === 401)) { err.hidden = false; err.textContent = "Could not reach the RuleGate server."; }
    }
  });

  // ------------------------------------------------------------------ theme + clock

  function applyTheme(theme) {
    if (theme === "light") document.documentElement.setAttribute("data-theme", "light");
    else document.documentElement.removeAttribute("data-theme");
  }
  applyTheme(store.getLocal("rulegate.theme"));
  $("theme-toggle").addEventListener("click", () => {
    const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
    applyTheme(next);
    store.setLocal("rulegate.theme", next);
  });

  function tickClock() {
    const now = new Date();
    $("utc-clock").textContent = `${now.getUTCFullYear()}-${pad(now.getUTCMonth() + 1)}-${pad(now.getUTCDate())} ${utc(now.toISOString())}`;
    if (state.job && !["completed", "failed"].includes(state.job.status)) renderElapsed();
  }
  tickClock();
  setInterval(tickClock, 1000);

  // ------------------------------------------------------------------ boot

  async function boot() {
    const [config, samples] = await Promise.all([api("/api/config"), api("/api/samples")]);
    state.config = config;
    state.samples = samples;
    $("auth-screen").hidden = true;
    $("app").hidden = false;
    renderBanner();
    renderStatusStrip();
    renderSamples();
    applyModeAvailability();
    renderFilters();
    await refreshHistory();
    const running = (await api("/api/reviews")).find((j) => !["completed", "failed"].includes(j.status));
    if (running) openJob(running.id);
  }

  function renderBanner() {
    const text = state.config.banner;
    for (const id of ["banner-top", "banner-bottom"]) {
      $(id).hidden = !text;
      $(id).textContent = text || "";
    }
    document.body.classList.toggle("has-banner", Boolean(text));
  }

  function ledItem(led, label, value, opt, title) {
    return h("div", { class: `led-item${opt ? " opt" : ""}`, title: title || null },
      h("span", { class: `led ${led}` }), label, value ? h("b", { text: value }) : null);
  }

  function renderStatusStrip() {
    const c = state.config;
    const strip = $("status-strip");
    const clockItem = strip.lastElementChild;
    clear(strip);
    const linkLed = state.link === "live" ? "ok pulse" : state.link === "retry" ? "warn pulse" : "";
    strip.append(
      ledItem("ok", "Firewall access", "read-only", false, "No endpoint can change a firewall"),
      ledItem("info", "Rulebase", c.mode === "offline" ? "offline export" : c.mode, true, "Rulebase source"),
      c.llm_configured
        ? ledItem("ok", "Model", c.model || "configured", true, "LLM used by the agents")
        : ledItem("warn", "Model", "not configured", true, "Set MODEL and an API key in .env to enable agents"),
      ledItem(linkLed, "Event link", state.link === "live" ? "live" : state.link === "retry" ? "reconnecting" : "idle", true, "Live event stream"),
      clockItem);
  }

  function setLink(status) {
    if (state.link === status) return;
    state.link = status;
    if (state.config) renderStatusStrip();
  }

  // ------------------------------------------------------------------ intake form

  function renderSamples() {
    const list = $("sample-list");
    clear(list);
    state.samples.forEach((s, idx) => {
      const btn = h("button", {
        type: "button", class: "sample", role: "radio", "aria-checked": "false", tabindex: idx === 0 ? "0" : "-1",
        dataset: { id: s.id },
      },
      h("span", { class: "sid", text: s.change_id || s.id }),
      h("span", { class: `vendor-tag ${s.vendor || ""}`, text: s.vendor ? (s.vendor === "panos" ? "PAN-OS" : "FTD") : "TEXT" }),
      h("span", { class: "stitle", text: s.title }));
      btn.addEventListener("click", () => selectSample(s.id, true));
      btn.addEventListener("keydown", (ev) => {
        if (!["ArrowDown", "ArrowUp"].includes(ev.key)) return;
        ev.preventDefault();
        const i = state.samples.findIndex((x) => x.id === state.selectedSample);
        const next = state.samples[(i + (ev.key === "ArrowDown" ? 1 : -1) + state.samples.length) % state.samples.length];
        selectSample(next.id, true);
      });
      list.appendChild(btn);
    });
    if (state.samples.length) selectSample(state.samples[0].id, false);
  }

  function selectSample(id, focus) {
    state.selectedSample = id;
    for (const el of $("sample-list").children) {
      const on = el.dataset.id === id;
      el.setAttribute("aria-checked", String(on));
      el.tabIndex = on ? 0 : -1;
      if (on && focus) el.focus();
    }
    const s = state.samples.find((x) => x.id === id);
    $("sample-hint").textContent = s && s.format === "text"
      ? "Free-text sample: requires the agent intake (LLM)."
      : "Labeled scenarios with expected decisions.";
    updateRunAvailability();
  }

  function setSource(source) {
    state.source = source;
    for (const btn of document.querySelectorAll("[data-source]")) {
      const on = btn.dataset.source === source;
      btn.setAttribute("aria-selected", String(on));
      btn.tabIndex = on ? 0 : -1;
      $(btn.getAttribute("aria-controls")).hidden = !on;
    }
    updateRunAvailability();
  }

  for (const btn of document.querySelectorAll("[data-source]")) {
    btn.addEventListener("click", () => setSource(btn.dataset.source));
    btn.addEventListener("keydown", (ev) => {
      if (!["ArrowLeft", "ArrowRight"].includes(ev.key)) return;
      const order = ["sample", "yaml", "text"];
      const next = order[(order.indexOf(state.source) + (ev.key === "ArrowRight" ? 1 : 2)) % 3];
      setSource(next);
      document.querySelector(`[data-source="${next}"]`).focus();
    });
  }

  $("edit-sample").addEventListener("click", async () => {
    const s = state.samples.find((x) => x.id === state.selectedSample);
    if (!s) return;
    try {
      const data = await api(`/api/samples/${encodeURIComponent(s.id)}`);
      if (data.format === "text") { $("text-input").value = data.content; setSource("text"); updateCount("text"); }
      else { $("yaml-input").value = data.content; setSource("yaml"); updateCount("yaml"); }
    } catch (e) { toast(e.message, "bad"); }
  });

  function updateCount(kind) {
    $(`${kind}-count`).textContent = `${$(`${kind}-input`).value.length} / 32000`;
  }
  $("yaml-input").addEventListener("input", () => { updateCount("yaml"); $("yaml-errors").hidden = true; });
  $("text-input").addEventListener("input", () => { updateCount("text"); $("text-errors").hidden = true; updateRunAvailability(); });
  for (const id of ["yaml-input", "text-input"]) {
    $(id).addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" && (ev.ctrlKey || ev.metaKey)) { ev.preventDefault(); runReview(); }
      if (ev.key === "Tab" && id === "yaml-input" && !ev.shiftKey && !ev.ctrlKey) {
        ev.preventDefault();
        const t = ev.target, s = t.selectionStart;
        t.setRangeText("  ", s, t.selectionEnd, "end");
      }
    });
  }

  function useLlm() { return $("mode-llm").checked; }

  function applyModeAvailability() {
    const ok = state.config.llm_configured;
    $("mode-llm").disabled = !ok;
    $("mode-llm-card").classList.toggle("disabled", !ok);
    $("mode-llm-card").title = ok ? "" : "No LLM is configured on the server (MODEL and an API key in .env).";
    if (!ok) $("mode-det").checked = true;
    updateRunAvailability();
  }
  for (const r of document.querySelectorAll('input[name="mode"]')) r.addEventListener("change", updateRunAvailability);

  function jobActive() { return state.job && !["completed", "failed"].includes(state.job.status); }

  function updateRunAvailability() {
    let reason = "";
    const sample = state.samples.find((x) => x.id === state.selectedSample);
    const needsLlm = state.source === "text" || (state.source === "sample" && sample && sample.format === "text");
    if (jobActive()) reason = state.job.status === "awaiting_approval"
      ? "A review is awaiting your approval decision." : "A review is in progress. One review runs at a time.";
    else if (needsLlm && !useLlm()) reason = state.config && state.config.llm_configured
      ? "Free-text requests need the agent intake. Select “Agents + deterministic engine”."
      : "Free-text requests need an LLM, which is not configured on the server.";
    else if (state.source === "sample" && !sample) reason = "Select a sample.";
    $("run-btn").disabled = Boolean(reason);
    $("run-note").textContent = reason;
  }

  $("run-btn").addEventListener("click", runReview);

  async function runReview() {
    if ($("run-btn").disabled) return;
    const body = { source: state.source, use_llm: useLlm(), process: $("process").value };
    const errBox = state.source === "yaml" ? $("yaml-errors") : state.source === "text" ? $("text-errors") : null;
    if (errBox) errBox.hidden = true;
    if (state.source === "sample") body.sample_id = state.selectedSample;
    if (state.source === "yaml") body.content = $("yaml-input").value;
    if (state.source === "text") {
      body.content = $("text-input").value;
      if ($("vendor-hint").value) body.vendor_hint = $("vendor-hint").value;
    }
    $("run-btn").disabled = true;
    try {
      const job = await api("/api/reviews", { method: "POST", body });
      toast(`Review started: ${job.label}`, "info", 3500);
      await openJob(job.id, true);
      refreshHistory();
    } catch (e) {
      if (e instanceof ApiError && errBox && (e.status === 422 || e.status === 400)) {
        clear(errBox);
        errBox.append(h("strong", { text: e.message }));
        if (e.errors.length) errBox.append(h("ul", null, e.errors.map((x) => h("li", null, h("code", { text: x.field }), " — ", x.message))));
        errBox.hidden = false;
      } else if (e.status !== 401) {
        toast(e.message, "bad");
      }
    } finally {
      updateRunAvailability();
    }
  }

  // ------------------------------------------------------------------ queue

  async function refreshHistory() {
    let jobs = [];
    try { jobs = await api("/api/reviews"); } catch { return; }
    const list = $("history");
    clear(list);
    if (!jobs.length) { list.append(h("li", { class: "empty-note", text: "No reviews in this session." })); return; }
    for (const j of jobs) {
      const btn = h("button", { type: "button", "aria-current": String(j.id === state.jobId) },
        h("span", { class: "h-title", text: j.change_id || j.label }),
        j.decision ? decisionBadge(j.decision) : h("span", { class: `status-pill status-${j.status}` }, h("span", { class: "dot" }), h("span", { class: "txt", text: statusText(j.status) })),
        h("span", { class: "h-meta", text: `${utc(j.created_at)} · ${j.use_llm ? "agents" : "deterministic"} · ${statusText(j.status)}` }));
      btn.addEventListener("click", () => openJob(j.id));
      list.append(h("li", null, btn));
    }
  }
  $("refresh-history").addEventListener("click", refreshHistory);

  function statusText(s) {
    return { queued: "Queued", running: "Running", awaiting_approval: "Awaiting decision", completed: "Completed", failed: "Failed" }[s] || s;
  }

  // ------------------------------------------------------------------ open / stream a job

  async function openJob(id, fresh) {
    if (state.stream) state.stream.abort();
    Object.assign(state, {
      jobId: id, job: null, lastSeq: 0, events: [], steps: {}, stepCounts: {}, thinkingShown: new Set(),
      stepFilter: null, approvalOpenedFor: null,
    });
    $("empty-state").hidden = true;
    for (const id2 of ["review-view", "pipeline-panel", "detail-panel"]) $(id2).hidden = false;
    $("approval-banner").hidden = true;
    $("error-banner").hidden = true;
    $("step-filter-chip").hidden = true;
    clear($("feed")).append(h("li", { class: "feed-empty", text: "Awaiting first event…" }));
    renderPipeline();
    selectTab("activity");
    await refreshJob();
    follow(id);
    if (fresh) $("main").focus({ preventScroll: true });
  }

  async function refreshJob() {
    if (!state.jobId) return;
    try {
      state.job = await api(`/api/reviews/${state.jobId}`);
    } catch (e) {
      if (e.status === 404) toast("That review is no longer available on the server.", "bad");
      return;
    }
    renderHeader();
    renderPackage();
    renderRequest();
    updateRunAvailability();
    syncApproval();
    if (state.job.status === "failed") {
      $("error-banner").hidden = false;
      $("error-banner-text").textContent = state.job.error || "Unknown error.";
    }
  }

  function follow(id) {
    const ctrl = new AbortController();
    state.stream = ctrl;
    let failures = 0;

    const run = async () => {
      while (!ctrl.signal.aborted) {
        try {
          const res = await fetch(`/api/reviews/${id}/events?after=${state.lastSeq}`, {
            headers: { Authorization: `Bearer ${token}`, Accept: "text/event-stream" },
            signal: ctrl.signal, credentials: "omit", cache: "no-store",
          });
          if (res.status === 401) { lockConsole("Your access token was rejected."); return; }
          if (!res.ok || !res.body) throw new Error(`stream ${res.status}`);
          failures = 0;
          setLink("live");
          const reader = res.body.getReader();
          const decoder = new TextDecoder();
          let buffer = "";
          for (;;) {
            const { value, done } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            let idx;
            while ((idx = buffer.indexOf("\n\n")) >= 0) {
              const chunk = buffer.slice(0, idx);
              buffer = buffer.slice(idx + 2);
              if (handleSse(chunk) === "end") { setLink("idle"); await refreshJob(); refreshHistory(); return; }
            }
          }
        } catch (e) {
          if (ctrl.signal.aborted) { setLink("idle"); return; }
          failures += 1;
          setLink("retry");
          if (failures > 8) { setLink("idle"); toast("Lost connection to the live event stream.", "bad"); return; }
          await new Promise((r) => setTimeout(r, Math.min(1000 * failures, 5000)));
        }
      }
    };
    run();
  }

  function handleSse(chunk) {
    let event = "message", data = "";
    for (const line of chunk.split("\n")) {
      if (line.startsWith(":")) continue;
      if (line.startsWith("event:")) event = line.slice(6).trim();
      else if (line.startsWith("data:")) data += line.slice(5).trim();
    }
    if (event === "end") return "end";
    if (!data) return null;
    let ev;
    try { ev = JSON.parse(data); } catch { return null; }
    if (typeof ev.seq !== "number" || ev.seq <= state.lastSeq) return null;
    state.lastSeq = ev.seq;
    onEvent(ev);
    return null;
  }

  // ------------------------------------------------------------------ event -> UI

  function setStep(id, status) {
    if (!id || !STEP_BY_ID[id]) return;
    if (state.steps[id] === "done" && status === "active") return;
    state.steps[id] = status;
  }

  function closeEarlierAgents(stepId) {
    const idx = AGENT_STEPS.indexOf(stepId);
    for (let i = 0; i < idx; i++) {
      const s = AGENT_STEPS[i];
      if (state.steps[s] === "active") state.steps[s] = "done";
    }
  }

  function onEvent(ev) {
    state.events.push(ev);
    const step = ev.step;
    switch (ev.kind) {
      case "intake_started": setStep("intake", "active"); break;
      case "analysis_complete": setStep("intake", "done"); setStep("analysis", "done"); refreshJob(); break;
      case "crew_skipped": AGENT_STEPS.forEach((s) => setStep(s, "skipped")); break;
      case "task_started": if (step) { closeEarlierAgents(step); setStep(step, "active"); } break;
      case "task_completed": if (step) setStep(step, "done"); break;
      case "task_failed": if (step) setStep(step, "failed"); break;
      case "tool_started": case "thinking":
        if (step && state.steps[step] !== "done") { closeEarlierAgents(step); setStep(step, "active"); }
        if (ev.kind === "tool_started" && step) state.stepCounts[step] = (state.stepCounts[step] || 0) + 1;
        break;
      case "crew_complete": AGENT_STEPS.forEach((s) => { if (state.steps[s] !== "skipped") state.steps[s] = "done"; }); break;
      case "approval_required": setStep("gate", "waiting"); refreshJob(); break;
      case "approval_submitted": case "approval_timeout": setStep("gate", "done"); break;
      case "report_written":
        if (!state.steps.gate) setStep("gate", "skipped");
        setStep("report", "done");
        refreshJob();
        break;
      case "completed": refreshJob(); refreshHistory(); break;
      case "failed": {
        const active = Object.keys(state.steps).find((k) => state.steps[k] === "active");
        if (active) state.steps[active] = "failed";
        refreshJob();
        refreshHistory();
        break;
      }
      default: break;
    }
    renderPipeline();
    renderFeedItem(ev);
    renderElapsed();
  }

  // ------------------------------------------------------------------ header strip + pipeline

  function renderHeader() {
    const j = state.job;
    const r = j.result;
    $("rv-id").textContent = j.change_id || j.label;
    const dec = clear($("rv-decision"));
    if (j.decision) dec.append(decisionBadge(j.decision, true));
    const meta = clear($("rv-meta"));
    const req = r && r.request;
    if (req) meta.append(h("span", null, "VENDOR ", h("b", { text: VENDOR_LABEL[req.target.vendor] || req.target.vendor })),
      h("span", null, "SCOPE ", h("b", { text: req.target.device_group || "—" })));
    meta.append(h("span", null, "MODE ", h("b", { text: j.use_llm ? `agents · ${j.process}` : "deterministic" })),
      h("span", null, "INPUT ", h("b", { text: j.free_text ? "free text" : "structured" })));

    const pill = $("rv-status");
    pill.className = `status-pill status-${j.status}`;
    pill.querySelector(".txt").textContent = statusText(j.status);
    renderMeter(j.risk_score);
    renderElapsed();

    const gate = $("rv-gate");
    if (j.status === "awaiting_approval") gate.textContent = "AWAITING REVIEWER DECISION";
    else if (r && r.final) gate.textContent = r.gate;
    else gate.textContent = "Pending routing";
  }

  function scoreBand(score) {
    return score == null ? "" : score >= 70 ? "crit" : score >= 40 ? "high" : score >= 15 ? "med" : "ok";
  }

  function renderMeter(score) {
    const meter = clear($("rv-meter"));
    const band = scoreBand(score);
    const lit = score == null ? 0 : Math.max(score > 0 ? 1 : 0, Math.round(score / 5));
    for (let i = 0; i < 20; i++) meter.append(h("span", { class: i < lit ? `b-${band}` : "" }));
    meter.setAttribute("aria-label", score == null ? "Risk score not yet available" : `Risk score ${score} out of 100`);
    const el = $("rv-score");
    el.className = `rs-big${band ? ` score-${band}` : ""}`;
    el.textContent = score == null ? "—" : `${score} / 100`;
  }

  function renderElapsed() {
    const j = state.job;
    if (!j) return;
    const start = new Date(j.created_at).getTime();
    const last = state.events.length ? new Date(state.events[state.events.length - 1].ts).getTime() : start;
    const end = ["completed", "failed"].includes(j.status) ? last : Date.now();
    $("rv-elapsed").textContent = `T+${duration(end - start)} · ${state.events.length} events · started ${utc(j.created_at)}`;
  }

  function renderPipeline() {
    const ol = clear($("pipeline"));
    for (const s of STEPS) {
      const st = state.steps[s.id] || "pending";
      const nodeIcon = st === "done" ? "check" : st === "failed" ? "x" : st === "waiting" ? "clock" : s.icon;
      const node = h("button", {
        type: "button", class: "step-node",
        "aria-label": `${s.label}: ${STATE_WORD[st]}. Filter the event log to this stage.`,
        "aria-pressed": String(state.stepFilter === s.id),
      }, icon(nodeIcon));
      node.addEventListener("click", () => setStepFilter(state.stepFilter === s.id ? null : s.id));
      const count = state.stepCounts[s.id];
      const kindClass = { Engine: "k-engine", Agent: "k-agent", Human: "k-human" }[s.kind] || "";
      ol.append(h("li", { class: `step ${st}${state.stepFilter === s.id ? " selected" : ""}` },
        node,
        h("span", { class: `label step-kind ${kindClass}`, text: s.kind }),
        h("span", { class: "step-label", text: s.label }),
        h("span", { class: "step-sub", text: s.sub }),
        h("span", { class: "step-state", text: STATE_WORD[st] }),
        h("span", { class: "step-count", text: count ? `${count} tool call${count > 1 ? "s" : ""}` : "" })));
    }
  }

  // ------------------------------------------------------------------ event log

  function renderFilters() {
    const box = clear($("feed-filters"));
    for (const f of FILTERS) {
      const b = h("button", { type: "button", "aria-pressed": String(state.filter === f.id), text: f.label });
      b.addEventListener("click", () => { state.filter = f.id; renderFilters(); rerenderFeed(); });
      box.append(b);
    }
  }

  function setStepFilter(stepId) {
    state.stepFilter = stepId;
    const chip = clear($("step-filter-chip"));
    if (stepId) {
      const btn = h("button", { type: "button", class: "link-btn", "aria-label": "Clear stage filter" }, icon("x"));
      btn.addEventListener("click", () => setStepFilter(null));
      chip.append(`STAGE: ${STEP_BY_ID[stepId].label.toUpperCase()}`, btn);
    }
    chip.hidden = !stepId;
    renderPipeline();
    selectTab("activity");
    rerenderFeed();
  }

  function stepOfEvent(ev) {
    if (ev.step) return ev.step;
    return {
      intake_started: "intake", analysis_complete: "analysis", approval_required: "gate", approval_submitted: "gate",
      approval_timeout: "gate", report_written: "report", completed: "report",
    }[ev.kind] || null;
  }

  /** Provenance of an event. Tools and the guardrail are deterministic code even when an agent calls them. */
  function provOf(ev) {
    if (["tool_started", "tool_finished", "tool_error", "guardrail", "analysis_complete"].includes(ev.kind)) return "det";
    if (["task_started", "task_completed", "task_failed", "thinking"].includes(ev.kind)) return "ai";
    if (ev.kind === "approval_submitted") return "human";
    return "flow";
  }

  function visible(ev) {
    if (state.stepFilter && stepOfEvent(ev) !== state.stepFilter) return false;
    const f = FILTERS.find((x) => x.id === state.filter);
    return !f || !f.test || f.test(provOf(ev));
  }

  function rerenderFeed() {
    const feed = clear($("feed"));
    state.thinkingShown = new Set();
    let n = 0;
    for (const ev of state.events) {
      if (!visible(ev)) continue;
      const item = feedItem(ev);
      if (item) { feed.append(item); n++; }
    }
    if (!n) feed.append(h("li", { class: "feed-empty", text: state.events.length ? "No events match this filter." : "Awaiting first event…" }));
    $("feed-count").textContent = String(state.events.length);
  }

  function renderFeedItem(ev) {
    $("feed-count").textContent = String(state.events.length);
    if (!visible(ev)) return;
    const item = feedItem(ev);
    if (!item) return;
    const feed = $("feed");
    const empty = feed.querySelector(".feed-empty");
    if (empty) empty.remove();
    feed.append(item);
    if ($("autoscroll").checked) feed.scrollTop = feed.scrollHeight;
  }

  function prettyOutput(text) {
    if (typeof text !== "string") return String(text);
    const trimmed = text.trim();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      try { return JSON.stringify(JSON.parse(trimmed), null, 2); } catch { /* not JSON */ }
    }
    return text;
  }

  function details(label, text) {
    if (!text || !String(text).trim() || String(text).trim() === "{}") return null;
    return h("details", null, h("summary", { text: label }), h("pre", { text: prettyOutput(text) }));
  }

  function taskName(ev) {
    return STEP_BY_ID[ev.step] ? STEP_BY_ID[ev.step].label.toLowerCase() + " task" : ev.task || "task";
  }

  function feedItem(ev) {
    // short stage name (e.g. "Rulebase Analyst") reads better than the full templated role
    const agent = (ev.step && STEP_BY_ID[ev.step] ? STEP_BY_ID[ev.step].label : null) || ev.agent;
    const p = provOf(ev);
    let actor = "Flow", src = null, mark = "", body = [], extra = [];
    switch (ev.kind) {
      case "intake_started":
        src = "intake"; body = [h("strong", { text: "Change request received" }), ev.free_text ? " — free text, routed to the intake agent" : " — structured request, schema-validated"];
        break;
      case "analysis_complete": {
        actor = "Analysis engine"; src = "shadow.py · risk_rules.py";
        const j = state.job;
        body = [h("strong", { text: "Deterministic analysis complete" }), j && j.decision ? ` — ${DECISION_LABEL[j.decision]}, risk ${j.risk_score}/100` : ""];
        extra.push(h("div", { class: "feed-note", text: "Duplicate / shadow / deny-override analysis and RG-001…RG-016 evaluated in Python. Agents may read these facts but cannot alter them." }));
        break;
      }
      case "crew_skipped": actor = "Crew"; src = "router"; body = [h("strong", { text: "Agent crew skipped" }), " — deterministic-only run"]; break;
      case "crew_started": actor = "Crew"; src = ev.process; body = [h("strong", { text: "Review crew dispatched" }), ` (${ev.process})`]; break;
      case "task_started":
        actor = agent || "Agent"; src = agent; body = ["Started ", h("strong", { text: taskName(ev) })];
        break;
      case "thinking": {
        const key = ev.step || ev.agent || "x";
        if (state.thinkingShown.has(key)) return null;
        state.thinkingShown.add(key);
        actor = agent || "Agent"; src = agent; body = [h("span", { class: "thinking-dots", text: "Reasoning over tool results" })];
        break;
      }
      case "tool_started":
        actor = agent || "Agent"; src = ev.tool;
        body = ["Invoked deterministic tool ", h("code", { text: ev.tool })];
        extra.push(details("Arguments", ev.args));
        break;
      case "tool_finished":
        actor = agent || "Agent"; src = ev.tool;
        body = ["Tool ", h("code", { text: ev.tool }), " returned", ev.duration_ms != null ? ` in ${ev.duration_ms} ms` : ""];
        extra.push(details("Tool output", ev.output));
        break;
      case "tool_error":
        actor = agent || "Agent"; src = ev.tool; mark = "k-bad";
        body = ["Tool ", h("code", { text: ev.tool }), " failed"];
        extra.push(h("div", { class: "feed-note", text: ev.error }));
        break;
      case "guardrail":
        actor = "Evidence guardrail"; src = "crew.py";
        if (ev.success) { mark = "k-ok"; body = [h("strong", { text: "Guardrail PASS" }), " — narrative cites only verified findings, rules and the computed decision"]; }
        else {
          mark = "k-warn";
          body = [h("strong", { text: "Guardrail REJECT" }), ` — draft returned to the writer (attempt ${(ev.retry || 0) + 1})`];
          extra.push(h("div", { class: "feed-note", text: ev.error }));
        }
        break;
      case "task_completed":
        actor = agent || "Agent"; src = agent; body = ["Completed ", h("strong", { text: taskName(ev) })];
        extra.push(details("Agent output", ev.output));
        break;
      case "task_failed":
        actor = agent || "Agent"; src = agent; mark = "k-bad"; body = [h("strong", { text: "Task failed" })];
        extra.push(h("div", { class: "feed-note", text: ev.error }));
        break;
      case "crew_complete": actor = "Crew"; body = [h("strong", { text: "All agents complete" })]; break;
      case "approval_required":
        actor = "Router"; src = "flow.route"; mark = "k-warn";
        body = [h("strong", { text: "Escalated to human approval" }), ` — ${ev.reason}`];
        break;
      case "approval_submitted":
        actor = ev.reviewer; src = "approval gate"; mark = "k-human";
        body = [h("strong", { text: ev.action }), " — decision recorded with timestamp"];
        break;
      case "approval_timeout":
        actor = "Approval gate"; src = "timeout"; mark = "k-warn";
        body = [h("strong", { text: "No decision received" }), ` within ${ev.minutes} minutes — recorded as DEFERRED`];
        break;
      case "report_written":
        actor = "Report writer"; src = "cab_report.md.j2"; mark = "k-ok"; body = [h("strong", { text: "Decision package written" })];
        extra.push(h("div", { class: "feed-note", text: `Approval gate: ${ev.gate}` }));
        break;
      case "completed": actor = "Flow"; mark = "k-ok"; body = [h("strong", { text: "Review complete" })]; break;
      case "failed": actor = "Flow"; mark = "k-bad"; body = [h("strong", { text: "Review failed" })]; extra.push(h("div", { class: "feed-note", text: ev.error })); break;
      default: body = [ev.kind];
    }
    return h("li", { class: `feed-item ${mark}` },
      h("span", { class: "feed-time", text: utc(ev.ts) }),
      h("span", { class: "feed-src", title: src ? `${PROV_TITLE[p]} · ${src}` : PROV_TITLE[p] }, prov(p)),
      h("span", { class: "feed-actor", text: actor, title: ev.agent || actor }),
      h("div", { class: "feed-body" }, ...body, ...extra));
  }

  // ------------------------------------------------------------------ tabs

  const TABS = ["activity", "package", "request"];
  function selectTab(name) {
    for (const t of TABS) {
      const btn = $(`tab-btn-${t}`);
      const on = t === name;
      btn.setAttribute("aria-selected", String(on));
      btn.tabIndex = on ? 0 : -1;
      $(`tab-${t}`).hidden = !on;
    }
  }
  for (const t of TABS) {
    const btn = $(`tab-btn-${t}`);
    btn.addEventListener("click", () => selectTab(t));
    btn.addEventListener("keydown", (ev) => {
      if (!["ArrowLeft", "ArrowRight"].includes(ev.key)) return;
      const i = TABS.indexOf(t);
      const next = TABS[(i + (ev.key === "ArrowRight" ? 1 : TABS.length - 1)) % TABS.length];
      selectTab(next);
      $(`tab-btn-${next}`).focus();
    });
  }

  // ------------------------------------------------------------------ decision package

  function section(titleText, iconName, provNode, sub, ...content) {
    return h("section", { class: "section" },
      h("div", { class: "section-head" },
        h("h2", null, icon(iconName), titleText),
        h("div", { class: "meta" }, sub ? h("span", { class: "sub", text: sub }) : null, provNode)),
      ...content);
  }

  function kpi(label, value, desc, provNode, extraNode, small) {
    return h("div", { class: "kpi" }, h("span", { class: "label", text: label }),
      value instanceof Node ? h("div", { class: `v${small ? " small" : ""}` }, value) : h("div", { class: `v${small ? " small" : ""}`, text: value }),
      desc ? h("div", { class: "d", text: desc }) : null, extraNode || null, provNode);
  }

  function guardrailStats() {
    let pass = 0, reject = 0;
    for (const e of state.events) if (e.kind === "guardrail") { if (e.success) pass++; else reject++; }
    return { pass, reject };
  }

  function evidenceChain(f) {
    const weights = (state.config && state.config.severity_weights) || {};
    const inputs = f.evidence.filter((e) => e.kind === "request_field" || e.kind === "object");
    const rules = f.evidence.filter((e) => e.kind === "rule");
    const node = (cls, label, ...vals) => h("div", { class: `chain-node ${cls}` }, h("span", { class: "label", text: label }),
      ...vals.map((v) => h("span", { class: "val", text: v })));
    const arrow = () => h("span", { class: "chain-arrow", "aria-hidden": "true", text: "→" });
    const parts = [];
    if (inputs.length) parts.push(node("c-input", "Input · change request", ...inputs.map((e) => `${e.ref}${e.detail ? ` = ${e.detail}` : ""}`)));
    if (rules.length) parts.push(arrow(), node("c-det", "Rulebase · first-match", ...rules.map((e) => `${e.ref}${e.detail ? ` (${e.detail})` : ""}`)));
    parts.push(arrow(), node("c-det", "Check · risk_rules.py", `${f.check_id} — ${f.title}`));
    parts.push(arrow(), node("c-pol", "Policy · compliance", ...(f.compliance.length ? f.compliance : ["No mapped clause (internal standard applies)"])));
    const w = weights[f.severity];
    parts.push(arrow(), node("c-out", "Outcome · risk_policy.yaml", `${f.severity.toUpperCase()}${w != null ? ` · +${w} risk points` : ""}`));
    if (parts[0].classList && parts[0].classList.contains("chain-arrow")) parts.shift();
    return h("div", { class: "chain", role: "list", "aria-label": `Evidence chain for ${f.check_id}` }, parts);
  }

  function renderPackage() {
    const box = clear($("tab-package"));
    const j = state.job;
    const r = j && j.result;
    if (!r) {
      box.append(h("div", { class: "placeholder", text: "The decision package appears as soon as the deterministic analysis completes." }));
      return;
    }
    const risk = r.risk;
    const counts = Object.fromEntries(SEV_ORDER.map((s) => [s, 0]));
    risk.findings.forEach((f) => { counts[f.severity] += 1; });
    const total = risk.findings.length;
    const bars = h("div", { class: "sevbars", "aria-hidden": "true" },
      SEV_ORDER.filter((s) => counts[s]).map((s) => {
        const span = h("span", { class: `b-${s}`, title: `${counts[s]} ${s}` });
        span.style.flex = String(counts[s]);
        return span;
      }));

    const gateNode = r.final
      ? kpi("Approval gate", r.gate, null, /^(ACCEPTED|OVERRIDDEN|DEFERRED)/.test(r.gate) ? prov("human", "reviewer") : prov("flow", "router"), null, true)
      : kpi("Approval gate", j.status === "awaiting_approval" ? "AWAITING" : "PENDING", j.status === "awaiting_approval" ? "Reviewer decision required" : "Routing after analysis", prov("flow", "router"));

    box.append(h("div", { class: "kpis" },
      kpi("Recommendation", decisionBadge(risk.decision), DECISION_TEXT[risk.decision], prov("det", "decide()")),
      kpi("Risk score", `${risk.risk_score} / 100`, "Σ policy severity weights, capped at 100", prov("det", "risk_policy.yaml")),
      kpi("Findings", String(total), total ? SEV_ORDER.filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`).join(" · ") : "No checks fired", prov("det", "risk_rules.py"), total ? bars : null),
      kpi("Human review", risk.needs_human_review ? "REQUIRED" : "NOT REQUIRED", risk.needs_human_review ? `${risk.review_notes.length} unresolved item(s)` : "All dependent objects resolved", prov("det", "shadow.py")),
      gateNode));

    if (r.final) {
      box.append(h("div", { class: "downloads-bar" },
        h("span", { class: "label", text: "CAB package · generated in-browser from this review" }),
        h("div", { class: "downloads" },
          downloadBtn("review.md", r.report_markdown, "text/markdown"),
          downloadBtn(r.staged.filename, r.staged.config, "text/plain"),
          downloadBtn("findings.json", JSON.stringify({ request: r.request, risk: r.risk, shadow: r.shadow, approval_gate: r.gate }, null, 2), "application/json"),
          printBtn())));
    }

    // Findings with evidence chain
    const sorted = [...risk.findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
    const rows = [];
    for (const f of sorted) {
      const chainRow = h("tr", { class: "chain-row", hidden: true }, h("td", { colspan: "6" }, evidenceChain(f)));
      const toggle = h("button", { type: "button", class: "link-btn chain-toggle", "aria-expanded": "false" }, "▸ Evidence chain");
      toggle.addEventListener("click", () => {
        const open = chainRow.hidden;
        chainRow.hidden = !open;
        toggle.setAttribute("aria-expanded", String(open));
        toggle.textContent = open ? "▾ Evidence chain" : "▸ Evidence chain";
      });
      rows.push(h("tr", null,
        h("td", null, sevSpan(f.severity)),
        h("td", { class: "mono", text: f.check_id }),
        h("td", null, h("div", { class: "f-title", text: f.title }), h("div", { class: "feed-note", text: f.detail }), toggle),
        h("td", null, h("div", { class: "evidence" }, f.evidence.map((e) => h("span", { text: `${e.kind}: ${e.ref}${e.detail ? ` (${e.detail})` : ""}` })))),
        h("td", { text: f.remediation || "" }),
        h("td", null, f.compliance.length ? h("div", { class: "refs" }, f.compliance.map((c) => h("span", { text: c }))) : h("span", { class: "none", text: "—" }))), chainRow);
    }
    box.append(section("Findings", "alert", prov("det", "risk_rules.py · RG-001…016"), "severity from risk_policy.yaml",
      sorted.length ? h("div", { class: "table-wrap" }, h("table", null,
        h("thead", null, h("tr", null, ["Severity", "Check", "Finding", "Evidence", "Remediation", "Compliance"].map((c) => h("th", { scope: "col", text: c })))),
        h("tbody", null, rows)))
        : h("div", { class: "placeholder", text: "No risk checks fired for this request." })));

    // Rulebase analysis
    const s = r.shadow;
    const ref = (x) => x ? `#${x.position} ${x.name} (${x.layer}, ${x.action})` : null;
    const kv = [
      ["Target section", `${s.section} · requested placement “${s.placement_requested}” · global position ${s.insertion_position}`],
      ["Duplicate of · RG-013", ref(s.duplicate_of)],
      ["Shadowed by · RG-014", ref(s.shadowed_by)],
      ["Overrides deny · RG-015", s.deny_overrides.map(ref).join("; ")],
      ["Partial overlaps", s.partial_overlaps.map((p) => `${ref(p.rule)} — differs in ${p.partial_dimensions.join(", ")}`).join("; ")],
      ["Needs human review", s.needs_review.map((n) => `${ref(n.rule)}: ${n.reason}`).join("; ")],
      ["Disabled cleanup candidates", s.disabled_cleanup_candidates.map(ref).join("; ")],
      ["Recommended placement", s.recommended_placement],
    ];
    box.append(section("Rulebase analysis", "cpu", prov("det", "shadow.py · first-match"), "offline rulebase export",
      h("dl", { class: "kv" }, kv.flatMap(([k, v]) => [h("dt", { text: k }), h("dd", null, v ? v : h("span", { class: "none", text: "None" }))]))));

    // Narrative (AI) with guardrail status
    let narrative;
    const g = guardrailStats();
    if (r.final && j.use_llm) {
      const md = h("div", { class: "md" });
      renderMarkdown(r.narrative || "", md);
      narrative = [md, h("div", { class: "ai-note" },
        h("span", null, "GUARDRAIL ", h("span", { class: g.pass ? "ok" : "", text: g.pass ? "PASS" : "—" })),
        g.reject ? h("span", { class: "warn", text: `${g.reject} draft(s) rejected before acceptance` }) : null,
        h("span", { text: "Cites only verified check IDs and related rules; cannot change the decision." }))];
    } else if (r.final) {
      narrative = [h("div", { class: "placeholder", text: "Deterministic-only run: no AI narrative generated. All findings above are computed." })];
    } else {
      narrative = [h("div", { class: "placeholder" }, j.use_llm ? h("span", { class: "thinking-dots", text: "CAB Report Writer is drafting the narrative" }) : "Written when the review completes.")];
    }
    box.append(section("Analyst narrative", "agent", j.use_llm ? prov("ai", "CAB Report Writer") : prov("flow", "not generated"),
      j.use_llm ? "guardrail-verified" : null, ...narrative));

    // Staged config, tests, rollback
    if (r.final) {
      const st = r.staged;
      const tmpl = st.vendor === "panos" ? "panos_set.j2" : "fmc_accessrule.json.j2";
      const copy = h("button", { type: "button", class: "btn small" }, icon("copy"), "Copy");
      copy.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(st.config); toast("Staged configuration copied.", "ok", 2500); }
        catch { toast("Clipboard is not available in this browser context.", "bad"); }
      });
      box.append(section("Staged configuration", "file", prov("det", `render.py · ${tmpl}`), null,
        h("div", { class: "code-card" },
          h("div", { class: "bar" }, h("span", { class: "stage-flag" }, icon("lock"), "STAGED · NOT APPLIED"),
            h("span", { class: "grow", text: `${st.filename} — apply only through the approved change process` }), copy),
          h("pre", null, h("code", { text: st.config })))));
      box.append(h("div", { class: "two-col" },
        section("Test plan", "check", prov("det", "render.py"), "pre / post change", h("ol", { class: "steps" }, st.test_plan.map((t) => h("li", null, h("code", { text: t }))))),
        section("Rollback", "flag", prov("det", "render.py"), null, h("ol", { class: "steps" }, st.rollback.map((t) => h("li", null, h("code", { text: t })))))));
    }

    box.append(section("Items requiring human review", "shield", prov("det", "shadow.py · scan()"), null,
      risk.review_notes.length ? h("ul", { class: "steps" }, risk.review_notes.map((n) => h("li", { text: n }))) : h("div", { class: "placeholder", text: "None." })));
  }

  function downloadBtn(name, content, type) {
    const b = h("button", { type: "button", class: "btn small" }, icon("download"), name);
    b.addEventListener("click", () => {
      const url = URL.createObjectURL(new Blob([content], { type: `${type};charset=utf-8` }));
      const a = h("a", { href: url, download: name });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
    return b;
  }

  function printBtn() {
    const b = h("button", { type: "button", class: "btn small" }, icon("file"), "Print / PDF");
    b.addEventListener("click", () => { selectTab("package"); window.print(); });
    return b;
  }

  // ------------------------------------------------------------------ change request tab

  function renderRequest() {
    const box = clear($("tab-request"));
    const j = state.job;
    const r = j && j.result;
    if (!r) { box.append(h("div", { class: "placeholder", text: "Shown once the request has been parsed and validated." })); return; }
    const cr = r.request, q = cr.request;
    const list = (v) => (Array.isArray(v) ? v.join(", ") : v);
    const rows = [
      ["Change ID", cr.change_id], ["Ticket", cr.ticket_ref], ["Requester", cr.requester],
      ["Business justification", cr.business_justification],
      ["Target", `${VENDOR_LABEL[cr.target.vendor] || cr.target.vendor} · ${cr.target.device_group || "—"}`],
      ["Action", q.action], ["Source", `${list(q.source_zone)} / ${list(q.source)}`],
      ["Destination", `${list(q.destination_zone)} / ${list(q.destination)}`],
      ["Application", list(q.application)], ["Service", list(q.service)],
      ["Users", q.users && q.users.length ? list(q.users) : null],
      ["Logging", q.logging ? "Enabled" : "Disabled"],
      ["Inspection", cr.target.vendor === "panos" ? (q.security_profile_group || null)
        : [q.intrusion_policy && `IPS: ${q.intrusion_policy}`, q.file_policy && `File: ${q.file_policy}`, q.ftd_action === "trust" && "Action: Trust", q.prefilter_fastpath && "Prefilter Fastpath"].filter(Boolean).join(" · ") || null],
      ["Placement", q.placement], ["Temporary", cr.temporary ? `Yes${cr.expiry ? `, expires ${cr.expiry}` : " — no expiry"}` : "No"],
    ];
    box.append(section("Normalized change request", "inbox",
      j.free_text ? prov("ai", "intake agent · schema-validated") : prov("det", "schema-validated"), "vendor-neutral schema",
      h("dl", { class: "kv" }, rows.flatMap(([k, v]) => [h("dt", { text: k }), h("dd", null, v ? v : h("span", { class: "none", text: "Not provided" }))]))));
    box.append(h("div", { class: "two-col" },
      section("Missing for CAB approval", "alert", prov("det", "missing_fields()"), null,
        r.missing_fields.length ? h("ul", { class: "steps" }, r.missing_fields.map((m) => h("li", null, h("code", { text: m })))) : h("div", { class: "placeholder", text: "Nothing missing." })),
      section("Assumptions made at intake", "agent", j.free_text ? prov("ai", "intake agent") : prov("det", "structured input"), null,
        cr.assumptions.length ? h("ul", { class: "steps" }, cr.assumptions.map((a) => h("li", { text: a }))) : h("div", { class: "placeholder", text: "None — structured request." }))));
  }

  // ------------------------------------------------------------------ safe Markdown (subset)

  function inline(text, parent) {
    const re = /(\*\*[^*]+\*\*|__[^_]+__|`[^`]+`|\*[^*\s][^*]*\*|_[^_\s][^_]*_)/g;
    let last = 0, m;
    while ((m = re.exec(text))) {
      if (m.index > last) parent.append(text.slice(last, m.index));
      const tok = m[0];
      if (tok.startsWith("**") || tok.startsWith("__")) parent.append(h("strong", { text: tok.slice(2, -2) }));
      else if (tok.startsWith("`")) parent.append(h("code", { text: tok.slice(1, -1) }));
      else parent.append(h("em", { text: tok.slice(1, -1) }));
      last = m.index + tok.length;
    }
    if (last < text.length) parent.append(text.slice(last));
    return parent;
  }

  function renderMarkdown(src, container) {
    const lines = src.replace(/\r\n?/g, "\n").split("\n");
    const isBlockStart = (l) => /^\s*(#{1,6}\s|```|[-*+]\s|\d+[.)]\s|\|)/.test(l) || /^\s*([-*_])\1\1+\s*$/.test(l);
    let i = 0;
    while (i < lines.length) {
      const line = lines[i];
      let m;
      if (/^\s*$/.test(line)) { i++; continue; }
      if (/^\s*```/.test(line)) {
        const buf = [];
        i++;
        while (i < lines.length && !/^\s*```/.test(lines[i])) buf.push(lines[i++]);
        i++;
        container.append(h("pre", { class: "block" }, h("code", { text: buf.join("\n") })));
        continue;
      }
      if ((m = /^(#{1,6})\s+(.*)$/.exec(line))) {
        container.append(inline(m[2].replace(/#+\s*$/, ""), h(`h${Math.min(6, m[1].length + 2)}`)));
        i++; continue;
      }
      if ((m = /^\s*\**\s*Recommendation:\s*\**\s*([A-Z_]+)\**\s*$/.exec(line))) {
        container.append(h("div", { class: "recommendation" }, h("strong", { text: "Recommendation" }), decisionBadge(m[1]) || m[1]));
        i++; continue;
      }
      if (/^\s*([-*_])\1\1+\s*$/.test(line)) { container.append(h("hr")); i++; continue; }
      if (/^\s*\|.*\|\s*$/.test(line)) {
        const rows = [];
        while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) rows.push(lines[i++]);
        const cells = (r) => r.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
        const body = rows.filter((r) => !/^\s*\|[\s:|-]+\|\s*$/.test(r));
        const [head, ...rest] = body;
        if (!head) continue;
        container.append(h("div", { class: "table-wrap" }, h("table", null,
          h("thead", null, h("tr", null, cells(head).map((c) => inline(c, h("th"))))),
          h("tbody", null, rest.map((r) => h("tr", null, cells(r).map((c) => inline(c, h("td"))))))) ));
        continue;
      }
      if (/^\s*([-*+]|\d+[.)])\s+/.test(line)) {
        const ordered = /^\s*\d+[.)]\s+/.test(line);
        const lst = h(ordered ? "ol" : "ul");
        while (i < lines.length && /^\s*([-*+]|\d+[.)])\s+/.test(lines[i])) {
          lst.append(inline(lines[i].replace(/^\s*([-*+]|\d+[.)])\s+/, ""), h("li")));
          i++;
        }
        container.append(lst);
        continue;
      }
      const para = [];
      while (i < lines.length && !/^\s*$/.test(lines[i]) && !isBlockStart(lines[i])) para.push(lines[i++].trim());
      if (!para.length) { para.push(line.trim()); i++; }
      container.append(inline(para.join(" "), h("p")));
    }
  }

  // ------------------------------------------------------------------ approval gate

  function syncApproval() {
    const j = state.job;
    const waiting = j && j.status === "awaiting_approval";
    $("approval-banner").hidden = !waiting;
    if (waiting) {
      setStep("gate", "waiting");
      renderPipeline();
      $("approval-banner-text").textContent =
        `${j.change_id}: deterministic recommendation ${DECISION_LABEL[j.decision] || j.decision} (risk ${j.risk_score}/100) — ${j.approval_reason || "review required"}. ` +
        `Undecided reviews are recorded as DEFERRED after ${state.config.approval_timeout_minutes} minutes.`;
      if (state.approvalOpenedFor !== j.id) { state.approvalOpenedFor = j.id; openApproval(); }
    } else if ($("approval-dialog").open) {
      $("approval-dialog").close();
    }
  }

  $("open-approval").addEventListener("click", openApproval);
  $("dlg-later").addEventListener("click", () => $("approval-dialog").close());

  function openApproval() {
    const j = state.job;
    if (!j || j.status !== "awaiting_approval") return;
    const risk = j.result && j.result.risk;
    const sum = clear($("dlg-summary"));
    sum.append(h("strong", { text: j.change_id }), decisionBadge(j.decision), h("span", { class: "chip", text: `RISK ${j.risk_score}/100` }),
      h("span", { class: "chip", text: (j.approval_reason || "review required").toUpperCase() }));
    const ul = clear($("dlg-findings"));
    const serious = risk ? risk.findings.filter((f) => f.severity === "critical" || f.severity === "high") : [];
    if (serious.length) serious.forEach((f) => ul.append(h("li", null, sevSpan(f.severity), h("code", { text: f.check_id }), h("span", { text: f.title }))));
    else ul.append(h("li", { class: "none", text: "None — escalated for items requiring human review." }));
    $("dlg-accept-desc").textContent = `Agree with the deterministic recommendation: ${DECISION_LABEL[j.decision] || j.decision}.`;
    $("dlg-attest-text").textContent = `I have reviewed the findings and their evidence for ${j.change_id}.`;
    $("dlg-timeout").textContent = `Auto-defer after ${state.config.approval_timeout_minutes} min`;
    $("dlg-reviewer").value = store.get("rulegate.reviewer") || "";
    $("dlg-comment").value = "";
    $("dlg-count").textContent = "0 / 500";
    $("dlg-attest").checked = false;
    document.querySelector('input[name="action"][value="accept"]').checked = true;
    $("dlg-errors").hidden = true;
    const dlg = $("approval-dialog");
    if (!dlg.open) dlg.showModal();
    ($("dlg-reviewer").value ? $("dlg-attest") : $("dlg-reviewer")).focus();
  }

  $("dlg-comment").addEventListener("input", () => { $("dlg-count").textContent = `${$("dlg-comment").value.length} / 500`; });

  $("approval-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const action = document.querySelector('input[name="action"]:checked').value;
    const reviewer = $("dlg-reviewer").value.trim();
    const comment = $("dlg-comment").value.trim();
    const attested = $("dlg-attest").checked;
    const problems = [];
    if (reviewer.length < 2) problems.push("Enter your name (at least 2 characters).");
    if (action === "override" && comment.length < 10) problems.push("An override needs a justification of at least 10 characters.");
    if (!attested) problems.push("Confirm that you reviewed the findings and evidence.");
    const errBox = $("dlg-errors");
    if (problems.length) {
      clear(errBox).append(h("ul", null, problems.map((p) => h("li", { text: p }))));
      errBox.hidden = false;
      return;
    }
    $("dlg-submit").disabled = true;
    try {
      await api(`/api/reviews/${state.jobId}/decision`, { method: "POST", body: { action, reviewer, comment, attested } });
      store.set("rulegate.reviewer", reviewer);
      $("approval-dialog").close();
      $("approval-banner").hidden = true;
      toast("Decision recorded. Generating the CAB package…", "ok", 3500);
      await refreshJob();
    } catch (e) {
      if (e.status !== 401) {
        clear(errBox).append(h("strong", { text: e.message }));
        if (e.errors && e.errors.length) errBox.append(h("ul", null, e.errors.map((x) => h("li", { text: x.message }))));
        errBox.hidden = false;
      }
    } finally {
      $("dlg-submit").disabled = false;
    }
  });

  // ------------------------------------------------------------------ start

  initToken();
  if (!token) lockConsole("");
  else boot().catch((e) => { if (!(e instanceof ApiError && e.status === 401)) lockConsole("Could not reach the RuleGate server."); });
})();
