// AgentGuard dashboard. No framework, no build step.
// All text from the server (logs, arguments, model output) is untrusted: it is only
// ever inserted with textContent / text nodes, never parsed as HTML.

const TOKEN_KEY = "agentguard.operatorToken";
const TERMINAL = new Set(["completed", "failed", "halted", "cancelled"]);

const state = {
  token: sessionStorage.getItem(TOKEN_KEY),
  config: null,
  policy: null,
  scenarios: [],
  datasets: [],
  runs: [],
  scenarioId: null,
  runId: null,
  detail: null, // {run, metrics, actions, current_policy_version}
  actions: new Map(),
  events: [],
  lastSeq: 0,
  selectedSeq: null,
  showAll: false,
  stream: null, // {ctrl: AbortController, runId}
  refreshTimer: null,
  announced: new Set(),
};

// ---------------------------------------------------------------- helpers

const $ = (id) => document.getElementById(id);

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") el.className = value;
    else if (key === "text") el.textContent = value;
    else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

function fmtTime(ts) {
  if (!ts) return "–";
  return new Date(ts).toLocaleTimeString([], { hour12: false });
}

function fmtDateTime(ts) {
  if (!ts) return "–";
  return new Date(ts).toLocaleString([], { hour12: false });
}

function pretty(value, limit = 8000) {
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return text.length > limit ? `${text.slice(0, limit)}\n… (${text.length - limit} more characters)` : text;
}

function shortArgs(args) {
  if (!args || typeof args !== "object") return "";
  const parts = Object.entries(args)
    .filter(([, v]) => v !== null && v !== undefined)
    .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`);
  const text = parts.join(", ");
  return text.length > 90 ? `${text.slice(0, 90)}…` : text;
}

function announce(message) {
  $("announcer").textContent = message;
}

const EFFECT_LABEL = { allow: "Allow", deny: "Deny", require_approval: "Needs approval" };
const EFFECT_CHIP = { allow: "chip-allow", deny: "chip-deny", require_approval: "chip-approval" };

// Inline SVG icons (stroke paths, 24x24). Built with createElementNS: no HTML parsing.
const ICONS = {
  search: ["M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14Z", "m20 20-3.5-3.5"],
  alert: ["M12 3.5 2.5 20h19L12 3.5Z", "M12 10v4.5", "M12 17.5v.01"],
  bug: ["M12 8a4 4 0 0 1 4 4v3a4 4 0 0 1-8 0v-3a4 4 0 0 1 4-4Z", "M4 13h4M16 13h4M5 7l3 2M19 7l-3 2M5 19l3-2M19 19l-3-2"],
  hand: ["M8 13V5.5a1.5 1.5 0 0 1 3 0V11", "M11 10.5V4.5a1.5 1.5 0 0 1 3 0v6", "M14 10.5V6a1.5 1.5 0 0 1 3 0v7c0 4-2.5 7-6.5 7S5 17 4 14l-1.2-2.6a1.4 1.4 0 0 1 2.4-1.4L8 13"],
  cloud: ["M7 18h10.5a4 4 0 0 0 .5-8 6 6 0 0 0-11.6 1.5A3.3 3.3 0 0 0 7 18Z"],
  play: ["M7 4.5v15l12-7.5-12-7.5Z"],
  sun: ["M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z", "M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"],
  moon: ["M12 3a9 9 0 1 0 9 9 7 7 0 0 1-9-9Z"],
  bell: ["M6 8a6 6 0 1 1 12 0c0 7 3 9 3 9H3s3-2 3-9", "M10.3 21a1.9 1.9 0 0 0 3.4 0"],
};
const SVG_NS = "http://www.w3.org/2000/svg";
function icon(name) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  for (const d of ICONS[name] || []) {
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", d);
    svg.append(path);
  }
  return svg;
}
const SCENARIO_LOOK = {
  normal: ["search", "tone-ok"],
  overreach: ["hand", "tone-bad"],
  injection: ["bug", "tone-bad"],
  approval: ["alert", "tone-warn"],
  cloudflare: ["cloud", "tone-info"],
};
// The timeline dot takes its colour from the status chip next to it.
function toneOf(chipEl) {
  const cls = chipEl.className || "";
  if (/chip-(ok|allow)/.test(cls)) return "tone-ok";
  if (/chip-(bad|deny)/.test(cls)) return "tone-bad";
  if (/chip-(warn|approval)/.test(cls)) return "tone-warn";
  if (/chip-info/.test(cls)) return "tone-info";
  return "";
}

function chip(text, cls = "chip-neutral") {
  return h("span", { class: `chip ${cls}`, text });
}

function stateChip(runState) {
  const cls =
    runState === "completed" ? "chip-ok"
    : runState === "halted" || runState === "failed" ? "chip-bad"
    : runState === "awaiting_approval" ? "chip-warn"
    : runState === "running" || runState === "created" ? "chip-info"
    : "chip-neutral";
  return chip(runState.replace("_", " "), cls);
}

const ACTION_STATE_CHIP = {
  succeeded: "chip-ok",
  allowed: "chip-ok",
  approved: "chip-ok",
  pending_approval: "chip-warn",
  executing: "chip-warn",
  denied: "chip-bad",
  rejected: "chip-bad",
  expired: "chip-bad",
  invalidated: "chip-bad",
  failed: "chip-bad",
};

// ---------------------------------------------------------------- API

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function api(path, { method = "GET", body } = {}) {
  const headers = state.token ? { Authorization: `Bearer ${state.token}` } : {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const isJson = (res.headers.get("content-type") || "").includes("application/json");
  const data = isJson ? await res.json() : null;
  if (res.status === 401) {
    // Parallel requests can all fail; only the first signs out, so its message stays.
    if (state.token) logout("That token was rejected.");
    else if ($("login").hidden) logout("");
    throw new ApiError(401, "unauthorized");
  }
  if (!res.ok) throw new ApiError(res.status, (data && data.detail) || res.statusText);
  return data;
}

// ---------------------------------------------------------------- auth

function logout(message = "") {
  sessionStorage.removeItem(TOKEN_KEY);
  state.token = null;
  stopStream();
  $("app").hidden = true;
  $("login").hidden = false;
  $("login-error").textContent = message;
  $("login-token").focus();
}

$("login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  state.token = $("login-token").value.trim();
  $("login-error").textContent = "";
  try {
    await boot();
    sessionStorage.setItem(TOKEN_KEY, state.token);
    $("login-token").value = "";
  } catch (err) {
    if (!(err instanceof ApiError && err.status === 401)) $("login-error").textContent = String(err.message || err);
  }
});

$("btn-logout").addEventListener("click", () => logout());

// Inspector tabs: Details (the selected timeline entry) and Policy (rules in force).
function showTab(name) {
  for (const tab of ["details", "policy"]) {
    $(`tab-${tab}`).setAttribute("aria-selected", String(tab === name));
    $(`pane-${tab}`).hidden = tab !== name;
  }
}
$("tab-details").addEventListener("click", () => showTab("details"));
$("tab-policy").addEventListener("click", () => showTab("policy"));

// Colour theme: follows the system until you pick one.
const THEME_KEY = "agentguard.theme";
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  $("btn-theme").replaceChildren(icon(theme === "dark" ? "sun" : "moon"));
  $("btn-theme").title = theme === "dark" ? "Switch to light theme" : "Switch to dark theme";
}
applyTheme(
  localStorage.getItem(THEME_KEY) || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"),
);
$("btn-theme").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  localStorage.setItem(THEME_KEY, next);
  applyTheme(next);
});
$("btn-alerts").addEventListener("click", async () => {
  await Notification.requestPermission();
  renderAlertsButton();
});

// ---------------------------------------------------------------- boot

async function boot() {
  const [config, policy, scenarios, datasets] = await Promise.all([
    api("/api/config"),
    api("/api/policies/current"),
    api("/api/scenarios"),
    api("/api/datasets"),
  ]);
  Object.assign(state, { config, policy, scenarios, datasets });
  $("login").hidden = true;
  $("app").hidden = false;
  renderHeader();
  renderPolicy();
  renderScenarioButtons();
  renderDatasets();
  if (!config.claude_available) $("mode").value = "replay";
  updateModeHint();
  renderAlertsButton();
  await loadRuns();
  if (!openLinkedRun() && !state.runId && state.runs.length) selectRun(state.runs[0].id);
}

// #run=<id> links (alerts use them) open that run, also when the dashboard is already open.
function openLinkedRun() {
  const linked = location.hash.match(/^#run=(run_[A-Za-z0-9_-]+)$/);
  if (!linked || !state.runs.some((r) => r.id === linked[1])) return false;
  if (state.runId !== linked[1]) selectRun(linked[1]);
  return true;
}
window.addEventListener("hashchange", () => {
  if (state.config) openLinkedRun();
});

function renderHeader() {
  const c = state.config;
  const real = c.upstreams || [];
  $("badge-tools").textContent = real.length ? `Tools: demo mocks + real ${real.join(", ")}` : "Tools: demo mocks";
  $("badge-tools").title = real.length
    ? `Calls to ${real.join(", ")} tools change real systems once allowed or approved.`
    : "No upstream MCP servers are connected; every tool is a mock.";
  $("badge-operator").textContent = `${c.user.name} · ${c.user.role}`;
  $("user-avatar").textContent = c.user.name.replace(/[^A-Za-z0-9]/g, "").slice(0, 2) || "?";
  $("badge-operator").title = c.user.via === "sso" ? "Signed in through single sign-on" : "Signed in with a token";
  $("btn-logout").hidden = c.user.via === "sso";
  // Show only what this role can do; the API enforces the same rules.
  document.body.dataset.role = c.user.role;
  $("run-form").hidden = !can("admin");
  $("run-form-locked").hidden = can("admin");
  const rp = state.policy.reviewer;
  const reviewer = $("badge-reviewer");
  if (!rp.enabled) reviewer.textContent = "Reviewer: off";
  else if (c.reviewer) reviewer.textContent = `Reviewer: ${{ jev: "Jev", clef: "Clef" }[c.reviewer] ?? c.reviewer} on ${rp.review_labels.join(", ")}`;
  else reviewer.textContent = `Reviewer: human, ${rp.review_labels.join(", ")} needs your approval`;
  reviewer.title = "A model reviewer can only escalate actions the rules allow; it never permits anything.";
  renderModeBadge();
}

const ROLE_ORDER = ["viewer", "approver", "admin"];
function can(role) {
  const mine = state.config && state.config.user ? state.config.user.role : "viewer";
  return ROLE_ORDER.indexOf(mine) >= ROLE_ORDER.indexOf(role);
}

function renderModeBadge() {
  const badge = $("badge-mode");
  const run = state.detail && state.detail.run;
  if (!run) {
    badge.textContent = state.config.claude_available ? "Live agent available" : "Replay only";
    return;
  }
  const labels = {
    live: `Live · Claude Code (${(run.agent && run.agent.model) || state.config.claude_model})`,
    replay: "Replay · scripted proposals",
    external: "External MCP agent",
  };
  badge.textContent = labels[run.mode] || run.mode;
}

function setConnection(status) {
  const badge = $("badge-conn");
  const text = { live: "Live updates on", retry: "Reconnecting…", idle: "Not connected" };
  badge.textContent = text[status];
  badge.className = `badge ${status === "live" ? "badge-ok" : status === "retry" ? "badge-bad" : ""}`;
}

// ---------------------------------------------------------------- new run form

function renderScenarioButtons() {
  const box = $("scenario-buttons");
  box.replaceChildren(
    ...state.scenarios.map((s) =>
      h(
        "button",
        {
          type: "button",
          class: "scenario-btn",
          "aria-pressed": String(state.scenarioId === s.id),
          disabled: !s.available,
          title: s.available ? null : `Not available: needs ${s.missing_tools.join(", ")}. See upstreams.example.yaml.`,
          onclick: () => chooseScenario(s.id),
        },
        h("span", { class: `scenario-icon ${(SCENARIO_LOOK[s.id] || [])[1] || ""}` }, icon((SCENARIO_LOOK[s.id] || ["play"])[0])),
        h(
          "span",
          { class: "t" },
          s.title,
          h("span", { class: `tag ${s.id === "cloudflare" ? "tag-real" : ""}`, text: s.id === "cloudflare" ? "real" : s.recommended_mode }),
        ),
        h("span", { class: "d", text: s.description }),
        s.available
          ? null
          : h("span", { class: "d unavailable", text: `Needs the ${upstreamsOf(s.missing_tools)} upstream` }),
      ),
    ),
  );
}

function upstreamsOf(tools) {
  return [...new Set(tools.map((t) => t.split("__")[0]))].join(", ");
}

function chooseScenario(id) {
  const s = state.scenarios.find((x) => x.id === id);
  if (!s) return;
  state.scenarioId = id;
  $("task").value = s.task;
  $("dataset").value = s.dataset;
  $("subject").value = s.subject;
  $("mode").value = s.recommended_mode === "live" && state.config.claude_available ? "live" : "replay";
  renderScenarioButtons();
  updateModeHint();
}

function renderDatasets() {
  $("dataset").replaceChildren(
    ...state.datasets.map((d) => h("option", { value: d.id, title: d.description, text: d.id })),
  );
}

function updateModeHint() {
  const mode = $("mode").value;
  const c = state.config;
  const scenario = state.scenarios.find((x) => x.id === state.scenarioId);
  const hints = {
    live: c.claude_available
      ? `Live: the real Claude (${c.claude_model}) decides every action itself, so results can differ from run to run.` +
        (scenario && scenario.recommended_mode === "replay"
          ? " Heads up: a live model usually won't make this scenario's mistake. Use Replay to show it."
          : "")
      : "Claude Code CLI not found on the server; use Replay.",
    replay: state.scenarioId
      ? "Replay: a scripted agent sends fixed requests through the same checks, so the demo is identical every time. These are not the AI's own decisions."
      : "Pick a demo scenario above to replay it.",
    external: "Creates a run token for any MCP agent. You connect the agent yourself.",
  };
  $("mode-hint").textContent = hints[mode];
}

$("mode").addEventListener("change", updateModeHint);
$("task").addEventListener("input", () => {
  const s = state.scenarios.find((x) => x.id === state.scenarioId);
  if (s && $("task").value !== s.task && $("mode").value === "replay") {
    $("mode-hint").textContent = "Replay ignores task edits: the proposals are fixed. Use Live to test a new task.";
  }
});

$("run-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("run-error").textContent = "";
  const mode = $("mode").value;
  if (mode === "replay" && !state.scenarioId) {
    $("run-error").textContent = "Pick a demo scenario to replay.";
    return;
  }
  const body = {
    task: $("task").value,
    mode,
    dataset_id: $("dataset").value,
    subject: $("subject").value,
    enforcement: $("enforcement").value,
    scenario: state.scenarioId,
  };
  const button = $("btn-run");
  button.disabled = true;
  try {
    const created = await api("/api/runs", { method: "POST", body });
    if (created.token) showConnectDialog(created);
    await loadRuns();
    selectRun(created.run.id);
  } catch (err) {
    $("run-error").textContent = String(err.message || err);
  } finally {
    button.disabled = false;
  }
});

function showConnectDialog(created) {
  const text = [
    "Claude Code:",
    `  ${created.claude_command}`,
    "",
    "MCP config JSON:",
    JSON.stringify(created.mcp_config, null, 2),
    "",
    "Only calls to AgentGuard's tools are checked. An agent's own built-in tools",
    "(shell, files, web) bypass AgentGuard unless you disable them.",
  ].join("\n");
  $("connect-text").textContent = text;
  $("connect-dialog").showModal();
}

// ---------------------------------------------------------------- policy

function renderPolicy() {
  const p = state.policy;
  $("policy-meta").textContent =
    `${p.name} · version ${p.version} · anything not allowed is denied · approvals expire after ${p.approval_ttl_seconds}s · ` +
    `limit ${p.limits.max_tool_calls} calls / ${p.limits.max_run_seconds}s`;
  $("policy-rules").replaceChildren(
    ...p.rules.map((r) =>
      h(
        "li",
        { class: r.inactive ? "inactive" : null, title: r.inactive ? "Inactive: its upstream server isn't configured" : null },
        chip(r.inactive ? "Inactive" : EFFECT_LABEL[r.effect], r.inactive ? "chip-neutral" : EFFECT_CHIP[r.effect]),
        h("div", {}, r.description, h("span", { class: "rid", text: r.id })),
      ),
    ),
  );
}

// ---------------------------------------------------------------- runs list

async function loadRuns() {
  state.runs = await api("/api/runs?limit=50");
  renderRunList();
}

function runTitle(run) {
  const s = state.scenarios.find((x) => x.id === run.scenario);
  if (s) return s.title;
  return run.task.length > 60 ? `${run.task.slice(0, 60)}…` : run.task;
}

function displayState(run, metrics) {
  if (run.state === "running" && metrics && metrics.pending_approvals > 0) return "awaiting_approval";
  return run.state;
}

function renderRunList() {
  const list = $("run-list");
  if (!state.runs.length) {
    list.replaceChildren(h("li", { class: "muted", text: "No runs yet." }));
    return;
  }
  list.replaceChildren(
    ...state.runs.map((r) =>
      h(
        "li",
        {},
        h(
          "button",
          {
            type: "button",
            class: "run-item",
            "aria-current": String(r.id === state.runId),
            onclick: () => selectRun(r.id),
          },
          h("span", { class: "top" }, h("span", { class: "title", text: runTitle(r) }), stateChip(displayState(r, r.metrics))),
          h("span", {
            class: "meta",
            text: `${r.mode}${r.enforcement === "shadow" ? " · monitor only" : ""} · ${fmtDateTime(r.created_at)} · ${r.metrics.checked} checked, ${r.metrics.policy_denials + r.metrics.human_denials} blocked`,
          }),
        ),
      ),
    ),
  );
}

// ---------------------------------------------------------------- selected run

function selectRun(runId) {
  if (location.hash !== `#run=${runId}`) history.replaceState(null, "", `#run=${runId}`);
  if (state.runId !== runId) {
    state.runId = runId;
    state.events = [];
    state.lastSeq = 0;
    state.selectedSeq = null;
    $("timeline-list").replaceChildren();
    $("details").replaceChildren(h("p", { class: "muted", text: "Select a timeline entry to see its details." }));
  }
  $("empty-state").hidden = true;
  $("run-view").hidden = false;
  renderRunList();
  loadRun().then(() => startStream(runId));
}

async function loadRun() {
  if (!state.runId) return;
  const runId = state.runId;
  const detail = await api(`/api/runs/${runId}`);
  if (runId !== state.runId) return;
  state.detail = detail;
  state.actions = new Map(detail.actions.map((a) => [a.id, a]));
  renderRun();
}

function scheduleRefresh() {
  clearTimeout(state.refreshTimer);
  state.refreshTimer = setTimeout(() => {
    loadRun().catch(() => {});
    loadRuns().catch(() => {});
  }, 150);
}

function renderRun() {
  const { run, metrics } = state.detail;
  renderModeBadge();
  $("run-title").textContent = runTitle(run);
  const agent = run.agent || {};
  const agentText =
    agent.kind === "claude-code"
      ? `Claude Code ${agent.model || ""}${agent.lockdown_verified ? " · tools locked to AgentGuard" : ""}`
      : agent.kind === "replay"
        ? `Replay script "${agent.script}"`
        : run.mode === "external"
          ? "External MCP agent"
          : "";
  const meta = [
    [agentText, agent.lockdown_verified ? "meta-ok" : ""],
    [run.enforcement === "shadow" ? "MONITOR ONLY: nothing is blocked" : "enforcing", run.enforcement === "shadow" ? "meta-warn" : ""],
    [`subject ${run.subject}`, ""],
    [`dataset ${run.dataset_id}`, ""],
    [`policy ${run.policy_version}`, ""],
    [fmtDateTime(run.created_at), ""],
  ];
  $("run-sub").replaceChildren(
    ...meta.filter(([text]) => text).map(([text, cls]) => h("span", { class: `meta-item ${cls}`, text })),
  );
  $("btn-stop").disabled = TERMINAL.has(run.state);
  $("btn-stop").hidden = !can("admin");

  const shown = displayState(run, metrics);
  const stateEl = $("card-state");
  stateEl.textContent = shown.replace("_", " ");
  stateEl.className = `card-value state-${shown}`;
  if (run.state_reason && TERMINAL.has(run.state)) stateEl.title = run.state_reason;
  $("card-checked").textContent = metrics.checked;
  $("card-blocked").textContent = metrics.policy_denials + metrics.human_denials;
  $("card-blocked-sub").textContent =
    `${metrics.policy_denials} by policy · ${metrics.human_denials} by a human` +
    (metrics.shadow_would_block ? ` · ${metrics.shadow_would_block} would-block (monitor only)` : "");
  $("card-pending").textContent = metrics.pending_approvals;

  renderApprovals();
  renderSummary(run);
  renderTimeline();
  if (state.selectedSeq !== null) renderDetails();
}

$("btn-stop").addEventListener("click", async () => {
  if (!state.runId) return;
  if (!confirm("Stop this run? Pending approvals are cancelled. Actions already executed are not undone.")) return;
  try {
    await api(`/api/runs/${state.runId}/cancel`, { method: "POST" });
  } finally {
    scheduleRefresh();
  }
});

// ---------------------------------------------------------------- approvals

function expectedEffect(action) {
  const a = action.args || {};
  // Built-in tools are mocks; upstream tools (server__tool) act on real systems.
  const upstream = action.tool.includes("__");
  const mock = upstream ? "" : " (mock tool: nothing real changes)";
  if (action.tool === "cloudflare__block_ip")
    return `Creates a real Cloudflare block on ${a.ip} for ${a.duration_minutes} minutes. This changes the live firewall.`;
  if (upstream) return `Calls ${action.tool.replace("__", ": ")} on a real system with the arguments below.`;
  if (action.tool === "block_ip") return `Blocks ${a.ip} at the perimeter firewall for ${a.duration_minutes} minutes${mock}.`;
  if (action.tool === "http_post") return `Sends ${String(a.body || "").length} characters to ${a.url}${mock}.`;
  return `Runs ${action.tool} with the arguments below${mock}.`;
}

function renderApprovals() {
  const box = $("approvals");
  const pending = state.detail.actions.filter((a) => a.state === "pending_approval");
  box.replaceChildren(
    ...pending.map((action) => {
      const decision = action.decision || {};
      const error = h("p", { class: "error", role: "alert" });
      const expires = h("span", { class: "expires", "data-expires": action.approval_expires_at });
      const buttons = [
        h("button", { type: "button", class: "btn btn-approve", text: "Approve once" }),
        h("button", { type: "button", class: "btn btn-deny", text: "Deny" }),
      ];
      const resolve = async (decisionValue) => {
        buttons.forEach((b) => (b.disabled = true));
        try {
          await api(`/api/approvals/${action.id}/resolve`, {
            method: "POST",
            body: { decision: decisionValue, args_hash: action.args_hash },
          });
          announce(decisionValue === "approve" ? "Approved." : "Denied.");
        } catch (err) {
          error.textContent = String(err.message || err);
          buttons.forEach((b) => (b.disabled = false));
        } finally {
          scheduleRefresh();
        }
      };
      buttons[0].addEventListener("click", () => resolve("approve"));
      buttons[1].addEventListener("click", () => resolve("deny"));
      if (!state.announced.has(action.id)) {
        state.announced.add(action.id);
        announce(`Approval needed for ${action.tool}.`);
      }
      return h(
        "section",
        { class: "panel approval", "aria-label": `Approval needed for ${action.tool}` },
        h("h3", { text: `Approval needed: ${action.tool}` }),
        h("p", { class: "effect", text: expectedEffect(action) }),
        h(
          "dl",
          {},
          Object.entries(action.args || {}).flatMap(([k, v]) => [
            h("dt", { text: k }),
            h("dd", { text: typeof v === "string" ? v : JSON.stringify(v) }),
          ]),
        ),
        h("p", { class: "muted small", text: `${decision.explanation || ""} (${(decision.rule_ids || []).join(", ")})` }),
        can("approver")
          ? h("div", { class: "actions" }, ...buttons, expires)
          : h("div", { class: "actions" }, h("span", { class: "muted", text: "Waiting for an approver. " }), expires),
        error,
      );
    }),
  );
  tickCountdowns();
}

function tickCountdowns() {
  for (const el of document.querySelectorAll("[data-expires]")) {
    const left = Math.max(0, Math.round((new Date(el.dataset.expires) - Date.now()) / 1000));
    el.textContent = left > 0 ? `expires in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}` : "expired";
  }
}
setInterval(tickCountdowns, 1000);

// ---------------------------------------------------------------- summary

function renderSummary(run) {
  const panel = $("summary-panel");
  const actions = state.detail ? state.detail.actions : [];
  if (!run.summary && !TERMINAL.has(run.state)) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  $("outcome-list").replaceChildren(
    ...(actions.length
      ? actions.map((a) => {
          const st = actionStatus(a);
          return h("li", {}, chip(st.label, st.tone), " ", actionTitle(a));
        })
      : [h("li", { class: "muted", text: "The agent took no actions." })]),
  );
  const reportParts = run.summary ? renderMarkdownLite(run.summary) : [h("p", { class: "muted", text: "The agent did not write a report." })];
  $("summary-text").replaceChildren(...reportParts);
  const check = run.summary_check || { cited: [], unknown: [], not_seen_by_agent: [] };
  const chips = [];
  if (check.cited.length) chips.push(chip(`Cites ${check.cited.length} log entries`));
  if (check.unknown.length) chips.push(chip(`Cites entries that don't exist: ${check.unknown.join(", ")}`, "chip-bad"));
  if (check.not_seen_by_agent.length)
    chips.push(chip(`Cites entries it was never shown: ${check.not_seen_by_agent.join(", ")}`, "chip-warn"));
  if (!check.unknown.length && !check.not_seen_by_agent.length && check.cited.length)
    chips.push(chip("All cited evidence checked: real, and seen by the agent", "chip-ok"));
  $("summary-check").replaceChildren(...chips);
}

// A tiny, safe formatter for the agent's report: headings, lists, **bold**, `code`.
// Builds DOM nodes directly; nothing is parsed as HTML.
function inlineMarkdown(text) {
  const out = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let last = 0;
  let m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const t = m[0];
    out.push(t.startsWith("**") ? h("strong", { text: t.slice(2, -2) }) : h("code", { text: t.slice(1, -1) }));
    last = m.index + t.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function renderMarkdownLite(text) {
  const blocks = [];
  let list = null;
  let listType = null;
  for (const raw of String(text).split("\n")) {
    const line = raw.trimEnd();
    if (!line.trim()) {
      list = null;
      continue;
    }
    const heading = line.match(/^#{1,6}\s+(.*)$/);
    const bullet = line.match(/^\s*[-*•]\s+(.*)$/);
    const numbered = line.match(/^\s*(\d+)[.)]\s+(.*)$/);
    const indent = raw.length - raw.trimStart().length;
    if (heading) {
      list = null;
      blocks.push(h("h4", { class: "md-h" }, ...inlineMarkdown(heading[1])));
    } else if (bullet || numbered) {
      const type = bullet ? "ul" : "ol";
      const item = h("li", {}, ...inlineMarkdown(bullet ? bullet[1] : numbered[2]));
      // Indented items nest under the previous item ("1. Do this:" then "   - detail").
      if (indent >= 2 && list && list.lastElementChild) {
        let sub = list.lastElementChild.querySelector(":scope > .md-list");
        if (!sub) {
          sub = h(type, { class: "md-list" });
          list.lastElementChild.append(sub);
        }
        sub.append(item);
        continue;
      }
      if (!list || listType !== type) {
        // A numbered list resumed after other content keeps its numbering.
        list = h(type, { class: "md-list", start: numbered && numbered[1] !== "1" ? numbered[1] : null });
        listType = type;
        blocks.push(list);
      }
      list.append(item);
    } else {
      list = null;
      blocks.push(h("p", { class: "md-p" }, ...inlineMarkdown(line)));
    }
  }
  return blocks;
}

// ---------------------------------------------------------------- plain-language actions

function actionTitle(action) {
  const a = action.args || action.raw_args || {};
  switch (action.tool) {
    case "get_user_logins":
      return `Read ${a.user ?? "a user"}'s login history`;
    case "get_ip_activity":
      return `Look up what ${a.ip ?? "an address"} did`;
    case "block_ip":
      return `Block ${a.ip ?? "an address"} at the firewall for ${a.duration_minutes ?? "?"} minutes`;
    case "http_post": {
      let host = String(a.url ?? "somewhere");
      try {
        host = new URL(a.url).host;
      } catch {
        /* keep the raw value */
      }
      return `Send data to ${host}`;
    }
    case "cloudflare__block_ip":
      return `Block ${a.ip ?? "an address"} at Cloudflare for ${a.duration_minutes ?? "?"} minutes (real firewall)`;
    case "cloudflare__unblock_ip":
      return `Remove the Cloudflare block on ${a.ip ?? "an address"}`;
    case "cloudflare__list_blocks":
      return "List AgentGuard's Cloudflare blocks";
    default: {
      const [server, tool] = action.tool.includes("__") ? action.tool.split("__", 2) : [null, action.tool];
      return server ? `${server}: ${tool.replaceAll("_", " ")}` : `Use ${action.tool}`;
    }
  }
}

function actionStatus(action) {
  const why = (action.decision && action.decision.explanation) || "";
  if (action.shadow_effect)
    return { label: "Would block", tone: "chip-warn", why: `Monitor only, so it ran anyway. Would have been stopped: ${why}` };
  switch (action.state) {
    case "succeeded":
      return action.approver
        ? { label: "Approved · done", tone: "chip-ok", why: `You (${action.approver}) approved it, then AgentGuard carried it out.` }
        : { label: "Allowed · done", tone: "chip-ok", why };
    case "denied":
      return { label: "Blocked", tone: "chip-bad", why: `${why} Not executed.` };
    case "pending_approval":
      return { label: "Waiting for you", tone: "chip-warn", why: `${why} Nothing happens until you decide.` };
    case "rejected":
      return { label: "Declined", tone: "chip-bad", why: `You (${action.approver}) declined it. Not executed.` };
    case "expired":
      return { label: "Expired", tone: "chip-bad", why: "Nobody decided in time. Not executed." };
    case "cancelled":
      return { label: "Cancelled", tone: "chip-neutral", why: "The run was stopped first. Not executed." };
    case "invalidated":
      return { label: "Cancelled", tone: "chip-neutral", why: "The rules changed while it waited. Not executed." };
    case "failed":
      return { label: "Failed", tone: "chip-bad", why: action.error || "The tool reported an error." };
    default:
      return { label: "Checking…", tone: "chip-neutral", why: "" };
  }
}

// ---------------------------------------------------------------- timeline

function describe(ev) {
  const p = ev.payload || {};
  switch (ev.type) {
    case "run.created":
      return {
        label: "Run created",
        tone: "chip-neutral",
        text: `${p.mode} · dataset ${p.dataset_id} · subject ${p.subject}${p.enforcement === "shadow" ? " · monitor only" : ""}`,
      };
    case "agent.launching":
      return { label: "Launching", tone: "chip-neutral", text: `Claude Code (${p.model})` };
    case "run.started": {
      const a = p.agent || {};
      const text =
        a.kind === "claude-code"
          ? `Claude (${a.model || "AI agent"}) started. Its only way to act is through AgentGuard.`
          : a.kind === "replay"
            ? "Scripted replay started. Every step goes through the same checks as a live agent."
            : "Agent connected through AgentGuard.";
      return { label: "Started", tone: "chip-info", text };
    }
    case "agent.lockdown_failed":
      return { label: "Lockdown failed", tone: "chip-bad", text: (p.problems || []).join("; ") };
    case "agent.message": {
      const text = String(p.text || "");
      return { label: "Agent says", tone: "chip-neutral", text: text.length > 240 ? `${text.slice(0, 240)}… (select for full text)` : text, agent: true };
    }
    case "tool.proposed":
      return { label: "Proposed", tone: "chip-neutral", text: p.tool, tool: true, sub: shortArgs(p.args) };
    case "policy.evaluated": {
      if (p.enforced === false)
        return {
          label: "Would block",
          tone: "chip-warn",
          text: p.tool,
          tool: true,
          sub: `monitor only, ran anyway: ${p.explanation}`,
        };
      const label = { allow: "Allowed", deny: "Blocked", require_approval: "Needs approval" }[p.effect];
      return { label, tone: EFFECT_CHIP[p.effect], text: p.tool, tool: true, sub: p.explanation };
    }
    case "shadow.would_block":
      return { label: "Monitor only", tone: "chip-warn", text: p.tool, tool: true, sub: `would ${p.would}: ${(p.rule_ids || []).join(", ")}` };
    case "approval.requested":
      return { label: "Waiting for you", tone: "chip-warn", text: p.tool, tool: true, sub: `until ${fmtTime(p.expires_at)}` };
    case "approval.resolved":
      return p.decision === "approve"
        ? { label: "Approved", tone: "chip-ok", text: `by ${p.approver}` }
        : { label: "Declined", tone: "chip-bad", text: `by ${p.approver}${p.note ? `: ${p.note}` : ""}` };
    case "approval.expired":
      return { label: "Expired", tone: "chip-bad", text: "No decision in time; not executed" };
    case "approval.cancelled":
      return { label: "Cancelled", tone: "chip-neutral", text: p.reason || "" };
    case "approval.invalidated":
      return { label: "Invalidated", tone: "chip-bad", text: "Policy changed; not executed" };
    case "tool.executed": {
      const red = p.redactions && Object.keys(p.redactions).length ? " · secrets redacted" : "";
      return { label: "Executed", tone: "chip-ok", text: p.tool, tool: true, sub: `${state.config.tools_mode} tool${red}` };
    }
    case "tool.failed":
      return { label: "Tool failed", tone: "chip-bad", text: p.tool || "", tool: true, sub: p.error };
    case "tool.cancelled":
      return { label: "Not run", tone: "chip-neutral", text: p.reason || "" };
    case "result.flagged":
      return { label: "Suspicious text", tone: "chip-warn", text: p.reason, sub: (p.snippets || [])[0] };
    case "agent.finished":
      return {
        label: "Agent finished",
        tone: "chip-neutral",
        text: `${p.num_turns ?? "?"} turns${p.total_cost_usd != null ? ` · $${Number(p.total_cost_usd).toFixed(3)} API-equivalent` : ""}`,
      };
    case "agent.summary":
      return { label: "Summary", tone: "chip-neutral", text: "Agent wrote a summary after the run stopped" };
    case "run.completed":
      return { label: "Run completed", tone: "chip-ok", text: "The agent finished. See “What happened” below." };
    case "run.halted":
      return { label: "Run halted", tone: "chip-bad", text: p.reason };
    case "run.cancelled":
      return { label: "Run stopped", tone: "chip-neutral", text: `${p.reason}${p.actor ? ` (${p.actor})` : ""}` };
    case "run.failed":
      return { label: "Run failed", tone: "chip-bad", text: p.reason };
    case "notify.sent":
      return { label: "Alert sent", tone: "chip-neutral", text: `Webhook alert for ${p.event}` };
    case "notify.failed":
      return { label: "Alert failed", tone: "chip-warn", text: `Webhook alert for ${p.event}: ${p.error}` };
    default:
      return { label: ev.type, tone: "chip-neutral", text: "" };
  }
}

function timelineItem(ev) {
  const d = describe(ev);
  const text = h("span", { class: "tl-text" });
  if (d.tool) text.append(h("span", { class: "tool", text: d.text }));
  else text.append(d.text || "");
  if (d.sub) text.append(d.tool ? " — " : " · ", d.sub);
  return h(
    "li",
    { class: d.agent ? "tl-agent" : "" },
    h(
      "button",
      {
        type: "button",
        class: "tl-item",
        "data-seq": ev.seq,
        "aria-current": String(ev.seq === state.selectedSeq),
        onclick: () => selectEvent(ev.seq),
      },
      h("span", { class: "tl-time", text: fmtTime(ev.ts) }),
      h("span", { class: `tl-dot ${toneOf(chip("", d.tone))}` }),
      h("span", { class: "tl-body" }, chip(d.label, d.tone), text),
    ),
  );
}

const STORY_HIDDEN = new Set(["run.created", "agent.launching", "agent.finished", "agent.summary"]);

function storyRow(key, ts, chipEl, title, lines, extraClass = "") {
  return h(
    "li",
    { class: extraClass },
    h(
      "button",
      {
        type: "button",
        class: "tl-item",
        "data-seq": key,
        "aria-current": String(key === state.selectedSeq),
        onclick: () => selectEvent(key),
      },
      h("span", { class: "tl-time", text: fmtTime(ts) }),
      h("span", { class: `tl-dot ${toneOf(chipEl)}` }),
      h(
        "span",
        { class: "tl-body" },
        chipEl,
        h("span", { class: "tl-text" }, h("span", { class: "tl-title" }, title), ...lines.filter(Boolean).map((l) => h("span", { class: "tl-sub", text: l }))),
      ),
    ),
  );
}

function storyItems() {
  const items = [];
  const seenActions = new Set();
  const flagged = new Set(state.events.filter((e) => e.type === "result.flagged").map((e) => e.action_id));
  const redacted = new Set(
    state.events
      .filter((e) => e.type === "tool.executed" && e.payload.redactions && Object.keys(e.payload.redactions).length)
      .map((e) => e.action_id),
  );
  const alerts = new Map(
    state.events.filter((e) => e.type.startsWith("notify.") && e.action_id).map((e) => [e.action_id, e.type]),
  );
  const summary = state.detail && state.detail.run.summary ? state.detail.run.summary.trim() : null;
  for (const ev of state.events) {
    if (ev.action_id) {
      if (seenActions.has(ev.action_id)) continue;
      seenActions.add(ev.action_id);
      const action =
        state.actions.get(ev.action_id) ||
        { tool: ev.payload.tool, args: ev.payload.args, state: "proposed", decision: null };
      const st = actionStatus(action);
      const lines = [st.why];
      if (flagged.has(ev.action_id)) lines.push("⚠ Suspicious text: the result contains text that looks like instructions to the AI.");
      if (redacted.has(ev.action_id)) lines.push("Secrets in the result were hidden from the AI.");
      if (alerts.get(ev.action_id) === "notify.sent") lines.push("An alert was sent to your webhook.");
      if (alerts.get(ev.action_id) === "notify.failed") lines.push("⚠ The webhook alert could not be delivered.");
      items.push(storyRow(ev.seq, ev.ts, chip(st.label, st.tone), actionTitle(action), lines));
      continue;
    }
    if (STORY_HIDDEN.has(ev.type)) continue;
    if (ev.type === "agent.message") {
      const text = String(ev.payload.text || "").trim();
      if (summary && text === summary) continue; // shown in the report below
      const short = text.length > 200 ? `${text.slice(0, 200)}…` : text;
      items.push(storyRow(ev.seq, ev.ts, chip("Agent", "chip-neutral"), `“${short}”`, [], "tl-agent"));
      continue;
    }
    const d = describe(ev);
    items.push(storyRow(ev.seq, ev.ts, chip(d.label, d.tone), d.text || "", d.sub ? [d.sub] : []));
  }
  return items;
}

function renderTimeline() {
  if (state.showAll) {
    $("timeline-list").replaceChildren(...state.events.map(timelineItem));
  } else {
    $("timeline-list").replaceChildren(...storyItems());
  }
}

// Desktop notification for a new approval request while the tab is in the background.
function desktopAlert(ev) {
  if (!("Notification" in window) || Notification.permission !== "granted" || !document.hidden) return;
  if (Date.now() - Date.parse(ev.ts) > 60_000) return; // history replayed on reconnect
  const n = new Notification("AgentGuard needs a decision", {
    body: `${ev.payload.tool}(${shortArgs(ev.payload.args)})`,
    tag: ev.action_id,
  });
  n.onclick = () => window.focus();
}

function renderAlertsButton() {
  const btn = $("btn-alerts");
  if (!("Notification" in window)) {
    btn.hidden = true;
    return;
  }
  const on = Notification.permission === "granted";
  btn.querySelector("span").textContent = on
    ? "Desktop alerts on"
    : Notification.permission === "denied"
      ? "Alerts blocked"
      : "Enable desktop alerts";
  btn.disabled = Notification.permission !== "default";
}

function appendEvent(ev) {
  state.events.push(ev);
  state.lastSeq = ev.seq;
  renderTimeline();
  if (ev.type === "approval.requested") {
    announce(`Approval needed: ${ev.payload.tool}.`);
    desktopAlert(ev);
  }
  if (ev.type.startsWith("run.") && TERMINAL.has(ev.type.slice(4))) announce(describe(ev).label);
}

$("show-all").addEventListener("change", (ev) => {
  state.showAll = ev.target.checked;
  renderTimeline();
});

$("timeline-list").addEventListener("keydown", (ev) => {
  if (ev.key !== "ArrowDown" && ev.key !== "ArrowUp") return;
  const items = [...$("timeline-list").querySelectorAll(".tl-item")];
  const i = items.indexOf(document.activeElement);
  const next = items[ev.key === "ArrowDown" ? Math.min(items.length - 1, i + 1) : Math.max(0, i - 1)];
  if (next) {
    ev.preventDefault();
    next.focus();
    next.click();
  }
});

// ---------------------------------------------------------------- details

function selectEvent(seq) {
  state.selectedSeq = seq;
  showTab("details");
  for (const el of document.querySelectorAll(".tl-item")) {
    el.setAttribute("aria-current", String(Number(el.dataset.seq) === seq));
  }
  renderDetails();
}

function dl(pairs) {
  return h(
    "dl",
    {},
    pairs.filter(([, v]) => v !== null && v !== undefined && v !== "").flatMap(([k, v]) => [
      h("dt", { text: k }),
      h("dd", {}, v instanceof Node ? v : String(v)),
    ]),
  );
}

function ruleBlock(hit, overridden) {
  return h(
    "div",
    { class: `rule ${hit.effect}${overridden ? " overridden" : ""}` },
    h("strong", { text: hit.rule_id }),
    " ",
    chip(overridden ? `${EFFECT_LABEL[hit.effect]} (overridden)` : EFFECT_LABEL[hit.effect], EFFECT_CHIP[hit.effect]),
    h("div", { text: hit.description }),
  );
}

function actionDetails(action) {
  const parts = [];
  const decision = action.decision;
  parts.push(
    h("h3", { text: "Proposed call" }),
    dl([
      ["Tool", h("code", { text: action.tool })],
      ["State", chip(action.state.replace("_", " "), ACTION_STATE_CHIP[action.state] || "chip-neutral")],
      ["Action", h("code", { text: action.id })],
      ["Proposed", fmtDateTime(action.created_at)],
      ["Args hash", action.args_hash ? h("code", { text: action.args_hash.slice(0, 23) + "…" }) : null],
    ]),
    h("pre", { text: pretty(action.args ?? action.raw_args) }),
  );
  if (decision) {
    const decisiveIds = new Set(decision.rule_ids);
    parts.push(
      h("h3", { text: "Decision" }),
      dl([
        ["Effect", chip(EFFECT_LABEL[decision.effect], EFFECT_CHIP[decision.effect])],
        ["Decided by", { builtin: "built-in check", policy: "policy rules", reviewer: "reviewer escalation" }[decision.source]],
        ["Policy", action.policy_version],
        ["Enforced", action.enforced ? "yes" : `no: monitor only (would ${action.shadow_effect})`],
      ]),
      ...decision.decisive.map((hit) => ruleBlock(hit, false)),
      ...decision.matched.filter((hit) => !decisiveIds.has(hit.rule_id)).map((hit) => ruleBlock(hit, true)),
    );
    if (decision.review) parts.push(h("h3", { text: "Reviewer" }), h("pre", { text: pretty(decision.review) }));
  }
  if (action.approval_expires_at) {
    parts.push(
      h("h3", { text: "Human approval" }),
      dl([
        ["Expected effect", expectedEffect(action)],
        ["Expires", fmtDateTime(action.approval_expires_at)],
        ["Resolved by", action.approver],
        ["Resolved", action.approval_resolved_at ? fmtDateTime(action.approval_resolved_at) : null],
        ["Note", action.approval_note],
      ]),
    );
  }
  parts.push(h("h3", { text: "Execution" }));
  if (action.exec_started_at) {
    parts.push(
      dl([
        ["Started", fmtDateTime(action.exec_started_at)],
        ["Finished", action.exec_finished_at ? fmtDateTime(action.exec_finished_at) : null],
        ["Error", action.error],
      ]),
    );
    if (action.result !== null && action.result !== undefined) parts.push(h("pre", { text: pretty(action.result) }));
  } else {
    parts.push(h("p", { class: "muted", text: action.error ? `Not executed: ${action.error}` : "Not executed." }));
  }
  return parts;
}

function renderDetails() {
  const ev = state.events.find((e) => e.seq === state.selectedSeq);
  const box = $("details");
  if (!ev) return;
  const d = describe(ev);
  const parts = [h("p", {}, chip(d.label, d.tone), " ", h("span", { class: "muted", text: fmtDateTime(ev.ts) }))];
  const action = ev.action_id ? state.actions.get(ev.action_id) : null;
  if (action) parts.push(...actionDetails(action));
  else if (ev.type === "agent.message") parts.push(h("pre", { text: ev.payload.text }));
  else parts.push(h("pre", { text: pretty(ev.payload) }));
  parts.push(h("details", {}, h("summary", { text: "Raw audit event" }), h("pre", { text: pretty(ev) })));
  box.replaceChildren(...parts);
}

// ---------------------------------------------------------------- live events (SSE over fetch)

function stopStream() {
  if (state.stream) state.stream.ctrl.abort();
  state.stream = null;
}

// The stream stays open after a run ends: late events (for example the agent's own
// summary after an operator stops a run) still arrive.
async function startStream(runId, attempt = 0) {
  stopStream();
  const ctrl = new AbortController();
  state.stream = { ctrl, runId };
  try {
    const res = await fetch(`/api/runs/${runId}/events?after=${state.lastSeq}`, {
      headers: { ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}), Accept: "text/event-stream" },
      signal: ctrl.signal,
    });
    if (res.status === 401) return logout("The operator token was rejected.");
    if (!res.ok || !res.body) throw new Error(`stream failed: ${res.status}`);
    setConnection("live");
    attempt = 0;
    const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
    let buffer = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += value;
      let cut;
      while ((cut = buffer.indexOf("\n\n")) >= 0) {
        const block = buffer.slice(0, cut);
        buffer = buffer.slice(cut + 2);
        const data = block
          .split("\n")
          .filter((line) => line.startsWith("data: "))
          .map((line) => line.slice(6))
          .join("\n");
        if (!data) continue;
        const ev = JSON.parse(data);
        if (ev.run_id !== state.runId || ev.seq <= state.lastSeq) continue;
        appendEvent(ev);
        scheduleRefresh();
      }
    }
  } catch (err) {
    if (ctrl.signal.aborted) return;
  }
  if (ctrl.signal.aborted || (state.stream && state.stream.ctrl !== ctrl)) return;
  if (state.runId !== runId) return;
  setConnection("retry");
  const delay = Math.min(10000, 500 * 2 ** attempt);
  setTimeout(() => {
    if (state.runId === runId) startStream(runId, attempt + 1);
  }, delay);
}

// ---------------------------------------------------------------- start

setInterval(() => {
  if (!$("app").hidden) loadRuns().catch(() => {});
}, 5000);

// With a saved token, use it. Without one, a single sign-on proxy may already have
// signed us in; otherwise show the token form.
async function start() {
  if (!state.token) {
    const session = await (await fetch("/api/session")).json();
    if (!session.user) {
      logout(session.message);
      return;
    }
  }
  await boot();
}
start().catch((err) => {
  if (!(err instanceof ApiError && err.status === 401)) logout(String(err.message || err));
});
