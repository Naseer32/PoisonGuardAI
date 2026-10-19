// PoisonGuardAI frontend controller. Plain ES modules, no build step.
// createApp(env) takes its browser dependencies as arguments so the same code runs in tests with fakes.
import schema from "./lib/contract-schema.js";
import { resolveConfig, explorerTxLink } from "./lib/config.js";
import { makeH, clear } from "./lib/ui.js";
import { validateRegister, validateEvidence, validateStatusChange, idError } from "./lib/validate.js";
import { outcomeMeta, scoreView, qualityTone, allowedTransitions, checklist, verifyAfter, shortHash, formatTime } from "./lib/model.js";
import { classifyError, classifyOutcome, extractTx, pollTx } from "./lib/tx.js";
import { loadSdk, describeSdk, resolveChain, makeReadClient, connectWallet, readView, sendWrite, fetchTransaction } from "./lib/genlayer.js";
import { createStore } from "./lib/store.js";
import { DEMO_ASSESSMENTS } from "./lib/demo.js";
import { sha256Blob } from "./lib/sha256.js";
import { safeJson } from "./lib/normalize.js";

const TABS = [["register", "Register"], ["evidence", "Evidence"], ["results", "Results"], ["history", "History"], ["activity", "Activity"]];
const EVIDENCE_HELP = {
  PROVENANCE_RECORD: "Where the data came from, how it was collected, who held it.",
  LABEL_AUDIT: "Audit of a random sample and high-risk subsets of labels.",
  FEATURE_ANALYSIS: "Repeated or near-duplicate features and how they relate to labels.",
  TRIGGER_TEST: "Model behavior on inputs WITH the candidate trigger. Needs trials, hits and a method.",
  CONTROL_TEST: "The same inputs WITHOUT the trigger. Needs trials, hits and a method.",
  CLEAN_BASELINE: "A model trained on trusted clean data. Method required; counts optional.",
  REPRODUCTION: "An independent second party repeated the test. Method required.",
  OTHER: "Anything else relevant. Usually best marked as allegation if unverified.",
};

export function createApp(env) {
  const { doc, storage, importer, now = Date.now } = env;
  const h = makeH(doc);
  const cfg = resolveConfig(env.rawConfig);
  const s = {
    cfg, mode: cfg.configured ? "live" : "demo", tab: "register",
    sdk: null, chain: null, readClient: null, wallet: null, ready: false, initError: null, initializing: false,
    count: null, countError: null,
    current: { id: "", data: null, error: null, loading: false },
    summaries: {}, lookup: "", busy: false, toast: null, hashProgress: null,
    regForm: { assessment_id: "", dataset_name: "", dataset_version: "", content_hash: "", provenance: "", model_name: "", model_version: "" },
    evForm: { assessment_id: "", evidence_type: "PROVENANCE_RECORD", nature: "OBSERVATION", summary: "", method: "", trials: "", hits: "" },
    evTarget: { id: "", data: null, error: null, loading: false },
    showErrors: { reg: false, ev: false },
    txs: [], history: [],
  };
  let store = null;
  const els = {};

  // ---------- small components
  const chip = (text, tone = "neutral") => h("span", { class: "chip tone-" + tone }, text);
  const kv = (k, v) => h("div", { class: "kv" }, h("span", { class: "k" }, k), h("span", { class: "v" }, v));
  const copyBtn = (text, label = "Copy") =>
    h("button", { type: "button", class: "btn small", onClick: async (ev) => {
      try { await env.win.navigator.clipboard.writeText(text); ev.target.textContent = "Copied"; } catch { ev.target.textContent = "Copy failed"; }
    } }, label);
  const list = (items, empty) => items && items.length
    ? h("ul", { class: "list" }, items.map((x) => h("li", {}, x)))
    : h("p", { class: "muted" }, empty);
  const section = (title, ...kids) => h("section", { class: "card" }, h("h2", {}, title), ...kids);
  const isDemo = () => s.mode === "demo";
  const canWrite = () => s.mode === "live" && s.cfg.configured && s.ready && s.wallet && s.wallet.chainMatches;

  function field({ label, name, type = "text", value, error, hint, area, rows = 3, attrs = {}, onInput, onChange, maxLen }) {
    const id = "f-" + name;
    const input = area
      ? h("textarea", { id, name, rows, value, ...attrs, onInput: (e) => { onInput && onInput(e.target.value, e); counter && (counter.textContent = e.target.value.length + "/" + maxLen); }, onChange: (e) => onChange && onChange(e.target.value) })
      : h("input", { id, name, type, value, ...attrs, onInput: (e) => onInput && onInput(e.target.value, e), onChange: (e) => onChange && onChange(e.target.value) });
    const counter = maxLen ? h("span", { class: "count" }, String((value || "").length) + "/" + maxLen) : null;
    return h("div", { class: "field" }, h("label", { for: id }, label, counter), input,
      hint ? h("div", { class: "hint" }, hint) : null, h("div", { class: "err", "data-err": name, role: "alert" }, error || ""));
  }
  const showErr = (form, errors) => {
    for (const el of els.content.querySelectorAll ? Array.from(els.content.querySelectorAll("[data-err]")) : []) el.textContent = errors[el.getAttribute("data-err")] || "";
  };

  // ---------- toast
  function toast(kind, title, detail) { s.toast = { kind, title, detail }; renderToast(); }
  function renderToast() {
    clear(els.toast);
    if (!s.toast) return;
    els.toast.appendChild(h("div", { class: "toast tone-" + s.toast.kind, role: "status" },
      h("strong", {}, s.toast.title), s.toast.detail ? h("div", { class: "small" }, s.toast.detail) : null,
      h("button", { type: "button", class: "btn small", onClick: () => { s.toast = null; renderToast(); } }, "Dismiss")));
  }

  // ---------- live initialization
  async function initLive() {
    if (!s.cfg.configured || s.ready || s.initializing) return;
    s.initializing = true; s.initError = null; renderOverview();
    try {
      s.sdk = await loadSdk(s.cfg, importer);
      s.chain = resolveChain(s.sdk, s.cfg);
      s.readClient = makeReadClient(s.sdk, s.cfg, s.chain);
      store = createStore(storage, s.cfg.chainKey + ":" + s.cfg.contractAddress.toLowerCase());
      s.history = store.history(); s.txs = store.txs();
      s.ready = true;
      await refreshCount();
    } catch (e) {
      s.initError = classifyError(e).kind === "UNKNOWN" || e.name === "AppError" ? (e.message || String(e)) : classifyError(e).title + ": " + (e.message || e);
    } finally { s.initializing = false; renderAll(); }
  }

  async function refreshCount() {
    try { s.count = await readView(s.readClient, s.cfg, "get_dataset_count"); s.countError = null; }
    catch (e) { s.count = null; s.countError = classifyError(e).title + ": " + (e.message || e); }
  }

  async function connect() {
    try {
      s.wallet = await connectWallet(s.sdk, s.cfg, s.chain, env.eth);
      toast(s.wallet.chainMatches ? "good" : "warn", "Wallet connected", s.wallet.chainMatches ? s.wallet.account : "Wallet is on chain " + s.wallet.walletChainId + " but the app expects " + s.chain.id + ". Switch network in your wallet.");
    } catch (e) {
      const c = e && e.name === "AppError" ? { title: e.message, detail: "" } : classifyError(e);
      toast("bad", c.title, c.detail);
    }
    renderOverview(); renderTab();
  }

  // ---------- reads
  async function loadAssessment(id, target) {
    const err = idError(id);
    target.id = id; target.error = err || null; target.data = null;
    if (err) { target.loading = false; return; }
    if (isDemo()) {
      target.data = DEMO_ASSESSMENTS.find((d) => d.assessment_id === id) || null;
      target.error = target.data ? null : "No demo assessment with that ID (try DEMO-clean, DEMO-suspicious, DEMO-inconclusive).";
      return;
    }
    if (!s.ready) { target.error = "Not connected to the network yet."; return; }
    target.loading = true;
    try {
      target.data = await readView(s.readClient, s.cfg, "get_assessment", [id]);
      if (store && s.mode === "live") { store.addHistory(id, "lookup"); s.history = store.history(); }
    } catch (e) {
      const c = classifyError(e);
      target.error = /unknown assessment_id/i.test(String(e && e.message)) ? "Not found on-chain: no assessment with this ID exists on this contract." : c.title + ": " + c.detail;
    } finally { target.loading = false; }
  }

  async function loadSummary(id) {
    if (isDemo()) { s.summaries[id] = { data: DEMO_ASSESSMENTS.find((d) => d.assessment_id === id) || null }; return; }
    try { s.summaries[id] = { data: await readView(s.readClient, s.cfg, "get_risk_summary", [id]) }; }
    catch (e) { s.summaries[id] = { error: /unknown assessment_id/i.test(String(e && e.message)) ? "Not found on-chain (yet)" : classifyError(e).title }; }
  }

  // ---------- writes
  function recordTx(rec) { if (!store) return null; const id = store.addTx(rec); s.txs = store.txs(); return id; }
  function patchTx(id, patch) { if (store && id) { store.updateTx(id, patch); s.txs = store.txs(); } if (s.tab === "activity") renderTab(); }

  async function doWrite(method, args, label, assessmentId) {
    if (s.busy) return;
    if (!canWrite()) { toast("warn", "Connect a wallet on the right network first"); return; }
    s.busy = true; renderTab();
    let before = null;
    try { before = await readView(s.readClient, s.cfg, "get_assessment", [assessmentId]); } catch { before = null; }
    let hash;
    try {
      hash = await sendWrite(s.wallet, s.cfg, method, args);
    } catch (e) {
      const c = e && e.name === "AppError" ? { kind: "APP", title: e.message, detail: "", sent: false } : classifyError(e);
      recordTx({ hash: null, method, label, error: c, outcome: { kind: "not_sent", label: c.sent === false ? "Not sent" : "Send failed; may or may not have been sent" } });
      toast(c.kind === "USER_REJECTED" ? "warn" : "bad", c.title, c.detail);
      s.busy = false; renderAll(); return;
    }
    const txId = recordTx({ hash, method, label, outcome: { kind: "pending", label: "Submitted; waiting for the network" } });
    if (method === "register_dataset" && store) { store.addHistory(assessmentId, "registered"); s.history = store.history(); }
    toast("neutral", "Transaction submitted", "Hash " + shortHash(hash) + ". Status below is read from the chain, not assumed.");
    s.busy = false; renderAll();
    const result = await pollTx({
      fetchTx: () => fetchTransaction(s.readClient, hash),
      onUpdate: ({ info, outcome, error }) => patchTx(txId, error
        ? { lastError: error, lastChecked: now() }
        : { status: info.status, statusCode: info.statusCode, consensus: info.consensusResult, execution: info.execution, outcome, lastChecked: now(), lastError: null }),
    });
    const o = result.info ? classifyOutcome(result.info) : null;
    if (o && (o.kind === "accepted_ok" || o.kind === "accepted_unverified" || o.kind === "finalized_ok" || o.kind === "finalized_unverified")) {
      try {
        const after = await readView(s.readClient, s.cfg, "get_assessment", [assessmentId]);
        const verdict = verifyAfter(method, args, before, after);
        patchTx(txId, { verify: verdict });
        if (s.current.id === assessmentId) s.current.data = after;
        if (s.evTarget.id === assessmentId) s.evTarget.data = after;
        s.summaries[assessmentId] = { data: after };
        toast(verdict.ok ? "good" : "warn", o.label, verdict.msg);
      } catch (e) {
        patchTx(txId, { verify: { ok: false, msg: "Read-back failed: " + classifyError(e).title } });
        toast("warn", o.label, "Could not read state back to confirm.");
      }
    } else if (o) {
      toast(o.tone === "bad" ? "bad" : "warn", o.label, result.stopped === "timeout" ? "Stopped waiting. Use Refresh status in Activity." : "");
    } else {
      toast("warn", "Status unavailable", "Stopped polling (" + result.stopped + "). Use Refresh status in Activity.");
    }
    await refreshCount();
    renderAll();
  }

  async function refreshTx(t) {
    if (!t.hash || !s.ready) return;
    try {
      const info = extractTx(await fetchTransaction(s.readClient, t.hash));
      patchTx(t.id, { status: info.status, statusCode: info.statusCode, consensus: info.consensusResult, execution: info.execution, outcome: classifyOutcome(info), lastChecked: now(), lastError: null });
    } catch (e) { patchTx(t.id, { lastError: classifyError(e), lastChecked: now() }); }
    renderTab();
  }

  // ---------- screens
  function demoBanner() {
    return isDemo() ? h("div", { class: "banner demo", role: "note" }, h("strong", {}, "DEMO DATA. "), "Invented sample values that show the layout. Nothing here is read from or written to a blockchain, and transactions are disabled.") : null;
  }

  function setupPanel() {
    return section("Live mode is not configured",
      h("p", {}, "The app has not been given everything it needs to talk to the contract:"),
      list(s.cfg.missing, ""), h("p", { class: "small" }, "Set the environment variables listed in the README, run the config script, then reload. Until then you can explore Demo mode."));
  }

  function liveGate() {
    if (isDemo()) return null;
    if (!s.cfg.configured) return setupPanel();
    if (s.initializing) return section("Connecting", h("p", {}, "Loading the GenLayer SDK and contacting the network…"));
    if (s.initError) return section("Could not connect", h("p", { class: "err-text" }, s.initError), h("button", { type: "button", class: "btn primary", onClick: initLive }, "Retry"));
    return null;
  }

  function registerScreen() {
    const f = s.regForm, L = schema.limits;
    const set = (k) => (v) => { f[k] = v; if (s.showErrors.reg) showErr("reg", validateRegister(f).errors); };
    const res = validateRegister(f);
    const fileInput = h("input", { type: "file", id: "f-file", class: "file", onChange: async (e) => {
      const file = e.target.files && e.target.files[0]; if (!file) return;
      try {
        s.hashProgress = 0; renderTab();
        f.content_hash = await sha256Blob(file, (p) => { s.hashProgress = p; const el = els.content.querySelector("[data-progress]"); if (el) el.textContent = Math.round(p * 100) + "%"; });
      } catch (err) { toast("bad", "Could not hash that file", String(err && err.message || err)); }
      s.hashProgress = null; renderTab();
    } });
    return h("div", {}, demoBanner(), liveGate(), section("Register a dataset",
      h("p", { class: "muted" }, "Creates an on-chain record. Everything you enter is public and permanent: never include secrets or private training data."),
      h("form", { novalidate: true, onSubmit: (e) => { e.preventDefault(); submitRegister(); } },
        field({ label: "Assessment ID", name: "assessment_id", value: f.assessment_id, error: s.showErrors.reg && res.errors.assessment_id, hint: "Your unique ID, e.g. support-tickets-2026-10", attrs: { autocapitalize: "off", autocomplete: "off", spellcheck: "false", maxlength: 64 }, onInput: set("assessment_id") }),
        field({ label: "Dataset name", name: "dataset_name", value: f.dataset_name, error: s.showErrors.reg && res.errors.dataset_name, maxLen: L.dataset_name.max, attrs: { maxlength: L.dataset_name.max + 50 }, onInput: set("dataset_name") }),
        field({ label: "Dataset version", name: "dataset_version", value: f.dataset_version, error: s.showErrors.reg && res.errors.dataset_version, maxLen: L.dataset_version.max, onInput: set("dataset_version") }),
        field({ label: "Content hash (SHA-256, 64 hex characters)", name: "content_hash", value: f.content_hash, error: s.showErrors.reg && res.errors.content_hash,
          hint: "A hash identifies the exact bytes. It is NOT proof the data is safe.", attrs: { autocapitalize: "off", autocomplete: "off", spellcheck: "false", inputmode: "text", maxlength: 80 }, onInput: set("content_hash") }),
        h("div", { class: "field" }, h("label", { for: "f-file" }, "Or hash a local file"), fileInput,
          h("div", { class: "hint" }, "Hashed in chunks on this device; the file is never uploaded.", s.hashProgress !== null ? h("span", { "data-progress": "1" }, " " + Math.round(s.hashProgress * 100) + "%") : null)),
        field({ label: "Provenance", name: "provenance", area: true, rows: 4, value: f.provenance, error: s.showErrors.reg && res.errors.provenance, maxLen: L.provenance.max, hint: "Source, collection method, who held it. Claims here are not verified by the contract.", onInput: set("provenance") }),
        field({ label: "Model name (optional)", name: "model_name", value: f.model_name, error: s.showErrors.reg && res.errors.model_name, hint: "Required later if you submit trigger, control, baseline or reproduction tests.", onInput: set("model_name") }),
        field({ label: "Model version (optional)", name: "model_version", value: f.model_version, error: s.showErrors.reg && res.errors.model_version, onInput: set("model_version") }),
        h("button", { type: "submit", class: "btn primary block", disabled: s.busy || isDemo() }, isDemo() ? "Disabled in demo mode" : s.busy ? "Working…" : "Register on-chain"),
        walletHint())));
  }

  function walletHint() {
    if (isDemo()) return null;
    if (!s.wallet) return h("p", { class: "hint" }, "You will be asked to connect a wallet first.");
    return s.wallet.chainMatches ? null : h("p", { class: "err-text" }, "Your wallet is on a different network than this app expects.");
  }

  async function ensureWalletThen(fn) {
    if (isDemo()) return;
    if (!s.ready) { await initLive(); if (!s.ready) return; }
    if (!s.wallet) await connect();
    if (canWrite()) await fn(); else toast("warn", "Wallet not ready", "Connect your wallet on the expected network, then try again.");
  }

  async function submitRegister() {
    s.showErrors.reg = true;
    const res = validateRegister(s.regForm);
    showErr("reg", res.errors);
    if (!res.ok) { toast("warn", "Fix the highlighted fields first"); return; }
    await ensureWalletThen(() => doWrite("register_dataset", res.args, "register " + s.regForm.assessment_id, s.regForm.assessment_id));
  }

  function targetSummary(t) {
    if (t.loading) return h("p", { class: "muted" }, "Reading from chain…");
    if (t.error) return h("p", { class: "err-text" }, t.error);
    if (!t.data) return null;
    const a = t.data, c = checklist(a.evidence);
    return h("div", { class: "subcard" },
      kv("Status", chip(a.status, "neutral")), kv("Evidence", Number(a.evidence_count) + "/" + schema.maxEvidence),
      kv("Model", a.model_name || "none (behavioral tests not allowed)"),
      h("div", { class: "small" }, "What the contract will count as covered (preview):"),
      h("ul", { class: "checks" }, c.rows.map((r) => h("li", { class: r.covered ? "yes" : "no" }, (r.covered ? "✓ " : "○ ") + r.label))),
      c.allegations ? h("p", { class: "hint" }, c.allegations + " allegation item(s) do not count toward coverage.") : null,
      h("p", { class: "hint" }, c.ready ? "Enough to run a full evaluation." : "Not enough yet: an assessment now would be INCONCLUSIVE (no LLM run)."));
  }

  function evidenceScreen() {
    const f = s.evForm, L = schema.limits, t = s.evTarget;
    const type = f.evidence_type, counts = schema.countTypes.includes(type), beh = schema.behavioralTypes.includes(type);
    const ctx = t.data ? { modelName: t.data.model_name } : {};
    const res = validateEvidence(f, ctx);
    const set = (k) => (v) => { f[k] = v; if (s.showErrors.ev) showErr("ev", validateEvidence(f, ctx).errors); };
    const idField = field({ label: "Assessment ID", name: "assessment_id", value: f.assessment_id, error: s.showErrors.ev && res.errors.assessment_id,
      attrs: { autocapitalize: "off", autocomplete: "off", spellcheck: "false" }, hint: "Pick from History or type an ID, then tap Load.",
      onInput: (v) => { f.assessment_id = v; }, onChange: async (v) => { f.assessment_id = v; await loadAssessment(v.trim(), t); renderTab(); } });
    return h("div", {}, demoBanner(), liveGate(), section("Submit evidence",
      h("p", { class: "muted" }, "Evidence is public and permanent. Submit observations you can back with a method. Mark unverified claims as allegations; they never support a finding."),
      h("form", { novalidate: true, onSubmit: (e) => { e.preventDefault(); submitEvidence(ctx); } },
        idField, h("button", { type: "button", class: "btn small", onClick: async () => { await loadAssessment(f.assessment_id.trim(), t); renderTab(); } }, "Load"),
        targetSummary(t),
        h("div", { class: "field" }, h("label", { for: "f-evidence_type" }, "Evidence type"),
          h("select", { id: "f-evidence_type", value: type, onChange: (e) => { f.evidence_type = e.target.value; renderTab(); } },
            schema.evidenceTypes.map((x) => h("option", { value: x }, x.replace(/_/g, " ").toLowerCase()))),
          h("div", { class: "hint" }, EVIDENCE_HELP[type] || ""), h("div", { class: "err", "data-err": "evidence_type", role: "alert" }, s.showErrors.ev && res.errors.evidence_type || "")),
        h("fieldset", { class: "field" }, h("legend", {}, "Nature"),
          ["OBSERVATION", "ALLEGATION"].map((n) => h("label", { class: "radio" },
            h("input", { type: "radio", name: "nature", value: n, checked: f.nature === n, onChange: () => { f.nature = n; } }),
            n === "OBSERVATION" ? " Observation (measured, with a method)" : " Allegation (reported, unverified)")),
          h("div", { class: "err", "data-err": "nature", role: "alert" }, "")),
        field({ label: "Summary", name: "summary", area: true, rows: 4, value: f.summary, maxLen: L.summary.max, error: s.showErrors.ev && res.errors.summary, onInput: set("summary") }),
        field({ label: beh ? "Method (required, " + schema.minMethodLength + "+ characters)" : "Method (optional)", name: "method", area: true, rows: 3, value: f.method, maxLen: L.method.max,
          error: s.showErrors.ev && res.errors.method, hint: beh ? "Tool, seed, data split, and how a hit is defined." : "", onInput: set("method") }),
        counts ? h("div", { class: "row two" },
          field({ label: "Trials", name: "trials", value: f.trials, attrs: { inputmode: "numeric", pattern: "[0-9]*" }, error: s.showErrors.ev && res.errors.trials, onInput: set("trials") }),
          field({ label: "Hits", name: "hits", value: f.hits, attrs: { inputmode: "numeric", pattern: "[0-9]*" }, error: s.showErrors.ev && res.errors.hits, hint: "Trials showing the target behavior", onInput: set("hits") })) : null,
        h("button", { type: "submit", class: "btn primary block", disabled: s.busy || isDemo() }, isDemo() ? "Disabled in demo mode" : s.busy ? "Working…" : "Submit evidence on-chain"),
        walletHint())));
  }

  async function submitEvidence(ctx) {
    s.showErrors.ev = true;
    const res = validateEvidence(s.evForm, ctx);
    showErr("ev", res.errors);
    if (!res.ok) { toast("warn", "Fix the highlighted fields first"); return; }
    await ensureWalletThen(() => doWrite("submit_evidence", res.args, "evidence " + s.evForm.evidence_type + " for " + s.evForm.assessment_id, s.evForm.assessment_id));
  }

  function findingView(f) {
    const refs = (f.evidence_indexes || []).map((i) => "#" + i).join(", ");
    return h("li", { class: "finding" }, chip(f.category.replace(/_/g, " ").toLowerCase(), "neutral"),
      chip(f.source === "CONTRACT_METRIC" ? "computed by contract from reported counts" : "written by evaluator (LLM)", f.source === "CONTRACT_METRIC" ? "good" : "neutral"),
      h("p", {}, f.statement || "(no statement)"), refs ? h("p", { class: "small muted" }, "Based on evidence " + refs) : null);
  }

  function assessmentView(a, demo) {
    const meta = outcomeMeta(a.outcome), sc = scoreView(a), inconclusive = a.outcome === "INCONCLUSIVE";
    const m = a.metrics || {};
    const pct = (pm) => (typeof pm === "number" ? (pm / 10).toFixed(1) + "%" : "n/a");
    return h("div", { class: "assessment" },
      demo || a.demo ? h("div", { class: "ribbon" }, "DEMO DATA") : null,
      h("div", { class: "card outcome tone-" + meta.tone + (inconclusive ? " inconclusive" : "") },
        h("div", { class: "row between wrap" }, h("h2", {}, a.assessment_id), chip(a.status, "neutral")),
        h("div", { class: "outcome-label" }, inconclusive ? "INCONCLUSIVE" : meta.label.toUpperCase()),
        h("p", {}, meta.text),
        a.stale ? h("p", { class: "banner warn" }, "New evidence was submitted after this assessment. Run the assessment again.") : null,
        h("div", { class: "scorebox" + (sc.muted ? " muted" : "") },
          h("div", { class: "score" }, sc.value === null ? "—" : String(sc.value), sc.value === null ? null : h("span", { class: "of" }, "/100")),
          h("div", { class: "bar", "aria-hidden": "true" }, h("div", { class: "fill", style: "width:" + (sc.value === null ? 0 : Math.max(0, Math.min(100, sc.value))) + "%" })),
          h("div", { class: "small" }, sc.note)),
        h("div", { class: "row wrap" }, h("span", {}, "Evidence quality "), chip(a.evidence_quality || "n/a", qualityTone(a.evidence_quality)),
          chip(a.evaluation_mode === "DETERMINISTIC_ONLY" ? "no LLM run (insufficient evidence)" : a.evaluation_mode === "LLM_CONSENSUS" ? "validator LLM consensus" : "not evaluated", "neutral"))),
      section("Explanation", h("p", {}, a.explanation || "None yet.")),
      section("Supported findings", (a.supported_findings || []).length ? h("ul", { class: "list" }, a.supported_findings.map(findingView)) : h("p", { class: "muted" }, inconclusive ? "None. With this evidence the contract cannot support any finding, in either direction." : "No supported findings.")),
      section("Alternative explanations", list(a.alternative_explanations, "None listed.")),
      section("Missing tests", list(a.missing_tests, "None flagged.")),
      section("Next verification step", h("p", {}, a.next_verification_step || "None yet.")),
      section("Confidence limitations", list(a.confidence_limitations, "None listed.")),
      typeof m.trigger_trials === "number" && m.trigger_trials > 0 ? section("Reported test numbers (unverified counts)",
        kv("Trigger", m.trigger_hits + "/" + m.trigger_trials + " (" + pct(m.trigger_rate_pm) + ")"),
        kv("Control trials", String(m.control_trials)), kv("Baseline trials", String(m.baseline_trials)),
        kv("Reference rate", pct(m.reference_rate_pm)), kv("Differential", typeof m.differential_pm === "number" ? (m.differential_pm / 10).toFixed(1) + " points" : "n/a"),
        kv("Qualifying trigger runs", String(m.qualifying_trigger_runs))) : null,
      section("Dataset", kv("Name", a.dataset_name || ""), kv("Version", a.dataset_version || ""),
        kv("SHA-256", h("span", { class: "mono wrap-any" }, a.content_hash || "")), a.content_hash ? copyBtn(a.content_hash) : null,
        kv("Provenance (submitter's claim)", a.provenance || ""), kv("Model", a.model_name ? a.model_name + (a.model_version ? " " + a.model_version : "") : "none"),
        kv("Registered by", h("span", { class: "mono wrap-any" }, a.submitter || "")), kv("Registered", formatTime(a.registered_at)), kv("Assessed", formatTime(a.assessed_at))),
      section("Evidence (" + (a.evidence || []).length + ")", (a.evidence || []).length ? (a.evidence || []).map((e, i) => h("details", { class: "ev" },
        h("summary", {}, "#" + (e.index ?? i) + " " + e.type.replace(/_/g, " ").toLowerCase() + " · ", chip(e.nature.toLowerCase(), e.nature === "OBSERVATION" ? "good" : "warn")),
        h("p", {}, e.summary), e.method ? h("p", { class: "small" }, "Method: " + e.method) : null,
        e.trials ? h("p", { class: "small" }, "Trials " + e.trials + ", hits " + e.hits) : null)) : h("p", { class: "muted" }, "No evidence submitted.")));
  }

  function actionsFor(a) {
    if (isDemo()) return null;
    const next = allowedTransitions(a.status);
    const can = a.status === "EVIDENCE_SUBMITTED" || a.status === "UNDER_REVIEW";
    return section("Actions",
      h("p", { class: "small muted" }, can ? "Running an assessment is a transaction. If evidence is thin the contract records INCONCLUSIVE without any LLM; otherwise validators run the evaluation, which can take minutes." : "Assessment can run once evidence is submitted (status EVIDENCE_SUBMITTED or UNDER_REVIEW)."),
      h("button", { type: "button", class: "btn primary block", disabled: !can || s.busy, onClick: () => ensureWalletThen(() => doWrite("assess_dataset", [a.assessment_id], "assess " + a.assessment_id, a.assessment_id)) }, s.busy ? "Working…" : "Run assessment"),
      next.length ? h("div", { class: "row wrap" }, next.map((st) => h("button", { type: "button", class: "btn", disabled: s.busy, onClick: () => {
        const v = validateStatusChange(a.assessment_id, st);
        if (v.ok) ensureWalletThen(() => doWrite("update_assessment_status", v.args, "status " + st + " for " + a.assessment_id, a.assessment_id));
      } }, "Set " + st.replace(/_/g, " ").toLowerCase()))) : null,
      h("p", { class: "hint" }, "Only the record's submitter (CLOSED only) or the contract owner may change status. The contract enforces this; the app cannot see who the owner is."));
  }

  function lookupBar(onGo) {
    return h("form", { class: "row lookup", onSubmit: (e) => { e.preventDefault(); onGo(); } },
      h("input", { type: "text", "aria-label": "Assessment ID", placeholder: isDemo() ? "DEMO-inconclusive" : "assessment ID", value: s.lookup, autocapitalize: "off", spellcheck: "false", onInput: (e) => { s.lookup = e.target.value; } }),
      h("button", { type: "submit", class: "btn primary" }, "Look up"));
  }

  async function openAssessment(id) {
    s.tab = "results"; s.lookup = id; renderNav(); await loadAssessment(id.trim(), s.current); renderTab();
  }

  function resultsScreen() {
    const c = s.current;
    return h("div", {}, demoBanner(), liveGate(), lookupBar(async () => { await loadAssessment(s.lookup.trim(), c); renderTab(); }),
      c.loading ? h("p", { class: "muted" }, "Reading from chain…") : null,
      c.error ? h("div", { class: "banner warn" }, c.error) : null,
      c.data ? h("div", {}, assessmentView(c.data, isDemo()),
        !isDemo() ? h("button", { type: "button", class: "btn", onClick: async () => { await loadAssessment(c.id, c); renderTab(); } }, "Refresh from chain") : null,
        actionsFor(c.data)) : (!c.error && !c.loading ? h("p", { class: "muted" }, "Look up an assessment ID, or open one from History.") : null));
  }

  function historyScreen() {
    const ids = isDemo() ? DEMO_ASSESSMENTS.map((d) => ({ id: d.assessment_id, source: "demo" })) : s.history;
    return h("div", {}, demoBanner(), liveGate(),
      lookupBar(() => { const id = s.lookup.trim(); if (!idError(id)) openAssessment(id); else toast("warn", "Invalid ID", idError(id)); }),
      h("p", { class: "hint" }, isDemo() ? "Demo assessments." : "The contract has no function to list assessments, so this list contains IDs this browser registered or looked up. Each card is read fresh from the chain."),
      ids.length ? ids.map((x) => historyCard(x)) : h("p", { class: "muted" }, "Nothing here yet. Register a dataset or look one up by ID."),
      !isDemo() && ids.length ? h("button", { type: "button", class: "btn", onClick: async () => { for (const x of ids) await loadSummary(x.id); renderTab(); } }, "Refresh all from chain") : null);
  }

  function historyCard(x) {
    const sum = s.summaries[x.id], a = sum && sum.data;
    if (!sum && (isDemo() || s.ready)) loadSummary(x.id).then(() => { if (s.tab === "history") renderTab(); });
    const meta = a ? outcomeMeta(a.outcome) : null;
    return h("button", { type: "button", class: "card histcard", onClick: () => openAssessment(x.id) },
      h("div", { class: "row between wrap" }, h("strong", {}, x.id), a ? chip(meta.label, meta.tone) : null),
      a ? h("div", { class: "small" }, "Status " + a.status + " · quality " + a.evidence_quality + (a.outcome === "INCONCLUSIVE" ? " · not a safety rating" : a.outcome === "NOT_ASSESSED" ? "" : " · score " + a.risk_score))
        : sum && sum.error ? h("div", { class: "small err-text" }, sum.error) : h("div", { class: "small muted" }, "Loading…"),
      h("div", { class: "small muted" }, x.source === "registered" ? "registered from this browser (confirm on-chain above)" : x.source === "demo" ? "demo" : "looked up"));
  }

  function txCard(t) {
    const link = explorerTxLink(s.cfg, t.hash);
    const o = t.outcome || { label: "Unknown", tone: "neutral" };
    const tone = t.error ? "bad" : o.tone || "neutral";
    return h("div", { class: "card tx" },
      h("div", { class: "row between wrap" }, h("strong", {}, t.label || t.method), chip(o.label || "Unknown", tone)),
      t.hash ? h("div", { class: "kv" }, h("span", { class: "k" }, "Tx hash"), h("span", { class: "v mono wrap-any" }, t.hash)) : h("p", { class: "small" }, "No transaction hash: nothing was recorded on-chain by this attempt."),
      t.hash ? h("div", { class: "row wrap" }, copyBtn(t.hash, "Copy hash"), link ? h("a", { class: "btn small", href: link, target: "_blank", rel: "noopener noreferrer" }, "Open in explorer") : h("span", { class: "small muted" }, "No explorer URL configured"), h("button", { type: "button", class: "btn small", onClick: () => refreshTx(t) }, "Refresh status")) : null,
      kv("Consensus status", t.status || (t.statusCode != null ? "code " + t.statusCode : "not reported")),
      kv("Execution result", t.execution || "not reported by RPC"),
      t.consensus ? kv("Validator result", t.consensus) : null,
      t.error ? h("p", { class: "err-text" }, t.error.title + (t.error.detail ? ": " + t.error.detail : "")) : null,
      t.lastError ? h("p", { class: "small err-text" }, "Last status check failed: " + t.lastError.title) : null,
      t.verify ? h("p", { class: "small " + (t.verify.ok ? "ok-text" : "err-text") }, t.verify.msg) : null,
      h("div", { class: "small muted" }, "Sent " + formatTime(t.createdAt) + (t.lastChecked ? " · checked " + formatTime(t.lastChecked) : "")));
  }

  function activityScreen() {
    return h("div", {}, demoBanner(), liveGate(),
      isDemo() ? h("p", { class: "muted" }, "Demo mode sends no transactions, so there is no activity.")
        : [h("p", { class: "hint" }, "Transactions sent from this browser. Statuses are read from the chain; nothing is marked successful on assumption."),
          s.txs.length ? s.txs.map(txCard) : h("p", { class: "muted" }, "No transactions yet."),
          s.txs.length ? h("button", { type: "button", class: "btn", onClick: () => { store.clearTxs(); s.txs = []; renderTab(); } }, "Clear local list (does not affect the chain)") : null]);
  }

  // ---------- shell
  function renderOverview() {
    clear(els.overview);
    const demo = isDemo();
    const addr = s.cfg.contractAddress;
    els.overview.appendChild(h("div", { class: "card overview" },
      h("div", { class: "row between wrap" }, h("h1", {}, "PoisonGuardAI"),
        h("div", { class: "seg", role: "group", "aria-label": "Mode" },
          h("button", { type: "button", "aria-pressed": String(!demo), class: !demo ? "on" : "", onClick: () => { s.mode = "live"; if (s.cfg.configured) initLive(); renderAll(); } }, "Live"),
          h("button", { type: "button", "aria-pressed": String(demo), class: demo ? "on" : "", onClick: () => { s.mode = "demo"; renderAll(); } }, "Demo"))),
      demo ? h("div", { class: "banner demo" }, h("strong", {}, "DEMO MODE. "), "Sample data only. No chain connection.") : null,
      kv("Network", (s.cfg.networkLabel || "not configured") + (s.chain ? " · chain id " + s.chain.id : "")),
      kv("Contract", addr ? h("span", { class: "mono wrap-any" }, addr) : "not configured"), addr ? copyBtn(addr) : null,
      !demo && s.ready ? kv("Datasets on-chain", s.countError ? h("span", { class: "err-text" }, s.countError) : s.count === null ? "…" : String(s.count)) : null,
      !demo && s.cfg.configured ? (s.wallet
        ? kv("Wallet", h("span", { class: "mono wrap-any" }, s.wallet.account + (s.wallet.chainMatches ? "" : " (wrong network)")))
        : h("button", { type: "button", class: "btn primary block", disabled: !s.ready, onClick: connect }, s.ready ? "Connect wallet" : "Waiting for SDK…")) : null,
      h("details", { class: "small" }, h("summary", {}, "Contract schema used by this frontend"),
        kv("File", schema.contractFile + " · " + schema.contractBytes + " bytes"), kv("SHA-256", h("span", { class: "mono wrap-any" }, schema.contractSha256)),
        h("p", { class: "hint" }, "Extracted from the contract source. The app cannot prove the deployed bytecode matches this file."))));
  }

  function renderNav() {
    clear(els.nav);
    TABS.forEach(([id, label]) => els.nav.appendChild(h("button", { type: "button", class: s.tab === id ? "on" : "", "aria-current": s.tab === id ? "page" : null,
      onClick: () => { s.tab = id; renderNav(); renderTab(); } }, label)));
  }

  function renderTab() {
    clear(els.content);
    const screens = { register: registerScreen, evidence: evidenceScreen, results: resultsScreen, history: historyScreen, activity: activityScreen };
    els.content.appendChild(screens[s.tab]());
  }

  function renderAll() { renderOverview(); renderNav(); renderTab(); renderToast(); }

  function mount(root) {
    clear(root);
    els.overview = h("div", { id: "overview" }); els.toast = h("div", { id: "toast", "aria-live": "polite" });
    els.content = h("main", { id: "content" }); els.nav = h("nav", { id: "nav", "aria-label": "Sections" });
    root.append(els.overview, els.toast, els.content, els.nav);
    renderAll();
    if (s.mode === "live" && s.cfg.configured) initLive();
  }

  return { state: s, mount, renderAll, renderTab, setTab: (t) => { s.tab = t; renderNav(); renderTab(); }, connect, initLive, doWrite, loadAssessment, refreshTx, safeJson };
}
