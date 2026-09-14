#!/usr/bin/env node
// buzz-mcp — join the Buzz relay from a Claude CLI session: see channels,
// read what your agents are saying, post, and @mention agents to delegate.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import * as nip19 from "nostr-tools/nip19";
import { resolveSigner, reactionTemplate, addMemberTemplate, removeMemberTemplate, deleteMessageTemplate, blossomAuthTemplate, buildImeta, parseImeta, messageAttachments, mediaMimeForPath, mediaCapCheck, MEDIA_MB, wireNameGet, wirePersistId, ekamBase, wireRefreshGet, wireRefreshSet, wirePubkeyGet, wirePubkeySet, wireNameSet, wireSign } from "./signer.mjs";
// buzz_login (v0.2.15) reuses the wire-sign OAuth primitives from the login CLI. NOTE: this
// import inlines wirelogin.mjs into the bundle — its CLI main is guarded by a basename check
// (see wirelogin.mjs) so it does NOT run at shim boot; we only compose its exported helpers.
import { pkce, authorizeUrl, exchangeAuthCode, bindLoopback } from "./wirelogin.mjs";
import { createHash, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, appendFileSync, renameSync, mkdirSync, existsSync, statSync, createReadStream } from "node:fs";
import { Readable } from "node:stream";
import { request as httpsRequest, Agent as HttpsAgent } from "node:https";
import { request as httpRequest, Agent as HttpAgent } from "node:http";
import { homedir, hostname, tmpdir } from "node:os";
import { join, basename, extname } from "node:path";
import { execSync, spawn } from "node:child_process";

const RELAY = process.env.BUZZ_RELAY_HTTP || "http://localhost:3000";
// URL base the relay validates NIP-98 against (its canonical community host).
// Behind a TLS edge we dial https://<fqdn> but the relay reconstructs the
// expected URL as http://localhost:3000 (its default RELAY_URL scheme + the
// canonical community host the fqdn folds to), so decouple sign-base from dial.
const SIGN_BASE = process.env.BUZZ_SIGN_BASE || RELAY;
const CFG_DIR = join(homedir(), ".config", "buzz-cli");

// ---- per-terminal identity (distinct per terminal so many CLIs don't collide) ----
// Keyed off the terminal session id (macOS Terminal/iTerm set these per window/tab),
// falling back to the parent pid. Each terminal → its own keypair → its own name.
function sessionId() {
  return (process.env.TERM_SESSION_ID || process.env.ITERM_SESSION_ID ||
          process.env.CLAUDE_SESSION_ID || `pid-${process.ppid}`).replace(/[^\w.-]/g, "_").slice(0, 60);
}
// #104: identity resolution lives in loadkey_v2 (async — Phase 2 self-fetches
// over HTTP). A NAMED/governed agent (BUZZ_NAME set) whose key is missing on
// restart recovers a STABLE identity — Phase 1: env pin / 0600 keystore; Phase 2:
// BUZZ_SERVICE_REFRESH → exchange → wire-key in memory — or fails LOUD, never a
// silent random pubkey. UNNAMED casual sessions keep per-terminal `.hex`/random.
// The signing seam (signer.mjs): local mode (default) resolves a key via loadkey_v2
// and signs in-process; wire mode (BUZZ_WIRE_SIGN + Ekam human token) holds NO key
// and calls /v1/me/wire-sign so events are signed AS the user (#317, Path A). PK is
// the identity's pubkey either way.
const signer = await resolveSigner({ sessionId: sessionId() });
const PK = signer.pubkey;

// ---- context-derived friendly name (like Codex): <repo-or-dir>·<memorable> ----
const ANIMALS = ["otter","falcon","lynx","heron","ibex","marten","tern","shrike","vireo",
  "saki","tapir","serval","caracal","fossa","dhole","quokka","kagu","takin","gaur","civet"];
function contextName() {
  let ctx;
  try { ctx = basename(execSync("git rev-parse --show-toplevel", { stdio: ["ignore","pipe","ignore"] }).toString().trim()); } catch {}
  if (!ctx) {
    const b = basename(process.cwd());
    ctx = (b && b !== basename(homedir())) ? b : hostname().split(".")[0].toLowerCase();
  }
  const animal = ANIMALS[parseInt(PK.slice(0, 8), 16) % ANIMALS.length];
  return `${ctx}·${animal}`;
}

// ---- timestamp formatting (pilot #3: buzz_read times were raw UTC, unlabelled) ----
// Honor BUZZ_TZ (IANA name, e.g. Asia/Kolkata); default UTC. Always append a zone
// label so a time is never ambiguous. Ola config sets BUZZ_TZ=Asia/Kolkata → IST.
const DISPLAY_TZ = (process.env.BUZZ_TZ || "UTC").trim() || "UTC";
function tzLabel(d) {
  if (DISPLAY_TZ === "UTC") return "UTC";
  try {
    const p = new Intl.DateTimeFormat("en-US", { timeZone: DISPLAY_TZ, timeZoneName: "short" })
      .formatToParts(d).find((x) => x.type === "timeZoneName");
    return p ? p.value : DISPLAY_TZ;
  } catch { return DISPLAY_TZ; }
}
function fmtTime(created_at, withDate = false) {
  const d = new Date(created_at * 1000);
  try {
    const opts = { timeZone: DISPLAY_TZ, hour12: false, hour: "2-digit", minute: "2-digit" };
    if (withDate) { opts.year = "numeric"; opts.month = "2-digit"; opts.day = "2-digit"; }
    const p = Object.fromEntries(
      new Intl.DateTimeFormat("en-GB", opts).formatToParts(d).map((x) => [x.type, x.value]));
    const hm = `${p.hour}:${p.minute}`;
    const stamp = withDate ? `${p.year}-${p.month}-${p.day} ${hm}` : hm;
    return `${stamp} ${tzLabel(d)}`;
  } catch { return `${d.toISOString().slice(11, 16)} UTC`; }
}
let MY_NAME = process.env.BUZZ_IDENTITY_NAME || process.env.BUZZ_NAME
  || (signer.mode === "wire" ? wireNameGet(wirePersistId(process.env)) : null)   // ekam #335 name captured at login
  || contextName();
// NIP-OA owner attestation: if BUZZ_AUTH_TAG is set (a signed ["auth",owner,conditions,sig] JSON),
// attach it to signed events so the desktop shows "Agent managed by <owner>" instead of "owner unavailable".
const AUTH_TAG = (() => { try { const t = JSON.parse(process.env.BUZZ_AUTH_TAG || ""); return (Array.isArray(t) && t[0] === "auth" && t.length === 4) ? t : null; } catch { return null; } })();

// ---- fail-CLOSED identity pinning (anti-impersonation) ----
// If BUZZ_EXPECTED_PUBKEY is pinned and the running key does NOT derive to it, this session is
// wearing the WRONG identity (shared/clobbered config, e.g. relay_sre's session reading a
// bossman-pinned block). Reads stay allowed; WRITES are refused so it can't publish AS someone else.
const EXPECTED_PK = (process.env.BUZZ_EXPECTED_PUBKEY || "").trim().toLowerCase() || null;
const IDENTITY_OK = !EXPECTED_PK || PK.toLowerCase() === EXPECTED_PK;
// isolation check: launched via buzz-claude (own CLAUDE_CONFIG_DIR) or on the SHARED config (seepage risk)?
const IS_ISOLATED = (process.env.CLAUDE_CONFIG_DIR || "").includes("/buzz-agents/");
const GUIDE_PATH = process.env.BUZZ_ONBOARDING_GUIDE || join(homedir(), ".config/ekam/community-signer/ONBOARDING.md");
if (!IDENTITY_OK)
  process.stderr.write(`[buzz-mcp] ⚠ IMPERSONATION GUARD: config expects ${EXPECTED_PK.slice(0, 16)} but running key is ${PK.slice(0, 16)} (${MY_NAME}). WRITES DISABLED. Fix: pin the correct key, or launch with your own CLAUDE_CONFIG_DIR.\n`);

// ---- NIP-98 auth header for the HTTP bridge ----
// Async: in wire mode signing is a network round-trip to Ekam's /v1/me/wire-sign
// (the per-request cost of "post as the user"); in local mode it's in-process.
// created_at is stamped by the signer (local) or the server (wire, anti-backdating).
async function nip98(url, method, body) {
  const payload = createHash("sha256").update(body ?? "").digest("hex");
  // A per-request `nonce` tag guarantees a unique event id even for two same-second requests
  // to the same URL with the same body (e.g. a tool that fires profiles()+members() back to
  // back) — otherwise the relay's NIP-98 replay guard (coarse dedup) 401s the second one.
  const ev = await signer.sign(
    { kind: 27235, tags: [["u", url], ["method", method], ["payload", payload], ["nonce", randomBytes(12).toString("hex")]], content: "" },
  );
  return "Nostr " + Buffer.from(JSON.stringify(ev)).toString("base64");
}

// Shim version for the x-buzz-client telemetry header. Keep in sync with package.json.
const SHIM_VERSION = "0.2.18";

// #243: coarse, bounded retry class from the caught NETWORK error (name/code only, never raw message).
function retryClass(e) {
  const c = ((e && (e.cause?.code || e.code || e.name)) || "").toString().toLowerCase();
  if (c.includes("reset") || c.includes("econnreset")) return "socket_reset";
  if (c.includes("timeout") || c.includes("etimedout") || c.includes("econnrefused") || c.includes("connect")) return "connect_timeout";
  return "unknown_transport";
}

// B (v0.2.17 item 3) — hard per-attempt timeout for the undici fetch. A slow-but-not-dead attempt
// would otherwise deliver LATE carrying an aged NIP-98 created_at that the relay 401s on ±60s; abort
// it so it THROWS instead → the existing fresh-socket catch in bridge() re-signs a fresh NIP-98
// (fresh created_at → the wedge can't recur). Env-tunable BUZZ_HTTP_TIMEOUT_S (seconds), default 25,
// clamped 1..300, parsed like the other env ints (wire-login TTL/ports).
const HTTP_TIMEOUT_S = (() => {
  const n = parseInt(process.env.BUZZ_HTTP_TIMEOUT_S || "", 10);
  return Number.isFinite(n) && n > 0 ? Math.max(1, Math.min(n, 300)) : 25;
})();

// A (v0.2.17 item 3) — DISTINCT process-level counter for stale-timestamp-401 remediations, so a
// clock-skewed / relay-queue-delayed fleet is visible as its OWN signal (separate from the
// transport-retry marker). Surfaced in a stderr telemetry line each time an A-retry fires.
let STALE_401_RETRIES = 0;
// Typed stale-timestamp codes a relay MAY return in a structured JSON body (preferred over string).
const STALE_TS_CODES = new Set(["nip98_timestamp_out_of_window", "stale_timestamp", "timestamp_out_of_window", "nip98_stale_timestamp", "nip98_timestamp_stale"]);
// A — is this 401 body the NIP-98 timestamp-staleness error (and ONLY that)? PREFER a typed code in
// a JSON body; FALL BACK to an EXACT substring on the ±60s window message the relay returns today
// ("event timestamp outside ±60s window"). Every OTHER 401/403/4xx (revoked, scope-denied,
// forbidden, …) → false → NOT retried, stays legible. Strictly gated to this one case.
function isStaleTimestamp401(bodyText) {
  const s = String(bodyText || "");
  try {
    const j = JSON.parse(s);
    const code = String(j.code || j.error || j.reason || "").toLowerCase();
    if (STALE_TS_CODES.has(code)) return true;
  } catch { /* body isn't JSON → fall through to the exact string match */ }
  return s.includes("outside ±60s window"); // exact window-message substring (relay's current wording)
}

// v0.2.8 transport self-heal. A long-lived MCP process can wedge Node's built-in undici fetch
// pool (releng: every /query throws unknown_transport while whoami — local, no fetch — still
// works; only a full process restart clears it). We can't recreate undici's dispatcher (undici
// isn't importable — ERR_MODULE_NOT_FOUND), so on a transport throw we retry over a FRESH
// node:https socket (keepAlive:false = a brand-new connection, never the wedged pool). Once a
// wedge is seen we stick to the raw path for the rest of the process so every later call keeps
// working without a restart; a clean undici attempt clears the flag. `whoami` surfaces it.
let TRANSPORT_WEDGED = false;
function rawPost(urlStr, headers, body) {
  return new Promise((resolve, reject) => {
    let u; try { u = new URL(urlStr); } catch (e) { return reject(e); }
    const isHttps = u.protocol === "https:";
    const req = (isHttps ? httpsRequest : httpRequest)(u, {
      method: "POST",
      headers: { ...headers, "Content-Length": Buffer.byteLength(body) },
      agent: new (isHttps ? HttpsAgent : HttpAgent)({ keepAlive: false }), // one-off socket, bypasses the wedged undici pool
    }, (res) => {
      let data = ""; res.setEncoding("utf8");
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, text: async () => data }));
    });
    req.on("error", reject);
    req.setTimeout(30_000, () => req.destroy(new Error("rawPost timeout")));
    req.end(body);
  });
}

// buzz_doctor (v0.2.16) — a one-off node:https/node:http GET over a BRAND-NEW socket
// (keepAlive:false), deliberately NOT the shim's normal undici client so it still answers
// when that client's pool is wedged. Diagnostic-only; short, caller-set timeout.
function rawGet(urlStr, headers, timeoutMs) {
  return new Promise((resolve, reject) => {
    let u; try { u = new URL(urlStr); } catch (e) { return reject(e); }
    const isHttps = u.protocol === "https:";
    const req = (isHttps ? httpsRequest : httpRequest)(u, {
      method: "GET",
      headers: { ...(headers || {}) },
      agent: new (isHttps ? HttpsAgent : HttpAgent)({ keepAlive: false }), // one-off socket, bypasses the wedged undici pool
    }, (res) => {
      let data = ""; res.setEncoding("utf8");
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, text: data }));
    });
    req.on("error", reject);
    req.setTimeout(timeoutMs || 5000, () => req.destroy(new Error("doctor probe timeout")));
    req.end();
  });
}

async function bridge(path, bodyObj) {
  const dialUrl = `${RELAY}${path}`;
  const signUrl = `${SIGN_BASE}${path}`;
  const body = JSON.stringify(bodyObj);
  // Fresh NIP-98 per attempt (a replayed NIP-98 would be rejected); the body — incl. any signed Nostr
  // event and its deterministic id — is unchanged, so a retried /events dedups server-side (ON CONFLICT
  // DO NOTHING before side effects, per relay ingest.rs). Reads are idempotent regardless.
  // The auth header is SIGNED before the fetch and passed in — so a wire-mode sign
  // failure (revoked/scope-denied Ekam token) surfaces as its own auth error and is
  // NOT swallowed by the transient transport-retry below (kill-switch stays legible).
  // Header set is shared by the undici (fetch) path and the node:https self-heal path so the
  // request the relay sees is identical either way. The auth header is SIGNED before the call —
  // a wire-mode sign failure (revoked/scope-denied Ekam token) surfaces as its own auth error
  // and is NOT swallowed by the transient transport-retry below (kill-switch stays legible).
  const headersFor = (authz, isRetry, rClass) => ({
    "Content-Type": "application/json",
    "Authorization": authz,
    // NIP-OA owner delegation: the relay reads membership from the `x-auth-tag` header (bridge.rs).
    ...(AUTH_TAG ? { "x-auth-tag": JSON.stringify(AUTH_TAG) } : {}),
    // Platform attribution — telemetry only (relay stamps a bounded `client` label, never gates auth).
    "x-buzz-client": `agent/${SHIM_VERSION}`,
    // #243: on a retry ONLY, mark it so the relay counts retry RATE (dedicated counter, telemetry only).
    ...(isRetry ? { "x-buzz-retry": `1; retry_class=${rClass}` } : {}),
  });
  const attempt = (authz, isRetry, rClass) => {
    // B: hard timeout so a slow undici attempt THROWS (→ the fresh-socket catch below re-signs)
    // instead of arriving late with an aged created_at. The timer is .unref()'d (never keeps the
    // process alive) and cleared on settle (success OR failure).
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(new Error(`undici attempt exceeded BUZZ_HTTP_TIMEOUT_S=${HTTP_TIMEOUT_S}s`)), HTTP_TIMEOUT_S * 1000);
    timer.unref?.();
    return fetch(dialUrl, { method: "POST", headers: headersFor(authz, isRetry, rClass), body, signal: ac.signal })
      .finally(() => clearTimeout(timer));
  };
  // v0.2.16 — NIP-98 FRESHNESS INVARIANT. `freshAuthz()` builds a brand-new NIP-98 auth event
  // (kind 27235) at the moment it is called. It is invoked ONCE PER ACTUAL SEND — once for the
  // first attempt (just below) and AGAIN for the fresh-transport retry — so a previously-signed
  // auth event is NEVER reused across a retry or a queue delay. This is what keeps `created_at`
  // inside the relay's ±60s NIP-98 window: a delayed/retried request always carries a freshly
  // stamped timestamp, instead of a stale one the relay 401s ("event timestamp outside ±60s
  // window") — the failure mode that wedged writes during a relay cutover. The event body (and
  // the deterministic Nostr event id it may carry) is unchanged, so a retried /events dedups
  // server-side (ON CONFLICT DO NOTHING before side effects); reads are idempotent regardless.
  const freshAuthz = () => nip98(signUrl, "POST", body);
  let res;
  // SINGLE-FLIGHT guard shared by B (transport-throw retry) and A (stale-timestamp-401 retry): one
  // logical bridge() call makes AT MOST TWO physical attempts (original + one remediation). Once
  // either B or A has remediated, the other MUST NOT add a third attempt — no cascade.
  let remediated = false;
  // Sign OUTSIDE the transport try/catch. A wire-mode mint/auth failure (revoked token, rotating-
  // refresh family-revoke, scope-denied) throws HERE and propagates VERBATIM with its own legible
  // message ("… re-run the one-time login") — it must never be mislabeled unknown_transport, and
  // never retried, since a mint retry re-presents a spent single-use refresh and compounds the
  // revoke. ONLY the relay fetch/rawPost throw below is transport-retryable. [releng 05:48 BUG 1]
  const authz = await freshAuthz();
  try {
    // If we've already seen a wedge this process, skip the doomed undici attempt and go straight
    // to the fresh-socket path — so a wedged process keeps working without a restart.
    res = TRANSPORT_WEDGED
      ? await rawPost(dialUrl, headersFor(authz, true, "wedged_reroute"), body)
      : await attempt(authz, false);
  } catch (e) {
    // NETWORK-level throw only (dead pooled socket / reset / connect timeout). HTTP errors return a
    // response (handled below) and are NEVER retried — a 401/403/4xx is not a throw. The retry goes
    // over a FRESH node:https socket (not the wedged undici pool), and marks the pool wedged so every
    // later call reroutes too.
    const rClass = retryClass(e);
    process.stderr.write(`[buzz-mcp] transient ${path} fetch failed (${rClass}); retrying on a fresh node:https socket\n`);
    // RE-SIGN a fresh NIP-98 for the retry (per the freshness invariant above) — hoisted out of the
    // inner try so an auth failure here ALSO propagates verbatim rather than being swallowed as
    // transport. (Cached access token → no re-mint; only a new, freshly-timestamped auth event.)
    const authz2 = await freshAuthz();
    try {
      res = await rawPost(dialUrl, headersFor(authz2, true, rClass), body);
      TRANSPORT_WEDGED = true; // the raw retry worked where undici didn't → the pool is wedged; reroute from here on
      remediated = true;        // B used this call's one remediation → A must NOT add a third attempt
    } catch {
      throw new Error(`${path} -> transient fetch failed [retried 1x on a fresh transport, still failed; class=${rClass}]. If reads/posts keep failing, FULLY RESTART your MCP client — reconnect and the shim's own retry do NOT clear a wedged connection pool.`);
    }
  }
  let text = await res.text();
  // A (v0.2.17 item 3) — narrow retry on a stale-timestamp NIP-98 401 (clock-skew / relay-queue
  // delay that B's timeout can't catch — a fast 401 whose created_at aged before the relay checked
  // it). Fires AT MOST ONCE, only when B hasn't already remediated (single-flight above), and ONLY
  // for the stale-timestamp case — every OTHER 401/403/4xx stays legible (falls through to the
  // res.ok throw below, returned exactly as today). The retry re-signs a FRESH NIP-98 via
  // freshAuthz() (signer's non-forced tokens.get(false) path — NEVER a forced mint) and goes over a
  // fresh node:https socket, consistent with the transport-retry path. A DISTINCT counter +
  // stderr marker (retry_class=stale_timestamp_401) make a clock-skewed fleet visible.
  if (!remediated && res.status === 401 && isStaleTimestamp401(text)) {
    remediated = true;
    STALE_401_RETRIES += 1;
    process.stderr.write(`[buzz-mcp] stale-timestamp 401 on ${path}; re-signing a fresh NIP-98 and retrying once on a fresh node:https socket (stale_401_retry_count=${STALE_401_RETRIES})\n`);
    const authzA = await freshAuthz(); // fresh created_at; non-forced token path (no re-mint)
    res = await rawPost(dialUrl, headersFor(authzA, true, "stale_timestamp_401"), body);
    text = await res.text();
  }
  if (!res.ok) throw new Error(`${path} -> HTTP ${res.status}: ${text.slice(0, 200)}`);
  try { return JSON.parse(text); } catch { return text; }
}

const query = (filters) => bridge("/query", filters);

// ── Attachments (Blossom BUD-01/02/11). The kind-24242 auth is built ONLY via
// blossomAuthTemplate (fail-closed). Per-type size caps (mediaCapCheck, from signer.mjs) are a
// PRE-FLIGHT COURTESY — the relay's 413 is authoritative; the local refusal is worded so it
// can't be mistaken for a server verdict.
const MB = MEDIA_MB;
const TEXT_MIME = /^(text\/|application\/(json|xml|.*\+xml|x-yaml|yaml))/; // safe to return inline as text
function sha256File(p) {
  return new Promise((res, rej) => { const h = createHash("sha256"); const s = createReadStream(p); s.on("error", rej); s.on("data", (c) => h.update(c)); s.on("end", () => res(h.digest("hex"))); });
}
async function blossomAuthHeader(verb, sha) {
  const ev = await signer.sign(blossomAuthTemplate({ verb, sha256: sha })); // fail-closed shape enforced here
  return "Nostr " + Buffer.from(JSON.stringify(ev)).toString("base64");
}
const DOWNLOAD_CHUNK = 16 * MB; // relay caps a single 206 range at 16 MiB → loop for larger

// Upload a local file → NIP-92 descriptor {url, sha256, size, mime, filename}. Streamed hash + PUT body.
async function blossomUpload(filePath) {
  let st; try { st = statSync(filePath); } catch { throw new Error(`attachment not found: ${filePath}`); }
  if (!st.isFile()) throw new Error(`attachment is not a file: ${filePath}`);
  const { mime } = mediaCapCheck(basename(filePath), st.size); // per-type cap; throws a distinguishable local refusal if over
  const sha = await sha256File(filePath);
  const res = await fetch(`${RELAY}/upload`, {
    method: "PUT",
    headers: { Authorization: await blossomAuthHeader("upload", sha), "X-SHA-256": sha, "Content-Type": mime, "Content-Length": String(st.size), ...(AUTH_TAG ? { "x-auth-tag": JSON.stringify(AUTH_TAG) } : {}) },
    body: Readable.toWeb(createReadStream(filePath)),
    duplex: "half",
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`upload ${basename(filePath)} -> HTTP ${res.status}: ${text.slice(0, 200)}`);
  let d = {}; try { d = JSON.parse(text); } catch {}
  return { url: d.url || `${RELAY}/media/${sha}${extname(filePath)}`, sha256: String(d.sha256 || d.x || sha).toLowerCase(), size: Number(d.size || st.size), mime: d.type || mime, filename: basename(filePath) };
}

// Download a media blob (sha[.ext]) → destPath, streamed to disk with Range-based resume.
async function blossomDownload(shaExt, destPath) {
  const sha = String(shaExt).split(".")[0].toLowerCase();
  const part = destPath + ".part";
  let start = 0; try { start = statSync(part).size; } catch {}
  let total = Infinity;
  while (start < total) {
    const res = await fetch(`${RELAY}/media/${shaExt}`, { headers: { Authorization: await blossomAuthHeader("get", sha), Range: `bytes=${start}-${start + DOWNLOAD_CHUNK - 1}`, ...(AUTH_TAG ? { "x-auth-tag": JSON.stringify(AUTH_TAG) } : {}) } });
    if (res.status === 200) { const buf = Buffer.from(await res.arrayBuffer()); writeFileSync(part, buf); start = buf.length; total = buf.length; break; }
    if (res.status !== 206) { const t = await res.text().catch(() => ""); throw new Error(`download <${sha.slice(0, 8)}> -> HTTP ${res.status}: ${t.slice(0, 160)}`); }
    const cr = res.headers.get("content-range") || ""; const m = cr.match(/\/(\d+)\s*$/); if (m) total = Number(m[1]);
    const buf = Buffer.from(await res.arrayBuffer());
    start === 0 ? writeFileSync(part, buf) : appendFileSync(part, buf);
    start += buf.length;
    if (!buf.length) break;
  }
  renameSync(part, destPath);
  return destPath;
}

// ---- self-reported agent runtime metadata (model / harness / interface) ----
// Extends the Buzz agent-card schema. Overridable per-session via env so each
// agent declares what it actually is; defaults suit a Claude Code CLI session.
const AGENT_MODEL = process.env.BUZZ_MODEL || process.env.ANTHROPIC_MODEL || "anthropic:claude";
const AGENT_HARNESS = process.env.BUZZ_HARNESS || "claude-code";   // claude-code | codex | goose | cursor | ...
const AGENT_INTERFACE = process.env.BUZZ_INTERFACE || "terminal";  // terminal | gui | web | ide-plugin
const KIND_AGENT_PROFILE = 10100; // Buzz: agent metadata (replaceable, agent-authored)

// publish this session's kind:0 profile (friendly name) enriched with model/harness/
// interface, plus a structured kind:10100 agent card, so the fleet sees what each
// agent actually is (which model, which harness, which interface).
async function publishProfile(name) {
  MY_NAME = name;
  const host = hostname().split(".")[0];
  const profile = {
    display_name: name, name,
    about: `${AGENT_MODEL} · ${AGENT_HARNESS} · ${AGENT_INTERFACE} · ${host}`,
    model: AGENT_MODEL, harness: AGENT_HARNESS, interface: AGENT_INTERFACE,
  };
  const ev = await signer.sign({ kind: 0, tags: AUTH_TAG ? [AUTH_TAG] : [], content: JSON.stringify(profile) });
  const res = await bridge("/events", ev);
  // best-effort structured agent card (relay may gate the kind; the kind:0 above always applies)
  try {
    const card = { name, model: AGENT_MODEL, harness: AGENT_HARNESS, interface: AGENT_INTERFACE, host, identity: "Ekam-governed" };
    const cardEv = await signer.sign({
      kind: KIND_AGENT_PROFILE,
      tags: [["model", AGENT_MODEL], ["harness", AGENT_HARNESS], ["interface", AGENT_INTERFACE], ["L", "agent-card"]],
      content: JSON.stringify(card),
    });
    await bridge("/events", cardEv);
  } catch { /* non-fatal */ }
  return res;
}

// ---- helpers: resolve channels + display names ----
async function channels() {
  // Member-first discovery. The old broad {kinds:[39000], limit:100} directory
  // scan is limit-truncated, so once the workspace has many channels a private
  // agent channel (e.g. navendu-agents-laptop) falls past the limit and can no
  // longer be resolved by name — which silently breaks the agent bus. Instead
  // find the channels THIS identity is a member of via its kind:39002 events
  // (#p = me; the relay synthesizes these from authoritative channel_members),
  // then fetch only those channels' kind:39000 metadata. Membership scope is a
  // handful of channels and cannot overflow the limit.
  const memberEvs = await query([{ kinds: [39002], "#p": [PK], limit: 1000 }]);
  const ids = [...new Set((memberEvs || []).map((e) => {
    const t = Object.fromEntries((e.tags || []).map((x) => [x[0], x[1]]));
    return t.d;
  }).filter(Boolean))];
  if (!ids.length) return [];
  const metaEvs = await query([{ kinds: [39000], "#d": ids, limit: 1000 }]);
  return (metaEvs || []).map((e) => {
    const t = Object.fromEntries((e.tags || []).map((x) => [x[0], x[1]]));
    return { id: t.d, name: t.name || "(unnamed)", about: t.about || "" };
  }).filter((c) => c.id);
}
async function profiles() {
  const evs = await query([{ kinds: [0], limit: 200 }]);
  const m = {};
  for (const e of evs || []) { try { const c = JSON.parse(e.content); m[e.pubkey] = c.display_name || c.name || e.pubkey.slice(0, 8); } catch {} }
  return m;
}
async function resolveChannel(nameOrId) {
  const cs = await channels();
  const hit = cs.find((c) => c.id === nameOrId) || cs.find((c) => c.name.toLowerCase() === String(nameOrId).toLowerCase());
  if (!hit) throw new Error(`channel not found: ${nameOrId}. Available: ${cs.map((c) => c.name).join(", ")}`);
  return hit;
}

// ---- DM helpers (v0.2.1) ----
// DMs are dm-type channels (kind:39000 with a ["t","dm"] tag) carrying kind:9 messages,
// membership-gated. Discovery reuses the member-first path; participants are the p-tags
// on the 39000. Opening a DM is a kind:41010 (DM_OPEN) command; sending is a kind:9.
async function dmChannels() {
  const memberEvs = await query([{ kinds: [39002], "#p": [PK], limit: 1000 }]);
  const ids = [...new Set((memberEvs || []).map((e) => Object.fromEntries((e.tags || []).map((x) => [x[0], x[1]])).d).filter(Boolean))];
  if (!ids.length) return [];
  const metaEvs = await query([{ kinds: [39000], "#d": ids, limit: 1000 }]);
  return (metaEvs || [])
    .filter((e) => (e.tags || []).some((t) => t[0] === "t" && t[1] === "dm"))
    .map((e) => {
      const t = Object.fromEntries((e.tags || []).map((x) => [x[0], x[1]]));
      const participants = [...new Set((e.tags || []).filter((x) => x[0] === "p").map((x) => x[1]))];
      return { id: t.d, name: t.name || "DM", participants, others: participants.filter((p) => p !== PK) };
    })
    .filter((c) => c.id);
}
// Resolve a recipient token → pubkey hex. npub / hex / exact display-name today;
// email → Ekam directory resolver (v0.2.1, isolated in resolveEmail below).
async function resolveRecipient(to) {
  const s = String(to || "").trim();
  if (/^[0-9a-f]{64}$/i.test(s)) return s.toLowerCase();
  if (s.startsWith("npub")) { const d = nip19.decode(s); if (d.type === "npub") return d.data; throw new Error(`bad npub: ${s}`); }
  if (s.includes("@")) return await resolveEmail(s);
  const names = await profiles();
  const hits = Object.entries(names).filter(([, n]) => String(n).toLowerCase() === s.toLowerCase()).map(([pk]) => pk);
  if (hits.length === 1) return hits[0];
  if (hits.length > 1) throw new Error(`"${to}" is ambiguous (${hits.length} people share that name) — use an npub or email`);
  throw new Error(`can't resolve recipient "${to}" — pass an npub, hex pubkey, email, or exact display name`);
}
// email→pubkey via Ekam's directory resolver (ekam #324): GET /v1/directory/resolve?email=,
// bearer the wire:sign token (same WHO-gate, no new credential). Returns the CANONICAL live
// pubkey for governed recipients only — a `404 not_governed` is the SAFE signal to fall back
// to npub/name (Ekam won't mint a device-key user a key they never read on). Wire-mode only.
async function resolveEmail(email) {
  if (signer.mode !== "wire" || typeof signer.ekamToken !== "function")
    throw new Error(`email addressing needs wire mode ("post as me") — pass an npub, hex pubkey, or exact display name instead`);
  const base = (signer.ekamBase ? signer.ekamBase() : (process.env.BUZZ_EKAM_BASE || "https://ekam.olakrutrim.com")).replace(/\/+$/, "");
  const res = await fetch(`${base}/v1/directory/resolve?email=${encodeURIComponent(email)}`, { headers: { Authorization: `Bearer ${await signer.ekamToken()}` } });
  const text = await res.text();
  if (res.ok) {
    let j; try { j = JSON.parse(text); } catch { throw new Error(`directory resolve returned non-JSON: ${text.slice(0, 120)}`); }
    if (j.nostr_pub && /^[0-9a-f]{64}$/i.test(j.nostr_pub)) return j.nostr_pub.toLowerCase();
    throw new Error(`directory resolve returned no nostr_pub for "${email}": ${text.slice(0, 120)}`);
  }
  let err = ""; try { err = JSON.parse(text).error || ""; } catch { /* keep */ }
  if (res.status === 404 && err === "not_governed")
    throw new Error(`"${email}" has no Ekam wire identity yet (device-key user) — DM them by npub or display name instead`);
  if (res.status === 404)
    throw new Error(`no directory identity for "${email}" in your workspace`);
  throw new Error(`directory resolve "${email}" -> HTTP ${res.status}: ${text.slice(0, 120)}`);
}
// Open (idempotent) a DM with the given OTHER-participant pubkeys → { channelId, created }.
async function openDm(others) {
  if (!others.length || others.length > 8) throw new Error(`a DM needs 1–8 other participants (got ${others.length})`);
  const ev = await signer.sign({ kind: 41010, tags: others.map((p) => ["p", p]), content: "" });
  const res = await bridge("/events", ev);
  let channelId = null, created = null;
  try { const j = JSON.parse(String((res && res.message) || "").replace(/^response:/, "")); channelId = j.channel_id; created = j.created; } catch { /* fall back to listing */ }
  if (!channelId) {
    const set = new Set(others);
    const hit = (await dmChannels()).find((c) => c.others.length === others.length && c.others.every((p) => set.has(p)));
    channelId = hit && hit.id;
  }
  if (!channelId) throw new Error("open_dm: relay did not return a channel id");
  return { channelId, created };
}

// ---- shared target/mention helpers (v0.2.13: reused by buzz_reply / buzz_forward) ----
// Resolve a message target IN a named channel and FAIL CLOSED if it isn't there — the same
// channel-scoped resolution buzz_react/buzz_delete inline: a full 64-hex id → exact (ids+#h)
// lookup; a short <id> prefix from buzz_read → a recency scan matched by prefix (ambiguity
// refused); then the h-tag is asserted so the resolved hit is proven to belong to this channel
// (never an unproven or cross-channel target). Returns the whole event.
async function resolveEventInChannel(chId, chName, rawEvent) {
  const targetId = String(rawEvent || "").trim();
  if (!targetId) throw new Error("a target event <id> is required (from buzz_read)");
  const isFullId = /^[0-9a-f]{64}$/i.test(targetId);
  let hit = null;
  if (isFullId) {
    hit = (await query([{ ids: [targetId], "#h": [chId] }]) || [])[0];
    if (!hit) throw new Error(`message ${targetId.slice(0, 8)}… is not in #${chName} — the target must be a message in the channel you name`);
  } else {
    // NEVER put a prefix in an `ids` filter — the relay rejects a non-64-hex id.
    const recent = await query([{ kinds: [9], "#h": [chId], limit: 200 }]) || [];
    const pref = recent.filter((e) => String(e.id).startsWith(targetId));
    if (pref.length > 1) throw new Error(`event id "${targetId}" is ambiguous in #${chName} (${pref.length} matches) — use more characters`);
    hit = pref[0];
    if (!hit) throw new Error(`no message with id "${targetId}" found in #${chName} — use the <id> shown by buzz_read`);
  }
  if (!(hit.tags || []).some((t) => t[0] === "h" && t[1] === chId))
    throw new Error(`target message is not bound to #${chName} — refusing a cross-channel operation`);
  return hit;
}
// @-mention → p-tag pubkeys. Same multi-key index buzz_post uses so @Pulse resolves even when the
// display name carries an icon/space ("Pulse 💓") or punctuation ("bharatrouter·falcon").
function mentionPtags(text, names) {
  const byName = {};
  for (const [pk, n] of Object.entries(names)) {
    const low = String(n).toLowerCase();
    const keys = new Set([low, low.replace(/[^a-z0-9]+/g, ""), (low.match(/[a-z0-9]+/) || [""])[0]]);
    for (const k of keys) if (k && !(k in byName)) byName[k] = pk;
  }
  const out = [];
  for (const m of (String(text).match(/@([A-Za-z0-9_-]+)/g) || [])) {
    const pk = byName[m.slice(1).toLowerCase()];
    if (pk && !out.includes(pk)) out.push(pk);
  }
  return out;
}

// ---- MCP server ----
const server = new Server({ name: "buzz", version: SHIM_VERSION }, { capabilities: { tools: {} } });

const TOOLS = [
  { name: "buzz_whoami", description: "Show this CLI session's Buzz identity (friendly name + npub + pubkey).", inputSchema: { type: "object", properties: {} } },
  { name: "buzz_setname", description: "Override this session's friendly display name on the fleet.", inputSchema: { type: "object", properties: { name: { type: "string" } }, required: ["name"] } },
  { name: "buzz_channels", description: "List channels in the Buzz workspace.", inputSchema: { type: "object", properties: {} } },
  { name: "buzz_agents", description: "List known agents/people (display name + pubkey) on the relay.", inputSchema: { type: "object", properties: {} } },
  { name: "buzz_search", description: "Full-text search recent messages across your channels (NIP-50). Optional `channel` to scope, `limit` (default 20).", inputSchema: { type: "object", properties: { query: { type: "string" }, channel: { type: "string" }, limit: { type: "number" } }, required: ["query"] } },
  { name: "buzz_channel_members", description: "List the members of a channel (display name + owner/member role).", inputSchema: { type: "object", properties: { channel: { type: "string" } }, required: ["channel"] } },
  { name: "buzz_read", description: "Read recent messages in a channel (by name or id).", inputSchema: { type: "object", properties: { channel: { type: "string" }, limit: { type: "number" } }, required: ["channel"] } },
  { name: "buzz_post", description: "Post a message to a channel. The body goes in `text` (its alias `message` is also accepted). Use @Name to mention an agent (resolved to a p-tag so the agent is triggered). Optional `attachment` = a local file path to upload and attach.", inputSchema: { type: "object", properties: { channel: { type: "string" }, text: { type: "string" }, message: { type: "string", description: "alias for `text` (accepted if `text` is omitted)" }, attachment: { type: "string", description: "local file path to upload + attach (image/doc/video, per-type size caps apply)" } }, required: ["channel"] } },
  { name: "buzz_attachment_read", description: "Download an attachment from a message you can read and return it (text extracted for docs; a saved file path otherwise). Identify the message by `channel` + `event` (the <id> from buzz_read); if the message has multiple attachments, pass `index` (default 0).", inputSchema: { type: "object", properties: { channel: { type: "string" }, event: { type: "string", description: "the target message's <id> (from buzz_read)" }, index: { type: "number", description: "which attachment on the message (default 0)" } }, required: ["channel", "event"] } },
  { name: "buzz_react", description: "React to a message with an emoji (NIP-25). Needs the channel and the target message's event id; reacts as this identity. Default emoji is 👍.", inputSchema: { type: "object", properties: { channel: { type: "string" }, event: { type: "string", description: "the target message's event id (from buzz_read)" }, emoji: { type: "string", description: "the reaction emoji; defaults to 👍" } }, required: ["channel", "event"] } },
  { name: "buzz_reply", description: "Reply to a message in a channel, threaded per NIP-10 (kind 9). Needs `channel` + `event` (the <id> from buzz_read); the reply body goes in `text` (its alias `message` is also accepted). Threads under the original via marked e-tags (root/reply). Use @Name to mention agents; optional `attachment` = a local file path to upload + attach.", inputSchema: { type: "object", properties: { channel: { type: "string" }, event: { type: "string", description: "the message being replied to (<id> from buzz_read)" }, text: { type: "string" }, message: { type: "string", description: "alias for `text` (accepted if `text` is omitted)" }, attachment: { type: "string", description: "local file path to upload + attach" } }, required: ["channel", "event"] } },
  { name: "buzz_forward", description: "Forward (quote) a message to another channel or person as a link-back pill (kind 9) — it REFERENCES the source event, it does not copy the original text. `source_channel` + `event` identify the message; `to` = a channel (name/id) OR a person (npub / hex / email / exact display-name, DM'd). Optional `comment` becomes your note (empty allowed).", inputSchema: { type: "object", properties: { source_channel: { type: "string" }, event: { type: "string", description: "the message to forward (<id> from buzz_read)" }, to: { type: "string", description: "target channel (name/id) or person (npub / hex / email / display-name)" }, comment: { type: "string", description: "optional note posted with the pill (empty allowed)" } }, required: ["source_channel", "event", "to"] } },
  { name: "buzz_add_member", description: "Add a person to a channel (NIP-29 kind 9000), as you. The relay only allows it where your OWN role permits (private channels need you to be a member; elevated roles need owner/admin). NOTE: the added person can then see the channel's prior history. `user` = npub / hex pubkey / exact display-name / email; optional `role` (member|admin|owner|guest|bot).", inputSchema: { type: "object", properties: { channel: { type: "string" }, user: { type: "string", description: "npub / hex pubkey / exact display name / email" }, role: { type: "string", description: "member|admin|owner|guest|bot (default member; elevated needs your owner/admin)" } }, required: ["channel", "user"] } },
  { name: "buzz_remove_member", description: "Remove a person from a channel (NIP-29 kind 9001), as you. Destructive: the relay only allows it where your OWN role permits (owner/admin). `user` = npub / hex pubkey / exact display-name / email.", inputSchema: { type: "object", properties: { channel: { type: "string" }, user: { type: "string", description: "npub / hex pubkey / exact display name / email" } }, required: ["channel", "user"] } },
  { name: "buzz_delete", description: "Delete a message in a channel (NIP-29 kind 9005), as you. Destructive: the relay only allows it where your OWN role permits (owner/admin). Identify the message by `channel` + `event` (the <id> from buzz_read).", inputSchema: { type: "object", properties: { channel: { type: "string" }, event: { type: "string", description: "the target message's <id> (from buzz_read)" } }, required: ["channel", "event"] } },
  { name: "buzz_dm_list", description: "List your direct-message conversations (other participant + dm channel id).", inputSchema: { type: "object", properties: {} } },
  { name: "buzz_dm_read", description: "Read a direct-message conversation. Identify it by `to` (npub / hex / email / exact display-name of the other person) or `channel` (dm channel id).", inputSchema: { type: "object", properties: { to: { type: "string" }, channel: { type: "string" }, limit: { type: "number" } } } },
  { name: "buzz_dm_open", description: "Open (or find) a 1:1 DM with a person and return its channel id. `to` = npub / hex / email / exact display-name.", inputSchema: { type: "object", properties: { to: { type: "string" } }, required: ["to"] } },
  { name: "buzz_dm_send", description: "Send a direct message to a person — opens the 1:1 if needed, then sends. `to` = npub / hex / email / exact display-name. The body goes in `text` (its alias `message` is also accepted).", inputSchema: { type: "object", properties: { to: { type: "string" }, text: { type: "string" }, message: { type: "string", description: "alias for `text` (accepted if `text` is omitted)" } }, required: ["to"] } },
  { name: "buzz_status_set", description: "Set your live user status (NIP-38 kind 30315, d=general). `text` = the status message (empty allowed), optional `emoji`. AGENT MODE ONLY — wire mode (post-as-the-user) can't sign kind 30315 yet, so it refuses there.", inputSchema: { type: "object", properties: { text: { type: "string", description: "the status text (empty allowed)" }, emoji: { type: "string", description: "optional status emoji" } } } },
  { name: "buzz_status_clear", description: "Clear your live user status (NIP-38 kind 30315 with empty content, d=general — a replaceable-event clear). AGENT MODE ONLY — wire mode can't sign kind 30315 yet, so it refuses there.", inputSchema: { type: "object", properties: {} } },
  { name: "buzz_unread", description: "Read-only activity digest: across your channels and DMs, count recent messages from others (last `hours`, default 24) and how many @mention you. A heuristic (NOT real read-state) — it performs no writes.", inputSchema: { type: "object", properties: { hours: { type: "number", description: "look-back window in hours (default 24)" } } } },
  { name: "buzz_login", description: "Sign in as YOURSELF for \"post as me\" (Ekam wire-sign OAuth) WITHOUT a terminal — for GUI/desktop (Claude Desktop/MCPB) clients that can't run the buzz-mcp-login CLI. NON-BLOCKING: the first call returns a URL to approve in your browser (it also tries to open it) and returns immediately; after you approve, call buzz_login again — or buzz_whoami — to confirm. Idempotent: if you're already connected it says so. Optional `client_id` (else env BUZZ_EKAM_CLIENT_ID).", inputSchema: { type: "object", properties: { client_id: { type: "string", description: "Ekam OAuth client id (from DCR); falls back to env BUZZ_EKAM_CLIENT_ID" } } } },
  { name: "buzz_doctor", description: "Diagnose why Buzz reads/posts are failing, WITHOUT using the shim's normal (possibly-wedged) transport — it probes the relay over a brand-new node:https socket. Read-only; no writes. Returns a 3-way diagnosis: (1) relay answers but your normal client is stuck → WEDGED CLIENT POOL → restart your MCP client; (2) the relay does not answer → RELAY UNREACHABLE → wait / check status; (3) an authed probe is rejected → LAPSED GRANT → re-run buzz_login. Also reports your identity, pin status, and relay dial URL. Connector-side probe only — not the authoritative relay health signal. Optional `timeout_s` (default 5).", inputSchema: { type: "object", properties: { timeout_s: { type: "number", description: "per-probe timeout in seconds (default 5, max 30)" } } } },
];

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

// ---- environment self-check: surface the relay's OWN self-report + key provenance,
// so no "live"/identity claim is ever made blind (see: 3x non-prod false-positives). ----
let RELAY_INFO = null, RELAY_INFO_AT = 0;
const RELAY_INFO_TTL = 30_000; // re-fetch NIP-11 if older than 30s, so a mid-session relay roll (software_sha) is visible instead of a process-lifetime stale cache
async function relayInfo() {
  if (RELAY_INFO && Date.now() - RELAY_INFO_AT < RELAY_INFO_TTL) return RELAY_INFO;
  try {
    const r = await fetch(`${RELAY}/`, { headers: { Accept: "application/nostr+json" } });
    const j = await r.json();
    RELAY_INFO = { name: j.name || "?", software: j.software || "?", version: j.version || "?", sha: j.software_sha || null };
  } catch (e) { RELAY_INFO = { error: e.message }; }
  RELAY_INFO_AT = Date.now();
  return RELAY_INFO;
}
const keyProvenance = () => {
  // wire mode: no key on this host at all — Ekam signs each event with the user's
  // escrowed key via a revocable token. The impersonation pin still applies to PK.
  if (signer.mode === "wire") {
    const base = "wire-sign (Ekam human token; NO key on disk) — posts AS the user";
    if (EXPECTED_PK) return IDENTITY_OK ? `${base}; pin VERIFIED ✅` : `⚠ IMPERSONATION GUARD TRIPPED: user pubkey ${PK.slice(0, 16)}… ≠ expected ${EXPECTED_PK.slice(0, 16)}… — WRITES DISABLED`;
    return base;
  }
  const base = (process.env.BUZZ_PRIVATE_KEY || process.env.BUZZ_IDENTITY_KEY)
    ? "key-pinned via env" : "⚠ no key in env — keyring or RANDOM per-session";
  if (EXPECTED_PK) return IDENTITY_OK
    ? `${base}; pin VERIFIED ✅ (matches BUZZ_EXPECTED_PUBKEY)`
    : `⚠ IMPERSONATION GUARD TRIPPED: key ${PK.slice(0, 16)}… ≠ expected ${EXPECTED_PK.slice(0, 16)}… — WRITES DISABLED`;
  return `${base} (no BUZZ_EXPECTED_PUBKEY — set it to fail-closed on mis-pin)`;
};

// buzz_login (v0.2.15) flow state. Module-level so a later buzz_login/buzz_whoami call can
// observe a flow started by an earlier call (the callback completes out-of-band, in the
// loopback server's request handler). null = no flow; else { srv, verifier, state, redirectUri,
// clientId, status: "pending"|"done"|"error"|"expired", authUrl, expires (epoch ms), error? }.
let pendingLogin = null;

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: a = {} } = req.params;
  const ok = (s) => ({ content: [{ type: "text", text: s }] });
  try {
    if (name === "buzz_whoami") {
      const info = await relayInfo();
      const relayLine = info.error ? `⚠ UNREACHABLE: ${info.error}` : `${info.name} · v${info.version}${info.sha ? ` · deploy ${info.sha.slice(0, 12)}` : " · (no software_sha — stale build?)"}`;
      const configLine = IS_ISOLATED ? "isolated ✅ (own CLAUDE_CONFIG_DIR)" : `⚠ SHARED ~/.claude.json — clobberable/flip-prone. Relaunch via 'buzz-claude ${MY_NAME}' to isolate. Guide: ${GUIDE_PATH}`;
      return ok(`Buzz CLI identity:\n  name: ${MY_NAME}\n  shim: @ola/buzz-mcp v${SHIM_VERSION}\n  model: ${AGENT_MODEL}\n  harness: ${AGENT_HARNESS}\n  interface: ${AGENT_INTERFACE}\n  npub: ${nip19.npubEncode(PK)}\n  pubkey: ${PK}\n  identity: ${keyProvenance()}\n  config: ${configLine}\n  relay (dial): ${RELAY}\n  relay (self-report): ${relayLine}\n  auth_tag: ${AUTH_TAG ? "present (ViaOwner delegation)" : "none"}\n  transport: ${TRANSPORT_WEDGED ? "⚠ undici pool wedged — self-healing via fresh node:https sockets (reads/posts still work); a full client RESTART clears it" : "ok"}\n  NOTE: the deploy SHA above is the LIVE prod build (relay's software_sha) — compare it before claiming "X is deployed". reachable ≠ up-to-date.`);
    }

    if (name === "buzz_setname") {
      if (!IDENTITY_OK) return { content: [{ type: "text", text: `refused: impersonation guard — key ${PK.slice(0, 16)}… ≠ pinned ${EXPECTED_PK.slice(0, 16)}… (running as ${MY_NAME}). Not writing a profile as the wrong agent.` }], isError: true };
      if (signer.mode === "wire") return { content: [{ type: "text", text: `refused: wire mode posts as the user — the display name is the user's own profile (kind:0), not settable from the shim.` }], isError: true };
      await publishProfile(a.name);
      return ok(`renamed this session to "${a.name}" on the fleet.`);
    }

    if (name === "buzz_channels") {
      const cs = await channels();
      return ok(cs.length ? cs.map((c) => `#${c.name}  [${c.id}]  ${c.about}`).join("\n") : "(no channels)");
    }

    if (name === "buzz_agents") {
      const p = await profiles();
      return ok(Object.entries(p).map(([pk, n]) => `${n}  ${pk.slice(0, 12)}…`).join("\n") || "(none)");
    }

    if (name === "buzz_read") {
      const ch = await resolveChannel(a.channel);
      const names = await profiles();
      const evs = await query([{ kinds: [9], "#h": [ch.id], limit: a.limit || 30 }]);
      const rows = (evs || []).sort((x, y) => x.created_at - y.created_at).map((e) => {
        const who = names[e.pubkey] || e.pubkey.slice(0, 8);
        const t = fmtTime(e.created_at);
        // include a short event id so buzz_react/buzz_attachment_read has a target, + 📎 for attachments.
        const atts = messageAttachments(e);
        const att = atts.length ? " " + atts.map((x) => `📎${x.filename || x.mime || "file"}`).join("") : "";
        return `[${t}] ${who} <${String(e.id).slice(0, 8)}>${att}: ${e.content}`;
      });
      return ok(`#${ch.name} (${rows.length} msgs) — <id> = react target:\n` + (rows.join("\n") || "(empty)"));
    }

    if (name === "buzz_search") {
      const q = String(a.query || "").trim();
      if (!q) throw new Error("buzz_search needs a `query` string");
      const names = await profiles();
      const cs = await channels();
      const chById = Object.fromEntries(cs.map((c) => [c.id, c.name]));
      const filt = { kinds: [9], search: q, limit: Math.min(a.limit || 20, 100) };
      let scope = "";
      if (a.channel) { const ch = await resolveChannel(a.channel); filt["#h"] = [ch.id]; scope = ` in #${ch.name}`; }
      const evs = await query([filt]);
      const rows = (evs || []).sort((x, y) => y.created_at - x.created_at).map((e) => {
        const who = names[e.pubkey] || e.pubkey.slice(0, 8);
        const hTag = (e.tags || []).find((t) => t[0] === "h");
        const chan = hTag ? (chById[hTag[1]] || hTag[1].slice(0, 8)) : "?";
        const t = fmtTime(e.created_at, true);
        return `#${chan} [${t}] ${who} <${String(e.id).slice(0, 8)}>: ${e.content}`;
      });
      return ok(`search "${q}"${scope} → ${rows.length} result(s):\n` + (rows.join("\n") || "(none)"));
    }

    if (name === "buzz_channel_members") {
      const ch = await resolveChannel(a.channel);
      const names = await profiles();
      const evs = await query([{ kinds: [39002], "#d": [ch.id], limit: 5 }]);
      // kind:39002 = one membership event per channel; p-tags are members, tag[3] = role (owner|member).
      const seen = new Map();
      for (const e of evs || []) for (const tg of e.tags || []) if (tg[0] === "p" && tg[1] && !seen.has(tg[1])) seen.set(tg[1], tg[3] || "member");
      const rows = [...seen].map(([pk, role]) => `${names[pk] || pk.slice(0, 12) + "…"}${role === "owner" ? " (owner)" : ""}`);
      return ok(`#${ch.name} — ${rows.length} member(s):\n` + (rows.join("\n") || "(none)"));
    }

    if (name === "buzz_post") {
      if (!IDENTITY_OK) return { content: [{ type: "text", text: `refused: impersonation guard — this session's key ${PK.slice(0, 16)}… ≠ pinned identity ${EXPECTED_PK.slice(0, 16)}…. Not posting as the wrong agent. Fix your pin, or launch with your own CLAUDE_CONFIG_DIR.` }], isError: true };
      // Accept the body under `text` (schema) OR `message` (a common client mis-key that dropped
      // the body silently — bossman [08:55]: dbre + likely Bhavish hit exactly this). Fail LOUD
      // only when BOTH are empty — never publish a blank post, never a cryptic "reading 'match'".
      const bodyText = (typeof a.text === "string" && a.text.trim()) ? a.text
        : (typeof a.message === "string" && a.message.trim()) ? a.message : null;
      if (bodyText === null)
        return { content: [{ type: "text", text: "buzz_post requires a non-empty `text` (its `message` alias is also accepted)." }], isError: true };
      const ch = await resolveChannel(a.channel);
      const names = await profiles();
      // Index each identity under several keys so @Pulse resolves even when the
      // display name carries an icon/space (e.g. "Pulse 💓") or punctuation
      // (e.g. "bharatrouter·falcon"): full-normalized, spaceless, and first token.
      const byName = {};
      for (const [pk, n] of Object.entries(names)) {
        const low = n.toLowerCase();
        const keys = new Set([
          low,
          low.replace(/[^a-z0-9]+/g, ""),            // "pulse💓"->"pulse", strip icon/space
          (low.match(/[a-z0-9]+/) || [""])[0],       // first alnum token: "pulse"
        ]);
        for (const k of keys) if (k && !(k in byName)) byName[k] = pk;
      }
      const tags = [["h", ch.id]];
      if (AUTH_TAG) tags.push(AUTH_TAG);   // NIP-OA owner attestation → "Agent managed by <owner>"
      for (const m of (bodyText.match(/@([A-Za-z0-9_-]+)/g) || [])) {
        const pk = byName[m.slice(1).toLowerCase()];
        if (pk) tags.push(["p", pk]);
      }
      // Optional attachment: upload the local file (Blossom) → attach a NIP-92 imeta tag
      // whose url/x match exactly what was uploaded (hash-bound). Content echoes the url too,
      // matching how Buzz clients render attachments.
      let attached = null, content = bodyText;
      if (a.attachment) {
        const up = await blossomUpload(String(a.attachment));
        tags.push(buildImeta(up));
        content = content ? `${content}\n${up.url}` : up.url;
        attached = up;
      }
      const ev = await signer.sign({ kind: 9, tags, content });
      await bridge("/events", ev);
      const mentioned = tags.filter((t) => t[0] === "p").length;
      return ok(`posted to #${ch.name}${mentioned ? ` (mentioned ${mentioned})` : ""}${attached ? ` [+attachment ${attached.filename}, ${(attached.size / MB).toFixed(1)} MB]` : ""}: ${bodyText}`);
    }

    if (name === "buzz_attachment_read") {
      const ch = await resolveChannel(a.channel);
      const targetId = String(a.event || "").trim();
      if (!targetId) throw new Error("buzz_attachment_read needs the message <id> (from buzz_read)");
      // Resolve the target IN this channel (target-bound; never an arbitrary URL) — same
      // channel-scoped resolution as buzz_react, so we only fetch attachments off a message
      // the caller can actually read here. [codex_kavach constraint #3]
      const isFull = /^[0-9a-f]{64}$/i.test(targetId);
      let hit = null;
      if (isFull) hit = (await query([{ ids: [targetId], "#h": [ch.id] }]) || [])[0];
      else {
        const recent = await query([{ kinds: [9], "#h": [ch.id], limit: 200 }]) || [];
        const pref = recent.filter((e) => String(e.id).startsWith(targetId));
        if (pref.length > 1) throw new Error(`event id "${targetId}" is ambiguous in #${ch.name} (${pref.length} matches) — use more characters`);
        hit = pref[0];
      }
      if (!hit) throw new Error(`no message ${targetId.slice(0, 8)}… in #${ch.name} — use the <id> from buzz_read`);
      const atts = messageAttachments(hit);
      if (!atts.length) return ok(`message <${String(hit.id).slice(0, 8)}> in #${ch.name} has no attachments.`);
      const idx = Number.isInteger(a.index) ? a.index : 0;
      const att = atts[idx];
      if (!att) throw new Error(`attachment index ${idx} out of range — message has ${atts.length} (0..${atts.length - 1})`);
      if (!att.sha256) throw new Error(`attachment has no sha256 (x tag) — refusing to fetch an unverifiable blob`);
      const shaExt = basename(new URL(att.url).pathname); // "<sha>.<ext>"
      const ext = extname(shaExt) || (att.filename ? extname(att.filename) : "");
      const dest = join(tmpdir(), `buzz-att-${att.sha256.slice(0, 16)}${ext}`);
      await blossomDownload(shaExt, dest);
      const got = await sha256File(dest);
      if (got !== att.sha256) throw new Error(`integrity check failed: downloaded ${got.slice(0, 12)}… ≠ imeta ${att.sha256.slice(0, 12)}… — discarded`);
      const size = statSync(dest).size;
      const isText = (att.mime && TEXT_MIME.test(att.mime)) || /\.(md|txt|csv|json|ya?ml|log|tsv)$/i.test(att.filename || shaExt);
      if (isText) {
        const full = readFileSync(dest, "utf8");
        const CAP = 200 * 1024;
        const body = full.length > CAP ? `${full.slice(0, CAP)}\n…[truncated ${full.length - CAP} chars — full file at ${dest}]` : full;
        return ok(`📎 ${att.filename || shaExt} (${att.mime || "text"}, ${(size / 1024).toFixed(0)} KB) from #${ch.name}:\n\n${body}`);
      }
      return ok(`📎 saved ${att.filename || shaExt} → ${dest}\n   (${att.mime || "binary"}, ${(size / MB).toFixed(2)} MB, sha ${att.sha256.slice(0, 12)}…) — not text; open the file to view.`);
    }

    if (name === "buzz_react") {
      if (!IDENTITY_OK) return { content: [{ type: "text", text: `refused: impersonation guard — this session's key ${PK.slice(0, 16)}… ≠ pinned identity ${EXPECTED_PK.slice(0, 16)}…. Not reacting as the wrong identity.` }], isError: true };
      const ch = await resolveChannel(a.channel);
      // Resolve the target: accept a full event id OR the short <id> prefix that buzz_read
      // prints. Try an exact id lookup first; if that misses, treat the input as a prefix and
      // find the unique recent message in this channel whose id starts with it. This makes
      // "react to what I just read" work, since buzz_read surfaces the 8-char prefix.
      let targetId = String(a.event || "").trim();
      if (!targetId) throw new Error("buzz_react needs a target event id (the <id> shown by buzz_read) — refusing a target-less reaction");
      const isFullId = /^[0-9a-f]{64}$/i.test(targetId);
      // Resolve the target IN the named channel and FAIL CLOSED if it isn't there. Both paths
      // query with "#h":[ch.id], so a resolved hit is proven to belong to the channel we're
      // reacting in — the shim never signs a reaction to an unproven or cross-channel target
      // (stronger than "has some e tag"; not relying on relay rejection after Ekam signs). [codex_kavach]
      let hit = null;
      if (isFullId) {
        // full event id → channel-scoped exact lookup (works for any age; not a recency scan)
        hit = (await query([{ ids: [targetId], "#h": [ch.id] }]) || [])[0];
        if (!hit) throw new Error(`message ${targetId.slice(0, 8)}… is not in #${ch.name} — reactions must target a message in the channel you name`);
      } else {
        // short <id> prefix from buzz_read → scan THIS channel and match by prefix.
        // NEVER put a prefix in an `ids` filter — the relay rejects a non-64-hex id.
        const recent = await query([{ kinds: [9], "#h": [ch.id], limit: 200 }]) || [];
        const pref = recent.filter((e) => String(e.id).startsWith(targetId));
        if (pref.length > 1) throw new Error(`event id "${targetId}" is ambiguous in #${ch.name} (${pref.length} matches) — use more characters`);
        hit = pref[0];
        if (!hit) throw new Error(`no message with id "${targetId}" found in #${ch.name} — use the <id> shown by buzz_read`);
      }
      // Belt-and-braces: assert the resolved target carries h = this channel before signing.
      if (!(hit.tags || []).some((t) => t[0] === "h" && t[1] === ch.id))
        throw new Error(`target message is not bound to #${ch.name} — refusing a cross-channel reaction`);
      targetId = hit.id;
      const author = hit.pubkey || "", tkind = hit.kind || 9;
      const emoji = (a.emoji && String(a.emoji).trim()) || "👍";
      // reactionTemplate REFUSES a target-less reaction (throws) → surfaced as a tool error.
      const tmpl = reactionTemplate({ targetId, targetAuthor: author, targetKind: tkind, channelId: ch.id, emoji });
      if (AUTH_TAG) tmpl.tags.push(AUTH_TAG);   // owner attestation (agent mode; absent in wire mode)
      const ev = await signer.sign(tmpl);
      await bridge("/events", ev);
      const who = author ? ((await profiles())[author] || author.slice(0, 8)) : "";
      return ok(`reacted ${emoji} to ${who ? `${who}'s ` : ""}message <${String(targetId).slice(0, 8)}> in #${ch.name}`);
    }

    if (name === "buzz_reply") {
      if (!IDENTITY_OK) return { content: [{ type: "text", text: `refused: impersonation guard — this session's key ${PK.slice(0, 16)}… ≠ pinned identity ${(EXPECTED_PK || "").slice(0, 16)}…. Not replying as the wrong identity.` }], isError: true };
      // Same `text`|`message` alias + fail-loud-if-both-empty as buzz_post (self-heals the mis-key class).
      const bodyText = (typeof a.text === "string" && a.text.trim()) ? a.text
        : (typeof a.message === "string" && a.message.trim()) ? a.message : null;
      if (bodyText === null)
        return { content: [{ type: "text", text: "buzz_reply requires a non-empty `text` (its `message` alias is also accepted)." }], isError: true };
      if (!String(a.event || "").trim())
        return { content: [{ type: "text", text: "buzz_reply needs the `event` <id> of the message you're replying to (from buzz_read)." }], isError: true };
      const ch = await resolveChannel(a.channel);
      // Resolve the target IN this channel exactly like buzz_react (ids+#h, prefix-ambiguity refused, h asserted).
      const target = await resolveEventInChannel(ch.id, ch.name, a.event);
      const names = await profiles();
      const tags = [["h", ch.id]];
      if (AUTH_TAG) tags.push(AUTH_TAG);   // NIP-OA owner attestation
      // NIP-10 marked threading. If the target is itself a reply (carries a marked "root" e-tag),
      // thread under that same root and mark the target as the direct reply; otherwise the target
      // IS the root of the thread → a single marked "root" e-tag (a direct reply to the root).
      const rootTag = (target.tags || []).filter((t) => t[0] === "e").find((t) => t[3] === "root");
      const rootId = (rootTag && rootTag[1] && rootTag[1] !== target.id) ? rootTag[1] : null;
      if (rootId) { tags.push(["e", rootId, "", "root"]); tags.push(["e", target.id, "", "reply"]); }
      else tags.push(["e", target.id, "", "root"]);
      // p-tags: the author being replied to (NIP-10) + any @-mentions in the body (buzz_post idiom).
      const ptags = new Set();
      if (/^[0-9a-f]{64}$/i.test(target.pubkey || "")) ptags.add(target.pubkey.toLowerCase());
      for (const pk of mentionPtags(bodyText, names)) ptags.add(pk);
      for (const pk of ptags) tags.push(["p", pk]);
      // Optional attachment: upload the local file (Blossom) → NIP-92 imeta tag, url echoed in content.
      let attached = null, content = bodyText;
      if (a.attachment) {
        const up = await blossomUpload(String(a.attachment));
        tags.push(buildImeta(up));
        content = content ? `${content}\n${up.url}` : up.url;
        attached = up;
      }
      const ev = await signer.sign({ kind: 9, tags, content });
      await bridge("/events", ev);
      const who = names[target.pubkey] || (target.pubkey || "").slice(0, 8);
      const mentioned = tags.filter((t) => t[0] === "p").length;
      return ok(`replied in #${ch.name} to ${who}'s <${String(target.id).slice(0, 8)}>${mentioned ? ` (p-tagged ${mentioned})` : ""}${attached ? ` [+attachment ${attached.filename}, ${(attached.size / MB).toFixed(1)} MB]` : ""}: ${bodyText}`);
    }

    if (name === "buzz_forward") {
      if (!IDENTITY_OK) return { content: [{ type: "text", text: `refused: impersonation guard — this session's key ${PK.slice(0, 16)}… ≠ pinned identity ${(EXPECTED_PK || "").slice(0, 16)}…. Not forwarding as the wrong identity.` }], isError: true };
      if (!String(a.event || "").trim())
        return { content: [{ type: "text", text: "buzz_forward needs the `event` <id> of the message to forward (from buzz_read)." }], isError: true };
      if (!String(a.to || "").trim())
        return { content: [{ type: "text", text: "buzz_forward needs a `to` target — a channel (name/id) or a person (npub / hex / email / display-name)." }], isError: true };
      const src = await resolveChannel(a.source_channel);
      // Resolve the source event IN the source channel (target-bound, like buzz_react).
      const source = await resolveEventInChannel(src.id, src.name, a.event);
      // Destination: try a channel first; if `to` isn't a channel, resolve a person and openDm.
      let destId, destLabel;
      try {
        const dch = await resolveChannel(a.to);
        destId = dch.id; destLabel = `#${dch.name}`;
      } catch {
        const pk = await resolveRecipient(a.to);   // npub / hex / email / exact name → 64-hex, or throws
        const { channelId } = await openDm([pk]);
        destId = channelId;
        destLabel = `DM ${(await profiles())[pk] || pk.slice(0, 8)}`;
      }
      // Link-back PILL, not a copy: reference the SOURCE event (+ its kind for context). content = the
      // optional comment only — never the original text. Clients render the e-tag as a quoted pill.
      const tags = [["h", destId], ["e", source.id], ["k", String(source.kind || 9)]];
      if (AUTH_TAG) tags.push(AUTH_TAG);
      const content = typeof a.comment === "string" ? a.comment : "";
      const ev = await signer.sign({ kind: 9, tags, content });
      await bridge("/events", ev);
      return ok(`forwarded <${String(source.id).slice(0, 8)}> from #${src.name} → ${destLabel}${content ? ` with comment: ${content}` : " (link-back pill, no comment)"}`);
    }

    // ---- Moderation tools (v0.2.7): add / remove members + delete messages, as you.
    // Ekam v206 signs kinds 9000/9001/9005 content-agnostically; the RELAY role-gates each
    // against your OWN role (validate_admin_event), so these can only do what you already can.
    // The shim's job is to fail closed on a malformed/target-less op: every handler resolves a
    // CONCRETE channel + CONCRETE 64-hex target before the template (which re-asserts it) signs. ----
    const modRefuse = (verb) => ({ content: [{ type: "text", text: `refused: impersonation guard — this session's key ${PK.slice(0, 16)}… ≠ pinned identity ${(EXPECTED_PK || "").slice(0, 16)}…. Not ${verb} as the wrong identity.` }], isError: true });

    if (name === "buzz_add_member") {
      if (!IDENTITY_OK) return modRefuse("adding members");
      const ch = await resolveChannel(a.channel);
      const pk = await resolveRecipient(a.user);            // 64-hex or throws (no bare name reaches the signer)
      const tmpl = addMemberTemplate({ channelId: ch.id, targetPubkey: pk, role: a.role });  // re-asserts concrete h + p
      if (AUTH_TAG) tmpl.tags.push(AUTH_TAG);
      const ev = await signer.sign(tmpl);
      await bridge("/events", ev);
      const who = (await profiles())[pk] || pk.slice(0, 12) + "…";
      return ok(`added ${who} to #${ch.name}${a.role ? ` as ${a.role}` : ""}. ⚠️ they can now see this channel's prior history.`);
    }

    if (name === "buzz_remove_member") {
      if (!IDENTITY_OK) return modRefuse("removing members");
      const ch = await resolveChannel(a.channel);
      const pk = await resolveRecipient(a.user);
      const tmpl = removeMemberTemplate({ channelId: ch.id, targetPubkey: pk });
      if (AUTH_TAG) tmpl.tags.push(AUTH_TAG);
      const ev = await signer.sign(tmpl);
      await bridge("/events", ev);
      const who = (await profiles())[pk] || pk.slice(0, 12) + "…";
      return ok(`removed ${who} from #${ch.name}. (Allowed only because the relay confirmed your role permits it.)`);
    }

    if (name === "buzz_delete") {
      if (!IDENTITY_OK) return modRefuse("deleting messages");
      const ch = await resolveChannel(a.channel);
      // Resolve the target message IN the named channel and FAIL CLOSED if it isn't there —
      // same channel-scoped resolution as buzz_react: full id (ids+#h) or short <id> prefix scan,
      // ambiguity refused, h-tag asserted. Never signs a delete against an unproven/cross-channel target.
      let targetId = String(a.event || "").trim();
      if (!targetId) throw new Error("buzz_delete needs a target message <id> (from buzz_read) — refusing a target-less delete");
      const isFullId = /^[0-9a-f]{64}$/i.test(targetId);
      let hit = null;
      if (isFullId) {
        hit = (await query([{ ids: [targetId], "#h": [ch.id] }]) || [])[0];
        if (!hit) throw new Error(`message ${targetId.slice(0, 8)}… is not in #${ch.name} — delete must target a message in the channel you name`);
      } else {
        const recent = await query([{ kinds: [9], "#h": [ch.id], limit: 200 }]) || [];
        const pref = recent.filter((e) => String(e.id).startsWith(targetId));
        if (pref.length > 1) throw new Error(`event id "${targetId}" is ambiguous in #${ch.name} (${pref.length} matches) — use more characters`);
        hit = pref[0];
        if (!hit) throw new Error(`no message with id "${targetId}" found in #${ch.name} — use the <id> shown by buzz_read`);
      }
      if (!(hit.tags || []).some((t) => t[0] === "h" && t[1] === ch.id))
        throw new Error(`target message is not bound to #${ch.name} — refusing a cross-channel delete`);
      targetId = hit.id;
      const tmpl = deleteMessageTemplate({ channelId: ch.id, targetId });  // re-asserts concrete h + e
      if (AUTH_TAG) tmpl.tags.push(AUTH_TAG);
      const ev = await signer.sign(tmpl);
      await bridge("/events", ev);
      return ok(`deleted message <${String(targetId).slice(0, 8)}> in #${ch.name}. (Allowed only because the relay confirmed your role permits it.)`);
    }

    // ---- DM tools (v0.2.1) ----
    const dmRefuse = () => ({ content: [{ type: "text", text: `refused: impersonation guard — this session's key ${PK.slice(0, 16)}… ≠ pinned identity ${(EXPECTED_PK || "").slice(0, 16)}…. Not acting as the wrong identity.` }], isError: true });

    if (name === "buzz_dm_list") {
      const dms = await dmChannels();
      if (!dms.length) return ok("(no direct messages)");
      const names = await profiles();
      return ok(dms.map((c) => {
        const label = c.others.map((p) => names[p] || p.slice(0, 8)).join(", ") || "(just you)";
        return `${label}${c.others.length > 1 ? ` (group, ${c.participants.length})` : ""}  [${c.id}]`;
      }).join("\n"));
    }

    if (name === "buzz_dm_read") {
      let chan = a.channel;
      if (!chan && a.to) {
        const pk = await resolveRecipient(a.to);
        const hit = (await dmChannels()).find((c) => c.others.length === 1 && c.others[0] === pk);
        if (!hit) return ok(`no existing 1:1 DM with ${a.to} yet — use buzz_dm_send to start one.`);
        chan = hit.id;
      }
      if (!chan) return { content: [{ type: "text", text: "buzz_dm_read needs `to` (the other person) or `channel` (dm id)." }], isError: true };
      const names = await profiles();
      const evs = await query([{ kinds: [9], "#h": [chan], limit: a.limit || 30 }]);
      const rows = (evs || []).sort((x, y) => x.created_at - y.created_at).map((e) => {
        const who = names[e.pubkey] || e.pubkey.slice(0, 8);
        const t = fmtTime(e.created_at);
        const atts = messageAttachments(e);
        const att = atts.length ? " " + atts.map((x) => `📎${x.filename || x.mime || "file"}`).join("") : "";
        return `[${t}] ${who} <${String(e.id).slice(0, 8)}>${att}: ${e.content}`;
      });
      return ok(`DM [${chan}] (${rows.length} msgs) — <id> = react target:\n` + (rows.join("\n") || "(empty)"));
    }

    if (name === "buzz_dm_open") {
      if (!IDENTITY_OK) return dmRefuse();
      const pk = await resolveRecipient(a.to);
      const { channelId, created } = await openDm([pk]);
      return ok(`DM ${created ? "opened" : "already exists"} with ${a.to}: ${channelId}`);
    }

    if (name === "buzz_dm_send") {
      if (!IDENTITY_OK) return dmRefuse();
      // Same `text`|`message` alias + fail-loud-if-both-empty as buzz_post (self-heals the class).
      const bodyText = (typeof a.text === "string" && a.text.trim()) ? a.text
        : (typeof a.message === "string" && a.message.trim()) ? a.message : null;
      if (bodyText === null)
        return { content: [{ type: "text", text: "buzz_dm_send requires a non-empty `text` (its `message` alias is also accepted)." }], isError: true };
      const pk = await resolveRecipient(a.to);
      const { channelId } = await openDm([pk]);
      const ev = await signer.sign({ kind: 9, tags: [["h", channelId]], content: bodyText });
      await bridge("/events", ev);
      return ok(`sent DM to ${a.to} [${channelId}]: ${bodyText}`);
    }

    // ---- Live user status (NIP-38 kind 30315) — v0.2.13. AGENT MODE ONLY: 30315 is NOT in the
    // wire-sign allowlist (Ekam doesn't sign it for post-as-me yet), so canSign(30315) fail-closes
    // in wire mode. We deliberately do NOT add 30315 to WIRE_ALLOWLIST. ----
    const STATUS_KIND = 30315;
    if (name === "buzz_status_set") {
      if (!IDENTITY_OK) return { content: [{ type: "text", text: `refused: impersonation guard — this session's key ${PK.slice(0, 16)}… ≠ pinned identity ${(EXPECTED_PK || "").slice(0, 16)}…. Not setting a status as the wrong identity.` }], isError: true };
      if (!signer.canSign(STATUS_KIND))
        return { content: [{ type: "text", text: "buzz_status_set: status (kind 30315) isn't in the wire-sign allowlist — agent-mode only (Ekam doesn't sign it for post-as-me yet)." }], isError: true };
      const text = typeof a.text === "string" ? a.text : "";
      const tags = [["d", "general"]];   // NIP-38 general status
      const emoji = a.emoji && String(a.emoji).trim();
      if (emoji) tags.push(["emoji", emoji]);
      if (AUTH_TAG) tags.push(AUTH_TAG);
      const ev = await signer.sign({ kind: STATUS_KIND, tags, content: text });
      await bridge("/events", ev);
      return ok(`status set${emoji ? ` ${emoji}` : ""}: ${text || "(empty)"}`);
    }

    if (name === "buzz_status_clear") {
      if (!IDENTITY_OK) return { content: [{ type: "text", text: `refused: impersonation guard — this session's key ${PK.slice(0, 16)}… ≠ pinned identity ${(EXPECTED_PK || "").slice(0, 16)}…. Not clearing a status as the wrong identity.` }], isError: true };
      if (!signer.canSign(STATUS_KIND))
        return { content: [{ type: "text", text: "buzz_status_clear: status (kind 30315) isn't in the wire-sign allowlist — agent-mode only (Ekam doesn't sign it for post-as-me yet)." }], isError: true };
      const tags = [["d", "general"]];
      if (AUTH_TAG) tags.push(AUTH_TAG);
      const ev = await signer.sign({ kind: STATUS_KIND, tags, content: "" });
      await bridge("/events", ev);
      return ok("status cleared.");
    }

    // ---- Read-only unread digest (v0.2.13). A HEURISTIC, not NIP-RS real read-state: it counts
    // recent kind:9 from OTHERS per channel/DM and how many @mention this session's PK. No writes. ----
    if (name === "buzz_unread") {
      const hours = (Number.isFinite(a.hours) && a.hours > 0) ? a.hours : 24;
      const since = Math.floor(Date.now() / 1000) - Math.floor(hours * 3600);
      const cs = await channels();
      const dms = await dmChannels();
      const names = await profiles();
      const meta = new Map();   // channel/dm id → display label
      for (const c of cs) meta.set(c.id, `#${c.name}`);
      for (const d of dms) meta.set(d.id, `DM ${d.others.map((p) => names[p] || p.slice(0, 8)).join(", ") || "(self)"}`);
      const ids = [...meta.keys()];
      if (!ids.length) return ok("no channels or DMs to scan.");
      // One round-trip over all h-scopes; bucket the union back by each event's own h-tag.
      const evs = await query([{ kinds: [9], "#h": ids, since, limit: 2000 }]) || [];
      const stat = new Map();   // id → { msgs, mentions }
      for (const e of evs) {
        const id = ((e.tags || []).find((t) => t[0] === "h") || [])[1];
        if (!id || !meta.has(id)) continue;
        if (e.pubkey === PK) continue;   // "unread" = from others, never your own posts
        const s = stat.get(id) || { msgs: 0, mentions: 0 };
        s.msgs++;
        if ((e.tags || []).some((t) => t[0] === "p" && t[1] === PK)) s.mentions++;
        stat.set(id, s);
      }
      const active = [...stat.entries()].sort((x, y) => y[1].msgs - x[1].msgs);
      if (!active.length) return ok(`Unread digest (last ${hours}h): no new messages across ${ids.length} channel(s)/DM(s).`);
      const totMsgs = active.reduce((n, [, s]) => n + s.msgs, 0);
      const totMentions = active.reduce((n, [, s]) => n + s.mentions, 0);
      const lines = active.map(([id, s]) => `  ${meta.get(id)}  —  ${s.msgs} new${s.mentions ? `  (${s.mentions} @you)` : ""}`);
      return ok(`Unread digest (last ${hours}h) — ${active.length} active of ${ids.length}:\n${lines.join("\n")}\nTotals: ${totMsgs} new, ${totMentions} @mention(s) of you.`);
    }

    // ---- buzz_login (v0.2.15): terminal-free "post as me" wire-sign OAuth, in-process. -----
    // Non-blocking + idempotent: never blocks the tool call waiting for the browser (that would
    // hit client tool-timeouts). The loopback callback completes out-of-band and flips
    // pendingLogin.status; a later buzz_login / buzz_whoami observes the result. Reuses the
    // wirelogin.mjs + signer.mjs primitives — no OAuth logic re-implemented here.
    if (name === "buzz_login") {
      const env = process.env;
      const clientId = (a.client_id || env.BUZZ_EKAM_CLIENT_ID || "").trim();
      const base = ekamBase(env);
      const persistId = wirePersistId(env);
      const whoLabel = () => wireNameGet(persistId) || wirePubkeyGet(persistId) || "your account";

      // Observe an existing flow / already-connected state FIRST — none of these need a client id,
      // and an already-connected user should hear "already connected", not a client-id error.
      // (a) a flow that already finished / failed / expired / is still mid-air.
      if (pendingLogin && pendingLogin.status === "done")
        return ok(`✅ connected as ${whoLabel()}. Run buzz_whoami to verify.`);
      if (pendingLogin && pendingLogin.status === "error") {
        const msg = pendingLogin.error || "unknown error";
        pendingLogin = null;   // clear so the next call can retry cleanly
        return { content: [{ type: "text", text: `buzz_login: the previous sign-in attempt failed: ${msg}\nRun buzz_login again to retry.` }], isError: true };
      }
      // auto-abandon: a pending flow that ran past its TTL (the timer below should have flipped it,
      // but observe it here too in case the timer never ran). Clear so this call's fall-through can
      // mint a FRESH link — retry is implicit in re-invoking buzz_login.
      if (pendingLogin && (pendingLogin.status === "expired" || (pendingLogin.status === "pending" && Date.now() >= pendingLogin.expires))) {
        try { pendingLogin.srv.close(); } catch { /* already closing */ }
        pendingLogin = null;
        return { content: [{ type: "text", text: "buzz_login: that sign-in link expired before it was approved. Starting a fresh one — run buzz_login once more to get the new URL." }], isError: true };
      }
      if (pendingLogin && pendingLogin.status === "pending") {
        const mins = Math.max(1, Math.ceil((pendingLogin.expires - Date.now()) / 60000));
        return ok(`still waiting on your browser sign-in — finish at this URL (~${mins} min left):\n${pendingLogin.authUrl}\nAfter you approve, run buzz_login again — or buzz_whoami — to confirm.`);
      }

      // (b) idempotent: already connected (a valid persisted refresh) and no flow in flight.
      if (wireRefreshGet(persistId))
        return ok(`already connected as ${whoLabel()}; run buzz_whoami to verify. (To re-consent, remove the persisted wire refresh, then call buzz_login again.)`);

      // (c) only NOW do we need a client id — it gates starting a new flow, not the states above.
      //     fail LOUD, naming the missing input — no crash.
      if (!clientId)
        return { content: [{ type: "text", text: "buzz_login: no OAuth client id — pass `client_id` or set the BUZZ_EKAM_CLIENT_ID env var (from the Ekam DCR registration). Without it the wire-sign login can't start." }], isError: true };

      // (d) start a NEW flow. Bind a loopback port, build the authorize URL, return immediately.
      const ports = (env.BUZZ_WIRE_LOGIN_PORTS || "8765,8766,8770").split(",").map((s) => parseInt(s.trim(), 10)).filter(Boolean);
      const { verifier, challenge } = pkce();
      const state = randomBytes(16).toString("base64url");
      const { srv, port } = await bindLoopback(ports);
      const redirectUri = `http://127.0.0.1:${port}/callback`;
      const authUrl = authorizeUrl(base, { clientId, redirectUri, challenge, state, resource: base });
      // TTL: how long the loopback listener waits for the browser callback before auto-abandoning.
      // Generous on purpose — a too-tight window (the classic 15s bug) expires mid-login while the
      // person is still approving SSO / verifying email. 5 min, overridable.
      const ttlMs = (parseInt(env.BUZZ_WIRE_LOGIN_TTL_S || "", 10) || 300) * 1000;
      pendingLogin = { srv, verifier, state, redirectUri, clientId, status: "pending", authUrl, expires: Date.now() + ttlMs };

      // The callback runs out-of-band. Wrapped so a failed exchange sets status="error" with the
      // message (never an unhandled throw). Mirrors wirelogin's persist steps at v0.2.13.
      srv.on("request", async (req2, res) => {
        try {
          const u = new URL(req2.url, redirectUri);
          if (u.pathname !== "/callback") { res.writeHead(404); res.end("not found"); return; }
          const oerr = u.searchParams.get("error");
          if (oerr) throw new Error(`authorize error: ${oerr} ${u.searchParams.get("error_description") || ""}`);
          if (u.searchParams.get("state") !== state) throw new Error("state mismatch (possible CSRF) — aborting");
          const code = u.searchParams.get("code");
          if (!code) throw new Error("no authorization code in callback");
          const tok = await exchangeAuthCode(base, { code, verifier, clientId, redirectUri });
          wireRefreshSet(persistId, tok.refresh_token);
          // capture the user's pubkey via one wire-sign probe (so wire mode needs no hand-set key)
          try {
            const probe = await wireSign(base, tok.access_token, { kind: 27235, tags: [["u", `${base}/whoami`], ["method", "GET"], ["payload", ""]], content: "" });
            if (probe?.pubkey) wirePubkeySet(persistId, probe.pubkey);
          } catch { /* pubkey auto-capture best-effort — BUZZ_USER_PUBKEY remains the fallback */ }
          // capture the person's display name (ekam #335: GET /v1/me/wire-key → name) best-effort
          try {
            const wk = await fetch(`${base}/v1/me/wire-key`, { headers: { authorization: `Bearer ${tok.access_token}` } });
            if (wk.ok) { const kj = await wk.json().catch(() => null); if (kj && kj.name) wireNameSet(persistId, String(kj.name)); }
          } catch { /* name is a nicety; the auto-handle remains the fallback */ }
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(`<!doctype html><meta charset="utf-8"><body style="font:15px/1.5 system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;color:#1a1a1a"><h2 style="margin:0 0 .5rem">✅ Buzz is now connected as you</h2><p>Sign-in complete. Return to your client and run buzz_whoami to confirm — your key was never shared with the tool.</p><p style="color:#666">You can safely close this tab.</p></body>`);
          if (pendingLogin) pendingLogin.status = "done";
        } catch (e) {
          try { res.writeHead(400, { "Content-Type": "text/plain" }); res.end("login failed: " + e.message); } catch { /* response may be gone */ }
          if (pendingLogin) { pendingLogin.status = "error"; pendingLogin.error = e.message; }
        } finally {
          try { srv.close(); } catch { /* already closing */ }
        }
      });
      srv.on("error", (e) => { if (pendingLogin) { pendingLogin.status = "error"; pendingLogin.error = e.message; } try { srv.close(); } catch {} });
      // auto-abandon after the TTL: close the loopback port and mark expired so it isn't left
      // listening forever if the person never finishes. .unref() so this timer never, on its own,
      // keeps the MCP process alive (stdio already does).
      const expiryTimer = setTimeout(() => {
        if (pendingLogin && pendingLogin.status === "pending") { pendingLogin.status = "expired"; try { pendingLogin.srv.close(); } catch { /* already closing */ } }
      }, ttlMs);
      if (typeof expiryTimer.unref === "function") expiryTimer.unref();

      // best-effort auto-open the browser (same pattern as wirelogin; the printed URL is the fallback)
      try {
        const [cmd, ...pre] = process.platform === "darwin" ? ["open"]
          : process.platform === "win32" ? ["cmd", "/c", "start", ""]
          : ["xdg-open"];
        spawn(cmd, [...pre, authUrl], { stdio: "ignore", detached: true }).unref();
      } catch { /* printing the URL is the fallback */ }

      return ok(`Opening your browser to sign in as yourself. If it didn't open, use this URL:\n${authUrl}\nThe link is valid for about ${Math.round(ttlMs / 60000)} min — after you approve, run buzz_login again (or buzz_whoami) to confirm. If it expires, just run buzz_login again for a fresh link.`);
    }

    if (name === "buzz_doctor") {
      const timeoutMs = Math.min(30, Math.max(1, Number(a.timeout_s) || 5)) * 1000;
      // Probe over a FRESH socket (rawGet/rawPost, keepAlive:false) — deliberately NOT the shim's
      // normal undici client, which is exactly what may be wedged. Every step below is best-effort
      // and wrapped so buzz_doctor ALWAYS returns a structured diagnosis rather than throwing.
      let classification, recovery, healthLine, authLine;

      // (1) unauthenticated /health — does the relay answer AT ALL over a brand-new socket?
      let health = null, healthErr = null;
      try { health = await rawGet(`${RELAY}/health`, {}, timeoutMs); }
      catch (e) { healthErr = e; }

      if (!health) {
        // No HTTP response at all (connect refused / timeout / DNS) → nothing local can fix this.
        classification = "relay unreachable";
        recovery = "the relay is unreachable — wait / check status; nothing local fixes this";
        healthLine = `unreachable (${(healthErr && (healthErr.code || healthErr.message)) || "no response"})`;
        authLine = "not probed (relay did not answer)";
      } else {
        healthLine = `HTTP ${health.status} over a fresh node:https socket → relay reachable`;
        // Relay answers on a fresh socket. Best-effort AUTHED probe (fresh NIP-98, fresh socket) to
        // tell a lapsed sign-in (401 / auth) apart from a merely-wedged local connection pool. The
        // authed probe has THREE outcomes: "rejected" (a clear 401/auth verdict), "ok" (200/grant
        // OK), or "inconclusive" (the probe ERRORED without a clear verdict — timeout/DNS/TLS/other);
        // an inconclusive probe must NOT be mislabeled as a confident "wedged" diagnosis.
        let authState = "ok";
        try {
          const authz = await nip98(`${SIGN_BASE}/query`, "POST", "[]");
          const probe = await rawPost(`${RELAY}/query`, {
            "Content-Type": "application/json",
            "Authorization": authz,
            ...(AUTH_TAG ? { "x-auth-tag": JSON.stringify(AUTH_TAG) } : {}),
            "x-buzz-client": `agent/${SHIM_VERSION}`,
          }, "[]");
          const ptext = await probe.text();
          if (probe.status === 401 || probe.status === 403 || /nip-?98|unauthor|sign-?in|invalid.?token|revoked|expired/i.test(ptext)) {
            authState = "rejected"; authLine = `authed probe HTTP ${probe.status} → auth rejected`;
          } else {
            authState = "ok"; authLine = `authed probe HTTP ${probe.status} → grant OK`;
          }
        } catch (e) {
          // A wire-mode sign failure (revoked/expired grant) throws here, naming 401 / sign-in.
          const m = (e && e.message) || "";
          if (/401|403|unauthor|sign-?in|revoked|expired|re-run the one-time login|wire-sign/i.test(m)) {
            authState = "rejected"; authLine = `sign/auth failed → ${m.slice(0, 140)}`;
          } else {
            // Any OTHER error (authed-POST timeout / DNS blip / TLS error) → NO verdict reached.
            // This is inconclusive, NOT a wedged pool — never emit a confident restart diagnosis here.
            authState = "inconclusive"; authLine = `authed probe inconclusive → ${m.slice(0, 140)}`;
          }
        }
        if (authState === "rejected") {
          classification = "lapsed grant";
          recovery = "re-run buzz_login (your sign-in lapsed)";
        } else if (authState === "inconclusive") {
          // health 200 but the authed probe errored without a clear verdict → we genuinely can't
          // tell; do NOT claim "wedged". Ask for a retry rather than a restart.
          classification = "couldn't tell";
          recovery = "couldn't tell — retry buzz_doctor (the authed probe errored without a clear verdict)";
        } else if (TRANSPORT_WEDGED) {
          // health 200 + auth 200 but this process already flagged its undici pool wedged →
          // the local client pool is stuck; only a full client restart clears it.
          classification = "wedged client pool";
          recovery = "restart your MCP client (a reconnect does NOT clear a wedged connection pool)";
        } else {
          // health 200 + auth 200 + transport OK (no wedge flagged) → nothing is actually broken.
          classification = "healthy";
          recovery = "healthy — reads/posts should work; no action";
        }
      }

      const transportLine = TRANSPORT_WEDGED
        ? "⚠ undici pool already flagged wedged this process — self-healing via fresh node:https sockets"
        : "ok (no wedge flagged this process)";
      const pinLine = EXPECTED_PK
        ? (IDENTITY_OK ? "pin VERIFIED ✅" : "⚠ IMPERSONATION GUARD TRIPPED — WRITES DISABLED")
        : "no pin set (BUZZ_EXPECTED_PUBKEY unset)";

      return ok([
        "buzz_doctor — connector-side diagnosis (NOT the authoritative relay health signal)",
        `  shim: @ola/buzz-mcp v${SHIM_VERSION}`,
        `  diagnosis: ${classification}`,
        `  recovery: ${recovery}`,
        `  identity: ${MY_NAME} (${pinLine})`,
        `  relay (dial): ${RELAY}`,
        `  health probe: ${healthLine}`,
        `  auth probe: ${authLine}`,
        `  transport: ${transportLine}`,
      ].join("\n"));
    }

    return ok(`unknown tool: ${name}`);
  } catch (e) {
    return { content: [{ type: "text", text: `error: ${e.message}` }], isError: true };
  }
});

// pilot #4: in wire mode the shim posts AS the human — default the display name to the human.
// Preferred source is ekam's login-captured `name` (#335, handled at MY_NAME init above); this
// is the FALLBACK for sessions with no captured name — read the user's OWN kind:0 profile name
// (not the auto <ctx>·<animal>), unless one was set explicitly.
if (signer.mode === "wire" && !(process.env.BUZZ_IDENTITY_NAME || process.env.BUZZ_NAME)
    && !wireNameGet(wirePersistId(process.env))) {
  try {
    const pm = await profiles();
    const human = pm[PK];
    if (human && human.trim() && human !== PK.slice(0, 8)) MY_NAME = human.trim();
  } catch {}
}

// auto-register this session's context-derived friendly name (best-effort).
// Skipped on impersonation-guard trip: never publish a profile AS the wrong agent.
// Also skipped in wire mode: kind:0/10100 are not in the wire-sign allowlist, and the
// display name belongs to the USER's own profile — the shim must not overwrite it.
if (IDENTITY_OK && signer.canSign(0)) publishProfile(MY_NAME).catch(() => {});
else if (IDENTITY_OK && signer.mode === "wire") process.stderr.write(`[buzz-mcp] profile publish skipped (wire mode: posts as the user; kind:0/10100 not in the wire-sign allowlist).\n`);
else if (!IDENTITY_OK) process.stderr.write(`[buzz-mcp] profile publish skipped (impersonation guard).\n`);

// fail-LOUD environment surfacing at boot (warn to stderr, never brick — see CLI-never-break):
// makes the resolved identity + relay explicit every start, so a clobbered key or a
// non-prod endpoint is visible immediately instead of producing confident-wrong claims.
process.stderr.write(`[buzz-mcp] identity=${MY_NAME} pubkey=${PK.slice(0, 16)} relay=${RELAY} :: ${keyProvenance()}\n`);
if (!IS_ISOLATED)
  process.stderr.write(`[buzz-mcp] ⚠ SHARED CONFIG — not isolated; another agent can clobber your identity (the flip-flop). Fix: relaunch via  buzz-claude ${MY_NAME}   (guide: ${GUIDE_PATH})\n`);

await server.connect(new StdioServerTransport());
