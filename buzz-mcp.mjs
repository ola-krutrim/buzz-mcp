#!/usr/bin/env node
// buzz-mcp — join the Buzz relay from a Claude CLI session: see channels,
// read what your agents are saying, post, and @mention agents to delegate.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import * as nip19 from "nostr-tools/nip19";
import { resolveSigner, reactionTemplate, addMemberTemplate, removeMemberTemplate, deleteMessageTemplate, blossomAuthTemplate, buildImeta, parseImeta, messageAttachments, mediaMimeForPath, mediaCapCheck, MEDIA_MB, wireNameGet, wirePersistId, ekamBase, wireRefreshGet, wireRefreshSet, wirePubkeyGet, wirePubkeySet, wireNameSet, wireSign, DEFAULT_EKAM_CLIENT_ID, WIRE_REFRESH_DIR } from "./signer.mjs";
import { IDENTITY_DIR } from "./loadkey_v2.mjs";
import { pickAdvertised, clientVersionStatus } from "./clientversion.mjs";
import { NAME_INVIS, BIDI_CONTROL, CHANNEL_NAME_FORBIDDEN, CASE_ONLY_IS_AMBIGUOUS, foldName, stripVariationSelectors, matchProfiles, emailError, looksLikeEmail, archivedFromEvents, isPubkeyHex, assertPTags, mentionTokens, resolveMentions, MENTION_MAX_TOKENS, matchChannel } from "./names.mjs";
import { verifyEvent } from "nostr-tools/pure";
// v0.2.31 best-practice guards (each unit-tested in safety.test.mjs).
import {
  UNTRUSTED_NOTE, escapeContent, escapeName, buildProfileIndex, whoLabel, resolveAttachment, openCheckedAttachment,
  createConfirmGate, privateDownloadDir, openExclusive, downloadLeaf, downloadCap,
  createWriteGuard, writeLimitFromEnv, scrubKeyEnv, minimalChildEnv,
  openUrlCommand, clampLimit, validateArgs, inboundMode, screenInbound,
} from "./safety.mjs";
const ERROR_TEXT_CAP = 1500; // v0.2.31 re-check: catch-all error text cap (code points)
import { AsyncLocalStorage } from "node:async_hooks";
// buzz_login (v0.2.15) reuses the wire-sign OAuth primitives from the login CLI. NOTE: this
// import inlines wirelogin.mjs into the bundle — its CLI main is guarded by a basename check
// (see wirelogin.mjs) so it does NOT run at shim boot; we only compose its exported helpers.
import { pkce, authorizeUrl, exchangeAuthCode, bindLoopback } from "./wirelogin.mjs";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync, statSync, createReadStream, writeSync, closeSync, fsyncSync, unlinkSync } from "node:fs";
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
// v0.2.31 (item 8): the signer reads key/credential env vars from a boot-time SNAPSHOT; once identity
// and the NIP-OA tags are resolved below, those vars are DELETED from process.env so nothing later in
// the process (a child process, a diagnostic dump, a dependency) can read them back.
const BOOT_ENV = { ...process.env };
const signer = await resolveSigner({ sessionId: sessionId(), env: BOOT_ENV });
// (E, v0.2.30) Strict p-tag guard on EVERY event this shim signs: a p-tag value that isn't exactly
// 64 lowercase hex (a malformed relay profile pubkey, an uppercase id, junk from a mention index)
// never reaches the signer. Wrapping sign() covers posts, replies, DMs, moderation and openDm alike.
{
  const rawSign = signer.sign.bind(signer);
  signer.sign = (tpl) => { assertPTags(tpl && tpl.tags); return rawSign(tpl); };
}
const PK = signer.pubkey;

// ---- context-derived friendly name (like Codex): <repo-or-dir>·<memorable> ----
const ANIMALS = ["otter","falcon","lynx","heron","ibex","marten","tern","shrike","vireo",
  "saki","tapir","serval","caracal","fossa","dhole","quokka","kagu","takin","gaur","civet"];
function contextName() {
  let ctx;
  try { ctx = basename(execSync("git rev-parse --show-toplevel", { stdio: ["ignore","pipe","ignore"], env: minimalChildEnv(), timeout: 5000 }).toString().trim()); } catch {}
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
// parseTagEnv distinguishes UNSET (fine → null) from SET-BUT-MALFORMED (loud). A bash `source` of
// agent.env strips the JSON double-quotes, so JSON.parse fails; silently nulling the tag here (the old
// behavior) yields an opaque `403 relay_membership_required` downstream that gives the operator no clue.
// Surface it with the exact remedy instead of swallowing it. All NIP-OA tags are 4-element arrays.
function parseTagEnv(raw, head) {
  if (!String(raw || "").trim()) return { tag: null, malformed: false };   // unset/empty — legitimate (e.g. wire mode)
  try {
    const t = JSON.parse(raw);
    if (Array.isArray(t) && t[0] === head && t.length === 4) return { tag: t, malformed: false };
    return { tag: null, malformed: true };
  } catch { return { tag: null, malformed: true }; }
}
const { tag: AUTH_TAG, malformed: AUTH_TAG_MALFORMED } = parseTagEnv(process.env.BUZZ_AUTH_TAG, "auth");
// 2b — individual-signed owner attestation for the owner-admission picker. Read from its OWN env var,
// kept entirely separate from BUZZ_AUTH_TAG; it goes ONLY on the kind:10100 agent card, NEVER on the
// NIP-42/NIP-98 credential or kind:0 (C3). Consumed VERBATIM — never re-encoded: the signature binds
// [1] owner xonly + [2] "created_at<0" + the agent pubkey, and only [0] is swappable ("picker-owner"
// ↔ "auth") for verification, so any re-serialization of [2] would break the signature.
const { tag: PICKER_OWNER_TAG, malformed: PICKER_OWNER_TAG_MALFORMED } = parseTagEnv(process.env.BUZZ_PICKER_OWNER_TAG, "picker-owner");
if (AUTH_TAG_MALFORMED)
  process.stderr.write(`[buzz-mcp] ⚠ BUZZ_AUTH_TAG is set but is not a valid ["auth",owner,conditions,sig] JSON array — owner attestation OMITTED, so the relay will reject membership/posts with 403 relay_membership_required. Most common cause: sourcing agent.env in bash strips the JSON quotes. Fix: single-quote the value (BUZZ_AUTH_TAG='["auth",...]') or avoid \`source\`. Run buzz_doctor for the same diagnosis.\n`);
if (PICKER_OWNER_TAG_MALFORMED)
  process.stderr.write(`[buzz-mcp] ⚠ BUZZ_PICKER_OWNER_TAG is set but is not a valid ["picker-owner",owner,conditions,sig] JSON array — the discovery attestation will be OMITTED from your kind:10100 card (same bash quote-strip cause; single-quote the value).\n`);
// v0.2.31 (item 8): everything that needs a key/credential env var has now read it (signer from
// BOOT_ENV, the two NIP-OA tags above, keyProvenance below from KEY_ENV_PIN) → scrub them.
// boolean only (review nice-to-have): keep no second copy of the key string around for the session.
const KEY_ENV_PIN = !!(BOOT_ENV.BUZZ_PRIVATE_KEY || BOOT_ENV.BUZZ_IDENTITY_KEY || "").trim();
const SCRUBBED_ENV = scrubKeyEnv(process.env);
// Zero the local key buffer on the way out (wire mode holds no key). Best effort.
process.once("exit", () => { try { signer.wipe?.(); } catch {} });
for (const [sig, code] of [["SIGINT", 130], ["SIGTERM", 143]]) process.once(sig, () => process.exit(code)); // → "exit" → wipe

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
const SHIM_VERSION = "0.2.31";

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

// v0.2.19 — CONNECTOR-SIDE WRITE-HEALTH. buzz_doctor's probes are BOTH READS (a /health GET + an
// authed /query), so a relay that serves reads while REJECTING this client's writes reads as
// "healthy" — the "check can't see failing posts" blind spot. Every write is a POST /events and
// every read is /query, both funnelled through the ONE bridge() choke-point, so we observe each
// write's REAL outcome there — success or throw — with NO extra network I/O and NO side-effect
// test-write (buzz_doctor reports on the posts you actually make; it never posts to probe). Reads
// (/query) never touch this. Process-scoped, like TRANSPORT_WEDGED / STALE_401_RETRIES; a client
// restart resets it, which is correct — it describes THIS process's write experience.
// A failure only means "writes are systemically broken" (the thing buzz_doctor should raise) when the
// relay could NOT give a definitive answer — a transport throw, an HTTP 5xx, or a persistent
// stale-timestamp 401 (clock/queue skew, the write-wedge). A request-specific 4xx (403 permission-
// denied, 404 not-found, 400/409 validation/conflict) is the OPPOSITE signal: the relay answered, so
// the write PATH is up — it just refused THIS event on its merits. Counting those as "posts failing"
// would fire false #buzz-help reports for ordinary permission errors (dx pre-publish review, v0.2.19).
function isSystemicWriteFailure(errMsg) {
  const s = String(errMsg || "");
  const m = s.match(/-> HTTP (\d{3})/);
  if (!m) return true;                                  // no HTTP status → transport throw / sign failure → systemic
  const status = parseInt(m[1], 10);
  if (status >= 500) return true;                       // relay error → systemic
  if (status === 401 && isStaleTimestamp401(s)) return true; // persistent stale-timestamp → clock/queue skew → systemic
  return false;                                         // other 4xx (403/404/400/409…) → request-specific, relay answered
}
// v0.2.20 (dx nit) — a 429 is neither a write outage nor a "refused on its merits" error: the write is
// fine, the client is being throttled, and the useful action is to WAIT, not to report or re-check
// permissions. Detect it so buzz_doctor says "rate-limited — retry in Ns" instead of the generic
// request-refusal wording. NOT systemic (isSystemicWriteFailure already returns false for 429). Returns
// the relay's retry hint when present ("retry in Ns"), else null.
function rateLimitHint(errMsg) {
  const s = String(errMsg || "");
  if (!/-> HTTP 429\b/.test(s) && !/\brate.?limit/i.test(s)) return null;
  const m = s.match(/retry in (\d+)\s*s/i) || s.match(/retry.?after["' :=]+(\d+)/i);
  return m ? `retry in ${m[1]}s` : "wait briefly and retry";
}
const WRITE_STALE_MS = 10 * 60 * 1000; // a systemic failure older than this, with nothing since, is not "currently failing"
const WRITE_HEALTH = {
  lastOutcome: null,          // "ok" | "failed" | null (no write attempted yet this process)
  lastKind: null,             // "ok" | "systemic" | "request" — classification of the most recent outcome
  lastError: null,            // short reason for the most recent failure (null when healthy)
  lastTs: 0,                  // epoch ms of the most recent write outcome (any kind)
  consecutiveSystemic: 0,     // consecutive SYSTEMIC failures; resets on ANY definitive relay answer (ok or a 4xx)
  lastSystemicTs: 0,          // epoch ms of the most recent systemic failure
  totalOk: 0,
  totalFailed: 0,
};
function recordWrite(okFlag, errMsg) {
  const now = Date.now();
  WRITE_HEALTH.lastTs = now;
  if (okFlag) {
    WRITE_HEALTH.lastOutcome = "ok"; WRITE_HEALTH.lastKind = "ok"; WRITE_HEALTH.lastError = null;
    WRITE_HEALTH.consecutiveSystemic = 0; // the relay accepted a write → not systemically broken
    WRITE_HEALTH.totalOk += 1;
    return;
  }
  WRITE_HEALTH.lastOutcome = "failed";
  WRITE_HEALTH.lastError = String(errMsg || "unknown").replace(/\s+/g, " ").slice(0, 160);
  WRITE_HEALTH.totalFailed += 1;
  if (isSystemicWriteFailure(errMsg)) {
    WRITE_HEALTH.lastKind = "systemic";
    WRITE_HEALTH.consecutiveSystemic += 1;
    WRITE_HEALTH.lastSystemicTs = now;
  } else if (rateLimitHint(errMsg)) {
    // 429 throttle — the write path is up, you're just being rate-limited. Its own kind so the doctor
    // says "rate-limited — retry", not "refused on its merits". Clears the systemic streak (relay answered).
    WRITE_HEALTH.lastKind = "rate_limited";
    WRITE_HEALTH.consecutiveSystemic = 0;
  } else {
    // The relay answered with a request-specific refusal (permission/validation) → the write PATH is
    // demonstrably up, so this does NOT signal a write outage and clears any systemic streak.
    WRITE_HEALTH.lastKind = "request";
    WRITE_HEALTH.consecutiveSystemic = 0;
  }
}
// True only when writes are CURRENTLY, systemically failing: a systemic streak whose most recent
// failure is recent (older ones with nothing since are stale, not current — dx #3).
function writesSystemicallyFailing() {
  return WRITE_HEALTH.consecutiveSystemic > 0 && (Date.now() - WRITE_HEALTH.lastSystemicTs) < WRITE_STALE_MS;
}
// Human-readable age for the writes line (avoid a bare "21600s ago").
function ageStr(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 90) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 90) return `${m}m ago`;
  return `${Math.round(m / 60)}h ago`;
}

// v0.2.8 transport self-heal. A long-lived MCP process can wedge Node's built-in undici fetch
// pool (releng: every /query throws unknown_transport while whoami — local, no fetch — still
// works; only a full process restart clears it). We can't recreate undici's dispatcher (undici
// isn't importable — ERR_MODULE_NOT_FOUND), so on a transport throw we retry over a FRESH
// node:https socket (keepAlive:false = a brand-new connection, never the wedged pool). Once a
// wedge is seen we stick to the raw path for the rest of the process so every later call keeps
// working without a restart; a clean undici attempt clears the flag. `whoami` surfaces it.
let TRANSPORT_WEDGED = false;

// v0.2.31 (item 6): per-tool-call context. The CallTool handler runs each call inside REQ_CTX with
// the client's cancellation signal (extra.signal) and a progress reporter, so deep helpers (bridge,
// upload, download) can abort when the client cancels and report progress without threading args.
const REQ_CTX = new AsyncLocalStorage();
const reqSignal = () => REQ_CTX.getStore()?.signal;
// Combine our own timeout with the client's cancel signal (either aborts the request).
function withCancel(signal) {
  const s = reqSignal();
  return s && typeof AbortSignal.any === "function" ? AbortSignal.any([signal, s]) : signal;
}
function throwIfCancelled() {
  const s = reqSignal();
  if (s?.aborted) throw new Error("cancelled by the client");
}
async function progress(done, total, message) {
  const c = REQ_CTX.getStore();
  if (!c || c.progressToken == null || !c.sendNotification) return;
  try {
    await c.sendNotification({ method: "notifications/progress", params: { progressToken: c.progressToken, progress: done, ...(total ? { total } : {}), ...(message ? { message } : {}) } });
  } catch { /* progress is best-effort */ }
}
// Hard timeouts (seconds, env-tunable, clamped) for the calls that previously had none.
const envSecs = (k, def, max) => { const n = parseInt(process.env[k] || "", 10); return Number.isFinite(n) && n > 0 ? Math.min(n, max) : def; };
const RELAYINFO_TIMEOUT_S = envSecs("BUZZ_RELAYINFO_TIMEOUT_S", 8, 60);
const TRANSFER_TIMEOUT_S = envSecs("BUZZ_TRANSFER_TIMEOUT_S", 600, 3600); // whole upload / download
const timeoutSignal = (secs) => withCancel(AbortSignal.timeout(secs * 1000));

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
    const cs = reqSignal();
    if (cs) { if (cs.aborted) req.destroy(new Error("cancelled by the client")); else cs.addEventListener("abort", () => req.destroy(new Error("cancelled by the client")), { once: true }); }
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

async function bridgeCore(path, bodyObj) {
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
    return fetch(dialUrl, { method: "POST", headers: headersFor(authz, isRetry, rClass), body, signal: withCancel(ac.signal) })
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
    throwIfCancelled(); // the client cancelled → don't retry, just stop
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

// v0.2.19 — WRITE-HEALTH WRAPPER around bridgeCore(). This is the single choke-point every read and
// write passes through, so it is the one place that observes each WRITE's real outcome. A write is a
// POST /events; everything else (/query) is a read and is NOT recorded. We record success (the core
// returned) and failure (the core threw, for ANY reason — transport double-fail, a returned 4xx, or a
// sign failure) and then re-throw unchanged, so callers and the existing error text are untouched.
// buzz_doctor consults WRITE_HEALTH to close the "check can't see failing posts" blind spot. No extra
// I/O, no test-write.
// v0.2.31 (item 7): the same choke-point applies the per-session write throttle + duplicate-post
// suppression to every POST /events. A throttle/duplicate refusal is LOCAL (nothing was sent), so it
// is NOT recorded as a write failure — buzz_doctor must not report "posts failing" for it.
const WRITE_GUARD = createWriteGuard({ perMin: writeLimitFromEnv() });
async function bridge(path, bodyObj) {
  const isWrite = path === "/events";
  if (isWrite) {
    const refusal = WRITE_GUARD.check(bodyObj);
    if (refusal) throw new Error(refusal);
  }
  throwIfCancelled();
  try {
    const r = await bridgeCore(path, bodyObj);
    if (isWrite) { recordWrite(true, null); WRITE_GUARD.commit(bodyObj); }
    return r;
  } catch (e) {
    if (isWrite) recordWrite(false, (e && e.message) || String(e));
    throw e;
  }
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
// v0.2.31 (item 6): whole-transfer timeout (BUZZ_TRANSFER_TIMEOUT_S), client cancel, progress.
// v0.2.31 fix (review §3.8): the bytes come from ONE fd opened O_NOFOLLOW and proven to be the
// same dev:ino that resolveAttachment checked against the secret-path denylist (no check/use swap).
async function blossomUpload(filePath, expectId) {
  const { fd, size } = openCheckedAttachment(filePath, expectId);
  const st = { size };
  let src, mime, sha;
  try {
    ({ mime } = mediaCapCheck(basename(filePath), st.size)); // per-type cap; throws a distinguishable local refusal if over
    sha = await new Promise((res, rej) => { const h = createHash("sha256"); const r = createReadStream(null, { fd, start: 0, autoClose: false }); r.on("error", rej); r.on("data", (c) => h.update(c)); r.on("end", () => res(h.digest("hex"))); });
    throwIfCancelled();
    src = createReadStream(null, { fd, start: 0, autoClose: true });
  } catch (e) { try { closeSync(fd); } catch {} throw e; }
  let sent = 0, lastPct = -1;
  src.on("data", (c) => { sent += c.length; const pct = st.size ? Math.floor((sent * 20) / st.size) : 20; if (pct !== lastPct) { lastPct = pct; progress(sent, st.size, `uploading ${basename(filePath)}`); } });
  const res = await fetch(`${RELAY}/upload`, {
    method: "PUT",
    headers: { Authorization: await blossomAuthHeader("upload", sha), "X-SHA-256": sha, "Content-Type": mime, "Content-Length": String(st.size), ...(AUTH_TAG ? { "x-auth-tag": JSON.stringify(AUTH_TAG) } : {}) },
    body: Readable.toWeb(src),
    duplex: "half",
    signal: timeoutSignal(TRANSFER_TIMEOUT_S),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`upload ${basename(filePath)} -> HTTP ${res.status}: ${text.slice(0, 200)}`);
  let d = {}; try { d = JSON.parse(text); } catch {}
  return { url: d.url || `${RELAY}/media/${sha}${extname(filePath)}`, sha256: String(d.sha256 || d.x || sha).toLowerCase(), size: Number(d.size || st.size), mime: d.type || mime, filename: basename(filePath) };
}

// Download a media blob (sha[.ext]) into the PRIVATE download dir (item 5): dir 0700, file created
// O_CREAT|O_EXCL|O_NOFOLLOW 0600 (never overwrites, never follows a planted symlink), streamed chunk
// by chunk to disk (no whole-blob buffering), refused past the size cap (BUZZ_DOWNLOAD_MAX_MB,
// default 200) both up front (Content-Range / Content-Length total) and while streaming. Range loop
// for blobs larger than one 16 MiB relay range. Whole-transfer timeout + client cancel (item 6).
async function blossomDownload(shaExt, { ext = "" } = {}) {
  const sha = String(shaExt).split(".")[0].toLowerCase();
  const dir = privateDownloadDir();
  const cap = downloadCap();
  const destPath = join(dir, downloadLeaf(sha, ext));
  const part = destPath + ".part";
  const fd = openExclusive(part);
  const signal = timeoutSignal(TRANSFER_TIMEOUT_S);
  const overCap = (n) => new Error(`download <${sha.slice(0, 8)}> refused: ${n} bytes exceeds the ${Math.round(cap / 1048576)} MB download cap (BUZZ_DOWNLOAD_MAX_MB)`);
  let ok = false;
  try {
    let start = 0, total = Infinity;
    while (start < total) {
      const res = await fetch(`${RELAY}/media/${shaExt}`, { signal, headers: { Authorization: await blossomAuthHeader("get", sha), Range: `bytes=${start}-${start + DOWNLOAD_CHUNK - 1}`, ...(AUTH_TAG ? { "x-auth-tag": JSON.stringify(AUTH_TAG) } : {}) } });
      if (res.status !== 200 && res.status !== 206) { const t = await res.text().catch(() => ""); throw new Error(`download <${sha.slice(0, 8)}> -> HTTP ${res.status}: ${t.slice(0, 160)}`); }
      const whole = res.status === 200;
      if (whole) { const cl = Number(res.headers.get("content-length")); if (Number.isFinite(cl) && cl > 0) total = cl; if (start) throw new Error(`download <${sha.slice(0, 8)}>: relay ignored the Range request mid-transfer`); }
      else { const m = (res.headers.get("content-range") || "").match(/\/(\d+)\s*$/); if (m) total = Number(m[1]); }
      if (Number.isFinite(total) && total > cap) { try { await res.body?.cancel(); } catch {} throw overCap(total); }
      let got = 0;
      const reader = res.body ? res.body.getReader() : null;
      while (reader) {
        const { done, value } = await reader.read();
        if (done) break;
        if (start + got + value.length > cap) { try { await reader.cancel(); } catch {} throw overCap(start + got + value.length); }
        writeSync(fd, value);
        got += value.length;
      }
      start += got;
      progress(start, Number.isFinite(total) ? total : undefined, `downloading <${sha.slice(0, 8)}>`);
      if (whole) { total = start; break; }
      if (!got) break;
    }
    fsyncSync(fd);
    ok = true;
  } finally {
    closeSync(fd);
    if (!ok) { try { unlinkSync(part); } catch {} }
  }
  if (existsSync(destPath)) throw new Error(`download target already exists: ${destPath}`);
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
    client_version: SHIM_VERSION,   // (C, v0.2.30) which shim build published this profile
  };
  // The kind:0 profile is the write-health canary — record its outcome (via bridge()). In agent mode
  // this fires on boot, so even a read-only session gets a real write signal.
  const res = await signer.sign({ kind: 0, tags: AUTH_TAG ? [AUTH_TAG] : [], content: JSON.stringify(profile) })
    .then((ev) => bridge("/events", ev));
  // best-effort structured agent card (relay may gate the kind; the kind:0 above always applies). Its
  // failure is deliberately swallowed as non-fatal, so it must NOT feed write-health — a grant without
  // the 10100 permission would otherwise show a false "posts failing" every boot (dx #2). Use
  // bridgeCore (full transport self-heal, but NOT recorded).
  try {
    const card = { name, model: AGENT_MODEL, harness: AGENT_HARNESS, interface: AGENT_INTERFACE, host, identity: "Ekam-governed", client_version: SHIM_VERSION };
    const cardTags = [["model", AGENT_MODEL], ["harness", AGENT_HARNESS], ["interface", AGENT_INTERFACE], ["L", "agent-card"],
      ["client", "buzz-mcp", SHIM_VERSION]];   // (C, v0.2.30) client + version on the agent card
    // 2b — individual-signed owner attestation for the owner-admission picker. kind:10100 ONLY,
    // appended VERBATIM as its own ["picker-owner",…] tag (NOT a second ["auth",…], so it never rides
    // the relay's auth-tag / >1-auth-tag-multiplicity path). C3: it is placed here and nowhere else.
    if (PICKER_OWNER_TAG) cardTags.push(PICKER_OWNER_TAG);
    const cardEv = await signer.sign({ kind: KIND_AGENT_PROFILE, tags: cardTags, content: JSON.stringify(card) });
    await bridgeCore("/events", cardEv);
  } catch (e) {
    // The card stays NON-FATAL (dx #2: a relay that gates kind:10100 must not surface a false "posts
    // failing" every boot) — so it is not recorded in write-health. C2: but when we are carrying the 2b
    // discovery attestation, a SILENT failure would hide the owner-admission picker never resolving the
    // owner; make THAT case observable on stderr, without making it fatal.
    if (PICKER_OWNER_TAG)
      process.stderr.write(`[buzz-mcp] ⚠ kind:10100 agent-card publish failed while carrying the picker-owner attestation (${retryClass(e)}) — the owner-admission picker will not resolve your owner until the next successful profile publish.\n`);
  }
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
// v0.2.31 (items 2 + 12): kind:0 events are signature-verified (forged profiles dropped), the NEWEST
// kind:0 per pubkey wins (not arrival order), and look-alike names across different pubkeys are
// flagged. The index is kept for whoLabel() so every rendered author shows "name (pk8)".
const INBOUND_MODE = inboundMode();
let PROFILE_IDX = { names: {}, collide: new Set() };
async function profiles() {
  const evs = await query([{ kinds: [0], limit: 200 }]);
  const { events } = screenInbound(evs || [], verifyEvent, { mode: INBOUND_MODE });
  PROFILE_IDX = buildProfileIndex(events);
  return PROFILE_IDX.names;
}
const who = (pk) => whoLabel(pk, PROFILE_IDX);
// Verify inbound content events (kind 9 etc.): drop (default) or flag forged signatures, flag a
// created_at from the future. → { events, note } where note is a header line when anything happened.
function screen(evs) {
  const r = screenInbound(evs || [], verifyEvent, { mode: INBOUND_MODE });
  const notes = [];
  if (r.dropped) notes.push(`⚠ ${r.dropped} event(s) failed signature verification and were hidden`);
  return { events: r.events, flagOf: r.flagOf, note: notes.join("; ") };
}
// One rendered message row: escaped single-line content, verified-author label, flags.
function row(e, { withDate = false, attach = "", flagOf, content = e.content, edited = false } = {}) {
  const f = flagOf ? flagOf(e) : "";
  return `[${fmtTime(e.created_at, withDate)}] ${who(e.pubkey)} <${String(e.id).slice(0, 8)}>${attach}: ${escapeContent(content)}${edited ? " (edited)" : ""}${f ? "  " + f : ""}`;
}
// A kind:9 row with its 📎 attachment labels and, when the author edited it (kind:40003 by the SAME
// pubkey, newest wins), the edited text marked "(edited)".
function renderMsg(e, { edits, flagOf, withDate = false } = {}) {
  const atts = messageAttachments(e);
  const attach = atts.length ? " " + atts.map((x) => `📎${escapeName(x.filename || x.mime || "file")}`).join("") : "";
  const ed = edits && edits.get(e.id);
  return row(e, { withDate, attach, flagOf, content: ed ? ed.content : e.content, edited: !!ed });
}
async function latestEdits(chId, events) {
  const m = new Map();
  const byId = new Map((events || []).map((e) => [e.id, e]));
  if (!byId.size) return m;
  let evs = [];
  try { evs = screen(await query([{ kinds: [40003], "#h": [chId], "#e": [...byId.keys()], limit: 500 }])).events; } catch { return m; }
  for (const ed of evs) {
    if (!ed || ed.kind !== 40003) continue;
    if (!(ed.tags || []).some((t) => t[0] === "h" && t[1] === chId)) continue;
    const tgt = ((ed.tags || []).find((t) => t[0] === "e") || [])[1];
    const orig = byId.get(tgt);
    if (!orig || orig.pubkey !== ed.pubkey) continue;   // only the author's own edit counts
    const prev = m.get(tgt);
    if (!prev || ed.created_at > prev.created_at) m.set(tgt, ed);
  }
  return m;
}
// (v0.2.30 fix, buzz_security review §3.1) Fail-closed channel lookup: exact id, else matchChannel
// (exact → case-only → lookalike; two channels sharing a name — "general"/"General" — or a single
// lookalike-only hit are REFUSED with the ids to pick from, never resolved to whichever came first).
class ChannelAmbiguousError extends Error {}
async function resolveChannel(nameOrId) {
  const cs = await channels();
  let hit;
  try { hit = matchChannel(nameOrId, cs); } catch (e) { throw new ChannelAmbiguousError(e.message); }
  if (!hit) throw new Error(`channel not found: ${escapeName(nameOrId)}. Available: ${cs.map((c) => escapeName(c.name)).join(", ")}`);
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
// Candidate kind:0 profiles for a free-text name, NOT the 200-newest {kinds:[0]} window that
// profiles() uses (a profile not updated recently is still found). (B, v0.2.30) Prefer the relay's
// dedicated POST /profiles/search (NIP-98; matches name/display_name only, best match first —
// buzz docs/profile-search.md); on 404/405 (older relay) or a non-array body fall back to NIP-50
// {kinds:[0], search} and remember that for 5 min, like the mobile client. Fails SOFT (returns [])
// so a relay without profile search degrades to "not found", never to a wrong match — matching
// itself is always done client-side by matchProfiles (name/display_name only, fail-closed).
const PROFILE_SEARCH_FALLBACK_MS = 5 * 60_000;
let PROFILE_SEARCH_UNSUPPORTED_UNTIL = 0;
const profileFromEvent = (e) => {
  try {
    const c = JSON.parse(e.content);
    return { pubkey: e.pubkey, created_at: e.created_at || 0, name: typeof c.name === "string" ? c.name : "", display_name: typeof c.display_name === "string" ? c.display_name : "", nip05: c.nip05 || "" };
  } catch { return null; }
};
async function searchProfiles(term, limit = 50) {
  const q = String(term || "").trim();
  if (!q) return [];
  let evs = null;
  if (Date.now() >= PROFILE_SEARCH_UNSUPPORTED_UNTIL && [...q].length <= 100) {
    try {
      const r = await bridge("/profiles/search", { query: q, limit: Math.min(limit, 100) });
      if (Array.isArray(r)) evs = r;
      else PROFILE_SEARCH_UNSUPPORTED_UNTIL = Date.now() + PROFILE_SEARCH_FALLBACK_MS;
    } catch (e) {
      if (/HTTP 40[45]\b/.test(String(e && e.message))) PROFILE_SEARCH_UNSUPPORTED_UNTIL = Date.now() + PROFILE_SEARCH_FALLBACK_MS;
    }
  }
  if (evs === null) {
    try { evs = await query([{ kinds: [0], search: q, limit }]) || []; } catch { evs = []; }
  }
  return evs.filter((e) => e && e.kind === 0).map(profileFromEvent).filter(Boolean);
}
// Merge candidate sets by pubkey, newest kind:0 wins.
function mergeProfiles(...lists) {
  const m = new Map();
  for (const l of lists) for (const p of l) { const prev = m.get(p.pubkey); if (!prev || p.created_at > prev.created_at) m.set(p.pubkey, p); }
  return [...m.values()];
}
// (A, v0.2.30) NIP-IA archived identities: the newest kind:13535 signed by the relay's NIP-11
// `self` key (exactly one ["-"] tag, bare ["p", pk] entries). Lists by any other key are ignored.
// Archived pubkeys are hidden from name resolution and buzz_agents. FAIL OPEN: no `self`, no list,
// an invalid signature or a read error → nothing is hidden (archival is a UX filter, not authz).
let ARCHIVED = { set: new Set(), at: 0, eventId: null };
const ARCHIVED_TTL = 30_000;
async function archivedPubkeys() {
  if (Date.now() - ARCHIVED.at < ARCHIVED_TTL) return ARCHIVED.set;
  let next = { set: new Set(), eventId: null };
  try {
    const info = await relayInfo();
    if (info && isPubkeyHex(info.self)) {
      const evs = await query([{ kinds: [13535], authors: [info.self], limit: 10 }]) || [];
      next = archivedFromEvents(evs, info.self, verifyEvent);
    }
  } catch { /* fail open */ }
  ARCHIVED = { ...next, at: Date.now() };
  return ARCHIVED.set;
}
// Resolve a display name → pubkey (v0.2.30 hardening). Candidates come from searching BOTH the input
// as typed and its NFKC+case-folded form (merged by pubkey); matchProfiles then matches only the
// name/display_name fields, ranks exact > case-only > lookalike (NFKC / TR39 skeleton), and FAILS
// CLOSED: >1 distinct pubkey → ambiguous; a single non-exact hit → "ambiguous / lookalike - use an
// npub" (case-only per CASE_ONLY_IS_AMBIGUOUS). Archived (NIP-IA) identities never resolve.
async function resolveRecipientByName(s) {
  const folded = foldName(s);
  if (!folded) return null;
  const typed = String(s).trim();
  const lists = [await searchProfiles(typed)];
  if (folded !== typed) lists.push(await searchProfiles(folded));
  const archived = await archivedPubkeys();
  const r = matchProfiles(s, mergeProfiles(...lists), { caseOnlyIsAmbiguous: CASE_ONLY_IS_AMBIGUOUS, archived });
  if (r.pubkey) return r.pubkey;
  if (r.archived) throw new Error(`"${s}" matches only an archived identity on this relay (NIP-IA) — use an npub if you really mean it`);
  return null;
}
// Resolve a recipient token → pubkey hex. npub / hex are exact. An email resolves ONLY via Ekam's
// directory in wire mode (authoritative): agent mode has no trustworthy email→pubkey source — the
// former kind:0 `nip05` fallback was self-asserted, so anyone could claim a colleague's address and
// receive their DMs/moderation (buzz_security #1492) — so it is refused. A name is resolved by
// server-side profile search (not the 200-newest cap), on both name fields, normalized, fail-closed.
async function resolveRecipient(to) {
  const s = String(to || "").trim();
  if (/^[0-9a-f]{64}$/i.test(s)) return s.toLowerCase();
  if (s.startsWith("npub")) { const d = nip19.decode(s); if (d.type === "npub") return d.data; throw new Error(`bad npub: ${s}`); }
  if (looksLikeEmail(s)) {
    // (v0.2.30) refuse a homoglyph / zero-width / fullwidth email BEFORE any Ekam or directory call.
    const bad = emailError(s);
    if (bad) throw new Error(bad);
    if (signer.mode === "wire" && typeof signer.ekamToken === "function") return await resolveEmail(s);
    throw new Error(`email addressing needs wire mode ("post as me") — in agent mode, use an npub, hex pubkey, or exact display name instead`);
  }
  const pk = await resolveRecipientByName(s);
  if (pk) return pk;
  throw new Error(`can't resolve recipient "${to}" — pass an npub, hex pubkey, email, or exact display name`);
}
// email→pubkey via Ekam's directory resolver (ekam #324): GET /v1/directory/resolve?email=,
// bearer the wire:sign token (same WHO-gate, no new credential). Returns the CANONICAL live
// pubkey for governed recipients only — a `404 not_governed` is the SAFE signal to fall back
// to npub/name (Ekam won't mint a device-key user a key they never read on). Wire-mode only.
async function resolveEmail(email) {
  const bad = emailError(email);   // defense in depth: never send a non-ASCII/invisible email to the directory
  if (bad) throw new Error(bad);
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
// (D, v0.2.30) Re-read a channel's newest kind:39000 and compare the fields an edit asked for.
// The relay regenerates 39000 synchronously on a 9002, but allow a short settle (3 reads) before
// declaring a mismatch. `want`: { name?, visibility?: "open"|"private", about?, ttl?: string|null }.
const EDIT_VERIFY_TRIES = 3, EDIT_VERIFY_GAP_MS = 400;
function channelMetaFields(ev) {
  const tags = (ev && ev.tags) || [];
  const get = (k) => { const t = tags.find((x) => x[0] === k); return t ? (t[1] ?? "") : null; };
  return {
    name: get("name"),
    visibility: tags.some((t) => t[0] === "private") ? "private" : tags.some((t) => t[0] === "public") ? "open" : null,
    about: (get("about") || "").trim(),
    ttl: get("ttl") || null,
  };
}
async function verifyChannelEdit(chId, want) {
  let mismatches = [], unreadable = null;
  for (let i = 0; i < EDIT_VERIFY_TRIES; i++) {
    if (i) await new Promise((r) => setTimeout(r, EDIT_VERIFY_GAP_MS));
    let evs;
    try { evs = await query([{ kinds: [39000], "#d": [chId], limit: 5 }]) || []; }
    catch (e) { unreadable = (e && e.message) || String(e); continue; }
    const latest = evs.filter((e) => e && e.kind === 39000 && (e.tags || []).some((t) => t[0] === "d" && t[1] === chId))
      .sort((a, b) => b.created_at - a.created_at)[0];
    if (!latest) { unreadable = "no kind:39000 for this channel"; continue; }
    unreadable = null;
    const got = channelMetaFields(latest);
    mismatches = [];
    const norm = (x) => (x == null ? x : String(x).normalize("NFC").trim());
    if ("visibility" in want && got.visibility !== want.visibility) mismatches.push(`visibility: asked ${want.visibility}, relay shows ${got.visibility || "unknown"}${want.visibility === "private" ? " (channel may still be PUBLIC)" : ""}`);
    if ("name" in want && norm(got.name) !== norm(want.name)) mismatches.push(`name: asked ${JSON.stringify(want.name)}, relay shows ${JSON.stringify(got.name)}`);
    if ("ttl" in want && (got.ttl || null) !== (want.ttl || null)) mismatches.push(`ttl: asked ${want.ttl ? want.ttl + "s" : "none (permanent)"}, relay shows ${got.ttl ? got.ttl + "s" : "none"}`);
    if ("about" in want && got.about !== want.about) mismatches.push(`description: asked ${JSON.stringify(want.about.slice(0, 60))}, relay shows ${JSON.stringify(got.about.slice(0, 60))}`);
    if (!mismatches.length) return { ok: true, mismatches, unreadable: null };
  }
  return { ok: false, mismatches, unreadable: mismatches.length ? null : unreadable };
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
// @-mention → p-tag pubkeys (v0.2.30 fix, buzz_security review §3.1). The old index was a
// lowercase FIRST-WINS map over the 200-newest kind:0 window, so "@buzz_security" tagged whichever
// of two same-named keys came first (the retired 7731945f…). Mentions now go through the same
// fail-closed matchProfiles tiers as recipient names (names.mjs resolveMentions): candidates are the
// 200-newest window PLUS a server-side profile search per token (so a real profile outside the window
// is still seen and collides with an impostor), archived (NIP-IA) identities never resolve, and an
// ambiguous / lookalike-only token tags NOBODY and is reported back. "Pulse 💓" → @pulse and
// "bharatrouter·falcon" → @bharatrouterfalcon still work (derived aliases, see mentionAliases).
async function mentionPtags(text) {
  const toks = mentionTokens(text);
  if (!toks.length) return { pubkeys: [], refused: [] };
  const lists = [];
  try { lists.push(((await query([{ kinds: [0], limit: 200 }])) || []).filter((e) => e && e.kind === 0).map(profileFromEvent).filter(Boolean)); } catch { /* search below */ }
  for (const t of toks.slice(0, MENTION_MAX_TOKENS)) lists.push(await searchProfiles(t));
  const archived = await archivedPubkeys();
  return resolveMentions(text, mergeProfiles(...lists), { archived });
}
const mentionNote = (r) => (r && r.refused && r.refused.length)
  ? ` — NOT tagged (fail-closed): ${r.refused.map((x) => `@${escapeName(x.token)}: ${escapeContent(x.reason, { cap: 300 })}`).join("; ")}. Use buzz_agents to find the right person and mention them by an unambiguous name.`
  : "";

// ---- channel name/about client-side limits (v0.2.27, per buzz_security's 0.2.26 GO notes) ----
// The relay caps neither a channel name nor its description — the only server check is
// "non-empty after canonicalization" (buzz-db store/channel.rs). So the shim fails these
// closed before signing a 9007/9002, rather than letting an unbounded or control-laden
// value through: a name is a single display line, a description a short blurb. Bounds are
// defensive (name 80 — the common chat cap; about 500). Both reject C0/DEL control
// characters; the name additionally rejects TAB/LF/CR (a single-line name has none).
const CHANNEL_NAME_MAX = 80;
const CHANNEL_ABOUT_MAX = 500;
const CTRL_ANY = /[\u0000-\u001f\u007f]/;                          // all C0 controls + DEL (incl. TAB/LF/CR)
const CTRL_NON_WS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/; // C0 + DEL except TAB/LF/CR
const cpLen = (s) => [...String(s)].length;                        // count code points, not UTF-16 units
// Channel-name canonicalization shared by create/edit: drop leading '#'/space, trailing space, and
// strip variation selectors (VS1–VS256) so emoji names like "Pulse 💓" / "Pulse ❤️" still work —
// every other invisible / Bidi_Control char is rejected by channelNameError, never silently stripped.
const canonChannelName = (s) => stripVariationSelectors(String(s)).replace(/^[#\s]+/, "").replace(/\s+$/, "");
function channelNameError(name) {
  if (cpLen(name) > CHANNEL_NAME_MAX)
    return `channel name is too long (${cpLen(name)} chars; max ${CHANNEL_NAME_MAX}).`;
  if (CTRL_ANY.test(name))
    return "channel name can't contain control characters or line breaks.";
  if (BIDI_CONTROL.test(name))
    return "channel name can't contain bidirectional control characters (LRM/RLM/ALM, embeddings, overrides, isolates).";
  if (CHANNEL_NAME_FORBIDDEN.test(name))
    return "channel name can't contain zero-width or other invisible (default-ignorable) characters.";
  return null;
}
function channelAboutError(about) {
  if (cpLen(about) > CHANNEL_ABOUT_MAX)
    return `channel description is too long (${cpLen(about)} chars; max ${CHANNEL_ABOUT_MAX}).`;
  if (CTRL_NON_WS.test(about))
    return "channel description can't contain control characters.";
  return null;
}

// ---- MCP server ----
// ---- v0.2.31 shared tool helpers ----
const CONFIRM = createConfirmGate();
// Wire mode only: the first 9001/9005/9002 of the session needs confirm:true (item 4).
const gate = (kind, a, label) => CONFIRM.check(kind, { wire: signer.mode === "wire", confirm: a && a.confirm, label });
const wireBlocked = (kind, tool) => (signer.canSign(kind) ? null
  : `${tool}: kind ${kind} is blocked on Ekam wire-sign allowlist — it can't be signed "as you" yet. Use an agent-mode session, or ask for kind ${kind} to be added to Ekam's allowlist.`);
// Upload a file OR every regular file in a folder (item 1). ANY file type / folder is allowed; only
// secret locations are refused — checked on the typed path AND the realpath (symlinks followed), incl.
// this shim's own key store (IDENTITY_DIR), wire-refresh tokens and ~/.config/buzz-cli (safety.mjs).
async function uploadAttachments(input) {
  const r = resolveAttachment(String(input), { extraDirs: [CFG_DIR, IDENTITY_DIR, WIRE_REFRESH_DIR] });
  const ups = [];
  for (const f of r.files) { throwIfCancelled(); ups.push(await blossomUpload(f, r.ids && r.ids[f])); }
  return { r, ups };
}
function attachedLabel(att) {
  if (!att) return "";
  const { r, ups } = att;
  const tot = ups.reduce((n, u) => n + (u.size || 0), 0);
  const names = ups.map((u) => u.filename).join(", ");
  const src = r.real === r.typed ? r.real : `${r.typed} → ${r.real}`;
  const skipped = r.skipped && r.skipped.length ? `; skipped ${r.skipped.length}: ${r.skipped.join(", ")}` : "";
  return ` [+attachment${ups.length > 1 ? `s (${ups.length})` : ""} ${names}, ${tot >= MB ? (tot / MB).toFixed(1) + " MB" : tot >= 1024 ? (tot / 1024).toFixed(1) + " KB" : tot + " B"} from ${src}${skipped}]`;
}
// `to` may be one recipient or an array (group DM, up to 8 others, item: group DMs).
async function resolveRecipients(to) {
  const list = Array.isArray(to) ? to : [to];
  if (!list.length || list.length > 8) throw new Error(`a DM needs 1–8 other participants (got ${list.length})`);
  const out = [];
  for (const t of list) { const pk = await resolveRecipient(t); if (pk !== PK && !out.includes(pk)) out.push(pk); }
  if (!out.length) throw new Error("a DM needs at least one participant other than you");
  return out;
}
const toLabel = (to) => (Array.isArray(to) ? to.join(", ") : String(to));
const threadRootOf = (ev) => {
  let mRoot = null, mReply = null;
  for (const t of (ev && ev.tags) || []) if (t[0] === "e" && /^[0-9a-f]{64}$/i.test(t[1] || "")) {
    if (t[3] === "root") mRoot = t[1];
    if (t[3] === "reply") mReply = t[1];
  }
  return mReply ? (mRoot || mReply) : ev.id;
};
async function dmById(id) {
  const hit = (await dmChannels()).find((c) => c.id === id);
  if (!hit) throw new Error(`no DM conversation ${String(id).slice(0, 8)}… that you're in — see buzz_dm_list`);
  return hit;
}

async function parityTool(name, a, { ok, fail }) {
  const guard = (verb) => (IDENTITY_OK ? null : fail(`refused: impersonation guard — this session's key ${PK.slice(0, 16)}… ≠ pinned identity ${(EXPECTED_PK || "").slice(0, 16)}…. Not ${verb} as the wrong identity.`));
  const withAuth = (tags) => (AUTH_TAG ? [...tags, AUTH_TAG] : tags);
  const publish = async (kind, tags, content = "") => { const ev = await signer.sign({ kind, tags: withAuth(tags), content }); await bridge("/events", ev); return ev; };

  if (name === "buzz_edit_message") {
    const g = guard("editing"); if (g) return g;
    const wb = wireBlocked(40003, name); if (wb) return fail(wb);
    const text = typeof a.text === "string" ? a.text : (typeof a.message === "string" ? a.message : "");
    if (!text.trim()) return fail("buzz_edit_message needs the new `text`.");
    if (Buffer.byteLength(text, "utf8") > 65536) return fail("buzz_edit_message: the new text is over the relay's 64 KB edit limit.");
    const ch = await resolveChannel(a.channel);
    const hit = await resolveEventInChannel(ch.id, ch.name, a.event);
    if (hit.pubkey !== PK) return fail(`buzz_edit_message: <${String(hit.id).slice(0, 8)}> isn't yours — you can only edit your own messages.`);
    if (hit.kind !== 9) return fail("buzz_edit_message: only chat messages (kind 9) can be edited.");
    await publish(40003, [["h", ch.id], ["e", hit.id]], text);
    return ok(`edited your message <${String(hit.id).slice(0, 8)}> in #${escapeName(ch.name)}: ${text}`);
  }

  if (name === "buzz_thread_read") {
    const ch = await resolveChannel(a.channel);
    const target = await resolveEventInChannel(ch.id, ch.name, a.event);
    await profiles();
    const rootId = threadRootOf(target);
    const root = rootId === target.id ? target : (await query([{ ids: [rootId], "#h": [ch.id] }]) || [])[0];
    const replies = await query([{ kinds: [9], "#h": [ch.id], "#e": [rootId], limit: clampLimit(a.limit, 50, 200) }]) || [];
    const seen = new Set(); const all = [];
    for (const e of [root, ...replies]) if (e && !seen.has(e.id) && (e.tags || []).some((t) => t[0] === "h" && t[1] === ch.id)) { seen.add(e.id); all.push(e); }
    const scr = screen(all);
    const edits = await latestEdits(ch.id, scr.events);
    const rows = scr.events.sort((x, y) => x.created_at - y.created_at).map((e) => (e.id === rootId ? "▶ " : "  ↳ ") + renderMsg(e, { edits, flagOf: scr.flagOf }));
    return ok(`thread <${rootId.slice(0, 8)}> in #${escapeName(ch.name)} (${rows.length} msgs${root ? "" : "; root not readable"}):\n${UNTRUSTED_NOTE}${scr.note ? "\n" + scr.note : ""}\n${rows.join("\n") || "(empty)"}`);
  }

  if (name === "buzz_channel_topic") {
    const g = guard("editing a channel"); if (g) return g;
    const ch = await resolveChannel(a.channel);
    const tags = [["h", ch.id]], changed = [];
    for (const k of ["topic", "purpose"]) {
      if (typeof a[k] !== "string") continue;
      const v = a[k];
      if (v) { const err = channelAboutError(v); if (err) return fail(`buzz_channel_topic: ${k}: ${err.replace(/description/gi, k)}`); }
      tags.push([k, v]); changed.push(v ? `${k} set` : `${k} cleared`);
    }
    if (!changed.length) return fail("buzz_channel_topic: pass `topic` and/or `purpose` (empty string clears).");
    { const gg = gate(9002, a, `set the ${changed.join(" + ")} on #${escapeName(ch.name)}`); if (gg) return fail(gg); }
    await publish(9002, tags);
    return ok(`#${escapeName(ch.name)}: ${changed.join(", ")}. (Applied only if the relay confirms your owner/admin role.)`);
  }

  if (name === "buzz_leave_channel") {
    const g = guard("leaving a channel"); if (g) return g;
    const wb = wireBlocked(9022, name); if (wb) return fail(wb);
    const ch = await resolveChannel(a.channel);
    await publish(9022, [["h", ch.id]]);
    return ok(`left #${escapeName(ch.name)}. Rejoin an open channel with buzz_join_channel; a private one needs an owner/admin to re-add you.`);
  }

  if (name === "buzz_archive_channel") {
    const g = guard("archiving a channel"); if (g) return g;
    const ch = await resolveChannel(a.channel);
    const archive = a.archived !== false;
    if (archive && a.confirm !== true) return fail(`buzz_archive_channel: archiving #${escapeName(ch.name)} makes it read-only for everyone. Re-run with confirm: true to proceed.`);
    { const gg = gate(9002, a, `${archive ? "archive" : "unarchive"} #${escapeName(ch.name)}`); if (gg) return fail(gg); }
    await publish(9002, [["h", ch.id], ["archived", archive ? "true" : "false"]]);
    return ok(`${archive ? "archived" : "unarchived"} #${escapeName(ch.name)}. (Applied only if the relay confirms your owner/admin role.)`);
  }

  if (name === "buzz_delete_channel") {
    const g = guard("deleting a channel"); if (g) return g;
    const wb = wireBlocked(9008, name); if (wb) return fail(wb);
    const ch = await resolveChannel(a.channel);
    if (a.confirm !== true) return fail(`buzz_delete_channel: deleting #${escapeName(ch.name)} [${ch.id}] is permanent for every member. Re-run with confirm: true to proceed.`);
    await publish(9008, [["h", ch.id]]);
    return ok(`deleted #${escapeName(ch.name)} [${ch.id}]. (Allowed only if the relay confirms you own it.)`);
  }

  if (name === "buzz_profile") {
    const q = String(a.user || "").trim();
    if (!q) return fail("buzz_profile needs `user` (npub / hex pubkey / email / exact display name).");
    const pk = await resolveRecipient(q);
    const scr = screen(await query([{ kinds: [0], authors: [pk], limit: 10 }]));
    const ev = scr.events.filter((e) => e.kind === 0 && e.pubkey === pk).sort((x, y) => y.created_at - x.created_at)[0];
    await profiles();
    const head = `profile ${who(pk)}\n  npub: ${nip19.npubEncode(pk)}\n  pubkey: ${pk}`;
    if (!ev) return ok(`${head}\n  (no kind:0 profile found${scr.note ? "; " + scr.note : ""})`);
    let c = {}; try { c = JSON.parse(ev.content) || {}; } catch {}
    const lines = ["display_name", "name", "about", "nip05", "model", "harness", "interface", "client_version", "picture", "website"]
      .filter((k) => typeof c[k] === "string" && c[k]).map((k) => `  ${k}: ${escapeContent(c[k], { cap: 500 })}`);
    const f = scr.flagOf(ev);
    return ok(`${head}\n${UNTRUSTED_NOTE.replace("message content", "profile content")}\n${lines.join("\n") || "  (empty profile)"}\n  updated: ${fmtTime(ev.created_at, true)}${f ? "  " + f : ""}`);
  }

  if (name === "buzz_unreact") {
    const g = guard("removing a reaction"); if (g) return g;
    const wb = wireBlocked(5, name); if (wb) return fail(wb);
    const ch = await resolveChannel(a.channel);
    const target = await resolveEventInChannel(ch.id, ch.name, a.event);
    const want = a.emoji != null && String(a.emoji).trim() ? String(a.emoji).trim() : null;
    const mine = (screen(await query([{ kinds: [7], authors: [PK], "#e": [target.id], limit: 50 }])).events)
      .filter((r) => r.kind === 7 && r.pubkey === PK && (r.tags || []).some((t) => t[0] === "e" && t[1] === target.id) && (!want || r.content === want));
    if (!mine.length) return fail(`buzz_unreact: you have no ${want ? want + " " : ""}reaction on <${String(target.id).slice(0, 8)}> in #${escapeName(ch.name)}.`);
    // buzz-sdk build_remove_reaction: kind 5, exactly ONE e tag (the reaction id), empty content.
    for (const r of mine) await publish(5, [["e", r.id]]);
    return ok(`removed ${mine.length} reaction${mine.length > 1 ? "s" : ""} (${[...new Set(mine.map((r) => r.content))].join(" ")}) from <${String(target.id).slice(0, 8)}> in #${escapeName(ch.name)}`);
  }

  if (name === "buzz_reactions") {
    const ch = await resolveChannel(a.channel);
    const target = await resolveEventInChannel(ch.id, ch.name, a.event);
    const rs = screen(await query([{ kinds: [7], "#e": [target.id], limit: 500 }])).events
      .filter((r) => r.kind === 7 && (r.tags || []).some((t) => t[0] === "e" && t[1] === target.id));
    let gone = new Set();
    if (rs.length) {
      const dels = screen(await query([{ kinds: [5], "#e": rs.map((r) => r.id), limit: 500 }])).events;
      const byId = new Map(rs.map((r) => [r.id, r]));
      for (const d of dels) for (const t of d.tags || []) if (t[0] === "e" && byId.get(t[1]) && byId.get(t[1]).pubkey === d.pubkey) gone.add(t[1]);
    }
    await profiles();
    const groups = new Map();
    for (const r of rs) {
      if (gone.has(r.id)) continue;
      const emo = escapeName(r.content || "+");
      const g = groups.get(emo) || new Set(); g.add(r.pubkey); groups.set(emo, g);
    }
    const rows = [...groups].sort((x, y) => y[1].size - x[1].size).map(([emo, pks]) => `${emo} ×${pks.size}: ${[...pks].map(who).join(", ")}`);
    return ok(`reactions on <${String(target.id).slice(0, 8)}> in #${escapeName(ch.name)}:\n${rows.join("\n") || "(none)"}`);
  }

  if (name === "buzz_dm_add") {
    const g = guard("adding to a DM"); if (g) return g;
    const wb = wireBlocked(41011, name); if (wb) return fail(wb);
    const dm = await dmById(String(a.channel || "").trim());
    const pk = await resolveRecipient(a.user);
    if (dm.participants.includes(pk)) return ok(`already in that DM.`);
    if (dm.participants.length >= 9) return fail("buzz_dm_add: a group DM holds at most 9 people (you + 8).");
    // v0.2.31 fix (review §3.8): adding someone exposes the DM's PRIOR history, so in wire / "post as
    // me" mode it needs confirm:true — once per session, like the other membership changes (9001).
    // The write throttle still applies to every call.
    await profiles();   // so the confirm prompt names the person
    { const gg = gate(41011, a, `adding ${who(pk)} to DM [${dm.id}]`); if (gg) return fail(gg); }
    await publish(41011, [["h", dm.id], ["p", pk]]);
    await profiles();
    return ok(`added ${who(pk)} to DM [${dm.id}]. ⚠️ they can see the conversation's prior history.`);
  }

  if (name === "buzz_dm_hide") {
    const g = guard("hiding a DM"); if (g) return g;
    const wb = wireBlocked(41012, name); if (wb) return fail(wb);
    let id = String(a.channel || "").trim();
    if (!id && a.to) {
      const pk = await resolveRecipient(a.to);
      const hit = (await dmChannels()).find((c) => c.others.length === 1 && c.others[0] === pk);
      if (!hit) return fail(`no 1:1 DM with ${a.to} to hide.`);
      id = hit.id;
    }
    if (!id) return fail("buzz_dm_hide needs `channel` (dm id) or `to`.");
    const dm = await dmById(id);
    await publish(41012, [["h", dm.id]]);
    return ok(`hid DM [${dm.id}] from your list.`);
  }
  return null;
}

const server = new Server({ name: "buzz", version: SHIM_VERSION }, { capabilities: { tools: {} } });

const TO_SCHEMA = { type: ["string", "array"], items: { type: "string" }, maxItems: 8, description: "one person (npub / hex / email / exact display-name) or an array of up to 8 for a group DM" };
const CONFIRM_PROP = { type: "boolean", description: "set true to confirm a destructive action (asked once per session per kind in wire / post-as-me mode)" };
const CH = { type: "string", description: "channel name or id" };
const EV = { type: "string", description: "the target message's <id> (from buzz_read)" };
const TOOLS = [
  { name: "buzz_whoami", description: "Show this CLI session's Buzz identity (friendly name + npub + pubkey).", inputSchema: { type: "object", properties: {} } },
  { name: "buzz_setname", description: "Override this session's friendly display name on the fleet.", inputSchema: { type: "object", properties: { name: { type: "string" } }, required: ["name"] } },
  { name: "buzz_channels", description: "List channels in the Buzz workspace.", inputSchema: { type: "object", properties: {} } },
  { name: "buzz_create_channel", description: "Create a new channel (NIP-29 kind 9007), as you — you become its owner. `name` is required. `visibility`: \"private\" (invite-only; the DEFAULT — fail-closed) or \"open\" (searchable, anyone self-joins). `type`: \"stream\" (default) or \"forum\". Optional `description`, and `ttl` (seconds — an ephemeral channel archived after that much idle). Does NOT add members: after creating, add them with buzz_add_member. The relay authorizes this against your own channel-write permission; it may refuse if your identity/delegation lacks it. `name` is at most 80 characters and `description` at most 500, neither containing control characters.", inputSchema: { type: "object", properties: { name: { type: "string", description: "channel name (a leading # and surrounding whitespace are trimmed; ≤80 chars, no control characters)" }, visibility: { type: "string", description: "\"private\" (default) or \"open\"" }, type: { type: "string", description: "\"stream\" (default) or \"forum\"" }, description: { type: "string", description: "optional channel description/about (≤500 chars)" }, ttl: { type: "number", description: "optional idle-seconds before the channel is archived (ephemeral)" } }, required: ["name"] } },
  { name: "buzz_edit_channel", description: "Edit a channel's metadata (NIP-29 kind 9002), as you — owner/admin only (relay-enforced). PATCH-style: pass only what changes; fields you omit are left untouched. `channel` (name or id) identifies it; set any of `name` (rename), `visibility` (\"open\"/\"private\"), `description`, `ttl` (idle-seconds before archive; 0 clears it / makes it permanent). Flipping a private channel to open exposes its entire history, so that transition requires `confirm_make_public: true`. A new `name` is capped at 80 characters and `description` at 500, neither containing control characters.", inputSchema: { type: "object", properties: { channel: { type: "string" }, name: { type: "string", description: "new channel name (≤80 chars, no control characters)" }, visibility: { type: "string", description: "\"open\" or \"private\"" }, description: { type: "string", description: "new about/description (empty string clears it; ≤500 chars)" }, ttl: { type: "number", description: "idle-seconds before archive; 0 clears it" }, confirm_make_public: { type: "boolean", description: "required opt-in when changing a private channel to open (acknowledges exposing its history)" } }, required: ["channel"] } },
  { name: "buzz_join_channel", description: "Join an OPEN channel yourself (NIP-29 kind 9021). Idempotent — a no-op if you're already a member. Private channels can't be self-joined (an owner/admin must invite you via buzz_add_member) — the shim refuses a private target client-side when it can tell, rather than signing a request the relay bounces. `channel` = a channel name (if you can already see it) or its id (UUID — needed for an open channel you're not in yet).", inputSchema: { type: "object", properties: { channel: { type: "string", description: "channel name or id (UUID)" } }, required: ["channel"] } },
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
  { name: "buzz_dm_open", description: "Open (or find) a 1:1 DM with a person and return its channel id. `to` = npub / hex / email / exact display-name.", inputSchema: { type: "object", properties: { to: TO_SCHEMA }, required: ["to"] } },
  { name: "buzz_dm_send", description: "Send a direct message to a person — opens the 1:1 if needed, then sends. `to` = npub / hex / email / exact display-name. The body goes in `text` (its alias `message` is also accepted).", inputSchema: { type: "object", properties: { to: TO_SCHEMA, text: { type: "string" }, message: { type: "string", description: "alias for `text` (accepted if `text` is omitted)" } }, required: ["to"] } },
  { name: "buzz_status_set", description: "Set your live user status (NIP-38 kind 30315, d=general). `text` = the status message (empty allowed), optional `emoji`. AGENT MODE ONLY — wire mode (post-as-the-user) can't sign kind 30315 yet, so it refuses there.", inputSchema: { type: "object", properties: { text: { type: "string", description: "the status text (empty allowed)" }, emoji: { type: "string", description: "optional status emoji" } } } },
  { name: "buzz_status_clear", description: "Clear your live user status (NIP-38 kind 30315 with empty content, d=general — a replaceable-event clear). AGENT MODE ONLY — wire mode can't sign kind 30315 yet, so it refuses there.", inputSchema: { type: "object", properties: {} } },
  { name: "buzz_unread", description: "Read-only activity digest: across your channels and DMs, count recent messages from others (last `hours`, default 24) and how many @mention you. A heuristic (NOT real read-state) — it performs no writes.", inputSchema: { type: "object", properties: { hours: { type: "number", description: "look-back window in hours (default 24)" } } } },
  { name: "buzz_login", description: "Sign in as YOURSELF for \"post as me\" (Ekam wire-sign OAuth) WITHOUT a terminal — for GUI/desktop (Claude Desktop/MCPB) clients that can't run the buzz-mcp-login CLI. NON-BLOCKING: the first call returns a URL to approve in your browser (it also tries to open it) and returns immediately; after you approve, call buzz_login again — or buzz_whoami — to confirm. Idempotent: if you're already connected it says so. Optional `client_id` (else env BUZZ_EKAM_CLIENT_ID).", inputSchema: { type: "object", properties: { client_id: { type: "string", description: "Ekam OAuth client id (from DCR); falls back to env BUZZ_EKAM_CLIENT_ID" } } } },
  { name: "buzz_doctor", description: "Diagnose why Buzz reads/posts are failing, WITHOUT using the shim's normal (possibly-wedged) transport — it probes the relay over a brand-new node:https socket. Read-only; no writes. Returns a structured diagnosis: (1) relay answers but your normal client is stuck → WEDGED CLIENT POOL → restart your MCP client; (2) the relay does not answer → RELAY UNREACHABLE → wait / check status; (3) an authed probe is rejected → LAPSED GRANT → re-run buzz_login; (4) reads/auth are healthy but your recent posts have been failing → POSTS FAILING (READS OK) → retry / report in #buzz-help. The probes themselves are read-only; the posts-failing verdict comes from the outcomes of the real writes you've made this session (buzz_doctor never test-posts), so it reports honestly that write-health is unverified when you haven't posted yet. Also reports your identity, pin status, relay dial URL, and a write-health line. Connector-side probe only — not the authoritative relay health signal. Optional `timeout_s` (default 5).", inputSchema: { type: "object", properties: { timeout_s: { type: "number", description: "per-probe timeout in seconds (default 5, max 30)" } } } },
  // ---- v0.2.31 Slack-parity tools ----
  { name: "buzz_edit_message", description: "Edit one of YOUR OWN messages (kind 40003, h + e tags; new text ≤ 64 KB). Clients show the edited text marked (edited). Not available in wire / post-as-me mode yet (kind 40003 is not on Ekam's wire-sign allowlist).", inputSchema: { type: "object", properties: { channel: CH, event: EV, text: { type: "string", description: "the replacement text" }, message: { type: "string", description: "alias for `text`" } }, required: ["channel", "event"] } },
  { name: "buzz_thread_read", description: "Read a whole thread: the root message plus every reply (NIP-10). `event` may be the root or any reply in it.", inputSchema: { type: "object", properties: { channel: CH, event: EV, limit: { type: "number", description: "max replies (default 50, max 200)" } }, required: ["channel", "event"] } },
  { name: "buzz_channel_topic", description: "Set or clear a channel's topic and/or purpose (kind 9002, owner/admin only — relay-enforced). Empty string clears.", inputSchema: { type: "object", properties: { channel: CH, topic: { type: "string", description: "new topic (≤500 chars; empty clears)" }, purpose: { type: "string", description: "new purpose (≤500 chars; empty clears)" }, confirm: CONFIRM_PROP }, required: ["channel"] } },
  { name: "buzz_leave_channel", description: "Leave a channel you're in (kind 9022). Not available in wire / post-as-me mode yet (kind 9022 is not on Ekam's wire-sign allowlist).", inputSchema: { type: "object", properties: { channel: CH }, required: ["channel"] } },
  { name: "buzz_archive_channel", description: "Archive (read-only for everyone) or unarchive a channel (kind 9002 archived tag; owner/admin only). Archiving needs `confirm: true`. `archived` defaults to true; pass false to unarchive.", inputSchema: { type: "object", properties: { channel: CH, archived: { type: "boolean", description: "true = archive (default), false = unarchive" }, confirm: CONFIRM_PROP }, required: ["channel"] } },
  { name: "buzz_delete_channel", description: "Permanently delete a channel (kind 9008; owner only — relay-enforced). Always needs `confirm: true`. Not available in wire / post-as-me mode yet (kind 9008 is not on Ekam's wire-sign allowlist).", inputSchema: { type: "object", properties: { channel: CH, confirm: CONFIRM_PROP }, required: ["channel"] } },
  { name: "buzz_profile", description: "Look up a person's profile (kind 0) by npub / hex pubkey / email (wire mode) / exact display name. Read-only; profile fields are shown escaped as untrusted text.", inputSchema: { type: "object", properties: { user: { type: "string", description: "npub / hex pubkey / email / exact display name" } }, required: ["user"] } },
  { name: "buzz_unreact", description: "Remove YOUR reaction from a message (kind 5 deletion with one e tag = your reaction's id). Optional `emoji` removes only that one; otherwise all of yours on the message. Not available in wire / post-as-me mode yet (kind 5 is not on Ekam's wire-sign allowlist).", inputSchema: { type: "object", properties: { channel: CH, event: EV, emoji: { type: "string", description: "only remove this emoji (default: all of yours on the message)" } }, required: ["channel", "event"] } },
  { name: "buzz_reactions", description: "List the reactions on a message, grouped by emoji, with who reacted. Read-only; reactions their author removed (kind 5) are left out.", inputSchema: { type: "object", properties: { channel: CH, event: EV }, required: ["channel", "event"] } },
  { name: "buzz_dm_add", description: "Add a person to an existing DM conversation you're in (kind 41011; at most 9 people total). They can see its prior history, so in wire / post-as-me mode the first add of the session needs `confirm: true`.", inputSchema: { type: "object", properties: { channel: { type: "string", description: "the DM's channel id (from buzz_dm_list)" }, user: { type: "string", description: "npub / hex pubkey / email / exact display name" }, confirm: CONFIRM_PROP }, required: ["channel", "user"] } },
  { name: "buzz_dm_hide", description: "Hide a DM conversation from your DM list (kind 41012). Identify it by `channel` (dm id) or `to` (the other person of a 1:1). Not available in wire / post-as-me mode yet (kind 41012 is not on Ekam's wire-sign allowlist).", inputSchema: { type: "object", properties: { channel: { type: "string", description: "the DM's channel id" }, to: { type: "string", description: "the other person of a 1:1 DM" } } } },
];

// ---- v0.2.31 (items 3 + 11): MCP tool annotations, closed schemas, bounded arguments. ----
// readOnly = never writes; destructive = can remove data/membership/visibility; idempotent =
// repeating it has no further effect; openWorld = talks to the Buzz relay (all do, except whoami's
// local identity lines, which still fetch relay info).
const ANNOTATIONS = {
  readOnly: ["buzz_whoami", "buzz_channels", "buzz_agents", "buzz_search", "buzz_channel_members", "buzz_read", "buzz_attachment_read", "buzz_dm_list", "buzz_dm_read", "buzz_unread", "buzz_doctor", "buzz_thread_read", "buzz_profile", "buzz_reactions"],
  destructive: ["buzz_remove_member", "buzz_delete", "buzz_edit_channel", "buzz_leave_channel", "buzz_archive_channel", "buzz_delete_channel", "buzz_unreact", "buzz_edit_message", "buzz_status_clear", "buzz_dm_hide"],
  idempotent: ["buzz_setname", "buzz_join_channel", "buzz_add_member", "buzz_remove_member", "buzz_delete", "buzz_dm_open", "buzz_status_set", "buzz_status_clear", "buzz_channel_topic", "buzz_leave_channel", "buzz_archive_channel", "buzz_delete_channel", "buzz_edit_message", "buzz_unreact", "buzz_dm_add", "buzz_dm_hide", "buzz_login", "buzz_edit_channel"],
};
const ARG_BOUNDS = {
  limit: { minimum: 1, maximum: 200 }, hours: { minimum: 0, maximum: 720 }, timeout_s: { minimum: 0, maximum: 30 },
  index: { minimum: 0, maximum: 63 }, ttl: { minimum: 0, maximum: 31536000 },
  text: { maxLength: 65536 }, message: { maxLength: 65536 }, comment: { maxLength: 65536 }, query: { maxLength: 1000 },
  attachment: { maxLength: 4096 }, emoji: { maxLength: 64 }, channel: { maxLength: 256 }, source_channel: { maxLength: 256 },
  event: { maxLength: 128 }, user: { maxLength: 320 }, client_id: { maxLength: 256 }, role: { maxLength: 16 },
  visibility: { maxLength: 16 }, type: { maxLength: 16 }, name: { maxLength: 400 }, description: { maxLength: 2000 },
  topic: { maxLength: 2000 }, purpose: { maxLength: 2000 },
};
for (const t of TOOLS) {
  const sc = t.inputSchema;
  sc.additionalProperties = false;
  for (const [k, p] of Object.entries(sc.properties || {})) {
    const b = ARG_BOUNDS[k];
    if (!b) continue;
    const isNum = p.type === "number" || p.type === "integer";
    for (const [bk, bv] of Object.entries(b)) {
      if ((bk === "maxLength") === isNum) continue;   // length bounds on strings, range bounds on numbers
      if (p[bk] == null) p[bk] = bv;
    }
  }
  if (["buzz_remove_member", "buzz_delete", "buzz_edit_channel"].includes(t.name)) sc.properties.confirm = CONFIRM_PROP;
  if (t.name === "buzz_search" && sc.properties.limit) sc.properties.limit.maximum = 100;
  const ro = ANNOTATIONS.readOnly.includes(t.name);
  t.annotations = {
    title: t.name.replace(/^buzz_/, "Buzz: ").replace(/_/g, " "),
    readOnlyHint: ro,
    destructiveHint: !ro && ANNOTATIONS.destructive.includes(t.name),
    idempotentHint: ro || ANNOTATIONS.idempotent.includes(t.name),
    openWorldHint: true,
  };
}

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

// ---- environment self-check: surface the relay's OWN self-report + key provenance,
// so no "live"/identity claim is ever made blind (see: 3x non-prod false-positives). ----
let RELAY_INFO = null, RELAY_INFO_AT = 0;
const RELAY_INFO_TTL = 30_000; // re-fetch NIP-11 if older than 30s, so a mid-session relay roll (software_sha) is visible instead of a process-lifetime stale cache
// v0.2.23 — client-version skew. The relay advertises the current/minimum shim version
// in its NIP-11 doc (shim_latest / shim_min); we read it off the fetch we already do.
// FAIL-OPEN: if the relay advertises nothing (its half not shipped yet) or the value is
// unparseable, CLIENT_VERSION stays "ok"/silent and nothing changes. We nudge to stderr
// (NEVER stdout — that's the MCP channel) at most once per process, so a long-lived
// session isn't nagged; buzz_doctor/buzz_whoami surface the status every time on demand.
let CLIENT_VERSION = { level: "ok", running: SHIM_VERSION, latest: undefined, min: undefined, message: null };
let VERSION_NUDGED = false;
async function relayInfo() {
  if (RELAY_INFO && Date.now() - RELAY_INFO_AT < RELAY_INFO_TTL) return RELAY_INFO;
  try {
    const r = await fetch(`${RELAY}/`, { headers: { Accept: "application/nostr+json" }, signal: timeoutSignal(RELAYINFO_TIMEOUT_S) });
    const j = await r.json();
    RELAY_INFO = { name: j.name || "?", software: j.software || "?", version: j.version || "?", sha: j.software_sha || null, self: typeof j.self === "string" ? j.self : null };
    try {
      CLIENT_VERSION = clientVersionStatus(SHIM_VERSION, pickAdvertised(j));
      if (CLIENT_VERSION.message && !VERSION_NUDGED) { VERSION_NUDGED = true; process.stderr.write(CLIENT_VERSION.message + "\n"); }
    } catch { /* fail-open: a skew-check bug must never break relay info */ }
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
  const base = KEY_ENV_PIN
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

server.setRequestHandler(CallToolRequestSchema, async (req, extra = {}) => {
  // v0.2.31 (item 6): every tool call runs inside a request context carrying the client's cancel
  // signal and progress token, so long transfers abort on cancel and report progress.
  const store = { signal: extra.signal, sendNotification: extra.sendNotification, progressToken: req.params && req.params._meta && req.params._meta.progressToken };
  return REQ_CTX.run(store, () => callTool(req));
});
async function callTool(req) {
  const { name, arguments: a = {} } = req.params;
  const ok = (s) => ({ content: [{ type: "text", text: s }] });
  const fail = (s) => ({ content: [{ type: "text", text: s }], isError: true });
  // v0.2.31 (item 11): refuse unknown keys / wrong types / out-of-range values against the advertised
  // schema (additionalProperties:false). Missing-argument messages stay with each handler.
  const tool = TOOLS.find((t) => t.name === name);
  if (tool) { const bad = validateArgs({ ...tool.inputSchema, required: [] }, a); if (bad) return fail(`${name}: ${bad}`); }
  try {
    if (name === "buzz_whoami") {
      const info = await relayInfo();
      const relayLine = info.error ? `⚠ UNREACHABLE: ${info.error}` : `${info.name} · v${info.version}${info.sha ? ` · deploy ${info.sha.slice(0, 12)}` : " · (no software_sha — stale build?)"}`;
      const configLine = IS_ISOLATED ? "isolated ✅ (own CLAUDE_CONFIG_DIR)" : `⚠ SHARED ~/.claude.json — clobberable/flip-prone. Relaunch via 'buzz-claude ${MY_NAME}' to isolate. Guide: ${GUIDE_PATH}`;
      const skewNote = CLIENT_VERSION.message
        ? (CLIENT_VERSION.level === "below-min" ? ` — ⚠ below the relay's minimum v${CLIENT_VERSION.min}, update soon` : ` — ℹ update available: v${CLIENT_VERSION.latest}`)
        : "";
      return ok(`Buzz CLI identity:\n  name: ${MY_NAME}\n  shim: @ola/buzz-mcp v${SHIM_VERSION}${skewNote}\n  model: ${AGENT_MODEL}\n  harness: ${AGENT_HARNESS}\n  interface: ${AGENT_INTERFACE}\n  npub: ${nip19.npubEncode(PK)}\n  pubkey: ${PK}\n  identity: ${keyProvenance()}\n  config: ${configLine}\n  relay (dial): ${RELAY}\n  relay (self-report): ${relayLine}\n  auth_tag: ${AUTH_TAG ? "present (ViaOwner delegation)" : (AUTH_TAG_MALFORMED ? "⚠ set but MALFORMED (quote-stripped? single-quote it in agent.env) — omitted → 403 membership" : "none")}\n  transport: ${TRANSPORT_WEDGED ? "⚠ undici pool wedged — self-healing via fresh node:https sockets (reads/posts still work); a full client RESTART clears it" : "ok"}\n  NOTE: the deploy SHA above is the LIVE prod build (relay's software_sha) — compare it before claiming "X is deployed". reachable ≠ up-to-date.`);
    }

    if (name === "buzz_setname") {
      if (!IDENTITY_OK) return { content: [{ type: "text", text: `refused: impersonation guard — key ${PK.slice(0, 16)}… ≠ pinned ${EXPECTED_PK.slice(0, 16)}… (running as ${MY_NAME}). Not writing a profile as the wrong agent.` }], isError: true };
      if (signer.mode === "wire") return { content: [{ type: "text", text: `refused: wire mode posts as the user — the display name is the user's own profile (kind:0), not settable from the shim.` }], isError: true };
      await publishProfile(a.name);
      return ok(`renamed this session to "${a.name}" on the fleet.`);
    }

    if (name === "buzz_channels") {
      const cs = await channels();
      // v0.2.31 fix (review §3.4): channel names/descriptions are attacker-writable free text
      // (a description is up to 500 chars incl. newlines) — escape both, one channel per line.
      return ok(`${UNTRUSTED_NOTE}\n` + (cs.length ? cs.map((c) => `#${escapeName(c.name)}  [${escapeName(c.id)}]${c.about ? `  ${escapeContent(c.about, { cap: 500 })}` : ""}`).join("\n") : "(no channels)"));
    }

    if (name === "buzz_agents") {
      const p = await profiles();
      const archived = await archivedPubkeys();   // (A) NIP-IA archived identities are hidden
      const rows = Object.entries(p).filter(([pk]) => !archived.has(pk));
      const hidden = Object.keys(p).length - rows.length;
      return ok((rows.map(([pk, n]) => `${escapeName(n)}  ${pk.slice(0, 12)}…${PROFILE_IDX.collide.has(pk) ? "  ⚠name-collision" : ""}`).join("\n") || "(none)")
        + (hidden ? `\n(${hidden} archived identit${hidden === 1 ? "y" : "ies"} hidden — NIP-IA)` : ""));
    }

    if (name === "buzz_read") {
      const ch = await resolveChannel(a.channel);
      const names = await profiles();
      void names;
      const scr = screen(await query([{ kinds: [9], "#h": [ch.id], limit: clampLimit(a.limit, 30, 200) }]));
      const edits = await latestEdits(ch.id, scr.events);
      const rows = scr.events.sort((x, y) => x.created_at - y.created_at).map((e) => renderMsg(e, { edits, flagOf: scr.flagOf }));
      return ok(`#${escapeName(ch.name)} (${rows.length} msgs) — <id> = react target:\n${UNTRUSTED_NOTE}${scr.note ? "\n" + scr.note : ""}\n` + (rows.join("\n") || "(empty)"));
    }

    if (name === "buzz_search") {
      const q = String(a.query || "").trim();
      if (!q) throw new Error("buzz_search needs a `query` string");
      const names = await profiles();
      const cs = await channels();
      const chById = Object.fromEntries(cs.map((c) => [c.id, c.name]));
      const filt = { kinds: [9], search: q, limit: clampLimit(a.limit, 20, 100) };
      let scope = "";
      if (a.channel) { const ch = await resolveChannel(a.channel); filt["#h"] = [ch.id]; scope = ` in #${escapeName(ch.name)}`; }
      void names;
      const scr = screen(await query([filt]));
      const rows = scr.events.sort((x, y) => y.created_at - x.created_at).map((e) => {
        const hTag = (e.tags || []).find((t) => t[0] === "h");
        const chan = hTag ? (chById[hTag[1]] || hTag[1].slice(0, 8)) : "?";
        return `#${escapeName(chan)} ${row(e, { withDate: true, flagOf: scr.flagOf })}`;
      });
      return ok(`search "${escapeContent(q)}"${scope} → ${rows.length} result(s):\n${UNTRUSTED_NOTE}${scr.note ? "\n" + scr.note : ""}\n` + (rows.join("\n") || "(none)"));
    }

    if (name === "buzz_channel_members") {
      const ch = await resolveChannel(a.channel);
      const names = await profiles();
      const evs = await query([{ kinds: [39002], "#d": [ch.id], limit: 5 }]);
      // kind:39002 = one membership event per channel; p-tags are members, tag[3] = role (owner|member).
      const seen = new Map();
      for (const e of evs || []) for (const tg of e.tags || []) if (tg[0] === "p" && tg[1] && !seen.has(tg[1])) seen.set(tg[1], tg[3] || "member");
      void names;
      const rows = [...seen].map(([pk, role]) => `${who(pk)}${role === "owner" ? " (owner)" : ""}`);
      return ok(`#${escapeName(ch.name)} — ${rows.length} member(s):\n` + (rows.join("\n") || "(none)"));
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
      // @-mentions → p-tags, fail-closed (mentionPtags: exact first, ambiguous/lookalike/archived
      // tags nobody and is reported). (E) only strict 64-lowercase-hex pubkeys.
      const tags = [["h", ch.id]];
      if (AUTH_TAG) tags.push(AUTH_TAG);   // NIP-OA owner attestation → "Agent managed by <owner>"
      const mres = await mentionPtags(bodyText);
      for (const pk of mres.pubkeys) tags.push(["p", pk]);
      // Optional attachment: upload the local file (Blossom) → attach a NIP-92 imeta tag
      // whose url/x match exactly what was uploaded (hash-bound). Content echoes the url too,
      // matching how Buzz clients render attachments.
      let attached = null, content = bodyText;
      if (a.attachment) {
        attached = await uploadAttachments(a.attachment);
        for (const up of attached.ups) { tags.push(buildImeta(up)); content = content ? `${content}\n${up.url}` : up.url; }
      }
      const ev = await signer.sign({ kind: 9, tags, content });
      await bridge("/events", ev);
      const mentioned = tags.filter((t) => t[0] === "p").length;
      return ok(`posted to #${escapeName(ch.name)}${mentioned ? ` (mentioned ${mentioned})` : ""}${attachedLabel(attached)}: ${bodyText}${mentionNote(mres)}`);
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
        if (pref.length > 1) throw new Error(`event id "${targetId}" is ambiguous in #${escapeName(ch.name)} (${pref.length} matches) — use more characters`);
        hit = pref[0];
      }
      if (!hit) throw new Error(`no message ${targetId.slice(0, 8)}… in #${escapeName(ch.name)} — use the <id> from buzz_read`);
      const atts = messageAttachments(hit);
      if (!atts.length) return ok(`message <${String(hit.id).slice(0, 8)}> in #${escapeName(ch.name)} has no attachments.`);
      const idx = Number.isInteger(a.index) ? a.index : 0;
      const att = atts[idx];
      if (!att) throw new Error(`attachment index ${idx} out of range — message has ${atts.length} (0..${atts.length - 1})`);
      if (!att.sha256) throw new Error(`attachment has no sha256 (x tag) — refusing to fetch an unverifiable blob`);
      const shaExt = basename(new URL(att.url).pathname); // "<sha>.<ext>"
      const ext = extname(shaExt) || (att.filename ? extname(att.filename) : "");
      if (!/^[0-9a-f]{64}$/.test(String(att.sha256).toLowerCase())) throw new Error("attachment sha256 is not 64-hex — refusing");
      const dest = await blossomDownload(shaExt, { ext });
      const got = await sha256File(dest);
      if (got !== att.sha256) { try { unlinkSync(dest); } catch {} throw new Error(`integrity check failed: downloaded ${got.slice(0, 12)}… ≠ imeta ${att.sha256.slice(0, 12)}… — discarded`); }
      const size = statSync(dest).size;
      const isText = (att.mime && TEXT_MIME.test(att.mime)) || /\.(md|txt|csv|json|ya?ml|log|tsv)$/i.test(att.filename || shaExt);
      if (isText) {
        const full = readFileSync(dest, "utf8");
        const CAP = 200 * 1024;
        // review §3.4 nice-to-have: fence the raw file text with a per-call random boundary the
        // file can't predict, so it can't fake "end of file" and append instructions after it.
        const fence = `<<<BEGIN UNTRUSTED FILE ${randomBytes(6).toString("hex")}>>>`;
        const body = full.length > CAP ? `${full.slice(0, CAP)}\n…[truncated ${full.length - CAP} chars — full file at ${dest}]` : full;
        return ok(`📎 ${escapeName(att.filename || shaExt)} (${escapeName(att.mime || "text")}, ${(size / 1024).toFixed(0)} KB) from #${escapeName(ch.name)} — saved at ${dest}\n${UNTRUSTED_NOTE.replace("message content", "file content")}\n${fence}\n${body}\n${fence.replace("BEGIN", "END")}`);
      }
      return ok(`📎 saved ${escapeName(att.filename || shaExt)} → ${dest}\n   (${att.mime || "binary"}, ${(size / MB).toFixed(2)} MB, sha ${att.sha256.slice(0, 12)}…) — not text; open the file to view.`);
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
        if (!hit) throw new Error(`message ${targetId.slice(0, 8)}… is not in #${escapeName(ch.name)} — reactions must target a message in the channel you name`);
      } else {
        // short <id> prefix from buzz_read → scan THIS channel and match by prefix.
        // NEVER put a prefix in an `ids` filter — the relay rejects a non-64-hex id.
        const recent = await query([{ kinds: [9], "#h": [ch.id], limit: 200 }]) || [];
        const pref = recent.filter((e) => String(e.id).startsWith(targetId));
        if (pref.length > 1) throw new Error(`event id "${targetId}" is ambiguous in #${escapeName(ch.name)} (${pref.length} matches) — use more characters`);
        hit = pref[0];
        if (!hit) throw new Error(`no message with id "${targetId}" found in #${escapeName(ch.name)} — use the <id> shown by buzz_read`);
      }
      // Belt-and-braces: assert the resolved target carries h = this channel before signing.
      if (!(hit.tags || []).some((t) => t[0] === "h" && t[1] === ch.id))
        throw new Error(`target message is not bound to #${escapeName(ch.name)} — refusing a cross-channel reaction`);
      targetId = hit.id;
      const author = hit.pubkey || "", tkind = hit.kind || 9;
      const emoji = (a.emoji && String(a.emoji).trim()) || "👍";
      // reactionTemplate REFUSES a target-less reaction (throws) → surfaced as a tool error.
      const tmpl = reactionTemplate({ targetId, targetAuthor: author, targetKind: tkind, channelId: ch.id, emoji });
      if (AUTH_TAG) tmpl.tags.push(AUTH_TAG);   // owner attestation (agent mode; absent in wire mode)
      const ev = await signer.sign(tmpl);
      await bridge("/events", ev);
      if (author) await profiles();
      const whoL = author ? who(author) : "";
      return ok(`reacted ${emoji} to ${whoL ? `${whoL}'s ` : ""}message <${String(targetId).slice(0, 8)}> in #${escapeName(ch.name)}`);
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
      // NIP-10 marked threading, read the way the relay reads it (buzz-core nip10.rs
      // ThreadMarkers::resolve: 64-hex ids only, last marker of each kind wins):
      //   root + reply → the target is a nested reply; its thread root is the root marker
      //   reply only   → the target is a direct reply; its thread root is the reply marker
      //   root only / none → the target is top-level, so it is the thread head itself
      // A target inside a thread gets root (its thread root) + reply (the target); a thread head
      // gets a single "reply" marker. Never a lone "root" (the relay reads that as top-level),
      // and never reply-only to a target inside a thread (the relay then takes the target as the
      // root, and ingest refuses 400 "root tag does not match thread ancestry").
      // Desktop (threading.ts) and mobile (send_message_provider.dart) build the same tags.
      let mRoot = null, mReply = null;
      for (const t of target.tags || []) if (t[0] === "e" && /^[0-9a-f]{64}$/i.test(t[1] || "")) {
        if (t[3] === "root") mRoot = t[1];
        if (t[3] === "reply") mReply = t[1];
      }
      const rootId = mReply ? (mRoot || mReply) : null;
      if (rootId && rootId !== target.id) { tags.push(["e", rootId, "", "root"]); tags.push(["e", target.id, "", "reply"]); }
      else tags.push(["e", target.id, "", "reply"]);
      // p-tags: the author being replied to (NIP-10) + any @-mentions in the body (buzz_post idiom).
      const ptags = new Set();
      if (/^[0-9a-f]{64}$/i.test(target.pubkey || "")) ptags.add(target.pubkey.toLowerCase());
      const mres = await mentionPtags(bodyText);
      for (const pk of mres.pubkeys) ptags.add(pk);
      for (const pk of ptags) tags.push(["p", pk]);
      // Optional attachment: upload the local file (Blossom) → NIP-92 imeta tag, url echoed in content.
      let attached = null, content = bodyText;
      if (a.attachment) {
        attached = await uploadAttachments(a.attachment);
        for (const up of attached.ups) { tags.push(buildImeta(up)); content = content ? `${content}\n${up.url}` : up.url; }
      }
      const ev = await signer.sign({ kind: 9, tags, content });
      await bridge("/events", ev);
      const mentioned = tags.filter((t) => t[0] === "p").length;
      return ok(`replied in #${escapeName(ch.name)} to ${who(target.pubkey)}'s <${String(target.id).slice(0, 8)}>${mentioned ? ` (p-tagged ${mentioned})` : ""}${attachedLabel(attached)}: ${bodyText}${mentionNote(mres)}`);
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
        destId = dch.id; destLabel = `#${escapeName(dch.name)}`;
      } catch {
        const pk = await resolveRecipient(a.to);   // npub / hex / email / exact name → 64-hex, or throws
        const { channelId } = await openDm([pk]);
        destId = channelId;
        await profiles(); destLabel = `DM ${who(pk)}`;
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
      await profiles();
      return ok(`added ${who(pk)} to #${escapeName(ch.name)}${a.role ? ` as ${a.role}` : ""}. ⚠️ they can now see this channel's prior history.`);
    }

    if (name === "buzz_remove_member") {
      if (!IDENTITY_OK) return modRefuse("removing members");
      const ch = await resolveChannel(a.channel);
      const pk = await resolveRecipient(a.user);
      { const g = gate(9001, a, `remove ${pk.slice(0, 8)} from #${escapeName(ch.name)}`); if (g) return fail(g); }
      const tmpl = removeMemberTemplate({ channelId: ch.id, targetPubkey: pk });
      if (AUTH_TAG) tmpl.tags.push(AUTH_TAG);
      const ev = await signer.sign(tmpl);
      await bridge("/events", ev);
      await profiles();
      return ok(`removed ${who(pk)} from #${escapeName(ch.name)}. (Allowed only because the relay confirmed your role permits it.)`);
    }

    if (name === "buzz_create_channel") {
      if (!IDENTITY_OK) return modRefuse("creating a channel");
      // Mirror buzz-core canonical_channel_name: strip a leading '#'/whitespace and trailing whitespace.
      const chName = canonChannelName(typeof a.name === "string" ? a.name : "");
      if (!chName)
        return { content: [{ type: "text", text: "buzz_create_channel needs a non-empty `name`." }], isError: true };
      const nameErr = channelNameError(chName);
      if (nameErr) return { content: [{ type: "text", text: `buzz_create_channel: ${nameErr}` }], isError: true };
      // visibility: open (searchable + self-join) | private (invite-only). Default "open" matches the
      // relay's own default for a kind:9007 lacking a visibility tag. type: stream | forum.
      const vis = (a.visibility == null || a.visibility === "") ? "private" : String(a.visibility).toLowerCase();  // fail-closed default
      if (vis !== "open" && vis !== "private")
        return { content: [{ type: "text", text: `buzz_create_channel: \`visibility\` must be "open" or "private" (got "${vis}").` }], isError: true };
      const ct = (a.type == null || a.type === "") ? "stream" : String(a.type).toLowerCase();
      if (ct !== "stream" && ct !== "forum")
        return { content: [{ type: "text", text: `buzz_create_channel: \`type\` must be "stream" or "forum" (got "${ct}").` }], isError: true };
      const channelId = randomUUID();
      // NIP-29 create-group (kind 9007): the relay creates the channel and makes the signer its owner.
      // h-tag = client-chosen channel UUID; name/visibility/channel_type/about/ttl mirror
      // buzz_sdk::build_create_channel so the relay's kind:9007 validator accepts it unchanged.
      const tags = [["h", channelId], ["name", chName], ["visibility", vis], ["channel_type", ct]];
      if (typeof a.description === "string" && a.description.trim()) {
        const aboutErr = channelAboutError(a.description);
        if (aboutErr) return { content: [{ type: "text", text: `buzz_create_channel: ${aboutErr}` }], isError: true };
        tags.push(["about", a.description]);
      }
      if (Number.isFinite(a.ttl) && a.ttl > 0) tags.push(["ttl", String(Math.floor(a.ttl))]);
      if (AUTH_TAG) tags.push(AUTH_TAG);   // NIP-OA owner attestation (relay authorizes under ChannelsWrite)
      const ev = await signer.sign({ kind: 9007, tags, content: "" });
      await bridge("/events", ev);
      return ok(`created #${chName} (${vis} ${ct}) — channel id ${channelId}. You are its owner. Add members with buzz_add_member (channel: "${chName}" or the id). ${vis === "open" ? "It's open, so anyone can find and join it." : "It's private — only members you add can see it."}`);
    }

    if (name === "buzz_edit_channel") {
      if (!IDENTITY_OK) return modRefuse("editing a channel");
      const ch = await resolveChannel(a.channel);
      // NIP-29 edit-metadata (kind 9002) is PATCH: the relay applies each tag present as its own
      // field update (handle_edit_metadata) and leaves every omitted field untouched — so a rename
      // never resets visibility/description. Mirror buzz_sdk::build_update_channel's tags.
      const tags = [["h", ch.id]];
      const changed = [];
      if (a.name != null && String(a.name).trim() !== "") {
        const nn = canonChannelName(a.name);
        if (!nn) return { content: [{ type: "text", text: "buzz_edit_channel: `name` can't be only '#'/whitespace." }], isError: true };
        const nameErr = channelNameError(nn);
        if (nameErr) return { content: [{ type: "text", text: `buzz_edit_channel: ${nameErr}` }], isError: true };
        tags.push(["name", nn]); changed.push(`name → "${nn}"`);
      }
      if (a.visibility != null && a.visibility !== "") {
        const v = String(a.visibility).toLowerCase();
        if (v !== "open" && v !== "private")
          return { content: [{ type: "text", text: `buzz_edit_channel: \`visibility\` must be "open" or "private" (got "${v}").` }], isError: true };
        // Guard the private → open flip: opening a private channel exposes its ENTIRE history to anyone
        // who can find and join it, in one call. Only proceed on an explicit opt-in. Read the channel's
        // CURRENT visibility from its kind:39000 metadata; if it's private — or we can't tell (fail safe)
        // — require confirm_make_public. An already-open channel staying open is a harmless no-op.
        if (v === "open") {
          let curVis = null;
          try {
            const meta = (await query([{ kinds: [39000], "#d": [ch.id], limit: 5 }]) || [])[0];
            if (meta) curVis = (meta.tags || []).some((t) => t[0] === "private") ? "private"
              : (meta.tags || []).some((t) => t[0] === "public") ? "open" : null;
          } catch { /* unknown → fail safe below */ }
          if (curVis !== "open" && a.confirm_make_public !== true)
            return { content: [{ type: "text", text: `buzz_edit_channel: making #${escapeName(ch.name)} open would expose its entire history to anyone who can find and join it${curVis === null ? " (and I couldn't confirm its current visibility)" : ""}. If that's intended, re-run with confirm_make_public: true.` }], isError: true };
        }
        tags.push(["visibility", v]); changed.push(`visibility → ${v}`);
      }
      if (typeof a.description === "string") {
        if (a.description) {
          const aboutErr = channelAboutError(a.description);
          if (aboutErr) return { content: [{ type: "text", text: `buzz_edit_channel: ${aboutErr}` }], isError: true };
        }
        tags.push(["about", a.description]); changed.push(a.description.trim() ? "description" : "description cleared");
      }
      if (a.ttl != null) {
        if (!Number.isFinite(a.ttl) || a.ttl < 0)
          return { content: [{ type: "text", text: "buzz_edit_channel: `ttl` must be a non-negative number of seconds (0 clears it)." }], isError: true };
        tags.push(["ttl", a.ttl > 0 ? String(Math.floor(a.ttl)) : ""]); changed.push(a.ttl > 0 ? `ttl → ${Math.floor(a.ttl)}s` : "ttl cleared (permanent)");
      }
      if (changed.length === 0)
        return { content: [{ type: "text", text: "buzz_edit_channel: pass at least one of `name`, `visibility`, `description`, `ttl` to change." }], isError: true };
      { const g = gate(9002, a, `edit #${escapeName(ch.name)} (${changed.join(", ")})`); if (g) return fail(g); }
      if (AUTH_TAG) tags.push(AUTH_TAG);
      const ev = await signer.sign({ kind: 9002, tags, content: "" });
      await bridge("/events", ev);
      // (D, v0.2.30) Read-back: an accepted 9002 is not proof the relay applied it. Re-read the
      // channel's kind:39000 and compare every field we asked to change — a mismatch (above all
      // visibility/private, name, ttl) is reported as an ERROR, never as "edited".
      const want = {};
      for (const t of tags) {
        if (t[0] === "name") want.name = t[1];
        if (t[0] === "visibility") want.visibility = t[1];
        if (t[0] === "about") want.about = t[1].trim();
        if (t[0] === "ttl") want.ttl = t[1] || null;
      }
      const v = await verifyChannelEdit(ch.id, want);
      if (!v.ok)
        return { content: [{ type: "text", text: `buzz_edit_channel: the relay accepted the kind:9002 for #${escapeName(ch.name)}, but ${v.unreadable ? `its kind:39000 metadata could not be re-read to confirm it (${escapeContent(v.unreadable, { cap: 300 })})` : `its kind:39000 metadata does NOT reflect it — ${escapeContent(v.mismatches.join("; "), { cap: 600 })}`}. Treat the edit as NOT applied; check with buzz_channels and retry, or ask a channel admin.` }], isError: true };
      return ok(`edited #${escapeName(ch.name)}: ${changed.join(", ")} — verified against the relay's kind:39000. Fields not listed are unchanged. (Allowed only if the relay confirms your owner/admin role on this channel.)`);
    }

    if (name === "buzz_join_channel") {
      if (!IDENTITY_OK) return modRefuse("joining a channel");
      const q = String(a.channel || "").trim();
      if (!q) return { content: [{ type: "text", text: "buzz_join_channel needs a `channel` (name or id)." }], isError: true };
      // The relay only self-joins OPEN channels (handle_join_request: visibility must be "open";
      // 39000 metadata marks it "public" vs "private"). When the shim can tell a target is private,
      // refuse here instead of signing a 9021 the relay bounces — and never silently target a
      // private channel by name (v0.2.27, per buzz_security's 0.2.26 GO notes).
      const privateRefusal = (nm) => ({ content: [{ type: "text", text: `buzz_join_channel: #${nm} is private — you can't self-join it. Ask an owner/admin to add you with buzz_add_member.` }], isError: true });
      let chId = null, chName = q, knownPrivate = false;
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(q)) {
        chId = q;   // a channel UUID → join by id (no membership needed to resolve it)
        // If its 39000 metadata is readable and marks it private, refuse now. If it isn't
        // readable (e.g. a private channel we're not in), proceed and let the relay be the gate.
        try {
          const meta = (await query([{ kinds: [39000], "#d": [chId], limit: 5 }]) || [])[0];
          if (meta) {
            const nm = (meta.tags || []).find((x) => x[0] === "name");
            if (nm && nm[1]) chName = nm[1];
            if ((meta.tags || []).some((x) => x[0] === "private")) knownPrivate = true;
          }
        } catch { /* unknown → relay remains the gate */ }
      } else {
        try { const hit = await resolveChannel(q); chId = hit.id; chName = hit.name; }
        catch (e) { if (e instanceof ChannelAmbiguousError) throw e; /* not a member yet — discover below */ }
        if (!chId) {
          // resolveChannel is member-first and can't see an OPEN channel you're not in yet. Discover
          // by name among the workspace's kind:39000 metadata. Only an OPEN match is self-joinable;
          // if the only name matches are private, refuse — never fall back to a private match.
          const metas = await query([{ kinds: [39000], limit: 500 }]);
          const named = (metas || []).map((e) => {
            const t = Object.fromEntries((e.tags || []).map((x) => [x[0], x[1]]));
            const isPrivate = (e.tags || []).some((x) => x[0] === "private");
            return { id: t.d, name: t.name || "", open: !isPrivate, at: e.created_at || 0 };
          }).filter((c) => c.id).sort((x, y) => y.at - x.at)
            .filter((c, i, arr) => arr.findIndex((o) => o.id === c.id) === i);   // newest 39000 per channel id
          // Same fail-closed matcher: two channels sharing the name (open or private) → refused.
          let hit = null;
          try { hit = matchChannel(q, named); } catch (e) { return { content: [{ type: "text", text: `buzz_join_channel: ${escapeContent(e.message, { cap: ERROR_TEXT_CAP })}` }], isError: true }; }
          if (hit && hit.open) { chId = hit.id; chName = hit.name; }
          else if (hit) return privateRefusal(hit.name || q);
        }
      }
      if (knownPrivate) return privateRefusal(chName);
      if (!chId)
        return { content: [{ type: "text", text: `buzz_join_channel: couldn't find a channel named "${q}". If it's an open channel you're not in, pass its id (UUID) instead — those aren't always discoverable by name.` }], isError: true };
      const tags = [["h", chId]];
      if (AUTH_TAG) tags.push(AUTH_TAG);
      const ev = await signer.sign({ kind: 9021, tags, content: "" });
      await bridge("/events", ev);
      return ok(`join request sent for #${chName}. If it's open you're now a member (a no-op if you already were); if it's private, an owner/admin must add you with buzz_add_member.`);
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
        if (!hit) throw new Error(`message ${targetId.slice(0, 8)}… is not in #${escapeName(ch.name)} — delete must target a message in the channel you name`);
      } else {
        const recent = await query([{ kinds: [9], "#h": [ch.id], limit: 200 }]) || [];
        const pref = recent.filter((e) => String(e.id).startsWith(targetId));
        if (pref.length > 1) throw new Error(`event id "${targetId}" is ambiguous in #${escapeName(ch.name)} (${pref.length} matches) — use more characters`);
        hit = pref[0];
        if (!hit) throw new Error(`no message with id "${targetId}" found in #${escapeName(ch.name)} — use the <id> shown by buzz_read`);
      }
      if (!(hit.tags || []).some((t) => t[0] === "h" && t[1] === ch.id))
        throw new Error(`target message is not bound to #${escapeName(ch.name)} — refusing a cross-channel delete`);
      targetId = hit.id;
      { const g = gate(9005, a, `delete message <${targetId.slice(0, 8)}> in #${escapeName(ch.name)}`); if (g) return fail(g); }
      const tmpl = deleteMessageTemplate({ channelId: ch.id, targetId });  // re-asserts concrete h + e
      if (AUTH_TAG) tmpl.tags.push(AUTH_TAG);
      const ev = await signer.sign(tmpl);
      await bridge("/events", ev);
      return ok(`deleted message <${String(targetId).slice(0, 8)}> in #${escapeName(ch.name)}. (Allowed only because the relay confirmed your role permits it.)`);
    }

    // ---- DM tools (v0.2.1) ----
    const dmRefuse = () => ({ content: [{ type: "text", text: `refused: impersonation guard — this session's key ${PK.slice(0, 16)}… ≠ pinned identity ${(EXPECTED_PK || "").slice(0, 16)}…. Not acting as the wrong identity.` }], isError: true });

    if (name === "buzz_dm_list") {
      const dms = await dmChannels();
      if (!dms.length) return ok("(no direct messages)");
      const names = await profiles();
      return ok(dms.map((c) => {
        void names;
        const label = c.others.map((p) => who(p)).join(", ") || "(just you)";
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
      void names;
      const scr = screen(await query([{ kinds: [9], "#h": [chan], limit: clampLimit(a.limit, 30, 200) }]));
      const edits = await latestEdits(chan, scr.events);
      const rows = scr.events.sort((x, y) => x.created_at - y.created_at).map((e) => renderMsg(e, { edits, flagOf: scr.flagOf }));
      return ok(`DM [${chan}] (${rows.length} msgs) — <id> = react target:\n${UNTRUSTED_NOTE}${scr.note ? "\n" + scr.note : ""}\n` + (rows.join("\n") || "(empty)"));
    }

    if (name === "buzz_dm_open") {
      if (!IDENTITY_OK) return dmRefuse();
      const pks = await resolveRecipients(a.to);
      const { channelId, created } = await openDm(pks);
      return ok(`DM ${created ? "opened" : "already exists"} with ${toLabel(a.to)}${pks.length > 1 ? ` (group of ${pks.length + 1})` : ""}: ${channelId}`);
    }

    if (name === "buzz_dm_send") {
      if (!IDENTITY_OK) return dmRefuse();
      // Same `text`|`message` alias + fail-loud-if-both-empty as buzz_post (self-heals the class).
      const bodyText = (typeof a.text === "string" && a.text.trim()) ? a.text
        : (typeof a.message === "string" && a.message.trim()) ? a.message : null;
      if (bodyText === null)
        return { content: [{ type: "text", text: "buzz_dm_send requires a non-empty `text` (its `message` alias is also accepted)." }], isError: true };
      const pks = await resolveRecipients(a.to);
      const { channelId } = await openDm(pks);
      // ["p", recipient] alongside ["h", channel]: desktop and mobile tag every DM
      // recipient, and the relay's push lease matches `#p=self` -- a DM without it
      // can never wake the recipient's phone (ola-silicon/buzz#1152; measured
      // 2026-09-27: no agent-sent DM had ever produced a push).
      const ev = await signer.sign({ kind: 9, tags: [["h", channelId], ...pks.map((pk) => ["p", pk])], content: bodyText });
      await bridge("/events", ev);
      return ok(`sent DM to ${toLabel(a.to)} [${channelId}]: ${bodyText}`);
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
      const hours = (Number.isFinite(a.hours) && a.hours > 0) ? Math.min(a.hours, 720) : 24;
      const since = Math.floor(Date.now() / 1000) - Math.floor(hours * 3600);
      const cs = await channels();
      const dms = await dmChannels();
      const names = await profiles();
      const meta = new Map();   // channel/dm id → display label
      void names;
      for (const c of cs) meta.set(c.id, `#${escapeName(c.name)}`);
      for (const d of dms) meta.set(d.id, `DM ${d.others.map((p) => who(p)).join(", ") || "(self)"}`);
      const ids = [...meta.keys()];
      if (!ids.length) return ok("no channels or DMs to scan.");
      // One round-trip over all h-scopes; bucket the union back by each event's own h-tag.
      const evs = screen(await query([{ kinds: [9], "#h": ids, since, limit: 2000 }])).events;
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
      const clientId = (a.client_id || (env.BUZZ_EKAM_CLIENT_ID ?? DEFAULT_EKAM_CLIENT_ID) || "").trim();
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
        return { content: [{ type: "text", text: `buzz_login: the previous sign-in attempt failed: ${escapeContent(msg, { cap: 500 })}\nRun buzz_login again to retry.` }], isError: true };
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
        // v0.2.31 (item 9): https only, no cmd.exe (rundll32 url.dll on Windows), minimal child env.
        const { cmd, args } = openUrlCommand(authUrl);
        spawn(cmd, args, { stdio: "ignore", detached: true, env: minimalChildEnv() }).unref();
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
        } else if (writesSystemicallyFailing()) {
          // v0.2.19 — health 200 + auth 200 + NOT wedged, but this process's recent writes FAILED
          // SYSTEMICALLY (transport / 5xx / persistent stale-timestamp) and the last such failure is
          // recent. Reads are healthy while writes can't reach the relay — the exact case the read-only
          // probes above miss. A request-specific refusal (403 permission, 404 not-found, validation)
          // is NOT counted here — the relay answered, so the write path is up; that would be a false
          // alarm. (Auth-lapse writes would already have tripped the "lapsed grant" branch.)
          classification = "posts failing (reads ok)";
          // v0.2.20 (dx nit): "couldn't be delivered" covers both a transport failure (never reached the
          // relay) and a 5xx (reached, relay errored) — "couldn't reach the relay" was wrong for the 5xx case.
          recovery = `reads are healthy but your last ${WRITE_HEALTH.consecutiveSystemic} write(s) (posts/reactions/edits) couldn't be delivered — retry; if it keeps failing, report in #buzz-help (last write error: ${WRITE_HEALTH.lastError})`;
        } else if (WRITE_HEALTH.lastKind === "rate_limited" && (Date.now() - WRITE_HEALTH.lastTs) < WRITE_STALE_MS) {
          // v0.2.20 (dx nit): a 429 is a throttle, not a failure or a permission refusal — its own verdict
          // with the wait action, not the generic "refused on its merits". RECENCY-GATED like the systemic
          // branch (dx v0.2.20 r2): a throttle from hours ago is stale, not current, so it falls through
          // to healthy below rather than telling you to "retry in 30s" six hours later.
          classification = "rate-limited";
          recovery = `reads OK — your last write was rate-limited by the relay (${rateLimitHint(WRITE_HEALTH.lastError)}); wait and retry, nothing to fix`;
        } else {
          // health 200 + auth 200 + transport OK + nothing CURRENTLY failing. A failure or throttle may be
          // on record but now stale (older than the window) — read as healthy, with an honest note of what
          // happened, never as "no write attempted" (which would misreport a real past write).
          classification = "healthy";
          if (WRITE_HEALTH.lastOutcome === "ok") {
            recovery = "healthy — reads OK and your last write reached the relay; no action";
          } else if (WRITE_HEALTH.lastKind === "request") {
            recovery = `healthy — reads OK; your last write was refused by the relay on its merits (not a write outage: ${WRITE_HEALTH.lastError}); no action`;
          } else if (WRITE_HEALTH.lastKind === "rate_limited") {
            recovery = `healthy — reads OK; an earlier write was rate-limited (${ageStr(Date.now() - WRITE_HEALTH.lastTs)}), nothing failing now; no action`;
          } else if (WRITE_HEALTH.lastKind === "systemic") {
            recovery = `healthy — reads OK; an earlier write didn't go through (${ageStr(Date.now() - WRITE_HEALTH.lastTs)}), but nothing is failing now; no action`;
          } else {
            recovery = "healthy — reads OK; no write has been attempted yet this session, so write-health is unverified (buzz_doctor observes the writes you make; it never test-writes); no action";
          }
        }
      }

      // A malformed BUZZ_AUTH_TAG is a deterministic cause of membership/post 403s that the read-only
      // probes above cannot see — a read /query probe can pass while writes 403 for the missing owner
      // tag. When the relay answered, surface it as the actionable root cause; let a genuinely
      // unreachable relay keep top billing.
      if (AUTH_TAG_MALFORMED && health) {
        classification = "config: BUZZ_AUTH_TAG malformed";
        recovery = `BUZZ_AUTH_TAG is set but not valid ["auth",…] JSON, so owner attestation is omitted and the relay will 403 membership/posts. Most likely a bash \`source\` of agent.env stripped the JSON quotes — single-quote the value (BUZZ_AUTH_TAG='["auth",...]') and relaunch.`;
      }

      const transportLine = TRANSPORT_WEDGED
        ? "⚠ undici pool already flagged wedged this process — self-healing via fresh node:https sockets"
        : "ok (no wedge flagged this process)";
      const authTagLine = AUTH_TAG_MALFORMED
        ? `⚠ set but MALFORMED (not valid ["auth",…] JSON) → owner attestation omitted → 403 membership/posts; likely a bash \`source\` of agent.env stripping the quotes — single-quote it`
        : (AUTH_TAG ? `present (["auth",…] parsed OK)` : "none (unset)");
      // v0.2.19 — the write-health line: what buzz_doctor observes about the writes you've made (the
      // read-only probes above can't see write rejection). Purely from recorded outcomes; no probe.
      const writeLine = (() => {
        const w = WRITE_HEALTH;
        const tally = `${w.totalOk} ok / ${w.totalFailed} failed this session`;
        if (w.lastOutcome === null) return `no write attempted this session — write-health is observed from your real writes, not probed (no test-write)`;
        if (w.lastOutcome === "ok") return `last write OK ${ageStr(Date.now() - w.lastTs)} (${tally})`;
        if (w.lastKind === "rate_limited") return `last write rate-limited ${ageStr(Date.now() - w.lastTs)} — throttled, not a failure; ${rateLimitHint(w.lastError)} (${tally})`;
        if (w.lastKind === "request") return `last write refused by the relay ${ageStr(Date.now() - w.lastTs)} — request-specific (permission/validation), write path is up (${tally}); ${w.lastError}`;
        return `⚠ last write couldn't be delivered ${ageStr(Date.now() - w.lastTs)} — ${w.consecutiveSystemic} consecutive systemic (${tally}); ${w.lastError}`;
      })();
      const pinLine = EXPECTED_PK
        ? (IDENTITY_OK ? "pin VERIFIED ✅" : "⚠ IMPERSONATION GUARD TRIPPED — WRITES DISABLED")
        : "no pin set (BUZZ_EXPECTED_PUBKEY unset)";

      // v0.2.23 — authoritative version status over the SAME fresh socket as the probes
      // above (so it holds even when the normal client is wedged). Best-effort: on any
      // failure fall back to the cached CLIENT_VERSION, then to a plain version string.
      let cv = CLIENT_VERSION;
      try {
        const r = await rawGet(`${RELAY}/`, { Accept: "application/nostr+json" }, timeoutMs);
        if (r.ok) cv = clientVersionStatus(SHIM_VERSION, pickAdvertised(JSON.parse(r.text)));
      } catch { /* keep cached CLIENT_VERSION */ }
      const shimLine = cv.level === "below-min"
        ? `@ola/buzz-mcp v${SHIM_VERSION} — ⚠ BELOW the relay's minimum v${cv.min}${cv.latest ? `; latest v${cv.latest}` : ""}, update soon`
        : cv.level === "update"
          ? `@ola/buzz-mcp v${SHIM_VERSION} — ℹ update available (relay advertises v${cv.latest})`
          : (cv.latest ? `@ola/buzz-mcp v${SHIM_VERSION} (up to date; relay advertises v${cv.latest})`
                       : `@ola/buzz-mcp v${SHIM_VERSION} (relay advertises no shim version — skew-check inert)`);

      return ok([
        "buzz_doctor — connector-side diagnosis (NOT the authoritative relay health signal)",
        `  shim: ${shimLine}`,
        `  diagnosis: ${classification}`,
        `  recovery: ${recovery}`,
        `  identity: ${MY_NAME} (${pinLine})`,
        `  relay (dial): ${RELAY}`,
        `  health probe: ${healthLine}`,
        `  auth probe: ${authLine}`,
        `  transport: ${transportLine}`,
        `  auth tag (config): ${authTagLine}`,
        `  writes: ${writeLine}`,
      ].join("\n"));
    }

    // ---- v0.2.31 Slack-parity tools. Kinds and tag shapes mirror buzz-sdk builders.rs (upstream
    // dc25198d5). Kinds outside the Ekam wire-sign allowlist (40003, 9022, 9008, 41012, 5) are refused
    // in wire mode with a clear reason, never signed some other way. ----
    const parity = await parityTool(name, a, { ok, fail });
    if (parity) return parity;

    return ok(`unknown tool: ${name}`);
  } catch (e) {
    // v0.2.31 re-check (must-fix): an error message can carry relay-controlled text (profile
    // names, channel names, relay error bodies), so the catch-all escapes it like message content
    // (one line, no raw C0/C1/bidi/invisible characters) and caps it. Labels names.mjs already
    // quoted show their backslashes doubled here ("\\u{202e}") — harmless, and never raw.
    return { content: [{ type: "text", text: `error: ${escapeContent(e && e.message != null ? e.message : e, { cap: ERROR_TEXT_CAP })}` }], isError: true };
  }
}

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
