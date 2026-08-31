#!/usr/bin/env node
// buzz-mcp — join the Buzz relay from a Claude CLI session: see channels,
// read what your agents are saying, post, and @mention agents to delegate.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { finalizeEvent, getPublicKey, generateSecretKey } from "nostr-tools/pure";
import * as nip19 from "nostr-tools/nip19";
import { resolveKey } from "./loadkey_v2.mjs";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { homedir, hostname } from "node:os";
import { join, basename } from "node:path";
import { execSync } from "node:child_process";

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
const SK = await resolveKey({ sessionId: sessionId() });
const PK = getPublicKey(SK);

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
let MY_NAME = process.env.BUZZ_IDENTITY_NAME || process.env.BUZZ_NAME || contextName();
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
function nip98(url, method, body) {
  const payload = createHash("sha256").update(body ?? "").digest("hex");
  const ev = finalizeEvent(
    { kind: 27235, created_at: Math.floor(Date.now() / 1000),
      tags: [["u", url], ["method", method], ["payload", payload]], content: "" },
    SK,
  );
  return "Nostr " + Buffer.from(JSON.stringify(ev)).toString("base64");
}

// Shim version for the x-buzz-client telemetry header. Keep in sync with package.json.
const SHIM_VERSION = "0.1.5";

// #243: coarse, bounded retry class from the caught NETWORK error (name/code only, never raw message).
function retryClass(e) {
  const c = ((e && (e.cause?.code || e.code || e.name)) || "").toString().toLowerCase();
  if (c.includes("reset") || c.includes("econnreset")) return "socket_reset";
  if (c.includes("timeout") || c.includes("etimedout") || c.includes("econnrefused") || c.includes("connect")) return "connect_timeout";
  return "unknown_transport";
}

async function bridge(path, bodyObj) {
  const dialUrl = `${RELAY}${path}`;
  const signUrl = `${SIGN_BASE}${path}`;
  const body = JSON.stringify(bodyObj);
  // Fresh NIP-98 per attempt (a replayed NIP-98 would be rejected); the body — incl. any signed Nostr
  // event and its deterministic id — is unchanged, so a retried /events dedups server-side (ON CONFLICT
  // DO NOTHING before side effects, per relay ingest.rs). Reads are idempotent regardless.
  const attempt = (isRetry, rClass) => fetch(dialUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": nip98(signUrl, "POST", body),
      // NIP-OA owner delegation: the relay reads membership from the `x-auth-tag`
      // header (bridge.rs). Without this, a ViaOwner agent 403s on reads/queries.
      ...(AUTH_TAG ? { "x-auth-tag": JSON.stringify(AUTH_TAG) } : {}),
      // Platform attribution — telemetry only (relay stamps a bounded `client` label,
      // never gates auth). Format pinned with relay_sre 15:17: platform; substrate=; version=.
      "x-buzz-client": `agent; substrate=local; version=${SHIM_VERSION}`,
      // #243: on a retry ONLY, mark it so the relay counts retry RATE (dedicated counter, telemetry
      // only, never gates). Absent on first attempts → no cardinality on the normal request path.
      ...(isRetry ? { "x-buzz-retry": `1; retry_class=${rClass}` } : {}),
    },
    body,
  });
  let res;
  try {
    res = await attempt(false);
  } catch (e) {
    // NETWORK-level throw only (dead pooled socket / reset / connect timeout). HTTP errors return a
    // response (handled below) and are NEVER retried — a 401/403/4xx is not a throw. One retry on a
    // fresh attempt (undici evicts the errored socket, so the retry does not reuse it). Counted, not silent.
    const rClass = retryClass(e);
    process.stderr.write(`[buzz-mcp] transient ${path} fetch failed (${rClass}); retrying once\n`);
    try {
      res = await attempt(true, rClass);
    } catch {
      // A failed retry never reaches the relay → the tool result is its only home (visible to the agent).
      throw new Error(`${path} -> transient fetch failed [retried 1x fresh-conn, still failed; class=${rClass}]`);
    }
  }
  const text = await res.text();
  if (!res.ok) throw new Error(`${path} -> HTTP ${res.status}: ${text.slice(0, 200)}`);
  try { return JSON.parse(text); } catch { return text; }
}

const query = (filters) => bridge("/query", filters);

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
  const ev = finalizeEvent({ kind: 0, created_at: Math.floor(Date.now() / 1000), tags: AUTH_TAG ? [AUTH_TAG] : [], content: JSON.stringify(profile) }, SK);
  const res = await bridge("/events", ev);
  // best-effort structured agent card (relay may gate the kind; the kind:0 above always applies)
  try {
    const card = { name, model: AGENT_MODEL, harness: AGENT_HARNESS, interface: AGENT_INTERFACE, host, identity: "Ekam-governed" };
    const cardEv = finalizeEvent({
      kind: KIND_AGENT_PROFILE, created_at: Math.floor(Date.now() / 1000),
      tags: [["model", AGENT_MODEL], ["harness", AGENT_HARNESS], ["interface", AGENT_INTERFACE], ["L", "agent-card"]],
      content: JSON.stringify(card),
    }, SK);
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

// ---- MCP server ----
const server = new Server({ name: "buzz", version: "0.1.0" }, { capabilities: { tools: {} } });

const TOOLS = [
  { name: "buzz_whoami", description: "Show this CLI session's Buzz identity (friendly name + npub + pubkey).", inputSchema: { type: "object", properties: {} } },
  { name: "buzz_setname", description: "Override this session's friendly display name on the fleet.", inputSchema: { type: "object", properties: { name: { type: "string" } }, required: ["name"] } },
  { name: "buzz_channels", description: "List channels in the Buzz workspace.", inputSchema: { type: "object", properties: {} } },
  { name: "buzz_agents", description: "List known agents/people (display name + pubkey) on the relay.", inputSchema: { type: "object", properties: {} } },
  { name: "buzz_read", description: "Read recent messages in a channel (by name or id).", inputSchema: { type: "object", properties: { channel: { type: "string" }, limit: { type: "number" } }, required: ["channel"] } },
  { name: "buzz_post", description: "Post a message to a channel. Use @Name to mention an agent (resolved to a p-tag so the agent is triggered).", inputSchema: { type: "object", properties: { channel: { type: "string" }, text: { type: "string" } }, required: ["channel", "text"] } },
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
  const base = (process.env.BUZZ_PRIVATE_KEY || process.env.BUZZ_IDENTITY_KEY)
    ? "key-pinned via env" : "⚠ no key in env — keyring or RANDOM per-session";
  if (EXPECTED_PK) return IDENTITY_OK
    ? `${base}; pin VERIFIED ✅ (matches BUZZ_EXPECTED_PUBKEY)`
    : `⚠ IMPERSONATION GUARD TRIPPED: key ${PK.slice(0, 16)}… ≠ expected ${EXPECTED_PK.slice(0, 16)}… — WRITES DISABLED`;
  return `${base} (no BUZZ_EXPECTED_PUBKEY — set it to fail-closed on mis-pin)`;
};

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: a = {} } = req.params;
  const ok = (s) => ({ content: [{ type: "text", text: s }] });
  try {
    if (name === "buzz_whoami") {
      const info = await relayInfo();
      const relayLine = info.error ? `⚠ UNREACHABLE: ${info.error}` : `${info.name} · v${info.version}${info.sha ? ` · deploy ${info.sha.slice(0, 12)}` : " · (no software_sha — stale build?)"}`;
      const configLine = IS_ISOLATED ? "isolated ✅ (own CLAUDE_CONFIG_DIR)" : `⚠ SHARED ~/.claude.json — clobberable/flip-prone. Relaunch via 'buzz-claude ${MY_NAME}' to isolate. Guide: ${GUIDE_PATH}`;
      return ok(`Buzz CLI identity:\n  name: ${MY_NAME}\n  model: ${AGENT_MODEL}\n  harness: ${AGENT_HARNESS}\n  interface: ${AGENT_INTERFACE}\n  npub: ${nip19.npubEncode(PK)}\n  pubkey: ${PK}\n  identity: ${keyProvenance()}\n  config: ${configLine}\n  relay (dial): ${RELAY}\n  relay (self-report): ${relayLine}\n  auth_tag: ${AUTH_TAG ? "present (ViaOwner delegation)" : "none"}\n  NOTE: the deploy SHA above is the LIVE prod build (relay's software_sha) — compare it before claiming "X is deployed". reachable ≠ up-to-date.`);
    }

    if (name === "buzz_setname") {
      if (!IDENTITY_OK) return { content: [{ type: "text", text: `refused: impersonation guard — key ${PK.slice(0, 16)}… ≠ pinned ${EXPECTED_PK.slice(0, 16)}… (running as ${MY_NAME}). Not writing a profile as the wrong agent.` }], isError: true };
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
        const t = new Date(e.created_at * 1000).toISOString().slice(11, 16);
        return `[${t}] ${who}: ${e.content}`;
      });
      return ok(`#${ch.name} (${rows.length} msgs):\n` + (rows.join("\n") || "(empty)"));
    }

    if (name === "buzz_post") {
      if (!IDENTITY_OK) return { content: [{ type: "text", text: `refused: impersonation guard — this session's key ${PK.slice(0, 16)}… ≠ pinned identity ${EXPECTED_PK.slice(0, 16)}…. Not posting as the wrong agent. Fix your pin, or launch with your own CLAUDE_CONFIG_DIR.` }], isError: true };
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
      for (const m of (a.text.match(/@([A-Za-z0-9_-]+)/g) || [])) {
        const pk = byName[m.slice(1).toLowerCase()];
        if (pk) tags.push(["p", pk]);
      }
      const ev = finalizeEvent({ kind: 9, created_at: Math.floor(Date.now() / 1000), tags, content: a.text }, SK);
      await bridge("/events", ev);
      const mentioned = tags.filter((t) => t[0] === "p").length;
      return ok(`posted to #${ch.name}${mentioned ? ` (mentioned ${mentioned})` : ""}: ${a.text}`);
    }

    return ok(`unknown tool: ${name}`);
  } catch (e) {
    return { content: [{ type: "text", text: `error: ${e.message}` }], isError: true };
  }
});

// auto-register this session's context-derived friendly name (best-effort).
// Skipped on impersonation-guard trip: never publish a profile AS the wrong agent.
if (IDENTITY_OK) publishProfile(MY_NAME).catch(() => {});
else process.stderr.write(`[buzz-mcp] profile publish skipped (impersonation guard).\n`);

// fail-LOUD environment surfacing at boot (warn to stderr, never brick — see CLI-never-break):
// makes the resolved identity + relay explicit every start, so a clobbered key or a
// non-prod endpoint is visible immediately instead of producing confident-wrong claims.
process.stderr.write(`[buzz-mcp] identity=${MY_NAME} pubkey=${PK.slice(0, 16)} relay=${RELAY} :: ${keyProvenance()}\n`);
if (!IS_ISOLATED)
  process.stderr.write(`[buzz-mcp] ⚠ SHARED CONFIG — not isolated; another agent can clobber your identity (the flip-flop). Fix: relaunch via  buzz-claude ${MY_NAME}   (guide: ${GUIDE_PATH})\n`);

await server.connect(new StdioServerTransport());
