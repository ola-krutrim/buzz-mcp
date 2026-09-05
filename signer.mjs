// signer.mjs — the shim's signing seam (#317 Path A / wire-sign client side).
//
// Splits "HOW an event gets signed" from the rest of the shim, so the shim runs in
// TWO identity modes with ZERO change at the call sites:
//   • local (default, unchanged): a key resolved by loadkey_v2 (env pin / Phase-2
//     wire-key / keystore) signs in-process with finalizeEvent. AGENT identity.
//   • wire  (Navendu 2026-09-04, "post as me"): the shim holds NO key. It carries a
//     REVOCABLE Ekam human token and calls POST /v1/me/wire-sign for every event —
//     Ekam signs with the user's OWN escrowed wire key and returns the signed event,
//     so the relay admits/sees the post AS the user. nsec never leaves escrow. (#317.)
//
// Every signable event in the shim goes through `signer.sign({kind, tags, content})`.
// created_at: LOCAL mode stamps it here; WIRE mode lets the SERVER stamp it
// (anti-backdating), so the template must NOT carry created_at in wire mode.

import { finalizeEvent, getPublicKey } from "nostr-tools/pure";
import * as nip19 from "nostr-tools/nip19";
import { resolveKey } from "./loadkey_v2.mjs";
import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const now = () => Math.floor(Date.now() / 1000);
export const ekamBase = (env) => (env.BUZZ_EKAM_BASE || "https://ekam.olakrutrim.com").replace(/\/+$/, "");
// The identity the wire refresh is persisted under — the one-time login helper and the
// runtime token provider MUST agree on this, or the shim won't find the login's refresh.
// DECOUPLED from BUZZ_NAME / BUZZ_IDENTITY_NAME on purpose: those are AGENT-mode identity
// vars, and when an agent-route shim is also present (or BUZZ_NAME is just left exported),
// the login runs in a plain shell → saves under "wire", but the MCP runtime inherits
// BUZZ_NAME=<agent> → looks for <agent>.pub → null → fails closed with "run the login"
// even though the login succeeded (releng finding, 2026-09-04). Wire mode keys ONLY off a
// dedicated BUZZ_WIRE_ID (default "wire"), so login and runtime agree regardless of BUZZ_NAME.
export const wirePersistId = (env) => ((env.BUZZ_WIRE_ID || "wire").trim() || "wire");
// Which env vars, if set, would have changed the id under the OLD rule — used by the login
// helper to warn the user that they must NOT rely on those for wire mode anymore.
export const wireBleedVars = (env) => ["BUZZ_IDENTITY_NAME", "BUZZ_NAME"].filter((k) => (env[k] || "").trim());

// ── wire-refresh persistence (0600), mirroring loadkey_v2's service-refresh side-file.
// The offline_access refresh is single-use/rotating; we persist the rotated one so the
// next session doesn't replay a spent token (which would revoke the family → lockout).
const WIRE_REFRESH_DIR = join(homedir(), ".config", "buzz-cli", "wire-refresh");
const wireRefreshFile = (id) => join(WIRE_REFRESH_DIR, `${(id || "default").replace(/[^\w.-]/g, "_").slice(0, 80)}.tok`);
export function wireRefreshGet(id) {
  try { const f = wireRefreshFile(id); return existsSync(f) ? (readFileSync(f, "utf8").trim() || null) : null; } catch { return null; }
}
export function wireRefreshSet(id, tok) {
  try { mkdirSync(WIRE_REFRESH_DIR, { recursive: true, mode: 0o700 }); const f = wireRefreshFile(id); writeFileSync(f, tok, { mode: 0o600 }); chmodSync(f, 0o600); return true; } catch { return false; }
}

// The user's pubkey captured at login (so wire mode needs no hand-set BUZZ_USER_PUBKEY).
// Written by the login helper next to the refresh; read as a fallback at resolve time.
const wirePubkeyFile = (id) => join(WIRE_REFRESH_DIR, `${(id || "default").replace(/[^\w.-]/g, "_").slice(0, 80)}.pub`);
export function wirePubkeyGet(id) {
  try { const f = wirePubkeyFile(id); const v = existsSync(f) ? readFileSync(f, "utf8").trim() : ""; return /^[0-9a-f]{64}$/i.test(v) ? v.toLowerCase() : null; } catch { return null; }
}
export function wirePubkeySet(id, hex) {
  try { mkdirSync(WIRE_REFRESH_DIR, { recursive: true, mode: 0o700 }); const f = wirePubkeyFile(id); writeFileSync(f, hex, { mode: 0o600 }); chmodSync(f, 0o600); return true; } catch { return false; }
}

// Wire-mode bearer provider (the loadkey_v2 Phase-2 seam for "post as me"). Sources:
//   • BUZZ_WIRE_REFRESH (+ BUZZ_EKAM_CLIENT_ID): the offline_access refresh from the
//     one-time wire:sign login. Shim self-re-mints a short-TTL wire:sign access token
//     via grant_type=refresh_token — autonomous, no browser. (ekam 04:30: refresh only
//     narrows scope + pins resource=ISSUER, so this can't cold-start or widen.)
//   • BUZZ_EKAM_HUMAN_TOKEN: a static pre-minted wire:sign token (per-session model).
// Defensive re ekam's two still-open details: persist a rotated refresh IFF returned;
// pre-empt expiry IFF expires_in returned, else fall back on the 401→re-mint retry.
export function makeWireTokenProvider(env, fetchFn) {
  const base = ekamBase(env);
  const clientId = (env.BUZZ_EKAM_CLIENT_ID || "").trim();
  const persistId = wirePersistId(env);
  let refresh = wireRefreshGet(persistId) || (env.BUZZ_WIRE_REFRESH || "").trim() || null;
  let access = (env.BUZZ_EKAM_HUMAN_TOKEN || "").trim() || null;
  let accessExp = access ? Infinity : 0; // static token: valid until a 401 says otherwise
  const SKEW_MS = 30_000;

  // Single-flight + proactive keep-alive (v0.2.8). Rotating refresh tokens make CONCURRENT
  // refreshes dangerous: two parallel /query calls on an expired access token would each POST
  // the same refresh; Ekam rotates on the first, so the second presents a spent token →
  // reuse-detection revokes the whole family (the ":40 lockout" this file already warns about).
  // `inflightMint` dedupes so only ONE refresh is ever in flight. `renewTimer` refreshes at ~75%
  // of the access token's life so a long-lived process never reaches expiry mid-use (unref'd, so
  // it never keeps the process alive on its own).
  let inflightMint = null, renewTimer = null;
  function scheduleRenew() {
    if (renewTimer) { clearTimeout(renewTimer); renewTimer = null; }
    if (!refresh || !isFinite(accessExp)) return; // need a refresh + a real expires_in to time a renew
    const delay = Math.max(30_000, Math.floor((accessExp - Date.now()) * 0.75)); // ~75% of remaining life
    renewTimer = setTimeout(() => { getToken(true).catch((e) => process.stderr.write(`[buzz-mcp] wire keep-alive renew failed (will retry on next call): ${e.message}\n`)); }, delay);
    if (renewTimer.unref) renewTimer.unref();
  }
  async function mint() {
    if (!refresh) throw new Error("wire mode: no refresh token to mint from (set BUZZ_WIRE_REFRESH from the one-time wire:sign login)");
    if (!clientId) throw new Error("wire mode: BUZZ_EKAM_CLIENT_ID required to mint a wire:sign token from a refresh");
    // Minimal refresh body per ekam step ④ — scope stays wire:sign and resource stays
    // pinned to ISSUER from the ORIGINAL login grant; the endpoint rejects extra keys
    // (live: HTTP 400 "Unrecognized key: resource"), and refresh can only ever narrow,
    // never widen, so omitting them keeps the original wire:sign/ISSUER grant intact.
    const res = await fetchFn(`${base}/oauth/token`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ grant_type: "refresh_token", client_id: clientId, refresh_token: refresh }),
    });
    const text = await res.text();
    if (!res.ok) {
      let detail = text.slice(0, 200);
      try { const j = JSON.parse(text); detail = j.error_description || j.error || detail; } catch { /* keep raw */ }
      throw new Error(`wire:sign token mint -> HTTP ${res.status}: ${detail} (refresh revoked/expired? re-run the one-time login)`);
    }
    let j;
    try { j = JSON.parse(text); } catch { throw new Error(`token mint returned non-JSON: ${text.slice(0, 120)}`); }
    if (!j.access_token) throw new Error("token mint returned no access_token");
    access = j.access_token;
    accessExp = j.expires_in ? Date.now() + j.expires_in * 1000 - SKEW_MS : Infinity;
    if (j.refresh_token) { refresh = j.refresh_token; wireRefreshSet(persistId, j.refresh_token); } // rotate iff rotated
    scheduleRenew(); // keep-alive: line up the next refresh at ~75% of this token's life
  }

  async function getToken(force) {
    if (!force && access && Date.now() < accessExp) return access;
    if (refresh) {
      // single-flight: concurrent callers (and the keep-alive timer) share ONE mint, so a rotating
      // refresh is never sent twice in parallel (which would trip reuse-detection → family revoke).
      if (!inflightMint) inflightMint = mint().finally(() => { inflightMint = null; });
      await inflightMint;
      return access;
    }
    if (access) return access; // static token, no refresh to rotate
    throw new Error("wire mode: no bearer available (set BUZZ_WIRE_REFRESH+BUZZ_EKAM_CLIENT_ID, or BUZZ_EKAM_HUMAN_TOKEN)");
  }

  return {
    hasRefresh: () => !!refresh,
    hasStatic: () => !!(env.BUZZ_EKAM_HUMAN_TOKEN || "").trim(),
    get: getToken,
    stopKeepAlive() { if (renewTimer) { clearTimeout(renewTimer); renewTimer = null; } }, // for clean shutdown/tests
  };
}

// wire-sign kind allowlist — MIRRORS ekam's server allowlist {22242, 9, 27235}
// (requirement A, buzz-main 03:50). The server is the authority; this is a fast
// client-side guard so the shim never makes a wire-sign call the server would
// refuse — e.g. the startup kind:0/10100 profile publish is skipped in wire mode.
//   9     = messages / DMs (the actual posts)
//   22242 = NIP-42 relay AUTH (unused by this HTTP shim; kept for parity)
//   27235 = NIP-98 HTTP auth — THIS shim's per-request transport auth event
//   41010 = DM_OPEN, 41011 = DM_ADD_MEMBER — DM membership commands (v199, ekam #322).
//           NOTE command kinds, not messages; server refuses 41012/41001/other commands.
//   7     = NIP-25 reaction (ekam #325 / v203) — a low-sensitivity ack, not a command.
//   24242 = Blossom media auth (ekam #326 / v204) — signs upload/get auth for attachments;
//           the shim only ever builds these via blossomAuthTemplate() (fail-closed shape).
export const WIRE_ALLOWLIST = new Set([9, 22242, 27235, 41010, 41011, 7, 24242, 9000, 9001, 9005]);

// NIP-29 governed moderation (kinds 9000 add-member / 9001 remove-member / 9005 delete-message),
// live server-side via Ekam v206 (allowlist {…,9000,9001,9005}). Ekam stays content-agnostic; the
// relay's validate_admin_event role-gates each against the SIGNER's OWN role (a wire-signed 9001/9005
// only works where the human is already owner/admin) — so the shim never widens authority, it only
// refuses to sign a malformed/target-less op. Each builder FAILS CLOSED: a concrete channel h-tag AND
// a concrete 64-hex target (p for add/remove, e for delete) are required before the signer is ever
// called — no bare name, no ambiguity, no target-less destructive op reaches Ekam.
const HEX64 = /^[0-9a-f]{64}$/;
export function addMemberTemplate({ channelId, targetPubkey, role } = {}) {
  const chan = String(channelId || "").trim();
  if (!chan) throw new Error("buzz_add_member: a channel is required (h-tag) — refusing a channel-less add");
  const pk = String(targetPubkey || "").trim().toLowerCase();
  if (!HEX64.test(pk)) throw new Error("buzz_add_member: a concrete 64-hex target pubkey is required (p-tag) — refusing a name-only/ambiguous add");
  const tags = [["h", chan], ["p", pk]];
  const r = String(role || "").trim().toLowerCase();
  if (r) {
    if (!["member", "admin", "owner", "guest", "bot"].includes(r)) throw new Error(`buzz_add_member: invalid role ${JSON.stringify(r)}`);
    tags.push(["role", r]);
  }
  return { kind: 9000, tags, content: "" };
}
export function removeMemberTemplate({ channelId, targetPubkey } = {}) {
  const chan = String(channelId || "").trim();
  if (!chan) throw new Error("buzz_remove_member: a channel is required (h-tag) — refusing a channel-less remove");
  const pk = String(targetPubkey || "").trim().toLowerCase();
  if (!HEX64.test(pk)) throw new Error("buzz_remove_member: a concrete 64-hex target pubkey is required (p-tag) — refusing a name-only/ambiguous remove");
  return { kind: 9001, tags: [["h", chan], ["p", pk]], content: "" };
}
export function deleteMessageTemplate({ channelId, targetId } = {}) {
  const chan = String(channelId || "").trim();
  if (!chan) throw new Error("buzz_delete: a channel is required (h-tag) — refusing a channel-less delete");
  const id = String(targetId || "").trim().toLowerCase();
  if (!HEX64.test(id)) throw new Error("buzz_delete: a concrete 64-hex target event id is required (e-tag) — refusing a target-less delete");
  return { kind: 9005, tags: [["h", chan], ["e", id]], content: "" };
}

// Build a NIP-25 reaction (kind 7) template, ENFORCING a concrete target event id — the
// condition ekam + security set when Ekam stayed content-agnostic for kind 7 (#325): a
// target-less reaction never reaches the signer. e-tag = the message reacted to; k-tag =
// its kind; h-tag routes it to the channel (relay membership gate = WHERE boundary); p-tag
// (author) is added only when it's a valid pubkey. content = the emoji (default "+").
export function reactionTemplate({ targetId, targetAuthor, targetKind, channelId, emoji } = {}) {
  const id = String(targetId || "").trim();
  if (!id) throw new Error("buzz_react: a concrete target event id is required — refusing a target-less reaction (kind 7 must carry an `e` tag)");
  const chan = String(channelId || "").trim();
  if (!chan) throw new Error("buzz_react: a channel is required to route the reaction (h-tag)");
  const tags = [["e", id], ["k", String(targetKind || 9)], ["h", chan]];
  const author = String(targetAuthor || "").trim().toLowerCase();
  if (/^[0-9a-f]{64}$/.test(author)) tags.push(["p", author]);
  const content = String(emoji ?? "").trim() || "+";
  return { kind: 7, tags, content };
}

// ── Blossom (BUD-01/02/11) media auth (kind 24242) — for attachment upload/download.
// Ekam v204 signs kind 24242, staying content-agnostic; per the security gate (codex_kavach)
// the SHIM owns the constraints. This builder FAILS CLOSED: verb must be exactly upload|get,
// content is a FIXED non-empty literal (BUD-11 requires a "human readable string" — an empty
// content is rejected by the relay's verify_blossom_auth_event before any other check; a fixed
// literal is as constrained as empty while being valid, and no caller-supplied/free-form text
// ever rides the field), expiration is present and short (≤ BLOSSOM_MAX_TTL), and an upload
// MUST carry the exact 64-hex file sha256 as its `x` tag (BUD-11 hash-binding). A `get` may
// bind the target hash too (preferred — resolve it from a visible message's imeta, never a
// user-supplied URL). The relay verifies content + BUD-11 (X-SHA-256 == an `x`) + NIP-43 membership.
export const BLOSSOM_AUTH_KIND = 24242;
export const BLOSSOM_MAX_TTL = 300; // seconds — ≤5 min per the security gate
// Fixed, non-caller-supplied content literals (mirror the desktop reference; BUD-11 §"human readable").
export const BLOSSOM_CONTENT = { upload: "Upload buzz-media", get: "Get buzz-media" };
export function blossomAuthTemplate({ verb, sha256, ttlSeconds, now } = {}) {
  if (verb !== "upload" && verb !== "get")
    throw new Error(`blossom auth: verb must be "upload" or "get" (got ${JSON.stringify(verb)})`);
  const ttl = Number.isFinite(ttlSeconds) ? ttlSeconds : BLOSSOM_MAX_TTL;
  if (!(ttl > 0 && ttl <= BLOSSOM_MAX_TTL))
    throw new Error(`blossom auth: expiration TTL must be 1..${BLOSSOM_MAX_TTL}s (got ${ttlSeconds})`);
  const nowS = Math.floor((now ?? Date.now()) / 1000);
  const tags = [["t", verb], ["expiration", String(nowS + ttl)]];
  const hash = String(sha256 || "").trim().toLowerCase();
  if (verb === "upload") {
    if (!/^[0-9a-f]{64}$/.test(hash))
      throw new Error("blossom upload auth: a 64-hex sha256 `x` (the exact file hash) is required");
    tags.push(["x", hash]);
  } else if (hash) {
    if (!/^[0-9a-f]{64}$/.test(hash))
      throw new Error("blossom get auth: sha256 must be 64-hex when provided");
    tags.push(["x", hash]); // target-bound get
  }
  return { kind: BLOSSOM_AUTH_KIND, tags, content: BLOSSOM_CONTENT[verb] };
}

// ── NIP-92 `imeta` media descriptor (how a Buzz kind:9 carries an attachment).
// A single tag: ["imeta","url <U>","m <mime>","x <sha256>","size <bytes>",("dim WxH"|"filename <name>")…]
// — each value after the tag name is a space-joined "key value" pair (first key wins).
export function parseImeta(tag) {
  if (!Array.isArray(tag) || tag[0] !== "imeta") return null;
  const d = {};
  for (const part of tag.slice(1)) {
    const s = String(part);
    const i = s.indexOf(" ");
    if (i < 0) continue;
    const k = s.slice(0, i);
    if (!(k in d)) d[k] = s.slice(i + 1); // first value wins
  }
  if (!d.url) return null;
  return {
    url: d.url,
    mime: d.m || null,
    sha256: d.x ? d.x.toLowerCase() : null,
    size: d.size != null && /^\d+$/.test(d.size) ? Number(d.size) : null,
    filename: d.filename || null,
    dim: d.dim || null,
  };
}
// All attachment descriptors on a message event (in tag order).
export function messageAttachments(ev) {
  return ((ev && ev.tags) || []).filter((t) => Array.isArray(t) && t[0] === "imeta").map(parseImeta).filter(Boolean);
}
// Build a NIP-92 `imeta` tag from an upload result — the exact-hash binding the security
// gate wants (the tag's `x`/`url` must match what was uploaded). Requires url + 64-hex sha.
export function buildImeta({ url, mime, sha256, size, filename } = {}) {
  const u = String(url || "").trim();
  const x = String(sha256 || "").trim().toLowerCase();
  if (!u) throw new Error("imeta: url is required");
  if (!/^[0-9a-f]{64}$/.test(x)) throw new Error("imeta: a 64-hex sha256 is required");
  const parts = [`url ${u}`, `x ${x}`];
  if (mime) parts.push(`m ${mime}`);
  if (Number.isFinite(size) && size >= 0) parts.push(`size ${size}`);
  if (filename) parts.push(`filename ${filename}`);
  return ["imeta", ...parts];
}

// ── Media size caps (mirror the relay per-type defaults: image 50 / gif 10 / file 100 /
// video 500 MB). A PRE-FLIGHT COURTESY — the relay's 413 is authoritative; this only saves
// a doomed upload, and its refusal is worded so it can't be mistaken for a server verdict.
export const MEDIA_MB = 1024 * 1024;
export const MEDIA_CAPS = { image: 50 * MEDIA_MB, gif: 10 * MEDIA_MB, video: 500 * MEDIA_MB, file: 100 * MEDIA_MB };
const MEDIA_MIME_BY_EXT = { ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp", ".svg": "image/svg+xml", ".mp4": "video/mp4", ".mov": "video/quicktime", ".webm": "video/webm", ".pdf": "application/pdf", ".md": "text/markdown", ".txt": "text/plain", ".csv": "text/csv", ".tsv": "text/tab-separated-values", ".json": "application/json", ".yaml": "application/yaml", ".yml": "application/yaml", ".log": "text/plain", ".zip": "application/zip", ".doc": "application/msword", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document" };
export function mediaMimeForPath(p) { return MEDIA_MIME_BY_EXT[(String(p).match(/\.[^.\/]+$/) || [""])[0].toLowerCase()] || "application/octet-stream"; }
export function mediaCapKind(mime) { return mime === "image/gif" ? "gif" : mime.startsWith("image/") ? "image" : mime.startsWith("video/") ? "video" : "file"; }
// Throws a DISTINGUISHABLE local-refusal error if `size` exceeds the per-type cap; else returns {mime,cap,kind}.
export function mediaCapCheck(filename, size) {
  const mime = mediaMimeForPath(filename);
  const kind = mediaCapKind(mime);
  const cap = MEDIA_CAPS[kind];
  if (size > cap)
    throw new Error(`buzz_post: attachment declined LOCALLY — ${String(filename).split("/").pop()} is ${(size / MEDIA_MB).toFixed(1)} MB, over the ${(cap / MEDIA_MB) | 0} MB ${kind} cap (a shim pre-flight limit, NOT a server 413).`);
  return { mime, cap, kind };
}

function normalizePubkey(v) {
  const s = (v || "").trim();
  if (/^[0-9a-f]{64}$/i.test(s)) return s.toLowerCase();
  if (s.startsWith("npub")) {
    try { const d = nip19.decode(s); if (d.type === "npub") return d.data; } catch { /* fall through */ }
  }
  return null;
}

// The SINGLE isolation boundary for the wire-sign wire format.
// CONTRACT CONFIRMED by ekam_agent (buzz-main 04:00, verified against ola-silicon/ekam#319):
//   Request : POST {base}/v1/me/wire-sign, `Authorization: Bearer <wire:sign-scoped token>`,
//             body {"event":{kind,tags,content}} — omit created_at (server-stamps,
//             anti-backdate), omit pubkey/id/sig (server fills from the escrowed key).
//   Response: 200 {"event": <fully-signed: kind,created_at,tags,content,pubkey,id,sig>,
//             "pubkey":"<hex>"} — nsec never appears.
//   Errors  : 401 unauthorized (revoked/expired/no token, agent token, or wrong aud),
//             403 forbidden (missing wire:sign scope / suspended human),
//             400 kind_not_allowed, 503 escrow/Vault unavailable — {error,error_description}.
// Guarded to fail LOUD on any mismatch, so a wrong/unsigned event never passes silently.
export async function wireSign(base, token, template, fetchFn = fetch) {
  const res = await fetchFn(`${base}/v1/me/wire-sign`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    // {event:{...}} envelope; kind/tags/content ONLY — server stamps created_at and
    // fills pubkey/id/sig from the escrowed wire key.
    body: JSON.stringify({ event: { kind: template.kind, tags: template.tags || [], content: template.content ?? "" } }),
  });
  const text = await res.text();
  if (!res.ok) {
    // surface ekam's typed failures cleanly, with a hint pointing at the WHO-gate
    // (#319): a wire:sign-scoped, ISSUER-audience token is required — a general
    // human token 403s/401s. The scoped-token mint is a loadkey_v2 Phase-2 concern.
    let detail = text.slice(0, 200);
    try { const j = JSON.parse(text); detail = j.error_description || j.error || detail; } catch { /* keep raw */ }
    const hint = res.status === 403 ? " (token likely missing the wire:sign scope, or human suspended)"
               : res.status === 401 ? " (token revoked/expired, or wrong audience — must be minted resource=ISSUER)"
               : res.status === 503 ? " (escrow/Vault unavailable — transient)"
               : "";
    throw new Error(`wire-sign kind ${template.kind} -> HTTP ${res.status}: ${detail}${hint}`);
  }
  let parsed;
  try { parsed = JSON.parse(text); }
  catch { throw new Error(`wire-sign returned non-JSON (contract mismatch): ${text.slice(0, 160)}`); }
  const ev = parsed.event; // confirmed envelope: {event, pubkey}
  if (!ev || !ev.id || !ev.sig || !ev.pubkey)
    throw new Error(`wire-sign response missing event.id/sig/pubkey (contract mismatch): ${text.slice(0, 160)}`);
  if (ev.kind !== template.kind)
    throw new Error(`wire-sign kind mismatch: asked ${template.kind}, got ${ev.kind}`);
  return ev;
}

/**
 * Resolve the shim's signer. Wire mode iff BUZZ_WIRE_SIGN is truthy AND a human
 * token is present; otherwise the existing local key path (fully unchanged).
 * Returns { mode, pubkey, canSign(kind), async sign({kind,tags,content}) }.
 * `opts.env` / `opts.fetch` injectable for tests; other opts pass to resolveKey.
 */
export async function resolveSigner(opts = {}) {
  const env = opts.env ?? process.env;
  const fetchFn = opts.fetch ?? fetch;

  const wantWire = /^(1|true|yes|on)$/i.test((env.BUZZ_WIRE_SIGN || "").trim());

  if (wantWire) {
    const base = ekamBase(env);
    // Wire mode needs the USER's pubkey up front — the membership query (#p),
    // @-mention self p-tags, and whoami all need it BEFORE any event is signed.
    // It's captured automatically at login (persisted alongside the refresh), so a
    // non-dev user never handles a key; BUZZ_USER_PUBKEY is only an override. Fail
    // CLOSED if neither is present: never guess or mint an identity.
    const pubkey = normalizePubkey(env.BUZZ_USER_PUBKEY) || wirePubkeyGet(wirePersistId(env));
    if (!pubkey)
      throw new Error("buzz-mcp: wire mode has no user identity yet — run the one-time login (it captures your pubkey), or set BUZZ_USER_PUBKEY.");
    const tokens = makeWireTokenProvider(env, fetchFn);
    if (!tokens.hasRefresh() && !tokens.hasStatic())
      throw new Error("buzz-mcp: wire mode needs BUZZ_WIRE_REFRESH (+BUZZ_EKAM_CLIENT_ID) from the one-time wire:sign login, or a static BUZZ_EKAM_HUMAN_TOKEN — refusing to start.");
    return {
      mode: "wire",
      pubkey,
      canSign: (kind) => WIRE_ALLOWLIST.has(kind),
      // Expose a valid wire:sign access token for authed Ekam reads (e.g. the
      // email→pubkey directory resolve) — same WHO-gate as signing, no new credential.
      ekamToken: () => tokens.get(false),
      ekamBase: () => base,
      async sign(template) {
        if (!WIRE_ALLOWLIST.has(template.kind))
          throw new Error(`wire mode refuses kind ${template.kind} (allowlist {${[...WIRE_ALLOWLIST].sort((a, b) => a - b).join(", ")}})`);
        const token = await tokens.get(false);
        try {
          return await wireSign(base, token, template, fetchFn);
        } catch (e) {
          // token expired mid-life → one forced re-mint + retry (only if we can refresh).
          if (/HTTP 401/.test(e.message) && tokens.hasRefresh()) {
            return await wireSign(base, await tokens.get(true), template, fetchFn);
          }
          throw e;
        }
      },
    };
  }

  // local (default): resolve a key and sign in-process — existing behavior, intact.
  const sk = await resolveKey(opts);
  const pubkey = getPublicKey(sk);
  return {
    mode: "local",
    pubkey,
    canSign: () => true,
    async sign(template) {
      return finalizeEvent(
        { kind: template.kind, created_at: template.created_at ?? now(), tags: template.tags || [], content: template.content ?? "" },
        sk,
      );
    },
  };
}
