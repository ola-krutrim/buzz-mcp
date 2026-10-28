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
import { getConversationKey as nip44ConvKey, encrypt as nip44Encrypt, decrypt as nip44Decrypt } from "./nip44.mjs";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
// Ola's registered PUBLIC OAuth client for "post as me" (PKCE, localhost redirect;
// no secret). Users kept getting "set BUZZ_EKAM_CLIENT_ID" at the one-time login
// because every install shares this one id — so it is the default; the env var
// still overrides it for another Ekam deployment.
export const DEFAULT_EKAM_CLIENT_ID = "clt_37501bdddf3c4e43a0ff";

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
export const WIRE_REFRESH_DIR = join(homedir(), ".config", "buzz-cli", "wire-refresh");
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

// The user's display name captured at login (ekam #335: /v1/me/wire-key returns `name` =
// the Ekam profile displayName → email local-part). Persisted next to the refresh so wire
// mode shows the PERSON's name (not an auto <ctx>·<animal>). Preferred over a kind:0 read
// because it's the identity system's authoritative name.
const wireNameFile = (id) => join(WIRE_REFRESH_DIR, `${(id || "default").replace(/[^\w.-]/g, "_").slice(0, 80)}.name`);
export function wireNameGet(id) {
  try { const f = wireNameFile(id); const v = existsSync(f) ? readFileSync(f, "utf8").trim() : ""; return v || null; } catch { return null; }
}
export function wireNameSet(id, name) {
  try { const v = String(name || "").trim(); if (!v) return false; mkdirSync(WIRE_REFRESH_DIR, { recursive: true, mode: 0o700 }); const f = wireNameFile(id); writeFileSync(f, v, { mode: 0o600 }); chmodSync(f, 0o600); return true; } catch { return false; }
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
  // unset → built-in Ola client; set (even empty) → used as-is, so a deployment can opt out.
  const clientId = (env.BUZZ_EKAM_CLIENT_ID ?? DEFAULT_EKAM_CLIENT_ID).trim();
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

// wire-sign kind allowlist — MIRRORS ekam's server allowlist (HUMAN_SIGN_ALLOWED_KINDS) plus
// 40003/9022, which Ekam is adding (see below). Originally {22242, 9, 27235}
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
//   9000/9001/9005 = NIP-29 governed moderation (add / remove / delete-message) — Ekam v206.
//   9007/9002/9021 = NIP-29 channel lifecycle (create-group / edit-metadata / join-request),
//           live server-side via ekam#464 (853feda, deployed Hyd v297 on 2026-10-20). Same
//           role-gated shape as the moderation kinds: Ekam stays content-agnostic; the relay's
//           validate_admin_event authorizes each against the SIGNER's OWN channel role (a wire-signed
//           create/edit only works where the human is already owner/admin; 9021 is open-channel
//           self-join, private refused) — so mirroring these does not widen authority.
//   40003 = edit one of your own messages, 9022 = leave a channel (v0.2.32-pre, approved by
//           Navendu). NOTE: the shim allows them, but Ekam only signs them once its own
//           HUMAN_SIGN_ALLOWED_KINDS gains them (pending security-reviewed Ekam PR). Until then
//           Ekam answers 400 kind_not_allowed, which wireSign() turns into a clear error naming
//           the refused kind and Ekam's current allowed set — no version pinning here.
//   NOT here, on purpose: 9008 (delete channel), 5 (deletion — unreact), 41012 (DM hide). Ekam
//           refuses them deliberately (pinned by Ekam tests), so the shim refuses them locally
//           before any network call; they only work with an agent's own key (agent mode).
export const WIRE_ALLOWLIST = new Set([9, 22242, 27235, 41010, 41011, 7, 24242, 9000, 9001, 9005, 9007, 9002, 9021, 40003, 9022]);
// Kinds Ekam refuses to wire-sign BY DESIGN (not "not yet"): the shim names them as such.
export const EKAM_REFUSED_BY_DESIGN = new Map([[9008, "delete channel"], [5, "deletion / remove reaction"], [41012, "hide a DM"]]);
// v0.2.34: kinds buzz-mcp NEVER signs, in ANY mode (local, wire, dry run). Workflow approval grant /
// deny (46030/46031) is a human decision: an agent must never approve (or deny on someone's behalf)
// a workflow step — least of all one it triggered itself (buzz_workflow_run). There is deliberately
// no approval tool; this guard makes that fail closed even if a future code path tries to sign one.
export const NEVER_SIGN = new Map([[46030, "workflow approval (grant)"], [46031, "workflow approval (deny)"]]);
const neverSignError = (kind) => new Error(`buzz-mcp never signs kind ${kind} (${NEVER_SIGN.get(kind)}) — workflow approvals are a human decision; approve or deny in the Buzz app. Nothing was signed.`);

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

// ── Attachment policy (attach-hardening, buzz_security attachment ruling on buzz@f040819e3).
// Agents are prompt-injectable, so the shim uploads only a NARROW ALLOW-LIST, decided from the
// file's BYTES — never from its extension (the old MEDIA_MIME_BY_EXT map, incl. its .svg →
// image/svg+xml entry, is gone). Same list and rules as buzz-cli's upload_policy.rs:
//   images  jpeg/png/gif/webp (50 MB; gif 10 MB)       video  mp4 (500 MB)
//   files   pdf, docx, xlsx, pptx, odt, ods, odp (sniffed) and txt, csv, md, json (extension +
//           valid UTF-8, no control chars, no HTML/XML markup at the start, .json must parse) — 100 MB
// Refused: HTML, XML/SVG, scripts, zip and other archives, legacy OLE (doc/xls/ppt/msi), executables,
// and OOXML/ODF whose ZIP central directory lists vbaProject.bin or ODF Basic/ / Scripts/ (fail closed).
// The posted filename is sanitised (NFC; no Cf/bidi, no C0/C1, no / \; trimmed of dots/spaces;
// ≤120 bytes) and its extension FORCED to the sniffed type. The relay re-validates and is authoritative.
export const MEDIA_MB = 1024 * 1024;
export const MEDIA_CAPS = { image: 50 * MEDIA_MB, gif: 10 * MEDIA_MB, video: 500 * MEDIA_MB, file: 100 * MEDIA_MB };
const DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
const XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
const PPTX = "application/vnd.openxmlformats-officedocument.presentationml.presentation";
const ODT = "application/vnd.oasis.opendocument.text";
const ODS = "application/vnd.oasis.opendocument.spreadsheet";
const ODP = "application/vnd.oasis.opendocument.presentation";
export const OCTET_STREAM = "application/octet-stream";
// THE allow-list for generic files: [forced extension, sniffed MIME | "text"].
export const ATTACH_ALLOWED_FILE_TYPES = Object.freeze([
  ["pdf", "application/pdf"], ["docx", DOCX], ["xlsx", XLSX], ["pptx", PPTX],
  ["odt", ODT], ["ods", ODS], ["odp", ODP],
  ["txt", "text"], ["csv", "text"], ["md", "text"], ["json", "text"],
].map(([ext, detect]) => Object.freeze({ ext, detect })));
export const ATTACH_IMAGE_MIMES = Object.freeze(["image/jpeg", "image/png", "image/gif", "image/webp"]);
export const ATTACH_VIDEO_MIMES = Object.freeze(["video/mp4"]);
export const ATTACH_MAX_NAME_BYTES = 120;
const TEXT_EXTS = new Set(ATTACH_ALLOWED_FILE_TYPES.filter((t) => t.detect === "text").map((t) => t.ext));
const SNIFFED_EXT = new Map(ATTACH_ALLOWED_FILE_TYPES.filter((t) => t.detect !== "text").map((t) => [t.detect, t.ext]));
// The relay's MP4 brands (buzz-media/src/validation.rs MP4_BRANDS).
const MP4_BRANDS = new Set(["isom", "iso2", "iso3", "iso4", "iso5", "iso6", "iso7", "iso8", "iso9", "mp41", "mp42", "avc1", "dash", "M4V "]);
const MARKUP_MARKERS = ["<!doctype", "<html", "<head", "<body", "<script", "<iframe", "<svg", "<?xml", "<xml"];

function declined(name, why) {
  return new Error(`buzz_post: attachment declined LOCALLY — ${name}: unsupported file type (${why}). Allowed: images (jpeg/png/gif/webp), mp4 video, and pdf, docx, xlsx, pptx, odt, ods, odp, txt, csv, md, json (a shim pre-flight check, NOT a server verdict).`);
}
const startsWith = (b, sig, at = 0) => b.length >= at + sig.length && sig.every((v, i) => b[at + i] === v);
const ascii = (s) => [...s].map((c) => c.charCodeAt(0));
function localExt(name) {
  const base = String(name).split(/[\\/]/).pop();
  const i = base.lastIndexOf(".");
  return i > 0 ? base.slice(i + 1).trim().toLowerCase() : "";
}

// Image / video / PDF / ZIP by magic bytes (the subset of `infer` the allow-list needs).
// → "image/…" | "video/mp4" | "application/pdf" | "zip" | null (no recognised magic).
function sniffHead(b) {
  if (startsWith(b, [0xff, 0xd8, 0xff])) return "image/jpeg";
  if (startsWith(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return "image/png";
  if (startsWith(b, ascii("GIF87a")) || startsWith(b, ascii("GIF89a"))) return "image/gif";
  if (startsWith(b, ascii("RIFF")) && startsWith(b, ascii("WEBP"), 8)) return "image/webp";
  if (startsWith(b, ascii("%PDF-"))) return "application/pdf";
  if (startsWith(b, [0x50, 0x4b, 0x03, 0x04])) return "zip";
  if (b.length >= 16 && startsWith(b, ascii("ftyp"), 4)) {
    const brands = [];
    const boxLen = Math.min(b.length, b.readUInt32BE(0) || b.length);
    brands.push(b.toString("latin1", 8, 12));
    for (let i = 16; i + 4 <= boxLen; i += 4) brands.push(b.toString("latin1", i, i + 4));
    return brands.some((x) => MP4_BRANDS.has(x)) ? "video/mp4" : "iso-bmff";
  }
  return null;
}

// Entry names from a ZIP central directory; null if missing/truncated/ZIP64.
export function zipCentralDirectoryNames(b) {
  if (b.length < 22) return null;
  let eocd = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 22 - 65535); i--) {
    if (b[i] === 0x50 && b[i + 1] === 0x4b && b[i + 2] === 0x05 && b[i + 3] === 0x06) { eocd = i; break; }
  }
  if (eocd < 0) return null;
  const count = b.readUInt16LE(eocd + 10), cdSize = b.readUInt32LE(eocd + 12), cdOff = b.readUInt32LE(eocd + 16);
  if (count === 0xffff || cdSize === 0xffffffff || cdOff === 0xffffffff || cdOff + cdSize > eocd) return null;
  const names = [];
  let at = cdOff;
  for (let n = 0; n < count; n++) {
    if (at + 46 > b.length || b.readUInt32LE(at) !== 0x02014b50) return null;
    const nl = b.readUInt16LE(at + 28), el = b.readUInt16LE(at + 30), cl = b.readUInt16LE(at + 32);
    if (at + 46 + nl > b.length) return null;
    names.push(b.toString("utf8", at + 46, at + 46 + nl));
    at += 46 + nl + el + cl;
  }
  return names;
}

// OOXML/ODF type of a ZIP, or throws (plain zip, macros, unreadable directory).
function classifyZip(b, name) {
  const names = zipCentralDirectoryNames(b);
  if (!names) throw declined(name, "ZIP with an unreadable directory");
  for (const n of names) {
    const lower = n.toLowerCase();
    if (lower.split("/").pop().startsWith("vbaproject")) throw declined(name, "Office file containing macros (vbaProject.bin)");
    if (lower.startsWith("basic/") || lower.startsWith("scripts/")) throw declined(name, `OpenDocument file containing macros (${n})`);
  }
  if (b.toString("latin1").toLowerCase().includes("vbaproject")) throw declined(name, "Office file containing macros (vbaProject.bin)");
  // ODF: first local entry is a stored "mimetype" whose content names the type (what infer checks).
  if (b.toString("latin1", 0x1e, 0x26) === "mimetype") {
    const m = b.toString("latin1", 0x26, 0x26 + 60);
    for (const t of [ODT, ODS, ODP]) if (m.startsWith(t)) return t;
  }
  const set = new Set(names);
  if (set.has("[Content_Types].xml") || names.some((n) => /^(word|xl|ppt)\//.test(n))) {
    if (names.some((n) => n.startsWith("word/"))) return DOCX;
    if (names.some((n) => n.startsWith("xl/"))) return XLSX;
    if (names.some((n) => n.startsWith("ppt/"))) return PPTX;
  }
  throw declined(name, "zip archive");
}

// Plain-text check for txt/csv/md/json (no magic bytes to sniff).
export function checkAttachmentText(b, ext, name = `file.${ext}`) {
  let body = startsWith(b, [0xef, 0xbb, 0xbf]) ? b.subarray(3) : b;
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(body); } catch { throw declined(name, `.${ext} that is not valid UTF-8 text`); }
  if (/[\u0000-\u0008\u000b\u000e-\u001f\u007f-\u009f]/.test(text)) throw declined(name, `.${ext} containing control characters`);
  if (text.trimStart().startsWith("<")) throw declined(name, `.${ext} that starts with markup`);
  if (text.startsWith("#!")) throw declined(name, `.${ext} that is a script (#!)`);
  const head = body.subarray(0, 1024).toString("latin1").toLowerCase();
  if (MARKUP_MARKERS.some((m) => head.includes(m))) throw declined(name, `.${ext} containing HTML/XML markup`);
  if (ext === "json") { try { JSON.parse(text); } catch { throw declined(name, ".json that is not valid JSON"); } }
}

// Decide from the bytes whether `name` may be uploaded. `read(start, len)` returns a Buffer of the
// file (the caller reads from the already-checked fd). → { mime, kind } | throws a local refusal.
// The whole file is read only for ZIP-based Office files and text (both ≤100 MB, size-checked first).
export function classifyAttachment({ name, size, read }) {
  const display = String(name).split(/[\\/]/).pop();
  const head = read(0, Math.min(size, 4096));
  const sniffed = sniffHead(head);
  const capped = (mime, kind) => { mediaCapCheck(display, size, mime); return { mime, kind }; };
  if (sniffed && ATTACH_IMAGE_MIMES.includes(sniffed)) return capped(sniffed, mediaCapKind(sniffed));
  if (sniffed === "video/mp4") return capped(sniffed, "video");
  if (sniffed === "iso-bmff") throw declined(display, "ISO-BMFF media that is not mp4");
  if (sniffed === "application/pdf") return capped(sniffed, "file");
  if (size > MEDIA_CAPS.file) mediaCapCheck(display, size, OCTET_STREAM); // throws before a whole-file read
  if (sniffed === "zip") return capped(classifyZip(read(0, size), display), "file");
  const ext = localExt(display);
  if (!TEXT_EXTS.has(ext)) throw declined(display, "unrecognised content; plain text must be .txt, .csv, .md or .json");
  checkAttachmentText(read(0, size), ext, display);
  return capped(OCTET_STREAM, "file");
}

export function mediaCapKind(mime) { return mime === "image/gif" ? "gif" : mime.startsWith("image/") ? "image" : mime.startsWith("video/") ? "video" : "file"; }
// Throws a DISTINGUISHABLE local-refusal error if `size` exceeds the per-type cap; else returns
// {mime,cap,kind}. `mime` is the SNIFFED type (classifyAttachment) — never derived from the extension.
export function mediaCapCheck(filename, size, mime = OCTET_STREAM) {
  const kind = mediaCapKind(mime);
  const cap = MEDIA_CAPS[kind];
  if (size > cap)
    throw new Error(`buzz_post: attachment declined LOCALLY — ${String(filename).split(/[\\/]/).pop()} is ${(size / MEDIA_MB).toFixed(1)} MB, over the ${(cap / MEDIA_MB) | 0} MB ${kind} cap (a shim pre-flight limit, NOT a server 413).`);
  return { mime, cap, kind };
}

// Clean a local path into the name other people see: basename, NFC, no Cf (incl. bidi U+202A–202E,
// U+2066–2069, U+200E/F, U+061C, zero-width, BOM), no C0/C1, no / or \, trimmed of dots/spaces.
export function sanitizeAttachmentName(p) {
  const base = String(p ?? "").split(/[\\/]/).pop();
  const cleaned = base.normalize("NFC").replace(/[\p{Cc}\p{Cf}\\/]/gu, "").replace(/^[\s.]+|[\s.]+$/gu, "");
  return cleaned || "file";
}
// The posted filename: sanitised, extension forced to the sniffed/stored type, ≤120 bytes.
export function attachmentDisplayName(p, mime) {
  const name = sanitizeAttachmentName(p);
  const i = name.lastIndexOf(".");
  const stem0 = i > 0 ? name.slice(0, i) : name;
  const ext = i > 0 ? name.slice(i + 1).toLowerCase() : "";
  let forced;
  if (SNIFFED_EXT.has(mime)) forced = SNIFFED_EXT.get(mime);
  else if (ATTACH_IMAGE_MIMES.includes(mime) || ATTACH_VIDEO_MIMES.includes(mime)) forced = { "image/jpeg": "jpg", "image/png": "png", "image/gif": "gif", "image/webp": "webp", "video/mp4": "mp4" }[mime];
  else forced = TEXT_EXTS.has(ext) ? ext : "txt";
  if (mime === "image/jpeg" && (ext === "jpg" || ext === "jpeg")) forced = ext;
  let stem = stem0.replace(/^[\s.]+|[\s.]+$/gu, "") || "file";
  const budget = ATTACH_MAX_NAME_BYTES - forced.length - 1;
  while (Buffer.byteLength(stem) > budget) stem = [...stem].slice(0, -1).join("");
  return `${stem.trimEnd() || "file"}.${forced}`;
}
// Escape markdown link-label metacharacters \ [ ] ( ) < > so a name can't break out of its link.
export function escapeLinkLabel(s) { return String(s).replace(/[\\[\]()<>]/g, (c) => `\\${c}`); }
// The message-body line for an uploaded blob: images/video stay a bare URL (rendered from imeta);
// every other file is a named [filename](url) link.
export function attachmentContentLine({ url, mime, filename }) {
  const m = String(mime || "");
  if (m.startsWith("image/") || m.startsWith("video/")) return String(url);
  return `[${escapeLinkLabel(filename || "file")}](${url})`;
}

function normalizePubkey(v) {
  const s = (v || "").trim();
  if (/^[0-9a-f]{64}$/i.test(s)) return s.toLowerCase();
  if (s.startsWith("npub")) {
    try { const d = nip19.decode(s); if (d.type === "npub") return d.data; } catch { /* fall through */ }
  }
  return null;
}

// v0.2.32-pre: Ekam's `400 kind_not_allowed` names the kinds it DOES sign in error_description
// (format not contractual). Pull them out defensively: an explicit array field if Ekam ever sends
// one, else the first {…} / […] / (…) group holding only integers, else the integers after the
// nearest "allow…" word that is followed by a list (up to the next . ; newline or "("). Only 0..65535 count (Nostr kinds). Anything else → null; never throws.
export function parseAllowedKinds(body) {
  try {
    const pick = (arr) => {
      const ks = [...new Set(arr.map((x) => Number(x)).filter((n) => Number.isInteger(n) && n >= 0 && n <= 65535))].sort((a, b) => a - b);
      return ks.length ? ks : null;
    };
    if (body && typeof body === "object") {
      for (const f of ["allowed_kinds", "allowed"]) if (Array.isArray(body[f])) { const r = pick(body[f]); if (r) return r; }
    }
    const desc = typeof body === "string" ? body : (body && typeof body.error_description === "string" ? body.error_description : "");
    if (!desc) return null;
    const d = desc.slice(0, 4000);
    const ints = (t) => (t.match(/\d+/g) || []);
    for (const m of d.matchAll(/[{[(]([^{}[\]()]*)[}\])]/g)) {
      if (/^[\s\d,;|]+$/.test(m[1]) && ints(m[1]).length) return pick(ints(m[1]));
    }
    for (const at of [...d.matchAll(/allow\w*/gi)].reverse()) {
      const tail = d.slice(at.index + at[0].length).split(/[.;\n(]/, 1)[0];
      const r = /^[\s\w:=,|]*$/.test(tail) ? pick(ints(tail)) : null;
      if (r) return r;
    }
    return null;
  } catch { return null; }
}
// Printable, single-line, bounded echo of a server string (no control / bidi characters).
const echo = (t) => String(t).replace(/[\p{Cc}\p{Bidi_Control}\u200B-\u200F\u2028\u2029\uFEFF]+/gu, " ").replace(/\s+/g, " ").trim().slice(0, 160);
export function kindNotAllowedMessage(kind, body) {
  const allowed = parseAllowedKinds(body);
  const desc = body && typeof body === "object" ? body.error_description : body;
  const what = allowed ? `it currently allows {${allowed.join(", ")}}`
    : `it didn't say which kinds it allows${desc ? ` (Ekam said: "${echo(desc)}")` : ""}`;
  return `Ekam (your signing service) doesn't sign kind ${kind} yet; ${what}. Ask the Ekam owner to add it, or use an agent's own key. (wire-sign HTTP 400 kind_not_allowed)`;
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
//             (v0.2.32-pre) 400 kind_not_allowed → kindNotAllowedMessage(): refused kind + Ekam's allowed set.
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
    let detail = text.slice(0, 200), j = null;
    try { j = JSON.parse(text); detail = j.error_description || j.error || detail; } catch { /* keep raw */ }
    if (res.status === 400 && j && typeof j === "object" && j.error === "kind_not_allowed") {
      const err = new Error(kindNotAllowedMessage(template.kind, j));
      err.code = "kind_not_allowed"; err.kind = template.kind; err.allowedKinds = parseAllowedKinds(j);
      throw err;
    }
    const hint = res.status === 403 ? " (token likely missing the wire:sign scope, or human suspended)"
               : res.status === 401 ? " (token revoked/expired, or wrong audience — must be minted resource=ISSUER)"
               : res.status === 503 ? " (escrow/Vault unavailable — transient)"
               : "";
    const err = new Error(`wire-sign kind ${template.kind} -> HTTP ${res.status}: ${detail}${hint}`);
    err.status = res.status; err.ekamError = j && typeof j === "object" && typeof j.error === "string" ? j.error : null; // v0.2.35: typed, for hosted mapping
    throw err;
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
      canSign: (kind) => WIRE_ALLOWLIST.has(kind) && !NEVER_SIGN.has(kind),
      wipe() { /* wire mode holds no key */ },
      // v0.2.33: no encrypt-to-self in wire mode — the user's key is escrowed at Ekam and Ekam offers
      // no NIP-44 endpoint, so NIP-44 features (read state, private saved items) are agent-mode only.
      selfCipher: null,
      // Expose a valid wire:sign access token for authed Ekam reads (e.g. the
      // email→pubkey directory resolve) — same WHO-gate as signing, no new credential.
      ekamToken: () => tokens.get(false),
      ekamBase: () => base,
      async sign(template) {
        if (NEVER_SIGN.has(template.kind)) throw neverSignError(template.kind);
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
  let wiped = false;
  // v0.2.33: NIP-44 v2 encrypt-to-SELF (conversation key = ECDH(own sk, own pk)), used for NIP-RS read
  // state (kind 30078) and private NIP-51 saved items. The secret key never leaves this closure; the
  // derived conversation key is computed lazily, held only here, and zeroed by wipe(). Only three
  // narrow operations are exposed: encrypt/decrypt to self, and derive(label) = HMAC-SHA256(convKey,
  // label) for stable per-identity identifiers (read-state slot / client_id) that reveal nothing.
  let convKey = null;
  const ck = () => {
    if (wiped) throw new Error("signer: key already wiped (shutting down)");
    if (!convKey) convKey = nip44ConvKey(sk, pubkey);
    return convKey;
  };
  const selfCipher = Object.freeze({
    encrypt: (plaintext) => nip44Encrypt(plaintext, ck()),
    decrypt: (payload) => nip44Decrypt(payload, ck()),
    derive: (label) => Buffer.from(hmac(sha256, ck(), new TextEncoder().encode(String(label)))).toString("hex"),
  });
  return {
    mode: "local",
    pubkey,
    canSign: (kind) => !NEVER_SIGN.has(kind),
    selfCipher,
    // v0.2.31 (item 8): zero the in-memory secret key on shutdown. After wipe() the signer refuses
    // rather than signing with an all-zero key. (Best effort: JS strings the key passed through as
    // hex cannot be wiped; the Uint8Array the signer holds can.)
    wipe() { wiped = true; sk.fill(0); if (convKey) convKey.fill(0); },
    async sign(template) {
      if (wiped) throw new Error("signer: key already wiped (shutting down)");
      if (NEVER_SIGN.has(template.kind)) throw neverSignError(template.kind);
      return finalizeEvent(
        { kind: template.kind, created_at: template.created_at ?? now(), tags: template.tags || [], content: template.content ?? "" },
        sk,
      );
    },
  };
}

// ---- v0.2.35 hosted (multi-user HTTP) wire signer ----
// The hosted connector holds NO key and NO refresh token on disk. Each session gets a signer whose
// wire:sign access token comes from `getToken(force)` — an RFC 8693 token exchange of the person's
// own validated Ekam access token (http-server.mjs / hosted-auth.mjs), cached in memory per user.
// Same allowlist + NEVER_SIGN as the stdio wire signer, plus an identity binding: every event Ekam
// returns MUST carry the pubkey this session was bound to, or it is refused (never relayed).
// The one message a hosted user sees when Ekam can't sign for them because their Buzz identity isn't
// provisioned yet (they've never opened the Buzz app / signed in there with Ekam).
// ASSUMPTION (unverified against live Ekam): that state surfaces as 403 from /v1/me/wire-sign, or as
// one of these error codes from wire-sign / the token exchange. Ekam to confirm the exact codes.
export const BUZZ_APP_SIGNIN_MESSAGE = "Open the Buzz app once and sign in with Ekam, then try again.";
export const BUZZ_APP_SIGNIN_RE = /Open the Buzz app once and sign in with Ekam/;
const BUZZ_APP_SIGNIN_CODES = new Set(["not_governed", "no_wire_key", "wire_key_not_found", "wire_key_missing", "not_provisioned", "human_not_found", "user_not_provisioned", "buzz_identity_missing"]);
export function isBuzzAppSigninError({ status, error } = {}) {
  if (error && BUZZ_APP_SIGNIN_CODES.has(String(error))) return true;
  return status === 403 && !error; // bare 403 from wire-sign after a successful wire:sign exchange
}
export function buzzAppSigninError(cause) {
  const e = new Error(BUZZ_APP_SIGNIN_MESSAGE);
  e.code = "buzz_app_signin_required"; e.cause = cause;
  return e;
}

// Hosted: never surface Ekam's raw response body (it could echo a token) — keep only HTTP status + a
// well-formed error code. Typed kind_not_allowed and the not-provisioned message pass through.
const SAFE_CODE = /^[A-Za-z0-9_.:-]{1,64}$/;
export function hostedWireError(e, kind) {
  if (!e || e.code === "kind_not_allowed" || e.code === "buzz_app_signin_required" || e.status == null) return e;
  const code = typeof e.ekamError === "string" && SAFE_CODE.test(e.ekamError) ? ` ${e.ekamError}` : "";
  const err = new Error(`wire-sign${kind != null ? ` kind ${kind}` : ""} -> HTTP ${e.status}${code} — Ekam could not sign; try again`);
  err.status = e.status; err.ekamError = code ? e.ekamError : null;
  return err;
}

export function makeHostedWireSigner({ pubkey, getToken, base, fetch: fetchFn = fetch } = {}) {
  const pk = normalizePubkey(pubkey);
  if (!pk) throw new Error("hosted signer: a 64-hex user pubkey is required");
  if (typeof getToken !== "function") throw new Error("hosted signer: getToken(force) is required");
  if (!base) throw new Error("hosted signer: the Ekam base URL is required");
  return {
    mode: "wire",
    hosted: true,
    pubkey: pk,
    canSign: (kind) => WIRE_ALLOWLIST.has(kind) && !NEVER_SIGN.has(kind),
    wipe() { /* holds no key */ },
    selfCipher: null,
    ekamToken: () => getToken(false),
    ekamBase: () => base,
    async sign(template) {
      if (NEVER_SIGN.has(template.kind)) throw neverSignError(template.kind);
      if (!WIRE_ALLOWLIST.has(template.kind))
        throw new Error(`wire mode refuses kind ${template.kind} (allowlist {${[...WIRE_ALLOWLIST].sort((a, b) => a - b).join(", ")}})`);
      let ev;
      // 403 (bare / "forbidden") or a not-provisioned code → the one friendly message; anything else unchanged.
      const mapped = (e) => (e && isBuzzAppSigninError({ status: e.status, error: e.ekamError === "forbidden" ? null : e.ekamError }) ? buzzAppSigninError(e) : hostedWireError(e, template.kind));
      try { ev = await wireSign(base, await getToken(false), template, fetchFn); }
      catch (e) {
        if (e.status !== 401) throw mapped(e);
        try { ev = await wireSign(base, await getToken(true), template, fetchFn); } // one forced re-exchange
        catch (e2) { throw mapped(e2); }
      }
      if (String(ev.pubkey).toLowerCase() !== pk)
        throw new Error("wire-sign returned an event for a different identity than this session — refused, nothing was sent");
      return ev;
    },
  };
}

// Learn the person's pubkey without ever fetching key material: sign a throwaway NIP-98 (27235)
// for a non-routable URL and read the pubkey off the signed event (same probe as wirelogin.mjs).
// The event is never sent anywhere.
export async function probeWirePubkey(base, token, fetchFn = fetch) {
  const ev = await wireSign(base, token, { kind: 27235, tags: [["u", `${base}/whoami`], ["method", "GET"], ["payload", ""]], content: "" }, fetchFn);
  const pk = normalizePubkey(ev.pubkey);
  if (!pk) throw new Error("wire-sign probe returned no usable pubkey");
  return pk;
}
