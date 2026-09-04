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
export const wirePersistId = (env) => (env.BUZZ_IDENTITY_NAME || env.BUZZ_NAME || "wire").trim();

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
  }

  return {
    hasRefresh: () => !!refresh,
    hasStatic: () => !!(env.BUZZ_EKAM_HUMAN_TOKEN || "").trim(),
    async get(force) {
      if (!force && access && Date.now() < accessExp) return access;
      if (refresh) { await mint(); return access; }
      if (access) return access; // static token, no refresh to rotate
      throw new Error("wire mode: no bearer available (set BUZZ_WIRE_REFRESH+BUZZ_EKAM_CLIENT_ID, or BUZZ_EKAM_HUMAN_TOKEN)");
    },
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
export const WIRE_ALLOWLIST = new Set([9, 22242, 27235, 41010, 41011]);

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
          throw new Error(`wire mode refuses kind ${template.kind} (allowlist {9, 22242, 27235})`);
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
