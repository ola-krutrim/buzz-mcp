// loadkey_v2 — the #104 identity-resolution for the Buzz MCP shim.
//
// Fixes the churn that 403'd releng + bossman: a NAMED (governed) agent whose
// key is missing on restart no longer silently mints a RANDOM new pubkey. It
// recovers a stable identity (Phase 1: env pin / 0600 keystore) or self-fetches
// it custody-clean (Phase 2: service-refresh → agent token → wire-key), and
// fails LOUD otherwise. Unnamed (casual) sessions are unchanged.
//
// TWO IDENTITY MODES (ekam_agent seam, 2026-08-29):
//   Phase 1 (clone-and-go today): `buzz agent add` writes BUZZ_PRIVATE_KEY (hex
//     agent nsec) + BUZZ_NAME + BUZZ_AUTH_TAG. The shim reads the key directly;
//     it's cached to the 0600 keystore so a lost env pin still recovers.
//   Phase 2 (custody-clean): `buzz agent add` writes a rotatable BUZZ_SERVICE_REFRESH
//     (NOT the raw nsec). The shim EXCHANGES it → short-TTL agent token →
//     GET /v1/me/wire-key → decodes the bech32 nsec → key in MEMORY, NEVER on
//     disk (no keystore read/write for this agent). Fail-closed on any fetch
//     error — never a random or persisted fallback. `owner_seed` never involved
//     (Ekam PR #286: the shim re-FETCHES its derived key, never re-derives).
//
// SECURITY (SEC-1 / #27, HIGH — fixed + buzz_security-cleared): the Phase-1
// keystore is a 0600 file under ~/.config/buzz-cli/identities/, NOT the macOS
// `security` CLI (which put the secret on argv). No child_process, no owner-seed
// derivation code.
//
// Standalone module: `node loadkey_v2.mjs --test` self-checks keystore round-trip,
// fail-closed, casual, AND the Phase-2 self-fetch (via an injected fetch). The
// live buzz-mcp.mjs imports `resolveKey` (now async — `await resolveKey(...)`).

import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { getPublicKey, generateSecretKey } from "nostr-tools/pure";
import * as nip19 from "nostr-tools/nip19";

const CFG_DIR = join(homedir(), ".config", "buzz-cli");
const IDENTITY_DIR = join(CFG_DIR, "identities");
const hexToSk = (hex) => Uint8Array.from(Buffer.from(hex, "hex"));
const skToHex = (sk) => Buffer.from(sk).toString("hex");

const identityFile = (account) =>
  join(IDENTITY_DIR, `${account.replace(/[^\w.-]/g, "_").slice(0, 80)}.hex`);

/** Read a named agent's cached secret from the 0600 keystore, or null. */
function keystoreGet(account) {
  try {
    const f = identityFile(account);
    if (!existsSync(f)) return null;
    const hex = readFileSync(f, "utf8").trim();
    return /^[0-9a-f]{64}$/.test(hex) ? hex : null;
  } catch {
    return null;
  }
}

/** Cache a named agent's secret to the keystore as a 0600 file (owner-only). */
function keystoreSet(account, hex) {
  try {
    mkdirSync(IDENTITY_DIR, { recursive: true, mode: 0o700 });
    const f = identityFile(account);
    writeFileSync(f, hex, { mode: 0o600 });
    chmodSync(f, 0o600);
    return true;
  } catch {
    return false;
  }
}

// ── Phase 2: custody-clean self-fetch ─────────────────────────────────────────
// Ekam base for the token exchange + wire-key fetch. Configurable; prod default.
const ekamBase = (env) =>
  (env.BUZZ_EKAM_BASE || "https://ekam.olakrutrim.com").replace(/\/+$/, "");

// The ekam agent service-refresh grant (a custom, ISOLATED grant — NOT the
// human/CLI `refresh_token` grant). Confirmed w/ ekam_agent 2026-08-29.
const SERVICE_REFRESH_GRANT = "urn:ekam:params:oauth:grant-type:service-refresh";
// The rotatable service-refresh token is SINGLE-USE: each exchange rotates it
// and burns the old one. We persist the rotated token to a 0600 side-file
// (preferred over the env seed) so the next session uses the live token — reusing
// a spent one trips replay detection and revokes the whole family (lockout).
const REFRESH_DIR = join(CFG_DIR, "service-refresh");
const refreshFile = (account) =>
  join(REFRESH_DIR, `${(account || "default").replace(/[^\w.-]/g, "_").slice(0, 80)}.tok`);

function refreshGet(account) {
  try {
    const f = refreshFile(account);
    if (!existsSync(f)) return null;
    const t = readFileSync(f, "utf8").trim();
    return t.length ? t : null;
  } catch {
    return null;
  }
}
function refreshSet(account, token) {
  try {
    mkdirSync(REFRESH_DIR, { recursive: true, mode: 0o700 });
    const f = refreshFile(account);
    writeFileSync(f, token, { mode: 0o600 });
    chmodSync(f, 0o600);
    return true;
  } catch {
    return false;
  }
}

/**
 * Exchange the rotatable service-refresh for the agent's escrowed wire-key and
 * return its 32-byte secret — IN MEMORY, never written to disk. `null` when no
 * service-refresh is available. Throws (→ caller fails closed) on any failure.
 *
 * `fetchFn` is injectable for testing. Flow (ekam seam, confirmed):
 *   1. POST {ekam}/oauth/token  (JSON: {grant_type: SERVICE_REFRESH_GRANT,
 *      refresh_token}) — body is strict, NO client_id → {access_token(type:agent),
 *      refresh_token(ROTATED), …}
 *   2. IMMEDIATELY persist the rotated refresh_token (old one is now burned).
 *   3. GET {ekam}/v1/me/wire-key (Bearer agent token) → bech32 nsec
 *   4. nip19-decode nsec → 32-byte sk (never persisted)
 */
export async function selfFetchKey(env, fetchFn = fetch) {
  const name = (env.BUZZ_IDENTITY_NAME || env.BUZZ_NAME || "").trim();
  // Prefer the persisted (rotated) token over the initial env seed.
  const refresh = (refreshGet(name) || env.BUZZ_SERVICE_REFRESH || "").trim();
  if (!refresh) return null;
  const base = ekamBase(env);

  const tokRes = await fetchFn(`${base}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ grant_type: SERVICE_REFRESH_GRANT, refresh_token: refresh }),
  });
  if (!tokRes.ok) {
    throw new Error(
      `service-refresh exchange failed: HTTP ${tokRes.status} ${(await tokRes.text()).slice(0, 160)}`,
    );
  }
  const tok = await tokRes.json();
  const token = tok.access_token;
  if (!token) throw new Error("service-refresh exchange returned no access_token");
  // #3 CRITICAL: persist the ROTATED refresh token now — the old one is burned
  // server-side; a later reuse → replay detection → family revoked. Persist
  // before the wire-key fetch so a fetch failure can't strand us on a spent token.
  if (tok.refresh_token) refreshSet(name, tok.refresh_token);

  const wkRes = await fetchFn(`${base}/v1/me/wire-key`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!wkRes.ok) {
    throw new Error(
      `wire-key fetch failed: HTTP ${wkRes.status} ${(await wkRes.text()).slice(0, 160)}`,
    );
  }
  const wk = await wkRes.json();
  const nsec = (wk.nsec || wk.wire_key || wk.key || "").trim();
  if (!nsec) throw new Error("wire-key response carried no nsec");

  const dec = nip19.decode(nsec); // throws on malformed bech32
  if (dec.type !== "nsec") throw new Error(`unexpected wire-key type: ${dec.type}`);
  return dec.data; // Uint8Array(32) — in memory only
}

/** Resolve the shim's identity key. Async (Phase 2 self-fetch is HTTP).
 *  Returns the 32-byte secret key. Throws (fail-closed) for a named agent whose
 *  stable identity can't be recovered. `opts.env` / `opts.fetch` injectable. */
export async function resolveKey(opts = {}) {
  const env = opts.env ?? process.env;
  const fetchFn = opts.fetch ?? fetch;
  const sessionId = opts.sessionId ?? "casual";
  const name = (env.BUZZ_IDENTITY_NAME || env.BUZZ_NAME || "").trim();
  const named = name.length > 0;

  // 1. Explicit pin (Phase 1) — cache under the name so a lost pin still recovers.
  for (const k of [env.BUZZ_IDENTITY_KEY, env.BUZZ_PRIVATE_KEY]) {
    const hex = (k || "").trim().toLowerCase();
    if (/^[0-9a-f]{64}$/.test(hex)) {
      if (named) keystoreSet(name, hex);
      return hexToSk(hex);
    }
  }

  // 2. Phase 2 custody-clean: a service-refresh is authoritative → self-fetch the
  //    key into memory. We do NOT read or write the keystore for this agent (the
  //    key is never persisted), and any failure is fail-closed — no random or
  //    stale-disk fallback.
  if ((env.BUZZ_SERVICE_REFRESH || "").trim()) {
    return await selfFetchKey(env, fetchFn); // non-null (refresh present) or throws
  }

  if (named) {
    // 3. Recover the stable identity from the 0600 keystore (Phase 1).
    const cached = keystoreGet(name);
    if (cached) return hexToSk(cached);

    // 4. Named but nothing recoverable → FAIL CLOSED (never random).
    throw new Error(
      `buzz-mcp: identity for "${name}" is unavailable — no env pin, no keystore ` +
        `entry, no service-refresh. Refusing to mint a random identity (would 403 ` +
        `as a non-member). Set BUZZ_PRIVATE_KEY / BUZZ_SERVICE_REFRESH, or ` +
        `provision "${name}" via Ekam.`,
    );
  }

  // 5. UNNAMED casual session → per-session .hex / random (unchanged behavior).
  const dir = join(CFG_DIR, "sessions");
  mkdirSync(dir, { recursive: true });
  const f = join(dir, sessionId + ".hex");
  if (existsSync(f)) return hexToSk(readFileSync(f, "utf8").trim());
  const sk = generateSecretKey();
  writeFileSync(f, skToHex(sk), { mode: 0o600 });
  return sk;
}

// ── self-test: `node loadkey_v2.mjs --test` ──────────────────────────────────
if (process.argv.includes("--test")) {
  const { rmSync, statSync } = await import("node:fs");
  let pass = 0,
    fail = 0;
  const ok = (c, m) => (c ? (pass++, console.log("  ✅ " + m)) : (fail++, console.log("  ❌ " + m)));

  console.log("resolve — pin caches + keystore recovery (the churn fix):");
  const pin = "0101010101010101010101010101010101010101010101010101010101010101";
  const a = await resolveKey({ env: { BUZZ_NAME: "smoke_governed", BUZZ_IDENTITY_KEY: pin }, sessionId: "x" });
  ok(skToHex(a) === pin, "named + pin → uses pin (and caches to keystore)");
  const b = await resolveKey({ env: { BUZZ_NAME: "smoke_governed" }, sessionId: "x" });
  ok(skToHex(b) === pin, "named, pin lost → RECOVERED from keystore (no random)");
  const mode = statSync(identityFile("smoke_governed")).mode & 0o777;
  ok(mode === 0o600, `keystore file is 0600 — no Keychain argv leak (SEC-1)`);
  try { rmSync(identityFile("smoke_governed")); } catch {}

  console.log("resolve — fail-closed + casual (custody-clean, no client derive):");
  try {
    await resolveKey({ env: { BUZZ_NAME: "buzz_bossman_absent" } });
    ok(false, "named + nothing recoverable should THROW");
  } catch {
    ok(true, "named + nothing recoverable → fail-closed (never derives, never random)");
  }
  const c1 = await resolveKey({ env: {}, sessionId: "test-casual-1" });
  ok(c1?.length === 32 && getPublicKey(c1)?.length === 64, "unnamed casual → per-session key (unchanged)");

  console.log("Phase 2 — service-refresh self-fetch (URN grant, rotation, in-memory):");
  const knownSk = hexToSk("0202020202020202020202020202020202020202020202020202020202020202");
  const knownNsec = nip19.nsecEncode(knownSk);
  const NM = "svc_agent";
  try { rmSync(refreshFile(NM)); } catch {}
  try { rmSync(identityFile(NM)); } catch {}
  const jsonRes = (obj) => ({ ok: true, status: 200, json: async () => obj, text: async () => "" });
  let captured = null;
  // Mock Ekam: only the EXPECTED (unspent) refresh token is accepted; each
  // exchange rotates it. Mirrors prod single-use replay detection.
  const mkFetch = (expect, rotateTo) => async (url, init) => {
    if (url.endsWith("/oauth/token")) {
      captured = { ct: init.headers["Content-Type"], body: JSON.parse(init.body) };
      if (captured.body.refresh_token !== expect) return { ok: false, status: 401, text: async () => "replay: spent token" };
      return jsonRes({ access_token: "agent-tok", refresh_token: rotateTo, expires_in: 900, scope: "wire-keys:resolve" });
    }
    if (url.endsWith("/v1/me/wire-key")) return jsonRes({ nsec: knownNsec });
    return { ok: false, status: 404, text: async () => "no route" };
  };
  const env2 = { BUZZ_NAME: NM, BUZZ_SERVICE_REFRESH: "srt-A", BUZZ_EKAM_BASE: "https://ekam.test" };
  const sk = await resolveKey({ env: env2, fetch: mkFetch("srt-A", "srt-B") });
  ok(skToHex(sk) === skToHex(knownSk), "exchange → wire-key → decoded nsec (matches)");
  ok(captured.ct === "application/json" && captured.body.grant_type === SERVICE_REFRESH_GRANT && !("client_id" in captured.body), "exchange: URN grant, JSON body, NO client_id");
  ok(refreshGet(NM) === "srt-B", "rotated refresh token PERSISTED (single-use rotation)");
  ok(!existsSync(identityFile(NM)), "Phase-2 key NEVER written to keystore (in memory only)");
  // Next session: env still holds the spent "srt-A", but the shim must use the
  // PERSISTED "srt-B" (else replay → lockout).
  const sk2 = await resolveKey({ env: env2, fetch: mkFetch("srt-B", "srt-C") });
  ok(skToHex(sk2) === skToHex(knownSk) && refreshGet(NM) === "srt-C", "next session uses PERSISTED rotated token, not the env seed → rotates again");
  try { rmSync(refreshFile(NM)); } catch {}
  const failFetch = async () => ({ ok: false, status: 401, text: async () => "expired" });
  try {
    await resolveKey({ env: { BUZZ_NAME: "svc_agent2", BUZZ_SERVICE_REFRESH: "bad" }, fetch: failFetch });
    ok(false, "service-refresh exchange failure should THROW");
  } catch {
    ok(true, "service-refresh failure → fail-closed (no random/stale fallback)");
  }
  try { rmSync(refreshFile("svc_agent2")); } catch {}

  console.log(`\n${fail === 0 ? "ALL PASS" : "FAILURES"}: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}
