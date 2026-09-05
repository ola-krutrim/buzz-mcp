// signer.test.mjs — `node signer.test.mjs`
// Exercises the wire-sign seam against a MOCK Ekam signer (no network, no prod
// dependency). Integration against the LIVE endpoint is deferred until ekam ships
// 27235 (requirement C) and confirms the contract (requirement D).

import { resolveSigner, wireSign, WIRE_ALLOWLIST, wirePersistId, wireBleedVars, reactionTemplate, blossomAuthTemplate, BLOSSOM_MAX_TTL, parseImeta, messageAttachments, buildImeta, mediaCapCheck, MEDIA_MB } from "./signer.mjs";
import { finalizeEvent, getPublicKey, verifyEvent } from "nostr-tools/pure";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✅ " + m)) : (fail++, console.log("  ❌ " + m)));

// The escrowed "user" key lives ONLY in the mock server — the shim never sees it.
const USER_SK = Uint8Array.from(Buffer.from("0303030303030303030303030303030303030303030303030303030303030303", "hex"));
const USER_PK = getPublicKey(USER_SK);

// Mock Ekam /v1/me/wire-sign: verifies the bearer token, enforces the allowlist,
// SERVER-STAMPS created_at, signs with the escrowed user key, returns the event.
// `captured` records the last request so we can assert what the shim actually sent.
let captured = null;
const GOOD_TOKEN = "ekam_human_valid";   // wire:sign-scoped, aud=ISSUER
const NOSCOPE_TOKEN = "ekam_human_noscope";
// Mock Ekam per the CONFIRMED contract (ekam #319): request {event:{kind,tags,content}},
// response {event:<signed>, pubkey}, typed errors {error,error_description}.
const mockFetch = async (url, init) => {
  if (!url.endsWith("/v1/me/wire-sign")) return { ok: false, status: 404, text: async () => "no route" };
  const auth = init.headers.Authorization || "";
  const body = JSON.parse(init.body);
  const tmpl = body.event || {};        // confirmed {event:{...}} envelope
  captured = { auth, body, tmpl };
  if (auth === `Bearer ${NOSCOPE_TOKEN}`) return { ok: false, status: 403, text: async () => '{"error":"forbidden","error_description":"the token must carry the wire:sign scope"}' };
  if (auth !== `Bearer ${GOOD_TOKEN}`) return { ok: false, status: 401, text: async () => '{"error":"unauthorized","error_description":"token revoked"}' };
  if (!WIRE_ALLOWLIST.has(tmpl.kind)) return { ok: false, status: 400, text: async () => '{"error":"kind_not_allowed","error_description":"kind not signable"}' };
  // sign with the escrowed key; SERVER stamps created_at (shim did not send one)
  const ev = finalizeEvent({ kind: tmpl.kind, created_at: Math.floor(Date.now() / 1000), tags: tmpl.tags || [], content: tmpl.content ?? "" }, USER_SK);
  return { ok: true, status: 200, text: async () => JSON.stringify({ event: ev, pubkey: USER_PK }) };
};

// HERMETIC: pin a persistId (BUZZ_WIRE_ID) with NO on-disk wire-refresh/pubkey, so these
// tests never pick up a developer's real persisted creds under the default "wire" id.
// (BUZZ_WIRE_ID is the dedicated wire-mode id — decoupled from BUZZ_NAME/BUZZ_IDENTITY_NAME.)
const HERMETIC = "wtest_hermetic";
const wireEnv = { BUZZ_WIRE_SIGN: "1", BUZZ_WIRE_ID: HERMETIC, BUZZ_EKAM_HUMAN_TOKEN: GOOD_TOKEN, BUZZ_USER_PUBKEY: USER_PK, BUZZ_EKAM_BASE: "https://ekam.test" };

console.log("wire mode — signer resolves as the USER, no local key:");
const wsigner = await resolveSigner({ env: wireEnv, fetch: mockFetch });
ok(wsigner.mode === "wire", "BUZZ_WIRE_SIGN + token + pubkey → wire mode");
ok(wsigner.pubkey === USER_PK, "signer.pubkey is the USER's pubkey (from BUZZ_USER_PUBKEY)");

console.log("wire mode — the two kinds the shim actually signs:");
const authEv = await wsigner.sign({ kind: 27235, tags: [["u", "https://relay/x"], ["method", "POST"], ["payload", "abc"]], content: "" });
ok(verifyEvent(authEv) && authEv.kind === 27235 && authEv.pubkey === USER_PK, "27235 NIP-98 auth → valid sig, as the user");
ok(captured.body.event && captured.body.event.created_at === undefined, "request uses {event:{...}} envelope; NO created_at (server stamps — anti-backdating)");
ok(captured.body.event.pubkey === undefined && captured.body.event.id === undefined, "shim did NOT send pubkey/id (server fills from escrow)");
ok(authEv.created_at > 0, "returned event carries the SERVER-stamped created_at");
const postEv = await wsigner.sign({ kind: 9, tags: [["h", "chan"]], content: "hello as me" });
ok(verifyEvent(postEv) && postEv.kind === 9 && postEv.content === "hello as me", "kind:9 post → valid sig, content intact");

console.log("wire mode — client-side allowlist guard (skip calls the server would refuse):");
ok(wsigner.canSign(9) && wsigner.canSign(27235) && !wsigner.canSign(0) && !wsigner.canSign(10100), "canSign: {9,27235} yes; 0/10100 (profile) no");
captured = null;
try { await wsigner.sign({ kind: 0, tags: [], content: "{}" }); ok(false, "kind:0 should be refused BEFORE any network call"); }
catch (e) { ok(/allowlist/.test(e.message) && captured === null, "kind:0 refused client-side, no wire-sign call made"); }

console.log("wire mode — typed failures surface cleanly:");
const revokedSigner = await resolveSigner({ env: { ...wireEnv, BUZZ_EKAM_HUMAN_TOKEN: "revoked_tok" }, fetch: mockFetch });
try { await revokedSigner.sign({ kind: 9, tags: [], content: "x" }); ok(false, "revoked token should throw"); }
catch (e) { ok(/HTTP 401/.test(e.message) && /token revoked/.test(e.message), "revoked token → HTTP 401 + description surfaced (kill-switch works end-to-end)"); }
const noscopeSigner = await resolveSigner({ env: { ...wireEnv, BUZZ_EKAM_HUMAN_TOKEN: NOSCOPE_TOKEN }, fetch: mockFetch });
try { await noscopeSigner.sign({ kind: 9, tags: [], content: "x" }); ok(false, "no-scope token should throw"); }
catch (e) { ok(/HTTP 403/.test(e.message) && /wire:sign scope/.test(e.message), "token without wire:sign scope → HTTP 403 + WHO-gate hint (#319)"); }

console.log("wire mode — contract-mismatch fails LOUD (never passes an unsigned event):");
const badShapeFetch = async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ kind: 9, tags: [], content: "x" /* no id/sig/pubkey */ }) });
const badSigner = await resolveSigner({ env: wireEnv, fetch: badShapeFetch });
try { await badSigner.sign({ kind: 9, tags: [], content: "x" }); ok(false, "missing id/sig/pubkey should throw"); }
catch (e) { ok(/contract mismatch/.test(e.message), "response missing id/sig/pubkey → LOUD contract-mismatch error"); }

console.log("wire mode — fail-closed config guards:");
try { await resolveSigner({ env: { BUZZ_WIRE_SIGN: "1", BUZZ_WIRE_ID: HERMETIC, BUZZ_USER_PUBKEY: USER_PK }, fetch: mockFetch }); ok(false, "missing token should throw"); }
catch (e) { ok(/BUZZ_EKAM_HUMAN_TOKEN/.test(e.message), "wire mode without human token → fail-closed"); }
try { await resolveSigner({ env: { BUZZ_WIRE_SIGN: "1", BUZZ_WIRE_ID: HERMETIC, BUZZ_EKAM_HUMAN_TOKEN: GOOD_TOKEN }, fetch: mockFetch }); ok(false, "missing pubkey should throw"); }
catch (e) { ok(/BUZZ_USER_PUBKEY/.test(e.message), "wire mode without user pubkey → fail-closed"); }
try { await resolveSigner({ env: { BUZZ_WIRE_SIGN: "1", BUZZ_WIRE_ID: HERMETIC, BUZZ_USER_PUBKEY: USER_PK }, fetch: mockFetch }); ok(false, "no credential should throw"); }
catch (e) { ok(/BUZZ_WIRE_REFRESH/.test(e.message) && /BUZZ_EKAM_HUMAN_TOKEN/.test(e.message), "wire mode with neither refresh nor static token → fail-closed"); }

const { rmSync, readFileSync: rf, mkdirSync: mkd, writeFileSync: wf } = await import("node:fs");
const { join: pjoin } = await import("node:path");
const { homedir: hd } = await import("node:os");
const wireTok = (id) => pjoin(hd(), ".config/buzz-cli/wire-refresh", id + ".tok");

console.log("wire mode — autonomous refresh-rotation (Phase-2 seam):");
try { rmSync(wireTok("wiretest")); } catch {}
let oauthCalls = 0, lastGrant = null;
const refreshMock = async (url, init) => {
  if (url.endsWith("/oauth/token")) {
    oauthCalls++; lastGrant = JSON.parse(init.body);
    const rot = { "seed-refresh": "rot-1", "rot-1": "rot-2" }[lastGrant.refresh_token];
    if (rot) return { ok: true, status: 200, text: async () => JSON.stringify({ access_token: GOOD_TOKEN, refresh_token: rot, expires_in: 900 }) };
    return { ok: false, status: 400, text: async () => '{"error":"invalid_grant","error_description":"spent"}' };
  }
  return mockFetch(url, init);
};
const rEnv = { BUZZ_WIRE_SIGN: "1", BUZZ_USER_PUBKEY: USER_PK, BUZZ_EKAM_BASE: "https://ekam.test", BUZZ_WIRE_REFRESH: "seed-refresh", BUZZ_EKAM_CLIENT_ID: "shim-client", BUZZ_WIRE_ID: "wiretest" };
const rSigner = await resolveSigner({ env: rEnv, fetch: refreshMock });
ok(rSigner.mode === "wire", "refresh env (no static token) → wire mode");
const rev = await rSigner.sign({ kind: 9, tags: [], content: "via refresh" });
ok(verifyEvent(rev) && rev.pubkey === USER_PK, "refresh-minted token signs kind:9 as the user");
ok(oauthCalls === 1 && lastGrant.grant_type === "refresh_token" && lastGrant.client_id === "shim-client" && lastGrant.refresh_token === "seed-refresh" && !("resource" in lastGrant) && !("scope" in lastGrant), "mint: minimal body {grant_type, refresh_token, client_id} — no scope/resource (endpoint rejects extra keys; pinned from original grant)");
ok(rf(wireTok("wiretest"), "utf8").trim() === "rot-1", "rotated refresh persisted 0600 (single-use rotation)");
await rSigner.sign({ kind: 9, tags: [], content: "again" });
ok(oauthCalls === 1, "valid access token reused within TTL — no needless re-mint");
try { rmSync(wireTok("wiretest")); } catch {}

console.log("wire mode — 401 mid-life → forced re-mint + retry:");
try { rmSync(wireTok("wt2")); } catch {}
let ws = 0, oauth2 = 0;
const expireMock = async (url, init) => {
  if (url.endsWith("/oauth/token")) { oauth2++; return { ok: true, status: 200, text: async () => JSON.stringify({ access_token: GOOD_TOKEN, refresh_token: "rot-x", expires_in: 900 }) }; }
  if (url.endsWith("/v1/me/wire-sign")) { ws++; if (ws === 2) return { ok: false, status: 401, text: async () => '{"error":"unauthorized","error_description":"expired mid-life"}' }; return mockFetch(url, init); }
  return { ok: false, status: 404, text: async () => "x" };
};
const eSigner = await resolveSigner({ env: { BUZZ_WIRE_SIGN: "1", BUZZ_USER_PUBKEY: USER_PK, BUZZ_EKAM_BASE: "https://ekam.test", BUZZ_WIRE_REFRESH: "seed-refresh", BUZZ_EKAM_CLIENT_ID: "c", BUZZ_WIRE_ID: "wt2" }, fetch: expireMock });
await eSigner.sign({ kind: 9, tags: [], content: "first ok" });
const before = oauth2;
const eev = await eSigner.sign({ kind: 9, tags: [], content: "second hits 401" });
ok(verifyEvent(eev) && oauth2 === before + 1 && ws === 3, "wire-sign 401 → one forced re-mint + retry → succeeds");
try { rmSync(wireTok("wt2")); } catch {}

console.log("wire mode — mint failure surfaces (refresh spent/revoked = kill-switch):");
try { rmSync(wireTok("wt3")); } catch {}
const deadMock = async (url) => { if (url.endsWith("/oauth/token")) return { ok: false, status: 400, text: async () => '{"error":"invalid_grant","error_description":"refresh spent"}' }; return { ok: false, status: 404, text: async () => "x" }; };
const dSigner = await resolveSigner({ env: { BUZZ_WIRE_SIGN: "1", BUZZ_USER_PUBKEY: USER_PK, BUZZ_EKAM_BASE: "https://ekam.test", BUZZ_WIRE_REFRESH: "dead", BUZZ_EKAM_CLIENT_ID: "c", BUZZ_WIRE_ID: "wt3" }, fetch: deadMock });
try { await dSigner.sign({ kind: 9, tags: [], content: "x" }); ok(false, "spent refresh should throw"); }
catch (e) { ok(/token mint -> HTTP 400/.test(e.message) && /refresh spent/.test(e.message), "spent/revoked refresh → mint failure surfaced (kill-switch; re-run one-time login)"); }
try { rmSync(wireTok("wt3")); } catch {}

console.log("wire mode — refresh precedence: persisted rotated token beats env seed (replay-safe):");
try { rmSync(wireTok("wt4")); } catch {}
mkd(pjoin(hd(), ".config/buzz-cli/wire-refresh"), { recursive: true });
wf(wireTok("wt4"), "persisted-rot", { mode: 0o600 });
let seenRefresh = null;
const precMock = async (url, init) => { if (url.endsWith("/oauth/token")) { seenRefresh = JSON.parse(init.body).refresh_token; return { ok: true, status: 200, text: async () => JSON.stringify({ access_token: GOOD_TOKEN, refresh_token: "next", expires_in: 900 }) }; } return mockFetch(url, init); };
const pSigner = await resolveSigner({ env: { BUZZ_WIRE_SIGN: "1", BUZZ_USER_PUBKEY: USER_PK, BUZZ_EKAM_BASE: "https://ekam.test", BUZZ_WIRE_REFRESH: "env-seed-spent", BUZZ_EKAM_CLIENT_ID: "c", BUZZ_WIRE_ID: "wt4" }, fetch: precMock });
await pSigner.sign({ kind: 9, tags: [], content: "x" });
ok(seenRefresh === "persisted-rot", "persisted rotated refresh used over env seed (replay-safe)");
try { rmSync(wireTok("wt4")); } catch {}

console.log("wire mode — pubkey auto-captured at login is used (no BUZZ_USER_PUBKEY needed):");
const pubFile = pjoin(hd(), ".config/buzz-cli/wire-refresh", "pubcap.pub");
try { rmSync(pubFile); } catch {}
mkd(pjoin(hd(), ".config/buzz-cli/wire-refresh"), { recursive: true });
wf(pubFile, USER_PK, { mode: 0o600 });
const capSigner = await resolveSigner({ env: { BUZZ_WIRE_SIGN: "1", BUZZ_EKAM_HUMAN_TOKEN: GOOD_TOKEN, BUZZ_WIRE_ID: "pubcap", BUZZ_EKAM_BASE: "https://ekam.test" }, fetch: mockFetch });
ok(capSigner.mode === "wire" && capSigner.pubkey === USER_PK, "persisted .pub (login-captured) used as identity when BUZZ_USER_PUBKEY is unset");
try { rmSync(pubFile); } catch {}

console.log("local mode — existing behavior intact (regression):");
const pin = "0101010101010101010101010101010101010101010101010101010101010101";
const lsigner = await resolveSigner({ env: { BUZZ_NAME: "reg_agent", BUZZ_PRIVATE_KEY: pin }, sessionId: "t" });
ok(lsigner.mode === "local", "no BUZZ_WIRE_SIGN → local mode (default)");
ok(lsigner.pubkey === getPublicKey(Uint8Array.from(Buffer.from(pin, "hex"))), "local pubkey derives from the pinned key");
const lev = await lsigner.sign({ kind: 9, tags: [["h", "c"]], content: "local post" });
ok(verifyEvent(lev) && lev.kind === 9 && lev.created_at > 0, "local sign → valid finalizeEvent, created_at stamped locally");
ok(lsigner.canSign(0) && lsigner.canSign(10100), "local canSign: all kinds (profile publish still works)");
try { const { rmSync } = await import("node:fs"); const { join } = await import("node:path"); const { homedir } = await import("node:os"); rmSync(join(homedir(), ".config/buzz-cli/identities/reg_agent.hex")); } catch {}

console.log("wire persistId — decoupled from agent-mode BUZZ_NAME (releng footgun fix):");
ok(wirePersistId({}) === "wire", "no env → id 'wire' (default)");
ok(wirePersistId({ BUZZ_NAME: "buzz_beekeeper" }) === "wire", "BUZZ_NAME set → still 'wire' (agent name does NOT change wire id)");
ok(wirePersistId({ BUZZ_IDENTITY_NAME: "buzz_beekeeper" }) === "wire", "BUZZ_IDENTITY_NAME set → still 'wire' (ignored for wire mode)");
ok(wirePersistId({ BUZZ_WIRE_ID: "alt" }) === "alt", "BUZZ_WIRE_ID → explicit override honored");
ok(wirePersistId({ BUZZ_WIRE_ID: "alt", BUZZ_NAME: "agent" }) === "alt", "BUZZ_WIRE_ID wins over BUZZ_NAME");
// The core guarantee: login shell (no BUZZ_NAME) and MCP runtime (BUZZ_NAME=agent) agree.
ok(wirePersistId({}) === wirePersistId({ BUZZ_NAME: "some_agent" }), "login-shell id === runtime id even when runtime inherits BUZZ_NAME (footgun closed)");
ok(wireBleedVars({ BUZZ_NAME: "a" }).includes("BUZZ_NAME") && wireBleedVars({}).length === 0, "wireBleedVars flags agent-mode vars for the login warning");

console.log("reactions — kind 7 in allowlist + reactionTemplate enforces the target e-tag (ekam #325/v203):");
ok(WIRE_ALLOWLIST.has(7), "kind 7 is in the wire-sign allowlist");
ok(wsigner.canSign(7), "wire signer canSign(7) → reactions signable as the user");
{
  const AUTHOR = "b".repeat(64);
  const t = reactionTemplate({ targetId: "evt123", targetAuthor: AUTHOR, targetKind: 9, channelId: "chan-1", emoji: "🎉" });
  const tagMap = Object.fromEntries(t.tags.map((x) => [x[0], x[1]]));
  ok(t.kind === 7 && t.content === "🎉", "reactionTemplate → kind 7, content = emoji");
  ok(tagMap.e === "evt123" && tagMap.k === "9" && tagMap.h === "chan-1" && tagMap.p === AUTHOR, "tags: e(target) + k(kind) + h(channel) + p(author)");
  ok(reactionTemplate({ targetId: "x", channelId: "c" }).content === "+", "default content is '+' when no emoji");
  ok(!reactionTemplate({ targetId: "x", targetAuthor: "not-hex", channelId: "c" }).tags.some((x) => x[0] === "p"), "no p-tag when author isn't a valid pubkey");
}
try { reactionTemplate({ targetId: "", channelId: "c" }); ok(false, "empty target should throw"); }
catch (e) { ok(/target-less|`e` tag|concrete target/i.test(e.message), "REFUSES a target-less reaction (the ekam/security e-tag condition)"); }
try { reactionTemplate({ targetId: "evt", channelId: "" }); ok(false, "missing channel should throw"); }
catch (e) { ok(/channel/i.test(e.message), "refuses a reaction with no channel to route to (h-tag)"); }

console.log("blossom media auth (kind 24242) — fail-closed shim constraints (codex_kavach gate):");
{
  const SHA = "a".repeat(64);
  const up = blossomAuthTemplate({ verb: "upload", sha256: SHA });
  const tm = Object.fromEntries(up.tags.map((x) => [x[0], x[1]]));
  ok(up.kind === 24242 && up.content === "Upload buzz-media", "upload → kind 24242, fixed non-empty content (BUD-11 requires it; relay rejects empty)");
  ok(blossomAuthTemplate({ verb: "get", sha256: SHA }).content === "Get buzz-media" && blossomAuthTemplate({ verb: "get" }).content.length > 0, "get → fixed non-empty content too");
  ok(tm.t === "upload" && tm.x === SHA, "upload → t=upload + x=<file sha256>");
  ok(Number(tm.expiration) > Math.floor(Date.now() / 1000), "upload → expiration in the future");
  ok(Number(tm.expiration) <= Math.floor(Date.now() / 1000) + BLOSSOM_MAX_TTL + 1, "upload → expiration ≤ 5 min TTL");
  const g = blossomAuthTemplate({ verb: "get" });
  ok(g.kind === 24242 && g.tags.some((t) => t[0] === "t" && t[1] === "get") && !g.tags.some((t) => t[0] === "x"), "get (no target) → t=get, no x");
  ok(blossomAuthTemplate({ verb: "get", sha256: SHA }).tags.some((t) => t[0] === "x" && t[1] === SHA), "get (target-bound) → x=<sha>");
}
try { blossomAuthTemplate({ verb: "delete", sha256: "a".repeat(64) }); ok(false, "bad verb should throw"); }
catch (e) { ok(/verb must be/.test(e.message), "REFUSES verb ∉ {upload,get}"); }
try { blossomAuthTemplate({ verb: "upload" }); ok(false, "upload w/o hash should throw"); }
catch (e) { ok(/64-hex sha256/.test(e.message), "REFUSES upload with no file hash (BUD-11 binding)"); }
try { blossomAuthTemplate({ verb: "upload", sha256: "nothex" }); ok(false, "upload bad hash should throw"); }
catch (e) { ok(/64-hex sha256/.test(e.message), "REFUSES upload with a non-64-hex hash"); }
try { blossomAuthTemplate({ verb: "upload", sha256: "a".repeat(64), ttlSeconds: 3600 }); ok(false, "long TTL should throw"); }
catch (e) { ok(/TTL must be/.test(e.message), `REFUSES expiration TTL > ${BLOSSOM_MAX_TTL}s`); }
try { blossomAuthTemplate({ verb: "upload", sha256: "a".repeat(64), ttlSeconds: 0 }); ok(false, "zero TTL should throw"); }
catch (e) { ok(/TTL must be/.test(e.message), "REFUSES non-positive TTL"); }

console.log("imeta media descriptor — parse/build (real Buzz wire shapes):");
{
  const SHA = "96eaafd504beb4fd17e40a2cb6dfccd36348d43f01f90fb80ad1a5cf321858a9";
  const img = ["imeta", `url https://ola.buzz.ola.in/media/${SHA}.png`, "m image/png", `x ${SHA}`, "size 985795", "dim 3526x2200", "blurhash L04.JG"];
  const p = parseImeta(img);
  ok(p.url.endsWith(`${SHA}.png`) && p.mime === "image/png" && p.sha256 === SHA && p.size === 985795 && p.dim === "3526x2200", "parse image imeta → url/mime/x/size/dim");
  const DSHA = "cfa37dcac3565d17b48ff8f89195a30fab6e37c5b0b91c55e81b00f621c704b7";
  const doc = ["imeta", `url https://ola.buzz.ola.in/media/${DSHA}.bin`, "m application/octet-stream", `x ${DSHA}`, "size 25055", "filename handover_ev_crm_leave.md"];
  const pd = parseImeta(doc);
  ok(pd.filename === "handover_ev_crm_leave.md" && pd.mime === "application/octet-stream" && pd.size === 25055, "parse doc imeta → filename/mime/size");
  ok(parseImeta(["p", "abc"]) === null && parseImeta(["imeta", "m image/png"]) === null, "parse → null for non-imeta or url-less");
  const ev = { tags: [["h", "chan"], img, ["p", "x"], doc] };
  ok(messageAttachments(ev).length === 2, "messageAttachments → all imeta on a message");
  // round-trip build → parse
  const built = buildImeta({ url: `https://ola.buzz.ola.in/media/${DSHA}.bin`, mime: "application/octet-stream", sha256: DSHA, size: 25055, filename: "x.md" });
  const rt = parseImeta(built);
  ok(built[0] === "imeta" && rt.sha256 === DSHA && rt.filename === "x.md" && rt.size === 25055, "build→parse round-trips");
}
try { buildImeta({ url: "https://x/y", sha256: "nothex" }); ok(false, "build w/o valid sha should throw"); }
catch (e) { ok(/64-hex sha256/.test(e.message), "buildImeta REFUSES a non-64-hex sha (hash-binding)"); }
try { buildImeta({ sha256: "a".repeat(64) }); ok(false, "build w/o url should throw"); }
catch (e) { ok(/url is required/.test(e.message), "buildImeta REFUSES a url-less descriptor"); }

console.log("media size caps — per-type pre-flight, distinguishable local refusal (codex gate):");
{
  const okImg = mediaCapCheck("pic.png", 40 * MEDIA_MB);
  ok(okImg.mime === "image/png" && okImg.kind === "image" && okImg.cap === 50 * MEDIA_MB, "image under 50 MB → ok, kind=image");
  ok(mediaCapCheck("doc.pdf", 90 * MEDIA_MB).kind === "file" && mediaCapCheck("clip.mp4", 400 * MEDIA_MB).kind === "video", "per-type: pdf=file(100), mp4=video(500) — under cap ok");
  ok(mediaCapCheck("a.gif", 9 * MEDIA_MB).kind === "gif", "gif under 10 MB → ok");
}
try { mediaCapCheck("pic.png", 60 * MEDIA_MB); ok(false, "51MB image should throw"); }
catch (e) { ok(/declined LOCALLY/.test(e.message) && /NOT a server 413/.test(e.message) && /image cap/.test(e.message), "image >50 MB → DISTINGUISHABLE local refusal (not a 413)"); }
try { mediaCapCheck("a.gif", 11 * MEDIA_MB); ok(false, "11MB gif should throw"); }
catch (e) { ok(/gif cap/.test(e.message), "gif >10 MB → refused (tightest per-type cap)"); }
try { mediaCapCheck("big.bin", 101 * MEDIA_MB); ok(false, "101MB file should throw"); }
catch (e) { ok(/file cap/.test(e.message), "generic file >100 MB → refused"); }

console.log(`\n${fail === 0 ? "ALL PASS" : "FAILURES"}: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
