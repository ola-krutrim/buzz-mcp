// loadkey.test.mjs — real tests for loadkey_v2.mjs (v0.2.30). Runs against an ISOLATED $HOME
// (mkdtemp) so it never reads or writes the developer's real ~/.config/buzz-cli keystore.
// loadkey_v2 resolves its config dir from os.homedir() at import time, so HOME is set first and
// the module is imported dynamically.
import { mkdtempSync, rmSync, statSync, existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const HOME = mkdtempSync(join(tmpdir(), "buzz-loadkey-home-"));
process.env.HOME = HOME;
const { homedir } = await import("node:os");
if (homedir() !== HOME) { console.log("✗ could not isolate HOME — refusing to run against the real keystore"); process.exit(1); }
const { resolveKey, selfFetchKey } = await import("./loadkey_v2.mjs");
const { getPublicKey } = await import("nostr-tools/pure");
const nip19 = await import("nostr-tools/nip19");

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.log("  ✗ " + m)));
const hex = (sk) => Buffer.from(sk).toString("hex");
const CFG = join(HOME, ".config", "buzz-cli");
const idFile = (n) => join(CFG, "identities", `${n}.hex`);
const rtFile = (n) => join(CFG, "service-refresh", `${n}.tok`);
const rejects = async (p) => { try { await p; return null; } catch (e) { return e; } };
const PIN = "01".repeat(32), PIN2 = "03".repeat(32);
const KNOWN = Uint8Array.from(Buffer.from("02".repeat(32), "hex"));
const jsonRes = (o) => ({ ok: true, status: 200, json: async () => o, text: async () => JSON.stringify(o) });
const mkEkam = (expect, rotateTo, { wk = { nsec: nip19.nsecEncode(KNOWN) }, log = [] } = {}) => async (url, init = {}) => {
  log.push({ url, init });
  if (url.endsWith("/oauth/token")) {
    const b = JSON.parse(init.body);
    if (b.refresh_token !== expect) return { ok: false, status: 401, text: async () => "replay: spent token" };
    return jsonRes({ access_token: "agent-tok", refresh_token: rotateTo });
  }
  if (url.endsWith("/v1/me/wire-key")) return wk === null ? { ok: false, status: 403, text: async () => "forbidden" } : jsonRes(wk);
  return { ok: false, status: 404, text: async () => "no route" };
};

try {
  console.log("\nPhase 1 — env pin + 0600 keystore");
  ok(hex(await resolveKey({ env: { BUZZ_NAME: "gov", BUZZ_IDENTITY_KEY: PIN } })) === PIN, "1. named + BUZZ_IDENTITY_KEY pin → that key");
  ok(existsSync(idFile("gov")) && (statSync(idFile("gov")).mode & 0o777) === 0o600 && readFileSync(idFile("gov"), "utf8") === PIN, "2. pin cached to the keystore as a 0600 file under the isolated HOME");
  ok(hex(await resolveKey({ env: { BUZZ_NAME: "gov" } })) === PIN, "3. pin lost → recovered from the keystore (no random churn)");
  ok(hex(await resolveKey({ env: { BUZZ_NAME: "gov2", BUZZ_PRIVATE_KEY: PIN2.toUpperCase() } })) === PIN2, "4. BUZZ_PRIVATE_KEY accepted (uppercase normalized)");
  ok(hex(await resolveKey({ env: { BUZZ_NAME: "gov3", BUZZ_IDENTITY_KEY: "zz", BUZZ_PRIVATE_KEY: PIN } })) === PIN, "5. malformed BUZZ_IDENTITY_KEY ignored → falls through to BUZZ_PRIVATE_KEY");
  ok(hex(await resolveKey({ env: { BUZZ_IDENTITY_NAME: "idn", BUZZ_NAME: "other", BUZZ_IDENTITY_KEY: PIN } })) === PIN && existsSync(idFile("idn")) && !existsSync(idFile("other")), "6. BUZZ_IDENTITY_NAME wins over BUZZ_NAME for the keystore account");
  ok(hex(await resolveKey({ env: { BUZZ_NAME: "../../evil", BUZZ_IDENTITY_KEY: PIN } })) === PIN && existsSync(idFile(".._.._evil")) && !existsSync(join(HOME, "evil.hex")), "7. account name is sanitized — no path traversal out of the keystore");
  mkdirSync(join(CFG, "identities"), { recursive: true }); writeFileSync(idFile("corrupt"), "not-hex");
  const eCorrupt = await rejects(resolveKey({ env: { BUZZ_NAME: "corrupt" } }));
  ok(eCorrupt && /Refusing to mint a random identity/.test(eCorrupt.message), "8. corrupt keystore entry → fail closed (not a random key)");
  const eAbsent = await rejects(resolveKey({ env: { BUZZ_NAME: "absent" } }));
  ok(eAbsent && /identity for "absent" is unavailable/.test(eAbsent.message), "9. named + nothing recoverable → fail closed");

  console.log("\ncasual sessions");
  const c1 = await resolveKey({ env: {}, sessionId: "cas1" });
  const c1b = await resolveKey({ env: {}, sessionId: "cas1" });
  const c2 = await resolveKey({ env: {}, sessionId: "cas2" });
  ok(c1.length === 32 && getPublicKey(c1).length === 64 && hex(c1) === hex(c1b) && hex(c1) !== hex(c2), "10. unnamed casual → stable per-session key, distinct across sessions");
  ok((statSync(join(CFG, "sessions", "cas1.hex")).mode & 0o777) === 0o600, "11. casual session key file is 0600");

  console.log("\nPhase 2 — service-refresh self-fetch");
  const log = [];
  const sk = await resolveKey({ env: { BUZZ_NAME: "svc", BUZZ_SERVICE_REFRESH: "srt-A", BUZZ_EKAM_BASE: "https://ekam.test/" }, fetch: mkEkam("srt-A", "srt-B", { log }) });
  const tokCall = log.find((l) => l.url.endsWith("/oauth/token"));
  const body = JSON.parse(tokCall.init.body);
  ok(hex(sk) === hex(KNOWN) && tokCall.url === "https://ekam.test/oauth/token" && body.grant_type === "urn:ekam:params:oauth:grant-type:service-refresh" && !("client_id" in body), "12. exchange (URN grant, no client_id, trailing-slash base trimmed) → decoded nsec");
  ok(log.find((l) => l.url.endsWith("/v1/me/wire-key")).init.headers.Authorization === "Bearer agent-tok", "13. wire-key fetched with the agent bearer");
  ok(readFileSync(rtFile("svc"), "utf8") === "srt-B" && (statSync(rtFile("svc")).mode & 0o777) === 0o600 && !existsSync(idFile("svc")), "14. rotated refresh persisted 0600; Phase-2 key NEVER written to the keystore");
  const sk2 = await resolveKey({ env: { BUZZ_NAME: "svc", BUZZ_SERVICE_REFRESH: "srt-A", BUZZ_EKAM_BASE: "https://ekam.test" }, fetch: mkEkam("srt-B", "srt-C") });
  ok(hex(sk2) === hex(KNOWN) && readFileSync(rtFile("svc"), "utf8") === "srt-C", "15. next session uses the PERSISTED rotated token, not the spent env seed");
  const e401 = await rejects(resolveKey({ env: { BUZZ_NAME: "svc2", BUZZ_SERVICE_REFRESH: "bad" }, fetch: mkEkam("good", "x") }));
  ok(e401 && /service-refresh exchange failed: HTTP 401/.test(e401.message), "16. exchange 401 → fail closed");
  const e403 = await rejects(resolveKey({ env: { BUZZ_NAME: "svc3", BUZZ_SERVICE_REFRESH: "t1" }, fetch: mkEkam("t1", "t2", { wk: null }) }));
  ok(e403 && /wire-key fetch failed: HTTP 403/.test(e403.message) && readFileSync(rtFile("svc3"), "utf8") === "t2", "17. wire-key 403 → fail closed, but the rotated refresh was persisted FIRST (no stranding on a spent token)");
  const eNpub = await rejects(resolveKey({ env: { BUZZ_NAME: "svc4", BUZZ_SERVICE_REFRESH: "t1" }, fetch: mkEkam("t1", "t2", { wk: { nsec: nip19.npubEncode("ab".repeat(32)) } }) }));
  ok(eNpub && /unexpected wire-key type: npub/.test(eNpub.message), "18. wire-key that is an npub (not nsec) → refused");
  const eEmpty = await rejects(resolveKey({ env: { BUZZ_NAME: "svc5", BUZZ_SERVICE_REFRESH: "t1" }, fetch: mkEkam("t1", "t2", { wk: {} }) }));
  ok(eEmpty && /no nsec/.test(eEmpty.message), "19. wire-key response without an nsec → refused");
  ok(await selfFetchKey({ BUZZ_NAME: "nobody" }, async () => { throw new Error("must not fetch"); }) === null, "20. selfFetchKey with no refresh → null, no network call");
  ok(hex(await resolveKey({ env: { BUZZ_NAME: "svc6", BUZZ_PRIVATE_KEY: PIN, BUZZ_SERVICE_REFRESH: "t1" }, fetch: async () => { throw new Error("must not fetch"); } })) === PIN, "21. an explicit pin takes precedence over the service-refresh (no exchange)");
  ok(!readdirSync(HOME).some((f) => f !== ".config"), "22. nothing written outside $HOME/.config/buzz-cli");
} finally {
  rmSync(HOME, { recursive: true, force: true });
}
console.log(`\nloadkey.test.mjs: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
