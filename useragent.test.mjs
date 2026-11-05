// useragent.test.mjs — every shim → Ekam HTTP call carries an explicit, identifier-free User-Agent
//   buzz-mcp/<version> (node/<process.versions.node>; <process.platform>)          (stdio shim)
//   buzz-mcp/<version> hosted (node/<process.versions.node>; <process.platform>)   (--http hosted)
// so Ekam logs can tell shim versions apart instead of seeing node's bare default.
// Fully offline; HOME is a throwaway dir set BEFORE signer.mjs is imported.
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir, hostname, userInfo } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";

const HOME = mkdtempSync(join(tmpdir(), "buzz-ua-test-"));
process.env.HOME = HOME; process.env.USERPROFILE = HOME;
const { SHIM_VERSION, shimUserAgent } = await import("./clientversion.mjs");
const { makeWireTokenProvider, wireRefreshSet, wireSign, probeWirePubkey, makeHostedWireSigner } = await import("./signer.mjs");
const { exchangeAuthCode } = await import("./wirelogin.mjs");
const { hostedConfig, createTokenExchanger } = await import("./hosted-auth.mjs");

let passed = 0, failed = 0;
const ok = (c, m) => { if (c) { passed++; console.log("  ✅ " + m); } else { failed++; console.log("  ❌ " + m); } };
const PKG = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8"));
const UA = `buzz-mcp/${PKG.version} (node/${process.versions.node}; ${process.platform})`;
const UA_HOSTED = `buzz-mcp/${PKG.version} hosted (node/${process.versions.node}; ${process.platform})`;
const uaOf = (init) => { const h = (init && init.headers) || {}; return h["User-Agent"] ?? h["user-agent"]; };
const res = (status, body) => ({ ok: status >= 200 && status < 300, status, headers: { get: () => null }, text: async () => JSON.stringify(body), json: async () => body });

console.log("useragent.test.mjs — explicit User-Agent on Ekam calls\n");

console.log("case 1: format, version source, no identifiers");
{
  ok(SHIM_VERSION === PKG.version, `clientversion SHIM_VERSION (${SHIM_VERSION}) === package.json version (${PKG.version})`);
  ok(shimUserAgent() === UA, `stdio UA === '${UA}'`);
  ok(shimUserAgent({ hosted: true }) === UA_HOSTED, `hosted UA === '${UA_HOSTED}'`);
  ok(/^buzz-mcp\/\d+\.\d+\.\d+( hosted)? \(node\/[0-9.]+; [a-z0-9]+\)$/.test(shimUserAgent()) && /^buzz-mcp\/\d+\.\d+\.\d+ hosted \(/.test(shimUserAgent({ hosted: true })), "matches buzz-mcp/<ver>[ hosted] (node/<ver>; <platform>)");
  const ids = [hostname(), (() => { try { return userInfo().username; } catch { return ""; } })(), HOME].filter((s) => s && s.length >= 3);
  ok(ids.every((s) => !shimUserAgent().includes(s) && !shimUserAgent({ hosted: true }).includes(s)), "UA carries no hostname, username or home path");
  const bmSrc = readFileSync(new URL("./buzz-mcp.mjs", import.meta.url), "utf8");
  ok(/export const SHIM_VERSION_EXPORT = SHIM_VERSION_SRC;/.test(bmSrc) && !/SHIM_VERSION_EXPORT = "\d/.test(bmSrc), "buzz-mcp.mjs takes its version from clientversion.mjs (one source, not a second literal)");
}

console.log("\ncase 2: refresh / mint (signer.mjs makeWireTokenProvider) sends the UA");
{
  const seen = [];
  const fetchFn = async (u, init) => { seen.push({ u, ua: uaOf(init) }); return res(200, { access_token: "acc-ua", refresh_token: "rt-ua-2", expires_in: 900 }); };
  wireRefreshSet("ua1", "rt-ua-1");
  const p = makeWireTokenProvider({ BUZZ_EKAM_BASE: "https://ekam.test", BUZZ_EKAM_CLIENT_ID: "cid", BUZZ_WIRE_ID: "ua1" }, fetchFn, { log: () => {} });
  const a = await p.get(); p.stopKeepAlive();
  ok(a === "acc-ua" && seen.length === 1 && seen[0].u === "https://ekam.test/oauth/token", "one refresh POST to /oauth/token");
  ok(seen[0].ua === UA, `refresh UA === '${UA}' (got '${seen[0].ua}')`);
  ok(String(seen[0].ua).includes(`buzz-mcp/${PKG.version}`), "refresh UA contains the shim version");
}

console.log("\ncase 3: refresh over a real socket — Ekam sees the UA, not bare 'node'");
{
  let got = null;
  const srv = createServer((req, r) => { got = req.headers["user-agent"]; req.resume(); req.on("end", () => { r.writeHead(200, { "content-type": "application/json" }); r.end(JSON.stringify({ access_token: "acc-w", refresh_token: "rt-w-2", expires_in: 900 })); }); });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  wireRefreshSet("ua2", "rt-w-1");
  const p = makeWireTokenProvider({ BUZZ_EKAM_BASE: `http://127.0.0.1:${srv.address().port}`, BUZZ_EKAM_CLIENT_ID: "cid", BUZZ_WIRE_ID: "ua2" }, fetch, { log: () => {} });
  await p.get(); p.stopKeepAlive(); srv.close();
  ok(got === UA, `server-side user-agent === '${UA}' (got '${got}')`);
}

console.log("\ncase 4: one-time login code exchange (wirelogin.mjs exchangeAuthCode) sends the UA");
{
  let cap = null;
  const fetchFn = async (u, init) => { cap = { u, ua: uaOf(init), ct: init.headers["Content-Type"] }; return res(200, { access_token: "at", refresh_token: "rt_1", expires_in: 900 }); };
  await exchangeAuthCode("https://ekam.test", { code: "c0de", verifier: "v", clientId: "clt_x", redirectUri: "http://127.0.0.1:8765/callback" }, fetchFn);
  ok(cap.u === "https://ekam.test/oauth/token" && cap.ct === "application/json", "authcode POST to /oauth/token, Content-Type kept");
  ok(cap.ua === UA, `login exchange UA === '${UA}' (got '${cap.ua}')`);
  ok(String(cap.ua).includes(`buzz-mcp/${PKG.version}`), "login exchange UA contains the shim version");
}

console.log("\ncase 5: wire-sign — stdio UA by default, hosted UA from the hosted signer / probe");
{
  const PK = "a".repeat(64);
  const seen = [];
  const fetchFn = async (u, init) => { seen.push(uaOf(init)); return res(200, { id: "1".repeat(64), pubkey: PK, sig: "2".repeat(128), kind: 1, tags: [], content: "x", created_at: 1 }); };
  try { await wireSign("https://ekam.test", "tok", { kind: 1, tags: [], content: "x" }, fetchFn); } catch { /* validation of the fake event is not under test */ }
  ok(seen[0] === UA, "wireSign (stdio) → stdio UA");
  try { await probeWirePubkey("https://ekam.test", "tok", fetchFn); } catch { /* ditto */ }
  ok(seen[1] === UA_HOSTED, "probeWirePubkey (hosted only) → hosted UA");
  const hs = makeHostedWireSigner({ pubkey: PK, getToken: async () => "tok", base: "https://ekam.test", fetch: fetchFn });
  try { await hs.sign({ kind: 9, tags: [], content: "x" }); } catch { /* ditto */ }
  ok(seen[2] === UA_HOSTED, "hosted wire signer → hosted UA");
}

console.log("\ncase 6: hosted token exchange (+ AS metadata) sends the hosted UA");
{
  const seen = [];
  const fetchFn = async (u, init) => {
    seen.push({ u, ua: uaOf(init) });
    if (u.endsWith("/.well-known/oauth-authorization-server")) return res(200, { issuer: "https://ekam.test", token_endpoint: "https://ekam.test/oauth/token" });
    return res(200, { access_token: "wire-tok", token_type: "Bearer", expires_in: 900, issued_token_type: "urn:ietf:params:oauth:token-type:access_token" });
  };
  const cfg = hostedConfig({ BUZZ_HOSTED_RESOURCE: "https://mcp.buzz.ola.in", BUZZ_EKAM_BASE: "https://ekam.test", BUZZ_HOSTED_CLIENT_ID: "test-client", BUZZ_HOSTED_CLIENT_SECRET: "s3cret-for-test" });
  const ex = createTokenExchanger(cfg, { fetch: fetchFn });
  let t = null; try { t = await ex.get({ sub: "u1" }, "subject-tok"); } catch (e) { console.log("    (exchange threw: " + e.message + ")"); }
  const tokCall = seen.find((s) => s.u.endsWith("/oauth/token"));
  ok(!!tokCall, "hosted exchange POSTed the token endpoint");
  ok(tokCall && tokCall.ua === UA_HOSTED, `hosted exchange UA === '${UA_HOSTED}' (got '${tokCall && tokCall.ua}')`);
  ok(seen.every((s) => s.ua === UA_HOSTED), "every hosted Ekam call (metadata + exchange) carries the hosted UA");
  ok(seen.every((s) => !String(s.ua).includes("s3cret") && !String(s.ua).includes("test-client")), "hosted UA carries no client id or secret");
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
