// hosted.test.mjs — v0.2.35 hosted HTTP mode ("Ola Buzz" connector). Fully offline: a mocked Ekam
// (AS metadata, JWKS, introspection, RFC 8693 token exchange, /v1/me/wire-sign signing with per-user
// test keys) and a mocked relay that authenticates every request by its NIP-98 pubkey.
process.env.BUZZ_MCP_AS_LIBRARY = "1";
import { createServer } from "node:http";
import { generateKeyPairSync, sign as cSign, randomBytes, createHash } from "node:crypto";
import { mkdtempSync, readFileSync, existsSync, statSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
const HERE = dirname(fileURLToPath(import.meta.url));
import { getPublicKey, finalizeEvent, verifyEvent } from "nostr-tools/pure";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { startHttpServer, redact, coreEnv } from "./http-server.mjs";
import { hostedConfig, createTokenValidator, createTokenExchanger, createEncryptedTokenStore, protectedResourceMetadata } from "./hosted-auth.mjs";
import { makeHostedWireSigner, BUZZ_APP_SIGNIN_MESSAGE } from "./signer.mjs";

// dynamic import AFTER setting BUZZ_MCP_AS_LIBRARY (static imports are hoisted and would start a stdio shim)
const { createBuzzServer } = await import("./buzz-mcp.mjs");

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log("  ✅ " + m); } else { fail++; console.log("  ❌ " + m); } };
const listenAny = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
const readAll = (rq) => new Promise((r) => { let b = ""; rq.on("data", (c) => (b += c)); rq.on("end", () => r(b)); });
const nowS = () => Math.floor(Date.now() / 1000);
const RESOURCE = "https://mcp.buzz.test";

// ---- people ----
const USERS = {
  alice: { sk: Uint8Array.from(randomBytes(32)), name: "Alice A", chan: "chanA" },
  bob: { sk: Uint8Array.from(randomBytes(32)), name: "Bob B", chan: "chanB" },
  carol: { sk: Uint8Array.from(randomBytes(32)), name: "Carol C", chan: "chanC", unprovisioned: true },
  dave: { sk: Uint8Array.from(randomBytes(32)), name: "Dave D", chan: "chanD", echo: true },        // Ekam echoes tokens in errors
  erin: { sk: Uint8Array.from(randomBytes(32)), name: "Erin E", chan: "chanE", exchangeEcho: true }, // exchange error echoes subject_token
};
for (const u of Object.values(USERS)) u.pk = getPublicKey(u.sk);
const byPk = Object.fromEntries(Object.entries(USERS).map(([k, u]) => [u.pk, k]));

// ---- mocked Ekam ----
const { privateKey: RSA, publicKey: RSAPUB } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const { privateKey: ROGUE } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...RSAPUB.export({ format: "jwk" }), kid: "k1", alg: "RS256", use: "sig" };
const minted = new Set();
const leaks = [];      // any client (MCP) access token seen where it must never go
const stats = { exchanges: 0, introspections: 0, exchangeBodies: [], wireSign: 0 };
let ISS;
function mint(sub, over = {}, key = RSA, header = {}) {
  const h = Buffer.from(JSON.stringify({ alg: "RS256", kid: "k1", typ: "at+jwt", ...header })).toString("base64url");
  const claims = { iss: ISS, aud: RESOURCE, sub, exp: nowS() + 600, iat: nowS(), name: USERS[sub]?.name, scope: "openid profile", ...over };
  const p = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const s = cSign("sha256", Buffer.from(`${h}.${p}`), key).toString("base64url");
  const t = `${h}.${p}.${s}`; minted.add(t); return t;
}
const opaque = new Map(); // introspection-mode opaque tokens → claims
const wireTok = new Map(); // issued wire:sign tokens → sub
const refreshOf = new Map(); // wire:sign token → refresh_token issued alongside it (must be dropped)
const daveSeen = new Set();
const ekam = createServer(async (rq, rs) => {
  const body = await readAll(rq);
  const reply = (st, o) => { rs.writeHead(st, { "Content-Type": "application/json" }); rs.end(JSON.stringify(o)); };
  const url = rq.url;
  if (url === "/.well-known/oauth-authorization-server") return reply(200, { issuer: ISS, token_endpoint: `${ISS}/oauth/token`, jwks_uri: `${ISS}/jwks`, introspection_endpoint: `${ISS}/oauth/introspect`, grant_types_supported: ["urn:ietf:params:oauth:grant-type:token-exchange"] });
  if (url === "/jwks") return reply(200, { keys: [jwk] });
  if (url === "/oauth/introspect") {
    stats.introspections++;
    const t = new URLSearchParams(body).get("token");
    if (String(t).startsWith("op_echo")) return reply(500, { error: "server_error", error_description: `cannot introspect ${t}` });
    const c = opaque.get(t);
    return reply(200, c ? { active: true, ...c } : { active: false });
  }
  if (url === "/oauth/token") {
    stats.exchanges++;
    let j = {}; try { j = JSON.parse(body); } catch {}
    stats.exchangeBodies.push({ grant_type: j.grant_type, scope: j.scope, resource: j.resource, subject_token_type: j.subject_token_type, client_id: j.client_id });
    if (j.grant_type !== "urn:ietf:params:oauth:grant-type:token-exchange" || j.scope !== "wire:sign") return reply(400, { error: "invalid_request" });
    let sub = null;
    if (minted.has(j.subject_token)) sub = JSON.parse(Buffer.from(j.subject_token.split(".")[1], "base64url")).sub;
    else if (opaque.has(j.subject_token)) sub = opaque.get(j.subject_token).sub;
    if (!sub) return reply(400, { error: "invalid_grant" });
    if (USERS[sub]?.exchangeEcho) return reply(400, { error: "invalid_grant", error_description: `subject_token ${j.subject_token} rejected` });
    const wt = `wt_${randomBytes(8).toString("hex")}`; wireTok.set(wt, sub);
    const rt = `rt_${randomBytes(12).toString("hex")}`; refreshOf.set(wt, rt);
    return reply(200, { access_token: wt, refresh_token: rt, id_token: `idt_${randomBytes(8).toString("hex")}`, token_type: "Bearer", expires_in: 300, scope: "wire:sign", issued_token_type: "urn:ietf:params:oauth:token-type:access_token" });
  }
  if (url === "/v1/me/wire-sign") {
    stats.wireSign++;
    const tok = String(rq.headers.authorization || "").replace(/^Bearer /, "");
    if (minted.has(tok) || opaque.has(tok)) { leaks.push("client token at wire-sign"); return reply(401, { error: "invalid_token" }); }
    const sub = wireTok.get(tok);
    if (!sub) return reply(401, { error: "invalid_token" });
    const u = USERS[sub];
    if (u.unprovisioned) return reply(403, { error: "not_governed" });
    const { event } = JSON.parse(body);
    if (u.echo && event.kind !== 27235) {
      const rt = refreshOf.get(tok);
      if (!daveSeen.has(sub)) { daveSeen.add(sub); return reply(401, { error: "invalid_token", error_description: `token ${tok} expired; refresh ${rt}` }); }
      rs.writeHead(500, { "Content-Type": "text/plain" }); return rs.end(`upstream rejected ${tok} refresh_token=${rt} raw:${rt} bearer ${tok}`);
    }
    const ev = finalizeEvent({ kind: event.kind, tags: event.tags, content: event.content, created_at: nowS() }, u.sk);
    return reply(200, { event: ev, pubkey: u.pk });
  }
  reply(404, { error: "not_found" });
});

// ---- mocked relay (per-pubkey data; refuses any request without a valid NIP-98) ----
const relayEvents = [];
const relayAuthPubkeys = new Set();
const msgId = (c) => createHash("sha256").update(c).digest("hex");
const relay = createServer(async (rq, rs) => {
  const body = await readAll(rq);
  const reply = (st, o) => { rs.writeHead(st, { "Content-Type": "application/json" }); rs.end(JSON.stringify(o)); };
  for (const v of Object.values(rq.headers)) if ([...minted, ...opaque.keys()].some((t) => String(v).includes(t))) leaks.push("client token at relay");
  if (rq.method === "GET") return reply(200, { name: "mockrelay", version: "9", software_sha: "abc123" });
  const a = String(rq.headers.authorization || "");
  let who = null;
  try { const ev = JSON.parse(Buffer.from(a.replace(/^Nostr /, ""), "base64").toString()); if (ev.kind === 27235 && verifyEvent(ev)) who = ev.pubkey; } catch {}
  if (!who) return reply(401, { error: "nip98 required" });
  relayAuthPubkeys.add(who);
  const me = byPk[who]; const u = USERS[me];
  if (rq.url === "/events") { const ev = JSON.parse(body); relayEvents.push(ev); return reply(200, { message: "response:{}" }); }
  if (rq.url === "/query") {
    let filters = []; try { filters = JSON.parse(body); } catch {}
    const kinds = new Set(filters.flatMap((f) => f.kinds || []));
    const n = nowS();
    if (kinds.has(39002)) return reply(200, [{ id: msgId("m" + me), pubkey: who, kind: 39002, created_at: n, tags: [["d", u.chan], ["p", who]], content: "" }]);
    if (kinds.has(39000)) return reply(200, [{ id: msgId("c" + me), pubkey: who, kind: 39000, created_at: n, tags: [["d", u.chan], ["name", `room-${me}`]], content: "" }]);
    if (kinds.has(0)) return reply(200, Object.values(USERS).map((x) => ({ id: msgId("p" + x.pk), pubkey: x.pk, kind: 0, created_at: n, tags: [], content: JSON.stringify({ name: x.name }) })));
    if (kinds.has(9) || filters.some((f) => f.ids)) return reply(200, [{ id: msgId("msg" + me), pubkey: who, kind: 9, created_at: n, tags: [["h", u.chan]], content: `hello from ${me}` }]);
    return reply(200, []);
  }
  reply(200, {});
});

const EKAM_PORT = await listenAny(ekam); ISS = `http://127.0.0.1:${EKAM_PORT}`;
const RELAY_PORT = await listenAny(relay);
const logs = [];
const baseEnv = {
  BUZZ_HOSTED_RESOURCE: RESOURCE, BUZZ_EKAM_BASE: ISS, BUZZ_HOSTED_CLIENT_ID: "test-client",
  BUZZ_RELAY_HTTP: `http://127.0.0.1:${RELAY_PORT}`, BUZZ_HOSTED_RATE_PER_MIN: "1000",
  BUZZ_PRIVATE_KEY: "11".repeat(32), BUZZ_AUTH_TAG: "should-never-be-used", // must be IGNORED by hosted cores
};
async function boot(extra = {}) {
  const srv = await startHttpServer({ createBuzzServer, version: "0.2.35", env: { ...baseEnv, ...extra }, listen: false, log: (o) => logs.push(JSON.stringify(o)) });
  const port = await listenAny(srv.httpServer);
  return { srv, base: `http://127.0.0.1:${port}` };
}
async function connect(base, token) {
  const c = new Client({ name: "t", version: "1" });
  const tr = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${token}` } } });
  await c.connect(tr);
  return { c, tr, call: async (name, args = {}) => { const r = await c.callTool({ name, arguments: args }); return { text: r.content.map((x) => x.text).join("\n"), isError: !!r.isError }; } };
}
const rawInit = (base, headers = {}, body) => fetch(`${base}/mcp`, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...headers },
  body: body ?? JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "x", version: "1" } } }) });

console.log("\nhosted 1: protected-resource metadata, healthz, 401 challenge");
const { srv, base } = await boot();
{
  const prm = await (await fetch(`${base}/.well-known/oauth-protected-resource`)).json();
  ok(prm.resource === RESOURCE && prm.authorization_servers[0] === ISS, "PRM advertises resource + Ekam as authorization server");
  const prm2 = await fetch(`${base}/.well-known/oauth-protected-resource/mcp`);
  ok(prm2.status === 200, "PRM also served at the /mcp path-suffixed location");
  const h = await (await fetch(`${base}/healthz`)).json();
  ok(h.ok === true && h.version === "0.2.35" && h.name === "Ola Buzz", "/healthz ok with version");
  const r = await rawInit(base);
  const www = r.headers.get("www-authenticate") || "";
  ok(r.status === 401 && www.includes(`resource_metadata="${RESOURCE}/.well-known/oauth-protected-resource"`), "no token → 401 + WWW-Authenticate resource_metadata");
}

console.log("\nhosted 2: bearer validation (JWKS)");
{
  const cases = [
    ["wrong audience", mint("alice", { aud: "https://other.example" })],
    ["wrong issuer", mint("alice", { iss: "https://evil.example" })],
    ["expired", mint("alice", { exp: nowS() - 3600 })],
    ["not yet valid", mint("alice", { nbf: nowS() + 3600 })],
    ["bad signature", mint("alice", {}, ROGUE)],
    ["alg none", (() => { const t = mint("alice"); const [, p] = t.split("."); const h = Buffer.from(JSON.stringify({ alg: "none", kid: "k1" })).toString("base64url"); const x = `${h}.${p}.`; minted.add(x); return x; })()],
    ["no subject", mint("alice", { sub: "" })],
  ];
  for (const [label, tok] of cases) {
    const r = await rawInit(base, { Authorization: `Bearer ${tok}` });
    ok(r.status === 401 && /error="invalid_token"/.test(r.headers.get("www-authenticate") || ""), `${label} → 401 invalid_token`);
  }
  const r = await rawInit(base, { Authorization: `Bearer ${mint("alice", { aud: [RESOURCE, "x"] })}` });
  ok(r.status === 200 && r.headers.get("mcp-session-id"), "valid token (aud array) → initialize 200 with Mcp-Session-Id");
}

console.log("\nhosted 3: two people, isolated sessions");
const TA = mint("alice"), TB = mint("bob");
const A = await connect(base, TA), B = await connect(base, TB);
{
  const info = A.c.getServerVersion();
  ok(info && info.name === "Ola Buzz", "server identifies as \"Ola Buzz\"");
  const tools = (await A.c.listTools()).tools.map((t) => t.name);
  ok(tools.length === 54 && !tools.includes("buzz_login"), `hosted tool list: 54 tools, no buzz_login (got ${tools.length})`);
  const post = (await A.c.listTools()).tools.find((t) => t.name === "buzz_post");
  ok(post && !("attachment" in post.inputSchema.properties), "hosted buzz_post has no local `attachment` path");
  const wa = await A.call("buzz_whoami"), wb = await B.call("buzz_whoami");
  ok(/Ola Buzz — posting as you \(Alice A\)/.test(wa.text) && wa.text.includes(USERS.alice.pk), "alice whoami: posting as you (Alice A) + her pubkey");
  ok(/v0\.2\.35 \(hosted\)/.test(wa.text), "whoami shows shim version (hosted)");
  ok(/posting as you \(Bob B\)/.test(wb.text) && wb.text.includes(USERS.bob.pk) && !wb.text.includes(USERS.alice.pk), "bob whoami: his identity, never alice's");
  const ca = await A.call("buzz_channels"), cb = await B.call("buzz_channels");
  ok(/room-alice/.test(ca.text) && !/room-bob/.test(ca.text), "alice's channel cache holds only her channels");
  ok(/room-bob/.test(cb.text) && !/room-alice/.test(cb.text), "bob's channel cache holds only his channels");
  const p = await A.call("buzz_post", { channel: "room-alice", text: "hi from hosted" });
  ok(!p.isError && /— posted as you \(Alice A\)/.test(p.text), "write result says posted as you (Alice A)");
  const sent = relayEvents.find((e) => e.kind === 9 && e.content.includes("hi from hosted"));
  ok(sent && sent.pubkey === USERS.alice.pk && verifyEvent(sent), "the relay got a kind-9 signed by Alice's key (via Ekam wire-sign)");
  ok(!sent.tags.some((t) => String(t[1] || "").includes("should-never-be-used")), "server env BUZZ_AUTH_TAG never leaks into a hosted user's event");
  ok(![...relayAuthPubkeys].includes(getPublicKey(Uint8Array.from(Buffer.from("11".repeat(32), "hex")))), "server env BUZZ_PRIVATE_KEY is never used to sign");
  // confirm gate is per session/person
  const del = await A.call("buzz_delete", { channel: "room-alice", event: msgId("msgalice") });
  ok(del.isError && /confirm: true/.test(del.text), "alice's first delete needs confirm:true");
  const delOk = await A.call("buzz_delete", { channel: "room-alice", event: msgId("msgalice"), confirm: true });
  ok(!delOk.isError, "alice confirms → delete goes through");
  const delB = await B.call("buzz_delete", { channel: "room-bob", event: msgId("msgbob") });
  ok(delB.isError && /confirm: true/.test(delB.text), "bob still needs his own confirm (no cross-user confirm leak)");
  const lg = await A.call("buzz_login");
  ok(lg.isError, "buzz_login is refused in hosted mode");
  const at = await A.call("buzz_post", { channel: "room-alice", text: "x", attachment: "/etc/passwd" });
  ok(at.isError, "a local attachment path is refused in hosted mode");
}

console.log("\nhosted 4: session binding, token exchange, no client-token leakage");
{
  const sidA = A.tr.sessionId;
  const r = await fetch(`${base}/mcp`, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", Authorization: `Bearer ${TB}`, "Mcp-Session-Id": sidA, "MCP-Protocol-Version": "2025-06-18" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "buzz_whoami", arguments: {} } }) });
  ok(r.status === 403, "bob's token on alice's session id → 403 (no hijack)");
  const r2 = await fetch(`${base}/mcp`, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", Authorization: `Bearer ${TA}`, "Mcp-Session-Id": "nope" }, body: "{}" });
  ok(r2.status === 404, "unknown session id → 404");
  ok(stats.exchanges === 2, `one token exchange per person, then cached (exchanges=${stats.exchanges})`);
  const eb = stats.exchangeBodies[0];
  ok(eb.grant_type === "urn:ietf:params:oauth:grant-type:token-exchange" && eb.scope === "wire:sign" && eb.resource === ISS && eb.client_id === "test-client"
    && eb.subject_token_type === "urn:ietf:params:oauth:token-type:access_token", "RFC 8693 exchange: grant, scope wire:sign, resource=issuer, client id, subject type");
  ok(leaks.length === 0, `client access token never reached wire-sign or the relay (${leaks.join("; ") || "none"})`);
  const A2 = await connect(base, TA);
  await A2.call("buzz_whoami");
  ok(stats.exchanges === 2, "a second session for alice reuses her cached wire:sign token");
  await A2.c.close();
}

console.log("\nhosted 5: not provisioned → friendly message; rate limit; body cap; origin");
{
  const C = await connect(base, mint("carol"));
  const w = await C.call("buzz_whoami");
  ok(w.isError && w.text === BUZZ_APP_SIGNIN_MESSAGE, "unprovisioned person → \"Open the Buzz app once and sign in with Ekam, then try again.\"");
  await C.c.close();
  const big = await rawInit(base, { Authorization: `Bearer ${TA}` }, JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { pad: "x".repeat(1100 * 1024) } }));
  ok(big.status === 413, "request body over the cap → 413");
  const o = await rawInit(base, { Authorization: `Bearer ${TA}`, Origin: "https://evil.example" });
  ok(o.status === 403, "foreign browser Origin → 403");
  const { srv: s2, base: b2 } = await boot({ BUZZ_HOSTED_RATE_PER_MIN: "3" });
  const t = mint("bob"); const codes = [];
  for (let i = 0; i < 5; i++) codes.push((await rawInit(b2, { Authorization: `Bearer ${t}` })).status);
  ok(codes.slice(0, 3).every((c) => c === 200) && codes[4] === 429, `per-user rate limit → 429 (${codes.join(",")})`);
  await s2.close();
}

console.log("\nhosted 6: logs carry no tokens");
{
  const all = logs.join("\n");
  ok(logs.length > 10 && ![...minted].some((t) => all.includes(t)) && ![...wireTok.keys()].some((t) => all.includes(t)), `structured logs contain no client or wire tokens (${logs.length} lines)`);
  ok(!/"(user|sub)":"(alice|bob|carol)"/.test(all) && /"user":"[0-9a-f]{12}"/.test(all), "logs carry a hashed user, not the raw subject");
  ok(redact("Authorization: Bearer abc.def-123") === "Authorization: Bearer [redacted]" && !redact(`x ${TA} y`).includes(TA), "redact() strips bearer/JWT shapes");
  ok(!("BUZZ_PRIVATE_KEY" in coreEnv(baseEnv)) && !("BUZZ_AUTH_TAG" in coreEnv(baseEnv)), "per-session core env is an allowlist (no key / auth-tag vars)");
}
await A.c.close(); await B.c.close();
await srv.close();

console.log("\nhosted 7: introspection mode, exchanger cache/expiry, encrypted store, signer binding");
{
  const cfg = hostedConfig({ BUZZ_HOSTED_RESOURCE: RESOURCE, BUZZ_EKAM_BASE: ISS, BUZZ_HOSTED_TOKEN_VALIDATION: "introspection", BUZZ_HOSTED_CLIENT_ID: "test-client" });
  const v = createTokenValidator(cfg);
  const op = "op_" + randomBytes(8).toString("hex");
  opaque.set(op, { sub: "bob", aud: RESOURCE, iss: ISS, exp: nowS() + 300, name: "Bob B" });
  const before = stats.introspections;
  const p = await v(op); await v(op);
  ok(p.sub === "bob" && p.name === "Bob B" && stats.introspections === before + 1, "introspection validates an opaque token and caches the result");
  const bad = "op_" + randomBytes(8).toString("hex"); opaque.set(bad, { sub: "bob", aud: "https://other", iss: ISS, exp: nowS() + 300 });
  let e1 = null; try { await v(bad); } catch (e) { e1 = e; }
  ok(e1 && e1.status === 401, "introspected token for another audience → rejected");
  let e2 = null; try { await v("op_unknown"); } catch (e) { e2 = e; }
  ok(e2 && e2.status === 401, "inactive token → rejected");
  ok(protectedResourceMetadata(hostedConfig({})).resource === "https://mcp.buzz.ola.in" && hostedConfig({}).clientId === "REPLACE_WITH_EKAM_CLIENT_ID", "defaults: resource mcp.buzz.ola.in, placeholder client id (no hardcoded secret)");

  let clock = Date.now();
  const ex = createTokenExchanger(cfg, { now: () => clock });
  const n0 = stats.exchanges;
  const t1 = await ex.get({ sub: "bob" }, TB); const t2 = await ex.get({ sub: "bob" }, TB);
  ok(t1 === t2 && stats.exchanges === n0 + 1, "exchanger caches per user");
  clock += 290_000; const t3 = await ex.get({ sub: "bob" }, TB);
  ok(t3 !== t1 && stats.exchanges === n0 + 2, "exchanger refreshes before expiry");
  const t4 = await ex.get({ sub: "bob" }, TB, true);
  ok(t4 !== t3, "forced refresh re-exchanges");

  const dir = mkdtempSync(join(tmpdir(), "bh-")); const path = join(dir, "tokens.enc");
  let threw = false; try { createEncryptedTokenStore({ path }); } catch { threw = true; }
  ok(threw, "token store path without a key → refused (no plaintext fallback)");
  const key = randomBytes(32).toString("base64");
  const st = createEncryptedTokenStore({ path, keyB64: key });
  const ex2 = createTokenExchanger(cfg, { store: st });
  const tok = await ex2.get({ sub: "alice" }, TA);
  const raw = readFileSync(path, "utf8");
  ok(existsSync(path) && !raw.includes(tok) && !raw.includes("alice") && (statSync(path).mode & 0o777) === 0o600, "store file is AES-256-GCM ciphertext, 0600, no plaintext token or subject");
  const ex3 = createTokenExchanger(cfg, { store: createEncryptedTokenStore({ path, keyB64: key }) });
  const n1 = stats.exchanges; ok((await ex3.get({ sub: "alice" }, TA)) === tok && stats.exchanges === n1, "restart with the same key reloads the cached token");
  const ex4 = createTokenExchanger(cfg, { store: createEncryptedTokenStore({ path, keyB64: randomBytes(32).toString("base64") }) });
  ok(ex4.size() === 0, "wrong key → store ignored (tamper / rotation safe)");
  rmSync(dir, { recursive: true, force: true });

  const s = makeHostedWireSigner({ pubkey: USERS.bob.pk, base: ISS, getToken: async () => [...wireTok.entries()].find(([, sub]) => sub === "alice")[0] });
  let e3 = null; try { await s.sign({ kind: 9, tags: [], content: "x" }); } catch (e) { e3 = e; }
  ok(e3 && /different identity/.test(e3.message), "hosted signer refuses an event signed for a different person than the session");
  let e4 = null; try { await s.sign({ kind: 46030, tags: [], content: "" }); } catch (e) { e4 = e; }
  ok(e4, "hosted signer keeps NEVER_SIGN (workflow approval) refused");
}

console.log("\nhosted 8: `buzz-mcp --http` entry (source + bundled dist) boots, serves /healthz, stdio untouched");
for (const entry of ["buzz-mcp.mjs", "dist/buzz-mcp.mjs"]) {
  if (!existsSync(join(HERE, entry))) { console.log(`  (skip: ${entry} not built)`); continue; }
  const child = spawn(process.execPath, [join(HERE, entry), "--http"], { env: { PATH: process.env.PATH, HOME: mkdtempSync(join(tmpdir(), "bh-home-")), PORT: "0", BUZZ_HOSTED_HOST: "127.0.0.1", BUZZ_EKAM_BASE: "http://127.0.0.1:9", BUZZ_HOSTED_CLIENT_ID: "test" }, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  const port = await new Promise((res) => { const to = setTimeout(() => res(null), 15000); child.stdout.on("data", (d) => { out += d; const m = /"evt":"listening","port":(\d+)/.exec(out); if (m) { clearTimeout(to); res(Number(m[1])); } }); });
  let h = null; if (port) try { h = await (await fetch(`http://127.0.0.1:${port}/healthz`)).json(); } catch {}
  ok(h && h.ok === true && h.version === "0.2.35", `${entry} --http → listening, /healthz ok`);
  child.kill("SIGTERM");
  const k = setTimeout(() => child.kill("SIGKILL"), 5000);
  await new Promise((r) => (child.exitCode != null ? r() : child.once("exit", r))); clearTimeout(k);
}

console.log("\nhosted 9: tokens (client bearer, exchanged wire:sign, refresh) never reach logs, stdout/stderr, tool output or HTTP errors");
{
  const seen = [];                       // everything the server could emit
  const oo = process.stdout.write.bind(process.stdout), oe = process.stderr.write.bind(process.stderr);
  process.stdout.write = (c, ...a) => { seen.push(String(c)); return oo(c, ...a); };
  process.stderr.write = (c, ...a) => { seen.push(String(c)); return oe(c, ...a); };
  const L0 = logs.length;
  try {
    const { srv: s9, base: b9 } = await boot();
    const TD = mint("dave"), TE = mint("erin");
    const D = await connect(b9, TD);
    const wd = await D.call("buzz_whoami"); seen.push(wd.text);
    ok(!wd.isError && /Dave D/.test(wd.text), "dave's probe works (whoami ok)");
    const ex0 = stats.exchanges;
    const pd = await D.call("buzz_post", { channel: "room-dave", text: "echo test" }); seen.push(pd.text);
    ok(pd.isError && /HTTP 500/.test(pd.text), "wire-sign 401 (echoing tokens) → one forced re-exchange → 500 (echoing tokens) → sanitised error");
    ok(stats.exchanges === ex0 + 1, "the 401 triggered exactly one forced re-exchange");
    const E = await connect(b9, TE);
    const we = await E.call("buzz_whoami"); seen.push(we.text);
    ok(we.isError && /token exchange failed/.test(we.text), "exchange error echoing the subject_token → generic error");
    const r = await rawInit(b9, { Authorization: `Bearer ${TD}`, "Mcp-Session-Id": D.tr.sessionId });
    seen.push(await r.text());
    await D.c.close(); await E.c.close(); await s9.close();
    const { srv: s10, base: b10 } = await boot({ BUZZ_HOSTED_TOKEN_VALIDATION: "introspection" });
    const opE = "op_echo_" + randomBytes(12).toString("hex");
    const ri = await rawInit(b10, { Authorization: `Bearer ${opE}` }); seen.push(await ri.text(), ri.headers.get("www-authenticate") || "");
    ok(ri.status === 401, "introspection 500 echoing the bearer → 401 without it");
    minted.add(opE);
    await s10.close();
  } finally { process.stdout.write = oo; process.stderr.write = oe; }
  seen.push(...logs.slice(L0));
  const hay = seen.join("\n");
  const daveWire = [...wireTok.entries()].filter(([, sub]) => sub === "dave").map(([t]) => t);
  const daveRefresh = daveWire.map((t) => refreshOf.get(t));
  ok(daveWire.length >= 2 && daveRefresh.every(Boolean), `test really issued dave wire:sign + refresh tokens (${daveWire.length})`);
  const leaked = (arr) => arr.filter((t) => t && hay.includes(t)).length;
  ok(leaked([...minted]) === 0, "no client bearer token in any output");
  ok(leaked([...wireTok.keys()]) === 0, "no exchanged wire:sign token in any output");
  ok(leaked([...refreshOf.values()]) === 0, "no refresh token in any output");
  ok(!/\b(?:wt|rt|idt)_[0-9a-f]{8,}/.test(hay) && !/eyJ[A-Za-z0-9_-]{10,}\./.test(hay), "no token-shaped strings at all");
  ok(logs.slice(L0).length > 5, `checked ${seen.length} output chunks incl. ${logs.slice(L0).length} log lines`);
}

ekam.close(); relay.close();
console.log(`\nhosted: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
