// bench/hosted-load.mjs — v0.2.35 hosted-mode resource measurement (not part of `npm test`).
// Spawns the BUNDLED server (`node dist/buzz-mcp.mjs --http`) against an in-process mock Ekam
// (JWKS + RFC 8693 exchange + wire-sign) and mock relay, then samples the server process's CPU
// (/proc/<pid>/stat utime+stime) and RSS (/proc/<pid>/status VmRSS / VmHWM): idle, then N concurrent
// sessions (one person each) looping buzz_whoami + buzz_read for D seconds. Linux only.
// Usage: node bench/hosted-load.mjs [N=50,200] [D=20]
import { createServer } from "node:http";
import { generateKeyPairSync, sign as cSign, randomBytes, createHash } from "node:crypto";
import { readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { getPublicKey, finalizeEvent, verifyEvent } from "nostr-tools/pure";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
const HERE = dirname(fileURLToPath(import.meta.url));
const NS = (process.argv[2] || "50,200").split(",").map(Number), DUR = Number(process.argv[3] || 20) * 1000;
const RESOURCE = "https://mcp.buzz.bench", nowS = () => Math.floor(Date.now() / 1000);
const readAll = (rq) => new Promise((r) => { let b = ""; rq.on("data", (c) => (b += c)); rq.on("end", () => r(b)); });
const listen = (s) => new Promise((r) => s.listen(0, "127.0.0.1", () => r(s.address().port)));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const skOf = (sub) => Uint8Array.from(createHash("sha256").update("bench:" + sub).digest());
const { privateKey: RSA, publicKey: PUB } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...PUB.export({ format: "jwk" }), kid: "b1", alg: "RS256", use: "sig" };
let ISS; const wire = new Map();
const mint = (sub) => { const h = Buffer.from(JSON.stringify({ alg: "RS256", kid: "b1" })).toString("base64url");
  const p = Buffer.from(JSON.stringify({ iss: ISS, aud: RESOURCE, sub, exp: nowS() + 3600, name: `User ${sub}` })).toString("base64url");
  return `${h}.${p}.${cSign("sha256", Buffer.from(`${h}.${p}`), RSA).toString("base64url")}`; };
const ekam = createServer(async (rq, rs) => {
  const body = await readAll(rq), reply = (s, o) => { rs.writeHead(s, { "Content-Type": "application/json" }); rs.end(JSON.stringify(o)); };
  if (rq.url === "/.well-known/oauth-authorization-server") return reply(200, { issuer: ISS, token_endpoint: `${ISS}/oauth/token`, jwks_uri: `${ISS}/jwks` });
  if (rq.url === "/jwks") return reply(200, { keys: [jwk] });
  if (rq.url === "/oauth/token") { const j = JSON.parse(body); const sub = JSON.parse(Buffer.from(j.subject_token.split(".")[1], "base64url")).sub;
    const t = "wt_" + randomBytes(8).toString("hex"); wire.set(t, sub); return reply(200, { access_token: t, expires_in: 3600, scope: "wire:sign" }); }
  if (rq.url === "/v1/me/wire-sign") { const sub = wire.get(String(rq.headers.authorization).slice(7)); const { event } = JSON.parse(body);
    const ev = finalizeEvent({ kind: event.kind, tags: event.tags, content: event.content, created_at: nowS() }, skOf(sub)); return reply(200, { event: ev, pubkey: ev.pubkey }); }
  reply(404, {});
});
const relay = createServer(async (rq, rs) => {
  const body = await readAll(rq), reply = (s, o) => { rs.writeHead(s, { "Content-Type": "application/json" }); rs.end(JSON.stringify(o)); };
  if (rq.method === "GET") return reply(200, { name: "bench", version: "1" });
  let who = null; try { const ev = JSON.parse(Buffer.from(String(rq.headers.authorization).slice(6), "base64")); if (verifyEvent(ev)) who = ev.pubkey; } catch {}
  if (!who) return reply(401, {});
  const f = JSON.parse(body || "[]"), kinds = new Set(f.flatMap((x) => x.kinds || [])), n = nowS();
  if (kinds.has(39002)) return reply(200, [{ id: "a".repeat(64), pubkey: who, kind: 39002, created_at: n, tags: [["d", "c1"], ["p", who]], content: "" }]);
  if (kinds.has(39000)) return reply(200, [{ id: "b".repeat(64), pubkey: who, kind: 39000, created_at: n, tags: [["d", "c1"], ["name", "general"]], content: "" }]);
  if (kinds.has(0)) return reply(200, []);
  if (kinds.has(9)) return reply(200, Array.from({ length: 20 }, (_, i) => ({ id: createHash("sha256").update(who + i).digest("hex"), pubkey: who, kind: 9, created_at: n - i * 60, tags: [["h", "c1"]], content: `message ${i} `.repeat(8) })));
  reply(200, []);
});
ISS = `http://127.0.0.1:${await listen(ekam)}`;
const RELAY = `http://127.0.0.1:${await listen(relay)}`;
const child = spawn(process.execPath, [join(HERE, "..", "dist", "buzz-mcp.mjs"), "--http"], { stdio: ["ignore", "pipe", "inherit"], env: {
  PATH: process.env.PATH, HOME: mkdtempSync(join(tmpdir(), "bench-")), PORT: "0", BUZZ_HOSTED_HOST: "127.0.0.1", BUZZ_HOSTED_RESOURCE: RESOURCE, BUZZ_EKAM_BASE: ISS,
  BUZZ_RELAY_HTTP: RELAY, BUZZ_HOSTED_CLIENT_ID: "bench", BUZZ_HOSTED_RATE_PER_MIN: "100000", BUZZ_HOSTED_MAX_SESSIONS: "100000" } });
let out = ""; const port = await new Promise((r) => child.stdout.on("data", (d) => { out += d; const m = /"evt":"listening","port":(\d+)/.exec(out); if (m) r(+m[1]); }));
child.stdout.resume();
const base = `http://127.0.0.1:${port}`, TICK = 100;
const cpu = () => { const f = readFileSync(`/proc/${child.pid}/stat`, "utf8").split(") ")[1].split(" "); return (+f[11] + +f[12]) / TICK; };
const mem = () => { const s = readFileSync(`/proc/${child.pid}/status`, "utf8"); const g = (k) => +(new RegExp(`${k}:\\s+(\\d+)`).exec(s)[1]) / 1024; return { rss: g("VmRSS"), hwm: g("VmHWM") }; };
async function window(ms, during) { const c0 = cpu(), b0 = process.cpuUsage(), t0 = Date.now(); const r = await (during ? during() : sleep(ms)); const wall = (Date.now() - t0) / 1000; const b = process.cpuUsage(b0);
  return { cpuPct: ((cpu() - c0) / wall) * 100, benchPct: ((b.user + b.system) / 1e6 / wall) * 100, wall, ...mem(), r }; }
const f1 = (x) => x.toFixed(1);
const rows = [];
await sleep(3000);
const idle = await window(10_000); rows.push(["idle (0 sessions, 10 s)", f1(idle.cpuPct), f1(idle.rss), "—", "—", "—", f1(idle.benchPct)]);
let uid = 0;
for (const N of NS) {
  const clients = await Promise.all(Array.from({ length: N }, async () => { const sub = `u${uid++}`;
    const c = new Client({ name: "bench", version: "1" }); const tr = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${mint(sub)}` } } });
    await c.connect(tr); await c.callTool({ name: "buzz_whoami", arguments: {} }); return c; }));
  const lat = []; let errs = 0;
  const load = await window(DUR, async () => { const end = Date.now() + DUR; await Promise.all(clients.map(async (c) => { let i = 0; while (Date.now() < end) {
    const t = performance.now(); const name = i++ % 2 ? "buzz_read" : "buzz_whoami";
    try { const r = await c.callTool({ name, arguments: name === "buzz_read" ? { channel: "general", limit: 20 } : {} }); if (r.isError) errs++; } catch { errs++; }
    lat.push(performance.now() - t); } })); });
  lat.sort((a, b) => a - b); const q = (p) => lat[Math.min(lat.length - 1, Math.floor(p * lat.length))];
  rows.push([`${N} sessions, whoami+read loop (${DUR / 1000} s)`, f1(load.cpuPct), f1(load.rss), `${f1(lat.length / load.wall)} (${errs} err)`, `${f1(q(0.5))} / ${f1(q(0.95))}`, f1(load.hwm), f1(load.benchPct)]);
  const held = await window(10_000); rows.push([`  then idle, ${N} sessions held open (10 s)`, f1(held.cpuPct), f1(held.rss), "—", "—", "—", f1(held.benchPct)]);
  await Promise.all(clients.map((c) => c.close().catch(() => {})));
}
console.log(`node ${process.version}, ${process.platform}/${process.arch}; server = dist/buzz-mcp.mjs --http (one process); mocks + clients in a separate process\n`);
console.log("| phase | server CPU % (of 1 core) | RSS MiB | calls/s | p50 / p95 ms | peak RSS MiB | load-gen+mocks CPU % |\n|---|---|---|---|---|---|---|");
for (const r of rows) console.log(`| ${r.join(" | ")} |`);
child.kill("SIGTERM"); ekam.close(); relay.close(); setTimeout(() => process.exit(0), 500);
