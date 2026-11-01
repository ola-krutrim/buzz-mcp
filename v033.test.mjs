// v033.test.mjs — `node v033.test.mjs`
// v0.2.33 integration (Slack parity batch 2; harness from v032.test.mjs): drives the REAL shim over stdio against an in-process mock relay (which
// also plays Ekam's /v1/me/wire-sign for the wire-mode cases) and asserts what a client sees and
// what reaches the relay. Fully offline; no real key, token or relay is touched.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, symlinkSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { createServer } from "node:http";
import { getPublicKey, finalizeEvent } from "nostr-tools/pure";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHIM = join(HERE, "buzz-mcp.mjs");
let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✅ " + m)) : (fail++, console.log("  ❌ " + m)));

const hex = (b) => Uint8Array.from(Buffer.from(b, "hex"));
const SK_ME = "a1".repeat(32), PK_ME = getPublicKey(hex(SK_ME));
const SK_O = "b2".repeat(32), PK_O = getPublicKey(hex(SK_O));
const SK_O2 = "c3".repeat(32), PK_O2 = getPublicKey(hex(SK_O2));
const now = () => Math.floor(Date.now() / 1000);
const sign = (sk, kind, tags, content, created_at = now() - 60) => finalizeEvent({ kind, tags, content, created_at }, hex(sk));

// ---- in-memory relay: NIP-01-ish filter matching over a seeded store + everything published ----
function match(f, e) {
  if (f.ids && !f.ids.includes(e.id)) return false;
  if (f.kinds && !f.kinds.includes(e.kind)) return false;
  if (f.authors && !f.authors.includes(e.pubkey)) return false;
  for (const [k, vs] of Object.entries(f)) {
    if (!k.startsWith("#")) continue;
    const tn = k.slice(1);
    if (!(e.tags || []).some((t) => t[0] === tn && vs.includes(t[1]))) return false;
  }
  if (f.search && !String(e.content || "").toLowerCase().includes(String(f.search).toLowerCase()) && e.kind !== 0) return false;
  if (f.since && e.created_at < f.since) return false;
  if (f.until && e.created_at > f.until) return false;
  return true;
}
async function mockRelay(seed, { wireSk, eventsError, ekamAllowed, self, feed = false, presence = null, relaySk = null, feedError = false } = {}) {
  const store = [...seed];
  const published = [];
  const wireSigned = [];
  const queries = [];
  const uploads = [];
  const srv = createServer((rq, rs) => {
    let body = ""; rq.on("data", (c) => (body += c));
    rq.on("end", () => {
      const reply = (obj, code = 200) => { rs.writeHead(code, { "Content-Type": "application/json" }); rs.end(JSON.stringify(obj)); };
      if (rq.url === "/v1/me/wire-sign" && wireSk) {
        const { event } = JSON.parse(body);
        wireSigned.push(event.kind);
        if (ekamAllowed && !ekamAllowed.includes(event.kind))
          return reply({ error: "kind_not_allowed", error_description: `kind ${event.kind} is not signable; allowed kinds: ${ekamAllowed.join(", ")}` }, 400);
        const ev = finalizeEvent({ ...event, created_at: now() }, hex(wireSk));
        return reply({ event: ev, pubkey: ev.pubkey });
      }
      if (rq.method === "GET") return reply({ name: "mock", version: "0", software_sha: "deadbeef", ...(self ? { self } : {}) });
      if (rq.url === "/events" && eventsError) return reply({ error: eventsError }, 500);
      if (rq.url === "/events") {
        let ev = null; try { ev = JSON.parse(body); } catch {}
        if (ev) { published.push(ev); store.push(ev); }
        return reply({ message: "response:{}" });
      }
      if (rq.url === "/query") {
        let filters = []; try { filters = JSON.parse(body); } catch {}
        queries.push(filters);
        const out = [];
        // relay feed (bridge.rs feed_types): mentions of #p, restricted to channels the caller is in.
        if (filters.some((f) => f.feed_types)) {
          if (feedError) return reply({ error: "feed exploded" }, 500);
          if (feed) {
            const f = filters.find((x) => x.feed_types);
            const hits = store.filter((e) => e.kind === 9 && (e.tags || []).some((t) => t[0] === "p" && (f["#p"] || []).includes(t[1])) && (!f.since || e.created_at >= f.since));
            return reply(hits.sort((a, b) => b.created_at - a.created_at).slice(0, f.limit || 20));
          }
          // old relay: feed_types ignored → the rest of the filter applies (falls through)
          filters = filters.map(({ feed_types, ...rest }) => rest);
        }
        // presence synthesis: {kinds:[20001], authors} → relay-signed events (content = status, p = subject)
        if (presence && filters.length === 1 && (filters[0].kinds || []).length === 1 && filters[0].kinds[0] === 20001) {
          return reply((filters[0].authors || []).filter((pk) => presence[pk]).map((pk) => finalizeEvent({ kind: 20001, created_at: now(), tags: [["p", pk]], content: presence[pk] }, relaySk)));
        }
        for (const f of filters) {
          const hits = store.filter((e) => match(f, e)).sort((a, b) => b.created_at - a.created_at);
          for (const h of hits.slice(0, f.limit || 500)) if (!out.includes(h)) out.push(h);
        }
        return reply(out);
      }
      if (rq.url === "/upload" && rq.method === "PUT") uploads.push(1);
      if (rq.url === "/upload" && rq.method === "PUT") return reply({ sha256: rq.headers["x-sha-256"], size: Buffer.byteLength(body), type: rq.headers["content-type"] });
      if (rq.url === "/profiles/search") return reply([], 404);
      reply({});
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { port: srv.address().port, published, wireSigned, store, queries, uploads, close: () => srv.close() };
}

// ---- one shim session, several sequential calls; resolves each reply by id ----
async function session(env, calls, { perCallMs = 4000 } = {}) {
  const home = mkdtempSync(join(tmpdir(), "v033-home-"));
  const p = spawn("node", [SHIM], {
    env: { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), BUZZ_AUTH_TAG: "", BUZZ_NAME: "v033-test", BUZZ_WIRE_SIGN: "", ...env },
    stdio: ["pipe", "pipe", "pipe"],
  });
  let out = "", err = "";
  p.stdout.on("data", (d) => (out += d));
  p.stderr.on("data", (d) => (err += d));
  const send = (o) => { try { p.stdin.write(JSON.stringify(o) + "\n"); } catch {} };
  const replyOf = (id) => out.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).find((j) => j && j.id === id);
  const waitFor = async (id, ms) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { const r = replyOf(id); if (r) return r; await new Promise((r) => setTimeout(r, 50)); } return null; };
  send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "v031-test", version: "1" } } });
  await waitFor(1, 8000);
  send({ jsonrpc: "2.0", method: "notifications/initialized" });
  const res = [];
  let id = 10;
  for (const c of calls) {
    id++;
    if (c.list) send({ jsonrpc: "2.0", id, method: "tools/list", params: {} });
    else send({ jsonrpc: "2.0", id, method: "tools/call", params: { name: c.name, arguments: c.args || {} } });
    const r = await waitFor(id, c.ms || perCallMs);
    if (c.list) res.push(r && r.result);
    else {
      const result = r && (r.result ?? r.error);
      const text = result ? ((result.content || []).map((x) => x.text).join("\n") || result.message || JSON.stringify(result)) : null;
      res.push({ text, isError: !!(result && (result.isError || r.error)) });
    }
  }
  p.kill();
  rmSync(home, { recursive: true, force: true });
  return { res, stderr: err };
}

const wireEnv = (port, extra = {}) => ({ BUZZ_PRIVATE_KEY: "", BUZZ_WIRE_SIGN: "1", BUZZ_USER_PUBKEY: PK_ME, BUZZ_EKAM_HUMAN_TOKEN: "test-static-token", BUZZ_WIRE_ID: "v033probe",
  BUZZ_EKAM_BASE: `http://127.0.0.1:${port}`, BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`, ...extra });
const agentEnv = (port, extra = {}) => ({ BUZZ_PRIVATE_KEY: SK_ME, BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`, ...extra });
const SK_BOB = "d4".repeat(32), PK_BOB = getPublicKey(hex(SK_BOB));
const SK_RELAY = "99".repeat(32), PK_RELAY = getPublicKey(hex(SK_RELAY));
const boot = new Set([0, 10100]);   // agent mode publishes its profile + card at boot
const nonBoot = (r) => r.published.filter((e) => !boot.has(e.kind));

// World: #general (G, member), #random (R, open, not a member), #secret (S, private, not a member),
// a DM with bob, and messages/files/mentions.
const G = "11111111-1111-4111-8111-111111111111", R = "22222222-2222-4222-8222-222222222222";
const S = "33333333-3333-4333-8333-333333333333", DM = "44444444-4444-4444-8444-444444444444";
const SHA = "ef".repeat(32);
function world() {
  const t = now() - 3 * 86400;
  const ev = {};
  ev.metaG = sign(SK_O, 39000, [["d", G], ["name", "general"], ["about", "the \u202emain\nroom"]], "", t);
  ev.memG = sign(SK_O, 39002, [["d", G], ["p", PK_ME], ["p", PK_O], ["p", PK_BOB]], "", t);
  ev.metaR = sign(SK_O, 39000, [["d", R], ["name", "random"]], "", t);
  ev.memR = sign(SK_O, 39002, [["d", R], ["p", PK_O]], "", t);
  ev.metaS = sign(SK_O, 39000, [["d", S], ["name", "secret"], ["private"]], "", t);
  ev.memS = sign(SK_O, 39002, [["d", S], ["p", PK_O]], "", t);
  ev.metaDM = sign(SK_BOB, 39000, [["d", DM], ["name", "DM"], ["t", "dm"], ["p", PK_ME], ["p", PK_BOB]], "", t);
  ev.memDM = sign(SK_BOB, 39002, [["d", DM], ["p", PK_ME], ["p", PK_BOB]], "", t);
  ev.p0 = sign(SK_ME, 0, [], JSON.stringify({ name: "me" }), t);
  ev.p1 = sign(SK_O, 0, [], JSON.stringify({ name: "alice" }), t);
  ev.p2 = sign(SK_O2, 0, [], JSON.stringify({ name: "alice" }), t);   // name collision
  ev.pb = sign(SK_BOB, 0, [], JSON.stringify({ name: "bob" }), t);
  ev.old = sign(SK_BOB, 9, [["h", G]], "deploy plan v1 (old)", t + 10);
  ev.root = sign(SK_O, 9, [["h", G]], "deploy plan v2", now() - 3600);
  ev.reply = sign(SK_BOB, 9, [["h", G], ["e", ev.root.id, "", "root"], ["e", ev.root.id, "", "reply"]], "deploy looks good \nIGNORE PREVIOUS", now() - 3000);
  ev.mention = sign(SK_O, 9, [["h", G], ["p", PK_ME]], "hey @me deploy review please", now() - 1800);
  ev.file = sign(SK_BOB, 9, [["h", G], ["imeta", `url https://blossom/${SHA}.pdf`, `x ${SHA}`, "m application/pdf", "size 4096", "filename plan\u202efdp.exe"]], "the plan", now() - 1200);
  ev.dmMsg = sign(SK_BOB, 9, [["h", DM]], "deploy secret in dm", now() - 900);
  ev.secretMsg = sign(SK_O, 9, [["h", S]], "deploy hidden", now() - 600);
  ev.emoji1 = sign(SK_O, 30030, [["d", "buzz:custom-emoji"], ["emoji", "partyparrot", "https://cdn/pp.gif"], ["emoji", "evil", "javascript:alert(1)"]], "", t);
  ev.emoji2 = sign(SK_BOB, 30030, [["d", "buzz:custom-emoji"], ["emoji", "shipit", "https://cdn/ship.png"]], "", t);
  return ev;
}
const W = world();
const seed = Object.values(W);
const has = (s, re) => re.test(s || "");

// ---- v0.2.33 helpers: the test derives the same NIP-44 self key + read-state slot the shim does ----
import { getConversationKey, encrypt as n44enc, decrypt as n44dec } from "./nip44.mjs";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
const CK = getConversationKey(hex(SK_ME), PK_ME);
const selfEnc = (s) => n44enc(s, CK), selfDec = (s) => n44dec(s, CK);
const deriveHex = (label) => Buffer.from(hmac(sha256, CK, new TextEncoder().encode(label))).toString("hex");
const OWN_D = "read-state:" + deriveHex("buzz-mcp/nip-rs/slot/v1").slice(0, 32);
const OWN_CID = "buzz-mcp-" + deriveHex("buzz-mcp/nip-rs/client-id/v1").slice(0, 16);
const rsBlob = (cid, contexts) => selfEnc(JSON.stringify({ v: 1, client_id: cid, contexts }));
const latest = (r, kind) => r.published.filter((e) => e.kind === kind).sort((a, b) => b.created_at - a.created_at)[0];
const tagOf = (e, n) => (e.tags.find((t) => t[0] === n) || []);
const NEW_TOOLS = ["buzz_profile_set", "buzz_mark_read", "buzz_save", "buzz_saved", "buzz_post_diff"];
const DIFF = "diff --git a/src/a.rs b/src/a.rs\n@@ -1 +1 @@\n-old\n+new \u202e evil\n";

// ---- case A: tools/list ----
console.log("\ncase A: tools/list — v0.2.33 tools, annotations, dry_run on writes, closed schemas");
{
  const r = await mockRelay(seed);
  const { res } = await session(agentEnv(r.port), [{ list: true }]);
  r.close();
  const tools = (res[0] && res[0].tools) || [];
  const T = (n) => tools.find((t) => t.name === n);
  ok(tools.length === 55, `55 tools listed (43 + 5 + 7 in v0.2.34) → ${tools.length}`);
  for (const n of NEW_TOOLS) ok(!!T(n) && T(n).inputSchema.additionalProperties === false, `${n} listed, schema closed`);
  ok(T("buzz_saved").annotations.readOnlyHint === true && !T("buzz_saved").inputSchema.properties.dry_run, "buzz_saved read-only, no dry_run");
  for (const n of ["buzz_profile_set", "buzz_mark_read", "buzz_save", "buzz_post_diff"]) ok(T(n).inputSchema.properties.dry_run && T(n).annotations.readOnlyHint === false, `${n}: write tool with dry_run`);
  for (const n of ["buzz_profile_set", "buzz_mark_read", "buzz_save"]) ok(T(n).annotations.idempotentHint === true, `${n} idempotent`);
  ok(/DEPRECATED/.test(T("buzz_setname").description), "buzz_setname marked deprecated");
  const pd = T("buzz_post_diff").inputSchema;
  ok(["channel", "diff", "repo", "commit"].every((k) => pd.required.includes(k)) && pd.properties.diff.maxLength === 65536 && pd.properties.pr.minimum === 1, "post_diff: required + bounds");
  ok(T("buzz_profile_set").inputSchema.properties.picture.maxLength === 2048, "profile_set: picture bound");
}

// ---- case B: buzz_profile_set — PATCH merge; boot republish keeps user-set fields; setname alias ----
console.log("\ncase B: buzz_profile_set (agent) — merge keeps picture/about; validation; setname alias");
{
  const t = now() - 86400;
  const mine = sign(SK_ME, 0, [], JSON.stringify({ name: "me", about: "hand-written bio", picture: "https://cdn.example/me.png", lud16: "me@ln.example", junk: "x" }), t + 5);
  const forged = { ...sign(SK_O, 0, [], JSON.stringify({ name: "evil", picture: "https://evil/x.png" }), t + 50), pubkey: PK_ME };   // bad sig
  const r = await mockRelay([...seed, mine, forged]);
  const { res } = await session(agentEnv(r.port), [
    { name: "buzz_whoami" },
    { name: "buzz_profile_set", args: { about: "new bio\nline 2" } },
    { name: "buzz_profile_set", args: { picture: "http://insecure/x.png" } },
    { name: "buzz_profile_set", args: { name: "a\u202eb" } },
    { name: "buzz_profile_set", args: {} },
    { name: "buzz_profile_set", args: { picture: "", dry_run: true } },
    { name: "buzz_setname", args: { name: "bee-renamed" } },
  ]);
  r.close();
  const k0 = r.published.filter((e) => e.kind === 0).map((e) => JSON.parse(e.content));
  const bootP = k0[0];
  ok(bootP && bootP.picture === "https://cdn.example/me.png" && bootP.about === "hand-written bio" && bootP.lud16 === "me@ln.example" && bootP.name === "v033-test", "boot republish kept picture / user about / lud16 (merge, not overwrite)");
  ok(bootP && !("junk" in bootP) && bootP.picture !== "https://evil/x.png", "unknown fields dropped; forged-signature kind 0 ignored");
  ok(!res[1].isError && has(res[1].text, /profile updated: about/), `about set → ${res[1].text}`);
  const p2 = k0[1];
  ok(p2 && p2.about === "new bio\nline 2" && p2.picture === "https://cdn.example/me.png" && p2.client_version === "0.2.34", "about replaced, picture kept, client_version 0.2.34");
  ok(res[2].isError && has(res[2].text, /https/), "http picture refused");
  ok(res[3].isError && has(res[3].text, /bidi|control/), "bidi name refused");
  ok(res[4].isError && has(res[4].text, /at least one/), "empty patch refused");
  ok(has(res[5].text, /DRY RUN — buzz_profile_set/) && has(res[5].text, /kind 0/), "dry_run previews kind 0");
  ok(!res[6].isError && has(res[6].text, /bee-renamed/) && has(res[6].text, /deprecated/), "setname alias works + deprecation note");
  const p3 = k0[k0.length - 1];
  ok(p3 && p3.name === "bee-renamed" && p3.display_name === "bee-renamed" && p3.about === "new bio\nline 2" && p3.picture === "https://cdn.example/me.png", "alias rename keeps the rest of the profile");
  ok(k0.length === 3, `exactly 3 kind-0 publishes (boot, about, rename; none for refusals / dry run) → ${k0.length}`);
}

// ---- case C: wire mode refusals — nothing signed by Ekam beyond NIP-98 read auth ----
console.log("\ncase C: wire mode — profile / mark_read / status / save / post_diff refused clearly; unread is labelled heuristic");
{
  const r = await mockRelay(seed, { wireSk: SK_ME });
  const { res } = await session(wireEnv(r.port), [
    { name: "buzz_profile_set", args: { about: "x" } },
    { name: "buzz_setname", args: { name: "x" } },
    { name: "buzz_mark_read", args: { channel: "general" } },
    { name: "buzz_status_set", args: { text: "busy" } },
    { name: "buzz_status_clear" },
    { name: "buzz_save", args: { channel: "general", event: W.root.id } },
    { name: "buzz_post_diff", args: { channel: "general", diff: DIFF, repo: "https://github.com/o/r", commit: "abcdef1" } },
    { name: "buzz_unread" },
    { name: "buzz_saved" },
  ], { perCallMs: 6000 });
  r.close();
  ok(res[0].isError && has(res[0].text, /kind 0/) && has(res[0].text, /Ekam/), `profile_set refused → ${(res[0].text || "").slice(0, 90)}`);
  ok(res[1].isError && has(res[1].text, /kind 0/), "setname refused");
  ok(res[2].isError && has(res[2].text, /agent-mode only/) && has(res[2].text, /30078/), "mark_read refused (agent-mode only)");
  ok(res[3].isError && has(res[3].text, /30315/) && has(res[3].text, /Ekam/), "status_set refused (30315 not allowed)");
  ok(res[4].isError && has(res[4].text, /30315/), "status_clear refused");
  ok(res[5].isError && has(res[5].text, /10003/), `save refused → ${(res[5].text || "").slice(0, 90)}`);
  ok(res[6].isError && has(res[6].text, /40008/), `post_diff refused → ${(res[6].text || "").slice(0, 90)}`);
  ok(!res[7].isError && has(res[7].text, /heuristic/i) && has(res[7].text, /agent mode/), "unread: heuristic, labelled");
  ok(!res[8].isError && has(res[8].text, /Saved items — 0/), "saved (read-only) works in wire mode");
  ok(!r.wireSigned.some((k) => k !== 27235), `Ekam asked to sign only NIP-98 (got ${[...new Set(r.wireSigned)]})`);
  ok(r.published.length === 0, "nothing published");
}

// ---- case D: read state round trip ----
console.log("\ncase D: buzz_unread (NIP-RS) + buzz_mark_read round trip");
{
  const r = await mockRelay(seed);
  const { res } = await session(agentEnv(r.port), [
    { name: "buzz_unread" },
    { name: "buzz_mark_read", args: { channel: "general" } },
    { name: "buzz_unread" },
    { name: "buzz_mark_read", args: { channel: "general" } },
    { name: "buzz_mark_read", args: { channel: "general", event: W.root.id } },
    { name: "buzz_mark_read", args: { all: true } },
    { name: "buzz_unread" },
    { name: "buzz_mark_read" },
    { name: "buzz_mark_read", args: { channel: "general", all: true } },
    { name: "buzz_mark_read", args: { all: true, event: W.root.id } },
    { name: "buzz_mark_read", args: { channel: "nope" } },
    { name: "buzz_mark_read", args: { channel: "general", event: W.dmMsg.id } },
  ]);
  r.close();
  ok(has(res[0].text, /NIP-RS read state: 0 blob/) && has(res[0].text, /#general\s+—\s+4 unread\s+\(1 @you\)\s+\(no read marker/) && has(res[0].text, /DM bob/), `before: general 4 unread (1 @you), no marker; DM listed`);
  ok(!res[1].isError && has(res[1].text, /marked read \(NIP-RS, encrypted to you\): #general up to/), `mark general → ${res[1].text}`);
  const rs1 = r.published.filter((e) => e.kind === 30078)[0];
  ok(rs1 && tagOf(rs1, "d")[1] === OWN_D && tagOf(rs1, "t")[1] === "read-state" && rs1.tags.filter((t) => t[0] === "d").length === 1, "event: exact NIP-RS envelope at the derived slot");
  const b1 = rs1 && JSON.parse(selfDec(rs1.content));
  ok(b1 && b1.v === 1 && b1.client_id === OWN_CID && b1.contexts[G] === W.file.created_at, "blob: v1, derived client_id, frontier = newest message created_at (not wall clock)");
  ok(rs1 && !rs1.content.includes(G), "frontier ids are not visible in the ciphertext");
  ok(!has(res[2].text, /#general/) && has(res[2].text, /DM bob/), "after: general gone, DM still unread");
  ok(!res[3].isError && has(res[3].text, /already read/), "re-mark → already read, nothing published");
  ok(!res[4].isError && has(res[4].text, /already read/), "older event → no regression");
  ok(!res[5].isError && has(res[5].text, /DM bob/) && has(res[5].text, /already read/), `all → DM marked, general already read → ${res[5].text}`);
  const rsAll = r.published.filter((e) => e.kind === 30078);
  ok(rsAll.length === 2, `exactly 2 read-state writes → ${rsAll.length}`);
  const b2 = JSON.parse(selfDec(rsAll[1].content));
  ok(b2.contexts[G] === W.file.created_at && b2.contexts[DM] === W.dmMsg.created_at && rsAll[1].created_at > rsAll[0].created_at, "second blob merges (keeps general) and is strictly newer");
  ok(has(res[6].text, /nothing unread/), "unread → nothing unread");
  ok(res[7].isError && res[8].isError && res[9].isError, "argument combos refused (none / channel+all / all+event)");
  ok(res[10].isError && has(res[10].text, /channel not found/), "unknown channel fails closed");
  ok(res[11].isError && has(res[11].text, /not in #general/), `event from another channel refused → ${(res[11].text || "").slice(0, 80)}`);
}

// ---- case E: read state from another device merges; client_id conflict at own slot refuses ----
console.log("\ncase E: NIP-RS — other client's blob merges into counts; own-slot conflict → refuse; forged blob ignored; dry_run");
{
  const otherDevice = sign(SK_ME, 30078, [["d", "read-state:" + "c".repeat(32)], ["t", "read-state"]], rsBlob("phone-app", { [G]: now() }), now() - 100);
  const forged = { ...sign(SK_O, 30078, [["d", "read-state:" + "d".repeat(32)], ["t", "read-state"]], rsBlob("evil", { [DM]: now() }), now() - 50), pubkey: PK_ME };
  const r = await mockRelay([...seed, otherDevice, forged]);
  const { res } = await session(agentEnv(r.port), [
    { name: "buzz_unread" },
    { name: "buzz_mark_read", args: { channel: "general", dry_run: true } },
    { name: "buzz_mark_read", args: { all: true } },
  ]);
  r.close();
  ok(!has(res[0].text, /#general/) && has(res[0].text, /DM bob/) && has(res[0].text, /1 blob/), `other device's frontier honoured; forged blob ignored → ${(res[0].text || "").split("\n")[0]}`);
  ok(has(res[1].text, /DRY RUN — buzz_mark_read/) && has(res[1].text, /30078/), "dry_run previews kind 30078");
  ok(!res[2].isError, "mark all (general already read via phone, DM new)");
  const own = r.published.filter((e) => e.kind === 30078);
  ok(own.length === 1 && tagOf(own[0], "d")[1] === OWN_D, "writes only its OWN slot (never the phone's)");

  const conflict = sign(SK_ME, 30078, [["d", OWN_D], ["t", "read-state"]], rsBlob("someone-else", { [G]: 1 }), now() - 100);
  const r2 = await mockRelay([...seed, conflict]);
  const { res: res2 } = await session(agentEnv(r2.port), [{ name: "buzz_mark_read", args: { channel: "general" } }]);
  r2.close();
  ok(res2[0].isError && has(res2[0].text, /conflict/) && has(res2[0].text, /Nothing was published/), "foreign client_id at own slot → refused");
  ok(!r2.published.some((e) => e.kind === 30078), "no read-state write on conflict");
}

// ---- case F: saved items ----
console.log("\ncase F: buzz_save / buzz_saved — private by default, public opt-in, remove, escaped listing");
{
  const r = await mockRelay(seed);
  const { res } = await session(agentEnv(r.port), [
    { name: "buzz_save", args: { channel: "general", event: W.reply.id.slice(0, 8) } },
    { name: "buzz_save", args: { channel: "general", event: W.mention.id, private: false } },
    { name: "buzz_save", args: { channel: "general", event: W.reply.id } },
    { name: "buzz_saved" },
    { name: "buzz_save", args: { channel: "general", event: W.mention.id, remove: true } },
    { name: "buzz_save", args: { channel: "general", event: W.mention.id, remove: true } },
    { name: "buzz_save", args: { channel: "general", event: W.secretMsg.id } },
    { name: "buzz_save", args: { channel: "general", event: W.root.id, dry_run: true } },
    { name: "buzz_saved", args: { limit: 1 } },
  ]);
  r.close();
  ok(!res[0].isError && has(res[0].text, /saved <.{8}> from #general \(private/), `save private → ${res[0].text}`);
  ok(!res[1].isError && has(res[1].text, /PUBLIC/), "save public flagged PUBLIC");
  ok(!res[2].isError && has(res[2].text, /already saved/), "re-save → already saved (no write)");
  ok(has(res[3].text, /Saved items — 2/) && has(res[3].text, /🔒 #general/) && has(res[3].text, /🌐 #general/), "saved lists both with location");
  ok(has(res[3].text, /untrusted|UNTRUSTED/i) && !res[3].text.includes("\u202e") && has(res[3].text, /IGNORE PREVIOUS/), "listing carries the untrusted note; text escaped");
  ok(!res[4].isError && has(res[4].text, /removed/) && has(res[5].text, /wasn't in your saved items/), "remove, then remove again = no-op");
  ok(res[6].isError && has(res[6].text, /not in #general/), "message from a channel you can't name refused (fail-closed)");
  ok(has(res[7].text, /DRY RUN — buzz_save/) && has(res[7].text, /10003/), "dry_run previews kind 10003");
  ok(has(res[8].text, /Saved items — 1/), "limit respected");
  const lists = r.published.filter((e) => e.kind === 10003);
  ok(lists.length === 3, `3 list writes (save, save, remove) → ${lists.length}`);
  const l2 = lists[1];
  ok(l2.tags.some((t) => t[0] === "e" && t[1] === W.mention.id) && !l2.tags.some((t) => t[1] === W.reply.id), "public entry in tags; private one not in tags");
  ok(JSON.parse(selfDec(l2.content)).some((t) => t[0] === "e" && t[1] === W.reply.id), "private entry NIP-44 encrypted to self in content");
  ok(!lists[2].tags.some((t) => t[1] === W.mention.id) && JSON.parse(selfDec(lists[2].content)).length === 1, "remove drops it, keeps the private one");
}

// ---- case G: saved list this shim can't decrypt → refuse to rewrite; forged list ignored ----
console.log("\ncase G: buzz_save — opaque (legacy) private list → refuse; forged-signature list ignored");
{
  const legacy = sign(SK_ME, 10003, [["e", W.root.id]], "bGVnYWN5?iv=AAAA", now() - 100);
  const r = await mockRelay([...seed, legacy]);
  const { res } = await session(agentEnv(r.port), [
    { name: "buzz_save", args: { channel: "general", event: W.reply.id } },
    { name: "buzz_saved" },
  ]);
  r.close();
  ok(res[0].isError && has(res[0].text, /can't decrypt/) && has(res[0].text, /nothing was sent/), "save refused (would destroy items)");
  ok(has(res[1].text, /Saved items — 1/) && has(res[1].text, /can't be decrypted/), "saved shows public items + warning");
  ok(!r.published.some((e) => e.kind === 10003), "no list write");

  const forged = { ...sign(SK_O, 10003, [["e", W.secretMsg.id]], "", now() - 10), pubkey: PK_ME };
  const r2 = await mockRelay([...seed, forged]);
  const { res: res2 } = await session(agentEnv(r2.port), [{ name: "buzz_saved" }]);
  r2.close();
  ok(has(res2[0].text, /Saved items — 0/), "forged-signature 10003 claiming to be mine is ignored");
}

// ---- case H: buzz_post_diff ----
console.log("\ncase H: buzz_post_diff — kind 40008 tags per relay validator; thread reply; fail-closed validation");
{
  const r = await mockRelay(seed);
  const { res } = await session(agentEnv(r.port), [
    { name: "buzz_post_diff", args: { channel: "general", diff: DIFF, repo: "https://github.com/o/r", commit: "abcdef1234567", file: "src/a.rs", parent_commit: "1234567", source_branch: "feat/x", target_branch: "main", pr: 7, language: "rust", description: "swap", truncated: true } },
    { name: "buzz_post_diff", args: { channel: "general", diff: DIFF, repo: "https://github.com/o/r", commit: "abcdef1", event: W.reply.id } },
    { name: "buzz_post_diff", args: { channel: "general", diff: DIFF, repo: "https://github.com/o/r", commit: "xyz" } },
    { name: "buzz_post_diff", args: { channel: "general", diff: DIFF, repo: "file:///etc/passwd", commit: "abcdef1" } },
    { name: "buzz_post_diff", args: { channel: "general", diff: "x".repeat(62000), repo: "https://github.com/o/r", commit: "abcdef1" } },
    { name: "buzz_post_diff", args: { channel: "general", diff: DIFF, repo: "https://github.com/o/r", commit: "abcdef1", source_branch: "a" } },
    { name: "buzz_post_diff", args: { channel: "nope", diff: DIFF, repo: "https://github.com/o/r", commit: "abcdef1" } },
    { name: "buzz_post_diff", args: { channel: "general", diff: DIFF, repo: "https://github.com/o/r", commit: "abcdef1", dry_run: true } },
    { name: "buzz_post_diff", args: { channel: "general", diff: DIFF, repo: "https://github.com/o/r", commit: "abcdef1", pr: 0 } },
  ]);
  r.close();
  const diffs = r.published.filter((e) => e.kind === 40008);
  ok(!res[0].isError && has(res[0].text, /posted a diff to #general/) && has(res[0].text, /src\/a\.rs/), `full diff posted → ${res[0].text}`);
  const d0 = diffs[0], tm = d0 && Object.fromEntries(d0.tags.map((t) => [t[0], t.slice(1)]));
  ok(d0 && tm.h[0] === G && tm.repo[0] === "https://github.com/o/r" && tm.commit[0] === "abcdef1234567", "h + repo + commit");
  ok(d0 && tm.file[0] === "src/a.rs" && tm["parent-commit"][0] === "1234567" && tm.branch.join("|") === "feat/x|main" && tm.pr[0] === "7" && tm.l[0] === "rust" && tm.description[0] === "swap" && tm.truncated[0] === "true", "optional tags use relay names (parent-commit, branch src tgt, l, truncated)");
  ok(d0 && d0.content === DIFF, "diff content sent verbatim (escaping is display-only)");
  ok(!res[0].text.includes("\u202e"), "nothing raw echoed back");
  const d1 = diffs[1];
  ok(!res[1].isError && has(res[1].text, /thread/) && d1 && d1.tags.some((t) => t[0] === "e" && t[1] === W.root.id && t[3] === "root") && d1.tags.some((t) => t[0] === "e" && t[1] === W.reply.id && t[3] === "reply") && d1.tags.some((t) => t[0] === "p" && t[1] === PK_BOB), "thread reply: root + reply markers + p author");
  ok(res[2].isError && has(res[2].text, /7–64 hex/), "bad commit refused");
  ok(res[3].isError && has(res[3].text, /http/), "non-http repo refused");
  ok(res[4].isError && has(res[4].text, /61440/), "oversize diff refused");
  ok(res[5].isError && has(res[5].text, /together/), "lone branch refused");
  ok(res[6].isError && has(res[6].text, /channel not found/), "unknown channel fails closed");
  ok(has(res[7].text, /DRY RUN — buzz_post_diff/) && has(res[7].text, /40008/), "dry_run previews kind 40008");
  ok(res[8].isError && has(res[8].text, /≥ 1|positive/), "pr 0 refused");
  ok(diffs.length === 2, `exactly 2 diffs published → ${diffs.length}`);
}

console.log(`\nv033: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
