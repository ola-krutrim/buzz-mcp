// v032.test.mjs — `node v032.test.mjs`
// v0.2.32 integration (harness copied from v031.test.mjs, extended): drives the REAL shim over stdio against an in-process mock relay (which
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
  const home = mkdtempSync(join(tmpdir(), "v032-home-"));
  const p = spawn("node", [SHIM], {
    env: { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), BUZZ_AUTH_TAG: "", BUZZ_NAME: "v032-test", BUZZ_WIRE_SIGN: "", ...env },
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

const wireEnv = (port, extra = {}) => ({ BUZZ_PRIVATE_KEY: "", BUZZ_WIRE_SIGN: "1", BUZZ_USER_PUBKEY: PK_ME, BUZZ_EKAM_HUMAN_TOKEN: "test-static-token", BUZZ_WIRE_ID: "v032probe",
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

// ---- case A: tools/list ----
console.log("\ncase A: tools/list — v0.2.32 tools, read-only annotations, dry_run on writes only");
{
  const r = await mockRelay(seed);
  const { res } = await session(agentEnv(r.port), [{ list: true }]);
  r.close();
  const tools = (res[0] && res[0].tools) || [];
  const T = (n) => tools.find((t) => t.name === n);
  for (const n of ["buzz_message_link", "buzz_activity", "buzz_files", "buzz_presence", "buzz_emoji"]) {
    ok(!!T(n), `${n} is listed`);
    ok(T(n) && T(n).annotations.readOnlyHint === true && !T(n).inputSchema.properties.dry_run, `${n} is read-only and has no dry_run`);
  }
  for (const n of ["buzz_post", "buzz_reply", "buzz_react", "buzz_delete", "buzz_edit_message", "buzz_setname", "buzz_dm_open", "buzz_join_channel", "buzz_leave_channel"])
    ok(T(n) && T(n).inputSchema.properties.dry_run && T(n).inputSchema.properties.dry_run.type === "boolean", `${n} has dry_run`);
  for (const n of ["buzz_read", "buzz_search", "buzz_login", "buzz_doctor"]) ok(T(n) && !T(n).inputSchema.properties.dry_run, `${n} has no dry_run`);
  const sp = T("buzz_search").inputSchema;
  ok(!(sp.required || []).includes("query") && sp.properties.from && sp.properties.after && sp.properties.before && sp.properties.in, "buzz_search: from/after/before/in, query optional");
  ok(T("buzz_channels").inputSchema.properties.scope, "buzz_channels: scope");
  ok(tools.every((t) => t.inputSchema.additionalProperties === false), "every schema stays closed");
}

// ---- case B: dry_run never signs or sends (agent mode, with an auth tag) ----
console.log("\ncase B: dry_run on buzz_post / buzz_reply / buzz_react / buzz_join_channel — preview, nothing sent, auth redacted");
{
  const AUTH = JSON.stringify(["auth", "f".repeat(64), "", "e".repeat(128)]);
  const r = await mockRelay(seed);
  const { res } = await session(agentEnv(r.port, { BUZZ_AUTH_TAG: AUTH }), [
    { name: "buzz_post", args: { channel: "general", text: "hello @bob \u202enew\nline", dry_run: true } },
    { name: "buzz_reply", args: { channel: "general", event: W.root.id.slice(0, 8), text: "+1", dry_run: true } },
    { name: "buzz_react", args: { channel: "general", event: W.root.id, emoji: ":partyparrot:", dry_run: true } },
    { name: "buzz_join_channel", args: { channel: R, dry_run: true } },
    { name: "buzz_post", args: { channel: "nope", text: "x", dry_run: true } },
    { name: "buzz_read", args: { channel: "general", dry_run: true } },
  ]);
  r.close();
  const [post, reply, react, join, missing, read] = res;
  ok(has(post.text, /DRY RUN — buzz_post: nothing was signed or sent/) && !post.isError, "post: dry-run preview");
  ok(has(post.text, /kind 9 \(chat message\)/) && post.text.includes(`["h","${G}"]`), "post: kind 9 + resolved h tag");
  ok(post.text.includes(`["p","${PK_BOB}"]`), "post: @bob resolved to a p tag in the preview");
  ok(post.text.includes("\\u{202e}") && !post.text.includes("\u202e") && post.text.includes("\\n"), "post: echoed content escaped");
  ok(post.text.includes('["auth","‹redacted›"]') && !post.text.includes("e".repeat(128)) && !post.text.includes("f".repeat(64)), "post: auth tag redacted, never printed");
  ok(has(reply.text, /DRY RUN — buzz_reply/) && reply.text.includes(`["e","${W.root.id}"`) && reply.text.includes(`["p","${PK_O}"]`), "reply: e (thread) + p (author) tags previewed");
  ok(has(react.text, /kind 7 \(reaction\)/) && react.text.includes('["emoji","partyparrot","https://cdn/pp.gif"]'), "react: custom emoji tag previewed");
  ok(has(join.text, /kind 9021/), "join: previewed");
  ok(missing.isError && has(missing.text, /channel not found/), "dry run still fails closed on resolution");
  ok(read.isError && has(read.text, /unknown argument `dry_run`/), "dry_run on a read tool is refused (not silently ignored)");
  ok(nonBoot(r).length === 0, `nothing but the boot profile was published (got kinds ${nonBoot(r).map((e) => e.kind)})`);
}

// ---- case C: dry_run in wire mode — no Ekam signing, confirm gate not consumed ----
console.log("\ncase C: wire mode — dry_run makes no wire-sign call for the event; confirm is never recorded");
{
  const r = await mockRelay(seed, { wireSk: SK_ME });
  const { res } = await session(wireEnv(r.port), [
    { name: "buzz_post", args: { channel: "general", text: "as me", dry_run: true } },
    { name: "buzz_delete", args: { channel: "general", event: W.reply.id, dry_run: true, confirm: true } },
    { name: "buzz_delete", args: { channel: "general", event: W.reply.id } },
  ], { perCallMs: 6000 });
  r.close();
  ok(has(res[0].text, /DRY RUN — buzz_post/) && !res[0].isError, "wire post: previewed");
  ok(!r.wireSigned.some((k) => k !== 27235), `Ekam signed only NIP-98 read auth (got ${[...new Set(r.wireSigned)]})`);
  ok(has(res[1].text, /DRY RUN — buzz_delete/) && has(res[1].text, /real run needs confirm: true/), "wire delete dry run: notes the confirm requirement");
  ok(res[2].isError && has(res[2].text, /confirm: true/), "the real delete is still gated (dry-run confirm:true was not recorded)");
  ok(r.published.length === 0, "nothing published");
}

// ---- case D: dry_run with an attachment — no upload; secret paths still refused ----
console.log("\ncase D: dry_run + attachment — nothing uploaded; secret-path refusal still applies");
{
  const dir = mkdtempSync(join(tmpdir(), "v032-att-"));
  writeFileSync(join(dir, "notes.txt"), "hello");
  mkdirSync(join(dir, ".ssh"));
  writeFileSync(join(dir, ".ssh", "id_ed25519"), "PRIVATE");
  const r = await mockRelay(seed);
  const { res } = await session(agentEnv(r.port), [
    { name: "buzz_post", args: { channel: "general", text: "see file", attachment: join(dir, "notes.txt"), dry_run: true } },
    { name: "buzz_post", args: { channel: "general", text: "key", attachment: join(dir, ".ssh", "id_ed25519"), dry_run: true } },
  ]);
  r.close();
  rmSync(dir, { recursive: true, force: true });
  ok(has(res[0].text, /DRY RUN — buzz_post/) && has(res[0].text, /notes\.txt not uploaded/), "attachment previewed as not uploaded");
  ok(r.uploads.length === 0, "no /upload request");
  ok(res[1].isError && !has(res[1].text, /DRY RUN/), `secret path refused even in a dry run (${(res[1].text || "").slice(0, 80)})`);
  ok(nonBoot(r).length === 0, "nothing published");
}

// ---- case E: dry_run buzz_setname leaves the name alone ----
console.log("\ncase E: dry_run buzz_setname — previews kind 0, session name unchanged");
{
  const r = await mockRelay(seed);
  const { res } = await session(agentEnv(r.port), [
    { name: "buzz_setname", args: { name: "renamed-bot", dry_run: true } },
    { name: "buzz_whoami" },
  ]);
  r.close();
  ok(has(res[0].text, /kind 0 \(profile\)/) && has(res[0].text, /renamed-bot/), "kind 0 previewed");
  ok(has(res[1].text, /name: v032-test/), "whoami still shows the original name");
  ok(!nonBoot(r).length && r.published.filter((e) => e.kind === 0).every((e) => !e.content.includes("renamed-bot")), "no renamed profile published");
}

// ---- case F: search filters ----
console.log("\ncase F: buzz_search — from / after / before / in, fail-closed");
{
  const r = await mockRelay(seed);
  const day = new Date((now() - 2 * 86400) * 1000).toISOString().slice(0, 10);
  const { res } = await session(agentEnv(r.port), [
    { name: "buzz_search", args: { query: "deploy", from: "bob" } },
    { name: "buzz_search", args: { query: "deploy", from: "alice" } },
    { name: "buzz_search", args: { query: "deploy", after: "24h" } },
    { name: "buzz_search", args: { query: "deploy", before: day } },
    { name: "buzz_search", args: { query: "deploy", in: "dms" } },
    { name: "buzz_search", args: { query: "deploy", in: "channels" } },
    { name: "buzz_search", args: { from: "bob" } },
    { name: "buzz_search", args: {} },
    { name: "buzz_search", args: { query: "deploy", after: "last tuesday" } },
    { name: "buzz_search", args: { query: "deploy", in: "everywhere" } },
    { name: "buzz_search", args: { query: "deploy", from: "me" } },
    { name: "buzz_search", args: { query: "deploy", after: "1h", before: "2d" } },
  ]);
  r.close();
  const [fromBob, fromAlice, after, before, dms, chans, emptyQ, none, badDate, badIn, fromMe, inverted] = res;
  ok(!fromBob.isError && has(fromBob.text, /from bob/) && fromBob.text.includes("deploy looks good") && fromBob.text.includes("[DM bob") && !fromBob.text.includes("deploy plan v2"), "from bob: only bob's messages (channel + DM rows labelled)");
  ok(r.queries.some((fs) => fs.some((f) => f.search === "deploy" && (f.authors || [])[0] === PK_BOB)), "from → authors filter sent to the relay");
  ok(fromAlice.isError && has(fromAlice.text, /ambiguous|npub/i), "from alice (two keys) refused — fail-closed");
  ok(!after.isError && !after.text.includes("(old)") && after.text.includes("deploy plan v2"), "after 24h excludes the 3-day-old message");
  ok(!before.isError && before.text.includes("(old)") && !before.text.includes("deploy plan v2"), "before <2 days ago> keeps only the old one");
  ok(!dms.isError && dms.text.includes("deploy secret in dm") && !dms.text.includes("deploy plan v2"), "in dms: DM rows only");
  ok(!chans.isError && !chans.text.includes("deploy secret in dm") && chans.text.includes("deploy plan v2"), "in channels: no DM rows");
  ok(!emptyQ.isError && has(emptyQ.text, /\(no text\)/) && emptyQ.text.includes("the plan"), "empty query + from works");
  ok(none.isError && has(none.text, /needs a `query`/), "no query + no filter refused");
  ok(badDate.isError && has(badDate.text, /can't read the time/), "unreadable date refused");
  ok(badIn.isError && has(badIn.text, /`in` must be/), "bad `in` refused");
  ok(!fromMe.isError && has(fromMe.text, /0 result/), "from me resolves to your own key");
  ok(inverted.isError && has(inverted.text, /later than/), "after > before refused");
}

// ---- case G: open-channel browse ----
console.log("\ncase G: buzz_channels scope:\"open\" — open channels only, joined marked, escaped");
{
  const r = await mockRelay(seed);
  const { res } = await session(agentEnv(r.port), [
    { name: "buzz_channels", args: { scope: "open" } },
    { name: "buzz_channels", args: { scope: "everything" } },
    { name: "buzz_channels", args: {} },
  ]);
  r.close();
  const t = res[0].text || "";
  ok(t.includes("#random") && t.includes("#general"), "open channels listed (member + non-member)");
  ok(!t.includes("#secret") && !t.includes(S), "private channel never listed");
  ok(!t.includes(DM), "DM never listed");
  ok(/✓ #general/.test(t) && /  #random/.test(t), "joined marked ✓");
  ok(t.includes("\\u{202e}") && !t.includes("\u202e"), "description escaped");
  ok(res[1].isError, "bad scope refused");
  ok(!res[2].isError && res[2].text.includes("#general") && !res[2].text.includes("#random"), "default scope = member channels");
}

// ---- case H: message links ----
console.log("\ncase H: buzz_message_link — make + open, fail-closed");
{
  const r = await mockRelay(seed);
  const link = `buzz://message?channel=${G}&id=${W.reply.id}&thread=${W.root.id}`;
  const { res } = await session(agentEnv(r.port), [
    { name: "buzz_message_link", args: { channel: "general", event: W.reply.id.slice(0, 8) } },
    { name: "buzz_message_link", args: { channel: "general", event: W.root.id } },
    { name: "buzz_message_link", args: { link } },
    { name: "buzz_message_link", args: { link: `buzz://message?channel=${S}&id=${W.secretMsg.id}` } },
    { name: "buzz_message_link", args: { link: `buzz://message?channel=${G}&id=${W.dmMsg.id}` } },
    { name: "buzz_message_link", args: { link: `buzz://message?channel=${G}&id=${W.root.id}&evil=1` } },
    { name: "buzz_message_link", args: { link, channel: "general" } },
    { name: "buzz_message_link", args: { link: `buzz://message?channel=${DM}&id=${W.dmMsg.id}` } },
  ]);
  r.close();
  ok(res[0].text.startsWith(link), "reply → canonical link with thread=root");
  ok(res[1].text.startsWith(`buzz://message?channel=${G}&id=${W.root.id}\n`), "root → no thread param");
  ok(!res[2].isError && res[2].text.includes("deploy looks good") && res[2].text.includes("\\n") && has(res[2].text, /reply in thread/), "open link → the message (escaped), thread noted");
  ok(res[3].isError && has(res[3].text, /can't read/), "link to a channel you're not in refused");
  ok(res[4].isError && has(res[4].text, /isn't in that channel/), "link whose id lives in another channel refused (h-tag bound)");
  ok(res[5].isError && has(res[5].text, /unknown parameter/), "malformed link refused");
  ok(res[6].isError && has(res[6].text, /either/), "link + channel together refused");
  ok(!res[7].isError && res[7].text.includes("deploy secret in dm"), "DM link opens for a participant");
}

// ---- case I: activity feed ----
console.log("\ncase I: buzz_activity — relay feed, old-relay fallback, error fallback");
{
  const r1 = await mockRelay(seed, { feed: true });
  const a1 = (await session(agentEnv(r1.port), [{ name: "buzz_activity", args: {} }, { name: "buzz_activity", args: { types: ["bogus"] } }])).res;
  r1.close();
  ok(!a1[0].isError && has(a1[0].text, /source: relay feed/) && a1[0].text.includes("deploy review please") && has(a1[0].text, /@you #general/), "relay feed: mention shown with channel label");
  ok(r1.queries.some((fs) => fs.some((f) => Array.isArray(f.feed_types) && (f["#p"] || [])[0] === PK_ME)), "feed query carries feed_types + #p me");
  ok(a1[1].isError && has(a1[1].text, /types/), "bad types refused");
  const r2 = await mockRelay(seed, { feed: false });
  const a2 = (await session(agentEnv(r2.port), [{ name: "buzz_activity", args: {} }])).res;
  r2.close();
  ok(!a2[0].isError && a2[0].text.includes("deploy review please") && !has(a2[0].text, /kind 3900/), "old relay (feed_types ignored): mentions only, membership events filtered");
  const r3 = await mockRelay(seed, { feedError: true });
  const a3 = (await session(agentEnv(r3.port), [{ name: "buzz_activity", args: {} }])).res;
  r3.close();
  ok(!a3[0].isError && has(a3[0].text, /@mention scan/) && a3[0].text.includes("deploy review please"), "feed error → @mention scan fallback, labelled");
}

// ---- case J: files ----
console.log("\ncase J: buzz_files — lists attachments, escaped, nothing downloaded");
{
  const r = await mockRelay(seed);
  const { res } = await session(agentEnv(r.port), [{ name: "buzz_files", args: { channel: "general" } }, { name: "buzz_files", args: { channel: "secret" } }]);
  r.close();
  const t = res[0].text || "";
  ok(!res[0].isError && t.includes("index 0") && t.includes("application/pdf") && t.includes("4.0 KB") && t.includes(`<${W.file.id.slice(0, 8)}>`), "file row: index, mime, size, <id>");
  ok(t.includes("plan\\u{202e}fdp.exe") && !t.includes("\u202e"), "filename escaped (RTLO spoof visible)");
  ok(res[1].isError, "a channel you're not in is refused");
}

// ---- case K: presence ----
console.log("\ncase K: buzz_presence — relay-signed only; no self → refused");
{
  const r = await mockRelay(seed, { self: PK_RELAY, relaySk: hex(SK_RELAY), presence: { [PK_BOB]: "online", [PK_O]: "away" } });
  const { res } = await session(agentEnv(r.port), [
    { name: "buzz_presence", args: { users: ["bob"] } },
    { name: "buzz_presence", args: { channel: "general" } },
    { name: "buzz_presence", args: { users: ["alice"] } },
    { name: "buzz_presence", args: {} },
  ]);
  r.close();
  ok(!res[0].isError && has(res[0].text, /🟢 bob.* — online/), "bob online");
  ok(has(res[1].text, /1 online of 3/) && has(res[1].text, /away/) && has(res[1].text, /⚪ v032-test.* — offline/), "channel members: online / away / offline");
  ok(res[2].isError && has(res[2].text, /ambiguous|npub/i), "ambiguous user refused");
  ok(res[3].isError, "no users/channel refused");
  const forged = await mockRelay(seed, { self: PK_RELAY, relaySk: hex(SK_O), presence: { [PK_BOB]: "online" } });
  const f = (await session(agentEnv(forged.port), [{ name: "buzz_presence", args: { users: ["bob"] } }])).res;
  forged.close();
  ok(!f[0].isError && has(f[0].text, /offline/) && !has(f[0].text, /🟢/), "presence signed by a non-relay key ignored → offline");
  const noself = await mockRelay(seed, { relaySk: hex(SK_RELAY), presence: { [PK_BOB]: "online" } });
  const n = (await session(agentEnv(noself.port), [{ name: "buzz_presence", args: { users: ["bob"] } }])).res;
  noself.close();
  ok(n[0].isError && has(n[0].text, /self/), "no NIP-11 self → refused, not guessed");
}

// ---- case L: custom emoji ----
console.log("\ncase L: buzz_emoji — palette union; unsafe URLs dropped; :shortcode: reactions tagged");
{
  const r = await mockRelay(seed);
  const { res } = await session(agentEnv(r.port), [
    { name: "buzz_emoji", args: {} },
    { name: "buzz_emoji", args: { query: "ship" } },
    { name: "buzz_react", args: { channel: "general", event: W.root.id, emoji: ":shipit:" } },
    { name: "buzz_react", args: { channel: "general", event: W.mention.id, emoji: ":nosuch:" } },
  ]);
  r.close();
  ok(has(res[0].text, /:partyparrot:  https:\/\/cdn\/pp\.gif/) && has(res[0].text, /:shipit:/) && !res[0].text.includes("javascript:"), "palette listed; javascript: URL dropped");
  ok(has(res[1].text, /:shipit:/) && !has(res[1].text, /partyparrot/), "query filters");
  const re = r.published.find((e) => e.kind === 7 && e.content === ":shipit:");
  ok(re && re.tags.some((t) => t[0] === "emoji" && t[1] === "shipit" && t[2] === "https://cdn/ship.png"), "reaction carries the NIP-30 emoji tag");
  const re2 = r.published.find((e) => e.kind === 7 && e.content === ":nosuch:");
  ok(re2 && !re2.tags.some((t) => t[0] === "emoji") && has(res[3].text, /no custom emoji/), "unknown shortcode → no emoji tag, noted");
}

console.log(`\nv032: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
