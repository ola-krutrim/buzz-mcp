// attach-relay.test.mjs — `node attach-relay.test.mjs`
// attach-hardening review round 1 (buzz_security HOLD, must-fix 1): drives the REAL shim over stdio
// against an in-process mock relay whose upload descriptor type is controlled per case, and asserts
// that the posted label / imeta filename / extension come from the shim's LOCAL classification and
// that a descriptor type that disagrees with it is refused (nothing posted). Fully offline.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, copyFileSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { createServer } from "node:http";
import { getPublicKey, finalizeEvent } from "nostr-tools/pure";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHIM = join(HERE, "buzz-mcp.mjs");
const FIX = join(HERE, "fixtures", "uploads");
let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✅ " + m)) : (fail++, console.log("  ❌ " + m)));

const hex = (b) => Uint8Array.from(Buffer.from(b, "hex"));
const SK_ME = "a1".repeat(32), PK_ME = getPublicKey(hex(SK_ME));
const SK_O = "b2".repeat(32);
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
  if (f.since && e.created_at < f.since) return false;
  if (f.until && e.created_at > f.until) return false;
  return true;
}
async function mockRelay(seed, { wireSk, eventsError, ekamAllowed, uploadType, uploadUrl } = {}) {
  const uploads = [], mediaGets = [];
  const store = [...seed];
  const published = [];
  const wireSigned = [];
  const srv = createServer((rq, rs) => {
    const chunks = []; let body = ""; rq.on("data", (c) => { chunks.push(c); body += c; });
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
      if (rq.method === "GET" && rq.url.startsWith("/media/")) { mediaGets.push(rq.url); rs.writeHead(404); return rs.end(); }
      if (rq.method === "GET") return reply({ name: "mock", version: "0", software_sha: "deadbeef" });
      if (rq.url === "/events" && eventsError) return reply({ error: eventsError }, 500);
      if (rq.url === "/events") {
        let ev = null; try { ev = JSON.parse(body); } catch {}
        if (ev) { published.push(ev); store.push(ev); }
        return reply({ message: "response:{}" });
      }
      if (rq.url === "/query") {
        let filters = []; try { filters = JSON.parse(body); } catch {}
        const out = [];
        for (const f of filters) {
          const hits = store.filter((e) => match(f, e)).sort((a, b) => b.created_at - a.created_at);
          for (const h of hits.slice(0, f.limit || 500)) if (!out.includes(h)) out.push(h);
        }
        return reply(out);
      }
      if (rq.url === "/upload" && rq.method === "PUT") {
        const bytes = Buffer.concat(chunks), sent = rq.headers["content-type"], sha = rq.headers["x-sha-256"];
        const type = uploadType ? uploadType(sent, bytes) : sent;
        uploads.push({ sent, type, size: bytes.length });
        const d = { sha256: sha, size: bytes.length };
        if (type !== undefined) d.type = type;
        if (uploadUrl) d.url = uploadUrl(sha, type);
        return reply(d);
      }
      if (rq.url === "/profiles/search") return reply([], 404);
      reply({});
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { port: srv.address().port, uploads, mediaGets, published, wireSigned, store, close: () => srv.close() };
}

// ---- one shim session, several sequential calls; resolves each reply by id ----
async function session(env, calls, { perCallMs = 4000 } = {}) {
  const home = mkdtempSync(join(tmpdir(), "attrelay-home-"));
  const p = spawn("node", [SHIM], {
    env: { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), BUZZ_AUTH_TAG: "", BUZZ_NAME: "attrelay-test", BUZZ_WIRE_SIGN: "", ...env },
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

const CH = "chanA";
function world(extra = []) {
  const t = now() - 600;
  return [sign(SK_O, 39000, [["d", CH], ["name", "general"]], "", t), sign(SK_O, 39002, [["d", CH], ["p", PK_ME], ["p", getPublicKey(hex(SK_O))]], "", t), ...extra];
}
const agentEnv = (port, extra = {}) => ({ BUZZ_PRIVATE_KEY: SK_ME, BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`, ...extra });
const DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
const XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
const imeta = (e) => (e.tags || []).filter((t) => t[0] === "imeta").map((t) => t.slice(1));
const field = (im, k) => (im.find((p) => p.startsWith(k + " ")) || "").slice(k.length + 1);
const work = realpathSync(mkdtempSync(join(tmpdir(), "attrelay-")));
copyFileSync(join(FIX, "docx-main-past-4k.docx"), join(work, "Q3 report.zip"));    // real docx, misnamed .zip
copyFileSync(join(FIX, "libreoffice.xlsx"), join(work, "budget.xlsx"));
writeFileSync(join(work, "notes.md"), "# notes\nplain text\n");
writeFileSync(join(work, "scan.pdf"), "%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n");

console.log("\ncase 1: relay stores a real docx as application/zip → posted as .docx from the LOCAL type");
{
  const r = await mockRelay(world(), { uploadType: (sent) => (sent === DOCX ? "application/zip" : sent), uploadUrl: (sha, type) => `http://127.0.0.1:1/media/${sha}.${type === "application/zip" ? "zip" : "x"}` });
  const { res } = await session(agentEnv(r.port), [{ name: "buzz_post", args: { channel: "general", text: "the report", attachment: join(work, "Q3 report.zip") } }], { perCallMs: 8000 });
  r.close();
  const post = r.published.find((e) => e.kind === 9);
  const im = post ? imeta(post)[0] || [] : [];
  console.log("  client sees: " + (res[0].text || "").split("\n")[0].slice(0, 200));
  ok(r.uploads[0] && r.uploads[0].sent === DOCX && r.uploads[0].type === "application/zip", "shim uploaded with its own type (docx); relay answered application/zip");
  ok(!res[0].isError && post, "post accepted (zip descriptor for a locally-classified docx)");
  ok(post && /\[Q3 report\.docx\]\(http:\/\/127\.0\.0\.1:1\/media\/[0-9a-f]{64}\.zip\)/.test(post.content), "label is [Q3 report.docx](<relay url>) — extension from the local type, not .zip/.txt");
  ok(field(im, "filename") === "Q3 report.docx", `imeta filename = ${JSON.stringify(field(im, "filename"))}`);
  ok(field(im, "m") === "application/zip", `imeta m = relay's stored type (${field(im, "m")})`);
}

console.log("\ncase 2: descriptor type disagrees with the local type → refused, nothing posted");
for (const [file, lie] of [["scan.pdf", "application/zip"], ["scan.pdf", "text/html"], ["budget.xlsx", DOCX], ["notes.md", "text/html"], ["notes.md", "image/svg+xml"], ["scan.pdf", undefined]]) {
  const r = await mockRelay(world(), { uploadType: () => lie });
  const { res } = await session(agentEnv(r.port), [{ name: "buzz_post", args: { channel: "general", text: "x", attachment: join(work, file) } }], { perCallMs: 8000 });
  r.close();
  const t = res[0].text || "";
  ok(r.uploads.length === 1 && res[0].isError && /refused — the relay stored it as/.test(t) && t.includes(lie === undefined ? "(no type)" : lie) && !r.published.some((e) => e.kind === 9), `${file} stored as ${lie === undefined ? "(no type)" : lie} → refused, names both types, no kind-9`);
}

console.log("\ncase 3: agreeing descriptors still post (xlsx as itself, text as octet-stream)");
{
  const r = await mockRelay(world(), { uploadType: (sent) => sent });
  const { res } = await session(agentEnv(r.port), [
    { name: "buzz_post", args: { channel: "general", text: "sheet", attachment: join(work, "budget.xlsx") } },
    { name: "buzz_post", args: { channel: "general", text: "md", attachment: join(work, "notes.md") } },
  ], { perCallMs: 8000 });
  r.close();
  const posts = r.published.filter((e) => e.kind === 9);
  ok(!res[0].isError && posts[0] && field(imeta(posts[0])[0], "filename") === "budget.xlsx" && field(imeta(posts[0])[0], "m") === XLSX, "xlsx stored as xlsx → posted, filename budget.xlsx");
  ok(!res[1].isError && posts[1] && /\[notes\.md\]\(/.test(posts[1].content) && field(imeta(posts[1])[0], "m") === "application/octet-stream", "notes.md as octet-stream → posted as [notes.md](…)");
}

console.log("\ncase 4: attachment_read refuses a media URL that is not /media/<imeta x>[.<ext>] (never fetched)");
{
  const X = "ab".repeat(32);
  const mk = (url, ts) => sign(SK_O, 9, [["h", CH], ["imeta", `url ${url}`, `x ${X}`, "m application/pdf", "filename a.pdf"]], "file", now() - ts);
  const bad = [mk("http://127.0.0.1:1/media/" + "cd".repeat(32) + ".pdf", 100), mk("http://127.0.0.1:1/media/" + X + ".pdf%2f..%2f..%2fetc", 90), mk("http://127.0.0.1:1/upload?x=" + X, 80)];
  const r = await mockRelay(world(bad));
  const { res } = await session(agentEnv(r.port), bad.map((e) => ({ name: "buzz_attachment_read", args: { channel: "general", event: e.id } })), { perCallMs: 6000 });
  r.close();
  for (const x of res) console.log("  client sees: " + (x.text || "").slice(0, 160));
  ok(res[0].isError && /≠ imeta x/.test(res[0].text || ""), "URL sha ≠ imeta x → refused");
  ok(res[1].isError && /not \/media\/<sha256>/.test(res[1].text || ""), "encoded path tail → refused");
  ok(res[2].isError && /not \/media\/<sha256>/.test(res[2].text || ""), "non-/media URL → refused");
  ok(r.mediaGets.length === 0, `nothing fetched (${r.mediaGets.length} /media GETs)`);
}

rmSync(work, { recursive: true, force: true });
console.log(`\n${fail === 0 ? "ALL PASS" : "FAILURES"}: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
