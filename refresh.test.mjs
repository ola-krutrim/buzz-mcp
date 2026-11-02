// refresh.test.mjs — cross-process refresh single-flight + invalid_grant / backoff policy.
// Regression: several shim processes sharing one rotating refresh replayed spent tokens (invalid_grant,
// family revocation) and kept re-POSTing them.
// Fully offline: a local HTTP mock stands in for Ekam's /oauth/token; HOME is a throwaway dir set
// BEFORE signer.mjs is imported, so ~/.config/buzz-cli of the person running the tests is never touched.
import { mkdtempSync, writeFileSync, readFileSync, existsSync, statSync, readdirSync, mkdirSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const SELF = fileURLToPath(import.meta.url);

// ── child mode: one "shim process" asking for a token ──────────────────────────────────────────
if (process.argv[2] === "--child") {
  const { makeWireTokenProvider } = await import("./signer.mjs");
  const env = { BUZZ_EKAM_BASE: process.env.T_BASE, BUZZ_EKAM_CLIENT_ID: "cid", BUZZ_WIRE_ID: process.env.T_ID };
  const p = makeWireTokenProvider(env, fetch, { log: () => {} });
  const at = Number(process.env.T_AT || 0); // start barrier so both children race for real
  if (at > Date.now()) await new Promise((r) => setTimeout(r, at - Date.now()));
  try { const a = await p.get(); p.stopKeepAlive(); process.stdout.write(JSON.stringify({ ok: true, access: a })); }
  catch (e) { process.stdout.write(JSON.stringify({ ok: false, err: e.message, code: e.code || null })); }
  process.exit(0);
}

const HOME = mkdtempSync(join(tmpdir(), "buzz-refresh-test-"));
process.env.HOME = HOME; process.env.USERPROFILE = HOME;
const S = await import("./signer.mjs");
const { makeWireTokenProvider, wireRefreshSet, wireRefreshGet, wireDeadGet, withWireLock, WIRE_REFRESH_DIR,
  WIRE_INVALID_GRANT_ATTEMPTS_DEFAULT, wireInvalidGrantAttempts, transientBackoffMs, invalidGrantBackoffMs, parseRetryAfter } = S;

let passed = 0, failed = 0;
const ok = (c, m) => { if (c) { passed++; console.log("  ✅ " + m); } else { failed++; console.log("  ❌ " + m); } };
const LOGIN_REMEDY = /buzz-mcp-login|re-run the one-time login|sign-?in expired|refresh (token )?(is )?(invalid|revoked|expired)/i;
const f = (id, ext) => join(WIRE_REFRESH_DIR, id + ext);
const quiet = { log: () => {} };
const json = (status, body, headers = {}) => ({ ok: status >= 200 && status < 300, status, headers: { get: (k) => headers[k.toLowerCase()] ?? null }, text: async () => JSON.stringify(body) });
const IG = () => json(400, { error: "invalid_grant", error_description: "refresh token is invalid" });
const fp = (t) => createHash("sha256").update(String(t)).digest("hex").slice(0, 32); // = signer's .acc binding
const fakeClock = (t0 = 1_800_000_000_000) => { let t = t0; const c = () => t; c.add = (ms) => { t += ms; }; return c; };
const ENV = (id, extra = {}) => ({ BUZZ_EKAM_BASE: "https://ekam.test", BUZZ_EKAM_CLIENT_ID: "cid", BUZZ_WIRE_ID: id, ...extra });
mkdirSync(WIRE_REFRESH_DIR, { recursive: true, mode: 0o700 });

console.log("refresh.test.mjs — cross-process refresh lock + invalid_grant/backoff policy\n");
console.log(`HOME=${HOME}`);

// ── 1. two PROCESSES refreshing at once → exactly ONE /oauth/token call ─────────────────────────
console.log("\ncase 1: two shim processes, same wire id, refresh at the same moment");
{
  const calls = [];
  const srv = createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
      const body = JSON.parse(b); calls.push(body.refresh_token);
      setTimeout(() => {
        if (body.refresh_token === "rt-0" && calls.length === 1) { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ access_token: "acc-1", refresh_token: "rt-1", expires_in: 900 })); }
        else { res.writeHead(400, { "content-type": "application/json" }); res.end('{"error":"invalid_grant","error_description":"refresh_token_replay"}'); }
      }, 400); // latency → the second process arrives while the first is mid-refresh
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  wireRefreshSet("xproc", "rt-0");
  const runChild = (at) => new Promise((resolve) => {
    const p = spawn(process.execPath, [SELF, "--child"], { env: { ...process.env, HOME, T_BASE: base, T_ID: "xproc", T_AT: String(at) }, stdio: ["ignore", "pipe", "inherit"] });
    let out = ""; p.stdout.on("data", (d) => (out += d)); p.on("close", () => { try { resolve(JSON.parse(out)); } catch { resolve({ ok: false, err: out }); } });
  });
  const at = Date.now() + 700;
  const [a, b] = await Promise.all([runChild(at), runChild(at)]);
  ok(calls.length === 1, `exactly ONE /oauth/token call across both processes (got ${calls.length})`);
  ok(calls[0] === "rt-0", "the rotating refresh was presented once — no replay of a spent token");
  ok(a.ok && b.ok && a.access === "acc-1" && b.access === "acc-1", "both processes got the same fresh access token (loser adopted the winner's)");
  ok(wireRefreshGet("xproc") === "rt-1", "rotated refresh persisted");
  ok((statSync(f("xproc", ".tok")).mode & 0o777) === 0o600 && (statSync(f("xproc", ".acc")).mode & 0o777) === 0o600, ".tok and .acc are 0600");
  ok(!existsSync(f("xproc", ".lock")) && !readdirSync(WIRE_REFRESH_DIR).some((n) => /\.tmp|stale/.test(n)), "no leftover lock or temp files");
  const c = await runChild(0);
  ok(c.ok && c.access === "acc-1" && calls.length === 1, "a third process adopts the shared access token — zero extra calls");
  srv.close();
}

// ── 2. invalid_grant: bounded retries (default 3 total), then clear + tombstone + sign-in prompt ─
console.log("\ncase 2: invalid_grant → 3 attempts total with ~2s/~8s backoff, then clear + sign in again");
{
  ok(WIRE_INVALID_GRANT_ATTEMPTS_DEFAULT === 3 && wireInvalidGrantAttempts({}) === 3, "default attempt count is 3");
  ok(wireInvalidGrantAttempts({ BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: "5" }) === 5 && wireInvalidGrantAttempts({ BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: "0" }) === 1 && wireInvalidGrantAttempts({ BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: "99" }) === 10 && wireInvalidGrantAttempts({ BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: "x" }) === 3, "BUZZ_WIRE_INVALID_GRANT_ATTEMPTS override, clamped to 1..10");
  const clock = fakeClock(); const sleeps = []; let calls = 0;
  const sleep = async (ms) => { sleeps.push(ms); clock.add(ms); };
  wireRefreshSet("ig3", "rt-dead");
  const p = makeWireTokenProvider(ENV("ig3", { BUZZ_WIRE_REFRESH: "env-seed" }), async () => { calls++; return IG(); }, { ...quiet, now: clock, sleep });
  let err = null; try { await p.get(); } catch (e) { err = e; }
  ok(calls === 3, `exactly 3 /oauth/token calls (got ${calls})`);
  ok(sleeps.length === 2 && sleeps[0] >= 1500 && sleeps[0] <= 2500 && sleeps[1] >= 6000 && sleeps[1] <= 10000, `backoff between attempts ≈2s then ≈8s with jitter (got ${sleeps.map((s) => Math.round(s / 100) / 10 + "s").join(", ")})`);
  ok(err && err.code === "WIRE_SIGNIN_REQUIRED" && LOGIN_REMEDY.test(err.message) && /buzz_login/.test(err.message) && /buzz-mcp-login/.test(err.message), "surfaces a sign-in-again error naming buzz_login / buzz-mcp-login");
  ok(!existsSync(f("ig3", ".tok")) && !existsSync(f("ig3", ".acc")) && !existsSync(f("ig3", ".state")), "stored refresh (+ access, + backoff state) cleared");
  ok(wireDeadGet("ig3") && wireDeadGet("ig3").reason === "invalid_grant", "persistent .dead tombstone written");
  ok(p.needsSignIn() && !p.hasRefresh(), "provider reports needsSignIn, no refresh (so the 401→force-remint path cannot fire)");
  for (let i = 0; i < 5; i++) { try { await p.get(); } catch {} try { await p.get(true); } catch {} }
  ok(calls === 3, "10 more get() calls → still 3 calls total (never loops)");
  let calls2 = 0;
  const p2 = makeWireTokenProvider(ENV("ig3", { BUZZ_WIRE_REFRESH: "env-seed" }), async () => { calls2++; return IG(); }, quiet);
  let e2 = null; try { await p2.get(); } catch (e) { e2 = e; }
  ok(calls2 === 0 && p2.needsSignIn() && e2 && e2.code === "WIRE_SIGNIN_REQUIRED", "restarted process (same spent env seed) → zero calls, sign-in prompt (cooldown survives restart)");
  let calls3 = 0;
  const p3 = makeWireTokenProvider(ENV("ig3", { BUZZ_WIRE_REFRESH: "a-different-fresh-seed" }), async () => { calls3++; return json(200, { access_token: "acc-fresh", refresh_token: "rt-fresh", expires_in: 900 }); }, quiet);
  ok(p3.hasRefresh() && !p3.needsSignIn() && (await p3.get()) === "acc-fresh" && calls3 === 1, "a DIFFERENT env seed (fresh paste) is accepted after the tombstone");
  p3.stopKeepAlive();
  ok(!existsSync(f("ig3", ".dead")) && wireRefreshGet("ig3") === "rt-fresh", "successful mint after re-login removes the tombstone");
}
for (const [n, want] of [["1", 1], ["5", 5]]) {
  const clock = fakeClock(); const sleeps = []; let calls = 0;
  wireRefreshSet("ign" + n, "rt-dead");
  const p = makeWireTokenProvider(ENV("ign" + n, { BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: n }), async () => { calls++; return IG(); }, { ...quiet, now: clock, sleep: async (ms) => { sleeps.push(ms); clock.add(ms); } });
  let err = null; try { await p.get(); } catch (e) { err = e; }
  ok(calls === want && sleeps.length === want - 1 && err && err.code === "WIRE_SIGNIN_REQUIRED" && !existsSync(f("ign" + n, ".tok")), `BUZZ_WIRE_INVALID_GRANT_ATTEMPTS=${n} → ${want} call(s), ${want - 1} backoff(s), then sign-in (got ${calls}/${sleeps.length})`);
  if (want === 5) ok(sleeps[2] >= 24000 && sleeps[2] <= 40000, `third backoff ≈32s (got ${Math.round(sleeps[2] / 1000)}s)`);
}

// ── 3. another process rotates during the retry window → adopt and stop ─────────────────────────
console.log("\ncase 3: a sibling rotates the token while we wait to retry → use it, stop retrying");
{
  // 3a: sibling wrote BOTH a new refresh and its access token → adopt, zero extra calls
  const clock = fakeClock(); let calls = 0;
  wireRefreshSet("rot", "rt-old");
  const sleep = async (ms) => {
    clock.add(ms);
    wireRefreshSet("rot", "rt-new");
    writeFileSync(f("rot", ".acc"), JSON.stringify({ access_token: "acc-sibling", exp: clock() + 600_000, rt: fp("rt-new") }), { mode: 0o600 });
  };
  const p = makeWireTokenProvider(ENV("rot"), async (_u, init) => { calls++; const rt = JSON.parse(init.body).refresh_token; return rt === "rt-old" ? IG() : json(200, { access_token: "acc-from-new", refresh_token: "rt-newer", expires_in: 900 }); }, { ...quiet, now: clock, sleep });
  const a = await p.get();
  ok(a === "acc-sibling" && calls === 1, `sibling's rotation + access token adopted after the first refusal — no second call (access=${a}, calls=${calls})`);
  ok(!existsSync(f("rot", ".dead")) && !p.needsSignIn(), "no tombstone, still signed in");
  ok(!existsSync(f("rot", ".state")), "invalid_grant counter reset after success");
  p.stopKeepAlive();
}
{
  // 3b: sibling wrote only the new refresh → the retry presents the NEW refresh (never rt-old twice)
  const clock = fakeClock(); const sent = [];
  wireRefreshSet("rot2", "rt-old");
  const p = makeWireTokenProvider(ENV("rot2"), async (_u, init) => { const rt = JSON.parse(init.body).refresh_token; sent.push(rt); return rt === "rt-old" ? IG() : json(200, { access_token: "acc-2", refresh_token: "rt-3", expires_in: 900 }); },
    { ...quiet, now: clock, sleep: async (ms) => { clock.add(ms); wireRefreshSet("rot2", "rt-sibling"); } });
  const a = await p.get();
  ok(a === "acc-2" && sent.join(",") === "rt-old,rt-sibling", `retry re-read the file under the lock and used the sibling's refresh (sent ${sent.join(",")})`);
  ok(wireRefreshGet("rot2") === "rt-3", "and persisted the next rotation");
  p.stopKeepAlive();
}

// ── 4. persistent cooldown: a restart mid-sequence does not restart the cycle ───────────────────
console.log("\ncase 4: process dies between invalid_grant attempts → restart honours the persisted cooldown");
{
  let calls = 0; const clock = fakeClock();
  wireRefreshSet("cool", "rt-x");
  const p1 = makeWireTokenProvider(ENV("cool"), async () => { calls++; return IG(); }, { ...quiet, now: clock, sleep: async () => { throw new Error("process killed"); } });
  try { await p1.get(); } catch {}
  ok(calls === 1 && existsSync(f("cool", ".state")) && existsSync(f("cool", ".tok")), "after attempt 1: state persisted, refresh NOT cleared yet");
  const p2 = makeWireTokenProvider(ENV("cool"), async () => { calls++; return IG(); }, { ...quiet, now: clock, sleep: async (ms) => clock.add(ms) });
  let e = null; try { await p2.get(); } catch (x) { e = x; }
  ok(calls === 1 && e && e.code === "WIRE_REFRESH_BACKOFF" && /attempt 1\/3/.test(e.message), "restarted process inside the window → zero calls, says attempt 1/3 + when it will retry");
  clock.add(3_000);
  try { await p2.get(); } catch (x) { e = x; }
  ok(calls === 3 && e.code === "WIRE_SIGNIN_REQUIRED", `after the window: attempts 2 and 3 only (count continues across restart; total ${calls}), then sign-in`);
}

// ── 5. transient errors: exponential backoff + jitter, Retry-After, ≥30s floor, cap; never cleared ─
console.log("\ncase 5: network / 5xx / 429 → backoff (Retry-After honoured), refresh kept");
{
  ok(transientBackoffMs(1, () => 0) === 1000 && transientBackoffMs(1, () => 1) === 2000, "1st failure: ~1–2s (jittered)");
  ok(transientBackoffMs(2, () => 0) === 30_000 && transientBackoffMs(3, () => 0) === 30_000, "≥30s once failures repeat");
  ok(transientBackoffMs(30, () => 1) === 300_000 && transientBackoffMs(30, () => 0) === 150_000, "capped at 5 min (jitter in [cap/2, cap])");
  ok(transientBackoffMs(1, () => 0, 120_000) === 120_000, "Retry-After wins when longer");
  ok(parseRetryAfter("7") === 7000 && parseRetryAfter("999999") === 3_600_000 && parseRetryAfter(new Date(1_000_090_000).toUTCString(), 1_000_000_000) === 90_000 && parseRetryAfter("soon") === 0, "Retry-After: delta-seconds, HTTP-date, capped at 1h, junk ignored");
  ok(invalidGrantBackoffMs(1, () => 0.5) === 2000 && invalidGrantBackoffMs(2, () => 0.5) === 8000 && invalidGrantBackoffMs(3, () => 0.5) === 32000, "invalid_grant schedule 2s / 8s / 32s (±25% jitter)");

  const clock = fakeClock(); let calls = 0; const seq = [];
  wireRefreshSet("tr", "rt-t");
  let mode = "429";
  const fetchFn = async () => {
    calls++; seq.push(mode);
    if (mode === "429") return json(429, { error: "slow_down" }, { "retry-after": "120" });
    if (mode === "503") return json(503, { error: "unavailable" });
    if (mode === "net") throw Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNRESET" } });
    return json(200, { access_token: "acc-t", refresh_token: "rt-t2", expires_in: 900 });
  };
  const p = makeWireTokenProvider(ENV("tr"), fetchFn, { ...quiet, now: clock, random: () => 0 });
  let e = null; try { await p.get(); } catch (x) { e = x; }
  ok(calls === 1 && e.code === "WIRE_REFRESH_BACKOFF" && e.retryAt - clock() === 120_000, "429 + Retry-After: 120 → next try in exactly 120s");
  for (let i = 0; i < 20; i++) { try { await p.get(); } catch {} }
  clock.add(60_000); try { await p.get(); } catch {}
  ok(calls === 1, "21 calls inside the window → still 1 request");
  const p2 = makeWireTokenProvider(ENV("tr"), fetchFn, { ...quiet, now: clock, random: () => 0 });
  try { await p2.get(); } catch {}
  ok(calls === 1, "a restarted process also honours the window (persisted)");
  clock.add(60_001); mode = "503"; try { await p.get(); } catch (x) { e = x; }
  ok(calls === 2 && e.retryAt - clock() === 30_000, "2nd consecutive failure (503) → ≥30s floor");
  clock.add(30_001); mode = "net"; try { await p.get(); } catch (x) { e = x; }
  ok(calls === 3 && e.transient && /network error/.test(e.message) && e.retryAt - clock() >= 30_000, "network error → transient backoff");
  ok(wireRefreshGet("tr") === "rt-t" && !existsSync(f("tr", ".dead")) && !p.needsSignIn(), "transient failures never clear the refresh or prompt sign-in");
  clock.add(300_001); mode = "ok";
  ok((await p.get()) === "acc-t" && calls === 4 && !existsSync(f("tr", ".state")), "recovers after the window; backoff state cleared");
  p.stopKeepAlive();
}
{
  const clock = fakeClock(); let calls = 0;
  wireRefreshSet("fx", "rt-f");
  const p = makeWireTokenProvider(ENV("fx"), async () => { calls++; return json(403, { error: "access_denied", error_description: "nope" }); }, { ...quiet, now: clock });
  let e = null; try { await p.get(); } catch (x) { e = x; }
  for (let i = 0; i < 5; i++) { try { await p.get(); } catch {} }
  ok(calls === 1 && e.retryAt - clock() >= 300_000 && wireRefreshGet("fx") === "rt-f", "other 4xx (403 access_denied) → one call, 5-min backoff, refresh NOT cleared");
}
{
  const clock = fakeClock(); let calls = 0;
  wireRefreshSet("ic", "rt-c");
  const p = makeWireTokenProvider(ENV("ic", { BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: "2" }), async () => { calls++; return json(401, { error: "invalid_client" }); }, { ...quiet, now: clock, sleep: async (ms) => clock.add(ms) });
  let e = null; try { await p.get(); } catch (x) { e = x; }
  ok(calls === 2 && e.code === "WIRE_SIGNIN_REQUIRED" && wireDeadGet("ic").reason === "invalid_client", "invalid_client follows the same bounded-then-sign-in path");
}

// ── 6. cross-process tombstone + the lock itself ─────────────────────────────────────────────────
console.log("\ncase 6: tombstone seen by a sibling; stale/live locks");
{
  let calls = 0; const clock = fakeClock(Date.now()); // real-ish epoch: b later reads b2's real-clock .acc
  wireRefreshSet("sib", "rt-s");
  const fetchFn = async () => { calls++; return IG(); };
  const a = makeWireTokenProvider(ENV("sib", { BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: "1" }), fetchFn, { ...quiet, now: clock });
  const b = makeWireTokenProvider(ENV("sib"), fetchFn, { ...quiet, now: clock }); // loaded the same refresh earlier
  try { await a.get(); } catch {}
  let e = null; try { await b.get(); } catch (x) { e = x; }
  ok(calls === 1 && e && e.code === "WIRE_SIGNIN_REQUIRED" && b.needsSignIn(), "sibling holding the same (refused) refresh → sees the tombstone under the lock, zero calls");
  wireRefreshSet("sib", "rt-relogin");
  let calls2 = 0;
  const b2 = makeWireTokenProvider(ENV("sib"), async () => { calls2++; return json(200, { access_token: "acc-r", refresh_token: "rt-r2", expires_in: 900 }); }, quiet);
  ok((await b2.get()) === "acc-r", "fresh login on disk → new process works");
  // the long-lived signed-out provider b revives from disk without a restart (adopts b2's access token)
  ok((await b.get()) === "acc-r" && calls === 1 && !b.needsSignIn(), "signed-out sibling revives from the fresh login on disk — no restart, no extra call");
  b.stopKeepAlive();
  ok(!existsSync(f("sib", ".dead")), "tombstone removed by the fresh login");
  b2.stopKeepAlive();
}
{
  // stale lock: holder pid is dead → broken, refresh proceeds
  const dead = spawn(process.execPath, ["-e", "0"]); const deadPid = dead.pid; await new Promise((r) => dead.on("close", r));
  wireRefreshSet("lk", "rt-l");
  writeFileSync(f("lk", ".lock"), JSON.stringify({ pid: deadPid, host: (await import("node:os")).hostname(), t: Date.now(), n: "x" }), { mode: 0o600 });
  let calls = 0;
  const p = makeWireTokenProvider(ENV("lk"), async () => { calls++; return json(200, { access_token: "acc-l", refresh_token: "rt-l2", expires_in: 900 }); }, { ...quiet, lock: { timeoutMs: 3000 } });
  ok((await p.get()) === "acc-l" && calls === 1 && !existsSync(f("lk", ".lock")), "lock held by a dead pid is broken; refresh proceeds; lock released");
  p.stopKeepAlive();
  // live lock (this very process holds it) → waiter times out as a TRANSIENT error, makes no call
  writeFileSync(f("lk", ".lock"), JSON.stringify({ pid: process.pid, host: (await import("node:os")).hostname(), t: Date.now(), n: "live" }), { mode: 0o600 });
  let calls2 = 0;
  const q = makeWireTokenProvider(ENV("lk"), async () => { calls2++; return IG(); }, { ...quiet, lock: { timeoutMs: 300 } });
  let e = null; try { await q.get(true); } catch (x) { e = x; }
  ok(calls2 === 0 && e && e.transient, `live lock → waiter gives up after its timeout without calling Ekam (${e && e.message.slice(0, 60)})`);
  unlinkSync(f("lk", ".lock"));
  // very old lock → stale by age even if the pid looks alive
  writeFileSync(f("lk", ".lock"), JSON.stringify({ pid: process.pid, host: "other-host", t: Date.now() - 120_000, n: "old" }), { mode: 0o600 });
  const r = await withWireLock("lk", async () => "got-it", { timeoutMs: 2000 });
  ok(r === "got-it" && !existsSync(f("lk", ".lock")), "lock older than staleMs is broken");
}

console.log(`\n${failed ? "FAIL" : "ALL PASS"}: ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
