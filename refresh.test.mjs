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

// ── child mode: a process contending for the lock on a STALE lock file (case 8 stress) ──────────
if (process.argv[2] === "--lockchild") {
  const { withWireLock } = await import("./signer.mjs");
  const { appendFileSync } = await import("node:fs");
  const at = Number(process.env.T_AT || 0);
  if (at > Date.now()) await new Promise((r) => setTimeout(r, at - Date.now()));
  try {
    await withWireLock(process.env.T_ID, async ({ owns }) => {
      appendFileSync(process.env.T_LOG, `E ${process.pid}\n`);
      await new Promise((r) => setTimeout(r, 120));
      appendFileSync(process.env.T_LOG, `X ${process.pid} ${owns() ? 1 : 0}\n`);
    }, { timeoutMs: 20_000, pollMs: 5 });
    process.stdout.write("ok");
  } catch (e) { process.stdout.write("err " + e.message); }
  process.exit(0);
}

// ── child mode: one "shim process" asking for a token ──────────────────────────────────────────
if (process.argv[2] === "--child") {
  const { makeWireTokenProvider } = await import("./signer.mjs");
  const env = { BUZZ_EKAM_BASE: process.env.T_BASE, BUZZ_EKAM_CLIENT_ID: "cid", BUZZ_WIRE_ID: process.env.T_ID };
  const p = makeWireTokenProvider(env, fetch, { log: () => {} });
  const at = Number(process.env.T_AT || 0); // start barrier so both children race for real
  if (at > Date.now()) await new Promise((r) => setTimeout(r, at - Date.now()));
  if (process.env.T_STARTUP) { // startup-keepalive child: never calls get(); only the startup timer may mint
    const p2 = makeWireTokenProvider(env, fetch, { log: () => {}, startupKeepAlive: { minMs: 50, maxMs: 400 } });
    await new Promise((r) => setTimeout(r, Number(process.env.T_STARTUP)));
    const pend = p2.keepAlivePending(); p2.stopKeepAlive(); p.stopKeepAlive();
    process.stdout.write(JSON.stringify({ ok: true, pend }));
    process.exit(0);
  }
  try { const a = await p.get(); p.stopKeepAlive(); process.stdout.write(JSON.stringify({ ok: true, access: a })); }
  catch (e) { process.stdout.write(JSON.stringify({ ok: false, err: e.message, code: e.code || null })); }
  process.exit(0);
}

const HOME = mkdtempSync(join(tmpdir(), "buzz-refresh-test-"));
process.env.HOME = HOME; process.env.USERPROFILE = HOME;
const S = await import("./signer.mjs");
const { makeWireTokenProvider, wireRefreshSet, wireRefreshGet, wireDeadGet, withWireLock, WIRE_REFRESH_DIR,
  WIRE_INVALID_GRANT_ATTEMPTS_DEFAULT, WIRE_INVALID_GRANT_ATTEMPTS_MAX, WIRE_FINAL_REFUSAL_RE, breakStaleLock, wireInvalidGrantAttempts, transientBackoffMs, invalidGrantBackoffMs, parseRetryAfter } = S;

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

// ── 2. invalid_grant: bounded retries (v0.2.37: default 1, cap 3), then clear + tombstone + sign-in prompt ─
console.log("\ncase 2: invalid_grant → default 1 attempt (no retry); opt-in up to 3 with ~2s/~8s backoff; then clear + sign in again");
{
  ok(WIRE_INVALID_GRANT_ATTEMPTS_DEFAULT === 1 && wireInvalidGrantAttempts({}) === 1 && WIRE_INVALID_GRANT_ATTEMPTS_MAX === 3, "default attempt count is 1, cap 3 (buzz_security Decision 1)");
  ok(wireInvalidGrantAttempts({ BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: "2" }) === 2 && wireInvalidGrantAttempts({ BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: "3" }) === 3 && wireInvalidGrantAttempts({ BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: "5" }) === 3 && wireInvalidGrantAttempts({ BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: "0" }) === 1 && wireInvalidGrantAttempts({ BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: "99" }) === 3 && wireInvalidGrantAttempts({ BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: "x" }) === 1, "BUZZ_WIRE_INVALID_GRANT_ATTEMPTS override, clamped to 1..3; junk → default 1");
  {
    const clock = fakeClock(); const sleeps = []; let calls = 0;
    wireRefreshSet("ig1", "rt-dead");
    const p = makeWireTokenProvider(ENV("ig1"), async () => { calls++; return IG(); }, { ...quiet, now: clock, sleep: async (ms) => { sleeps.push(ms); clock.add(ms); } });
    let err = null; try { await p.get(); } catch (e) { err = e; }
    ok(calls === 1 && sleeps.length === 0 && err && err.code === "WIRE_SIGNIN_REQUIRED" && !existsSync(f("ig1", ".tok")) && wireDeadGet("ig1"), `default (env unset) → exactly 1 /oauth/token call, no backoff, then sign-in + tombstone (got ${calls}/${sleeps.length})`);
    for (let i = 0; i < 3; i++) { try { await p.get(true); } catch {} }
    ok(calls === 1, "further get() calls → still 1 call total");
  }
  // replay / family revoked in error_description → final at once, even with attempts=3
  ok(WIRE_FINAL_REFUSAL_RE.test("refresh_token_replay") && WIRE_FINAL_REFUSAL_RE.test("Replay detected") && WIRE_FINAL_REFUSAL_RE.test("token family revoked") && WIRE_FINAL_REFUSAL_RE.test("family_revoked") && !WIRE_FINAL_REFUSAL_RE.test("refresh token is invalid") && !WIRE_FINAL_REFUSAL_RE.test("refresh token expired"), "final-refusal matcher: replay / family revoked yes; plain invalid / expired no");
  for (const desc of ["refresh_token_replay", "replay detected", "token family revoked", "family_revoked"]) {
    const clock = fakeClock(); const sleeps = []; let calls = 0; const id = "igf-" + desc.replace(/\W/g, "");
    wireRefreshSet(id, "rt-dead");
    const p = makeWireTokenProvider(ENV(id, { BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: "3" }), async () => { calls++; return json(400, { error: "invalid_grant", error_description: desc }); }, { ...quiet, now: clock, sleep: async (ms) => { sleeps.push(ms); clock.add(ms); } });
    let err = null; try { await p.get(); } catch (e) { err = e; }
    ok(calls === 1 && sleeps.length === 0 && err && err.code === "WIRE_SIGNIN_REQUIRED" && /final/.test(err.message) && !existsSync(f(id, ".tok")) && wireDeadGet(id), `attempts=3 but error_description "${desc}" → final after 1 call, no retry, tombstone (got ${calls})`);
  }
  {
    // a replay refusal on a LATER attempt also stops at once (attempt 2 of 3 → no attempt 3)
    const clock = fakeClock(); let calls = 0;
    wireRefreshSet("igf2", "rt-dead");
    const p = makeWireTokenProvider(ENV("igf2", { BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: "3" }), async () => { calls++; return calls === 1 ? IG() : json(400, { error: "invalid_grant", error_description: "refresh_token_replay" }); }, { ...quiet, now: clock, sleep: async (ms) => clock.add(ms) });
    let err = null; try { await p.get(); } catch (e) { err = e; }
    ok(calls === 2 && err && err.code === "WIRE_SIGNIN_REQUIRED", `plain invalid_grant then replay → stops at attempt 2 of 3 (got ${calls})`);
  }
  const clock = fakeClock(); const sleeps = []; let calls = 0;
  const sleep = async (ms) => { sleeps.push(ms); clock.add(ms); };
  wireRefreshSet("ig3", "rt-dead");
  const p = makeWireTokenProvider(ENV("ig3", { BUZZ_WIRE_REFRESH: "env-seed", BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: "3" }), async () => { calls++; return IG(); }, { ...quiet, now: clock, sleep });
  let err = null; try { await p.get(); } catch (e) { err = e; }
  ok(calls === 3, `BUZZ_WIRE_INVALID_GRANT_ATTEMPTS=3 (the cap) → exactly 3 /oauth/token calls (got ${calls})`);
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
for (const [n, want] of [["1", 1], ["2", 2], ["5", 3]]) {
  const clock = fakeClock(); const sleeps = []; let calls = 0;
  wireRefreshSet("ign" + n, "rt-dead");
  const p = makeWireTokenProvider(ENV("ign" + n, { BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: n }), async () => { calls++; return IG(); }, { ...quiet, now: clock, sleep: async (ms) => { sleeps.push(ms); clock.add(ms); } });
  let err = null; try { await p.get(); } catch (e) { err = e; }
  ok(calls === want && sleeps.length === want - 1 && err && err.code === "WIRE_SIGNIN_REQUIRED" && !existsSync(f("ign" + n, ".tok")), `BUZZ_WIRE_INVALID_GRANT_ATTEMPTS=${n} → ${want} call(s), ${want - 1} backoff(s), then sign-in (got ${calls}/${sleeps.length})`);
  if (n === "5") ok(sleeps.length === 2, `BUZZ_WIRE_INVALID_GRANT_ATTEMPTS=5 is capped at 3 (no ≈32s third backoff; got ${sleeps.length} backoffs)`);
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
  const p = makeWireTokenProvider(ENV("rot", { BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: "3" }), async (_u, init) => { calls++; const rt = JSON.parse(init.body).refresh_token; return rt === "rt-old" ? IG() : json(200, { access_token: "acc-from-new", refresh_token: "rt-newer", expires_in: 900 }); }, { ...quiet, now: clock, sleep });
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
  const p = makeWireTokenProvider(ENV("rot2", { BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: "3" }), async (_u, init) => { const rt = JSON.parse(init.body).refresh_token; sent.push(rt); return rt === "rt-old" ? IG() : json(200, { access_token: "acc-2", refresh_token: "rt-3", expires_in: 900 }); },
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
  const p1 = makeWireTokenProvider(ENV("cool", { BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: "3" }), async () => { calls++; return IG(); }, { ...quiet, now: clock, sleep: async () => { throw new Error("process killed"); } });
  try { await p1.get(); } catch {}
  ok(calls === 1 && existsSync(f("cool", ".state")) && existsSync(f("cool", ".tok")), "after attempt 1: state persisted, refresh NOT cleared yet");
  const p2 = makeWireTokenProvider(ENV("cool", { BUZZ_WIRE_INVALID_GRANT_ATTEMPTS: "3" }), async () => { calls++; return IG(); }, { ...quiet, now: clock, sleep: async (ms) => clock.add(ms) });
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

// ── startup-keepalive: the first keep-alive refresh fires at process start, not only after a mint ──
console.log("\ncase 7: startup keep-alive (Ekam 7-day sliding refresh idle)");
const waitFor = async (cond, ms = 3000) => { const t0 = Date.now(); while (!cond() && Date.now() - t0 < ms) await new Promise((r) => setTimeout(r, 10)); return cond(); };
{
  // stored token → exactly one startup refresh, minimal body, then a normal renew is scheduled
  wireRefreshSet("sk1", "rt-s1");
  const bodies = [];
  const p = makeWireTokenProvider(ENV("sk1"), async (_u, init) => { bodies.push(JSON.parse(init.body)); return json(200, { access_token: "acc-s1", refresh_token: "rt-s2", expires_in: 900 }); }, { ...quiet, startupKeepAlive: { delayMs: 20 } });
  ok(p.keepAlivePending().startup && bodies.length === 0, "startup timer armed at construction; no network call yet");
  await waitFor(() => bodies.length >= 1 && !p.keepAlivePending().startup);
  await new Promise((r) => setTimeout(r, 100));
  ok(bodies.length === 1, `startup keep-alive fired exactly once with a stored token (got ${bodies.length})`);
  ok(bodies[0] && Object.keys(bodies[0]).sort().join(",") === "client_id,grant_type,refresh_token" && bodies[0].refresh_token === "rt-s1", "refresh body unchanged: {grant_type, refresh_token, client_id} only");
  ok(wireRefreshGet("sk1") === "rt-s2", "rotated refresh persisted by the startup refresh");
  const pend = p.keepAlivePending();
  ok(!pend.startup && pend.renew, "after the startup refresh the regular ~75% renew timer takes over");
  ok((await p.get()) === "acc-s1" && bodies.length === 1, "first tool call reuses the startup token — no extra mint");
  p.stopKeepAlive();
}
{
  // no stored token → nothing scheduled, never any call (and never an interactive login)
  let calls = 0;
  const p = makeWireTokenProvider(ENV("sk-none"), async () => { calls++; return json(200, { access_token: "x", expires_in: 900 }); }, { ...quiet, startupKeepAlive: { delayMs: 5 } });
  await new Promise((r) => setTimeout(r, 80));
  ok(calls === 0 && !p.keepAlivePending().startup && !p.keepAlivePending().renew, "no stored token → no startup timer, no /oauth/token call");
  // env-only seed (no <id>.tok) → also no startup refresh (only a STORED token qualifies)
  const q = makeWireTokenProvider(ENV("sk-envonly", { BUZZ_WIRE_REFRESH: "seed-only" }), async () => { calls++; return json(200, { access_token: "x", expires_in: 900 }); }, { ...quiet, startupKeepAlive: { delayMs: 5 } });
  await new Promise((r) => setTimeout(r, 80));
  ok(calls === 0 && !q.keepAlivePending().startup, "env-only seed (no .tok) → no startup refresh");
  // static token alongside a stored refresh → no startup refresh
  wireRefreshSet("sk-static", "rt-st");
  const r = makeWireTokenProvider(ENV("sk-static", { BUZZ_EKAM_HUMAN_TOKEN: "static-tok" }), async () => { calls++; return json(200, { access_token: "x", expires_in: 900 }); }, { ...quiet, startupKeepAlive: { delayMs: 5 } });
  await new Promise((r2) => setTimeout(r2, 80));
  ok(calls === 0 && !r.keepAlivePending().startup, "static BUZZ_EKAM_HUMAN_TOKEN → no startup refresh");
  // tombstoned id → no startup refresh
  writeFileSync(f("sk-dead", ".dead"), JSON.stringify({ at: "x", reason: "invalid_grant", seed: null }), { mode: 0o600 });
  const d = makeWireTokenProvider(ENV("sk-dead"), async () => { calls++; return json(200, { access_token: "x", expires_in: 900 }); }, { ...quiet, startupKeepAlive: { delayMs: 5 } });
  await new Promise((r2) => setTimeout(r2, 80));
  ok(calls === 0 && !d.keepAlivePending().startup && d.needsSignIn(), "signed-out (tombstone) → no startup refresh");
  // provider default (opt not set) → off: only resolveSigner (stdio wire mode) turns it on
  wireRefreshSet("sk-default", "rt-d");
  const e = makeWireTokenProvider(ENV("sk-default"), async () => { calls++; return json(200, { access_token: "x", expires_in: 900 }); }, quiet);
  ok(!e.keepAlivePending().startup, "makeWireTokenProvider without startupKeepAlive → no startup timer (opt-in)");
}
{
  // two signers sharing one token file at startup → exactly ONE mint; the other adopts via the lock
  wireRefreshSet("sk2", "rt-a");
  const sent = [];
  const fetchFn = async (_u, init) => { const rt = JSON.parse(init.body).refresh_token; sent.push(rt); await new Promise((r) => setTimeout(r, 150)); return rt === "rt-a" && sent.length === 1 ? json(200, { access_token: "acc-a", refresh_token: "rt-b", expires_in: 900 }) : IG(); };
  const a = makeWireTokenProvider(ENV("sk2"), fetchFn, { ...quiet, startupKeepAlive: { delayMs: 10 } });
  const b = makeWireTokenProvider(ENV("sk2"), fetchFn, { ...quiet, startupKeepAlive: { delayMs: 12 } });
  await waitFor(() => !a.keepAlivePending().startup && !b.keepAlivePending().startup && a.keepAlivePending().renew && b.keepAlivePending().renew);
  ok(sent.length === 1 && sent[0] === "rt-a", `two signers at startup → exactly one /oauth/token call (got ${sent.length})`);
  ok((await a.get()) === "acc-a" && (await b.get()) === "acc-a" && sent.length === 1, "both hold the same fresh access token; the loser adopted it from shared storage");
  ok(wireRefreshGet("sk2") === "rt-b" && !existsSync(f("sk2", ".lock")), "rotated refresh on disk; lock released");
  a.stopKeepAlive(); b.stopKeepAlive();
  // a third signer starting now adopts the shared access token at construction → renew only, no startup mint
  const c = makeWireTokenProvider(ENV("sk2"), fetchFn, { ...quiet, startupKeepAlive: { delayMs: 5 } });
  await new Promise((r) => setTimeout(r, 60));
  ok(sent.length === 1 && !c.keepAlivePending().startup && c.keepAlivePending().renew, "a later signer adopts the sibling's access token → schedules a renew, makes no call");
  c.stopKeepAlive();
}
{
  // two PROCESSES starting together, neither making a tool call → exactly one mint (cross-process lock)
  const calls = [];
  const srv = createServer((req, res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
    calls.push(JSON.parse(b).refresh_token);
    setTimeout(() => { res.writeHead(calls.length === 1 ? 200 : 400, { "content-type": "application/json" }); res.end(calls.length === 1 ? JSON.stringify({ access_token: "acc-x1", refresh_token: "rt-x1", expires_in: 900 }) : '{"error":"invalid_grant"}'); }, 200);
  }); });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  wireRefreshSet("skx", "rt-x0");
  const runChild = () => new Promise((resolve) => {
    const p = spawn(process.execPath, [SELF, "--child"], { env: { ...process.env, HOME, T_BASE: base, T_ID: "skx", T_STARTUP: "1500" }, stdio: ["ignore", "pipe", "inherit"] });
    let out = ""; p.stdout.on("data", (d) => (out += d)); p.on("close", () => { try { resolve(JSON.parse(out)); } catch { resolve({ ok: false, err: out }); } });
  });
  const [x, y] = await Promise.all([runChild(), runChild()]);
  ok(x.ok && y.ok && calls.length === 1 && calls[0] === "rt-x0", `two shim processes at startup → exactly ONE /oauth/token call (got ${calls.length})`);
  ok(wireRefreshGet("skx") === "rt-x1" && x.pend.renew && y.pend.renew && !x.pend.startup && !y.pend.startup, "both processes moved on to the regular renew timer");
  srv.close();
}
{
  // stopKeepAlive clears the startup timer (nothing fires afterwards)
  wireRefreshSet("sk3", "rt-c");
  let calls = 0;
  const p = makeWireTokenProvider(ENV("sk3"), async () => { calls++; return json(200, { access_token: "acc-c", expires_in: 900 }); }, { ...quiet, startupKeepAlive: { delayMs: 40 } });
  ok(p.keepAlivePending().startup, "startup timer pending");
  p.stopKeepAlive();
  await new Promise((r) => setTimeout(r, 120));
  ok(!p.keepAlivePending().startup && calls === 0, "stopKeepAlive() cleared the startup timer — no refresh fired");
  // a tool call before the startup timer fires supersedes it (no second mint)
  const q = makeWireTokenProvider(ENV("sk3"), async () => { calls++; return json(200, { access_token: "acc-c2", refresh_token: "rt-c2", expires_in: 900 }); }, { ...quiet, startupKeepAlive: { delayMs: 60 } });
  ok((await q.get()) === "acc-c2" && calls === 1 && !q.keepAlivePending().startup, "an early tool call mints once and cancels the pending startup timer");
  await new Promise((r) => setTimeout(r, 120));
  ok(calls === 1, "no second mint from the cancelled startup timer");
  q.stopKeepAlive();
}
{
  // failure at startup → logged to stderr-style log, falls back to on-demand
  wireRefreshSet("sk4", "rt-f");
  const logs = [];
  let calls = 0;
  const p = makeWireTokenProvider(ENV("sk4"), async () => { calls++; return json(503, { error: "temporarily_unavailable" }); }, { log: (m) => logs.push(m), startupKeepAlive: { delayMs: 5 } });
  await waitFor(() => logs.length > 0);
  ok(calls === 1 && logs.some((m) => /startup keep-alive failed .*retry on next call/.test(m)), "startup failure is logged and falls back to on-demand");
  ok(wireRefreshGet("sk4") === "rt-f" && !p.needsSignIn(), "a transient startup failure keeps the stored refresh");
  p.stopKeepAlive();
}
{
  // delay helper: jittered within [min, max]
  ok(S.startupKeepAliveDelayMs(() => 0) === S.STARTUP_KEEPALIVE_MIN_MS && S.startupKeepAliveDelayMs(() => 0.999999) <= S.STARTUP_KEEPALIVE_MAX_MS && S.STARTUP_KEEPALIVE_MIN_MS >= 1000 && S.STARTUP_KEEPALIVE_MAX_MS <= 60_000, "startup delay is jittered in [3s, 60s]");
  ok(S.wireStartupKeepAliveEnabled({}) && !S.wireStartupKeepAliveEnabled({ BUZZ_WIRE_STARTUP_KEEPALIVE: "0" }) && !S.wireStartupKeepAliveEnabled({ BUZZ_WIRE_STARTUP_KEEPALIVE: "off" }), "BUZZ_WIRE_STARTUP_KEEPALIVE=0/off opts out");
}
{
  // resolveSigner (stdio wire mode) turns it on; the env opt-out turns it off; a static token never arms it
  wireRefreshSet("sk5", "rt-r");
  const PK = "a".repeat(64);
  const wenv = { BUZZ_WIRE_SIGN: "1", BUZZ_WIRE_ID: "sk5", BUZZ_USER_PUBKEY: PK, BUZZ_EKAM_BASE: "https://ekam.test", BUZZ_EKAM_CLIENT_ID: "cid" };
  let calls = 0;
  const fetchFn = async () => { calls++; return json(200, { access_token: "acc-r", refresh_token: "rt-r2", expires_in: 900 }); };
  const s1 = await S.resolveSigner({ env: wenv, fetch: fetchFn, wireTokenOpts: { log: () => {}, startupKeepAlive: { delayMs: 10 } } });
  await waitFor(() => calls >= 1);
  ok(calls === 1 && s1.keepAlivePending().renew, "resolveSigner (stdio wire) → startup refresh fired once, renew scheduled");
  s1.wipe();
  ok(!s1.keepAlivePending().renew && !s1.keepAlivePending().startup, "signer.wipe() (shutdown) stops the keep-alive timers");
  const s2 = await S.resolveSigner({ env: { ...wenv, BUZZ_WIRE_STARTUP_KEEPALIVE: "0" }, fetch: fetchFn, wireTokenOpts: { log: () => {}, startupKeepAlive: { delayMs: 10 } } });
  ok(!s2.keepAlivePending().startup, "BUZZ_WIRE_STARTUP_KEEPALIVE=0 → no startup timer via resolveSigner");
  s2.wipe();
  const s3 = await S.resolveSigner({ env: { ...wenv, BUZZ_WIRE_ID: "sk5-static", BUZZ_EKAM_HUMAN_TOKEN: "st" }, fetch: fetchFn, wireTokenOpts: { log: () => {}, startupKeepAlive: { delayMs: 10 } } });
  ok(!s3.keepAlivePending().startup, "static token via resolveSigner → no startup timer");
  s3.wipe();
}

// ── 8. v0.2.37 (buzz_security must-fix 1): stale-lock break is serialized + ownership re-check before the POST ──
console.log("\ncase 8: stale-lock break race (.break serialization, nonce re-check, pre-POST ownership)");
{
  const { hostname } = await import("node:os");
  const lf = f("br", ".lock");
  // (a) the race itself: we saw stale nonce X, but another breaker already broke it and took a NEW lock Y
  writeFileSync(lf, JSON.stringify({ pid: process.pid, host: hostname(), t: Date.now(), n: "Y-new-holder" }), { mode: 0o600 });
  ok(breakStaleLock(lf, "X-stale") === false && JSON.parse(readFileSync(lf, "utf8")).n === "Y-new-holder", "breaker with a stale snapshot (n=X) does NOT remove the new holder's lock (n=Y)");
  ok(!existsSync(lf + ".break"), ".break released after a no-op break");
  // (b) nonce still matches → broken, .break released
  writeFileSync(lf, JSON.stringify({ pid: 1, host: "h", t: 0, n: "X-stale" }), { mode: 0o600 });
  ok(breakStaleLock(lf, "X-stale") === true && !existsSync(lf) && !existsSync(lf + ".break"), "nonce still the stale one → lock removed, .break released");
  // (c) another breaker holds a FRESH .break → we do not break at all
  writeFileSync(lf, JSON.stringify({ pid: 1, host: "h", t: 0, n: "X-stale" }), { mode: 0o600 });
  writeFileSync(lf + ".break", JSON.stringify({ pid: 1, host: "h", t: Date.now(), n: "other-breaker" }), { mode: 0o600 });
  ok(breakStaleLock(lf, "X-stale") === false && existsSync(lf) && JSON.parse(readFileSync(lf + ".break", "utf8")).n === "other-breaker", "a live .break (another breaker mid-break) → no break, its .break untouched");
  // (d) a crashed breaker's .break is cleared once older than breakStaleMs; the next try breaks the lock
  ok(breakStaleLock(lf, "X-stale", { breakStaleMs: 5_000, now: () => Date.now() + 10_000 }) === false && !existsSync(lf + ".break") && existsSync(lf), ".break older than breakStaleMs is cleared (that call still does not break)");
  ok(breakStaleLock(lf, "X-stale") === true && !existsSync(lf), "…and the next call breaks the stale lock");
  // (e) unreadable lock: broken only if still unreadable AND old by mtime
  writeFileSync(lf, "", { mode: 0o600 });
  ok(breakStaleLock(lf, null) === false && existsSync(lf), "fresh empty lock (holder mid-write) is not broken");
  ok(breakStaleLock(lf, null, { now: () => Date.now() + 120_000 }) === true && !existsSync(lf), "empty lock older than staleMs is broken");
  // (f) withWireLock: owns() reflects a stolen lock; release never removes someone else's lock
  const r = await withWireLock("br", async ({ owns }) => {
    const before = owns();
    writeFileSync(lf, JSON.stringify({ pid: process.pid, host: hostname(), t: Date.now(), n: "thief" }), { mode: 0o600 });
    return [before, owns()];
  }, { timeoutMs: 2000 });
  ok(r[0] === true && r[1] === false && JSON.parse(readFileSync(lf, "utf8")).n === "thief", "owns() true while held, false once another holder's lock replaced ours; our release leaves theirs alone");
  unlinkSync(lf);
}
{
  // (g) provider: a racing breaker replaces our lock right after we acquire → NO POST that round; we re-acquire, then POST once
  const { hostname } = await import("node:os");
  const dead = spawn(process.execPath, ["-e", "0"]); const deadPid = dead.pid; await new Promise((r) => dead.on("close", r));
  wireRefreshSet("own", "rt-o");
  let calls = 0, hits = 0;
  const onAcquire = ({ lockFile }) => { if (hits++ === 0) writeFileSync(lockFile, JSON.stringify({ pid: deadPid, host: hostname(), t: Date.now(), n: "racer" }), { mode: 0o600 }); };
  const p = makeWireTokenProvider(ENV("own"), async (_u, init) => { calls++; return json(200, { access_token: "acc-o", refresh_token: "rt-o2", expires_in: 900 }); }, { ...quiet, lock: { timeoutMs: 3000, onAcquire } });
  const a = await p.get();
  ok(a === "acc-o" && calls === 1 && hits === 2, `lost lock before the POST → zero POSTs that round, one POST after re-acquiring (calls=${calls}, acquisitions=${hits})`);
  ok(!existsSync(f("own", ".lock")) && wireRefreshGet("own") === "rt-o2", "lock released, rotation persisted");
  p.stopKeepAlive();
}
{
  // (h) provider: .tok changes right after we acquire (sibling rotated) → the old refresh is never sent
  wireRefreshSet("own2", "rt-old");
  const sent = []; let hits = 0;
  const onAcquire = () => { if (hits++ === 0) wireRefreshSet("own2", "rt-sib"); };
  const p = makeWireTokenProvider(ENV("own2"), async (_u, init) => { sent.push(JSON.parse(init.body).refresh_token); return json(200, { access_token: "acc-s", refresh_token: "rt-s2", expires_in: 900 }); }, { ...quiet, lock: { timeoutMs: 3000, onAcquire } });
  // force the provider to hold rt-old in memory first
  ok(p.hasRefresh(), "provider loaded rt-old");
  const a = await p.get();
  ok(a === "acc-s" && sent.join(",") === "rt-sib", `.tok rotated before the POST → sent only the sibling's refresh (sent ${sent.join(",")})`);
  p.stopKeepAlive();
}
{
  // (i) stress: 6 processes race to break the SAME stale lock (dead pid) at the same instant → critical sections never overlap
  const { hostname } = await import("node:os");
  const dead = spawn(process.execPath, ["-e", "0"]); const deadPid = dead.pid; await new Promise((r) => dead.on("close", r));
  writeFileSync(f("stress", ".lock"), JSON.stringify({ pid: deadPid, host: hostname(), t: Date.now(), n: "stale" }), { mode: 0o600 });
  const logf = join(HOME, "stress.log"); writeFileSync(logf, "");
  const at = Date.now() + 800;
  const run = () => new Promise((resolve) => {
    const c = spawn(process.execPath, [SELF, "--lockchild"], { env: { ...process.env, HOME, T_ID: "stress", T_LOG: logf, T_AT: String(at) }, stdio: ["ignore", "pipe", "inherit"] });
    let out = ""; c.stdout.on("data", (d) => (out += d)); c.on("close", () => resolve(out));
  });
  const outs = await Promise.all(Array.from({ length: 6 }, run));
  const lines = readFileSync(logf, "utf8").trim().split("\n");
  let overlap = false, depth = 0, lost = false;
  for (const l of lines) { const [k, , o] = l.split(" "); if (k === "E") { depth++; if (depth > 1) overlap = true; } else { depth--; if (o !== "1") lost = true; } }
  ok(outs.every((o) => o === "ok") && lines.length === 12, `all 6 processes got the lock once (${outs.filter((o) => o === "ok").length}/6, ${lines.length} log lines)`);
  ok(!overlap && !lost, "no two holders at once; every holder still owned its lock at the end of its critical section");
  ok(!existsSync(f("stress", ".lock")) && !existsSync(f("stress", ".lock.break")) && !readdirSync(WIRE_REFRESH_DIR).some((n) => /^stress.*stale/.test(n)), "no leftover lock, .break or grave files");
}

console.log(`\n${failed ? "FAIL" : "ALL PASS"}: ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
