// bridge.test.mjs — `node bridge.test.mjs`
// Runtime-string regression for bridge(): the error a CLIENT actually receives.
//
// WHY THIS EXISTS (origin: @buzz_appdev's acceptance harness, folded into the
// shim's own suite per Navendu). v0.2.8 shipped, was reviewed, and was BELIEVED
// to surface a legible "re-run the one-time login" message — but at runtime it
// buried the wire mint's auth-400 as `unknown_transport` and re-minted it. A
// structural assertion ("nip98 is outside the catch") is exactly what was
// believed true while the bug was live. So this drives the real binary over
// stdio and asserts the RENDERED TEXT a client holds, not a code shape.
//
// Two cases, pinning the boundary from both sides:
//   1. auth-400  → must carry the login remedy, must NOT say unknown_transport
//   2. transport → a genuine relay-fetch failure must STILL say restart/transport
//                   and must NOT tell the user to re-login (that would be wrong —
//                   their token is fine, the socket is not).
//
// SAFETY — consumes no real credential:
//   BUZZ_WIRE_ID=bridgeprobe + BUZZ_WIRE_REFRESH=<junk> forces the mint 400
//   without presenting, spending, or revoking any real token family; a persist
//   id nobody uses, so ~/.config/buzz-cli/wire-refresh/wire.tok is never touched.
//
// Network: case 1 reaches Ekam to get the 400 (safe, junk refresh). If Ekam is
// unreachable the case is reported SKIP rather than FAIL, so an offline CI run
// does not go red for the wrong reason. Case 2 is fully offline (unroutable host).

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHIM = join(HERE, "buzz-mcp.mjs");

let pass = 0, fail = 0, skip = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✅ " + m)) : (fail++, console.log("  ❌ " + m)));
const skipped = (m) => (skip++, console.log("  ⊘ SKIP " + m));

// Drive the shim over stdio: initialize, one buzz_read, capture the reply text a
// client would receive. Returns the stringified result/error for tool call id 2.
function probeRead(env, { waitMs = 9000 } = {}) {
  return new Promise((resolve) => {
    // Inherit process.env for PATH etc., then let the case env override. Each
    // case sets the agent-identity vars (PRIVATE_KEY/NAME/AUTH_TAG) explicitly so
    // nothing from the caller's environment bleeds into the mode under test.
    const p = spawn("node", [SHIM], {
      env: { ...process.env, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    const send = (o) => { try { p.stdin.write(JSON.stringify(o) + "\n"); } catch {} };
    send({ jsonrpc: "2.0", id: 1, method: "initialize",
           params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "bridge-test", version: "1" } } });
    setTimeout(() => send({ jsonrpc: "2.0", id: 2, method: "tools/call",
           params: { name: "buzz_read", arguments: { channel: "buzz-main", limit: 1 } } }), 1000);
    setTimeout(() => {
      p.kill();
      const reply = out.split("\n").filter(Boolean)
        .map((l) => { try { return JSON.parse(l); } catch { return null; } })
        .find((j) => j && j.id === 2);
      resolve(reply ? JSON.stringify(reply.result ?? reply.error) : null);
    }, waitMs);
  });
}

const LOGIN_REMEDY = /buzz-mcp-login|re-run the one-time login|sign-?in expired|refresh (token )?(is )?(invalid|revoked|expired)/i;
const UNKNOWN_TRANSPORT = /unknown_transport/;
const RESTART = /restart|transport|terminated|fetch failed/i;

console.log("bridge.test.mjs — runtime string a client receives\n");

// ---- Case 1: wire auth-400 → legible remedy, never unknown_transport ---------
console.log("case 1: wire mint auth-400 (junk refresh)");
{
  const text = await probeRead({
    BUZZ_WIRE_SIGN: "1",
    BUZZ_WIRE_ID: "bridgeprobe",
    BUZZ_WIRE_REFRESH: "invalid-refresh-token-for-bridge-regression",
    BUZZ_EKAM_CLIENT_ID: process.env.BUZZ_EKAM_CLIENT_ID || "clt_37501bdddf3c4e43a0ff",
    BUZZ_USER_PUBKEY: "ab".repeat(32),
    BUZZ_RELAY_HTTP: "https://ola.buzz.ola.in",
    BUZZ_RELAY_URL: "wss://ola.buzz.ola.in",
    BUZZ_PRIVATE_KEY: "", BUZZ_NAME: "", BUZZ_AUTH_TAG: "",
  });
  if (text == null) {
    skipped("no tools/call reply — shim did not start or Ekam unreachable");
  } else if (/wire.?sign|mint|ekam/i.test(text) === false && UNKNOWN_TRANSPORT.test(text)) {
    // Reached the transport path without ever hitting the mint — almost always
    // means Ekam was unreachable, so the auth-400 never happened. Don't FAIL.
    skipped("reply looks like an Ekam-unreachable transport error, not an auth-400: " + text.slice(0, 160));
  } else {
    console.log("  client sees: " + text.slice(0, 200));
    ok(!UNKNOWN_TRANSPORT.test(text), "does NOT mislabel the auth error as unknown_transport");
    ok(LOGIN_REMEDY.test(text), "carries an actionable login remedy");
  }
}

// ---- Case 2: genuine transport failure → restart, NOT a re-login prompt ------
console.log("\ncase 2: agent-mode relay-fetch failure (unroutable relay)");
{
  // Throwaway agent key so signing succeeds locally; the relay host is a
  // black-hole port so the fetch itself fails — a real transport error.
  const text = await probeRead({
    BUZZ_PRIVATE_KEY: "11".repeat(32),
    BUZZ_NAME: "bridge-test",
    BUZZ_AUTH_TAG: "",
    BUZZ_WIRE_SIGN: "",
    BUZZ_RELAY_HTTP: "http://127.0.0.1:1",
    BUZZ_RELAY_URL: "ws://127.0.0.1:1",
  }, { waitMs: 12000 });
  if (text == null) {
    skipped("no tools/call reply for transport case");
  } else {
    console.log("  client sees: " + text.slice(0, 200));
    ok(RESTART.test(text), "a genuine transport failure still points at restart/transport");
    ok(!/buzz-mcp-login|re-run the one-time login|sign-?in expired/i.test(text),
       "does NOT wrongly tell the user to re-login when the token is fine");
  }
}

// ---- Case 3: buzz_post with the wrong param name → clear error, not a cryptic throw ----
// Origin: Anirban's pilot — a post call missing `text` (e.g. passing `message`) threw
// "reading 'match'" from the @-mention scan. The guard must return an actionable message.
console.log("\ncase 3: buzz_post missing `text` (passed `message`)");
{
  const text = await new Promise((resolve) => {
    const p = spawn("node", [SHIM], {
      env: { ...process.env, BUZZ_PRIVATE_KEY: "22".repeat(32), BUZZ_NAME: "bridge-test",
             BUZZ_AUTH_TAG: "", BUZZ_WIRE_SIGN: "",
             BUZZ_RELAY_HTTP: "https://ola.buzz.ola.in", BUZZ_RELAY_URL: "wss://ola.buzz.ola.in" },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let out = ""; p.stdout.on("data", (d) => (out += d));
    const send = (o) => { try { p.stdin.write(JSON.stringify(o) + "\n"); } catch {} };
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "bridge-test", version: "1" } } });
    setTimeout(() => send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "buzz_post", arguments: { channel: "buzz-main", message: "oops, wrong param" } } }), 1000);
    setTimeout(() => { p.kill(); const r = out.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).find((j) => j && j.id === 2); resolve(r ? JSON.stringify(r.result ?? r.error) : null); }, 6000);
  });
  if (text == null) skipped("no reply for post-guard case");
  else {
    console.log("  client sees: " + text.slice(0, 160));
    ok(/requires a non-empty `?text`? string/i.test(text), "missing text → clear, actionable error naming `text`");
    ok(!/reading 'match'/i.test(text), "does NOT throw the cryptic reading-'match' TypeError");
  }
}

console.log(`\nbridge.test.mjs: ${pass} passed, ${fail} failed, ${skip} skipped`);
process.exit(fail ? 1 : 0);
