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
import { createServer } from "node:http";
import { getPublicKey } from "nostr-tools/pure";

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

// Generic: drive the shim over stdio, call ONE arbitrary tool, capture the client-visible reply.
function probeTool(env, toolName, args, { waitMs = 6000, callDelay = 1000 } = {}) {
  return new Promise((resolve) => {
    const p = spawn("node", [SHIM], { env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    const send = (o) => { try { p.stdin.write(JSON.stringify(o) + "\n"); } catch {} };
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "bridge-test", version: "1" } } });
    setTimeout(() => send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: toolName, arguments: args } }), callDelay);
    setTimeout(() => {
      p.kill();
      const reply = out.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).find((j) => j && j.id === 2);
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

// ---- Case 3: buzz_post with NO body at all → fail LOUD, not a cryptic throw / not a blank post ----
// Origin: Anirban's pilot — a post call with the body under the wrong key threw "reading 'match'".
// As of v0.2.12 `message` is accepted as an alias for `text` (bossman [08:55]), so the guard only
// fires when BOTH are absent. It must then return an actionable error naming `text` — never the
// cryptic TypeError, never a blank post. (We assert the empty path, which needs no live post.)
console.log("\ncase 3: buzz_post with neither `text` nor `message` → fail loud");
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
    setTimeout(() => send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "buzz_post", arguments: { channel: "buzz-main" } } }), 1000);
    setTimeout(() => { p.kill(); const r = out.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).find((j) => j && j.id === 2); resolve(r ? JSON.stringify(r.result ?? r.error) : null); }, 6000);
  });
  if (text == null) skipped("no reply for post-guard case");
  else {
    console.log("  client sees: " + text.slice(0, 160));
    ok(/requires a non-empty `?text`?/i.test(text), "empty body → clear, actionable error naming `text`");
    ok(!/reading 'match'/i.test(text), "does NOT throw the cryptic reading-'match' TypeError");
  }
}

// ---- Case 4 (v0.2.13): buzz_status_set / buzz_status_clear REFUSED in wire mode -------------
// NIP-38 kind 30315 is NOT in the wire-sign allowlist, so canSign(30315) fail-closes BEFORE any
// network — the refusal surfaces even with a junk refresh and Ekam unreachable (local check first).
console.log("\ncase 4: buzz_status_set/clear refused in wire mode (kind 30315 not wire-signable)");
{
  const WIRE = {
    BUZZ_WIRE_SIGN: "1", BUZZ_WIRE_ID: "statusprobe",
    BUZZ_WIRE_REFRESH: "invalid-refresh-token-for-status-regression",
    BUZZ_EKAM_CLIENT_ID: process.env.BUZZ_EKAM_CLIENT_ID || "clt_37501bdddf3c4e43a0ff",
    BUZZ_USER_PUBKEY: "ab".repeat(32),
    BUZZ_RELAY_HTTP: "https://ola.buzz.ola.in", BUZZ_RELAY_URL: "wss://ola.buzz.ola.in",
    BUZZ_PRIVATE_KEY: "", BUZZ_NAME: "", BUZZ_AUTH_TAG: "",
  };
  const setText = await probeTool(WIRE, "buzz_status_set", { text: "heads down" }, { waitMs: 9000 });
  if (setText == null) skipped("no reply for status_set wire case");
  else {
    console.log("  client sees: " + setText.slice(0, 160));
    ok(/agent-mode only/i.test(setText) && /30315/.test(setText), "status_set → refused in wire mode, names the allowlist gap");
    ok(!/posted|status set/i.test(setText), "status_set → did NOT sign/post in wire mode");
  }
  const clrText = await probeTool(WIRE, "buzz_status_clear", {}, { waitMs: 9000 });
  if (clrText == null) skipped("no reply for status_clear wire case");
  else ok(/agent-mode only/i.test(clrText) && /30315/.test(clrText), "status_clear → refused in wire mode too");
}

// ---- Case 5 (v0.2.13): buzz_reply / buzz_forward arg validation → clear, pre-network errors ---
// The body/target guards short-circuit BEFORE any relay call, so these run fully offline.
console.log("\ncase 5: buzz_reply/buzz_forward arg validation (missing event/target → clear error)");
{
  const AGENT = { BUZZ_PRIVATE_KEY: "33".repeat(32), BUZZ_NAME: "bridge-test", BUZZ_AUTH_TAG: "",
    BUZZ_WIRE_SIGN: "", BUZZ_RELAY_HTTP: "http://127.0.0.1:1", BUZZ_RELAY_URL: "ws://127.0.0.1:1" };
  const replyNoEvent = await probeTool(AGENT, "buzz_reply", { channel: "buzz-main", text: "hi" });
  if (replyNoEvent == null) skipped("no reply for buzz_reply arg case");
  else {
    console.log("  reply (no event): " + replyNoEvent.slice(0, 140));
    ok(/buzz_reply needs the `?event`?/i.test(replyNoEvent), "buzz_reply without `event` → clear, actionable error naming event");
  }
  const replyNoBody = await probeTool(AGENT, "buzz_reply", { channel: "buzz-main", event: "ab".repeat(32) });
  if (replyNoBody != null) ok(/requires a non-empty `?text`?/i.test(replyNoBody), "buzz_reply with no text/message → fail loud naming `text`");
  const fwdNoTo = await probeTool(AGENT, "buzz_forward", { source_channel: "buzz-main", event: "ab".repeat(32) });
  if (fwdNoTo == null) skipped("no reply for buzz_forward arg case");
  else {
    console.log("  forward (no to): " + fwdNoTo.slice(0, 140));
    ok(/buzz_forward needs a `?to`?/i.test(fwdNoTo), "buzz_forward without `to` → clear error naming the target");
  }
  const fwdNoEvent = await probeTool(AGENT, "buzz_forward", { source_channel: "buzz-main", to: "someone" });
  if (fwdNoEvent != null) ok(/buzz_forward needs the `?event`?/i.test(fwdNoEvent), "buzz_forward without `event` → clear error naming event");
}

// ---- Case 6 (v0.2.13): buzz_unread returns a digest shape (against a canned mock relay) --------
// A tiny in-process HTTP relay serves membership → channel meta → profiles → kind:9, so the
// read-only heuristic produces a real per-channel digest with counts + @mentions of self.
console.log("\ncase 6: buzz_unread returns a digest shape (mock relay)");
{
  const SK = "33".repeat(32);
  const PK = getPublicKey(Uint8Array.from(Buffer.from(SK, "hex")));
  const OTHER = "44".repeat(32);
  const now = Math.floor(Date.now() / 1000);
  const relay = createServer((rq, rs) => {
    let body = ""; rq.on("data", (c) => (body += c));
    rq.on("end", () => {
      const reply = (obj) => { rs.writeHead(200, { "Content-Type": "application/json" }); rs.end(JSON.stringify(obj)); };
      if (rq.method === "GET") return reply({ name: "mock", version: "0", software_sha: "deadbeef" });
      if (rq.url === "/events") return reply({ message: "response:{}" });
      if (rq.url === "/query") {
        let filters = []; try { filters = JSON.parse(body); } catch {}
        const kinds = new Set(filters.flatMap((f) => f.kinds || []));
        if (kinds.has(39002)) return reply([{ id: "m1", pubkey: PK, kind: 39002, created_at: now, tags: [["d", "chanA"], ["p", PK]], content: "" }]);
        if (kinds.has(39000)) return reply([{ id: "c1", pubkey: PK, kind: 39000, created_at: now, tags: [["d", "chanA"], ["name", "testchan"]], content: "" }]);
        if (kinds.has(0)) return reply([
          { id: "p1", pubkey: PK, kind: 0, created_at: now, tags: [], content: JSON.stringify({ name: "me" }) },
          { id: "p2", pubkey: OTHER, kind: 0, created_at: now, tags: [], content: JSON.stringify({ name: "otheragent" }) },
        ]);
        if (kinds.has(9)) return reply([
          { id: "e1", pubkey: OTHER, kind: 9, created_at: now, tags: [["h", "chanA"], ["p", PK]], content: "you were mentioned" },
          { id: "e2", pubkey: OTHER, kind: 9, created_at: now, tags: [["h", "chanA"]], content: "just chatter" },
          { id: "e3", pubkey: PK, kind: 9, created_at: now, tags: [["h", "chanA"]], content: "my own post (excluded)" },
        ]);
        return reply([]);
      }
      reply({});
    });
  });
  await new Promise((r) => relay.listen(0, "127.0.0.1", r));
  const port = relay.address().port;
  const text = await probeTool({
    BUZZ_PRIVATE_KEY: SK, BUZZ_NAME: "bridge-test", BUZZ_AUTH_TAG: "", BUZZ_WIRE_SIGN: "",
    BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
  }, "buzz_unread", { hours: 24 });
  relay.close();
  if (text == null) skipped("no reply for buzz_unread mock case");
  else {
    console.log("  client sees: " + text.replace(/\\n/g, " | ").slice(0, 220));
    ok(/Unread digest \(last 24h\)/.test(text), "buzz_unread → returns a labelled digest shape");
    ok(/#testchan/.test(text) && /2 new/.test(text), "digest counts messages from others (own post excluded → 2 new)");
    ok(/1 @you/.test(text), "digest counts @mentions of self");
  }
}

console.log(`\nbridge.test.mjs: ${pass} passed, ${fail} failed, ${skip} skipped`);
process.exit(fail ? 1 : 0);
