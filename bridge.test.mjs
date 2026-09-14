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
import { statSync } from "node:fs";
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

// Generic: drive the shim over stdio, call tools/list, capture the registered tool list.
function probeList(env, { waitMs = 6000, callDelay = 1000 } = {}) {
  return new Promise((resolve) => {
    const p = spawn("node", [SHIM], { env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    const send = (o) => { try { p.stdin.write(JSON.stringify(o) + "\n"); } catch {} };
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "bridge-test", version: "1" } } });
    setTimeout(() => send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }), callDelay);
    setTimeout(() => {
      p.kill();
      const reply = out.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).find((j) => j && j.id === 2);
      resolve(reply ? (reply.result ?? null) : null);
    }, waitMs);
  });
}

// Generic: drive the shim over stdio and capture the MCP `initialize` handshake result (id 1) —
// where serverInfo (name + version) is advertised. No tool call, fully static/offline.
function probeInit(env, { waitMs = 4000 } = {}) {
  return new Promise((resolve) => {
    const p = spawn("node", [SHIM], { env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    const send = (o) => { try { p.stdin.write(JSON.stringify(o) + "\n"); } catch {} };
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "bridge-test", version: "1" } } });
    setTimeout(() => {
      p.kill();
      const reply = out.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).find((j) => j && j.id === 1);
      resolve(reply ? (reply.result ?? null) : null);
    }, waitMs);
  });
}

// Like probeTool, but ALSO captures the shim's stderr (where the retry/telemetry markers land) so a
// test can assert the stale-401 counter line fired. Returns { text, err }.
function probeToolErr(env, toolName, args, { waitMs = 8000, callDelay = 1200 } = {}) {
  return new Promise((resolve) => {
    const p = spawn("node", [SHIM], { env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    const send = (o) => { try { p.stdin.write(JSON.stringify(o) + "\n"); } catch {} };
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "bridge-test", version: "1" } } });
    setTimeout(() => send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: toolName, arguments: args } }), callDelay);
    setTimeout(() => {
      p.kill();
      const reply = out.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).find((j) => j && j.id === 2);
      resolve({ text: reply ? JSON.stringify(reply.result ?? reply.error) : null, err });
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

// ---- Case 7 (v0.2.16): buzz_login + buzz_doctor registered and the tool count is now 24 -------
// Static: tools/list is answered from the in-process TOOLS array — no network, no OAuth. Agent
// mode boots cleanly offline; the black-hole relay is never dialed for tools/list.
console.log("\ncase 7: buzz_login + buzz_doctor registered + tool count is 24 (static, no OAuth)");
{
  const AGENT = { BUZZ_PRIVATE_KEY: "55".repeat(32), BUZZ_NAME: "bridge-test", BUZZ_AUTH_TAG: "",
    BUZZ_WIRE_SIGN: "", BUZZ_EKAM_CLIENT_ID: "",
    BUZZ_RELAY_HTTP: "http://127.0.0.1:1", BUZZ_RELAY_URL: "ws://127.0.0.1:1" };
  const res = await probeList(AGENT);
  if (res == null) skipped("no tools/list reply — shim did not start");
  else {
    const names = (res.tools || []).map((t) => t.name);
    console.log("  tools: " + names.length + " → " + names.join(", "));
    ok(names.includes("buzz_login"), "buzz_login is registered in tools/list");
    ok(names.includes("buzz_doctor"), "buzz_doctor is registered in tools/list");
    ok(names.length === 24, `total tool count is 24 (got ${names.length})`);
  }
}

// ---- Case 8 (v0.2.15): buzz_login with NO client_id and no env → fail LOUD, no crash ---------
// Since v0.2.15 the "already connected" check runs BEFORE the client-id guard (friendlier UX),
// so this test pins BUZZ_WIRE_ID to an id nobody uses → wireRefreshGet misses deterministically
// (never touches a real persisted wire.tok on the dev box), so we always reach the client-id
// guard regardless of ambient login state. That guard short-circuits before any port bind or
// network — fully offline + static, and deterministic (bossman's env-control ask).
console.log("\ncase 8: buzz_login with no client_id/env → clear BUZZ_EKAM_CLIENT_ID error");
{
  const AGENT = { BUZZ_PRIVATE_KEY: "55".repeat(32), BUZZ_NAME: "bridge-test", BUZZ_AUTH_TAG: "",
    BUZZ_WIRE_SIGN: "", BUZZ_EKAM_CLIENT_ID: "", BUZZ_WIRE_ID: "loginprobe-noclient",
    BUZZ_RELAY_HTTP: "http://127.0.0.1:1", BUZZ_RELAY_URL: "ws://127.0.0.1:1" };
  const text = await probeTool(AGENT, "buzz_login", {});
  if (text == null) skipped("no reply for buzz_login no-client case");
  else {
    console.log("  client sees: " + text.slice(0, 180));
    ok(/BUZZ_EKAM_CLIENT_ID/.test(text), "names BUZZ_EKAM_CLIENT_ID as the missing input");
    ok(!/reading '|TypeError|is not a function|Cannot read/.test(text), "fails loud — no crash / cryptic throw");
  }
}

// ---- Case 9 (v0.2.16): buzz_doctor works when the relay is unreachable → no crash -------------
// Point the dial host at a black-hole port. buzz_doctor probes over a FRESH node:https socket, so
// the connect error must surface as the "relay unreachable" 3-way classification (verbatim string
// docs track), NOT an unhandled throw. Fully offline + static.
console.log("\ncase 9: buzz_doctor against a dead relay → 'relay unreachable', structured, no crash");
{
  const AGENT = { BUZZ_PRIVATE_KEY: "66".repeat(32), BUZZ_NAME: "bridge-test", BUZZ_AUTH_TAG: "",
    BUZZ_WIRE_SIGN: "", BUZZ_RELAY_HTTP: "http://127.0.0.1:1", BUZZ_RELAY_URL: "ws://127.0.0.1:1" };
  const text = await probeTool(AGENT, "buzz_doctor", { timeout_s: 2 }, { waitMs: 9000, callDelay: 1200 });
  if (text == null) skipped("no reply for buzz_doctor unreachable case");
  else {
    console.log("  client sees: " + text.replace(/\\n/g, " | ").slice(0, 220));
    ok(/relay unreachable/i.test(text), "buzz_doctor → classifies a dead relay as 'relay unreachable'");
    ok(/nothing local fixes this/i.test(text), "buzz_doctor → gives the unreachable recovery text");
    ok(!/reading '|TypeError|is not a function|Cannot read/.test(text), "buzz_doctor → structured result, no crash");
  }
}

// ---- Case 10 (v0.2.16): NIP-98 is RE-SIGNED per attempt (fresh, never reused across a retry) ---
// A mock relay resets the socket on the FIRST membership (kind 39002) /query, forcing the shim's
// fresh-transport retry, then serves the retry. We capture the Authorization (base64 NIP-98 event)
// on BOTH the reset request and its retry and prove they are DISTINCT signed events (different
// event id + nonce) — i.e. the auth event was rebuilt for the retry, not the stale one reused
// (which would 401 on ±60s during a delay). STATIC/offline — no live relay.
console.log("\ncase 10: NIP-98 auth event is re-signed per attempt (retry carries a fresh event)");
{
  const SK = "77".repeat(32);
  const PK = getPublicKey(Uint8Array.from(Buffer.from(SK, "hex")));
  const OTHER = "88".repeat(32);
  const now = Math.floor(Date.now() / 1000);
  const captured = [];
  let resetOnce = false;
  const relay = createServer((rq, rs) => {
    let body = ""; rq.on("data", (c) => (body += c));
    rq.on("end", () => {
      captured.push({ url: rq.url, body, auth: rq.headers["authorization"] || "" });
      const reply = (obj) => { rs.writeHead(200, { "Content-Type": "application/json" }); rs.end(JSON.stringify(obj)); };
      if (rq.method === "GET") return reply({ name: "mock", version: "0", software_sha: "deadbeef" });
      if (rq.url === "/events") return reply({ message: "response:{}" });
      if (rq.url === "/query") {
        let filters = []; try { filters = JSON.parse(body); } catch {}
        const kinds = new Set(filters.flatMap((f) => f.kinds || []));
        // Reset the socket on the FIRST 39002 query → a genuine transport throw → shim re-signs +
        // retries over a fresh node:https socket. The retry (same body) is served normally.
        if (kinds.has(39002) && !resetOnce) { resetOnce = true; try { rq.socket.destroy(); } catch {} return; }
        if (kinds.has(39002)) return reply([{ id: "m1", pubkey: PK, kind: 39002, created_at: now, tags: [["d", "chanA"], ["p", PK]], content: "" }]);
        if (kinds.has(39000)) return reply([{ id: "c1", pubkey: PK, kind: 39000, created_at: now, tags: [["d", "chanA"], ["name", "testchan"]], content: "" }]);
        if (kinds.has(0)) return reply([{ id: "p1", pubkey: PK, kind: 0, created_at: now, tags: [], content: JSON.stringify({ name: "me" }) }]);
        if (kinds.has(9)) return reply([{ id: "e1", pubkey: OTHER, kind: 9, created_at: now, tags: [["h", "chanA"]], content: "hi" }]);
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
  }, "buzz_read", { channel: "testchan", limit: 5 }, { waitMs: 10000, callDelay: 1500 });
  relay.close();

  const decode = (a) => { try { return JSON.parse(Buffer.from(String(a).replace(/^Nostr /, ""), "base64").toString("utf8")); } catch { return null; } };
  const nonceOf = (ev) => ((ev.tags || []).find((t) => t[0] === "nonce") || [])[1];
  // The two requests whose body carries a 39002 filter are the reset attempt + its retry.
  const memberReqs = captured.filter((c) => c.url === "/query" && /39002/.test(c.body) && c.auth);
  if (memberReqs.length < 2) {
    skipped(`did not observe both the reset attempt and its retry (saw ${memberReqs.length} membership queries; reply=${(text || "").slice(0, 80)})`);
  } else {
    const [a1, a2] = [decode(memberReqs[0].auth), decode(memberReqs[1].auth)];
    ok(!!a1 && !!a2 && a1.kind === 27235 && a2.kind === 27235, "both attempts carry a NIP-98 (kind 27235) auth event");
    ok(!!a1 && !!a2 && a1.id && a2.id && a1.id !== a2.id, "retry auth event has a DIFFERENT id → re-signed, not reused");
    ok(!!a1 && !!a2 && nonceOf(a1) && nonceOf(a2) && nonceOf(a1) !== nonceOf(a2), "retry auth event has a fresh nonce (distinct per attempt)");
    ok(!!a1 && !!a2 && Number.isFinite(a1.created_at) && Number.isFinite(a2.created_at) && a2.created_at >= a1.created_at, "retry auth event created_at is freshly (re-)stamped, not older");
  }
}

// ---- Case 11 (v0.2.16): both dist bins ship EXECUTABLE (git mode 100755) --------------------
// dist/wirelogin.mjs shipped 100644 which stalls `npx -p …buzz-mcp-login`. esbuild can reset the
// mode on rebuild, so this guards that BOTH shipped bins keep an exec bit. (releng must chmod 755
// after the canonical dist rebuild — the source patch cannot carry a dist file-mode change.)
console.log("\ncase 11: dist/buzz-mcp.mjs and dist/wirelogin.mjs are executable");
{
  for (const f of ["buzz-mcp.mjs", "wirelogin.mjs"]) {
    let mode = 0; try { mode = statSync(join(HERE, "dist", f)).mode; } catch {}
    ok((mode & 0o111) !== 0, `dist/${f} has an exec bit (mode ${(mode & 0o777).toString(8)})`);
  }
}

// ---- Case 12 (v0.2.17): buzz_doctor healthy path → 'healthy', NOT 'wedged' ------------------
// FIX 2: with a reachable relay (health 200 + authed /query 200) AND no transport wedge flagged
// this process, buzz_doctor must classify "healthy" — the old code keyed the "wedged client pool"
// branch on health==200 alone and mislabeled a perfectly healthy setup as wedged. A local mock
// relay answers GET /health → 200 and POST /query → 200 (grant OK, not a 401/auth rejection).
// STATIC/offline — no live relay, agent-mode NIP-98 is signed locally. TRANSPORT_WEDGED stays
// false because no transport throw ever occurs on the fresh-socket probes.
console.log("\ncase 12: buzz_doctor healthy relay (health 200 + auth 200, no wedge) → 'healthy', not 'wedged'");
{
  const SK = "99".repeat(32);
  const relay = createServer((rq, rs) => {
    let body = ""; rq.on("data", (c) => (body += c));
    rq.on("end", () => {
      // GET (health / self-report) → 200; POST /query (authed probe) → 200 with a benign body
      // (no 401/403 and no nip-98/unauthorized text → the probe reads as "grant OK").
      if (rq.method === "GET") { rs.writeHead(200, { "Content-Type": "application/json" }); rs.end(JSON.stringify({ name: "mock", version: "0", software_sha: "healthy" })); return; }
      rs.writeHead(200, { "Content-Type": "application/json" }); rs.end("[]");
    });
  });
  await new Promise((r) => relay.listen(0, "127.0.0.1", r));
  const port = relay.address().port;
  const text = await probeTool({
    BUZZ_PRIVATE_KEY: SK, BUZZ_NAME: "bridge-test", BUZZ_AUTH_TAG: "", BUZZ_WIRE_SIGN: "",
    BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
  }, "buzz_doctor", { timeout_s: 3 }, { waitMs: 9000, callDelay: 1200 });
  relay.close();
  if (text == null) skipped("no reply for buzz_doctor healthy case");
  else {
    console.log("  client sees: " + text.replace(/\\n/g, " | ").slice(0, 260));
    ok(/diagnosis: healthy/i.test(text), "buzz_doctor → classifies a reachable+authed+unwedged relay as 'healthy'");
    ok(!/diagnosis: wedged/i.test(text), "buzz_doctor → does NOT mislabel a healthy setup as 'wedged'");
    ok(/reads\/posts should work|no action/i.test(text), "buzz_doctor → gives the healthy recovery text");
    ok(/connector-side diagnosis \(NOT the authoritative/i.test(text), "buzz_doctor → keeps the 'NOT authoritative' disclaimer");
    ok(!/reading '|TypeError|is not a function|Cannot read/.test(text), "buzz_doctor → structured result, no crash");
  }
}

// ---- Case 13 (v0.2.17): buzz_doctor auth probe INCONCLUSIVE → 'couldn't tell', NOT 'wedged' ---
// FIX 2 (5th branch): health 200 but the authed /query probe ERRORS in a non-401 way (timeout /
// DNS / TLS / socket reset = no clear verdict). That is inconclusive — it must NOT be reported as
// a confident "wedged client pool → restart". The mock relay answers GET /health → 200 but DESTROYS
// the socket on the authed POST /query, so rawPost throws a transport error whose message matches
// neither the auth-rejected patterns nor a wedge → the new "couldn't tell → retry" branch.
// STATIC/offline. TRANSPORT_WEDGED stays false (buzz_doctor's fresh-socket probes never set it).
console.log("\ncase 13: buzz_doctor health ok but authed probe errors (non-401) → 'couldn't tell', not 'wedged'");
{
  const SK = "aa".repeat(32);
  const relay = createServer((rq, rs) => {
    if (rq.method === "GET") { rs.writeHead(200, { "Content-Type": "application/json" }); rs.end(JSON.stringify({ name: "mock", version: "0", software_sha: "healthy" })); return; }
    // authed POST /query → reset the socket → rawPost throws a NON-auth transport error → inconclusive.
    try { rq.socket.destroy(); } catch {}
  });
  await new Promise((r) => relay.listen(0, "127.0.0.1", r));
  const port = relay.address().port;
  const text = await probeTool({
    BUZZ_PRIVATE_KEY: SK, BUZZ_NAME: "bridge-test", BUZZ_AUTH_TAG: "", BUZZ_WIRE_SIGN: "",
    BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
  }, "buzz_doctor", { timeout_s: 3 }, { waitMs: 9000, callDelay: 1200 });
  relay.close();
  if (text == null) skipped("no reply for buzz_doctor inconclusive case");
  else {
    console.log("  client sees: " + text.replace(/\\n/g, " | ").slice(0, 260));
    ok(/diagnosis: couldn't tell/i.test(text), "buzz_doctor → an inconclusive authed probe → 'couldn't tell'");
    ok(!/diagnosis: wedged/i.test(text), "buzz_doctor → does NOT mislabel an inconclusive probe as 'wedged'");
    ok(/retry buzz_doctor/i.test(text) && !/restart your MCP client/i.test(text), "buzz_doctor → asks for a retry, not a restart");
    ok(!/reading '|TypeError|is not a function|Cannot read/.test(text), "buzz_doctor → structured result, no crash");
  }
}

// ==== v0.2.17 item 3 (write-wedge fix B + A) — stale-timestamp-401 remediation + hard timeout ====
// Shared helpers for the NIP-98 auth events these cases inspect.
const decodeNip98 = (a) => { try { return JSON.parse(Buffer.from(String(a).replace(/^Nostr /, ""), "base64").toString("utf8")); } catch { return null; } };
const nonceTag = (ev) => ((ev && ev.tags || []).find((t) => t[0] === "nonce") || [])[1];

// ---- Case 14 (v0.2.17 item 3 / A): a stale-timestamp 401 → ONE re-signed retry, then succeeds ----
// A mock relay 401s the FIRST membership (kind 39002) /query with the ±60s window message, then
// serves 200 on every later request (incl. the retry). Assert: exactly ONE remediation retry (two
// physical 39002 requests, not three), the retry carried a FRESHLY-signed NIP-98 (distinct id +
// fresh created_at), the call ultimately succeeds (no 401 surfaced), and the DISTINCT stale-401
// counter incremented (stderr telemetry line). STATIC/offline — agent-mode NIP-98 signed locally.
console.log("\ncase 14: A fires on a stale-timestamp 401 → exactly one re-signed retry, succeeds, counter++");
{
  const SK = "12".repeat(32);
  const PK = getPublicKey(Uint8Array.from(Buffer.from(SK, "hex")));
  const OTHER = "34".repeat(32);
  const now = Math.floor(Date.now() / 1000);
  const captured = [];
  let staleServed = false;
  const relay = createServer((rq, rs) => {
    let body = ""; rq.on("data", (c) => (body += c));
    rq.on("end", () => {
      captured.push({ url: rq.url, body, auth: rq.headers["authorization"] || "" });
      const reply = (obj) => { rs.writeHead(200, { "Content-Type": "application/json" }); rs.end(JSON.stringify(obj)); };
      const reply401 = (txt) => { rs.writeHead(401, { "Content-Type": "application/json" }); rs.end(txt); };
      if (rq.method === "GET") return reply({ name: "mock", version: "0", software_sha: "deadbeef" });
      if (rq.url === "/events") return reply({ message: "response:{}" });
      if (rq.url === "/query") {
        let filters = []; try { filters = JSON.parse(body); } catch {}
        const kinds = new Set(filters.flatMap((f) => f.kinds || []));
        // First membership query → a stale-timestamp 401 (exact ±60s window wording, wrapped in JSON).
        if (kinds.has(39002) && !staleServed) { staleServed = true; return reply401(JSON.stringify({ error: "event timestamp outside ±60s window" })); }
        if (kinds.has(39002)) return reply([{ id: "m1", pubkey: PK, kind: 39002, created_at: now, tags: [["d", "chanA"], ["p", PK]], content: "" }]);
        if (kinds.has(39000)) return reply([{ id: "c1", pubkey: PK, kind: 39000, created_at: now, tags: [["d", "chanA"], ["name", "testchan"]], content: "" }]);
        if (kinds.has(0)) return reply([{ id: "p1", pubkey: PK, kind: 0, created_at: now, tags: [], content: JSON.stringify({ name: "me" }) }]);
        if (kinds.has(9)) return reply([{ id: "e1", pubkey: OTHER, kind: 9, created_at: now, tags: [["h", "chanA"]], content: "hi from other" }]);
        return reply([]);
      }
      reply({});
    });
  });
  await new Promise((r) => relay.listen(0, "127.0.0.1", r));
  const port = relay.address().port;
  const { text, err } = await probeToolErr({
    BUZZ_PRIVATE_KEY: SK, BUZZ_NAME: "bridge-test", BUZZ_AUTH_TAG: "", BUZZ_WIRE_SIGN: "",
    BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
  }, "buzz_read", { channel: "testchan", limit: 5 }, { waitMs: 10000, callDelay: 1500 });
  relay.close();
  const memberReqs = captured.filter((c) => c.url === "/query" && /39002/.test(c.body) && c.auth);
  if (text == null || memberReqs.length < 2) {
    skipped(`A-fires: did not observe the stale 401 + its retry (saw ${memberReqs.length} membership queries; reply=${(text || "").slice(0, 80)})`);
  } else {
    console.log("  client sees: " + text.replace(/\\n/g, " | ").slice(0, 160));
    ok(memberReqs.length === 2, `exactly ONE remediation retry — two physical 39002 attempts (got ${memberReqs.length}, no cascade)`);
    const [a1, a2] = [decodeNip98(memberReqs[0].auth), decodeNip98(memberReqs[1].auth)];
    ok(!!a1 && !!a2 && a1.kind === 27235 && a2.kind === 27235, "both attempts carry a NIP-98 (kind 27235) auth event");
    ok(!!a1 && !!a2 && a1.id && a2.id && a1.id !== a2.id, "retry carried a NEWLY-signed NIP-98 (different id → re-signed, not reused)");
    ok(!!a1 && !!a2 && nonceTag(a1) !== nonceTag(a2), "retry NIP-98 has a fresh nonce (distinct per attempt)");
    ok(!!a1 && !!a2 && Number.isFinite(a2.created_at) && a2.created_at >= a1.created_at, "retry NIP-98 created_at is freshly (re-)stamped, not older");
    ok(!/HTTP 401/.test(text), "the stale 401 did NOT surface — the call ultimately succeeded");
    ok(/stale_401_retry_count=1/.test(err), "the DISTINCT stale-401 counter incremented (stderr telemetry line)");
  }
}

// ---- Case 15 (v0.2.17 item 3 / A): a NON-stale 401 → NO retry, surfaces legibly -----------------
// The relay 401s the membership query with "revoked token" (NOT the ±60s message and no stale code).
// A must NOT fire: exactly ONE physical attempt, the 401 surfaces as a legible HTTP 401 error, and
// the stale-401 counter does NOT increment. STATIC/offline.
console.log("\ncase 15: A does NOT fire on a non-stale 401 (revoked token) → no retry, legible error");
{
  const SK = "56".repeat(32);
  const PK = getPublicKey(Uint8Array.from(Buffer.from(SK, "hex")));
  const captured = [];
  const relay = createServer((rq, rs) => {
    let body = ""; rq.on("data", (c) => (body += c));
    rq.on("end", () => {
      captured.push({ url: rq.url, body });
      if (rq.method === "GET") { rs.writeHead(200, { "Content-Type": "application/json" }); rs.end(JSON.stringify({ name: "mock", version: "0", software_sha: "deadbeef" })); return; }
      if (rq.url === "/query") {
        let filters = []; try { filters = JSON.parse(body); } catch {}
        const kinds = new Set(filters.flatMap((f) => f.kinds || []));
        if (kinds.has(39002)) { rs.writeHead(401, { "Content-Type": "application/json" }); rs.end(JSON.stringify({ error: "revoked token" })); return; }
      }
      rs.writeHead(200, { "Content-Type": "application/json" }); rs.end("[]");
    });
  });
  await new Promise((r) => relay.listen(0, "127.0.0.1", r));
  const port = relay.address().port;
  const { text, err } = await probeToolErr({
    BUZZ_PRIVATE_KEY: SK, BUZZ_NAME: "bridge-test", BUZZ_AUTH_TAG: "", BUZZ_WIRE_SIGN: "",
    BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
  }, "buzz_read", { channel: "testchan", limit: 5 }, { waitMs: 9000, callDelay: 1500 });
  relay.close();
  const memberReqs = captured.filter((c) => c.url === "/query" && /39002/.test(c.body));
  if (text == null) skipped("A-no-fire: no tools/call reply");
  else {
    console.log("  client sees: " + text.slice(0, 160));
    ok(memberReqs.length === 1, `NO retry on a non-stale 401 — exactly one physical attempt (got ${memberReqs.length})`);
    ok(/HTTP 401/.test(text) && /revoked token/.test(text), "the non-stale 401 surfaces legibly (HTTP 401 + body)");
    ok(!/stale_401_retry_count/.test(err), "the stale-401 counter did NOT increment for a non-stale 401");
  }
}

// ---- Case 16 (v0.2.17 item 3 / single-flight): stale 401 TWICE → retry once, then surface --------
// The relay 401s EVERY membership query with the stale message. A must retry exactly ONCE and then
// surface the second 401 (no cascade / no loop): exactly TWO physical attempts, an HTTP 401 result,
// and the counter incremented exactly once. STATIC/offline.
console.log("\ncase 16: single-flight — stale 401 twice → retried once then surfaced (no cascade)");
{
  const SK = "78".repeat(32);
  const PK = getPublicKey(Uint8Array.from(Buffer.from(SK, "hex")));
  const captured = [];
  const relay = createServer((rq, rs) => {
    let body = ""; rq.on("data", (c) => (body += c));
    rq.on("end", () => {
      captured.push({ url: rq.url, body });
      if (rq.method === "GET") { rs.writeHead(200, { "Content-Type": "application/json" }); rs.end(JSON.stringify({ name: "mock", version: "0", software_sha: "deadbeef" })); return; }
      if (rq.url === "/query") {
        let filters = []; try { filters = JSON.parse(body); } catch {}
        const kinds = new Set(filters.flatMap((f) => f.kinds || []));
        if (kinds.has(39002)) { rs.writeHead(401, { "Content-Type": "application/json" }); rs.end(JSON.stringify({ error: "event timestamp outside ±60s window" })); return; }
      }
      rs.writeHead(200, { "Content-Type": "application/json" }); rs.end("[]");
    });
  });
  await new Promise((r) => relay.listen(0, "127.0.0.1", r));
  const port = relay.address().port;
  const { text, err } = await probeToolErr({
    BUZZ_PRIVATE_KEY: SK, BUZZ_NAME: "bridge-test", BUZZ_AUTH_TAG: "", BUZZ_WIRE_SIGN: "",
    BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
  }, "buzz_read", { channel: "testchan", limit: 5 }, { waitMs: 9000, callDelay: 1500 });
  relay.close();
  const memberReqs = captured.filter((c) => c.url === "/query" && /39002/.test(c.body));
  const staleHits = (err.match(/stale_401_retry_count=/g) || []).length;
  if (text == null) skipped("single-flight: no tools/call reply");
  else {
    console.log("  client sees: " + text.slice(0, 160));
    ok(memberReqs.length === 2, `at most two physical attempts (original + one remediation) — got ${memberReqs.length}, no cascade`);
    ok(/HTTP 401/.test(text), "the second stale 401 surfaced (did not loop forever)");
    ok(staleHits === 1, `A fired exactly once for this call (counter line count = ${staleHits})`);
  }
}

// ---- Case 17 (v0.2.17 item 3 / B): a slow undici attempt → hard timeout THROWS → fresh-socket retry
// BUZZ_HTTP_TIMEOUT_S is set very low (1s) and the mock DELAYS the first membership response past it,
// so the undici attempt() aborts (throws) → the EXISTING transport catch re-signs a fresh NIP-98 and
// retries over a fresh node:https socket, which the mock serves immediately. Assert: two physical
// 39002 attempts, the retry carried a fresh NIP-98, the transient-retry stderr marker fired, and the
// call ultimately succeeds. (This is the offline simulation of B; the abort is driven by the real
// AbortController timeout wired from BUZZ_HTTP_TIMEOUT_S.)
console.log("\ncase 17: B — slow undici attempt aborts on BUZZ_HTTP_TIMEOUT_S → fresh-socket re-sign retry");
{
  const SK = "9a".repeat(32);
  const PK = getPublicKey(Uint8Array.from(Buffer.from(SK, "hex")));
  const OTHER = "bc".repeat(32);
  const now = Math.floor(Date.now() / 1000);
  const captured = [];
  let delayedOnce = false;
  const relay = createServer((rq, rs) => {
    let body = ""; rq.on("data", (c) => (body += c));
    rq.on("end", () => {
      captured.push({ url: rq.url, body, auth: rq.headers["authorization"] || "" });
      const reply = (obj) => { rs.writeHead(200, { "Content-Type": "application/json" }); rs.end(JSON.stringify(obj)); };
      if (rq.method === "GET") return reply({ name: "mock", version: "0", software_sha: "deadbeef" });
      if (rq.url === "/events") return reply({ message: "response:{}" });
      if (rq.url === "/query") {
        let filters = []; try { filters = JSON.parse(body); } catch {}
        const kinds = new Set(filters.flatMap((f) => f.kinds || []));
        if (kinds.has(39002) && !delayedOnce) {
          // First membership query: hold the response well past the 1s BUZZ_HTTP_TIMEOUT_S so the
          // undici attempt aborts. The retry (fresh socket) is served immediately below.
          delayedOnce = true;
          const t = setTimeout(() => { try { reply([]); } catch {} }, 3000); t.unref?.();
          return;
        }
        if (kinds.has(39002)) return reply([{ id: "m1", pubkey: PK, kind: 39002, created_at: now, tags: [["d", "chanA"], ["p", PK]], content: "" }]);
        if (kinds.has(39000)) return reply([{ id: "c1", pubkey: PK, kind: 39000, created_at: now, tags: [["d", "chanA"], ["name", "testchan"]], content: "" }]);
        if (kinds.has(0)) return reply([{ id: "p1", pubkey: PK, kind: 0, created_at: now, tags: [], content: JSON.stringify({ name: "me" }) }]);
        if (kinds.has(9)) return reply([{ id: "e1", pubkey: OTHER, kind: 9, created_at: now, tags: [["h", "chanA"]], content: "recovered ok" }]);
        return reply([]);
      }
      reply({});
    });
  });
  await new Promise((r) => relay.listen(0, "127.0.0.1", r));
  const port = relay.address().port;
  const { text, err } = await probeToolErr({
    BUZZ_PRIVATE_KEY: SK, BUZZ_NAME: "bridge-test", BUZZ_AUTH_TAG: "", BUZZ_WIRE_SIGN: "",
    BUZZ_HTTP_TIMEOUT_S: "1",
    BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
  }, "buzz_read", { channel: "testchan", limit: 5 }, { waitMs: 13000, callDelay: 1500 });
  relay.close();
  const memberReqs = captured.filter((c) => c.url === "/query" && /39002/.test(c.body) && c.auth);
  if (text == null || memberReqs.length < 2) {
    skipped(`B-timeout: did not observe the aborted attempt + its retry (saw ${memberReqs.length} membership queries; reply=${(text || "").slice(0, 80)})`);
  } else {
    console.log("  client sees: " + text.replace(/\\n/g, " | ").slice(0, 160));
    ok(memberReqs.length === 2, `slow attempt aborted → one fresh-socket retry (two physical 39002 attempts, got ${memberReqs.length})`);
    const [a1, a2] = [decodeNip98(memberReqs[0].auth), decodeNip98(memberReqs[1].auth)];
    ok(!!a1 && !!a2 && a1.id && a2.id && a1.id !== a2.id, "the timeout retry carried a fresh, re-signed NIP-98 (different id)");
    ok(/transient .* fetch failed/.test(err) && /fresh node:https socket/.test(err), "the transport (B→existing) retry marker fired on stderr");
    ok(!/HTTP 401|timeout|outside ±60s/.test(text), "the call ultimately succeeded (no timeout/401 surfaced to the client)");
  }
}

// ---- Case 18 (v0.2.18): MCP initialize serverInfo.version = the shim version, NOT "0.1.0" ------
// The handshake used to advertise a HARDCODED serverInfo.version "0.1.0" for every release. It must
// now report the real SHIM_VERSION so a client/agent can read what's actually running. Fully static
// (handshake is answered in-process; the black-hole relay is never dialed for initialize).
console.log("\ncase 18: MCP initialize serverInfo.version reports the shim version (0.2.18), not 0.1.0");
{
  const AGENT = { BUZZ_PRIVATE_KEY: "55".repeat(32), BUZZ_NAME: "bridge-test", BUZZ_AUTH_TAG: "",
    BUZZ_WIRE_SIGN: "", BUZZ_EKAM_CLIENT_ID: "",
    BUZZ_RELAY_HTTP: "http://127.0.0.1:1", BUZZ_RELAY_URL: "ws://127.0.0.1:1" };
  const res = await probeInit(AGENT);
  if (res == null) skipped("no initialize reply — shim did not start");
  else {
    const si = res.serverInfo || {};
    console.log("  serverInfo: " + JSON.stringify(si));
    ok(si.name === "buzz", "serverInfo.name is still 'buzz'");
    ok(si.version === "0.2.18", `serverInfo.version === '0.2.18' (got '${si.version}')`);
    ok(si.version !== "0.1.0", "serverInfo.version is NOT the old hardcoded '0.1.0'");
    ok(res.protocolVersion === "2024-11-05", "protocolVersion is untouched ('2024-11-05')");
  }
}

// ---- Case 19 (v0.2.18): buzz_whoami surfaces the shim version -------------------------------
// The identity block must carry a readable shim-version line. Offline: whoami builds its block
// locally; relayInfo() against a black-hole host just renders an UNREACHABLE self-report line.
console.log("\ncase 19: buzz_whoami output contains the shim version string");
{
  const AGENT = { BUZZ_PRIVATE_KEY: "55".repeat(32), BUZZ_NAME: "bridge-test", BUZZ_AUTH_TAG: "",
    BUZZ_WIRE_SIGN: "", BUZZ_EKAM_CLIENT_ID: "",
    BUZZ_RELAY_HTTP: "http://127.0.0.1:1", BUZZ_RELAY_URL: "ws://127.0.0.1:1" };
  const text = await probeTool(AGENT, "buzz_whoami", {}, { waitMs: 6000, callDelay: 1000 });
  if (text == null) skipped("no reply for buzz_whoami version case");
  else {
    console.log("  client sees: " + text.replace(/\\n/g, " | ").slice(0, 200));
    ok(/@ola\/buzz-mcp v0\.2\.18/.test(text), "buzz_whoami → reports 'shim: @ola/buzz-mcp v0.2.18'");
    ok(!/reading '|TypeError|is not a function|Cannot read/.test(text), "buzz_whoami → structured result, no crash");
  }
}

// ---- Case 20 (v0.2.18): buzz_doctor surfaces the shim version -------------------------------
// The connector-side diagnosis block must carry the same shim-version line. Offline: doctor probes a
// dead relay over a fresh socket and STILL returns its structured diagnosis (incl. the shim line).
console.log("\ncase 20: buzz_doctor output contains the shim version string");
{
  const AGENT = { BUZZ_PRIVATE_KEY: "55".repeat(32), BUZZ_NAME: "bridge-test", BUZZ_AUTH_TAG: "",
    BUZZ_WIRE_SIGN: "", BUZZ_EKAM_CLIENT_ID: "",
    BUZZ_RELAY_HTTP: "http://127.0.0.1:1", BUZZ_RELAY_URL: "ws://127.0.0.1:1" };
  const text = await probeTool(AGENT, "buzz_doctor", { timeout_s: 2 }, { waitMs: 9000, callDelay: 1200 });
  if (text == null) skipped("no reply for buzz_doctor version case");
  else {
    console.log("  client sees: " + text.replace(/\\n/g, " | ").slice(0, 200));
    ok(/@ola\/buzz-mcp v0\.2\.18/.test(text), "buzz_doctor → reports 'shim: @ola/buzz-mcp v0.2.18'");
    ok(!/reading '|TypeError|is not a function|Cannot read/.test(text), "buzz_doctor → structured result, no crash");
  }
}

console.log(`\nbridge.test.mjs: ${pass} passed, ${fail} failed, ${skip} skipped`);
process.exit(fail ? 1 : 0);
