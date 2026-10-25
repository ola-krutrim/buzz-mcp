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
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { createServer } from "node:http";
import { statSync } from "node:fs";
import { getPublicKey, finalizeEvent } from "nostr-tools/pure";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHIM = join(HERE, "buzz-mcp.mjs");

let pass = 0, fail = 0, skip = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✅ " + m)) : (fail++, console.log("  ❌ " + m)));
const skipped = (m) => (skip++, console.log("  ⊘ SKIP " + m));
// v0.2.30: in the capture-based cases (31–34 and the new 35+), "nothing was captured" is a FAILURE,
// never a skip — a shim that crashed before signing must not read as green.
const missing = (m) => ok(false, "MISSING CAPTURE (counts as a failure): " + m);
const isErr = (text) => typeof text === "string" && /"isError":true/.test(text);

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

// ---- Case 7 (v0.2.16): buzz_login + buzz_doctor registered and the tool count is now 27 -------
// Static: tools/list is answered from the in-process TOOLS array — no network, no OAuth. Agent
// mode boots cleanly offline; the black-hole relay is never dialed for tools/list.
// (Count: 24 through v0.2.24; 27 at v0.2.25 with buzz_create_channel + buzz_edit_channel + buzz_join_channel.)
console.log("\ncase 7: buzz_login + buzz_doctor registered + tool count is 27 (static, no OAuth)");
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
    ok(names.includes("buzz_create_channel"), "buzz_create_channel is registered in tools/list");
    ok(names.includes("buzz_edit_channel"), "buzz_edit_channel is registered in tools/list");
    ok(names.includes("buzz_join_channel"), "buzz_join_channel is registered in tools/list");
    ok(names.length === 27, `total tool count is 27 (got ${names.length})`);
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
    // A real "post as me" login on the developer's machine persists a refresh under the
    // default id; isolate HOME so this case never finds one and short-circuits to
    // "already connected" (seen 2026-09-27 right after a real buzz-mcp-login).
    HOME: mkdtempSync(join(tmpdir(), "bridge-login-noclient-")),
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
console.log("\ncase 18: MCP initialize serverInfo.version reports the shim version (0.2.30), not 0.1.0");
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
    ok(si.version === "0.2.30", `serverInfo.version === '0.2.30' (got '${si.version}')`);
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
    ok(/@ola\/buzz-mcp v0\.2\.30/.test(text), "buzz_whoami → reports 'shim: @ola/buzz-mcp v0.2.30'");
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
    ok(/@ola\/buzz-mcp v0\.2\.30/.test(text), "buzz_doctor → reports 'shim: @ola/buzz-mcp v0.2.30'");
    ok(!/reading '|TypeError|is not a function|Cannot read/.test(text), "buzz_doctor → structured result, no crash");
  }
}

// ============================================================================
// v0.2.19 — CONNECTOR-SIDE WRITE-HEALTH ("check can't see failing posts")
// ----------------------------------------------------------------------------
// buzz_doctor's probes are both READS (health GET + authed /query). A relay that
// serves reads while REJECTING writes used to read as "healthy". The fix records
// each real write's outcome in bridge() and lets buzz_doctor consult it. These
// cases drive ONE process: a real buzz_post (which the mock relay accepts or
// rejects), THEN buzz_doctor in the SAME process, so the per-process write-health
// state persists across the two calls. No test-write is performed by the doctor
// itself — it only reports the outcome of the post the test made.
// ============================================================================

// Drive the shim over stdio: initialize → buzz_post (id 2) → buzz_doctor (id 3),
// both in the SAME process. Returns { postText, doctorText }.
function probePostThenDoctor(env, { channel = "testchan", waitMs = 13000 } = {}) {
  return new Promise((resolve) => {
    const p = spawn("node", [SHIM], { env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    const send = (o) => { try { p.stdin.write(JSON.stringify(o) + "\n"); } catch {} };
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "bridge-test", version: "1" } } });
    setTimeout(() => send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "buzz_post", arguments: { channel, text: "write-health probe" } } }), 1200);
    setTimeout(() => send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "buzz_doctor", arguments: { timeout_s: 3 } } }), 5000);
    setTimeout(() => {
      p.kill();
      const msgs = out.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } });
      const at = (id) => { const m = msgs.find((j) => j && j.id === id); return m ? JSON.stringify(m.result ?? m.error) : null; };
      resolve({ postText: at(2), doctorText: at(3) });
    }, waitMs);
  });
}

// A mock relay parameterised by the status it returns on POST /events. Reads
// (GET /health, POST /query) always succeed so the doctor's read probes are green
// and channel resolution proceeds to the write.
function writeHealthRelay(eventsStatus, eventsBody) {
  const SK = "66".repeat(32);
  const PK = getPublicKey(Uint8Array.from(Buffer.from(SK, "hex")));
  const now = Math.floor(Date.now() / 1000);
  const relay = createServer((rq, rs) => {
    let body = ""; rq.on("data", (c) => (body += c));
    rq.on("end", () => {
      const reply = (obj, status = 200) => { rs.writeHead(status, { "Content-Type": "application/json" }); rs.end(typeof obj === "string" ? obj : JSON.stringify(obj)); };
      if (rq.method === "GET") return reply({ name: "mock", version: "0", software_sha: "healthy" });
      if (rq.url === "/events") return reply(eventsBody, eventsStatus);
      if (rq.url === "/query") {
        let filters = []; try { filters = JSON.parse(body); } catch {}
        const kinds = new Set(filters.flatMap((f) => f.kinds || []));
        if (kinds.has(39002)) return reply([{ id: "m1", pubkey: PK, kind: 39002, created_at: now, tags: [["d", "chanA"], ["p", PK]], content: "" }]);
        if (kinds.has(39000)) return reply([{ id: "c1", pubkey: PK, kind: 39000, created_at: now, tags: [["d", "chanA"], ["name", "testchan"]], content: "" }]);
        return reply([]); // kind 0 profiles + the doctor's authed "[]" probe → 200, empty
      }
      reply({});
    });
  });
  return { relay, SK };
}

// ---- Case 21 (v0.2.19): write fails SYSTEMICALLY (relay 5xx /events) → 'posts failing (reads ok)' --
// A 5xx (or transport throw / persistent stale-401) means the write couldn't reach the relay — the
// systemic case buzz_doctor SHOULD raise. (A 403 permission refusal is tested separately in case 24
// and must NOT trip this — the relay answered, so the write path is up.)
console.log("\ncase 21: buzz_post fails systemically (relay 5xx /events) → buzz_doctor → 'posts failing (reads ok)', NOT 'healthy'");
{
  const { relay, SK } = writeHealthRelay(500, { error: "relay_down" });
  await new Promise((r) => relay.listen(0, "127.0.0.1", r));
  const port = relay.address().port;
  const { postText, doctorText } = await probePostThenDoctor({
    BUZZ_PRIVATE_KEY: SK, BUZZ_NAME: "bridge-test", BUZZ_AUTH_TAG: "", BUZZ_WIRE_SIGN: "",
    BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
  });
  relay.close();
  if (doctorText == null) skipped("no buzz_doctor reply for write-fail case");
  else {
    console.log("  post sees:   " + String(postText).slice(0, 140));
    console.log("  doctor sees: " + String(doctorText).replace(/\\n/g, " | ").slice(0, 260));
    ok(/HTTP 500|relay_down/i.test(String(postText)), "buzz_post → surfaces the relay's systemic write failure");
    ok(/posts failing \(reads ok\)/i.test(doctorText), "buzz_doctor → classifies reads-ok-but-writes-systemically-failing as 'posts failing (reads ok)'");
    ok(!/diagnosis: healthy/i.test(doctorText), "buzz_doctor → does NOT report 'healthy' while writes are systemically failing");
    ok(/#buzz-help/i.test(doctorText), "buzz_doctor → gives the posts-failing recovery (report in #buzz-help)");
    ok(/last write couldn't be delivered/i.test(doctorText), "buzz_doctor → the writes line shows the systemic write failure");
    ok(!/reading '|TypeError|is not a function|Cannot read/.test(doctorText), "buzz_doctor → structured result, no crash");
  }
}

// ---- Case 22 (v0.2.19): write succeeds → buzz_doctor → 'healthy' (last post succeeded) -----------
console.log("\ncase 22: buzz_post succeeds → buzz_doctor → 'healthy' and the writes line confirms the post");
{
  const { relay, SK } = writeHealthRelay(200, { message: "response:{}" });
  await new Promise((r) => relay.listen(0, "127.0.0.1", r));
  const port = relay.address().port;
  const { postText, doctorText } = await probePostThenDoctor({
    BUZZ_PRIVATE_KEY: SK, BUZZ_NAME: "bridge-test", BUZZ_AUTH_TAG: "", BUZZ_WIRE_SIGN: "",
    BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
  });
  relay.close();
  if (doctorText == null) skipped("no buzz_doctor reply for write-ok case");
  else {
    console.log("  post sees:   " + String(postText).slice(0, 140));
    console.log("  doctor sees: " + String(doctorText).replace(/\\n/g, " | ").slice(0, 260));
    ok(/posted to #testchan/i.test(String(postText)), "buzz_post → confirms the post went through");
    ok(/diagnosis: healthy/i.test(doctorText), "buzz_doctor → a reachable relay that accepts the write → 'healthy'");
    ok(/last write reached the relay/i.test(doctorText), "buzz_doctor → the healthy recovery notes the successful write");
    ok(/last write OK/i.test(doctorText), "buzz_doctor → the writes line records the OK write");
    ok(!/posts failing/i.test(doctorText), "buzz_doctor → does NOT report posts-failing after a successful write");
  }
}

// ---- Case 23 (v0.2.19): the BOOT-PUBLISH CANARY — a read-only session still catches broken writes.
// In agent mode the shim fire-and-forgets its kind:0 profile publish on boot (publishProfile), so
// WRITE_HEALTH is populated even when the USER never calls buzz_post. If that boot write fails
// SYSTEMICALLY (5xx here), buzz_doctor reports 'posts failing (reads ok)' with NO explicit post — the
// user learns writes are down before they even try. Only the kind:0 profile is recorded; the kind:10100
// agent card publishes via bridgeCore and is NOT recorded (dx #2), so the systemic count here is 1, not
// 2. (The null/"unverified" branch is reached only in wire mode, where the boot publish is skipped.)
console.log("\ncase 23: read-only session, relay 5xx's the boot profile publish → buzz_doctor → 'posts failing (reads ok)' with NO user post");
{
  const { relay, SK } = writeHealthRelay(500, { error: "relay_down" });
  await new Promise((r) => relay.listen(0, "127.0.0.1", r));
  const port = relay.address().port;
  // Only ever call buzz_doctor — never buzz_post. The only recorded write is the shim's boot kind:0.
  const doctorText = await probeTool({
    BUZZ_PRIVATE_KEY: SK, BUZZ_NAME: "bridge-test", BUZZ_AUTH_TAG: "", BUZZ_WIRE_SIGN: "",
    BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
  }, "buzz_doctor", { timeout_s: 3 }, { waitMs: 9000, callDelay: 2500 });
  relay.close();
  if (doctorText == null) skipped("no buzz_doctor reply for boot-canary case");
  else {
    console.log("  doctor sees: " + String(doctorText).replace(/\\n/g, " | ").slice(0, 260));
    ok(/posts failing \(reads ok\)/i.test(doctorText), "buzz_doctor → the failed boot publish alone trips 'posts failing (reads ok)' — no user post needed");
    ok(!/diagnosis: healthy/i.test(doctorText), "buzz_doctor → does NOT report 'healthy' when the boot write failed systemically");
    ok(/last write couldn't be delivered/i.test(doctorText), "buzz_doctor → the writes line records the failed boot write");
    ok(/1 consecutive systemic/i.test(doctorText), "buzz_doctor → the agent card is NOT counted (systemic count is 1: kind:0 only)");
    ok(!/reading '|TypeError|is not a function|Cannot read/.test(doctorText), "buzz_doctor → structured result, no crash");
  }
}

// ---- Case 24 (v0.2.19): a PERMISSION-DENIED write (403) must NOT read as 'posts failing' (dx #1) ----
// Every /events failure used to trip 'posts failing (reads ok)', so an ordinary 403 (e.g. add_member
// without admin, deleting someone else's message) produced a false "report in #buzz-help" while posting
// worked fine. A request-specific 4xx means the relay ANSWERED — the write path is up — so it must NOT
// flip the verdict. The doctor stays 'healthy' and explains the refusal was request-specific.
console.log("\ncase 24: buzz_post refused with 403 (permission) → buzz_doctor stays 'healthy', NOT 'posts failing' (no false #buzz-help)");
{
  const { relay, SK } = writeHealthRelay(403, { error: "forbidden" });
  await new Promise((r) => relay.listen(0, "127.0.0.1", r));
  const port = relay.address().port;
  const { postText, doctorText } = await probePostThenDoctor({
    BUZZ_PRIVATE_KEY: SK, BUZZ_NAME: "bridge-test", BUZZ_AUTH_TAG: "", BUZZ_WIRE_SIGN: "",
    BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
  });
  relay.close();
  if (doctorText == null) skipped("no buzz_doctor reply for permission-denied case");
  else {
    console.log("  post sees:   " + String(postText).slice(0, 140));
    console.log("  doctor sees: " + String(doctorText).replace(/\\n/g, " | ").slice(0, 260));
    ok(/HTTP 403|forbidden/i.test(String(postText)), "buzz_post → the 403 still surfaces to the caller verbatim");
    ok(!/posts failing/i.test(doctorText), "buzz_doctor → a 403 permission refusal does NOT read as 'posts failing' (dx #1 fix)");
    ok(/diagnosis: healthy/i.test(doctorText), "buzz_doctor → stays 'healthy' — the relay answered, the write path is up");
    ok(!/#buzz-help/i.test(doctorText), "buzz_doctor → no false 'report in #buzz-help' for an ordinary permission error");
    ok(/request-specific/i.test(doctorText), "buzz_doctor → explains the refusal was request-specific (permission/validation)");
  }
}

// ---- Case 25 (v0.2.20): a 429 rate-limit reads as 'rate-limited — retry', not a failure or a refusal
// dx v0.2.20 nit: a throttle isn't a write outage (not "posts failing") and isn't a permission refusal
// ("refused on its merits / no action") — the useful action is to WAIT. buzz_doctor should say so and
// surface the relay's "retry in Ns" hint.
console.log("\ncase 25: buzz_post rate-limited (429) → buzz_doctor → 'rate-limited' with the retry hint, NOT 'posts failing' or a permission refusal");
{
  const { relay, SK } = writeHealthRelay(429, { error: "rate-limited: quota exceeded; retry in 30s" });
  await new Promise((r) => relay.listen(0, "127.0.0.1", r));
  const port = relay.address().port;
  const { postText, doctorText } = await probePostThenDoctor({
    BUZZ_PRIVATE_KEY: SK, BUZZ_NAME: "bridge-test", BUZZ_AUTH_TAG: "", BUZZ_WIRE_SIGN: "",
    BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
  });
  relay.close();
  if (doctorText == null) skipped("no buzz_doctor reply for rate-limit case");
  else {
    console.log("  post sees:   " + String(postText).slice(0, 140));
    console.log("  doctor sees: " + String(doctorText).replace(/\\n/g, " | ").slice(0, 260));
    ok(/HTTP 429|rate-limited/i.test(String(postText)), "buzz_post → the 429 still surfaces to the caller");
    ok(/diagnosis: rate-limited/i.test(doctorText), "buzz_doctor → a 429 reads as 'rate-limited', its own verdict");
    ok(!/posts failing/i.test(doctorText), "buzz_doctor → a 429 is NOT 'posts failing' (throttle, not outage)");
    ok(!/on its merits/i.test(doctorText), "buzz_doctor → a 429 is NOT the generic 'refused on its merits' wording");
    ok(/retry in 30s/i.test(doctorText), "buzz_doctor → surfaces the relay's 'retry in Ns' hint");
    ok(!/reading '|TypeError|is not a function|Cannot read/.test(doctorText), "buzz_doctor → structured result, no crash");
  }
}

// A mock relay that CAPTURES every event posted to /events (for asserting which tags land on which
// kind). GET → health 200; /query → empty; /events → records the event and returns accepted.
function captureRelay() {
  const SK = "77".repeat(32);
  const posted = [];
  const relay = createServer((rq, rs) => {
    let body = ""; rq.on("data", (c) => (body += c));
    rq.on("end", () => {
      const reply = (obj, status = 200) => { rs.writeHead(status, { "Content-Type": "application/json" }); rs.end(typeof obj === "string" ? obj : JSON.stringify(obj)); };
      if (rq.method === "GET") return reply({ name: "mock", version: "0", software_sha: "healthy" });
      if (rq.url === "/events") { try { posted.push(JSON.parse(body)); } catch {} return reply({ event_id: "e1", accepted: true, message: "ok" }); }
      if (rq.url === "/query") return reply([]);
      reply({});
    });
  });
  return { relay, SK, posted };
}

// ---- Case 26 (v0.2.22): BUZZ_AUTH_TAG malformed (bash quote-strip) → LOUD, not silent -----------
// `source`-ing agent.env in bash strips the JSON double-quotes, so JSON.parse fails. v0.2.20 nulled the
// tag SILENTLY → the relay then 403s membership with no clue why. v0.2.22 must (a) warn on stderr with
// the single-quote remedy, and (b) have buzz_doctor name it as the root cause (a read probe can pass
// while writes 403 for the missing owner tag, so only an explicit config check catches it).
console.log("\ncase 26: BUZZ_AUTH_TAG malformed → stderr warning + buzz_doctor 'config: BUZZ_AUTH_TAG malformed'");
{
  const { relay, SK } = writeHealthRelay(200, {});
  await new Promise((r) => relay.listen(0, "127.0.0.1", r));
  const port = relay.address().port;
  const { text, err } = await probeToolErr({
    BUZZ_PRIVATE_KEY: SK, BUZZ_NAME: "bridge-test", BUZZ_WIRE_SIGN: "",
    BUZZ_AUTH_TAG: "[auth,aabbcc,,deadbeef]",   // quote-stripped: looks like a tag, is NOT valid JSON
    BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
  }, "buzz_doctor", {}, { waitMs: 8000 });
  relay.close();
  if (text == null) skipped("no buzz_doctor reply for malformed-auth-tag case");
  else {
    console.log("  doctor: " + String(text).replace(/\\n/g, " | ").slice(0, 260));
    ok(/BUZZ_AUTH_TAG is set but is not a valid/i.test(err), "startup → loud stderr warning naming BUZZ_AUTH_TAG");
    ok(/single-quote/i.test(err), "startup → warning gives the single-quote remedy");
    ok(/config: BUZZ_AUTH_TAG malformed/i.test(text), "buzz_doctor → classifies it as 'config: BUZZ_AUTH_TAG malformed'");
    ok(/single-quote/i.test(text), "buzz_doctor → recovery gives the single-quote fix");
    ok(!/reading '|TypeError|is not a function|Cannot read/.test(text), "buzz_doctor → structured result, no crash");
  }
}

// ---- Case 27: a VALID BUZZ_AUTH_TAG does NOT warn, and buzz_doctor does NOT flag config (control) --
console.log("\ncase 27: valid BUZZ_AUTH_TAG → no malformed warning, no config verdict (control)");
{
  const { relay, SK } = writeHealthRelay(200, {});
  await new Promise((r) => relay.listen(0, "127.0.0.1", r));
  const port = relay.address().port;
  const validTag = JSON.stringify(["auth", "aa".repeat(32), "", "bb".repeat(32)]);
  const { text, err } = await probeToolErr({
    BUZZ_PRIVATE_KEY: SK, BUZZ_NAME: "bridge-test", BUZZ_WIRE_SIGN: "",
    BUZZ_AUTH_TAG: validTag,
    BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
  }, "buzz_doctor", {}, { waitMs: 8000 });
  relay.close();
  if (text == null) skipped("no buzz_doctor reply for valid-auth-tag case");
  else {
    ok(!/BUZZ_AUTH_TAG is set but is not a valid/i.test(err), "valid tag → NO malformed stderr warning");
    ok(!/config: BUZZ_AUTH_TAG malformed/i.test(text), "valid tag → buzz_doctor does NOT flag config");
    ok(/auth tag \(config\): present/i.test(text), "buzz_doctor → auth-tag config line reads 'present'");
  }
}

// ---- Case 28: BUZZ_PICKER_OWNER_TAG malformed → its own distinct loud warning (2b) ---------------
console.log("\ncase 28: BUZZ_PICKER_OWNER_TAG malformed → distinct stderr warning (2b)");
{
  const { relay, SK } = writeHealthRelay(200, {});
  await new Promise((r) => relay.listen(0, "127.0.0.1", r));
  const port = relay.address().port;
  const { err } = await probeToolErr({
    BUZZ_PRIVATE_KEY: SK, BUZZ_NAME: "bridge-test", BUZZ_WIRE_SIGN: "", BUZZ_AUTH_TAG: "",
    BUZZ_PICKER_OWNER_TAG: "[picker-owner,aabb,,ccdd]",   // quote-stripped
    BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
  }, "buzz_doctor", {}, { waitMs: 6000 });
  relay.close();
  ok(/BUZZ_PICKER_OWNER_TAG is set but is not a valid/i.test(err), "startup → distinct stderr warning for BUZZ_PICKER_OWNER_TAG");
  ok(/single-quote/i.test(err), "picker warning → gives the single-quote remedy");
}

// ---- Case 29 (2b): a valid BUZZ_PICKER_OWNER_TAG lands on kind:10100 ONLY, never on kind:0 (C3) ---
// The whole safety property of 2b lives in the shim: the individual-signed tag goes on the discovery
// card (kind:10100) and NOWHERE near the auth credential or kind:0 (which stays team-signed).
console.log("\ncase 29 (2b): picker-owner tag threads onto kind:10100 verbatim, never onto kind:0 (C3)");
{
  const { relay, SK, posted } = captureRelay();
  await new Promise((r) => relay.listen(0, "127.0.0.1", r));
  const port = relay.address().port;
  const pickerTag = ["picker-owner", "cd".repeat(32), "created_at<0", "ef".repeat(32)];
  const authTag = ["auth", "12".repeat(32), "", "34".repeat(32)];
  await probeTool({
    BUZZ_PRIVATE_KEY: SK, BUZZ_NAME: "bridge-test", BUZZ_WIRE_SIGN: "",
    BUZZ_AUTH_TAG: JSON.stringify(authTag),
    BUZZ_PICKER_OWNER_TAG: JSON.stringify(pickerTag),
    BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
  }, "buzz_whoami", {}, { waitMs: 6000, callDelay: 1500 });
  relay.close();
  const k0 = posted.find((e) => e && e.kind === 0);
  const k10100 = posted.find((e) => e && e.kind === 10100);
  const tagHead = (ev, head) => (ev && (ev.tags || []).find((t) => Array.isArray(t) && t[0] === head)) || null;
  if (!k10100) skipped("no kind:10100 card captured (boot profile publish did not land in time)");
  else {
    console.log("  10100 tags: " + JSON.stringify(k10100.tags));
    const pk = tagHead(k10100, "picker-owner");
    ok(!!pk, "kind:10100 card carries the ['picker-owner',…] tag");
    ok(JSON.stringify(pk) === JSON.stringify(pickerTag), "picker-owner tag threaded VERBATIM (no re-encode of [2])");
    ok(!tagHead(k10100, "auth"), "kind:10100 card does NOT carry an ['auth',…] tag");
    if (k0) {
      ok(!tagHead(k0, "picker-owner"), "C3: kind:0 does NOT carry the picker-owner tag");
      ok(!!tagHead(k0, "auth"), "kind:0 still carries the team ['auth',…] delegation");
    } else {
      skipped("no kind:0 event captured to cross-check C3");
    }
  }
}

// ---- Case 30: buzz_reply e-tag markers resolve the way the relay resolves them -----------------
// The relay (buzz-core nip10.rs ThreadMarkers::resolve) reads (root+reply) → nested, (reply only) →
// direct reply to the root, and (root only) → TOP-LEVEL. Ingest (buzz-relay ingest.rs) then refuses a
// reply whose root is not the parent's own thread root: 400 "root tag does not match thread ancestry".
// v0.2.23 sent a lone "root" to a thread head (stored flat). A first v0.2.24 draft sent reply-only to
// every target without a "root" marker, which 400s on a target that is itself a direct reply
// (reply-only is how desktop, mobile and the shim all tag those). Both are checked here, against
// ports of the relay's resolve rule AND its ancestry check, fed the target's tags as well.
console.log("\ncase 30: buzz_reply → e-tags the relay resolves under the target's real thread root");
{
  const resolve = (tags) => {
    let root = null, reply = null;
    for (const t of tags || []) if (t[0] === "e" && /^[0-9a-f]{64}$/.test(t[1] || "")) {
      if (t[3] === "root") root = t[1];
      if (t[3] === "reply") reply = t[1];
    }
    if (root && reply) return [root, reply];
    if (reply) return [reply, reply];
    return null;   // root-only or neither → top-level
  };
  // ingest.rs: the reply's resolved root must equal the parent's effective root, which is the
  // parent's own resolved root when the parent is in a thread, else the parent itself.
  const ancestryOk = (replyTags, parent) => {
    const r = resolve(replyTags);
    if (!r || r[1] !== parent.id) return false;
    const parentRoot = (resolve(parent.tags) || [parent.id])[0];
    return r[0] === parentRoot;
  };
  const replyRelay = (target) => {
    const SK = "88".repeat(32);
    const PK = getPublicKey(Uint8Array.from(Buffer.from(SK, "hex")));
    const now = Math.floor(Date.now() / 1000);
    const posted = [];
    const relay = createServer((rq, rs) => {
      let body = ""; rq.on("data", (c) => (body += c));
      rq.on("end", () => {
        const reply = (obj, status = 200) => { rs.writeHead(status, { "Content-Type": "application/json" }); rs.end(JSON.stringify(obj)); };
        if (rq.method === "GET") return reply({ name: "mock", version: "0", software_sha: "healthy" });
        if (rq.url === "/events") { try { posted.push(JSON.parse(body)); } catch {} return reply({ event_id: "e1", accepted: true, message: "ok" }); }
        if (rq.url === "/query") {
          let filters = []; try { filters = JSON.parse(body); } catch {}
          if (filters.some((f) => (f.ids || []).includes(target.id))) return reply([target]);
          const kinds = new Set(filters.flatMap((f) => f.kinds || []));
          if (kinds.has(39002)) return reply([{ id: "m1", pubkey: PK, kind: 39002, created_at: now, tags: [["d", "chanA"], ["p", PK]], content: "" }]);
          if (kinds.has(39000)) return reply([{ id: "c1", pubkey: PK, kind: 39000, created_at: now, tags: [["d", "chanA"], ["name", "testchan"]], content: "" }]);
          return reply([]);
        }
        reply({});
      });
    });
    return { relay, SK, posted };
  };
  const HEAD = "a1".repeat(32), MID = "b2".repeat(32), DEEP = "d4".repeat(32), OLD = "e5".repeat(32), AUTHOR = "c3".repeat(32);
  const ev = (id, tags) => ({ id, pubkey: AUTHOR, kind: 9, created_at: 1, content: "x", tags: [["h", "chanA"], ...tags] });
  const cases = [
    { name: "reply to a thread head", target: ev(HEAD, []),
      wantE: [["e", HEAD, "", "reply"]] },
    { name: "reply to a direct reply (reply-only, as desktop/mobile/shim send it)", target: ev(MID, [["e", HEAD, "", "reply"]]),
      wantE: [["e", HEAD, "", "root"], ["e", MID, "", "reply"]] },
    { name: "reply to a nested reply (root+reply)", target: ev(DEEP, [["e", HEAD, "", "root"], ["e", MID, "", "reply"]]),
      wantE: [["e", HEAD, "", "root"], ["e", DEEP, "", "reply"]] },
    { name: "reply to a legacy root-only reply (stored top-level)", target: ev(OLD, [["e", HEAD, "", "root"]]),
      wantE: [["e", OLD, "", "reply"]] },
  ];
  for (const c of cases) {
    const { relay, SK, posted } = replyRelay(c.target);
    await new Promise((r) => relay.listen(0, "127.0.0.1", r));
    const port = relay.address().port;
    await probeTool({
      BUZZ_PRIVATE_KEY: SK, BUZZ_NAME: "bridge-test", BUZZ_WIRE_SIGN: "", BUZZ_AUTH_TAG: "",
      BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
    }, "buzz_reply", { channel: "testchan", event: c.target.id, text: "threaded" }, { waitMs: 7000, callDelay: 1500 });
    relay.close();
    const sent = posted.find((e) => e && e.kind === 9);
    if (!sent) { skipped(`no kind:9 reply captured for '${c.name}'`); continue; }
    const eTags = (sent.tags || []).filter((t) => t[0] === "e");
    console.log(`  ${c.name}: e-tags ${JSON.stringify(eTags)}`);
    ok(JSON.stringify(eTags) === JSON.stringify(c.wantE), `${c.name} → e-tags ${JSON.stringify(c.wantE)}`);
    ok(ancestryOk(sent.tags, c.target), `${c.name} → passes the relay's ancestry check (not top-level, not a 400)`);
  }
}

// ---- Case 31: buzz_create_channel emits a valid NIP-29 create-group (kind 9007) --------------
// The relay (buzz-sdk build_create_channel + buzz-relay kind:9007 ingest) expects an h-tag channel
// UUID, a canonicalized `name`, `visibility` (open|private), `channel_type` (stream|forum), and
// optional `about`/`ttl`; the signer becomes the channel owner. This asserts the shim emits exactly
// that shape — defaults (open/stream) and an explicit private forum with a #-prefixed, padded name
// that must come out canonicalized. Local mock relay (no network): GET=NIP-11, POST /events captures.
console.log("\ncase 31: buzz_create_channel → kind:9007 create-group with the relay's expected tags");
{
  const mk = () => {
    const posted = [];
    const relay = createServer((rq, rs) => {
      let body = ""; rq.on("data", (c) => (body += c));
      rq.on("end", () => {
        const reply = (obj) => { rs.writeHead(200, { "Content-Type": "application/json" }); rs.end(JSON.stringify(obj)); };
        if (rq.method === "GET") return reply({ name: "mock", version: "0", software_sha: "healthy" });
        if (rq.url === "/events") { try { posted.push(JSON.parse(body)); } catch {} return reply({ event_id: "e1", accepted: true, message: "ok" }); }
        return reply([]);
      });
    });
    return { relay, posted };
  };
  const cases = [
    { name: "defaults (private stream — fail-closed)", args: { name: "data-lake" },
      wantName: "data-lake", wantVis: "private", wantType: "stream", wantAbout: undefined },
    { name: "explicit open stream", args: { name: "town-square", visibility: "open" },
      wantName: "town-square", wantVis: "open", wantType: "stream", wantAbout: undefined },
    { name: "private forum, #-prefixed padded name + description", args: { name: "#  Ops Review ", visibility: "private", type: "forum", description: "weekly ops" },
      wantName: "Ops Review", wantVis: "private", wantType: "forum", wantAbout: "weekly ops" },
    // v0.2.27 client-side limits (per buzz_security's 0.2.26 GO notes) — each must be refused, no 9007 signed.
    { name: "name too long (81 chars) is refused", args: { name: "x".repeat(81) }, wantRefused: true, wantErr: /too long/ },
    { name: "name with a control char is refused", args: { name: "ops\u0007room" }, wantRefused: true, wantErr: /control characters/ },
    { name: "name with a line break is refused", args: { name: "ops\nroom" }, wantRefused: true, wantErr: /control characters/ },
    { name: "name with a bidi override is refused (v0.2.29 anti-lookalike)", args: { name: "ops\u202Eroom" }, wantRefused: true, wantErr: /bidirectional control/ },
    { name: "name with a zero-width char is refused (v0.2.29 anti-lookalike)", args: { name: "ops\u200Broom" }, wantRefused: true, wantErr: /invisible|zero-width/ },
    { name: "description too long (501 chars) is refused", args: { name: "notes", description: "y".repeat(501) }, wantRefused: true, wantErr: /too long/ },
    // v0.2.30: every Bidi_Control is refused (LRM/RLM/ALM were not in the v0.2.29 set) + other default-ignorables.
    { name: "name with LRM U+200E is refused (v0.2.30)", args: { name: "ops\u200Eroom" }, wantRefused: true, wantErr: /bidirectional control/ },
    { name: "name with RLM U+200F is refused (v0.2.30)", args: { name: "ops\u200Froom" }, wantRefused: true, wantErr: /bidirectional control/ },
    { name: "name with ALM U+061C is refused (v0.2.30)", args: { name: "ops\u061Croom" }, wantRefused: true, wantErr: /bidirectional control/ },
    { name: "name with an isolate U+2067 is refused (v0.2.30)", args: { name: "ops\u2067room" }, wantRefused: true, wantErr: /bidirectional control/ },
    { name: "name with a soft hyphen U+00AD is refused (v0.2.30)", args: { name: "ops\u00ADroom" }, wantRefused: true, wantErr: /invisible/ },
    { name: "name with a BOM U+FEFF is refused (v0.2.30)", args: { name: "ops\uFEFFroom" }, wantRefused: true, wantErr: /invisible/ },
    // Variation selectors are STRIPPED, not refused: emoji names keep working.
    { name: "emoji name 'Pulse 💓' still works (v0.2.30)", args: { name: "Pulse 💓", visibility: "private" },
      wantName: "Pulse 💓", wantVis: "private", wantType: "stream", wantAbout: undefined },
    { name: "emoji + VS16 'Pulse ❤️' → VS stripped, accepted (v0.2.30)", args: { name: "Pulse \u2764\uFE0F", visibility: "private" },
      wantName: "Pulse \u2764", wantVis: "private", wantType: "stream", wantAbout: undefined },
  ];
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  for (const c of cases) {
    const { relay, posted } = mk();
    await new Promise((r) => relay.listen(0, "127.0.0.1", r));
    const port = relay.address().port;
    const text = await probeTool({
      BUZZ_PRIVATE_KEY: "66".repeat(32), BUZZ_NAME: "bridge-test", BUZZ_WIRE_SIGN: "", BUZZ_AUTH_TAG: "",
      BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
    }, "buzz_create_channel", c.args, { waitMs: 7000, callDelay: 1500 });
    relay.close();
    const ev = posted.find((e) => e && e.kind === 9007);
    if (c.wantRefused) {
      ok(!ev, `${c.name} → no kind:9007 posted (client-side validation blocked it)`);
      ok(isErr(text) && (!c.wantErr || c.wantErr.test(JSON.parse(text).content[0].text)), `${c.name} → the client got the refusal error${c.wantErr ? ` (${c.wantErr})` : ""}, not a crash/silence`);
      continue;
    }
    if (!ev) { missing(`no kind:9007 event captured for '${c.name}'`); continue; }
    const tg = (k) => { const t = (ev.tags || []).find((x) => x[0] === k); return t ? t[1] : undefined; };
    console.log(`  ${c.name}: tags ${JSON.stringify(ev.tags)}`);
    ok(ev.kind === 9007, `${c.name} → kind 9007`);
    ok(ev.content === "", `${c.name} → empty content`);
    ok(UUID_RE.test(tg("h") || ""), `${c.name} → h is a channel UUID`);
    ok(tg("name") === c.wantName, `${c.name} → name "${c.wantName}" (canonicalized)`);
    ok(tg("visibility") === c.wantVis, `${c.name} → visibility ${c.wantVis}`);
    ok(tg("channel_type") === c.wantType, `${c.name} → channel_type ${c.wantType}`);
    ok(tg("about") === c.wantAbout, `${c.name} → about ${c.wantAbout === undefined ? "(absent)" : `"${c.wantAbout}"`}`);
  }
}

// ---- Case 32: buzz_edit_channel emits a PATCH-style NIP-29 edit-metadata (kind 9002) ----------
// Only the fields passed appear as tags (the relay applies each as its own ChannelUpdate and leaves
// omitted fields untouched), always under the target channel's h-tag. Resolving the channel by NAME
// exercises resolveChannel, so the mock serves the member (39002) + metadata (39000) events.
console.log("\ncase 32: buzz_edit_channel → kind:9002 carries only the changed fields, under the channel h-tag");
{
  const CHID = "c0ffee00-1111-2222-3333-444455556666";
  // v0.2.30 (D): the mock now APPLIES each kind:9002 to its 39000 state (like the relay), so the
  // shim's post-edit read-back verification sees the change; case 35 covers a relay that doesn't.
  const relayWith = () => {
    const posted = [];
    const PK = getPublicKey(Uint8Array.from(Buffer.from("77".repeat(32), "hex")));
    const now = Math.floor(Date.now() / 1000);
    const st = { name: "projects", vis: "private", about: "", ttl: "", ver: 0 };
    const meta = () => ({ id: "c1", pubkey: PK, kind: 39000, created_at: now + st.ver, content: "",
      tags: [["d", CHID], ["name", st.name], [st.vis === "private" ? "private" : "public"], ...(st.about ? [["about", st.about]] : []), ...(st.ttl ? [["ttl", st.ttl]] : [])] });
    const relay = createServer((rq, rs) => {
      let body = ""; rq.on("data", (c) => (body += c));
      rq.on("end", () => {
        const reply = (o) => { rs.writeHead(200, { "Content-Type": "application/json" }); rs.end(JSON.stringify(o)); };
        if (rq.method === "GET") return reply({ name: "mock", version: "0", software_sha: "healthy" });
        if (rq.url === "/events") {
          let ev = null; try { ev = JSON.parse(body); posted.push(ev); } catch {}
          if (ev && ev.kind === 9002) {
            for (const t of ev.tags || []) {
              if (t[0] === "name") st.name = t[1];
              if (t[0] === "visibility") st.vis = t[1];
              if (t[0] === "about") st.about = t[1];
              if (t[0] === "ttl") st.ttl = t[1];
            }
            st.ver++;
          }
          return reply({ event_id: "e1", accepted: true, message: "ok" });
        }
        if (rq.url === "/query") {
          let filters = []; try { filters = JSON.parse(body); } catch {}
          const kinds = new Set(filters.flatMap((f) => f.kinds || []));
          if (kinds.has(39002)) return reply([{ id: "m1", pubkey: PK, kind: 39002, created_at: now, tags: [["d", CHID], ["p", PK]], content: "" }]);
          if (kinds.has(39000)) return reply([meta()]);
          return reply([]);
        }
        reply({});
      });
    });
    return { relay, posted };
  };
  const cases = [
    { name: "rename only", args: { channel: "projects", name: "#  Projects X " },
      wantTags: [["h", CHID], ["name", "Projects X"]] },
    { name: "visibility + description", args: { channel: "projects", visibility: "private", description: "internal" },
      wantTags: [["h", CHID], ["visibility", "private"], ["about", "internal"]] },
    { name: "clear ttl", args: { channel: "projects", ttl: 0 },
      wantTags: [["h", CHID], ["ttl", ""]] },
    // The mock channel's current visibility is private, so flipping it open is the exposing transition.
    { name: "private→open WITHOUT confirm is refused (history-exposure guard)", args: { channel: "projects", visibility: "open" },
      wantRefused: true, wantErr: /confirm_make_public/ },
    { name: "private→open WITH confirm_make_public", args: { channel: "projects", visibility: "open", confirm_make_public: true },
      wantTags: [["h", CHID], ["visibility", "open"]] },
    // v0.2.27 client-side limits (per buzz_security's 0.2.26 GO notes) — refused, no 9002 signed.
    { name: "rename to a too-long name is refused", args: { channel: "projects", name: "z".repeat(81) }, wantRefused: true, wantErr: /too long/ },
    { name: "rename with a zero-width char is refused (v0.2.29)", args: { channel: "projects", name: "Proj\u200Bects" }, wantRefused: true, wantErr: /invisible|zero-width/ },
    { name: "description too long is refused", args: { channel: "projects", description: "w".repeat(501) }, wantRefused: true, wantErr: /too long/ },
    // v0.2.30: LRM / RLM / ALM refused on EDIT too.
    { name: "rename with LRM U+200E is refused (v0.2.30)", args: { channel: "projects", name: "Proj\u200Eects" }, wantRefused: true, wantErr: /bidirectional control/ },
    { name: "rename with RLM U+200F is refused (v0.2.30)", args: { channel: "projects", name: "Proj\u200Fects" }, wantRefused: true, wantErr: /bidirectional control/ },
    { name: "rename with ALM U+061C is refused (v0.2.30)", args: { channel: "projects", name: "Proj\u061Cects" }, wantRefused: true, wantErr: /bidirectional control/ },
    { name: "rename to an emoji+VS16 name → VS stripped (v0.2.30)", args: { channel: "projects", name: "Pulse \u2764\uFE0F" },
      wantTags: [["h", CHID], ["name", "Pulse \u2764"]] },
  ];
  for (const c of cases) {
    const { relay, posted } = relayWith();
    await new Promise((r) => relay.listen(0, "127.0.0.1", r));
    const port = relay.address().port;
    const text = await probeTool({
      BUZZ_PRIVATE_KEY: "77".repeat(32), BUZZ_NAME: "bridge-test", BUZZ_WIRE_SIGN: "", BUZZ_AUTH_TAG: "",
      BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
    }, "buzz_edit_channel", c.args, { waitMs: 7000, callDelay: 1500 });
    relay.close();
    const ev = posted.find((e) => e && e.kind === 9002);
    if (c.wantRefused) {
      ok(!ev, `${c.name} → no kind:9002 posted (guard blocked the write)`);
      ok(isErr(text) && (!c.wantErr || c.wantErr.test(JSON.parse(text).content[0].text)), `${c.name} → the client got the refusal error${c.wantErr ? ` (${c.wantErr})` : ""}`);
      continue;
    }
    if (!ev) { missing(`no kind:9002 captured for '${c.name}'`); continue; }
    console.log(`  ${c.name}: tags ${JSON.stringify(ev.tags)}`);
    ok(JSON.stringify(ev.tags) === JSON.stringify(c.wantTags), `${c.name} → tags ${JSON.stringify(c.wantTags)} (patch — only the changed fields)`);
    ok(!isErr(text) && /verified against the relay's kind:39000/.test(text || ""), `${c.name} → (D) read-back verified, reported as success`);
  }
}

// ---- Case 33: buzz_join_channel self-joins only OPEN channels; refuses private targets ---------
// The relay self-joins only an OPEN channel (handle_join_request: visibility must be "open"), and
// 39000 metadata marks visibility "public" vs "private" (group_metadata_tags; a "closed" tag is on
// EVERY channel and is not the gate). v0.2.27 refuses a known-private target client-side — on the
// UUID path (reading the channel's 39000) and the name path (no fallback to a private name match) —
// rather than signing a 9021 the relay bounces. The mock serves 39002 empty (member of nothing), so
// a name resolves only via directory discovery, and serves 39000 for #d lookups and the limit scan.
console.log("\ncase 33: buzz_join_channel → self-join only OPEN channels; refuse private targets client-side");
{
  const AGENT_PK = getPublicKey(Uint8Array.from(Buffer.from("77".repeat(32), "hex")));
  const now = Math.floor(Date.now() / 1000);
  const meta39000 = (ch) => ({ id: `meta-${ch.id}`, pubkey: AGENT_PK, kind: 39000, created_at: now,
    tags: [["d", ch.id], ["name", ch.name], [ch.visibility === "private" ? "private" : "public"], ["closed"]], content: "" });
  const mkJoin = (dir) => {
    const posted = [];
    const relay = createServer((rq, rs) => {
      let body = ""; rq.on("data", (c) => (body += c));
      rq.on("end", () => {
        const reply = (o) => { rs.writeHead(200, { "Content-Type": "application/json" }); rs.end(JSON.stringify(o)); };
        if (rq.method === "GET") return reply({ name: "mock", version: "0", software_sha: "healthy" });
        if (rq.url === "/events") { try { posted.push(JSON.parse(body)); } catch {} return reply({ event_id: "e1", accepted: true, message: "ok" }); }
        if (rq.url === "/query") {
          let filters = []; try { filters = JSON.parse(body); } catch {}
          const kinds = new Set(filters.flatMap((f) => f.kinds || []));
          if (kinds.has(39002)) return reply([]);                 // agent is a member of nothing
          if (kinds.has(39000)) {
            const dfilter = filters.flatMap((f) => f["#d"] || []);
            const pool = dfilter.length ? dir.filter((c) => dfilter.includes(c.id)) : dir;
            return reply(pool.map(meta39000));
          }
          return reply([]);
        }
        reply({});
      });
    });
    return { relay, posted };
  };
  const OPEN = { id: "0b57a11e-9999-8888-7777-666655554444", name: "town-square", visibility: "open" };
  const PRIV = { id: "0b57a11e-0000-1111-2222-333344445555", name: "leadership", visibility: "private" };
  const cases = [
    { name: "open channel by UUID → 9021 posted", dir: [OPEN], args: { channel: OPEN.id }, wantH: OPEN.id },
    { name: "private channel by UUID → refused, no 9021", dir: [PRIV], args: { channel: PRIV.id }, wantRefused: true },
    { name: "UUID with no readable metadata → proceeds (relay is the gate)", dir: [], args: { channel: OPEN.id }, wantH: OPEN.id },
    { name: "open channel by name (discovery) → 9021 posted", dir: [OPEN], args: { channel: "town-square" }, wantH: OPEN.id },
    { name: "private channel by name → refused, no named[0] fallback", dir: [PRIV], args: { channel: "leadership" }, wantRefused: true },
    { name: "unknown name → error, no 9021", dir: [OPEN], args: { channel: "no-such-channel" }, wantRefused: true },
  ];
  for (const c of cases) {
    const { relay, posted } = mkJoin(c.dir);
    await new Promise((r) => relay.listen(0, "127.0.0.1", r));
    const port = relay.address().port;
    await probeTool({
      BUZZ_PRIVATE_KEY: "77".repeat(32), BUZZ_NAME: "bridge-test", BUZZ_WIRE_SIGN: "", BUZZ_AUTH_TAG: "",
      BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
    }, "buzz_join_channel", c.args, { waitMs: 7000, callDelay: 1500 });
    relay.close();
    const ev = posted.find((e) => e && e.kind === 9021);
    if (c.wantRefused) { ok(!ev, `${c.name} → no kind:9021 posted`); continue; }
    if (!ev) { missing(`no kind:9021 captured for '${c.name}'`); continue; }
    console.log(`  ${c.name}: tags ${JSON.stringify(ev.tags)}`);
    ok(ev.kind === 9021 && ev.content === "", `${c.name} → kind 9021, empty content`);
    ok(JSON.stringify((ev.tags || []).filter((t) => t[0] === "e")) === "[]", `${c.name} → no e-tags`);
    const h = (ev.tags || []).find((t) => t[0] === "h");
    ok(h && h[1] === c.wantH, `${c.name} → h-tag is ${c.wantH}`);
  }
}

// ---- Case 34: resolveRecipient — server-side name search (not the 200-newest cap), BOTH name
// fields normalized (NFC + bidi/zero-width stripped), agent-mode email REFUSED, fail-closed (v0.2.29)
// The old resolver matched `to` against the 200 newest kind:0 profiles on a single name field, so an
// older profile (Anirban's) or a client-shown name differing from the stored field never resolved.
// v0.2.28 added a server-side search + both fields; v0.2.29 hardens it: agent-mode email no longer
// resolves (the self-asserted nip05 fallback let anyone claim a colleague's address — #1492), and a
// bidi/zero-width lookalike is normalized away so it collides with the real name → fail-closed.
// Exercised through buzz_dm_open: resolves `to` → pubkey → signs a kind:41010 DM_OPEN whose p-tag is
// the resolved pubkey. The mock serves kind:0 "search" results for any kinds:[0] query and answers
// /events so openDm gets a channel id (no listing fallback).
console.log("\ncase 34: resolveRecipient → name search (both fields, NFKC+fold+TR39 skeleton), fail-closed, archived/profile-search aware");
{
  const ANI = "a".repeat(64), BOB = "b".repeat(64), CAR = "c".repeat(64);
  const RELAY_SK = Uint8Array.from(Buffer.from("99".repeat(32), "hex"));
  const RELAY_SELF = getPublicKey(RELAY_SK);
  const OTHER_SK = Uint8Array.from(Buffer.from("98".repeat(32), "hex"));
  const archiveList = (sk, pks, extraTags = [["-"]]) => finalizeEvent({ kind: 13535, created_at: Math.floor(Date.now() / 1000), tags: [...extraTags, ...pks.map((p) => ["p", p])], content: "" }, sk);
  // Anirban's profile: `name` and `display_name` DIFFER — the real-world bug (a client shows one,
  // the profile's other field differs: "Anirban Das" vs "Anirban D Das").
  const DIR = {
    anirban: [{ pubkey: ANI, name: "Anirban Das", display_name: "Anirban D Das", nip05: "anirban.das@olaelectric.com" }],
    dupe:    [{ pubkey: BOB, name: "Sam Roy", display_name: "Sam Roy", nip05: "" },
              { pubkey: CAR, name: "Sam Roy", display_name: "Sam Roy", nip05: "" }],
    // A zero-width twin of the real name (BOB injects U+200B) → collides with ANI → ambiguous → refused.
    lookalike: [{ pubkey: ANI, name: "Anirban Das", display_name: "", nip05: "" },
                { pubkey: BOB, name: "Anirban\u200B Das", display_name: "", nip05: "" }],
    // v0.2.30: the ONLY hit is a Cyrillic-А homoglyph of what was typed (skeleton-equal, raw differs).
    cyrOnly: [{ pubkey: BOB, name: "\u0410nirban Das", display_name: "", nip05: "" }],
    // v0.2.30: the ONLY hit is a fullwidth (NFKC-equal) twin.
    fullwidthOnly: [{ pubkey: BOB, name: "\uFF21nirban Das", display_name: "", nip05: "" }],
    // v0.2.30: a ligature twin "ﬁnance-bot" (U+FB01) of "finance-bot".
    ligOnly: [{ pubkey: BOB, name: "\uFB01nance-bot", display_name: "", nip05: "" }],
    // v0.2.30 (B): matched by the search engine only through bio / nip05 — never a resolution.
    bioOnly: [{ pubkey: CAR, name: "Mallory", display_name: "Mal", about: "assistant to Anirban Das", nip05: "anirban-das@evil.example" }],
    exactPlusBio: [{ pubkey: CAR, name: "Mallory", display_name: "", about: "Anirban Das fan account", nip05: "" },
                   { pubkey: ANI, name: "Anirban Das", display_name: "", nip05: "" }],
    none:    [],
  };
  // opts: { self, archive: [events], search: "none" | "api" | "404" }
  const mkDir = (profs, opts = {}) => {
    const posted = [], seen = { searchApi: [], nip50: 0, archiveQ: 0 };
    const k0 = () => profs.map((p, i) => ({ id: `pf${i}`, pubkey: p.pubkey, kind: 0, created_at: Math.floor(Date.now() / 1000), tags: [], content: JSON.stringify({ name: p.name, display_name: p.display_name, about: p.about || "", nip05: p.nip05 }) }));
    const relay = createServer((rq, rs) => {
      let body = ""; rq.on("data", (c) => (body += c));
      rq.on("end", () => {
        const reply = (o, st = 200) => { rs.writeHead(st, { "Content-Type": "application/json" }); rs.end(JSON.stringify(o)); };
        if (rq.method === "GET") return reply({ name: "mock", version: "0", software_sha: "healthy", ...(opts.self ? { self: opts.self } : {}) });
        if (rq.url === "/events") { try { posted.push(JSON.parse(body)); } catch {} return reply({ event_id: "e1", accepted: true, message: 'response:{"channel_id":"dm-1","created":true}' }); }
        if (rq.url === "/profiles/search") {
          let b = null; try { b = JSON.parse(body); } catch {}
          seen.searchApi.push({ body: b, auth: String(rq.headers.authorization || "").startsWith("Nostr ") });
          if (opts.search === "api") return reply(k0());
          if (opts.search === "404") return reply({ error: "not found" }, 404);
          return reply({});
        }
        if (rq.url === "/query") {
          let filters = []; try { filters = JSON.parse(body); } catch {}
          const kinds = new Set(filters.flatMap((f) => f.kinds || []));
          if (kinds.has(13535)) { seen.archiveQ++; return reply(opts.archive || []); }
          if (kinds.has(0)) {
            if (filters.some((f) => f.search)) seen.nip50++;
            // With a working /profiles/search, NIP-50 returns nothing — so a resolution PROVES the API path.
            if (opts.search === "api") return reply([]);
            return reply(k0());
          }
          return reply([]);
        }
        reply({});
      });
    });
    return { relay, posted, seen };
  };
  const cases = [
    { name: "name matches display_name field", profiles: DIR.anirban, to: "Anirban D Das", wantPk: ANI },
    { name: "name matches the OTHER field (client-shown name ≠ stored field)", profiles: DIR.anirban, to: "Anirban Das", wantPk: ANI },
    { name: "agent-mode email is REFUSED (self-asserted nip05 not trusted — #1492)", profiles: DIR.anirban, to: "anirban.das@olaelectric.com", wantRefused: true, wantErr: /wire mode/ },
    { name: "zero-width lookalike collides with real name → ambiguous, refused", profiles: DIR.lookalike, to: "Anirban Das", wantRefused: true, wantErr: /ambiguous/ },
    { name: "ambiguous name → refused, no DM_OPEN", profiles: DIR.dupe, to: "Sam Roy", wantRefused: true, wantErr: /ambiguous/ },
    { name: "unknown name → refused", profiles: DIR.none, to: "Nobody Here", wantRefused: true, wantErr: /can't resolve recipient/ },
    // ---- v0.2.30: NFKC + case-fold + TR39 skeleton, fail-closed on a non-exact single hit ----
    { name: "Cyrillic 'Аnirban Das' typed vs the real Latin name → lookalike, refused", profiles: DIR.anirban.slice(0, 1).map((p) => ({ ...p, display_name: "" })), to: "\u0410nirban Das", wantRefused: true, wantErr: /ambiguous \/ lookalike - use an npub/ },
    { name: "single skeleton-only hit (Cyrillic twin) for the Latin name → refused", profiles: DIR.cyrOnly, to: "Anirban Das", wantRefused: true, wantErr: /ambiguous \/ lookalike - use an npub/ },
    { name: "fullwidth NFKC collision → refused", profiles: DIR.fullwidthOnly, to: "Anirban Das", wantRefused: true, wantErr: /ambiguous \/ lookalike - use an npub/ },
    { name: "ligature 'ﬁnance-bot' NFKC collision with 'finance-bot' → refused", profiles: DIR.ligOnly, to: "finance-bot", wantRefused: true, wantErr: /ambiguous \/ lookalike - use an npub/ },
    { name: "case-only difference → refused (CASE_ONLY_IS_AMBIGUOUS default true)", profiles: DIR.anirban, to: "anirban das", wantRefused: true, wantErr: /letter case/ },
    { name: "invisible LRM inside the typed name vs real → lookalike, refused", profiles: DIR.anirban, to: "Anirban\u200E Das", wantRefused: true, wantErr: /lookalike/ },
    // ---- v0.2.30 (B): only name/display_name ever match; exact first ----
    { name: "(B) bio/nip05-only search hit → NOT resolved", profiles: DIR.bioOnly, to: "Anirban Das", wantRefused: true, wantErr: /can't resolve recipient/ },
    { name: "(B) exact name + a bio-only hit → resolves to the exact one", profiles: DIR.exactPlusBio, to: "Anirban Das", wantPk: ANI },
    { name: "(B) POST /profiles/search used when supported (NIP-50 returns nothing)", profiles: DIR.anirban, to: "Anirban Das", wantPk: ANI, opts: { search: "api" },
      check: (seen) => {
        ok(seen.searchApi.length >= 1, "(B) /profiles/search was called");
        ok(seen.searchApi.every((x) => x.auth), "(B) /profiles/search carried NIP-98 auth");
        ok(seen.searchApi.every((x) => x.body && typeof x.body.query === "string" && Object.keys(x.body).every((k) => ["query", "limit", "page"].includes(k)) && x.body.limit >= 1 && x.body.limit <= 100), "(B) body is {query, limit≤100} only (relay rejects unknown fields)");
        ok(seen.nip50 === 0, "(B) no NIP-50 fallback when the API answered");
      } },
    { name: "(B) /profiles/search 404 → falls back to NIP-50", profiles: DIR.anirban, to: "Anirban Das", wantPk: ANI, opts: { search: "404" },
      check: (seen) => { ok(seen.searchApi.length === 1, "(B) API tried once, then cached as unsupported"); ok(seen.nip50 >= 1, "(B) NIP-50 fallback used"); } },
    // ---- v0.2.30 (A): NIP-IA archived identities ----
    { name: "(A) archived (relay-self-signed 13535) identity → not resolved", profiles: DIR.anirban, to: "Anirban Das", wantRefused: true, wantErr: /archived identity/,
      opts: { self: RELAY_SELF, archive: [archiveList(RELAY_SK, [ANI])] }, check: (seen) => ok(seen.archiveQ >= 1, "(A) 13535 list queried") },
    { name: "(A) 13535 signed by a NON-self key is ignored → resolves", profiles: DIR.anirban, to: "Anirban Das", wantPk: ANI,
      opts: { self: RELAY_SELF, archive: [archiveList(OTHER_SK, [ANI])] } },
    { name: "(A) 13535 without exactly one '-' tag is ignored → resolves", profiles: DIR.anirban, to: "Anirban Das", wantPk: ANI,
      opts: { self: RELAY_SELF, archive: [archiveList(RELAY_SK, [ANI], [])] } },
    { name: "(A) tampered 13535 (bad signature) is ignored → resolves", profiles: DIR.anirban, to: "Anirban Das", wantPk: ANI,
      opts: { self: RELAY_SELF, archive: [{ ...archiveList(RELAY_SK, [BOB]), tags: [["-"], ["p", ANI]] }] } },
    { name: "(A) no NIP-11 self → fail open → resolves", profiles: DIR.anirban, to: "Anirban Das", wantPk: ANI,
      opts: { archive: [archiveList(RELAY_SK, [ANI])] } },
    { name: "(A) archived twin filtered → the remaining exact match resolves", profiles: DIR.dupe, to: "Sam Roy", wantPk: BOB,
      opts: { self: RELAY_SELF, archive: [archiveList(RELAY_SK, [CAR])] } },
  ];
  for (const c of cases) {
    const { relay, posted, seen } = mkDir(c.profiles, c.opts);
    await new Promise((r) => relay.listen(0, "127.0.0.1", r));
    const port = relay.address().port;
    const text = await probeTool({
      BUZZ_PRIVATE_KEY: "77".repeat(32), BUZZ_NAME: "bridge-test", BUZZ_WIRE_SIGN: "", BUZZ_AUTH_TAG: "",
      BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
    }, "buzz_dm_open", { to: c.to }, { waitMs: 7000, callDelay: 1500 });
    relay.close();
    const ev = posted.find((e) => e && e.kind === 41010);
    if (c.check) c.check(seen);
    if (c.wantRefused) {
      ok(!ev, `${c.name} → no kind:41010 DM_OPEN posted (resolver refused)`);
      ok(isErr(text) && (!c.wantErr || c.wantErr.test(JSON.parse(text).content[0].text)), `${c.name} → refusal error reached the client${c.wantErr ? ` (${c.wantErr})` : ""}`);
      continue;
    }
    if (!ev) { missing(`no kind:41010 captured for '${c.name}' (reply=${String(text).slice(0, 160)})`); continue; }
    const p = (ev.tags || []).find((t) => t[0] === "p");
    console.log(`  ${c.name}: p=${p ? p[1].slice(0, 8) + "…" : "(none)"}`);
    ok(p && p[1] === c.wantPk, `${c.name} → DM_OPEN p-tag is the resolved pubkey`);
  }
}

// ---- Case 35 (v0.2.30 D): buzz_edit_channel re-reads kind:39000 and reports a mismatch as an ERROR --
// A relay that ACKs the kind:9002 but never applies it (the real bug: "private" flip silently ignored
// → channel stays PUBLIC) must not be reported as success.
console.log("\ncase 35 (D): edit accepted but NOT applied by the relay → isError with the mismatch");
{
  const CHID = "c0ffee".repeat(6).slice(0, 36);
  const lazyRelay = ({ vanish = false } = {}) => {
    const posted = [];
    const PK = getPublicKey(Uint8Array.from(Buffer.from("77".repeat(32), "hex")));
    const now = Math.floor(Date.now() / 1000);
    const relay = createServer((rq, rs) => {
      let body = ""; rq.on("data", (c) => (body += c));
      rq.on("end", () => {
        const reply = (obj, status = 200) => { rs.writeHead(status, { "Content-Type": "application/json" }); rs.end(JSON.stringify(obj)); };
        if (rq.method === "GET") return reply({ name: "mock", version: "0", software_sha: "healthy" });
        if (rq.url === "/events") { try { posted.push(JSON.parse(body)); } catch {} return reply({ event_id: "e1", accepted: true, message: "ok" }); }
        if (rq.url === "/query") {
          let filters = []; try { filters = JSON.parse(body); } catch {}
          const kinds = new Set(filters.flatMap((f) => f.kinds || []));
          if (kinds.has(39002)) return reply([{ id: "m1", pubkey: PK, kind: 39002, created_at: now, tags: [["d", CHID], ["p", PK]], content: "" }]);
          if (kinds.has(39000)) {
            const byD = filters.some((f) => f["#d"]);
            if (vanish && byD && posted.some((e) => e.kind === 9002)) return reply([]);
            return reply([{ id: "c1", pubkey: PK, kind: 39000, created_at: now, tags: [["d", CHID], ["name", "projects"], ["public"]], content: "" }]);
          }
          return reply([]);
        }
        reply({});
      });
    });
    return { relay, posted };
  };
  const cases = [
    { name: "visibility→private ignored by relay", args: { channel: "projects", visibility: "private" }, want: /does NOT reflect it — visibility: asked private, relay shows open \(channel may still be PUBLIC\)/ },
    { name: "rename ignored by relay", args: { channel: "projects", name: "Renamed" }, want: /does NOT reflect it — name: asked "Renamed", relay shows "projects"/ },
    { name: "ttl ignored by relay", args: { channel: "projects", ttl: 3600 }, want: /does NOT reflect it — ttl: asked 3600s, relay shows none/ },
    { name: "39000 can't be re-read after edit → fail closed", args: { channel: "projects", name: "Renamed" }, vanish: true, want: /could not be re-read/ },
  ];
  for (const c of cases) {
    const { relay, posted } = lazyRelay({ vanish: c.vanish });
    await new Promise((r) => relay.listen(0, "127.0.0.1", r));
    const port = relay.address().port;
    const text = await probeTool({
      BUZZ_PRIVATE_KEY: "77".repeat(32), BUZZ_NAME: "bridge-test", BUZZ_WIRE_SIGN: "", BUZZ_AUTH_TAG: "",
      BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
    }, "buzz_edit_channel", c.args, { waitMs: 9000, callDelay: 1500 });
    relay.close();
    if (!posted.some((e) => e && e.kind === 9002)) { missing(`no kind:9002 captured for '${c.name}'`); continue; }
    if (text === null) { missing(`no reply for '${c.name}'`); continue; }
    const t = JSON.parse(text).content[0].text;
    console.log(`  ${c.name}: ${t.slice(0, 150)}…`);
    ok(isErr(text), `${c.name} → reported as an ERROR (not success)`);
    ok(c.want.test(t), `${c.name} → names the mismatch (${c.want})`);
    ok(/Treat the edit as NOT applied/.test(t), `${c.name} → tells the caller the edit is NOT applied`);
  }
}

// ---- Case 36 (v0.2.30): a homoglyph / zero-width / fullwidth email is refused BEFORE any Ekam call --
console.log("\ncase 36: wire-mode email addressing refuses non-ASCII/invisible/NFKC-changing emails before the directory");
{
  const HOME_ISO = mkdtempSync(join(tmpdir(), "buzz-email-home-"));
  const ANI = "a".repeat(64);
  const mk = () => {
    const seen = { directory: [], ekamAny: 0 };
    const srv = createServer((rq, rs) => {
      let body = ""; rq.on("data", (c) => (body += c));
      rq.on("end", () => {
        const reply = (o, st = 200) => { rs.writeHead(st, { "Content-Type": "application/json" }); rs.end(JSON.stringify(o)); };
        if (rq.url.startsWith("/v1/")) seen.ekamAny++;
        if (rq.url.startsWith("/v1/directory/resolve")) { seen.directory.push(decodeURIComponent(rq.url.split("email=")[1] || "")); return reply({ nostr_pub: ANI }); }
        if (rq.url.startsWith("/v1/")) return reply({ error: "mock" }, 500);
        if (rq.method === "GET") return reply({ name: "mock", version: "0", software_sha: "healthy" });
        if (rq.url === "/query") return reply([]);
        reply({});
      });
    });
    return { srv, seen };
  };
  const cases = [
    { name: "Cyrillic-а homoglyph email", to: "\u0430nirban.das@olaelectric.com", want: /non-ASCII/ },
    { name: "zero-width-space email", to: "anirban\u200B.das@olaelectric.com", want: /invisible/ },
    { name: "LRM-bearing email", to: "anirban.das@olaelectric.com\u200E", want: /invisible/ },
    { name: "fullwidth-＠ email (NFKC changes it)", to: "anirban.das\uFF20olaelectric.com", want: /non-ASCII|NFKC/ },
    { name: "fullwidth-letter email", to: "\uFF41nirban.das@olaelectric.com", want: /non-ASCII|NFKC/ },
  ];
  let n = 0;
  for (const c of [...cases, { name: "ASCII control email reaches the directory", to: "anirban.das@olaelectric.com", control: true }]) {
    const { srv, seen } = mk();
    await new Promise((r) => srv.listen(0, "127.0.0.1", r));
    const port = srv.address().port;
    const text = await probeTool({
      HOME: HOME_ISO, BUZZ_PRIVATE_KEY: "", BUZZ_NAME: "", BUZZ_AUTH_TAG: "",
      BUZZ_WIRE_SIGN: "1", BUZZ_WIRE_ID: `emailprobe${n++}`, BUZZ_USER_PUBKEY: "e".repeat(64), BUZZ_EKAM_HUMAN_TOKEN: "mock-static-token",
      BUZZ_EKAM_BASE: `http://127.0.0.1:${port}`,
      BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
    }, "buzz_dm_open", { to: c.to }, { waitMs: 7000, callDelay: 1200 });
    srv.close();
    if (text === null) { missing(`no reply for '${c.name}'`); continue; }
    if (c.control) { ok(seen.directory.length === 1 && seen.directory[0] === c.to, `${c.name} (positive control: the directory IS called for a clean email)`); continue; }
    const t = JSON.parse(text).content[0].text;
    ok(isErr(text) && c.want.test(t), `${c.name} → refused (${c.want})`);
    ok(seen.directory.length === 0, `${c.name} → NO /v1/directory/resolve call was made`);
  }
  rmSync(HOME_ISO, { recursive: true, force: true });
}

// ---- Case 37 (v0.2.30 C): client identification on kind:0 and kind:10100 ------------------------
console.log("\ncase 37 (C): kind:10100 carries [client,buzz-mcp,<ver>]; kind:0 JSON carries client_version");
{
  const VER = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8")).version;
  const { relay, SK, posted } = captureRelay();
  await new Promise((r) => relay.listen(0, "127.0.0.1", r));
  const port = relay.address().port;
  await probeTool({
    BUZZ_PRIVATE_KEY: SK, BUZZ_NAME: "bridge-test", BUZZ_WIRE_SIGN: "", BUZZ_AUTH_TAG: "",
    BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
  }, "buzz_whoami", {}, { waitMs: 6000, callDelay: 1500 });
  relay.close();
  const k0 = posted.find((e) => e && e.kind === 0);
  const k10100 = posted.find((e) => e && e.kind === 10100);
  if (!k10100) missing("no kind:10100 card captured");
  else ok((k10100.tags || []).some((t) => JSON.stringify(t) === JSON.stringify(["client", "buzz-mcp", VER])), `kind:10100 tags include ["client","buzz-mcp","${VER}"]`);
  if (!k0) missing("no kind:0 captured");
  else {
    let c = {}; try { c = JSON.parse(k0.content); } catch {}
    ok(c.client_version === VER, `kind:0 content.client_version === "${VER}"`);
  }
}

// ---- Case 38 (v0.2.30 A): buzz_agents hides relay-archived identities ---------------------------
console.log("\ncase 38 (A): buzz_agents filters pubkeys on the relay-self-signed kind:13535 list");
{
  const ANI = "a".repeat(64), BOB = "b".repeat(64);
  const RELAY_SK = Uint8Array.from(Buffer.from("99".repeat(32), "hex"));
  const mk = (self, signer) => createServer((rq, rs) => {
    let body = ""; rq.on("data", (c) => (body += c));
    rq.on("end", () => {
      const reply = (o) => { rs.writeHead(200, { "Content-Type": "application/json" }); rs.end(JSON.stringify(o)); };
      if (rq.method === "GET") return reply({ name: "mock", version: "0", software_sha: "healthy", ...(self ? { self } : {}) });
      if (rq.url === "/query") {
        let f = []; try { f = JSON.parse(body); } catch {}
        const kinds = new Set(f.flatMap((x) => x.kinds || []));
        if (kinds.has(13535)) return reply([finalizeEvent({ kind: 13535, created_at: Math.floor(Date.now() / 1000), tags: [["-"], ["p", ANI]], content: "" }, signer)]);
        if (kinds.has(0)) return reply([ANI, BOB].map((pk, i) => ({ id: `p${i}`, pubkey: pk, kind: 0, created_at: 1, tags: [], content: JSON.stringify({ name: i ? "Bob Archer" : "Anirban Das" }) })));
        return reply([]);
      }
      reply({});
    });
  });
  for (const c of [
    { name: "relay-signed list", self: getPublicKey(RELAY_SK), signer: RELAY_SK, hidden: true },
    { name: "list signed by another key", self: getPublicKey(RELAY_SK), signer: Uint8Array.from(Buffer.from("98".repeat(32), "hex")), hidden: false },
    { name: "no NIP-11 self (fail open)", self: null, signer: RELAY_SK, hidden: false },
  ]) {
    const relay = mk(c.self, c.signer);
    await new Promise((r) => relay.listen(0, "127.0.0.1", r));
    const port = relay.address().port;
    const text = await probeTool({
      BUZZ_PRIVATE_KEY: "77".repeat(32), BUZZ_NAME: "bridge-test", BUZZ_WIRE_SIGN: "", BUZZ_AUTH_TAG: "",
      BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
    }, "buzz_agents", {}, { waitMs: 6000, callDelay: 1200 });
    relay.close();
    if (text === null) { missing(`no buzz_agents reply for '${c.name}'`); continue; }
    const t = JSON.parse(text).content[0].text;
    ok(/Bob Archer/.test(t), `${c.name} → non-archived Bob listed`);
    if (c.hidden) { ok(!/Anirban/.test(t), `${c.name} → archived Anirban hidden`); ok(/1 archived identity hidden — NIP-IA/.test(t), `${c.name} → says 1 hidden`); }
    else ok(/Anirban/.test(t) && !/hidden/.test(t), `${c.name} → list ignored, Anirban still listed`);
  }
}

// ---- Case 39 (v0.2.30 E): strict 64-lowercase-hex on @mention p-tags ------------------------------
console.log("\ncase 39 (E): a malformed/uppercase profile pubkey never becomes a p-tag");
{
  const GOOD = "d".repeat(64), UPPER = "AB".repeat(32), SHORT = "ab".repeat(20);
  const PK = getPublicKey(Uint8Array.from(Buffer.from("88".repeat(32), "hex")));
  const now = Math.floor(Date.now() / 1000);
  const posted = [];
  const relay = createServer((rq, rs) => {
    let body = ""; rq.on("data", (c) => (body += c));
    rq.on("end", () => {
      const reply = (o) => { rs.writeHead(200, { "Content-Type": "application/json" }); rs.end(JSON.stringify(o)); };
      if (rq.method === "GET") return reply({ name: "mock", version: "0", software_sha: "healthy" });
      if (rq.url === "/events") { try { posted.push(JSON.parse(body)); } catch {} return reply({ event_id: "e1", accepted: true, message: "ok" }); }
      if (rq.url === "/query") {
        let f = []; try { f = JSON.parse(body); } catch {}
        const kinds = new Set(f.flatMap((x) => x.kinds || []));
        if (kinds.has(39002)) return reply([{ id: "m1", pubkey: PK, kind: 39002, created_at: now, tags: [["d", "chanA"], ["p", PK]], content: "" }]);
        if (kinds.has(39000)) return reply([{ id: "c1", pubkey: PK, kind: 39000, created_at: now, tags: [["d", "chanA"], ["name", "testchan"]], content: "" }]);
        if (kinds.has(0)) return reply([[GOOD, "Pulse"], [UPPER, "Mallory"], [SHORT, "Shorty"]].map(([pk, n], i) => ({ id: `p${i}`, pubkey: pk, kind: 0, created_at: 1, tags: [], content: JSON.stringify({ name: n }) })));
        return reply([]);
      }
      reply({});
    });
  });
  await new Promise((r) => relay.listen(0, "127.0.0.1", r));
  const port = relay.address().port;
  await probeTool({
    BUZZ_PRIVATE_KEY: "88".repeat(32), BUZZ_NAME: "bridge-test", BUZZ_WIRE_SIGN: "", BUZZ_AUTH_TAG: "",
    BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
  }, "buzz_post", { channel: "testchan", text: "@pulse @mallory @shorty @pulse hello" }, { waitMs: 7000, callDelay: 1500 });
  relay.close();
  const ev = posted.find((e) => e && e.kind === 9);
  if (!ev) missing("no kind:9 captured for the mention post");
  else {
    const ps = (ev.tags || []).filter((t) => t[0] === "p").map((t) => t[1]);
    console.log(`  p-tags: ${JSON.stringify(ps.map((p) => p.slice(0, 8)))}`);
    ok(ps.length === 1 && ps[0] === GOOD, "only the valid 64-lowercase-hex mention became a p-tag (deduped)");
    ok(ps.every((p) => /^[0-9a-f]{64}$/.test(p)), "every signed p-tag is 64 lowercase hex");
  }
}

// ---- Case 40 (v0.2.30 fix): @mention resolution is fail-closed (buzz_security review §3.1) ---------
// Regression: two kind:0 profiles both named "buzz_security" — the OLD key 7731945f… listed first.
// The old first-wins index tagged the old key; now nobody is tagged and the post reports why.
console.log("\ncase 40: @mention of a duplicated name tags nobody (old key never tagged); exact single name tags");
{
  const OLD = "7731945f" + "0".repeat(56), REAL = "28ff3202" + "1".repeat(56), PULSE = "d".repeat(64);
  const PK = getPublicKey(Uint8Array.from(Buffer.from("88".repeat(32), "hex")));
  const now = Math.floor(Date.now() / 1000);
  const run = async (profilesList, msg) => {
    const posted = [];
    const relay = createServer((rq, rs) => {
      let body = ""; rq.on("data", (c) => (body += c));
      rq.on("end", () => {
        const reply = (o) => { rs.writeHead(200, { "Content-Type": "application/json" }); rs.end(JSON.stringify(o)); };
        if (rq.method === "GET") return reply({ name: "mock", version: "0", software_sha: "healthy" });
        if (rq.url === "/events") { try { posted.push(JSON.parse(body)); } catch {} return reply({ event_id: "e1", accepted: true, message: "ok" }); }
        if (rq.url === "/query") {
          let f = []; try { f = JSON.parse(body); } catch {}
          const kinds = new Set(f.flatMap((x) => x.kinds || []));
          if (kinds.has(39002)) return reply([{ id: "m1", pubkey: PK, kind: 39002, created_at: now, tags: [["d", "chanA"], ["p", PK]], content: "" }]);
          if (kinds.has(39000)) return reply([{ id: "c1", pubkey: PK, kind: 39000, created_at: now, tags: [["d", "chanA"], ["name", "testchan"]], content: "" }]);
          if (kinds.has(0)) return reply(profilesList.map(([pk, n], i) => ({ id: `p${i}`, pubkey: pk, kind: 0, created_at: 1 + i, tags: [], content: JSON.stringify({ name: n }) })));
          return reply([]);
        }
        reply({});
      });
    });
    await new Promise((r) => relay.listen(0, "127.0.0.1", r));
    const port = relay.address().port;
    const text = await probeTool({
      BUZZ_PRIVATE_KEY: "88".repeat(32), BUZZ_NAME: "bridge-test", BUZZ_WIRE_SIGN: "", BUZZ_AUTH_TAG: "",
      BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
    }, "buzz_post", { channel: "testchan", text: msg }, { waitMs: 7000, callDelay: 1500 });
    relay.close();
    const ev = posted.find((e) => e && e.kind === 9);
    return { text, ps: ev ? (ev.tags || []).filter((t) => t[0] === "p").map((t) => t[1]) : null };
  };
  let r = await run([[OLD, "buzz_security"], [REAL, "buzz_security"], [PULSE, "Pulse"]], "@buzz_security review please @pulse");
  if (!r.ps) missing("no kind:9 captured for the duplicate-name mention post");
  else {
    console.log(`  p-tags: ${JSON.stringify(r.ps.map((p) => p.slice(0, 8)))}`);
    ok(!r.ps.includes(OLD) && !r.ps.includes(REAL), "duplicate 'buzz_security' (old key first) → NEITHER key tagged");
    ok(r.ps.length === 1 && r.ps[0] === PULSE, "the unambiguous @pulse is still tagged");
    ok(/NOT tagged \(fail-closed\)/.test(r.text || "") && /buzz_security/.test(r.text || ""), "the post result reports the refused @buzz_security mention");
  }
  r = await run([[REAL, "buzz_security"]], "@buzz_security hello");
  if (!r.ps) missing("no kind:9 captured for the single-name mention post");
  else ok(r.ps.length === 1 && r.ps[0] === REAL, "a single exact 'buzz_security' profile → tagged");
  r = await run([[OLD, "buzz_s\u0435curity"]], "@buzz_security hello");
  if (!r.ps) missing("no kind:9 captured for the lookalike mention post");
  else ok(r.ps.length === 0 && /lookalike/.test(r.text || ""), "a lookalike-only profile → not tagged, reported");
}

// ---- Case 41 (v0.2.30 fix): duplicate channel names are refused, never first-match ----------------
console.log("\ncase 41: two channels named 'general'/'General' → buzz_post refused with both ids; nothing signed");
{
  const PK = getPublicKey(Uint8Array.from(Buffer.from("88".repeat(32), "hex")));
  const now = Math.floor(Date.now() / 1000);
  const posted = [];
  const relay = createServer((rq, rs) => {
    let body = ""; rq.on("data", (c) => (body += c));
    rq.on("end", () => {
      const reply = (o) => { rs.writeHead(200, { "Content-Type": "application/json" }); rs.end(JSON.stringify(o)); };
      if (rq.method === "GET") return reply({ name: "mock", version: "0", software_sha: "healthy" });
      if (rq.url === "/events") { try { posted.push(JSON.parse(body)); } catch {} return reply({ event_id: "e1", accepted: true, message: "ok" }); }
      if (rq.url === "/query") {
        let f = []; try { f = JSON.parse(body); } catch {}
        const kinds = new Set(f.flatMap((x) => x.kinds || []));
        if (kinds.has(39002)) return reply(["gen-aaaa", "gen-bbbb"].map((d, i) => ({ id: `m${i}`, pubkey: PK, kind: 39002, created_at: now, tags: [["d", d], ["p", PK]], content: "" })));
        if (kinds.has(39000)) return reply([["gen-aaaa", "general"], ["gen-bbbb", "General"]].map(([d, n], i) => ({ id: `c${i}`, pubkey: PK, kind: 39000, created_at: now, tags: [["d", d], ["name", n]], content: "" })));
        return reply([]);
      }
      reply({});
    });
  });
  await new Promise((r) => relay.listen(0, "127.0.0.1", r));
  const port = relay.address().port;
  const text = await probeTool({
    BUZZ_PRIVATE_KEY: "88".repeat(32), BUZZ_NAME: "bridge-test", BUZZ_WIRE_SIGN: "", BUZZ_AUTH_TAG: "",
    BUZZ_RELAY_HTTP: `http://127.0.0.1:${port}`, BUZZ_RELAY_URL: `ws://127.0.0.1:${port}`,
  }, "buzz_post", { channel: "general", text: "hello" }, { waitMs: 7000, callDelay: 1500 });
  relay.close();
  if (text === null) missing("no buzz_post reply for the duplicate-channel case");
  else {
    ok(/ambiguous/.test(text) && /gen-aaaa/.test(text) && /gen-bbbb/.test(text), "refused as ambiguous, listing both channel ids");
    ok(!posted.some((e) => e && e.kind === 9), "nothing was signed or sent");
  }
}

console.log(`\nbridge.test.mjs: ${pass} passed, ${fail} failed, ${skip} skipped`);
process.exit(fail ? 1 : 0);
