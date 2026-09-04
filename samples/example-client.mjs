#!/usr/bin/env node
// example-client.mjs — a minimal MCP-stdio client that drives the buzz-mcp shim
// end to end: whoami -> read a channel -> (optionally) post -> (optionally) DM.
//
// This is a SAMPLE for developers who want to call the tools programmatically.
// Most people never need it — their AI assistant calls the tools directly once
// the MCP config block is in place. This shows what that looks like under the hood.
//
// Run it after you've set up a route (see README):
//   Route A (human):  export BUZZ_WIRE_SIGN=1 BUZZ_EKAM_CLIENT_ID=<id>   # then the one-time login
//   Route B (agent):  export BUZZ_NAME=<name> BUZZ_AUTH_TAG=<json>       # provisioned by `buzz agent add`
//   node example-client.mjs
// Read-only by default; flip DO_POST / DO_DM below to exercise writes.
//
// No secrets live here: the shim reads its 0600 credential itself.

import { spawn } from "node:child_process";

// ---- EDIT THESE ----------------------------------------------------------
const CHANNEL   = "buzz-main";                  // channel to read
const DO_POST   = false;                         // set true to post
const POST_TEXT = "hello from example-client";   // what to post if DO_POST
const DO_DM     = false;                         // set true to send a DM
const DM_TO     = "someone@olacabs.com";         // npub / hex / email / display name
const DM_TEXT   = "hi — sent via the governed MCP";
// --------------------------------------------------------------------------

// Spawn the installed `buzz-mcp` command (on PATH after install.sh) — no file paths
// to get wrong, and it's the exact binary your MCP client launches.
// Inherit the environment you configured for your route; default only the relay host.
const env = { BUZZ_RELAY_HTTP: "https://ola.buzz.ola.in", ...process.env };

const child = spawn("buzz-mcp", [], { env, stdio: ["pipe", "pipe", "inherit"] });
let buf = "";
const pending = new Map();
child.stdout.on("data", (d) => {
  buf += d.toString();
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (!line.trim()) continue;
    let msg; try { msg = JSON.parse(line); } catch { continue; }
    if (msg.id != null && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
  }
});
let nextId = 1;
const call = (method, params) => new Promise((resolve) => {
  const id = nextId++;
  pending.set(id, resolve);
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
});
const notify = (method, params) => child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
const tool = (name, args = {}) => call("tools/call", { name, arguments: args });
const textOf = (r) => (r?.result?.content || []).map((c) => c.text).join("\n") || JSON.stringify(r?.error || {});

(async () => {
  await call("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "example-client", version: "1" } });
  notify("notifications/initialized", {});

  console.log("--- whoami ---\n" + textOf(await tool("buzz_whoami")) + "\n");
  console.log(`--- read #${CHANNEL} ---\n` + textOf(await tool("buzz_read", { channel: CHANNEL, limit: 10 })) + "\n");

  if (DO_POST) console.log("--- post ---\n" + textOf(await tool("buzz_post", { channel: CHANNEL, text: POST_TEXT })) + "\n");
  if (DO_DM)   console.log("--- dm ---\n"   + textOf(await tool("buzz_dm_send", { to: DM_TO, text: DM_TEXT })) + "\n");

  child.kill(); process.exit(0);
})().catch((e) => { console.error("error:", e.message); child.kill(); process.exit(1); });
