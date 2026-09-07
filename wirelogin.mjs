#!/usr/bin/env node
// wirelogin.mjs — one-time "post as me" consent (loadkey_v2 Phase-2 login helper).
//
// Runs the browser authcode+PKCE flow ONCE to obtain the rotating wire:sign refresh
// token; the shim then runs autonomously off it (signer.mjs makeWireTokenProvider).
// This is Navendu's step ③ (ekam 04:53). It is NOT part of the shim's runtime — it's a
// separate one-shot the user runs when connecting (and again at the absolute-cap re-consent).
//
//   BUZZ_EKAM_CLIENT_ID=<from DCR>  node wirelogin.mjs
//
// PKCE (S256) is generated locally; the refresh is persisted 0600 under the SAME id the
// runtime reads (wirePersistId), so the shim finds it with no further config.

import http from "node:http";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { ekamBase, wireRefreshSet, wirePersistId, wirePubkeySet, wireBleedVars, wireSign } from "./signer.mjs";

const b64url = (buf) => Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

export function pkce() {
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

export function authorizeUrl(base, { clientId, redirectUri, challenge, state, resource }) {
  const p = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: "openid wire:sign offline_access",
    resource,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state,
  });
  return `${base}/authorize?${p.toString()}`;
}

// Exchange the authorization code for tokens. Isolated + testable. Fails LOUD if the
// response carries no refresh_token (the usual cause: the client wasn't granted
// offline_access + refresh_token in step ② — so the shim could never go autonomous).
export async function exchangeAuthCode(base, { code, verifier, clientId, redirectUri }, fetchFn = fetch) {
  const res = await fetchFn(`${base}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId, redirect_uri: redirectUri }),
  });
  const text = await res.text();
  if (!res.ok) {
    let d = text.slice(0, 200);
    try { const j = JSON.parse(text); d = j.error_description || j.error || d; } catch { /* keep raw */ }
    throw new Error(`authcode exchange -> HTTP ${res.status}: ${d}`);
  }
  let j;
  try { j = JSON.parse(text); } catch { throw new Error(`authcode exchange returned non-JSON: ${text.slice(0, 120)}`); }
  if (!j.refresh_token)
    throw new Error("authcode exchange returned no refresh_token — did step ② grant offline_access + refresh_token to this client?");
  return j; // {access_token, refresh_token, expires_in, ...}
}

// Bind the first free loopback port from the candidate list (matches the ports the
// client's redirect_uris were registered with — exact-match, no patch endpoint).
export async function bindLoopback(ports) {
  for (const port of ports) {
    const srv = http.createServer();
    const bound = await new Promise((resolve) => {
      srv.once("error", () => resolve(false));
      srv.listen(port, "127.0.0.1", () => resolve(true));
    });
    if (bound) return { srv, port };
    try { srv.close(); } catch { /* try next */ }
  }
  throw new Error(`no free loopback port among ${ports.join(", ")} — free one or set BUZZ_WIRE_LOGIN_PORTS`);
}

// CLI entry (skipped when imported by tests).
if (import.meta.url === `file://${process.argv[1]}`) {
  const env = process.env;
  const clientId = (env.BUZZ_EKAM_CLIENT_ID || "").trim();
  if (!clientId) { console.error("[wire-login] set BUZZ_EKAM_CLIENT_ID (from the DCR registration)"); process.exit(1); }
  const base = ekamBase(env);
  const ports = (env.BUZZ_WIRE_LOGIN_PORTS || "8765,8766,8770").split(",").map((s) => parseInt(s.trim(), 10)).filter(Boolean);
  const { verifier, challenge } = pkce();
  const state = b64url(randomBytes(16));
  const { srv, port } = await bindLoopback(ports);
  const redirectUri = `http://127.0.0.1:${port}/callback`;
  const url = authorizeUrl(base, { clientId, redirectUri, challenge, state, resource: base });
  console.error(`\n[wire-login] open this URL in your browser to grant "post as me":\n\n${url}\n\n[wire-login] waiting for the redirect on ${redirectUri} …`);
  // pilot #2: best-effort auto-open the browser (fall back to the printed URL if it fails).
  try {
    const [cmd, ...pre] = process.platform === "darwin" ? ["open"]
      : process.platform === "win32" ? ["cmd", "/c", "start", ""]
      : ["xdg-open"];
    spawn(cmd, [...pre, url], { stdio: "ignore", detached: true }).unref();
    console.error("[wire-login] (tried to open your browser — if nothing opened, paste the URL above)");
  } catch { /* printing the URL above is the fallback */ }
  srv.on("request", async (req, res) => {
    try {
      const u = new URL(req.url, redirectUri);
      if (u.pathname !== "/callback") { res.writeHead(404); res.end("not found"); return; }
      const err = u.searchParams.get("error");
      if (err) throw new Error(`authorize error: ${err} ${u.searchParams.get("error_description") || ""}`);
      if (u.searchParams.get("state") !== state) throw new Error("state mismatch (possible CSRF) — aborting");
      const code = u.searchParams.get("code");
      if (!code) throw new Error("no authorization code in callback");
      const tok = await exchangeAuthCode(base, { code, verifier, clientId, redirectUri });
      wireRefreshSet(wirePersistId(env), tok.refresh_token);
      // Capture the user's pubkey (one wire-sign with the fresh access token) so the
      // shim needs no hand-set BUZZ_USER_PUBKEY — non-dev users never touch a key.
      try {
        const probe = await wireSign(base, tok.access_token, { kind: 27235, tags: [["u", `${base}/whoami`], ["method", "GET"], ["payload", ""]], content: "" });
        if (probe?.pubkey) wirePubkeySet(wirePersistId(env), probe.pubkey);
      } catch (e) { console.error(`[wire-login] (pubkey auto-capture skipped: ${e.message} — set BUZZ_USER_PUBKEY if needed)`); }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(`<!doctype html><meta charset="utf-8"><body style="font:15px/1.5 system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;color:#1a1a1a">
<h2 style="margin:0 0 .5rem">✅ Buzz is now connected as you</h2>
<p>Sign-in complete. The Buzz tool can now post and DM under your identity through Ekam's revocable signer — your key was never shared with it.</p>
<p style="color:#666">You can safely close this tab.</p></body>`);
      const pid = wirePersistId(env);
      console.error(`[wire-login] success — wire:sign refresh persisted 0600 (id=${pid}). The shim is now autonomous. access expires_in=${tok.expires_in || "?"}s`);
      // The runtime resolves the SAME id (BUZZ_WIRE_ID default "wire") independent of
      // BUZZ_NAME, so no matching config is needed. But warn if the caller set agent-mode
      // identity vars — under the pre-0.2.2 rule those changed the id and silently broke
      // wire mode ("run the login" after a login that worked). They're ignored now; flag
      // it so a copy-pasted agent config doesn't leave someone chasing a phantom.
      const bleed = wireBleedVars(env);
      if (bleed.length)
        console.error(`[wire-login] note: ${bleed.join(", ")} is set but IGNORED for wire mode (it keys off BUZZ_WIRE_ID, default "wire"). Do NOT set BUZZ_IDENTITY_NAME=<agent> for the human "post as me" shim — that was the old footgun.`);
      setTimeout(() => { try { srv.close(); } catch {} process.exit(0); }, 200);
    } catch (e) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("login failed: " + e.message);
      console.error(`[wire-login] FAILED: ${e.message}`);
      setTimeout(() => { try { srv.close(); } catch {} process.exit(1); }, 200);
    }
  });
}
