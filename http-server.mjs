// http-server.mjs — v0.2.35 hosted mode: `buzz-mcp --http`, the "Ola Buzz" Grok Bot catalog connector.
//
// One Node HTTP server, many people. MCP Streamable HTTP (SDK transport, stateful Mcp-Session-Id).
// Every /mcp request carries an Ekam access token (OAuth 2.1 resource server, MCP auth 2025-06-18):
// validated (JWKS or introspection) for audience = this resource, bound to its session (a session id
// presented with a different person's token is refused). The client token is NEVER sent to the relay
// or to wire-sign: it is only RFC 8693-exchanged at Ekam's token endpoint for a short-lived wire:sign
// token for that same person, cached in memory per user.
//
// Isolation: each session gets its own buzz core (createBuzzServer({hosted:true})) — its own signer
// (bound to the person's pubkey), caches, confirm gate; per-USER write guard + rate limit. Hosted cores
// never read key/auth-tag env, never touch the disk, never open a loopback login.
//
// This module never imports buzz-mcp.mjs (the factory is passed in): buzz-mcp.mjs's entry does a
// top-level-await import of this file, and a cycle would deadlock.
import { createServer } from "node:http";
import { randomUUID, createHash } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { ListToolsRequestSchema, CallToolRequestSchema, isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { hostedConfig, protectedResourceMetadata, resourceMetadataUrl, createAsMetadata, createTokenValidator, createTokenExchanger, createEncryptedTokenStore, AuthError, hashSub } from "./hosted-auth.mjs";
import { makeHostedWireSigner, hostedWireError, probeWirePubkey, isBuzzAppSigninError, BUZZ_APP_SIGNIN_MESSAGE, BUZZ_APP_SIGNIN_RE } from "./signer.mjs";
import { createWriteGuard, writeLimitFromEnv } from "./safety.mjs";

const int = (s, d, lo, hi) => { const n = parseInt(s ?? "", 10); return Number.isFinite(n) ? Math.max(lo, Math.min(n, hi)) : d; };
const list = (s) => String(s || "").split(/[\s,]+/).filter(Boolean);

// Non-secret config the per-session core may see. Never key / auth-tag / client-secret vars.
export const HOSTED_CORE_ENV_ALLOW = ["BUZZ_RELAY_HTTP", "BUZZ_SIGN_BASE", "BUZZ_EKAM_BASE", "BUZZ_TZ", "BUZZ_HTTP_TIMEOUT_S",
  "BUZZ_RELAYINFO_TIMEOUT_S", "BUZZ_TRANSFER_TIMEOUT_S", "BUZZ_HOSTED_ATTACHMENT_MAX_MB", "BUZZ_ONBOARDING_GUIDE"];
export function coreEnv(env) {
  const o = { BUZZ_HARNESS: "ola-buzz-hosted", BUZZ_INTERFACE: "mcp-http", BUZZ_WIRE_SIGN: "1" };
  for (const k of HOSTED_CORE_ENV_ALLOW) if (env[k] != null && env[k] !== "") o[k] = String(env[k]);
  return Object.freeze(o);
}

// Strip anything token-shaped from text before it is logged or returned.
// Exact-value scrub of this session's live tokens (client bearer + exchanged wire:sign) — catches opaque
// tokens a regex can't recognise, e.g. echoed back in an upstream error body — then the pattern redact.
export function scrub(text, ...secrets) {
  let t = String(text ?? "");
  for (const v of secrets) if (typeof v === "string" && v.length >= 8) t = t.split(v).join("[redacted]");
  return redact(t);
}
function scrubResult(r, ...secrets) {
  if (!r || !Array.isArray(r.content)) return r;
  return { ...r, content: r.content.map((c) => (c && c.type === "text" && typeof c.text === "string" ? { ...c, text: scrub(c.text, ...secrets) } : c)) };
}

export function redact(s) {
  return String(s ?? "")
    .replace(/Bearer\s+[A-Za-z0-9._~+\/=-]+/gi, "Bearer [redacted]")
    .replace(/\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g, "[jwt]")
    .replace(/\bnsec1[02-9ac-hj-np-z]{20,}/gi, "[nsec]")
    .replace(/("?(?:access_token|subject_token|refresh_token|id_token|client_secret|token)"?\s*[:=]\s*"?)[^"\s,&}]+/gi, "$1[redacted]");
}

function bucket(perMin, now) {
  const m = new Map();
  return (key) => {
    const t = now(); let b = m.get(key);
    if (!b) { b = { tokens: perMin, at: t }; m.set(key, b); if (m.size > 50_000) m.delete(m.keys().next().value); }
    b.tokens = Math.min(perMin, b.tokens + ((t - b.at) / 60_000) * perMin); b.at = t;
    if (b.tokens < 1) return Math.ceil(((1 - b.tokens) / perMin) * 60);
    b.tokens -= 1; return 0;
  };
}

export async function startHttpServer({ createBuzzServer, version = "?", env = process.env, fetch: fetchFn = fetch, now = Date.now,
  listen = true, port, host, log: logSink } = {}) {
  if (typeof createBuzzServer !== "function") throw new Error("startHttpServer needs the createBuzzServer factory");
  const cfg = hostedConfig(env);
  const O = {
    maxBody: int(env.BUZZ_HOSTED_MAX_BODY_KB, 1024, 1, 16384) * 1024,
    perMin: int(env.BUZZ_HOSTED_RATE_PER_MIN, 120, 1, 100_000),
    anonPerMin: int(env.BUZZ_HOSTED_ANON_RATE_PER_MIN, 60, 1, 100_000),
    maxSessionsPerUser: int(env.BUZZ_HOSTED_MAX_SESSIONS_PER_USER, 8, 1, 100),
    maxSessions: int(env.BUZZ_HOSTED_MAX_SESSIONS, 200, 1, 1_000_000),
    idleMs: int(env.BUZZ_HOSTED_SESSION_IDLE_S, 1800, 30, 86400) * 1000,
    allowedOrigins: list(env.BUZZ_HOSTED_ALLOWED_ORIGINS),
    allowedHosts: list(env.BUZZ_HOSTED_ALLOWED_HOSTS).map((h) => h.toLowerCase()),
    jsonResponse: env.BUZZ_HOSTED_JSON_RESPONSE === "1",
  };
  if (cfg.clientId === "REPLACE_WITH_EKAM_CLIENT_ID" && env.BUZZ_HOSTED_ALLOW_PLACEHOLDER !== "1" && listen)
    process.stderr.write("[buzz-mcp] ⚠ BUZZ_HOSTED_CLIENT_ID is the placeholder — token exchange will fail until Ekam issues a client id.\n");
  const write = logSink || ((o) => process.stdout.write(JSON.stringify(o) + "\n"));
  const log = (evt, f = {}) => { try { const o = { ts: new Date(now()).toISOString(), evt, ...f }; if (o.err) o.err = redact(o.err).slice(0, 300); write(o); } catch {} };

  const meta = createAsMetadata(cfg, { fetch: fetchFn, now });
  const validate = createTokenValidator(cfg, { fetch: fetchFn, now, metadata: meta });
  const store = createEncryptedTokenStore({ path: cfg.tokenStorePath, keyB64: cfg.tokenStoreKey, now });
  const exchanger = createTokenExchanger(cfg, { fetch: fetchFn, now, metadata: meta, store });
  const userLimit = bucket(O.perMin, now), anonLimit = bucket(O.anonPerMin, now);
  const CORE_ENV = coreEnv(env);
  const signBase = cfg.signBase;
  const pubkeys = new Map();            // sub → person's pubkey (learned via a wire-sign probe, never a key fetch)
  const writeGuards = new Map();        // sub → per-USER write guard (shared across that person's sessions)
  const guardFor = (sub) => { let g = writeGuards.get(sub); if (!g) { g = createWriteGuard({ perMin: writeLimitFromEnv(env) }); writeGuards.set(sub, g); } return g; };
  const sessions = new Map();           // sid → session
  const userSessions = new Map();       // sub → Set<sid>

  // Tool list for ListTools without a person's identity: one template core with a signer that can't sign.
  const template = await createBuzzServer({ hosted: true, env: CORE_ENV, displayName: "Ola Buzz",
    signer: makeHostedWireSigner({ pubkey: "0".repeat(64), base: signBase, fetch: async () => { throw new Error("template signer never signs"); }, getToken: async () => { throw new Error("no identity"); } }) });
  const TOOLS = template.tools;
  await template.close();

  async function ensureCore(s) {
    if (s.core) return s.core;
    if (s.coreP) return s.coreP;
    s.coreP = (async () => {
      const getToken = async (force = false) => (s.wireToken = await exchanger.get(s.principal, s.subjectToken, force));
      let pk = pubkeys.get(s.sub);
      if (!pk) {
        const t0 = await getToken(false);   // exchange errors are already sanitised; don't relabel them
        try { pk = await probeWirePubkey(signBase, t0, fetchFn); }
        catch (e) {
          if (e.status === 401) { const t1 = await getToken(true); pk = await probeWirePubkey(signBase, t1, fetchFn).catch((e2) => { throw hostedWireError(e2, 27235); }); }
          else if (e.code === "buzz_app_signin_required" || isBuzzAppSigninError({ status: e.status, error: e.ekamError === "forbidden" ? null : e.ekamError })) { const x = new Error(BUZZ_APP_SIGNIN_MESSAGE); x.code = "buzz_app_signin_required"; throw x; }
          else throw hostedWireError(e, 27235);
        }
        pubkeys.set(s.sub, pk);
      }
      const signer = makeHostedWireSigner({ pubkey: pk, getToken, base: signBase, fetch: fetchFn });
      const core = await createBuzzServer({ hosted: true, env: CORE_ENV, signer, displayName: s.principal.name || null, writeGuard: guardFor(s.sub) });
      s.core = core; return core;
    })();
    try { return await s.coreP; } finally { s.coreP = null; }
  }

  function newSession(principal, subjectToken) {
    const s = { sid: null, sub: principal.sub, user: hashSub(principal.sub), principal, subjectToken, core: null, coreP: null, last: now(), transport: null, server: null };
    const server = new Server({ name: "Ola Buzz", title: "Ola Buzz", version }, { capabilities: { tools: {} } });
    server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
    server.setRequestHandler(CallToolRequestSchema, async (req, extra) => {
      const t0 = now(), tool = req.params && req.params.name;
      try {
        const core = await ensureCore(s);
        const r = scrubResult(await core.callTool(req, extra), s.subjectToken, s.wireToken);
        log("tool", { user: s.user, sid: s.sid && s.sid.slice(0, 8), tool, ok: !r.isError, ms: now() - t0 });
        return r;
      } catch (e) {
        const friendly = e && (e.code === "buzz_app_signin_required" || BUZZ_APP_SIGNIN_RE.test(String(e.message)));
        log("tool", { user: s.user, sid: s.sid && s.sid.slice(0, 8), tool, ok: false, ms: now() - t0, err: friendly ? "not_provisioned" : scrub(e && e.message, s.subjectToken, s.wireToken) });
        return { content: [{ type: "text", text: friendly ? BUZZ_APP_SIGNIN_MESSAGE : `error: ${scrub(e && e.message, s.subjectToken, s.wireToken).slice(0, 400)}` }], isError: true };
      }
    });
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      enableJsonResponse: O.jsonResponse,
      onsessioninitialized: (sid) => {
        s.sid = sid; sessions.set(sid, s);
        let set = userSessions.get(s.sub); if (!set) userSessions.set(s.sub, (set = new Set()));
        set.add(sid);
        while (set.size > O.maxSessionsPerUser) { const oldest = set.values().next().value; closeSession(sessions.get(oldest), "per_user_cap"); }
        log("session_open", { user: s.user, sid: sid.slice(0, 8) });
      },
    });
    transport.onclose = () => dropSession(s, "closed");
    s.transport = transport; s.server = server;
    return s;
  }
  function dropSession(s, why) {
    if (!s || !s.sid || !sessions.has(s.sid)) return;
    sessions.delete(s.sid);
    const set = userSessions.get(s.sub); if (set) { set.delete(s.sid); if (!set.size) userSessions.delete(s.sub); }
    if (s.core) s.core.close().catch(() => {});
    s.core = null; s.subjectToken = null;
    log("session_close", { user: s.user, sid: s.sid.slice(0, 8), why });
  }
  function closeSession(s, why) { if (!s) return; dropSession(s, why); s.transport.close().catch(() => {}); s.server.close().catch(() => {}); }
  const sweep = setInterval(() => { const cut = now() - O.idleMs; for (const s of [...sessions.values()]) if (s.last < cut) closeSession(s, "idle"); }, Math.min(60_000, O.idleMs));
  sweep.unref?.();

  const prmUrl = resourceMetadataUrl(cfg);
  const send = (res, status, body, headers = {}) => {
    if (res.headersSent) { try { res.end(); } catch {} return; }
    res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...headers });
    res.end(typeof body === "string" ? body : JSON.stringify(body));
  };
  const rpcErr = (res, status, code, message, headers) => send(res, status, { jsonrpc: "2.0", error: { code, message }, id: null }, headers);
  const challenge = (e) => {
    const parts = [`Bearer resource_metadata="${prmUrl}"`];
    if (e) parts.push(`error="${e.error}"`, `error_description="${String(e.description).replace(/["\\]/g, "")}"`);
    if (e && e.error === "insufficient_scope" && cfg.requiredScopes.length) parts.push(`scope="${cfg.requiredScopes.join(" ")}"`);
    return parts.join(", ");
  };
  const readBody = (req) => new Promise((resolve, reject) => {
    const len = Number(req.headers["content-length"]);
    if (Number.isFinite(len) && len > O.maxBody) return reject(Object.assign(new Error("too large"), { status: 413 }));
    const chunks = []; let n = 0;
    req.on("data", (c) => { n += c.length; if (n > O.maxBody) { req.removeAllListeners("data"); req.resume(); reject(Object.assign(new Error("too large"), { status: 413 })); } else chunks.push(c); });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
  const clientIp = (req) => String(req.socket.remoteAddress || "?");

  async function handle(req, res) {
    const t0 = now();
    const url = new URL(req.url || "/", "http://x");
    const path = url.pathname.replace(/\/+$/, "") || "/";
    let status = 0, user = null;
    res.on("finish", () => { status = res.statusCode; if (path !== "/healthz") log("http", { method: req.method, path, status, ms: now() - t0, user }); });
    if (O.allowedHosts.length) {
      const h = String(req.headers.host || "").toLowerCase().replace(/:\d+$/, "");
      if (!O.allowedHosts.includes(h)) return send(res, 421, { error: "misdirected_request" });
    }
    if (path === "/healthz") return send(res, 200, { ok: true, name: "Ola Buzz", version, sessions: sessions.size });
    if (path === "/.well-known/oauth-protected-resource" || path === `/.well-known/oauth-protected-resource${cfg.mcpPath}`) {
      if (req.method !== "GET" && req.method !== "HEAD") return send(res, 405, { error: "method_not_allowed" }, { Allow: "GET" });
      return send(res, 200, protectedResourceMetadata(cfg), { "Cache-Control": "public, max-age=300", "Access-Control-Allow-Origin": "*" });
    }
    if (path !== cfg.mcpPath) return send(res, 404, { error: "not_found" });
    if (!["POST", "GET", "DELETE"].includes(req.method)) return send(res, 405, { error: "method_not_allowed" }, { Allow: "POST, GET, DELETE" });
    const origin = req.headers.origin;
    if (origin && !O.allowedOrigins.includes(origin)) return send(res, 403, { error: "origin_not_allowed" });

    const auth = String(req.headers.authorization || "");
    const m = /^Bearer[ ]+([^\s]+)$/i.exec(auth);
    if (!m) { const wait = anonLimit(clientIp(req)); if (wait) return send(res, 429, { error: "rate_limited" }, { "Retry-After": String(wait) }); return send(res, 401, { error: "unauthorized" }, { "WWW-Authenticate": challenge(null) }); }
    let principal;
    try { principal = await validate(m[1]); }
    catch (e) {
      const wait = anonLimit(clientIp(req)); if (wait) return send(res, 429, { error: "rate_limited" }, { "Retry-After": String(wait) });
      const ae = e instanceof AuthError ? e : new AuthError(401, "invalid_token", "token could not be validated");
      if (!(e instanceof AuthError)) log("auth_error", { err: scrub(e && e.message, m[1]) });
      return send(res, ae.status, { error: ae.error, error_description: ae.description }, { "WWW-Authenticate": challenge(ae) });
    }
    user = hashSub(principal.sub);
    const wait = userLimit(principal.sub);
    if (wait) return send(res, 429, { error: "rate_limited" }, { "Retry-After": String(wait) });

    let body;
    if (req.method === "POST") {
      const ct = String(req.headers["content-type"] || "");
      if (!/^application\/json\b/i.test(ct)) return rpcErr(res, 415, -32000, "Content-Type must be application/json");
      let raw;
      try { raw = await readBody(req); } catch (e) { return rpcErr(res, e.status || 400, -32000, e.status === 413 ? `request body exceeds ${O.maxBody} bytes` : "could not read request body", { Connection: "close" }); }
      try { body = JSON.parse(raw); } catch { return rpcErr(res, 400, -32700, "Parse error"); }
    }

    const sid = req.headers["mcp-session-id"];
    let s;
    if (sid) {
      s = sessions.get(String(sid));
      if (!s) return rpcErr(res, 404, -32001, "Session not found");
      if (s.sub !== principal.sub) { log("session_mismatch", { user, sid: String(sid).slice(0, 8) }); return rpcErr(res, 403, -32003, "Session belongs to a different user"); }
      s.principal = principal; s.subjectToken = m[1]; s.last = now();
    } else {
      const isInit = req.method === "POST" && (Array.isArray(body) ? body.some(isInitializeRequest) : isInitializeRequest(body));
      if (!isInit) return rpcErr(res, 400, -32000, "Bad Request: no valid session ID provided");
      if (sessions.size >= O.maxSessions) return rpcErr(res, 503, -32000, "Server busy — too many sessions", { "Retry-After": "30" });
      s = newSession(principal, m[1]);
      await s.server.connect(s.transport);
    }
    try { await s.transport.handleRequest(req, res, body); }
    catch (e) { log("mcp_error", { user, err: scrub(e && e.message, m[1], s && s.wireToken) }); if (!res.headersSent) rpcErr(res, 500, -32603, "Internal error"); }
  }

  const httpServer = createServer({ requestTimeout: 120_000, headersTimeout: 30_000, maxHeaderSize: 16 * 1024 }, (req, res) => {
    handle(req, res).catch((e) => { log("http_error", { err: String(e && e.message) }); if (!res.headersSent) send(res, 500, { error: "internal_error" }); });
  });
  const close = async () => {
    clearInterval(sweep);
    for (const s of [...sessions.values()]) closeSession(s, "shutdown");
    await new Promise((r) => httpServer.close(() => r()));
  };
  if (listen) {
    const p = port ?? int(env.PORT || env.BUZZ_HOSTED_PORT, 8080, 0, 65535);
    const h = host ?? (env.BUZZ_HOSTED_HOST || "0.0.0.0");
    await new Promise((r) => httpServer.listen(p, h, r));
    log("listening", { port: httpServer.address().port, resource: cfg.resource, issuer: cfg.issuer, validation: cfg.validation, version });
    const stop = () => { log("shutdown", {}); close().finally(() => process.exit(0)); setTimeout(() => process.exit(0), 10_000).unref(); };
    process.once("SIGTERM", stop); process.once("SIGINT", stop);
  }
  return { httpServer, close, sessions, config: cfg, exchanger, tools: TOOLS, handle };
}
