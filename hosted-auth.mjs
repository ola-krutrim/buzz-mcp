// hosted-auth.mjs — v0.2.35 hosted ("Ola Buzz" catalog connector) OAuth resource-server pieces.
// PURE of process state: everything takes a config object + an injectable fetch/clock, so the unit
// tests drive it with a mocked Ekam. Nothing here ever logs, persists in plaintext, or forwards the
// client's access token anywhere except Ekam's own token / introspection endpoints (the issuer).
//
//   hostedConfig(env)              → config (endpoints + client id from env; placeholders, no secrets)
//   createAsMetadata(cfg, deps)    → cached Ekam authorization-server metadata (RFC 8414)
//   createTokenValidator(cfg, deps)→ validate(bearer) → principal {sub, name, email, scopes, exp}
//                                     JWKS (RFC 7515/7517/7519) or introspection (RFC 7662)
//   createTokenExchanger(cfg, deps)→ get(principal, subjectToken, force) → wire:sign access token
//                                     RFC 8693 token exchange, cached per user in memory (+ optional
//                                     AES-256-GCM encrypted-at-rest store)
//   protectedResourceMetadata(cfg) → RFC 9728 document
import { createHash, createPublicKey, verify as cryptoVerify, createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync, writeFileSync, renameSync, existsSync, chmodSync } from "node:fs";
import { isBuzzAppSigninError, buzzAppSigninError } from "./signer.mjs";

export const DEFAULT_RESOURCE = "https://mcp.buzz.ola.in";
export const DEFAULT_ISSUER = "https://ekam.olakrutrim.com";
export const CLIENT_ID_PLACEHOLDER = "REPLACE_WITH_EKAM_CLIENT_ID";
export const TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
export const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const ALLOWED_ALGS = new Set(["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"]);

const trimSlash = (s) => String(s || "").trim().replace(/\/+$/, "");
const list = (s, dflt = []) => (s == null || String(s).trim() === "" ? dflt : String(s).split(/[\s,]+/).filter(Boolean));
const int = (s, d, lo, hi) => { const n = parseInt(s ?? "", 10); return Number.isFinite(n) ? Math.max(lo, Math.min(n, hi)) : d; };

export class AuthError extends Error {
  // status 401 → invalid_token (re-auth), 403 → insufficient_scope; never carries the token.
  constructor(status, error, description) { super(description || error); this.status = status; this.error = error; this.description = description || error; }
}

export function hostedConfig(env = process.env) {
  const resource = trimSlash(env.BUZZ_HOSTED_RESOURCE || DEFAULT_RESOURCE);
  const issuer = trimSlash(env.BUZZ_HOSTED_ISSUER || env.BUZZ_EKAM_BASE || DEFAULT_ISSUER);
  const validation = (env.BUZZ_HOSTED_TOKEN_VALIDATION || "auto").trim().toLowerCase();
  if (!["auto", "jwks", "introspection"].includes(validation)) throw new Error(`BUZZ_HOSTED_TOKEN_VALIDATION must be auto|jwks|introspection (got "${validation}")`);
  const exchangeFormat = (env.BUZZ_HOSTED_EXCHANGE_FORMAT || "json").trim().toLowerCase();
  if (!["json", "form"].includes(exchangeFormat)) throw new Error(`BUZZ_HOSTED_EXCHANGE_FORMAT must be json|form`);
  return Object.freeze({
    resource,
    publicUrl: trimSlash(env.BUZZ_HOSTED_PUBLIC_URL || resource),
    mcpPath: (env.BUZZ_HOSTED_MCP_PATH || "/mcp").trim() || "/mcp",
    issuer,
    signBase: trimSlash(env.BUZZ_EKAM_BASE || issuer),          // where /v1/me/wire-sign lives
    validation,
    jwksUri: trimSlash(env.BUZZ_HOSTED_JWKS_URI || ""),
    introspectionEndpoint: trimSlash(env.BUZZ_HOSTED_INTROSPECTION_ENDPOINT || ""),
    tokenEndpoint: trimSlash(env.BUZZ_HOSTED_TOKEN_ENDPOINT || ""),
    clientId: (env.BUZZ_HOSTED_CLIENT_ID || CLIENT_ID_PLACEHOLDER).trim(),
    clientSecret: (env.BUZZ_HOSTED_CLIENT_SECRET || "").trim() || null,   // env/secret only; optional
    exchangeFormat,
    exchangeScope: (env.BUZZ_HOSTED_EXCHANGE_SCOPE || "wire:sign").trim(),
    exchangeResource: trimSlash(env.BUZZ_HOSTED_EXCHANGE_RESOURCE || issuer), // wire-sign wants aud = ISSUER
    requiredScopes: list(env.BUZZ_HOSTED_REQUIRED_SCOPES),
    scopesSupported: list(env.BUZZ_HOSTED_SCOPES_SUPPORTED, ["openid", "profile", "email"]),
    clockSkewS: int(env.BUZZ_HOSTED_CLOCK_SKEW_S, 60, 0, 300),
    metadataTtlS: int(env.BUZZ_HOSTED_METADATA_TTL_S, 3600, 60, 86400),
    tokenStorePath: (env.BUZZ_HOSTED_TOKEN_STORE || "").trim() || null,
    tokenStoreKey: (env.BUZZ_HOSTED_TOKEN_STORE_KEY || "").trim() || null,  // base64 32 bytes, from a Secret / KMS
  });
}

export function protectedResourceMetadata(cfg) {
  return {
    resource: cfg.resource,
    authorization_servers: [cfg.issuer],
    scopes_supported: cfg.scopesSupported,
    bearer_methods_supported: ["header"],
    resource_name: "Ola Buzz",
    resource_documentation: "https://github.com/ola-krutrim/buzz-mcp#hosted-mode",
  };
}
export const resourceMetadataUrl = (cfg) => `${cfg.publicUrl}/.well-known/oauth-protected-resource`;

async function readJson(res, what) {
  const text = await res.text();
  let j = null; try { j = JSON.parse(text); } catch { /* non-JSON */ }
  if (!res.ok) {
    const e = new Error(`${what} -> HTTP ${res.status}${j && (j.error || j.error_description) ? `: ${String(j.error_description || j.error).slice(0, 160)}` : ""}`);
    e.status = res.status; e.oauthError = j && typeof j.error === "string" ? j.error : null;
    throw e;
  }
  if (!j || typeof j !== "object") throw new Error(`${what} returned non-JSON`);
  return j;
}

export function createAsMetadata(cfg, { fetch: fetchFn = fetch, now = Date.now } = {}) {
  let cached = null, at = 0, inflight = null;
  return async function get() {
    if (cached && now() - at < cfg.metadataTtlS * 1000) return cached;
    if (inflight) return inflight;
    inflight = (async () => {
      try {
        const j = await readJson(await fetchFn(`${cfg.issuer}/.well-known/oauth-authorization-server`, { headers: { Accept: "application/json" } }), "authorization-server metadata");
        if (j.issuer && trimSlash(j.issuer) !== cfg.issuer) throw new Error(`authorization-server metadata issuer mismatch (${j.issuer} ≠ ${cfg.issuer})`);
        cached = j; at = now(); return j;
      } finally { inflight = null; }
    })();
    return inflight;
  };
}

const b64urlJson = (s) => JSON.parse(Buffer.from(s, "base64url").toString("utf8"));
const looksJwt = (t) => /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(t);
const audList = (a) => (Array.isArray(a) ? a : a == null ? [] : [a]).map((x) => trimSlash(x));
const scopeList = (c) => (Array.isArray(c.scp) ? c.scp : list(c.scope || c.scp || ""));

function principalFrom(c, exp) {
  const sub = typeof c.sub === "string" ? c.sub.trim() : "";
  if (!sub) throw new AuthError(401, "invalid_token", "token has no subject");
  const nm = [c.name, c.preferred_username, [c.given_name, c.family_name].filter(Boolean).join(" "), typeof c.email === "string" ? c.email.split("@")[0] : ""]
    .map((x) => (typeof x === "string" ? x.trim() : "")).find(Boolean) || null;
  return Object.freeze({ sub, name: nm, email: typeof c.email === "string" ? c.email : null, scopes: scopeList(c), exp, clientId: c.client_id || c.azp || null });
}

function checkClaims(cfg, c, nowS) {
  if (c.iss != null && trimSlash(c.iss) !== cfg.issuer) throw new AuthError(401, "invalid_token", "token issuer is not Ekam");
  if (!audList(c.aud).includes(cfg.resource) && !audList(c.resource).includes(cfg.resource))
    throw new AuthError(401, "invalid_token", `token audience is not ${cfg.resource}`);
  const exp = Number(c.exp);
  if (!Number.isFinite(exp)) throw new AuthError(401, "invalid_token", "token has no expiry");
  if (exp + cfg.clockSkewS < nowS) throw new AuthError(401, "invalid_token", "token expired");
  if (c.nbf != null && Number(c.nbf) - cfg.clockSkewS > nowS) throw new AuthError(401, "invalid_token", "token not yet valid");
  const p = principalFrom(c, exp);
  const missing = cfg.requiredScopes.filter((s) => !p.scopes.includes(s));
  if (missing.length) throw new AuthError(403, "insufficient_scope", `token lacks scope ${missing.join(" ")}`);
  return p;
}

function verifyJwtSig(alg, jwk, signingInput, sig) {
  const key = createPublicKey({ key: jwk, format: "jwk" });
  const data = Buffer.from(signingInput);
  if (alg === "EdDSA") return cryptoVerify(null, data, key, sig);
  const hash = `sha${alg.slice(2)}`;
  if (alg.startsWith("RS")) return cryptoVerify(hash, data, key, sig);
  if (alg.startsWith("PS")) return cryptoVerify(hash, data, { key, padding: 6 /* RSA_PKCS1_PSS_PADDING */, saltLength: Number(alg.slice(2)) / 8 }, sig);
  if (alg.startsWith("ES")) return cryptoVerify(hash, data, { key, dsaEncoding: "ieee-p1363" }, sig);
  return false;
}

export function createTokenValidator(cfg, { fetch: fetchFn = fetch, now = Date.now, metadata } = {}) {
  const meta = metadata || createAsMetadata(cfg, { fetch: fetchFn, now });
  let jwks = null, jwksAt = 0, jwksMissAt = 0;
  const introCache = new Map(); // sha256(token) → { p, until }
  const INTRO_TTL = 60_000, INTRO_MAX = 10_000;

  async function jwksUri() { return cfg.jwksUri || (await meta()).jwks_uri || null; }
  async function loadJwks(force) {
    if (!force && jwks && now() - jwksAt < cfg.metadataTtlS * 1000) return jwks;
    const uri = await jwksUri();
    if (!uri) throw new AuthError(401, "invalid_token", "no JWKS available to verify the token");
    const j = await readJson(await fetchFn(uri, { headers: { Accept: "application/json" } }), "JWKS");
    jwks = Array.isArray(j.keys) ? j.keys : []; jwksAt = now();
    return jwks;
  }
  async function viaJwks(token) {
    const [h, p, s] = token.split(".");
    let header, claims;
    try { header = b64urlJson(h); claims = b64urlJson(p); } catch { throw new AuthError(401, "invalid_token", "malformed token"); }
    if (!ALLOWED_ALGS.has(header.alg)) throw new AuthError(401, "invalid_token", "token algorithm not accepted");
    const pick = (ks) => ks.filter((k) => (!header.kid || k.kid === header.kid) && (!k.use || k.use === "sig") && (!k.alg || k.alg === header.alg));
    let cands = pick(await loadJwks(false));
    if (!cands.length && now() - jwksMissAt > 60_000) { jwksMissAt = now(); cands = pick(await loadJwks(true)); } // key rotation
    if (!cands.length) throw new AuthError(401, "invalid_token", "token signing key not found");
    const sig = Buffer.from(s, "base64url");
    const good = cands.some((k) => { try { return verifyJwtSig(header.alg, k, `${h}.${p}`, sig); } catch { return false; } });
    if (!good) throw new AuthError(401, "invalid_token", "token signature invalid");
    return checkClaims(cfg, claims, Math.floor(now() / 1000));
  }
  async function viaIntrospection(token) {
    const key = createHash("sha256").update(token).digest("hex");
    const hit = introCache.get(key);
    if (hit && hit.until > now()) return hit.p;
    const ep = cfg.introspectionEndpoint || (await meta()).introspection_endpoint;
    if (!ep) throw new AuthError(401, "invalid_token", "no introspection endpoint configured");
    const headers = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" };
    const form = new URLSearchParams({ token, token_type_hint: "access_token" });
    if (cfg.clientSecret) headers.Authorization = "Basic " + Buffer.from(`${encodeURIComponent(cfg.clientId)}:${encodeURIComponent(cfg.clientSecret)}`).toString("base64");
    else form.set("client_id", cfg.clientId);
    let j;
    try { j = await readJson(await fetchFn(ep, { method: "POST", headers, body: form.toString() }), "introspection"); }
    catch (e) { throw new AuthError(401, "invalid_token", `token could not be introspected (${e.status ? `HTTP ${e.status}` : "unreachable"})`); }
    if (j.active !== true) throw new AuthError(401, "invalid_token", "token is not active");
    const p = checkClaims(cfg, j, Math.floor(now() / 1000));
    if (introCache.size >= INTRO_MAX) introCache.delete(introCache.keys().next().value);
    introCache.set(key, { p, until: Math.min(now() + INTRO_TTL, p.exp * 1000) });
    return p;
  }
  return async function validate(token) {
    if (typeof token !== "string" || !token || token.length > 8192) throw new AuthError(401, "invalid_token", "missing or oversized bearer token");
    if (cfg.validation === "introspection") return viaIntrospection(token);
    if (cfg.validation === "jwks") { if (!looksJwt(token)) throw new AuthError(401, "invalid_token", "token is not a JWT"); return viaJwks(token); }
    return looksJwt(token) ? viaJwks(token) : viaIntrospection(token); // auto
  };
}

// ---- optional encrypted-at-rest token store (AES-256-GCM; never plaintext) ----
const STORE_AAD = Buffer.from("buzz-mcp-hosted-tokens-v1");
export function createEncryptedTokenStore({ path, keyB64, now = Date.now } = {}) {
  if (!path) return null;
  const key = keyB64 ? Buffer.from(keyB64, "base64") : null;
  if (!key || key.length !== 32) throw new Error("BUZZ_HOSTED_TOKEN_STORE is set but BUZZ_HOSTED_TOKEN_STORE_KEY is missing or not 32 bytes (base64) — refusing to store tokens without encryption");
  const load = () => {
    if (!existsSync(path)) return new Map();
    try {
      const { iv, tag, ct } = JSON.parse(readFileSync(path, "utf8"));
      const d = createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64")); d.setAAD(STORE_AAD); d.setAuthTag(Buffer.from(tag, "base64"));
      const m = new Map(Object.entries(JSON.parse(Buffer.concat([d.update(Buffer.from(ct, "base64")), d.final()]).toString("utf8"))));
      for (const [k, v] of m) if (!v || !(v.exp > now())) m.delete(k);
      return m;
    } catch { return new Map(); } // wrong key / tampered → start empty (tokens are re-exchangeable)
  };
  const save = (m) => {
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", key, iv); c.setAAD(STORE_AAD);
    const ct = Buffer.concat([c.update(JSON.stringify(Object.fromEntries(m)), "utf8"), c.final()]);
    const tmp = `${path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify({ v: 1, iv: iv.toString("base64"), tag: c.getAuthTag().toString("base64"), ct: ct.toString("base64") }), { mode: 0o600 });
    try { chmodSync(tmp, 0o600); } catch {}
    renameSync(tmp, path);
  };
  return { load, save };
}

// ---- RFC 8693 token exchange: the person's validated access token → a wire:sign token for them ----
export function createTokenExchanger(cfg, { fetch: fetchFn = fetch, now = Date.now, metadata, store = null, maxUsers = 10_000 } = {}) {
  const meta = metadata || createAsMetadata(cfg, { fetch: fetchFn, now });
  const cache = store ? store.load() : new Map(); // sub → { token, exp (ms) }
  const inflight = new Map();
  const MARGIN = 60_000;
  const persist = () => { if (store) try { store.save(cache); } catch { /* best effort; memory cache still serves */ } };
  async function exchange(subjectToken) {
    const ep = cfg.tokenEndpoint || (await meta()).token_endpoint || `${cfg.issuer}/oauth/token`;
    const params = {
      grant_type: TOKEN_EXCHANGE_GRANT,
      subject_token: subjectToken,
      subject_token_type: ACCESS_TOKEN_TYPE,
      requested_token_type: ACCESS_TOKEN_TYPE,
      scope: cfg.exchangeScope,
      resource: cfg.exchangeResource,
      client_id: cfg.clientId,
    };
    const headers = { Accept: "application/json" };
    if (cfg.clientSecret) headers.Authorization = "Basic " + Buffer.from(`${encodeURIComponent(cfg.clientId)}:${encodeURIComponent(cfg.clientSecret)}`).toString("base64");
    let body;
    if (cfg.exchangeFormat === "form") { headers["Content-Type"] = "application/x-www-form-urlencoded"; body = new URLSearchParams(params).toString(); }
    else { headers["Content-Type"] = "application/json"; body = JSON.stringify(params); }
    let j;
    try { j = await readJson(await fetchFn(ep, { method: "POST", headers, body }), "token exchange"); }
    catch (e) {
      if (e.oauthError && isBuzzAppSigninError({ error: e.oauthError })) throw buzzAppSigninError(e); // only explicit codes (ASSUMPTION)
      const err = new Error(`Ekam token exchange failed (${e.status ? `HTTP ${e.status}${e.oauthError ? ` ${e.oauthError}` : ""}` : "unreachable"}) — reconnect Ola Buzz and try again`);
      err.status = e.status; err.oauthError = e.oauthError; throw err;
    }
    if (typeof j.access_token !== "string" || !j.access_token) throw new Error("Ekam token exchange returned no access_token");
    if (j.scope != null && !list(j.scope).includes(cfg.exchangeScope)) throw new Error(`Ekam token exchange did not grant ${cfg.exchangeScope}`);
    // Only access_token is kept. A refresh_token / id_token in the response is deliberately dropped:
    // never cached, persisted, logged or returned (re-exchange from the client's token instead).
    const ttl = Math.max(30, Math.min(Number(j.expires_in) || 300, 86400)) * 1000;
    return { token: j.access_token, exp: now() + ttl };
  }
  return {
    async get(principal, subjectToken, force = false) {
      const sub = principal && principal.sub;
      if (!sub) throw new Error("token exchange needs a validated principal");
      const hit = cache.get(sub);
      if (!force && hit && hit.exp - MARGIN > now()) return hit.token;
      if (inflight.has(sub)) return inflight.get(sub);
      const p = (async () => {
        try {
          const r = await exchange(subjectToken);
          cache.delete(sub); cache.set(sub, r);
          while (cache.size > maxUsers) cache.delete(cache.keys().next().value);
          persist();
          return r.token;
        } finally { inflight.delete(sub); }
      })();
      inflight.set(sub, p);
      return p;
    },
    drop(sub) { if (cache.delete(sub)) persist(); },
    size: () => cache.size,
  };
}

export const hashSub = (sub) => createHash("sha256").update(String(sub)).digest("hex").slice(0, 12);
export const constantTimeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); };
