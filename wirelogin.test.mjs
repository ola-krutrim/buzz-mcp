// wirelogin.test.mjs — `node wirelogin.test.mjs`
import { pkce, authorizeUrl, exchangeAuthCode, bindLoopback } from "./wirelogin.mjs";
import { createHash } from "node:crypto";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✅ " + m)) : (fail++, console.log("  ❌ " + m)));
const b64url = (buf) => Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

console.log("pkce — S256 challenge derives from the verifier:");
const { verifier, challenge } = pkce();
ok(verifier.length >= 43 && !/[+/=]/.test(verifier), "verifier is base64url, ≥43 chars (RFC 7636)");
ok(challenge === b64url(createHash("sha256").update(verifier).digest()), "challenge = base64url(sha256(verifier))");

console.log("authorizeUrl — carries the wire:sign scope + resource + PKCE:");
const url = authorizeUrl("https://ekam.test", { clientId: "clt_x", redirectUri: "http://127.0.0.1:8765/callback", challenge, state: "st8", resource: "https://ekam.test" });
const q = new URL(url).searchParams;
ok(url.startsWith("https://ekam.test/authorize?"), "hits /authorize");
ok(q.get("response_type") === "code" && q.get("client_id") === "clt_x", "response_type=code, client_id");
ok(q.get("scope") === "openid wire:sign offline_access", "scope = openid wire:sign offline_access");
ok(q.get("resource") === "https://ekam.test" && q.get("code_challenge_method") === "S256", "resource=ISSUER, S256");
ok(q.get("code_challenge") === challenge && q.get("state") === "st8" && q.get("redirect_uri") === "http://127.0.0.1:8765/callback", "code_challenge, state, redirect_uri");

console.log("exchangeAuthCode — authcode grant request shape + token handling:");
let captured = null;
const okFetch = async (u, init) => { captured = { u, body: JSON.parse(init.body) }; return { ok: true, status: 200, text: async () => JSON.stringify({ access_token: "at", refresh_token: "rt_1", expires_in: 900 }) }; };
const tok = await exchangeAuthCode("https://ekam.test", { code: "c0de", verifier, clientId: "clt_x", redirectUri: "http://127.0.0.1:8765/callback" }, okFetch);
ok(captured.u === "https://ekam.test/oauth/token", "POSTs /oauth/token");
ok(captured.body.grant_type === "authorization_code" && captured.body.code === "c0de" && captured.body.code_verifier === verifier && captured.body.client_id === "clt_x" && captured.body.redirect_uri === "http://127.0.0.1:8765/callback", "body: grant_type=authorization_code + code + code_verifier + client_id + redirect_uri");
ok(tok.refresh_token === "rt_1" && tok.access_token === "at", "returns {access_token, refresh_token}");

const noRefreshFetch = async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ access_token: "at" }) });
try { await exchangeAuthCode("https://ekam.test", { code: "c", verifier, clientId: "x", redirectUri: "r" }, noRefreshFetch); ok(false, "missing refresh should throw"); }
catch (e) { ok(/no refresh_token/.test(e.message) && /offline_access/.test(e.message), "no refresh_token → LOUD (points at the ② offline_access grant)"); }

const errFetch = async () => ({ ok: false, status: 400, text: async () => '{"error":"invalid_grant","error_description":"code expired"}' });
try { await exchangeAuthCode("https://ekam.test", { code: "c", verifier, clientId: "x", redirectUri: "r" }, errFetch); ok(false, "http error should throw"); }
catch (e) { ok(/HTTP 400/.test(e.message) && /code expired/.test(e.message), "authcode HTTP error → surfaced with description"); }

console.log("bindLoopback — binds a free port, rejects when none free:");
const { srv, port } = await bindLoopback([8765, 8766, 8770]);
ok([8765, 8766, 8770].includes(port), `bound a candidate loopback port (${port})`);
// a second bind over the same single port must fail (already held)
try { const two = await bindLoopback([port]); try { two.srv.close(); } catch {} ok(false, "second bind on the held port should fail"); }
catch (e) { ok(/no free loopback port/.test(e.message), "no free port → throws"); }
try { srv.close(); } catch {}

console.log(`\n${fail === 0 ? "ALL PASS" : "FAILURES"}: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
