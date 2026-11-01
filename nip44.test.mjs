// nip44.test.mjs — `node nip44.test.mjs`
// v0.2.33: the vendored spec-strict NIP-44 v2 module against the OFFICIAL NIP-44 test vectors
// (vectors/nip44.vectors.json, sha256 pinned below = the hash published in NIP-44), the NIP-RS
// read-state ciphertext vector, and a cross-check against nostr-tools' nip44 for in-spec sizes.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { getPublicKey } from "nostr-tools/pure";
import * as ref from "nostr-tools/nip44";
import { getConversationKey, getMessageKeys, calcPaddedLen, encrypt, decrypt, ctEqual, MAX_PLAINTEXT } from "./nip44.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✅ " + m)) : (fail++, console.log("  ❌ " + m)));
const hx = (b) => Buffer.from(b).toString("hex");
const sha = (x) => createHash("sha256").update(x).digest("hex");
const throws = (f) => { try { f(); return false; } catch { return true; } };

const raw = readFileSync(join(HERE, "vectors", "nip44.vectors.json"));
ok(sha(raw) === "269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040", "vector file sha256 matches the hash published in NIP-44");
const V = JSON.parse(raw).v2;

console.log("valid.get_conversation_key");
{
  let good = 0;
  for (const t of V.valid.get_conversation_key) if (hx(getConversationKey(t.sec1, t.pub2)) === t.conversation_key) good++;
  ok(good === V.valid.get_conversation_key.length && good === 35, `all ${good}/35 conversation keys match`);
}
console.log("valid.get_message_keys");
{
  const { conversation_key, keys } = V.valid.get_message_keys;
  let good = 0;
  for (const k of keys) {
    const m = getMessageKeys(conversation_key, k.nonce);
    if (hx(m.chachaKey) === k.chacha_key && hx(m.chachaNonce) === k.chacha_nonce && hx(m.hmacKey) === k.hmac_key) good++;
  }
  ok(good === keys.length && good === 32, `all ${good}/32 message-key triples match`);
}
console.log("valid.calc_padded_len");
{
  let good = 0;
  for (const [n, p] of V.valid.calc_padded_len) if (calcPaddedLen(n) === p) good++;
  ok(good === V.valid.calc_padded_len.length && good === 24, `all ${good}/24 padded lengths match`);
}
console.log("valid.encrypt_decrypt");
for (const t of V.valid.encrypt_decrypt) {
  const ck = getConversationKey(t.sec1, getPublicKey(Buffer.from(t.sec2, "hex")));
  ok(hx(ck) === t.conversation_key, `conv key ${t.conversation_key.slice(0, 8)}…`);
  // and symmetric: (sec2, pub1) gives the same key
  ok(hx(getConversationKey(t.sec2, getPublicKey(Buffer.from(t.sec1, "hex")))) === t.conversation_key, `conv key symmetric ${t.conversation_key.slice(0, 8)}…`);
  ok(encrypt(t.plaintext, ck, Buffer.from(t.nonce, "hex")) === t.payload, `encrypt → exact payload (${t.plaintext.length} chars)`);
  ok(decrypt(t.payload, ck) === t.plaintext, `decrypt → exact plaintext`);
}
console.log("valid.encrypt_decrypt_long_msg");
for (const t of V.valid.encrypt_decrypt_long_msg) {
  const pt = t.pattern.repeat(t.repeat);
  ok(sha(pt) === t.plaintext_sha256, `plaintext sha (${t.repeat} × "${t.pattern}")`);
  const payload = encrypt(pt, Buffer.from(t.conversation_key, "hex"), Buffer.from(t.nonce, "hex"));
  ok(sha(payload) === t.payload_sha256, `payload sha256 matches (${pt.length} bytes)`);
  ok(decrypt(payload, t.conversation_key) === pt, "round-trips");
}
console.log("invalid.encrypt_msg_lengths");
{
  const ck = new Uint8Array(32).fill(1);
  for (const n of V.invalid.encrypt_msg_lengths) ok(throws(() => encrypt("a".repeat(n), ck)), `refuses a ${n}-byte plaintext`);
  ok(!throws(() => encrypt("a".repeat(MAX_PLAINTEXT), ck)), "accepts exactly 65535 bytes (the spec max)");
  ok(throws(() => encrypt("é".repeat(32768), ck)), "length is counted in UTF-8 BYTES (65536-byte multibyte string refused)");
}
console.log("invalid.get_conversation_key");
for (const t of V.invalid.get_conversation_key) ok(throws(() => getConversationKey(t.sec1, t.pub2)), `refuses: ${t.note}`);
console.log("invalid.decrypt");
for (const t of V.invalid.decrypt) ok(throws(() => decrypt(t.payload, t.conversation_key)), `refuses: ${t.note}`);

console.log("NIP-RS read-state ciphertext vector (upstream docs/nips/NIP-RS.md)");
{
  const priv = "0".repeat(63) + "1";
  const pub = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
  ok(getPublicKey(Buffer.from(priv, "hex")) === pub, "vector pubkey = G.x");
  const ck = getConversationKey(priv, pub);   // encrypt-to-self
  const ct = "Akt10yui5aDIjfH+xED2Dr1NJ/SGWp85SC/r/bloiLRtj8K59rJrYhcfsNQMoMhpLlvhKqrN0HIGb9/V9BcYKxWV8HT/jjDdvfHLUVfo688I6WpapcX41GzL4VnGGDdFyUom53odJncjHszS3dpTrG1OKp2x9dtdG+924/+Ne49KN4nztd1pikqYeqQuxflKCmh+VcCFbDclQ8a9NUpqWkPpeoweISVVuZDnP9WFoKG5X6YcpXBWH6wjc69xK4cs6KkJ";
  ok(decrypt(ct, ck) === '{"v":1,"client_id":"test-vector-client","contexts":{"group:general":1700001000,"group:dev":1700000500}}', "decrypts to the documented plaintext");
}

console.log("cross-check vs nostr-tools nip44 (in-spec sizes only)");
{
  const a = "11".repeat(32), b = "22".repeat(32);
  const ck = getConversationKey(a, getPublicKey(Buffer.from(b, "hex")));
  ok(hx(ck) === hx(ref.getConversationKey(Buffer.from(a, "hex"), getPublicKey(Buffer.from(b, "hex")))), "same conversation key as nostr-tools");
  for (const n of [1, 31, 32, 33, 300, 4097, 65535]) {
    const pt = n > 3 ? "z".repeat(n - 3) + "✓" : "z".repeat(n);   // multibyte tail, exactly n UTF-8 bytes
    const nonce = new Uint8Array(32).fill(n & 0xff);
    const mine = encrypt(pt, ck, nonce);
    ok(Buffer.byteLength(pt) === n && mine === ref.encrypt(pt, ck, nonce), `identical payload to nostr-tools (${n} B)`);
    ok(ref.decrypt(mine, ck) === pt && decrypt(ref.encrypt(pt, ck), ck) === pt, `interoperates both ways (${n} B)`);
  }
  ok(throws(() => encrypt("q".repeat(65536), ck)), "refuses 65536 bytes even though nostr-tools would accept it (non-spec extension)");
}

console.log("tamper / misc");
{
  const ck = new Uint8Array(32).fill(7);
  const p = encrypt("hello", ck);
  ok(p !== encrypt("hello", ck), "fresh random nonce each call");
  const bytes = Buffer.from(p, "base64");
  bytes[40] ^= 1;
  ok(throws(() => decrypt(bytes.toString("base64"), ck)), "a flipped ciphertext bit fails the MAC");
  ok(throws(() => decrypt(p, new Uint8Array(32).fill(8))), "the wrong key fails the MAC");
  ok(throws(() => decrypt(p.replace(/=+$/, "") + "!!!!", ck)), "non-base64 characters refused");
  ok(throws(() => decrypt(" " + p.slice(1), ck)), "whitespace-mangled payload refused");
  ok(ctEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2])) && !ctEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3])) && !ctEqual(new Uint8Array(1), new Uint8Array(2)), "ctEqual");
  ok(throws(() => encrypt(123, ck)), "non-string plaintext refused");
  ok(throws(() => getConversationKey("11".repeat(32), "zz")), "malformed pubkey refused");
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
