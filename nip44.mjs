// nip44.mjs — vendored, SPEC-STRICT NIP-44 v2 (https://github.com/nostr-protocol/nips/blob/master/44.md).
// v0.2.33. Built only on the audited @noble primitives already in the lockfile (no new packages).
//
// Why vendored instead of nostr-tools' nip44: nostr-tools 2.25.x accepts plaintexts > 65535 bytes via a
// non-spec 32-bit length prefix. Read state (NIP-RS) and private bookmarks are read by OTHER Buzz
// clients, so this module refuses anything outside the spec (1..65535 bytes) instead of emitting a
// payload another client can't decrypt. Verified against the official NIP-44 vectors (nip44.test.mjs).
//
// SECURITY REVIEW: flagged for buzz_security (crypto code). The MAC is checked in constant time BEFORE
// decrypting; every length/version check fails closed with a generic error (no oracle detail).
import { chacha20 } from "@noble/ciphers/chacha.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { extract as hkdfExtract, expand as hkdfExpand } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes, concatBytes } from "@noble/hashes/utils.js";

const SALT = new TextEncoder().encode("nip44-v2");
export const MIN_PLAINTEXT = 1;
export const MAX_PLAINTEXT = 65535;
const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });

const isHex = (s, n) => typeof s === "string" && s.length === n && /^[0-9a-f]+$/i.test(s);
const hexToBytes = (h) => Uint8Array.from(Buffer.from(h, "hex"));
function toBytes32(k, what) {
  if (k instanceof Uint8Array && k.length === 32) return k;
  if (isHex(k, 64)) return hexToBytes(k);
  throw new Error(`nip44: ${what} must be 32 bytes`);
}

// Constant-time equality (length leak only, which is public here).
export function ctEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/** conversation_key = HKDF-extract(salt="nip44-v2", IKM = shared_x(privA, pubB)). pubB is x-only hex. */
export function getConversationKey(privA, pubBx) {
  const sk = toBytes32(privA, "private key");
  if (!isHex(pubBx, 64)) throw new Error("nip44: public key must be 64 hex chars (x-only)");
  // getSharedSecret validates the point (throws for x not on the curve) and the scalar range.
  const shared = secp256k1.getSharedSecret(sk, hexToBytes("02" + pubBx));
  const x = shared.subarray(1, 33);
  const key = hkdfExtract(sha256, x, SALT);
  shared.fill(0);
  return key;
}

export function getMessageKeys(conversationKey, nonce) {
  const ck = toBytes32(conversationKey, "conversation key");
  const n = toBytes32(nonce, "nonce");
  const keys = hkdfExpand(sha256, ck, n, 76);
  return { chachaKey: keys.subarray(0, 32), chachaNonce: keys.subarray(32, 44), hmacKey: keys.subarray(44, 76), _all: keys };
}

export function calcPaddedLen(len) {
  if (!Number.isSafeInteger(len) || len < 1) throw new Error("nip44: expected positive integer");
  if (len <= 32) return 32;
  const nextPower = 1 << (Math.floor(Math.log2(len - 1)) + 1);
  const chunk = nextPower <= 256 ? 32 : nextPower / 8;
  return chunk * (Math.floor((len - 1) / chunk) + 1);
}

function pad(plaintext) {
  const u = te.encode(plaintext);
  const n = u.length;
  if (n < MIN_PLAINTEXT || n > MAX_PLAINTEXT) throw new Error("nip44: invalid plaintext size: must be between 1 and 65535 bytes");
  const out = new Uint8Array(2 + calcPaddedLen(n));
  out[0] = n >> 8; out[1] = n & 0xff;
  out.set(u, 2);
  return out;
}

function unpad(padded) {
  if (padded.length < 2) throw new Error("nip44: invalid padding");
  const n = (padded[0] << 8) | padded[1];
  if (n < MIN_PLAINTEXT || n > MAX_PLAINTEXT || padded.length !== 2 + calcPaddedLen(n)) throw new Error("nip44: invalid padding");
  try { return td.decode(padded.subarray(2, 2 + n)); } catch { throw new Error("nip44: invalid utf-8"); }
}

const hmacAad = (key, msg, aad) => hmac(sha256, key, concatBytes(aad, msg));

/** Encrypt. `nonce` is for test vectors only; production callers omit it (fresh CSPRNG 32 bytes). */
export function encrypt(plaintext, conversationKey, nonce = randomBytes(32)) {
  if (typeof plaintext !== "string") throw new Error("nip44: plaintext must be a string");
  const n = toBytes32(nonce, "nonce");
  const { chachaKey, chachaNonce, hmacKey, _all } = getMessageKeys(conversationKey, n);
  try {
    const padded = pad(plaintext);
    const ciphertext = chacha20(chachaKey, chachaNonce, padded);
    padded.fill(0);
    const mac = hmacAad(hmacKey, ciphertext, n);
    return Buffer.from(concatBytes(new Uint8Array([2]), n, ciphertext, mac)).toString("base64");
  } finally { _all.fill(0); }
}

const B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;
function decodePayload(payload) {
  if (typeof payload !== "string") throw new Error("nip44: payload must be a string");
  const plen = payload.length;
  if (plen === 0 || payload[0] === "#") throw new Error("nip44: unknown encryption version");
  if (plen < 132 || plen > 87472) throw new Error("nip44: invalid payload length");
  if (plen % 4 !== 0 || !B64_RE.test(payload)) throw new Error("nip44: invalid base64");
  const data = Uint8Array.from(Buffer.from(payload, "base64"));
  const dlen = data.length;
  if (dlen < 99 || dlen > 65603) throw new Error("nip44: invalid data length");
  if (data[0] !== 2) throw new Error("nip44: unknown encryption version");
  return { nonce: data.subarray(1, 33), ciphertext: data.subarray(33, dlen - 32), mac: data.subarray(dlen - 32) };
}

export function decrypt(payload, conversationKey) {
  const { nonce, ciphertext, mac } = decodePayload(payload);
  const { chachaKey, chachaNonce, hmacKey, _all } = getMessageKeys(conversationKey, nonce);
  try {
    const want = hmacAad(hmacKey, ciphertext, nonce);
    if (!ctEqual(want, mac)) throw new Error("nip44: invalid MAC");
    const padded = chacha20(chachaKey, chachaNonce, ciphertext);
    try { return unpad(padded); } finally { padded.fill(0); }
  } finally { _all.fill(0); }
}
