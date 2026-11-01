// parity33.mjs — v0.2.33 Slack-parity batch 2: PURE logic (no I/O, no keys), unit-tested in
// parity33.test.mjs. The shim (buzz-mcp.mjs) wires these into tools; every function here fails
// CLOSED on malformed input and treats relay / other-author data as untrusted.

// ───────────────────────── NIP-RS read state (kind 30078) ─────────────────────────
// Spec: upstream-buzz docs/nips/NIP-RS.md. Content is NIP-44 v2 encrypted to self.
export const READ_STATE_KIND = 30078;
export const READ_STATE_T = "read-state";
export const READ_STATE_MAX_CONTEXTS = 10_000;
export const READ_STATE_MAX_CTX_BYTES = 256;
export const READ_STATE_MAX_TS = 4_294_967_295;
const SLOT_RE = /^read-state:[0-9a-f]{32}$/;

/** Exact NIP-RS public envelope: kind 30078, exactly one d = read-state:<32 lc hex>, exactly one t = read-state. */
export function isReadStateEvent(e) {
  if (!e || e.kind !== READ_STATE_KIND || !Array.isArray(e.tags)) return false;
  const ds = e.tags.filter((t) => Array.isArray(t) && t[0] === "d");
  const ts = e.tags.filter((t) => Array.isArray(t) && t[0] === "t");
  return ds.length === 1 && SLOT_RE.test(String(ds[0][1])) && ts.length === 1 && ts[0][1] === READ_STATE_T;
}
export const readStateD = (e) => (e.tags.find((t) => t[0] === "d") || [])[1];

/** Derive this identity's stable slot-id + client_id from a keyed derive() (HMAC under the self conv key). */
export function readStateIdentity(derive) {
  const slot = String(derive("buzz-mcp/nip-rs/slot/v1")).slice(0, 32);
  const client = String(derive("buzz-mcp/nip-rs/client-id/v1")).slice(0, 16);
  if (!/^[0-9a-f]{32}$/.test(slot) || !/^[0-9a-f]{16}$/.test(client)) throw new Error("read state: identity derivation failed");
  return { slot, d: `read-state:${slot}`, clientId: `buzz-mcp-${client}` };
}

const isCtxTs = (v) => Number.isInteger(v) && v >= 0 && v <= READ_STATE_MAX_TS;
/** Validate a decrypted blob per NIP-RS §Validation. Returns { clientId, contexts } or null (discard). */
export function parseReadStateBlob(plaintext) {
  let j;
  try { j = JSON.parse(plaintext); } catch { return null; }
  if (!j || typeof j !== "object" || Array.isArray(j)) return null;
  if (j.v !== 1) return null;   // unknown version → ignore
  const cid = j.client_id;
  if (typeof cid !== "string" || [...cid].length < 1 || [...cid].length > 64) return null;
  const c = j.contexts;
  if (!c || typeof c !== "object" || Array.isArray(c)) return null;
  const keys = Object.keys(c);
  if (keys.length > READ_STATE_MAX_CONTEXTS) return null;
  const contexts = Object.create(null);
  for (const k of keys) {
    if (Buffer.byteLength(k, "utf8") > READ_STATE_MAX_CTX_BYTES) continue;
    if (!isCtxTs(c[k])) continue;
    contexts[k] = c[k];
  }
  return { clientId: cid, contexts };
}

/** Max-merge any number of context maps (NIP-RS merge rule). ov_* override keys are carried verbatim. */
export function mergeContexts(...maps) {
  const out = Object.create(null);
  for (const m of maps) for (const [k, v] of Object.entries(m || {})) if (isCtxTs(v) && !(k in out && out[k] >= v)) out[k] = v;
  return out;
}

// Frontier-key escaping for raw ids starting with the reserved ov_ / esc: stems (a bijection).
export const escapeCtxKey = (raw) => (/^(ov_|esc:)/.test(raw) ? `esc:${raw}` : raw);
export const unescapeCtxKey = (wire) => (wire.startsWith("esc:") ? wire.slice(4) : wire);

/** Frontier-only view (drops ov_* override entries, unescapes esc:) — what unread counting reads. */
export function frontiers(contexts) {
  const out = Object.create(null);
  for (const [k, v] of Object.entries(contexts || {})) { if (k.startsWith("ov_")) continue; out[unescapeCtxKey(k)] = v; }
  return out;
}

/**
 * Decode a set of fetched read-state events. `decrypt` is the signer's encrypt-to-self decrypt.
 * Only events authored by `me` with the exact envelope are considered; undecryptable / invalid blobs
 * are skipped (counted). Returns { merged, own, ownMaxCreatedAt, conflict, used, skipped }.
 */
export function decodeReadState(events, { me, decrypt, ownD, ownClientId }) {
  const blobs = [];
  let skipped = 0, own = null, ownMaxCreatedAt = 0, conflict = false;
  for (const e of events || []) {
    if (!e || e.pubkey !== me || !isReadStateEvent(e)) { skipped++; continue; }
    let pt; try { pt = decrypt(String(e.content || "")); } catch { skipped++; continue; }
    const b = parseReadStateBlob(pt);
    if (!b) { skipped++; continue; }
    blobs.push(b.contexts);
    if (readStateD(e) === ownD) {
      ownMaxCreatedAt = Math.max(ownMaxCreatedAt, e.created_at | 0);
      if (b.clientId !== ownClientId) conflict = true;
      else if (!own || (e.created_at | 0) >= own.created_at) own = { created_at: e.created_at | 0, contexts: b.contexts };
    }
  }
  return { merged: mergeContexts(...blobs), own, ownMaxCreatedAt, conflict, used: blobs.length, skipped };
}

/** Build the next own blob (read-before-write merge) + its created_at = max(now, maxFetched+1). */
export function nextReadStateBlob({ clientId, ownContexts, updates, nowS, ownMaxCreatedAt = 0 }) {
  const esc = Object.create(null);
  for (const [raw, ts] of Object.entries(updates || {})) {
    if (!isCtxTs(ts)) throw new Error("read state: timestamp out of range");
    const k = escapeCtxKey(String(raw));
    if (Buffer.byteLength(k, "utf8") > READ_STATE_MAX_CTX_BYTES) throw new Error("read state: context id too long");
    esc[k] = ts;
  }
  const contexts = mergeContexts(ownContexts || {}, esc);
  if (Object.keys(contexts).length > READ_STATE_MAX_CONTEXTS) throw new Error(`read state: more than ${READ_STATE_MAX_CONTEXTS} contexts — refusing to publish a blob other clients must reject`);
  const plaintext = JSON.stringify({ v: 1, client_id: clientId, contexts });
  if (Buffer.byteLength(plaintext, "utf8") > 65535) throw new Error("read state: blob exceeds the NIP-44 plaintext limit");
  return { plaintext, contexts, created_at: Math.max(nowS, (ownMaxCreatedAt | 0) + 1) };
}

/** Effective frontier for a message per the NIP-RS hierarchy (channel ⊂ thread:<root> ⊂ msg:<id>). */
export function effectiveFrontier(fr, { channel, root, id }) {
  let f = fr[channel] ?? -1;
  if (root && fr[`thread:${root}`] != null) f = Math.max(f, fr[`thread:${root}`]);
  if (id && fr[`msg:${id}`] != null) f = Math.max(f, fr[`msg:${id}`]);
  return f;
}

const tagVal = (e, n) => ((e.tags || []).find((t) => t[0] === n) || [])[1];
const rootOf = (e) => {
  const tags = (e.tags || []).filter((t) => t[0] === "e" && /^[0-9a-f]{64}$/.test(t[1] || ""));
  const r = tags.find((t) => t[3] === "root") || tags.find((t) => t[3] === "reply");
  return r ? r[1] : null;
};
/**
 * Real unread counts. events: kind:9 (already signature-screened). fr: frontiers(). channelIds: the
 * conversations to count. Messages from `me` never count. A channel with NO frontier is reported as
 * `noMarker` (counted within the caller's fallback window, never silently as 0).
 */
export function unreadCounts(events, fr, { me, channelIds, fallbackSince }) {
  const want = new Set(channelIds);
  const stat = new Map();
  for (const id of channelIds) stat.set(id, { unread: 0, mentions: 0, noMarker: fr[id] == null, newest: 0 });
  for (const e of events || []) {
    const ch = tagVal(e, "h");
    if (!ch || !want.has(ch) || e.pubkey === me) continue;
    const s = stat.get(ch);
    const f = s.noMarker ? Math.max(effectiveFrontier(fr, { channel: ch, root: rootOf(e), id: e.id }), (fallbackSince | 0) - 1) : effectiveFrontier(fr, { channel: ch, root: rootOf(e), id: e.id });
    if (e.created_at > f) {
      s.unread++;
      if ((e.tags || []).some((t) => t[0] === "p" && t[1] === me)) s.mentions++;
      s.newest = Math.max(s.newest, e.created_at);
    }
  }
  return stat;
}

// ───────────────────────── kind:0 profile (buzz_profile_set) ─────────────────────────
const CTRL_RE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/u;
const cps = (s) => [...s].length;
export const PROFILE_NAME_MAX = 64, PROFILE_ABOUT_MAX = 500, PROFILE_PICTURE_MAX = 2048;
/** Validate a buzz_profile_set patch. Returns { patch } or { error }. At least one field required. */
export function validateProfilePatch(a = {}) {
  const patch = {};
  if (a.name != null) {
    const n = String(a.name).trim();
    if (!n) return { error: "name must not be empty" };
    if (cps(n) > PROFILE_NAME_MAX) return { error: `name is limited to ${PROFILE_NAME_MAX} characters` };
    if (CTRL_RE.test(n) || /[\n\t]/.test(n)) return { error: "name must not contain control, bidi or invisible characters" };
    patch.name = n;
  }
  if (a.about != null) {
    const s = String(a.about);
    if (cps(s) > PROFILE_ABOUT_MAX) return { error: `about is limited to ${PROFILE_ABOUT_MAX} characters` };
    if (CTRL_RE.test(s)) return { error: "about must not contain control, bidi or invisible characters (newlines are fine)" };
    patch.about = s;
  }
  if (a.picture != null) {
    const s = String(a.picture).trim();
    if (s === "") patch.picture = "";   // explicit clear
    else {
      if (s.length > PROFILE_PICTURE_MAX) return { error: `picture URL is limited to ${PROFILE_PICTURE_MAX} characters` };
      let u; try { u = new URL(s); } catch { return { error: "picture must be an https:// URL" }; }
      if (u.protocol !== "https:" || u.username || u.password || CTRL_RE.test(s) || /\s/.test(s)) return { error: "picture must be a plain https:// URL (no credentials, spaces or control characters)" };
      patch.picture = u.href;
    }
  }
  if (!Object.keys(patch).length) return { error: "give at least one of name / about / picture" };
  return { patch };
}

/** The auto "about" line the shim writes (model · harness · interface · host) — recognisable shape. */
export const AUTO_ABOUT_RE = /^[^·\n]+ · [^·\n]+ · [^·\n]+ · [^·\n]+$/;
const KEEP_FIELDS = ["picture", "banner", "website", "lud16", "nip05", "about", "bot"];
/**
 * Merge: existing kind:0 (own, verified; may be null) + auto fields (always refreshed) + explicit patch
 * (wins). A user-set `about` survives a later boot republish; an auto-shaped (or absent) one is refreshed.
 */
export function mergeProfile(existing, auto, patch = {}) {
  const base = {};
  if (existing && typeof existing === "object" && !Array.isArray(existing))
    for (const k of KEEP_FIELDS) if (typeof existing[k] === "string" || (k === "bot" && typeof existing[k] === "boolean")) base[k] = existing[k];
  const out = { ...base, ...auto };
  if (typeof base.about === "string" && base.about && !AUTO_ABOUT_RE.test(base.about)) out.about = base.about;
  if (patch.name != null) { out.name = patch.name; out.display_name = patch.name; }
  if (patch.about != null) out.about = patch.about;
  if (patch.picture != null) { if (patch.picture === "") delete out.picture; else out.picture = patch.picture; }
  return out;
}
export function parseProfileContent(content) {
  try { const j = JSON.parse(content); return j && typeof j === "object" && !Array.isArray(j) ? j : null; } catch { return null; }
}

// ───────────────────────── NIP-51 saved items (kind 10003) ─────────────────────────
export const BOOKMARK_KIND = 10003;
export const BOOKMARK_MAX = 500;   // keeps the private (NIP-44) list well under the 65535-byte plaintext cap
const isId = (s) => /^[0-9a-f]{64}$/.test(String(s || ""));
/**
 * Read a kind:10003 list. Public items = e tags; private items = NIP-44 (to self) JSON array of tags.
 * Returns { pub, priv, opaque } — opaque=true when content is present but can't be decrypted/parsed
 * (e.g. legacy NIP-04): the caller must then REFUSE to rewrite the list (it would destroy those items).
 */
export function parseBookmarks(ev, decrypt) {
  if (!ev) return { pub: [], priv: [], opaque: false, otherPub: [] };
  const pub = [], otherPub = [];
  for (const t of ev.tags || []) {
    if (!Array.isArray(t)) continue;
    if (t[0] === "e" && isId(t[1])) pub.push(t[1]); else otherPub.push(t);
  }
  let priv = [], otherPriv = [], opaque = false;
  const c = String(ev.content || "");
  if (c) {
    try {
      if (!decrypt) throw new Error("no cipher");
      const arr = JSON.parse(decrypt(c));
      if (!Array.isArray(arr)) throw new Error("not an array");
      for (const t of arr) { if (Array.isArray(t) && t[0] === "e" && isId(t[1])) priv.push(t[1]); else if (Array.isArray(t)) otherPriv.push(t); }
    } catch { opaque = true; }
  }
  return { pub: [...new Set(pub)], priv: [...new Set(priv)], opaque, otherPub, otherPriv };
}
/** Apply save/unsave. Returns the new { tags, privateTags } (other tag types are preserved verbatim). */
export function applyBookmark(list, { id, remove = false, isPrivate = true }) {
  if (!isId(id)) throw new Error("saved items: a 64-hex event id is required");
  let pub = list.pub.filter((x) => x !== id), priv = list.priv.filter((x) => x !== id);
  if (!remove) { if (isPrivate) priv.push(id); else pub.push(id); }
  if (pub.length + priv.length > BOOKMARK_MAX) throw new Error(`saved items: list is full (${BOOKMARK_MAX}) — unsave something first`);
  return {
    tags: [...(list.otherPub || []).filter((t) => t[0] !== "e"), ...pub.map((x) => ["e", x])],
    privateTags: [...(list.otherPriv || []), ...priv.map((x) => ["e", x])],
    changed: list.pub.length !== pub.length || list.priv.length !== priv.length || list.pub.some((x, i) => x !== pub[i]) || list.priv.some((x, i) => x !== priv[i]),
  };
}

// ───────────────────────── kind:40008 diff message (buzz_post_diff) ─────────────────────────
// Mirrors buzz-sdk build_diff_message + the relay's validate_diff_event (ingest.rs).
export const DIFF_KIND = 40008;
export const DIFF_MAX_BYTES = 61_440;
const HEX7 = /^[0-9a-fA-F]{7,}$/;
export function buildDiffTags(m = {}) {
  const repo = String(m.repo || "").trim();
  if (!/^https?:\/\//.test(repo)) throw new Error("repo must be an http:// or https:// URL");
  if (/\s/.test(repo) || CTRL_RE.test(repo) || repo.length > 2048) throw new Error("repo URL must not contain spaces or control characters (≤ 2048 chars)");
  const commit = String(m.commit || "").trim();
  if (!HEX7.test(commit) || commit.length > 64) throw new Error("commit must be 7–64 hex characters");
  const tags = [["repo", repo], ["commit", commit]];
  const str = (v, what, max) => {
    const s = String(v).trim();
    if (!s) throw new Error(`${what} must not be empty`);
    if (CTRL_RE.test(s) || /[\n\r\t]/.test(s) || cps(s) > max) throw new Error(`${what} must be one line, ≤ ${max} characters, no control characters`);
    return s;
  };
  if (m.file != null) tags.push(["file", str(m.file, "file", 512)]);
  if (m.parent_commit != null) {
    const pc = String(m.parent_commit).trim();
    if (!HEX7.test(pc) || pc.length > 64) throw new Error("parent_commit must be 7–64 hex characters");
    tags.push(["parent-commit", pc]);
  }
  if (m.source_branch != null || m.target_branch != null) {
    if (m.source_branch == null || m.target_branch == null) throw new Error("source_branch and target_branch go together (both or neither)");
    tags.push(["branch", str(m.source_branch, "source_branch", 255), str(m.target_branch, "target_branch", 255)]);
  }
  if (m.pr != null) {
    if (!Number.isInteger(m.pr) || m.pr < 1 || m.pr > 4294967295) throw new Error("pr must be a positive integer");
    tags.push(["pr", String(m.pr)]);
  }
  if (m.language != null) tags.push(["l", str(m.language, "language", 64)]);
  if (m.description != null) tags.push(["description", str(m.description, "description", 500)]);
  if (m.truncated === true) tags.push(["truncated", "true"]);
  return tags;
}
export function checkDiffContent(diff) {
  if (typeof diff !== "string" || !diff.trim()) throw new Error("diff text is required");
  const n = Buffer.byteLength(diff, "utf8");
  if (n > DIFF_MAX_BYTES) throw new Error(`diff is ${n} bytes — the relay caps kind:40008 at ${DIFF_MAX_BYTES} (60 KB); trim it or set truncated:true after cutting it down`);
  if (/\u0000/.test(diff)) throw new Error("diff must not contain NUL bytes");
  return diff;
}
