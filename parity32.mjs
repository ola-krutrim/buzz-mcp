// parity32.mjs — v0.2.32 Slack-parity helpers (pure; unit-tested in parity32.test.mjs).
// Message links, search date parsing, dry-run previews (with auth redaction), the open-channel
// directory filter, file listing, relay-signed presence and the custom-emoji palette.
// Nothing here does I/O; the shim wires these to the relay.
import { escapeContent } from "./safety.mjs";
import { parseImeta } from "./signer.mjs";

const HEX64 = /^[0-9a-f]{64}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ── 1. message links ────────────────────────────────────────────────────────────────────────────
// Canonical Buzz deep link (mirrors buzz-cli links.rs): buzz://message?channel=<uuid>&id=<64hex>
// [&thread=<64hex root>]. The parser is STRICT (fail-closed): scheme buzz, host "message", empty
// path, no user/password/fragment, only channel/id/thread, no duplicate or empty values, channel a
// UUID, ids 64-hex (lowercased). Anything else → an error, never a best-effort guess.
export function buildMessageLink({ channel, id, thread } = {}) {
  const ch = String(channel || "").toLowerCase(), ev = String(id || "").toLowerCase();
  if (!UUID.test(ch)) throw new Error("message link: channel must be a UUID");
  if (!HEX64.test(ev)) throw new Error("message link: id must be a 64-hex event id");
  let s = `buzz://message?channel=${ch}&id=${ev}`;
  if (thread != null && thread !== "") {
    const th = String(thread).toLowerCase();
    if (!HEX64.test(th)) throw new Error("message link: thread must be a 64-hex event id");
    if (th !== ev) s += `&thread=${th}`;
  }
  return s;
}
export function parseMessageLink(input) {
  const raw = String(input ?? "").trim();
  if (!raw) throw new Error("message link is empty");
  if (raw.length > 512) throw new Error("message link is too long");
  if (/[\s\u0000-\u001f\u007f-\u009f]/.test(raw)) throw new Error("message link contains whitespace or control characters");
  let u;
  try { u = new URL(raw); } catch { throw new Error("not a valid buzz:// message link"); }
  if (u.protocol !== "buzz:") throw new Error("not a buzz:// link");
  if (u.username || u.password) throw new Error("message link must not carry user info");
  if (u.hash || raw.includes("#")) throw new Error("message link must not carry a fragment");
  if (u.host !== "message") throw new Error('message link host must be "message"');
  if (u.pathname && u.pathname !== "" && u.pathname !== "/") throw new Error("message link must have an empty path");
  if (u.pathname === "/") throw new Error("message link must have an empty path");
  const seen = {};
  for (const [k, v] of u.searchParams) {
    if (!["channel", "id", "thread"].includes(k)) throw new Error(`message link: unknown parameter "${escapeContent(k, { cap: 32 })}"`);
    if (k in seen) throw new Error(`message link: duplicate "${k}"`);
    if (!v) throw new Error(`message link: empty "${k}"`);
    seen[k] = v;
  }
  if (!seen.channel) throw new Error('message link: missing "channel"');
  if (!seen.id) throw new Error('message link: missing "id"');
  if (!UUID.test(seen.channel)) throw new Error("message link: channel must be a UUID");
  if (!HEX64.test(seen.id)) throw new Error("message link: id must be a 64-hex event id");
  if (seen.thread != null && !HEX64.test(seen.thread)) throw new Error("message link: thread must be a 64-hex event id");
  return { channel: seen.channel.toLowerCase(), id: seen.id.toLowerCase(), thread: seen.thread ? seen.thread.toLowerCase() : null };
}

// ── 2. search dates ─────────────────────────────────────────────────────────────────────────────
// `after` / `before` accept: an ISO date (YYYY-MM-DD, UTC midnight; for `before` the END of that
// day), an ISO datetime WITH an explicit zone (Z or ±hh:mm), epoch seconds, or a relative age
// ("90m", "24h", "7d", "2w" = that long ago). Ambiguous inputs (a zone-less datetime, "yesterday")
// are an ERROR — a silently mis-read window is worse than a refusal.
export function parseWhen(input, { end = false, now = Math.floor(Date.now() / 1000) } = {}) {
  if (input == null || input === "") return null;
  if (typeof input === "number") {
    if (!Number.isFinite(input) || input < 0 || input > 1e10) throw new Error(`bad time ${input} — epoch seconds expected`);
    return Math.floor(input);
  }
  const s = String(input).trim();
  if (/^\d{9,10}$/.test(s)) return Number(s);
  const rel = /^(\d{1,5})\s*(m|h|d|w)$/i.exec(s);
  if (rel) return now - Number(rel[1]) * { m: 60, h: 3600, d: 86400, w: 604800 }[rel[2].toLowerCase()];
  const day = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  if (day) {
    const t = Date.UTC(+day[1], +day[2] - 1, +day[3]);
    const d = new Date(t);
    if (d.getUTCFullYear() !== +day[1] || d.getUTCMonth() !== +day[2] - 1 || d.getUTCDate() !== +day[3]) throw new Error(`bad date ${escapeContent(s, { cap: 40 })}`);
    return Math.floor(t / 1000) + (end ? 86399 : 0);
  }
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})$/i.test(s)) {
    const t = Date.parse(s);
    if (Number.isFinite(t)) return Math.floor(t / 1000);
  }
  throw new Error(`can't read the time ${escapeContent(s, { cap: 40 })} — use YYYY-MM-DD, an ISO datetime with a zone (…Z or …-07:00), epoch seconds, or an age like 24h / 7d`);
}

// ── 3. dry-run previews ─────────────────────────────────────────────────────────────────────────
// A write called with dry_run:true resolves everything (channel, recipient, target, mentions) and
// builds its event, then STOPS at signer.sign: DryRunStop carries the unsigned template back. The
// auth / picker-owner delegation tags are credentials — they are REDACTED, never echoed.
export class DryRunStop extends Error {
  constructor(template) { super("dry run — stopped before signing"); this.name = "DryRunStop"; this.template = template; }
}
const REDACT_TAGS = new Set(["auth", "picker-owner"]);
export function redactTags(tags) {
  return (tags || []).map((t) => (Array.isArray(t) && REDACT_TAGS.has(t[0]) ? [t[0], "‹redacted›"] : t));
}
export const KIND_LABELS = {
  0: "profile", 5: "deletion", 7: "reaction", 9: "chat message", 9000: "add member", 9001: "remove member",
  9002: "edit channel metadata", 9005: "delete message", 9007: "create channel", 9008: "delete channel",
  9021: "join channel", 9022: "leave channel", 20001: "presence", 30315: "user status", 40003: "edit message",
  41010: "open DM", 41011: "add to DM", 41012: "hide DM", 24242: "blossom upload auth",
};
export function dryRunPreview(tool, template, { notes = [] } = {}) {
  const t = template || {};
  const tags = redactTags(t.tags);
  const lines = [
    `DRY RUN — ${tool}: nothing was signed or sent.`,
    `would sign: kind ${t.kind}${KIND_LABELS[t.kind] ? ` (${KIND_LABELS[t.kind]})` : ""}`,
    `tags (${tags.length}):`,
    ...tags.map((x) => "  " + escapeContent(JSON.stringify(x), { cap: 300 })),
    `content: ${t.content ? escapeContent(t.content, { cap: 2000 }) : "(empty)"}`,
    ...notes.map((n) => "note: " + n),
  ];
  return lines.join("\n");
}

// ── 4. open-channel directory ───────────────────────────────────────────────────────────────────
// Newest kind:39000 per channel id; OPEN = no ["private"] tag (and no ["hidden"]); DM channels
// (t=dm) are never listed. → [{ id, name, about, at }], newest first.
export function openChannelsFromMeta(evs) {
  const byId = new Map();
  for (const e of evs || []) {
    if (!e || e.kind !== 39000) continue;
    const d = ((e.tags || []).find((t) => t[0] === "d") || [])[1];
    if (!d) continue;
    const prev = byId.get(d);
    if (!prev || (e.created_at || 0) > (prev.created_at || 0)) byId.set(d, e);
  }
  const out = [];
  for (const [id, e] of byId) {
    const tags = e.tags || [];
    if (tags.some((t) => t[0] === "private" || t[0] === "hidden")) continue;
    if (tags.some((t) => t[0] === "t" && t[1] === "dm")) continue;
    const g = (k) => ((tags.find((t) => t[0] === k) || [])[1] || "");
    out.push({ id, name: g("name") || "(unnamed)", about: g("about"), archived: tags.some((t) => t[0] === "archived"), at: e.created_at || 0 });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

// ── 5. files in a channel ───────────────────────────────────────────────────────────────────────
// Every NIP-92 imeta attachment on the given kind:9 events, newest first. → [{ event, index, ...att }]
export function filesFromEvents(evs, { chId } = {}) {
  const out = [];
  for (const e of evs || []) {
    if (!e || e.kind !== 9) continue;
    if (chId && !(e.tags || []).some((t) => t[0] === "h" && t[1] === chId)) continue;
    const atts = ((e.tags || []).filter((t) => Array.isArray(t) && t[0] === "imeta")).map(parseImeta).filter(Boolean);
    atts.forEach((a, i) => out.push({ event: e, index: i, ...a }));
  }
  return out.sort((a, b) => (b.event.created_at || 0) - (a.event.created_at || 0));
}
export function fmtBytes(n) {
  if (!Number.isFinite(n)) return "?";
  return n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : n >= 1024 ? (n / 1024).toFixed(1) + " KB" : n + " B";
}

// ── 6. presence ─────────────────────────────────────────────────────────────────────────────────
// The relay answers a {kinds:[20001], authors} query with events it SYNTHESIZES and signs with its
// NIP-11 `self` key (content = status, ["p", subject]). Only those count: an event by any other key,
// a bad signature, or a p tag for someone we didn't ask about is ignored. No `self` → nothing can be
// verified → the caller reports "unverifiable", never a guessed status.
export const PRESENCE_STATUSES = new Set(["online", "away", "offline"]);
export function presenceFromEvents(evs, relaySelf, verify, wanted) {
  const want = new Set(wanted || []);
  const m = new Map();
  if (!relaySelf) return m;
  for (const e of evs || []) {
    if (!e || (e.kind !== 20001 && e.kind !== 40902)) continue;
    if (e.pubkey !== relaySelf) continue;
    // verify a CLONE: nostr-tools caches a verified flag on the object (a mutated copy keeps it).
    if (verify) { let v = false; try { v = !!verify(JSON.parse(JSON.stringify(e))); } catch { v = false; } if (!v) continue; }
    const subj = ((e.tags || []).find((t) => t[0] === "p" && /^[0-9a-f]{64}$/.test(t[1] || "")) || [])[1];
    if (!subj || (want.size && !want.has(subj))) continue;
    const st = String(e.content || "").trim().toLowerCase();
    const status = PRESENCE_STATUSES.has(st) ? st : "unknown";
    const prev = m.get(subj);
    if (!prev || (e.created_at || 0) > prev.at) m.set(subj, { status, at: e.created_at || 0, raw: st });
  }
  return m;
}

// ── 7. custom emoji ─────────────────────────────────────────────────────────────────────────────
// Community palette = union of every member's kind:30030 set (d = "buzz:custom-emoji"), one entry per
// normalized shortcode; newest set wins, equal timestamps → lexicographically smallest URL (mirrors
// desktop customEmoji.ts). URLs are listed as TEXT only — never fetched. Non-http(s) URLs are dropped.
export const CUSTOM_EMOJI_D = "buzz:custom-emoji";
export function normalizeShortcode(raw) {
  const s = String(raw ?? "").trim().replace(/^:+/, "").replace(/:+$/, "").toLowerCase();
  return s.length && s.length <= 64 && /^[a-z0-9_-]+$/.test(s) ? s : null;
}
const okUrl = (u) => { try { const x = new URL(String(u)); return (x.protocol === "https:" || x.protocol === "http:") && !x.username && !x.password; } catch { return false; } };
export function emojiFromTags(tags) {
  const seen = new Set(), out = [];
  for (const t of tags || []) {
    if (!Array.isArray(t) || t[0] !== "emoji" || !t[1] || !t[2]) continue;
    const sc = normalizeShortcode(t[1]);
    if (!sc || seen.has(sc) || !okUrl(t[2]) || String(t[2]).length > 2048) continue;
    seen.add(sc); out.push({ shortcode: sc, url: String(t[2]) });
  }
  return out;
}
export function emojiPalette(evs) {
  const by = new Map();
  for (const e of evs || []) {
    if (!e || e.kind !== 30030) continue;
    if (!(e.tags || []).some((t) => t[0] === "d" && t[1] === CUSTOM_EMOJI_D)) continue;
    for (const { shortcode, url } of emojiFromTags(e.tags)) {
      const w = by.get(shortcode), at = e.created_at || 0;
      if (!w || at > w.at || (at === w.at && url < w.url)) by.set(shortcode, { url, at, pubkey: e.pubkey });
    }
  }
  return [...by].map(([shortcode, v]) => ({ shortcode, url: v.url, pubkey: v.pubkey })).sort((a, b) => a.shortcode.localeCompare(b.shortcode));
}
