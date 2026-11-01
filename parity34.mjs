// parity34.mjs — v0.2.34 Slack-parity batch 3 (canvases, reminders, workflows): PURE logic (no I/O,
// no keys), unit-tested in parity34.test.mjs. The shim (buzz-mcp.mjs) wires these into tools. Every
// function fails CLOSED on malformed input and treats relay / other-author data as untrusted.
import { randomBytes } from "node:crypto";
import { escapeContent } from "./safety.mjs";

const HEX64 = /^[0-9a-f]{64}$/;
const tagVals = (e, n) => ((e && Array.isArray(e.tags)) ? e.tags : []).filter((t) => Array.isArray(t) && t[0] === n).map((t) => t[1]);
const oneTag = (e, n) => { const v = tagVals(e, n); return v.length === 1 && typeof v[0] === "string" && v[0] !== "" ? v[0] : null; };

/** Head of a set of events: highest created_at; ties → the lexicographically LOWEST id (NIP-01 replaceable rule). */
export function pickHead(events, pred = () => true) {
  let head = null;
  for (const e of events || []) {
    if (!e || typeof e.id !== "string" || !Number.isInteger(e.created_at) || !pred(e)) continue;
    if (!head || e.created_at > head.created_at || (e.created_at === head.created_at && e.id < head.id)) head = e;
  }
  return head;
}

// Render multi-line untrusted text (canvas markdown, workflow YAML) as a fenced block: EVERY line is
// escaped (control / bidi / invisible chars → \u{..}) and prefixed with "│ ", so content can never
// forge a line of the shim's own output. Capped by lines and by total characters.
export function renderUntrustedBlock(text, { maxLines = 2000, maxChars = 200_000, lineCap = 2000 } = {}) {
  const lines = String(text ?? "").split(/\r\n|\r|\n/);
  const out = [];
  let chars = 0, shown = 0;
  for (const l of lines) {
    if (shown >= maxLines || chars >= maxChars) break;
    const esc = escapeContent(l, { cap: lineCap });
    out.push("│ " + esc);
    chars += esc.length; shown++;
  }
  if (shown < lines.length) out.push(`│ …[+${lines.length - shown} more line(s) not shown]`);
  return out.join("\n");
}

// ───────────────────────── Canvas (kind 40100) ─────────────────────────
// One canvas per channel: a REGULAR event with one h tag; the newest one is the canvas (desktop
// get_canvas: {kinds:[40100], "#h":[ch], limit:1}). The relay has NO compare-and-swap.
export const CANVAS_KIND = 40100;
// The relay's general content cap is 256 KB; we stay at half of it so a canvas plus tags is never
// near the edge (the relay is the authority — this is a client-side ceiling).
export const CANVAS_MAX_BYTES = 131_072;

export const isCanvasFor = (channelId) => (e) => e && e.kind === CANVAS_KIND && tagVals(e, "h").length === 1 && oneTag(e, "h") === channelId;
export const canvasHead = (events, channelId) => pickHead(events, isCanvasFor(channelId));

/** Validate new canvas markdown. Empty content only with clear:true (it blanks the canvas for everyone). */
export function checkCanvasContent(content, { clear = false } = {}) {
  if (typeof content !== "string") throw new Error("`content` (the canvas markdown) is required");
  if (content === "" && !clear) throw new Error("empty `content` would blank the canvas for everyone — pass clear: true if that's intended");
  if (content !== "" && clear) throw new Error("clear: true goes with empty content");
  if (content.includes("\u0000")) throw new Error("canvas content can't contain NUL characters");
  const n = Buffer.byteLength(content, "utf8");
  if (n > CANVAS_MAX_BYTES) throw new Error(`canvas content is ${n} bytes — the limit is ${CANVAS_MAX_BYTES} (128 KB)`);
  return content;
}

/** `expected_head`: the full 64-hex event id buzz_canvas_read showed, or "none" for a channel with no canvas yet. */
export function parseExpectedHead(v) {
  const s = String(v ?? "").trim().toLowerCase();
  if (s === "none") return null;
  if (HEX64.test(s)) return s;
  throw new Error("`expected_head` must be the full head id from buzz_canvas_read (64 hex), or \"none\" when the channel has no canvas yet — read the canvas first");
}

/** Read-before-write head check. → { ok: true } | { ok: false, reason }. NOT a CAS: see buzz-mcp.mjs TODO(buzz_dx). */
export function canvasHeadCheck(expectedId, head) {
  const cur = head ? head.id : null;
  if (expectedId === cur) return { ok: true };
  if (expectedId === null) return { ok: false, reason: `a canvas now exists (head <${cur.slice(0, 12)}>) but you expected none` };
  if (cur === null) return { ok: false, reason: `the canvas you read (<${expectedId.slice(0, 12)}>) is no longer visible — no canvas head found` };
  return { ok: false, reason: `the canvas changed since your read: head is now <${cur.slice(0, 12)}>, you read <${expectedId.slice(0, 12)}>` };
}

// ───────────────────────── Reminders (kind 30300, NIP-ER) ─────────────────────────
// Addressable, author-only, content NIP-44 v2 encrypted to self. Plaintext shape matches the Buzz
// desktop/mobile clients (reminderTypes.ts): {target?:{eventId,channelId,preview,authorPubkey}, note?, status}.
export const REMINDER_KIND = 30300;
export const REMINDER_ALT = "Encrypted reminder";
export const REMINDER_MAX_AHEAD = 31_536_000;   // relay default SPROUT_MAX_NOT_BEFORE_DELTA (1 year)
export const REMINDER_NOTE_MAX = 1000;
export const REMINDER_PREVIEW_MAX = 200;
export const REMINDER_STATUSES = new Set(["pending", "done", "cancelled"]);
const MAX_SAFE = 9_007_199_254_740_991;

/** ≥128-bit random d (NIP-ER MUST): 16 bytes → 32 lowercase hex. */
export const newReminderD = (rnd = randomBytes) => Buffer.from(rnd(16)).toString("hex");

/** Strict NIP-ER not_before: ASCII digits, no leading zero (except "0"), ≤ 2^53-1. → number | undefined. */
export function parseNotBefore(raw) {
  if (typeof raw !== "string" || !/^(0|[1-9][0-9]*)$/.test(raw) || raw.length > 16) return undefined;
  const v = Number(raw);
  return v <= MAX_SAFE ? v : undefined;
}

/**
 * When a reminder is due. Accepts: a duration from now ("30m", "in 2h", "1d", "1w"), epoch seconds,
 * or an ISO datetime WITH a zone (…Z / …-07:00). A zone-less time is refused (ambiguous). Must be in
 * the future and within the relay's 1-year horizon.
 */
export function parseDue(input, { now = Math.floor(Date.now() / 1000) } = {}) {
  let t = null;
  if (typeof input === "number") {
    if (!Number.isInteger(input) || input < 0) throw new Error("`when` as a number must be whole epoch seconds");
    t = input;
  } else {
    const s = String(input ?? "").trim();
    if (!s) throw new Error("`when` is required (e.g. \"30m\", \"in 2h\", \"1d\", or an ISO time with a zone)");
    const rel = /^(?:in\s+)?(\d{1,6})\s*(m|min|mins|minutes?|h|hrs?|hours?|d|days?|w|weeks?)$/i.exec(s);
    if (rel) {
      const u = rel[2].toLowerCase()[0];
      t = now + Number(rel[1]) * { m: 60, h: 3600, d: 86400, w: 604800 }[u];
    } else if (/^\d{9,10}$/.test(s)) t = Number(s);
    else if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})$/i.test(s)) {
      const ms = Date.parse(s);
      if (Number.isFinite(ms)) t = Math.floor(ms / 1000);
    }
    if (t == null) throw new Error(`can't read \`when\` ${escapeContent(s, { cap: 40 })} — use a duration like 30m / 2h / 1d / 1w, epoch seconds, or an ISO datetime with a zone (…Z or …-07:00)`);
  }
  if (t <= now) throw new Error("`when` must be in the future");
  if (t - now > REMINDER_MAX_AHEAD) throw new Error("`when` is more than a year out — the relay rejects reminders beyond its 1-year horizon");
  return t;
}

const isStr = (v) => typeof v === "string";
/** Build pending/terminal plaintext. A reminder needs a target or a non-empty note (both parsers reject otherwise). */
export function reminderPlaintext({ target, note, status = "pending" } = {}) {
  if (!REMINDER_STATUSES.has(status)) throw new Error(`bad reminder status ${status}`);
  const hasNote = isStr(note) && note.length > 0;
  if (note != null && !isStr(note)) throw new Error("`note` must be text");
  if (hasNote && [...note].length > REMINDER_NOTE_MAX) throw new Error(`\`note\` is over ${REMINDER_NOTE_MAX} characters`);
  if (hasNote && /[\u0000-\u0008\u000b-\u001f\u007f]/.test(note)) throw new Error("`note` can't contain control characters");
  let t;
  if (target != null) {
    if (!HEX64.test(target.eventId || "") || !isStr(target.channelId) || !target.channelId || !HEX64.test(target.authorPubkey || ""))
      throw new Error("reminder target must be a real message (64-hex id, channel, 64-hex author)");
    const preview = [...String(target.preview ?? "")].slice(0, REMINDER_PREVIEW_MAX).join("");
    // id duplicates eventId for NIP-ER readers (target.id); the Buzz apps read eventId and ignore extras.
    t = { eventId: target.eventId, channelId: target.channelId, preview, authorPubkey: target.authorPubkey, id: target.eventId };
  }
  if (!t && !hasNote) throw new Error("a reminder needs a message (`channel` + `event`) or a non-empty `note`");
  // absent ≠ null: omit keys instead of writing null (desktop drops {"target": null} entirely).
  return JSON.stringify({ ...(t ? { target: t } : {}), ...(hasNote ? { note } : {}), status });
}

/** Mirror of the desktop's strict parseReminderContent (+ NIP-ER target.id check when present). → content | null. */
export function parseReminderContent(plaintext) {
  let o;
  try { o = JSON.parse(plaintext); } catch { return null; }
  if (!o || typeof o !== "object" || Array.isArray(o)) return null;
  if (!REMINDER_STATUSES.has(o.status)) return null;
  if (o.note !== undefined && !isStr(o.note)) return null;
  let target;
  if (o.target !== undefined) {
    const x = o.target;
    if (!x || typeof x !== "object" || Array.isArray(x)) return null;
    if (![x.eventId, x.channelId, x.preview, x.authorPubkey].every(isStr)) return null;
    if (x.id !== undefined && !(isStr(x.id) && HEX64.test(x.id))) return null;
    target = { eventId: x.eventId, channelId: x.channelId, preview: x.preview, authorPubkey: x.authorPubkey };
  }
  if (!target && !(isStr(o.note) && o.note.length > 0)) return null;
  return { status: o.status, ...(target ? { target } : {}), ...(o.note !== undefined ? { note: o.note } : {}) };
}

/** Tags: pending → d + not_before + alt; done/cancelled → d + alt + expiration (jittered 30–90 days), NO not_before. */
export function reminderTags({ d, status, notBefore, now = Math.floor(Date.now() / 1000), rand = Math.random } = {}) {
  if (!/^[0-9a-f]{32,64}$/.test(String(d || ""))) throw new Error("reminder d must be ≥128-bit hex");
  if (status === "pending") {
    if (!Number.isInteger(notBefore) || notBefore < 0 || notBefore > MAX_SAFE) throw new Error("pending reminder needs a valid not_before");
    return [["d", d], ["not_before", String(notBefore)], ["alt", REMINDER_ALT]];
  }
  if (status !== "done" && status !== "cancelled") throw new Error(`bad reminder status ${status}`);
  const days = 30 + Math.floor(Math.min(Math.max(rand(), 0), 0.999999) * 60);
  return [["d", d], ["alt", REMINDER_ALT], ["expiration", String(now + days * 86400)]];
}

/**
 * Decode own reminders. Only OWN events with a valid signature (verify) are used; signature is checked
 * BEFORE decrypting (NIP-ER). Head per d (highest created_at, tie lowest id). Undecryptable / malformed
 * heads, a pending head without a valid not_before, and expired heads are skipped (counted).
 * → { reminders: [{ d, status, notBefore, due, content, created_at, id }], skipped, forged }
 */
export function decodeReminders(events, { me, decrypt, verify, now = Math.floor(Date.now() / 1000) }) {
  const byD = new Map();
  let forged = 0;
  for (const e of events || []) {
    if (!e || e.kind !== REMINDER_KIND || e.pubkey !== me) continue;
    if (!verify(e)) { forged++; continue; }   // verify BEFORE head selection and decryption
    const d = oneTag(e, "d");
    if (!d) continue;
    const prev = byD.get(d);
    if (!prev || e.created_at > prev.created_at || (e.created_at === prev.created_at && e.id < prev.id)) byD.set(d, e);
  }
  const out = [];
  let skipped = 0;
  for (const [d, e] of byD) {
    const nbs = tagVals(e, "not_before");
    if (nbs.length > 1) { skipped++; continue; }
    const nb = nbs.length ? parseNotBefore(nbs[0]) : undefined;
    if (nbs.length && nb === undefined) { skipped++; continue; }
    const exp = tagVals(e, "expiration");
    if (exp.length === 1 && /^\d{1,16}$/.test(String(exp[0])) && Number(exp[0]) <= now) { skipped++; continue; }
    let content = null;
    try { content = parseReminderContent(decrypt(e.content)); } catch { content = null; }
    if (!content) { skipped++; continue; }
    if (content.status === "pending" && nb === undefined) { skipped++; continue; }
    out.push({ d, status: content.status, notBefore: content.status === "pending" ? nb : undefined, due: content.status === "pending" && nb <= now, content, created_at: e.created_at, id: e.id });
  }
  out.sort((a, b) => (a.status === "pending") !== (b.status === "pending") ? (a.status === "pending" ? -1 : 1)
    : a.status === "pending" ? a.notBefore - b.notBefore : b.created_at - a.created_at);
  return { reminders: out, skipped, forged };
}

/** Find a reminder by its full d or a unique prefix (≥ 8 hex). Fails closed on ambiguity. */
export function findReminder(list, ref) {
  const s = String(ref ?? "").trim().toLowerCase();
  if (!/^[0-9a-f]{8,64}$/.test(s)) throw new Error("`reminder` must be the reminder id from buzz_reminders (≥ 8 hex)");
  const hits = list.filter((r) => r.d === s || r.d.startsWith(s));
  if (!hits.length) throw new Error(`no reminder ${s.slice(0, 12)}… of yours — see buzz_reminders`);
  if (hits.length > 1) throw new Error(`${hits.length} reminders start with ${s} — give more of the id`);
  return hits[0];
}

// ───────────────────────── Workflows (def 30620, trigger 46020) ─────────────────────────
export const WORKFLOW_DEF_KIND = 30620;
export const WORKFLOW_TRIGGER_KIND = 46020;
export const WORKFLOW_YAML_SHOW_MAX = 65_536;
export const WORKFLOW_INPUTS_MAX_KEYS = 32;
export const WORKFLOW_INPUT_VALUE_MAX = 4096;
export const WORKFLOW_INPUTS_MAX_BYTES = 16_384;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isUuid = (s) => UUID_RE.test(String(s || ""));
export const TRIGGER_TYPES = ["message_posted", "reaction_added", "diff_posted", "schedule", "webhook"];
export const ACTION_TYPES = ["send_message", "send_dm", "set_channel_topic", "add_reaction", "call_webhook", "request_approval", "delay"];

/** Workflow definitions in a channel: kind 30620 with one h = channel and a UUID d; newest per (author, d). */
export function workflowDefs(events, channelId) {
  const m = new Map();
  for (const e of events || []) {
    if (!e || e.kind !== WORKFLOW_DEF_KIND || tagVals(e, "h").length !== 1 || oneTag(e, "h") !== channelId) continue;
    const d = oneTag(e, "d");
    if (!d || !isUuid(d)) continue;
    const k = `${e.pubkey}:${d.toLowerCase()}`;
    const p = m.get(k);
    if (!p || e.created_at > p.created_at || (e.created_at === p.created_at && e.id < p.id)) m.set(k, e);
  }
  return [...m.values()].sort((a, b) => b.created_at - a.created_at);
}

const unq = (s) => { const t = String(s).trim(); return (/^"(.*)"$/.test(t) || /^'(.*)'$/.test(t)) ? t.slice(1, -1) : t; };
/**
 * Regex summary of a workflow's YAML (no YAML parser is bundled; the relay is the authority on
 * validity). Only top-level scalars and the known enum words are extracted. Every string returned is
 * still UNTRUSTED — callers escape it. → { name, description, trigger, steps, actions, approval, webhook, enabled }
 */
export function summarizeWorkflowYaml(yaml, tagName = null) {
  const y = String(yaml ?? "").slice(0, 262_144);
  const top = (k) => { const m = new RegExp(`^${k}:[ \\t]*(.+?)[ \\t]*$`, "m").exec(y); return m ? unq(m[1]) : null; };
  const name = top("name") || (tagName ? String(tagName) : null);
  const description = top("description");
  let trigger = null;
  const tm = /\bon:[ \t]*["']?([a-z_]+)["']?/.exec(y.slice(Math.max(0, y.search(/^trigger:/m))));
  if (tm && TRIGGER_TYPES.includes(tm[1])) trigger = tm[1];
  const actions = [];
  for (const m of y.matchAll(/\baction:[ \t]*["']?([a-z_]+)["']?/g)) if (!actions.includes(m[1])) actions.push(m[1]);
  const steps = (y.match(/^[ \t]*-[ \t]+id:/gm) || []).length;
  const en = /^enabled:[ \t]*(true|false)\b/m.exec(y);
  return {
    name, description, trigger, steps, actions,
    unknownActions: actions.filter((x) => !ACTION_TYPES.includes(x)),
    approval: actions.includes("request_approval"),
    webhook: actions.includes("call_webhook"),
    enabled: en ? en[1] === "true" : true,   // schema default_true
  };
}

/** Resolve a workflow by its UUID (d) or its exact name (case-insensitive). Ambiguity fails closed. */
export function resolveWorkflow(defs, ref) {
  const s = String(ref ?? "").trim();
  if (!s) throw new Error("`workflow` (its id or exact name, from buzz_workflows) is required");
  if (isUuid(s)) {
    const hits = defs.filter((e) => oneTag(e, "d").toLowerCase() === s.toLowerCase());
    if (!hits.length) throw new Error(`no workflow ${s} in this channel — see buzz_workflows`);
    if (hits.length > 1) throw new Error(`workflow id ${s} has definitions from ${hits.length} different authors — refusing to guess`);
    return hits[0];
  }
  const want = s.normalize("NFC").toLowerCase();
  const hits = defs.filter((e) => { const n = summarizeWorkflowYaml(e.content, oneTag(e, "name")).name; return n && n.normalize("NFC").toLowerCase() === want; });
  if (!hits.length) throw new Error(`no workflow named ${escapeContent(s, { cap: 80 })} in this channel — see buzz_workflows`);
  if (hits.length > 1) throw new Error(`${hits.length} workflows are named ${escapeContent(s, { cap: 80 })} — pass the id instead (${hits.map((e) => oneTag(e, "d")).join(", ")})`);
  return hits[0];
}
export const workflowId = (e) => oneTag(e, "d");

/** Trigger inputs → event content ("" when none, like the SDK). Flat object of string / number / boolean. */
export function workflowTriggerContent(inputs) {
  if (inputs == null) return "";
  if (typeof inputs !== "object" || Array.isArray(inputs)) throw new Error("`inputs` must be an object of name → value");
  const keys = Object.keys(inputs);
  if (!keys.length) return "";
  if (keys.length > WORKFLOW_INPUTS_MAX_KEYS) throw new Error(`at most ${WORKFLOW_INPUTS_MAX_KEYS} inputs`);
  const out = {};
  for (const k of keys) {
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(k)) throw new Error(`bad input name ${escapeContent(k, { cap: 70 })} (letters, digits, _; ≤ 64)`);
    const v = inputs[k];
    if (typeof v === "string") {
      if ([...v].length > WORKFLOW_INPUT_VALUE_MAX) throw new Error(`input ${k} is over ${WORKFLOW_INPUT_VALUE_MAX} characters`);
      if (v.includes("\u0000")) throw new Error(`input ${k} contains a NUL character`);
    } else if (!(typeof v === "boolean" || (typeof v === "number" && Number.isFinite(v)))) throw new Error(`input ${k} must be text, a number or true/false`);
    out[k] = v;
  }
  const s = JSON.stringify(out);
  if (Buffer.byteLength(s, "utf8") > WORKFLOW_INPUTS_MAX_BYTES) throw new Error(`inputs are over ${WORKFLOW_INPUTS_MAX_BYTES} bytes`);
  return s;
}
export const workflowTriggerTags = (id) => { if (!isUuid(id)) throw new Error("bad workflow id"); return [["d", id.toLowerCase()]]; };
