// names.mjs — pure, dependency-free identity/name guards shared by buzz-mcp.mjs (v0.2.30).
//
//   * invisible / bidi character classes (Unicode properties, no literal invisibles in source)
//   * foldName(): NFKC + case-fold + invisible-strip + whitespace-collapse
//   * skeleton(): Unicode TR39 §4 skeleton over the vendored confusables table (confusables.mjs)
//   * matchProfiles(): fail-closed name → pubkey resolution with exact-first ranking
//   * emailError(): refuse non-ASCII / invisible / NFKC-unstable email input
//   * archivedFromEvents(): NIP-IA kind:13535 archived-identity list, relay-self-signed only
//   * isPubkeyHex() / assertPTags(): strict 64-lowercase-hex p-tag guard
//
// Everything here is synchronous and side-effect free so names.test.mjs can unit-test it.
import { CONFUSABLES } from "./confusables.mjs";

// Case-only mismatch policy. A single hit whose name differs from the input ONLY by case
// ("anirban das" vs "Anirban Das") is, by default, treated like any other non-exact hit:
// ambiguous / lookalike → refused, use an npub. Flip to false to accept a case-only match.
export const CASE_ONLY_IS_AMBIGUOUS = true;

// ---- invisible / direction-manipulating characters ----
// Bidi_Control: ALM U+061C, LRM U+200E, RLM U+200F, U+202A–202E, U+2066–2069.
// Default_Ignorable_Code_Point: soft hyphen U+00AD, CGJ U+034F, U+115F/1160 & U+3164/FFA0 Hangul
// fillers, U+17B4/17B5, U+180B–180F, ZWSP/ZWNJ/ZWJ U+200B–200D, U+2060–206F, variation selectors
// U+FE00–FE0F & U+E0100–E01EF, BOM/ZWNBSP U+FEFF, tag characters U+E0000–E0FFF, …
// U+00AD is DICP already; listed explicitly so the intent survives a property-table change.
export const NAME_INVIS = /[\p{Bidi_Control}\p{Default_Ignorable_Code_Point}\u00AD]/u;
export const NAME_INVIS_G = new RegExp(NAME_INVIS.source, "gu");
export const BIDI_CONTROL = /\p{Bidi_Control}/u;
export const VARIATION_SELECTOR_G = /[\uFE00-\uFE0F\u{E0100}-\u{E01EF}]/gu;
// What a channel NAME may not contain: every Bidi_Control and every default-ignorable EXCEPT
// variation selectors (those are stripped by canonicalizeChannelName so "Pulse ❤️" still works).
export const CHANNEL_NAME_FORBIDDEN = /(?![\uFE00-\uFE0F\u{E0100}-\u{E01EF}])[\p{Bidi_Control}\p{Default_Ignorable_Code_Point}\u00AD]/u;

export const stripInvisible = (s) => String(s ?? "").replace(NAME_INVIS_G, "");
export const stripVariationSelectors = (s) => String(s ?? "").replace(VARIATION_SELECTOR_G, "");

// Simple full case fold. JS has no String#casefold; upper→lower folds ß→ss, ﬁ→fi (after NFKC),
// Kelvin K→k etc. Final sigma is normalized explicitly because toLowerCase applies the
// context-sensitive final-sigma rule.
const caseFold = (s) => s.toUpperCase().toLowerCase().replace(/\u03C2/g, "\u03C3");

/** NFKC + case-fold + invisible-strip + whitespace-collapse + trim. The comparison key for "same name". */
export function foldName(s) {
  let t = stripInvisible(s).normalize("NFKC");
  t = caseFold(t).normalize("NFKC");
  return stripInvisible(t).replace(/\s+/gu, " ").trim();
}

/** Unicode TR39 §4 skeleton(X): NFD → map every code point to its confusables prototype → NFD. */
export function skeleton(s) {
  let out = "";
  for (const ch of String(s ?? "").normalize("NFD")) out += CONFUSABLES.get(ch.codePointAt(0)) ?? ch;
  return out.normalize("NFD");
}

/** Case-insensitive confusability key: fold, skeleton, re-fold until stable (TR39 prototypes
 *  can be uppercase, e.g. "0" → "O", so a single pass would keep "B0B" ≠ "bob"). */
export function nameKey(s) {
  let k = foldName(s);
  for (let i = 0; i < 4; i++) {
    const n = foldName(skeleton(k));
    if (n === k) break;
    k = n;
  }
  return k;
}
/** Second key: skeleton BEFORE case-folding, so case-sensitive prototypes still collide
 *  ("I" (capital i) and "l" share prototype "l"; folding first would turn "I" into "i"). */
export function nameKeyCased(s) {
  return foldName(skeleton(stripInvisible(s).normalize("NFKC")));
}
/** Are two names confusable (NFKC / case-fold / TR39 skeleton collision)? */
export const confusableNames = (a, b) => {
  const ka = nameKey(a);
  return !!ka && (ka === nameKey(b) || nameKeyCased(a) === nameKeyCased(b));
};

/** The "raw" compare for fail-closed: NFC + trim (+ lowercase when case-only differences are allowed). */
export function rawKey(s, { caseOnlyIsAmbiguous = CASE_ONLY_IS_AMBIGUOUS } = {}) {
  const t = String(s ?? "").normalize("NFC").trim();
  return caseOnlyIsAmbiguous ? t : t.toLowerCase();
}

export const isPubkeyHex = (pk) => typeof pk === "string" && /^[0-9a-f]{64}$/.test(pk);
/** Throw if any p-tag in `tags` is not a strict 64-lowercase-hex pubkey. Call right before signing. */
export function assertPTags(tags) {
  for (const t of tags || []) {
    if (Array.isArray(t) && t[0] === "p" && !isPubkeyHex(t[1]))
      throw new Error(`refusing to sign: p-tag pubkey ${JSON.stringify(String(t[1]).slice(0, 80))} is not 64 lowercase hex`);
  }
  return tags;
}

/**
 * Resolve `query` against candidate profiles [{pubkey, name, display_name, …}] — FAIL CLOSED.
 * Only `name` / `display_name` are ever matched; a candidate a search engine returned because of
 * its bio / about / nip05 / any other field never resolves. Candidates are ranked:
 *   tier 0  exact: rawKey(field) === rawKey(query)            (NFC+trim; + lowercase if case-only allowed)
 *   tier 1  case-only: same NFC+trim ignoring case            (only when CASE_ONLY_IS_AMBIGUOUS)
 *   tier 2  lookalike: nameKey / nameKeyCased equal           (NFKC/case-fold/TR39 skeleton collision)
 * Returns { pubkey } on exactly one distinct pubkey at tier 0. Throws:
 *   >1 distinct matching pubkeys (any tier)  → ambiguous
 *   1 pubkey, best tier 1                    → case-only ambiguous
 *   1 pubkey, best tier 2                    → ambiguous / lookalike
 * Returns { pubkey: null, archived, otherFieldOnly } when nothing matched by name.
 */
export function matchProfiles(query, profiles, { caseOnlyIsAmbiguous = CASE_ONLY_IS_AMBIGUOUS, archived = new Set() } = {}) {
  const q = String(query ?? "");
  const want = nameKey(q), wantCased = nameKeyCased(q);
  if (!want) return { pubkey: null, archived: 0, otherFieldOnly: 0, ranked: [] };
  const wantRaw = rawKey(q, { caseOnlyIsAmbiguous });
  const wantCase = rawKey(q, { caseOnlyIsAmbiguous: false });
  const best = new Map();   // pubkey → { tier, label }
  let archivedHits = 0, otherFieldOnly = 0;
  for (const p of profiles || []) {
    if (!p || !isPubkeyHex(p.pubkey)) continue;
    let tier = null, label = "";
    for (const f of [p.name, p.display_name]) {
      if (typeof f !== "string" || !f.trim()) continue;
      let t = null;
      if (rawKey(f, { caseOnlyIsAmbiguous }) === wantRaw) t = 0;
      else if (rawKey(f, { caseOnlyIsAmbiguous: false }) === wantCase) t = 1;
      else if (nameKey(f) === want || nameKeyCased(f) === wantCased) t = 2;
      if (t !== null && (tier === null || t < tier)) { tier = t; label = f; }
    }
    if (tier === null) { otherFieldOnly++; continue; }
    if (archived.has(p.pubkey)) { archivedHits++; continue; }
    const prev = best.get(p.pubkey);
    if (!prev || tier < prev.tier) best.set(p.pubkey, { tier, label });
  }
  const ranked = [...best.entries()].map(([pubkey, v]) => ({ pubkey, ...v })).sort((a, b) => a.tier - b.tier);
  const shown = (r) => `${JSON.stringify(r.label)} ${r.pubkey.slice(0, 8)}…${r.tier === 0 ? "" : r.tier === 1 ? " (case differs)" : " (lookalike)"}`;
  if (ranked.length > 1)
    throw new Error(`"${q}" is ambiguous (${ranked.length} people match: ${ranked.slice(0, 5).map(shown).join(", ")}) — use an npub`);
  if (ranked.length === 1) {
    const r = ranked[0];
    if (r.tier === 0) return { pubkey: r.pubkey, archived: archivedHits, otherFieldOnly, ranked };
    if (r.tier === 1)
      throw new Error(`"${q}" is ambiguous / lookalike - use an npub (the only match, ${shown(r)}, differs in letter case)`);
    throw new Error(`"${q}" is ambiguous / lookalike - use an npub (the only match, ${shown(r)}, is not the same text)`);
  }
  return { pubkey: null, archived: archivedHits, otherFieldOnly, ranked };
}

/** Does this token look like an email (incl. fullwidth ＠ / small ﹫ that NFKC turns into "@")? */
export const looksLikeEmail = (s) => String(s ?? "").normalize("NFKC").includes("@");
/** null if `s` is a plain printable-ASCII email token; otherwise why it is refused. */
export function emailError(s) {
  const e = String(s ?? "");
  if (NAME_INVIS.test(e)) return `email "${stripInvisible(e)}" contains invisible or bidirectional characters — refused`;
  if (/[^\x21-\x7e]/.test(e)) return `email contains non-ASCII or whitespace characters (possible homoglyph) — refused; type it in plain ASCII or use an npub`;
  if (e.normalize("NFKC") !== e) return `email changes under NFKC normalization — refused`;
  if (!/^[^@]+@[^@]+$/.test(e)) return `"${e}" is not a single-@ email address`;
  return null;
}

/**
 * NIP-IA: archived identities = the `p` tags of the newest kind:13535 event signed by the relay's
 * NIP-11 `self` key that carries exactly one ["-"] tag. Events by any other key are ignored (they
 * are not authoritative). `verify` is nostr-tools verifyEvent (injected to keep this module dep-free).
 * Returns { set, eventId } — an empty set when there is no valid list (fail open).
 */
export function archivedFromEvents(events, selfPk, verify) {
  if (!isPubkeyHex(selfPk)) return { set: new Set(), eventId: null };
  const valid = (events || []).filter((e) => e && e.kind === 13535 && e.pubkey === selfPk
    && (e.tags || []).filter((t) => Array.isArray(t) && t[0] === "-").length === 1
    && (() => { try { return verify(e) === true; } catch { return false; } })());
  valid.sort((a, b) => (b.created_at - a.created_at) || String(a.id).localeCompare(String(b.id)));
  const latest = valid[0];
  if (!latest) return { set: new Set(), eventId: null };
  const set = new Set();
  for (const t of latest.tags) if (t[0] === "p" && isPubkeyHex(t[1])) set.add(t[1]);
  return { set, eventId: latest.id };
}
