// names.test.mjs — unit tests for names.mjs (v0.2.30): invisible classes, NFKC+case-fold,
// TR39 skeleton (against the spec's own examples), fail-closed matchProfiles under BOTH
// CASE_ONLY_IS_AMBIGUOUS settings, emailError, NIP-IA archivedFromEvents, and the p-tag guard.
import {
  CASE_ONLY_IS_AMBIGUOUS, NAME_INVIS, BIDI_CONTROL, CHANNEL_NAME_FORBIDDEN, stripInvisible, stripVariationSelectors,
  foldName, skeleton, nameKey, confusableNames, matchProfiles, looksLikeEmail, emailError,
  archivedFromEvents, isPubkeyHex, assertPTags, mentionAliases, mentionTokens, matchMention, resolveMentions, matchChannel,
} from "./names.mjs";
import { CONFUSABLES, CONFUSABLES_UNICODE_VERSION, CONFUSABLES_SOURCE_SHA256 } from "./confusables.mjs";
import { finalizeEvent, getPublicKey, verifyEvent } from "nostr-tools/pure";
import { readFileSync } from "node:fs";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.log("  ✗ " + m)));
const throws = (fn, re, m) => { try { fn(); ok(false, m + " (did not throw)"); } catch (e) { ok(re.test(e.message), m + (re.test(e.message) ? "" : ` (got: ${e.message})`)); } };
const cp = (...xs) => String.fromCodePoint(...xs);

console.log("\ninvisible / bidi classes");
for (const [c, n] of [[0x200E, "LRM"], [0x200F, "RLM"], [0x061C, "ALM"], [0x202A, "LRE"], [0x202B, "RLE"], [0x202C, "PDF"], [0x202D, "LRO"], [0x202E, "RLO"], [0x2066, "LRI"], [0x2067, "RLI"], [0x2068, "FSI"], [0x2069, "PDI"]]) {
  ok(BIDI_CONTROL.test(cp(c)) && NAME_INVIS.test(cp(c)) && CHANNEL_NAME_FORBIDDEN.test(cp(c)), `${n} U+${c.toString(16).toUpperCase()} is Bidi_Control, invisible, forbidden in channel names`);
}
for (const [c, n] of [[0x200B, "ZWSP"], [0x200C, "ZWNJ"], [0x200D, "ZWJ"], [0x2060, "WJ"], [0xFEFF, "BOM"], [0x00AD, "soft hyphen"], [0x034F, "CGJ"], [0x3164, "Hangul filler"]]) {
  ok(NAME_INVIS.test(cp(c)) && CHANNEL_NAME_FORBIDDEN.test(cp(c)), `${n} is invisible and forbidden in channel names`);
}
ok(NAME_INVIS.test("\uFE0F") && !CHANNEL_NAME_FORBIDDEN.test("\uFE0F") && !CHANNEL_NAME_FORBIDDEN.test(cp(0xE0100)), "variation selectors: invisible for names, but NOT forbidden in channel names (stripped instead)");
ok(stripVariationSelectors("Pulse \u2764\uFE0F") === "Pulse \u2764" && !CHANNEL_NAME_FORBIDDEN.test("Pulse 💓"), "'Pulse ❤️' → VS stripped; 'Pulse 💓' passes");
ok(stripInvisible("A\u200Bn\u200Ei\u00ADr\uFEFFban") === "Anirban", "stripInvisible removes ZWSP/LRM/SHY/BOM");
ok(!/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF\u00AD\u061C]/.test(readFileSync(new URL("./names.mjs", import.meta.url), "utf8")) &&
   !/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF\u00AD\u061C]/.test(readFileSync(new URL("./buzz-mcp.mjs", import.meta.url), "utf8")),
   "no LITERAL invisible/bidi characters in names.mjs or buzz-mcp.mjs source (escapes / properties only)");

console.log("\nfoldName (NFKC + case fold)");
ok(foldName("Ａｎｉｒｂａｎ  Das") === "anirban das", "fullwidth + double space → 'anirban das'");
ok(foldName("\uFB01nance") === "finance", "ligature ﬁ → fi");
ok(foldName("Stra\u00DFe") === foldName("STRASSE"), "ß folds to ss");
ok(foldName("\u212A") === "k", "Kelvin sign K → k");
ok(foldName("\u039F\u0394\u03A5\u03A3\u03A3\u0395\u03A5\u03A3") === foldName("\u03BF\u03B4\u03C5\u03C3\u03C3\u03B5\u03C5\u03C2"), "Greek final sigma folds with σ");

console.log("\nTR39 skeleton (Unicode UTS #39 §4 examples + common confusables)");
ok(CONFUSABLES.size > 6000 && /^\d+\.\d+\.\d+$/.test(CONFUSABLES_UNICODE_VERSION) && /^[0-9a-f]{64}$/.test(CONFUSABLES_SOURCE_SHA256), `vendored table: ${CONFUSABLES.size} entries, Unicode ${CONFUSABLES_UNICODE_VERSION}, source sha256 recorded`);
ok(skeleton("\u03C1\u237A\u0443\u{1D4C5}\u{1D482}\u05DF") === skeleton("paypal") && skeleton("paypal") === "paypal", "UTS#39 example: skeleton('ρ⍺у𝓅𝒂ן') === skeleton('paypal') === 'paypal'");
ok(skeleton("s\u0441\u043E\u0440\u0435") === skeleton("scope"), "UTS#39 example: Cyrillic 'sсоре' ≍ 'scope'");
ok(skeleton("m") === skeleton("rn"), "'m' ≍ 'rn'");
ok(skeleton("0") === "O", "'0' → prototype 'O'");
ok(skeleton("1") === "l" && skeleton("I") === "l" && skeleton("l") === "l", "'1', 'I', 'l' share prototype 'l'");
ok(skeleton("paypal") !== skeleton("paypa1x"), "distinct strings keep distinct skeletons");
ok(nameKey("B0B") === nameKey("bob") && nameKey("\u0410nirban Das") === nameKey("Anirban Das"), "nameKey: 'B0B' ≍ 'bob', Cyrillic 'Аnirban' ≍ 'Anirban'");
ok(confusableNames("ALlCE", "alice") || confusableNames("AIice", "Alice"), "I/l collide (nameKeyCased)");
ok(!confusableNames("Alice", "Bob"), "unrelated names do not collide");

console.log("\nmatchProfiles — fail closed, exact first, name/display_name only");
const A = "a".repeat(64), B = "b".repeat(64), C = "c".repeat(64);
ok(CASE_ONLY_IS_AMBIGUOUS === true, "CASE_ONLY_IS_AMBIGUOUS defaults to true");
ok(matchProfiles("Anirban Das", [{ pubkey: A, name: "Anirban Das" }]).pubkey === A, "exact name → resolves");
ok(matchProfiles("Anirban D Das", [{ pubkey: A, name: "Anirban Das", display_name: "Anirban D Das" }]).pubkey === A, "exact display_name → resolves");
throws(() => matchProfiles("\u0410nirban Das", [{ pubkey: A, name: "Anirban Das" }]), /ambiguous \/ lookalike - use an npub/, "Cyrillic input vs real name → lookalike refused");
throws(() => matchProfiles("Anirban Das", [{ pubkey: B, name: "\u0410nirban Das" }]), /ambiguous \/ lookalike - use an npub/, "single skeleton-only hit (raw differs in both fields) → refused");
throws(() => matchProfiles("finance", [{ pubkey: B, name: "\uFB01nance" }]), /lookalike/, "ligature NFKC collision → refused");
throws(() => matchProfiles("Anirban Das", [{ pubkey: B, name: "\uFF21nirban Das" }]), /lookalike/, "fullwidth NFKC collision → refused");
throws(() => matchProfiles("Anirban Das", [{ pubkey: A, name: "Anirban Das" }, { pubkey: B, name: "Anirban\u200B Das" }]), /ambiguous \(2 people match/, "exact + zero-width twin → ambiguous (2)");
throws(() => matchProfiles("Sam", [{ pubkey: A, name: "Sam" }, { pubkey: B, name: "sam" }]), /ambiguous \(2 people/, "exact + case twin → still ambiguous (ranking orders, never picks)");
// case-only policy, BOTH settings
throws(() => matchProfiles("anirban das", [{ pubkey: A, name: "Anirban Das" }]), /letter case/, "CASE_ONLY_IS_AMBIGUOUS=true: case-only single hit → refused");
ok(matchProfiles("anirban das", [{ pubkey: A, name: "Anirban Das" }], { caseOnlyIsAmbiguous: false }).pubkey === A, "CASE_ONLY_IS_AMBIGUOUS=false: case-only single hit → resolves");
throws(() => matchProfiles("\u0430nirban das", [{ pubkey: A, name: "Anirban Das" }], { caseOnlyIsAmbiguous: false }), /lookalike/, "CASE_ONLY_IS_AMBIGUOUS=false: a homoglyph is STILL refused");
throws(() => matchProfiles("sam", [{ pubkey: A, name: "Sam" }, { pubkey: B, name: "SAM" }], { caseOnlyIsAmbiguous: false }), /ambiguous \(2/, "CASE_ONLY_IS_AMBIGUOUS=false: two case-variants → ambiguous");
// (B) other fields never match
const bio = matchProfiles("Anirban Das", [{ pubkey: C, name: "Mallory", about: "Anirban Das", nip05: "anirban.das@x" }]);
ok(bio.pubkey === null && bio.otherFieldOnly === 1, "(B) bio/nip05-only hit → no resolution, counted as other-field-only");
ok(matchProfiles("Anirban Das", [{ pubkey: C, name: "Mallory", about: "Anirban Das" }, { pubkey: A, name: "Anirban Das" }]).pubkey === A, "(B) exact + bio-only → the exact one");
ok(matchProfiles("x", [{ pubkey: "AB".repeat(32), name: "x" }]).pubkey === null, "(E) profile with an uppercase pubkey is never a candidate");
// (A) archived
const ar = matchProfiles("Sam Roy", [{ pubkey: A, name: "Sam Roy" }, { pubkey: B, name: "Sam Roy" }], { archived: new Set([B]) });
ok(ar.pubkey === A && ar.archived === 1, "(A) archived twin excluded → the live one resolves");
const ar2 = matchProfiles("Sam Roy", [{ pubkey: B, name: "Sam Roy" }], { archived: new Set([B]) });
ok(ar2.pubkey === null && ar2.archived === 1, "(A) only-archived match → no resolution, archived counted");

console.log("\nemail guard");
ok(emailError("anirban.das@olaelectric.com") === null, "plain ASCII email accepted");
ok(/invisible/.test(emailError("anirban\u200B@x.com")), "zero-width email refused");
ok(/invisible/.test(emailError("anirban@x.com\u200E")), "LRM email refused");
ok(/non-ASCII/.test(emailError("\u0430nirban@x.com")), "Cyrillic homoglyph email refused");
ok(looksLikeEmail("a\uFF20x.com") && !!emailError("a\uFF20x.com"), "fullwidth ＠ is detected as an email (NFKC) and refused");
ok(/single-@/.test(emailError("a@b@c")), "double-@ refused");

console.log("\nNIP-IA archivedFromEvents");
const RSK = Uint8Array.from(Buffer.from("99".repeat(32), "hex")), SELF = getPublicKey(RSK);
const OSK = Uint8Array.from(Buffer.from("98".repeat(32), "hex"));
const mk = (sk, tags, at) => finalizeEvent({ kind: 13535, created_at: at, tags, content: "" }, sk);
ok(archivedFromEvents([mk(RSK, [["-"], ["p", A]], 10)], SELF, verifyEvent).set.has(A), "valid self-signed list → A archived");
ok(archivedFromEvents([mk(OSK, [["-"], ["p", A]], 10)], SELF, verifyEvent).set.size === 0, "list by another key → ignored");
ok(archivedFromEvents([mk(RSK, [["-"], ["-"], ["p", A]], 10)], SELF, verifyEvent).set.size === 0, "two '-' tags → ignored");
ok(archivedFromEvents([mk(RSK, [["p", A]], 10)], SELF, verifyEvent).set.size === 0, "no '-' tag → ignored");
// JSON round-trip = what arrives from the relay (drops nostr-tools' in-memory "verified" cache symbol).
const wire = (e) => JSON.parse(JSON.stringify(e));
ok(archivedFromEvents([wire({ ...mk(RSK, [["-"], ["p", A]], 10), tags: [["-"], ["p", B]] })], SELF, verifyEvent).set.size === 0, "tampered (bad sig, as received over the wire) → ignored");
const nw = archivedFromEvents([mk(RSK, [["-"], ["p", A]], 10), mk(RSK, [["-"], ["p", B]], 20)], SELF, verifyEvent).set;
ok(nw.has(B) && !nw.has(A), "newest valid list wins (un-archive works)");
ok(archivedFromEvents([mk(RSK, [["-"], ["p", A]], 10)], null, verifyEvent).set.size === 0, "no NIP-11 self → empty set (fail open)");

console.log("\np-tag guard (E)");
ok(isPubkeyHex(A) && !isPubkeyHex("AB".repeat(32)) && !isPubkeyHex("ab".repeat(31)) && !isPubkeyHex(A + "\n"), "isPubkeyHex: strict 64 lowercase hex");
throws(() => assertPTags([["h", "x"], ["p", "AB".repeat(32)]]), /refusing to sign: p-tag pubkey/, "uppercase p-tag → refused before signing");
throws(() => assertPTags([["p", "npub1xyz"]]), /not 64 lowercase hex/, "npub in a p-tag → refused");
let threw = false; try { assertPTags([["p", A], ["e", "x"], ["h", "y"]]); assertPTags(undefined); } catch { threw = true; }
ok(!threw, "valid p-tags / no tags → allowed");

console.log("\n@mentions (v0.2.30 fix: fail-closed, same tiers as recipient names)");
{
  const OLD = "7731945f" + "0".repeat(56), REAL = "28ff3202" + "1".repeat(56), P = "d".repeat(64), F = "e".repeat(64), Z = "f".repeat(64);
  // REGRESSION (buzz_security review §3.1): two profiles named buzz_security, the OLD key listed first.
  let r = resolveMentions("ping @buzz_security please", [{ pubkey: OLD, name: "buzz_security" }, { pubkey: REAL, name: "buzz_security" }]);
  ok(r.pubkeys.length === 0 && r.refused.length === 1 && /ambiguous/.test(r.refused[0].reason), "two same-named profiles (old key first) → nobody tagged, reported ambiguous");
  ok(!r.pubkeys.includes(OLD), "the retired 7731945f… key is NEVER tagged for @buzz_security");
  r = resolveMentions("@Buzz_Security", [{ pubkey: OLD, name: "buzz_security" }, { pubkey: REAL, display_name: "Buzz_Security" }]);
  ok(r.pubkeys.length === 0 && r.refused.length === 1, "case variants on two keys → ambiguous, nobody tagged");
  r = resolveMentions("@buzz_security", [{ pubkey: REAL, name: "buzz_security" }]);
  ok(r.pubkeys.length === 1 && r.pubkeys[0] === REAL && !r.refused.length, "single exact profile → tagged");
  r = resolveMentions("@buzz_security", [{ pubkey: OLD, name: "buzz_s\u0435curity" }]);
  ok(r.pubkeys.length === 0 && /lookalike/.test(r.refused[0].reason), "single LOOKALIKE-only profile (Cyrillic е) → refused, not tagged");
  r = resolveMentions("@buzz_security", [{ pubkey: REAL, name: "buzz_security" }, { pubkey: OLD, name: "buzz_s\u0435curity" }]);
  ok(r.pubkeys.length === 0 && /ambiguous/.test(r.refused[0].reason), "exact + lookalike on another key → ambiguous, nobody tagged");
  r = resolveMentions("@paypal", [{ pubkey: OLD, name: "p\u0430ypal" }]);
  ok(r.pubkeys.length === 0 && r.refused.length === 1, "TR39 skeleton lookalike (Cyrillic а in paypal) → refused");
  r = resolveMentions("@buzz_security", [{ pubkey: OLD, name: "buzz_security" }, { pubkey: REAL, name: "buzz_security" }], { archived: new Set([OLD]) });
  ok(r.pubkeys.length === 1 && r.pubkeys[0] === REAL, "archived (NIP-IA) old key excluded → only the live key is tagged");
  r = resolveMentions("@buzz_security", [{ pubkey: OLD, name: "buzz_security" }], { archived: new Set([OLD]) });
  ok(r.pubkeys.length === 0 && /archived/.test(r.refused[0].reason), "only an archived identity matches → nobody tagged, reported");
  r = resolveMentions("@pulse @bharatrouterfalcon @pulse", [{ pubkey: P, display_name: "Pulse \u{1F493}" }, { pubkey: F, name: "bharatrouter\u00B7falcon" }]);
  ok(r.pubkeys.length === 2 && r.pubkeys[0] === P && r.pubkeys[1] === F && !r.refused.length, "derived aliases still work: 'Pulse 💓' → @pulse, 'bharatrouter·falcon' → @bharatrouterfalcon (deduped)");
  r = resolveMentions("@pulse", [{ pubkey: P, name: "Pulse" }, { pubkey: Z, display_name: "Pulse \u{1F493}" }]);
  ok(r.pubkeys.length === 0 && r.refused.length === 1, "an alias collision across two keys → ambiguous, nobody tagged");
  r = resolveMentions("@nobody here", [{ pubkey: P, name: "Pulse" }]);
  ok(r.pubkeys.length === 0 && r.refused.length === 0, "an unknown @token is simply not a mention (no refusal noise)");
  r = resolveMentions("@pulse", [{ pubkey: "AB".repeat(32), name: "Pulse" }, { pubkey: "ab".repeat(20), name: "Pulse" }]);
  ok(r.pubkeys.length === 0, "malformed / uppercase pubkeys are never mention targets");
  r = resolveMentions("@Pulse", [{ pubkey: P, name: "Pulse", about: "x" }, { pubkey: Z, name: "Other", about: "Pulse", nip05: "pulse@x" }]);
  ok(r.pubkeys.length === 1 && r.pubkeys[0] === P, "only name/display_name match (about / nip05 never do)");
  ok(mentionTokens("hi @a-b_ @c, mail x@y.z @a-b").join(",") === "a-b,c,y", "mentionTokens: trailing -/_ trimmed, deduped");
  ok(mentionAliases("Pulse \u{1F493}").join("|") === "Pulse \u{1F493}|Pulse", "mentionAliases('Pulse 💓')");
  const many = Array.from({ length: 25 }, (_, i) => `@u${i}`).join(" ");
  r = resolveMentions(many, [{ pubkey: P, name: "u24" }]);
  ok(r.pubkeys.length === 0 && r.refused.length === 5 && /more than 20/.test(r.refused[0].reason), "more than 20 distinct @mentions → the extra ones are refused, not resolved");
  ok(matchMention("pulse", [{ pubkey: P, name: "Pulse" }]).pubkey === P, "matchMention: case-only is accepted for a typed @token");
}

console.log("\nchannel names (v0.2.30 fix: fail-closed matchChannel)");
{
  const cs = [{ id: "c-gen-1", name: "general" }, { id: "c-gen-2", name: "General" }, { id: "c-eng", name: "eng" }, { id: "c-ops", name: "ops" }, { id: "c-ops", name: "ops" }];
  let msg = ""; try { matchChannel("general", cs); } catch (e) { msg = e.message; }
  ok(/ambiguous/.test(msg) && /c-gen-1/.test(msg) && /c-gen-2/.test(msg), "two channels 'general'/'General' → refused, listing both ids");
  ok(matchChannel("c-gen-2", cs).id === "c-gen-2", "an exact channel id always resolves");
  ok(matchChannel("ENG", cs).id === "c-eng", "a single case-only name still resolves (unchanged behaviour)");
  ok(matchChannel("ops", cs).id === "c-ops", "the same channel id listed twice is not a duplicate");
  ok(matchChannel("missing", cs) === null, "no match → null (caller reports 'not found')");
  throws(() => matchChannel("\u0435ng", cs), /lookalike/, "a single lookalike-only hit (Cyrillic е) → refused");
  throws(() => matchChannel("eng", [...cs, { id: "c-eng2", name: "\u0435ng" }]), /ambiguous.*c-eng2/, "exact + lookalike channel → ambiguous, ids listed");
  throws(() => matchChannel("e\u200Bng", [{ id: "c-eng", name: "eng" }, { id: "x", name: "e\u200Bng" }]), /ambiguous/, "zero-width variant → ambiguous");
}

console.log(`\nnames.test.mjs: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
