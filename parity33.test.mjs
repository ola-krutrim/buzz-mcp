// parity33.test.mjs — `node parity33.test.mjs`
// Unit tests for parity33.mjs (v0.2.33 Slack-parity batch 2 pure logic): NIP-RS read state, profile
// patch/merge, NIP-51 saved list, kind:40008 diff tags. Offline; real NIP-44 (nip44.mjs) for round-trips.
import { getConversationKey, encrypt, decrypt } from "./nip44.mjs";
import { getPublicKey } from "nostr-tools/pure";
import * as P from "./parity33.mjs";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✅ " + m)) : (fail++, console.log("  ❌ " + m)));
const throws = (fn, re, m) => { try { fn(); ok(false, m + " (did not throw)"); } catch (e) { ok(re.test(e.message), m + ` → ${e.message}`); } };
const hex = (b) => Uint8Array.from(Buffer.from(b, "hex"));
const SK = "a1".repeat(32), ME = getPublicKey(hex(SK)), OTHER = "b2".repeat(32);
const ck = getConversationKey(hex(SK), ME);
const enc = (s) => encrypt(s, ck), dec = (s) => decrypt(s, ck);
const id = (c) => c.repeat(64).slice(0, 64);

console.log("\nNIP-RS envelope + identity");
const D = "read-state:" + "0123456789abcdef".repeat(2);
const rsEv = (o = {}) => ({ kind: 30078, pubkey: ME, created_at: 1000, tags: [["d", D], ["t", "read-state"]], content: "", ...o });
ok(P.isReadStateEvent(rsEv()), "exact envelope accepted");
ok(!P.isReadStateEvent(rsEv({ kind: 30079 })), "wrong kind rejected");
ok(!P.isReadStateEvent(rsEv({ tags: [["d", D], ["d", D], ["t", "read-state"]] })), "two d tags rejected");
ok(!P.isReadStateEvent(rsEv({ tags: [["d", D]] })), "missing t rejected");
ok(!P.isReadStateEvent(rsEv({ tags: [["d", D], ["t", "read-state"], ["t", "x"]] })), "two t tags rejected");
ok(!P.isReadStateEvent(rsEv({ tags: [["d", "read-state:ABCDEF0123456789abcdef0123456789"], ["t", "read-state"]] })), "uppercase slot rejected");
ok(!P.isReadStateEvent(rsEv({ tags: [["d", "read-state:abc"], ["t", "read-state"]] })), "short slot rejected");
// stand-in keyed derive (the shim uses HMAC-SHA256 under the self conversation key — signer.mjs)
const fakeDerive = (l) => [...Buffer.from(l + "x".repeat(32))].map((b) => (b % 16).toString(16)).join("").slice(0, 64);
const idt = P.readStateIdentity(fakeDerive);
ok(/^read-state:[0-9a-f]{32}$/.test(idt.d) && /^buzz-mcp-[0-9a-f]{16}$/.test(idt.clientId), "identity: d + client_id shapes");
ok(P.readStateIdentity(fakeDerive).d === idt.d, "identity is deterministic");
throws(() => P.readStateIdentity(() => "zz"), /derivation failed/, "identity: bad derive fails closed");

console.log("\nNIP-RS blob validation");
ok(P.parseReadStateBlob("nope") === null, "non-JSON discarded");
ok(P.parseReadStateBlob(JSON.stringify({ v: 2, client_id: "a", contexts: {} })) === null, "v≠1 discarded");
ok(P.parseReadStateBlob(JSON.stringify({ v: 1, client_id: "", contexts: {} })) === null, "empty client_id discarded");
ok(P.parseReadStateBlob(JSON.stringify({ v: 1, client_id: "x".repeat(65), contexts: {} })) === null, "65-char client_id discarded");
ok(P.parseReadStateBlob(JSON.stringify({ v: 1, client_id: "a", contexts: [] })) === null, "array contexts discarded");
const big = {}; for (let i = 0; i < 10001; i++) big["c" + i] = 1;
ok(P.parseReadStateBlob(JSON.stringify({ v: 1, client_id: "a", contexts: big })) === null, ">10k contexts discarded");
const b1 = P.parseReadStateBlob(JSON.stringify({ v: 1, client_id: "a", contexts: { ok: 5, neg: -1, flt: 1.5, str: "3", huge: 4294967296, ["k".repeat(257)]: 1, max: 4294967295 } }));
ok(b1 && b1.contexts.ok === 5 && b1.contexts.max === 4294967295, "valid entries kept");
ok(b1 && !("neg" in b1.contexts) && !("flt" in b1.contexts) && !("str" in b1.contexts) && !("huge" in b1.contexts) && !(("k".repeat(257)) in b1.contexts), "invalid entries dropped individually");
const pp = P.parseReadStateBlob(JSON.stringify({ v: 1, client_id: "a", contexts: { __proto__: 7 } }));
ok(pp && Object.getPrototypeOf(pp.contexts) === null, "contexts has no prototype (no __proto__ pollution)");

console.log("\nmerge / escape / frontiers");
const m = P.mergeContexts({ a: 1, b: 9 }, { a: 5, c: 2 }, { b: 3, bad: -4 });
ok(m.a === 5 && m.b === 9 && m.c === 2 && !("bad" in m), "max-merge per key; invalid ignored");
ok(P.escapeCtxKey("ov_x") === "esc:ov_x" && P.escapeCtxKey("esc:y") === "esc:esc:y" && P.escapeCtxKey("plain") === "plain", "escape reserved stems");
for (const s of ["ov_x", "esc:y", "esc:esc:z", "plain", "thread:abc"]) ok(P.unescapeCtxKey(P.escapeCtxKey(s)) === s, `escape bijection: ${s}`);
const fr = P.frontiers({ ch1: 10, ov_mute: 99, "esc:ov_raw": 4 });
ok(fr.ch1 === 10 && !("ov_mute" in fr) && fr.ov_raw === 4, "frontiers: overrides dropped, esc: unescaped");

console.log("\ndecodeReadState");
const blob = (cid, ctx) => enc(JSON.stringify({ v: 1, client_id: cid, contexts: ctx }));
const OWN_D = "read-state:" + "a".repeat(32), OTHER_D = "read-state:" + "b".repeat(32);
const evA = { kind: 30078, pubkey: ME, created_at: 100, tags: [["d", OWN_D], ["t", "read-state"]], content: blob("mine", { c1: 50 }) };
const evB = { kind: 30078, pubkey: ME, created_at: 200, tags: [["d", OTHER_D], ["t", "read-state"]], content: blob("phone", { c1: 70, c2: 3 }) };
const evForged = { ...evB, pubkey: OTHER, content: blob("evil", { c1: 9999 }) };
const evJunk = { ...evB, content: "AAAA" };
let r = P.decodeReadState([evA, evB, evForged, evJunk], { me: ME, decrypt: dec, ownD: OWN_D, ownClientId: "mine" });
ok(r.merged.c1 === 70 && r.merged.c2 === 3, "merged across slots (max)");
ok(r.own && r.own.contexts.c1 === 50 && r.ownMaxCreatedAt === 100 && !r.conflict, "own slot found, no conflict");
ok(r.used === 2 && r.skipped === 2, "foreign-author + undecryptable blobs skipped");
r = P.decodeReadState([evA], { me: ME, decrypt: dec, ownD: OWN_D, ownClientId: "someone-else" });
ok(r.conflict && !r.own && r.ownMaxCreatedAt === 100, "client_id conflict at own slot detected");

console.log("\nnextReadStateBlob");
const nx = P.nextReadStateBlob({ clientId: "mine", ownContexts: { c1: 50, keep: 1 }, updates: { c1: 40, c3: 60, ov_raw: 5 }, nowS: 1000, ownMaxCreatedAt: 1500 });
const j = JSON.parse(nx.plaintext);
ok(j.v === 1 && j.client_id === "mine", "blob v=1 + client_id");
ok(j.contexts.c1 === 50 && j.contexts.c3 === 60 && j.contexts.keep === 1 && j.contexts["esc:ov_raw"] === 5, "never regresses; keeps others; escapes ov_ ids");
ok(nx.created_at === 1501, "created_at = max(now, maxFetched+1)");
ok(P.nextReadStateBlob({ clientId: "m", ownContexts: {}, updates: { a: 1 }, nowS: 1000, ownMaxCreatedAt: 10 }).created_at === 1000, "created_at = now when newer");
throws(() => P.nextReadStateBlob({ clientId: "m", updates: { a: -1 }, nowS: 1 }), /out of range/, "negative ts refused");
throws(() => P.nextReadStateBlob({ clientId: "m", updates: { ["x".repeat(300)]: 1 }, nowS: 1 }), /too long/, "long context id refused");
ok(dec(enc(nx.plaintext)) === nx.plaintext, "blob round-trips through NIP-44");

console.log("\nunread counting (hierarchy)");
const C = "chan-1", ROOT = id("1");
const msg = (o) => ({ kind: 9, pubkey: OTHER, created_at: 100, tags: [["h", C]], id: id("9"), ...o });
const evs = [
  msg({ id: id("a"), created_at: 90 }),
  msg({ id: id("b"), created_at: 110, tags: [["h", C], ["p", ME]] }),
  msg({ id: id("c"), created_at: 120, pubkey: ME }),
  msg({ id: id("d"), created_at: 130, tags: [["h", C], ["e", ROOT, "", "root"], ["e", ROOT, "", "reply"]] }),
  msg({ id: id("e"), created_at: 140 }),
  msg({ id: id("f"), created_at: 150, tags: [["h", "other-chan"]] }),
];
let st = P.unreadCounts(evs, { [C]: 100, [`thread:${ROOT}`]: 135, [`msg:${id("e")}`]: 140 }, { me: ME, channelIds: [C], fallbackSince: 0 });
let s = st.get(C);
ok(s.unread === 1 && s.mentions === 1 && !s.noMarker, `only the @mention after the frontier counts (thread + msg frontiers honoured; own msg ignored) → ${JSON.stringify(s)}`);
st = P.unreadCounts(evs, {}, { me: ME, channelIds: [C], fallbackSince: 125 });
s = st.get(C);
ok(s.noMarker && s.unread === 2, `no marker → counted within fallback window → ${JSON.stringify(s)}`);
ok(P.effectiveFrontier({}, { channel: "x" }) === -1, "no frontier → -1 (everything unread)");

console.log("\nprofile patch");
ok(P.validateProfilePatch({}).error, "empty patch refused");
ok(P.validateProfilePatch({ name: "  " }).error, "blank name refused");
ok(P.validateProfilePatch({ name: "x".repeat(65) }).error, "65-char name refused");
ok(P.validateProfilePatch({ name: "a\u202eb" }).error, "bidi in name refused");
ok(P.validateProfilePatch({ name: "a\nb" }).error, "newline in name refused");
ok(P.validateProfilePatch({ name: " Bee " }).patch.name === "Bee", "name trimmed");
ok(P.validateProfilePatch({ about: "line1\nline2" }).patch.about === "line1\nline2", "about keeps newlines");
ok(P.validateProfilePatch({ about: "x".repeat(501) }).error, "501-char about refused");
ok(P.validateProfilePatch({ about: "a\u200bb" }).error, "zero-width in about refused");
ok(P.validateProfilePatch({ picture: "http://x/y.png" }).error, "http picture refused");
ok(P.validateProfilePatch({ picture: "javascript:alert(1)" }).error, "javascript: picture refused");
ok(P.validateProfilePatch({ picture: "https://u:p@x/y.png" }).error, "credentials in picture refused");
ok(P.validateProfilePatch({ picture: "https://x/" + "a".repeat(2050) }).error, "overlong picture refused");
ok(P.validateProfilePatch({ picture: "https://cdn.example/a.png" }).patch.picture === "https://cdn.example/a.png", "https picture ok");
ok(P.validateProfilePatch({ picture: "" }).patch.picture === "", "empty picture = clear");

console.log("\nprofile merge");
const auto = { name: "bee", display_name: "bee", about: "m · h · i · host", model: "m", client_version: "0.2.33" };
let mp = P.mergeProfile({ name: "old", picture: "https://p", about: "hand written", lud16: "x@y", evil: "drop", bot: true }, auto);
ok(mp.picture === "https://p" && mp.lud16 === "x@y" && mp.bot === true && mp.about === "hand written" && mp.name === "bee" && !("evil" in mp), "keeps picture/lud16/bot + user about; refreshes auto; drops unknown");
mp = P.mergeProfile({ about: "old · harness · iface · oldhost" }, auto);
ok(mp.about === auto.about, "auto-shaped about is refreshed");
mp = P.mergeProfile({ picture: "https://p" }, auto, { name: "New", about: "hi", picture: "" });
ok(mp.name === "New" && mp.display_name === "New" && mp.about === "hi" && !("picture" in mp), "patch wins; picture cleared");
ok(P.mergeProfile(null, auto).about === auto.about, "no existing → auto");
ok(P.mergeProfile({ picture: 5 }, auto).picture === undefined, "non-string field ignored");
ok(P.parseProfileContent("[1]") === null && P.parseProfileContent("x") === null && P.parseProfileContent('{"a":1}').a === 1, "parseProfileContent fail-closed");

console.log("\nsaved list (NIP-51 10003)");
ok(JSON.stringify(P.parseBookmarks(null, dec)) === JSON.stringify({ pub: [], priv: [], opaque: false, otherPub: [] }), "no list → empty");
const bev = { tags: [["e", id("1")], ["e", "short"], ["t", "keepme"], ["e", id("1")]], content: enc(JSON.stringify([["e", id("2")], ["a", "30023:x:y"]])) };
let bl = P.parseBookmarks(bev, dec);
ok(bl.pub.length === 1 && bl.pub[0] === id("1") && bl.priv[0] === id("2") && !bl.opaque, "public + private parsed, deduped, bad ids not items");
ok(bl.otherPub.some((t) => t[0] === "t") && bl.otherPriv.some((t) => t[0] === "a"), "other tags preserved");
ok(P.parseBookmarks({ tags: [], content: "legacy?iv=abc" }, dec).opaque, "undecryptable content → opaque");
ok(P.parseBookmarks({ tags: [], content: enc("{}") }, dec).opaque, "non-array private → opaque");
ok(P.parseBookmarks({ tags: [], content: "x" }, null).opaque, "no cipher (wire) → opaque");
let ap = P.applyBookmark(bl, { id: id("3") });
ok(ap.changed && ap.privateTags.some((t) => t[1] === id("3")) && ap.privateTags.some((t) => t[0] === "a") && ap.tags.some((t) => t[0] === "t"), "save private keeps other tags");
ap = P.applyBookmark(bl, { id: id("2"), isPrivate: false });
ok(ap.changed && ap.tags.some((t) => t[1] === id("2")) && !ap.privateTags.some((t) => t[1] === id("2")), "save public moves an item");
ok(!P.applyBookmark(bl, { id: id("2") }).changed, "re-saving the same private item = no change");
ap = P.applyBookmark(bl, { id: id("1"), remove: true });
ok(ap.changed && !ap.tags.some((t) => t[1] === id("1")), "remove");
ok(!P.applyBookmark(bl, { id: id("9"), remove: true }).changed, "remove absent = no change");
throws(() => P.applyBookmark(bl, { id: "abc" }), /64-hex/, "non-id refused");
const full = { pub: Array.from({ length: 500 }, (_, i) => i.toString(16).padStart(64, "0")), priv: [], otherPub: [], otherPriv: [] };
throws(() => P.applyBookmark(full, { id: id("f") }), /full/, "list cap enforced");
const maxPriv = JSON.stringify(Array.from({ length: P.BOOKMARK_MAX }, () => ["e", id("f")]));
ok(Buffer.byteLength(maxPriv) < 65535, `a full private list fits NIP-44 (${Buffer.byteLength(maxPriv)} B)`);

console.log("\ndiff tags (kind 40008)");
const base = { repo: "https://github.com/o/r", commit: "abcdef1" };
let t = P.buildDiffTags(base);
ok(JSON.stringify(t) === JSON.stringify([["repo", base.repo], ["commit", "abcdef1"]]), "required tags only");
t = P.buildDiffTags({ ...base, file: "src/a.rs", parent_commit: "1234567", source_branch: "feat", target_branch: "main", pr: 42, language: "rust", description: "fix", truncated: true });
const tm = Object.fromEntries(t.map((x) => [x[0], x.slice(1)]));
ok(tm.file[0] === "src/a.rs" && tm["parent-commit"][0] === "1234567" && tm.branch.join() === "feat,main" && tm.pr[0] === "42" && tm.l[0] === "rust" && tm.description[0] === "fix" && tm.truncated[0] === "true", "all optional tags (relay names)");
ok(!P.buildDiffTags({ ...base, truncated: false }).some((x) => x[0] === "truncated"), "truncated:false omitted");
throws(() => P.buildDiffTags({ ...base, repo: "ftp://x" }), /http/, "non-http repo refused");
throws(() => P.buildDiffTags({ ...base, repo: "https://x y" }), /spaces/, "repo with space refused");
throws(() => P.buildDiffTags({ ...base, commit: "abc" }), /7–64 hex/, "short commit refused");
throws(() => P.buildDiffTags({ ...base, commit: "g".repeat(7) }), /7–64 hex/, "non-hex commit refused");
throws(() => P.buildDiffTags({ ...base, commit: "a".repeat(65) }), /7–64 hex/, "65-hex commit refused");
throws(() => P.buildDiffTags({ ...base, parent_commit: "xyz" }), /parent_commit/, "bad parent refused");
throws(() => P.buildDiffTags({ ...base, source_branch: "a" }), /together/, "lone branch refused");
throws(() => P.buildDiffTags({ ...base, source_branch: "a", target_branch: " " }), /empty/, "empty branch refused");
throws(() => P.buildDiffTags({ ...base, pr: 0 }), /positive/, "pr 0 refused");
throws(() => P.buildDiffTags({ ...base, pr: 1.5 }), /positive/, "fractional pr refused");
throws(() => P.buildDiffTags({ ...base, file: "a\nb" }), /one line/, "multi-line file refused");
throws(() => P.buildDiffTags({ ...base, description: "a\u202eb" }), /control/, "bidi description refused");
ok(P.checkDiffContent("@@ -1 +1 @@\n-a\n+b") .startsWith("@@"), "diff ok");
throws(() => P.checkDiffContent("  "), /required/, "empty diff refused");
throws(() => P.checkDiffContent("x".repeat(61441)), /61440/, "oversize diff refused");
ok(P.checkDiffContent("x".repeat(61440)).length === 61440, "exactly 61440 bytes ok");
throws(() => P.checkDiffContent("é".repeat(30721)), /bytes/, "byte (not char) limit");
throws(() => P.checkDiffContent("a\u0000b"), /NUL/, "NUL refused");

console.log(`\nparity33: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
