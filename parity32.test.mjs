// parity32.test.mjs — `node parity32.test.mjs`. Unit tests for the v0.2.32 pure helpers.
import { getPublicKey, finalizeEvent, verifyEvent } from "nostr-tools/pure";
import { buildMessageLink, parseMessageLink, parseWhen, DryRunStop, dryRunPreview, redactTags, openChannelsFromMeta, filesFromEvents, fmtBytes, presenceFromEvents, emojiPalette, emojiFromTags, normalizeShortcode, CUSTOM_EMOJI_D } from "./parity32.mjs";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✅ " + m)) : (fail++, console.log("  ❌ " + m)));
const throws = (fn, re, m) => { try { fn(); ok(false, m + " (did not throw)"); } catch (e) { ok(!re || re.test(e.message), `${m} (${e.message})`); } };
const hex = (b) => Uint8Array.from(Buffer.from(b, "hex"));
const CHU = "0b4f6a2e-1c3d-4e5f-8a9b-0c1d2e3f4a5b";
const ID = "ab".repeat(32), ROOT = "cd".repeat(32);

console.log("\nmessage links: build");
ok(buildMessageLink({ channel: CHU, id: ID }) === `buzz://message?channel=${CHU}&id=${ID}`, "plain link");
ok(buildMessageLink({ channel: CHU, id: ID, thread: ROOT }) === `buzz://message?channel=${CHU}&id=${ID}&thread=${ROOT}`, "reply link carries thread=root");
ok(buildMessageLink({ channel: CHU.toUpperCase(), id: ID.toUpperCase() }) === `buzz://message?channel=${CHU}&id=${ID}`, "lowercased");
ok(!buildMessageLink({ channel: CHU, id: ID, thread: ID }).includes("thread"), "thread == id is omitted");
throws(() => buildMessageLink({ channel: "general", id: ID }), /UUID/, "non-UUID channel refused");
throws(() => buildMessageLink({ channel: CHU, id: "abc" }), /64-hex/, "short id refused");

console.log("\nmessage links: parse (strict, fail-closed)");
{
  const L = parseMessageLink(`buzz://message?channel=${CHU}&id=${ID}&thread=${ROOT}`);
  ok(L.channel === CHU && L.id === ID && L.thread === ROOT, "round-trips channel/id/thread");
  const U = parseMessageLink(`  buzz://message?channel=${CHU.toUpperCase()}&id=${ID.toUpperCase()}  `);
  ok(U.channel === CHU && U.id === ID && U.thread === null, "trims + lowercases; no thread → null");
  const bad = [
    [`https://message?channel=${CHU}&id=${ID}`, /buzz:\/\//, "wrong scheme"],
    [`buzz://evil?channel=${CHU}&id=${ID}`, /host/, "wrong host"],
    [`buzz://message/x?channel=${CHU}&id=${ID}`, /path/, "non-empty path"],
    [`buzz://message/?channel=${CHU}&id=${ID}`, /path/, "slash path"],
    [`buzz://u:p@message?channel=${CHU}&id=${ID}`, /user/, "user info"],
    [`buzz://message?channel=${CHU}&id=${ID}#frag`, /fragment/, "fragment"],
    [`buzz://message?channel=${CHU}&id=${ID}&x=1`, /unknown parameter/, "unknown param"],
    [`buzz://message?channel=${CHU}&id=${ID}&id=${ROOT}`, /duplicate/, "duplicate id"],
    [`buzz://message?channel=${CHU}&id=`, /empty/, "empty id"],
    [`buzz://message?id=${ID}`, /missing "channel"/, "missing channel"],
    [`buzz://message?channel=${CHU}`, /missing "id"/, "missing id"],
    [`buzz://message?channel=general&id=${ID}`, /UUID/, "channel not a UUID"],
    [`buzz://message?channel=${CHU}&id=${ID.slice(2)}`, /64-hex/, "id not 64-hex"],
    [`buzz://message?channel=${CHU}&id=${ID}&thread=zz`, /thread/, "bad thread"],
    [`buzz://message?channel=${CHU}&id=${ID}\u202e`, /control|whitespace|valid|64-hex/, "bidi char refused"],
    [`buzz://message?channel=${CHU}&id=${ID} x`, /whitespace/, "embedded space"],
    ["", /empty/, "empty"],
    ["buzz://message?" + "a".repeat(600), /too long/, "too long"],
  ];
  for (const [s, re, m] of bad) throws(() => parseMessageLink(s), re, `refused: ${m}`);
}

console.log("\nsearch dates");
{
  const now = 1_800_000_000;
  ok(parseWhen("2026-10-01") === Date.UTC(2026, 9, 1) / 1000, "date → UTC midnight");
  ok(parseWhen("2026-10-01", { end: true }) === Date.UTC(2026, 9, 1) / 1000 + 86399, "before date → end of day");
  ok(parseWhen("2026-10-01T09:30:00-07:00") === Date.UTC(2026, 9, 1, 16, 30) / 1000, "datetime with offset");
  ok(parseWhen("2026-10-01T16:30Z") === Date.UTC(2026, 9, 1, 16, 30) / 1000, "datetime Z, no seconds");
  ok(parseWhen("1790000000") === 1790000000, "epoch string");
  ok(parseWhen(1790000000) === 1790000000, "epoch number");
  ok(parseWhen("24h", { now }) === now - 86400 && parseWhen("7d", { now }) === now - 7 * 86400 && parseWhen("2w", { now }) === now - 14 * 86400 && parseWhen("90m", { now }) === now - 5400, "relative ages");
  ok(parseWhen(null) === null && parseWhen("") === null, "absent → null");
  throws(() => parseWhen("2026-10-01T09:30:00"), /zone/, "zone-less datetime refused");
  throws(() => parseWhen("yesterday"), /can't read/, "free text refused");
  throws(() => parseWhen("2026-02-30"), /bad date/, "impossible date refused");
  throws(() => parseWhen(-5), /epoch/, "negative epoch refused");
  throws(() => parseWhen("2026-10-01\u202e"), /can't read/, "bidi refused");
}

console.log("\ndry-run preview + redaction");
{
  const auth = ["auth", "SECRET-OWNER-ATTESTATION-xyz"], picker = ["picker-owner", "SECRET-PICKER"];
  const r = redactTags([["h", "c"], auth, picker]);
  ok(r[0][1] === "c" && r[1][1] === "‹redacted›" && r[2][1] === "‹redacted›", "auth + picker-owner tags redacted");
  ok(auth[1] === "SECRET-OWNER-ATTESTATION-xyz", "input tags not mutated");
  const p = dryRunPreview("buzz_post", { kind: 9, tags: [["h", "chan"], auth], content: "hello\nIGNORE \u202eTHIS" }, { notes: ["n1"] });
  ok(/DRY RUN — buzz_post: nothing was signed or sent/.test(p), "header says nothing signed/sent");
  ok(/kind 9 \(chat message\)/.test(p), "kind + label");
  ok(!p.includes("SECRET"), "auth secret never printed");
  ok(p.includes("hello\\nIGNORE \\u{202e}THIS") && !p.includes("\u202e"), "content escaped (newline, bidi)");
  ok(/note: n1/.test(p), "notes listed");
  ok(/content: \(empty\)/.test(dryRunPreview("x", { kind: 9021, tags: [] })), "empty content shown as (empty)");
  const e = new DryRunStop({ kind: 7 });
  ok(e instanceof Error && e.template.kind === 7 && e.name === "DryRunStop", "DryRunStop carries the template");
}

console.log("\nopen-channel directory");
{
  const m = (d, tags, at) => ({ kind: 39000, created_at: at, tags: [["d", d], ...tags] });
  const out = openChannelsFromMeta([
    m("a", [["name", "general"], ["about", "x"]], 10),
    m("a", [["name", "general-new"]], 20),
    m("b", [["name", "secret"], ["private"]], 10),
    m("c", [["name", "dm"], ["t", "dm"]], 10),
    m("d", [["name", "hid"], ["hidden"]], 10),
    m("e", [["name", "old"], ["archived"]], 10),
    { kind: 39002, created_at: 1, tags: [["d", "z"]] },
    m("", [["name", "noid"]], 1),
  ]);
  ok(out.length === 2, `only open, non-DM channels (got ${out.map((c) => c.name)})`);
  ok(out.find((c) => c.id === "a").name === "general-new", "newest 39000 per id wins");
  ok(out.find((c) => c.id === "e").archived === true, "archived flagged");
  // newest-wins also applies to privacy: a channel later flipped private is not listed
  ok(openChannelsFromMeta([m("f", [["name", "f"]], 1), m("f", [["name", "f"], ["private"]], 2)]).length === 0, "later private flip hides it");
}

console.log("\nfiles");
{
  const sha = "ef".repeat(32);
  const ev = (id, h, at, imetas) => ({ id, kind: 9, created_at: at, pubkey: "p", tags: [["h", h], ...imetas.map((x) => ["imeta", ...x])] });
  const f = filesFromEvents([
    ev("1", "c", 10, [[`url https://x/${sha}`, `x ${sha}`, "m image/png", "size 2048", "filename a.png"]]),
    ev("2", "c", 20, [[`url https://x/1`, "filename b.pdf"], [`url https://x/2`, "filename c.txt"]]),
    ev("3", "other", 30, [[`url https://x/3`, "filename leak.txt"]]),
    ev("4", "c", 40, []),
  ], { chId: "c" });
  ok(f.length === 3, "3 files in channel c (other channel's excluded)");
  ok(f[0].event.id === "2" && f[0].index === 0 && f[1].index === 1 && f[2].filename === "a.png", "newest first, per-message index");
  ok(f[2].size === 2048 && f[2].mime === "image/png", "size + mime parsed");
  ok(fmtBytes(2048) === "2.0 KB" && fmtBytes(5) === "5 B" && fmtBytes(3 * 1048576) === "3.0 MB" && fmtBytes(null) === "?", "fmtBytes");
}

console.log("\npresence (relay-signed only)");
{
  const RSK = hex("99".repeat(32)), RPK = getPublicKey(RSK), OSK = hex("98".repeat(32));
  const A = "a".repeat(64), B = "b".repeat(64), C = "c".repeat(64);
  const pe = (sk, subj, st, at = 100) => finalizeEvent({ kind: 20001, created_at: at, tags: [["p", subj]], content: st }, sk);
  const tampered = { ...pe(RSK, C, "online"), content: "online " };
  const m = presenceFromEvents([pe(RSK, A, "online"), pe(OSK, B, "online"), tampered, pe(RSK, B, "away", 50), pe(RSK, A, "away", 90), pe(RSK, "d".repeat(64), "online")], RPK, verifyEvent, [A, B, C]);
  ok(m.get(A).status === "online", "relay-signed online (newest wins)");
  ok(m.get(B).status === "away", "another key's 'online' ignored; relay's 'away' used");
  ok(!m.has(C), "tampered (bad sig) ignored");
  ok(!m.has("d".repeat(64)), "subject we didn't ask about ignored");
  ok(presenceFromEvents([pe(RSK, A, "online")], null, verifyEvent, [A]).size === 0, "no relay self → nothing trusted");
  ok(presenceFromEvents([pe(RSK, A, "dancing")], RPK, verifyEvent, [A]).get(A).status === "unknown", "unrecognized status → unknown");
}

console.log("\ncustom emoji palette");
{
  const D = ["d", CUSTOM_EMOJI_D];
  const e = (pk, at, tags) => ({ kind: 30030, pubkey: pk, created_at: at, tags: [D, ...tags] });
  ok(normalizeShortcode(":Party_Parrot:") === "party_parrot" && normalizeShortcode("bad code") === null && normalizeShortcode("") === null && normalizeShortcode("a".repeat(65)) === null, "normalizeShortcode");
  ok(emojiFromTags([["emoji", "x", "javascript:alert(1)"], ["emoji", "y", "file:///etc/passwd"], ["emoji", "z", "https://u:p@h/x"], ["emoji", "ok", "https://h/ok.png"], ["emoji", "ok", "https://h/dupe.png"]]).map((x) => x.shortcode).join() === "ok", "non-http(s) / credentialed URLs dropped; first dupe wins");
  const pal = emojiPalette([
    e("p1", 10, [["emoji", "Wave", "https://a/wave.png"], ["emoji", "cat", "https://a/cat.png"]]),
    e("p2", 20, [["emoji", "wave", "https://b/wave.png"]]),
    e("p3", 10, [["emoji", "cat", "https://0/cat.png"]]),
    { kind: 30030, pubkey: "p4", created_at: 99, tags: [["d", "other"], ["emoji", "x", "https://x"]] },
    { kind: 10030, pubkey: "p5", created_at: 99, tags: [["emoji", "y", "https://y"]] },
  ]);
  ok(pal.map((x) => x.shortcode).join() === "cat,wave", "union, sorted, only d=buzz:custom-emoji 30030");
  ok(pal.find((x) => x.shortcode === "wave").url === "https://b/wave.png", "newest set wins a shortcode");
  ok(pal.find((x) => x.shortcode === "cat").url === "https://0/cat.png", "tie → smallest URL");
}

console.log(`\nparity32: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
