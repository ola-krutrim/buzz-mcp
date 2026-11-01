// parity34.test.mjs — `node parity34.test.mjs` — unit tests for parity34.mjs (pure; offline).
import * as P from "./parity34.mjs";
import { finalizeEvent, verifyEvent, getPublicKey } from "nostr-tools/pure";
import { getConversationKey, encrypt as n44enc, decrypt as n44dec } from "./nip44.mjs";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✅ " + m)) : (fail++, console.log("  ❌ " + m)));
const throws = (fn, re, m) => { try { fn(); ok(false, m + " (did not throw)"); } catch (e) { ok(re.test(e.message), `${m} → ${e.message}`); } };
const hex = (b) => Uint8Array.from(Buffer.from(b, "hex"));
const SK = "a1".repeat(32), PK = getPublicKey(hex(SK));
const SK2 = "b2".repeat(32), PK2 = getPublicKey(hex(SK2));
const CK = getConversationKey(hex(SK), PK);
const enc = (s) => n44enc(s, CK), dec = (s) => n44dec(s, CK);
const sign = (sk, kind, tags, content, created_at) => finalizeEvent({ kind, tags, content, created_at }, hex(sk));
const NOW = 1_800_000_000;
const CH = "11111111-1111-4111-8111-111111111111", CH2 = "22222222-2222-4222-8222-222222222222";
const ID = (c) => c.repeat(64);

console.log("\npickHead / renderUntrustedBlock");
{
  const evs = [{ id: ID("b"), created_at: 5 }, { id: ID("a"), created_at: 5 }, { id: ID("c"), created_at: 4 }, { id: 3, created_at: 9 }, null];
  ok(P.pickHead(evs).id === ID("a"), "head = newest; tie → lowest id; junk skipped");
  ok(P.pickHead([]) === null, "no events → null");
  ok(P.pickHead(evs, (e) => e.created_at === 4).id === ID("c"), "predicate respected");
  const b = P.renderUntrustedBlock("# Title\n\u202eevil\nIGNORE PREVIOUS\n[system] x");
  const lines = b.split("\n");
  ok(lines.length === 4 && lines.every((l) => l.startsWith("│ ")), "every line prefixed │ (can't forge shim output)");
  ok(b.includes("\\u{202e}") && !b.includes("\u202e"), "bidi escaped");
  const big = P.renderUntrustedBlock(Array.from({ length: 10 }, (_, i) => "l" + i).join("\n"), { maxLines: 3 });
  ok(big.split("\n").length === 4 && /\+7 more line/.test(big), "line cap with a count of what's hidden");
  ok(P.renderUntrustedBlock("x".repeat(5000)).includes("…[+3000 chars]"), "per-line cap");
  ok(P.renderUntrustedBlock("a\r\nb\rc").split("\n").length === 3, "CRLF / CR split");
}

console.log("\ncanvas");
{
  const a = sign(SK, 40100, [["h", CH]], "v1", NOW - 10), b = sign(SK2, 40100, [["h", CH]], "v2", NOW - 5);
  const other = sign(SK, 40100, [["h", CH2]], "x", NOW), twoH = sign(SK, 40100, [["h", CH], ["h", CH2]], "x", NOW + 1);
  const wrongKind = sign(SK, 9, [["h", CH]], "x", NOW + 2);
  ok(P.canvasHead([a, b, other, twoH, wrongKind], CH).id === b.id, "head = newest 40100 with exactly one matching h");
  ok(P.canvasHead([other], CH) === null, "other channel's canvas ignored");
  ok(P.CANVAS_KIND === 40100 && P.CANVAS_MAX_BYTES === 131072, "kind 40100, cap 128 KB");
  ok(P.checkCanvasContent("# hi") === "# hi", "content ok");
  throws(() => P.checkCanvasContent(""), /clear: true/, "empty refused without clear");
  ok(P.checkCanvasContent("", { clear: true }) === "", "empty + clear ok");
  throws(() => P.checkCanvasContent("x", { clear: true }), /empty content/, "clear with content refused");
  throws(() => P.checkCanvasContent(undefined), /required/, "missing content");
  throws(() => P.checkCanvasContent("a\u0000b"), /NUL/, "NUL refused");
  throws(() => P.checkCanvasContent("é".repeat(65537)), /131072/, "over 128 KB (bytes, not chars) refused");
  ok(P.checkCanvasContent("x".repeat(131072)).length === 131072, "exactly 128 KB ok");
  ok(P.parseExpectedHead("none") === null && P.parseExpectedHead(" NONE ") === null, "\"none\" → null");
  ok(P.parseExpectedHead(ID("A")) === ID("a"), "64 hex → lowercased id");
  throws(() => P.parseExpectedHead(ID("a").slice(0, 12)), /full head id/, "prefix refused (fail closed)");
  throws(() => P.parseExpectedHead(undefined), /full head id/, "missing refused");
  ok(P.canvasHeadCheck(b.id, b).ok, "unchanged head → ok");
  ok(P.canvasHeadCheck(null, null).ok, "none + no canvas → ok");
  const c1 = P.canvasHeadCheck(a.id, b); ok(!c1.ok && /changed since your read/.test(c1.reason), "changed head → refused");
  const c2 = P.canvasHeadCheck(null, b); ok(!c2.ok && /expected none/.test(c2.reason), "canvas appeared → refused");
  const c3 = P.canvasHeadCheck(a.id, null); ok(!c3.ok && /no longer visible/.test(c3.reason), "canvas vanished → refused");
}

console.log("\nreminders: d, not_before, when");
{
  const d = P.newReminderD();
  ok(/^[0-9a-f]{32}$/.test(d) && d !== P.newReminderD(), "d = 32 hex (128-bit), random");
  ok(P.newReminderD(() => new Uint8Array(16).fill(255)) === "f".repeat(32), "d from injected randomness");
  ok(P.parseNotBefore("0") === 0 && P.parseNotBefore("1700000000") === 1700000000, "strict digits ok");
  for (const bad of ["01", "-1", "1.5", " 1", "1e9", "", "9007199254740992", "0x10", "１"]) ok(P.parseNotBefore(bad) === undefined, `not_before ${JSON.stringify(bad)} rejected`);
  ok(P.parseNotBefore("9007199254740991") === 9007199254740991, "max safe ok");
  ok(P.parseNotBefore(5) === undefined, "non-string rejected");
  ok(P.parseDue("30m", { now: NOW }) === NOW + 1800, "30m");
  ok(P.parseDue("in 2h", { now: NOW }) === NOW + 7200, "in 2h");
  ok(P.parseDue("1 day", { now: NOW }) === NOW + 86400 && P.parseDue("2w", { now: NOW }) === NOW + 2 * 604800, "1 day / 2w");
  ok(P.parseDue(String(NOW + 60), { now: NOW }) === NOW + 60 && P.parseDue(NOW + 60, { now: NOW }) === NOW + 60, "epoch string / number");
  ok(P.parseDue("2027-01-15T09:00:00-08:00", { now: NOW - 10 ** 8 + 10 ** 8 - 30_000_000 }) === Date.parse("2027-01-15T17:00:00Z") / 1000, "ISO with zone");
  throws(() => P.parseDue("2027-01-15T09:00", { now: NOW }), /zone/, "zone-less ISO refused");
  throws(() => P.parseDue("tomorrow", { now: NOW }), /can't read/, "words refused");
  throws(() => P.parseDue(String(NOW - 5), { now: NOW }), /future/, "past refused");
  throws(() => P.parseDue("0m", { now: NOW }), /future/, "now refused");
  throws(() => P.parseDue("53w", { now: NOW }), /year/, "beyond 1-year horizon refused");
  throws(() => P.parseDue("", { now: NOW }), /required/, "empty refused");
  throws(() => P.parseDue(1.5, { now: NOW }), /whole/, "fractional refused");
}

console.log("\nreminders: plaintext / content / tags");
{
  const tgt = { eventId: ID("e"), channelId: CH, preview: "p".repeat(300), authorPubkey: PK2 };
  const pt = JSON.parse(P.reminderPlaintext({ target: tgt, note: "ship it" }));
  ok(pt.status === "pending" && pt.note === "ship it" && pt.target.eventId === ID("e") && pt.target.id === ID("e") && pt.target.channelId === CH && pt.target.authorPubkey === PK2, "desktop/mobile target shape + NIP-ER id");
  ok([...pt.target.preview].length === 200, "preview capped at 200");
  const noteOnly = JSON.parse(P.reminderPlaintext({ note: "standup" }));
  ok(!("target" in noteOnly) && noteOnly.note === "standup", "note-only omits target (absent, not null)");
  const tOnly = JSON.parse(P.reminderPlaintext({ target: tgt }));
  ok(!("note" in tOnly), "target-only omits note");
  throws(() => P.reminderPlaintext({}), /needs a message/, "neither → refused");
  throws(() => P.reminderPlaintext({ note: "" }), /needs a message/, "empty note → refused");
  throws(() => P.reminderPlaintext({ note: "x".repeat(1001) }), /1000/, "note cap");
  throws(() => P.reminderPlaintext({ note: "a\u0007b" }), /control/, "control chars refused");
  ok(JSON.parse(P.reminderPlaintext({ note: "a\nb" })).note === "a\nb", "newlines allowed in note");
  throws(() => P.reminderPlaintext({ target: { ...tgt, eventId: "abc" } }), /real message/, "bad target id refused");
  throws(() => P.reminderPlaintext({ target: { ...tgt, authorPubkey: "x" } }), /real message/, "bad author refused");
  throws(() => P.reminderPlaintext({ note: "x", status: "snoozed" }), /status/, "unknown status refused");
  ok(JSON.parse(P.reminderPlaintext({ note: "x", status: "done" })).status === "done", "done plaintext");
  const pc = P.parseReminderContent;
  ok(pc(P.reminderPlaintext({ target: tgt })).target.eventId === ID("e"), "round trip");
  ok(pc('{"status":"pending","note":"x"}').note === "x", "desktop note-only ok");
  ok(pc('{"status":"pending","target":{"eventId":"a","channelId":"b","preview":"c","authorPubkey":"d"}}') !== null, "desktop-written target (no id) ok");
  for (const [bad, why] of [["nope", "not JSON"], ["[1]", "array"], ["null", "null"], ['"s"', "string"], ['{"status":"later","note":"x"}', "unknown status"],
    ['{"note":"x"}', "no status"], ['{"status":"pending"}', "no target or note"], ['{"status":"pending","note":""}', "empty note"],
    ['{"status":"pending","note":5}', "non-string note"], ['{"status":"pending","target":null}', "target null (desktop drops it)"],
    ['{"status":"pending","target":{"eventId":"a"}}', "partial target"], ['{"status":"pending","target":{"eventId":"a","channelId":"b","preview":"c","authorPubkey":"d","id":"zz"}}', "bad target.id"]])
    ok(pc(bad) === null, `content rejected: ${why}`);
  const d = "ab".repeat(16);
  const tp = P.reminderTags({ d, status: "pending", notBefore: NOW + 60 });
  ok(JSON.stringify(tp) === JSON.stringify([["d", d], ["not_before", String(NOW + 60)], ["alt", "Encrypted reminder"]]), "pending tags");
  const td = P.reminderTags({ d, status: "done", now: NOW, rand: () => 0 });
  ok(!td.some((t) => t[0] === "not_before") && td.find((t) => t[0] === "expiration")[1] === String(NOW + 30 * 86400), "done: no not_before, expiration +30d (min jitter)");
  const tc = P.reminderTags({ d, status: "cancelled", now: NOW, rand: () => 0.99999999 });
  ok(tc.find((t) => t[0] === "expiration")[1] === String(NOW + 89 * 86400), "cancelled: expiration ≤ +89d (max jitter)");
  throws(() => P.reminderTags({ d: "short", status: "pending", notBefore: 1 }), /128-bit/, "short d refused");
  throws(() => P.reminderTags({ d, status: "pending" }), /not_before/, "pending without not_before refused");
  throws(() => P.reminderTags({ d, status: "snoozed" }), /status/, "bad status refused");
}

console.log("\nreminders: decode (verify before decrypt, head per d, skips)");
{
  const d1 = "11".repeat(16), d2 = "22".repeat(16), d3 = "33".repeat(16), d4 = "44".repeat(16), d5 = "55".repeat(16), d6 = "66".repeat(16), d7 = "77".repeat(16);
  const r = (d, content, tags, at, sk = SK) => sign(sk, 30300, [["d", d], ...tags], content, at);
  const evs = [
    r(d1, enc(P.reminderPlaintext({ note: "due one" })), [["not_before", String(NOW - 10)]], NOW - 100),
    r(d2, enc(P.reminderPlaintext({ note: "later" })), [["not_before", String(NOW + 3600)]], NOW - 100),
    r(d3, enc(P.reminderPlaintext({ note: "first" })), [["not_before", String(NOW + 10)]], NOW - 200),
    r(d3, enc(P.reminderPlaintext({ note: "first", status: "done" })), [["expiration", String(NOW + 86400 * 40)]], NOW - 50),
    r(d4, "not-ciphertext", [["not_before", String(NOW + 10)]], NOW - 100),
    r(d5, enc(P.reminderPlaintext({ note: "x" })), [], NOW - 100),   // pending without not_before → skipped
    r(d6, enc(P.reminderPlaintext({ note: "old", status: "cancelled" })), [["expiration", String(NOW - 1)]], NOW - 100),   // expired
    r(d7, enc(P.reminderPlaintext({ note: "x" })), [["not_before", "010"]], NOW - 100),   // malformed nb
    r("99".repeat(16), enc(P.reminderPlaintext({ note: "theirs" })), [["not_before", "1"]], NOW, SK2),   // other author
  ];
  const forged = { ...JSON.parse(JSON.stringify(r(d2, enc(P.reminderPlaintext({ note: "FORGED" })), [["not_before", "1"]], NOW))), sig: "00".repeat(64) };   // JSON round trip: no cached verify flag
  const doneWithNb = r("88".repeat(16), enc(P.reminderPlaintext({ note: "t", status: "done" })), [["not_before", String(NOW + 5)]], NOW - 10);
  let decrypts = 0;
  const out = P.decodeReminders([...evs, forged, doneWithNb], { me: PK, decrypt: (c) => (decrypts++, dec(c)), verify: verifyEvent, now: NOW });
  const by = Object.fromEntries(out.reminders.map((x) => [x.d, x]));
  ok(by[d1] && by[d1].due === true && by[d1].status === "pending", "past not_before → due");
  ok(by[d2] && by[d2].due === false && by[d2].content.note === "later", "future → pending, not due; FORGED newer head ignored (verify before head)");
  ok(by[d3] && by[d3].status === "done" && by[d3].notBefore === undefined, "newest head wins (done)");
  ok(!by[d4] && !by[d5] && !by[d6] && !by[d7], "undecryptable / pending-without-nb / expired / malformed nb skipped");
  ok(by["88".repeat(16)] && by["88".repeat(16)].status === "done", "done head carrying not_before is terminal");
  ok(!out.reminders.some((x) => x.content.note === "theirs"), "other author's reminder ignored");
  ok(out.forged === 1 && out.skipped === 4, `counts: forged 1, skipped 4 → ${out.forged}/${out.skipped}`);
  ok(out.reminders[0].d === d1 && out.reminders[1].d === d2, "pending first, soonest first");
  ok(decrypts === 6, `forged / foreign / expired / malformed never decrypted → ${decrypts} decrypts`);
  const tie1 = r("aa".repeat(16), enc(P.reminderPlaintext({ note: "A" })), [["not_before", "5"]], NOW - 5);
  const tie2 = r("aa".repeat(16), enc(P.reminderPlaintext({ note: "B" })), [["not_before", "5"]], NOW - 5);
  const lo = tie1.id < tie2.id ? tie1 : tie2;
  const t = P.decodeReminders([tie1, tie2], { me: PK, decrypt: dec, verify: verifyEvent, now: NOW });
  ok(t.reminders.length === 1 && t.reminders[0].id === lo.id, "same-second tie → lowest id");
  const list = out.reminders;
  ok(P.findReminder(list, d1.slice(0, 8)).d === d1 && P.findReminder(list, d1).d === d1, "find by prefix / full");
  throws(() => P.findReminder(list, "1111"), /≥ 8 hex/, "too-short ref refused");
  throws(() => P.findReminder(list, "ffffffff"), /no reminder/, "unknown ref");
  throws(() => P.findReminder([{ d: "abcdef0011" }, { d: "abcdef0022" }], "abcdef00"), /give more/, "ambiguous prefix refused");
}

console.log("\nworkflows");
{
  const U1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", U2 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const Y = `name: "Deploy gate"\ndescription: ask before deploy\ntrigger:\n  on: message_posted\n  filter: "deploy"\nsteps:\n  - id: ask\n    action: request_approval\n    from: "@me"\n    message: ok?\n  - id: hook\n    action: call_webhook\n    url: https://x\n  - id: say\n    action: send_message\n    text: done\nenabled: true\n`;
  const s = P.summarizeWorkflowYaml(Y);
  ok(s.name === "Deploy gate" && s.description === "ask before deploy" && s.trigger === "message_posted", "name / description / trigger");
  ok(s.steps === 3 && s.actions.join(",") === "request_approval,call_webhook,send_message" && s.approval && s.webhook && s.enabled === true, "steps, actions, approval + webhook flags");
  const s2 = P.summarizeWorkflowYaml("name: x\ntrigger: { on: webhook }\nsteps: []\nenabled: false\n");
  ok(s2.trigger === "webhook" && s2.enabled === false && s2.steps === 0 && !s2.approval, "flow-style trigger, disabled");
  ok(P.summarizeWorkflowYaml("steps:\n  - id: a\n    action: launch_missiles\n").unknownActions[0] === "launch_missiles", "unknown action surfaced");
  ok(P.summarizeWorkflowYaml("trigger:\n  on: evil_thing\n").trigger === null, "unknown trigger → null");
  ok(P.summarizeWorkflowYaml("", "Tag Name").name === "Tag Name" && P.summarizeWorkflowYaml("").enabled === true, "name tag fallback; enabled defaults true");
  ok(P.summarizeWorkflowYaml(" name: nested\n").name === null, "indented name isn't top-level");
  const w = (sk, d, yaml, at, h = CH, extra = []) => sign(sk, 30620, [["h", h], ["d", d], ...extra], yaml, at);
  const w1 = w(SK, U1, Y, NOW - 100), w1b = w(SK, U1, Y.replace("Deploy gate", "Deploy gate v2"), NOW - 50);
  const w2 = w(SK2, U2, "name: Other\n", NOW - 70), wx = w(SK, U2, "name: elsewhere\n", NOW, CH2), wbad = w(SK, "not-a-uuid", "name: bad\n", NOW);
  const defs = P.workflowDefs([w1, w1b, w2, wx, wbad], CH);
  ok(defs.length === 2 && defs[0].id === w1b.id && defs[1].id === w2.id, "newest per (author, d); other channel / non-UUID d dropped");
  ok(P.resolveWorkflow(defs, U1).id === w1b.id && P.resolveWorkflow(defs, U1.toUpperCase()).id === w1b.id, "resolve by id (case-insensitive)");
  ok(P.resolveWorkflow(defs, "deploy GATE v2").id === w1b.id, "resolve by exact name, case-insensitive");
  throws(() => P.resolveWorkflow(defs, "deploy"), /no workflow named/, "partial name refused");
  throws(() => P.resolveWorkflow(defs, ""), /required/, "empty ref");
  const dupName = P.workflowDefs([w1b, w(SK2, U2, Y.replace("Deploy gate", "Deploy gate v2"), NOW)], CH);
  throws(() => P.resolveWorkflow(dupName, "Deploy gate v2"), /pass the id/, "duplicate names → refused (fail closed)");
  const sameD = P.workflowDefs([w1b, w(SK2, U1, "name: impostor\n", NOW)], CH);
  throws(() => P.resolveWorkflow(sameD, U1), /refusing to guess/, "same id from two authors → refused");
  ok(P.workflowId(w1) === U1, "workflowId");
  ok(P.workflowTriggerContent(undefined) === "" && P.workflowTriggerContent({}) === "", "no inputs → empty content (SDK default)");
  ok(P.workflowTriggerContent({ env: "prod", n: 2, dry: false }) === '{"env":"prod","n":2,"dry":false}', "flat inputs JSON");
  throws(() => P.workflowTriggerContent([1]), /object/, "array refused");
  throws(() => P.workflowTriggerContent({ "bad key": "x" }), /bad input name/, "bad key refused");
  throws(() => P.workflowTriggerContent({ a: { b: 1 } }), /text, a number/, "nested refused");
  throws(() => P.workflowTriggerContent({ a: NaN }), /text, a number/, "NaN refused");
  throws(() => P.workflowTriggerContent({ a: "x".repeat(4097) }), /4096/, "value cap");
  throws(() => P.workflowTriggerContent(Object.fromEntries(Array.from({ length: 33 }, (_, i) => ["k" + i, "v"]))), /32/, "key-count cap");
  throws(() => P.workflowTriggerContent(Object.fromEntries(Array.from({ length: 5 }, (_, i) => ["k" + i, "v".repeat(4000)]))), /16384/, "total-bytes cap");
  ok(JSON.stringify(P.workflowTriggerTags(U1.toUpperCase())) === JSON.stringify([["d", U1]]), "trigger tags = [d, uuid]");
  throws(() => P.workflowTriggerTags("x"), /bad workflow id/, "bad id refused");
  ok(P.WORKFLOW_DEF_KIND === 30620 && P.WORKFLOW_TRIGGER_KIND === 46020 && P.REMINDER_KIND === 30300, "kinds");
}

console.log(`\nparity34: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
