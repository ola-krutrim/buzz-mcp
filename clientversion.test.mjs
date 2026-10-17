// clientversion.test.mjs — `node clientversion.test.mjs`
// Unit tests for the client-version skew check. Pure logic, no network, no prod
// dependency. Covers: semver compare, NIP-11 field extraction (both shapes),
// and the status decision incl. its fail-open behaviour on garbage input.

import { cmpVersions, pickAdvertised, clientVersionStatus } from "./clientversion.mjs";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✅ " + m)) : (fail++, console.log("  ❌ " + m)));

console.log("cmpVersions:");
ok(cmpVersions("0.2.22", "0.2.23") === -1, "0.2.22 < 0.2.23");
ok(cmpVersions("0.2.23", "0.2.22") === 1, "0.2.23 > 0.2.22");
ok(cmpVersions("0.2.23", "0.2.23") === 0, "0.2.23 == 0.2.23");
ok(cmpVersions("0.3.0", "0.2.99") === 1, "minor outranks patch");
ok(cmpVersions("1.0.0", "0.9.9") === 1, "major outranks minor");
ok(cmpVersions("v0.2.23", "0.2.23") === 0, "leading v tolerated");
ok(cmpVersions("0.2.23", "0.2.23-dev") === 0, "pre-release suffix ignored on the compared core");
ok(cmpVersions("0.2", "0.2.0") === 0, "short form padded with zeros");
ok(cmpVersions("0.2.23", "garbage") === null, "unparseable right => null (caller fails open)");
ok(cmpVersions(undefined, "0.2.23") === null, "undefined left => null");

console.log("pickAdvertised:");
ok(pickAdvertised({ shim_latest: "0.2.23" }).latest === "0.2.23", "top-level shim_latest");
ok(pickAdvertised({ shim_min: "0.2.20" }).min === "0.2.20", "top-level shim_min");
ok(pickAdvertised({ ola_buzz: { shim_latest: "0.2.24" } }).latest === "0.2.24", "nested ola_buzz.shim_latest");
ok(pickAdvertised({ shim_latest: "0.2.9", ola_buzz: { shim_latest: "0.2.1" } }).latest === "0.2.9", "top-level wins over nested");
ok(pickAdvertised({ shim_latest: 223 }).latest === undefined, "non-string field ignored");
ok(pickAdvertised(null).latest === undefined, "null doc => {} (no throw)");
ok(pickAdvertised("nope").latest === undefined, "non-object doc => {} (no throw)");
ok(Object.keys(pickAdvertised({ name: "relay", version: "1.2" })).length === 2 && pickAdvertised({}).latest === undefined, "doc without our fields => both undefined");

console.log("clientVersionStatus:");
let s;
s = clientVersionStatus("0.2.22", { latest: "0.2.23" });
ok(s.level === "update" && s.message && s.message.includes("v0.2.23") && s.message.includes("v0.2.22"), "behind latest => update nudge naming both versions");
s = clientVersionStatus("0.2.23", { latest: "0.2.23" });
ok(s.level === "ok" && s.message === null, "on latest => silent ok");
s = clientVersionStatus("0.2.24", { latest: "0.2.23" });
ok(s.level === "ok" && s.message === null, "ahead of advertised (dev build) => silent ok");
s = clientVersionStatus("0.2.22", {});
ok(s.level === "ok" && s.message === null, "relay advertises nothing => silent ok (fail-open, inert)");
s = clientVersionStatus("0.2.22", { latest: "garbage" });
ok(s.level === "ok" && s.message === null, "garbage advertised => silent ok (fail-open)");
s = clientVersionStatus("0.2.19", { latest: "0.2.23", min: "0.2.20" });
ok(s.level === "below-min" && s.message.includes("requires at least v0.2.20"), "under hard floor => below-min takes precedence over update");
s = clientVersionStatus("0.2.21", { latest: "0.2.23", min: "0.2.20" });
ok(s.level === "update", "at/above floor but behind latest => update");

console.log(`\nclientversion: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
