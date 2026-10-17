// clientversion.mjs (v0.2.23) — client-version skew check.
//
// WHY A SEPARATE MODULE: buzz-mcp.mjs connects a StdioServerTransport at load
// (its last line), so it can't be imported by a test without the process trying
// to speak MCP on stdio. The skew logic lives here so it is unit-testable in
// isolation (clientversion.test.mjs) and still bundled into dist/ by esbuild.
//
// SOURCE OF TRUTH: the relay's NIP-11 document. Every agent already fetches it
// (relayInfo()), and the relay is the one component the whole fleet talks to, so
// it is the natural place to advertise the current shim version. The relay-side
// half is a single optional NIP-11 field (relay_sre's lane); until it exists this
// check is INERT AND FAIL-OPEN — it never blocks, never throws, never nags.

// Parse "0.2.23" → [0,2,23]. Non-numeric / malformed → null (caller fails open).
function parse(v) {
  if (typeof v !== "string") return null;
  const core = v.trim().replace(/^v/, "").split(/[-+]/, 1)[0]; // drop any -pre / +build
  if (!/^\d+(\.\d+)*$/.test(core)) return null;
  return core.split(".").map((n) => parseInt(n, 10));
}

// Semver-ish compare of dotted numeric versions. Returns -1 / 0 / 1, or null if
// either side is unparseable (so the caller can fail open rather than guess).
export function cmpVersions(a, b) {
  const pa = parse(a), pb = parse(b);
  if (!pa || !pb) return null;
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return 0;
}

// Pull the advertised versions out of a NIP-11 doc. Canonical fields (what I'm
// asking relay_sre to add): top-level `shim_latest` (string) and optional
// `shim_min` (string, a future hard floor). Anything missing/garbage → undefined.
// Accepts a nested `ola_buzz` object too, so either shape the relay settles on works.
export function pickAdvertised(nip11) {
  if (!nip11 || typeof nip11 !== "object") return {};
  const ns = (nip11.ola_buzz && typeof nip11.ola_buzz === "object") ? nip11.ola_buzz : {};
  const latest = nip11.shim_latest ?? ns.shim_latest;
  const min = nip11.shim_min ?? ns.shim_min;
  return {
    latest: typeof latest === "string" ? latest : undefined,
    min: typeof min === "string" ? min : undefined,
  };
}

// Decide what to tell the user. Pure function — no I/O — so it is trivially
// testable and the caller owns when/where to print. Returns:
//   { level: "ok" | "update" | "below-min", running, latest, min, message }
// level "ok" covers "up to date", "ahead of advertised" (dev build), and
// "relay advertises nothing" — all silent. Only "update"/"below-min" carry a
// non-null `message`. Fails open: any unparseable version => "ok", silent.
export function clientVersionStatus(running, advertised) {
  const { latest, min } = advertised || {};
  // Hard floor first: a relay-declared minimum the running shim is under.
  if (min) {
    const c = cmpVersions(running, min);
    if (c !== null && c < 0) {
      return {
        level: "below-min", running, latest, min,
        message: `[buzz-mcp] ⚠ this shim is v${running}, but the relay requires at least v${min}. Update: npx -y github:ola-krutrim/buzz-mcp (or re-run the install-cli). Older clients may be refused.`,
      };
    }
  }
  if (latest) {
    const c = cmpVersions(running, latest);
    if (c !== null && c < 0) {
      return {
        level: "update", running, latest, min,
        message: `[buzz-mcp] ℹ a newer shim is available: v${latest} (you're on v${running}). Update: npx -y github:ola-krutrim/buzz-mcp (or re-run the install-cli).`,
      };
    }
  }
  return { level: "ok", running, latest, min, message: null };
}
