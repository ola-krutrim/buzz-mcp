#!/usr/bin/env bash
# install.sh — curl-installer for @ola/buzz-mcp (v0.2.2+; dependency-free, no npm).
#
#   curl -fsSL https://raw.githubusercontent.com/ola-krutrim/buzz-mcp/main/install.sh | bash
#
# Installs the Buzz MCP shim under ~/.local/share/buzz-mcp and puts `buzz-mcp` +
# `buzz-mcp-login` on PATH. The shim ships as a SELF-CONTAINED bundle (deps inlined
# in dist/), so there is NO `npm install` step and no npm/registry needed — the
# clone is the whole install. v0.2.31+: installs the LATEST RELEASE TAG by default (not main), and
# refuses to install a bundle whose sha256 doesn't match dist/SHA256SUMS (and, when the GitHub
# release exists, the SHA256SUMS published on that release). Pin a tag with BUZZ_MCP_REF=<tag>;
# BUZZ_MCP_REF=main installs the unreleased tip on purpose.
set -euo pipefail

REPO="${BUZZ_MCP_REPO:-https://github.com/ola-krutrim/buzz-mcp.git}"
REF="${BUZZ_MCP_REF:-}"
DEST="${BUZZ_MCP_DIR:-$HOME/.local/share/buzz-mcp}"
BINDIR="${BUZZ_MCP_BIN:-$HOME/.local/bin}"

command -v node >/dev/null 2>&1 || { echo "buzz-mcp install: Node >= 20 required (not found on PATH)." >&2; exit 1; }
command -v git  >/dev/null 2>&1 || { echo "buzz-mcp install: git required (not found on PATH)." >&2; exit 1; }
# NOTE: npm is intentionally NOT required — the shim is bundled (deps inlined). The old
# npm-install step was the #1 silent onboarding failure (blocked registry/proxy → cryptic
# ERR_MODULE_NOT_FOUND for nostr-tools). Bundling removes that class of failure entirely.

if [ -z "$REF" ]; then
  # Newest v* tag by version order (peeled ^{} entries dropped).
  REF="$(git ls-remote --tags --refs --sort=-v:refname "$REPO" 'v*' 2>/dev/null | head -n1 | sed 's#.*refs/tags/##')" || true
  [ -n "$REF" ] || { echo "buzz-mcp install: could not find a release tag at $REPO (set BUZZ_MCP_REF=<tag> to pin one, or BUZZ_MCP_REF=main)." >&2; exit 1; }
fi

sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

echo "buzz-mcp: installing from $REPO @ $REF ..."
rm -rf "$DEST/src"
mkdir -p "$DEST" "$BINDIR"
git clone --depth 1 --branch "$REF" "$REPO" "$DEST/src" >/dev/null 2>&1 || {
  echo "buzz-mcp install: git clone failed ($REPO @ $REF). Check network/access and retry." >&2; exit 1; }

PKG="$DEST/src"
# Verify the self-contained runtime actually landed (fail loud, not later with a cryptic import error).
[ -f "$PKG/dist/buzz-mcp.mjs" ]  || { echo "buzz-mcp install: dist/buzz-mcp.mjs missing at $PKG (unexpected layout for ref '$REF' — needs v0.2.2+)." >&2; exit 1; }
[ -f "$PKG/dist/wirelogin.mjs" ] || { echo "buzz-mcp install: dist/wirelogin.mjs missing at $PKG (needs v0.2.2+)." >&2; exit 1; }
# Prove the bundle loads on THIS Node before we call it installed — catches a bad Node or a corrupt clone now.
node --check "$PKG/dist/buzz-mcp.mjs"  || { echo "buzz-mcp install: dist/buzz-mcp.mjs failed to parse on this Node ($(node -v)). Node >= 20 required." >&2; exit 1; }
node --check "$PKG/dist/wirelogin.mjs" || { echo "buzz-mcp install: dist/wirelogin.mjs failed to parse on this Node ($(node -v)). Node >= 20 required." >&2; exit 1; }

# sha256: the installed bundles must match the committed dist/SHA256SUMS (what CI proved is the
# reproducible build of the reviewed source) — and, for a release tag, the SHA256SUMS published on
# the GitHub release. A mismatch aborts the install.
SUMS="$PKG/dist/SHA256SUMS"
[ -f "$SUMS" ] || { echo "buzz-mcp install: dist/SHA256SUMS missing at $PKG — refusing an unverifiable install." >&2; exit 1; }
for f in buzz-mcp.mjs wirelogin.mjs; do
  want="$(awk -v f="dist/$f" '$2==f || $2=="*"f {print $1}' "$SUMS")"
  got="$(sha256_of "$PKG/dist/$f")"
  [ -n "$want" ] && [ "$want" = "$got" ] || { echo "buzz-mcp install: sha256 mismatch for dist/$f (expected ${want:-<none>}, got $got) — refusing to install." >&2; exit 1; }
done
case "$REPO" in
  https://github.com/*)
    slug="${REPO#https://github.com/}"; slug="${slug%.git}"
    if command -v curl >/dev/null 2>&1 && [ "$REF" != "main" ]; then
      if rel="$(curl -fsSL "https://github.com/$slug/releases/download/$REF/SHA256SUMS" 2>/dev/null)"; then
        [ "$rel" = "$(cat "$SUMS")" ] || { echo "buzz-mcp install: the release's SHA256SUMS for $REF differs from the tag's dist/SHA256SUMS — refusing to install." >&2; exit 1; }
        echo "buzz-mcp: sha256 verified against the $REF release."
      else
        echo "buzz-mcp: (no release asset for $REF — verified against the tag's dist/SHA256SUMS only)"
      fi
    fi;;
esac
echo "buzz-mcp: sha256 OK — buzz-mcp.mjs $(sha256_of "$PKG/dist/buzz-mcp.mjs")"

# PATH wrappers → run the self-contained bundles (no node_modules needed).
cat > "$BINDIR/buzz-mcp" <<EOF
#!/usr/bin/env bash
exec node "$PKG/dist/buzz-mcp.mjs" "\$@"
EOF
chmod +x "$BINDIR/buzz-mcp"

cat > "$BINDIR/buzz-mcp-login" <<EOF
#!/usr/bin/env bash
# One-time "post as me" email login (Route A / wire-sign). Needs BUZZ_EKAM_CLIENT_ID.
exec node "$PKG/dist/wirelogin.mjs" "\$@"
EOF
chmod +x "$BINDIR/buzz-mcp-login"

echo "buzz-mcp: installed → $BINDIR/buzz-mcp  (+ buzz-mcp-login)"
case ":$PATH:" in
  *":$BINDIR:"*) ;;
  *) echo "buzz-mcp: add $BINDIR to your PATH (e.g. echo 'export PATH=\"$BINDIR:\$PATH\"' >> ~/.zshrc)";;
esac
