#!/usr/bin/env bash
# install.sh — curl-installer for @ola/buzz-mcp (v0.2.2+; dependency-free, no npm).
#
#   curl -fsSL https://raw.githubusercontent.com/ola-krutrim/buzz-mcp/main/install.sh | bash
#
# Installs the Buzz MCP shim under ~/.local/share/buzz-mcp and puts `buzz-mcp` +
# `buzz-mcp-login` on PATH. The shim ships as a SELF-CONTAINED bundle (deps inlined
# in dist/), so there is NO `npm install` step and no npm/registry needed — the
# clone is the whole install. Pin a tag with BUZZ_MCP_REF=<tag>.
set -euo pipefail

REPO="${BUZZ_MCP_REPO:-https://github.com/ola-krutrim/buzz-mcp.git}"
REF="${BUZZ_MCP_REF:-main}"
DEST="${BUZZ_MCP_DIR:-$HOME/.local/share/buzz-mcp}"
BINDIR="${BUZZ_MCP_BIN:-$HOME/.local/bin}"

command -v node >/dev/null 2>&1 || { echo "buzz-mcp install: Node >= 20 required (not found on PATH)." >&2; exit 1; }
command -v git  >/dev/null 2>&1 || { echo "buzz-mcp install: git required (not found on PATH)." >&2; exit 1; }
# NOTE: npm is intentionally NOT required — the shim is bundled (deps inlined). The old
# npm-install step was the #1 silent onboarding failure (blocked registry/proxy → cryptic
# ERR_MODULE_NOT_FOUND for nostr-tools). Bundling removes that class of failure entirely.

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
