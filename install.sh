#!/usr/bin/env bash
# install.sh — curl-installer for @ola/buzz-mcp (v0; no npm registry).
#
#   curl -fsSL https://raw.githubusercontent.com/ola-krutrim/buzz-mcp/main/install.sh | bash
#
# Installs the Buzz MCP shim under ~/.local/share/buzz-mcp and puts a `buzz-mcp`
# command on PATH (the invocation the MCP config points at). Pin a tag with
# BUZZ_MCP_REF=<tag> for a reproducible install.
set -euo pipefail

REPO="${BUZZ_MCP_REPO:-https://github.com/ola-krutrim/buzz-mcp.git}"
REF="${BUZZ_MCP_REF:-main}"
DEST="${BUZZ_MCP_DIR:-$HOME/.local/share/buzz-mcp}"
BINDIR="${BUZZ_MCP_BIN:-$HOME/.local/bin}"

command -v node >/dev/null 2>&1 || { echo "buzz-mcp install: Node >= 20 required" >&2; exit 1; }
command -v git  >/dev/null 2>&1 || { echo "buzz-mcp install: git required" >&2; exit 1; }

echo "buzz-mcp: installing from $REPO @ $REF ..."
rm -rf "$DEST/src"
mkdir -p "$DEST" "$BINDIR"
git clone --depth 1 --branch "$REF" "$REPO" "$DEST/src" >/dev/null 2>&1

PKG="$DEST/src"
[ -f "$PKG/buzz-mcp.mjs" ] || { echo "buzz-mcp install: package not found at $PKG" >&2; exit 1; }
( cd "$PKG" && npm install --omit=dev --no-audit --no-fund >/dev/null 2>&1 )

# PATH wrapper → runs the installed shim.
cat > "$BINDIR/buzz-mcp" <<EOF
#!/usr/bin/env bash
exec node "$PKG/buzz-mcp.mjs" "\$@"
EOF
chmod +x "$BINDIR/buzz-mcp"

echo "buzz-mcp: installed → $BINDIR/buzz-mcp"
case ":$PATH:" in
  *":$BINDIR:"*) ;;
  *) echo "buzz-mcp: add $BINDIR to your PATH (e.g. echo 'export PATH=\"$BINDIR:\$PATH\"' >> ~/.zshrc)";;
esac
