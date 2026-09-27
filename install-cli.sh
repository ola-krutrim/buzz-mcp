#!/usr/bin/env bash
# install-cli.sh — curl-installer for the Buzz CLI (`buzz`): prebuilt, no Rust toolchain, no source.
#
#   curl -fsSL https://raw.githubusercontent.com/ola-krutrim/buzz-mcp/main/install-cli.sh | bash
#
# Downloads the `buzz` binary for your OS/arch from the buzz-cli GitHub Release,
# verifies its sha256 against the published sha256sums.txt, and installs it to
# ~/.local/bin/buzz. Pin a version with BUZZ_CLI_VERSION=buzz-cli-vX.Y.Z.
set -euo pipefail

REPO="${BUZZ_CLI_REPO:-ola-krutrim/buzz-mcp}"
VERSION="${BUZZ_CLI_VERSION:-buzz-cli-v0.1.1}"     # pinned; bump per release
BINDIR="${BUZZ_CLI_BIN:-$HOME/.local/bin}"
BASE="https://github.com/$REPO/releases/download/$VERSION"

# --- detect OS/arch → asset name (must match the release assets) ---
os=$(uname -s); arch=$(uname -m)
case "$os" in
  Darwin) OS=darwin ;;
  Linux)  OS=linux ;;
  *) echo "buzz-cli install: unsupported OS '$os'. Windows: download buzz-windows-x64.exe from $BASE" >&2; exit 1 ;;
esac
case "$arch" in
  arm64|aarch64) ARCH=arm64 ;;
  x86_64|amd64)  ARCH=x64 ;;
  *) echo "buzz-cli install: unsupported arch '$arch'." >&2; exit 1 ;;
esac
ASSET="buzz-${OS}-${ARCH}"

command -v curl >/dev/null 2>&1 || { echo "buzz-cli install: curl required." >&2; exit 1; }

echo "buzz-cli: fetching $ASSET from $REPO @ $VERSION ..."
mkdir -p "$BINDIR"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL "$BASE/$ASSET"          -o "$tmp/buzz"       || { echo "buzz-cli install: download failed ($BASE/$ASSET). Check the version/asset exists." >&2; exit 1; }
curl -fsSL "$BASE/sha256sums.txt"  -o "$tmp/sums"       || { echo "buzz-cli install: could not fetch sha256sums.txt." >&2; exit 1; }

# --- verify sha256 (fail loud before we install anything) ---
want=$(grep " ${ASSET}\$" "$tmp/sums" | awk '{print $1}' | head -1)
[ -n "$want" ] || { echo "buzz-cli install: $ASSET not listed in sha256sums.txt." >&2; exit 1; }
if command -v shasum >/dev/null 2>&1; then got=$(shasum -a256 "$tmp/buzz" | awk '{print $1}')
else got=$(sha256sum "$tmp/buzz" | awk '{print $1}'); fi
[ "$got" = "$want" ] || { echo "buzz-cli install: sha256 MISMATCH ($got != $want) — refusing to install." >&2; exit 1; }
echo "buzz-cli: sha256 verified ✓"

install -m 0755 "$tmp/buzz" "$BINDIR/buzz"

# --- macOS: strip the quarantine xattr so Gatekeeper doesn't block the binary the user just
#     deliberately downloaded via this installer. (v1 ships un-notarized; this is the documented path.)
if [ "$OS" = darwin ]; then xattr -d com.apple.quarantine "$BINDIR/buzz" 2>/dev/null || true; fi

echo "buzz-cli: installed → $BINDIR/buzz  ($("$BINDIR/buzz" --version 2>/dev/null || echo 'run: buzz --version'))"
case ":$PATH:" in
  *":$BINDIR:"*) ;;
  *) echo "buzz-cli: add $BINDIR to your PATH (e.g. echo 'export PATH=\"$BINDIR:\$PATH\"' >> ~/.zshrc)";;
esac
