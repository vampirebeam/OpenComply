#!/bin/sh
# Installs the opencomply binary for this machine from the GitHub release that matches this skill, after checking
# its SHA-256. User-level only: no sudo, no PATH changes. Prints the binary path on the last line.
# Supported: Linux x86_64, macOS Apple Silicon. Override the version with OPENCOMPLY_VERSION=X.Y.Z.
set -eu

VERSION="${OPENCOMPLY_VERSION:-0.2.0}"
REPO="vampirebeam/OpenComply"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
  Darwin-arm64) TARGET="aarch64-apple-darwin" ;;
  *) echo "opencomply: no release build for $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac

DEST="${XDG_DATA_HOME:-$HOME/.local/share}/opencomply/v$VERSION"
BIN="$DEST/opencomply"
if [ -x "$BIN" ] && "$BIN" --version 2>/dev/null | grep -qx "opencomply $VERSION"; then
  echo "$BIN"
  exit 0
fi

NAME="opencomply-v$VERSION-$TARGET"
URL="https://github.com/$REPO/releases/download/v$VERSION/$NAME.tar.gz"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget --https-only -q "$1" -O "$2"
  else
    echo "opencomply: curl or wget is required" >&2
    exit 1
  fi
}
fetch "$URL" "$TMP/$NAME.tar.gz"
fetch "$URL.sha256" "$TMP/$NAME.tar.gz.sha256"

EXPECTED="$(cut -d' ' -f1 "$TMP/$NAME.tar.gz.sha256")"
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "$TMP/$NAME.tar.gz" | cut -d' ' -f1)"
else
  ACTUAL="$(shasum -a 256 "$TMP/$NAME.tar.gz" | cut -d' ' -f1)"
fi
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "opencomply: SHA-256 mismatch for $NAME.tar.gz — not installed" >&2
  exit 1
fi

tar -xzf "$TMP/$NAME.tar.gz" -C "$TMP"
mkdir -p "$DEST"
cp "$TMP/$NAME/opencomply" "$BIN"
cp "$TMP/$NAME/LICENSE" "$TMP/$NAME/NOTICE" "$TMP/$NAME/THIRD-PARTY-NOTICES.txt" "$DEST/"
chmod 755 "$BIN"
"$BIN" --version >/dev/null
echo "$BIN"
