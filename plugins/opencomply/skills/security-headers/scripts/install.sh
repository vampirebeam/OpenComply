#!/bin/sh
# Installs the opencomply CLI from the GitHub release that matches this script, after checking its SHA-256, so that
# `opencomply` works in any new terminal. User-level only (no sudo): the binary goes to
# ~/.local/share/opencomply/vX.Y.Z and is linked as ~/.local/bin/opencomply; older versions are removed.
# `--uninstall` removes both. Prints the command path on the last line.
# Supported: Linux x86_64, macOS Apple Silicon. Override the version with OPENCOMPLY_VERSION=X.Y.Z.
set -eu

VERSION="${OPENCOMPLY_VERSION:-0.2.4}"
REPO="vampirebeam/OpenComply"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}/opencomply"
LINK="$HOME/.local/bin/opencomply"

if [ "${1:-}" = "--uninstall" ]; then
  [ -L "$LINK" ] && rm -f "$LINK"
  rm -rf "$DATA"
  echo "opencomply: removed"
  exit 0
fi

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
  Darwin-arm64) TARGET="aarch64-apple-darwin" ;;
  *) echo "opencomply: no release build for $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac

DEST="$DATA/v$VERSION"
BIN="$DEST/opencomply"

if ! { [ -x "$BIN" ] && "$BIN" --version 2>/dev/null | grep -qx "opencomply $VERSION"; }; then
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
  rm -rf "$DEST"
  mkdir -p "$DEST"
  cp "$TMP/$NAME/opencomply" "$TMP/$NAME/LICENSE" "$TMP/$NAME/NOTICE" "$TMP/$NAME/THIRD-PARTY-NOTICES.txt" "$DEST/"
  chmod 755 "$BIN"
  "$BIN" --version >/dev/null
fi

for old in "$DATA"/v*; do
  [ "$old" = "$DEST" ] || rm -rf "$old"
done
mkdir -p "$(dirname "$LINK")"
ln -sf "$BIN" "$LINK"

case ":$PATH:" in
  *":$HOME/.local/bin:"*) ;;
  *) echo "opencomply: add ~/.local/bin to PATH to run 'opencomply' from any terminal (then restart open terminals, including those inside VS Code or Claude Code), e.g. in ~/.profile:" >&2
     echo '  export PATH="$HOME/.local/bin:$PATH"' >&2 ;;
esac
echo "$LINK"
