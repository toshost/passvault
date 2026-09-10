#!/usr/bin/env bash
# Regenerates extension/lib/ from web/. Not a build step in the normal
# sense (no bundler, no transpilation) — just keeps the extension's copy
# of the crypto trust boundary in sync with the one true source at
# web/crypto.js, since a Manifest V3 classic (non-module) service worker
# can't `import` an ES module but CAN `importScripts()` a plain script.
# Every top-level `export ` is stripped so the file's declarations become
# ambient globals within the worker's scope instead — nothing else about
# the file changes. Run this after any edit to web/crypto.js, before
# loading or packaging the extension.
set -euo pipefail
cd "$(dirname "$0")/.."

SRC_CRYPTO="web/crypto.js"
DST_CRYPTO="extension/lib/crypto.js"
SRC_WASM="web/vendor/hash-wasm/argon2.umd.min.js"
DST_WASM="extension/lib/vendor/hash-wasm/argon2.umd.min.js"

if [ ! -f "$SRC_CRYPTO" ]; then
  echo "error: $SRC_CRYPTO not found — run this from the repo root or scripts/" >&2
  exit 1
fi

{
  echo "// GENERATED FILE — do not edit directly."
  echo "// Source: $SRC_CRYPTO, via scripts/sync-extension-libs.sh."
  echo "// Every top-level 'export ' is stripped (classic service worker script,"
  echo "// loaded via importScripts() — no ES module system available), so each"
  echo "// function below becomes an ambient global within the worker's scope."
  echo "// Re-run this script after any change to $SRC_CRYPTO."
  echo
  sed -E 's/^export (async function|function|const)/\1/' "$SRC_CRYPTO"
} > "$DST_CRYPTO"

mkdir -p "$(dirname "$DST_WASM")"
cp "$SRC_WASM" "$DST_WASM"

echo "synced $SRC_CRYPTO -> $DST_CRYPTO"
echo "synced $SRC_WASM -> $DST_WASM"
