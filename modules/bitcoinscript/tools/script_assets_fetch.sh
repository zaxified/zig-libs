#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Fetches Bitcoin Core's BIP341/342 consensus corpus `script_assets_test.json`
# (bitcoin-core/qa-assets, MIT, 2244 entries, 9.2 MB) into
# `modules/bitcoinscript/tools/script_assets/`, a gitignored directory of its
# own: too big to vendor, and re-fetchable. `src/script_assets_test.zig` runs
# every entry when `BITCOINSCRIPT_SCRIPT_ASSETS` names the file:
#
#   modules/bitcoinscript/tools/script_assets_fetch.sh
#   BITCOINSCRIPT_SCRIPT_ASSETS=$PWD/modules/bitcoinscript/tools/script_assets/script_assets_test.json \
#     hw run --slots 1 -- scripts/modtest bitcoinscript --fresh
#
# The file is pinned by sha256; a mismatch deletes the download and fails.
# Needs: curl, sha256sum.
set -euo pipefail

URL="https://raw.githubusercontent.com/bitcoin-core/qa-assets/main/unit_test_data/script_assets_test.json"
SHA256="cd789a58ec45916e1721cdd14e82ca4c93100959f1cef4e229b22e3bf539f095"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="$HERE/script_assets"
FILE="$DEST/script_assets_test.json"

if [ -f "$FILE" ] && [ "$(sha256sum "$FILE" | cut -d' ' -f1)" = "$SHA256" ] && [ "${FORCE:-0}" != 1 ]; then
  echo "script_assets_test.json already present: $FILE"
  exit 0
fi

mkdir -p "$DEST"
curl -sSfL --max-time 300 -o "$FILE.part" "$URL"
got="$(sha256sum "$FILE.part" | cut -d' ' -f1)"
if [ "$got" != "$SHA256" ]; then
  rm -f "$FILE.part"
  echo "sha256 mismatch: got $got, want $SHA256" >&2
  exit 1
fi
mv "$FILE.part" "$FILE"
echo "fetched $FILE"
