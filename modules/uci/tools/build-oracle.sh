#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Builds the libuci-linked `oracle_dump` and the interop corpus into
# <repo>/.zig-cache/uci-differential, the inputs `zig build interop-uci` needs.
#
#   build-oracle.sh
#
# Env:
#   BASE  scratch root (default: <repo>/.zig-cache/uci-differential, derived from
#         this script's own location, like diff_run.sh)
#
# Idempotent: an existing checkout already at UCI_SHA is reused, everything else
# (header, binary, corpus) is cheap and rewritten. ⚠ UCI_SHA is the libuci the
# committed capture (src/testdata/libuci_capture.zig) was taken with: moving it
# means re-capturing, so it changes together with `interop-uci -- --capture`.
# libuci is LGPL: the source lands only in the droppable cache, never in the repo.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
BASE="${BASE:-$REPO/.zig-cache/uci-differential}"
UCI_SHA=74f6277aabffc943d026f406df57c22595134c42
SRC="$BASE/ref/uci"

mkdir -p "$BASE/ref" "$BASE/out" "$BASE/probes" "$SRC"

if [ "$(git -C "$SRC" rev-parse HEAD 2>/dev/null || true)" = "$UCI_SHA" ]; then
    echo "build-oracle: libuci $UCI_SHA already checked out in $SRC"
else
    echo "build-oracle: fetching libuci $UCI_SHA"
    [ -d "$SRC/.git" ] || git init -q "$SRC"
    # A shallow fetch by sha works on both hosts; the GitHub mirror is the
    # fallback when git.openwrt.org is down or unreachable from the runner.
    fetched=0
    for url in https://git.openwrt.org/project/uci.git https://github.com/openwrt/uci.git; do
        if git -C "$SRC" fetch -q --depth 1 "$url" "$UCI_SHA"; then
            fetched=1
            break
        fi
        echo "build-oracle: fetch from $url failed" >&2
    done
    [ "$fetched" = 1 ] || { echo "build-oracle: cannot fetch libuci from any mirror" >&2; exit 1; }
    git -C "$SRC" checkout -q FETCH_HEAD
    got="$(git -C "$SRC" rev-parse HEAD)"
    [ "$got" = "$UCI_SHA" ] || { echo "build-oracle: checked out $got, expected $UCI_SHA" >&2; exit 1; }
fi

echo "build-oracle: writing uci_config.h"
printf '/* audit */\n' > "$SRC/uci_config.h"

echo "build-oracle: compiling oracle_dump"
mkdir -p "$BASE/ref/root/etc/config"
(cd "$SRC" && gcc -O1 -std=gnu99 -I. -DUCI_PREFIX='"'"$BASE/ref/root"'"' \
    -o "$BASE/out/oracle_dump" "$HERE/oracle_dump.c" \
    libuci.c file.c util.c delta.c parse.c)

echo "build-oracle: generating corpus.json"
(cd "$REPO" && python3 modules/uci/tools/libuci_corpus.py > "$BASE/corpus.json")

echo "build-oracle: done ($BASE/out/oracle_dump, $BASE/corpus.json)"
