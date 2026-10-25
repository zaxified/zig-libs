#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Build the three probes (kvtree Zig, bbolt Go, LMDB C), make a pristine store
# per side, then run the damaged-file experiment and print the summary table.
# Backs the kvtree "never crashes on a damaged file" **Ahead:** claim.
# Usage:  hw run --slots 1 --mem 6G --name kvtree-corrupt --quiet 600 -- bash modules/kvtree/tools/corrupt_probe/run.sh [M]
# M = trials per (store, mode) cell, default 3000. Needs zig 0.17, go (offline,
# module cache holding go.etcd.io/bbolt v1.5.0), gcc and /usr/lib/x86_64-linux-gnu/liblmdb.so.0.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
M=${1:-3000}
w=$root/.zig-cache/corrupt-probe
mkdir -p "$w/bin" "$w/trials"
cd "$root"
m=modules
zig build-exe -OReleaseSafe -fllvm --cache-dir "$w/zc" -femit-bin="$w/bin/kvtree" \
  --dep kvtree -Mroot="$here/kvtree/corrupt.zig" \
  --dep kv --dep crc32 -Mkvtree=$m/kvtree/src/root.zig \
  -Mkv=$m/kv/src/root.zig -Mcrc32=$m/crc32/src/root.zig
(cd "$here/bbolt" && GOPROXY=off GOFLAGS=-mod=readonly go build -o "$w/bin/bbolt" .)
gcc -O2 -Wall -o "$w/bin/lmdb" "$here/lmdb/main.c" /usr/lib/x86_64-linux-gnu/liblmdb.so.0
for s in kvtree bbolt lmdb; do
  rm -f "$w/base/$s"/* 2>/dev/null || true
  mkdir -p "$w/base/$s"
  "$w/bin/$s" build "$w/base/$s"
done
python3 -I "$here/run.py" "$w" "$M" kvtree,kvtree-mmap,bbolt,lmdb
rmdir "$w/trials" 2>/dev/null || true
