#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Build the kv probe (Zig) and the rosedb / bitcask / nutsdb probes (Go), run
# P1 (read-only reader beside a writer), P2 (torn tail), P3 / P3b (flipped byte)
# and print the summary. Backs the kv "Ahead" claims (read-only open, torn tail).
# Usage:  hw run --slots 1 --mem 6G --name kv-lead --quiet 600 -- bash modules/kv/tools/lead_probe/run.sh
# Needs zig 0.17 and go with an offline module cache holding the pins in go/*/go.mod.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
w=$root/.zig-cache/kv-lead-probe
mkdir -p "$w/bin"
cd "$root"
zig build-exe -OReleaseSafe -fllvm --cache-dir "$w/zc" -femit-bin="$w/bin/kv" \
  --dep kv -Mroot="$here/zig/probe.zig" -Mkv=modules/kv/src/root.zig
# Three modules (three different dependency pins, so one go.mod is not possible);
# the shared common.go is kept once and copied next to each adapter for the build.
for s in rosedb bitcask nutsdb; do
  mkdir -p "$w/go/$s"
  cp "$here/go/$s/adapter.go" "$here/go/$s/go.mod" "$here/go/$s/go.sum" "$here/common.go" "$w/go/$s/"
  (cd "$w/go/$s" && GOPROXY=off GOFLAGS=-mod=readonly go build -o "$w/bin/$s" .)
done
d="python3 -I $here/drive.py $w"
$d p1
$d p2
$d p3
$d p3b
$d p2z nutsdb
$d summary
