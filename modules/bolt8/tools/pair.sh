#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Pairs this repo's `bolt8` (via the compiled `interop` binary) against lnd's
# `brontide` (via the compiled `oraclebin`) back-to-back over two FIFOs.
#
# WHAT IT NEEDS: `interop` (built from `peer.zig`, this directory) and
# `oraclebin` (built by `fetch-oracle.sh`), both already compiled.
#
# Usage:
#   ZIG=<path/to/interop> GO=<path/to/oraclebin> ./pair.sh <zig-role: init|resp> [n]
# The Go side takes the complementary role.
set -u
ZIG="${ZIG:?set ZIG=<path to compiled interop>}"
GO="${GO:?set GO=<path to compiled oraclebin>}"

INIT_PRIV=1111111111111111111111111111111111111111111111111111111111111111
INIT_PUB=034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa
RESP_PRIV=2121212121212121212121212121212121212121212121212121212121212121
RESP_PUB=028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7

ZROLE="${1:-init}"
N="${2:-1100}"
D=$(mktemp -d "${TMPDIR:-.}/pair.XXXXXX")
mkfifo "$D/a" "$D/b"
# Hold both FIFOs open read-write so neither child blocks in open(2).
exec 8<>"$D/a"
exec 9<>"$D/b"

if [ "$ZROLE" = "init" ]; then
  timeout 25 "$ZIG" init "$INIT_PRIV" "$RESP_PUB" "$N" < "$D/b" > "$D/a" &
  ZPID=$!
  timeout 25 "$GO" -role resp -priv "$RESP_PRIV" -n "$N" < "$D/a" > "$D/b" &
  GPID=$!
else
  timeout 25 "$ZIG" resp "$RESP_PRIV" - "$N" < "$D/a" > "$D/b" &
  ZPID=$!
  timeout 25 "$GO" -role init -priv "$INIT_PRIV" -remote "$RESP_PUB" -n "$N" < "$D/b" > "$D/a" &
  GPID=$!
fi

wait $ZPID; ZR=$?
wait $GPID; GR=$?
rm -f "$D/a" "$D/b"; rmdir "$D"
echo "zig-role=$ZROLE zig_exit=$ZR go_exit=$GR"
[ $ZR -eq 0 ] && [ $GR -eq 0 ]
