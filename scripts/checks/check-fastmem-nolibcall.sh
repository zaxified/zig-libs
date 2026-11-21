#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# check-fastmem-nolibcall.sh — prove that `fastmem`'s own copy and set code
# never calls `memset` / `memcpy`.
#
# WHY THIS EXISTS
# ---------------
# `fastmem` IS the `memset` / `memcpy` of a libc-free binary. Its loops are
# written with `volatile` stores precisely so that the optimiser does not
# recognise them as a memset or memcpy idiom and replace them by a call to the
# function being defined: a dropped `volatile` turns `memset` into an
# infinite self-recursion that only an optimised build shows, as a hang or a
# stack overflow. No value test sees it in Debug.
#
# WHAT IT PROVES
# --------------
# A ReleaseFast object of `fastmem.set` / `fastmem.copy` (and everything they
# reach: setSmall, copySmall, setLarge, copyLarge) has no relocation against
# `memset`, `memcpy`, `memmove`, `bcmp` or `memcmp`. A control object with a plain runtime
# `@memset` / `@memcpy` must show them, otherwise the check is not looking at
# what it thinks it is. Native target only (the lowering is the same on every
# target; the CI lanes that matter run ReleaseFast).

set -euo pipefail

cd "$(dirname "$0")/../.."

OUT=".zig-cache/check-fastmem-nolibcall"
mkdir -p "$OUT"

zig build-obj -femit-bin="$OUT/probe.o" -OReleaseFast \
    --dep fastmem -Mroot=modules/fastmem/tools/libcall_probe.zig \
    -Mfastmem=modules/fastmem/src/root.zig
zig build-obj -femit-bin="$OUT/control.o" -OReleaseFast \
    -Mroot=modules/fastmem/tools/libcall_control.zig

# A call or a tail jump to the libc routines shows as a relocation naming them.
RE='R_[A-Z0-9_]+[ 	]+(memset|memcpy|memmove|bcmp|memcmp)([+-]|$)'

hits() { objdump -dr "$1" | grep -E "$RE" || true; }

CONTROL=$(hits "$OUT/control.o")
if [[ "$CONTROL" != *memset* || "$CONTROL" != *memcpy* ]]; then
    echo "FAIL: the control object does not call memset and memcpy, so this check is blind."
    echo "objdump lines matched: ${CONTROL:-none}"
    exit 1
fi
# And the probe must hold the code under test, not an empty object.
DIS=$(objdump -d "$OUT/probe.o")
if [[ "$DIS" != *'<probe_set>:'* || "$DIS" != *'<probe_copy>:'* ]]; then
    echo "FAIL: probe.o lacks probe_set / probe_copy; the disassembly is not of fastmem."
    exit 1
fi

BAD=$(hits "$OUT/probe.o")
if [ -n "$BAD" ]; then
    echo "FAIL: fastmem's set/copy code calls memset/memcpy in ReleaseFast:"
    printf '%s\n' "$BAD" | sed 's/^/  /'
    exit 1
fi

echo "check-fastmem-nolibcall: OK — no memset/memcpy relocation in fastmem.set/copy (the control shows both)."
