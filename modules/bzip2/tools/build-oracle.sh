#!/usr/bin/env bash
# Builds the libbzip2 1.0.8 black-box driver `bzref` (tools/c_oracle/bzref.c)
# from the pinned upstream clone. Needs: git (first run only) and cc.
#
#   modules/bzip2/tools/build-oracle.sh        # -> .zig-cache/bzip2-oracle/bzref
#
# Run from the repository root. The clone is gitignored scratch under
# .zig-cache/survey/bzip2 (override with BZIP2_SRC=<dir>); it is never built
# with its own Makefile -- the seven library sources are compiled directly.
set -euo pipefail
src="${BZIP2_SRC:-.zig-cache/survey/bzip2}"
pin=f5dfc96063fef2d9c5446d0733867d899ef9b942
if [ ! -d "$src" ]; then
    git clone --depth 1 https://sourceware.org/git/bzip2.git "$src"
fi
head=$(git -C "$src" rev-parse HEAD)
if [ "$head" != "$pin" ]; then echo "warning: $src is at $head, not the pinned $pin" >&2; fi
out=.zig-cache/bzip2-oracle
mkdir -p "$out"
cc -O2 -D_FILE_OFFSET_BITS=64 -I"$src" -o "$out/bzref" \
    modules/bzip2/tools/c_oracle/bzref.c \
    "$src"/{blocksort,huffman,crctable,randtable,compress,decompress,bzlib}.c
echo "$out/bzref"
