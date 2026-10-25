#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Builds target/lmdb_bench, the LMDB side of `zig build bench-kvtree` (see
# main.c). Benchmark instrument only: links the host's LMDB shared library
# (Ubuntu/Debian package liblmdb0); no LMDB source is fetched, compiled or
# copied. LMDB is under the OpenLDAP Public License 2.8.
#
# Needs: gcc, liblmdb.so.0.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lib=""
for d in /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu /usr/lib64 /usr/lib; do
    if [ -e "$d/liblmdb.so.0" ]; then lib="$d/liblmdb.so.0"; break; fi
done
if [ -z "$lib" ]; then
    echo "lmdb_bench: liblmdb.so.0 not found (install liblmdb0, or BENCH_LMDB=0)" >&2
    exit 1
fi
mkdir -p "$here/target"
gcc -O2 -Wall -Wextra -o "$here/target/lmdb_bench" "$here/main.c" "$lib"
