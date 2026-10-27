#!/bin/bash
# Build google/brotli's three shared libraries from source for `bench-brotli`,
# padded against the Intel JCC erratum like `zig build bench-brotli -Djcc-safe`
# pads our side (2026-10-27). Compiles the library sources with `zig cc` only;
# google's build system is never run.
#
#   tools/c_bench/build_libbrotli.sh <google/brotli checkout at v1.2.0> <out dir>
#   LIBBROTLI_DIR=<out dir> zig build bench-brotli -Djcc-safe
set -euo pipefail
src=$1
out=$2
mkdir -p "$out"
flags=(-O2 -fPIC -I"$src/c/include" -DNDEBUG -march=native -mbranches-within-32B-boundaries)
zig cc "${flags[@]}" -shared -o "$out/libbrotlicommon.so.1" -Wl,-soname,libbrotlicommon.so.1 "$src"/c/common/*.c
zig cc "${flags[@]}" -shared -o "$out/libbrotlienc.so.1" -Wl,-soname,libbrotlienc.so.1 "$src"/c/enc/*.c "$out/libbrotlicommon.so.1" -Wl,-rpath,"$out"
zig cc "${flags[@]}" -shared -o "$out/libbrotlidec.so.1" -Wl,-soname,libbrotlidec.so.1 "$src"/c/dec/*.c "$out/libbrotlicommon.so.1" -Wl,-rpath,"$out"
echo "built $out (google/brotli $(git -C "$src" describe --tags 2>/dev/null || echo '?'))"
