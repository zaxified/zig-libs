#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Builds target/trie_bench_cpp, the darts-clone / marisa-trie side of
# `zig build bench-trie` (see main.cpp). Benchmark instrument only: the foreign
# sources are fetched into tools/trie-cpp-vendor/ (gitignored) at pinned tags, checked against
# pinned commit ids, and compiled in place with one g++ call. None of their
# build systems (CMake, autotools) is used, and nothing from there is ever
# shipped or copied into the repository. Licences: darts-clone BSD-2-Clause;
# marisa-trie BSD-2-Clause OR LGPL-2.1-or-later (we use it under BSD-2-Clause).
#
# Needs: git, g++ (C++17), network on the first run only.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Outside modules/: check-copyleft walks modules/ and marisa's COPYING names
# the LGPL (the same reason tools/zstd-silesia lives there).
vendor="$(cd "$here/../../../.." && pwd)/tools/trie-cpp-vendor"
out="$here/target/trie_bench_cpp"

# name  url  tag  commit (the commit the tag must resolve to)
darts_url=https://github.com/s-yata/darts-clone.git
darts_tag=v0.32h
darts_commit=87b71afd6cf784953e3c08f24c64203397f3b724
marisa_url=https://github.com/s-yata/marisa-trie.git
marisa_tag=v0.3.1
marisa_commit=3e87d53b78e15f2f43783d5e376561a8c9722051

fetch() { # dir url tag commit
    local dir="$vendor/$1" url="$2" tag="$3" want="$4"
    if [ ! -d "$dir/.git" ]; then
        mkdir -p "$vendor"
        git clone --quiet --depth 1 --branch "$tag" "$url" "$dir"
    fi
    local have
    have="$(git -C "$dir" rev-parse HEAD)"
    if [ "$have" != "$want" ]; then
        echo "build.sh: $1 is at $have, expected $want ($tag); remove $dir and retry" >&2
        exit 1
    fi
    if [ -n "$(git -C "$dir" status --porcelain)" ]; then
        echo "build.sh: $dir has local modifications; remove it and retry" >&2
        exit 1
    fi
}

fetch darts-clone "$darts_url" "$darts_tag" "$darts_commit"
fetch marisa-trie "$marisa_url" "$marisa_tag" "$marisa_commit"

m="$vendor/marisa-trie"

# marisa-trie picks its rank/select code by MARISA_USE_* macros (its CMake sets
# them from -march=native probes; we mirror that: the best level the host has).
native="$(g++ -march=native -dM -E -x c++ /dev/null)"
has() { grep -q "#define $1 1" <<<"$native"; }
marisa_isa=()
if has __BMI2__; then marisa_isa=(-DMARISA_USE_BMI2)
elif has __BMI__; then marisa_isa=(-DMARISA_USE_BMI)
elif has __SSE4_2__; then marisa_isa=(-DMARISA_USE_SSE4_2)
elif has __SSSE3__; then marisa_isa=(-DMARISA_USE_SSSE3)
fi
echo "build.sh: marisa isa flags: ${marisa_isa[*]:-(none)}" >&2

mkdir -p "$here/target"
# Flags: -O3 -march=native -DNDEBUG (no asserts, as a release build of both
# libraries); -flto because it is free with one translation unit list;
# -std=c++17 (marisa needs >= 17; with 20 it would use std::popcount, the
# builtin is the same instruction). -isystem: vendor warnings stay quiet.
g++ -O3 -march=native -DNDEBUG -std=c++17 -flto \
    "${marisa_isa[@]}" \
    -isystem "$vendor/darts-clone/include" -isystem "$m/include" -isystem "$m/lib" \
    -o "$out" \
    "$here/main.cpp" \
    "$m/lib/marisa/agent.cc" \
    "$m/lib/marisa/keyset.cc" \
    "$m/lib/marisa/trie.cc" \
    "$m/lib/marisa/grimoire/io/mapper.cc" \
    "$m/lib/marisa/grimoire/io/reader.cc" \
    "$m/lib/marisa/grimoire/io/writer.cc" \
    "$m/lib/marisa/grimoire/trie/louds-trie.cc" \
    "$m/lib/marisa/grimoire/trie/tail.cc" \
    "$m/lib/marisa/grimoire/vector/bit-vector.cc"
echo "build.sh: built $out" >&2
