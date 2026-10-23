#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Builds target/icu_bench, the ICU4C side of `zig build bench-numparse` (see
# main.cpp), against the SYSTEM libicu (pkg-config icu-i18n; a distro package,
# no ICU source is fetched or compiled). Needs g++ (C++17) and libicu-dev.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$here/target"
# -O3 -march=native as the other native sides; ICU itself is the distro build.
g++ -O3 -march=native -DNDEBUG -std=c++17 \
    $(pkg-config --cflags icu-i18n icu-uc) \
    -o "$here/target/icu_bench" "$here/main.cpp" \
    $(pkg-config --libs icu-i18n icu-uc)
echo "build.sh: built $here/target/icu_bench (ICU $(pkg-config --modversion icu-i18n))" >&2
