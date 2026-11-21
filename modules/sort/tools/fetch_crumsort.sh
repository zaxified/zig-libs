#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Fetch crumsort 1.2.1.3 (scandum/crumsort, Unlicense) into
# .zig-cache/bench-sort/crumsort_src/ (outside the module tree) for `BENCH_CRUMSORT=.zig-cache/bench-sort/crumsort_src zig build bench-sort`
# (the C side of the "alt" column, see README). The sources are checked against
# the digests below; nothing from there is vendored.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
commit=d21d7c3aa13212c234967a9aaf037690825916be
dest=../../../.zig-cache/bench-sort/crumsort_src
mkdir -p "$dest"
cd "$dest"
for f in quadsort.h quadsort.c crumsort.c crumsort.h; do
    curl -fsSL -o "$f" "https://raw.githubusercontent.com/scandum/crumsort/$commit/src/$f"
done
sha256sum -c - <<'SUMS'
56dc95c382ac0d961f4a6efe1db9293ba1bd58e919da323933a7b524f23c0185  crumsort.c
75f8031cf24d7b5bb2b30e60b687bdc513c6b6de8b29394f9649c47d807ba6c7  crumsort.h
10a9e8ee36ed7d5b9ff7d59a61af9782a58834ca85260380da83086c7df97be0  quadsort.c
8645dea4fbd2eff549d6230aae9482102d038f512c75084459c34c3a16b044ce  quadsort.h
SUMS
