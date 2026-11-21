#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Fetch Highway 1.3.0 (google/highway, Apache-2.0; vqsort lives in hwy/contrib/sort)
# into .zig-cache/bench-sort/vqsort_src/ (outside the module tree) for
# `BENCH_VQSORT=.zig-cache/bench-sort/vqsort_src/highway-1.3.0 zig build bench-sort`
# (the C++ side of the "alt" column, see README). The tarball is checked against
# the digest below; nothing from there is vendored.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
dest=../../../.zig-cache/bench-sort/vqsort_src
mkdir -p "$dest"
cd "$dest"
curl -fsSL -o hwy.tar.gz https://github.com/google/highway/archive/refs/tags/1.3.0.tar.gz
echo "07b3c1ba2c1096878a85a31a5b9b3757427af963b1141ca904db2f9f4afe0bc2  hwy.tar.gz" | sha256sum -c -
tar xzf hwy.tar.gz
