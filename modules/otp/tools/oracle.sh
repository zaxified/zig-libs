#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Differential oracle for the TOTP codes against karlseguin/otp.zig (MIT, Zig 0.16 target).
#
# WHY. The module's tests replay the RFC 4226 / 6238 vectors; this answers "what does another implementation print
# for THIS random secret, time, period and digit count". The other library is fetched here at a pinned commit into
# the repo's .zig-cache (never vendored, never committed) and compiled with this repository's zig.
#
# USAGE. modules/otp/tools/oracle.sh [cases] [seed]     (defaults: 20000 cases, seed 1)
# NEEDS. curl, zig 0.17.x on PATH, network on the first run. Run it through `hw run` like any heavy job.
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
PIN=923a1ecdc857080691f8c5a2c1e153ff87970876
D="$REPO/.zig-cache/otp-oracle/$PIN"
mkdir -p "$D/src"
for f in otp totp; do
    [ -s "$D/src/$f.zig" ] || curl -fsSL "https://raw.githubusercontent.com/karlseguin/otp.zig/$PIN/src/$f.zig" -o "$D/src/$f.zig"
done
zig build-exe -O ReleaseSafe \
    --dep otp --dep theirs -Mroot="$HERE/karlseguin_oracle.zig" \
    --dep base32 -Motp="$REPO/modules/otp/src/root.zig" \
    -Mbase32="$REPO/modules/base32/src/root.zig" \
    -Mtheirs="$D/src/totp.zig" \
    --cache-dir "$REPO/.zig-cache/otp-oracle/cache" -femit-bin="$D/oracle"
exec "$D/oracle" "$@"
