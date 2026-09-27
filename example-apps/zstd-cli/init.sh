#!/usr/bin/env bash
# Fetch what this app needs and build it. One command, from a fresh copy.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

NEED_ZIG=0.16.0

have() { command -v "$1" >/dev/null 2>&1; }

if ! have zig; then
    cat >&2 <<MSG
init.sh: zig is not on PATH.

This app needs Zig $NEED_ZIG. Install it from https://ziglang.org/download/
(or via your version manager) and run this script again. Nothing is installed
for you: picking where a toolchain lives is your decision, not this script's.
MSG
    exit 1
fi

got="$(zig version)"
if [ "$got" != "$NEED_ZIG" ]; then
    echo "init.sh: found zig $got, this app is written against $NEED_ZIG." >&2
    echo "         A different minor version will most likely fail to build." >&2
    echo "         Continuing anyway — pass --strict to make this an error." >&2
    [ "${1:-}" = "--strict" ] && exit 1
fi

# The zig-libs dependency is pinned in build.zig.zon by URL and hash; this
# fetches it into the local cache and verifies the hash before anything builds.
echo "init.sh: fetching dependencies…"
zig build --fetch

echo "init.sh: building (ReleaseFast)…"
zig build

cat <<MSG

Built: zig-out/bin/zstd

Try it:

  ./zig-out/bin/zstd -19 somefile          # -> somefile.zst
  ./zig-out/bin/zstd -d somefile.zst -o back
  ./zig-out/bin/zstd -l somefile.zst
  ./smoke.sh                               # checks it against a real zstd 1.5.7, if installed

See README.md for what it does and does not do.
MSG
