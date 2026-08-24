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

echo "init.sh: building (ReleaseSafe)…"
zig build

cat <<MSG

Built: zig-out/bin/timecapsule

Try it:

  ./zig-out/bin/timecapsule keygen --out alice
  echo "the eagle lands at midnight" > msg.txt
  ./zig-out/bin/timecapsule seal --to alice.pk --at +2m --in msg.txt --out msg.tc
  ./zig-out/bin/timecapsule open --key alice.sk --in msg.tc --out msg.out
      # → "still locked — round N publishes …" (exit 3); run it again in 2 minutes

See README.md for what it does and does not do.
MSG
