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

Built: zig-out/bin/mls-chat

Three terminals:

  ./zig-out/bin/mls-chat relay                      # the delivery service
  ./zig-out/bin/mls-chat join --name alice --create # creates the group
  ./zig-out/bin/mls-chat join --name bob            # waits for a Welcome

then type  /invite bob  in alice's terminal.

See README.md for what it does and does not do.
MSG
