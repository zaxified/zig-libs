#!/usr/bin/env bash
# Fetch the three @node-idempotency packages (pinned, sha512-checked), lay
# them out as node_modules under .zig-cache, run probe.js with bun. Nothing
# is installed and no package script runs (none of the three has one).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../../.." && pwd)
w="$repo/.zig-cache/idem-lead-probe"
mkdir -p "$w/tgz" "$w/node_modules/@node-idempotency"
while read -r name ver sri; do
    t="$w/tgz/$name-$ver.tgz"
    [ -f "$t" ] || curl -fsS -o "$t" "https://registry.npmjs.org/@node-idempotency/$name/-/$name-$ver.tgz"
    got="sha512-$(openssl dgst -sha512 -binary "$t" | base64 -w0)"
    [ "$got" = "$sri" ] || { echo "integrity mismatch: $name $ver" >&2; exit 1; }
    d="$w/node_modules/@node-idempotency/$name"
    mkdir -p "$d"
    tar -xzf "$t" -C "$d" --strip-components=1
done <<'PKGS'
core 1.1.0 sha512-EwsGvkn81pssFB56eT94ESneT7Dl4U/YZ21yx8kT3hLzz7FkdmaAfxhOLGn+3Jyh3CjX2Y9z5WNgP/IGc6aOsg==
storage 1.0.5 sha512-0qWmQDbmGog5TvuAi3ixPvCEokYArSHYvKsoB3nPQBw6SmgeiNgDtNaXLHZ7/mNTX8fFfe/2LzBbTWM5b82AOg==
storage-adapter-memory 1.0.5 sha512-5++IvsWKAd3eoR1UdZIV5k7XWt6csLHK7b/2iTqg/iv0au83o/cnC5T8vXhoLAtOyDFY2/FSQxt47eKILHJ3PQ==
PKGS
cp "$here/probe.js" "$w/probe.js"
cd "$w"
bun="${BUN:-$(command -v bun || echo "$HOME/.bun/bin/bun")}"
"$bun" --version
"$bun" probe.js
