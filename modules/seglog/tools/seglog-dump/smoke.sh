#!/usr/bin/env bash
# Smoke test of seglog-dump: writes a 200-record log over 4 segments (the
# first two compressed to .zst) with interop-seglog, runs every subcommand and
# checks the output. Run from the repository root; scratch under .zig-cache/.
#   modules/seglog/tools/seglog-dump/smoke.sh
set -euo pipefail
zig build install-dump-seglog install-interop-seglog
D=zig-out/dump/seglog-dump
S=.zig-cache/seglog-dump-smoke
rm -f "$S"/* 2>/dev/null || true
rmdir "$S" 2>/dev/null || true
mkdir -p .zig-cache
zig-out/interop/interop-seglog write "$S" 200 >/dev/null
fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }
has() { grep -q -- "$2" <<<"$1" || fail "$3: missing '$2' in: $1"; }

out=$($D segments "$S"); echo "$out"
[ "$(wc -l <<<"$out")" -ge 5 ] || fail "segments: want header + >= 4 rows"
has "$out" $'^1\tzst\t1\t' segments; has "$out" $'^3\traw\t129\t' segments
has "$out" $'^4\traw\t193\t' segments

out=$($D verify "$S"); echo "$out"
has "$out" '^records 200$' verify; has "$out" '^last_lsn 200$' verify; has "$out" '^clean$' verify

out=$($D seek "$S" --lsn 100); echo "$out"
has "$out" 'segment 2 .* lsn 100$' 'seek lsn'
out=$($D seek "$S" --time 150); echo "$out"
has "$out" 'lsn 150$' 'seek time'
if $D seek "$S" --lsn 9999 >/dev/null 2>&1; then fail "seek past the end should exit 1"; fi

out=$($D get "$S" --lsn 100); echo "$out"
has "$out" '^lsn 100$' get; has "$out" '^ts 100$' get; has "$out" '^payload 000000000100;' get
out=$($D get "$S" --lsn 100 --hex); has "$out" '^payload 3030303030303030303130303b' 'get hex'
if $D get "$S" --lsn 9999 >/dev/null 2>&1; then fail "get past the end should exit 1"; fi

# rebuild-manifest: refused while a MANIFEST decodes, works once it is gone
if $D rebuild-manifest "$S" >/dev/null 2>&1; then fail "rebuild must refuse a good MANIFEST"; fi
rm "$S/MANIFEST"
out=$($D rebuild-manifest "$S"); echo "$out"
has "$out" 'rebuilt over 4 segments (1..4)' rebuild
out=$($D verify "$S"); has "$out" '^clean$' 'verify after rebuild'
for f in "$S"/*; do rm "$f"; done
rmdir "$S"
echo "SMOKE OK"
