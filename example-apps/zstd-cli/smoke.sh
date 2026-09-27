#!/usr/bin/env bash
# Run the command and check that it does what the real `zstd` does.
#
#   ./smoke.sh            # after ./init.sh, or after `zig build`
#
# Always: round trips at several levels, thread counts and window sizes,
# several files at once, --test, --list, and the verdicts on bad input
# (an existing output without -f, an unknown suffix, trailing garbage, a
# truncated frame). When a `zstd` of version 1.5.7 is on PATH, also the
# claim this app is built on: the same frames, byte for byte, and the same
# messages as that command, for the same options.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

BIN="$(pwd)/zig-out/bin/zstd"
[ -x "$BIN" ] || { echo "smoke: $BIN is not built — run ./init.sh first" >&2; exit 2; }

WORK="$(mktemp -d)"
cleanup() {
    find "$WORK" -mindepth 1 -delete 2>/dev/null || true
    rmdir "$WORK" 2>/dev/null || true
}
trap cleanup EXIT
cd "$WORK"

fail() { echo "smoke: FAILED — $1" >&2; exit 1; }
checks=0
ok() { checks=$((checks + 1)); }

# Inputs: text-like (repetitive with variation) and incompressible.
awk 'BEGIN { srand(7); for (i = 0; i < 12000; i++) printf "line %d: the frame of the block %d, window %x\n", i, int(rand()*500), int(rand()*65536) }' > text
head -c 300000 /dev/urandom > noise
head -c 131072 text > exact128k
: > empty

# ---------------------------------------------------------------- round trips
for f in text noise exact128k empty; do
    for opt in -1 -3 -19 --fast=4 "-3 -T2" "-3 --single-thread" "-6 --long" "-3 --no-check"; do
        # shellcheck disable=SC2086
        "$BIN" -q -c $opt "$f" > z
        "$BIN" -q -d -c z | cmp -s - "$f" || fail "round trip of $f with $opt"
        ok
    done
done

# several files, then --test and --list over them
cp text a; cp noise b
"$BIN" -q a b || fail "compressing two files"
[ -f a.zst ] && [ -f b.zst ] || fail "a.zst/b.zst not written"
"$BIN" -q -t a.zst b.zst || fail "--test of good frames"
"$BIN" -l a.zst b.zst | head -1 | grep -q '^Frames  Skips  Compressed  Uncompressed  Ratio  Check  Filename$' || fail "--list header"
rm a b
"$BIN" -q -d a.zst b.zst || fail "decompressing two files"
cmp -s a text && cmp -s b noise || fail "two files back"
ok; ok; ok; ok

# ------------------------------------------------------------ bad input verdicts
if "$BIN" -q a 2>/dev/null; then fail "overwrote a.zst without -f"; fi
"$BIN" -q -f a || fail "-f did not overwrite"
if "$BIN" -q -d text 2>/dev/null; then fail "decompressed a file with an unknown suffix"; fi
{ cat a.zst; printf 'junk'; } > trail.zst
if "$BIN" -q -d -c trail.zst > /dev/null 2>&1; then fail "accepted trailing garbage"; fi
head -c 1000 a.zst > trunc.zst
if "$BIN" -q -t trunc.zst 2>/dev/null; then fail "a truncated frame tested good"; fi
ok; ok; ok; ok; ok

# ------------------------------------------------ parity with the real command
REF="$(command -v zstd || true)"
if [ -n "$REF" ] && [ "$(readlink -f "$REF")" != "$(readlink -f "$BIN")" ] && [ "$("$REF" -qV 2>/dev/null)" = "1.5.7" ]; then
    for f in text noise exact128k empty; do
        for opt in -1 -3 -9 -19 --fast=4 "-3 -T2" "-3 --single-thread" "-6 --long" "-3 --no-check" "-3 --rsyncable" "-3 -B600K" "-3 --no-content-size"; do
            # shellcheck disable=SC2086
            "$REF" -q -c $opt "$f" > r.zst
            # shellcheck disable=SC2086
            "$BIN" -q -c $opt "$f" > o.zst
            cmp -s r.zst o.zst || fail "frame differs from zstd 1.5.7 for $f $opt"
            ok
        done
        "$REF" -q -c -3 < "$f" > r.zst
        "$BIN" -q -c -3 < "$f" > o.zst
        cmp -s r.zst o.zst || fail "frame from stdin differs from zstd 1.5.7 for $f"
        ok
    done
    # messages: the same text on stderr, and the same exit code
    same() {
        local want got rw rg
        # shellcheck disable=SC2086
        want="$(cd ref && eval "$1" 2>&1 >/dev/null </dev/null; echo "rc=$?")" || true
        # shellcheck disable=SC2086
        got="$(cd ours && eval "${1//\$REF/\$BIN}" 2>&1 >/dev/null </dev/null; echo "rc=$?")" || true
        [ "$want" = "$got" ] || { printf 'want:\n%s\ngot:\n%s\n' "$want" "$got" >&2; fail "messages differ for: $1"; }
        ok
    }
    for d in ref ours; do mkdir "$d"; cp text "$d/t"; "$REF" -q -19 text -o "$d/t19.zst"; cp text "$d/plain.zst"; done
    same '"$REF" t'
    same '"$REF" t'                       # already exists, not overwritten
    same '"$REF" -d t19.zst -o back'
    same '"$REF" -d plain.zst -o back2'  # not a zstd frame
    same '"$REF" nosuch'
    same '"$REF" --bogus'
    same '"$REF" -t t19.zst'
    (cd ref && "$REF" -l t19.zst plain.zst > ../list.ref 2>&1 || true)
    (cd ours && "$BIN" -l t19.zst plain.zst > ../list.ours 2>&1 || true)
    cmp -s list.ref list.ours || { diff list.ref list.ours >&2 || true; fail "--list output differs"; }
    ok
    echo "smoke: parity with $REF (1.5.7) checked"
else
    echo "smoke: no zstd 1.5.7 on PATH — parity with the real command NOT checked (round trips and verdicts only)"
fi

echo "smoke: OK ($checks checks)"
