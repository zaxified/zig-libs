#!/usr/bin/env bash
# Run the command and check that it does what the real `zstd` does.
#
#   ./smoke.sh            # after ./init.sh, or after `zig build`
#
# Always: round trips at several levels, thread counts and window sizes,
# several files at once, --test, --list, and the verdicts on bad input
# (an existing output without -f, an unknown suffix, trailing garbage, a
# truncated frame); -r, --filelist, --output-dir-*, --patch-from, --zstd=,
# a trained dictionary, -b without a file and --adapt. When a `zstd` of version
# 1.5.7 is on PATH, also the
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

# ------------------------------------------------------------------ benchmark
"$BIN" -q -i0 -b3 text | grep -q '^-3 ' || fail "-b printed no result line"
"$BIN" -i0 -b2 -d a.zst 2>/dev/null | tr '\r' '\n' | grep -q '^ 0#$' || fail "-b -d (decode only) did not finish"
"$BIN" -q -i0 -b1 -B100K | grep -q 'Lorem ipsum' || fail "-b without a file (lorem ipsum)"
ok; ok; ok

# ------------------------------------------------- directories and file lists
mkdir -p tree/sub; cp text tree/t; cp noise tree/sub/n
"$BIN" -q -r tree --output-dir-mirror mirror || fail "-r --output-dir-mirror"
[ -f mirror/tree/t.zst ] && [ -f mirror/tree/sub/n.zst ] || fail "mirrored files not written"
mkdir flat; "$BIN" -q -d -r mirror --output-dir-flat flat || fail "-d -r --output-dir-flat"
cmp -s flat/t text && cmp -s flat/n noise || fail "flat files back"
printf 'tree/t\ntree/sub/n\n' > list
"$BIN" -q -c --filelist list > listed.zst || fail "--filelist"
"$BIN" -q -d -c listed.zst | cmp -s - <(cat text noise) || fail "--filelist round trip"
ok; ok; ok; ok

# ------------------------------------------- --patch-from, --zstd=, --train
{ head -c 200000 text; printf 'CHANGED'; tail -c +200001 text; } > text2
"$BIN" -q --patch-from=text text2 -o p.zst || fail "--patch-from"
"$BIN" -q -d --patch-from=text p.zst -o p.back && cmp -s p.back text2 || fail "--patch-from round trip"
[ "$(stat -c %s p.zst)" -lt 2000 ] || fail "--patch-from made no small patch"
"$BIN" -q -c --zstd=wlog=18,clog=15,hlog=16,slog=4,mml=5,tlen=32,strat=5 text > zp.zst || fail "--zstd="
"$BIN" -q -d -c zp.zst | cmp -s - text || fail "--zstd= round trip"
"$BIN" --show-default-cparams -c text 2>&1 >/dev/null | grep -q 'strategy      : ZSTD_dfast (2)' || fail "--show-default-cparams"
mkdir samples; (cd samples && split -l 60 ../text s)
"$BIN" -q --train -r samples -o dict --maxdict=8K -T1 || fail "--train"
"$BIN" -q -D dict -c samples/saa > sd.zst && "$BIN" -q -d -D dict -c sd.zst | cmp -s - samples/saa || fail "trained dictionary round trip"
ok; ok; ok; ok; ok; ok; ok
# --adapt: the level moves with the I/O, the frame still decodes; workers only
for i in $(seq 20); do cat text; done > big
"$BIN" -q -c --adapt -T2 -B1M big | "$BIN" -q -d -c | cmp -s - big || fail "--adapt round trip"
if "$BIN" -q -c --adapt --single-thread text > /dev/null 2>&1; then fail "--adapt accepted with --single-thread"; fi
ok; ok

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
    # -b: the same sizes and ratios (the speeds are measurements)
    cols() { awk '/^-/ { print $1, $2, $3, $NF }'; }
    "$REF" -q -i0 -b1 -e3 -B64K text | cols > bench.ref
    "$BIN" -q -i0 -b1 -e3 -B64K text | cols > bench.ours
    [ -s bench.ref ] && cmp -s bench.ref bench.ours || { diff bench.ref bench.ours >&2 || true; fail "-b sizes differ from zstd 1.5.7"; }
    ok
    # the stage-2 options: patches, parameters, dictionaries, directories
    "$REF" -q --patch-from=text text2 -o p.ref; "$BIN" -q -f --patch-from=text text2 -o p.ours
    cmp -s p.ref p.ours || fail "--patch-from frame differs from zstd 1.5.7"
    "$REF" -q -c --zstd=wlog=18,strat=4,ovlog=3 -T2 text > r.zst; "$BIN" -q -c --zstd=wlog=18,strat=4,ovlog=3 -T2 text > o.zst
    cmp -s r.zst o.zst || fail "--zstd= frame differs from zstd 1.5.7"
    "$REF" -q --train-cover=d=8,steps=4 -r samples -o dict.ref --maxdict=8K -T1; "$BIN" -q --train-cover=d=8,steps=4 -r samples -o dict.ours --maxdict=8K -T1
    cmp -s dict.ref dict.ours || fail "trained dictionary differs from zstd 1.5.7"
    "$REF" -q -c -r tree > r.zst; "$BIN" -q -c -r tree > o.zst
    cmp -s r.zst o.zst || fail "-r -c output differs from zstd 1.5.7"
    for d in ref ours; do cp -r samples "$d/"; done
    same '"$REF" --show-default-cparams -19 -c t'
    same '"$REF" --train -r samples -o d --maxdict=8K -T1'
    same '"$REF" --zstd=strat=10 t -o x'
    same '"$REF" --patch-from=t -D t t19.zst'
    same '"$REF" --adapt --single-thread t'
    same '"$REF" --adapt=min=5,max=3 t'
    # --adapt held at one level: the frame no longer depends on timing
    "$REF" -q -c --adapt=min=5,max=5 -T2 big > r.zst; "$BIN" -q -c --adapt=min=5,max=5 -T2 big > o.zst
    cmp -s r.zst o.zst || fail "--adapt=min=5,max=5 frame differs from zstd 1.5.7"
    for p in "" -P50; do
        # shellcheck disable=SC2086
        "$REF" -q -i0 -b1 -B100K $p | cols > syn.ref
        # shellcheck disable=SC2086
        "$BIN" -q -i0 -b1 -B100K $p | cols > syn.ours
        [ -s syn.ref ] && cmp -s syn.ref syn.ours || { diff syn.ref syn.ours >&2 || true; fail "-b $p (synthetic) sizes differ from zstd 1.5.7"; }
    done
    # the progress counter's numbers (ZSTD_getFrameProgression), every
    # update shown at -vvvv, single-threaded for determinism
    prog() { "$1" -vvvv --progress --single-thread -c text 2>&1 >/dev/null | tr '\r' '\n' | grep 'Buffered:'; }
    [ "$(prog "$REF")" = "$(prog "$BIN")" ] || fail "progress numbers differ from zstd 1.5.7"
    ok; ok; ok; ok; ok; ok; ok; ok
    echo "smoke: parity with $REF (1.5.7) checked"
else
    echo "smoke: no zstd 1.5.7 on PATH — parity with the real command NOT checked (round trips and verdicts only)"
fi

echo "smoke: OK ($checks checks)"
