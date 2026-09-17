# `imap` verification instruments

Two instruments that work as a pair, run by hand. Neither is wired into
`zig build`: the oracle needs pymap, a Python IMAP server by an independent
author, and `zig build test-imap` must not require it (`CONVENTIONS.md` §9).

| tool | question it answers |
|---|---|
| `utf7_dump.zig` | What does `imap.utf7` make of 62 decode and 23 encode inputs (RFC 3501 shapes, go-imap table entries, malformed shifts, raw UTF-8, control characters)? |
| `utf7_oracle.py` | Does pymap's `parsing/modutf7.py` — the SERVER side of the same protocol — give the same answer for each? |

The module's own UTF-7 tests are pinned against RFC 3501 and the go-imap table;
`src/live_test.zig` drives a whole pymap session but never compares codec values
one by one. This pair does.

```bash
python3 -m venv ~/.cache/zig-libs-imap && ~/.cache/zig-libs-imap/bin/pip install pymap
S=.zig-cache/imap-utf7; mkdir -p $S
zig build-exe --dep imap -Mmain=modules/imap/tools/utf7_dump.zig \
    -Mimap=modules/imap/src/root.zig --cache-dir $S/zc -femit-bin=$S/dump
$S/dump 2> $S/dump.txt          # the lines go to stderr
~/.cache/zig-libs-imap/bin/python3 modules/imap/tools/utf7_oracle.py $S/dump.txt
```

Measured 2026-09-17: `agree=54 both_reject=14 zig_stricter=12 pymap_stricter=0
known=5 DISAGREE_ON_VALUE=0`, exit 0. The twelve where this module is stricter
are canonical-form rules it documents and pymap does not enforce. The five
`known` rows are named in the script: three raw-UTF-8 pass-throughs pymap reads
as Latin-1, and a pymap bug that encodes CR/LF as a literal `&-`. A new value
disagreement, or any case where pymap is the stricter side, exits 1; so does an
empty input.

⚠ pymap's decoder does not terminate on an unterminated shift (`&Jjo`), so every
call runs under a 0.5 s timer.
