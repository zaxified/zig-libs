#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Differential: this module's modified UTF-7 against pymap's
parsing/modutf7.py (MIT, Python, independent author -- the SERVER side of this
protocol).

WHAT IT NEEDS: pymap, run with the interpreter of the venv that
`src/live_test.zig` already documents (`~/.cache/zig-libs-imap/bin/python3`).
WHAT IT PRODUCES: agree / both-reject / stricter / DISAGREE counts over the
lines `utf7_dump.zig` printed, then one row per non-agreement. Exits 1 on a
value disagreement not in EXPECTED, on a case where pymap is the stricter side, or on empty input -- an oracle that compared nothing has
not passed.

    utf7_oracle.py <dump.txt>
"""
import sys
from pymap.parsing.modutf7 import modutf7_encode, modutf7_decode
import signal

class Timeout(Exception):
    pass

def _alarm(sig, frm):
    raise Timeout()

signal.signal(signal.SIGALRM, _alarm)

def guarded(fn, arg):
    # pymap's decoder does not terminate on an unterminated shift sequence
    # ("&Jjo"): its inner scan finds no '-' and never advances `buf`. Bound
    # every call so one such input cannot stall the differential.
    signal.setitimer(signal.ITIMER_REAL, 0.5)
    try:
        return fn(arg)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)

# Known value disagreements, each named. A new one fails the run; these do not.
EXPECTED = {
    # This module passes raw UTF-8 through a decode (a documented choice);
    # pymap reads those bytes as Latin-1.
    ("D", "c3a9"), ("D", "61c3a962"), ("D", "f09f9880"),
    # pymap bug: Python's utf-7 codec has CR/LF in its direct set, so pymap
    # encodes them as `&-`, a literal ampersand.
    ("E", "0d0a"), ("E", "610d62"),
}

agree = both_reject = zig_stricter = pymap_stricter = disagree = expected = 0
rows = []
for line in open(sys.argv[1]):
    parts = line.rstrip("\n").split(" ")
    kind, hin = parts[0], parts[1]
    zres = parts[2] if len(parts) > 2 else ""
    src = bytes.fromhex(hin)
    if kind == "D":
        try:
            p = guarded(modutf7_decode, src).encode("utf-8").hex()
            pok = True
        except Exception as e:
            p, pok = type(e).__name__, False
    else:
        try:
            p = guarded(modutf7_encode, src.decode("utf-8")).hex()
            pok = True
        except Exception as e:
            p, pok = type(e).__name__, False
    zok = zres != "REJECT"
    if zok and pok:
        if zres == p:
            agree += 1
        elif (kind, hin) in EXPECTED:
            expected += 1
            rows.append(("known", kind, hin, zres, p))
        else:
            disagree += 1
            rows.append(("DISAGREE", kind, hin, zres, p))
    elif not zok and not pok:
        both_reject += 1
    elif not zok and pok:
        zig_stricter += 1
        rows.append(("zig-stricter", kind, hin, "REJECT", p))
    else:
        pymap_stricter += 1
        rows.append(("pymap-stricter", kind, hin, zres, p))

def txt(h):
    try:
        return bytes.fromhex(h).decode("utf-8", "backslashreplace")
    except Exception:
        return h

print(f"agree={agree} both_reject={both_reject} zig_stricter={zig_stricter} "
      f"pymap_stricter={pymap_stricter} known={expected} DISAGREE_ON_VALUE={disagree}\n")
for r in rows:
    print(f"{r[0]:<15} {r[1]} in={bytes.fromhex(r[2])!r:<40} zig={r[3][:60]!s:<40} pymap={r[4][:60]}")

if agree + both_reject + zig_stricter + pymap_stricter + disagree + expected == 0:
    sys.exit("no input lines -- did the dump go to stderr without 2>&1?")
sys.exit(1 if disagree or pymap_stricter else 0)
