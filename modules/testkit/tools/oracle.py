#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Grade `testkit.hex` against two from-scratch references, over the TSV that
`hexprobe.zig` produces by driving `testkit.hex.into`/`.alloc` (its public
API only) across every 0..3-byte string over a hostile alphabet.

References (both written here, not vendored):
  1. `strict()` — a strict RFC 4648 hex decoder: even length, digits only
     from [0-9a-fA-F]. This is the class this module claims to belong to.
  2. `pyfromhex()` — Python's own `bytes.fromhex`, which is the "OK/ERR
     classification" oracle SPEC.md names as the second column.

Needs: Python 3 (stdlib only, no packages).
Produces: a summary line `lines=<n> strict-diffs=<n> py-diffs=<n>` on stdout,
plus up to 25/30 example mismatches of each kind.

Usage (see `tools/README.md` for the full recipe and measured result):
    <path-to-hexprobe-binary> > /dev/null 2> hex-zig.tsv   # hexprobe writes to stderr
    python3 modules/testkit/tools/oracle.py hex-zig.tsv
"""
import sys

HEX = set(b"0123456789abcdefABCDEF")


def strict(b):
    if len(b) % 2:
        return "E:InvalidLength"
    for c in b:
        if c not in HEX:
            return "E:InvalidCharacter"
    return "OK:" + b.decode().lower()


def pyfromhex(b):
    try:
        return "OK:" + bytes.fromhex(b.decode("latin1")).hex()
    except ValueError as e:
        return "E:py(" + str(e)[:40] + ")"
    except Exception:
        return "E:py-other"


def main(path):
    d_strict = d_py = lines = 0
    with open(path, "rb") as f:
        for line in f:
            line = line.rstrip(b"\n")
            parts = line.split(b"\t")
            if len(parts) != 3:
                print("BADLINE", line)
                continue
            inhex, into_r, alloc_r = (p.decode() for p in parts)
            raw = bytes.fromhex(inhex) if inhex else b""
            lines += 1
            s = strict(raw)
            if into_r != s:
                d_strict += 1
                if d_strict <= 25:
                    print("STRICT-DIFF into  in=%-10r zig=%-22s strict=%s" % (raw, into_r, s))
            if alloc_r != s:
                d_strict += 1
                if d_strict <= 25:
                    print("STRICT-DIFF alloc in=%-10r zig=%-22s strict=%s" % (raw, alloc_r, s))
            if into_r != alloc_r:
                print("INTO/ALLOC DISAGREE in=%r into=%s alloc=%s" % (raw, into_r, alloc_r))
            p = pyfromhex(raw)
            # only compare the OK/ERR classification, and the value when both OK
            zok = into_r.startswith("OK:")
            pok = p.startswith("OK:")
            if zok != pok or (zok and pok and into_r != p):
                d_py += 1
                if d_py <= 30:
                    print("PY-DIFF   in=%-12r zig=%-22s py=%s" % (raw, into_r, p))
    print("lines=%d strict-diffs=%d py-diffs=%d" % (lines, d_strict, d_py))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
