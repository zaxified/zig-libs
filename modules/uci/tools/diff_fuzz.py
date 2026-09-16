#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Randomised differential fuzz, module vs. real libuci.

Generates UCI-shaped text (biased toward well-formed, so most cases actually
reach both parsers rather than dying at the first keyword), feeds it to both
dumpers, and classifies every disagreement. Seeded, so any hit is replayable.

  diff_fuzz.py [n] [seed] [--valid]

Env: BASE  scratch root with out/oracle_dump, out/module_dump, ref/root/etc/config
"""
import os
import pathlib, random, subprocess, sys, collections

REPO = pathlib.Path(__file__).resolve().parents[3]
BASE = os.environ.get("BASE", str(REPO / ".zig-cache/uci-differential"))
ORACLE = os.path.join(BASE, "out", "oracle_dump")
MODULE = os.path.join(BASE, "out", "module_dump")
CONFDIR = os.path.join(BASE, "ref", "root", "etc", "config")

KEYWORDS = ["config", "option", "list", "package"]
# Every byte with grammatical meaning, plus boundary bytes.
TOKCHARS = "abAB01_-.=@[]#\\'\"\t x/:;"


def gen_token(r):
    style = r.randrange(6)
    n = r.randrange(0, 6)
    body = "".join(r.choice(TOKCHARS) for _ in range(n))
    if style == 0:
        return body                       # bare
    if style == 1:
        return "'" + body + "'"           # single-quoted
    if style == 2:
        return '"' + body + '"'           # double-quoted
    if style == 3:
        return "'" + body + "'" + '"' + body + '"'   # concatenated segments
    if style == 4:
        return r.choice(["''", '""', "x", "1"])
    return body + "#" + body              # mid-token hash


def gen(r, valid=False):
    """valid=True keeps the STATEMENT SHAPE well-formed (right keyword, right
    argument count, a section before any option) so the case actually reaches
    both parsers' value/name handling instead of dying at the first keyword —
    that is where the interesting disagreements live."""
    lines = []
    if not valid:
        for _ in range(r.randrange(1, 8)):
            k = r.choice(KEYWORDS) if r.random() < 0.9 else gen_token(r)
            args = [gen_token(r) for _ in range(r.randrange(0, 4))]
            lines.append(" ".join([k] + args))
        return ("\n".join(lines) + "\n").encode("latin-1", "replace")
    for _ in range(r.randrange(1, 4)):
        if r.random() < 0.5:
            lines.append("config t " + gen_token(r))
        else:
            lines.append("config t")
        for _ in range(r.randrange(0, 4)):
            kw = "option" if r.random() < 0.7 else "list"
            lines.append("\t%s k%d %s" % (kw, r.randrange(4), gen_token(r)))
    return ("\n".join(lines) + "\n").encode("latin-1", "replace")


def main():
    argv = [a for a in sys.argv[1:] if a != "--valid"]
    valid = "--valid" in sys.argv
    n = int(argv[0]) if len(argv) > 0 else 3000
    seed = int(argv[1]) if len(argv) > 1 else 20260905
    r = random.Random(seed)
    os.makedirs(CONFDIR, exist_ok=True)
    probe = os.path.join(CONFDIR, "fz")

    counts = collections.Counter()
    examples = {}
    for _ in range(n):
        data = gen(r, valid)
        with open(probe, "wb") as f:
            f.write(data)
        o = subprocess.run([ORACLE, CONFDIR, "fz"], capture_output=True, text=True).stdout
        m = subprocess.run([MODULE], input=data, capture_output=True).stdout.decode("latin-1")
        oe, me = o.startswith("ERR"), m.startswith("ERR")
        if o == m:
            k = "SAME"
        elif oe and me:
            k = "BOTH-REJECT"
        elif oe and not me:
            k = "MODULE-ACCEPTS-LIBUCI-REJECTS"
        elif me and not oe:
            k = "MODULE-REJECTS-LIBUCI-ACCEPTS"
        else:
            k = "VALUE-DIVERGE"
        counts[k] += 1
        if k not in ("SAME", "BOTH-REJECT") and k not in examples:
            examples[k] = (data, o.strip(), m.strip())

    os.path.exists(probe) and os.remove(probe)
    print(f"n={n} seed={seed} valid={valid}")
    for k, v in counts.most_common():
        print(f"  {k:<32} {v}")
    for k, (d, o, m) in examples.items():
        print(f"\n-- first {k} --\n  input : {d!r}\n  libuci: {o}\n  module: {m}")


if __name__ == "__main__":
    main()
