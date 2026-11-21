#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Differential oracle for the dictionary support: our blocks and frames against liblz4 through
python-lz4 (`dict=`) and the `lz4` CLI (`-D`), in both directions. Prints one line per check;
every verdict must be True.

Build the driver first (once), from the repository root:

    zig build-exe -O ReleaseSafe --dep lz4 -Mroot=modules/lz4/tools/dict_cli.zig \
        -Mlz4=modules/lz4/src/root.zig -femit-bin=<scratch>/dict_cli

then run `python3 modules/lz4/tools/dict_oracle.py <scratch>/dict_cli` from a scratch directory.
Needs `lz4` (CLI) and python3 with `lz4`.
"""
import random
import subprocess
import sys

import lz4.block

cli = sys.argv[1]
random.seed(5)
words = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon", b"zeta", b"theta", b"kappa",
         b"lambda", b"sigma", b"omega", b"packet", b"session", b"header"]


def text(n):
    out = bytearray()
    while len(out) < n:
        out += random.choice(words) + b" "
    return bytes(out[:n])


dict_ = text(30000)
data = text(200000) + bytes(random.randrange(256) for _ in range(500)) + text(90000)
open("dictfile", "wb").write(dict_)
open("data", "wb").write(data)


def run(*a):
    subprocess.run([cli, *a], check=True)


run("bc", "dictfile", "data", "bout")
ours = open("bout", "rb").read()
print("block ours -> python-lz4:", lz4.block.decompress(ours, uncompressed_size=len(data), dict=dict_) == data)
py = lz4.block.compress(data, mode="fast", store_size=False, dict=dict_)
open("pyblk", "wb").write(py)
run("bd", "dictfile", "pyblk", "bback", str(len(data)))
print("block python-lz4 -> ours:", open("bback", "rb").read() == data)
for mode, name in (("fc", "linked"), ("fci", "independent")):
    run(mode, "dictfile", "data", "fout")
    r = subprocess.run(["lz4", "-d", "-D", "dictfile", "-c", "fout"], capture_output=True)
    print("frame ours (%s) -> lz4 CLI:" % name, r.returncode == 0 and r.stdout == data)
for flags in ([], ["--no-frame-crc"], ["-BD"], ["-BI"], ["-B5"]):
    r = subprocess.run(["lz4", "-c", "-D", "dictfile", *flags, "data"], capture_output=True)
    open("clifr", "wb").write(r.stdout)
    run("fd", "dictfile", "clifr", "back")
    print("frame lz4 CLI %s -> ours:" % (" ".join(flags) or "default"), open("back", "rb").read() == data)

# HC levels: our output decodes with liblz4, and its size against `lz4 -N` (both run an optimal
# parser at 10..12).
for lv in (3, 6, 9, 10, 11, 12):
    run("hb", "dictfile", "data", "hcb", str(lv))
    ours = open("hcb", "rb").read()
    ok = lz4.block.decompress(ours, uncompressed_size=len(data)) == data
    ref = subprocess.run(["lz4", "-c", "-%d" % lv, "data"], capture_output=True).stdout
    print("hc level %d block: liblz4 decodes %s; ours %d bytes, frame from lz4 -%d %d bytes" % (lv, ok, len(ours), lv, len(ref)))
    run("hf", "dictfile", "data", "hcf", str(lv))
    r = subprocess.run(["lz4", "-d", "-c", "hcf"], capture_output=True)
    print("hc level %d frame -> lz4 CLI:" % lv, r.returncode == 0 and r.stdout == data)
