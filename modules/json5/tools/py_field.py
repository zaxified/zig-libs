# SPDX-License-Identifier: MIT
#
# The pyjson5 side of `zig build bench-json5` (modules/json5/tools/bench.zig):
# Kijewski's pyjson5 2.0.1 (Cython over a C++ core) reading the files the Zig
# program writes into <work dir>, same protocol and timing method as
# rs_field/src/main.rs: `python py_field.py <work dir> <workload>` prints
# `name \t ns/op \t count` on stdout and the banner on stderr. Each op is
# `pyjson5.decode(text)` into plain dict/list; `count` is object members +
# array elements of the tree (summed over the 1000 parses of `small_config`).
#
# Setup (no root; the bench skips this side when the venv is missing):
#   python3 -m venv .zig-cache/bench-json5/venv
#   .zig-cache/bench-json5/venv/bin/pip install --only-binary=:all: pyjson5==2.0.1
import sys
import time

import pyjson5


def count(v):
    if isinstance(v, list):
        return len(v) + sum(count(x) for x in v)
    if isinstance(v, dict):
        return len(v) + sum(count(x) for x in v.values())
    return 0


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: py_field.py <work dir> <workload>\n")
        sys.exit(2)
    work = {
        "small_config": ("small_config.json5", 1000),
        "large_json": ("large_json.json", 1),
        "large_json5": ("large_json5.json5", 1),
    }.get(sys.argv[2])
    if work is None:
        sys.stderr.write("unknown workload %s\n" % sys.argv[2])
        sys.exit(2)
    file, reps = work
    with open("%s/%s" % (sys.argv[1], file), encoding="utf-8") as f:
        text = f.read()

    def once():
        s = 0
        for _ in range(reps):
            s += count(pyjson5.decode(text))
        return s

    n = 1
    while True:
        t = time.perf_counter_ns()
        for _ in range(n):
            once()
        if time.perf_counter_ns() - t > 100_000_000:
            break
        n *= 2
    best = float("inf")
    result = 0
    for _ in range(5):
        t = time.perf_counter_ns()
        for _ in range(n):
            result = once()
        best = min(best, time.perf_counter_ns() - t)
    sys.stderr.write("pyjson5 %s, Python %s (decode into dict/list)\n" % (pyjson5.__version__, sys.version.split()[0]))
    print("%s\t%s\t%d" % (sys.argv[2], best / n, result))


main()
