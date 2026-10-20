# SPDX-License-Identifier: MIT
#
# The reference side of `zig build bench-numparse` (modules/numparse/tools/bench.zig):
# Babel's `numbers.parse_decimal(s, locale, strict=True)`.
#
#   python3 -I bench_ref.py <work dir> <workload>
#
# Prints `name \t ns/op \t count` on stdout, the banner on stderr. Same timing
# method as the Zig side: double the batch until it takes over 100 ms, then the
# best of five batches, per op. One op parses every line of <work dir>/<workload>.txt
# once with a `Locale` object resolved once. `count` = (digest << 32) | accepted,
# where `accepted` is the number of lines Babel accepts and `digest` the sum mod
# 2^32 of the parsed values scaled by 10^12 (Decimal's raw representation), which
# the Zig side must reproduce exactly.
import os
import sys
import time

import babel
from babel import Locale
from babel.numbers import NumberFormatError, parse_decimal

# workload -> (locale, numbering_system)
WORKS = {
    "en_US_grouped": ("en_US", "latn"),
    "de_grouped": ("de", "latn"),
    "cs_nbsp": ("cs", "latn"),
    "en_IN_indian": ("en_IN", "latn"),
    "fr_mixed": ("fr", "latn"),
    "ar_EG_native": ("ar_EG", "default"),
}

if len(sys.argv) != 3 or sys.argv[2] not in WORKS:
    sys.stderr.write("usage: python3 -I bench_ref.py <work dir> <%s>\n" % "|".join(WORKS))
    sys.exit(2)
work_dir, name = sys.argv[1], sys.argv[2]
loc_name, ns = WORKS[name]
loc = Locale.parse(loc_name)
with open(os.path.join(work_dir, name + ".txt"), encoding="utf-8") as f:
    lines = f.read().split("\n")
if lines and lines[-1] == "":
    lines.pop()

MASK = 0xFFFFFFFF


def once():
    accepted = 0
    digest = 0
    for s in lines:
        try:
            d = parse_decimal(s, loc, strict=True, numbering_system=ns)
        except NumberFormatError:
            continue
        accepted += 1
        digest = (digest + (int(d.scaleb(12)) & MASK)) & MASK
    return (digest << 32) | accepted


now = time.perf_counter_ns
sink = 0
n = 1
while True:
    t = now()
    for _ in range(n):
        sink += once() & 1
    if now() - t > 100_000_000:
        break
    n *= 2
best = None
result = 0
for _ in range(5):
    t = now()
    for _ in range(n):
        result = once()
    dt = now() - t
    best = dt if best is None else min(best, dt)
if sink < 0:
    sys.stderr.write(str(sink))
sys.stderr.write("babel %s, python %s\n" % (babel.__version__, sys.version.split()[0]))
sys.stdout.write("%s\t%s\t%d\n" % (name, best / n, result))
