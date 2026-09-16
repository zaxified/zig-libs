#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Campaign 1: well-formed random messages, both directions.

  d: reference bytes -> our decoder, field-by-field dump compared
  r: same bytes -> decode and re-encode on both sides, byte-compared

WHY THIS EXISTS, and why it comes first. Every other campaign feeds hostile or
corrupted input, where a disagreement can be a legitimate difference of policy.
Here the bytes are what the reference implementation itself produced from a
message it built: there is no room for interpretation, so ANY divergence is a
defect on one side or the other. If this campaign is not clean, nothing measured
by the others means anything.

The `r` direction is the sharper one. Decoding to the same values proves we read
the bytes; re-encoding to the same bytes proves we also agree on what the
canonical form IS — field order, default omission, packing — which no decode-only
comparison can see.

WHAT IT NEEDS. `pip install protobuf` and the `probe` binary (README.md).

    python3 camp1.py [count] [seed]      # default 5000 messages, seed 1

WHAT IT PRODUCES. A comparison count, a mismatch count, and one worked example
per (direction, schema) bucket. Exit 1 if anything diverged — see above for why
there is no artifact class here.
"""
import sys, random, collections
import gen, oracle

N = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
SEED = int(sys.argv[2]) if len(sys.argv) > 2 else 1
rnd = random.Random(SEED)

cases = []
for i in range(N):
    sch = rnd.choice(["Wide", "Repeated", "Presence", "Chain"])
    m = gen.GEN[sch](rnd)
    hx = m.SerializeToString(deterministic=True).hex()
    cases.append(("wf%d" % i, "d", sch, hx))
    cases.append(("wf%d" % i, "r", sch, hx))

BATCH = 20000
mismatch = collections.Counter()
examples = {}
total = 0
for off in range(0, len(cases), BATCH):
    for (lbl, op, sch, hx, z, p) in gen.run(cases[off:off + BATCH]):
        total += 1
        if z != p:
            key = (op, sch)
            mismatch[key] += 1
            if key not in examples:
                examples[key] = (hx, z, p)

print("comparisons: %d   mismatches: %d" % (total, sum(mismatch.values())))
for k, v in mismatch.most_common():
    hx, z, p = examples[k]
    print("  %s x%d\n    hex: %s\n    zig: %s\n    py : %s" % (k, v, hx, z[:400], p[:400]))

# A run that compared nothing is a failure, not a clean sheet.
if total == 0:
    print("⛔ no comparison was made at all")
    sys.exit(1)
sys.exit(1 if sum(mismatch.values()) else 0)
