#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Campaign 4: random MUTATIONS of well-formed messages -> decision parity.

WHY THIS EXISTS. `camp2.py` probes the pathologies somebody thought of. This
probes the ones nobody did: take a message the reference itself produced, corrupt
it the way a network or an attacker would — flip a byte, truncate, splice in a
hostile tag, set a continuation bit — and ask both sides. What is compared is
first the DECISION (accept or reject) and only then the value, because on
corrupted input the decision is the interesting half: accepting what the
reference rejects is where an attack lives.

⚠ IT REPORTS, IT DOES NOT FAIL. On mutated input a divergence is often
legitimate — the two implementations draw the line at different places for
inputs no spec pins down — so a non-zero exit here would fire on every run and
teach everyone to ignore it. Read the buckets: `DIVERGE-decision(zig=accept)` is
the one to look at first. It exits non-zero only if it compared nothing.

WHAT IT NEEDS. `pip install protobuf` and the `probe` binary (README.md).

    python3 camp4.py [count] [seed]      # default 20000 inputs, seed 7

WHAT IT PRODUCES. Counts per outcome class (see `classify.py`), then up to three
worked examples per divergence signature.
"""
import sys, random, collections
import gen, oracle, classify

N = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
SEED = int(sys.argv[2]) if len(sys.argv) > 2 else 7
rnd = random.Random(SEED)

SCHEMAS = ["Wide", "Repeated", "Presence", "Chain"]


def mutate(b, rnd):
    b = bytearray(b)
    op = rnd.randrange(7)
    if not b:
        return bytes([rnd.randrange(256) for _ in range(rnd.randint(1, 4))])
    if op == 0:                                   # flip one byte
        b[rnd.randrange(len(b))] = rnd.randrange(256)
    elif op == 1:                                 # truncate
        b = b[:rnd.randrange(len(b))]
    elif op == 2:                                 # insert a byte
        b.insert(rnd.randrange(len(b) + 1), rnd.randrange(256))
    elif op == 3:                                 # delete a byte
        del b[rnd.randrange(len(b))]
    elif op == 4:                                 # duplicate a slice (dup fields)
        i = rnd.randrange(len(b)); j = rnd.randrange(i, len(b)) + 1
        b = b + b[i:j]
    elif op == 5:                                 # splice in a hostile tag
        t = rnd.choice([b"\x00", b"\x0b", b"\x0c", b"\x0e", b"\x0f",
                        b"\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01",
                        b"\x7a\xff\xff\xff\xff\x0f"])
        i = rnd.randrange(len(b) + 1)
        b = b[:i] + bytearray(t) + b[i:]
    else:                                         # set a high bit (continuation)
        i = rnd.randrange(len(b)); b[i] |= 0x80
    return bytes(b)


BATCH = 20000
cnt = collections.Counter()
examples = {}
seen = 0
buf = []
for i in range(N):
    sch = rnd.choice(SCHEMAS)
    m = gen.GEN[sch](rnd)
    raw = m.SerializeToString(deterministic=True)
    for _ in range(rnd.randint(1, 3)):
        raw = mutate(raw, rnd)
    buf.append(("m%d" % i, "d", sch, raw.hex()))
    if len(buf) >= BATCH:
        for row in gen.run(buf):
            seen += 1
            k = classify.kind(row[4], row[5])
            cnt[k] += 1
            if k.startswith("DIVERGE"):
                sig = (k, row[2])
                examples.setdefault(sig, []).append(row)
        buf = []
if buf:
    for row in gen.run(buf):
        seen += 1
        k = classify.kind(row[4], row[5])
        cnt[k] += 1
        if k.startswith("DIVERGE"):
            examples.setdefault((k, row[2]), []).append(row)

print("inputs compared: %d" % seen)
for k, v in cnt.most_common():
    print("  %-34s %d" % (k, v))
print()
for sig, rows in sorted(examples.items(), key=lambda x: -len(x[1])):
    print("== %s %s  x%d" % (sig[0], sig[1], len(rows)))
    for r in rows[:3]:
        print("   hex: %s" % r[3][:120])
        print("   zig: %s" % r[4][:200])
        print("   py : %s" % r[5][:200])

if seen == 0:
    print("⛔ nothing was compared")
    sys.exit(1)
