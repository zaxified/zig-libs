#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Corpus generator, and the driver that puts one input to both implementations.

WHY THIS EXISTS. Everything in the rig reduces to: build a message, ask both
sides, compare the two answers as strings. `run()` is that step, in one place, so
a campaign is a corpus and nothing else. The generators below produce messages
the reference implementation itself serialises — so the bytes a campaign starts
from are the reference's own output, not ours, and a shared misunderstanding
cannot hide in the corpus.

Note the deliberately awkward values: NaN and signalling NaN, -0.0, 5e-324,
enum values outside the declared set, embedded NUL and a 4-byte emoji in
strings. Those are where two implementations disagree; uniformly random integers
are where they never do.

WHAT IT NEEDS. `pip install protobuf`, and the `probe` binary built beside this
file — see `README.md` for the one-line build. $PB_PROBE overrides its location.

WHAT IT PRODUCES. Nothing on its own; it is imported by `camp1/2/4/5.py`.
"""
import sys, os, random, struct, subprocess, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oracle

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE = os.environ.get("PB_PROBE") or os.path.join(HERE, "probe")

MIN32, MAX32 = -(2**31), 2**31 - 1
MIN64, MAX64 = -(2**63), 2**63 - 1
UMAX32, UMAX64 = 2**32 - 1, 2**64 - 1


def varint(n):
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def tag(num, wt):
    return varint((num << 3) | wt)


def rand_wide(rnd):
    m = oracle.cls("Wide")()
    if rnd.random() < 0.7: m.i32_ = rnd.randint(MIN32, MAX32)
    if rnd.random() < 0.7: m.i64_ = rnd.randint(MIN64, MAX64)
    if rnd.random() < 0.7: m.u32_ = rnd.randint(0, UMAX32)
    if rnd.random() < 0.7: m.u64_ = rnd.randint(0, UMAX64)
    if rnd.random() < 0.7: m.s32 = rnd.randint(MIN32, MAX32)
    if rnd.random() < 0.7: m.s64 = rnd.randint(MIN64, MAX64)
    if rnd.random() < 0.5: m.b = True
    if rnd.random() < 0.7: m.color = rnd.choice([0, 1, 2, 77, MAX32, -1, MIN32])
    if rnd.random() < 0.7: m.f64_ = rnd.randint(0, UMAX64)
    if rnd.random() < 0.7: m.sf64 = rnd.randint(MIN64, MAX64)
    if rnd.random() < 0.7:
        m.d = rnd.choice([rnd.uniform(-1e300, 1e300), 0.0, -0.0, float("inf"),
                          float("-inf"), float("nan"), 5e-324, 1e-310])
    if rnd.random() < 0.7: m.f32_ = rnd.randint(0, UMAX32)
    if rnd.random() < 0.7: m.sf32 = rnd.randint(MIN32, MAX32)
    if rnd.random() < 0.7:
        m.f = rnd.choice([rnd.uniform(-1e30, 1e30), 0.0, -0.0, float("inf"),
                          float("-inf"), float("nan"), 1e-45])
    if rnd.random() < 0.7:
        m.s = "".join(rnd.choice("aä€\U0001f389 \0\x7f~") for _ in range(rnd.randint(0, 12)))
    if rnd.random() < 0.7:
        m.raw = bytes(rnd.randrange(256) for _ in range(rnd.randint(0, 12)))
    if rnd.random() < 0.6:
        m.inner.v = rnd.randint(MIN32, MAX32)
        m.inner.note = "n" * rnd.randint(0, 5)
    return m


def rand_repeated(rnd):
    m = oracle.cls("Repeated")()
    m.nums.extend(rnd.randint(MIN32, MAX32) for _ in range(rnd.randint(0, 6)))
    m.unpacked.extend(rnd.randint(MIN32, MAX32) for _ in range(rnd.randint(0, 6)))
    m.zz.extend(rnd.randint(MIN64, MAX64) for _ in range(rnd.randint(0, 6)))
    m.fixed.extend(rnd.randint(0, UMAX32) for _ in range(rnd.randint(0, 6)))
    m.flags.extend(rnd.random() < 0.5 for _ in range(rnd.randint(0, 6)))
    m.colors.extend(rnd.choice([0, 1, 2, 99, -5]) for _ in range(rnd.randint(0, 6)))
    m.names.extend("s" * rnd.randint(0, 4) for _ in range(rnd.randint(0, 4)))
    for _ in range(rnd.randint(0, 3)):
        i = m.inners.add()
        i.v = rnd.randint(MIN32, MAX32)
        i.note = "x" * rnd.randint(0, 3)
    return m


def rand_presence(rnd):
    m = oracle.cls("Presence")()
    if rnd.random() < 0.7: m.implicit = rnd.randint(MIN32, MAX32)
    if rnd.random() < 0.5: m.explicit = rnd.choice([0, 1, MIN32, MAX32])
    if rnd.random() < 0.5: m.implicit_str = "a" * rnd.randint(0, 4)
    if rnd.random() < 0.5: m.explicit_str = "b" * rnd.randint(0, 4)
    return m


def rand_chain(rnd, depth=0):
    m = oracle.cls("Chain")()
    m.depth = rnd.randint(MIN32, MAX32)
    if depth < 4 and rnd.random() < 0.6:
        sub = rand_chain(rnd, depth + 1)
        m.next.CopyFrom(sub)
    return m


GEN = {"Wide": rand_wide, "Repeated": rand_repeated,
       "Presence": rand_presence, "Chain": rand_chain}


def run(cases):
    """cases: list of (label, op, schema, hexbytes). Returns list of (label, op, schema, hex, zig, py)."""
    if not os.path.exists(PROBE):
        sys.exit(f"⛔ no probe binary at {PROBE} — build it first, see README.md "
                 f"(or set $PB_PROBE)")
    lines = "".join("%s %s %s\n" % (op, sch, hx) for (_, op, sch, hx) in cases)
    z = subprocess.run([PROBE], input=lines.encode(), capture_output=True)
    if z.returncode != 0:
        sys.stderr.write("PROBE CRASHED rc=%d\n%s\n" % (z.returncode, z.stderr.decode()[:2000]))
    p = subprocess.run([sys.executable, os.path.join(HERE, "oracle.py")],
                       input=lines.encode(), capture_output=True)
    zl = z.stdout.decode().split("\n")
    pl = p.stdout.decode().split("\n")
    out = []
    for i, (lbl, op, sch, hx) in enumerate(cases):
        out.append((lbl, op, sch, hx,
                    zl[i] if i < len(zl) else "<missing>",
                    pl[i] if i < len(pl) else "<missing>"))
    return out
