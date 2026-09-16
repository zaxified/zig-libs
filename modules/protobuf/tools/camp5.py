#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Campaign 5: the long run — well-formed round trips plus mutated inputs, with
every divergence bucketed by CAUSE.

WHY THIS EXISTS. `camp4.py` counts divergences; at a quarter of a million inputs
a count is not usable. This classifies each one by why it happened, which turns a
number into a short list of distinct facts — and separates the two kinds that
must never be mixed:

  - ARTIFACTS OF THE ORACLE. The reference normalises NaN payloads, and reports a
    field as unknown when its tag was non-minimal. Both make the two dumps differ
    without anything being wrong with either implementation.
  - EVERYTHING ELSE, including `value: OTHER ...` — a divergence this script
    cannot explain. That is the interesting one, and it is what the exit code
    keys on.

⚠ THE EXIT CODE IS DELIBERATELY NARROW: 0 when every divergence fell into a
known bucket, 1 when an unclassified cause appeared or nothing was compared.
Failing on any divergence at all would fire on the artifacts every run; failing
on none would make the run unreadable by anything but a person.

WHAT IT NEEDS. `pip install protobuf` and the `probe` binary (README.md). The
default run is large — a quarter of a million inputs — so give it time.

    python3 camp5.py [well-formed] [mutated] [seed]     # default 50000 200000 11

WHAT IT PRODUCES. Section A (well-formed, decode + re-encode), section B
(mutated, decision + value), section C (divergences by cause with one worked
example each).
"""
import sys, random, collections
import gen, oracle, classify, camp4

NW = int(sys.argv[1]) if len(sys.argv) > 1 else 50000     # well-formed messages
NM = int(sys.argv[2]) if len(sys.argv) > 2 else 200000    # mutated inputs
SEED = int(sys.argv[3]) if len(sys.argv) > 3 else 11
rnd = random.Random(SEED)
SCHEMAS = ["Wide", "Repeated", "Presence", "Chain"]


def fields(s):
    if not s.startswith("OK "):
        return None
    body = s[3:]
    out, depth, cur, key = {}, 0, [], None
    # top-level split on ';' only (submessages are wrapped in {})
    part, buf = [], ""
    for ch in body:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        if ch == ";" and depth == 0:
            part.append(buf); buf = ""
        else:
            buf += ch
    part.append(buf)
    for p in part:
        if "=" in p:
            k, v = p.split("=", 1)
            out[k] = v
    return out


NANY = lambda v: v.startswith("f64:7ff") or v.startswith("f64:fff") or v.startswith("f32:7f8") \
    or v.startswith("f32:7fc") or v.startswith("f32:ff8") or v.startswith("f32:ffc")

# Causes that are properties of the ORACLE, not of either implementation.
ARTIFACTS = (
    "value: NaN payload (oracle normalises, artifact)",
    "value: field present for us, unknown for the reference (non-minimal tag)",
)


def cause(z, p):
    zr, pr = z.startswith("ERR"), p.startswith("ERR")
    if zr and pr:
        return None
    if zr != pr:
        return "decision: zig=%s" % (z.split(" ", 1)[1] if zr else "accept/py=" + p.split(" ", 1)[1])
    fz, fp = fields(z), fields(p)
    diff = sorted(k for k in set(fz) | set(fp) if fz.get(k) != fp.get(k))
    if diff == ["s32"]:
        return "value: sint32 zigzag/truncate order"
    if all(k in ("d", "f") for k in diff) and all(NANY(fz.get(k, "")) or NANY(fp.get(k, "")) for k in diff):
        return ARTIFACTS[0]
    if all(fp.get(k) in ("0", "<unset>", "h", "[]", "f64:0000000000000000", "f32:00000000") for k in diff):
        return ARTIFACTS[1]
    return "value: OTHER %s" % ",".join(diff)


cnt = collections.Counter()
causes = collections.Counter()
examples = {}
BATCH = 20000


def consume(rows):
    for (lbl, op, sch, hx, z, p) in rows:
        k = classify.kind(z, p)
        cnt[k] += 1
        if k.startswith("DIVERGE"):
            c = cause(z, p) or "?"
            causes[c] += 1
            examples.setdefault(c, (sch, hx, z[:200], p[:200]))


buf = []
for i in range(NW):
    sch = rnd.choice(SCHEMAS)
    m = gen.GEN[sch](rnd)
    hx = m.SerializeToString(deterministic=True).hex()
    buf += [("w%d" % i, "d", sch, hx), ("w%d" % i, "r", sch, hx)]
    if len(buf) >= BATCH:
        consume(gen.run(buf)); buf = []
if buf:
    consume(gen.run(buf)); buf = []
wf_total = sum(cnt.values())
print("A) well-formed reference messages, decode + re-encode compared: %d comparisons" % wf_total)
for k, v in cnt.most_common():
    print("     %-34s %d" % (k, v))

cnt.clear()
for i in range(NM):
    sch = rnd.choice(SCHEMAS)
    m = gen.GEN[sch](rnd)
    raw = m.SerializeToString(deterministic=True)
    for _ in range(rnd.randint(1, 3)):
        raw = camp4.mutate(raw, rnd)
    buf.append(("m%d" % i, "d", sch, raw.hex()))
    if len(buf) >= BATCH:
        consume(gen.run(buf)); buf = []
if buf:
    consume(gen.run(buf))
mut_total = sum(cnt.values())
print("\nB) mutated (hostile) inputs, decision + value compared: %d inputs" % mut_total)
for k, v in cnt.most_common():
    print("     %-34s %d" % (k, v))

print("\nC) divergences by cause (both campaigns):")
for c, v in causes.most_common():
    sch, hx, z, p = examples[c]
    mark = "   " if c in ARTIFACTS else "!! "
    print("%s%-58s %6d   e.g. %s %s" % (mark, c, v, sch, hx[:56]))

unexplained = [c for c in causes if c not in ARTIFACTS]
if wf_total == 0 and mut_total == 0:
    print("\n⛔ nothing was compared")
    sys.exit(1)
if unexplained:
    print("\n⛔ %d cause(s) outside the known artifacts — these are the ones to read"
          % len(unexplained))
sys.exit(1 if unexplained else 0)
