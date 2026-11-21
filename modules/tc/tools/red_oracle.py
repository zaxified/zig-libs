#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for the rows in `src/redparams.zig`'s tables: run a stock `tc ... red`
(or `sfq` with RED) through `capture.sh` for each parameter set and print one
Zig table row per set, in the field order of the test's `RedCase`.

    modules/tc/tools/red_oracle.py red   "limit 100000 min 10000 max 30000 avpkt 1000 burst 20"
    modules/tc/tools/red_oracle.py sfq   "limit 100 redflowlimit 100000 avpkt 1000 burst 20 ecn"
    modules/tc/tools/red_oracle.py grid  200   # 200 random red parameter sets (seed 7)

A set `tc` refuses prints `# refused: <args>`. The derivation in `redparams.zig`
was fitted to, and is checked against, rows from this script; it needs a
foreign toolchain (iproute2, strace, unprivileged user namespaces), so like
`capture.sh` it is run by hand, never by `zig build test-tc`.
"""
import random, struct, subprocess, sys, zlib, os

HERE = os.path.dirname(os.path.abspath(__file__))
CAP = os.path.join(HERE, "capture.sh")

def capture(cmd):
    out = subprocess.run([CAP, cmd], capture_output=True, text=True, timeout=60).stdout.split("\n")
    return max(out, key=len) if out else ""

def options(b, kind):
    i = b.find(kind.encode() + b"\0")
    if i < 0:
        return None
    p = (i + len(kind) + 1 + 3) & ~3
    ln, _ = struct.unpack_from("<HH", b, p)
    return b[p + 4:p + ln]

def red_row(args):
    b = bytes.fromhex(capture("tc qdisc add dev lo root handle 2: red " + args) or "00")
    o = options(b, "red")
    if o is None:
        return None
    res, p = {}, 0
    while p < len(o):
        ln, ty = struct.unpack_from("<HH", o, p)
        pl, ty = o[p + 4:p + ln], ty & 0x7fff
        if ty == 1: res["parms"] = struct.unpack("<IIIBBBB", pl)
        elif ty == 2: res["crc"] = zlib.crc32(pl)
        elif ty == 3: res["max_p"] = struct.unpack("<I", pl)[0]
        p += (ln + 3) & ~3
    lim, mn, mx, w, pl_, sc, fl = res["parms"]
    return mn, mx, w, pl_, sc, res["max_p"], res["crc"], fl

def sfq_row(args):
    b = bytes.fromhex(capture("tc qdisc add dev lo root handle 1: sfq " + args) or "00")
    o = options(b, "sfq")
    if o is None or len(o) < 48:
        return None
    lim, mn, mx, w, pl_, sc, fl, maxp = struct.unpack_from("<IIIBBBBI", o, 28)
    return mn, mx, w, pl_, sc, maxp, 0, fl

def fields(args):
    t = [x for x in args.split() if x not in ("ecn", "harddrop", "adaptive", "nodrop")]
    return dict(zip(t[::2], t[1::2]))

def bytes_per_s(s):
    """`tc`'s rate words as bytes per second (bit, Kbit, Mbit, Gbit; a bare number is bytes/s)."""
    for suffix, mul in (("gbit", 1e9 / 8), ("mbit", 1e6 / 8), ("kbit", 1e3 / 8), ("bit", 1 / 8)):
        if s.lower().endswith(suffix):
            return int(float(s[:-len(suffix)]) * mul)
    return int(s)

def zig(args, row, sfq):
    d = fields(args)
    lim = d["redflowlimit"] if sfq else d["limit"]
    bw = bytes_per_s(d.get("bandwidth", "0"))
    return (".{ .limit = %s, .min = %s, .max = %s, .avpkt = %s, .burst = %s, .p = %s, .bw = %d, "
            ".qmin = %d, .qmax = %d, .wlog = %d, .plog = %d, .scell = %d, .max_p = %d, .crc = %d, .flags = %d },") % (
        lim, d.get("min", "null"), d.get("max", "null"), d.get("avpkt", "0"), d.get("burst", "null"),
        d.get("probability", "0.02"), bw, *row)

def main():
    mode = sys.argv[1]
    if mode == "grid":
        random.seed(7)
        sets = []
        for _ in range(int(sys.argv[2])):
            avp = random.choice([64, 100, 200, 500, 1000, 1500, 3000, 9000])
            mn = int(avp * random.uniform(2, 150)); mx = int(mn * random.uniform(1.5, 6))
            sets.append("limit %d min %d max %d avpkt %d burst %d bandwidth %s probability %s" % (
                int(mx * random.uniform(1.2, 6)), mn, mx, avp, max(1, int(mn / avp + random.choice([0, 1, 2, 5, 10, 30, 100]))),
                random.choice(["100Kbit", "1Mbit", "10Mbit", "100Mbit", "1Gbit", "10Gbit"]),
                random.choice(["0.001", "0.01", "0.02", "0.05", "0.1", "0.5", "1.0"])))
        mode = "red"
    else:
        sets = sys.argv[2:]
    for a in sets:
        r = (sfq_row if mode == "sfq" else red_row)(a)
        print(zig(a, r, mode == "sfq") if r else "# refused: " + a)

main()
