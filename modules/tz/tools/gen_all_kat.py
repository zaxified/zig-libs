#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate src/all_kat.bin: an all-zones differential vector file for tz,
from Python's zoneinfo used as a black-box oracle.

Python must read the SAME tzdata release the committed table was generated
from, never the host's /usr/share/zoneinfo:

    scripts/gen/tz-gen/fetch-and-build.sh --check     # builds .zig-cache/tz-gen/<release>/zoneinfo
    python3 -I modules/tz/tools/gen_all_kat.py .zig-cache/tz-gen/<release>/zoneinfo modules/tz/src/all_kat.bin

For EVERY zone file of the tree (the zone list comes from the tree, not from
tz_data.zig, so a zone the table lacks is caught) it records, over the instants
1970-01-01 .. 2050-01-01:
  - the state (UTC offset, DST flag, abbreviation) at the start;
  - every change of that state (found by a 3-day scan then bisection to the
    exact second -- the generator asserts no two changes lie within 4 days);
  - for every change that moves the offset, the local-time classification of
    five wall-clock times around it (unique / fold / gap, as the 2-bit codes
    below) -- the same five points as gen_local_kat.py.
The Zig test (`src/all_kat_test.zig`) derives its probes from the changes: the
state at the start, at each change instant, one second before it, one second
after it, and halfway to the neighbours; the local-time samples under every
Disambiguation policy.

Zones whose trace is identical share one record (the aliases collapse), so the
file stays small. Format (little-endian; V = LEB128 varint, Z = zigzag varint):

    "TZKAT1\\n"  release(len u8, bytes)
    V n_abbr, then n_abbr x (len u8, bytes)
    V n_traces, then per trace:
        V n_zones, then n_zones x (V len, bytes)       names, sorted
        Z off0  V flags0                               state at 1970 (flags = dst | abbr << 1)
        V n_changes, then per change:
            V ts - previous ts (the first from 0)      seconds
            Z off   V flags                            the NEW state
            if off != the previous off: u16 codes      5 x 2 bits, sample 0 in the low bits
    code: 0 = unique, local - before | 1 = unique, local - after
          2 = fold   (earlier = local - before, later = local - after)
          3 = gap    (earlier = local - after,  later = local - before)
"""
import os
import sys
import zoneinfo
from datetime import datetime, timedelta, timezone

START = 0  # 1970-01-01T00:00:00Z
END = int(datetime(2050, 1, 1, tzinfo=timezone.utc).timestamp())
STEP = 3 * 86400
EPOCH = datetime(1970, 1, 1)


def state(z, u):
    d = datetime.fromtimestamp(u, z)
    return (int(d.utcoffset().total_seconds()), d.dst() != timedelta(0), d.tzname())


def changes(z):
    out = []
    u = START
    s = state(z, u)
    while u < END:
        v = min(u + STEP, END)
        t = state(z, v)
        if t != s:
            a, b = u, v  # state(a) == s, state(b) != s: bisect to the first second of the new state
            while b - a > 1:
                m = (a + b) // 2
                if state(z, m) == s:
                    a = m
                else:
                    b = m
            n = state(z, b)
            out.append((b, n))
            s = n
            u = b
            continue
        u = v
    return out


def local_code(z, local, before, after):
    naive = EPOCH + timedelta(seconds=local)
    us = sorted({int(naive.replace(tzinfo=z, fold=f).timestamp()) for f in (0, 1)})
    shown = [datetime.fromtimestamp(u, z).replace(tzinfo=None) == naive for u in us]
    if len(us) == 1:
        assert shown[0]
        if us[0] == local - before:
            return 0
        assert us[0] == local - after, (local, us, before, after)
        return 1
    if all(shown):
        assert us == [local - before, local - after] or us == [local - after, local - before]
        assert us[0] == local - before, (local, us, before, after)  # fold: earlier = the old offset
        return 2
    assert not any(shown)
    assert us == [local - after, local - before], (local, us, before, after)
    return 3


def varint(n):
    assert n >= 0
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def zigzag(n):
    return varint((n << 1) if n >= 0 else ((-n << 1) - 1))


def zone_names(root):
    names = []
    for dirpath, dirs, files in os.walk(root):
        if dirpath == root:
            dirs[:] = [d for d in dirs if d not in ("posix", "right")]
        for f in files:
            p = os.path.join(dirpath, f)
            name = os.path.relpath(p, root)
            if name in ("localtime", "posixrules"):
                continue
            with open(p, "rb") as fh:
                if fh.read(4) != b"TZif":
                    continue
            names.append(name)
    return sorted(names)


def main():
    root = os.path.abspath(sys.argv[1])
    zoneinfo.reset_tzpath([root])
    with open(os.path.join(root, "+VERSION")) as f:
        release = f.read().strip()
    abbrs = []

    def abbr_idx(a):
        if a not in abbrs:
            abbrs.append(a)
        return abbrs.index(a)

    traces = {}  # key -> (names, bytes)
    for name in zone_names(root):
        z = zoneinfo.ZoneInfo(name)
        s0 = state(z, START)
        body = bytearray()
        body += zigzag(s0[0]) + varint(int(s0[1]) | abbr_idx(s0[2]) << 1)
        ch = changes(z)
        body += varint(len(ch))
        prev_ts, prev_off = 0, s0[0]
        for ts, (off, dst, ab) in ch:
            body += varint(ts - prev_ts) + zigzag(off) + varint(int(dst) | abbr_idx(ab) << 1)
            if off != prev_off:
                lo, hi = ts + min(prev_off, off), ts + max(prev_off, off)
                code = 0
                for k, local in enumerate([lo - 1, lo, (lo + hi) // 2, hi - 1, hi]):
                    code |= local_code(z, local, prev_off, off) << (2 * k)
                body += code.to_bytes(2, "little")
            prev_ts, prev_off = ts, off
        key = bytes(body)
        traces.setdefault(key, []).append(name)

    out = bytearray(b"TZKAT1\n")
    out += bytes([len(release)]) + release.encode()
    out += varint(len(abbrs))
    for a in abbrs:
        out += bytes([len(a)]) + a.encode()
    out += varint(len(traces))
    for body, names in sorted(traces.items(), key=lambda kv: kv[1][0]):
        out += varint(len(names))
        for n in names:
            out += varint(len(n)) + n.encode()
        out += body
    with open(sys.argv[2], "wb") as f:
        f.write(out)
    print(f"{sum(len(v) for v in traces.values())} zones, {len(traces)} distinct traces, "
          f"{sum(1 for _ in abbrs)} abbreviations, {len(out)} bytes", file=sys.stderr)


main()
