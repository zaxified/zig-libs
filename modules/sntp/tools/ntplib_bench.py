# SPDX-License-Identifier: MIT
"""Second implementation for the sntp bench (informational): ntplib 0.4.0
(MIT) decoding the same 64 replies `tools/bench.zig` writes and computing
offset / delay / root distance. Python with float seconds, so the counts differ
from the exact-integer sides and are not compared; only its time is reported.

Run through hw (it is a generated measurement, not a test):
  hw run --name sntp-ntplib --mem 2G --timeout 300 -- \
    ~/.local/share/zig-libs/oracle-venvs/ntplib/bin/python3 -I modules/sntp/tools/ntplib_bench.py .zig-cache/bench-sntp
"""
import struct
import sys
import time

import ntplib

d = sys.argv[1]
raw = open(d + "/replies.bin", "rb").read()
msgs = []
while raw:
    n = raw[0] << 8 | raw[1]
    msgs.append(raw[2:2 + n])
    raw = raw[2 + n:]
t1, t4 = struct.unpack(">QQ", open(d + "/clock.bin", "rb").read())
t4 = t4 / 1e9


def once():
    acc = 0.0
    for m in msgs:
        s = ntplib.NTPStats()
        try:
            s.from_data(m)
        except Exception:
            continue
        # ntplib stores times as NTP seconds; orig_time is the request's T1
        s.orig_timestamp = t1 / 1e9 + ntplib.NTP.NTP_DELTA
        s.dest_timestamp = t4 + ntplib.NTP.NTP_DELTA
        acc += s.offset + s.delay + s.root_delay / 2 + s.root_dispersion
    return acc


n = 1
while True:
    t = time.perf_counter()
    for _ in range(n):
        once()
    if time.perf_counter() - t > 0.2:
        break
    n *= 2
best = 1e99
for _ in range(5):
    t = time.perf_counter()
    for _ in range(n):
        once()
    best = min(best, (time.perf_counter() - t) / n)
print("exchange\t%.0f" % (best * 1e9))
