#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Turn `strace -e trace=sendmsg -e write=all` output into one hex line per
buffer written, plus -- when a sendmsg used several iovecs -- the concatenation
of that call's buffers, which is the actual netlink datagram.

    | 00000  2c 00 00 00 24 00 05 05  48 f4 9a 6a 00 00 00 00  ,...$...H..j.... |

Called by capture.sh; not useful on its own.
"""
import re, sys

bufs, cur, calls = [], [], []
for line in open(sys.argv[1], errors="replace"):
    if line.startswith("sendmsg("):
        if cur:
            bufs.append("".join(cur)); cur = []
        if bufs:
            calls.append(bufs)
        bufs = []
    m = re.match(r"\s*\|\s*[0-9a-f]{5}\s{2}(.*)$", line.rstrip("\n"))
    if m:
        cur.append(re.sub(r"[^0-9a-f]", "", m.group(1)[:48]))
    elif cur:
        bufs.append("".join(cur)); cur = []
if cur:
    bufs.append("".join(cur))
if bufs:
    calls.append(bufs)

for bs in calls:
    for b in bs:
        print(b)
    if len(bs) > 1:
        print("".join(bs))
