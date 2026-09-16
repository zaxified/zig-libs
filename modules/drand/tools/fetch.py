#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture live drand documents — the raw material for this module's vectors.

WHY THIS EXISTS. The `/info` and `/public/<round>` documents pinned in
`src/root.zig` and `src/verify.zig` are bytes a foreign implementation served,
which is what makes them an EXTERNAL anchor rather than our own opinion. That
property only survives if the capture is reproducible: a vector nobody can
re-obtain is a constant with a story attached. This is the capture.

It reaches the REAL NETWORK (api.drand.sh and the League of Entropy testnet), so
it is here in `tools/` and never part of the module's tests.

WHAT IT NEEDS. Python with `urllib`, and working DNS.

    python3 fetch.py [outdir]     # default: ./live

WHAT IT PRODUCES. In <outdir>: `quicknet_info.json`, `quicknet_t_info.json`,
`quicknet_rounds.json` (~60 rounds, spread across the chain's history) and
`quicknet_t_rounds.json`. Feed them to `gen_vectors.py`.

⚠ It exits non-zero if a chain yielded no rounds at all. A fetcher that writes
an empty array and reports success is how an empty vector file gets committed:
every later run then "agrees" with nothing.
"""
import json, urllib.request, sys, os

BASE = "https://api.drand.sh"
QN = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
TN_BASE = "https://pl-us.testnet.drand.sh"
TN = "cc9c398442737cbd141526600919edd69f1d6f9b4adb67e4d912fbc64341a9a5"

out_dir = sys.argv[1] if len(sys.argv) > 1 else "live"


def get(u):
    with urllib.request.urlopen(u, timeout=20) as r:
        return json.loads(r.read())


os.makedirs(out_dir, exist_ok=True)
p = lambda name: os.path.join(out_dir, name)

qn_info = get(f"{BASE}/{QN}/info")
json.dump(qn_info, open(p("quicknet_info.json"), "w"))
tn_info = get(f"{TN_BASE}/{TN}/info")
json.dump(tn_info, open(p("quicknet_t_info.json"), "w"))

latest = get(f"{BASE}/{QN}/public/latest")["round"]
rounds = [1, 2, 1000, 1000000] + [latest - i * 400000 for i in range(0, 56)]
rounds = [r for r in rounds if r >= 1]
out = []
for r in sorted(set(rounds)):
    try:
        out.append(get(f"{BASE}/{QN}/public/{r}"))
    except Exception as e:
        print("skip", r, e, file=sys.stderr)
json.dump(out, open(p("quicknet_rounds.json"), "w"))
print("quicknet rounds fetched:", len(out), "latest:", latest)

tlatest = get(f"{TN_BASE}/{TN}/public/latest")["round"]
tout = []
for r in sorted(set([1, 1000, tlatest, tlatest - 100000, tlatest - 1000000])):
    if r < 1:
        continue
    try:
        tout.append(get(f"{TN_BASE}/{TN}/public/{r}"))
    except Exception as e:
        print("skip t", r, e, file=sys.stderr)
json.dump(tout, open(p("quicknet_t_rounds.json"), "w"))
print("testnet rounds fetched:", len(tout), "latest:", tlatest)

if not out or not tout:
    print("⛔ a chain yielded no rounds — the files written are empty and must not "
          "be used as vectors", file=sys.stderr)
    sys.exit(1)
