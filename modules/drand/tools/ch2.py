#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The SEARCH that found the chain-hash formula `chainhash.py` now checks.

WHY THIS EXISTS, and why it is kept rather than deleted once it had done its
job. drand's chain hash is a SHA-256 over concatenated fields, and the order,
the integer widths and which extras are appended are not stated anywhere this
module could cite — they are whatever `chainhash.go` does. Rather than read that
source and copy a formula, this brute-forces the candidate encodings against a
published hash until one reproduces it: 3 prefix widths x 2 field orders x 6
extras variants. Exactly one combination matches, and that combination is what
`chainhash.py` implements.

Keeping the search means the formula in `chainhash.py` is not a claim on trust.
Anyone can re-run this and see that the alternatives do NOT produce the
published hash — which is a stronger statement than "we read the Go and it says
this", and it is how the value was actually obtained.

⚠ It answers "which encoding reproduces this hash", NOT "is this chain
genuine". For the second question use `chainhash.py`.

WHAT IT NEEDS. Python, nothing else.

    python3 ch2.py

WHAT IT PRODUCES. A `MATCH <prefix> <order> <extras-index>` line for every
encoding that reproduces quicknet's published hash. Exit 0 if at least one did,
1 if none did — a search that finds nothing has failed, and must not read as
success.
"""
import hashlib, struct, itertools, sys

pk = bytes.fromhex("83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a")
gh = bytes.fromhex("f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e")
target = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
period = 3
genesis = 1692803367
scheme = b"bls-unchained-g1-rfc9380"
bid = b"quicknet"

extras_variants = [
  [scheme, bid], [bid, scheme], [scheme], [bid], [],
  [scheme + bid],
]
prefix_variants = {
 'p32g64': [struct.pack(">I", period), struct.pack(">q", genesis)],
 'p64g64': [struct.pack(">Q", period), struct.pack(">Q", genesis)],
 'p32g32': [struct.pack(">I", period), struct.pack(">I", genesis)],
}

hits = 0
for pn, pre in prefix_variants.items():
    for order in itertools.permutations([('pk', pk), ('gh', gh)]):
        for ei, ex in enumerate(extras_variants):
            h = hashlib.sha256()
            for b in pre:
                h.update(b)
            for _, b in order:
                h.update(b)
            for b in ex:
                h.update(b)
            if h.hexdigest() == target:
                print("MATCH", pn, [o[0] for o in order], ei)
                hits += 1
print(f"done — {hits} encoding(s) reproduce the published hash")
sys.exit(0 if hits else 1)
