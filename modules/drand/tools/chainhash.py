#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Re-derive each drand chain's own hash from the fields it publishes, and check
it against the hash the network advertises.

WHY THIS EXISTS. A chain hash is the identifier a consumer pins; everything this
module verifies is scoped to it. The module reads that hash out of `/info` and
trusts it. Nothing in the module derives it, so a chain whose fields and hash
disagree — a misconfigured relay, a substituted document — reads as valid. This
recomputes it the way drand does (`chainhash.go`: period, genesis, public key,
group hash, and the beacon id unless it is "default") and compares.

It is a RE-DERIVATION oracle, not an external one: it catches a transcription
slip or a swapped field, not a misreading shared with the drand source.

WHAT IT NEEDS. Python, nothing else — the three chains are pinned below exactly
as published, so it is offline and deterministic.

    python3 chainhash.py

WHAT IT PRODUCES. One line per chain with computed vs published and MATCH or
MISMATCH, a total, and an EXIT CODE: 0 only if every chain matched.

⚠ The exit code is the point. Until 2026-09-16 this script printed MISMATCH and
then fell off the end of the file, which is exit 0 — so anything that ran it
without reading the text was told the chains agreed.
"""
import hashlib, struct, sys

DEFAULT_BEACON = "default"


def chain_hash(period, genesis, pk_hex, group_hash_hex, beacon_id):
    h = hashlib.sha256()
    h.update(struct.pack(">I", period))
    h.update(struct.pack(">q", genesis))
    h.update(bytes.fromhex(pk_hex))
    h.update(bytes.fromhex(group_hash_hex))
    if beacon_id and beacon_id != DEFAULT_BEACON:
        h.update(beacon_id.encode())
    return h.hexdigest()


# (beacon id, period, genesis, public key, group hash, PUBLISHED chain hash)
cases = [
 ("quicknet", 3, 1692803367,
  "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
  "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e",
  "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"),
 # ⚠ The groupHash here was `a81e9d63f614ccdb...` until 2026-09-16 and does not
 # belong to this chain: with it, quicknet-t computes 7094dd83... against a
 # published cc9c3984..., i.e. this oracle reported a MISMATCH on every run it
 # ever made — and exited 0 anyway, so nobody saw it. The module had already
 # caught the same stale fixture and says so at `src/chaininfo.zig`'s
 # `quicknet_t_info_json`: "An earlier fixture in verify.zig carried a groupHash
 # that did not belong to this chain and nothing noticed". The value below is
 # the one the module's own live /info document carries.
 ("quicknet-t", 3, 1689232296,
  "b15b65b46fb29104f6a4b5d1e11a8da6344463973d423661bb0804846a0ecd1ef93c25057f1c0baab2ac53e56c662b66072f6d84ee791a3382bfb055afab1e6a375538d8ffc451104ac971d2dc9b168e2d3246b0be2015969cbaac298f6502da",
  "40d49d910472d4adb1d67f65db8332f11b4284eecf05c05c5eacd5eef7d40e2d",
  "cc9c398442737cbd141526600919edd69f1d6f9b4adb67e4d912fbc64341a9a5"),
 ("default", 30, 1595431050,
  "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31",
  "176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a",
  "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"),
]

ok = 0
for name, p, g, pk, gh, pub in cases:
    c = chain_hash(p, g, pk, gh, name)
    print(f"{name:12s} computed={c}\n{'':12s} published={pub}  {'MATCH' if c == pub else 'MISMATCH'}")
    ok += c == pub
print(f"{ok}/{len(cases)} match")
sys.exit(0 if ok == len(cases) else 1)
