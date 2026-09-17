#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bidirectional differential: the `sealedbox` module vs real libsodium (PyNaCl),
driven through the module's public API only, via `driver.zig`'s line protocol.

Runs three independent comparisons over N random cases:
  1. module seals (deterministic ephemeral) -> byte-exact against a libsodium
     recomputation of crypto_box_seal.c's own construction
     (scalarmult_base -> BLAKE2b-192(epk||rpk) -> crypto_box_easy).
  2. module seals (real entropy)            -> libsodium crypto_box_seal_open decrypts.
  3. libsodium crypto_box_seal              -> module `open` decrypts.
Plus a negative control on the nonce argument order.

Needs: PyNaCl (`python3 -c "import nacl"`) — Apache License 2.0, verified at
its dist-info METADATA (`License: Apache License 2.0`). Not copyleft.
Produces: three agreement counts (out of N each) plus a negative-control
verdict on stdout; exit 0 iff all three are N/N and the control fired.

Usage (see `tools/README.md` for the full recipe, including how to build
`driver.zig`, and the measured result of the last run):
    diff_pynacl.py <driver-binary> [N]
"""
import os, subprocess, sys, secrets
import nacl.bindings as B

DRIVER = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 500

def run(lines):
    p = subprocess.run([DRIVER], input="\n".join(lines) + "\n",
                       capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("driver failed rc=%d: %s" % (p.returncode, p.stderr[:2000]))
    return p.stdout.strip().split("\n") if p.stdout.strip() else []

def sodium_seal(msg, rpk, esk):
    """libsodium's own crypto_box_seal construction, with the ephemeral key pinned."""
    epk = B.crypto_scalarmult_base(esk)
    nonce = B.crypto_generichash_blake2b_salt_personal(epk + rpk, digest_size=24)
    return epk + B.crypto_box(msg, nonce, rpk, esk)

LENS = [0, 1, 2, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 100, 255, 256, 1000, 4096]

def main():
    cases = []
    for i in range(N):
        rsk = secrets.token_bytes(32)
        rpk = B.crypto_scalarmult_base(rsk)
        seed = secrets.token_bytes(32)
        ln = LENS[i % len(LENS)] if i < 4 * len(LENS) else secrets.randbelow(2048)
        msg = secrets.token_bytes(ln)
        cases.append((rsk, rpk, seed, msg))

    # --- 1 + 2: module seals -----------------------------------------------
    cmds = []
    for rsk, rpk, seed, msg in cases:
        cmds.append("SEALD %s %s %s" % (seed.hex(), rpk.hex(), msg.hex()))
        cmds.append("SEAL %s %s" % (rpk.hex(), msg.hex()))
    out = run(cmds)
    assert len(out) == 2 * len(cases), (len(out), 2 * len(cases))

    n_exact = n_open = n_rev = 0
    fails = []
    for i, (rsk, rpk, seed, msg) in enumerate(cases):
        det = out[2 * i]
        rnd = out[2 * i + 1]
        if not det.startswith("OK "):
            fails.append(("SEALD-error", i, det)); continue
        got = bytes.fromhex(det[3:])
        # NOTE: std's X25519.KeyPair.generate uses the raw 32 random bytes as the
        # secret scalar (clamping happens inside the scalar multiply), exactly as
        # libsodium's crypto_box_keypair does -> the same `seed` is the same esk.
        want = sodium_seal(msg, rpk, seed)
        if got == want:
            n_exact += 1
        else:
            fails.append(("byte-mismatch", i, got.hex()[:64], want.hex()[:64]))
        if not rnd.startswith("OK "):
            fails.append(("SEAL-error", i, rnd)); continue
        rndb = bytes.fromhex(rnd[3:])
        try:
            pt = B.crypto_box_seal_open(rndb, rpk, rsk)
        except Exception as e:
            fails.append(("sodium-open-failed", i, repr(e))); continue
        if pt == msg:
            n_open += 1
        else:
            fails.append(("sodium-open-plaintext", i))

    # --- 3: libsodium seals, the module opens ------------------------------
    cmds = []
    for rsk, rpk, seed, msg in cases:
        ct = B.crypto_box_seal(msg, rpk)
        cmds.append("OPEN %s %s %s" % (rsk.hex(), rpk.hex(), ct.hex()))
    out = run(cmds)
    for i, (rsk, rpk, seed, msg) in enumerate(cases):
        r = out[i]
        if not r.startswith("OK "):
            fails.append(("module-open-error", i, r)); continue
        if bytes.fromhex(r[3:]) == msg:
            n_rev += 1
        else:
            fails.append(("module-open-plaintext", i))

    # --- negative control: swapped nonce argument order must NOT match ------
    rsk, rpk, seed, msg = cases[0]
    epk = B.crypto_scalarmult_base(seed)
    bad_nonce = B.crypto_generichash_blake2b_salt_personal(rpk + epk, digest_size=24)
    bad = epk + B.crypto_box(msg, bad_nonce, rpk, seed)
    good = sodium_seal(msg, rpk, seed)
    neg_ok = (bad != good)

    print("cases                                : %d" % len(cases))
    print("1. byte-exact vs libsodium recompute : %d/%d" % (n_exact, len(cases)))
    print("2. libsodium opens module ciphertext : %d/%d" % (n_open, len(cases)))
    print("3. module opens libsodium ciphertext : %d/%d" % (n_rev, len(cases)))
    print("negative control (nonce arg order)   : %s" % ("differs (good)" if neg_ok else "IDENTICAL (control dead!)"))
    print("total comparisons                    : %d" % (3 * len(cases)))
    print("mismatches                           : %d" % len(fails))
    for f in fails[:20]:
        print("   ", f)
    return 1 if fails or not neg_ok else 0

sys.exit(main())
