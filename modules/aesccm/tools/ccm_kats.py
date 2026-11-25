#!/usr/bin/env python3
# Recipe for the KAT table in ../src/root.zig (`kats`): AES-CCM outputs from
# Python `cryptography`'s AESCCM (OpenSSL), over inputs that the test
# re-derives with its `expand` helper (SHA-256 of "<label>-<counter>",
# concatenated). Needs: python3 with `cryptography` (pip install --user
# cryptography). Output: one row per case, "key_len tag_len nonce_len ad_len
# pt_len ciphertext||tag", pasted into `kats`.
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


def expand(label, n):
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(f"{label}-{i}".encode()).digest()
        i += 1
    return out[:n]


CASES = [(16, 8, 12, 0, 0), (16, 8, 12, 13, 16), (16, 16, 12, 20, 33), (32, 16, 12, 0, 64),
         (32, 8, 12, 5, 1), (16, 16, 13, 8, 31), (32, 8, 13, 300, 17), (16, 8, 12, 70000, 40)]
# AES-192 rows (`kats192`): all four tag/nonce combinations of the tests.
CASES_192 = [(24, 8, 12, 0, 0), (24, 8, 12, 13, 33), (24, 16, 12, 20, 16), (24, 16, 12, 300, 64),
             (24, 8, 13, 8, 31), (24, 8, 13, 70000, 17), (24, 16, 13, 5, 1), (24, 16, 13, 0, 40)]

for kl, tl, nl, al, pl in CASES + CASES_192:
    k, n, a, p = expand("key", kl), expand("nonce", nl), expand("ad", al), expand("pt", pl)
    print(kl, tl, nl, al, pl, AESCCM(k, tag_length=tl).encrypt(n, p, a).hex())
