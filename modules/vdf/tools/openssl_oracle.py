#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""External value oracle for `eval` (finding O1, A1 audit, disposition
2026-09-17), via OpenSSL's `libcrypto` `BN_mod_exp`.

`BN_mod_exp(x, 2**k, N)` performs the same computation `eval`'s sequential
squaring loop does — `x^(2^k) mod N` — through an independent implementation
(OpenSSL's modexp, not this repo's `montint`/`std.crypto.ff`), at a `k` far
beyond the shipped KATs (largest in `modules/vdf/src/kat_test.zig` is
`T = 10_000`). It is a VALUE oracle: this is what makes it worth keeping under
`CONVENTIONS.md` §9, not merely a timer (the original audit script this was
adopted from also measured `BN_mod_exp` wall time per squaring for a delay
calibration finding, F5; that timing-only part is deliberately NOT kept here
— the audit record keeps the pre-adoption original).

This module's `eval` returns the CANONICAL representative of `x^(2^k)` in the
quotient group Z_N*/{±1}, i.e. `min(v, N-v)` (`group.canonicalize` — see
`group.zig`'s module doc comment for why: `-1` has order 2 in Z_N*, so a
value and its negation are the same VDF output up to sign). OpenSSL's raw
`BN_mod_exp` does not know about that fold, so this script applies it in
Python before printing — the fold is public-input arithmetic on `N` alone,
not a copy of any module source — making its output directly byte-comparable
against `modules/vdf/tools/eval_driver.zig`'s.

WHAT IT NEEDS: OpenSSL 3 `libcrypto` importable via `ctypes` (system package;
nothing pip-installed, nothing vendored). Tested against OpenSSL 3.5.5.

WHAT IT PRODUCES: one line, `y <512 lowercase hex chars>` — same shape as
`eval_driver.zig`'s output line, for `diff`.

    python3 modules/vdf/tools/openssl_oracle.py [k]      # default k=200000
"""
import ctypes
import ctypes.util
import sys

# The RSA-2048 Factoring Challenge modulus this module ships
# (`group.rsa2048ChallengeModulus` / `group.zig`'s `rsa2048_challenge_hex`).
N_HEX = (
    "c7970ceedcc3b0754490201a7aa613cd73911081c790f5f1a8726f463550bb5b"
    "7ff0db8e1ea1189ec72f93d1650011bd721aeeacc2acde32a04107f0648c2813"
    "a31f5b0b7765ff8b44b4b6ffc93384b646eb09c7cf5e8592d40ea33c80039f35"
    "b4f14a04b51f7bfd781be4d1673164ba8eb991c2c4d730bbbe35f592bdef524a"
    "f7e8daefd26c66fc02c479af89d64d373f442709439de66ceb955f3ea37d5159"
    "f6135809f85334b5cb1813addc80cd05609f10ac6a95ad65872c909525bdad32"
    "bc729592642920f24c61dc5b3c3b7923e56b16a4d9d373d8721f24a3fc0f1b31"
    "31f55615172866bccc30f95054c824e733a5eb6817f7bc16399d48c6361cc7e5"
)

k = int(sys.argv[1]) if len(sys.argv) > 1 else 200000

path = ctypes.util.find_library("crypto") or "libcrypto.so.3"
lib = ctypes.CDLL(path)
lib.BN_new.restype = ctypes.c_void_p
lib.BN_CTX_new.restype = ctypes.c_void_p
lib.BN_bin2bn.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
lib.BN_bin2bn.restype = ctypes.c_void_p
lib.BN_mod_exp.argtypes = [ctypes.c_void_p] * 5
lib.BN_mod_exp.restype = ctypes.c_int
lib.BN_bn2bin.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
lib.BN_bn2bin.restype = ctypes.c_int


def bn(v: int):
    b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    return lib.BN_bin2bn(b, len(b), None)


N = int(N_HEX, 16)
n_bn, x_bn, e_bn, r_bn = bn(N), bn(5), bn(1 << k), lib.BN_new()
ctx = lib.BN_CTX_new()

assert lib.BN_mod_exp(r_bn, x_bn, e_bn, n_bn, ctx) == 1

buf = ctypes.create_string_buffer(256)
n = lib.BN_bn2bin(r_bn, buf)
raw = int.from_bytes(buf.raw[:n], "big")

# Fold into the quotient Z_N*/{+-1} the same way `group.canonicalize` does,
# so this is comparable to `eval`'s return value rather than to the raw
# (unfolded) OpenSSL result.
canon = min(raw, N - raw)
val = canon.to_bytes(256, "big").hex()

print(f"y {val}")
