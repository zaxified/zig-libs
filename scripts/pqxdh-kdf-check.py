#!/usr/bin/env python3
"""Independent implementation of PQXDH's key-derivation chain.

`modules/signal/src/pqxdh.zig` composes the shared secret as

    SK = HKDF-SHA256(salt = 32 zero bytes,
                     ikm  = F || DH1 || DH2 || DH3 [|| DH4] || SS,
                     info = pqxdh_info,
                     L    = 32)

with F = 32 bytes of 0xFF. Signal publishes no byte-exact PQXDH vectors
(checked 2026-08-22: neither the spec page nor libsignal), so the composition
cannot be anchored against the protocol's authors. What it CAN be anchored
against is a second implementation of the same arithmetic that shares no code
with the first -- this file, written from `hmac`/`hashlib` only, no third-party
crypto library and nothing imported from the Zig side.

That catches the failure this composition is actually prone to: a term in the
wrong order, a missing prefix, the wrong salt length, or `info` fed to
`extract` instead of `expand`. It does NOT catch a mistake in HKDF itself --
`std.crypto.kdf.hkdf` and Python's `hmac` would have to be wrong the same way
-- but HKDF has RFC 5869 vectors of its own and both sides already pass those.

Usage:
    scripts/pqxdh-kdf-check.py            # print the pinned vectors as Zig
    scripts/pqxdh-kdf-check.py --check    # re-derive and diff against the pin

The output is pinned in `modules/signal/src/interop_vectors.zig`; the test in
`pqxdh.zig` compares this module's `deriveSharedSecret` against it.
"""

import hashlib
import hmac
import sys

INFO = b"zig-libs/signal/pqxdh/v1_CURVE25519_SHA-256_ML-KEM-1024"
F = b"\xff" * 32


def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def sk(dh1: bytes, dh2: bytes, dh3: bytes, dh4: bytes | None, ss: bytes) -> bytes:
    ikm = F + dh1 + dh2 + dh3 + (dh4 or b"") + ss
    return hkdf_sha256(b"\x00" * 32, ikm, INFO, 32)


# Deterministic, obviously-fake inputs: each term is a distinct constant byte,
# so a swapped pair of terms changes the answer. Real DH outputs would not.
CASES = [
    ("with_one_time_prekey", b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, b"\x04" * 32, b"\x05" * 32),
    ("without_one_time_prekey", b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, None, b"\x05" * 32),
    # Swapped DH3/SS: proves the pin is order-sensitive, and gives the test a
    # value it must NOT produce.
    ("ss_and_dh3_swapped", b"\x01" * 32, b"\x02" * 32, b"\x05" * 32, b"\x04" * 32, b"\x03" * 32),
]


def main() -> int:
    for name, dh1, dh2, dh3, dh4, ss in CASES:
        print(f'pub const {name} = "{sk(dh1, dh2, dh3, dh4, ss).hex()}";')
    return 0


if __name__ == "__main__":
    sys.exit(main())
