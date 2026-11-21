# Recipe for the frozen BIP152 short-ID value in src/compact_block.zig: an independent
# SipHash-2-4 (written from the SipHash paper, Aumasson and Bernstein 2012) and hashlib's
# SHA-256, nothing from the module. Checked first against the paper's published vector.
#   python3 -I modules/btcp2p/tools/shortid_kat.py
import hashlib
import struct

M = (1 << 64) - 1


def rotl(x, b):
    return ((x << b) | (x >> (64 - b))) & M


def siphash24(key, data):
    k0, k1 = struct.unpack("<QQ", key)
    v0 = k0 ^ 0x736F6D6570736575
    v1 = k1 ^ 0x646F72616E646F6D
    v2 = k0 ^ 0x6C7967656E657261
    v3 = k1 ^ 0x7465646279746573

    def rnd():
        nonlocal v0, v1, v2, v3
        v0 = (v0 + v1) & M
        v1 = rotl(v1, 13) ^ v0
        v0 = rotl(v0, 32)
        v2 = (v2 + v3) & M
        v3 = rotl(v3, 16) ^ v2
        v0 = (v0 + v3) & M
        v3 = rotl(v3, 21) ^ v0
        v2 = (v2 + v1) & M
        v1 = rotl(v1, 17) ^ v2
        v2 = rotl(v2, 32)

    n = len(data) // 8 * 8
    for i in range(0, n, 8):
        m = struct.unpack("<Q", data[i : i + 8])[0]
        v3 ^= m
        rnd()
        rnd()
        v0 ^= m
    last = ((len(data) & 0xFF) << 56) | int.from_bytes(data[n:], "little")
    v3 ^= last
    rnd()
    rnd()
    v0 ^= last
    v2 ^= 0xFF
    for _ in range(4):
        rnd()
    return v0 ^ v1 ^ v2 ^ v3


assert siphash24(bytes(range(16)), bytes(range(15))) == 0xA129CA6149BE45E5

header = bytes((i * 7 + 1) & 0xFF for i in range(80))
nonce = 0x0123456789ABCDEF
key = hashlib.sha256(header + struct.pack("<Q", nonce)).digest()[:16]
txhash = bytes((i * 11 + 3) & 0xFF for i in range(32))
sid = siphash24(key, txhash) & 0xFFFFFFFFFFFF
print("key", key.hex())
print("shortid", struct.pack("<Q", sid)[:6].hex())
