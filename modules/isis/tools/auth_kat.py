#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for the authentication KATs in ../src/auth_kat_test.zig.

An independent computation of IS-IS Authentication TLV digests: every PDU is
assembled here field by field from ISO/IEC 10589 §9 (not by the Zig builders),
the digest comes from Python's `hmac`/`hashlib`, and the LSP checksum from the
ISO 8473 Annex C construction written out below. The Zig test builds the same
PDUs with the module's builders, signs them, and must reproduce these bytes.

Digest rules (RFC 5304 §2, RFC 5310 §3.3-§3.5):
  * the Authentication Value hashes as zeros (HMAC-MD5) or as Apad =
    0x878FE1F3 repeated L/4 times (RFC 5310);
  * in an LSP, Remaining Lifetime and Checksum hash as zero; the checksum is
    computed after the digest is in place.
Key preparation: plain RFC 2104 HMAC by default; `strict` applies RFC 5310
§3.3 (Ko = H(K) when K is longer than the hash output L).

Run: python3 -I tools/auth_kat.py   (prints one Zig test-table entry per KAT)
"""

import hashlib
import hmac
import struct

APAD = bytes.fromhex("878FE1F3") * 16

HASHES = {
    "hmac_md5": hashlib.md5,
    "hmac_sha1": hashlib.sha1,
    "hmac_sha224": hashlib.sha224,
    "hmac_sha256": hashlib.sha256,
    "hmac_sha384": hashlib.sha384,
    "hmac_sha512": hashlib.sha512,
}


def common(li, pdu_type):
    # discriminator, length indicator, version, id length (6), type, version,
    # reserved, max area addresses (3)
    return bytes([0x83, li, 1, 6, pdu_type, 1, 0, 3])


def auth_placeholder(alg, key_id, secret):
    if alg == "cleartext":
        value = bytes([1]) + secret
    elif alg == "hmac_md5":
        value = bytes([54]) + bytes(16)
    else:
        l = HASHES[alg]().digest_size
        value = bytes([3]) + struct.pack(">H", key_id) + APAD[:l]
    return bytes([10, len(value)]) + value


def mac(alg, secret, strict, msg):
    h = HASHES[alg]
    key = secret
    if strict and alg != "hmac_md5" and len(secret) > h().digest_size:
        key = h(secret).digest()
    return hmac.new(key, msg, h).digest()


def fletcher(region, off):
    """ISO 8473 Annex C checksum for a field at `off` within `region`."""
    buf = bytearray(region)
    buf[off] = buf[off + 1] = 0
    c0 = c1 = 0
    for b in buf:
        c0 = (c0 + b) % 255
        c1 = (c1 + c0) % 255
    n = off + 1
    length = len(buf)
    x = ((length - n) * c0 - c1) % 255
    y = ((length - n + 1) * (-c0) + c1) % 255
    if x == 0:
        x = 255
    if y == 0:
        y = 255
    return bytes([x, y])


def sign(pdu, auth_off, alg, secret, strict, is_lsp):
    """auth_off = offset of the Authentication TLV's code octet."""
    pdu = bytearray(pdu)
    if alg == "cleartext":
        return bytes(pdu)
    doff = auth_off + 3 if alg == "hmac_md5" else auth_off + 5
    l = HASHES[alg]().digest_size
    view = bytearray(pdu)
    if is_lsp:
        view[10:12] = b"\x00\x00"
        view[24:26] = b"\x00\x00"
    view[doff:doff + l] = bytes(l) if alg == "hmac_md5" else APAD[:l]
    pdu[doff:doff + l] = mac(alg, secret, strict, bytes(view))
    if is_lsp:
        pdu[24:26] = fletcher(bytes(pdu[12:]), 12)
    return bytes(pdu)


SYS = bytes.fromhex("1921680000ff")
TLV_PROTOS = bytes([129, 1, 0xCC])
TLV_AREA = bytes([1, 4, 3, 0x49, 0x00, 0x01])


def p2p_iih(alg, key_id, secret, strict):
    tlvs = auth_placeholder(alg, key_id, secret) + TLV_AREA + TLV_PROTOS
    total = 20 + len(tlvs)
    fixed = common(20, 17) + bytes([3]) + SYS + struct.pack(">HH", 30, total) + bytes([1])
    return sign(fixed + tlvs, 20, alg, secret, strict, False)


def lan_iih(alg, key_id, secret, strict):
    tlvs = auth_placeholder(alg, key_id, secret) + TLV_AREA
    total = 27 + len(tlvs)
    fixed = (common(27, 15) + bytes([1]) + SYS + struct.pack(">HH", 9, total)
             + bytes([64]) + SYS + bytes([1]))
    return sign(fixed + tlvs, 27, alg, secret, strict, False)


def lsp(alg, key_id, secret, strict, l2=False):
    tlvs = auth_placeholder(alg, key_id, secret) + TLV_AREA + TLV_PROTOS
    total = 27 + len(tlvs)
    lsp_id = SYS + bytes([0, 0])
    fixed = (common(27, 20 if l2 else 18) + struct.pack(">HH", total, 1200) + lsp_id
             + struct.pack(">I", 5) + b"\x00\x00" + bytes([0x03]))
    return sign(fixed + tlvs, 27, alg, secret, strict, True)


def csnp(alg, key_id, secret, strict):
    entry = struct.pack(">H", 1100) + SYS + bytes([0, 0]) + struct.pack(">IH", 5, 0x1234)
    tlvs = auth_placeholder(alg, key_id, secret) + bytes([9, len(entry)]) + entry
    total = 33 + len(tlvs)
    fixed = (common(33, 24) + struct.pack(">H", total) + SYS + bytes([0])
             + bytes(8) + b"\xff" * 8)
    return sign(fixed + tlvs, 33, alg, secret, strict, False)


def psnp(alg, key_id, secret, strict):
    entry = struct.pack(">H", 1100) + SYS + bytes([0, 0]) + struct.pack(">IH", 5, 0x1234)
    tlvs = auth_placeholder(alg, key_id, secret) + bytes([9, len(entry)]) + entry
    total = 17 + len(tlvs)
    fixed = common(17, 26) + struct.pack(">H", total) + SYS + bytes([0])
    return sign(fixed + tlvs, 17, alg, secret, strict, False)


KEY_SHORT = b"isis-test-key"            # 13 octets <= every L
KEY_22 = bytes(range(0x41, 0x41 + 22))  # 20 < 22 <= 64 for SHA-1
KEY_40 = bytes(range(0x61, 0x61 + 26)) + bytes(range(0x30, 0x30 + 14))  # 32 < 40 <= 64
KEY_LONG = bytes(range(1, 131))         # > every block size

KATS = [
    # name, builder, algorithm, key id, key, strict
    ("p2p_md5", p2p_iih, "hmac_md5", 0, KEY_SHORT, False),
    ("p2p_clear", p2p_iih, "cleartext", 0, b"letmein", False),
    ("lan_sha1", lan_iih, "hmac_sha1", 7, KEY_SHORT, False),
    ("csnp_sha1_k22", csnp, "hmac_sha1", 1, KEY_22, False),
    ("csnp_sha1_k22_strict", csnp, "hmac_sha1", 1, KEY_22, True),
    ("psnp_sha224", psnp, "hmac_sha224", 2, KEY_SHORT, False),
    ("lsp_sha256", lsp, "hmac_sha256", 3, KEY_SHORT, False),
    ("lsp_sha256_k40", lsp, "hmac_sha256", 3, KEY_40, False),
    ("lsp_sha256_k40_strict", lsp, "hmac_sha256", 3, KEY_40, True),
    ("lsp_md5", lsp, "hmac_md5", 0, KEY_SHORT, False),
    ("lsp_sha384", lsp, "hmac_sha384", 0xBEEF, KEY_SHORT, False),
    ("p2p_sha512_long", p2p_iih, "hmac_sha512", 65535, KEY_LONG, False),
    ("p2p_sha512_long_strict", p2p_iih, "hmac_sha512", 65535, KEY_LONG, True),
]


def main():
    for name, build, alg, key_id, key, strict in KATS:
        wire = build(alg, key_id, key, strict)
        print(f'    .{{ .name = "{name}", .wire = "{wire.hex()}" }},')


if __name__ == "__main__":
    main()
