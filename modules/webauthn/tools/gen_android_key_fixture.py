#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for src/android_key_fixture.zig (synthetic, NOT an Android attestation).

W3C §16.14's example certificate carries a KeyDescription whose challenge does not match its own signature's
clientDataHash, so it cannot serve as a positive anchor. This builds `android-key` attestations per WebAuthn
§8.4 with python `cryptography`: a P-256 credential key, a self-signed certificate over it with the Android
extension 1.3.6.1.4.1.11129.2.1.17 (KeyDescription with `attestationChallenge`, `softwareEnforced`,
`teeEnforced`), and `sig` over authData || clientDataHash. One good object and one variant per rejected rule.

Run from the module directory:  python3 tools/gen_android_key_fixture.py > src/android_key_fixture.zig
"""
import datetime, hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

EXT_OID = ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
client_data_hash = hashlib.sha256(b"android fixture client data").digest()


def cbor(v):
    def head(mt, n):
        if n < 24: return bytes([mt << 5 | n])
        if n < 256: return bytes([mt << 5 | 24, n])
        return bytes([mt << 5 | 25]) + n.to_bytes(2, "big")
    if isinstance(v, int): return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str): return head(3, len(v)) + v.encode()
    if isinstance(v, list): return head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, tuple): return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v)
    raise TypeError(v)


def der(tag, content):
    n = len(content)
    l = bytes([n]) if n < 128 else (bytes([0x81, n]) if n < 256 else bytes([0x82]) + n.to_bytes(2, "big"))
    return bytes([tag]) + l + content


def der_int(v): return der(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big"))


def explicit(tag, inner):  # context-specific constructed tag, possibly high-tag-number
    if tag < 31: return der(0xA0 | tag, inner)
    out, t = [tag & 0x7F], tag >> 7
    while t: out.insert(0, 0x80 | (t & 0x7F)); t >>= 7
    return bytes([0xBF]) + bytes(out) + der(0, inner)[1:]


def auth_list(purpose=(2,), origin=0, all_applications=False):
    parts = b""
    if purpose is not None: parts += explicit(1, der(0x31, b"".join(der_int(p) for p in purpose)))
    if all_applications: parts += explicit(600, der(0x05, b""))
    if origin is not None: parts += explicit(702, der_int(origin))
    return der(0x30, parts)


def make(cert_key, cred_key, challenge, sw, tee, sign_data=None):
    pub = cred_key.public_key().public_numbers()
    x, y = pub.x.to_bytes(32, "big"), pub.y.to_bytes(32, "big")
    cose = cbor(((1, 2), (3, -7), (-1, 1), (-2, x), (-3, y)))
    cred_id = hashlib.sha256(b"android cred").digest()
    auth = hashlib.sha256(b"example.org").digest() + bytes([0x41]) + (1).to_bytes(4, "big") + bytes(16) \
        + len(cred_id).to_bytes(2, "big") + cred_id + cose
    kd = der(0x30, der_int(300) + der(0x0A, b"\x00") + der_int(0) + der(0x0A, b"\x00") + der(0x04, challenge)
             + der(0x04, b"") + sw + tee)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "android fixture")])
    t0 = datetime.datetime(2026, 1, 1)
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(cert_key.public_key())
         .serial_number(1).not_valid_before(t0).not_valid_after(t0 + datetime.timedelta(days=3650))
         .add_extension(x509.UnrecognizedExtension(EXT_OID, kd), critical=False)
         .sign(cert_key, hashes.SHA256()))
    cert = c.public_bytes(serialization.Encoding.DER)
    sig = cert_key.sign(auth + client_data_hash, ec.ECDSA(hashes.SHA256()))
    return cbor((("fmt", "android-key"), ("attStmt", (("alg", -7), ("sig", sig), ("x5c", [cert]))), ("authData", auth)))


k = ec.derive_private_key(0x3333333333333333333333333333333333333333333333333333333333333333, ec.SECP256R1())
k2 = ec.derive_private_key(0x4444444444444444444444444444444444444444444444444444444444444444, ec.SECP256R1())
ch = client_data_hash
variants = {
    "attestation_object": make(k, k, ch, auth_list(None, None), auth_list()),
    "software_only_attestation_object": make(k, k, ch, auth_list(), auth_list(None, None)),
    "bad_challenge_attestation_object": make(k, k, b"x" * 32, auth_list(None, None), auth_list()),
    "all_applications_attestation_object": make(k, k, ch, auth_list(None, None), auth_list(all_applications=True)),
    "bad_origin_attestation_object": make(k, k, ch, auth_list(None, None), auth_list(origin=2)),
    "no_origin_attestation_object": make(k, k, ch, auth_list(None, None), auth_list(origin=None)),
    "extra_purpose_attestation_object": make(k, k, ch, auth_list(None, None), auth_list(purpose=(2, 3))),
    "verify_purpose_attestation_object": make(k, k, ch, auth_list(None, None), auth_list(purpose=(3,))),
    "other_key_attestation_object": make(k2, k, ch, auth_list(None, None), auth_list()),
}
print("// SPDX-License-Identifier: MIT")
print("//! GENERATED by tools/gen_android_key_fixture.py -- synthetic, NOT an Android attestation.\n")
print(f'pub const client_data_hash = hexLit("{client_data_hash.hex()}");')
for n, v in variants.items():
    print(f'pub const {n} = hexLit("{v.hex()}");')
print('''
fn hexLit(comptime hex: []const u8) [hex.len / 2]u8 {
    comptime {
        @setEvalBranchQuota(200_000);
        var out: [hex.len / 2]u8 = undefined;
        _ = @import("std").fmt.hexToBytes(&out, hex) catch unreachable;
        return out;
    }
}''')
