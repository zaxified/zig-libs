#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate the P-521 fixtures in src/data/p521/ for p521_test.zig.

    python3 -I modules/x509/tools/gen_p521_fixtures.py modules/x509/src/data/p521

Needs Python `cryptography` (>= 41) and OpenSSL on PATH (the verdict oracle:
every chain and CRL verdict the Zig tests expect is first asked of
`openssl verify`, and the run aborts on any disagreement). Generated
2026-10-10 with cryptography 50.0.0 and OpenSSL 3.5.5.

Hierarchies (validity 2025-01-01 .. 2030-01-01, tests run at 2026-01-01):
  A. root521 (P-521, self-signed ecdsa-with-SHA512)
       -> inter521 (P-521, signed with SHA-384)
         -> leaf521 (P-521, signed with SHA-256, SAN p521.example)
         -> leaf256 (P-256 leaf under the P-521 CA, signed with SHA-512)
  B. root384 (P-384, SHA-384) -> interB521 (P-521, signed with SHA-384: std's
     path) -> leafB521 (P-521, signed with SHA-512: this module's path)
  C. crl_inter521: inter521's CRL (ecdsa-with-SHA512) revoking leaf256's
     serial, so checkRevocation(crl, leaf256, inter521) is `revoked` and
     (crl, leaf521, inter521) is `good`.
Tamper cases (flipped signature byte, expired) are derived in the Zig test
from these bytes.
"""
import datetime as dt
import os
import subprocess
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

OUT = sys.argv[1]
UTC = dt.timezone.utc
NOT_BEFORE = dt.datetime(2025, 1, 1, tzinfo=UTC)
NOT_AFTER = dt.datetime(2030, 1, 1, tzinfo=UTC)
NOW = dt.datetime(2026, 1, 1, tzinfo=UTC)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "zig-libs p521 test"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def ku(ca):
    return x509.KeyUsage(digital_signature=not ca, content_commitment=False, key_encipherment=False,
                         data_encipherment=False, key_agreement=False, key_cert_sign=ca, crl_sign=ca,
                         encipher_only=False, decipher_only=False)


def cert(cn, key, issuer_cn, issuer_key, serial, h, ca, san=None):
    b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(issuer_cn))
         .public_key(key.public_key()).serial_number(serial)
         .not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(ku(ca), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
    return b.sign(issuer_key, h)


def der(obj):
    return obj.public_bytes(serialization.Encoding.DER)


def pem(obj):
    return obj.public_bytes(serialization.Encoding.PEM)


def openssl_verify(tmp, root, inters, leaf, crl=None):
    def w(n, data):
        p = os.path.join(tmp, n)
        open(p, "wb").write(data)
        return p
    args = ["openssl", "verify", "-attime", str(int(NOW.timestamp())), "-CAfile", w("root.pem", pem(root))]
    if inters:
        args += ["-untrusted", w("inter.pem", b"".join(pem(c) for c in inters))]
    if crl is not None:
        args += ["-crl_check", "-CRLfile", w("crl.pem", crl.public_bytes(serialization.Encoding.PEM))]
    args.append(w("leaf.pem", pem(leaf)))
    r = subprocess.run(args, capture_output=True, text=True)
    return r.returncode == 0


root521_k = ec.generate_private_key(ec.SECP521R1())
inter521_k = ec.generate_private_key(ec.SECP521R1())
leaf521_k = ec.generate_private_key(ec.SECP521R1())
leaf256_k = ec.generate_private_key(ec.SECP256R1())
root384_k = ec.generate_private_key(ec.SECP384R1())
interB_k = ec.generate_private_key(ec.SECP521R1())
leafB_k = ec.generate_private_key(ec.SECP521R1())

root521 = cert("p521 root", root521_k, "p521 root", root521_k, 1, hashes.SHA512(), True)
inter521 = cert("p521 inter", inter521_k, "p521 root", root521_k, 2, hashes.SHA384(), True)
leaf521 = cert("p521 leaf", leaf521_k, "p521 inter", inter521_k, 3, hashes.SHA256(), False, "p521.example")
leaf256 = cert("p256 leaf", leaf256_k, "p521 inter", inter521_k, 4, hashes.SHA512(), False, "p256.example")
root384 = cert("p384 root", root384_k, "p384 root", root384_k, 5, hashes.SHA384(), True)
interB = cert("p521 inter B", interB_k, "p384 root", root384_k, 6, hashes.SHA384(), True)
leafB = cert("p521 leaf B", leafB_k, "p521 inter B", interB_k, 7, hashes.SHA512(), False, "b.p521.example")

crl = (x509.CertificateRevocationListBuilder().issuer_name(inter521.subject)
       .last_update(NOW - dt.timedelta(days=1)).next_update(NOW + dt.timedelta(days=7))
       .add_extension(x509.CRLNumber(1), critical=False)
       .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(inter521_k.public_key()), critical=False)
       .add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(4)
                                .revocation_date(NOW - dt.timedelta(days=2)).build())
       .sign(inter521_k, hashes.SHA512()))

with tempfile.TemporaryDirectory() as tmp:
    assert openssl_verify(tmp, root521, [inter521], leaf521)
    assert openssl_verify(tmp, root521, [inter521], leaf256)
    assert openssl_verify(tmp, root384, [interB], leafB)
    assert not openssl_verify(tmp, root384, [inter521], leaf521)  # wrong anchor
    assert openssl_verify(tmp, root521, [inter521], leaf521, crl)
    assert not openssl_verify(tmp, root521, [inter521], leaf256, crl)  # revoked

os.makedirs(OUT, exist_ok=True)
for fname, obj in (("root521.der", root521), ("inter521.der", inter521), ("leaf521.der", leaf521),
                   ("leaf256.der", leaf256), ("root384.der", root384), ("interB521.der", interB),
                   ("leafB521.der", leafB)):
    open(os.path.join(OUT, fname), "wb").write(der(obj))
open(os.path.join(OUT, "crl_inter521.der"), "wb").write(crl.public_bytes(serialization.Encoding.DER))
print("ok: 7 certificates + 1 CRL, openssl verdicts agree")
