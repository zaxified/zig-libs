#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate the CRL fixtures in src/data/crl/ for crl_test.zig.

    python3 modules/x509/tools/gen_crl_fixtures.py modules/x509/src/data/crl

Needs Python `cryptography` (>= 41; used as a black-box builder) and
OpenSSL >= 3.5 on PATH (ML-DSA keys and CRLs, and the verdict oracle). Every
run makes fresh keys, so the committed files change wholesale when it is
rerun; the tests depend only on the structure described here.

Oracle: before writing anything, `openssl verify -crl_check` must agree with
the verdict the Zig tests expect for every good/revoked/out-of-scope case
(ORACLE below). A disagreement aborts the run.

Time: all fixtures are valid at NOW = 2026-01-01T01:00:00Z (T0 + 1 h). CRLs
are issued at T0 with nextUpdate T0 + 7 days.
"""
import datetime as dt
import os
import subprocess
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID

UTC = dt.timezone.utc
T0 = dt.datetime(2026, 1, 1, tzinfo=UTC)
NOW = T0 + dt.timedelta(hours=1)
NOT_BEFORE = dt.datetime(2025, 1, 1, tzinfo=UTC)
NOT_AFTER = dt.datetime(2030, 1, 1, tzinfo=UTC)

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "zig-libs crl test"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def ca_cert(cn, key, crl_sign=True, sign_hash=hashes.SHA256()):
    pub = key.public_key()
    b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(cn))
         .public_key(pub).serial_number(1).not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER)
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False,
                                      key_agreement=False, key_cert_sign=True, crl_sign=crl_sign,
                                      encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False))
    return b.sign(key, None if isinstance(key, ed25519.Ed25519PrivateKey) else sign_hash)


def leaf_cert(cn, serial, ca, ca_key, dp=None, is_ca=False, sign_hash=hashes.SHA256()):
    key = ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(ca.subject)
         .public_key(key.public_key()).serial_number(serial)
         .not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER)
         .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False))
    if dp:
        b = b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier(dp)], relative_name=None, reasons=None, crl_issuer=None)]),
            critical=False)
    return b.sign(ca_key, None if isinstance(ca_key, ed25519.Ed25519PrivateKey) else sign_hash)


def revoked(serial, reason=None, invalidity=None):
    b = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(T0 - dt.timedelta(days=1))
    if reason is not None:
        b = b.add_extension(x509.CRLReason(reason), critical=False)
    if invalidity is not None:
        b = b.add_extension(x509.InvalidityDate(invalidity.replace(tzinfo=None)), critical=False)
    return b.build()


def crl(ca, ca_key, entries, exts=(), number=1, sign_hash=hashes.SHA256(), rsa_padding=None, aki_key=None):
    b = (x509.CertificateRevocationListBuilder().issuer_name(ca.subject)
         .last_update(T0).next_update(T0 + dt.timedelta(days=7))
         .add_extension(x509.CRLNumber(number), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key((aki_key or ca_key).public_key()),
                        critical=False))
    for e in entries:
        b = b.add_revoked_certificate(e)
    for ext, critical in exts:
        b = b.add_extension(ext, critical=critical)
    alg = None if isinstance(ca_key, ed25519.Ed25519PrivateKey) else sign_hash
    if rsa_padding is not None:
        return b.sign(ca_key, alg, rsa_padding=rsa_padding)
    return b.sign(ca_key, alg)


def write(fname, obj):
    data = obj if isinstance(obj, bytes) else obj.public_bytes(serialization.Encoding.DER)
    with open(os.path.join(OUT, fname), "wb") as f:
        f.write(data)
    return data


# ── DER helpers for the one hand-assembled CRL (no nextUpdate) ──────────────

def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def der_read(buf, i):
    """(tag, header_len, content_len) of the TLV at buf[i]."""
    tag = buf[i]
    l = buf[i + 1]
    if l < 0x80:
        return tag, 2, l
    k = l & 0x7F
    return tag, 2 + k, int.from_bytes(buf[i + 2:i + 2 + k], "big")


def tlv(tag, body):
    return bytes([tag]) + der_len(len(body)) + body


def resign(crl_der, key, edit):
    """Re-sign `crl_der` (RSA PKCS#1 v1.5, SHA-256) after `edit(fields)` rewrote
    the list of tbsCertList field TLVs; the outer signatureAlgorithm is kept."""
    _, h, _ = der_read(crl_der, 0)
    tbs_at = h
    _, th, tl = der_read(crl_der, tbs_at)
    tbs_body = crl_der[tbs_at + th:tbs_at + th + tl]
    fields = []
    i = 0
    while i < len(tbs_body):
        t, fh, fl = der_read(tbs_body, i)
        fields.append(tbs_body[i:i + fh + fl])
        i += fh + fl
    new_tbs = tlv(0x30, b"".join(edit(fields)))
    rest = crl_der[tbs_at + th + tl:]
    _, ah, al = der_read(rest, 0)
    alg = rest[:ah + al]
    sig = key.sign(new_tbs, padding.PKCS1v15(), hashes.SHA256())
    return tlv(0x30, new_tbs + alg + tlv(0x03, b"\x00" + sig))


def drop_next_update(crl_der, key):
    """Re-sign `crl_der`'s tbsCertList without nextUpdate (RSA PKCS#1 v1.5, SHA-256)."""
    _, h, _ = der_read(crl_der, 0)
    tbs_at = h
    _, th, tl = der_read(crl_der, tbs_at)
    tbs_body = crl_der[tbs_at + th:tbs_at + th + tl]
    fields = []
    i = 0
    while i < len(tbs_body):
        t, fh, fl = der_read(tbs_body, i)
        fields.append(tbs_body[i:i + fh + fl])
        i += fh + fl
    # version, signature, issuer, thisUpdate, nextUpdate, revoked, [0]exts
    assert fields[4][0] in (0x17, 0x18), "field 4 must be nextUpdate"
    new_tbs = tlv(0x30, b"".join(fields[:4] + fields[5:]))
    rest = crl_der[tbs_at + th + tl:]
    _, ah, al = der_read(rest, 0)
    alg = rest[:ah + al]
    sig = key.sign(new_tbs, padding.PKCS1v15(), hashes.SHA256())
    return tlv(0x30, new_tbs + alg + tlv(0x03, b"\x00" + sig))


# ── the fixtures ─────────────────────────────────────────────────────────────

pem = serialization.Encoding.PEM
ORACLE = []  # (ca, crl, leaf, expected) — "ok" | "revoked" | "scope"

# RSA CA: the main CRL.
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_ca = ca_cert("RSA CA", rsa_key)
write("rsa_ca.der", rsa_ca)
write("rsa_leaf_revoked.der", leaf_cert("revoked", 0x1001, rsa_ca, rsa_key))
write("rsa_leaf_good.der", leaf_cert("good", 0x1002, rsa_ca, rsa_key))
write("rsa_leaf_hold.der", leaf_cert("hold", 0x1003, rsa_ca, rsa_key))
main_entries = [
    revoked(0x0999),
    revoked(0x1001, x509.ReasonFlags.key_compromise, T0 - dt.timedelta(days=2)),
    revoked(0x1003, x509.ReasonFlags.certificate_hold),
]
rsa_crl = crl(rsa_ca, rsa_key, main_entries)
write("rsa.crl", rsa_crl)
write("rsa_pss.crl", crl(rsa_ca, rsa_key, main_entries,
                         rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)))
write("rsa_no_next.crl", drop_next_update(rsa_crl.public_bytes(serialization.Encoding.DER), rsa_key))
write("rsa_empty.crl", crl(rsa_ca, rsa_key, []))
rsa_crl_der = rsa_crl.public_bytes(serialization.Encoding.DER)
# version INTEGER 2 (v3): no such CRL version.
write("rsa_bad_version.crl", resign(rsa_crl_der, rsa_key, lambda f: [tlv(0x02, b"\x02")] + f[1:]))
# Inner signature AlgorithmIdentifier without its NULL parameters: the same
# algorithm, different bytes from the outer one (RFC 5280 §5.1.1.2 wants them equal),
# and the signature is valid.
sha256_rsa_no_params = tlv(0x30, tlv(0x06, bytes.fromhex("2a864886f70d01010b")))
write("rsa_alg_mismatch.crl", resign(rsa_crl_der, rsa_key, lambda f: [f[0], sha256_rsa_no_params] + f[2:]))
ORACLE += [("rsa_ca", "rsa.crl", "rsa_leaf_revoked", "revoked"), ("rsa_ca", "rsa.crl", "rsa_leaf_good", "ok"),
           ("rsa_ca", "rsa_pss.crl", "rsa_leaf_revoked", "revoked"), ("rsa_ca", "rsa_pss.crl", "rsa_leaf_good", "ok")]

# Refusals on the RSA CA.
write("rsa_delta.crl", crl(rsa_ca, rsa_key, main_entries, exts=[(x509.DeltaCRLIndicator(1), True)], number=2))
unknown = x509.ObjectIdentifier("1.3.6.1.4.1.55555.1")
write("rsa_critical_ext.crl", crl(rsa_ca, rsa_key, [], exts=[(x509.UnrecognizedExtension(unknown, b"\x05\x00"), True)]))
write("rsa_noncritical_ext.crl", crl(rsa_ca, rsa_key, main_entries,
                                     exts=[(x509.UnrecognizedExtension(unknown, b"\x05\x00"), False)]))
entry_crit = (x509.RevokedCertificateBuilder().serial_number(0x1001).revocation_date(T0 - dt.timedelta(days=1))
              .add_extension(x509.UnrecognizedExtension(unknown, b"\x05\x00"), critical=True).build())
write("rsa_entry_critical.crl", crl(rsa_ca, rsa_key, [entry_crit]))
# certificateIssuer (indirect CRLs only), even when a CA forgot to mark it critical.
entry_ci = (x509.RevokedCertificateBuilder().serial_number(0x1001).revocation_date(T0 - dt.timedelta(days=1))
            .add_extension(x509.CertificateIssuer([x509.DirectoryName(name("Other CA"))]), critical=False).build())
write("rsa_entry_cert_issuer.crl", crl(rsa_ca, rsa_key, [entry_ci]))

# Partitioned CRLs (issuing distribution point).
dp1, dp2 = "http://crl.example/1.crl", "http://crl.example/2.crl"
write("rsa_leaf_dp1.der", leaf_cert("dp1", 0x3001, rsa_ca, rsa_key, dp=dp1))
write("rsa_leaf_dp2.der", leaf_cert("dp2", 0x3002, rsa_ca, rsa_key, dp=dp2))
write("rsa_sub_ca_dp1.der", leaf_cert("sub CA", 0x3003, rsa_ca, rsa_key, dp=dp1, is_ca=True))


def idp(full_name=None, only_user=False, only_ca=False, some_reasons=None, indirect=False):
    return x509.IssuingDistributionPoint(
        full_name=[x509.UniformResourceIdentifier(full_name)] if full_name else None, relative_name=None,
        only_contains_user_certs=only_user, only_contains_ca_certs=only_ca, only_some_reasons=some_reasons,
        indirect_crl=indirect, only_contains_attribute_certs=False)


write("rsa_idp1.crl", crl(rsa_ca, rsa_key, [revoked(0x3001, x509.ReasonFlags.superseded)],
                          exts=[(idp(dp1, only_user=True), True)]))
write("rsa_idp_ca_only.crl", crl(rsa_ca, rsa_key, [], exts=[(idp(only_ca=True), True)]))
write("rsa_idp_some_reasons.crl", crl(rsa_ca, rsa_key, [],
                                      exts=[(idp(some_reasons=frozenset([x509.ReasonFlags.key_compromise])), True)]))
write("rsa_idp_indirect.crl", crl(rsa_ca, rsa_key, [], exts=[(idp(indirect=True), True)]))
ORACLE += [("rsa_ca", "rsa_idp1.crl", "rsa_leaf_dp1", "revoked"), ("rsa_ca", "rsa_idp1.crl", "rsa_leaf_dp2", "scope")]

# The same CA name with another key: a CRL it signed must not pass for RSA CA.
other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
write("rsa_impostor.crl", crl(rsa_ca, other_key, []))  # AKI names the impostor key
write("rsa_impostor_rsa_aki.crl", crl(rsa_ca, other_key, [], aki_key=rsa_key))  # AKI lies, signature cannot

# A CA whose keyUsage lacks cRLSign.
nosign_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
nosign_ca = ca_cert("No-CRL-sign CA", nosign_key, crl_sign=False)
write("nosign_ca.der", nosign_ca)
write("nosign_leaf.der", leaf_cert("nosign leaf", 0x4001, nosign_ca, nosign_key))
write("nosign.crl", crl(nosign_ca, nosign_key, []))

# ECDSA P-256 / P-384 and Ed25519 CAs.
for tag, key, h in (("ec256", ec.generate_private_key(ec.SECP256R1()), hashes.SHA256()),
                    ("ec384", ec.generate_private_key(ec.SECP384R1()), hashes.SHA384()),
                    ("ed25519", ed25519.Ed25519PrivateKey.generate(), None)):
    ca = ca_cert(tag + " CA", key, sign_hash=h or hashes.SHA256())
    write(f"{tag}_ca.der", ca)
    write(f"{tag}_leaf_revoked.der", leaf_cert("revoked", 0x2001, ca, key, sign_hash=h or hashes.SHA256()))
    write(f"{tag}_leaf_good.der", leaf_cert("good", 0x2002, ca, key, sign_hash=h or hashes.SHA256()))
    write(f"{tag}.crl", crl(ca, key, [revoked(0x2001, x509.ReasonFlags.cessation_of_operation)],
                            sign_hash=h or hashes.SHA256()))
    ORACLE += [(f"{tag}_ca", f"{tag}.crl", f"{tag}_leaf_revoked", "revoked"),
               (f"{tag}_ca", f"{tag}.crl", f"{tag}_leaf_good", "ok")]


def sh(args, cwd):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


# ML-DSA-44 CA, certificates and CRL through openssl (cryptography has no ML-DSA signing here).
with tempfile.TemporaryDirectory() as d:
    def ok(r):
        assert r.returncode == 0, r.stderr
    ok(sh(["openssl", "genpkey", "-algorithm", "ML-DSA-44", "-out", "ca.key"], d))
    with open(os.path.join(d, "ca.cnf"), "w") as f:
        f.write("""[ca]
default_ca = d
[d]
dir = .
database = index.txt
new_certs_dir = .
serial = serial
crlnumber = crlnumber
default_md = default
policy = p
default_crl_days = 7
[p]
commonName = supplied
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[v3_leaf]
basicConstraints = critical, CA:FALSE
authorityKeyIdentifier = keyid
""")
    open(os.path.join(d, "index.txt"), "w").close()
    with open(os.path.join(d, "serial"), "w") as f:
        f.write("5001\n")
    with open(os.path.join(d, "crlnumber"), "w") as f:
        f.write("01\n")
    ok(sh(["openssl", "req", "-new", "-x509", "-key", "ca.key", "-subj", "/CN=ML-DSA CA", "-days", "3650",
           "-config", "ca.cnf", "-extensions", "v3_ca", "-out", "ca.pem", "-not_before", "20250101000000Z",
           "-not_after", "20300101000000Z"], d))
    for leaf in ("revoked", "good"):
        ok(sh(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", f"{leaf}.key"], d))
        ok(sh(["openssl", "req", "-new", "-key", f"{leaf}.key", "-subj", f"/CN={leaf}", "-out", f"{leaf}.csr"], d))
        ok(sh(["openssl", "ca", "-batch", "-config", "ca.cnf", "-extensions", "v3_leaf", "-cert", "ca.pem",
               "-keyfile", "ca.key", "-in", f"{leaf}.csr", "-out", f"{leaf}.pem", "-notext",
               "-startdate", "20250101000000Z", "-enddate", "20300101000000Z"], d))
    ok(sh(["openssl", "ca", "-config", "ca.cnf", "-cert", "ca.pem", "-keyfile", "ca.key", "-revoke", "revoked.pem",
           "-crl_reason", "keyCompromise"], d))
    ok(sh(["openssl", "ca", "-gencrl", "-config", "ca.cnf", "-cert", "ca.pem", "-keyfile", "ca.key",
           "-out", "crl.pem"], d))
    for src, dst, kind in (("ca.pem", "mldsa_ca.der", "x509"), ("revoked.pem", "mldsa_leaf_revoked.der", "x509"),
                           ("good.pem", "mldsa_leaf_good.der", "x509"), ("crl.pem", "mldsa.crl", "crl")):
        ok(sh(["openssl", kind, "-in", src, "-outform", "DER", "-out", os.path.join(os.path.abspath(OUT), dst)], d))
    # The openssl CRL's own times are "now"; the Zig test reads them from the file,
    # and the oracle checks it at the current time (no -attime).
ORACLE += [("mldsa_ca", "mldsa.crl", "mldsa_leaf_revoked", "revoked"), ("mldsa_ca", "mldsa.crl", "mldsa_leaf_good", "ok")]

ORACLE_NOW = int(NOW.timestamp())

# ── the oracle: openssl must agree with every expected verdict ──────────────
with tempfile.TemporaryDirectory() as d:
    def to_pem(fname, kind):
        out = os.path.join(d, fname + ".pem")
        r = subprocess.run(["openssl", kind, "-inform", "DER", "-in", os.path.join(OUT, fname), "-out", out],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        return out

    for ca, crl_name, leaf, want in ORACLE:
        at = [] if crl_name.startswith("mldsa") else ["-attime", str(ORACLE_NOW)]
        r = subprocess.run(["openssl", "verify", "-crl_check", *at,
                            "-CAfile", to_pem(ca + ".der", "x509"), "-CRLfile", to_pem(crl_name, "crl"),
                            to_pem(leaf + ".der", "x509")], capture_output=True, text=True)
        text = r.stdout + r.stderr
        got = ("ok" if r.returncode == 0 else
               "revoked" if "certificate revoked" in text else
               "scope" if ("unable to get certificate CRL" in text or "different CRL scope" in text) else "other: " + text.strip())
        assert got == want, f"openssl disagrees on {crl_name}/{leaf}: want {want}, got {got}"
        print(f"oracle: {crl_name} {leaf}: {got}")
print("fixtures written to", OUT)
