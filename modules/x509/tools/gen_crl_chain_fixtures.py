#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate the three-level CRL fixtures `chain_*` in src/data/crl/ for chain_crl_test.zig.

    python3 modules/x509/tools/gen_crl_chain_fixtures.py modules/x509/src/data/crl

Sibling of gen_crl_fixtures.py (same NOW / T0 time base, same helpers in spirit),
kept apart so that rerunning it does not regenerate the two-level fixtures. It
only ever writes `chain_*` files. Needs Python `cryptography` (>= 41) and
OpenSSL on PATH (the verdict oracle).

Layout: root R -> intermediate I1 -> leaf, plus I2, a re-issue of I1 (same
subject, same key, so the same SKI the leaf's AKI names, another serial). That
is what makes the backtracking tests possible: both are candidate issuers of the
leaf, and only the serial tells them apart on the root's CRL.

Oracle: `openssl verify -crl_check_all` (every certificate of the chain) or
`-crl_check` (leaf only) must agree with the verdict the Zig tests expect for
each case in ORACLE, else the run aborts. OpenSSL does not backtrack on
revocation, so the backtracking cases are asked one intermediate at a time
(the non-revoked one passes, the revoked one is revoked); the Zig test then
presents both.
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

UTC = dt.timezone.utc
T0 = dt.datetime(2026, 1, 1, tzinfo=UTC)
NOW = T0 + dt.timedelta(hours=1)
NOT_BEFORE = dt.datetime(2025, 1, 1, tzinfo=UTC)
NOT_AFTER = dt.datetime(2030, 1, 1, tzinfo=UTC)

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)
DER = serialization.Encoding.DER


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "zig-libs crl chain test"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def ca_cert(cn, serial, key, issuer_cert=None, issuer_key=None):
    """A CA certificate; self-signed when no issuer is given."""
    pub = key.public_key()
    b = (x509.CertificateBuilder().subject_name(name(cn))
         .issuer_name(issuer_cert.subject if issuer_cert else name(cn))
         .public_key(pub).serial_number(serial).not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER)
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False,
                                      key_agreement=False, key_cert_sign=True, crl_sign=True,
                                      encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False))
    if issuer_cert:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                            critical=False)
    return b.sign(issuer_key or key, hashes.SHA256())


def leaf_cert(cn, serial, issuer_cert, issuer_key):
    key = ec.generate_private_key(ec.SECP256R1())
    return (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(issuer_cert.subject)
            .public_key(key.public_key()).serial_number(serial)
            .not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                           critical=False)
            .sign(issuer_key, hashes.SHA256()))


def crl(ca, ca_key, serials, number=1):
    b = (x509.CertificateRevocationListBuilder().issuer_name(ca.subject)
         .last_update(T0).next_update(T0 + dt.timedelta(days=7))
         .add_extension(x509.CRLNumber(number), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False))
    for s in serials:
        b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(s)
                                      .revocation_date(T0 - dt.timedelta(days=1)).build())
    return b.sign(ca_key, hashes.SHA256())


FILES = {}


def write(fname, obj):
    data = obj.public_bytes(DER)
    with open(os.path.join(OUT, fname), "wb") as f:
        f.write(data)
    FILES[fname] = data


root_key = ec.generate_private_key(ec.SECP256R1())
int_key = ec.generate_private_key(ec.SECP256R1())
root = ca_cert("Chain Root", 1, root_key)
int1 = ca_cert("Chain Intermediate", 0x10, int_key, root, root_key)
int2 = ca_cert("Chain Intermediate", 0x11, int_key, root, root_key)  # re-issue: same subject and key
leaf = leaf_cert("chain leaf", 0x100, int1, int_key)
leaf_rev = leaf_cert("chain leaf revoked", 0x101, int1, int_key)

write("chain_root.der", root)
write("chain_int.der", int1)
write("chain_int2.der", int2)
write("chain_leaf.der", leaf)
write("chain_leaf_revoked.der", leaf_rev)
# The root's CRLs: nothing revoked / I1 revoked / I1 and I2 revoked.
write("chain_root_empty.crl", crl(root, root_key, []))
write("chain_root_revokes_int.crl", crl(root, root_key, [0x10]))
write("chain_root_revokes_both.crl", crl(root, root_key, [0x10, 0x11]))
# The intermediate's CRL (signed by the key both I1 and I2 carry): only the revoked leaf.
write("chain_int.crl", crl(int1, int_key, [0x101]))

# (mode, untrusted intermediates, CRLs, leaf, expected). mode: "all" = -crl_check_all, "leaf" = -crl_check.
# expected: "ok" | "revoked" | "unknown" (no CRL for some certificate).
ORACLE = [
    ("all", ["chain_int"], ["chain_root_empty.crl", "chain_int.crl"], "chain_leaf", "ok"),
    ("all", ["chain_int"], ["chain_root_empty.crl", "chain_int.crl"], "chain_leaf_revoked", "revoked"),
    ("all", ["chain_int"], ["chain_root_revokes_int.crl", "chain_int.crl"], "chain_leaf", "revoked"),
    ("leaf", ["chain_int"], ["chain_int.crl"], "chain_leaf", "ok"),
    ("leaf", ["chain_int"], ["chain_root_revokes_int.crl", "chain_int.crl"], "chain_leaf", "ok"),
    ("leaf", ["chain_int"], ["chain_int.crl"], "chain_leaf_revoked", "revoked"),
    ("all", ["chain_int"], ["chain_int.crl"], "chain_leaf", "unknown"),
    # Backtracking: I1 revoked, I2 not.
    ("all", ["chain_int2"], ["chain_root_revokes_int.crl", "chain_int.crl"], "chain_leaf", "ok"),
    ("all", ["chain_int"], ["chain_root_revokes_int.crl", "chain_int.crl"], "chain_leaf", "revoked"),
    ("all", ["chain_int2"], ["chain_root_revokes_both.crl", "chain_int.crl"], "chain_leaf", "revoked"),
]

with tempfile.TemporaryDirectory() as d:
    pems = {}

    def pem(fname, kind):
        if fname not in pems:
            out = os.path.join(d, fname + ".pem")
            r = subprocess.run(["openssl", kind, "-inform", "DER", "-in", os.path.join(OUT, fname), "-out", out],
                               capture_output=True, text=True)
            assert r.returncode == 0, r.stderr
            pems[fname] = out
        return pems[fname]

    for n, (mode, ints, crls, leaf_name, want) in enumerate(ORACLE):
        crlfile = os.path.join(d, f"crls{n}.pem")
        with open(crlfile, "w") as f:
            for c in crls:
                f.write(open(pem(c, "crl")).read())
        args = ["openssl", "verify", "-crl_check_all" if mode == "all" else "-crl_check",
                "-attime", str(int(NOW.timestamp())), "-CAfile", pem("chain_root.der", "x509"), "-CRLfile", crlfile]
        for i in ints:
            args += ["-untrusted", pem(i + ".der", "x509")]
        r = subprocess.run(args + [pem(leaf_name + ".der", "x509")], capture_output=True, text=True)
        text = r.stdout + r.stderr
        got = ("ok" if r.returncode == 0 else
               "revoked" if "certificate revoked" in text else
               "unknown" if "unable to get certificate CRL" in text else "other: " + text.strip())
        assert got == want, f"openssl disagrees on case {n} {mode} {ints} {crls} {leaf_name}: want {want}, got {got}"
        print(f"oracle: {mode:4} {'+'.join(ints):18} {' '.join(crls):50} {leaf_name}: {got}")
print("fixtures written to", OUT, "->", ", ".join(sorted(FILES)))
