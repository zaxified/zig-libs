#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Behaviour probes for modules/x509: Go crypto/x509 vs OpenSSL on hand-built certificates.

    python3 modules/x509/tools/gen_names_fixtures.py [OUTDIR]     (default: modules/x509/.zig-cache/probes)

Builds every certificate as raw DER (own tiny encoder, so nothing is validated away: trailing-dot
dNSNames, duplicate extensions, negative serials, v1 certificates with extensions ... all possible),
signs with Python `cryptography` keys, writes cases.jsonl (input of tools/go_oracle), runs the Go
oracle and the OpenSSL CLI on each case, and writes verdicts.tsv:

    id  probe  description  go_ok  go_reason/msg  openssl_ok  openssl_msg

Fixed times, no wall clock: notBefore 2025-01-01, notAfter 2035-01-01, verify time 2026-06-01.
Needs `cryptography` (>= 41), `openssl` on PATH and `go` (builds the oracle if the binary is missing).
A disposable probe, not a test: the durable output is the findings (see CONVENTIONS.md section 9).
"""
# ---------------------------------------------------------------- corpus.bin FORMAT (committed differential corpus)
# Written to src/data/s2/corpus.bin; replayed by a Zig test through x509.verifyChain / hostname matching
# and compared with Go's verdict (go_ok).  O-parse cases are NOT included.
# little-endian. Header: 8 bytes magic `X509S2\x00\x02`, u32 record count. Each record:
#   u8  id_len, id bytes (ASCII, the case id)
#   u8  mode: 0 = verify, 1 = hostname
#   i64 time (unix seconds; hostname mode: the verify time, unused)
#   u8  host_len, host bytes (verify: dns_name or empty when null; hostname: the host)
#   u8  usages bitmask: bit0 serverAuth, bit1 clientAuth, bit2 any; 0 = null (Go default)
#   u8  n_policies, then n_policies x (u8 len, OID content bytes: DER OID value, no tag/length)
#       = the caller's acceptable policy set (Go VerifyOptions.CertificatePolicies); 0 = none (Go default)
#   u8  go_ok (1 = Go accepted)
#   u8  n_roots, u8 n_inters
#   then n_roots x (u16 len, DER), n_inters x (u16 len, DER), then leaf (u16 len, DER)
# Hostname mode: n_roots = n_inters = 0, leaf only.
# Deterministic apart from ECDSA/RSA signature randomness (EC keys derived from fixed integers, fixed serials
# and times); only the O-sha1 cases use fresh RSA keys.
import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
import struct
import subprocess
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

HERE = os.path.dirname(os.path.abspath(__file__))
MOD = os.path.dirname(HERE)
OUT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(MOD, ".zig-cache", "probes")
UTC = dt.timezone.utc
NB = dt.datetime(2025, 1, 1, tzinfo=UTC)
NA = dt.datetime(2035, 1, 1, tzinfo=UTC)
T_VERIFY = int(dt.datetime(2026, 6, 1, tzinfo=UTC).timestamp())

# ---------------------------------------------------------------- DER encoder


def L(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, c=b""):
    return bytes([tag]) + L(len(c)) + c


def seq(*p):
    return tlv(0x30, b"".join(p))


def sset(*p):
    return tlv(0x31, b"".join(p))


def oid(s):
    a = [int(x) for x in s.split(".")]
    out = bytes([a[0] * 40 + a[1]])
    for v in a[2:]:
        t = [v & 0x7F]
        v >>= 7
        while v:
            t.append(0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(reversed(t))
    return tlv(0x06, out)


def integer(n):
    """Minimal two's complement INTEGER."""
    if n == 0:
        return tlv(0x02, b"\x00")
    ln = (n.bit_length() + 8) // 8 if n > 0 else ((-n - 1).bit_length() + 8) // 8
    return tlv(0x02, n.to_bytes(ln, "big", signed=True))


def boolean(v):
    return tlv(0x01, b"\xff" if v else b"\x00")


def null():
    return tlv(0x05)


def octets(b):
    return tlv(0x04, b)


def bitstr(b, unused=0):
    return tlv(0x03, bytes([unused]) + b)


def utf8(s):
    return tlv(0x0C, s.encode())


def ia5(s):
    return tlv(0x16, s.encode())


def prtstr(s):
    return tlv(0x13, s.encode())


def utctime(d):
    return tlv(0x17, d.strftime("%y%m%d%H%M%SZ").encode())


def ctx(n, c):  # constructed [n]
    return tlv(0xA0 | n, c)


def ctxp(n, b):  # primitive [n] (IMPLICIT)
    return tlv(0x80 | n, b)


# ---------------------------------------------------------------- OIDs, GeneralNames, extensions
O_BC, O_KU, O_EKU, O_SAN, O_IAN = "2.5.29.19", "2.5.29.15", "2.5.29.37", "2.5.29.17", "2.5.29.18"
O_NC, O_CP, O_PM, O_PC, O_IAP = "2.5.29.30", "2.5.29.32", "2.5.29.33", "2.5.29.36", "2.5.29.54"
O_SKI, O_AKI, O_CRLDP, O_FCRL = "2.5.29.14", "2.5.29.35", "2.5.29.31", "2.5.29.46"
O_AIA, O_SDA, O_POISON, O_UNK = "1.3.6.1.5.5.7.1.1", "2.5.29.9", "1.3.6.1.4.1.11129.2.4.3", "1.3.6.1.4.1.99999.1"
EKU_OID = {"server": "1.3.6.1.5.5.7.3.1", "client": "1.3.6.1.5.5.7.3.2", "any": "2.5.29.37.0"}
OID_EMAIL = "1.2.840.113549.1.9.1"

DNS, EMAIL, URI, IPA, DIRN = 2, 1, 6, 7, 4


def gn(kind, v):
    if kind == IPA:
        return ctxp(7, ipaddress.ip_address(v).packed)
    if kind == DIRN:
        return ctx(4, v)
    return ctxp(kind, v.encode())


# an extension is (oid, critical, value_der)
def ext(o, crit, val):
    return (o, crit, val)


def x_bc(ca, pathlen=None, crit=True):
    c = (boolean(True) if ca else b"") + (integer(pathlen) if pathlen is not None else b"")
    return ext(O_BC, crit, seq(c))


def x_ku(*bits, crit=True):
    """bits: names from the RFC 5280 order."""
    names = ["digitalSignature", "contentCommitment", "keyEncipherment", "dataEncipherment", "keyAgreement",
             "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"]
    top = 0
    for b in bits:
        top = max(top, names.index(b))
    raw = bytearray(2 if top >= 8 else 1)
    for b in bits:
        i = names.index(b)
        raw[i // 8] |= 0x80 >> (i % 8)
    unused = 7 - (top % 8)
    return ext(O_KU, crit, bitstr(bytes(raw), unused))


def x_eku(*kinds, crit=False):
    return ext(O_EKU, crit, seq(*[oid(EKU_OID[k]) for k in kinds]))


def x_san(*names, crit=False, o=O_SAN):
    return ext(o, crit, seq(*[gn(k, v) for k, v in names]))


def x_nc(permitted=(), excluded=(), crit=True):
    c = b""
    if permitted:
        c += ctx(0, b"".join(seq(gn(k, v)) for k, v in permitted))
    if excluded:
        c += ctx(1, b"".join(seq(gn(k, v)) for k, v in excluded))
    return ext(O_NC, crit, seq(c))


def x_certpol(*oids, crit=False):
    return ext(O_CP, crit, seq(*[seq(oid(o)) for o in oids]))


def x_polmap(a, b, crit=True):
    return ext(O_PM, crit, seq(seq(oid(a), oid(b))))


def x_polcons(require=None, inhibit=None, crit=True):
    c = b""
    if require is not None:
        c += ctxp(0, bytes([require]))
    if inhibit is not None:
        c += ctxp(1, bytes([inhibit]))
    return ext(O_PC, crit, seq(c))


def x_inhibit_any(n, crit=True):
    return ext(O_IAP, crit, integer(n))


def x_crldp(o=O_CRLDP, crit=False):
    return ext(o, crit, seq(seq(ctx(0, ctx(0, gn(URI, "http://crl.example.test/x.crl"))))))


def x_aia(crit=False):
    return ext(O_AIA, crit, seq(seq(oid("1.3.6.1.5.5.7.48.2"), gn(URI, "http://ca.example.test/ca.cer"))))


def x_sda(crit=False):
    return ext(O_SDA, crit, seq(seq(oid("1.3.6.1.5.5.7.9.4"), sset(prtstr("CZ")))))


def x_poison(crit=True):
    return ext(O_POISON, crit, null())


def x_unknown(crit=True):
    return ext(O_UNK, crit, null())


def keyid(key):
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha1(spki).digest()


def x_ski(key, crit=False):
    return ext(O_SKI, crit, octets(keyid(key)))


def x_aki(key, crit=False):
    return ext(O_AKI, crit, seq(ctxp(0, keyid(key))))


def ext_der(e):
    o, crit, val = e
    return seq(oid(o), boolean(True) if crit else b"", octets(val))


def put(exts, e):
    """Replace the extension with the same OID, else append."""
    out = [x for x in exts if x[0] != e[0]]
    i = [x[0] for x in exts].index(e[0]) if e[0] in [x[0] for x in exts] else len(out)
    out.insert(i, e)
    return out


# ---------------------------------------------------------------- names, keys, signing
def dn(cn=None, email=None):
    rdns = []
    if cn:
        rdns.append(sset(seq(oid("2.5.4.3"), utf8(cn))))
    if email:
        rdns.append(sset(seq(oid(OID_EMAIL), ia5(email))))
    return seq(*rdns)


def spki(key):
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def sigalg(scheme):
    return {"ec256": seq(oid("1.2.840.10045.4.3.2")), "ecsha1": seq(oid("1.2.840.10045.4.1")),
            "rsa256": seq(oid("1.2.840.113549.1.1.11"), null()),
            "rsa1": seq(oid("1.2.840.113549.1.1.5"), null())}[scheme]


def sign(key, scheme, data):
    if scheme == "ec256":
        return key.sign(data, ec.ECDSA(hashes.SHA256()))
    if scheme == "ecsha1":
        return key.sign(data, ec.ECDSA(hashes.SHA1()))
    if scheme == "rsa256":
        return key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return key.sign(data, padding.PKCS1v15(), hashes.SHA1())


_serial = [0x1000]


def make_cert(subject, key, issuer, signer, scheme, exts, serial=None, serial_der=None, nb=NB, na=NA,
              version=3, sigalg_der=None):
    """subject/issuer: DN DER. key: subject key. signer: issuer key. exts: list of (oid, crit, val) or None."""
    if serial_der is None:
        if serial is None:
            _serial[0] += 1
            serial = _serial[0]
        serial_der = integer(serial)
    sa = sigalg_der if sigalg_der is not None else sigalg(scheme)
    parts = []
    if version == 3:
        parts.append(ctx(0, integer(2)))
    parts += [serial_der, sa, issuer, seq(utctime(nb), utctime(na)), subject, spki(key)]
    if exts:
        parts.append(ctx(3, seq(*[ext_der(e) for e in exts])))
    tbs = seq(*parts)
    return seq(tbs, sa, bitstr(sign(signer, scheme, tbs)))


def pem(der):
    b = base64.b64encode(der).decode()
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + "\n-----END CERTIFICATE-----\n"


def ec_key(n):
    # deterministic: the private key is derived from a fixed per-role integer
    return ec.derive_private_key(n, ec.SECP256R1())


def rsa_key():
    return rsa.generate_private_key(65537, 2048)


K = {"root": ec_key(0x5201), "inter": ec_key(0x5202), "leaf": ec_key(0x5203)}
KR = {"root": rsa_key(), "inter": rsa_key(), "leaf": rsa_key()}
ROOT_DN, INTER_DN, LEAF_DN = dn("Probe Root"), dn("Probe Inter"), dn("leaf cert")


def ca_exts(key, pathlen=None):
    return [x_bc(True, pathlen), x_ku("keyCertSign", "cRLSign")]


def leaf_exts(*names):
    return [x_san(*names), x_ku("digitalSignature")] if names else [x_ku("digitalSignature")]


DEF_SAN = [(DNS, "example.com")]


def chain(root_exts=None, inter_exts=None, leaf_exts_=None, keys=K, root_scheme="ec256", inter_scheme="ec256",
          leaf_scheme="ec256", root_kw=None, inter_kw=None, leaf_kw=None, no_inter=False, leaf_dn=LEAF_DN):
    """Returns dict(roots=[der], intermediates=[der], leaf=der)."""
    root_exts = ca_exts(keys["root"]) if root_exts is None else root_exts
    inter_exts = ca_exts(keys["inter"]) if inter_exts is None else inter_exts
    leaf_exts_ = leaf_exts(*DEF_SAN) if leaf_exts_ is None else leaf_exts_
    root = make_cert(ROOT_DN, keys["root"], ROOT_DN, keys["root"], root_scheme, root_exts, **(root_kw or {}))
    if no_inter:
        leaf = make_cert(leaf_dn, keys["leaf"], ROOT_DN, keys["root"], leaf_scheme, leaf_exts_, **(leaf_kw or {}))
        return dict(roots=[root], intermediates=[], leaf=leaf)
    inter = make_cert(INTER_DN, keys["inter"], ROOT_DN, keys["root"], inter_scheme, inter_exts, **(inter_kw or {}))
    leaf = make_cert(leaf_dn, keys["leaf"], INTER_DN, keys["inter"], leaf_scheme, leaf_exts_, **(leaf_kw or {}))
    return dict(roots=[root], intermediates=[inter], leaf=leaf)


# ---------------------------------------------------------------- case registry
CASES = []


def add(cid, probe, desc, ch, mode="verify", time=T_VERIFY, dns_name=None, key_usages=None, host=None,
        ossl=None, policies=None):
    CASES.append(dict(id=cid, probe=probe, desc=desc, der=dict(roots=list(ch["roots"]), inters=list(ch["intermediates"]), leaf=ch["leaf"]),
                      roots=[pem(x) for x in ch["roots"]],
                      intermediates=[pem(x) for x in ch["intermediates"]], leaf=pem(ch["leaf"]), time=time,
                      dns_name=dns_name, key_usages=key_usages, mode=mode, host=host or "", ossl=ossl or {}, policies=list(policies or [])))


def hostcase(cid, probe, desc, leaf_der, host):
    add(cid, probe, desc, dict(roots=[], intermediates=[], leaf=leaf_der), mode="hostname", host=host)


def simple_leaf(exts, dn_=LEAF_DN):
    return make_cert(dn_, K["leaf"], ROOT_DN, K["root"], "ec256", exts)


# ---- O-dns
DNS_CONS = ["example.com", ".example.com", ""]
DNS_SANS = ["example.com", "a.example.com", "a.b.example.com", "xexample.com", "EXAMPLE.com", "a.example.com."]
for ci, c in enumerate(DNS_CONS):
    for kind in ("permitted", "excluded"):
        for si, s in enumerate(DNS_SANS):
            nc = x_nc(permitted=[(DNS, c)]) if kind == "permitted" else x_nc(excluded=[(DNS, c)])
            add(f"dns-{kind[:4]}-c{ci}-s{si}", "O-dns", f"{kind} dNSName '{c}' vs SAN '{s}'",
                chain(inter_exts=ca_exts(K["inter"]) + [nc], leaf_exts_=leaf_exts((DNS, s))))

# ---- O-uri
URI_CONS = ["example.com", ".example.com"]
URIS = ["https://example.com/x", "https://a.example.com", "https://user@example.com:8443/p", "https://192.0.2.1/",
        "https://[::1]/", "urn:uuid:1234", "spiffe://example.com/ns/a"]
for ci, c in enumerate(URI_CONS):
    for kind in ("permitted", "excluded"):
        for ui, u in enumerate(URIS):
            nc = x_nc(permitted=[(URI, c)]) if kind == "permitted" else x_nc(excluded=[(URI, c)])
            add(f"uri-{kind[:4]}-c{ci}-u{ui}", "O-uri", f"{kind} URI '{c}' vs SAN URI '{u}'",
                chain(inter_exts=ca_exts(K["inter"]) + [nc], leaf_exts_=leaf_exts((URI, u))))

# ---- O-email
EM_CONS = ["user@example.com", "example.com", ".example.com"]
EMAILS = ["user@example.com", "User@example.com", "user@EXAMPLE.COM", "user@a.example.com", '"a@b"@example.com']
for ci, c in enumerate(EM_CONS):
    for kind in ("permitted", "excluded"):
        for ei, e in enumerate(EMAILS):
            nc = x_nc(permitted=[(EMAIL, c)]) if kind == "permitted" else x_nc(excluded=[(EMAIL, c)])
            add(f"email-{kind[:4]}-c{ci}-e{ei}", "O-email", f"{kind} rfc822 '{c}' vs SAN email '{e}'",
                chain(inter_exts=ca_exts(K["inter"]) + [nc], leaf_exts_=leaf_exts((EMAIL, e))))
add("email-subj-perm", "O-email", "permitted rfc822 'example.com'; leaf has NO SAN, subject emailAddress=user@other.com",
    chain(inter_exts=ca_exts(K["inter"]) + [x_nc(permitted=[(EMAIL, "example.com")])], leaf_exts_=leaf_exts(),
          leaf_dn=dn("leaf cert", "user@other.com")))
add("email-subj-excl", "O-email", "excluded rfc822 'example.com'; leaf has NO SAN, subject emailAddress=user@example.com",
    chain(inter_exts=ca_exts(K["inter"]) + [x_nc(excluded=[(EMAIL, "example.com")])], leaf_exts_=leaf_exts(),
          leaf_dn=dn("leaf cert", "user@example.com")))
add("email-subj-perm-ok", "O-email", "permitted rfc822 'example.com'; leaf has NO SAN, subject emailAddress=user@example.com",
    chain(inter_exts=ca_exts(K["inter"]) + [x_nc(permitted=[(EMAIL, "example.com")])], leaf_exts_=leaf_exts(),
          leaf_dn=dn("leaf cert", "user@example.com")))

# ---- O-wild
for si, s in enumerate(["*.example.com", "*.com", "f*.example.com", "*.*.example.com", "a.*.example.com", "*"]):
    leaf = simple_leaf(leaf_exts((DNS, s)))
    for hi, h in enumerate(["a.example.com", "example.com", "a.b.example.com", "foo.com", "fa.example.com",
                            "A.EXAMPLE.COM"]):
        hostcase(f"wild-s{si}-h{hi}", "O-wild", f"SAN '{s}' vs host '{h}'", leaf, h)

# ---- O-trailing
leaf = simple_leaf(leaf_exts((DNS, "example.com")))
hostcase("trail-1", "O-trailing", "SAN 'example.com' vs host 'example.com.'", leaf, "example.com.")
leaf = simple_leaf(leaf_exts((DNS, "example.com.")))
hostcase("trail-2", "O-trailing", "SAN 'example.com.' vs host 'example.com'", leaf, "example.com")
hostcase("trail-2b", "O-trailing", "SAN 'example.com.' vs host 'example.com.'", leaf, "example.com.")
for tag, ipv in (("v4", "192.0.2.1"), ("v6", "2001:db8::1")):
    leaf = simple_leaf(leaf_exts((IPA, ipv)))
    for hi, h in enumerate(["192.0.2.1", "[2001:db8::1]", "2001:db8::1", "2001:0db8::1", "::ffff:192.0.2.1"]):
        hostcase(f"trail-ip{tag}-h{hi}", "O-trailing", f"IP SAN {ipv} vs host '{h}'", leaf, h)
hostcase("trail-ip4-h5", "O-trailing", "IP SAN 192.0.2.1 vs host '[192.0.2.1]'",
         simple_leaf(leaf_exts((IPA, "192.0.2.1"))), "[192.0.2.1]")
hostcase("trail-cn", "O-trailing", "CN-only leaf (no SAN, CN=example.com) vs host 'example.com'",
         simple_leaf([x_ku("digitalSignature")], dn("example.com")), "example.com")
hostcase("trail-iponly-dns", "O-trailing", "SAN only an IP (192.0.2.1) vs DNS host 'example.com'",
         simple_leaf(leaf_exts((IPA, "192.0.2.1"))), "example.com")
hostcase("trail-dnsip", "O-trailing", "DNS SAN '192.0.2.1' vs host '192.0.2.1'",
         simple_leaf(leaf_exts((DNS, "192.0.2.1"))), "192.0.2.1")

# ---- O-crit
def _ki(key):
    return key


CRIT_EXT = {  # name -> (leaf builder or None, intermediate builder or None); builder takes `crit`
    "unknown": (x_unknown, x_unknown),
    "certpol": (lambda c: x_certpol("1.2.3.4", crit=c),) * 2,
    "polmap": (None, lambda c: x_polmap("1.2.3.4", "1.2.3.5", c)),
    "polcons": (lambda c: x_polcons(require=5, crit=c),) * 2,
    "inhibitany": (lambda c: x_inhibit_any(5, c),) * 2,
    "ian": (lambda c: x_san((DNS, "issuer.example.test"), crit=c, o=O_IAN),) * 2,
    "crldp": (lambda c: x_crldp(crit=c),) * 2,
    "aia": (x_aia, x_aia),
    "ski": (lambda c: x_ski(K["leaf"], c), lambda c: x_ski(K["inter"], c)),
    "aki": (lambda c: x_aki(K["inter"], c), lambda c: x_aki(K["root"], c)),
    "poison": (x_poison, x_poison),
    "sda": (x_sda, x_sda),
    "freshest": (lambda c: x_crldp(O_FCRL, c),) * 2,
    "nc": (lambda c: x_nc(permitted=[(DNS, "example.com")], crit=c),) * 2,
    "eku": (lambda c: x_eku("server", "client", crit=c),) * 2,
    "ku": (lambda c: x_ku("digitalSignature", "keyCertSign", crit=c),) * 2,
    "bc": (lambda c: x_bc(False, crit=c), lambda c: x_bc(True, crit=c)),
    "san": (lambda c: x_san(*DEF_SAN, crit=c),) * 2,
}
for name, (mk_leaf, mk_inter) in CRIT_EXT.items():
    for crit in (True, False):
        tag = "crit" if crit else "noncrit"
        if mk_leaf:
            add(f"crit-leaf-{name}-{tag}", "O-crit", f"LEAF has {name} extension, critical={crit}",
                chain(leaf_exts_=put(leaf_exts(*DEF_SAN), mk_leaf(crit))))
        if mk_inter:
            ex = put(ca_exts(K["inter"]), mk_inter(crit))
            if name == "polmap":
                ex = ex + [x_certpol("1.2.3.4")]
            add(f"crit-inter-{name}-{tag}", "O-crit", f"INTERMEDIATE has {name} extension, critical={crit}",
                chain(inter_exts=ex))

# duplicates
base = leaf_exts(*DEF_SAN)
add("dup-leaf-san", "O-crit", "LEAF with two SAN extensions (example.com, then other.com)",
    chain(leaf_exts_=base + [x_san((DNS, "other.com"))]), dns_name="example.com")
add("dup-leaf-san-b", "O-crit", "LEAF with two SAN extensions (example.com, then other.com), dns_name=other.com",
    chain(leaf_exts_=base + [x_san((DNS, "other.com"))]), dns_name="other.com")
add("dup-inter-bc", "O-crit", "INTERMEDIATE with two basicConstraints (cA=true, then cA=false)",
    chain(inter_exts=ca_exts(K["inter"]) + [x_bc(False)]))
add("dup-inter-bc-rev", "O-crit", "INTERMEDIATE with two basicConstraints (cA=false first, then cA=true)",
    chain(inter_exts=[x_bc(False), x_ku("keyCertSign"), x_bc(True)]))
add("dup-inter-nc", "O-crit", "INTERMEDIATE with two nameConstraints (permit example.com, then exclude example.com)",
    chain(inter_exts=ca_exts(K["inter"]) + [x_nc(permitted=[(DNS, "example.com")]), x_nc(excluded=[(DNS, "example.com")])]))
add("dup-inter-nc2", "O-crit", "INTERMEDIATE with two nameConstraints (exclude example.com first, then permit example.com)",
    chain(inter_exts=ca_exts(K["inter"]) + [x_nc(excluded=[(DNS, "example.com")]), x_nc(permitted=[(DNS, "example.com")])]))
DUP_LEAF = chain(leaf_exts_=base + [x_san((DNS, "other.com"))])["leaf"]
DUP_INTER = chain(inter_exts=ca_exts(K["inter"]) + [x_bc(False)])["intermediates"][0]

# ---- O-roots
LEAF_X = leaf_exts(*DEF_SAN)
add("roots-v1", "O-roots", "v1 self-signed root (no extensions) signs leaf directly",
    chain(root_exts=[], root_kw=dict(version=1), no_inter=True))
add("roots-v3-nobc", "O-roots", "v3 root without basicConstraints (has keyUsage keyCertSign)",
    chain(root_exts=[x_ku("keyCertSign")], no_inter=True))
add("roots-v3-noext", "O-roots", "v3 root with no extensions at all",
    chain(root_exts=[], no_inter=True))
add("roots-ca-false", "O-roots", "root with basicConstraints cA=false",
    chain(root_exts=[x_bc(False), x_ku("keyCertSign")], no_inter=True))
add("roots-nokcs", "O-roots", "root with keyUsage lacking keyCertSign (digitalSignature only)",
    chain(root_exts=[x_bc(True), x_ku("digitalSignature")], no_inter=True))
add("roots-control", "O-roots", "control: normal root (cA=true, keyCertSign) signs leaf directly",
    chain(no_inter=True))

# ---- O-anchor-time
yr = lambda y: dt.datetime(y, 1, 1, tzinfo=UTC)
add("anchor-control", "O-anchor-time", "control: everything valid", chain())
add("anchor-root-expired", "O-anchor-time", "root notAfter 2026-01-01 < verify time 2026-06-01, leaf/inter valid",
    chain(root_kw=dict(na=yr(2026))))
add("anchor-root-notyet", "O-anchor-time", "root notBefore 2027-01-01 > verify time, leaf/inter valid",
    chain(root_kw=dict(nb=yr(2027))))
add("anchor-inter-expired", "O-anchor-time", "intermediate expired (notAfter 2026-01-01), root valid",
    chain(inter_kw=dict(na=yr(2026))))
add("anchor-leaf-expired", "O-anchor-time", "leaf expired (notAfter 2026-01-01), chain valid",
    chain(leaf_kw=dict(na=yr(2026))))

# ---- O-policy
add("policy-control", "O-policy", "control: no policy extensions", chain())
add("policy-reqexp", "O-policy", "intermediate critical policyConstraints{requireExplicitPolicy=0}, leaf no certificatePolicies",
    chain(inter_exts=ca_exts(K["inter"]) + [x_polcons(require=0)]))
add("policy-inhmap", "O-policy", "intermediate critical policyConstraints{inhibitPolicyMapping=0}, leaf no certificatePolicies",
    chain(inter_exts=ca_exts(K["inter"]) + [x_polcons(inhibit=0)]))
add("policy-inhany", "O-policy", "intermediate critical inhibitAnyPolicy=0, leaf no certificatePolicies",
    chain(inter_exts=ca_exts(K["inter"]) + [x_inhibit_any(0)]))
add("policy-reqexp-leafpol", "O-policy",
    "intermediate requireExplicitPolicy=0 + certificatePolicies 1.2.3.4; leaf certificatePolicies 1.2.3.4",
    chain(inter_exts=ca_exts(K["inter"]) + [x_polcons(require=0), x_certpol("1.2.3.4")],
          leaf_exts_=leaf_exts(*DEF_SAN) + [x_certpol("1.2.3.4")]))
add("policy-reqexp-leafother", "O-policy",
    "intermediate requireExplicitPolicy=0 + certificatePolicies 1.2.3.4; leaf certificatePolicies 1.2.3.9 (disjoint)",
    chain(inter_exts=ca_exts(K["inter"]) + [x_polcons(require=0), x_certpol("1.2.3.4")],
          leaf_exts_=leaf_exts(*DEF_SAN) + [x_certpol("1.2.3.9")]))
add("policy-reqexp-leafany", "O-policy",
    "intermediate requireExplicitPolicy=0; leaf certificatePolicies anyPolicy (2.5.29.32.0)",
    chain(inter_exts=ca_exts(K["inter"]) + [x_polcons(require=0)],
          leaf_exts_=leaf_exts(*DEF_SAN) + [x_certpol("2.5.29.32.0")]))

# ---- O-policy2: RFC 5280 6.1 policy processing (mappings, constraints, self-issued, caller policy set)
PA, PB, PC, PD, PANY = "1.2.3.1", "1.2.3.2", "1.2.3.4", "1.2.3.5", "2.5.29.32.0"
K_MID = ec_key(0x5204)
MID_DN = dn("Probe Inter2")


def x_polmaps(*pairs, crit=True):
    return ext(O_PM, crit, seq(*[seq(oid(a), oid(b)) for a, b in pairs]))


def x_cp(*oids, crit=False):
    return x_certpol(*oids, crit=crit)


def pol_chain(i1=(), mid=None, leaf=(), root=(), req=None, inh=None, ia=None, self_issued=False, extra_i1=()):
    """root -> inter1 [-> mid] -> leaf. i1/mid/leaf: extra extensions. req/inh: policyConstraints on inter1;
    ia: inhibitAnyPolicy on inter1. self_issued: mid has inter1's subject DN (different key)."""
    rx = ca_exts(K["root"]) + list(root)
    ix = ca_exts(K["inter"]) + list(i1) + list(extra_i1)
    if req is not None or inh is not None:
        ix.append(x_polcons(require=req, inhibit=inh))
    if ia is not None:
        ix.append(x_inhibit_any(ia))
    if self_issued:  # key ids so that OpenSSL (and Go) pick the right one of the two same-subject issuers
        ix.append(x_ski(K["inter"]))
    root_c = make_cert(ROOT_DN, K["root"], ROOT_DN, K["root"], "ec256", rx)
    inter_c = make_cert(INTER_DN, K["inter"], ROOT_DN, K["root"], "ec256", ix)
    lx = leaf_exts(*DEF_SAN) + list(leaf)
    if mid is None:
        leaf_c = make_cert(LEAF_DN, K["leaf"], INTER_DN, K["inter"], "ec256", lx)
        return dict(roots=[root_c], intermediates=[inter_c], leaf=leaf_c)
    mdn = INTER_DN if self_issued else MID_DN
    mkid = [x_ski(K_MID), x_aki(K["inter"])] if self_issued else []
    lx = lx + ([x_aki(K_MID)] if self_issued else [])
    mid_c = make_cert(mdn, K_MID, INTER_DN, K["inter"], "ec256", ca_exts(K_MID) + list(mid) + mkid)
    leaf_c = make_cert(LEAF_DN, K["leaf"], mdn, K_MID, "ec256", lx)
    return dict(roots=[root_c], intermediates=[inter_c, mid_c], leaf=leaf_c)


def pcase(cid, desc, pol=(), **kw):
    add("pol2-" + cid, "O-policy2", desc, pol_chain(**kw), policies=pol)


# matrix: scenario x {plain, requireExplicitPolicy=0 on inter1, caller set}
MATRIX = [
    ("same", "inter1 {C}, leaf {C}", dict(i1=[x_cp(PC)], leaf=[x_cp(PC)]), [PC]),
    ("disj", "inter1 {C}, leaf {D}", dict(i1=[x_cp(PC)], leaf=[x_cp(PD)]), [PC]),
    ("leafonly", "inter1 none, leaf {C}", dict(leaf=[x_cp(PC)]), [PC]),
    ("i1only", "inter1 {C}, leaf none", dict(i1=[x_cp(PC)]), [PC]),
    ("i1any-leafC", "inter1 anyPolicy, leaf {C}", dict(i1=[x_cp(PANY)], leaf=[x_cp(PC)]), [PC]),
    ("i1C-leafany", "inter1 {C}, leaf anyPolicy", dict(i1=[x_cp(PC)], leaf=[x_cp(PANY)]), [PC]),
    ("any-any", "inter1 anyPolicy, leaf anyPolicy", dict(i1=[x_cp(PANY)], leaf=[x_cp(PANY)]), [PC]),
    ("map", "inter1 {A} maps A->B, leaf {B}", dict(i1=[x_cp(PA), x_polmaps((PA, PB))], leaf=[x_cp(PB)]), [PB]),
    ("map-leafA", "inter1 {A} maps A->B, leaf {A}", dict(i1=[x_cp(PA), x_polmaps((PA, PB))], leaf=[x_cp(PA)]), [PA]),
    ("map-any", "inter1 anyPolicy maps A->B, leaf {B}", dict(i1=[x_cp(PANY), x_polmaps((PA, PB))], leaf=[x_cp(PB)]), [PB]),
    ("map-1tomany", "inter1 {A} maps A->B and A->C, leaf {C}",
     dict(i1=[x_cp(PA), x_polmaps((PA, PB), (PA, PC))], leaf=[x_cp(PC)]), [PC]),
    ("mid-same", "inter1 {C}, inter2 {C}, leaf {C}", dict(i1=[x_cp(PC)], mid=[x_cp(PC)], leaf=[x_cp(PC)]), [PC]),
    ("mid-gap", "inter1 {C}, inter2 {D}, leaf {C}", dict(i1=[x_cp(PC)], mid=[x_cp(PD)], leaf=[x_cp(PC)]), [PC]),
]
SET_VARIANTS = {"same", "disj", "i1any-leafC", "i1C-leafany", "any-any", "map", "map-leafA", "mid-same"}
for name, desc, kw, pset in MATRIX:
    pcase(name, desc, **kw)
    pcase(name + "-rx0", desc + "; inter1 requireExplicitPolicy=0", req=0, **kw)
    if name in SET_VARIANTS:
        pcase(name + "-set", desc + "; inter1 requireExplicitPolicy=0; caller policy set {%s}" % pset[0], pol=pset, req=0, **kw)
        pcase(name + "-setplain", desc + "; caller policy set {%s} (explicit policy not required)" % pset[0], pol=pset, **kw)

# caller set variants beyond the matrix
pcase("set-two", "inter1 {C}, leaf {C}; inter1 requireExplicitPolicy=0; caller set {C, D}", pol=[PC, PD], req=0, i1=[x_cp(PC)], leaf=[x_cp(PC)])
pcase("set-two-miss", "inter1 {C}, leaf {C}; inter1 requireExplicitPolicy=0; caller set {A, D} (neither)", pol=[PA, PD], req=0, i1=[x_cp(PC)], leaf=[x_cp(PC)])
pcase("set-via-map", "inter1 {A} maps A->C, leaf {C}; inter1 requireExplicitPolicy=0; caller set {C}", pol=[PC], req=0, i1=[x_cp(PA), x_polmaps((PA, PC))],
      leaf=[x_cp(PC)])
pcase("set-via-map-src", "inter1 {A} maps A->C, leaf {C}; caller set {A} (the mapped-away policy); inter1 requireExplicitPolicy=0", pol=[PA], req=0,
      i1=[x_cp(PA), x_polmaps((PA, PC))], leaf=[x_cp(PC)])
pcase("set-via-any-chain", "inter1 anyPolicy, inter2 anyPolicy, leaf anyPolicy; inter1 requireExplicitPolicy=0; caller set {C}", pol=[PC], req=0,
      i1=[x_cp(PANY)], mid=[x_cp(PANY)], leaf=[x_cp(PANY)])
pcase("set-nopol", "no policies anywhere; inter1 requireExplicitPolicy=0; caller set {C}", pol=[PC], req=0)
pcase("set-nopol-plain", "no policies anywhere; caller set {C} (explicit policy not required)", pol=[PC])

# inhibitPolicyMapping (inter1) with the mapping on inter2
for v in (0, 1):
    for rx in (False, True):
        pcase(f"inhmap{v}" + ("-rx" if rx else ""),
              f"inter1 {{A}} inhibitPolicyMapping={v}; inter2 {{A}} maps A->B; leaf {{B}}" + ("; requireExplicitPolicy=0" if rx else ""),
              i1=[x_cp(PA)], inh=v, req=0 if rx else None, mid=[x_cp(PA), x_polmaps((PA, PB))], leaf=[x_cp(PB)])

# inhibitAnyPolicy with anyPolicy below
for v in (0, 1):
    pcase(f"inhany{v}-direct", f"inter1 inhibitAnyPolicy={v}, anyPolicy; leaf {{C}}; requireExplicitPolicy=0",
          i1=[x_cp(PANY)], ia=v, req=0, leaf=[x_cp(PC)])
    pcase(f"inhany{v}-mid", f"inter1 {{C}} inhibitAnyPolicy={v}; inter2 anyPolicy; leaf {{C}}; requireExplicitPolicy=0",
          i1=[x_cp(PC)], ia=v, req=0, mid=[x_cp(PANY)], leaf=[x_cp(PC)])
    pcase(f"inhany{v}-leafany", f"inter1 {{C}} inhibitAnyPolicy={v}; leaf anyPolicy; requireExplicitPolicy=0",
          i1=[x_cp(PC)], ia=v, req=0, leaf=[x_cp(PANY)])

# requireExplicitPolicy counting
for v in (0, 1, 2):
    pcase(f"req{v}-leafnone", f"inter1 {{C}} requireExplicitPolicy={v}, inter2 {{C}}, leaf without policies",
          i1=[x_cp(PC)], req=v, mid=[x_cp(PC)])
    pcase(f"req{v}-leafC", f"inter1 {{C}} requireExplicitPolicy={v}, inter2 {{C}}, leaf {{C}}",
          i1=[x_cp(PC)], req=v, mid=[x_cp(PC)], leaf=[x_cp(PC)])
    pcase(f"req{v}-nomid-leafnone", f"inter1 {{C}} requireExplicitPolicy={v}, no inter2, leaf without policies",
          i1=[x_cp(PC)], req=v)
pcase("req1-leafdisj", "inter1 {C} requireExplicitPolicy=1, inter2 {C}, leaf {D}", i1=[x_cp(PC)], req=1, mid=[x_cp(PC)],
      leaf=[x_cp(PD)])

# self-issued intermediate (same subject DN as inter1, different key) between inter1 and leaf
for si in (True, False):
    t = "selfissued" if si else "otherdn"
    d = "self-issued" if si else "different-DN"
    pcase(f"{t}-inhany0", f"inter1 {{C}} inhibitAnyPolicy=0; {d} inter2 anyPolicy; leaf {{C}}; requireExplicitPolicy=0",
          i1=[x_cp(PC)], ia=0, req=0, mid=[x_cp(PANY)], leaf=[x_cp(PC)], self_issued=si)
    pcase(f"{t}-req1-leafnone", f"inter1 {{C}} requireExplicitPolicy=1; {d} inter2 {{C}}; leaf without policies",
          i1=[x_cp(PC)], req=1, mid=[x_cp(PC)], self_issued=si)
    pcase(f"{t}-req1-leafC", f"inter1 {{C}} requireExplicitPolicy=1; {d} inter2 {{C}}; leaf {{C}}",
          i1=[x_cp(PC)], req=1, mid=[x_cp(PC)], leaf=[x_cp(PC)], self_issued=si)
pcase("selfissued-inhany1", "inter1 {C} inhibitAnyPolicy=1; self-issued inter2 anyPolicy; leaf anyPolicy; requireExplicitPolicy=0",
      i1=[x_cp(PC)], ia=1, req=0, mid=[x_cp(PANY)], leaf=[x_cp(PANY)], self_issued=True)

# misc
pcase("root-policies", "root carries certificatePolicies {D}; inter1 {C}, leaf {C}; inter1 requireExplicitPolicy=0",
      root=[x_cp(PD)], i1=[x_cp(PC)], req=0, leaf=[x_cp(PC)])

# malformed
pcase("bad-map-from-any", "inter1 policyMappings anyPolicy->B (issuerDomainPolicy is anyPolicy), leaf {B}",
      i1=[x_cp(PANY), x_polmaps((PANY, PB))], leaf=[x_cp(PB)])
pcase("bad-map-to-any", "inter1 policyMappings A->anyPolicy (subjectDomainPolicy is anyPolicy), leaf {A}",
      i1=[x_cp(PA), x_polmaps((PA, PANY))], leaf=[x_cp(PA)])
pcase("bad-polcons-empty", "inter1 empty policyConstraints SEQUENCE {}, inter1 {C}, leaf {C}",
      i1=[x_cp(PC)], req=None, inh=None, extra_i1=[x_polcons()], leaf=[x_cp(PC)])
pcase("bad-dup-leaf", "leaf certificatePolicies lists {C, C}; inter1 {C}; requireExplicitPolicy=0",
      i1=[x_cp(PC)], req=0, leaf=[x_cp(PC, PC)])
pcase("bad-dup-i1", "inter1 certificatePolicies lists {C, C}; leaf {C}; requireExplicitPolicy=0",
      i1=[x_cp(PC, PC)], req=0, leaf=[x_cp(PC)])
pcase("bad-empty-leaf", "leaf certificatePolicies is an empty SEQUENCE; inter1 {C}; requireExplicitPolicy=0",
      i1=[x_cp(PC)], req=0, leaf=[x_cp()])
pcase("bad-empty-i1", "inter1 certificatePolicies is an empty SEQUENCE; leaf {C}; requireExplicitPolicy=0",
      i1=[x_cp()], req=0, leaf=[x_cp(PC)])
pcase("bad-empty-leaf-set", "leaf certificatePolicies is an empty SEQUENCE; inter1 {C}; caller set {C}",
      pol=[PC], req=0, i1=[x_cp(PC)], leaf=[x_cp()])

# ---- O-sha1
add("sha1-control", "O-sha1", "control: RSA chain all sha256WithRSA", chain(keys=KR, root_scheme="rsa256",
    inter_scheme="rsa256", leaf_scheme="rsa256"))
add("sha1-leaf-rsa", "O-sha1", "leaf signed sha1WithRSAEncryption", chain(keys=KR, root_scheme="rsa256",
    inter_scheme="rsa256", leaf_scheme="rsa1"))
add("sha1-inter-rsa", "O-sha1", "intermediate signed sha1WithRSAEncryption (leaf sha256)", chain(keys=KR,
    root_scheme="rsa256", inter_scheme="rsa1", leaf_scheme="rsa256"))
add("sha1-root-self", "O-sha1", "root SELF-signature sha1WithRSA, rest sha256", chain(keys=KR, root_scheme="rsa1",
    inter_scheme="rsa256", leaf_scheme="rsa256"))
add("sha1-leaf-ecdsa", "O-sha1", "leaf signed ecdsa-with-SHA1", chain(leaf_scheme="ecsha1"))
add("sha1-inter-ecdsa", "O-sha1", "intermediate signed ecdsa-with-SHA1", chain(inter_scheme="ecsha1"))

# ---- O-eku
KU_SETS = {"null": None, "server": ["server"], "client": ["client"], "any": ["any"], "client+server": ["client", "server"]}
for le in ("none", "server", "client", "any"):
    for ie in ("none", "server", "client"):
        for kn, ks in KU_SETS.items():
            lx = leaf_exts(*DEF_SAN) + ([x_eku(le)] if le != "none" else [])
            ix = ca_exts(K["inter"]) + ([x_eku(ie)] if ie != "none" else [])
            add(f"eku-l{le}-i{ie}-k{kn}", "O-eku", f"leaf EKU {le}, intermediate EKU {ie}, KeyUsages {kn}",
                chain(inter_exts=ix, leaf_exts_=lx), key_usages=ks)

# ---- O-parse
def parse_case(cid, desc, leaf_der):
    add(cid, "O-parse", desc, dict(roots=[], intermediates=[], leaf=leaf_der), mode="parse")


LX = leaf_exts(*DEF_SAN)
parse_case("parse-control", "control: ordinary leaf", simple_leaf(LX))
parse_case("parse-serial0", "serial 0", make_cert(LEAF_DN, K["leaf"], ROOT_DN, K["root"], "ec256", LX, serial=0))
parse_case("parse-serial-neg", "negative serial (-1)", make_cert(LEAF_DN, K["leaf"], ROOT_DN, K["root"], "ec256", LX, serial=-1))
parse_case("parse-serial20", "20-octet positive serial", make_cert(LEAF_DN, K["leaf"], ROOT_DN, K["root"], "ec256", LX,
           serial=(1 << 159) - 1))
parse_case("parse-serial20hi", "20-octet serial with high bit via 0x00 pad (21 octets encoded, 2^159+1)",
           make_cert(LEAF_DN, K["leaf"], ROOT_DN, K["root"], "ec256", LX, serial=(1 << 159) + 1))
parse_case("parse-serial21", "21 significant octets serial (2^160 + 1)", make_cert(LEAF_DN, K["leaf"], ROOT_DN, K["root"],
           "ec256", LX, serial=(1 << 160) + 1))
parse_case("parse-serial-nonminimal", "non-minimal INTEGER serial (00 00 05)",
           make_cert(LEAF_DN, K["leaf"], ROOT_DN, K["root"], "ec256", LX, serial_der=tlv(0x02, b"\x00\x00\x05")))
parse_case("parse-serial-nonminimal-ff", "non-minimal INTEGER serial (ff ff)",
           make_cert(LEAF_DN, K["leaf"], ROOT_DN, K["root"], "ec256", LX, serial_der=tlv(0x02, b"\xff\xff")))
parse_case("parse-v1-ext", "v1 certificate (no version field) carrying extensions",
           make_cert(LEAF_DN, K["leaf"], ROOT_DN, K["root"], "ec256", LX, version=1))
parse_case("parse-dup-ext-san", "duplicate extension: leaf with two SAN (from O-crit)", DUP_LEAF)
parse_case("parse-dup-ext-bc", "duplicate extension: intermediate with two basicConstraints (from O-crit)", DUP_INTER)
parse_case("parse-unknown-sigalg", "unknown signature algorithm OID (inner and outer)",
           make_cert(LEAF_DN, K["leaf"], ROOT_DN, K["root"], "ec256", LX, sigalg_der=seq(oid("1.3.6.1.4.1.99999.2"))))

# ================================================================ run the oracles


def clean(d):
    """Remove generated files per-file (never rm -rf); keep the go_oracle binary."""
    for r, ds, fs in os.walk(d, topdown=False):
        for f in fs:
            if r == d and f == "go_oracle":
                continue
            os.remove(os.path.join(r, f))
        for x in ds:
            os.rmdir(os.path.join(r, x))


os.makedirs(OUT, exist_ok=True)
clean(OUT)
for c in CASES:
    d = os.path.join(OUT, "cases", c["id"])
    os.makedirs(d)
    for name, content in (("roots.pem", "".join(c["roots"])), ("inter.pem", "".join(c["intermediates"])),
                          ("leaf.pem", c["leaf"])):
        with open(os.path.join(d, name), "w") as f:
            f.write(content)
ids = [c["id"] for c in CASES]
assert len(ids) == len(set(ids)), "duplicate case id"
with open(os.path.join(OUT, "cases.jsonl"), "w") as f:
    for c in CASES:
        f.write(json.dumps({k: c[k] for k in ("id", "probe", "roots", "intermediates", "leaf", "time", "dns_name",
                                              "key_usages", "mode", "host", "policies")}) + "\n")

GO = os.path.join(OUT, "go_oracle")
if not os.path.exists(GO):
    env = dict(os.environ, GOFLAGS="-mod=mod", GOTOOLCHAIN="local")
    subprocess.run(["go", "build", "-o", GO, "."], cwd=os.path.join(HERE, "go_oracle"), env=env, check=True)
with open(os.path.join(OUT, "cases.jsonl")) as f:
    p = subprocess.run([GO], stdin=f, capture_output=True, text=True, timeout=120, check=True)
GOR = {}
for line in p.stdout.splitlines():
    r = json.loads(line)
    GOR[r["id"]] = r
with open(os.path.join(OUT, "go_results.jsonl"), "w") as f:
    f.write(p.stdout)
# oracle sanity: exactly one result per case, same ids, no oracle-side error (bad PEM)
_lines = [x for x in p.stdout.splitlines() if x.strip()]
if len(_lines) != len(CASES) or set(GOR) != {c["id"] for c in CASES}:
    sys.exit(f"go_oracle returned {len(_lines)} lines for {len(CASES)} cases (or ids differ)")
for _r in GOR.values():
    if _r["msg"].startswith("bad pem"):
        sys.exit(f"go_oracle error on {_r['id']}: {_r['msg']}")


def sh(args, timeout=20):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr)
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def one(s, n=220):
    return " | ".join(x.strip() for x in s.strip().splitlines() if x.strip())[:n].replace("\t", " ")


PANY_OID = "2.5.29.32.0"  # OpenSSL treats an empty -policy set as "nothing acceptable"; pass anyPolicy instead
PURPOSE = {"null": "sslserver", "server": "sslserver", "client": "sslclient", "any": "any"}


def openssl_verify(c, d, purpose=None, extra=()):
    cmd = ["openssl", "verify", "-attime", str(c["time"]), "-CAfile", os.path.join(d, "roots.pem")]
    if c["intermediates"]:
        cmd += ["-untrusted", os.path.join(d, "inter.pem")]
    if purpose:
        cmd += ["-purpose", purpose]
    if c["dns_name"]:
        cmd += ["-verify_hostname", c["dns_name"]]
    cmd += list(extra) + [os.path.join(d, "leaf.pem")]
    rc, out = sh(cmd)
    out = out.replace(OUT, "")
    lines = [x for x in out.splitlines() if "depth lookup" in x or x.strip().endswith(": OK")]
    return rc == 0, one(" ; ".join(lines) or out)


def openssl_case(c):
    d = os.path.join(OUT, "cases", c["id"])
    leaf = os.path.join(d, "leaf.pem")
    if c["mode"] == "parse":
        rc, out = sh(["openssl", "x509", "-noout", "-in", leaf])
        return rc == 0, one(out) or "parsed"
    if c["mode"] == "hostname":
        h = c["host"]
        rc, out = sh(["openssl", "x509", "-noout", "-checkhost", h, "-in", leaf])
        hostok = "does match" in out
        msg = "checkhost: " + one(out)
        try:
            ipaddress.ip_address(h.strip("[]"))
            rc2, out2 = sh(["openssl", "x509", "-noout", "-checkip", h.strip("[]"), "-in", leaf])
            ipok = "does match" in out2
            return ipok, msg + " ; checkip: " + one(out2)
        except ValueError:
            return hostok, msg
    if c["probe"] == "O-eku":
        ks = c["key_usages"]
        if ks is None:
            return openssl_verify(c, d, "sslserver")
        if ks == ["client", "server"]:
            a, am = openssl_verify(c, d, "sslserver")
            b, bm = openssl_verify(c, d, "sslclient")
            return "n/a", f"two purposes: sslserver={a} ({am}) ; sslclient={b} ({bm})"
        return openssl_verify(c, d, PURPOSE[ks[0]])
    if c["probe"] == "O-policy2":
        pe = []
        for o in c["policies"] or [PANY_OID]:
            pe += ["-policy", o]
        ok, msg = openssl_verify(c, d, extra=["-policy_check"] + pe)
        ok2, msg2 = openssl_verify(c, d, extra=["-policy_check", "-explicit_policy"] + pe)
        return ok, msg + f" ; +explicit_policy: {ok2}" + ("" if ok2 == ok else f" ({msg2})")
    ok, msg = openssl_verify(c, d)
    if c["probe"] == "O-policy":
        ok2, msg2 = openssl_verify(c, d, extra=["-policy_check"])
        msg += f" ; -policy_check: {ok2} ({msg2})"
    return ok, msg


rows = []
for c in CASES:
    g = GOR[c["id"]]
    gmsg = "ok" if g["ok"] else f"{g['err_type']}" + (f" reason={g['reason']}" if g["reason"] is not None else "") + f": {g['msg']}"
    ook, omsg = openssl_case(c)
    rows.append((c["id"], c["probe"], c["desc"], str(g["ok"]).lower(), gmsg.replace("\t", " "),
                 ook if ook == "n/a" else str(ook).lower(), omsg))
with open(os.path.join(OUT, "verdicts.tsv"), "w") as f:
    f.write("id\tprobe\tdescription\tgo_ok\tgo_reason/msg\topenssl_ok\topenssl_msg\n")
    for r in rows:
        f.write("\t".join(r) + "\n")
dis = [r for r in rows if r[5] != "n/a" and r[3] != r[5]]
print(f"{len(rows)} cases, {len(dis)} Go/OpenSSL disagreements -> {os.path.join(OUT, 'verdicts.tsv')}")


# ================================================================ corpus.bin
CORPUS = os.path.join(MOD, "src", "data", "s2", "corpus.bin")
USAGE_BIT = {"server": 1, "client": 2, "any": 4}


def build_corpus(cases):
    recs = []
    for c in cases:
        if c["mode"] == "parse":
            continue
        d = c["der"]
        ids = c["id"].encode("ascii")
        if c["mode"] == "verify":
            host = (c["dns_name"] or "").encode()
        else:
            host = c["host"].encode()
        mask = 0
        for k in c["key_usages"] or []:
            mask |= USAGE_BIT[k]
        r = bytes([len(ids)]) + ids + bytes([0 if c["mode"] == "verify" else 1]) + struct.pack("<q", c["time"])
        r += bytes([len(host)]) + host + bytes([mask])
        r += bytes([len(c["policies"])])
        for po in c["policies"]:
            pb = oid(po)[2:]
            r += bytes([len(pb)]) + pb
        r += bytes([1 if GOR[c["id"]]["ok"] else 0, len(d["roots"]), len(d["inters"])])
        for der in d["roots"] + d["inters"] + [d["leaf"]]:
            r += struct.pack("<H", len(der)) + der
        recs.append(r)
    return b"X509S2\x00\x02" + struct.pack("<I", len(recs)) + b"".join(recs), len(recs)


_blob, _n = build_corpus(CASES)
if len(_blob) > 600 * 1024:
    keep, seen = [], 0
    eku = [c for c in CASES if c["probe"] == "O-eku"]
    # drop duplicate-heavy O-eku cases down to the 20 most distinct (distinct verdict+usage first)
    _sel, _seen = [], set()
    for c in eku:
        k = (GOR[c["id"]]["ok"], tuple(c["key_usages"] or []))
        if k not in _seen:
            _seen.add(k)
            _sel.append(c["id"])
    for c in eku:
        if len(_sel) >= 20:
            break
        if c["id"] not in _sel:
            _sel.append(c["id"])
    _sel = set(_sel[:20])
    _blob, _n = build_corpus([c for c in CASES if c["probe"] != "O-eku" or c["id"] in _sel])
    print("corpus > 600 KiB: O-eku cases reduced to 20")
os.makedirs(os.path.dirname(CORPUS), exist_ok=True)
with open(CORPUS, "wb") as f:
    f.write(_blob)
print(f"{_n} corpus records, {len(_blob)} bytes -> {CORPUS}")
