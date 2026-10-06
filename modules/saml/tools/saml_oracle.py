#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Differential oracle for saml's SP metadata and AuthnRequest builders.

NEEDS: python3 with python3-saml 1.16.0 (MIT) and its dependencies lxml and
xmlsec (the PyPI wheels bundle libxml2 / libxmlsec1). Set up in a throwaway
venv OUTSIDE the repository, e.g.:

    python3 -m venv /tmp/saml-oracle
    /tmp/saml-oracle/bin/pip install python3-saml==1.16.0 lxml xmlsec

RUN (from the repository root):

    /tmp/saml-oracle/bin/python -I modules/saml/tools/saml_oracle.py \
        modules/saml/src/test_metadata.zig

READS the pinned fixtures out of `test_metadata.zig` (every `pub const
<name>_xml` Zig multiline literal, plus `sp_cert_der_b64`) — the same bytes the
module's tests assert `buildSpMetadata` / `buildAuthnRequest` emit — and checks
them against foreign implementations only:

  1. each `*_md_xml` validates against OASIS `saml-schema-metadata-2.0.xsd`
     and each `authn_request_*_xml` against `saml-schema-protocol-2.0.xsd`
     (the schema copies python3-saml bundles; lxml/libxml2 XML Schema), and
     python3-saml's own `OneLogin_Saml2_XML.validate_xml` accepts it;
  2. `signed_md_xml` verifies under xmlsec1 (python3-saml's
     `validate_metadata_sign`, with the certificate from `sp_cert_der_b64`),
     and the same document with one signed value changed does NOT;
  3. structure: python3-saml's own `OneLogin_Saml2_Metadata.builder` +
     `add_x509_key_descriptors` is run for equivalent settings, and every
     (element path, attribute name) it emits must also occur in
     `full_md_xml` (ours is a superset: more endpoints, contacts, ...).

PRODUCES: a report on stdout, exit status 0 iff every check passed. Nothing is
written. Kept per CONVENTIONS §9 (a differential oracle that speaks only the
wire format); last run 2026-10-06, all checks passed.
"""

import base64
import re
import sys

from lxml import etree
from onelogin.saml2.metadata import OneLogin_Saml2_Metadata
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML

FIXTURE = re.compile(r"pub const (\w+) =\n((?:[ \t]*\\\\.*\n)+)[ \t]*;")
STRING = re.compile(r'pub const sp_cert_der_b64 = "([A-Za-z0-9+/=]+)";')


def load(path):
    src = open(path, encoding="utf-8").read()
    fixtures = {}
    for m in FIXTURE.finditer(src):
        lines = [re.sub(r"^[ \t]*\\\\", "", ln) for ln in m.group(2).splitlines()]
        fixtures[m.group(1)] = "\n".join(lines)
    cert = STRING.search(src).group(1)
    return fixtures, cert


def structure(root):
    """Set of (path, attribute) pairs; path uses {ns}local names."""
    out = set()

    def walk(el, prefix):
        if not isinstance(el.tag, str):
            return
        path = prefix + "/" + el.tag
        out.add((path, None))
        for a in el.attrib:
            out.add((path, a))
        for c in el:
            walk(c, path)

    walk(root, "")
    return out


def main():
    fixtures, cert_b64 = load(sys.argv[1])
    cert_pem = OneLogin_Saml2_Utils.format_cert(cert_b64)
    failures = 0

    def check(ok, what):
        nonlocal failures
        print(("PASS " if ok else "FAIL ") + what)
        if not ok:
            failures += 1

    md = {k: v for k, v in fixtures.items() if k.endswith("_md_xml")}
    rq = {k: v for k, v in fixtures.items() if k.startswith("authn_request_")}
    check(len(md) == 3 and len(rq) == 2, f"fixtures found: {sorted(fixtures)}")

    for name, doc in sorted(md.items()):
        res = OneLogin_Saml2_XML.validate_xml(doc.encode(), "saml-schema-metadata-2.0.xsd", debug=True)
        check(not isinstance(res, str), f"{name}: saml-schema-metadata-2.0.xsd ({len(doc)} bytes)")
    for name, doc in sorted(rq.items()):
        res = OneLogin_Saml2_XML.validate_xml(doc.encode(), "saml-schema-protocol-2.0.xsd", debug=True)
        check(not isinstance(res, str), f"{name}: saml-schema-protocol-2.0.xsd ({len(doc)} bytes)")

    signed = md["signed_md_xml"]
    try:
        ok = OneLogin_Saml2_Utils.validate_metadata_sign(signed.encode(), cert=cert_pem) is True
    except Exception as e:  # noqa: BLE001 - report any refusal
        print("   xmlsec:", e)
        ok = False
    check(ok, "signed_md_xml: enveloped signature verifies under xmlsec1")
    tampered = signed.replace('Location="https://sp.example.org/acs"', 'Location="https://evil.example/acs"', 1)
    assert tampered != signed
    try:
        refused = not OneLogin_Saml2_Utils.validate_metadata_sign(tampered.encode(), cert=cert_pem)
    except Exception:  # noqa: BLE001 - a refusal is what we want
        refused = True
    check(refused, "signed_md_xml with one signed value changed: refused by xmlsec1")

    # python3-saml's own SP metadata for equivalent settings.
    sp = {
        "entityId": "https://sp.example.org/metadata?tenant=a&v=2",
        "assertionConsumerService": {
            "url": "https://sp.example.org/acs",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        },
        "singleLogoutService": {
            "url": "https://sp.example.org/slo",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        },
        "NameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        "attributeConsumingService": {
            "serviceName": "Example SP",
            "serviceDescription": "Staff portal",
            "requestedAttributes": [
                {"name": "urn:oid:0.9.2342.19200300.100.1.3", "nameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "friendlyName": "mail", "isRequired": True},
            ],
        },
    }
    theirs = OneLogin_Saml2_Metadata.builder(
        sp.copy(), authnsign=True, wsign=True, valid_until="2030-01-01T00:00:00Z", cache_duration="PT604800S",
        contacts={"technical": {"givenName": "Ops", "emailAddress": "ops@example.org"}},
        organization={"en": {"name": "Example", "displayname": "Example", "url": "https://example.org/"}},
    )
    theirs = OneLogin_Saml2_Metadata.add_x509_key_descriptors(theirs.replace("&", "&amp;"), cert_b64)
    t_root = etree.fromstring(theirs.encode() if isinstance(theirs, str) else theirs)
    o_root = etree.fromstring(md["full_md_xml"].encode())
    missing = structure(t_root) - structure(o_root)
    for m in sorted(missing, key=str):
        print("   python3-saml emits, ours lacks:", m)
    check(not missing, "full_md_xml structure is a superset of python3-saml's builder output")

    print(f"{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
