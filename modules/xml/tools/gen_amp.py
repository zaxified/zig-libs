#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate the amplification / complexity corpus (21 documents, ~12 MB).

WHY THIS EXISTS: these are the inputs behind the audit's memory and complexity
numbers -- the input:live-bytes ratio that found F2 (the documented worst case
was understated 2.3x), the flat/attribute/namespace shapes that show whether a
scan is linear or quadratic, and `cap.xml`, which sits exactly at
`Options.max_elements`.

⚠ `cap.xml` alone is ~9 MB and `flat_4096k.xml` ~4 MB. Write them under
`.zig-cache/`, never `/tmp` -- tmpfs is RAM.

WHAT IT PRODUCES: `<out>/amp/`, 22 files.

    modules/xml/tools/gen_amp.py [outdir]     # default: .zig-cache/xml-corpus
"""
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
repo = os.path.abspath(os.path.join(here, "..", "..", ".."))
out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(repo, ".zig-cache", "xml-corpus")
d = os.path.join(out, "amp")
os.makedirs(d, exist_ok=True)


def w(n, s):
    with open(os.path.join(d, n), "w") as f:
        f.write(s)


# Flat element storms: cost is in node construction, not scanning.
for kb in (16, 64, 256, 1024, 4096):
    w(f'flat_{kb}k.xml', '<r>' + '<a/>' * (kb * 1024 // 4) + '</r>')

# Exactly at the default max_elements cap -- the boundary, not past it.
w('cap.xml', '<r>' + '<a/>' * 1048575 + '</r>')

# Text-heavy: the other end, where scanning dominates.
for kb in (64, 256, 1024):
    w(f'text_{kb}k.xml', '<r>' + 'x' * (kb * 1024) + '</r>')

# Attribute and namespace-declaration storms on ONE element: this is the shape
# that made the 2026-08 quadratic duplicate-detection finding visible, and the
# shape `inScopeNamespaces` was quadratic in (audit F1).
for k in (1024, 2048, 4096):
    w(f'attrk_{k}.xml', '<r ' + ' '.join(f'a{i}="1"' for i in range(k)) + '/>')
    w(f'nsk_{k}.xml', '<r ' + ' '.join(f'xmlns:p{i}="urn:{i}"' for i in range(k)) + '/>')

# A SAML-shaped document: the realistic case the throughput numbers quote.
# ⚠ Reproduced from the audit generator verbatim (one `role` attribute per
# assertion, sizes 1/200/2000) -- an earlier draft of this file invented a
# different assertion shape, which would have made every quoted throughput
# number incomparable with the record.
head = ('<?xml version="1.0" encoding="UTF-8"?>\n'
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="R1" Version="2.0" '
        'IssueInstant="2026-09-05T00:00:00Z"><saml:Issuer>urn:idp</saml:Issuer>')
body = ('<saml:Assertion ID="A{i}" Version="2.0"><saml:Subject>'
        '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
        'u{i}@example.test</saml:NameID></saml:Subject><saml:AttributeStatement>'
        '<saml:Attribute Name="role"><saml:AttributeValue>user</saml:AttributeValue>'
        '</saml:Attribute></saml:AttributeStatement></saml:Assertion>')
for n_assert in (1, 200, 2000):
    w(f'saml_{n_assert}.xml', head + ''.join(body.format(i=i) for i in range(n_assert)) + '</samlp:Response>')

# ── four documents the audit left with NO generator ──────────────────────────
# They existed only as files in the droppable cache. Reproduced here from the
# artefacts themselves (measured, not guessed), and NAMED BY WHAT THEY ARE:
#
# ⚠ The audit called these `attrs_16k` / `attrs_64k` / `attrs_256k`, as though
# labelled by byte size. They are not: `attrs_16k` is 22294 B with 2340
# attributes, `attrs_64k` is 38894 B with 4000 -- and `attrs_256k` was
# BYTE-IDENTICAL to `attrs_64k` (verified with cmp). One document under two
# names, the second promising a size it never had. Any figure quoted against
# "attrs_256k" was measured on the 64k document.
for k in (2340, 4000):
    w(f'attrs_{k}.xml', '<r ' + ' '.join(f'a{i}="1"' for i in range(k)) + '/>')

# The billion-laughs / quadratic-blowup document behind the record's
# "ratio < 1" anchor: 100037 B in, ~1400 B live. The entity body is exactly
# 100000 characters -- measured from the original file, byte for byte.
w('ent_ignore.xml', '<!DOCTYPE b [<!ENTITY a "' + 'A' * 100000 + '">]><b>x</b>')

n = len(os.listdir(d))
total = sum(os.path.getsize(os.path.join(d, f)) for f in os.listdir(d))
print(f"wrote {n} documents to {d} ({total} B)")
if n != 21:
    raise SystemExit(f"expected 21 documents, wrote {n} -- the corpus is not what the measurements expect")
