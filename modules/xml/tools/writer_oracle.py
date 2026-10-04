#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Differential oracle for the writer: libxml2 (via lxml, public API only)
reads the ORIGINAL document and the document this module WROTE from it, and
their exclusive-free C14N 1.0 forms must be equal. Inputs: the vendored
xmlconf slice plus the core vectors' accepted documents.

    python3 writer_oracle.py <writer_oracle binary> <empty out dir>
"""
import glob, os, re, subprocess, sys
from lxml import etree

here = os.path.dirname(os.path.abspath(__file__))
exe, out = sys.argv[1], sys.argv[2]
files = sorted(glob.glob(os.path.join(here, "..", "src", "testdata", "xmlconf", "**", "*.xml"), recursive=True))
vec = open(os.path.join(here, "..", "src", "core_vectors.zig")).read()
extra = []
for m in re.finditer(r'\.input = "([0-9a-f]*)", \.entities = (true|false), \.lxml = "', vec):
    p = os.path.join(out, "core-%d.in" % len(extra))
    open(p, "wb").write(bytes.fromhex(m.group(1)))
    extra.append(p)
inputs = files + extra
subprocess.run([exe, out] + inputs, check=True)
parser = etree.XMLParser(resolve_entities=True, no_network=True, load_dtd=False)
same = differ = skipped = 0
for n, path in enumerate(inputs):
    ours = os.path.join(out, "%d.xml" % n)
    if not os.path.exists(ours):
        skipped += 1
        continue
    try:
        a = etree.tostring(etree.parse(path, parser), method="c14n")
    except etree.XMLSyntaxError:
        skipped += 1
        continue
    b = etree.tostring(etree.parse(ours, parser), method="c14n")
    if a == b:
        same += 1
    else:
        differ += 1
        print("DIFFER", os.path.relpath(path, here))
print(f"same={same} differ={differ} skipped={skipped} of {len(inputs)}")
