#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Differential oracle for the writer: libxml2 (via lxml, public API only)
reads the ORIGINAL document and the document this module WROTE from it, and
their exclusive-free C14N 1.0 forms must be equal. Inputs: the accepted
documents of the own well-formedness vectors (`gen_wf_vectors.py --files`) plus
the core vectors' accepted documents.

    python3 writer_oracle.py <writer_oracle binary> <empty out dir>
"""
import os, re, subprocess, sys
from lxml import etree

here = os.path.dirname(os.path.abspath(__file__))
exe, out = sys.argv[1], sys.argv[2]
wfdir = os.path.join(out, "wf")
subprocess.run([sys.executable, os.path.join(here, "gen_wf_vectors.py"), "--files", wfdir], check=True)
files = []
for line in open(os.path.join(wfdir, "index.tsv")):
    cid, mode, verdict, _ = line.rstrip("\n").split("\t")
    if verdict == "OK":
        files.append(os.path.join(wfdir, cid + ".xml"))
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
        print("DIFFER", os.path.relpath(path, out))
print(f"same={same} differ={differ} skipped={skipped} of {len(inputs)}")
