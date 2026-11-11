#!/usr/bin/env python3
"""Every place that names the Zig version must name the same one.

A Zig bump touches build.zig.zon, the CI workflows' setup-zig `version:` and
the `# zig:` header of every count-insns baseline (modules/*/tools/count.tsv).
count-insns refuses a baseline taken under another zig, but only in the full
CI's count lane: the 0.17.1 branch lost a full run to exactly that (CI
42929122017, 2026-11-11). Comparing the strings needs no build, so it runs
in checks-fast.

usage: scripts/checks/check-toolchain-pins.py        (exit 1 on a mismatch)
"""
import glob
import os
import re
import sys

os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

zon = open("build.zig.zon", encoding="utf-8").read()
m = re.search(r'\.minimum_zig_version\s*=\s*"([^"]+)"', zon)
if not m:
    sys.exit("check-toolchain-pins: no minimum_zig_version in build.zig.zon")
want = m.group(1)

bad = []
for wf in sorted(glob.glob(".github/workflows/*.yml")):
    text = open(wf, encoding="utf-8").read()
    # setup-zig's `with: version:` -- the only `version: <x.y.z>` lines there.
    for n, line in enumerate(text.splitlines(), 1):
        v = re.match(r"\s+version:\s*['\"]?(\d+\.\d+\.\d+)['\"]?\s*$", line)
        if v and v.group(1) != want:
            bad.append(f"{wf}:{n}: setup-zig version {v.group(1)}")

for tsv in sorted(glob.glob("modules/*/tools/count.tsv")):
    for line in open(tsv, encoding="utf-8"):
        if not line.startswith("#"):
            break
        v = re.match(r"#\s*zig:\s*(\S+)", line)
        if v and v.group(1) != want:
            bad.append(f"{tsv}: baseline taken under zig {v.group(1)} "
                       "(re-measure: hw run -- scripts/count-insns --rewrite <m>, "
                       "or re-pin from the full CI count lane)")

if bad:
    print(f"check-toolchain-pins: build.zig.zon says zig {want}, but:", file=sys.stderr)
    for b in bad:
        print("  " + b, file=sys.stderr)
    sys.exit(1)
print(f"check-toolchain-pins: zig {want} everywhere")
