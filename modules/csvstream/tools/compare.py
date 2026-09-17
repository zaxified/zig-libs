#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# Three-way comparison for the csvstream differential oracle
# (CONVENTIONS.md §9): holds Python's `csv.reader` (oracle.txt, from
# `gen.py`), Go's `encoding/csv` (the `go/` oracle binary) and this module's
# own `LineIterator`/`splitFields` (the `dump.zig` binary) against each other
# over the same hostile vectors, and reports where they agree and where they
# don't.
#
# Go's reader only ever answers the FIRST record of a multi-record input
# (`csv.Reader.Read()` reads one record); Python's `csv.reader` and this
# module's `LineIterator` can both see "more than one record" (on '\r'/'\n'
# for Python, on '\n' only for this module -- a documented, deliberate
# deviation, SPEC.md "Deliberate RFC 4180 deviation"). So the comparison is
# in two parts: FIRST-RECORD fields (all three, always comparable) and
# MULTI-ROW detection (Python vs this module only).
#
# WHAT IT NEEDS: the two binaries built per gen.py/go/main.go/dump.zig's own
# headers, and a `oracle.txt`/`zz_vectors.hex` pair from `gen.py`, in the
# same directory.
#
# Run (from the directory holding zz_vectors.hex + oracle.txt):
#   GOBIN=<path-to-go-oracle> ZIGBIN=<path-to-dump> python3 compare.py
import os, subprocess, sys

workdir = sys.argv[1] if len(sys.argv) > 1 else "."
gobin = os.environ["GOBIN"]
zigbin = os.environ["ZIGBIN"]

with open(os.path.join(workdir, "zz_vectors.hex")) as f:
    # NOT `if l.strip()` -- the '' vector hex-encodes to an EMPTY line, which
    # must still occupy a row so hexvecs/py_lines/go_lines/zig_lines stay
    # aligned by index.
    hexvecs = f.read().split("\n")
    if hexvecs and hexvecs[-1] == "":
        hexvecs.pop()
with open(os.path.join(workdir, "oracle.txt")) as f:
    py_lines = [l.rstrip("\n") for l in f]

stdin_bytes = ("\n".join(hexvecs) + "\n").encode()
go_out = subprocess.run([gobin], input=stdin_bytes, capture_output=True, check=True).stdout
zig_out = subprocess.run([zigbin], input=stdin_bytes, capture_output=True, check=True).stdout
go_lines = go_out.decode().splitlines()
zig_lines = zig_out.decode().splitlines()

n = len(hexvecs)
assert len(py_lines) == n, f"oracle.txt has {len(py_lines)} lines, expected {n}"
assert len(go_lines) == n, f"go oracle produced {len(go_lines)} lines, expected {n}"
assert len(zig_lines) == n, f"zig dump produced {len(zig_lines)} lines, expected {n}"


def parse_zig(line):
    multi = line.startswith("MULTI:")
    if multi:
        line = line[len("MULTI:"):]
    if line == "ERR":
        return multi, None
    return multi, line  # "N:f1|f2|..."


def parse_go(line):
    if line == "ERR":
        return None
    return line  # "N:f1|f2|..."


def py_first_record(line):
    if line == "MULTIROW":
        return True, None
    return False, line  # fields string, possibly empty


three_agree = 0
py_zig_first_agree = 0
zig_go_agree = 0
py_zig_multi_agree = 0
mismatches = []

for i in range(n):
    py_multi, py_fields = py_first_record(py_lines[i])
    zig_multi, zig_fields = parse_zig(zig_lines[i])
    go_fields = parse_go(go_lines[i])

    if py_multi == zig_multi:
        py_zig_multi_agree += 1

    # Go has no MULTIROW state; compare its fields against the first record's
    # fields from Python (when Python itself was single-row) and from this
    # module.
    zig_go_match = zig_fields is not None and go_fields is not None and zig_fields == go_fields
    if zig_go_match:
        zig_go_agree += 1

    if not py_multi:
        # zig_fields is "N:f1|f2|..."; compare only the field part to Python's
        # bare "f1|f2|...".
        zig_field_part = zig_fields.split(":", 1)[1] if zig_fields and ":" in zig_fields else None
        py_match = zig_field_part is not None and zig_field_part == py_fields
        if py_match:
            py_zig_first_agree += 1
        if py_match and zig_go_match:
            three_agree += 1
        if not (py_match and zig_go_match):
            mismatches.append((hexvecs[i], py_lines[i], go_lines[i], zig_lines[i]))
    else:
        mismatches.append((hexvecs[i], py_lines[i], go_lines[i], zig_lines[i]))

print(f"{n} vectors")
print(f"python multi-row flag == this module's multi-record flag: {py_zig_multi_agree}/{n}")
print(f"this module's first record == Go's first record (always comparable): {zig_go_agree}/{n}")
print(f"Python single-row fields == this module's first record: {py_zig_first_agree}/{n}")
print(f"all three agree (single-row cases only): {three_agree}/{n}")
print(f"rows not in the three-way-agree bucket: {len(mismatches)}")
if "-v" in sys.argv:
    for hexvec, py, go, zig in mismatches:
        print(f"  hex={hexvec!r} py={py!r} go={go!r} zig={zig!r}")
