#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regenerate src/testdata/golden.tsv and src/testdata/sums.txt.

The recipe behind the committed goldens (CONVENTIONS section 9). Run from the
module directory:  python3 tools/gen_golden.py

Messages are generated, not downloaded: byte i of a message is (i*31+7) & 255.
golden.tsv rows: <algo> <TAB> <len> <TAB> <hex>, digests from Python hashlib
(OpenSSL) -- SHA-2, SHA-3, BLAKE2b-256, and SHAKE128/256 with 100 output bytes.
sums.txt is the output of GNU coreutils sha256sum / sha512sum / b2sum (plain,
--binary, --tag) over files whose name ends in the message length, including
names that need the backslash escape; each block starts with a '# algo=' comment line. The Zig test regenerates the contents.
"""
import hashlib, os, subprocess, tempfile

LENS = [0, 1, 3, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 200, 255, 256, 1000, 4096]


def msg(n):
    return bytes((i * 31 + 7) & 255 for i in range(n))


here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "testdata")
os.makedirs(here, exist_ok=True)

rows = []
for n in LENS:
    m = msg(n)
    for a in ["sha256", "sha224", "sha384", "sha512", "sha512_256", "sha3_256", "sha3_512"]:
        rows.append((a, n, hashlib.new(a, m).hexdigest()))
    rows.append(("blake2b256", n, hashlib.blake2b(m, digest_size=32).hexdigest()))
    rows.append(("shake128", n, hashlib.shake_128(m).hexdigest(100)))
    rows.append(("shake256", n, hashlib.shake_256(m).hexdigest(100)))
with open(os.path.join(here, "golden.tsv"), "w") as f:
    for a, n, h in rows:
        f.write(f"{a}\t{n}\t{h}\n")

names = ["f0", "f1", "f200", "a b100", "back\\slash64", "new\nline33", "star*65", "tab\there129", "(paren) = x7"]
out = []
with tempfile.TemporaryDirectory() as d:
    for nm in names:
        with open(os.path.join(d, nm), "wb") as f:
            f.write(msg(int(nm[len(nm.rstrip("0123456789")):])))
    def run(cmd, algo):
        r = subprocess.run(cmd + names, cwd=d, capture_output=True, check=True)
        return "# algo=" + algo + " (" + " ".join(cmd) + ")\n" + r.stdout.decode()
    out.append(run(["sha256sum"], "sha256"))
    out.append(run(["sha256sum", "--binary"], "sha256"))
    out.append(run(["sha256sum", "--tag"], "sha256"))
    out.append(run(["sha512sum"], "sha512"))
    out.append(run(["sha512sum", "--tag"], "sha512"))
    out.append(run(["b2sum", "-l", "256", "--tag"], "blake2b256"))
    out.append(run(["b2sum", "-l", "256"], "blake2b256"))
with open(os.path.join(here, "sums.txt"), "w") as f:
    f.write("".join(out))
