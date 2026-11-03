#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regenerate src/testdata/golden.tsv and src/testdata/sums.txt.

The recipe behind the committed goldens (CONVENTIONS section 9). Run from the
module directory:  python3 tools/gen_golden.py

Messages are generated, not downloaded: byte i of a message is (i*31+7) & 255.
golden.tsv rows: <algo> <TAB> <len> <TAB> <hex>, digests from Python hashlib
(OpenSSL) -- SHA-2, SHA-3, BLAKE2b-256, and SHAKE128/256 with 100 output bytes.
sums.txt is the output of GNU coreutils 9.x (gnusha256sum...) and uutils coreutils (sha256sum...) -- each block's comment line names the tool and version -- (plain,
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

names = ["f0", "f1", "f200", "a b100", "back\\slash64", "new\nline33", "star*65", "tab\there129", "(paren) = x7", "carriage\rret11"]
out = []
with tempfile.TemporaryDirectory() as d:
    for nm in names:
        with open(os.path.join(d, nm), "wb") as f:
            f.write(msg(int(nm[len(nm.rstrip("0123456789")):])))
    def run(cmd, algo, tool):
        r = subprocess.run(cmd + names, cwd=d, capture_output=True, check=True)
        return "# algo=" + algo + " (" + tool + ": " + " ".join(cmd) + ")\n" + r.stdout.decode()
    # Two implementations on this host: GNU coreutils 9.x (binaries installed as gnu*)
    # and uutils coreutils (the plain names on this Ubuntu). Both are checked.
    for tool, pre in (("GNU coreutils", "gnu"), ("uutils coreutils", "")):
        v = subprocess.run([pre + "sha256sum", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
        tool = tool + " [" + v + "]"
        out.append(run([pre + "sha256sum"], "sha256", tool))
        out.append(run([pre + "sha256sum", "--binary"], "sha256", tool))
        out.append(run([pre + "sha256sum", "--tag"], "sha256", tool))
        out.append(run([pre + "sha512sum"], "sha512", tool))
        out.append(run([pre + "sha512sum", "--tag"], "sha512", tool))
        out.append(run([pre + "b2sum", "-l", "256", "--tag"], "blake2b256", tool))
        out.append(run([pre + "b2sum", "-l", "256"], "blake2b256", tool))
with open(os.path.join(here, "sums.txt"), "w") as f:
    f.write("".join(out))

# BLAKE3: a slice of the official test vectors (needs network). Origin:
# BLAKE3-team/BLAKE3, test_vectors/test_vectors.json at the pinned commit below.
# Licence: CC0-1.0 (LICENSE_CC0), alternatively Apache-2.0 (LICENSE_A2) per its
# README "Licenses" section -- both MIT-compatible. Input byte i = i % 251; key
# "whats the Elvish word for friend"; derive-key context "BLAKE3 2019-12-27
# 16:29:52 test vectors context"; outputs are 131 bytes.
import json, urllib.request

B3_COMMIT = "f55849f89cd85083c1c9daa2c5de20766f309c00"
B3_URL = "https://raw.githubusercontent.com/BLAKE3-team/BLAKE3/" + B3_COMMIT + "/test_vectors/test_vectors.json"
B3_LENS = [0, 1, 63, 64, 65, 1024, 1025, 8193]
tv = json.load(urllib.request.urlopen(B3_URL, timeout=30))
by_len = {c["input_len"]: c for c in tv["cases"]}
with open(os.path.join(here, "blake3_vectors.tsv"), "w") as f:
    f.write("# origin: " + B3_URL + " (CC0-1.0 / Apache-2.0)\n")
    f.write("# key=" + tv["key"] + " context=" + tv["context_string"] + "\n")
    for n in B3_LENS:
        c = by_len[n]
        for kind in ("hash", "keyed_hash", "derive_key"):
            f.write(f"{kind}\t{n}\t{c[kind]}\n")
