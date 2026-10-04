#!/usr/bin/env python3
"""Recipe for modules/noise/src/testdata/cacophony-subset.json.

Input: snow's tests/vectors/cacophony.txt (github.com/mcginty/snow, the
cacophony vector format for Noise rev 34), fetched e.g. with
  gh api -H 'Accept: application/vnd.github.raw' \
    repos/mcginty/snow/contents/tests/vectors/cacophony.txt > cacophony.txt

Output: the vectors this module runs, copied verbatim (whole JSON objects,
no field changed): every Noise_*_25519_ChaChaPoly_SHA256 vector (all 15
fundamental patterns, the 23 deferred ones and every PSK variant the file
has), plus four patterns (IK, KK1, NNpsk0, XXpsk3) under each of the other
seven 25519 suites (AESGCM x 4 hashes, ChaChaPoly x SHA512/BLAKE2s/BLAKE2b).
The 448 vectors are left out: this module binds no X448 by default.

  python3 tools/extract-vectors.py cacophony.txt > src/testdata/cacophony-subset.json
"""
import json, sys

src = json.load(open(sys.argv[1]))["vectors"]
extra_patterns = {"IK", "KK1", "NNpsk0", "XXpsk3"}
out = []
for v in src:
    _, pattern, dh, cipher, hash_ = v["protocol_name"].split("_")
    if dh != "25519":
        continue
    if (cipher, hash_) == ("ChaChaPoly", "SHA256") or pattern in extra_patterns:
        out.append(v)
json.dump({"vectors": out}, sys.stdout, indent=1)
sys.stdout.write("\n")
