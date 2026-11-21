# Recipe for src/testdata/blake3_vectors.tsv: the official BLAKE3 test vectors
# (https://github.com/BLAKE3-team/BLAKE3, test_vectors/test_vectors.json at the
# commit named in the file's first line; CC0-1.0 / Apache-2.0), every one of
# its 35 input lengths, as `kind<TAB>input_len<TAB>131-byte hex`.
#
#     python3 -I blake3_vectors.py test_vectors.json > ../src/testdata/blake3_vectors.tsv
#
# The input of a case is the repeating byte pattern 0, 1, ... 250, 0, 1, ...
import json
import sys

ORIGIN = "https://raw.githubusercontent.com/BLAKE3-team/BLAKE3/f55849f89cd85083c1c9daa2c5de20766f309c00/test_vectors/test_vectors.json"
doc = json.load(open(sys.argv[1]))
print(f"# origin: {ORIGIN} (CC0-1.0 / Apache-2.0)")
print(f"# key={doc['key']} context={doc['context_string']}")
for kind in ("hash", "keyed_hash", "derive_key"):
    for case in doc["cases"]:
        print(f"{kind}\t{case['input_len']}\t{case[kind]}")
