# SPDX-License-Identifier: MIT
"""Print "name hex" per recorded TCP case of interop_vectors.zig: the client's
first TLS record (its ClientHello), for ja4_oracle (main.go)."""
import re
import sys

src = open(sys.argv[1]).read()
for m in re.finditer(r'\.name = "([^"]+)",(.*?)\.client = &hx\(\d+, ((?:"[0-9a-f]*"\s*(?:\+\+\s*)?)+)\)', src, re.S):
    name, body, hexes = m.group(1), m.group(2), m.group(3)
    if re.search(r"\.quic = true", body):
        continue
    data = bytes.fromhex("".join(re.findall(r'"([0-9a-f]*)"', hexes)))
    if len(data) < 5 or data[0] != 22:
        continue
    n = int.from_bytes(data[3:5], "big")
    print(name, data[: 5 + n].hex())
