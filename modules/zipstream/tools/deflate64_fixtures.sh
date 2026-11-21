#!/usr/bin/env bash
# Re-takes src/testdata/deflate64.zip: 7-Zip (p7zip) writes Deflate64 (ZIP method 9) archives;
# src/deflate64_test.zig decodes them. Needs 7z and python3.
#
#   modules/zipstream/tools/deflate64_fixtures.sh      (from the repository root)
#
# far.bin repeats a 40000-byte block (a distance above 32768, which only Deflate64 can code)
# and holds 70000 zeros (a match longer than Deflate's 258: length code 285 with 16 extra
# bits); its bytes come from a 31-bit LCG the test regenerates. text.txt and small.txt are
# dynamic- and fixed-Huffman blocks; rand.bin and tiny.txt come out stored (7-Zip's choice).
set -euo pipefail
root=$(pwd)
out=modules/zipstream/src/testdata
work=$root/.zig-cache/zipstream-deflate64
mkdir -p "$work" "$out"
cd "$work"
for f in *; do [ -f "$f" ] && rm "$f"; done
python3 -I - <<'PY'
def lcg(n, x=12345):
    out = bytearray()
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0x7fffffff
        out.append((x >> 16) & 0xff)
    return bytes(out)
a = lcg(40000)
open('far.bin', 'wb').write(a + a + bytes(70000) + a[:5000] + b'tail\n')
open('text.txt', 'wb').write(b''.join(b'line %d: Pr\xc5\x99\xc3\xad\xc5\xa1ern\xc4\x9b \xc5\xbelu\xc5\xa5ou\xc4\x8dk\xc3\xbd k\xc5\xaf\xc5\x88\n' % i for i in range(400)))
open('small.txt', 'wb').write(b'abcabcabcabcabcabc hello hello hello\n')
open('tiny.txt', 'wb').write(b'tiny\n')
open('rand.bin', 'wb').write(lcg(3000, 99))
PY
touch -d @1700000000 far.bin text.txt small.txt tiny.txt rand.bin
7z a -tzip -mm=Deflate64 -mx9 -mtc=off -mta=off d64.zip far.bin text.txt small.txt tiny.txt rand.bin >/dev/null
7z t d64.zip | tail -3
cp d64.zip "$root/$out/deflate64.zip"
