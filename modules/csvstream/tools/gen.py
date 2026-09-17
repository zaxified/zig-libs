#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# Data recipe for the csvstream differential oracle (CONVENTIONS.md §9): writes
# ~300 hostile/edge-case CSV strings and Python's own `csv` module's verdict on
# each, as inputs `go/main.go` (Go `encoding/csv`) and `dump.zig` (this
# module's own public API) are then run against, so a mismatch between three
# independently written CSV readers is caught rather than merely two.
#
# WHAT IT NEEDS: Python 3 stdlib only (`csv`, `io`, `itertools`) -- nothing
# foreign to fetch or install.
# WHAT IT PRODUCES (in the current directory -- run it from a scratch dir,
# e.g. `~/workspace/zig-libs/.zig-cache/o1-csvstream/`):
#   zz_vectors.hex  -- one hex-encoded input vector per line
#   oracle.txt      -- Python's verdict per vector: `MULTIROW` if csv.reader
#                       produced more than one row, else the row's fields,
#                       hex-encoded and '|'-joined (blank line for zero fields)
#   vectors.txt     -- the same vectors as Python `repr()`, for a human to read
#
# Run:
#   python3 gen.py
#
# Then compare all three readers with `compare.py` in this directory.
import csv, io, itertools, sys

vectors = [
 'a,b,c',
 'a,b,',
 ',a',
 'a,,b',
 '"a,b",c',
 '"a""b"',
 '""',
 '"",""',
 'a,"b"',
 '"a"b',            # junk after closing quote
 '"a"b"c',
 '"a"",b",c',
 'a"b,c',           # quote in middle of unquoted field
 '"unterminated',
 '"unterminated,x',
 'a,"unterminated',
 '"a""',            # ends with escaped quote at EOF
 '"',               # lone quote
 '""""',
 '"""',
 'a,b"',
 '"a" ,b',          # space between closing quote and delimiter
 ' "a",b',          # leading space then quote
 '"a" b,c',
 'a,b,"c"',
 '"",a',
 ',,',
 ',',
 '',
 'a',
 '"a",',
 '"a",,',
 '"a,b"c,d',
 'x"y"z',
 '"\t",b',
 '"a\rb",c',
 'a\rb,c',
]
# also a few generated exhaustively over the alphabet {a , "} up to length 4
alpha = ['a', ',', '"']
for n in range(1,5):
    for t in itertools.product(alpha, repeat=n):
        vectors.append(''.join(t))

seen=set(); vs=[]
for v in vectors:
    if v in seen: continue
    seen.add(v); vs.append(v)

with open('zz_vectors.hex','w') as f:
    for v in vs:
        f.write(v.encode('utf-8').hex()+'\n')

with open('oracle.txt','w') as f:
    for v in vs:
        rows = list(csv.reader(io.StringIO(v, newline='')))
        if len(rows) == 0:
            fields = []
        elif len(rows) == 1:
            fields = rows[0]
        else:
            f.write('MULTIROW\n'); continue
        f.write('|'.join(x.encode('utf-8').hex() for x in fields)+'\n')

with open('vectors.txt','w') as f:
    for v in vs:
        f.write(repr(v)+'\n')
print(len(vs),"vectors", file=sys.stderr)
