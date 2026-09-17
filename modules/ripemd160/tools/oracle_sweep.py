#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare the module's sweep against TWO independent external oracles.

    modules/ripemd160/tools/oracle_sweep.py <sweep-output> <workdir>

WHY THIS EXISTS: `src/root.zig`'s KATs are individual digests. This is where
those numbers can be re-derived -- every length 0..1024 against Python
`hashlib` AND `openssl`, rather than a handful of lengths against a table
somebody typed in. No test in `src/` compares even one length to a foreign
implementation; the tests compare the module to constants, and constants
inherit whatever mistake produced them.

WHY TWO ORACLES AND NOT ONE: `hashlib`'s ripemd160 is itself provided by
OpenSSL on most builds, so "hashlib agrees" and "openssl agrees" can be the
same witness wearing two hats. They are kept separate and counted separately
so that a single shared backend shows up as two suspiciously identical
answers rather than as independent confirmation.

WHAT IT NEEDS:
  - Python `hashlib` with ripemd160 (OpenSSL's legacy provider on OpenSSL 3;
    measured working here on OpenSSL 3.5.5)
  - the `openssl` CLI
  Measured 2026-09-17: both present, both return 8eb208f7... for "abc".

WHAT IT PRODUCES: per-oracle mismatch counts, and the number of digests each
oracle actually returned -- because an oracle that silently returned NOTHING
would otherwise look like "0 mismatches". ⚠ A comparison count of zero is a
statement about this script, not about the module.

⚠ workdir must live under `.zig-cache/`, never `/tmp` -- it writes 1025 files.
"""
import hashlib
import os
import subprocess
import sys

if len(sys.argv) < 3:
    print(__doc__)
    sys.exit(2)

zig_file = sys.argv[1]
workdir = sys.argv[2]          # must be under .zig-cache, never /tmp

msg = bytes((i * 7 + 13) % 256 for i in range(4096))

rows = {}
for line in open(zig_file):
    n, d, h160 = line.split()
    rows[int(n)] = (d, h160)

if not rows:
    print("⛔ the sweep file is EMPTY -- nothing was compared.", file=sys.stderr)
    sys.exit(2)

# ---- oracle 1: python hashlib -------------------------------------------
try:
    hashlib.new('ripemd160')
except ValueError as e:
    print(f"⛔ hashlib has no ripemd160 ({e}). On OpenSSL 3 this lives in the "
          f"legacy provider. NOT a statement about the module.", file=sys.stderr)
    sys.exit(2)

py_bad = []
for n, (d, h160) in rows.items():
    m = msg[:n]
    if hashlib.new('ripemd160', m).hexdigest() != d:
        py_bad.append(('rmd', n))
    if hashlib.new('ripemd160', hashlib.sha256(m).digest()).hexdigest() != h160:
        py_bad.append(('h160', n))

# ---- oracle 2: openssl, batched over message files ----------------------
os.makedirs(workdir, exist_ok=True)
names = []
for n in rows:
    p = os.path.join(workdir, "m%04d.bin" % n)
    with open(p, 'wb') as f:
        f.write(msg[:n])
    names.append(p)

ssl_bad = []
CH = 400
ssl = {}
for i in range(0, len(names), CH):
    out = subprocess.run(['openssl', 'dgst', '-r', '-ripemd160'] + names[i:i + CH],
                         capture_output=True, text=True)
    if out.returncode != 0:
        print("OPENSSL FAILED:", out.stderr[:400], file=sys.stderr)
        sys.exit(2)
    for ln in out.stdout.splitlines():
        h, f = ln.split(' *')
        ssl[int(os.path.basename(f.strip())[1:5])] = h
for n, (d, _) in rows.items():
    if ssl.get(n) != d:
        ssl_bad.append((n, ssl.get(n), d))
for p in names:
    os.remove(p)

print("lengths compared        :", len(rows))
print("total digest comparisons:", len(rows) * 3,
      "(hashlib rmd160 + hashlib hash160 + openssl rmd160)")
print("hashlib mismatches      :", len(py_bad), py_bad[:5])
print("openssl mismatches      :", len(ssl_bad), ssl_bad[:5])
print("openssl digests obtained:", len(ssl))

rc = 0
if len(ssl) != len(rows):
    print(f"\n⛔ openssl returned {len(ssl)} digests for {len(rows)} lengths -- the "
          f"comparison is INCOMPLETE, not clean.", file=sys.stderr)
    rc = 2
if py_bad or ssl_bad:
    print(f"\n⛔ {len(py_bad)} hashlib and {len(ssl_bad)} openssl MISMATCHES.",
          file=sys.stderr)
    rc = 1
sys.exit(rc)
