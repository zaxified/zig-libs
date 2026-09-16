#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare the hex vectors pinned in `../src/kat_vectors_kem.zig` against the
official HQC reference `.rsp` KAT files, field by field.

WHY THIS EXISTS. The module's own tests read those vectors and check the
implementation against them; nothing in this repository checks the VECTORS
THEMSELVES, because the authority for them — the reference's `.rsp` files —
is not shipped here. A transcription slip made once would then be replayed by
every green run forever. This reads both sides and compares the bytes.

WHAT IT NEEDS. A reference checkout (no build required, only its `kats/`
directory); see `README.md` here for the clone recipe.

    python3 compare_kat.py "HQC v5.0.0" .zig-cache/hqc-cref/hqc-v5.0.0

⚠ WHICH CHECKOUT MATTERS. Against tag `v5.0.0` the expected result is
45/45 fields MATCH. Against the `next-release` branch — where a bare clone
lands — only the nine seeds match and every other field differs, because that
branch changed the KATs. That output looks exactly like a defect in this module
and is not one.

WHAT IT PRODUCES. One MATCH/DIFF line per field on stdout, a totals line, and
an EXIT CODE: 0 only when every field matched.

⚠ The exit code is the point of this paragraph. Until 2026-09-16 this script
computed the mismatch count, returned it from main() — and then called
`sys.exit(0)` unconditionally, so it reported success no matter what it found.
Anything that ran it from a script, or read only its status, was told the
vectors agreed without any of them being compared.
"""
import re, sys, os, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
ZIG = os.path.join(HERE, "..", "src", "kat_vectors_kem.zig")

def parse_zig(path):
    src = open(path).read()
    # strip // line comments that are not inside strings: safer -> remove comment-only lines
    out = {}
    # find `pub const hqcNNN: [N]Vector = .{ ... };`
    for m in re.finditer(r'pub const (hqc\d+)\s*:\s*\[(\d+)\]Vector\s*=\s*\.\{', src):
        name = m.group(1); n = int(m.group(2))
        # brace-match from the `.{`
        i = src.index('.{', m.end()-2)
        depth = 0; j = i
        while True:
            if src[j] == '{': depth += 1
            elif src[j] == '}':
                depth -= 1
                if depth == 0: break
            j += 1
        body = src[i:j+1]
        # each vector: .count = K, .seed = "..." ++ "...", ...
        vecs = []
        for vm in re.finditer(r'\.count\s*=\s*(\d+)\s*,', body):
            start = vm.start()
            nxt = body.find('.count', vm.end())
            chunk = body[start: nxt if nxt != -1 else len(body)]
            v = {'count': int(vm.group(1))}
            for field in ('seed','pk','sk','ct','ss'):
                fm = re.search(r'\.'+field+r'\s*=\s*(.*?),\s*\n\s*(?:\.\w+\s*=|\}|\.\{)', chunk, re.S)
                if not fm:
                    fm = re.search(r'\.'+field+r'\s*=\s*((?:"[0-9a-fA-F]*"\s*(?:\+\+)?\s*)+)', chunk, re.S)
                expr = fm.group(1)
                parts = re.findall(r'"([0-9a-fA-F]*)"', expr)
                v[field] = ''.join(parts).lower()
            vecs.append(v)
        assert len(vecs) == n, (name, len(vecs), n)
        out[name] = vecs
    return out

def parse_rsp(path, want_counts):
    """Parse NIST .rsp; return {count: {field: hexlower}} for counts in want_counts."""
    res = {}
    cur = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'): continue
            if '=' not in line: continue
            k, _, v = line.partition('=')
            k = k.strip(); v = v.strip()
            if k == 'count':
                c = int(v)
                if c in want_counts:
                    cur = {}; res[c] = cur
                else:
                    cur = None
                    if len(res) == len(want_counts) and max(want_counts) < c:
                        break
            elif cur is not None:
                cur[k] = v.lower()
    return res

RSP = {
  'hqc128': ('hqc-1', 'PQCkemKAT_2321.rsp'),
  'hqc192': ('hqc-3', 'PQCkemKAT_4602.rsp'),
  'hqc256': ('hqc-5', 'PQCkemKAT_7333.rsp'),
}

def main(rootlabel, root):
    zig = parse_zig(ZIG)
    total_ok = total_bad = 0
    print(f"### Comparing against: {rootlabel}  ({root})")
    for name in ('hqc128','hqc192','hqc256'):
        if name not in zig:
            print(f"  {name}: NOT PRESENT in zig file"); total_bad += 1; continue
        vecs = zig[name]
        sub, fn = RSP[name]
        p = os.path.join(root, 'kats', 'ref', sub, fn)
        if not os.path.exists(p):
            print(f"  {name}: rsp missing {p}"); total_bad += 1; continue
        want = {v['count'] for v in vecs}
        rsp = parse_rsp(p, want)
        for v in vecs:
            c = v['count']
            if c not in rsp:
                print(f"  {name} count={c}: MISSING in rsp"); total_bad += 1; continue
            r = rsp[c]
            for field in ('seed','pk','sk','ct','ss'):
                a = v[field]; b = r.get(field, None)
                if b is None:
                    print(f"  {name} count={c} {field}: field absent in rsp"); total_bad += 1; continue
                if a == b:
                    total_ok += 1
                    print(f"  MATCH  {name} count={c} {field:4s} len={len(a)//2}B sha256={hashlib.sha256(bytes.fromhex(a)).hexdigest()[:16]}")
                else:
                    total_bad += 1
                    # locate first differing nibble
                    d = next((i for i in range(min(len(a),len(b))) if a[i]!=b[i]), min(len(a),len(b)))
                    print(f"  DIFF   {name} count={c} {field:4s} ziglen={len(a)//2}B rsplen={len(b)//2}B firstdiff@nibble {d} zig=...{a[max(0,d-8):d+8]}... rsp=...{b[max(0,d-8):d+8]}...")
    print(f"  == {rootlabel}: {total_ok} fields MATCH, {total_bad} fields DIFFER/MISSING")
    # A comparison with nothing to compare is a failure, not a pass: an empty or
    # unparsed vector file would otherwise print a tidy "0 MATCH, 0 DIFFER".
    if total_ok == 0:
        print("  == no field was compared at all — treating as failure")
        return 1
    return total_bad

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print("usage: compare_kat.py <label> <reference-checkout>", file=sys.stderr)
        sys.exit(2)
    bad = main(sys.argv[1], sys.argv[2])
    sys.exit(1 if bad else 0)
