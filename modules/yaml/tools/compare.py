#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Differential oracle: this module's `composeAll` (YAML 1.2 core) vs PyYAML
6.0.3 (MIT, `pip show pyyaml`; YAML 1.1) (`CONVENTIONS.md` SS9).

Reads YAML records (one file per record, walking a corpus directory), feeds
them to the `ydump` probe (built from `ydump.zig`, this module's PUBLIC
`composeAll` -- see `README.md`) in batch mode and to PyYAML, then classifies
every divergence. YAML 1.1 vs 1.2 differences are EXPECTED and get their own
buckets; what matters is what is left over. Adopted from an audit reproducer
2026-09-17; only the docstring changed (the `--mutate N` form it advertised
was never implemented in `main()` below, so it is not documented here).

usage: compare.py <ydump-binary> <corpus-dir-or-list-file>

Needs: Python 3 + `pyyaml` (`pip install pyyaml==6.0.3`).
"""
import sys, os, subprocess, datetime, random, json, collections

# ---------- parse ydump's canonical form back into Python values ----------
class P:
    def __init__(s, t): s.t, s.i = t, 0
    def peek(s): return s.t[s.i] if s.i < len(s.t) else ''
    def val(s):
        c = s.peek()
        if c == 'N': s.i += 1; return None
        if c == 'B':
            s.i += 2
            if s.t.startswith('true', s.i): s.i += 4; return True
            s.i += 5; return False
        if c in 'IF':
            k = c; s.i += 2; j = s.i
            while s.i < len(s.t) and s.t[s.i] not in ',]}=': s.i += 1
            x = s.t[j:s.i]
            return int(x) if k == 'I' else float(x)
        if c == 'S':
            s.i += 2; out = bytearray()
            while s.i < len(s.t):
                if s.t[s.i] == '\\' and s.t[s.i+1] == 'x':
                    out.append(int(s.t[s.i+2:s.i+4], 16)); s.i += 4; continue
                if s.t[s.i] != ' ' and not s.t[s.i].isalnum(): break
                out.append(ord(s.t[s.i])); s.i += 1
            # the module is byte-transparent; decode so it compares against
            # PyYAML's str, keeping invalid bytes distinguishable.
            return bytes(out).decode('utf-8', 'surrogateescape')
        if c == '[':
            s.i += 1; r = []
            if s.peek() == ']': s.i += 1; return r
            while True:
                r.append(s.val())
                if s.peek() == ',': s.i += 1; continue
                s.i += 1; return r
        if c == '{':
            s.i += 1; r = []
            if s.peek() == '}': s.i += 1; return ('map', r)
            while True:
                k = s.val(); s.i += 2; v = s.val(); r.append((k, v))
                if s.peek() == ',': s.i += 1; continue
                s.i += 1; return ('map', r)
        if s.t.startswith('<deep>', s.i): s.i += 6; return '<deep>'
        raise ValueError('bad canon at %d: %r' % (s.i, s.t[s.i:s.i+20]))

def zig_parse(line):
    if line.startswith('ERR:'): return ('err', line[4:])
    body = line.split(':', 2)[2]
    if body == '': return ('ok', [])
    return ('ok', [P(d).val() for d in split_docs(body)])

def split_docs(b):
    out, depth, cur = [], 0, []
    i = 0
    while i < len(b):
        c = b[i]
        if c == '\\': cur.append(b[i:i+4]); i += 4; continue
        if c in '[{': depth += 1
        elif c in ']}': depth -= 1
        elif c == '|' and depth == 0: out.append(''.join(cur)); cur = []; i += 1; continue
        cur.append(c); i += 1
    out.append(''.join(cur))
    return out

# ---------- canonicalize a PyYAML value into the same shape ----------
def py_canon(v):
    if v is None or isinstance(v, bool): return v
    if isinstance(v, (int, float, str)): return v
    if isinstance(v, list): return [py_canon(x) for x in v]
    if isinstance(v, dict): return ('map', [(py_canon(k), py_canon(x)) for k, x in v.items()])
    if isinstance(v, tuple): return ('map', [(py_canon(k), py_canon(x)) for k, x in v])
    if isinstance(v, (datetime.date, datetime.datetime)): return ('ts', str(v))
    if isinstance(v, bytes): return ('bin', v.hex())
    if isinstance(v, set): return ('set', sorted(map(str, v)))
    return ('other', type(v).__name__)

def eq(a, b):
    if isinstance(a, bool) or isinstance(b, bool): return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        if a != a and b != b: return True          # NaN
        return a == b
    if type(a) is not type(b): return False
    if isinstance(a, list):
        return len(a) == len(b) and all(eq(x, y) for x, y in zip(a, b))
    if isinstance(a, tuple):
        if a[0] != b[0]: return False
        if a[0] != 'map': return a[1] == b[1]
        return len(a[1]) == len(b[1]) and all(eq(k1, k2) and eq(v1, v2)
                                              for (k1, v1), (k2, v2) in zip(a[1], b[1]))
    return a == b

# ---------- classification of a divergence ----------
ONEONE_BOOL = {'yes','Yes','YES','no','No','NO','on','On','ON','off','Off','OFF','y','Y','n','N'}

def classify(src, z, p):
    zk, zv = z
    if zk == 'err' and p[0] == 'err': return 'both_reject'
    if zk == 'err':
        e = zv
        if e == 'DuplicateKey': return 'dup_key_1.2_strict'
        if e == 'AliasCycle': return 'cycle_rejected_by_design'
        if e == 'TooDeep' or e == 'TooManyNodes': return 'bound_hit'
        return 'zig_rejects_pyyaml_accepts'
    if p[0] == 'err':
        m = p[1]
        if 'could not determine a constructor' in m or 'unhashable' in m: return 'pyyaml_ctor_limit'
        if 'found duplicate' in m: return 'pyyaml_dup'
        return 'pyyaml_rejects_zig_accepts'
    # both parsed: find the first differing leaf and name the reason
    r = first_diff(z[1], p[1])
    return r

TS_HINT = ('ts',)

def first_diff(a, b, depth=0):
    if depth > 40: return 'value_mismatch_deep'
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b): return 'seq_len_%d_vs_%d' % (len(a), len(b))
        for x, y in zip(a, b):
            if not eq(x, y): return first_diff(x, y, depth+1)
        return 'value_mismatch_none'
    if isinstance(a, tuple) and isinstance(b, tuple):
        if a[0] == 'map' and b[0] == 'map':
            if len(a[1]) != len(b[1]): return 'map_len_%d_vs_%d' % (len(a[1]), len(b[1]))
            for (k1, v1), (k2, v2) in zip(a[1], b[1]):
                if not eq(k1, k2): return first_diff(k1, k2, depth+1)
                if not eq(v1, v2): return first_diff(v1, v2, depth+1)
            return 'value_mismatch_none'
        if a[0] != b[0]: return 'kind_%s_vs_%s' % (a[0], b[0])
        return 'value_mismatch'
    # leaves
    ta, tb = leafkind(a), leafkind(b)
    if ta == 'str' and tb == 'bool' and a in ONEONE_BOOL: return 'bool_1.1_yes_no_on_off'
    if ta == 'str' and tb == 'ts': return 'timestamp_1.1'
    if ta == 'str' and tb == 'bin': return 'binary_tag_1.1'
    if ta == 'int' and tb == 'int': return 'int_octal_or_underscore_1.1'
    if ta == 'str' and tb == 'int':
        return 'sexagesimal_1.1' if ':' in str(a) else 'int_shape_1.1_wider'
    if ta == 'str' and tb == 'float':
        return 'sexagesimal_1.1' if ':' in str(a) else 'float_shape_1.1_wider'
    if ta == 'int' and tb == 'float' or ta == 'float' and tb == 'int': return 'int_vs_float'
    if ta == 'str' and tb == 'null': return 'null_spelling_1.1'
    if ta == 'null' and tb == 'str': return 'null_spelling_1.2'
    return 'leaf_%s_vs_%s' % (ta, tb)

def leafkind(v):
    if v is None: return 'null'
    if isinstance(v, bool): return 'bool'
    if isinstance(v, int): return 'int'
    if isinstance(v, float): return 'float'
    if isinstance(v, str): return 'str'
    if isinstance(v, tuple): return v[0]
    if isinstance(v, list): return 'seq'
    return 'other'

def main():
    ydump, corpus = sys.argv[1], sys.argv[2]
    files = []
    if os.path.isdir(corpus):
        for root, _, fs in os.walk(corpus):
            for f in fs:
                if f == 'in.yaml': files.append(os.path.join(root, f))
    else:
        files = [l.strip() for l in open(corpus) if l.strip()]
    files.sort()
    srcs = []
    for f in files:
        try: srcs.append(open(f, 'rb').read())
        except Exception: pass
    run(ydump, srcs, [os.path.relpath(f, corpus) if os.path.isdir(corpus) else f for f in files])

def run(ydump, srcs, names):
    import yaml as PY
    inp = b''.join(b'.' + s.hex().encode() + b'\n' for s in srcs)
    out = subprocess.run([ydump], input=inp, capture_output=True, timeout=1200)
    lines = out.stdout.decode('utf-8', 'replace').splitlines()
    assert len(lines) == len(srcs), 'ydump returned %d lines for %d records' % (len(lines), len(srcs))
    buckets = collections.Counter()
    examples = collections.defaultdict(list)
    agree = 0
    for name, src, line in zip(names, srcs, lines):
        try: z = zig_parse(line)
        except Exception as e: z = ('err', 'CANON_FAIL:%s' % e)
        try:
            docs = [py_canon(d) for d in PY.safe_load_all(src)]
            p = ('ok', docs)
        except Exception as e:
            p = ('err', str(e).replace('\n', ' ')[:120])
        if z[0] == 'ok' and p[0] == 'ok' and len(z[1]) == len(p[1]) and all(eq(a, b) for a, b in zip(z[1], p[1])):
            agree += 1
            continue
        c = classify(src, z, p)
        buckets[c] += 1
        if len(examples[c]) < 6:
            examples[c].append((name, src[:120], line[:120], str(p)[:120]))
    total = len(srcs)
    print('records=%d agree=%d (%.2f%%) diverge=%d' % (total, agree, 100.0*agree/total, total-agree))
    for k, v in buckets.most_common():
        print('  %-32s %5d' % (k, v))
    print()
    for k in buckets:
        print('### %s' % k)
        for n, s, zl, pl in examples[k]:
            print('  %s' % n)
            print('    in   %r' % s)
            print('    zig  %s' % zl)
            print('    py   %s' % pl)
        print()

if __name__ == '__main__':
    main()
