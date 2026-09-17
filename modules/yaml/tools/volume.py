#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Volume differential: N mutated documents through this module's `composeAll`
(via the `ydump` probe, `ydump.zig`) and libyaml (Expat/MIT-equivalent licence,
Debian's `/usr/share/doc/libyaml-0-2/copyright`; PyYAML's `CSafeLoader` binds
it) (`CONVENTIONS.md` SS9).

Seeds are the yaml-test-suite inputs; each record is one seed with 1-3 random
byte edits. The interesting signal is the ACCEPT/REJECT disagreement with
libyaml, bucketed by what the edit did. Adopted from an audit reproducer
2026-09-17, unchanged apart from this header.

usage: volume.py <ydump> <suite-dir> <N> [seed]

Needs: Python 3 + `pyyaml` built with its libyaml C bindings
(`python3 -c "import yaml; assert yaml.__with_libyaml__"`).
"""
import sys, os, random, subprocess, collections
import yaml as PY

ydump, suite, N = sys.argv[1], sys.argv[2], int(sys.argv[3])
rnd = random.Random(int(sys.argv[4]) if len(sys.argv) > 4 else 20260905)

seeds = []
for root, _, fs in os.walk(suite):
    for f in fs:
        if f == 'in.yaml':
            try: seeds.append(open(os.path.join(root, f), 'rb').read())
            except Exception: pass
seeds.sort()
print('seeds=%d' % len(seeds), file=sys.stderr)

ALPHA = bytes(range(0x20, 0x7f)) + b'\n\t\r' + bytes([0x80, 0xc3, 0xe2, 0xf0, 0xff, 0x00])

def mutate(s):
    b = bytearray(s)
    for _ in range(rnd.randint(1, 3)):
        if not b or rnd.random() < 0.25:
            b.insert(rnd.randrange(len(b) + 1), rnd.choice(ALPHA))
        elif rnd.random() < 0.4 and len(b) > 1:
            del b[rnd.randrange(len(b))]
        else:
            b[rnd.randrange(len(b))] = rnd.choice(ALPHA)
    return bytes(b[:4096])

BATCH = 5000
tot = agree_ar = 0
zig_only = lib_only = 0
buckets = collections.Counter()
examples = collections.defaultdict(list)
val_cmp = val_agree = 0

while tot < N:
    n = min(BATCH, N - tot)
    recs = [mutate(rnd.choice(seeds)) for _ in range(n)]
    inp = b''.join(b'.' + r.hex().encode() + b'\n' for r in recs)
    out = subprocess.run([ydump], input=inp, capture_output=True, timeout=3600)
    lines = out.stdout.decode('utf-8', 'replace').splitlines()
    if len(lines) != n:
        print('FRAMING MISMATCH %d != %d' % (len(lines), n), file=sys.stderr); break
    for r, l in zip(recs, lines):
        tot += 1
        zok = not l.startswith('ERR')
        try:
            docs = list(PY.load_all(r, Loader=PY.CSafeLoader)); lok = True
        except Exception as e:
            lok = False; lerr = str(e).split('\n')[0]
        if zok == lok:
            agree_ar += 1
        elif zok and not lok:
            zig_only += 1
            k = 'zig_accepts_libyaml_rejects'
            if 'unacceptable character' in lerr or 'invalid' in lerr or 'special characters' in lerr:
                k = 'zig_accepts__libyaml_charset_reject'
            elif 'found duplicate' in lerr:
                k = 'zig_accepts__libyaml_dupkey'
            buckets[k] += 1
            if len(examples[k]) < 5: examples[k].append((r[:90], l[:90], lerr[:70]))
        else:
            lib_only += 1
            k = 'libyaml_accepts_zig_rejects'
            buckets[k] += 1
            if len(examples[k]) < 8: examples[k].append((r[:90], l[:90], ''))

print('records=%d  accept/reject AGREE with libyaml=%d (%.2f%%)  zig-only-accept=%d  libyaml-only-accept=%d'
      % (tot, agree_ar, 100.0*agree_ar/tot, zig_only, lib_only))
for k, v in buckets.most_common():
    print('  %-40s %6d' % (k, v))
print()
for k in buckets:
    print('### %s' % k)
    for r, l, e in examples[k]:
        print('  in  %r' % r); print('  zig %s' % l); print('  lib %s' % e)
    print()
