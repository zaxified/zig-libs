# SPDX-License-Identifier: MIT
"""Emit the frozen foreign-peer corpus as a Zig table.

Run once; the output is committed and the tests then run offline with all three
foreign implementations deleted.  Nothing here is transcribed from anyone's
source -- every verdict below is what the three implementations *did* when the
bytes were put in front of them.
"""
import json, sys, struct
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cases import CASES
WORK = os.environ.get('WS_WORK', '.zig-cache/websocket-capture')  # scratch; run from the repo root
os.makedirs(WORK, exist_ok=True)
merged = json.load(open(os.path.join(WORK, 'merged.json')))
MASK = bytes([0x37, 0xfa, 0x21, 0x3d])

def mask_frame(data):
    b1 = data[1]; l7 = b1 & 0x7f
    hl = 2 if l7 <= 125 else (4 if l7 == 126 else 10)
    head = bytes([data[0], data[1] | 0x80]) + data[2:hl]
    pay = data[hl:]
    return head + MASK + bytes(b ^ MASK[i % 4] for i, b in enumerate(pay))

def zigstr(b):
    return '"' + ''.join('\\x%02x' % c for c in b) + '"'

def zigwire(b):
    """Byte-exact, but collapse a long masked run of a repeated byte into an
    explicit `**` repetition so the frozen literal stays readable. The bytes are
    identical either way -- verified by asserting the expansion below."""
    if len(b) <= 40: return zigstr(b)
    l7 = b[1] & 0x7f
    hl = (2 if l7 <= 125 else (4 if l7 == 126 else 10)) + 4
    head, pay = b[:hl], b[hl:]
    per = pay[:4]
    n = len(pay) // 4
    if pay[:n*4] == per * n:
        tail = pay[n*4:]
        out = '%s ++ (%s ** %d)' % (zigstr(head), zigstr(per), n)
        if tail: out += ' ++ ' + zigstr(tail)
        assert eval_check(out, b)
        return out
    return zigstr(b)

def eval_check(expr, b):
    import re
    parts = re.findall(r'"((?:\\x[0-9a-f]{2})+)"(?: \*\* (\d+))?', expr)
    acc = b''
    for lit, mult in parts:
        raw = bytes(int(x, 16) for x in lit.split('\\x')[1:])
        acc += raw * (int(mult) if mult else 1)
    return acc == b

# Cases whose payload is huge -- skip from the frozen table (the length-boundary
# behaviour they cover is already asserted by the RFC 5.7 64KiB vector).
SKIP_BIG = {"valid_text_65535_16bit", "valid_text_65536_64bit", "nonminimal_len64_at_65535",
            "valid_binary_256"}

# Cases where all three peers accept but this module deliberately rejects: RFC 6455
# §5.2 requires the minimal length encoding ("the minimal number of bytes MUST be
# used"), which none of the three enforces. Recorded as a divergence, not silently
# dropped -- the anchor's verdict is preserved next to ours.
DIVERGENCE = {"nonminimal_len16", "nonminimal_len16_zero", "nonminimal_len64"}

rows = []
for name, data in CASES:
    if name in SKIP_BIG: continue
    m = merged[name]
    verds = [m['python'][0], m['coder'][0], m['gorilla'][0]]
    # DROP (peer closed the TCP connection without a close frame) counts as a rejection.
    norm = ['REJECT' if v == 'DROP' else v for v in verds]
    unanimous = len(set(norm)) == 1
    codes = [m['python'][1], m['coder'][1], m['gorilla'][1]]
    rej_codes = {c for v, c in zip(norm, codes) if v == 'REJECT' and c is not None}
    code = rej_codes.pop() if len(rej_codes) == 1 else None
    rows.append(dict(name=name, wire=mask_frame(data), verdict=norm[0] if unanimous else None,
                     unanimous=unanimous, code=code,
                     detail="py=%s%s coder=%s%s gorilla=%s%s" % (
                         norm[0], '' if codes[0] is None else '/%d'%codes[0],
                         norm[1], '' if codes[1] is None else '/%d'%codes[1],
                         norm[2], '' if codes[2] is None else '/%d'%codes[2])))

out = []
for r in rows:
    if not r['unanimous']:
        out.append('    // SPLIT: %s\n    .{ .label = "%s", .wire = %s, .verdict = .split, .close_code = null, .peers = "%s" },'
                   % (r['detail'], r['name'], zigwire(r['wire']), r['detail']))
    elif r['name'] in DIVERGENCE:
        out.append('    .{ .label = "%s", .wire = %s, .verdict = .divergence, .close_code = 1002, .peers = "%s" },'
                   % (r['name'], zigwire(r['wire']), r['detail']))
    else:
        v = 'accept' if r['verdict'] == 'ACCEPT' else 'reject'
        cc = 'null' if r['code'] is None else str(r['code'])
        out.append('    .{ .label = "%s", .wire = %s, .verdict = .%s, .close_code = %s, .peers = "%s" },'
                   % (r['name'], zigwire(r['wire']), v, cc, r['detail']))
open(os.path.join(WORK, 'corpus.zig.txt'),'w').write('\n'.join(out) + '\n')
print(len(rows), "rows;", sum(1 for r in rows if not r['unanimous']), "splits")
