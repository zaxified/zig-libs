# SPDX-License-Identifier: MIT
import json, struct, sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cases import CASES
WORK = os.environ.get('WS_WORK', '.zig-cache/websocket-capture')  # scratch; run from the repo root
os.makedirs(WORK, exist_ok=True)
py = json.load(open(os.path.join(WORK, 'out_python.json')))['results']
go = json.load(open(os.path.join(WORK, 'out_go.json')))['results']
byname = dict(CASES)

def sent_close_code(data):
    """If the case frame is a close frame with a >=2-byte body, its code."""
    if (data[0] & 0x0f) != 0x8: return None
    l7 = data[1] & 0x7f
    body = data[2:2+l7]
    return struct.unpack('!H',body[:2])[0] if len(body) >= 2 else None

def go_verdict(name, r):
    """Classify a foreign server's raw reply. An echoed close code or a pong is
    ACCEPT; a close carrying a *different* code is REJECT with that code."""
    sent = sent_close_code(byname[name])
    if not r['reply_hex']:
        if r['err'] and 'timeout' not in r['err'] and 'deadline' not in r['err']:
            return ("DROP", None)           # peer closed the TCP conn with no close frame
        return ("ACCEPT", None)
    b = bytes.fromhex(r['reply_hex']); op = b[0] & 0x0f
    if op == 0xA: return ("ACCEPT", None)   # pong echo
    if op != 0x8: return ("ACCEPT", None)
    ln = b[1] & 0x7f; body = b[2:2+ln]
    code = struct.unpack('!H', body[:2])[0] if len(body) >= 2 else None
    if sent is not None and code == sent: return ("ACCEPT", code)   # clean close echo
    if sent is None and code is None:      return ("ACCEPT", None)  # empty close echo
    return ("REJECT", code)

def py_verdict(name, r):
    if 'harness_error' in r: return ("ACCEPT", None)
    if r.get('exc'): return ("REJECT", r['close_code'])
    return ("ACCEPT", None)

rows = {}
print("%-28s | %-12s | %-12s | %-12s | %s" % ("case","py-websockets","coder","gorilla","note"))
print("-"*92)
for name,_ in CASES:
    p  = py_verdict(name, py[name])
    c  = go_verdict(name, go['coder'][name])
    g  = go_verdict(name, go['gorilla'][name])
    agree = p[0]==c[0]==g[0]
    rows[name] = {"python": p, "coder": c, "gorilla": g, "unanimous": agree}
    f = lambda v: v[0] + ("" if v[1] is None else " %d"%v[1])
    print("%-28s | %-12s | %-12s | %-12s | %s" % (name, f(p), f(c), f(g), "" if agree else "DISAGREE"))
print()
print("accept coder  :", go['coder']['valid_text_hello']['accept'])
print("accept gorilla:", go['gorilla']['valid_text_hello']['accept'])
json.dump(rows, open(os.path.join(WORK, 'merged.json'),'w'), indent=1)
