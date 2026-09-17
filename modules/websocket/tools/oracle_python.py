# SPDX-License-Identifier: MIT
"""Oracle A: python-websockets 15.0.1 (BSD-3-Clause) sans-io server state machine.

Feeds each case's bytes to a real ServerProtocol in OPEN state and records what
the foreign implementation actually did: the events it surfaced, and -- for a
rejection -- the close frame it emits on the wire, which is the RFC 6455 close
code it decided on.  Nothing is transcribed from its source; only executed.
"""
import json, sys, struct
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cases import CASES
from websockets.server import ServerProtocol
from websockets.protocol import State
WORK = os.environ.get('WS_WORK', '.zig-cache/websocket-capture')  # scratch; run from the repo root
os.makedirs(WORK, exist_ok=True)

MASK = bytes([0x37, 0xfa, 0x21, 0x3d])

def mask_frame(data):
    """Re-emit an unmasked client->server frame with the MASK bit + key set."""
    b0 = data[0]; b1 = data[1]
    assert b1 & 0x80 == 0
    l7 = b1 & 0x7f
    if l7 <= 125: hl = 2
    elif l7 == 126: hl = 4
    else: hl = 10
    head = data[:hl]; payload = data[hl:]
    head = bytes([head[0], head[1] | 0x80]) + head[2:]
    m = bytes(b ^ MASK[i % 4] for i, b in enumerate(payload))
    return head + MASK + m

def run(name, data):
    p = ServerProtocol(state=State.OPEN, max_size=None)
    p.receive_data(mask_frame(data))
    events = [repr(e) for e in p.events_received()]
    out = b"".join(p.data_to_send())
    exc = p.parser_exc or p.close_exc if p.state is not State.OPEN else p.parser_exc
    res = {"name": name, "events": events, "reply_hex": out.hex(),
           "state": p.state.name, "exc": None, "close_code": None, "close_reason": None}
    if p.parser_exc is not None:
        res["exc"] = type(p.parser_exc).__name__ + ": " + str(p.parser_exc)
    # decode the close frame the peer put on the wire, if any
    if len(out) >= 2 and (out[0] & 0x0f) == 0x8:
        body = out[2:2 + (out[1] & 0x7f)]
        if len(body) >= 2:
            res["close_code"] = struct.unpack('!H', body[:2])[0]
            res["close_reason"] = body[2:].decode('utf-8', 'replace')
    return res

results = {}
for name, data in CASES:
    try:
        results[name] = run(name, data)
    except Exception as e:
        results[name] = {"name": name, "harness_error": type(e).__name__ + ": " + str(e)}
json.dump({"oracle": "python-websockets", "version": __import__('websockets').__version__,
           "results": results}, open(os.path.join(WORK, 'out_python.json'), 'w'), indent=1)
# also dump the case table for the Go oracles
json.dump({n: d.hex() for n, d in CASES}, open(os.path.join(WORK, 'cases.json'), 'w'), indent=1)
print("cases:", len(CASES))
for n, r in results.items():
    if "harness_error" in r: print("HARNESS", n, r["harness_error"]); continue
    print("%-28s state=%-9s close=%-6s exc=%s" % (n, r["state"], r["close_code"], r["exc"]))
