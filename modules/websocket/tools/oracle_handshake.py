#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Differential oracle: python-websockets 15.0.1 (BSD-3-Clause) sans-io
`ClientProtocol`/`ServerProtocol` against this module's public handshake API
(`handshake.verifyResponse`, `handshake.acceptHandshake`).

Distinct from `oracle_python.py`, which drives POST-handshake DATA FRAMES
into a `ServerProtocol` (`Connection`-layer corpus). This file is about the
OPENING HANDSHAKE itself: the client-side response check (`verifyResponse`)
and the server-side request check (`acceptHandshake`) -- neither is exercised
by `oracle_python.py`'s frame corpus, so the two do not overlap.

Adopted from an audit reproducer (2026-09-17, `CONVENTIONS.md` §9 "a
differential oracle ... kept"). The audit script only printed python-
websockets' own verdicts; this version additionally builds and runs
`verify_response_probe.zig` -- a small Zig program that calls the module's
public `verifyResponse`/`acceptHandshake` over the SAME case table -- and
diffs the two implementations' ACCEPT/REJECT decisions case by case.

Needs: Python 3 + `websockets` 15.0.1 (`pip install websockets==15.0.1`);
a built `verify_response_probe` binary (see `tools/README.md` for the exact
`zig build-exe` invocation).

Run (from the repo root):
    modules/websocket/tools/oracle_handshake.py <path-to-verify_response_probe>

Produces: one line per case ("agree"/"MISMATCH") plus a summary; exit code
0 iff every case agrees.

measured 2026-09-17: 10/10 cases agree (see tools/README.md).
"""
import subprocess
import sys

try:
    import websockets
except ImportError:
    print("SKIP: `websockets` is not importable (pip install websockets==15.0.1)", file=sys.stderr)
    sys.exit(1)

from websockets.client import ClientProtocol
from websockets.uri import parse_uri
from websockets.datastructures import Headers
from websockets.http11 import Response, Request
from websockets.server import ServerProtocol

KEY = "dGhlIHNhbXBsZSBub25jZQ=="
ACC = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def client_verdict(headers):
    p = ClientProtocol(parse_uri("ws://example.com/"))
    p.key = KEY  # pin the nonce so ACC is the right answer
    h = Headers()
    for k, v in headers:
        h[k] = v
    try:
        p.process_response(Response(101, "Switching Protocols", h))
        return "ACCEPT", None
    except Exception as e:
        return "REJECT", f"{type(e).__name__}: {e}"


def server_verdict(headers):
    sp = ServerProtocol()
    h = Headers()
    for k, v in headers:
        h[k] = v
    try:
        resp = sp.accept(Request("/", h))
        return ("ACCEPT" if resp.status_code == 101 else "REJECT"), f"status {resp.status_code}"
    except Exception as e:
        return "REJECT", f"{type(e).__name__}: {e}"


base = [("Upgrade", "websocket"), ("Connection", "Upgrade"), ("Sec-WebSocket-Accept", ACC)]
CLIENT_CASES = [
    ("baseline 101", base),
    ("+ Sec-WebSocket-Extensions: permessage-deflate", base + [("Sec-WebSocket-Extensions", "permessage-deflate")]),
    ("+ Sec-WebSocket-Extensions: x-made-up", base + [("Sec-WebSocket-Extensions", "x-made-up")]),
    ("+ Sec-WebSocket-Protocol: chat (never offered)", base + [("Sec-WebSocket-Protocol", "chat")]),
    ("Accept x2 (right then wrong)", base + [("Sec-WebSocket-Accept", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=")]),
    ("Upgrade x2 (websocket then h2c)", [("Upgrade", "websocket"), ("Upgrade", "h2c"), ("Connection", "Upgrade"), ("Sec-WebSocket-Accept", ACC)]),
]

sbase = [("Host", "h"), ("Upgrade", "websocket"), ("Connection", "Upgrade"), ("Sec-WebSocket-Key", KEY), ("Sec-WebSocket-Version", "13")]
SERVER_CASES = [
    ("baseline GET upgrade", sbase),
    ("Sec-WebSocket-Key x2", sbase + [("Sec-WebSocket-Key", "AAAAAAAAAAAAAAAAAAAAAA==")]),
    ("Sec-WebSocket-Version: 13, 8", [("Host", "h"), ("Upgrade", "websocket"), ("Connection", "Upgrade"), ("Sec-WebSocket-Key", KEY), ("Sec-WebSocket-Version", "13, 8")]),
    ("Origin: https://evil.example", sbase + [("Origin", "https://evil.example")]),
]


def run_zig_probe(path):
    """Returns {(side, name): (verdict, detail)} from verify_response_probe's stdout."""
    out = subprocess.run([path], capture_output=True, text=True, check=True).stdout
    verdicts = {}
    for line in out.splitlines():
        side, name, verdict, detail = line.split("\t", 3)
        verdicts[(side, name)] = (verdict, detail)
    return verdicts


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <path-to-verify_response_probe>", file=sys.stderr)
        return 2
    print("python-websockets", websockets.__version__)
    zig_verdicts = run_zig_probe(sys.argv[1])

    mismatches = 0
    total = 0
    for side, cases, verdict_fn in (("client", CLIENT_CASES, client_verdict), ("server", SERVER_CASES, server_verdict)):
        print(f"\n== {side} side ==")
        for name, headers in cases:
            total += 1
            py_verdict, py_detail = verdict_fn(headers)
            zig_verdict, zig_detail = zig_verdicts.get((side, name), ("MISSING", None))
            tag = "agree" if py_verdict == zig_verdict else "MISMATCH"
            if tag == "MISMATCH":
                mismatches += 1
            print(f"  {name:<50} python={py_verdict:<7} zig={zig_verdict:<7} {tag}  ({py_detail} / {zig_detail})")

    print(f"\n{total - mismatches}/{total} agree, {mismatches} mismatch(es)")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
