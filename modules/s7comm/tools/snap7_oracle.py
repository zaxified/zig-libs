#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# ⚠ Needs `python-snap7` (measured against 3.1.0) -- a FOREIGN TOOLCHAIN that
# `zig build test-s7comm` must never require, which is why this lives in
# tools/ (CONVENTIONS.md §9). Everything is 127.0.0.1 on an unprivileged port;
# no real device is touched.
#
# This is the re-derivation recipe for `src/goldens.zig` (45 KB, 113 byte-exact
# captures). SPEC.md grades the module "class A - oracle MIXED" and names those
# captures as the anchor; without this script they can be read but not
# re-obtained, and a golden nobody can re-derive is a number, not evidence.
"""External oracle: a local python-snap7 SERVER on loopback (no real device).

Sends hand-built S7 frames straight at it over a socket and prints the raw
replies, so a second, independently written stack answers the same questions the
audit asks of this module. Everything is 127.0.0.1 on an unprivileged port.
"""
import ctypes
import socket
import sys
import time

import snap7
from snap7.server import Server
from snap7.type import SrvArea

PORT = 10502
HOST = "127.0.0.1"


def hexs(b):
    return b.hex()


def tpkt(payload: bytes) -> bytes:
    total = 4 + len(payload)
    return bytes([0x03, 0x00, total >> 8, total & 0xFF]) + payload


def dt(pdu: bytes) -> bytes:
    return tpkt(bytes([0x02, 0xF0, 0x80]) + pdu)


def s7job(ref: int, params: bytes, data: bytes = b"") -> bytes:
    return dt(
        bytes([0x32, 0x01, 0, 0, ref >> 8, ref & 0xFF,
               len(params) >> 8, len(params) & 0xFF,
               len(data) >> 8, len(data) & 0xFF]) + params + data
    )


def item(ts: int, count: int, db: int, area: int, addr: int) -> bytes:
    return bytes([0x12, 0x0A, 0x10, ts, count >> 8, count & 0xFF,
                  db >> 8, db & 0xFF, area,
                  (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF])


def recv_tpkt(s):
    head = b""
    while len(head) < 4:
        c = s.recv(4 - len(head))
        if not c:
            return None
        head += c
    total = (head[2] << 8) | head[3]
    body = b""
    while len(head) + len(body) < total:
        c = s.recv(total - len(head) - len(body))
        if not c:
            break
        body += c
    return head + body


def main():
    srv = Server()
    db1 = (ctypes.c_ubyte * 64)()
    mk = (ctypes.c_ubyte * 64)()
    for i in range(64):
        db1[i] = 0x5A
        mk[i] = 0xFF
    srv.register_area(SrvArea.DB, 1, db1)
    srv.register_area(SrvArea.MK, 0, mk)
    srv.start_to(HOST, PORT)
    time.sleep(0.4)
    print(f"snap7 server {snap7.__version__} up on {HOST}:{PORT}")

    try:
        s = socket.create_connection((HOST, PORT), timeout=5)
        # COTP CR, rack 0 slot 1.
        cr = tpkt(bytes([0x11, 0xE0, 0, 0, 0, 1, 0,
                         0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x01, 0x00,
                         0xC2, 0x02, 0x01, 0x01]))
        s.sendall(cr)
        print("CC        :", hexs(recv_tpkt(s)))
        # Setup communication, 480.
        s.sendall(s7job(1, bytes([0xF0, 0, 0, 1, 0, 1, 0x01, 0xE0])))
        print("SetupAck  :", hexs(recv_tpkt(s)))

        # ── the question the audit needs answered ───────────────────────────
        # Two items: a 1-octet byte read (ODD payload) then a single bit read.
        # Does the reference stack emit a pad octet between them?
        p = bytes([0x04, 0x02]) + item(0x02, 1, 1, 0x84, 0) + item(0x01, 1, 0, 0x83, 0)
        s.sendall(s7job(2, p))
        rep = recv_tpkt(s)
        print("byte+bit  :", hexs(rep))
        print("  data blk:", hexs(rep[21:]))

        # Control: bit first, then the odd byte.
        p = bytes([0x04, 0x02]) + item(0x01, 1, 0, 0x83, 0) + item(0x02, 1, 1, 0x84, 0)
        s.sendall(s7job(3, p))
        rep = recv_tpkt(s)
        print("bit+byte  :", hexs(rep))
        print("  data blk:", hexs(rep[21:]))

        # Three odd items, the shape goldens.zig already has, as a sanity check.
        p = (bytes([0x04, 0x03]) + item(0x02, 1, 1, 0x84, 0)
             + item(0x02, 3, 1, 0x84, 4 * 8) + item(0x02, 2, 0, 0x83, 0))
        s.sendall(s7job(4, p))
        rep = recv_tpkt(s)
        print("1,3,2     :", hexs(rep))
        print("  data blk:", hexs(rep[21:]))

        # A zero element count on the bit path -- the CRIT of the 2026-08 audit.
        p = bytes([0x04, 0x01]) + item(0x01, 0, 1, 0x84, 64 * 8)
        s.sendall(s7job(5, p))
        rep = recv_tpkt(s)
        print("bit cnt=0 one past the DB:", hexs(rep))

        # An address past the end of the DB.
        p = bytes([0x04, 0x01]) + item(0x02, 32, 1, 0x84, 250 * 8)
        s.sendall(s7job(6, p))
        print("oob read  :", hexs(recv_tpkt(s)))

        # ── how does the reference answer the length disagreements? ─────────
        s.close()
        for name, frame in [
            ("COTP DT with EOT=0",
             tpkt(bytes([0x02, 0xF0, 0x03]) + bytes([0x32, 0x01, 0, 0, 0, 7, 0, 2, 0, 0, 0x04, 0x01]))),
            ("TPKT length one too long",
             bytes([0x03, 0x00, 0x00, 0x20]) + dt(bytes([0x32, 0x01, 0, 0, 0, 8, 0, 14, 0, 0])
                                                  + bytes([0x04, 0x01]) + item(0x02, 4, 1, 0x84, 0))[4:]),
            ("S7 param_len one short",
             dt(bytes([0x32, 0x01, 0, 0, 0, 9, 0, 13, 0, 0]) + bytes([0x04, 0x01]) + item(0x02, 4, 1, 0x84, 0))),
            ("item count 2, one item present",
             s7job(10, bytes([0x04, 0x02]) + item(0x02, 4, 1, 0x84, 0))),
        ]:
            s2 = socket.create_connection((HOST, PORT), timeout=3)
            s2.sendall(cr)
            recv_tpkt(s2)
            s2.sendall(s7job(1, bytes([0xF0, 0, 0, 1, 0, 1, 0x01, 0xE0])))
            recv_tpkt(s2)
            s2.sendall(frame)
            try:
                r = recv_tpkt(s2)
                print(f"{name:<32}: {hexs(r) if r else 'CLOSED (no reply)'}")
            except Exception as e:
                print(f"{name:<32}: {type(e).__name__}")
            s2.close()
    finally:
        srv.stop()
        srv.destroy()
        print("snap7 server stopped")


if __name__ == "__main__":
    sys.exit(main())
