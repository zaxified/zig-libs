#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# ⚠ Needs `python-snap7`. Drives this module's own `Responder` with an
# INDEPENDENT S7 client, the other way round from snap7_oracle.py
# (CONVENTIONS.md §9).
"""Drives the module's own `Responder` (via its `live: a real S7 client against
our responder` test) with an independent S7 client, on loopback.

    S7COMM_TEST_LISTEN=127.0.0.1:10503 zig build test-s7comm &
    python3 snap7_client_drive.py 10503
"""
import sys
import time

import snap7
from snap7.type import Area

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 10503

c = snap7.Client()
for attempt in range(30):
    try:
        c.connect("127.0.0.1", 0, 1, PORT)
        break
    except Exception as e:
        time.sleep(0.3)
else:
    print("could not connect")
    sys.exit(1)

print("connected, pdu:", c.get_pdu_length() if hasattr(c, "get_pdu_length") else "?")
try:
    d = c.db_read(1, 0, 8)
    print("db_read(1,0,8)  =", d.hex())
    c.db_write(1, 4, bytearray(b"\xde\xad\xbe\xef"))
    print("db_write ok")
    d = c.db_read(1, 0, 8)
    print("db_read again   =", d.hex())
    r = c.read_area(Area.MK, 0, 0, 4)
    print("read_area MK    =", r.hex())
    try:
        info = c.get_cpu_info()
        print("cpu_info        =", info)
    except Exception as e:
        print("cpu_info        : FAILED", type(e).__name__, e)
    try:
        print("cpu_state       =", c.get_cpu_state())
    except Exception as e:
        print("cpu_state       : FAILED", type(e).__name__, e)
    try:
        d = c.db_read(77, 0, 4)
        print("db_read(77)     = UNEXPECTED SUCCESS", d.hex())
    except Exception as e:
        print("db_read(77)     : correctly refused ->", type(e).__name__, e)
finally:
    c.disconnect()
    print("disconnected")
