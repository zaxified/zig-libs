#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# ⚠ Needs `python-snap7`. Stands up a local S7 server so the module's own
# `live:` test -- normally SKIPPED -- runs against a genuine second
# implementation (CONVENTIONS.md §9).
"""Stands up a local python-snap7 server on loopback and holds it open, so the
module's own `live: our client against a real S7 server` test (normally SKIPPED)
can run against a genuine second implementation.

    python3 snap7_live.py &        # prints the port, then serves
    S7COMM_TEST_SERVER=127.0.0.1:10502 S7COMM_TEST_SLOT=1 \
        zig build test-s7comm

No real device is touched: 127.0.0.1, unprivileged port, in-process server.
"""
import ctypes
import signal
import sys
import time

import snap7
from snap7.server import Server
from snap7.type import SrvArea

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 10502
SECONDS = int(sys.argv[2]) if len(sys.argv) > 2 else 120

srv = Server()
db1 = (ctypes.c_ubyte * 512)()
db9 = (ctypes.c_ubyte * 1024)()
mk = (ctypes.c_ubyte * 256)()
srv.register_area(SrvArea.DB, 1, db1)
srv.register_area(SrvArea.DB, 9, db9)
srv.register_area(SrvArea.MK, 0, mk)
srv.start_to("127.0.0.1", PORT)
print(f"snap7 {snap7.__version__} serving 127.0.0.1:{PORT} for {SECONDS}s", flush=True)


def bye(*_):
    srv.stop()
    srv.destroy()
    print("stopped", flush=True)
    sys.exit(0)


signal.signal(signal.SIGTERM, bye)
signal.signal(signal.SIGINT, bye)
time.sleep(SECONDS)
bye()
