#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Loopback stub for the read-timeout question (audit F2): a peer that says
# nothing, or announces 256 octets and then says nothing. Pure stdlib.
"""Loopback stub: accepts one connection and then either says nothing (mode a)
or sends four TPKT header octets announcing 256 more and then says nothing
(mode b). Used to ask what `TcpTransport.setReadTimeout` actually bounds."""
import socket, sys, time
port = int(sys.argv[1]); mode = sys.argv[2]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(1)
print("stub listening", port, mode, flush=True)
c, _ = s.accept()
if mode == "b":
    c.sendall(bytes([0x03, 0x00, 0x01, 0x00]))   # announces a 256-octet packet
    print("sent 4 header octets, now silent", flush=True)
time.sleep(30)
c.close(); s.close()
