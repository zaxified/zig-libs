# SPDX-License-Identifier: MIT
#
# The evidence behind the abuseguard card's `**Ahead:**` correctness claim:
# nginx `limit_conn` counts a connection only once its whole request header
# has been read, so sockets parked mid-header (slowloris) are not limited.
# With `limit_conn perip 1`: a second request while one is served -> 503
# (the control: the limit is live); 20 sockets with an unfinished header and
# then a full request -> 200. abuseguard takes the slot at accept (test
# "integration: a socket with an unfinished request header holds its per-IP
# slot").
#
#   modules/abuseguard/tools/nginx_probe/run.sh
#
# 2026-10-23, nginx 1.28.3-2ubuntu1.11: control 503; after 20 parked sockets 200.
import socket, sys, time

A = ("127.0.0.1", 18431)


def full(path):
    s = socket.create_connection(A)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    return s


def status(s):
    s.settimeout(5)
    return s.recv(64).split(b"\r\n", 1)[0].decode()


busy = full("/big")  # rate-limited download: one request in progress
time.sleep(0.3)
ctl = full("/")
c = status(ctl)
busy.close()
ctl.close()
time.sleep(0.5)

n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
slow = []
for _ in range(n):
    s = socket.create_connection(A)
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n")  # never finished
    slow.append(s)
time.sleep(0.5)
got = status(full("/"))
print(f"control (2nd request while one is served): {c}")
print(f"after {n} open sockets with unfinished headers, a full request: {got}")
for s in slow:
    s.close()
sys.exit(0 if c.startswith("HTTP/1.1 503") else 1)
