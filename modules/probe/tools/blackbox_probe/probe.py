# SPDX-License-Identifier: MIT
#
# The evidence behind the probe card's `**Ahead:**` correctness claim:
# Prometheus blackbox_exporter's tcp prober (the reference) resolves a name,
# picks ONE address of the preferred family (ip6 by default) and dials only
# that one. A dual-stack name whose IPv6 path is dead -- here `localhost`
# with ::1:P a black hole (a full accept queue: SYNs dropped) and
# 127.0.0.1:P listening -- is reported down (probe_success 0) although the
# service answers on IPv4. The control, target 127.0.0.1:P, is up.
# PosixConnector races the addresses (RFC 8305) and reports up (tests
# "race: a black-holed first address does not starve a listening second
# one (RFC 8305)", "race (scripted): ...").
#
#   modules/probe/tools/blackbox_probe/run.sh
#
# 2026-10-23, blackbox_exporter 0.26.0 (Ubuntu 0.26.0-2): localhost:P
# probe_success 0 after the 2 s timeout; 127.0.0.1:P probe_success 1.
import socket, sys, time, urllib.request

EXPORTER = sys.argv[1]  # host:port of the running exporter

v6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
v6.bind(("::1", 0))
port = v6.getsockname()[1]
v6.listen(1)
fillers = []
for _ in range(16):  # fill the one-slot accept queue; later SYNs are dropped
    f = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    f.setblocking(False)
    try:
        f.connect(("::1", port))
    except BlockingIOError:
        pass
    fillers.append(f)
time.sleep(0.3)
v4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
v4.bind(("127.0.0.1", port))
v4.listen(16)


def probe(target):
    t0 = time.monotonic()
    url = f"http://{EXPORTER}/probe?module=tcp_connect&target={target}"
    body = urllib.request.urlopen(url, timeout=10).read().decode()
    ok = next(l for l in body.splitlines() if l.startswith("probe_success "))
    return ok.split()[1], time.monotonic() - t0


got_v4, t_v4 = probe(f"127.0.0.1:{port}")
got_name, t_name = probe(f"localhost:{port}")
print(f"control 127.0.0.1:{port}: probe_success {got_v4} ({t_v4:.2f} s)")
print(f"localhost:{port} (::1 black hole, 127.0.0.1 listening): probe_success {got_name} ({t_name:.2f} s)")
sys.exit(0 if got_v4 == "1" and got_name == "0" else 1)
