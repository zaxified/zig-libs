#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture what a real lib60870-C (c104 2.2.1) controlled station answers when a
real lib60870-C controlling station interrogates the GLOBAL common address 0xFFFF.

Topology:   c104 Client  ->  recording TCP proxy  ->  c104 Server (station CA 47)

Everything that crosses the wire is dumped as hex with a direction tag.  Nothing
of ours is in the path; both endpoints are the third-party stack.

Run:  python3 global_ca_capture.py
Output: JSON on stdout.
"""
import json, socket, sys, threading, time

import c104

SRV_PORT = 24051
PROXY_PORT = 24052
CA = 47

log = []
log_lock = threading.Lock()
t0 = time.time()


def rec(direction, data):
    with log_lock:
        log.append({"t": round(time.time() - t0, 3), "dir": direction, "hex": data.hex()})


def pump(src, dst, direction, stop):
    try:
        while not stop.is_set():
            b = src.recv(65535)
            if not b:
                break
            rec(direction, b)
            dst.sendall(b)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def proxy(stop):
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", PROXY_PORT))
    ls.listen(4)
    ls.settimeout(1.0)
    conns = []
    while not stop.is_set():
        try:
            cs, _ = ls.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        ss = socket.create_connection(("127.0.0.1", SRV_PORT))
        conns.append((cs, ss))
        threading.Thread(target=pump, args=(cs, ss, "m2s", stop), daemon=True).start()
        threading.Thread(target=pump, args=(ss, cs, "s2m", stop), daemon=True).start()
    ls.close()


def main():
    # ---- controlled station (the RTU under observation) --------------------
    srv = c104.Server(ip="127.0.0.1", port=SRV_PORT)
    st = srv.add_station(common_address=CA)
    p1 = st.add_point(io_address=101, type=c104.Type.M_SP_NA_1)
    p1.value = True
    p2 = st.add_point(io_address=105, type=c104.Type.M_ME_NA_1)
    p2.info = c104.NormalizedInfo(c104.NormalizedFloat(0.5))
    p3 = st.add_point(io_address=108, type=c104.Type.M_IT_NA_1)
    st2 = srv.add_station(common_address=99)
    q1 = st2.add_point(io_address=201, type=c104.Type.M_SP_NA_1)
    q1.value = True
    q2 = st2.add_point(io_address=208, type=c104.Type.M_IT_NA_1)
    srv.start()
    time.sleep(0.5)

    stop = threading.Event()
    threading.Thread(target=proxy, args=(stop,), daemon=True).start()
    time.sleep(0.3)

    # ---- controlling station ----------------------------------------------
    cl = c104.Client(tick_rate_ms=100, command_timeout_ms=1000)
    conn = cl.add_connection(ip="127.0.0.1", port=PROXY_PORT, init=c104.Init.NONE)
    cl.start()
    time.sleep(1.5)

    def step(label, fn):
        log.append({"note": "--- %s ---" % label})
        time.sleep(0.3)
        try:
            r = fn()
        except Exception as e:  # noqa
            r = "RAISED %r" % (e,)
        log.append({"note": "%s -> %r" % (label, r)})
        time.sleep(2.5)

    G = 0xFFFF
    step("GI global 0xFFFF, server has stations 47 AND 99",
         lambda: conn.interrogation(common_address=G))
    step("counter-GI global 0xFFFF, two stations",
         lambda: conn.counter_interrogation(common_address=G))
    step("clock sync global 0xFFFF, two stations",
         lambda: conn.clock_sync(common_address=G, wait_for_response=False))
    step("GI to UNKNOWN station CA 200",
         lambda: conn.interrogation(common_address=200, wait_for_response=False))
    step("clock sync to UNKNOWN station CA 200",
         lambda: conn.clock_sync(common_address=200, wait_for_response=False))

    cl.stop()
    time.sleep(0.5)
    stop.set()
    srv.stop()
    json.dump(log, sys.stdout, indent=1)
    print()


main()
