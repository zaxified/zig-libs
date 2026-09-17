#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Drive a live outstation with a real c104 controlling station, on CA 0xFFFF."""
import json, sys, time
import c104

PORT = int(sys.argv[1])
rx = []

cl = c104.Client(tick_rate_ms=100, command_timeout_ms=3000)
conn = cl.add_connection(ip="127.0.0.1", port=PORT, init=c104.Init.NONE)


def on_rx(connection: c104.Connection, data: bytes) -> None:
    rx.append(bytes(data).hex())
    return None


conn.on_receive_raw(callable=on_rx)
cl.start()
for _ in range(100):
    if conn.is_connected:
        break
    time.sleep(0.1)

res = {"connected": conn.is_connected}
res["gi_global"] = conn.interrogation(common_address=0xFFFF)
time.sleep(0.5)
res["ci_global"] = conn.counter_interrogation(common_address=0xFFFF)
time.sleep(0.5)
res["cs_global"] = conn.clock_sync(common_address=0xFFFF, wait_for_response=False)
time.sleep(1.0)
res["gi_own_ca"] = conn.interrogation(common_address=47)
time.sleep(1.0)
res["still_connected"] = conn.is_connected
res["state"] = str(conn.state)
cl.stop()
res["rx"] = rx
res["explained"] = [c104.explain_bytes(apdu=bytes.fromhex(h)) for h in rx]
json.dump(res, sys.stdout, indent=1)
print()
