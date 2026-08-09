#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Drive a `fleetsim`-simulated Modbus slave with a REAL third-party master.

This is the guest half of `scripts/vm/run.sh fleetsim debian`. It runs inside
the disposable Debian VM, never on the host, and it exists because
`modules/fleetsim`'s only external anchor — "a real master drove a simulated
device and was satisfied by what came back" — cannot be had from anything we
wrote ourselves. pymodbus is a mature, independently-developed Modbus stack;
it encodes the requests and decodes the replies with no knowledge of how
`fleetsim` produced them, so it can disagree with us, which is the whole
definition of an anchor.

Two jobs, deliberately in one process:

1. **Drive.** A fixed sequence of Modbus operations against the simulated
   slave, each with an expectation that a *third party's* decoder has to
   satisfy. A wrong byte order, a wrong PDU length, a wrong exception code or
   a wrong MBAP transaction id all surface as a pymodbus error or a wrong
   value here, not as an assertion we wrote about our own bytes.

2. **Capture.** Everything on that TCP connection passes through an in-process
   byte tap, so the exact ADUs pymodbus put on the wire — and the exact ADUs
   the simulated device answered with — can be frozen into the offline test
   suite. A live test that only runs in a VM nobody spins up is barely better
   than a skip; the frozen bytes are what makes the ordinary `zig build
   test-fleetsim` stronger.

   The tap is a plain socket relay rather than pymodbus's own debug logging on
   purpose: it depends on no pymodbus internal, so a version bump cannot
   silently change what gets captured, and it records what actually crossed
   the wire rather than what a library said it was about to send.

Usage: fleetsim-modbus-master.py <device-host> <device-port> [wait-seconds]

Output: a human-readable transcript, then one JSON object per operation
between FLEETSIM_CAPTURE_BEGIN/END markers, then MODBUS_MASTER_OK (exit 0) or
MODBUS_MASTER_FAIL (exit 1). `run.sh` fails the whole run if the OK marker is
absent, so "the master never actually connected" cannot read as a pass.
"""

import json
import socket
import struct
import sys
import threading
import time

CAPTURE_BEGIN = "FLEETSIM_CAPTURE_BEGIN"
CAPTURE_END = "FLEETSIM_CAPTURE_END"


def split_adus(buf):
    """Split a Modbus/TCP byte stream into whole ADUs.

    MBAP is transaction(2) protocol(2) length(2) unit(1); `length` counts the
    unit byte plus the PDU. Reassembling from the length field rather than
    from read boundaries is what makes the capture independent of TCP
    segmentation — the frozen vectors must be frames, not packets.
    """
    out = []
    i = 0
    while i + 6 <= len(buf):
        (ln,) = struct.unpack(">H", buf[i + 4 : i + 6])
        if ln < 1 or i + 6 + ln > len(buf):
            break
        out.append(buf[i : i + 6 + ln])
        i += 6 + ln
    return out, buf[i:]


class Tap:
    """A one-connection TCP relay that records both directions.

    pymodbus connects here; here connects to the simulated device. Nothing is
    modified in flight — this is a recorder, not a proxy with opinions.
    """

    def __init__(self, upstream):
        self.up = upstream
        self.lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lsock.bind(("127.0.0.1", 0))
        self.lsock.listen(1)
        self.port = self.lsock.getsockname()[1]
        self.down = None
        self.lock = threading.Lock()
        self.tx_raw = b""  # master -> device
        self.rx_raw = b""  # device -> master
        self.tx_adus = []
        self.rx_adus = []
        self._tx_taken = 0
        self._rx_taken = 0
        self.stopped = False

    def start(self):
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        self.down, _ = self.lsock.accept()
        self.down.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=self._pump, args=(self.down, self.up, "tx"), daemon=True).start()
        threading.Thread(target=self._pump, args=(self.up, self.down, "rx"), daemon=True).start()

    def _pump(self, src, dst, which):
        while not self.stopped:
            try:
                data = src.recv(4096)
            except OSError:
                break
            if not data:
                break
            with self.lock:
                if which == "tx":
                    self.tx_raw += data
                    adus, self.tx_raw = split_adus(self.tx_raw)
                    self.tx_adus.extend(adus)
                else:
                    self.rx_raw += data
                    adus, self.rx_raw = split_adus(self.rx_raw)
                    self.rx_adus.extend(adus)
            try:
                dst.sendall(data)
            except OSError:
                break
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def drain(self):
        """ADUs seen since the previous drain, as (requests, responses)."""
        time.sleep(0.05)  # let the reply's pump thread land before we look
        with self.lock:
            tx = [bytes(a) for a in self.tx_adus[self._tx_taken :]]
            rx = [bytes(a) for a in self.rx_adus[self._rx_taken :]]
            self._tx_taken = len(self.tx_adus)
            self._rx_taken = len(self.rx_adus)
        return tx, rx

    def stop(self):
        self.stopped = True
        for s in (self.down, self.up, self.lsock):
            try:
                if s is not None:
                    s.close()
            except OSError:
                pass


def wait_upstream(host, port, seconds):
    """Connect to the simulated device, retrying until it has bound.

    The Zig test binary and this script are started by the same shell line, so
    which one wins the race is not fixed; retrying is what makes the run
    reproducible instead of order-dependent.
    """
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return s, None
        except OSError as e:
            last = e
            time.sleep(0.25)
    return None, last


def call(fn, **kw):
    """pymodbus renamed the unit-id keyword `slave` -> `device_id` in 3.x.

    Try the current name, fall back once. Anything else propagates: a silent
    fallback to "no unit id at all" would change the bytes being captured.
    """
    try:
        return fn(**kw)
    except TypeError:
        kw2 = dict(kw)
        if "device_id" in kw2:
            kw2["slave"] = kw2.pop("device_id")
            return fn(**kw2)
        raise


def main():
    host = sys.argv[1]
    port = int(sys.argv[2])
    wait_s = float(sys.argv[3]) if len(sys.argv) > 3 else 90.0

    import pymodbus
    from pymodbus.client import ModbusTcpClient

    version = getattr(pymodbus, "__version__", "?")
    # Recorded, not assumed: the frozen vectors' NOTICE entry has to name the
    # counterpart's licence, and reading it off the installed distribution is
    # the only way that statement stays true when the pin moves.
    try:
        import importlib.metadata as md

        meta = md.metadata("pymodbus")
        licence = meta.get("License-Expression") or meta.get("License") or "?"
    except Exception:  # noqa: BLE001
        licence = "?"
    print("master: pymodbus %s (licence: %s) -> %s:%d" % (version, licence, host, port), flush=True)

    up, err = wait_upstream(host, port, wait_s)
    if up is None:
        print("master: device never accepted a connection: %s" % err, flush=True)
        print("MODBUS_MASTER_FAIL", flush=True)
        return 1

    tap = Tap(up)
    tap.start()
    client = ModbusTcpClient("127.0.0.1", port=tap.port, timeout=5, retries=1)
    if not client.connect():
        print("master: could not connect through the capture tap", flush=True)
        print("MODBUS_MASTER_FAIL", flush=True)
        tap.stop()
        return 1

    records = []
    failures = []

    def op(name, deterministic, fn, check):
        """Run one operation, record its bytes, grade the master's own decode."""
        try:
            rr = fn()
        except Exception as e:  # noqa: BLE001 - a master-side raise is a result too
            tx, rx = tap.drain()
            records.append(
                {
                    "op": name,
                    "deterministic": deterministic,
                    "request": [t.hex() for t in tx],
                    "response": [r.hex() for r in rx],
                    "raised": "%s: %s" % (type(e).__name__, e),
                }
            )
            failures.append("%s raised %s" % (name, e))
            return
        tx, rx = tap.drain()
        decoded, problem = check(rr)
        rec = {
            "op": name,
            "deterministic": deterministic,
            "request": [t.hex() for t in tx],
            "response": [r.hex() for r in rx],
            "decoded": decoded,
        }
        records.append(rec)
        if problem:
            failures.append("%s: %s" % (name, problem))
        print(
            "master: %-28s req=%s resp=%s -> %s%s"
            % (
                name,
                ",".join(t.hex() for t in tx),
                ",".join(r.hex() for r in rx),
                decoded,
                "" if not problem else "  ** " + problem,
            ),
            flush=True,
        )

    def regs(expected):
        def check(rr):
            if rr.isError():
                return {"error": str(rr)}, "master reports an error response"
            got = list(rr.registers)
            return {"registers": got}, None if got == expected else "expected %s" % (expected,)

        return check

    def bits(expected):
        def check(rr):
            if rr.isError():
                return {"error": str(rr)}, "master reports an error response"
            got = [bool(b) for b in rr.bits][: len(expected)]
            return {"bits": got}, None if got == expected else "expected %s" % (expected,)

        return check

    def written(check_value):
        def check(rr):
            if rr.isError():
                return {"error": str(rr)}, "master reports an error response"
            return {"echo": str(rr)}, None

        _ = check_value
        return check

    # ── the fixture these expectations describe ─────────────────────────────
    # `test "live: a real Modbus master drives a simulated slave over the TCP
    # binding"` (modules/fleetsim/src/root.zig) builds: holding[i] = i*111 over
    # 32 registers, input registers {1000,2000,3000,4000}, 32 coils all false
    # (discrete inputs share that same array), unit id 1. A sine drives
    # holding[0] only, so every operation below except the explicitly
    # non-deterministic one reads or writes registers the signal never touches
    # — which is what lets these captures be frozen.
    op("read_holding_1_8", True,
       lambda: call(client.read_holding_registers, address=1, count=8, device_id=1),
       regs([111, 222, 333, 444, 555, 666, 777, 888]))
    op("read_input_0_4", True,
       lambda: call(client.read_input_registers, address=0, count=4, device_id=1),
       regs([1000, 2000, 3000, 4000]))
    op("read_coils_0_16", True,
       lambda: call(client.read_coils, address=0, count=16, device_id=1),
       bits([False] * 16))
    op("read_discrete_0_8", True,
       lambda: call(client.read_discrete_inputs, address=0, count=8, device_id=1),
       bits([False] * 8))
    op("write_register_10", True,
       lambda: call(client.write_register, address=10, value=0x1234, device_id=1),
       written(None))
    op("read_holding_10_2", True,
       lambda: call(client.read_holding_registers, address=10, count=2, device_id=1),
       regs([0x1234, 1221]))
    op("write_coil_3", True,
       lambda: call(client.write_coil, address=3, value=True, device_id=1),
       written(None))
    op("read_coils_0_8_after_write", True,
       lambda: call(client.read_coils, address=0, count=8, device_id=1),
       bits([False, False, False, True, False, False, False, False]))

    def out_of_range(rr):
        # An exception reply is the most valuable single vector here: the
        # master must recognise the 0x80-flagged function code AND the
        # exception byte. Whatever code the device chooses is recorded rather
        # than asserted, so this pins the device's real answer instead of our
        # expectation of it.
        if not rr.isError():
            return {"unexpected_ok": str(rr)}, "expected an exception reply"
        return {"exception": str(rr), "exception_code": getattr(rr, "exception_code", None)}, None

    op("read_holding_200_4_oob", True,
       lambda: call(client.read_holding_registers, address=200, count=4, device_id=1),
       out_of_range)

    def report_id(rr):
        if rr.isError():
            return {"error": str(rr)}, None  # optional function; not a failure
        ident = getattr(rr, "identifier", b"")
        if isinstance(ident, (bytes, bytearray)):
            ident = bytes(ident).decode("latin-1")
        return {"identifier": ident, "status": getattr(rr, "status", None)}, None

    if hasattr(client, "report_slave_id"):
        op("report_slave_id", True,
           lambda: call(client.report_slave_id, device_id=1),
           report_id)

    def sine_range(rr):
        # holding[0] is driven by the sine (mean 500, amplitude 400), so its
        # VALUE is not freezable — only the fact that a live third party read
        # something in the driven band. Marked non-deterministic so the freeze
        # step cannot promote it into a golden by accident.
        if rr.isError():
            return {"error": str(rr)}, "master reports an error response"
        v = rr.registers[0]
        return {"registers": [v]}, None if 100 <= v <= 900 else "sine out of band: %d" % v

    op("read_holding_0_1_sine", False,
       lambda: call(client.read_holding_registers, address=0, count=1, device_id=1),
       sine_range)

    client.close()
    time.sleep(0.2)
    tap.stop()

    print(CAPTURE_BEGIN, flush=True)
    print(json.dumps({"master": "pymodbus", "version": version, "licence": licence}), flush=True)
    for rec in records:
        print(json.dumps(rec, separators=(",", ":")), flush=True)
    print(CAPTURE_END, flush=True)

    if failures:
        for f in failures:
            print("master: FAILURE %s" % f, flush=True)
        print("MODBUS_MASTER_FAIL", flush=True)
        return 1
    print("master: %d operations, all satisfied by pymodbus %s" % (len(records), version), flush=True)
    print("MODBUS_MASTER_OK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
