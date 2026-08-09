#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Drive a `fleetsim`-simulated BACnet device with a REAL bacpypes3 client.

The BACnet sibling of `fleetsim-modbus-master.py`; that file's docstring
explains *why* all of these exist, and is worth reading first. bacpypes3 is the
reference Python BACnet stack, developed by the author of the ASHRAE 135
Python ecosystem and with no knowledge of this repository — it encodes the
requests and decodes the replies on its own terms, so it can disagree with us,
which is the whole definition of an anchor.

## The write-back channel BACnet offers

`WriteProperty` (Clause 15.9), on properties the device marks writable. The
simulated device carries objects that exist only for this purpose:

    analog-value,1 .. analog-value,8   present-value (REAL), one per mark
    binary-value,1                     present-value, the pass mark

and `bacnet_verdict` in `modules/fleetsim/src/root.zig` asserts on all of them,
against constants recomputed from the fixture.

    analog-value,1 = 61882      "a real client was here" magic
    analog-value,2 = graded checks
    analog-value,3 = failures
    analog-value,4 = analog-input,1 present-value scaled by 10
    analog-value,5 = checksum of the object-name string it decoded
    analog-value,6 = the four status flags it unpacked, packed LSB-first
    analog-value,7 = the device instance it learned from the I-Am
    analog-value,8 = the BACnet error code IT named for a missing property
    binary-value,1 = active iff no check failed, written in BOTH outcomes

Eight objects rather than one array property: that is what a stock client
writes without being told about array indices, and a wrong object instance then
lands on a wrong slot rather than silently overwriting a neighbour.

Nothing here is an echo. A REAL scaled to a tenth-integer grades the float
encoding without letting a symmetric error cancel; a checksum grades the
character string's framing; a bitmap grades the bit order of a BACnetStatusFlags
*as a third party unpacked it*, which is why the fixture deliberately sets one
of those bits — an all-zero bit string decodes identically whichever way round
a client reads it, and would grade nothing.

## Things about bacpypes3 0.0.106 worth knowing before editing this

* **Its protocol errors are `BaseException`, not `Exception`.**
  `bacpypes3.apdu.ErrorRejectAbortNack` derives straight from `BaseException`,
  so a `try/except Exception` around a read silently fails to catch a perfectly
  ordinary `unknown-property` and takes the process down. Caught by name below.
* **`Application.from_args`** with `SimpleArgumentParser` is the supported way
  to stand one up; `from_object_list` builds an application with no link layer.
* The client needs a UDP port of its own, so it binds one — it is a BACnet
  device in its own right, which is what makes `who_is` meaningful.

## Provenance

bacpypes3 is MIT. Nothing from it is copied, translated or redistributed; what
is frozen into `modules/fleetsim/src/master_goldens.zig` is the byte output of
a session between two programs exchanging messages defined by the public ASHRAE
135 standard, plus what the client reported it decoded.

Usage: fleetsim-bacnet-master.py <host> <port> [wait-seconds]

Output: a transcript, then one JSON object per operation between
FLEETSIM_CAPTURE_BEGIN/END, then BACNET_MASTER_DONE, then BACNET_MASTER_OK
(exit 0) or BACNET_MASTER_FAIL (exit 1). `run.sh` gates on the _DONE marker —
presence only; the grade is the Zig suite's job.
"""

import asyncio
import json
import socket
import sys
import threading
import time

CAPTURE_BEGIN = "FLEETSIM_CAPTURE_BEGIN"
CAPTURE_END = "FLEETSIM_CAPTURE_END"

MAGIC = 61882

# The fixture, mirrored from `test "live: a real BACnet client discovers a
# simulated device over UDP"`. Restated here only so the client can GRADE; the
# Zig side recomputes its constants from its own copy.
AI_NAME = "Zone-1-Temp"
PRESENT_VALUE = 21.5
UNITS = "degrees-celsius"
DEVICE_INSTANCE = 260001
VENDOR_NAME = "zig-libs"
# The four BACnetStatusFlags in their standard order, under the names
# bacpypes3's own `_bitstring_names` map uses. Indexing a BitString BY NAME is
# what makes the mark grade the name-to-position mapping as well as the bit
# order; `getattr` does NOT work here — BitString subclasses `list` and the
# attributes of that name are class-level bit indices, so `rr.fault` is the
# integer 1 and reads as truthy no matter what the device sent. That mistake
# produced a bitmap of 6 for a device that had set exactly one flag.
FLAG_ORDER = ["in-alarm", "fault", "overridden", "out-of-service"]

CLIENT_INSTANCE = 599
CLIENT_ADDRESS = "127.0.0.1:47809"


def wait_device(host, port, seconds):
    """Wait until the simulated device's UDP socket exists.

    UDP has no connect handshake to wait on, so this leans on the one signal
    loopback does give: a datagram sent to a port nothing is bound to earns an
    ICMP port-unreachable, and on a *connected* UDP socket that surfaces as
    ECONNREFUSED on the NEXT send. Two sends with a pause between them is
    therefore a real liveness probe, not a formality — which matters here
    because the live tests run one after another and this device is the last of
    them to bind.
    """
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((host, port))
            s.send(b"\x00")
            time.sleep(0.2)
            s.send(b"\x00")  # a refused first datagram is reported on the next
            s.close()
            return True, None
        except OSError as e:
            last = e
            s.close()
            time.sleep(0.25)
    return False, last


class UdpTap:
    """A UDP relay that records both directions verbatim.

    BACnet/IP is datagrams, so there is no stream to reassemble: every recv IS
    a BVLL frame, which is what gets frozen. Like the TCP taps in the sibling
    scripts this is a plain socket relay and depends on no bacpypes3 internal,
    so a version bump cannot silently change what is captured, and it records
    what actually crossed the wire rather than what a library said it was about
    to send.

    One subtlety this protocol forces: the client must be pointed at the tap,
    and the device answers to whatever source address it saw — the tap's — so
    the relay keeps the last client address and sends replies back there. That
    is exactly what a BACnet/IP router does, and it is why the client's view of
    "the device address" is the tap's port.
    """

    def __init__(self, host, port):
        self.up_addr = (host, port)
        self.down = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.down.bind(("127.0.0.1", 0))
        self.port = self.down.getsockname()[1]
        self.up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.up.bind(("127.0.0.1", 0))
        self.client_addr = None
        self.lock = threading.Lock()
        self.tx = []
        self.rx = []
        self._tx_taken = 0
        self._rx_taken = 0
        self.stopped = False

    def start(self):
        threading.Thread(target=self._pump_down, daemon=True).start()
        threading.Thread(target=self._pump_up, daemon=True).start()

    def _pump_down(self):
        while not self.stopped:
            try:
                data, addr = self.down.recvfrom(4096)
            except OSError:
                return
            self.client_addr = addr
            with self.lock:
                self.tx.append(data)
            try:
                self.up.sendto(data, self.up_addr)
            except OSError:
                pass

    def _pump_up(self):
        while not self.stopped:
            try:
                data, _ = self.up.recvfrom(4096)
            except OSError:
                return
            with self.lock:
                self.rx.append(data)
            if self.client_addr is not None:
                try:
                    self.down.sendto(data, self.client_addr)
                except OSError:
                    pass

    def drain(self):
        time.sleep(0.05)
        with self.lock:
            tx = [bytes(d) for d in self.tx[self._tx_taken :]]
            rx = [bytes(d) for d in self.rx[self._rx_taken :]]
            self._tx_taken = len(self.tx)
            self._rx_taken = len(self.rx)
        return tx, rx

    def stop(self):
        self.stopped = True
        for s in (self.down, self.up):
            try:
                s.close()
            except OSError:
                pass


async def run(host, port, wait_s):
    import bacpypes3
    from bacpypes3.apdu import ErrorRejectAbortNack
    from bacpypes3.app import Application
    from bacpypes3.argparse import SimpleArgumentParser
    from bacpypes3.pdu import Address
    from bacpypes3.primitivedata import ObjectIdentifier

    version = getattr(bacpypes3, "__version__", "?")
    try:
        import importlib.metadata as md

        meta = md.metadata("bacpypes3")
        licence = meta.get("License-Expression") or meta.get("License") or "?"
    except Exception:  # noqa: BLE001
        licence = "?"
    print("client: bacpypes3 %s (licence: %s) -> %s:%d" % (version, licence, host, port), flush=True)

    ok, err = wait_device(host, port, wait_s)
    if not ok:
        print("client: device socket never came up: %s" % err, flush=True)
        print("BACNET_MASTER_FAIL", flush=True)
        return 1

    parser = SimpleArgumentParser()
    args = parser.parse_args(
        ["--address", CLIENT_ADDRESS, "--instance", str(CLIENT_INSTANCE), "--name", "fleetsim-probe"]
    )
    app = Application.from_args(args)
    tap = UdpTap(host, port)
    tap.start()
    dev = Address("127.0.0.1:%d" % tap.port)

    records = []
    failures = []
    marks = {}

    def record(name, deterministic, decoded, problem):
        tx, rx = tap.drain()
        records.append(
            {
                "op": name,
                "deterministic": deterministic,
                "request": [t.hex() for t in tx],
                "response": [r.hex() for r in rx],
                "decoded": decoded,
            }
        )
        if problem:
            failures.append("%s: %s" % (name, problem))
        print(
            "client: %-30s -> %s%s" % (name, decoded, "" if not problem else "  ** " + problem),
            flush=True,
        )

    async def op(name, deterministic, coro_fn, check):
        try:
            rr = await coro_fn()
            decoded, problem = check(rr, None)
        # ErrorRejectAbortNack is a BaseException in bacpypes3 — see the module
        # docstring. Catching Exception here would let an ordinary protocol
        # error kill the process instead of being graded. The `check` call is
        # inside the same try on purpose: a decoder that raises while grading
        # is a result too, and must not take the process down before the
        # verdict block is written.
        except (ErrorRejectAbortNack, Exception) as e:  # noqa: BLE001
            decoded, problem = check(None, e)
        record(name, deterministic, decoded, problem)

    async def read(oid, prop):
        return await app.read_property(dev, ObjectIdentifier(oid), prop)

    def expect(value, mark=None, transform=None):
        def check(rr, exc):
            if exc is not None:
                return {"raised": "%s: %s" % (type(exc).__name__, exc)}, "raised %s" % exc
            got = transform(rr) if transform else rr
            if mark is not None:
                marks[mark] = got
            return {"value": str(rr), "as_graded": got}, (
                None if got == value else "expected %r, got %r" % (value, got)
            )

        return check

    # ── the reads that get graded ───────────────────────────────────────────
    await op("read_present_value", True,
             lambda: read("analog-input,1", "present-value"),
             expect(PRESENT_VALUE, mark="present_value", transform=float))
    await op("read_object_name", True,
             lambda: read("analog-input,1", "object-name"),
             expect(AI_NAME, mark="object_name", transform=str))
    await op("read_units", True,
             lambda: read("analog-input,1", "units"),
             expect(UNITS, transform=lambda v: str(v).split(":")[-1].strip(" >")))
    await op("read_vendor_name", True,
             lambda: read("device,%d" % DEVICE_INSTANCE, "vendor-name"),
             expect(VENDOR_NAME, transform=str))

    def status_flags_check(rr, exc):
        # The bit order is the point: bacpypes3 unpacks BACnetStatusFlags into
        # named booleans, and the mark is what IT set, packed LSB-first here.
        # A device that emitted the bits the other way round lands on a
        # different number.
        if exc is not None:
            return {"raised": str(exc)}, "raised %s" % exc
        bits = {}
        for name in FLAG_ORDER:
            bits[name] = bool(rr[name])
        bitmap = 0
        for i, name in enumerate(FLAG_ORDER):
            if bits[name]:
                bitmap |= 1 << i
        marks["status_bitmap"] = bitmap
        return {"flags": bits, "bitmap": bitmap}, None

    await op("read_status_flags", True,
             lambda: read("analog-input,1", "status-flags"),
             status_flags_check)

    def who_is_check(rr, exc):
        # The device instance the CLIENT learned, not the one it was told to
        # ask about — an I-Am that carried the wrong instance, or encoded the
        # 260001 object identifier wrongly, lands on a different number.
        if exc is not None:
            return {"raised": str(exc)}, "raised %s" % exc
        if not rr:
            return {"i_am": []}, "no I-Am received"
        seen = []
        for iam in rr:
            oid = iam.iAmDeviceIdentifier
            seen.append(str(oid))
            marks["device_instance"] = int(oid[1])
            marks["vendor_id"] = int(iam.vendorID)
        return {"i_am": seen, "instance": marks.get("device_instance"),
                "vendor_id": marks.get("vendor_id")}, (
            None if marks.get("device_instance") == DEVICE_INSTANCE
            else "expected device instance %d" % DEVICE_INSTANCE
        )

    await op("who_is", True, lambda: app.who_is(address=dev), who_is_check)

    def missing_property_check(rr, exc):
        # The device, not the client, picks the code. Recorded rather than
        # asserted here, so this pins the device's real answer instead of our
        # expectation of it; the Zig side is where it is compared.
        if exc is None:
            return {"unexpected_ok": str(rr)}, "expected an Error for a property the device lacks"
        if not isinstance(exc, ErrorRejectAbortNack):
            return {"raised": "%s: %s" % (type(exc).__name__, exc)}, "expected a BACnet Error"
        cls = getattr(exc, "errorClass", None)
        code = getattr(exc, "errorCode", None)
        marks["error_class"] = str(cls)
        marks["error_code_name"] = str(code)
        marks["error_code"] = int(code) if code is not None else -1
        return {"error_class": str(cls), "error_code": str(code),
                "error_code_number": marks["error_code"]}, None

    await op("read_missing_property", True,
             lambda: read("analog-input,1", "description"),
             missing_property_check)

    # ── the verdict block ──────────────────────────────────────────────────
    graded = len(records)
    pv = marks.get("present_value")
    name = marks.get("object_name", "")
    verdict = [
        MAGIC,
        graded,
        len(failures),
        int(round(pv * 10)) if pv is not None else -1,
        sum(ord(c) for c in name),
        marks.get("status_bitmap", -1),
        marks.get("device_instance", -1),
        marks.get("error_code", -1),
    ]
    all_passed = not failures

    from bacpypes3.primitivedata import Real

    write_errors = []
    for i, value in enumerate(verdict):
        oid = "analog-value,%d" % (i + 1)
        try:
            await app.write_property(dev, ObjectIdentifier(oid), "present-value", Real(float(value)))
        except (ErrorRejectAbortNack, Exception) as e:  # noqa: BLE001
            write_errors.append("%s: %s" % (oid, e))

    # Written LAST and unconditionally, both ways: an explicit `inactive` here
    # is the client saying "I was here and I am not satisfied", which is a
    # different fact from "no client ever connected" (magic absent).
    try:
        await app.write_property(
            dev, ObjectIdentifier("binary-value,1"), "present-value",
            "active" if all_passed else "inactive",
        )
    except (ErrorRejectAbortNack, Exception) as e:  # noqa: BLE001
        write_errors.append("binary-value,1: %s" % e)

    record("write_verdict", True,
           {"verdict": verdict, "pass": all_passed, "write_errors": write_errors},
           None if not write_errors else "verdict write refused: %s" % write_errors[0])

    app.close()
    await asyncio.sleep(0.2)
    tap.stop()

    print(CAPTURE_BEGIN, flush=True)
    print(json.dumps({"master": "bacpypes3", "version": version, "licence": licence}), flush=True)
    for rec in records:
        print(json.dumps(rec, separators=(",", ":"), default=str), flush=True)
    print(CAPTURE_END, flush=True)

    print("client: verdict %s, all_passed=%s" % (verdict, all_passed), flush=True)
    print("BACNET_MASTER_DONE", flush=True)
    if failures:
        for f in failures:
            print("client: FAILURE %s" % f, flush=True)
        print("BACNET_MASTER_FAIL", flush=True)
        return 1
    print("client: %d operations, all satisfied by bacpypes3 %s" % (len(records), version), flush=True)
    print("BACNET_MASTER_OK", flush=True)
    return 0


def main():
    host = sys.argv[1]
    port = int(sys.argv[2])
    wait_s = float(sys.argv[3]) if len(sys.argv) > 3 else 120.0
    return asyncio.run(run(host, port, wait_s))


if __name__ == "__main__":
    sys.exit(main())
