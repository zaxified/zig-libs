#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Drive a `fleetsim`-simulated OPC UA server with a REAL asyncua client.

The OPC UA sibling of `fleetsim-modbus-master.py`; that file's docstring
explains why these exist. asyncua (the FreeOpcUa project) is a mature,
independently-developed OPC UA stack: it builds the SecureConversation, the
Session, the Read and Write service requests and decodes every DataValue on its
own terms, with no knowledge of how this repository produced the bytes.

## The write-back channel OPC UA offers

The `Write` service on a Variable whose AccessLevel includes CurrentWrite. The
simulated server carries nodes that exist only for this purpose:

    ns=1;s=verdict.0 .. verdict.7   Int32, the marks
    ns=1;s=verdict.pass             Boolean, written in BOTH outcomes

and `opcua_verdict` in `modules/fleetsim/src/root.zig` asserts on all of them.

    verdict.0 = 0x0000F10C   "a real client was here" magic
    verdict.1 = graded checks
    verdict.2 = failures
    verdict.3 = the Int32 measurement PLUS the Double setpoint scaled by 10
    verdict.4 = checksum of the String it decoded from ns=1;s=the.label
    verdict.5 = the numeric StatusCode it NAMED for an unknown node
    verdict.6 = checksum of namespace 1's URI, read from the server's
                NamespaceArray rather than assumed
    verdict.7 = the measurement's DataType numeric id x100 + its AccessLevel

**Why verdict.3 is a sum and not the value.** This protocol is where the echo
trap is sharpest. Reading an Int32 and writing that same Int32 back is exactly
the round trip a server whose integer codec is byte-swapped in BOTH directions
survives untouched: it hands the client a wrong number, the client hands the
wrong number back, the server decodes it wrongly again and stores the original.
Folding a Double-derived term into the mark breaks that symmetry — the two
codecs would have to be wrong in a way that cancels across different built-in
types, which is not what a codec bug looks like.

## Things worth knowing before editing

* `Client(url=...)` needs the endpoint URL the server advertises to match the
  one dialled, or the client chases an address nothing listens on. The Zig test
  builds `opc.tcp://<host>:<port>` from the endpoint it was given, so this
  holds automatically.
* asyncua raises `asyncua.ua.uaerrors.UaStatusCodeError` subclasses whose
  `.code` is the numeric StatusCode — that is what makes "the status the client
  named" a number here rather than a parsed string.

## Provenance

asyncua is LGPL-3.0-or-later. It is used here strictly as a **separate
process**: nothing from it is copied, translated, linked or redistributed, and
the repository ships no part of it. What is frozen into
`modules/fleetsim/src/master_goldens.zig` is the byte output of a session
between two programs exchanging messages defined by the public OPC UA
specification (OPC 10000-4/-6), plus what the client reported it decoded — the
same standing that the module's `NOTICE` records for every other counterpart.

Usage: fleetsim-opcua-master.py <host> <port> [wait-seconds]

Output: a transcript, then one JSON object per operation between
FLEETSIM_CAPTURE_BEGIN/END, then OPCUA_MASTER_DONE, then OPCUA_MASTER_OK
(exit 0) or OPCUA_MASTER_FAIL (exit 1). `run.sh` gates on the _DONE marker —
presence only.
"""

import asyncio
import json
import socket
import struct
import sys
import threading
import time

CAPTURE_BEGIN = "FLEETSIM_CAPTURE_BEGIN"
CAPTURE_END = "FLEETSIM_CAPTURE_END"

MAGIC = 0x0000F10C

# The fixture, mirrored from `test "live: a real OPC UA client drives a
# simulated server, and sees BadDeviceFailure"`. Restated here only so the
# client can GRADE; the Zig side recomputes its constants from its own copy.
MEASUREMENT = 42
SETPOINT = 21.5
LABEL = "zig-fleetsim"
NS_URI = "urn:zig-libs:fleetsim"


def split_uatcp(buf):
    """Split a UA-TCP stream into whole messages.

    Every UA-TCP message begins with a three-octet type, a one-octet chunk
    type and a 32-bit little-endian size that INCLUDES the eight-octet header
    (OPC 10000-6 §7.1.2), so the frozen vectors are messages rather than TCP
    segments.
    """
    out = []
    i = 0
    while i + 8 <= len(buf):
        (size,) = struct.unpack("<I", buf[i + 4 : i + 8])
        if size < 8 or i + size > len(buf):
            break
        out.append(buf[i : i + size])
        i += size
    return out, buf[i:]


class Tap:
    """A TCP relay that records both directions verbatim."""

    def __init__(self, host, port):
        self.host = host
        self.port_up = port
        self.lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lsock.bind(("127.0.0.1", 0))
        self.lsock.listen(4)
        self.port = self.lsock.getsockname()[1]
        self.lock = threading.Lock()
        self.tx_raw = b""
        self.rx_raw = b""
        self.tx = []
        self.rx = []
        self._tx_taken = 0
        self._rx_taken = 0
        self.socks = []
        self.stopped = False

    def start(self):
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while not self.stopped:
            try:
                down, _ = self.lsock.accept()
            except OSError:
                return
            try:
                up = socket.create_connection((self.host, self.port_up), timeout=5)
            except OSError:
                down.close()
                continue
            down.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            up.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.socks += [down, up]
            threading.Thread(target=self._pump, args=(down, up, "tx"), daemon=True).start()
            threading.Thread(target=self._pump, args=(up, down, "rx"), daemon=True).start()

    def _pump(self, src, dst, which):
        while not self.stopped:
            try:
                data = src.recv(16384)
            except OSError:
                break
            if not data:
                break
            with self.lock:
                if which == "tx":
                    self.tx_raw += data
                    msgs, self.tx_raw = split_uatcp(self.tx_raw)
                    self.tx.extend(msgs)
                else:
                    self.rx_raw += data
                    msgs, self.rx_raw = split_uatcp(self.rx_raw)
                    self.rx.extend(msgs)
            try:
                dst.sendall(data)
            except OSError:
                break
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def drain(self):
        time.sleep(0.05)
        with self.lock:
            tx = [bytes(m) for m in self.tx[self._tx_taken :]]
            rx = [bytes(m) for m in self.rx[self._rx_taken :]]
            self._tx_taken = len(self.tx)
            self._rx_taken = len(self.rx)
        return tx, rx

    def stop(self):
        self.stopped = True
        for s in self.socks + [self.lsock]:
            try:
                s.close()
            except OSError:
                pass


async def run(host, port, wait_s):
    import asyncua
    from asyncua import Client, ua

    version = getattr(asyncua, "__version__", "?")
    try:
        import importlib.metadata as md

        meta = md.metadata("asyncua")
        licence = meta.get("License-Expression") or meta.get("License") or "?"
    except Exception:  # noqa: BLE001
        licence = "?"
    print("client: asyncua %s (licence: %s) -> %s:%d" % (version, licence, host, port), flush=True)

    # The tap listens on 127.0.0.1 and forwards to the device. The server's
    # advertised endpoint URL names the DEVICE's port, so the client is pointed
    # at the tap and told not to follow the advertised URL.
    tap = Tap(host, port)
    tap.start()

    url = "opc.tcp://127.0.0.1:%d" % tap.port
    client = None
    end = time.monotonic() + wait_s
    last = None
    while time.monotonic() < end:
        try:
            client = Client(url=url, timeout=5)
            await client.connect()
            break
        except Exception as e:  # noqa: BLE001
            last = e
            client = None
            await asyncio.sleep(0.3)
    if client is None:
        print("client: server never completed a session: %s" % last, flush=True)
        print("OPCUA_MASTER_FAIL", flush=True)
        tap.stop()
        return 1

    records = []
    failures = []
    marks = {}

    # HEL/ACK/OpenSecureChannel/CreateSession/ActivateSession are not GRADED,
    # but they are recorded. Note the caveat in master_goldens.zig: unlike the
    # other protocols here, an OPC UA session is not replayable from bytes
    # alone — the server mints a nonce, a session id and an authentication
    # token, and every later request carries the token it was given.
    _tx, _rx = tap.drain()
    records.append({"op": "open_session", "deterministic": False,
                    "request": [t.hex() for t in _tx],
                    "response": [r.hex() for r in _rx],
                    "decoded": {"note": "session establishment; server-minted material"}})

    async def op(name, deterministic, coro_fn, check):
        try:
            rr = await coro_fn()
            decoded, problem = check(rr, None)
        except Exception as e:  # noqa: BLE001 - a client-side raise is a result too
            decoded, problem = check(None, e)
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
            "client: %-24s req=%d resp=%d -> %s%s"
            % (name, len(tx), len(rx), decoded, "" if not problem else "  ** " + problem),
            flush=True,
        )

    def node(sid):
        return client.get_node(ua.NodeId(sid, 1))

    def expect(value, mark=None, transform=None):
        def check(rr, exc):
            if exc is not None:
                return {"raised": "%s: %s" % (type(exc).__name__, exc)}, "raised %s" % exc
            got = transform(rr) if transform else rr
            if mark is not None:
                marks[mark] = got
            return {"value": got}, None if got == value else "expected %r, got %r" % (value, got)

        return check

    await op("read_measurement", True,
             lambda: node("the.measurement").read_value(),
             expect(MEASUREMENT, mark="measurement", transform=int))
    await op("read_setpoint", True,
             lambda: node("the.setpoint").read_value(),
             expect(SETPOINT, mark="setpoint", transform=float))
    await op("read_label", True,
             lambda: node("the.label").read_value(),
             expect(LABEL, mark="label", transform=str))

    def namespace_check(rr, exc):
        # Read from the server's own NamespaceArray rather than assumed: a
        # server that published the URI in the wrong slot, or truncated the
        # string, lands on a different checksum.
        if exc is not None:
            return {"raised": str(exc)}, "raised %s" % exc
        arr = list(rr)
        if len(arr) < 2:
            return {"array": arr}, "namespace array has no index 1"
        marks["ns_uri"] = str(arr[1])
        return {"array": arr, "ns1": marks["ns_uri"]}, (
            None if marks["ns_uri"] == NS_URI else "expected %r at index 1" % NS_URI
        )

    await op("read_namespace_array", True,
             lambda: client.get_node(ua.NodeId(ua.ObjectIds.Server_NamespaceArray)).read_value(),
             namespace_check)

    def attributes_check(rr, exc):
        if exc is not None:
            return {"raised": str(exc)}, "raised %s" % exc
        dt, access = rr
        # `dt` is a NodeId; its numeric identifier is the built-in type id the
        # server advertises for the measurement (Int32 = 6).
        marks["datatype_id"] = int(dt.Identifier)
        marks["access_level"] = int(access.Value.Value)
        return {"data_type": str(dt), "access_level": marks["access_level"]}, None

    async def read_attributes():
        n = node("the.measurement")
        dt = await n.read_data_type()
        access = await n.read_attribute(ua.AttributeIds.AccessLevel)
        return dt, access

    await op("read_measurement_attributes", True, read_attributes, attributes_check)

    def unknown_node_check(rr, exc):
        # The SERVER picks the status; asyncua raises a typed error whose
        # `.code` is the numeric StatusCode it named. Recorded rather than
        # asserted here — the Zig side is where it is compared.
        if exc is None:
            return {"unexpected_ok": str(rr)}, "expected a Bad status for an unknown node"
        code = getattr(exc, "code", None)
        if code is None:
            return {"raised": "%s: %s" % (type(exc).__name__, exc)}, "not a UA status error"
        marks["bad_node_status"] = int(code) & 0xFFFFFFFF
        return {"error": type(exc).__name__, "status": "0x%08X" % marks["bad_node_status"]}, None

    await op("read_unknown_node", True,
             lambda: node("no.such.node").read_value(),
             unknown_node_check)

    # ── the verdict block ──────────────────────────────────────────────────
    graded = len(records)

    def i32(x):
        x = int(x) & 0xFFFFFFFF
        return x - (1 << 32) if x >= (1 << 31) else x

    measurement = marks.get("measurement")
    setpoint = marks.get("setpoint")
    verdict = [
        MAGIC,
        i32(graded),
        i32(len(failures)),
        i32(measurement + round(setpoint * 10))
        if (measurement is not None and setpoint is not None)
        else -1,
        i32(sum(ord(c) for c in marks.get("label", ""))),
        i32(marks.get("bad_node_status", 0)),
        i32(sum(ord(c) for c in marks.get("ns_uri", ""))),
        i32(marks.get("datatype_id", 0) * 100 + marks.get("access_level", 0)),
    ]
    all_passed = not failures

    write_errors = []
    for i, value in enumerate(verdict):
        try:
            await node("verdict.%d" % i).write_value(ua.Variant(value, ua.VariantType.Int32))
        except Exception as e:  # noqa: BLE001
            write_errors.append("verdict.%d: %s" % (i, e))

    # Written LAST and unconditionally, both ways: an explicit `false` here is
    # the client saying "I was here and I am not satisfied", which is a
    # different fact from "no client ever connected" (magic absent).
    try:
        await node("verdict.pass").write_value(ua.Variant(all_passed, ua.VariantType.Boolean))
    except Exception as e:  # noqa: BLE001
        write_errors.append("verdict.pass: %s" % e)

    tx, rx = tap.drain()
    records.append(
        {
            "op": "write_verdict",
            "deterministic": True,
            "request": [t.hex() for t in tx],
            "response": [r.hex() for r in rx],
            "decoded": {"verdict": verdict, "pass": all_passed, "write_errors": write_errors},
        }
    )
    if write_errors:
        failures.append("write_verdict: %s" % write_errors[0])
    print("client: write_verdict -> %s pass=%s errors=%s"
          % (verdict, all_passed, write_errors), flush=True)

    try:
        await client.disconnect()
    except Exception:  # noqa: BLE001
        pass
    await asyncio.sleep(0.2)
    tap.stop()

    print(CAPTURE_BEGIN, flush=True)
    print(json.dumps({"master": "asyncua", "version": version, "licence": licence}), flush=True)
    for rec in records:
        print(json.dumps(rec, separators=(",", ":"), default=str), flush=True)
    print(CAPTURE_END, flush=True)

    print("client: verdict %s, all_passed=%s" % (verdict, all_passed), flush=True)
    print("OPCUA_MASTER_DONE", flush=True)
    if failures:
        for f in failures:
            print("client: FAILURE %s" % f, flush=True)
        print("OPCUA_MASTER_FAIL", flush=True)
        return 1
    print("client: %d operations, all satisfied by asyncua %s" % (len(records), version), flush=True)
    print("OPCUA_MASTER_OK", flush=True)
    return 0


def main():
    host = sys.argv[1]
    port = int(sys.argv[2])
    wait_s = float(sys.argv[3]) if len(sys.argv) > 3 else 120.0
    return asyncio.run(run(host, port, wait_s))


if __name__ == "__main__":
    sys.exit(main())
