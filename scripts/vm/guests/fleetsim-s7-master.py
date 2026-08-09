#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Drive a `fleetsim`-simulated S7 CPU with a REAL python-snap7 client.

The S7comm sibling of `fleetsim-modbus-master.py`; that file's docstring
explains why these exist. python-snap7 is an independently-developed S7 stack —
and, from 3.0, a **pure-Python** one: 3.1.0 speaks TPKT/COTP/S7 over an
ordinary socket and needs no `libsnap7.so` at all, which is why nothing is
installed for it beyond the wheel (verified: `snap7.client.Client()` with no
`lib_location` connects, negotiates and reads).

## The write-back channel S7 offers

A DB write. The simulated CPU binds three data blocks:

    DB1   64 bytes, DB1.DBB[i] = i, with a sine driving DB1.DBD8
    DB3   a fixed typed record: REAL 21.5, INT -1234, DINT 100000, big-endian
    DB2   40 bytes, the verdict channel and nothing else

and `s7_verdict` in `modules/fleetsim/src/root.zig` asserts on DB2, against
constants recomputed from the fixture.

    DB2.DBD0  = 0x0000F157   "a real client was here" magic
    DB2.DBD4  = graded checks
    DB2.DBD8  = failures
    DB2.DBD12 = sum of DB1 bytes 16..47 as it read them
    DB2.DBD16 = DB3's REAL scaled by 10
    DB2.DBD20 = DB3's DINT minus DB3's INT
    DB2.DBD24 = the S7 return code it NAMED for a read of an unbound DB
    DB2.DBD28 = the S7 return code it NAMED for a read past the end of DB1
    DB2.DBD32 = the PDU length the DEVICE chose during setup-communication
    DB2.DBD36 = 1 iff no check failed — written in a SEPARATE, unconditional
                write so it is last, and so "a client was here and is unhappy"
                stays distinguishable from "no client ran"

Not an echo anywhere. The byte sum grades the read's offset and framing; the
scaled REAL and the `DINT - INT` difference grade typed big-endian decoding
and cannot be produced by handing either operand back; the two return codes
grade that the device tells "no such block" apart from "address out of range",
which a device that collapsed both into one answer would still pass a
single-error test with.

## Things about this pairing worth knowing before editing

* **`get_cpu_state()` does not work against this CPU** — it times out. The
  device answers `read_szl(0x0424)` (the CPU-state SZL) but not whatever
  request python-snap7's `get_cpu_state` issues, and `get_cpu_info` /
  `get_order_code` are refused outright with `Object does not exist (0x0a)`.
  The CPU going to STOP under the scheduled fault is therefore still asserted
  device-side by the Zig test, not through a mark. Worked around, not fixed:
  extending the responder's SZL coverage is a change to `modules/s7comm`.
* Connecting prints two `USERDATA response error 0xd401: Information function
  unavailable` lines from python-snap7's own probing. Harmless, and left
  visible rather than muted — a silenced warning is how a real failure hides.
* The client dials rack 0 / slot 2 on the test's port, not 102.

## Provenance

python-snap7 is MIT. Nothing from it is copied, translated or redistributed;
what is frozen into `modules/fleetsim/src/master_goldens.zig` is the byte
output of a session between two programs exchanging messages defined by the
published S7 communication frame layouts, plus what the client reported it
decoded.

Usage: fleetsim-s7-master.py <host> <port> [wait-seconds]

Output: a transcript, then one JSON object per operation between
FLEETSIM_CAPTURE_BEGIN/END, then S7_MASTER_DONE, then S7_MASTER_OK (exit 0) or
S7_MASTER_FAIL (exit 1). `run.sh` gates on the _DONE marker — presence only.
"""

import json
import socket
import struct
import sys
import threading
import time

CAPTURE_BEGIN = "FLEETSIM_CAPTURE_BEGIN"
CAPTURE_END = "FLEETSIM_CAPTURE_END"

MAGIC = 0x0000F157

# The fixture, mirrored from `test "live: a real S7 client drives a simulated
# CPU, and sees it go to STOP"`. Restated here only so the client can GRADE.
DB1_FROM = 16
DB1_LEN = 32
REAL_VALUE = 21.5
INT_VALUE = -1234
DINT_VALUE = 100000

RACK = 0
SLOT = 2


def split_tpkt(buf):
    """Split a TPKT stream into whole packets.

    RFC 1006's four-octet header carries a 16-bit big-endian total length that
    INCLUDES the header, so the vectors frozen from this are TPKTs rather than
    TCP segments.
    """
    out = []
    i = 0
    while i + 4 <= len(buf):
        if buf[i] != 0x03:
            break
        (ln,) = struct.unpack(">H", buf[i + 2 : i + 4])
        if ln < 4 or i + ln > len(buf):
            break
        out.append(buf[i : i + ln])
        i += ln
    return out, buf[i:]


class Tap:
    """A one-connection TCP relay that records both directions verbatim."""

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
                data = src.recv(8192)
            except OSError:
                break
            if not data:
                break
            with self.lock:
                if which == "tx":
                    self.tx_raw += data
                    msgs, self.tx_raw = split_tpkt(self.tx_raw)
                    self.tx.extend(msgs)
                else:
                    self.rx_raw += data
                    msgs, self.rx_raw = split_tpkt(self.rx_raw)
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


def main():
    host = sys.argv[1]
    port = int(sys.argv[2])
    wait_s = float(sys.argv[3]) if len(sys.argv) > 3 else 120.0

    import snap7
    from snap7.s7protocol import S7_RETURN_CODES
    from snap7.util import get_dint, get_int, get_real

    version = getattr(snap7, "__version__", "?")
    try:
        import importlib.metadata as md

        meta = md.metadata("python-snap7")
        licence = meta.get("License-Expression") or meta.get("License") or "?"
    except Exception:  # noqa: BLE001
        licence = "?"
    print("client: python-snap7 %s (licence: %s) -> %s:%d" % (version, licence, host, port), flush=True)

    # `S7_RETURN_CODES` is python-snap7's own table of S7 data-section return
    # codes. Reversing it turns the phrase python-snap7 CHOSE for a refused
    # read back into the numeric code, so the mark records the client's naming
    # rather than our reading of the raw byte.
    code_of = {v: k for k, v in S7_RETURN_CODES.items()}

    def named_return_code(exc):
        # python-snap7 formats these as "<operation> failed: <name> (0xNN)".
        text = str(exc)
        if ":" not in text:
            return -1
        tail = text.split(":", 1)[1].strip()
        name = tail.split(" (0x")[0].strip()
        return code_of.get(name, -1)

    tap = Tap(host, port)
    tap.start()

    client = snap7.client.Client()
    end = time.monotonic() + wait_s
    connected = False
    last = None
    while time.monotonic() < end:
        try:
            client.connect("127.0.0.1", RACK, SLOT, tap.port)
            connected = True
            break
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(0.3)
    if not connected:
        print("client: device never accepted a connection: %s" % last, flush=True)
        print("S7_MASTER_FAIL", flush=True)
        tap.stop()
        return 1

    records = []
    failures = []
    marks = {}

    # The COTP connect and Setup-communication are not GRADED, but they are
    # recorded: the frozen corpus replays from the responder's initial state,
    # and those two exchanges are what move it there.
    _tx, _rx = tap.drain()
    records.append({"op": "open_connection", "deterministic": True,
                    "request": [t.hex() for t in _tx],
                    "response": [r.hex() for r in _rx],
                    "decoded": {"connected": True}})

    def op(name, deterministic, fn, check):
        try:
            rr = fn()
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
            "client: %-24s req=%s resp=%s -> %s%s"
            % (
                name,
                ",".join(t.hex() for t in tx),
                ",".join(r.hex() for r in rx),
                decoded,
                "" if not problem else "  ** " + problem,
            ),
            flush=True,
        )

    # ── the reads that get graded ───────────────────────────────────────────
    def db1_window(rr, exc):
        if exc is not None:
            return {"raised": "%s: %s" % (type(exc).__name__, exc)}, "raised %s" % exc
        data = bytes(rr)
        marks["db1_sum"] = sum(data)
        return {"bytes": data.hex(), "sum": marks["db1_sum"]}, (
            None
            if len(data) == DB1_LEN
            else "expected %d bytes, got %d" % (DB1_LEN, len(data))
        )

    op("read_db1_window", True, lambda: client.db_read(1, DB1_FROM, DB1_LEN), db1_window)

    def db3_typed(rr, exc):
        # One read, three typed decodes, all done by python-snap7's own
        # accessors against the big-endian S7 process image.
        if exc is not None:
            return {"raised": "%s: %s" % (type(exc).__name__, exc)}, "raised %s" % exc
        buf = bytearray(rr)
        real = get_real(buf, 0)
        i16 = get_int(buf, 4)
        i32 = get_dint(buf, 6)
        marks["real"] = real
        marks["int"] = i16
        marks["dint"] = i32
        problem = None
        if abs(real - REAL_VALUE) > 1e-6:
            problem = "REAL expected %r" % REAL_VALUE
        elif i16 != INT_VALUE:
            problem = "INT expected %r" % INT_VALUE
        elif i32 != DINT_VALUE:
            problem = "DINT expected %r" % DINT_VALUE
        return {"real": real, "int": i16, "dint": i32}, problem

    op("read_db3_typed", True, lambda: client.db_read(3, 0, 16), db3_typed)

    def refused(mark):
        # The DEVICE picks the code; it is recorded here rather than asserted,
        # so this pins the device's real answer instead of our expectation of
        # it. The comparison happens on the Zig side.
        def check(rr, exc):
            if exc is None:
                return {"unexpected_ok": bytes(rr).hex()}, "expected a refusal"
            marks[mark] = named_return_code(exc)
            return {"raised": str(exc), "return_code": marks[mark]}, (
                None if marks[mark] >= 0 else "could not name the return code: %s" % exc
            )

        return check

    op("read_unbound_db99", True, lambda: client.db_read(99, 0, 4), refused("no_such_block"))
    op("read_past_end_of_db1", True, lambda: client.db_read(1, 60, 64), refused("invalid_address"))

    def pdu_len(rr, exc):
        if exc is not None:
            return {"raised": str(exc)}, "raised %s" % exc
        marks["pdu"] = int(rr)
        return {"pdu_length": marks["pdu"]}, None if marks["pdu"] > 0 else "no PDU length"

    op("negotiated_pdu_length", True, lambda: client.get_pdu_length(), pdu_len)

    # A DB write and its read-back, so the write path is exercised before the
    # verdict block depends on it. Deliberately NOT one of the graded decodes:
    # a write followed by a read of the same bytes is a round trip, and a round
    # trip proves the two paths share a convention, not that it is the right
    # one.
    def wrote_ok(rr, exc):
        if exc is not None:
            return {"raised": str(exc)}, "write refused: %s" % exc
        return {"ok": True}, None

    op("write_db2_probe", True,
       lambda: client.db_write(2, 0, bytearray(b"\x00\x00\x00\x00")), wrote_ok)

    def probe_readback(rr, exc):
        if exc is not None:
            return {"raised": str(exc)}, "raised %s" % exc
        return {"bytes": bytes(rr).hex()}, None

    op("read_db2_probe", True, lambda: client.db_read(2, 0, 4), probe_readback)

    # ── the verdict block ──────────────────────────────────────────────────
    graded = len(records)
    real = marks.get("real")
    i16 = marks.get("int")
    i32 = marks.get("dint")

    def u32(x):
        return int(x) & 0xFFFFFFFF

    verdict = [
        MAGIC,
        u32(graded),
        u32(len(failures)),
        u32(marks.get("db1_sum", 0)),
        u32(round(real * 10)) if real is not None else 0xFFFFFFFF,
        u32(i32 - i16) if (i32 is not None and i16 is not None) else 0xFFFFFFFF,
        u32(marks.get("no_such_block", -1)),
        u32(marks.get("invalid_address", -1)),
        u32(marks.get("pdu", 0)),
    ]
    all_passed = not failures

    payload = bytearray()
    for v in verdict:
        payload += struct.pack(">I", v)
    op("write_verdict", True, lambda: client.db_write(2, 0, payload), wrote_ok)

    # Written LAST, in its own write, and in BOTH outcomes.
    op("write_verdict_pass", True,
       lambda: client.db_write(2, 4 * len(verdict), bytearray(struct.pack(">I", 1 if all_passed else 0))),
       wrote_ok)

    try:
        client.disconnect()
        client.destroy()
    except Exception:  # noqa: BLE001
        pass
    time.sleep(0.2)
    tap.stop()

    print(CAPTURE_BEGIN, flush=True)
    print(json.dumps({"master": "python-snap7", "version": version, "licence": licence}), flush=True)
    for rec in records:
        print(json.dumps(rec, separators=(",", ":"), default=str), flush=True)
    print(CAPTURE_END, flush=True)

    print("client: verdict %s, all_passed=%s" % (verdict, all_passed), flush=True)
    print("S7_MASTER_DONE", flush=True)
    if failures:
        for f in failures:
            print("client: FAILURE %s" % f, flush=True)
        print("S7_MASTER_FAIL", flush=True)
        return 1
    print("client: %d operations, all satisfied by python-snap7 %s" % (len(records), version), flush=True)
    print("S7_MASTER_OK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
