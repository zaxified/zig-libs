#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Drive a `fleetsim`-simulated EtherNet/IP adapter with a REAL pycomm3 master.

The EtherNet/IP sibling of `fleetsim-modbus-master.py`; read that file's
docstring first, because the *reason* both exist is the same one and is
written out there in full. In short: `modules/fleetsim`'s live tests are its
only external anchor, a master that merely connects proves nothing, so this
script grades every read in its own number domain and commands the marks back
into the device where the Zig test asserts on them.

## The write-back channel EtherNet/IP offers

CIP `Write Tag` (service 0x4D) by symbolic name. The simulated adapter serves
two tags that exist only for this purpose:

    Verdict      DINT[8]   the marks
    VerdictPass  DINT      1 iff the master is satisfied, written either way

and `enip_verdict` in `modules/fleetsim/src/root.zig` asserts on both, against
constants recomputed from the fixture rather than restated.

    Verdict[0] = 0x0000F1E9   "a real master was here" magic
    Verdict[1] = graded checks
    Verdict[2] = failures
    Verdict[3] = sum of the six-element `Counts` DINT array it decoded
    Verdict[4] = `Setpoint` REAL scaled by 10 and rounded
    Verdict[5] = checksum of the ASCII product name from ListIdentity
    Verdict[6] = the CIP general status it NAMED for a tag the device lacks
    Verdict[7] = sum of `Counts[2]{3}` — a three-element slice from element 2

Sums, a scaled float and a checksum — never an echo. An echo is the inverse of
the read, so a device whose encoder and decoder shared the same wrong
convention would round-trip it cleanly and the mutation would hide inside it.
Verdict[7] is there specifically to grade array-element addressing, which a
whole-array read cannot distinguish from a device that ignores the member
segment.

## Two things about pycomm3 1.2.16 that this script has to work around

Both were found by running it, and both are recorded here rather than in a
commit message because the next person to touch this file will hit them.

1. **`LogixDriver.open()` cannot complete against this adapter.** Its
   `_initialize_driver` calls `get_plc_name()` (CIP class 0x64, the Program
   Name object) and `get_tag_list()` (class 0x6B Symbol Object enumerated with
   service 0x55 `Get_Instance_Attribute_List`). `modules/enip`'s adapter
   implements neither, so both come back `0x05 Path destination unknown` and
   pycomm3 raises. The driver below therefore overrides `_initialize_driver`
   to keep the part the adapter *does* answer — `get_plc_info()`, a real
   Get_Attributes_All on the Identity object, decoded by pycomm3 — and to
   supply the tag table instead of uploading it.

   That is a deliberate line, and it is worth being precise about which side
   of it the oracle lives on. What is supplied is *configuration*: tag names
   and their CIP type codes, i.e. exactly what a tag upload would have
   returned. What is NOT supplied, and what makes this an anchor, is every
   byte on the wire: pycomm3 encodes the symbolic EPATH, frames the CIP
   request, and decodes the reply's type code and payload with no knowledge of
   how this repository produced them. A wrong type code, a wrong endianness, a
   wrong element count or a wrong array offset all land on a wrong number
   here.

2. **A single-tag `write()` emits a duplicated PDU.** `RequestPacket.
   _setup_message` appends to `self._msg` and never resets it, while
   `LogixDriver._write_build_single_request` calls `build_message()` and then
   sets `request._msg_setup = False`, so the message is composed twice and the
   second copy is concatenated onto the first. Captured off the wire against
   this adapter: `...b1 0028 0100 <4d 04 9105 "Speed" 00 c400 0100 92100000>
   0100 <4d 04 9105 "Speed" 00 c400 0100 92100000>` — a 40-octet connected data
   item carrying the same Write Tag twice. Our adapter refuses it with
   `0x17 Too much data`, which is the correct reading of a request whose
   declared payload runs past the tag.

   The multi-tag path is unaffected: `MultiServiceRequestPacket` composes its
   members with `tag_only_message()`, which does not go through
   `build_message()`. So every write below is issued as a **pair**, which is
   also what the verdict block wants anyway.

   Not reported upstream — the repo's standing rule is to work around and
   record. Do not "fix" this by loosening the adapter: a trailing second copy
   of a request genuinely is too much data, and accepting it would be the
   defect.

## Provenance

pycomm3 is MIT. Nothing from it is copied, translated or redistributed; what
is frozen into `modules/fleetsim/src/master_goldens.zig` is the byte output of
a session between two programs exchanging messages defined by the public ODVA
CIP Volume 1 and Volume 2 specifications, plus what the master reported it
decoded.

Usage: fleetsim-enip-master.py <host> <port> [wait-seconds]

Output: a transcript, then one JSON object per operation between
FLEETSIM_CAPTURE_BEGIN/END, then ENIP_MASTER_DONE, then ENIP_MASTER_OK
(exit 0) or ENIP_MASTER_FAIL (exit 1).

`run.sh` gates on ENIP_MASTER_DONE — presence only. The grade is the Zig
suite's job; a grade enforced by a shell `grep` is what F1b was about.
"""

import json
import socket
import struct
import sys
import threading
import time

CAPTURE_BEGIN = "FLEETSIM_CAPTURE_BEGIN"
CAPTURE_END = "FLEETSIM_CAPTURE_END"

MAGIC = 0x0000F1E9

# The fixture, mirrored from `test "live: a real EtherNet/IP master drives a
# simulated adapter"`. Restated here only so the master can GRADE; the Zig side
# recomputes its constants from its own copy, so the two have to agree.
COUNTS = [7, 140, 3300, 41000, 555, 66]
SETPOINT = 21.5
SPEED = 1500
PRODUCT_NAME = "zig-fleetsim adapter"


def split_enip(buf):
    """Split an EtherNet/IP encapsulation stream into whole messages.

    The 24-octet header's `length` field at offset 2 counts the data after the
    header. Reassembling from it — rather than from read boundaries — is what
    makes the frozen vectors frames instead of TCP segments.
    """
    out = []
    i = 0
    while i + 24 <= len(buf):
        (ln,) = struct.unpack("<H", buf[i + 2 : i + 4])
        if i + 24 + ln > len(buf):
            break
        out.append(buf[i : i + 24 + ln])
        i += 24 + ln
    return out, buf[i:]


class Tap:
    """A one-connection TCP relay that records both directions verbatim.

    Same construction as the Modbus lane's: a plain socket relay depends on no
    pycomm3 internal, so a version bump cannot silently change what is
    captured, and it records what crossed the wire rather than what a library
    said it was about to send.
    """

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
                    msgs, self.tx_raw = split_enip(self.tx_raw)
                    self.tx.extend(msgs)
                else:
                    self.rx_raw += data
                    msgs, self.rx_raw = split_enip(self.rx_raw)
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


def wait_device(host, port, seconds):
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.close()
            return True, None
        except OSError as e:
            last = e
            time.sleep(0.25)
    return False, last


def main():
    host = sys.argv[1]
    port = int(sys.argv[2])
    wait_s = float(sys.argv[3]) if len(sys.argv) > 3 else 120.0

    import pycomm3
    from pycomm3 import LogixDriver, CIPDriver
    from pycomm3.const import BASE_TAG_BIT
    from pycomm3.cip import SERVICE_STATUS

    version = getattr(pycomm3, "__version__", "?")
    try:
        import importlib.metadata as md

        meta = md.metadata("pycomm3")
        licence = meta.get("License-Expression") or meta.get("License") or "?"
    except Exception:  # noqa: BLE001
        licence = "?"
    print("master: pycomm3 %s (licence: %s) -> %s:%d" % (version, licence, host, port), flush=True)

    ok, err = wait_device(host, port, wait_s)
    if not ok:
        print("master: device never accepted a connection: %s" % err, flush=True)
        print("ENIP_MASTER_FAIL", flush=True)
        return 1

    # `SERVICE_STATUS` is pycomm3's own CIP general-status table. Reversing it
    # turns the string pycomm3 CHOSE for the reply back into the numeric code,
    # so the mark records the master's naming and not our reading of the raw
    # byte. (Its 0x05 entry is the long Rockwell wording, "Destination unknown,
    # class unsupported, instance undefined or structure element undefined" —
    # which is why the reverse map, not a substring match, is what is used.)
    status_code_of = {v: k for k, v in SERVICE_STATUS.items() if isinstance(v, str)}

    def status_code(msg):
        """The numeric general status behind the sentence pycomm3 produced.

        pycomm3 concatenates the extended status onto the table entry, e.g.
        "Destination unknown, … (see extended status) - Extended status out of
        memory  (05, 00)", so an exact reverse lookup misses. The head of the
        string — up to that suffix — is verbatim the `SERVICE_STATUS` value.
        """
        if not msg:
            return -1
        if msg in status_code_of:
            return status_code_of[msg]
        head = msg.split(" - Extended status")[0].strip()
        return status_code_of.get(head, -1)

    tap = Tap(host, port)
    tap.start()

    class Driver(LogixDriver):
        """`LogixDriver` minus the two services this adapter does not serve.

        See the module docstring, point 1: `get_plc_name` (class 0x64) and
        `get_tag_list` (class 0x6B / service 0x55) are not implemented by
        `modules/enip`, so a stock `open()` raises before any tag is read.
        `get_plc_info` IS kept — it is a real Get_Attributes_All on the
        Identity object, decoded by pycomm3.
        """

        def _initialize_driver(self, init_tags, init_program_tags, tag_namespace_filter=""):
            self._info = self.get_plc_info()
            # Instance-id addressing is a Logix v21+ optimisation; this adapter
            # addresses tags symbolically, which is also what makes the EPATH
            # encoding part of the oracle.
            self._cfg["use_instance_ids"] = False
            self._tags = {}

    def mktag(plc, name, code, count=0):
        """Build one tag-table entry through pycomm3's OWN `_create_tag`.

        The input is a symbol_type word exactly as a Symbol Object upload would
        have produced it — atomic type code in the low byte, array dimension
        count in bits 13-14 — so the derived `tag_info` (type class, element
        size, dimensions) is pycomm3's, not ours.
        """
        sym = code | ((1 << 13) if count else 0)
        raw = {
            "instance_id": 0,
            "symbol_type": sym,
            "symbol_address": 0,
            "symbol_object_address": 0,
            "software_control": BASE_TAG_BIT,
            "dimensions": [count, 0, 0],
            "external_access": "Read/Write",
        }
        return plc._create_tag(name, raw)

    records = []
    failures = []
    marks = {}

    def record(name, deterministic, tx, rx, decoded, problem):
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
            "master: %-26s req=%s resp=%s -> %s%s"
            % (
                name,
                ",".join(t.hex() for t in tx),
                ",".join(r.hex() for r in rx),
                decoded,
                "" if not problem else "  ** " + problem,
            ),
            flush=True,
        )

    def op(name, deterministic, fn, check):
        try:
            rr = fn()
        except Exception as e:  # noqa: BLE001
            tx, rx = tap.drain()
            record(name, deterministic, tx, rx, {"raised": "%s: %s" % (type(e).__name__, e)},
                   "raised %s" % e)
            return
        tx, rx = tap.drain()
        decoded, problem = check(rr)
        record(name, deterministic, tx, rx, decoded, problem)

    DINT = 0xC4
    REAL = 0xCA

    # ── identity, over the same tap ────────────────────────────────────────
    # `list_identity` is a whole encapsulation command of its own (0x0063) and
    # its reply carries the product name as a SHORT_STRING. pycomm3 decodes it;
    # the checksum of what it decoded becomes a mark, so a device that
    # mis-framed the name — wrong length byte, off-by-one — lands on a wrong
    # number rather than on a string nobody looked at.
    def identity_check(ident):
        if not ident:
            return {"identity": None}, "list_identity returned nothing"
        name = ident.get("product_name", "")
        marks["name_checksum"] = sum(ord(c) for c in name)
        marks["identity_status"] = int.from_bytes(ident.get("status", b"\x00\x00"), "little")
        return {"product_name": name, "revision": ident.get("revision"),
                "serial": ident.get("serial"), "status": marks["identity_status"]}, (
            None if name == PRODUCT_NAME else "expected product name %r" % PRODUCT_NAME
        )

    op("list_identity", True,
       lambda: CIPDriver.list_identity("127.0.0.1:%d" % tap.port),
       identity_check)

    plc = Driver("127.0.0.1:%d" % tap.port, init_tags=False, init_program_tags=False)
    if not plc.open():
        print("master: could not open a session through the capture tap", flush=True)
        print("ENIP_MASTER_FAIL", flush=True)
        tap.stop()
        return 1
    # The session/forward-open handshake is not GRADED, but it is recorded:
    # the frozen corpus has to replay from the adapter's initial state, and
    # RegisterSession / Forward_Open are what move it there. Dropping them
    # would make the corpus unreplayable and quietly turn it into prose.
    _tx, _rx = tap.drain()
    records.append({"op": "open_session", "deterministic": True,
                    "request": [t.hex() for t in _tx],
                    "response": [r.hex() for r in _rx],
                    "decoded": {"info": str(plc.info)}})

    plc._tags = {
        "Speed": mktag(plc, "Speed", DINT),
        "Counts": mktag(plc, "Counts", DINT, count=len(COUNTS)),
        "Setpoint": mktag(plc, "Setpoint", REAL),
        "Verdict": mktag(plc, "Verdict", DINT, count=8),
        "VerdictPass": mktag(plc, "VerdictPass", DINT),
        # Declared to the master but NOT served by the device — the only way to
        # make the device itself choose an error code, rather than pycomm3
        # refusing the request client-side because the name is unknown to it.
        "Ghost": mktag(plc, "Ghost", DINT),
    }

    def scalar(expected, mark=None):
        def check(rr):
            if rr.error:
                return {"error": rr.error}, "master reports an error: %s" % rr.error
            if mark is not None:
                marks[mark] = rr.value
            return {"value": rr.value, "type": rr.type}, (
                None if rr.value == expected else "expected %r" % (expected,)
            )

        return check

    def vector(expected, mark=None):
        def check(rr):
            if rr.error:
                return {"error": rr.error}, "master reports an error: %s" % rr.error
            got = list(rr.value)
            if mark is not None:
                marks[mark] = got
            return {"value": got, "type": rr.type}, (
                None if got == expected else "expected %r" % (expected,)
            )

        return check

    op("read_Speed", True, lambda: plc.read("Speed"), scalar(SPEED))
    op("read_Counts_6", True, lambda: plc.read("Counts{6}"), vector(COUNTS, mark="counts"))
    op("read_Counts_slice", True, lambda: plc.read("Counts[2]{3}"),
       vector(COUNTS[2:5], mark="counts_slice"))
    op("read_Setpoint", True, lambda: plc.read("Setpoint"), scalar(SETPOINT, mark="setpoint"))

    def ghost_check(rr):
        # The valuable vector: the device, not the master, picks the code. It
        # is recorded rather than asserted, so this pins the device's real
        # answer instead of our expectation of it.
        if not rr.error:
            return {"unexpected_ok": rr.value}, "expected an error reply for an unserved tag"
        marks["missing_tag_status"] = status_code(rr.error)
        return {"error": rr.error, "status_code": marks["missing_tag_status"]}, None

    op("read_Ghost_unserved", True, lambda: plc.read("Ghost"), ghost_check)

    # ── the verdict block ──────────────────────────────────────────────────
    # `graded` counts what ran before this point, pinned exactly on the Zig
    # side, so a script that died halfway cannot look like a complete run.
    graded = len(records)

    def i32(x):
        x = int(x) & 0xFFFFFFFF
        return x - (1 << 32) if x >= (1 << 31) else x

    counts = marks.get("counts", [])
    counts_slice = marks.get("counts_slice", [])
    setpoint = marks.get("setpoint")
    verdict = [
        MAGIC,
        i32(graded),
        i32(len(failures)),
        i32(sum(counts)),
        i32(round(setpoint * 10)) if setpoint is not None else -1,
        i32(marks.get("name_checksum", -1)),
        i32(marks.get("missing_tag_status", -1)),
        i32(sum(counts_slice)),
    ]
    all_passed = not failures

    # Issued as ONE multi-service write of two tags — see docstring point 2:
    # a single-tag write in pycomm3 1.2.16 puts the request on the wire twice.
    # The pass mark rides along and is written in BOTH outcomes, so "a master
    # was here and is unhappy" stays distinguishable from "no master ran".
    def verdict_check(rr):
        results = rr if isinstance(rr, list) else [rr]
        bad = [t for t in results if t.error]
        return ({"written": [(t.tag, t.value) for t in results],
                 "errors": [t.error for t in bad]},
                None if not bad else "verdict write refused: %s" % bad[0].error)

    op("write_verdict", True,
       lambda: plc.write(("Verdict{8}", verdict), ("VerdictPass", 1 if all_passed else 0)),
       verdict_check)

    plc.close()
    time.sleep(0.2)
    tap.stop()

    print(CAPTURE_BEGIN, flush=True)
    print(json.dumps({"master": "pycomm3", "version": version, "licence": licence}), flush=True)
    for rec in records:
        print(json.dumps(rec, separators=(",", ":")), flush=True)
    print(CAPTURE_END, flush=True)

    print("master: verdict %s, all_passed=%s" % (verdict, all_passed), flush=True)
    print("ENIP_MASTER_DONE", flush=True)
    if failures:
        for f in failures:
            print("master: FAILURE %s" % f, flush=True)
        print("ENIP_MASTER_FAIL", flush=True)
        return 1
    print("master: %d operations, all satisfied by pycomm3 %s" % (len(records), version), flush=True)
    print("ENIP_MASTER_OK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
