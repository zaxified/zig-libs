#!/usr/bin/env python3
"""NOT YET RUN: written against the pymodbus 3.16.2 source read as text; nothing of
pymodbus has executed, so its API calls are unverified (owner approval pending).

Differential oracle: pymodbus (BSD-3) against the modbus module's FC 0x16,
FC 0x2B/0x0E and RTU-over-TCP framing.

    python3 -I tools/oracle.py gen <out.zig>

drives pymodbus's own encoders, its server-side `datastore_update` and its RTU
framer IN PROCESS (no socket, no server, no network) and writes what it says as
Zig vectors; `src/oracle_test.zig` replays them against this module. Run it as
described in tools/README.md (pinned wheel, sha256 check, `unshare -rn`).

Nothing here is seeded from the module under test: every expected byte comes
from pymodbus.
"""
import asyncio
import random
import sys

import pymodbus
from pymodbus.constants import ExcCodes
from pymodbus.framer import FramerRTU
from pymodbus.pdu import ExceptionResponse
from pymodbus.pdu import mei_message
from pymodbus.pdu.bit_message import (
    ReadCoilsRequest, ReadCoilsResponse, WriteMultipleCoilsRequest,
    WriteMultipleCoilsResponse, WriteSingleCoilRequest, WriteSingleCoilResponse,
)
from pymodbus.pdu.decoders import DecodePDU
from pymodbus.pdu.device import ModbusDeviceIdentification
from pymodbus.pdu.mei_message import ReadDeviceInformationRequest
from pymodbus.pdu.register_message import (
    MaskWriteRegisterRequest, ReadHoldingRegistersRequest,
    ReadHoldingRegistersResponse, ReadWriteMultipleRegistersRequest,
    ReadWriteMultipleRegistersResponse, WriteMultipleRegistersRequest,
    WriteMultipleRegistersResponse, WriteSingleRegisterRequest,
    WriteSingleRegisterResponse,
)

PINNED = "3.16.2"


def zbytes(b):
    return '"' + "".join("\\x%02x" % c for c in b) + '"'


def pdu_bytes(p):
    return bytes([p.function_code]) + p.x_encode()


def run(coro):
    return asyncio.run(coro)


class StubContext:
    """Just enough of ModbusServerContext for FC 0x16: one holding register."""

    def __init__(self, cur, fail=None):
        self.cur = cur
        self.fail = fail
        self.after = cur

    async def async_getValues(self, dev, fc, addr, count):
        return self.fail if self.fail is not None else [self.cur]

    async def async_setValues(self, dev, fc, addr, values):
        self.after = values[0]
        return 0


# --------------------------------------------------------------- FC 0x16
def mask_cases(rng):
    cases = [(4, 0x00F2, 0x0025, 0x0012)]  # spec section 6.16 example
    for and_m, or_m, cur in (
        (0x0000, 0xFFFF, 0x1234), (0xFFFF, 0x0000, 0x1234), (0xFFFF, 0xFFFF, 0x1234),
        (0x0000, 0x0000, 0xFFFF), (0x00FF, 0xFF00, 0xABCD), (0xFF00, 0x00FF, 0xABCD),
        (0x5555, 0xFFFF, 0xAAAA), (0xAAAA, 0xFFFF, 0x5555), (0x8000, 0x7FFF, 0x0001),
    ):
        cases.append((0, and_m, or_m, cur))
    for _ in range(40):
        cases.append((rng.randrange(0x10000), rng.randrange(0x10000), rng.randrange(0x10000), rng.randrange(0x10000)))
    out = []
    for addr, and_m, or_m, cur in cases:
        req = MaskWriteRegisterRequest(address=addr, and_mask=and_m, or_mask=or_m)
        ctx = StubContext(cur)
        resp = run(req.datastore_update(ctx, 1))
        out.append((addr, and_m, or_m, cur, pdu_bytes(req), pdu_bytes(resp), ctx.after))
    # a register outside the datastore: pymodbus answers the datastore's code
    req = MaskWriteRegisterRequest(address=9, and_mask=1, or_mask=2)
    resp = run(req.datastore_update(StubContext(0, fail=ExcCodes.ILLEGAL_ADDRESS), 1))
    exc = (pdu_bytes(req), bytes([resp.function_code]) + resp.x_encode())
    return out, exc


# --------------------------------------------------------------- FC 0x2B
def tables():
    big = bytes(range(65, 65 + 60))
    return [
        # 0: basic only
        {0: b"Acme", 1: b"P-100", 2: b"1.2"},
        # 1: basic + regular
        {0: b"Acme", 1: b"P-100", 2: b"1.2", 3: b"http://x", 4: b"Prod", 5: b"Model", 6: b"App"},
        # 2: + extended
        {0: b"V", 1: b"C", 2: b"R", 3: b"U", 4: b"N", 5: b"M", 6: b"A", 0x80: b"ext-80", 0x81: b"ext-81", 0xFF: b"ext-ff"},
        # 3: more-follows (big objects)
        {0: big, 1: big, 2: big, 3: big, 4: big, 5: big, 6: big, 0x80: big},
        # 4: basic + extended, regular category EMPTY
        {0: b"V", 1: b"C", 2: b"R", 0x80: b"E80", 0x90: b"E90"},
        # 5: only vendor name
        {0: b"V"},
        # 6: one object that alone is too big for a response (value 250 bytes)
        {0: b"V", 1: b"C", 2: b"R", 3: bytes(250)},
        # 7: empty values and exact-fit objects
        {0: b"V", 1: b"C", 2: b"R", 3: bytes(240), 4: b"x", 0x80: b""},
    ]


def mei_cases():
    out = []
    tabs = tables()
    for ti, tab in enumerate(tabs):
        mei_message._MCB.Identity = ModbusDeviceIdentification(info=tab)
        ids = sorted({0, 1, 2, 3, 6, 7, 0x50, 0x7F, 0x80, 0x81, 0x90, 0xFF} | set(tab))
        for code in (0, 1, 2, 3, 4, 5):
            for oid in ids:
                req = ReadDeviceInformationRequest(read_code=code, object_id=oid)
                # pymodbus maps read_code 0 to BASIC ("read_code or BASIC")
                rbytes = pdu_bytes(req)
                try:
                    resp = run(req.datastore_update(None, 1))
                    wire = pdu_bytes(resp)
                    if isinstance(resp, ExceptionResponse):
                        wire = bytes([resp.function_code]) + resp.x_encode()
                except Exception as e:  # keep what pymodbus raised, as a note
                    wire = b""
                    print("pymodbus raised on table %d code %d id %d: %r" % (ti, code, oid, e), file=sys.stderr)
                out.append((ti, rbytes, wire))
    return tabs, out


# ----------------------------------------------------------------- RTU
def rtu_streams(rng):
    """Frames built by pymodbus's FramerRTU, in a stream with garbage between."""
    dec_c = DecodePDU(is_server=False)
    dec_s = DecodePDU(is_server=True)
    fr_req = FramerRTU(dec_s)  # frames a server reads: requests (encode side is symmetric)
    fr_resp = FramerRTU(dec_c)
    def regs(n):
        return [rng.randrange(0x10000) for _ in range(n)]
    reqs, resps = [], []
    for unit in (1, 17, 247):
        reqs += [
            ReadCoilsRequest(address=3, count=19, dev_id=unit),
            ReadHoldingRegistersRequest(address=0x100, count=7, dev_id=unit),
            WriteSingleCoilRequest(address=5, bits=[True], dev_id=unit),
            WriteSingleRegisterRequest(address=6, registers=[0xBEEF], dev_id=unit),
            WriteMultipleCoilsRequest(address=0x20, bits=[True, False, True] * 5, dev_id=unit),
            WriteMultipleRegistersRequest(address=0x30, registers=regs(9), dev_id=unit),
            ReadWriteMultipleRegistersRequest(read_address=1, read_count=4, write_address=9, write_registers=regs(3), dev_id=unit),
            MaskWriteRegisterRequest(address=4, and_mask=0xF2, or_mask=0x25, dev_id=unit),
            ReadDeviceInformationRequest(read_code=1, object_id=0, dev_id=unit),
            ReadDeviceInformationRequest(read_code=4, object_id=3, dev_id=unit),
        ]
        resps += [
            ReadCoilsResponse(bits=[True, False, True, True, False, False, True, True, True] , dev_id=unit),
            ReadHoldingRegistersResponse(registers=regs(7), dev_id=unit),
            WriteSingleCoilResponse(address=5, bits=[True], dev_id=unit),
            WriteSingleRegisterResponse(address=6, registers=[0xBEEF], dev_id=unit),
            WriteMultipleCoilsResponse(address=0x20, count=15, dev_id=unit),
            WriteMultipleRegistersResponse(address=0x30, count=9, dev_id=unit),
            ReadWriteMultipleRegistersResponse(registers=regs(4), dev_id=unit),
            ExceptionResponse(3, 2, device_id=unit),
            ExceptionResponse(0x2B, 1, device_id=unit),
        ]
    for ti in (0, 2, 3, 4):
        for code, oid in ((1, 0), (2, 3), (3, 0x80), (4, 1)):
            mei_message._MCB.Identity = ModbusDeviceIdentification(info=tables()[ti])
            q = ReadDeviceInformationRequest(read_code=code, object_id=oid)
            resps.append(run(q.datastore_update(None, 9)))
    def frame(fr, p):
        return fr.buildFrame(p), p.dev_id, bytes([p.function_code]) + p.x_encode()
    def garbage(n):
        return bytes(rng.randrange(0xA0, 0x100) for _ in range(n))
    out = []
    for role, fr, items in ((0, fr_req, reqs), (1, fr_resp, resps)):
        # one stream per role: every frame back to back; then with garbage; then one with a corrupted frame
        frames = [frame(fr, p) for p in items]
        out.append((role, b"".join(f[0] for f in frames), [(f[1], f[2]) for f in frames]))
        s, exp = b"", []
        for f in frames:
            s += garbage(rng.randrange(0, 6)) + f[0]
            exp.append((f[1], f[2]))
        out.append((role, s, exp))
        s, exp = b"", []
        for i, f in enumerate(frames):
            if i % 5 == 2:
                bad = bytearray(f[0])
                bad[-1] ^= 0x55  # CRC broken: this frame must be dropped, the next one found
                s += bytes(bad)
            else:
                s += f[0]
                exp.append((f[1], f[2]))
        out.append((role, s, exp))
    return out


def main():
    if len(sys.argv) != 3 or sys.argv[1] != "gen":
        sys.exit("usage: oracle.py gen <out.zig>")
    if pymodbus.__version__ != PINNED:
        sys.exit("pymodbus %s found, %s pinned" % (pymodbus.__version__, PINNED))
    rng = random.Random(20261119)
    mask, mask_exc = mask_cases(rng)
    tabs, mei = mei_cases()
    rtu = rtu_streams(rng)
    w = []
    w.append("// SPDX-License-Identifier: MIT\n")
    w.append("// GENERATED by tools/oracle.py gen (pymodbus %s, BSD-3): do not edit.\n" % PINNED)
    w.append("// Every byte below is what pymodbus produced; src/oracle_test.zig replays it.\n\n")
    w.append("pub const Obj = struct { id: u8, value: []const u8 };\n")
    w.append("pub const MaskCase = struct { addr: u16, and_mask: u16, or_mask: u16, cur: u16, request: []const u8, response: []const u8, after: u16 };\n")
    w.append("pub const MeiCase = struct { table: u8, request: []const u8, response: []const u8 };\n")
    w.append("pub const Frame = struct { unit: u8, pdu: []const u8 };\n")
    w.append("pub const RtuCase = struct { response_role: bool, stream: []const u8, frames: []const Frame };\n\n")
    w.append("pub const mask_cases = [_]MaskCase{\n")
    for addr, a, o, cur, rq, rp, after in mask:
        w.append("    .{ .addr = 0x%04x, .and_mask = 0x%04x, .or_mask = 0x%04x, .cur = 0x%04x, .request = %s, .response = %s, .after = 0x%04x },\n" % (addr, a, o, cur, zbytes(rq), zbytes(rp), after))
    w.append("};\n\n")
    w.append("pub const mask_exception_request: []const u8 = %s;\n" % zbytes(mask_exc[0]))
    w.append("pub const mask_exception_response: []const u8 = %s;\n\n" % zbytes(mask_exc[1]))
    w.append("pub const tables = [_][]const Obj{\n")
    for tab in tabs:
        w.append("    &.{\n")
        for k in sorted(tab):
            w.append("        .{ .id = 0x%02x, .value = %s },\n" % (k, zbytes(tab[k])))
        w.append("    },\n")
    w.append("};\n\n")
    w.append("pub const mei_cases = [_]MeiCase{\n")
    for ti, rq, rp in mei:
        w.append("    .{ .table = %d, .request = %s, .response = %s },\n" % (ti, zbytes(rq), zbytes(rp)))
    w.append("};\n\n")
    w.append("pub const rtu_cases = [_]RtuCase{\n")
    for role, stream, frames in rtu:
        w.append("    .{ .response_role = %s, .stream = %s, .frames = &.{\n" % ("true" if role else "false", zbytes(stream)))
        for unit, p in frames:
            w.append("        .{ .unit = %d, .pdu = %s },\n" % (unit, zbytes(p)))
        w.append("    } },\n")
    w.append("};\n")
    open(sys.argv[2], "w").write("".join(w))
    print("masks=%d mei=%d rtu_streams=%d" % (len(mask), len(mei), len(rtu)))


main()
