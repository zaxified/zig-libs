// SPDX-License-Identifier: MIT

//! External anchor: a **real third-party Modbus master** (pymodbus 3.14.0),
//! recorded driving a simulated slave, replayed offline.
//!
//! ## Why this file exists, when `goldens.zig` already exists
//!
//! `goldens.zig` freezes Wireshark's *reading* of bytes this module emits. That
//! is a real oracle, but it is a passive one: a dissector grades a frame that
//! was produced, and can never grade whether the device answered the right
//! question, or what a master's own decoder makes of the answer. The audit's
//! HIGH finding on this module was specifically the *active* half — the eight
//! `test "live: …"` cases that need a real master and therefore never ran.
//!
//! This file closes that half for Modbus. Every exchange below is a byte-exact
//! recording of a session in which pymodbus — a mature Modbus stack developed
//! by people who have never seen this repository — composed the requests,
//! consumed the replies, and reported what it understood them to mean. It can
//! disagree with us, which is the definition an anchor has to meet.
//!
//! ## How it was recorded (capture-and-freeze, run once)
//!
//! Installing a SCADA master on the dev host is not allowed (pip-only
//! libraries; a venv here is one-shot by standing rule), which is what left
//! this finding open. The route that works is the repo's own disposable-VM
//! lane:
//!
//!     scripts/vm/run.sh fleetsim debian
//!
//! Inside that guest — never on the host — `pymodbus==3.14.0` is installed
//! from the provisioning recipe (`scripts/vm/manifest.sh`, `VM_DEBIAN_PIP`),
//! the module's own `test "live: a real Modbus master drives a simulated slave
//! over the TCP binding"` binds `127.0.0.1:15020`, and
//! `scripts/vm/guests/fleetsim-modbus-master.py` drives it through an
//! in-process byte tap. The tap is a plain socket relay, so what is recorded is
//! what crossed the wire, not what a library said it was about to send, and it
//! reassembles frames from the MBAP length field so the vectors are ADUs
//! rather than TCP segments.
//!
//! **The test suite never invokes any of that.** The bytes below are frozen;
//! this file runs offline, on every build, with the VM deleted, and never
//! skips.
//!
//! ## What is frozen, and what is deliberately not
//!
//! The fixture is exactly the one the live test builds: 32 holding registers
//! where `holding[i] = i*111`, input registers `{1000,2000,3000,4000}`, 32
//! coils all false with discrete inputs aliased onto the same array, unit id 1.
//! A sine drives `holding[0]` — and *only* `holding[0]` — so the master's
//! script reads registers `1..` for everything it expects a stable answer from.
//! The one operation that did read `holding[0]` (transaction id 0x000A,
//! `0000000501030202 6f`, decoded by pymodbus as 623) is **not** frozen here:
//! its value is a function of when the poll landed, and promoting it to a
//! golden would pin the scheduler's timing, not the protocol. It is recorded in
//! the run log and asserted only to be inside the sine's band.
//!
//! Order is load-bearing: exchange 5 writes `holding[10]` and exchange 7 writes
//! `coil[3]`, and exchanges 6 and 8 read them back. Replaying out of order is a
//! different test.
//!
//! ## The verdict exchanges, and why a replay corpus needs them
//!
//! The first nine exchanges are a *replay*: our device produced those bytes
//! once, and this test checks it still produces them. That catches a change,
//! but it says nothing about whether the bytes were ever right — a corpus
//! recorded from a wrong device would freeze the wrong answers just as happily.
//! What upgrades it is that the last two exchanges are the master's own marks:
//! pymodbus decoded the replies, summed and packed what it understood in its
//! own number domain, and wrote the result back with FC 0x10 and FC 0x05. Those
//! request bytes are therefore a function of what the device said, computed by
//! a third party — and the test below recomputes the expected values from the
//! fixture rather than restating them, so the two have to agree.
//!
//! Concretely: a device whose register encoder was byte-swapped would have made
//! pymodbus read 28416, 56832, … instead of 111, 222, …, so the sum in exchange
//! 11 would not be 0x0F9C and the pass bit in exchange 12 would be 0x0000. That
//! is the same defect the live test now catches (F1b); this file catches it
//! offline, on every build, with no VM.
//!
//! ## Provenance and licence
//!
//! Nothing from pymodbus is copied, translated or redistributed here. What is
//! frozen is the byte output of a session — numbers produced by two programs
//! exchanging messages defined by the public MODBUS Application Protocol
//! specification — plus, in comments, what the master reported it decoded.
//! pymodbus is BSD-3-Clause; a permissive licence would not have constrained
//! this either way, and the reasoning is recorded in this module's `NOTICE`
//! rather than only here.

const std = @import("std");
const testing = std.testing;

const adapters = @import("adapters.zig");

/// One recorded request/response pair. `decoded` is what pymodbus itself said
/// the reply meant — the part of the recording that a byte comparison alone
/// would not preserve, and the part that makes a wrong-but-self-consistent
/// encoding visible to a reader.
const Exchange = struct {
    op: []const u8,
    request: []const u8,
    response: []const u8,
    decoded: []const u8,
};

/// The session, in the order it happened. Transaction ids run 1..9 because
/// pymodbus allocated them, not because we chose them — which is itself worth
/// having frozen: the MBAP transaction id must be echoed, and a device that
/// invented its own would break a real master while passing any round-trip
/// test we could write against ourselves.
const session = [_]Exchange{
    .{
        .op = "read_holding_registers(address=1, count=8)",
        .request = &.{ 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x01, 0x00, 0x08 },
        .response = &.{
            0x00, 0x01, 0x00, 0x00, 0x00, 0x13, 0x01, 0x03, 0x10,
            0x00, 0x6F, 0x00, 0xDE, 0x01, 0x4D, 0x01, 0xBC, 0x02,
            0x2B, 0x02, 0x9A, 0x03, 0x09, 0x03, 0x78,
        },
        .decoded = "registers [111, 222, 333, 444, 555, 666, 777, 888]",
    },
    .{
        .op = "read_input_registers(address=0, count=4)",
        .request = &.{ 0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x04, 0x00, 0x00, 0x00, 0x04 },
        .response = &.{
            0x00, 0x02, 0x00, 0x00, 0x00, 0x0B, 0x01, 0x04, 0x08,
            0x03, 0xE8, 0x07, 0xD0, 0x0B, 0xB8, 0x0F, 0xA0,
        },
        .decoded = "registers [1000, 2000, 3000, 4000]",
    },
    .{
        // 16 coils, all clear, arrive as two zero bytes — and pymodbus reports
        // sixteen falses, not eight. A device that mis-sized the byte count
        // would be caught here by the master's own unpacking, not by ours.
        .op = "read_coils(address=0, count=16)",
        .request = &.{ 0x00, 0x03, 0x00, 0x00, 0x00, 0x06, 0x01, 0x01, 0x00, 0x00, 0x00, 0x10 },
        .response = &.{ 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x01, 0x01, 0x02, 0x00, 0x00 },
        .decoded = "bits [false x16]",
    },
    .{
        .op = "read_discrete_inputs(address=0, count=8)",
        .request = &.{ 0x00, 0x04, 0x00, 0x00, 0x00, 0x06, 0x01, 0x02, 0x00, 0x00, 0x00, 0x08 },
        .response = &.{ 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x01, 0x02, 0x01, 0x00 },
        .decoded = "bits [false x8]",
    },
    .{
        // FC 0x06's reply is a verbatim echo of the request. Trivial to get
        // right and trivial to get subtly wrong (echoing the value the device
        // stored rather than the value it was sent), and no dissector-based
        // golden can tell those apart.
        .op = "write_register(address=10, value=0x1234)",
        .request = &.{ 0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x0A, 0x12, 0x34 },
        .response = &.{ 0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x0A, 0x12, 0x34 },
        .decoded = "WriteSingleRegisterResponse(address=10, registers=[4660])",
    },
    .{
        // Reads back the write above (0x1234) and its untouched neighbour
        // holding[11] = 11*111 = 1221 = 0x04C5.
        .op = "read_holding_registers(address=10, count=2)",
        .request = &.{ 0x00, 0x06, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x0A, 0x00, 0x02 },
        .response = &.{ 0x00, 0x06, 0x00, 0x00, 0x00, 0x07, 0x01, 0x03, 0x04, 0x12, 0x34, 0x04, 0xC5 },
        .decoded = "registers [4660, 1221]",
    },
    .{
        // 0xFF00 is Modbus's "ON" for a single coil, not 0x0001.
        .op = "write_coil(address=3, value=True)",
        .request = &.{ 0x00, 0x07, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x03, 0xFF, 0x00 },
        .response = &.{ 0x00, 0x07, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x03, 0xFF, 0x00 },
        .decoded = "WriteSingleCoilResponse(address=3, bits=[True])",
    },
    .{
        // 0x08 is bit 3 of the first byte: coil packing is LSB-first within a
        // byte, starting at the lowest requested address. pymodbus decoded it
        // as the fourth coil, which is what makes this an anchor for the bit
        // order rather than a restatement of it.
        .op = "read_coils(address=0, count=8) after the write",
        .request = &.{ 0x00, 0x08, 0x00, 0x00, 0x00, 0x06, 0x01, 0x01, 0x00, 0x00, 0x00, 0x08 },
        .response = &.{ 0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x01, 0x08 },
        .decoded = "bits [false, false, false, true, false, false, false, false]",
    },
    .{
        // Out of range for a 32-register bank. The device answers 0x83 0x02 and
        // pymodbus *named* it: ExceptionResponse(function_code=131,
        // exception_code=2) — Illegal Data Address. A third party agreeing on
        // WHICH exception a bad address earns is worth more than any assertion
        // we could write about our own error path, and note that this is a
        // different code from the 0x04 Slave Device Failure that `goldens.zig`
        // pins for the trouble state: the two must not collapse into one.
        .op = "read_holding_registers(address=200, count=4) — out of range",
        .request = &.{ 0x00, 0x09, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0xC8, 0x00, 0x04 },
        .response = &.{ 0x00, 0x09, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x02 },
        .decoded = "ExceptionResponse(function_code=131, exception_code=2 Illegal Data Address)",
    },
    // Transaction id 0x000A is the sine read, deliberately not frozen (see the
    // header). 0x000B and 0x000C are the master's VERDICT — the two exchanges
    // that make this corpus grade rather than merely replay.
    .{
        // FC 0x10, seven registers at 24. Every value in this payload is a
        // number the *master* computed from what it decoded, not a number we
        // sent it: f135 magic, 10 checks run, 0 failures, exception code 2,
        // 0x0F9C = 3996 = the sum of the eight holding registers it read,
        // 0x2710 = 10000 = the sum of the four input registers, 0x0008 = the
        // eight coils packed LSB-first. Freezing the request means a device
        // that mis-encoded its replies could not produce these bytes: the
        // master would have summed different numbers.
        .op = "write_registers(address=24, values=<the master's verdict>)",
        .request = &.{
            0x00, 0x0B, 0x00, 0x00, 0x00, 0x15, 0x01, 0x10, 0x00, 0x18, 0x00, 0x07, 0x0E,
            0xF1, 0x35, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x02, 0x0F, 0x9C, 0x27, 0x10, 0x00,
            0x08,
        },
        .response = &.{ 0x00, 0x0B, 0x00, 0x00, 0x00, 0x06, 0x01, 0x10, 0x00, 0x18, 0x00, 0x07 },
        .decoded = "WriteMultipleRegistersResponse(address=24, count=7)",
    },
    .{
        // The pass bit, written last and written either way. 0xFF00 here is
        // pymodbus saying "satisfied"; a 0x0000 in this slot would be a real
        // master reporting, in-band, that the device it just drove is wrong.
        .op = "write_coil(address=31, value=True) — the master's pass bit",
        .request = &.{ 0x00, 0x0C, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x1F, 0xFF, 0x00 },
        .response = &.{ 0x00, 0x0C, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x1F, 0xFF, 0x00 },
        .decoded = "WriteSingleCoilResponse(address=31, bits=[True])",
    },
};

test "anchor: replay a real pymodbus 3.14.0 master's recorded session offline" {
    // The live test's fixture, rebuilt exactly (src/root.zig, test "live: a
    // real Modbus master drives a simulated slave over the TCP binding").
    var holdings = [_]u16{0} ** 32;
    var coils = [_]bool{false} ** 32;
    var inputs = [_]u16{ 1000, 2000, 3000, 4000 };
    for (&holdings, 0..) |*h, i| h.* = @intCast(i * 111);

    var slave = adapters.Modbus.init(
        .{ .unit_id = 1, .framing = .tcp, .accept_any_unit = true, .slave_id = "zig-fleetsim" },
        .{
            .holding_registers = .{ .base = 0, .values = &holdings },
            .input_registers = .{ .base = 0, .values = &inputs },
            .coils = .{ .base = 0, .values = &coils },
            .discrete_inputs = .{ .base = 0, .values = &coils },
        },
    );
    const n = slave.node();

    for (session) |x| {
        var out: [512]u8 = undefined;
        const reply = (try n.deliver(x.request, &out, 0)) orelse {
            std.debug.print(
                "pymodbus anchor: the device answered nothing to {s}\n",
                .{x.op},
            );
            return error.NoReplyToRecordedRequest;
        };
        testing.expectEqualSlices(u8, x.response, reply) catch |e| {
            std.debug.print(
                "pymodbus anchor: {s}\n  a real master read this reply as: {s}\n",
                .{ x.op, x.decoded },
            );
            return e;
        };
    }

    // The writes in the recording must actually have landed. If they had not,
    // exchanges 6 and 8 could still have matched by the device echoing state it
    // never stored.
    try testing.expectEqual(@as(u16, 0x1234), holdings[10]);
    try testing.expect(coils[3]);

    // ── the master's verdict, replayed ──────────────────────────────────────
    // The last two exchanges carry numbers pymodbus computed from what it
    // decoded. Comparing them against the fixture — recomputed here, not
    // restated as literals — is the part of this corpus that grades the
    // device's encoding rather than replaying it. A byte-swapped register
    // encoder cannot reach these values: the master would have summed 28416,
    // 56832, … instead of 111, 222, ….
    try testing.expectEqual(@as(u16, 0xF135), holdings[24]); // "a real master was here"
    try testing.expectEqual(@as(u16, 10), holdings[25]); // operations it graded
    try testing.expectEqual(@as(u16, 0), holdings[26]); // and none of them failed
    try testing.expectEqual(@as(u16, 0x02), holdings[27]); // Illegal Data Address, as pymodbus named it

    var want_hsum: u16 = 0;
    for (1..9) |i| want_hsum +%= @intCast(i * 111);
    try testing.expectEqual(want_hsum, holdings[28]);

    var want_isum: u16 = 0;
    for (inputs) |v| want_isum +%= v;
    try testing.expectEqual(want_isum, holdings[29]);

    // Coil 3 set, LSB-first within the byte — the bit order as a third party
    // unpacked it, not as we packed it.
    try testing.expectEqual(@as(u16, 1 << 3), holdings[30]);

    // The pass bit. `false` here would be a real master saying, over the wire,
    // that it was there and is not satisfied.
    try testing.expect(coils[31]);
}
