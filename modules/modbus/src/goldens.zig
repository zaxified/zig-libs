// SPDX-License-Identifier: MIT

//! modbus.goldens — byte-exact wire goldens.
//!
//! Every golden below is decoded *and* re-encoded and compared byte-for-byte,
//! so a golden proves both directions at once. Each one is labelled with its
//! provenance:
//!
//! - **CAPTURED** — copied verbatim out of a live session between this module
//!   and a real third-party peer (pymodbus 3.14.0). See `SPEC.md`
//!   "Verification" for the capture topology; the harness is reproducible.
//! - **SPEC** — a worked wire example printed in the Modbus Application
//!   Protocol Specification V1.1b3.
//! - **SELF-DERIVED** — built by this module and only checked for internal
//!   consistency (round-trip, field values). These prove the codec is
//!   self-consistent, not that it matches anyone else.

const std = @import("std");
const mb = @import("root.zig");
const srv = @import("server.zig");

const testing = std.testing;

// ── the device under test ───────────────────────────────────────────────────
//
// Exactly the point database the capture harness configured, so a captured
// request replayed here must produce the captured reply bit for bit.

const capture_unit: u8 = 7;

/// Rebuilds the exact server the capture harness ran, with fresh storage.
fn captureServer(
    coils: *[16]bool,
    discretes: *[16]bool,
    holdings: *[16]u16,
    inputs: *[16]u16,
) srv.Server {
    for (coils, 0..) |*v, i| v.* = (i % 2 == 0);
    discretes.* = [_]bool{false} ** 16;
    for ([_]usize{ 1, 2, 3, 5, 8, 13 }) |i| discretes[i] = true;
    for (holdings, 0..) |*v, i| v.* = @intCast(0x1000 + i);
    for (inputs, 0..) |*v, i| v.* = @intCast(0x2000 + i * 2);

    return srv.Server.init(.{
        .unit_id = capture_unit,
        .framing = .tcp,
        .exception_status = 0x5A,
        .slave_id = "zig-libs-modbus",
        .slave_id_extra = &.{ 0x01, 0x00 },
    }, .{
        .coils = .{ .base = 0, .values = coils },
        .discrete_inputs = .{ .base = 0, .values = discretes },
        .holding_registers = .{ .base = 0, .values = holdings },
        .input_registers = .{ .base = 0, .values = inputs },
    });
}

/// One captured request/reply pair. `reply == null` means the server stayed
/// silent and the peer saw nothing at all.
const Exchange = struct {
    name: []const u8,
    request: []const u8,
    reply: ?[]const u8,
};

// ── CAPTURED: pymodbus 3.14.0 ModbusTcpClient -> this module's Server ───────
//
// Recorded 2026-07-23. A pymodbus master issued each call over a real
// loopback TCP socket; this module's `server.Server` (configured exactly as
// `captureServer` above) produced every reply byte; the harness logged both
// directions verbatim. The `PARSED` column of the capture log — what pymodbus
// made of each reply — is asserted separately in
// "the values pymodbus decoded out of our replies".
//
// The list is in capture order and the server is stateful, so it must be
// replayed in order: the writes and the diagnostic counters depend on it.
//
// Transaction ids 0x0001..0x000F are pymodbus's own, incrementing per call;
// 0x00C8.. are the four raw frames injected on the same socket for the cases
// pymodbus's *client* refuses to emit (it range-checks locally before it
// would ever put an over-large quantity on the wire, and it has no Report
// Slave ID request class). Those four are marked "raw".
const pymodbus_exchanges = [_]Exchange{
    .{
        .name = "FC01 read_coils(0, count=16)",
        .request = &.{ 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x07, 0x01, 0x00, 0x00, 0x00, 0x10 },
        .reply = &.{ 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x07, 0x01, 0x02, 0x55, 0x55 },
    },
    .{
        .name = "FC01 read_coils(3, count=7)",
        .request = &.{ 0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x07, 0x01, 0x00, 0x03, 0x00, 0x07 },
        .reply = &.{ 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x07, 0x01, 0x01, 0x2A },
    },
    .{
        .name = "FC02 read_discrete_inputs(0, count=16)",
        .request = &.{ 0x00, 0x03, 0x00, 0x00, 0x00, 0x06, 0x07, 0x02, 0x00, 0x00, 0x00, 0x10 },
        .reply = &.{ 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x07, 0x02, 0x02, 0x2E, 0x21 },
    },
    .{
        .name = "FC03 read_holding_registers(0, count=4)",
        .request = &.{ 0x00, 0x04, 0x00, 0x00, 0x00, 0x06, 0x07, 0x03, 0x00, 0x00, 0x00, 0x04 },
        .reply = &.{
            0x00, 0x04, 0x00, 0x00, 0x00, 0x0B, 0x07, 0x03, 0x08,
            0x10, 0x00, 0x10, 0x01, 0x10, 0x02, 0x10, 0x03,
        },
    },
    .{
        .name = "FC04 read_input_registers(2, count=3)",
        .request = &.{ 0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x07, 0x04, 0x00, 0x02, 0x00, 0x03 },
        .reply = &.{
            0x00, 0x05, 0x00, 0x00, 0x00, 0x09, 0x07, 0x04, 0x06,
            0x20, 0x04, 0x20, 0x06, 0x20, 0x08,
        },
    },
    .{
        .name = "FC05 write_coil(1, True)",
        .request = &.{ 0x00, 0x06, 0x00, 0x00, 0x00, 0x06, 0x07, 0x05, 0x00, 0x01, 0xFF, 0x00 },
        .reply = &.{ 0x00, 0x06, 0x00, 0x00, 0x00, 0x06, 0x07, 0x05, 0x00, 0x01, 0xFF, 0x00 },
    },
    .{
        .name = "FC06 write_register(5, 0xBEEF)",
        .request = &.{ 0x00, 0x07, 0x00, 0x00, 0x00, 0x06, 0x07, 0x06, 0x00, 0x05, 0xBE, 0xEF },
        .reply = &.{ 0x00, 0x07, 0x00, 0x00, 0x00, 0x06, 0x07, 0x06, 0x00, 0x05, 0xBE, 0xEF },
    },
    .{
        .name = "FC0F write_coils(4, 8 values)",
        .request = &.{ 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x07, 0x0F, 0x00, 0x04, 0x00, 0x08, 0x01, 0xCD },
        .reply = &.{ 0x00, 0x08, 0x00, 0x00, 0x00, 0x06, 0x07, 0x0F, 0x00, 0x04, 0x00, 0x08 },
    },
    .{
        // Coils 8..17, but the window is 0..15 -> IllegalDataAddress. This
        // one is why the golden set is captured rather than predicted: the
        // request looks innocuous and the reply is an exception.
        .name = "FC0F write_coils(8, 10 values) past the 16-coil window -> exception 02",
        .request = &.{ 0x00, 0x09, 0x00, 0x00, 0x00, 0x09, 0x07, 0x0F, 0x00, 0x08, 0x00, 0x0A, 0x02, 0xCD, 0x01 },
        .reply = &.{ 0x00, 0x09, 0x00, 0x00, 0x00, 0x03, 0x07, 0x8F, 0x02 },
    },
    .{
        .name = "FC10 write_registers(10, [0xAAAA, 0x5555])",
        .request = &.{
            0x00, 0x0A, 0x00, 0x00, 0x00, 0x0B, 0x07, 0x10, 0x00,
            0x0A, 0x00, 0x02, 0x04, 0xAA, 0xAA, 0x55, 0x55,
        },
        .reply = &.{ 0x00, 0x0A, 0x00, 0x00, 0x00, 0x06, 0x07, 0x10, 0x00, 0x0A, 0x00, 0x02 },
    },
    .{
        .name = "FC17 readwrite_registers(read 0/3, write 12/[0x0102, 0x0304])",
        .request = &.{
            0x00, 0x0B, 0x00, 0x00, 0x00, 0x0F, 0x07, 0x17, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x0C, 0x00, 0x02, 0x04, 0x01, 0x02, 0x03, 0x04,
        },
        .reply = &.{
            0x00, 0x0B, 0x00, 0x00, 0x00, 0x09, 0x07, 0x17, 0x06,
            0x10, 0x00, 0x10, 0x01, 0x10, 0x02,
        },
    },
    .{
        .name = "FC03 read_holding_registers(100, count=2) -> exception 02",
        .request = &.{ 0x00, 0x0C, 0x00, 0x00, 0x00, 0x06, 0x07, 0x03, 0x00, 0x64, 0x00, 0x02 },
        .reply = &.{ 0x00, 0x0C, 0x00, 0x00, 0x00, 0x03, 0x07, 0x83, 0x02 },
    },
    .{
        .name = "FC07 read_exception_status",
        .request = &.{ 0x00, 0x0D, 0x00, 0x00, 0x00, 0x02, 0x07, 0x07 },
        .reply = &.{ 0x00, 0x0D, 0x00, 0x00, 0x00, 0x03, 0x07, 0x07, 0x5A },
    },
    .{
        .name = "FC08 diag_query_data(A5 37) -> echo",
        .request = &.{ 0x00, 0x0E, 0x00, 0x00, 0x00, 0x06, 0x07, 0x08, 0x00, 0x00, 0xA5, 0x37 },
        .reply = &.{ 0x00, 0x0E, 0x00, 0x00, 0x00, 0x06, 0x07, 0x08, 0x00, 0x00, 0xA5, 0x37 },
    },
    .{
        // pymodbus's Read Device Identification (MEI 0x2B/0x0E). We do not
        // implement it, so the honest answer is IllegalFunction with the
        // high bit set on 0x2B.
        .name = "FC2B/0E read_device_information -> exception 01",
        .request = &.{ 0x00, 0x0F, 0x00, 0x00, 0x00, 0x05, 0x07, 0x2B, 0x0E, 0x01, 0x00 },
        .reply = &.{ 0x00, 0x0F, 0x00, 0x00, 0x00, 0x03, 0x07, 0xAB, 0x01 },
    },
    .{
        .name = "raw: FC03 quantity 126 (over the 125 limit) -> exception 03",
        .request = &.{ 0x00, 0xC8, 0x00, 0x00, 0x00, 0x06, 0x07, 0x03, 0x00, 0x00, 0x00, 0x7E },
        .reply = &.{ 0x00, 0xC8, 0x00, 0x00, 0x00, 0x03, 0x07, 0x83, 0x03 },
    },
    .{
        .name = "raw: FC11 report_slave_id",
        .request = &.{ 0x00, 0xC9, 0x00, 0x00, 0x00, 0x02, 0x07, 0x11 },
        .reply = &.{
            0x00, 0xC9, 0x00, 0x00, 0x00, 0x15, 0x07, 0x11, 0x12,
            0x7A, 0x69, 0x67, 0x2D, 0x6C, 0x69, 0x62, 0x73, 0x2D, // "zig-libs-"
            0x6D, 0x6F, 0x64, 0x62, 0x75, 0x73, // "modbus"
            0xFF, 0x01, 0x00, // run indicator ON + extra
        },
    },
    .{
        // 18 = every ADU the server had seen by this point in the session,
        // counted at the ADU layer. Replaying the goldens in order has to
        // reproduce that number exactly, which makes this golden a check on
        // the whole session's state, not just one frame.
        .name = "raw: FC08 sub 0x000B return bus message count -> 18",
        .request = &.{ 0x00, 0xCA, 0x00, 0x00, 0x00, 0x06, 0x07, 0x08, 0x00, 0x0B, 0x00, 0x00 },
        .reply = &.{ 0x00, 0xCA, 0x00, 0x00, 0x00, 0x06, 0x07, 0x08, 0x00, 0x0B, 0x00, 0x12 },
    },
    .{
        .name = "raw: FC03 addressed to unit 9 -> total silence",
        .request = &.{ 0x00, 0xCB, 0x00, 0x00, 0x00, 0x06, 0x09, 0x03, 0x00, 0x00, 0x00, 0x04 },
        .reply = null,
    },
};

test "CAPTURED: replaying the live pymodbus session reproduces every reply byte-for-byte" {
    var coils: [16]bool = undefined;
    var discretes: [16]bool = undefined;
    var holdings: [16]u16 = undefined;
    var inputs: [16]u16 = undefined;
    var server = captureServer(&coils, &discretes, &holdings, &inputs);

    var out: [mb.tcp.max_adu_len]u8 = undefined;
    for (pymodbus_exchanges) |ex| {
        const got = try server.handleAdu(ex.request, &out);
        if (ex.reply) |want| {
            if (got == null) {
                std.debug.print("golden '{s}': server stayed silent\n", .{ex.name});
                return error.TestUnexpectedResult;
            }
            testing.expectEqualSlices(u8, want, got.?) catch |err| {
                std.debug.print("golden '{s}' mismatch\n", .{ex.name});
                return err;
            };
        } else if (got != null) {
            std.debug.print("golden '{s}': expected silence, got a reply\n", .{ex.name});
            return error.TestUnexpectedResult;
        }
    }
}

test "CAPTURED: every golden frame decodes and re-encodes byte-identically" {
    var out: [mb.tcp.max_adu_len]u8 = undefined;
    for (pymodbus_exchanges) |ex| {
        const frames: [2]?[]const u8 = .{ ex.request, ex.reply };
        for (frames) |maybe| {
            const frame = maybe orelse continue;
            const decoded = try mb.tcp.decodeAdu(frame);
            const again = try mb.tcp.encodeAdu(&out, decoded.transaction_id, decoded.unit, decoded.pdu);
            try testing.expectEqualSlices(u8, frame, again);
        }
    }
}

test "CAPTURED: the values pymodbus decoded out of our replies" {
    // Transcribed from the capture log's PARSED column: what pymodbus itself
    // made of each of our replies. If our packing were wrong in a way that
    // still round-tripped through our own decoder, this is what would catch
    // it.
    var out: [16]bool = undefined;

    // FC01 read_coils(0, 16) -> alternating starting True.
    try mb.pdu.parseReadBitsResponse(pymodbus_exchanges[0].reply.?[7..], .read_coils, &out);
    for (out, 0..) |bit, i| try testing.expectEqual(i % 2 == 0, bit);

    // FC01 read_coils(3, 7): pymodbus reported
    // [False, True, False, True, False, True, False] (+ one pad bit).
    var seven: [7]bool = undefined;
    try mb.pdu.parseReadBitsResponse(pymodbus_exchanges[1].reply.?[7..], .read_coils, &seven);
    try testing.expectEqualSlices(bool, &.{ false, true, false, true, false, true, false }, &seven);

    // FC02 read_discrete_inputs(0, 16): points 1,2,3,5,8,13 set.
    var di: [16]bool = undefined;
    try mb.pdu.parseReadBitsResponse(pymodbus_exchanges[2].reply.?[7..], .read_discrete_inputs, &di);
    for (di, 0..) |bit, i| {
        const want = switch (i) {
            1, 2, 3, 5, 8, 13 => true,
            else => false,
        };
        try testing.expectEqual(want, bit);
    }

    // FC03 -> pymodbus reported registers 0x1000..0x1003.
    var hr: [4]u16 = undefined;
    try mb.pdu.parseReadRegistersResponse(pymodbus_exchanges[3].reply.?[7..], .read_holding_registers, &hr);
    try testing.expectEqualSlices(u16, &.{ 0x1000, 0x1001, 0x1002, 0x1003 }, &hr);

    // FC04 -> pymodbus reported registers 0x2004, 0x2006, 0x2008.
    var ir: [3]u16 = undefined;
    try mb.pdu.parseReadRegistersResponse(pymodbus_exchanges[4].reply.?[7..], .read_input_registers, &ir);
    try testing.expectEqualSlices(u16, &.{ 0x2004, 0x2006, 0x2008 }, &ir);

    // FC17 -> pymodbus reported registers 0x1000..0x1002.
    var rw: [3]u16 = undefined;
    try mb.pdu.parseReadRegistersResponse(pymodbus_exchanges[10].reply.?[7..], .read_write_multiple_registers, &rw);
    try testing.expectEqualSlices(u16, &.{ 0x1000, 0x1001, 0x1002 }, &rw);

    // The three exception responses pymodbus reported as ExceptionResponse
    // with codes 2, 2, 1 and 3 respectively.
    try testing.expectError(error.IllegalDataAddress, mb.pdu.checkFunction(
        pymodbus_exchanges[8].reply.?[7..],
        .write_multiple_coils,
    ));
    try testing.expectError(error.IllegalDataAddress, mb.pdu.checkFunction(
        pymodbus_exchanges[11].reply.?[7..],
        .read_holding_registers,
    ));
    try testing.expectError(error.IllegalDataValue, mb.pdu.checkFunction(
        pymodbus_exchanges[15].reply.?[7..],
        .read_holding_registers,
    ));
}

test "CAPTURED: the session's writes left the expected process image" {
    var coils: [16]bool = undefined;
    var discretes: [16]bool = undefined;
    var holdings: [16]u16 = undefined;
    var inputs: [16]u16 = undefined;
    var server = captureServer(&coils, &discretes, &holdings, &inputs);

    var out: [mb.tcp.max_adu_len]u8 = undefined;
    for (pymodbus_exchanges) |ex| _ = try server.handleAdu(ex.request, &out);

    // FC05 set coil 1 (it started OFF: even indices were ON).
    try testing.expect(coils[1]);
    // FC0F wrote 8 coils from 4 with data byte 0xCD = 1,0,1,1,0,0,1,1.
    const written = [_]bool{ true, false, true, true, false, false, true, true };
    for (written, 0..) |want, i| try testing.expectEqual(want, coils[4 + i]);
    // The rejected FC0F (coils 8..17) must not have written a single bit —
    // coils 8..11 still carry what the accepted write left there.
    try testing.expectEqual(false, coils[8]);
    try testing.expectEqual(false, coils[9]);
    try testing.expectEqual(true, coils[10]);
    try testing.expectEqual(true, coils[11]);
    // ...and 12..15 are untouched initial values (even = ON).
    try testing.expect(coils[12] and !coils[13] and coils[14] and !coils[15]);

    // FC06 wrote register 5; FC10 wrote 10..11; FC17 wrote 12..13.
    try testing.expectEqual(@as(u16, 0xBEEF), holdings[5]);
    try testing.expectEqual(@as(u16, 0xAAAA), holdings[10]);
    try testing.expectEqual(@as(u16, 0x5555), holdings[11]);
    try testing.expectEqual(@as(u16, 0x0102), holdings[12]);
    try testing.expectEqual(@as(u16, 0x0304), holdings[13]);
    try testing.expectEqual(@as(u16, 0x1000), holdings[0]);

    // Input registers and discrete inputs have no write path over the wire.
    try testing.expectEqual(@as(u16, 0x2000), inputs[0]);
    try testing.expect(discretes[1]);

    // The counters the session ended with, as the FC08 golden reported them.
    try testing.expectEqual(@as(u16, 19), server.counters.bus_message);
    try testing.expectEqual(@as(u16, 18), server.counters.slave_message);
    try testing.expectEqual(@as(u16, 4), server.counters.slave_exception_error);
}

// ── CAPTURED: this module's Client -> a live pymodbus ModbusTcpServer ───────
//
// The reverse direction, recorded in the same run: this module's `Client`
// drove a pymodbus `ModbusTcpServer` over a real loopback socket, with
// pymodbus's data bank seeded with the same values. The requests are ours;
// the replies are pymodbus's *encoder*, so these cross-check the
// pre-existing master-side parser against a third-party implementation.
const pymodbus_server_replies = [_]Exchange{
    .{
        .name = "our FC03(0,4) -> pymodbus server",
        .request = &.{ 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x07, 0x03, 0x00, 0x00, 0x00, 0x04 },
        .reply = &.{
            0x00, 0x01, 0x00, 0x00, 0x00, 0x0B, 0x07, 0x03, 0x08,
            0x10, 0x00, 0x10, 0x01, 0x10, 0x02, 0x10, 0x03,
        },
    },
    .{
        .name = "our FC01(0,16) -> pymodbus server",
        .request = &.{ 0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x07, 0x01, 0x00, 0x00, 0x00, 0x10 },
        .reply = &.{ 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x07, 0x01, 0x02, 0x55, 0x55 },
    },
    .{
        .name = "our FC04(2,3) -> pymodbus server",
        .request = &.{ 0x00, 0x03, 0x00, 0x00, 0x00, 0x06, 0x07, 0x04, 0x00, 0x02, 0x00, 0x03 },
        .reply = &.{
            0x00, 0x03, 0x00, 0x00, 0x00, 0x09, 0x07, 0x04, 0x06,
            0x20, 0x04, 0x20, 0x06, 0x20, 0x08,
        },
    },
    .{
        .name = "our FC06(5, 0xBEEF) -> pymodbus server",
        .request = &.{ 0x00, 0x04, 0x00, 0x00, 0x00, 0x06, 0x07, 0x06, 0x00, 0x05, 0xBE, 0xEF },
        .reply = &.{ 0x00, 0x04, 0x00, 0x00, 0x00, 0x06, 0x07, 0x06, 0x00, 0x05, 0xBE, 0xEF },
    },
    .{
        .name = "our FC10(10, 2 registers) -> pymodbus server",
        .request = &.{
            0x00, 0x05, 0x00, 0x00, 0x00, 0x0B, 0x07, 0x10, 0x00,
            0x0A, 0x00, 0x02, 0x04, 0xAA, 0xAA, 0x55, 0x55,
        },
        .reply = &.{ 0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x07, 0x10, 0x00, 0x0A, 0x00, 0x02 },
    },
    .{
        .name = "our FC0F(4, 8 coils) -> pymodbus server",
        .request = &.{ 0x00, 0x06, 0x00, 0x00, 0x00, 0x08, 0x07, 0x0F, 0x00, 0x04, 0x00, 0x08, 0x01, 0xCD },
        .reply = &.{ 0x00, 0x06, 0x00, 0x00, 0x00, 0x06, 0x07, 0x0F, 0x00, 0x04, 0x00, 0x08 },
    },
    .{
        .name = "our FC17(read 0/3, write 12/2) -> pymodbus server",
        .request = &.{
            0x00, 0x07, 0x00, 0x00, 0x00, 0x0F, 0x07, 0x17, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x0C, 0x00, 0x02, 0x04, 0x01, 0x02, 0x03, 0x04,
        },
        .reply = &.{
            0x00, 0x07, 0x00, 0x00, 0x00, 0x09, 0x07, 0x17, 0x06,
            0x10, 0x00, 0x10, 0x01, 0x10, 0x02,
        },
    },
    .{
        .name = "our FC03(10000, 2) -> pymodbus server exception 02",
        .request = &.{ 0x00, 0x08, 0x00, 0x00, 0x00, 0x06, 0x07, 0x03, 0x27, 0x10, 0x00, 0x02 },
        .reply = &.{ 0x00, 0x08, 0x00, 0x00, 0x00, 0x03, 0x07, 0x83, 0x02 },
    },
};

const ReplayTransport = struct {
    reply: []const u8,
    got: [mb.tcp.max_adu_len]u8 = undefined,
    got_len: usize = 0,

    fn transport(self: *ReplayTransport) mb.Transport {
        return .{ .ctx = self, .exchangeFn = exchangeFn };
    }

    fn exchangeFn(ctx: *anyopaque, request: []const u8, reply_buf: []u8) mb.TransportError!usize {
        const self: *ReplayTransport = @ptrCast(@alignCast(ctx));
        if (request.len > self.got.len or self.reply.len > reply_buf.len) return error.TransportFailed;
        @memcpy(self.got[0..request.len], request);
        self.got_len = request.len;
        @memcpy(reply_buf[0..self.reply.len], self.reply);
        return self.reply.len;
    }
};

test "CAPTURED: our master's request bytes are what pymodbus's server answered" {
    // The transaction ids in the capture run 1..8 because the client is a
    // single `Client` instance; replaying with one instance reproduces them.
    var transports: [pymodbus_server_replies.len]ReplayTransport = undefined;
    for (&transports, pymodbus_server_replies) |*t, ex| t.* = .{ .reply = ex.reply.? };

    var client = mb.Client.init(.tcp, transports[0].transport());

    var hr: [4]u16 = undefined;
    try client.readHoldingRegisters(capture_unit, 0, &hr);
    try testing.expectEqualSlices(u16, &.{ 0x1000, 0x1001, 0x1002, 0x1003 }, &hr);
    try testing.expectEqualSlices(u8, pymodbus_server_replies[0].request, transports[0].got[0..transports[0].got_len]);

    client.transport = transports[1].transport();
    var coils: [16]bool = undefined;
    try client.readCoils(capture_unit, 0, &coils);
    for (coils, 0..) |on, i| try testing.expectEqual(i % 2 == 0, on);
    try testing.expectEqualSlices(u8, pymodbus_server_replies[1].request, transports[1].got[0..transports[1].got_len]);

    client.transport = transports[2].transport();
    var ir: [3]u16 = undefined;
    try client.readInputRegisters(capture_unit, 2, &ir);
    try testing.expectEqualSlices(u16, &.{ 0x2004, 0x2006, 0x2008 }, &ir);
    try testing.expectEqualSlices(u8, pymodbus_server_replies[2].request, transports[2].got[0..transports[2].got_len]);

    client.transport = transports[3].transport();
    try client.writeSingleRegister(capture_unit, 5, 0xBEEF);
    try testing.expectEqualSlices(u8, pymodbus_server_replies[3].request, transports[3].got[0..transports[3].got_len]);

    client.transport = transports[4].transport();
    try client.writeMultipleRegisters(capture_unit, 10, &.{ 0xAAAA, 0x5555 });
    try testing.expectEqualSlices(u8, pymodbus_server_replies[4].request, transports[4].got[0..transports[4].got_len]);

    client.transport = transports[5].transport();
    const eight = [_]bool{ true, false, true, true, false, false, true, true };
    try client.writeMultipleCoils(capture_unit, 4, &eight);
    try testing.expectEqualSlices(u8, pymodbus_server_replies[5].request, transports[5].got[0..transports[5].got_len]);

    client.transport = transports[6].transport();
    var rw: [3]u16 = undefined;
    try client.readWriteMultipleRegisters(capture_unit, 0, &rw, 12, &.{ 0x0102, 0x0304 });
    try testing.expectEqualSlices(u16, &.{ 0x1000, 0x1001, 0x1002 }, &rw);
    try testing.expectEqualSlices(u8, pymodbus_server_replies[6].request, transports[6].got[0..transports[6].got_len]);

    client.transport = transports[7].transport();
    var oops: [2]u16 = undefined;
    try testing.expectError(
        error.IllegalDataAddress,
        client.readHoldingRegisters(capture_unit, 10000, &oops),
    );
    try testing.expectEqualSlices(u8, pymodbus_server_replies[7].request, transports[7].got[0..transports[7].got_len]);
}

// ── CAPTURED: pymodbus FramerRTU <-> this module's RTU server ──────────────
//
// pymodbus 3.14.0's `FramerRTU` built these request frames with its own
// CRC-16 implementation, and validated the CRC on every reply our server
// produced (`check_CRC` returned True on all four). A fresh server, so the
// data bank is at its initial values until the FC06.
const pymodbus_rtu_exchanges = [_]Exchange{
    .{
        .name = "RTU FC03 read 4 holding registers",
        .request = &.{ 0x07, 0x03, 0x00, 0x00, 0x00, 0x04, 0x44, 0x6F },
        .reply = &.{
            0x07, 0x03, 0x08, 0x10, 0x00, 0x10, 0x01,
            0x10, 0x02, 0x10, 0x03, 0x5D, 0xC2,
        },
    },
    .{
        .name = "RTU FC01 read 16 coils",
        .request = &.{ 0x07, 0x01, 0x00, 0x00, 0x00, 0x10, 0x3D, 0xA0 },
        .reply = &.{ 0x07, 0x01, 0x02, 0x55, 0x55, 0xCE, 0x93 },
    },
    .{
        .name = "RTU FC06 write register 5 = 0xBEEF",
        .request = &.{ 0x07, 0x06, 0x00, 0x05, 0xBE, 0xEF, 0xA9, 0x81 },
        .reply = &.{ 0x07, 0x06, 0x00, 0x05, 0xBE, 0xEF, 0xA9, 0x81 },
    },
    .{
        .name = "RTU FC03 out of range -> exception 02",
        .request = &.{ 0x07, 0x03, 0x00, 0x64, 0x00, 0x02, 0x85, 0xB2 },
        .reply = &.{ 0x07, 0x83, 0x02, 0x20, 0xF0 },
    },
};

test "CAPTURED: pymodbus RTU frames drive our RTU server byte-for-byte" {
    var coils: [16]bool = undefined;
    var discretes: [16]bool = undefined;
    var holdings: [16]u16 = undefined;
    var inputs: [16]u16 = undefined;
    var server = captureServer(&coils, &discretes, &holdings, &inputs);
    server.config.framing = .rtu;

    var out: [mb.rtu.max_adu_len]u8 = undefined;
    for (pymodbus_rtu_exchanges) |ex| {
        const got = (try server.handleAdu(ex.request, &out)) orelse {
            std.debug.print("RTU golden '{s}': server stayed silent\n", .{ex.name});
            return error.TestUnexpectedResult;
        };
        testing.expectEqualSlices(u8, ex.reply.?, got) catch |err| {
            std.debug.print("RTU golden '{s}' mismatch\n", .{ex.name});
            return err;
        };
    }
    try testing.expectEqual(@as(u16, 0xBEEF), holdings[5]);
}

test "CAPTURED: pymodbus's CRC-16 and ours agree on every RTU golden" {
    for (pymodbus_rtu_exchanges) |ex| {
        const frames: [2]?[]const u8 = .{ ex.request, ex.reply };
        for (frames) |maybe| {
            const frame = maybe orelse continue;
            // If pymodbus's CRC-16 disagreed with ours by even one bit,
            // decodeAdu would return BadCrc here.
            const decoded = try mb.rtu.decodeAdu(frame);
            var out: [mb.rtu.max_adu_len]u8 = undefined;
            const again = try mb.rtu.encodeAdu(&out, decoded.unit, decoded.pdu);
            try testing.expectEqualSlices(u8, frame, again);
        }
    }
}

// ── SPEC: the worked examples from Application Protocol V1.1b3 §6 ──────────
//
// The client side already pins these as request/response *parsers*; here the
// server has to *produce* them. The point database is the one each example
// assumes.

test "SPEC 6.1: FC 01 read coils 20-38 produces the spec's response bytes" {
    var coils = [_]bool{false} ** 64;
    const pattern = [_]u8{ 0xCD, 0x6B, 0x05 };
    for (0..19) |i| {
        const shift: u3 = @intCast(i % 8);
        coils[19 + i] = (pattern[i / 8] >> shift) & 1 != 0;
    }
    var server = srv.Server.init(
        .{ .unit_id = 1, .framing = .rtu },
        .{ .coils = .{ .base = 0, .values = &coils } },
    );
    var out: [mb.max_pdu_len]u8 = undefined;
    const reply = try server.handlePdu(&.{ 0x01, 0x00, 0x13, 0x00, 0x13 }, &out);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x03, 0xCD, 0x6B, 0x05 }, reply);
}

test "SPEC 6.2: FC 02 read discrete inputs 197-218" {
    var inputs = [_]bool{false} ** 256;
    const pattern = [_]u8{ 0xAC, 0xDB, 0x35 };
    for (0..22) |i| {
        const shift: u3 = @intCast(i % 8);
        inputs[196 + i] = (pattern[i / 8] >> shift) & 1 != 0;
    }
    var server = srv.Server.init(
        .{ .unit_id = 1, .framing = .rtu },
        .{ .discrete_inputs = .{ .base = 0, .values = &inputs } },
    );
    var out: [mb.max_pdu_len]u8 = undefined;
    const reply = try server.handlePdu(&.{ 0x02, 0x00, 0xC4, 0x00, 0x16 }, &out);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x03, 0xAC, 0xDB, 0x35 }, reply);
}

test "SPEC 6.3: FC 03 read holding registers 108-110" {
    var regs = [_]u16{0} ** 128;
    regs[107] = 555;
    regs[108] = 0;
    regs[109] = 100;
    var server = srv.Server.init(
        .{ .unit_id = 1, .framing = .rtu },
        .{ .holding_registers = .{ .base = 0, .values = &regs } },
    );
    var out: [mb.max_pdu_len]u8 = undefined;
    const reply = try server.handlePdu(&.{ 0x03, 0x00, 0x6B, 0x00, 0x03 }, &out);
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64 }, reply);
}

test "SPEC 6.4: FC 04 read input register 9" {
    var regs = [_]u16{0} ** 16;
    regs[8] = 10;
    var server = srv.Server.init(
        .{ .unit_id = 1, .framing = .rtu },
        .{ .input_registers = .{ .base = 0, .values = &regs } },
    );
    var out: [mb.max_pdu_len]u8 = undefined;
    const reply = try server.handlePdu(&.{ 0x04, 0x00, 0x08, 0x00, 0x01 }, &out);
    try testing.expectEqualSlices(u8, &.{ 0x04, 0x02, 0x00, 0x0A }, reply);
}

test "SPEC 6.5/6.6: FC 05 and FC 06 echo the request" {
    var coils = [_]bool{false} ** 256;
    var regs = [_]u16{0} ** 16;
    var server = srv.Server.init(.{ .unit_id = 1, .framing = .rtu }, .{
        .coils = .{ .base = 0, .values = &coils },
        .holding_registers = .{ .base = 0, .values = &regs },
    });
    var out: [mb.max_pdu_len]u8 = undefined;

    const r5 = try server.handlePdu(&.{ 0x05, 0x00, 0xAC, 0xFF, 0x00 }, &out);
    try testing.expectEqualSlices(u8, &.{ 0x05, 0x00, 0xAC, 0xFF, 0x00 }, r5);
    try testing.expect(coils[172]);

    const r6 = try server.handlePdu(&.{ 0x06, 0x00, 0x01, 0x00, 0x03 }, &out);
    try testing.expectEqualSlices(u8, &.{ 0x06, 0x00, 0x01, 0x00, 0x03 }, r6);
    try testing.expectEqual(@as(u16, 3), regs[1]);
}

test "SPEC 6.11/6.12: FC 0F and FC 10 echo address + quantity" {
    var coils = [_]bool{false} ** 64;
    var regs = [_]u16{0} ** 16;
    var server = srv.Server.init(.{ .unit_id = 1, .framing = .rtu }, .{
        .coils = .{ .base = 0, .values = &coils },
        .holding_registers = .{ .base = 0, .values = &regs },
    });
    var out: [mb.max_pdu_len]u8 = undefined;

    const r0f = try server.handlePdu(&.{ 0x0F, 0x00, 0x13, 0x00, 0x0A, 0x02, 0xCD, 0x01 }, &out);
    try testing.expectEqualSlices(u8, &.{ 0x0F, 0x00, 0x13, 0x00, 0x0A }, r0f);
    const expect = [_]bool{ true, false, true, true, false, false, true, true, true, false };
    for (expect, 0..) |want, i| try testing.expectEqual(want, coils[19 + i]);

    const r10 = try server.handlePdu(&.{ 0x10, 0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x0A, 0x01, 0x02 }, &out);
    try testing.expectEqualSlices(u8, &.{ 0x10, 0x00, 0x01, 0x00, 0x02 }, r10);
    try testing.expectEqual(@as(u16, 0x000A), regs[1]);
    try testing.expectEqual(@as(u16, 0x0102), regs[2]);
}

test "SPEC 6.17: FC 17 writes before it reads" {
    var regs = [_]u16{0} ** 32;
    regs[3] = 0x00FE;
    regs[4] = 0x0ACD;
    regs[5] = 0x0001;
    regs[6] = 0x0003;
    regs[7] = 0x000D;
    regs[8] = 0x00FF;
    var server = srv.Server.init(
        .{ .unit_id = 1, .framing = .rtu },
        .{ .holding_registers = .{ .base = 0, .values = &regs } },
    );
    var out: [mb.max_pdu_len]u8 = undefined;
    const reply = try server.handlePdu(&.{
        0x17, 0x00, 0x03, 0x00, 0x06, 0x00, 0x0E, 0x00,
        0x03, 0x06, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
    }, &out);
    try testing.expectEqualSlices(u8, &.{
        0x17, 0x0C, 0x00, 0xFE, 0x0A, 0xCD, 0x00, 0x01,
        0x00, 0x03, 0x00, 0x0D, 0x00, 0xFF,
    }, reply);
    try testing.expectEqual(@as(u16, 0x00FF), regs[14]);
    try testing.expectEqual(@as(u16, 0x00FF), regs[16]);

    // Now make the write-before-read ordering observable: read exactly the
    // range being written. A read-first implementation would return the old
    // values here.
    const reply2 = try server.handlePdu(&.{
        0x17, 0x00, 0x0E, 0x00, 0x03, 0x00, 0x0E, 0x00,
        0x03, 0x06, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33,
    }, &out);
    try testing.expectEqualSlices(u8, &.{
        0x17, 0x06, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33,
    }, reply2);
}

// ── SELF-DERIVED: round-trip only ──────────────────────────────────────────

/// Wires a `Server` behind a `Client`'s transport seam, so the two halves of
/// this module talk to each other with no I/O at all.
fn Loopback(comptime framing: mb.Framing) type {
    return struct {
        server: *srv.Server,

        const Self = @This();

        fn transport(self: *Self) mb.Transport {
            return .{ .ctx = self, .exchangeFn = exchangeFn };
        }

        fn exchangeFn(ctx: *anyopaque, request: []const u8, reply_buf: []u8) mb.TransportError!usize {
            const self: *Self = @ptrCast(@alignCast(ctx));
            var out: [mb.tcp.max_adu_len]u8 = undefined;
            const reply = (self.server.handleAdu(request, &out) catch return error.TransportFailed) orelse
                return error.Timeout;
            if (reply.len > reply_buf.len) return error.TransportFailed;
            @memcpy(reply_buf[0..reply.len], reply);
            _ = framing;
            return reply.len;
        }
    };
}

test "SELF-DERIVED: our Client and our Server complete a full TCP round trip" {
    var coils = [_]bool{false} ** 32;
    var regs = [_]u16{0} ** 32;
    var server = srv.Server.init(.{ .unit_id = 3, .framing = .tcp }, .{
        .coils = .{ .base = 0, .values = &coils },
        .holding_registers = .{ .base = 0, .values = &regs },
    });

    var loop = Loopback(.tcp){ .server = &server };
    var client = mb.Client.init(.tcp, loop.transport());

    try client.writeMultipleRegisters(3, 4, &.{ 11, 22, 33 });
    var read_back: [3]u16 = undefined;
    try client.readHoldingRegisters(3, 4, &read_back);
    try testing.expectEqualSlices(u16, &.{ 11, 22, 33 }, &read_back);

    const written = [_]bool{ true, true, false, true };
    try client.writeMultipleCoils(3, 8, &written);
    var coils_back: [4]bool = undefined;
    try client.readCoils(3, 8, &coils_back);
    try testing.expectEqualSlices(bool, &written, &coils_back);

    try client.writeSingleCoil(3, 0, true);
    try client.writeSingleRegister(3, 1, 0x1234);
    try testing.expect(coils[0]);
    try testing.expectEqual(@as(u16, 0x1234), regs[1]);

    var rw_out: [2]u16 = undefined;
    try client.readWriteMultipleRegisters(3, 4, &rw_out, 20, &.{ 7, 8 });
    try testing.expectEqualSlices(u16, &.{ 11, 22 }, &rw_out);
    try testing.expectEqual(@as(u16, 7), regs[20]);

    var oops: [2]u16 = undefined;
    try testing.expectError(error.IllegalDataAddress, client.readHoldingRegisters(3, 200, &oops));
}

test "SELF-DERIVED: our Client and our Server complete a full RTU round trip" {
    var regs = [_]u16{0} ** 16;
    var server = srv.Server.init(
        .{ .unit_id = 9, .framing = .rtu },
        .{ .holding_registers = .{ .base = 100, .values = &regs } },
    );

    var loop = Loopback(.rtu){ .server = &server };
    var client = mb.Client.init(.rtu, loop.transport());

    try client.writeSingleRegister(9, 105, 0xCAFE);
    var back: [1]u16 = undefined;
    try client.readHoldingRegisters(9, 105, &back);
    try testing.expectEqual(@as(u16, 0xCAFE), back[0]);
    try testing.expectEqual(@as(u16, 0xCAFE), regs[5]);

    // Below the window base -> IllegalDataAddress, not a wrap into regs[0].
    try testing.expectError(error.IllegalDataAddress, client.readHoldingRegisters(9, 99, &back));
    // A request for another slave gets no reply at all: the transport times out.
    try testing.expectError(error.Timeout, client.readHoldingRegisters(8, 105, &back));
}
