// SPDX-License-Identifier: MIT

//! dnp3.goldens — byte-exact wire goldens.
//!
//! Every golden below is a complete data-link frame, replayed through the same
//! `outstation.Session` the capture harness ran. Each one is labelled with its
//! provenance:
//!
//! - **CAPTURED** — copied verbatim out of a live TCP session between this
//!   module and a real third-party peer (opendnp3 3.1.x, built from source).
//!   See `SPEC.md` "Verification" for the capture topology; the harness is
//!   reproducible.
//! - **SELF-DERIVED** — built by this module and only checked for internal
//!   consistency (round-trip, field values). These prove the codec is
//!   self-consistent, not that it matches anyone else.
//!
//! The captured sessions are **ordered and stateful**: the outstation's IIN
//! bits, event buffer and event timestamps all depend on what came before, so
//! replaying a golden out of order will not reproduce it. The harness advanced
//! its injected clock by exactly 10 ms per step, and these tests do the same —
//! which is why the 48-bit event timestamps in the captured event responses
//! come back byte-identical.

const std = @import("std");
const dnp3 = @import("root.zig");
const outstation = @import("outstation.zig");
const records = @import("records.zig");

const testing = std.testing;

/// One step of a captured session: either a frame exchange, or the moment the
/// operator poked the simulated process image.
const Step = union(enum) {
    exchange: struct {
        /// Hex of one complete inbound data-link frame.
        request: []const u8,
        /// Hex of the concatenated outbound frames, or null for silence.
        reply: ?[]const u8,
    },
    /// The harness toggled binary input 0 and bumped analog input 1.
    inject_event,
};

// ── CAPTURED: opendnp3 master-demo -> this module's Outstation ──────────────
//
// Recorded 2026-07-23. opendnp3's `master-demo` (master address 1, outstation
// address 10) connected to a real loopback TCP socket; a proxy split the byte
// stream into data-link frames and handed each to this module's
// `outstation.Session`; every reply byte came out of this module. The master
// ran its startup tasks and then, on the operator's keystrokes: integrity
// scan, ad-hoc range scan of g1v2 0..3, disable-unsolicited, a CROB
// select+operate, a class-1 exception scan across an injected process change,
// a cold restart, and a second integrity scan. opendnp3 logged
// "Received command result w/ summary: SUCCESS" for the CROB and
// "Success, Time: 100" for the restart, and raised no protocol warnings.
const opendnp3_session = [_]Step{
    .{ .exchange = .{
        .request = "056411c40a0001000615c0c0153c02063c03063c04061a55",
        .reply = "05640a4401000a006e25c0c08190009b2c",
    } },
    .{ .exchange = .{
        .request = "05640ec40a0001002529c1c102500100070700ff81",
        .reply = "05640a4401000a006e25c1c18110005ad6",
    } },
    .{ .exchange = .{
        .request = "056414c40a0001008fedc2c2013c02063c03063c04063c01065af0",
        .reply = "0564a54401000a008d81c2c281100001020000098101018101012a82810101810302000003014181c10a0200" ++
            "9c1e0005018101810181140100000401e80333c0000001e903000001ea03000001eb030037930001ec030000" ++
            "150100000401f4010000f65601f501000001f601000001f70100000106b1f80100001e0100000501ecffffff" ++
            "01f6f151ffffff0100000000010a000000011400c7960000011e000000280100000301000000991f00010100" ++
            "000001020000000103000000c9b5",
    } },
    .{ .exchange = .{
        .request = "056411c40a0001000615c3c3143c02063c03063c0406bad5",
        .reply = "05640a4401000a006e25c3c3811000ff58",
    } },
    .{ .exchange = .{
        .request = "056414c40a0001008fedc4c4013c02063c03063c04063c0106535f",
        .reply = "0564a54401000a008d81c4c48110000102000009810101810101524b810101810302000003014181c10a0200" ++
            "9c1e0005018101810181140100000401e80333c0000001e903000001ea03000001eb030037930001ec030000" ++
            "150100000401f4010000f65601f501000001f601000001f70100000106b1f80100001e0100000501ecffffff" ++
            "01f6f151ffffff0100000000010a000000011400c7960000011e000000280100000301000000991f00010100" ++
            "000001020000000103000000c9b5",
    } },
    .{ .exchange = .{
        .request = "05640bc40a000100acd1c5c5013c0206c3b7",
        .reply = "05640a4401000a006e25c5c58110006986",
    } },
    .{ .exchange = .{
        .request = "05640bc40a000100acd1c6c6013c02069941",
        .reply = "05640a4401000a006e25c6c681100022e9",
    } },
    .{ .exchange = .{
        .request = "056414c40a0001008fedc7c7013c02063c03063c04063c01066bae",
        .reply = "0564a54401000a008d81c7c78110000102000009810101810101ee2f810101810302000003014181c10a0200" ++
            "9c1e0005018101810181140100000401e80333c0000001e903000001ea03000001eb030037930001ec030000" ++
            "150100000401f4010000f65601f501000001f601000001f70100000106b1f80100001e0100000501ecffffff" ++
            "01f6f151ffffff0100000000010a000000011400c7960000011e000000280100000301000000991f00010100" ++
            "000001020000000103000000c9b5",
    } },
    .{ .exchange = .{
        .request = "05640fc40a000100c29cc8c801010201000003008eeb",
        .reply = "0564134401000a009472c8c8811000010200000381010181c3ea",
    } },
    .{ .exchange = .{
        .request = "05640bc40a000100acd1c9c9013c020620b9",
        .reply = "05640a4401000a006e25c9c98110003c76",
    } },
    .{ .exchange = .{
        .request = "056411c40a0001000615caca153c02063c03063c0406ef90",
        .reply = "05640a4401000a006e25caca8110007719",
    } },
    .{ .exchange = .{
        .request = "05641ac40a0001008a1ccbcb030c012801000000030164000000985e6400000000005b",
        .reply = "05641c4401000a007636cbcb8110000c01280100000003016400a38500006400000000005b",
    } },
    .{ .exchange = .{
        .request = "05641ac40a0001008a1ccccc040c012801000000030164000000a40c6400000000005b",
        .reply = "05641c4401000a007636cccc8112000c0128010000000301640039d100006400000000005b",
    } },
    .inject_event,
    .{ .exchange = .{
        .request = "05640bc40a000100acd1cdcd013c02065678",
        .reply = "0564224401000a00304ecded8116000b021701008182000000003ebd000202170100018c00000000009d6c",
    } },
    .{ .exchange = .{
        .request = "056408c40a000100fc42cecd0073fd",
        .reply = null,
    } },
    .{ .exchange = .{
        .request = "05640bc40a000100acd1cfce013c0206eb3b",
        .reply = "05640a4401000a006e25cece8114008e7e",
    } },
    .{ .exchange = .{
        .request = "056408c40a000100fc42d0cf0d90b8",
        .reply = "0564104401000a00c4e1cfcf8190003402070164007aaf",
    } },
    .{ .exchange = .{
        .request = "05640ec40a0001002529d1c00250010007070023bf",
        .reply = "05640a4401000a006e25d0c0811000269d",
    } },
    .{ .exchange = .{
        .request = "056414c40a0001008fedd2c1013c02063c03063c04063c0106a5b0",
        .reply = "0564a54401000a008d81d1c181100001020000090101018101014857810101810302000003014181c10a0200" ++
            "9c1e0005818101810181140100000401e8031249000001e903000001ea03000001eb030037930001ec030000" ++
            "150100000401f4010000f65601f501000001f601000001f70100000106b1f80100001e0100000501ecffffff" ++
            "01f7af67ffffff0100000000010a000000011400c7960000011e000000280100000301000000991f00010100" ++
            "000001020000000103000000c9b5",
    } },
    .{ .exchange = .{
        .request = "056411c40a0001000615d3c2143c02063c03063c0406111e",
        .reply = "05640a4401000a006e25d2c28110008313",
    } },
    .{ .exchange = .{
        .request = "05640bc40a000100acd1d4c3013c0206f1b0",
        .reply = "05640a4401000a006e25d3c38110006df2",
    } },
    .{ .exchange = .{
        .request = "056414c40a0001008fedd5c4013c02063c03063c04063c0106a432",
        .reply = "0564a54401000a008d81d4c481100001020000090101018101018cfa810101810302000003014181c10a0200" ++
            "9c1e0005818101810181140100000401e8031249000001e903000001ea03000001eb030037930001ec030000" ++
            "150100000401f4010000f65601f501000001f601000001f70100000106b1f80100001e0100000501ecffffff" ++
            "01f7af67ffffff0100000000010a000000011400c7960000011e000000280100000301000000991f00010100" ++
            "000001020000000103000000c9b5",
    } },
};
// 23 steps

// ── CAPTURED: the same master against a *fragmented* response ──────────────
//
// The same run with 300 binary inputs and `max_tx_fragment = 400`, so the
// class-0 integrity scan cannot fit in one application fragment. opendnp3
// confirms each non-final fragment and reassembles the series; it logged no
// "Response with bad sequence" warnings, which is exactly what an earlier
// draft of this code got wrong.
const opendnp3_fragmented_session = [_]Step{
    .{ .exchange = .{
        .request = "056411c40a0001000615c0c0153c02063c03063c04061a55",
        .reply = "05640a4401000a006e25c0c08190009b2c",
    } },
    .{ .exchange = .{
        .request = "05640ec40a0001002529c1c102500100070700ff81",
        .reply = "05640a4401000a006e25c1c18110005ad6",
    } },
    .{ .exchange = .{
        .request = "056414c40a0001008fedc2c2013c02063c03063c04063c01065af0",
        .reply = "0564ff4401000a005aeb42a281100001020100002b0181010181a8fe01018101018101018101018101018101" ++
            "c17e01810101810101810101810101810101a998810101810101810101810101810101818bbb010181010181" ++
            "01018101018101018101c17e01810101810101810101810101810101a9988101018101018101018101018101" ++
            "01818bbb01018101018101018101018101018101c17e01810101810101810101810101810101a99881010181" ++
            "0101810101810101810101818bbb01018101018101018101018101018101c17e018101018101018101018101" ++
            "01810101a998810101810101810101810101810101818bbb01018101018101018101018101018101c17e0181" ++
            "0101810101810101810101810101a998810101810101810101817ee40564944401000a0029bd830101810101" ++
            "81010181010181010181932001018101018101018101018101018101c17e0181010181010181010181010181" ++
            "0101a998810101810101810101810101810101038b7102000003014181c10a02000005018101dd3681018114" ++
            "0100000401e803000001e9033725000001ea03000001eb03000001ec0300402800150100000401f401000001" ++
            "f50100009a2101f601000001f701000001f8010000f98d",
    } },
    .{ .exchange = .{
        .request = "056408c40a000100fc42c3c2001ea7",
        .reply = "0564464401000a00a15cc4438110001e0100000501ecffffff012faaf6ffffff0100000000010a0000000114" ++
            "5c2f000000011e0000002801000003010000d6e100000101000000010200000001030000f18400ffff",
    } },
    .{ .exchange = .{
        .request = "056411c40a0001000615c4c4143c02063c03063c040657a8",
        .reply = "05640a4401000a006e25c5c48110008144",
    } },
    .{ .exchange = .{
        .request = "056414c40a0001008fedc5c5013c02063c03063c04063c0106bb0f",
        .reply = "0564ff4401000a005aeb46a581100001020100002b0181010181d0c201018101018101018101018101018101" ++
            "c17e01810101810101810101810101810101a998810101810101810101810101810101818bbb010181010181" ++
            "01018101018101018101c17e01810101810101810101810101810101a9988101018101018101018101018101" ++
            "01818bbb01018101018101018101018101018101c17e01810101810101810101810101810101a99881010181" ++
            "0101810101810101810101818bbb01018101018101018101018101018101c17e018101018101018101018101" ++
            "01810101a998810101810101810101810101810101818bbb01018101018101018101018101018101c17e0181" ++
            "0101810101810101810101810101a998810101810101810101817ee40564944401000a0029bd870101810101" ++
            "81010181010181010181da5b01018101018101018101018101018101c17e0181010181010181010181010181" ++
            "0101a998810101810101810101810101810101038b7102000003014181c10a02000005018101dd3681018114" ++
            "0100000401e803000001e9033725000001ea03000001eb03000001ec0300402800150100000401f401000001" ++
            "f50100009a2101f601000001f701000001f8010000f98d",
    } },
    .{ .exchange = .{
        .request = "056408c40a000100fc42c6c500275f",
        .reply = "0564464401000a00a15cc8468110001e0100000501ecffffff01f5bcf6ffffff0100000000010a0000000114" ++
            "5c2f000000011e0000002801000003010000d6e100000101000000010200000001030000f18400ffff",
    } },
    .{ .exchange = .{
        .request = "05640bc40a000100acd1c7c7013c020678d7",
        .reply = "05640a4401000a006e25c9c78110009197",
    } },
    .{ .exchange = .{
        .request = "056414c40a0001008fedc8c8013c02063c03063c04063c0106384c",
        .reply = "0564ff4401000a005aeb4aa881100001020100002b0181010181417301018101018101018101018101018101" ++
            "c17e01810101810101810101810101810101a998810101810101810101810101810101818bbb010181010181" ++
            "01018101018101018101c17e01810101810101810101810101810101a9988101018101018101018101018101" ++
            "01818bbb01018101018101018101018101018101c17e01810101810101810101810101810101a99881010181" ++
            "0101810101810101810101818bbb01018101018101018101018101018101c17e018101018101018101018101" ++
            "01810101a998810101810101810101810101810101818bbb01018101018101018101018101018101c17e0181" ++
            "0101810101810101810101810101a998810101810101810101817ee40564944401000a0029bd8b0101810101" ++
            "8101018101018101018101d601018101018101018101018101018101c17e0181010181010181010181010181" ++
            "0101a998810101810101810101810101810101038b7102000003014181c10a02000005018101dd3681018114" ++
            "0100000401e803000001e9033725000001ea03000001eb03000001ec0300402800150100000401f401000001" ++
            "f50100009a2101f601000001f701000001f8010000f98d",
    } },
    .{ .exchange = .{
        .request = "056408c40a000100fc42c9c800df2d",
        .reply = "0564464401000a00a15ccc498110001e0100000501ecffffff01c627f6ffffff0100000000010a0000000114" ++
            "5c2f000000011e0000002801000003010000d6e100000101000000010200000001030000f18400ffff",
    } },
    .{ .exchange = .{
        .request = "05640bc40a000100acd1caca013c02067a4f",
        .reply = "05640a4401000a006e25cdca81100065f0",
    } },
    .{ .exchange = .{
        .request = "05640bc40a000100acd1cbcb013c02069bd9",
        .reply = "05640a4401000a006e25cecb8110008757",
    } },
};
// 12 steps

// ── replay ──────────────────────────────────────────────────────────────────

/// The device the capture harness ran. `binary_count` and `max_tx_fragment`
/// are the only two knobs the two captured sessions differ in.
const Fixture = struct {
    binaries: [300]outstation.BinaryInput = undefined,
    dbits: [4]outstation.DoubleBitInput = undefined,
    bouts: [6]outstation.BinaryOutputStatus = undefined,
    counters: [5]outstation.Counter = undefined,
    frozen: [5]outstation.FrozenCounter = undefined,
    analogs: [6]outstation.AnalogInput = undefined,
    aouts: [4]outstation.AnalogOutputStatus = undefined,
    event_storage: [64]outstation.Event = undefined,

    fn station(
        self: *Fixture,
        binary_count: usize,
        max_tx_fragment: usize,
    ) outstation.Outstation {
        for (&self.binaries, 0..) |*p, i| p.* = .{
            .value = (i % 3 == 0),
            .class = .class1,
            .static_variation = 2,
            .event_variation = 2,
        };
        for (&self.dbits, 0..) |*p, i| p.* = .{
            .value = @enumFromInt(@as(u2, @intCast(i % 4))),
            .class = .class1,
            .static_variation = 2,
            .event_variation = 2,
        };
        for (&self.bouts, 0..) |*p, i| p.* = .{
            .value = (i % 2 == 1),
            .class = .class1,
            .static_variation = 2,
            .event_variation = 2,
        };
        for (&self.counters, 0..) |*p, i| p.* = .{
            .value = @intCast(1000 + i),
            .class = .class3,
            .static_variation = 1,
            .event_variation = 1,
        };
        for (&self.frozen, 0..) |*p, i| p.* = .{
            .value = @intCast(500 + i),
            .class = null,
            .static_variation = 1,
        };
        for (&self.analogs, 0..) |*p, i| p.* = .{
            .value = @floatFromInt(@as(i32, @intCast(i)) * 10 - 20),
            .class = .class2,
            .static_variation = 1,
            .event_variation = 1,
        };
        for (&self.aouts, 0..) |*p, i| p.* = .{
            .value = @floatFromInt(i),
            .class = null,
            .static_variation = 1,
            .min = -1000,
            .max = 1000,
        };

        return outstation.Outstation.init(.{
            .address = 10,
            .master_address = 1,
            .max_tx_fragment = max_tx_fragment,
            .unsolicited_supported = true,
            .allow_restart = true,
            .restart_delay_ms = 100,
            .delay_measure_ms = 7,
        }, .{
            .binary_inputs = self.binaries[0..binary_count],
            .double_bit_inputs = &self.dbits,
            .binary_outputs = &self.bouts,
            .counters = &self.counters,
            .frozen_counters = &self.frozen,
            .analog_inputs = &self.analogs,
            .analog_outputs = &self.aouts,
        }, outstation.EventBuffer.init(&self.event_storage));
    }
};

fn hexBytes(buf: []u8, hex: []const u8) ![]u8 {
    return std.fmt.hexToBytes(buf, hex);
}

/// Replays a captured session and asserts every reply byte.
fn replay(
    steps: []const Step,
    binary_count: usize,
    max_tx_fragment: usize,
) !void {
    var fixture: Fixture = undefined;
    var station = fixture.station(binary_count, max_tx_fragment);

    var rx_buf: [4096]u8 = undefined;
    var scratch: [512]u8 = undefined;
    var tx_fragment: [2048]u8 = undefined;
    var session = outstation.Session.init(&station, &rx_buf, &scratch, &tx_fragment);

    var frame_buf: [1024]u8 = undefined;
    var want_buf: [8192]u8 = undefined;
    var out_buf: [8192]u8 = undefined;
    var now: u64 = 0;

    for (steps, 0..) |step, step_index| {
        now += 10;
        switch (step) {
            .inject_event => {
                fixture.binaries[0].value = !fixture.binaries[0].value;
                station.reportChange(.binary_input, 0, now);
                fixture.analogs[1].value += 1;
                station.reportChange(.analog_input, 1, now);
            },
            .exchange => |ex| {
                const frame = try hexBytes(&frame_buf, ex.request);
                const got = session.feedFrame(frame, now, &out_buf) catch |err| {
                    std.debug.print("step {d}: feedFrame failed: {s}\n", .{ step_index, @errorName(err) });
                    return err;
                };
                if (ex.reply) |reply_hex| {
                    const want = try hexBytes(&want_buf, reply_hex);
                    if (got == null) {
                        std.debug.print("step {d}: expected a reply, got silence\n", .{step_index});
                        return error.TestUnexpectedResult;
                    }
                    testing.expectEqualSlices(u8, want, got.?) catch |err| {
                        std.debug.print("step {d} reply mismatch\n", .{step_index});
                        return err;
                    };
                } else if (got != null) {
                    std.debug.print("step {d}: expected silence, got a reply\n", .{step_index});
                    return error.TestUnexpectedResult;
                }
            },
        }
    }
}

test "CAPTURED: replaying the live opendnp3 session reproduces every reply byte-for-byte" {
    try replay(&opendnp3_session, 10, 2048);
}

test "CAPTURED: the fragmented session reproduces byte-for-byte, FIR/FIN/SEQ included" {
    try replay(&opendnp3_fragmented_session, 300, 400);
}

// ── CAPTURED: this module's master-side codecs -> a live opendnp3 outstation ─
//
// The reverse direction, recorded 2026-07-23 against opendnp3's
// `outstation-demo` (outstation address 10, master address 1) over a real
// loopback TCP socket. The requests were built by this module's
// `link`/`transport`/`application`/`objects` codecs; the responses are
// opendnp3's *encoder*, so these cross-check the pre-existing master-side
// parsers against a third-party implementation. opendnp3's demo database is
// all-zero, which is why every value below is 0.
const opendnp3_outstation_replies = [_]struct {
    name: []const u8,
    /// Hex of the link frames our master put on the wire.
    request: []const u8,
    /// Hex of the link frame opendnp3's outstation sent back.
    reply: []const u8,
}{
    .{
        .name = "our READ class 0 -> opendnp3's unsolicited NULL response",
        .request = "05640bc40a000100acd1c0c0013c0106ff50",
        .reply = "05640a4401000a006e25c0f082900043a2",
    },
    .{
        .name = "our READ g1v2 [0,4] -> 5 binary inputs",
        .request = "05640dc40a00010075bac0c1010102000004ac9d",
        .reply = "0564144401000a00aaacc1c1819000010200000402020202023339",
    },
    .{
        .name = "our READ g20v1 all-objects -> 10 counters",
        .request = "05640bc40a000100acd1c0c301140106be18",
        .reply = "0564414401000a009f82c3c381900014010000090200000000020fce000000000200000000020000000002" ++
            "0069ce00000002000000000200000000020000dd5e0000020000000002000000004e72",
    },
    .{
        .name = "our DIRECT_OPERATE CROB -> opendnp3's g52v2 delay reply",
        .request = "056418c40a0001003d3ac0c5050c01170100030164000000640084bc000000ffff",
        .reply = "0564104401000a00c4e1c5c48190003402070100007ea8",
    },
};

test "CAPTURED: our master's codecs parse what opendnp3's outstation encoded" {
    var frame_buf: [1024]u8 = undefined;
    var scratch: [512]u8 = undefined;
    var reasm: [1024]u8 = undefined;

    // 1. The unsolicited NULL response opendnp3 opens with.
    {
        const frame = try hexBytes(&frame_buf, opendnp3_outstation_replies[0].reply);
        var receiver = dnp3.FrameReceiver.init(&reasm);
        const fragment = (try receiver.feedFrame(frame, &scratch)).?;
        const decoded = try dnp3.application.decodeResponseHeader(fragment);
        try testing.expectEqual(dnp3.application.FunctionCode.unsolicited_response, decoded.header.function);
        try testing.expect(decoded.header.control.uns);
        try testing.expect(decoded.header.control.con);
        // IIN 0x90 0x00: device restart + need time -- a freshly started
        // outstation, exactly what ours reports at start-up too.
        try testing.expect(decoded.header.iin.device_restart);
        try testing.expect(decoded.header.iin.need_time);
        try testing.expectEqual(@as(usize, 0), decoded.rest.len);
    }

    // 2. Five g1v2 binary inputs, all offline-but-known (flags 0x02 = RESTART).
    {
        const frame = try hexBytes(&frame_buf, opendnp3_outstation_replies[1].reply);
        var receiver = dnp3.FrameReceiver.init(&reasm);
        const fragment = (try receiver.feedFrame(frame, &scratch)).?;
        const decoded = try dnp3.application.decodeResponseHeader(fragment);
        const hdr = try dnp3.objects.decodeObjectHeader(decoded.rest);
        try testing.expectEqual(@as(u8, 1), hdr.header.group);
        try testing.expectEqual(@as(u8, 2), hdr.header.variation);
        try testing.expectEqual(@as(u64, 5), hdr.header.range.objectCount().?);
        const layout = records.layoutOf(1, 2).?;
        const body = decoded.rest[hdr.consumed..];
        for (0..5) |i| {
            const rec = try records.decode(layout, .binary_input, body[i..]);
            try testing.expect(!rec.value.binary);
            try testing.expect(rec.flags.restart);
        }
    }

    // 3. Ten g20v1 counters, all zero.
    {
        const frame = try hexBytes(&frame_buf, opendnp3_outstation_replies[2].reply);
        var receiver = dnp3.FrameReceiver.init(&reasm);
        const fragment = (try receiver.feedFrame(frame, &scratch)).?;
        const decoded = try dnp3.application.decodeResponseHeader(fragment);
        const hdr = try dnp3.objects.decodeObjectHeader(decoded.rest);
        try testing.expectEqual(@as(u8, 20), hdr.header.group);
        try testing.expectEqual(@as(u64, 10), hdr.header.range.objectCount().?);
        const layout = records.layoutOf(20, 1).?;
        const body = decoded.rest[hdr.consumed..];
        for (0..10) |i| {
            const rec = try records.decode(layout, .counter, body[i * layout.wireLen().? ..]);
            try testing.expectEqual(@as(u32, 0), rec.value.counter);
        }
    }

    // 4. g52v2 time delay.
    {
        const frame = try hexBytes(&frame_buf, opendnp3_outstation_replies[3].reply);
        var receiver = dnp3.FrameReceiver.init(&reasm);
        const fragment = (try receiver.feedFrame(frame, &scratch)).?;
        const decoded = try dnp3.application.decodeResponseHeader(fragment);
        const hdr = try dnp3.objects.decodeObjectHeader(decoded.rest);
        try testing.expectEqual(@as(u8, 52), hdr.header.group);
        try testing.expectEqual(@as(u8, 2), hdr.header.variation);
    }
}

test "CAPTURED: every request our master sent re-encodes byte-identically" {
    var frame_buf: [1024]u8 = undefined;
    var scratch: [512]u8 = undefined;
    var out: [1024]u8 = undefined;

    for (opendnp3_outstation_replies) |ex| {
        // The request is one link frame carrying one transport segment.
        const frame = try hexBytes(&frame_buf, ex.request);
        const decoded = try dnp3.link.decodeFrame(frame, &scratch);
        const again = try dnp3.link.encodeFrame(
            decoded.control,
            decoded.dest,
            decoded.src,
            scratch[0..decoded.user_data_len],
            &out,
        );
        try testing.expectEqualSlices(u8, frame, again);
    }
}

// ── SELF-DERIVED: the module's two halves talking to each other ────────────

test "SELF-DERIVED: our own master-side codecs drive our own outstation" {
    var fixture: Fixture = undefined;
    var station = fixture.station(10, 2048);
    station.restart = false;

    var rx_buf: [4096]u8 = undefined;
    var scratch: [512]u8 = undefined;
    var tx_fragment: [2048]u8 = undefined;
    var session = outstation.Session.init(&station, &rx_buf, &scratch, &tx_fragment);

    // Master side: a class-0 integrity poll, sent through the real link and
    // transport layers.
    var req: [64]u8 = undefined;
    const fragment = try dnp3.application.buildRequest(
        4,
        .read,
        dnp3.objects.g60.readClassHeader(.class0),
        &req,
    );
    var wire: [512]u8 = undefined;
    const frames = try dnp3.sendFragment(
        .{ .dir = true, .prm = true, .function = @intFromEnum(dnp3.link.PrimaryFunction.unconfirmed_user_data) },
        10,
        1,
        fragment,
        &wire,
    );

    var out: [2048]u8 = undefined;
    const reply_frames = (try session.feedFrame(frames, 1000, &out)).?;

    // Master side again: reassemble and parse the response.
    var reasm: [2048]u8 = undefined;
    var receiver = dnp3.FrameReceiver.init(&reasm);
    var scratch2: [512]u8 = undefined;
    var offset: usize = 0;
    var response: ?[]const u8 = null;
    while (offset < reply_frames.len) {
        const user_len: usize = @as(usize, reply_frames[offset + 2]) - 5;
        const blocks = if (user_len == 0) 0 else std.math.divCeil(usize, user_len, dnp3.link.max_block_len) catch unreachable;
        const frame_len = dnp3.link.header_frame_len + user_len + blocks * dnp3.link.crc_len;
        response = try receiver.feedFrame(reply_frames[offset..][0..frame_len], &scratch2);
        offset += frame_len;
    }

    const decoded = try dnp3.application.decodeResponseHeader(response.?);
    try testing.expectEqual(dnp3.application.FunctionCode.response, decoded.header.function);
    try testing.expectEqual(@as(u4, 4), decoded.header.control.seq);
    try testing.expect(decoded.header.control.fir and decoded.header.control.fin);

    // Walk every object header and check the point values came back intact.
    var rest = decoded.rest;
    var groups_seen: usize = 0;
    var first_analog: ?i32 = null;
    while (rest.len > 0) {
        const hdr = dnp3.objects.decodeObjectHeader(rest) catch break;
        rest = rest[hdr.consumed..];
        groups_seen += 1;
        const layout = records.layoutOf(hdr.header.group, hdr.header.variation) orelse break;
        const count: usize = @intCast(hdr.header.range.objectCount() orelse break);
        if (layout.isPacked()) {
            rest = rest[records.packedBitBytes(count)..];
            continue;
        }
        const each = layout.wireLen().?;
        if (hdr.header.group == 30 and first_analog == null) {
            const rec = try records.decode(layout, .analog_input, rest);
            first_analog = rec.value.analog_int;
        }
        rest = rest[count * each ..];
    }
    try testing.expectEqual(@as(usize, 7), groups_seen);
    // The fixture seeds analog input 0 at (0 * 10 - 20) = -20.
    try testing.expectEqual(@as(i32, -20), first_analog.?);
}
