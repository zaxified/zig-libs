// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for tenantkex (added 2026-10-10): `TENANTKEX_FUZZ=<runs>[,<first seed>]`
//! (testkit's driver; `_ONLY` selects a harness by name). Harness name:
//! `tenantkex-handshake`: a whole Noise_IK exchange between an Initiator and a
//! Responder with knob-chosen static keys, fabric context and payloads; the
//! genuine exchange agrees on the payloads, the crossed session keys and the
//! transcript hash; ONE flipped bit in message 1 or message 2, a wrong fabric
//! context, an unexpected initiator static, damaged copies and out-of-order
//! calls are refused (never a panic), and a refused message 1 does not let
//! the responder write message 2.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;
pub const Cursor = testkit.fuzz.Cursor;

/// Reach counters for one harness's labels. `mark` also feeds the driver's
/// `REACH` report; `reach` runs `seeds` seeds in the ordinary test binary and
/// fails with `error.HarnessDoesNotReach` if a label never fired.
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

/// `frame` into `buf` with 0-3 octets damaged and maybe truncated.
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        buf[src.index(n)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Deterministic bytes from a knob cursor (its first octets seed a PRNG).
pub fn expand(knobs: *Cursor, out: []u8) void {
    var s: u64 = 0;
    for (0..8) |_| s = (s << 8) | knobs.byte();
    var prng = std.Random.DefaultPrng.init(s);
    prng.random().bytes(out);
}

/// Smith-side wrapper so `--fuzz` keeps working: the harness bodies are
/// generic over `S`; `testing.fuzz` hands them a `std.testing.Smith`.
pub fn smithWrap(comptime harness: anytype) fn (void, *std.testing.Smith) anyerror!void {
    return struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            try harness(std.testing.Smith, smith, testing.allocator);
        }
    }.f;
}

const tk = @import("root.zig");
const KeyPair = tk.KeyPair;

fn flipBit(knobs: *Cursor, bytes: []u8) void {
    const at = (@as(usize, knobs.byte()) << 8 | knobs.byte()) % bytes.len;
    bytes[at] ^= @as(u8, 1) << @intCast(knobs.ranged(0, 7));
}

fn kpOf(knobs: *Cursor) !KeyPair {
    var seed: [32]u8 = undefined;
    expand(knobs, &seed);
    return KeyPair.generateDeterministic(seed);
}

const Mark = Marker(enum {
    genuine,
    flipped_msg1_refused,
    flipped_msg2_refused,
    wrong_context_refused,
    wrong_initiator_refused,
    damaged_msg1_refused,
    damaged_msg2_refused,
    state_errors,
    refused_cannot_continue,
});

fn fuzzHandshake(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [32]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    const is = try kpOf(&knobs);
    const rs = try kpOf(&knobs);
    const ie = try kpOf(&knobs);
    const re = try kpOf(&knobs);
    const stranger = try kpOf(&knobs);
    const ctx: tk.FabricContext = .{
        .isid = @intCast(knobs.ranged(0, 255) << 16 | knobs.ranged(0, 255) << 8 | knobs.ranged(0, 255)),
        .initiator_pe = knobs.ranged(0, 255),
        .responder_pe = knobs.ranged(0, 255),
    };
    var p1: [24]u8 = undefined;
    var p2: [24]u8 = undefined;
    expand(&knobs, &p1);
    expand(&knobs, &p2);
    const pl1 = p1[0..knobs.ranged(0, 24)];
    const pl2 = p2[0..knobs.ranged(0, 24)];
    var prng = std.Random.DefaultPrng.init(knobs.byte());

    var ini: tk.Initiator = undefined;
    ini.initEphemeral(&is, rs.public_key, ctx, &ie);
    var m1: [64 + 24 + 16 + 16]u8 = undefined;
    const l1 = try ini.writeMessage1(prng.random(), pl1, &m1);
    if (l1 != tk.message1Len(pl1.len)) return error.Message1LengthDiffers;
    const wire1 = m1[0..l1];

    var rsp: tk.Responder = undefined;
    rsp.initEphemeral(&rs, is.public_key, ctx, &re);
    var out1: [24]u8 = undefined;
    const n1 = rsp.readMessage1(wire1, &out1) catch return error.GenuineMessage1Refused;
    if (!std.mem.eql(u8, out1[0..n1], pl1)) return error.Payload1Differs;
    var m2: [32 + 24 + 16 + 16]u8 = undefined;
    var rkeys: tk.SessionKeys = undefined;
    const l2 = try rsp.writeMessage2(prng.random(), pl2, &m2, &rkeys);
    if (l2 != tk.message2Len(pl2.len)) return error.Message2LengthDiffers;
    const wire2 = m2[0..l2];
    var ikeys: tk.SessionKeys = undefined;
    var out2: [24]u8 = undefined;
    const n2 = ini.readMessage2(wire2, &out2, &ikeys) catch return error.GenuineMessage2Refused;
    if (!std.mem.eql(u8, out2[0..n2], pl2)) return error.Payload2Differs;
    if (!std.mem.eql(u8, &ikeys.send_key, &rkeys.recv_key) or !std.mem.eql(u8, &ikeys.recv_key, &rkeys.send_key)) return error.KeysDoNotCross;
    if (!std.mem.eql(u8, &ikeys.transcript_hash, &rkeys.transcript_hash)) return error.TranscriptDiffers;
    Mark.mark(.genuine);

    // Out-of-order calls: typed errors, never a panic.
    {
        if (ini.writeMessage1(prng.random(), pl1, &m1)) |_| return error.WrongStateAccepted else |_| {}
        if (rsp.readMessage1(wire1, &out1)) |_| return error.WrongStateAccepted else |_| {}
        if (ini.readMessage2(wire2, &out2, &ikeys)) |_| return error.WrongStateAccepted else |_| {}
        var fresh: tk.Initiator = undefined;
        fresh.initEphemeral(&is, rs.public_key, ctx, &ie);
        if (fresh.readMessage2(wire2, &out2, &ikeys)) |_| return error.WrongStateAccepted else |_| {}
        Mark.mark(.state_errors);
    }

    // Message 1: flipped bit, wrong context, wrong initiator, damaged copy.
    {
        var bad: [m1.len]u8 = undefined;
        @memcpy(bad[0..l1], wire1);
        flipBit(&knobs, bad[0..l1]);
        var r: tk.Responder = undefined;
        r.initEphemeral(&rs, is.public_key, ctx, &re);
        if (r.readMessage1(bad[0..l1], &out1)) |_| return error.FlippedMessage1Accepted else |_| Mark.mark(.flipped_msg1_refused);
        // A refused message 1 must not let the responder answer.
        if (r.writeMessage2(prng.random(), pl2, &m2, &rkeys)) |_| return error.AnsweredAfterRefusal else |_| Mark.mark(.refused_cannot_continue);

        var ctx2 = ctx;
        ctx2.initiator_pe +%= 1 + knobs.ranged(0, 3);
        var r2: tk.Responder = undefined;
        r2.initEphemeral(&rs, is.public_key, ctx2, &re);
        if (r2.readMessage1(wire1, &out1)) |_| return error.WrongContextAccepted else |_| Mark.mark(.wrong_context_refused);

        var r3: tk.Responder = undefined;
        r3.initEphemeral(&rs, stranger.public_key, ctx, &re);
        if (!std.mem.eql(u8, &stranger.public_key, &is.public_key)) {
            if (r3.readMessage1(wire1, &out1)) |_| return error.UnknownInitiatorAccepted else |e| {
                if (e != error.UnknownInitiator) return error.WrongRefusalKind;
                Mark.mark(.wrong_initiator_refused);
            }
        }

        var buf: [m1.len + 8]u8 = undefined;
        const n = damage(src, &buf, wire1);
        var r4: tk.Responder = undefined;
        r4.initEphemeral(&rs, is.public_key, ctx, &re);
        var big: [m1.len + 8]u8 = undefined;
        if (r4.readMessage1(buf[0..n], &big)) |_| {
            if (!std.mem.eql(u8, buf[0..n], wire1)) return error.DamagedMessage1Accepted;
        } else |_| Mark.mark(.damaged_msg1_refused);
    }
    // Message 2: against an identical, fresh initiator (same ephemeral, same random).
    {
        var prng2 = std.Random.DefaultPrng.init(0);
        var ini2: tk.Initiator = undefined;
        ini2.initEphemeral(&is, rs.public_key, ctx, &ie);
        var dummy: [m1.len]u8 = undefined;
        _ = try ini2.writeMessage1(prng2.random(), pl1, &dummy);
        var bad: [m2.len]u8 = undefined;
        @memcpy(bad[0..l2], wire2);
        flipBit(&knobs, bad[0..l2]);
        if (ini2.readMessage2(bad[0..l2], &out2, &ikeys)) |_| return error.FlippedMessage2Accepted else |_| Mark.mark(.flipped_msg2_refused);

        var ini3: tk.Initiator = undefined;
        ini3.initEphemeral(&is, rs.public_key, ctx, &ie);
        _ = try ini3.writeMessage1(prng2.random(), pl1, &dummy);
        var buf: [m2.len + 8]u8 = undefined;
        const n = damage(src, &buf, wire2);
        if (ini3.readMessage2(buf[0..n], &out2, &ikeys)) |_| {
            if (!std.mem.eql(u8, buf[0..n], wire2)) return error.DamagedMessage2Accepted;
        } else |_| Mark.mark(.damaged_msg2_refused);
    }
}

test "fuzz: tenantkex handshake, genuine agrees / damaged refused" {
    try testing.fuzz({}, smithWrap(fuzzHandshake), .{});
}
test "fuzz driver: TENANTKEX_FUZZ (handshake)" {
    try fuzz_driver.run(fuzzHandshake, .{ .prefix = "TENANTKEX_FUZZ", .name = "tenantkex-handshake", .scale = 2 });
}
test "fuzz harness: handshake, 100 seeds, reaches every outcome" {
    try Mark.reach(fuzzHandshake, "tenantkex-handshake", 100);
}
