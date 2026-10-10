// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for timelock_envelope (added 2026-10-10): `TLE_FUZZ=<runs>[,<first seed>]`
//! (testkit's driver; `_ONLY` selects a harness by name). Harness names:
//! `tle-open` and `tle-stream`. Both open a genuine, once-built (fixed
//! randomness, real drand quicknet material from `security_test.zig`)
//! envelope / stream and a damaged copy of it: the genuine one opens to the
//! exact plaintext; ONE flipped bit, a truncation, an extension, a wrong round
//! signature (the time gate) and a wrong recipient key are refused, a copy
//! with 0-3 octets damaged is accepted only when byte-identical. For the
//! stream, whatever was released before the refusal is a prefix of the
//! genuine plaintext (chunks are authenticated one by one).
//! Each run is a pairing plus an HQC decapsulation, so these harnesses run at
//! `.scale` (see the card).

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

const tlock = @import("tlock");
const hqc = @import("hqc");
const envelope = @import("envelope.zig");
const stream = @import("stream.zig");
const fx = @import("security_test.zig");

const Env = envelope.Envelope128;
const Kem = hqc.Hqc128;
const pa = std.heap.page_allocator; // global-alloc-ok: process-lifetime fuzz/test fixture cached across driver runs, outlives testing.allocator's per-test teardown

const plaintext = "the launch codes expire at dawn";

/// Built once per process: seal is a pairing plus an HQC encapsulation.
const Base = struct {
    var ready = false;
    var kp: Kem.KeyPair = undefined;
    var other: Kem.KeyPair = undefined;
    var env: []u8 = &.{};
    var stream_small: []u8 = &.{};
    var stream_big: []u8 = &.{};
    var big_pt: []u8 = &.{};

    fn get() !void {
        if (ready) return;
        kp = fx.recipientKeypair(0x0C);
        other = fx.recipientKeypair(0x0D);
        const rnd = fx.fixedRandomness();
        env = try Env.seal(pa, plaintext, &kp.ek, fx.quicknetPubkey(), fx.seal_round, &rnd);
        stream_small = try sealStream(plaintext, &rnd);
        big_pt = try pa.alloc(u8, stream.chunk_bytes + 10);
        for (big_pt, 0..) |*b, i| b.* = @truncate(i *% 131 +% 7);
        stream_big = try sealStream(big_pt, &rnd);
        ready = true;
    }

    fn sealStream(pt: []const u8, rnd: *const Env.SealRandomness) ![]u8 {
        var aw: std.Io.Writer.Allocating = .init(pa);
        errdefer aw.deinit();
        var r: std.Io.Reader = .fixed(pt);
        try Env.sealStream(pa, &aw.writer, &r, &kp.ek, fx.quicknetPubkey(), fx.seal_round, rnd);
        return aw.toOwnedSlice();
    }
};

fn flipBit(knobs: *Cursor, bytes: []u8) void {
    const at = (@as(usize, knobs.byte()) << 8 | knobs.byte() *% 31 +% knobs.byte()) % bytes.len;
    bytes[at] ^= @as(u8, 1) << @intCast(knobs.ranged(0, 7));
}

const OpenMark = Marker(enum { genuine, flipped_refused, truncated_refused, extended_refused, damaged_refused, time_gate_closed, wrong_key_refused });

fn fuzzOpen(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    try Base.get();
    var raw: [16]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    const gpa = testing.allocator;
    const which = knobs.ranged(0, 6);
    var buf: [8192]u8 = undefined;
    switch (which) {
        0 => { // the genuine envelope opens
            const pt = Env.open(gpa, Base.env, &Base.kp.dk, fx.round1000Signature()) catch return error.GenuineEnvelopeRefused;
            defer gpa.free(pt);
            if (!std.mem.eql(u8, pt, plaintext)) return error.PlaintextDiffers;
            OpenMark.mark(.genuine);
        },
        1 => { // one flipped bit anywhere
            @memcpy(buf[0..Base.env.len], Base.env);
            flipBit(&knobs, buf[0..Base.env.len]);
            if (Env.open(gpa, buf[0..Base.env.len], &Base.kp.dk, fx.round1000Signature())) |pt| {
                gpa.free(pt);
                return error.FlippedEnvelopeAccepted;
            } else |_| OpenMark.mark(.flipped_refused);
        },
        2 => { // any shorter prefix
            const cut = knobs.ranged(0, 255) % Base.env.len;
            if (Env.open(gpa, Base.env[0..cut], &Base.kp.dk, fx.round1000Signature())) |pt| {
                gpa.free(pt);
                return error.TruncatedEnvelopeAccepted;
            } else |_| OpenMark.mark(.truncated_refused);
        },
        3 => { // trailing bytes
            @memcpy(buf[0..Base.env.len], Base.env);
            const extra = knobs.ranged(1, 8);
            @memset(buf[Base.env.len..][0..extra], knobs.byte());
            if (Env.open(gpa, buf[0 .. Base.env.len + extra], &Base.kp.dk, fx.round1000Signature())) |pt| {
                gpa.free(pt);
                return error.ExtendedEnvelopeAccepted;
            } else |_| OpenMark.mark(.extended_refused);
        },
        4 => { // damage (0-3 octets, maybe truncated)
            const n = damage(src, &buf, Base.env);
            const same = std.mem.eql(u8, buf[0..n], Base.env);
            if (Env.open(gpa, buf[0..n], &Base.kp.dk, fx.round1000Signature())) |pt| {
                defer gpa.free(pt);
                if (!same) return error.DamagedEnvelopeAccepted;
            } else |_| OpenMark.mark(.damaged_refused);
        },
        5 => { // the time gate: a signature of another beacon
            if (Env.open(gpa, Base.env, &Base.kp.dk, fx.wrongSignature())) |pt| {
                gpa.free(pt);
                return error.TimeGateOpenedEarly;
            } else |e| {
                if (e != error.TimeGateClosed) return error.WrongRefusalKind;
                OpenMark.mark(.time_gate_closed);
            }
        },
        else => { // another recipient's key
            if (Env.open(gpa, Base.env, &Base.other.dk, fx.round1000Signature())) |pt| {
                gpa.free(pt);
                return error.WrongKeyAccepted;
            } else |_| OpenMark.mark(.wrong_key_refused);
        },
    }
}

test "fuzz: timelock envelope open, genuine accepted / damaged refused" {
    try testing.fuzz({}, smithWrapOpen, .{});
}
fn smithWrapOpen(_: void, smith: *std.testing.Smith) anyerror!void {
    try fuzzOpen(std.testing.Smith, smith, testing.allocator);
}
test "fuzz driver: TLE_FUZZ (open)" {
    try fuzz_driver.run(fuzzOpen, .{ .prefix = "TLE_FUZZ", .name = "tle-open", .scale = 10, .default_limit_ms = 20_000 });
}
test "fuzz harness: open, 70 seeds, reaches every outcome" {
    try OpenMark.reach(fuzzOpen, "tle-open", 70);
}

const StreamMark = Marker(enum { genuine, genuine_big, flipped_refused, truncated_refused, damaged_refused, boundary_cut_refused, time_gate_closed, wrong_key_refused, released_is_prefix });

fn openStream(wire: []const u8, dk: *const Kem.DecapsKey, sig: tlock.bls12_381.g1.Affine, released: *std.Io.Writer.Allocating) stream.StreamOpenError!void {
    var r: std.Io.Reader = .fixed(wire);
    return Env.openStream(testing.allocator, &released.writer, &r, dk, sig);
}

fn fuzzStream(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    try Base.get();
    var raw: [16]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    const big = knobs.byte() % 4 == 0;
    const wire = if (big) Base.stream_big else Base.stream_small;
    const pt = if (big) Base.big_pt else @as([]const u8, plaintext);
    const gpa = testing.allocator;
    const which = knobs.ranged(0, 6);

    var released: std.Io.Writer.Allocating = .init(gpa);
    defer released.deinit();

    const copy = try gpa.dupe(u8, wire);
    defer gpa.free(copy);
    var used: []const u8 = wire;
    var dk = &Base.kp.dk;
    var sig = fx.round1000Signature();
    switch (which) {
        0 => {},
        1 => {
            flipBit(&knobs, copy);
            used = copy;
        },
        2 => {
            // A cut anywhere; half of them exactly at a chunk boundary.
            const prefix = stream.Stream(Kem).prefix_bytes;
            var cut = knobs.ranged(0, 255) % wire.len;
            if (big and knobs.byte() & 1 == 0) cut = prefix + stream.sealed_chunk_bytes;
            used = wire[0..cut];
        },
        3 => {
            var buf: [8192]u8 = undefined;
            const n = damage(src, &buf, wire[0..@min(wire.len, buf.len)]);
            if (!big) {
                @memcpy(copy[0..n], buf[0..n]);
                used = copy[0..n];
            } else return; // a damaged window of the big stream adds nothing
        },
        4 => sig = fx.wrongSignature(),
        5 => dk = &Base.other.dk,
        else => {
            flipBit(&knobs, copy[0..@min(copy.len, 400)]); // header and the two locks
            used = copy;
        },
    }
    const identical = std.mem.eql(u8, used, wire);
    if (openStream(used, dk, sig, &released)) {
        if (!identical or which >= 4) return error.DamagedStreamAccepted;
        if (!std.mem.eql(u8, released.written(), pt)) return error.PlaintextDiffers;
        if (big) StreamMark.mark(.genuine_big) else StreamMark.mark(.genuine);
    } else |e| {
        if (identical and which < 4) return error.GenuineStreamRefused;
        // Whatever was released is a prefix of the genuine plaintext.
        const got = released.written();
        if (got.len > pt.len or !std.mem.eql(u8, got, pt[0..got.len])) return error.ReleasedNotAPrefix;
        StreamMark.mark(.released_is_prefix);
        switch (which) {
            1, 6 => StreamMark.mark(.flipped_refused),
            2 => {
                StreamMark.mark(.truncated_refused);
                if (big and used.len == stream.Stream(Kem).prefix_bytes + stream.sealed_chunk_bytes) StreamMark.mark(.boundary_cut_refused);
            },
            3 => StreamMark.mark(.damaged_refused),
            4 => {
                if (e != error.TimeGateClosed) return error.WrongRefusalKind;
                StreamMark.mark(.time_gate_closed);
            },
            5 => StreamMark.mark(.wrong_key_refused),
            else => {},
        }
    }
}

test "fuzz: timelock envelope stream, genuine accepted / damaged refused" {
    try testing.fuzz({}, smithWrapStream, .{});
}
fn smithWrapStream(_: void, smith: *std.testing.Smith) anyerror!void {
    try fuzzStream(std.testing.Smith, smith, testing.allocator);
}
test "fuzz driver: TLE_FUZZ (stream)" {
    try fuzz_driver.run(fuzzStream, .{ .prefix = "TLE_FUZZ", .name = "tle-stream", .scale = 10, .default_limit_ms = 20_000 });
}
test "fuzz harness: stream, 120 seeds, reaches every outcome" {
    try StreamMark.reach(fuzzStream, "tle-stream", 120);
}
