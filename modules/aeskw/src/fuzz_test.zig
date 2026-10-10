// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for aeskw (added 2026-10-10): `AESKW_FUZZ=<runs>[,<first seed>]`
//! (testkit's driver; `_ONLY` selects a harness by name). Harness name:
//! `aeskw-unwrap`: a wrapped key (AES-128/192/256 KEK, 2-8 semiblocks) is
//! unwrapped exactly; ONE flipped bit anywhere, another KEK, a truncation to
//! any length and a damaged copy are refused, and every refusal leaves `out`
//! all zero (no partial key material); wrong KEK sizes and short buffers get
//! their own errors.

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

const aeskw = @import("root.zig");

const Mark = Marker(enum { genuine, flipped_refused, wrong_kek_refused, truncated_refused, damaged_refused, zeroed_on_failure, bad_kek_len, small_buffer, kek128, kek192, kek256 });

fn allZero(b: []const u8) bool {
    for (b) |x| if (x != 0) return false;
    return true;
}

fn fuzzUnwrap(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [24]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    var kek_bytes: [32]u8 = undefined;
    expand(&knobs, &kek_bytes);
    const kek_len: usize = switch (knobs.ranged(0, 2)) {
        0 => 16,
        1 => 24,
        else => 32,
    };
    switch (kek_len) {
        16 => Mark.mark(.kek128),
        24 => Mark.mark(.kek192),
        else => Mark.mark(.kek256),
    }
    const kek = kek_bytes[0..kek_len];
    var pt_bytes: [64]u8 = undefined;
    expand(&knobs, &pt_bytes);
    const pt = pt_bytes[0 .. 8 * knobs.ranged(2, 8)];

    var ct_buf: [72]u8 = undefined;
    const ct = try aeskw.wrap(kek, pt, &ct_buf);
    var out: [64]u8 = undefined;
    const got = aeskw.unwrap(kek, ct, &out) catch return error.GenuineWrapRefused;
    if (!std.mem.eql(u8, got, pt)) return error.UnwrapDiffers;
    Mark.mark(.genuine);

    // One flipped bit anywhere: Unauthentic, and out zeroed.
    {
        var bad: [72]u8 = undefined;
        @memcpy(bad[0..ct.len], ct);
        const at = (@as(usize, knobs.byte()) << 8 | knobs.byte()) % ct.len;
        bad[at] ^= @as(u8, 1) << @intCast(knobs.ranged(0, 7));
        @memset(&out, 0xAA);
        if (aeskw.unwrap(kek, bad[0..ct.len], &out)) |_| return error.FlippedWrapAccepted else |e| {
            if (e != error.Unauthentic) return error.WrongRefusalKind;
            if (!allZero(out[0 .. ct.len - 8])) return error.PartialKeyLeaked;
            Mark.mark(.flipped_refused);
            Mark.mark(.zeroed_on_failure);
        }
    }
    // Another KEK of the same size.
    {
        var other = kek_bytes;
        other[knobs.ranged(0, @intCast(kek_len - 1))] ^= @as(u8, 1) << @intCast(knobs.ranged(0, 7));
        if (aeskw.unwrap(other[0..kek_len], ct, &out)) |_| return error.WrongKekAccepted else |e| {
            if (e != error.Unauthentic) return error.WrongRefusalKind;
            Mark.mark(.wrong_kek_refused);
        }
    }
    // Truncation to any length (including non-multiples of 8).
    {
        const cut = knobs.ranged(0, @intCast(ct.len - 1));
        if (aeskw.unwrap(kek, ct[0..cut], &out)) |_| return error.TruncatedWrapAccepted else |_| Mark.mark(.truncated_refused);
    }
    // Damage + arbitrary length: never accepted unless identical.
    {
        var buf: [80]u8 = undefined;
        const n = damage(src, &buf, ct);
        if (aeskw.unwrap(kek, buf[0..n], &out)) |_| {
            if (!std.mem.eql(u8, buf[0..n], ct)) return error.DamagedWrapAccepted;
        } else |_| Mark.mark(.damaged_refused);
    }
    // KEK sizes the module does not support, buffers that are too small.
    {
        if (aeskw.unwrap(kek_bytes[0..knobs.ranged(0, 15)], ct, &out)) |_| return error.BadKekAccepted else |e| {
            if (e != error.UnsupportedKeyLength) return error.WrongRefusalKind;
            Mark.mark(.bad_kek_len);
        }
        if (aeskw.wrap(kek_bytes[0..17], pt, &ct_buf)) |_| return error.BadKekAccepted else |_| {}
        if (aeskw.unwrap(kek, ct, out[0 .. ct.len - 9])) |_| return error.SmallBufferAccepted else |e| {
            if (e != error.BufferTooSmall) return error.WrongRefusalKind;
            Mark.mark(.small_buffer);
        }
        if (aeskw.wrap(kek, pt, ct_buf[0 .. pt.len + 7])) |_| return error.SmallBufferAccepted else |_| {}
    }
}

test "fuzz: aeskw unwrap, genuine accepted / damaged refused and zeroed" {
    try testing.fuzz({}, smithWrap(fuzzUnwrap), .{});
}
test "fuzz driver: AESKW_FUZZ (unwrap)" {
    try fuzz_driver.run(fuzzUnwrap, .{ .prefix = "AESKW_FUZZ", .name = "aeskw-unwrap" });
}
test "fuzz harness: unwrap, 300 seeds, reaches every outcome" {
    try Mark.reach(fuzzUnwrap, "aeskw-unwrap", 300);
}
