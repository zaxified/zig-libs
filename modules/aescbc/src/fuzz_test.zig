// SPDX-License-Identifier: MIT

//! Shared plumbing for aescbc's deterministic fuzz driver (added 2026-10-10).
//!
//! The harness BODIES stay in `root.zig` beside their corpora; each is
//! generic over its source of choices, `fn(comptime S, *S, gpa)`, and
//! `testing.fuzz` hands it a `std.testing.Smith` directly (every harness
//! begins with one `slice`, so corpus seeds replay as before). This file
//! holds what they share with the driver: the reach counters with the N-seed
//! in-suite check, and the input draw.
//!
//! Driver: `AESCBC_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `aescbc-cbc`, `aescbc-padding`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;

/// One harness input into `buf`; returns its length. Under `Smith` (`--fuzz`,
/// `_INPUT` replay) it is exactly `src.slice`. Under the driver's `Rng` half
/// the draws are instead a corpus entry (frames carry a little-endian u32
/// length header; the octets after the frame, if any, are dropped) with 0-3
/// octets damaged and maybe truncated: random bytes alone almost never get
/// past the first grammar check of these parsers.
pub fn drawInput(comptime S: type, src: *S, buf: []u8, corpus: []const []const u8) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf);
    if (corpus.len == 0 or !src.value(bool)) return src.slice(buf);
    const entry = corpus[src.index(corpus.len)];
    const flen = std.mem.readInt(u32, entry[0..4], .little);
    const frame = entry[4..][0..@min(flen, entry.len - 4)];
    return damage(src, buf, frame);
}

/// `frame` into `buf` with 0-3 octets damaged and maybe truncated (the
/// driver's `Rng` only; the damage is drawn from `src`).
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

/// Reach counters for one harness file's labels. `mark` also feeds the
/// driver's `REACH` report; `reach` runs `seeds` seeds in the ordinary test
/// binary and fails with `error.HarnessDoesNotReach` if a label never fired.
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

// ── harnesses ───────────────────────────────────────────────────────────

const aescbc = @import("root.zig");
const Cursor = testkit.fuzz.Cursor;
const Rng = fuzz_driver.Rng;
const Aes128 = std.crypto.core.aes.Aes128;
const Aes256 = std.crypto.core.aes.Aes256;

const CbcMark = Marker(enum { aes128, aes256, roundtrip, malleability, misaligned_refused, short_out_refused });
const PadMark = Marker(enum { genuine_unpadded, valid, invalid, xmlenc_valid, xmlenc_invalid });

fn cbcSmith(_: void, s: *testing.Smith) !void {
    return fuzzCbc(testing.Smith, s, testing.allocator);
}
test "fuzz: CBC round-trips, and a flipped ciphertext bit has the exact CBC effect" {
    try testing.fuzz({}, cbcSmith, .{});
}
test "fuzz driver: AESCBC_FUZZ (cbc)" {
    try fuzz_driver.run(fuzzCbc, .{ .prefix = "AESCBC_FUZZ", .name = "aescbc-cbc" });
}
test "fuzz harness: cbc, 300 seeds, reaches every outcome" {
    try CbcMark.reach(fuzzCbc, "aescbc-cbc", 300);
}

fn cbcCase(comptime Aes: type, k: *Cursor) !void {
    var key: [Aes.key_bits / 8]u8 = undefined;
    for (&key) |*x| x.* = k.byte();
    var iv: [16]u8 = undefined;
    for (&iv) |*x| x.* = k.byte();
    var pt: [96]u8 = undefined;
    for (&pt) |*x| x.* = k.byte();
    const blocks = k.ranged(0, 6);
    const len = blocks * 16;
    var ct: [96]u8 = undefined;
    const n = try aescbc.encrypt(Aes, &key, iv, pt[0..len], &ct);
    if (n != len) return error.WrongLength;
    var back: [96]u8 = undefined;
    _ = try aescbc.decrypt(Aes, &key, iv, ct[0..len], &back);
    if (!std.mem.eql(u8, back[0..len], pt[0..len])) return error.RoundTripAltered;
    CbcMark.mark(.roundtrip);
    if (blocks > 0) {
        // Flip bit `b` of ciphertext octet `at` in block `bi`: block `bi` of the
        // plaintext changes (to garbage), block `bi+1` changes by exactly that
        // bit at that position, every other block is untouched.
        const bi = k.ranged(0, @intCast(blocks - 1));
        const pos = k.ranged(0, 15);
        const bit = @as(u8, 1) << @intCast(k.ranged(0, 7));
        var bad = ct;
        bad[bi * 16 + pos] ^= bit;
        var out: [96]u8 = undefined;
        _ = try aescbc.decrypt(Aes, &key, iv, bad[0..len], &out);
        for (0..blocks) |b| {
            const got = out[b * 16 ..][0..16];
            const want = pt[b * 16 ..][0..16];
            if (b == bi) {
                if (std.mem.eql(u8, got, want)) return error.FlippedBlockUnchanged;
            } else if (b == bi + 1) {
                var expect: [16]u8 = want.*;
                expect[pos] ^= bit;
                if (!std.mem.eql(u8, got, &expect)) return error.NextBlockNotXorOfFlip;
            } else if (!std.mem.eql(u8, got, want)) return error.OtherBlockChanged;
        }
        CbcMark.mark(.malleability);
        var o2: [96]u8 = undefined;
        if (aescbc.decrypt(Aes, &key, iv, ct[0 .. len - 1], &o2)) |_| return error.MisalignedAccepted else |e| if (e != error.NotBlockAligned) return error.WrongError;
        if (aescbc.encrypt(Aes, &key, iv, pt[0 .. len - 1], &o2)) |_| return error.MisalignedAccepted else |e| if (e != error.NotBlockAligned) return error.WrongError;
        CbcMark.mark(.misaligned_refused);
        if (aescbc.decrypt(Aes, &key, iv, ct[0..len], o2[0 .. len - 1])) |_| return error.ShortOutAccepted else |e| if (e != error.BufferTooSmall) return error.WrongError;
        CbcMark.mark(.short_out_refused);
    }
}

fn fuzzCbc(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [256]u8 = undefined;
    const n: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n] };
    if (k.byte() & 1 == 0) {
        CbcMark.mark(.aes128);
        try cbcCase(Aes128, &k);
    } else {
        CbcMark.mark(.aes256);
        try cbcCase(Aes256, &k);
    }
}

fn padSmith(_: void, s: *testing.Smith) !void {
    return fuzzPad(testing.Smith, s, testing.allocator);
}
test "fuzz: padding agrees with a plain reference" {
    try testing.fuzz({}, padSmith, .{});
}
test "fuzz driver: AESCBC_FUZZ (padding)" {
    try fuzz_driver.run(fuzzPad, .{ .prefix = "AESCBC_FUZZ", .name = "aescbc-padding" });
}
test "fuzz harness: padding, 300 seeds, reaches every outcome" {
    try PadMark.reach(fuzzPad, "aescbc-padding", 300);
}

/// The straightforward, branching reference the constant-time `unpadPkcs7`
/// must agree with on every buffer.
fn refUnpad(buf: []const u8) ?usize {
    if (buf.len == 0 or buf.len % 16 != 0) return null;
    const nn = buf[buf.len - 1];
    if (nn == 0 or nn > 16) return null;
    for (buf[buf.len - nn ..]) |b| if (b != nn) return null;
    return buf.len - nn;
}

fn fuzzPad(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var buf: [80]u8 = undefined;
    var len: usize = undefined;
    var genuine: ?[]const u8 = null;
    var msg_store: [64]u8 = undefined;
    if (S == Rng) {
        var raw: [96]u8 = undefined;
        const n: usize = src.slice(&raw);
        var k: Cursor = .{ .bytes = raw[0..n] };
        for (&msg_store) |*x| x.* = k.byte();
        const msg = msg_store[0..k.ranged(0, 63)];
        len = try aescbc.padPkcs7(msg, &buf);
        if (len != aescbc.paddedLenPkcs7(msg.len)) return error.PaddedLenWrong;
        const hits = if (k.byte() & 1 == 0) k.ranged(1, 3) else 0;
        for (0..hits) |_| buf[len - 1 - k.ranged(0, 17) % len] = k.byte();
        if (k.ranged(0, 7) == 0) len -= 1; // unaligned
        if (hits == 0 and len % 16 == 0) genuine = msg;
    } else {
        len = src.slice(&buf);
    }
    const got = aescbc.unpadPkcs7(buf[0..len]);
    const want = refUnpad(buf[0..len]);
    if (want) |w| {
        const g = got catch return error.ValidPaddingRefused;
        if (g != w) return error.UnpaddedLengthDiffers;
        PadMark.mark(.valid);
        if (genuine) |m| {
            if (!std.mem.eql(u8, buf[0..g], m)) return error.GenuineMessageAltered;
            PadMark.mark(.genuine_unpadded);
        }
    } else {
        if (got) |_| return error.InvalidPaddingAccepted else |_| {}
        if (genuine != null) return error.GenuinePaddingRefused;
        PadMark.mark(.invalid);
    }
    // XML-Enc: only the final length octet matters.
    const xml = aescbc.unpadXmlEnc(buf[0..len]);
    const xml_want: ?usize = if (len == 0 or len % 16 != 0 or buf[len - 1] == 0 or buf[len - 1] > 16) null else len - buf[len - 1];
    if (xml_want) |w| {
        if ((xml catch return error.XmlEncValidRefused) != w) return error.XmlEncLengthDiffers;
        PadMark.mark(.xmlenc_valid);
    } else {
        if (xml) |_| return error.XmlEncInvalidAccepted else |_| {}
        PadMark.mark(.xmlenc_invalid);
    }
}
