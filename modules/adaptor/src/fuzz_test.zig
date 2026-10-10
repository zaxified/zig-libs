// SPDX-License-Identifier: MIT

//! Shared plumbing for adaptor's deterministic fuzz driver (added 2026-10-10).
//!
//! The harness BODIES stay in `root.zig` beside their corpora; each is
//! generic over its source of choices, `fn(comptime S, *S, gpa)`, and
//! `testing.fuzz` hands it a `std.testing.Smith` directly (every harness
//! begins with one `slice`, so corpus seeds replay as before). This file
//! holds what they share with the driver: the reach counters with the N-seed
//! in-suite check, and the input draw.
//!
//! Driver: `ADAPTOR_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `adaptor-preverify`, `adaptor-flow`.

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

const adaptor = @import("root.zig");
const bip340 = @import("bip340");
const k256 = @import("k256");
const v = @import("kat_vectors.zig");
const Cursor = testkit.fuzz.Cursor;
const Rng = fuzz_driver.Rng;

const PreVerifyMark = Marker(enum { pristine_accepted, parsed, refused, unparsed });
const FlowMark = Marker(enum { presig_accepted, adapted_verifies, extracted, presig_flipped_refused, sig_flipped_refused, wrong_adaptor_refused });

fn hexN(comptime n: usize, hex_str: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

fn preVerifySmith(_: void, s: *testing.Smith) !void {
    return fuzzPreVerify(testing.Smith, s, testing.allocator);
}
test "fuzz: preVerify never panics, and only the pristine pre-signature verifies" {
    try testing.fuzz({}, preVerifySmith, .{});
}
test "fuzz driver: ADAPTOR_FUZZ (preverify)" {
    try fuzz_driver.run(fuzzPreVerify, .{ .prefix = "ADAPTOR_FUZZ", .name = "adaptor-preverify" });
}
test "fuzz harness: preverify, 300 seeds, reaches every outcome" {
    try PreVerifyMark.reach(fuzzPreVerify, "adaptor-preverify", 300);
}

/// Vector 0's pre-signature with octets damaged (the corpus script format
/// under `Smith`, a fresh draw under the driver): whatever differs from the
/// pristine 65 octets must not verify.
fn fuzzPreVerify(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    const vec0 = v.vectors[0];
    const px = try bip340.XOnlyPublicKey.fromBytes(hexN(32, vec0.px));
    const t_point = try adaptor.AdaptorPoint.fromBytes(hexN(33, vec0.adaptor_point));
    var pristine: [65]u8 = undefined;
    pristine[0..32].* = hexN(32, vec0.r);
    pristine[32..64].* = hexN(32, vec0.s_prime);
    pristine[64] = @intFromBool(vec0.needs_negation);
    var bytes = pristine;
    var script: [32]u8 = undefined;
    const n: usize = src.slice(&script);
    var k: Cursor = .{ .bytes = script[0..n] };
    if (S == Rng) {
        for (0..k.ranged(0, 3)) |_| bytes[k.ranged(0, 64)] = k.byte();
        // s' >= n needs the leading octets forced to 0xFF.
        if (k.ranged(0, 15) == 0) @memset(bytes[32..48], 0xff);
    } else if (n > 0) {
        for (0..script[0] % 7) |i| {
            const at = 1 + i * 2;
            if (at + 1 >= n) break;
            bytes[script[at] % 65] = script[at + 1];
        }
    }
    const presig = adaptor.PreSignature.fromBytes(bytes) catch {
        PreVerifyMark.mark(.unparsed);
        return;
    };
    PreVerifyMark.mark(.parsed);
    if (adaptor.preVerify(px, vec0.msg, t_point, presig)) {
        if (!std.mem.eql(u8, &bytes, &pristine)) return error.DamagedPreSignatureVerifies;
        PreVerifyMark.mark(.pristine_accepted);
    } else PreVerifyMark.mark(.refused);
}

fn flowSmith(_: void, s: *testing.Smith) !void {
    return fuzzFlow(testing.Smith, s, testing.allocator);
}
test "fuzz: pre-sign, adapt and extract round-trip, and every damaged part is refused" {
    try testing.fuzz({}, flowSmith, .{});
}
test "fuzz driver: ADAPTOR_FUZZ (flow)" {
    try fuzz_driver.run(fuzzFlow, .{ .prefix = "ADAPTOR_FUZZ", .name = "adaptor-flow", .scale = 4 });
}
test "fuzz harness: flow, 60 seeds, reaches every outcome" {
    try FlowMark.reach(fuzzFlow, "adaptor-flow", 60);
}

fn fuzzFlow(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [160]u8 = undefined;
    const n_raw: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n_raw] };
    var sb: [32]u8 = undefined;
    var tb: [32]u8 = undefined;
    for (&sb) |*x| x.* = k.byte();
    for (&tb) |*x| x.* = k.byte();
    sb[0] &= 0x7f;
    tb[0] &= 0x7f;
    sb[31] |= 1;
    tb[31] |= 1;
    var aux: [32]u8 = undefined;
    for (&aux) |*x| x.* = k.byte();
    var msg_buf: [32]u8 = undefined;
    for (&msg_buf) |*x| x.* = k.byte();
    const msg = msg_buf[0..k.ranged(0, 32)];

    const sk = bip340.SecretKey.fromBytes(sb) catch return;
    const px = (try bip340.PublicKey.fromSecretKey(&sk)).xonly;
    const t_point = try adaptor.AdaptorPoint.fromBytes((try k256.Secp256k1.combMulBase(tb, .big)).toCompressedSec1());

    const presig = try adaptor.preSign(&sk, msg, aux, t_point, testing.io);
    if (!adaptor.preVerify(px, msg, t_point, presig)) return error.GenuinePreSignatureRefused;
    FlowMark.mark(.presig_accepted);

    const full_bytes = try adaptor.adapt(presig, &tb);
    const full = try bip340.Signature.fromBytes(full_bytes);
    if (!bip340.verify(px, msg, full)) return error.AdaptedSignatureDoesNotVerify;
    FlowMark.mark(.adapted_verifies);
    const t_back = try adaptor.extract(presig, full, t_point);
    if (!std.mem.eql(u8, &t_back, &tb)) return error.ExtractedSecretDiffers;
    FlowMark.mark(.extracted);

    // A damaged pre-signature does not verify.
    var pb = presig.toBytes();
    pb[k.ranged(0, 63)] ^= @as(u8, 1) << @intCast(k.ranged(0, 7));
    if (adaptor.PreSignature.fromBytes(pb)) |bad| {
        if (adaptor.preVerify(px, msg, t_point, bad)) return error.FlippedPreSignatureVerifies;
    } else |_| {}
    FlowMark.mark(.presig_flipped_refused);

    // A damaged full signature neither verifies nor yields t.
    var fb = full_bytes;
    fb[k.ranged(32, 63)] ^= @as(u8, 1) << @intCast(k.ranged(0, 7));
    if (bip340.Signature.fromBytes(fb)) |bad| {
        if (bip340.verify(px, msg, bad)) return error.FlippedSignatureVerifies;
        if (adaptor.extract(presig, bad, t_point)) |t2| {
            if (std.mem.eql(u8, &t2, &tb)) return error.FlippedSignatureYieldsSecret;
        } else |_| {}
    } else |_| {}
    FlowMark.mark(.sig_flipped_refused);

    // Another adaptor point does not accept the pre-signature.
    var other = tb;
    other[k.ranged(1, 31)] ^= @as(u8, 1) << @intCast(k.ranged(0, 7));
    const other_t = adaptor.AdaptorPoint.fromBytes((try k256.Secp256k1.combMulBase(other, .big)).toCompressedSec1()) catch return;
    if (adaptor.preVerify(px, msg, other_t, presig)) return error.OtherAdaptorPointAccepted;
    FlowMark.mark(.wrong_adaptor_refused);
}
