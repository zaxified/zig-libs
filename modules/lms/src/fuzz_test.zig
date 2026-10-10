// SPDX-License-Identifier: MIT

//! Shared plumbing for lms's deterministic fuzz driver (added 2026-10-09).
//!
//! The harness BODIES stay in `root.zig` beside their corpora; each is
//! generic over its source of choices, `fn(comptime S, *S, gpa)`, and
//! `testing.fuzz` hands it a `std.testing.Smith` directly (every harness
//! begins with one `slice`, so corpus seeds replay as before). This file
//! holds what they share with the driver: the reach counters with the N-seed
//! in-suite check, and the input draw.
//!
//! Driver: `LMS_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `lms-verify`, `lms-parse`, `lms-sign-verify`,
//! `hss-sign-verify`.

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

// ── the harnesses ───────────────────────────────────────────────────────────

const core = @import("core.zig");
const sign = @import("sign.zig");
const params = @import("params.zig");
const kat = @import("kat_vectors.zig");

const tc_pk = kat.bytes(kat.tc1_pub);
const tc_msg = kat.bytes(kat.tc1_msg);
const tc_sig = kat.bytes(kat.tc1_sig);
/// The LMS-only form of Test Case 1: the level-1 key and the final LMS signature.
const lms_pk = tc_sig[4 + 1292 ..][0..core.LmsPublicKey.encoded_len].*;
const lms_sig = tc_sig[4 + 1292 + core.LmsPublicKey.encoded_len ..].*;

const VerifyMark = Marker(enum { hss_genuine_accepted, lms_genuine_accepted, hss_damaged_refused, lms_damaged_refused, wild_refused });

/// `draw` of one octet string: the real one with 0-3 octets damaged (maybe
/// truncated) in the driver's structured half, `slice` under `Smith`.
fn drawOne(comptime S: type, src: *S, buf: []u8, real: []const u8, damaged: bool) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf);
    if (!damaged) {
        @memcpy(buf[0..real.len], real);
        return real.len;
    }
    return damage(src, buf, real);
}

/// RFC 8554 Test Case 1, each of key / message / signature either intact or
/// damaged: all intact verifies (HSS, and the LMS-only form), anything else does
/// not. Plus wild triples, which only have to be refused without a panic.
fn fuzzVerify(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var pk: [96]u8 = undefined;
    var msg: [256]u8 = undefined;
    var sig: [4096]u8 = undefined;
    if (S == fuzz_driver.Rng and src.index(4) == 0) {
        const pl = src.slice(&pk);
        const ml = src.slice(&msg);
        const sl = src.slice(&sig);
        const a = core.hssVerify(pk[0..pl], msg[0..ml], sig[0..sl]);
        const b = core.lmsVerify(pk[0..pl], msg[0..ml], sig[0..sl]);
        if (a or b) {
            // Wild bytes that verify would be a forgery -- unless they ARE a genuine triple.
            if (!(std.mem.eql(u8, pk[0..pl], &tc_pk) and std.mem.eql(u8, msg[0..ml], &tc_msg) and std.mem.eql(u8, sig[0..sl], &tc_sig)) and
                !(std.mem.eql(u8, pk[0..pl], &lms_pk) and std.mem.eql(u8, msg[0..ml], &tc_msg) and std.mem.eql(u8, sig[0..sl], &lms_sig)))
                return error.WildTripleVerified;
        }
        VerifyMark.mark(.wild_refused);
        return;
    }
    const lms_only = S == fuzz_driver.Rng and src.value(bool);
    const dmg_pk = S == fuzz_driver.Rng and src.index(3) == 0;
    const dmg_msg = S == fuzz_driver.Rng and src.index(3) == 0;
    const dmg_sig = S == fuzz_driver.Rng and src.index(3) == 0;
    const real_pk: []const u8 = if (lms_only) &lms_pk else &tc_pk;
    const real_sig: []const u8 = if (lms_only) &lms_sig else &tc_sig;
    const pl = drawOne(S, src, &pk, real_pk, dmg_pk);
    const ml = drawOne(S, src, &msg, &tc_msg, dmg_msg);
    const sl = drawOne(S, src, &sig, real_sig, dmg_sig);
    const pristine = std.mem.eql(u8, pk[0..pl], real_pk) and std.mem.eql(u8, msg[0..ml], &tc_msg) and std.mem.eql(u8, sig[0..sl], real_sig);
    const ok = if (lms_only) core.lmsVerify(pk[0..pl], msg[0..ml], sig[0..sl]) else core.hssVerify(pk[0..pl], msg[0..ml], sig[0..sl]);
    if (ok != pristine) {
        std.debug.print("lms_only={} pristine={} verified={}\n", .{ lms_only, pristine, ok });
        return if (pristine) error.GenuineTripleRefused else error.DamagedTripleVerified;
    }
    if (pristine) {
        if (lms_only) VerifyMark.mark(.lms_genuine_accepted) else VerifyMark.mark(.hss_genuine_accepted);
    } else {
        if (lms_only) VerifyMark.mark(.lms_damaged_refused) else VerifyMark.mark(.hss_damaged_refused);
    }
}

const ParseMark = Marker(enum { hss_accepted, hss_refused, lms_accepted, lms_refused });

/// Public-key parsers: what parses re-encodes to the same octets.
fn fuzzParse(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var buf: [96]u8 = undefined;
    var len: usize = undefined;
    if (S == fuzz_driver.Rng and src.value(bool)) {
        len = damage(src, &buf, if (src.value(bool)) &tc_pk else &lms_pk);
    } else len = src.slice(&buf);
    if (core.HssPublicKey.parse(buf[0..len])) |pk| {
        ParseMark.mark(.hss_accepted);
        if (!std.mem.eql(u8, &pk.toBytes(), buf[0..len])) return error.NonCanonicalHssKeyAccepted;
    } else |_| ParseMark.mark(.hss_refused);
    if (core.LmsPublicKey.parse(buf[0..len])) |pk| {
        ParseMark.mark(.lms_accepted);
        if (!std.mem.eql(u8, &pk.toBytes(), buf[0..len])) return error.NonCanonicalLmsKeyAccepted;
    } else |_| ParseMark.mark(.lms_refused);
}

// ── sign + verify with this module's own signer ─────────────────────────────

const ots_sets = [_]params.OtsParamSet{ .sha256_n32_w1, .sha256_n32_w2, .sha256_n32_w4, .sha256_n32_w8 };
var trees: [4]?sign.Tree = @splat(null);
const SignMark = Marker(enum { w1, w2, w4, w8, genuine_accepted, flipped_refused, truncated_refused, wrong_message_refused, wrong_root_refused });

/// A leaf-`q` signature from `Tree.sign` verifies under the tree's public key;
/// a flipped octet, a truncation, another message and another root do not.
fn fuzzLmsSignVerify(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    const which = src.index(4);
    if (trees[which] == null) {
        var seed: [params.n]u8 = @splat(@intCast(which + 1));
        trees[which] = @as(sign.Tree, undefined);
        try sign.Tree.init(&trees[which].?, std.heap.page_allocator, .sha256_m32_h5, ots_sets[which], @splat(@intCast(0x40 + which)), &seed);
    }
    const tree = &trees[which].?;
    switch (which) {
        0 => SignMark.mark(.w1),
        1 => SignMark.mark(.w2),
        2 => SignMark.mark(.w4),
        else => SignMark.mark(.w8),
    }
    var mbuf: [40]u8 = undefined;
    const ml = src.index(mbuf.len + 1);
    src.bytes(mbuf[0..ml]);
    const msg = mbuf[0..ml];
    const q = src.valueRangeAtMost(u32, 0, 31);
    const sig_len = core.lmsSignatureLength(.sha256_m32_h5, ots_sets[which]);
    var sig: [core.max_lms_signature_length]u8 = undefined;
    tree.sign(q, msg, sig[0..sig_len]);
    const pk = tree.publicKey().toBytes();
    if (!core.lmsVerify(&pk, msg, sig[0..sig_len])) return error.GenuineSignatureRefused;
    SignMark.mark(.genuine_accepted);

    sig[src.index(sig_len)] ^= src.valueRangeAtMost(u8, 1, 255);
    if (core.lmsVerify(&pk, msg, sig[0..sig_len])) return error.FlippedSignatureVerified;
    SignMark.mark(.flipped_refused);
    // (The flip stays: the truncation below is of a damaged copy, which must be refused all the more.)
    if (core.lmsVerify(&pk, msg, sig[0..src.index(sig_len)])) return error.TruncatedSignatureVerified;
    SignMark.mark(.truncated_refused);

    tree.sign(q, msg, sig[0..sig_len]);
    var m2: [41]u8 = undefined;
    @memcpy(m2[0..ml], msg);
    m2[ml] = src.value(u8);
    if (core.lmsVerify(&pk, m2[0 .. ml + 1], sig[0..sig_len])) return error.OtherMessageVerified;
    SignMark.mark(.wrong_message_refused);
    var pk2 = pk;
    pk2[24 + src.index(32)] ^= src.valueRangeAtMost(u8, 1, 255);
    if (core.lmsVerify(&pk2, msg, sig[0..sig_len])) return error.OtherRootVerified;
    SignMark.mark(.wrong_root_refused);
}

var hss_key: ?sign.SecretKey = null;
const HssMark = Marker(enum { genuine_accepted, flipped_refused, truncated_refused, wrong_message_refused });
const hss_levels = [_]params.Level{
    .{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w8 },
    .{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w8 },
};

/// The same for a 2-level HSS key (the key is stateful: it signs the next leaf
/// each run and is re-created when exhausted).
fn fuzzHssSignVerify(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    const seed: [params.n]u8 = @splat(0x5a);
    if (hss_key == null) {
        hss_key = @as(sign.SecretKey, undefined);
        try sign.SecretKey.init(&hss_key.?, std.heap.page_allocator, &hss_levels, &seed, @splat(0x77), null);
    }
    var mbuf: [40]u8 = undefined;
    const ml = src.index(mbuf.len + 1);
    src.bytes(mbuf[0..ml]);
    const msg = mbuf[0..ml];
    var sig: [4096]u8 = undefined;
    const got = hss_key.?.sign(msg, &sig) catch |e| switch (e) {
        error.KeyExhausted => {
            hss_key.?.deinit();
            hss_key = null;
            return;
        },
        else => return e,
    };
    const pk = hss_key.?.publicKey().toBytes();
    if (!core.hssVerify(&pk, msg, got)) return error.GenuineSignatureRefused;
    HssMark.mark(.genuine_accepted);

    var m2: [41]u8 = undefined;
    @memcpy(m2[0..ml], msg);
    m2[ml] = src.value(u8);
    if (core.hssVerify(&pk, m2[0 .. ml + 1], got)) return error.OtherMessageVerified;
    HssMark.mark(.wrong_message_refused);

    got[src.index(got.len)] ^= src.valueRangeAtMost(u8, 1, 255);
    if (core.hssVerify(&pk, msg, got)) return error.FlippedSignatureVerified;
    HssMark.mark(.flipped_refused);
    if (core.hssVerify(&pk, msg, got[0..src.index(got.len)])) return error.TruncatedSignatureVerified;
    HssMark.mark(.truncated_refused);
}

fn smithRun(comptime f: anytype) fn (void, *std.testing.Smith) anyerror!void {
    return struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            try f(std.testing.Smith, smith, testing.allocator);
        }
    }.run;
}

test "fuzz: lms verify, parse and sign/verify (Smith replay)" {
    try testing.fuzz({}, smithRun(fuzzVerify), .{});
    try testing.fuzz({}, smithRun(fuzzParse), .{});
    try testing.fuzz({}, smithRun(fuzzLmsSignVerify), .{});
}

test "fuzz driver: LMS_FUZZ (verify)" {
    try fuzz_driver.run(fuzzVerify, .{ .prefix = "LMS_FUZZ", .name = "lms-verify" });
}
test "fuzz driver: LMS_FUZZ (parse)" {
    try fuzz_driver.run(fuzzParse, .{ .prefix = "LMS_FUZZ", .name = "lms-parse" });
}
test "fuzz driver: LMS_FUZZ (LMS sign + verify)" {
    try fuzz_driver.run(fuzzLmsSignVerify, .{ .prefix = "LMS_FUZZ", .name = "lms-sign-verify", .scale = 100 });
}
test "fuzz driver: LMS_FUZZ (HSS sign + verify)" {
    try fuzz_driver.run(fuzzHssSignVerify, .{ .prefix = "LMS_FUZZ", .name = "hss-sign-verify", .scale = 200 });
}

test "fuzz harness: lms, reaches every outcome" {
    try VerifyMark.reach(fuzzVerify, "lms-verify", 400);
    try ParseMark.reach(fuzzParse, "lms-parse", 400);
    try SignMark.reach(fuzzLmsSignVerify, "lms-sign-verify", 40);
    try HssMark.reach(fuzzHssSignVerify, "hss-sign-verify", 20);
}
