// SPDX-License-Identifier: MIT

//! Shared plumbing for musig2's deterministic fuzz driver (added 2026-10-10).
//!
//! The harness BODIES stay in `root.zig` beside their corpora; each is
//! generic over its source of choices, `fn(comptime S, *S, gpa)`, and
//! `testing.fuzz` hands it a `std.testing.Smith` directly (every harness
//! begins with one `slice`, so corpus seeds replay as before). This file
//! holds what they share with the driver: the reach counters with the N-seed
//! in-suite check, and the input draw.
//!
//! Driver: `MUSIG2_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `musig2-psig`, `musig2-session`.

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

const musig2 = @import("root.zig");
const bip340 = @import("bip340");
const k256 = @import("k256");
const v = @import("kat_vectors.zig");
const Cursor = testkit.fuzz.Cursor;

const PsigMark = Marker(enum { unchanged_accepted, parsed, refused, out_of_range });
const SessionMark = Marker(enum { genuine_accepted, partial_flipped_refused, aggregate_verifies, aggregate_flipped_refused, wrong_message_refused, tweaked });

fn hexN(comptime n: usize, hex_str: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

fn psigSmith(_: void, s: *testing.Smith) !void {
    return fuzzPsig(testing.Smith, s, testing.allocator);
}
test "fuzz: partialSigVerify never panics, and only the published signature verifies" {
    try testing.fuzz({}, psigSmith, .{});
}
test "fuzz driver: MUSIG2_FUZZ (psig)" {
    try fuzz_driver.run(fuzzPsig, .{ .prefix = "MUSIG2_FUZZ", .name = "musig2-psig", .scale = 4 });
}
test "fuzz harness: psig, 300 seeds, reaches every outcome" {
    try PsigMark.reach(fuzzPsig, "musig2-psig", 300);
}

/// The published valid case with its partial signature damaged (the driver
/// flips 0-3 octets; the old script format is still read under `Smith`). A
/// signature that differs from the published one must be refused.
fn fuzzPsig(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var script: [128]u8 = undefined;
    const script_len: usize = src.slice(&script);
    var cur: Cursor = .{ .bytes = script[0..script_len] };
    const case = v.sign_verify.valid_test_cases[0];
    var pk_buf: [8]musig2.PlainPublicKey = undefined;
    for (case.key_indices, 0..) |idx, i| pk_buf[i] = try musig2.PlainPublicKey.fromBytes(hexN(33, v.sign_verify.pubkeys[idx]));
    const pks = pk_buf[0..case.key_indices.len];
    var pn_buf: [8]musig2.PubNonce = undefined;
    for (case.nonce_indices, 0..) |idx, i| pn_buf[i] = try musig2.PubNonce.fromBytes(hexN(66, v.sign_verify.pnonces[idx]));
    const pns = pn_buf[0..case.nonce_indices.len];
    const msg = try gpa.alloc(u8, v.sign_verify.msgs[case.msg_index].len / 2);
    defer gpa.free(msg);
    _ = try std.fmt.hexToBytes(msg, v.sign_verify.msgs[case.msg_index]);

    const published = hexN(32, case.expected);
    var bytes = published;
    // Under the driver the flip count is 0..32 like the corpus script, but
    // biased: half the draws flip one octet only (near-misses).
    const n_flips = if (S == fuzz_driver.Rng and cur.byte() & 1 == 0) cur.ranged(0, 1) else cur.ranged(0, 32);
    for (0..n_flips) |_| bytes[cur.ranged(0, 31)] = cur.byte();

    // s >= n needs fifteen leading 0xFF octets: no random edit gets there.
    if (S == fuzz_driver.Rng and cur.ranged(0, 15) == 0) @memset(bytes[0..16], 0xff);
    const psig = musig2.PartialSignature.fromBytes(bytes) catch {
        PsigMark.mark(.out_of_range);
        return;
    };
    PsigMark.mark(.parsed);
    if (musig2.partialSigVerify(psig, pns, pks, &.{}, msg, case.signer_index)) |_| {
        if (!std.mem.eql(u8, &bytes, &published)) return error.DamagedPartialSignatureVerifies;
        PsigMark.mark(.unchanged_accepted);
    } else |_| PsigMark.mark(.refused);
}

fn sessionSmith(_: void, s: *testing.Smith) !void {
    return fuzzSession(testing.Smith, s, testing.allocator);
}
test "fuzz: a genuine MuSig2 session verifies and every damaged part is refused" {
    try testing.fuzz({}, sessionSmith, .{});
}
test "fuzz driver: MUSIG2_FUZZ (session)" {
    try fuzz_driver.run(fuzzSession, .{ .prefix = "MUSIG2_FUZZ", .name = "musig2-session", .scale = 20 });
}
test "fuzz harness: session, 40 seeds, reaches every outcome" {
    try SessionMark.reach(fuzzSession, "musig2-session", 40);
}

fn fuzzSession(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [200]u8 = undefined;
    const n_raw: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n_raw] };
    const io = testing.io;
    const n = k.ranged(2, 3);
    var sks: [3]bip340.SecretKey = undefined;
    var pks: [3]musig2.PlainPublicKey = undefined;
    for (0..n) |i| {
        var b: [32]u8 = undefined;
        for (&b) |*x| x.* = k.byte();
        b[0] &= 0x7f;
        b[31] |= 1; // never zero
        sks[i] = bip340.SecretKey.fromBytes(b) catch return;
        pks[i] = .{ .bytes = (try k256.Secp256k1.combMulBase(b, .big)).toCompressedSec1() };
    }
    var msg_buf: [32]u8 = undefined;
    for (&msg_buf) |*x| x.* = k.byte();
    const msg = msg_buf[0..k.ranged(0, 32)];
    var tweak_buf: [1]musig2.Tweak = undefined;
    var tweaks: []const musig2.Tweak = &.{};
    if (k.byte() & 1 == 0) {
        tweak_buf[0].is_xonly = k.byte() & 1 == 0;
        for (&tweak_buf[0].tweak) |*x| x.* = k.byte();
        tweak_buf[0].tweak[0] &= 0x7f;
        tweaks = &tweak_buf;
        SessionMark.mark(.tweaked);
    }

    var ngs: [3]musig2.NonceGenResult = undefined;
    var pns: [3]musig2.PubNonce = undefined;
    for (0..n) |i| {
        var rand: [32]u8 = undefined;
        for (&rand) |*x| x.* = k.byte();
        const sk_bytes = sks[i].bytes;
        try musig2.nonceGen(&ngs[i], &sk_bytes, pks[i].bytes, null, msg, null, &rand, io);
        pns[i] = ngs[i].pubnonce;
    }
    const aggnonce = try musig2.nonceAgg(pns[0..n]);
    const ctx = musig2.SessionContext{ .aggnonce = aggnonce, .pubkeys = pks[0..n], .tweaks = tweaks, .msg = msg };
    var psigs: [3]musig2.PartialSignature = undefined;
    for (0..n) |i| {
        psigs[i] = musig2.sign(&ngs[i].secnonce, &sks[i], ctx) catch |e| switch (e) {
            // A tweak that lands on infinity or out of range is a session-level refusal (2^-128).
            error.TweakOutOfRange, error.TweakedKeyIsInfinite => return,
            else => return e,
        };
        musig2.partialSigVerify(psigs[i], pns[0..n], pks[0..n], tweaks, msg, i) catch return error.GenuinePartialRefused;
    }
    SessionMark.mark(.genuine_accepted);

    // One flipped bit in one partial signature is refused (or out of range).
    const who = k.ranged(0, @intCast(n - 1));
    var bad = psigs[who].bytes;
    bad[k.ranged(0, 31)] ^= @as(u8, 1) << @intCast(k.ranged(0, 7));
    if (musig2.PartialSignature.fromBytes(bad)) |bp| {
        if (musig2.partialSigVerify(bp, pns[0..n], pks[0..n], tweaks, msg, who)) |_| return error.FlippedPartialAccepted else |_| {}
    } else |_| {}
    SessionMark.mark(.partial_flipped_refused);

    // The aggregate is a BIP340 signature under the (tweaked) aggregate key.
    const sig_bytes = try musig2.partialSigAgg(psigs[0..n], ctx);
    var kctx = try musig2.keyAgg(pks[0..n]);
    for (tweaks) |t| kctx = try kctx.applyTweak(t.tweak, t.is_xonly);
    const agg_pk = bip340.XOnlyPublicKey{ .x = kctx.getXonlyPubkey() };
    const sig = try bip340.Signature.fromBytes(sig_bytes);
    if (!bip340.verify(agg_pk, msg, sig)) return error.AggregateDoesNotVerify;
    SessionMark.mark(.aggregate_verifies);

    var bad_sig = sig_bytes;
    bad_sig[k.ranged(0, 63)] ^= @as(u8, 1) << @intCast(k.ranged(0, 7));
    if (bip340.Signature.fromBytes(bad_sig)) |bs| {
        if (bip340.verify(agg_pk, msg, bs)) return error.FlippedAggregateVerifies;
    } else |_| {}
    SessionMark.mark(.aggregate_flipped_refused);
    var other_msg: [33]u8 = undefined;
    @memcpy(other_msg[0..msg.len], msg);
    other_msg[msg.len] = k.byte();
    if (bip340.verify(agg_pk, other_msg[0 .. msg.len + 1], sig)) return error.WrongMessageVerifies;
    SessionMark.mark(.wrong_message_refused);
}
