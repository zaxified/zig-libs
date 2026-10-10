// SPDX-License-Identifier: MIT

//! Shared plumbing for bls12_381's deterministic fuzz driver (added 2026-10-10).
//!
//! The harness BODIES stay in `root.zig` beside their corpora; each is
//! generic over its source of choices, `fn(comptime S, *S, gpa)`, and
//! `testing.fuzz` hands it a `std.testing.Smith` directly (every harness
//! begins with one `slice`, so corpus seeds replay as before). This file
//! holds what they share with the driver: the reach counters with the N-seed
//! in-suite check, and the input draw.
//!
//! Driver: `BLS12_381_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `bls-codec`, `bls-sign-verify`.

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

const bls = @import("bls_sig.zig");
const g1 = @import("g1.zig");
const g2 = @import("g2.zig");
const Cursor = testkit.fuzz.Cursor;
const Rng = fuzz_driver.Rng;

const CodecMark = Marker(enum { sk_accepted, sk_refused, pk_accepted, pk_refused, sig_accepted, sig_refused, genuine_accepted, canonical });
const SignMark = Marker(enum { genuine_accepted, flipped_refused, wrong_message_refused, wrong_key_refused, aggregate_accepted, aggregate_flipped_refused, distinct_aggregate_accepted, swapped_messages_refused, pop_accepted, pop_wrong_key_refused });

/// True when `b` is `a` with only the compressed form's sort flag (bit 5 of
/// octet 0) flipped: that names the negated point, a valid point in its own right.
fn signFlipOf(a: []const u8, b: []const u8) bool {
    return a.len == b.len and (a[0] ^ b[0]) == 0x20 and std.mem.eql(u8, a[1..], b[1..]);
}

fn codecSmith(_: void, s: *testing.Smith) !void {
    return fuzzCodec(testing.Smith, s, testing.allocator);
}
test "fuzz: BLS decoders never crash, and what they accept re-encodes to the same octets" {
    try testing.fuzz({}, codecSmith, .{});
}
test "fuzz driver: BLS12_381_FUZZ (codec)" {
    try fuzz_driver.run(fuzzCodec, .{ .prefix = "BLS12_381_FUZZ", .name = "bls-codec", .scale = 10 });
}
test "fuzz harness: codec, 60 seeds, reaches every outcome" {
    try CodecMark.reach(fuzzCodec, "bls-codec", 60);
}

fn keyFromCursor(k: *Cursor) !bls.SecretKey {
    var ikm: [32]u8 = undefined;
    for (&ikm) |*x| x.* = k.byte();
    var sk: bls.SecretKey = undefined;
    try bls.keyGen(&sk, &ikm, "");
    return sk;
}

/// Public key (48 octets) and signature (96 octets) from a real key, damaged
/// 0-3 octets under the driver; the secret key's 32 octets raw. Accepting means
/// re-encoding to the very input (compressed form has one spelling), and a
/// damaged genuine encoding is refused or names another point.
fn fuzzCodec(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [160]u8 = undefined;
    const n: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n] };
    var sk_bytes: [32]u8 = undefined;
    var pk_bytes: [bls.PublicKey.encoded_bytes]u8 = undefined;
    var sig_bytes: [bls.Signature.encoded_bytes]u8 = undefined;
    var gen_pk: ?[bls.PublicKey.encoded_bytes]u8 = null;
    var gen_sig: ?[bls.Signature.encoded_bytes]u8 = null;
    if (S == Rng and k.byte() & 1 == 0) {
        var sk = try keyFromCursor(&k);
        defer sk.deinit();
        const pk = bls.skToPk(&sk);
        const sig = bls.sign(&sk, "fuzz");
        gen_pk = pk.toBytes();
        gen_sig = sig.toBytes();
        pk_bytes = gen_pk.?;
        sig_bytes = gen_sig.?;
        sk.toBytes(&sk_bytes);
        for (0..if (k.byte() & 1 == 0) k.ranged(1, 3) else 0) |_| pk_bytes[k.ranged(0, pk_bytes.len - 1)] = k.byte();
        for (0..if (k.byte() & 1 == 0) k.ranged(1, 3) else 0) |_| sig_bytes[k.ranged(0, sig_bytes.len - 1)] = k.byte();
        for (0..if (k.byte() & 1 == 0) k.ranged(1, 2) else 0) |_| sk_bytes[k.ranged(0, 31)] = k.byte();
    } else {
        src.bytes(&sk_bytes);
        src.bytes(&pk_bytes);
        src.bytes(&sig_bytes);
    }
    var sk: bls.SecretKey = undefined;
    if (bls.SecretKey.fromBytes(&sk, &sk_bytes)) {
        defer sk.deinit();
        var back: [32]u8 = undefined;
        sk.toBytes(&back);
        if (!std.mem.eql(u8, &back, &sk_bytes)) return error.SecretKeyNotCanonical;
        CodecMark.mark(.sk_accepted);
    } else |_| CodecMark.mark(.sk_refused);
    if (bls.PublicKey.fromBytes(pk_bytes)) |pk| {
        CodecMark.mark(.pk_accepted);
        if (!std.mem.eql(u8, &pk.toBytes(), &pk_bytes)) return error.PublicKeyNotCanonical;
        CodecMark.mark(.canonical);
        if (gen_pk) |g| {
            // A damaged encoding naming another subgroup point is a 2^-128 event;
            // the one legitimate exception is the sort flag flipped, which names -P.
            if (!std.mem.eql(u8, &g, &pk_bytes) and !signFlipOf(&g, &pk_bytes)) return error.DamagedPublicKeyAccepted;
            CodecMark.mark(.genuine_accepted);
        }
        _ = bls.keyValidate(pk);
    } else |_| {
        if (gen_pk) |g| if (std.mem.eql(u8, &g, &pk_bytes)) return error.GenuinePublicKeyRefused;
        CodecMark.mark(.pk_refused);
    }
    if (bls.Signature.fromBytes(sig_bytes)) |sig| {
        CodecMark.mark(.sig_accepted);
        if (!std.mem.eql(u8, &sig.toBytes(), &sig_bytes)) return error.SignatureNotCanonical;
        if (gen_sig) |g| if (!std.mem.eql(u8, &g, &sig_bytes) and !signFlipOf(&g, &sig_bytes)) return error.DamagedSignatureAccepted;
    } else |_| {
        if (gen_sig) |g| if (std.mem.eql(u8, &g, &sig_bytes)) return error.GenuineSignatureRefused;
        CodecMark.mark(.sig_refused);
    }
}

fn signSmith(_: void, s: *testing.Smith) !void {
    return fuzzSignVerify(testing.Smith, s, testing.allocator);
}
test "fuzz: genuine BLS signatures verify and every damaged one is refused" {
    try testing.fuzz({}, signSmith, .{});
}
test "fuzz driver: BLS12_381_FUZZ (sign-verify)" {
    try fuzz_driver.run(fuzzSignVerify, .{ .prefix = "BLS12_381_FUZZ", .name = "bls-sign-verify", .scale = 200 });
}
test "fuzz harness: sign-verify, 6 seeds, reaches every outcome" {
    try SignMark.reach(fuzzSignVerify, "bls-sign-verify", 6);
}

fn fuzzSignVerify(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [200]u8 = undefined;
    const n_raw: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n_raw] };
    const n = k.ranged(2, 3);
    var sks: [3]bls.SecretKey = undefined;
    var pks: [3]bls.PublicKey = undefined;
    var made: usize = 0;
    defer for (sks[0..made]) |*s| s.deinit();
    for (0..n) |i| {
        sks[i] = try keyFromCursor(&k);
        made += 1;
        pks[i] = bls.skToPk(&sks[i]);
        // Two draws giving the same key (an empty input) would hide the wrong-key check.
        if (i > 0 and std.mem.eql(u8, &pks[i].toBytes(), &pks[0].toBytes())) return;
    }
    var msg_buf: [33]u8 = undefined;
    for (&msg_buf) |*x| x.* = k.byte();
    const msg = msg_buf[0..k.ranged(0, 32)];
    const bit = @as(u8, 1) << @intCast(k.ranged(0, 7));

    const sig = bls.sign(&sks[0], msg);
    if (!bls.verify(pks[0], msg, sig)) return error.GenuineSignatureRefused;
    SignMark.mark(.genuine_accepted);

    var sb = sig.toBytes();
    sb[k.ranged(0, sb.len - 1)] ^= bit;
    if (bls.Signature.fromBytes(sb)) |bad| {
        if (bls.verify(pks[0], msg, bad)) return error.FlippedSignatureVerifies;
    } else |_| {}
    SignMark.mark(.flipped_refused);
    var other: [34]u8 = undefined;
    @memcpy(other[0..msg.len], msg);
    other[msg.len] = k.byte();
    if (bls.verify(pks[0], other[0 .. msg.len + 1], sig)) return error.WrongMessageVerifies;
    SignMark.mark(.wrong_message_refused);
    if (bls.verify(pks[1], msg, sig)) return error.WrongKeyVerifies;
    SignMark.mark(.wrong_key_refused);

    // Aggregate over one message (fast), then over distinct messages.
    var sigs: [3]bls.Signature = undefined;
    for (0..n) |i| sigs[i] = bls.sign(&sks[i], msg);
    const agg = try bls.aggregate(sigs[0..n]);
    if (!(try bls.fastAggregateVerify(pks[0..n], msg, agg))) return error.GenuineAggregateRefused;
    SignMark.mark(.aggregate_accepted);
    var ab = agg.toBytes();
    ab[k.ranged(0, ab.len - 1)] ^= bit;
    if (bls.Signature.fromBytes(ab)) |bad| {
        if (try bls.fastAggregateVerify(pks[0..n], msg, bad)) return error.FlippedAggregateVerifies;
    } else |_| {}
    SignMark.mark(.aggregate_flipped_refused);

    var m0: [34]u8 = undefined;
    var m1: [34]u8 = undefined;
    var m2: [34]u8 = undefined;
    const mbufs = [_]*[34]u8{ &m0, &m1, &m2 };
    var msgs: [3][]const u8 = undefined;
    for (0..n) |i| {
        @memcpy(mbufs[i][0..msg.len], msg);
        mbufs[i][msg.len] = @intCast(i);
        msgs[i] = mbufs[i][0 .. msg.len + 1];
        sigs[i] = bls.sign(&sks[i], msgs[i]);
    }
    const dagg = try bls.aggregate(sigs[0..n]);
    if (!(try bls.aggregateVerify(pks[0..n], msgs[0..n], dagg))) return error.GenuineDistinctAggregateRefused;
    SignMark.mark(.distinct_aggregate_accepted);
    std.mem.swap([]const u8, &msgs[0], &msgs[1]);
    if (try bls.aggregateVerify(pks[0..n], msgs[0..n], dagg)) return error.SwappedMessagesVerify;
    SignMark.mark(.swapped_messages_refused);

    // Proof of possession: own key accepted, another key's refused.
    const pop = bls.popProve(&sks[0]);
    if (!bls.popVerify(pks[0], pop)) return error.GenuinePopRefused;
    SignMark.mark(.pop_accepted);
    if (bls.popVerify(pks[1], pop)) return error.PopForWrongKeyVerifies;
    SignMark.mark(.pop_wrong_key_refused);
}
