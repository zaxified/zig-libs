// SPDX-License-Identifier: MIT

//! Shared plumbing for k256's deterministic fuzz driver (added 2026-10-10).
//!
//! The harness BODIES stay in `root.zig` beside their corpora; each is
//! generic over its source of choices, `fn(comptime S, *S, gpa)`, and
//! `testing.fuzz` hands it a `std.testing.Smith` directly (every harness
//! begins with one `slice`, so corpus seeds replay as before). This file
//! holds what they share with the driver: the reach counters with the N-seed
//! in-suite check, and the input draw.
//!
//! Driver: `K256_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `k256-sec1`, `k256-fe`, `k256-mul`, `k256-sign`.

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

const k256 = @import("root.zig");
const Secp256k1 = k256.Secp256k1;
const Fe = k256.Fe;
const sign = k256.sign;
const ecdsa_recover = k256.ecdsa_recover;
const Cursor = testkit.fuzz.Cursor;
const Rng = fuzz_driver.Rng;

const Sec1Mark = Marker(enum { genuine_compressed, genuine_uncompressed, accepted, refused, canonical, identity, damaged_other_point });
const FeMark = Marker(enum { accepted, refused, canonical, boundary });
const MulMark = Marker(enum { implementations_agree, base_matches, distributive });
const SignMark = Marker(enum { ecdsa_accepted, recovered, bip340_accepted, flipped_refused, wrong_key_refused, wrong_message_refused });

fn randScalar(k: *Cursor) [32]u8 {
    var b: [32]u8 = undefined;
    for (&b) |*x| x.* = k.byte();
    b[0] &= 0x7f; // below the group order
    b[31] |= 1; // never zero
    return b;
}

fn sec1Smith(_: void, s: *testing.Smith) !void {
    return fuzzSec1(testing.Smith, s, testing.allocator);
}
test "fuzz: fromSec1 never panics, and what it accepts re-encodes to the same octets" {
    try testing.fuzz({}, sec1Smith, .{});
}
test "fuzz driver: K256_FUZZ (sec1)" {
    try fuzz_driver.run(fuzzSec1, .{ .prefix = "K256_FUZZ", .name = "k256-sec1" });
}
test "fuzz harness: sec1, 400 seeds, reaches every outcome" {
    try Sec1Mark.reach(fuzzSec1, "k256-sec1", 400);
}

fn fuzzSec1(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var buf: [65]u8 = undefined;
    var len: usize = undefined;
    var genuine: ?Secp256k1 = null;
    var damaged = false;
    if (S == Rng) {
        var raw: [64]u8 = undefined;
        const n: usize = src.slice(&raw);
        var k: Cursor = .{ .bytes = raw[0..n] };
        const mode = k.ranged(0, 3);
        if (mode < 3) {
            const p = try Secp256k1.combMulBase(randScalar(&k), .big);
            genuine = p;
            var orig: [65]u8 = undefined;
            if (mode == 0) {
                orig[0..33].* = p.toCompressedSec1();
                len = 33;
                SecMarkGenuine(true);
            } else {
                orig = p.toUncompressedSec1();
                len = 65;
                SecMarkGenuine(false);
            }
            buf = orig;
            const hits = if (k.byte() & 1 == 0) k.ranged(1, 3) else 0;
            for (0..hits) |_| buf[k.ranged(0, @intCast(len - 1))] = k.byte();
            if (k.ranged(0, 7) == 0) len = k.ranged(0, @intCast(len));
            damaged = len != (if (mode == 0) @as(usize, 33) else 65) or !std.mem.eql(u8, buf[0..len], orig[0..len]);
        } else {
            len = src.slice(&buf);
            // The one-octet identity encoding is 1 in 2^64 draws away: steer some there.
            if (k.byte() & 3 == 0) {
                buf[0] = 0;
                len = k.ranged(0, 2);
            }
        }
    } else {
        len = src.slice(&buf);
    }
    const p = Secp256k1.fromSec1(buf[0..len]) catch {
        if (genuine != null and !damaged) return error.GenuinePointRefused;
        Sec1Mark.mark(.refused);
        return;
    };
    Sec1Mark.mark(.accepted);
    if (len == 1) {
        Sec1Mark.mark(.identity);
        return;
    }
    // Canonical: the accepted point re-encodes to the very octets it came from.
    const same = switch (len) {
        33 => std.mem.eql(u8, &p.toCompressedSec1(), buf[0..33]),
        65 => std.mem.eql(u8, &p.toUncompressedSec1(), buf[0..65]),
        else => false,
    };
    if (!same) return error.AcceptedPointNotCanonical;
    Sec1Mark.mark(.canonical);
    if (damaged) {
        if (p.equivalent(genuine.?)) return error.DamagedEncodingIsSamePoint;
        Sec1Mark.mark(.damaged_other_point);
    }
}

fn SecMarkGenuine(compressed: bool) void {
    if (compressed) Sec1Mark.mark(.genuine_compressed) else Sec1Mark.mark(.genuine_uncompressed);
}

fn feSmith(_: void, s: *testing.Smith) !void {
    return fuzzFe(testing.Smith, s, testing.allocator);
}
test "fuzz: Fe.fromBytes accepts exactly the canonical encodings" {
    try testing.fuzz({}, feSmith, .{});
}
test "fuzz driver: K256_FUZZ (fe)" {
    try fuzz_driver.run(fuzzFe, .{ .prefix = "K256_FUZZ", .name = "k256-fe" });
}
test "fuzz harness: fe, 300 seeds, reaches every outcome" {
    try FeMark.reach(fuzzFe, "k256-fe", 300);
}

const field_prime: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

fn fuzzFe(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var s: [32]u8 = undefined;
    src.bytes(&s);
    var near = false;
    if (S == Rng) {
        // Land on p-2..p+2 (as a big-endian integer) in a quarter of the draws.
        if (s[0] & 3 == 0) {
            const delta: i3 = @intCast(@as(i8, @intCast(s[1] % 5)) - 2);
            var v: u256 = field_prime;
            v = if (delta < 0) v - @as(u256, @intCast(-@as(i8, delta))) else v +% @as(u256, @intCast(delta));
            std.mem.writeInt(u256, &s, v, .big);
            near = true;
        }
    }
    const endian: std.builtin.Endian = if (s[31] & 1 == 0) .big else .little;
    var bytes = s;
    if (endian == .little) std.mem.reverse(u8, &bytes);
    const value = std.mem.readInt(u256, &s, if (endian == .big) .big else .little);
    const fe = Fe.fromBytes(s, endian) catch {
        // Refused exactly when it is not below p.
        if (value < field_prime) return error.CanonicalEncodingRefused;
        FeMark.mark(.refused);
        if (near) FeMark.mark(.boundary);
        return;
    };
    if (value >= field_prime) return error.NonCanonicalEncodingAccepted;
    FeMark.mark(.accepted);
    if (!std.mem.eql(u8, &fe.toBytes(endian), &s)) return error.AcceptedFeNotCanonical;
    FeMark.mark(.canonical);
}

fn mulSmith(_: void, s: *testing.Smith) !void {
    return fuzzMul(testing.Smith, s, testing.allocator);
}
test "fuzz: every scalar-multiplication implementation agrees" {
    try testing.fuzz({}, mulSmith, .{});
}
test "fuzz driver: K256_FUZZ (mul)" {
    try fuzz_driver.run(fuzzMul, .{ .prefix = "K256_FUZZ", .name = "k256-mul", .scale = 4 });
}
test "fuzz harness: mul, 60 seeds, reaches every outcome" {
    try MulMark.reach(fuzzMul, "k256-mul", 60);
}

/// Differential: `s*P` through `mulPublic`, `mulPublicDoubleAdd`, `mulPublicGlv`
/// and (for `P = G`) `combMulBase` agree, and `(a+b)P == aP + bP`.
fn fuzzMul(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [128]u8 = undefined;
    const n: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n] };
    const a = randScalar(&k);
    const b = randScalar(&k);
    const p = try Secp256k1.combMulBase(randScalar(&k), .big);
    const r1 = try p.mulPublic(a, .big);
    const r2 = try p.mulPublicDoubleAdd(a, .big);
    const r3 = try p.mulPublicGlv(a, .big);
    if (!r1.equivalent(r2) or !r1.equivalent(r3)) return error.ImplementationsDisagree;
    MulMark.mark(.implementations_agree);
    const g1 = try Secp256k1.combMulBase(a, .big);
    const g2 = try Secp256k1.basePoint.mulPublic(a, .big);
    if (!g1.equivalent(g2)) return error.CombDisagrees;
    MulMark.mark(.base_matches);
    const sum = (try k256.Scalar.fromBytes(a, .big)).add(try k256.Scalar.fromBytes(b, .big)).toBytes(.big);
    const lhs = try p.mulPublic(sum, .big);
    const rb = try p.mulPublic(b, .big);
    if (!lhs.equivalent(r1.add(rb))) return error.NotDistributive;
    MulMark.mark(.distributive);
}

fn signSmith(_: void, s: *testing.Smith) !void {
    return fuzzSign(testing.Smith, s, testing.allocator);
}
test "fuzz: ECDSA and BIP340 signatures verify when genuine and fail when damaged" {
    try testing.fuzz({}, signSmith, .{});
}
test "fuzz driver: K256_FUZZ (sign)" {
    try fuzz_driver.run(fuzzSign, .{ .prefix = "K256_FUZZ", .name = "k256-sign", .scale = 4 });
}
test "fuzz harness: sign, 60 seeds, reaches every outcome" {
    try SignMark.reach(fuzzSign, "k256-sign", 60);
}

fn fuzzSign(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [200]u8 = undefined;
    const n: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n] };
    const sk = randScalar(&k);
    var other_sk = randScalar(&k);
    if (std.mem.eql(u8, &sk, &other_sk)) other_sk[5] ^= 1;
    var digest: [32]u8 = undefined;
    for (&digest) |*x| x.* = k.byte();
    var msg_buf: [40]u8 = undefined;
    for (&msg_buf) |*x| x.* = k.byte();
    const msg = msg_buf[0..k.ranged(0, 40)];
    const bit = @as(u8, 1) << @intCast(k.ranged(0, 7));
    const pk = try Secp256k1.combMulBase(sk, .big);
    const pk_c = pk.toCompressedSec1();
    const other_c = (try Secp256k1.combMulBase(other_sk, .big)).toCompressedSec1();

    // ECDSA.
    const sig = try ecdsa_recover.sign(&sk, digest);
    var rs: [64]u8 = undefined;
    rs[0..32].* = sig.r;
    rs[32..64].* = sig.s;
    if (!sign.ecdsaVerifyPrehashed(&pk_c, digest, rs)) return error.GenuineEcdsaRefused;
    if (!sign.ecdsaVerifyPrehashed(&pk.toUncompressedSec1(), digest, rs)) return error.GenuineEcdsaRefused;
    SignMark.mark(.ecdsa_accepted);
    const rec = try ecdsa_recover.recoverPubkey(digest, sig.r, sig.s, sig.recid);
    if (!rec.equivalent(pk)) return error.RecoveredKeyDiffers;
    SignMark.mark(.recovered);
    var bad_rs = rs;
    bad_rs[k.ranged(0, 63)] ^= bit;
    if (sign.ecdsaVerifyPrehashed(&pk_c, digest, bad_rs)) return error.FlippedEcdsaVerifies;
    var bad_digest = digest;
    bad_digest[k.ranged(0, 31)] ^= bit;
    if (sign.ecdsaVerifyPrehashed(&pk_c, bad_digest, rs)) return error.WrongDigestVerifies;
    if (sign.ecdsaVerifyPrehashed(&other_c, digest, rs)) return error.WrongKeyVerifies;
    // A flipped signature must not recover the same key either.
    if (ecdsa_recover.recoverPubkey(digest, bad_rs[0..32].*, bad_rs[32..64].*, sig.recid)) |p2| {
        if (p2.equivalent(pk)) return error.FlippedSignatureRecoversKey;
    } else |_| {}

    // BIP340.
    var aux: [32]u8 = undefined;
    for (&aux) |*x| x.* = k.byte();
    const bsig = try sign.bip340Sign(&sk, msg, aux);
    var xonly: [32]u8 = pk_c[1..33].*;
    if (!sign.bip340Verify(xonly, msg, bsig)) return error.GenuineBip340Refused;
    SignMark.mark(.bip340_accepted);
    var bad_b = bsig;
    bad_b[k.ranged(0, 63)] ^= bit;
    if (sign.bip340Verify(xonly, msg, bad_b)) return error.FlippedBip340Verifies;
    SignMark.mark(.flipped_refused);
    var other_x: [32]u8 = other_c[1..33].*;
    if (sign.bip340Verify(other_x, msg, bsig)) return error.WrongKeyBip340Verifies;
    SignMark.mark(.wrong_key_refused);
    var other_msg: [41]u8 = undefined;
    @memcpy(other_msg[0..msg.len], msg);
    other_msg[msg.len] = k.byte();
    if (sign.bip340Verify(xonly, other_msg[0 .. msg.len + 1], bsig)) return error.WrongMessageVerifies;
    SignMark.mark(.wrong_message_refused);
    xonly = undefined;
    other_x = undefined;
}
