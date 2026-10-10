// SPDX-License-Identifier: MIT

//! Shared plumbing for xmss's deterministic fuzz driver (added 2026-10-09).
//!
//! The harness BODIES stay in `root.zig` beside their corpora; each is
//! generic over its source of choices, `fn(comptime S, *S, gpa)`, and
//! `testing.fuzz` hands it a `std.testing.Smith` directly (every harness
//! begins with one `slice`, so corpus seeds replay as before). This file
//! holds what they share with the driver: the reach counters with the N-seed
//! in-suite check, and the input draw.
//!
//! Driver: `XMSS_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `xmss-verify`, `xmss-pubkey`,
//! `xmss-sign-verify`.

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

// ── the harnesses (XMSS-SHA2_10_256) ────────────────────────────────────────

const root = @import("root.zig");
const X = root.XmssSha2_10_256;

var fixture_cache: ?struct { pk: [X.public_key_length]u8, msg: [64]u8, sig: [X.signature_length]u8 } = null;

fn fixture() @TypeOf(fixture_cache.?) {
    if (fixture_cache) |f| return f;
    var kp: X.KeyPair = undefined;
    X.keyGen(&kp, &([_]u8{1} ** root.n), &([_]u8{2} ** root.n), &([_]u8{3} ** root.n));
    const msg = [_]u8{0xA7} ** 64;
    var sig: [X.signature_length]u8 = undefined;
    X.sign(&kp.sk, &sig, &msg) catch unreachable;
    fixture_cache = .{ .pk = kp.pk.toBytes(), .msg = msg, .sig = sig };
    return fixture_cache.?;
}

fn drawOne(comptime S: type, src: *S, buf: []u8, real: []const u8, damaged: bool) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf);
    if (!damaged) {
        @memcpy(buf[0..real.len], real);
        return real.len;
    }
    return damage(src, buf, real);
}

const VerifyMark = Marker(enum { genuine_accepted, damaged_refused, pk_refused, wild_refused });

/// The module's own signature with key / message / signature each intact or
/// damaged: only the intact triple verifies. Wild triples are refused.
fn fuzzVerify(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    const f = fixture();
    var pk_bytes: [X.public_key_length]u8 = undefined;
    var msg: [64]u8 = undefined;
    var sig: [X.signature_length]u8 = undefined;
    if (S == fuzz_driver.Rng and src.index(4) == 0) {
        src.bytes(&pk_bytes);
        std.mem.writeInt(u32, pk_bytes[0..4], X.oid, .big);
        src.bytes(&msg);
        const n = src.slice(&sig);
        const pk = try X.PublicKey.fromBytes(&pk_bytes);
        if (X.verify(pk, &msg, sig[0..n])) return error.WildTripleVerified;
        VerifyMark.mark(.wild_refused);
        return;
    }
    const dmg_pk = S == fuzz_driver.Rng and src.index(3) == 0;
    const dmg_msg = S == fuzz_driver.Rng and src.index(3) == 0;
    const dmg_sig = S == fuzz_driver.Rng and src.index(3) == 0;
    var pk_len: usize = undefined;
    if (S == fuzz_driver.Rng) {
        pk_len = drawOne(S, src, &pk_bytes, &f.pk, dmg_pk);
    } else {
        src.bytes(&pk_bytes);
        std.mem.writeInt(u32, pk_bytes[0..4], X.oid, .big);
        pk_len = pk_bytes.len;
    }
    // Short or damaged-OID keys are refused by the decoder.
    var full_pk: [X.public_key_length]u8 = @splat(0);
    @memcpy(full_pk[0..pk_len], pk_bytes[0..pk_len]);
    var ml: usize = undefined;
    if (S == fuzz_driver.Rng) {
        ml = drawOne(S, src, &msg, &f.msg, dmg_msg);
    } else {
        src.bytes(&msg);
        ml = msg.len;
    }
    const sl = drawOne(S, src, &sig, &f.sig, dmg_sig);
    const pristine = pk_len == f.pk.len and std.mem.eql(u8, &full_pk, &f.pk) and std.mem.eql(u8, msg[0..ml], &f.msg) and std.mem.eql(u8, sig[0..sl], &f.sig);
    const pk = X.PublicKey.fromBytes(&full_pk) catch {
        if (pristine) return error.GenuineKeyRefused;
        VerifyMark.mark(.pk_refused);
        return;
    };
    const ok = X.verify(pk, msg[0..ml], sig[0..sl]);
    if (ok != pristine) return if (pristine) error.GenuineTripleRefused else error.DamagedTripleVerified;
    if (pristine) VerifyMark.mark(.genuine_accepted) else VerifyMark.mark(.damaged_refused);
}

const PubMark = Marker(enum { accepted, refused });

/// `PublicKey.fromBytes`: only the module's OID is accepted, and what it
/// accepts re-encodes to the same octets.
fn fuzzPubkey(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    const f = fixture();
    var bytes: [X.public_key_length]u8 = undefined;
    if (S == fuzz_driver.Rng and src.value(bool)) {
        var tmp: [X.public_key_length]u8 = undefined;
        const n = damage(src, &tmp, &f.pk);
        @memset(&bytes, 0);
        @memcpy(bytes[0..n], tmp[0..n]);
    } else src.bytes(&bytes);
    if (X.PublicKey.fromBytes(&bytes)) |pk| {
        PubMark.mark(.accepted);
        if (!std.mem.eql(u8, &pk.toBytes(), &bytes)) return error.NonCanonicalPublicKeyAccepted;
    } else |_| PubMark.mark(.refused);
}

var sign_key: ?X.KeyPair = null;
const SignMark = Marker(enum { genuine_accepted, flipped_refused, truncated_refused, extended_refused, wrong_message_refused, wrong_key_refused });

/// A signature `sign` produced (a stateful key, one leaf per run, re-created
/// when its 1,024 leaves are spent) verifies; a flipped octet anywhere, a
/// truncation, an extension, another message and another key do not.
fn fuzzSignVerify(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    if (sign_key == null) {
        sign_key = @as(X.KeyPair, undefined);
        X.keyGen(&sign_key.?, &([_]u8{9} ** root.n), &([_]u8{8} ** root.n), &([_]u8{7} ** root.n));
    }
    var mbuf: [70]u8 = undefined;
    const ml = src.index(mbuf.len + 1);
    src.bytes(mbuf[0..ml]);
    const msg = mbuf[0..ml];
    var sig: [X.signature_length]u8 = undefined;
    X.sign(&sign_key.?.sk, &sig, msg) catch {
        sign_key = null; // spent
        return;
    };
    const pk = sign_key.?.pk;
    if (!X.verify(pk, msg, &sig)) return error.GenuineSignatureRefused;
    SignMark.mark(.genuine_accepted);

    var m2: [71]u8 = undefined;
    @memcpy(m2[0..ml], msg);
    m2[ml] = src.value(u8);
    if (X.verify(pk, m2[0 .. ml + 1], &sig)) return error.OtherMessageVerified;
    SignMark.mark(.wrong_message_refused);
    var pk2 = pk;
    pk2.root[src.index(root.n)] ^= src.valueRangeAtMost(u8, 1, 255);
    if (X.verify(pk2, msg, &sig)) return error.OtherRootVerified;
    SignMark.mark(.wrong_key_refused);
    var pk3 = pk;
    pk3.seed[src.index(root.n)] ^= src.valueRangeAtMost(u8, 1, 255);
    if (X.verify(pk3, msg, &sig)) return error.OtherSeedVerified;

    if (X.verify(pk, msg, sig[0..src.index(sig.len)])) return error.TruncatedSignatureVerified;
    SignMark.mark(.truncated_refused);
    var longer: [X.signature_length + 1]u8 = undefined;
    @memcpy(longer[0..sig.len], &sig);
    longer[sig.len] = src.value(u8);
    if (X.verify(pk, msg, &longer)) return error.ExtendedSignatureVerified;
    SignMark.mark(.extended_refused);

    sig[src.index(sig.len)] ^= src.valueRangeAtMost(u8, 1, 255);
    if (X.verify(pk, msg, &sig)) return error.FlippedSignatureVerified;
    SignMark.mark(.flipped_refused);
}

fn smithRun(comptime f: anytype) fn (void, *std.testing.Smith) anyerror!void {
    return struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            try f(std.testing.Smith, smith, testing.allocator);
        }
    }.run;
}

test "fuzz: xmss verify, pubkey and sign/verify (Smith replay)" {
    try testing.fuzz({}, smithRun(fuzzVerify), .{});
    try testing.fuzz({}, smithRun(fuzzPubkey), .{});
    try testing.fuzz({}, smithRun(fuzzSignVerify), .{});
}

test "fuzz driver: XMSS_FUZZ (verify)" {
    try fuzz_driver.run(fuzzVerify, .{ .prefix = "XMSS_FUZZ", .name = "xmss-verify" });
}
test "fuzz driver: XMSS_FUZZ (pubkey)" {
    try fuzz_driver.run(fuzzPubkey, .{ .prefix = "XMSS_FUZZ", .name = "xmss-pubkey" });
}
test "fuzz driver: XMSS_FUZZ (sign + verify)" {
    // `.scale`: each run signs one of the key's 1,024 leaves and verifies up to six times.
    try fuzz_driver.run(fuzzSignVerify, .{ .prefix = "XMSS_FUZZ", .name = "xmss-sign-verify", .scale = 200 });
}

test "fuzz harness: xmss, reaches every outcome" {
    try VerifyMark.reach(fuzzVerify, "xmss-verify", 400);
    try PubMark.reach(fuzzPubkey, "xmss-pubkey", 400);
    try SignMark.reach(fuzzSignVerify, "xmss-sign-verify", 20);
}
