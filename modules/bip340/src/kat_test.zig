// SPDX-License-Identifier: MIT
//! Tests against the official BIP340 test vectors (`kat_vectors.zig`).
//!
//! Coverage:
//!   - `XOnlyPublicKey.fromBytes` / `lift_x` on every vector's public key,
//!     including the two that must fail (index 5: not on the curve; index
//!     14: x exceeds the field size).
//!   - `Signature.fromBytes`'s canonical range checks (`r < p`, `s < n`)
//!     on every vector's signature, including the two that must fail on
//!     parse alone (index 12: `r == p`; index 13: `s == n`) and the one
//!     that must NOT fail on parse alone (index 11: `r` is a canonical
//!     field element that simply isn't a valid x-coordinate — that failure
//!     only shows up at `verify`, whose computed `x(R)` can never equal a
//!     non-x-coordinate `r`).
//!   - `KeyPair.fromSecretKey`/`PublicKey.fromSecretKey`'s even-y
//!     normalization + derived-public-key computation, on every vector
//!     that has a known secret key (indices 0-3, 15-18).
//!   - Full `sign` round-trip: every secret-key vector signs to the exact
//!     64 published signature bytes.
//!   - Full `verify`: every vector's `verification result` column matched
//!     exactly — all TRUE rows accept, all 10 FALSE rows reject.
//!   - `verifyBatch` correctness (no official KAT vectors exist for it):
//!     a batch of all valid vectors accepts; corrupting any single
//!     signature/message/pubkey rejects the whole batch.

const std = @import("std");
const bip340 = @import("root.zig");
const v = @import("kat_vectors.zig");
const k256 = @import("k256");
const Scalar = k256.Secp256k1.scalar.Scalar;

fn hexAlloc(gpa: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, hex_str.len / 2);
    _ = try std.fmt.hexToBytes(out, hex_str);
    return out;
}

fn hex32(hex_str: []const u8) ![32]u8 {
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, hex_str);
    return out;
}

fn hex64(hex_str: []const u8) ![64]u8 {
    var out: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, hex_str);
    return out;
}

/// Vectors whose PUBLIC KEY itself must fail `lift_x` (independent of the
/// signature): index 5 (not on the curve), index 14 (exceeds field size).
fn pubkeyMustBeInvalid(index: u8) bool {
    return index == 5 or index == 14;
}

/// Vectors whose SIGNATURE must fail parse-level range checks (`r < p`,
/// `s < n`) alone, before any curve-point lifting: index 12 (`r == p`),
/// index 13 (`s == n`).
fn signatureMustFailRangeCheck(index: u8) bool {
    return index == 12 or index == 13;
}

test "KAT: XOnlyPublicKey.fromBytes / lift_x on every vector's public key" {
    for (v.vectors) |vec| {
        const pk_bytes = try hex32(vec.public_key);
        const result = bip340.XOnlyPublicKey.fromBytes(pk_bytes);
        if (pubkeyMustBeInvalid(vec.index)) {
            try std.testing.expectError(error.InvalidPublicKey, result);
        } else {
            const xonly = try result;
            try std.testing.expectEqualSlices(u8, &pk_bytes, &xonly.toBytes());
            // lift() must succeed and reproduce the same x, with an even y.
            const p = try xonly.lift();
            const xy = p.affineCoordinates();
            try std.testing.expect(!xy.y.isOdd());
            try std.testing.expectEqualSlices(u8, &pk_bytes, &xy.x.toBytes(.big));
        }
    }
}

test "KAT: Signature.fromBytes canonical range checks (r < p, s < n)" {
    for (v.vectors) |vec| {
        const sig_bytes = try hex64(vec.signature);
        const result = bip340.Signature.fromBytes(sig_bytes);
        if (signatureMustFailRangeCheck(vec.index)) {
            try std.testing.expectError(error.InvalidSignature, result);
        } else {
            const sig = try result;
            try std.testing.expectEqualSlices(u8, &sig_bytes, &sig.toBytes());
        }
    }
}

test "KAT: index 11's r is parse-valid (canonical) even though it is not a valid x-coordinate" {
    // Distinguishes "r < p" (parse-level, Signature.fromBytes's job) from
    // "x(R) can equal r" (verify-level) — the comment on this vector is
    // specifically about the latter failing, not the former.
    const vec = v.vectors[11];
    try std.testing.expectEqualStrings("sig[0:32] is not an X coordinate on the curve", vec.comment);
    const sig_bytes = try hex64(vec.signature);
    _ = try bip340.Signature.fromBytes(sig_bytes);
}

test "KAT: KeyPair/PublicKey derivation from secret key matches the published public key" {
    const gpa = std.testing.allocator;
    for (v.vectors) |vec| {
        const sk_hex = vec.secret_key orelse continue;
        const sk_bytes = try hex32(sk_hex);
        const sk = try bip340.SecretKey.fromBytes(sk_bytes);

        const want_pk = try hex32(vec.public_key);

        const kp = try bip340.KeyPair.fromSecretKey(sk);
        try std.testing.expectEqualSlices(u8, &want_pk, &kp.public.toBytes());

        const pk = try bip340.PublicKey.fromSecretKey(sk);
        try std.testing.expectEqualSlices(u8, &want_pk, &pk.xonly.toBytes());

        _ = gpa;
    }
}

test "KAT: sign reproduces the expected signature for every secret-key vector" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for (v.vectors) |vec| {
        const sk_hex = vec.secret_key orelse continue;
        const sk = try bip340.SecretKey.fromBytes(try hex32(sk_hex));
        const aux = try hex32(vec.aux_rand.?);
        const msg = try hexAlloc(gpa, vec.message);
        defer gpa.free(msg);
        const got = try bip340.sign(sk, msg, aux, io);
        try std.testing.expectEqualSlices(u8, &(try hex64(vec.signature)), &got);
    }
}

test "KAT: verify accepts every TRUE vector and rejects every FALSE (negative) vector" {
    const gpa = std.testing.allocator;
    for (v.vectors) |vec| {
        const pk = bip340.XOnlyPublicKey.fromBytes(try hex32(vec.public_key)) catch {
            try std.testing.expect(!vec.result); // invalid pubkey => must be a FALSE vector
            continue;
        };
        const sig = bip340.Signature.fromBytes(try hex64(vec.signature)) catch {
            try std.testing.expect(!vec.result);
            continue;
        };
        const msg = try hexAlloc(gpa, vec.message);
        defer gpa.free(msg);
        try std.testing.expectEqual(vec.result, bip340.verify(pk, msg, sig));
    }
    // This is the test that exercises the R.y-parity check (index 6),
    // negated-message/negated-s (indices 7/8), sG-eP-infinite (indices
    // 9/10), and r-doesn't-lift (index 11) negative cases — i.e. the
    // subtle bugs this KAT set exists to catch.
}

test "batch: all valid vectors accept; corrupting any single item rejects the whole batch" {
    // No official KAT vectors exist for batch verification (BIP340's CSV
    // covers single verification only) — cross-check against `verify`
    // instead: a batch of every TRUE vector must accept, and flipping any
    // one item's signature, message, or pubkey must reject the batch.
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var items: std.ArrayList(bip340.BatchItem) = .empty;
    defer items.deinit(gpa);
    var msgs: std.ArrayList([]u8) = .empty;
    defer {
        for (msgs.items) |m| gpa.free(m);
        msgs.deinit(gpa);
    }
    for (v.vectors) |vec| {
        if (!vec.result) continue;
        const msg = try hexAlloc(gpa, vec.message);
        try msgs.append(gpa, msg);
        try items.append(gpa, .{
            .pubkey = try bip340.XOnlyPublicKey.fromBytes(try hex32(vec.public_key)),
            .msg = msg,
            .sig = try bip340.Signature.fromBytes(try hex64(vec.signature)),
        });
    }
    try std.testing.expect(items.items.len >= 3);

    // Sanity: every item verifies individually, and the clean batch accepts.
    for (items.items) |item| try std.testing.expect(bip340.verify(item.pubkey, item.msg, item.sig));
    try std.testing.expect(bip340.verifyBatch(items.items, io));

    // The empty batch is vacuously valid.
    try std.testing.expect(bip340.verifyBatch(items.items[0..0], io));

    // Corrupt each item's s (flip one bit) — the whole batch must reject.
    for (items.items, 0..) |orig, i| {
        var corrupted = orig;
        corrupted.sig.s[31] ^= 0x01;
        items.items[i] = corrupted;
        try std.testing.expect(!bip340.verifyBatch(items.items, io));
        items.items[i] = orig;
    }

    // Corrupt one item's message — reject.
    {
        const orig = items.items[1];
        items.items[1].msg = items.items[2].msg;
        try std.testing.expect(!bip340.verifyBatch(items.items, io));
        items.items[1] = orig;
    }

    // Swap one item's pubkey for another vector's — reject.
    {
        const orig = items.items[0];
        items.items[0].pubkey = items.items[1].pubkey;
        try std.testing.expect(!bip340.verifyBatch(items.items, io));
        items.items[0] = orig;
    }

    // A batch containing an r that does not lift (vector 11) — reject.
    {
        const vec11 = v.vectors[11];
        const orig = items.items[0];
        items.items[0] = .{
            .pubkey = try bip340.XOnlyPublicKey.fromBytes(try hex32(vec11.public_key)),
            .msg = msgs.items[0],
            .sig = try bip340.Signature.fromBytes(try hex64(vec11.signature)),
        };
        try std.testing.expect(!bip340.verifyBatch(items.items, io));
        items.items[0] = orig;
    }
}

test "KAT: hexAlloc helper decodes variable-length messages (sanity for the sign/verify TODOs above)" {
    const gpa = std.testing.allocator;
    for (v.vectors) |vec| {
        const msg = try hexAlloc(gpa, vec.message);
        defer gpa.free(msg);
        try std.testing.expectEqual(vec.message.len / 2, msg.len);
    }
}

// ── fuzz: verify on hostile signature bytes ─────────────────────────────
//
// `verify` is the module's untrusted-input entry point: any peer can hand
// it 64 arbitrary bytes claiming to be a signature over a fixed, known
// pubkey/message, and it must return `false` — never panic, never read out
// of bounds. Vector 0 (a real, valid `(pubkey, message, signature)` triple)
// supplies the fixed pubkey/message; only the signature bytes are mutated,
// starting from the real published signature and flipping a handful of
// bytes, so the fuzzer spends its budget near the `r < p`/`s < n` boundary
// and the curve-equation check rather than being rejected by the first
// range check on almost every draw.
// ⛔ AND THE PARAGRAPH ABOVE DESCRIBED SOMETHING THAT NEVER HAPPENED. The
// "flipping a handful of bytes" was `smith.valueRangeAtMost(u8, 0, 6)` as
// the harness's FIRST draw. A `Smith` ranged draw reads eight octets as a
// little-endian `u64` and returns the range MINIMUM when fewer remain, and
// the target had no corpus, so outside `--fuzz` the single input it ever ran
// was empty: **zero flips, every time**. Every ordinary `zig build test`
// verified the pristine, valid vector-0 signature — which the KAT tests two
// screens up already assert — and not one corrupted byte ever reached the
// `r < p` / `s < n` range checks or the curve-equation check the comment
// says the budget is spent near. Measured 2026-09-07: 1 round, 1 input, 0
// bytes flipped, 0 refusals from `Signature.fromBytes`.
//
// The flip loop is gone. A signature is 64 octets off the wire, so the
// harness draws those 64 octets byte-first and the near-misses are a written
// corpus instead of a flip count the ordinary lane always drew as zero.
// Under `--fuzz` this is strictly better: the fuzzer mutates real 64-octet
// signatures rather than replaying one unmodified vector.

/// `testkit.fuzz.seedHex`, aliased so the corpus reads as the signatures it
/// is. A corpus entry is not the signature: `Smith.slice` reads a
/// little-endian `u32` length first, so a raw signature would arrive minus
/// the first four octets of `r`.
const seedHex = @import("testkit").fuzz.seedHex;

/// 64-octet signatures over vector 0's `(pubkey, message)`, in the format the
/// length draw reads. The two range checks `Signature.fromBytes` performs are
/// `r < p` and `s < n`, so both boundaries appear here from both sides — the
/// cases the deleted flip loop was supposed to find and never once produced.
///
/// ⚠ 64 octets is the buffer exactly. A seed longer than the buffer is not a
/// large seed, it is the EMPTY one.
const sig_seeds = [_][]const u8{
    // The real vector-0 signature: the one input the old harness ever ran.
    seedHex("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"),
    // Vector 1's signature: well-formed, over the wrong message → false.
    seedHex("6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"),
    // r = p exactly: the first thing `Fe.fromBytes` must refuse.
    seedHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"),
    // r = p − 1: the largest r that is still canonical.
    seedHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"),
    // s = n exactly: the group-order boundary `Scalar.fromBytes` refuses.
    seedHex("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
    // s = n − 1: the largest s that is still canonical.
    seedHex("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"),
    // r = 0, s = 0: canonical, and `lift_x(0)` has no even-y point.
    seedHex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
    // Every octet set: r and s are both over their moduli.
    seedHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
    // Vector 0 with one octet of s flipped: the near-miss the flip loop meant.
    seedHex("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C1"),
    // Vector 0 with one octet of r flipped.
    seedHex("E807831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"),
    // A 63-octet signature: short of the wire form, zero-padded by the harness.
    seedHex("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536"),
    seedHex(""), // zero length, which is what an empty corpus produced
};

test "fuzz: verify never panics on corrupted signature bytes" {
    try std.testing.fuzz({}, fuzzVerify, .{ .corpus = &sig_seeds });
}

fn fuzzVerify(_: void, smith: *std.testing.Smith) !void {
    const vec0 = v.vectors[0];
    const pk = bip340.XOnlyPublicKey.fromBytes(hex32(vec0.public_key) catch unreachable) catch return;
    var msg_buf: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&msg_buf, vec0.message) catch unreachable;

    // ⚠ ONE byte-first draw. Never a ranged draw before the bytes: see the
    // block comment above for the four months that cost.
    var buf: [64]u8 = undefined;
    const n: usize = smith.slice(&buf);
    // `fromBytes` takes exactly 64 octets, so a short draw is zero-padded the
    // way a short wire read would have to be.
    var bytes: [64]u8 = [_]u8{0} ** 64;
    @memcpy(bytes[0..n], buf[0..n]);

    const sig = bip340.Signature.fromBytes(bytes) catch return;
    _ = bip340.verify(pk, &msg_buf, sig);
}

test "corpus: every signature seed reaches fromBytes, and the outcomes are pinned" {
    // ⭐ The measurement, executable. It draws exactly the way the harness
    // does, because the defect WAS the draw.
    //
    // `refused` is the second number and it is the load-bearing one:
    // `Signature.fromBytes` on 64 zero octets — the input an empty corpus
    // produces — SUCCEEDS, because 0 is a canonical `Fe` and a canonical
    // `Scalar`. So an "accepted > 0" guard would read 100% while the harness
    // walked nothing. A refusal can only come from a seed that puts a value
    // at or above `p` or `n`, which zeroes cannot do.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var refused: usize = 0;
    var verified: usize = 0;
    const vec0 = v.vectors[0];
    const pk = try bip340.XOnlyPublicKey.fromBytes(try hex32(vec0.public_key));
    var msg_buf: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&msg_buf, vec0.message);
    for (sig_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [64]u8 = undefined;
        const n: usize = smith.slice(&buf);
        if (n != 0) nonempty += 1;
        var bytes: [64]u8 = [_]u8{0} ** 64;
        @memcpy(bytes[0..n], buf[0..n]);
        const sig = bip340.Signature.fromBytes(bytes) catch {
            refused += 1;
            continue;
        };
        accepted += 1;
        if (bip340.verify(pk, &msg_buf, sig)) verified += 1;
    }
    // Measured 2026-09-07. Before: 1 round, 1 input, 0 refusals, 1
    // verification — of the pristine vector the KATs already assert.
    try std.testing.expectEqual(sig_seeds.len - 1, nonempty); // the deliberate empty seed
    try std.testing.expectEqual(@as(usize, 3), refused);
    try std.testing.expectEqual(@as(usize, 9), accepted);
    try std.testing.expectEqual(@as(usize, 1), verified);
}

// ── F1: verifyBatch's randomizers are what a mutation test needs to see ────
//
// A1 audit F1 (`~/CML/20260901-zig-libs-audit/A1/bip340.md`): the random
// linear-combination coefficients `a_2..a_u` are the ONLY thing standing
// between `verifyBatch` and an attacker who submits a batch of individually
// INVALID signatures whose errors are crafted to cancel. Before this test,
// no test in the suite could tell a working randomizer from a broken one —
// mutating `verifyBatch` to always use `a_i = 1` passed the whole suite
// green (the existing "corrupting any single item" test flips one bit of
// `s`, which breaks a plain sum too, so it cannot distinguish the two).
//
// This test builds exactly that forged, cancelling pair:
//   item1 = (P1, m1, (r1, s1 + d))   -- individually INVALID
//   item2 = (P2, m2, (r2, s2 - d))   -- individually INVALID
// With `a_i = 1` for both items the batch equation degenerates to
// `sum(s_i)*G == sum(R_i + e_i*P_i)`, and the `+d`/`-d` errors cancel
// exactly — the mutant batch verifier accepts two forgeries. With real
// independent random `a_i`, the batch must reject.
test "batch: a random-linear-combination forgery (cancelling +d/-d pair) is REJECTED (F1)" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const sk1 = try bip340.SecretKey.fromBytes([_]u8{0xa1} ** 32);
    const sk2 = try bip340.SecretKey.fromBytes([_]u8{0xb2} ** 32);
    var kp1 = try bip340.KeyPair.fromSecretKey(sk1);
    defer kp1.deinit();
    var kp2 = try bip340.KeyPair.fromSecretKey(sk2);
    defer kp2.deinit();
    const m1 = [_]u8{0x11} ** 32;
    const m2 = [_]u8{0x22} ** 32;
    const aux = [_]u8{0} ** 32;

    const sig1 = try bip340.sign(sk1, &m1, aux, io);
    const sig2 = try bip340.sign(sk2, &m2, aux, io);
    const p1 = try bip340.Signature.fromBytes(sig1);
    const p2 = try bip340.Signature.fromBytes(sig2);

    // Sanity: the real signatures verify individually before we corrupt them.
    try std.testing.expect(bip340.verify(kp1.public, &m1, p1));
    try std.testing.expect(bip340.verify(kp2.public, &m2, p2));

    // Craft the cancelling pair: s1 += delta, s2 -= delta.
    const delta = Scalar.fromBytes([_]u8{0xde} ** 32, .big) catch unreachable;
    const s1 = Scalar.fromBytes(p1.s, .big) catch unreachable;
    const s2 = Scalar.fromBytes(p2.s, .big) catch unreachable;
    const forged1 = bip340.Signature{ .r = p1.r, .s = s1.add(delta).toBytes(.big) };
    const forged2 = bip340.Signature{ .r = p2.r, .s = s2.sub(delta).toBytes(.big) };

    // Each forged signature must be individually invalid...
    try std.testing.expect(!bip340.verify(kp1.public, &m1, forged1));
    try std.testing.expect(!bip340.verify(kp2.public, &m2, forged2));

    // ...and the batch that cancels them must still be rejected. This is
    // the property that only a real (non-degenerate) randomizer draw can
    // provide -- it is the whole point of F1.
    const items = [_]bip340.BatchItem{
        .{ .pubkey = kp1.public, .msg = &m1, .sig = forged1 },
        .{ .pubkey = kp2.public, .msg = &m2, .sig = forged2 },
    };
    var trials: usize = 0;
    while (trials < 20) : (trials += 1) {
        try std.testing.expect(!bip340.verifyBatch(&items, io));
    }
}
