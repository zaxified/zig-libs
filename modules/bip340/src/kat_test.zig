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
