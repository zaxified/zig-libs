// SPDX-License-Identifier: MIT
//! Byte-exact assertions against `kat_vectors.zig`'s official RFC 7748 /
//! RFC 8032 vectors, exercised end-to-end through `x448.zig`/
//! `ed448.zig`'s public API (scalarmult/DH, keygen, sign, verify,
//! tamper-reject, context binding, Ed448 vs Ed448ph domain separation).

const std = @import("std");
const x448 = @import("x448.zig");
const ed448 = @import("ed448.zig");
const scalar = @import("scalar.zig");
const v = @import("kat_vectors.zig");

// ── X448 (RFC 7748 §5.2, §6.2) ──────────────────────────────────────────

test "RFC 7748 §5.2: X448 scalarmult test vector 1, byte-exact" {
    const vec = v.x448.scalarmult_vectors[0];
    var out: [x448.shared_length]u8 = undefined;
    try x448.scalarmult(&out, &vec.scalar, vec.u);
    try std.testing.expectEqualSlices(u8, &vec.output, &out);
}

test "RFC 7748 §5.2: X448 scalarmult test vector 2, byte-exact" {
    const vec = v.x448.scalarmult_vectors[1];
    var out: [x448.shared_length]u8 = undefined;
    try x448.scalarmult(&out, &vec.scalar, vec.u);
    try std.testing.expectEqualSlices(u8, &vec.output, &out);
}

test "RFC 7748 §5.2: X448 iterated test, one iteration, byte-exact" {
    // Initial k = u = base_u (the byte value 5 followed by zeros).
    var out: [x448.shared_length]u8 = undefined;
    try x448.scalarmult(&out, &x448.base_u, x448.base_u);
    try std.testing.expectEqualSlices(u8, &v.x448.iterated_1, &out);
}

test "RFC 7748 §6.2: X448 Diffie-Hellman example — Alice/Bob public keys, byte-exact" {
    const alice_pub = try x448.recoverPublicKey(&v.x448.dh.alice_private);
    try std.testing.expectEqualSlices(u8, &v.x448.dh.alice_public, &alice_pub);

    const bob_pub = try x448.recoverPublicKey(&v.x448.dh.bob_private);
    try std.testing.expectEqualSlices(u8, &v.x448.dh.bob_public, &bob_pub);
}

test "RFC 7748 §6.2: X448 Diffie-Hellman example — shared secret, byte-exact, both directions" {
    var k_alice: [x448.shared_length]u8 = undefined;
    try x448.scalarmult(&k_alice, &v.x448.dh.alice_private, v.x448.dh.bob_public);
    try std.testing.expectEqualSlices(u8, &v.x448.dh.shared, &k_alice);

    var k_bob: [x448.shared_length]u8 = undefined;
    try x448.scalarmult(&k_bob, &v.x448.dh.bob_private, v.x448.dh.alice_public);
    try std.testing.expectEqualSlices(u8, &v.x448.dh.shared, &k_bob);
}

test "RFC 7748 §5: X448 of a small-order u (0, 1, p - 1) is all zeros" {
    // u = 0 has order 2 and u = ±1 order 4 (on the curve or its twist); the
    // clamped scalar is a multiple of the cofactor 4, so the ladder ends at
    // the point at infinity, z_2 = 0, and RFC 7748 §5's x_2 · z_2^(p-2) is 0.
    // RFC 7748 §6.2 names this all-zero output as the check a caller MAY make.
    var p_minus_1 = @as([56]u8, @splat(0xff)); // p = 2^448 - 2^224 - 1, little-endian
    p_minus_1[28] = 0xfe;
    p_minus_1[0] = 0xfe;
    var one = @as([56]u8, @splat(0));
    one[0] = 1;
    const zero = @as([56]u8, @splat(0));
    for ([_][56]u8{ zero, one, p_minus_1 }) |u| {
        var out: [x448.shared_length]u8 = undefined;
        try x448.scalarmult(&out, &v.x448.dh.alice_private, u);
        try std.testing.expectEqualSlices(u8, &zero, &out);
    }
}

// ── Ed448 / Ed448ph (RFC 8032 §7.4, §7.5) ───────────────────────────────

fn checkEd448Vector(vec: v.ed448.Vec) !void {
    const kp = ed448.KeyPair.create(&vec.sk);
    try std.testing.expectEqualSlices(u8, &vec.pk, &kp.public_key.bytes);

    const sig = try ed448.sign(&kp, vec.msg, vec.ctx);
    try std.testing.expectEqualSlices(u8, &vec.sig, &sig.toBytes());

    try ed448.verify(sig, vec.msg, vec.ctx, kp.public_key);

    // Tamper: flipping a message byte (or, for the empty message, adding
    // one) must be rejected.
    if (vec.msg.len > 0) {
        var tampered = std.testing.allocator.dupe(u8, vec.msg) catch unreachable;
        defer std.testing.allocator.free(tampered);
        tampered[0] ^= 0x01;
        try std.testing.expectError(error.SignatureVerificationFailed, ed448.verify(sig, tampered, vec.ctx, kp.public_key));
    }
}

test "RFC 8032 §7.4: Ed448 'Blank' vector (0-byte message) — keygen + sign + verify, byte-exact" {
    try checkEd448Vector(v.ed448.blank);
}

test "RFC 8032 §7.4: Ed448 '1 octet' vector — keygen + sign + verify, byte-exact" {
    try checkEd448Vector(v.ed448.one_octet);
}

test "RFC 8032 §7.4: Ed448 '1 octet (with context)' vector — keygen + sign + verify, byte-exact" {
    try checkEd448Vector(v.ed448.one_octet_with_context);
}

test "RFC 8032 §7.4: Ed448 '11 octets' vector — keygen + sign + verify, byte-exact" {
    try checkEd448Vector(v.ed448.eleven_octets);
}

test "RFC 8032 §7.4/§7.5: the variable-base Point.mul reproduces the public keys" {
    // A = [s]B (RFC 8032 §5.2.5). `KeyPair.create` uses the fixed-base comb;
    // this asks the generic windowed `Point.mul` (decaf448's path) for the
    // same point, against the RFC's public keys.
    for ([_]v.ed448.Vec{ v.ed448.blank, v.ed448.one_octet, v.ed448.one_octet_with_context, v.ed448.eleven_octets, v.ed448.ph_test_abc }) |vec| {
        var h: [114]u8 = undefined;
        std.crypto.hash.sha3.Shake256.hash(&vec.sk, &h, .{});
        var s = h[0..57].*;
        scalar.clamp(&s);
        const a = ed448.Point.mul(ed448.Point.basePoint, s);
        try std.testing.expectEqualSlices(u8, &vec.pk, &a.toBytes());
    }
}

test "RFC 8032 §7.4: context binding — a signature made under one context fails to verify under another" {
    const vec = v.ed448.one_octet_with_context;
    const kp = ed448.KeyPair.create(&vec.sk);
    const sig = try ed448.sign(&kp, vec.msg, vec.ctx);
    try std.testing.expectError(error.SignatureVerificationFailed, ed448.verify(sig, vec.msg, "bar", kp.public_key));
    try std.testing.expectError(error.SignatureVerificationFailed, ed448.verify(sig, vec.msg, "", kp.public_key));
}

test "RFC 8032 §7.5: Ed448ph 'TEST abc' vector — keygen + signPh + verifyPh, byte-exact" {
    const vec = v.ed448.ph_test_abc;
    const kp = ed448.KeyPair.create(&vec.sk);
    try std.testing.expectEqualSlices(u8, &vec.pk, &kp.public_key.bytes);

    const sig = try ed448.signPh(&kp, vec.msg, vec.ctx);
    try std.testing.expectEqualSlices(u8, &vec.sig, &sig.toBytes());

    try ed448.verifyPh(sig, vec.msg, vec.ctx, kp.public_key);
    try std.testing.expectError(error.SignatureVerificationFailed, ed448.verifyPh(sig, "abd", vec.ctx, kp.public_key));
}

test "RFC 8032 §7.4: Ed448 plain 'verify' rejects a signature made for Ed448ph, and vice versa" {
    // phflag=0 vs phflag=1 changes the dom4 prefix, so a signature valid
    // under one is not valid under the other, even for the same
    // underlying message bytes and key pair.
    const vec = v.ed448.ph_test_abc;
    const kp = ed448.KeyPair.create(&vec.sk);
    const sig_ph = try ed448.signPh(&kp, vec.msg, vec.ctx);
    try std.testing.expectError(error.SignatureVerificationFailed, ed448.verify(sig_ph, vec.msg, vec.ctx, kp.public_key));
}

// ── every RFC 8032 §7.4/§7.5 vector (rfc8032_vectors.zig) ───────────────

const rfc = @import("rfc8032_vectors.zig");
const wp = @import("wycheproof_vectors.zig");

fn unhex(gpa: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, hex.len / 2);
    errdefer gpa.free(out);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

test "RFC 8032 §7.4/§7.5: every vector (9 Ed448 incl. 1023 octets, 2 Ed448ph) — keygen, sign, verify, tamper" {
    const gpa = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, 11), rfc.vectors.len);
    var n_ph: usize = 0;
    for (rfc.vectors) |vec| {
        const sk = try unhex(gpa, vec.sk);
        defer gpa.free(sk);
        const pk = try unhex(gpa, vec.pk);
        defer gpa.free(pk);
        const msg = try unhex(gpa, vec.msg);
        defer gpa.free(msg);
        const ctx = try unhex(gpa, vec.ctx);
        defer gpa.free(ctx);
        const sig_bytes = try unhex(gpa, vec.sig);
        defer gpa.free(sig_bytes);

        const kp = ed448.KeyPair.create(sk[0..57]);
        try std.testing.expectEqualSlices(u8, pk, &kp.public_key.bytes);

        const sig = if (vec.ph) try ed448.signPh(&kp, msg, ctx) else try ed448.sign(&kp, msg, ctx);
        try std.testing.expectEqualSlices(u8, sig_bytes, &sig.toBytes());

        // Verify the RFC's own signature bytes, not only ours.
        const rfc_sig = try ed448.Signature.fromBytes(sig_bytes[0..114].*);
        if (vec.ph) {
            n_ph += 1;
            try ed448.verifyPh(rfc_sig, msg, ctx, kp.public_key);
            try std.testing.expectError(error.SignatureVerificationFailed, ed448.verify(rfc_sig, msg, ctx, kp.public_key));
        } else {
            try ed448.verify(rfc_sig, msg, ctx, kp.public_key);
            try std.testing.expectError(error.SignatureVerificationFailed, ed448.verifyPh(rfc_sig, msg, ctx, kp.public_key));
        }
        // A flipped bit in R or S must not verify (S may become non-canonical).
        for ([_]usize{ 0, 56, 57, 100 }) |pos| {
            var bad = sig_bytes[0..114].*;
            bad[pos] ^= 0x01;
            const bs = ed448.Signature.fromBytes(bad) catch continue;
            const r = if (vec.ph) ed448.verifyPh(bs, msg, ctx, kp.public_key) else ed448.verify(bs, msg, ctx, kp.public_key);
            try std.testing.expect(std.meta.isError(r));
        }
    }
    try std.testing.expectEqual(@as(usize, 2), n_ph);
}

// ── Wycheproof ed448_test.json (wycheproof_vectors.zig) ─────────────────

/// Our verdict on one Wycheproof case: true = accepted. A wrong-length
/// signature or public key is rejected by the caller before the API
/// (the API takes fixed-size arrays).
fn wycheproofAccepts(gpa: std.mem.Allocator, vec: wp.Vector) !bool {
    const pk = try unhex(gpa, vec.pk);
    defer gpa.free(pk);
    const msg = try unhex(gpa, vec.msg);
    defer gpa.free(msg);
    const sig_bytes = try unhex(gpa, vec.sig);
    defer gpa.free(sig_bytes);
    if (pk.len != 57 or sig_bytes.len != 114) return false;
    const sig = ed448.Signature.fromBytes(sig_bytes[0..114].*) catch return false;
    ed448.verify(sig, msg, "", ed448.PublicKey.fromBytes(pk[0..57].*)) catch return false;
    return true;
}

test "Wycheproof Ed448: all 87 cases agree with the expected result (17 valid, 70 invalid, 0 acceptable)" {
    const gpa = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, 87), wp.vectors.len);
    var n_valid: usize = 0;
    var n_invalid: usize = 0;
    var n_acceptable: usize = 0;
    for (wp.vectors) |vec| {
        const ok = try wycheproofAccepts(gpa, vec);
        switch (vec.result) {
            .valid => {
                n_valid += 1;
                if (!ok) {
                    std.debug.print("Wycheproof tcId {d} ({s}) must verify\n", .{ vec.tc_id, vec.comment });
                    return error.TestUnexpectedResult;
                }
            },
            .invalid => {
                n_invalid += 1;
                if (ok) {
                    std.debug.print("Wycheproof tcId {d} ({s}) must be rejected\n", .{ vec.tc_id, vec.comment });
                    return error.TestUnexpectedResult;
                }
            },
            // The file has none; a future refresh that adds some must
            // decide per case, so fail loudly rather than record silently.
            .acceptable => {
                n_acceptable += 1;
                std.debug.print("Wycheproof tcId {d} is 'acceptable': we answer {}\n", .{ vec.tc_id, ok });
                return error.TestUnexpectedResult;
            },
        }
    }
    try std.testing.expectEqual(@as(usize, 17), n_valid);
    try std.testing.expectEqual(@as(usize, 70), n_invalid);
    try std.testing.expectEqual(@as(usize, 0), n_acceptable);
}

test "Wycheproof Ed448: the error class for each invalid kind (non-canonical S, non-canonical R/A, small order, wrong length)" {
    // Records WHICH check rejects, so a regression that rejects for the wrong
    // reason (or accepts) shows. Counts are what the code answers today.
    const gpa = std.testing.allocator;
    var wrong_len: usize = 0;
    var s_noncanonical: usize = 0;
    var other: usize = 0;
    for (wp.vectors) |vec| {
        if (vec.result != .invalid) continue;
        const pk = try unhex(gpa, vec.pk);
        defer gpa.free(pk);
        const msg = try unhex(gpa, vec.msg);
        defer gpa.free(msg);
        const sig_bytes = try unhex(gpa, vec.sig);
        defer gpa.free(sig_bytes);
        if (sig_bytes.len != 114) {
            wrong_len += 1;
            continue;
        }
        const sig = ed448.Signature.fromBytes(sig_bytes[0..114].*) catch {
            s_noncanonical += 1;
            continue;
        };
        try std.testing.expect(std.meta.isError(ed448.verify(sig, msg, "", ed448.PublicKey.fromBytes(pk[0..57].*))));
        other += 1;
    }
    try std.testing.expectEqual(@as(usize, 12), wrong_len);
    try std.testing.expectEqual(@as(usize, 16), s_noncanonical);
    try std.testing.expectEqual(@as(usize, 42), other);
}
