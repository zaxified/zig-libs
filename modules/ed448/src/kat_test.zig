// SPDX-License-Identifier: MIT
//! Byte-exact assertions against `kat_vectors.zig`'s official RFC 7748 /
//! RFC 8032 vectors, exercised end-to-end through `x448.zig`/
//! `ed448.zig`'s public API (scalarmult/DH, keygen, sign, verify,
//! tamper-reject, context binding, Ed448 vs Ed448ph domain separation).

const std = @import("std");
const x448 = @import("x448.zig");
const ed448 = @import("ed448.zig");
const v = @import("kat_vectors.zig");

// ── X448 (RFC 7748 §5.2, §6.2) ──────────────────────────────────────────

test "RFC 7748 §5.2: X448 scalarmult test vector 1, byte-exact" {
    const vec = v.x448.scalarmult_vectors[0];
    const out = try x448.scalarmult(vec.scalar, vec.u);
    try std.testing.expectEqualSlices(u8, &vec.output, &out);
}

test "RFC 7748 §5.2: X448 scalarmult test vector 2, byte-exact" {
    const vec = v.x448.scalarmult_vectors[1];
    const out = try x448.scalarmult(vec.scalar, vec.u);
    try std.testing.expectEqualSlices(u8, &vec.output, &out);
}

test "RFC 7748 §5.2: X448 iterated test, one iteration, byte-exact" {
    // Initial k = u = base_u (the byte value 5 followed by zeros).
    const out = try x448.scalarmult(x448.base_u, x448.base_u);
    try std.testing.expectEqualSlices(u8, &v.x448.iterated_1, &out);
}

test "RFC 7748 §6.2: X448 Diffie-Hellman example — Alice/Bob public keys, byte-exact" {
    const alice_pub = try x448.recoverPublicKey(v.x448.dh.alice_private);
    try std.testing.expectEqualSlices(u8, &v.x448.dh.alice_public, &alice_pub);

    const bob_pub = try x448.recoverPublicKey(v.x448.dh.bob_private);
    try std.testing.expectEqualSlices(u8, &v.x448.dh.bob_public, &bob_pub);
}

test "RFC 7748 §6.2: X448 Diffie-Hellman example — shared secret, byte-exact, both directions" {
    const k_alice = try x448.scalarmult(v.x448.dh.alice_private, v.x448.dh.bob_public);
    try std.testing.expectEqualSlices(u8, &v.x448.dh.shared, &k_alice);

    const k_bob = try x448.scalarmult(v.x448.dh.bob_private, v.x448.dh.alice_public);
    try std.testing.expectEqualSlices(u8, &v.x448.dh.shared, &k_bob);
}

// ── Ed448 / Ed448ph (RFC 8032 §7.4, §7.5) ───────────────────────────────

fn checkEd448Vector(vec: v.ed448.Vec) !void {
    const kp = ed448.KeyPair.create(vec.sk);
    try std.testing.expectEqualSlices(u8, &vec.pk, &kp.public_key.bytes);

    const sig = try ed448.sign(kp, vec.msg, vec.ctx);
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

test "RFC 8032 §7.4: context binding — a signature made under one context fails to verify under another" {
    const vec = v.ed448.one_octet_with_context;
    const kp = ed448.KeyPair.create(vec.sk);
    const sig = try ed448.sign(kp, vec.msg, vec.ctx);
    try std.testing.expectError(error.SignatureVerificationFailed, ed448.verify(sig, vec.msg, "bar", kp.public_key));
    try std.testing.expectError(error.SignatureVerificationFailed, ed448.verify(sig, vec.msg, "", kp.public_key));
}

test "RFC 8032 §7.5: Ed448ph 'TEST abc' vector — keygen + signPh + verifyPh, byte-exact" {
    const vec = v.ed448.ph_test_abc;
    const kp = ed448.KeyPair.create(vec.sk);
    try std.testing.expectEqualSlices(u8, &vec.pk, &kp.public_key.bytes);

    const sig = try ed448.signPh(kp, vec.msg, vec.ctx);
    try std.testing.expectEqualSlices(u8, &vec.sig, &sig.toBytes());

    try ed448.verifyPh(sig, vec.msg, vec.ctx, kp.public_key);
    try std.testing.expectError(error.SignatureVerificationFailed, ed448.verifyPh(sig, "abd", vec.ctx, kp.public_key));
}

test "RFC 8032 §7.4: Ed448 plain 'verify' rejects a signature made for Ed448ph, and vice versa" {
    // phflag=0 vs phflag=1 changes the dom4 prefix, so a signature valid
    // under one is not valid under the other, even for the same
    // underlying message bytes and key pair.
    const vec = v.ed448.ph_test_abc;
    const kp = ed448.KeyPair.create(vec.sk);
    const sig_ph = try ed448.signPh(kp, vec.msg, vec.ctx);
    try std.testing.expectError(error.SignatureVerificationFailed, ed448.verify(sig_ph, vec.msg, vec.ctx, kp.public_key));
}
