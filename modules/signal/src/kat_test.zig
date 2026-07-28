// SPDX-License-Identifier: MIT
//! Tests for `x3dh.zig` + `xeddsa.zig`. Two groups (the ordering used to
//! matter when group 2 `@panic`ed against the XEdDSA stubs; it is kept
//! for readability now that everything passes):
//!
//!   1. **X3DH agreement + codec.** Exercises `x3dh.initiateUnverified`/
//!      `x3dh.respond` (the DH+HKDF composition, deliberately not routed
//!      through `xeddsa.verify` so the agreement math is tested in
//!      isolation) and the `PreKeyBundle`/`InitialMessage` byte codecs.
//!   2. **XEdDSA + the fail-closed X3DH entry points.** Round-trip,
//!      tamper rejection, fail-closed garbage-input handling, the
//!      libsignal known-answer vector (see below), an independent
//!      cross-check of `xeddsa.sign` against `std.crypto.sign.Ed25519`'s
//!      own verifier, and the full `generateSignedPreKey` -> `initiate`
//!      -> `respond` path.
//!
//! **Test-vector provenance:** the XEdDSA spec text publishes no numeric
//! vector. The known-answer vector below is libsignal's own
//! (`test_curve25519_signature` in libsignal-protocol-c's
//! `tests/test_curve25519.c`; the same bytes appear in
//! libsignal-protocol-java) — numeric facts only, no code taken; see
//! `../NOTICE`. **EXTERNAL ANCHOR**, exercised against BOTH variants this
//! module ships (`xeddsa.zig`'s module doc comment): the module's public
//! `xeddsa.libsignal.verify` must ACCEPT this vector byte-exactly with
//! all 64 single-byte tampers rejected — a positive anchor for the
//! deployed-libsignal variant, proving the Montgomery->Edwards recovery
//! and the whole `sB - hA` equation against a real libsignal-produced
//! signature the module did not itself create — and the spec-pure
//! top-level `xeddsa.verify` must REJECT the very same bytes (the
//! variants are deliberately incompatible for sign-1 keys, and this
//! vector's key IS sign-1 — exactly the case the spec variant cannot
//! handle). Before this pass, only a test-local reimplementation of the
//! variant (`libsignalVariantVerify`, since removed) accepted the vector;
//! the shipped `xeddsa.libsignal.verify` is now exercised directly.

const std = @import("std");
const x3dh = @import("x3dh.zig");
const xeddsa = @import("xeddsa.zig");
const X25519 = std.crypto.dh.X25519;

fn testIo() std.Io.Threaded {
    return std.Io.Threaded.init(std.testing.allocator, .{});
}

fn dummySignature() xeddsa.Signature {
    var sig: xeddsa.Signature = undefined;
    for (&sig, 0..) |*b, i| b.* = @intCast(i);
    return sig;
}

// ═══════════════════════════════════════════════════════════════════════
// 1. X3DH agreement + codec — REAL, must pass today.
// ═══════════════════════════════════════════════════════════════════════

test "X3DH: initiateUnverified <-> respond agree on SK/AD, WITH a one-time prekey" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    const alice_ik = X25519.KeyPair.generate(io);
    const bob_ik = X25519.KeyPair.generate(io);
    const bob_spk_kp = X25519.KeyPair.generate(io);
    const bob_opk_kp = X25519.KeyPair.generate(io);

    const bob_spk = x3dh.SignedPreKey{ .key_pair = bob_spk_kp, .signature = dummySignature(), .id = 7 };
    const bob_opk = x3dh.OneTimePreKey{ .key_pair = bob_opk_kp, .id = 42 };

    const bundle = x3dh.PreKeyBundle{
        .identity_key = bob_ik.public_key,
        .signed_prekey = bob_spk.key_pair.public_key,
        .signed_prekey_id = bob_spk.id,
        .signed_prekey_signature = bob_spk.signature,
        .one_time_prekey = bob_opk.key_pair.public_key,
        .one_time_prekey_id = bob_opk.id,
    };

    const alice_out = try x3dh.initiateUnverified(std.testing.allocator, alice_ik, bundle, "hello bob", io);
    defer alice_out.message.deinit(std.testing.allocator);

    const bob_agreement = try x3dh.respond(bob_ik, bob_spk, bob_opk, alice_out.message);

    try std.testing.expectEqualSlices(u8, &alice_out.agreement.shared_secret, &bob_agreement.shared_secret);
    try std.testing.expectEqualSlices(u8, &alice_out.agreement.associated_data, &bob_agreement.associated_data);
    try std.testing.expectEqualSlices(u8, "hello bob", alice_out.message.ciphertext);
}

test "X3DH: initiateUnverified <-> respond agree on SK/AD, WITHOUT a one-time prekey (bundle exhausted)" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    const alice_ik = X25519.KeyPair.generate(io);
    const bob_ik = X25519.KeyPair.generate(io);
    const bob_spk_kp = X25519.KeyPair.generate(io);

    const bob_spk = x3dh.SignedPreKey{ .key_pair = bob_spk_kp, .signature = dummySignature(), .id = 1 };

    const bundle = x3dh.PreKeyBundle{
        .identity_key = bob_ik.public_key,
        .signed_prekey = bob_spk.key_pair.public_key,
        .signed_prekey_id = bob_spk.id,
        .signed_prekey_signature = bob_spk.signature,
        .one_time_prekey = null,
        .one_time_prekey_id = null,
    };

    const alice_out = try x3dh.initiateUnverified(std.testing.allocator, alice_ik, bundle, "no opk today", io);
    defer alice_out.message.deinit(std.testing.allocator);

    try std.testing.expect(alice_out.message.one_time_prekey_id == null);

    const bob_agreement = try x3dh.respond(bob_ik, bob_spk, null, alice_out.message);

    try std.testing.expectEqualSlices(u8, &alice_out.agreement.shared_secret, &bob_agreement.shared_secret);
    try std.testing.expectEqualSlices(u8, &alice_out.agreement.associated_data, &bob_agreement.associated_data);
}

test "X3DH: a DIFFERENT bob_ik makes the agreement disagree (sanity check the test isn't vacuous)" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    const alice_ik = X25519.KeyPair.generate(io);
    const bob_ik = X25519.KeyPair.generate(io);
    const wrong_ik = X25519.KeyPair.generate(io);
    const bob_spk_kp = X25519.KeyPair.generate(io);
    const bob_spk = x3dh.SignedPreKey{ .key_pair = bob_spk_kp, .signature = dummySignature(), .id = 1 };

    const bundle = x3dh.PreKeyBundle{
        .identity_key = bob_ik.public_key,
        .signed_prekey = bob_spk.key_pair.public_key,
        .signed_prekey_id = bob_spk.id,
        .signed_prekey_signature = bob_spk.signature,
    };

    const alice_out = try x3dh.initiateUnverified(std.testing.allocator, alice_ik, bundle, "msg", io);
    defer alice_out.message.deinit(std.testing.allocator);

    // wrong_ik responds instead of the real bob_ik -> DH2 differs -> SK differs.
    const wrong_agreement = try x3dh.respond(wrong_ik, bob_spk, null, alice_out.message);
    try std.testing.expect(!std.mem.eql(u8, &alice_out.agreement.shared_secret, &wrong_agreement.shared_secret));
}

test "codec: PreKeyBundle round-trips through toBytes/fromBytes, WITH an OPK" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    const ik = X25519.KeyPair.generate(io);
    const spk = X25519.KeyPair.generate(io);
    const opk = X25519.KeyPair.generate(io);

    const bundle = x3dh.PreKeyBundle{
        .identity_key = ik.public_key,
        .signed_prekey = spk.public_key,
        .signed_prekey_id = 99,
        .signed_prekey_signature = dummySignature(),
        .one_time_prekey = opk.public_key,
        .one_time_prekey_id = 123,
    };

    const bytes = bundle.toBytes();
    const decoded = try x3dh.PreKeyBundle.fromBytes(bytes);
    try std.testing.expectEqualSlices(u8, &bundle.identity_key, &decoded.identity_key);
    try std.testing.expectEqualSlices(u8, &bundle.signed_prekey, &decoded.signed_prekey);
    try std.testing.expectEqual(bundle.signed_prekey_id, decoded.signed_prekey_id);
    try std.testing.expectEqualSlices(u8, &bundle.signed_prekey_signature, &decoded.signed_prekey_signature);
    try std.testing.expectEqualSlices(u8, &bundle.one_time_prekey.?, &decoded.one_time_prekey.?);
    try std.testing.expectEqual(bundle.one_time_prekey_id.?, decoded.one_time_prekey_id.?);
}

test "codec: PreKeyBundle round-trips through toBytes/fromBytes, WITHOUT an OPK" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    const ik = X25519.KeyPair.generate(io);
    const spk = X25519.KeyPair.generate(io);

    const bundle = x3dh.PreKeyBundle{
        .identity_key = ik.public_key,
        .signed_prekey = spk.public_key,
        .signed_prekey_id = 5,
        .signed_prekey_signature = dummySignature(),
    };

    const bytes = bundle.toBytes();
    const decoded = try x3dh.PreKeyBundle.fromBytes(bytes);
    try std.testing.expect(decoded.one_time_prekey == null);
    try std.testing.expect(decoded.one_time_prekey_id == null);
    try std.testing.expectEqual(bundle.signed_prekey_id, decoded.signed_prekey_id);
}

test "codec: PreKeyBundle.fromBytes rejects a has_opk flag byte other than 0/1" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const ik = X25519.KeyPair.generate(io);
    const spk = X25519.KeyPair.generate(io);
    const bundle = x3dh.PreKeyBundle{
        .identity_key = ik.public_key,
        .signed_prekey = spk.public_key,
        .signed_prekey_id = 1,
        .signed_prekey_signature = dummySignature(),
    };
    var bytes = bundle.toBytes();
    bytes[key_len_flag_offset()] = 2; // corrupt the has_opk byte
    try std.testing.expectError(error.InvalidPreKeyBundle, x3dh.PreKeyBundle.fromBytes(bytes));
}

fn key_len_flag_offset() usize {
    // identity_key(32) + signed_prekey(32) + signed_prekey_id(4) + signature(64)
    return 32 + 32 + 4 + 64;
}

test "codec: InitialMessage round-trips through toBytes/fromBytes, WITH a one-time prekey id" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const ik = X25519.KeyPair.generate(io);
    const ek = X25519.KeyPair.generate(io);

    const msg = x3dh.InitialMessage{
        .identity_key = ik.public_key,
        .ephemeral_key = ek.public_key,
        .signed_prekey_id = 3,
        .one_time_prekey_id = 77,
        .ciphertext = "the actual encrypted first message",
    };

    const bytes = try msg.toBytes(std.testing.allocator);
    defer std.testing.allocator.free(bytes);

    const decoded = try x3dh.InitialMessage.fromBytes(std.testing.allocator, bytes);
    defer decoded.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, &msg.identity_key, &decoded.identity_key);
    try std.testing.expectEqualSlices(u8, &msg.ephemeral_key, &decoded.ephemeral_key);
    try std.testing.expectEqual(msg.signed_prekey_id, decoded.signed_prekey_id);
    try std.testing.expectEqual(msg.one_time_prekey_id.?, decoded.one_time_prekey_id.?);
    try std.testing.expectEqualStrings(msg.ciphertext, decoded.ciphertext);
}

test "codec: InitialMessage round-trips through toBytes/fromBytes, WITHOUT a one-time prekey id, empty ciphertext" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const ik = X25519.KeyPair.generate(io);
    const ek = X25519.KeyPair.generate(io);

    const msg = x3dh.InitialMessage{
        .identity_key = ik.public_key,
        .ephemeral_key = ek.public_key,
        .signed_prekey_id = 3,
        .one_time_prekey_id = null,
        .ciphertext = "",
    };

    const bytes = try msg.toBytes(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqual(x3dh.InitialMessage.header_length, bytes.len);

    const decoded = try x3dh.InitialMessage.fromBytes(std.testing.allocator, bytes);
    defer decoded.deinit(std.testing.allocator);
    try std.testing.expect(decoded.one_time_prekey_id == null);
    try std.testing.expectEqualStrings("", decoded.ciphertext);
}

test "codec: InitialMessage.fromBytes rejects a truncated header" {
    const short = [_]u8{0} ** 10;
    try std.testing.expectError(error.InvalidInitialMessage, x3dh.InitialMessage.fromBytes(std.testing.allocator, &short));
}

test "codec: InitialMessage.fromBytes rejects a ciphertext-length mismatch" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const ik = X25519.KeyPair.generate(io);
    const ek = X25519.KeyPair.generate(io);
    const msg = x3dh.InitialMessage{
        .identity_key = ik.public_key,
        .ephemeral_key = ek.public_key,
        .signed_prekey_id = 1,
        .one_time_prekey_id = null,
        .ciphertext = "abc",
    };
    const bytes = try msg.toBytes(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    // Truncate the trailing ciphertext byte -> declared length no longer matches.
    try std.testing.expectError(error.InvalidInitialMessage, x3dh.InitialMessage.fromBytes(std.testing.allocator, bytes[0 .. bytes.len - 1]));
}

// ═══════════════════════════════════════════════════════════════════════
// 2. XEdDSA + the fail-closed X3DH entry points.
// ═══════════════════════════════════════════════════════════════════════

test "XEdDSA: sign -> verify round-trip" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    const kp = X25519.KeyPair.generate(io);
    var z: xeddsa.RandomData = undefined;
    io.random(&z);

    const msg = "an X3DH signed prekey, encoded";
    const sig = xeddsa.sign(kp.secret_key, msg, z);
    try std.testing.expect(xeddsa.verify(kp.public_key, msg, sig));
}

test "XEdDSA: verify REJECTS a tampered message" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    const kp = X25519.KeyPair.generate(io);
    var z: xeddsa.RandomData = undefined;
    io.random(&z);

    const sig = xeddsa.sign(kp.secret_key, "original message", z);
    try std.testing.expect(!xeddsa.verify(kp.public_key, "tampered message", sig));
}

test "XEdDSA: verify REJECTS a tampered signature" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    const kp = X25519.KeyPair.generate(io);
    var z: xeddsa.RandomData = undefined;
    io.random(&z);

    const msg = "a message";
    var sig = xeddsa.sign(kp.secret_key, msg, z);
    sig[0] ^= 0x01;
    try std.testing.expect(!xeddsa.verify(kp.public_key, msg, sig));
}

// ── libsignal known-answer vector ───────────────────────────────────────
//
// From libsignal-protocol-c's tests/test_curve25519.c
// (test_curve25519_signature); the identical bytes ship in
// libsignal-protocol-java. The 0x05 "DJB key type" prefix byte libsignal
// puts on serialized public keys is STRIPPED from the key (libsignal's
// own decode does the same before verifying) but KEPT on the message —
// libsignal signs the full 33-byte serialized ephemeral key, prefix
// included.

const ls_alice_priv: [32]u8 = .{
    0xc0, 0x97, 0x24, 0x84, 0x12, 0xe5, 0x8b, 0xf0,
    0x5d, 0xf4, 0x87, 0x96, 0x82, 0x05, 0x13, 0x27,
    0x94, 0x17, 0x8e, 0x36, 0x76, 0x37, 0xf5, 0x81,
    0x8f, 0x81, 0xe0, 0xe6, 0xce, 0x73, 0xe8, 0x65,
};
const ls_alice_pub: [32]u8 = .{
    0xab, 0x7e, 0x71, 0x7d, 0x4a, 0x16, 0x3b, 0x7d,
    0x9a, 0x1d, 0x80, 0x71, 0xdf, 0xe9, 0xdc, 0xf8,
    0xcd, 0xcd, 0x1c, 0xea, 0x33, 0x39, 0xb6, 0x35,
    0x6b, 0xe8, 0x4d, 0x88, 0x7e, 0x32, 0x2c, 0x64,
};
const ls_message: [33]u8 = .{
    0x05, 0xed, 0xce, 0x9d, 0x9c, 0x41, 0x5c, 0xa7,
    0x8c, 0xb7, 0x25, 0x2e, 0x72, 0xc2, 0xc4, 0xa5,
    0x54, 0xd3, 0xeb, 0x29, 0x48, 0x5a, 0x0e, 0x1d,
    0x50, 0x31, 0x18, 0xd1, 0xa8, 0x2d, 0x99, 0xfb,
    0x4a,
};
const ls_signature: [64]u8 = .{
    0x5d, 0xe8, 0x8c, 0xa9, 0xa8, 0x9b, 0x4a, 0x11,
    0x5d, 0xa7, 0x91, 0x09, 0xc6, 0x7c, 0x9c, 0x74,
    0x64, 0xa3, 0xe4, 0x18, 0x02, 0x74, 0xf1, 0xcb,
    0x8c, 0x63, 0xc2, 0x98, 0x4e, 0x28, 0x6d, 0xfb,
    0xed, 0xe8, 0x2d, 0xeb, 0x9d, 0xcd, 0x9f, 0xae,
    0x0b, 0xfb, 0xb8, 0x21, 0x56, 0x9b, 0x3d, 0x90,
    0x01, 0xbd, 0x81, 0x30, 0xcd, 0x11, 0xd4, 0x86,
    0xce, 0xf0, 0x47, 0xbd, 0x60, 0xb8, 0x6e, 0x88,
};

test "XEdDSA KAT: the libsignal vector's keypair is a genuine X25519 pair (vector transcription sanity)" {
    const derived = try X25519.recoverPublicKey(ls_alice_priv);
    try std.testing.expectEqualSlices(u8, &ls_alice_pub, &derived);
}

test "XEdDSA KAT: libsignal test_curve25519_signature accepted byte-exactly by xeddsa.libsignal.verify; every 1-byte tamper rejected" {
    // EXTERNAL ANCHOR (libsignal-protocol-c's own KAT — see this file's
    // module doc comment and ../NOTICE), exercised against the module's
    // SHIPPED deployed-libsignal-variant verifier, not a test-local
    // reimplementation. This vector's key is a sign-1 key (sig[63]'s top
    // bit is set), which is exactly the case the spec variant cannot
    // handle — so this is also the required positive anchor for a
    // natural-sign-1 key.
    try std.testing.expectEqual(@as(u8, 1), ls_signature[63] >> 7);
    try std.testing.expect(xeddsa.libsignal.verify(ls_alice_pub, &ls_message, ls_signature));

    // Teeth check: same tamper sweep libsignal's own C test runs — flip
    // the low bit of each of the 64 signature bytes in turn, confirm
    // EVERY one is rejected, then move to the next (each iteration starts
    // from a fresh untampered copy, so the vector itself is never left
    // corrupted for the accept-check above, which already ran first).
    var i: usize = 0;
    while (i < ls_signature.len) : (i += 1) {
        var tampered = ls_signature;
        tampered[i] ^= 0x01;
        try std.testing.expect(!xeddsa.libsignal.verify(ls_alice_pub, &ls_message, tampered));
    }
}

test "XEdDSA KAT: the spec-pure verify deliberately REJECTS libsignal's sign-bit-in-s variant signature" {
    // sig[63]'s smuggled sign bit makes `s` >= 2^255 under the spec's
    // reading -> non-canonical scalar -> fail-closed false. This pins the
    // documented variant incompatibility (xeddsa.zig module doc comment);
    // do NOT "fix" verify to accept it.
    try std.testing.expect(!xeddsa.verify(ls_alice_pub, &ls_message, ls_signature));
}

test "XEdDSA KAT: this module's spec-variant sign round-trips over the libsignal vector's own (sign-1) key" {
    // Self round-trip, NOT an external anchor: `z` here is this test's own
    // choice, not libsignal's, so it cannot reproduce `ls_signature`'s
    // exact bytes (a different nonce yields a different, equally valid,
    // signature) — it only checks this module's own sign/verify agree.
    var z: xeddsa.RandomData = undefined;
    for (&z, 0..) |*b, i| b.* = @intCast(i);
    const sig = xeddsa.sign(ls_alice_priv, &ls_message, z);
    // Spec variant: s is canonical, top bit never smuggled.
    try std.testing.expectEqual(@as(u8, 0), sig[63] >> 7);
    try std.testing.expect(xeddsa.verify(ls_alice_pub, &ls_message, sig));
    // And the deployed-variant verifier accepts it too: a spec signature
    // is the sign_bit == 0 special case of the variant.
    try std.testing.expect(xeddsa.libsignal.verify(ls_alice_pub, &ls_message, sig));
}

test "XEdDSA KAT: xeddsa.libsignal.sign self-round-trips over the libsignal vector's own (sign-1) key" {
    // Self round-trip, NOT an external anchor (same nonce caveat as
    // above): confirms the module's OWN deployed-variant signer produces
    // a signature its OWN deployed-variant verifier accepts, and that it
    // reproduces the vector's sign-1 bit (a property of the KEY, not the
    // nonce) even though the signature bytes themselves necessarily
    // differ from `ls_signature`.
    var z: xeddsa.RandomData = undefined;
    for (&z, 0..) |*b, i| b.* = @intCast(255 - i);
    const sig = xeddsa.libsignal.sign(ls_alice_priv, &ls_message, z);
    try std.testing.expectEqual(@as(u8, 1), sig[63] >> 7);
    try std.testing.expect(xeddsa.libsignal.verify(ls_alice_pub, &ls_message, sig));
    // A sign-1 deployed-variant signature must NOT verify under the
    // spec-pure verifier (non-canonical s, same reasoning as the raw
    // libsignal vector above).
    try std.testing.expect(!xeddsa.verify(ls_alice_pub, &ls_message, sig));
}

// ── independent cross-check via std's Ed25519 verifier ─────────────────
//
// XEdDSA's domain separation lives ONLY in the nonce hash (`hash1`, a
// signer-side secret derivation the verifier never recomputes); the
// CHALLENGE hash `SHA-512(R || A || M)` is byte-identical to Ed25519's.
// A spec-pure XEdDSA signature is therefore a valid Ed25519 signature
// under the recovered sign-0 `A` as an Ed25519 public key — verifying
// that with `std.crypto.sign.Ed25519`'s own (independently implemented)
// verifier cross-checks this module's `sign` and Montgomery->Edwards
// recovery against code this module shares nothing with.

test "XEdDSA cross-check: signatures verify under std.crypto.sign.Ed25519 with the recovered sign-0 A" {
    const Ed25519 = std.crypto.sign.Ed25519;
    var z: xeddsa.RandomData = undefined;
    for (&z, 0..) |*b, i| b.* = @intCast(255 - i);

    // The libsignal vector's key (a known sign-1 key) plus deterministic
    // seeds — several keys, both sign-bit branches statistically covered.
    var seeds: [5][32]u8 = undefined;
    seeds[0] = ls_alice_priv;
    var i: u8 = 1;
    while (i < seeds.len) : (i += 1) {
        var wide: [64]u8 = undefined;
        std.crypto.hash.sha2.Sha512.hash(&[_]u8{ 'e', 'd', 'x', 'c', 'h', 'k', i }, &wide, .{});
        seeds[i] = wide[0..32].*;
    }

    for (seeds) |seed| {
        const msg = "cross-checked against std's own Ed25519 verifier";
        const sig = xeddsa.sign(seed, msg, z);
        const mont_pub = try X25519.recoverPublicKey(seed);
        try std.testing.expect(xeddsa.verify(mont_pub, msg, sig));

        const a = try xeddsa.edwardsFromMontgomery(mont_pub);
        const ed_pub = try Ed25519.PublicKey.fromBytes(a.toBytes());
        const ed_sig = Ed25519.Signature.fromBytes(sig);
        try ed_sig.verify(msg, ed_pub); // std must ACCEPT — errors fail the test
    }
}

// ── fail-closed on garbage (never panic on attacker input) ─────────────

test "XEdDSA: verify fails closed (false, no panic) on malformed keys and signatures" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    const kp = X25519.KeyPair.generate(io);
    var z: xeddsa.RandomData = undefined;
    io.random(&z);
    const msg = "fail closed";
    const good = xeddsa.sign(kp.secret_key, msg, z);
    try std.testing.expect(xeddsa.verify(kp.public_key, msg, good));

    // All-zero public key: maps to the order-2 point (0, -1) -> rejected.
    try std.testing.expect(!xeddsa.verify([_]u8{0} ** 32, msg, good));
    // Non-canonical public key (top bit set).
    var noncanon_pub = kp.public_key;
    noncanon_pub[31] |= 0x80;
    try std.testing.expect(!xeddsa.verify(noncanon_pub, msg, good));
    // u = p - 1 (the birational map's pole).
    var pole = [_]u8{0xFF} ** 32;
    pole[0] = 0xEC;
    pole[31] = 0x7F;
    try std.testing.expect(!xeddsa.verify(pole, msg, good));
    // Non-canonical s (>= L).
    var bad_s = good;
    bad_s[63] |= 0x20; // pushes s >= 2^253 > L
    try std.testing.expect(!xeddsa.verify(kp.public_key, msg, bad_s));
    // All-zero signature.
    try std.testing.expect(!xeddsa.verify(kp.public_key, msg, [_]u8{0} ** 64));
    // All-0xFF signature (non-canonical everything).
    try std.testing.expect(!xeddsa.verify(kp.public_key, msg, [_]u8{0xFF} ** 64));
}

// ── the fail-closed X3DH entry points, end-to-end ───────────────────────

test "X3DH end-to-end: generateSignedPreKey -> initiate (verifies XEdDSA) -> respond agree on SK/AD" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    const alice_ik = X25519.KeyPair.generate(io);
    const bob_ik = X25519.KeyPair.generate(io);
    var z: xeddsa.RandomData = undefined;
    io.random(&z);
    const bob_spk = x3dh.generateSignedPreKey(bob_ik, 7, z, io);
    const bob_opk = x3dh.OneTimePreKey{ .key_pair = X25519.KeyPair.generate(io), .id = 42 };

    const bundle = x3dh.PreKeyBundle{
        .identity_key = bob_ik.public_key,
        .signed_prekey = bob_spk.key_pair.public_key,
        .signed_prekey_id = bob_spk.id,
        .signed_prekey_signature = bob_spk.signature,
        .one_time_prekey = bob_opk.key_pair.public_key,
        .one_time_prekey_id = bob_opk.id,
    };

    const alice_out = try x3dh.initiate(std.testing.allocator, alice_ik, bundle, "first ratchet msg", io);
    defer alice_out.message.deinit(std.testing.allocator);

    const bob_agreement = try x3dh.respond(bob_ik, bob_spk, bob_opk, alice_out.message);
    try std.testing.expectEqualSlices(u8, &alice_out.agreement.shared_secret, &bob_agreement.shared_secret);
    try std.testing.expectEqualSlices(u8, &alice_out.agreement.associated_data, &bob_agreement.associated_data);
}

test "X3DH.initiate fail-closes on a tampered signed-prekey signature AND on a substituted signed prekey" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    const alice_ik = X25519.KeyPair.generate(io);
    const bob_ik = X25519.KeyPair.generate(io);
    var z: xeddsa.RandomData = undefined;
    io.random(&z);
    const bob_spk = x3dh.generateSignedPreKey(bob_ik, 1, z, io);

    var bundle = x3dh.PreKeyBundle{
        .identity_key = bob_ik.public_key,
        .signed_prekey = bob_spk.key_pair.public_key,
        .signed_prekey_id = bob_spk.id,
        .signed_prekey_signature = bob_spk.signature,
    };

    // Tampered signature bit.
    bundle.signed_prekey_signature[0] ^= 0x01;
    try std.testing.expectError(error.SignedPreKeyVerificationFailed, x3dh.initiate(std.testing.allocator, alice_ik, bundle, "msg", io));
    bundle.signed_prekey_signature[0] ^= 0x01;

    // Substituted signed prekey (the MITM move initiate exists to stop).
    const mitm_spk = X25519.KeyPair.generate(io);
    bundle.signed_prekey = mitm_spk.public_key;
    try std.testing.expectError(error.SignedPreKeyVerificationFailed, x3dh.initiate(std.testing.allocator, alice_ik, bundle, "msg", io));
}
