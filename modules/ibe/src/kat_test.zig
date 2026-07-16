// SPDX-License-Identifier: MIT

//! kat_test — the KAT harness for `ibe.zig`'s `setup`/`extract`/
//! `encrypt`/`decrypt`.
//!
//! ## Why self-consistent, honestly
//!
//! `tlock` (this repo's sibling module) can byte-exact-verify against
//! a REAL ciphertext produced by drand's own Go implementation, because
//! `tlock` specializes a widely-deployed external system (drand/kyber's
//! `encrypt/ibe` package). `ibe` is this repo's OWN standalone scheme —
//! a caller-run PKG over an arbitrary identity string is not a format
//! any other library publishes test vectors for, so **no external
//! BF-IBE-over-BLS12-381 vector exists to check this module against**.
//! What follows is instead:
//!
//! 1. **Round-trip** across several identities/messages — the basic
//!    functional correctness property.
//! 2. **Pairing consistency** — the core BF-IBE identity
//!    `e(d_id, U) == Gid^r` (see `ibe.zig`'s module doc comment for the
//!    bilinearity derivation) checked DIRECTLY, not just inferred from
//!    a successful round trip.
//! 3. **Soundness/CCA** — tampered ciphertexts and wrong private keys
//!    must be rejected, never silently mis-decrypt.
//!
//! This is meaningful, not weak, because EVERY primitive `ibe` is built
//! from is ALREADY externally grounded: `bls12_381.pairing`/
//! `hash_to_curve`/`g1`/`g2` are byte-exact-KAT'd against the IETF
//! pairing-friendly-curves draft and RFC 9380 (see `bls12_381`'s own
//! `root.zig`), and the encrypt/decrypt ASSEMBLY (which hash feeds
//! which XOR, the FO consistency check, the `fp12Pow` construction) is
//! the exact shape `tlock`'s sibling module proved byte-exact against
//! a genuine drand-Go-produced ciphertext (see `tlock`'s `NOTICE`/
//! `SPEC.md`). What `ibe` adds on top — its own DSTs/hash tags and no
//! drand-style cube (see `ibe.zig`'s "No drand-style cube" section) —
//! is exactly the surface these self-consistency tests exercise.

const std = @import("std");
const bls12_381 = @import("bls12_381");
const ibe = @import("ibe.zig");
const ciphersuite = @import("ciphersuite.zig");

const g1 = bls12_381.g1;
const g2 = bls12_381.g2;
const pairing = bls12_381.pairing;
const Fr = bls12_381.Fr;

fn testIo() std.Io.Threaded {
    return std.Io.Threaded.init(std.testing.allocator, .{});
}

// ── 1. Round-trip ─────────────────────────────────────────────────────

test "round trip: setup -> extract -> encrypt -> decrypt recovers the message, several identities/messages" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const kp = ibe.setup(io);

    const cases = [_]struct { id: []const u8, msg: u8, sig: u8 }{
        .{ .id = "alice@example.com", .msg = 0x01, .sig = 0x11 },
        .{ .id = "bob@example.com", .msg = 0x02, .sig = 0x22 },
        .{ .id = "device-serial-0042", .msg = 0xff, .sig = 0xee },
        .{ .id = "", .msg = 0x00, .sig = 0x99 }, // empty identity is a valid byte string
        .{ .id = "policy:finance/quarter-close/2026Q3", .msg = 0x7a, .sig = 0x3c },
    };

    for (cases) |c| {
        const d_id = ibe.extract(kp.msk, c.id);
        const message = [_]u8{c.msg} ** ibe.block_bytes;
        const sigma = [_]u8{c.sig} ** ibe.block_bytes;

        const ct = ibe.encrypt(kp.mpk, c.id, message, sigma);
        const recovered = try ibe.decrypt(d_id, ct);
        try std.testing.expectEqualSlices(u8, &message, &recovered);
    }
}

test "round trip: sigma sourced from randomSigma (production entropy path)" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const kp = ibe.setup(io);

    const id = "alice@example.com";
    const d_id = ibe.extract(kp.msk, id);
    const message = [_]u8{0x5a} ** ibe.block_bytes;
    const sigma = ciphersuite.randomSigma(io);

    const ct = ibe.encrypt(kp.mpk, id, message, sigma);
    const recovered = try ibe.decrypt(d_id, ct);
    try std.testing.expectEqualSlices(u8, &message, &recovered);
}

test "encrypt is deterministic given fixed (mpk, id, message, sigma)" {
    var threaded = testIo();
    defer threaded.deinit();
    const kp = ibe.setup(threaded.io());

    const id = "alice@example.com";
    const message = [_]u8{0x33} ** ibe.block_bytes;
    const sigma = [_]u8{0x44} ** ibe.block_bytes;

    const ct1 = ibe.encrypt(kp.mpk, id, message, sigma);
    const ct2 = ibe.encrypt(kp.mpk, id, message, sigma);
    try std.testing.expectEqualSlices(u8, &ct1.toBytes(), &ct2.toBytes());
}

// ── 2. Pairing consistency (the core BF-IBE identity, checked directly) ─

test "pairing consistency: e(d_id, U) == fp12Pow(Gid, r) directly, on a known case" {
    var threaded = testIo();
    defer threaded.deinit();
    const kp = ibe.setup(threaded.io());

    const id = "alice@example.com";
    const d_id = ibe.extract(kp.msk, id);
    const message = [_]u8{0x12} ** ibe.block_bytes;
    const sigma = [_]u8{0x34} ** ibe.block_bytes;

    // Reproduce encrypt's internal Gid/r/U exactly, to check the core
    // identity independent of the XOR/hash masking layer.
    const qid = ciphersuite.h1(id);
    const gid = pairing.pairing(qid, kp.mpk);
    const r = ciphersuite.h3(&sigma, &message);
    const u = g2.Jacobian.fromAffine(g2.Affine.generator).scalarMul(r).toAffine();

    const lhs = pairing.pairing(d_id, u); // decrypt's side: one pairing call
    const rhs = ibe.testing_fp12Pow(gid, r); // encrypt's side: explicit Gt exponentiation
    try std.testing.expect(lhs.eql(rhs));

    // Sanity: this identity is exactly what encrypt/decrypt rely on —
    // confirm it also equals the ciphertext's actual gid_r by running
    // the real encrypt/decrypt and checking the recovered message.
    const ct = ibe.encrypt(kp.mpk, id, message, sigma);
    try std.testing.expect(ct.u.x.eql(u.x));
    const recovered = try ibe.decrypt(d_id, ct);
    try std.testing.expectEqualSlices(u8, &message, &recovered);
}

test "pairing consistency: e(d_id, G2gen) == e(H1(id), mpk) — the Extract correctness identity" {
    // The identity a caller crossing a trust boundary would check to
    // confirm a received d_id genuinely came from the claimed PKG for
    // the claimed identity (analogous to tlock's round-signature
    // verification against the beacon public key).
    var threaded = testIo();
    defer threaded.deinit();
    const kp = ibe.setup(threaded.io());

    const id = "alice@example.com";
    const d_id = ibe.extract(kp.msk, id);
    const qid = ciphersuite.h1(id);

    // e(d_id, G2gen) == e(qid, mpk)  <=>  e(-d_id, G2gen) * e(qid, mpk) == 1
    const neg_d_id = g1.Jacobian.fromAffine(d_id).negate().toAffine();
    try std.testing.expect(pairing.pairingCheck(&.{
        .{ .p = neg_d_id, .q = g2.Affine.generator },
        .{ .p = qid, .q = kp.mpk },
    }));
}

// ── 3. fp12Pow KAT (bilinearity cross-check) ─────────────────────────

test "fp12Pow matches pairing bilinearity: e(P,Q)^r == e(rP,Q) (KAT, module-exposed helper)" {
    var r_bytes = [_]u8{0} ** 32;
    r_bytes[20] = 0x9c;
    r_bytes[27] = 0x02;
    r_bytes[31] = 0x11;
    const r = try Fr.fromBytes(r_bytes);

    const gt = pairing.pairing(g1.Affine.generator, g2.Affine.generator);
    const lhs = ibe.testing_fp12Pow(gt, r);

    const rp = g1.Jacobian.fromAffine(g1.Affine.generator).scalarMul(r).toAffine();
    const rhs = pairing.pairing(rp, g2.Affine.generator);
    try std.testing.expect(lhs.eql(rhs));
}

// ── 4. Soundness / CCA rejection ─────────────────────────────────────

test "soundness: tampered U is rejected by the FO check" {
    var threaded = testIo();
    defer threaded.deinit();
    const kp = ibe.setup(threaded.io());
    const id = "alice@example.com";
    const d_id = ibe.extract(kp.msk, id);
    const message = [_]u8{0x01} ** ibe.block_bytes;
    const sigma = [_]u8{0x02} ** ibe.block_bytes;

    var ct = ibe.encrypt(kp.mpk, id, message, sigma);
    // Corrupt U by using a different point (the generator scaled by a
    // different, unrelated scalar) — still a valid G2 encoding, so this
    // exercises the FO check rather than the codec's format rejection.
    ct.u = g2.Jacobian.fromAffine(g2.Affine.generator).scalarMul(Fr.one.add(Fr.one)).toAffine();

    try std.testing.expectError(error.FoCheckFailed, ibe.decrypt(d_id, ct));
}

test "soundness: tampered V is rejected by the FO check" {
    var threaded = testIo();
    defer threaded.deinit();
    const kp = ibe.setup(threaded.io());
    const id = "alice@example.com";
    const d_id = ibe.extract(kp.msk, id);
    const message = [_]u8{0x01} ** ibe.block_bytes;
    const sigma = [_]u8{0x02} ** ibe.block_bytes;

    var ct = ibe.encrypt(kp.mpk, id, message, sigma);
    ct.v[0] ^= 0xff;

    try std.testing.expectError(error.FoCheckFailed, ibe.decrypt(d_id, ct));
}

test "soundness: tampered W is rejected by the FO check" {
    var threaded = testIo();
    defer threaded.deinit();
    const kp = ibe.setup(threaded.io());
    const id = "alice@example.com";
    const d_id = ibe.extract(kp.msk, id);
    const message = [_]u8{0x01} ** ibe.block_bytes;
    const sigma = [_]u8{0x02} ** ibe.block_bytes;

    var ct = ibe.encrypt(kp.mpk, id, message, sigma);
    ct.w[0] ^= 0xff;

    try std.testing.expectError(error.FoCheckFailed, ibe.decrypt(d_id, ct));
}

test "soundness: a random G1 point as d_id is rejected (not the identity's real key)" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const kp = ibe.setup(io);
    const id = "alice@example.com";
    const message = [_]u8{0x01} ** ibe.block_bytes;
    const sigma = [_]u8{0x02} ** ibe.block_bytes;
    const ct = ibe.encrypt(kp.mpk, id, message, sigma);

    // A random scalar multiple of H1(id) that is NOT msk*H1(id).
    const wrong_scalar = Fr.random(io);
    const qid = ciphersuite.h1(id);
    const wrong_d_id = g1.Jacobian.fromAffine(qid).scalarMul(wrong_scalar).toAffine();

    try std.testing.expectError(error.FoCheckFailed, ibe.decrypt(wrong_d_id, ct));
}

test "soundness: extract for id_A cannot decrypt a ciphertext encrypted to id_B" {
    var threaded = testIo();
    defer threaded.deinit();
    const kp = ibe.setup(threaded.io());

    const id_a = "alice@example.com";
    const id_b = "bob@example.com";
    const d_id_a = ibe.extract(kp.msk, id_a);

    const message = [_]u8{0x77} ** ibe.block_bytes;
    const sigma = [_]u8{0x88} ** ibe.block_bytes;
    const ct_for_b = ibe.encrypt(kp.mpk, id_b, message, sigma);

    try std.testing.expectError(error.FoCheckFailed, ibe.decrypt(d_id_a, ct_for_b));
}

test "soundness: a different PKG's msk (different setup) cannot extract a working key" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const kp_real = ibe.setup(io);
    const kp_other = ibe.setup(io);

    const id = "alice@example.com";
    const message = [_]u8{0x55} ** ibe.block_bytes;
    const sigma = [_]u8{0x66} ** ibe.block_bytes;
    const ct = ibe.encrypt(kp_real.mpk, id, message, sigma);

    const d_id_wrong_pkg = ibe.extract(kp_other.msk, id);
    try std.testing.expectError(error.FoCheckFailed, ibe.decrypt(d_id_wrong_pkg, ct));
}
