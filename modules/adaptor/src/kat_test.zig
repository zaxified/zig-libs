// SPDX-License-Identifier: MIT
//! Round-trip and byte-exact tests against `kat_vectors.zig`'s six
//! self-authored reference vectors (see that file's doc comment and
//! `../NOTICE` for how/why they were generated — no official BIP/spec
//! exists for Schnorr adaptor signatures).
//!
//! Every test below is written against `root.zig`'s FINAL public API
//! (`preSign`/`preVerify`/`adapt`/`extract`), which is fully implemented —
//! no `@panic`/TODO stub remains, and `zig build test-adaptor` runs these
//! assertions for real (see `root.zig`'s module doc comment and
//! `SPEC.md`).
//!
//! Two layers of assertion, deliberately BOTH present:
//!
//!   1. **Byte-exact KAT**: `preSign`'s `(r, s_prime, needs_negation)`
//!      output, `adapt`'s 64-byte signature, and `extract`'s recovered
//!      scalar must match `kat_vectors.zig` EXACTLY, for all six vectors.
//!      This is the strong, unambiguous oracle — it pins down not just
//!      "some self-consistent scheme" but THIS EXACT construction
//!      (domain tags, preimage ordering, parity convention).
//!   2. **Property / cross-validation harness**: independent of the
//!      byte-exact numbers, every vector's pre-signature must `preVerify`
//!      as true, `adapt`'s output must verify under PLAIN
//!      `bip340.verify` (the scheme's headline property — chains into
//!      `bip340`'s own 19 official BIP340 vectors as a transitive
//!      oracle), `extract` must recover exactly the adaptor secret that
//!      was used, and deliberate tampering (wrong `T`, wrong message,
//!      wrong pre-signature paired with a mismatched full signature) must
//!      be rejected. This layer would still catch a broken implementation
//!      even if `kat_vectors.zig`'s numbers were themselves wrong.

const std = @import("std");
const adaptor = @import("root.zig");
const bip340 = @import("bip340");
const v = @import("kat_vectors.zig");
const k256 = @import("k256");
const Secp256k1 = k256.Secp256k1;
const Scalar = Secp256k1.scalar.Scalar;

fn hexN(comptime n: usize, hex_str: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

fn testIo() std.Io.Threaded {
    return std.Io.Threaded.init(std.testing.allocator, .{});
}

// ── byte-exact KAT ──────────────────────────────────────────────────────

test "KAT: preSign byte-exact (r, s_prime, needs_negation) against all 6 vectors" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    for (v.vectors) |vec| {
        const sk = try bip340.SecretKey.fromBytes(hexN(32, vec.sk));
        const aux_rand = hexN(32, vec.aux_rand);
        const t_point = try adaptor.AdaptorPoint.fromBytes(hexN(33, vec.adaptor_point));

        const presig = try adaptor.preSign(sk, vec.msg, aux_rand, t_point, io);

        try std.testing.expectEqualSlices(u8, &hexN(32, vec.r), &presig.r);
        try std.testing.expectEqualSlices(u8, &hexN(32, vec.s_prime), &presig.s_prime);
        try std.testing.expectEqual(vec.needs_negation, presig.needs_negation);
    }
}

test "KAT: adapt byte-exact 64-byte signature against all 6 vectors" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    for (v.vectors) |vec| {
        const sk = try bip340.SecretKey.fromBytes(hexN(32, vec.sk));
        const aux_rand = hexN(32, vec.aux_rand);
        const t_point = try adaptor.AdaptorPoint.fromBytes(hexN(33, vec.adaptor_point));
        const presig = try adaptor.preSign(sk, vec.msg, aux_rand, t_point, io);

        const sig = try adaptor.adapt(presig, hexN(32, vec.t));
        try std.testing.expectEqualSlices(u8, &hexN(64, vec.sig), &sig);
    }
}

test "KAT: extract recovers the exact adaptor secret (byte-identical to vec.t) for all 6 vectors" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    for (v.vectors) |vec| {
        const sk = try bip340.SecretKey.fromBytes(hexN(32, vec.sk));
        const aux_rand = hexN(32, vec.aux_rand);
        const t_point = try adaptor.AdaptorPoint.fromBytes(hexN(33, vec.adaptor_point));
        const presig = try adaptor.preSign(sk, vec.msg, aux_rand, t_point, io);
        const sig_bytes = try adaptor.adapt(presig, hexN(32, vec.t));
        const full_sig = try bip340.Signature.fromBytes(sig_bytes);

        const recovered = try adaptor.extract(presig, full_sig, t_point);
        try std.testing.expectEqualSlices(u8, &hexN(32, vec.recovered_t), &recovered);
        try std.testing.expectEqualSlices(u8, &hexN(32, vec.t), &recovered);
    }
}

// ── round-trip property harness (independent of the byte-exact numbers) ──

test "property: preVerify accepts every vector's PUBLISHED pre-signature" {
    for (v.vectors) |vec| {
        const px = try bip340.XOnlyPublicKey.fromBytes(hexN(32, vec.px));
        const t_point = try adaptor.AdaptorPoint.fromBytes(hexN(33, vec.adaptor_point));
        const presig = adaptor.PreSignature{
            .r = hexN(32, vec.r),
            .s_prime = hexN(32, vec.s_prime),
            .needs_negation = vec.needs_negation,
        };
        try std.testing.expect(adaptor.preVerify(px, vec.msg, t_point, presig));
    }
}

test "property: full pipeline — preSign -> preVerify -> adapt -> bip340.verify -> extract, for all 6 vectors" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    for (v.vectors) |vec| {
        const sk = try bip340.SecretKey.fromBytes(hexN(32, vec.sk));
        const px = try bip340.XOnlyPublicKey.fromBytes(hexN(32, vec.px));
        const aux_rand = hexN(32, vec.aux_rand);
        const t_point = try adaptor.AdaptorPoint.fromBytes(hexN(33, vec.adaptor_point));
        const t_secret = hexN(32, vec.t);

        // PreSign -> PreVerify.
        const presig = try adaptor.preSign(sk, vec.msg, aux_rand, t_point, io);
        try std.testing.expect(adaptor.preVerify(px, vec.msg, t_point, presig));

        // Adapt -> plain bip340.verify (the scheme's headline property:
        // chains transitively into bip340's own 19 official KAT vectors
        // as the strongest available oracle for THIS half of the scheme).
        const sig_bytes = try adaptor.adapt(presig, t_secret);
        const full_sig = try bip340.Signature.fromBytes(sig_bytes);
        try std.testing.expect(bip340.verify(px, vec.msg, full_sig));

        // Extract -> the exact adaptor secret, byte-identical.
        const recovered = try adaptor.extract(presig, full_sig, t_point);
        try std.testing.expectEqualSlices(u8, &t_secret, &recovered);

        // And the recovered secret really does satisfy T = t*G (the
        // property extract's caller ultimately cares about, re-derived
        // here independently of extract's own internal check).
        const rederived_t_point = try adaptor.AdaptorPoint.fromSecret(recovered);
        try std.testing.expectEqualSlices(u8, &t_point.toBytes(), &rederived_t_point.toBytes());
    }
}

// ── negative / tamper cases ─────────────────────────────────────────────

test "property: preVerify REJECTS a pre-signature checked against the WRONG adaptor point" {
    const vec = v.vectors[0];
    const other = v.vectors[1]; // a different, unrelated adaptor point

    const px = try bip340.XOnlyPublicKey.fromBytes(hexN(32, vec.px));
    const wrong_t_point = try adaptor.AdaptorPoint.fromBytes(hexN(33, other.adaptor_point));
    const presig = adaptor.PreSignature{
        .r = hexN(32, vec.r),
        .s_prime = hexN(32, vec.s_prime),
        .needs_negation = vec.needs_negation,
    };
    try std.testing.expect(!adaptor.preVerify(px, vec.msg, wrong_t_point, presig));
}

test "property: preVerify REJECTS a pre-signature checked against the WRONG message" {
    const vec = v.vectors[0];
    const px = try bip340.XOnlyPublicKey.fromBytes(hexN(32, vec.px));
    const t_point = try adaptor.AdaptorPoint.fromBytes(hexN(33, vec.adaptor_point));
    const presig = adaptor.PreSignature{
        .r = hexN(32, vec.r),
        .s_prime = hexN(32, vec.s_prime),
        .needs_negation = vec.needs_negation,
    };
    try std.testing.expect(!adaptor.preVerify(px, "a completely different message", t_point, presig));
}

test "property: preVerify REJECTS a pre-signature with a FLIPPED needs_negation bit" {
    // The single highest-severity bug class this scheme has (see SPEC.md):
    // flipping the parity bit must be caught by preVerify, not silently
    // accepted (which would mean a real signer's honest presig and a
    // parity-corrupted one are indistinguishable to a verifier).
    const vec = v.vectors[0];
    const px = try bip340.XOnlyPublicKey.fromBytes(hexN(32, vec.px));
    const t_point = try adaptor.AdaptorPoint.fromBytes(hexN(33, vec.adaptor_point));
    const flipped = adaptor.PreSignature{
        .r = hexN(32, vec.r),
        .s_prime = hexN(32, vec.s_prime),
        .needs_negation = !vec.needs_negation,
    };
    try std.testing.expect(!adaptor.preVerify(px, vec.msg, t_point, flipped));
}

test "property: extract REJECTS a full signature whose r does not match the pre-signature's r" {
    const vec0 = v.vectors[0];
    const vec1 = v.vectors[1];
    const presig0 = adaptor.PreSignature{
        .r = hexN(32, vec0.r),
        .s_prime = hexN(32, vec0.s_prime),
        .needs_negation = vec0.needs_negation,
    };
    // vec1's full signature has a completely different r.
    const mismatched_sig = try bip340.Signature.fromBytes(hexN(64, vec1.sig));
    const t_point0 = try adaptor.AdaptorPoint.fromBytes(hexN(33, vec0.adaptor_point));
    try std.testing.expectError(error.NonceMismatch, adaptor.extract(presig0, mismatched_sig, t_point0));
}

test "property: extract REJECTS a genuine (r-matching) full signature adapted with a DIFFERENT adaptor point" {
    // Same r, but paired with the wrong T: the recovered scalar's public
    // point will not equal the given (wrong) adaptor_point.
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    const vec = v.vectors[2];
    const sk = try bip340.SecretKey.fromBytes(hexN(32, vec.sk));
    const t_point = try adaptor.AdaptorPoint.fromBytes(hexN(33, vec.adaptor_point));
    const presig = try adaptor.preSign(sk, vec.msg, hexN(32, vec.aux_rand), t_point, io);
    const sig_bytes = try adaptor.adapt(presig, hexN(32, vec.t));
    const full_sig = try bip340.Signature.fromBytes(sig_bytes);

    const wrong_t_point = try adaptor.AdaptorPoint.fromBytes(hexN(33, v.vectors[0].adaptor_point));
    try std.testing.expectError(error.AdaptorSecretMismatch, adaptor.extract(presig, full_sig, wrong_t_point));
}

test "property: adapt REJECTS an all-zero adaptor secret" {
    const vec = v.vectors[0];
    const presig = adaptor.PreSignature{
        .r = hexN(32, vec.r),
        .s_prime = hexN(32, vec.s_prime),
        .needs_negation = vec.needs_negation,
    };
    try std.testing.expectError(error.InvalidAdaptorSecret, adaptor.adapt(presig, [_]u8{0} ** 32));
}

// ── malleability: preVerify must REJECT non-canonical s_prime, not reduce it ─
//
// Every KAT vector's s_prime is already canonical (< n), so byte-exact and
// property tests above never exercise `preVerify`'s defensive `s_prime < n`
// re-check (root.zig step 3) on a value that actually fails it. This test
// builds its OWN presignature from scratch — independent of kat_vectors.zig
// — specifically so that the "true" s_prime value is small enough
// (X = 12345) that `X + n` still fits in 32 bytes: a non-canonical wire
// encoding of the SAME residue mod n. A verifier that reduces mod n instead
// of rejecting non-canonical scalars (classic ECDSA/Schnorr malleability
// class) would accept both encodings as the same signature; `preVerify` must
// accept only the canonical one.
test "property: preVerify REJECTS a non-canonical (>= n) re-encoding of an otherwise-valid s_prime" {
    const px = try bip340.XOnlyPublicKey.fromBytes(hexN(32, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"));

    // R = 42*G; lift_x(x(R)) is the canonical even-y point preVerify will
    // reconstruct — record which sign of 42 has that parity.
    const m_bytes = hexN(32, "000000000000000000000000000000000000000000000000000000000000002A");
    const m_scalar = try Scalar.fromBytes(m_bytes, .big);
    const r_point = try Secp256k1.combMulBase(m_bytes, .big);
    const r_xy = r_point.affineCoordinates();
    const r_bytes = r_xy.x.toBytes(.big);
    const r_dl = if (r_xy.y.isOdd()) m_scalar.neg() else m_scalar;

    const msg = "malleability probe";
    var challenge_hasher = bip340.hash.taggedHasher(bip340.hash.challenge_tag);
    challenge_hasher.update(&r_bytes);
    challenge_hasher.update(&px.x);
    challenge_hasher.update(msg);
    var wide = [_]u8{0} ** 48;
    wide[16..48].* = challenge_hasher.finalResult();
    const e = Scalar.fromBytes48(wide, .big);

    const x_scalar = try Scalar.fromBytes(hexN(32, "0000000000000000000000000000000000000000000000000000000000003039"), .big); // X = 12345

    // Solve t = r_dl + e - X (mod n) so that lhs = s_prime*G - e*P equals
    // rhs = R_even - T for needs_negation=false, with T = t*G.
    const t_scalar = r_dl.add(e).sub(x_scalar);
    try std.testing.expect(!t_scalar.isZero());
    const t_point = try adaptor.AdaptorPoint.fromSecret(t_scalar.toBytes(.big));

    const presig_canonical = adaptor.PreSignature{
        .r = r_bytes,
        .s_prime = x_scalar.toBytes(.big),
        .needs_negation = false,
    };
    try std.testing.expect(adaptor.preVerify(px, msg, t_point, presig_canonical));

    // Non-canonical re-encoding: X + n. n's bit length is 256 and X is tiny
    // (12345), so X + n still fits in 32 bytes — it is NOT the same 32
    // bytes as X, but reduces to the identical scalar mod n.
    const n_u256: u256 = Secp256k1.scalar.field_order;
    const noncanonical_u256: u256 = @as(u256, 12345) + n_u256;
    var noncanonical_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &noncanonical_bytes, noncanonical_u256, .big);
    try std.testing.expect(!std.mem.eql(u8, &noncanonical_bytes, &x_scalar.toBytes(.big)));

    const presig_noncanonical = adaptor.PreSignature{
        .r = r_bytes,
        .s_prime = noncanonical_bytes,
        .needs_negation = false,
    };
    try std.testing.expect(!adaptor.preVerify(px, msg, t_point, presig_noncanonical));
}
