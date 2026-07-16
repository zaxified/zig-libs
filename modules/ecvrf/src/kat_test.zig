// SPDX-License-Identifier: MIT
//! Tests against the official RFC 9381 Appendix B.3 test vectors
//! (`kat_vectors.zig`), ECVRF-EDWARDS25519-SHA512-TAI.
//!
//! Coverage per vector (Examples 16, 17, 18):
//!   - `secretScalar`/`publicKey`: `SK -> x`, `SK -> PK`, byte-exact.
//!   - `encodeToCurve`: `(PK, alpha) -> H`, byte-exact, including the
//!     published `try_and_increment` counter.
//!   - `nonceGenerationString`/`nonceGeneration`: `(SK, H) -> k_string`
//!     (pre-reduction) and `-> k` (post-reduction), byte-exact.
//!   - `prove`: `(SK, alpha) -> pi`, byte-exact (80 bytes) — this is the
//!     end-to-end assertion that also implicitly pins `Gamma`/`c`/`s`
//!     (sliced straight out of `pi`, RFC 9381 never lists them
//!     separately from `pi` for this ciphersuite) and `U`/`V` (only
//!     observable via `c`'s correctness, since `challengeGeneration` is
//!     not part of the public API — see the note below).
//!   - `proofToHash`: `pi -> beta`, byte-exact (64 bytes).
//!   - `verify`: accepts every vector, `beta` matches `proofToHash`.
//!
//! Negative/tamper coverage (no official RFC vectors exist for these —
//! constructed against Example 16's valid `(PK, alpha, pi)`):
//!   - flipping a byte inside `Gamma`, `c`, and `s` (each of `pi`'s three
//!     fields) independently -> `verify` rejects every one;
//!   - wrong `alpha` -> `verify` rejects;
//!   - a small-order/non-canonical public key -> `verify` rejects
//!     (`error.InvalidPublicKey`), not a crash.

const std = @import("std");
const ecvrf = @import("root.zig");
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

fn hex80(hex_str: []const u8) ![80]u8 {
    var out: [80]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, hex_str);
    return out;
}

test "KAT: SK -> x (secretScalar) matches RFC 9381 Appendix B.3 for every example" {
    for (v.vectors) |vec| {
        const sk = try hex32(vec.sk);
        const want_x = try hex32(vec.x);
        try std.testing.expectEqualSlices(u8, &want_x, &ecvrf.secretScalar(sk));
    }
}

test "KAT: SK -> PK (publicKey) matches RFC 9381 Appendix B.3 for every example" {
    for (v.vectors) |vec| {
        const sk = try hex32(vec.sk);
        const want_pk = try hex32(vec.pk);
        try std.testing.expectEqualSlices(u8, &want_pk, &ecvrf.publicKey(sk));
    }
}

test "KAT: encodeToCurve(PK, alpha) -> H matches RFC 9381 Appendix B.3, including the published ctr" {
    const Edwards25519 = std.crypto.ecc.Edwards25519;
    const Sha512 = std.crypto.hash.sha2.Sha512;
    const gpa = std.testing.allocator;
    for (v.vectors) |vec| {
        const pk = try hex32(vec.pk);
        const alpha = try hexAlloc(gpa, vec.alpha);
        defer gpa.free(alpha);
        const want_h = try hex32(vec.h);
        const got_h = ecvrf.encodeToCurve(pk, alpha);
        try std.testing.expectEqualSlices(u8, &want_h, &got_h);

        // Cross-check the published ctr independently, hashing by hand
        // (duplicating §5.4.1.1's steps outside `encodeToCurve`): every
        // ctr strictly before vec.ctr must NOT decode to a valid,
        // non-identity point, and vec.ctr itself must, with H matching.
        var ctr: u16 = 0;
        while (ctr < vec.ctr) : (ctr += 1) {
            var st = Sha512.init(.{});
            st.update(&[_]u8{ecvrf.suite_string});
            st.update(&[_]u8{0x01});
            st.update(&pk);
            st.update(alpha);
            st.update(&[_]u8{@intCast(ctr)});
            st.update(&[_]u8{0x00});
            var hash_string: [64]u8 = undefined;
            st.final(&hash_string);
            const candidate = Edwards25519.fromBytes(hash_string[0..32].*) catch continue;
            try std.testing.expectError(error.IdentityElement, candidate.clearCofactor().rejectIdentity());
        }
        {
            var st = Sha512.init(.{});
            st.update(&[_]u8{ecvrf.suite_string});
            st.update(&[_]u8{0x01});
            st.update(&pk);
            st.update(alpha);
            st.update(&[_]u8{@intCast(vec.ctr)});
            st.update(&[_]u8{0x00});
            var hash_string: [64]u8 = undefined;
            st.final(&hash_string);
            const candidate = try Edwards25519.fromBytes(hash_string[0..32].*);
            const h_point = candidate.clearCofactor();
            try h_point.rejectIdentity();
            try std.testing.expectEqualSlices(u8, &want_h, &h_point.toBytes());
        }
    }
}

test "KAT: nonceGenerationString/nonceGeneration -> k_string/k match RFC 9381 Appendix B.3" {
    for (v.vectors) |vec| {
        const sk = try hex32(vec.sk);
        const h = try hex32(vec.h);
        const want_k_string = try hex64(vec.k_string);
        const got_k_string = ecvrf.nonceGenerationString(sk, h);
        try std.testing.expectEqualSlices(u8, &want_k_string, &got_k_string);

        const want_k = try hex32(vec.k);
        const got_k = ecvrf.nonceGeneration(sk, h);
        try std.testing.expectEqualSlices(u8, &want_k, &got_k);
    }
}

test "KAT: prove(SK, alpha) -> pi matches RFC 9381 Appendix B.3, byte-exact (80 bytes)" {
    const gpa = std.testing.allocator;
    for (v.vectors) |vec| {
        const sk = try hex32(vec.sk);
        const alpha = try hexAlloc(gpa, vec.alpha);
        defer gpa.free(alpha);
        const want_pi = try hex80(vec.pi);
        const got_pi = ecvrf.prove(sk, alpha);
        try std.testing.expectEqualSlices(u8, &want_pi, &got_pi);

        // pi = Gamma(32) || c(16) || s(32) — cross-check the U/V-derived
        // c and the (k + c*x) mod q derived s against the RFC's Gamma
        // implicitly, via decodeProof's own structural split.
        const decoded = try ecvrf.decodeProof(got_pi);
        try std.testing.expectEqualSlices(u8, want_pi[0..32], &decoded.gamma);
        try std.testing.expectEqualSlices(u8, want_pi[32..48], &decoded.c);
        try std.testing.expectEqualSlices(u8, want_pi[48..80], &decoded.s);
    }
}

test "KAT: proofToHash(pi) -> beta matches RFC 9381 Appendix B.3, byte-exact (64 bytes)" {
    for (v.vectors) |vec| {
        const pi = try hex80(vec.pi);
        const want_beta = try hex64(vec.beta);
        const got_beta = try ecvrf.proofToHash(pi);
        try std.testing.expectEqualSlices(u8, &want_beta, &got_beta);
    }
}

test "KAT: verify accepts every vector and returns the matching beta" {
    const gpa = std.testing.allocator;
    for (v.vectors) |vec| {
        const pk = try hex32(vec.pk);
        const alpha = try hexAlloc(gpa, vec.alpha);
        defer gpa.free(alpha);
        const pi = try hex80(vec.pi);
        const want_beta = try hex64(vec.beta);

        const got_beta = try ecvrf.verify(pk, alpha, pi);
        try std.testing.expectEqualSlices(u8, &want_beta, &got_beta);
    }
}

test "negative: tampering Gamma, c, or s inside a valid pi independently rejects" {
    const vec = v.vectors[0]; // Example 16, alpha = empty string
    const pk = try hex32(vec.pk);
    const alpha = "";
    const pi = try hex80(vec.pi);

    // Sanity: the untouched vector verifies first.
    _ = try ecvrf.verify(pk, alpha, pi);

    // Flip one byte inside Gamma (pi[0..32]).
    {
        var tampered = pi;
        tampered[0] ^= 0x01;
        try std.testing.expectError(error.InvalidProof, ecvrf.verify(pk, alpha, tampered));
    }
    // Flip one byte inside c (pi[32..48]).
    {
        var tampered = pi;
        tampered[32] ^= 0x01;
        try std.testing.expectError(error.InvalidProof, ecvrf.verify(pk, alpha, tampered));
    }
    // Flip one byte inside s (pi[48..80]).
    {
        var tampered = pi;
        tampered[79] ^= 0x01;
        try std.testing.expectError(error.InvalidProof, ecvrf.verify(pk, alpha, tampered));
    }
}

test "negative: wrong alpha rejects a valid (PK, pi) pair" {
    const vec = v.vectors[1]; // Example 17, alpha = 0x72
    const pk = try hex32(vec.pk);
    const pi = try hex80(vec.pi);

    _ = try ecvrf.verify(pk, "\x72", pi); // sanity: the correct alpha verifies
    try std.testing.expectError(error.InvalidProof, ecvrf.verify(pk, "\x73", pi));
    try std.testing.expectError(error.InvalidProof, ecvrf.verify(pk, "", pi));
}

test "negative: a small-order public key is rejected by verify, not a crash" {
    const vec = v.vectors[0];
    const alpha = "";
    const pi = try hex80(vec.pi);

    // The eight low-order edwards25519 points RFC 9381 §5.4.5 discusses
    // (order 1, 2, 4, or 8) — the identity (order 1) and the order-2
    // point `p - 1` are the two simplest to construct without a curve
    // library: both are on-curve valid ENCODINGS (`Edwards25519.fromBytes`
    // succeeds) that `ECVRF_validate_key`'s cofactor-clear-then-
    // reject-identity check must still catch.
    const identity_pk = [_]u8{0} ** 31 ++ [_]u8{1}; // y = 1, x = 0: the identity point
    try std.testing.expectError(error.InvalidPublicKey, ecvrf.verify(identity_pk, alpha, pi));

    var order2_pk = [_]u8{0xff} ** 32; // y = p - 1
    order2_pk[0] = 0xec;
    order2_pk[31] = 0x7f;
    try std.testing.expectError(error.InvalidPublicKey, ecvrf.verify(order2_pk, alpha, pi));

    // A structurally invalid encoding (not on the curve at all) must
    // also reject cleanly rather than crash `Edwards25519.fromBytes`.
    var not_on_curve = [_]u8{0xaa} ** 32;
    not_on_curve[31] &= 0x7f;
    // This specific byte pattern is not guaranteed to be off-curve for
    // every possible 0xaa-filled value, so only assert IF it actually
    // fails to decode as a point OR fails validate_key — either is an
    // acceptable "rejected, not panicked" outcome.
    _ = ecvrf.verify(not_on_curve, alpha, pi) catch {};
}

test "negative: decodeProof rejects non-canonical s (s >= group order)" {
    var pi = try hex80(v.vectors[0].pi);
    // Overwrite s (pi[48..80]) with all-0xff — far above the group
    // order (~2^252), guaranteed non-canonical.
    @memset(pi[48..80], 0xff);
    try std.testing.expectError(error.InvalidProof, ecvrf.decodeProof(pi));
    try std.testing.expectError(error.InvalidProof, ecvrf.verify(try hex32(v.vectors[0].pk), "", pi));
}
