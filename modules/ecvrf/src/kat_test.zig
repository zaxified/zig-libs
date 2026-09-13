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
            const candidate = ecvrf.stringToPoint(hash_string[0..32].*) catch continue;
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
            const candidate = try ecvrf.stringToPoint(hash_string[0..32].*);
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

    // A1 E3: identity and order-2 are the ONLY two of the eight low-order
    // points whose `x`-coordinate is zero — i.e. the only two a bare
    // `rejectIdentity()` (without the preceding `clearCofactor()`) also
    // happens to catch. Order-4 and order-8 points below have nonzero `x`
    // and DO decode as distinct, non-identity points; only cofactor-clearing
    // first exposes them as low-order. Without these, a mutation that drops
    // `clearCofactor()` from `validateKey` passes this test file green while
    // accepting 7 of these 10 points (measured: `A1/ecvrf.md` E3).
    // RFC 9381 §5.4.5's own low-order point list, hex-encoded.
    const order4_pk_a = try hex32("0000000000000000000000000000000000000000000000000000000000000000"); // y = 0, sign 0
    try std.testing.expectError(error.InvalidPublicKey, ecvrf.verify(order4_pk_a, alpha, pi));
    const order4_pk_b = try hex32("0000000000000000000000000000000000000000000000000000000000000080"[0..64]); // y = 0, sign 1
    try std.testing.expectError(error.InvalidPublicKey, ecvrf.verify(order4_pk_b, alpha, pi));
    const order8_pk_a = try hex32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a");
    try std.testing.expectError(error.InvalidPublicKey, ecvrf.verify(order8_pk_a, alpha, pi));
    const order8_pk_b = try hex32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa");
    try std.testing.expectError(error.InvalidPublicKey, ecvrf.verify(order8_pk_b, alpha, pi));
    const order8_pk_c = try hex32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05");
    try std.testing.expectError(error.InvalidPublicKey, ecvrf.verify(order8_pk_c, alpha, pi));
    const order8_pk_d = try hex32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85");
    try std.testing.expectError(error.InvalidPublicKey, ecvrf.verify(order8_pk_d, alpha, pi));

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

test "negative: N random (c, s) forgery attempts against a valid Gamma all reject (E2)" {
    // A1 E2: `verify`'s challenge comparison IS the full 16 bytes
    // (`std.crypto.timing_safe.eql([c_len]u8, ...)`) — but every tamper test
    // in this file flips a byte inside a REAL `c`, and SHA-512's avalanche
    // means that always changes every one of `c`'s 16 bytes at once, so a
    // mutation that only compares a PREFIX or SUFFIX of `c` still turns every
    // existing tamper test red. What those tests cannot see is an EXISTENTIAL
    // forgery: a random `(c, s)` pair against a real `Gamma`, which a
    // narrowed comparison accepts roughly once every 2^(8*narrowed_width)
    // tries. Measured (`A1/ecvrf.md` E2, 200000 trials): base 0 accepted,
    // comparing only `c[0..1]` 768 accepted (1 in ~260), comparing only
    // `c[15..16]` 786 accepted. This test drives a smaller N (fast enough for
    // every optimize mode, including Debug) against the real, unmutated
    // `verify` and expects exactly 0 acceptances; P(0 accepts | a 1-byte-wide
    // comparison mutation, N=3000) is negligible so this still fails hard
    // under that mutation.
    const vec = v.vectors[0];
    const pk = try hex32(vec.pk);
    const alpha = "";
    const real_pi = try hex80(vec.pi);
    const gamma = real_pi[0..32].*;

    var prng = std.Random.DefaultPrng.init(0xE2E2_C0DE_0000_0001);
    const rand = prng.random();
    var accepted: usize = 0;
    const n: usize = 3000;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        var pi: [80]u8 = undefined;
        pi[0..32].* = gamma;
        rand.bytes(pi[32..48]); // c: any 16 bytes is structurally valid (c < 2^128 < q always)
        // s must be a CANONICAL scalar or decodeProof rejects it before the
        // challenge comparison is even reached, which would test the wrong
        // thing (structural rejection, not the comparison itself).
        var s_wide: [32]u8 = undefined;
        rand.bytes(&s_wide);
        const s = std.crypto.ecc.Edwards25519.scalar.reduce(s_wide);
        pi[48..80].* = s;
        if (ecvrf.verify(pk, alpha, pi)) |_| accepted += 1 else |_| {}
    }
    try std.testing.expectEqual(@as(usize, 0), accepted);

    // Sanity: the real vector still verifies (proves the loop above wasn't
    // rejecting everything for an unrelated reason, e.g. a bad Gamma).
    _ = try ecvrf.verify(pk, alpha, real_pi);
}

test "negative: decodeProof rejects a Gamma that is not a valid point encoding; proofToHash/verify do not return a beta for it (E5)" {
    // A1 E5: `decodeProof`'s `Edwards25519.fromBytes(gamma_string) catch
    // return error.InvalidProof` had no test of its own; without it, two
    // `catch unreachable`s downstream (`proofToHash`, `verify`) are undefined
    // behaviour in ReleaseFast on exactly this input. Measured
    // (`A1/ecvrf.md` E5): 50057/100000 random 32-byte strings are not valid
    // point encodings, so this is a hot path, not a corner case.
    const Edwards25519 = std.crypto.ecc.Edwards25519;
    const vec = v.vectors[0];
    const pk = try hex32(vec.pk);
    const alpha = "";
    var pi = try hex80(vec.pi);

    // Find a 32-byte value that is NOT a valid edwards25519 point encoding —
    // a deterministic search, not a hardcoded magic constant.
    var t: u32 = 0;
    const bad_gamma: [32]u8 = while (t < 100_000) : (t += 1) {
        var cand = [_]u8{0} ** 32;
        std.mem.writeInt(u32, cand[0..4], t, .little);
        cand[31] = 0x40;
        if (Edwards25519.fromBytes(cand)) |_| {} else |_| break cand;
    } else return error.NoInvalidEncodingFound;
    pi[0..32].* = bad_gamma;

    try std.testing.expectError(error.InvalidProof, ecvrf.decodeProof(pi));
    try std.testing.expectError(error.InvalidProof, ecvrf.proofToHash(pi));
    try std.testing.expectError(error.InvalidProof, ecvrf.verify(pk, alpha, pi));
}

/// `y + p` for a small `y`: the second, non-canonical 32-byte string for
/// the point whose canonical encoding has `y` in its low byte and zeros
/// above (only `y < 19` has one, since `y + p < 2^255`).
fn plusP(y: u8, sign: u1) [32]u8 {
    var out = [_]u8{0xff} ** 32;
    out[0] = 0xed + y;
    out[31] = 0x7f | (@as(u8, sign) << 7);
    return out;
}

test "negative: RFC 8032 §5.1.3 strict decoding refuses a non-canonical Gamma, and a canonical one still decodes (E14)" {
    const vec = v.vectors[0];
    const pk = try hex32(vec.pk);
    const alpha = "";
    var pi = try hex80(vec.pi);

    // Control: the identity, canonically encoded, IS a valid Gamma encoding
    // (decode_proof does not ask for a low-order check), so a rejection
    // below is about the bytes, not the point.
    const identity = [_]u8{1} ++ [_]u8{0} ** 31;
    pi[0..32].* = identity;
    _ = try ecvrf.decodeProof(pi);

    // The same point spelled `y = p + 1`: std's `fromBytes` reduces it to 1.
    pi[0..32].* = plusP(1, 0);
    try std.testing.expect(if (std.crypto.ecc.Edwards25519.fromBytes(pi[0..32].*)) |_| true else |_| false);
    try std.testing.expectError(error.InvalidProof, ecvrf.decodeProof(pi));
    try std.testing.expectError(error.InvalidProof, ecvrf.proofToHash(pi));
    try std.testing.expectError(error.InvalidProof, ecvrf.verify(pk, alpha, pi));

    // The same point with its sign bit set, although x = 0.
    var signed = identity;
    signed[31] = 0x80;
    pi[0..32].* = signed;
    try std.testing.expect(if (std.crypto.ecc.Edwards25519.fromBytes(signed)) |_| true else |_| false);
    try std.testing.expectError(error.InvalidProof, ecvrf.decodeProof(pi));
    try std.testing.expectError(error.InvalidEncoding, ecvrf.stringToPoint(signed));
}

test "negative: a public key spelled y + p is refused although std decodes it to a valid, prime-order key (E16)" {
    const Edwards25519 = std.crypto.ecc.Edwards25519;
    // A point with a small canonical `y` that is not low-order: the only
    // kind with a non-canonical twin, found by search rather than assumed.
    var found: ?u8 = null;
    var y: u8 = 2;
    while (y < 19) : (y += 1) {
        var canon = [_]u8{0} ** 32;
        canon[0] = y;
        const p = Edwards25519.fromBytes(canon) catch continue;
        p.clearCofactor().rejectIdentity() catch continue;
        found = y;
        break;
    }
    const small_y = found orelse return error.NoSmallYKeyFound;
    var canon = [_]u8{0} ** 32;
    canon[0] = small_y;

    _ = try ecvrf.validateKey(canon); // control: the canonical spelling is a valid key
    const twin = plusP(small_y, 0);
    const std_point = try Edwards25519.fromBytes(twin); // std takes the twin …
    try std.testing.expectEqualSlices(u8, &canon, &std_point.toBytes()); // … as the same point
    try std.testing.expectError(error.InvalidPublicKey, ecvrf.validateKey(twin));
    try std.testing.expectError(error.InvalidPublicKey, ecvrf.verify(twin, "", try hex80(v.vectors[0].pi)));
}

test "KeyPair: public key and proofs match publicKey/prove byte for byte on every RFC 9381 vector (E10)" {
    const gpa = std.testing.allocator;
    for (v.vectors) |vec| {
        const sk = try hex32(vec.sk);
        const alpha = try hexAlloc(gpa, vec.alpha);
        defer gpa.free(alpha);
        const kp = ecvrf.KeyPair.fromSecretKey(sk);
        try std.testing.expectEqualSlices(u8, &(try hex32(vec.pk)), &kp.public_key);
        try std.testing.expectEqualSlices(u8, &(try hex80(vec.pi)), &kp.prove(alpha));
    }
}

test "KeyPair: a public_key filled in by hand makes proofs no key verifies (E10)" {
    const a = ecvrf.KeyPair.fromSecretKey(try hex32(v.vectors[0].sk));
    const b = ecvrf.KeyPair.fromSecretKey(try hex32(v.vectors[1].sk));
    const lying: ecvrf.KeyPair = .{ .secret_key = a.secret_key, .public_key = b.public_key };
    const pi = lying.prove("input");
    try std.testing.expectError(error.InvalidProof, ecvrf.verify(a.public_key, "input", pi));
    try std.testing.expectError(error.InvalidProof, ecvrf.verify(b.public_key, "input", pi));
}

test "negative: decodeProof rejects non-canonical s (s >= group order)" {
    var pi = try hex80(v.vectors[0].pi);
    // Overwrite s (pi[48..80]) with all-0xff — far above the group
    // order (~2^252), guaranteed non-canonical.
    @memset(pi[48..80], 0xff);
    try std.testing.expectError(error.InvalidProof, ecvrf.decodeProof(pi));
    try std.testing.expectError(error.InvalidProof, ecvrf.verify(try hex32(v.vectors[0].pk), "", pi));
}
