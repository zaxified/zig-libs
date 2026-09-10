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
const fuzzseed = @import("testkit").fuzz;

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

// Regression (audit A1 `adaptor` F2): `extract`'s DL check must reject a
// forged pair whose recovered scalar has the SAME x-coordinate as `T` but is
// NOT `t` itself — i.e. `y_used = n - t`, whose point is `-T` (same x,
// opposite y). A check weakened to compare only `x(implied)` against
// `x(T)` — instead of the full point equality `extract` actually uses
// (`implied.equivalent(t_point)`) — would wrongly ACCEPT this. Constructed
// exactly as the audit describes: choose `full_sig.s = presig.s_prime +
// (n - t)`, so `y = s - s_prime = n - t`, and (since this vector's
// `needs_negation` may itself flip the sign again) the crafted `s` is chosen
// so the FINAL `y_used` — after `extract`'s own conditional negation — comes
// out to `n - t`, not `t`.
test "audit F2: extract REJECTS a forged (r-matching) signature whose recovered scalar is n-t (same x as T, wrong y)" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();

    const vec = v.vectors[2];
    const sk = try bip340.SecretKey.fromBytes(hexN(32, vec.sk));
    const t_point = try adaptor.AdaptorPoint.fromBytes(hexN(33, vec.adaptor_point));
    const presig = try adaptor.preSign(sk, vec.msg, hexN(32, vec.aux_rand), t_point, io);

    // Genuine adapt first, to confirm the baseline is honest and n != t.
    const genuine_sig = try adaptor.adapt(presig, hexN(32, vec.t));
    const genuine_full = try bip340.Signature.fromBytes(genuine_sig);
    const genuine_recovered = try adaptor.extract(presig, genuine_full, t_point);
    try std.testing.expectEqualSlices(u8, &hexN(32, vec.t), &genuine_recovered);

    // Forge: want extract's `y_used` (AFTER its own conditional negation by
    // `presig.needs_negation`) to equal `n - t`. `extract` computes
    // `y_used = if (needs_negation) (s - s_prime).neg() else (s - s_prime)`.
    // So pick `s - s_prime` accordingly: if `!needs_negation`, want
    // `s - s_prime = n - t` directly; if `needs_negation`, want
    // `(s - s_prime).neg() = n - t`, i.e. `s - s_prime = t`.
    const s_prime = Scalar.fromBytes(presig.s_prime, .big) catch unreachable;
    const t_scalar = Scalar.fromBytes(hexN(32, vec.t), .big) catch unreachable;
    const delta = if (presig.needs_negation) t_scalar else t_scalar.neg();
    const forged_s = s_prime.add(delta);
    const forged_sig = bip340.Signature{ .r = presig.r, .s = forged_s.toBytes(.big) };

    // Sanity: the forged pair really does share `r` (extract's step 1 must
    // not be what rejects it — the DL check must be).
    try std.testing.expectEqualSlices(u8, &presig.r, &forged_sig.r);
    try std.testing.expectError(error.AdaptorSecretMismatch, adaptor.extract(presig, forged_sig, t_point));
}

// Pin (audit A1 `adaptor` F6, no code change — see `SPEC.md` Threat model for
// why: this is algebraic, inherent to `rhs = R_even ± T`, not a bug). A
// pre-signature verifies under `(T, needs_negation)` iff it ALSO verifies
// under `(-T, !needs_negation)` — the two are the SAME statement viewed from
// either sign. Pinned so a future change to `preVerify`'s equation is a
// deliberate, tested decision, not a silent narrowing or widening of this.
test "audit F6 (pin, not a bug): a pre-signature verifies under EITHER (T, flag) or (-T, !flag), never both flags for one T" {
    const vec = v.vectors[0];
    const px = try bip340.XOnlyPublicKey.fromBytes(hexN(32, vec.px));
    const t_point = try adaptor.AdaptorPoint.fromBytes(hexN(33, vec.adaptor_point));
    const t_real = try t_point.point();
    const neg_t_point = try adaptor.AdaptorPoint.fromBytes(t_real.neg().toCompressedSec1());

    const presig = adaptor.PreSignature{
        .r = hexN(32, vec.r),
        .s_prime = hexN(32, vec.s_prime),
        .needs_negation = vec.needs_negation,
    };
    const flipped = adaptor.PreSignature{
        .r = presig.r,
        .s_prime = presig.s_prime,
        .needs_negation = !presig.needs_negation,
    };

    try std.testing.expect(adaptor.preVerify(px, vec.msg, t_point, presig)); // (T, flag)
    try std.testing.expect(!adaptor.preVerify(px, vec.msg, neg_t_point, presig)); // (-T, flag)
    try std.testing.expect(!adaptor.preVerify(px, vec.msg, t_point, flipped)); // (T, !flag)
    try std.testing.expect(adaptor.preVerify(px, vec.msg, neg_t_point, flipped)); // (-T, !flag)
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

// ── fuzz: preVerify on hostile pre-signature bytes ──────────────────────
//
// `preVerify` is the untrusted-input entry point: a counterparty hands the
// presigner's own public key a `(PreSignature, AdaptorPoint)` pair over the
// wire and it must accept/reject via `PreSignatureError`/`bool` alone —
// never panic, never read out of bounds — for ANY 65 bytes, not just the
// six self-authored vectors. `pubkey`/`msg`/`adaptor_point` are pinned to
// vector 0 (a real, valid triple) and only the `PreSignature` wire bytes
// are mutated, biased toward "nearly valid" by starting from vector 0's
// real `r || s_prime || flag` encoding and flipping a handful of bytes —
// pure random 65-byte strings almost never survive `Fe`/`Scalar`'s
// canonical-range checks far enough to reach the group-equation math this
// exists to exercise.
fn fuzzPreVerify(_: void, smith: *std.testing.Smith) !void {
    const vec0 = v.vectors[0];
    const px = try bip340.XOnlyPublicKey.fromBytes(hexN(32, vec0.px));
    const t_point = try adaptor.AdaptorPoint.fromBytes(hexN(33, vec0.adaptor_point));

    var bytes: [65]u8 = undefined;
    bytes[0..32].* = hexN(32, vec0.r);
    bytes[32..64].* = hexN(32, vec0.s_prime);
    bytes[64] = @intFromBool(vec0.needs_negation);

    // ⚠ ONE byte-first draw, read as a flip script. This used to open with
    // `n_flips = smith.valueRangeAtMost(u8, 0, 6)`, and a ranged `Smith` draw
    // reads eight octets as a little-endian `u64` and returns the range
    // MINIMUM unless that whole word already lies inside the range — so with
    // no corpus, on the single `in = ""` round the lane runs, `n_flips` was 0
    // and the harness verified vector 0's PRISTINE pre-signature, unmodified,
    // for ever. The word "corrupted" in this target's own name had never been
    // true of a single input it ran. Measured 2026-09-07: 1 input, 0 flips,
    // 0 refusals from `fromBytes`.
    var script_buf: [32]u8 = undefined;
    const n: usize = smith.slice(&script_buf);
    applyFlips(script_buf[0..n], &bytes);

    const presig = adaptor.PreSignature.fromBytes(bytes) catch return;
    _ = adaptor.preVerify(px, vec0.msg, t_point, presig);
}

/// Octet 0 is the flip count (0..6), then two octets per flip: an offset into
/// the 65-octet encoding and the byte to write.
fn applyFlips(script: []const u8, bytes: []u8) void {
    if (script.len == 0) return;
    const n_flips = script[0] % 7;
    var i: usize = 0;
    while (i < n_flips) : (i += 1) {
        const at = 1 + i * 2;
        if (at + 1 >= script.len) return;
        bytes[script[at] % bytes.len] = script[at + 1];
    }
}

/// The three fields of the wire encoding sit at fixed offsets — `r` at 0..32,
/// `s_prime` at 32..64, the negation flag at 64 — so a seed names which one it
/// damages.
const presig_seeds = [_][]const u8{
    fuzzseed.seed(""), // the pristine vector: exactly what this target ran, for ever
    fuzzseed.seed("\x00"), // the same, said explicitly
    fuzzseed.seed("\x01\x00\xff"), // ⭐ the first octet of `r`
    fuzzseed.seed("\x01\x1f\x00"), // the last octet of `r`
    fuzzseed.seed("\x01\x20\xff"), // ⭐ the first octet of `s_prime`
    fuzzseed.seed("\x01\x3f\x01"), // the last octet of `s_prime`
    fuzzseed.seed("\x01\x40\x01"), // ⭐ the negation flag flipped to 1
    fuzzseed.seed("\x01\x40\x02"), // ⭐ the flag set to a value that is neither 0 nor 1
    fuzzseed.seed("\x01\x40\xff"), // the flag at the far end of its octet
    fuzzseed.seed("\x02\x00\xff\x20\xff"), // both scalars damaged at once
    fuzzseed.seed("\x06" ++ "\x00\xff\x08\xff\x10\xff\x20\xff\x28\xff\x40\x01"), // the maximum flip count
    fuzzseed.seed("\xff" ++ "\x00\x00\x20\x00"), // a flip count past the ceiling, wrapped
    fuzzseed.seed("\x02" ++ "\x00\xff\x01\xff\x02\xff\x03\xff"), // ⭐ more flip payload than the count consumes
};

test "fuzz: preVerify never panics on corrupted pre-signature bytes" {
    try std.testing.fuzz({}, fuzzPreVerify, .{ .corpus = &presig_seeds });
}

test "corpus: every seed reaches preVerify or its decoder, and both verdicts are pinned" {
    // ⭐ `accepted > 0` would have read 100% on the OLD harness, because the
    // one input it ran was the untouched vector and it verifies. The numbers
    // that say the corpus damages anything are the `fromBytes` refusals and
    // the pre-signatures that decode but do NOT verify — neither of which the
    // pristine encoding can produce.
    const vec0 = v.vectors[0];
    const px = try bip340.XOnlyPublicKey.fromBytes(hexN(32, vec0.px));
    const t_point = try adaptor.AdaptorPoint.fromBytes(hexN(33, vec0.adaptor_point));

    var decode_refusals: usize = 0;
    var verified: usize = 0;
    var rejected: usize = 0;
    var distinct: usize = 0;
    for (presig_seeds) |sd| {
        var pristine: [65]u8 = undefined;
        pristine[0..32].* = hexN(32, vec0.r);
        pristine[32..64].* = hexN(32, vec0.s_prime);
        pristine[64] = @intFromBool(vec0.needs_negation);
        var bytes = pristine;

        var smith: std.testing.Smith = .{ .in = sd };
        var script_buf: [32]u8 = undefined;
        const n: usize = smith.slice(&script_buf);
        applyFlips(script_buf[0..n], &bytes);
        if (!std.mem.eql(u8, &bytes, &pristine)) distinct += 1;

        const presig = adaptor.PreSignature.fromBytes(bytes) catch {
            decode_refusals += 1;
            continue;
        };
        if (adaptor.preVerify(px, vec0.msg, t_point, presig)) verified += 1 else rejected += 1;
    }
    // Measured 2026-09-07. Before: 0 damaged encodings, 0 decode refusals, 0
    // rejections — one input, and it verified.
    try std.testing.expectEqual(@as(usize, 11), distinct);
    try std.testing.expectEqual(@as(usize, 2), decode_refusals);
    try std.testing.expectEqual(@as(usize, 2), verified);
    try std.testing.expectEqual(@as(usize, 9), rejected);
}
