// SPDX-License-Identifier: MIT

//! kat_test — the KAT harness for `ibe.zig`'s `setup`/`extract`/
//! `encrypt`/`decrypt`.
//!
//! ## What is anchored externally, and what cannot be
//!
//! This module's scheme is `ibe.Scheme(ciphersuite)`: an ASSEMBLY (which
//! hash output feeds which XOR, the FO consistency check, the `fp12Pow`
//! construction, where `U`/`V`/`W` land in the wire encoding) driven by
//! a set of PARAMETERS (this module's own hash tags, its own
//! hash-to-curve DST, its 32-byte block width, and the canonical
//! un-cubed `Gt` representation). The two are anchored very differently,
//! and section 5 below exists to keep that distinction honest:
//!
//! - **The assembly IS externally anchored** (section 5). `ibe.Scheme`
//!   instantiated with DRAND's parameters — drand's DSTs and tags, its
//!   16-byte blocks, and the `gt -> gt³` representation adapter — must
//!   reproduce a genuine ciphertext produced by drand's own Go `tle`
//!   CLI, byte for byte. That fixture is a foreign artifact (frozen in
//!   the sibling `tlock` module, `tlock/NOTICE` for its provenance
//!   chain): it can fail regardless of what anyone here believed while
//!   writing `ibe.zig`. It is THIS module's code doing the work — the
//!   same `encrypt`/`decrypt`/`fp12Pow`/`Ciphertext` bodies the default
//!   instantiation uses, not a copy of them and not a re-derivation of
//!   them in another language, which would be a sibling and would prove
//!   nothing.
//! - **The parameters CANNOT be externally anchored, by construction.**
//!   RFC 9380 §3.1 *requires* every application to choose its own
//!   domain-separation tag, so there is no external value for
//!   `dst_g1`/`h{2,3,4}_tag` to match — an `ibe` DST that agreed with
//!   somebody else's would be a bug, not an anchor. Likewise the
//!   no-cube decision (`ibe.zig`'s "No drand-style cube"): `tlock`'s
//!   cube exists solely to match `kilic/bls12-381`'s
//!   final-exponentiation convention, and with no external byte target
//!   any self-consistent choice is correct. These two choices are
//!   pinned by sections 1-4's self-consistency tests and by nothing
//!   else, and that is the end state, not a to-do.
//!
//! Sections 1-4 (round-trip, pairing consistency, `fp12Pow` laws,
//! soundness/CCA) remain what they were and are still the only check on
//! the parameter choices; section 5 is what stops a systematic assembly
//! error from hiding behind them.
//!
//! Everything underneath is anchored independently: `bls12_381.pairing`/
//! `hash_to_curve`/`g1`/`g2` are byte-exact-KAT'd against the IETF
//! pairing-friendly-curves draft and RFC 9380 (see `bls12_381`'s own
//! `root.zig`).

const std = @import("std");
const bls12_381 = @import("bls12_381");
const ibe = @import("ibe.zig");
const ciphersuite = @import("ciphersuite.zig");

/// TEST-ONLY import (`build.zig`'s `test_deps`, proven test-only by
/// `zig build check-testonly`). Section 5 reuses `tlock`'s
/// drand-transcribed ciphersuite and its frozen drand interop fixture;
/// the PUBLISHED `ibe` module does not depend on `tlock` at all.
const tlock = @import("tlock");

const g1 = bls12_381.g1;
const g2 = bls12_381.g2;
const pairing = bls12_381.pairing;
const Fr = bls12_381.Fr;
const Fp12 = bls12_381.Fp12;

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

// ── 5. drand-parameterised interop anchor (THE external oracle) ──────
//
// Everything above is self-consistency: our encoder agreeing with our
// decoder, and our pairing identity agreeing with itself. None of it can
// fail because of a SYSTEMATIC assembly error — a mistake made
// identically on both sides (H3's operand order, the V/W byte
// placement, which mask XORs which half) is invisible to every one of
// those tests by construction.
//
// This section closes that. `ibe.Scheme` is instantiated with DRAND's
// parameters instead of this module's own, and the resulting scheme is
// required to reproduce, byte for byte, a real ciphertext that drand's
// own Go `tle` CLI produced. `ibe.zig`'s `encrypt`/`decrypt`/`fp12Pow`/
// `Ciphertext` bodies do the work unchanged — only the ciphersuite
// differs — so a byte-exact match is a statement about THIS module's
// assembly, made by an artifact nobody here authored.
//
// What it does NOT anchor, stated plainly so the docs never claim more
// than the test proves: this module's OWN parameters. `ciphersuite.zig`'s
// `dst_g1` and `zig-libs/ibe/H{2,3,4}` tags are unanchorable in
// principle — RFC 9380 §3.1 requires each application to pick its own
// DST, so "matches somebody else's" is the wrong property to want — and
// the no-cube decision is likewise a free choice with no external byte
// target (see `ibe.zig`'s "No drand-style cube"). Sections 1-4 are the
// only check on those, and that is the end state.
//
// One further residual, stated rather than glossed: this runs the
// assembly at drand's 16-byte block width, so a defect that only
// manifests at this module's own 32-byte width would slip past. The
// bodies are generic in `cs.block_bytes` and contain no width-specific
// arithmetic, which makes that narrow — not absent.
//
// PROVENANCE of the frozen bytes below: they are `tlock`'s, copied
// verbatim from `modules/tlock/src/kat_test.zig` section 3, whose own
// section comment and `modules/tlock/NOTICE` carry the full chain — a
// `tle`-armored age fixture from `github.com/drand/tlock` commit
// `7ceb44a598293f10c43d2291df9e669c4251fe24`
// (`testdata/lorem-tle-testnet-quicknet-t-2024-01-17-15-28.tle`,
// testnet beacon quicknet-t, round 5423142), the round signature
// fetched live from that beacon, and a plaintext independently
// confirmed through the age header MAC. They are numeric OUTPUT of a
// public specification produced by a third-party implementation, not
// third-party source code; no new attribution obligation arises beyond
// what `tlock/NOTICE` already records (see `ibe/NOTICE`).
//
// The copy is deliberate: `tlock`'s constants are private to its own
// test file and `modules/tlock/` is shared, so exporting them would
// mean editing a module this work is not allowed to change. The
// provenance test below re-derives their mutual consistency here
// (signature vs. public key vs. `h1(beaconId(round))`) rather than
// trusting the transcription, so a typo in any of them is a RED, not a
// silently weaker anchor.

/// drand's ciphersuite, in the shape `ibe.Scheme` consumes.
///
/// Every hash is `tlock.ciphersuite`'s — drand's DSTs, drand's
/// `IBE-H{2,3,4}` tags, drand's little-endian rejection-sampling `h3`,
/// drand's 16-byte block width — reused as-is rather than restated
/// here. Nothing in this struct re-implements anything; it is an
/// adapter between two call shapes plus the one representation
/// adapter drand's `Gt` convention needs.
const drand_ciphersuite = struct {
    /// drand's `tlock.go` `cipherVLen`/`cipherWLen`: 16, not `ibe`'s 32.
    pub const block_bytes = tlock.ciphersuite.block_bytes;

    /// `ibe.Scheme` passes the identity as a byte slice (an arbitrary
    /// caller-chosen string); drand's identity is always exactly
    /// `beaconId(round)`, a 32-byte SHA-256 digest, so its `h1` takes a
    /// fixed-size array. Same `hashToCurveG1` call underneath.
    pub fn h1(id: []const u8) g1.Affine {
        std.debug.assert(id.len == 32);
        return tlock.ciphersuite.h1(id[0..32].*);
    }

    /// THE `Gt` REPRESENTATION ADAPTER. `kilic/bls12-381` (drand's
    /// pairing backend) uses an FCKRH final exponentiation computing
    /// `f^(3d)` — a fixed CUBE of the canonical `f^d` value
    /// `bls12_381.pairing` returns — so drand hashes `gt³` where this
    /// repo hashes `gt`. `ibe.Scheme`'s `encrypt`/`decrypt` always hand
    /// `h2` the canonical value and never adapt it themselves (that is
    /// what makes the assembly representation-agnostic), so the cube
    /// belongs HERE, inside the ciphersuite that needs it — exactly
    /// where `tlock.zig` puts its own private `gtToDrandRepr`, whose
    /// one-line body (`gt.square().mul(gt)`) is restated here only
    /// because it is private to that file. Bilinearity commutes with a
    /// fixed power, so `(gid^r)³ == (gid³)^r` and the placement is
    /// immaterial to the value — the derivation lives in `tlock`'s
    /// `SPEC.md`, "Gt serialization". If this cube were wrong, absent,
    /// or applied in the wrong place, the byte-exact tests below fail:
    /// the fixture, not this comment, is the authority.
    pub fn h2(gt: Fp12) [block_bytes]u8 {
        return tlock.ciphersuite.h2(block_bytes, gt.square().mul(gt));
    }

    pub fn h3(sigma: []const u8, msg: []const u8) Fr {
        return tlock.ciphersuite.h3(sigma, msg);
    }

    pub fn h4(sigma: []const u8) [block_bytes]u8 {
        return tlock.ciphersuite.h4(block_bytes, sigma);
    }
};

/// `ibe.zig`'s OWN assembly, driven with drand's parameters.
const DrandIbe = ibe.Scheme(drand_ciphersuite);

fn hexBytes(comptime n: usize, comptime hex: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// quicknet-t (testnet) master public key, `G2` compressed.
const quicknet_t_pubkey_hex =
    "b15b65b46fb29104f6a4b5d1e11a8da6344463973d423661bb0804846a0ecd1" ++
    "ef93c25057f1c0baab2ac53e56c662b66072f6d84ee791a3382bfb055afab1e" ++
    "6a375538d8ffc451104ac971d2dc9b168e2d3246b0be2015969cbaac298f650" ++
    "2da";

/// The round `tle` encrypted the fixture to.
const interop_round: u64 = 5423142;

/// Round 5423142's published quicknet-t threshold-BLS signature (`G1`
/// compressed) — the BF-IBE private key for the fixture's identity.
const interop_round_sig_hex =
    "96fce8e2f70e2784577c8f2d8bd36af7a4b0dfd73dd91469d8556b36d2973a4" ++
    "f84681a45b1af2ce0511e5a32dd72508f";

/// The fixture's raw 128-byte BF-IBE ciphertext `U || V || W`.
const interop_ct_hex =
    "87333e1baaf45ffafbaac29e472ae0974986e9d6028fb4b15cc470fdc7d4121" ++
    "31733f6c867c7bc56ed52b6ae85196b4b0d156e65ba0038b3c6521017b3aed0" ++
    "c45f31011db4a326cc75f4f4a8d78ded24715853d25d7acee2ee98a8a01d8b0" ++
    "d20868992a49bbb8dfa7756f8a804930fe58c997398f72fe8c72da3aab6984f" ++
    "2c9c";

/// The expected `decrypt` output: the age file key `tle` wrapped.
const interop_filekey_hex = "2088b21b7778175ecb9349dd98737373";

/// The BF-IBE `sigma` pad drand's Go implementation drew for the
/// fixture (recovered from the ciphertext; see `tlock`'s section 3).
const interop_sigma_hex = "7f4a8bfc5ae6e845ee01773a45dd92ae";

fn interopIdentity() [32]u8 {
    return tlock.ciphersuite.beaconId(interop_round);
}

fn interopRoundSignature() g1.Affine {
    return g1.fromBytesCompressed(hexBytes(48, interop_round_sig_hex)) catch unreachable;
}

fn quicknetTPubkey() g2.Affine {
    return g2.fromBytesCompressed(hexBytes(96, quicknet_t_pubkey_hex)) catch unreachable;
}

test "drand anchor: the seam really re-parameterises (16-byte blocks, 128-byte wire)" {
    // If `Scheme` had quietly kept `ibe`'s own 32-byte width, the
    // byte-exact tests below could not even be expressed — assert the
    // instantiation actually took, so a future refactor that hard-wires
    // the ciphersuite back in fails HERE with a clear message rather
    // than as a confusing length mismatch.
    try std.testing.expectEqual(@as(usize, 16), DrandIbe.block_bytes);
    try std.testing.expectEqual(@as(usize, 128), DrandIbe.Ciphertext.encoded_bytes);
    try std.testing.expectEqual(@as(usize, 32), ibe.block_bytes);
    try std.testing.expectEqual(@as(usize, 160), ibe.Ciphertext.encoded_bytes);
}

test "drand anchor: the transcribed fixture constants are mutually consistent (no IBE core involved)" {
    // e(sig, G2gen) == e(h1(beaconId(round)), P_pub), using only
    // bls12_381 machinery — proves the public key, the round signature
    // and the identity copied into this file belong together, so a
    // transcription typo cannot silently weaken the anchor below into
    // "some ciphertext decrypts to some bytes".
    const sig = interopRoundSignature();
    const qid = drand_ciphersuite.h1(&interopIdentity());
    const neg_qid = g1.Jacobian.fromAffine(qid).negate().toAffine();
    try std.testing.expect(pairing.pairingCheck(&.{
        .{ .p = sig, .q = g2.Affine.generator },
        .{ .p = neg_qid, .q = quicknetTPubkey() },
    }));
}

test "drand anchor: ibe's own encrypt reproduces a genuine Go-tle ciphertext byte-exactly" {
    const ct = DrandIbe.encrypt(
        quicknetTPubkey(),
        &interopIdentity(),
        hexBytes(16, interop_filekey_hex),
        hexBytes(16, interop_sigma_hex),
    );
    try std.testing.expectEqualSlices(u8, &hexBytes(128, interop_ct_hex), &ct.toBytes());
}

test "drand anchor: ibe's own decrypt recovers the Go-tle file key byte-exactly" {
    const ct = try DrandIbe.Ciphertext.fromBytes(hexBytes(128, interop_ct_hex));
    const filekey = try DrandIbe.decrypt(interopRoundSignature(), ct);
    try std.testing.expectEqualSlices(u8, &hexBytes(16, interop_filekey_hex), &filekey);
}

test "drand anchor: the genuine fixture is rejected under a wrong private key (FO check on foreign bytes)" {
    // The same soundness property sections 1-4 test on our OWN
    // ciphertexts, here on bytes we did not produce: a valid G1 point
    // that is not this identity's key must yield FoCheckFailed, never a
    // wrong file key.
    const ct = try DrandIbe.Ciphertext.fromBytes(hexBytes(128, interop_ct_hex));
    const wrong = g1.Jacobian.fromAffine(interopRoundSignature()).double().toAffine();
    try std.testing.expectError(error.FoCheckFailed, DrandIbe.decrypt(wrong, ct));
}
