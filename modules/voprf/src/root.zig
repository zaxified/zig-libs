// SPDX-License-Identifier: MIT
//! voprf — Oblivious Pseudorandom Functions (OPRF) per RFC 9497, **all five
//! §4 ciphersuites** — ristretto255-SHA512 (§4.1, the top-level API of this
//! file), decaf448-SHAKE256 (§4.2), P256-SHA256 (§4.3), P384-SHA384 (§4.4)
//! and P521-SHA512 (§4.5) — each in all three modes: the base **OPRF** mode
//! (`modeOPRF = 0x00`), the verifiable **VOPRF** mode (`modeVOPRF = 0x01`,
//! with the batched Chaum-Pedersen DLEQ proof of §2.2), and the
//! partially-oblivious **POPRF** mode (`modePOPRF = 0x02`, §3.3.3: the same
//! DLEQ machinery with the composite lists swapped, plus one `"Info"`-framed
//! key tweak). A client obtains `output = F(skS, input)` without the server
//! learning `input` and without the client learning `skS`; in the verifiable
//! modes the client additionally checks a zero-knowledge proof that the
//! server used the private key matching the published `pkS` (or the
//! info-tweaked key in POPRF).
//!
//! **Ciphersuite as a comptime parameter.** `protocol.zig`'s `Protocol(G)`
//! is the functional layer, generic over a group backend `G`
//! (`groups.zig`); `Suite(.p256_sha256)` (or the named
//! `P256Sha256`/`P384Sha384`/`P521Sha512`/`Decaf448Shake256`/
//! `Ristretto255Sha512`) returns the namespace, with the same function
//! names and argument order as the top level. The top level IS
//! `Ristretto255Sha512`, re-exported, so the pre-2026-11-13 API is
//! unchanged. The NIST suites' RFC 9380 hash-to-curve (simplified SWU) is
//! `h2c.zig`, built on the `p256`/`p384`/`p521` siblings' public field API.
//!
//! **Status:** every suite × mode KAT-validated byte-exact against RFC 9497
//! Appendix A.1-A.5 (`suite_kat_test.zig`, 40 vectors, generated from the
//! RFC text by `tools/gen_vectors.py`; A.1 also hand-transcribed in
//! `kat_vectors.zig`/`kat_test.zig`), and `h2c.zig` against RFC 9380
//! Appendix J.1.1/J.2.1/J.3.1 and K.1/K.3 (`h2c_test.zig`). This module has
//! NO internal RNG: blinds and proof nonces are caller-supplied
//! (`scalarFromWideBytes`), which is what makes the RFC's
//! `ProofRandomScalar` KATs reproducible.
//!
//! ## std recon finding — `Ristretto255.fromUniform` IS the Elligator
//! half of `hash_to_ristretto255`
//!
//! RFC 9497 §4.1's `HashToGroup` is `hash_to_ristretto255` (RFC 9380
//! Appendix B): `uniform_bytes = expand_message_xmd(SHA-512, msg, DST,
//! 64)` followed by the RFC 9496 §4.3.4 one-way map (Elligator on each
//! 32-byte half, then point addition). `std.crypto.ecc.Ristretto255.
//! fromUniform(h: [64]u8)` implements exactly that one-way map (its
//! internal `elligator(Fe)` on `h[0..32]` and `h[32..64]`, added) — so
//! the only missing piece was `expand_message_xmd`, implemented here
//! (`expandMessageXmd`) per RFC 9380 §5.4.1. The rest of the group
//! interface maps 1:1 onto std (all MIT, part of Zig itself):
//! `Ristretto255.basePoint` (Generator), `.mul(s: [32]u8)` (a
//! constant-time ladder that then BRANCHES on its own result — see the
//! Security notes; used here only for PUBLIC scalars),
//! `.add`/`.sub`, `.fromBytes`/`.toBytes` (RFC 9496 Decode/Encode,
//! Ne = 32), `.rejectIdentity`; `Ristretto255.scalar` (the shared
//! edwards25519 scalar field, order `2^252 + 27742317777372353535851937
//! 790883648493`): `.reduce64` (exactly §4.1's HashToScalar reduction
//! of 64 little-endian uniform bytes), `.add`/`.sub`/`.mul` (all mod L,
//! canonical outputs = SerializeScalar), `.rejectNonCanonical`
//! (DeserializeScalar validation), and `scalar.Scalar.fromBytes(x)
//! .invert().toBytes()` (ScalarInverse, constant-time, used for
//! unblinding); `std.crypto.hash.sha2.Sha512` (Hash, Nh = 64).
//!
//! ## Security notes
//!
//! - **Secret scalars do not go through `Ristretto255.mul`.** This was
//!   the module's own claim for a long time and it was WRONG. std's
//!   `mul` IS a constant-time 4-bit-window ladder — and then its
//!   `pcMul16` ends with `try q.rejectIdentity()`, a branch on a
//!   scalar-derived value, whose error union forced a `catch` at every
//!   one of the nine secret-scalar call sites in this file. Those nine
//!   now use the sibling `ct25519` (std's identical ladder with that
//!   tail removed, neutral element returned as a value, no error union
//!   to `catch`): `skS` in `deriveKeyPair`/`blindEvaluate`/`evaluate`/
//!   `computeCompositesFast`, the client `blind` in `blind` and its
//!   inverse in `unblind`, POPRF's tweak `t`/`t_inv`, and the DLEQ proof
//!   nonce `r` in `generateProof` (`s = r - c*k` hands `k` to anyone who
//!   learns `r`). The `scalar` add/sub/mul/invert ops are std's and are
//!   constant-time as-is.
//! - **Public scalars deliberately stay on std's `mul`.** `verifyProof`'s
//!   `s`/`c` come off the wire; the per-term composite scalars `di` are
//!   hashes of wire elements; POPRF's `m` is a hash of the PUBLIC `info`.
//!   Variable-time or result-branching behaviour on those leaks nothing
//!   that is not already published, and `error.DegenerateComposite` /
//!   `error.InvalidProof` are genuine fail-closed rejections of peer
//!   data. No variable-time scalar mult (`mulPublic`) is used anywhere.
//! - `verifyProof` compares the recomputed challenge with
//!   `std.crypto.timing_safe.eql`, and `finalizeVerifiable`/
//!   `finalizePoprf` run `verifyProof` BEFORE unblinding — an invalid
//!   proof yields `error.InvalidProof` and no output (fail closed).
//! - `Element.fromBytes` enforces RFC 9497 §4.1 DeserializeElement:
//!   canonical ristretto255 decoding AND identity-element rejection.
//!   `deserializeScalar` enforces canonical (< group order) scalars.
//! - Per RFC 9497 §3.2.1/§4.7, `deriveKeyPair`'s rejection loop, the
//!   POPRF `t == 0` check and `unblind`'s zero-blind check branch on
//!   secret-derived "is zero" conditions exactly where the RFC's own
//!   pseudocode does (the branch outcome is part of the protocol, not a
//!   side channel on a fixed secret). These are the ONLY remaining
//!   secret-dependent branches, and each one guards an operation that is
//!   arithmetically undefined for zero (a key that PRFs everything to the
//!   identity; an inverse that does not exist) rather than reporting a
//!   scalar multiplication's result.
//!
//! Wire sizes (§4.1): Ne = Ns = 32, Nh = 64; `Proof` = 64 bytes (c||s).

const std = @import("std");
const ct25519 = @import("ct25519");
const Sha512 = std.crypto.hash.sha2.Sha512;
const protocol = @import("protocol.zig");

/// RFC 9380 hashing (expand_message_xmd/xof, the NIST simplified-SWU
/// hash-to-curve) used by the decaf448 and NIST ciphersuites.
pub const h2c = @import("h2c.zig");
/// The five §4 group backends `Protocol` is instantiated over.
pub const groups = @import("groups.zig");

/// The generic RFC 9497 functional layer: `Protocol(G)` for a backend `G`
/// in `groups`. Prefer the named instances below.
pub const Protocol = protocol.Protocol;

/// RFC 9497 §4 ciphersuites.
pub const Ciphersuite = enum {
    ristretto255_sha512,
    decaf448_shake256,
    p256_sha256,
    p384_sha384,
    p521_sha512,
};

/// The protocol namespace for one ciphersuite: `Suite(.p256_sha256).blind(...)`
/// and so on, with exactly the same function names and argument order as
/// this file's top-level (ristretto255-SHA512) API; only the byte widths
/// (`Ne`, `Ns`, `Nh`, `wide_length`) differ.
pub fn Suite(comptime cs: Ciphersuite) type {
    return switch (cs) {
        .ristretto255_sha512 => Ristretto255Sha512,
        .decaf448_shake256 => Decaf448Shake256,
        .p256_sha256 => P256Sha256,
        .p384_sha384 => P384Sha384,
        .p521_sha512 => P521Sha512,
    };
}

/// §4.1 ristretto255-SHA512 — also re-exported at top level (the default).
pub const Ristretto255Sha512 = Protocol(groups.Ristretto255Sha512);
/// §4.2 decaf448-SHAKE256 (group from the sibling `decaf448`).
pub const Decaf448Shake256 = Protocol(groups.Decaf448Shake256);
/// §4.3 P256-SHA256 (curve from the sibling `p256`).
pub const P256Sha256 = Protocol(groups.P256Sha256);
/// §4.4 P384-SHA384 (curve from the sibling `p384`).
pub const P384Sha384 = Protocol(groups.P384Sha384);
/// §4.5 P521-SHA512 (curve from the sibling `p521`).
pub const P521Sha512 = Protocol(groups.P521Sha512);

const Default = Ristretto255Sha512;

/// Re-exported: the std group backing the default ciphersuite.
pub const Ristretto255 = std.crypto.ecc.Ristretto255;
const scalar = Ristretto255.scalar;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "(V)OPRF — Oblivious Pseudorandom Functions (RFC 9497), all five ciphersuites (ristretto255, decaf448, P-256, P-384, P-521): OPRF, verifiable, and partially-oblivious modes with batched DLEQ proofs.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure computation — no I/O, no allocation, no RNG
    .concurrency = .reentrant, // no globals; all types are plain values
    .model_after = "RFC 9497 (\"Oblivious Pseudorandom Functions (OPRFs) Using Prime-Order Groups\"), all §4 ciphersuites, OPRF+VOPRF+POPRF modes; RFC 9380 §5.3 expand_message_xmd/xof, §6.6.2 simplified SWU, Appendix B hash_to_ristretto255 / Appendix C hash_to_decaf448; std.crypto.ecc.Ristretto255 and the decaf448/p256/p384/p521 siblings supply the groups",
    // constant-time secret-scalar multiply (ristretto255), and the other
    // four ciphersuites' groups
    .deps = .{ "ct25519", "decaf448", "p256", "p384", "p521" },
};

// ── the default ciphersuite (RFC 9497 §4.1), source-compatible API ───────

/// RFC 9497 §4.1's ciphersuite identifier string.
pub const identifier = Default.identifier;
/// `Ne` (§4.1): encoded length of a group `Element`.
pub const Ne: usize = Default.Ne;
/// `Ns` (§4.1): encoded length of a `Scalar`.
pub const Ns: usize = Default.Ns;
/// `Nh` (§4.1): output length of the ciphersuite hash (SHA-512).
pub const Nh: usize = Default.Nh;

pub const Mode = protocol.Mode;
pub const contextString = Default.contextString;

/// RFC 9380 §5.4.1 `expand_message_xmd` with SHA-512, specialized to
/// `len_in_bytes <= 64` (`ell = 1`). `msg` may be passed as multiple parts.
/// Validated standalone against RFC 9380 Appendix K.3 (`kat_test.zig`).
/// The general expander (any SHA-2 hash, any `ell`) is `h2c.expandMessageXmd`.
/// Caller contract: `dst` is 1..255 bytes (RFC 9380 §5.3.1 step 1); anything
/// else is a checked `@panic("voprf: ...")`, never undefined behaviour.
pub fn expandMessageXmd(
    comptime len_in_bytes: usize,
    msg_parts: []const []const u8,
    dst: []const u8,
) [len_in_bytes]u8 {
    comptime std.debug.assert(len_in_bytes > 0 and len_in_bytes <= 64); // ell == 1
    if (dst.len == 0 or dst.len > 255) @panic("voprf: expandMessageXmd: DST must be 1..255 bytes");
    const block_size = 128; // SHA-512 input block size (s_in_bytes)
    const z_pad = @as([block_size]u8, @splat(0));
    var l_i_b_str: [2]u8 = undefined;
    std.mem.writeInt(u16, &l_i_b_str, len_in_bytes, .big);
    const dst_len = [1]u8{@intCast(dst.len)};

    var h0 = Sha512.init(.{});
    h0.update(&z_pad);
    for (msg_parts) |part| h0.update(part);
    h0.update(&l_i_b_str);
    h0.update(&[1]u8{0x00});
    h0.update(dst);
    h0.update(&dst_len);
    var b_0: [64]u8 = undefined;
    h0.final(&b_0);

    var h1 = Sha512.init(.{});
    h1.update(&b_0);
    h1.update(&[1]u8{0x01});
    h1.update(dst);
    h1.update(&dst_len);
    var b_1: [64]u8 = undefined;
    h1.final(&b_1);

    return b_1[0..len_in_bytes].*;
}

pub const InvalidInputError = protocol.InvalidInputError;
pub const hashToGroup = Default.hashToGroup;
pub const hashToScalar = Default.hashToScalar;
pub const DeserializeElementError = protocol.DeserializeElementError;
pub const Element = Default.Element;
pub const DeserializeScalarError = protocol.DeserializeScalarError;
pub const deserializeScalar = Default.deserializeScalar;
pub const scalarFromWideBytes = Default.scalarFromWideBytes;
pub const Proof = Default.Proof;
pub const KeyPair = Default.KeyPair;
pub const max_input_length = protocol.max_input_length;
pub const max_batch_length = protocol.max_batch_length;
pub const InputTooLongError = protocol.InputTooLongError;
pub const DeriveKeyPairError = protocol.DeriveKeyPairError;
pub const deriveKeyPair = Default.deriveKeyPair;
pub const GenerateProofError = protocol.GenerateProofError;
pub const generateProof = Default.generateProof;
pub const VerifyProofError = protocol.VerifyProofError;
pub const verifyProof = Default.verifyProof;
pub const BlindError = protocol.BlindError;
pub const blind = Default.blind;
pub const blindEvaluate = Default.blindEvaluate;
pub const BlindEvaluateBatchError = protocol.BlindEvaluateBatchError;
pub const blindEvaluateBatch = Default.blindEvaluateBatch;
pub const FinalizeError = protocol.FinalizeError;
pub const finalize = Default.finalize;
pub const EvaluateError = protocol.EvaluateError;
pub const evaluate = Default.evaluate;
pub const BlindEvaluateVerifiableError = protocol.BlindEvaluateVerifiableError;
pub const VerifiableEvaluation = Default.VerifiableEvaluation;
pub const blindEvaluateVerifiable = Default.blindEvaluateVerifiable;
pub const blindEvaluateVerifiableBatch = Default.blindEvaluateVerifiableBatch;
pub const FinalizeVerifiableError = protocol.FinalizeVerifiableError;
pub const finalizeVerifiable = Default.finalizeVerifiable;
pub const FinalizeBatchError = protocol.FinalizeBatchError;
pub const finalizeVerifiableBatch = Default.finalizeVerifiableBatch;
pub const PoprfBlindResult = Default.PoprfBlindResult;
pub const blindPoprf = Default.blindPoprf;
pub const PoprfEvaluateError = protocol.PoprfEvaluateError;
pub const blindEvaluatePoprfBatch = Default.blindEvaluatePoprfBatch;
pub const blindEvaluatePoprf = Default.blindEvaluatePoprf;
pub const finalizePoprf = Default.finalizePoprf;
pub const finalizePoprfBatch = Default.finalizePoprfBatch;
pub const finalizePoprfUnverified = Default.finalizePoprfUnverified;
pub const PoprfDirectEvaluateError = protocol.PoprfDirectEvaluateError;
pub const evaluatePoprf = Default.evaluatePoprf;
const poprfInfoScalar = Default.poprfInfoScalar;
pub const OprfClient = Default.OprfClient;
pub const VoprfClient = Default.VoprfClient;
pub const PoprfClient = Default.PoprfClient;
pub const OprfServer = Default.OprfServer;
pub const VoprfServer = Default.VoprfServer;
pub const PoprfServer = Default.PoprfServer;

// ── tests ────────────────────────────────────────────────────────────────

test {
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("stackprobe_test.zig");
    _ = @import("h2c_test.zig");
    _ = @import("suite_kat_test.zig");
    _ = @import("sweep_test.zig");
}

test "wire sizes match RFC 9497 §4.1" {
    try std.testing.expectEqual(@as(usize, 32), Element.encoded_length);
    try std.testing.expectEqual(@as(usize, 64), Proof.encoded_length);
    try std.testing.expectEqual(@as(usize, 64), Nh);
}

test "contextString has the exact RFC 9497 §3.1 shape" {
    // "OPRFV1-" || I2OSP(mode, 1) || "-" || "ristretto255-SHA512"
    const ctx = contextString(.voprf);
    try std.testing.expectEqual(@as(usize, 28), ctx.len);
    try std.testing.expectEqualSlices(u8, "OPRFV1-", ctx[0..7]);
    try std.testing.expectEqual(@as(u8, 0x01), ctx[7]);
    try std.testing.expectEqual(@as(u8, '-'), ctx[8]);
    try std.testing.expectEqualSlices(u8, identifier, ctx[9..]);
    try std.testing.expectEqual(@as(u8, 0x00), contextString(.oprf)[7]);
    try std.testing.expectEqual(@as(u8, 0x02), contextString(.poprf)[7]);
}

test "Element.fromBytes rejects the identity element and junk" {
    // The ristretto255 identity encodes as 32 zero bytes.
    try std.testing.expectError(error.InvalidElement, Element.fromBytes(@as([32]u8, @splat(0))));
    // Non-canonical / invalid encoding.
    try std.testing.expectError(error.InvalidElement, Element.fromBytes(@as([32]u8, @splat(0xff))));
}

// ── constant-time regression: no API reports a secret scalar's value ─────
//
// std's `Ristretto255.mul` ends its constant-time ladder with
// `try q.rejectIdentity()` — a branch on a scalar-derived value — and the
// error union that produces forced a `catch` at every secret-scalar call
// site here. The observable symptom of that leak is that a degenerate
// SECRET scalar came back as a distinct ERROR instead of a group element.
// These three tests pin the fixed behaviour: the degenerate case is an
// ordinary value, and the two entry points carry no error to branch on.
// Route any of these multiplies back through `.mul(...) catch return
// error.X` and all three go red.

test "blind REPORTS NOTHING about a zero blind (constant-time, ct25519)" {
    // Old shape: `input_element.p.mul(blind_scalar) catch return
    // error.InvalidBlind` — an error whose presence is decided by the
    // client's SECRET blind. Now the product is simply the identity.
    const zero_blind = @as([Ns]u8, @splat(0));
    const blinded = try shim.blind(.oprf, "ct regression", zero_blind);
    try std.testing.expectEqualSlices(u8, &@as([Ne]u8, @splat(0)), &blinded.toBytes());
    // And the same input under std's own multiply really does error —
    // pinning that this is a behaviour change, not a tautology.
    const p = try hashToGroup(.oprf, "ct regression");
    try std.testing.expectError(error.IdentityElement, p.p.mul(zero_blind));
}

const shim = @import("test_shim.zig");

test "blindEvaluate REPORTS NOTHING about a degenerate skS (constant-time)" {
    // Old shape: `blinded_element.p.mul(sk) catch return
    // error.InvalidSecretKey`. `deriveKeyPair` guarantees skS != 0, so this
    // path was unreachable in the protocol and existed only to leak.
    const blinded = try shim.blind(.oprf, "ct regression", shim.scalarFromWideBytes(@as([64]u8, @splat(0x5a))));
    const evaluated = shim.blindEvaluate(@as([Ns]u8, @splat(0)), blinded);
    try std.testing.expectEqualSlices(u8, &@as([Ne]u8, @splat(0)), &evaluated.toBytes());
}

test "blind/blindEvaluate carry no error a caller could branch on a secret with" {
    // `blindEvaluate` has no error union at all; `blind`'s members are
    // `InvalidInput` (from `hashToGroup`) and `InputTooLong` (the PUBLIC
    // input length, 2026-11-13), never anything from the multiply.
    // `InvalidBlind` must NOT be back.
    try std.testing.expect(@typeInfo(@TypeOf(blindEvaluate)).@"fn".return_type.? == Element);
    const blind_err = @typeInfo(@typeInfo(@TypeOf(blind)).@"fn".return_type.?).error_union.error_set;
    const members = @typeInfo(blind_err).error_set.error_names.?;
    try std.testing.expectEqual(@as(usize, 2), members.len);
    for (members) |name| try std.testing.expect(std.mem.eql(u8, name, "InvalidInput") or std.mem.eql(u8, name, "InputTooLong"));
}

test "deserializeScalar enforces canonicity" {
    try std.testing.expectError(error.InvalidScalar, deserializeScalar(@as([32]u8, @splat(0xff))));
    _ = try deserializeScalar(@as([32]u8, @splat(0))); // zero is canonical (validity is contextual)
}

/// `s + L` as 32 little-endian bytes: the same scalar to the group, a
/// different (non-canonical) encoding on the wire.
fn plusOrder(s: [Ns]u8) [Ns]u8 {
    var out: [Ns]u8 = undefined;
    std.mem.writeInt(u256, &out, std.mem.readInt(u256, &s, .little) + scalar.field_order, .little);
    return out;
}

test "verifyProof refuses s + L (malleability) and a C/D length mismatch" {
    const kp = try shim.deriveKeyPair(.voprf, @as([32]u8, @splat(0x2b)), "verifyProof refusals");
    const blinded = try shim.blind(.voprf, "input", shim.scalarFromWideBytes(@as([64]u8, @splat(0x22))));
    const ev = try shim.blindEvaluateVerifiable(kp.sk, kp.pk, blinded, shim.scalarFromWideBytes(@as([64]u8, @splat(0x33))));
    try verifyProof(.voprf, Element.generator, kp.pk, &.{blinded}, &.{ev.evaluated_element}, ev.proof);

    // `s + L` multiplies every point exactly as `s` does, so only the
    // canonicity check stands between it and a second valid encoding.
    const forged: Proof = .{ .c = ev.proof.c, .s = plusOrder(ev.proof.s) };
    try std.testing.expectError(error.InvalidProof, verifyProof(.voprf, Element.generator, kp.pk, &.{blinded}, &.{ev.evaluated_element}, forged));

    const two = [_]Element{ ev.evaluated_element, ev.evaluated_element };
    try std.testing.expectError(error.InvalidProof, verifyProof(.voprf, Element.generator, kp.pk, &.{blinded}, &two, ev.proof));
}

test "finalize refuses a non-canonical blind (blind + L)" {
    const kp = try shim.deriveKeyPair(.oprf, @as([32]u8, @splat(0x7e)), "non-canonical blind");
    const b = shim.scalarFromWideBytes(@as([64]u8, @splat(0x11)));
    const evaluated = shim.blindEvaluate(kp.sk, try shim.blind(.oprf, "input", b));
    _ = try shim.finalize("input", b, evaluated);
    try std.testing.expectError(error.InvalidBlind, shim.finalize("input", plusOrder(b), evaluated));
}

test "POPRF: skS == -m is InverseError, and pkS == -m*G is a refused tweaked key" {
    const info = "inverse";
    const sk = scalar.neg(try poprfInfoScalar(info));
    const b = shim.scalarFromWideBytes(@as([64]u8, @splat(0x44)));
    const blinded = try shim.blind(.poprf, "input", b);
    var out: [1]Element = undefined;
    try std.testing.expectError(error.InverseError, shim.blindEvaluatePoprfBatch(sk, &.{blinded}, info, &out, b));
    try std.testing.expectError(error.InverseError, shim.evaluatePoprf(sk, "input", info));

    const pk: Element = .{ .p = ct25519.mulRistrettoBase(sk) };
    try std.testing.expectError(error.InvalidInput, shim.blindPoprf("input", info, pk, b));
}

// ── fuzz: Element.fromBytes / Proof.fromBytes never panic ─────────────────
//
// Both are wire-decode entry points for values a peer sends over the OPRF/
// POPRF protocol — a `BlindedElement`/`EvaluationElement` (`Element`) and a
// verifiable-mode `Proof` (`c||s`). `Element.fromBytes` composes ristretto255
// decode + identity-rejection; `Proof.fromBytes` decodes two independent
// scalars. Random 32/64-byte strings are the natural fuzz shape here (no
// length-prefix/tag structure to get past — every byte is part of the fixed-
// width encoding), plus the identity/all-0xff edge cases already unit-tested
// above are folded in via biased byte fills.

/// The frames both corpora are cut from.
///
/// ⛔ A ristretto255 element in the form `Element.fromBytes` accepts is not
/// reachable from arbitrary bytes — the encoding has to survive RFC 9496
/// Decode, which rejects most 32-octet strings outright — so the accepted
/// frames come from the module's own `toBytes`. The refusals are literals,
/// because those a draw CAN produce.
const Fixtures = struct {
    /// The ristretto255 base point, and `2·G`, so the corpus carries two
    /// distinct accepted elements rather than one repeated.
    g: [Ne]u8 = undefined,
    g2: [Ne]u8 = undefined,
    /// A real `Proof`: two canonical scalars, `c ‖ s`.
    proof: [Proof.encoded_length]u8 = undefined,

    fn build(self: *Fixtures) void {
        self.g = Element.generator.toBytes();
        const two = Element{ .p = Element.generator.p.add(Element.generator.p) };
        self.g2 = two.toBytes();
        const c = deserializeScalar([_]u8{2} ++ @as([31]u8, @splat(0))) catch unreachable;
        const s = deserializeScalar([_]u8{3} ++ @as([31]u8, @splat(0))) catch unreachable;
        self.proof = (Proof{ .c = c, .s = s }).toBytes();
    }
};

/// ⚠ A `smith.bytes(&buf)` harness reads its corpus entry RAW — no `u32`
/// length header — so these are the 32/64-octet frames themselves, each
/// followed by the `u64` word the mode knob after the byte draw reads.
/// ⛔ Without that word the knob is dead on a corpus replay: it would be 0
/// (`memset` to zero) on every seed, and every element frame would be
/// overwritten before `fromBytes` saw it.
const ElementCorpus = struct {
    store: [7][Ne + 8]u8 = undefined,
    entries: [7][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *ElementCorpus, frame: [Ne]u8, mode: u64) void {
        @memcpy(self.store[self.n][0..Ne], &frame);
        std.mem.writeInt(u64, self.store[self.n][Ne..][0..8], mode, .little);
        self.entries[self.n] = &self.store[self.n];
        self.n += 1;
    }

    fn build(self: *ElementCorpus, fx: *const Fixtures) []const []const u8 {
        self.push(fx.g, 2); // the base point, untouched
        self.push(fx.g2, 2); // 2·G — a DIFFERENT accepted element
        var t = fx.g;
        t[31] ^= 0x80; // the high bit RFC 9496 Decode requires to be clear
        self.push(t, 2);
        t = fx.g;
        t[0] ^= 0x01; // one octet inside the field element: not a valid encoding
        self.push(t, 2);
        self.push(@splat(0), 0); // mode 0 — the canonical identity, rejected
        self.push(@splat(0), 1); // mode 1 — all-0xff, non-canonical junk
        self.push(@splat(0), 2); // the all-zero buffer straight through
        return self.entries[0..self.n];
    }
};

test "fuzz: Element.fromBytes never panics on arbitrary bytes" {
    var fx: Fixtures = .{};
    fx.build();
    var corpus: ElementCorpus = .{};
    try std.testing.fuzz({}, fuzzElementFromBytes, .{ .corpus = corpus.build(&fx) });
}

fn fuzzElementFromBytes(_: void, smith: *std.testing.Smith) !void {
    // ⚠ The byte draw comes FIRST. It used to come last, behind
    // `smith.valueRangeAtMost(u8, 0, 2)` — a ranged draw, which returns the
    // range MINIMUM unless a whole eight-octet word lands inside it — so with
    // no corpus the mode was 0 on every input this target ever ran outside
    // `--fuzz`, and the only thing it ever decoded was the all-zero identity
    // encoding. The `smith.bytes` branch had never executed.
    var buf: [Ne]u8 = undefined;
    smith.bytes(&buf);
    switch (smith.valueRangeAtMost(u8, 0, 2)) {
        0 => @memset(&buf, 0), // canonical identity encoding
        1 => @memset(&buf, 0xff), // non-canonical junk
        else => {}, // the drawn (or seeded) octets, untouched
    }
    _ = Element.fromBytes(buf) catch {};
}

const ProofCorpus = struct {
    store: [6][Proof.encoded_length]u8 = undefined,
    entries: [6][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *ProofCorpus, frame: [Proof.encoded_length]u8) void {
        self.store[self.n] = frame;
        self.entries[self.n] = &self.store[self.n];
        self.n += 1;
    }

    fn build(self: *ProofCorpus, fx: *const Fixtures) []const []const u8 {
        self.push(fx.proof); // two canonical scalars
        var t = fx.proof;
        t[31] = 0xff; // c's top octet: the three high bits must be clear
        self.push(t);
        t = fx.proof;
        t[63] = 0xff; // the same in s
        self.push(t);
        self.push(@splat(0)); // c = s = 0, canonical, so this is accepted
        self.push(@splat(0xff)); // both non-canonical
        return self.entries[0..self.n];
    }
};

test "fuzz: Proof.fromBytes never panics on arbitrary bytes" {
    var fx: Fixtures = .{};
    fx.build();
    var corpus: ProofCorpus = .{};
    try std.testing.fuzz({}, fuzzProofFromBytes, .{ .corpus = corpus.build(&fx) });
}

fn fuzzProofFromBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [Proof.encoded_length]u8 = undefined;
    smith.bytes(&buf);
    _ = Proof.fromBytes(buf) catch {};
}

test "corpus: the element and proof seeds reach their decoders, and the counts are pinned" {
    var fx: Fixtures = .{};
    fx.build();

    var el_corpus: ElementCorpus = .{};
    var el_accepted: usize = 0;
    // ⛔ The number the collapsed harness could not produce: DISTINCT elements
    // decoded. It only ever saw the all-zero identity encoding, which is
    // refused, so this was 0 — and an `accepted > 0` guard would have been
    // satisfied by a single repeated base point.
    var seen: [4][Ne]u8 = undefined;
    var distinct: usize = 0;
    var modes_seen: [3]bool = @splat(false);
    for (el_corpus.build(&fx)) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [Ne]u8 = undefined;
        smith.bytes(&buf);
        const mode = smith.valueRangeAtMost(u8, 0, 2);
        modes_seen[mode] = true;
        switch (mode) {
            0 => @memset(&buf, 0),
            1 => @memset(&buf, 0xff),
            else => {},
        }
        const e = Element.fromBytes(buf) catch continue;
        el_accepted += 1;
        const enc = e.toBytes();
        var already = false;
        for (seen[0..distinct]) |prev| {
            if (std.mem.eql(u8, &prev, &enc)) already = true;
        }
        if (!already) {
            seen[distinct] = enc;
            distinct += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), el_accepted);
    try std.testing.expectEqual(@as(usize, 2), distinct);
    // All three mode branches ran — the knob is alive on a corpus replay,
    // which no number of element seeds alone could have achieved.
    for (modes_seen) |m| try std.testing.expect(m);

    var pf_corpus: ProofCorpus = .{};
    var pf_accepted: usize = 0;
    for (pf_corpus.build(&fx)) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [Proof.encoded_length]u8 = undefined;
        smith.bytes(&buf);
        _ = Proof.fromBytes(buf) catch continue;
        pf_accepted += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), pf_accepted);
}
