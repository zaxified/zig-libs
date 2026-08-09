// SPDX-License-Identifier: MIT
//! voprf — Oblivious Pseudorandom Functions (OPRF) per RFC 9497,
//! **ristretto255-SHA512 ciphersuite (RFC 9497 §4.1) only**: the base
//! **OPRF** mode (`modeOPRF = 0x00`), the verifiable **VOPRF** mode
//! (`modeVOPRF = 0x01`, with the batched Chaum-Pedersen DLEQ proof of
//! §2.2), and the partially-oblivious **POPRF** mode (`modePOPRF =
//! 0x02`, §3.3.3 — implemented because it reuses every VOPRF core:
//! same DLEQ machinery with the composite lists swapped, plus one
//! `"Info"`-framed key tweak). A client obtains `output = F(skS,
//! input)` without the server learning `input` and without the client
//! learning `skS`; in the verifiable modes the client additionally
//! checks a zero-knowledge proof that the server used the private key
//! matching the published `pkS` (or the info-tweaked key in POPRF).
//!
//! **Status: complete** — all cores implemented and KAT-validated
//! against RFC 9497 Appendix A.1's official ristretto255-SHA512 test
//! vectors for all three modes (`kat_vectors.zig` / `kat_test.zig`),
//! byte-exact: `deriveKeyPair` reproduces every mode's `skSm`/`pkSm`
//! from `Seed`/`KeyInfo`; `blind` reproduces every `BlindedElement`;
//! `blindEvaluate`/`blindEvaluateVerifiable`/`blindEvaluatePoprf`
//! reproduce every `EvaluationElement`; `generateProof` (with the
//! vector's caller-supplied `ProofRandomScalar` — this module has NO
//! internal RNG; all random scalars are caller-supplied so KATs and
//! callers with their own CSPRNG discipline stay reproducible)
//! reproduces every `Proof` including the batch-size-2 vectors;
//! `finalize`/`finalizeVerifiable`/`finalizePoprf` reproduce every
//! `Output`; and `verifyProof` accepts each published proof and
//! rejects tampered ones (fail-closed typed error, never a panic).
//! `expandMessageXmd` (RFC 9380 §5.4.1, SHA-512, `ell = 1`) is
//! additionally validated standalone against RFC 9380 Appendix K.3.
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

/// Re-exported: the std group backing this ciphersuite (see the module
/// doc comment's recon finding for the exact API surface used).
pub const Ristretto255 = std.crypto.ecc.Ristretto255;
const scalar = Ristretto255.scalar;

pub const meta = .{
    .platform = .any,
    .role = .util, // pure computation — no I/O, no allocation, no RNG
    .concurrency = .reentrant, // no globals; all types are plain values
    .model_after = "RFC 9497 (\"Oblivious Pseudorandom Functions (OPRFs) Using Prime-Order Groups\"), §4.1 ristretto255-SHA512 ciphersuite, OPRF+VOPRF+POPRF modes; RFC 9380 §5.4.1 expand_message_xmd + Appendix B hash_to_ristretto255; std.crypto.ecc.Ristretto255 supplies the group",
    .deps = .{"ct25519"}, // constant-time secret-scalar multiply (see Security notes)
};

// ── ciphersuite constants (RFC 9497 §3.1 / §4.1) ─────────────────────────

/// RFC 9497 §4.1's ciphersuite identifier string.
pub const identifier = "ristretto255-SHA512";

/// `Ne` (§4.1): encoded length of a group `Element` (RFC 9496 Encode).
pub const Ne: usize = 32;

/// `Ns` (§4.1): encoded length of a `Scalar` (32-byte little-endian,
/// top three bits zero).
pub const Ns: usize = 32;

/// `Nh` (§4.1): output length of the ciphersuite hash (SHA-512).
pub const Nh: usize = 64;

/// The three protocol variants (RFC 9497 §3.1 Table 1). The enum value
/// is the exact one-byte mode identifier used in `contextString`.
pub const Mode = enum(u8) {
    oprf = 0x00,
    voprf = 0x01,
    poprf = 0x02,
};

/// RFC 9497 §3.1 `CreateContextString(mode, identifier)`:
/// `"OPRFV1-" || I2OSP(mode, 1) || "-" || identifier` (the mode byte is
/// the raw value 0x00/0x01/0x02, NOT an ASCII digit).
pub fn contextString(comptime mode: Mode) []const u8 {
    return "OPRFV1-" ++ [1]u8{@intFromEnum(mode)} ++ "-" ++ identifier;
}

// ── hash layer (RFC 9380 §5.4.1 + RFC 9497 §4.1) ─────────────────────────

/// RFC 9380 §5.4.1 `expand_message_xmd` with SHA-512, specialized to
/// `len_in_bytes <= 64` so `ell = ceil(len / b_in_bytes) = 1` — the only
/// case this ciphersuite needs (both HashToGroup and HashToScalar use
/// exactly 64 uniform bytes). `msg` may be passed as multiple parts;
/// they are hashed in order as one logical message (transcripts here
/// are concatenations, so this avoids any intermediate buffer).
/// Validated standalone against RFC 9380 Appendix K.3 (`kat_test.zig`).
pub fn expandMessageXmd(
    comptime len_in_bytes: usize,
    msg_parts: []const []const u8,
    dst: []const u8,
) [len_in_bytes]u8 {
    comptime std.debug.assert(len_in_bytes > 0 and len_in_bytes <= 64); // ell == 1
    std.debug.assert(dst.len > 0 and dst.len <= 255);
    const block_size = 128; // SHA-512 input block size (s_in_bytes)
    const z_pad = [_]u8{0} ** block_size;
    var l_i_b_str: [2]u8 = undefined;
    std.mem.writeInt(u16, &l_i_b_str, len_in_bytes, .big);
    const dst_len = [1]u8{@intCast(dst.len)};

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    var h0 = Sha512.init(.{});
    h0.update(&z_pad);
    for (msg_parts) |part| h0.update(part);
    h0.update(&l_i_b_str);
    h0.update(&[1]u8{0x00});
    h0.update(dst);
    h0.update(&dst_len);
    var b_0: [64]u8 = undefined;
    h0.final(&b_0);

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime); ell == 1 so we are done.
    var h1 = Sha512.init(.{});
    h1.update(&b_0);
    h1.update(&[1]u8{0x01});
    h1.update(dst);
    h1.update(&dst_len);
    var b_1: [64]u8 = undefined;
    h1.final(&b_1);

    return b_1[0..len_in_bytes].*;
}

/// Raised by `hashToGroup` (and its callers `blind`/`evaluate`/...)
/// when the input maps to the group identity element, per RFC 9497
/// §3.3.1's `InvalidInputError` (probability ~2^-252; the error path
/// exists for spec conformance, not because it is reachable in
/// practice), and by `blindPoprf` when `tweakedKey` is the identity.
pub const InvalidInputError = error{InvalidInput};

/// RFC 9497 §4.1 `HashToGroup(x)`: `hash_to_ristretto255` (RFC 9380
/// Appendix B) with `DST = "HashToGroup-" || contextString` —
/// 64 uniform bytes from `expandMessageXmd`, then the RFC 9496 §4.3.4
/// one-way map via `Ristretto255.fromUniform`. Rejects an identity
/// result per §3.3.1.
pub fn hashToGroup(comptime mode: Mode, input: []const u8) InvalidInputError!Element {
    const dst = "HashToGroup-" ++ comptime contextString(mode);
    const uniform = expandMessageXmd(64, &.{input}, dst);
    const p = Ristretto255.fromUniform(uniform);
    p.rejectIdentity() catch return error.InvalidInput;
    return .{ .p = p };
}

/// RFC 9497 §4.1 `HashToScalar(x)` with the standard
/// `DST = "HashToScalar-" || contextString`: 64 uniform bytes,
/// interpreted as a little-endian integer and reduced mod the group
/// order (`scalar.reduce64` — the std reduction is exactly this).
/// `msg_parts` are concatenated in order (transcript convenience).
pub fn hashToScalar(comptime mode: Mode, msg_parts: []const []const u8) [Ns]u8 {
    return hashToScalarDst(msg_parts, "HashToScalar-" ++ comptime contextString(mode));
}

/// `HashToScalar` with an explicit DST — needed because §3.2.1's
/// `DeriveKeyPair` overrides the DST to `"DeriveKeyPair" || contextString`
/// (no separator dash, per the RFC's own pseudocode).
fn hashToScalarDst(msg_parts: []const []const u8, dst: []const u8) [Ns]u8 {
    return scalar.reduce64(expandMessageXmd(64, msg_parts, dst));
}

// ── types ────────────────────────────────────────────────────────────────

pub const DeserializeElementError = error{InvalidElement};

/// A validated non-identity ristretto255 group element (RFC 9497 §2.1
/// `Element`). Constructing one via `fromBytes` performs the full §4.1
/// `DeserializeElement` validation (canonical RFC 9496 decoding AND
/// identity rejection), so every `Element` held by this module's
/// functions is already wire-valid.
pub const Element = struct {
    p: Ristretto255,

    pub const encoded_length = Ne;

    /// §2.1 `Generator()`: the ristretto255 base point.
    pub const generator = Element{ .p = Ristretto255.basePoint };

    /// §4.1 `DeserializeElement`: RFC 9496 Decode + identity rejection.
    pub fn fromBytes(bytes: [Ne]u8) DeserializeElementError!Element {
        const p = Ristretto255.fromBytes(bytes) catch return error.InvalidElement;
        p.rejectIdentity() catch return error.InvalidElement;
        return .{ .p = p };
    }

    /// §4.1 `SerializeElement`: RFC 9496 Encode (canonical, 32 bytes).
    pub fn toBytes(e: Element) [Ne]u8 {
        return e.p.toBytes();
    }
};

pub const DeserializeScalarError = error{InvalidScalar};

/// §4.1 `DeserializeScalar`: accepts a 32-byte little-endian string iff
/// it encodes a scalar in `[0, Order() - 1]` (top three bits zero is
/// implied by canonicity). Returns the validated bytes unchanged —
/// scalars are carried as canonical `[Ns]u8` throughout this module.
pub fn deserializeScalar(bytes: [Ns]u8) DeserializeScalarError![Ns]u8 {
    scalar.rejectNonCanonical(bytes) catch return error.InvalidScalar;
    return bytes;
}

/// Reduce 64 uniformly random bytes (little-endian) to a canonical
/// scalar — RFC 9497 §4.7.2's "random number generation using extra
/// random bits" recipe. This is the intended way for a caller with its
/// own CSPRNG to produce the `blind` / proof-randomness scalars this
/// module's API takes as parameters (this module has no internal RNG).
pub fn scalarFromWideBytes(wide: [64]u8) [Ns]u8 {
    return scalar.reduce64(wide);
}

/// A DLEQ proof (RFC 9497 §2.2): two scalars `(c, s)`, serialized as
/// their concatenation (§3.3: "values of type Proof are serialized as
/// the concatenation of two serialized Scalar values").
pub const Proof = struct {
    c: [Ns]u8,
    s: [Ns]u8,

    pub const encoded_length = 2 * Ns;

    pub fn toBytes(proof: Proof) [encoded_length]u8 {
        return proof.c ++ proof.s;
    }

    pub fn fromBytes(bytes: [encoded_length]u8) DeserializeScalarError!Proof {
        return .{
            .c = try deserializeScalar(bytes[0..Ns].*),
            .s = try deserializeScalar(bytes[Ns..].*),
        };
    }
};

/// A server key pair: `sk` is the canonical serialized secret scalar,
/// `pk = ScalarMultGen(sk)` its public element (RFC 9497 §3.2).
pub const KeyPair = struct {
    sk: [Ns]u8,
    pk: Element,
};

// ── key generation (RFC 9497 §3.2.1) ─────────────────────────────────────

pub const DeriveKeyPairError = error{DeriveKeyPairFailed};

/// RFC 9497 §3.2.1 `DeriveKeyPair(seed, info)`: deterministic key
/// generation. `skS = HashToScalar(seed || I2OSP(len(info), 2) || info
/// || I2OSP(counter, 1))` with `DST = "DeriveKeyPair" || contextString`,
/// retrying (counter 0..255) while the result is zero. Reproduces the
/// Appendix A.1 `skSm`/`pkSm` values from `Seed`/`KeyInfo` (KAT).
pub fn deriveKeyPair(comptime mode: Mode, seed: [32]u8, info: []const u8) DeriveKeyPairError!KeyPair {
    std.debug.assert(info.len <= 0xffff);
    const dst = "DeriveKeyPair" ++ comptime contextString(mode);
    var info_len: [2]u8 = undefined;
    std.mem.writeInt(u16, &info_len, @intCast(info.len), .big);
    var counter: u16 = 0;
    while (counter <= 255) : (counter += 1) {
        const counter_byte = [1]u8{@intCast(counter)};
        const sk = hashToScalarDst(&.{ &seed, &info_len, info, &counter_byte }, dst);
        // skS == 0 → retry (this zero test is the RFC's own loop condition).
        if (std.mem.allEqual(u8, &sk, 0)) continue;
        // SECRET scalar: `ct25519.mulRistrettoBase`, not std's `mul` (see
        // the Security notes). The `catch continue` this replaces was a
        // second branch on `sk` on top of the RFC's own zero test.
        return .{ .sk = sk, .pk = .{ .p = ct25519.mulRistrettoBase(sk) } };
    }
    return error.DeriveKeyPairFailed;
}

// ── DLEQ proofs (RFC 9497 §2.2) ──────────────────────────────────────────

const Composites = struct {
    m: Element,
    z: Element,
};

/// The shared seed both §2.2.1 `ComputeCompositesFast` and §2.2.2
/// `ComputeComposites` derive first: `seed = Hash(I2OSP(len(Bm), 2) ||
/// Bm || I2OSP(len(seedDST), 2) || seedDST)` with
/// `seedDST = "Seed-" || contextString`.
fn compositesSeed(comptime mode: Mode, b: Element) [Nh]u8 {
    const seed_dst = "Seed-" ++ comptime contextString(mode);
    const bm = b.toBytes();
    var h = Sha512.init(.{});
    h.update(&.{ 0, Ne }); // I2OSP(len(Bm), 2), Bm is always Ne bytes
    h.update(&bm);
    h.update(&.{ 0, seed_dst.len }); // I2OSP(len(seedDST), 2)
    h.update(seed_dst);
    var seed: [Nh]u8 = undefined;
    h.final(&seed);
    return seed;
}

/// The per-element composite scalar `di` (§2.2.1/§2.2.2):
/// `di = HashToScalar(I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
/// I2OSP(len(Ci), 2) || Ci || I2OSP(len(Di), 2) || Di || "Composite")`.
fn compositeScalar(comptime mode: Mode, seed: *const [Nh]u8, i: u16, c_i: Element, d_i: Element) [Ns]u8 {
    var i_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &i_bytes, i, .big);
    const ci = c_i.toBytes();
    const di = d_i.toBytes();
    return hashToScalar(mode, &.{
        &.{ 0, Nh }, seed,
        &i_bytes,    &.{ 0, Ne },
        &ci,         &.{ 0, Ne },
        &di,         "Composite",
    });
}

const CompositesError = error{DegenerateComposite};

/// §2.2.1 `ComputeCompositesFast(k, B, C, D)` — server side, secret key
/// known: `M = sum(di * C[i])`, `Z = k * M`. The accumulator is seeded
/// with the first term instead of the identity element (the lists are
/// non-empty per §2.2.1), so no identity arithmetic is needed.
fn computeCompositesFast(
    comptime mode: Mode,
    k: [Ns]u8,
    b: Element,
    c_list: []const Element,
    d_list: []const Element,
) CompositesError!Composites {
    std.debug.assert(c_list.len >= 1 and c_list.len == d_list.len);
    const seed = compositesSeed(mode, b);
    var m_acc: Ristretto255 = undefined;
    for (c_list, d_list, 0..) |c_i, d_i, i| {
        const d_scalar = compositeScalar(mode, &seed, @intCast(i), c_i, d_i);
        const term = c_i.p.mul(d_scalar) catch return error.DegenerateComposite;
        m_acc = if (i == 0) term else m_acc.add(term);
    }
    // `k` is the SECRET key: constant-time multiply, no `catch`. (The
    // per-term `di` above are PUBLIC — derived by hash from wire elements
    // — so std's ladder is correct for them and its rejection branches on
    // nothing secret.)
    const z = ct25519.mulRistretto(m_acc, k);
    return .{ .m = .{ .p = m_acc }, .z = .{ .p = z } };
}

/// §2.2.2 `ComputeComposites(B, C, D)` — verifier side, no secret key:
/// `M = sum(di * C[i])`, `Z = sum(di * D[i])`.
fn computeComposites(
    comptime mode: Mode,
    b: Element,
    c_list: []const Element,
    d_list: []const Element,
) CompositesError!Composites {
    std.debug.assert(c_list.len >= 1 and c_list.len == d_list.len);
    const seed = compositesSeed(mode, b);
    var m_acc: Ristretto255 = undefined;
    var z_acc: Ristretto255 = undefined;
    for (c_list, d_list, 0..) |c_i, d_i, i| {
        const d_scalar = compositeScalar(mode, &seed, @intCast(i), c_i, d_i);
        const m_term = c_i.p.mul(d_scalar) catch return error.DegenerateComposite;
        const z_term = d_i.p.mul(d_scalar) catch return error.DegenerateComposite;
        if (i == 0) {
            m_acc = m_term;
            z_acc = z_term;
        } else {
            m_acc = m_acc.add(m_term);
            z_acc = z_acc.add(z_term);
        }
    }
    return .{ .m = .{ .p = m_acc }, .z = .{ .p = z_acc } };
}

/// The §2.2.1/§2.2.2 challenge scalar:
/// `c = HashToScalar(I2OSP(len(Bm), 2) || Bm || I2OSP(len(a0), 2) || a0
/// || ... || I2OSP(len(a3), 2) || a3 || "Challenge")` where
/// `a0..a3 = SerializeElement(M / Z / t2 / t3)`.
fn challengeScalar(comptime mode: Mode, b: Element, m: Element, z: Element, t2: Element, t3: Element) [Ns]u8 {
    const bm = b.toBytes();
    const a0 = m.toBytes();
    const a1 = z.toBytes();
    const a2 = t2.toBytes();
    const a3 = t3.toBytes();
    const len_prefix = [2]u8{ 0, Ne };
    return hashToScalar(mode, &.{
        &len_prefix, &bm,
        &len_prefix, &a0,
        &len_prefix, &a1,
        &len_prefix, &a2,
        &len_prefix, &a3,
        "Challenge",
    });
}

pub const GenerateProofError = error{ProofGenerationFailed};

/// RFC 9497 §2.2.1 `GenerateProof(k, A, B, C, D)` with caller-supplied
/// proof randomness `r` (the RFC's `r = G.RandomScalar()` — supplied by
/// the caller so the Appendix A KATs, which publish `ProofRandomScalar`,
/// are reproducible; `r` MUST be a fresh uniformly random scalar per
/// proof, e.g. via `scalarFromWideBytes`). Proves `k * A == B` and
/// `k * C[i] == D[i]` for every i. `c_list`/`d_list` must be non-empty
/// and of equal length; a batch produces one constant-size proof.
pub fn generateProof(
    comptime mode: Mode,
    k: [Ns]u8,
    a: Element,
    b: Element,
    c_list: []const Element,
    d_list: []const Element,
    r: [Ns]u8,
) GenerateProofError!Proof {
    const comp = computeCompositesFast(mode, k, b, c_list, d_list) catch
        return error.ProofGenerationFailed;
    // `r` is the SECRET proof nonce — `s = r - c*k` reveals `k` to anyone
    // who learns `r`, so it gets the same treatment as `k` itself.
    const t2 = ct25519.mulRistretto(a.p, r);
    const t3 = ct25519.mulRistretto(comp.m.p, r);
    const c = challengeScalar(mode, b, comp.m, comp.z, .{ .p = t2 }, .{ .p = t3 });
    const s = scalar.sub(r, scalar.mul(c, k)); // s = r - c * k (mod Order)
    return .{ .c = c, .s = s };
}

pub const VerifyProofError = error{InvalidProof};

/// RFC 9497 §2.2.2 `VerifyProof(A, B, C, D, proof)`. Recomputes the
/// composites without the secret key, reconstructs `t2 = s*A + c*B` and
/// `t3 = s*M + c*Z`, re-derives the challenge, and compares it with
/// `proof.c` via `std.crypto.timing_safe.eql`. Fails CLOSED: every
/// failure path (non-canonical proof scalars, degenerate intermediate
/// elements, challenge mismatch) is `error.InvalidProof` — no panics.
pub fn verifyProof(
    comptime mode: Mode,
    a: Element,
    b: Element,
    c_list: []const Element,
    d_list: []const Element,
    proof: Proof,
) VerifyProofError!void {
    if (c_list.len == 0 or c_list.len != d_list.len) return error.InvalidProof;
    _ = deserializeScalar(proof.c) catch return error.InvalidProof;
    _ = deserializeScalar(proof.s) catch return error.InvalidProof;
    const comp = computeComposites(mode, b, c_list, d_list) catch return error.InvalidProof;
    const s_a = a.p.mul(proof.s) catch return error.InvalidProof;
    const c_b = b.p.mul(proof.c) catch return error.InvalidProof;
    const t2 = s_a.add(c_b);
    const s_m = comp.m.p.mul(proof.s) catch return error.InvalidProof;
    const c_z = comp.z.p.mul(proof.c) catch return error.InvalidProof;
    const t3 = s_m.add(c_z);
    const expected_c = challengeScalar(mode, b, comp.m, comp.z, .{ .p = t2 }, .{ .p = t3 });
    if (!std.crypto.timing_safe.eql([Ns]u8, expected_c, proof.c)) return error.InvalidProof;
}

// ── shared Finalize hash (RFC 9497 §3.3.1/§3.3.3) ────────────────────────

/// The common tail of every Finalize/Evaluate:
/// `Hash(I2OSP(len(input), 2) || input || [I2OSP(len(info), 2) || info
/// ||] I2OSP(len(unblindedElement), 2) || unblindedElement ||
/// "Finalize")`. The optional `info` block only exists in POPRF mode
/// (§3.3.3); OPRF/VOPRF pass `null`.
fn finalizeHash(input: []const u8, info: ?[]const u8, unblinded: [Ne]u8) [Nh]u8 {
    std.debug.assert(input.len <= 0xffff);
    var len2: [2]u8 = undefined;
    var h = Sha512.init(.{});
    std.mem.writeInt(u16, &len2, @intCast(input.len), .big);
    h.update(&len2);
    h.update(input);
    if (info) |inf| {
        std.debug.assert(inf.len <= 0xffff);
        std.mem.writeInt(u16, &len2, @intCast(inf.len), .big);
        h.update(&len2);
        h.update(inf);
    }
    h.update(&.{ 0, Ne });
    h.update(&unblinded);
    h.update("Finalize");
    var out: [Nh]u8 = undefined;
    h.final(&out);
    return out;
}

/// `ScalarInverse(blind) * evaluatedElement` — the unblinding step
/// shared by every Finalize. Rejects a non-canonical or zero blind.
fn unblind(blind_scalar: [Ns]u8, evaluated_element: Element) FinalizeError![Ne]u8 {
    _ = deserializeScalar(blind_scalar) catch return error.InvalidBlind;
    if (std.mem.allEqual(u8, &blind_scalar, 0)) return error.InvalidBlind;
    const inv = scalar.Scalar.fromBytes(blind_scalar).invert().toBytes();
    // `inv` is derived from the SECRET blind: constant-time multiply.
    return ct25519.mulRistretto(evaluated_element.p, inv).toBytes();
}

// ── OPRF mode (RFC 9497 §3.3.1) ──────────────────────────────────────────

/// `InvalidBlind` is deliberately NOT a member: blinding multiplies a
/// SECRET scalar, and the only way the multiply could report anything about
/// it is by branching on it. `blind` therefore accepts every 32-byte blind
/// and returns a group element for it; a degenerate blind (`0 mod L`) yields
/// the identity, which `finalize` still rejects on the way back out (there
/// the scalar is being INVERTED, so zero has to be excluded arithmetically
/// rather than as a side channel). See the Security notes.
pub const BlindError = error{InvalidInput};

/// RFC 9497 §3.3.1 `Blind(input)` with caller-supplied blind scalar
/// (the RFC's `blind = G.RandomScalar()` — MUST be fresh, uniformly
/// random, and kept secret by the client; see `scalarFromWideBytes`).
/// Returns `blindedElement = blind * HashToGroup(input)`; the caller
/// keeps `blind_scalar` for `finalize`. `comptime mode` selects the
/// context (the same Blind is used by all three modes; POPRF callers
/// normally use `blindPoprf`, which also derives the tweaked key).
pub fn blind(comptime mode: Mode, input: []const u8, blind_scalar: [Ns]u8) BlindError!Element {
    const input_element = try hashToGroup(mode, input);
    // `blind_scalar` is the client's SECRET: constant-time multiply.
    return .{ .p = ct25519.mulRistretto(input_element.p, blind_scalar) };
}

/// RFC 9497 §3.3.1 `BlindEvaluate(skS, blindedElement)` — the OPRF-mode
/// server evaluation: `skS * blindedElement`, constant-time in `skS`.
///
/// Returns an `Element`, NOT an error union: `skS` is secret, and the only
/// failure std's `Ristretto255.mul` could report is "the product is the
/// identity", which for this prime-order group and a validated non-identity
/// `blindedElement` happens iff `skS == 0 (mod L)` — a broken server key,
/// never anything a client can induce. Reporting it would mean branching on
/// `skS`. `deriveKeyPair` is what guarantees `skS != 0`, by the RFC's own
/// rejection loop (§3.2.1).
pub fn blindEvaluate(sk: [Ns]u8, blinded_element: Element) Element {
    return .{ .p = ct25519.mulRistretto(blinded_element.p, sk) };
}

pub const FinalizeError = error{InvalidBlind};

/// RFC 9497 §3.3.1 `Finalize(input, blind, evaluatedElement)` — the
/// OPRF-mode client output (no proof; use `finalizeVerifiable` for
/// VOPRF): unblind with `blind^-1`, then the "Finalize" hash.
pub fn finalize(input: []const u8, blind_scalar: [Ns]u8, evaluated_element: Element) FinalizeError![Nh]u8 {
    const unblinded = try unblind(blind_scalar, evaluated_element);
    return finalizeHash(input, null, unblinded);
}

pub const EvaluateError = error{InvalidInput}; // see blindEvaluate re: the dropped InvalidSecretKey

/// RFC 9497 §3.3.1 `Evaluate(skS, input)` — the direct (non-oblivious)
/// PRF, computable by anyone holding both `skS` and `input`. Used by
/// the OPRF (`mode = .oprf`) and VOPRF (`mode = .voprf`) modes; the
/// KATs assert it agrees with the blinded protocol round trip.
pub fn evaluate(comptime mode: Mode, sk: [Ns]u8, input: []const u8) EvaluateError![Nh]u8 {
    const input_element = try hashToGroup(mode, input);
    const evaluated = ct25519.mulRistretto(input_element.p, sk); // SECRET sk
    return finalizeHash(input, null, evaluated.toBytes());
}

// ── VOPRF mode (RFC 9497 §3.3.2) ─────────────────────────────────────────

pub const BlindEvaluateVerifiableError = error{ProofGenerationFailed}; // see blindEvaluate re: the dropped InvalidSecretKey

/// The result of a single-element VOPRF `BlindEvaluate`.
pub const VerifiableEvaluation = struct {
    evaluated_element: Element,
    proof: Proof,
};

/// RFC 9497 §3.3.2 `BlindEvaluate(skS, pkS, blindedElement)` — the
/// VOPRF-mode server evaluation for one element: evaluates and attaches
/// a DLEQ proof that `log_G(pkS) == log_blinded(evaluated)`. `proof_r`
/// is the proof randomness (`ProofRandomScalar` in the KATs) — MUST be
/// fresh and uniformly random per call in production.
pub fn blindEvaluateVerifiable(
    sk: [Ns]u8,
    pk: Element,
    blinded_element: Element,
    proof_r: [Ns]u8,
) BlindEvaluateVerifiableError!VerifiableEvaluation {
    var evaluated: [1]Element = undefined;
    const proof = try blindEvaluateVerifiableBatch(sk, pk, &.{blinded_element}, &evaluated, proof_r);
    return .{ .evaluated_element = evaluated[0], .proof = proof };
}

/// Batched §3.3.2 `BlindEvaluate`: evaluates every element of `blinded`
/// into `evaluated_out` (same length, caller-allocated) and returns ONE
/// constant-size DLEQ proof covering the whole batch.
pub fn blindEvaluateVerifiableBatch(
    sk: [Ns]u8,
    pk: Element,
    blinded: []const Element,
    evaluated_out: []Element,
    proof_r: [Ns]u8,
) BlindEvaluateVerifiableError!Proof {
    std.debug.assert(blinded.len >= 1 and evaluated_out.len == blinded.len);
    for (blinded, evaluated_out) |blinded_element, *out| {
        out.* = blindEvaluate(sk, blinded_element);
    }
    return generateProof(.voprf, sk, Element.generator, pk, blinded, evaluated_out, proof_r);
}

pub const FinalizeVerifiableError = error{ InvalidBlind, InvalidProof };

/// RFC 9497 §3.3.2 `Finalize(input, blind, evaluatedElement,
/// blindedElement, pkS, proof)` — the VOPRF-mode client output. Runs
/// `VerifyProof` FIRST and fails closed (`error.InvalidProof`, no
/// output) if the server's DLEQ proof does not verify against `pkS`;
/// only then unblinds and hashes. For a batched evaluation, call
/// `verifyProof(.voprf, Element.generator, pkS, blinded, evaluated,
/// proof)` once, then `finalize` per element.
pub fn finalizeVerifiable(
    input: []const u8,
    blind_scalar: [Ns]u8,
    evaluated_element: Element,
    blinded_element: Element,
    pk: Element,
    proof: Proof,
) FinalizeVerifiableError![Nh]u8 {
    try verifyProof(.voprf, Element.generator, pk, &.{blinded_element}, &.{evaluated_element}, proof);
    return finalize(input, blind_scalar, evaluated_element);
}

// ── POPRF mode (RFC 9497 §3.3.3) ─────────────────────────────────────────

/// §3.3.3's framed-info scalar `m = HashToScalar("Info" || I2OSP(
/// len(info), 2) || info)`, shared by POPRF Blind/BlindEvaluate/Evaluate.
fn poprfInfoScalar(info: []const u8) [Ns]u8 {
    std.debug.assert(info.len <= 0xffff);
    var info_len: [2]u8 = undefined;
    std.mem.writeInt(u16, &info_len, @intCast(info.len), .big);
    return hashToScalar(.poprf, &.{ "Info", &info_len, info });
}

/// The result of POPRF `Blind`: the client keeps `tweaked_key` (and its
/// blind scalar) for `finalizePoprf`.
pub const PoprfBlindResult = struct {
    blinded_element: Element,
    tweaked_key: Element,
};

/// RFC 9497 §3.3.3 `Blind(input, info, pkS)` with caller-supplied blind
/// scalar: derives `tweakedKey = ScalarMultGen(m) + pkS` from the
/// public `info` and blinds the private `input` as in the other modes.
pub fn blindPoprf(
    input: []const u8,
    info: []const u8,
    pk: Element,
    blind_scalar: [Ns]u8,
) BlindError!PoprfBlindResult {
    const m = poprfInfoScalar(info);
    const t_point = Ristretto255.basePoint.mul(m) catch return error.InvalidInput;
    const tweaked = t_point.add(pk.p);
    tweaked.rejectIdentity() catch return error.InvalidInput;
    const blinded = try blind(.poprf, input, blind_scalar);
    return .{ .blinded_element = blinded, .tweaked_key = .{ .p = tweaked } };
}

/// §3.3.3 `InverseError`: the framed `info` maps to the negation of the
/// server's private key (`t = skS + m == 0`). Per the RFC, a client
/// triggering this should be assumed to know `skS` — servers seeing it
/// should rotate their key.
pub const PoprfEvaluateError = error{ InverseError, ProofGenerationFailed }; // see blindEvaluate re: the dropped InvalidSecretKey

/// Batched RFC 9497 §3.3.3 `BlindEvaluate(skS, blindedElement, info)`:
/// `evaluated[i] = (skS + m)^-1 * blinded[i]`, plus one DLEQ proof over
/// `(G, tweakedKey, evaluatedElements, blindedElements)` — note the
/// composite lists are SWAPPED relative to VOPRF, per the RFC (the
/// proven relation is `t * evaluated[i] == blinded[i]`).
pub fn blindEvaluatePoprfBatch(
    sk: [Ns]u8,
    blinded: []const Element,
    info: []const u8,
    evaluated_out: []Element,
    proof_r: [Ns]u8,
) PoprfEvaluateError!Proof {
    std.debug.assert(blinded.len >= 1 and evaluated_out.len == blinded.len);
    const m = poprfInfoScalar(info);
    const t = scalar.add(sk, m);
    if (std.mem.allEqual(u8, &t, 0)) return error.InverseError;
    const t_inv = scalar.Scalar.fromBytes(t).invert().toBytes();
    for (blinded, evaluated_out) |blinded_element, *out| {
        // `t_inv`/`t` are derived from the SECRET key: constant-time.
        out.* = .{ .p = ct25519.mulRistretto(blinded_element.p, t_inv) };
    }
    const tweaked = ct25519.mulRistrettoBase(t);
    return generateProof(.poprf, t, Element.generator, .{ .p = tweaked }, evaluated_out, blinded, proof_r) catch
        return error.ProofGenerationFailed;
}

/// Single-element §3.3.3 `BlindEvaluate` convenience wrapper.
pub fn blindEvaluatePoprf(
    sk: [Ns]u8,
    blinded_element: Element,
    info: []const u8,
    proof_r: [Ns]u8,
) PoprfEvaluateError!VerifiableEvaluation {
    var evaluated: [1]Element = undefined;
    const proof = try blindEvaluatePoprfBatch(sk, &.{blinded_element}, info, &evaluated, proof_r);
    return .{ .evaluated_element = evaluated[0], .proof = proof };
}

/// RFC 9497 §3.3.3 `Finalize(input, blind, evaluatedElement,
/// blindedElement, proof, info, tweakedKey)` — verifies the DLEQ proof
/// against the client-derived `tweakedKey` (fail closed) BEFORE
/// unblinding; note the swapped composite lists and the `info` block in
/// the final hash. For a batch, call `verifyProof(.poprf,
/// Element.generator, tweakedKey, evaluated, blinded, proof)` once,
/// then `finalizePoprfUnverified` per element.
pub fn finalizePoprf(
    input: []const u8,
    blind_scalar: [Ns]u8,
    evaluated_element: Element,
    blinded_element: Element,
    proof: Proof,
    info: []const u8,
    tweaked_key: Element,
) FinalizeVerifiableError![Nh]u8 {
    try verifyProof(.poprf, Element.generator, tweaked_key, &.{evaluated_element}, &.{blinded_element}, proof);
    return finalizePoprfUnverified(input, blind_scalar, evaluated_element, info);
}

/// The unblind+hash tail of POPRF Finalize, WITHOUT proof verification —
/// only for batch callers that already ran `verifyProof` over the whole
/// batch. Never skip verification on untrusted server output.
pub fn finalizePoprfUnverified(
    input: []const u8,
    blind_scalar: [Ns]u8,
    evaluated_element: Element,
    info: []const u8,
) FinalizeError![Nh]u8 {
    const unblinded = try unblind(blind_scalar, evaluated_element);
    return finalizeHash(input, info, unblinded);
}

pub const PoprfDirectEvaluateError = error{ InvalidInput, InverseError }; // see blindEvaluate re: the dropped InvalidSecretKey

/// RFC 9497 §3.3.3 `Evaluate(skS, input, info)` — the direct
/// (non-oblivious) POPRF, computable by anyone holding `skS`, `input`,
/// and `info`. The KATs assert it agrees with the blinded round trip.
pub fn evaluatePoprf(sk: [Ns]u8, input: []const u8, info: []const u8) PoprfDirectEvaluateError![Nh]u8 {
    const input_element = try hashToGroup(.poprf, input);
    const m = poprfInfoScalar(info);
    const t = scalar.add(sk, m);
    if (std.mem.allEqual(u8, &t, 0)) return error.InverseError;
    const t_inv = scalar.Scalar.fromBytes(t).invert().toBytes();
    const evaluated = ct25519.mulRistretto(input_element.p, t_inv); // SECRET t_inv
    return finalizeHash(input, info, evaluated.toBytes());
}

// ── tests ────────────────────────────────────────────────────────────────

test {
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
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
    try std.testing.expectError(error.InvalidElement, Element.fromBytes([_]u8{0} ** 32));
    // Non-canonical / invalid encoding.
    try std.testing.expectError(error.InvalidElement, Element.fromBytes([_]u8{0xff} ** 32));
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
    const zero_blind = [_]u8{0} ** Ns;
    const blinded = try blind(.oprf, "ct regression", zero_blind);
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** Ne, &blinded.toBytes());
    // And the same input under std's own multiply really does error —
    // pinning that this is a behaviour change, not a tautology.
    const p = try hashToGroup(.oprf, "ct regression");
    try std.testing.expectError(error.IdentityElement, p.p.mul(zero_blind));
}

test "blindEvaluate REPORTS NOTHING about a degenerate skS (constant-time)" {
    // Old shape: `blinded_element.p.mul(sk) catch return
    // error.InvalidSecretKey`. `deriveKeyPair` guarantees skS != 0, so this
    // path was unreachable in the protocol and existed only to leak.
    const blinded = try blind(.oprf, "ct regression", scalarFromWideBytes([_]u8{0x5a} ** 64));
    const evaluated = blindEvaluate([_]u8{0} ** Ns, blinded);
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** Ne, &evaluated.toBytes());
}

test "blind/blindEvaluate carry no error a caller could branch on a secret with" {
    // `blindEvaluate` has no error union at all; `blind`'s only member is
    // `InvalidInput`, which comes from `hashToGroup` (PUBLIC input framing),
    // never from the multiply. `InvalidBlind` must NOT be back.
    try std.testing.expect(@typeInfo(@TypeOf(blindEvaluate)).@"fn".return_type.? == Element);
    const blind_err = @typeInfo(@typeInfo(@TypeOf(blind)).@"fn".return_type.?).error_union.error_set;
    const members = @typeInfo(blind_err).error_set.?;
    try std.testing.expectEqual(@as(usize, 1), members.len);
    try std.testing.expectEqualStrings("InvalidInput", members[0].name);
}

test "deserializeScalar enforces canonicity" {
    try std.testing.expectError(error.InvalidScalar, deserializeScalar([_]u8{0xff} ** 32));
    _ = try deserializeScalar([_]u8{0} ** 32); // zero is canonical (validity is contextual)
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

test "fuzz: Element.fromBytes never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzElementFromBytes, .{});
}

fn fuzzElementFromBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [Ne]u8 = undefined;
    switch (smith.valueRangeAtMost(u8, 0, 2)) {
        0 => @memset(&buf, 0), // canonical identity encoding
        1 => @memset(&buf, 0xff), // non-canonical junk
        else => smith.bytes(&buf),
    }
    _ = Element.fromBytes(buf) catch {};
}

test "fuzz: Proof.fromBytes never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzProofFromBytes, .{});
}

fn fuzzProofFromBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [Proof.encoded_length]u8 = undefined;
    smith.bytes(&buf);
    _ = Proof.fromBytes(buf) catch {};
}
