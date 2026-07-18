// SPDX-License-Identifier: MIT
//! zkproofs — the GG18/GG20 MtA zero-knowledge range proofs (I2 **Phase
//! 2c**): the layer that upgrades `mta.zig`'s semi-honest MtA core to
//! MALICIOUS security. See GG18 (R. Gennaro, S. Goldfeder, "Fast
//! Multiparty Threshold ECDSA with Fast Trustless Setup", IACR ePrint
//! 2019/114) **Appendix A** for the two Sigma-protocol proofs this file
//! implements:
//!
//!   - **"Alice's range proof" (Πᵢ)**: proves a Paillier ciphertext `c_A =
//!     Enc_A(a)` encrypts a plaintext `a` lying in the agreed bounded
//!     range, WITHOUT revealing `a`. Consumed by whichever party is about
//!     to operate on `c_A` homomorphically (in this MtA flow, Bob) — it is
//!     what stops a malicious Alice from feeding an out-of-range `a` to
//!     bias or leak information through the homomorphic combination.
//!   - **"Bob's MtA proof" (Π^MtA, sometimes written Πᵢⱼ or Π' depending on
//!     edition)**: proves `c_B` was correctly derived from the PUBLIC
//!     `c_A` — `c_B = c_A^b · Enc_A(β'; r_B)` — with `b`/`β'` both in
//!     range and `r_B` a fresh Paillier blinding factor Bob actually knows.
//!     Consumed by Alice before she decrypts `c_B` in `mtaAliceFinalize`.
//!   - **"MtA with check" (Π^MtAwc)**: the extension GG18/GG20 use for the
//!     signing round's `k·x` share conversion, where Bob ADDITIONALLY
//!     proves `b·G == B` for a public point `B` the parties already agreed
//!     on (so the multiplicative share Bob used in MtA is provably the
//!     SAME `b` behind his public key-share contribution). See GG20 (R.
//!     Gennaro, S. Goldfeder, "One Round Threshold ECDSA with Identifiable
//!     Abort", IACR ePrint 2020/540) for the identifiable-abort framing
//!     that motivates verifying (not just trusting) every MtA instance.
//!
//! ## Threat model — why the "reject" tests matter more than the "accept" ones
//!
//! Both proofs exist to close the EXACT gap `mta.zig`'s module doc comment
//! flags as `TODO(2c)`: without them, `mtaBobResponse`/`mtaAliceFinalize`
//! (Phase 2b) are secure only against a passive adversary. A MALICIOUS
//! party can feed an out-of-range multiplicative input (`a`, `b`, or `β'`)
//! and, over the O(t²) MtA instances a real signing round runs, extract
//! bits of the counterparty's secret share — this is the general shape of
//! the **Alpha-Rays** and **TSSHOCK** failure classes documented against
//! real threshold-ECDSA implementations (out-of-range/malformed Paillier
//! plaintexts smuggled through an under-checked MtA or key-generation
//! step, then amplified across many signing sessions into a full key
//! recovery). The range/MtA proofs are the ONLY thing standing between
//! Phase-2b's correct-but-naive arithmetic and that class of attack —
//! which is exactly why this file treats the REJECT-path tests (tampered
//! `c_B`, out-of-range `b`, wrong `β'`, a mangled proof field) as the
//! load-bearing assertions, not the accept-path ones. A prove/verify pair
//! that always returns `true` would make every "honest accept" test pass
//! trivially while leaving the door wide open — the reject tests are what
//! actually pins the security property down.
//!
//! ## Status: IMPLEMENTED — verified against GG18 ePrint 2019/114 Appendix A
//!
//! The prove/verify number theory below was implemented against the ACTUAL
//! GG18 paper text (Appendix A.1 "Range Proof", A.2 "Respondent ZK Proof
//! for MtAwc", A.3 "Respondent ZK Proof for MtA" — retrieved from the NSF
//! Public Access mirror of the CCS'18 version, which carries the same
//! Appendix A as ePrint 2019/114) and structurally cross-checked against
//! bnb-chain/tss-lib's `crypto/mta` (`range_proof.go`/`proofs.go` —
//! structure/bounds reference only, NO code ported; see NOTICE). The exact
//! sampling ranges and verifier bounds used, with their sources:
//!
//! **A.1 Alice's range proof** (per the paper, identical in tss-lib):
//!   - prover samples `alpha ∈ Z_{q³}`, `beta ∈ Z_N^*`,
//!     `gamma ∈ Z_{q³·N_tilde}`, `rho ∈ Z_{q·N_tilde}`;
//!   - verifier checks `s1 <= q³` plus the two consistency equations.
//!
//! **A.2/A.3 Bob's MtA proof** (paper, with two DELIBERATE hardenings
//! adopted from tss-lib/GG20 practice — marked ⚠):
//!   - prover samples `alpha ∈ Z_{q³}`, `rho ∈ Z_{q·N_tilde}`,
//!     `rho' ∈ Z_{q³·N_tilde}`, `sigma ∈ Z_{q·N_tilde}`, `beta ∈ Z_N^*`,
//!     ⚠ `gamma ∈ Z_{q⁷}` (paper: `Z_N^*`), ⚠ `tau ∈ Z_{q³·N_tilde}`
//!     (paper: `Z_{q·N_tilde}`);
//!   - verifier checks `s1 <= q³` (paper) AND ⚠ `t1 <= q⁷` (paper has NO
//!     `t1` bound because its `y = β'` ranges over all of `Z_N`; tss-lib
//!     bounds `β' ∈ Z_{q⁵}` and checks `t1 <= q⁷` — this is the post-GG18
//!     hardening that also bounds Bob's additive blind, closing the
//!     unbounded-`β'` degree of freedom the Alpha-Rays class of attack
//!     abuses. This module's checked-MtA wiring samples `β' ∈ Z_q`, well
//!     inside `q⁵`, so honest proofs pass with slack; the bound is
//!     strictly STRONGER than the paper's, never weaker). The wider
//!     `tau ∈ Z_{q³·N_tilde}` follows so `t2 = e·sigma + tau` remains
//!     statistically hiding for `sigma ∈ Z_{q·N_tilde}`.
//!
//! **A.2 MtAwc**: exactly the A.3 proof plus `u1 = alpha·G` (the SAME
//! `alpha` that masks `b` — the paper reuses it, see `MtaProofWc`'s doc
//! comment) and the verifier equation `g^{s1} == X^e · u1` in the curve
//! group (`s1` reduced mod `q` there only).
//!
//! `mta.zig`'s `mtaAliceInitChecked`/`mtaBobResponseChecked`/
//! `mtaAliceFinalizeChecked` wiring (real Paillier-primitive composition)
//! consumes these — see their doc comments.
//!
//! ## Verification level — READ THIS BEFORE TRUSTING THE TESTS
//!
//! There is NO cross-implementation KAT for these proofs: the Fiat-Shamir
//! transcript is implementation-defined (the paper specifies an
//! INTERACTIVE verifier challenge `e ∈R Z_q`; tss-lib instantiates FS with
//! SHA512/256 over Go big.Int serializations + rejection sampling; this
//! module uses SHA-256 over the domain-separated length-prefixed
//! `Transcript` below + wide reduction mod q), so proofs are NOT
//! byte-compatible across implementations and a deterministic reference
//! KAT is impossible by construction. The tests below are therefore
//! (a) self-consistency: honest prove → verify accepts, end-to-end checked
//! MtA yields `α + β ≡ a·b`; (b) the SECURITY-CRITICAL reject paths:
//! out-of-range witnesses (fed via the test-only wide-witness entry
//! points), tampered ciphertexts, wrong witnesses, and per-field proof
//! mangling all verify false / fail closed. What the self-tests do NOT
//! prove: soundness against an adversarial prover exploring the full
//! malicious-input space (that rests on the construction matching the
//! paper — reviewed by transcription, twice, against paper + tss-lib —
//! and on the Strong-RSA/Paillier assumptions), nor side-channel freedom.
//! See SPEC.md's Phase-2c verification-level section.
//!
//! ## Fiat-Shamir challenge space
//!
//! `Transcript.finalize()` reduces the SHA-256 transcript digest into
//! `Scalar` (`Zq`, `q` = secp256k1's group order) via the same wide
//! 48-byte-buffer reduction `bip340`/`adaptor`/`frost` all use for their
//! own challenge scalars (`reduceToScalar` below). **Confirmed against the
//! paper**: GG18 Appendix A's verifier "selects a challenge e ∈R Z_q" in
//! every one of the three proofs (A.1/A.2/A.3), so `Zq` IS the paper's
//! challenge space; this module's Fiat-Shamir instantiation (SHA-256 +
//! statistically-uniform wide reduction) matches tss-lib's posture
//! (SHA512/256 + rejection sampling into `[0, q)`) in distribution while
//! differing in hash/encoding — see the "verification level" note above
//! on why that rules out cross-implementation KATs.
//!
//! ## Verifier-vs-prover aux-param ownership (the detail most likely to be
//! gotten backwards)
//!
//! Every `verifier_aux: root.AuxParams` parameter below is the AUX PARAMS
//! OF WHOEVER IS VERIFYING that specific proof — NOT the prover's own
//! tuple, and NOT a shared/global one. Concretely, in this MtA flow:
//!
//!   - `proveAliceRange`/`verifyAliceRange`'s `verifier_aux` is BOB's
//!     `AuxParams` (Bob is the one who will verify Alice's proof before
//!     operating on `c_A`), even though ALICE is the one calling
//!     `proveAliceRange`.
//!   - `proveBobMta`/`verifyBobMta`/`proveBobMtaWc`/`verifyBobMtaWc`'s
//!     `verifier_aux` is ALICE's `AuxParams` (Alice verifies Bob's proof
//!     before calling `mtaAliceFinalize` on `c_B`), even though BOB is the
//!     one calling `proveBobMta`.
//!
//! This mirrors `root.zig`'s own `generateAuxParams` doc comment: "this
//! party acting as the *verifier* of range proofs about OTHER parties'
//! Paillier plaintexts" — soundness (the Pedersen commitment's binding
//! property) requires the PROVER to never know the verifier's `lambda =
//! log_h1(h2)`, which only holds if the tuple truly belongs to the
//! verifying party.
//!
//! Zig std GAP: none new — `std.crypto.ff` (`Modulus`/`Fe`, reused via
//! `root.AuxModulus`/`root.AuxFe`/`paillier.Fe`) and
//! `std.crypto.hash.sha2.Sha256` are the only primitives this file needs;
//! same posture as `mta.zig`/`root.zig`.

const std = @import("std");
const builtin = @import("builtin");
const paillier = @import("paillier");
const root = @import("root.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

/// Re-exported for callers that only import `zkproofs` directly — same
/// `Zq` field `mta.zig`/`root.zig` use.
pub const Scalar = root.Scalar;

// ── small shared helpers (mechanical byte-buffer plumbing only) ─────────
//
// Duplicated from `root.zig`'s identically-named PRIVATE helpers (not
// `pub` there, so not importable) — the same "small mechanical helper,
// copied per file" convention this repo's `paillier`/`rsa`/`root.zig`
// already establish for `stripLeadingZeros`/`byteLen`-shaped functions.

fn stripLeadingZeros(bytes: []const u8) []const u8 {
    var i: usize = 0;
    while (i < bytes.len and bytes[i] == 0) : (i += 1) {}
    return bytes[i..];
}

fn appendLenPrefixed(list: *std.ArrayList(u8), allocator: std.mem.Allocator, data: []const u8) std.mem.Allocator.Error!void {
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(data.len), .big);
    try list.appendSlice(allocator, &len_buf);
    try list.appendSlice(allocator, data);
}

const InvalidEncodingError = error{InvalidEncoding};

fn readLenPrefixed(bytes: []const u8, offset: *usize) InvalidEncodingError![]const u8 {
    if (bytes.len < offset.* + 4) return error.InvalidEncoding;
    const len = std.mem.readInt(u32, bytes[offset.*..][0..4], .big);
    offset.* += 4;
    if (bytes.len < offset.* + len) return error.InvalidEncoding;
    const data = bytes[offset.* .. offset.* + len];
    offset.* += len;
    return data;
}

/// `int(bytes32) mod q`: the same wide-reduction idiom `bip340`/`adaptor`/
/// `frost` each keep a local copy of (`bip340` does not export a public
/// version) — zero-pad a 32-byte SHA-256 digest into 48 bytes and reduce
/// via `Scalar.fromBytes48`'s constant-time wide reduction, so a digest
/// `>= q` folds instead of getting rejected.
fn reduceToScalar(bytes32: [32]u8) Scalar {
    var wide = [_]u8{0} ** 48;
    wide[16..48].* = bytes32;
    return Scalar.fromBytes48(wide, .big);
}

// ── GG18 Appendix A bound constants (q, q³, q⁷ as big-endian bytes) ─────
//
// `q` = secp256k1's group order ("the order of the DSA group" in GG18's
// notation). The powers are computed at comptime from
// `std.crypto.ecc.Secp256k1.scalar.field_order` — no hand-transcribed
// constant to get wrong.

const q_int = root.Secp256k1.scalar.field_order;

/// Big-endian fixed-width encoding of a comptime integer.
fn comptimeIntBytes(comptime len: usize, comptime value: comptime_int) [len]u8 {
    var out: [len]u8 = undefined;
    var v = value;
    var i: usize = len;
    while (i > 0) {
        i -= 1;
        out[i] = @intCast(v & 0xff);
        v >>= 8;
    }
    if (v != 0) @compileError("comptimeIntBytes: value does not fit in len bytes");
    return out;
}

/// `q` (32 bytes) — factor for the `q·N_tilde` Pedersen-randomness bounds.
const q_bytes = comptimeIntBytes(32, q_int);
/// `q³` (96 bytes) — Alice's/Bob's multiplicative-input range bound: the
/// verifier is convinced `m ∈ [-q³, q³]` (GG18 A.1) / `x ∈ [-q³, q³]`
/// (A.2/A.3), and the prover's mask `alpha` is sampled from `Z_{q³}`.
const q3_bytes = comptimeIntBytes(96, q_int * q_int * q_int);
/// `q⁷` (224 bytes) — the `t1` bound for Bob's `β'` response (tss-lib/GG20
/// hardening; see the module doc comment — the GG18 paper itself leaves
/// `y = β'` unbounded over `Z_N` and checks no `t1` bound).
const q7_bytes = comptimeIntBytes(224, q_int * q_int * q_int * q_int * q_int * q_int * q_int);

// ── byte-level big-integer helpers (schoolbook; no allocator) ────────────
//
// The Sigma-protocol responses (`s1 = e·m + alpha`, ...) and the runtime
// sampling bounds (`q·N_tilde`, `q³·N_tilde`) are plain non-modular
// integers of at most a few hundred bytes — small enough that schoolbook
// byte arithmetic into caller-provided buffers beats pulling in
// `std.math.big.int` (no scratch allocator, trivially auditable carry
// handling, and the secret-containing buffers stay on the stack where the
// callers `secureZero` them).

/// Unsigned big-endian compare of arbitrary-length byte strings (leading
/// zeros ignored). Variable-time — only ever applied to PUBLIC proof
/// fields (verifier range checks) and to rejection-sampling draws (where
/// the comparison outcome is itself the discarded/accepted coin).
fn intCompare(a_in: []const u8, b_in: []const u8) std.math.Order {
    const a = stripLeadingZeros(a_in);
    const b = stripLeadingZeros(b_in);
    if (a.len != b.len) return if (a.len < b.len) .lt else .gt;
    return std.mem.order(u8, a, b);
}

/// `out = a * b` (big-endian, unsigned). `out.len` must be exactly
/// `a.len + b.len` (the product always fits). Used for the runtime
/// sampling bounds `q^k · N_tilde` (public values).
fn mulBytes(a: []const u8, b: []const u8, out: []u8) void {
    std.debug.assert(out.len == a.len + b.len);
    @memset(out, 0);
    var i: usize = a.len;
    while (i > 0) {
        i -= 1;
        var carry: u32 = 0;
        var j: usize = b.len;
        while (j > 0) {
            j -= 1;
            // weight (in bytes from the LSB) of a[i]*b[j] is
            // (a.len-1-i) + (b.len-1-j); LSB lives at out[out.len-1].
            const pos = out.len - 1 - (a.len - 1 - i) - (b.len - 1 - j);
            const cur = @as(u32, out[pos]) + @as(u32, a[i]) * @as(u32, b[j]) + carry;
            out[pos] = @truncate(cur);
            carry = cur >> 8;
        }
        var pos = out.len - 1 - (a.len - 1 - i) - b.len;
        while (carry != 0) {
            const cur = @as(u32, out[pos]) + carry;
            out[pos] = @truncate(cur);
            carry = cur >> 8;
            if (pos == 0) break;
            pos -= 1;
        }
    }
}

/// `out = e * x + addend` (big-endian, unsigned) — the Sigma-protocol
/// response shape. `out.len` must be >= `max(e.len + x.len, addend.len) + 1`.
/// Returns the full (zero-padded) `out`; callers strip. Variable-time in
/// the operands' LENGTHS only (all call sites pass fixed-width buffers for
/// the secret operands); the multiply itself touches every byte position
/// unconditionally.
fn mulAddBytes(e: []const u8, x: []const u8, addend: []const u8, out: []u8) []u8 {
    std.debug.assert(out.len >= e.len + x.len + 1 and out.len >= addend.len + 1);
    @memset(out, 0);
    @memcpy(out[out.len - addend.len ..], addend);
    var i: usize = e.len;
    while (i > 0) {
        i -= 1;
        var carry: u32 = 0;
        var j: usize = x.len;
        while (j > 0) {
            j -= 1;
            const pos = out.len - 1 - (e.len - 1 - i) - (x.len - 1 - j);
            const cur = @as(u32, out[pos]) + @as(u32, e[i]) * @as(u32, x[j]) + carry;
            out[pos] = @truncate(cur);
            carry = cur >> 8;
        }
        var pos = out.len - 1 - (e.len - 1 - i) - x.len;
        while (carry != 0) {
            const cur = @as(u32, out[pos]) + carry;
            out[pos] = @truncate(cur);
            carry = cur >> 8;
            if (pos == 0) break;
            pos -= 1;
        }
    }
    return out;
}

/// Allocate the minimal big-endian encoding of `e·x + addend` (at least
/// one byte, so a zero value round-trips through the codecs).
fn mulAddOwned(
    allocator: std.mem.Allocator,
    e: []const u8,
    x: []const u8,
    addend: []const u8,
) std.mem.Allocator.Error![]u8 {
    var buf: [max_response_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    const full = mulAddBytes(e, x, addend, &buf);
    const trimmed = stripLeadingZeros(full);
    if (trimmed.len == 0) return allocator.dupe(u8, &[_]u8{0});
    return allocator.dupe(u8, trimmed);
}

/// Widest response any call site produces: `t1 = e·y + gamma` with a
/// test-widened `y` (up to `q⁷`'s 224 bytes) still fits, as does
/// `s2/t2 = e·rho + gamma_pedersen` with `gamma_pedersen < q³·N_tilde`.
const max_response_bytes = 32 + 224 + root.aux_modulus_bytes + 2;

// ── sampling helpers ─────────────────────────────────────────────────────

/// Uniform integer in `[0, bound)` by rejection sampling (mask the top
/// byte to `bound`'s bit length, redraw on >= bound — the same idiom
/// `paillier.sampleNonzeroLtN`/`mta.samplePaillierRandomness` use).
/// Returns the `bound.len`-wide big-endian slice of `out_buf` (fixed width
/// per bound, so downstream constant-time exponentiations see a
/// value-independent exponent length).
fn sampleBelow(random: std.Random, bound_in: []const u8, out_buf: []u8) []u8 {
    const bound = stripLeadingZeros(bound_in);
    std.debug.assert(bound.len >= 1 and out_buf.len >= bound.len);
    const mask: u8 = @as(u8, 0xff) >> @intCast(@clz(bound[0]));
    const out = out_buf[0..bound.len];
    while (true) {
        random.bytes(out);
        out[0] &= mask;
        if (intCompare(out, bound) == .lt) return out;
    }
}

/// Uniform NONZERO integer in `[1, bound)` — the `beta ∈ Z_N^*` draw
/// (coprimality to N is not tested, matching `paillier.encryptRandom`'s
/// own documented posture: a random value sharing a factor with a real
/// 1024-bit+ semiprime is astronomically unlikely, and a broken draw only
/// breaks the prover's OWN proof).
fn sampleNonzeroBelow(random: std.Random, bound: []const u8, out_buf: []u8) []u8 {
    while (true) {
        const out = sampleBelow(random, bound, out_buf);
        if (stripLeadingZeros(out).len != 0) return out;
    }
}

// ── montint modexp backend for the ZK-proof hot path ─────────────────────
//
// The GG18/GG20 range/MtA proofs' ring-Pedersen commitments (`h1^x·h2^ρ mod
// Ñ`) and their Paillier-side terms (`c^α mod N²`, `r^e mod N`) were single
// `std.crypto.ff` modexps — the ~7–8× hot spot the audit's N1 finding measured
// (per-signature multi-second at production key sizes, `ff`'s schoolbook O(n²)
// Montgomery). They now route through the sibling `montint` module (full-radix
// 2⁶⁴ CIOS Montgomery), using the same runtime-limb-dispatch recipe the `rsa`
// (`603a493`) / `paillier` (`6b587a5`) pilots validated — the montint modulus is
// reconstructed per call via `Modint.fromElem` (the moduli reaching these
// generic choke points are not carried on a precomputed key struct). Two
// moduli flow through here at runtime — Ñ (`root.AuxModulus`, ~2048-bit) and
// Paillier N²/N (`paillier.Modulus`, up to ~4096-bit) — so the backend is
// generic over the `ff.Modulus`/`ff.Fe` pair and keys the comptime `Modint`
// instantiation on the operand's live limb count. Only the modular
// exponentiation primitive moved: every Fiat-Shamir transcript, sampling range,
// verifier bound, and serialization is byte-identical (the montint result is
// re-canonicalized into the SAME `ff.Fe` the old path returned), so the proofs
// and their KAT-less self/reject tests are unchanged.
//
// CONSTANT-TIME: secret witness exponents (the prover's masks `m, alpha, rho,
// gamma, sigma, tau`, secret Paillier randomness `r_a`, aux trapdoor `lambda`)
// go through `powCt` → montint's CT windowed `powMont` (fixed 5-bit window, all
// `L·64` exponent bits processed, branchless CT table gather) — the exact
// guarantee the `paillier` decrypt path relies on. The slot is chosen from the
// PUBLIC operand byte-lengths only (every secret exponent is a fixed-width
// buffer — see `sampleBelow`'s value-independent-length contract), and the
// result is sliced to the modulus' public byte width (never a value-dependent
// `stripLeadingZeros` on a secret-derived result). Public verifier exponents
// (challenge `e`, proof response fields) use the variable-time `powPub`.

const montint = @import("montint");

/// Widest big-endian buffer any modulus/base/result here needs — Paillier N²
/// (`paillier.modulus_sq_bytes` = 512) ≥ Ñ (`root.aux_modulus_bytes` = 256).
const mont_be_bytes: usize = paillier.modulus_sq_bytes;
const mont_step: usize = 4;
const mont_min_limbs: usize = 4;
/// Ceiling limb count: covers Paillier N² (64 limbs) and every secret exponent
/// (widest is `< q³·N_tilde` ≈ 2816 bits = 44 limbs).
const mont_max_limbs: usize = (paillier.max_bits + 63) / 64;

/// Round a runtime limb count up to the modeled `Modint` slot: the smallest
/// multiple of `mont_step` that is ≥ `l` and ≥ `mont_min_limbs`.
fn montSlot(l: usize) usize {
    var s: usize = mont_min_limbs;
    while (s < l) s += mont_step;
    return s;
}

/// Load a big-endian byte string into a `slot`-limb little-endian value with NO
/// value-dependent branch (the only branch is on the PUBLIC byte position vs the
/// limb count) — safe on a secret base/exponent. The caller guarantees the
/// value fits in `slot` limbs.
fn montBeToLimbs(comptime slot: usize, be: []const u8) [slot]u64 {
    var v = [_]u64{0} ** slot;
    var idx: usize = 0;
    var i: usize = be.len;
    while (i > 0) : (idx += 8) {
        i -= 1;
        const limb = idx >> 6;
        if (limb >= slot) break; // branch on public position, not on any value
        v[limb] |= @as(u64, be[i]) << @intCast(idx & 63);
    }
    return v;
}

// ── modular-exponentiation helpers (montint modexp, ff.Fe in/out) ────────

/// `base^e mod m`, CONSTANT-TIME in the base and the exponent VALUE (montint's
/// windowed `powMont`). `m`/`base` are an `ff` `Modulus`/`Fe` pair of any width;
/// `e` is a big-endian exponent byte string whose LENGTH is public (all secret-
/// exponent call sites pass fixed-width buffers). Returns an `Fe` canonical mod
/// `m`. `e = 0` maps to the mathematically-correct `base^0 = 1`.
fn powCt(m: anytype, base: anytype, e: []const u8) @TypeOf(base) {
    const Fe = @TypeOf(base);
    var m_be: [mont_be_bytes]u8 = undefined;
    m.toBytes(&m_be, .big) catch unreachable; // fits: modulus ≤ max_bits
    var b_be: [mont_be_bytes]u8 = undefined;
    base.toBytes(&b_be, .big) catch unreachable; // base < m
    const mod_bytes = (m.bits() + 7) / 8;
    // Slot must hold BOTH the modulus and the exponent — `powMont` takes the
    // exponent as an `L`-limb value. Selection is on PUBLIC lengths only.
    const slot = montSlot(@max((m.bits() + 63) / 64, (e.len * 8 + 63) / 64));
    var out: [mont_be_bytes]u8 = undefined;
    comptime var s: usize = mont_min_limbs;
    inline while (s <= mont_max_limbs) : (s += mont_step) {
        if (s == slot) {
            const M = montint.Modint(s * 64);
            const mont = M.fromElem(montBeToLimbs(s, &m_be)) catch unreachable; // odd, ≥3
            const bl = montBeToLimbs(s, &b_be);
            const el = montBeToLimbs(s, e);
            const r = mont.powMont(&bl, &el);
            mont.toBytesBE(&r, out[0..M.encoded_bytes]);
            // Slice to the modulus' PUBLIC byte width — the high bytes are zero
            // (result < m), so no value-dependent strip on a secret result.
            return Fe.fromBytes(m, out[M.encoded_bytes - mod_bytes .. M.encoded_bytes], .big) catch unreachable;
        }
    }
    unreachable;
}

/// `base^e mod m` for PUBLIC exponents (verifier side: every exponent is a
/// proof field or the Fiat-Shamir challenge, all public by definition). Left-
/// to-right square-and-multiply over `e`'s actual bit length (variable-time is
/// fine — `e` is public), the base still through montint's Montgomery multiply.
fn powPub(m: anytype, base: anytype, e: []const u8) @TypeOf(base) {
    const Fe = @TypeOf(base);
    var m_be: [mont_be_bytes]u8 = undefined;
    m.toBytes(&m_be, .big) catch unreachable;
    var b_be: [mont_be_bytes]u8 = undefined;
    base.toBytes(&b_be, .big) catch unreachable;
    const mod_bytes = (m.bits() + 7) / 8;
    const slot = montSlot((m.bits() + 63) / 64); // exp iterated as bytes ⇒ mod width suffices
    var out: [mont_be_bytes]u8 = undefined;
    comptime var s: usize = mont_min_limbs;
    inline while (s <= mont_max_limbs) : (s += mont_step) {
        if (s == slot) {
            const M = montint.Modint(s * 64);
            const mont = M.fromElem(montBeToLimbs(s, &m_be)) catch unreachable;
            const bl = montBeToLimbs(s, &b_be);
            const b_mont = mont.toMontgomery(&bl);
            var acc: M.Elem = mont.one_mont;
            var seen = false;
            const eb = stripLeadingZeros(e);
            for (eb) |byte| {
                var mask: u8 = 0x80;
                while (mask != 0) : (mask >>= 1) {
                    if (seen) acc = mont.montSqr(&acc);
                    if (byte & mask != 0) {
                        if (seen) {
                            acc = mont.montMul(&acc, &b_mont);
                        } else {
                            acc = b_mont; // first set bit: acc = base^1
                            seen = true;
                        }
                    }
                }
            }
            const r = mont.fromMontgomery(&acc); // e == 0 ⇒ acc == one_mont ⇒ 1
            mont.toBytesBE(&r, out[0..M.encoded_bytes]);
            return Fe.fromBytes(m, out[M.encoded_bytes - mod_bytes .. M.encoded_bytes], .big) catch unreachable;
        }
    }
    unreachable;
}

/// Byte-exact `AuxFe` equality (comparing via canonical serialization
/// sidesteps ff's internal Montgomery-form flag, which raw `eql` on
/// mixed-provenance values would trip over).
fn auxFeEql(a: root.AuxFe, b: root.AuxFe) bool {
    var ab: [root.aux_modulus_bytes]u8 = undefined;
    a.toBytes(&ab, .big) catch return false;
    var bb: [root.aux_modulus_bytes]u8 = undefined;
    b.toBytes(&bb, .big) catch return false;
    return std.mem.eql(u8, &ab, &bb);
}

/// Byte-exact `paillier.Fe` equality (same rationale as `auxFeEql`).
fn pailFeEql(a: paillier.Fe, b: paillier.Fe) bool {
    var ab: [paillier.modulus_sq_bytes]u8 = undefined;
    a.toBytes(&ab, .big) catch return false;
    var bb: [paillier.modulus_sq_bytes]u8 = undefined;
    b.toBytes(&bb, .big) catch return false;
    return std.mem.eql(u8, &ab, &bb);
}

/// `Γ^e mod N²` for an arbitrary-width NON-NEGATIVE integer exponent
/// (GG18 writes the Paillier generator as `Γ`; this repo's `paillier`
/// derives the standard `Γ = N+1`). Fast path: the same binomial identity
/// `paillier.encrypt`'s internal `gPow` uses — `(1+N)^e ≡ 1 + e·N (mod
/// N²)`, valid for ANY integer `e < N²` since `e·N mod N² = (e mod N)·N`
/// and `⟨1+N⟩` has order `N`. Falls back to a full modexp for a
/// non-standard caller-supplied `g`. Returns null (⇒ verifier rejects)
/// only if `e` doesn't fit below `N²` — unreachable after the `s1 <= q³` /
/// `t1 <= q⁷` range checks for any >= 1024-bit Paillier key.
fn gammaPowWide(pk: paillier.PublicKey, e_bytes: []const u8) ?paillier.Fe {
    const nsq = pk.n_sq;
    const one = nsq.one();
    var n_buf: [paillier.modulus_bytes]u8 = undefined;
    const n_len = pk.nByteLen();
    pk.nToBytes(n_buf[0..n_len]) catch return null;
    const n_fe = paillier.Fe.fromBytes(nsq, n_buf[0..n_len], .big) catch return null;
    const g_std = nsq.add(n_fe, one);
    if (pailFeEql(pk.g, g_std)) {
        const e_fe = paillier.Fe.fromBytes(nsq, stripLeadingZeros(e_bytes), .big) catch return null;
        return nsq.add(nsq.mul(e_fe, n_fe), one);
    }
    return powPub(nsq, pk.g, e_bytes);
}

/// Reduce an arbitrary-length big-endian integer into `Zq` (Horner over
/// 16-byte chunks with radix `2^128`, each chunk folded in via the
/// constant-time `fromBytes48` wide reduction). Used for the MtAwc curve
/// check's `s1 mod q` (public) and the prover's `alpha mod q` (its own
/// fresh mask).
fn scalarFromWide(bytes: []const u8) Scalar {
    // 2^128 as a Scalar (bit 128 => byte 31 of a 48-byte BE buffer).
    var radix_buf = [_]u8{0} ** 48;
    radix_buf[31] = 1;
    const radix = Scalar.fromBytes48(radix_buf, .big);

    var acc = Scalar.zero;
    var idx: usize = 0;
    const head = bytes.len % 16;
    if (head != 0) {
        acc = chunkScalar(bytes[0..head]);
        idx = head;
    }
    while (idx < bytes.len) : (idx += 16) {
        acc = acc.mul(radix).add(chunkScalar(bytes[idx .. idx + 16]));
    }
    return acc;
}

fn chunkScalar(chunk: []const u8) Scalar {
    std.debug.assert(chunk.len <= 16);
    var buf = [_]u8{0} ** 48;
    @memcpy(buf[48 - chunk.len ..], chunk);
    return Scalar.fromBytes48(buf, .big);
}

// ── Fiat-Shamir transcript (REAL) ────────────────────────────────────────

/// Domain-separation tags — one per proof KIND, so a `RangeProof`
/// transcript and an `MtaProof`/`MtaProofWc` transcript can never collide
/// even when fed an identical public-input sequence (same purpose as
/// `bip340.hash`'s `challenge_tag`/`nonce_tag`/`aux_tag` split).
pub const range_proof_domain = "threshold_ecdsa/zkproofs/range-proof/v1";
pub const mta_proof_domain = "threshold_ecdsa/zkproofs/mta-proof/v1";
pub const mta_proof_wc_domain = "threshold_ecdsa/zkproofs/mta-proof-wc/v1";

/// Fiat-Shamir transcript builder: binds every public value relevant to a
/// proof's soundness — the verifier's aux params, the ciphertexts/points
/// the proof is ABOUT, and the proof's own first-message commitments —
/// into one SHA-256 digest, finalized into a `Scalar` challenge (see the
/// module doc comment's "Fiat-Shamir challenge space" note). Every
/// `append*` funnels through `appendBytes`, which length-prefixes each
/// field (mirrors `root.zig`'s `appendLenPrefixed` byte-codec convention)
/// so e.g. `"ab"` followed by `"c"` can never hash the same as `"a"`
/// followed by `"bc"`.
///
/// REAL — this is mechanical hashing/serialization, not the crypto CORE
/// (the number theory that produces the values fed INTO the transcript is
/// what `proveAliceRange`/`proveBobMta`/etc. stub out).
pub const Transcript = struct {
    hasher: Sha256,

    /// `domain_tag` must be a comptime string (one of the `*_domain`
    /// constants above, or a caller's own if this is reused elsewhere).
    pub fn init(comptime domain_tag: []const u8) Transcript {
        var hasher = Sha256.init(.{});
        hasher.update(domain_tag);
        return .{ .hasher = hasher };
    }

    fn appendBytes(self: *Transcript, bytes: []const u8) void {
        var len_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_buf, @intCast(bytes.len), .big);
        self.hasher.update(&len_buf);
        self.hasher.update(bytes);
    }

    /// Appends an `AuxFe` (an `h1`/`h2`/Pedersen-commitment value, always
    /// canonical mod SOME `root.AuxModulus`) — serialized into the fixed
    /// `root.aux_modulus_bytes`-wide buffer every `AuxFe` fits regardless
    /// of the actual `N_tilde`'s real bit length (the backing `Modulus`
    /// type is comptime-fixed to `root.aux_modulus_bits`; see
    /// `root.AuxModulus`'s doc comment), so this needs no modulus
    /// parameter.
    pub fn appendAuxFe(self: *Transcript, fe: root.AuxFe) void {
        var buf: [root.aux_modulus_bytes]u8 = undefined;
        fe.toBytes(&buf, .big) catch unreachable; // fixed-width buffer, always sufficient
        self.appendBytes(&buf);
    }

    /// Appends every field of a party's `AuxParams` (`N_tilde`, `h1`,
    /// `h2`) — used to bind the transcript to WHICH party's aux params
    /// are acting as the commitment base (see the module doc comment's
    /// "verifier-vs-prover aux-param ownership" note).
    pub fn appendAuxParams(self: *Transcript, aux: root.AuxParams) void {
        var n_buf: [root.aux_modulus_bytes]u8 = undefined;
        aux.n_tilde.toBytes(&n_buf, .big) catch unreachable;
        self.appendBytes(&n_buf);
        self.appendAuxFe(aux.h1);
        self.appendAuxFe(aux.h2);
    }

    /// Appends a Paillier `Ciphertext` — fixed `paillier.modulus_sq_bytes`
    /// width, same "comptime-fixed backing width" reasoning as
    /// `appendAuxFe` (every `paillier.Fe`/`Ciphertext` is canonical mod
    /// the SAME comptime-fixed `paillier.Modulus(max_bits)` regardless of
    /// the actual key's real bit length).
    pub fn appendCiphertext(self: *Transcript, c: paillier.Ciphertext) void {
        var buf: [paillier.modulus_sq_bytes]u8 = undefined;
        c.toBytes(&buf) catch unreachable;
        self.appendBytes(&buf);
    }

    /// Appends a Paillier public key's `n` — binds the transcript to
    /// WHOSE Paillier key the ciphertexts above are encrypted under
    /// (Alice's, always, in this MtA flow).
    pub fn appendPaillierPublicKey(self: *Transcript, pk: paillier.PublicKey) void {
        var buf: [paillier.modulus_bytes]u8 = undefined;
        const n_len = pk.nByteLen();
        pk.nToBytes(buf[0..n_len]) catch unreachable;
        self.appendBytes(buf[0..n_len]);
    }

    /// Appends a `Zq` scalar (32-byte big-endian).
    pub fn appendScalar(self: *Transcript, s: Scalar) void {
        self.appendBytes(&s.toBytes(.big));
    }

    /// Appends a secp256k1 group element (33-byte SEC1-compressed) — used
    /// by the MtAwc transcript to bind the public point `B = b·G`.
    pub fn appendElement(self: *Transcript, e: root.Element) void {
        self.appendBytes(&e.toBytes());
    }

    /// Finalize into the challenge `e ∈ Zq`. Consumes `self` by value
    /// (Sha256's `finalResult` does) — callers build one `Transcript`,
    /// feed it every public input via `append*`, then call this exactly
    /// once.
    pub fn finalize(self: *Transcript) Scalar {
        return reduceToScalar(self.hasher.finalResult());
    }

    /// Like `finalize`, but returns the raw 32-byte SHA-256 digest instead
    /// of reducing it into `Zq` — for a challenge space OTHER than `Zq`
    /// (e.g. `aux_proofs.zig`'s Πprm/Πmod challenges, which need `{0,1}^m`
    /// bits or an `AuxFe` per proof iteration rather than a single `Scalar`
    /// — `aux_proofs.zig` expands this digest into as many challenge values
    /// as it needs via its own deterministic counter-mode expansion). Same
    /// "consumes `self` by value, call exactly once" contract as
    /// `finalize`.
    pub fn finalizeDigest(self: *Transcript) [32]u8 {
        return self.hasher.finalResult();
    }
};

/// The concrete transcript `proveAliceRange`/`verifyAliceRange` commit to
/// — binds Bob's (the verifier's) aux params, Alice's Paillier public key,
/// the ciphertext `c_A` the proof is ABOUT, and the proof's own first-
/// message commitments (`z`, `u`, `w`). REAL, mechanical — the actual
/// VALUES `z`/`u`/`w` come from the prover.
pub fn rangeProofChallenge(
    verifier_aux: root.AuxParams,
    alice_pk: paillier.PublicKey,
    c_a: paillier.Ciphertext,
    z: root.AuxFe,
    u: paillier.Ciphertext,
    w: root.AuxFe,
) Scalar {
    var t = Transcript.init(range_proof_domain);
    t.appendAuxParams(verifier_aux);
    t.appendPaillierPublicKey(alice_pk);
    t.appendCiphertext(c_a);
    t.appendAuxFe(z);
    t.appendCiphertext(u);
    t.appendAuxFe(w);
    return t.finalize();
}

/// The concrete transcript `proveBobMta`/`verifyBobMta` commit to — binds
/// Alice's (the verifier's) aux params, Alice's Paillier public key, BOTH
/// ciphertexts (`c_A` public input, `c_B` the ciphertext being proven
/// well-formed), and the proof's five first-message commitments.
pub fn mtaProofChallenge(
    verifier_aux: root.AuxParams,
    alice_pk: paillier.PublicKey,
    c_a: paillier.Ciphertext,
    c_b: paillier.Ciphertext,
    z: root.AuxFe,
    z1: root.AuxFe,
    t_commit: root.AuxFe,
    v: paillier.Ciphertext,
    w: root.AuxFe,
) Scalar {
    var t = Transcript.init(mta_proof_domain);
    t.appendAuxParams(verifier_aux);
    t.appendPaillierPublicKey(alice_pk);
    t.appendCiphertext(c_a);
    t.appendCiphertext(c_b);
    t.appendAuxFe(z);
    t.appendAuxFe(z1);
    t.appendAuxFe(t_commit);
    t.appendCiphertext(v);
    t.appendAuxFe(w);
    return t.finalize();
}

/// `mtaProofChallenge` plus the MtAwc extension's extra public inputs: the
/// public point `B = b·G` and the Schnorr commitment `u1_point`.
pub fn mtaProofWcChallenge(
    verifier_aux: root.AuxParams,
    alice_pk: paillier.PublicKey,
    c_a: paillier.Ciphertext,
    c_b: paillier.Ciphertext,
    z: root.AuxFe,
    z1: root.AuxFe,
    t_commit: root.AuxFe,
    v: paillier.Ciphertext,
    w: root.AuxFe,
    b_point: root.Element,
    u1_point: root.Element,
) Scalar {
    var t = Transcript.init(mta_proof_wc_domain);
    t.appendAuxParams(verifier_aux);
    t.appendPaillierPublicKey(alice_pk);
    t.appendCiphertext(c_a);
    t.appendCiphertext(c_b);
    t.appendAuxFe(z);
    t.appendAuxFe(z1);
    t.appendAuxFe(t_commit);
    t.appendCiphertext(v);
    t.appendAuxFe(w);
    t.appendElement(b_point);
    t.appendElement(u1_point);
    return t.finalize();
}

// ── RangeProof — Alice's proof Πᵢ (STRUCT+CODEC real, MATH real, GG18 App. A) ─────

/// GG18 Appendix A.1 "Range Proof" (Alice's proof): a non-interactive
/// (Fiat-Shamir) Sigma-protocol proof that a Paillier ciphertext `c_A =
/// Enc_A(a; r_A)` encrypts a plaintext the verifier can conclude lies in
/// `[-q³, q³]` (the paper's exact statement: "the Verifier is convinced
/// that m ∈ [-q³, q³]"; the honest prover's `a ∈ Z_q`), without revealing
/// `a` or `r_A`.
///
/// Field roles (per the paper's own notation, `m := a`, `Γ := N+1`):
///
///   - `z`  — Pedersen commitment (mod the verifier's `N_tilde`) to `a`:
///     `z = h1^a · h2^ρ mod N_tilde`.
///   - `u`  — a Paillier-ciphertext-shaped commitment to the prover's
///     random mask `alpha` for `a`: `u = Enc_A(alpha; beta) = g^alpha ·
///     beta^N mod N^2` (Alice's OWN Paillier `N`).
///   - `w`  — Pedersen commitment (mod `N_tilde`) to `alpha`: `w = h1^alpha
///     · h2^gamma mod N_tilde`.
///   - `s`  — the Paillier-randomness response `s = beta · r_A^e mod N`
///     (canonical mod `alice_pk.n_sq` per this repo's `paillier` module's
///     Fe-construction-contract convention — see `mta.zig`'s
///     `scalarToFe` doc comment — even though `s` conceptually lives in
///     `Z_N^*`).
///   - `s1` — the RANGE response for `a`, a plain INTEGER (no modular
///     reduction): `s1 = e·m + alpha`. THIS is the value whose bound the
///     verifier checks (`s1 <= q³`) — the entire "range" property lives
///     here. Owned big-endian bytes.
///   - `s2` — the response for the Pedersen commitment's randomness:
///     `s2 = e·rho + gamma`, likewise a plain INTEGER. Owned big-endian
///     bytes.
///
/// `s1`/`s2` are stored as arbitrary-length owned byte slices (not a
/// fixed-width `Fe`): an honest `s1` fits `q³`'s 96 bytes + slack, but
/// `s2 < q·N_tilde·q + q³·N_tilde` scales with the verifier's `N_tilde`,
/// and a VERIFIER must be able to parse (then reject) an out-of-range
/// attacker-chosen value rather than truncate it.
pub const RangeProof = struct {
    z: root.AuxFe,
    u: paillier.Ciphertext,
    w: root.AuxFe,
    s: paillier.Fe,
    /// Owned; free via `deinit`.
    s1: []const u8,
    /// Owned; free via `deinit`.
    s2: []const u8,

    pub fn deinit(self: RangeProof, allocator: std.mem.Allocator) void {
        allocator.free(self.s1);
        allocator.free(self.s2);
    }

    pub const ByteError = std.crypto.ff.OverflowError || std.crypto.ff.RepresentationError;
    pub const AllocError = std.mem.Allocator.Error || ByteError;

    /// `len-prefixed(z) || len-prefixed(u) || len-prefixed(w) ||
    /// len-prefixed(s) || len-prefixed(s1) || len-prefixed(s2)`. REAL,
    /// mechanical — mirrors `root.zig`'s `AuxParams.toBytesAlloc` shape.
    pub fn toBytesAlloc(self: RangeProof, allocator: std.mem.Allocator) AllocError![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(allocator);

        var z_buf: [root.aux_modulus_bytes]u8 = undefined;
        try self.z.toBytes(&z_buf, .big);
        try appendLenPrefixed(&list, allocator, &z_buf);

        var u_buf: [paillier.modulus_sq_bytes]u8 = undefined;
        try self.u.toBytes(&u_buf);
        try appendLenPrefixed(&list, allocator, &u_buf);

        var w_buf: [root.aux_modulus_bytes]u8 = undefined;
        try self.w.toBytes(&w_buf, .big);
        try appendLenPrefixed(&list, allocator, &w_buf);

        var s_buf: [paillier.modulus_sq_bytes]u8 = undefined;
        try self.s.toBytes(&s_buf, .big);
        try appendLenPrefixed(&list, allocator, &s_buf);

        try appendLenPrefixed(&list, allocator, self.s1);
        try appendLenPrefixed(&list, allocator, self.s2);

        return list.toOwnedSlice(allocator);
    }

    pub const FromBytesError = error{InvalidEncoding};

    /// Inverse of `toBytesAlloc`. `n_tilde`/`alice_pk` are needed to give
    /// `z`/`w` and `u`/`s` their modulus context (same "caller supplies
    /// the modulus" shape `paillier.Ciphertext.fromBytes` already uses).
    /// Allocates `s1`/`s2`; free with `deinit`.
    pub fn fromBytesAlloc(
        allocator: std.mem.Allocator,
        n_tilde: root.AuxModulus,
        alice_pk: paillier.PublicKey,
        bytes: []const u8,
    ) (std.mem.Allocator.Error || FromBytesError)!RangeProof {
        var offset: usize = 0;

        const z_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const z = root.AuxFe.fromBytes(n_tilde, stripLeadingZeros(z_bytes), .big) catch return error.InvalidEncoding;

        const u_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const u = paillier.Ciphertext.fromBytes(alice_pk, u_bytes) catch return error.InvalidEncoding;

        const w_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const w = root.AuxFe.fromBytes(n_tilde, stripLeadingZeros(w_bytes), .big) catch return error.InvalidEncoding;

        const s_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const s = paillier.Fe.fromBytes(alice_pk.n_sq, stripLeadingZeros(s_bytes), .big) catch return error.InvalidEncoding;

        const s1_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const s1 = try allocator.dupe(u8, s1_bytes);
        errdefer allocator.free(s1);

        const s2_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const s2 = try allocator.dupe(u8, s2_bytes);

        return .{ .z = z, .u = u, .w = w, .s = s, .s1 = s1, .s2 = s2 };
    }
};

/// `InvalidAuxParams` surfaces the audit-F1/F2 fail-closed rejection of a
/// RECEIVED counterparty aux tuple or sub-floor Paillier key at the prove
/// entry points (see `root.AuxParams.validate` / `root.paillierNMeetsFloor`).
pub const ProveError = std.mem.Allocator.Error || root.AuxParams.ValidateError;

/// **Audit F1 + F2 — validate the RECEIVED parameters a prover is about to
/// commit its secret witness under.** `verifier_aux` is the counterparty's
/// broadcast ring-Pedersen tuple (a malicious one leaks the witness through
/// the Pedersen commitment — audit F1); `alice_pk` is the Paillier key the
/// range bounds are taken relative to (a sub-`q⁷` one makes them vacuous —
/// audit F2). Called fail-closed at the top of every public prove entry
/// point before any secret-touching arithmetic runs.
fn validateReceivedParams(
    verifier_aux: root.AuxParams,
    alice_pk: paillier.PublicKey,
    random: std.Random,
) ProveError!void {
    try verifier_aux.validate(random);
    if (!root.paillierNMeetsFloor(alice_pk)) return error.InvalidAuxParams;
}

/// **GG18 Appendix A.1 "Range Proof", prover side — REAL, verified against
/// the paper.**
///
/// Construction exactly as the paper states it (see the module doc
/// comment for the retrieval provenance; `q` = secp256k1 group order;
/// `N`/`N²` = `alice_pk`'s Paillier modulus/its square; `Γ = N+1`;
/// `N_tilde`/`h1`/`h2` = `verifier_aux`, i.e. BOB's aux params — see the
/// module doc comment's "verifier-vs-prover aux-param ownership" note):
///
/// ```text
/// 1. Sample:
///      alpha ← Z_{q³}              // mask for m
///      beta  ← Z_N^*               // fresh Paillier randomness for `u`
///      gamma ← Z_{q³·N_tilde}      // Pedersen randomness for w
///      rho   ← Z_{q·N_tilde}       // Pedersen randomness for z
/// 2. Commit:
///      z = h1^m     * h2^rho   mod N_tilde
///      u = Γ^alpha  * beta^N   mod N²       // = Enc_A(alpha; beta)
///      w = h1^alpha * h2^gamma mod N_tilde
/// 3. Challenge (paper: interactive e ∈R Z_q; here Fiat-Shamir):
///      e = rangeProofChallenge(verifier_aux, alice_pk, c_a, z, u, w)
/// 4. Respond (s1/s2 are INTEGERS — no modular reduction):
///      s  = r_a^e * beta mod N
///      s1 = e*m   + alpha
///      s2 = e*rho + gamma
/// 5. Proof = RangeProof{ z, u, w, s, s1 (bytes), s2 (bytes) }
/// ```
///
/// `r_a` is the Paillier encryption randomness Alice used for `c_A =
/// Enc_A(a; r_a)` — the semi-honest `mtaAliceInit` discards this (it never
/// needed it), so this checked path's witness comes from
/// `mta.mtaAliceInitChecked` instead (see that function). `c_A` itself is
/// recomputed internally from `(a, r_a)` for the challenge transcript, so
/// the proof is guaranteed to bind to the exact ciphertext this witness
/// pair produces.
///
/// Timing posture: commitments use `ff`'s constant-time
/// `powWithEncodedExponent` with fixed-width exponent buffers (the secret
/// `m`/`alpha` never drive a variable exponent length); the plain-integer
/// response arithmetic (`mulAddOwned`) runs over fixed-width buffers too.
/// The rejection-sampling loops are variable-time in their own discarded
/// coins only. See SPEC.md's timing note.
pub fn proveAliceRange(
    allocator: std.mem.Allocator,
    a: Scalar,
    r_a: paillier.Fe,
    alice_pk: paillier.PublicKey,
    verifier_aux: root.AuxParams,
    random: std.Random,
) ProveError!RangeProof {
    try validateReceivedParams(verifier_aux, alice_pk, random); // audit F1/F2, fail-closed
    var a_bytes = a.toBytes(.big);
    defer std.crypto.secureZero(u8, &a_bytes);
    return proveAliceRangeInner(allocator, &a_bytes, r_a, alice_pk, verifier_aux, random);
}

/// `proveAliceRange` with the witness plaintext as raw big-endian bytes —
/// split out so the SECURITY-CRITICAL reject test below can produce an
/// honestly-CONSISTENT proof for an OUT-OF-RANGE `m` (> q³, inexpressible
/// through the `Scalar`-typed public API) and assert that `verifyAliceRange`
/// rejects it on the range check alone (equations 2/3 still hold — the
/// exact Alpha-Rays/TSSHOCK failure shape). `m_bytes` must be < N.
fn proveAliceRangeInner(
    allocator: std.mem.Allocator,
    m_bytes: []const u8,
    r_a: paillier.Fe,
    alice_pk: paillier.PublicKey,
    verifier_aux: root.AuxParams,
    random: std.Random,
) ProveError!RangeProof {
    const nt = verifier_aux.n_tilde;
    const nsq = alice_pk.n_sq;

    // Runtime bounds: q·N_tilde (for rho), q³·N_tilde (for gamma).
    var nt_buf: [root.aux_modulus_bytes]u8 = undefined;
    nt.toBytes(&nt_buf, .big) catch unreachable; // fixed-width buffer always sufficient
    const nt_bytes = stripLeadingZeros(&nt_buf);
    var q_nt_buf: [32 + root.aux_modulus_bytes]u8 = undefined;
    const q_nt = q_nt_buf[0 .. 32 + nt_bytes.len];
    mulBytes(&q_bytes, nt_bytes, q_nt);
    var q3_nt_buf: [96 + root.aux_modulus_bytes]u8 = undefined;
    const q3_nt = q3_nt_buf[0 .. 96 + nt_bytes.len];
    mulBytes(&q3_bytes, nt_bytes, q3_nt);

    // N as bytes (bound for beta).
    var n_buf: [paillier.modulus_bytes]u8 = undefined;
    const n_len = alice_pk.nByteLen();
    alice_pk.nToBytes(n_buf[0..n_len]) catch unreachable;

    // 1. Sample masks (all SECRET; zeroed on exit).
    var alpha: [96]u8 = undefined;
    defer std.crypto.secureZero(u8, &alpha);
    _ = sampleBelow(random, &q3_bytes, &alpha);
    var rho_buf: [32 + root.aux_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &rho_buf);
    const rho = sampleBelow(random, q_nt, &rho_buf);
    var gamma_buf: [96 + root.aux_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &gamma_buf);
    const gamma = sampleBelow(random, q3_nt, &gamma_buf);
    var beta_buf: [paillier.modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &beta_buf);
    const beta = sampleNonzeroBelow(random, n_buf[0..n_len], &beta_buf);

    // 2. Commit.
    const z = nt.mul(powCt(nt, verifier_aux.h1, m_bytes), powCt(nt, verifier_aux.h2, rho));
    // u = Enc_A(alpha; beta) — alpha < q³ < N for any >= 1024-bit key.
    const alpha_fe = paillier.Fe.fromBytes(nsq, &alpha, .big) catch unreachable;
    const beta_nsq = paillier.Fe.fromBytes(nsq, beta, .big) catch unreachable; // < N < N²
    const u = paillier.encrypt(alice_pk, alpha_fe, beta_nsq) catch unreachable; // beta nonzero by construction
    const w = nt.mul(powCt(nt, verifier_aux.h1, &alpha), powCt(nt, verifier_aux.h2, gamma));

    // 3. Fiat-Shamir challenge over the ciphertext this witness produces.
    const m_fe = paillier.Fe.fromBytes(nsq, stripLeadingZeros(m_bytes), .big) catch unreachable; // caller contract: m < N
    const c_a = paillier.encrypt(alice_pk, m_fe, r_a) catch unreachable; // r_a nonzero per witness contract
    const e = rangeProofChallenge(verifier_aux, alice_pk, c_a, z, u, w);
    const e_bytes = e.toBytes(.big);

    // 4. Respond. s = r_a^e * beta mod N (mod N, not N²!).
    var r_buf: [paillier.modulus_sq_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &r_buf);
    const nsq_len = (nsq.bits() + 7) / 8;
    r_a.toBytes(r_buf[0..nsq_len], .big) catch unreachable;
    const r_n = paillier.Fe.fromBytes(alice_pk.n, stripLeadingZeros(r_buf[0..nsq_len]), .big) catch unreachable; // r_a < N per witness contract
    const beta_n = paillier.Fe.fromBytes(alice_pk.n, beta, .big) catch unreachable;
    const s_n = alice_pk.n.mul(powCt(alice_pk.n, r_n, &e_bytes), beta_n);
    var s_buf: [paillier.modulus_bytes]u8 = undefined;
    s_n.toBytes(s_buf[0..n_len], .big) catch unreachable;
    const s = paillier.Fe.fromBytes(nsq, stripLeadingZeros(s_buf[0..n_len]), .big) catch unreachable; // canonical mod N² per struct contract

    const s1 = try mulAddOwned(allocator, &e_bytes, m_bytes, &alpha);
    errdefer allocator.free(s1);
    const s2 = try mulAddOwned(allocator, &e_bytes, rho, gamma);

    return .{ .z = z, .u = u, .w = w, .s = s, .s1 = s1, .s2 = s2 };
}

/// **GG18 Appendix A.1 "Range Proof", verifier side — REAL, verified
/// against the paper.** The paper's verifier: "checks that s1 <= q³,
/// u = Γ^{s1} s^N c^{-e} mod N² and h1^{s1} h2^{s2} z^{-e} = w mod Ñ."
/// Implemented in the inversion-free equivalent form (multiply both sides
/// by `c^e`/`z^e` — same equations, no modular inverse needed, and a
/// non-invertible attacker-chosen value can't crash the verifier):
///
/// ```text
/// e = rangeProofChallenge(verifier_aux, alice_pk, c_a, proof.z, proof.u, proof.w)
/// accept iff ALL of:
///   1. s1 (as a non-negative integer) <= q³
///   2. proof.u * c_a^e == Γ^s1 * proof.s^N   (mod N²)
///   3. proof.w * proof.z^e == h1^s1 * h2^s2  (mod N_tilde)
/// ```
///
/// Equation 2 is the "ciphertext consistency" check (ties the response
/// back to the SAME `a`/`alpha` that produced `c_a`/`u`); equation 3 is
/// the "commitment consistency" check (ties the response back to the
/// SAME `a`/`alpha` the Pedersen commitments `z`/`w` were built from).
/// Equation 1 is THE range check — a malicious Alice who used an
/// out-of-range `a` can satisfy equations 2/3 (they only bind
/// consistency, not range) but cannot make `s1` land inside `q³`
/// except with the Sigma protocol's soundness-error probability
/// (`~1/q`, from the challenge space). **This is the exact check that
/// stops the Alpha-Rays/TSSHOCK class of attack — do not weaken it.**
/// (Honest completeness slack: `s1 = e·m + alpha <= (q-1)² + q³-1`, which
/// exceeds `q³` only when `alpha > q³ - e·m`, probability < 1/q — the
/// paper's own negligible completeness error.)
///
/// Additional fail-closed sanity (degenerate-value hardening, mirroring
/// tss-lib's post-audit checks): zero `z`/`w`/`s`/`u` reject immediately.
///
/// Returns `bool` (no error union) — a malformed/out-of-range proof is a
/// REJECT, not a Zig error; callers (Bob's gate before operating on
/// `c_A`) turn `false` into their own fail-closed error. Variable-time
/// throughout: every input is public (the proof, the ciphertext, the
/// challenge).
pub fn verifyAliceRange(
    proof: RangeProof,
    c_a: paillier.Ciphertext,
    alice_pk: paillier.PublicKey,
    verifier_aux: root.AuxParams,
) bool {
    const nt = verifier_aux.n_tilde;
    const nsq = alice_pk.n_sq;

    // Audit F2 — key-size floor (fail closed): a range proof over a sub-q⁷
    // Paillier `N` / ring-Pedersen `Ñ` has a vacuous `s1 <= q³` bound, so
    // reject it outright rather than "verify" a proof that proves nothing.
    if (!root.paillierNMeetsFloor(alice_pk) or !root.nTildeMeetsFloor(nt)) return false;

    // Degenerate-value hardening (fail closed before any arithmetic).
    if (proof.z.isZero() or proof.w.isZero() or proof.s.isZero() or proof.u.c.isZero()) return false;
    if (c_a.c.isZero()) return false;

    // 1. THE range check: s1 <= q³.
    if (intCompare(proof.s1, &q3_bytes) == .gt) return false;

    const e = rangeProofChallenge(verifier_aux, alice_pk, c_a, proof.z, proof.u, proof.w);
    const e_bytes = e.toBytes(.big);

    // 2. u * c^e == Γ^s1 * s^N (mod N²).
    const lhs2 = nsq.mul(proof.u.c, powPub(nsq, c_a.c, &e_bytes));
    const g_s1 = gammaPowWide(alice_pk, proof.s1) orelse return false;
    var n_buf: [paillier.modulus_bytes]u8 = undefined;
    const n_len = alice_pk.nByteLen();
    alice_pk.nToBytes(n_buf[0..n_len]) catch return false;
    const rhs2 = nsq.mul(g_s1, powPub(nsq, proof.s, n_buf[0..n_len]));
    if (!pailFeEql(lhs2, rhs2)) return false;

    // 3. w * z^e == h1^s1 * h2^s2 (mod N_tilde).
    const lhs3 = nt.mul(proof.w, powPub(nt, proof.z, &e_bytes));
    const rhs3 = nt.mul(powPub(nt, verifier_aux.h1, proof.s1), powPub(nt, verifier_aux.h2, proof.s2));
    if (!auxFeEql(lhs3, rhs3)) return false;

    return true;
}

// ── MtaProof — Bob's MtA proof Π^MtA (STRUCT+CODEC real, MATH real, GG18 App. A) ──

/// GG18 Appendix A "Bob's MtA proof" (Π^MtA / Πᵢⱼ, naming varies by
/// edition): proves `c_B = c_A^b · Enc_A(β'; r_B)` — i.e. that `c_B` was
/// correctly derived from the PUBLIC `c_A` using a Bob-known `b` and a
/// fresh Bob-known Paillier blinding `r_B`, with both `b` and `β'` in
/// range — without revealing `b`, `β'`, or `r_B`.
///
/// This is the natural Sigma-protocol EXTENSION of `RangeProof` above: it
/// carries a Pedersen commitment / mask / response TRIPLE for `b` (like
/// `RangeProof`'s `a`), a SECOND commitment/mask/response triple for `β'`,
/// and one extra "homomorphic consistency" commitment `v` binding the two
/// together through `c_A`. Field roles per GG18 Appendix A.2/A.3's own
/// notation (`x := b`, `y := β'`, `z' := z1`, `Γ := N+1`; see
/// `proveBobMta`'s doc comment for the full prover/verifier steps and the
/// module doc comment for the two deliberate tss-lib/GG20 bound
/// hardenings):
///
///   - `z`  — Pedersen commitment to `b`: `z = h1^b · h2^rho mod N_tilde`.
///   - `z1` — Pedersen commitment to `b`'s mask `alpha`: `z1 = h1^alpha ·
///     h2^rho1 mod N_tilde`.
///   - `t`  — Pedersen commitment to `β'`: `t = h1^beta_prime · h2^sigma
///     mod N_tilde`.
///   - `v`  — the homomorphic-consistency commitment, binding `c_A` (via
///     the SAME mask `alpha` that masks `b`) to a fresh mask `delta` for
///     `β'`: `v = c_A^alpha · g^delta · beta^N mod N^2` (Alice's `N`).
///     THIS is what ties the proof to the SPECIFIC public `c_A`/`c_B`
///     pair, not just to `b`/`β'` in isolation.
///   - `w`  — Pedersen commitment to `delta` (the `β'`-mask): `w =
///     h1^delta · h2^tau mod N_tilde`.
///   - `s`  — the Paillier-randomness response for the fresh blind `r_B`:
///     `s = beta · r_B^e mod N` (canonical mod `alice_pk.n_sq`, same
///     Fe-construction-contract convention as `RangeProof.s`).
///   - `s1` — INTEGER range response for `b`: `s1 = alpha + e·b`.
///   - `s2` — INTEGER response for `z`'s Pedersen randomness: `s2 = rho1 +
///     e·rho`.
///   - `t1` — INTEGER range response for `β'`: `t1 = delta + e·beta_prime`.
///   - `t2` — INTEGER response for `t`'s Pedersen randomness: `t2 = tau +
///     e·sigma`.
pub const MtaProof = struct {
    z: root.AuxFe,
    z1: root.AuxFe,
    t: root.AuxFe,
    v: paillier.Ciphertext,
    w: root.AuxFe,
    s: paillier.Fe,
    /// Owned; free via `deinit`.
    s1: []const u8,
    /// Owned; free via `deinit`.
    s2: []const u8,
    /// Owned; free via `deinit`.
    t1: []const u8,
    /// Owned; free via `deinit`.
    t2: []const u8,

    pub fn deinit(self: MtaProof, allocator: std.mem.Allocator) void {
        allocator.free(self.s1);
        allocator.free(self.s2);
        allocator.free(self.t1);
        allocator.free(self.t2);
    }

    pub const ByteError = std.crypto.ff.OverflowError || std.crypto.ff.RepresentationError;
    pub const AllocError = std.mem.Allocator.Error || ByteError;

    /// `len-prefixed(z) || len-prefixed(z1) || len-prefixed(t) ||
    /// len-prefixed(v) || len-prefixed(w) || len-prefixed(s) ||
    /// len-prefixed(s1) || len-prefixed(s2) || len-prefixed(t1) ||
    /// len-prefixed(t2)`. REAL, mechanical.
    pub fn toBytesAlloc(self: MtaProof, allocator: std.mem.Allocator) AllocError![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(allocator);

        var z_buf: [root.aux_modulus_bytes]u8 = undefined;
        try self.z.toBytes(&z_buf, .big);
        try appendLenPrefixed(&list, allocator, &z_buf);

        var z1_buf: [root.aux_modulus_bytes]u8 = undefined;
        try self.z1.toBytes(&z1_buf, .big);
        try appendLenPrefixed(&list, allocator, &z1_buf);

        var t_buf: [root.aux_modulus_bytes]u8 = undefined;
        try self.t.toBytes(&t_buf, .big);
        try appendLenPrefixed(&list, allocator, &t_buf);

        var v_buf: [paillier.modulus_sq_bytes]u8 = undefined;
        try self.v.toBytes(&v_buf);
        try appendLenPrefixed(&list, allocator, &v_buf);

        var w_buf: [root.aux_modulus_bytes]u8 = undefined;
        try self.w.toBytes(&w_buf, .big);
        try appendLenPrefixed(&list, allocator, &w_buf);

        var s_buf: [paillier.modulus_sq_bytes]u8 = undefined;
        try self.s.toBytes(&s_buf, .big);
        try appendLenPrefixed(&list, allocator, &s_buf);

        try appendLenPrefixed(&list, allocator, self.s1);
        try appendLenPrefixed(&list, allocator, self.s2);
        try appendLenPrefixed(&list, allocator, self.t1);
        try appendLenPrefixed(&list, allocator, self.t2);

        return list.toOwnedSlice(allocator);
    }

    pub const FromBytesError = error{InvalidEncoding};

    /// Inverse of `toBytesAlloc`. Allocates `s1`/`s2`/`t1`/`t2`; free with
    /// `deinit`.
    pub fn fromBytesAlloc(
        allocator: std.mem.Allocator,
        n_tilde: root.AuxModulus,
        alice_pk: paillier.PublicKey,
        bytes: []const u8,
    ) (std.mem.Allocator.Error || FromBytesError)!MtaProof {
        var offset: usize = 0;

        const z_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const z = root.AuxFe.fromBytes(n_tilde, stripLeadingZeros(z_bytes), .big) catch return error.InvalidEncoding;

        const z1_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const z1 = root.AuxFe.fromBytes(n_tilde, stripLeadingZeros(z1_bytes), .big) catch return error.InvalidEncoding;

        const t_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const t_val = root.AuxFe.fromBytes(n_tilde, stripLeadingZeros(t_bytes), .big) catch return error.InvalidEncoding;

        const v_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const v = paillier.Ciphertext.fromBytes(alice_pk, v_bytes) catch return error.InvalidEncoding;

        const w_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const w = root.AuxFe.fromBytes(n_tilde, stripLeadingZeros(w_bytes), .big) catch return error.InvalidEncoding;

        const s_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const s = paillier.Fe.fromBytes(alice_pk.n_sq, stripLeadingZeros(s_bytes), .big) catch return error.InvalidEncoding;

        const s1_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const s1 = try allocator.dupe(u8, s1_bytes);
        errdefer allocator.free(s1);

        const s2_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const s2 = try allocator.dupe(u8, s2_bytes);
        errdefer allocator.free(s2);

        const t1_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const t1 = try allocator.dupe(u8, t1_bytes);
        errdefer allocator.free(t1);

        const t2_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const t2 = try allocator.dupe(u8, t2_bytes);

        return .{ .z = z, .z1 = z1, .t = t_val, .v = v, .w = w, .s = s, .s1 = s1, .s2 = s2, .t1 = t1, .t2 = t2 };
    }
};

/// **GG18 Appendix A.3 Bob's MtA proof (Π^MtA), prover side — REAL,
/// verified against the paper** (A.3 is A.2 minus the public-point check;
/// both are implemented by the shared `proveBobInner` below, exactly the
/// factoring tss-lib uses — `ProveBob` delegates to `ProveBobWC` with
/// `X = nil`).
///
/// Full construction, paper notation `x := b`, `y := β'`, `z' := z1`
/// (`verifier_aux` here is ALICE's aux params — see the module doc
/// comment's ownership note); ⚠ marks the two deliberate tss-lib/GG20
/// hardenings over the paper's A.2/A.3 sampling (see the module doc
/// comment):
///
/// ```text
/// 1. Sample masks:
///      alpha ← Z_{q³}                // mask for x (paper)
///      rho   ← Z_{q·N_tilde}         // Pedersen randomness for z (paper)
///      rho'  ← Z_{q³·N_tilde}        // Pedersen randomness for z1 (paper)
///      sigma ← Z_{q·N_tilde}         // Pedersen randomness for t (paper)
///      beta  ← Z_N^*                 // fresh Paillier randomness for v (paper)
///      gamma ← Z_{q⁷}                // ⚠ mask for y (paper: Z_N^*)
///      tau   ← Z_{q³·N_tilde}        // ⚠ Pedersen randomness for w (paper: Z_{q·N_tilde})
/// 2. Commit:
///      z  = h1^x     * h2^rho    mod N_tilde
///      z1 = h1^alpha * h2^rho'   mod N_tilde
///      t  = h1^y     * h2^sigma  mod N_tilde
///      v  = c_A^alpha * Γ^gamma * beta^N  mod N²
///      w  = h1^gamma * h2^tau    mod N_tilde
/// 3. Challenge (paper: interactive e ∈R Z_q; here Fiat-Shamir):
///      e = mtaProofChallenge(verifier_aux, alice_pk, c_a, c_b, z, z1, t, v, w)
/// 4. Respond (s1/s2/t1/t2 are INTEGERS — no modular reduction):
///      s  = r_b^e   * beta mod N
///      s1 = e*x     + alpha
///      s2 = e*rho   + rho'
///      t1 = e*y     + gamma
///      t2 = e*sigma + tau
/// 5. Proof = MtaProof{ z, z1, t, v, w, s, s1, s2, t1, t2 }
/// ```
///
/// `r_b` is the FRESH Paillier blinding factor Bob used when forming
/// `c_b`'s additive term — the semi-honest `mtaBobResponse` never
/// generates one (it uses `paillier.addPlaintext`'s deterministic `g^m`
/// term, with no `r^n` factor — see that function's doc comment), which
/// is exactly why the checked path calls `mta.mtaBobResponseChecked`
/// instead: it reconstructs `c_b` with an EXTRA fresh blind so this
/// witness exists. `c_b` itself is passed explicitly (not re-derived
/// internally) so the proof is guaranteed to bind to the SAME ciphertext
/// the caller will actually send Alice.
pub fn proveBobMta(
    allocator: std.mem.Allocator,
    b: Scalar,
    beta_prime: Scalar,
    r_b: paillier.Fe,
    c_a: paillier.Ciphertext,
    c_b: paillier.Ciphertext,
    alice_pk: paillier.PublicKey,
    verifier_aux: root.AuxParams,
    random: std.Random,
) ProveError!MtaProof {
    try validateReceivedParams(verifier_aux, alice_pk, random); // audit F1/F2, fail-closed
    var x_bytes = b.toBytes(.big);
    defer std.crypto.secureZero(u8, &x_bytes);
    var y_bytes = beta_prime.toBytes(.big);
    defer std.crypto.secureZero(u8, &y_bytes);
    const out = try proveBobInner(allocator, &x_bytes, &y_bytes, r_b, c_a, c_b, alice_pk, verifier_aux, null, random);
    return out.proof;
}

/// Shared prover for Π^MtA (A.3, `b_point == null`) and Π^MtAwc (A.2,
/// `b_point != null`) — the ONLY differences per the paper are (a) the
/// extra curve commitment `u1 = alpha·G` reusing the SAME `alpha`, and
/// (b) which transcript the challenge binds. Witnesses come in as raw
/// big-endian bytes so the SECURITY-CRITICAL reject tests can drive
/// out-of-range `x`/`y` (> q³ / > q⁷) that the `Scalar`-typed public API
/// cannot express. `x_bytes`/`y_bytes` must be < N.
fn proveBobInner(
    allocator: std.mem.Allocator,
    x_bytes: []const u8,
    y_bytes: []const u8,
    r_b: paillier.Fe,
    c_a: paillier.Ciphertext,
    c_b: paillier.Ciphertext,
    alice_pk: paillier.PublicKey,
    verifier_aux: root.AuxParams,
    b_point: ?root.Element,
    random: std.Random,
) ProveError!struct { proof: MtaProof, u1_point: ?root.Element } {
    const nt = verifier_aux.n_tilde;
    const nsq = alice_pk.n_sq;

    // Runtime bounds q·N_tilde / q³·N_tilde.
    var nt_buf: [root.aux_modulus_bytes]u8 = undefined;
    nt.toBytes(&nt_buf, .big) catch unreachable;
    const nt_bytes = stripLeadingZeros(&nt_buf);
    var q_nt_buf: [32 + root.aux_modulus_bytes]u8 = undefined;
    const q_nt = q_nt_buf[0 .. 32 + nt_bytes.len];
    mulBytes(&q_bytes, nt_bytes, q_nt);
    var q3_nt_buf: [96 + root.aux_modulus_bytes]u8 = undefined;
    const q3_nt = q3_nt_buf[0 .. 96 + nt_bytes.len];
    mulBytes(&q3_bytes, nt_bytes, q3_nt);

    var n_buf: [paillier.modulus_bytes]u8 = undefined;
    const n_len = alice_pk.nByteLen();
    alice_pk.nToBytes(n_buf[0..n_len]) catch unreachable;

    // 1. Sample masks (SECRET; zeroed on exit). For MtAwc, `alpha` also
    // serves as the Schnorr nonce for `u1 = alpha·G`, so redraw in the
    // (never-in-practice) case alpha ≡ 0 (mod q) where the curve API
    // rejects the identity result.
    var alpha: [96]u8 = undefined;
    defer std.crypto.secureZero(u8, &alpha);
    var u1_point: ?root.Element = null;
    while (true) {
        _ = sampleBelow(random, &q3_bytes, &alpha);
        if (b_point == null) break;
        const alpha_q = scalarFromWide(&alpha);
        const pt = root.Secp256k1.basePoint.mul(alpha_q.toBytes(.big), .big) catch continue;
        u1_point = root.Element.fromPoint(pt) catch continue;
        break;
    }
    var rho_buf: [32 + root.aux_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &rho_buf);
    const rho = sampleBelow(random, q_nt, &rho_buf);
    var rho_prime_buf: [96 + root.aux_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &rho_prime_buf);
    const rho_prime = sampleBelow(random, q3_nt, &rho_prime_buf);
    var sigma_buf: [32 + root.aux_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &sigma_buf);
    const sigma = sampleBelow(random, q_nt, &sigma_buf);
    var tau_buf: [96 + root.aux_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &tau_buf);
    const tau = sampleBelow(random, q3_nt, &tau_buf);
    var gamma: [224]u8 = undefined;
    defer std.crypto.secureZero(u8, &gamma);
    _ = sampleBelow(random, &q7_bytes, &gamma);
    var beta_buf: [paillier.modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &beta_buf);
    const beta = sampleNonzeroBelow(random, n_buf[0..n_len], &beta_buf);

    // 2. Commit.
    const z = nt.mul(powCt(nt, verifier_aux.h1, x_bytes), powCt(nt, verifier_aux.h2, rho));
    const z1 = nt.mul(powCt(nt, verifier_aux.h1, &alpha), powCt(nt, verifier_aux.h2, rho_prime));
    const t_commit = nt.mul(powCt(nt, verifier_aux.h1, y_bytes), powCt(nt, verifier_aux.h2, sigma));
    // v = c_A^alpha * Γ^gamma * beta^N mod N² — the Γ^gamma·beta^N factor
    // is exactly Enc_A(gamma; beta) (gamma < q⁷ < N² for >= 1024-bit keys;
    // the standard-generator binomial identity is valid for any gamma < N²).
    const gamma_fe = paillier.Fe.fromBytes(nsq, &gamma, .big) catch unreachable;
    const beta_nsq = paillier.Fe.fromBytes(nsq, beta, .big) catch unreachable;
    const enc_gamma = paillier.encrypt(alice_pk, gamma_fe, beta_nsq) catch unreachable; // beta nonzero
    const v: paillier.Ciphertext = .{ .c = nsq.mul(powCt(nsq, c_a.c, &alpha), enc_gamma.c) };
    const w = nt.mul(powCt(nt, verifier_aux.h1, &gamma), powCt(nt, verifier_aux.h2, tau));

    // 3. Challenge.
    const e = if (b_point) |bp|
        mtaProofWcChallenge(verifier_aux, alice_pk, c_a, c_b, z, z1, t_commit, v, w, bp, u1_point.?)
    else
        mtaProofChallenge(verifier_aux, alice_pk, c_a, c_b, z, z1, t_commit, v, w);
    const e_bytes = e.toBytes(.big);

    // 4. Respond. s = r_b^e * beta mod N.
    var r_buf: [paillier.modulus_sq_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &r_buf);
    const nsq_len = (nsq.bits() + 7) / 8;
    r_b.toBytes(r_buf[0..nsq_len], .big) catch unreachable;
    const r_n = paillier.Fe.fromBytes(alice_pk.n, stripLeadingZeros(r_buf[0..nsq_len]), .big) catch unreachable; // r_b < N per witness contract
    const beta_n = paillier.Fe.fromBytes(alice_pk.n, beta, .big) catch unreachable;
    const s_n = alice_pk.n.mul(powCt(alice_pk.n, r_n, &e_bytes), beta_n);
    var s_buf: [paillier.modulus_bytes]u8 = undefined;
    s_n.toBytes(s_buf[0..n_len], .big) catch unreachable;
    const s = paillier.Fe.fromBytes(nsq, stripLeadingZeros(s_buf[0..n_len]), .big) catch unreachable;

    const s1 = try mulAddOwned(allocator, &e_bytes, x_bytes, &alpha);
    errdefer allocator.free(s1);
    const s2 = try mulAddOwned(allocator, &e_bytes, rho, rho_prime);
    errdefer allocator.free(s2);
    const t1 = try mulAddOwned(allocator, &e_bytes, y_bytes, &gamma);
    errdefer allocator.free(t1);
    const t2 = try mulAddOwned(allocator, &e_bytes, sigma, tau);

    return .{
        .proof = .{ .z = z, .z1 = z1, .t = t_commit, .v = v, .w = w, .s = s, .s1 = s1, .s2 = s2, .t1 = t1, .t2 = t2 },
        .u1_point = u1_point,
    };
}

/// **GG18 Appendix A.3 Bob's MtA proof (Π^MtA), verifier side — REAL,
/// verified against the paper.** The paper's verifier: "checks that
/// s1 <= q³, h1^{s1} h2^{s2} = z^e z' mod Ñ, h1^{t1} h2^{t2} = t^e w mod
/// Ñ, and c1^{s1} s^N Γ^{t1} = c2^e v mod N²" — plus the ⚠ tss-lib/GG20
/// `t1 <= q⁷` hardening (see the module doc comment; the paper's own A.3
/// leaves `y = β'` unbounded and checks no `t1` bound — this module's
/// bound is strictly STRONGER, never weaker):
///
/// ```text
/// e = mtaProofChallenge(verifier_aux, alice_pk, c_a, c_b, proof.z, proof.z1,
///                        proof.t, proof.v, proof.w)
/// accept iff ALL of:
///   1. s1 (as a non-negative integer) <= q³
///   2. t1 (as a non-negative integer) <= q⁷    // ⚠ tss-lib/GG20 hardening
///   3. h1^s1 * h2^s2 == proof.z^e * proof.z1   (mod N_tilde)
///   4. h1^t1 * h2^t2 == proof.t^e * proof.w    (mod N_tilde)
///   5. c_a^s1 * proof.s^N * Γ^t1 == c_b^e * proof.v   (mod N²)
/// ```
///
/// Equation 5 is the load-bearing one: it is the ONLY check that ties the
/// proof to the SPECIFIC public `c_a`/`c_b` pair (via `c_a^s1` on the
/// left-hand side — the verifier, who does not know `b`/`alpha`, can
/// still compute this because `c_a` and `s1` are both public/revealed).
/// A malicious Bob who tampered with `c_b` after computing the proof, or
/// who used a `b`/`beta_prime` different from what the proof's masks
/// were built for, fails equation 5 (or, for out-of-range inputs,
/// equations 1/2) with overwhelming probability. **Do not weaken any of
/// these five checks — together they are the whole malicious-security
/// property this file exists to provide.** Variable-time throughout
/// (every input is public).
pub fn verifyBobMta(
    proof: MtaProof,
    c_a: paillier.Ciphertext,
    c_b: paillier.Ciphertext,
    alice_pk: paillier.PublicKey,
    verifier_aux: root.AuxParams,
) bool {
    return verifyBobInner(proof, c_a, c_b, alice_pk, verifier_aux, null, null);
}

/// Shared verifier for Π^MtA (A.3, `b_point == null`) and Π^MtAwc (A.2,
/// `b_point`/`u1_point` set) — same factoring as `proveBobInner`.
fn verifyBobInner(
    proof: MtaProof,
    c_a: paillier.Ciphertext,
    c_b: paillier.Ciphertext,
    alice_pk: paillier.PublicKey,
    verifier_aux: root.AuxParams,
    b_point: ?root.Element,
    u1_point: ?root.Element,
) bool {
    const nt = verifier_aux.n_tilde;
    const nsq = alice_pk.n_sq;

    // Audit F2 — key-size floor (fail closed): sub-q⁷ moduli make the
    // `s1 <= q³` / `t1 <= q⁷` bounds vacuous, so reject before verifying.
    if (!root.paillierNMeetsFloor(alice_pk) or !root.nTildeMeetsFloor(nt)) return false;

    // Degenerate-value hardening (fail closed before any arithmetic).
    if (proof.z.isZero() or proof.z1.isZero() or proof.t.isZero() or
        proof.w.isZero() or proof.s.isZero() or proof.v.c.isZero()) return false;
    if (c_a.c.isZero() or c_b.c.isZero()) return false;

    // 1./2. THE range checks.
    if (intCompare(proof.s1, &q3_bytes) == .gt) return false;
    if (intCompare(proof.t1, &q7_bytes) == .gt) return false;

    const e = if (b_point) |bp|
        mtaProofWcChallenge(verifier_aux, alice_pk, c_a, c_b, proof.z, proof.z1, proof.t, proof.v, proof.w, bp, u1_point.?)
    else
        mtaProofChallenge(verifier_aux, alice_pk, c_a, c_b, proof.z, proof.z1, proof.t, proof.v, proof.w);
    const e_bytes = e.toBytes(.big);

    // 6. (MtAwc only) [s1 mod q]·G == [e]·B + u1 — the paper's
    // "g^{s1} = X^e u ∈ G" check; s1 is reduced mod q HERE ONLY (the
    // Paillier-side checks below use the unreduced integer s1).
    if (b_point) |bp| {
        const s1_q = scalarFromWide(proof.s1);
        const lhs = root.Secp256k1.basePoint.mul(s1_q.toBytes(.big), .big) catch return false;
        const b_pt = bp.point() catch return false;
        const b_e = b_pt.mul(e_bytes, .big) catch return false;
        const u1_pt = (u1_point.?).point() catch return false;
        if (!lhs.equivalent(b_e.add(u1_pt))) return false;
    }

    // 3. h1^s1 * h2^s2 == z^e * z1 (mod N_tilde).
    const lhs3 = nt.mul(powPub(nt, verifier_aux.h1, proof.s1), powPub(nt, verifier_aux.h2, proof.s2));
    const rhs3 = nt.mul(powPub(nt, proof.z, &e_bytes), proof.z1);
    if (!auxFeEql(lhs3, rhs3)) return false;

    // 4. h1^t1 * h2^t2 == t^e * w (mod N_tilde).
    const lhs4 = nt.mul(powPub(nt, verifier_aux.h1, proof.t1), powPub(nt, verifier_aux.h2, proof.t2));
    const rhs4 = nt.mul(powPub(nt, proof.t, &e_bytes), proof.w);
    if (!auxFeEql(lhs4, rhs4)) return false;

    // 5. c_a^s1 * s^N * Γ^t1 == c_b^e * v (mod N²).
    var n_buf: [paillier.modulus_bytes]u8 = undefined;
    const n_len = alice_pk.nByteLen();
    alice_pk.nToBytes(n_buf[0..n_len]) catch return false;
    const g_t1 = gammaPowWide(alice_pk, proof.t1) orelse return false;
    const lhs5 = nsq.mul(nsq.mul(powPub(nsq, c_a.c, proof.s1), powPub(nsq, proof.s, n_buf[0..n_len])), g_t1);
    const rhs5 = nsq.mul(powPub(nsq, c_b.c, &e_bytes), proof.v.c);
    if (!pailFeEql(lhs5, rhs5)) return false;

    return true;
}

// ── MtaProofWc — MtA "with check" Π^MtAwc (STRUCT real, MATH real, GG18 App. A) ───

/// GG18/GG20 "MtA with check" (Π^MtAwc): `MtaProof` PLUS a Schnorr-style
/// EC commitment proving the SAME `b` also satisfies `b·G == B` for a
/// PUBLIC point `B` the parties already agreed on. This is the variant
/// GG20's signing round needs for the `k·x` share conversion (where `B`
/// is a party's already-published EC public-key share) — see this
/// module's doc comment and `SPEC.md`'s Phase-2c/2d boundary note for
/// exactly where MtAwc is invoked versus plain MtA.
///
/// `u1_point = alpha·G` REUSES `base`'s exponent-mask `alpha` (the same one
/// that masks `b` in `base.z1`/`base.s1`) — the standard "prove once, use
/// for both" economy: since `alpha` already masks `b` for the Paillier
/// side, the SAME mask serves as a Schnorr nonce for the EC side, and
/// the SAME integer response `base.s1` (reduced mod `q` for the EC
/// check specifically — `s1` itself is NOT bounded by `q`, only its
/// value mod `q` is meaningful as a curve scalar) verifies both.
/// **CONFIRMED against GG18 Appendix A.2** (the scaffold's open question,
/// now resolved): the paper's prover "selects alpha ∈R Z_{q³}" ONCE and
/// "computes u = g^alpha" from that same alpha (no distinct EC-only
/// mask), and the paper's verifier checks `g^{s1} = X^e·u ∈ G` with the
/// same `s1 = ex + alpha` the Paillier-side equations use. tss-lib's
/// `ProveBobWC` (`u = ScalarBaseMult(ec, alpha)`, verify
/// `g^{s1 mod q} == X^e·U`) matches.
pub const MtaProofWc = struct {
    base: MtaProof,
    /// `u1_point = alpha·G` — the Schnorr commitment binding `base`'s mask to
    /// the public point check.
    u1_point: root.Element,

    pub fn deinit(self: MtaProofWc, allocator: std.mem.Allocator) void {
        self.base.deinit(allocator);
    }

    pub const AllocError = MtaProof.AllocError;

    /// `len-prefixed(base.toBytesAlloc()) || u1_point (33 bytes)`. REAL,
    /// mechanical.
    pub fn toBytesAlloc(self: MtaProofWc, allocator: std.mem.Allocator) AllocError![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(allocator);

        const base_bytes = try self.base.toBytesAlloc(allocator);
        defer allocator.free(base_bytes);
        try appendLenPrefixed(&list, allocator, base_bytes);

        try list.appendSlice(allocator, &self.u1_point.toBytes());

        return list.toOwnedSlice(allocator);
    }

    pub const FromBytesError = error{InvalidEncoding} || MtaProof.FromBytesError || root.ElementError;

    pub fn fromBytesAlloc(
        allocator: std.mem.Allocator,
        n_tilde: root.AuxModulus,
        alice_pk: paillier.PublicKey,
        bytes: []const u8,
    ) (std.mem.Allocator.Error || FromBytesError)!MtaProofWc {
        var offset: usize = 0;
        const base_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const base = try MtaProof.fromBytesAlloc(allocator, n_tilde, alice_pk, base_bytes);
        errdefer base.deinit(allocator);

        if (bytes.len < offset + root.Ne) return error.InvalidEncoding;
        const u1_point = try root.Element.fromBytes(bytes[offset..][0..root.Ne].*);

        return .{ .base = base, .u1_point = u1_point };
    }
};

/// **GG18 Appendix A.2 "Respondent ZK Proof for MtAwc", prover side —
/// REAL, verified against the paper.** Runs `proveBobMta`'s construction
/// (the shared `proveBobInner`) with the paper's ONE addition: after
/// sampling `alpha` in step 1, also compute `u1_point = alpha·G` (the
/// paper's `u = g^alpha ∈ G`, same `alpha` — see `MtaProofWc`'s doc
/// comment for the paper-confirmed mask reuse) and derive the challenge
/// via `mtaProofWcChallenge` (which also binds the public point
/// `b_point = B = b·G`) instead of `mtaProofChallenge`.
pub fn proveBobMtaWc(
    allocator: std.mem.Allocator,
    b: Scalar,
    beta_prime: Scalar,
    r_b: paillier.Fe,
    c_a: paillier.Ciphertext,
    c_b: paillier.Ciphertext,
    alice_pk: paillier.PublicKey,
    verifier_aux: root.AuxParams,
    b_point: root.Element,
    random: std.Random,
) ProveError!MtaProofWc {
    try validateReceivedParams(verifier_aux, alice_pk, random); // audit F1/F2, fail-closed
    var x_bytes = b.toBytes(.big);
    defer std.crypto.secureZero(u8, &x_bytes);
    var y_bytes = beta_prime.toBytes(.big);
    defer std.crypto.secureZero(u8, &y_bytes);
    const out = try proveBobInner(allocator, &x_bytes, &y_bytes, r_b, c_a, c_b, alice_pk, verifier_aux, b_point, random);
    return .{ .base = out.proof, .u1_point = out.u1_point.? };
}

/// **GG18 Appendix A.2 "Respondent ZK Proof for MtAwc", verifier side —
/// REAL, verified against the paper.** Runs `verifyBobMta`'s five checks
/// (against `proof.base`, with the challenge bound to the Wc transcript
/// including `b_point`/`u1_point`) PLUS the paper's sixth check
/// (`g^{s1} = X^e·u ∈ G`):
///
/// ```text
/// 6. [s1 mod q]*G == [e]*b_point + proof.u1_point   (Schnorr verification,
///                                                 EC group addition;
///                                                 s1 reduced mod q here
///                                                 ONLY — the Paillier-
///                                                 side checks use the
///                                                 unreduced integer s1)
/// ```
///
/// This is what forces Bob's MtA input `b` to be the SAME `b` behind the
/// already-public point `B` (a key-share commitment in GG20's signing
/// use) — without it a malicious Bob could pass the range proof for one
/// `b` while `B` commits to another.
pub fn verifyBobMtaWc(
    proof: MtaProofWc,
    c_a: paillier.Ciphertext,
    c_b: paillier.Ciphertext,
    alice_pk: paillier.PublicKey,
    verifier_aux: root.AuxParams,
    b_point: root.Element,
) bool {
    return verifyBobInner(proof.base, c_a, c_b, alice_pk, verifier_aux, b_point, proof.u1_point);
}

// ── tests ────────────────────────────────────────────────────────────────
//
// No cross-implementation KAT exists for these proofs (the Fiat-Shamir
// transcript is implementation-defined — see the module doc comment's
// "verification level" section), so the net is: (a) mechanical
// Transcript/codec tests; (b) honest-accept self-consistency over REAL
// Paillier keys and real-composite ring-Pedersen parameters; (c) the
// SECURITY-CRITICAL reject tests — out-of-range witnesses (driven through
// the byte-level inner provers, since the Scalar-typed public API cannot
// even express an out-of-range input), tampered ciphertexts, wrong
// witnesses, wrong public point, and per-field proof mangling. (c) is the
// load-bearing group: a prove/verify pair that always returned true would
// pass every accept test and fail every one of these.

const testing = std.testing;

fn scalarFromU64(v: u64) Scalar {
    var buf = [_]u8{0} ** 48;
    std.mem.writeInt(u64, buf[40..48], v, .big);
    return Scalar.fromBytes48(buf, .big);
}

/// Byte-exact equality for two `std.crypto.ff.Fe` values sharing the same
/// (comptime-fixed) backing buffer width — `AuxFe` (`root.aux_modulus_bytes`)
/// or `paillier.Fe` (`paillier.modulus_sq_bytes`).
fn expectFeEqual(comptime buf_len: usize, a: anytype, b: @TypeOf(a)) !void {
    var a_buf: [buf_len]u8 = undefined;
    try a.toBytes(&a_buf, .big);
    var b_buf: [buf_len]u8 = undefined;
    try b.toBytes(&b_buf, .big);
    try testing.expectEqualSlices(u8, &a_buf, &b_buf);
}

/// Byte-exact equality for two `paillier.Ciphertext` values.
fn expectCiphertextEqual(a: paillier.Ciphertext, b: paillier.Ciphertext) !void {
    var a_buf: [paillier.modulus_sq_bytes]u8 = undefined;
    try a.toBytes(&a_buf);
    var b_buf: [paillier.modulus_sq_bytes]u8 = undefined;
    try b.toBytes(&b_buf);
    try testing.expectEqualSlices(u8, &a_buf, &b_buf);
}

// -- Transcript: real, must pass --

test "Transcript: deterministic and input-sensitive" {
    var t1 = Transcript.init(range_proof_domain);
    t1.appendScalar(scalarFromU64(1));
    t1.appendScalar(scalarFromU64(2));
    const e1 = t1.finalize();

    var t2 = Transcript.init(range_proof_domain);
    t2.appendScalar(scalarFromU64(1));
    t2.appendScalar(scalarFromU64(2));
    const e2 = t2.finalize();
    try testing.expectEqualSlices(u8, &e1.toBytes(.big), &e2.toBytes(.big));

    // Different input -> (overwhelmingly likely) different challenge.
    var t3 = Transcript.init(range_proof_domain);
    t3.appendScalar(scalarFromU64(1));
    t3.appendScalar(scalarFromU64(3));
    const e3 = t3.finalize();
    try testing.expect(!std.mem.eql(u8, &e1.toBytes(.big), &e3.toBytes(.big)));
}

test "Transcript: domain-separated across proof kinds for identical input" {
    var tr = Transcript.init(range_proof_domain);
    tr.appendScalar(scalarFromU64(42));
    const e_range = tr.finalize();

    var tm = Transcript.init(mta_proof_domain);
    tm.appendScalar(scalarFromU64(42));
    const e_mta = tm.finalize();

    var tw = Transcript.init(mta_proof_wc_domain);
    tw.appendScalar(scalarFromU64(42));
    const e_wc = tw.finalize();

    try testing.expect(!std.mem.eql(u8, &e_range.toBytes(.big), &e_mta.toBytes(.big)));
    try testing.expect(!std.mem.eql(u8, &e_mta.toBytes(.big), &e_wc.toBytes(.big)));
    try testing.expect(!std.mem.eql(u8, &e_range.toBytes(.big), &e_wc.toBytes(.big)));
}

test "Transcript: length-prefixing prevents ambiguous concatenation" {
    // "ab" then "c" must NOT hash the same as "a" then "bc".
    var ta = Transcript.init(range_proof_domain);
    ta.appendBytes("ab");
    ta.appendBytes("c");
    const ea = ta.finalize();

    var tb = Transcript.init(range_proof_domain);
    tb.appendBytes("a");
    tb.appendBytes("bc");
    const eb = tb.finalize();

    try testing.expect(!std.mem.eql(u8, &ea.toBytes(.big), &eb.toBytes(.big)));
}

// -- helpers for the struct/codec tests below --

fn toyAuxAndKey(seed: u8) struct { aux: root.AuxParams, pk: paillier.KeyPair } {
    var kprng = std.Random.DefaultPrng.init(@as(u64, 0x7a6b70_726f6f66) ^ @as(u64, seed)); // "zkproof"-ish
    const kp = paillier.generate(kprng.random(), 1024) catch unreachable;

    // Toy (non-secure) hand-built AuxParams, same shape mta.zig's own
    // "compose over real KeyShare material" test uses — only the STRUCT/
    // CODEC is being exercised here, not the number theory.
    const n_tilde = root.AuxModulus.fromBytes(&[_]u8{187}, .big) catch unreachable;
    const aux: root.AuxParams = .{
        .n_tilde = n_tilde,
        .h1 = root.AuxFe.fromBytes(n_tilde, &[_]u8{5}, .big) catch unreachable,
        .h2 = root.AuxFe.fromBytes(n_tilde, &[_]u8{25}, .big) catch unreachable,
    };
    return .{ .aux = aux, .pk = kp };
}

// -- RangeProof / MtaProof / MtaProofWc: struct+codec real, must pass --

test "RangeProof: toBytesAlloc/fromBytesAlloc round-trip on hand-built values" {
    const allocator = testing.allocator;
    const setup = toyAuxAndKey(1);

    var prng = std.Random.DefaultPrng.init(0x72616e6765);
    const random = prng.random();
    const c = paillier.encryptRandom(setup.pk.public, paillier.Fe.fromBytes(setup.pk.public.n_sq, &[_]u8{7}, .big) catch unreachable, random) catch unreachable;

    const proof: RangeProof = .{
        .z = setup.aux.h1,
        .u = c,
        .w = setup.aux.h2,
        .s = paillier.Fe.fromBytes(setup.pk.public.n_sq, &[_]u8{9}, .big) catch unreachable,
        .s1 = try allocator.dupe(u8, &[_]u8{ 0x01, 0x02, 0x03 }),
        .s2 = try allocator.dupe(u8, &[_]u8{0xff}),
    };
    defer proof.deinit(allocator);

    const bytes = try proof.toBytesAlloc(allocator);
    defer allocator.free(bytes);

    const back = try RangeProof.fromBytesAlloc(allocator, setup.aux.n_tilde, setup.pk.public, bytes);
    defer back.deinit(allocator);

    try expectFeEqual(root.aux_modulus_bytes, proof.z, back.z);
    try expectFeEqual(root.aux_modulus_bytes, proof.w, back.w);
    try expectFeEqual(paillier.modulus_sq_bytes, proof.s, back.s);
    try testing.expectEqualSlices(u8, proof.s1, back.s1);
    try testing.expectEqualSlices(u8, proof.s2, back.s2);
}

test "MtaProof: toBytesAlloc/fromBytesAlloc round-trip on hand-built values" {
    const allocator = testing.allocator;
    const setup = toyAuxAndKey(2);

    var prng = std.Random.DefaultPrng.init(0x6d7461707266);
    const random = prng.random();
    const c = paillier.encryptRandom(setup.pk.public, paillier.Fe.fromBytes(setup.pk.public.n_sq, &[_]u8{11}, .big) catch unreachable, random) catch unreachable;

    const proof: MtaProof = .{
        .z = setup.aux.h1,
        .z1 = setup.aux.h2,
        .t = setup.aux.h1,
        .v = c,
        .w = setup.aux.h2,
        .s = paillier.Fe.fromBytes(setup.pk.public.n_sq, &[_]u8{13}, .big) catch unreachable,
        .s1 = try allocator.dupe(u8, &[_]u8{0x11}),
        .s2 = try allocator.dupe(u8, &[_]u8{0x22}),
        .t1 = try allocator.dupe(u8, &[_]u8{0x33}),
        .t2 = try allocator.dupe(u8, &[_]u8{0x44}),
    };
    defer proof.deinit(allocator);

    const bytes = try proof.toBytesAlloc(allocator);
    defer allocator.free(bytes);

    const back = try MtaProof.fromBytesAlloc(allocator, setup.aux.n_tilde, setup.pk.public, bytes);
    defer back.deinit(allocator);

    try testing.expectEqualSlices(u8, proof.s1, back.s1);
    try testing.expectEqualSlices(u8, proof.s2, back.s2);
    try testing.expectEqualSlices(u8, proof.t1, back.t1);
    try testing.expectEqualSlices(u8, proof.t2, back.t2);
    try expectCiphertextEqual(proof.v, back.v);
}

test "MtaProofWc: toBytesAlloc/fromBytesAlloc round-trip on hand-built values" {
    const allocator = testing.allocator;
    const setup = toyAuxAndKey(3);

    var prng = std.Random.DefaultPrng.init(0x6d7461777072);
    const random = prng.random();
    const c = paillier.encryptRandom(setup.pk.public, paillier.Fe.fromBytes(setup.pk.public.n_sq, &[_]u8{3}, .big) catch unreachable, random) catch unreachable;

    const base: MtaProof = .{
        .z = setup.aux.h1,
        .z1 = setup.aux.h2,
        .t = setup.aux.h1,
        .v = c,
        .w = setup.aux.h2,
        .s = paillier.Fe.fromBytes(setup.pk.public.n_sq, &[_]u8{15}, .big) catch unreachable,
        .s1 = try allocator.dupe(u8, &[_]u8{0xaa}),
        .s2 = try allocator.dupe(u8, &[_]u8{0xbb}),
        .t1 = try allocator.dupe(u8, &[_]u8{0xcc}),
        .t2 = try allocator.dupe(u8, &[_]u8{0xdd}),
    };
    const u1_point = root.Element.fromPoint(root.Secp256k1.basePoint) catch unreachable;
    const proof: MtaProofWc = .{ .base = base, .u1_point = u1_point };
    defer proof.deinit(allocator);

    const bytes = try proof.toBytesAlloc(allocator);
    defer allocator.free(bytes);

    const back = try MtaProofWc.fromBytesAlloc(allocator, setup.aux.n_tilde, setup.pk.public, bytes);
    defer back.deinit(allocator);

    try testing.expectEqualSlices(u8, &proof.u1_point.toBytes(), &back.u1_point.toBytes());
    try testing.expectEqualSlices(u8, proof.base.s1, back.base.s1);
}

// -- honest accept / reject: the real Phase-2c security net --

/// A REAL test fixture: a **2048-bit** Alice Paillier key plus ring-Pedersen
/// params over a genuine **2048-bit** two-prime composite `N_tilde` with `h1`
/// a square and `h2 = h1^lambda` (the same shape `root.generateAuxParams`
/// produces, minus the safe-prime search — completeness/reject behavior
/// doesn't depend on safe primes). **Sized at 2048 bits (not the old 1024 /
/// 512) because the audit-F2 floor now REQUIRES every checked-path Paillier
/// `N` and aux `Ñ` to exceed `q⁷ ≈ 2^1792`** — below that the `t1 <= q⁷`
/// range bound is vacuous. Callers of this fixture are consequently gated to
/// ReleaseFast (the 2048-bit safe-prime-free keygen is slow in Debug).
fn realAuxAndKey(seed: u64) !struct { kp: paillier.KeyPair, aux: root.AuxParams } {
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    const kp = try paillier.generate(random, 2048);
    const nt_kp = try paillier.generate(random, 2048);

    var nt_buf: [paillier.modulus_bytes]u8 = undefined;
    const nt_len = nt_kp.public.nByteLen();
    nt_kp.public.nToBytes(nt_buf[0..nt_len]) catch unreachable;
    const n_tilde = root.AuxModulus.fromBytes(stripLeadingZeros(nt_buf[0..nt_len]), .big) catch unreachable;

    var x_buf: [paillier.modulus_bytes]u8 = undefined;
    const x_bytes = sampleNonzeroBelow(random, nt_buf[0..nt_len], &x_buf);
    const x = root.AuxFe.fromBytes(n_tilde, stripLeadingZeros(x_bytes), .big) catch unreachable;
    const h1 = n_tilde.sq(x);
    var l_buf: [paillier.modulus_bytes]u8 = undefined;
    const lambda_bytes = sampleNonzeroBelow(random, nt_buf[0..nt_len], &l_buf);
    const h2 = powCt(n_tilde, h1, lambda_bytes);

    return .{ .kp = kp, .aux = .{ .n_tilde = n_tilde, .h1 = h1, .h2 = h2 } };
}

/// Uniform Paillier randomness in [1, N), canonical mod N² — the same
/// draw `mta.samplePaillierRandomness`/`paillier.sampleNonzeroLtN` make
/// (duplicated per the repo's small-helper convention; importing mta.zig
/// here would create the import cycle this file avoids).
fn testPaillierRandomness(pk: paillier.PublicKey, random: std.Random) paillier.Fe {
    var n_buf: [paillier.modulus_bytes]u8 = undefined;
    const n_len = pk.nByteLen();
    pk.nToBytes(n_buf[0..n_len]) catch unreachable;
    var r_buf: [paillier.modulus_bytes]u8 = undefined;
    const r = sampleNonzeroBelow(random, n_buf[0..n_len], &r_buf);
    return paillier.Fe.fromBytes(pk.n_sq, stripLeadingZeros(r), .big) catch unreachable;
}

fn scalarToTestFe(s: Scalar, pk: paillier.PublicKey) paillier.Fe {
    const bytes = s.toBytes(.big);
    return paillier.Fe.fromBytes(pk.n_sq, &bytes, .big) catch unreachable;
}

/// Build the checked-MtA-shaped `c_B = c_A^x · Enc_A(y; r_b)` the Bob
/// proofs are ABOUT (mirrors `mta.mtaBobResponseChecked`'s composition,
/// with byte-level `x`/`y` so the out-of-range reject tests can exceed
/// the Scalar domain).
fn buildCb(pk: paillier.PublicKey, c_a: paillier.Ciphertext, x_bytes: []const u8, y_bytes: []const u8, r_b: paillier.Fe) paillier.Ciphertext {
    const x_fe = paillier.Fe.fromBytes(pk.n_sq, stripLeadingZeros(x_bytes), .big) catch unreachable;
    const y_fe = paillier.Fe.fromBytes(pk.n_sq, stripLeadingZeros(y_bytes), .big) catch unreachable;
    const c_ax = paillier.mulPlaintext(pk, c_a, x_fe) catch unreachable;
    const enc_y = paillier.encrypt(pk, y_fe, r_b) catch unreachable;
    return paillier.addCiphertexts(pk, c_ax, enc_y);
}

test "GG18 A.1 honest accept: Alice's range proof verifies, and re-verifies after a codec round-trip" {
    if (builtin.mode == .Debug) return error.SkipZigTest; // 2048-bit keygen: ReleaseFast only
    const allocator = testing.allocator;
    const setup = try realAuxAndKey(0xa11ce_0001);
    const pk = setup.kp.public;

    var prng = std.Random.DefaultPrng.init(0x686f6e657374); // "honest"
    const random = prng.random();

    const a = scalarFromU64(0xa11ce);
    const r_a = testPaillierRandomness(pk, random);
    // c_a is the SAME (a, r_a) pair proveAliceRange is given as witness.
    const c_a = paillier.encrypt(pk, scalarToTestFe(a, pk), r_a) catch unreachable;

    const proof = try proveAliceRange(allocator, a, r_a, pk, setup.aux, random);
    defer proof.deinit(allocator);
    try testing.expect(verifyAliceRange(proof, c_a, pk, setup.aux));

    // Wire-format round-trip must verify identically (a proof is bytes on
    // a real network).
    const bytes = try proof.toBytesAlloc(allocator);
    defer allocator.free(bytes);
    const back = try RangeProof.fromBytesAlloc(allocator, setup.aux.n_tilde, pk, bytes);
    defer back.deinit(allocator);
    try testing.expect(verifyAliceRange(back, c_a, pk, setup.aux));
}

test "GG18 A.1 reject (SECURITY-CRITICAL): out-of-range a fails the range check even though the consistency equations hold" {
    // The Alpha-Rays/TSSHOCK shape: an honestly-CONSISTENT proof for
    // m = 2q³ (equations 2/3 hold by construction — the prover ran the
    // real protocol on the real witness) must be rejected by equation 1
    // alone. Driven through the byte-level inner prover because the
    // Scalar-typed public API cannot even express m > q.
    if (builtin.mode == .Debug) return error.SkipZigTest; // 2048-bit keygen: ReleaseFast only
    const allocator = testing.allocator;
    const setup = try realAuxAndKey(0xa11ce_0002);
    const pk = setup.kp.public;

    var prng = std.Random.DefaultPrng.init(0x6f75746f66); // "outof"
    const random = prng.random();

    const m_big = comptime comptimeIntBytes(97, 2 * (q_int * q_int * q_int)); // 2q³ < N (1024-bit)
    const r_a = testPaillierRandomness(pk, random);
    const m_fe = paillier.Fe.fromBytes(pk.n_sq, &m_big, .big) catch unreachable;
    const c_a = paillier.encrypt(pk, m_fe, r_a) catch unreachable;

    const proof = try proveAliceRangeInner(allocator, &m_big, r_a, pk, setup.aux, random);
    defer proof.deinit(allocator);
    try testing.expect(!verifyAliceRange(proof, c_a, pk, setup.aux));

    // Control in the same fixture: an in-range witness DOES verify (so
    // the reject above is the range check, not a broken fixture).
    const a_ok = scalarFromU64(0x5eed);
    const r_ok = testPaillierRandomness(pk, random);
    const c_ok = paillier.encrypt(pk, scalarToTestFe(a_ok, pk), r_ok) catch unreachable;
    const proof_ok = try proveAliceRange(allocator, a_ok, r_ok, pk, setup.aux, random);
    defer proof_ok.deinit(allocator);
    try testing.expect(verifyAliceRange(proof_ok, c_ok, pk, setup.aux));
}

test "GG18 A.1 reject (SECURITY-CRITICAL): tampered c_a and every mangled proof field" {
    if (builtin.mode == .Debug) return error.SkipZigTest; // 2048-bit keygen: ReleaseFast only
    const allocator = testing.allocator;
    const setup = try realAuxAndKey(0xa11ce_0003);
    const pk = setup.kp.public;
    const nt = setup.aux.n_tilde;

    var prng = std.Random.DefaultPrng.init(0x74616d706572); // "tamper"
    const random = prng.random();

    const a = scalarFromU64(0xfeed);
    const r_a = testPaillierRandomness(pk, random);
    const c_a = paillier.encrypt(pk, scalarToTestFe(a, pk), r_a) catch unreachable;
    const proof = try proveAliceRange(allocator, a, r_a, pk, setup.aux, random);
    defer proof.deinit(allocator);
    try testing.expect(verifyAliceRange(proof, c_a, pk, setup.aux)); // control

    // Tampered ciphertext: same proof, homomorphically-shifted c_a.
    const one_fe = paillier.Fe.fromPrimitive(u64, pk.n_sq, 1) catch unreachable;
    const c_bad = paillier.addPlaintext(pk, c_a, one_fe) catch unreachable;
    try testing.expect(!verifyAliceRange(proof, c_bad, pk, setup.aux));

    // Every field mangled (value-level perturbations that keep each field
    // well-formed, so the REJECT comes from the equations, not a parser).
    var bad = proof;
    bad.z = nt.mul(proof.z, setup.aux.h1);
    try testing.expect(!verifyAliceRange(bad, c_a, pk, setup.aux));
    bad = proof;
    bad.u = .{ .c = pk.n_sq.mul(proof.u.c, proof.u.c) };
    try testing.expect(!verifyAliceRange(bad, c_a, pk, setup.aux));
    bad = proof;
    bad.w = nt.mul(proof.w, setup.aux.h2);
    try testing.expect(!verifyAliceRange(bad, c_a, pk, setup.aux));
    bad = proof;
    bad.s = pk.n_sq.mul(proof.s, proof.s);
    try testing.expect(!verifyAliceRange(bad, c_a, pk, setup.aux));

    var s1_mangled = try allocator.dupe(u8, proof.s1);
    defer allocator.free(s1_mangled);
    s1_mangled[s1_mangled.len - 1] ^= 0x01;
    bad = proof;
    bad.s1 = s1_mangled;
    try testing.expect(!verifyAliceRange(bad, c_a, pk, setup.aux));

    var s2_mangled = try allocator.dupe(u8, proof.s2);
    defer allocator.free(s2_mangled);
    s2_mangled[s2_mangled.len - 1] ^= 0x01;
    bad = proof;
    bad.s2 = s2_mangled;
    try testing.expect(!verifyAliceRange(bad, c_a, pk, setup.aux));
}

test "GG18 A.3 honest accept: Bob's MtA proof over checked-MtA-shaped ciphertexts, and after a codec round-trip" {
    if (builtin.mode == .Debug) return error.SkipZigTest; // 2048-bit keygen: ReleaseFast only
    const allocator = testing.allocator;
    const setup = try realAuxAndKey(0xb0b_0001);
    const pk = setup.kp.public;

    var prng = std.Random.DefaultPrng.init(0x6d7461_6f6b); // "mta ok"
    const random = prng.random();

    const a = scalarFromU64(0xdeadbeef);
    const b = scalarFromU64(0xfeedface);
    const beta_prime = scalarFromU64(0xb14b);
    const r_a = testPaillierRandomness(pk, random);
    const r_b = testPaillierRandomness(pk, random);
    const c_a = paillier.encrypt(pk, scalarToTestFe(a, pk), r_a) catch unreachable;
    const b_bytes = b.toBytes(.big);
    const bp_bytes = beta_prime.toBytes(.big);
    const c_b = buildCb(pk, c_a, &b_bytes, &bp_bytes, r_b);

    const proof = try proveBobMta(allocator, b, beta_prime, r_b, c_a, c_b, pk, setup.aux, random);
    defer proof.deinit(allocator);
    try testing.expect(verifyBobMta(proof, c_a, c_b, pk, setup.aux));

    const bytes = try proof.toBytesAlloc(allocator);
    defer allocator.free(bytes);
    const back = try MtaProof.fromBytesAlloc(allocator, setup.aux.n_tilde, pk, bytes);
    defer back.deinit(allocator);
    try testing.expect(verifyBobMta(back, c_a, c_b, pk, setup.aux));
}

test "GG18 A.3 reject (SECURITY-CRITICAL): out-of-range b (s1 > q³) and out-of-range beta' (t1 > q⁷)" {
    // Both rejects are honestly-CONSISTENT proofs (the consistency
    // equations 3-5 hold); ONLY the range bounds catch them — the exact
    // degree of freedom Alpha-Rays-class attacks exploit. The t1 case is
    // specifically the tss-lib/GG20 hardening the GG18 paper does not
    // have (see the module doc comment) — this test is what pins it.
    if (builtin.mode == .Debug) return error.SkipZigTest; // 2048-bit keygen: ReleaseFast only
    const allocator = testing.allocator;
    const setup = try realAuxAndKey(0xb0b_0002);
    const pk = setup.kp.public;

    var prng = std.Random.DefaultPrng.init(0x62696778); // "bigx"
    const random = prng.random();

    const a = scalarFromU64(0xa);
    const r_a = testPaillierRandomness(pk, random);
    const c_a = paillier.encrypt(pk, scalarToTestFe(a, pk), r_a) catch unreachable;

    // x = 2q³ (out of range), y in range.
    const x_big = comptime comptimeIntBytes(97, 2 * (q_int * q_int * q_int));
    const y_ok = scalarFromU64(0xbeef).toBytes(.big);
    const r_b1 = testPaillierRandomness(pk, random);
    const c_b1 = buildCb(pk, c_a, &x_big, &y_ok, r_b1);
    const out1 = try proveBobInner(allocator, &x_big, &y_ok, r_b1, c_a, c_b1, pk, setup.aux, null, random);
    defer out1.proof.deinit(allocator);
    try testing.expect(!verifyBobMta(out1.proof, c_a, c_b1, pk, setup.aux));

    // x in range, y = 2q⁷ (out of range; still < N² so the ciphertext
    // composition stays well-formed — the proof equations remain
    // consistent mod N, only the t1 bound trips).
    const x_ok = scalarFromU64(0xb0b).toBytes(.big);
    const y_big = comptime comptimeIntBytes(225, 2 * (q_int * q_int * q_int * q_int * q_int * q_int * q_int));
    const r_b2 = testPaillierRandomness(pk, random);
    const c_b2 = buildCb(pk, c_a, &x_ok, &y_big, r_b2);
    const out2 = try proveBobInner(allocator, &x_ok, &y_big, r_b2, c_a, c_b2, pk, setup.aux, null, random);
    defer out2.proof.deinit(allocator);
    try testing.expect(!verifyBobMta(out2.proof, c_a, c_b2, pk, setup.aux));

    // Control: both in range verifies.
    const r_b3 = testPaillierRandomness(pk, random);
    const c_b3 = buildCb(pk, c_a, &x_ok, &y_ok, r_b3);
    const out3 = try proveBobInner(allocator, &x_ok, &y_ok, r_b3, c_a, c_b3, pk, setup.aux, null, random);
    defer out3.proof.deinit(allocator);
    try testing.expect(verifyBobMta(out3.proof, c_a, c_b3, pk, setup.aux));
}

test "GG18 A.3 reject (SECURITY-CRITICAL): tampered c_b, wrong beta' witness, and every mangled proof field" {
    if (builtin.mode == .Debug) return error.SkipZigTest; // 2048-bit keygen: ReleaseFast only
    const allocator = testing.allocator;
    const setup = try realAuxAndKey(0xb0b_0003);
    const pk = setup.kp.public;
    const nt = setup.aux.n_tilde;

    var prng = std.Random.DefaultPrng.init(0x62616462); // "badb"
    const random = prng.random();

    const a = scalarFromU64(0x1111);
    const b = scalarFromU64(0x2222);
    const beta_prime = scalarFromU64(0x3333);
    const r_a = testPaillierRandomness(pk, random);
    const r_b = testPaillierRandomness(pk, random);
    const c_a = paillier.encrypt(pk, scalarToTestFe(a, pk), r_a) catch unreachable;
    const b_bytes = b.toBytes(.big);
    const bp_bytes = beta_prime.toBytes(.big);
    const c_b = buildCb(pk, c_a, &b_bytes, &bp_bytes, r_b);

    const proof = try proveBobMta(allocator, b, beta_prime, r_b, c_a, c_b, pk, setup.aux, random);
    defer proof.deinit(allocator);
    try testing.expect(verifyBobMta(proof, c_a, c_b, pk, setup.aux)); // control

    // Tampered c_b after the proof was produced (equation 5).
    const one_fe = paillier.Fe.fromPrimitive(u64, pk.n_sq, 1) catch unreachable;
    const c_b_bad = paillier.addPlaintext(pk, c_b, one_fe) catch unreachable;
    try testing.expect(!verifyBobMta(proof, c_a, c_b_bad, pk, setup.aux));

    // Wrong beta' witness: prover claims a beta' different from the one
    // actually folded into c_b (equations 4/5).
    const wrong_bp = scalarFromU64(0x4444);
    const proof_wrong = try proveBobMta(allocator, b, wrong_bp, r_b, c_a, c_b, pk, setup.aux, random);
    defer proof_wrong.deinit(allocator);
    try testing.expect(!verifyBobMta(proof_wrong, c_a, c_b, pk, setup.aux));

    // Wrong b witness too, for completeness (equations 3/5).
    const proof_wrong_b = try proveBobMta(allocator, scalarFromU64(0x5555), beta_prime, r_b, c_a, c_b, pk, setup.aux, random);
    defer proof_wrong_b.deinit(allocator);
    try testing.expect(!verifyBobMta(proof_wrong_b, c_a, c_b, pk, setup.aux));

    // Every field mangled.
    var bad = proof;
    bad.z = nt.mul(proof.z, setup.aux.h1);
    try testing.expect(!verifyBobMta(bad, c_a, c_b, pk, setup.aux));
    bad = proof;
    bad.z1 = nt.mul(proof.z1, setup.aux.h1);
    try testing.expect(!verifyBobMta(bad, c_a, c_b, pk, setup.aux));
    bad = proof;
    bad.t = nt.mul(proof.t, setup.aux.h2);
    try testing.expect(!verifyBobMta(bad, c_a, c_b, pk, setup.aux));
    bad = proof;
    bad.v = .{ .c = pk.n_sq.mul(proof.v.c, proof.v.c) };
    try testing.expect(!verifyBobMta(bad, c_a, c_b, pk, setup.aux));
    bad = proof;
    bad.w = nt.mul(proof.w, setup.aux.h2);
    try testing.expect(!verifyBobMta(bad, c_a, c_b, pk, setup.aux));
    bad = proof;
    bad.s = pk.n_sq.mul(proof.s, proof.s);
    try testing.expect(!verifyBobMta(bad, c_a, c_b, pk, setup.aux));

    inline for (.{ "s1", "s2", "t1", "t2" }) |field| {
        const orig = @field(proof, field);
        var mangled = try allocator.dupe(u8, orig);
        defer allocator.free(mangled);
        mangled[mangled.len - 1] ^= 0x01;
        bad = proof;
        @field(bad, field) = mangled;
        try testing.expect(!verifyBobMta(bad, c_a, c_b, pk, setup.aux));
    }
}

test "GG18 A.2 MtAwc: honest accept; wrong B, tampered u1, and cross-protocol proof reuse all reject" {
    if (builtin.mode == .Debug) return error.SkipZigTest; // 2048-bit keygen: ReleaseFast only
    const allocator = testing.allocator;
    const setup = try realAuxAndKey(0xb0b_0004);
    const pk = setup.kp.public;

    var prng = std.Random.DefaultPrng.init(0x6d746177_6363); // "mtaw cc"
    const random = prng.random();

    const a = scalarFromU64(0xaaaa);
    const b = scalarFromU64(0xbbbb);
    const beta_prime = scalarFromU64(0xcccc);
    const r_a = testPaillierRandomness(pk, random);
    const r_b = testPaillierRandomness(pk, random);
    const c_a = paillier.encrypt(pk, scalarToTestFe(a, pk), r_a) catch unreachable;
    const b_bytes = b.toBytes(.big);
    const bp_bytes = beta_prime.toBytes(.big);
    const c_b = buildCb(pk, c_a, &b_bytes, &bp_bytes, r_b);

    // B = b·G — the public point the proof must tie Bob's MtA input to.
    const b_point = root.Element.fromPoint(root.Secp256k1.basePoint.mul(b.toBytes(.big), .big) catch unreachable) catch unreachable;

    const proof = try proveBobMtaWc(allocator, b, beta_prime, r_b, c_a, c_b, pk, setup.aux, b_point, random);
    defer proof.deinit(allocator);
    try testing.expect(verifyBobMtaWc(proof, c_a, c_b, pk, setup.aux, b_point));

    // Codec round-trip re-verifies.
    const bytes = try proof.toBytesAlloc(allocator);
    defer allocator.free(bytes);
    const back = try MtaProofWc.fromBytesAlloc(allocator, setup.aux.n_tilde, pk, bytes);
    defer back.deinit(allocator);
    try testing.expect(verifyBobMtaWc(back, c_a, c_b, pk, setup.aux, b_point));

    // Wrong B: the SAME b in MtA but a different public point (the exact
    // cheat MtAwc exists to catch — check 6).
    const b_wrong = root.Element.fromPoint(root.Secp256k1.basePoint.mul(b.add(Scalar.one).toBytes(.big), .big) catch unreachable) catch unreachable;
    try testing.expect(!verifyBobMtaWc(proof, c_a, c_b, pk, setup.aux, b_wrong));

    // Tampered u1 (check 6 + challenge binding).
    const u1_pt = proof.u1_point.point() catch unreachable;
    const u1_bad = root.Element.fromPoint(u1_pt.add(root.Secp256k1.basePoint)) catch unreachable;
    const proof_bad_u1: MtaProofWc = .{ .base = proof.base, .u1_point = u1_bad };
    try testing.expect(!verifyBobMtaWc(proof_bad_u1, c_a, c_b, pk, setup.aux, b_point));

    // Cross-protocol confusion: the Wc proof's base must NOT verify as a
    // plain MtA proof (different Fiat-Shamir domain + transcript — this
    // is what the domain-separation tags buy).
    try testing.expect(!verifyBobMta(proof.base, c_a, c_b, pk, setup.aux));
}

// -- audit F1/F2: checked-path received-parameter validation (NEW) --
//
// A malicious counterparty supplies the `verifier_aux` a prover commits its
// secret witness under (F1) and/or a sub-q⁷ Paillier key (F2). These assert
// the prove entry points refuse both, fail-closed, with error.InvalidAuxParams.
// They are FAST — validation rejects before any sampling/modexp — so unlike
// the honest-accept/reject fixtures above they run in BOTH Debug and
// ReleaseFast (no 2048-bit keygen on the reject path).

fn toyPaillierPk() paillier.PublicKey {
    return (paillier.fromPrimes(&[_]u8{11}, &[_]u8{17}) catch unreachable).public; // N = 187 ≪ q⁷
}

fn auxFromBytes(nt_byte: u8, h1_byte: u8, h2_byte: u8) root.AuxParams {
    const nt = root.AuxModulus.fromBytes(&[_]u8{nt_byte}, .big) catch unreachable;
    return .{
        .n_tilde = nt,
        .h1 = root.AuxFe.fromBytes(nt, &[_]u8{h1_byte}, .big) catch unreachable,
        .h2 = root.AuxFe.fromBytes(nt, &[_]u8{h2_byte}, .big) catch unreachable,
    };
}

test "audit F1: proveAliceRange/proveBobMta fail-close on a crafted bad received aux (prime Ñ / out-of-range h / non-QR h)" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x66315f61757800); // "f1_aux"
    const random = prng.random();

    const pk = toyPaillierPk(); // aux validation runs before any pk use
    const a = scalarFromU64(5);
    const r_a = paillier.Fe.fromPrimitive(u32, pk.n_sq, 3) catch unreachable;

    // Ñ = 251 is PRIME -> Miller-Rabin composite check rejects.
    try testing.expectError(error.InvalidAuxParams, proveAliceRange(allocator, a, r_a, pk, auxFromBytes(251, 2, 4), random));
    // h1 = 1 (out of range) on a composite Ñ.
    try testing.expectError(error.InvalidAuxParams, proveAliceRange(allocator, a, r_a, pk, auxFromBytes(187, 1, 16), random));
    // h1 = 5 is a quadratic NON-residue mod 187 (Jacobi -1).
    try testing.expectError(error.InvalidAuxParams, proveAliceRange(allocator, a, r_a, pk, auxFromBytes(187, 5, 4), random));

    // Same fail-closed gate on Bob's prover (shares validateReceivedParams).
    const b = scalarFromU64(6);
    const bp = scalarFromU64(7);
    const r_b = paillier.Fe.fromPrimitive(u32, pk.n_sq, 5) catch unreachable;
    const one_fe = paillier.Fe.fromPrimitive(u32, pk.n_sq, 1) catch unreachable;
    const two_fe = paillier.Fe.fromPrimitive(u32, pk.n_sq, 2) catch unreachable;
    const c_dummy = paillier.encrypt(pk, one_fe, two_fe) catch unreachable;
    try testing.expectError(error.InvalidAuxParams, proveBobMta(allocator, b, bp, r_b, c_dummy, c_dummy, pk, auxFromBytes(251, 2, 4), random));
}

test "audit F2: prove entry points fail-close on a sub-q⁷ modulus on the checked path" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x66325f666c6f6f72); // "f2_floor"
    const random = prng.random();
    const a = scalarFromU64(7);

    // (a) sub-floor aux Ñ = 187 with structurally-valid square-subgroup
    // generators (h1 = 4, h2 = 16): the AUX key-size floor rejects it.
    {
        const pk = toyPaillierPk();
        const r_a = paillier.Fe.fromPrimitive(u32, pk.n_sq, 3) catch unreachable;
        try testing.expectError(error.InvalidAuxParams, proveAliceRange(allocator, a, r_a, pk, auxFromBytes(187, 4, 16), random));
    }

    // (b) VALID > q⁷ aux (a genuine ~2000-bit composite with perfect-square
    // generators, built at comptime — no keygen, so this stays fast) BUT a
    // sub-floor toy Paillier key (N = 187): the PAILLIER key-size floor is
    // what rejects it, proving the F2 check covers the received Paillier N too.
    {
        const big_composite = comptime comptimeIntBytes(256, ((1 << 1000) + 9) * ((1 << 1000) + 15));
        const nt = root.AuxModulus.fromBytes(stripLeadingZeros(&big_composite), .big) catch unreachable;
        const good_aux: root.AuxParams = .{
            .n_tilde = nt,
            .h1 = root.AuxFe.fromBytes(nt, &[_]u8{4}, .big) catch unreachable,
            .h2 = root.AuxFe.fromBytes(nt, &[_]u8{16}, .big) catch unreachable,
        };
        const pk = toyPaillierPk();
        const r_a = paillier.Fe.fromPrimitive(u32, pk.n_sq, 3) catch unreachable;
        try testing.expectError(error.InvalidAuxParams, proveAliceRange(allocator, a, r_a, pk, good_aux, random));

        // And the verify-side F2 floor (defense-in-depth): a proof "verified"
        // against a sub-floor Paillier key is rejected outright. Build a
        // syntactically-valid RangeProof over the toy pk and assert reject.
        const dummy: RangeProof = .{
            .z = good_aux.h1,
            .u = paillier.encrypt(pk, paillier.Fe.fromPrimitive(u32, pk.n_sq, 1) catch unreachable, paillier.Fe.fromPrimitive(u32, pk.n_sq, 2) catch unreachable) catch unreachable,
            .w = good_aux.h2,
            .s = paillier.Fe.fromPrimitive(u32, pk.n_sq, 3) catch unreachable,
            .s1 = try allocator.dupe(u8, &[_]u8{1}),
            .s2 = try allocator.dupe(u8, &[_]u8{1}),
        };
        defer dummy.deinit(allocator);
        const c_dummy = paillier.encrypt(pk, paillier.Fe.fromPrimitive(u32, pk.n_sq, 4) catch unreachable, paillier.Fe.fromPrimitive(u32, pk.n_sq, 5) catch unreachable) catch unreachable;
        try testing.expect(!verifyAliceRange(dummy, c_dummy, pk, good_aux));
    }
}
