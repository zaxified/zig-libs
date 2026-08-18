// SPDX-License-Identifier: MIT
//! bbs — the `Signature`/`Proof` wire types (REAL, byte-exact codecs) and
//! the FOUR Fable-hard cores this module scaffolds around:
//! `sign`/`verify` (draft §3.5.1/§3.5.2, "CoreSign"/"CoreVerify" §3.6.1/
//! §3.6.2) and `proofGen`/`proofVerify` (draft §3.5.3/§3.5.4, the
//! selective-disclosure Fiat-Shamir NIZK — §3.6.3/§3.6.4 plus the
//! `ProofInit`/`ProofFinalize`/`ProofVerifyInit`/`ProofChallengeCalculate`
//! subroutines, §3.7). All four are IMPLEMENTED (a Fable pass filled the
//! scaffold and flipped `gate.core_implemented = true`), each carrying a
//! complete per-step doc-comment contract transcribed from
//! draft-irtf-cfrg-bbs-signatures-04 — see `../SPEC.md` for why THIS
//! draft version was pinned and `gate.zig` for the scaffold-then-Fable
//! discipline.
//!
//! **Why `proofGen`/`proofVerify`, not `sign`/`verify`, are the genuinely
//! hard core**: `sign`/`verify` are a single Schnorr-like pairing
//! signature — real work, but a direct, unambiguous transcription of
//! §3.6.1/§3.6.2's 7-and-4-step procedures with no per-call design
//! choice. `proofGen`/`proofVerify` are a full Fiat-Shamir NIZK: getting
//! the `r1`/`r2`/`r3`/`m~_j` blinding-factor roles right, the
//! `Abar`/`Bbar`/`T` accumulation order, WHICH generators get
//! disclosed-vs-undisclosed treatment in `ProofVerifyInit`'s `D`/`T`
//! split, and the exact transcript `ProofChallengeCalculate` folds into
//! `c` are all genuine soundness-critical judgment calls (get any one
//! backwards and the result can still "look plausible" — compile, run,
//! even pass a lazy prove-then-verify smoke test — while being
//! completely unsound), the same class of risk `bulletproofs`' IPA and
//! `threshold_ecdsa`'s Πprm/Πmod document for their own Fable cores.
//!
//! **Randomness — explicit parameter, not internal entropy** (see
//! `../README.md`'s "Randomness" section): `proofGen` takes
//! `random_scalars: []const Fr` as a plain parameter (length MUST be
//! `3 + U`, `U` = the undisclosed-message count) rather than an `io:
//! std.Io`/internal RNG read. This mirrors `frost`'s "nonces are an
//! explicit input" convention (`frost/src/root.zig`), and is what makes
//! the draft's own deterministic `mocked_random_scalars` (KAT
//! reproducibility, draft §7.1 — `ciphersuite.mockedRandomScalars`) and
//! real entropy (`ciphersuite.calculateRandomScalars`) interchangeable
//! at this boundary: `kat_test.zig`'s gated `proofGen` tests pass a
//! `mockedRandomScalars(3 + U, seed)` slice and assert the exact
//! resulting proof bytes; a real caller would instead pass
//! `&calculateRandomScalars(3 + U, io)`.

const std = @import("std");
const cs = @import("ciphersuite.zig");
const keys = @import("keys.zig");
const gate = @import("gate.zig");
const bls = @import("bls12_381");

pub const G1 = cs.G1;
pub const G2 = cs.G2;
pub const Fr = cs.Fr;
pub const SecretKey = keys.SecretKey;
pub const PublicKey = keys.PublicKey;

pub const BbsError = error{
    /// `Signature`/`Proof` byte decoding failed a structural or
    /// range check (wrong length, a point failing `on-curve`/
    /// non-identity, or a scalar `== 0` or `>= r` — draft
    /// §4.2.4.3/§4.2.4.5's `octets_to_signature`/`octets_to_proof`
    /// "return INVALID" conditions).
    InvalidSignatureEncoding,
    InvalidProofEncoding,
    /// `proofGen`'s `disclosed_indexes` contains a value `>= messages.len`
    /// (draft §3.6.3's ABORT condition).
    DisclosedIndexOutOfRange,
    /// `proofGen`'s `disclosed_indexes.len > messages.len` (draft
    /// §3.6.3 step 6: "if R > L, return INVALID").
    TooManyDisclosedIndexes,
    /// `proofGen`'s `random_scalars.len != 3 + (messages.len -
    /// disclosed_indexes.len)` (draft §3.7.1 step 5's ABORT condition,
    /// generalized to the Interface-level `random_scalars` input this
    /// module's `proofGen` takes explicitly — see this file's module
    /// doc comment).
    RandomScalarCountMismatch,
    /// `proofVerify`'s `disclosed_messages.len != disclosed_indexes.len`
    /// (draft §3.7.3's ABORT condition 2).
    DisclosedMessageCountMismatch,
} || std.mem.Allocator.Error;

/// A BBS signature: `(A, e)`, `A` a `G1` point, `e` a nonzero `Fr`
/// scalar — draft §3.6.1's output shape. Fixed 80-byte wire encoding
/// (`G1.compressed_bytes` `48` + `Fr.encoded_bytes` `32`).
pub const Signature = struct {
    a: G1.Affine,
    e: Fr,

    pub const encoded_bytes = G1.compressed_bytes + Fr.encoded_bytes; // 80

    /// `signature_to_octets` (draft §4.2.4.2): `ser(A) || I2OSP(e, 32)`.
    /// REAL.
    pub fn toBytes(self: Signature) [encoded_bytes]u8 {
        var out: [encoded_bytes]u8 = undefined;
        out[0..G1.compressed_bytes].* = G1.toBytesCompressed(self.a);
        out[G1.compressed_bytes..].* = self.e.toBytes();
        return out;
    }

    /// `octets_to_signature` (draft §4.2.4.3): parses `A` (rejecting the
    /// identity AND any non-prime-order-subgroup point) and `e` (rejecting
    /// `0` or `>= r`), so `verify`/`proofGen` operate only on subgroup inputs.
    /// REAL.
    pub fn fromBytes(bytes: [encoded_bytes]u8) BbsError!Signature {
        const a = G1.fromBytesCompressed(bytes[0..G1.compressed_bytes].*) catch return error.InvalidSignatureEncoding;
        if (a.infinity) return error.InvalidSignatureEncoding;
        if (!G1.Jacobian.fromAffine(a).subgroupCheck()) return error.InvalidSignatureEncoding;
        const e = Fr.fromBytes(bytes[G1.compressed_bytes..].*) catch return error.InvalidSignatureEncoding;
        if (e.isZero()) return error.InvalidSignatureEncoding;
        return .{ .a = a, .e = e };
    }
};

/// A BBS proof: `(Abar, Bbar, r2_hat, r3_hat, m_hat[0..U], c)` — draft
/// §3.7.2's `ProofFinalize` output shape (`Abar`/`Bbar` two `G1`
/// points; `r2_hat`/`r3_hat`/`c` three scalars; `m_hat` one scalar per
/// UNDISCLOSED message). Variable-length wire encoding: `2 *
/// G1.compressed_bytes + (3 + U) * Fr.encoded_bytes` — `U = m_hat.len`
/// is recovered from the encoded length itself on decode (draft
/// §4.2.4.5), not carried out-of-band.
pub const Proof = struct {
    abar: G1.Affine,
    bbar: G1.Affine,
    r2_hat: Fr,
    r3_hat: Fr,
    /// One response scalar per UNDISCLOSED message (`m^_j1 .. m^_jU`,
    /// draft §3.7.2 step 4). Owned by whoever constructed this `Proof`
    /// (`proofGen`'s return, or `fromBytes`'s allocation) — free with
    /// `deinit`.
    m_hat: []const Fr,
    c: Fr,

    pub fn encodedLen(undisclosed_count: usize) usize {
        return 2 * G1.compressed_bytes + (3 + undisclosed_count) * Fr.encoded_bytes;
    }

    pub fn deinit(self: Proof, allocator: std.mem.Allocator) void {
        allocator.free(self.m_hat);
    }

    /// `proof_to_octets` (draft §4.2.4.4): `ser(Abar) || ser(Bbar) ||
    /// I2OSP(r2_hat,32) || I2OSP(r3_hat,32) || I2OSP(m_hat_1,32) || .. ||
    /// I2OSP(m_hat_U,32) || I2OSP(c,32)`. REAL. Caller owns the returned
    /// slice.
    pub fn toBytes(self: Proof, allocator: std.mem.Allocator) ![]u8 {
        const out = try allocator.alloc(u8, encodedLen(self.m_hat.len));
        errdefer allocator.free(out);
        var off: usize = 0;
        out[off..][0..G1.compressed_bytes].* = G1.toBytesCompressed(self.abar);
        off += G1.compressed_bytes;
        out[off..][0..G1.compressed_bytes].* = G1.toBytesCompressed(self.bbar);
        off += G1.compressed_bytes;
        out[off..][0..Fr.encoded_bytes].* = self.r2_hat.toBytes();
        off += Fr.encoded_bytes;
        out[off..][0..Fr.encoded_bytes].* = self.r3_hat.toBytes();
        off += Fr.encoded_bytes;
        for (self.m_hat) |m| {
            out[off..][0..Fr.encoded_bytes].* = m.toBytes();
            off += Fr.encoded_bytes;
        }
        out[off..][0..Fr.encoded_bytes].* = self.c.toBytes();
        off += Fr.encoded_bytes;
        std.debug.assert(off == out.len);
        return out;
    }

    /// `octets_to_proof` (draft §4.2.4.5): `U` is recovered from
    /// `bytes.len` (`proof_len_floor = 2*48 + 3*32 = 192`; `U =
    /// (bytes.len - proof_len_floor) / 32`, REJECTING a remainder).
    /// Rejects `Abar`/`Bbar` decoding to the identity, and every scalar
    /// (`r2_hat`/`r3_hat`/each `m_hat`/`c`) being `0` or `>= r`. Does NOT
    /// subgroup-check `Abar`/`Bbar` (same non-subgroup-checking
    /// deserialization contract as `Signature.fromBytes`). Caller owns
    /// the returned `.m_hat` (free via `.deinit`).
    pub fn fromBytes(allocator: std.mem.Allocator, bytes: []const u8) BbsError!Proof {
        const floor = 2 * G1.compressed_bytes + 3 * Fr.encoded_bytes;
        if (bytes.len < floor) return error.InvalidProofEncoding;
        if ((bytes.len - floor) % Fr.encoded_bytes != 0) return error.InvalidProofEncoding;
        const u = (bytes.len - floor) / Fr.encoded_bytes;

        var off: usize = 0;
        const abar = G1.fromBytesCompressed(bytes[off..][0..G1.compressed_bytes].*) catch return error.InvalidProofEncoding;
        if (abar.infinity) return error.InvalidProofEncoding;
        if (!G1.Jacobian.fromAffine(abar).subgroupCheck()) return error.InvalidProofEncoding;
        off += G1.compressed_bytes;
        const bbar = G1.fromBytesCompressed(bytes[off..][0..G1.compressed_bytes].*) catch return error.InvalidProofEncoding;
        if (bbar.infinity) return error.InvalidProofEncoding;
        if (!G1.Jacobian.fromAffine(bbar).subgroupCheck()) return error.InvalidProofEncoding;
        off += G1.compressed_bytes;

        const r2_hat = try fromBytesNonzeroScalar(bytes[off..][0..Fr.encoded_bytes].*);
        off += Fr.encoded_bytes;
        const r3_hat = try fromBytesNonzeroScalar(bytes[off..][0..Fr.encoded_bytes].*);
        off += Fr.encoded_bytes;

        const m_hat = try allocator.alloc(Fr, u);
        errdefer allocator.free(m_hat);
        for (m_hat) |*m| {
            m.* = try fromBytesNonzeroScalar(bytes[off..][0..Fr.encoded_bytes].*);
            off += Fr.encoded_bytes;
        }

        const c = try fromBytesNonzeroScalar(bytes[off..][0..Fr.encoded_bytes].*);
        off += Fr.encoded_bytes;
        std.debug.assert(off == bytes.len);

        return .{ .abar = abar, .bbar = bbar, .r2_hat = r2_hat, .r3_hat = r3_hat, .m_hat = m_hat, .c = c };
    }
};

fn fromBytesNonzeroScalar(bytes: [Fr.encoded_bytes]u8) BbsError!Fr {
    const s = Fr.fromBytes(bytes) catch return error.InvalidProofEncoding;
    if (s.isZero()) return error.InvalidProofEncoding;
    return s;
}

// ── private helpers shared by the four cores ────────────────────────────

/// `B = P1 + [domain]Q_1 + sum_i [msg_i]H_i` — the accumulation shared
/// verbatim by `CoreSign` step 5, `CoreVerify` step 5, and `ProofInit`
/// step 6 (draft §3.6.1/§3.6.2/§3.7.1). `generators[0]` is `Q_1`,
/// `generators[1..]` are `H_1..H_L` (exactly `createGenerators(L + 1)`'s
/// layout).
fn computeB(domain: Fr, generators: []const G1.Affine, message_scalars: []const Fr) G1.Jacobian {
    std.debug.assert(generators.len == message_scalars.len + 1);
    var b = G1.Jacobian.fromAffine(cs.P1)
        .add(G1.Jacobian.fromAffine(generators[0]).scalarMul(domain));
    for (generators[1..], message_scalars) |h, m| {
        b = b.add(G1.Jacobian.fromAffine(h).scalarMul(m));
    }
    return b;
}

// ── verifier-side MSM crossover (F4) ─────────────────────────────────────
//
// `computeB` above stays exactly as it was: a sequential per-generator
// `scalarMul` loop, and the ONLY path `sign` and `proofGen` use. Those two
// callers' `message_scalars` can include UNDISCLOSED credential attributes
// (`proofGen` folds ALL messages, disclosed and undisclosed, into `B` — the
// undisclosed ones are exactly what the selective-disclosure proof exists
// to hide) or a signer's private message content (`sign`). `bls12_381`'s
// `kzg.g1Msm` (Pippenger bucket MSM) is EXPLICITLY variable-time — which
// bucket a term lands in, and even which windows go idle, depends on the
// scalar's bit pattern — so using it there would open a timing side
// channel on exactly the values this module's own CT posture (audit A6)
// protects with `bls12_381`'s constant-time `scalarMul`. That would be a
// worse regression than the LOW-severity perf gap F4 flags.
//
// `verify`'s `computeB` call and `proofVerify`'s `ProofVerifyInit` `d_j`/
// `t_j` accumulation are different: every scalar involved is already
// public to whoever can observe the timing. `verify`'s `message_scalars`
// are the caller's own plaintext messages (non-selective CoreVerify — the
// verifier already holds them in full). `proofVerify`'s `d_j` uses only
// `disclosed_scalars` (revealed by definition) plus the public
// `domain`/`P1`/generators; its `t_j` uses only wire-received proof fields
// (`Abar`/`Bbar`/`r2_hat`/`r3_hat`/`m_hat`/`c`) the prover already
// transmitted in the clear — the verifier has no secret of its own in that
// computation to leak. Those two call sites are safe for a variable-time
// MSM and are what this crossover applies to.

/// `Σ scalars[i] * points[i]` via the plain sequential loop —
/// `computeB`'s own accumulation shape, factored out so the crossover
/// dispatcher's "small L" branch and `computeB` never drift apart.
fn msmLoop(points: []const G1.Affine, scalars: []const Fr) G1.Jacobian {
    std.debug.assert(points.len == scalars.len);
    var acc = G1.Jacobian.identity;
    for (points, scalars) |p, s| acc = acc.add(G1.Jacobian.fromAffine(p).scalarMul(s));
    return acc;
}

/// `Σ scalars[i] * points[i]` via `bls12_381.kzg.g1Msm` (Pippenger bucket
/// MSM). `g1Msm`'s only fallible step is its two internal `allocator.alloc`
/// calls (see `kzg.zig`'s `g1Msm` body) — no other error path exists for
/// well-formed equal-length input, so every other `KzgError` variant is
/// `unreachable` here.
fn msmPippenger(allocator: std.mem.Allocator, points: []const G1.Affine, scalars: []const Fr) std.mem.Allocator.Error!G1.Jacobian {
    return bls.kzg.g1Msm(allocator, points, scalars) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => unreachable, // g1Msm's other `KzgError` variants (trusted-setup parsing etc.) are unreachable from a well-formed points/scalars call.
    };
}

/// Crossover point (term count) between `msmLoop` and `msmPippenger`,
/// MEASURED on this host at `-Doptimize=ReleaseFast`
/// (`BBS_BENCH=1 scripts/capped zig build test-bbs -Doptimize=ReleaseFast`,
/// the "bench (opt-in via BBS_BENCH)" test below):
///
/// ```
///   n |     loop ns/op | pippenger ns/op | winner
///   1 |         720272 |         450771  |  MSM (1.6x)
///   2 |       1,441711 |         679862  |  MSM (2.1x)
///   4 |       2,988500 |       1,164915  |  MSM (2.6x)
///   8 |       5,941928 |       1,555471  |  MSM (3.8x)
///  16 |      11,674799 |       2,518119  |  MSM (4.6x)
///  32 |      23,330754 |       3,585844  |  MSM (6.5x)
///  64 |      50,611939 |       5,859254  |  MSM (8.6x)
/// 128 |      93,999985 |       9,006337  |  MSM (10.4x)
/// 256 |     189,265820 |      15,135721  |  MSM (12.5x)
/// 512 |     373,324049 |      25,407709  |  MSM (14.7x)
/// ```
///
/// There is NO regime in this data where the sequential loop wins — the
/// crossover is degenerate, at the bottom of the measurable range. This
/// is NOT the "Pippenger has less asymptotic work" story alone: `msmLoop`
/// calls `bls12_381`'s CONSTANT-TIME `scalarMul` once per term (paid
/// because `computeB`, its production counterpart, MUST tolerate secret
/// scalars), while `msmPippenger`'s bucket phase uses `bls12_381`'s
/// variable-time mixed-add formulas throughout — cheaper per point-op
/// even before Pippenger's asymptotic win compounds it. `verify`'s and
/// `proofVerify`'s call sites never construct fewer than 2 terms (`P1` +
/// `Q_1` are always present), so in production this dispatcher always
/// takes the Pippenger branch; the loop branch below is kept only so
/// `msmPublic` degrades sanely for the n<2 case no real caller hits.
const msm_crossover: usize = 2;

/// `Σ scalars[i] * points[i]`, dispatching on `msm_crossover`.
///
/// SAFETY (variable-time!): only call this when every scalar in
/// `scalars` is already public to whoever can observe the timing — see
/// the section comment above. NEVER call it on `sign`'s or `proofGen`'s
/// message scalars.
fn msmPublic(allocator: std.mem.Allocator, points: []const G1.Affine, scalars: []const Fr) std.mem.Allocator.Error!G1.Jacobian {
    std.debug.assert(points.len == scalars.len);
    if (points.len < msm_crossover) return msmLoop(points, scalars);
    return msmPippenger(allocator, points, scalars);
}

/// `computeB`'s exact value (`P1 + [domain]Q_1 + sum_i [msg_i]H_i`),
/// computed via `msmPublic` instead of `computeB`'s sequential loop. See
/// the section comment above for why this may ONLY be called on public
/// message scalars (`verify`, never `sign`/`proofGen`).
fn computeBPublic(allocator: std.mem.Allocator, domain: Fr, generators: []const G1.Affine, message_scalars: []const Fr) std.mem.Allocator.Error!G1.Jacobian {
    std.debug.assert(generators.len == message_scalars.len + 1);
    const n = generators.len + 1; // + P1
    const points = try allocator.alloc(G1.Affine, n);
    defer allocator.free(points);
    const scalars = try allocator.alloc(Fr, n);
    defer allocator.free(scalars);
    points[0] = cs.P1;
    scalars[0] = Fr.one;
    points[1] = generators[0];
    scalars[1] = domain;
    @memcpy(points[2..], generators[1..]);
    @memcpy(scalars[2..], message_scalars);
    return msmPublic(allocator, points, scalars);
}

fn appendU64(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, v: u64) std.mem.Allocator.Error!void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .big);
    try buf.appendSlice(allocator, &b);
}

/// `ProofChallengeCalculate` (draft §3.7.4), shared by `proofGen` and
/// `proofVerify` — the ONE place the Fiat-Shamir transcript is
/// serialized, so the two sides cannot drift:
/// ```
/// c_arr  = (Abar, Bbar, T, R, i1, .., iR, msg_i1, .., msg_iR, domain)
/// c_octs = serialize(c_arr) || I2OSP(len(ph), 8) || ph
/// c      = hash_to_scalar(c_octs, h2s_dst)      // challenge_dst == h2s_dst
/// ```
/// `serialize` per draft §4.2.4.1: points compressed (48 bytes), the
/// count `R` and each index as `I2OSP(.., 8)`, scalars as
/// `I2OSP(.., 32)` (`Fr.toBytes`). Disclosed indexes are serialized
/// exactly as passed (0-based, ascending — the fixtures' own
/// convention, byte-confirmed by `proof001`/`proof003`).
fn calculateChallenge(
    allocator: std.mem.Allocator,
    abar: G1.Affine,
    bbar: G1.Affine,
    t: G1.Affine,
    disclosed_indexes: []const usize,
    disclosed_scalars: []const Fr,
    domain: Fr,
    ph: []const u8,
) std.mem.Allocator.Error!Fr {
    std.debug.assert(disclosed_indexes.len == disclosed_scalars.len);
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, &G1.toBytesCompressed(abar));
    try buf.appendSlice(allocator, &G1.toBytesCompressed(bbar));
    try buf.appendSlice(allocator, &G1.toBytesCompressed(t));
    try appendU64(&buf, allocator, disclosed_indexes.len);
    for (disclosed_indexes) |i| try appendU64(&buf, allocator, i);
    for (disclosed_scalars) |m| try buf.appendSlice(allocator, &m.toBytes());
    try buf.appendSlice(allocator, &domain.toBytes());
    try appendU64(&buf, allocator, ph.len);
    try buf.appendSlice(allocator, ph);
    return cs.hashToScalar(buf.items, cs.h2s_dst);
}

/// The ascending complement of `disclosed_indexes` within `0..total` —
/// draft §3.6.3/§3.6.4's `undisclosed_indexes` set. Duplicate disclosed
/// indexes shrink the marked set, so the returned length exceeding
/// `total - disclosed_indexes.len` is the callers' duplicate-detection
/// signal (each caller pre-validates every index `< total`). Caller
/// owns the returned slice.
fn undisclosedIndexes(allocator: std.mem.Allocator, total: usize, disclosed_indexes: []const usize) std.mem.Allocator.Error![]usize {
    const marks = try allocator.alloc(bool, total);
    defer allocator.free(marks);
    @memset(marks, false);
    for (disclosed_indexes) |i| marks[i] = true;
    var count: usize = 0;
    for (marks) |m| count += @intFromBool(!m);
    const out = try allocator.alloc(usize, count);
    var k: usize = 0;
    for (marks, 0..) |m, i| {
        if (!m) {
            out[k] = i;
            k += 1;
        }
    }
    return out;
}

/// `-BP2` in affine form — the fixed second `G2` argument of both
/// pairing checks (`e(X, Y) == e(B, BP2)` is verified as
/// `pairingCheck({X, Y}, {B, -BP2})`).
fn negBp2() G2.Affine {
    return G2.Jacobian.fromAffine(cs.BP2).negate().toAffine();
}

// ── the four Fable-hard cores ────────────────────────────────────────────

/// FABLE CORE — `Sign(SK, PK, header, messages)` (draft §3.5.1 Interface
/// wrapping §3.6.1's `CoreSign`; `commitment` is always `Identity_G1`
/// for this Interface — no blind-signature extension point is exposed,
/// so `comm` below is always the empty octet string).
///
/// Construction (draft §3.5.1 + §3.6.1, composed):
/// ```
/// 1. message_scalars = ciphersuite.messagesToScalars(allocator, messages)   // [msg_1..msg_L]
/// 2. generators = ciphersuite.createGenerators(allocator, messages.len + 1)
///    (Q_1, H_1, ..., H_L) = (generators[0], generators[1..])
/// 3. domain = ciphersuite.calculateDomain(allocator, pk.toBytes(), Q_1, H_1..H_L, header)
/// 4. e = hash_to_scalar(serialize((sk, domain, msg_1, .., msg_L)), h2s_dst)
///    // "serialize" per draft §4.2.4.1: sk as I2OSP(sk,32), domain as
///    // I2OSP(domain,32), each msg_i as I2OSP(msg_i,32), concatenated —
///    // NOTHING appended for `comm` since it is always "" here.
/// 5. B = P1 + [domain]Q_1 + sum_i [msg_i]H_i        (Jacobian accumulation,
///                                                     P1 = ciphersuite.P1)
/// 6. A = [(sk + e)^-1] B
/// 7. return Signature{ .a = A.toAffine(), .e = e }.toBytes()
/// ```
/// Byte-exact against `mattrglobal/pairing_crypto`'s `signature/
/// signature001.json` (single message) and `signature004.json`
/// (10-message) fixtures — see `kat_test.zig`'s gated tests.
pub fn sign(allocator: std.mem.Allocator, sk: SecretKey, pk: PublicKey, header: []const u8, messages: []const []const u8) BbsError![Signature.encoded_bytes]u8 {
    const message_scalars = try cs.messagesToScalars(allocator, messages);
    defer allocator.free(message_scalars);
    const generators = try cs.createGenerators(allocator, messages.len + 1);
    defer allocator.free(generators);
    const domain = try cs.calculateDomain(allocator, pk.toBytes(), generators[0], generators[1..], header);

    // e = hash_to_scalar(serialize((SK, domain, msg_1, .., msg_L)), h2s_dst)
    // — draft §3.6.1's e derivation (`signature_dst` == `h2s_dst`, see
    // `ciphersuite.h2s_dst`); `serialize` per §4.2.4.1 is each scalar's
    // 32-byte big-endian encoding, concatenated, with NOTHING appended
    // for the always-empty `comm`.
    var e_input: std.ArrayList(u8) = .empty;
    defer e_input.deinit(allocator);
    try e_input.appendSlice(allocator, &sk.toBytes());
    try e_input.appendSlice(allocator, &domain.toBytes());
    for (message_scalars) |m| try e_input.appendSlice(allocator, &m.toBytes());
    const e = cs.hashToScalar(e_input.items, cs.h2s_dst);

    // B = P1 + [domain]Q_1 + sum_i [msg_i]H_i ;  A = [(SK + e)^-1]B.
    const b = computeB(domain, generators, message_scalars);
    // `SK + e == 0` needs hash_to_scalar's output to equal `-SK` —
    // probability ~2^-255 (breaking SHA-256), same "astronomically
    // unlikely, surfaced as an error rather than UB" posture as
    // `keys.KeyGenError.InvalidSecretKey`. Likewise `A == Identity_G1`
    // (only when `B` is the identity — a degenerate message/domain
    // combination) cannot be encoded as a valid signature
    // (`Signature.fromBytes` rejects it), so it fails here, closed.
    const sk_plus_e_inv = sk.scalar.add(e).inv() catch return error.InvalidSignatureEncoding;
    const a = b.scalarMul(sk_plus_e_inv).toAffine();
    if (a.infinity) return error.InvalidSignatureEncoding;
    return (Signature{ .a = a, .e = e }).toBytes();
}

/// FABLE CORE — `Verify(PK, signature, header, messages)` (draft §3.5.2
/// wrapping §3.6.2's `CoreVerify`).
///
/// Construction (draft §3.5.2 + §3.6.2, composed):
/// ```
/// 1. (A, e) = Signature.fromBytes(signature)   // rejects malformed input
/// 2. message_scalars = ciphersuite.messagesToScalars(allocator, messages)
/// 3. generators = ciphersuite.createGenerators(allocator, messages.len + 1)
///    (Q_1, H_1, ..., H_L) = (generators[0], generators[1..])
/// 4. domain = ciphersuite.calculateDomain(allocator, pk.toBytes(), Q_1, H_1..H_L, header)
/// 5. B = P1 + [domain]Q_1 + sum_i [msg_i]H_i
/// 6. return pairing.pairingCheck(&.{
///        .{ .p = A,  .q = (pk.point + [e]BP2) },
///        .{ .p = B,  .q = -BP2 },
///    })    // e(A, W + [e]BP2) * e(B, -BP2) == 1  <=>  e(A,W+[e]BP2) == e(B,BP2)
/// ```
/// Total/fail-closed on malformed `signature` bytes (returns `false`,
/// not an error — draft §3.6.2 steps 1-2's "if signature_result is
/// INVALID, return INVALID" maps to a boolean `false` result at the
/// Interface layer, matching `bls12_381.bls_sig`'s verify-family
/// convention of never panicking on attacker-controlled input). Byte
/// pattern for a tamper test is `mattrglobal/pairing_crypto`'s
/// `signature002.json` (signature001's exact bytes, verified against a
/// DIFFERENT message set — expected `false`) — see `kat_test.zig`.
pub fn verify(allocator: std.mem.Allocator, pk: PublicKey, signature: [Signature.encoded_bytes]u8, header: []const u8, messages: []const []const u8) BbsError!bool {
    // Fail-closed on malformed signature bytes (draft §3.6.2 steps 1-2's
    // "return INVALID" — a boolean `false` at this Interface layer).
    const sig = Signature.fromBytes(signature) catch return false;

    const message_scalars = try cs.messagesToScalars(allocator, messages);
    defer allocator.free(message_scalars);
    const generators = try cs.createGenerators(allocator, messages.len + 1);
    defer allocator.free(generators);
    const domain = try cs.calculateDomain(allocator, pk.toBytes(), generators[0], generators[1..], header);
    // `message_scalars` here are the caller's OWN plaintext messages
    // (non-selective CoreVerify) — public to this call, so the
    // MSM-crossover path (`computeBPublic`) is safe; see the section
    // comment above `computeBPublic`'s definition.
    const b = (try computeBPublic(allocator, domain, generators, message_scalars)).toAffine();

    // e(A, W + [e]BP2) == e(B, BP2)  <=>
    // e(A, W + [e]BP2) * e(B, -BP2) == 1  (draft §3.6.2 step 6).
    const w_plus_e_bp2 = G2.Jacobian.fromAffine(pk.point)
        .add(G2.Jacobian.fromAffine(cs.BP2).scalarMul(sig.e))
        .toAffine();
    return cs.pairing.pairingCheck(&.{
        .{ .p = sig.a, .q = w_plus_e_bp2 },
        .{ .p = b, .q = negBp2() },
    });
}

/// FABLE CORE — `ProofGen(PK, signature, header, ph, messages,
/// disclosed_indexes, random_scalars)` (draft §3.5.3 wrapping §3.6.3's
/// `CoreProofGen`, itself `ProofInit` (§3.7.1) + `ProofChallengeCalculate`
/// (§3.7.4) + `ProofFinalize` (§3.7.2)) — **the module's genuinely hard
/// core**, see this file's module doc comment.
///
/// `random_scalars.len` MUST be exactly `3 + U` (`U = messages.len -
/// disclosed_indexes.len`) — see this file's module doc comment for why
/// this is an explicit parameter rather than internal entropy;
/// `ciphersuite.mockedRandomScalars`/`calculateRandomScalars` are the
/// two intended sources.
///
/// Construction (draft §3.6.3 + §3.7.1 + §3.7.4 + §3.7.2, composed;
/// `L = messages.len`, `R = disclosed_indexes.len`, `U = L - R`,
/// `undisclosed_indexes = {0..L-1} \ disclosed_indexes`, both index sets
/// kept in ascending order):
/// ```
/// 1. (A, e) = Signature.fromBytes(signature)
/// 2. message_scalars = ciphersuite.messagesToScalars(allocator, messages)
/// 3. generators = ciphersuite.createGenerators(allocator, L + 1)
///    (Q_1, H_1, ..., H_L) = (generators[0], generators[1..])
/// 4. domain = ciphersuite.calculateDomain(allocator, pk.toBytes(), Q_1, H_1..H_L, header)
///
/// -- ProofInit (§3.7.1) --
/// 5. (r1, r2, r3, m~_j1, .., m~_jU) = random_scalars   // random_scalars[0..3] are r1,r2,r3
/// 6. B    = P1 + [domain]Q_1 + sum_i [msg_i]H_i
/// 7. Abar = [r1]A
/// 8. Bbar = [r1]B - [e]Abar
/// 9. T    = [r2]Abar + [r3]Bbar + sum_{j in undisclosed} [m~_j]H_j
///
/// -- ProofChallengeCalculate (§3.7.4) --
/// 10. c_arr  = (Abar, Bbar, T, R, i1, .., iR, msg_i1, .., msg_iR, domain)
///     // i1..iR = disclosed_indexes; msg_i1..msg_iR = their message_scalars
/// 11. c_octs = serialize(c_arr) || I2OSP(len(ph), 8) || ph
/// 12. challenge = hash_to_scalar(c_octs, h2s_dst)
///
/// -- ProofFinalize (§3.7.2) --
/// 13. r4      = -(r1^-1) mod r
/// 14. r2_hat  = r2 + e * r4 * challenge (mod r)
/// 15. r3_hat  = r3 + r4 * challenge (mod r)
/// 16. for j in undisclosed_indexes (in order):
///         m_hat_j = m~_j + message_scalars[j] * challenge (mod r)
/// 17. return Proof{ Abar, Bbar, r2_hat, r3_hat, m_hat[0..U], c = challenge }.toBytes()
/// ```
/// Byte-exact (given the fixture's own `random_scalars =
/// ciphersuite.mockedRandomScalars(3 + U, "3.14159...")`) against
/// `mattrglobal/pairing_crypto`'s `proof/proof001.json` (`U=0`) and
/// `proof003.json` (`U=6`) fixtures — see `kat_test.zig`'s gated tests
/// and this file's module doc comment for the mocked-RNG seed
/// provenance.
pub fn proofGen(
    allocator: std.mem.Allocator,
    pk: PublicKey,
    signature: [Signature.encoded_bytes]u8,
    header: []const u8,
    ph: []const u8,
    messages: []const []const u8,
    disclosed_indexes: []const usize,
    random_scalars: []const Fr,
) BbsError![]u8 {
    if (disclosed_indexes.len > messages.len) return error.TooManyDisclosedIndexes;
    for (disclosed_indexes) |i| if (i >= messages.len) return error.DisclosedIndexOutOfRange;
    const undisclosed_count = messages.len - disclosed_indexes.len;
    if (random_scalars.len != 3 + undisclosed_count) return error.RandomScalarCountMismatch;

    const sig = try Signature.fromBytes(signature);

    const message_scalars = try cs.messagesToScalars(allocator, messages);
    defer allocator.free(message_scalars);
    const generators = try cs.createGenerators(allocator, messages.len + 1);
    defer allocator.free(generators);
    const domain = try cs.calculateDomain(allocator, pk.toBytes(), generators[0], generators[1..], header);

    const undisclosed = try undisclosedIndexes(allocator, messages.len, disclosed_indexes);
    defer allocator.free(undisclosed);
    // A DUPLICATE disclosed index makes the true undisclosed count exceed
    // `L - R`, so `random_scalars.len == 3 + (L - R)` can no longer be
    // the right count for the actual undisclosed set — surfaced as the
    // same count-mismatch error.
    if (undisclosed.len != undisclosed_count) return error.RandomScalarCountMismatch;

    // -- ProofInit (draft §3.7.1) --
    const r1 = random_scalars[0];
    const r2 = random_scalars[1];
    const r3 = random_scalars[2];
    const m_tilde = random_scalars[3..];
    // `r1 == 0` is not a valid random-scalar draw (probability ~2^-255
    // from either blessed source, `ciphersuite.mockedRandomScalars`/
    // `calculateRandomScalars`) and would make `Abar` the identity AND
    // `r4 = -(r1^-1)` undefined — rejected as a malformed
    // `random_scalars` input rather than UB.
    const r1_inv = r1.inv() catch return error.RandomScalarCountMismatch;

    const b = computeB(domain, generators, message_scalars);
    const abar_j = G1.Jacobian.fromAffine(sig.a).scalarMul(r1);
    const bbar_j = b.scalarMul(r1).add(abar_j.scalarMul(sig.e).negate());
    var t_j = abar_j.scalarMul(r2).add(bbar_j.scalarMul(r3));
    for (undisclosed, m_tilde) |j, mt| {
        t_j = t_j.add(G1.Jacobian.fromAffine(generators[j + 1]).scalarMul(mt));
    }
    const abar = abar_j.toAffine();
    const bbar = bbar_j.toAffine();

    // -- ProofChallengeCalculate (draft §3.7.4) --
    const disclosed_scalars = try allocator.alloc(Fr, disclosed_indexes.len);
    defer allocator.free(disclosed_scalars);
    for (disclosed_indexes, disclosed_scalars) |i, *s| s.* = message_scalars[i];
    const challenge = try calculateChallenge(allocator, abar, bbar, t_j.toAffine(), disclosed_indexes, disclosed_scalars, domain, ph);

    // -- ProofFinalize (draft §3.7.2) --
    const r4 = r1_inv.neg(); // r4 = -(r1^-1) mod r
    const r2_hat = r2.add(sig.e.mul(r4).mul(challenge));
    const r3_hat = r3.add(r4.mul(challenge));
    const m_hat = try allocator.alloc(Fr, undisclosed.len);
    defer allocator.free(m_hat);
    for (undisclosed, m_tilde, m_hat) |j, mt, *mh| {
        mh.* = mt.add(message_scalars[j].mul(challenge));
    }

    const out: Proof = .{ .abar = abar, .bbar = bbar, .r2_hat = r2_hat, .r3_hat = r3_hat, .m_hat = m_hat, .c = challenge };
    return try out.toBytes(allocator);
}

/// FABLE CORE — `ProofVerify(PK, proof, header, ph, disclosed_messages,
/// disclosed_indexes)` (draft §3.5.4 wrapping §3.6.4's
/// `CoreProofVerify`, itself `ProofVerifyInit` (§3.7.3) +
/// `ProofChallengeCalculate` (§3.7.4)).
///
/// `disclosed_messages.len` MUST equal `disclosed_indexes.len` (draft
/// §3.7.3 ABORT condition 2 — `error.DisclosedMessageCountMismatch`
/// otherwise). `L` (total original message count) and `U` (undisclosed
/// count) are BOTH recovered without an explicit parameter: `U =
/// Proof.fromBytes`'s derived `m_hat.len`, `L = disclosed_indexes.len +
/// U` (draft §3.7.3 steps 1-4).
///
/// Construction (draft §3.6.4 + §3.7.3 + §3.7.4, composed;
/// `undisclosed_indexes = {0..L-1} \ disclosed_indexes`, ascending):
/// ```
/// 1. proof = Proof.fromBytes(allocator, proof_bytes)   // rejects malformed input
/// 2. R = disclosed_indexes.len; U = proof.m_hat.len; L = R + U
/// 3. disclosed_scalars = ciphersuite.messagesToScalars(allocator, disclosed_messages)
/// 4. generators = ciphersuite.createGenerators(allocator, L + 1)
///    (Q_1, H_1, ..., H_L) = (generators[0], generators[1..])
///
/// -- ProofVerifyInit (§3.7.3) --
/// 5. domain = ciphersuite.calculateDomain(allocator, pk.toBytes(), Q_1, H_1..H_L, header)
/// 6. D = P1 + [domain]Q_1 + sum_{i in disclosed} [disclosed_scalars[i]]H_i
/// 7. T = [proof.r2_hat]Abar + [proof.r3_hat]Bbar
///        + sum_{j in undisclosed} [proof.m_hat[j]]H_j
/// 8. T = T + [proof.c]D
///
/// -- ProofChallengeCalculate (§3.7.4) — MUST reproduce proof.c --
/// 9.  c_arr  = (proof.abar, proof.bbar, T, R, i1, .., iR, disclosed_scalars, domain)
/// 10. c_octs = serialize(c_arr) || I2OSP(len(ph), 8) || ph
/// 11. recomputed_challenge = hash_to_scalar(c_octs, h2s_dst)
/// 12. if recomputed_challenge != proof.c, return false
///
/// -- pairing check --
/// 13. return pairing.pairingCheck(&.{
///         .{ .p = proof.abar, .q = pk.point },
///         .{ .p = proof.bbar, .q = -BP2 },
///     })
/// ```
/// Total/fail-closed on malformed `proof` bytes (returns `false`).
/// Byte-exact-input-round-trip against `mattrglobal/pairing_crypto`'s
/// `proof001.json`/`proof003.json` (expect `true`) and `proof004.json`
/// (tampered presentation header — expect `false`) — see
/// `kat_test.zig`'s gated tests.
pub fn proofVerify(
    allocator: std.mem.Allocator,
    pk: PublicKey,
    proof: []const u8,
    header: []const u8,
    ph: []const u8,
    disclosed_messages: []const []const u8,
    disclosed_indexes: []const usize,
) BbsError!bool {
    if (disclosed_messages.len != disclosed_indexes.len) return error.DisclosedMessageCountMismatch;

    // Fail-closed on malformed proof bytes (draft §3.6.4 steps 1-2's
    // "return INVALID"); only a genuine allocation failure propagates.
    const parsed = Proof.fromBytes(allocator, proof) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return false,
    };
    defer parsed.deinit(allocator);

    const r_count = disclosed_indexes.len;
    const u_count = parsed.m_hat.len;
    const total = r_count + u_count; // L, recovered per draft §3.7.3 steps 1-4
    for (disclosed_indexes) |i| if (i >= total) return false;

    const undisclosed = try undisclosedIndexes(allocator, total, disclosed_indexes);
    defer allocator.free(undisclosed);
    // Duplicate disclosed index => the complement is bigger than U — the
    // disclosed set cannot belong to this proof. Reject, closed.
    if (undisclosed.len != u_count) return false;

    const disclosed_scalars = try cs.messagesToScalars(allocator, disclosed_messages);
    defer allocator.free(disclosed_scalars);
    const generators = try cs.createGenerators(allocator, total + 1);
    defer allocator.free(generators);
    const domain = try cs.calculateDomain(allocator, pk.toBytes(), generators[0], generators[1..], header);

    // -- ProofVerifyInit (draft §3.7.3), MSM-crossover form --
    //
    // Every scalar below is PUBLIC to the verifier: `disclosed_scalars`
    // are revealed by definition, and `r2_hat`/`r3_hat`/`m_hat`/`c` are
    // wire-received proof fields the prover already sent in the clear —
    // see the section comment above `msmPublic`'s definition for why
    // that makes the variable-time MSM safe here (unlike `sign`/
    // `proofGen`).
    const d_points = try allocator.alloc(G1.Affine, disclosed_indexes.len + 2);
    defer allocator.free(d_points);
    const d_scalars = try allocator.alloc(Fr, disclosed_indexes.len + 2);
    defer allocator.free(d_scalars);
    d_points[0] = cs.P1;
    d_scalars[0] = Fr.one;
    d_points[1] = generators[0];
    d_scalars[1] = domain;
    for (disclosed_indexes, disclosed_scalars, d_points[2..], d_scalars[2..]) |i, m, *dp, *ds| {
        dp.* = generators[i + 1];
        ds.* = m;
    }
    const d_j = try msmPublic(allocator, d_points, d_scalars);

    const t_points = try allocator.alloc(G1.Affine, undisclosed.len + 3);
    defer allocator.free(t_points);
    const t_scalars = try allocator.alloc(Fr, undisclosed.len + 3);
    defer allocator.free(t_scalars);
    t_points[0] = parsed.abar;
    t_scalars[0] = parsed.r2_hat;
    t_points[1] = parsed.bbar;
    t_scalars[1] = parsed.r3_hat;
    for (undisclosed, parsed.m_hat, t_points[2 .. 2 + undisclosed.len], t_scalars[2 .. 2 + undisclosed.len]) |j, mh, *tp, *ts| {
        tp.* = generators[j + 1];
        ts.* = mh;
    }
    t_points[t_points.len - 1] = d_j.toAffine();
    t_scalars[t_scalars.len - 1] = parsed.c;
    const t_j = try msmPublic(allocator, t_points, t_scalars);

    // -- ProofChallengeCalculate (draft §3.7.4) — MUST reproduce c --
    const challenge = try calculateChallenge(allocator, parsed.abar, parsed.bbar, t_j.toAffine(), disclosed_indexes, disclosed_scalars, domain, ph);
    if (!challenge.eql(parsed.c)) return false;

    // -- pairing check: e(Abar, W) == e(Bbar, BP2) (draft §3.6.4 step 5) --
    return cs.pairing.pairingCheck(&.{
        .{ .p = parsed.abar, .q = pk.point },
        .{ .p = parsed.bbar, .q = negBp2() },
    });
}

// ── tests (REAL, ungated — Signature/Proof codec only) ───────────────────

const testing = std.testing;

test "Signature.encoded_bytes is 80 (48 G1 compressed + 32 Fr)" {
    try testing.expectEqual(@as(usize, 80), Signature.encoded_bytes);
}

test "Signature round-trips through toBytes/fromBytes" {
    const a = G1.Affine.generator;
    var e_bytes = [_]u8{0} ** 32;
    e_bytes[31] = 9;
    const e = try Fr.fromBytes(e_bytes);
    const sig: Signature = .{ .a = a, .e = e };
    const bytes = sig.toBytes();
    const back = try Signature.fromBytes(bytes);
    try testing.expectEqualSlices(u8, &G1.toBytesCompressed(a), &G1.toBytesCompressed(back.a));
    try testing.expect(e.eql(back.e));
}

test "Signature.fromBytes rejects e == 0" {
    const a = G1.Affine.generator;
    const e_zero = [_]u8{0} ** 32;
    const sig: Signature = .{ .a = a, .e = Fr.zero };
    var bytes = sig.toBytes();
    bytes[G1.compressed_bytes..].* = e_zero;
    try testing.expectError(error.InvalidSignatureEncoding, Signature.fromBytes(bytes));
}

test "Proof.encodedLen matches draft formula (2*48 + (3+U)*32)" {
    try testing.expectEqual(@as(usize, 192), Proof.encodedLen(0));
    try testing.expectEqual(@as(usize, 192 + 6 * 32), Proof.encodedLen(6));
}

test "Proof round-trips through toBytes/fromBytes (U = 2 undisclosed)" {
    var m1b = [_]u8{0} ** 32;
    m1b[31] = 11;
    var m2b = [_]u8{0} ** 32;
    m2b[31] = 22;
    const m_hat = try testing.allocator.alloc(Fr, 2);
    defer testing.allocator.free(m_hat);
    m_hat[0] = try Fr.fromBytes(m1b);
    m_hat[1] = try Fr.fromBytes(m2b);

    var scalar_bytes = [_]u8{0} ** 32;
    scalar_bytes[31] = 3;
    const some_scalar = try Fr.fromBytes(scalar_bytes);

    const proof: Proof = .{
        .abar = G1.Affine.generator,
        .bbar = G1.Affine.generator,
        .r2_hat = some_scalar,
        .r3_hat = some_scalar,
        .m_hat = m_hat,
        .c = some_scalar,
    };
    const bytes = try proof.toBytes(testing.allocator);
    defer testing.allocator.free(bytes);
    // NOTE: `proof.m_hat` IS `m_hat` (this test allocated it directly and
    // frees it itself, above) — do NOT also call `proof.deinit` here, or
    // the `m_hat[0]`/`m_hat[1]` comparisons below would use-after-free.

    try testing.expectEqual(Proof.encodedLen(2), bytes.len);

    const back = try Proof.fromBytes(testing.allocator, bytes);
    defer back.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), back.m_hat.len);
    try testing.expect(back.m_hat[0].eql(m_hat[0]));
    try testing.expect(back.m_hat[1].eql(m_hat[1]));
}

test "Proof.fromBytes rejects a length not aligned to a whole scalar count" {
    const floor = 2 * G1.compressed_bytes + 3 * Fr.encoded_bytes;
    var bad: [floor + 5]u8 = @splat(0);
    // Fill with something that at least parses as points/scalars up to
    // the misalignment so the length check itself is what's exercised.
    bad[0..G1.compressed_bytes].* = G1.toBytesCompressed(G1.Affine.generator);
    bad[G1.compressed_bytes..][0..G1.compressed_bytes].* = G1.toBytesCompressed(G1.Affine.generator);
    try testing.expectError(error.InvalidProofEncoding, Proof.fromBytes(testing.allocator, &bad));
}

test "Proof.fromBytes rejects a too-short buffer" {
    const too_short: [10]u8 = @splat(0);
    try testing.expectError(error.InvalidProofEncoding, Proof.fromBytes(testing.allocator, &too_short));
}

test "proofGen validates disclosed_indexes/random_scalars count before touching the core" {
    const messages = [_][]const u8{ "a", "b", "c" };
    var sig_bytes: [Signature.encoded_bytes]u8 = @splat(0);
    sig_bytes[0..G1.compressed_bytes].* = G1.toBytesCompressed(G1.Affine.generator);
    var e_bytes = [_]u8{0} ** 32;
    e_bytes[31] = 1;
    sig_bytes[G1.compressed_bytes..].* = e_bytes;
    var sk_bytes = [_]u8{0} ** 32;
    sk_bytes[31] = 1;
    const sk = try SecretKey.fromBytes(sk_bytes);
    const pk = keys.skToPk(sk);

    // Too many disclosed indexes: caught before the panic.
    try testing.expectError(error.TooManyDisclosedIndexes, proofGen(
        testing.allocator,
        pk,
        sig_bytes,
        "",
        "",
        &messages,
        &.{ 0, 1, 2, 3 },
        &.{},
    ));

    // Out-of-range disclosed index: caught before the panic.
    try testing.expectError(error.DisclosedIndexOutOfRange, proofGen(
        testing.allocator,
        pk,
        sig_bytes,
        "",
        "",
        &messages,
        &.{5},
        &.{},
    ));

    // Wrong random_scalars count (need 3 + (3-1) = 5 for disclosed_indexes={0}): caught before the panic.
    try testing.expectError(error.RandomScalarCountMismatch, proofGen(
        testing.allocator,
        pk,
        sig_bytes,
        "",
        "",
        &messages,
        &.{0},
        &.{},
    ));
}

test "proofGen REJECTS a duplicate disclosed index instead of silently under-counting undisclosed messages" {
    // disclosed_indexes = {0, 0} makes the FORMULA's undisclosed_count
    // (messages.len - disclosed_indexes.len = 3 - 2 = 1) diverge from the
    // TRUE undisclosed set ({1, 2}, length 2) once duplicates collapse —
    // this is the exact case root.zig's doc comment on `undisclosedIndexes`
    // calls out as "callers' duplicate-detection signal". A caller that
    // supplies random_scalars sized to the (wrong) formula count must be
    // rejected, not silently proceed with a mismatched undisclosed/m_tilde
    // pairing (which would zip two different-length slices).
    const messages = [_][]const u8{ "a", "b", "c" };
    var sig_bytes: [Signature.encoded_bytes]u8 = @splat(0);
    sig_bytes[0..G1.compressed_bytes].* = G1.toBytesCompressed(G1.Affine.generator);
    var e_bytes = [_]u8{0} ** 32;
    e_bytes[31] = 1;
    sig_bytes[G1.compressed_bytes..].* = e_bytes;
    var sk_bytes = [_]u8{0} ** 32;
    sk_bytes[31] = 1;
    const sk = try SecretKey.fromBytes(sk_bytes);
    const pk = keys.skToPk(sk);

    // NONZERO scalars throughout — critically r1 != 0, so this exercises
    // the duplicate-index guard itself rather than the separate `r1 == 0`
    // rejection at `r1.inv()`.
    var one_bytes = [_]u8{0} ** 32;
    one_bytes[31] = 1;
    const one = try Fr.fromBytes(one_bytes);
    const random_scalars = [_]Fr{one} ** 4; // 3 + formula's undisclosed_count(1)
    try testing.expectError(error.RandomScalarCountMismatch, proofGen(
        testing.allocator,
        pk,
        sig_bytes,
        "",
        "",
        &messages,
        &.{ 0, 0 },
        &random_scalars,
    ));
}

test "proofVerify validates disclosed_messages/disclosed_indexes count before touching the core" {
    var sk_bytes = [_]u8{0} ** 32;
    sk_bytes[31] = 1;
    const sk = try SecretKey.fromBytes(sk_bytes);
    const pk = keys.skToPk(sk);
    try testing.expectError(error.DisclosedMessageCountMismatch, proofVerify(
        testing.allocator,
        pk,
        &.{},
        "",
        "",
        &.{"a"},
        &.{ 0, 1 },
    ));
}

// ── the RNG seam (entropy re-audit 2026-08-13) ───────────────────────────

test "RNG seam: calculateRandomScalars really draws entropy, and round-trips through proofGen/proofVerify" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // A signature pin alone would pass over a body that ignores `io`. Two
    // draws of the SAME count from the SAME `io` must differ.
    //
    // This catches a constant blinding-scalar buffer and a buffer that is
    // drawn but never read. It does NOT catch a weak-but-varying PRNG
    // substituted for `entropy.fill` — two draws from a seeded
    // `DefaultPrng` also differ from each other, so distinctness alone
    // cannot tell "real entropy" from "some other varying stream". Pinning
    // *which* `std.Io` vtable slot is hit (`entropy`'s own `CountingIo`,
    // `modules/entropy/src/root.zig:298`) is not applied here: that probe
    // is a private test helper of the `entropy` module, and `bbs` has one
    // call site — `calculateRandomScalars` — that does nothing but forward
    // to `entropy.fill`, already covered by `entropy`'s own suite.
    //
    // A third gap, sharper than the second: this also does not catch a
    // PARTIAL draw into any one scalar's 48-byte `expand_len` buffer —
    // `entropy.fill` covering only part of it before `Fr.reduceWide` still
    // yields a scalar that differs from the next call's, so the loop below
    // cannot distinguish that from a fully-drawn buffer. Measured directly
    // in `megolm`'s 128-byte ratchet seed (`session.zig`): zeroing 96 of the
    // 128 drawn bytes right after `entropy.fill` left `zig build
    // test-megolm` green on an assertion of this same shape. Not
    // re-measured here, but each scalar's buffer is filled the same way.
    const scalars1 = cs.calculateRandomScalars(3, io);
    const scalars2 = cs.calculateRandomScalars(3, io);
    var any_differs = false;
    for (scalars1, scalars2) |a, b| {
        if (!a.eql(b)) any_differs = true;
    }
    try testing.expect(any_differs);

    // And the production path is a working path, not just a typed one:
    // sign a message, then prove-and-verify selective disclosure with
    // random_scalars drawn from the same `io` (U = 0 undisclosed, so 3
    // scalars — r1, r2, r3 — matches `calculateRandomScalars(3, io)` above).
    var sk_bytes = [_]u8{0} ** 32;
    sk_bytes[31] = 1;
    const sk = try SecretKey.fromBytes(sk_bytes);
    const pk = keys.skToPk(sk);
    const messages = [_][]const u8{"only message"};
    const sig = try sign(testing.allocator, sk, pk, "header", &messages);
    try testing.expect(try verify(testing.allocator, pk, sig, "header", &messages));

    const random_scalars = cs.calculateRandomScalars(3, io);
    const proof = try proofGen(
        testing.allocator,
        pk,
        sig,
        "header",
        "",
        &messages,
        &.{0},
        &random_scalars,
    );
    defer testing.allocator.free(proof);
    try testing.expect(try proofVerify(
        testing.allocator,
        pk,
        proof,
        "header",
        "",
        &messages,
        &.{0},
    ));
}

// ── fuzz harnesses (untrusted-wire decoders) ────────────────────────────

test "fuzz: Signature.fromBytes never crashes on arbitrary bytes" {
    try testing.fuzz({}, fuzzSignatureFromBytes, .{});
}

fn fuzzSignatureFromBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [Signature.encoded_bytes]u8 = undefined;
    smith.bytes(&buf);
    const sig = Signature.fromBytes(buf) catch return;
    _ = sig.toBytes();
}

test "fuzz: PublicKey.fromBytes never crashes on arbitrary bytes" {
    try testing.fuzz({}, fuzzPublicKeyFromBytes, .{});
}

fn fuzzPublicKeyFromBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [PublicKey.encoded_bytes]u8 = undefined;
    smith.bytes(&buf);
    const pk = PublicKey.fromBytes(buf) catch return;
    _ = pk.toBytes();
}

test "fuzz: Proof.fromBytes never crashes on arbitrary bytes" {
    try testing.fuzz({}, fuzzProofFromBytes, .{});
}

fn fuzzProofFromBytes(_: void, smith: *std.testing.Smith) !void {
    // Cover both a "floor-only" length (U=0) and a length with a few
    // undisclosed scalars, plus arbitrary (possibly misaligned) lengths —
    // exercises both the remainder-rejection path and the point/scalar
    // structural checks.
    var buf: [2 * G1.compressed_bytes + 8 * Fr.encoded_bytes]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u32, 0, @intCast(buf.len));
    const proof = Proof.fromBytes(testing.allocator, buf[0..len]) catch return;
    defer proof.deinit(testing.allocator);
    if (proof.toBytes(testing.allocator)) |out| testing.allocator.free(out) else |_| {}
}

// ── F4: computeB MSM crossover — differential oracle + bench ────────────

fn testRandomFr(rand: std.Random) Fr {
    var buf: [48]u8 = undefined;
    rand.bytes(&buf);
    return Fr.reduceWide(&buf);
}

/// TEST-ONLY oracle: reproduces `proofVerify`'s ORIGINAL (pre-F4)
/// sequential `ProofVerifyInit` `d_j`/`t_j` accumulation verbatim,
/// unchanged, so the MSM-crossover form now live in `proofVerify` has
/// something to be checked against that never itself changed. Not called
/// from production code — differential-test anchor only.
fn proofVerifyInitLoopOracle(
    generators: []const G1.Affine,
    domain: Fr,
    disclosed_indexes: []const usize,
    disclosed_scalars: []const Fr,
    undisclosed: []const usize,
    m_hat: []const Fr,
    abar: G1.Affine,
    bbar: G1.Affine,
    r2_hat: Fr,
    r3_hat: Fr,
    c: Fr,
) struct { d: G1.Jacobian, t: G1.Jacobian } {
    var d_j = G1.Jacobian.fromAffine(cs.P1)
        .add(G1.Jacobian.fromAffine(generators[0]).scalarMul(domain));
    for (disclosed_indexes, disclosed_scalars) |i, m| {
        d_j = d_j.add(G1.Jacobian.fromAffine(generators[i + 1]).scalarMul(m));
    }
    var t_j = G1.Jacobian.fromAffine(abar).scalarMul(r2_hat)
        .add(G1.Jacobian.fromAffine(bbar).scalarMul(r3_hat));
    for (undisclosed, m_hat) |j, mh| {
        t_j = t_j.add(G1.Jacobian.fromAffine(generators[j + 1]).scalarMul(mh));
    }
    t_j = t_j.add(d_j.scalarMul(c));
    return .{ .d = d_j, .t = t_j };
}

test "F4 oracle: computeB (sequential) == msmLoop == msmPippenger == computeBPublic, bit-exact, across L" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xB855_F0FA);
    const rand = prng.random();

    // L = 0, 1, 2 (the brief's mandated minimum), straddling msm_crossover
    // (== 2, see its doc comment) on both sides, and well past it.
    const ls = [_]usize{ 0, 1, 2, 3, 4, 8, 16, 64, 300 };

    for (ls) |l| {
        const generators = try cs.createGenerators(allocator, l + 1);
        defer allocator.free(generators);
        const message_scalars = try allocator.alloc(Fr, l);
        defer allocator.free(message_scalars);
        for (message_scalars) |*m| m.* = testRandomFr(rand);
        const domain = testRandomFr(rand);

        // The oracle: computeB, UNCHANGED, still `sign`'s/`proofGen`'s only
        // path.
        const want = computeB(domain, generators, message_scalars).toAffine();
        const want_bytes = G1.toBytesCompressed(want);

        // The same (points, scalars) computeBPublic assembles internally.
        const points = try allocator.alloc(G1.Affine, l + 2);
        defer allocator.free(points);
        const scalars = try allocator.alloc(Fr, l + 2);
        defer allocator.free(scalars);
        points[0] = cs.P1;
        scalars[0] = Fr.one;
        points[1] = generators[0];
        scalars[1] = domain;
        @memcpy(points[2..], generators[1..]);
        @memcpy(scalars[2..], message_scalars);

        const got_loop = msmLoop(points, scalars).toAffine();
        try testing.expectEqualSlices(u8, &want_bytes, &G1.toBytesCompressed(got_loop));

        // Force the Pippenger path regardless of `msm_crossover`, so the
        // MSM algorithm itself is checked at every L, not only where the
        // dispatcher happens to route to it.
        const got_pippenger = (try msmPippenger(allocator, points, scalars)).toAffine();
        try testing.expectEqualSlices(u8, &want_bytes, &G1.toBytesCompressed(got_pippenger));

        // The actual dispatcher, as `verify` calls it.
        const got_public = (try computeBPublic(allocator, domain, generators, message_scalars)).toAffine();
        try testing.expectEqualSlices(u8, &want_bytes, &G1.toBytesCompressed(got_public));
    }
}

test "F4 oracle: proofVerify's ProofVerifyInit — MSM form matches the original sequential form, bit-exact, across L" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x0D5F_1E17);
    const rand = prng.random();

    // total = R (disclosed) + U (undisclosed); cover R/U = 0 and a spread
    // straddling msm_crossover (== 2) for each of the two MSM calls (d_j
    // has R+2 terms, t_j has U+3).
    const totals = [_]usize{ 0, 1, 2, 3, 8, 300 };

    for (totals) |total| {
        const generators = try cs.createGenerators(allocator, total + 1);
        defer allocator.free(generators);

        // Split roughly in half: disclosed = evens, undisclosed = odds.
        var disclosed_indexes: std.ArrayList(usize) = .empty;
        defer disclosed_indexes.deinit(allocator);
        var undisclosed: std.ArrayList(usize) = .empty;
        defer undisclosed.deinit(allocator);
        for (0..total) |i| {
            if (i % 2 == 0) try disclosed_indexes.append(allocator, i) else try undisclosed.append(allocator, i);
        }

        const disclosed_scalars = try allocator.alloc(Fr, disclosed_indexes.items.len);
        defer allocator.free(disclosed_scalars);
        for (disclosed_scalars) |*s| s.* = testRandomFr(rand);
        const m_hat = try allocator.alloc(Fr, undisclosed.items.len);
        defer allocator.free(m_hat);
        for (m_hat) |*s| s.* = testRandomFr(rand);

        const domain = testRandomFr(rand);
        const abar = G1.Jacobian.fromAffine(G1.Affine.generator).scalarMul(testRandomFr(rand)).toAffine();
        const bbar = G1.Jacobian.fromAffine(G1.Affine.generator).scalarMul(testRandomFr(rand)).toAffine();
        const r2_hat = testRandomFr(rand);
        const r3_hat = testRandomFr(rand);
        const c = testRandomFr(rand);

        const want = proofVerifyInitLoopOracle(generators, domain, disclosed_indexes.items, disclosed_scalars, undisclosed.items, m_hat, abar, bbar, r2_hat, r3_hat, c);

        // Reproduce exactly what `proofVerify` now builds.
        const d_points = try allocator.alloc(G1.Affine, disclosed_indexes.items.len + 2);
        defer allocator.free(d_points);
        const d_scalars = try allocator.alloc(Fr, disclosed_indexes.items.len + 2);
        defer allocator.free(d_scalars);
        d_points[0] = cs.P1;
        d_scalars[0] = Fr.one;
        d_points[1] = generators[0];
        d_scalars[1] = domain;
        for (disclosed_indexes.items, disclosed_scalars, d_points[2..], d_scalars[2..]) |i, m, *dp, *ds| {
            dp.* = generators[i + 1];
            ds.* = m;
        }
        const got_d = try msmPublic(allocator, d_points, d_scalars);
        try testing.expectEqualSlices(u8, &G1.toBytesCompressed(want.d.toAffine()), &G1.toBytesCompressed(got_d.toAffine()));

        const t_points = try allocator.alloc(G1.Affine, undisclosed.items.len + 3);
        defer allocator.free(t_points);
        const t_scalars = try allocator.alloc(Fr, undisclosed.items.len + 3);
        defer allocator.free(t_scalars);
        t_points[0] = abar;
        t_scalars[0] = r2_hat;
        t_points[1] = bbar;
        t_scalars[1] = r3_hat;
        for (undisclosed.items, m_hat, t_points[2 .. 2 + undisclosed.items.len], t_scalars[2 .. 2 + undisclosed.items.len]) |j, mh, *tp, *ts| {
            tp.* = generators[j + 1];
            ts.* = mh;
        }
        t_points[t_points.len - 1] = got_d.toAffine();
        t_scalars[t_scalars.len - 1] = c;
        const got_t = try msmPublic(allocator, t_points, t_scalars);
        try testing.expectEqualSlices(u8, &G1.toBytesCompressed(want.t.toAffine()), &G1.toBytesCompressed(got_t.toAffine()));
    }
}

fn nowNsBench() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

test "bench (opt-in via BBS_BENCH): computeB-shape loop vs Pippenger MSM crossover" {
    if (@import("builtin").target.os.tag == .windows or std.testing.environ.getPosix("BBS_BENCH") == null) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xF4F4_CAFE);
    const rand = prng.random();

    // Term counts (= L + 2, the size computeB/computeBPublic actually
    // handle). All well under a KB of G1.Affine each — see the module doc
    // comment for why this stays far from the sizes that have OOM-killed
    // this host before.
    const ns = [_]usize{ 1, 2, 4, 8, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512 };

    std.debug.print("\nbbs F4: computeB-shape MSM crossover (msmLoop vs msmPippenger, n terms)\n", .{});
    std.debug.print("{s:>6} | {s:>14} | {s:>14} | {s:>8}\n", .{ "n", "loop ns/op", "pippenger ns/op", "winner" });

    for (ns) |n| {
        const points = try allocator.alloc(G1.Affine, n);
        defer allocator.free(points);
        const scalars = try allocator.alloc(Fr, n);
        defer allocator.free(scalars);
        const gens = try cs.createGenerators(allocator, n);
        defer allocator.free(gens);
        @memcpy(points, gens);
        for (scalars) |*s| s.* = testRandomFr(rand);

        // Repeat instead of enlarge for timing stability.
        const iters: usize = if (n <= 32) 300 else if (n <= 128) 60 else 15;

        const t0 = nowNsBench();
        for (0..iters) |_| std.mem.doNotOptimizeAway(msmLoop(points, scalars));
        const loop_ns = (nowNsBench() - t0) / iters;

        const t1 = nowNsBench();
        for (0..iters) |_| std.mem.doNotOptimizeAway(msmPippenger(allocator, points, scalars) catch unreachable);
        const pip_ns = (nowNsBench() - t1) / iters;

        std.debug.print("{d:>6} | {d:>14} | {d:>14} | {s:>8}\n", .{ n, loop_ns, pip_ns, if (pip_ns < loop_ns) "MSM" else "loop" });
    }
}
