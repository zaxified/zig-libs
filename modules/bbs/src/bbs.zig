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
//! draft-irtf-cfrg-bbs-signatures-12 — see `../SPEC.md` for the pin and `gate.zig` for the scaffold-then-Fable
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
//! `randomScalarCount(U) = 5 + U`, `U` = the undisclosed-message count) rather than an `io:
//! std.Io`/internal RNG read. This mirrors `frost`'s "nonces are an
//! explicit input" convention (`frost/src/root.zig`), and is what makes
//! the draft's own deterministic `mocked_random_scalars` (KAT
//! reproducibility, draft §7.1 — `ciphersuite.mockedRandomScalars`) and
//! real entropy (`ciphersuite.calculateRandomScalars`) interchangeable
//! at this boundary: `kat_test.zig`'s gated `proofGen` tests pass a
//! `mockedRandomScalars(5 + U, seed)` slice and assert the exact
//! resulting proof bytes; a real caller would instead pass
//! `&calculateRandomScalars(5 + U, io)`.

const std = @import("std");
const builtin = @import("builtin");
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
        // The decoder refuses a point outside the subgroup.
        const a = G1.fromBytesCompressed(bytes[0..G1.compressed_bytes].*) catch return error.InvalidSignatureEncoding;
        if (a.infinity) return error.InvalidSignatureEncoding;
        const e = Fr.fromBytes(bytes[G1.compressed_bytes..].*) catch return error.InvalidSignatureEncoding;
        if (e.isZero()) return error.InvalidSignatureEncoding;
        return .{ .a = a, .e = e };
    }
};

/// A BBS proof: `(Abar, Bbar, D, e^, r1^, r3^, m^[0..U], c)` — draft-12
/// §3.7.2's `ProofFinalize` output shape (`Abar`/`Bbar`/`D` three `G1`
/// points; `e^`/`r1^`/`r3^`/`c` four scalars; `m^` one scalar per
/// UNDISCLOSED message). Variable-length wire encoding: `3 *
/// G1.compressed_bytes + (4 + U) * Fr.encoded_bytes` — `U = m_hat.len` is
/// recovered from the encoded length itself on decode (draft §4.2.4.5),
/// not carried out-of-band.
pub const Proof = struct {
    abar: G1.Affine,
    bbar: G1.Affine,
    d: G1.Affine,
    e_hat: Fr,
    r1_hat: Fr,
    r3_hat: Fr,
    /// One response scalar per UNDISCLOSED message (`m^_j1 .. m^_jU`,
    /// draft §3.7.2 step 5). Owned by whoever constructed this `Proof`
    /// (`proofGen`'s return, or `fromBytes`'s allocation) — free with
    /// `deinit`.
    m_hat: []const Fr,
    c: Fr,

    /// `3 * 48 + 4 * 32 = 272` octets with nothing undisclosed.
    pub const floor_bytes = 3 * G1.compressed_bytes + 4 * Fr.encoded_bytes;

    pub fn encodedLen(undisclosed_count: usize) usize {
        return floor_bytes + undisclosed_count * Fr.encoded_bytes;
    }

    pub fn deinit(self: Proof, allocator: std.mem.Allocator) void {
        allocator.free(self.m_hat);
    }

    /// `proof_to_octets` (draft §4.2.4.4): `serialize((Abar, Bbar, D, e^,
    /// r1^, r3^, m^_1, .., m^_U, c))` — points compressed, scalars
    /// `I2OSP(.., 32)`. Caller owns the returned slice.
    pub fn toBytes(self: Proof, allocator: std.mem.Allocator) ![]u8 {
        const out = try allocator.alloc(u8, encodedLen(self.m_hat.len));
        errdefer allocator.free(out);
        var off: usize = 0;
        for ([_]G1.Affine{ self.abar, self.bbar, self.d }) |p| {
            out[off..][0..G1.compressed_bytes].* = G1.toBytesCompressed(p);
            off += G1.compressed_bytes;
        }
        for ([_]Fr{ self.e_hat, self.r1_hat, self.r3_hat }) |x| {
            out[off..][0..Fr.encoded_bytes].* = x.toBytes();
            off += Fr.encoded_bytes;
        }
        for (self.m_hat) |m| {
            out[off..][0..Fr.encoded_bytes].* = m.toBytes();
            off += Fr.encoded_bytes;
        }
        out[off..][0..Fr.encoded_bytes].* = self.c.toBytes();
        off += Fr.encoded_bytes;
        std.debug.assert(off == out.len);
        return out;
    }

    /// `octets_to_proof` (draft §4.2.4.5): `U = (bytes.len - floor_bytes) /
    /// 32`, REJECTING a remainder. Each of `Abar`/`Bbar`/`D` must decode to
    /// a non-identity point of `G1` (the decoder subgroup-checks), and
    /// every scalar must be in `1..r-1`. Caller owns the returned `.m_hat`
    /// (free via `.deinit`).
    pub fn fromBytes(allocator: std.mem.Allocator, bytes: []const u8) BbsError!Proof {
        if (bytes.len < floor_bytes) return error.InvalidProofEncoding;
        if ((bytes.len - floor_bytes) % Fr.encoded_bytes != 0) return error.InvalidProofEncoding;
        const u = (bytes.len - floor_bytes) / Fr.encoded_bytes;

        var off: usize = 0;
        var points: [3]G1.Affine = undefined;
        for (&points) |*p| {
            // The decoder refuses a point outside the subgroup.
            p.* = G1.fromBytesCompressed(bytes[off..][0..G1.compressed_bytes].*) catch return error.InvalidProofEncoding;
            if (p.infinity) return error.InvalidProofEncoding;
            off += G1.compressed_bytes;
        }
        var head: [3]Fr = undefined;
        for (&head) |*x| {
            x.* = try fromBytesNonzeroScalar(bytes[off..][0..Fr.encoded_bytes].*);
            off += Fr.encoded_bytes;
        }

        const m_hat = try allocator.alloc(Fr, u);
        errdefer allocator.free(m_hat);
        for (m_hat) |*m| {
            m.* = try fromBytesNonzeroScalar(bytes[off..][0..Fr.encoded_bytes].*);
            off += Fr.encoded_bytes;
        }

        const c = try fromBytesNonzeroScalar(bytes[off..][0..Fr.encoded_bytes].*);
        off += Fr.encoded_bytes;
        std.debug.assert(off == bytes.len);

        return .{ .abar = points[0], .bbar = points[1], .d = points[2], .e_hat = head[0], .r1_hat = head[1], .r3_hat = head[2], .m_hat = m_hat, .c = c };
    }
};

/// How many random scalars `proofGen` takes for `undisclosed_count`
/// undisclosed messages: `5 + U` (draft-12 §3.6.3 — `r1, r2, e~, r1~, r3~`
/// and one `m~_j` per undisclosed message).
pub fn randomScalarCount(undisclosed_count: usize) usize {
    return 5 + undisclosed_count;
}

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
fn computeB(p1: G1.Affine, domain: Fr, generators: []const G1.Affine, message_scalars: []const Fr) G1.Jacobian {
    std.debug.assert(generators.len == message_scalars.len + 1);
    var b = G1.Jacobian.fromAffine(p1)
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
// (`Abar`/`Bbar`/`D`/`e^`/`r1^`/`r3^`/`m^`/`c`) the prover already
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
fn computeBPublic(allocator: std.mem.Allocator, p1: G1.Affine, domain: Fr, generators: []const G1.Affine, message_scalars: []const Fr) std.mem.Allocator.Error!G1.Jacobian {
    std.debug.assert(generators.len == message_scalars.len + 1);
    const n = generators.len + 1; // + P1
    const points = try allocator.alloc(G1.Affine, n);
    defer allocator.free(points);
    const scalars = try allocator.alloc(Fr, n);
    defer allocator.free(scalars);
    points[0] = p1;
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

/// `ProofChallengeCalculate` (draft-12 §3.7.4), shared by `proofGen` and
/// `proofVerify` — the ONE place the Fiat-Shamir transcript is
/// serialized, so the two sides cannot drift:
/// ```
/// c_arr  = (R, i1, msg_i1, .., iR, msg_iR, Abar, Bbar, D, T1, T2, domain)
/// c_octs = serialize(c_arr) || I2OSP(len(ph), 8) || ph
/// c      = hash_to_scalar(c_octs, api_id || "H2S_")
/// ```
/// `serialize` per draft §4.2.4.1: the count `R` and each index as
/// `I2OSP(.., 8)`, scalars as `I2OSP(.., 32)`, points compressed. Each
/// index is followed by ITS message (draft-04 listed all indexes, then all
/// messages, and put the points first).
fn calculateChallenge(
    comptime Suite: type,
    allocator: std.mem.Allocator,
    points: [5]G1.Affine, // Abar, Bbar, D, T1, T2
    disclosed_indexes: []const usize,
    disclosed_scalars: []const Fr,
    domain: Fr,
    ph: []const u8,
) std.mem.Allocator.Error!Fr {
    std.debug.assert(disclosed_indexes.len == disclosed_scalars.len);
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try appendU64(&buf, allocator, disclosed_indexes.len);
    for (disclosed_indexes, disclosed_scalars) |i, m| {
        try appendU64(&buf, allocator, i);
        try buf.appendSlice(allocator, &m.toBytes());
    }
    for (points) |p| try buf.appendSlice(allocator, &G1.toBytesCompressed(p));
    try buf.appendSlice(allocator, &domain.toBytes());
    try appendU64(&buf, allocator, ph.len);
    try buf.appendSlice(allocator, ph);
    return Suite.hashToScalar(buf.items, Suite.h2s_dst);
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

/// `ProofVerifyInit` (draft-12 §3.7.3) steps 2-4, MSM-crossover form:
/// ```
/// T1 = [c]Bbar + [e^]Abar + [r1^]D
/// Bv = P1 + [domain]Q_1 + sum_{i in disclosed} [msg_i]H_i
/// T2 = [c]Bv + [r3^]D + sum_{j in undisclosed} [m^_j]H_j
/// ```
/// Every scalar here is PUBLIC to the verifier: `disclosed_scalars` are
/// revealed by definition, and `e^`/`r1^`/`r3^`/`m^`/`c` are wire-received
/// proof fields the prover already sent in the clear — see the section
/// comment above `msmPublic`'s definition for why that makes the
/// variable-time MSM safe here (unlike `sign`/`proofGen`).
fn proofVerifyInit(
    allocator: std.mem.Allocator,
    p1: G1.Affine,
    generators: []const G1.Affine,
    domain: Fr,
    disclosed_indexes: []const usize,
    disclosed_scalars: []const Fr,
    undisclosed: []const usize,
    proof: Proof,
) std.mem.Allocator.Error!struct { t1: G1.Jacobian, t2: G1.Jacobian } {
    std.debug.assert(disclosed_indexes.len == disclosed_scalars.len);
    std.debug.assert(undisclosed.len == proof.m_hat.len);
    const t1 = try msmPublic(allocator, &.{ proof.bbar, proof.abar, proof.d }, &.{ proof.c, proof.e_hat, proof.r1_hat });

    const bv_points = try allocator.alloc(G1.Affine, disclosed_indexes.len + 2);
    defer allocator.free(bv_points);
    const bv_scalars = try allocator.alloc(Fr, disclosed_indexes.len + 2);
    defer allocator.free(bv_scalars);
    bv_points[0] = p1;
    bv_scalars[0] = Fr.one;
    bv_points[1] = generators[0];
    bv_scalars[1] = domain;
    for (disclosed_indexes, disclosed_scalars, bv_points[2..], bv_scalars[2..]) |i, m, *bp, *bs| {
        bp.* = generators[i + 1];
        bs.* = m;
    }
    const bv = try msmPublic(allocator, bv_points, bv_scalars);

    const t2_points = try allocator.alloc(G1.Affine, undisclosed.len + 2);
    defer allocator.free(t2_points);
    const t2_scalars = try allocator.alloc(Fr, undisclosed.len + 2);
    defer allocator.free(t2_scalars);
    t2_points[0] = bv.toAffine();
    t2_scalars[0] = proof.c;
    t2_points[1] = proof.d;
    t2_scalars[1] = proof.r3_hat;
    for (undisclosed, proof.m_hat, t2_points[2..], t2_scalars[2..]) |j, mh, *tp, *ts| {
        tp.* = generators[j + 1];
        ts.* = mh;
    }
    return .{ .t1 = t1, .t2 = try msmPublic(allocator, t2_points, t2_scalars) };
}

/// The four BBS cores for one ciphersuite (`ciphersuite.Sha256` or
/// `ciphersuite.Shake256`, draft-12 §7.2). `Signature`/`Proof` and their
/// codecs are suite-independent.
pub fn Scheme(comptime Suite: type) type {
    return struct {
        pub const suite = Suite;

        /// FABLE CORE — `Sign(SK, PK, header, messages)` (draft-12 §3.5.1
        /// Interface wrapping §3.6.1's `CoreSign`).
        ///
        /// Construction (draft §3.5.1 + §3.6.1, composed):
        /// ```
        /// 1. message_scalars = ciphersuite.messagesToScalars(allocator, messages)   // [msg_1..msg_L]
        /// 2. generators = ciphersuite.createGenerators(allocator, messages.len + 1)
        ///    (Q_1, H_1, ..., H_L) = (generators[0], generators[1..])
        /// 3. domain = ciphersuite.calculateDomain(allocator, pk.toBytes(), Q_1, H_1..H_L, header)
        /// 4. e = hash_to_scalar(serialize((sk, msg_1, .., msg_L, domain)), h2s_dst)
        ///    // "serialize" per draft §4.2.4.1: each scalar as I2OSP(.., 32),
        ///    // concatenated. draft-12 puts `domain` LAST (draft-04: right after
        ///    // `sk`, with a `comm` slot that was always empty here).
        /// 5. B = P1 + [domain]Q_1 + sum_i [msg_i]H_i        (Jacobian accumulation,
        ///                                                     P1 = ciphersuite.P1)
        /// 6. A = [(sk + e)^-1] B
        /// 7. return Signature{ .a = A.toAffine(), .e = e }.toBytes()
        /// ```
        /// Byte-exact against draft-12 §8.4.4 (single and ten messages) and
        /// Appendix D.2.1.1 (no header) — see `kat_test.zig`.
        pub fn sign(allocator: std.mem.Allocator, sk: SecretKey, pk: PublicKey, header: []const u8, messages: []const []const u8) BbsError![Signature.encoded_bytes]u8 {
            const message_scalars = try Suite.messagesToScalars(allocator, messages);
            defer allocator.free(message_scalars);
            const generators = try Suite.createGenerators(allocator, messages.len + 1);
            defer allocator.free(generators);
            const domain = try Suite.calculateDomain(allocator, pk.toBytes(), generators[0], generators[1..], header);

            // e = hash_to_scalar(serialize((SK, msg_1, .., msg_L, domain)),
            // api_id || "H2S_") — draft-12 §3.6.1 step 2; `serialize` per §4.2.4.1
            // is each scalar's 32-byte big-endian encoding, concatenated.
            var e_input: std.ArrayList(u8) = .empty;
            defer {
                std.crypto.secureZero(u8, e_input.items); // holds SK
                e_input.deinit(allocator);
            }
            try e_input.appendSlice(allocator, &sk.toBytes());
            for (message_scalars) |m| try e_input.appendSlice(allocator, &m.toBytes());
            try e_input.appendSlice(allocator, &domain.toBytes());
            const e = Suite.hashToScalar(e_input.items, Suite.h2s_dst);

            // B = P1 + [domain]Q_1 + sum_i [msg_i]H_i ;  A = [(SK + e)^-1]B.
            const b = computeB(Suite.P1, domain, generators, message_scalars);
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
        /// convention of never panicking on attacker-controlled input). The six
        /// invalid cases of draft-12 Appendix D.2.1 (modified, extra, missing and
        /// reordered messages, wrong public key, wrong header) are pinned in
        /// `kat_test.zig`.
        pub fn verify(allocator: std.mem.Allocator, pk: PublicKey, signature: [Signature.encoded_bytes]u8, header: []const u8, messages: []const []const u8) BbsError!bool {
            // Fail-closed on malformed signature bytes (draft §3.6.2 steps 1-2's
            // "return INVALID" — a boolean `false` at this Interface layer).
            const sig = Signature.fromBytes(signature) catch return false;

            const message_scalars = try Suite.messagesToScalars(allocator, messages);
            defer allocator.free(message_scalars);
            const generators = try Suite.createGenerators(allocator, messages.len + 1);
            defer allocator.free(generators);
            const domain = try Suite.calculateDomain(allocator, pk.toBytes(), generators[0], generators[1..], header);
            // `message_scalars` here are the caller's OWN plaintext messages
            // (non-selective CoreVerify) — public to this call, so the
            // MSM-crossover path (`computeBPublic`) is safe; see the section
            // comment above `computeBPublic`'s definition.
            const b = (try computeBPublic(allocator, Suite.P1, domain, generators, message_scalars)).toAffine();

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
        /// disclosed_indexes, random_scalars)` (draft-12 §3.5.3 wrapping §3.6.3's
        /// `CoreProofGen`, itself `ProofInit` (§3.7.1) + `ProofChallengeCalculate`
        /// (§3.7.4) + `ProofFinalize` (§3.7.2)) — **the module's genuinely hard
        /// core**, see this file's module doc comment.
        ///
        /// `random_scalars.len` MUST be exactly `randomScalarCount(U) = 5 + U`
        /// (`U = messages.len - disclosed_indexes.len`) — see this file's module
        /// doc comment for why this is an explicit parameter rather than internal
        /// entropy; `ciphersuite.mockedRandomScalars`/`calculateRandomScalars` are
        /// the two intended sources.
        ///
        /// Construction (draft-12 §3.6.3 + §3.7.1 + §3.7.4 + §3.7.2, composed;
        /// `L = messages.len`, `R = disclosed_indexes.len`, `U = L - R`,
        /// `undisclosed_indexes = {0..L-1} \ disclosed_indexes`, both ascending):
        /// ```
        /// 1. (A, e) = Signature.fromBytes(signature)
        /// 2. message_scalars = messagesToScalars(messages); generators = createGenerators(L + 1)
        /// 3. domain = calculateDomain(PK, Q_1, H_1..H_L, header)
        ///
        /// -- ProofInit (§3.7.1) --
        /// 4. (r1, r2, e~, r1~, r3~, m~_j1, .., m~_jU) = random_scalars
        /// 5. B    = P1 + [domain]Q_1 + sum_i [msg_i]H_i
        /// 6. D    = [r2]B
        /// 7. Abar = [r1 * r2]A
        /// 8. Bbar = [r1]D - [e]Abar
        /// 9. T1   = [e~]Abar + [r1~]D
        /// 10. T2  = [r3~]D + sum_{j in undisclosed} [m~_j]H_j
        ///
        /// -- ProofChallengeCalculate (§3.7.4) --
        /// 11. c = hash_to_scalar(serialize((R, i1, msg_i1, .., Abar, Bbar, D, T1, T2, domain))
        ///                        || I2OSP(len(ph), 8) || ph)
        ///
        /// -- ProofFinalize (§3.7.2) --
        /// 12. r3  = r2^-1
        /// 13. e^  = e~ + e * c;  r1^ = r1~ - r1 * c;  r3^ = r3~ - r3 * c
        /// 14. m^_j = m~_j + msg_j * c   for j in undisclosed (in order)
        /// 15. return proof_to_octets((Abar, Bbar, D, e^, r1^, r3^, m^, c))
        /// ```
        /// Byte-exact (under the draft's mocked RNG, `kat_vectors.mocked_rng`)
        /// against draft-12 §8.4.5 and Appendix D.2.2 — see `kat_test.zig`.
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
            if (random_scalars.len != randomScalarCount(undisclosed_count)) return error.RandomScalarCountMismatch;

            const sig = try Signature.fromBytes(signature);

            const message_scalars = try Suite.messagesToScalars(allocator, messages);
            defer allocator.free(message_scalars);
            const generators = try Suite.createGenerators(allocator, messages.len + 1);
            defer allocator.free(generators);
            const domain = try Suite.calculateDomain(allocator, pk.toBytes(), generators[0], generators[1..], header);

            const undisclosed = try undisclosedIndexes(allocator, messages.len, disclosed_indexes);
            defer allocator.free(undisclosed);
            // A DUPLICATE disclosed index makes the true undisclosed count exceed
            // `L - R`, so `random_scalars.len == 5 + (L - R)` can no longer be
            // the right count for the actual undisclosed set — surfaced as the
            // same count-mismatch error.
            if (undisclosed.len != undisclosed_count) return error.RandomScalarCountMismatch;

            // -- ProofInit (draft-12 §3.7.1) --
            const r1 = random_scalars[0];
            const r2 = random_scalars[1];
            const e_tilde = random_scalars[2];
            const r1_tilde = random_scalars[3];
            const r3_tilde = random_scalars[4];
            const m_tilde = random_scalars[5..];
            // `r2 == 0` is not a valid random-scalar draw (probability ~2^-255
            // from either blessed source) and would make `D` the identity and
            // `r3 = r2^-1` undefined; `r1 == 0` would make `Abar` the identity.
            // Both are refused as malformed `random_scalars` rather than UB.
            const r3 = r2.inv() catch return error.RandomScalarCountMismatch;
            if (r1.isZero()) return error.RandomScalarCountMismatch;

            // Every multiplication below involves a secret (the signature, the
            // undisclosed messages folded into `B`, or a blinding scalar), so all
            // of them use `bls12_381`'s constant-time `scalarMul` — never the
            // variable-time MSM (see the section comment above `msmPublic`).
            const b = computeB(Suite.P1, domain, generators, message_scalars);
            const d_j = b.scalarMul(r2);
            const abar_j = G1.Jacobian.fromAffine(sig.a).scalarMul(r1.mul(r2));
            const bbar_j = d_j.scalarMul(r1).add(abar_j.scalarMul(sig.e).negate());
            const t1_j = abar_j.scalarMul(e_tilde).add(d_j.scalarMul(r1_tilde));
            var t2_j = d_j.scalarMul(r3_tilde);
            for (undisclosed, m_tilde) |j, mt| {
                t2_j = t2_j.add(G1.Jacobian.fromAffine(generators[j + 1]).scalarMul(mt));
            }
            const abar = abar_j.toAffine();
            const bbar = bbar_j.toAffine();
            const d = d_j.toAffine();

            // -- ProofChallengeCalculate (draft-12 §3.7.4) --
            const disclosed_scalars = try allocator.alloc(Fr, disclosed_indexes.len);
            defer allocator.free(disclosed_scalars);
            for (disclosed_indexes, disclosed_scalars) |i, *s| s.* = message_scalars[i];
            const challenge = try calculateChallenge(Suite, allocator, .{ abar, bbar, d, t1_j.toAffine(), t2_j.toAffine() }, disclosed_indexes, disclosed_scalars, domain, ph);

            // -- ProofFinalize (draft-12 §3.7.2) --
            const e_hat = e_tilde.add(sig.e.mul(challenge));
            const r1_hat = r1_tilde.sub(r1.mul(challenge));
            const r3_hat = r3_tilde.sub(r3.mul(challenge));
            const m_hat = try allocator.alloc(Fr, undisclosed.len);
            defer allocator.free(m_hat);
            for (undisclosed, m_tilde, m_hat) |j, mt, *mh| {
                mh.* = mt.add(message_scalars[j].mul(challenge));
            }

            const out: Proof = .{ .abar = abar, .bbar = bbar, .d = d, .e_hat = e_hat, .r1_hat = r1_hat, .r3_hat = r3_hat, .m_hat = m_hat, .c = challenge };
            return try out.toBytes(allocator);
        }

        /// FABLE CORE — `ProofVerify(PK, proof, header, ph, disclosed_messages,
        /// disclosed_indexes)` (draft-12 §3.5.4 wrapping §3.6.4's
        /// `CoreProofVerify`, itself `ProofVerifyInit` (§3.7.3) +
        /// `ProofChallengeCalculate` (§3.7.4)).
        ///
        /// `disclosed_messages.len` MUST equal `disclosed_indexes.len`
        /// (`error.DisclosedMessageCountMismatch` otherwise). `L` and `U` are
        /// recovered without an explicit parameter: `U = Proof.fromBytes`'s
        /// derived `m_hat.len`, `L = disclosed_indexes.len + U` (§3.7.3 steps 1-4).
        ///
        /// Construction (draft-12 §3.6.4 + §3.7.3 + §3.7.4, composed;
        /// `undisclosed_indexes = {0..L-1} \ disclosed_indexes`, ascending):
        /// ```
        /// 1. (Abar, Bbar, D, e^, r1^, r3^, m^, cp) = Proof.fromBytes(proof)
        /// 2. disclosed_scalars = messagesToScalars(disclosed_messages); generators = createGenerators(L + 1)
        /// 3. domain = calculateDomain(PK, Q_1, H_1..H_L, header)
        ///
        /// -- ProofVerifyInit (§3.7.3) --
        /// 4. T1 = [cp]Bbar + [e^]Abar + [r1^]D
        /// 5. Bv = P1 + [domain]Q_1 + sum_{i in disclosed} [msg_i]H_i
        /// 6. T2 = [cp]Bv + [r3^]D + sum_{j in undisclosed} [m^_j]H_j
        ///
        /// -- ProofChallengeCalculate (§3.7.4) — MUST reproduce cp --
        /// 7. if hash_to_scalar(... Abar, Bbar, D, T1, T2, domain ... ph) != cp, return false
        ///
        /// -- pairing check --
        /// 8. return e(Abar, W) * e(Bbar, -BP2) == 1
        /// ```
        /// Total/fail-closed on malformed `proof` bytes (returns `false`).
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

            const disclosed_scalars = try Suite.messagesToScalars(allocator, disclosed_messages);
            defer allocator.free(disclosed_scalars);
            const generators = try Suite.createGenerators(allocator, total + 1);
            defer allocator.free(generators);
            const domain = try Suite.calculateDomain(allocator, pk.toBytes(), generators[0], generators[1..], header);

            // -- ProofVerifyInit (draft-12 §3.7.3) --
            const init = try proofVerifyInit(allocator, Suite.P1, generators, domain, disclosed_indexes, disclosed_scalars, undisclosed, parsed);

            // -- ProofChallengeCalculate (draft-12 §3.7.4) — MUST reproduce cp --
            const challenge = try calculateChallenge(Suite, allocator, .{ parsed.abar, parsed.bbar, parsed.d, init.t1.toAffine(), init.t2.toAffine() }, disclosed_indexes, disclosed_scalars, domain, ph);
            if (!challenge.eql(parsed.c)) return false;

            // -- pairing check: e(Abar, W) * e(Bbar, -BP2) == 1 (draft §3.6.4 step 6) --
            return cs.pairing.pairingCheck(&.{
                .{ .p = parsed.abar, .q = pk.point },
                .{ .p = parsed.bbar, .q = negBp2() },
            });
        }
    };
}

/// BLS12-381-SHA-256 (draft-12 §7.2.2).
pub const sha256 = Scheme(cs.Sha256);
/// BLS12-381-SHAKE-256 (draft-12 §7.2.1).
pub const shake256 = Scheme(cs.Shake256);

// The SHA-256 suite under the names this file had before it gained a
// second suite.
pub const sign = sha256.sign;
pub const verify = sha256.verify;
pub const proofGen = sha256.proofGen;
pub const proofVerify = sha256.proofVerify;

// ── tests (REAL, ungated — Signature/Proof codec only) ───────────────────

const testing = std.testing;
/// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
/// framing helpers.
const testkit = @import("testkit");

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

test "Proof.encodedLen matches the draft-12 formula (3*48 + (4+U)*32)" {
    try testing.expectEqual(@as(usize, 272), Proof.encodedLen(0));
    try testing.expectEqual(@as(usize, 272 + 6 * 32), Proof.encodedLen(6));
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
        .d = G1.Affine.generator,
        .e_hat = some_scalar,
        .r1_hat = some_scalar,
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
    const floor = Proof.floor_bytes;
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

    // Wrong random_scalars count (need 5 + (3-1) = 7 for disclosed_indexes={0}): caught before the panic.
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

    // NONZERO scalars throughout — critically r1, r2 != 0, so this
    // exercises the duplicate-index guard itself rather than the separate
    // zero-scalar rejections.
    var one_bytes = [_]u8{0} ** 32;
    one_bytes[31] = 1;
    const one = try Fr.fromBytes(one_bytes);
    const random_scalars = [_]Fr{one} ** 6; // 5 + formula's undisclosed_count(1)
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

// ── refusals the mutation run of 2026-10-05 found unpinned ───────────────

/// `(0, 2)`: on `y² = x³ + 4`, of order 3, so outside `G1`.
const g1_order3_compressed: [G1.compressed_bytes]u8 = .{0x80} ++ .{0} ** (G1.compressed_bytes - 1);
const g1_identity_compressed: [G1.compressed_bytes]u8 = .{0xc0} ++ .{0} ** (G1.compressed_bytes - 1);

fn testKeyPair() !struct { sk: SecretKey, pk: PublicKey } {
    var sk_bytes = [_]u8{0} ** 32;
    sk_bytes[31] = 5;
    const sk = try SecretKey.fromBytes(sk_bytes);
    return .{ .sk = sk, .pk = keys.skToPk(sk) };
}

test "Signature/Proof decoders refuse the identity and a point outside G1" {
    _ = try G1.fromBytesCompressedUnchecked(g1_order3_compressed); // on the curve
    try testing.expectError(error.NotInSubgroup, G1.fromBytesCompressed(g1_order3_compressed));

    const kp = try testKeyPair();
    const messages = [_][]const u8{ "a", "b", "c" };
    const sig = try sign(testing.allocator, kp.sk, kp.pk, "h", &messages);
    _ = try Signature.fromBytes(sig);
    var bad_sig = sig;
    bad_sig[0..G1.compressed_bytes].* = g1_identity_compressed;
    try testing.expectError(error.InvalidSignatureEncoding, Signature.fromBytes(bad_sig));
    bad_sig[0..G1.compressed_bytes].* = g1_order3_compressed;
    try testing.expectError(error.InvalidSignatureEncoding, Signature.fromBytes(bad_sig));

    const random_scalars = cs.mockedRandomScalars(7, "decoder refusals");
    const proof = try proofGen(testing.allocator, kp.pk, sig, "h", "", &messages, &.{0}, &random_scalars);
    defer testing.allocator.free(proof);
    (try Proof.fromBytes(testing.allocator, proof)).deinit(testing.allocator);
    const bad = try testing.allocator.dupe(u8, proof);
    defer testing.allocator.free(bad);
    for ([_]usize{ 0, G1.compressed_bytes, 2 * G1.compressed_bytes }) |off| {
        for ([_][G1.compressed_bytes]u8{ g1_identity_compressed, g1_order3_compressed }) |pt| {
            @memcpy(bad, proof);
            bad[off..][0..G1.compressed_bytes].* = pt;
            try testing.expectError(error.InvalidProofEncoding, Proof.fromBytes(testing.allocator, bad));
        }
    }
}

test "proofGen refuses index == L and too MANY random scalars" {
    const kp = try testKeyPair();
    const messages = [_][]const u8{ "a", "b", "c" };
    const sig = try sign(testing.allocator, kp.sk, kp.pk, "", &messages);
    const eight = cs.mockedRandomScalars(8, "too many");
    try testing.expectError(error.DisclosedIndexOutOfRange, proofGen(testing.allocator, kp.pk, sig, "", "", &messages, &.{3}, eight[0..7]));
    try testing.expectError(error.RandomScalarCountMismatch, proofGen(testing.allocator, kp.pk, sig, "", "", &messages, &.{0}, &eight));
}

test "proofGen refuses a zero r1 or r2 instead of emitting an identity Abar/Bbar/D" {
    // r1 = 0 makes Abar and Bbar the identity, r2 = 0 makes D the identity
    // and r3 = r2^-1 undefined: a proof no verifier can decode. Probability
    // ~2^-255 from a real draw; refused as malformed random scalars. The
    // 2026-10-06 mutation run found the r1 check unpinned.
    const kp = try testKeyPair();
    const messages = [_][]const u8{ "a", "b", "c" };
    const sig = try sign(testing.allocator, kp.sk, kp.pk, "", &messages);
    var rs = cs.mockedRandomScalars(7, "zero blinding");
    const ok = try proofGen(testing.allocator, kp.pk, sig, "", "", &messages, &.{0}, &rs);
    testing.allocator.free(ok);
    for ([_]usize{ 0, 1 }) |k| {
        var bad = rs;
        bad[k] = Fr.zero;
        try testing.expectError(error.RandomScalarCountMismatch, proofGen(testing.allocator, kp.pk, sig, "", "", &messages, &.{0}, &bad));
    }
}

test "proofVerify refuses more messages than indexes, index == L, a duplicate index, and a proof over a forged signature" {
    const kp = try testKeyPair();
    const messages = [_][]const u8{ "a", "b", "c" };
    const sig = try sign(testing.allocator, kp.sk, kp.pk, "", &messages);
    const random_scalars = cs.mockedRandomScalars(7, "verify refusals");
    const proof = try proofGen(testing.allocator, kp.pk, sig, "", "", &messages, &.{0}, &random_scalars);
    defer testing.allocator.free(proof);
    try testing.expect(try proofVerify(testing.allocator, kp.pk, proof, "", "", &.{"a"}, &.{0}));

    try testing.expectError(error.DisclosedMessageCountMismatch, proofVerify(testing.allocator, kp.pk, proof, "", "", &.{ "a", "b" }, &.{0}));
    // L = 1 disclosed + 2 hidden = 3, so index 3 is out of range.
    try testing.expect(!try proofVerify(testing.allocator, kp.pk, proof, "", "", &.{"a"}, &.{3}));
    try testing.expect(!try proofVerify(testing.allocator, kp.pk, proof, "", "", &.{ "a", "a" }, &.{ 0, 0 }));

    // A proof over a signature that does not verify: the Schnorr part is
    // consistent for ANY (A, e), so the challenge matches and only the
    // pairing check refuses it.
    var forged = sig;
    var e = try Fr.fromBytes(forged[G1.compressed_bytes..].*);
    e = e.add(Fr.one);
    forged[G1.compressed_bytes..].* = e.toBytes();
    try testing.expect(!try verify(testing.allocator, kp.pk, forged, "", &messages));
    const forged_proof = try proofGen(testing.allocator, kp.pk, forged, "", "", &messages, &.{0}, &random_scalars);
    defer testing.allocator.free(forged_proof);
    try testing.expect(!try proofVerify(testing.allocator, kp.pk, forged_proof, "", "", &.{"a"}, &.{0}));
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
    const scalars1 = cs.calculateRandomScalars(5, io);
    const scalars2 = cs.calculateRandomScalars(5, io);
    var any_differs = false;
    for (scalars1, scalars2) |a, b| {
        if (!a.eql(b)) any_differs = true;
    }
    try testing.expect(any_differs);

    // And the production path is a working path, not just a typed one:
    // sign a message, then prove-and-verify selective disclosure with
    // random_scalars drawn from the same `io` (U = 0 undisclosed, so 5
    // scalars — r1, r2, e~, r1~, r3~).
    var sk_bytes = [_]u8{0} ** 32;
    sk_bytes[31] = 1;
    const sk = try SecretKey.fromBytes(sk_bytes);
    const pk = keys.skToPk(sk);
    const messages = [_][]const u8{"only message"};
    const sig = try sign(testing.allocator, sk, pk, "header", &messages);
    try testing.expect(try verify(testing.allocator, pk, sig, "header", &messages));

    const random_scalars = cs.calculateRandomScalars(5, io);
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

/// The one signature/public key/proof triple every corpus below is cut from.
///
/// ⛔ These are not literals because none of them can be: a `bls12_381` point
/// in the form the decoders accept is structurally unreachable from arbitrary
/// bytes — a compressed G1 octet string has to land on the curve AND in the
/// prime-order subgroup, and `Fr.fromBytes` refuses anything `>= r`. Drawn
/// bytes produce refusals; only the module's own encoders produce acceptances.
/// So the fixtures come out of `sign` and `proofGen` with the draft's own
/// mocked scalars, which makes them deterministic and reviewable.
const Fixtures = struct {
    sig: [Signature.encoded_bytes]u8 = undefined,
    pk: [PublicKey.encoded_bytes]u8 = undefined,
    /// U = 0, so `Proof.encodedLen(0)` = 272 octets — the floor exactly.
    proof_u0: [Proof.encodedLen(0)]u8 = undefined,
    /// Three messages, one disclosed: U = 2, 336 octets.
    proof_u2: [Proof.encodedLen(2)]u8 = undefined,

    fn build(self: *Fixtures) void {
        var sk_bytes = [_]u8{0} ** 32;
        sk_bytes[31] = 1;
        const sk = SecretKey.fromBytes(sk_bytes) catch unreachable;
        const pk = keys.skToPk(sk);
        self.pk = pk.toBytes();

        const one = [_][]const u8{"only message"};
        self.sig = sign(testing.allocator, sk, pk, "header", &one) catch unreachable;

        const rs0 = cs.mockedRandomScalars(5, "corpus");
        const p0 = proofGen(testing.allocator, pk, self.sig, "header", "", &one, &.{0}, &rs0) catch unreachable;
        defer testing.allocator.free(p0);
        @memcpy(&self.proof_u0, p0);

        const three = [_][]const u8{ "m0", "m1", "m2" };
        const sig3 = sign(testing.allocator, sk, pk, "header", &three) catch unreachable;
        const rs2 = cs.mockedRandomScalars(7, "corpus");
        const p2 = proofGen(testing.allocator, pk, sig3, "header", "", &three, &.{0}, &rs2) catch unreachable;
        defer testing.allocator.free(p2);
        @memcpy(&self.proof_u2, p2);
    }
};

/// ⚠ A `smith.bytes(&buf)` harness reads its corpus entry RAW — there is no
/// `u32` length header in front of it, so these are the frames themselves and
/// NOT `testkit.fuzz.seed` wrappers. (`Proof` below is the other case.)
const SigCorpus = struct {
    store: [6][Signature.encoded_bytes]u8 = undefined,
    entries: [6][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *SigCorpus, frame: [Signature.encoded_bytes]u8) void {
        self.store[self.n] = frame;
        self.entries[self.n] = &self.store[self.n];
        self.n += 1;
    }

    fn build(self: *SigCorpus, fx: *const Fixtures) []const []const u8 {
        self.push(fx.sig); // the real signature: A ‖ e
        var t = fx.sig;
        t[0] ^= 0x01; // A's leading octet: flags/sign bits mangled
        self.push(t);
        t = fx.sig;
        t[40] ^= 0x40; // one octet inside A: off the curve
        self.push(t);
        t = fx.sig;
        @memset(t[G1.compressed_bytes..], 0); // e = 0, refused as a scalar
        self.push(t);
        t = fx.sig;
        @memset(t[G1.compressed_bytes..], 0xff); // e >= r
        self.push(t);
        self.push(@splat(0)); // the all-zero buffer, the only input this ever ran
        return self.entries[0..self.n];
    }
};

test "fuzz: Signature.fromBytes never crashes on arbitrary bytes" {
    var fx: Fixtures = .{};
    fx.build();
    var corpus: SigCorpus = .{};
    try testing.fuzz({}, fuzzSignatureFromBytes, .{ .corpus = corpus.build(&fx) });
}

fn fuzzSignatureFromBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [Signature.encoded_bytes]u8 = undefined;
    smith.bytes(&buf);
    const sig = Signature.fromBytes(buf) catch return;
    _ = sig.toBytes();
}

test "corpus: Signature seeds reach the decoder, and the accepted count is pinned" {
    var fx: Fixtures = .{};
    fx.build();
    var corpus: SigCorpus = .{};
    var nonzero: usize = 0;
    var accepted: usize = 0;
    for (corpus.build(&fx)) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [Signature.encoded_bytes]u8 = undefined;
        smith.bytes(&buf);
        if (!std.mem.allEqual(u8, &buf, 0)) nonzero += 1;
        const sig = Signature.fromBytes(buf) catch continue;
        accepted += 1;
        std.mem.doNotOptimizeAway(sig.toBytes());
    }
    // ⛔ Not `accepted > 0`: `nonzero` is the number the all-zero replay
    // cannot hold up, and it only moves when a seed's own octets land in
    // `buf`. Both measured, not guessed.
    try testing.expectEqual(@as(usize, 5), nonzero);
    try testing.expectEqual(@as(usize, 1), accepted);
}

const PkCorpus = struct {
    store: [5][PublicKey.encoded_bytes]u8 = undefined,
    entries: [5][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *PkCorpus, frame: [PublicKey.encoded_bytes]u8) void {
        self.store[self.n] = frame;
        self.entries[self.n] = &self.store[self.n];
        self.n += 1;
    }

    fn build(self: *PkCorpus, fx: *const Fixtures) []const []const u8 {
        self.push(fx.pk); // the real compressed G2 point
        var t = fx.pk;
        // ⚠ 0x20 is the y-SIGN flag, not the infinity flag (0x40): this decodes
        // to -P, a DIFFERENT valid key. Deliberate — it is the seed that proves
        // the corpus entry's own octets decided what came out, the way `rsa`'s
        // perturbed-modulus seed does. Written as "infinity flag" first and
        // pinned at 1 accepted; the guard measured 2 and said so.
        t[0] ^= 0x20;
        self.push(t);
        t = fx.pk;
        t[48] ^= 0x01; // one octet in the second field element: off the curve
        self.push(t);
        t = fx.pk;
        t[0] = 0xc0; // the canonical compressed identity, which `fromBytes` refuses
        @memset(t[1..], 0);
        self.push(t);
        self.push(@splat(0)); // the all-zero buffer, the only input this ever ran
        return self.entries[0..self.n];
    }
};

test "fuzz: PublicKey.fromBytes never crashes on arbitrary bytes" {
    var fx: Fixtures = .{};
    fx.build();
    var corpus: PkCorpus = .{};
    try testing.fuzz({}, fuzzPublicKeyFromBytes, .{ .corpus = corpus.build(&fx) });
}

fn fuzzPublicKeyFromBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [PublicKey.encoded_bytes]u8 = undefined;
    smith.bytes(&buf);
    const pk = PublicKey.fromBytes(buf) catch return;
    _ = pk.toBytes();
}

test "corpus: PublicKey seeds reach the decoder, and the accepted count is pinned" {
    var fx: Fixtures = .{};
    fx.build();
    var corpus: PkCorpus = .{};
    var nonzero: usize = 0;
    var accepted: usize = 0;
    // ⛔ The number the all-zero replay cannot produce, and that a corpus
    // collapsed onto one entry cannot hold up: two DISTINCT keys came back,
    // P and -P, so the seeds' own octets reached `G2.fromBytesCompressed`.
    var first: ?[PublicKey.encoded_bytes]u8 = null;
    var distinct: usize = 0;
    for (corpus.build(&fx)) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [PublicKey.encoded_bytes]u8 = undefined;
        smith.bytes(&buf);
        if (!std.mem.allEqual(u8, &buf, 0)) nonzero += 1;
        const pk = PublicKey.fromBytes(buf) catch continue;
        accepted += 1;
        const enc = pk.toBytes();
        if (first) |f| {
            if (!std.mem.eql(u8, &f, &enc)) distinct += 1;
        } else {
            first = enc;
            distinct += 1;
        }
    }
    try testing.expectEqual(@as(usize, 4), nonzero);
    try testing.expectEqual(@as(usize, 2), accepted);
    try testing.expectEqual(@as(usize, 2), distinct);
}

/// The `Proof` buffer, and the reason it is this size: `Proof.encodedLen(8)`.
/// ⚠ Checked against the largest proof the module itself can produce that has
/// to fit — a seed longer than the buffer reads back EMPTY, silently.
const proof_buf_len = Proof.encodedLen(8);

const ProofCorpus = struct {
    store: [10 * (4 + proof_buf_len)]u8 = undefined,
    used: usize = 0,
    entries: [10][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *ProofCorpus, frame: []const u8) void {
        const sd = testkit.fuzz.seedInto(self.store[self.used..], frame);
        self.entries[self.n] = self.store[self.used..][0..sd.len];
        self.used += sd.len;
        self.n += 1;
    }

    fn build(self: *ProofCorpus, fx: *const Fixtures) []const []const u8 {
        self.push(&fx.proof_u0); // U = 0: the floor length exactly
        self.push(&fx.proof_u2); // U = 2: the m_hat loop runs twice
        var t2 = fx.proof_u2;
        t2[3 * G1.compressed_bytes + 4 * Fr.encoded_bytes] ^= 0x01; // one octet inside m_hat_1
        self.push(&t2);
        var t0 = fx.proof_u0;
        @memset(t0[3 * G1.compressed_bytes ..][0..Fr.encoded_bytes], 0); // e_hat = 0
        self.push(&t0);
        t0 = fx.proof_u0;
        @memset(t0[t0.len - Fr.encoded_bytes ..], 0xff); // c >= r
        self.push(&t0);
        t0 = fx.proof_u0;
        t0[G1.compressed_bytes] ^= 0x08; // Bbar off the curve / out of the subgroup
        self.push(&t0);
        self.push(fx.proof_u0[0 .. fx.proof_u0.len - 1]); // one octet under the floor
        self.push(fx.proof_u2[0 .. fx.proof_u2.len - 1]); // over the floor, bad remainder
        self.push(&[_]u8{0} ** Proof.encodedLen(0)); // all-zero at a legal length
        self.push(""); // and the input this target used to run for ever
        return self.entries[0..self.n];
    }
};

test "fuzz: Proof.fromBytes never crashes on arbitrary bytes" {
    var fx: Fixtures = .{};
    fx.build();
    var corpus: ProofCorpus = .{};
    try testing.fuzz({}, fuzzProofFromBytes, .{ .corpus = corpus.build(&fx) });
}

fn fuzzProofFromBytes(_: void, smith: *std.testing.Smith) !void {
    // ⚠ One `smith.slice` call, never `bytes` followed by a ranged length: the
    // latter drew `len == 0` on every input the ordinary lane ever ran (a
    // ranged draw needs eight octets and `bytes` had eaten them), so this
    // target had returned `InvalidProofEncoding` on the length check every
    // round, with the proof sitting unread in `buf`.
    var buf: [proof_buf_len]u8 = undefined;
    const len: usize = smith.slice(&buf);
    const proof = Proof.fromBytes(testing.allocator, buf[0..len]) catch return;
    defer proof.deinit(testing.allocator);
    if (proof.toBytes(testing.allocator)) |out| testing.allocator.free(out) else |_| {}
}

test "corpus: Proof seeds reach the decoder, and the counts are pinned" {
    var fx: Fixtures = .{};
    fx.build();
    var corpus: ProofCorpus = .{};
    var nonempty: usize = 0;
    var accepted: usize = 0;
    // ⛔ The second number, which an empty input cannot produce: the total
    // number of `m_hat` scalars actually decoded. `accepted` alone would not
    // notice a corpus that collapsed to the U = 0 proof.
    var m_hat_total: usize = 0;
    for (corpus.build(&fx)) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [proof_buf_len]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const proof = Proof.fromBytes(testing.allocator, buf[0..len]) catch continue;
        defer proof.deinit(testing.allocator);
        accepted += 1;
        m_hat_total += proof.m_hat.len;
    }
    try testing.expectEqual(corpus.n - 1, nonempty); // all but the empty seed
    try testing.expectEqual(@as(usize, 3), accepted);
    try testing.expectEqual(@as(usize, 4), m_hat_total);
}

// ── F4: computeB MSM crossover — differential oracle + bench ────────────

fn testRandomFr(rand: std.Random) Fr {
    var buf: [48]u8 = undefined;
    rand.bytes(&buf);
    return Fr.reduceWide(&buf);
}

/// TEST-ONLY oracle: draft-12 `ProofVerifyInit`'s `T1`/`T2` by the plain
/// sequential constant-time `scalarMul` loop, transcribed from §3.7.3
/// independently of `proofVerifyInit`'s MSM assembly, so the variable-time
/// MSM form has something to be checked against.
fn proofVerifyInitLoopOracle(
    generators: []const G1.Affine,
    domain: Fr,
    disclosed_indexes: []const usize,
    disclosed_scalars: []const Fr,
    undisclosed: []const usize,
    proof: Proof,
) struct { t1: G1.Jacobian, t2: G1.Jacobian } {
    const mul = struct {
        fn f(p: G1.Affine, k: Fr) G1.Jacobian {
            return G1.Jacobian.fromAffine(p).scalarMul(k);
        }
    }.f;
    const t1 = mul(proof.bbar, proof.c).add(mul(proof.abar, proof.e_hat)).add(mul(proof.d, proof.r1_hat));
    var bv = G1.Jacobian.fromAffine(cs.P1).add(mul(generators[0], domain));
    for (disclosed_indexes, disclosed_scalars) |i, m| bv = bv.add(mul(generators[i + 1], m));
    var t2 = bv.scalarMul(proof.c).add(mul(proof.d, proof.r3_hat));
    for (undisclosed, proof.m_hat) |j, mh| t2 = t2.add(mul(generators[j + 1], mh));
    return .{ .t1 = t1, .t2 = t2 };
}

test "F4 oracle: computeB (sequential) == msmLoop == msmPippenger == computeBPublic, bit-exact, across L" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xB855_F0FA);
    const rand = prng.random();

    // L = 0, 1, 2 (the brief's mandated minimum), straddling msm_crossover
    // (== 2, see its doc comment) on both sides, and well past it.
    //
    // Debug: measured ~32s for this test ALONE, isolated (dominated by
    // L=300's createGenerators + three separate MSM computations) --
    // over the campaign's 10s per-test budget (audit A1, 2026-09-15 gate
    // survey). The large L values (16, 64, 300) are extended coverage past
    // the crossover, not the brief's mandated minimum (0, 1, 2) or the
    // "well past it" boundary (8 already clears msm_crossover == 2 by 4x) --
    // trimmed in Debug only, full set kept in ReleaseFast/ReleaseSafe/
    // ReleaseSmall.
    const ls: []const usize = if (builtin.mode == .Debug)
        &[_]usize{ 0, 1, 2, 3, 4, 8 }
    else
        &[_]usize{ 0, 1, 2, 3, 4, 8, 16, 64, 300 };

    for (ls) |l| {
        const generators = try cs.createGenerators(allocator, l + 1);
        defer allocator.free(generators);
        const message_scalars = try allocator.alloc(Fr, l);
        defer allocator.free(message_scalars);
        for (message_scalars) |*m| m.* = testRandomFr(rand);
        const domain = testRandomFr(rand);

        // The oracle: computeB, UNCHANGED, still `sign`'s/`proofGen`'s only
        // path.
        const want = computeB(cs.P1, domain, generators, message_scalars).toAffine();
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
        const got_public = (try computeBPublic(allocator, cs.P1, domain, generators, message_scalars)).toAffine();
        try testing.expectEqualSlices(u8, &want_bytes, &G1.toBytesCompressed(got_public));
    }
}

test "F4 oracle: proofVerifyInit's MSM form matches the sequential draft-12 form, bit-exact, across L" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x0D5F_1E17);
    const rand = prng.random();

    // total = R (disclosed) + U (undisclosed); cover R/U = 0 and a spread
    // straddling msm_crossover (== 2) for each MSM call (T1 has 3 terms,
    // Bv R+2, T2 U+2). Debug trims the 300 case (createGenerators dominates).
    const totals: []const usize = if (builtin.mode == .Debug)
        &[_]usize{ 0, 1, 2, 3, 8 }
    else
        &[_]usize{ 0, 1, 2, 3, 8, 300 };

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

        const point = struct {
            fn f(r: std.Random) G1.Affine {
                return G1.Jacobian.fromAffine(G1.Affine.generator).scalarMul(testRandomFr(r)).toAffine();
            }
        }.f;
        const proof: Proof = .{
            .abar = point(rand),
            .bbar = point(rand),
            .d = point(rand),
            .e_hat = testRandomFr(rand),
            .r1_hat = testRandomFr(rand),
            .r3_hat = testRandomFr(rand),
            .m_hat = m_hat,
            .c = testRandomFr(rand),
        };
        const domain = testRandomFr(rand);

        const want = proofVerifyInitLoopOracle(generators, domain, disclosed_indexes.items, disclosed_scalars, undisclosed.items, proof);
        const got = try proofVerifyInit(allocator, cs.P1, generators, domain, disclosed_indexes.items, disclosed_scalars, undisclosed.items, proof);
        try testing.expectEqualSlices(u8, &G1.toBytesCompressed(want.t1.toAffine()), &G1.toBytesCompressed(got.t1.toAffine()));
        try testing.expectEqualSlices(u8, &G1.toBytesCompressed(want.t2.toAffine()), &G1.toBytesCompressed(got.t2.toAffine()));
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
