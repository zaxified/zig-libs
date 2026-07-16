// SPDX-License-Identifier: MIT

//! aux_proofs — the Πprm ("ring-Pedersen parameters") and Πmod
//! ("Paillier-Blum modulus") zero-knowledge proofs-of-correct-generation
//! for `root.AuxParams` (CGGMP21, R. Canetti/R. Gennaro/S. Goldfeder/N.
//! Makriyannis/U. Peled, "UC Non-Interactive, Proactive, Threshold ECDSA
//! with Identifiable Aborts", IACR ePrint 2021/060, Fig.16 "Πmod" / Fig.17
//! "Πprm"). These close **audit F1** for real: `root.AuxParams.validate`
//! (root.zig) already enforces the cheap STRUCTURAL floor a verifier can
//! check WITHOUT `n_tilde`'s factorization (composite, in-range,
//! Jacobi-symbol `+1`) — but the Jacobi check is NECESSARY, not
//! SUFFICIENT, for quadratic residuosity: a value that is a non-residue
//! mod BOTH prime factors of `n_tilde` also has symbol `+1`, so a
//! malicious party can still craft an `(n_tilde, h1, h2)` that passes
//! `validate` yet leaks the honest prover's Pedersen-commitment witness
//! (the TSSHOCK / Alpha-Rays class — see root.zig's `AuxParams.validate`
//! doc comment and this module's own KAT tests below). Πprm+Πmod let the
//! GENERATOR of an `AuxParams` tuple *prove* it is well-formed, and the
//! VALIDATOR *verify* that proof, fully closing the gap.
//!
//! **Status: IMPLEMENTED.** The proof STRUCTS (`ModProof`/`PrmProof`),
//! their byte codecs, the Fiat-Shamir transcript wiring
//! (`deriveModChallenge`/`derivePrmChallengeBits`, built on
//! `zkproofs.Transcript`), and the `proveWellFormed`/`verifyWellFormed`
//! public-API wiring landed first (scaffold pass); the two irreducible
//! ZK-proof number-theory CORES — `Piprm.prove`/`.verify` and
//! `Pimod.prove`/`.verify` — are now implemented as well and
//! `gate.aux_proofs_core_implemented` is flipped, so the previously-gated
//! KAT below (completeness, BOTH F1-soundness rejections, tamper suite)
//! executes for real. See `gate.zig`'s doc comment for the
//! scaffold-then-implement convention this followed (`bn254`, `df-elect`).
//!
//! ## `s`/`t` vs `h1`/`h2` — the naming this module bridges
//!
//! CGGMP21 Fig.17 (Πprm) writes the ring-Pedersen generators as `s`, `t`
//! with `t = s^lambda mod N`; this repo's `root.zig` calls them `h1`, `h2`
//! with the IDENTICAL relation `h2 = h1^lambda mod n_tilde` (see
//! `root.generateAuxParams`'s construction). Concretely: `s := aux.h1`,
//! `t := aux.h2`. Every doc comment below uses `s`/`t` when quoting the
//! paper's equations and `h1`/`h2` when referring to this module's fields
//! — they are the SAME values.
//!
//! ## Soundness parameter
//!
//! Both proofs are `m`-round Fiat-Shamir Sigma protocols; `m` is a NAMED
//! CONSTANT below (`pi_mod_iterations`/`pi_prm_iterations`, both `80`),
//! giving soundness error `~2^-80` per proof (Πmod: each of `m`
//! independent `y_i` challenges catches a cheating prover with probability
//! `>= 1/2`; Πprm: each of `m` independent single-bit challenges catches a
//! cheating prover with probability `>= 1/2` — `(1/2)^80 = 2^-80` for
//! both, the same target `zkproofs.zig`'s own Fiat-Shamir challenge space
//! achieves via a single `~2^-256`-soundness `Zq` challenge; `m=80`
//! rounds of a 1-bit challenge is the standard CGGMP21 parameterization
//! rather than a wide single challenge, since both proofs' per-round
//! algebra is cheap but the challenge itself cannot be widened past 1
//! bit/round without leaking additional structure).
//!
//! Zig std GAP: none new — `std.crypto.ff` (via `root.AuxModulus`/
//! `root.AuxFe`) and `std.crypto.hash.sha2.Sha256` (via `zkproofs
//! .Transcript`) are the only primitives this file needs.

const std = @import("std");
const root = @import("root.zig");
const zkproofs = @import("zkproofs.zig");
const gate = @import("gate.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

/// Soundness parameter for Πmod (CGGMP21 Fig.16) — `m` independent
/// Fiat-Shamir challenges `y_1..y_m`, each catching a cheating prover with
/// probability `>= 1/2`; `(1/2)^80 ≈ 2^-80` soundness error.
pub const pi_mod_iterations: usize = 80;

/// Soundness parameter for Πprm (CGGMP21 Fig.17) — `m` independent
/// single-bit Fiat-Shamir challenges `e_1..e_m`; `(1/2)^80 ≈ 2^-80`
/// soundness error.
pub const pi_prm_iterations: usize = 80;

/// Domain-separation tag for Πmod's Fiat-Shamir seed — same
/// per-proof-kind domain-separation discipline as `zkproofs.zig`'s
/// `range_proof_domain`/`mta_proof_domain`/`mta_proof_wc_domain`.
pub const pi_mod_domain = "threshold_ecdsa/aux-proofs/pi-mod/v1";
/// Domain-separation tag for Πprm's Fiat-Shamir seed.
pub const pi_prm_domain = "threshold_ecdsa/aux-proofs/pi-prm/v1";

// ── small shared helpers (mechanical byte-buffer plumbing only) ─────────
//
// Duplicated from `root.zig`/`zkproofs.zig`'s identically-named PRIVATE
// helpers — the repo's own "small mechanical helper, copied per file"
// convention (see `zkproofs.zig`'s own header comment on this).

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

/// Unsigned big-endian compare (leading zeros ignored) — same shape as
/// `root.zig`/`zkproofs.zig`'s identically-named helpers.
fn intCompare(a_in: []const u8, b_in: []const u8) std.math.Order {
    const a = stripLeadingZeros(a_in);
    const b = stripLeadingZeros(b_in);
    if (a.len != b.len) return if (a.len < b.len) .lt else .gt;
    return std.mem.order(u8, a, b);
}

/// Big-endian fixed-width encoding of a comptime integer — mirrors
/// `root.zig`/`zkproofs.zig`'s identically-named helper (used by this
/// file's own KAT tests to build crafted comptime-composite `n_tilde`
/// values, same trick `root.zig`'s F1/F2 `validate` test uses).
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

// ── ModProof — Πmod's proof object (STRUCT+CODEC real) ──────────────────

/// One of Πmod's `pi_mod_iterations` per-round responses (CGGMP21 Fig.16
/// step 3): `x` is a 4th root of `y'_i = (-1)^a * w^b * y_i mod n_tilde`,
/// `z` is `y_i^(n_tilde^-1 mod phi(n_tilde)) mod n_tilde`, and `a`/`b` are
/// the sign/quadratic-residue-class bits that turned `y_i` into the
/// residue `y'_i` whose 4th root `x` is.
pub const ModEntry = struct {
    /// Canonical mod `n_tilde`.
    x: root.AuxFe,
    /// Canonical mod `n_tilde`.
    z: root.AuxFe,
    a: bool,
    b: bool,
};

/// Πmod's full non-interactive proof object (CGGMP21 Fig.16): `w` is the
/// prover's chosen Jacobi-symbol-`-1` witness, `entries` holds one
/// `ModEntry` per Fiat-Shamir round `1..=pi_mod_iterations`.
pub const ModProof = struct {
    /// Canonical mod `n_tilde`.
    w: root.AuxFe,
    entries: [pi_mod_iterations]ModEntry,

    pub const ByteError = std.crypto.ff.OverflowError || std.crypto.ff.RepresentationError;
    pub const AllocError = std.mem.Allocator.Error || ByteError;

    /// `len-prefixed(w) || (len-prefixed(x) || len-prefixed(z) || a-byte ||
    /// b-byte) * pi_mod_iterations`. REAL, mechanical — mirrors
    /// `zkproofs.RangeProof.toBytesAlloc`'s length-prefixed-fields shape.
    pub fn toBytesAlloc(self: ModProof, allocator: std.mem.Allocator) AllocError![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(allocator);

        var w_buf: [root.aux_modulus_bytes]u8 = undefined;
        try self.w.toBytes(&w_buf, .big);
        try appendLenPrefixed(&list, allocator, &w_buf);

        for (self.entries) |e| {
            var x_buf: [root.aux_modulus_bytes]u8 = undefined;
            try e.x.toBytes(&x_buf, .big);
            try appendLenPrefixed(&list, allocator, &x_buf);

            var z_buf: [root.aux_modulus_bytes]u8 = undefined;
            try e.z.toBytes(&z_buf, .big);
            try appendLenPrefixed(&list, allocator, &z_buf);

            try list.append(allocator, if (e.a) 1 else 0);
            try list.append(allocator, if (e.b) 1 else 0);
        }

        return list.toOwnedSlice(allocator);
    }

    pub const FromBytesError = error{InvalidEncoding};

    /// Inverse of `toBytesAlloc`. `n_tilde` gives `w`/`x`/`z` their modulus
    /// context (same "caller supplies the modulus" shape
    /// `zkproofs.RangeProof.fromBytesAlloc` uses). Does not allocate
    /// (`entries` is a fixed-size array).
    pub fn fromBytesAlloc(n_tilde: root.AuxModulus, bytes: []const u8) FromBytesError!ModProof {
        var offset: usize = 0;
        const w_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const w = root.AuxFe.fromBytes(n_tilde, stripLeadingZeros(w_bytes), .big) catch return error.InvalidEncoding;

        var entries: [pi_mod_iterations]ModEntry = undefined;
        for (&entries) |*slot| {
            const x_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
            const x = root.AuxFe.fromBytes(n_tilde, stripLeadingZeros(x_bytes), .big) catch return error.InvalidEncoding;
            const z_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
            const z = root.AuxFe.fromBytes(n_tilde, stripLeadingZeros(z_bytes), .big) catch return error.InvalidEncoding;
            if (bytes.len < offset + 2) return error.InvalidEncoding;
            const a = bytes[offset] != 0;
            const b = bytes[offset + 1] != 0;
            offset += 2;
            slot.* = .{ .x = x, .z = z, .a = a, .b = b };
        }
        return .{ .w = w, .entries = entries };
    }
};

// ── PrmProof — Πprm's proof object (STRUCT+CODEC real) ──────────────────

/// One of Πprm's `pi_prm_iterations` per-round responses (CGGMP21 Fig.17
/// step 1/3): `a_commit` is the round's first-message commitment `A_i =
/// s^{a_i} mod n_tilde`, `z` is the response `z_i = a_i + e_i*lambda mod
/// phi(n_tilde)` (re-encoded canonical mod `n_tilde`, valid since `z_i <
/// phi(n_tilde) < n_tilde`).
pub const PrmEntry = struct {
    /// Canonical mod `n_tilde`.
    a_commit: root.AuxFe,
    /// Canonical mod `n_tilde`.
    z: root.AuxFe,
};

/// Πprm's full non-interactive proof object (CGGMP21 Fig.17): one
/// `PrmEntry` per Fiat-Shamir round `1..=pi_prm_iterations`.
pub const PrmProof = struct {
    entries: [pi_prm_iterations]PrmEntry,

    pub const ByteError = std.crypto.ff.OverflowError || std.crypto.ff.RepresentationError;
    pub const AllocError = std.mem.Allocator.Error || ByteError;

    /// `(len-prefixed(a_commit) || len-prefixed(z)) * pi_prm_iterations`.
    /// REAL, mechanical.
    pub fn toBytesAlloc(self: PrmProof, allocator: std.mem.Allocator) AllocError![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(allocator);

        for (self.entries) |e| {
            var a_buf: [root.aux_modulus_bytes]u8 = undefined;
            try e.a_commit.toBytes(&a_buf, .big);
            try appendLenPrefixed(&list, allocator, &a_buf);

            var z_buf: [root.aux_modulus_bytes]u8 = undefined;
            try e.z.toBytes(&z_buf, .big);
            try appendLenPrefixed(&list, allocator, &z_buf);
        }

        return list.toOwnedSlice(allocator);
    }

    pub const FromBytesError = error{InvalidEncoding};

    /// Inverse of `toBytesAlloc`. Does not allocate (`entries` is a
    /// fixed-size array).
    pub fn fromBytesAlloc(n_tilde: root.AuxModulus, bytes: []const u8) FromBytesError!PrmProof {
        var offset: usize = 0;
        var entries: [pi_prm_iterations]PrmEntry = undefined;
        for (&entries) |*slot| {
            const a_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
            const a_commit = root.AuxFe.fromBytes(n_tilde, stripLeadingZeros(a_bytes), .big) catch return error.InvalidEncoding;
            const z_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
            const z = root.AuxFe.fromBytes(n_tilde, stripLeadingZeros(z_bytes), .big) catch return error.InvalidEncoding;
            slot.* = .{ .a_commit = a_commit, .z = z };
        }
        return .{ .entries = entries };
    }
};

// ── Fiat-Shamir challenge derivation (REAL — mechanical hashing, not the
//    proof cores) ─────────────────────────────────────────────────────────
//
// Reuses `zkproofs.Transcript` for the "BIND" half (domain-separated
// hashing of `n_tilde`/`h1`/`h2` plus every first-message commitment into
// one 32-byte seed, via the `finalizeDigest` extension added alongside
// this file) and a local deterministic counter-mode SHA-256 expansion for
// the "EXPAND" half (turning that one seed into `pi_mod_iterations`
// distinct `Z_n_tilde*` challenges, or `pi_prm_iterations` challenge
// bits). There is no cross-implementation KAT for Πprm/Πmod either (same
// posture `zkproofs.zig`'s own module doc comment documents for its three
// proofs — the paper's verifier is INTERACTIVE, Fiat-Shamir instantiation
// is implementation-defined) — this is this module's OWN deterministic
// scheme, real and tested below, not a claimed interop format.

/// Deterministic counter-mode SHA-256 expansion: fills `out` with
/// `SHA256(seed || index_BE32 || sub_BE32 || block_BE32)` blocks
/// concatenated. `index` identifies WHICH per-round challenge (`i` in
/// `1..=m`); `sub` is a rejection-sampling retry counter (see
/// `deriveModChallenge`) — distinct `(index, sub)` pairs are
/// cryptographically independent draws from the same `seed`.
fn expandChallenge(seed: [32]u8, index: u32, sub: u32, out: []u8) void {
    var offset: usize = 0;
    var block: u32 = 0;
    while (offset < out.len) : (block += 1) {
        var h = Sha256.init(.{});
        h.update(&seed);
        var idx_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &idx_buf, index, .big);
        h.update(&idx_buf);
        var sub_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &sub_buf, sub, .big);
        h.update(&sub_buf);
        var blk_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &blk_buf, block, .big);
        h.update(&blk_buf);
        const digest = h.finalResult();
        const n = @min(digest.len, out.len - offset);
        @memcpy(out[offset..][0..n], digest[0..n]);
        offset += n;
    }
}

/// The Πmod Fiat-Shamir seed (CGGMP21 Fig.16: "FS(N, w, i)" — this binds
/// the `(N, w)` half once; `deriveModChallenge` below expands it per `i`).
/// Binds the FULL `aux` tuple (`n_tilde`, `h1`, `h2`), not just `n_tilde`
/// — a conservative superset of the paper's minimal binding, same
/// "bind everything public" discipline `zkproofs.zig`'s transcripts use.
fn deriveModSeed(aux: root.AuxParams, w: root.AuxFe) [32]u8 {
    var t = zkproofs.Transcript.init(pi_mod_domain);
    t.appendAuxParams(aux);
    t.appendAuxFe(w);
    return t.finalizeDigest();
}

/// Πmod's per-round challenge `y_i = FS(n_tilde, w, i) ∈ Z_n_tilde*`
/// (CGGMP21 Fig.16 step 2). Deterministic rejection sampling via
/// `expandChallenge` — mirrors `zkproofs.zig`'s `sampleBelow` rejection
/// shape but over a DETERMINISTIC (not random) byte stream, so prover and
/// verifier derive the IDENTICAL `y_i` from the same public `(aux, w)`.
/// `index` is 1-based (`1..=pi_mod_iterations`) to match the paper's `i`.
pub fn deriveModChallenge(n_tilde: root.AuxModulus, seed: [32]u8, index: u32) root.AuxFe {
    var n_buf: [root.aux_modulus_bytes]u8 = undefined;
    n_tilde.toBytes(&n_buf, .big) catch unreachable; // fixed-width buffer always sufficient
    const n_bytes = stripLeadingZeros(&n_buf);
    const mask: u8 = @as(u8, 0xff) >> @intCast(@clz(n_bytes[0]));
    var buf: [root.aux_modulus_bytes]u8 = undefined;
    var sub: u32 = 0;
    while (true) : (sub += 1) {
        expandChallenge(seed, index, sub, buf[0..n_bytes.len]);
        buf[0] &= mask;
        const cand = buf[0..n_bytes.len];
        if (intCompare(cand, n_bytes) == .lt and stripLeadingZeros(cand).len != 0) {
            return root.AuxFe.fromBytes(n_tilde, stripLeadingZeros(cand), .big) catch continue;
        }
    }
}

/// The Πprm Fiat-Shamir seed (CGGMP21 Fig.17: "e = FS(N, s, t, A_1..A_m)").
/// Binds the full `aux` tuple plus every round's first-message commitment
/// `A_i`.
fn derivePrmSeed(aux: root.AuxParams, commitments: []const root.AuxFe) [32]u8 {
    var t = zkproofs.Transcript.init(pi_prm_domain);
    t.appendAuxParams(aux);
    for (commitments) |a| t.appendAuxFe(a);
    return t.finalizeDigest();
}

/// Πprm's `pi_prm_iterations`-bit challenge `e ∈ {0,1}^m` (CGGMP21 Fig.17
/// step 2) — one deterministic expansion block, sliced into individual
/// bits (`m = 80 <= 256` fits inside a single `expandChallenge` call's
/// first block; the loop still handles `m > 256` correctly if the
/// soundness constant is ever widened).
pub fn derivePrmChallengeBits(seed: [32]u8, out_bits: *[pi_prm_iterations]bool) void {
    var bit_bytes: [(pi_prm_iterations + 7) / 8]u8 = undefined;
    expandChallenge(seed, 0, 0, &bit_bytes);
    for (out_bits, 0..) |*b, i| {
        b.* = (bit_bytes[i / 8] >> @intCast(7 - i % 8)) & 1 == 1;
    }
}

// ── number-theory helpers for the two proof cores ───────────────────────
//
// Big-integer scratch machinery mirroring `root.zig`'s identically-named
// PRIVATE helpers (`newBig`/`bigFromBytes`/`jacobiSymbol`/`isProbablePrime`
// — the repo's "small mechanical helper, copied per file" convention; the
// Jacobi copy additionally deinit-cleans its temporaries so it is safe
// under leak-detecting allocators), plus the Πmod-specific pieces
// (modular inverse, Blum-prime 4th root, CRT recombination).

fn byteLen(bit_count: usize) usize {
    return (bit_count + 7) / 8;
}

const BigInt = std.math.big.int.Managed;

/// Limb capacity covering an `aux_modulus_bits`-wide product plus headroom
/// — same sizing as `root.zig`'s `aux_big_capacity`.
const big_capacity = (2 * root.aux_modulus_bits) / @bitSizeOf(std.math.big.Limb) + 4;

/// Fixed scratch for the allocator-less `verify` entry points' big-int
/// arithmetic (Jacobi symbols) — same `FixedBufferAllocator` idiom and
/// sizing as `root.zig`'s `AuxParams.validate`.
const verify_scratch_bytes = 128 * 1024;

/// Miller-Rabin rounds — matches `root.zig`'s `aux_mr_rounds`.
const mr_rounds = 64;

fn newBig(gpa: std.mem.Allocator) std.mem.Allocator.Error!BigInt {
    return BigInt.initCapacity(gpa, big_capacity);
}

fn bigFromBytes(gpa: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error!BigInt {
    var x = try newBig(gpa);
    errdefer x.deinit();
    if (bytes.len == 0) {
        try x.set(0);
        return x;
    }
    try x.ensureCapacity(bytes.len / @sizeOf(std.math.big.Limb) + 2);
    var m = x.toMutable();
    m.readTwosComplement(bytes, bytes.len * 8, .big, .unsigned);
    x.setMetadata(m.positive, m.len);
    return x;
}

/// `AuxFe` (canonical mod any `AuxModulus`-typed modulus) -> non-negative
/// big integer.
fn bigFromFe(gpa: std.mem.Allocator, fe: root.AuxFe) std.mem.Allocator.Error!BigInt {
    var buf: [root.aux_modulus_bytes]u8 = undefined;
    fe.toBytes(&buf, .big) catch unreachable; // fixed-width buffer always sufficient
    return bigFromBytes(gpa, stripLeadingZeros(&buf));
}

/// Non-negative big integer `x < m` -> canonical `AuxFe`. Fail-closed: an
/// out-of-range value (only reachable through a corrupt/mismatched
/// trapdoor) maps to zero — a garbage proof value a correct verifier
/// rejects, never a panic.
fn feFromBig(m: root.AuxModulus, x: *const BigInt) root.AuxFe {
    if (x.bitCountAbs() > root.aux_modulus_bits or !x.isPositive() and !x.eqlZero()) return m.zero;
    var buf: [root.aux_modulus_bytes]u8 = undefined;
    x.toConst().writeTwosComplement(&buf, .big);
    const stripped = stripLeadingZeros(&buf);
    if (stripped.len == 0) return m.zero;
    return root.AuxFe.fromBytes(m, stripped, .big) catch m.zero;
}

/// Byte-exact `AuxFe` equality — copy of `zkproofs.zig`'s identically-named
/// private helper (comparing via canonical serialization sidesteps ff's
/// internal Montgomery-form flag, which raw `eql` on mixed-provenance
/// values would trip over).
fn auxFeEql(a: root.AuxFe, b: root.AuxFe) bool {
    var ab: [root.aux_modulus_bytes]u8 = undefined;
    a.toBytes(&ab, .big) catch return false;
    var bb: [root.aux_modulus_bytes]u8 = undefined;
    b.toBytes(&bb, .big) catch return false;
    return std.mem.eql(u8, &ab, &bb);
}

/// Jacobi symbol `(a / n)` for odd `n > 0` — the same reciprocity
/// algorithm as `root.zig`'s private `jacobiSymbol`, with owned (deinit'd)
/// temporaries so it is safe under any allocator, including
/// `std.testing.allocator`. Returns `-1`, `0`, or `+1`; `0` exactly when
/// `gcd(a, n) > 1`. Variable-time — every input it sees here is public
/// (challenges, proof fields) or factor-level knowledge the prover
/// already holds.
fn jacobiBig(gpa: std.mem.Allocator, a_in: *const BigInt, n_in: *const BigInt) std.mem.Allocator.Error!i8 {
    var a = try newBig(gpa);
    defer a.deinit();
    var n = try newBig(gpa);
    defer n.deinit();
    var quot = try newBig(gpa);
    defer quot.deinit();
    var rem = try newBig(gpa);
    defer rem.deinit();
    var tmp = try newBig(gpa);
    defer tmp.deinit();
    try a.copy(a_in.toConst());
    try n.copy(n_in.toConst());

    // a := a mod n
    try quot.divFloor(&rem, &a, &n);
    a.swap(&rem);

    var result: i8 = 1;
    while (!a.eqlZero()) {
        // Strip factors of two, flipping per (2/n) = (-1)^((n²-1)/8) — i.e.
        // flip whenever n ≡ 3 or 5 (mod 8). `a` is nonzero here (outer
        // guard), so its odd part is ≥ 1 and limbs[0] is always in range.
        while ((a.toConst().limbs[0] & 1) == 0) {
            try tmp.shiftRight(&a, 1);
            a.swap(&tmp);
            const n8 = n.toConst().limbs[0] & 7;
            if (n8 == 3 or n8 == 5) result = -result;
        }
        // Quadratic reciprocity: swap, flipping when a ≡ n ≡ 3 (mod 4).
        a.swap(&n);
        if ((a.toConst().limbs[0] & 3) == 3 and (n.toConst().limbs[0] & 3) == 3) result = -result;
        try quot.divFloor(&rem, &a, &n);
        a.swap(&rem);
    }
    if (n.toConst().orderAgainstScalar(1) == .eq) return result;
    return 0; // gcd(a, n) > 1
}

/// `a^{-1} mod m` (for `m > 1`), or `null` when `gcd(a, m) != 1`. Standard
/// iterative extended Euclid over `std.math.big.int` (signed Bezout
/// coefficient, folded back into `[0, m)` at the end). Variable-time —
/// prove-side only, on values the prover already knows.
fn modInverse(gpa: std.mem.Allocator, a_in: *const BigInt, m_in: *const BigInt) std.mem.Allocator.Error!?BigInt {
    if (m_in.toConst().orderAgainstScalar(1) != .gt) return null;
    var r0 = try newBig(gpa);
    defer r0.deinit();
    var r1 = try newBig(gpa);
    defer r1.deinit();
    var s0 = try newBig(gpa);
    defer s0.deinit();
    var s1 = try newBig(gpa);
    defer s1.deinit();
    var quot = try newBig(gpa);
    defer quot.deinit();
    var rem = try newBig(gpa);
    defer rem.deinit();
    var tmp = try newBig(gpa);
    defer tmp.deinit();

    try r0.copy(m_in.toConst());
    try quot.divFloor(&rem, a_in, m_in); // r1 = a mod m
    r1.swap(&rem);
    try s0.set(0);
    try s1.set(1);

    while (!r1.eqlZero()) {
        try quot.divFloor(&rem, &r0, &r1);
        r0.swap(&r1);
        r1.swap(&rem);
        // (s0, s1) := (s1, s0 - quot*s1)
        try tmp.mul(&quot, &s1);
        try tmp.sub(&s0, &tmp);
        s0.swap(&s1);
        s1.swap(&tmp);
    }
    if (r0.toConst().orderAgainstScalar(1) != .eq) return null;

    var out = try newBig(gpa);
    errdefer out.deinit();
    try quot.divFloor(&rem, &s0, m_in); // fold the Bezout coefficient into [0, m)
    try out.copy(rem.toConst());
    return out;
}

/// Uniform nonzero `AuxFe` in `[1, m)` by rejection sampling — copy of
/// `root.zig`'s identically-named private helper (the Πmod witness `w` is
/// public once broadcast).
fn sampleNonzeroLtModulus(m: root.AuxModulus, random: std.Random) root.AuxFe {
    const n_bits = m.bits();
    const n_len = byteLen(n_bits);
    var buf: [root.aux_modulus_bytes]u8 = undefined;
    while (true) {
        random.bytes(buf[0..n_len]);
        buf[0] &= @as(u8, 0xff) >> @intCast(8 * n_len - n_bits);
        const r = root.AuxFe.fromBytes(m, buf[0..n_len], .big) catch continue;
        if (r.isZero()) continue;
        return r;
    }
}

/// In-place big-endian right shift by `s` bits — copy of `root.zig`'s
/// identically-named private helper (Miller-Rabin dependency).
fn shrBytesBe(buf: []u8, s: usize) void {
    const byte_sh = s / 8;
    const bit_sh: u4 = @intCast(s % 8);
    var i: usize = buf.len;
    while (i > 0) {
        i -= 1;
        const lo: u16 = if (i >= byte_sh) buf[i - byte_sh] else 0;
        const hi: u16 = if (i >= byte_sh + 1) buf[i - byte_sh - 1] else 0;
        buf[i] = @truncate(((hi << 8) | lo) >> bit_sh);
    }
}

/// Uniform Miller-Rabin witness in [2, m-2] by rejection sampling — copy
/// of `root.zig`'s identically-named private helper.
fn randomWitness(m: root.AuxModulus, random: std.Random) root.AuxFe {
    const n_bits = m.bits();
    const n_len = byteLen(n_bits);
    const n_minus_1 = m.sub(m.zero, m.one());
    var buf: [root.aux_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, buf[0..n_len]);
    while (true) {
        random.bytes(buf[0..n_len]);
        buf[0] &= @as(u8, 0xff) >> @intCast(8 * n_len - n_bits);
        const a = root.AuxFe.fromBytes(m, buf[0..n_len], .big) catch continue;
        if (a.isZero() or a.eql(m.one()) or a.eql(n_minus_1)) continue;
        return a;
    }
}

/// Miller-Rabin probable-prime test — copy of `root.zig`'s identically-
/// named private helper (`m` must be odd; every `AuxModulus` is). Used by
/// `Pimod.verify`'s "n_tilde must be composite" check.
fn isProbablePrime(m: root.AuxModulus, random: std.Random) bool {
    const n_len = byteLen(m.bits());

    var d_buf: [root.aux_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, d_buf[0..n_len]);
    m.toBytes(d_buf[0..n_len], .big) catch unreachable;
    d_buf[n_len - 1] &= 0xfe; // m - 1 (m odd)
    var s: usize = 0;
    var i: usize = n_len;
    while (i > 0) {
        i -= 1;
        if (d_buf[i] == 0) {
            s += 8;
        } else {
            s += @ctz(d_buf[i]);
            break;
        }
    }
    shrBytesBe(d_buf[0..n_len], s);
    const d_bytes = stripLeadingZeros(d_buf[0..n_len]);

    const one = m.one();
    const n_minus_1 = m.sub(m.zero, one);

    var round: usize = 0;
    rounds: while (round < mr_rounds) : (round += 1) {
        const a = randomWitness(m, random);
        var x = m.powWithEncodedExponent(a, d_bytes, .big) catch unreachable; // d odd, never 0
        if (x.eql(one) or x.eql(n_minus_1)) continue :rounds;
        var j: usize = 1;
        while (j < s) : (j += 1) {
            x = m.sq(x);
            if (x.eql(n_minus_1)) continue :rounds;
            if (x.eql(one)) return false;
        }
        return false;
    }
    return true;
}

/// The `ff` modulus + fixed-width `(r+1)/4` square-root exponent for one
/// Blum-prime factor `r` (Πmod prover side). `e_buf` is caller-owned
/// backing storage for the returned exponent slice — fixed width = `r`'s
/// byte length (the exponent VALUE is secret — it reveals the factor —
/// but its LENGTH is public: each factor is half the public modulus).
/// Fail-closed on a degenerate `r` (even, etc.): the `ff` modulus falls
/// back to `nt`, yielding garbage a correct verifier rejects.
fn blumFactorCtx(
    gpa: std.mem.Allocator,
    r_big: *const BigInt,
    nt: root.AuxModulus,
    e_buf: *[root.aux_modulus_bytes]u8,
) std.mem.Allocator.Error!struct { m: root.AuxModulus, e_bytes: []const u8 } {
    var r_buf: [root.aux_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &r_buf);
    r_big.toConst().writeTwosComplement(&r_buf, .big);
    const m = root.AuxModulus.fromBytes(stripLeadingZeros(&r_buf), .big) catch nt;

    var t1 = try newBig(gpa);
    defer t1.deinit();
    var t2 = try newBig(gpa);
    defer t2.deinit();
    try t1.addScalar(r_big, 1);
    try t2.shiftRight(&t1, 2); // (r+1)/4 — exact for r ≡ 3 (mod 4)
    @memset(e_buf, 0);
    t2.toConst().writeTwosComplement(e_buf, .big);
    const r_len = byteLen(r_big.bitCountAbs());
    return .{ .m = m, .e_bytes = e_buf[root.aux_modulus_bytes - r_len ..] };
}

/// A 4th root of `c` modulo one Blum-prime factor `r` (`r ≡ 3 (mod 4)`,
/// `c` a QR mod `r`): two successive square roots via the closed form
/// `v^{(r+1)/4} mod r`, flipping the intermediate root's sign to land on
/// the QR square root before the second one (for `r ≡ 3 (mod 4)`, exactly
/// one of `±s` is a QR — `-1` is a non-residue). `rm`/`r_big` are the SAME
/// modulus in `ff`/big-int form; `e_bytes` is `blumFactorCtx`'s exponent.
/// Returns the root as an owned big integer (for CRT recombination).
fn fourthRootBlum(
    gpa: std.mem.Allocator,
    rm: root.AuxModulus,
    r_big: *const BigInt,
    c_big: *const BigInt,
    e_bytes: []const u8,
) std.mem.Allocator.Error!BigInt {
    var quot = try newBig(gpa);
    defer quot.deinit();
    var rem = try newBig(gpa);
    defer rem.deinit();
    try quot.divFloor(&rem, c_big, r_big); // c mod r
    const c_fe = feFromBig(rm, &rem);

    // First square root s = c^{(r+1)/4}; pick the QR one of ±s.
    var s = rm.powWithEncodedExponent(c_fe, e_bytes, .big) catch rm.one();
    {
        var s_big = try bigFromFe(gpa, s);
        defer s_big.deinit();
        if ((try jacobiBig(gpa, &s_big, r_big)) == -1) s = rm.sub(rm.zero, s);
    }
    // Second square root: a 4th root of c mod r.
    const x_fe = rm.powWithEncodedExponent(s, e_bytes, .big) catch rm.one();
    return bigFromFe(gpa, x_fe);
}

// ── Piprm / Pimod — the two irreducible ZK-proof cores (IMPLEMENTED) ────

/// Shared prove-side error set: the two cores need a scratch allocator
/// (big-integer arithmetic over `trapdoor.p`/`.q`/`phi(n_tilde)`, which is
/// NOT `root.AuxModulus`-shaped since `phi(n_tilde)` isn't itself a
/// modulus this module has a fixed-width type for — same
/// `std.math.big.int.Managed` + `std.heap.FixedBufferAllocator` scratch
/// idiom `root.zig`'s `generateAuxParamsInternal` already uses).
pub const ProveError = std.mem.Allocator.Error;

/// Πprm — CGGMP21 ePrint 2021/060 **Fig.17**, "ring-Pedersen parameters".
pub const Piprm = struct {
    /// **Prover.** Proves `t = s^lambda mod n_tilde` (`s := aux.h1`,
    /// `t := aux.h2`) for a KNOWN `lambda`, i.e. that `s` and `t` generate
    /// the SAME cyclic subgroup of `Z_n_tilde*` — WITHOUT revealing
    /// `lambda`. Soundness `~2^-80` (`pi_prm_iterations` 1-bit rounds).
    ///
    /// Construction (prover knows `trapdoor.lambda` AND `phi(n_tilde) =
    /// (p̃-1)(q̃-1)`, computable from `trapdoor.p`/`.q`):
    ///
    /// ```text
    /// 1. For i in 1..=m: sample a_i <- Z_{phi(n_tilde)} uniformly,
    ///    compute A_i = s^{a_i} mod n_tilde.
    /// 2. e = derivePrmChallengeBits(derivePrmSeed(aux, A_1..A_m))
    ///    ∈ {0,1}^m — REAL, already implemented above.
    /// 3. For i in 1..=m: z_i = a_i + e_i*lambda mod phi(n_tilde) (plain
    ///    modular arithmetic over the SECRET phi(n_tilde) — needs
    ///    std.math.big.int over trapdoor.p/.q, not std.crypto.ff, since
    ///    phi(n_tilde) isn't this module's fixed AuxModulus type; z_i is
    ///    then re-encoded canonical mod n_tilde into `PrmEntry.z`, valid
    ///    since z_i < phi(n_tilde) < n_tilde).
    /// 4. Proof = PrmProof{ entries: [{A_i, z_i}]_{i=1..m} }.
    /// ```
    ///
    /// `aux`/`trapdoor` MUST correspond (same `n_tilde`) — a mismatch is a
    /// caller bug, not a soundness question this proof needs to catch.
    pub fn prove(
        allocator: std.mem.Allocator,
        aux: root.AuxParams,
        trapdoor: root.AuxTrapdoor,
        random: std.Random,
    ) ProveError!PrmProof {
        const nt = aux.n_tilde;

        // phi(n_tilde) = (p̃-1)(q̃-1) from the trapdoor. Degenerate factors
        // (< 2, or wider than the modulus type) are substituted fail-closed
        // — the resulting proof is garbage a correct verifier rejects; an
        // aux/trapdoor mismatch is a caller bug per this function's
        // contract, never a soundness question.
        var p = try bigFromBytes(allocator, stripLeadingZeros(trapdoor.p));
        defer p.deinit();
        var q = try bigFromBytes(allocator, stripLeadingZeros(trapdoor.q));
        defer q.deinit();
        if (p.toConst().orderAgainstScalar(2) == .lt or p.bitCountAbs() > root.aux_modulus_bits) try p.set(3);
        if (q.toConst().orderAgainstScalar(2) == .lt or q.bitCountAbs() > root.aux_modulus_bits) try q.set(3);

        var phi = try newBig(allocator);
        defer phi.deinit();
        {
            var p1 = try newBig(allocator);
            defer p1.deinit();
            var q1 = try newBig(allocator);
            defer q1.deinit();
            try p1.addScalar(&p, -1);
            try q1.addScalar(&q, -1);
            try phi.mul(&p1, &q1);
        }
        if (phi.toConst().orderAgainstScalar(1) != .gt or phi.bitCountAbs() > root.aux_modulus_bits) try phi.set(4);

        // phi is SECRET (equivalent to n_tilde's factorization) — its byte
        // image below is zeroed on return; its bit LENGTH is public (an
        // honest phi has n_tilde's size).
        const phi_bits = phi.bitCountAbs();
        const phi_len = byteLen(phi_bits);
        var phi_buf: [root.aux_modulus_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &phi_buf);
        phi.toConst().writeTwosComplement(&phi_buf, .big);
        const phi_bytes = phi_buf[root.aux_modulus_bytes - phi_len ..];

        var lam_big = blk: {
            var lam_buf: [root.aux_modulus_bytes]u8 = undefined;
            defer std.crypto.secureZero(u8, &lam_buf);
            trapdoor.lambda.toBytes(&lam_buf, .big) catch unreachable; // fixed-width buffer always sufficient
            break :blk try bigFromBytes(allocator, stripLeadingZeros(&lam_buf));
        };
        defer lam_big.deinit();

        // 1. Per-round nonce a_i <- Z_phi (uniform via rejection sampling
        //    against phi's byte image) and commitment A_i = s^{a_i}
        //    (constant-time modexp — a_i masks lambda).
        var a_bufs: [pi_prm_iterations][root.aux_modulus_bytes]u8 = undefined;
        defer for (&a_bufs) |*ab| std.crypto.secureZero(u8, ab);
        var commitments: [pi_prm_iterations]root.AuxFe = undefined;
        const top_mask: u8 = @as(u8, 0xff) >> @intCast(8 * phi_len - phi_bits);
        for (&a_bufs, &commitments) |*ab, *commit| {
            @memset(ab, 0);
            while (true) {
                random.bytes(ab[0..phi_len]);
                ab[0] &= top_mask;
                if (intCompare(ab[0..phi_len], phi_bytes) == .lt) break;
            }
            commit.* = nt.powWithEncodedExponent(aux.h1, ab[0..phi_len], .big) catch nt.one(); // a_i = 0 -> s^0 = 1
        }

        // 2. Fiat-Shamir bit-challenge — the REAL scaffold machinery above.
        const seed = derivePrmSeed(aux, &commitments);
        var e_bits: [pi_prm_iterations]bool = undefined;
        derivePrmChallengeBits(seed, &e_bits);

        // 3. Responses z_i = a_i + e_i*lambda mod phi (z_i < phi < n_tilde,
        //    so the canonical-mod-n_tilde re-encoding is always valid).
        var entries: [pi_prm_iterations]PrmEntry = undefined;
        var z = try newBig(allocator);
        defer z.deinit();
        var sum = try newBig(allocator);
        defer sum.deinit();
        var quot = try newBig(allocator);
        defer quot.deinit();
        for (&entries, &a_bufs, &commitments, e_bits) |*slot, *ab, commit, e_i| {
            var av = try bigFromBytes(allocator, stripLeadingZeros(ab[0..phi_len]));
            defer av.deinit();
            if (e_i) {
                try sum.add(&av, &lam_big);
                try quot.divFloor(&z, &sum, &phi);
            } else {
                try z.copy(av.toConst());
            }
            slot.* = .{ .a_commit = commit, .z = feFromBig(nt, &z) };
        }
        return .{ .entries = entries };
    }

    /// **Verifier.** Verifier knows only `aux` (`s = aux.h1`, `t =
    /// aux.h2`, `n_tilde`) and `proof` — NOT the factorization.
    ///
    /// ```text
    /// 1. 1 < s,t < n_tilde and gcd(s,n_tilde) = gcd(t,n_tilde) = 1 (reuse
    ///    root.zig's Jacobi-symbol machinery or a plain std.math.big.int
    ///    gcd — either establishes coprimality; a genuine subgroup
    ///    membership question, distinct from — and a PRECONDITION for —
    ///    the per-round equation check below).
    /// 2. Recompute e = derivePrmChallengeBits(derivePrmSeed(aux,
    ///    proof.entries[*].a_commit)) — the SAME call the prover made.
    /// 3. For each i in 1..=m: verify
    ///      s^{z_i} == A_i * t^{e_i} (mod n_tilde)
    ///    (powWithEncodedPublicExponent — z_i/A_i/e_i are all PUBLIC
    ///    proof fields). Reject (return false) on ANY single failure.
    /// 4. Accept (return true) only if every round's equation holds.
    /// ```
    pub fn verify(aux: root.AuxParams, proof: PrmProof) bool {
        const nt = aux.n_tilde;
        const one = nt.one();

        // 1. 1 < s,t < n_tilde (the upper bound is AuxFe canonicality) and
        //    coprimality with n_tilde — Jacobi symbol != 0 <=> gcd == 1,
        //    the same machinery root.zig's `AuxParams.validate` leans on.
        if (aux.h1.isZero() or aux.h1.eql(one)) return false;
        if (aux.h2.isZero() or aux.h2.eql(one)) return false;
        {
            var scratch: [verify_scratch_bytes]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&scratch);
            const gpa = fba.allocator();
            var nt_buf: [root.aux_modulus_bytes]u8 = undefined;
            nt.toBytes(&nt_buf, .big) catch return false;
            const nb = bigFromBytes(gpa, stripLeadingZeros(&nt_buf)) catch return false;
            for ([_]root.AuxFe{ aux.h1, aux.h2 }) |h| {
                const hb = bigFromFe(gpa, h) catch return false;
                if ((jacobiBig(gpa, &hb, &nb) catch return false) == 0) return false;
            }
        }

        // 2. Recompute the challenge from the proof's own commitments — the
        //    SAME derivePrmSeed/derivePrmChallengeBits call the prover made.
        var commitments: [pi_prm_iterations]root.AuxFe = undefined;
        for (proof.entries, &commitments) |e, *c| c.* = e.a_commit;
        const seed = derivePrmSeed(aux, &commitments);
        var e_bits: [pi_prm_iterations]bool = undefined;
        derivePrmChallengeBits(seed, &e_bits);

        // 3+4. Per-round equation s^{z_i} == A_i * t^{e_i} (mod n_tilde);
        //      reject on ANY single failure.
        for (proof.entries, e_bits) |e, e_i| {
            var z_buf: [root.aux_modulus_bytes]u8 = undefined;
            e.z.toBytes(&z_buf, .big) catch return false;
            const lhs = nt.powWithEncodedPublicExponent(aux.h1, stripLeadingZeros(&z_buf), .big) catch nt.one(); // z = 0 -> s^0 = 1
            const rhs = if (e_i) nt.mul(e.a_commit, aux.h2) else e.a_commit;
            if (!auxFeEql(lhs, rhs)) return false;
        }
        return true;
    }
};

/// Πmod — CGGMP21 ePrint 2021/060 **Fig.16**, "Paillier-Blum modulus".
pub const Pimod = struct {
    /// **Prover.** Proves `aux.n_tilde` is the product of two Blum
    /// primes `p̃, q̃ ≡ 3 (mod 4)` (which `trapdoor.p`/`.q` — the safe-prime
    /// search behind `root.generateAuxParamsWithTrapdoor` — already
    /// guarantees, via `generateSafePrime`'s own `p̃ ≡ 3 (mod 4)` filter)
    /// with `gcd(n_tilde, phi(n_tilde)) = 1` (automatic for a genuine
    /// two-DISTINCT-prime product), WITHOUT revealing `p̃`/`q̃`. Soundness
    /// `~2^-80` (`pi_mod_iterations` rounds, each catching a cheating
    /// prover with probability `>= 1/2`).
    ///
    /// Construction (prover knows `p̃ = trapdoor.p`, `q̃ = trapdoor.q`,
    /// hence `phi(n_tilde) = (p̃-1)(q̃-1)`):
    ///
    /// ```text
    /// 1. Pick w <- Z_n_tilde with Jacobi symbol (w / n_tilde) = -1 — a
    ///    quadratic non-residue that is +1 mod ONE prime factor and -1
    ///    mod the OTHER (rejection-sample random w until the symbol hits
    ///    -1; this ALWAYS succeeds for a genuine two-Blum-prime n_tilde,
    ///    since exactly half of Z_n_tilde* has symbol -1).
    /// 2. y_i = deriveModChallenge(n_tilde, deriveModSeed(aux, w), i) for
    ///    i in 1..=m — REAL, already implemented above.
    /// 3. For each y_i: since n_tilde is a Blum integer, EXACTLY ONE of
    ///    {y_i, -y_i, w*y_i, -w*y_i} (mod n_tilde) is a quadratic residue
    ///    — find the (a_i, b_i in {0,1}) pair such that
    ///      y'_i = (-1)^{a_i} * w^{b_i} * y_i mod n_tilde
    ///    is a QR, by checking each candidate's Legendre symbol mod p̃ and
    ///    mod q̃ directly (cheap with the factorization in hand).
    /// 4. Compute x_i = a 4th root of y'_i mod n_tilde: take modular
    ///    square roots mod p̃ and mod q̃ TWICE each (p̃, q̃ ≡ 3 mod 4 gives a
    ///    closed-form root `a^{(p+1)/4} mod p`, no Tonelli-Shanks needed),
    ///    then CRT-recombine into x_i mod n_tilde.
    /// 5. Compute z_i = y_i^{n_tilde^{-1} mod phi(n_tilde)} mod n_tilde —
    ///    n_tilde is invertible mod phi(n_tilde) iff gcd(n_tilde,
    ///    phi(n_tilde)) = 1, exactly the property this proof establishes;
    ///    an honest two-distinct-prime n_tilde always succeeds here.
    /// 6. Proof = ModProof{ w, entries: [{x_i, z_i, a_i, b_i}]_{i=1..m} }.
    /// ```
    ///
    /// `aux`/`trapdoor` MUST correspond (same `n_tilde`) — a mismatch is a
    /// caller bug.
    pub fn prove(
        allocator: std.mem.Allocator,
        aux: root.AuxParams,
        trapdoor: root.AuxTrapdoor,
        random: std.Random,
    ) ProveError!ModProof {
        const nt = aux.n_tilde;
        const n_len = byteLen(nt.bits());

        var nt_buf: [root.aux_modulus_bytes]u8 = undefined;
        nt.toBytes(&nt_buf, .big) catch unreachable; // fixed-width buffer always sufficient
        var n_big = try bigFromBytes(allocator, stripLeadingZeros(&nt_buf));
        defer n_big.deinit();

        // Trapdoor factors — degenerate input is substituted fail-closed
        // (garbage proof a correct verifier rejects, never a panic/hang);
        // an aux/trapdoor mismatch is a caller bug per the contract.
        var p = try bigFromBytes(allocator, stripLeadingZeros(trapdoor.p));
        defer p.deinit();
        var q = try bigFromBytes(allocator, stripLeadingZeros(trapdoor.q));
        defer q.deinit();
        if (p.toConst().orderAgainstScalar(2) == .lt or p.bitCountAbs() > root.aux_modulus_bits) try p.set(3);
        if (q.toConst().orderAgainstScalar(2) == .lt or q.bitCountAbs() > root.aux_modulus_bits) try q.set(3);

        var phi = try newBig(allocator);
        defer phi.deinit();
        {
            var p1 = try newBig(allocator);
            defer p1.deinit();
            var q1 = try newBig(allocator);
            defer q1.deinit();
            try p1.addScalar(&p, -1);
            try q1.addScalar(&q, -1);
            try phi.mul(&p1, &q1);
        }
        if (phi.toConst().orderAgainstScalar(1) != .gt or phi.bitCountAbs() > root.aux_modulus_bits) try phi.set(4);

        // 5's exponent: d = n_tilde^{-1} mod phi — SECRET (factor-
        // equivalent), hence the fixed-width buffer + constant-time modexp
        // below, and a fail-closed d = 1 when phi is degenerate or
        // gcd(n_tilde, phi) != 1 (an honest two-distinct-Blum-prime
        // trapdoor always inverts — that is exactly the property Πmod
        // establishes).
        var d_buf: [root.aux_modulus_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &d_buf);
        @memset(&d_buf, 0);
        d_buf[d_buf.len - 1] = 1;
        if (try modInverse(allocator, &n_big, &phi)) |d_val| {
            var d = d_val;
            defer d.deinit();
            d.toConst().writeTwosComplement(&d_buf, .big);
        }
        const d_bytes = d_buf[root.aux_modulus_bytes - n_len ..];

        // Per-factor ff moduli + (r+1)/4 square-root exponents.
        var ep_buf: [root.aux_modulus_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &ep_buf);
        const pctx = try blumFactorCtx(allocator, &p, nt, &ep_buf);
        var eq_buf: [root.aux_modulus_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &eq_buf);
        const qctx = try blumFactorCtx(allocator, &q, nt, &eq_buf);

        // CRT constant q^{-1} mod p (Garner recombination), fail-closed 0.
        var qinv = (try modInverse(allocator, &q, &p)) orelse blk: {
            var zero_big = try newBig(allocator);
            errdefer zero_big.deinit();
            try zero_big.set(0);
            break :blk zero_big;
        };
        defer qinv.deinit();

        // 1. Witness w with Jacobi (w/n_tilde) = -1. Exactly half of
        //    Z_n_tilde* qualifies for a genuine Blum modulus, so the search
        //    is a couple of coin flips; the try-cap is a fail-closed guard
        //    against a crafted n_tilde where NO such w exists (e.g. a
        //    perfect square), leaving w = 1 (Jacobi +1) for the verifier's
        //    own Jacobi check to reject.
        var w_fe = nt.one();
        {
            var tries: usize = 0;
            while (tries < 4096) : (tries += 1) {
                const cand = sampleNonzeroLtModulus(nt, random);
                var cb = try bigFromFe(allocator, cand);
                defer cb.deinit();
                if ((try jacobiBig(allocator, &cb, &n_big)) == -1) {
                    w_fe = cand;
                    break;
                }
            }
        }

        // Per-prime characters of -1 and w, computed once: the per-round
        // (a_i, b_i) selection only multiplies these signs together.
        // χ_r(-1) = -1 exactly when r ≡ 3 (mod 4) — true for both factors
        // of a genuine Blum modulus, which is what makes the four
        // candidates cover all four QR classes.
        const jp_m1: i8 = if ((p.toConst().limbs[0] & 3) == 3) -1 else 1;
        const jq_m1: i8 = if ((q.toConst().limbs[0] & 3) == 3) -1 else 1;
        var w_big = try bigFromFe(allocator, w_fe);
        defer w_big.deinit();
        const jp_w = try jacobiBig(allocator, &w_big, &p);
        const jq_w = try jacobiBig(allocator, &w_big, &q);

        // 2. Fiat-Shamir challenges — the REAL scaffold machinery above.
        const seed = deriveModSeed(aux, w_fe);
        var entries: [pi_mod_iterations]ModEntry = undefined;

        // Loop temporaries for the CRT recombination.
        var t = try newBig(allocator);
        defer t.deinit();
        var quot = try newBig(allocator);
        defer quot.deinit();
        var rem = try newBig(allocator);
        defer rem.deinit();

        for (&entries, 0..) |*slot, idx| {
            const y = deriveModChallenge(nt, seed, @intCast(idx + 1));

            // 3. Pick (a_i, b_i) making y' = (-1)^{a_i} w^{b_i} y_i a QR
            //    mod BOTH factors (Legendre via the Jacobi routine — the
            //    factors are prime for an honest trapdoor). Exactly one
            //    pair works for a genuine Blum modulus; fall back to (0,0)
            //    otherwise (garbage the verifier rejects).
            var y_big = try bigFromFe(allocator, y);
            defer y_big.deinit();
            const jp_y = try jacobiBig(allocator, &y_big, &p);
            const jq_y = try jacobiBig(allocator, &y_big, &q);

            var a_bit = false;
            var b_bit = false;
            for ([_][2]bool{ .{ false, false }, .{ true, false }, .{ false, true }, .{ true, true } }) |ab| {
                var sp = jp_y;
                var sq = jq_y;
                if (ab[0]) {
                    sp *= jp_m1;
                    sq *= jq_m1;
                }
                if (ab[1]) {
                    sp *= jp_w;
                    sq *= jq_w;
                }
                if (sp == 1 and sq == 1) {
                    a_bit = ab[0];
                    b_bit = ab[1];
                    break;
                }
            }

            var y_prime = y;
            if (b_bit) y_prime = nt.mul(w_fe, y_prime);
            if (a_bit) y_prime = nt.sub(nt.zero, y_prime);

            // 4. x_i = 4th root of y' — per-factor Blum roots + Garner CRT
            //    x = x_q + q * ((x_p - x_q) * q^{-1} mod p) < p*q.
            var c_big = try bigFromFe(allocator, y_prime);
            defer c_big.deinit();
            var xp = try fourthRootBlum(allocator, pctx.m, &p, &c_big, pctx.e_bytes);
            defer xp.deinit();
            var xq = try fourthRootBlum(allocator, qctx.m, &q, &c_big, qctx.e_bytes);
            defer xq.deinit();
            try t.sub(&xp, &xq);
            try t.mul(&t, &qinv);
            try quot.divFloor(&rem, &t, &p);
            try t.mul(&rem, &q);
            try t.add(&t, &xq);
            const x_fe = feFromBig(nt, &t);

            // 5. z_i = y_i^d (constant-time in the secret exponent d).
            const z_fe = nt.powWithEncodedExponent(y, d_bytes, .big) catch nt.one();

            slot.* = .{ .x = x_fe, .z = z_fe, .a = a_bit, .b = b_bit };
        }

        // 6. Proof object — struct + codec were already real.
        return .{ .w = w_fe, .entries = entries };
    }

    /// **Verifier.** Verifier knows only `aux.n_tilde` (NOT its
    /// factorization) and `proof`.
    ///
    /// ```text
    /// 1. n_tilde ODD and COMPOSITE (reuse root.zig's Miller-Rabin
    ///    `isProbablePrime` — reject if PRIME, same check
    ///    `AuxParams.validate` already performs).
    /// 2. Recompute y_i = deriveModChallenge(n_tilde,
    ///    deriveModSeed(aux, proof.w), i) for i in 1..=m — the SAME call
    ///    the prover made.
    /// 3. For each i in 1..=m: verify BOTH
    ///      z_i^n_tilde == y_i (mod n_tilde), AND
    ///      x_i^4 == (-1)^{a_i} * w^{b_i} * y_i (mod n_tilde).
    ///    Reject (return false) on ANY single failure (either equation,
    ///    any round).
    /// 4. Accept (return true) only if every round's pair of equations
    ///    holds. (A prime-power n_tilde that slips past step 1's
    ///    Miller-Rabin check is caught here with overwhelming probability
    ///    instead — the per-round 4th-root/Paillier-response equations
    ///    are vanishingly unlikely to hold simultaneously for a
    ///    non-Blum-integer n_tilde.)
    /// ```
    pub fn verify(aux: root.AuxParams, proof: ModProof) bool {
        const nt = aux.n_tilde;
        var nt_buf: [root.aux_modulus_bytes]u8 = undefined;
        nt.toBytes(&nt_buf, .big) catch return false;
        const n_bytes = stripLeadingZeros(&nt_buf);

        // 1. n_tilde must be an odd composite. Odd is structural (ff
        //    rejects even moduli); composite = Miller-Rabin with witnesses
        //    drawn from a PRNG seeded by H(n_tilde) — `verify` takes no
        //    CSPRNG parameter, and deriving the witnesses from the modulus
        //    itself keeps them outside the modulus-crafter's control (the
        //    modulus cannot be chosen AFTER its own witnesses are known).
        //    An honest composite fails MR on the first witness; only a
        //    (rejected) prime pays the full round count.
        {
            var digest: [Sha256.digest_length]u8 = undefined;
            Sha256.hash(n_bytes, &digest, .{});
            var prng = std.Random.DefaultPrng.init(std.mem.readInt(u64, digest[0..8], .big));
            if (isProbablePrime(nt, prng.random())) return false;
        }

        // 2. Jacobi (w/n_tilde) must be -1 — the witness property every
        //    round's QR-class adjustment leans on; also forces w != 0 and
        //    gcd(w, n_tilde) = 1 (the symbol is 0 for either).
        {
            var scratch: [verify_scratch_bytes]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&scratch);
            const gpa = fba.allocator();
            const wb = bigFromFe(gpa, proof.w) catch return false;
            const nb = bigFromBytes(gpa, n_bytes) catch return false;
            if ((jacobiBig(gpa, &wb, &nb) catch return false) != -1) return false;
        }

        // 3+4. Recompute every y_i (the SAME derivation the prover used)
        //      and check BOTH per-round equations; reject on ANY failure.
        const seed = deriveModSeed(aux, proof.w);
        for (proof.entries, 0..) |e, idx| {
            const y = deriveModChallenge(nt, seed, @intCast(idx + 1));

            // z_i^{n_tilde} == y_i — forces gcd(n_tilde, phi(n_tilde)) = 1
            // (the n-th-power map must be a bijection on Z_n_tilde*).
            const zn = nt.powWithEncodedPublicExponent(e.z, n_bytes, .big) catch return false;
            if (!auxFeEql(zn, y)) return false;

            // x_i^4 == (-1)^{a_i} w^{b_i} y_i — forces the Blum structure
            // (4th roots of a full QR-class cover exist only when both
            // prime factors are ≡ 3 mod 4; a 3-prime or prime-power
            // n_tilde fails this with overwhelming probability across the
            // 80 rounds).
            const x4 = nt.sq(nt.sq(e.x));
            var rhs = y;
            if (e.b) rhs = nt.mul(rhs, proof.w);
            if (e.a) rhs = nt.sub(nt.zero, rhs);
            if (!auxFeEql(x4, rhs)) return false;
        }
        return true;
    }
};

// ── AuxParams.proveWellFormed / .verifyWellFormed — the public API ──────
//
// Free functions rather than methods ON `root.AuxParams` (the task's
// suggested `AuxParams.proveWellFormed`/`.verifyWellFormed` names) because
// `root.zig` cannot import `aux_proofs.zig` back — `aux_proofs.zig`
// already imports `root.zig` for `AuxParams`/`AuxFe`/`AuxModulus`/
// `AuxTrapdoor`, and Zig has no forward-declared circular imports. Same
// shape `zkproofs.zig`'s own `proveAliceRange`/`verifyAliceRange` etc.
// already use for functions that operate ON a `root.AuxParams` value.

/// Both proofs-of-correct-generation for one `AuxParams` tuple, bundled —
/// what a generator broadcasts ALONGSIDE its `(n_tilde, h1, h2)` to let
/// every counterparty verify well-formedness instead of only the
/// structural floor `AuxParams.validate` can check.
pub const WellFormedProof = struct {
    prm: PrmProof,
    mod: ModProof,
};

pub const VerifyError = error{InvalidWellFormedProof};

/// Generator-side: produce BOTH proofs-of-correct-generation for `aux`,
/// using the retained trapdoor (`root.generateAuxParamsWithTrapdoor`).
pub fn proveWellFormed(
    allocator: std.mem.Allocator,
    aux: root.AuxParams,
    trapdoor: root.AuxTrapdoor,
    random: std.Random,
) ProveError!WellFormedProof {
    return .{
        .prm = try Piprm.prove(allocator, aux, trapdoor, random),
        .mod = try Pimod.prove(allocator, aux, trapdoor, random),
    };
}

/// Validator-side: verify BOTH proofs-of-correct-generation for a
/// RECEIVED `aux` tuple. Call this IN ADDITION TO (after)
/// `aux.validate(random)` — `validate` is the cheap always-enforced
/// structural floor (audit F1's necessary-but-not-sufficient Jacobi
/// check); this is the full fix. Fail-closed: either proof's rejection
/// rejects the WHOLE tuple.
pub fn verifyWellFormed(aux: root.AuxParams, proof: WellFormedProof) VerifyError!void {
    if (!Piprm.verify(aux, proof.prm)) return error.InvalidWellFormedProof;
    if (!Pimod.verify(aux, proof.mod)) return error.InvalidWellFormedProof;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn toyModulus() root.AuxModulus {
    // Same `187 = 11*17` toy modulus `root.zig`'s own `toyAuxParams` test
    // helper uses — exists only to exercise struct/codec/FS shapes, not a
    // secure ring-Pedersen instance.
    return root.AuxModulus.fromBytes(&[_]u8{187}, .big) catch unreachable;
}

fn toyFe(nt: root.AuxModulus, v: u8) root.AuxFe {
    return root.AuxFe.fromBytes(nt, &[_]u8{v}, .big) catch unreachable;
}

test "ModProof toBytesAlloc/fromBytesAlloc round-trip (hand-built dummy values, ungated)" {
    const allocator = testing.allocator;
    const nt = toyModulus();

    var entries: [pi_mod_iterations]ModEntry = undefined;
    for (&entries, 0..) |*e, i| {
        e.* = .{
            .x = toyFe(nt, @intCast(2 + i % 90)),
            .z = toyFe(nt, @intCast(3 + i % 90)),
            .a = i % 2 == 0,
            .b = i % 3 == 0,
        };
    }
    const proof: ModProof = .{ .w = toyFe(nt, 5), .entries = entries };

    const bytes = try proof.toBytesAlloc(allocator);
    defer allocator.free(bytes);
    const back = try ModProof.fromBytesAlloc(nt, bytes);

    try testing.expect(proof.w.eql(back.w));
    for (proof.entries, back.entries) |a, b| {
        try testing.expect(a.x.eql(b.x));
        try testing.expect(a.z.eql(b.z));
        try testing.expectEqual(a.a, b.a);
        try testing.expectEqual(a.b, b.b);
    }
}

test "PrmProof toBytesAlloc/fromBytesAlloc round-trip (hand-built dummy values, ungated)" {
    const allocator = testing.allocator;
    const nt = toyModulus();

    var entries: [pi_prm_iterations]PrmEntry = undefined;
    for (&entries, 0..) |*e, i| {
        e.* = .{
            .a_commit = toyFe(nt, @intCast(2 + i % 90)),
            .z = toyFe(nt, @intCast(3 + i % 90)),
        };
    }
    const proof: PrmProof = .{ .entries = entries };

    const bytes = try proof.toBytesAlloc(allocator);
    defer allocator.free(bytes);
    const back = try PrmProof.fromBytesAlloc(nt, bytes);

    for (proof.entries, back.entries) |a, b| {
        try testing.expect(a.a_commit.eql(b.a_commit));
        try testing.expect(a.z.eql(b.z));
    }
}

test "deriveModChallenge: deterministic and canonical (< n_tilde), varies by index (ungated)" {
    const nt = toyModulus();
    const w = toyFe(nt, 5);
    const aux: root.AuxParams = .{ .n_tilde = nt, .h1 = toyFe(nt, 4), .h2 = toyFe(nt, 16) };
    const seed = deriveModSeed(aux, w);

    const y1 = deriveModChallenge(nt, seed, 1);
    const y1_again = deriveModChallenge(nt, seed, 1);
    try testing.expect(y1.eql(y1_again));

    const y2 = deriveModChallenge(nt, seed, 2);
    try testing.expect(!y1.eql(y2));

    // Different seed (different w) -> different challenge at the same index.
    const seed2 = deriveModSeed(aux, toyFe(nt, 25));
    const y1_other_seed = deriveModChallenge(nt, seed2, 1);
    try testing.expect(!y1.eql(y1_other_seed));
}

test "derivePrmChallengeBits: deterministic, not degenerate (ungated)" {
    const nt = toyModulus();
    const aux: root.AuxParams = .{ .n_tilde = nt, .h1 = toyFe(nt, 5), .h2 = toyFe(nt, 25) };
    var commitments: [pi_prm_iterations]root.AuxFe = undefined;
    for (&commitments, 0..) |*c, i| c.* = toyFe(nt, @intCast(2 + i % 90));

    const seed = derivePrmSeed(aux, &commitments);
    var bits1: [pi_prm_iterations]bool = undefined;
    derivePrmChallengeBits(seed, &bits1);
    var bits2: [pi_prm_iterations]bool = undefined;
    derivePrmChallengeBits(seed, &bits2);
    try testing.expectEqualSlices(bool, &bits1, &bits2);

    var all_same = true;
    for (bits1) |b| {
        if (b != bits1[0]) {
            all_same = false;
            break;
        }
    }
    try testing.expect(!all_same); // overwhelmingly likely for a real hash output

    // Different commitments -> a different bit-string (overwhelmingly likely).
    commitments[0] = toyFe(nt, 99);
    const seed3 = derivePrmSeed(aux, &commitments);
    var bits3: [pi_prm_iterations]bool = undefined;
    derivePrmChallengeBits(seed3, &bits3);
    try testing.expect(!std.mem.eql(bool, &bits1, &bits3));
}

// ── F1 soundness scenario (a): a 3-prime n_tilde ────────────────────────
//
// A composite `n_tilde` with THREE prime-ish factors instead of two still
// passes `AuxParams.validate` (composite via Miller-Rabin, > q^7, and
// `h1=4`/`h2=16` are perfect squares so their Jacobi symbol is trivially
// `+1` regardless of n_tilde's factorization) — this is EXACTLY audit F1's
// gap. It is NOT a genuine Paillier-Blum modulus (Πmod's whole point), so
// once the core lands, `Pimod.verify` must reject it.

/// ~2013-bit odd composite = product of THREE distinct ~671-bit
/// comptime-computed factors — comfortably inside `root.AuxModulus`'s
/// 2048-bit capacity and comfortably above the audit-F2 `q^7` (~1792-bit)
/// floor, so `AuxParams.validate` never trips on size or oddness, only on
/// whatever Πmod would eventually check. Mirrors `root.zig`'s own
/// `big_composite` comptime-composite trick (its F1/F2 `validate` test).
fn threePrimeNTilde() root.AuxModulus {
    const three_factor = comptime blk: {
        const f1 = (1 << 671) + 9;
        const f2 = (1 << 671) + 15;
        const f3 = (1 << 671) + 21;
        break :blk f1 * f2 * f3;
    };
    const bytes = comptime comptimeIntBytes(root.aux_modulus_bytes, three_factor);
    return root.AuxModulus.fromBytes(stripLeadingZeros(&bytes), .big) catch unreachable;
}

test "F1 soundness (a) — 3-prime n_tilde: AuxParams.validate() ACCEPTS it (documents the gap, ungated)" {
    var prng = std.Random.DefaultPrng.init(0x3370726d6531);
    const random = prng.random();

    const nt = threePrimeNTilde();
    const aux: root.AuxParams = .{ .n_tilde = nt, .h1 = toyFe2048(nt, 4), .h2 = toyFe2048(nt, 16) };
    try aux.validate(random); // ACCEPTS — this is the gap Πmod closes.
}

test "F1 soundness (a) — 3-prime n_tilde: Pimod.verify REJECTS it (documents the fix, GATED)" {
    if (!gate.aux_proofs_core_implemented) return error.SkipZigTest;

    var prng = std.Random.DefaultPrng.init(0x3370726d6532);
    const random = prng.random();
    const allocator = testing.allocator;

    const nt = threePrimeNTilde();
    const aux: root.AuxParams = .{ .n_tilde = nt, .h1 = toyFe2048(nt, 4), .h2 = toyFe2048(nt, 16) };

    // A dishonest prover who genuinely knows all three factors might try
    // to fake a bi-prime split — p := factor 1, q := factor2*factor3
    // (which is NOT itself prime). Whether `Pimod.prove` refuses this
    // trapdoor outright (fail-closed on a non-prime "q̃") or produces a
    // proof, `Pimod.verify` must never accept a 3-prime modulus as
    // Paillier-Blum.
    const f1_bytes = comptime comptimeIntBytes(88, (1 << 671) + 9);
    const f23_bytes = comptime comptimeIntBytes(root.aux_modulus_bytes, ((1 << 671) + 15) * ((1 << 671) + 21));
    const fake_trapdoor: root.AuxTrapdoor = .{
        .p = stripLeadingZeros(&f1_bytes),
        .q = stripLeadingZeros(&f23_bytes),
        .lambda = aux.h1, // placeholder — this scenario is about n_tilde's factorization shape
    };

    const maybe_proof = Pimod.prove(allocator, aux, fake_trapdoor, random);
    if (maybe_proof) |proof| {
        try testing.expect(!Pimod.verify(aux, proof));
    } else |_| {
        // A prove-side refusal (e.g. on a non-prime "q̃") is an equally
        // acceptable fail-closed outcome.
    }
}

/// `toyFe` sized for the 2048-bit `threePrimeNTilde`/`outsideSubgroupAux`
/// moduli (`toyFe` above assumes a 1-byte-representable modulus like
/// `187`, but `AuxFe.fromBytes` itself only cares that the value < the
/// modulus — a single-byte value is always valid regardless of the
/// modulus's own size, so this is the SAME helper under a name that
/// doesn't imply "toy-sized modulus too").
fn toyFe2048(nt: root.AuxModulus, v: u8) root.AuxFe {
    return root.AuxFe.fromBytes(nt, &[_]u8{v}, .big) catch unreachable;
}

// ── F1 soundness scenario (b): h2 outside <h1> ──────────────────────────

/// A genuine ~2000-bit odd composite (two ~1000-bit comptime factors —
/// same construction `root.zig`'s own F1/F2 `validate` test uses for its
/// `nt_ok`) with `h1 = 4 = 2^2`, `h2 = 9 = 3^2`: both perfect squares
/// (hence Jacobi `+1`, hence `AuxParams.validate` accepts), but nothing
/// ties `9` to a power of `4` mod this modulus — `h2` is (with
/// overwhelming likelihood) NOT in the cyclic subgroup `<h1>`, exactly
/// what Πprm exists to rule out.
fn outsideSubgroupAux() root.AuxParams {
    const composite = comptime blk: {
        const f1 = (1 << 1000) + 9;
        const f2 = (1 << 1000) + 15;
        break :blk f1 * f2;
    };
    const bytes = comptime comptimeIntBytes(root.aux_modulus_bytes, composite);
    const nt = root.AuxModulus.fromBytes(stripLeadingZeros(&bytes), .big) catch unreachable;
    return .{ .n_tilde = nt, .h1 = toyFe2048(nt, 4), .h2 = toyFe2048(nt, 9) };
}

test "F1 soundness (b) — h2 outside <h1>: AuxParams.validate() ACCEPTS it (documents the gap, ungated)" {
    var prng = std.Random.DefaultPrng.init(0x6f75747369646562); // "outsideb"
    const random = prng.random();

    const aux = outsideSubgroupAux();
    try aux.validate(random); // ACCEPTS — this is the gap Πprm closes.
}

test "F1 soundness (b) — h2 outside <h1>: Piprm.verify REJECTS it (documents the fix, GATED)" {
    if (!gate.aux_proofs_core_implemented) return error.SkipZigTest;

    const aux = outsideSubgroupAux();
    const nt = aux.n_tilde;

    // No genuine trapdoor exists relating this h1/h2 pair by a known
    // discrete log (that IS Πprm's point — such a tuple should be
    // UNPROVABLE). Demonstrate rejection the other way: a hand-built
    // proof with plausible-shaped-but-arbitrary (A_i, z_i) values must
    // fail Piprm.verify's per-round equation check.
    var entries: [pi_prm_iterations]PrmEntry = undefined;
    for (&entries, 0..) |*e, i| {
        e.* = .{
            .a_commit = toyFe2048(nt, @intCast(2 + i % 90)),
            .z = toyFe2048(nt, @intCast(3 + i % 90)),
        };
    }
    const forged: PrmProof = .{ .entries = entries };
    try testing.expect(!Piprm.verify(aux, forged));
}

// ── completeness (GATED — needs the core) ───────────────────────────────

test "Πprm+Πmod completeness: honest generateAuxParamsWithTrapdoor -> proveWellFormed -> verifyWellFormed accepts (GATED)" {
    if (!gate.aux_proofs_core_implemented) return error.SkipZigTest;

    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x636f6d706c657465); // "complete"
    const random = prng.random();

    const bits: usize = 128; // fast test size; production uses root.aux_modulus_bits
    const gen = try root.generateAuxParamsWithTrapdoor(allocator, random, bits);
    defer gen.trapdoor.deinit(allocator);

    const proof = try proveWellFormed(allocator, gen.params, gen.trapdoor, random);
    try verifyWellFormed(gen.params, proof);
}

// ── tamper (GATED — needs a valid proof to tamper) ──────────────────────

test "tamper: flipping a byte of w/x_i/z_i(mod)/A_i/z_i(prm) causes verifyWellFormed to reject (GATED)" {
    if (!gate.aux_proofs_core_implemented) return error.SkipZigTest;

    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x74616d706572); // "tamper"
    const random = prng.random();

    const bits: usize = 128;
    const gen = try root.generateAuxParamsWithTrapdoor(allocator, random, bits);
    defer gen.trapdoor.deinit(allocator);

    const proof = try proveWellFormed(allocator, gen.params, gen.trapdoor, random);
    try verifyWellFormed(gen.params, proof); // sanity: the honest proof accepts

    const nt = gen.params.n_tilde;

    // Flip Πmod's `w`.
    {
        var tampered = proof;
        var buf: [root.aux_modulus_bytes]u8 = undefined;
        tampered.mod.w.toBytes(&buf, .big) catch unreachable;
        buf[buf.len - 1] ^= 0x01;
        tampered.mod.w = root.AuxFe.fromBytes(nt, stripLeadingZeros(&buf), .big) catch unreachable;
        try testing.expectError(error.InvalidWellFormedProof, verifyWellFormed(gen.params, tampered));
    }
    // Flip Πmod's entries[0].x.
    {
        var tampered = proof;
        var buf: [root.aux_modulus_bytes]u8 = undefined;
        tampered.mod.entries[0].x.toBytes(&buf, .big) catch unreachable;
        buf[buf.len - 1] ^= 0x01;
        tampered.mod.entries[0].x = root.AuxFe.fromBytes(nt, stripLeadingZeros(&buf), .big) catch unreachable;
        try testing.expectError(error.InvalidWellFormedProof, verifyWellFormed(gen.params, tampered));
    }
    // Flip Πmod's entries[0].z.
    {
        var tampered = proof;
        var buf: [root.aux_modulus_bytes]u8 = undefined;
        tampered.mod.entries[0].z.toBytes(&buf, .big) catch unreachable;
        buf[buf.len - 1] ^= 0x01;
        tampered.mod.entries[0].z = root.AuxFe.fromBytes(nt, stripLeadingZeros(&buf), .big) catch unreachable;
        try testing.expectError(error.InvalidWellFormedProof, verifyWellFormed(gen.params, tampered));
    }
    // Flip Πprm's entries[0].a_commit.
    {
        var tampered = proof;
        var buf: [root.aux_modulus_bytes]u8 = undefined;
        tampered.prm.entries[0].a_commit.toBytes(&buf, .big) catch unreachable;
        buf[buf.len - 1] ^= 0x01;
        tampered.prm.entries[0].a_commit = root.AuxFe.fromBytes(nt, stripLeadingZeros(&buf), .big) catch unreachable;
        try testing.expectError(error.InvalidWellFormedProof, verifyWellFormed(gen.params, tampered));
    }
    // Flip Πprm's entries[0].z.
    {
        var tampered = proof;
        var buf: [root.aux_modulus_bytes]u8 = undefined;
        tampered.prm.entries[0].z.toBytes(&buf, .big) catch unreachable;
        buf[buf.len - 1] ^= 0x01;
        tampered.prm.entries[0].z = root.AuxFe.fromBytes(nt, stripLeadingZeros(&buf), .big) catch unreachable;
        try testing.expectError(error.InvalidWellFormedProof, verifyWellFormed(gen.params, tampered));
    }
}
