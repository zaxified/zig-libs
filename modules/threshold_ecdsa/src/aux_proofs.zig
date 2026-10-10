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
//! with `s = t^lambda mod N` and commits as `s^x·t^ρ`; this repo's
//! `root.zig` calls them `h1`, `h2` with the IDENTICAL relation `h1 =
//! h2^lambda mod n_tilde` and commitment `h1^x·h2^ρ` (see
//! `root.generateAuxParams`'s construction). Concretely: `s := aux.h1`,
//! `t := aux.h2`.
//!
//! ⚠ The direction is the security property. `h1 ∈ ⟨h2⟩` makes
//! `h1^x·h2^ρ = h2^{λx+ρ}`, which `ρ` masks. Until 2026-10-03 this module
//! had it reversed (`h2 = h1^λ`, proving `h2 ∈ ⟨h1⟩`), which a dishonest
//! tuple owner satisfies with `h2 = h1^M` for a smooth `M | ord(h1)`: the
//! commitment then fixes `x mod M` whatever `ρ` is, and Pohlig–Hellman
//! reads it off (Alpha-Rays/TSSHOCK class). Πmod does not stop it — Blum
//! primes may have smooth `(p̃−1)/2`. Every doc comment below uses `s`/`t` when quoting the
//! paper's equations and `h1`/`h2` when referring to this module's fields
//! — they are the SAME values.
//!
//! ## Soundness parameter
//!
//! Both proofs are `m`-round Fiat-Shamir Sigma protocols; `m` is a NAMED
//! CONSTANT below (`pi_mod_iterations`/`pi_prm_iterations`, both `128`),
//! giving soundness error `~2^-128` per proof (Πmod: each of `m`
//! independent `y_i` challenges catches a cheating prover with probability
//! `>= 1/2`; Πprm: each of `m` independent single-bit challenges catches a
//! cheating prover with probability `>= 1/2` — `(1/2)^128` for both).
//! Rounds of a 1-bit challenge rather than one wide challenge, since the
//! challenge cannot be widened past 1 bit/round without leaking structure.
//! Until 2026-10-03 `m` was CGGMP21's and tss-lib's `80`: a non-interactive
//! proof is GRINDABLE (the prover can re-roll its commitments offline until
//! the derived bits suit a false statement), so `2^-80` was an 80-bit
//! security level under a module that otherwise reads as ~128 (review F7).
//!
//! Zig std GAP: none new — `std.crypto.ff` (via `root.AuxModulus`/
//! `root.AuxFe`) and `std.crypto.hash.sha2.Sha256` (via `zkproofs
//! .Transcript`) are the only primitives this file needs.

const std = @import("std");
const root = @import("root.zig");
const zkproofs = @import("zkproofs.zig");
const montint = @import("montint");
const gate = @import("gate.zig");
const burn = @import("burn.zig");

// Dead-stack burns of the secret entry points (`burn.zig`), each a little
// above the depth its body reached in `stackprobe_test.zig` (ReleaseFast,
// x86_64, 2026-10-08; `verbose = true` prints the depths). The probe asserts
// that no secret survives, which a body outgrowing its burn would break.
const piprm_prove_stack_burn = 640 * 1024;
const piprm_prove_bound_stack_burn = 640 * 1024;
const pimod_prove_stack_burn = 640 * 1024;
const pimod_prove_bound_stack_burn = 640 * 1024;
const prove_paillier_stack_burn = 576 * 1024;
const prove_well_formed_stack_burn = 1280 * 1024;
const prove_well_formed_bound_stack_burn = 1280 * 1024;

const Sha256 = std.crypto.hash.sha2.Sha256;

/// Soundness parameter for Πmod (CGGMP21 Fig.16) — `m` independent
/// Fiat-Shamir challenges `y_1..y_m`, each catching a cheating prover with
/// probability `>= 1/2`; `(1/2)^128` soundness error (was 80, review F7).
pub const pi_mod_iterations: usize = 128;

/// Soundness parameter for Πprm (CGGMP21 Fig.17) — `m` independent
/// single-bit Fiat-Shamir challenges `e_1..e_m`; `(1/2)^128` soundness
/// error (was 80, review F7).
pub const pi_prm_iterations: usize = 128;

/// Domain-separation tag for Πmod's Fiat-Shamir seed — same
/// per-proof-kind domain-separation discipline as `zkproofs.zig`'s
/// `range_proof_domain`/`mta_proof_domain`/`mta_proof_wc_domain`.
pub const pi_mod_domain = "threshold_ecdsa/aux-proofs/pi-mod/v1";
/// Domain-separation tag for Πprm's Fiat-Shamir seed.
pub const pi_prm_domain = "threshold_ecdsa/aux-proofs/pi-prm/v1";
/// Πmod over a party's PAILIER modulus (dealer-free keygen) — a domain of
/// its own, so a proof about an aux `Ñ` can never pass as one about a
/// Paillier `N` or the other way round.
pub const pi_mod_paillier_domain = "threshold_ecdsa/aux-proofs/pi-mod-paillier/v1";
/// Πmod and Πprm over an aux `Ñ` BOUND to the prover's context (`session id
/// || prover index`, as every other proof in dealer-free keygen) — domains
/// of their own, so a bound proof never passes as an unbound one or back.
pub const pi_mod_bound_domain = "threshold_ecdsa/aux-proofs/pi-mod-bound/v1";
pub const pi_prm_bound_domain = "threshold_ecdsa/aux-proofs/pi-prm-bound/v1";

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
    // Subtractions, not `offset + len`: a u32 length added to a usize offset
    // wraps on 32-bit targets and would pass the bound.
    if (bytes.len - offset.* < 4) return error.InvalidEncoding;
    const len = std.mem.readInt(u32, bytes[offset.*..][0..4], .big);
    offset.* += 4;
    if (bytes.len - offset.* < len) return error.InvalidEncoding;
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

/// One length-prefixed field of a proof, held to the exact width `toBytesAlloc`
/// writes (`root.aux_modulus_bytes`), so each value has ONE encoding (review
/// F4: leading-zero variants used to decode to the same proof).
fn readFixedFe(n_tilde: root.AuxModulus, bytes: []const u8, offset: *usize) error{InvalidEncoding}!root.AuxFe {
    const field = readLenPrefixed(bytes, offset) catch return error.InvalidEncoding;
    if (field.len != root.aux_modulus_bytes) return error.InvalidEncoding;
    return root.AuxFe.fromBytes(n_tilde, stripLeadingZeros(field), .big) catch error.InvalidEncoding;
}

/// `a <= b` for canonical `AuxFe`s (public values; big-endian byte order).
fn auxFeLeq(a: root.AuxFe, b: root.AuxFe) bool {
    var ab: [root.aux_modulus_bytes]u8 = undefined;
    a.toBytes(&ab, .big) catch return false;
    var bb: [root.aux_modulus_bytes]u8 = undefined;
    b.toBytes(&bb, .big) catch return false;
    return std.mem.order(u8, &ab, &bb) != .gt;
}

/// `a < b` over little-endian limbs, without a branch on the values (the
/// borrow of `a − b`).
fn limbsLessCt(a: anytype, b: anytype) bool {
    var borrow: u1 = 0;
    for (a, b) |x, y| {
        const d1 = @subWithOverflow(x, y);
        const d2 = @subWithOverflow(d1[0], borrow);
        borrow = d1[1] | d2[1];
    }
    return borrow == 1;
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
        const w = try readFixedFe(n_tilde, bytes, &offset);

        var entries: [pi_mod_iterations]ModEntry = undefined;
        for (&entries) |*slot| {
            const x = try readFixedFe(n_tilde, bytes, &offset);
            const z = try readFixedFe(n_tilde, bytes, &offset);
            if (bytes.len < offset + 2) return error.InvalidEncoding;
            // One encoding per proof (review F4): flag bytes are 0 or 1.
            if (bytes[offset] > 1 or bytes[offset + 1] > 1) return error.InvalidEncoding;
            const a = bytes[offset] == 1;
            const b = bytes[offset + 1] == 1;
            offset += 2;
            slot.* = .{ .x = x, .z = z, .a = a, .b = b };
        }
        if (offset != bytes.len) return error.InvalidEncoding; // no trailing bytes (F4)
        return .{ .w = w, .entries = entries };
    }
};

// ── PrmProof — Πprm's proof object (STRUCT+CODEC real) ──────────────────

/// One of Πprm's `pi_prm_iterations` per-round responses (CGGMP21 Fig.17
/// step 1/3): `a_commit` is the round's first-message commitment `A_i =
/// t^{a_i} mod n_tilde`, `z` is the response `z_i = a_i + e_i*lambda mod
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
            const a_commit = try readFixedFe(n_tilde, bytes, &offset);
            const z = try readFixedFe(n_tilde, bytes, &offset);
            slot.* = .{ .a_commit = a_commit, .z = z };
        }
        if (offset != bytes.len) return error.InvalidEncoding; // no trailing bytes (F4)
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
fn deriveModSeed(binding: ModBinding, w: root.AuxFe) [32]u8 {
    switch (binding) {
        .aux => |aux| {
            var t = zkproofs.Transcript.init(pi_mod_domain);
            t.appendAuxParams(aux);
            t.appendAuxFe(w);
            return t.finalizeDigest();
        },
        .aux_bound => |ab| {
            var t = zkproofs.Transcript.init(pi_mod_bound_domain);
            t.appendContext(ab.context);
            t.appendAuxParams(ab.aux);
            t.appendAuxFe(w);
            return t.finalizeDigest();
        },
        .paillier => |pb| {
            var t = zkproofs.Transcript.init(pi_mod_paillier_domain);
            t.appendContext(pb.context);
            var n_buf: [root.aux_modulus_bytes]u8 = undefined;
            pb.n.toBytes(&n_buf, .big) catch unreachable; // fixed-width buffer always sufficient
            t.appendContext(&n_buf);
            t.appendAuxFe(w);
            return t.finalizeDigest();
        },
    }
}

/// What a Πmod transcript is bound to: an aux tuple (the original use, its
/// seed unchanged), or a Paillier modulus plus the caller's `context`
/// (`session id || prover index` in dealer-free keygen, so a proof can be
/// neither replayed into another session nor claimed by another party).
const ModBinding = union(enum) {
    aux: root.AuxParams,
    /// An aux tuple plus the prover's context: a copied `Ñ` with its proof
    /// does not verify under the copier's context.
    aux_bound: struct { aux: root.AuxParams, context: []const u8 },
    paillier: struct { n: root.AuxModulus, context: []const u8 },
};

/// Πmod's per-round challenge `y_i = FS(n_tilde, w, i) ∈ Z_n_tilde*`
/// (CGGMP21 Fig.16 step 2). Deterministic rejection sampling via
/// `expandChallenge` — mirrors `zkproofs.zig`'s `sampleBelow` rejection
/// shape but over a DETERMINISTIC (not random) byte stream, so prover and
/// verifier derive the IDENTICAL `y_i` from the same public `(aux, w)`.
/// `index` is 1-based (`1..=pi_mod_iterations`) to match the paper's `i`.
// secret-api-ok: `seed` is the public Fiat-Shamir digest of the (public) transcript, recomputed by
// the verifier; not secret material.
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
/// `A_i`, and — for a bound proof — the prover's `context` under a domain of
/// its own.
fn derivePrmSeed(aux: root.AuxParams, context: ?[]const u8, commitments: []const root.AuxFe) [32]u8 {
    var t = if (context) |c| blk: {
        var tb = zkproofs.Transcript.init(pi_prm_bound_domain);
        tb.appendContext(c);
        break :blk tb;
    } else zkproofs.Transcript.init(pi_prm_domain);
    t.appendAuxParams(aux);
    for (commitments) |a| t.appendAuxFe(a);
    return t.finalizeDigest();
}

/// Πprm's `pi_prm_iterations`-bit challenge `e ∈ {0,1}^m` (CGGMP21 Fig.17
/// step 2) — one deterministic expansion block, sliced into individual
/// bits (`m = 128 <= 256` fits inside a single `expandChallenge` call's
/// first block; the loop still handles `m > 256` correctly if the
/// soundness constant is ever widened).
// secret-api-ok: `seed` is the public Fiat-Shamir digest of the (public) transcript, recomputed by
// the verifier; not secret material.
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

/// The run-time montint modulus the Πmod prover works in (a factor of Ñ,
/// or Ñ itself).
const Ct = montint.DynModint(root.aux_modulus_bits);

/// One Blum-prime factor `r` of the prover's modulus as a SECRET montint
/// modulus, with the exponents the per-round steps need. Fail-closed on a
/// degenerate `r` (even, < 3): the modulus falls back to `nt`, yielding
/// garbage a correct verifier rejects.
const BlumCt = struct {
    m: Ct,
    /// `(r+1)/4` — the square-root exponent for `r ≡ 3 (mod 4)`.
    sqrt_e: Ct.Elem,
    /// `(r-1)/2` — Euler's criterion.
    leg_e: Ct.Elem,
    /// `r-2` — Fermat inversion.
    pm2: Ct.Elem,
    /// 1 iff `-1` is a non-residue mod `r`, i.e. `r ≡ 3 (mod 4)` (bit 1 of
    /// an odd `r`) — read off the value, no branch.
    nm1: u1,
    one: Ct.Elem,

    /// `r_be` is the secret factor's big-endian bytes. Its bit length is
    /// taken as `⌈bits(Ñ)/2⌉` — the public key size — so nothing scans the
    /// value for it; a factor of another length falls back to a scan
    /// (`fromBytesBE`), a degenerate one to `nt`.
    fn init(r_be: []const u8, nt: root.AuxModulus) BlumCt {
        var v = Ct.loadBE(r_be) catch Ct.zero;
        defer std.crypto.secureZero(u64, &v);
        const m = Ct.fromLimbsBits(&v, (nt.bits() + 1) / 2) catch
            Ct.fromBytesBE(r_be) catch (Ct.fromFf(nt) catch unreachable);
        var one = Ct.zero;
        one[0] = 1;
        var two = Ct.zero;
        two[0] = 2;
        var rp1 = m.m;
        _ = montint.limbs.addInto(&rp1, &one);
        var rm1 = m.m;
        _ = montint.limbs.subInto(&rm1, &one);
        var rm2 = m.m;
        _ = montint.limbs.subInto(&rm2, &two);
        defer std.crypto.secureZero(u64, &rp1);
        defer std.crypto.secureZero(u64, &rm1);
        return .{
            .m = m,
            .sqrt_e = shrElem(&rp1, 2),
            .leg_e = shrElem(&rm1, 1),
            .pm2 = rm2,
            .nm1 = @truncate(m.m[0] >> 1),
            .one = one,
        };
    }

    fn wipe(self: *BlumCt) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    /// 1 iff `c` is not a non-zero QR mod `r` (Euler's criterion,
    /// `c^((r-1)/2) ≠ 1`), constant-time. Returned as a bit for the caller
    /// to combine with bit operations, never to branch on.
    fn nonResidue(self: *const BlumCt, c: *const Ct.Elem) u1 {
        var l = self.m.pow(c, &self.leg_e);
        defer std.crypto.secureZero(u64, &l);
        return @intFromBool(!Ct.eql(&l, &self.one));
    }

    /// A 4th root of the QR `c` mod `r ≡ 3 (mod 4)`: `s = c^((r+1)/4)`, the
    /// QR one of `±s` (exactly one is, `-1` being a non-residue) picked by a
    /// constant-time select, then its square root again.
    fn fourthRoot(self: *const BlumCt, c: *const Ct.Elem) Ct.Elem {
        var s = self.m.pow(c, &self.sqrt_e);
        defer std.crypto.secureZero(u64, &s);
        var neg = self.m.neg(&s);
        defer std.crypto.secureZero(u64, &neg);
        var qr = Ct.select(self.nonResidue(&s) == 1, &neg, &s);
        defer std.crypto.secureZero(u64, &qr);
        return self.m.pow(&qr, &self.sqrt_e);
    }
};

/// `v >> k` over the limbs (`k < 64`), positions only.
fn shrElem(v: *const Ct.Elem, comptime k: u6) Ct.Elem {
    var out: Ct.Elem = undefined;
    for (&out, 0..) |*o, i| {
        const hi: u64 = if (i + 1 < v.len) v[i + 1] else 0;
        o.* = (v[i] >> k) | (hi << @intCast(64 - @as(u7, k)));
    }
    return out;
}

/// 1 iff `(-1)^a · w^b · y` is a QR mod one prime, from the three
/// non-residue bits — `ny ⊕ a·nm1 ⊕ b·nw = 0`.
inline fn qrBit(ny: u1, nm1: u1, nw: u1, a: u1, b: u1) u1 {
    return ~(ny ^ (a & nm1) ^ (b & nw));
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
    /// **Prover.** Proves `s = t^lambda mod n_tilde` (`s := aux.h1`,
    /// `t := aux.h2`) for a KNOWN `lambda`, i.e. that `s ∈ ⟨t⟩` — the
    /// message base lies in the subgroup the randomness base generates,
    /// which is what makes `s^x·t^ρ` hiding — WITHOUT revealing `lambda`.
    /// (It does NOT show `⟨s⟩ = ⟨t⟩`, and hiding does not need that.) Soundness `~2^-128` (`pi_prm_iterations` 1-bit rounds).
    ///
    /// Construction (prover knows `trapdoor.lambda` AND `phi(n_tilde) =
    /// (p̃-1)(q̃-1)`, computable from `trapdoor.p`/`.q`):
    ///
    /// ```text
    /// 1. For i in 1..=m: sample a_i <- Z_{phi(n_tilde)} uniformly,
    ///    compute A_i = t^{a_i} mod n_tilde.
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
        trapdoor: *const root.AuxTrapdoor,
        random: std.Random,
    ) ProveError!PrmProof {
        const result = proveUnburned(allocator, aux, trapdoor, random);
        burn.stack(piprm_prove_stack_burn);
        return result;
    }

    noinline fn proveUnburned(
        allocator: std.mem.Allocator,
        aux: root.AuxParams,
        trapdoor: *const root.AuxTrapdoor,
        random: std.Random,
    ) ProveError!PrmProof {
        return proveByValue(allocator, aux, trapdoor.*, random);
    }

    fn proveByValue(
        allocator: std.mem.Allocator,
        aux: root.AuxParams,
        trapdoor: root.AuxTrapdoor,
        random: std.Random,
    ) ProveError!PrmProof {
        return proveCtx(allocator, aux, trapdoor, null, random);
    }

    /// `prove`, bound to the prover's `context` (`session id || prover
    /// index`): verifies only under `verifyBound` with the same context.
    pub fn proveBound(
        allocator: std.mem.Allocator,
        aux: root.AuxParams,
        trapdoor: *const root.AuxTrapdoor,
        context: []const u8,
        random: std.Random,
    ) ProveError!PrmProof {
        const result = proveBoundUnburned(allocator, aux, trapdoor, context, random);
        burn.stack(piprm_prove_bound_stack_burn);
        return result;
    }

    noinline fn proveBoundUnburned(
        allocator: std.mem.Allocator,
        aux: root.AuxParams,
        trapdoor: *const root.AuxTrapdoor,
        context: []const u8,
        random: std.Random,
    ) ProveError!PrmProof {
        return proveBoundByValue(allocator, aux, trapdoor.*, context, random);
    }

    fn proveBoundByValue(
        allocator: std.mem.Allocator,
        aux: root.AuxParams,
        trapdoor: root.AuxTrapdoor,
        context: []const u8,
        random: std.Random,
    ) ProveError!PrmProof {
        return proveCtx(allocator, aux, trapdoor, context, random);
    }

    fn proveCtx(
        allocator: std.mem.Allocator,
        aux: root.AuxParams,
        trapdoor: root.AuxTrapdoor,
        context: ?[]const u8,
        random: std.Random,
    ) ProveError!PrmProof {
        const nt = aux.n_tilde;
        _ = allocator; // kept in the signature; nothing here allocates since 2026-10-03

        // φ(n_tilde) = (p̃−1)(q̃−1) from the trapdoor, on montint limbs: the
        // primes are SECRET and nothing below branches on them (until
        // 2026-10-03 this was std.math.big.int — `divFloor` on φ and λ,
        // a byte compare in the rejection loop). Degenerate factors are
        // substituted fail-closed by `BlumCt.init` — the resulting proof is
        // garbage a correct verifier rejects; an aux/trapdoor mismatch is a
        // caller bug per this function's contract.
        var pb = BlumCt.init(trapdoor.p, nt);
        defer pb.wipe();
        var qb = BlumCt.init(trapdoor.q, nt);
        defer qb.wipe();
        const ntc = Ct.fromFf(nt) catch unreachable; // odd, ≥ 3
        var phi: Ct.Elem = undefined;
        defer std.crypto.secureZero(u64, &phi);
        {
            var p1 = pb.m.m;
            p1[0] &= ~@as(u64, 1);
            defer std.crypto.secureZero(u64, &p1);
            var q1 = qb.m.m;
            q1[0] &= ~@as(u64, 1);
            defer std.crypto.secureZero(u64, &q1);
            var prod: [2 * Ct.max_limbs]u64 = undefined;
            defer std.crypto.secureZero(u64, &prod);
            montint.limbs.mulSchoolbook(&prod, &p1, &q1);
            phi = prod[0..Ct.max_limbs].*;
        }
        // λ < ord(h1) < φ (generateAuxParams); moved off ff positionally.
        var lam = Ct.elemFromFf(&trapdoor.lambda.v);
        defer std.crypto.secureZero(u64, &lam);

        // 1. Per-round nonce a_i <- Z_φ, uniform: draws below 2^bits(n_tilde)
        //    (public; φ has n_tilde's length up to one bit, so a draw is kept
        //    with probability ≥ 1/2), kept when the borrow of a_i − φ says
        //    a_i < φ — the accept verdict is the only branch, its count
        //    depends on φ/2^bits only. Commitment A_i = t^{a_i}
        //    (constant-time modexp — a_i masks λ).
        const n_bits = nt.bits();
        const n_len = byteLen(n_bits);
        var a_elems: [pi_prm_iterations]Ct.Elem = undefined;
        defer for (&a_elems) |*ae| std.crypto.secureZero(u64, ae);
        var a_buf: [root.aux_modulus_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &a_buf);
        var commitments: [pi_prm_iterations]root.AuxFe = undefined;
        const top_mask: u8 = @as(u8, 0xff) >> @intCast(8 * n_len - n_bits);
        for (&a_elems, &commitments) |*ae, *commit| {
            while (true) {
                random.bytes(a_buf[0..n_len]);
                a_buf[0] &= top_mask;
                ae.* = Ct.loadBE(a_buf[0..n_len]) catch unreachable; // ≤ aux_modulus_bytes
                var t = ae.*;
                defer std.crypto.secureZero(u64, &t);
                if (montint.limbs.subInto(&t, &phi) == 1) break; // a_i < φ
            }
            ntc.toBytesBE(ae, a_buf[0..n_len]);
            commit.* = zkproofs.powSecret(nt, aux.h2, a_buf[0..n_len]); // a_i = 0 -> t^0 = 1; ff's pow branches on secret windows
        }

        // 2. Fiat-Shamir bit-challenge — the REAL scaffold machinery above.
        const seed = derivePrmSeed(aux, context, &commitments);
        var e_bits: [pi_prm_iterations]bool = undefined;
        derivePrmChallengeBits(seed, &e_bits);

        // 3. Responses z_i = a_i + e_i·λ mod φ: a_i, λ < φ, so the sum is
        //    below 2φ and one masked subtraction of φ reduces it (the carry
        //    out of the top limb counts as "≥ φ"). e_i is public (the
        //    challenge), so its `if` is not a leak. z_i < φ < n_tilde, so
        //    the positional move into an n_tilde element is canonical.
        var entries: [pi_prm_iterations]PrmEntry = undefined;
        for (&entries, &a_elems, &commitments, e_bits) |*slot, *ae, commit, e_i| {
            var z = ae.*;
            defer std.crypto.secureZero(u64, &z);
            if (e_i) {
                const carry = montint.limbs.addInto(&z, &lam);
                var t = z;
                defer std.crypto.secureZero(u64, &t);
                const borrow = montint.limbs.subInto(&t, &phi);
                z = Ct.select((carry | (borrow ^ 1)) == 1, &t, &z); // z ≥ φ → z − φ
            }
            slot.* = .{ .a_commit = commit, .z = Ct.elemToFf(root.AuxFe, nt, &z) };
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
    ///      t^{z_i} == A_i * s^{e_i} (mod n_tilde)
    ///    (powWithEncodedPublicExponent — z_i/A_i/e_i are all PUBLIC
    ///    proof fields). Reject (return false) on ANY single failure.
    /// 4. Accept (return true) only if every round's equation holds.
    /// ```
    ///
    /// UNBOUND: the proof names no session or prover, so it can be replayed
    /// into any run. Never use it in keygen — there, `verifyBound` with the
    /// prover's context (review F8). Kept for standalone checks of a tuple.
    pub fn verify(aux: root.AuxParams, proof: PrmProof) bool {
        return verifyCtx(aux, null, proof);
    }

    /// `proveBound`'s counterpart; `context` must be the prover's.
    pub fn verifyBound(aux: root.AuxParams, context: []const u8, proof: PrmProof) bool {
        return verifyCtx(aux, context, proof);
    }

    fn verifyCtx(aux: root.AuxParams, context: ?[]const u8, proof: PrmProof) bool {
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
        const seed = derivePrmSeed(aux, context, &commitments);
        var e_bits: [pi_prm_iterations]bool = undefined;
        derivePrmChallengeBits(seed, &e_bits);

        // 3+4. Per-round equation t^{z_i} == A_i * s^{e_i} (mod n_tilde);
        //      reject on ANY single failure. t = h2 is the base: the
        //      equation shows s = h1 ∈ ⟨h2⟩ (module doc, "direction").
        for (proof.entries, e_bits) |e, e_i| {
            var z_buf: [root.aux_modulus_bytes]u8 = undefined;
            e.z.toBytes(&z_buf, .big) catch return false;
            const lhs = nt.powWithEncodedPublicExponent(aux.h2, stripLeadingZeros(&z_buf), .big) catch nt.one(); // z = 0 -> t^0 = 1
            const rhs = if (e_i) nt.mul(e.a_commit, aux.h1) else e.a_commit;
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
    /// `~2^-128` (`pi_mod_iterations` rounds, each catching a cheating
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
        trapdoor: *const root.AuxTrapdoor,
        random: std.Random,
    ) ProveError!ModProof {
        const result = proveUnburned(allocator, aux, trapdoor, random);
        burn.stack(pimod_prove_stack_burn);
        return result;
    }

    noinline fn proveUnburned(
        allocator: std.mem.Allocator,
        aux: root.AuxParams,
        trapdoor: *const root.AuxTrapdoor,
        random: std.Random,
    ) ProveError!ModProof {
        return proveByValue(allocator, aux, trapdoor.*, random);
    }

    fn proveByValue(
        allocator: std.mem.Allocator,
        aux: root.AuxParams,
        trapdoor: root.AuxTrapdoor,
        random: std.Random,
    ) ProveError!ModProof {
        return proveCore(allocator, aux.n_tilde, trapdoor.p, trapdoor.q, .{ .aux = aux }, random);
    }

    /// `prove`, bound to the prover's `context` (`session id || prover
    /// index`): verifies only under `verifyBound` with the same context.
    pub fn proveBound(
        allocator: std.mem.Allocator,
        aux: root.AuxParams,
        trapdoor: *const root.AuxTrapdoor,
        context: []const u8,
        random: std.Random,
    ) ProveError!ModProof {
        const result = proveBoundUnburned(allocator, aux, trapdoor, context, random);
        burn.stack(pimod_prove_bound_stack_burn);
        return result;
    }

    noinline fn proveBoundUnburned(
        allocator: std.mem.Allocator,
        aux: root.AuxParams,
        trapdoor: *const root.AuxTrapdoor,
        context: []const u8,
        random: std.Random,
    ) ProveError!ModProof {
        return proveBoundByValue(allocator, aux, trapdoor.*, context, random);
    }

    fn proveBoundByValue(
        allocator: std.mem.Allocator,
        aux: root.AuxParams,
        trapdoor: root.AuxTrapdoor,
        context: []const u8,
        random: std.Random,
    ) ProveError!ModProof {
        return proveCore(allocator, aux.n_tilde, trapdoor.p, trapdoor.q, .{ .aux_bound = .{ .aux = aux, .context = context } }, random);
    }

    /// **Prover, Paillier modulus.** The same proof for a party's own
    /// Paillier `N = p·q` (`p ≡ q ≡ 3 mod 4`, see `root.generatePaillierBlum`),
    /// bound to `context`. Together with `fac_proof` it is what lets the
    /// other parties trust an `N` they did not generate (CGGMP21 §4, Fig.16;
    /// the BitForge class without it). `p`/`q` are big-endian, SECRET.
    pub fn provePaillier(
        allocator: std.mem.Allocator,
        n: root.AuxModulus,
        p: []const u8,
        q: []const u8,
        context: []const u8,
        random: std.Random,
    ) ProveError!ModProof {
        const result = provePaillierUnburned(allocator, n, p, q, context, random);
        burn.stack(prove_paillier_stack_burn);
        return result;
    }

    noinline fn provePaillierUnburned(
        allocator: std.mem.Allocator,
        n: root.AuxModulus,
        p: []const u8,
        q: []const u8,
        context: []const u8,
        random: std.Random,
    ) ProveError!ModProof {
        return proveCore(allocator, n, p, q, .{ .paillier = .{ .n = n, .context = context } }, random);
    }

    fn proveCore(
        allocator: std.mem.Allocator,
        nt: root.AuxModulus,
        p_secret: []const u8,
        q_secret: []const u8,
        binding: ModBinding,
        random: std.Random,
    ) ProveError!ModProof {
        const n_len = byteLen(nt.bits());

        var nt_buf: [root.aux_modulus_bytes]u8 = undefined;
        nt.toBytes(&nt_buf, .big) catch unreachable; // fixed-width buffer always sufficient
        var n_big = try bigFromBytes(allocator, stripLeadingZeros(&nt_buf));
        defer n_big.deinit();

        // Per-factor constant-time contexts: the primes are SECRET moduli
        // (montint.DynModint), and every step below — φ and d, the Legendre
        // symbols, square roots, the CRT — runs on them without a branch on
        // their value. (Until 2026-10-02 this was big-int Jacobi symbols and
        // division plus std.crypto.ff pow modulo the secret factor; until
        // 2026-10-03 φ and d were big-int extended Euclid.) A degenerate
        // factor is substituted fail-closed inside `BlumCt.init` (garbage
        // proof a correct verifier rejects, never a panic/hang); an
        // aux/trapdoor mismatch is a caller bug per the contract.
        var pb = BlumCt.init(p_secret, nt);
        defer pb.wipe();
        var qb = BlumCt.init(q_secret, nt);
        defer qb.wipe();
        const ntc = Ct.fromFf(nt) catch unreachable; // odd, ≥ 3

        // 5's exponent: d = n_tilde^{-1} mod φ, φ = (p−1)(q−1) — SECRET
        // (factor-equivalent). p, q are odd, so p − 1 is p with bit 0
        // cleared. `inverseOfModulus` takes the even modulus φ; a fail-closed
        // d = 1 when gcd(n_tilde, φ) != 1 (an honest two-distinct-Blum-prime
        // trapdoor always inverts — that is exactly the property Πmod
        // establishes). A product wider than the element (only for the
        // substituted factors) is truncated: garbage, as above.
        var d_buf: [root.aux_modulus_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &d_buf);
        {
            var p1 = pb.m.m;
            p1[0] &= ~@as(u64, 1);
            defer std.crypto.secureZero(u64, &p1);
            var q1 = qb.m.m;
            q1[0] &= ~@as(u64, 1);
            defer std.crypto.secureZero(u64, &q1);
            var prod: [2 * Ct.max_limbs]u64 = undefined;
            defer std.crypto.secureZero(u64, &prod);
            montint.limbs.mulSchoolbook(&prod, &p1, &q1);
            var d: Ct.Elem = undefined;
            defer std.crypto.secureZero(u64, &d);
            const ok = ntc.inverseOfModulus(prod[0..Ct.max_limbs], &d);
            var one = Ct.zero;
            one[0] = 1;
            d = Ct.select(ok, &d, &one);
            ntc.toBytesBE(&d, &d_buf);
        }
        const d_bytes = d_buf[root.aux_modulus_bytes - n_len ..];
        // CRT constant q^{-1} mod p by Fermat (p prime) — constant-time,
        // unlike the extended Euclid it replaces.
        var qinv_p = pb.m.pow(&pb.m.reduceLimbs(qb.m.m[0..qb.m.L]), &pb.pm2);
        defer std.crypto.secureZero(u64, &qinv_p);

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

        // Non-residue bits of w per prime, computed once (w is public, its
        // characters modulo the secret primes are not).
        const w_el = Ct.elemFromFf(&w_fe.v);
        const nw_p = pb.nonResidue(&pb.m.reduceLimbs(w_el[0..ntc.L]));
        const nw_q = qb.nonResidue(&qb.m.reduceLimbs(w_el[0..ntc.L]));

        // 2. Fiat-Shamir challenges — the REAL scaffold machinery above.
        const seed = deriveModSeed(binding, w_fe);
        var entries: [pi_mod_iterations]ModEntry = undefined;

        for (&entries, 0..) |*slot, idx| {
            const y = deriveModChallenge(nt, seed, @intCast(idx + 1));

            // 3. Pick (a_i, b_i) making y' = (-1)^{a_i} w^{b_i} y_i a QR
            //    mod BOTH factors: the first of (0,0),(1,0),(0,1),(1,1) that
            //    works, chosen with bit operations on the secret
            //    per-prime characters. (a_i, b_i) themselves are published.
            //    Exactly one pair works for a genuine Blum modulus; (0,0)
            //    otherwise (garbage the verifier rejects).
            const y_el = Ct.elemFromFf(&y.v);
            const ny_p = pb.nonResidue(&pb.m.reduceLimbs(y_el[0..ntc.L]));
            const ny_q = qb.nonResidue(&qb.m.reduceLimbs(y_el[0..ntc.L]));
            const ok00 = qrBit(ny_p, pb.nm1, nw_p, 0, 0) & qrBit(ny_q, qb.nm1, nw_q, 0, 0);
            const ok10 = qrBit(ny_p, pb.nm1, nw_p, 1, 0) & qrBit(ny_q, qb.nm1, nw_q, 1, 0);
            const ok01 = qrBit(ny_p, pb.nm1, nw_p, 0, 1) & qrBit(ny_q, qb.nm1, nw_q, 0, 1);
            const ok11 = qrBit(ny_p, pb.nm1, nw_p, 1, 1) & qrBit(ny_q, qb.nm1, nw_q, 1, 1);
            const a_bit = (~ok00 & (ok10 | (~ok01 & ok11))) == 1;
            const b_bit = (~ok00 & ~ok10 & (ok01 | ok11)) == 1;

            var y_prime = y;
            if (b_bit) y_prime = nt.mul(w_fe, y_prime);
            if (a_bit) y_prime = nt.sub(nt.zero, y_prime);

            // 4. x_i = 4th root of y' — per-factor Blum roots + Garner CRT
            //    x = x_q + q * ((x_p - x_q) * q^{-1} mod p) < p*q, the last
            //    step mod n_tilde (exact: x < p*q = n_tilde).
            const c_el = Ct.elemFromFf(&y_prime.v);
            var xp = pb.fourthRoot(&pb.m.reduceLimbs(c_el[0..ntc.L]));
            defer std.crypto.secureZero(u64, &xp);
            var xq = qb.fourthRoot(&qb.m.reduceLimbs(c_el[0..ntc.L]));
            defer std.crypto.secureZero(u64, &xq);
            var h = pb.m.mul(&pb.m.sub(&xp, &pb.m.reduceLimbs(xq[0..qb.m.L])), &qinv_p);
            defer std.crypto.secureZero(u64, &h);
            var x_any = ntc.add(&xq, &ntc.mul(&qb.m.m, &h));
            defer std.crypto.secureZero(u64, &x_any);
            // Canonical root (review F4): of the pair {x, Ñ − x} publish the
            // smaller one, which the verifier enforces — anyone could flip a
            // published x to Ñ − x and get a second valid proof otherwise.
            // Selected without a branch: x derives from the secret factors.
            var x_neg = ntc.neg(&x_any);
            defer std.crypto.secureZero(u64, &x_neg);
            var x = Ct.select(limbsLessCt(&x_neg, &x_any), &x_neg, &x_any);
            defer std.crypto.secureZero(u64, &x);
            const x_fe = Ct.elemToFf(root.AuxFe, nt, &x);

            // 5. z_i = y_i^d (constant-time in the secret exponent d).
            const z_fe = zkproofs.powSecret(nt, y, d_bytes); // not ff's pow: it branches on secret windows

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
    ///
    /// UNBOUND: the proof names no session or prover, so it can be replayed
    /// into any run. Never use it in keygen — there, `verifyBound` /
    /// `verifyPaillier` with the prover's context (review F8).
    pub fn verify(aux: root.AuxParams, proof: ModProof) bool {
        return verifyCore(aux.n_tilde, .{ .aux = aux }, proof);
    }

    /// `proveBound`'s counterpart; `context` must be the prover's.
    pub fn verifyBound(aux: root.AuxParams, context: []const u8, proof: ModProof) bool {
        return verifyCore(aux.n_tilde, .{ .aux_bound = .{ .aux = aux, .context = context } }, proof);
    }

    /// **Verifier, Paillier modulus** — `provePaillier`'s counterpart.
    /// `context` must be the prover's (`session id || prover index`).
    pub fn verifyPaillier(n: root.AuxModulus, context: []const u8, proof: ModProof) bool {
        return verifyCore(n, .{ .paillier = .{ .n = n, .context = context } }, proof);
    }

    fn verifyCore(nt: root.AuxModulus, binding: ModBinding, proof: ModProof) bool {
        // The smallest Paillier-Blum modulus is 3·7 = 21 (5 bits). Below it
        // the Miller-Rabin witness range [2, N−2] is empty for N = 3 and
        // `randomWitness` would never return (review 2026-10-03 F2).
        if (nt.bits() < 5) return false;
        var nt_buf: [root.aux_modulus_bytes]u8 = undefined;
        nt.toBytes(&nt_buf, .big) catch return false;
        const n_bytes = stripLeadingZeros(&nt_buf);

        // 1. n_tilde must be an odd composite. Odd is structural (ff
        //    rejects even moduli); composite = Miller-Rabin with witnesses
        //    drawn from a PRNG seeded by H(n_tilde) — `verify` takes no
        //    CSPRNG parameter. Audit F9 (2026-09-10 doc fix): the witnesses
        //    are NOT outside the modulus-crafter's control — H(n_tilde) is
        //    a public, deterministic function of a candidate the crafter
        //    already holds, so nothing stops computing them offline for
        //    any n_tilde before submitting it. What actually carries this
        //    check is cost, not unpredictability: an honest PRIME survives
        //    only with probability <= 4^-rounds per witness (rounds = 64
        //    here, i.e. ~2^-128), so grinding for a prime whose SHA256-seeded
        //    witnesses all happen to miss it is exactly as expensive as
        //    guessing a witness blind would be. The per-round equations in
        //    step 3+ are the ones load-bearing against a chosen-witness
        //    attack in general (see the module's KAT with a genuinely
        //    3-prime modulus); this step alone would not be sound against
        //    an adversary who COULD predict the witnesses, but grinding one
        //    who cannot see them coming is not a smaller problem than
        //    factoring the near-miss.
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
        const seed = deriveModSeed(binding, proof.w);
        for (proof.entries, 0..) |e, idx| {
            const y = deriveModChallenge(nt, seed, @intCast(idx + 1));

            // gcd(y_i, n_tilde) = 1 (review F3): a challenge sharing a factor
            // with n_tilde is no member of Z_n_tilde*, and the per-round
            // equations below argue about units. Jacobi 0 <=> gcd > 1.
            {
                var scratch: [verify_scratch_bytes]u8 = undefined;
                var fba = std.heap.FixedBufferAllocator.init(&scratch);
                const gpa = fba.allocator();
                const yb = bigFromFe(gpa, y) catch return false;
                const nb = bigFromBytes(gpa, n_bytes) catch return false;
                if ((jacobiBig(gpa, &yb, &nb) catch return false) == 0) return false;
            }

            // Canonical root (review F4): x <= n_tilde − x, so a third party
            // cannot turn one valid proof into a second by negating x.
            if (!auxFeLeq(e.x, nt.sub(nt.zero, e.x))) return false;

            // z_i^{n_tilde} == y_i — forces gcd(n_tilde, phi(n_tilde)) = 1
            // (the n-th-power map must be a bijection on Z_n_tilde*).
            const zn = nt.powWithEncodedPublicExponent(e.z, n_bytes, .big) catch return false;
            if (!auxFeEql(zn, y)) return false;

            // x_i^4 == (-1)^{a_i} w^{b_i} y_i — forces the Blum structure
            // (4th roots of a full QR-class cover exist only when both
            // prime factors are ≡ 3 mod 4; a 3-prime or prime-power
            // n_tilde fails this with overwhelming probability across the
            // `pi_mod_iterations` rounds).
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

pub const VerifyError = error{
    InvalidWellFormedProof,
    /// `AuxParams.validate` refused the tuple (structural floor, including
    /// `Ñ > q⁷`) — checked by `verifyWellFormed` itself (audit F10).
    InvalidAuxParams,
};

/// Generator-side: produce BOTH proofs-of-correct-generation for `aux`,
/// using the retained trapdoor (`root.generateAuxParamsWithTrapdoor`).
pub fn proveWellFormed(
    allocator: std.mem.Allocator,
    aux: root.AuxParams,
    trapdoor: *const root.AuxTrapdoor,
    random: std.Random,
) ProveError!WellFormedProof {
    const result = proveWellFormedUnburned(allocator, aux, trapdoor, random);
    burn.stack(prove_well_formed_stack_burn);
    return result;
}

noinline fn proveWellFormedUnburned(
    allocator: std.mem.Allocator,
    aux: root.AuxParams,
    trapdoor: *const root.AuxTrapdoor,
    random: std.Random,
) ProveError!WellFormedProof {
    return proveWellFormedByValue(allocator, aux, trapdoor.*, random);
}

fn proveWellFormedByValue(
    allocator: std.mem.Allocator,
    aux: root.AuxParams,
    trapdoor: root.AuxTrapdoor,
    random: std.Random,
) ProveError!WellFormedProof {
    return .{
        .prm = try Piprm.prove(allocator, aux, &trapdoor, random),
        .mod = try Pimod.prove(allocator, aux, &trapdoor, random),
    };
}

/// `proveWellFormed`, both proofs bound to the prover's `context`
/// (`session id || prover index`) — what dealer-free keygen broadcasts, so a
/// party cannot copy another's `Ñ` together with its proofs.
pub fn proveWellFormedBound(
    allocator: std.mem.Allocator,
    aux: root.AuxParams,
    trapdoor: *const root.AuxTrapdoor,
    context: []const u8,
    random: std.Random,
) ProveError!WellFormedProof {
    const result = proveWellFormedBoundUnburned(allocator, aux, trapdoor, context, random);
    burn.stack(prove_well_formed_bound_stack_burn);
    return result;
}

noinline fn proveWellFormedBoundUnburned(
    allocator: std.mem.Allocator,
    aux: root.AuxParams,
    trapdoor: *const root.AuxTrapdoor,
    context: []const u8,
    random: std.Random,
) ProveError!WellFormedProof {
    return proveWellFormedBoundByValue(allocator, aux, trapdoor.*, context, random);
}

fn proveWellFormedBoundByValue(
    allocator: std.mem.Allocator,
    aux: root.AuxParams,
    trapdoor: root.AuxTrapdoor,
    context: []const u8,
    random: std.Random,
) ProveError!WellFormedProof {
    return .{
        .prm = try Piprm.proveBound(allocator, aux, &trapdoor, context, random),
        .mod = try Pimod.proveBound(allocator, aux, &trapdoor, context, random),
    };
}

/// Validator-side: decide whether a RECEIVED `aux` tuple can be trusted —
/// `aux.validate(random)` (the structural floor, including `Ñ > q⁷`) and
/// then BOTH proofs-of-correct-generation. Fail-closed: any refusal rejects
/// the WHOLE tuple. `random` feeds `validate`'s Miller-Rabin and MUST be a
/// real CSPRNG.
///
/// Audit F10: this used to verify only the two proofs and leave `validate`
/// to the caller by doc comment ("call this IN ADDITION TO `validate`") —
/// yet it is the one function whose job is to make a received tuple
/// trustworthy, and Πprm/Πmod hold over a toy modulus far below the floor
/// (tested: an honest 128-bit tuple with its honest proof).
pub fn verifyWellFormed(aux: root.AuxParams, proof: WellFormedProof, random: std.Random) VerifyError!void {
    aux.validate(random) catch return error.InvalidAuxParams;
    try verifyProofs(aux, proof);
}

/// `verifyWellFormed` for `proveWellFormedBound`; `context` must be the
/// prover's.
pub fn verifyWellFormedBound(aux: root.AuxParams, context: []const u8, proof: WellFormedProof, random: std.Random) VerifyError!void {
    aux.validate(random) catch return error.InvalidAuxParams;
    if (!Piprm.verifyBound(aux, context, proof.prm)) return error.InvalidWellFormedProof;
    if (!Pimod.verifyBound(aux, context, proof.mod)) return error.InvalidWellFormedProof;
}

/// The two proofs alone, without `validate` — for the proof tests, which
/// run over tuples too small to pass the floor.
fn verifyProofs(aux: root.AuxParams, proof: WellFormedProof) error{InvalidWellFormedProof}!void {
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
    const seed = deriveModSeed(.{ .aux = aux }, w);

    const y1 = deriveModChallenge(nt, seed, 1);
    const y1_again = deriveModChallenge(nt, seed, 1);
    try testing.expect(y1.eql(y1_again));

    const y2 = deriveModChallenge(nt, seed, 2);
    try testing.expect(!y1.eql(y2));

    // Different seed (different w) -> different challenge at the same index.
    const seed2 = deriveModSeed(.{ .aux = aux }, toyFe(nt, 25));
    const y1_other_seed = deriveModChallenge(nt, seed2, 1);
    try testing.expect(!y1.eql(y1_other_seed));
}

test "derivePrmChallengeBits: deterministic, not degenerate (ungated)" {
    const nt = toyModulus();
    const aux: root.AuxParams = .{ .n_tilde = nt, .h1 = toyFe(nt, 5), .h2 = toyFe(nt, 25) };
    var commitments: [pi_prm_iterations]root.AuxFe = undefined;
    for (&commitments, 0..) |*c, i| c.* = toyFe(nt, @intCast(2 + i % 90));

    const seed = derivePrmSeed(aux, null, &commitments);
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
    const seed3 = derivePrmSeed(aux, null, &commitments);
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

    const maybe_proof = Pimod.prove(allocator, aux, &fake_trapdoor, random);
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

// ── F1 soundness scenario (b): h1 outside <h2> ──────────────────────────

/// A genuine ~2000-bit odd composite (two ~1000-bit comptime factors —
/// same construction `root.zig`'s own F1/F2 `validate` test uses for its
/// `nt_ok`) with `h1 = 4 = 2^2`, `h2 = 9 = 3^2`: both perfect squares
/// (hence Jacobi `+1`, hence `AuxParams.validate` accepts), but nothing
/// ties `4` to a power of `9` mod this modulus — `h1` is (with
/// overwhelming likelihood) NOT in the cyclic subgroup `<h2>`, exactly
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

test "F1 soundness (b) — h1 outside <h2>: AuxParams.validate() ACCEPTS it (documents the gap, ungated)" {
    var prng = std.Random.DefaultPrng.init(0x6f75747369646562); // "outsideb"
    const random = prng.random();

    const aux = outsideSubgroupAux();
    try aux.validate(random); // ACCEPTS — this is the gap Πprm closes.
}

test "F1 soundness (b) — h1 outside <h2>: Piprm.verify REJECTS it (documents the fix, GATED)" {
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
    var gen: root.AuxParamsWithTrapdoor = undefined;
    try root.generateAuxParamsWithTrapdoor(allocator, random, bits, &gen);
    defer gen.trapdoor.deinit(allocator);

    const proof = try proveWellFormed(allocator, gen.params, &gen.trapdoor, random);
    try verifyProofs(gen.params, proof);
}

test "bound Πprm/Πmod over Ñ: verify only under the prover's context, never as unbound (GATED)" {
    if (!gate.aux_proofs_core_implemented) return error.SkipZigTest;

    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x626f756e64); // "bound"
    const random = prng.random();
    var gen: root.AuxParamsWithTrapdoor = undefined;
    try root.generateAuxParamsWithTrapdoor(allocator, random, 128, &gen);
    defer gen.trapdoor.deinit(allocator);
    const aux = gen.params;
    const ctx_a = "session-7" ++ [_]u8{ 0, 0, 0, 1 };
    const ctx_b = "session-7" ++ [_]u8{ 0, 0, 0, 2 };

    const prm = try Piprm.proveBound(allocator, aux, &gen.trapdoor, ctx_a, random);
    try testing.expect(Piprm.verifyBound(aux, ctx_a, prm));
    try testing.expect(!Piprm.verifyBound(aux, ctx_b, prm));
    try testing.expect(!Piprm.verify(aux, prm));
    const mod = try Pimod.proveBound(allocator, aux, &gen.trapdoor, ctx_a, random);
    try testing.expect(Pimod.verifyBound(aux, ctx_a, mod));
    try testing.expect(!Pimod.verifyBound(aux, ctx_b, mod));
    try testing.expect(!Pimod.verify(aux, mod));
    // …and an unbound proof does not pass as a bound one.
    const unbound = try proveWellFormed(allocator, aux, &gen.trapdoor, random);
    try testing.expect(!Piprm.verifyBound(aux, ctx_a, unbound.prm));
    try testing.expect(!Pimod.verifyBound(aux, ctx_a, unbound.mod));
}

// ── tamper (GATED — needs a valid proof to tamper) ──────────────────────

test "tamper: flipping a byte of w/x_i/z_i(mod)/A_i/z_i(prm) causes verifyWellFormed to reject (GATED)" {
    if (!gate.aux_proofs_core_implemented) return error.SkipZigTest;

    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x74616d706572); // "tamper"
    const random = prng.random();

    const bits: usize = 128;
    var gen: root.AuxParamsWithTrapdoor = undefined;
    try root.generateAuxParamsWithTrapdoor(allocator, random, bits, &gen);
    defer gen.trapdoor.deinit(allocator);

    const proof = try proveWellFormed(allocator, gen.params, &gen.trapdoor, random);
    try verifyProofs(gen.params, proof); // sanity: the honest proof accepts

    const nt = gen.params.n_tilde;

    // Flip Πmod's `w`.
    {
        var tampered = proof;
        var buf: [root.aux_modulus_bytes]u8 = undefined;
        tampered.mod.w.toBytes(&buf, .big) catch unreachable;
        buf[buf.len - 1] ^= 0x01;
        tampered.mod.w = root.AuxFe.fromBytes(nt, stripLeadingZeros(&buf), .big) catch unreachable;
        try testing.expectError(error.InvalidWellFormedProof, verifyProofs(gen.params, tampered));
    }
    // Review F4: the negated root Ñ − x satisfies x⁴ just the same; only the
    // canonical-root rule refuses it, so a third party cannot re-mint a proof.
    {
        var tampered = proof;
        tampered.mod.entries[0].x = nt.sub(nt.zero, proof.mod.entries[0].x);
        try testing.expect(nt.sq(nt.sq(tampered.mod.entries[0].x)).eql(nt.sq(nt.sq(proof.mod.entries[0].x))));
        try testing.expectError(error.InvalidWellFormedProof, verifyProofs(gen.params, tampered));
    }
    // Review F4: one encoding per proof — no trailing byte, flag bytes 0/1,
    // fields at their full width.
    {
        const bytes = try proof.mod.toBytesAlloc(allocator);
        defer allocator.free(bytes);
        _ = try ModProof.fromBytesAlloc(nt, bytes);
        const longer = try std.mem.concat(allocator, u8, &.{ bytes, &[_]u8{0} });
        defer allocator.free(longer);
        try testing.expectError(error.InvalidEncoding, ModProof.fromBytesAlloc(nt, longer));
        const flag_at = 4 + root.aux_modulus_bytes + 2 * (4 + root.aux_modulus_bytes); // entries[0].a
        try testing.expect(bytes[flag_at] <= 1);
        const flagged = try allocator.dupe(u8, bytes);
        defer allocator.free(flagged);
        flagged[flag_at] = 2;
        try testing.expectError(error.InvalidEncoding, ModProof.fromBytesAlloc(nt, flagged));
        // w re-encoded one byte narrower (its top byte is zero for a 128-bit Ñ).
        const narrow = try allocator.alloc(u8, bytes.len - 1);
        defer allocator.free(narrow);
        std.mem.writeInt(u32, narrow[0..4], root.aux_modulus_bytes - 1, .big);
        @memcpy(narrow[4..], bytes[5..]);
        try testing.expectError(error.InvalidEncoding, ModProof.fromBytesAlloc(nt, narrow));

        const prm_bytes = try proof.prm.toBytesAlloc(allocator);
        defer allocator.free(prm_bytes);
        _ = try PrmProof.fromBytesAlloc(nt, prm_bytes);
        const prm_longer = try std.mem.concat(allocator, u8, &.{ prm_bytes, &[_]u8{0} });
        defer allocator.free(prm_longer);
        try testing.expectError(error.InvalidEncoding, PrmProof.fromBytesAlloc(nt, prm_longer));
    }
    // Flip Πmod's entries[0].x.
    {
        var tampered = proof;
        var buf: [root.aux_modulus_bytes]u8 = undefined;
        tampered.mod.entries[0].x.toBytes(&buf, .big) catch unreachable;
        buf[buf.len - 1] ^= 0x01;
        tampered.mod.entries[0].x = root.AuxFe.fromBytes(nt, stripLeadingZeros(&buf), .big) catch unreachable;
        try testing.expectError(error.InvalidWellFormedProof, verifyProofs(gen.params, tampered));
    }
    // Flip Πmod's entries[0].z.
    {
        var tampered = proof;
        var buf: [root.aux_modulus_bytes]u8 = undefined;
        tampered.mod.entries[0].z.toBytes(&buf, .big) catch unreachable;
        buf[buf.len - 1] ^= 0x01;
        tampered.mod.entries[0].z = root.AuxFe.fromBytes(nt, stripLeadingZeros(&buf), .big) catch unreachable;
        try testing.expectError(error.InvalidWellFormedProof, verifyProofs(gen.params, tampered));
    }
    // Flip Πprm's entries[0].a_commit.
    {
        var tampered = proof;
        var buf: [root.aux_modulus_bytes]u8 = undefined;
        tampered.prm.entries[0].a_commit.toBytes(&buf, .big) catch unreachable;
        buf[buf.len - 1] ^= 0x01;
        tampered.prm.entries[0].a_commit = root.AuxFe.fromBytes(nt, stripLeadingZeros(&buf), .big) catch unreachable;
        try testing.expectError(error.InvalidWellFormedProof, verifyProofs(gen.params, tampered));
    }
    // Flip Πprm's entries[0].z.
    {
        var tampered = proof;
        var buf: [root.aux_modulus_bytes]u8 = undefined;
        tampered.prm.entries[0].z.toBytes(&buf, .big) catch unreachable;
        buf[buf.len - 1] ^= 0x01;
        tampered.prm.entries[0].z = root.AuxFe.fromBytes(nt, stripLeadingZeros(&buf), .big) catch unreachable;
        try testing.expectError(error.InvalidWellFormedProof, verifyProofs(gen.params, tampered));
    }
}

// ── audit F8: ModProof/PrmProof.fromBytesAlloc had no fuzz coverage —
//    the two remaining decoders of the twelve the audit counted (with
//    `RangeProof`/`MtaProof`/`MtaProofWc` from `zkproofs.zig`, closed
//    alongside this). Both take a modulus context but do not allocate
//    (fixed-size `entries` arrays), so the fixture is just the same toy
//    8-bit `n_tilde` `root.zig`'s own `toyAuxParams`/this file's decoder
//    fixture in `zkproofs.zig` both use — no Paillier key needed here. ──

// ── audit F10: verifyWellFormed enforces validate itself ────────────────

/// Two 1024-bit SAFE primes for a real ring-Pedersen tuple above the `q⁷`
/// floor, generated once with `openssl prime -generate -safe -bits 1024`
/// and checked independently (`p` and `(p-1)/2` prime, `p ≡ 3 mod 4`,
/// distinct, product 2048 bits). Searching for safe primes this size in a
/// test takes minutes; the tuple built from them below is what the test
/// needs, not the search.
const floor_p_hex = "e8b9d6a3adc7c356c8dc34ffac5c310c26f00d339da9d4d29a3242df890a8b3cb99621e9a5d9b7b2a2dda75cc47080dfa428ff071f2903bdf7e1cf9b63a6703a1faba133533045cd2d586c96f58ce9dddcc758f0eed9a26dd4f39d63ea6e95d1d602ac84de4a4b6cf3282aaf63499c03e8516bdd687f9edef9bfb59e406f7f27";
const floor_q_hex = "d8b302a58e7c2892e3da8d73f56ebae0e4500b2ba96ec204744bf9a36457c881cd250e64f64324d8449678f54d11525a7ddaa66e3d883bcee543e5fba24ca57e227b630d1ef07860a60234f364b0b63877b3082d45c03fb69c86d38ee4f5754069e3d4c88d268ccb2f8185f2627ab4020fda8ab65951980adcc4843dc244a52f";

/// `(Ñ = p̃·q̃, h2 = r², h1 = h2^λ)` with its trapdoor, the shape
/// `root.generateAuxParamsWithTrapdoor` produces, from the fixed primes.
/// `λ` is a random 256-bit value: any `λ ∈ [1, p'·q')` is honest, and
/// `p'·q' ≈ 2^2046`.
fn floorAuxWithTrapdoor(allocator: std.mem.Allocator, random: std.Random) !root.AuxParamsWithTrapdoor {
    const p = try allocator.alloc(u8, floor_p_hex.len / 2);
    errdefer allocator.free(p);
    _ = try std.fmt.hexToBytes(p, floor_p_hex);
    const q = try allocator.alloc(u8, floor_q_hex.len / 2);
    errdefer allocator.free(q);
    _ = try std.fmt.hexToBytes(q, floor_q_hex);

    var bp = try bigFromBytes(allocator, p);
    defer bp.deinit();
    var bq = try bigFromBytes(allocator, q);
    defer bq.deinit();
    var bn = try newBig(allocator);
    defer bn.deinit();
    try bn.mul(&bp, &bq);
    var n_buf: [root.aux_modulus_bytes]u8 = undefined;
    bn.toConst().writeTwosComplement(&n_buf, .big);
    const n_tilde = try root.AuxModulus.fromBytes(stripLeadingZeros(&n_buf), .big);

    const h2 = n_tilde.sq(sampleNonzeroLtModulus(n_tilde, random));
    var lam: [32]u8 = undefined;
    random.bytes(&lam);
    lam[0] |= 0x80;
    const lambda = try root.AuxFe.fromBytes(n_tilde, &lam, .big);
    const h1 = try n_tilde.pow(h2, lambda);
    return .{
        .params = .{ .n_tilde = n_tilde, .h1 = h1, .h2 = h2 },
        .trapdoor = .{ .p = p, .q = q, .lambda = lambda },
    };
}

test "F10: an honest proof over a tuple below the q⁷ floor passes the proofs but verifyWellFormed refuses the tuple" {
    if (!gate.aux_proofs_core_implemented) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xF10_0001);
    const random = prng.random();

    var gen: root.AuxParamsWithTrapdoor = undefined;

    try root.generateAuxParamsWithTrapdoor(allocator, random, 128, &gen);
    defer gen.trapdoor.deinit(allocator);
    const proof = try proveWellFormed(allocator, gen.params, &gen.trapdoor, random);

    try verifyProofs(gen.params, proof); // Πprm and Πmod both hold …
    try testing.expectError(error.InvalidAuxParams, gen.params.validate(random)); // … over a tuple validate refuses
    try testing.expectError(error.InvalidAuxParams, verifyWellFormed(gen.params, proof, random));
}

test "F10: verifyWellFormed accepts an honest tuple above the q⁷ floor, and still refuses a tampered proof for it" {
    // 2048-bit Πprm/Πmod: skipped only in Debug, like zkproofs.zig's 2048-bit
    // fixtures (this module is `heavy`, so the default lane is ReleaseSafe).
    if (@import("builtin").mode == .Debug) return error.SkipZigTest;
    if (!gate.aux_proofs_core_implemented) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xF10_0002);
    const random = prng.random();

    const gen = try floorAuxWithTrapdoor(allocator, random);
    defer gen.trapdoor.deinit(allocator);
    try gen.params.validate(random); // the fixture itself clears the floor
    const proof = try proveWellFormed(allocator, gen.params, &gen.trapdoor, random);
    try verifyWellFormed(gen.params, proof, random);

    var tampered = proof;
    var buf: [root.aux_modulus_bytes]u8 = undefined;
    tampered.prm.entries[0].z.toBytes(&buf, .big) catch unreachable;
    buf[buf.len - 1] ^= 0x01;
    tampered.prm.entries[0].z = root.AuxFe.fromBytes(gen.params.n_tilde, stripLeadingZeros(&buf), .big) catch unreachable;
    try testing.expectError(error.InvalidWellFormedProof, verifyWellFormed(gen.params, tampered, random));
}

// ── audit F4(b)/(c) (2026-09-16): the two input guards no per-round
//    equation stands in for. Each test builds a proof whose every round
//    holds, so deleting the guard is the only way it can be accepted. ──

/// Value of an `AuxFe` over the one-byte toy modulus.
fn toyInt(fe: root.AuxFe) u64 {
    var buf: [root.aux_modulus_bytes]u8 = undefined;
    fe.toBytes(&buf, .big) catch unreachable;
    return buf[buf.len - 1];
}

fn powModSmall(base: u64, exp: u64, m: u64) u64 {
    var r: u64 = 1 % m;
    var b = base % m;
    var e = exp;
    while (e > 0) : (e >>= 1) {
        if (e & 1 == 1) r = r * b % m;
        b = b * b % m;
    }
    return r;
}

test "audit F4(b): Pimod.verify's Jacobi guard alone refuses a non-unit w that forges a proof for a non-Blum modulus" {
    // Ñ = 187 = 11·17 with 17 ≡ 1 (mod 4) is NOT Paillier-Blum, yet
    // gcd(187, φ = 160) = 1, so every y has the Ñ-th root z = y^83 and the
    // z-equation holds in every round. With w ≡ 0 (mod 17) and b_i = 1 the
    // x-equation holds too: x ≡ 0 (mod 17), and mod 11 (≡ 3 mod 4) one of
    // ±w·y is a square, and every square is a 4th power. A prover knowing
    // the factors answers every round; only `(w/Ñ) = −1` — which is 0 for
    // a non-unit w — refuses it. CGGMP21 Fig.16 picks w with Jacobi −1.
    const nt = toyModulus();
    const aux: root.AuxParams = .{ .n_tilde = nt, .h1 = toyFe(nt, 4), .h2 = toyFe(nt, 16) };
    const n: u64 = 187;
    const d: u64 = 83;
    try testing.expectEqual(@as(u64, 1), (n * d) % 160);

    for ([_]u8{ 0, 17 }) |w_val| {
        const w = toyFe(nt, w_val);
        const seed = deriveModSeed(.{ .aux = aux }, w);
        var entries: [pi_mod_iterations]ModEntry = undefined;
        for (&entries, 0..) |*e, idx| {
            const y = toyInt(deriveModChallenge(nt, seed, @intCast(idx + 1)));
            const wy = (@as(u64, w_val) * y) % n;
            var found: ?ModEntry = null;
            search: for ([_]bool{ false, true }) |a| {
                const rhs = if (a) (n - wy) % n else wy;
                var x: u64 = 0;
                while (x < n) : (x += 1) {
                    if (powModSmall(x, 4, n) == rhs) {
                        found = .{ .x = toyFe(nt, @intCast(x)), .z = toyFe(nt, @intCast(powModSmall(y, d, n))), .a = a, .b = true };
                        break :search;
                    }
                }
            }
            e.* = found orelse return error.TestFixtureHasNoFourthRoot;
        }
        try testing.expect(!Pimod.verify(aux, .{ .w = w, .entries = entries }));
    }
}

/// A hand-built Πprm proof over the toy Ñ = 187 that `base^{z_i} = A_i ·
/// other^{e_i}` with `other = base^log`: the honest prover's arithmetic
/// without reducing mod φ (`z_i = a_i + e_i·log` stays below 187).
fn toyPrmProof(aux: root.AuxParams, base: u64, log: u64) PrmProof {
    const nt = aux.n_tilde;
    var commitments: [pi_prm_iterations]root.AuxFe = undefined;
    var a_vals: [pi_prm_iterations]u64 = undefined;
    for (&commitments, &a_vals, 0..) |*c, *a, i| {
        a.* = 1 + (i * 37) % 150;
        c.* = toyFe(nt, @intCast(powModSmall(base, a.*, 187)));
    }
    var e_bits: [pi_prm_iterations]bool = undefined;
    derivePrmChallengeBits(derivePrmSeed(aux, null, &commitments), &e_bits);
    var entries: [pi_prm_iterations]PrmEntry = undefined;
    for (&entries, commitments, a_vals, e_bits) |*e, c, a, e_i| {
        e.* = .{ .a_commit = c, .z = toyFe(nt, @intCast(a + if (e_i) log else 0)) };
    }
    return .{ .entries = entries };
}

test "review 2026-10-03 F1: Πprm proves h1 ∈ ⟨h2⟩ — a proof of h2 ∈ ⟨h1⟩ over a tuple with [⟨h1⟩:⟨h2⟩] = 5 is refused" {
    // Ñ = 187: 3 has order 80, 3^5 = 56 has order 16. The tuple (h1 = 3,
    // h2 = 56) is the attack shape: h2 = h1^5, h1 ∉ ⟨h2⟩. Until 2026-10-03
    // the verifier checked h1^{z} = A·h2^{e} and accepted the owner's proof
    // of it (λ = 5) — while every commitment c = h1^x·h2^ρ gives x mod 5
    // away: c^16 = h1^{16x} (ord h2 = 16) and h1^16 has order 5.
    const n: u64 = 187;
    for (0..80) |x| for (0..16) |rho| {
        const c = powModSmall(3, x, n) * powModSmall(56, rho, n) % n;
        try testing.expectEqual(powModSmall(3, 16 * (x % 5), n), powModSmall(c, 16, n));
    };

    const nt = toyModulus();
    const attack: root.AuxParams = .{ .n_tilde = nt, .h1 = toyFe(nt, 3), .h2 = toyFe(nt, 56) };
    // The reversed-relation proof (base h1, log 5) is what the old verifier took.
    try testing.expect(!Piprm.verify(attack, toyPrmProof(attack, 3, 5)));

    // Positive control, same machinery: h2 = 3 (order 80), h1 = 3^7 ∈ ⟨h2⟩,
    // proof with base h2 and log 7 — the honest direction verifies.
    const honest: root.AuxParams = .{ .n_tilde = nt, .h1 = toyFe(nt, @intCast(powModSmall(3, 7, n))), .h2 = toyFe(nt, 3) };
    try testing.expect(Piprm.verify(honest, toyPrmProof(honest, 3, 7)));
}

test "review 2026-10-03 F2: Pimod.verify refuses Ñ = 3 instead of looping in the witness draw" {
    // AuxModulus accepts any odd value ≥ 3 and the wire codec parses one;
    // Miller-Rabin's witness range [2, N−2] is empty for N = 3.
    const nt = try root.AuxModulus.fromBytes(&[_]u8{3}, .big);
    const aux: root.AuxParams = .{ .n_tilde = nt, .h1 = toyFe(nt, 2), .h2 = toyFe(nt, 2) };
    var entries: [pi_mod_iterations]ModEntry = undefined;
    for (&entries) |*e| e.* = .{ .x = toyFe(nt, 1), .z = toyFe(nt, 1), .a = false, .b = false };
    try testing.expect(!Pimod.verify(aux, .{ .w = toyFe(nt, 2), .entries = entries }));
}

test "audit F4(c): Piprm.verify's h in {0,1} guard alone refuses a degenerate tuple whose proof is otherwise honest" {
    // h1 = s = 1 makes `s = t^λ` TRUE for λ = 0, so the honest prover
    // (A_i = t^{a_i}, z_i = a_i) passes every round — and a Pedersen
    // commitment h1^m·h2^ρ = h2^ρ under that tuple binds nothing. With
    // h1 = h2 = 1 every round holds trivially. Jacobi (1/Ñ) = 1, so the
    // coprimality half of step 1 lets both through; the `eql(one)` checks
    // (CGGMP21 Fig.17's s, t ∈ Z_N^* with s, t ≠ 1) are the only refusal.
    const nt = toyModulus();
    for ([_][2]u8{ .{ 1, 4 }, .{ 1, 1 } }) |c| {
        const aux: root.AuxParams = .{ .n_tilde = nt, .h1 = toyFe(nt, c[0]), .h2 = toyFe(nt, c[1]) };
        var entries: [pi_prm_iterations]PrmEntry = undefined;
        for (&entries, 0..) |*e, i| {
            const a: u64 = 1 + (i * 37) % 150;
            e.* = .{ .a_commit = toyFe(nt, @intCast(powModSmall(c[1], a, 187))), .z = toyFe(nt, @intCast(a)) };
        }
        try testing.expect(!Piprm.verify(aux, .{ .entries = entries }));
    }
}

fn toyNTilde() root.AuxModulus {
    return root.AuxModulus.fromBytes(&[_]u8{187}, .big) catch unreachable;
}

const fz = @import("fuzz_test.zig");
const ModMark = fz.Marker(enum { accepted, refused, fixed_point });
const PrmMark = fz.Marker(enum { accepted, refused, fixed_point });

test "fuzz: ModProof.fromBytesAlloc never panics on arbitrary bytes (audit F8)" {
    try testing.fuzz({}, fuzzModProofSmith, .{});
}

test "fuzz: PrmProof.fromBytesAlloc never panics on arbitrary bytes (audit F8)" {
    try testing.fuzz({}, fuzzPrmProofSmith, .{});
}

test "fuzz driver: TECDSA_FUZZ (mod proof)" {
    try fz.fuzz_driver.run(fuzzModProof, .{ .prefix = "TECDSA_FUZZ", .name = "tecdsa-mod-proof" });
}
test "fuzz driver: TECDSA_FUZZ (prm proof)" {
    try fz.fuzz_driver.run(fuzzPrmProof, .{ .prefix = "TECDSA_FUZZ", .name = "tecdsa-prm-proof" });
}
test "fuzz harness: mod proof, 400 seeds, reaches every outcome" {
    try ModMark.reach(fuzzModProof, "tecdsa-mod-proof", 400);
}
test "fuzz harness: prm proof, 400 seeds, reaches every outcome" {
    try PrmMark.reach(fuzzPrmProof, "tecdsa-prm-proof", 400);
}

fn fuzzModProofSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzModProof(std.testing.Smith, smith, testing.allocator);
}
fn fuzzPrmProofSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzPrmProof(std.testing.Smith, smith, testing.allocator);
}

var frame_buf: [70_000]u8 = undefined;

/// A frame of the Πmod/Πprm layout over the toy Ñ = 187: fixed-width 256-octet
/// length-prefixed field elements (mostly in range), flag octets for Πmod.
/// Under the driver, 3/4 of the draws are such a frame (then 0-3 octets
/// damaged, maybe truncated, maybe a trailing octet); the rest are plain
/// slices. (The old 4096-octet buffer could never hold one: a Πmod frame is
/// ~67 KB, so the harness before this one never reached `accepted`.)
fn drawProofFrame(comptime S: type, src: *S, buf: []u8, comptime flags: bool) usize {
    if (S != fz.fuzz_driver.Rng or src.valueRangeAtMost(u8, 0, 3) == 0) return src.slice(buf);
    var n: usize = 0;
    const fields: usize = if (flags) 1 + 2 * pi_mod_iterations else 2 * pi_prm_iterations;
    for (0..fields) |i| {
        std.mem.writeInt(u32, buf[n..][0..4], root.aux_modulus_bytes, .big);
        n += 4;
        @memset(buf[n..][0..root.aux_modulus_bytes], 0);
        buf[n + root.aux_modulus_bytes - 1] = @intCast(src.index(187));
        if (src.valueRangeAtMost(u8, 0, 63) == 0) buf[n + root.aux_modulus_bytes - 1] = src.value(u8);
        n += root.aux_modulus_bytes;
        if (flags and i != 0 and i % 2 == 0) {
            buf[n] = @intFromBool(src.value(bool));
            buf[n + 1] = @intFromBool(src.value(bool));
            if (src.valueRangeAtMost(u8, 0, 63) == 0) buf[n + src.index(2)] = src.value(u8);
            n += 2;
        }
    }
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| buf[src.index(n)] = src.value(u8);
    switch (src.valueRangeAtMost(u8, 0, 7)) {
        0 => n = src.index(n + 1),
        1 => {
            buf[n] = src.value(u8);
            n += 1;
        },
        else => {},
    }
    return n;
}

/// Oracles: no panic or leak; whatever is accepted re-encodes to bytes that
/// decode and re-encode identically.
fn fuzzModProof(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const buf = &frame_buf;
    const len = drawProofFrame(S, src, buf, true);
    const p = ModProof.fromBytesAlloc(toyNTilde(), buf[0..len]) catch {
        ModMark.mark(.refused);
        return;
    };
    ModMark.mark(.accepted);
    const once = try p.toBytesAlloc(gpa);
    defer gpa.free(once);
    const back = try ModProof.fromBytesAlloc(toyNTilde(), once);
    const twice = try back.toBytesAlloc(gpa);
    defer gpa.free(twice);
    if (!std.mem.eql(u8, once, twice)) return error.EncodingNotFixedPoint;
    ModMark.mark(.fixed_point);
}

fn fuzzPrmProof(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const buf = &frame_buf;
    const len = drawProofFrame(S, src, buf, false);
    const p = PrmProof.fromBytesAlloc(toyNTilde(), buf[0..len]) catch {
        PrmMark.mark(.refused);
        return;
    };
    PrmMark.mark(.accepted);
    const once = try p.toBytesAlloc(gpa);
    defer gpa.free(once);
    const back = try PrmProof.fromBytesAlloc(toyNTilde(), once);
    const twice = try back.toBytesAlloc(gpa);
    defer gpa.free(twice);
    if (!std.mem.eql(u8, once, twice)) return error.EncodingNotFixedPoint;
    PrmMark.mark(.fixed_point);
}

// ── Πmod over a Paillier modulus (dealer-free keygen) ───────────────────

const tss_vectors = @import("tsslib_vectors.zig");

fn tssPaillier(party: usize, p: *[128]u8, q: *[128]u8) !root.AuxModulus {
    const pp = tss_vectors.tsslib_keygen.parties[party];
    _ = try std.fmt.hexToBytes(p, pp.paillier_p);
    _ = try std.fmt.hexToBytes(q, pp.paillier_q);
    var kp: @import("paillier").KeyPair = undefined;
    try @import("paillier").fromPrimes(p, q, &kp);
    return root.paillierModulusAsAux(kp.public) orelse error.TestUnexpectedResult;
}

test "Πmod/Paillier: tss-lib's 2048-bit N verifies, bound to its context and its own domain" {
    var prng = std.Random.DefaultPrng.init(0x6d6f_6431);
    const random = prng.random();
    var p: [128]u8 = undefined;
    var q: [128]u8 = undefined;
    const n0 = try tssPaillier(0, &p, &q);
    const ctx = "sid" ++ [_]u8{ 0, 0, 0, 1 };
    const proof = try Pimod.provePaillier(testing.allocator, n0, &p, &q, ctx, random);
    try testing.expect(Pimod.verifyPaillier(n0, ctx, proof));
    try testing.expect(!Pimod.verifyPaillier(n0, "sid" ++ [_]u8{ 0, 0, 0, 2 }, proof));
    // The same N as an aux modulus: a different transcript domain, so the
    // proof does not carry over.
    const as_aux: root.AuxParams = .{ .n_tilde = n0, .h1 = toyFe2048(n0, 4), .h2 = toyFe2048(n0, 9) };
    try testing.expect(!Pimod.verify(as_aux, proof));
    // Another party's N under this proof.
    var p2: [128]u8 = undefined;
    var q2: [128]u8 = undefined;
    const n2 = try tssPaillier(1, &p2, &q2);
    try testing.expect(!Pimod.verifyPaillier(n2, ctx, proof));
}

test "Πmod/Paillier: generatePaillierBlum keys are Blum and prove" {
    var prng = std.Random.DefaultPrng.init(0x6d6f_6432);
    const random = prng.random();
    var key: root.PaillierBlumKey = undefined;
    try root.generatePaillierBlum(random, 512, &key);
    defer key.wipe();
    try testing.expectEqual(@as(u8, 3), key.p()[key.p().len - 1] & 3);
    try testing.expectEqual(@as(u8, 3), key.q()[key.q().len - 1] & 3);
    const n = key.modulus();
    try testing.expectEqual(@as(usize, 512), n.bits());
    const proof = try Pimod.provePaillier(testing.allocator, n, key.p(), key.q(), "c", random);
    try testing.expect(Pimod.verifyPaillier(n, "c", proof));

    var scratch_key: root.PaillierBlumKey = undefined;
    try testing.expectError(error.InvalidBits, root.generatePaillierBlum(random, 511, &scratch_key));
    try testing.expectError(error.InvalidBits, root.generatePaillierBlum(random, 256, &scratch_key));
}

test "Πmod/Paillier TEETH: a modulus with a factor ≡ 1 (mod 4) is refused" {
    // A two-prime N that is not Blum: p ≡ 3, q ≡ 1 (mod 4).
    var prng = std.Random.DefaultPrng.init(0x6d6f_6433);
    const random = prng.random();
    // 1019 ≡ 3 (mod 4), 1033 ≡ 1 (mod 4): prime, so the prover's
    // arithmetic is well-defined and only the Blum property is missing.
    const p = [_]u8{ 0x03, 0xfb }; // 1019
    const q = [_]u8{ 0x04, 0x09 }; // 1033
    const n = try root.AuxModulus.fromBytes(&[_]u8{ 0x10, 0x0f, 0xd3 }, .big); // 1019 · 1033
    const proof = try Pimod.provePaillier(testing.allocator, n, &p, &q, "c", random);
    try testing.expect(!Pimod.verifyPaillier(n, "c", proof));
}

test "review F3: Πmod refuses a round whose challenge y_i shares a factor with Ñ" {
    // Ñ = 77 = 7·11, both ≡ 3 (mod 4): a genuine Paillier-Blum modulus, and
    // gcd(77, φ = 60) = 1 (d = 77⁻¹ mod 60 = 53). An honest prover answers
    // every round — including the non-unit y_i (≡ 0 mod 7 or 11), whose
    // roots exist too (0 is its own root). Every other check passes (w has
    // Jacobi −1, roots canonical), so only the gcd(y_i, Ñ) = 1 rule refuses it.
    const n: u64 = 77;
    const d: u64 = 53;
    try testing.expectEqual(@as(u64, 1), (n * d) % 60);
    const nt = root.AuxModulus.fromBytes(&[_]u8{77}, .big) catch unreachable;
    const aux: root.AuxParams = .{ .n_tilde = nt, .h1 = toyFe(nt, 4), .h2 = toyFe(nt, 16) };
    const w_val: u64 = 2; // (2/7) = +1, (2/11) = −1: Jacobi −1
    const w = toyFe(nt, @intCast(w_val));
    const seed = deriveModSeed(.{ .aux = aux }, w);
    var entries: [pi_mod_iterations]ModEntry = undefined;
    var non_units: usize = 0;
    for (&entries, 0..) |*e, idx| {
        const y = toyInt(deriveModChallenge(nt, seed, @intCast(idx + 1)));
        if (y % 7 == 0 or y % 11 == 0) non_units += 1;
        var found: ?ModEntry = null;
        search: for ([_]bool{ false, true }) |b| for ([_]bool{ false, true }) |a| {
            var rhs = if (b) (w_val * y) % n else y;
            if (a) rhs = (n - rhs) % n;
            var x: u64 = 0;
            while (x <= n / 2) : (x += 1) { // the canonical half
                if (powModSmall(x, 4, n) == rhs) {
                    found = .{ .x = toyFe(nt, @intCast(x)), .z = toyFe(nt, @intCast(powModSmall(y, d, n))), .a = a, .b = b };
                    break :search;
                }
            }
        };
        e.* = found orelse return error.TestFixtureHasNoFourthRoot;
    }
    try testing.expect(non_units > 0);
    try testing.expect(!Pimod.verify(aux, .{ .w = w, .entries = entries }));
}

test "mutation audit: Πmod refuses a modulus below 5 bits instead of looping in Miller-Rabin" {
    const nt = root.AuxModulus.fromBytes(&[_]u8{3}, .big) catch unreachable;
    const aux: root.AuxParams = .{ .n_tilde = nt, .h1 = toyFe(nt, 2), .h2 = toyFe(nt, 2) };
    var entries: [pi_mod_iterations]ModEntry = undefined;
    for (&entries) |*e| e.* = .{ .x = toyFe(nt, 1), .z = toyFe(nt, 1), .a = false, .b = false };
    const proof: ModProof = .{ .w = toyFe(nt, 2), .entries = entries };
    // Without the width guard the witness range [2, N-2] is empty and
    // `isProbablePrime` never returns (this call would hang, not fail).
    try testing.expect(!Pimod.verify(aux, proof));
    try testing.expect(!Pimod.verifyPaillier(nt, "ctx", proof));
}

test "mutation audit: verifyWellFormedBound runs the structural floor, honest bound proofs or not" {
    if (!gate.aux_proofs_core_implemented) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x666c6f6f72); // "floor"
    const random = prng.random();
    var gen: root.AuxParamsWithTrapdoor = undefined;
    try root.generateAuxParamsWithTrapdoor(allocator, random, 128, &gen);
    defer gen.trapdoor.deinit(allocator);
    const aux = gen.params;
    const ctx = "floor-ctx";
    const proof = try proveWellFormedBound(allocator, aux, &gen.trapdoor, ctx, random);
    // Both proofs verify on their own (a 128-bit Ñ is a fine toy modulus)…
    try testing.expect(Piprm.verifyBound(aux, ctx, proof.prm));
    try testing.expect(Pimod.verifyBound(aux, ctx, proof.mod));
    // …but the tuple is far below the q⁷ floor and must be refused as a whole.
    try testing.expectError(error.InvalidAuxParams, verifyWellFormedBound(aux, ctx, proof, random));
}
