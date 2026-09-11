// SPDX-License-Identifier: MIT

//! vdf — `eval`, `hashToPrime`, the `Proof` codec, and the two Fable cores
//! `prove`/`verify` (all REAL). See `root.zig`'s module doc comment for the
//! construction overview and the trusted-setup caveat; this file is where
//! every piece of it actually lives.

const std = @import("std");
const group = @import("group.zig");

// ── eval — the sequential delay (REAL) ──────────────────────────────────────

/// `y = x^(2^T) mod N`, computed as `T` SEQUENTIAL modular squarings —
/// `y := x; repeat T times: y := y*y mod N`. This loop, with no shortcut,
/// IS the VDF's delay: each squaring depends on the previous one's output,
/// so — absent knowledge of `N`'s factorization (see `root.zig`) — there
/// is no way to compute `y` in fewer than (approximately) `T` sequential
/// steps, even with unbounded PARALLEL hardware. Wall-clock proportional
/// to `T`; entirely mechanical (no cryptographic design judgment beyond
/// "call `group.square` in a loop"), unlike `prove`/`verify` below.
///
/// The result is the class of `x^(2^T)` in Z_N*/{±1}, returned as its
/// representative `min(y, N-y)` (`group.canonicalize`) — the form `verify`
/// requires of `y`, and the reason a VDF output is ONE value: in Z_N*
/// itself a proof for `y` proves `N-y` just as well (see `group.zig`).
pub fn eval(m: group.Modulus, x: group.Fe, t: u64) group.Fe {
    // Montgomery-resident: convert `x` into the Montgomery domain ONCE, perform
    // the `T` sequential squarings there (each a single `montint` Montgomery
    // squaring — the fast, non-constant-time path, correct because every value
    // is public: see `group.zig`'s montint-backend note), then convert out
    // ONCE. Staying resident across the loop is the whole speed win — the two
    // domain conversions are amortized over all `T` ticks. `T = 0` is the
    // identity (0 squarings; the in/out round trip returns `x`).
    const mod = group.montModulus(m);
    var y = group.toMont(&mod, x);
    var i: u64 = 0;
    while (i < t) : (i += 1) y = group.montSquare(&mod, y);
    return group.canonicalize(m, group.fromMont(m, &mod, y));
}

// ── hashToPrime — the Fiat-Shamir challenge prime (REAL) ────────────────────

/// Bit length of the Fiat-Shamir challenge prime `l` that `hashToPrime`
/// produces. 256 bits matches the ~128-bit soundness-error target common
/// in the VDF literature (a cheating prover's forged proof passes `verify`
/// with probability roughly `1/l`, i.e. `~2^-256` here — see `root.zig`'s
/// `verify` doc comment) while staying small enough that `pow2Mod`'s
/// `O(log T)` modular squarings mod `l` stay cheap regardless of `T`.
pub const prime_bits = 256;

/// `l`'s canonical serialized length, in bytes.
pub const prime_bytes = prime_bits / 8;

/// Fixed-capacity big-unsigned-integer type for the `l`-modulus below.
pub const PrimeUint = std.crypto.ff.Uint(prime_bits);

/// The finite-field modulus type `l` itself is used as — NOT the group
/// modulus `N` (`group.Modulus`). `pow2Mod`'s `r = 2^T mod l` and the
/// (future) `verify`'s `π^l * x^r == y (mod N)` check both need `l` in
/// this form; `hashToPrime` itself only ever produces `l`'s raw bytes
/// (below), never this type directly — construct it at the call site via
/// `PrimeModulus.fromBytes(l_bytes, .big)`.
pub const PrimeModulus = std.crypto.ff.Modulus(prime_bits);

/// A field element mod `l`.
pub const PrimeFe = PrimeModulus.Fe;

/// Domain separation for `hashToPrime`'s candidate derivation. Distinct
/// from `mr_witness_domain` below (two different hashes with two
/// different purposes must never share a tag) and versioned (`v1`) so a
/// future incompatible change to the derivation is a hard error, not a
/// silent behavior change, for anyone who cached a proof.
const hash_to_prime_domain = "zig-libs/vdf/wesolowski/hash-to-prime/v1";

/// Domain separation for the deterministic Miller-Rabin witness seed
/// (`deterministicWitnessRandom` below) — see that function's doc comment
/// for why this needs to be deterministic at all.
const mr_witness_domain = "zig-libs/vdf/wesolowski/mr-witness-seed/v1";

/// Derive the FIRST candidate in `hashToPrime`'s search from the public
/// binding `(N, x, y, T)`: `SHAKE256(domain || N || x || y || T_be64)`,
/// squeezed to `prime_bytes`, then the top bit is forced set (fixes the
/// bit length at exactly `prime_bits`, never fewer) and the bottom bit is
/// forced set (odd — `hashToPrime`'s search only ever visits odd
/// candidates, below).
///
/// `n_bytes`/`x_bytes`/`y_bytes` are hashed as opaque byte strings of
/// WHATEVER length the caller passes — this function does not require
/// them to be `group.modulus_bytes` each (a caller-supplied smaller `N`
/// hashes just as unambiguously, since `T`'s fixed-width 8-byte encoding
/// plus the domain tag prevent any cross-field ambiguity in the
/// concatenation... PROVIDED the caller is consistent about which byte
/// encoding of `N`/`x`/`y` it uses between `prove` and `verify`. This
/// module always uses `group.toBytes`'s fixed `group.modulus_bytes`-wide
/// canonical encoding for all three, which removes the ambiguity
/// entirely — see `root.zig`'s "binding must be unambiguous" note.
fn deriveCandidate(n_bytes: []const u8, x_bytes: []const u8, y_bytes: []const u8, t: u64) [prime_bytes]u8 {
    var h = std.crypto.hash.sha3.Shake256.init(.{});
    h.update(hash_to_prime_domain);
    h.update(n_bytes);
    h.update(x_bytes);
    h.update(y_bytes);
    var t_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &t_be, t, .big);
    h.update(&t_be);
    var out: [prime_bytes]u8 = undefined;
    h.final(&out);
    out[0] |= 0x80;
    out[prime_bytes - 1] |= 1;
    return out;
}

/// In-place big-endian `buf += 2` (the search step: only odd candidates
/// are ever tested, so `hashToPrime`'s loop advances by 2, never 1).
fn incrementCandidateByTwo(buf: *[prime_bytes]u8) void {
    var carry: u16 = 2;
    var i: usize = buf.len;
    while (carry != 0 and i > 0) {
        i -= 1;
        const sum = @as(u16, buf[i]) + carry;
        buf[i] = @truncate(sum);
        carry = sum >> 8;
    }
    // The top bit (fixing the candidate's bit length at `prime_bits`) must
    // stay set. A carry chain reaching byte 0 and clearing it would mean
    // the search wandered `2^prime_bits`-ish steps without finding a
    // prime — prime density (~1/(prime_bits * ln 2), roughly 1-in-177
    // here) makes that astronomically unlikely long before this point;
    // assert rather than silently narrow the bit length.
    std.debug.assert(buf[0] & 0x80 != 0);
}

/// Hard ceiling on `hashToPrime`'s search length — a safety net against a
/// derivation/primality-test bug looping far past prime density's
/// expectation, not a value ever expected to bind in correct operation
/// (empirically the search finds a prime within a few dozen odd
/// candidates; see `kat_test.zig`'s hash-to-prime vector, which needed
/// 27).
const max_search_candidates: u32 = 1 << 20;

/// `SHA-256(mr_witness_domain || candidate_bytes)`'s low 8 bytes, as a
/// `DefaultPrng` seed. Deterministic in `candidate_bytes` alone — this is
/// the crux of why `hashToPrime` is safe to build on top of a Miller-Rabin
/// primality test at all: `isProbablePrime` (below) needs RANDOM witnesses
/// to have its usual soundness (a fixed witness set is breakable by a
/// crafted Carmichael-like composite), but `hashToPrime` must be a PURE
/// FUNCTION of its `(N, x, y, T)` binding — the prover and verifier must
/// derive the byte-identical `l` from the same binding, deterministically,
/// on two different machines, with no shared state. Drawing witnesses from
/// `std.crypto.random` (as `rsa`/`paillier`/`threshold_ecdsa`'s own
/// per-module Miller-Rabin helpers correctly do for KEY GENERATION, where
/// determinism is neither needed nor wanted) would silently break that:
/// a composite candidate that OS-random witnesses happen to call
/// "probably prime" on the prover's machine but "composite" on the
/// verifier's would make an honestly-computed proof fail to verify with
/// nonzero (if negligible) probability — a liveness bug, and specifically
/// the kind that would show up as sporadic, hard-to-reproduce CI flakes
/// rather than a clean failure. Seeding from a hash of the candidate
/// itself sidesteps this: the witness sequence is still effectively
/// unpredictable to an adversary picking the candidate (candidates come
/// from `deriveCandidate`'s SHAKE256 output, not attacker-chosen), but is
/// perfectly reproducible across machines/runs for the SAME candidate.
fn deterministicWitnessRandom(candidate_bytes: []const u8) std.Random.DefaultPrng {
    var seed_digest: [32]u8 = undefined;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(mr_witness_domain);
    h.update(candidate_bytes);
    h.final(&seed_digest);
    const seed = std.mem.readInt(u64, seed_digest[0..8], .little);
    return std.Random.DefaultPrng.init(seed);
}

/// Miller-Rabin round count. Mirrors the uniform `mr_rounds = 64` this
/// repo's other modules (`rsa`, `paillier`, `threshold_ecdsa`) each use in
/// their own private per-module Miller-Rabin helper — see this file's
/// module doc comment / `root.zig`'s `meta.deps` note for why this module
/// has its own copy rather than importing one of theirs (none of the
/// three export their `isProbablePrime`).
const mr_rounds = 64;

/// Bytes needed to hold a value of `bit_count` bits.
fn byteLen(bit_count: usize) usize {
    return (bit_count + 7) / 8;
}

/// Uniform random Miller-Rabin witness in `[2, m-2]` by rejection sampling
/// — same technique as `rsa.zig`'s `randomWitness`, resized for `l`.
/// Drawing exactly `byteLen(m.bits())` bytes (masked to `m.bits()`,
/// not a full `prime_bytes`-wide draw) matters here: `isProbablePrime`
/// is also exercised directly in this file's tests against small toy
/// moduli (far fewer than `prime_bits` bits) — a full-width draw would
/// make the "< m" acceptance probability for those astronomically small,
/// hanging the rejection-sampling loop in practice, not just in theory.
fn randomWitness(m: PrimeModulus, random: std.Random) PrimeFe {
    const n_bits = m.bits();
    const n_len = byteLen(n_bits);
    const n_minus_1 = m.sub(m.zero, m.one());
    var buf: [prime_bytes]u8 = undefined;
    while (true) {
        random.bytes(buf[0..n_len]);
        buf[0] &= @as(u8, 0xff) >> @intCast(8 * n_len - n_bits);
        const a = PrimeFe.fromBytes(m, buf[0..n_len], .big) catch continue; // >= m: redraw
        if (a.isZero() or a.eql(m.one()) or a.eql(n_minus_1)) continue;
        return a;
    }
}

/// In-place big-endian right shift by `s` bits (zero-fill from the left).
/// Same routine as `rsa.zig`'s `shrBytesBe`.
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

/// Drop leading zero bytes (but always leave at least one byte).
fn stripLeadingZeros(bytes: []const u8) []const u8 {
    var i: usize = 0;
    while (i < bytes.len - 1 and bytes[i] == 0) : (i += 1) {}
    return bytes[i..];
}

/// Miller-Rabin probable-prime test, `mr_rounds` witnesses from `random`.
/// `m` must be an odd integer >= 5 — every candidate `hashToPrime` builds
/// is odd (bottom bit forced) and `>= 2^(prime_bits-1)` (top bit forced),
/// so this always holds. Returns `false` iff a witness proves `m`
/// composite. Algorithm identical to `rsa.zig`'s private `isProbablePrime`
/// (see that function's doc comment for the `n-1 = d*2^s` derivation this
/// mirrors); NOT re-exported from here (nor is `rsa`'s), by design — see
/// this file's module doc comment.
fn isProbablePrime(m: PrimeModulus, random: std.Random) bool {
    var d_buf: [prime_bytes]u8 = undefined;
    m.toBytes(&d_buf, .big) catch unreachable; // buffer is exactly prime_bytes
    d_buf[prime_bytes - 1] &= 0xfe;
    var s: usize = 0;
    var i: usize = prime_bytes;
    while (i > 0) {
        i -= 1;
        if (d_buf[i] == 0) {
            s += 8;
        } else {
            s += @ctz(d_buf[i]);
            break;
        }
    }
    shrBytesBe(&d_buf, s);
    const d_bytes = stripLeadingZeros(&d_buf);

    const one = m.one();
    const n_minus_1 = m.sub(m.zero, one);

    var round: usize = 0;
    rounds: while (round < mr_rounds) : (round += 1) {
        const a = randomWitness(m, random);
        var x = m.powWithEncodedExponent(a, d_bytes, .big) catch unreachable; // d is odd, never 0
        if (x.eql(one) or x.eql(n_minus_1)) continue :rounds;
        var j: usize = 1;
        while (j < s) : (j += 1) {
            x = m.sq(x);
            if (x.eql(n_minus_1)) continue :rounds;
            if (x.eql(one)) return false; // nontrivial sqrt of 1: composite for sure
        }
        return false; // never hit n-1: `a` witnesses compositeness
    }
    return true;
}

/// Audit F4: primes below 258 — every candidate `hashToPrime` builds is
/// tested for divisibility by each of these BEFORE paying for a full
/// Miller-Rabin round. `verify` measured 58-96% of its cost (median ~82%)
/// in `hashToPrime`, and most composite candidates are divisible by a
/// small prime; sieving them out first is 3-5x cheaper per rejected
/// candidate than one Miller-Rabin round would have been.
///
/// This changes NEITHER which candidate `hashToPrime` accepts NOR how many
/// candidates it walks through: a candidate divisible by one of these is
/// composite, and `isProbablePrime` would (overwhelmingly certainly) have
/// rejected it too — see the differential test below, which checks this
/// empirically against the pre-sieve algorithm rather than just asserting
/// it. (The only way this could theoretically diverge is a composite
/// candidate for which the DETERMINISTIC per-candidate Miller-Rabin
/// witnesses happen to misidentify it as prime — a pre-existing caveat of
/// `isProbablePrime`'s determinism, not something this sieve introduces,
/// and one no test in this campaign can rule out by construction; a
/// generic hash-derived candidate divisible by a small prime is not the
/// kind of adversarially structured composite that fools Miller-Rabin.)
const sieve_primes = [_]u16{
    3,   5,   7,   11,  13,  17,  19,  23,  29,  31,  37,  41,  43,  47,
    53,  59,  61,  67,  71,  73,  79,  83,  89,  97,  101, 103, 107, 109,
    113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191,
    193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257,
};

/// `bytes` (big-endian) mod `p`, via Horner's method over the raw bytes —
/// no bignum division, just one O(prime_bytes) pass per prime.
fn modSmall(bytes: []const u8, p: u16) u16 {
    var r: u32 = 0;
    for (bytes) |b| r = (r * 256 + b) % p;
    return @intCast(r);
}

/// The Fiat-Shamir challenge prime `l`, deterministically derived from the
/// public binding `(N, x, y, T)`: hash to a `prime_bits`-bit odd candidate
/// (`deriveCandidate`), then walk odd candidates upward
/// (`incrementCandidateByTwo`) until one passes a `mr_rounds`-round
/// Miller-Rabin test with DETERMINISTIC per-candidate witnesses
/// (`deterministicWitnessRandom` — see that function's doc comment for why
/// this must NOT be `std.crypto.random`, unlike this repo's other
/// per-module Miller-Rabin helpers). Both `prove` and `verify` call this
/// with the identical `(N, x, y, T)` encoding and must therefore always
/// agree on `l` for an honest proof — this determinism, not the primality
/// test's cryptographic strength per se, is `hashToPrime`'s actual
/// correctness-critical property (see `mr_witness_domain`'s doc comment).
pub fn hashToPrime(n_bytes: []const u8, x_bytes: []const u8, y_bytes: []const u8, t: u64) [prime_bytes]u8 {
    var candidate = deriveCandidate(n_bytes, x_bytes, y_bytes, t);
    // Audit F4: incremental small-prime sieve. `remainders[i]` is always
    // `candidate mod sieve_primes[i]`, updated by `+2 mod p` alongside
    // `incrementCandidateByTwo` instead of recomputed from scratch — O(1)
    // per prime per step rather than another O(prime_bytes) pass.
    var remainders: [sieve_primes.len]u16 = undefined;
    for (sieve_primes, 0..) |p, i| remainders[i] = modSmall(&candidate, p);

    var tries: u32 = 0;
    while (true) : (tries += 1) {
        std.debug.assert(tries < max_search_candidates);
        sieve_composite: {
            for (remainders) |r| {
                if (r == 0) break :sieve_composite; // divisible by a small prime
            }
            const pm = PrimeModulus.fromBytes(&candidate, .big) catch unreachable; // odd, exactly prime_bits, well within PrimeUint
            var prng = deterministicWitnessRandom(&candidate);
            if (isProbablePrime(pm, prng.random())) return candidate;
        }
        incrementCandidateByTwo(&candidate);
        for (sieve_primes, 0..) |p, i| {
            remainders[i] = @intCast((@as(u32, remainders[i]) + 2) % p);
        }
    }
}

/// The pre-F4 algorithm, unchanged: Miller-Rabin on EVERY odd candidate,
/// no sieve. Kept only so the differential test below can check the sieve
/// against it directly rather than trusting the "no behavioral impact"
/// claim by inspection.
fn hashToPrimeUnsieved(n_bytes: []const u8, x_bytes: []const u8, y_bytes: []const u8, t: u64) [prime_bytes]u8 {
    var candidate = deriveCandidate(n_bytes, x_bytes, y_bytes, t);
    var tries: u32 = 0;
    while (true) : (tries += 1) {
        std.debug.assert(tries < max_search_candidates);
        const pm = PrimeModulus.fromBytes(&candidate, .big) catch unreachable;
        var prng = deterministicWitnessRandom(&candidate);
        if (isProbablePrime(pm, prng.random())) return candidate;
        incrementCandidateByTwo(&candidate);
    }
}

// ── pow2Mod — the mechanical half of verify's soundness check (REAL) ───────

/// `2^t mod l` — `r` in the Wesolowski verification relation `π^l * x^r ==
/// y (mod N)` (see `verify`'s doc comment below). REAL, not gated: this is
/// ordinary square-and-multiply modular exponentiation of the PUBLIC
/// constant `2` by the PUBLIC exponent `t`, entirely mechanical — no
/// cryptographic design judgment lives here, unlike `prove`/`verify`'s
/// Fable cores. Cost is `O(log t)` modular operations on a `prime_bits`
/// (256-bit) value, independent of `t`'s magnitude in any way that scales
/// with the VDF's actual delay `T` — this IS the "verification is cheap"
/// half of the construction. `verify` calls this directly (step 3) rather
/// than re-derive it.
pub fn pow2Mod(lm: PrimeModulus, t: u64) PrimeFe {
    const two = PrimeFe.fromPrimitive(u64, lm, 2) catch unreachable; // l has its top bit set (>= 2^(prime_bits-1)), so 2 < l always
    var result = lm.one();
    var base = two;
    var e = t;
    while (e != 0) : (e >>= 1) {
        if (e & 1 != 0) result = lm.mul(result, base);
        base = lm.sq(base);
    }
    return result;
}

// ── Proof — struct + byte codec (REAL) ──────────────────────────────────────

/// A Wesolowski proof: a single Z_N* element `π`. `l` is NOT carried in
/// the wire encoding — both prover and verifier recompute it
/// deterministically via `hashToPrime` from the public `(N, x, y, T)`
/// binding (standard non-interactive Wesolowski via Fiat-Shamir; see
/// `root.zig`).
pub const Proof = struct {
    pi: [group.modulus_bytes]u8,

    pub const CodecError = error{WrongLength};

    /// Canonical big-endian encoding, exactly `group.modulus_bytes` long.
    pub fn toBytes(self: Proof, out: []u8) CodecError!void {
        if (out.len != group.modulus_bytes) return error.WrongLength;
        @memcpy(out, &self.pi);
    }

    pub fn fromBytes(bytes: []const u8) CodecError!Proof {
        if (bytes.len != group.modulus_bytes) return error.WrongLength;
        var pi: [group.modulus_bytes]u8 = undefined;
        @memcpy(&pi, bytes);
        return .{ .pi = pi };
    }
};

// ── prove / verify — THE FABLE CORE ─────────────────────────────────────────

pub const ProveError = error{InvalidElement};

/// **FABLE CORE — irreducible.** Wesolowski's prover: given the
/// group modulus `N`, input `x`, claimed output `y = x^(2^T) mod N`
/// (already computed by `eval`), and the delay parameter `T`, produce a
/// proof `π` that lets `verify` check `y` in time independent of `T`.
///
/// **The relation to compute:**
///   1. `l_bytes = hashToPrime(N_bytes, x_bytes, y_bytes, T)` — the same
///      Fiat-Shamir challenge prime `verify` will independently
///      recompute; `l = PrimeModulus.fromBytes(l_bytes, .big)`.
///   2. `π = x^floor(2^T / l) mod N`.
///
/// **Two ways to compute step 2 — this module ships the SECOND, not the
/// first:**
///
/// - **Naive** (NOT the shipped algorithm): materialize `2^T` as a
///   `std.math.big.int.Managed` (a `T`-bit integer — for `T` in the
///   millions, a multi-kilobyte-to-megabyte allocation), `divFloor` by `l`
///   to get `q = floor(2^T / l)` (still ~`T` bits), then
///   `Modulus.powWithEncodedExponent(x, q_bytes, .big)`. Correct, but
///   doubles the memory footprint of the whole delay and makes the prover
///   own a big-int dependency nothing else in this module needs.
/// - **Efficient / streaming** (what ships, in `streamingQuotientPow`):
///   never materialize `q`.
///   Walk the SAME `T` squarings `eval` already performed, maintaining two
///   small running values instead of one huge exponent:
///     - `r` — the running remainder of "`2^i` divided by `l`", tracked as
///       a value mod `l` (fits in a `PrimeFe`/`u64`-ish register, never
///       grows): start `r = 1`; each of the `T` steps, `r := 2*r`, and if
///       `r >= l` then `r -= l` AND this step's "quotient bit" is `1`
///       (`r < l`: quotient bit `0`). This is long division of `2^T` by
///       `l`, performed one bit of the exponent at a time, in lock-step
///       with `eval`'s squaring loop — NOT `T` iterations of a
///       `group.Modulus`-sized operation, only a `prime_bits`-sized
///       doubling + compare per step.
///     - `π` — the accumulated proof element mod `N`: start `π = 1`; each
///       step, `π := π^2 mod N`, and if this step's quotient bit is `1`,
///       `π := π * x mod N`. This is Horner's-rule evaluation of `x^q mod
///       N` from `q`'s bits AS THEY ARE PRODUCED by the `r` recurrence
///       above — `q` itself is never held anywhere as a single big
///       integer, only one bit of it exists at a time.
///   Net cost: one `prime_bits`-sized doubling/compare (cheap) plus one
///   `group.Modulus`-sized squaring, and conditionally one
///   `group.Modulus`-sized multiply, per step — i.e. AT MOST ~2x the work
///   `eval` already did, with zero big-int allocation. Standard technique
///   from Wesolowski's paper §3 / Boneh-Bünz-Fisch's VDF survey §2.4
///   ("Simple Verifiable Delay Functions") — not novel to this module; see
///   `SPEC.md`'s "References" section.
///
/// `x_bytes`/`y_bytes` are validated via `group.elementFromBytes`
/// before any arithmetic touches them — never skipped just because the
/// values usually come from this module's own `eval` (an out-of-range or
/// zero element yields `error.InvalidElement`, not garbage). Two more
/// shapes are `InvalidElement` for the quotient group's sake: an `x` in
/// the identity class `{1, N-1}` (a degenerate input `verify` refuses —
/// see `group.isIdentityClass`), and a `y` that is not the canonical
/// representative of its class (`eval` never produces one; a proof over
/// it would be for a `y` `verify` will not accept). The returned `π` is
/// canonical too.
pub fn prove(m: group.Modulus, x_bytes: []const u8, y_bytes: []const u8, t: u64) ProveError!Proof {
    // Validate both untrusted elements before any arithmetic touches them
    // (contract: never skipped just because they usually come from `eval`).
    const x = group.elementFromBytes(m, x_bytes) catch return error.InvalidElement;
    const y = group.elementFromBytes(m, y_bytes) catch return error.InvalidElement;
    if (group.isIdentityClass(m, x)) return error.InvalidElement;
    if (!group.isCanonical(m, y)) return error.InvalidElement;

    // Fiat-Shamir binding over the fixed-width canonical encodings — the
    // decoded elements are re-serialized through `group.toBytes` (rather
    // than hashing the caller's slices as-is) so `prove` and `verify`
    // always feed `hashToPrime` byte-identical `(N, x, y, T)` regardless
    // of how the caller happened to encode its input slices. See
    // `deriveCandidate`'s doc comment / `root.zig`'s "binding must be
    // unambiguous" note.
    var n_canon: [group.modulus_bytes]u8 = undefined;
    m.toBytes(&n_canon, .big) catch unreachable; // buffer is exactly modulus_bytes
    var x_canon: [group.modulus_bytes]u8 = undefined;
    group.toBytes(x, &x_canon) catch unreachable;
    var y_canon: [group.modulus_bytes]u8 = undefined;
    group.toBytes(y, &y_canon) catch unreachable;

    const l_bytes = hashToPrime(&n_canon, &x_canon, &y_canon, t);

    // pi = x^floor(2^t / l) mod N, via the streaming quotient — the huge
    // exponent `floor(2^t / l)` is never materialized (see the helper) —
    // then reduced to its class representative: `verify` compares in the
    // quotient, so `π` and `N-π` prove the same thing, and the wire form
    // carries the one of them a verifier will admit.
    const pi = group.canonicalize(m, streamingQuotientPow(m, x, &l_bytes, t));
    var proof: Proof = .{ .pi = undefined };
    group.toBytes(pi, &proof.pi) catch unreachable; // buffer is exactly modulus_bytes
    return proof;
}

/// Unsigned integer type holding the streaming long-division remainder
/// (`< l < 2^prime_bits`), plus a one-bit-wider type for its doubling.
const RemUint = std.meta.Int(.unsigned, prime_bits);
const RemUintWide = std.meta.Int(.unsigned, prime_bits + 1);

/// `x^floor(2^t / l) mod N` WITHOUT ever materializing the ~`t`-bit
/// quotient `q = floor(2^t / l)`: schoolbook long division of `2^t` by
/// `l`, one dividend bit per step, fused with Horner's-rule
/// exponentiation by `q`'s bits AS THEY ARE PRODUCED (the exact algorithm
/// `prove`'s doc comment specifies; Wesolowski §3 / Boneh-Bünz-Fisch
/// §2.4's proof-computation trick).
///
/// Derivation of the loop's initial state: `2^t`'s binary expansion is a
/// leading 1 followed by `t` zeros. Long division consumes dividend bits
/// most-significant first — `rem := 2*rem + bit`, quotient bit `b = 1`
/// iff `rem >= l` (then `rem -= l`). Consuming the leading 1 gives
/// `rem = 1` and quotient-so-far `0` (`1 < l` always: `hashToPrime`
/// forces `l`'s top bit, so `l >= 2^(prime_bits-1)`), which is exactly
/// `r_acc = 1`, `pi = 1` below; the remaining `t` dividend bits are all
/// zero, one per loop step. Each step therefore doubles `r_acc`, emits
/// `b = (2*r_acc >= l)`, reduces, and advances the Horner accumulator
/// `pi := pi^2 * x^b mod N`. After `t` steps `pi = x^q` and `r_acc =
/// 2^t mod l` (the latter is discarded — `verify` recomputes it via
/// `pow2Mod`).
///
/// The doubling runs in plain `prime_bits+1`-bit machine arithmetic
/// (`r_acc < l`, so `2*r_acc` needs exactly one extra bit). Every value
/// here is public — `l` derives from the public `(N, x, y, T)` binding —
/// so the data-dependent branch is not a side-channel concern (see
/// `root.zig`'s "not constant-time" caveat).
fn streamingQuotientPow(m: group.Modulus, x: group.Fe, l_bytes: *const [prime_bytes]u8, t: u64) group.Fe {
    const l = std.mem.readInt(RemUint, l_bytes, .big);
    // The `group.Modulus`-sized squaring/multiply move onto montint's fast
    // Montgomery arithmetic (public data — no CT tax; see `group.zig`); the
    // streaming long-division of `2^t` by `l` (`r_acc` recurrence + quotient
    // bit) is unchanged. `pi` stays Montgomery-resident across the `t` steps —
    // `x` is converted in once, the accumulator seeds at Montgomery `1`.
    const mod = group.montModulus(m);
    const x_mont = group.toMont(&mod, x);
    var r_acc: RemUint = 1;
    var pi = group.montOne(&mod);
    var i: u64 = 0;
    while (i < t) : (i += 1) {
        const doubled = @as(RemUintWide, r_acc) << 1;
        pi = group.montSquare(&mod, pi);
        if (doubled >= l) {
            r_acc = @intCast(doubled - l); // quotient bit 1
            pi = group.montMulResident(&mod, pi, x_mont);
        } else {
            r_acc = @intCast(doubled); // quotient bit 0
        }
    }
    return group.fromMont(m, &mod, pi);
}

/// TEST-ONLY reference for `streamingQuotientPow`: materialize
/// `q = floor(2^t / l)` with `std.math.big.int` (a different algorithm
/// AND a different arithmetic library) and exponentiate directly — the
/// naive approach `prove`'s doc comment describes and rejects as the
/// shipping algorithm. Only the cross-check test below calls this; it is
/// the module's internal second opinion on the quotient, independent of
/// the completeness KAT's transitive pin against `eval`.
fn naiveQuotientPowForTest(gpa: std.mem.Allocator, m: group.Modulus, x: group.Fe, l_bytes: *const [prime_bytes]u8, t: u64) !group.Fe {
    const Managed = std.math.big.int.Managed;

    var one_big = try Managed.initSet(gpa, 1);
    defer one_big.deinit();
    var two_t = try Managed.init(gpa);
    defer two_t.deinit();
    try two_t.shiftLeft(&one_big, @intCast(t)); // 2^t

    var l_big = try Managed.init(gpa);
    defer l_big.deinit();
    const l_hex = std.fmt.bytesToHex(l_bytes.*, .lower);
    try l_big.setString(16, &l_hex);

    var q = try Managed.init(gpa);
    defer q.deinit();
    var rem = try Managed.init(gpa);
    defer rem.deinit();
    try q.divFloor(&rem, &two_t, &l_big);

    // q = 0 (i.e. 2^t < l): x^0 = 1. Handled explicitly because
    // `powWithEncodedPublicExponent` rejects a zero exponent.
    if (q.eqlZero()) return m.one();

    const q_bytes = try gpa.alloc(u8, byteLen(q.bitCountAbs()));
    defer gpa.free(q_bytes);
    q.toConst().writeTwosComplement(q_bytes, .big); // q > 0: plain big-endian magnitude
    return try m.powWithEncodedPublicExponent(x, q_bytes, .big);
}

pub const VerifyError = error{InvalidElement};

/// **FABLE CORE — irreducible.** Wesolowski's verifier: given
/// `N`, `x`, the claimed `y`, a proof `π`, and `T`, check `y = x^(2^T) mod
/// N` in time independent of `T` — this IS the "succinct" half of the VDF,
/// the entire reason a proof exists instead of just re-running `eval`.
///
/// **The check, in order:**
///   1. Decode + validate `x_bytes`, `y_bytes`, and `proof.pi` via
///      `group.elementFromBytes` — an out-of-range value (`0`, `N`,
///      `>= N`, or too many bytes) must make this function return `false`
///      (or a documented error), NEVER panic or invoke UB. Every one of
///      these three values arrives from an untrusted prover.
///   2. `l_bytes = hashToPrime(N_bytes, x_bytes, y_bytes, T)` — recompute
///      the SAME challenge prime an honest prover derived in `prove` step
///      1. Both sides derive `l` from the caller-visible `(N, x, y, T)`
///      only; nothing from the prover beyond `π` itself is trusted here
///      (Fiat-Shamir — see `root.zig`).
///   3. `r = pow2Mod(PrimeModulus.fromBytes(l_bytes, .big), t)` — already
///      implemented and real, see `pow2Mod` above.
///   4. Accept iff `π^l * x^r == y` **in Z_N*/{±1}** — i.e.
///      `canonicalize(π^l * x^r mod N) == y`, with `y` and `π` required to
///      be canonical representatives (step 1) and `x` not the identity
///      class.
///
/// **Why step 4 holds when `π` is honest:** writing `2^T = q*l + r` (the
/// division `prove` performed; `q = floor(2^T/l)`, and `r = 2^T mod l` —
/// the SAME `r` step 3 computes independently, without needing `q`):
/// `π^l * x^r = (x^q)^l * x^r = x^(q*l + r) = x^(2^T) = y`. Completeness
/// is therefore a one-line algebraic identity — up to sign, which is what
/// the quotient absorbs: `prove` ships `min(π, N-π)`, and `(N-π)^l = -π^l`
/// for odd `l`, so the raw product is `±y` and its class is `y`'s.
///
/// **Soundness — the module's actual crux, not boilerplate:** a CHEATING
/// prover must NOT be able to produce a `π' != x^q` (or claim a wrong
/// `y'`) that still satisfies step 4. This rests on two things: (a) `l`
/// being an UNPREDICTABLE-TO-THE-PROVER prime chosen ONLY AFTER `y` is
/// fixed — exactly what the Fiat-Shamir `hashToPrime` binding buys, and
/// exactly why `hashToPrime` must hash `y` (the prover's claim) and not
/// just `(N, x, T)` (fixable in advance); (b) the group having no known
/// element of low order — the "low order assumption" of Boneh-Bünz-Fisch
/// §2.3, which needs BOTH the order of `N` to be hidden (see `root.zig`'s
/// trusted-setup caveat; the reduction breaks down entirely for a
/// caller-supplied `N` whose factorization anyone knows) AND the one
/// low-order element everybody knows, `-1`, to be factored out. That
/// second half is why this verifier works in Z_N*/{±1} (BBF §6): in Z_N*
/// the same `π` negated is a valid proof of `N-y`, so a prover chooses
/// which of two "outputs" to publish — 38 of 38 such forgeries were
/// accepted before 2026-09-06. The full argument is Wesolowski §3
/// Theorem 1 over the quotient; implementing steps 1-4 above without
/// internalizing WHY step 2's binding must include `y` (not just `N, x,
/// T`), and why `-1` must be quotiented away, are the two easiest ways to
/// ship a verifier that accepts forged proofs; see `SPEC.md`.
pub fn verify(m: group.Modulus, x_bytes: []const u8, y_bytes: []const u8, proof: Proof, t: u64) VerifyError!bool {
    // Step 1: decode + validate every untrusted element. An out-of-range
    // value (`0`, `N`, `>= N`, wrong length) is a REJECTED proof — return
    // `false`, never panic/UB (and never an error: a malformed input from
    // an untrusted prover is an ordinary verification failure, which is
    // also the semantics the soundness KAT pins).
    const x = group.elementFromBytes(m, x_bytes) catch return false;
    const y = group.elementFromBytes(m, y_bytes) catch return false;
    const pi = group.elementFromBytes(m, &proof.pi) catch return false;
    // The quotient group's own three rejections. `y`/`π` must be the
    // representative of their class, not merely a member — folding `N-y`
    // to `y` here would hand a caller that hashes `y_bytes` the two-valued
    // output back (`group.isCanonical`). And `x ∈ {1, N-1}` is the
    // identity: `eval` is constant in `T` on it, so a "proof of 10^18
    // squarings" over it is free (`group.isIdentityClass`).
    if (!group.isCanonical(m, y) or !group.isCanonical(m, pi)) return false;
    if (group.isIdentityClass(m, x)) return false;

    // Step 2: recompute the challenge prime from the SAME fixed-width
    // canonical `(N, x, y, T)` binding `prove` hashed — including `y`,
    // the prover's claim; binding only `(N, x, T)` would let a cheating
    // prover fix `l` in advance and forge a proof for a wrong `y` (see
    // this function's doc comment, soundness point (a)).
    var n_canon: [group.modulus_bytes]u8 = undefined;
    m.toBytes(&n_canon, .big) catch unreachable; // buffer is exactly modulus_bytes
    var x_canon: [group.modulus_bytes]u8 = undefined;
    group.toBytes(x, &x_canon) catch unreachable;
    var y_canon: [group.modulus_bytes]u8 = undefined;
    group.toBytes(y, &y_canon) catch unreachable;
    const l_bytes = hashToPrime(&n_canon, &x_canon, &y_canon, t);
    const lm = PrimeModulus.fromBytes(&l_bytes, .big) catch unreachable; // odd, exactly prime_bits (top bit forced)

    // Step 3: r = 2^t mod l — O(log t), the cheap half of the check.
    const r = pow2Mod(lm, t);
    var r_bytes: [prime_bytes]u8 = undefined;
    r.toBytes(&r_bytes, .big) catch unreachable; // buffer is exactly prime_bytes

    // Step 4: accept iff pi^l * x^r == y (mod N). Both exponents are
    // public (Fiat-Shamir transcript values), so both exponentiations run on
    // montint's fast (non-constant-time) Montgomery arithmetic via
    // `group.montPowPublic` — no CT tax on public data (see `group.zig`).
    // Neither exponent is ever zero: `l` has its top bit forced, and
    // `r = 2^t mod l != 0` since `l` is an odd prime (no power of 2 divides it).
    const mod = group.montModulus(m);
    const pi_l = group.montPowPublic(m, &mod, pi, &l_bytes);
    const x_r = group.montPowPublic(m, &mod, x, &r_bytes);
    // Compared in the quotient: the raw product is `±y` for an honest
    // canonical `π` (see the doc comment), and its class representative is
    // what `y` was required to be.
    return group.canonicalize(m, group.mul(m, pi_l, x_r)).eql(y);
}

// ── tests ────────────────────────────────────────────────────────────────────
//
// (audit F1, `audit/modules/vdf.md`) The positive-control y-binding soundness
// test now lives in `kat_test.zig` section 2c: the adaptive false-`y` forgery
// is REJECTED by `verify` yet ACCEPTED by that file's `brokenVerifyUnboundY`
// control, so deleting `y` from `hashToPrime` flips the final assertion to
// failing (goes RED).

const testing = std.testing;

test "eval: x^(2^0) = x (zero delay is the identity)" {
    const m = try group.Modulus.fromPrimitive(u64, 1_000_003 * 999_983);
    const x = try group.Fe.fromPrimitive(u64, m, 12345);
    try testing.expect(eval(m, x, 0).eql(x));
}

test "eval: T=1 is a single squaring" {
    const m = try group.Modulus.fromPrimitive(u64, 1_000_003 * 999_983);
    const x = try group.Fe.fromPrimitive(u64, m, 12345);
    try testing.expect(eval(m, x, 1).eql(m.sq(x)));
}

test "pow2Mod: t=0 is 1" {
    const l = try PrimeModulus.fromPrimitive(u64, (1 << 61) - 1); // a convenient odd modulus for this arithmetic smoke test (need not be prime)
    try testing.expect(pow2Mod(l, 0).eql(l.one()));
}

test "pow2Mod: matches naive repeated doubling for a small t" {
    const l = try PrimeModulus.fromPrimitive(u64, (1 << 61) - 1);
    const t: u64 = 37;
    var naive = l.one();
    var i: u64 = 0;
    while (i < t) : (i += 1) naive = l.add(naive, naive); // *2 mod l, the slow way
    try testing.expect(pow2Mod(l, t).eql(naive));
}

test "Proof codec: round trip" {
    var prng = std.Random.DefaultPrng.init(0xdeadbeef);
    var pi: [group.modulus_bytes]u8 = undefined;
    prng.random().bytes(&pi);
    const p = Proof{ .pi = pi };
    var out: [group.modulus_bytes]u8 = undefined;
    try p.toBytes(&out);
    const p2 = try Proof.fromBytes(&out);
    try testing.expect(std.mem.eql(u8, &p.pi, &p2.pi));
}

test "Proof codec: rejects wrong-length input" {
    var short: [10]u8 = undefined;
    try testing.expectError(error.WrongLength, Proof.fromBytes(&short));
}

// (A1 F7) The suite above only ever exercised a SHORTER-than-`modulus_bytes`
// buffer, so a weakening of the `!=` length check to `<` (accept a LONGER
// buffer and silently truncate it — two distinct wire encodings for one
// proof, a malleability the codec's single fixed-width format is supposed to
// rule out) left every test green. This is the missing tooth.
test "Proof codec: rejects too-long input (A1 F7)" {
    var long: [group.modulus_bytes + 1]u8 = undefined;
    try testing.expectError(error.WrongLength, Proof.fromBytes(&long));
}

// ── fuzz: Proof.fromBytes never panics on arbitrary bytes ────────────────
//
// `Proof.fromBytes` is this module's only variable-length byte-loading
// entry point (a proof exchanged between prover and verifier over an
// untrusted channel) -- shallow by construction (an exact-length check
// then a plain `@memcpy`, no internal structure to speak of), but it's
// the module's one boundary of this kind, so it gets a harness rather
// than being skipped outright.
test "fuzz: Proof.fromBytes never panics on arbitrary bytes" {
    // Seeds at the one boundary the codec has (exactly `modulus_bytes`, one
    // short, one long): without a corpus the harness sees a single empty
    // input on the default lane — `check-fuzz-reach` measured that across
    // the repository on 2026-09-06.
    try testing.fuzz({}, fuzzProofFromBytes, .{ .corpus = &.{
        &([_]u8{0xab} ** group.modulus_bytes),
        &([_]u8{0xab} ** (group.modulus_bytes - 1)),
        &([_]u8{0xab} ** (group.modulus_bytes + 1)),
    } });
}

fn fuzzProofFromBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [group.modulus_bytes + 8]u8 = undefined;
    // `smith.slice`, not `bytes` + a ranged length: `bytes` consumes the
    // whole seed, after which the length draw is always 0.
    const n = smith.slice(&buf);
    _ = Proof.fromBytes(buf[0..n]) catch return;
}

test "hashToPrime: deterministic given the same binding" {
    const n = "N-placeholder";
    const x = "x-placeholder";
    const y = "y-placeholder";
    const l1 = hashToPrime(n, x, y, 42);
    const l2 = hashToPrime(n, x, y, 42);
    try testing.expect(std.mem.eql(u8, &l1, &l2));
}

test "hashToPrime: sensitive to every one of N/x/y/T" {
    const n = "N-placeholder";
    const x = "x-placeholder";
    const y = "y-placeholder";
    const base = hashToPrime(n, x, y, 42);
    try testing.expect(!std.mem.eql(u8, &base, &hashToPrime("N-different", x, y, 42)));
    try testing.expect(!std.mem.eql(u8, &base, &hashToPrime(n, "x-different", y, 42)));
    try testing.expect(!std.mem.eql(u8, &base, &hashToPrime(n, x, "y-different", 42)));
    try testing.expect(!std.mem.eql(u8, &base, &hashToPrime(n, x, y, 43)));
}

test "hashToPrime: output is prime-bits long with the top and bottom bit set" {
    const l = hashToPrime("a", "b", "c", 1);
    try testing.expectEqual(@as(usize, prime_bytes), l.len);
    try testing.expect(l[0] & 0x80 != 0);
    try testing.expect(l[prime_bytes - 1] & 1 != 0);
}

test "hashToPrime: output actually passes Miller-Rabin (self-consistency)" {
    const l_bytes = hashToPrime("self-check-N", "self-check-x", "self-check-y", 7);
    const pm = try PrimeModulus.fromBytes(&l_bytes, .big);
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    try testing.expect(isProbablePrime(pm, prng.random()));
}

test "A1 F4: the small-prime sieve agrees with the pre-fix Miller-Rabin-only search on random bindings" {
    // hashToPrime's inputs are opaque byte strings to it (they only feed
    // SHAKE256) -- arbitrary random bytes exercise exactly the same
    // candidate-search code path a real (N, x, y, T) binding would.
    var prng = std.Random.DefaultPrng.init(0xF4D1FF5E);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 24) : (i += 1) {
        var n_bytes: [32]u8 = undefined;
        var x_bytes: [32]u8 = undefined;
        var y_bytes: [32]u8 = undefined;
        rand.bytes(&n_bytes);
        rand.bytes(&x_bytes);
        rand.bytes(&y_bytes);
        const t = rand.int(u64);
        const sieved = hashToPrime(&n_bytes, &x_bytes, &y_bytes, t);
        const unsieved = hashToPrimeUnsieved(&n_bytes, &x_bytes, &y_bytes, t);
        try testing.expectEqualSlices(u8, &unsieved, &sieved);
    }
}

test "A1 F4: the sieve actually rejects small-prime-divisible candidates before Miller-Rabin, not just no-ops" {
    // A positive control for the test above: if `sieve_composite` never
    // actually fired (e.g. a bug that always fell through to Miller-Rabin
    // regardless of `remainders`), the differential test would still pass
    // vacuously -- both algorithms doing the same full search. Confirms
    // the sieve is truly participating: `deriveCandidate`'s FIRST output
    // is composite (divisible by a small prime) far more often than not
    // across many random bindings, and `hashToPrime` must still land on
    // the correct final prime each time.
    var prng = std.Random.DefaultPrng.init(0xF4D1FF60);
    const rand = prng.random();
    var sieve_hits: usize = 0;
    var i: usize = 0;
    while (i < 24) : (i += 1) {
        var n_bytes: [32]u8 = undefined;
        var x_bytes: [32]u8 = undefined;
        var y_bytes: [32]u8 = undefined;
        rand.bytes(&n_bytes);
        rand.bytes(&x_bytes);
        rand.bytes(&y_bytes);
        const t = rand.int(u64);
        const first_candidate = deriveCandidate(&n_bytes, &x_bytes, &y_bytes, t);
        for (sieve_primes) |p| {
            if (modSmall(&first_candidate, p) == 0) {
                sieve_hits += 1;
                break;
            }
        }
        // Still must find the identical prime either way.
        try testing.expectEqualSlices(
            u8,
            &hashToPrimeUnsieved(&n_bytes, &x_bytes, &y_bytes, t),
            &hashToPrime(&n_bytes, &x_bytes, &y_bytes, t),
        );
    }
    // A 256-bit random-ish odd number's chance of NOT being divisible by
    // any prime up to 257 is roughly `prod(1 - 1/p)` over the sieve list,
    // about 12% -- so most of the 24 first-candidates should trip the
    // sieve. Loose bound (>= 8, i.e. >= 1/3) keeps this robust to which
    // 24 random bindings this seed happens to draw.
    try testing.expect(sieve_hits >= 8);
}

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

test "A1 F4: sieve wall-clock speedup over the pre-fix search (ReleaseFast, printed, not asserted)" {
    // Not asserted -- a wall-clock number on a machine other agents share
    // is exactly the kind of thing this campaign's own notes warn against
    // pinning as a pass/fail gate (see A1/blindrsa.md's perf section and
    // this campaign's "delta needs its spread" feedback). Correctness and
    // sieve engagement are asserted above, deterministically; this is
    // printed for the record alongside them, interleaved to reduce bias
    // from whichever binary runs first.
    if (@import("builtin").mode != .ReleaseFast) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(0xF4D1FF61);
    const rand = prng.random();
    const rounds = 12;
    var sieved_ns: u64 = 0;
    var unsieved_ns: u64 = 0;
    var i: usize = 0;
    while (i < rounds) : (i += 1) {
        var n_bytes: [32]u8 = undefined;
        var x_bytes: [32]u8 = undefined;
        var y_bytes: [32]u8 = undefined;
        rand.bytes(&n_bytes);
        rand.bytes(&x_bytes);
        rand.bytes(&y_bytes);
        const t = rand.int(u64);

        const t1a = nowNs();
        std.mem.doNotOptimizeAway(hashToPrime(&n_bytes, &x_bytes, &y_bytes, t));
        sieved_ns += nowNs() - t1a;

        const t2a = nowNs();
        std.mem.doNotOptimizeAway(hashToPrimeUnsieved(&n_bytes, &x_bytes, &y_bytes, t));
        unsieved_ns += nowNs() - t2a;
    }
    const ratio = @as(f64, @floatFromInt(unsieved_ns)) / @as(f64, @floatFromInt(sieved_ns));
    std.debug.print(
        "A1 F4: {d} hashToPrime calls -- sieved {d} us total, unsieved {d} us total, {d:.2}x speedup (audit estimated ~2.5x)\n",
        .{ rounds, sieved_ns / 1000, unsieved_ns / 1000, ratio },
    );
}

test "prove core: streaming quotient matches naive big.int division (incl. q=0 and the 2^t ~ l boundary)" {
    const m = group.rsa2048ChallengeModulus();
    var n_canon: [group.modulus_bytes]u8 = undefined;
    try m.toBytes(&n_canon, .big);
    var x_canon: [group.modulus_bytes]u8 = [_]u8{0} ** group.modulus_bytes;
    x_canon[group.modulus_bytes - 1] = 5;
    const x = try group.elementFromBytes(m, &x_canon);

    // t below / straddling / above prime_bits exercises q = 0 (2^t < l),
    // the q = 1 boundary, and genuinely multi-bit quotients.
    const ts = [_]u64{ 1, 17, 255, 256, 257, 300, 1000 };
    for (ts) |t| {
        const y = eval(m, x, t);
        var y_canon: [group.modulus_bytes]u8 = undefined;
        try group.toBytes(y, &y_canon);
        const l_bytes = hashToPrime(&n_canon, &x_canon, &y_canon, t);

        const streaming = streamingQuotientPow(m, x, &l_bytes, t);
        const naive = try naiveQuotientPowForTest(testing.allocator, m, x, &l_bytes, t);
        try testing.expect(streaming.eql(naive));
    }
}

// ── the quotient group Z_N*/{±1} (A1 F1, 2026-09-06) ────────────────────────

/// `x` as a canonical fixed-width element, for the RSA-2048 tests below.
fn smallElement(v: u8) [group.modulus_bytes]u8 {
    var buf: [group.modulus_bytes]u8 = [_]u8{0} ** group.modulus_bytes;
    buf[group.modulus_bytes - 1] = v;
    return buf;
}

test "quotient group: eval and prove emit the class representative, and verify accepts a proof whose raw π lay above N/2" {
    // Not merely "the honest proof verifies": for at least one of these
    // inputs the raw `x^q` is the LARGER member of its class, so `prove`
    // folded it and `verify`'s raw product is `N-y` — the case that only
    // passes because the comparison happens in the quotient. Counted, so a
    // future change to the inputs cannot make this vacuous.
    const m = group.rsa2048ChallengeModulus();
    var n_canon: [group.modulus_bytes]u8 = undefined;
    try m.toBytes(&n_canon, .big);
    const t: u64 = 1000;
    var folded_pi: usize = 0;
    var folded_y: usize = 0;
    for ([_]u8{ 2, 3, 5, 7, 11, 13, 17, 19 }) |xv| {
        const x_bytes = smallElement(xv);
        const x = try group.elementFromBytes(m, &x_bytes);
        const y = eval(m, x, t);
        try testing.expect(group.isCanonical(m, y));
        // The raw squaring chain, for comparison with what `eval` returned.
        var raw = x;
        var i: u64 = 0;
        while (i < t) : (i += 1) raw = group.square(m, raw);
        try testing.expect(group.canonicalize(m, raw).eql(y));
        if (!raw.eql(y)) folded_y += 1;

        var y_bytes: [group.modulus_bytes]u8 = undefined;
        try group.toBytes(y, &y_bytes);
        const proof = try prove(m, &x_bytes, &y_bytes, t);
        const pi = try group.elementFromBytes(m, &proof.pi);
        try testing.expect(group.isCanonical(m, pi));
        const l_bytes = hashToPrime(&n_canon, &x_bytes, &y_bytes, t);
        const raw_pi = streamingQuotientPow(m, x, &l_bytes, t);
        try testing.expect(group.canonicalize(m, raw_pi).eql(pi));
        if (!raw_pi.eql(pi)) folded_pi += 1;

        try testing.expect(try verify(m, &x_bytes, &y_bytes, proof, t));
    }
    try testing.expect(folded_y > 0);
    try testing.expect(folded_pi > 0);
}

test "quotient group: the negation forgery y' = N - y, π' = N - π is rejected, as is every other sign combination (A1 F1)" {
    // `-1` has order 2 and `l` is odd, so in Z_N* `(N-π)^l · x^r = N - y`:
    // a prover could publish EITHER `y` or `N-y` with a valid proof and pick
    // the one whose hash suits it — 38 of 38 such forgeries were accepted
    // before the verifier moved to Z_N*/{±1}. Now `N-y` is not a canonical
    // representative and is refused at the door; and even if it were
    // folded, the class it names is `y`'s, so a forger gains no second
    // output.
    const m = group.rsa2048ChallengeModulus();
    for ([_]u64{ 1, 17, 1000 }) |t| {
        for ([_]u8{ 5, 7 }) |xv| {
            const x_bytes = smallElement(xv);
            const x = try group.elementFromBytes(m, &x_bytes);
            const y = eval(m, x, t);
            var y_bytes: [group.modulus_bytes]u8 = undefined;
            try group.toBytes(y, &y_bytes);
            const proof = try prove(m, &x_bytes, &y_bytes, t);
            try testing.expect(try verify(m, &x_bytes, &y_bytes, proof, t));

            var neg_y_bytes: [group.modulus_bytes]u8 = undefined;
            try group.toBytes(group.negate(m, y), &neg_y_bytes);
            const pi = try group.elementFromBytes(m, &proof.pi);
            var neg_proof: Proof = .{ .pi = undefined };
            try group.toBytes(group.negate(m, pi), &neg_proof.pi);

            // The forgery proper: (N-y, N-π).
            try testing.expect(!(try verify(m, &x_bytes, &neg_y_bytes, neg_proof, t)));
            // And the two half-negations.
            try testing.expect(!(try verify(m, &x_bytes, &neg_y_bytes, proof, t)));
            try testing.expect(!(try verify(m, &x_bytes, &y_bytes, neg_proof, t)));
            // `prove` will not even start on the non-canonical `y`.
            try testing.expectError(error.InvalidElement, prove(m, &x_bytes, &neg_y_bytes, t));
        }
    }
}

test "quotient group: the identity class x ∈ {1, N-1} is refused — no free proof of 10^18 squarings (A1 F2)" {
    // `1^(2^T) = 1` and `(N-1)^(2^T) = 1` for every `T ≥ 1`: `eval` is
    // constant in `T` on these, and the honest proof is `π = x^q ∈ {1, N-1}`
    // — writable without a single squaring. Before 2026-09-06 `verify`
    // accepted `x = 1, y = 1, π = 1, T = 10^18` in 6.3 ms.
    const m = group.rsa2048ChallengeModulus();
    const one_bytes = smallElement(1);
    var n_minus_1_bytes: [group.modulus_bytes]u8 = undefined;
    try group.toBytes(group.negate(m, m.one()), &n_minus_1_bytes);
    const t: u64 = 1_000_000_000_000_000_000;
    const proof_one: Proof = .{ .pi = one_bytes };

    try testing.expect(!(try verify(m, &one_bytes, &one_bytes, proof_one, t)));
    try testing.expect(!(try verify(m, &n_minus_1_bytes, &one_bytes, proof_one, t)));
    try testing.expectError(error.InvalidElement, prove(m, &one_bytes, &one_bytes, t));
    try testing.expectError(error.InvalidElement, prove(m, &n_minus_1_bytes, &one_bytes, t));
    // The next element up is an ordinary input and still works.
    const two_bytes = smallElement(2);
    const y = eval(m, try group.elementFromBytes(m, &two_bytes), 10);
    var y_bytes: [group.modulus_bytes]u8 = undefined;
    try group.toBytes(y, &y_bytes);
    const proof = try prove(m, &two_bytes, &y_bytes, 10);
    try testing.expect(try verify(m, &two_bytes, &y_bytes, proof, 10));
}

test "quotient group: verify demands the canonical encoding of y and π rather than folding it" {
    // A verifier that silently folded `N-y` to `y` would be sound in the
    // quotient and yet hand a caller comparing/hashing the RAW `y_bytes`
    // the two-valued output back. Pinned separately from the forgery test:
    // this one goes red if someone "helpfully" replaces the rejection with
    // a `canonicalize` on input.
    const m = try group.Modulus.fromPrimitive(u64, 1_000_003 * 999_983);
    const x = try group.Fe.fromPrimitive(u64, m, 12345);
    var x_bytes: [group.modulus_bytes]u8 = undefined;
    try group.toBytes(x, &x_bytes);
    const t: u64 = 64;
    const y = eval(m, x, t);
    var y_bytes: [group.modulus_bytes]u8 = undefined;
    try group.toBytes(y, &y_bytes);
    const proof = try prove(m, &x_bytes, &y_bytes, t);
    try testing.expect(try verify(m, &x_bytes, &y_bytes, proof, t));

    // Same class, other member: rejected on both y and π individually,
    // even though the pair (N-y, N-π) names exactly the honest classes.
    var neg_y_bytes: [group.modulus_bytes]u8 = undefined;
    try group.toBytes(group.negate(m, y), &neg_y_bytes);
    var neg_proof: Proof = .{ .pi = undefined };
    try group.toBytes(group.negate(m, try group.elementFromBytes(m, &proof.pi)), &neg_proof.pi);
    try testing.expect(!(try verify(m, &x_bytes, &neg_y_bytes, neg_proof, t)));
}

// ── Miller-Rabin strength (A1 F3) ───────────────────────────────────────────

test "isProbablePrime: strong pseudoprimes to base 2 are rejected — the witnesses are random, not the fixed base 2" {
    // Every value here passes a Miller-Rabin round with witness 2 (they are
    // the strong pseudoprimes base 2 below 10^5, OEIS A001262) and is
    // composite. A test that hard-wired the witness to 2 — or that drew it
    // from a PRNG seeded so that 2 is what comes out — would call each of
    // them prime. `deterministicWitnessRandom` is used exactly as
    // `hashToPrime` uses it, so this is the production witness stream.
    const spsp2 = [_]u64{ 2047, 3277, 4033, 4681, 8321, 15841, 29341, 42799, 49141, 52633, 65281, 74665, 80581, 85489, 88357, 90751 };
    for (spsp2) |n| {
        const pm = try PrimeModulus.fromPrimitive(u64, n);
        var n_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &n_bytes, n, .big);
        var prng = deterministicWitnessRandom(&n_bytes);
        try testing.expect(!isProbablePrime(pm, prng.random()));
    }
    // …and a prime of the same size still passes under the same stream.
    const p = try PrimeModulus.fromPrimitive(u64, 65_537);
    var p_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &p_bytes, 65_537, .big);
    var prng = deterministicWitnessRandom(&p_bytes);
    try testing.expect(isProbablePrime(p, prng.random()));
}

// F3 (A1/vdf.md): the existing anchor above uses OEIS A001262 (strong
// pseudoprimes to base 2 alone, all < 10^5) -- a MUCH weaker adversary than
// what the finding actually asked for ("an Arnault pseudoprime"). Below is a
// real, independently-verified one: 3825123056546413051 = 149491 x 747451 x
// 34233211 is a documented strong pseudoprime to EVERY ONE of the first nine
// prime bases (2,3,5,7,11,13,17,19,23) simultaneously -- not fabricated for
// this test: verified here against a from-scratch Python oracle (trial
// factorization + the standard n-1=d*2^s strong-witness check per base,
// independent of this file's own algorithm), not taken on faith from a
// citation. `deterministicWitnessRandom`'s FULL 62-bit-range draw makes
// actually landing on one of these 9 small fooling bases by chance
// vanishingly unlikely (~25/2^62) -- consistent with the original audit's
// own honest "could not construct a self-referential exploit, density out
// of reach" conclusion, which this does not overturn. What it DOES add:
// (1) a real measurement that the CURRENT production scheme (64 rounds,
// witnesses from the full range) rejects this much stronger adversary, not
// just the weak base-2-only list; (2) a permanent regression test for the
// audit's OTHER live-but-unpinned finding -- "witness hard-wired to base 2
// lets Fermat pseudoprimes through, and today's suite cannot see that
// mutation" -- pinned here with a real number instead of left as an ad hoc
// probe result.
const arnault_class_pseudoprime: u64 = 3825123056546413051; // = 149491 * 747451 * 34233211

/// A `std.Random` that always yields the same fixed witness value, however
/// many bytes/rounds are drawn — models "witness diversity failed" (a
/// hardcoded base, or a PRNG that degenerated to a constant), independent of
/// `mr_rounds`'s actual value: repeating one non-detecting witness 64 times
/// catches nothing MORE than repeating it once would.
const FixedWitness = struct {
    value: u64,

    fn fill(ptr: *anyopaque, buf: []u8) void {
        const self: *const FixedWitness = @ptrCast(@alignCast(ptr));
        @memset(buf, 0);
        var v = self.value;
        var i = buf.len;
        while (i > 0 and v != 0) {
            i -= 1;
            buf[i] = @truncate(v);
            v >>= 8;
        }
    }

    fn random(self: *const FixedWitness) std.Random {
        return .{ .ptr = @constCast(self), .fillFn = fill };
    }
};

test "isProbablePrime: a real 9-base Arnault-class pseudoprime is still rejected by the production witness stream" {
    // Confirms the CURRENT scheme (deterministicWitnessRandom, mr_rounds=64)
    // against an adversary far stronger than OEIS A001262 above: not just a
    // base-2 pseudoprime, but one that fools all nine of the smallest prime
    // bases at once.
    const pm = try PrimeModulus.fromPrimitive(u64, arnault_class_pseudoprime);
    var n_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &n_bytes, arnault_class_pseudoprime, .big);
    var prng = deterministicWitnessRandom(&n_bytes);
    try testing.expect(!isProbablePrime(pm, prng.random()));
}

test "isProbablePrime: a witness fixed to any base this number fools calls it prime — the mutation last session's suite could not see" {
    // A1/vdf.md's own mutation ladder found "witness hard-wired to base 2 ->
    // GREEN" but left it as a one-off probe result, not a standing test.
    // Pinned here with a real, verified pseudoprime: EVERY one of the first
    // nine prime bases individually fools it (not just base 2), so this is
    // strictly stronger than what the ladder tried.
    const witnesses = [_]u64{ 2, 3, 5, 7, 11, 13, 17, 19, 23 };
    for (witnesses) |w| {
        const pm = try PrimeModulus.fromPrimitive(u64, arnault_class_pseudoprime);
        var fixed: FixedWitness = .{ .value = w };
        // Full mr_rounds=64 on purpose: repeating the same non-detecting
        // witness 64 times catches nothing a single round would not, which
        // is exactly the point -- round COUNT alone is not what soundness
        // rests on, witness DIVERSITY is, and that assumption is invisible
        // to every test that only ever draws from a real random stream.
        try testing.expect(isProbablePrime(pm, fixed.random()));
    }

    // Positive control: `FixedWitness` is not a stub that always answers
    // "prime" regardless of input — an ORDINARY composite (not built to
    // fool base 2) is still correctly rejected under the same fixed-witness
    // source, so the `true` results above are about THIS number, not about
    // `FixedWitness` being broken.
    const ordinary_composite = try PrimeModulus.fromPrimitive(u64, 15); // 3 * 5, not a base-2 SPSP
    var fixed2: FixedWitness = .{ .value = 2 };
    try testing.expect(!isProbablePrime(ordinary_composite, fixed2.random()));
}

test "isProbablePrime: the round count is the repo-wide 64 (a tripwire, not a proof of strength)" {
    // What this CAN see: a round count lowered by a refactor. What it
    // CANNOT: whether 64 random witnesses are enough — that is the
    // (1/4)^rounds bound of the algorithm, not a property a test can
    // observe. A weakening from 64 to 32 rounds leaves every value test in
    // this file green, which is why the constant is pinned by name.
    try testing.expectEqual(@as(usize, 64), mr_rounds);
}

test "isProbablePrime: known small primes pass, known composites fail" {
    var prng = std.Random.DefaultPrng.init(1);
    const random = prng.random();

    const p_mersenne = try PrimeModulus.fromPrimitive(u64, (1 << 31) - 1); // 2^31 - 1, prime
    try testing.expect(isProbablePrime(p_mersenne, random));

    const carmichael_561 = try PrimeModulus.fromPrimitive(u64, 561); // smallest Carmichael number: 3*11*17
    try testing.expect(!isProbablePrime(carmichael_561, random));

    const composite = try PrimeModulus.fromPrimitive(u64, 1_000_003 * 999_983);
    try testing.expect(!isProbablePrime(composite, random));
}
