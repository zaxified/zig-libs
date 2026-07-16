// SPDX-License-Identifier: MIT
//! gf2x — the ambient ring R = F2[X] / (X^n - 1) that every HQC vector
//! (h, x, y, s, r1, r2, e, u, v-before-truncation) lives in.
//!
//! Bit ordering (spec §2.1): "Let v = (v0,...,v_{n-1}) with index 0 the
//! least-significant bit." `fromBytes`/`toBytes` therefore use LSB-first
//! packing: bit i of the vector is bit (i mod 8) of byte (i / 8) — the
//! same convention as a plain little-endian bitset, and confirmed
//! byte-exact against the reference's `h` output in kat_vectors.zig
//! (produced by `vect_set_random`, which XOF-fills the byte buffer
//! directly with no repacking).
//!
//! `mul` implements the ring product w = u*v with w_k = sum_{i+j=k mod n}
//! u_i*v_j (spec §2.1 Definition), i.e. cyclic convolution reduced mod
//! (X^n - 1). The reference implementation computes the identical
//! mathematical product using word-aligned Toom-Cook/Karatsuba plus a
//! `pclmul` elementary multiply (spec §3.3) for performance; this module
//! instead uses a schoolbook shift-and-mask-xor multiply (see `mul`'s
//! doc) — same result, same asymptotic *structure* (no data-dependent
//! branch or memory-access pattern on the operands, matching the
//! reference's "multiplications are performed without taking account of
//! sparsity" constant-time requirement, spec §3.3), but O(n^2/64) instead
//! of the reference's near-linear Toom-Cook/Karatsuba. That performance
//! gap is a deliberate Part-1 simplification (this is the mechanical
//! ring-arithmetic foundation, not the performance-critical path) — see
//! SPEC.md for the follow-up note.

const std = @import("std");
const params = @import("params.zig");

/// The ring R = F2[X]/(X^n-1), specialized to one HQC parameter set's n.
/// `Elem` is a fixed-size bit-packed vector: `words = ceil(n/64)` u64s,
/// LSB-first within each word (bit i of the vector = bit (i mod 64) of
/// word (i / 64)), with any bits beyond position n-1 in the last word
/// always kept zero (the "canonical" invariant every function here
/// maintains and, for `add`/`mul`, assumes of its inputs).
pub fn Ring(comptime n: u32) type {
    return struct {
        pub const bit_len = n;
        pub const words = (n + 63) / 64;
        pub const n_bytes = (n + 7) / 8;
        /// Mask for the top (partially-used) word: keeps only bits
        /// [0, n mod 64) of word `words-1`. For every real HQC parameter
        /// set n is prime (hence n mod 64 != 0), so this is always a
        /// proper partial-word mask — see params.zig's module doc.
        const top_bits: u6 = @intCast(n % 64);
        const top_mask: u64 = (@as(u64, 1) << top_bits) - 1;

        pub const Elem = [words]u64;
        pub const zero: Elem = [_]u64{0} ** words;

        /// Zero every bit at position >= n (enforces the canonical
        /// invariant after a raw fill, e.g. from PRNG output).
        pub fn maskTop(v: *Elem) void {
            v[words - 1] &= top_mask;
        }

        /// Set bit `pos` (0 <= pos < n).
        pub fn setBit(v: *Elem, pos: u32) void {
            std.debug.assert(pos < n);
            v[pos / 64] |= @as(u64, 1) << @intCast(pos % 64);
        }

        /// Read bit `pos` (0 <= pos < n).
        pub fn getBit(v: Elem, pos: u32) u1 {
            std.debug.assert(pos < n);
            return @intCast((v[pos / 64] >> @intCast(pos % 64)) & 1);
        }

        /// a XOR b (= a + b in F2[X]).
        pub fn add(a: Elem, b: Elem) Elem {
            var out: Elem = undefined;
            for (&out, a, b) |*o, x, y| o.* = x ^ y;
            return out;
        }

        /// Hamming weight (number of set bits), assuming `a` is
        /// canonical (bits >= n already zero — true of every value this
        /// module produces).
        pub fn weight(a: Elem) u32 {
            var w: u32 = 0;
            for (a) |word| w += @popCount(word);
            return w;
        }

        /// Deserialize `n_bytes` bytes (LSB-first, see module doc) into a
        /// canonical Elem. `bytes.len` must be >= n_bytes; only the first
        /// n_bytes are read.
        pub fn fromBytes(bytes: []const u8) Elem {
            std.debug.assert(bytes.len >= n_bytes);
            var out: Elem = zero;
            const dst = std.mem.sliceAsBytes(out[0..]);
            @memcpy(dst[0..n_bytes], bytes[0..n_bytes]);
            maskTop(&out);
            return out;
        }

        /// Serialize to exactly n_bytes bytes (LSB-first, see module
        /// doc). `out.len` must be >= n_bytes.
        pub fn toBytes(a: Elem, out: []u8) void {
            std.debug.assert(out.len >= n_bytes);
            const src = std.mem.sliceAsBytes(a[0..]);
            @memcpy(out[0..n_bytes], src[0..n_bytes]);
        }

        /// Zero every bit at position >= n1n2 (spec §3.5's `Truncate`:
        /// "discards the n' most-significant bits, keeps the n' least
        /// significant" — here n' = n1n2, applied to a full n-bit Elem).
        /// Matches the reference's `vect_truncate` word-for-word.
        pub fn truncate(v: *Elem, n1n2: u32) void {
            std.debug.assert(n1n2 <= n);
            const full_words = n1n2 / 64;
            const rem_bits = n1n2 % 64;
            var start = full_words;
            if (rem_bits != 0) {
                const mask: u64 = (@as(u64, 1) << @intCast(rem_bits)) - 1;
                v[full_words] &= mask;
                start += 1;
            }
            for (v[start..words]) |*w| w.* = 0;
        }

        // ── multiplication ──────────────────────────────────────────

        // Wide enough to hold every bit position a shifted copy of `b`
        // can reach: max shift is n-1, b spans n-1 more bits, so the
        // highest possible set bit is at position (n-1)+(n-1) = 2n-2,
        // requiring ceil((2n-1)/64) words; `2*words` is always >= that.
        const ext_words = 2 * words;

        /// XOR (b << shift), AND-masked by `mask` (0 or all-ones — the
        /// caller's constant-time bit-select), into `acc` (length
        /// ext_words). No branch on `mask`'s value.
        fn shiftMaskXorInto(acc: *[ext_words]u64, b: Elem, shift: u32, mask: u64) void {
            const word_shift = shift / 64;
            const bit_shift: u6 = @intCast(shift % 64);
            if (bit_shift == 0) {
                for (b, 0..) |w, idx| acc[idx + word_shift] ^= w & mask;
            } else {
                var carry: u64 = 0;
                for (b, 0..) |w, idx| {
                    const mw = w & mask;
                    acc[idx + word_shift] ^= (mw << bit_shift) | carry;
                    carry = mw >> @intCast(64 - @as(u32, bit_shift));
                }
                acc[words + word_shift] ^= carry;
            }
        }

        /// Ring product a*b in R = F2[X]/(X^n-1) (spec §2.1). Iterates
        /// over every bit position of `a` (not just the set ones — see
        /// module doc's constant-time note), accumulating a masked,
        /// shifted copy of `b` into a double-width buffer, then folds
        /// the double-width result mod (X^n - 1): bit position p >= n is
        /// equivalent to bit (p - n) since X^n = 1 in this ring.
        pub fn mul(a: Elem, b: Elem) Elem {
            var acc: [ext_words]u64 = [_]u64{0} ** ext_words;
            for (0..n) |i| {
                const bit: u64 = (a[i / 64] >> @intCast(i % 64)) & 1;
                const mask: u64 = 0 -% bit; // all-ones if bit=1, else 0
                shiftMaskXorInto(&acc, b, @intCast(i), mask);
            }
            // Fold bits [n, 2n-2] onto [0, n-2] (X^{n+j} = X^j). Bit
            // extraction + shift-back is branch-free (no `if` on the
            // secret bit value).
            var p: u32 = n;
            while (p <= 2 * n - 2) : (p += 1) {
                const bit = (acc[p / 64] >> @intCast(p % 64)) & 1;
                const dst = p - n;
                acc[dst / 64] ^= bit << @intCast(dst % 64);
            }
            var out: Elem = undefined;
            @memcpy(out[0..], acc[0..words]);
            maskTop(&out);
            return out;
        }
    };
}

// ── tests: algebraic identities (no official gf2x KAT is published — the
// reference ships no isolated multiply test vectors, only full KEM KATs
// that require the Part-2/3 decoder; see SPEC.md) ────────────────────────

const R128 = Ring(params.hqc128.n);
const R192 = Ring(params.hqc192.n);
const R256 = Ring(params.hqc256.n);

fn monomial(comptime R: type, i: u32) R.Elem {
    var v = R.zero;
    R.setBit(&v, i);
    return v;
}

fn testMonomialWraparound(comptime R: type) !void {
    const t = std.testing;
    // X^i * X^j = X^{(i+j) mod n}: exact, hand-verifiable "known vector"
    // multiplication, including the wraparound case that exercises the
    // mod-(X^n-1) reduction fold.
    const cases = [_][2]u32{
        .{ 0, 0 },                         .{ 0, 5 },                             .{ 1, 1 }, .{ R.bit_len - 1, 1 },
        .{ R.bit_len - 1, R.bit_len - 1 }, .{ R.bit_len / 2, R.bit_len / 2 + 3 },
    };
    for (cases) |c| {
        const got = R.mul(monomial(R, c[0]), monomial(R, c[1]));
        const want = monomial(R, (c[0] + c[1]) % R.bit_len);
        try t.expectEqualSlices(u64, &want, &got);
    }
}

fn testIdentityElement(comptime R: type, seed: u64) !void {
    const t = std.testing;
    var rng = std.Random.DefaultPrng.init(seed);
    var a: R.Elem = undefined;
    for (&a) |*w| w.* = rng.random().int(u64);
    R.maskTop(&a);
    const one = monomial(R, 0);
    try t.expectEqualSlices(u64, &a, &R.mul(a, one));
}

fn testCommutativity(comptime R: type, seed: u64) !void {
    const t = std.testing;
    var rng = std.Random.DefaultPrng.init(seed);
    var a: R.Elem = undefined;
    var b: R.Elem = undefined;
    for (&a) |*w| w.* = rng.random().int(u64);
    for (&b) |*w| w.* = rng.random().int(u64);
    R.maskTop(&a);
    R.maskTop(&b);
    try t.expectEqualSlices(u64, &R.mul(a, b), &R.mul(b, a));
}

fn testDistributivity(comptime R: type, seed: u64) !void {
    const t = std.testing;
    var rng = std.Random.DefaultPrng.init(seed);
    var a: R.Elem = undefined;
    var b: R.Elem = undefined;
    var c: R.Elem = undefined;
    for (&a) |*w| w.* = rng.random().int(u64);
    for (&b) |*w| w.* = rng.random().int(u64);
    for (&c) |*w| w.* = rng.random().int(u64);
    R.maskTop(&a);
    R.maskTop(&b);
    R.maskTop(&c);
    const lhs = R.mul(a, R.add(b, c));
    const rhs = R.add(R.mul(a, b), R.mul(a, c));
    try t.expectEqualSlices(u64, &lhs, &rhs);
}

test "hqc-128 ring: monomial wraparound (hand-verified X^i*X^j)" {
    try testMonomialWraparound(R128);
}
test "hqc-128 ring: multiplicative identity" {
    try testIdentityElement(R128, 1);
}
test "hqc-128 ring: commutativity" {
    try testCommutativity(R128, 2);
}
test "hqc-128 ring: distributivity" {
    try testDistributivity(R128, 3);
}

test "hqc-192 ring: monomial wraparound" {
    try testMonomialWraparound(R192);
}
test "hqc-192 ring: commutativity" {
    try testCommutativity(R192, 4);
}

test "hqc-256 ring: monomial wraparound" {
    try testMonomialWraparound(R256);
}
test "hqc-256 ring: commutativity" {
    try testCommutativity(R256, 5);
}

test "weight bound: weight(a*b) <= weight(a)*weight(b)" {
    const t = std.testing;
    var rng = std.Random.DefaultPrng.init(42);
    const random = rng.random();
    // Sparse-ish random vectors; the product's weight can only shrink
    // from collisions during reduction/accumulation, never exceed the
    // naive upper bound.
    var a = R128.zero;
    var b = R128.zero;
    var wa: u32 = 0;
    var wb: u32 = 0;
    while (wa < 20) : (wa += 1) R128.setBit(&a, random.uintLessThan(u32, R128.bit_len));
    while (wb < 20) : (wb += 1) R128.setBit(&b, random.uintLessThan(u32, R128.bit_len));
    const prod = R128.mul(a, b);
    try t.expect(R128.weight(prod) <= R128.weight(a) * R128.weight(b));
}

test "fromBytes/toBytes round-trip and LSB-first bit convention" {
    const t = std.testing;
    // Byte 0x01 -> bit 0 set (LSB-first), matching spec §2.1's "index 0
    // is the least-significant bit".
    var bytes = [_]u8{0} ** R128.n_bytes;
    bytes[0] = 0x01;
    const v = R128.fromBytes(&bytes);
    try t.expectEqual(@as(u1, 1), R128.getBit(v, 0));
    try t.expectEqual(@as(u1, 0), R128.getBit(v, 1));

    var rng = std.Random.DefaultPrng.init(7);
    var raw = [_]u8{0} ** R128.n_bytes;
    rng.random().bytes(&raw);
    const parsed = R128.fromBytes(&raw);
    var out = [_]u8{0} ** R128.n_bytes;
    R128.toBytes(parsed, &out);
    // Top bits beyond n get masked on the way in, so re-encode must equal
    // the masked value, not necessarily the raw random bytes verbatim.
    const reparsed = R128.fromBytes(&out);
    try t.expectEqualSlices(u64, &parsed, &reparsed);
}

test "truncate zeroes bits >= n1n2, keeps bits below" {
    const t = std.testing;
    const P = params.hqc128;
    var v = R128.zero;
    R128.setBit(&v, P.n1n2() - 1); // last kept bit
    R128.setBit(&v, P.n1n2()); // first discarded bit
    R128.setBit(&v, P.n - 1); // last discarded bit
    R128.truncate(&v, P.n1n2());
    try t.expectEqual(@as(u1, 1), R128.getBit(v, P.n1n2() - 1));
    try t.expectEqual(@as(u1, 0), R128.getBit(v, P.n1n2()));
    try t.expectEqual(@as(u1, 0), R128.getBit(v, P.n - 1));
}
