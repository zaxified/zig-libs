// SPDX-License-Identifier: MIT
//! gf256 — GF(2^8), the finite field HQC's Part-2 Reed-Solomon layer is
//! built over (reference: `src/ref/gf.c`/`gf.h`).
//!
//! **Field representation**: elements are plain `u8` values interpreted as
//! polynomials over F2 of degree < 8 (bit i of the byte = coefficient of
//! x^i), reduced modulo the primitive polynomial `poly` below. This is the
//! reference's own representation (`gf_carryless_mul`/`gf_reduce` operate
//! on the same byte-as-polynomial convention), so every value here is
//! byte-identical to the reference's for the same mathematical element —
//! there is no repacking or basis change anywhere in this module.
//!
//! **`mul` uses a different algorithm than the reference, but is
//! byte-exact anyway.** The reference computes a*b via a carryless
//! (`pclmulqdq`-emulating) polynomial multiply followed by a fixed-tap
//! reduction (`gf_carryless_mul` + `gf_reduce`) — a performance-motivated
//! choice for its target hardware. This module instead multiplies via the
//! `exp`/`log` tables below (`exp[(log[a]+log[b]) mod 255]`), the textbook
//! discrete-log approach. **These compute the identical field product**:
//! GF(2^8) multiplication is uniquely determined by the field's
//! representation (same primitive polynomial `poly`, same generator
//! alpha=2 i.e. "x") — not by which algorithm computes it. This is
//! confirmed two independent ways in this file's tests: (1)
//! `generateTables` independently re-derives `exp`/`log` from `poly` via
//! the reference's own `gf_generate` recurrence (a different piece of the
//! reference than `gf_mul` itself) and checks the result matches the
//! transcribed tables exactly, byte-for-byte; (2) the field-axiom tests
//! (multiplicative inverse, associativity, distributivity over `add`)
//! only hold for the one true field product. This is the same
//! "simpler-but-provably-equivalent" tradeoff `gf2x.zig` made for its ring
//! `mul` (schoolbook convolution vs. the reference's Toom-Cook/Karatsuba +
//! `pclmul`) — see that file's module doc for the same reasoning applied
//! to the ambient ring instead of this field.
//!
//! **Why this is real (Sonnet), not Fable**: every operation here is a
//! closed-form, fully-specified finite-field primitive (table lookup or a
//! short fixed addition chain) — there is no open algorithmic problem to
//! solve, unlike the Reed-Solomon/Reed-Muller *decoders* (reedsolomon.zig
//! / reedmuller.zig) that consume this field.

const std = @import("std");

/// Primitive polynomial (reference: `PARAM_GF_POLY`, every HQC parameter
/// set's `parameters.h`; identical across hqc-128/192/256). Bit pattern
/// 0x11D = 0b1_0001_1101 = bits {8,4,3,2,0} set, i.e.
/// x^8 + x^4 + x^3 + x^2 + 1 (0x100 | 0x10 | 0x08 | 0x04 | 0x01 = 0x11D).
/// This matches `gf.h`'s own doc comment on `gf_exp`/`gf_log` ("Powers of
/// the root alpha of 1 + x^2 + x^3 + x^4 + x^8"). **Note**: `gf.c`'s
/// `gf_reduce` doc comment mislabels the same constant as
/// "x⁸ + x⁴ + x³ + x + 1" (missing the x^2 term) — an apparent typo in
/// that one comment in the reference itself; the bit decomposition above
/// and `gf.h`'s comment (and this module's `generateTables` KAT, which
/// reproduces the transcribed tables exactly using 0x11D) all agree, so
/// 0x11D with the x^2 term is what's actually implemented, here and in
/// the reference.
pub const poly: u16 = 0x11D;

/// Antilog table: `exp[i] = alpha^i` for `i` in `[0, 254]`, alpha = 2 (the
/// polynomial "x") being the field's chosen generator. `exp[255..257]`
/// repeat `exp[0..2]` (`alpha^255 = alpha^0 = 1`, etc.) — carried over
/// from the reference's `gf_exp[258]` even though nothing in THIS module
/// reads past index 254 (the reference's own `gf_mul` doesn't use this
/// table either; a *different*, unused-here reference multiplier,
/// `gf_lutmul.c`, is the one that wants the two extra guard entries).
/// Transcribed verbatim from `gf.h`.
pub const exp: [258]u16 = .{
    1,   2,   4,   8,   16,  32,  64,  128, 29,  58,  116, 232, 205, 135, 19,  38,  76,  152, 45,  90,  180, 117,
    234, 201, 143, 3,   6,   12,  24,  48,  96,  192, 157, 39,  78,  156, 37,  74,  148, 53,  106, 212, 181, 119,
    238, 193, 159, 35,  70,  140, 5,   10,  20,  40,  80,  160, 93,  186, 105, 210, 185, 111, 222, 161, 95,  190,
    97,  194, 153, 47,  94,  188, 101, 202, 137, 15,  30,  60,  120, 240, 253, 231, 211, 187, 107, 214, 177, 127,
    254, 225, 223, 163, 91,  182, 113, 226, 217, 175, 67,  134, 17,  34,  68,  136, 13,  26,  52,  104, 208, 189,
    103, 206, 129, 31,  62,  124, 248, 237, 199, 147, 59,  118, 236, 197, 151, 51,  102, 204, 133, 23,  46,  92,
    184, 109, 218, 169, 79,  158, 33,  66,  132, 21,  42,  84,  168, 77,  154, 41,  82,  164, 85,  170, 73,  146,
    57,  114, 228, 213, 183, 115, 230, 209, 191, 99,  198, 145, 63,  126, 252, 229, 215, 179, 123, 246, 241, 255,
    227, 219, 171, 75,  150, 49,  98,  196, 149, 55,  110, 220, 165, 87,  174, 65,  130, 25,  50,  100, 200, 141,
    7,   14,  28,  56,  112, 224, 221, 167, 83,  166, 81,  162, 89,  178, 121, 242, 249, 239, 195, 155, 43,  86,
    172, 69,  138, 9,   18,  36,  72,  144, 61,  122, 244, 245, 247, 243, 251, 235, 203, 139, 11,  22,  44,  88,
    176, 125, 250, 233, 207, 131, 27,  54,  108, 216, 173, 71,  142, 1,   2,   4,
};

/// Discrete-log table: `log[a] = i` such that `exp[i] == a`, for `a` in
/// `[1, 255]`. `log[0] := 0` by convention (0 has no logarithm; every
/// function below that could reach `a == 0` special-cases it explicitly
/// rather than trusting this placeholder). Transcribed verbatim from
/// `gf.h`'s `gf_log[256]`.
pub const log: [256]u16 = .{
    0,   0,   1,   25,  2,   50,  26,  198, 3,   223, 51,  238, 27,  104, 199, 75,  4,   100, 224, 14,  52,  141,
    239, 129, 28,  193, 105, 248, 200, 8,   76,  113, 5,   138, 101, 47,  225, 36,  15,  33,  53,  147, 142, 218,
    240, 18,  130, 69,  29,  181, 194, 125, 106, 39,  249, 185, 201, 154, 9,   120, 77,  228, 114, 166, 6,   191,
    139, 98,  102, 221, 48,  253, 226, 152, 37,  179, 16,  145, 34,  136, 54,  208, 148, 206, 143, 150, 219, 189,
    241, 210, 19,  92,  131, 56,  70,  64,  30,  66,  182, 163, 195, 72,  126, 110, 107, 58,  40,  84,  250, 133,
    186, 61,  202, 94,  155, 159, 10,  21,  121, 43,  78,  212, 229, 172, 115, 243, 167, 87,  7,   112, 192, 247,
    140, 128, 99,  13,  103, 74,  222, 237, 49,  197, 254, 24,  227, 165, 153, 119, 38,  184, 180, 124, 17,  68,
    146, 217, 35,  32,  137, 46,  55,  63,  209, 91,  149, 188, 207, 205, 144, 135, 151, 178, 220, 252, 190, 97,
    242, 86,  211, 171, 20,  42,  93,  158, 132, 60,  57,  83,  71,  109, 65,  162, 31,  45,  67,  216, 183, 123,
    164, 118, 196, 23,  73,  236, 127, 12,  111, 246, 108, 161, 59,  82,  41,  157, 85,  170, 251, 96,  134, 177,
    187, 204, 62,  90,  203, 89,  95,  176, 156, 169, 160, 81,  11,  245, 22,  235, 122, 117, 44,  215, 79,  174,
    213, 233, 230, 231, 173, 232, 116, 214, 244, 234, 168, 80,  88,  175,
};

/// a + b in GF(2^8) (= a XOR b; addition and subtraction coincide in
/// characteristic 2 — the reference has no separate `gf_add`, every call
/// site XORs directly, which is what every caller of this function does
/// too — this exists only for symmetry/readability with `mul`).
pub fn add(a: u8, b: u8) u8 {
    return a ^ b;
}

/// a * b in GF(2^8) — see this file's module doc for why a table lookup
/// (not the reference's carryless-multiply) is used, and why the result
/// is still byte-exact.
pub fn mul(a: u8, b: u8) u8 {
    if (a == 0 or b == 0) return 0;
    var s: u16 = log[a] + log[b];
    if (s >= 255) s -= 255;
    return @intCast(exp[s]);
}

/// a^2 in GF(2^8) (reference: `gf_square`, a bit-doubling-then-reduce
/// shortcut this scaffold doesn't need — `mul(a, a)` is the same value).
pub fn square(a: u8) u8 {
    return mul(a, a);
}

/// Multiplicative inverse of `a` in GF(2^8)\{0}: `inverse(a) * a == 1`.
/// `inverse(0) == 0` by convention, matching the reference's addition-
/// chain `gf_inverse(0)` (which mechanically evaluates to 0 — 0 has no
/// true inverse, and every call site in the RS decoder that could reach
/// `a == 0` is expected to mask the result out via the surrounding
/// constant-time selection rather than rely on this value being
/// meaningful — see reedsolomon.zig's `decode` doc contract).
pub fn inverse(a: u8) u8 {
    if (a == 0) return 0;
    // Want exp[(255 - log[a]) mod 255]; (510 - log[a]) mod 255 gives the
    // same result without a separate zero-wraparound branch, since
    // log[a] in [0,254] implies (510 - log[a]) in [256,510], always >=255.
    const s: u16 = (510 - log[a]) % 255;
    return @intCast(exp[s]);
}

// ── tests ──────────────────────────────────────────────────────────────

test "exp/log round-trip (table self-consistency)" {
    const t = std.testing;
    for (1..256) |a| {
        try t.expectEqual(@as(u16, @intCast(a)), exp[log[a]]);
    }
    for (0..255) |i| {
        try t.expectEqual(@as(u16, @intCast(i)), log[exp[i]]);
    }
}

/// Independent re-derivation of `exp`/`log` from `poly` alone, mirroring
/// the reference's `gf_generate` (`gf.c`) — NOT called by `mul`/`inverse`
/// above (those use the transcribed tables directly), only by the test
/// below, as a from-scratch cross-check that the transcribed tables
/// really are `poly`'s exp/log tables and not a transcription slip.
fn generateTables() struct { exp: [258]u16, log: [256]u16 } {
    var e: [258]u16 = [_]u16{0} ** 258;
    var l: [256]u16 = [_]u16{0} ** 256;
    var elt: u16 = 1;
    for (0..255) |i| {
        e[i] = elt;
        l[elt] = @intCast(i);
        elt <<= 1; // multiply by alpha=2, i.e. by "x": a left shift by 1
        if (elt >= 256) elt ^= poly; // reduce mod `poly` if it overflowed GF(2^8)
    }
    e[255] = 1;
    e[256] = 2;
    e[257] = 4;
    l[0] = 0;
    return .{ .exp = e, .log = l };
}

test "generateTables independently reproduces the transcribed exp/log tables byte-exact" {
    const t = std.testing;
    const gen = generateTables();
    try t.expectEqualSlices(u16, &exp, &gen.exp);
    try t.expectEqualSlices(u16, &log, &gen.log);
}

test "mul: identity, zero, commutativity" {
    const t = std.testing;
    var rng = std.Random.DefaultPrng.init(1);
    const random = rng.random();
    for (0..64) |_| {
        const a = random.int(u8);
        try t.expectEqual(a, mul(a, 1));
        try t.expectEqual(@as(u8, 0), mul(a, 0));
        try t.expectEqual(@as(u8, 0), mul(0, a));
        const b = random.int(u8);
        try t.expectEqual(mul(a, b), mul(b, a));
    }
}

test "mul: associativity and distributivity over add (field axioms)" {
    const t = std.testing;
    var rng = std.Random.DefaultPrng.init(2);
    const random = rng.random();
    for (0..64) |_| {
        const a = random.int(u8);
        const b = random.int(u8);
        const c = random.int(u8);
        try t.expectEqual(mul(mul(a, b), c), mul(a, mul(b, c)));
        try t.expectEqual(mul(a, add(b, c)), add(mul(a, b), mul(a, c)));
    }
}

test "inverse: a * inverse(a) == 1 for every nonzero a" {
    const t = std.testing;
    for (1..256) |a| {
        const av: u8 = @intCast(a);
        try t.expectEqual(@as(u8, 1), mul(av, inverse(av)));
    }
    try t.expectEqual(@as(u8, 0), inverse(0));
}

test "square matches mul(a,a) for every a" {
    const t = std.testing;
    for (0..256) |a| {
        const av: u8 = @intCast(a);
        try t.expectEqual(mul(av, av), square(av));
    }
}
