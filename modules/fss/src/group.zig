// SPDX-License-Identifier: MIT

//! group — the DPF output group. **Fully real and ungated** (mechanical
//! modular arithmetic, no cryptographic judgment): `Z2k(L)` is the additive
//! group Z_{2^{8L}} represented as an `L`-byte little-endian integer, with
//! wrapping `add`/`sub`/`neg`. This is the standard DPF output group (a
//! point function f_{α,β} whose non-zero value β lives in an additive group;
//! Z_{2^k} is the canonical choice — see SPEC.md §"Output group").
//!
//! The two DPF shares reconstruct by ADDING in this group
//! (`Eval0(x) + Eval1(x) == f(x)`), with party 1 contributing the negation
//! (`neg`) so that off-target the two shares cancel to `0` and on-target
//! they sum to β. Everything here is ordinary wrapping integer arithmetic;
//! the subtlety lives in the correction-word core (`dpf.zig`), not here.

const std = @import("std");

/// The additive group Z_{2^{8L}} of `L`-byte little-endian integers.
/// `L` must be > 0. Common choices: `L=4` (Z_{2^32}), `L=8` (Z_{2^64}),
/// `L=16` (Z_{2^128}). Arbitrary-width via `@Int`.
pub fn Z2k(comptime L: usize) type {
    if (L == 0) @compileError("Z2k: L must be > 0");
    return struct {
        pub const byte_len = L;
        /// The group element type: an unsigned integer of exactly `8*L` bits,
        /// so ordinary `+%`/`-%` already reduce mod 2^{8L}.
        pub const Int = @Int(.unsigned, 8 * L);

        pub const Elem = Int;

        /// A PRG seed's element: `convert`'s `8L` uniform bits.
        pub fn fromPrg(p: anytype, seed: [16]u8) Int {
            return p.convert(L, seed);
        }

        /// group addition (mod 2^{8L})
        pub fn add(a: Int, b: Int) Int {
            return a +% b;
        }

        /// group subtraction (mod 2^{8L})
        pub fn sub(a: Int, b: Int) Int {
            return a -% b;
        }

        /// additive inverse (mod 2^{8L})
        pub fn neg(a: Int) Int {
            return 0 -% a;
        }

        /// little-endian encoding of a group element
        pub fn toBytes(a: Int) [L]u8 {
            var out: [L]u8 = undefined;
            std.mem.writeInt(Int, &out, a, .little);
            return out;
        }

        /// decode a group element from its little-endian encoding
        pub fn fromBytes(b: [L]u8) Int {
            return std.mem.readInt(Int, &b, .little);
        }
    };
}

/// The XOR group `({0,1}^{8L}, ⊕)`: `add == sub == ⊕`, `neg` the identity.
/// With it the two DPF shares reconstruct by XOR (PIR-by-XOR: a server's
/// answer is the XOR of the records its share selects).
pub fn Xor(comptime L: usize) type {
    if (L == 0) @compileError("Xor: L must be > 0");
    return struct {
        pub const byte_len = L;
        pub const Int = @Int(.unsigned, 8 * L);
        pub const Elem = Int;

        pub fn fromPrg(p: anytype, seed: [16]u8) Int {
            return p.convert(L, seed);
        }
        pub fn add(a: Int, b: Int) Int {
            return a ^ b;
        }
        pub fn sub(a: Int, b: Int) Int {
            return a ^ b;
        }
        pub fn neg(a: Int) Int {
            return a;
        }
    };
}

/// The additive group `Z_N` for a modulus `2 ≤ N ≤ 2^64` (a prime field's
/// additive group for a prime `N`, e.g. a VDAF field), elements `u64` in
/// `[0, N)`, 8 bytes on the wire. `fromPrg` reduces 192 PRG bits mod `N`
/// (statistical distance from uniform `< 2^-128`), bit-serially. `add`/`sub`/`neg` reduce
/// with a mask, never a branch on an element.
pub fn ZMod(comptime N: u65) type {
    if (N < 2 or N > (1 << 64)) @compileError("ZMod: N must be in 2..2^64");
    return struct {
        pub const byte_len = 8;
        pub const modulus = N;
        pub const Elem = u64;

        pub fn fromPrg(p: anytype, seed: [16]u8) u64 {
            const wide: u192 = p.convert(24, seed);
            // Bit-serial reduction with a masked subtract: a `%` on a 192-bit
            // value is a library division whose time depends on its operands,
            // and the PRG output is secret.
            var r: u66 = 0;
            var i: usize = 192;
            while (i > 0) {
                i -= 1;
                r = (r << 1) | @as(u66, @as(u1, @truncate(wide >> @intCast(i))));
                const d: u66 = r -% N;
                const keep_r: u66 = 0 -% (d >> 65); // borrow ⇒ r < N
                r = (r & keep_r) | (d & ~keep_r);
            }
            return @intCast(r);
        }
        /// `a + b mod N` for canonical `a, b`.
        pub fn add(a: u64, b: u64) u64 {
            const s: u65 = @as(u65, a) + b;
            const r: u65 = s -% N;
            // r's top bit set (borrow) iff s < N: keep s, else r.
            const keep_s: u65 = 0 -% (r >> 64);
            return @truncate((s & keep_s) | (r & ~keep_s));
        }
        pub fn neg(a: u64) u64 {
            const r: u65 = @as(u65, N) - a; // in (0, N]
            const is_n: u65 = 0 -% @as(u65, @intFromBool(r == N));
            return @truncate(r & ~is_n);
        }
        pub fn sub(a: u64, b: u64) u64 {
            return add(a, neg(b));
        }
    };
}

/// A vector of `k` independent `Z_{2^{8L}}` components (Google's tuple value
/// types for a homogeneous tuple), packed little-endian into one `8·L·k`-bit
/// integer, component `i` in bits `[8L·i, 8L·(i+1))`. Group operations act per
/// component, with no carry between components. `L·k ≤ 32` (one `convert`).
pub fn Vector(comptime L: usize, comptime k: usize) type {
    if (L == 0 or k == 0 or L * k > 32) @compileError("Vector: need L, k > 0 and L*k <= 32");
    return struct {
        pub const byte_len = L * k;
        pub const components = k;
        pub const Comp = @Int(.unsigned, 8 * L);
        pub const Elem = @Int(.unsigned, 8 * L * k);

        pub fn fromPrg(p: anytype, seed: [16]u8) Elem {
            return p.convert(L * k, seed);
        }
        pub fn get(a: Elem, i: usize) Comp {
            return @truncate(a >> @intCast(8 * L * i));
        }
        pub fn pack(c: [k]Comp) Elem {
            var out: Elem = 0;
            for (c, 0..) |x, i| out |= @as(Elem, x) << @intCast(8 * L * i);
            return out;
        }
        pub fn add(a: Elem, b: Elem) Elem {
            var c: [k]Comp = undefined;
            for (&c, 0..) |*x, i| x.* = get(a, i) +% get(b, i);
            return pack(c);
        }
        pub fn sub(a: Elem, b: Elem) Elem {
            var c: [k]Comp = undefined;
            for (&c, 0..) |*x, i| x.* = get(a, i) -% get(b, i);
            return pack(c);
        }
        pub fn neg(a: Elem) Elem {
            return sub(0, a);
        }
    };
}

// ── tests (REAL, ungated — prove the group law holds) ─────────────────────

test "Z2k add/sub/neg wrap mod 2^{8L}" {
    const G = Z2k(4); // Z_{2^32}
    try std.testing.expectEqual(@as(G.Int, 0), G.add(std.math.maxInt(G.Int), 1));
    try std.testing.expectEqual(@as(G.Int, std.math.maxInt(G.Int)), G.sub(0, 1));
    // a + neg(a) == 0 for all a
    for ([_]G.Int{ 0, 1, 42, 0xDEADBEEF, std.math.maxInt(G.Int) }) |a| {
        try std.testing.expectEqual(@as(G.Int, 0), G.add(a, G.neg(a)));
    }
    // sub is add of neg
    try std.testing.expectEqual(G.sub(7, 12), G.add(7, G.neg(12)));
}

test "Z2k byte round-trip is little-endian" {
    const G = Z2k(8); // Z_{2^64}
    const v: G.Int = 0x0102030405060708;
    const b = G.toBytes(v);
    try std.testing.expectEqual(@as(u8, 0x08), b[0]); // LSB first
    try std.testing.expectEqual(@as(u8, 0x01), b[7]);
    try std.testing.expectEqual(v, G.fromBytes(b));
}

test "Z2k works at multiple widths" {
    inline for ([_]usize{ 1, 2, 4, 8, 16 }) |L| {
        const G = Z2k(L);
        try std.testing.expectEqual(@as(usize, L), G.byte_len);
        try std.testing.expectEqual(@as(G.Int, 0), G.add(G.neg(3), 3));
    }
}

test "Xor and ZMod obey the group law" {
    const X = Xor(4);
    try std.testing.expectEqual(@as(X.Int, 0), X.add(0xabcd, 0xabcd));
    try std.testing.expectEqual(@as(X.Int, 0x1234), X.neg(0x1234));
    const P = ZMod(0xffff_ffff_0000_0001); // the Goldilocks prime
    const Z7 = ZMod(7);
    for (0..7) |a| for (0..7) |b| {
        try std.testing.expectEqual(@as(u64, (a + b) % 7), Z7.add(a, b));
        try std.testing.expectEqual(@as(u64, (a + 7 - b) % 7), Z7.sub(a, b));
    };
    try std.testing.expectEqual(@as(u64, 0), Z7.neg(0));
    const big: u64 = 0xffff_ffff_0000_0000;
    try std.testing.expectEqual(@as(u64, big - 1), P.add(big, big));
    try std.testing.expectEqual(@as(u64, 0), P.add(big, P.neg(big)));
    const Full = ZMod(1 << 64);
    try std.testing.expectEqual(@as(u64, 1), Full.add(std.math.maxInt(u64), 2));
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), Full.neg(1));
}

test "ZMod.fromPrg equals the 192-bit value mod N" {
    const prg = @import("prg.zig");
    const p = prg.Sha256Prg.init();
    inline for (.{ 7, 0xffff_ffff_0000_0001, 1 << 64, 3 }) |N| {
        const Z = ZMod(N);
        for (0..20) |i| {
            const seed: [16]u8 = @splat(@intCast(i * 13));
            const wide: u192 = p.convert(24, seed);
            try std.testing.expectEqual(@as(u64, @intCast(wide % N)), Z.fromPrg(p, seed));
        }
    }
}

test "Vector adds per component with no carry between components" {
    const V = Vector(2, 3);
    const a = V.pack(.{ 0xffff, 1, 0x8000 });
    const b = V.pack(.{ 1, 2, 0x8000 });
    const c = V.add(a, b);
    try std.testing.expectEqual(@as(V.Comp, 0), V.get(c, 0));
    try std.testing.expectEqual(@as(V.Comp, 3), V.get(c, 1));
    try std.testing.expectEqual(@as(V.Comp, 0), V.get(c, 2));
    try std.testing.expectEqual(@as(V.Elem, 0), V.add(a, V.neg(a)));
    try std.testing.expectEqual(V.sub(a, b), V.add(a, V.neg(b)));
}
