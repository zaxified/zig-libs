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
/// `L=16` (Z_{2^128}). Arbitrary-width via `std.meta.Int`.
pub fn Z2k(comptime L: usize) type {
    if (L == 0) @compileError("Z2k: L must be > 0");
    return struct {
        pub const byte_len = L;
        /// The group element type: an unsigned integer of exactly `8*L` bits,
        /// so ordinary `+%`/`-%` already reduce mod 2^{8L}.
        pub const Int = std.meta.Int(.unsigned, 8 * L);

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
