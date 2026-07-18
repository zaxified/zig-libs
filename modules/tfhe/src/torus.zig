// SPDX-License-Identifier: MIT

//! torus — the discretised real torus `T = R/Z` represented as `Z_q` with the
//! power-of-two modulus `q = 2^32` (a `u32`). This is the numeric backbone of
//! TFHE and the reason the whole scheme is std-only and *exactly* computable:
//!
//!   - `q = 2^32` means modular addition/subtraction/multiplication are just
//!     **wrapping `u32` arithmetic** (`+%`, `-%`, `*%`) — natively exact, no
//!     modular reduction, no NTT prime, and (crucially) **no FFT precision
//!     bound** to reason about. Unlike a prime-modulus RLWE ring, negacyclic
//!     polynomial multiplication here is an exact integer convolution mod
//!     `2^32` (see `poly.zig`), so the mechanical layer has zero rounding
//!     debt of its own.
//!
//! All helpers here are REAL/ungated: message (de)coding by a scaling factor
//! `Δ`, the round-to-nearest rescale used by modulus switching (`q → 2N`), and
//! the gadget-weight helper. They are pure integer rounding — no secrets, no
//! randomness — so they are deterministic and exhaustively testable.

const std = @import("std");

/// Torus element: `Z_{2^32}`. A signed real `x ∈ [0,1)` maps to `round(x·2^32)`.
pub const Torus = u32;

pub const log_q: u6 = 32;

/// Encode an integer message `m` at scale `Δ`: `μ = m·Δ (mod q)`. For a bit
/// with `Δ = q/4` this places `m ∈ {0,1}` at `{0, q/4}` (the padding-bit
/// convention keeps valid messages in the lower half `[0, q/2)`).
pub fn encode(m: u32, delta: Torus) Torus {
    return m *% delta;
}

/// Decode `μ` back to a message in `[0, p)` where `p = 2^p_log` and the scale
/// is `Δ = q/p` (so `delta_log = log_q − p_log`). Round-to-nearest:
/// `⌊(μ + Δ/2) / Δ⌋ mod p`.
pub fn decode(mu: Torus, delta_log: u6, p_log: u6) u32 {
    const half: u64 = @as(u64, 1) << @intCast(delta_log - 1);
    const q = (@as(u64, mu) + half) >> @intCast(delta_log);
    const p_mask: u64 = (@as(u64, 1) << @intCast(p_log)) - 1;
    return @intCast(q & p_mask);
}

/// Round-to-nearest rescale `q → M` with `M = 2^log_m`: `⌊x·M/q + 1/2⌋ mod M`.
/// This is the modulus switch that maps a torus coordinate into one of the
/// `2N` rotation slots of the accumulator ring before blind rotation. Result
/// in `[0, M)`. Deterministic rounding; the only "noise" it adds is the
/// half-ulp rounding error, bounded by `q/(2M)` and accounted for in SPEC.md.
pub fn modSwitch(x: Torus, comptime log_m: u6) usize {
    comptime std.debug.assert(log_m < log_q);
    const shift: u6 = log_q - log_m;
    const half: u64 = @as(u64, 1) << @intCast(shift - 1);
    const r = (@as(u64, x) + half) >> @intCast(shift);
    const m_mask: u64 = (@as(u64, 1) << @intCast(log_m)) - 1;
    return @intCast(r & m_mask); // fold M ≡ 0 (the top slot wraps to 0)
}

/// Gadget weight `q / B^{level+1} = 2^{log_q − (level+1)·b_bits}` as a torus
/// scalar (`level` 0-based). Used by GGSW / key-switch key generation and by
/// the (gated) external product's recomposition.
pub fn gadgetWeight(comptime b_bits: u6, level: usize) Torus {
    const shift: u32 = @intCast(log_q - @as(u32, b_bits) * @as(u32, @intCast(level + 1)));
    return @as(Torus, 1) << @intCast(shift);
}

const testing = std.testing;

test "encode/decode a bit at Δ = q/4 round-trips, tolerates noise < q/8" {
    const delta: Torus = 1 << 30; // q/4
    for ([_]u32{ 0, 1 }) |b| {
        const mu = encode(b, delta);
        try testing.expectEqual(b, decode(mu, 30, 2));
        // +noise below q/8 still decodes to b.
        try testing.expectEqual(b, decode(mu +% (1 << 28), 30, 2));
        try testing.expectEqual(b, decode(mu -% (1 << 28), 30, 2));
    }
}

test "modSwitch rounds q → 2N to nearest slot" {
    // 2N = 512 ⇒ log_m = 9. q/2N = 2^23.
    try testing.expectEqual(@as(usize, 0), modSwitch(0, 9));
    try testing.expectEqual(@as(usize, 1), modSwitch(1 << 23, 9)); // exactly one slot
    try testing.expectEqual(@as(usize, 128), modSwitch(1 << 30, 9)); // q/4 = 128 slots
    try testing.expectEqual(@as(usize, 0), modSwitch(0xFFFFFFFF, 9)); // rounds up, wraps 512→0
    // nearest-rounding: just under half a slot rounds down.
    try testing.expectEqual(@as(usize, 0), modSwitch((1 << 22) - 1, 9));
    try testing.expectEqual(@as(usize, 1), modSwitch(1 << 22, 9)); // exactly half rounds up
}

test "gadgetWeight halves per level" {
    try testing.expectEqual(@as(Torus, 1 << 25), gadgetWeight(7, 0)); // q/2^7
    try testing.expectEqual(@as(Torus, 1 << 18), gadgetWeight(7, 1)); // q/2^14
    try testing.expectEqual(@as(Torus, 1 << 4), gadgetWeight(4, 6)); // q/2^28
}
