// SPDX-License-Identifier: MIT

//! Dead-stack burn for the prover's secret entry points: `prover.setup` (toxic
//! waste), `prover.prove` and `zkprove.prove` (witness, randomizers `r`/`s`,
//! the quotient), `phase2.contribute` (the contribution secrets `x`/`s`) and
//! `circom.parseWitness` (the witness decoded from a `.wtns`). Each runs its
//! body one frame down (`run`, a `never_inline` call), then zeroes the bytes
//! that body dirtied at that depth. The body is a separate frame on purpose:
//! inlined into the entry point, the burn would land above the body's locals.
//! `stackprobe_test.zig` goes red when a body outgrows its burn.

/// Zero `n` bytes of stack below the caller.
pub noinline fn stack(comptime n: usize) void {
    // Volatile 32-byte vector stores: `secureZero` is a volatile byte memset
    // (~3 B/ns without libc, 2.5 µs per 8 KiB); this is ~100 B/ns (2026-10-08).
    const V = @Vector(4, u64);
    // align(16), not `V`'s natural 32: a 32-aligned buffer makes the frame
    // realign, and the up to 56 bytes between the saved frame pointer and
    // the buffer stayed unzeroed — a callee's secret survived there
    // (threshold_ecdsa stack probe, 2026-10-08). At 16 the buffer ends at
    // the saved frame pointer.
    var buf: [n / @sizeOf(V)]V align(16) = undefined;
    const p: [*]align(16) volatile V = &buf;
    for (0..buf.len) |i| p[i] = @splat(0);
}

/// `f(args)` in a frame of its own, then `stack(n)` at the same depth.
/// `inline`, so the argument tuple lives in the entry point's frame — it holds
/// only pointers and public values, never a secret by value.
pub inline fn run(comptime n: usize, comptime R: type, comptime f: anytype, args: anytype) R {
    const r: R = @call(.never_inline, f, args);
    stack(n);
    return r;
}

// Sizes: the body's real depth was measured with every burn at 1 KiB,
// `verbose` on, in the probe (the `dirty=` figure, ReleaseFast, 2026-10-09,
// n = 4); each constant keeps about 2x that. The fixed part is what the frames
// below the entry point reach (scalar multiplications, the inverse, the FFT);
// the part per domain point is the body's own arrays (`a_ev`, `b_ev`, `c_ev`,
// `ab`, `p`, `h` ≈ 8n field elements), which sit in the frame the burn has to
// cover before it reaches the callees.

/// Bytes of burn per domain point (`n`): twice the body's 8 × 32 B.
pub const per_point_burn = 512;

/// `prover.setup`: dirtied 12.3 KiB.
pub const setup_burn = 32 * 1024;

/// `prover.prove`: dirtied 14.8 KiB (arrays included).
pub const prove_burn = 32 * 1024;

/// `zkprove.prove`: dirtied 17.6 KiB (its arrays are on the heap).
pub const zkprove_burn = 40 * 1024;

/// `phase2.contribute`: dirtied 10.8 KiB.
pub const contribute_burn = 24 * 1024;

/// `circom.parseWitness`: dirtied 1.3 KiB.
pub const witness_burn = 4 * 1024;
