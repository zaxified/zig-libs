// SPDX-License-Identifier: MIT

//! Dead-stack burn for the secret entry points (`KeyPair.generate*`,
//! `pairwiseConsistencyCheck`, `PublicKey.encaps*`, `SecretKey.decaps`,
//! `SecretKey.fromBytes`). Each runs its body one frame down (`run`, a
//! `never_inline` call), then zeroes the bytes that body dirtied at that
//! depth: the secret polynomials (s, e, r, e1, e2), m, K and the Keccak
//! states that the per-local `secureZero` calls cannot reach in callee
//! frames. The body is a separate frame on purpose: inlined into the entry
//! point, the burn would land above the body's locals. Added 2026-11-23
//! (the module had none; `check-secret-api.py` flagged every entry point).
//! `stackprobe_test.zig` goes red when a body outgrows its burn.

/// Zero `n` bytes of stack below the caller.
pub noinline fn stack(comptime n: usize) void {
    // Volatile 16-byte vector stores (~50 B/ns; `secureZero` is a volatile
    // byte memset, ~3 B/ns). 16, not 32: with a 32-byte vector LLVM raised
    // the buffer's alignment and realigned the frame, leaving the top bytes
    // below the saved frame pointer unzeroed (voprf, 2026-10-09).
    const V = @Vector(2, u64);
    var buf: [n / @sizeOf(V)]V align(16) = undefined;
    const p: [*]align(16) volatile V = &buf;
    for (0..buf.len) |i| p[i] = @splat(0);
}

/// `f(args...)` one frame down, then `stack(n)`.
pub inline fn run(comptime n: usize, comptime R: type, comptime f: anytype, args: anytype) R {
    const r: R = @call(.never_inline, f, args);
    stack(n);
    return r;
}

// Sizes: the body's real depth, measured in ReleaseFast with every burn at
// 1 KiB (`stackprobe_test.zig` with `verbose`, the residue's deepest byte,
// 2026-11-23), about 1.5x that, in 4 KiB steps; indexed by the parameter
// set's k (2, 3, 4 = ML-KEM-512, -768, -1024). Kept tight on purpose: a burn
// is ~20 ns per KiB, and decaps is ~10-15 us.

/// `burn` sizes per parameter set (k = 2, 3, 4).
pub fn by(comptime k: u8, comptime sizes: [3]usize) usize {
    return sizes[k - 2];
}

/// keygen: 10.7 / 12.2 / 13.8 KiB.
pub const keygen_burn = [3]usize{ 16 * 1024, 20 * 1024, 24 * 1024 };
/// encaps: 9.6 / 11.2 / 12.7 KiB.
pub const encaps_burn = [3]usize{ 16 * 1024, 20 * 1024, 20 * 1024 };
/// decaps (decrypt + re-encrypt + J): 13.4 / 15.8 / 18.3 KiB.
pub const decaps_burn = [3]usize{ 20 * 1024, 24 * 1024, 28 * 1024 };
/// `SecretKey.fromBytes`: 7.5 / 7.5 / 7.7 KiB.
pub const key_burn = [3]usize{ 12 * 1024, 12 * 1024, 12 * 1024 };
