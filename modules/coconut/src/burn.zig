// SPDX-License-Identifier: MIT

//! Dead-stack burn for every Coconut entry point that holds a secret
//! (`keygen`, `VerificationKey.fromSecret`, `VerificationKeyShare.fromShare`,
//! `signingExponent`, `psSignWithSecret`, `signPartial`, `proveCredential`).
//! Each runs its body one frame down (`run`, a `never_inline` call), then zeroes the bytes that body
//! dirtied at that depth. The body is a separate frame on purpose: inlined
//! into the entry point, the burn would land above the body's locals.
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

// Sizes: the dirty depth of each body is the probe's "dirty" figure for it in
// ReleaseFast (2026-10-09); each constant keeps at least 1.7x that, the whole
// dirtied depth rather than only the depth the probe happened to find a secret
// at (with every burn at 1 KiB the deepest residue sat 4.2 KiB down in
// `proveCredential`, 1.5 KiB in `keygen`, but the scalar multiplications below
// them are fed secret scalars all the way down).

/// `keygen` dirtied 13.9 KiB (the G2 multiplications of `fromSecret` /
/// `fromShare`, 12.9 KiB, run inside it).
pub const key_burn = 24 * 1024;

/// `psSignWithSecret` dirtied 6.4 KiB, `signPartial` 7.4 KiB (a G1 multiply by
/// the signing exponent); `signingExponent` alone is a few field operations.
pub const sign_burn = 12 * 1024;

/// `evalPoly`: Horner over `Fr`, no frame deeper than the field multiply.
pub const eval_burn = 2 * 1024;

/// `proveCredential` dirtied 20.2 KiB (G1/G2 multiplications by `r'`, `r`,
/// `r~`, `m~_j`, the challenge hash).
pub const prove_burn = 32 * 1024;
