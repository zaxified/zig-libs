// SPDX-License-Identifier: MIT

//! Dead-stack burn for key generation and signing. Each secret-touching entry
//! point (`keyGenFromSeed`, `signInternal`, `sign`) runs its body one frame
//! down (`run`, a `never_inline` call), then zeroes the bytes that body
//! dirtied at that depth: SK.seed, SK.prf and the WOTS+/FORS secret values
//! derived from SK.seed live in the body's callees' frames (the tweakable
//! hash, the Merkle recursion). The body is a separate frame on purpose:
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

/// Key generation: the body dirtied 4.4 KiB (SHA2-128f) to 17.2 KiB
/// (SHAKE-256s) in ReleaseFast (2026-10-09; SHAKE's Keccak state and the
/// recursion of `xmssNode` make the deep ones). One size for all twelve sets:
/// a burn costs ~0.3 µs per 32 KiB, nothing against a hypertree computation.
pub const keygen_burn = 24 * 1024;

/// `sign` / `signInternal`: the body dirtied 5.7 KiB (SHA2-128f) to 25.1 KiB
/// (SHAKE-256s) in ReleaseFast (2026-10-09; SHAKE-256f 18.3 KiB, SHA2-256f
/// 11.2 KiB).
pub const sign_burn = 32 * 1024;
