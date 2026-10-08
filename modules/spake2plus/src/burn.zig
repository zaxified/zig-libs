// SPDX-License-Identifier: MIT

//! Dead-stack burn for every secret-touching entry point. Each public entry
//! point runs its body one frame down (`run`, a `never_inline` call), then
//! zeroes the bytes that body dirtied at that depth. The body is a separate
//! frame on purpose: inlined into the entry point, the burn would land above
//! the body's locals. `stackprobe_test.zig` goes red when a body outgrows its
//! burn.

/// Zero `n` bytes of stack below the caller.
pub noinline fn stack(comptime n: usize) void {
    // Volatile 32-byte vector stores: `secureZero` is a volatile byte memset
    // (~3 B/ns without libc); this is ~100 B/ns (2026-10-08).
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

/// Anything that multiplies a point (`computeL`, `proverStart`,
/// `verifierStart`, the three Z/V cores). Measured in ReleaseFast before the
/// burns existed (2026-10-08, `stackprobe_test.zig`): the dirtied depth of
/// these calls was 8.6 KiB (`computeL`), 9.0 KiB (the shares), 10.3-10.8 KiB
/// (`proverFinish`/`verifierConfirm`/`verifierFinish`) — of which the `p256`
/// multiply's own 8 KiB burn is the bulk. 32 KiB is the next power of two
/// at least twice the deepest of those; 32 KiB of vector stores is well under
/// a microsecond next to a scalar multiply.
pub const core_burn = 32 * 1024;

/// `kdf`, `mac`, `deriveKeys`, `computeW0W1`, `computeTranscript`: SHA-256 /
/// HMAC / HKDF state and the wide-reduction scratch, no multiply. Measured
/// 0.9 KiB (`mac`), 1.2 KiB (`computeW0W1`), 1.4 KiB (`kdf`), 1.7 KiB
/// (`deriveKeys`); 4 KiB is at least twice the deepest.
pub const hash_burn = 4 * 1024;
