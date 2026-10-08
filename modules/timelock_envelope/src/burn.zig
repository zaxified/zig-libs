// SPDX-License-Identifier: MIT

//! Dead-stack burn for the envelope's secret paths (`seal`/`open`,
//! `sealStream`/`openStream`, `deriveKeys`, `deriveStreamKey`). tlock and hqc
//! burn their own frames below these. Each runs its body one frame down (`run`, a `never_inline` call), then zeroes the bytes that body
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

/// `seal`/`open`/`sealStream`/`openStream`: this module's own frames above
/// tlock's and hqc's (which burn themselves). With every burn at 64 B the
/// deepest residue sat 0.8 KiB below the entry in ReleaseFast (2026-10-09).
pub const envelope_burn = 16 * 1024;

/// `deriveKeys` / `deriveStreamKey` (HKDF-SHA-256) dirtied 1.4 KiB (2026-10-09).
pub const kdf_burn = 4 * 1024;
