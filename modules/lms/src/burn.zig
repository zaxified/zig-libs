// SPDX-License-Identifier: MIT

//! Dead-stack burn for the key-generation and signing entry points
//! (`Tree.init`, `Tree.sign`, HSS tree building). Each runs its body one frame
//! down (`run`, a `never_inline` call), then zeroes the bytes that body
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
/// only pointers and public values (`id`, `q`, the level list), never a secret
/// by value.
pub inline fn run(comptime n: usize, comptime R: type, comptime f: anytype, args: anytype) R {
    const r: R = @call(.never_inline, f, args);
    stack(n);
    return r;
}

/// `Tree.init` / `initCached`: the body (with the tree walk and the OTS chains)
/// dirtied 2.2 KiB below the probe's call in ReleaseFast (2026-10-09; the
/// caller's frame and the entry point's are part of that).
pub const init_burn = 4 * 1024;

/// `Tree.sign` / `signWithRandomizer`: 1.2 KiB (LMS, h5/w4) and 1.5 KiB (HSS
/// message signature) in ReleaseFast (2026-10-09). Hits without a burn lay
/// up to 1.5 KiB deep.
pub const sign_burn = 2 * 1024;

/// HSS `ensureTrees` (child seed derivation, child `Tree.init`, the parent's
/// certificate signature): 3.1 KiB in ReleaseFast (2026-10-09).
pub const hss_burn = 4 * 1024;
