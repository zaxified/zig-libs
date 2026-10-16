// SPDX-License-Identifier: MIT

//! Dead-stack burn for the TSIG entry points (`tsig.sign`, `tsig.verify`):
//! each runs its body one frame down (`noinline`), then calls `stack` to zero
//! the bytes that body dirtied at that depth -- the HMAC key schedule (the
//! ipad/opad-xored secret) and the inner hash state live there. Copied from
//! `acme`'s `burn.zig` (itself `p256`'s). `noinline` on both is load-bearing:
//! inlined, the body and the burn would share a frame and the burn would land
//! above the body's locals. `stackprobe_test.zig` goes red when a body
//! outgrows its burn.

/// Zero `n` bytes of stack below the caller.
pub noinline fn stack(comptime n: usize) void {
    // Volatile 16-byte vector stores (`secureZero` is a volatile byte memset,
    // ~3 B/ns without libc; this is ~50 B/ns, 2026-10-09). 16, not 32: with a
    // 32-byte vector LLVM raised the buffer's alignment to 32 for small burns
    // (n <= 2 KiB) and realigned the frame (`and $-32, %rsp`), leaving 32..63 bytes
    // between the buffer top and the saved frame pointer unzeroed -- a callee's
    // 32-byte scalar survived there (voprf stack probe, 2026-10-09; `align(16)` on
    // the buffer alone did not stop it). At 16 the frame needs no realignment and
    // the buffer ends at the saved frame pointer.
    const V = @Vector(2, u64);
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

/// HMAC-SHA-1/224/256/384/512 over one message: the keyed state, the hash
/// block buffer and the compression function's schedule (SHA-512: 80 u64
/// words). Sized from the ReleaseFast stack probe (`stackprobe_test.zig`).
pub const tsig_burn = 8 * 1024;
