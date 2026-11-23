// SPDX-License-Identifier: MIT

//! Dead-stack burn for the entry points that derive a key from a password
//! (std's PBKDF2 and HMAC frames hold the password-derived state). The body
//! runs one frame down (`noinline`), then `stack` zeroes the bytes it dirtied
//! at that depth. Same pattern as `keycodec`'s `burn.zig`; `noinline` on both
//! is load-bearing: inlined, the body and the burn would share a frame and the
//! burn would land above the body's locals.

/// Zero `n` bytes of stack below the caller.
pub noinline fn stack(comptime n: usize) void {
    // Volatile 16-byte vector stores; 16, not 32, so the frame needs no
    // realignment and the buffer ends at the saved frame pointer.
    const V = @Vector(2, u64);
    var buf: [n / @sizeOf(V)]V align(16) = undefined;
    const p: [*]align(16) volatile V = &buf;
    for (0..buf.len) |i| p[i] = @splat(0);
}

/// `f(args)` in a frame of its own, then `stack(n)` at the same depth.
/// `inline`, so the argument tuple lives in the entry point's frame -- it holds
/// only pointers and public values, never a secret by value.
pub inline fn run(comptime n: usize, comptime R: type, comptime f: anytype, args: anytype) R {
    const r: R = @call(.never_inline, f, args);
    stack(n);
    return r;
}
