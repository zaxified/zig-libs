// SPDX-License-Identifier: MIT

//! Dead-stack burn for the credential-rotation entry points (`addToken`,
//! `removeToken`, `addBasicUser`, `removeBasicUser`): each runs its body one
//! frame down (`run`, a `never_inline` call), then zeroes the bytes that body
//! dirtied at that depth, so the SHA-256 state that absorbed the token or the
//! password does not survive in a dead frame. Copied from
//! `webhooksig/src/burn.zig` (`stack` and `run` identical in every module).

/// Zero `n` bytes of stack below the caller.
pub noinline fn stack(comptime n: usize) void {
    // Volatile 16-byte vector stores; 16, not 32, so the frame needs no
    // realignment and the buffer ends at the saved frame pointer (see the
    // note in `webhooksig/src/burn.zig`).
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

/// One SHA-256 over a credential plus a list append: a SHA-256 state and one
/// block buffer (< 1 KiB); 2 KiB leaves room for the allocator call under it.
pub const hash_burn = 2 * 1024;
