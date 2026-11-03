// SPDX-License-Identifier: MIT

//! Dead-stack burn for `Auth.compute` / `sign` / `verify`: the pre-shared key
//! passes through the hash or CMAC state in the body's frame. Each public entry
//! runs its body one frame down (`run`, a `never_inline` call), then zeroes the
//! bytes that body dirtied at that depth. Copied from `aes192/src/burn.zig`
//! (`stack` and `run` identical in every module); `stackprobe_test.zig`
//! measures the depth in ReleaseFast.

/// Zero `n` bytes of stack below the caller.
pub noinline fn stack(comptime n: usize) void {
    // 16-byte volatile vector stores, see aes192/src/burn.zig for why not 32.
    const V = @Vector(2, u64);
    var buf: [n / @sizeOf(V)]V align(16) = undefined;
    const p: [*]align(16) volatile V = &buf;
    for (0..buf.len) |i| p[i] = @splat(0);
}

/// `f(args)` in a frame of its own, then `stack(n)` at the same depth.
pub inline fn run(comptime n: usize, comptime R: type, comptime f: anytype, args: anytype) R {
    const r: R = @call(.never_inline, f, args);
    stack(n);
    return r;
}

/// SHA-512 state + block + CMAC/AES schedule fit well below this; the probe
/// shows the real depth.
pub const mac_burn = 4096;
