// SPDX-License-Identifier: MIT

//! Dead-stack burn for the HQC-KEM entry points (`keypair`, `encaps`,
//! `decaps`). Each runs its body one frame down (`run`, a `never_inline` call), then zeroes the bytes that body
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

/// Burn sizes per parameter set (`security_bytes` 16 / 24 / 32), each above
/// the body's measured depth; one size for all sets would make HQC-128 need
/// the stack HQC-256 needs. Measured in ReleaseFast (2026-10-09, burns at
/// 64 B): HQC-128 keypair 40 / encaps 65 / decaps 95 KiB, HQC-256 124 / 203 /
/// 283 KiB; HQC-192 sits between them (the probe covers all three sets).
pub fn sizes(comptime security_bytes: usize) struct { keypair: usize, encaps: usize, decaps: usize } {
    return switch (security_bytes) {
        16 => .{ .keypair = 64 * 1024, .encaps = 96 * 1024, .decaps = 128 * 1024 },
        24 => .{ .keypair = 128 * 1024, .encaps = 192 * 1024, .decaps = 256 * 1024 },
        else => .{ .keypair = 192 * 1024, .encaps = 288 * 1024, .decaps = 384 * 1024 },
    };
}
