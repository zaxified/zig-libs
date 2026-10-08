// SPDX-License-Identifier: MIT

//! Dead-stack burn for the module's secret entry points (k256 `group.zig`'s
//! shape). A public entry point runs its body one frame down (`noinline`),
//! then calls `stack` from the same frame, so the zeroed region starts where
//! the body's frames started. Measured by `stackprobe_test.zig`.

/// Zeroes `bytes` of stack at the caller's call depth. `noinline` is
/// load-bearing. Volatile 32-byte vector stores: ~100 B/ns, where
/// `secureZero` (a volatile byte memset) does ~3 B/ns without libc.
pub noinline fn stack(comptime bytes: usize) void {
    const V = @Vector(4, u64);
    // align(16), not `V`'s natural 32: a 32-aligned buffer makes the frame
    // realign, and the up to 56 bytes between the saved frame pointer and
    // the buffer stayed unzeroed — a callee's secret survived there
    // (threshold_ecdsa stack probe, 2026-10-08). At 16 the buffer ends at
    // the saved frame pointer.
    var buf: [bytes / @sizeOf(V)]V align(16) = undefined;
    const p: [*]align(16) volatile V = &buf;
    for (0..buf.len) |i| p[i] = @splat(0);
}
