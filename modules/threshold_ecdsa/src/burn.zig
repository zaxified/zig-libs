// SPDX-License-Identifier: MIT

//! Dead-stack burn for the module's secret entry points (k256 `group.zig`'s
//! shape). A public entry point runs its body one frame down (`noinline`),
//! then calls `stack` from the same frame, so the zeroed region starts where
//! the body's frames started. Measured and pinned by `stackprobe_test.zig`.

/// Zeroes `bytes` of stack at the caller's call depth. `noinline` is
/// load-bearing. Volatile 32-byte vector stores: ~100 B/ns, where
/// `secureZero` (a volatile byte memset) does ~3 B/ns without libc.
pub noinline fn stack(comptime bytes: usize) void {
    // Volatile 16-byte vector stores (`secureZero` is a volatile byte memset,
    // ~3 B/ns without libc; this is ~50 B/ns, 2026-10-09). 16, not 32: with a
    // 32-byte vector LLVM raised the buffer's alignment to 32 for small burns
    // (n <= 2 KiB) and realigned the frame (`and $-32, %rsp`), leaving 32..63 bytes
    // between the buffer top and the saved frame pointer unzeroed -- a callee's
    // 32-byte scalar survived there (voprf stack probe, 2026-10-09; `align(16)` on
    // the buffer alone did not stop it). At 16 the frame needs no realignment and
    // the buffer ends at the saved frame pointer.
    const V = @Vector(2, u64);
    var buf: [bytes / @sizeOf(V)]V align(16) = undefined;
    const p: [*]align(16) volatile V = &buf;
    for (0..buf.len) |i| p[i] = @splat(0);
}
