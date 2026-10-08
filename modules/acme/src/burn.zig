// SPDX-License-Identifier: MIT

//! Dead-stack burn for the key-handling entry points (`generateKeyPair`,
//! `ecPrivateKeyToPem`, `ecPrivateKeyFromPem`). Each runs its body one frame
//! down (`noinline`), then calls `stack` to zero the bytes that body dirtied at
//! that depth. Copied from `p256`'s `burn.zig`. `noinline` on both is load-bearing: inlined, the body
//! and the burn would share a frame and the burn would land above the body's
//! locals. `stackprobe_test.zig` goes red when a body outgrows its burn.

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

/// A key mint (`jws.generateKeyPair`: entropy draw + seed handling) and the
/// RFC 5915 key codec (`ecPrivateKeyToPem`: DER of the key in a stack buffer;
/// `ecPrivateKeyFromPem`: the decoded scalar) — the stack probe in
/// `stackprobe_test.zig` reads clean with this (2026-10-08). The ECDSA signer
/// itself is `p256`'s and burns its own frames.
pub const key_burn = 8 * 1024;
