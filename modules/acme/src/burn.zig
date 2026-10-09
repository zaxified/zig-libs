// SPDX-License-Identifier: MIT

//! Dead-stack burn for the key-handling entry points (`generateKeyPair`,
//! `ecPrivateKeyToPem`, `ecPrivateKeyFromPem`). Each runs its body one frame
//! down (`noinline`), then calls `stack` to zero the bytes that body dirtied at
//! that depth. Copied from `p256`'s `burn.zig`. `noinline` on both is load-bearing: inlined, the body
//! and the burn would share a frame and the burn would land above the body's
//! locals. `stackprobe_test.zig` goes red when a body outgrows its burn.

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

/// A key mint (`jws.generateKeyPair`: entropy draw + seed handling) and the
/// RFC 5915 key codec (`ecPrivateKeyToPem`: DER of the key in a stack buffer;
/// `ecPrivateKeyFromPem`: the decoded scalar) — the stack probe in
/// `stackprobe_test.zig` reads clean with this (2026-10-08). The ECDSA signer
/// itself is `p256`'s and burns its own frames.
pub const key_burn = 8 * 1024;
