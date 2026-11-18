// SPDX-License-Identifier: MIT

//! Dead-stack burn for the secret-key entry points (`KeyPair.generate`, the
//! signers, `toRawSecretKeyPlain`, `sealSecretKey` / `openSecretKey`, the
//! secret-key file codec). Each runs its body one frame down (`run`, a
//! `never_inline` call), then zeroes the bytes that body dirtied at that depth.
//! The body is a separate frame on purpose: inlined into the entry point, the
//! burn would land above the body's locals. `stackprobe_test.zig` goes red
//! when a body outgrows its burn.
//!
//! scrypt's working memory (`xy`, `V`, `dk`) is HEAP, not stack: the seal/open
//! bodies hand it a `wipealloc.WipingAllocator`, which zeroes every buffer before it goes
//! back to the caller's allocator.

const std = @import("std");

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

// Sizes: the body's real depth was measured with every burn at 1 KiB, `verbose`
// on, in the probe (residue hits' depth, ReleaseFast, 2026-10-09); each constant
// keeps about 2x that.

/// `KeyPair.generate`: Ed25519 seed expansion reached 2.7 KiB below the entry.
pub const generate_burn = 8 * 1024;

/// Every Ed25519 signature (`signMessage`, `signDigest`, `signTrustedComment`
/// and the `signFile*` pairs): the std signer reached 3.8 KiB.
pub const sign_burn = 8 * 1024;

/// `sealSecretKey` / `openSecretKey`: BLAKE2b, pbkdf2 and the scrypt frames
/// reached 1.4 KiB (dirty total 2.2 KiB; scrypt's big buffers are on the heap).
pub const kdf_burn = 8 * 1024;

/// `toRawSecretKeyPlain` and the secret-key file codec (base64, parse, write):
/// no residue below 1 KiB, dirty total 1.2 KiB.
pub const codec_burn = 4 * 1024;
