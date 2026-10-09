// SPDX-License-Identifier: MIT

//! Dead-stack burn for the secret-touching steps of `encode.zig` (signing with
//! every algorithm) and of HS* verification in `root.zig` (the keyed HMAC
//! state). Each such step runs one frame down (`run`, a `never_inline` call),
//! then zeroes the bytes that body dirtied at that depth. The body is a
//! separate frame on purpose: inlined into the entry point, the burn would
//! land above the body's locals. `stackprobe_test.zig` goes red when a body
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

/// HS256/384/512 signing and verification: the keyed HMAC body (key ⊕ ipad /
/// opad, the two hash states, the MAC) dirtied 2.4 KiB at most in ReleaseFast
/// (2026-10-09; SHA-512 the deepest).
pub const hmac_burn = 4 * 1024;

/// ES256 / ES384 / Ed25519 signing: the body dirtied 9.6 KiB (ES256, through
/// p256's own burned wrapper), 5.5 KiB (ES384, std's P-384) and 4.2 KiB
/// (Ed25519) in ReleaseFast (2026-10-09). One size for the three.
pub const ec_burn = 16 * 1024;

/// ML-DSA signing, per parameter set: the signer's matrices and polynomial
/// vectors live in the body's frame. Dirtied 96.6 KiB (44), 166.2 KiB (65)
/// and 262.9 KiB (87) in ReleaseFast (2026-10-09), rounded up by ~10-18 %.
/// Sized per set because a burn deeper than the body is stack the caller may
/// not have (a worker thread with a small stack that runs ML-DSA-44 fits;
/// 288 KiB of burn on top of it need not).
pub const mldsa44_burn = 112 * 1024;
pub const mldsa65_burn = 192 * 1024;
pub const mldsa87_burn = 288 * 1024;
