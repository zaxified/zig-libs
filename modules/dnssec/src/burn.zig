// SPDX-License-Identifier: MIT

//! Dead-stack burn for `sign.signRrset`, the one entry point that holds a
//! zone signing key. Its ECDSA P-256/P-384 and Ed25519 paths sign through
//! `std.crypto`, which leaves the secret scalar in its dead frames (2026-11-27
//! coverage sweep: P-256 12 needle hits 1.5-3 KiB deep, no burn); the RSA and
//! Ed448 paths burn inside their own modules. The body runs one frame down
//! (`run`, a `never_inline` call), then the bytes it dirtied at that depth are
//! zeroed. `stackprobe_test.zig` goes red when the body outgrows the burn.
//! Copied from `hpke/src/burn.zig` (`stack` and `run` identical in every
//! module).

/// Zero `n` bytes of stack below the caller.
pub noinline fn stack(comptime n: usize) void {
    // Volatile 16-byte vector stores (`secureZero` is a volatile byte memset,
    // ~3 B/ns without libc; this is ~50 B/ns). 16, not 32: with a
    // 32-byte vector LLVM raised the buffer's alignment to 32 for small burns
    // (n <= 2 KiB) and realigned the frame (`and $-32, %rsp`), leaving 32..63 bytes
    // between the buffer top and the saved frame pointer unzeroed -- a callee's
    // 32-byte scalar survived there (voprf stack probe; `align(16)` on
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

/// `signRrset`, every algorithm: unburned, the std ECDSA P-256 path dirtied
/// 7.8 KiB in ReleaseFast (2026-11-27, `stackprobe_test.zig`); at 32 KiB every
/// algorithm shows zero residue (RSA and Ed448 burn deeper inside their own
/// modules). ~0.6 µs of zeroing per RRSIG.
pub const sign_burn = 32 * 1024;
