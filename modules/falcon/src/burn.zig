// SPDX-License-Identifier: MIT

//! Dead-stack burn for the secret entry points (`generateKeyPair`,
//! `SecretKey.fromBytes`, `SigningKey.toSecretKeyBytes`, `signRandomized` /
//! `signWithRng`, `poly.computePublic`, the SHAKE256 stream behind
//! `ShakePrng`). Each runs its body one frame down (`run`, a `never_inline`
//! call), then zeroes the bytes that body dirtied at that depth. The body is
//! a separate frame on purpose: inlined into the entry point, the burn would
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

/// Pick the size for a degree: `sizes[0]` for Falcon-512 (logn = 9),
/// `sizes[1]` for Falcon-1024 (logn = 10).
pub fn by(comptime logn: u5, comptime sizes: [2]usize) usize {
    return sizes[logn - 9];
}

/// `Keygen.generate` (NTRUGen + NTRUSolve + the basis copy): the body dirtied
/// 55.3 KiB (Falcon-512) and 104.4 KiB (Falcon-1024) in ReleaseFast
/// (2026-10-09).
pub const keygen_burn = [2]usize{ 80 * 1024, 144 * 1024 };

/// `Signer.signWithRng` (the sampler's Gram matrix, FFT scratch and ChaCha
/// state, per attempt): 71.5 KiB (Falcon-512) and 138.3 KiB (Falcon-1024)
/// in ReleaseFast (2026-10-09). At a 1 KiB burn the ChaCha state and the
/// candidate s1/s2 survive at 33..72 KiB below the entry.
pub const sign_burn = [2]usize{ 96 * 1024, 176 * 1024 };

/// `SecretKey.fromBytes`, `SigningKey.toSecretKeyBytes`: 1.2 KiB each
/// (2026-10-09).
pub const codec_burn = [2]usize{ 4 * 1024, 4 * 1024 };

/// `poly.computePublic` (lifted and NTT-domain f, g): the probe's
/// `publicKey` call dirtied 6.4 KiB (Falcon-512) and 12.5 KiB (Falcon-1024)
/// including its public result (2026-10-09).
pub const public_burn = [2]usize{ 16 * 1024, 24 * 1024 };

/// One SHAKE256 absorb / squeeze (`ShakePrng.init`, `ShakePrng.fill`): no
/// residue survives a 1 KiB burn (2026-10-09).
pub const shake_burn = 2 * 1024;
