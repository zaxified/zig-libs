// SPDX-License-Identifier: MIT

//! Dead-stack burn for every entry point that holds a BLS secret (`keyGen`,
//! the `SecretKey`/`SecretKeyShare` codecs, `skToPk`/`sign`/`popProve`,
//! EIP-2333 derivation, `splitSecretKey`, `partialSign`). Each runs its body one
//! frame down (`run`, a `never_inline` call), then zeroes the bytes that body
//! dirtied at that depth. The body is a separate frame on purpose: inlined
//! into the entry point, the burn would land above the body's locals.
//! `stackprobe_test.zig` goes red when a body outgrows its burn.

/// Zero `n` bytes of stack below the caller.
pub noinline fn stack(comptime n: usize) void {
    // Volatile 16-byte vector stores (`secureZero` is a volatile byte memset,
    // ~3 B/ns without libc; this is ~50 B/ns). 16, not 32: with a
    // 32-byte vector LLVM raised the buffer's alignment to 32 for small burns
    // (n <= 2 KiB) and realigned the frame (`and $-32, %rsp`), leaving 32..63 bytes
    // between the buffer top and the saved frame pointer unzeroed -- a callee's
    // 32-byte scalar survived there (voprf stack probe,; `align(16)` on
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

/// `keyGen` (HKDF-SHA-256 + `Fr.reduceWide`) dirtied 2.2 KiB in ReleaseFast.
pub const keygen_burn = 8 * 1024;

/// The `SecretKey` / `SecretKeyShare` codecs dirtied 0.6 KiB.
pub const codec_burn = 4 * 1024;

/// A secret-scalar multiply: `skToPk` 6.3 KiB (G1) / 12.6 KiB (G2), `sign`
/// and `popProve` ≤ 16.5 KiB (hash-to-G2 + G2 multiply), `partialSign`
/// 16.5 KiB, `splitSecretKey` 6.6 KiB in ReleaseFast.
pub const sign_burn = 32 * 1024;

/// EIP-2333: a child derivation holds two 8 KiB Lamport keys and their 16 KiB
/// public key; it dirtied 35 KiB in ReleaseFast.
pub const derive_burn = 64 * 1024;

/// `Fr.randomInto` (the drawn bytes, the by-value `fromBytes` argument and the
/// Montgomery conversion temporaries; the fail-closed `entropy.fill` frames
/// below it) -- sized with the `keygen_burn` margin.
pub const random_burn = 8 * 1024;
