// SPDX-License-Identifier: MIT

//! Dead-stack burn for every secret-touching entry point (the Noise HKDF steps,
//! `HandshakeState` init/write/read, `CipherState`). Each public entry
//! point runs its body one frame down (`run`, a `never_inline` call), then
//! zeroes the bytes that body dirtied at that depth. The body is a separate
//! frame on purpose: inlined into the entry point, the burn would land above
//! the body's locals. `stackprobe_test.zig` goes red when a body outgrows its
//! burn.

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

/// `CipherState`'s three keyed calls: this module's own frame plus the
/// argument copies the AEAD call makes (the AEAD burns its own tree where it
/// is `chachapoly`).
pub const cipher_burn = 1024;

/// The HKDF behind `mixKey`/`mixKeyAndHash`/`split`: HMAC state, the `temp_key`
/// and the outputs. 1.3 KiB measured on SHA-256 (ReleaseFast, 2026-10-09);
/// SHA-512/BLAKE2b states are about twice as large.
pub const hkdf_burn = 4 * 1024;

/// `HandshakeState.init`/`initialize`: the key pairs copied into the frame.
pub const init_burn = 4 * 1024;

/// `HandshakeState.writeMessage`/`readMessage`: the DH (std's X25519, scalar
/// clamp + ladder), key generation, the HKDF and the `Split()`. 3.2 KiB
/// measured on the default suite (ReleaseFast, 2026-10-09). A pluggable DH with
/// a deeper stack (a P-384 DH dirties ~12 KiB) needs a larger burn on top.
pub const hs_burn = 8 * 1024;
