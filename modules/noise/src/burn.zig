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

/// The burn sizes for one suite, from the stack its primitives dirty
/// (`state.stack_bytes`) plus this module's own frames, doubled for headroom
/// and rounded up to 1 KiB. The floors are the 2026-10-09 sizes of the default
/// suite (X25519, ChaChaPoly, SHA-256), so that suite's burns are unchanged.
/// `stackprobe_test.zig` checks, for every std suite and a P-384 adapter, that
/// each burn reaches under its body.
pub const Sizes = struct {
    /// `CipherState`'s three keyed calls: this module's frame plus the AEAD.
    cipher: usize,
    /// The HKDF behind `mixKey`/`mixKeyAndHash`/`split`: HMAC state, the
    /// `temp_key` and the outputs (1.3 KiB measured on SHA-256).
    hkdf: usize,
    /// `HandshakeState.init`/`initialize`: the key pairs copied into the
    /// frame, the `MixHash` of the prologue and the pre-message keys.
    init: usize,
    /// `HandshakeState.writeMessage`/`readMessage`: key generation, the DH,
    /// and the already burned HKDF / cipher calls nested under it (3.2 KiB
    /// measured on the default suite).
    hs: usize,

    pub fn of(dh: usize, cipher: usize, hash: usize) Sizes {
        const c = sized(1024, own_frame + cipher);
        const k = sized(4 * 1024, own_frame + hash);
        return .{
            .cipher = c,
            .hkdf = k,
            .init = sized(4 * 1024, own_frame + hash),
            // The nested HKDF and cipher burns are exact sizes, not estimates:
            // they only need this module's frames on top, not doubling.
            .hs = @max(sized(8 * 1024, own_frame + dh), 2 * own_frame + @max(k, c)),
        };
    }

    /// This module's frames above a primitive call.
    const own_frame = 512;

    fn sized(floor: usize, need: usize) usize {
        const kib = 1024;
        return @max(floor, (2 * need + kib - 1) / kib * kib);
    }
};
