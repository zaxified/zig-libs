// SPDX-License-Identifier: MIT

//! Dead-stack burn for the entry points that decode or encode a secret key
//! through a stack buffer (`parsePrivateKeyPem`, `writePrivateKeyPem`).
//! Each runs its body one frame down (`noinline`), then calls `stack` to zero
//! the bytes that body dirtied at that depth. Copied from `acme`'s
//! `burn.zig`. `noinline` on both is load-bearing: inlined, the body and the
//! burn would share a frame and the burn would land above the body's locals.

/// Zero `n` bytes of stack below the caller.
pub noinline fn stack(comptime n: usize) void {
    // Volatile 16-byte vector stores; 16, not 32, so the frame needs no
    // realignment and the buffer ends at the saved frame pointer (see
    // `acme/src/burn.zig` for the measurement).
    const V = @Vector(2, u64);
    var buf: [n / @sizeOf(V)]V align(16) = undefined;
    const p: [*]align(16) volatile V = &buf;
    for (0..buf.len) |i| p[i] = @splat(0);
}

/// `f(args)` in a frame of its own, then `stack(n)` at the same depth.
/// `inline`, so the argument tuple lives in the entry point's frame -- it holds
/// only pointers and public values, never a secret by value.
pub inline fn run(comptime n: usize, comptime R: type, comptime f: anytype, args: anytype) R {
    const r: R = @call(.never_inline, f, args);
    stack(n);
    return r;
}

/// `b64ct`'s decoder and encoder and the DER walk keep a few words per call
/// frame; generous until a stack probe measures it (SPEC § Open).
pub const pem_burn = 4 * 1024;

/// `writePrivateKeyPem`: its body frame holds the 16 KiB DER buffer
/// (`max_private_der_len`, wiped by its own `defer`), so the burn must reach
/// past it to the frames of `writePkcs8` and `b64ct.encodeWrapped` below
/// (review 2026-11-05 I1).
pub const pem_write_burn = 16 * 1024 + 4 * 1024;
