// SPDX-License-Identifier: MIT

//! Dead-stack burn for every secret-touching entry point (every HMAC sign and
//! verify, the Ed25519 signing key decode and `signEd25519`). Each public entry
//! point runs its body one frame down (`run`, a `never_inline` call), then
//! zeroes the bytes that body dirtied at that depth. The body is a separate
//! frame on purpose: inlined into the entry point, the burn would land above
//! the body's locals. `stackprobe_test.zig` goes red when a body outgrows its
//! burn. Copied from `hpke/src/burn.zig` (`stack` and `run` identical in
//! every module).

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

/// Every HMAC sign/verify (SHA-1/-256/-512, up to `max_keys` keys): dirtied
/// 1.5 KiB (`computeHex`) .. 3.2 KiB (`stripe.verify`) in ReleaseFast with
/// 64-byte burns (`stackprobe_test.zig`, 2026-10-09).
pub const mac_burn = 8 * 1024;

/// Ed25519 key derivation and signing (3.7 / 4.4 KiB) and `standard.verify`
/// with its `v1a` verify loop (8.6 KiB), same measurement.
pub const ed_burn = 16 * 1024;
