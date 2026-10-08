// SPDX-License-Identifier: MIT

//! Dead-stack burn for the host/user-key entry points (`HostKey.sign`,
//! `HostKey.fromOpenSSH` and the two container parsers). Each runs its body one
//! frame down (`run`, a `never_inline` call), then zeroes the bytes that body
//! dirtied at that depth. The body is a separate frame on purpose: inlined
//! into the entry point, the burn would land above the body's locals.
//! `stackprobe_test.zig` goes red when a body outgrows its burn.

/// Zero `n` bytes of stack below the caller.
pub noinline fn stack(comptime n: usize) void {
    // Volatile 32-byte vector stores: `secureZero` is a volatile byte memset
    // (~3 B/ns without libc, 2.5 µs per 8 KiB); this is ~100 B/ns (2026-10-08).
    const V = @Vector(4, u64);
    // align(16), not `V`'s natural 32: a 32-aligned buffer makes the frame
    // realign, and the up to 56 bytes between the saved frame pointer and
    // the buffer stayed unzeroed — a callee's secret survived there
    // (threshold_ecdsa stack probe, 2026-10-08). At 16 the buffer ends at
    // the saved frame pointer.
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

/// `HostKey.sign`: the std Ed25519 body dirtied 6.1 KiB, std ECDSA P-256
/// 7.3 KiB in ReleaseFast (2026-10-09). `rsa.signPkcs1v15` burns its own
/// frames; this one only has to cover ours above it.
pub const sign_burn = 16 * 1024;

/// `HostKey.fromOpenSSH` and the container parsers: the 16 KiB container and
/// 24 KiB base64 buffers plus the key derivation dirtied 48.8 KiB (ed25519)
/// and 52.6 KiB (ecdsa-p256) in ReleaseFast (2026-10-09). `rsa.fromOpenSSH`
/// burns its own frames.
pub const load_burn = 64 * 1024;
