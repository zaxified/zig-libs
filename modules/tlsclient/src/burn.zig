// SPDX-License-Identifier: MIT

//! Dead-stack burn for the client-certificate signature
//! (`Client.signCertificateVerify`) and for the handshake (`Client.init`:
//! the ECDHE key shares and the key schedule). It runs its body one frame down (`run`, a `never_inline` call), then zeroes the bytes that body
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

/// `signCertificateVerify`: std ECDSA P-256 dirtied 7.3 KiB, P-384 7.1 KiB,
/// Ed25519 6.1 KiB in ReleaseFast (2026-10-09).
pub const sign_burn = 16 * 1024;

/// `Client.init`: the body's own frame is 181 KiB (`sub $0x2d580,%rsp`: two
/// 16 KiB cleartext buffers, the certificate chain state, the cipher unions)
/// and the ECDHE + key-schedule callees (ML-KEM decaps + X25519 for the hybrid
/// group, the deepest) reach 237 KiB below the body's entry in ReleaseFast
/// (stack probe, 2026-10-09; P-256/P-384/X25519 alone 227 KiB). 320 KiB leaves a
/// third over the measured depth for the certificate-verification callees,
/// which the probe does not reach; ~3 µs of vector stores next to a handshake.
pub const init_burn = 320 * 1024;
