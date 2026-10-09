// SPDX-License-Identifier: MIT

//! Dead-stack burn for every secret-touching entry point (key generation, the
//! KDF steps, the handshake calls, the data-plane `seal`/`open`). Each public entry
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

/// `noise.kdf1`/`kdf2`/`kdf3`/`mixKey`: HMAC-BLAKE2s state, `temp_key` and the
/// output blocks. 1.5 KiB measured (ReleaseFast, 2026-10-09).
pub const kdf_burn = 4 * 1024;

/// `Keypair.generate`/`fromPrivateKey`: the seed, the X25519 clamp and ladder.
/// 2.0 KiB measured.
pub const keypair_burn = 4 * 1024;

/// The four `Handshake` message calls and `deriveTransportKeys`: two DHs, the
/// KDF chain, the AEAD key copies. 3.4 KiB measured.
pub const hs_burn = 8 * 1024;

/// `SendSession.seal`/`RecvSession.open`: the call passes the session key BY
/// VALUE to the AEAD (std's shape), so the copy lands in this frame; the
/// residue sat 0.1-0.3 KiB below the top. `chachapoly` burns its own tree.
/// Per packet, so kept small: ~10 ns.
pub const seal_burn = 1024;

/// The cookie layer (`CookieChecker`/`PeerCookie`) and the control-plane
/// private-key paths (`keyFromBase64Into`, `buildSetRequests`,
/// `DeviceParser`): 1.7 KiB deepest measured (`admit`), the HMAC/BLAKE2s keyed
/// state and the netlink builder frames.
pub const cp_burn = 4 * 1024;
