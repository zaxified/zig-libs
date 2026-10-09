// SPDX-License-Identifier: MIT

//! Dead-stack burn for the host/user-key entry points (`HostKey.sign`,
//! `HostKey.fromOpenSSH` and the two container parsers). Each runs its body one
//! frame down (`run`, a `never_inline` call), then zeroes the bytes that body
//! dirtied at that depth. The body is a separate frame on purpose: inlined
//! into the entry point, the burn would land above the body's locals.
//! `stackprobe_test.zig` goes red when a body outgrows its burn.

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

/// `HostKey.sign`: the std Ed25519 body dirtied 6.1 KiB, std ECDSA P-256
/// 7.3 KiB in ReleaseFast (2026-10-09). `rsa.signPkcs1v15` burns its own
/// frames; this one only has to cover ours above it.
pub const sign_burn = 16 * 1024;

/// `HostKey.fromOpenSSH` and the container parsers: the 16 KiB container and
/// 24 KiB base64 buffers plus the key derivation dirtied 48.8 KiB (ed25519)
/// and 52.6 KiB (ecdsa-p256) in ReleaseFast (2026-10-09). `rsa.fromOpenSSH`
/// burns its own frames.
pub const load_burn = 64 * 1024;

/// The six per-method KEX entry points (`transport.curve25519Kex`, …,
/// `server.dhGroupKexServer`), one size per method: one size for all would
/// make every curve25519 exchange zero ML-KEM's depth. Dirtied in ReleaseFast
/// (client / server, 64 B burns, `stackprobe_test.zig`'s key-exchange test,
/// 2026-10-09; the probe's own frames included): curve25519 30 / 38 KiB,
/// DH group14 43 / 46 KiB, group16 53 / 56 KiB, mlkem768x25519 87 / 98 KiB
/// (std's ML-KEM keeps its matrices on the stack).
pub const kex_x25519_burn = 64 * 1024;
/// `ecdhNistKex` / `ecdhNistKexServer` (P-256, P-384): sized above curve25519
/// for std's P-384 tables; `stackprobe_test.zig`'s key-exchange test finds no
/// scalar or `K` residue under it in ReleaseFast (2026-10-10), the depth
/// itself not yet measured.
pub const kex_ecdh_burn = 96 * 1024;
pub const kex_dh_burn = 128 * 1024;
pub const kex_mlkem_burn = 192 * 1024;

/// `clientKexRound` / `serverKexRound`: the round's own frame, key derivation
/// and cipher install — the KEX below them burns its own, deeper (2026-10-09).
pub const round_burn = 32 * 1024;

/// `Transport.installCipher` (the state is built by value) and `deriveKeys`
/// (2026-10-09).
pub const install_burn = 8 * 1024;

/// `writePacket` / `readPacket`: the plaintext buffer and the per-packet key
/// material (2026-10-09).
pub const record_burn = 16 * 1024;

/// `PasswordCheck.check`: the server's password hook runs one frame down, so
/// its own frames (a hash, a constant-time compare, a lookup) are zeroed too.
/// Once per password attempt; 16 KiB until measured in ReleaseFast.
pub const password_burn = 16 * 1024;
