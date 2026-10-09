// SPDX-License-Identifier: MIT

//! Dead-stack burn for every secret-touching entry point (key generation,
//! XEdDSA signing, X3DH / PQXDH initiate and respond, the Double Ratchet
//! `init*` / `encrypt` / `decrypt`). Each public entry
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

/// `generateKeyPair` (2.5 KiB measured, ReleaseFast 2026-10-09).
pub const key_burn = 8 * 1024;

/// `xeddsa.sign` / `libsignal.sign` (3.9 KiB), `generateSignedPreKey` (4.1 KiB).
pub const sign_burn = 12 * 1024;

/// `x3dh.initiate` / `initiateUnverified` (6.9 KiB), `respond` (3.6 KiB).
pub const x3dh_burn = 16 * 1024;

/// `State.initAlice` (3.2 KiB), `encrypt` (5.1 KiB).
pub const ratchet_burn = 12 * 1024;

/// `State.decrypt` with a DH ratchet step and skipped-key bookkeeping (6.2 KiB).
pub const decrypt_burn = 16 * 1024;

/// `pqxdh.generateKemPreKey`: ML-KEM-1024 key generation, 135.5 KiB measured.
pub const kem_gen_burn = 288 * 1024;

/// `pqxdh.initiate*`: ML-KEM-1024 encapsulation, 89.5 KiB measured.
pub const pq_initiate_burn = 192 * 1024;

/// `pqxdh.respond`: ML-KEM-1024 decapsulation (re-encryption), 120.4 KiB.
pub const pq_respond_burn = 256 * 1024;
