// SPDX-License-Identifier: MIT

//! Dead-stack burn for every secret-touching entry point (the DHKEMs, the key
//! schedule, `Context`, the single-shot `seal*`/`open*`). Each public entry
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

/// Anything that reaches a DHKEM: measured 2026-10-08 when P-384 was std's
/// group (12.6 KiB, the deepest; P-256 9.7 KiB, X25519 2.5 KiB); P-384 is
/// the `p384` module since 2026-10-31, covered by the same stack probe. The
/// `pq.zig` KEMs burn their own `pq_burn_*` below. One size for all keeps the setup/seal/open wrappers,
/// generic over the KEM, simple; 32 KiB of vector stores is well under a
/// microsecond next to a scalar multiply.
pub const kem_burn = 32 * 1024;

/// `Context.seal`/`open`/`exportSecret`: AES-GCM key expansion + GHASH table,
/// 1.8 KiB at most (2026-10-08).
pub const aead_burn = 8 * 1024;

/// `suite.labeledExtract` / `labeledExpand`: one HMAC state plus the 512-byte
/// labeled-info scratch, called a handful of times per KEM / key schedule --
/// tight, not yet measured (`stackprobe2_test.zig`, 2026-10-09).
pub const kdf_burn = 4 * 1024;

/// The `pq.zig` KEMs (std's ML-KEM keeps its polynomial vectors and matrix on
/// the stack): ML-KEM-512/768 and the 768 hybrids, and the 1024 ones. Measured
/// with the burn off, ReleaseFast (`stackprobe_test.zig`, `verbose`, 2026-10-31):
/// the deepest entry point is `fromSeed`/`deriveKeyPair` (key generation) --
/// 768 family 57.8-59.0 KiB (ML-KEM-768 57.8, X-Wing 58.7, MLKEM768-P256 59.0),
/// 1024 family 86.1-87.1 KiB (ML-KEM-1024 86.1, MLKEM1024-P384 87.1);
/// `encapDeterministic` 46.8-47.4 / 64.8-65.4 KiB, `decap` 46.9-47.4 /
/// 62.1-62.6 KiB. The seed's `G(d || k)` residue lies as deep as 84.6 KiB
/// (1024), so the burn must reach the frame bottom, not only the shallow
/// secrets. ML-KEM-512 is shallower than 768.
/// 768: 88 KiB = 1.49x the deepest; 1024: 132 KiB = 1.52x.
pub const pq_burn_768 = 88 * 1024;
pub const pq_burn_1024 = 132 * 1024;

/// `Context.seal`/`open` over `aesgcm`'s expanded key (std AEAD types too):
/// the message transform only, 1.1 KiB deep in ReleaseFast (2026-10-31, AES
/// round keys no longer expanded per message). Was `aead_burn` (8 KiB), which
/// made a 64-byte seal 1.7x Go's.
pub const msg_burn = 2 * 1024;
