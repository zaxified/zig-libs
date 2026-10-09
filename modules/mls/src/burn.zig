// SPDX-License-Identifier: MIT

//! Dead-stack burn for every secret-touching public entry point of `mls`
//! (the labeled crypto, the key schedule, the secret tree, framing, Welcome,
//! TreeKEM and every `Group` operation). Each public entry point runs its body
//! one frame down (`run`, a `never_inline` call), then zeroes the bytes that
//! body dirtied at that depth. The body is a separate frame on purpose:
//! inlined into the entry point, the burn would land above the body's locals.
//! `stackprobe_test.zig` goes red when a body outgrows its burn. Copied from
//! `hpke/src/burn.zig` (`stack` and `run` identical in every module).

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

/// HKDF-only bodies (`ExpandWithLabel`, `DeriveSecret`, the secret tree,
/// `mlsExporter`, `pskSecret`, the MACs, sender-data/content AEAD): at most
/// 2.5 KiB dirtied in ReleaseFast with 64-byte burns (2026-10-09). On the
/// per-message path, so kept small.
pub const kdf_burn = 4 * 1024;

/// Bodies that reach a KEM, an HPKE context or a signature: 33..35 KiB with
/// 64-byte burns (`hpke`'s own 32 KiB burn included), `protectPrivate` 6.8 KiB.
pub const kem_burn = 48 * 1024;

/// Every `Group` operation: 6.5 KiB (`updateLeaf`) .. 53 KiB (`fromWelcome`)
/// with 64-byte burns (2026-10-09); a Commit is milliseconds, the burn ~2 us.
pub const group_burn = 96 * 1024;
