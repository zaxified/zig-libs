// SPDX-License-Identifier: MIT

//! Dead-stack burn for every BBS entry point that holds a secret (`keyGen`,
//! `skToPk`, `SecretKey.fromBytes`, `sign`, `proofGen`,
//! `ciphersuite.calculateRandomScalars`). Each runs its body one frame down
//! (`run`, a `never_inline` call), then zeroes the bytes that body dirtied at
//! that depth. The body is a separate frame on purpose: inlined into the entry
//! point, the burn would land above the body's locals. `stackprobe_test.zig`
//! goes red when a body outgrows its burn.
//!
//! The heap that held secrets (the message scalars `sign` and `proofGen` map
//! the messages to, the `SK || msgs` hash input as it grows) is handed a
//! `wipealloc.WipingAllocator`: every buffer is zeroed before it goes back to the
//! caller's allocator.

const std = @import("std");

/// Zero `n` bytes of stack below the caller.
pub noinline fn stack(comptime n: usize) void {
    // Volatile 16-byte vector stores (`secureZero` is a volatile byte memset,
    // ~3 B/ns without libc; this is ~50 B/ns). 16, not 32: with a
    // 32-byte vector LLVM raised the buffer's alignment to 32 for small burns
    // (n <= 2 KiB) and realigned the frame (`and $-32, %rsp`), leaving 32..63 bytes
    // between the buffer top and the saved frame pointer unzeroed -- a callee's
    // 32-byte scalar survived there (voprf stack probe,; `align(16)` on
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

// Sizes: the real depth of each body was measured with every burn at 1 KiB,
// `verbose` on, in the probe (deepest residue hit, ReleaseFast);
// each constant keeps about 2x that.

/// `keyGen`: the 4 KiB derive buffer (a copy of the key material) plus
/// `hash_to_scalar` under it; residue reached 4.4 KiB below the entry.
pub const keygen_burn = 12 * 1024;

/// `skToPk` (a G2 multiply by SK) and `SecretKey.fromBytes`/`toBytes`: no
/// residue below 1 KiB (the whole call dirties 11 KiB, none of it SK).
pub const key_burn = 4 * 1024;

/// `sign`: message scalars, `SK || msgs`, `1/(SK+e)` and a G1 multiply;
/// residue reached 1.3 KiB below the entry.
pub const sign_burn = 8 * 1024;

/// `proofGen`: the blinding scalars, `r3`, `r1*r2` and the G1 multiplies by
/// them; residue reached 4.4 KiB below the entry.
pub const proof_burn = 8 * 1024;

/// `calculateRandomScalars`: the raw entropy and the reduction; residue
/// reached 0.9 KiB below the entry.
pub const rng_burn = 2 * 1024;
