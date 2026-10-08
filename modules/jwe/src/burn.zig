// SPDX-License-Identifier: MIT

//! Dead-stack burn for the ECDH-ES secret entry points (`generateEphemeral`,
//! `deriveZ`, `concatKdfSha256`). Each runs its body one frame down
//! (`noinline`), then calls `stack` to zero the bytes that body dirtied at that
//! depth. `noinline` on both is load-bearing: inlined, the body and the burn
//! would share a frame and the burn would land above the body's locals.
//! `stackprobe_test.zig` goes red when a body outgrows its burn.

/// Zero `n` bytes of stack below the caller.
pub noinline fn stack(comptime n: usize) void {
    // Volatile 32-byte vector stores: `secureZero` is a volatile byte memset
    // (~3 B/ns without libc); this is ~100 B/ns (2026-10-08).
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

/// Ephemeral key generation and `deriveZ`: the body plus `P256.mulInto` (which
/// burns its own 8 KiB) and `affineCoordinates` dirtied 8.9-9.3 KiB in
/// ReleaseFast before the fix; the body's own share is the part below
/// `mulInto`'s frame.
pub const ecdh_burn = 8 * 1024;

/// Content encryption (`enc.encrypt` / `enc.decrypt`: std AES-GCM or AES-CBC +
/// HMAC, the CEK in key schedules / GHASH keys / ipad / opad): the CEK was
/// found up to 24.5 KiB below the call in ReleaseFast (2026-10-08).
pub const content_burn = 32 * 1024;

/// The Concat KDF (SHA-256 rounds over `Z`): 750 B in ReleaseFast
/// (2026-10-08).
pub const kdf_burn = 4 * 1024;
