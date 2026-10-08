// SPDX-License-Identifier: MIT

//! Dead-stack burn for the secret-scalar entry points — every public
//! function that takes a `SecretKey` (signing, decryption, the raw RSADP/RSASP1
//! primitives) or produces one (`fromPrimes`/`fromDer`/`fromPem`/`fromPkcs8`/
//! `fromOpenSSH`, `generate`). Before the burn, every signature and decryption
//! left `p`, `q`, `d`, `dP`, `dQ`, `qInv` and the CRT halves on the dead stack,
//! dozens of copies each: `std.crypto.ff` passes its 4096-bit-capacity
//! `Modulus` by value into every operation (2026-10-08). Each runs its body one
//! frame down (`noinline`), then calls `stack` to zero the bytes that body
//! dirtied at that depth. `noinline` on both is load-bearing: inlined, the body
//! and the burn would share a frame and the burn would land above the body's
//! locals. `stackprobe_test.zig` goes red when a body outgrows its burn.

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

/// Signing / decryption dirtied 187 KiB in ReleaseFast (2026-10-08): the
/// key is carried at the 4096-bit capacity whatever its size, so the depth
/// does not shrink with the key. ~2 µs of zeroing against a 2048-bit private
/// operation's ~1 ms. Nested public calls (`signPkcs1v15` →
/// `signPkcs1v15Blinded`) burn at each level.
pub const private_op_burn = 200 * 1024;
