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

/// Signing / decryption dirtied 187 KiB in ReleaseFast (2026-10-08): the
/// key is carried at the 4096-bit capacity whatever its size, so the depth
/// does not shrink with the key. ~2 µs of zeroing against a 2048-bit private
/// operation's ~1 ms. Nested public calls (`signPkcs1v15` →
/// `signPkcs1v15Blinded`) burn at each level.
pub const private_op_burn = 200 * 1024;

/// `bcryptPbkdf` and `Blowfish.init` (4 KiB Blowfish state per frame, one
/// SHA-512 of the passphrase): one-shot slow KDF, generous size, not yet
/// measured (`stackprobe2_test.zig`, 2026-10-09).
pub const kdf_burn = 32 * 1024;
