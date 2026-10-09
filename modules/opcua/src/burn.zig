// SPDX-License-Identifier: MIT

//! Dead-stack burn for every secret-touching entry point (the P-SHA256 / AES-256-CBC primitives,
//! the symmetric and asymmetric chunk seal/open, the user-token secret and
//! self-signed credential generation). Each public entry point runs its
//! body one frame down (`run`, a `never_inline` call), then zeroes the bytes
//! that body dirtied at that depth. The body is a separate frame on purpose:
//! inlined into the entry point, the burn would land above the body's locals.
//! `stackprobe_test.zig` goes red when a body outgrows its burn. Copied from
//! `webhooksig/src/burn.zig` (`stack` and `run` identical in every module).

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

/// `pSha256`, `aes256CbcEncrypt`/`Decrypt`: one HMAC / AES context each, per
/// chunk or per key derivation (tight; not yet measured).
pub const prim_burn = 2 * 1024;

/// `symmetricSealChunk` / `symmetricDecryptAndVerify` (and their wrappers): per
/// MSG chunk on the data path — HMAC and AES contexts, the allocator frames
/// the plaintext copy passes through (tight; not yet measured).
pub const chunk_burn = 8 * 1024;

/// RSA-backed one-shot or per-OPN calls (`sealAsymmetricMessage`,
/// `openAsymmetricMessage`, `encryptUserTokenSecret`, `decryptUserTokenSecret`,
/// `ClientCredentials.generateSelfSigned`): the `rsa` module burns its own
/// frames; this covers the wrapper's (generous; not yet measured).
pub const rsa_burn = 64 * 1024;

/// Client request methods (`Session.*`, `Subscription.*`, `SecureChannel.close`):
/// one service round trip through `services.Channel` — encode, seal (copies of
/// the security context live in these frames), socket write/read, open, decode.
/// Per request, so kept moderate (not yet measured).
pub const req_burn = 32 * 1024;

/// `SecureChannel.open`: the OPN exchange — two RSA operations and the nonce
/// derivation, on top of a request round trip (one-shot; not yet measured).
pub const open_burn = 128 * 1024;

/// `Connection.tick`: the server's whole per-event state machine, including
/// the RSA work of an OpenSecureChannel and the symmetric chunk open/seal
/// (not yet measured; a probe needs a live connection).
pub const tick_burn = 128 * 1024;
