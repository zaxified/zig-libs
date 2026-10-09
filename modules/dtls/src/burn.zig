// SPDX-License-Identifier: MIT

//! Dead-stack burn for the CertificateVerify signers (`certverify.sign`: ECDSA
//! P-256/P-384 and Ed25519 through std, RSA-PSS through `rsa`) and for every
//! secret-touching public entry point of `Connection.zig` (`startHandshake`,
//! `handleFlight`, `installApplicationKeys`, `send`, `recv`: the ECDHE scalars
//! and ML-KEM seeds, the shared secrets, the key schedule, the record keys).
//! Each body runs one frame down (`run`, a `never_inline` call), then the bytes
//! that body dirtied at that depth are zeroed. The body is a separate frame on
//! purpose: inlined into the entry point, the burn would land above the body's
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

/// `f(args)` in a frame of its own, then `stack(n)` at the same depth.
/// `inline`, so the argument tuple lives in the caller's frame — it holds
/// only pointers and public values, never a secret by value.
pub inline fn run(comptime n: usize, comptime R: type, comptime f: anytype, args: anytype) R {
    const r: R = @call(.never_inline, f, args);
    stack(n);
    return r;
}

/// ECDSA through std's `Ecdsa(P256, Sha256)` / `Ecdsa(P384, Sha384)`:
/// `signEcdsaP256` dirtied 38.6 KiB, `signEcdsaP384` 34.1 KiB in ReleaseFast
/// (2026-10-08). One size for both.
pub const ecdsa_burn = 48 * 1024;

/// `signEd25519` (std `Ed25519.KeyPair.generateDeterministic` + `sign`)
/// dirtied 33.8 KiB in ReleaseFast (2026-10-08).
pub const ed25519_burn = 40 * 1024;

/// `signRsaPss`: the frames above `rsa.signPss` (key by pointer, no copy) are
/// well under 1 KiB and `rsa` burns its own 200 KiB below them; before the
/// pointer API the by-value key copies reached 26.9 KiB deep (2026-10-08).
/// 8 KiB is a margin, not a measured depth.
pub const rsa_burn = 8 * 1024;

// `Connection` entry points. Depths are the dirty stack of the unburned body in
// ReleaseFast, from the full-handshake probe (2026-10-09); each burn is ~2x
// that, rounded.

/// `startHandshake`: ClientHello build, the ECDHE / ML-KEM keygen. Deepest case
/// the hybrid group (70.2 KiB; PSK 7.2, X25519 26.9, P-256 33.4).
pub const start_burn = 128 * 1024;

/// `handleFlight`: both roles, the whole key exchange, key schedule, record
/// protection and certificate verification/signing. Deepest case the hybrid
/// client reading the server flight (107.0 KiB); the hybrid server 81.6 KiB,
/// the P-256 server 85.3 KiB.
pub const flight_burn = 224 * 1024;

/// `send` / `recv`: AEAD, the sequence-number mask and the 1500-byte inner
/// plaintext buffer (4.3 KiB at most, ChaCha20-Poly1305).
pub const record_burn = 8 * 1024;

/// `installApplicationKeys`: two HKDF expansions per direction (2.1 KiB).
pub const install_burn = 8 * 1024;

// Public `keyschedule` building blocks: one HKDF-Expand / Extract / HMAC with
// a handful of 32..48-byte locals, one-shot per handshake step. Generous
// margin, not a measured depth.

/// `keyschedule.expandLabel` / `earlySecret` / `pskBinder` /
/// `deriveHandshakeSecret` / `deriveMasterSecret` / `computeFinishedVerifyData`.
pub const ks_burn = 8 * 1024;

/// Per-record `aead.Protection.protect` / `unprotect` and the sequence-number
/// masks: on the data path, so tight (AES-GCM / ChaCha20-Poly1305 plus a
/// 16-byte block). Margin, not a measured depth.
pub const aead_burn = 4 * 1024;
