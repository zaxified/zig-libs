// SPDX-License-Identifier: MIT

//! Dead-stack burn for the secret-touching public entry points of the TLS 1.3
//! building blocks (`keyschedule`, `certverify.sign`). Each body runs one frame down (`run`, a
//! `never_inline` call), then the bytes that body dirtied at that depth are
//! zeroed. The body is a separate frame on purpose: inlined into the entry
//! point, the burn would land above the body's locals. Copied from
//! `dtls/src/burn.zig` (`stack` and `run` identical in every module); dtls's
//! stack probes measure these entry points through its `keyschedule` shim and
//! its `certverify` re-export.

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

/// `keyschedule` building blocks: one HKDF-Expand / Extract / HMAC with a
/// handful of 32..48-byte locals, one-shot per handshake step. Generous
/// margin, not a measured depth (the value dtls used since 2026-10-08).
pub const ks_burn = 8 * 1024;

// `certverify.sign` signers, moved with the file from `dtls/src/burn.zig`
// (2026-10-20); depths measured there, by dtls's `stackprobe_test.zig`.

/// ECDSA through std's `Ecdsa(P256, Sha256)` / `Ecdsa(P384, Sha384)`:
/// `signEcdsaP256` dirtied 38.6 KiB, `signEcdsaP384` 34.1 KiB in ReleaseFast
/// (2026-10-08). One size for both.
pub const ecdsa_burn = 48 * 1024;

/// `signEd25519` (std `Ed25519.KeyPair.generateDeterministic` + `sign`)
/// dirtied 33.8 KiB in ReleaseFast (2026-10-08).
pub const ed25519_burn = 40 * 1024;
/// ML-DSA (std), per parameter set: `sign` borrows the expanded key but
/// keeps its vectors on the stack; `verify` decodes the public key with its
/// matrix A by value. ReleaseFast depths from `stackprobe_test.zig`
/// (2026-10-21), sign / verify: ML-DSA-44 95.9 / 153.4 KiB, ML-DSA-65
/// 163.8 / 217.0 KiB, ML-DSA-87 258.3 / 337.3 KiB; each burn ~1.3x.
pub const mldsa_sign_burn = .{ .mldsa44 = 128 * 1024, .mldsa65 = 224 * 1024, .mldsa87 = 352 * 1024 };
pub const mldsa_verify_burn = .{ .mldsa44 = 208 * 1024, .mldsa65 = 288 * 1024, .mldsa87 = 448 * 1024 };

/// `signRsaPss`: the frames above `rsa.signPss` (key by pointer, no copy) are
/// well under 1 KiB and `rsa` burns its own 200 KiB below them; before the
/// pointer API the by-value key copies reached 26.9 KiB deep (2026-10-08).
/// 8 KiB is a margin, not a measured depth.
pub const rsa_burn = 8 * 1024;

// `kex` entry points, per group (the group is a runtime value, so each arm
// instantiates its own burn). Depths are the dirty stack of the unburned
// bodies in ReleaseFast, from `stackprobe_test.zig` (2026-10-20), as
// generate / serverExchange / sharedSecret; each burn is ~1.6-2x the deepest,
// rounded. `serverExchange` is the deepest of the curve arms because its
// keygen and multiplication are inlined into one frame.

/// x25519: 18.0 / 58.2 / 30.8 KiB.
pub const kex_x25519_burn = 96 * 1024;
/// secp256r1 (std P-256): 24.0 / 64.1 / 36.8 KiB.
pub const kex_p256_burn = 112 * 1024;
/// secp384r1 (std P-384): 27.4 / 66.5 / 39.8 KiB.
pub const kex_p384_burn = 112 * 1024;
/// X25519MLKEM768 (ML-KEM-768 keygen / encaps / decaps plus X25519):
/// 61.4 / 60.9 / 77.6 KiB.
pub const kex_hybrid_burn = 160 * 1024;
/// MLKEM1024 (ML-KEM-1024 keygen / encaps / decaps, out of line):
/// 114.1 / 103.9 / 184.9 KiB.
pub const kex_mlkem1024_burn = 256 * 1024;
