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

/// `keyschedule` building blocks: HKDF-Expand / Extract / HMAC with a
/// handful of 32..48-byte locals, ~15 per handshake. Deepest 3.1 KiB
/// (`deriveMasterSecret`, its inner `deriveSecret` unburned) of the
/// handshake steps in `stackprobe_test.zig`, ReleaseFast, 2026-10-21; ~2x.
/// Was 8 KiB, a margin from dtls (2026-10-08).
pub const ks_burn = 6 * 1024;

// `certverify.sign` signers, moved with the file from `dtls/src/burn.zig`
// (2026-10-20); depths measured there, by dtls's `stackprobe_test.zig`.

/// ECDSA on the collection's `p256` / `p384` / `p521`, which burn their
/// own signing frames (`sign_burn`): the frames left to this burn reach
/// 2.1 / 2.3 / 2.8 KiB (ReleaseFast, `stackprobe_test.zig` with this burn
/// off, 2026-10-21); ~3x. Was 48 KiB while the signers were std's (38.6 KiB
/// for P-256, 2026-10-08) — 1.4 µs of zeroing per handshake.
pub const ecdsa_burn = 8 * 1024;

/// `signEd25519` dirtied 33.8 KiB in ReleaseFast while it was std's
/// `generateDeterministic` + `sign` (2026-10-08); on `ct25519`'s 4x64 comb it
/// needs a 1.5 KiB field state plus SHA-512 and scalar frames (the stack probe
/// is the check: `stackprobe_test.zig`'s Ed25519 case, per-call key and prepared signer, with the seed, the clamped scalar and the nonce prefix as needles, is clean at 8 KiB). Was 40 KiB -- ~0.8 µs of zeroing per signature (2026-11-01).
pub const ed25519_burn = 8 * 1024;
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
// instantiates its own burn). Depths: how deep this module's frames leave
// non-zero bytes with these burns off (`stackprobe_test.zig`, ReleaseFast,
// 2026-10-21), as generate / serverExchange / sharedSecret; each burn is
// ~1.5-2x the deepest, rounded. The curve groups compute on `ct25519` /
// `p256` / `p384`, which burn their own frames, and the ML-KEM arms are out
// of line, so a curve arm's own frames are ~2 KiB. (2026-10-20, with std's
// curves and the hybrid arms inline, they were 18-67 KiB, the burns
// 96-112 KiB: ~5 µs of zeroing per handshake.)

/// x25519: 0.3 / 2.0 / 0.2 KiB.
pub const kex_x25519_burn = 4 * 1024;
/// secp256r1: 0.7 / 2.0 / 0.2 KiB.
pub const kex_p256_burn = 4 * 1024;
/// secp384r1: 1.6 / 2.0 / 0.2 KiB.
pub const kex_p384_burn = 4 * 1024;
/// X25519MLKEM768 (ML-KEM-768 keygen / encaps / decaps plus X25519): 58.1 /
/// 57.2 / 90.8 KiB measured with std's ML-KEM; after the switch to `mlkem`
/// (2026-11-01) the ReleaseFast probe is clean with this burn, depths not re-measured.
pub const kex_hybrid_burn = 160 * 1024;
/// MLKEM1024 (ML-KEM-1024 keygen / encaps / decaps): 98.4 / 78.1 / 137.2 KiB
/// measured with std's ML-KEM; the probe is clean with `mlkem` too (2026-11-01).
pub const kex_mlkem1024_burn = 256 * 1024;
/// secp521r1 (the collection's `p521`, which burns its own frames): the same
/// ~2 KiB of frames as p384's; the probe (`stackprobe_test.zig`) finds no
/// residue with this burn (and none with 1 KiB either, 2026-11-01).
pub const kex_p521_burn = 4 * 1024;
/// MLKEM512 / MLKEM768 (no second half). One depth measured
/// (ReleaseFast, `stackprobe_test.zig`, burn at 1 KiB, 2026-11-01): MLKEM512
/// generate dirties 39.4 KiB; the rest are scaled from the hybrid / MLKEM1024
/// depths above (X25519MLKEM768 58 / 57 / 91 KiB, MLKEM1024 98 / 78 / 137):
/// ~2x the scaled deepest. The probe finds no residue with these burns.
pub const kex_mlkem512_burn = 128 * 1024;
pub const kex_mlkem768_burn = 160 * 1024;
/// SecP256r1MLKEM768 (ML-KEM-768 plus the collection's P-256): 65.7 / 49.4 /
/// 73.3 KiB (ReleaseFast, `stackprobe_test.zig` with this burn at 1 KiB,
/// 2026-10-31); ~1.5x the deepest.
pub const kex_p256_hybrid_burn = 112 * 1024;
/// SecP384r1MLKEM1024 (ML-KEM-1024 plus the collection's P-384): 98.5 / 67.1 /
/// 107.0 KiB (same measurement); ~1.5x the deepest.
pub const kex_p384_hybrid_burn = 160 * 1024;

/// ffdhe2048..ffdhe8192 (`ffdhe.zig`, `montint.DynModint(8192)`): one burn for
/// all five groups. Depths are measured by `stackprobe_test.zig` (see its
/// ffdhe cases); the initial figure is `DynModint(8192).stack_bytes` rounded up.
pub const kex_ffdhe_burn = 160 * 1024;
