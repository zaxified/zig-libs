// SPDX-License-Identifier: MIT
//! spake2plus — SPAKE2+, an AUGMENTED (asymmetric) Password-Authenticated
//! Key Exchange, per RFC 9383, **P-256 / SHA-256 / HKDF-SHA256 /
//! HMAC-SHA256 ciphersuite only** (RFC 9383 §4's
//! `P256-SHA256-HKDF-SHA256-HMAC-SHA256` row — the ciphersuite Matter/
//! Thread device commissioning uses). Two parties, a Prover (the client —
//! knows the password-derived `w0`/`w1`) and a Verifier (the server —
//! stores only `w0` and a registration record `L = w1*P`, NEVER `w1`
//! itself), run a two-round key exchange plus a key-confirmation round
//! and end up agreeing on `K_shared`, with the Verifier able to
//! authenticate the Prover's knowledge of the password WITHOUT the
//! Verifier's own database compromise directly handing an attacker the
//! password (`L` alone does not reveal `w1` — recovering it is a discrete
//! -log problem — the way a stolen plain SPAKE2 symmetric secret would).
//!
//! **RFC 9382 vs RFC 9383 — do not confuse them.** RFC 9382 is plain
//! SPAKE2, a BALANCED PAKE: both sides hold the identical symmetric
//! secret `w` and the protocol has no asymmetry between the two roles.
//! RFC 9383 (THIS module) is SPAKE2+, an AUGMENTED PAKE: the two sides
//! are asymmetric BY DESIGN — the Prover holds `w0` AND `w1`; the
//! Verifier holds `w0` AND `L = w1*P` (a one-way, discrete-log-hard
//! function of `w1`), never `w1` itself. This is the entire point of the
//! "+" — it is what makes a Verifier-side database compromise NOT
//! directly equivalent to a stolen password (an offline dictionary
//! attack against `L` still costs one exponentiation-and-compare per
//! password guess, unlike a balanced scheme's stolen symmetric secret,
//! which IS the password-derived value outright). Every asymmetric
//! artifact this module carries — the separate `w0`/`w1` split, the
//! registration record `L`, the `V` term each side derives via a
//! DIFFERENT route (Prover: `h*w1*(Y-w0*N)`; Verifier: `h*y*L`) — exists
//! BECAUSE of this augmentation; collapsing it to a single shared `w`
//! would silently turn this into (a differently-transcripted variant of)
//! plain SPAKE2, which is NOT what RFC 9383 specifies and NOT what this
//! module implements.
//!
//! **Status: complete** — all seven crypto cores implemented and
//! KAT-validated, green in Debug + ReleaseFast. REAL pure-bytes
//! pieces: the ciphersuite's fixed group elements `M`/`N` (RFC 9383 §4's
//! P-256 table, transcribed byte-exact — see `NOTICE`), `mPoint`/`nPoint`
//! (parse-once accessors, `std.crypto.ecc.P256.fromSec1`), the
//! length-prefixed transcript encoder `computeTranscript` (RFC 9383 §3.4's
//! `TT = len(Context) || Context || ... || len(w0) || w0`, 8-byte
//! little-endian prefixes, uncompressed SEC1 points — byte-exact against
//! the official Appendix C P-256 vector's 570-byte `TT`), and the
//! `hash`/`mac`/`kdf` wrappers (`std.crypto.hash.sha2.Sha256`,
//! `HmacSha256`, `HkdfSha256`). The seven crypto cores (`computeW0W1`,
//! `computeL`, `proverStart`, `verifierStart`, `deriveKeys`,
//! `proverFinish`, `verifierFinish`) are implemented per each doc
//! comment's RFC 9383 construction: `shareP = x*P + w0*M` /
//! `shareV = y*P + w0*N`; the augmented-PAKE `Z`/`V` terms (Prover uses
//! `w1`, Verifier uses `L = w1*P` — the SPAKE2+ asymmetry); the
//! `K_main = Hash(TT)` → HKDF `K_confirmP`/`K_confirmV`/`K_shared`
//! schedule; and the constant-time confirmation-MAC check (fail-closed to
//! `error.ConfirmationMismatch`). Secret-touching scalar multiplies use
//! the constant-time `P256.mul` (never `mulPublic`). Byte-exact against
//! RFC 9383 Appendix C (L, shareP/shareV, Z, V, TT, K_main, both confirm
//! keys, confirmP/confirmV, K_shared) + an end-to-end Prover↔Verifier
//! round-trip. `computeW0W1` (the PBKDF-half wide-reduction mod n) is
//! implemented per §3.2 but has no standalone byte-exact oracle — the RFC
//! vector supplies w0/w1 directly.
//!
//! `kat_vectors.zig` carries RFC 9383 Appendix C's OFFICIAL P-256/SHA-256
//! test vector (`Context`, `idProver`, `idVerifier`, `w0`, `w1`, `L`,
//! `x`, `shareP`, `y`, `shareV`, `Z`, `V`, `TT`, `K_main`, `K_confirmP`,
//! `K_confirmV`, `confirmP`, `confirmV`, `K_shared`) transcribed
//! byte-exact from the RFC text — see `NOTICE`. `kat_test.zig` asserts
//! (once the cores are filled in): (1) `computeL` reproduces the
//! vector's `L`; (2) `proverStart`/`verifierStart` reproduce `shareP`/
//! `shareV` byte-exact; (3) `proverFinish`'s/`verifierFinish`'s `Z`/`V`
//! terms match; (4) `computeTranscript` reproduces `TT` byte-exact
//! (already real — passes today); (5) `K_main`, `K_confirmP`,
//! `K_confirmV`, `confirmP`, `confirmV`, `K_shared` all byte-exact; (6)
//! both confirmation MACs verify and a tampered share/MAC is rejected;
//! (7) an end-to-end Prover<->Verifier run (using ONLY the public API,
//! feeding the Verifier's `shareP`/`confirmP` output into the Prover and
//! vice versa) agrees on `K_shared`.
//!
//! **`verifierConfirm` — an eighth, ADDITIVE function, not one of the
//! seven cores above.** RFC 9383 Appendix A.5's Verifier flow transmits
//! `confirmV` BEFORE it has received `confirmP` — but `verifierFinish`
//! (one of the seven cores) requires `received_confirm_p` as an input
//! parameter, so it cannot be called yet at that point in a genuinely
//! blind two-party run. `verifierConfirm` is `verifierFinish`'s `Z`/`V`/
//! `TT`/key-schedule computation with the `confirmP` check removed and
//! with everything except `confirmV` kept INSIDE the call — a returned
//! `K_main` or `TT` is one public `deriveKeys`/`kdf` call away from
//! `K_shared`, so withholding merely the `k_shared` field would not have
//! withheld the key — it exists so the real message order
//! (`proverStart` -> `verifierStart` -> `verifierConfirm` ->
//! `proverFinish` -> `verifierFinish`) is drivable through public API
//! alone, with neither party ever needing foreknowledge of the other's
//! confirmation value. `proverFinish` needed no equivalent split:
//! `proverStart` already lets the Prover emit its first message with no
//! peer input, and by the time the Prover acts again it already holds
//! BOTH `shareV` and the Verifier's `confirmV` (RFC 9383's own pseudocode
//! has the Verifier transmit both before the Prover does anything else)
//! — see `verifierConfirm`'s own doc comment and README.md's "Protocol
//! flow" for the runnable sequence.
//!
//! Zig std GAP: yes — `std.crypto.ecc.P256` gives the group (field,
//! scalar, `basePoint`, `mul`, `mulDoubleBasePublic`, `add`/`sub`/`neg`,
//! `fromSec1`/`toUncompressedSec1`/`toCompressedSec1`, `P256.scalar.
//! Scalar` with `fromBytes`/`fromBytes48`/`add`/`sub`/`mul`/`neg`/
//! `invert`/`toBytes`) and `std.crypto.hash.sha2.Sha256` /
//! `std.crypto.auth.hmac.sha2.HmacSha256` / `std.crypto.kdf.hkdf.
//! HkdfSha256` give the hash/MAC/KDF primitives — but std ships no PAKE
//! layer of any kind (balanced or augmented); the entire SPAKE2+
//! construction (fixed `M`/`N`, the `w0`/`w1`/`L` registration split, the
//! `shareP`/`shareV`/`Z`/`V` equations, the length-prefixed transcript,
//! and the confirmation-key schedule) is entirely this module's own.
//! Clean-room from RFC 9383's public specification text (public spec,
//! not copyrightable expression — see `NOTICE`); the official RFC 9383
//! Appendix C test vector is a public specification artifact, cited (not
//! copied from any third-party implementation's test suite) in
//! `kat_vectors.zig`.
//!
//! Only the P-256/SHA-256/HKDF-SHA256/HMAC-SHA256 ciphersuite (RFC 9383
//! §4's first table row) is implemented. RFC 9383 also documents
//! ciphersuites for P-256/SHA-512, P-384, P-521, edwards25519,
//! edwards448, and CMAC-AES-128 variants — none of those are in scope
//! here; each would need its own group/hash/KDF/MAC wiring and is
//! explicitly out of scope for this pass.

const std = @import("std");
// P-256 curve group from the asm-accelerated `p256` module (byte-exact to
// `std.crypto.ecc.P256`) — the RFC 9383 P256-SHA256 ciphersuite group.
const P256 = @import("p256").P256;
const scalar_mod = P256.scalar;
const Scalar = scalar_mod.Scalar;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "SPAKE2+ — an augmented PAKE (RFC 9383), P-256/SHA-256 (the Matter/Thread commissioning PAKE); resists server-compromise.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure computation — no I/O, no wire framing of its own
    .concurrency = .reentrant, // no globals; keys/points are plain value types
    .model_after = "RFC 9383 (\"SPAKE2+, an Augmented Password-Authenticated Key Exchange (PAKE) Protocol\"), §4 P256-SHA256-HKDF-SHA256-HMAC-SHA256 ciphersuite; the asm-accelerated `p256` module (byte-exact to std.crypto.ecc.P256) supplies the curve group, std.crypto.hash.sha2.Sha256 / std.crypto.auth.hmac.sha2.HmacSha256 / std.crypto.kdf.hkdf.HkdfSha256 supply Hash/MAC/KDF",
    .deps = .{"p256"}, // p256 supplies the P-256 curve group (byte-exact to std.crypto.ecc.P256); Hash/MAC/KDF stay on std
};

// ── ciphersuite constants (RFC 9383 §3, §3.4, §4) ───────────────────────

/// `p`, the P-256 group order — RFC 9383's "the large prime" `p` (the
/// cofactor `h` is 1 for P-256: it is a prime-order curve, so there is no
/// smaller subgroup to confine into — see `cofactor_h` below).
pub const group_order = scalar_mod.field_order;

/// RFC 9383 §3: `h`, the cofactor. P-256 is a prime-order Weierstrass
/// curve (unlike, say, edwards25519/edwards448, which RFC 9383 also
/// ciphersuites but this module does not implement), so `h = 1` always —
/// every `h*x*(...)` / `h*y*(...)` term in §3.3's `Z`/`V` equations is
/// therefore literally just `x*(...)` / `y*(...)` for THIS ciphersuite;
/// the multiplication-by-`h` step is a documented no-op here, not
/// omitted by oversight.
pub const cofactor_h: u8 = 1;

/// The fixed-length encoding of a P-256 group element in this module:
/// UNCOMPRESSED SEC1 (`0x04 || X (32) || Y (32)` = 65 bytes,
/// `P256.toUncompressedSec1`/`P256.fromSec1`). RFC 9383 Appendix C states
/// this explicitly for its test vectors ("All points are encoded using
/// the uncompressed format... with a 0x04 octet prefix") and the
/// transcript `TT` in `kat_vectors.zig`'s official vector was
/// independently confirmed (`kat_test.zig`'s passing-today transcript
/// test) to embed `M`/`N`/`shareP`/`shareV`/`Z`/`V` in exactly this
/// 65-byte uncompressed form — NOT the 33-byte compressed form RFC 9383
/// §4's ciphersuite table prints `M`/`N` in (that table's compressed
/// encoding is a compact way to LIST the constants; the wire/transcript
/// encoding actually used is uncompressed).
pub const share_length: usize = 65;

/// The fixed-length encoding of a P-256 scalar (`w0`, `w1`, `x`, `y`):
/// 32-byte big-endian (`P256.scalar.encoded_length`).
pub const scalar_length: usize = 32;

/// `Hash()`'s output length for this ciphersuite (SHA-256): 32 bytes.
/// Also `K_main`'s length (RFC 9383 §3.4: "The length of K_main is equal
/// to the length of the digest output").
pub const hash_length: usize = 32;

/// `M`, RFC 9383 §4's fixed P-256 constant, SEC1-COMPRESSED as printed in
/// the RFC's ciphersuite table (33 bytes: `02` || 32-byte X). Transcribed
/// byte-exact — see `NOTICE`. Its discrete log is deliberately unknown
/// (Appendix B's point-generation procedure); folded into the Prover's
/// share `shareP = x*P + w0*M` (§3.3).
pub const m_compressed_sec1 = [33]u8{
    0x02, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7,
    0x24, 0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab,
    0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f,
};

/// `N`, RFC 9383 §4's fixed P-256 constant, SEC1-COMPRESSED (33 bytes:
/// `03` || 32-byte X). Transcribed byte-exact — see `NOTICE`. Folded into
/// the Verifier's share `shareV = y*P + w0*N` (§3.3).
pub const n_compressed_sec1 = [33]u8{
    0x03, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99,
    0x7f, 0x38, 0xc3, 0x77, 0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49,
    0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49,
};

/// Parses `m_compressed_sec1` into a real P-256 point. REAL — a one-time,
/// deterministic `fromSec1` parse of a fixed constant (on-curve check +
/// `recoverY` under the hood); no cryptographic judgment beyond "did the
/// RFC's own compressed constant parse". Called on every `proverStart`/
/// `verifierFinish` invocation rather than memoized at comptime: `P256.
/// fromSec1`'s `sqrt`-based `recoverY` is not comptime-friendly at this
/// repo's `@setEvalBranchQuota` budget, and re-parsing 33 fixed bytes is
/// negligible cost next to the scalar multiplications this module
/// otherwise performs.
pub fn mPoint() P256 {
    return P256.fromSec1(&m_compressed_sec1) catch unreachable; // m_compressed_sec1 is a validated RFC constant
}

/// Parses `n_compressed_sec1` into a real P-256 point. REAL — see
/// `mPoint`'s doc comment (identical reasoning, the other constant).
pub fn nPoint() P256 {
    return P256.fromSec1(&n_compressed_sec1) catch unreachable; // n_compressed_sec1 is a validated RFC constant
}

// ── Hash / MAC / KDF wrappers (RFC 9383 §4's ciphersuite row) ──────────
//
// REAL — one-line wrappers around std primitives, no protocol-specific
// composition (that composition is `deriveKeys`, which IS a stubbed
// core). `kat_test.zig`'s "REAL TODAY" section checks `mac` directly
// against the official vector's `K_confirmP`/`confirmP` pair, with no
// core involved — this passes right now, before any core is implemented.

/// `Hash()` for this ciphersuite: plain SHA-256 (RFC 9383 §4's `Hash`
/// column). REAL.
pub fn hash(msg: []const u8) [hash_length]u8 {
    var out: [hash_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &out, .{});
    return out;
}

/// `MAC()` for this ciphersuite: HMAC-SHA256 (RFC 9383 §4's `MAC`
/// column). REAL. Used both for key confirmation (`confirmP =
/// MAC(K_confirmP, shareV)`, `confirmV = MAC(K_confirmV, shareP)`, RFC
/// 9383 §3.4) and, transitively, inside `kdf` below (HKDF is built on
/// HMAC).
pub fn mac(key: []const u8, msg: []const u8) [hash_length]u8 {
    var out: [hash_length]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&out, msg, key);
    return out;
}

/// `KDF(salt, IKM, info)` for this ciphersuite: HKDF-SHA256 (RFC 9383
/// §4's `KDF` column), Extract-then-Expand (RFC 5869). REAL — a thin
/// composition of `std.crypto.kdf.hkdf.HkdfSha256.extract`/`.expand`;
/// `len` is comptime so the caller gets a value type back, matching the
/// fixed-size outputs `deriveKeys` needs (64 bytes for the
/// `K_confirmP || K_confirmV` pair, 32 bytes for `K_shared`). RFC 9383
/// §3.4/§3.5 always calls this with `salt = nil` (the empty string, NOT
/// omitted — HKDF-Extract still runs, with an empty-string salt) — every
/// call site in this module passes `""` for `salt`.
pub fn kdf(comptime len: usize, salt: []const u8, ikm: []const u8, info: []const u8) [len]u8 {
    var out: [len]u8 = undefined;
    const prk = std.crypto.kdf.hkdf.HkdfSha256.extract(salt, ikm);
    std.crypto.kdf.hkdf.HkdfSha256.expand(&out, info, prk);
    return out;
}

// ── transcript encoder (RFC 9383 §3.4 / Appendix A.3) — REAL ───────────

/// RFC 9383 §3.4 / Appendix A.3 `ComputeTranscript`:
///
/// ```text
/// TT = len(Context) || Context
///   || len(idProver) || idProver
///   || len(idVerifier) || idVerifier
///   || len(M) || M
///   || len(N) || N
///   || len(shareP) || shareP
///   || len(shareV) || shareV
///   || len(Z) || Z
///   || len(V) || V
///   || len(w0) || w0
/// ```
///
/// Every `len(...)` is an 8-byte LITTLE-ENDIAN length prefix (RFC 9383
/// §3's own definition: "len(S) denote[s] the length of a string in
/// bytes, represented as an eight-byte little-endian number") — NOT
/// big-endian, and NOT a varint; this is the single easiest byte-exact
/// mistake to make transcribing this function. `M`/`N` are THIS
/// ciphersuite's fixed constants (`mPoint()`/`nPoint()`, re-encoded
/// uncompressed via `toUncompressedSec1` — see `share_length`'s doc
/// comment for why uncompressed, not the compressed form §4's table
/// prints them in) — callers do NOT pass `M`/`N` in, exactly mirroring
/// RFC 9383 Appendix A.3's own `ComputeTranscript(Context, idProver,
/// idVerifier, shareP, shareV, Z, V, w0)` signature (no `M`/`N`
/// parameters there either).
///
/// REAL — pure, deterministic byte concatenation; no cryptographic
/// judgment (the field ORDER and the 8-byte-LE prefix width are the only
/// two things that can go wrong, and both are fixed by this function,
/// not left to a caller). Allocates the exact total length via
/// `allocator` (caller frees the returned slice with the same
/// allocator) — `Context`/`idProver`/`idVerifier` are arbitrary-length
/// per RFC 9383 §3 ("The parties may share additional data (the
/// context)..."; identities "may also have digital representations"),
/// so a fixed-size stack buffer cannot bound this function's output in
/// general.
///
/// Byte-exact against RFC 9383 Appendix C's official P-256/SHA-256
/// vector's published `TT` (570 bytes for that vector) — see
/// `kat_test.zig`'s "REAL TODAY" section, which passes right now, with
/// no core implemented (this function has no stub dependency).
pub fn computeTranscript(
    allocator: std.mem.Allocator,
    context: []const u8,
    id_prover: []const u8,
    id_verifier: []const u8,
    share_p: [share_length]u8,
    share_v: [share_length]u8,
    z: [share_length]u8,
    v: [share_length]u8,
    w0: [scalar_length]u8,
) std.mem.Allocator.Error![]u8 {
    const m_bytes = mPoint().toUncompressedSec1();
    const n_bytes = nPoint().toUncompressedSec1();

    const total = 8 + context.len +
        8 + id_prover.len +
        8 + id_verifier.len +
        8 + m_bytes.len +
        8 + n_bytes.len +
        8 + share_p.len +
        8 + share_v.len +
        8 + z.len +
        8 + v.len +
        8 + w0.len;

    const out = try allocator.alloc(u8, total);
    var offset: usize = 0;
    offset = writeField(out, offset, context);
    offset = writeField(out, offset, id_prover);
    offset = writeField(out, offset, id_verifier);
    offset = writeField(out, offset, &m_bytes);
    offset = writeField(out, offset, &n_bytes);
    offset = writeField(out, offset, &share_p);
    offset = writeField(out, offset, &share_v);
    offset = writeField(out, offset, &z);
    offset = writeField(out, offset, &v);
    offset = writeField(out, offset, &w0);
    std.debug.assert(offset == total);
    return out;
}

/// `len(field) || field` — one transcript entry, 8-byte little-endian
/// length prefix (RFC 9383 §3's `len(S)` definition) followed by the raw
/// bytes. Returns the new write offset.
fn writeField(out: []u8, offset: usize, field: []const u8) usize {
    std.mem.writeInt(u64, out[offset..][0..8], field.len, .little);
    var off = offset + 8;
    @memcpy(out[off..][0..field.len], field);
    off += field.len;
    return off;
}

// ── crypto cores (TODO(fable): stubbed — see each doc comment) ─────────

/// The registration-phase scalar pair `(w0, w1)` (RFC 9383 §3.2).
pub const W0W1 = struct {
    w0: [scalar_length]u8,
    w1: [scalar_length]u8,
};

pub const ComputeW0W1Error = error{
    /// `pbkdf_output.len != 80` — this function implements only RFC
    /// 9383 §3.2's RECOMMENDED minimum size for P-256 (`2 *
    /// (ceil(log2(p)) + k)` bits with `k = 64`, `ceil(log2(p)) = 256` ->
    /// `2 * 320` bits = 640 bits = 80 bytes, split into two 40-byte
    /// halves) — not a general variable-length PBKDF-output splitter.
    InvalidPbkdfOutputLength,
};

/// RFC 9383 §3.2's RECOMMENDED method for deriving the registration
/// scalars from a PBKDF output:
///
/// ```text
/// w0s || w1s = pbkdf_output    // two 40-byte (320-bit) halves
/// w0 = w0s mod p
/// w1 = w1s mod p
/// ```
///
/// `p` = `group_order` (the P-256 scalar field order). Each 40-byte half
/// is WIDER than a canonical 32-byte scalar (320 bits vs. the 256-bit
/// group order) BY DESIGN — §3.2: "To control bias, each half must be of
/// length at least ceil(log2(p)) + k bits, with k >= 64. Reducing such
/// integers mod p gives bias at most 2^-k" — so a canonical
/// `Scalar.fromBytes` (which REJECTS anything `>= p` instead of
/// reducing) is the WRONG primitive here; the reduction must go through
/// `std.crypto.ecc.P256.scalar.Scalar.fromBytes48` (zero-pad each
/// 40-byte, big-endian half with 8 LEADING zero bytes to reach 48, then
/// wide-reduce — the same "widen and wide-reduce" pattern `bip340`'s
/// private `reduceToScalar`/`frost`'s `hashToScalar` already establish
/// in this repository for turning an oversized hash/PBKDF output into a
/// canonical scalar).
///
/// No RFC 9383 Appendix C vector exercises this function directly: the
/// appendix states "the choice of PBKDF is omitted, and values for w0
/// and w1 are provided directly" — `kat_vectors.zig`'s vector supplies
/// `w0`/`w1` as already-reduced scalars, not a raw PBKDF output, so
/// there is no official byte-exact oracle for `computeW0W1` itself (see
/// `kat_test.zig`'s coverage note). It is still specified byte-exactly
/// here — via `group_order`/`Scalar.fromBytes48`'s own well-defined
/// semantics — so a correct implementation is unambiguous even without
/// a published KAT.
pub fn computeW0W1(pbkdf_output: []const u8) ComputeW0W1Error!W0W1 {
    if (pbkdf_output.len != 80) return error.InvalidPbkdfOutputLength;
    // Each 40-byte big-endian half, zero-padded with 8 LEADING zero
    // bytes to 48, then wide-reduced mod p via Scalar.fromBytes48 (the
    // widen-and-wide-reduce pattern — see the doc comment above).
    var out: W0W1 = undefined;
    var wide = [_]u8{0} ** 48;
    @memcpy(wide[8..48], pbkdf_output[0..40]);
    out.w0 = Scalar.fromBytes48(wide, .big).toBytes(.big);
    @memcpy(wide[8..48], pbkdf_output[40..80]);
    out.w1 = Scalar.fromBytes48(wide, .big).toBytes(.big);
    return out;
}

pub const ComputeLError = error{
    /// `w1` is `0` or `>= group_order` — not a valid scalar
    /// (`Scalar.fromBytes`'s canonical range check).
    InvalidScalar,
};

/// RFC 9383 §3.2: the registration record `L = w1*P` (`P` = the P-256
/// base point, `std.crypto.ecc.P256.basePoint`) — the value the Prover
/// computes once at registration time and hands to the Verifier IN
/// PLACE OF `w1` itself. `w1` is SECRET (it is half of the
/// password-derived material); this multiplication touches secret data,
/// so it MUST use `P256.basePoint.mul` (std's constant-time scalar
/// multiply), never `mulPublic`/`mulDoubleBasePublic` (std's
/// variable-time alternatives, reserved for PUBLIC-input verification
/// equations elsewhere in this repository — see `bip340.verify`'s own
/// precedent). Returns `L` UNCOMPRESSED SEC1 (65 bytes,
/// `P256.toUncompressedSec1`) — RFC 9383 Appendix C's vector publishes
/// `L` in exactly this form.
///
/// Byte-exact target: RFC 9383 Appendix C's official P-256/SHA-256
/// vector's published `L` (`kat_test.zig`).
pub fn computeL(w1: [scalar_length]u8) ComputeLError![share_length]u8 {
    // Canonical range check (rejects w1 >= p); zero is canonical but
    // yields the identity, which mul itself rejects below.
    scalar_mod.rejectNonCanonical(w1, .big) catch return error.InvalidScalar;
    const l = P256.basePoint.mul(w1, .big) catch return error.InvalidScalar;
    return l.toUncompressedSec1();
}

pub const ProverStartError = error{
    /// `x` or `w0` is `0` or `>= group_order`, OR the resulting share
    /// `X` lands on the point at infinity (only possible via an
    /// adversarial/degenerate `w0`, since `x` is freshly random —
    /// defensive, mirrors `bip340.sign`'s own identity-element guard on
    /// its nonce point).
    InvalidScalar,
};

/// RFC 9383 §3.3 / Appendix A.1 `ProverInit`: the Prover's round-1 share.
///
/// ```text
/// X = x*P + w0*M
/// ```
///
/// `x` is the Prover's freshly random ephemeral scalar (`x <- [0, p-1]`,
/// RFC 9383 §3.3 — the CALLER's responsibility to source from a CSPRNG,
/// same division of labor as `bip340.sign`'s `aux_rand`/nonce inputs:
/// this function takes `x` as an explicit parameter rather than
/// generating it internally, so the KAT vector's fixed `x` can be
/// replayed byte-exactly). `w0` is SECRET (password-derived); `x` is
/// secret too (the Prover's own ephemeral). Both multiplications
/// (`x*P`, `w0*M`) MUST use `P256.basePoint.mul`/`mPoint().mul`
/// (constant-time) and be summed via `P256.add` — never the
/// variable-time `mulDoubleBasePublic` (that helper is reserved for
/// PUBLIC-input verification equations elsewhere in this repository,
/// e.g. `bip340.verify`; here BOTH scalars are secret). Returns `X`
/// UNCOMPRESSED SEC1 (65 bytes) — matches `kat_vectors.zig`'s published
/// `shareP`.
///
/// Byte-exact target: RFC 9383 Appendix C's official vector's published
/// `shareP` (`kat_test.zig`).
pub fn proverStart(x: [scalar_length]u8, w0: [scalar_length]u8) ProverStartError![share_length]u8 {
    scalar_mod.rejectNonCanonical(x, .big) catch return error.InvalidScalar;
    scalar_mod.rejectNonCanonical(w0, .big) catch return error.InvalidScalar;
    const x_p = P256.basePoint.mul(x, .big) catch return error.InvalidScalar;
    const w0_m = mPoint().mul(w0, .big) catch return error.InvalidScalar;
    const share = x_p.add(w0_m);
    share.rejectIdentity() catch return error.InvalidScalar;
    return share.toUncompressedSec1();
}

pub const VerifierStartError = error{
    /// Same shape as `ProverStartError` — `y`/`w0` out of range, or the
    /// share lands on the identity.
    InvalidScalar,
};

/// RFC 9383 §3.3 / Appendix A.2 `VerifierFinish`'s share-generation half
/// only (the `Z`/`V` half is `verifierFinish` below — split the same way
/// `proverStart`/`proverFinish` are split, per this module's own task
/// shape, even though RFC 9383's own pseudocode fuses share-generation
/// and `Z`/`V` into one `VerifierFinish` function): the Verifier's
/// round-1 share.
///
/// ```text
/// Y = y*P + w0*N
/// ```
///
/// `y` is the Verifier's freshly random ephemeral scalar (`y <- [0,
/// p-1]`) — same caller-supplies-the-randomness division of labor as
/// `proverStart`'s `x`. `w0` is SECRET; `y` is secret. Identical
/// constant-time-multiply-then-add construction to `proverStart`
/// (`P256.basePoint.mul(y,.big)` + `nPoint().mul(w0,.big)`, via
/// `P256.add`, never `mulDoubleBasePublic`). Returns `Y` UNCOMPRESSED
/// SEC1 (65 bytes) — matches `kat_vectors.zig`'s published `shareV`.
///
/// Byte-exact target: RFC 9383 Appendix C's official vector's published
/// `shareV` (`kat_test.zig`).
pub fn verifierStart(y: [scalar_length]u8, w0: [scalar_length]u8) VerifierStartError![share_length]u8 {
    scalar_mod.rejectNonCanonical(y, .big) catch return error.InvalidScalar;
    scalar_mod.rejectNonCanonical(w0, .big) catch return error.InvalidScalar;
    const y_p = P256.basePoint.mul(y, .big) catch return error.InvalidScalar;
    const w0_n = nPoint().mul(w0, .big) catch return error.InvalidScalar;
    const share = y_p.add(w0_n);
    share.rejectIdentity() catch return error.InvalidScalar;
    return share.toUncompressedSec1();
}

/// The four keys RFC 9383 §3.4/§3.5's key schedule derives from a
/// protocol transcript `TT`.
pub const DerivedKeys = struct {
    k_main: [hash_length]u8,
    k_confirm_p: [hash_length]u8,
    k_confirm_v: [hash_length]u8,
    k_shared: [hash_length]u8,
};

/// RFC 9383 §3.4 / Appendix A.4 `ComputeKeySchedule`:
///
/// ```text
/// K_main = Hash(TT)
/// K_confirmP || K_confirmV = KDF(nil, K_main, "ConfirmationKeys")
/// K_shared = KDF(nil, K_main, "SharedKey")
/// ```
///
/// `nil` (RFC 9383 §3's own glossary: "let nil represent an empty
/// string") is the `salt` argument to `kdf` (this module's `kdf(len,
/// salt, ikm, info)` wrapper) — i.e. `salt = ""`, NOT omitted (HKDF-
/// Extract still runs, with an empty-string salt). `K_confirmP ||
/// K_confirmV` is ONE 64-byte HKDF-Expand call whose output splits into
/// two 32-byte halves in order (`K_confirmP` = bytes `[0,32)`,
/// `K_confirmV` = bytes `[32,64)`) — NOT two independent 32-byte `kdf`
/// calls with different `info` strings (that would be a DIFFERENT,
/// non-conformant construction; RFC 9383's own pseudocode is explicit
/// about the `||` split of ONE expand call's output).
///
/// Every sub-step (`hash`, `kdf`) is already REAL — this stub is purely
/// the three-line composition above, but is a named core (not inlined
/// into `proverFinish`/`verifierFinish`) so `kat_test.zig` can pin
/// `K_main`/`K_confirmP`/`K_confirmV`/`K_shared` byte-exact against RFC
/// 9383 Appendix C's official vector WITHOUT first needing
/// `proverFinish`'s/`verifierFinish`'s own `Z`/`V`/`TT` assembly to be
/// correct (this function takes `TT` directly, which
/// `kat_vectors.zig`'s vector also publishes verbatim).
///
/// Byte-exact target: RFC 9383 Appendix C's official vector's published
/// `K_main`, `K_confirmP`, `K_confirmV`, `K_shared` (`kat_test.zig`).
pub fn deriveKeys(tt: []const u8) DerivedKeys {
    const k_main = hash(tt);
    const confirm = kdf(64, "", &k_main, "ConfirmationKeys");
    return .{
        .k_main = k_main,
        .k_confirm_p = confirm[0..32].*,
        .k_confirm_v = confirm[32..64].*,
        .k_shared = kdf(32, "", &k_main, "SharedKey"),
    };
}

pub const ProverFinishError = error{
    OutOfMemory,
    /// `w0`/`w1` out of range, or an intermediate point lands on the
    /// identity (defensive; see `computeL`/`proverStart`'s own guards).
    InvalidScalar,
    /// `share_v` (`Y`, received from the Verifier) fails to parse as a
    /// valid P-256 point, OR is the identity element — RFC 9383 §6's
    /// mandatory group-membership check ("An endpoint MUST abort the
    /// protocol upon receiving any value V such that V*h = I"; for
    /// P-256's prime-order group with `h = 1`, this reduces to "parses,
    /// on-curve, and is not the identity").
    InvalidShareV,
    /// The Verifier's `received_confirm_v` does not match this Prover's
    /// own recomputed `expected_confirmV` — RFC 9383 §3.3's mandatory
    /// key-confirmation check ("Both parties MUST NOT consider the
    /// protocol complete prior to receipt and validation of these key
    /// confirmation messages").
    ConfirmationMismatch,
};

/// One complete result of the Prover's second round (RFC 9383 §3.3 /
/// Appendix A.5's Prover flow, `ProverFinish` plus the confirmation-
/// message exchange that follows it in the same function call — see the
/// module doc comment for why this is fused into one function rather
/// than split further).
pub const ProverFinishResult = struct {
    /// `confirmP = MAC(K_confirmP, shareV)` (RFC 9383 §3.4) — transmit
    /// this to the Verifier to complete key confirmation.
    confirm_p: [hash_length]u8,
    /// The final authenticated shared secret (RFC 9383 §3.5's
    /// `K_shared`). Only meaningful once `verifierFinish`'s (or an
    /// out-of-band mechanism's) confirmation of THIS `confirm_p` has
    /// also succeeded on the Verifier's side — this struct alone proves
    /// the PROVER accepted the Verifier's `confirmV`, not the reverse.
    k_shared: [hash_length]u8,
    /// `Z = h*x*(Y - w0*N)` (RFC 9383 §3.3), UNCOMPRESSED SEC1. Exposed
    /// (not just consumed internally) so `kat_test.zig` can pin it
    /// byte-exact against RFC 9383 Appendix C's published `Z`.
    z: [share_length]u8,
    /// `V = h*w1*(Y - w0*N)` (RFC 9383 §3.3), UNCOMPRESSED SEC1. Exposed
    /// for the same byte-exact-KAT reason as `z`.
    v: [share_length]u8,
    /// The assembled transcript `TT` this call fed to `deriveKeys`.
    /// ALLOCATOR-OWNED — the caller MUST free this with the same
    /// `allocator` passed to `proverFinish` (mirrors `computeTranscript`
    /// itself, and `frost.encodeGroupCommitmentList`'s precedent in this
    /// repository).
    tt: []u8,
    k_main: [hash_length]u8,
    k_confirm_p: [hash_length]u8,
    k_confirm_v: [hash_length]u8,
};

/// RFC 9383 §3.3 / Appendix A.1 `ProverFinish` + Appendix A.5's Prover
/// flow's confirmation-message half, fused into one call (this module's
/// KAT-testing/task shape is synchronous — the whole exchange's inputs
/// are known up front — unlike a live network protocol, where the
/// Prover would `Transmit(confirmP)` only AFTER separately validating
/// `confirmV`; a real transport-layer caller drives that ordering
/// itself, calling this function once it has BOTH `share_v` and
/// `received_confirm_v` in hand):
///
/// ```text
/// // ProverFinish (§3.3 / Appendix A.1):
/// if not_in_subgroup(Y): abort                          // group-membership check, RFC 9383 §6
/// Z = h*x*(Y - w0*N)                                     // h = 1 for P-256 — see cofactor_h
/// V = h*w1*(Y - w0*N)                                    // same (Y - w0*N) term as Z
///
/// // Appendix A.5 Prover, continued:
/// TT = ComputeTranscript(Context, idProver, idVerifier, shareP, shareV, Z, V, w0)
/// (K_confirmP, K_confirmV, K_shared) = ComputeKeySchedule(TT)     // deriveKeys(TT)
/// expected_confirmV = MAC(K_confirmV, shareP)             // == received_confirm_v, or abort
/// confirmP = MAC(K_confirmP, shareV)                      // returned for the caller to transmit
/// return K_shared
/// ```
///
/// `share_p` is `X`, ALREADY computed by a prior `proverStart(x, w0)`
/// call and passed back in here (this function does not recompute it) —
/// the transcript needs `shareP`'s bytes, and the confirmation MAC
/// `expected_confirmV = MAC(K_confirmV, shareP)` needs them too.
/// `share_v` is `Y`, received from the Verifier. `w1` is used ONLY for
/// `V`'s computation (`Z` never touches `w1` — only `x`); both
/// multiplications inside `Y - w0*N` -> `x*(...)`/`w1*(...)` are
/// SECRET-touching and MUST use `P256`'s constant-time `mul`, exactly
/// like `proverStart`/`computeL`.
///
/// Byte-exact target: RFC 9383 Appendix C's official vector's `Z`, `V`,
/// `TT`, `K_main`, `K_confirmP`, `K_confirmV`, `confirmP`, and
/// `K_shared` — all in one call (`kat_test.zig`).
pub fn proverFinish(
    allocator: std.mem.Allocator,
    context: []const u8,
    id_prover: []const u8,
    id_verifier: []const u8,
    w0: [scalar_length]u8,
    w1: [scalar_length]u8,
    x: [scalar_length]u8,
    share_p: [share_length]u8,
    share_v: [share_length]u8,
    received_confirm_v: [hash_length]u8,
) ProverFinishError!ProverFinishResult {
    scalar_mod.rejectNonCanonical(w0, .big) catch return error.InvalidScalar;
    scalar_mod.rejectNonCanonical(w1, .big) catch return error.InvalidScalar;
    scalar_mod.rejectNonCanonical(x, .big) catch return error.InvalidScalar;

    // RFC 9383 §6 group-membership check on the received share Y:
    // parses, on-curve, not the identity (h = 1 — see cofactor_h).
    const y_point = P256.fromSec1(&share_v) catch return error.InvalidShareV;
    y_point.rejectIdentity() catch return error.InvalidShareV;

    // Z = h*x*(Y - w0*N), V = h*w1*(Y - w0*N) — h = 1; compute the
    // shared (Y - w0*N) term once. w0/x/w1 are secret -> constant-time mul.
    const w0_n = nPoint().mul(w0, .big) catch return error.InvalidScalar;
    const diff = y_point.sub(w0_n);
    const z_point = diff.mul(x, .big) catch return error.InvalidScalar;
    const v_point = diff.mul(w1, .big) catch return error.InvalidScalar;
    const z = z_point.toUncompressedSec1();
    const v = v_point.toUncompressedSec1();

    const tt = try computeTranscript(allocator, context, id_prover, id_verifier, share_p, share_v, z, v, w0);
    errdefer allocator.free(tt);

    const keys = deriveKeys(tt);

    // RFC 9383 §3.3's mandatory key-confirmation check, constant-time.
    const expected_confirm_v = mac(&keys.k_confirm_v, &share_p);
    if (!std.crypto.timing_safe.eql([hash_length]u8, expected_confirm_v, received_confirm_v)) {
        return error.ConfirmationMismatch;
    }

    return .{
        .confirm_p = mac(&keys.k_confirm_p, &share_v),
        .k_shared = keys.k_shared,
        .z = z,
        .v = v,
        .tt = tt,
        .k_main = keys.k_main,
        .k_confirm_p = keys.k_confirm_p,
        .k_confirm_v = keys.k_confirm_v,
    };
}

pub const VerifierFinishError = error{
    OutOfMemory,
    InvalidScalar,
    /// `share_p` (`X`, received from the Prover) or `l` (`L`, this
    /// Verifier's own registration record) fails to parse / is the
    /// identity — see `ProverFinishError.InvalidShareV`'s identical RFC
    /// 9383 §6 rationale, mirrored for the Verifier's received value.
    InvalidShareP,
    /// The Prover's `received_confirm_p` does not match this Verifier's
    /// own recomputed `expected_confirmP`.
    ConfirmationMismatch,
};

/// One complete result of the Verifier's second round — the mirror
/// image of `ProverFinishResult` (RFC 9383 §3.3 / Appendix A.2
/// `VerifierFinish`'s `Z`/`V` half, plus Appendix A.5's Verifier flow's
/// confirmation-message half, fused for the same synchronous-KAT reason
/// `proverFinish` documents).
pub const VerifierFinishResult = struct {
    /// `confirmV = MAC(K_confirmV, shareP)` (RFC 9383 §3.4) — transmit
    /// this to the Prover to complete key confirmation.
    confirm_v: [hash_length]u8,
    /// The final authenticated shared secret. Only meaningful once this
    /// call ALSO accepted the Prover's `received_confirm_p` (a non-error
    /// return already implies that — see `ConfirmationMismatch`).
    k_shared: [hash_length]u8,
    /// `Z = h*y*(X - w0*M)` (RFC 9383 §3.3), UNCOMPRESSED SEC1.
    z: [share_length]u8,
    /// `V = h*y*L` (RFC 9383 §3.3), UNCOMPRESSED SEC1 — note this is a
    /// STRUCTURALLY DIFFERENT computation from the Prover's `V = h*w1*
    /// (Y-w0*N)` (different operands entirely: `y` and the REGISTRATION
    /// RECORD `L`, not `w1` and a fresh Diffie-Hellman-style term) — the
    /// two sides land on the SAME group element only because `L = w1*P`
    /// and `Y - w0*N = y*P` (algebraically: `y*L = y*w1*P = w1*y*P =
    /// w1*(Y-w0*N)`, since scalar multiplication commutes) — this
    /// commutativity IS the augmented-PAKE trick that lets the Verifier
    /// authenticate the Prover's `w1` knowledge without ever holding
    /// `w1` itself. See `SPEC.md`'s "Design" section.
    v: [share_length]u8,
    /// ALLOCATOR-OWNED — see `ProverFinishResult.tt`'s identical note.
    tt: []u8,
    k_main: [hash_length]u8,
    k_confirm_p: [hash_length]u8,
    k_confirm_v: [hash_length]u8,
};

pub const VerifierConfirmError = error{
    OutOfMemory,
    /// `w0`/`y` out of range, or an intermediate point lands on the
    /// identity — see `verifierFinish`'s identical guard.
    InvalidScalar,
    /// `share_p` (`X`, received from the Prover) or `l` (`L`, this
    /// Verifier's own registration record) fails to parse / is the
    /// identity — see `VerifierFinishError.InvalidShareP`'s identical RFC
    /// 9383 §6 rationale.
    InvalidShareP,
};

/// One result of the Verifier's confirmation-EMISSION half — deliberately
/// NOT the same struct as `VerifierFinishResult`.
///
/// **The single field IS the contract.** RFC 9383 §3.3 requires that
/// neither party consider the protocol complete before validating the
/// peer's confirmation, and this step runs before the Verifier has seen
/// `confirmP` at all — so everything this call computes on the way to
/// `confirmV` (`Z`, `V`, `TT`, `K_main`, both confirmation keys) stays
/// inside it. `K_main` and `TT` are each a ONE-CALL pre-image of
/// `K_shared` through this module's own public `deriveKeys`/`kdf`, so a
/// struct that returned them for "KAT visibility" would have handed back
/// the very key the gate exists to withhold, in a struct whose
/// documentation promised the opposite. `Z`/`V` are two calls away by the
/// same route (`computeTranscript` then `deriveKeys`, from arguments the
/// caller already holds), so they are withheld too.
///
/// `TT` is allocated and freed inside `verifierConfirm`; unlike
/// `ProverFinishResult`/`VerifierFinishResult` there is nothing here for
/// the caller to free. The byte-exact KAT coverage those fields carried is
/// unaffected: `verifierFinish` recomputes `Z`/`V`/`TT`/the key schedule
/// from the same inputs and returns them after the confirmation check, and
/// `kat_test.zig` pins them there. A wrong `Z` or `V` here still fails
/// loudly — it lands in `confirmV`, which is pinned byte-exact against RFC
/// 9383 Appendix C.
///
/// ⚠ This is a gate against a *caller's mistake*, not against a hostile
/// Verifier: the Verifier holds `w0`, `L`, `y` and both shares, so it can
/// always recompute the key schedule from scratch if it sets out to. What
/// the type now guarantees is that it cannot do so by accident, from a
/// field it was handed.
pub const VerifierConfirmResult = struct {
    /// `confirmV = MAC(K_confirmV, shareP)` (RFC 9383 §3.4) — transmit
    /// this to the Prover. This is the value RFC 9383 Appendix A.5's
    /// Verifier flow sends BEFORE it has seen the Prover's `confirmP`.
    confirm_v: [hash_length]u8,
};

/// RFC 9383 §3.3 / Appendix A.2 `VerifierFinish`'s `Z`/`V` half PLUS
/// Appendix A.5's Verifier flow's `confirmV`-emission half ONLY — the
/// half that runs BEFORE the Verifier has received the Prover's
/// `confirmP`:
///
/// ```text
/// // VerifierFinish (§3.3 / Appendix A.2), Z/V half:
/// if not_in_subgroup(X): abort                          // group-membership check, RFC 9383 §6
/// Z = h*y*(X - w0*M)                                     // h = 1 for P-256
/// V = h*y*L                                              // NOT h*w1*(...) — see VerifierFinishResult.v's doc comment
///
/// // Appendix A.5 Verifier, continued (confirmV half only):
/// TT = ComputeTranscript(Context, idProver, idVerifier, shareP, shareV, Z, V, w0)
/// (K_confirmP, K_confirmV, K_shared) = ComputeKeySchedule(TT)     // deriveKeys(TT)
/// confirmV = MAC(K_confirmV, shareP)                      // returned for the caller to transmit
/// // (expected_confirmP / Receive(confirmP) / the final check and
/// // K_shared return are `verifierFinish`'s job, called separately once
/// // confirmP has actually arrived — see this function's own doc comment.)
/// ```
///
/// **Why this function exists, additively, next to `verifierFinish`.**
/// RFC 9383 Appendix A.5's Verifier pseudocode computes `confirmV` and
/// transmits it BEFORE it has any `confirmP` to check — the Verifier's
/// `Transmit(confirmV)` line comes before its `confirmP = Receive()`
/// line. `verifierFinish` (this file, below) takes `received_confirm_p`
/// as a required parameter, so it literally cannot be called until
/// `confirmP` already exists — which makes it unusable for producing the
/// EARLIER `confirmV` message a genuinely blind Verifier must send
/// first. This function is that earlier step, split out on its own:
/// same `Z`/`V`/`TT`/key-schedule computation as `verifierFinish`, same
/// inputs (everything `verifierFinish` needs EXCEPT `received_confirm_p`,
/// because this step runs before that value exists), but it stops right
/// after emitting `confirmV` — it does NOT check anything received from
/// the Prover, and it returns `confirmV` and NOTHING ELSE (see
/// `VerifierConfirmResult`'s doc comment, where the emptiness of that
/// struct is argued in full): RFC 9383 §3.3 is explicit that neither
/// party may consider the protocol complete before validating the peer's
/// confirmation, and `K_shared` is only ever safe to hand back from
/// `verifierFinish`, once `received_confirm_p` has actually been checked.
/// Withholding the `k_shared` FIELD is not enough to make that true — a
/// returned `K_main` or `TT` is one public `deriveKeys`/`kdf` call away
/// from the same key — which is why this call keeps its whole key
/// schedule and frees its own transcript.
/// A caller drives the real, blind two-party protocol as:
/// `proverStart` -> `verifierStart` -> `verifierConfirm` (send
/// `confirm_v`) -> `proverFinish` (validates `confirm_v`, sends
/// `confirm_p`) -> `verifierFinish` (validates `confirm_p`, both sides
/// now hold `K_shared`) — see README.md's "Protocol flow" for the full
/// runnable sequence.
///
/// `share_v` is `Y`, ALREADY computed by a prior `verifierStart(y, w0)`
/// call and passed back in here (same division of labor as
/// `verifierFinish`). `share_p` is `X`, received from the Prover. `l` is
/// THIS Verifier's registration record for the Prover (`computeL`'s
/// output). Both multiplications inside `X - w0*M` -> `y*(...)`, and
/// `y*L`, are SECRET-touching (`y` is secret) and MUST use `P256`'s
/// constant-time `mul` — identical constant-time discipline to
/// `verifierFinish`.
///
/// Byte-exact target: RFC 9383 Appendix C's official vector's `confirmV`
/// (`kat_test.zig` exercises this function directly, ahead of `confirmP`
/// ever being computed). `confirmV` is `MAC(K_confirmV, shareP)` over a
/// key schedule fed by `Z`/`V`/`TT`, so pinning it pins all of them —
/// and `verifierFinish`'s own KAT pins those intermediates individually,
/// on the same inputs, where returning them is safe.
pub fn verifierConfirm(
    allocator: std.mem.Allocator,
    context: []const u8,
    id_prover: []const u8,
    id_verifier: []const u8,
    w0: [scalar_length]u8,
    l: [share_length]u8,
    y: [scalar_length]u8,
    share_p: [share_length]u8,
    share_v: [share_length]u8,
) VerifierConfirmError!VerifierConfirmResult {
    scalar_mod.rejectNonCanonical(w0, .big) catch return error.InvalidScalar;
    scalar_mod.rejectNonCanonical(y, .big) catch return error.InvalidScalar;

    // RFC 9383 §6 group-membership checks: the received share X, and this
    // Verifier's own stored registration record L.
    const x_point = P256.fromSec1(&share_p) catch return error.InvalidShareP;
    x_point.rejectIdentity() catch return error.InvalidShareP;
    const l_point = P256.fromSec1(&l) catch return error.InvalidShareP;
    l_point.rejectIdentity() catch return error.InvalidShareP;

    // Z = h*y*(X - w0*M), V = h*y*L — h = 1; y/w0 are secret ->
    // constant-time mul. Identical computation to verifierFinish's own
    // Z/V half (deliberately not factored into a shared private helper —
    // this file's own convention keeps each RFC-pseudocode step
    // legible/self-contained, matching proverStart/proverFinish's
    // sibling split above).
    const w0_m = mPoint().mul(w0, .big) catch return error.InvalidScalar;
    const diff = x_point.sub(w0_m);
    const z_point = diff.mul(y, .big) catch return error.InvalidScalar;
    const v_point = l_point.mul(y, .big) catch return error.InvalidScalar;
    const z = z_point.toUncompressedSec1();
    const v = v_point.toUncompressedSec1();

    // Freed here, not returned: see `VerifierConfirmResult`'s doc comment —
    // `TT` is a one-call pre-image of `K_shared`, which this step must not
    // hand back.
    const tt = try computeTranscript(allocator, context, id_prover, id_verifier, share_p, share_v, z, v, w0);
    defer allocator.free(tt);

    const keys = deriveKeys(tt);

    return .{ .confirm_v = mac(&keys.k_confirm_v, &share_p) };
}

/// RFC 9383 §3.3 / Appendix A.2 `VerifierFinish`'s `Z`/`V` half (the
/// share-generation half is `verifierStart` above) + Appendix A.5's
/// Verifier flow's confirmation-message half. **This is the LAST step of
/// the protocol for the Verifier — it requires `received_confirm_p`,
/// which a genuinely blind Verifier does not have yet at the point it
/// must emit its own `confirmV`; for that earlier step, see
/// `verifierConfirm` above** (this function still recomputes `Z`/`V`/`TT`
/// from scratch from the same inputs, so it does not depend on
/// `verifierConfirm` having been called first — only on `confirmP`
/// actually being in hand by the time THIS function is called):
///
/// ```text
/// // VerifierFinish (§3.3 / Appendix A.2), Z/V half only:
/// if not_in_subgroup(X): abort                          // group-membership check, RFC 9383 §6
/// Z = h*y*(X - w0*M)                                     // h = 1 for P-256
/// V = h*y*L                                              // NOT h*w1*(...) — see VerifierFinishResult.v's doc comment
///
/// // Appendix A.5 Verifier, continued:
/// TT = ComputeTranscript(Context, idProver, idVerifier, shareP, shareV, Z, V, w0)
/// (K_confirmP, K_confirmV, K_shared) = ComputeKeySchedule(TT)     // deriveKeys(TT)
/// confirmV = MAC(K_confirmV, shareP)                      // returned for the caller to transmit
/// expected_confirmP = MAC(K_confirmP, shareV)             // == received_confirm_p, or abort
/// return K_shared
/// ```
///
/// `share_v` is `Y`, ALREADY computed by a prior `verifierStart(y, w0)`
/// call and passed back in here. `share_p` is `X`, received from the
/// Prover. `l` is THIS Verifier's registration record for the Prover
/// (`computeL`'s output, stored at registration time — NEVER `w1`
/// itself). Both multiplications inside `X - w0*M` -> `y*(...)`, and
/// `y*L`, are SECRET-touching (`y` is secret) and MUST use `P256`'s
/// constant-time `mul`.
///
/// Byte-exact target: RFC 9383 Appendix C's official vector's `Z`, `V`,
/// `TT`, `K_main`, `K_confirmP`, `K_confirmV`, `confirmV`, and
/// `K_shared` — all in one call (`kat_test.zig`).
pub fn verifierFinish(
    allocator: std.mem.Allocator,
    context: []const u8,
    id_prover: []const u8,
    id_verifier: []const u8,
    w0: [scalar_length]u8,
    l: [share_length]u8,
    y: [scalar_length]u8,
    share_p: [share_length]u8,
    share_v: [share_length]u8,
    received_confirm_p: [hash_length]u8,
) VerifierFinishError!VerifierFinishResult {
    scalar_mod.rejectNonCanonical(w0, .big) catch return error.InvalidScalar;
    scalar_mod.rejectNonCanonical(y, .big) catch return error.InvalidScalar;

    // RFC 9383 §6 group-membership checks: the received share X, and this
    // Verifier's own stored registration record L.
    const x_point = P256.fromSec1(&share_p) catch return error.InvalidShareP;
    x_point.rejectIdentity() catch return error.InvalidShareP;
    const l_point = P256.fromSec1(&l) catch return error.InvalidShareP;
    l_point.rejectIdentity() catch return error.InvalidShareP;

    // Z = h*y*(X - w0*M), V = h*y*L — h = 1; y/w0 are secret ->
    // constant-time mul. NOTE the Verifier's V route uses L, never w1
    // (the augmentation — see VerifierFinishResult.v's doc comment).
    const w0_m = mPoint().mul(w0, .big) catch return error.InvalidScalar;
    const diff = x_point.sub(w0_m);
    const z_point = diff.mul(y, .big) catch return error.InvalidScalar;
    const v_point = l_point.mul(y, .big) catch return error.InvalidScalar;
    const z = z_point.toUncompressedSec1();
    const v = v_point.toUncompressedSec1();

    const tt = try computeTranscript(allocator, context, id_prover, id_verifier, share_p, share_v, z, v, w0);
    errdefer allocator.free(tt);

    const keys = deriveKeys(tt);

    // RFC 9383 §3.3's mandatory key-confirmation check, constant-time.
    const expected_confirm_p = mac(&keys.k_confirm_p, &share_v);
    if (!std.crypto.timing_safe.eql([hash_length]u8, expected_confirm_p, received_confirm_p)) {
        return error.ConfirmationMismatch;
    }

    return .{
        .confirm_v = mac(&keys.k_confirm_v, &share_p),
        .k_shared = keys.k_shared,
        .z = z,
        .v = v,
        .tt = tt,
        .k_main = keys.k_main,
        .k_confirm_p = keys.k_confirm_p,
        .k_confirm_v = keys.k_confirm_v,
    };
}

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too.
test {
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
    _ = @import("bssl_w0w1_vectors.zig");
    _ = @import("bssl_w0w1_test.zig");
}

test "meta.model_after names RFC 9383 / SPAKE2+ (not RFC 9382 / plain SPAKE2)" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "9383") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "9382") == null);
}

test "share_length/scalar_length/hash_length match this ciphersuite's wire sizes" {
    try std.testing.expectEqual(@as(usize, 65), share_length);
    try std.testing.expectEqual(@as(usize, 32), scalar_length);
    try std.testing.expectEqual(@as(usize, 32), hash_length);
}

test "mPoint/nPoint parse the RFC 9383 §4 P-256 constants and land on-curve, non-identity" {
    const m = mPoint();
    const n = nPoint();
    try m.rejectIdentity();
    try n.rejectIdentity();
    // The compressed encodings' own prefix bytes (0x02 / 0x03) must be
    // reproduced by re-compressing the parsed point — this is really just
    // fromSec1/toCompressedSec1 round-tripping, but it pins M and N apart
    // from each other (distinct points, not an accidental typo-duplicate).
    try std.testing.expectEqualSlices(u8, &m_compressed_sec1, &m.toCompressedSec1());
    try std.testing.expectEqualSlices(u8, &n_compressed_sec1, &n.toCompressedSec1());
    try std.testing.expect(!std.mem.eql(u8, &m_compressed_sec1, &n_compressed_sec1));
}

// ── fuzz: the share-decode boundary never panics/OOB on arbitrary bytes ───
//
// `proverFinish`/`verifierFinish`/`verifierConfirm` all feed a
// peer-supplied share (`share_v`/`share_p`, arbitrary wire bytes in a live
// protocol) straight into `P256.fromSec1` before any group-membership
// check runs — this is the module's actual untrusted-wire decode boundary
// (RFC 9383 §6's "MUST abort... upon receiving any value V such that..."
// starts with "does this even parse as a point").
//
// ⚠ An earlier version of this harness drew a random length in [0, 96] and
// called `P256.fromSec1` directly. Measured over 20,000,000 draws, that
// reached a parsing point 0.008% of the time, **and not once in the
// 65-byte UNCOMPRESSED form — the only encoding this module ever receives**
// (both entry points take `[share_length]u8`). It was fuzzing the
// compressed-point path, which no caller can reach, and a random (x, y)
// satisfies the curve equation with probability ~2^-256 so the
// uncompressed path was unreachable by construction, not by luck.
//
// So: fix the buffer at `share_length`, and derive half the draws from a
// REAL encoding the smith then perturbs, which puts valid,
// one-byte-off-valid, and wildly-invalid shares all in range. The share is
// driven through the public entry point rather than `fromSec1` alone, so
// the identity/canonical guards behind the parse are on the fuzzed path
// too. Costs stay bounded: a share that does not parse returns before any
// scalar multiplication happens.

fn fuzzShareDecode(_: void, smith: *std.testing.Smith) !void {
    var share: [share_length]u8 = undefined;
    if (smith.value(bool)) {
        // Perturb a genuine uncompressed encoding: reachable valid input,
        // and every near-miss around it.
        share = mPoint().toUncompressedSec1();
        var i: usize = 0;
        const flips = smith.valueRangeAtMost(u8, 0, 4);
        while (i < flips) : (i += 1) {
            const at = smith.valueRangeAtMost(u8, 0, share_length - 1);
            share[at] ^= smith.value(u8);
        }
    } else {
        smith.bytes(&share);
    }

    // The bare decode boundary.
    if (P256.fromSec1(&share)) |point| {
        point.rejectIdentity() catch {};
    } else |_| {}

    // And the real entry point behind it: parse, RFC 9383 §6 group check,
    // then the secret-touching arithmetic and the transcript allocation.
    const w = [_]u8{0x2a} ** scalar_length;
    if (proverFinish(
        std.testing.allocator,
        "fuzz",
        "p",
        "v",
        w,
        w,
        w,
        share,
        share,
        [_]u8{0} ** hash_length,
    )) |ok| {
        std.testing.allocator.free(ok.tt);
    } else |_| {}
}
test "fuzz the share-decode boundary and the entry point behind it" {
    try std.testing.fuzz({}, fuzzShareDecode, .{});
}

// The module doc comment and SPEC.md both state that EVERY scalar
// multiplication here touches secret material and must therefore go
// through `P256`'s constant-time `mul`, never the variable-time
// `mulPublic`/`mulDoubleBasePublic`. Nothing enforced it: swapping
// `computeL`'s multiply — the one that touches `w1`, whose secrecy is the
// entire point of the "+" in SPAKE2+ — for `mulPublic` left all 29 tests
// green in Debug AND ReleaseFast (measured, audit 2026-09-01).
//
// ⚠ What this test pins is the CALL SITE, which is exactly what the claim
// says: it cannot measure timing. Whether `p256`'s `mul` is itself free of
// secret-dependent branches is `p256`'s to prove, and `p256` has no
// `ctgrind_harness.zig` — so neither module is in the `ct` set that covers
// the sibling `k256`/`montint`. That gap is recorded, not closed here. Do
// not read a green run of this test as a constant-time measurement.
//
// The needles are assembled from fragments so this test cannot match its
// own source text.
test "CT discipline: no secret multiply may use a variable-time routine" {
    const src = @embedFile("root.zig");
    const vartime = [_][]const u8{
        "." ++ "mulPublic(",
        "." ++ "mulDoubleBasePublic(",
    };
    for (vartime) |needle| {
        var at: usize = 0;
        while (std.mem.indexOfPos(u8, src, at, needle)) |hit| {
            // A mention inside a doc/line comment is the claim itself; a
            // call is code. Find the start of the hit's line and reject it
            // only when that line is not a comment.
            const line_start = if (std.mem.lastIndexOfScalar(u8, src[0..hit], '\n')) |nl| nl + 1 else 0;
            const line = std.mem.trimStart(u8, src[line_start..hit], " ");
            if (!std.mem.startsWith(u8, line, "//")) {
                std.debug.print(
                    "\nvariable-time multiply on a secret scalar at byte {d}: {s}\n",
                    .{ hit, src[line_start..@min(src.len, hit + 40)] },
                );
                return error.VariableTimeMultiplyOnSecretScalar;
            }
            at = hit + needle.len;
        }
    }
}

test "hash/mac wrappers agree with std's own primitives directly (sanity, not a KAT)" {
    const msg = "spake2plus scaffold sanity";
    var want_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &want_hash, .{});
    try std.testing.expectEqualSlices(u8, &want_hash, &hash(msg));

    const key = "key";
    var want_mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&want_mac, msg, key);
    try std.testing.expectEqualSlices(u8, &want_mac, &mac(key, msg));
}
