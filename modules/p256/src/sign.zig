// SPDX-License-Identifier: MIT

//! sign — ECDSA-P256/SHA-256 sign + verify over p256, present so the scaffold
//! can be anchored against EXTERNAL vectors (the RFC 6979 P-256 test vectors)
//! and against std's signer, not just against std's low-level field/group. Every
//! field multiply, point op, and scalar multiply the scheme below touches runs
//! on p256's own arithmetic, so a passing external vector is an end-to-end proof
//! that the whole p256 stack agrees with the reference.
//!
//!   * `ecdsaVerify` — P-256 ECDSA/SHA-256 verification, cross-checked in
//!     `oracle_test.zig` against signatures produced by
//!     `std.crypto.sign.ecdsa.EcdsaP256Sha256` and in `kat_test.zig` against the
//!     official RFC 6979 vectors.
//!   * `ecdsaSign` — P-256 ECDSA/SHA-256 signing with a caller-supplied nonce
//!     `k`. Signatures round-trip through both p256's and std's verifier
//!     (`oracle_test.zig`), proving sign+verify agree with std end-to-end.
//!   * `ecdsaSignDeterministic` — the same signer with the RFC 6979 nonce, so
//!     the RFC's own published `(r, s)` come back byte for byte.
//!
//! This layer is intentionally thin: it is a verification-harness surface, not
//! the module's reason to exist. A later phase can grow it into a full drop-in
//! for `std.crypto.sign.ecdsa` (DER codec) if desired; for now it proves the
//! primitives against external anchors.

const std = @import("std");
const builtin = @import("builtin");
const group = @import("group.zig");
const scalarmod = @import("scalar.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const P256 = group.P256;
const Scalar = scalarmod.Scalar;
const Fe = @import("field.zig").Fe;
const burn = @import("burn.zig");

/// Std-compatible ECDSA-P256 over `Hash`, instantiated over p256's fast curve.
/// This is `std.crypto.sign.ecdsa.Ecdsa` driven by `group.P256`, so it reuses
/// std's ECDSA scaffolding verbatim (`KeyPair`/`PublicKey`/`Signature`, DER +
/// raw codecs, RFC 6979 deterministic nonces, `generateDeterministic`) while
/// every field/point op runs on p256's asm-accelerated arithmetic. It is the
/// drop-in for `std.crypto.sign.ecdsa.EcdsaP256Sha256` that the P2 HTTPS-API
/// JWT ES256 hot path (and jwe ECDH-ES) rewires onto.
///
/// Constant-time split is exactly std's: signing/keygen commit `k·G` / `d·G`
/// through `group.P256.basePoint.mul` (the CT windowed core), while `verify`
/// runs the two public scalar mults through `group.P256.mulPublic` (vartime
/// wNAF on PUBLIC inputs only). No secret scalar ever touches a vartime mul.
///
/// Byte-exact to `std.crypto.sign.ecdsa.EcdsaP256Sha256`: same construction,
/// same curve math (p256's group is the byte-exact std oracle).
///
/// That argument used to be written here as "so every RFC 6979 / Wycheproof
/// vector that passes on std passes here unchanged" — which was reasoning, not
/// evidence, and in any case said nothing about `ecdsaVerify` below, a
/// separate implementation. Both are now run against all 241 Wycheproof
/// P1363 vectors in `wycheproof_kat_test.zig`.
///
/// Wrapped, not aliased: std's signer keeps the secret key, the nonce and its
/// inverse in its own frames and never wipes them — measured 2026-10-08, every
/// `KeyPair.sign` left `d` and `k` on the dead stack (`stackprobe_test.zig`),
/// and `k` next to the published signature is the private key. The wrapper
/// runs each secret-touching std call one frame down and burns its depth
/// (`burn.zig`). Same surface as std, with two differences: `KeyPair` is this
/// wrapper's own type (same fields), and `sign`/`signPrehashed`/`signer` take
/// it by `*const` — `kp.sign(...)` still reads the same at the call site, but
/// no by-value copy of the key lands in the caller's frame.
///
/// A digest longer than 32 bytes (SHA-384, SHA-512, …) is truncated to its
/// leftmost 256 bits (bits2int) by std's scaffold; `Hash.digest_length` is
/// the size `signPrehashed` takes. The fast `ecdsaVerify` below stays
/// SHA-256-only (`ecdsaVerifyDigest` takes any digest).
pub fn Ecdsa(comptime Hash: type) type {
    return struct {
        const Std = std.crypto.sign.ecdsa.Ecdsa(P256, Hash);

        pub const noise_length = Std.noise_length;
        pub const SecretKey = Std.SecretKey;
        pub const PublicKey = Std.PublicKey;
        /// std's signature type, for interop (`Signature.toStd`/`fromStd`). ⚠ Its
        /// `toDer` panics on r = 0 or s = 0; use `Signature.toDer`.
        pub const StdSignature = Std.Signature;

        /// An ECDSA signature: std's fields and method set, one difference.
        /// `toDer` is total. std's `toDer` indexes the first byte of the r/s
        /// magnitude after trimming leading zeros, so a signature with r = 0 or
        /// s = 0 (which `fromBytes` and `fromDer` accept and verification
        /// refuses) panics there; here a zero scalar encodes as `02 01 00`.
        /// Parsing and verification behave exactly as std's.
        pub const Signature = struct {
            pub const encoded_length = StdSignature.encoded_length;
            pub const der_encoded_length_max = StdSignature.der_encoded_length_max;
            pub const VerifyError = StdSignature.VerifyError;
            comptime {
                std.debug.assert(der_encoded_length_max == der_max_len);
            }

            /// The R component, big-endian.
            r: [32]u8,
            /// The S component, big-endian.
            s: [32]u8,

            pub fn fromStd(sig: StdSignature) Signature {
                return .{ .r = sig.r, .s = sig.s };
            }

            pub fn toStd(sig: Signature) StdSignature {
                return .{ .r = sig.r, .s = sig.s };
            }

            /// Create a Verifier for incremental verification of a signature.
            pub fn verifier(sig: Signature, public_key: PublicKey) Verifier.InitError!Verifier {
                return sig.toStd().verifier(public_key);
            }

            /// Verify the signature against a message and public key.
            pub fn verify(sig: Signature, msg: []const u8, public_key: PublicKey) VerifyError!void {
                return sig.toStd().verify(msg, public_key);
            }

            /// Verify the signature against a message already hashed with `Hash`.
            pub fn verifyPrehashed(sig: Signature, msg_hash: [Hash.digest_length]u8, public_key: PublicKey) VerifyError!void {
                return sig.toStd().verifyPrehashed(msg_hash, public_key);
            }

            /// The raw signature (r, s), big-endian.
            pub fn toBytes(sig: Signature) [encoded_length]u8 {
                return sig.r ++ sig.s;
            }

            /// A signature from a raw (r, s) encoding. ECDSA is big-endian.
            pub fn fromBytes(bytes: [encoded_length]u8) Signature {
                return .{ .r = bytes[0..32].*, .s = bytes[32..64].* };
            }

            /// Encode as DER; total, for every r and s. The slice is at most
            /// `der_encoded_length_max` bytes.
            pub fn toDer(sig: Signature, buf: *[der_encoded_length_max]u8) []u8 {
                const der = rawToDer(sig.toBytes(), buf);
                return buf[0..der.len];
            }

            /// Parse a DER signature with std's parser, so std's verdicts: LENIENT
            /// (accepts r = 0, s = 0 and non-minimal INTEGERs; verification rejects
            /// zero). For strict DER use `p256.sign.derToRaw`.
            pub fn fromDer(der: []const u8) std.crypto.errors.EncodingError!Signature {
                return fromStd(try StdSignature.fromDer(der));
            }
        };
        pub const Verifier = Std.Verifier;

        const StdSignError = std.crypto.errors.IdentityElementError || std.crypto.errors.NonCanonicalError;

        /// Incremental signer; `finalize` is burned like `KeyPair.sign`. Holds the
        /// secret key until finalized.
        pub const Signer = struct {
            inner: Std.Signer,

            pub fn update(self: *Signer, data: []const u8) void {
                self.inner.update(data);
            }

            pub fn finalize(self: *Signer) StdSignError!Signature {
                const r = finalizeUnburned(self);
                burn.stack(burn.sign_burn);
                return r;
            }

            noinline fn finalizeUnburned(self: *Signer) StdSignError!Signature {
                const r: StdSignError!Signature = if (self.inner.finalize()) |sig| Signature.fromStd(sig) else |e| e;
                std.crypto.secureZero(u8, std.mem.asBytes(&self.inner));
                return r;
            }
        };

        /// An ECDSA key pair — std's fields, burned methods.
        pub const KeyPair = struct {
            pub const seed_length = Std.KeyPair.seed_length;

            /// Public part.
            public_key: PublicKey,
            /// Secret scalar.
            secret_key: SecretKey,

            /// Deterministically derive a key pair from a cryptographically secure
            /// secret seed (std's derivation, byte for byte).
            pub fn generateDeterministic(seed: [seed_length]u8) std.crypto.errors.IdentityElementError!KeyPair {
                const r = generateDeterministicUnburned(&seed);
                burn.stack(burn.sign_burn);
                return r;
            }

            noinline fn generateDeterministicUnburned(seed: *const [seed_length]u8) std.crypto.errors.IdentityElementError!KeyPair {
                return fromStd(try Std.KeyPair.generateDeterministic(seed.*));
            }

            /// Generate a new, random key pair. std's shape (the pair comes back
            /// by value); `generateInto` is the pointer twin.
            pub fn generate(io: std.Io) KeyPair {
                var kp: KeyPair = undefined;
                generateInto(&kp, io);
                return kp;
            }

            /// `generate` into `out`: the secret scalar is drawn directly from
            /// `io`'s CSPRNG by rejection (32 random bytes, kept iff
            /// `0 < d < n`), as OpenSSL's and Go's key generation do, instead of
            /// std's HMAC-DRBG over a random seed — that derivation is ~25 % of a
            /// key generation (SHA-256 without SHA-NI) and adds nothing to a seed
            /// that is already uniform. The range test is branch-free arithmetic;
            /// the one branch is on its result, which only says whether a draw
            /// that is then DISCARDED was out of range (probability ~2^−32), so
            /// the kept scalar's value never steers it. The public key comes from
            /// `fromSecretKeyInto` (burned); the draw is wiped.
            pub fn generateInto(out: *KeyPair, io: std.Io) void {
                var sk: SecretKey = undefined;
                defer std.crypto.secureZero(u8, &sk.bytes);
                while (true) {
                    io.random(&sk.bytes);
                    if (!scalarInRange(&sk.bytes)) continue;
                    fromSecretKeyInto(out, &sk) catch continue;
                    return;
                }
            }

            /// `0 < d < n` for a big-endian scalar, without a branch on `d`:
            /// one 256-bit subtract for the borrow and an OR-reduction for zero.
            fn scalarInRange(d: *const [32]u8) bool {
                const v = std.mem.readInt(u256, d, .big);
                const lt: u1 = @subWithOverflow(v, scalarmod.field_order)[1];
                const nz: u1 = @intFromBool(v != 0);
                return (lt & nz) == 1;
            }

            /// Return the key pair for `secret_key`.
            pub fn fromSecretKey(secret_key: SecretKey) std.crypto.errors.IdentityElementError!KeyPair {
                const r = fromSecretKeyUnburned(&secret_key);
                burn.stack(burn.sign_burn);
                return r;
            }

            noinline fn fromSecretKeyUnburned(secret_key: *const SecretKey) std.crypto.errors.IdentityElementError!KeyPair {
                return fromStd(try Std.KeyPair.fromSecretKey(secret_key.*));
            }

            /// `generateDeterministic` with the seed by pointer and the pair into
            /// `out` (zeroed on error): the std-shaped form leaves the pair —
            /// secret half included — in the caller's error-union temporary.
            pub fn generateDeterministicInto(out: *KeyPair, seed: *const [seed_length]u8) std.crypto.errors.IdentityElementError!void {
                const r = generateDeterministicIntoUnburned(out, seed);
                burn.stack(burn.sign_burn);
                return r;
            }

            noinline fn generateDeterministicIntoUnburned(out: *KeyPair, seed: *const [seed_length]u8) std.crypto.errors.IdentityElementError!void {
                errdefer std.crypto.secureZero(u8, std.mem.asBytes(out));
                out.* = fromStd(try Std.KeyPair.generateDeterministic(seed.*));
            }

            /// `fromSecretKey` with the key by pointer and the pair into `out`
            /// (zeroed on error), for the same reason.
            pub fn fromSecretKeyInto(out: *KeyPair, secret_key: *const SecretKey) std.crypto.errors.IdentityElementError!void {
                const r = fromSecretKeyIntoUnburned(out, secret_key);
                burn.stack(burn.sign_burn);
                return r;
            }

            noinline fn fromSecretKeyIntoUnburned(out: *KeyPair, secret_key: *const SecretKey) std.crypto.errors.IdentityElementError!void {
                errdefer std.crypto.secureZero(u8, std.mem.asBytes(out));
                out.* = fromStd(try Std.KeyPair.fromSecretKey(secret_key.*));
            }

            /// Sign `msg`. `noise` null gives a deterministic signature; random
            /// noise hardens against fault attacks (std's construction).
            pub fn sign(key_pair: *const KeyPair, msg: []const u8, noise: ?[noise_length]u8) StdSignError!Signature {
                const r = signUnburned(key_pair, msg, if (noise) |*n| n else null);
                burn.stack(burn.sign_burn);
                return r;
            }

            noinline fn signUnburned(key_pair: *const KeyPair, msg: []const u8, noise: ?*const [noise_length]u8) StdSignError!Signature {
                return Signature.fromStd(try toStd(key_pair).sign(msg, if (noise) |n| n.* else null));
            }

            /// Sign a message already hashed with SHA-256.
            pub fn signPrehashed(key_pair: *const KeyPair, msg_hash: [Hash.digest_length]u8, noise: ?[noise_length]u8) StdSignError!Signature {
                const r = signPrehashedUnburned(key_pair, &msg_hash, if (noise) |*n| n else null);
                burn.stack(burn.sign_burn);
                return r;
            }

            noinline fn signPrehashedUnburned(key_pair: *const KeyPair, msg_hash: *const [Hash.digest_length]u8, noise: ?*const [noise_length]u8) StdSignError!Signature {
                return Signature.fromStd(try toStd(key_pair).signPrehashed(msg_hash.*, if (noise) |n| n.* else null));
            }

            /// An incremental signer over this key pair.
            ///
            /// Burned (`burn.zig`): building the signer copies the key through
            /// std's frames. The result holds the secret key, returned by value —
            /// `signerInto` is the dead-stack-clean form.
            pub fn signer(key_pair: *const KeyPair, noise: ?[noise_length]u8) !Signer {
                const r = signerUnburned(key_pair, if (noise) |*n| n else null);
                burn.stack(burn.sign_burn);
                return r;
            }

            noinline fn signerUnburned(key_pair: *const KeyPair, noise: ?*const [noise_length]u8) !Signer {
                return .{ .inner = try toStd(key_pair).signer(if (noise) |n| n.* else null) };
            }

            /// `signer` into `out` (zeroed on error), noise by pointer: the signer
            /// holds the secret key, so `signer`'s by-value result leaves a copy
            /// in the caller's frame (`stackprobe2_test.zig`, 2026-10-09).
            pub fn signerInto(out: *Signer, key_pair: *const KeyPair, noise: ?*const [noise_length]u8) !void {
                const r = signerIntoUnburned(out, key_pair, noise);
                burn.stack(burn.sign_burn);
                return r;
            }

            noinline fn signerIntoUnburned(out: *Signer, key_pair: *const KeyPair, noise: ?*const [noise_length]u8) !void {
                errdefer std.crypto.secureZero(u8, std.mem.asBytes(out));
                out.* = .{ .inner = try toStd(key_pair).signer(if (noise) |n| n.* else null) };
            }

            inline fn toStd(key_pair: *const KeyPair) Std.KeyPair {
                return .{ .public_key = key_pair.public_key, .secret_key = key_pair.secret_key };
            }

            inline fn fromStd(kp: Std.KeyPair) KeyPair {
                return .{ .public_key = kp.public_key, .secret_key = kp.secret_key };
            }
        };

        /// Sign `msg` with the secret scalar alone, into `out` (`noise` as
        /// `KeyPair.sign`'s, by pointer). std's signer reads only the secret
        /// key, so this skips the `d·G` that `KeyPair.fromSecretKeyInto`
        /// computes for the public half — a server that signs once per
        /// handshake with a key it loaded once paid it every time (14 µs of
        /// a 326 µs qap connection, 2026-10-21). `error.IdentityElement` for
        /// a scalar outside [1, n − 1]. Burned.
        pub fn signWithSecretKey(out: *Signature, secret_key: *const SecretKey, msg: []const u8, noise: ?*const [noise_length]u8) StdSignError!void {
            const r = signWithSecretKeyUnburned(out, secret_key, msg, noise);
            burn.stack(burn.sign_burn);
            return r;
        }

        noinline fn signWithSecretKeyUnburned(out: *Signature, secret_key: *const SecretKey, msg: []const u8, noise: ?*const [noise_length]u8) StdSignError!void {
            // Branches only on whether the key is valid at all.
            if (!KeyPair.scalarInRange(&secret_key.bytes)) return error.IdentityElement;
            // std's `KeyPair.signer` hands only `secret_key` to its `Signer`;
            // the base point stands in for the public half it never reads
            // (a test pins the signatures to `KeyPair.sign`'s).
            const kp: Std.KeyPair = .{ .public_key = .{ .p = P256.basePoint }, .secret_key = secret_key.* };
            out.* = Signature.fromStd(try kp.sign(msg, if (noise) |n| n.* else null));
        }
    };
}

/// ECDSA-P256/SHA-256 (JWS `ES256`, TLS `ecdsa_secp256r1_sha256`): the
/// drop-in for `std.crypto.sign.ecdsa.EcdsaP256Sha256`.
pub const EcdsaP256Sha256 = Ecdsa(Sha256);

pub const SignError = error{ InvalidSecretKey, InvalidNonce };

/// `int(bytes32) mod n` — reduce a 32-byte value into the scalar field (a
/// 32-byte hash or field x-coordinate can exceed `n`, so a plain `fromBytes`
/// would wrongly reject it). This is the ECDSA `e = int(H(m))` and `x(R) mod n`.
fn reduceToScalar(bytes32: [32]u8) Scalar {
    var wide = @as([48]u8, @splat(0));
    wide[16..48].* = bytes32;
    return Scalar.fromBytes48(wide, .big);
}

/// Sign `SHA-256(msg)` under P-256 ECDSA with the caller-supplied nonce `k`
/// (32-byte big-endian, `0 < k < n`). Returns the 64-byte `r || s` signature.
///
/// `r = x(k·G) mod n`, `s = k⁻¹·(e + r·d) mod n` with `e = int(SHA256(msg)) mod n`.
/// Rejects a zero/oversized key or nonce and the (negligible-probability)
/// `r == 0` / `s == 0` degeneracies — the caller retries with a fresh `k`. The
/// nonce is a parameter (not derived here) to keep the scaffold free of an
/// RFC 6979 HMAC-DRBG; the test harness supplies random nonces and cross-checks
/// every signature against std's verifier.
///
/// Key and nonce by pointer, body burned (`burn.zig`): in value form every
/// call left `d`, `k`, `k⁻¹` and `r·d` on the dead stack (`stackprobe_test.zig`,
/// 2026-10-08).
pub fn ecdsaSign(secret_key: *const [32]u8, msg: []const u8, nonce_k: *const [32]u8) SignError![64]u8 {
    const r = ecdsaSignUnburned(secret_key, msg, nonce_k);
    burn.stack(burn.sign_burn);
    return r;
}

noinline fn ecdsaSignUnburned(secret_key: *const [32]u8, msg: []const u8, nonce_k: *const [32]u8) SignError![64]u8 {
    const d = Scalar.fromBytes(secret_key.*, .big) catch return error.InvalidSecretKey;
    if (d.isZero()) return error.InvalidSecretKey;
    const k = Scalar.fromBytes(nonce_k.*, .big) catch return error.InvalidNonce;
    if (k.isZero()) return error.InvalidNonce;

    // R = k·G (constant-time fixed-base); r = x(R) mod n.
    const R = P256.combMulBase(nonce_k.*, .big) catch return error.InvalidNonce;
    const rx = R.affineCoordinates().x.toBytes(.big);
    const r = reduceToScalar(rx);
    if (r.isZero()) return error.InvalidNonce;

    var h: [32]u8 = undefined;
    Sha256.hash(msg, &h, .{});
    const e = reduceToScalar(h);

    // s = k⁻¹·(e + r·d) mod n.
    const s = k.invert().mul(e.add(r.mul(d)));
    if (s.isZero()) return error.InvalidNonce;

    var sig: [64]u8 = undefined;
    sig[0..32].* = r.toBytes(.big);
    sig[32..64].* = s.toBytes(.big);
    return sig;
}

// ── signature encoding: DER ↔ IEEE P1363 (raw r||s) ─────────────────────────
//
// X.509, OCSP, CMS and TLS 1.2 carry ECDSA signatures as the ASN.1
// `Ecdsa-Sig-Value`; JWS/COSE/XML-DSig and this module's own API use raw
// `r || s`. Converting between them is where signature malleability creeps in:
// a decoder that accepts non-minimal INTEGERs, negative INTEGERs, or trailing
// bytes inside the SEQUENCE lets the same signature be re-encoded many ways,
// all of which still verify. `derToRaw` therefore enforces DER strictly rather
// than accepting the wider BER, and is anchored on the 484 Wycheproof
// `ecdsa_secp256r1_sha256` vectors, 310 of which are malformed encodings.
//
// Deliberately self-contained: p256 declares no module dependencies, and
// pulling in an ASN.1 module for two INTEGERs would trade that for far more
// code than the parser below.

/// Longest DER `Ecdsa-Sig-Value` for P-256: `30 46 02 21 00 <32> 02 21 00 <32>`.
pub const der_max_len = 2 + 2 * (2 + 33);

/// Decode a DER `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` into
/// raw `r || s` (32 bytes each, big-endian). Returns null for anything that is
/// not valid DER for this type, including encodings that are legal BER.
/// STRICT, unlike `Ecdsa(..).Signature.fromDer` (std's parser, lenient: it
/// accepts non-minimal INTEGERs such as `02 04 00 00 00 01`); use this one
/// when a signature must have a single encoding.
///
/// Rejected on purpose, each one a way to mint a second encoding of the same
/// signature: a non-minimal length octet, a leading `0x00` that is not needed
/// for the sign bit, a negative INTEGER (high bit set), an empty INTEGER, a
/// value wider than 32 bytes, bytes left over inside the SEQUENCE, and bytes
/// after it. Zero values are left to the verifier, which rejects `r` or `s`
/// of zero anyway.
pub fn derToRaw(sig_der: []const u8) ?[64]u8 {
    if (sig_der.len < 2 or sig_der[0] != 0x30) return null;
    const body = readLen(sig_der[1..]) orelse return null;
    if (body.len_bytes + 1 + body.len != sig_der.len) return null; // trailing data
    var rest = sig_der[1 + body.len_bytes ..][0..body.len];

    var out = @as([64]u8, @splat(0));
    inline for (.{ 0, 32 }) |off| {
        if (rest.len < 2 or rest[0] != 0x02) return null;
        const int = readLen(rest[1..]) orelse return null;
        const start = 1 + int.len_bytes;
        if (start + int.len > rest.len) return null;
        const v = rest[start..][0..int.len];
        if (v.len == 0) return null; // INTEGER must have content
        if (v[0] & 0x80 != 0) return null; // negative
        if (v[0] == 0 and (v.len == 1 or v[1] & 0x80 == 0)) return null; // non-minimal
        const mag = if (v[0] == 0) v[1..] else v;
        if (mag.len > 32) return null;
        @memcpy(out[off + 32 - mag.len ..][0..mag.len], mag);
        rest = rest[start + int.len ..];
    }
    if (rest.len != 0) return null; // extra content inside the SEQUENCE
    return out;
}

const Len = struct { len: usize, len_bytes: usize };

/// DER definite-form length: short form below 128, otherwise the minimal
/// number of length octets with no leading zero. Indefinite form (`0x80`) is
/// BER only and rejected.
fn readLen(bytes: []const u8) ?Len {
    if (bytes.len == 0) return null;
    const first = bytes[0];
    if (first < 0x80) return .{ .len = first, .len_bytes = 1 };
    const n = first & 0x7f;
    if (n == 0 or n > 2 or bytes.len < 1 + n) return null; // 2 octets spans any P-256 sig
    if (bytes[1] == 0) return null; // non-minimal
    var v: usize = 0;
    for (bytes[1..][0..n]) |b| v = (v << 8) | b;
    if (v < 0x80) return null; // should have used the short form
    return .{ .len = v, .len_bytes = 1 + n };
}

/// Encode raw `r || s` as a DER `Ecdsa-Sig-Value` into `buf` (at least
/// `der_max_len` bytes) and return the written slice.
pub fn rawToDer(sig_rs: [64]u8, buf: *[der_max_len]u8) []const u8 {
    var body: [2 * (2 + 33)]u8 = undefined;
    var n: usize = 0;
    inline for (.{ 0, 32 }) |off| {
        var v: []const u8 = sig_rs[off..][0..32];
        while (v.len > 1 and v[0] == 0) v = v[1..];
        const pad: usize = @intFromBool(v[0] & 0x80 != 0);
        body[n] = 0x02;
        body[n + 1] = @intCast(v.len + pad);
        if (pad != 0) body[n + 2] = 0x00;
        @memcpy(body[n + 2 + pad ..][0..v.len], v);
        n += 2 + pad + v.len;
    }
    buf[0] = 0x30;
    buf[1] = @intCast(n); // always < 0x80 for P-256
    @memcpy(buf[2..][0..n], body[0..n]);
    return buf[0 .. 2 + n];
}

// ── RFC 6979 §3.2 deterministic nonce (HMAC-SHA256 DRBG) ────────────────────

/// The RFC 6979 nonce for `(privkey, hash32)`.
///
/// Specialised to P-256/SHA-256, where the hash length equals the group-order
/// byte length (32 == 32), so RFC 6979's `bits2int` is the identity and
/// `bits2octets(H(m))` is just `H(m) mod n` re-encoded. A curve/hash pairing
/// with different sizes would need the bit-shifting the RFC describes; this is
/// deliberately not written generically for a case the module cannot reach.
/// Mirrors `k256.ecdsa_recover`'s DRBG, which the same reasoning covers.
fn rfc6979Nonce(privkey: [32]u8, hash32: [32]u8) Scalar {
    const h1 = reduceToScalar(hash32).toBytes(.big);

    var v: [32]u8 = @as([32]u8, @splat(0x01));
    var k: [32]u8 = @as([32]u8, @splat(0x00));

    var buf: [32 + 1 + 32 + 32]u8 = undefined;
    buf[0..32].* = v;
    buf[32] = 0x00;
    buf[33..65].* = privkey;
    buf[65..97].* = h1;
    var mac = KeyedHmac.init(&k);
    mac.mac(&k, &buf);
    mac = KeyedHmac.init(&k);
    mac.mac(&v, &v);

    buf[0..32].* = v;
    buf[32] = 0x01;
    buf[33..65].* = privkey;
    buf[65..97].* = h1;
    mac.mac(&k, &buf);
    mac = KeyedHmac.init(&k);
    mac.mac(&v, &v);

    while (true) {
        mac.mac(&v, &v);
        // `Scalar.fromBytes` rejects `>= n`, which is exactly RFC 6979's
        // "discard and re-derive" condition; zero is discarded too.
        if (Scalar.fromBytes(v, .big)) |cand| {
            if (!cand.isZero() and !test_retry.take()) return cand;
        } else |_| {}
        var buf2: [32 + 1]u8 = undefined;
        buf2[0..32].* = v;
        buf2[32] = 0x00;
        mac.mac(&k, &buf2);
        mac = KeyedHmac.init(&k);
        mac.mac(&v, &v);
    }
}

/// Test builds only: discard this many candidates as if they were `>= n`, to
/// reach RFC 6979's re-derive step (3.2 h.3: `K = HMAC_K(V || 0x00)`), which a
/// real P-256 key hits with probability ~2^-32 per candidate -- no random test
/// ever gets there, and a K that stops being re-keyed there went unnoticed
/// (mutant, 2026-09-29). Outside tests `take` is a constant false.
const test_retry = if (builtin.is_test) struct {
    var reject: u32 = 0;
    fn take() bool {
        if (reject == 0) return false;
        reject -= 1;
        return true;
    }
} else struct {
    inline fn take() bool {
        return false;
    }
};

/// HMAC-SHA-256 under one fixed 32-byte key with the key schedule done once:
/// the two SHA-256 states that have absorbed `K ^ ipad` and `K ^ opad` are kept
/// and cloned per message, so a MAC costs 2 compressions for a short message
/// instead of `HmacSha256.create`'s 4 (which re-absorbs both pads every call).
/// The RFC 6979 DRBG changes K only twice per nonce, but calls `HMAC_K(V)`
/// several times under the same K. Byte-identical to `HmacSha256.create` (the
/// differential test below). Constant-time: pad derivation and absorption
/// are data-independent, no branch or index depends on the key bytes.
const KeyedHmac = struct {
    inner: Sha256,
    outer: Sha256,

    fn init(key: *const [32]u8) KeyedHmac {
        var ipad: [Sha256.block_length]u8 = @splat(0x36);
        var opad: [Sha256.block_length]u8 = @splat(0x5c);
        for (key, 0..) |kb, i| {
            ipad[i] ^= kb;
            opad[i] ^= kb;
        }
        var self: KeyedHmac = .{ .inner = Sha256.init(.{}), .outer = Sha256.init(.{}) };
        self.inner.update(&ipad);
        self.outer.update(&opad);
        std.crypto.secureZero(u8, &ipad);
        std.crypto.secureZero(u8, &opad);
        return self;
    }

    /// `out = HMAC_K(msg)`; `out` may alias `msg` (the digest is written last).
    fn mac(self: *const KeyedHmac, out: *[32]u8, msg: []const u8) void {
        var h = self.inner;
        h.update(msg);
        var d: [32]u8 = undefined;
        h.final(&d);
        var o = self.outer;
        o.update(&d);
        o.final(out);
    }
};

/// Sign `SHA-256(msg)` with the RFC 6979 deterministic nonce — no entropy
/// source, and the same message under the same key always yields the same
/// bytes. That reproducibility is what makes the signer anchorable: the RFC's
/// own published `(r, s)` for "sample" and "test" must come back byte for
/// byte (`kat_test.zig`), which `ecdsaSign` with a caller-chosen nonce can
/// never demonstrate.
///
/// Prefer this over `ecdsaSign` unless you have a specific reason to supply
/// `k` yourself: a nonce that repeats across two different messages leaks the
/// private key outright, and deriving it from the key and message removes that
/// failure mode along with any dependence on the platform's RNG.
///
/// Key by pointer, body burned like `ecdsaSign`.
pub fn ecdsaSignDeterministic(secret_key: *const [32]u8, msg: []const u8) SignError![64]u8 {
    const r = ecdsaSignDeterministicUnburned(secret_key, msg);
    burn.stack(burn.sign_burn);
    return r;
}

noinline fn ecdsaSignDeterministicUnburned(secret_key: *const [32]u8, msg: []const u8) SignError![64]u8 {
    _ = Scalar.fromBytes(secret_key.*, .big) catch return error.InvalidSecretKey;
    var h: [32]u8 = undefined;
    Sha256.hash(msg, &h, .{});
    const k = rfc6979Nonce(secret_key.*, h).toBytes(.big);
    return ecdsaSignUnburned(secret_key, msg, &k);
}

/// Verify a P-256 ECDSA signature over SHA-256(`msg`). `pubkey_sec1` is a
/// SEC1-encoded public key (compressed 33-byte or uncompressed 65-byte);
/// `sig_rs` is `r (32) || s (32)` big-endian. Variable-time (all inputs public).
pub fn ecdsaVerify(pubkey_sec1: []const u8, msg: []const u8, sig_rs: [64]u8) bool {
    var h: [32]u8 = undefined;
    Sha256.hash(msg, &h, .{});
    return ecdsaVerifyDigest(pubkey_sec1, &h, sig_rs);
}

/// `ecdsaVerify` over a digest the caller computed with any hash — what
/// X.509 needs for `ecdsa-with-SHA384`/`SHA512` under a P-256 key. Per SEC 1
/// §4.1.4 step 5 (and std's `Ecdsa`), `e` is the leftmost 256 bits of the
/// digest; a shorter digest is its whole value. An empty digest is refused.
/// Variable-time (all inputs public).
pub fn ecdsaVerifyDigest(pubkey_sec1: []const u8, digest: []const u8, sig_rs: [64]u8) bool {
    if (digest.len == 0) return false;
    const Q = P256.fromSec1(pubkey_sec1) catch return false;
    // `fromSec1` accepts the identity encodings (`00`, `04 00..00`); with Q = O
    // anyone can forge (pick s, r = x(e*s^-1 * G)), so refuse it here instead of
    // relying on `mulDoubleBasePublic` to do it.
    Q.rejectIdentity() catch return false;
    const r = Scalar.fromBytes(sig_rs[0..32].*, .big) catch return false;
    const s = Scalar.fromBytes(sig_rs[32..64].*, .big) catch return false;
    if (r.isZero() or s.isZero()) return false;

    var h = @as([32]u8, @splat(0));
    const take = @min(digest.len, 32);
    @memcpy(h[32 - take ..], digest[0..take]);
    const e = reduceToScalar(h);
    // std's verifier rejects `e == 0` and this one did not. With `e ≡ 0
    // (mod n)` the verification equation collapses to `R = u2·Q`, which
    // anyone can satisfy without a private key: pick `t`, set `R = t·Q`,
    // `r = x(R) mod n`, `s = r·t⁻¹`. Unreachable here — `e` is SHA-256 of the
    // message, so triggering it needs a preimage of 0 or of n — but this
    // module is anchored on being behaviourally identical to std, and a
    // divergence in a rejection rule is exactly what such an anchor is for.
    if (e.isZero()) return false;

    const sinv = s.invert();
    const u1v = e.mul(sinv);
    const u2v = r.mul(sinv);

    const R = P256.mulDoubleBasePublic(
        P256.basePoint,
        u1v.toBytes(.big),
        Q,
        u2v.toBytes(.big),
        .big,
    ) catch return false;
    // v = x(R) mod n; accept iff v == r.
    const v = reduceToScalar(R.affineCoordinates().x.toBytes(.big));
    return v.equivalent(r);
}

// A minimal round-trip smoke test (the deep anchors live in oracle_test.zig +
// kat_test.zig).
test "ecdsa sign→verify round-trip (fixed key + nonce)" {
    const sk = @as([32]u8, @splat(0x11));
    const k = @as([32]u8, @splat(0x22));
    const msg = "p256 scaffold smoke";
    const sig = try ecdsaSign(&sk, msg, &k);
    const pk = (P256.combMulBase(sk, .big) catch unreachable).toUncompressedSec1();
    try std.testing.expect(ecdsaVerify(&pk, msg, sig));
    // tamper → reject.
    var bad = sig;
    bad[5] ^= 1;
    try std.testing.expect(!ecdsaVerify(&pk, msg, bad));
}

test "ecdsaVerifyDigest agrees with std's Ecdsa(P256, SHA-384/512/224) and with ecdsaVerify" {
    // The truncation rule (leftmost 256 bits; a shorter digest whole) is the
    // only thing this adds over `ecdsaVerify`, so std's verifier over each
    // hash is the oracle: same verdict on a genuine signature and on one with
    // a flipped bit, for digests longer, equal and shorter than 32 bytes.
    const StdEcdsa = std.crypto.sign.ecdsa.Ecdsa;
    const Curve = std.crypto.ecc.P256;
    inline for (.{ std.crypto.hash.sha2.Sha384, std.crypto.hash.sha2.Sha512, std.crypto.hash.sha2.Sha224, Sha256 }) |H| {
        const E = StdEcdsa(Curve, H);
        const kp = E.KeyPair.generateDeterministic(@as([E.KeyPair.seed_length]u8, @splat(0x5a))) catch unreachable;
        const pk = kp.public_key.toUncompressedSec1();
        var i: u8 = 0;
        while (i < 8) : (i += 1) {
            const msg = [_]u8{ 'd', 'i', 'g', i };
            const sig = try kp.sign(&msg, null);
            var d: [H.digest_length]u8 = undefined;
            H.hash(&msg, &d, .{});
            try std.testing.expect(ecdsaVerifyDigest(&pk, &d, sig.toBytes()));
            if (H == Sha256) try std.testing.expect(ecdsaVerify(&pk, &msg, sig.toBytes()));
            var bad = sig.toBytes();
            bad[40 + i] ^= 1;
            const std_ok = if (E.Signature.fromBytes(bad).verify(&msg, kp.public_key)) |_| true else |_| false;
            try std.testing.expectEqual(std_ok, ecdsaVerifyDigest(&pk, &d, bad));
            // The wrong digest (one bit inside the used prefix) must fail.
            d[0] ^= 0x80;
            try std.testing.expect(!ecdsaVerifyDigest(&pk, &d, sig.toBytes()));
        }
    }
    try std.testing.expect(!ecdsaVerifyDigest(&([_]u8{4} ++ @as([64]u8, @splat(0))), "", @as([64]u8, @splat(1))));
}

test "ecdsaVerify: r=0 and s=0 are rejected explicitly (never fed to any test before)" {
    // No existing test had ever called ecdsaVerify with a zero r or s.
    // Mutation testing (disable the `r.isZero() or s.isZero()` guard)
    // shows this module's downstream math happens to fail closed anyway
    // for BOTH cases against a real signature — s=0 forces sinv=0 (std's
    // documented invert(0)==0), zeroing both mulDoubleBasePublic
    // coefficients and hitting the already-checked identity rejection;
    // r=0 zeroes only the Q-coefficient, leaving u1v*G's x-coordinate
    // essentially never equal to r=0 by chance — so this guard is an
    // explicit, defense-in-depth check of a documented invariant (RFC
    // 6979-adjacent "r, s in [1, n-1]") rather than the only thing
    // standing between here and a forgery. Pinned directly regardless,
    // matching this module's own sign-side r=0/s=0 rejection tests.
    const sk = @as([32]u8, @splat(0x11));
    const k = @as([32]u8, @splat(0x22));
    const msg = "p256 zero r/s smoke";
    const sig = try ecdsaSign(&sk, msg, &k);
    const pk = (P256.combMulBase(sk, .big) catch unreachable).toUncompressedSec1();

    var zero_r = sig;
    @memset(zero_r[0..32], 0);
    try std.testing.expect(!ecdsaVerify(&pk, msg, zero_r));

    var zero_s = sig;
    @memset(zero_s[32..64], 0);
    try std.testing.expect(!ecdsaVerify(&pk, msg, zero_s));
}

// The std-compatible `EcdsaP256Sha256` must interoperate byte-for-byte with
// `std.crypto.sign.ecdsa.EcdsaP256Sha256`: same keypair from the same seed,
// each side's signature verifies under the other. This pins the drop-in the
// jwt/jwe rewire relies on.
test "EcdsaP256Sha256 cross-verifies with std both directions" {
    const Std = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const seed = @as([Std.KeyPair.seed_length]u8, @splat(0x37));
    const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const std_kp = try Std.KeyPair.generateDeterministic(seed);

    // Same seed ⇒ byte-identical public key (SEC1).
    try std.testing.expectEqualSlices(
        u8,
        &kp.public_key.toUncompressedSec1(),
        &std_kp.public_key.toUncompressedSec1(),
    );

    const msg = "p256 ecdsa drop-in oracle";

    // p256-signed ⇒ verifies under std.
    const sig_ours = try kp.sign(msg, null);
    try Std.Signature.fromBytes(sig_ours.toBytes()).verify(msg, std_kp.public_key);

    // std-signed ⇒ verifies under p256.
    const sig_std = try std_kp.sign(msg, null);
    try EcdsaP256Sha256.Signature.fromBytes(sig_std.toBytes()).verify(msg, kp.public_key);
}

// ── KeyedHmac / rfc6979Nonce: differential against the previous code ────────

/// The implementation before `KeyedHmac`: one `HmacSha256.create` per step,
/// re-absorbing both key pads every time. Kept only as the test oracle.
fn rfc6979NonceOld(privkey: [32]u8, hash32: [32]u8) Scalar {
    const h1 = reduceToScalar(hash32).toBytes(.big);

    var v: [32]u8 = @as([32]u8, @splat(0x01));
    var k: [32]u8 = @as([32]u8, @splat(0x00));

    var buf: [32 + 1 + 32 + 32]u8 = undefined;
    buf[0..32].* = v;
    buf[32] = 0x00;
    buf[33..65].* = privkey;
    buf[65..97].* = h1;
    HmacSha256.create(&k, &buf, &k);
    HmacSha256.create(&v, &v, &k);

    buf[0..32].* = v;
    buf[32] = 0x01;
    buf[33..65].* = privkey;
    buf[65..97].* = h1;
    HmacSha256.create(&k, &buf, &k);
    HmacSha256.create(&v, &v, &k);

    while (true) {
        HmacSha256.create(&v, &v, &k);
        if (Scalar.fromBytes(v, .big)) |cand| {
            if (!cand.isZero() and !test_retry.take()) return cand;
        } else |_| {}
        var buf2: [32 + 1]u8 = undefined;
        buf2[0..32].* = v;
        buf2[32] = 0x00;
        HmacSha256.create(&k, &buf2, &k);
        HmacSha256.create(&v, &v, &k);
    }
}

fn hex32(s: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "rfc6979Nonce: RFC 6979 A.2.5 P-256/SHA-256 k for \"sample\" and \"test\"" {
    const x = hex32("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    const cases = [_]struct { msg: []const u8, k: []const u8 }{
        .{ .msg = "sample", .k = "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60" },
        .{ .msg = "test", .k = "D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0" },
    };
    for (cases) |c| {
        var h: [32]u8 = undefined;
        Sha256.hash(c.msg, &h, .{});
        const k = rfc6979Nonce(x, h);
        try std.testing.expectEqualSlices(u8, &hex32(c.k), &k.toBytes(.big));
    }
}

test "KeyedHmac is byte-identical to HmacSha256.create (random keys, lengths 0..200)" {
    var prng = std.Random.DefaultPrng.init(0x6979_0001);
    const rnd = prng.random();
    var msg: [200]u8 = undefined;
    for (0..2000) |_| {
        var key: [32]u8 = undefined;
        rnd.bytes(&key);
        rnd.bytes(&msg);
        const len = rnd.uintAtMost(usize, msg.len);
        var want: [32]u8 = undefined;
        HmacSha256.create(&want, msg[0..len], &key);
        const km = KeyedHmac.init(&key);
        var got: [32]u8 = undefined;
        km.mac(&got, msg[0..len]);
        try std.testing.expectEqualSlices(u8, &want, &got);
        // Reusable: a second message under the same schedule.
        HmacSha256.create(&want, msg[0 .. len / 2], &key);
        km.mac(&got, msg[0 .. len / 2]);
        try std.testing.expectEqualSlices(u8, &want, &got);
    }
}

test "rfc6979Nonce equals the previous implementation (random keys and hashes)" {
    var prng = std.Random.DefaultPrng.init(0x6979_0002);
    const rnd = prng.random();
    for (0..3000) |i| {
        var x: [32]u8 = undefined;
        var h: [32]u8 = undefined;
        rnd.bytes(&x);
        rnd.bytes(&h);
        // Edge inputs: all-zero and all-ones hashes / keys now and then.
        if (i % 500 == 1) @memset(&h, 0);
        if (i % 500 == 2) @memset(&h, 0xff);
        if (i % 500 == 3) @memset(&x, 0xff);
        const want = rfc6979NonceOld(x, h).toBytes(.big);
        const got = rfc6979Nonce(x, h).toBytes(.big);
        try std.testing.expectEqualSlices(u8, &want, &got);
    }
}

test "rfc6979Nonce: the re-derive step (forced) equals the previous implementation" {
    defer test_retry.reject = 0;
    var prng = std.Random.DefaultPrng.init(0x6979_0003);
    const rnd = prng.random();
    for (0..200) |i| {
        var x: [32]u8 = undefined;
        var h: [32]u8 = undefined;
        rnd.bytes(&x);
        rnd.bytes(&h);
        const rejects: u32 = @intCast(1 + i % 3);
        test_retry.reject = 0;
        const first = rfc6979Nonce(x, h).toBytes(.big);
        test_retry.reject = rejects;
        const want = rfc6979NonceOld(x, h).toBytes(.big);
        test_retry.reject = rejects;
        const got = rfc6979Nonce(x, h).toBytes(.big);
        try std.testing.expectEqualSlices(u8, &want, &got);
        // The retry really ran: a different nonce than the first candidate.
        try std.testing.expect(!std.mem.eql(u8, &first, &got));
    }
}

test "ecdsaSignDeterministic: signature bytes unchanged vs the old nonce" {
    var prng = std.Random.DefaultPrng.init(0x6979_0003);
    const rnd = prng.random();
    var msg: [64]u8 = undefined;
    for (0..200) |_| {
        var sk: [32]u8 = undefined;
        rnd.bytes(&sk);
        rnd.bytes(&msg);
        const m = msg[0..rnd.uintAtMost(usize, msg.len)];
        const sig = ecdsaSignDeterministic(&sk, m) catch continue; // sk >= n: not a key
        var h: [32]u8 = undefined;
        Sha256.hash(m, &h, .{});
        const old_k = rfc6979NonceOld(sk, h).toBytes(.big);
        const old_sig = try ecdsaSign(&sk, m, &old_k);
        try std.testing.expectEqualSlices(u8, &old_sig, &sig);
    }
}

test "KeyPair.generate: the range test keeps exactly 0 < d < n" {
    const n = scalarmod.field_order;
    const cases = [_]struct { v: u256, ok: bool }{
        .{ .v = 0, .ok = false },
        .{ .v = 1, .ok = true },
        .{ .v = n - 1, .ok = true },
        .{ .v = n, .ok = false },
        .{ .v = n + 1, .ok = false },
        .{ .v = std.math.maxInt(u256), .ok = false },
        .{ .v = 1 << 255, .ok = true },
    };
    for (cases) |c| {
        var b: [32]u8 = undefined;
        std.mem.writeInt(u256, &b, c.v, .big);
        try std.testing.expectEqual(c.ok, EcdsaP256Sha256.KeyPair.scalarInRange(&b));
    }
    // `signWithSecretKey` refuses the same scalars `fromSecretKey` does.
    for ([_]u256{ 0, n, std.math.maxInt(u256) }) |v| {
        var sk: EcdsaP256Sha256.SecretKey = undefined;
        std.mem.writeInt(u256, &sk.bytes, v, .big);
        var sig: EcdsaP256Sha256.Signature = undefined;
        try std.testing.expectError(error.IdentityElement, EcdsaP256Sha256.signWithSecretKey(&sig, &sk, "m", null));
    }
    // A generated pair is consistent: its public key is d·G.
    const kp = EcdsaP256Sha256.KeyPair.generate(std.testing.io);
    const again = try EcdsaP256Sha256.KeyPair.fromSecretKey(kp.secret_key);
    try std.testing.expectEqualSlices(u8, &kp.public_key.toUncompressedSec1(), &again.public_key.toUncompressedSec1());
}

test "Ecdsa(Hash): signatures are byte-identical to std's Ecdsa(P256, Hash) for SHA-256/384/512 and SHA3-256" {
    const sha2 = std.crypto.hash.sha2;
    inline for (.{ sha2.Sha256, sha2.Sha384, sha2.Sha512, std.crypto.hash.sha3.Sha3_256 }) |H| {
        const Ours = Ecdsa(H);
        const Theirs = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P256, H);
        const seed: [Ours.KeyPair.seed_length]u8 = @splat(0x4b);
        const kp = try Ours.KeyPair.generateDeterministic(seed);
        const std_kp = try Theirs.KeyPair.generateDeterministic(seed);
        try std.testing.expectEqualSlices(u8, &std_kp.public_key.toUncompressedSec1(), &kp.public_key.toUncompressedSec1());

        const noise: [Ours.noise_length]u8 = @splat(0x39);
        var i: u8 = 0;
        while (i < 4) : (i += 1) {
            const msg = [_]u8{ 'E', 'c', 'd', 's', 'a', i };
            for ([_]?[Ours.noise_length]u8{ null, noise }) |nz| {
                const sig = try kp.sign(&msg, nz);
                const std_sig = try std_kp.sign(&msg, nz);
                try std.testing.expectEqualSlices(u8, &std_sig.toBytes(), &sig.toBytes());

                // Round trip through our verifier, std's, and the DER codec.
                try sig.verify(&msg, kp.public_key);
                try Theirs.Signature.fromBytes(sig.toBytes()).verify(&msg, std_kp.public_key);
                var der_buf: [Ours.Signature.der_encoded_length_max]u8 = undefined;
                const der = sig.toDer(&der_buf);
                const back = try Ours.Signature.fromDer(der);
                try back.verify(&msg, kp.public_key);

                // signPrehashed over the digest is the same signature.
                var digest: [H.digest_length]u8 = undefined;
                H.hash(&msg, &digest, .{});
                const pre = try kp.signPrehashed(digest, nz);
                try std.testing.expectEqualSlices(u8, &sig.toBytes(), &pre.toBytes());

                // So is a signature from the secret key alone.
                var alone: Ours.Signature = undefined;
                try Ours.signWithSecretKey(&alone, &kp.secret_key, &msg, if (nz) |*n| n else null);
                try std.testing.expectEqualSlices(u8, &sig.toBytes(), &alone.toBytes());

                // A flipped message bit and a flipped signature bit are refused.
                var bad_msg = msg;
                bad_msg[0] ^= 1;
                try std.testing.expectError(error.SignatureVerificationFailed, sig.verify(&bad_msg, kp.public_key));
                var bad = sig;
                bad.s[31] ^= 1;
                try std.testing.expectError(error.SignatureVerificationFailed, bad.verify(&msg, kp.public_key));
            }
        }
    }
}
