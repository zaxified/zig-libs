// SPDX-License-Identifier: MIT

//! jwe — JSON Web Encryption (RFC 7516) + the JWA (RFC 7518) encryption
//! algorithms, compact serialization only. The encryption sibling of `jwt`
//! (which does JWS/signing): this module produces and consumes encrypted
//! tokens — `header.encrypted_key.iv.ciphertext.tag` — for a "confidential
//! claims" use case `jwt` deliberately doesn't cover.
//!
//! ## Scope (v1)
//!
//! **Compact serialization** (RFC 7516 §3.1) for encrypting and decrypting; the General/Flattened JSON
//! serializations (§7.2) are read by `decryptJson` (any number of recipients, `aad`, shared unprotected header)
//! and written by `encryptJson` (one recipient, re-framing the compact token) and `encryptJsonRecipients` (one CEK
//! wrapped for several recipients, with the `aad` member).
//!
//! **Content encryption (`enc`, RFC 7518 §5)**:
//!   - `A128GCM`/`A256GCM` — REAL (`aesgcm.Aes128Gcm`/`Aes256Gcm`); `A192GCM` —
//!     REAL (`aesgcm.Aes192Gcm`; std 0.16 has no AES-192).
//!   - `A128CBC-HS256`/`A192CBC-HS384`/`A256CBC-HS512` — REAL (AES-CBC +
//!     HMAC-SHA-2 encrypt-then-MAC; byte-exact against RFC 7518 Appendix
//!     B.1–B.3; AES-192 from the `aes192` module). See `enc.zig`.
//!
//! **Key management (`alg`, RFC 7518 §4)**:
//!   - `dir` — REAL (trivial: the CEK is the shared key).
//!   - `RSA-OAEP` / `RSA-OAEP-256` — REAL (wraps the `rsa` module's OAEP).
//!   - `A128KW`/`A192KW`/`A256KW` — REAL (RFC 3394 AES Key Wrap; byte-exact
//!     against RFC 3394 §4.1/§4.2 and RFC 7516 A.3). See the shared `aeskw`
//!     module.
//!   - `A128GCMKW`/`A192GCMKW`/`A256GCMKW` — REAL.
//!   - `PBES2-HS256+A128KW`/`PBES2-HS384+A192KW`/`PBES2-HS512+A256KW` — REAL
//!     (PBKDF2 KDF feeding the AES Key Wrap above).
//!   - `ECDH-ES` / `ECDH-ES+A128KW` / `ECDH-ES+A192KW` / `ECDH-ES+A256KW` —
//!     REAL (§4.6
//!     ephemeral-static ECDH on P-256 or X25519 + the Concat KDF; byte-exact
//!     against RFC 7518 Appendix C — see `ecdhes.zig`). Direct mode derives
//!     the CEK itself (empty Encrypted Key segment); the `+AxxxKW` modes
//!     derive a KEK feeding the RFC 3394 wrap.
//!
//! AES-192 (every `A192*` above): std 0.16 has no AES-192;
//! the block cipher is the `aes192` module's, GCM is `aesgcm`'s.
//!
//! ## Usage
//!
//! ```zig
//! const jwe = @import("jwe");
//!
//! // A256GCM content encryption, `dir` key management (real end to end).
//! const key = [_]u8{0x2b} ** 32;
//! var csprng = std.Random.DefaultCsprng.init(seed); // caller's real CSPRNG
//! const token = try jwe.encryptCompact(
//!     gpa, .dir, .A256GCM, .{ .symmetric = &key }, "attack at dawn", "",
//!     .{ .csprng = csprng.random() }, .{},
//! );
//! defer gpa.free(token);
//!
//! const plaintext = try jwe.decryptCompact(gpa, .{ .symmetric = &key }, token, .{});
//! defer gpa.free(plaintext);
//! ```
//!
//! Design notes:
//! - `gpa`-owned results (not caller-supplied fixed buffers): plaintext is
//!   arbitrary-length application data with no natural upper bound, unlike
//!   e.g. the `rsa` module's fixed-modulus buffers — an arena-per-call
//!   allocator model (mirroring `jwt`'s `ParsedToken`) is the honest fit.
//!   Fixed-size scratch is used internally wherever a size IS bounded (CEK,
//!   encrypted key, IV, tag, header JSON).
//! - `KeyMaterial`'s union tag is part of the security model, same as
//!   `jwt.Key`: the header's `alg` must match the *kind* of key material
//!   supplied (`error.KeyMaterialMismatch`) — this is the "confusion"
//!   defense named in the threat model (SPEC.md).
//! - `zip` (compression) is always rejected — see `header.zig`.
//! - **Randomness is a named caller obligation.** `encryptCompact` takes an
//!   `Entropy`, not a `std.Random`: the caller writes `.csprng` (a claim this
//!   module cannot verify) or `.fixed_for_test`. `dir` is the mode where
//!   getting it wrong is catastrophic rather than merely bad — the CEK is the
//!   caller's long-lived key, so a repeated content IV under `AxxxGCM` gives
//!   up plaintext AND the GHASH authentication subkey. See `entropy.zig`.
//! - Compact serialization carries no extra AAD (RFC 7516 §5.1); passing a
//!   non-empty `aad_extra` to `encryptCompact` is `error.CompactSerializationNoAad`.

const std = @import("std");
const builtin = @import("builtin");
const rsa = @import("rsa");

pub const header = @import("header.zig");
pub const enc = @import("enc.zig");
const burn = @import("burn.zig");
pub const alg = @import("alg.zig");
pub const Entropy = @import("entropy.zig").Entropy;
pub const aeskw = alg.aeskw;
pub const ecdhes = alg.ecdhes;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "JSON Web Encryption (RFC 7516/7518) compact serialization — RSA-OAEP/AxxxKW/ECDH-ES key management + AES-GCM/CBC-HMAC content encryption, AES-128/192/256 throughout (AES-192 via the aes192/aesgcm modules)",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec, // pure wire codec + crypto dispatch, no I/O of its own
    .concurrency = .reentrant, // no shared/global state; every call is self-contained
    .model_after = "RFC 7516 (JWE) + RFC 7518 (JWA encryption algs) + RFC 3394 (AES Key Wrap); sibling of this repo's `jwt` (RFC 7515 JWS)",
    .deps = .{ "rsa", "p256", "p384", "p521", "aescbc", "aeskw", "aes192", "aesgcm" }, // p256 / p384 / p521 supply the ECDH-ES NIST curves (p256 byte-exact to std.crypto.ecc.P256); X25519 stays on std; aescbc/aeskw supply the shared CBC + RFC 3394 key-wrap cores; aes192 the AES-192 block cipher; aesgcm all A128/A192/A256GCM (std AES-GCM is 2.6x slower on Zig 0.17, #36256)
};

/// Key management algorithm (`alg` header parameter, RFC 7518 §4 names).
pub const Alg = enum {
    dir,
    @"RSA-OAEP",
    @"RSA-OAEP-256",
    A128KW,
    A192KW,
    A256KW,
    A128GCMKW,
    A192GCMKW,
    A256GCMKW,
    @"PBES2-HS256+A128KW",
    @"PBES2-HS384+A192KW",
    @"PBES2-HS512+A256KW",
    @"ECDH-ES",
    @"ECDH-ES+A128KW",
    @"ECDH-ES+A192KW",
    @"ECDH-ES+A256KW",
    unknown,

    pub fn fromString(s: []const u8) Alg {
        return std.meta.stringToEnum(Alg, s) orelse .unknown;
    }
};

/// Content encryption algorithm (`enc` header parameter, RFC 7518 §5 names).
pub const Enc = enum {
    A128GCM,
    A192GCM,
    A256GCM,
    @"A128CBC-HS256",
    @"A192CBC-HS384",
    @"A256CBC-HS512",
    unknown,

    pub fn fromString(s: []const u8) Enc {
        return std.meta.stringToEnum(Enc, s) orelse .unknown;
    }

    /// Content Encryption Key length in bytes (RFC 7518 §5.1/§5.2.1), or
    /// `null` for `.unknown`.
    pub fn cekLen(self: Enc) ?usize {
        return switch (self) {
            .A128GCM => 16,
            .A192GCM => 24,
            .A256GCM => 32,
            .@"A128CBC-HS256" => 32, // MAC_KEY(16) ‖ ENC_KEY(16)
            .@"A192CBC-HS384" => 48, // MAC_KEY(24) ‖ ENC_KEY(24)
            .@"A256CBC-HS512" => 64, // MAC_KEY(32) ‖ ENC_KEY(32)
            .unknown => null,
        };
    }

    /// JWE Initialization Vector length in bytes.
    pub fn ivLen(self: Enc) ?usize {
        return switch (self) {
            .A128GCM, .A192GCM, .A256GCM => 12,
            .@"A128CBC-HS256", .@"A192CBC-HS384", .@"A256CBC-HS512" => 16,
            .unknown => null,
        };
    }

    /// Authentication Tag length in bytes.
    pub fn tagLen(self: Enc) ?usize {
        return switch (self) {
            .A128GCM, .A192GCM, .A256GCM => 16,
            .@"A128CBC-HS256" => 16,
            .@"A192CBC-HS384" => 24,
            .@"A256CBC-HS512" => 32,
            .unknown => null,
        };
    }

    pub fn isGcm(self: Enc) bool {
        return switch (self) {
            .A128GCM, .A192GCM, .A256GCM => true,
            else => false,
        };
    }
};

/// The key material `encryptCompact`/`decryptCompact` need — a tagged union
/// so the header's `alg` can be checked against what was actually supplied
/// (`error.KeyMaterialMismatch`), the JWE analogue of `jwt.Key`'s
/// algorithm-confusion defense.
pub const KeyMaterial = union(enum) {
    /// Shared symmetric key: `dir`'s CEK, or an AxxxKW/AxxxGCMKW KEK.
    /// Borrowed, not copied — must outlive the call.
    symmetric: []const u8,
    /// RSA public key — `RSA-OAEP`/`RSA-OAEP-256` encrypt side.
    rsa_public: rsa.PublicKey,
    /// RSA private key — `RSA-OAEP`/`RSA-OAEP-256` decrypt side. Borrowed,
    /// not copied: a by-value `rsa.SecretKey` would be duplicated into every
    /// frame this union is passed through.
    rsa_private: *const rsa.SecretKey,
    /// Password — every `PBES2-*` variant. Borrowed, not copied.
    password: []const u8,
    /// Recipient's static EC/OKP public key (P-256 or X25519) —
    /// `ECDH-ES`/`ECDH-ES+AxxxKW` encrypt side.
    ec_public: ecdhes.PublicKey,
    /// Recipient's static EC/OKP private key — `ECDH-ES`/`ECDH-ES+AxxxKW`
    /// decrypt side. Borrowed, not copied: a by-value 32-byte secret would be
    /// duplicated into every frame this union is passed through.
    ec_private: *const ecdhes.PrivateKey,
};

/// Largest CEK/encrypted-key/IV/tag this module's internal scratch buffers
/// are sized for. `max_encrypted_key_len` is dominated by RSA (up to a
/// 4096-bit modulus, `rsa.max_modulus_len`); AES-KW (`cek_len + 8`) and
/// AES-GCM key wrap (`cek_len`) are both far smaller.
pub const max_cek_len = enc.max_cek_len;
pub const max_encrypted_key_len = rsa.max_modulus_len;

pub const EncryptOptions = struct {
    kid: ?[]const u8 = null,
    cty: ?[]const u8 = null,
    /// PBES2 iteration count (`p2c`, RFC 7518 §4.8.1.2). RFC 7518 sets no
    /// floor; 600_000 tracks current (2020s) OWASP PBKDF2-HMAC-SHA256
    /// guidance rather than any value from the RFC itself.
    pbes2_iterations: u32 = 600_000,
    /// PBES2 salt input length in bytes (`p2s`, before the
    /// `alg-name || 0x00` prefix `pbes2DeriveKek` adds) — RFC 7518 §4.8.1.1
    /// recommends >= 8 bytes.
    pbes2_salt_len: usize = 16,
    /// ECDH-ES Agreement PartyUInfo/PartyVInfo (`apu`/`apv`, RFC 7518
    /// §4.6.1.2/.3): RAW bytes (base64url encoding is the header codec's
    /// job), fed into the Concat KDF and carried in the header. Only
    /// meaningful for the `ECDH-ES*` algs — ignored by every other `alg`.
    /// At most `header.max_member_len` bytes each.
    apu: ?[]const u8 = null,
    apv: ?[]const u8 = null,
};

pub const DecryptOptions = struct {
    /// Reject unless the header's `alg` equals this. `null` accepts any
    /// `alg` consistent with the supplied `KeyMaterial`'s kind (the mismatch
    /// check below is never skippable — this only adds a *further* pin).
    expect_alg: ?Alg = null,
    /// Reject unless the header's `enc` equals this.
    expect_enc: ?Enc = null,
    /// Ceiling on the PBES2 iteration count a received token may command.
    /// See `default_max_p2c` — this is a work bound, not a size bound.
    max_p2c: u32 = default_max_p2c,
};

pub const EncryptError = error{
    OutOfMemory,
    BufferTooSmall,
    UnsupportedAlg,
    UnsupportedEnc,
    /// The header this call would build exceeds `header.max_header_json_len`
    /// (an oversized `kid`/`cty`, typically).
    HeaderTooLarge,
    /// `key`'s tag doesn't match what `alg` needs (e.g. `RSA-OAEP` with a
    /// `.symmetric` key) — the encrypt-side analogue of `jwt`'s
    /// `AlgKeyMismatch`.
    KeyMaterialMismatch,
    /// Compact serialization carries no additional AAD (RFC 7516 §5.1) —
    /// `aad_extra` must be empty.
    CompactSerializationNoAad,
    /// `encryptJsonRecipients`: no recipient, more than `max_json_recipients`, or `.flattened` with other than one.
    InvalidRecipients,
} || alg.Error || enc.Error || header.EncodeError;

/// Largest PBES2 iteration count (`p2c`) this module will perform on a
/// received token.
///
/// ⚠ `p2c` is an **attacker-chosen work factor**, read from an unauthenticated
/// header and obeyed before anything is verified. It was unbounded. Measured
/// on this host at ~1 µs per iteration: a **192-byte token** declaring
/// `p2c=100,000,000` costs **99.75 s** of CPU and then returns
/// `AuthenticationFailed`; at `u32` max it is roughly 71 CPU-minutes. One
/// small token, one core, indefinitely.
///
/// SPEC.md's "header-size-bounded decode" bullet was read as covering this. It
/// does not: it bounds the header's BYTES, and the quantity that grows here is
/// the WORK the header's contents command — the same "cap bounds the wrong
/// quantity" shape found five other times in this collection.
///
/// The ceiling is generous next to RFC 7518 §4.8.1.2's "a minimum of 1000" and
/// to what any real issuer sets, so it refuses only tokens no honest sender
/// produces. `DecryptOptions.max_p2c` raises it for a caller who really does
/// mint tokens above it.
pub const default_max_p2c: u32 = 1_000_000;

pub const DecryptError = error{
    OutOfMemory,
    BufferTooSmall,
    /// Not exactly five dot-separated segments, or an empty header segment.
    MalformedToken,
    /// The base64url-encoded header segment exceeds
    /// `header.max_header_b64_len`.
    HeaderTooLarge,
    /// The header's `alg`/`enc` is unrecognized.
    UnsupportedAlg,
    UnsupportedEnc,
    /// `key`'s tag doesn't match the header's `alg` — see `EncryptError`'s
    /// doc comment; this is the mandatory confusion defense.
    KeyMaterialMismatch,
    /// `DecryptOptions.expect_alg`/`expect_enc` was set and didn't match.
    AlgMismatch,
    EncMismatch,
    /// A JWE-level integrity check failed (GCM tag, key-unwrap tag, …).
    AuthenticationFailed,
    InvalidKey,
    /// The token's PBES2 `p2c` exceeds `DecryptOptions.max_p2c`. Refused
    /// before the derivation runs — see `default_max_p2c`.
    WorkFactorTooHigh,
} || header.ParseError || alg.Error || enc.Error;

/// The ECDH-ES encrypt arm's secret-touching body: draws the ephemeral key,
/// derives `Z`, runs the Concat KDF and (for the KW variants) wraps a random
/// CEK. Own frame so the caller can burn everything it dirtied; the ephemeral
/// scalar, `Z` and the KEK never leave it, and are wiped before it returns.
noinline fn ecdhesEncryptKey(
    key_alg: Alg,
    content_enc: Enc,
    pk: ecdhes.PublicKey,
    entropy: Entropy,
    random: std.Random,
    opts: EncryptOptions,
    cek: []u8,
    shared_cek: bool,
    ek_buf: *[max_encrypted_key_len]u8,
    epk_coords: *ecdhes.Coordinates,
) EncryptError![]const u8 {
    const curve = std.meta.activeTag(pk);
    var eph: ecdhes.EphemeralKeyPair = undefined;
    ecdhes.generateEphemeral(&eph, curve, entropy);
    defer eph.private.wipe();
    var z_buf: [ecdhes.max_z_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &z_buf);
    const z = try ecdhes.deriveZ(&eph.private, pk, &z_buf);
    const apu = opts.apu orelse "";
    const apv = opts.apv orelse "";

    epk_coords.* = eph.public.coordinates();

    if (key_alg == .@"ECDH-ES") {
        // Direct Key Agreement: the derived key IS the CEK
        // (keydatalen = the `enc` key size, AlgorithmID = the `enc`
        // name); the Encrypted Key segment stays empty.
        ecdhes.concatKdfSha256(z, @tagName(content_enc), apu, apv, cek);
        return &.{};
    }
    // Key Agreement with Key Wrapping: derive a KEK (keydatalen =
    // the KW size, AlgorithmID = the full `alg` name), wrap a
    // random CEK under it.
    const kek_len: usize = switch (key_alg) {
        .@"ECDH-ES+A128KW" => 16,
        .@"ECDH-ES+A192KW" => 24,
        .@"ECDH-ES+A256KW" => 32,
        else => unreachable,
    };
    var kek_buf: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &kek_buf);
    const kek = kek_buf[0..kek_len];
    ecdhes.concatKdfSha256(z, @tagName(key_alg), apu, apv, kek);
    if (!shared_cek) random.bytes(cek);
    return try alg.aeskw.wrap(kek, cek, ek_buf);
}

/// What wrapping the CEK for one recipient produced: the Encrypted Key and the header members that belong to it.
/// Slices point into the struct itself: it must not move after `wrapKey` filled it.
const Wrapped = struct {
    ek_buf: [max_encrypted_key_len]u8 = undefined,
    encrypted_key: []const u8 = &.{},
    wrap_iv: ?[12]u8 = null,
    wrap_tag: ?[16]u8 = null,
    pbes2_salt_buf: [alg.max_pbes2_salt_value_len]u8 = undefined,
    pbes2_salt: ?[]const u8 = null,
    pbes2_iterations: ?u32 = null,
    epk_coords: ecdhes.Coordinates = undefined, // written before any read (ECDH-ES arm only)
    epk_curve: ?ecdhes.Curve = null,

    fn epkParams(self: *const Wrapped) ?header.EpkParams {
        const curve = self.epk_curve orelse return null;
        return .{ .kty = curve.jwkKty(), .crv = curve.jwkCrv(), .x = self.epk_coords.xSlice(), .y = self.epk_coords.ySlice() };
    }
};

/// Produce the Encrypted Key of `key_alg` for `cek` (`cek.len` is the `content_enc` key size). With `shared_cek` the
/// CEK is already filled in (one CEK wrapped for several recipients) and `dir` / `ECDH-ES`, whose CEK is derived,
/// are `UnsupportedAlg`; otherwise the arm draws the CEK (or derives it) into `cek`.
fn wrapKey(
    w: *Wrapped,
    key_alg: Alg,
    content_enc: Enc,
    key: KeyMaterial,
    entropy: Entropy,
    random: std.Random,
    opts: EncryptOptions,
    cek: []u8,
    shared_cek: bool,
) EncryptError!void {
    w.encrypted_key = switch (key_alg) {
        .dir => blk: {
            const shared = switch (key) {
                .symmetric => |s| s,
                else => return error.KeyMaterialMismatch,
            };
            if (shared_cek) return error.UnsupportedAlg; // direct encryption has exactly one recipient
            _ = try alg.dirCek(shared, cek.len, cek);
            break :blk &.{};
        },
        .@"RSA-OAEP", .@"RSA-OAEP-256" => blk: {
            const pk = switch (key) {
                .rsa_public => |p| p,
                else => return error.KeyMaterialMismatch,
            };
            if (!shared_cek) random.bytes(cek);
            const hash: alg.OaepHash = if (key_alg == .@"RSA-OAEP") .sha1 else .sha256;
            break :blk try alg.rsaOaepWrap(pk, hash, entropy, cek, &w.ek_buf);
        },
        .A128KW, .A192KW, .A256KW => blk: {
            const kek = switch (key) {
                .symmetric => |s| s,
                else => return error.KeyMaterialMismatch,
            };
            if (!shared_cek) random.bytes(cek);
            break :blk try alg.aeskw.wrap(kek, cek, &w.ek_buf);
        },
        .A128GCMKW, .A192GCMKW, .A256GCMKW => blk: {
            const kek = switch (key) {
                .symmetric => |s| s,
                else => return error.KeyMaterialMismatch,
            };
            if (!shared_cek) random.bytes(cek);
            var iv: [12]u8 = undefined;
            random.bytes(&iv);
            var tag: [16]u8 = undefined;
            const ct = try alg.gcmkwWrap(kek, iv, cek, &w.ek_buf, &tag);
            w.wrap_iv = iv;
            w.wrap_tag = tag;
            break :blk ct;
        },
        .@"PBES2-HS256+A128KW", .@"PBES2-HS384+A192KW", .@"PBES2-HS512+A256KW" => blk: {
            const password = switch (key) {
                .password => |p| p,
                else => return error.KeyMaterialMismatch,
            };
            if (!shared_cek) random.bytes(cek);
            const salt_len = @min(opts.pbes2_salt_len, w.pbes2_salt_buf.len);
            const salt = w.pbes2_salt_buf[0..salt_len];
            random.bytes(salt);
            const variant: alg.Pbes2Variant = switch (key_alg) {
                .@"PBES2-HS256+A128KW" => .hs256_a128kw,
                .@"PBES2-HS384+A192KW" => .hs384_a192kw,
                .@"PBES2-HS512+A256KW" => .hs512_a256kw,
                else => unreachable,
            };
            var kek_buf: [32]u8 = undefined;
            const kek = try alg.pbes2DeriveKek(variant, password, salt, opts.pbes2_iterations, &kek_buf);
            w.pbes2_salt = salt;
            w.pbes2_iterations = opts.pbes2_iterations;
            break :blk try alg.aeskw.wrap(kek, cek, &w.ek_buf);
        },
        .@"ECDH-ES", .@"ECDH-ES+A128KW", .@"ECDH-ES+A192KW", .@"ECDH-ES+A256KW" => blk: {
            const pk = switch (key) {
                .ec_public => |p| p,
                else => return error.KeyMaterialMismatch,
            };
            if (shared_cek and key_alg == .@"ECDH-ES") return error.UnsupportedAlg; // direct agreement has exactly one recipient
            const curve = std.meta.activeTag(pk);
            // The secret-touching part (ephemeral key, Z, KEK) runs one frame
            // down and is burned after it returns; only public results
            // (`epk_coords`, the wrapped key) and the CEK come back.
            const r = ecdhesEncryptKey(key_alg, content_enc, pk, entropy, random, opts, cek, shared_cek, &w.ek_buf, &w.epk_coords);
            burn.stack(burn.ecdh_burn + burn.content_burn / 2);
            const ek = try r;
            w.epk_curve = curve;
            break :blk ek;
        },
        .unknown => unreachable,
    };
}

/// Encrypt `plaintext` into a compact-serialization JWE. `entropy` supplies
/// every fresh value this call needs — the CEK (when `alg` isn't `dir`), the
/// content IV, the AxxxGCMKW wrap IV, the PBES2 salt input, the ECDH-ES
/// ephemeral private scalar — and its arm is the caller's written claim about
/// what kind of generator that is. Returns a `gpa`-owned string; free with
/// `gpa`.
///
/// The consequence of getting it wrong is not uniform across `alg`: under
/// `dir` the CEK is the caller's long-lived key and the IV is the only thing
/// separating two messages, so a repeated IV under `AxxxGCM` recovers
/// plaintext **and** the GHASH authentication subkey, i.e. forgery of every
/// other token under that key. See `entropy.zig` for the full statement and
/// for why a stateless RFC 7516 encoder cannot prevent this outright.
///
/// `aad_extra` must be empty — see the module doc comment.
// secret-api-ok: KeyMaterial holds only BORROWED slices / pointers (see its doc comment; `rsa_private` and `ec_private` are `*const`); a by-value copy copies a pointer, never key bytes
pub fn encryptCompact(
    gpa: std.mem.Allocator,
    key_alg: Alg,
    content_enc: Enc,
    key: KeyMaterial,
    plaintext: []const u8,
    aad_extra: []const u8,
    entropy: Entropy,
    opts: EncryptOptions,
) EncryptError![]u8 {
    // Unwrapped here rather than through an accessor on `Entropy` — see the
    // note at the bottom of `entropy.zig`.
    const random: std.Random = switch (entropy) {
        .csprng => |r| r,
        .fixed_for_test => |r| r,
    };
    if (aad_extra.len != 0) return error.CompactSerializationNoAad;
    if (key_alg == .unknown) return error.UnsupportedAlg;
    if (content_enc == .unknown) return error.UnsupportedEnc;
    const cek_len = content_enc.cekLen() orelse return error.UnsupportedEnc;

    var cek_buf: [max_cek_len]u8 = undefined;
    // The CEK (random, or the ECDH-ES / `dir` derived key) never left in the frame.
    defer std.crypto.secureZero(u8, &cek_buf);
    const cek = cek_buf[0..cek_len];
    var w: Wrapped = .{};
    try wrapKey(&w, key_alg, content_enc, key, entropy, random, opts, cek, false);
    const encrypted_key = w.encrypted_key;

    var header_buf: [header.max_header_json_len]u8 = undefined;
    const header_json = header.encode(&header_buf, .{
        .alg = @tagName(key_alg),
        .enc = @tagName(content_enc),
        .kid = opts.kid,
        .cty = opts.cty,
        .iv = if (w.wrap_iv) |*v| v[0..] else null,
        .tag = if (w.wrap_tag) |*v| v[0..] else null,
        .p2s = w.pbes2_salt,
        .p2c = w.pbes2_iterations,
        .epk = w.epkParams(),
        .apu = if (w.epk_curve != null) opts.apu else null,
        .apv = if (w.epk_curve != null) opts.apv else null,
    }) catch return error.HeaderTooLarge;

    var content_iv: [16]u8 = undefined;
    const iv_len = content_enc.ivLen().?;
    random.bytes(content_iv[0..iv_len]);
    const tag_len = content_enc.tagLen().?;

    const b64 = std.base64.url_safe_no_pad;
    const header_b64_len = b64.Encoder.calcSize(header_json.len);

    // Base64url the header first — the same bytes are both the wire segment
    // and the AAD (RFC 7516 §5.1: AAD = ASCII(BASE64URL(header))).
    const header_b64 = try gpa.alloc(u8, header_b64_len);
    defer gpa.free(header_b64);
    _ = b64.Encoder.encode(header_b64, header_json);

    // CBC-HMAC output includes PKCS#7 padding — up to one whole extra block;
    // GCM writes exactly `plaintext.len` (the extra 16 bytes stay unused).
    const ct_scratch = try gpa.alloc(u8, plaintext.len + 16);
    defer gpa.free(ct_scratch);
    var tag_buf: [enc.max_tag_len]u8 = undefined;
    const ct_len = try enc.encrypt(content_enc, cek, content_iv[0..iv_len], header_b64, plaintext, ct_scratch, tag_buf[0..tag_len]);
    const ciphertext = ct_scratch[0..ct_len];

    const ek_b64_len = b64.Encoder.calcSize(encrypted_key.len);
    const iv_b64_len = b64.Encoder.calcSize(iv_len);
    const ct_b64_len = b64.Encoder.calcSize(ciphertext.len);
    const tag_b64_len = b64.Encoder.calcSize(tag_len);
    const total = header_b64_len + 1 + ek_b64_len + 1 + iv_b64_len + 1 + ct_b64_len + 1 + tag_b64_len;

    const out = try gpa.alloc(u8, total);
    errdefer gpa.free(out);
    var pos: usize = 0;
    @memcpy(out[pos..][0..header_b64_len], header_b64);
    pos += header_b64_len;
    out[pos] = '.';
    pos += 1;
    _ = b64.Encoder.encode(out[pos..][0..ek_b64_len], encrypted_key);
    pos += ek_b64_len;
    out[pos] = '.';
    pos += 1;
    _ = b64.Encoder.encode(out[pos..][0..iv_b64_len], content_iv[0..iv_len]);
    pos += iv_b64_len;
    out[pos] = '.';
    pos += 1;
    _ = b64.Encoder.encode(out[pos..][0..ct_b64_len], ciphertext);
    pos += ct_b64_len;
    out[pos] = '.';
    pos += 1;
    _ = b64.Encoder.encode(out[pos..][0..tag_b64_len], tag_buf[0..tag_len]);
    pos += tag_b64_len;
    std.debug.assert(pos == total);

    return out;
}

/// Decrypt a compact-serialization JWE. Returns `gpa`-owned plaintext; free
/// with `gpa`. Fails closed on anything malformed or unauthenticated —
/// never partially trusts a token.
///
/// Burned (`burn.content_burn`): the unwrap / KDF / content-decryption frames
/// run one frame down and are zeroed after (`stackprobe2_test.zig`).
// secret-api-ok: KeyMaterial holds only BORROWED slices / pointers (see its doc comment); a by-value copy copies a pointer, never key bytes
pub fn decryptCompact(
    gpa: std.mem.Allocator,
    key: KeyMaterial,
    token: []const u8,
    opts: DecryptOptions,
) DecryptError![]u8 {
    return burn.run(burn.content_burn, DecryptError![]u8, decryptCompactBody, .{ gpa, key, token, opts });
}

fn decryptCompactBody(
    gpa: std.mem.Allocator,
    key: KeyMaterial,
    token: []const u8,
    opts: DecryptOptions,
) DecryptError![]u8 {
    var it = std.mem.splitScalar(u8, token, '.');
    const header_b64 = it.next() orelse return error.MalformedToken;
    const ek_b64 = it.next() orelse return error.MalformedToken;
    const iv_b64 = it.next() orelse return error.MalformedToken;
    const ct_b64 = it.next() orelse return error.MalformedToken;
    const tag_b64 = it.next() orelse return error.MalformedToken;
    if (it.next() != null) return error.MalformedToken;
    if (header_b64.len == 0) return error.MalformedToken;
    if (header_b64.len > header.max_header_b64_len) return error.HeaderTooLarge;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const header_json = try decodeSegmentAlloc(arena, header_b64);
    const parsed = try header.parse(arena, header_json);
    if (parsed.alg == .unknown) return error.UnsupportedAlg;
    if (parsed.enc == .unknown) return error.UnsupportedEnc;
    if (opts.expect_alg) |want| if (want != parsed.alg) return error.AlgMismatch;
    if (opts.expect_enc) |want| if (want != parsed.enc) return error.EncMismatch;

    const cek_len = parsed.enc.cekLen() orelse return error.UnsupportedEnc;
    var cek_buf: [max_cek_len]u8 = undefined;
    // Z1 (CONVENTIONS.md §2.1): module-owned storage holding the recovered
    // CEK, known death at function return, not on the Z2/Z3 lists — MUST
    // wipe. Registered before any of the per-`alg` arms below (all fallible)
    // fill it, so every error path still wipes whatever was written so far.
    // `enc.decrypt` below is the CEK's last use, so this defer also covers
    // the success path. Matches the `z_buf`/`kek_buf` defers already present
    // in this same function's ECDH-ES/GCMKW arms.
    defer std.crypto.secureZero(u8, &cek_buf);
    const cek = cek_buf[0..cek_len];

    const encrypted_key = try decodeSegmentAlloc(arena, ek_b64);
    const content_iv = try decodeSegmentAlloc(arena, iv_b64);
    const ciphertext = try decodeSegmentAlloc(arena, ct_b64);
    const tag = try decodeSegmentAlloc(arena, tag_b64);

    // ── RFC 7516 §11.5, verbatim ─────────────────────────────────────────
    //
    //   "To mitigate the attacks described in RFC 3218, the recipient MUST NOT
    //    distinguish between format, padding, and length errors of encrypted
    //    keys. It is strongly recommended, in the event of receiving an
    //    improperly formatted key, that the recipient substitute a randomly
    //    generated CEK and proceed to the next step, to mitigate timing
    //    attacks."
    //
    // This code used to return THREE distinguishable values for one RSA-OAEP
    // decryption — `UnwrapFailed` for junk, `InvalidKey` for a valid OAEP wrap
    // of a wrong-length message (the "length error" the sentence names), and
    // `AuthenticationFailed` once both passed. That is Manger's oracle read
    // straight off the return value, no statistics required. `AxxxKW` and
    // `AxxxGCMKW` had the same shape.
    //
    // ⚠ Collapsing the VALUE alone would not have been enough, and this
    // campaign has already paid for learning that once (`xmlenc`, a 97%
    // classifier through a fully unified error): the early returns also
    // skipped the content decryption entirely, so the two arms did different
    // amounts of WORK. Substituting a decoy CEK and proceeding is what makes
    // the work identical — every path now runs the AEAD and fails there.
    return unwrapAndFinish(gpa, parsed, key, header_b64, encrypted_key, content_iv, ciphertext, tag, cek, cek_len, opts);
}

/// The key-unwrap and content-decryption tail shared by the compact and the JSON entry points: recover the CEK
/// (substituting a decoy on a format/padding/length error, RFC 7516 §11.5) and decrypt with `aad` as the AEAD AAD.
fn unwrapAndFinish(
    gpa: std.mem.Allocator,
    parsed: header.Parsed,
    key: KeyMaterial,
    aad: []const u8,
    encrypted_key: []const u8,
    content_iv: []const u8,
    ciphertext: []const u8,
    tag: []const u8,
    cek: []u8,
    cek_len: usize,
    opts: DecryptOptions,
) DecryptError![]u8 {
    var unwrap_failed = false;
    unwrapCek(parsed, key, encrypted_key, cek, cek_len, opts) catch |err| switch (err) {
        // Not "errors of encrypted keys": these are properties of the caller's
        // own configuration or of the host, decided before any attacker-chosen
        // key material is touched, and collapsing them would only hide bugs.
        error.OutOfMemory,
        error.KeyMaterialMismatch,
        error.UnsupportedKeyLength,
        // ⚠ `error.BufferTooSmall` is NOT in this list, though it reads like a
        // caller mistake. `aeskw.unwrap` raises it when the Encrypted Key's
        // length does not match the CEK the header asks for — i.e. it is
        // precisely a "length error of an encrypted key", raised on an
        // attacker-chosen length. The name says nothing about whose fault it
        // is; only where it is raised does. It cost this test one red run to
        // notice, which is the argument for having the test.
        // Structural and configuration checks, all decided BEFORE any
        // secret-dependent computation touches the encrypted key: a missing
        // `epk`, a curve that is not the recipient's, a non-empty Encrypted
        // Key under a direct-agreement `alg`. §11.5 is about format, padding
        // and length errors *of encrypted keys* — errors from the unwrap
        // itself. Collapsing these would leak nothing and would hide the
        // algorithm-confusion and malleability defenses that raise them.
        error.MalformedToken,
        error.CurveMismatch,
        // A refusal to perform work the unauthenticated header commanded,
        // decided from a PUBLIC parameter before any secret is touched.
        // Collapsing it would mean silently doing the work and then reporting
        // an authentication failure — i.e. not refusing at all.
        error.WorkFactorTooHigh,
        => return err,
        // Everything else IS a format, padding or length error of the
        // encrypted key. One value, and the same work after it.
        else => unwrap_failed = true,
    };
    if (unwrap_failed) decoyCek(key, encrypted_key, cek);

    return finishDecrypt(gpa, parsed, aad, cek, content_iv, ciphertext, tag);
}

// ── JSON serialization (RFC 7516 §7.2) ──────────────────────────────────────

/// Largest JWE JSON document `decryptJson` reads.
pub const max_json_len: usize = 8 << 20;
/// Most recipients of a general JWE JSON document `decryptJson` looks at.
pub const max_json_recipients: usize = 32;

pub const JsonForm = enum { flattened, general };

/// Re-serialize a compact JWE as the JSON serialization of one recipient (flattened, or general with a
/// single-element `recipients` array). The protected header, encrypted key, IV, ciphertext and tag are the
/// compact token's own segments, so the result decrypts with the same key through `decryptJson`.
/// For several recipients and the JSON `aad` member see `encryptJsonRecipients`.
// secret-api-ok: KeyMaterial holds only BORROWED slices / pointers; the key work runs in encryptCompact, the rest re-serializes its public output
pub fn encryptJson(
    gpa: std.mem.Allocator,
    form: JsonForm,
    key_alg: Alg,
    content_enc: Enc,
    key: KeyMaterial,
    plaintext: []const u8,
    entropy: Entropy,
    opts: EncryptOptions,
) EncryptError![]u8 {
    const compact = try encryptCompact(gpa, key_alg, content_enc, key, plaintext, "", entropy, opts);
    defer gpa.free(compact);
    var it = std.mem.splitScalar(u8, compact, '.');
    const protected = it.next().?;
    const ek = it.next().?;
    const iv = it.next().?;
    const ct = it.next().?;
    const tag = it.next().?;
    return switch (form) {
        .flattened => try std.fmt.allocPrint(gpa, "{{\"protected\":\"{s}\",\"encrypted_key\":\"{s}\",\"iv\":\"{s}\",\"ciphertext\":\"{s}\",\"tag\":\"{s}\"}}", .{ protected, ek, iv, ct, tag }),
        .general => try std.fmt.allocPrint(gpa, "{{\"protected\":\"{s}\",\"recipients\":[{{\"encrypted_key\":\"{s}\"}}],\"iv\":\"{s}\",\"ciphertext\":\"{s}\",\"tag\":\"{s}\"}}", .{ protected, ek, iv, ct, tag }),
    };
}

/// One recipient of `encryptJsonRecipients`: the key-management algorithm, the recipient's key and its own
/// `kid` / ECDH-ES `apu`/`apv` / PBES2 parameters (`EncryptOptions.cty` is the document's, in `JsonEncryptOptions`).
pub const JsonRecipient = struct {
    key_alg: Alg,
    key: KeyMaterial,
    opts: EncryptOptions = .{},
};

pub const JsonEncryptOptions = struct {
    /// Additional authenticated data (RFC 7516 §5.1, §7.2.1): written as the `aad` member and appended to the AEAD's
    /// AAD as `"." || BASE64URL(aad)`. `null` writes no member; an empty slice writes an empty one.
    aad: ?[]const u8 = null,
    /// `cty` of the protected header.
    cty: ?[]const u8 = null,
};

/// Encrypt `plaintext` to one or several recipients as a JWE JSON serialization (RFC 7516 §7.2). The protected header
/// carries `enc` (and `cty`); every recipient has its own unprotected `header` (`alg`, `kid`, `epk`, `iv` / `tag`,
/// `p2s` / `p2c`, `apu` / `apv`) and `encrypted_key`. With more than one recipient one fresh CEK is drawn and wrapped
/// for each (RSA-OAEP*, AxxxKW, AxxxGCMKW, PBES2-*, ECDH-ES+AxxxKW); `dir` and direct `ECDH-ES`, whose CEK is derived
/// from one key, are `UnsupportedAlg` there and only allowed as the sole recipient. `form = .flattened` needs exactly
/// one recipient. The result decrypts through `decryptJson` for every recipient's key. Returns a `gpa`-owned string.
// secret-api-ok: KeyMaterial holds only BORROWED slices / pointers; a by-value copy copies a pointer, never key bytes
pub fn encryptJsonRecipients(
    gpa: std.mem.Allocator,
    form: JsonForm,
    content_enc: Enc,
    recipients: []const JsonRecipient,
    plaintext: []const u8,
    entropy: Entropy,
    jopts: JsonEncryptOptions,
) EncryptError![]u8 {
    const random: std.Random = switch (entropy) {
        .csprng => |r| r,
        .fixed_for_test => |r| r,
    };
    if (content_enc == .unknown) return error.UnsupportedEnc;
    const cek_len = content_enc.cekLen() orelse return error.UnsupportedEnc;
    if (recipients.len == 0 or recipients.len > max_json_recipients) return error.InvalidRecipients;
    if (form == .flattened and recipients.len != 1) return error.InvalidRecipients;

    var cek_buf: [max_cek_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &cek_buf);
    const cek = cek_buf[0..cek_len];
    const shared = recipients.len > 1;
    if (shared) random.bytes(cek);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const b64 = std.base64.url_safe_no_pad;

    const Out = struct { header: []const u8, ek_b64: []const u8 };
    const outs = try arena.alloc(Out, recipients.len);
    for (recipients, outs) |r, *out| {
        if (r.key_alg == .unknown) return error.UnsupportedAlg;
        var w: Wrapped = .{};
        try wrapKey(&w, r.key_alg, content_enc, r.key, entropy, random, r.opts, cek, shared);
        var header_buf: [header.max_header_json_len]u8 = undefined;
        const header_json = header.encode(&header_buf, .{
            .alg = @tagName(r.key_alg),
            .enc = null,
            .kid = r.opts.kid,
            .iv = if (w.wrap_iv) |*v| v[0..] else null,
            .tag = if (w.wrap_tag) |*v| v[0..] else null,
            .p2s = w.pbes2_salt,
            .p2c = w.pbes2_iterations,
            .epk = w.epkParams(),
            .apu = if (w.epk_curve != null) r.opts.apu else null,
            .apv = if (w.epk_curve != null) r.opts.apv else null,
        }) catch return error.HeaderTooLarge;
        const ek_b64 = try arena.alloc(u8, b64.Encoder.calcSize(w.encrypted_key.len));
        _ = b64.Encoder.encode(ek_b64, w.encrypted_key);
        out.* = .{ .header = try arena.dupe(u8, header_json), .ek_b64 = ek_b64 };
    }

    const protected_json = try std.json.Stringify.valueAlloc(arena, .{ .enc = @tagName(content_enc), .cty = jopts.cty }, .{ .emit_null_optional_fields = false });
    const protected_b64 = try arena.alloc(u8, b64.Encoder.calcSize(protected_json.len));
    _ = b64.Encoder.encode(protected_b64, protected_json);
    var aad_b64: ?[]u8 = null;
    if (jopts.aad) |a| {
        aad_b64 = try arena.alloc(u8, b64.Encoder.calcSize(a.len));
        _ = b64.Encoder.encode(aad_b64.?, a);
    }
    const aead_aad = if (aad_b64) |ab| try std.fmt.allocPrint(arena, "{s}.{s}", .{ protected_b64, ab }) else protected_b64;

    var content_iv: [16]u8 = undefined;
    const iv_len = content_enc.ivLen().?;
    random.bytes(content_iv[0..iv_len]);
    const tag_len = content_enc.tagLen().?;
    const ct_scratch = try arena.alloc(u8, plaintext.len + 16);
    var tag_buf: [enc.max_tag_len]u8 = undefined;
    const ct_len = try enc.encrypt(content_enc, cek, content_iv[0..iv_len], aead_aad, plaintext, ct_scratch, tag_buf[0..tag_len]);

    const iv_b64 = try arena.alloc(u8, b64.Encoder.calcSize(iv_len));
    _ = b64.Encoder.encode(iv_b64, content_iv[0..iv_len]);
    const ct_b64 = try arena.alloc(u8, b64.Encoder.calcSize(ct_len));
    _ = b64.Encoder.encode(ct_b64, ct_scratch[0..ct_len]);
    const tag_b64 = try arena.alloc(u8, b64.Encoder.calcSize(tag_len));
    _ = b64.Encoder.encode(tag_b64, tag_buf[0..tag_len]);

    var doc: std.Io.Writer.Allocating = .init(gpa);
    errdefer doc.deinit();
    const wr = &doc.writer;
    (blk: {
        wr.print("{{\"protected\":\"{s}\"", .{protected_b64}) catch |e| break :blk e;
        if (aad_b64) |ab| wr.print(",\"aad\":\"{s}\"", .{ab}) catch |e| break :blk e;
        if (form == .general) {
            wr.writeAll(",\"recipients\":[") catch |e| break :blk e;
            for (outs, 0..) |o, i| {
                if (i != 0) wr.writeByte(',') catch |e| break :blk e;
                wr.print("{{\"header\":{s}", .{o.header}) catch |e| break :blk e;
                if (o.ek_b64.len != 0) wr.print(",\"encrypted_key\":\"{s}\"", .{o.ek_b64}) catch |e| break :blk e;
                wr.writeByte('}') catch |e| break :blk e;
            }
            wr.writeByte(']') catch |e| break :blk e;
        } else {
            wr.print(",\"header\":{s}", .{outs[0].header}) catch |e| break :blk e;
            if (outs[0].ek_b64.len != 0) wr.print(",\"encrypted_key\":\"{s}\"", .{outs[0].ek_b64}) catch |e| break :blk e;
        }
        wr.print(",\"iv\":\"{s}\",\"ciphertext\":\"{s}\",\"tag\":\"{s}\"}}", .{ iv_b64, ct_b64, tag_b64 }) catch |e| break :blk e;
    }) catch return error.OutOfMemory;
    return doc.toOwnedSlice() catch return error.OutOfMemory;
}

fn jsonString(obj: std.json.ObjectMap, name: []const u8) DecryptError!?[]const u8 {
    const v = obj.get(name) orelse return null;
    return switch (v) {
        .string => |str| str,
        else => error.MalformedToken,
    };
}

fn jsonObject(obj: std.json.ObjectMap, name: []const u8) DecryptError!?std.json.ObjectMap {
    const v = obj.get(name) orelse return null;
    return switch (v) {
        .object => |o| o,
        else => error.MalformedToken,
    };
}

/// Add every member of `from` to `into`; a name already present is `MalformedToken` (RFC 7516 §7.2.1: header
/// parameter names MUST be unique across the protected, shared unprotected and per-recipient headers).
fn mergeHeader(arena: std.mem.Allocator, into: *std.json.ObjectMap, from: ?std.json.ObjectMap) DecryptError!void {
    const f = from orelse return;
    var it = f.iterator();
    while (it.next()) |e| {
        const gop = try into.getOrPut(arena, e.key_ptr.*);
        if (gop.found_existing) return error.MalformedToken;
        gop.value_ptr.* = e.value_ptr.*;
    }
}

/// Decrypt a JWE in JSON serialization, flattened or general (RFC 7516 §7.2.1 / §7.2.2). Recipients are tried in
/// order with `key`: one whose header (protected + shared unprotected + its own, names unique) names an `alg` the
/// key cannot serve (`KeyMaterialMismatch`, `AlgMismatch`, ...) is skipped, and the first that decrypts wins; if none
/// does, the last error is returned. The AEAD's AAD is `BASE64URL(protected)` and, when the document carries an
/// `aad` member, `"." || aad` (§5.1). With `recipients` present, a top-level `header` / `encrypted_key` (which §7.2.1
/// forbids, and go-jose writes) is ignored entirely: not in the header union, not the AAD, not tried as a key.
/// Returns `gpa`-owned plaintext.
// secret-api-ok: KeyMaterial holds only BORROWED slices / pointers; a by-value copy copies a pointer, never key bytes
pub fn decryptJson(
    gpa: std.mem.Allocator,
    key: KeyMaterial,
    json: []const u8,
    opts: DecryptOptions,
) DecryptError![]u8 {
    return burn.run(burn.content_burn, DecryptError![]u8, decryptJsonBody, .{ gpa, key, json, opts });
}

fn decryptJsonBody(
    gpa: std.mem.Allocator,
    key: KeyMaterial,
    json: []const u8,
    opts: DecryptOptions,
) DecryptError![]u8 {
    if (json.len > max_json_len) return error.MalformedToken;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, json, .{}) catch return error.MalformedToken;
    const top = switch (root) {
        .object => |o| o,
        else => return error.MalformedToken,
    };

    const protected_b64 = try jsonString(top, "protected");
    var protected_obj: ?std.json.ObjectMap = null;
    if (protected_b64) |pb| {
        if (pb.len == 0) return error.MalformedToken;
        if (pb.len > header.max_header_b64_len) return error.HeaderTooLarge;
        const pj = try decodeSegmentAlloc(arena, pb);
        const pv = std.json.parseFromSliceLeaky(std.json.Value, arena, pj, .{}) catch return error.MalformedToken;
        protected_obj = switch (pv) {
            .object => |o| o,
            else => return error.MalformedToken,
        };
    }
    const shared_unprotected = try jsonObject(top, "unprotected");
    const iv_b64 = (try jsonString(top, "iv")) orelse return error.MalformedToken;
    const ct_b64 = (try jsonString(top, "ciphertext")) orelse return error.MalformedToken;
    const tag_b64 = (try jsonString(top, "tag")) orelse return error.MalformedToken;
    const content_iv = try decodeSegmentAlloc(arena, iv_b64);
    const ciphertext = try decodeSegmentAlloc(arena, ct_b64);
    const tag = try decodeSegmentAlloc(arena, tag_b64);

    // AAD (RFC 7516 §5.1): ASCII(BASE64URL(protected)), then "." || BASE64URL(aad) if `aad` is present.
    const aad_member = try jsonString(top, "aad");
    const aad: []const u8 = if (aad_member) |am| blk: {
        _ = try decodeSegmentAlloc(arena, am); // must be base64url
        break :blk try std.fmt.allocPrint(arena, "{s}.{s}", .{ protected_b64 orelse "", am });
    } else protected_b64 orelse "";

    // Recipients: general (`recipients` array) or flattened (the recipient's members are at the top level).
    const Recipient = struct { header: ?std.json.ObjectMap, ek_b64: []const u8 };
    var recipients: [max_json_recipients]Recipient = undefined;
    var n_rec: usize = 0;
    if (top.get("recipients")) |rv| {
        // A top-level `header` / `encrypted_key` next to `recipients` is ignored (go-jose writes one; RFC 7516 §7.2.1
        // forbids producers to; panva/jose, nimbus and jwcrypto read `recipients` only).
        const arr = switch (rv) {
            .array => |a| a,
            else => return error.MalformedToken,
        };
        if (arr.items.len == 0 or arr.items.len > max_json_recipients) return error.MalformedToken;
        for (arr.items) |item| {
            const o = switch (item) {
                .object => |o| o,
                else => return error.MalformedToken,
            };
            recipients[n_rec] = .{ .header = try jsonObject(o, "header"), .ek_b64 = (try jsonString(o, "encrypted_key")) orelse "" };
            n_rec += 1;
        }
    } else {
        recipients[0] = .{ .header = try jsonObject(top, "header"), .ek_b64 = (try jsonString(top, "encrypted_key")) orelse "" };
        n_rec = 1;
    }

    var last_err: DecryptError = error.MalformedToken;
    for (recipients[0..n_rec]) |rec| {
        var merged: std.json.ObjectMap = .empty;
        try mergeHeader(arena, &merged, protected_obj);
        try mergeHeader(arena, &merged, shared_unprotected);
        try mergeHeader(arena, &merged, rec.header);
        const merged_json = try std.json.Stringify.valueAlloc(arena, std.json.Value{ .object = merged }, .{});
        const parsed = header.parse(arena, merged_json) catch |e| {
            last_err = e;
            continue;
        };
        if (parsed.alg == .unknown) {
            last_err = error.UnsupportedAlg;
            continue;
        }
        if (parsed.enc == .unknown) {
            last_err = error.UnsupportedEnc;
            continue;
        }
        if (opts.expect_alg) |want| if (want != parsed.alg) {
            last_err = error.AlgMismatch;
            continue;
        };
        if (opts.expect_enc) |want| if (want != parsed.enc) {
            last_err = error.EncMismatch;
            continue;
        };
        const cek_len = parsed.enc.cekLen() orelse {
            last_err = error.UnsupportedEnc;
            continue;
        };
        const encrypted_key = decodeSegmentAlloc(arena, rec.ek_b64) catch |e| {
            last_err = e;
            continue;
        };
        var cek_buf: [max_cek_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &cek_buf);
        const plaintext = unwrapAndFinish(gpa, parsed, key, aad, encrypted_key, content_iv, ciphertext, tag, cek_buf[0..cek_len], cek_len, opts) catch |e| {
            last_err = e;
            continue;
        };
        return plaintext;
    }
    return last_err;
}

/// Derive a decoy CEK the peer cannot compute, so a failed key unwrap runs the
/// content decryption anyway and fails there like any wrong key would.
/// Domain-separated, and bound to the encrypted key so the same token always
/// takes the same path.
fn decoyCek(key: KeyMaterial, encrypted_key: []const u8, out: []u8) void {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("zig-libs/jwe decoy CEK v1");
    // Secret material the sender of a forged token does not have. Which arm is
    // present depends on `alg`; any of them is unpredictable to the peer.
    switch (key) {
        .symmetric => |k| h.update(k),
        .password => |p| h.update(p),
        .rsa_private, .ec_private, .rsa_public, .ec_public => {
            // Key types with no directly hashable byte slice here: the
            // encrypted key alone still gives a per-token constant, which is
            // all this needs — the CEK is wrong either way, and the point is
            // that the work happens, not that the decoy is secret-keyed.
        },
    }
    h.update(encrypted_key);
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    h.final(&digest);
    const n = @min(out.len, digest.len);
    @memcpy(out[0..n], digest[0..n]);
    if (out.len > n) @memset(out[n..], 0);
}

fn unwrapCek(
    parsed: header.Parsed,
    key: KeyMaterial,
    encrypted_key: []const u8,
    cek: []u8,
    cek_len: usize,
    opts: DecryptOptions,
) DecryptError!void {
    switch (parsed.alg) {
        .dir => {
            const shared = switch (key) {
                .symmetric => |s| s,
                else => return error.KeyMaterialMismatch,
            };
            // RFC 7516 §5.2 step 10, the same rule as ECDH-ES below: Direct
            // Encryption carries no Encrypted Key. The segment is not in the
            // AAD, so without this anyone could splice bytes into it and the
            // token would still decrypt — a second, different token for the
            // same message (found, mutation-run review).
            if (encrypted_key.len != 0) return error.MalformedToken;
            _ = try alg.dirCek(shared, cek_len, cek);
        },
        .@"RSA-OAEP", .@"RSA-OAEP-256" => {
            const sk = switch (key) {
                .rsa_private => |s| s,
                else => return error.KeyMaterialMismatch,
            };
            const hash: alg.OaepHash = if (parsed.alg == .@"RSA-OAEP") .sha1 else .sha256;
            // OAEP decrypt requires `out` sized to the worst-case recoverable
            // message length regardless of the *expected* CEK length (so its
            // own buffer-size check can't leak length info) — use a
            // dedicated max-size scratch, then copy the actual CEK out.
            var oaep_buf: [max_encrypted_key_len]u8 = undefined;
            // Z1 (CONVENTIONS.md §2.1, audit F1): this scratch holds the
            // full OAEP-decrypted message (the recovered CEK is a prefix of
            // it) — module-owned, known death, not Z2/Z3. Registered before
            // the fallible unwrap call so a failed/rejected unwrap still
            // wipes whatever the RSA op wrote.
            defer std.crypto.secureZero(u8, &oaep_buf);
            const got = try alg.rsaOaepUnwrap(sk, hash, encrypted_key, &oaep_buf);
            if (got.len != cek_len) return error.InvalidKey;
            @memcpy(cek, got[0..cek_len]);
        },
        .A128KW, .A192KW, .A256KW => {
            const kek = switch (key) {
                .symmetric => |s| s,
                else => return error.KeyMaterialMismatch,
            };
            _ = try alg.aeskw.unwrap(kek, encrypted_key, cek);
        },
        .A128GCMKW, .A192GCMKW, .A256GCMKW => {
            const kek = switch (key) {
                .symmetric => |s| s,
                else => return error.KeyMaterialMismatch,
            };
            const wrap_iv = parsed.iv orelse return error.InvalidKey;
            const wrap_tag = parsed.tag orelse return error.InvalidKey;
            if (wrap_iv.len != 12 or wrap_tag.len != 16) return error.InvalidKey;
            const got = try alg.gcmkwUnwrap(kek, wrap_iv[0..12].*, wrap_tag[0..16].*, encrypted_key, cek);
            if (got.len != cek_len) return error.InvalidKey;
        },
        .@"PBES2-HS256+A128KW", .@"PBES2-HS384+A192KW", .@"PBES2-HS512+A256KW" => {
            const password = switch (key) {
                .password => |p| p,
                else => return error.KeyMaterialMismatch,
            };
            const p2s = parsed.p2s orelse return error.InvalidKey;
            const p2c = parsed.p2c orelse return error.InvalidKey;
            // Before the derivation, not after: the whole point is not to
            // perform the work the token asked for.
            if (p2c > opts.max_p2c) return error.WorkFactorTooHigh;
            // RFC 7518 §4.8.1.1: "A minimum salt length of 8 octets MUST be
            // used." The encrypt-side doc called this a recommendation.
            if (p2s.len < 8) return error.InvalidKey;
            const variant: alg.Pbes2Variant = switch (parsed.alg) {
                .@"PBES2-HS256+A128KW" => .hs256_a128kw,
                .@"PBES2-HS384+A192KW" => .hs384_a192kw,
                .@"PBES2-HS512+A256KW" => .hs512_a256kw,
                else => unreachable,
            };
            var kek_buf: [32]u8 = undefined;
            const kek = try alg.pbes2DeriveKek(variant, password, p2s, p2c, &kek_buf);
            _ = try alg.aeskw.unwrap(kek, encrypted_key, cek);
        },
        .@"ECDH-ES", .@"ECDH-ES+A128KW", .@"ECDH-ES+A192KW", .@"ECDH-ES+A256KW" => {
            const sk = switch (key) {
                .ec_private => |s| s,
                else => return error.KeyMaterialMismatch,
            };
            // Structural, decided before any secret is touched — see the
            // §11.5 note above for why these stay distinguishable.
            const epk = parsed.epk orelse return error.MalformedToken;
            // Typed cross-curve rejection: the epk's curve must be one this
            // module implements AND the same curve as the recipient key —
            // before any point decoding or scalar mult runs.
            const curve = ecdhes.Curve.fromJwkCrv(epk.crv) orelse return error.CurveMismatch;
            if (curve != std.meta.activeTag(sk.*)) return error.CurveMismatch;
            const peer = try ecdhes.PublicKey.fromCoordinates(curve, epk.x, epk.y);
            var z_buf: [ecdhes.max_z_len]u8 = undefined;
            defer std.crypto.secureZero(u8, &z_buf);
            const z = try ecdhes.deriveZ(sk, peer, &z_buf);
            const apu = parsed.apu orelse "";
            const apv = parsed.apv orelse "";
            if (parsed.alg == .@"ECDH-ES") {
                // Direct Key Agreement: the Encrypted Key segment MUST be
                // empty (RFC 7516 §5.2 step 10 — this comment used to cite
                // step 5, which is the `crit` step) — a non-empty one is a
                // malformed/hostile token, not something to ignore. That
                // segment is outside the AAD, so accepting it is unbounded
                // token malleability with no key at all.
                if (encrypted_key.len != 0) return error.MalformedToken;
                ecdhes.concatKdfSha256(z, @tagName(parsed.enc), apu, apv, cek);
            } else {
                const kek_len: usize = switch (parsed.alg) {
                    .@"ECDH-ES+A128KW" => 16,
                    .@"ECDH-ES+A192KW" => 24,
                    .@"ECDH-ES+A256KW" => 32,
                    else => unreachable,
                };
                var kek_buf: [32]u8 = undefined;
                defer std.crypto.secureZero(u8, &kek_buf);
                const kek = kek_buf[0..kek_len];
                ecdhes.concatKdfSha256(z, @tagName(parsed.alg), apu, apv, kek);
                _ = try alg.aeskw.unwrap(kek, encrypted_key, cek);
            }
        },
        .unknown => unreachable,
    }
}

/// The content decryption, reached identically whether the key unwrap
/// succeeded or a decoy CEK was substituted — that sameness is the point.
fn finishDecrypt(
    gpa: std.mem.Allocator,
    parsed: header.Parsed,
    header_b64: []const u8,
    cek: []const u8,
    content_iv: []const u8,
    ciphertext: []const u8,
    tag: []const u8,
) DecryptError![]u8 {
    const plaintext = try gpa.alloc(u8, ciphertext.len);
    errdefer gpa.free(plaintext);
    const n = try enc.decrypt(parsed.enc, cek, content_iv, header_b64, ciphertext, tag, plaintext);
    if (n == plaintext.len) return plaintext;
    const trimmed = try gpa.realloc(plaintext, n);
    return trimmed;
}

/// The one place this file's test call sites enter `Entropy`'s weak arm.
/// Returns the tagged VALUE, not a `std.Random`, so no test can hand a
/// generator to `encryptCompact` without the claim travelling with it.
/// Production callers supply `.{ .csprng = … }` — see `entropy.zig`.
fn seededForTest() Entropy {
    const S = struct {
        var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x42)));
    };
    return .{ .fixed_for_test = S.csprng.random() };
}

fn decodeSegmentAlloc(arena: std.mem.Allocator, segment: []const u8) error{ OutOfMemory, InvalidBase64 }![]u8 {
    const b64 = std.base64.url_safe_no_pad;
    const n = b64.Decoder.calcSizeForSlice(segment) catch return error.InvalidBase64;
    const buf = try arena.alloc(u8, n);
    b64.Decoder.decode(buf, segment) catch return error.InvalidBase64;
    return buf;
}

test {
    _ = header;
    _ = enc;
    _ = alg;
    _ = aeskw;
    _ = ecdhes;
    _ = @import("kat_rfc7516.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("stackprobe_test.zig");
    _ = @import("stackprobe2_test.zig");
    _ = @import("stackprobe3_test.zig");
    _ = @import("sweep_test.zig");
}

test "dir + A128GCM real round-trip" {
    const key = @as([16]u8, @splat(0x2b));
    const token = try encryptCompact(std.testing.allocator, .dir, .A128GCM, .{ .symmetric = &key }, "attack at dawn", "", seededForTest(), .{});
    defer std.testing.allocator.free(token);

    const plaintext = try decryptCompact(std.testing.allocator, .{ .symmetric = &key }, token, .{});
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings("attack at dawn", plaintext);
}

test "dir + A256GCM real round-trip, empty plaintext" {
    const key = @as([32]u8, @splat(0x11));
    const token = try encryptCompact(std.testing.allocator, .dir, .A256GCM, .{ .symmetric = &key }, "", "", seededForTest(), .{});
    defer std.testing.allocator.free(token);

    const plaintext = try decryptCompact(std.testing.allocator, .{ .symmetric = &key }, token, .{});
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings("", plaintext);
}

test "every A192 algorithm round-trips: A192KW, A192GCMKW, PBES2-HS384+A192KW, ECDH-ES+A192KW x A192GCM, A192CBC-HS384" {
    // RFC 7520 has no AES-192 example for any of these; the anchors are the
    // primitives' own KATs (aeskw RFC 3394 §4.2/§4.4, McGrew–Viega 7–10,
    // RFC 7518 B.2) plus these full-token round trips.
    const gpa = std.testing.allocator;
    const kek = @as([24]u8, @splat(0x5c));
    var recipient: ecdhes.EphemeralKeyPair = undefined;
    ecdhes.generateEphemeral(&recipient, .p256, seededForTest());
    inline for (.{ Enc.A192GCM, Enc.@"A192CBC-HS384" }) |e| {
        inline for (.{ Alg.A192KW, Alg.A192GCMKW, Alg.@"PBES2-HS384+A192KW", Alg.@"ECDH-ES+A192KW", Alg.dir }) |a| {
            var cek_buf: [48]u8 = @splat(0x3e);
            const enc_key: KeyMaterial, const dec_key: KeyMaterial = switch (a) {
                .A192KW, .A192GCMKW => .{ .{ .symmetric = &kek }, .{ .symmetric = &kek } },
                .@"PBES2-HS384+A192KW" => .{ .{ .password = "correct horse" }, .{ .password = "correct horse" } },
                .@"ECDH-ES+A192KW" => .{ .{ .ec_public = recipient.public }, .{ .ec_private = &recipient.private } },
                .dir => .{ .{ .symmetric = cek_buf[0..e.cekLen().?] }, .{ .symmetric = cek_buf[0..e.cekLen().?] } },
                else => unreachable,
            };
            const token = try encryptCompact(gpa, a, e, enc_key, "AES-192 everywhere", "", seededForTest(), .{ .pbes2_iterations = 1000 });
            defer gpa.free(token);
            const pt = try decryptCompact(gpa, dec_key, token, .{ .expect_alg = a });
            defer gpa.free(pt);
            try std.testing.expectEqualStrings("AES-192 everywhere", pt);
        }
    }
}

test "A128GCMKW + A128GCM real round-trip" {
    const kek = @as([16]u8, @splat(0x77));
    const token = try encryptCompact(std.testing.allocator, .A128GCMKW, .A128GCM, .{ .symmetric = &kek }, "the eagle flies at midnight", "", seededForTest(), .{});
    defer std.testing.allocator.free(token);

    const plaintext = try decryptCompact(std.testing.allocator, .{ .symmetric = &kek }, token, .{});
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings("the eagle flies at midnight", plaintext);
}

test "tampered ciphertext fails authentication, never returns garbage plaintext" {
    const key = @as([16]u8, @splat(0x2b));
    const token = try encryptCompact(std.testing.allocator, .dir, .A128GCM, .{ .symmetric = &key }, "attack at dawn", "", seededForTest(), .{});
    defer std.testing.allocator.free(token);

    var mutable = try std.testing.allocator.dupe(u8, token);
    defer std.testing.allocator.free(mutable);
    // Flip the FIRST byte of the ciphertext segment (4th dot-separated
    // field) — not the last character of any segment, so this can't
    // spuriously trip base64's "unused trailing bits must be zero" check;
    // it lands squarely inside the ciphertext's own base64 content.
    var it = std.mem.splitScalar(u8, mutable, '.');
    _ = it.next().?; // header
    _ = it.next().?; // encrypted_key
    _ = it.next().?; // iv
    const ct_field = it.next().?;
    const ct_start = @intFromPtr(ct_field.ptr) - @intFromPtr(mutable.ptr);
    mutable[ct_start] ^= 0x01;

    try std.testing.expectError(error.AuthenticationFailed, decryptCompact(std.testing.allocator, .{ .symmetric = &key }, mutable, .{}));
}

test "key-material confusion is rejected: dir token vs RSA key" {
    const key = @as([16]u8, @splat(0x2b));
    const token = try encryptCompact(std.testing.allocator, .dir, .A128GCM, .{ .symmetric = &key }, "hi", "", seededForTest(), .{});
    defer std.testing.allocator.free(token);

    const bogus_rsa = rsa.PublicKey.fromBytes(&@as([128]u8, @splat(0xff)), &[_]u8{ 0x01, 0x00, 0x01 }) catch unreachable;
    try std.testing.expectError(error.KeyMaterialMismatch, decryptCompact(std.testing.allocator, .{ .rsa_public = bogus_rsa }, token, .{}));
}

test "compact serialization rejects non-empty aad_extra" {
    const key = @as([16]u8, @splat(0x2b));
    try std.testing.expectError(error.CompactSerializationNoAad, encryptCompact(std.testing.allocator, .dir, .A128GCM, .{ .symmetric = &key }, "hi", "extra", seededForTest(), .{}));
}

test "unknown alg/enc are rejected up front" {
    const key = @as([16]u8, @splat(0x2b));
    try std.testing.expectError(error.UnsupportedAlg, encryptCompact(std.testing.allocator, .unknown, .A128GCM, .{ .symmetric = &key }, "hi", "", seededForTest(), .{}));
    try std.testing.expectError(error.UnsupportedEnc, encryptCompact(std.testing.allocator, .dir, .unknown, .{ .symmetric = &key }, "hi", "", seededForTest(), .{}));
}

test "ECDH-ES direct + A128GCM real round-trip (P-256, apu/apv, empty encrypted_key)" {
    var recipient: ecdhes.EphemeralKeyPair = undefined;
    ecdhes.generateEphemeral(&recipient, .p256, seededForTest());
    const token = try encryptCompact(
        std.testing.allocator,
        .@"ECDH-ES",
        .A128GCM,
        .{ .ec_public = recipient.public },
        "meet at the old bridge",
        "",
        seededForTest(),
        .{ .apu = "Alice", .apv = "Bob" },
    );
    defer std.testing.allocator.free(token);

    // Direct Key Agreement: the Encrypted Key segment must be EMPTY.
    var it = std.mem.splitScalar(u8, token, '.');
    _ = it.next().?; // header
    try std.testing.expectEqual(@as(usize, 0), it.next().?.len);

    const plaintext = try decryptCompact(std.testing.allocator, .{ .ec_private = &recipient.private }, token, .{
        .expect_alg = .@"ECDH-ES",
        .expect_enc = .A128GCM,
    });
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings("meet at the old bridge", plaintext);
}

test "ECDH-ES over P-384 and P-521 round-trips, direct and with key wrap; epk is a full-width JWK" {
    inline for ([_]ecdhes.Curve{ .p384, .p521 }) |crv| {
        const width: usize = if (crv == .p384) 48 else 66;
        var recipient: ecdhes.EphemeralKeyPair = undefined;
        ecdhes.generateEphemeral(&recipient, crv, seededForTest());
        for ([_]Alg{ .@"ECDH-ES", .@"ECDH-ES+A128KW", .@"ECDH-ES+A256KW" }) |key_alg| {
            const token = try encryptCompact(std.testing.allocator, key_alg, .A256GCM, .{ .ec_public = recipient.public }, "curves of the NIST family", "", seededForTest(), .{});
            defer std.testing.allocator.free(token);
            var it = std.mem.splitScalar(u8, token, '.');
            var hdr_buf: [512]u8 = undefined;
            const hdr_b64 = it.next().?;
            const hdr = hdr_buf[0..try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(hdr_b64)];
            try std.base64.url_safe_no_pad.Decoder.decode(hdr, hdr_b64);
            const want = if (crv == .p384) "\"crv\":\"P-384\"" else "\"crv\":\"P-521\"";
            try std.testing.expect(std.mem.find(u8, hdr, want) != null);
            var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena.deinit();
            const parsed = try header.parse(arena.allocator(), hdr);
            try std.testing.expectEqual(width, parsed.epk.?.x.len);
            try std.testing.expectEqual(width, parsed.epk.?.y.?.len);
            const plaintext = try decryptCompact(std.testing.allocator, .{ .ec_private = &recipient.private }, token, .{ .expect_alg = key_alg });
            defer std.testing.allocator.free(plaintext);
            try std.testing.expectEqualStrings("curves of the NIST family", plaintext);
        }
        // A key of another curve is refused before any point arithmetic.
        var other: ecdhes.EphemeralKeyPair = undefined;
        ecdhes.generateEphemeral(&other, .p256, seededForTest());
        const t2 = try encryptCompact(std.testing.allocator, .@"ECDH-ES", .A128GCM, .{ .ec_public = recipient.public }, "x", "", seededForTest(), .{});
        defer std.testing.allocator.free(t2);
        try std.testing.expectError(error.CurveMismatch, decryptCompact(std.testing.allocator, .{ .ec_private = &other.private }, t2, .{}));
    }
}

test "JSON serialization: flattened and general round-trip; tampering and a wrong key fail" {
    const gpa = std.testing.allocator;
    const kek: [16]u8 = @splat(0x5a);
    for ([_]JsonForm{ .flattened, .general }) |form| {
        const doc = try encryptJson(gpa, form, .A128KW, .A128GCM, .{ .symmetric = &kek }, "json form", seededForTest(), .{ .kid = "k1" });
        defer gpa.free(doc);
        const pt = try decryptJson(gpa, .{ .symmetric = &kek }, doc, .{ .expect_alg = .A128KW });
        defer gpa.free(pt);
        try std.testing.expectEqualStrings("json form", pt);
        const wrong: [16]u8 = @splat(0x5b);
        try std.testing.expectError(error.AuthenticationFailed, decryptJson(gpa, .{ .symmetric = &wrong }, doc, .{}));
        try std.testing.expectError(error.AlgMismatch, decryptJson(gpa, .{ .symmetric = &kek }, doc, .{ .expect_alg = .A256KW }));
        const bad = try gpa.dupe(u8, doc);
        defer gpa.free(bad);
        const at = std.mem.find(u8, bad, "\"ciphertext\":\"") orelse return error.TestUnexpectedResult;
        bad[at + 14] = if (bad[at + 14] == 'A') 'B' else 'A';
        try std.testing.expectError(error.AuthenticationFailed, decryptJson(gpa, .{ .symmetric = &kek }, bad, .{}));
    }
    try std.testing.expectError(error.MalformedToken, decryptJson(gpa, .{ .symmetric = &kek }, "[]", .{}));
    try std.testing.expectError(error.MalformedToken, decryptJson(gpa, .{ .symmetric = &kek }, "{\"iv\":\"AA\"}", .{}));
}

test "JSON serialization: a two-recipient general JWE decrypts for either recipient; shared header names must be unique; aad is bound" {
    const gpa = std.testing.allocator;
    const b64 = std.base64.url_safe_no_pad;
    const k1: [16]u8 = @splat(0x61);
    const k2: [16]u8 = @splat(0x62);
    const cek: [16]u8 = @splat(0x7c);
    var w1: [24]u8 = undefined;
    var w2: [24]u8 = undefined;
    const e1 = try aeskw.wrap(&k1, &cek, &w1);
    const e2 = try aeskw.wrap(&k2, &cek, &w2);
    const protected = "{\"enc\":\"A128GCM\"}";
    var pb: [64]u8 = undefined;
    const protected_b64 = b64.Encoder.encode(&pb, protected);
    const aad_b64 = "YWFk"; // "aad"
    const aad = try std.fmt.allocPrint(gpa, "{s}.{s}", .{ protected_b64, aad_b64 });
    defer gpa.free(aad);
    const iv: [12]u8 = @splat(0x33);
    var ct: [16]u8 = undefined;
    var tag: [16]u8 = undefined;
    const n = try enc.encrypt(.A128GCM, &cek, &iv, aad, "two recipients", &ct, &tag);
    var buf: [1024]u8 = undefined;
    var f1: [64]u8 = undefined;
    var f2: [64]u8 = undefined;
    var fiv: [32]u8 = undefined;
    var fct: [32]u8 = undefined;
    var ftag: [32]u8 = undefined;
    const doc = try std.fmt.bufPrint(&buf, "{{\"protected\":\"{s}\",\"aad\":\"{s}\",\"recipients\":[" ++
        "{{\"header\":{{\"alg\":\"A128KW\",\"kid\":\"one\"}},\"encrypted_key\":\"{s}\"}}," ++
        "{{\"header\":{{\"alg\":\"A128KW\",\"kid\":\"two\"}},\"encrypted_key\":\"{s}\"}}]," ++
        "\"iv\":\"{s}\",\"ciphertext\":\"{s}\",\"tag\":\"{s}\"}}", .{
        protected_b64,                   aad_b64,
        b64.Encoder.encode(&f1, e1),     b64.Encoder.encode(&f2, e2),
        b64.Encoder.encode(&fiv, &iv),   b64.Encoder.encode(&fct, ct[0..n]),
        b64.Encoder.encode(&ftag, &tag),
    });
    for ([_]*const [16]u8{ &k1, &k2 }) |k| {
        const pt = try decryptJson(gpa, .{ .symmetric = k }, doc, .{});
        defer gpa.free(pt);
        try std.testing.expectEqualStrings("two recipients", pt);
    }
    const other: [16]u8 = @splat(0x63);
    try std.testing.expectError(error.AuthenticationFailed, decryptJson(gpa, .{ .symmetric = &other }, doc, .{}));
    // A changed aad member breaks the AEAD.
    var tampered: [1024]u8 = undefined;
    @memcpy(tampered[0..doc.len], doc);
    const at = std.mem.find(u8, tampered[0..doc.len], "\"aad\":\"YWFk") orelse return error.TestUnexpectedResult;
    tampered[at + 9] = 'Z';
    try std.testing.expectError(error.AuthenticationFailed, decryptJson(gpa, .{ .symmetric = &k1 }, tampered[0..doc.len], .{}));
    // The same parameter name in the protected and a per-recipient header is malformed.
    const dup = try std.mem.replaceOwned(u8, gpa, doc, "\"kid\":\"one\"", "\"enc\":\"A128GCM\"");
    defer gpa.free(dup);
    try std.testing.expectError(error.MalformedToken, decryptJson(gpa, .{ .symmetric = &k1 }, dup, .{}));
    // A stray top-level `header` / `encrypted_key` beside `recipients` (go-jose writes one, RFC 7516 §7.2.1 forbids it)
    // has no effect: not in the header union (its `alg` / `enc` are not used), not tried as a key, not in the AAD.
    const stray = try std.mem.replaceOwned(u8, gpa, doc, "{\"protected\"", "{\"header\":{\"alg\":\"A256KW\",\"enc\":\"A256GCM\"},\"encrypted_key\":\"AAAA\",\"protected\"");
    defer gpa.free(stray);
    try std.testing.expect(stray.len > doc.len);
    for ([_]*const [16]u8{ &k1, &k2 }) |k| {
        const pt = try decryptJson(gpa, .{ .symmetric = k }, stray, .{});
        defer gpa.free(pt);
        try std.testing.expectEqualStrings("two recipients", pt);
    }
    try std.testing.expectError(error.AuthenticationFailed, decryptJson(gpa, .{ .symmetric = &other }, stray, .{}));
    // Our own writers never emit them: no top-level `header` / `encrypted_key` in a general document.
    const ours = try encryptJson(gpa, .general, .A128KW, .A128GCM, .{ .symmetric = &k1 }, "x", seededForTest(), .{});
    defer gpa.free(ours);
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, ours, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value.object.get("recipients") != null);
    try std.testing.expect(parsed.value.object.get("header") == null and parsed.value.object.get("encrypted_key") == null);
}

test "ECDH-ES+A256KW over X25519 real round-trip" {
    var recipient: ecdhes.EphemeralKeyPair = undefined;
    ecdhes.generateEphemeral(&recipient, .x25519, seededForTest());
    const token = try encryptCompact(
        std.testing.allocator,
        .@"ECDH-ES+A256KW",
        .A256GCM,
        .{ .ec_public = recipient.public },
        "the eagle flies at midnight",
        "",
        seededForTest(),
        .{},
    );
    defer std.testing.allocator.free(token);

    const plaintext = try decryptCompact(std.testing.allocator, .{ .ec_private = &recipient.private }, token, .{
        .expect_alg = .@"ECDH-ES+A256KW",
    });
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings("the eagle flies at midnight", plaintext);
}

test "ECDH-ES+A128KW + A128CBC-HS256 real round-trip (P-256)" {
    var recipient: ecdhes.EphemeralKeyPair = undefined;
    ecdhes.generateEphemeral(&recipient, .p256, seededForTest());
    const token = try encryptCompact(
        std.testing.allocator,
        .@"ECDH-ES+A128KW",
        .@"A128CBC-HS256",
        .{ .ec_public = recipient.public },
        "wrapped CEK, CBC-HMAC content",
        "",
        seededForTest(),
        .{ .apv = "bob@example.org" },
    );
    defer std.testing.allocator.free(token);

    const plaintext = try decryptCompact(std.testing.allocator, .{ .ec_private = &recipient.private }, token, .{});
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings("wrapped CEK, CBC-HMAC content", plaintext);
}

test "ECDH-ES cross-curve confusion is rejected: P-256 token vs X25519 key (typed)" {
    var p256_recipient: ecdhes.EphemeralKeyPair = undefined;
    ecdhes.generateEphemeral(&p256_recipient, .p256, seededForTest());
    var x25519_recipient: ecdhes.EphemeralKeyPair = undefined;
    ecdhes.generateEphemeral(&x25519_recipient, .x25519, seededForTest());
    const token = try encryptCompact(std.testing.allocator, .@"ECDH-ES", .A128GCM, .{ .ec_public = p256_recipient.public }, "hi", "", seededForTest(), .{});
    defer std.testing.allocator.free(token);

    try std.testing.expectError(error.CurveMismatch, decryptCompact(std.testing.allocator, .{ .ec_private = &x25519_recipient.private }, token, .{}));
}

test "ECDH-ES key-material confusion is rejected: ECDH token vs symmetric key" {
    var recipient: ecdhes.EphemeralKeyPair = undefined;
    ecdhes.generateEphemeral(&recipient, .p256, seededForTest());
    const token = try encryptCompact(std.testing.allocator, .@"ECDH-ES", .A128GCM, .{ .ec_public = recipient.public }, "hi", "", seededForTest(), .{});
    defer std.testing.allocator.free(token);

    const key = @as([16]u8, @splat(0x2b));
    try std.testing.expectError(error.KeyMaterialMismatch, decryptCompact(std.testing.allocator, .{ .symmetric = &key }, token, .{}));
}

test "ECDH-ES direct rejects a non-empty encrypted_key segment" {
    var recipient: ecdhes.EphemeralKeyPair = undefined;
    ecdhes.generateEphemeral(&recipient, .p256, seededForTest());
    const token = try encryptCompact(std.testing.allocator, .@"ECDH-ES", .A128GCM, .{ .ec_public = recipient.public }, "hi", "", seededForTest(), .{});
    defer std.testing.allocator.free(token);

    // Splice a non-empty Encrypted Key into the (empty) second segment.
    var it = std.mem.splitScalar(u8, token, '.');
    const h = it.next().?;
    _ = it.next().?; // empty encrypted_key
    const rest = it.rest();
    const forged = try std.testing.allocator.print("{s}.AAAAAAAAAAA.{s}", .{ h, rest });
    defer std.testing.allocator.free(forged);

    // `MalformedToken`, not `InvalidKey`: this is a structural property of the
    // token decided before any secret is used, and it is deliberately NOT
    // collapsed into the §11.5 unified key-error path — collapsing it would
    // hide the malleability defense it exists to be.
    try std.testing.expectError(error.MalformedToken, decryptCompact(std.testing.allocator, .{ .ec_private = &recipient.private }, forged, .{}));
}

// Was "ECDH-ES+A192KW is the documented AES-192 std gap" (expected
// UnsupportedKeyLength) until aeskw gained the 24-byte KEK arm over the
// `aes192` module,. RFC 7520 has no ECDH-ES+A192KW example, so the
// anchor is aeskw's RFC 3394 §4.2/§4.4 KATs plus this round trip.
test "ECDH-ES+A192KW real round-trip (P-256), through aeskw's AES-192 KEK" {
    var recipient: ecdhes.EphemeralKeyPair = undefined;
    ecdhes.generateEphemeral(&recipient, .p256, seededForTest());
    const token = try encryptCompact(std.testing.allocator, .@"ECDH-ES+A192KW", .A128GCM, .{ .ec_public = recipient.public }, "hi", "", seededForTest(), .{});
    defer std.testing.allocator.free(token);
    const plaintext = try decryptCompact(std.testing.allocator, .{ .ec_private = &recipient.private }, token, .{
        .expect_alg = .@"ECDH-ES+A192KW",
    });
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings("hi", plaintext);
}

test "malformed compact tokens are rejected, never panic on arbitrary bytes" {
    const key = @as([16]u8, @splat(0x2b));
    try std.testing.expectError(error.MalformedToken, decryptCompact(std.testing.allocator, .{ .symmetric = &key }, "not.enough.parts", .{}));
    try std.testing.expectError(error.MalformedToken, decryptCompact(std.testing.allocator, .{ .symmetric = &key }, "too.many.parts.here.for.sure", .{}));
    try std.testing.expectError(error.InvalidBase64, decryptCompact(std.testing.allocator, .{ .symmetric = &key }, "not!base64.a.b.c.d", .{}));
}

const fuzzseed = @import("testkit").fuzz;

/// A flip script: octet 0 is the flip COUNT (1..24 after clamping), then three
/// octets per flip — a 16-bit offset into the token and the byte to write.
///
/// ⛔ The knobs used to be ranged `Smith` draws, and `n_flips` was the FIRST
/// of them. A ranged draw reads eight octets as a little-endian `u64` and
/// returns the range MINIMUM unless that whole word falls inside the range, so
/// on the one input the ordinary test lane runs, `n_flips` was 1,
/// `smith.index(token.len)` was 0 and `smith.value(u8)` was 0: **this target
/// ran exactly one input for ever — the genuine token with its first octet
/// zeroed, which `InvalidBase64` refuses before `header.parse`.** The offset
/// draw was the worse half: `smith.index` over a token of ~180 octets is
/// coverage-guided under `--fuzz` but pinned to 0 outside it.
const token_seeds = [_][]const u8{
    fuzzseed.seedHex(""), // the empty script: one flip at offset 0 to 0x00, which is what this target ran
    fuzzseed.seedHex("01" ++ "0000" ++ "41"), // the header segment's first octet
    fuzzseed.seedHex("01" ++ "0005" ++ "2e"), // ⭐ a '.' spliced into the header: a sixth segment
    fuzzseed.seedHex("01" ++ "000a" ++ "21"), // '!' in the header: not base64url
    fuzzseed.seedHex("01" ++ "0028" ++ "41"), // ⭐ inside the encrypted key, past the header
    fuzzseed.seedHex("01" ++ "0050" ++ "ff"), // deeper still: the IV or ciphertext
    fuzzseed.seedHex("01" ++ "00b0" ++ "00"), // ⭐ near the end: the authentication tag
    fuzzseed.seedHex("04" ++ "0000" ++ "61" ++ "0001" ++ "62" ++ "0002" ++ "63" ++ "0003" ++ "64"), // four flips across the header
    fuzzseed.seedHex("18" ++ strRepeat("00045a", 24)), // the maximum flip count, all in the header
    fuzzseed.seedHex("ff" ++ strRepeat("003030", 8)), // a flip count past the ceiling, clamped
    fuzzseed.seedHex("03" ++ "0002" ++ "7b" ++ "0003" ++ "22" ++ "0004" ++ "61"), // '{', '"', 'a' — pushing the header toward JSON-ish
};

const fz = @import("fuzz_test.zig");
const testkit = @import("testkit");
const DecryptMark = fz.Marker(enum { genuine_accepted, framing_refused, past_framing_refused });
const RoundtripMark = fz.Marker(enum { dir, key_wrap, gcm_key_wrap, genuine_accepted, flipped_refused });

test "fuzz: decryptCompact never panics on arbitrary compact tokens" {
    try std.testing.fuzz({}, fuzzDecryptCompactSmith, .{ .corpus = &token_seeds });
}

test "fuzz driver: JWE_FUZZ (decrypt)" {
    try fz.fuzz_driver.run(fuzzDecryptCompact, .{ .prefix = "JWE_FUZZ", .name = "jwe-decrypt" });
}

test "fuzz harness: decrypt, 300 seeds, reaches every outcome" {
    try DecryptMark.reach(fuzzDecryptCompact, "jwe-decrypt", 300);
}

fn fuzzDecryptCompactSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzDecryptCompact(std.testing.Smith, smith, std.testing.allocator);
}

fn fuzzDecryptCompact(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const key = @as([16]u8, @splat(0x2b));

    // ⚠ This harness used to draw 512 uniform-random bytes and hand them
    // straight to `decryptCompact`. Measured: **0 of 200,000** such inputs got
    // past `MalformedToken`/`InvalidBase64` into `header.parse` — a random
    // buffer essentially never spells five dot-separated base64url segments.
    // So the whole surface the audit's findings live on (the header parse, the
    // alg dispatch, every key-unwrap arm) was never reached, while
    // `check-fuzz` reported the module covered. Worse, outside `--fuzz` the
    // empty corpus gives exactly one input and `valueRangeAtMost` falls back
    // to its LOWER bound, so the one input was `len = 0`. (The replacement
    // then had the same disease one level down — see `token_seeds`.)
    //
    // Start from a genuine token and corrupt it instead, so the framing is
    // valid by construction and the draws are spent on what happens past it.
    const token = try encryptCompact(gpa, .A128KW, .A128GCM, .{ .symmetric = &key }, "fuzz", "", seededForTest(), .{});
    defer gpa.free(token);
    var buf: [512]u8 = undefined;
    if (token.len > buf.len) return error.TokenOverBuffer;
    @memcpy(buf[0..token.len], token);

    // ⚠ ONE byte-first draw, read as a flip script. See `token_seeds` for what
    // the ranged draws were worth on a corpus replay.
    var script_buf: [128]u8 = undefined;
    const script_len: usize = src.slice(&script_buf);
    var script: fuzzseed.Cursor = .{ .bytes = script_buf[0..script_len] };
    applyFlips(&script, buf[0..token.len]);

    // The genuine token opens (the oracle's other half).
    {
        const genuine = decryptCompact(gpa, .{ .symmetric = &key }, token, .{}) catch return error.GenuineTokenRefused;
        defer gpa.free(genuine);
        if (!std.mem.eql(u8, genuine, "fuzz")) return error.OpenedWrongPlaintext;
        DecryptMark.mark(.genuine_accepted);
    }
    // A token the flips left unchanged is the genuine one and must open; a
    // changed one may only be accepted if it still carries the SAME plaintext
    // (a base64url trailing-bits flip is not a forgery) -- never another one.
    const unchanged = std.mem.eql(u8, buf[0..token.len], token);
    const pt = decryptCompact(gpa, .{ .symmetric = &key }, buf[0..token.len], .{}) catch |e| {
        if (unchanged) return error.GenuineTokenRefused;
        switch (e) {
            error.MalformedToken, error.InvalidBase64 => DecryptMark.mark(.framing_refused),
            else => DecryptMark.mark(.past_framing_refused),
        }
        return;
    };
    defer gpa.free(pt);
    if (!std.mem.eql(u8, pt, "fuzz")) return error.DamagedTokenOpenedToOtherPlaintext;
}

test "fuzz driver: JWE_FUZZ (encrypt + decrypt round trip)" {
    try fz.fuzz_driver.run(fuzzRoundtrip, .{ .prefix = "JWE_FUZZ", .name = "jwe-roundtrip" });
}

test "fuzz harness: round trip, 200 seeds, reaches every outcome" {
    try RoundtripMark.reach(fuzzRoundtrip, "jwe-roundtrip", 200);
}

test "fuzz: a genuine JWE opens and a flipped one is refused" {
    try std.testing.fuzz({}, fuzzRoundtripSmith, .{});
}

fn fuzzRoundtripSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzRoundtrip(testkit.fuzz.ScriptSource, &src, std.testing.allocator);
}

/// `alg` x `enc` knob-chosen, key and plaintext from the source: what
/// `encryptCompact` made `decryptCompact` opens to the same plaintext, and the
/// same token with one octet changed (not a segment's last, whose base64url
/// unused bits are not authenticated) is REFUSED, as is the wrong key.
fn fuzzRoundtrip(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const algs = [_]Alg{ .dir, .A128KW, .A192KW, .A256KW, .A128GCMKW, .A192GCMKW, .A256GCMKW };
    const encs = [_]Enc{ .A128GCM, .A192GCM, .A256GCM, .@"A128CBC-HS256", .@"A192CBC-HS384", .@"A256CBC-HS512" };
    const key_alg = algs[src.index(algs.len)];
    const content_enc = encs[src.index(encs.len)];
    switch (key_alg) {
        .dir => RoundtripMark.mark(.dir),
        .A128GCMKW, .A192GCMKW, .A256GCMKW => RoundtripMark.mark(.gcm_key_wrap),
        else => RoundtripMark.mark(.key_wrap),
    }
    var key_buf: [64]u8 = undefined;
    src.bytes(&key_buf);
    const key_len: usize = switch (key_alg) {
        .dir => content_enc.cekLen().?,
        .A128KW, .A128GCMKW => 16,
        .A192KW, .A192GCMKW => 24,
        else => 32,
    };
    const key = key_buf[0..key_len];
    var pt_buf: [40]u8 = undefined;
    src.bytes(&pt_buf);
    const pt = pt_buf[0..src.valueRangeAtMost(u8, 0, pt_buf.len)];

    const token = try encryptCompact(gpa, key_alg, content_enc, .{ .symmetric = key }, pt, "", seededForTest(), .{});
    defer gpa.free(token);
    const opened = decryptCompact(gpa, .{ .symmetric = key }, token, .{}) catch return error.GenuineTokenRefused;
    defer gpa.free(opened);
    if (!std.mem.eql(u8, opened, pt)) return error.OpenedWrongPlaintext;
    RoundtripMark.mark(.genuine_accepted);

    const copy = try gpa.dupe(u8, token);
    defer gpa.free(copy);
    var at = src.index(copy.len - 1);
    while (copy[at] == '.' or copy[at + 1] == '.') at = (at + 1) % (copy.len - 1);
    copy[at] = if (copy[at] == 'A') 'B' else 'A';
    if (decryptCompact(gpa, .{ .symmetric = key }, copy, .{})) |p| {
        gpa.free(p);
        return error.FlippedTokenAccepted;
    } else |_| {}

    var wrong: [64]u8 = key_buf;
    const wrong_at = src.index(key_len);
    const wrong_bit = src.index(8);
    wrong[wrong_at] ^= @as(u8, 1) << @as(u3, @intCast(wrong_bit));
    // A wrong key is refused -- except that in AES-CBC-HMAC only the MAC half
    // of the key authenticates: a damaged AES half passes the tag and decrypts
    // to garbage (valid padding about one time in 256). That is the
    // construction, not a defect; what must never happen is the right
    // plaintext from a wrong key.
    if (decryptCompact(gpa, .{ .symmetric = wrong[0..key_len] }, token, .{})) |p| {
        defer gpa.free(p);
        if (std.mem.eql(u8, p, pt)) return error.WrongKeyOpenedToThePlaintext;
        const aes_half_only = switch (key_alg) {
            .dir => !content_enc.isGcm() and wrong_at >= key_len / 2,
            else => false,
        };
        if (!aes_half_only) return error.WrongKeyAccepted;
    } else |_| {}
    RoundtripMark.mark(.flipped_refused);
}

/// At least one flip: zero flips is the valid token, which the round-trip
/// tests already cover. The offset is 16-bit, because a compact token here is
/// about 180 octets and a one-octet offset could never have reached the tag.
fn applyFlips(script: *fuzzseed.Cursor, buf: []u8) void {
    if (buf.len == 0) return;
    const n_flips = 1 + script.byte() % 24;
    var i: u8 = 0;
    while (i < n_flips) : (i += 1) {
        const pos = script.word() % buf.len;
        buf[pos] = script.byte();
    }
}

test "corpus: every token seed reaches decryptCompact, and how far each gets is pinned" {
    // ⭐ Nothing here may ever decrypt — a damaged token that authenticates
    // would be the defect — so "accepted" is not the reach signal. What is
    // pinned is how far each damaged token gets: `MalformedToken` and
    // `InvalidBase64` are refusals at the FRAMING, and anything else means the
    // input got past framing into the header parse and the key unwrap, which
    // is the surface this target exists for.
    const gpa = std.testing.allocator;
    const key = @as([16]u8, @splat(0x2b));
    const token = try encryptCompact(gpa, .A128KW, .A128GCM, .{ .symmetric = &key }, "fuzz", "", seededForTest(), .{});
    defer gpa.free(token);

    var nonempty: usize = 0;
    var framing_refusals: usize = 0;
    var past_framing: usize = 0;
    var accepted: usize = 0;
    var distinct_tokens: usize = 0;
    for (token_seeds) |sd| {
        var buf: [512]u8 = undefined;
        @memcpy(buf[0..token.len], token);
        var smith: std.testing.Smith = .{ .in = sd };
        var script_buf: [128]u8 = undefined;
        const n: usize = smith.slice(&script_buf);
        if (n != 0) nonempty += 1;
        var script: fuzzseed.Cursor = .{ .bytes = script_buf[0..n] };
        applyFlips(&script, buf[0..token.len]);
        if (!std.mem.eql(u8, buf[0..token.len], token)) distinct_tokens += 1;
        if (decryptCompact(gpa, .{ .symmetric = &key }, buf[0..token.len], .{})) |pt| {
            accepted += 1;
            gpa.free(pt);
        } else |e| switch (e) {
            error.MalformedToken, error.InvalidBase64 => framing_refusals += 1,
            else => past_framing += 1,
        }
    }
    // One seed is deliberately the empty script.
    try std.testing.expectEqual(token_seeds.len - 1, nonempty);
    // Measured. The single input this target used to run was one
    // flip at offset 0 to 0x00 — `InvalidBase64`, a framing refusal, so
    // `past_framing` was 0 for every run it ever made.
    try std.testing.expectEqual(@as(usize, 11), distinct_tokens);
    try std.testing.expectEqual(@as(usize, 8), framing_refusals);
    try std.testing.expectEqual(@as(usize, 3), past_framing);
    // A damaged token must never authenticate.
    try std.testing.expectEqual(@as(usize, 0), accepted);
}

test "TEETH: the decrypt fuzz harness reaches the header parser" {
    // What `check-fuzz` structurally cannot ask. Drives the harness's own
    // corruption strategy and asserts that some draws get past the framing
    // into a parsed header — before this, uniform random bytes reached it
    // 0 times in 200,000.
    const gpa = std.testing.allocator;
    const key = @as([16]u8, @splat(0x2b));
    const token = try encryptCompact(gpa, .A128KW, .A128GCM, .{ .symmetric = &key }, "fuzz", "", seededForTest(), .{});
    defer gpa.free(token);

    var prng = std.Random.DefaultPrng.init(0x7e57);
    const rand = prng.random();
    var reached: usize = 0;
    for (0..256) |_| {
        var buf: [512]u8 = undefined;
        @memcpy(buf[0..token.len], token);
        const n_flips = rand.intRangeAtMost(u8, 1, 24);
        for (0..n_flips) |_| buf[rand.uintLessThan(usize, token.len)] = rand.int(u8);

        // "Reached the parser" = it got past dot-splitting and base64 into
        // something the header parser answered for, one way or the other.
        if (decryptCompact(gpa, .{ .symmetric = &key }, buf[0..token.len], .{})) |pt| {
            gpa.free(pt);
            reached += 1;
        } else |err| switch (err) {
            error.MalformedToken, error.InvalidBase64 => {},
            else => reached += 1,
        }
    }
    try std.testing.expect(reached > 0);
}

// ── the randomness seam (RNG-seam audit, `entropy.zig`) ────────────────────
//
// `encryptCompact` takes an `Entropy`, not a `std.Random`. The two generators
// are indistinguishable once they are a vtable, so the caller names which one
// it is handing over. The first test pins that the type keeps exactly the two
// arms; the second measures what naming the wrong one actually costs, so the
// doc comment's warning is a fact and not a claim.

test "Entropy: exactly two arms, production and test are distinct, and nothing else is admitted" {
    const info = @typeInfo(Entropy).@"union";
    try std.testing.expectEqual(@as(usize, 2), info.field_names.len);
    try std.testing.expectEqualStrings("csprng", info.field_names[0]);
    try std.testing.expectEqualStrings("fixed_for_test", info.field_names[1]);

    // The SAME generator under the two arms — different claims about the same
    // bytes is precisely the distinction the type exists to carry.
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x77)));
    const production: Entropy = .{ .csprng = csprng.random() };
    const for_test: Entropy = .{ .fixed_for_test = csprng.random() };
    try std.testing.expect(std.meta.activeTag(production) != std.meta.activeTag(for_test));
}

test "the CSPRNG requirement is load-bearing: dir + A256GCM with a repeated generator reuses the IV" {
    // `dir` is the sharp case: the CEK is the caller's long-lived key, so the
    // content IV is the only thing separating two messages. Two generators in
    // the same state stand in for "the consumer reached for DefaultPrng".
    const gpa = std.testing.allocator;
    const key = @as([32]u8, @splat(0x2b));
    const p1 = "transfer 100 to alice!!!";
    const p2 = "transfer 999 to mallory??";

    var g1 = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x11)));
    var g2 = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x11))); // same seed
    var g3 = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x12))); // different

    const t1 = try encryptCompact(gpa, .dir, .A256GCM, .{ .symmetric = &key }, p1, "", .{ .fixed_for_test = g1.random() }, .{});
    defer gpa.free(t1);
    const t2 = try encryptCompact(gpa, .dir, .A256GCM, .{ .symmetric = &key }, p2, "", .{ .fixed_for_test = g2.random() }, .{});
    defer gpa.free(t2);
    const t3 = try encryptCompact(gpa, .dir, .A256GCM, .{ .symmetric = &key }, p2, "", .{ .fixed_for_test = g3.random() }, .{});
    defer gpa.free(t3);

    var iv1: [12]u8 = undefined;
    var iv2: [12]u8 = undefined;
    var iv3: [12]u8 = undefined;
    var c1: [64]u8 = undefined;
    var c2: [64]u8 = undefined;
    var c3: [64]u8 = undefined;
    const n1 = try segmentsOf(t1, &iv1, &c1);
    const n2 = try segmentsOf(t2, &iv2, &c2);
    const n3 = try segmentsOf(t3, &iv3, &c3);
    try std.testing.expectEqual(p1.len, n1);
    try std.testing.expectEqual(p2.len, n2);
    try std.testing.expectEqual(p2.len, n3);

    // Same generator state ⇒ byte-identical 96-bit GCM nonce under the same key.
    try std.testing.expectEqualSlices(u8, &iv1, &iv2);
    // GCM is CTR mode underneath, so the leak is the full-length keystream —
    // not a prefix, the way a CBC-mode IV repeat would be.
    const common = @min(p1.len, p2.len);
    for (c1[0..common], c2[0..common], p1[0..common], p2[0..common]) |x, y, a, b| {
        try std.testing.expectEqual(a ^ b, x ^ y);
    }
    // Stated as the attack: knowing one plaintext recovers the other.
    var recovered: [24]u8 = undefined;
    for (&recovered, c1[0..24], c2[0..24], p1[0..24]) |*r, x, y, a| r.* = x ^ y ^ a;
    try std.testing.expectEqualStrings(p2[0..24], &recovered);

    // Not vacuous: a different generator state breaks both the IV equality and
    // the XOR relation, so the test is measuring the reuse and not arithmetic.
    try std.testing.expect(!std.mem.eql(u8, &iv1, &iv3));
    var still_leaks = true;
    for (c1[0..common], c3[0..common], p1[0..common], p2[0..common]) |x, y, a, b| {
        if ((a ^ b) != (x ^ y)) still_leaks = false;
    }
    try std.testing.expect(!still_leaks);
}

/// Split a compact JWE into its IV and ciphertext segments (test helper).
/// Returns the ciphertext length written into `ct_out`.
fn segmentsOf(token: []const u8, iv_out: *[12]u8, ct_out: []u8) !usize {
    const b64 = std.base64.url_safe_no_pad;
    var it = std.mem.splitScalar(u8, token, '.');
    _ = it.next() orelse return error.MalformedToken; // header
    _ = it.next() orelse return error.MalformedToken; // encrypted key (empty for dir)
    const iv_seg = it.next() orelse return error.MalformedToken;
    const ct_seg = it.next() orelse return error.MalformedToken;
    try b64.Decoder.decode(iv_out, iv_seg);
    const n = try b64.Decoder.calcSizeForSlice(ct_seg);
    try b64.Decoder.decode(ct_out[0..n], ct_seg);
    return n;
}

test "TEETH: RFC 7516 s11.5 — one error value for every encrypted-key failure" {
    // "the recipient MUST NOT distinguish between format, padding, and length
    //  errors of encrypted keys" (RFC 7516 s11.5, verbatim).
    //
    // Before this, one decryption could return three different values: a junk
    // Encrypted Key gave an unwrap error, a VALID wrap of a wrong-length
    // message gave `InvalidKey` (the "length error" the sentence names), and a
    // correct-length CEK gave `AuthenticationFailed`. Read off the return
    // value, that is a padding oracle with no statistics required.
    const gpa = std.testing.allocator;
    const kek = @as([16]u8, @splat(0x5a));

    // A genuine token, so the tail of every case below is well-formed.
    const token = try encryptCompact(gpa, .A128KW, .A128GCM, .{ .symmetric = &kek }, "secret", "", seededForTest(), .{});
    defer gpa.free(token);

    var it = std.mem.splitScalar(u8, token, '.');
    const h = it.next().?;
    const real_ek = it.next().?;
    const rest = it.rest();

    // Case A — format/padding: the Encrypted Key is not a valid AES-KW blob.
    const junk = try gpa.print("{s}.{s}.{s}", .{ h, "AAAAAAAAAAAAAAAAAAAAAAA", rest });
    defer gpa.free(junk);
    // Case B — length: a VALID wrap, of a message that is not the CEK length.
    // Built by wrapping a 24-byte key under the same KEK.
    var wrapped24: [32]u8 = undefined;
    _ = try alg.aeskw.wrap(&kek, &@as([24]u8, @splat(0x11)), &wrapped24);
    var wrapped_b64: [64]u8 = undefined;
    const enc_len = std.base64.url_safe_no_pad.Encoder.encode(&wrapped_b64, &wrapped24).len;
    const wrong_len = try gpa.print("{s}.{s}.{s}", .{ h, wrapped_b64[0..enc_len], rest });
    defer gpa.free(wrong_len);
    // Case C — the encrypted key is fine; the CONTENT fails to authenticate.
    // Same real EK, one character changed inside the ciphertext segment — to
    // ANOTHER VALID base64url character, so the failure is authentication and
    // not decoding. (Flipping a bit produced `InvalidBase64` and this test
    // caught it, which is the difference between checking the value you meant
    // and checking the one you got.)
    const forged_ct = try gpa.dupe(u8, token);
    defer gpa.free(forged_ct);
    {
        var seg: usize = 0;
        var ct_start: usize = 0;
        for (forged_ct, 0..) |c, i| {
            if (c != '.') continue;
            seg += 1;
            if (seg == 3) ct_start = i + 1;
        }
        forged_ct[ct_start] = if (forged_ct[ct_start] == 'A') 'B' else 'A';
    }

    const a_err = decryptCompact(gpa, .{ .symmetric = &kek }, junk, .{});
    const b_err = decryptCompact(gpa, .{ .symmetric = &kek }, wrong_len, .{});
    const c_err = decryptCompact(gpa, .{ .symmetric = &kek }, forged_ct, .{});

    try std.testing.expectError(error.AuthenticationFailed, a_err);
    try std.testing.expectError(error.AuthenticationFailed, b_err);
    try std.testing.expectError(error.AuthenticationFailed, c_err);
    _ = real_ek;

    // And the genuine token still decrypts, so the unification did not simply
    // break decryption for everyone.
    const pt = try decryptCompact(gpa, .{ .symmetric = &kek }, token, .{});
    defer gpa.free(pt);
    try std.testing.expectEqualStrings("secret", pt);
}

test "TEETH: an attacker-chosen PBES2 work factor is REFUSED, not performed" {
    // `p2c` is read from an unauthenticated header and was obeyed without a
    // ceiling. Measured at ~1 us/iteration: a 192-byte token declaring
    // p2c=100,000,000 costs ~99.75 s of CPU and then reports
    // AuthenticationFailed. SPEC.md's "header-size-bounded decode" bullet
    // bounds the header's BYTES; the quantity that grows here is the WORK its
    // contents command.
    const gpa = std.testing.allocator;
    const password = "correct horse battery staple";

    // A genuine PBES2 token at a sane iteration count. The count used to
    // BUILD this token is not under test here (the tamper checks below
    // rewrite `p2c` outright) -- only that encrypt/decrypt agree on
    // whatever count they used, which holds at any value. Debug: the
    // production default (600_000, OWASP PBKDF2-HMAC-SHA256 guidance) costs
    // real seconds of unoptimized Debug SHA-256 per round trip here; scaled
    // down for Debug only, full default kept outside Debug.
    const initial_p2c: u32 = if (builtin.mode == .debug) 1_000 else 600_000;
    const token = try encryptCompact(gpa, .@"PBES2-HS256+A128KW", .A128GCM, .{ .password = password }, "hi", "", seededForTest(), .{ .pbes2_iterations = initial_p2c });
    defer gpa.free(token);
    const pt = try decryptCompact(gpa, .{ .password = password }, token, .{});
    defer gpa.free(pt);
    try std.testing.expectEqualStrings("hi", pt);

    // The same token with p2c rewritten far above the ceiling must be refused
    // BEFORE the derivation, so this test finishes in milliseconds. If the
    // ceiling is removed it does not fail — it runs for minutes, which is
    // itself the report.
    const forged = try rewriteP2c(gpa, token, 4_000_000_000);
    defer gpa.free(forged);
    try std.testing.expectError(
        error.WorkFactorTooHigh,
        decryptCompact(gpa, .{ .password = password }, forged, .{}),
    );

    // At exactly the ceiling the token is accepted for processing (and then
    // fails on its own merits), so the bound is not off by one.
    //
    // Debug: this sub-case actually PERFORMS the full PBKDF2 derivation at
    // the ceiling (that is the point -- proving "accepted, then fails on
    // its own merits" rather than wrongly rejected) -- measured ~1us/round
    // in the comment above is a ReleaseFast number; Debug's unoptimized
    // SHA-256 is far slower, and this test ALONE was measured ~37s isolated
    // at the real `default_max_p2c` (1,000,000 rounds), over the campaign's
    // 10s budget and uncomfortably close to the full gate's 3-minute
    // per-test timeout under load. The "over the ceiling, refused before
    // derivation" case just above is untouched -- it is already cheap in
    // every mode, since a refusal never runs the KDF, and it still checks
    // against the REAL `default_max_p2c` (no override).
    //
    // What changes here is ONLY the boundary value this "not off by one"
    // sub-case exercises: `max_p2c` is a public `DecryptOptions` field
    // precisely so the ceiling is caller-configurable, and the
    // over/at-ceiling comparison in the code under test does not special-
    // case any particular magnitude -- so a smaller configured ceiling
    // exercises the identical comparison logic. `default_max_p2c` itself
    // (the production constant) is verified at its REAL value outside
    // Debug, where the cost is negligible.
    const at_ceiling_p2c: u32 = if (builtin.mode == .debug) 20_000 else default_max_p2c;
    const at_ceiling = try rewriteP2c(gpa, token, at_ceiling_p2c);
    defer gpa.free(at_ceiling);
    try std.testing.expectError(
        error.AuthenticationFailed,
        decryptCompact(gpa, .{ .password = password }, at_ceiling, .{ .max_p2c = at_ceiling_p2c }),
    );
}

/// Re-encode a compact token's protected header with a different `p2c`.
fn rewriteP2c(gpa: std.mem.Allocator, token: []const u8, p2c: u32) ![]u8 {
    var it = std.mem.splitScalar(u8, token, '.');
    const h_b64 = it.next().?;
    const rest = it.rest();

    const b64 = std.base64.url_safe_no_pad;
    const n = try b64.Decoder.calcSizeForSlice(h_b64);
    const json = try gpa.alloc(u8, n);
    defer gpa.free(json);
    try b64.Decoder.decode(json, h_b64);

    // The encoder writes `"p2c":<digits>`; swap the digits.
    const key = "\"p2c\":";
    const at = std.mem.find(u8, json, key).?;
    var end = at + key.len;
    while (end < json.len and json[end] >= '0' and json[end] <= '9') end += 1;

    var rebuilt: std.ArrayList(u8) = .empty;
    defer rebuilt.deinit(gpa);
    try rebuilt.appendSlice(gpa, json[0 .. at + key.len]);
    try rebuilt.print(gpa, "{d}", .{p2c});
    try rebuilt.appendSlice(gpa, json[end..]);

    const enc_len = b64.Encoder.calcSize(rebuilt.items.len);
    const new_h = try gpa.alloc(u8, enc_len);
    defer gpa.free(new_h);
    _ = b64.Encoder.encode(new_h, rebuilt.items);

    return gpa.print("{s}.{s}", .{ new_h, rest });
}

// ── mutation run ─────────────────────────────────────────────────
//
// 35 mutants, 18 survivors on the first pass. Each test below names the rule
// it pins and why its expected value is the right one.

const test_b64 = std.base64.url_safe_no_pad;

/// `header_json` b64url'd, then the four other segments, built by hand so a
/// test can put exactly the bytes it wants into each.
fn buildCompact(a: std.mem.Allocator, header_json: []const u8, ek: []const u8, iv: []const u8, ct: []const u8, tag: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    for ([_][]const u8{ header_json, ek, iv, ct, tag }, 0..) |part, i| {
        if (i != 0) try out.append(a, '.');
        const start = out.items.len;
        try out.resize(a, start + test_b64.Encoder.calcSize(part.len));
        _ = test_b64.Encoder.encode(out.items[start..], part);
    }
    return out.toOwnedSlice(a);
}

/// A token whose content is A128GCM under `cek`, with `ek` as its Encrypted
/// Key, whatever `ek` actually wraps.
fn tokenWithCek(a: std.mem.Allocator, header_json: []const u8, ek: []const u8, cek: [16]u8, pt: []const u8) ![]u8 {
    const iv = @as([12]u8, @splat(0x24));
    var hb: [256]u8 = undefined;
    const header_b64 = test_b64.Encoder.encode(&hb, header_json);
    const ct = try a.alloc(u8, pt.len);
    defer a.free(ct);
    var tag: [16]u8 = undefined;
    _ = try enc.encrypt(.A128GCM, &cek, &iv, header_b64, pt, ct, &tag);
    return buildCompact(a, header_json, ek, &iv, ct, &tag);
}

test "dir refuses a non-empty encrypted_key segment (RFC 7516 §5.2 step 10)" {
    // Review finding: only ECDH-ES checked this. The segment is
    // outside the AAD, so a dir token with bytes spliced into it decrypted
    // to the same plaintext — the malleability the ECDH-ES test names.
    const key = @as([16]u8, @splat(0x2b));
    const token = try encryptCompact(std.testing.allocator, .dir, .A128GCM, .{ .symmetric = &key }, "hi", "", seededForTest(), .{});
    defer std.testing.allocator.free(token);
    var it = std.mem.splitScalar(u8, token, '.');
    const h = it.next().?;
    try std.testing.expectEqual(@as(usize, 0), it.next().?.len);
    const forged = try std.testing.allocator.print("{s}.AAAAAAAAAAA.{s}", .{ h, it.rest() });
    defer std.testing.allocator.free(forged);
    try std.testing.expectError(error.MalformedToken, decryptCompact(std.testing.allocator, .{ .symmetric = &key }, forged, .{}));
}

test "expect_alg / expect_enc refuse a token of another algorithm" {
    // The caller's algorithm pin (RFC 8725 §3.1): without it the token's own
    // header picks the algorithm. Removing either check left every test green.
    const key = @as([16]u8, @splat(0x2b));
    const token = try encryptCompact(std.testing.allocator, .dir, .A128GCM, .{ .symmetric = &key }, "pinned", "", seededForTest(), .{});
    defer std.testing.allocator.free(token);
    try std.testing.expectError(error.AlgMismatch, decryptCompact(std.testing.allocator, .{ .symmetric = &key }, token, .{ .expect_alg = .A128KW }));
    try std.testing.expectError(error.EncMismatch, decryptCompact(std.testing.allocator, .{ .symmetric = &key }, token, .{ .expect_enc = .A256GCM }));
    const ok = try decryptCompact(std.testing.allocator, .{ .symmetric = &key }, token, .{ .expect_alg = .dir, .expect_enc = .A128GCM });
    defer std.testing.allocator.free(ok);
    try std.testing.expectEqualStrings("pinned", ok);
}

test "unknown alg/enc and an empty header segment are typed errors, never reach the key path" {
    // `unwrapCek` has `.unknown => unreachable`; the up-front checks are what
    // keep an unknown `alg` from it.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const key = @as([16]u8, @splat(0x2b));
    const z = @as([16]u8, @splat(0));
    const bad_alg = try buildCompact(a, "{\"alg\":\"XYZ\",\"enc\":\"A128GCM\"}", "", &z, &z, &z);
    try std.testing.expectError(error.UnsupportedAlg, decryptCompact(std.testing.allocator, .{ .symmetric = &key }, bad_alg, .{}));
    const bad_enc = try buildCompact(a, "{\"alg\":\"dir\",\"enc\":\"XYZ\"}", "", &z, &z, &z);
    try std.testing.expectError(error.UnsupportedEnc, decryptCompact(std.testing.allocator, .{ .symmetric = &key }, bad_enc, .{}));
    try std.testing.expectError(error.MalformedToken, decryptCompact(std.testing.allocator, .{ .symmetric = &key }, ".AA.AA.AA.AA", .{}));
}

test "header size limits: the b64 header at max + 1, a member at max_member_len + 1" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const key = @as([16]u8, @splat(0x2b));
    for ([_]usize{ header.max_header_b64_len, header.max_header_b64_len + 1 }) |n| {
        const big = try a.alloc(u8, n + ".AA.AA.AA.AA".len);
        @memset(big[0..n], 'e');
        @memcpy(big[n..], ".AA.AA.AA.AA");
        if (decryptCompact(std.testing.allocator, .{ .symmetric = &key }, big, .{})) |pt| {
            std.testing.allocator.free(pt);
            return error.TestUnexpectedResult;
        } else |err| {
            if (n > header.max_header_b64_len) {
                try std.testing.expectEqual(error.HeaderTooLarge, err);
            } else {
                try std.testing.expect(err != error.HeaderTooLarge);
            }
        }
    }
    for ([_]usize{ header.max_member_len, header.max_member_len + 1 }) |n| {
        const raw = try a.alloc(u8, n);
        @memset(raw, 0x11);
        const enc_iv = try a.alloc(u8, test_b64.Encoder.calcSize(n));
        _ = test_b64.Encoder.encode(enc_iv, raw);
        const json = try a.print("{{\"alg\":\"A128GCMKW\",\"enc\":\"A128GCM\",\"iv\":\"{s}\"}}", .{enc_iv});
        const r = header.parse(a, json);
        if (n > header.max_member_len) {
            try std.testing.expectError(error.InvalidHeaderField, r);
        } else {
            _ = try r;
        }
    }
}

test "a failed key unwrap never decrypts under a predictable CEK (RFC 7516 §11.5 decoy)" {
    // A128KW with an Encrypted Key that fails the RFC 3394 integrity check.
    // The decoy CEK is a hash of the key and the Encrypted Key; without it
    // the CEK would be whatever `cek_buf` held — 0xAA in the safe modes, so a
    // token whose content was sealed under 0xAA… would have DECRYPTED.
    const kek = @as([16]u8, @splat(0x77));
    const bad_ek = @as([24]u8, @splat(0x01));
    for ([_]u8{ 0xAA, 0x00 }) |fill| {
        const token = try tokenWithCek(std.testing.allocator, "{\"alg\":\"A128KW\",\"enc\":\"A128GCM\"}", &bad_ek, @splat(fill), "predictable");
        defer std.testing.allocator.free(token);
        try std.testing.expectError(error.AuthenticationFailed, decryptCompact(std.testing.allocator, .{ .symmetric = &kek }, token, .{}));
    }
}

test "content tags must be exactly the enc's length: one octet more is refused, not truncated" {
    // RFC 7518 §5.2.2.2 / §5.3: the tag is T_LEN octets (16 for both here).
    // With the length checks moved, the first 16 octets were compared and a
    // token with a 17-octet tag decrypted.
    const key = @as([32]u8, @splat(0x2b));
    for ([_]Enc{ .A128GCM, .@"A128CBC-HS256" }) |e| {
        const k = key[0..e.cekLen().?];
        const token = try encryptCompact(std.testing.allocator, .dir, e, .{ .symmetric = k }, "tag length", "", seededForTest(), .{});
        defer std.testing.allocator.free(token);
        const dot = std.mem.findScalarLast(u8, token, '.').?;
        var tag_buf: [17]u8 = undefined;
        try test_b64.Decoder.decode(tag_buf[0..16], token[dot + 1 ..]);
        tag_buf[16] = 0;
        var tb: [32]u8 = undefined;
        const long = try std.mem.concat(std.testing.allocator, u8, &.{ token[0 .. dot + 1], test_b64.Encoder.encode(&tb, &tag_buf) });
        defer std.testing.allocator.free(long);
        if (decryptCompact(std.testing.allocator, .{ .symmetric = k }, long, .{})) |pt| {
            std.testing.allocator.free(pt);
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "unwrapCek: wrapped CEKs of the wrong length and GCMKW iv/tag of the wrong length are InvalidKey" {
    // A wrapped CEK must be exactly the enc's key length (RFC 7516 §5.2
    // step 9 hands it to the enc as-is); GCMKW's iv is 96 bits and its tag
    // 128 bits (RFC 7518 §4.7.1). Longer values were silently truncated
    // with the checks moved, shorter RSA ones read past the buffer.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var cek: [16]u8 = undefined;

    var prng = std.Random.DefaultPrng.init(0x6a77_655f_6d75_7421);
    var kp: rsa.KeyPair = undefined;
    try rsa.generate(&kp, prng.random(), 1024, 65537);
    const rsa_parsed = try header.parse(a, "{\"alg\":\"RSA-OAEP\",\"enc\":\"A128GCM\"}");
    const cek17 = @as([17]u8, @splat(0x5a));
    for ([_]usize{ 15, 17 }) |n| {
        var ek_buf: [max_encrypted_key_len]u8 = undefined;
        const ek = try alg.rsaOaepWrap(kp.public_key, .sha1, seededForTest(), cek17[0..n], &ek_buf);
        try std.testing.expectError(error.InvalidKey, unwrapCek(rsa_parsed, .{ .rsa_private = &kp.secret_key }, ek, &cek, 16, .{}));
    }

    const kek = @as([16]u8, @splat(0x77));
    const iv13 = @as([13]u8, @splat(0x31));
    var ct16: [16]u8 = undefined;
    var tag: [16]u8 = undefined;
    _ = try alg.gcmkwWrap(&kek, iv13[0..12].*, &(@as([16]u8, @splat(0x5a))), &ct16, &tag);
    var ivb: [32]u8 = undefined;
    var tb: [32]u8 = undefined;
    const tag17 = tag ++ [_]u8{0};
    const long_iv = try header.parse(a, try a.print("{{\"alg\":\"A128GCMKW\",\"enc\":\"A128GCM\",\"iv\":\"{s}\",\"tag\":\"{s}\"}}", .{ test_b64.Encoder.encode(&ivb, &iv13), test_b64.Encoder.encode(&tb, &tag) }));
    try std.testing.expectError(error.InvalidKey, unwrapCek(long_iv, .{ .symmetric = &kek }, &ct16, &cek, 16, .{}));
    const long_tag = try header.parse(a, try a.print("{{\"alg\":\"A128GCMKW\",\"enc\":\"A128GCM\",\"iv\":\"{s}\",\"tag\":\"{s}\"}}", .{ test_b64.Encoder.encode(&ivb, iv13[0..12]), test_b64.Encoder.encode(&tb, &tag17) }));
    try std.testing.expectError(error.InvalidKey, unwrapCek(long_tag, .{ .symmetric = &kek }, &ct16, &cek, 16, .{}));

    var ct8: [8]u8 = undefined;
    _ = try alg.gcmkwWrap(&kek, iv13[0..12].*, &(@as([8]u8, @splat(0x5a))), &ct8, &tag);
    const short = try header.parse(a, try a.print("{{\"alg\":\"A128GCMKW\",\"enc\":\"A128GCM\",\"iv\":\"{s}\",\"tag\":\"{s}\"}}", .{ test_b64.Encoder.encode(&ivb, iv13[0..12]), test_b64.Encoder.encode(&tb, &tag) }));
    try std.testing.expectError(error.InvalidKey, unwrapCek(short, .{ .symmetric = &kek }, &ct8, &cek, 16, .{}));
}

test "PBES2: p2c above max_p2c is WorkFactorTooHigh, p2s under 8 octets is InvalidKey (exact edges)" {
    // RFC 7518 §4.8.1.1: the salt input is at least 8 octets. `max_p2c` is
    // inclusive. Both edges moved by one unnoticed before.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var cek: [16]u8 = undefined;
    const password = "correct horse";
    const p2s8 = "AQIDBAUGBwg"; // 8 octets
    const p2s7 = "AQIDBAUGBw"; // 7 octets
    const fmt = "{{\"alg\":\"PBES2-HS256+A128KW\",\"enc\":\"A128GCM\",\"p2s\":\"{s}\",\"p2c\":{d}}}";

    var kek_buf: [32]u8 = undefined;
    const salt8 = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const kek = try alg.pbes2DeriveKek(.hs256_a128kw, password, &salt8, 10, &kek_buf);
    var ek: [24]u8 = undefined;
    _ = try aeskw.wrap(kek, &(@as([16]u8, @splat(0x5a))), &ek);

    const at_max = try header.parse(a, try a.print(fmt, .{ p2s8, 10 }));
    try unwrapCek(at_max, .{ .password = password }, &ek, &cek, 16, .{ .max_p2c = 10 });
    try std.testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0x5a))), &cek);
    const over = try header.parse(a, try a.print(fmt, .{ p2s8, 11 }));
    try std.testing.expectError(error.WorkFactorTooHigh, unwrapCek(over, .{ .password = password }, &ek, &cek, 16, .{ .max_p2c = 10 }));
    const short_salt = try header.parse(a, try a.print(fmt, .{ p2s7, 10 }));
    try std.testing.expectError(error.InvalidKey, unwrapCek(short_salt, .{ .password = password }, &ek, &cek, 16, .{ .max_p2c = 10 }));
}

test "KAT: PBES2-HS256+A128KW against RFC 7517 Appendix C.4/C.5" {
    // The only PBES2 vectors so far were round-trips, which agree with any
    // salt construction: the RFC's `UTF8(alg) || 0x00 || p2s` separator could
    // be changed with every test green. C.4 prints the derived KEK and C.5
    // the Encrypted Key of C.3's CEK.
    const p2s = [_]u8{ 217, 96, 147, 112, 150, 117, 70, 247, 127, 8, 155, 137, 174, 42, 80, 215 };
    const want_kek = [_]u8{ 110, 171, 169, 92, 129, 92, 109, 117, 233, 242, 116, 233, 170, 14, 24, 75 };
    const want_cek = [_]u8{ 111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112, 161, 131, 36, 55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48, 253, 182 };
    const ek = [_]u8{ 78, 186, 151, 59, 11, 141, 81, 240, 213, 245, 83, 211, 53, 188, 134, 188, 66, 125, 36, 200, 222, 124, 5, 103, 249, 52, 117, 184, 140, 81, 246, 158, 161, 177, 20, 33, 245, 57, 59, 4 };
    const password = "Thus from my lips, by yours, my sin is purged.";

    var kek_buf: [32]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &want_kek, try alg.pbes2DeriveKek(.hs256_a128kw, password, &p2s, 4096, &kek_buf));

    // The same through the decrypt path, from C.2's protected header.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try header.parse(arena.allocator(), "{\"alg\":\"PBES2-HS256+A128KW\",\"p2s\":\"2WCTcJZ1Rvd_CJuJripQ1w\",\"p2c\":4096,\"enc\":\"A128CBC-HS256\",\"cty\":\"jwk+json\"}");
    var cek: [32]u8 = undefined;
    try unwrapCek(parsed, .{ .password = password }, &ek, &cek, 32, .{});
    try std.testing.expectEqualSlices(u8, &want_cek, &cek);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}

// ── whole-module mutation run (2026-11): behaviours no earlier test held ──────────────────────

test "encryptCompact draws the CEK, the wrap IV and the PBES2 salt from the entropy, in that order" {
    // Dropping a `random.bytes(cek)` still round-trips (the wrapped CEK is whatever the stack held) and is
    // invisible to every round-trip test; only the content key reveals it: it must be the stream's first octets.
    const gpa = std.testing.allocator;
    const seed: u8 = 0x5c;
    var prng = std.Random.DefaultPrng.init(0x6a77_655f_6d75_7421);
    var kp: rsa.KeyPair = undefined;
    try rsa.generate(&kp, prng.random(), 1024, 65537);
    const kek16 = @as([16]u8, @splat(0x77));

    const Case = struct { key_alg: Alg, key: KeyMaterial };
    const cases = [_]Case{
        .{ .key_alg = .@"RSA-OAEP", .key = .{ .rsa_public = kp.public_key } },
        .{ .key_alg = .@"RSA-OAEP-256", .key = .{ .rsa_public = kp.public_key } },
        .{ .key_alg = .A128KW, .key = .{ .symmetric = &kek16 } },
        .{ .key_alg = .A128GCMKW, .key = .{ .symmetric = &kek16 } },
        .{ .key_alg = .@"PBES2-HS256+A128KW", .key = .{ .password = "pw" } },
    };
    for (cases) |c| {
        var gen = std.Random.DefaultCsprng.init(@as([32]u8, @splat(seed)));
        const token = try encryptCompact(gpa, c.key_alg, .A128GCM, c.key, "entropy order", "", .{ .fixed_for_test = gen.random() }, .{ .pbes2_iterations = 1000 });
        defer gpa.free(token);

        var it = std.mem.splitScalar(u8, token, '.');
        const header_b64 = it.next().?;
        _ = it.next().?; // encrypted key
        var iv: [12]u8 = undefined;
        try test_b64.Decoder.decode(&iv, it.next().?);
        const ct_b64 = it.next().?;
        var ct: [13]u8 = undefined;
        try test_b64.Decoder.decode(&ct, ct_b64);
        var tag: [16]u8 = undefined;
        try test_b64.Decoder.decode(&tag, it.next().?);

        // The same generator, asked in the same chunk sizes: the CEK first, then the wrap IV / the salt.
        var expect = std.Random.DefaultCsprng.init(@as([32]u8, @splat(seed)));
        var cek: [16]u8 = undefined;
        expect.random().bytes(&cek);
        var back: [13]u8 = undefined;
        _ = try enc.decrypt(.A128GCM, &cek, &iv, header_b64, &ct, &tag, &back);
        try std.testing.expectEqualStrings("entropy order", &back);

        var hdr: [header.max_header_json_len]u8 = undefined;
        const hn = try test_b64.Decoder.calcSizeForSlice(header_b64);
        try test_b64.Decoder.decode(hdr[0..hn], header_b64);
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const parsed = try header.parse(arena.allocator(), hdr[0..hn]);
        if (c.key_alg == .A128GCMKW) {
            var want_iv: [12]u8 = undefined;
            expect.random().bytes(&want_iv);
            try std.testing.expectEqualSlices(u8, &want_iv, parsed.iv.?);
        }
        if (c.key_alg == .@"PBES2-HS256+A128KW") {
            var want_salt: [16]u8 = undefined;
            expect.random().bytes(&want_salt);
            try std.testing.expectEqualSlices(u8, &want_salt, parsed.p2s.?);
        }
    }
}

test "RSA-OAEP and RSA-OAEP-256 round-trip through encryptCompact/decryptCompact, each with its own hash" {
    // The RFC 7516 A.1 KAT only decrypts RSA-OAEP (SHA-1); with the hash choice swapped on the encrypt side,
    // or for RSA-OAEP-256 on the decrypt side, every other test stayed green.
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6a77_655f_6d75_7421);
    var kp: rsa.KeyPair = undefined;
    try rsa.generate(&kp, prng.random(), 1024, 65537);
    for ([_]Alg{ .@"RSA-OAEP", .@"RSA-OAEP-256" }) |a| {
        for ([_]Enc{ .A128GCM, .@"A128CBC-HS256" }) |e| {
            const token = try encryptCompact(gpa, a, e, .{ .rsa_public = kp.public_key }, "rsa", "", seededForTest(), .{});
            defer gpa.free(token);
            const back = try decryptCompact(gpa, .{ .rsa_private = &kp.secret_key }, token, .{ .expect_alg = a, .expect_enc = e });
            defer gpa.free(back);
            try std.testing.expectEqualStrings("rsa", back);
        }
    }
}

test "PBES2-HS384 and PBES2-HS512 round-trip end to end (each variant maps to its own KDF and key wrap)" {
    const gpa = std.testing.allocator;
    for ([_]Alg{ .@"PBES2-HS256+A128KW", .@"PBES2-HS384+A192KW", .@"PBES2-HS512+A256KW" }) |a| {
        const token = try encryptCompact(gpa, a, .A128GCM, .{ .password = "pw" }, "pbes2", "", seededForTest(), .{ .pbes2_iterations = 1000, .pbes2_salt_len = 8 });
        defer gpa.free(token);
        const back = try decryptCompact(gpa, .{ .password = "pw" }, token, .{ .expect_alg = a });
        defer gpa.free(back);
        try std.testing.expectEqualStrings("pbes2", back);
        // The salt length option is honoured, not clamped to a default.
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        var hdr: [header.max_header_json_len]u8 = undefined;
        const header_b64 = token[0..std.mem.findScalar(u8, token, '.').?];
        const hn = try test_b64.Decoder.calcSizeForSlice(header_b64);
        try test_b64.Decoder.decode(hdr[0..hn], header_b64);
        const parsed = try header.parse(arena.allocator(), hdr[0..hn]);
        try std.testing.expectEqual(@as(usize, 8), parsed.p2s.?.len);
        try std.testing.expectEqual(@as(?u32, 1000), parsed.p2c);
    }
}

/// SHA-256(domain || extra...) truncated to a 16-octet CEK — what a forger who does NOT hold the key can compute.
fn forgedDecoy(parts: []const []const u8) [16]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("zig-libs/jwe decoy CEK v1");
    for (parts) |p| h.update(p);
    var digest: [32]u8 = undefined;
    h.final(&digest);
    return digest[0..16].*;
}

test "the decoy CEK is keyed: a token sealed under the key-less hash of its Encrypted Key does not open" {
    // RFC 7516 §11.5's decoy replaces the CEK after a failed unwrap. If the key were not mixed in, anyone could
    // compute it from the token alone and forge a token that "decrypts" through a deliberately broken unwrap.
    const gpa = std.testing.allocator;
    const bad_ek = @as([24]u8, @splat(0x01));
    const kek = @as([16]u8, @splat(0x77));
    const forged_sym = try tokenWithCek(gpa, "{\"alg\":\"A128KW\",\"enc\":\"A128GCM\"}", &bad_ek, forgedDecoy(&.{&bad_ek}), "forged");
    defer gpa.free(forged_sym);
    try std.testing.expectError(error.AuthenticationFailed, decryptCompact(gpa, .{ .symmetric = &kek }, forged_sym, .{}));

    const hdr = "{\"alg\":\"PBES2-HS256+A128KW\",\"enc\":\"A128GCM\",\"p2s\":\"AQIDBAUGBwg\",\"p2c\":10}";
    const forged_pw = try tokenWithCek(gpa, hdr, &bad_ek, forgedDecoy(&.{&bad_ek}), "forged");
    defer gpa.free(forged_pw);
    try std.testing.expectError(error.AuthenticationFailed, decryptCompact(gpa, .{ .password = "pw" }, forged_pw, .{}));
}

test "PBES2 without p2s or without p2c is refused, not decrypted under made-up defaults" {
    const gpa = std.testing.allocator;
    var kek_buf: [32]u8 = undefined;
    // What a lenient parser would derive if it defaulted the missing member.
    const kek = try alg.pbes2DeriveKek(.hs256_a128kw, "pw", "12345678", 1000, &kek_buf);
    const cek = @as([16]u8, @splat(0x5a));
    var ek: [24]u8 = undefined;
    _ = try aeskw.wrap(kek, &cek, &ek);
    for ([_][]const u8{
        "{\"alg\":\"PBES2-HS256+A128KW\",\"enc\":\"A128GCM\",\"p2c\":1000}",
        "{\"alg\":\"PBES2-HS256+A128KW\",\"enc\":\"A128GCM\",\"p2s\":\"MTIzNDU2Nzg\"}",
    }) |hdr| {
        const token = try tokenWithCek(gpa, hdr, &ek, cek, "forged");
        defer gpa.free(token);
        try std.testing.expectError(error.AuthenticationFailed, decryptCompact(gpa, .{ .password = "pw" }, token, .{}));
    }
}

test "ECDH-ES: a missing epk, an unknown curve and a cross-curve epk are typed errors" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const z = @as([16]u8, @splat(0));
    var x_b64: [43]u8 = undefined;
    _ = test_b64.Encoder.encode(&x_b64, &@as([32]u8, @splat(9)));
    const x25519_sk = ecdhes.PrivateKey{ .x25519 = @as([32]u8, @splat(0x33)) };

    const no_epk = try buildCompact(a, "{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\"}", "", &z, &z, &z);
    try std.testing.expectError(error.MalformedToken, decryptCompact(gpa, .{ .ec_private = &x25519_sk }, no_epk, .{}));

    const p384 = try buildCompact(a, try a.print("{{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":{{\"kty\":\"EC\",\"crv\":\"P-384\",\"x\":\"{s}\",\"y\":\"{s}\"}}}}", .{ x_b64, x_b64 }), "", &z, &z, &z);
    try std.testing.expectError(error.CurveMismatch, decryptCompact(gpa, .{ .ec_private = &x25519_sk }, p384, .{}));

    // A P-256 epk (without its y, i.e. not even decodable as a P-256 point) against an X25519 recipient is a
    // curve mismatch BEFORE any point decoding — not an InvalidKey from the decoder.
    const p256_no_y = try buildCompact(a, try a.print("{{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{s}\"}}}}", .{x_b64}), "", &z, &z, &z);
    try std.testing.expectError(error.CurveMismatch, decryptCompact(gpa, .{ .ec_private = &x25519_sk }, p256_no_y, .{}));
}

test "an unknown enc is UnsupportedEnc even when the caller pinned another alg or enc" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const key = @as([16]u8, @splat(0x2b));
    const z = @as([16]u8, @splat(0));
    const bad_enc = try buildCompact(a, "{\"alg\":\"dir\",\"enc\":\"XYZ\"}", "", &z, &z, &z);
    try std.testing.expectError(error.UnsupportedEnc, decryptCompact(std.testing.allocator, .{ .symmetric = &key }, bad_enc, .{ .expect_enc = .A256GCM }));
    try std.testing.expectError(error.UnsupportedEnc, decryptCompact(std.testing.allocator, .{ .symmetric = &key }, bad_enc, .{ .expect_alg = .A128KW }));
}

test "a GCMKW key of an impossible length is UnsupportedKeyLength, a configuration error, not folded into the decoy path" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kek20 = @as([20]u8, @splat(0x77));
    const iv = @as([12]u8, @splat(0x31));
    const tag = @as([16]u8, @splat(0x32));
    var ivb: [16]u8 = undefined;
    var tb: [22]u8 = undefined;
    const hdr = try a.print("{{\"alg\":\"A128GCMKW\",\"enc\":\"A128GCM\",\"iv\":\"{s}\",\"tag\":\"{s}\"}}", .{ test_b64.Encoder.encode(&ivb, &iv), test_b64.Encoder.encode(&tb, &tag) });
    const z = @as([16]u8, @splat(0));
    const token = try buildCompact(a, hdr, &z, &z, &z, &z);
    try std.testing.expectError(error.UnsupportedKeyLength, decryptCompact(std.testing.allocator, .{ .symmetric = &kek20 }, token, .{}));
}

// ── JSON serialization: several recipients and aad on encrypt (RFC 7516 §7.2.1, Appendix A.4 shape) ───────────

test "encryptJsonRecipients: every recipient of a general JWE decrypts it, aad is bound, A.4 shape" {
    const gpa = std.testing.allocator;
    const kek_a: [16]u8 = @splat(0x11);
    const kek_b: [32]u8 = @splat(0x22);
    var rsa_kp: rsa.KeyPair = undefined;
    try rsa.generate(&rsa_kp, seededForTest().fixed_for_test, 1024, 65537);
    var ec: ecdhes.EphemeralKeyPair = undefined;
    ecdhes.generateEphemeral(&ec, .p256, seededForTest());
    const recipients = [_]JsonRecipient{
        .{ .key_alg = .A128KW, .key = .{ .symmetric = &kek_a }, .opts = .{ .kid = "a" } },
        .{ .key_alg = .A256KW, .key = .{ .symmetric = &kek_b }, .opts = .{ .kid = "b" } },
        .{ .key_alg = .@"RSA-OAEP", .key = .{ .rsa_public = rsa_kp.public_key }, .opts = .{ .kid = "c" } },
        .{ .key_alg = .@"ECDH-ES+A128KW", .key = .{ .ec_public = ec.public }, .opts = .{ .apu = "u", .apv = "v" } },
        .{ .key_alg = .A128GCMKW, .key = .{ .symmetric = &kek_a } },
    };
    const keys = [_]KeyMaterial{
        .{ .symmetric = &kek_a }, .{ .symmetric = &kek_b }, .{ .rsa_private = &rsa_kp.secret_key }, .{ .ec_private = &ec.private }, .{ .symmetric = &kek_a },
    };
    for ([_]Enc{ .A128GCM, .A256GCM, .@"A128CBC-HS256" }) |content| {
        const doc = try encryptJsonRecipients(gpa, .general, content, &recipients, "to five recipients", seededForTest(), .{ .aad = "extra data", .cty = "text/plain" });
        defer gpa.free(doc);
        // The RFC 7516 A.4 shape: enc in the protected header, alg / kid per recipient.
        try std.testing.expect(std.mem.find(u8, doc, "\"recipients\":[{\"header\":{\"alg\":\"A128KW\",\"kid\":\"a\"}") != null);
        try std.testing.expect(std.mem.find(u8, doc, "\"aad\":\"ZXh0cmEgZGF0YQ\"") != null);
        for (keys) |k| {
            const plain = try decryptJson(gpa, k, doc, .{});
            defer gpa.free(plain);
            try std.testing.expectEqualStrings("to five recipients", plain);
        }
        // A changed aad member breaks the AEAD for everyone.
        const tampered = try gpa.dupe(u8, doc);
        defer gpa.free(tampered);
        const at = std.mem.find(u8, tampered, "\"aad\":\"ZXh0") orelse return error.TestUnexpectedResult;
        tampered[at + 8] = 'Z' ^ 0x20; // 'Z' -> 'z'
        try std.testing.expectError(error.AuthenticationFailed, decryptJson(gpa, keys[0], tampered, .{}));
    }
}

test "encryptJsonRecipients: flattened with aad, the sole direct recipient, refusals" {
    const gpa = std.testing.allocator;
    const key: [32]u8 = @splat(0x33);
    const one = [_]JsonRecipient{.{ .key_alg = .A256KW, .key = .{ .symmetric = &key } }};
    const flat = try encryptJsonRecipients(gpa, .flattened, .A256GCM, &one, "flat", seededForTest(), .{ .aad = "" });
    defer gpa.free(flat);
    try std.testing.expect(std.mem.find(u8, flat, "\"recipients\"") == null);
    try std.testing.expect(std.mem.find(u8, flat, "\"aad\":\"\"") != null);
    const plain = try decryptJson(gpa, .{ .symmetric = &key }, flat, .{});
    defer gpa.free(plain);
    try std.testing.expectEqualStrings("flat", plain);

    // dir alone is fine: no encrypted_key member.
    const dir = [_]JsonRecipient{.{ .key_alg = .dir, .key = .{ .symmetric = &key } }};
    const d = try encryptJsonRecipients(gpa, .general, .A256GCM, &dir, "dir", seededForTest(), .{});
    defer gpa.free(d);
    try std.testing.expect(std.mem.find(u8, d, "encrypted_key") == null);
    const dp = try decryptJson(gpa, .{ .symmetric = &key }, d, .{});
    defer gpa.free(dp);
    try std.testing.expectEqualStrings("dir", dp);

    // dir next to another recipient, none, flattened with two, an unknown alg.
    const two = [_]JsonRecipient{ one[0], dir[0] };
    try std.testing.expectError(error.UnsupportedAlg, encryptJsonRecipients(gpa, .general, .A256GCM, &two, "x", seededForTest(), .{}));
    try std.testing.expectError(error.InvalidRecipients, encryptJsonRecipients(gpa, .general, .A256GCM, &.{}, "x", seededForTest(), .{}));
    const two_kw = [_]JsonRecipient{ one[0], one[0] };
    try std.testing.expectError(error.InvalidRecipients, encryptJsonRecipients(gpa, .flattened, .A256GCM, &two_kw, "x", seededForTest(), .{}));
    try std.testing.expectError(error.UnsupportedEnc, encryptJsonRecipients(gpa, .general, .unknown, &one, "x", seededForTest(), .{}));
    // A wrong key for the one recipient it was not made for fails closed.
    const other: [32]u8 = @splat(0x34);
    try std.testing.expectError(error.AuthenticationFailed, decryptJson(gpa, .{ .symmetric = &other }, flat, .{}));
}
