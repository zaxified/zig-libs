// SPDX-License-Identifier: MIT

//! jwe — JSON Web Encryption (RFC 7516) + the JWA (RFC 7518) encryption
//! algorithms, compact serialization only. The encryption sibling of `jwt`
//! (which does JWS/signing): this module produces and consumes encrypted
//! tokens — `header.encrypted_key.iv.ciphertext.tag` — for a "confidential
//! claims" use case `jwt` deliberately doesn't cover.
//!
//! ## Scope (v1)
//!
//! **Compact serialization only** (RFC 7516 §3.1); the General/Flattened
//! JSON serializations (§7.2) are OUT OF SCOPE — they exist to carry
//! multiple recipients per message, which this module's single-`KeyMaterial`
//! API has no seam for yet (see SPEC.md).
//!
//! **Content encryption (`enc`, RFC 7518 §5)**:
//!   - `A128GCM`/`A256GCM` — REAL (`std.crypto.aead.aes_gcm`).
//!   - `A128CBC-HS256`/`A256CBC-HS512` — REAL (from-scratch AES-CBC +
//!     HMAC-SHA-2 encrypt-then-MAC; byte-exact against RFC 7518 Appendix B).
//!     See `enc.zig`.
//!   - `A192GCM`/`A192CBC-HS384` — **unsupported** (not stubbed): std 0.16
//!     ships no AES-192 cipher at all (`error.UnsupportedKeyLength`). See
//!     `enc.zig`.
//!
//! **Key management (`alg`, RFC 7518 §4)**:
//!   - `dir` — REAL (trivial: the CEK is the shared key).
//!   - `RSA-OAEP` / `RSA-OAEP-256` — REAL (wraps the `rsa` module's OAEP).
//!   - `A128KW`/`A256KW` — REAL (RFC 3394 AES Key Wrap; byte-exact against
//!     RFC 3394 §4.1 and RFC 7516 A.3). See the shared `aeskw` module.
//!   - `A128GCMKW`/`A256GCMKW` — REAL; `A192GCMKW`/`A192KW` unsupported
//!     (the same AES-192 std gap as content encryption).
//!   - `PBES2-HS256+A128KW`/`PBES2-HS512+A256KW` — REAL (PBKDF2 KDF feeding
//!     the AES Key Wrap above); `PBES2-HS384+A192KW` unsupported (its KW
//!     half needs the missing AES-192 core).
//!   - `ECDH-ES` / `ECDH-ES+A128KW` / `ECDH-ES+A256KW` — REAL (§4.6
//!     ephemeral-static ECDH on P-256 or X25519 + the Concat KDF; byte-exact
//!     against RFC 7518 Appendix C — see `ecdhes.zig`). Direct mode derives
//!     the CEK itself (empty Encrypted Key segment); the `+AxxxKW` modes
//!     derive a KEK feeding the RFC 3394 wrap. `ECDH-ES+A192KW` is the same
//!     AES-192 std gap as `A192KW`.
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
pub const alg = @import("alg.zig");
pub const Entropy = @import("entropy.zig").Entropy;
pub const aeskw = alg.aeskw;
pub const ecdhes = alg.ecdhes;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "JSON Web Encryption (RFC 7516/7518) compact serialization — RSA-OAEP/AxxxKW/ECDH-ES key management + AES-GCM/CBC-HMAC content encryption; A192* unsupported (no AES-192 in std)",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec, // pure wire codec + crypto dispatch, no I/O of its own
    .concurrency = .reentrant, // no shared/global state; every call is self-contained
    .model_after = "RFC 7516 (JWE) + RFC 7518 (JWA encryption algs) + RFC 3394 (AES Key Wrap); sibling of this repo's `jwt` (RFC 7515 JWS)",
    .deps = .{ "rsa", "p256", "aescbc", "aeskw" }, // p256 supplies the ECDH-ES P-256 curve (byte-exact to std.crypto.ecc.P256); X25519 stays on std; aescbc/aeskw supply the shared CBC + RFC 3394 key-wrap cores
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
    /// RSA private key — `RSA-OAEP`/`RSA-OAEP-256` decrypt side.
    rsa_private: rsa.SecretKey,
    /// Password — every `PBES2-*` variant. Borrowed, not copied.
    password: []const u8,
    /// Recipient's static EC/OKP public key (P-256 or X25519) —
    /// `ECDH-ES`/`ECDH-ES+AxxxKW` encrypt side.
    ec_public: ecdhes.PublicKey,
    /// Recipient's static EC/OKP private key — `ECDH-ES`/`ECDH-ES+AxxxKW`
    /// decrypt side.
    ec_private: ecdhes.PrivateKey,
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
    const cek = cek_buf[0..cek_len];
    var ek_buf: [max_encrypted_key_len]u8 = undefined;

    var wrap_iv: ?[12]u8 = null;
    var wrap_tag: ?[16]u8 = null;
    var pbes2_salt_buf: [alg.max_pbes2_salt_value_len]u8 = undefined;
    var pbes2_salt: ?[]const u8 = null;
    var pbes2_iterations: ?u32 = null;
    var epk_coords: ecdhes.Coordinates = undefined; // written before any read (ECDH-ES arm only)
    var epk_params: ?header.EpkParams = null;

    const encrypted_key: []const u8 = switch (key_alg) {
        .dir => blk: {
            const shared = switch (key) {
                .symmetric => |s| s,
                else => return error.KeyMaterialMismatch,
            };
            _ = try alg.dirCek(shared, cek_len, cek);
            break :blk &.{};
        },
        .@"RSA-OAEP", .@"RSA-OAEP-256" => blk: {
            const pk = switch (key) {
                .rsa_public => |p| p,
                else => return error.KeyMaterialMismatch,
            };
            random.bytes(cek);
            const hash: alg.OaepHash = if (key_alg == .@"RSA-OAEP") .sha1 else .sha256;
            break :blk try alg.rsaOaepWrap(pk, hash, entropy, cek, &ek_buf);
        },
        .A128KW, .A192KW, .A256KW => blk: {
            const kek = switch (key) {
                .symmetric => |s| s,
                else => return error.KeyMaterialMismatch,
            };
            random.bytes(cek);
            break :blk try alg.aeskw.wrap(kek, cek, &ek_buf);
        },
        .A128GCMKW, .A192GCMKW, .A256GCMKW => blk: {
            const kek = switch (key) {
                .symmetric => |s| s,
                else => return error.KeyMaterialMismatch,
            };
            random.bytes(cek);
            var iv: [12]u8 = undefined;
            random.bytes(&iv);
            var tag: [16]u8 = undefined;
            const ct = try alg.gcmkwWrap(kek, iv, cek, &ek_buf, &tag);
            wrap_iv = iv;
            wrap_tag = tag;
            break :blk ct;
        },
        .@"PBES2-HS256+A128KW", .@"PBES2-HS384+A192KW", .@"PBES2-HS512+A256KW" => blk: {
            const password = switch (key) {
                .password => |p| p,
                else => return error.KeyMaterialMismatch,
            };
            random.bytes(cek);
            const salt_len = @min(opts.pbes2_salt_len, pbes2_salt_buf.len);
            const salt = pbes2_salt_buf[0..salt_len];
            random.bytes(salt);
            const variant: alg.Pbes2Variant = switch (key_alg) {
                .@"PBES2-HS256+A128KW" => .hs256_a128kw,
                .@"PBES2-HS384+A192KW" => .hs384_a192kw,
                .@"PBES2-HS512+A256KW" => .hs512_a256kw,
                else => unreachable,
            };
            var kek_buf: [32]u8 = undefined;
            const kek = try alg.pbes2DeriveKek(variant, password, salt, opts.pbes2_iterations, &kek_buf);
            pbes2_salt = salt;
            pbes2_iterations = opts.pbes2_iterations;
            break :blk try alg.aeskw.wrap(kek, cek, &ek_buf);
        },
        .@"ECDH-ES", .@"ECDH-ES+A128KW", .@"ECDH-ES+A192KW", .@"ECDH-ES+A256KW" => blk: {
            const pk = switch (key) {
                .ec_public => |p| p,
                else => return error.KeyMaterialMismatch,
            };
            const curve = std.meta.activeTag(pk);
            var eph = ecdhes.generateEphemeral(curve, entropy);
            defer eph.private.wipe();
            var z_buf: [ecdhes.max_z_len]u8 = undefined;
            defer std.crypto.secureZero(u8, &z_buf);
            const z = try ecdhes.deriveZ(eph.private, pk, &z_buf);
            const apu = opts.apu orelse "";
            const apv = opts.apv orelse "";

            epk_coords = eph.public.coordinates();
            epk_params = .{
                .kty = curve.jwkKty(),
                .crv = curve.jwkCrv(),
                .x = epk_coords.x[0..],
                .y = if (epk_coords.y) |*y| y[0..] else null,
            };

            if (key_alg == .@"ECDH-ES") {
                // Direct Key Agreement: the derived key IS the CEK
                // (keydatalen = the `enc` key size, AlgorithmID = the `enc`
                // name); the Encrypted Key segment stays empty.
                ecdhes.concatKdfSha256(z, @tagName(content_enc), apu, apv, cek);
                break :blk &.{};
            }
            // Key Agreement with Key Wrapping: derive a KEK (keydatalen =
            // the KW size, AlgorithmID = the full `alg` name), wrap a
            // random CEK under it. ECDH-ES+A192KW's 24-byte KEK hits
            // aeskw's typed AES-192 std gap.
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
            random.bytes(cek);
            break :blk try alg.aeskw.wrap(kek, cek, &ek_buf);
        },
        .unknown => unreachable,
    };

    var header_buf: [header.max_header_json_len]u8 = undefined;
    const header_json = header.encode(&header_buf, .{
        .alg = @tagName(key_alg),
        .enc = @tagName(content_enc),
        .kid = opts.kid,
        .cty = opts.cty,
        .iv = if (wrap_iv) |*v| v[0..] else null,
        .tag = if (wrap_tag) |*v| v[0..] else null,
        .p2s = pbes2_salt,
        .p2c = pbes2_iterations,
        .epk = epk_params,
        .apu = if (epk_params != null) opts.apu else null,
        .apv = if (epk_params != null) opts.apv else null,
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
pub fn decryptCompact(
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

    return finishDecrypt(gpa, parsed, header_b64, cek, content_iv, ciphertext, tag);
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
            // same message (found 2026-10-05, mutation-run review).
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
            if (curve != std.meta.activeTag(sk)) return error.CurveMismatch;
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
        var csprng = std.Random.DefaultCsprng.init([_]u8{0x42} ** 32);
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
}

test "dir + A128GCM real round-trip" {
    const key = [_]u8{0x2b} ** 16;
    const token = try encryptCompact(std.testing.allocator, .dir, .A128GCM, .{ .symmetric = &key }, "attack at dawn", "", seededForTest(), .{});
    defer std.testing.allocator.free(token);

    const plaintext = try decryptCompact(std.testing.allocator, .{ .symmetric = &key }, token, .{});
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings("attack at dawn", plaintext);
}

test "dir + A256GCM real round-trip, empty plaintext" {
    const key = [_]u8{0x11} ** 32;
    const token = try encryptCompact(std.testing.allocator, .dir, .A256GCM, .{ .symmetric = &key }, "", "", seededForTest(), .{});
    defer std.testing.allocator.free(token);

    const plaintext = try decryptCompact(std.testing.allocator, .{ .symmetric = &key }, token, .{});
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings("", plaintext);
}

test "A128GCMKW + A128GCM real round-trip" {
    const kek = [_]u8{0x77} ** 16;
    const token = try encryptCompact(std.testing.allocator, .A128GCMKW, .A128GCM, .{ .symmetric = &kek }, "the eagle flies at midnight", "", seededForTest(), .{});
    defer std.testing.allocator.free(token);

    const plaintext = try decryptCompact(std.testing.allocator, .{ .symmetric = &kek }, token, .{});
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings("the eagle flies at midnight", plaintext);
}

test "tampered ciphertext fails authentication, never returns garbage plaintext" {
    const key = [_]u8{0x2b} ** 16;
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
    const key = [_]u8{0x2b} ** 16;
    const token = try encryptCompact(std.testing.allocator, .dir, .A128GCM, .{ .symmetric = &key }, "hi", "", seededForTest(), .{});
    defer std.testing.allocator.free(token);

    const bogus_rsa = rsa.PublicKey.fromBytes(&[_]u8{0xff} ** 64, &[_]u8{ 0x01, 0x00, 0x01 }) catch unreachable;
    try std.testing.expectError(error.KeyMaterialMismatch, decryptCompact(std.testing.allocator, .{ .rsa_public = bogus_rsa }, token, .{}));
}

test "compact serialization rejects non-empty aad_extra" {
    const key = [_]u8{0x2b} ** 16;
    try std.testing.expectError(error.CompactSerializationNoAad, encryptCompact(std.testing.allocator, .dir, .A128GCM, .{ .symmetric = &key }, "hi", "extra", seededForTest(), .{}));
}

test "unknown alg/enc are rejected up front" {
    const key = [_]u8{0x2b} ** 16;
    try std.testing.expectError(error.UnsupportedAlg, encryptCompact(std.testing.allocator, .unknown, .A128GCM, .{ .symmetric = &key }, "hi", "", seededForTest(), .{}));
    try std.testing.expectError(error.UnsupportedEnc, encryptCompact(std.testing.allocator, .dir, .unknown, .{ .symmetric = &key }, "hi", "", seededForTest(), .{}));
}

test "ECDH-ES direct + A128GCM real round-trip (P-256, apu/apv, empty encrypted_key)" {
    const recipient = ecdhes.generateEphemeral(.p256, seededForTest());
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

    const plaintext = try decryptCompact(std.testing.allocator, .{ .ec_private = recipient.private }, token, .{
        .expect_alg = .@"ECDH-ES",
        .expect_enc = .A128GCM,
    });
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings("meet at the old bridge", plaintext);
}

test "ECDH-ES+A256KW over X25519 real round-trip" {
    const recipient = ecdhes.generateEphemeral(.x25519, seededForTest());
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

    const plaintext = try decryptCompact(std.testing.allocator, .{ .ec_private = recipient.private }, token, .{
        .expect_alg = .@"ECDH-ES+A256KW",
    });
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings("the eagle flies at midnight", plaintext);
}

test "ECDH-ES+A128KW + A128CBC-HS256 real round-trip (P-256)" {
    const recipient = ecdhes.generateEphemeral(.p256, seededForTest());
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

    const plaintext = try decryptCompact(std.testing.allocator, .{ .ec_private = recipient.private }, token, .{});
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings("wrapped CEK, CBC-HMAC content", plaintext);
}

test "ECDH-ES cross-curve confusion is rejected: P-256 token vs X25519 key (typed)" {
    const p256_recipient = ecdhes.generateEphemeral(.p256, seededForTest());
    const x25519_recipient = ecdhes.generateEphemeral(.x25519, seededForTest());
    const token = try encryptCompact(std.testing.allocator, .@"ECDH-ES", .A128GCM, .{ .ec_public = p256_recipient.public }, "hi", "", seededForTest(), .{});
    defer std.testing.allocator.free(token);

    try std.testing.expectError(error.CurveMismatch, decryptCompact(std.testing.allocator, .{ .ec_private = x25519_recipient.private }, token, .{}));
}

test "ECDH-ES key-material confusion is rejected: ECDH token vs symmetric key" {
    const recipient = ecdhes.generateEphemeral(.p256, seededForTest());
    const token = try encryptCompact(std.testing.allocator, .@"ECDH-ES", .A128GCM, .{ .ec_public = recipient.public }, "hi", "", seededForTest(), .{});
    defer std.testing.allocator.free(token);

    const key = [_]u8{0x2b} ** 16;
    try std.testing.expectError(error.KeyMaterialMismatch, decryptCompact(std.testing.allocator, .{ .symmetric = &key }, token, .{}));
}

test "ECDH-ES direct rejects a non-empty encrypted_key segment" {
    const recipient = ecdhes.generateEphemeral(.p256, seededForTest());
    const token = try encryptCompact(std.testing.allocator, .@"ECDH-ES", .A128GCM, .{ .ec_public = recipient.public }, "hi", "", seededForTest(), .{});
    defer std.testing.allocator.free(token);

    // Splice a non-empty Encrypted Key into the (empty) second segment.
    var it = std.mem.splitScalar(u8, token, '.');
    const h = it.next().?;
    _ = it.next().?; // empty encrypted_key
    const rest = it.rest();
    const forged = try std.fmt.allocPrint(std.testing.allocator, "{s}.AAAAAAAAAAA.{s}", .{ h, rest });
    defer std.testing.allocator.free(forged);

    // `MalformedToken`, not `InvalidKey`: this is a structural property of the
    // token decided before any secret is used, and it is deliberately NOT
    // collapsed into the §11.5 unified key-error path — collapsing it would
    // hide the malleability defense it exists to be.
    try std.testing.expectError(error.MalformedToken, decryptCompact(std.testing.allocator, .{ .ec_private = recipient.private }, forged, .{}));
}

test "ECDH-ES+A192KW is the documented AES-192 std gap" {
    const recipient = ecdhes.generateEphemeral(.p256, seededForTest());
    try std.testing.expectError(error.UnsupportedKeyLength, encryptCompact(std.testing.allocator, .@"ECDH-ES+A192KW", .A128GCM, .{ .ec_public = recipient.public }, "hi", "", seededForTest(), .{}));
}

test "malformed compact tokens are rejected, never panic on arbitrary bytes" {
    const key = [_]u8{0x2b} ** 16;
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
    fuzzseed.seedHex("18" ++ "00045a" ** 24), // the maximum flip count, all in the header
    fuzzseed.seedHex("ff" ++ "003030" ** 8), // a flip count past the ceiling, clamped
    fuzzseed.seedHex("03" ++ "0002" ++ "7b" ++ "0003" ++ "22" ++ "0004" ++ "61"), // '{', '"', 'a' — pushing the header toward JSON-ish
};

test "fuzz: decryptCompact never panics on arbitrary compact tokens" {
    try std.testing.fuzz({}, fuzzDecryptCompact, .{ .corpus = &token_seeds });
}

fn fuzzDecryptCompact(_: void, smith: *std.testing.Smith) !void {
    const gpa = std.testing.allocator;
    const key = [_]u8{0x2b} ** 16;

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
    const token = encryptCompact(gpa, .A128KW, .A128GCM, .{ .symmetric = &key }, "fuzz", "", seededForTest(), .{}) catch return;
    defer gpa.free(token);
    var buf: [512]u8 = undefined;
    if (token.len > buf.len) return;
    @memcpy(buf[0..token.len], token);

    // ⚠ ONE byte-first draw, read as a flip script. See `token_seeds` for what
    // the ranged draws were worth on a corpus replay.
    var script_buf: [128]u8 = undefined;
    const script_len: usize = smith.slice(&script_buf);
    var script: fuzzseed.Cursor = .{ .bytes = script_buf[0..script_len] };
    applyFlips(&script, buf[0..token.len]);

    const pt = decryptCompact(gpa, .{ .symmetric = &key }, buf[0..token.len], .{}) catch return;
    gpa.free(pt);
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
    const key = [_]u8{0x2b} ** 16;
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
    // Measured 2026-09-07. The single input this target used to run was one
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
    const key = [_]u8{0x2b} ** 16;
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
    try std.testing.expectEqual(@as(usize, 2), info.fields.len);
    try std.testing.expectEqualStrings("csprng", info.fields[0].name);
    try std.testing.expectEqualStrings("fixed_for_test", info.fields[1].name);

    // The SAME generator under the two arms — different claims about the same
    // bytes is precisely the distinction the type exists to carry.
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x77} ** 32);
    const production: Entropy = .{ .csprng = csprng.random() };
    const for_test: Entropy = .{ .fixed_for_test = csprng.random() };
    try std.testing.expect(std.meta.activeTag(production) != std.meta.activeTag(for_test));
}

test "the CSPRNG requirement is load-bearing: dir + A256GCM with a repeated generator reuses the IV" {
    // `dir` is the sharp case: the CEK is the caller's long-lived key, so the
    // content IV is the only thing separating two messages. Two generators in
    // the same state stand in for "the consumer reached for DefaultPrng".
    const gpa = std.testing.allocator;
    const key = [_]u8{0x2b} ** 32;
    const p1 = "transfer 100 to alice!!!";
    const p2 = "transfer 999 to mallory??";

    var g1 = std.Random.DefaultCsprng.init([_]u8{0x11} ** 32);
    var g2 = std.Random.DefaultCsprng.init([_]u8{0x11} ** 32); // same seed
    var g3 = std.Random.DefaultCsprng.init([_]u8{0x12} ** 32); // different

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
    const kek = [_]u8{0x5a} ** 16;

    // A genuine token, so the tail of every case below is well-formed.
    const token = try encryptCompact(gpa, .A128KW, .A128GCM, .{ .symmetric = &kek }, "secret", "", seededForTest(), .{});
    defer gpa.free(token);

    var it = std.mem.splitScalar(u8, token, '.');
    const h = it.next().?;
    const real_ek = it.next().?;
    const rest = it.rest();

    // Case A — format/padding: the Encrypted Key is not a valid AES-KW blob.
    const junk = try std.fmt.allocPrint(gpa, "{s}.{s}.{s}", .{ h, "AAAAAAAAAAAAAAAAAAAAAAA", rest });
    defer gpa.free(junk);
    // Case B — length: a VALID wrap, of a message that is not the CEK length.
    // Built by wrapping a 24-byte key under the same KEK.
    var wrapped24: [32]u8 = undefined;
    _ = try alg.aeskw.wrap(&kek, &[_]u8{0x11} ** 24, &wrapped24);
    var wrapped_b64: [64]u8 = undefined;
    const enc_len = std.base64.url_safe_no_pad.Encoder.encode(&wrapped_b64, &wrapped24).len;
    const wrong_len = try std.fmt.allocPrint(gpa, "{s}.{s}.{s}", .{ h, wrapped_b64[0..enc_len], rest });
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
    const initial_p2c: u32 = if (builtin.mode == .Debug) 1_000 else 600_000;
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
    const at_ceiling_p2c: u32 = if (builtin.mode == .Debug) 20_000 else default_max_p2c;
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
    const at = std.mem.indexOf(u8, json, key).?;
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

    return std.fmt.allocPrint(gpa, "{s}.{s}", .{ new_h, rest });
}

// ── mutation run 2026-10-05 ─────────────────────────────────────────────────
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
    const iv = [_]u8{0x24} ** 12;
    var hb: [256]u8 = undefined;
    const header_b64 = test_b64.Encoder.encode(&hb, header_json);
    const ct = try a.alloc(u8, pt.len);
    defer a.free(ct);
    var tag: [16]u8 = undefined;
    _ = try enc.encrypt(.A128GCM, &cek, &iv, header_b64, pt, ct, &tag);
    return buildCompact(a, header_json, ek, &iv, ct, &tag);
}

test "dir refuses a non-empty encrypted_key segment (RFC 7516 §5.2 step 10)" {
    // Review finding 2026-10-05: only ECDH-ES checked this. The segment is
    // outside the AAD, so a dir token with bytes spliced into it decrypted
    // to the same plaintext — the malleability the ECDH-ES test names.
    const key = [_]u8{0x2b} ** 16;
    const token = try encryptCompact(std.testing.allocator, .dir, .A128GCM, .{ .symmetric = &key }, "hi", "", seededForTest(), .{});
    defer std.testing.allocator.free(token);
    var it = std.mem.splitScalar(u8, token, '.');
    const h = it.next().?;
    try std.testing.expectEqual(@as(usize, 0), it.next().?.len);
    const forged = try std.fmt.allocPrint(std.testing.allocator, "{s}.AAAAAAAAAAA.{s}", .{ h, it.rest() });
    defer std.testing.allocator.free(forged);
    try std.testing.expectError(error.MalformedToken, decryptCompact(std.testing.allocator, .{ .symmetric = &key }, forged, .{}));
}

test "expect_alg / expect_enc refuse a token of another algorithm" {
    // The caller's algorithm pin (RFC 8725 §3.1): without it the token's own
    // header picks the algorithm. Removing either check left every test green.
    const key = [_]u8{0x2b} ** 16;
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
    const key = [_]u8{0x2b} ** 16;
    const z = [_]u8{0} ** 16;
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
    const key = [_]u8{0x2b} ** 16;
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
        const json = try std.fmt.allocPrint(a, "{{\"alg\":\"A128GCMKW\",\"enc\":\"A128GCM\",\"iv\":\"{s}\"}}", .{enc_iv});
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
    const kek = [_]u8{0x77} ** 16;
    const bad_ek = [_]u8{0x01} ** 24;
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
    const key = [_]u8{0x2b} ** 32;
    for ([_]Enc{ .A128GCM, .@"A128CBC-HS256" }) |e| {
        const k = key[0..e.cekLen().?];
        const token = try encryptCompact(std.testing.allocator, .dir, e, .{ .symmetric = k }, "tag length", "", seededForTest(), .{});
        defer std.testing.allocator.free(token);
        const dot = std.mem.lastIndexOfScalar(u8, token, '.').?;
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
    const kp = try rsa.generate(prng.random(), 1024, 65537);
    const rsa_parsed = try header.parse(a, "{\"alg\":\"RSA-OAEP\",\"enc\":\"A128GCM\"}");
    const cek17 = [_]u8{0x5a} ** 17;
    for ([_]usize{ 15, 17 }) |n| {
        var ek_buf: [max_encrypted_key_len]u8 = undefined;
        const ek = try alg.rsaOaepWrap(kp.public_key, .sha1, seededForTest(), cek17[0..n], &ek_buf);
        try std.testing.expectError(error.InvalidKey, unwrapCek(rsa_parsed, .{ .rsa_private = kp.secret_key }, ek, &cek, 16, .{}));
    }

    const kek = [_]u8{0x77} ** 16;
    const iv13 = [_]u8{0x31} ** 13;
    var ct16: [16]u8 = undefined;
    var tag: [16]u8 = undefined;
    _ = try alg.gcmkwWrap(&kek, iv13[0..12].*, &([_]u8{0x5a} ** 16), &ct16, &tag);
    var ivb: [32]u8 = undefined;
    var tb: [32]u8 = undefined;
    const tag17 = tag ++ [_]u8{0};
    const long_iv = try header.parse(a, try std.fmt.allocPrint(a, "{{\"alg\":\"A128GCMKW\",\"enc\":\"A128GCM\",\"iv\":\"{s}\",\"tag\":\"{s}\"}}", .{ test_b64.Encoder.encode(&ivb, &iv13), test_b64.Encoder.encode(&tb, &tag) }));
    try std.testing.expectError(error.InvalidKey, unwrapCek(long_iv, .{ .symmetric = &kek }, &ct16, &cek, 16, .{}));
    const long_tag = try header.parse(a, try std.fmt.allocPrint(a, "{{\"alg\":\"A128GCMKW\",\"enc\":\"A128GCM\",\"iv\":\"{s}\",\"tag\":\"{s}\"}}", .{ test_b64.Encoder.encode(&ivb, iv13[0..12]), test_b64.Encoder.encode(&tb, &tag17) }));
    try std.testing.expectError(error.InvalidKey, unwrapCek(long_tag, .{ .symmetric = &kek }, &ct16, &cek, 16, .{}));

    var ct8: [8]u8 = undefined;
    _ = try alg.gcmkwWrap(&kek, iv13[0..12].*, &([_]u8{0x5a} ** 8), &ct8, &tag);
    const short = try header.parse(a, try std.fmt.allocPrint(a, "{{\"alg\":\"A128GCMKW\",\"enc\":\"A128GCM\",\"iv\":\"{s}\",\"tag\":\"{s}\"}}", .{ test_b64.Encoder.encode(&ivb, iv13[0..12]), test_b64.Encoder.encode(&tb, &tag) }));
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
    _ = try aeskw.wrap(kek, &([_]u8{0x5a} ** 16), &ek);

    const at_max = try header.parse(a, try std.fmt.allocPrint(a, fmt, .{ p2s8, 10 }));
    try unwrapCek(at_max, .{ .password = password }, &ek, &cek, 16, .{ .max_p2c = 10 });
    try std.testing.expectEqualSlices(u8, &([_]u8{0x5a} ** 16), &cek);
    const over = try header.parse(a, try std.fmt.allocPrint(a, fmt, .{ p2s8, 11 }));
    try std.testing.expectError(error.WorkFactorTooHigh, unwrapCek(over, .{ .password = password }, &ek, &cek, 16, .{ .max_p2c = 10 }));
    const short_salt = try header.parse(a, try std.fmt.allocPrint(a, fmt, .{ p2s7, 10 }));
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
