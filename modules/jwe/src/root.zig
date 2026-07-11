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
//!     RFC 3394 §4.1 and RFC 7516 A.3). See `aeskw.zig`.
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
//!     csprng.random(), .{},
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
//! - Compact serialization carries no extra AAD (RFC 7516 §5.1); passing a
//!   non-empty `aad_extra` to `encryptCompact` is `error.CompactSerializationNoAad`.

const std = @import("std");
const rsa = @import("rsa");

pub const header = @import("header.zig");
pub const enc = @import("enc.zig");
pub const alg = @import("alg.zig");
pub const aeskw = alg.aeskw;
pub const ecdhes = alg.ecdhes;

pub const meta = .{
    .platform = .any,
    .role = .codec, // pure wire codec + crypto dispatch, no I/O of its own
    .concurrency = .reentrant, // no shared/global state; every call is self-contained
    .model_after = "RFC 7516 (JWE) + RFC 7518 (JWA encryption algs) + RFC 3394 (AES Key Wrap); sibling of this repo's `jwt` (RFC 7515 JWS)",
    .deps = .{"rsa"},
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
} || header.ParseError || alg.Error || enc.Error;

/// Encrypt `plaintext` into a compact-serialization JWE. `random` supplies
/// every fresh value this call needs (CEK when `alg` isn't `dir`, the
/// content IV, the AxxxGCMKW wrap IV, the PBES2 salt input) and MUST be
/// cryptographically secure. Returns a `gpa`-owned string; free with `gpa`.
///
/// `aad_extra` must be empty — see the module doc comment.
pub fn encryptCompact(
    gpa: std.mem.Allocator,
    key_alg: Alg,
    content_enc: Enc,
    key: KeyMaterial,
    plaintext: []const u8,
    aad_extra: []const u8,
    random: std.Random,
    opts: EncryptOptions,
) EncryptError![]u8 {
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
            break :blk try alg.rsaOaepWrap(pk, hash, random, cek, &ek_buf);
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
            var eph = ecdhes.generateEphemeral(curve, random);
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
    const cek = cek_buf[0..cek_len];

    const encrypted_key = try decodeSegmentAlloc(arena, ek_b64);
    const content_iv = try decodeSegmentAlloc(arena, iv_b64);
    const ciphertext = try decodeSegmentAlloc(arena, ct_b64);
    const tag = try decodeSegmentAlloc(arena, tag_b64);

    switch (parsed.alg) {
        .dir => {
            const shared = switch (key) {
                .symmetric => |s| s,
                else => return error.KeyMaterialMismatch,
            };
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
            const epk = parsed.epk orelse return error.InvalidKey;
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
                // empty (RFC 7516 §5.2 step 5) — a non-empty one is a
                // malformed/hostile token, not something to ignore.
                if (encrypted_key.len != 0) return error.InvalidKey;
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

    const plaintext = try gpa.alloc(u8, ciphertext.len);
    errdefer gpa.free(plaintext);
    const n = try enc.decrypt(parsed.enc, cek, content_iv, header_b64, ciphertext, tag, plaintext);
    if (n == plaintext.len) return plaintext;
    const trimmed = try gpa.realloc(plaintext, n);
    return trimmed;
}

/// Deterministic CSPRNG for tests only — production callers must supply
/// their own cryptographically secure `std.Random` (see the module doc
/// comment's usage example; std 0.16 removed `std.crypto.random`).
fn testRandom() std.Random {
    const S = struct {
        var csprng = std.Random.DefaultCsprng.init([_]u8{0x42} ** 32);
    };
    return S.csprng.random();
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
    const token = try encryptCompact(std.testing.allocator, .dir, .A128GCM, .{ .symmetric = &key }, "attack at dawn", "", testRandom(), .{});
    defer std.testing.allocator.free(token);

    const plaintext = try decryptCompact(std.testing.allocator, .{ .symmetric = &key }, token, .{});
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings("attack at dawn", plaintext);
}

test "dir + A256GCM real round-trip, empty plaintext" {
    const key = [_]u8{0x11} ** 32;
    const token = try encryptCompact(std.testing.allocator, .dir, .A256GCM, .{ .symmetric = &key }, "", "", testRandom(), .{});
    defer std.testing.allocator.free(token);

    const plaintext = try decryptCompact(std.testing.allocator, .{ .symmetric = &key }, token, .{});
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings("", plaintext);
}

test "A128GCMKW + A128GCM real round-trip" {
    const kek = [_]u8{0x77} ** 16;
    const token = try encryptCompact(std.testing.allocator, .A128GCMKW, .A128GCM, .{ .symmetric = &kek }, "the eagle flies at midnight", "", testRandom(), .{});
    defer std.testing.allocator.free(token);

    const plaintext = try decryptCompact(std.testing.allocator, .{ .symmetric = &kek }, token, .{});
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings("the eagle flies at midnight", plaintext);
}

test "tampered ciphertext fails authentication, never returns garbage plaintext" {
    const key = [_]u8{0x2b} ** 16;
    const token = try encryptCompact(std.testing.allocator, .dir, .A128GCM, .{ .symmetric = &key }, "attack at dawn", "", testRandom(), .{});
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
    const token = try encryptCompact(std.testing.allocator, .dir, .A128GCM, .{ .symmetric = &key }, "hi", "", testRandom(), .{});
    defer std.testing.allocator.free(token);

    const bogus_rsa = rsa.PublicKey.fromBytes(&[_]u8{0xff} ** 64, &[_]u8{ 0x01, 0x00, 0x01 }) catch unreachable;
    try std.testing.expectError(error.KeyMaterialMismatch, decryptCompact(std.testing.allocator, .{ .rsa_public = bogus_rsa }, token, .{}));
}

test "compact serialization rejects non-empty aad_extra" {
    const key = [_]u8{0x2b} ** 16;
    try std.testing.expectError(error.CompactSerializationNoAad, encryptCompact(std.testing.allocator, .dir, .A128GCM, .{ .symmetric = &key }, "hi", "extra", testRandom(), .{}));
}

test "unknown alg/enc are rejected up front" {
    const key = [_]u8{0x2b} ** 16;
    try std.testing.expectError(error.UnsupportedAlg, encryptCompact(std.testing.allocator, .unknown, .A128GCM, .{ .symmetric = &key }, "hi", "", testRandom(), .{}));
    try std.testing.expectError(error.UnsupportedEnc, encryptCompact(std.testing.allocator, .dir, .unknown, .{ .symmetric = &key }, "hi", "", testRandom(), .{}));
}

test "ECDH-ES direct + A128GCM real round-trip (P-256, apu/apv, empty encrypted_key)" {
    const recipient = ecdhes.generateEphemeral(.p256, testRandom());
    const token = try encryptCompact(
        std.testing.allocator,
        .@"ECDH-ES",
        .A128GCM,
        .{ .ec_public = recipient.public },
        "meet at the old bridge",
        "",
        testRandom(),
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
    const recipient = ecdhes.generateEphemeral(.x25519, testRandom());
    const token = try encryptCompact(
        std.testing.allocator,
        .@"ECDH-ES+A256KW",
        .A256GCM,
        .{ .ec_public = recipient.public },
        "the eagle flies at midnight",
        "",
        testRandom(),
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
    const recipient = ecdhes.generateEphemeral(.p256, testRandom());
    const token = try encryptCompact(
        std.testing.allocator,
        .@"ECDH-ES+A128KW",
        .@"A128CBC-HS256",
        .{ .ec_public = recipient.public },
        "wrapped CEK, CBC-HMAC content",
        "",
        testRandom(),
        .{ .apv = "bob@example.org" },
    );
    defer std.testing.allocator.free(token);

    const plaintext = try decryptCompact(std.testing.allocator, .{ .ec_private = recipient.private }, token, .{});
    defer std.testing.allocator.free(plaintext);
    try std.testing.expectEqualStrings("wrapped CEK, CBC-HMAC content", plaintext);
}

test "ECDH-ES cross-curve confusion is rejected: P-256 token vs X25519 key (typed)" {
    const p256_recipient = ecdhes.generateEphemeral(.p256, testRandom());
    const x25519_recipient = ecdhes.generateEphemeral(.x25519, testRandom());
    const token = try encryptCompact(std.testing.allocator, .@"ECDH-ES", .A128GCM, .{ .ec_public = p256_recipient.public }, "hi", "", testRandom(), .{});
    defer std.testing.allocator.free(token);

    try std.testing.expectError(error.CurveMismatch, decryptCompact(std.testing.allocator, .{ .ec_private = x25519_recipient.private }, token, .{}));
}

test "ECDH-ES key-material confusion is rejected: ECDH token vs symmetric key" {
    const recipient = ecdhes.generateEphemeral(.p256, testRandom());
    const token = try encryptCompact(std.testing.allocator, .@"ECDH-ES", .A128GCM, .{ .ec_public = recipient.public }, "hi", "", testRandom(), .{});
    defer std.testing.allocator.free(token);

    const key = [_]u8{0x2b} ** 16;
    try std.testing.expectError(error.KeyMaterialMismatch, decryptCompact(std.testing.allocator, .{ .symmetric = &key }, token, .{}));
}

test "ECDH-ES direct rejects a non-empty encrypted_key segment" {
    const recipient = ecdhes.generateEphemeral(.p256, testRandom());
    const token = try encryptCompact(std.testing.allocator, .@"ECDH-ES", .A128GCM, .{ .ec_public = recipient.public }, "hi", "", testRandom(), .{});
    defer std.testing.allocator.free(token);

    // Splice a non-empty Encrypted Key into the (empty) second segment.
    var it = std.mem.splitScalar(u8, token, '.');
    const h = it.next().?;
    _ = it.next().?; // empty encrypted_key
    const rest = it.rest();
    const forged = try std.fmt.allocPrint(std.testing.allocator, "{s}.AAAAAAAAAAA.{s}", .{ h, rest });
    defer std.testing.allocator.free(forged);

    try std.testing.expectError(error.InvalidKey, decryptCompact(std.testing.allocator, .{ .ec_private = recipient.private }, forged, .{}));
}

test "ECDH-ES+A192KW is the documented AES-192 std gap" {
    const recipient = ecdhes.generateEphemeral(.p256, testRandom());
    try std.testing.expectError(error.UnsupportedKeyLength, encryptCompact(std.testing.allocator, .@"ECDH-ES+A192KW", .A128GCM, .{ .ec_public = recipient.public }, "hi", "", testRandom(), .{}));
}

test "malformed compact tokens are rejected, never panic on arbitrary bytes" {
    const key = [_]u8{0x2b} ** 16;
    try std.testing.expectError(error.MalformedToken, decryptCompact(std.testing.allocator, .{ .symmetric = &key }, "not.enough.parts", .{}));
    try std.testing.expectError(error.MalformedToken, decryptCompact(std.testing.allocator, .{ .symmetric = &key }, "too.many.parts.here.for.sure", .{}));
    try std.testing.expectError(error.InvalidBase64, decryptCompact(std.testing.allocator, .{ .symmetric = &key }, "not!base64.a.b.c.d", .{}));
}
