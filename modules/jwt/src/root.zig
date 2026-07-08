// SPDX-License-Identifier: MIT

//! jwt — JWT/JWS validator for OAuth2/OIDC resource servers
//! (RFC 7515 compact JWS serialization + RFC 7519 JWT claims + RFC 7518
//! JWA signature algorithms).
//!
//! Scope so far: compact-token **parsing** into typed models (P1),
//! **registered-claims validation** (`exp`/`nbf`/`iat`/`iss`/`aud`, P1), and
//! **JWS signature verification** (P2+P3) for HS256/384/512 (HMAC-SHA-2),
//! ES256/ES384 (ECDSA P-256/P-384), EdDSA (Ed25519) and RS256/384/512
//! (RSASSA-PKCS1-v1_5, the OIDC default) — plus the one-call
//! `parseAndVerify` that chains all three.
//!
//! ## SECURITY — `parse()` alone does NOT verify signatures
//!
//! `parse()` only *decodes* a token. A `ParsedToken` is **UNTRUSTED,
//! attacker-controlled input** until `verify(parsed, key)` (or the
//! all-in-one `parseAndVerify`) has run. Never make an authorization
//! decision from a `ParsedToken` alone; anyone can mint a syntactically
//! valid token with any claims. The parsed `signing_input` + `signature` +
//! `alg` exist precisely so the verify step layers on without re-parsing.
//!
//! `verify` implements the RFC 8725 hardening rules: `alg:"none"` is always
//! rejected (`UnsecuredToken`), and the token's `alg` must match the *type*
//! of the provided key (`AlgKeyMismatch`) so an attacker cannot downgrade an
//! asymmetric token to HMAC-with-the-public-key.
//!
//! Planned parts: P4 JWKS key sets · P5 fetch/OIDC discovery ·
//! P6 resource-server middleware.
//!
//! ## Usage
//!
//! ```zig
//! const jwt = @import("jwt");
//!
//! // One call: parse → verify signature → validate claims.
//! var token = try jwt.parseAndVerify(gpa, bearer_token, .{ .hmac = secret }, .{
//!     .now_s = now_seconds, // caller-supplied clock, no hidden time source
//!     .issuer = "https://issuer.example",
//!     .audience = "api://my-service",
//! });
//! defer token.deinit();
//! const scope = token.claims.claimStr("scope") orelse "";
//!
//! // Or step by step (e.g. pick the key from the header's `kid` first):
//! var parsed = try jwt.parse(gpa, bearer_token);
//! defer parsed.deinit();
//! const key = pickKey(parsed.header.kid); // P4 will do this from a JWKS
//! try jwt.verify(&parsed, key);
//! try jwt.validateClaims(parsed.claims, .{ .now_s = now_seconds });
//! ```
//!
//! Design notes:
//! - std-only; one `gpa` in, everything a token owns lives in one internal
//!   arena freed by `ParsedToken.deinit()`. The returned token does not
//!   borrow the input string — the caller may free it right after `parse`.
//! - `parse` and `validateClaims` are deliberately separate: resource
//!   servers decide *when* to check time/issuer/audience (and with which
//!   `now_s`), e.g. after picking a tenant from the unvalidated `iss`.
//! - Time is caller-supplied (`Options.now_s`) — no hidden clock, mirroring
//!   the `resilience`/`probe` siblings' injected-clock rule.
//! - Malformed input returns typed errors; it never panics.

const std = @import("std");

pub const meta = .{
    .status = .gap,
    .platform = .any,
    .role = .util, // P6 adds the resource-server middleware on top.
    .concurrency = .reentrant,
    .model_after = "RFC 7515 (JWS) + RFC 7519 (JWT) + RFC 7518 (JWA) verify incl. RS256 (RSASSA-PKCS1-v1_5, RFC 8017), RFC 8725 hardening; OAuth2/OIDC resource server",
    .deps = .{},
};

// ── public API ──────────────────────────────────────────────────────────────

/// Errors from `parse`. Every malformed-token shape maps to one of these —
/// parsing never panics on arbitrary bytes.
pub const ParseError = error{
    /// Not exactly three dot-separated segments, or an empty header/payload
    /// segment.
    MalformedToken,
    /// A segment is not valid base64url-without-padding (RFC 7515 §2).
    InvalidBase64,
    /// Header or payload decoded fine but is not valid JSON.
    InvalidJson,
    /// Header or payload is valid JSON but not a JSON object.
    NotAnObject,
    /// Header lacks the REQUIRED `alg` member, or `alg` is not a string
    /// (RFC 7515 §4.1.1).
    MissingAlg,
    /// A known header parameter or registered claim has the wrong JSON type
    /// (e.g. string `exp`, numeric `iss`, non-string entry in an `aud` array).
    InvalidClaim,
    OutOfMemory,
};

/// Errors from `validateClaims` (RFC 7519 §4.1 semantics).
pub const ValidateError = error{
    /// `exp` (+ leeway) is in the past.
    Expired,
    /// `nbf` (− leeway) is in the future.
    NotYetValid,
    /// `iat` (− leeway) is in the future (checked only when
    /// `Options.reject_future_iat` is set — lenient by default).
    IssuedInFuture,
    /// `Options.issuer` was given and `iss` is absent or different.
    IssuerMismatch,
    /// `Options.audience` was given and is not contained in `aud`.
    AudienceMismatch,
    /// `exp` is absent and `Options.require_exp` is set.
    MissingExp,
};

/// JWS signature algorithm, from the header's `alg` (RFC 7518 §3.1 names).
/// Parsed for Part 2's verify dispatch; unrecognized names map to `.unknown`.
/// `alg: "none"` (unsecured JWT) parses as `.none` — the verify step rejects
/// it (RFC 8725 §2.1), parsing alone does not.
pub const Alg = enum {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
    PS256,
    PS384,
    PS512,
    EdDSA,
    none,
    unknown,

    pub fn fromString(s: []const u8) Alg {
        return std.meta.stringToEnum(Alg, s) orelse .unknown;
    }
};

/// JOSE header (RFC 7515 §4) — the parameters a resource server needs.
/// Slices point into the owning `ParsedToken`'s arena.
pub const Header = struct {
    /// REQUIRED `alg`, verbatim (also available typed as `ParsedToken.alg`).
    alg: []const u8,
    typ: ?[]const u8 = null,
    /// Key ID — Part 4's JWKS lookup key.
    kid: ?[]const u8 = null,
    cty: ?[]const u8 = null,
};

/// The `aud` claim (RFC 7519 §4.1.3): absent, a single StringOrURI, or an
/// array of them.
pub const Audience = union(enum) {
    none,
    single: []const u8,
    many: []const []const u8,

    /// Case-sensitive membership test (RFC 7519 string comparison).
    pub fn contains(self: Audience, candidate: []const u8) bool {
        return switch (self) {
            .none => false,
            .single => |s| std.mem.eql(u8, s, candidate),
            .many => |list| for (list) |a| {
                if (std.mem.eql(u8, a, candidate)) break true;
            } else false,
        };
    }
};

/// Registered claims (RFC 7519 §4.1) plus access to every other claim via
/// `raw` / the `claim*` getters. NumericDates are seconds since the epoch
/// (i64; fractional JSON numbers are truncated). Slices point into the
/// owning `ParsedToken`'s arena.
pub const Claims = struct {
    iss: ?[]const u8 = null,
    sub: ?[]const u8 = null,
    aud: Audience = .none,
    exp: ?i64 = null,
    nbf: ?i64 = null,
    iat: ?i64 = null,
    jti: ?[]const u8 = null,
    /// The full decoded payload (always `.object`) — custom claims live here.
    raw: std.json.Value,

    /// Any claim by name, as a JSON value; null when absent.
    pub fn claim(self: Claims, name: []const u8) ?std.json.Value {
        return self.raw.object.get(name);
    }

    /// String claim by name; null when absent or not a JSON string.
    pub fn claimStr(self: Claims, name: []const u8) ?[]const u8 {
        const v = self.claim(name) orelse return null;
        return switch (v) {
            .string => |s| s,
            else => null,
        };
    }

    /// Integer claim by name; null when absent or not a JSON integer.
    pub fn claimInt(self: Claims, name: []const u8) ?i64 {
        const v = self.claim(name) orelse return null;
        return switch (v) {
            .integer => |i| i,
            else => null,
        };
    }

    /// Boolean claim by name; null when absent or not a JSON boolean.
    pub fn claimBool(self: Claims, name: []const u8) ?bool {
        const v = self.claim(name) orelse return null;
        return switch (v) {
            .bool => |b| b,
            else => null,
        };
    }
};

/// A decoded — **NOT verified** — token. Everything it references lives in
/// its internal arena; call `deinit()` when done. See the module-level
/// security note: treat as attacker-controlled until Part 2's `verify` runs.
pub const ParsedToken = struct {
    header: Header,
    claims: Claims,
    /// `ASCII(BASE64URL(header) || '.' || BASE64URL(payload))` — exactly the
    /// bytes the signature covers (RFC 7515 §5.1); input to Part 2's verify.
    signing_input: []const u8,
    /// Decoded signature bytes (may be empty for an unsecured JWT).
    signature: []const u8,
    /// `header.alg` parsed for dispatch; `.unknown` for unrecognized names.
    alg: Alg,

    arena: *std.heap.ArenaAllocator,

    pub fn deinit(self: *ParsedToken) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
        self.* = undefined;
    }
};

/// Parse a compact-serialization JWS/JWT (RFC 7515 §3.1:
/// `BASE64URL(header) '.' BASE64URL(payload) '.' BASE64URL(signature)`).
///
/// Decodes and type-checks; does **not** verify the signature and does
/// **not** validate any claim (call `validateClaims` — and, from Part 2 on,
/// `verify` — separately). The result owns copies of everything it needs;
/// `token` may be freed immediately after this returns.
pub fn parse(gpa: std.mem.Allocator, token: []const u8) ParseError!ParsedToken {
    // Split into exactly three segments (an unsecured JWT's third segment
    // is legitimately empty, so only header/payload must be non-empty).
    const dot1 = std.mem.indexOfScalar(u8, token, '.') orelse return error.MalformedToken;
    const dot2 = std.mem.indexOfScalarPos(u8, token, dot1 + 1, '.') orelse return error.MalformedToken;
    if (std.mem.indexOfScalarPos(u8, token, dot2 + 1, '.') != null) return error.MalformedToken;
    const header_b64 = token[0..dot1];
    const payload_b64 = token[dot1 + 1 .. dot2];
    const signature_b64 = token[dot2 + 1 ..];
    if (header_b64.len == 0 or payload_b64.len == 0) return error.MalformedToken;

    const arena_state = try gpa.create(std.heap.ArenaAllocator);
    errdefer gpa.destroy(arena_state);
    arena_state.* = .init(gpa);
    errdefer arena_state.deinit();
    const arena = arena_state.allocator();

    const header_json = try decodeSegment(arena, header_b64);
    const payload_json = try decodeSegment(arena, payload_b64);
    const signature = try decodeSegment(arena, signature_b64);
    const signing_input = try arena.dupe(u8, token[0..dot2]);

    // Header.
    const header_val = try parseJsonObject(arena, header_json);
    const header_obj = header_val.object;
    const alg_str = blk: {
        const v = header_obj.get("alg") orelse return error.MissingAlg;
        break :blk switch (v) {
            .string => |s| s,
            else => return error.MissingAlg,
        };
    };
    const header: Header = .{
        .alg = alg_str,
        .typ = try optionalString(header_obj, "typ"),
        .kid = try optionalString(header_obj, "kid"),
        .cty = try optionalString(header_obj, "cty"),
    };

    // Payload / claims.
    const payload_val = try parseJsonObject(arena, payload_json);
    const payload_obj = payload_val.object;
    const claims: Claims = .{
        .iss = try optionalString(payload_obj, "iss"),
        .sub = try optionalString(payload_obj, "sub"),
        .aud = try extractAudience(arena, payload_obj),
        .exp = try optionalNumericDate(payload_obj, "exp"),
        .nbf = try optionalNumericDate(payload_obj, "nbf"),
        .iat = try optionalNumericDate(payload_obj, "iat"),
        .jti = try optionalString(payload_obj, "jti"),
        .raw = payload_val,
    };

    return .{
        .header = header,
        .claims = claims,
        .signing_input = signing_input,
        .signature = signature,
        .alg = Alg.fromString(alg_str),
        .arena = arena_state,
    };
}

/// Claims-validation options. `now_s` is REQUIRED and caller-supplied
/// (seconds since epoch) — this module has no hidden clock.
pub const Options = struct {
    /// Current time, seconds since the Unix epoch.
    now_s: i64,
    /// Clock-skew allowance applied to `exp`/`nbf`/`iat` (RFC 7519 §4.1.4
    /// "usually no more than a few minutes").
    leeway_s: u32 = 60,
    /// When set, `iss` must be present and equal (case-sensitive).
    issuer: ?[]const u8 = null,
    /// When set, this value must be contained in `aud` (single string or
    /// any element of an array).
    audience: ?[]const u8 = null,
    /// Reject tokens without `exp` (a resource server should not accept
    /// tokens that never expire).
    require_exp: bool = true,
    /// Also reject `iat` in the future. Off by default — RFC 7519 makes
    /// `iat` informational, and some issuers' clocks run ahead.
    reject_future_iat: bool = false,
};

/// Validate registered claims per RFC 7519 §4.1. Pure and allocation-free;
/// separate from `parse` so the caller picks the clock and policy.
///
/// SECURITY: passing claims validation does NOT make a token trustworthy —
/// the signature must also be verified (Part 2). Check order: exp, nbf,
/// iat, iss, aud; the first failure is returned.
pub fn validateClaims(claims: Claims, opts: Options) ValidateError!void {
    const leeway: i64 = opts.leeway_s;
    if (claims.exp) |exp| {
        if (exp +| leeway < opts.now_s) return error.Expired;
    } else if (opts.require_exp) {
        return error.MissingExp;
    }
    if (claims.nbf) |nbf| {
        if (nbf -| leeway > opts.now_s) return error.NotYetValid;
    }
    if (opts.reject_future_iat) {
        if (claims.iat) |iat| {
            if (iat -| leeway > opts.now_s) return error.IssuedInFuture;
        }
    }
    if (opts.issuer) |want| {
        const iss = claims.iss orelse return error.IssuerMismatch;
        if (!std.mem.eql(u8, iss, want)) return error.IssuerMismatch;
    }
    if (opts.audience) |want| {
        if (!claims.aud.contains(want)) return error.AudienceMismatch;
    }
}

// ── signature verification (RFC 7515 §5.2, RFC 7518, RFC 8037) ─────────────

/// std signature schemes re-exported so callers (and P4's JWKS) can name the
/// key types without spelling out the std.crypto paths.
pub const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
pub const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
pub const Ed25519 = std.crypto.sign.Ed25519;

const hmac_sha2 = std.crypto.auth.hmac.sha2;
const sha2 = std.crypto.hash.sha2;
/// std's RSA verify machinery (it lives under Certificate because TLS
/// certificate validation is its std consumer; the math is generic
/// RFC 8017 RSASSA-PKCS1-v1_5 over std.crypto.ff big-integer modexp).
const cert_rsa = std.crypto.Certificate.rsa;

/// An RSA public verification key: the validated `(n, e)` pair plus the
/// modulus octet length `k` (RFC 8017 §4.1) — an RS* JWS signature is
/// valid only if it is exactly `k` bytes (RFC 7518 §3.3). Built via
/// `Key.rsaFromModExp`; supports the common 2048/3072/4096-bit sizes.
pub const RsaPublicKey = struct {
    inner: cert_rsa.PublicKey,
    /// Modulus length in octets: 256, 384 or 512.
    modulus_len: usize,
};

/// Errors from the `Key` constructors: the bytes do not encode a valid key
/// (point not on the curve, non-canonical encoding, …).
pub const KeyError = error{InvalidKey};

/// A verification key. The union *tag* is part of the security model: the
/// token's `alg` must match the key's type (see `verify`), which is what
/// blocks the classic RS/ES→HS256 algorithm-confusion downgrade
/// (RFC 8725 §2.1). Part 4 builds these from JWKS entries
/// (`kty`/`crv`/`x`/`y`/`k`/`n`/`e`).
pub const Key = union(enum) {
    /// Symmetric HMAC secret for HS256/HS384/HS512. Borrowed, not copied —
    /// must outlive the `verify` call (it always does; `verify` returns
    /// before control leaves the caller).
    hmac: []const u8,
    /// P-256 public key for ES256.
    ecdsa_p256: EcdsaP256Sha256.PublicKey,
    /// P-384 public key for ES384.
    ecdsa_p384: EcdsaP384Sha384.PublicKey,
    /// Ed25519 public key for EdDSA (RFC 8037).
    ed25519: Ed25519.PublicKey,
    /// RSA public key for RS256/RS384/RS512 (RSASSA-PKCS1-v1_5).
    rsa: RsaPublicKey,

    /// P-256 key from raw big-endian affine coordinates — exactly a JWK's
    /// decoded `x`/`y` (RFC 7518 §6.2.1).
    pub fn ecdsaP256FromCoords(x: [32]u8, y: [32]u8) KeyError!Key {
        var sec1: [65]u8 = undefined;
        sec1[0] = 0x04; // uncompressed SEC1 point
        @memcpy(sec1[1..33], &x);
        @memcpy(sec1[33..65], &y);
        const pk = EcdsaP256Sha256.PublicKey.fromSec1(&sec1) catch return error.InvalidKey;
        return .{ .ecdsa_p256 = pk };
    }

    /// P-384 key from raw big-endian affine coordinates (JWK `x`/`y`).
    pub fn ecdsaP384FromCoords(x: [48]u8, y: [48]u8) KeyError!Key {
        var sec1: [97]u8 = undefined;
        sec1[0] = 0x04;
        @memcpy(sec1[1..49], &x);
        @memcpy(sec1[49..97], &y);
        const pk = EcdsaP384Sha384.PublicKey.fromSec1(&sec1) catch return error.InvalidKey;
        return .{ .ecdsa_p384 = pk };
    }

    /// Ed25519 key from its 32-byte encoding — a JWK's decoded `x`
    /// (RFC 8037 §2).
    pub fn ed25519FromBytes(bytes: [32]u8) KeyError!Key {
        const pk = Ed25519.PublicKey.fromBytes(bytes) catch return error.InvalidKey;
        return .{ .ed25519 = pk };
    }

    /// RSA key from big-endian modulus + public-exponent bytes — exactly a
    /// JWK's decoded `n`/`e` (RFC 7518 §6.3.1); leading zero bytes are
    /// tolerated on both. Accepts the common 2048/3072/4096-bit modulus
    /// sizes and rejects everything else as `InvalidKey`: zero/empty or
    /// odd-sized or oversized modulus, and (via std's checks, which mirror
    /// what TLS accepts) an even exponent, e < 3, or e ≥ 2^32.
    pub fn rsaFromModExp(n: []const u8, e: []const u8) KeyError!Key {
        const n_bytes = std.mem.trimStart(u8, n, &.{0});
        const e_bytes = std.mem.trimStart(u8, e, &.{0});
        if (n_bytes.len == 0 or e_bytes.len == 0) return error.InvalidKey;
        // std validates: modulus ≥ 512 bits (and ≤ 4096 by construction),
        // exponent odd, in [3, 2^32). Anything off → InvalidKey.
        const pk = cert_rsa.PublicKey.fromBytes(e_bytes, n_bytes) catch
            return error.InvalidKey;
        // k = the modulus octet length = the required signature length.
        const k = (pk.n.bits() + 7) / 8;
        switch (k) {
            256, 384, 512 => {},
            else => return error.InvalidKey,
        }
        return .{ .rsa = .{ .inner = pk, .modulus_len = k } };
    }
};

/// Errors from `verify`. Signature/key bytes never panic — every failure
/// shape maps to one of these.
pub const VerifyError = error{
    /// `alg: "none"` — always rejected, key or no key (RFC 8725 §2.1).
    UnsecuredToken,
    /// The token's `alg` does not match the provided key's type (e.g. an
    /// HS256 token offered an EC/Ed public key, or ES256 vs a P-384 key).
    AlgKeyMismatch,
    /// `alg` is unrecognized, or recognized but not implemented here
    /// (PS* — RSA-PSS; ES512 — std.crypto has no P-521).
    UnsupportedAlg,
    /// The signature has the wrong length for the alg, or does not verify
    /// over `signing_input`.
    BadSignature,
    /// The key itself is unusable (e.g. an empty HMAC secret).
    InvalidKey,
};

/// Verify `parsed.signature` over `parsed.signing_input` with `key`
/// (RFC 7515 §5.2). Constant-time comparison for HMAC; JWS ECDSA signatures
/// are the raw fixed-width `R‖S` concatenation (RFC 7518 §3.4), NOT DER.
///
/// This checks the signature ONLY — pair it with `validateClaims` (or use
/// `parseAndVerify`, which chains parse → verify → validateClaims).
pub fn verify(parsed: *const ParsedToken, key: Key) VerifyError!void {
    switch (parsed.alg) {
        .none => return error.UnsecuredToken,
        .unknown => return error.UnsupportedAlg,
        // PS* needs RSA-PSS; ES512 needs P-521 (not in std).
        .PS256, .PS384, .PS512, .ES512 => return error.UnsupportedAlg,
        .HS256 => try verifyHmac(hmac_sha2.HmacSha256, parsed, key),
        .HS384 => try verifyHmac(hmac_sha2.HmacSha384, parsed, key),
        .HS512 => try verifyHmac(hmac_sha2.HmacSha512, parsed, key),
        .RS256 => try verifyRsaPkcs1(sha2.Sha256, parsed, key),
        .RS384 => try verifyRsaPkcs1(sha2.Sha384, parsed, key),
        .RS512 => try verifyRsaPkcs1(sha2.Sha512, parsed, key),
        .ES256 => switch (key) {
            .ecdsa_p256 => |pk| try verifyEcdsa(EcdsaP256Sha256, pk, parsed),
            else => return error.AlgKeyMismatch,
        },
        .ES384 => switch (key) {
            .ecdsa_p384 => |pk| try verifyEcdsa(EcdsaP384Sha384, pk, parsed),
            else => return error.AlgKeyMismatch,
        },
        .EdDSA => switch (key) {
            .ed25519 => |pk| {
                if (parsed.signature.len != Ed25519.Signature.encoded_length)
                    return error.BadSignature;
                const sig: Ed25519.Signature = .fromBytes(parsed.signature[0..Ed25519.Signature.encoded_length].*);
                sig.verify(parsed.signing_input, pk) catch return error.BadSignature;
            },
            else => return error.AlgKeyMismatch,
        },
    }
}

/// Errors from the one-call `parseAndVerify`.
pub const ParseAndVerifyError = ParseError || VerifyError || ValidateError;

/// The one-call API: parse (P1) → verify signature (P2) → validate claims
/// (P1). Returns the token only when ALL THREE pass; on any failure the
/// partially built token is freed and the typed error returned. Order
/// matters: the signature is checked before any claim is trusted.
pub fn parseAndVerify(
    gpa: std.mem.Allocator,
    token: []const u8,
    key: Key,
    claim_opts: Options,
) ParseAndVerifyError!ParsedToken {
    var parsed = try parse(gpa, token);
    errdefer parsed.deinit();
    try verify(&parsed, key);
    try validateClaims(parsed.claims, claim_opts);
    return parsed;
}

/// HS256/384/512: recompute the MAC over the signing input and compare in
/// constant time (std.crypto.timing_safe — never std.mem.eql on a MAC).
fn verifyHmac(comptime Mac: type, parsed: *const ParsedToken, key: Key) VerifyError!void {
    const secret = switch (key) {
        .hmac => |s| s,
        else => return error.AlgKeyMismatch,
    };
    // An empty secret would make every attacker-computable MAC "valid".
    if (secret.len == 0) return error.InvalidKey;
    // Length is public information — checking it early leaks nothing.
    if (parsed.signature.len != Mac.mac_length) return error.BadSignature;
    var expected: [Mac.mac_length]u8 = undefined;
    Mac.create(&expected, parsed.signing_input, secret);
    if (!std.crypto.timing_safe.eql(
        [Mac.mac_length]u8,
        expected,
        parsed.signature[0..Mac.mac_length].*,
    )) return error.BadSignature;
}

/// ES256/ES384: the JWS signature is the raw fixed-width big-endian `R‖S`
/// (32+32 for P-256, 48+48 for P-384; RFC 7518 §3.4) — `Signature.fromBytes`
/// takes exactly that layout. Any crypto-level rejection (non-canonical
/// scalar, identity element, mismatch) is `BadSignature`.
fn verifyEcdsa(comptime Scheme: type, public_key: Scheme.PublicKey, parsed: *const ParsedToken) VerifyError!void {
    const sig_len = Scheme.Signature.encoded_length;
    if (parsed.signature.len != sig_len) return error.BadSignature;
    const sig: Scheme.Signature = .fromBytes(parsed.signature[0..sig_len].*);
    sig.verify(parsed.signing_input, public_key) catch return error.BadSignature;
}

/// RS256/384/512: RSASSA-PKCS1-v1_5 (RFC 8017 §8.2.2) via std —
/// `s^e mod n` (std.crypto.ff modexp), then the full EMSA-PKCS1-v1_5
/// check (`0x00 01 FF…FF 00 || DigestInfo(hash)`) against the SHA-2
/// digest of `signing_input`. The signature must be exactly the modulus
/// length (RFC 7518 §3.3); anything else — wrong length, s ≥ n, bad
/// padding, wrong hash OID, digest mismatch — is `BadSignature`.
fn verifyRsaPkcs1(comptime Hash: type, parsed: *const ParsedToken, key: Key) VerifyError!void {
    const pk = switch (key) {
        .rsa => |k| k,
        else => return error.AlgKeyMismatch,
    };
    if (parsed.signature.len != pk.modulus_len) return error.BadSignature;
    switch (pk.modulus_len) {
        inline 256, 384, 512 => |k_len| {
            cert_rsa.PKCS1v1_5Signature.verify(
                k_len,
                parsed.signature[0..k_len].*,
                parsed.signing_input,
                pk.inner,
                Hash,
            ) catch return error.BadSignature;
        },
        // A hand-assembled RsaPublicKey with a modulus_len the constructor
        // never produces: refuse rather than trust it.
        else => return error.InvalidKey,
    }
}

// ── internals ───────────────────────────────────────────────────────────────

/// base64url-decode (URL alphabet, NO padding — RFC 7515 §2) into the arena.
fn decodeSegment(arena: std.mem.Allocator, seg: []const u8) ParseError![]u8 {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const n = decoder.calcSizeForSlice(seg) catch return error.InvalidBase64;
    const buf = try arena.alloc(u8, n);
    decoder.decode(buf, seg) catch return error.InvalidBase64;
    return buf;
}

/// Parse `bytes` as JSON and require a top-level object.
fn parseJsonObject(arena: std.mem.Allocator, bytes: []const u8) ParseError!std.json.Value {
    const val = std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{}) catch |err|
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidJson,
        };
    if (val != .object) return error.NotAnObject;
    return val;
}

/// Optional member that, when present, must be a JSON string.
fn optionalString(obj: std.json.ObjectMap, name: []const u8) ParseError!?[]const u8 {
    const v = obj.get(name) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => error.InvalidClaim,
    };
}

/// Optional NumericDate member (RFC 7519 §2): a JSON number, seconds since
/// epoch; a fractional value is truncated toward zero.
fn optionalNumericDate(obj: std.json.ObjectMap, name: []const u8) ParseError!?i64 {
    const v = obj.get(name) orelse return null;
    switch (v) {
        .integer => |i| return i,
        .float => |f| {
            // Guard @intFromFloat: reject NaN/inf and anything outside i64.
            if (!std.math.isFinite(f)) return error.InvalidClaim;
            if (f < -9223372036854775808.0 or f >= 9223372036854775808.0) return error.InvalidClaim;
            return @intFromFloat(@trunc(f));
        },
        else => return error.InvalidClaim,
    }
}

/// `aud` per RFC 7519 §4.1.3: absent | string | array-of-strings.
fn extractAudience(arena: std.mem.Allocator, obj: std.json.ObjectMap) ParseError!Audience {
    const v = obj.get("aud") orelse return .none;
    switch (v) {
        .string => |s| return .{ .single = s },
        .array => |arr| {
            const list = try arena.alloc([]const u8, arr.items.len);
            for (arr.items, list) |item, *slot| {
                switch (item) {
                    .string => |s| slot.* = s,
                    else => return error.InvalidClaim,
                }
            }
            return .{ .many = list };
        },
        else => return error.InvalidClaim,
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// RFC 7519 §3.1 example JWT (also RFC 7515 §A.1):
/// header  {"typ":"JWT",\r\n "alg":"HS256"}
/// payload {"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}
const rfc7519_example_token =
    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" ++
    "." ++
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" ++
    "." ++
    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// Build `b64url(header).b64url(payload).b64url("test-signature")` for tests.
fn buildToken(buf: []u8, header_json: []const u8, payload_json: []const u8) []const u8 {
    const enc = std.base64.url_safe_no_pad.Encoder;
    var w: usize = 0;
    w += enc.encode(buf[w..], header_json).len;
    buf[w] = '.';
    w += 1;
    w += enc.encode(buf[w..], payload_json).len;
    buf[w] = '.';
    w += 1;
    w += enc.encode(buf[w..], "test-signature").len;
    return buf[0..w];
}

test "RFC 7519 example: header, claims, custom claim, signing input, signature" {
    var parsed = try parse(testing.allocator, rfc7519_example_token);
    defer parsed.deinit();

    try testing.expectEqualStrings("HS256", parsed.header.alg);
    try testing.expectEqual(Alg.HS256, parsed.alg);
    try testing.expectEqualStrings("JWT", parsed.header.typ.?);
    try testing.expect(parsed.header.kid == null);
    try testing.expect(parsed.header.cty == null);

    try testing.expectEqualStrings("joe", parsed.claims.iss.?);
    try testing.expectEqual(@as(i64, 1300819380), parsed.claims.exp.?);
    try testing.expect(parsed.claims.nbf == null);
    try testing.expect(parsed.claims.aud == .none);
    try testing.expectEqual(true, parsed.claims.claimBool("http://example.com/is_root").?);
    try testing.expect(parsed.claims.claim("nope") == null);

    // Signing input = the token up to (excluding) the last dot.
    const last_dot = std.mem.lastIndexOfScalar(u8, rfc7519_example_token, '.').?;
    try testing.expectEqualStrings(rfc7519_example_token[0..last_dot], parsed.signing_input);

    // HS256 signature is 32 raw bytes; base64url round-trips to the segment.
    try testing.expectEqual(@as(usize, 32), parsed.signature.len);
    var b64buf: [64]u8 = undefined;
    const reencoded = std.base64.url_safe_no_pad.Encoder.encode(&b64buf, parsed.signature);
    try testing.expectEqualStrings(rfc7519_example_token[last_dot + 1 ..], reencoded);
}

test "parse result does not borrow the input token" {
    const gpa = testing.allocator;
    const token_copy = try gpa.dupe(u8, rfc7519_example_token);
    var parsed = try parse(gpa, token_copy);
    defer parsed.deinit();
    gpa.free(token_copy); // must be safe: ParsedToken owns copies
    try testing.expectEqualStrings("joe", parsed.claims.iss.?);
    try testing.expect(std.mem.startsWith(u8, parsed.signing_input, "eyJ0eXAi"));
}

test "aud as a single string" {
    var buf: [512]u8 = undefined;
    const token = buildToken(&buf,
        \\{"alg":"RS256","typ":"JWT","kid":"k1"}
    ,
        \\{"iss":"https://issuer.example","sub":"user-1","aud":"api://svc","exp":1000,"jti":"id-1"}
    );
    var parsed = try parse(testing.allocator, token);
    defer parsed.deinit();

    try testing.expectEqual(Alg.RS256, parsed.alg);
    try testing.expectEqualStrings("k1", parsed.header.kid.?);
    try testing.expectEqualStrings("user-1", parsed.claims.sub.?);
    try testing.expectEqualStrings("id-1", parsed.claims.jti.?);
    try testing.expectEqualStrings("api://svc", parsed.claims.aud.single);
    try testing.expect(parsed.claims.aud.contains("api://svc"));
    try testing.expect(!parsed.claims.aud.contains("api://other"));
}

test "aud as an array: membership" {
    var buf: [512]u8 = undefined;
    const token = buildToken(&buf,
        \\{"alg":"ES256"}
    ,
        \\{"aud":["api://a","api://b"],"exp":1000}
    );
    var parsed = try parse(testing.allocator, token);
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 2), parsed.claims.aud.many.len);
    try testing.expect(parsed.claims.aud.contains("api://a"));
    try testing.expect(parsed.claims.aud.contains("api://b"));
    try testing.expect(!parsed.claims.aud.contains("api://c"));
}

test "custom claims: claimStr / claimInt / claimBool getters" {
    var buf: [512]u8 = undefined;
    const token = buildToken(&buf,
        \\{"alg":"HS256"}
    ,
        \\{"exp":1000,"scope":"read write","level":42,"admin":false}
    );
    var parsed = try parse(testing.allocator, token);
    defer parsed.deinit();

    try testing.expectEqualStrings("read write", parsed.claims.claimStr("scope").?);
    try testing.expectEqual(@as(i64, 42), parsed.claims.claimInt("level").?);
    try testing.expectEqual(false, parsed.claims.claimBool("admin").?);
    // Wrong-type getters return null rather than lying.
    try testing.expect(parsed.claims.claimStr("level") == null);
    try testing.expect(parsed.claims.claimInt("scope") == null);
    try testing.expect(parsed.claims.claimBool("scope") == null);
}

test "NumericDate: fractional exp truncates; unknown and none algs; empty signature" {
    var buf: [512]u8 = undefined;
    const token = buildToken(&buf,
        \\{"alg":"XS999"}
    ,
        \\{"exp":1300819380.75,"nbf":100.5,"iat":50}
    );
    var parsed = try parse(testing.allocator, token);
    defer parsed.deinit();
    try testing.expectEqual(Alg.unknown, parsed.alg);
    try testing.expectEqualStrings("XS999", parsed.header.alg);
    try testing.expectEqual(@as(i64, 1300819380), parsed.claims.exp.?);
    try testing.expectEqual(@as(i64, 100), parsed.claims.nbf.?);
    try testing.expectEqual(@as(i64, 50), parsed.claims.iat.?);

    // Unsecured JWT (RFC 7519 §6): alg "none", empty third segment. Parses;
    // Part 2's verify is what rejects it.
    const unsecured = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UifQ.";
    var p2 = try parse(testing.allocator, unsecured);
    defer p2.deinit();
    try testing.expectEqual(Alg.none, p2.alg);
    try testing.expectEqual(@as(usize, 0), p2.signature.len);
}

test "validateClaims: expired, and leeway lets a just-expired token pass" {
    var buf: [512]u8 = undefined;
    const token = buildToken(&buf,
        \\{"alg":"HS256"}
    ,
        \\{"exp":1000}
    );
    var parsed = try parse(testing.allocator, token);
    defer parsed.deinit();

    // Well past exp + leeway.
    try testing.expectError(error.Expired, validateClaims(parsed.claims, .{
        .now_s = 1061,
        .leeway_s = 60,
    }));
    // Just expired but inside the leeway window.
    try validateClaims(parsed.claims, .{ .now_s = 1030, .leeway_s = 60 });
    // Exactly at the edge (exp + leeway == now) is still acceptable.
    try validateClaims(parsed.claims, .{ .now_s = 1060, .leeway_s = 60 });
    // Zero leeway: one second past exp fails.
    try testing.expectError(error.Expired, validateClaims(parsed.claims, .{
        .now_s = 1001,
        .leeway_s = 0,
    }));
}

test "validateClaims: nbf in the future, leeway window" {
    var buf: [512]u8 = undefined;
    const token = buildToken(&buf,
        \\{"alg":"HS256"}
    ,
        \\{"exp":100000,"nbf":5000}
    );
    var parsed = try parse(testing.allocator, token);
    defer parsed.deinit();

    try testing.expectError(error.NotYetValid, validateClaims(parsed.claims, .{
        .now_s = 4000,
        .leeway_s = 60,
    }));
    // Inside leeway of nbf: acceptable.
    try validateClaims(parsed.claims, .{ .now_s = 4950, .leeway_s = 60 });
    try validateClaims(parsed.claims, .{ .now_s = 6000, .leeway_s = 60 });
}

test "validateClaims: iat in the future (lenient by default, opt-in reject)" {
    var buf: [512]u8 = undefined;
    const token = buildToken(&buf,
        \\{"alg":"HS256"}
    ,
        \\{"exp":100000,"iat":5000}
    );
    var parsed = try parse(testing.allocator, token);
    defer parsed.deinit();

    // Default: future iat tolerated.
    try validateClaims(parsed.claims, .{ .now_s = 1000 });
    // Opt-in strictness.
    try testing.expectError(error.IssuedInFuture, validateClaims(parsed.claims, .{
        .now_s = 1000,
        .reject_future_iat = true,
    }));
    try validateClaims(parsed.claims, .{
        .now_s = 4950,
        .leeway_s = 60,
        .reject_future_iat = true,
    });
}

test "validateClaims: issuer match, mismatch, and missing iss" {
    var buf: [512]u8 = undefined;
    const token = buildToken(&buf,
        \\{"alg":"HS256"}
    ,
        \\{"exp":100000,"iss":"https://issuer.example"}
    );
    var parsed = try parse(testing.allocator, token);
    defer parsed.deinit();

    try validateClaims(parsed.claims, .{ .now_s = 1000, .issuer = "https://issuer.example" });
    try testing.expectError(error.IssuerMismatch, validateClaims(parsed.claims, .{
        .now_s = 1000,
        .issuer = "https://evil.example",
    }));

    // Token with no iss at all: requiring an issuer must fail.
    var buf2: [512]u8 = undefined;
    const no_iss = buildToken(&buf2,
        \\{"alg":"HS256"}
    ,
        \\{"exp":100000}
    );
    var parsed2 = try parse(testing.allocator, no_iss);
    defer parsed2.deinit();
    try testing.expectError(error.IssuerMismatch, validateClaims(parsed2.claims, .{
        .now_s = 1000,
        .issuer = "https://issuer.example",
    }));
}

test "validateClaims: audience string + array membership, mismatch, missing aud" {
    var buf: [512]u8 = undefined;
    const single = buildToken(&buf,
        \\{"alg":"HS256"}
    ,
        \\{"exp":100000,"aud":"api://svc"}
    );
    var p1 = try parse(testing.allocator, single);
    defer p1.deinit();
    try validateClaims(p1.claims, .{ .now_s = 1000, .audience = "api://svc" });
    try testing.expectError(error.AudienceMismatch, validateClaims(p1.claims, .{
        .now_s = 1000,
        .audience = "api://other",
    }));

    var buf2: [512]u8 = undefined;
    const many = buildToken(&buf2,
        \\{"alg":"HS256"}
    ,
        \\{"exp":100000,"aud":["api://a","api://b"]}
    );
    var p2 = try parse(testing.allocator, many);
    defer p2.deinit();
    try validateClaims(p2.claims, .{ .now_s = 1000, .audience = "api://b" });
    try testing.expectError(error.AudienceMismatch, validateClaims(p2.claims, .{
        .now_s = 1000,
        .audience = "api://c",
    }));

    var buf3: [512]u8 = undefined;
    const no_aud = buildToken(&buf3,
        \\{"alg":"HS256"}
    ,
        \\{"exp":100000}
    );
    var p3 = try parse(testing.allocator, no_aud);
    defer p3.deinit();
    try testing.expectError(error.AudienceMismatch, validateClaims(p3.claims, .{
        .now_s = 1000,
        .audience = "api://svc",
    }));
}

test "validateClaims: missing exp vs require_exp" {
    var buf: [512]u8 = undefined;
    const token = buildToken(&buf,
        \\{"alg":"HS256"}
    ,
        \\{"iss":"joe"}
    );
    var parsed = try parse(testing.allocator, token);
    defer parsed.deinit();

    try testing.expectError(error.MissingExp, validateClaims(parsed.claims, .{ .now_s = 1000 }));
    try validateClaims(parsed.claims, .{ .now_s = 1000, .require_exp = false });
}

test "validateClaims: RFC 7519 example token against its own exp" {
    var parsed = try parse(testing.allocator, rfc7519_example_token);
    defer parsed.deinit();
    // Just before exp: fine (with issuer pinned).
    try validateClaims(parsed.claims, .{ .now_s = 1300819380 - 100, .issuer = "joe" });
    // Past exp + leeway: expired.
    try testing.expectError(error.Expired, validateClaims(parsed.claims, .{
        .now_s = 1300819380 + 61,
    }));
}

test "validateClaims: saturating arithmetic at the i64 extremes" {
    var buf: [512]u8 = undefined;
    const token = buildToken(&buf,
        \\{"alg":"HS256"}
    ,
        \\{"exp":9223372036854775807,"nbf":-9223372036854775808}
    );
    var parsed = try parse(testing.allocator, token);
    defer parsed.deinit();
    // exp +| leeway and nbf -| leeway must not overflow.
    try validateClaims(parsed.claims, .{ .now_s = 0, .leeway_s = 60 });
}

test "malformed: segment count, empty segments" {
    const gpa = testing.allocator;
    // 1, 2 and 4 segments.
    try testing.expectError(error.MalformedToken, parse(gpa, "eyJhbGciOiJIUzI1NiJ9"));
    try testing.expectError(error.MalformedToken, parse(gpa, "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UifQ"));
    try testing.expectError(error.MalformedToken, parse(gpa, "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UifQ.c2ln.extra"));
    // Empty header / payload segments.
    try testing.expectError(error.MalformedToken, parse(gpa, ".eyJpc3MiOiJqb2UifQ.c2ln"));
    try testing.expectError(error.MalformedToken, parse(gpa, "eyJhbGciOiJIUzI1NiJ9..c2ln"));
    try testing.expectError(error.MalformedToken, parse(gpa, ""));
    try testing.expectError(error.MalformedToken, parse(gpa, "."));
}

test "malformed: bad base64url" {
    const gpa = testing.allocator;
    // '!' is outside the URL-safe alphabet.
    try testing.expectError(error.InvalidBase64, parse(gpa, "e!Jh.eyJpc3MiOiJqb2UifQ.c2ln"));
    // '+' and '/' belong to the STANDARD alphabet, not base64url.
    try testing.expectError(error.InvalidBase64, parse(gpa, "eyJh+GciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UifQ.c2ln"));
    // Padding is forbidden in compact serialization.
    try testing.expectError(error.InvalidBase64, parse(gpa, "eyJhbGciOiJIUzI1NiJ9=.eyJpc3MiOiJqb2UifQ.c2ln"));
    // len % 4 == 1 is never a valid base64 length.
    try testing.expectError(error.InvalidBase64, parse(gpa, "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UifQ.c"));
}

test "malformed: non-JSON and non-object header/payload, missing alg" {
    const gpa = testing.allocator;
    var buf: [512]u8 = undefined;

    // Header decodes but is not JSON.
    try testing.expectError(error.InvalidJson, parse(gpa, buildToken(&buf, "not json at all",
        \\{"iss":"joe"}
    )));
    // Header is valid JSON but not an object.
    try testing.expectError(error.NotAnObject, parse(gpa, buildToken(&buf, "[1,2,3]",
        \\{"iss":"joe"}
    )));
    // Payload not an object.
    try testing.expectError(error.NotAnObject, parse(gpa, buildToken(&buf,
        \\{"alg":"HS256"}
    , "\"just a string\"")));
    // Missing alg, and alg of the wrong type.
    try testing.expectError(error.MissingAlg, parse(gpa, buildToken(&buf,
        \\{"typ":"JWT"}
    ,
        \\{"iss":"joe"}
    )));
    try testing.expectError(error.MissingAlg, parse(gpa, buildToken(&buf,
        \\{"alg":123}
    ,
        \\{"iss":"joe"}
    )));
}

test "malformed: wrong-typed registered claims are rejected" {
    const gpa = testing.allocator;
    var buf: [512]u8 = undefined;

    try testing.expectError(error.InvalidClaim, parse(gpa, buildToken(&buf,
        \\{"alg":"HS256"}
    ,
        \\{"exp":"1300819380"}
    )));
    try testing.expectError(error.InvalidClaim, parse(gpa, buildToken(&buf,
        \\{"alg":"HS256"}
    ,
        \\{"iss":123}
    )));
    try testing.expectError(error.InvalidClaim, parse(gpa, buildToken(&buf,
        \\{"alg":"HS256"}
    ,
        \\{"aud":123}
    )));
    try testing.expectError(error.InvalidClaim, parse(gpa, buildToken(&buf,
        \\{"alg":"HS256"}
    ,
        \\{"aud":["ok",42]}
    )));
    try testing.expectError(error.InvalidClaim, parse(gpa, buildToken(&buf,
        \\{"alg":"HS256","kid":42}
    ,
        \\{"iss":"joe"}
    )));
}

test "garbage sweep: arbitrary bytes never panic" {
    const gpa = testing.allocator;

    const fixed = [_][]const u8{
        ".",                                          "..",                         "...",   "....",
        "a",                                          "a.b",                        "a.b.c", "!!!.@@@.###",
        "\x00\x01.\x02\x03.\x04",                     "\xff\xfe\xfd.\xfc\xfb.\xfa", " . . ", "=.=.=",
        "à.é.î",
        "🔑.🔒.🔓",
        "eyJhbGciOiJIUzI1NiJ9.\x00\x00\x00\x00.c2ln",
    };
    for (fixed) |g| {
        if (parse(gpa, g)) |p| {
            var owned = p;
            owned.deinit();
            return error.TestUnexpectedResult; // none of these is a valid JWT
        } else |_| {} // any typed error is fine; the point is: no panic
    }

    // Deterministic pseudo-random byte soup, dots sprinkled in so the
    // splitter also gets exercised.
    var prng = std.Random.DefaultPrng.init(0x6a77745f70310000); // "jwt_p1"
    const random = prng.random();
    var buf: [96]u8 = undefined;
    var i: usize = 0;
    while (i < 512) : (i += 1) {
        const len = random.intRangeAtMost(usize, 0, buf.len);
        const soup = buf[0..len];
        random.bytes(soup);
        for (soup) |*b| {
            if (random.intRangeAtMost(u8, 0, 9) == 0) b.* = '.';
        }
        if (parse(gpa, soup)) |p| {
            var owned = p;
            owned.deinit(); // astronomically unlikely, but must not leak
        } else |_| {}
    }
}

// ── tests: signature verification (Part 2) ──────────────────────────────────

/// base64url-decode a test constant into `buf` (test-only; asserts validity).
fn b64uDecode(buf: []u8, s: []const u8) []const u8 {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const n = decoder.calcSizeForSlice(s) catch unreachable;
    decoder.decode(buf[0..n], s) catch unreachable;
    return buf[0..n];
}

/// Encode `b64url(header) '.' b64url(payload)` into `buf`; returns the
/// signing-input slice. Sign it, then call `finishToken`.
fn signingInputInto(buf: []u8, header_json: []const u8, payload_json: []const u8) []const u8 {
    const enc = std.base64.url_safe_no_pad.Encoder;
    var w: usize = 0;
    w += enc.encode(buf[w..], header_json).len;
    buf[w] = '.';
    w += 1;
    w += enc.encode(buf[w..], payload_json).len;
    return buf[0..w];
}

/// Append `'.' b64url(sig)` after the signing input already in `buf`.
fn finishToken(buf: []u8, signing_input_len: usize, sig: []const u8) []const u8 {
    const enc = std.base64.url_safe_no_pad.Encoder;
    buf[signing_input_len] = '.';
    const n = enc.encode(buf[signing_input_len + 1 ..], sig).len;
    return buf[0 .. signing_input_len + 1 + n];
}

/// RFC 7515 §A.1.1 HMAC key (the JWK's `k` member, base64url).
const rfc7515_a1_hmac_key_b64 =
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

test "verify: RFC 7515 A.1 HS256 known-answer token" {
    var key_buf: [64]u8 = undefined;
    const secret = b64uDecode(&key_buf, rfc7515_a1_hmac_key_b64);
    const key: Key = .{ .hmac = secret };

    // The exact RFC token (== rfc7519_example_token) verifies.
    var parsed = try parse(testing.allocator, rfc7519_example_token);
    defer parsed.deinit();
    try verify(&parsed, key);

    // Wrong secret → BadSignature.
    try testing.expectError(error.BadSignature, verify(&parsed, .{ .hmac = "wrong-secret" }));

    // One flipped signature byte → BadSignature (flip a mid-signature base64
    // char so the segment stays valid base64url).
    var tampered_buf: [256]u8 = undefined;
    const tampered = tampered_buf[0..rfc7519_example_token.len];
    @memcpy(tampered, rfc7519_example_token);
    const last_dot = std.mem.lastIndexOfScalar(u8, tampered, '.').?;
    tampered[last_dot + 5] = if (tampered[last_dot + 5] == 'A') 'B' else 'A';
    var p_tampered = try parse(testing.allocator, tampered);
    defer p_tampered.deinit();
    try testing.expectError(error.BadSignature, verify(&p_tampered, key));

    // Truncated signature (wrong length for HS256) → BadSignature.
    const truncated = rfc7519_example_token[0 .. rfc7519_example_token.len - 8];
    var p_trunc = try parse(testing.allocator, truncated);
    defer p_trunc.deinit();
    try testing.expectError(error.BadSignature, verify(&p_trunc, key));
}

test "verify: RFC 7515 A.3 ES256 known-answer token" {
    // RFC 7515 §A.3.1 public key (JWK x/y) and §A.3.1/§A.3.3 token.
    var x_buf: [32]u8 = undefined;
    var y_buf: [32]u8 = undefined;
    _ = b64uDecode(&x_buf, "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU");
    _ = b64uDecode(&y_buf, "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0");
    const key = try Key.ecdsaP256FromCoords(x_buf, y_buf);

    const token =
        "eyJhbGciOiJFUzI1NiJ9" ++
        "." ++
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" ++
        "." ++
        "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
    var parsed = try parse(testing.allocator, token);
    defer parsed.deinit();
    try testing.expectEqual(Alg.ES256, parsed.alg);
    try verify(&parsed, key);

    // Same signature over a tampered payload → BadSignature.
    var buf: [512]u8 = undefined;
    var sig_buf: [64]u8 = undefined;
    const si = signingInputInto(&buf,
        \\{"alg":"ES256"}
    ,
        \\{"iss":"mallory","exp":1300819380}
    );
    const forged = finishToken(&buf, si.len, b64uDecode(&sig_buf, "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"));
    var p_forged = try parse(testing.allocator, forged);
    defer p_forged.deinit();
    try testing.expectError(error.BadSignature, verify(&p_forged, key));
}

test "verify: RFC 8037 A.4 Ed25519 known-answer signature" {
    // RFC 8037's JWS payload is the plain string "Example of Ed25519
    // signing" — not a JSON claims object — so it cannot go through
    // `parse`; exercise `verify` directly on a hand-built ParsedToken
    // (verify only reads alg/signing_input/signature).
    var x_buf: [32]u8 = undefined;
    _ = b64uDecode(&x_buf, "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
    const key = try Key.ed25519FromBytes(x_buf);

    var sig_buf: [64]u8 = undefined;
    const sig = b64uDecode(&sig_buf, "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg");
    const signing_input = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";

    var kat: ParsedToken = .{
        .header = .{ .alg = "EdDSA" },
        .claims = .{ .raw = .null },
        .signing_input = signing_input,
        .signature = sig,
        .alg = .EdDSA,
        .arena = undefined, // never deinit'd; verify does not touch it
    };
    try verify(&kat, key);

    // Flip one signature byte → BadSignature.
    sig_buf[7] ^= 0x01;
    try testing.expectError(error.BadSignature, verify(&kat, key));
    sig_buf[7] ^= 0x01;
    // Flip the signing input instead → BadSignature.
    kat.signing_input = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmd";
    try testing.expectError(error.BadSignature, verify(&kat, key));
}

test "verify: HS384/HS512 round-trip, cross-length rejection" {
    const secret = "another-shared-secret-of-decent-length";

    inline for (.{
        .{ hmac_sha2.HmacSha384, "HS384" },
        .{ hmac_sha2.HmacSha512, "HS512" },
    }) |case| {
        const Mac = case[0];
        var buf: [512]u8 = undefined;
        const si = signingInputInto(&buf, "{\"alg\":\"" ++ case[1] ++ "\"}",
            \\{"exp":1000,"iss":"joe"}
        );
        var mac: [Mac.mac_length]u8 = undefined;
        Mac.create(&mac, si, secret);
        const token = finishToken(&buf, si.len, &mac);

        var parsed = try parse(testing.allocator, token);
        defer parsed.deinit();
        try verify(&parsed, .{ .hmac = secret });
        try testing.expectError(error.BadSignature, verify(&parsed, .{ .hmac = "not-it" }));
        // Empty HMAC secret is never usable.
        try testing.expectError(error.InvalidKey, verify(&parsed, .{ .hmac = "" }));
    }

    // An HS384-length MAC on an HS512 token is a length mismatch.
    var buf: [512]u8 = undefined;
    const si = signingInputInto(&buf,
        \\{"alg":"HS512"}
    ,
        \\{"exp":1000}
    );
    var mac384: [hmac_sha2.HmacSha384.mac_length]u8 = undefined;
    hmac_sha2.HmacSha384.create(&mac384, si, secret);
    const token = finishToken(&buf, si.len, &mac384);
    var parsed = try parse(testing.allocator, token);
    defer parsed.deinit();
    try testing.expectError(error.BadSignature, verify(&parsed, .{ .hmac = secret }));
}

test "verify: ES256/ES384 generated round-trip, tampering" {
    inline for (.{
        .{ EcdsaP256Sha256, "ES256", Alg.ES256 },
        .{ EcdsaP384Sha384, "ES384", Alg.ES384 },
    }) |case| {
        const Scheme = case[0];
        const kp = try Scheme.KeyPair.generateDeterministic(
            [_]u8{0x42} ** Scheme.KeyPair.seed_length,
        );
        // Wrap via the coords constructor — the same path P4's JWK takes.
        const sec1 = kp.public_key.toUncompressedSec1();
        const fe_len = (sec1.len - 1) / 2;
        const key = if (fe_len == 32)
            try Key.ecdsaP256FromCoords(sec1[1..33].*, sec1[33..65].*)
        else
            try Key.ecdsaP384FromCoords(sec1[1..49].*, sec1[49..97].*);

        var buf: [512]u8 = undefined;
        const si = signingInputInto(&buf, "{\"alg\":\"" ++ case[1] ++ "\"}",
            \\{"exp":1000,"iss":"joe","scope":"read"}
        );
        const sig = try kp.sign(si, null);
        const sig_bytes = sig.toBytes(); // raw fixed-width R‖S — JWS layout
        const token = finishToken(&buf, si.len, &sig_bytes);

        var parsed = try parse(testing.allocator, token);
        defer parsed.deinit();
        try testing.expectEqual(case[2], parsed.alg);
        try verify(&parsed, key);

        // Same signature over a different payload → BadSignature.
        var buf2: [512]u8 = undefined;
        const si2 = signingInputInto(&buf2, "{\"alg\":\"" ++ case[1] ++ "\"}",
            \\{"exp":1000,"iss":"joe","scope":"admin"}
        );
        const forged = finishToken(&buf2, si2.len, &sig_bytes);
        var p_forged = try parse(testing.allocator, forged);
        defer p_forged.deinit();
        try testing.expectError(error.BadSignature, verify(&p_forged, key));

        // Corrupted signature byte → BadSignature.
        var bad_sig = sig_bytes;
        bad_sig[10] ^= 0x01;
        var buf3: [512]u8 = undefined;
        const si3 = signingInputInto(&buf3, "{\"alg\":\"" ++ case[1] ++ "\"}",
            \\{"exp":1000,"iss":"joe","scope":"read"}
        );
        const corrupted = finishToken(&buf3, si3.len, &bad_sig);
        var p_corrupted = try parse(testing.allocator, corrupted);
        defer p_corrupted.deinit();
        try testing.expectError(error.BadSignature, verify(&p_corrupted, key));

        // A different keypair's key → BadSignature.
        const other = try Scheme.KeyPair.generateDeterministic(
            [_]u8{0x43} ** Scheme.KeyPair.seed_length,
        );
        const other_key = switch (Scheme) {
            EcdsaP256Sha256 => Key{ .ecdsa_p256 = other.public_key },
            EcdsaP384Sha384 => Key{ .ecdsa_p384 = other.public_key },
            else => unreachable,
        };
        try testing.expectError(error.BadSignature, verify(&parsed, other_key));
    }
}

test "verify: EdDSA generated round-trip through a full token" {
    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x24} ** 32);
    const key = try Key.ed25519FromBytes(kp.public_key.toBytes());

    var buf: [512]u8 = undefined;
    const si = signingInputInto(&buf,
        \\{"alg":"EdDSA"}
    ,
        \\{"exp":1000,"sub":"user-1"}
    );
    const sig = try kp.sign(si, null);
    const sig_bytes = sig.toBytes();
    const token = finishToken(&buf, si.len, &sig_bytes);

    var parsed = try parse(testing.allocator, token);
    defer parsed.deinit();
    try testing.expectEqual(Alg.EdDSA, parsed.alg);
    try verify(&parsed, key);

    // Tampered payload under the same signature → BadSignature.
    var buf2: [512]u8 = undefined;
    const si2 = signingInputInto(&buf2,
        \\{"alg":"EdDSA"}
    ,
        \\{"exp":1000,"sub":"user-2"}
    );
    const forged = finishToken(&buf2, si2.len, &sig_bytes);
    var p_forged = try parse(testing.allocator, forged);
    defer p_forged.deinit();
    try testing.expectError(error.BadSignature, verify(&p_forged, key));

    // A different keypair's public key → BadSignature.
    const other = try Ed25519.KeyPair.generateDeterministic([_]u8{0x25} ** 32);
    try testing.expectError(error.BadSignature, verify(&parsed, .{ .ed25519 = other.public_key }));
}

test "verify: alg none is always rejected, key or no key (RFC 8725 §2.1)" {
    const unsecured = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UifQ.";
    var parsed = try parse(testing.allocator, unsecured);
    defer parsed.deinit();

    try testing.expectError(error.UnsecuredToken, verify(&parsed, .{ .hmac = "secret" }));
    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{7} ** 32);
    try testing.expectError(error.UnsecuredToken, verify(&parsed, .{ .ed25519 = kp.public_key }));
}

test "verify: alg confusion — token alg must match the key type" {
    const ed_kp = try Ed25519.KeyPair.generateDeterministic([_]u8{9} ** 32);
    const ec256_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic([_]u8{9} ** 32);
    const ec384_kp = try EcdsaP384Sha384.KeyPair.generateDeterministic([_]u8{9} ** 48);

    // The RFC 8725 §2.1 downgrade: attacker takes a server that holds an
    // asymmetric PUBLIC key, mints an HS256 token HMAC'd with those public
    // key bytes. The tag check must refuse before any MAC math happens.
    const pub_bytes = ed_kp.public_key.toBytes();
    var buf: [512]u8 = undefined;
    const si = signingInputInto(&buf,
        \\{"alg":"HS256"}
    ,
        \\{"exp":1000,"admin":true}
    );
    var mac: [32]u8 = undefined;
    hmac_sha2.HmacSha256.create(&mac, si, &pub_bytes);
    const hs_token = finishToken(&buf, si.len, &mac);
    var hs_parsed = try parse(testing.allocator, hs_token);
    defer hs_parsed.deinit();
    try testing.expectError(error.AlgKeyMismatch, verify(&hs_parsed, .{ .ed25519 = ed_kp.public_key }));
    try testing.expectError(error.AlgKeyMismatch, verify(&hs_parsed, .{ .ecdsa_p256 = ec256_kp.public_key }));
    try testing.expectError(error.AlgKeyMismatch, verify(&hs_parsed, .{ .ecdsa_p384 = ec384_kp.public_key }));

    // Asymmetric algs offered an HMAC key (or the wrong curve) also refuse.
    var buf2: [512]u8 = undefined;
    inline for (.{ "ES256", "ES384", "EdDSA" }) |alg_name| {
        const si2 = signingInputInto(&buf2, "{\"alg\":\"" ++ alg_name ++ "\"}",
            \\{"exp":1000}
        );
        const t = finishToken(&buf2, si2.len, "dummy-signature-bytes");
        var p = try parse(testing.allocator, t);
        defer p.deinit();
        try testing.expectError(error.AlgKeyMismatch, verify(&p, .{ .hmac = "secret" }));
    }
    // Right family, wrong curve.
    const si3 = signingInputInto(&buf2,
        \\{"alg":"ES256"}
    ,
        \\{"exp":1000}
    );
    const es_token = finishToken(&buf2, si3.len, "dummy-signature-bytes");
    var es_parsed = try parse(testing.allocator, es_token);
    defer es_parsed.deinit();
    try testing.expectError(error.AlgKeyMismatch, verify(&es_parsed, .{ .ecdsa_p384 = ec384_kp.public_key }));
    try testing.expectError(error.AlgKeyMismatch, verify(&es_parsed, .{ .ed25519 = ed_kp.public_key }));
}

test "verify: unknown and not-yet-supported algs → UnsupportedAlg" {
    var buf: [512]u8 = undefined;
    inline for (.{ "XS999", "PS256", "PS512", "ES512" }) |alg_name| {
        const si = signingInputInto(&buf, "{\"alg\":\"" ++ alg_name ++ "\"}",
            \\{"exp":1000}
        );
        const token = finishToken(&buf, si.len, "some-signature");
        var parsed = try parse(testing.allocator, token);
        defer parsed.deinit();
        try testing.expectError(error.UnsupportedAlg, verify(&parsed, .{ .hmac = "secret" }));
    }
}

test "verify: wrong-length or garbage signatures never panic" {
    const ec_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic([_]u8{1} ** 32);
    const ed_kp = try Ed25519.KeyPair.generateDeterministic([_]u8{1} ** 32);
    const ec_key: Key = .{ .ecdsa_p256 = ec_kp.public_key };
    const ed_key: Key = .{ .ed25519 = ed_kp.public_key };

    var buf: [512]u8 = undefined;
    // Truncated (63), oversized (65), empty, and garbage-but-right-length
    // (64) signatures for ES256; same lengths against EdDSA.
    inline for (.{ "ES256", "EdDSA" }) |alg_name| {
        const key = if (comptime std.mem.eql(u8, alg_name, "ES256")) ec_key else ed_key;
        inline for (.{ 0, 1, 63, 65, 96, 128 }) |bad_len| {
            const si = signingInputInto(&buf, "{\"alg\":\"" ++ alg_name ++ "\"}",
                \\{"exp":1000}
            );
            const token = finishToken(&buf, si.len, &([_]u8{0xAB} ** bad_len));
            var parsed = try parse(testing.allocator, token);
            defer parsed.deinit();
            try testing.expectError(error.BadSignature, verify(&parsed, key));
        }
        // Right length, arbitrary bytes: rejected, not a panic.
        const si = signingInputInto(&buf, "{\"alg\":\"" ++ alg_name ++ "\"}",
            \\{"exp":1000}
        );
        const token = finishToken(&buf, si.len, &([_]u8{0xAB} ** 64));
        var parsed = try parse(testing.allocator, token);
        defer parsed.deinit();
        try testing.expectError(error.BadSignature, verify(&parsed, key));
    }

    // ES384 with an ES256-length signature.
    const si = signingInputInto(&buf,
        \\{"alg":"ES384"}
    ,
        \\{"exp":1000}
    );
    const token = finishToken(&buf, si.len, &([_]u8{0xCD} ** 64));
    var parsed = try parse(testing.allocator, token);
    defer parsed.deinit();
    const ec384_kp = try EcdsaP384Sha384.KeyPair.generateDeterministic([_]u8{1} ** 48);
    try testing.expectError(error.BadSignature, verify(&parsed, .{ .ecdsa_p384 = ec384_kp.public_key }));
}

test "Key constructors: invalid key bytes → InvalidKey, never a panic" {
    // (0,0) is not on P-256/P-384 (b != 0), and all-0xFF exceeds the field.
    try testing.expectError(error.InvalidKey, Key.ecdsaP256FromCoords([_]u8{0} ** 32, [_]u8{0} ** 32));
    try testing.expectError(error.InvalidKey, Key.ecdsaP256FromCoords([_]u8{0xFF} ** 32, [_]u8{0xFF} ** 32));
    try testing.expectError(error.InvalidKey, Key.ecdsaP384FromCoords([_]u8{0} ** 48, [_]u8{0} ** 48));
    try testing.expectError(error.InvalidKey, Key.ecdsaP384FromCoords([_]u8{0xFF} ** 48, [_]u8{0xFF} ** 48));
    // Non-canonical Ed25519 encoding.
    try testing.expectError(error.InvalidKey, Key.ed25519FromBytes([_]u8{0xFF} ** 32));
}

test "parseAndVerify: end-to-end happy path and each failure stage" {
    const gpa = testing.allocator;
    const secret = "shared-secret-for-the-e2e-test";

    var buf: [512]u8 = undefined;
    const si = signingInputInto(&buf,
        \\{"alg":"HS256"}
    ,
        \\{"iss":"https://issuer.example","aud":"api://svc","exp":2000,"scope":"read write"}
    );
    var mac: [32]u8 = undefined;
    hmac_sha2.HmacSha256.create(&mac, si, secret);
    const token = finishToken(&buf, si.len, &mac);

    // Good token + key + claims → the one call succeeds.
    var verified = try parseAndVerify(gpa, token, .{ .hmac = secret }, .{
        .now_s = 1000,
        .issuer = "https://issuer.example",
        .audience = "api://svc",
    });
    defer verified.deinit();
    try testing.expectEqualStrings("read write", verified.claims.claimStr("scope").?);

    // Bad signature → BadSignature (and no leak — testing.allocator checks).
    try testing.expectError(error.BadSignature, parseAndVerify(
        gpa,
        token,
        .{ .hmac = "wrong" },
        .{ .now_s = 1000 },
    ));
    // Wrong key type → AlgKeyMismatch.
    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{3} ** 32);
    try testing.expectError(error.AlgKeyMismatch, parseAndVerify(
        gpa,
        token,
        .{ .ed25519 = kp.public_key },
        .{ .now_s = 1000 },
    ));
    // Valid signature but expired claims → Expired.
    try testing.expectError(error.Expired, parseAndVerify(
        gpa,
        token,
        .{ .hmac = secret },
        .{ .now_s = 5000 },
    ));
    // Malformed token → the parse error surfaces unchanged.
    try testing.expectError(error.MalformedToken, parseAndVerify(
        gpa,
        "not-a-token",
        .{ .hmac = secret },
        .{ .now_s = 1000 },
    ));
}

// ── tests: RSA signature verification (Part 3) ──────────────────────────────

/// RFC 7515 §A.2.1 RSA-2048 key, transcribed from the JWK in the RFC
/// (base64url `n` / `e`, plus the private exponent `d` used only by the
/// test-local signer below).
const rfc7515_a2_n_b64 =
    "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp" ++
    "-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOW" ++
    "vG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUs" ++
    "LA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9k" ++
    "G4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2" ++
    "PAcDTW9gb54h4FRWyuXpoQ";
const rfc7515_a2_e_b64 = "AQAB";
const rfc7515_a2_d_b64 =
    "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_G" ++
    "Q5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKV" ++
    "RUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9J" ++
    "YanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoF" ++
    "aFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjn" ++
    "czT0QU91p1DhOVRuOopznQ";

/// RFC 7515 §A.2: header {"alg":"RS256"}, the §A.1 payload, and the
/// RSASSA-PKCS1-v1_5 SHA-256 signature from the RFC.
const rfc7515_a2_token =
    "eyJhbGciOiJSUzI1NiJ9" ++
    "." ++
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" ++
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" ++
    "." ++
    "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7" ++
    "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4" ++
    "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K" ++
    "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv" ++
    "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB" ++
    "p0igcN_IoypGlUPQGe77Rw";

/// Build the RFC A.2 public key via the JWK-shaped constructor.
fn rfc7515A2Key() Key {
    var n_buf: [256]u8 = undefined;
    var e_buf: [8]u8 = undefined;
    return Key.rsaFromModExp(
        b64uDecode(&n_buf, rfc7515_a2_n_b64),
        b64uDecode(&e_buf, rfc7515_a2_e_b64),
    ) catch unreachable;
}

/// Test-only RSASSA-PKCS1-v1_5 signer (RFC 8017 §8.2.1): EMSA-PKCS1-v1_5
/// encode with the SHA-2 DigestInfo prefixes from §9.2 Notes 1, then
/// `em^d mod n` via std.crypto.ff. Only exists so RS384/RS512 (which have
/// no RFC KAT) get real round-trip coverage without leaving std.
fn rsaTestSign(
    comptime Hash: type,
    comptime k: usize,
    signing_input: []const u8,
    n_bytes: []const u8,
    d_bytes: []const u8,
) [k]u8 {
    const digest_info: []const u8 = switch (Hash) {
        sha2.Sha256 => &.{
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
            0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
        },
        sha2.Sha384 => &.{
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
            0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
        },
        sha2.Sha512 => &.{
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
            0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
        },
        else => @compileError("unsupported hash"),
    };
    // EM = 0x00 01 FF…FF 00 || DigestInfo || H(signing_input).
    var em: [k]u8 = undefined;
    const t_len = digest_info.len + Hash.digest_length;
    em[0] = 0x00;
    em[1] = 0x01;
    @memset(em[2 .. k - t_len - 1], 0xFF);
    em[k - t_len - 1] = 0x00;
    @memcpy(em[k - t_len ..][0..digest_info.len], digest_info);
    Hash.hash(signing_input, em[k - Hash.digest_length ..][0..Hash.digest_length], .{});
    // s = em^d mod n.
    const M = std.crypto.ff.Modulus(4096);
    const n = M.fromBytes(n_bytes, .big) catch unreachable;
    const m = M.Fe.fromBytes(n, &em, .big) catch unreachable;
    const s = n.powWithEncodedExponent(m, d_bytes, .big) catch unreachable;
    var sig: [k]u8 = undefined;
    s.toBytes(&sig, .big) catch unreachable;
    return sig;
}

test "verify: RFC 7515 A.2 RS256 known-answer token" {
    const key = rfc7515A2Key();

    // The exact RFC token verifies.
    var parsed = try parse(testing.allocator, rfc7515_a2_token);
    defer parsed.deinit();
    try testing.expectEqual(Alg.RS256, parsed.alg);
    try testing.expectEqual(@as(usize, 256), parsed.signature.len);
    try verify(&parsed, key);

    // One flipped signature byte → BadSignature (swap a mid-signature
    // base64 char so the segment stays valid base64url).
    var tampered_buf: [1024]u8 = undefined;
    const tampered = tampered_buf[0..rfc7515_a2_token.len];
    @memcpy(tampered, rfc7515_a2_token);
    const last_dot = std.mem.lastIndexOfScalar(u8, tampered, '.').?;
    tampered[last_dot + 20] = if (tampered[last_dot + 20] == 'A') 'B' else 'A';
    var p_tampered = try parse(testing.allocator, tampered);
    defer p_tampered.deinit();
    try testing.expectError(error.BadSignature, verify(&p_tampered, key));

    // The same signature over a tampered payload → BadSignature.
    var buf: [1024]u8 = undefined;
    var sig_buf: [256]u8 = undefined;
    const rfc_sig = b64uDecode(&sig_buf, rfc7515_a2_token[last_dot + 1 ..]);
    const si = signingInputInto(&buf,
        \\{"alg":"RS256"}
    ,
        \\{"iss":"mallory","exp":1300819380}
    );
    const forged = finishToken(&buf, si.len, rfc_sig);
    var p_forged = try parse(testing.allocator, forged);
    defer p_forged.deinit();
    try testing.expectError(error.BadSignature, verify(&p_forged, key));
}

test "verify: RS256/RS384/RS512 generated round-trip, tampering, cross-alg" {
    var n_buf: [256]u8 = undefined;
    var d_buf: [256]u8 = undefined;
    const n_bytes = b64uDecode(&n_buf, rfc7515_a2_n_b64);
    const d_bytes = b64uDecode(&d_buf, rfc7515_a2_d_b64);
    const key = rfc7515A2Key();

    inline for (.{
        .{ sha2.Sha256, "RS256", Alg.RS256 },
        .{ sha2.Sha384, "RS384", Alg.RS384 },
        .{ sha2.Sha512, "RS512", Alg.RS512 },
    }) |case| {
        var buf: [1024]u8 = undefined;
        const si = signingInputInto(&buf, "{\"alg\":\"" ++ case[1] ++ "\"}",
            \\{"exp":1000,"iss":"joe","scope":"read"}
        );
        const sig = rsaTestSign(case[0], 256, si, n_bytes, d_bytes);
        const token = finishToken(&buf, si.len, &sig);

        var parsed = try parse(testing.allocator, token);
        defer parsed.deinit();
        try testing.expectEqual(case[2], parsed.alg);
        try verify(&parsed, key);

        // Same signature over a different payload → BadSignature.
        var buf2: [1024]u8 = undefined;
        const si2 = signingInputInto(&buf2, "{\"alg\":\"" ++ case[1] ++ "\"}",
            \\{"exp":1000,"iss":"joe","scope":"admin"}
        );
        const forged = finishToken(&buf2, si2.len, &sig);
        var p_forged = try parse(testing.allocator, forged);
        defer p_forged.deinit();
        try testing.expectError(error.BadSignature, verify(&p_forged, key));

        // Corrupted signature byte → BadSignature.
        var bad_sig = sig;
        bad_sig[100] ^= 0x01;
        var buf3: [1024]u8 = undefined;
        const si3 = signingInputInto(&buf3, "{\"alg\":\"" ++ case[1] ++ "\"}",
            \\{"exp":1000,"iss":"joe","scope":"read"}
        );
        const corrupted = finishToken(&buf3, si3.len, &bad_sig);
        var p_corrupted = try parse(testing.allocator, corrupted);
        defer p_corrupted.deinit();
        try testing.expectError(error.BadSignature, verify(&p_corrupted, key));
    }

    // A signature computed for RS256 presented under an RS512 header —
    // right length, wrong DigestInfo/digest → BadSignature (bad padding).
    var buf: [1024]u8 = undefined;
    const si256 = signingInputInto(&buf,
        \\{"alg":"RS256"}
    ,
        \\{"exp":1000}
    );
    const sig256 = rsaTestSign(sha2.Sha256, 256, si256, n_bytes, d_bytes);
    var buf2: [1024]u8 = undefined;
    const si512 = signingInputInto(&buf2,
        \\{"alg":"RS512"}
    ,
        \\{"exp":1000}
    );
    const cross = finishToken(&buf2, si512.len, &sig256);
    var p_cross = try parse(testing.allocator, cross);
    defer p_cross.deinit();
    try testing.expectError(error.BadSignature, verify(&p_cross, key));
}

test "verify: RSA alg confusion — RS tokens vs non-RSA keys and vice versa" {
    const rsa_key = rfc7515A2Key();

    // The RFC RS256 token offered every non-RSA key type → AlgKeyMismatch.
    var parsed = try parse(testing.allocator, rfc7515_a2_token);
    defer parsed.deinit();
    const ed_kp = try Ed25519.KeyPair.generateDeterministic([_]u8{9} ** 32);
    const ec256_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic([_]u8{9} ** 32);
    const ec384_kp = try EcdsaP384Sha384.KeyPair.generateDeterministic([_]u8{9} ** 48);
    try testing.expectError(error.AlgKeyMismatch, verify(&parsed, .{ .hmac = "secret" }));
    try testing.expectError(error.AlgKeyMismatch, verify(&parsed, .{ .ed25519 = ed_kp.public_key }));
    try testing.expectError(error.AlgKeyMismatch, verify(&parsed, .{ .ecdsa_p256 = ec256_kp.public_key }));
    try testing.expectError(error.AlgKeyMismatch, verify(&parsed, .{ .ecdsa_p384 = ec384_kp.public_key }));

    // Non-RSA tokens offered the RSA key → AlgKeyMismatch (incl. the
    // RFC 8725 downgrade shape: an HS256 token MAC'd with public-key
    // bytes must refuse before any MAC math).
    var buf: [512]u8 = undefined;
    inline for (.{ "HS256", "ES256", "ES384", "EdDSA" }) |alg_name| {
        const si = signingInputInto(&buf, "{\"alg\":\"" ++ alg_name ++ "\"}",
            \\{"exp":1000}
        );
        const t = finishToken(&buf, si.len, "dummy-signature-bytes");
        var p = try parse(testing.allocator, t);
        defer p.deinit();
        try testing.expectError(error.AlgKeyMismatch, verify(&p, rsa_key));
    }

    // alg:none stays UnsecuredToken even with an RSA key.
    const unsecured = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UifQ.";
    var p_none = try parse(testing.allocator, unsecured);
    defer p_none.deinit();
    try testing.expectError(error.UnsecuredToken, verify(&p_none, rsa_key));
}

test "verify: RSA wrong-length and garbage signatures never panic" {
    const key = rfc7515A2Key();

    // Any length ≠ the 256-byte modulus length → BadSignature.
    var buf: [1024]u8 = undefined;
    inline for (.{ 0, 1, 64, 255, 257, 384, 512 }) |bad_len| {
        const si = signingInputInto(&buf,
            \\{"alg":"RS256"}
        ,
            \\{"exp":1000}
        );
        const token = finishToken(&buf, si.len, &([_]u8{0xAB} ** bad_len));
        var parsed = try parse(testing.allocator, token);
        defer parsed.deinit();
        try testing.expectError(error.BadSignature, verify(&parsed, key));
    }

    // Right length, garbage bytes. 0xAB… as an integer exceeds n (top
    // byte 0xa1) → the s ≥ n reject path; 0x00… decrypts to a padding
    // failure. Both are BadSignature, never a panic.
    inline for (.{ 0xAB, 0x00, 0x01 }) |fill| {
        const si = signingInputInto(&buf,
            \\{"alg":"RS256"}
        ,
            \\{"exp":1000}
        );
        const token = finishToken(&buf, si.len, &([_]u8{fill} ** 256));
        var parsed = try parse(testing.allocator, token);
        defer parsed.deinit();
        try testing.expectError(error.BadSignature, verify(&parsed, key));
    }
}

test "Key.rsaFromModExp: invalid modulus/exponent shapes → InvalidKey" {
    var n_buf: [256]u8 = undefined;
    const n_bytes = b64uDecode(&n_buf, rfc7515_a2_n_b64);
    const e_ok = [_]u8{ 0x01, 0x00, 0x01 };

    // Happy path, and leading zeros tolerated on both n and e.
    _ = try Key.rsaFromModExp(n_bytes, &e_ok);
    var padded_n: [258]u8 = undefined;
    padded_n[0] = 0;
    padded_n[1] = 0;
    @memcpy(padded_n[2..], n_bytes);
    const padded_e = [_]u8{ 0x00, 0x01, 0x00, 0x01 };
    _ = try Key.rsaFromModExp(&padded_n, &padded_e);

    // Empty / all-zero modulus or exponent.
    try testing.expectError(error.InvalidKey, Key.rsaFromModExp("", &e_ok));
    try testing.expectError(error.InvalidKey, Key.rsaFromModExp(&([_]u8{0} ** 256), &e_ok));
    try testing.expectError(error.InvalidKey, Key.rsaFromModExp(n_bytes, ""));
    try testing.expectError(error.InvalidKey, Key.rsaFromModExp(n_bytes, &.{ 0, 0 }));

    // Too-small (512-bit), odd-sized (800-bit) and oversized (8192-bit)
    // moduli — only 2048/3072/4096 pass.
    try testing.expectError(error.InvalidKey, Key.rsaFromModExp(&([_]u8{0xFF} ** 64), &e_ok));
    try testing.expectError(error.InvalidKey, Key.rsaFromModExp(&([_]u8{0xFF} ** 100), &e_ok));
    try testing.expectError(error.InvalidKey, Key.rsaFromModExp(&([_]u8{0xFF} ** 1024), &e_ok));

    // Even modulus (an RSA modulus is a product of odd primes).
    var even_n: [256]u8 = undefined;
    @memcpy(&even_n, n_bytes);
    even_n[255] &= 0xFE;
    try testing.expectError(error.InvalidKey, Key.rsaFromModExp(&even_n, &e_ok));

    // Bad exponents: even, too small, ≥ 2^32.
    try testing.expectError(error.InvalidKey, Key.rsaFromModExp(n_bytes, &.{0x04}));
    try testing.expectError(error.InvalidKey, Key.rsaFromModExp(n_bytes, &.{0x01}));
    try testing.expectError(error.InvalidKey, Key.rsaFromModExp(n_bytes, &.{ 0x01, 0x00, 0x00, 0x00, 0x01 }));
}

test "parseAndVerify: RS256 end-to-end" {
    const gpa = testing.allocator;
    var n_buf: [256]u8 = undefined;
    var d_buf: [256]u8 = undefined;
    const n_bytes = b64uDecode(&n_buf, rfc7515_a2_n_b64);
    const d_bytes = b64uDecode(&d_buf, rfc7515_a2_d_b64);
    const key = rfc7515A2Key();

    var buf: [1024]u8 = undefined;
    const si = signingInputInto(&buf,
        \\{"alg":"RS256"}
    ,
        \\{"iss":"https://issuer.example","aud":"api://svc","exp":2000,"scope":"read"}
    );
    const sig = rsaTestSign(sha2.Sha256, 256, si, n_bytes, d_bytes);
    const token = finishToken(&buf, si.len, &sig);

    var verified = try parseAndVerify(gpa, token, key, .{
        .now_s = 1000,
        .issuer = "https://issuer.example",
        .audience = "api://svc",
    });
    defer verified.deinit();
    try testing.expectEqualStrings("read", verified.claims.claimStr("scope").?);

    // Valid signature but expired → Expired (and no leak on the way out).
    try testing.expectError(error.Expired, parseAndVerify(gpa, token, key, .{ .now_s = 5000 }));
    // Wrong key type → AlgKeyMismatch.
    try testing.expectError(error.AlgKeyMismatch, parseAndVerify(
        gpa,
        token,
        .{ .hmac = "secret" },
        .{ .now_s = 1000 },
    ));
    // RFC KAT through the one-call API (its exp is long past → Expired
    // proves the signature check passed first and claims ran).
    try testing.expectError(error.Expired, parseAndVerify(
        gpa,
        rfc7515_a2_token,
        key,
        .{ .now_s = 1600000000 },
    ));
}
