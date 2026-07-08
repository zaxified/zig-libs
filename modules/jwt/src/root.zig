// SPDX-License-Identifier: MIT

//! jwt — JWT/JWS validator for OAuth2/OIDC resource servers
//! (RFC 7515 compact JWS serialization + RFC 7519 JWT claims + RFC 7518
//! JWA signature algorithms).
//!
//! Scope so far: compact-token **parsing** into typed models (P1),
//! **registered-claims validation** (`exp`/`nbf`/`iat`/`iss`/`aud`, P1),
//! **JWS signature verification** (P2+P3) for HS256/384/512 (HMAC-SHA-2),
//! ES256/ES384 (ECDSA P-256/P-384), EdDSA (Ed25519) and RS256/384/512
//! (RSASSA-PKCS1-v1_5, the OIDC default) — plus the one-call
//! `parseAndVerify` that chains all three — and **JWKS key sets** (P4,
//! RFC 7517): parse a `{"keys":[…]}` document into a typed `JwkSet`,
//! select the key by the token header's `kid`, and verify via
//! `verifyWithJwks` / `parseVerifyJwks` — plus the **networked layer** (P5):
//! OpenID Connect Discovery 1.0 (`discover` resolves
//! `<issuer>/.well-known/openid-configuration` to the issuer's `jwks_uri`),
//! `fetchJwks`, and the cached `Provider` (TTL + key-rotation refresh with a
//! `min_refresh_interval_s` rate limit) whose `Provider.verify` is the
//! turnkey resource-server call. All I/O goes through the `Fetcher` seam
//! ("GET this URL, give me status + body"), so everything stays
//! offline-testable; `HttpFetcher` adapts our `http.Client` for real use.
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
//! Planned parts: P6 resource-server middleware (wrapping `Provider.verify`).
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
//! // The networked turnkey path (P5): one Provider per issuer, JWKS
//! // fetched via OIDC discovery, cached, refreshed on key rotation.
//! var threaded = std.Io.Threaded.init(gpa, .{});
//! var client = http.Client.init(threaded.io(), gpa, .{});
//! var hf: jwt.HttpFetcher = .{ .client = &client };
//! var provider = jwt.Provider.init(gpa, hf.fetcher(), .{
//!     .issuer = "https://issuer.example",
//! });
//! defer provider.deinit();
//! var t = try provider.verify(gpa, bearer_token, now_seconds, .{
//!     .audience = "api://my-service", // issuer is enforced automatically
//! });
//! defer t.deinit();
//!
//! // With a JWKS you already hold (fully offline):
//! var jwks = try jwt.parseJwks(gpa, jwks_json);
//! defer jwks.deinit();
//! var token2 = try jwt.parseVerifyJwks(gpa, bearer_token, jwks, .{
//!     .now_s = now_seconds,
//!     .issuer = "https://issuer.example",
//! });
//! defer token2.deinit();
//!
//! // Or step by step (e.g. pick the key from the header's `kid` first):
//! var parsed = try jwt.parse(gpa, bearer_token);
//! defer parsed.deinit();
//! const jwk = jwks.selectKey(parsed.header) orelse return error.NoMatchingKey;
//! try jwt.verify(&parsed, jwk.key);
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
const http = @import("http");

pub const meta = .{
    .status = .gap,
    .platform = .any, // pure logic over the Fetcher seam; HttpFetcher uses `http`
    .role = .util, // P6 adds the resource-server middleware on top.
    .concurrency = .reentrant, // except Provider — one mutable cache, external sync
    .model_after = "RFC 7515 (JWS) + RFC 7519 (JWT) + RFC 7518 (JWA) verify incl. RS256 (RSASSA-PKCS1-v1_5, RFC 8017) + RFC 7517 (JWK/JWKS key sets), RFC 8725 hardening + OpenID Connect Discovery 1.0 / RFC 8414 (issuer metadata -> jwks_uri) with cached, rotation-aware Provider; OAuth2/OIDC resource server",
    // ramcache is wired in build.zig for P6; P5 keeps the *parsed* JwkSet in
    // the Provider (no raw-byte cache — see Provider docs).
    .deps = .{"http"},
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
    /// JWKS resolution failed (`verifyWithJwks`/`parseVerifyJwks` only):
    /// no JWK matches the token's `kid`, none of the matches is usable for
    /// signature verification (`use:"enc"`, pinned `alg` disagreeing with
    /// the token's), or the token has no `kid` and the set does not contain
    /// exactly one usable key.
    NoMatchingKey,
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

// ── JWKS key sets (Part 4, RFC 7517) ────────────────────────────────────────

/// Errors from `parseJwks`. Anything wrong with an *individual* JWK inside
/// a well-formed set is NOT an error — that key is skipped and recorded in
/// `JwkSet.skipped` (a JWKS routinely contains keys a verifier does not
/// use, RFC 7517 §5).
pub const JwksError = error{
    /// The document is not valid JSON.
    InvalidJson,
    /// Valid JSON, but not a JSON object with a `keys` array (RFC 7517 §5).
    NotAJwks,
    OutOfMemory,
};

/// The `use` (Public Key Use) member, RFC 7517 §4.2. `other` covers any
/// value besides `sig`/`enc` — such keys are never selected for signature
/// verification (fail closed on semantics we do not know).
pub const KeyUse = enum { sig, enc, other };

/// Why a JWK inside a set was skipped rather than converted to a `Key`.
pub const JwkSkipReason = enum {
    /// The `keys` array element is not a JSON object.
    not_an_object,
    /// `kty` is absent (it is the only REQUIRED member, RFC 7517 §4.1).
    missing_kty,
    /// `kty` is none of RSA / EC / OKP / oct.
    unsupported_kty,
    /// EC/OKP without the `crv` member.
    missing_crv,
    /// `crv` names a curve this module does not support (P-521, X25519, …).
    unsupported_crv,
    /// A required key-material member (`n`/`e`, `x`/`y`, `k`) is absent or
    /// not a JSON string.
    missing_member,
    /// Key material is not valid base64url-without-padding.
    invalid_base64,
    /// Material decoded but is not a valid key: wrong coordinate length,
    /// point not on the curve, bad modulus/exponent, empty `oct` secret.
    invalid_key,
    /// A metadata member (`kid`/`use`/`alg`/`kty`/`crv`) has the wrong
    /// JSON type.
    invalid_member,
};

/// Record of one skipped JWK: its index in the original `keys` array plus
/// the reason. Present so operators can log *why* a key was dropped instead
/// of silently shrinking the set.
pub const SkippedJwk = struct {
    index: usize,
    reason: JwkSkipReason,
};

/// One usable key from a JWKS: the converted `Key` plus the selection
/// metadata (RFC 7517 §4). Slices point into the owning `JwkSet`'s arena.
pub const Jwk = struct {
    key: Key,
    /// `kid` (§4.5) — matched against the token header's `kid`.
    kid: ?[]const u8 = null,
    /// `use` (§4.2) — `enc`/`other` keys are never selected for signature
    /// verification.
    use: ?KeyUse = null,
    /// `alg` (§4.4) — when present the JWK is pinned to that algorithm and
    /// is only selected for tokens with exactly that `alg`.
    alg: ?Alg = null,
};

/// What key selection hands back: a pointer into `JwkSet.keys`, valid until
/// the set's `deinit`. `resolved.key` goes straight into `verify`.
pub const ResolvedKey = *const Jwk;

/// A parsed JWK Set (RFC 7517 §5). Everything it references lives in its
/// internal arena; call `deinit()` when done. Immutable after parse —
/// share freely across threads (the module-wide reentrancy rule).
pub const JwkSet = struct {
    /// The usable keys, in document order.
    keys: []const Jwk,
    /// JWKs that could not be used, with reasons (see `JwkSkipReason`).
    skipped: []const SkippedJwk,

    arena: *std.heap.ArenaAllocator,

    pub fn deinit(self: *JwkSet) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
        self.* = undefined;
    }

    /// First key with this `kid` that is usable for signature verification
    /// (`use` absent or `"sig"`). No alg check — use `selectKey` when you
    /// have the token header.
    pub fn keyForKid(self: *const JwkSet, kid: []const u8) ?ResolvedKey {
        for (self.keys) |*jwk| {
            if (!usableForSig(jwk)) continue;
            const jwk_kid = jwk.kid orelse continue;
            if (std.mem.eql(u8, jwk_kid, kid)) return jwk;
        }
        return null;
    }

    /// Select the verification key for a token header (RFC 7517 §4.5 spirit):
    ///
    /// - Token has a `kid` → the first key matching that `kid` which is
    ///   usable for signatures (`use` absent or `"sig"`) and whose pinned
    ///   `alg` (if any) equals the token's `alg`.
    /// - Token has no `kid` → only an unambiguous set resolves: exactly one
    ///   sig-usable key (whose `alg` pin, if any, must also match). More
    ///   than one candidate → null; guessing among keys is not verification.
    ///
    /// Selection cannot smuggle a mismatched key past the RFC 8725 checks:
    /// whatever this returns still goes through `verify`, which enforces
    /// that the key *type* matches the token's `alg`.
    pub fn selectKey(self: *const JwkSet, header: Header) ?ResolvedKey {
        const token_alg = Alg.fromString(header.alg);
        if (header.kid) |kid| {
            for (self.keys) |*jwk| {
                if (!usableForSig(jwk)) continue;
                const jwk_kid = jwk.kid orelse continue;
                if (!std.mem.eql(u8, jwk_kid, kid)) continue;
                if (jwk.alg) |pinned| {
                    if (pinned != token_alg) continue;
                }
                return jwk;
            }
            return null;
        }
        var found: ?ResolvedKey = null;
        for (self.keys) |*jwk| {
            if (!usableForSig(jwk)) continue;
            if (found != null) return null; // ambiguous — refuse to guess
            found = jwk;
        }
        const jwk = found orelse return null;
        if (jwk.alg) |pinned| {
            if (pinned != token_alg) return null;
        }
        return jwk;
    }

    fn usableForSig(jwk: *const Jwk) bool {
        const use = jwk.use orelse return true;
        return use == .sig;
    }
};

/// Parse a JWKS document (`{"keys":[{JWK},…]}`, RFC 7517 §5) into a typed
/// `JwkSet`. Supported key types (RFC 7518 §6 / RFC 8037 §2 parameters):
///
/// - `kty:"RSA"` — `n`/`e` → `Key.rsaFromModExp` (for RS256/384/512).
/// - `kty:"EC"`, `crv:"P-256"|"P-384"` — `x`/`y` →
///   `ecdsaP256FromCoords`/`ecdsaP384FromCoords` (ES256/ES384).
/// - `kty:"OKP"`, `crv:"Ed25519"` — `x` → `ed25519FromBytes` (EdDSA).
/// - `kty:"oct"` — `k` → `.hmac`. Parsed for completeness (HS* dev/test
///   setups); a *symmetric* key has no business in a *published* JWKS —
///   anyone who can read it can mint tokens.
///
/// Individual JWKs that are malformed or unsupported are skipped and
/// recorded in `skipped` — a set-wide error is returned only when the
/// document itself is not a JWKS. Arbitrary bytes never panic.
pub fn parseJwks(gpa: std.mem.Allocator, json: []const u8) JwksError!JwkSet {
    const arena_state = try gpa.create(std.heap.ArenaAllocator);
    errdefer gpa.destroy(arena_state);
    arena_state.* = .init(gpa);
    errdefer arena_state.deinit();
    const arena = arena_state.allocator();

    const val = std.json.parseFromSliceLeaky(std.json.Value, arena, json, .{}) catch |err|
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidJson,
        };
    if (val != .object) return error.NotAJwks;
    const keys_val = val.object.get("keys") orelse return error.NotAJwks;
    if (keys_val != .array) return error.NotAJwks;

    var keys: std.ArrayList(Jwk) = .empty;
    var skipped: std.ArrayList(SkippedJwk) = .empty;
    for (keys_val.array.items, 0..) |item, i| {
        const jwk = jwkFromValue(arena, item) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |reason| {
                try skipped.append(arena, .{ .index = i, .reason = skipReason(reason) });
                continue;
            },
        };
        try keys.append(arena, jwk);
    }

    return .{
        .keys = try keys.toOwnedSlice(arena),
        .skipped = try skipped.toOwnedSlice(arena),
        .arena = arena_state,
    };
}

/// Verify `parsed`'s signature against a JWKS: resolve the key via
/// `JwkSet.selectKey` (kid + `use`/`alg` constraints), then run the
/// existing `verify` — all its RFC 8725 hardening (alg/key-type match,
/// `none` rejection) applies unchanged. No usable key → `NoMatchingKey`.
pub fn verifyWithJwks(parsed: *const ParsedToken, jwks: JwkSet) VerifyError!void {
    const jwk = jwks.selectKey(parsed.header) orelse return error.NoMatchingKey;
    try verify(parsed, jwk.key);
}

/// The one-call JWKS API: parse (P1) → resolve key + verify signature (P4)
/// → validate claims (P1). Same contract as `parseAndVerify`, with the key
/// picked from the set by the token's `kid`.
pub fn parseVerifyJwks(
    gpa: std.mem.Allocator,
    token: []const u8,
    jwks: JwkSet,
    claim_opts: Options,
) ParseAndVerifyError!ParsedToken {
    var parsed = try parse(gpa, token);
    errdefer parsed.deinit();
    try verifyWithJwks(&parsed, jwks);
    try validateClaims(parsed.claims, claim_opts);
    return parsed;
}

/// Per-JWK conversion failures — mapped 1:1 onto `JwkSkipReason` by the
/// `parseJwks` loop (only OutOfMemory propagates).
const JwkFailure = error{
    NotAnObject,
    MissingKty,
    UnsupportedKty,
    MissingCrv,
    UnsupportedCrv,
    MissingMember,
    InvalidBase64,
    InvalidKeyMaterial,
    InvalidMember,
};

fn skipReason(err: JwkFailure) JwkSkipReason {
    return switch (err) {
        error.NotAnObject => .not_an_object,
        error.MissingKty => .missing_kty,
        error.UnsupportedKty => .unsupported_kty,
        error.MissingCrv => .missing_crv,
        error.UnsupportedCrv => .unsupported_crv,
        error.MissingMember => .missing_member,
        error.InvalidBase64 => .invalid_base64,
        error.InvalidKeyMaterial => .invalid_key,
        error.InvalidMember => .invalid_member,
    };
}

/// Convert one `keys` array element into a `Jwk` (RFC 7517 §4 members +
/// RFC 7518 §6 / RFC 8037 §2 key material).
fn jwkFromValue(
    arena: std.mem.Allocator,
    val: std.json.Value,
) (JwkFailure || error{OutOfMemory})!Jwk {
    if (val != .object) return error.NotAnObject;
    const obj = val.object;

    const key: Key = blk: {
        const kty = (try jwkString(obj, "kty")) orelse return error.MissingKty;
        if (std.mem.eql(u8, kty, "RSA")) {
            // RFC 7518 §6.3.1: n, e as base64url big-endian integers.
            const n = try jwkMaterial(arena, obj, "n");
            const e = try jwkMaterial(arena, obj, "e");
            break :blk Key.rsaFromModExp(n, e) catch return error.InvalidKeyMaterial;
        }
        if (std.mem.eql(u8, kty, "EC")) {
            // RFC 7518 §6.2.1: crv + x, y — fixed-width big-endian coords.
            // Curve support is checked *before* touching the material so an
            // unsupported curve reports as such, not as a material error.
            const crv = (try jwkString(obj, "crv")) orelse return error.MissingCrv;
            if (std.mem.eql(u8, crv, "P-256")) {
                const x = try jwkMaterial(arena, obj, "x");
                const y = try jwkMaterial(arena, obj, "y");
                if (x.len != 32 or y.len != 32) return error.InvalidKeyMaterial;
                break :blk Key.ecdsaP256FromCoords(x[0..32].*, y[0..32].*) catch
                    return error.InvalidKeyMaterial;
            }
            if (std.mem.eql(u8, crv, "P-384")) {
                const x = try jwkMaterial(arena, obj, "x");
                const y = try jwkMaterial(arena, obj, "y");
                if (x.len != 48 or y.len != 48) return error.InvalidKeyMaterial;
                break :blk Key.ecdsaP384FromCoords(x[0..48].*, y[0..48].*) catch
                    return error.InvalidKeyMaterial;
            }
            return error.UnsupportedCrv; // P-521: no std P-521 support
        }
        if (std.mem.eql(u8, kty, "OKP")) {
            // RFC 8037 §2: crv + x (the raw public key bytes).
            const crv = (try jwkString(obj, "crv")) orelse return error.MissingCrv;
            if (!std.mem.eql(u8, crv, "Ed25519")) return error.UnsupportedCrv;
            const x = try jwkMaterial(arena, obj, "x");
            if (x.len != 32) return error.InvalidKeyMaterial;
            break :blk Key.ed25519FromBytes(x[0..32].*) catch return error.InvalidKeyMaterial;
        }
        if (std.mem.eql(u8, kty, "oct")) {
            // RFC 7518 §6.4.1: k — the symmetric secret. See parseJwks doc.
            const k = try jwkMaterial(arena, obj, "k");
            if (k.len == 0) return error.InvalidKeyMaterial; // unusable as HMAC secret
            break :blk .{ .hmac = k };
        }
        return error.UnsupportedKty;
    };

    const use: ?KeyUse = blk: {
        const s = (try jwkString(obj, "use")) orelse break :blk null;
        if (std.mem.eql(u8, s, "sig")) break :blk .sig;
        if (std.mem.eql(u8, s, "enc")) break :blk .enc;
        break :blk .other;
    };
    const alg: ?Alg = blk: {
        const s = (try jwkString(obj, "alg")) orelse break :blk null;
        // Unrecognized names pin as .unknown — the token side maps them the
        // same way and verify rejects .unknown, so nothing slips through.
        break :blk Alg.fromString(s);
    };

    return .{
        .key = key,
        .kid = try jwkString(obj, "kid"),
        .use = use,
        .alg = alg,
    };
}

/// Optional JWK member that, when present, must be a JSON string.
fn jwkString(obj: std.json.ObjectMap, name: []const u8) error{InvalidMember}!?[]const u8 {
    const v = obj.get(name) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => error.InvalidMember,
    };
}

/// Required base64url key-material member, decoded into the arena.
fn jwkMaterial(
    arena: std.mem.Allocator,
    obj: std.json.ObjectMap,
    name: []const u8,
) error{ MissingMember, InvalidBase64, OutOfMemory }![]u8 {
    const v = obj.get(name) orelse return error.MissingMember;
    const s = switch (v) {
        .string => |str| str,
        else => return error.MissingMember,
    };
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const n = decoder.calcSizeForSlice(s) catch return error.InvalidBase64;
    const buf = try arena.alloc(u8, n);
    decoder.decode(buf, s) catch return error.InvalidBase64;
    return buf;
}

// ── networked layer (Part 5): discovery + JWKS fetch + cached Provider ──────
// Clean-room from OpenID Connect Discovery 1.0 + RFC 8414 (OAuth 2.0
// Authorization Server Metadata) + RFC 7517 §5. All network I/O goes through
// the `Fetcher` seam so the logic (and every test) is offline; `HttpFetcher`
// is the one real implementation, over our `http.Client`.

/// Module-level alias so `Provider.verify` can reach the signature-check
/// `verify` (the method name shadows it inside the struct namespace).
const verifySignature = verify;

/// Errors a `Fetcher` implementation may return.
pub const FetchError = error{
    /// Connect / TLS / send / receive failed.
    FetchFailed,
    /// The body did not fit the caller's buffer (byte cap). Implementations
    /// MUST return this instead of truncating silently.
    ResponseTooLarge,
};

/// The one I/O operation this module needs: GET `url`, return the HTTP
/// status and the body bytes in `body_buf`. Same seam as the `rdap` sibling.
/// Tests drive it with a scripted fake; production uses `HttpFetcher`.
pub const Fetcher = struct {
    ctx: *anyopaque,
    fetchFn: *const fn (ctx: *anyopaque, url: []const u8, body_buf: []u8) FetchError!Result,

    pub const Result = struct { status: u16, body_len: usize };
    pub const Response = struct { status: u16, body: []const u8 };

    pub fn fetch(f: Fetcher, url: []const u8, body_buf: []u8) FetchError!Response {
        const r = try f.fetchFn(f.ctx, url, body_buf);
        if (r.body_len > body_buf.len) return error.FetchFailed;
        return .{ .status = r.status, .body = body_buf[0..r.body_len] };
    }
};

/// Byte cap for one fetched document (discovery metadata or JWKS). Real
/// provider JWKS documents are a few KiB; 64 KiB is generous headroom while
/// still bounding what an issuer (or a MITM'd DNS answer) can make us buffer.
pub const max_response_bytes: usize = 64 * 1024;

/// Cap for the derived well-known URL (issuer + `well_known_path`).
pub const max_url_len: usize = 2048;

/// OpenID Connect Discovery 1.0 §4: the well-known suffix appended to the
/// issuer URL (also the RFC 8414 §3 path, minus the legacy prefix ordering).
pub const well_known_path = "/.well-known/openid-configuration";

/// `Fetcher` implementation over `http.Client` (GET + JSON Accept header;
/// redirects and HTTPS/TLS are the client's job). Compiled always, dialed
/// never in tests.
pub const HttpFetcher = struct {
    client: *http.Client,

    pub fn fetcher(f: *HttpFetcher) Fetcher {
        return .{ .ctx = f, .fetchFn = fetchFn };
    }

    fn fetchFn(ctx: *anyopaque, url: []const u8, body_buf: []u8) FetchError!Fetcher.Result {
        const f: *HttpFetcher = @ptrCast(@alignCast(ctx));
        var res = f.client.request(.get, url, .{
            .headers = &.{.{ .name = "Accept", .value = "application/json" }},
        }) catch return error.FetchFailed;
        defer res.deinit();

        const n = res.reader().readSliceShort(body_buf) catch return error.FetchFailed;
        if (n == body_buf.len) {
            // Buffer exactly full — distinguish "fit exactly" from "more coming".
            var extra: [1]u8 = undefined;
            const m = res.reader().readSliceShort(&extra) catch return error.FetchFailed;
            if (m != 0) return error.ResponseTooLarge;
        }
        return .{ .status = res.status, .body_len = n };
    }
};

/// Errors from `discover`.
pub const DiscoverError = FetchError || error{
    /// The well-known endpoint answered with a non-200 status.
    HttpStatus,
    /// The response is not a usable discovery document: not JSON, not an
    /// object, `issuer`/`jwks_uri` absent or not strings, the issuer too
    /// long/empty, or a malformed optional member.
    DiscoveryFailed,
    /// The document's `issuer` differs from the one queried — per OIDC
    /// Discovery §4.3 the two MUST be identical (an issuer answering for
    /// another issuer is exactly the mix-up attack the check exists for).
    IssuerMismatch,
    OutOfMemory,
};

/// OIDC provider metadata (OpenID Connect Discovery 1.0 §3 / RFC 8414 §2) —
/// just the members a resource-server validator needs. Everything it
/// references lives in its internal arena; call `deinit()` when done.
pub const Metadata = struct {
    /// The document's `issuer` — what `Provider.verify` enforces as `iss`.
    issuer: []const u8,
    /// Where the issuer publishes its JWKS.
    jwks_uri: []const u8,
    /// Optional `id_token_signing_alg_values_supported`, verbatim.
    id_token_signing_alg_values_supported: ?[]const []const u8 = null,

    arena: *std.heap.ArenaAllocator,

    pub fn deinit(self: *Metadata) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
        self.* = undefined;
    }
};

/// OpenID Connect Discovery 1.0: fetch
/// `<issuer>/.well-known/openid-configuration` and extract the validator's
/// view of the provider metadata. A trailing `/` on `issuer` is tolerated
/// (stripped before deriving the URL and before the issuer comparison —
/// several real IdPs are sloppy about it); otherwise the returned `issuer`
/// must be identical to the requested one (`IssuerMismatch`).
pub fn discover(
    gpa: std.mem.Allocator,
    fetcher: Fetcher,
    issuer: []const u8,
) DiscoverError!Metadata {
    const want_issuer = std.mem.trimEnd(u8, issuer, "/");
    if (want_issuer.len == 0) return error.DiscoveryFailed;
    var url_buf: [max_url_len]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "{s}" ++ well_known_path, .{want_issuer}) catch
        return error.DiscoveryFailed;

    const body_buf = try gpa.alloc(u8, max_response_bytes);
    defer gpa.free(body_buf);
    const res = try fetcher.fetch(url, body_buf);
    if (res.status != 200) return error.HttpStatus;

    const arena_state = try gpa.create(std.heap.ArenaAllocator);
    errdefer gpa.destroy(arena_state);
    arena_state.* = .init(gpa);
    errdefer arena_state.deinit();
    const arena = arena_state.allocator();

    // std.json Value parsing copies every string into the arena
    // (.alloc_always), so nothing below borrows body_buf.
    const val = std.json.parseFromSliceLeaky(std.json.Value, arena, res.body, .{}) catch |err|
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.DiscoveryFailed,
        };
    if (val != .object) return error.DiscoveryFailed;
    const obj = val.object;

    const doc_issuer = stringMember(obj, "issuer") orelse return error.DiscoveryFailed;
    const jwks_uri = stringMember(obj, "jwks_uri") orelse return error.DiscoveryFailed;
    if (!std.mem.eql(u8, std.mem.trimEnd(u8, doc_issuer, "/"), want_issuer))
        return error.IssuerMismatch;

    const algs: ?[]const []const u8 = blk: {
        const v = obj.get("id_token_signing_alg_values_supported") orelse break :blk null;
        if (v != .array) return error.DiscoveryFailed;
        const list = try arena.alloc([]const u8, v.array.items.len);
        for (v.array.items, list) |item, *slot| switch (item) {
            .string => |s| slot.* = s,
            else => return error.DiscoveryFailed,
        };
        break :blk list;
    };

    return .{
        .issuer = doc_issuer,
        .jwks_uri = jwks_uri,
        .id_token_signing_alg_values_supported = algs,
        .arena = arena_state,
    };
}

/// Member that must be a JSON string to count as present (discovery docs).
fn stringMember(obj: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const v = obj.get(name) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

/// Errors from `fetchJwks`: the fetch seam's, a non-200 status, or the P4
/// parse errors (`InvalidJson`/`NotAJwks`) verbatim.
pub const FetchJwksError = FetchError || JwksError || error{HttpStatus};

/// GET `jwks_uri` and parse the body via `parseJwks` (P4). The returned set
/// owns arena copies of everything — the transfer buffer dies here.
pub fn fetchJwks(
    gpa: std.mem.Allocator,
    fetcher: Fetcher,
    jwks_uri: []const u8,
) FetchJwksError!JwkSet {
    const body_buf = try gpa.alloc(u8, max_response_bytes);
    defer gpa.free(body_buf);
    const res = try fetcher.fetch(jwks_uri, body_buf);
    if (res.status != 200) return error.HttpStatus;
    return parseJwks(gpa, res.body);
}

/// Errors from `Provider.refresh`. The two sides of a refresh collapse to
/// one typed error each (the caller of a cached provider can't do anything
/// finer-grained anyway); `discover`/`fetchJwks` keep the detailed sets for
/// callers who drive the steps themselves.
pub const RefreshError = error{
    /// OIDC discovery failed (fetch, status, malformed document, issuer
    /// mismatch) — only for issuer-configured providers.
    DiscoveryFailed,
    /// The JWKS fetch or parse failed.
    JwksFetchFailed,
    OutOfMemory,
};

/// A cached JWKS resolver for ONE issuer — the P5 turnkey type. Configure it
/// with either the `issuer` (JWKS located via OIDC discovery, metadata cached
/// for the provider's lifetime) or a direct `jwks_uri`. `verify` lazily
/// fetches the key set, re-fetches when `ttl_s` has passed, and — when a
/// token names a `kid` the cached set lacks (key rotation) — refreshes at
/// most once per `min_refresh_interval_s`, so a flood of bogus-kid tokens
/// cannot hammer the issuer.
///
/// Design notes:
/// - The *parsed* `JwkSet` is the cache (not raw bytes in `ramcache`): one
///   provider serves one issuer, so there is exactly one entry — a keyed
///   byte cache would only add a re-parse per hit.
/// - No hidden clock: every entry point takes `now_s`, like the rest of the
///   module (and refresh scheduling is therefore deterministic in tests).
/// - Fail closed: a failed TTL/rotation refresh surfaces as its typed error
///   instead of silently serving stale keys forever. (P6 middleware can
///   layer a serve-stale policy on top if wanted.)
/// - NOT thread-safe (`refresh` swaps the set) — one Provider per thread, or
///   external synchronization. Everything else in the module stays reentrant.
pub const Provider = struct {
    gpa: std.mem.Allocator,
    fetcher: Fetcher,
    options: ProviderOptions,
    /// Cached discovery metadata (issuer-configured providers, after the
    /// first refresh).
    metadata: ?Metadata = null,
    /// The current key set; null until the first successful refresh.
    jwks: ?JwkSet = null,
    /// When the current set was fetched (drives `ttl_s`).
    fetched_at_s: i64 = 0,
    /// When a refresh was last *attempted*, success or failure — the
    /// `min_refresh_interval_s` reference point.
    last_attempt_s: ?i64 = null,

    pub const ProviderOptions = struct {
        /// OIDC issuer URL — JWKS located via discovery. Exactly one of
        /// `issuer`/`jwks_uri` should be set; `jwks_uri` wins when both are
        /// (then `issuer` still serves as the expected `iss` for claims).
        issuer: ?[]const u8 = null,
        /// Direct JWKS URL — skips discovery.
        jwks_uri: ?[]const u8 = null,
        /// How long a fetched JWKS is served before `verify` re-fetches.
        ttl_s: u32 = 300,
        /// Floor between two rotation-driven refresh *attempts* (unknown
        /// `kid`), measured from the last attempt of any kind. Lazy-load and
        /// TTL refreshes are not gated — they are already bounded by `ttl_s`.
        min_refresh_interval_s: u32 = 30,
    };

    /// Claim policy for `Provider.verify` — `Options` minus `now_s` (passed
    /// per call) and with `issuer = null` meaning "enforce the discovered /
    /// configured issuer" rather than "don't check".
    pub const ClaimOptions = struct {
        leeway_s: u32 = 60,
        /// Override the expected `iss`. Default: the discovery document's
        /// `issuer` (issuer-configured providers) or `options.issuer`; a
        /// plain jwks_uri-configured provider checks nothing.
        issuer: ?[]const u8 = null,
        audience: ?[]const u8 = null,
        require_exp: bool = true,
        reject_future_iat: bool = false,
    };

    pub const Error = ParseAndVerifyError || RefreshError;

    pub fn init(gpa: std.mem.Allocator, fetcher: Fetcher, options: ProviderOptions) Provider {
        std.debug.assert(options.issuer != null or options.jwks_uri != null);
        return .{ .gpa = gpa, .fetcher = fetcher, .options = options };
    }

    pub fn deinit(p: *Provider) void {
        if (p.metadata) |*m| m.deinit();
        if (p.jwks) |*s| s.deinit();
        p.* = undefined;
    }

    /// Fetch the JWKS now (running discovery first, once, for
    /// issuer-configured providers) and swap it in. Records the attempt for
    /// rate-limiting whether it succeeds or fails; the old set stays in
    /// place on failure.
    pub fn refresh(p: *Provider, now_s: i64) RefreshError!void {
        p.last_attempt_s = now_s;
        const jwks_uri = p.options.jwks_uri orelse blk: {
            if (p.metadata == null) {
                p.metadata = discover(p.gpa, p.fetcher, p.options.issuer.?) catch |err|
                    switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return error.DiscoveryFailed,
                    };
            }
            break :blk p.metadata.?.jwks_uri;
        };
        const fresh = fetchJwks(p.gpa, p.fetcher, jwks_uri) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.JwksFetchFailed,
        };
        if (p.jwks) |*old| old.deinit();
        p.jwks = fresh;
        p.fetched_at_s = now_s;
    }

    /// The turnkey call: ensure the JWKS is loaded and fresh (lazy first
    /// fetch; re-fetch past `ttl_s`), parse the token, resolve its key from
    /// the cached set — refreshing once (rate-limited) when the `kid` is
    /// unknown, i.e. on key rotation — then run the P2-P4 signature check
    /// and `validateClaims` with the issuer injected (see `ClaimOptions`).
    /// Returns the verified token (caller `deinit`s) or a typed error;
    /// nothing about a failed token is trusted.
    pub fn verify(
        p: *Provider,
        gpa: std.mem.Allocator,
        token: []const u8,
        now_s: i64,
        claim_opts: ClaimOptions,
    ) Error!ParsedToken {
        if (p.jwks == null or now_s -| p.fetched_at_s >= @as(i64, p.options.ttl_s)) {
            try p.refresh(now_s);
        }

        var parsed = try parse(gpa, token);
        errdefer parsed.deinit();

        var jwk = p.jwks.?.selectKey(parsed.header);
        if (jwk == null and p.refreshAllowed(now_s)) {
            // Unknown kid — plausibly a rotation we haven't seen. One
            // bounded re-fetch; a bogus-kid flood is absorbed by the rate
            // limit and fails below without touching the network.
            try p.refresh(now_s);
            jwk = p.jwks.?.selectKey(parsed.header);
        }
        const resolved = jwk orelse return error.NoMatchingKey;
        try verifySignature(&parsed, resolved.key);

        const expected_issuer = claim_opts.issuer orelse
            (if (p.metadata) |m| m.issuer else p.options.issuer);
        try validateClaims(parsed.claims, .{
            .now_s = now_s,
            .leeway_s = claim_opts.leeway_s,
            .issuer = expected_issuer,
            .audience = claim_opts.audience,
            .require_exp = claim_opts.require_exp,
            .reject_future_iat = claim_opts.reject_future_iat,
        });
        return parsed;
    }

    fn refreshAllowed(p: *const Provider, now_s: i64) bool {
        const last = p.last_attempt_s orelse return true;
        return now_s -| last >= @as(i64, p.options.min_refresh_interval_s);
    }
};

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

// ── tests: JWKS key sets (Part 4) ────────────────────────────────────────────

/// RFC 7515 §A.3.1 P-256 public-key coordinates (JWK `x`/`y`), reused as
/// JWK members by the P4 tests.
const rfc7515_a3_x_b64 = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
const rfc7515_a3_y_b64 = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

const test_jwks_hmac_secret = "jwks-multi-key-shared-secret";

fn testEs256KeyPair() !EcdsaP256Sha256.KeyPair {
    return EcdsaP256Sha256.KeyPair.generateDeterministic(
        [_]u8{0x42} ** EcdsaP256Sha256.KeyPair.seed_length,
    );
}

fn testEd25519KeyPair() !Ed25519.KeyPair {
    return Ed25519.KeyPair.generateDeterministic([_]u8{0x24} ** 32);
}

/// Build the standard 4-key test JWKS: oct "hs" + EC P-256 "es" +
/// RSA "rs" (the RFC 7515 A.2 modulus) + OKP Ed25519 "ed".
fn testJwksJson(buf: []u8) ![]const u8 {
    const enc = std.base64.url_safe_no_pad.Encoder;
    var k_b64: [64]u8 = undefined;
    var x_b64: [43]u8 = undefined;
    var y_b64: [43]u8 = undefined;
    var ed_b64: [43]u8 = undefined;
    const k_s = enc.encode(&k_b64, test_jwks_hmac_secret);
    const es = try testEs256KeyPair();
    const sec1 = es.public_key.toUncompressedSec1();
    const x_s = enc.encode(&x_b64, sec1[1..33]);
    const y_s = enc.encode(&y_b64, sec1[33..65]);
    const ed = try testEd25519KeyPair();
    const ed_pub = ed.public_key.toBytes();
    const ed_s = enc.encode(&ed_b64, &ed_pub);
    return std.fmt.bufPrint(buf,
        \\{{"keys":[
        \\ {{"kty":"oct","kid":"hs","k":"{s}"}},
        \\ {{"kty":"EC","kid":"es","use":"sig","crv":"P-256","x":"{s}","y":"{s}"}},
        \\ {{"kty":"RSA","kid":"rs","n":"{s}","e":"AQAB"}},
        \\ {{"kty":"OKP","kid":"ed","crv":"Ed25519","x":"{s}"}}
        \\]}}
    , .{ k_s, x_s, y_s, rfc7515_a2_n_b64, ed_s });
}

test "JWKS: RFC 7517 A.1 example set parses into typed keys" {
    // RFC 7517 Appendix A.1 — two public keys: an EC P-256 encryption key
    // and an RSA signature key.
    const jwks_json =
        \\{"keys":
        \\  [
        \\    {"kty":"EC",
        \\     "crv":"P-256",
        \\     "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        \\     "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        \\     "use":"enc",
        \\     "kid":"1"},
        \\    {"kty":"RSA",
        \\     "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        \\     "e":"AQAB",
        \\     "alg":"RS256",
        \\     "kid":"2011-04-29"}
        \\  ]
        \\}
    ;
    var jwks = try parseJwks(testing.allocator, jwks_json);
    defer jwks.deinit();

    try testing.expectEqual(@as(usize, 2), jwks.keys.len);
    try testing.expectEqual(@as(usize, 0), jwks.skipped.len);

    const ec = jwks.keys[0];
    try testing.expect(ec.key == .ecdsa_p256);
    try testing.expectEqualStrings("1", ec.kid.?);
    try testing.expectEqual(KeyUse.enc, ec.use.?);
    try testing.expect(ec.alg == null);

    const rsa = jwks.keys[1];
    try testing.expect(rsa.key == .rsa);
    try testing.expectEqual(@as(usize, 256), rsa.key.rsa.modulus_len);
    try testing.expectEqualStrings("2011-04-29", rsa.kid.?);
    try testing.expectEqual(Alg.RS256, rsa.alg.?);

    // kid lookup honors `use`: the enc key is never offered for signatures.
    try testing.expect(jwks.keyForKid("2011-04-29") != null);
    try testing.expect(jwks.keyForKid("1") == null);
    try testing.expect(jwks.keyForKid("nope") == null);
}

test "JWKS: multi-key set — verifyWithJwks picks the right key by kid" {
    var jwks_buf: [2048]u8 = undefined;
    var jwks = try parseJwks(testing.allocator, try testJwksJson(&jwks_buf));
    defer jwks.deinit();
    try testing.expectEqual(@as(usize, 4), jwks.keys.len);
    try testing.expectEqual(@as(usize, 0), jwks.skipped.len);

    var n_buf: [256]u8 = undefined;
    var d_buf: [256]u8 = undefined;
    const n_bytes = b64uDecode(&n_buf, rfc7515_a2_n_b64);
    const d_bytes = b64uDecode(&d_buf, rfc7515_a2_d_b64);
    const es = try testEs256KeyPair();
    const ed = try testEd25519KeyPair();

    // HS256 by kid "hs".
    {
        var buf: [512]u8 = undefined;
        const si = signingInputInto(&buf,
            \\{"alg":"HS256","kid":"hs"}
        ,
            \\{"exp":1000}
        );
        var mac: [32]u8 = undefined;
        hmac_sha2.HmacSha256.create(&mac, si, test_jwks_hmac_secret);
        const token = finishToken(&buf, si.len, &mac);
        var parsed = try parse(testing.allocator, token);
        defer parsed.deinit();
        try verifyWithJwks(&parsed, jwks);
    }
    // ES256 by kid "es".
    {
        var buf: [512]u8 = undefined;
        const si = signingInputInto(&buf,
            \\{"alg":"ES256","kid":"es"}
        ,
            \\{"exp":1000}
        );
        const sig = try es.sign(si, null);
        const sig_bytes = sig.toBytes();
        const token = finishToken(&buf, si.len, &sig_bytes);
        var parsed = try parse(testing.allocator, token);
        defer parsed.deinit();
        try verifyWithJwks(&parsed, jwks);
    }
    // RS256 by kid "rs".
    {
        var buf: [1024]u8 = undefined;
        const si = signingInputInto(&buf,
            \\{"alg":"RS256","kid":"rs"}
        ,
            \\{"exp":1000}
        );
        const sig = rsaTestSign(sha2.Sha256, 256, si, n_bytes, d_bytes);
        const token = finishToken(&buf, si.len, &sig);
        var parsed = try parse(testing.allocator, token);
        defer parsed.deinit();
        try verifyWithJwks(&parsed, jwks);
    }
    // EdDSA by kid "ed".
    {
        var buf: [512]u8 = undefined;
        const si = signingInputInto(&buf,
            \\{"alg":"EdDSA","kid":"ed"}
        ,
            \\{"exp":1000}
        );
        const sig = try ed.sign(si, null);
        const sig_bytes = sig.toBytes();
        const token = finishToken(&buf, si.len, &sig_bytes);
        var parsed = try parse(testing.allocator, token);
        defer parsed.deinit();
        try verifyWithJwks(&parsed, jwks);
    }
    // A kid nobody published → NoMatchingKey.
    {
        var buf: [512]u8 = undefined;
        const si = signingInputInto(&buf,
            \\{"alg":"HS256","kid":"ghost"}
        ,
            \\{"exp":1000}
        );
        var mac: [32]u8 = undefined;
        hmac_sha2.HmacSha256.create(&mac, si, test_jwks_hmac_secret);
        const token = finishToken(&buf, si.len, &mac);
        var parsed = try parse(testing.allocator, token);
        defer parsed.deinit();
        try testing.expectError(error.NoMatchingKey, verifyWithJwks(&parsed, jwks));
    }
    // keyForKid resolves every published key to the right type.
    try testing.expect(jwks.keyForKid("hs").?.key == .hmac);
    try testing.expect(jwks.keyForKid("es").?.key == .ecdsa_p256);
    try testing.expect(jwks.keyForKid("rs").?.key == .rsa);
    try testing.expect(jwks.keyForKid("ed").?.key == .ed25519);
}

test "JWKS: kid selection cannot smuggle a mismatched key type (RFC 8725)" {
    var jwks_buf: [2048]u8 = undefined;
    var jwks = try parseJwks(testing.allocator, try testJwksJson(&jwks_buf));
    defer jwks.deinit();

    // HS256 token pointing (kid) at the RSA JWK: selection resolves the RSA
    // key, but verify's type check still refuses — the downgrade where an
    // attacker HMACs with public-key bytes stays dead under JWKS.
    var buf: [512]u8 = undefined;
    const si = signingInputInto(&buf,
        \\{"alg":"HS256","kid":"rs"}
    ,
        \\{"exp":1000,"admin":true}
    );
    var mac: [32]u8 = undefined;
    hmac_sha2.HmacSha256.create(&mac, si, "whatever");
    const token = finishToken(&buf, si.len, &mac);
    var parsed = try parse(testing.allocator, token);
    defer parsed.deinit();
    try testing.expectError(error.AlgKeyMismatch, verifyWithJwks(&parsed, jwks));

    // ES256 token pointing at the Ed25519 key: same refusal.
    var buf2: [512]u8 = undefined;
    const si2 = signingInputInto(&buf2,
        \\{"alg":"ES256","kid":"ed"}
    ,
        \\{"exp":1000}
    );
    const token2 = finishToken(&buf2, si2.len, "dummy-signature-bytes");
    var parsed2 = try parse(testing.allocator, token2);
    defer parsed2.deinit();
    try testing.expectError(error.AlgKeyMismatch, verifyWithJwks(&parsed2, jwks));

    // alg:none with a valid kid → still UnsecuredToken, never accepted.
    var buf3: [512]u8 = undefined;
    const si3 = signingInputInto(&buf3,
        \\{"alg":"none","kid":"rs"}
    ,
        \\{"exp":1000}
    );
    const token3 = finishToken(&buf3, si3.len, "");
    var parsed3 = try parse(testing.allocator, token3);
    defer parsed3.deinit();
    try testing.expectError(error.UnsecuredToken, verifyWithJwks(&parsed3, jwks));
}

test "JWKS: token without kid — single usable key resolves, ambiguity refuses" {
    // Single-key set: the RFC 7515 A.1 HMAC key as an oct JWK (no kid on
    // either side) verifies the RFC HS256 token.
    const single = "{\"keys\":[{\"kty\":\"oct\",\"k\":\"" ++ rfc7515_a1_hmac_key_b64 ++ "\"}]}";
    var jwks = try parseJwks(testing.allocator, single);
    defer jwks.deinit();
    var parsed = try parse(testing.allocator, rfc7519_example_token);
    defer parsed.deinit();
    try verifyWithJwks(&parsed, jwks);

    // The same token against a multi-key set: no kid to pick by → refuse
    // (guessing among keys is not verification).
    var jwks_buf: [2048]u8 = undefined;
    var multi = try parseJwks(testing.allocator, try testJwksJson(&jwks_buf));
    defer multi.deinit();
    try testing.expectError(error.NoMatchingKey, verifyWithJwks(&parsed, multi));

    // Single-key set whose only key is use:"enc": nothing usable → refuse.
    const enc_only = "{\"keys\":[{\"kty\":\"oct\",\"use\":\"enc\",\"k\":\"" ++
        rfc7515_a1_hmac_key_b64 ++ "\"}]}";
    var jwks_enc = try parseJwks(testing.allocator, enc_only);
    defer jwks_enc.deinit();
    try testing.expectError(error.NoMatchingKey, verifyWithJwks(&parsed, jwks_enc));

    // An unrecognized use value is fail-closed the same way.
    const other_use = "{\"keys\":[{\"kty\":\"oct\",\"use\":\"backup\",\"k\":\"" ++
        rfc7515_a1_hmac_key_b64 ++ "\"}]}";
    var jwks_other = try parseJwks(testing.allocator, other_use);
    defer jwks_other.deinit();
    try testing.expectError(error.NoMatchingKey, verifyWithJwks(&parsed, jwks_other));
}

test "JWKS: RFC 7515 A.2 (RSA) and A.3 (EC) keys as JWKs verify the RFC tokens" {
    // A.3 P-256 key as a JWK; the RFC ES256 token has no kid → the
    // single-key path resolves it.
    const ec_set = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"a3\",\"use\":\"sig\"," ++
        "\"x\":\"" ++ rfc7515_a3_x_b64 ++ "\",\"y\":\"" ++ rfc7515_a3_y_b64 ++ "\"}]}";
    var ec_jwks = try parseJwks(testing.allocator, ec_set);
    defer ec_jwks.deinit();
    try testing.expect(ec_jwks.keyForKid("a3").?.key == .ecdsa_p256);

    const a3_token =
        "eyJhbGciOiJFUzI1NiJ9" ++
        "." ++
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" ++
        "." ++
        "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
    var es_parsed = try parse(testing.allocator, a3_token);
    defer es_parsed.deinit();
    try verifyWithJwks(&es_parsed, ec_jwks);

    // A.2 RSA key as a JWK (alg pinned to RS256, matching the token).
    const rsa_set = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"a2\",\"alg\":\"RS256\"," ++
        "\"n\":\"" ++ rfc7515_a2_n_b64 ++ "\",\"e\":\"" ++ rfc7515_a2_e_b64 ++ "\"}]}";
    var rsa_jwks = try parseJwks(testing.allocator, rsa_set);
    defer rsa_jwks.deinit();
    var rs_parsed = try parse(testing.allocator, rfc7515_a2_token);
    defer rs_parsed.deinit();
    try verifyWithJwks(&rs_parsed, rsa_jwks);

    // RFC 8037 A.2 public-key JWK (kty OKP, crv Ed25519) parses to an
    // Ed25519 key.
    const okp_set = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"ed8037\"," ++
        "\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}]}";
    var okp_jwks = try parseJwks(testing.allocator, okp_set);
    defer okp_jwks.deinit();
    try testing.expect(okp_jwks.keyForKid("ed8037").?.key == .ed25519);
}

test "JWKS: unsupported and enc keys don't break the set; good key resolves" {
    const mixed =
        "{\"keys\":[" ++
        // P-521: recognized kty, unsupported curve → skipped.
        "{\"kty\":\"EC\",\"crv\":\"P-521\",\"x\":\"AAAA\",\"y\":\"AAAA\",\"kid\":\"p521\"}," ++
        // Unknown kty → skipped.
        "{\"kty\":\"quantum\",\"kid\":\"q\"}," ++
        // X25519 is key agreement, not signing → skipped.
        "{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":\"AAAA\",\"kid\":\"x25519\"}," ++
        // Encryption key: parses fine but is never selected for signatures.
        "{\"kty\":\"EC\",\"crv\":\"P-256\",\"use\":\"enc\",\"kid\":\"enc-ec\"," ++
        "\"x\":\"" ++ rfc7515_a3_x_b64 ++ "\",\"y\":\"" ++ rfc7515_a3_y_b64 ++ "\"}," ++
        // The one signing key.
        "{\"kty\":\"RSA\",\"kid\":\"rs\",\"n\":\"" ++ rfc7515_a2_n_b64 ++ "\",\"e\":\"AQAB\"}" ++
        "]}";
    var jwks = try parseJwks(testing.allocator, mixed);
    defer jwks.deinit();

    try testing.expectEqual(@as(usize, 2), jwks.keys.len);
    try testing.expectEqual(@as(usize, 3), jwks.skipped.len);
    try testing.expectEqual(@as(usize, 0), jwks.skipped[0].index);
    try testing.expectEqual(JwkSkipReason.unsupported_crv, jwks.skipped[0].reason);
    try testing.expectEqual(@as(usize, 1), jwks.skipped[1].index);
    try testing.expectEqual(JwkSkipReason.unsupported_kty, jwks.skipped[1].reason);
    try testing.expectEqual(@as(usize, 2), jwks.skipped[2].index);
    try testing.expectEqual(JwkSkipReason.unsupported_crv, jwks.skipped[2].reason);

    // The good key still verifies a real token by kid.
    var n_buf: [256]u8 = undefined;
    var d_buf: [256]u8 = undefined;
    const n_bytes = b64uDecode(&n_buf, rfc7515_a2_n_b64);
    const d_bytes = b64uDecode(&d_buf, rfc7515_a2_d_b64);
    var buf: [1024]u8 = undefined;
    const si = signingInputInto(&buf,
        \\{"alg":"RS256","kid":"rs"}
    ,
        \\{"exp":1000}
    );
    const sig = rsaTestSign(sha2.Sha256, 256, si, n_bytes, d_bytes);
    const token = finishToken(&buf, si.len, &sig);
    var parsed = try parse(testing.allocator, token);
    defer parsed.deinit();
    try verifyWithJwks(&parsed, jwks);

    // The enc EC key exists in the set but is not selectable.
    try testing.expect(jwks.keyForKid("enc-ec") == null);
}

test "JWKS: a JWK's pinned alg must match the token alg" {
    // RSA key pinned to RS384.
    const set = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"rs\",\"alg\":\"RS384\"," ++
        "\"n\":\"" ++ rfc7515_a2_n_b64 ++ "\",\"e\":\"AQAB\"}]}";
    var jwks = try parseJwks(testing.allocator, set);
    defer jwks.deinit();

    var n_buf: [256]u8 = undefined;
    var d_buf: [256]u8 = undefined;
    const n_bytes = b64uDecode(&n_buf, rfc7515_a2_n_b64);
    const d_bytes = b64uDecode(&d_buf, rfc7515_a2_d_b64);

    // An RS256 token with the right kid but the wrong alg for the pin —
    // even with a VALID RS256 signature — must not resolve the key.
    var buf: [1024]u8 = undefined;
    const si256 = signingInputInto(&buf,
        \\{"alg":"RS256","kid":"rs"}
    ,
        \\{"exp":1000}
    );
    const sig256 = rsaTestSign(sha2.Sha256, 256, si256, n_bytes, d_bytes);
    const t256 = finishToken(&buf, si256.len, &sig256);
    var p256 = try parse(testing.allocator, t256);
    defer p256.deinit();
    try testing.expectError(error.NoMatchingKey, verifyWithJwks(&p256, jwks));
    try testing.expect(jwks.selectKey(p256.header) == null);
    // keyForKid alone (no alg context) still finds it — selectKey is the
    // header-aware entry point.
    try testing.expect(jwks.keyForKid("rs") != null);

    // The matching RS384 token verifies.
    var buf2: [1024]u8 = undefined;
    const si384 = signingInputInto(&buf2,
        \\{"alg":"RS384","kid":"rs"}
    ,
        \\{"exp":1000}
    );
    const sig384 = rsaTestSign(sha2.Sha384, 256, si384, n_bytes, d_bytes);
    const t384 = finishToken(&buf2, si384.len, &sig384);
    var p384 = try parse(testing.allocator, t384);
    defer p384.deinit();
    try verifyWithJwks(&p384, jwks);

    // The no-kid single-key path honors the pin the same way.
    const nokid_set = "{\"keys\":[{\"kty\":\"RSA\",\"alg\":\"RS384\"," ++
        "\"n\":\"" ++ rfc7515_a2_n_b64 ++ "\",\"e\":\"AQAB\"}]}";
    var jwks2 = try parseJwks(testing.allocator, nokid_set);
    defer jwks2.deinit();
    var buf3: [1024]u8 = undefined;
    const si_nk = signingInputInto(&buf3,
        \\{"alg":"RS256"}
    ,
        \\{"exp":1000}
    );
    const sig_nk = rsaTestSign(sha2.Sha256, 256, si_nk, n_bytes, d_bytes);
    const t_nk = finishToken(&buf3, si_nk.len, &sig_nk);
    var p_nk = try parse(testing.allocator, t_nk);
    defer p_nk.deinit();
    try testing.expectError(error.NoMatchingKey, verifyWithJwks(&p_nk, jwks2));
}

test "JWKS: malformed JWKs are skipped with reasons, never a panic" {
    const set =
        "{\"keys\":[" ++
        "42," ++ // not an object
        "{}," ++ // no kty
        "{\"kty\":42}," ++ // kty of the wrong type
        "{\"kty\":\"RSA\",\"n\":\"!!!\",\"e\":\"AQAB\"}," ++ // bad base64url n
        "{\"kty\":\"RSA\",\"e\":\"AQAB\"}," ++ // n missing
        "{\"kty\":\"EC\",\"x\":\"AAAA\",\"y\":\"AAAA\"}," ++ // crv missing
        "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" ++ ("A" ** 22) ++
        "\",\"y\":\"" ++ ("A" ** 22) ++ "\"}," ++ // 16-byte coords: wrong length
        "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" ++ ("A" ** 43) ++
        "\",\"y\":\"" ++ ("A" ** 43) ++ "\"}," ++ // (0,0): not on the curve
        "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" ++ ("_" ** 42) ++
        "8\"}," ++ // 0xFF…: non-canonical Ed25519
        "{\"kty\":\"oct\",\"k\":\"\"}," ++ // empty secret: unusable
        "{\"kty\":\"oct\",\"k\":\"c2VjcmV0\",\"kid\":42}," ++ // kid wrong type
        "{\"kty\":\"oct\",\"k\":\"c2VjcmV0\",\"kid\":\"good\"}" ++ // the survivor
        "]}";
    var jwks = try parseJwks(testing.allocator, set);
    defer jwks.deinit();

    try testing.expectEqual(@as(usize, 1), jwks.keys.len);
    try testing.expectEqualStrings("good", jwks.keys[0].kid.?);
    try testing.expect(jwks.keys[0].key == .hmac);
    try testing.expectEqualStrings("secret", jwks.keys[0].key.hmac);

    const expected = [_]JwkSkipReason{
        .not_an_object,  .missing_kty, .invalid_member, .invalid_base64,
        .missing_member, .missing_crv, .invalid_key,    .invalid_key,
        .invalid_key,    .invalid_key, .invalid_member,
    };
    try testing.expectEqual(@as(usize, expected.len), jwks.skipped.len);
    for (jwks.skipped, expected, 0..) |s, want, i| {
        try testing.expectEqual(i, s.index);
        try testing.expectEqual(want, s.reason);
    }
}

test "JWKS: garbage documents → typed errors; empty set resolves nothing" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidJson, parseJwks(gpa, "not json"));
    try testing.expectError(error.InvalidJson, parseJwks(gpa, ""));
    try testing.expectError(error.InvalidJson, parseJwks(gpa, "{\"keys\":[}"));
    try testing.expectError(error.NotAJwks, parseJwks(gpa, "42"));
    try testing.expectError(error.NotAJwks, parseJwks(gpa, "[]"));
    try testing.expectError(error.NotAJwks, parseJwks(gpa, "{}"));
    try testing.expectError(error.NotAJwks, parseJwks(gpa, "{\"keys\":42}"));
    try testing.expectError(error.NotAJwks, parseJwks(gpa, "{\"keys\":{}}"));

    // {"keys":[]} is a well-formed, useless set: everything → NoMatchingKey.
    var empty = try parseJwks(gpa, "{\"keys\":[]}");
    defer empty.deinit();
    try testing.expectEqual(@as(usize, 0), empty.keys.len);
    var parsed = try parse(gpa, rfc7519_example_token);
    defer parsed.deinit();
    try testing.expect(empty.selectKey(parsed.header) == null);
    try testing.expect(empty.keyForKid("any") == null);
    try testing.expectError(error.NoMatchingKey, verifyWithJwks(&parsed, empty));
}

test "parseVerifyJwks: end-to-end against a multi-key set" {
    const gpa = testing.allocator;
    var jwks_buf: [2048]u8 = undefined;
    var jwks = try parseJwks(gpa, try testJwksJson(&jwks_buf));
    defer jwks.deinit();

    var n_buf: [256]u8 = undefined;
    var d_buf: [256]u8 = undefined;
    const n_bytes = b64uDecode(&n_buf, rfc7515_a2_n_b64);
    const d_bytes = b64uDecode(&d_buf, rfc7515_a2_d_b64);

    var buf: [1024]u8 = undefined;
    const si = signingInputInto(&buf,
        \\{"alg":"RS256","kid":"rs"}
    ,
        \\{"iss":"https://issuer.example","aud":"api://svc","exp":2000,"scope":"read"}
    );
    const sig = rsaTestSign(sha2.Sha256, 256, si, n_bytes, d_bytes);
    const token = finishToken(&buf, si.len, &sig);

    var verified = try parseVerifyJwks(gpa, token, jwks, .{
        .now_s = 1000,
        .issuer = "https://issuer.example",
        .audience = "api://svc",
    });
    defer verified.deinit();
    try testing.expectEqualStrings("read", verified.claims.claimStr("scope").?);

    // Valid signature but expired → Expired (and nothing leaks on the way out).
    try testing.expectError(error.Expired, parseVerifyJwks(gpa, token, jwks, .{
        .now_s = 5000,
    }));

    // Token bearing a kid that was rotated away → NoMatchingKey.
    var buf2: [1024]u8 = undefined;
    const si2 = signingInputInto(&buf2,
        \\{"alg":"RS256","kid":"rotated-away"}
    ,
        \\{"exp":2000}
    );
    const sig2 = rsaTestSign(sha2.Sha256, 256, si2, n_bytes, d_bytes);
    const token2 = finishToken(&buf2, si2.len, &sig2);
    try testing.expectError(error.NoMatchingKey, parseVerifyJwks(gpa, token2, jwks, .{
        .now_s = 1000,
    }));

    // Right kid, corrupted signature → BadSignature.
    var bad_sig = sig;
    bad_sig[100] ^= 0x01;
    var buf3: [1024]u8 = undefined;
    const si3 = signingInputInto(&buf3,
        \\{"alg":"RS256","kid":"rs"}
    ,
        \\{"iss":"https://issuer.example","aud":"api://svc","exp":2000,"scope":"read"}
    );
    const token3 = finishToken(&buf3, si3.len, &bad_sig);
    try testing.expectError(error.BadSignature, parseVerifyJwks(gpa, token3, jwks, .{
        .now_s = 1000,
    }));

    // Malformed token → the parse error surfaces unchanged.
    try testing.expectError(error.MalformedToken, parseVerifyJwks(gpa, "nope", jwks, .{
        .now_s = 1000,
    }));
}

// ── tests: networked layer (Part 5) ─────────────────────────────────────────
// Everything below runs offline: a scripted fake Fetcher plus a virtual
// `now_s`. The network is never touched.

/// Scripted fetcher: responses are consumed IN ORDER and each step pins the
/// exact URL it expects. A call past the end of the script or with the wrong
/// URL fails the fetch — and, via the call counter the tests assert on,
/// fails the test loudly. This is what makes "the fetcher was NOT called
/// again" provable in the rate-limit tests.
const ScriptFetcher = struct {
    script: []const Step,
    next: usize = 0,
    calls: usize = 0,

    const Step = struct { url: []const u8, status: u16 = 200, body: []const u8 };

    fn fetcher(s: *ScriptFetcher) Fetcher {
        return .{ .ctx = s, .fetchFn = fetchFn };
    }

    fn fetchFn(ctx: *anyopaque, url: []const u8, body_buf: []u8) FetchError!Fetcher.Result {
        const s: *ScriptFetcher = @ptrCast(@alignCast(ctx));
        s.calls += 1;
        if (s.next >= s.script.len) return error.FetchFailed;
        const step = s.script[s.next];
        s.next += 1;
        if (!std.mem.eql(u8, step.url, url)) return error.FetchFailed;
        if (step.body.len > body_buf.len) return error.ResponseTooLarge;
        @memcpy(body_buf[0..step.body.len], step.body);
        return .{ .status = step.status, .body_len = step.body.len };
    }
};

const test_wellknown_url = "https://issuer.example" ++ well_known_path;
const test_jwks_url = "https://issuer.example/jwks";
const test_discovery_json =
    \\{"issuer":"https://issuer.example",
    \\ "jwks_uri":"https://issuer.example/jwks",
    \\ "id_token_signing_alg_values_supported":["RS256","ES256"],
    \\ "token_endpoint":"https://issuer.example/token",
    \\ "response_types_supported":["code"]}
;

test "discover: canned well-known doc → issuer, jwks_uri, alg list" {
    var stub: ScriptFetcher = .{ .script = &.{
        .{ .url = test_wellknown_url, .body = test_discovery_json },
    } };
    var md = try discover(testing.allocator, stub.fetcher(), "https://issuer.example");
    defer md.deinit();

    try testing.expectEqual(@as(usize, 1), stub.calls);
    try testing.expectEqualStrings("https://issuer.example", md.issuer);
    try testing.expectEqualStrings(test_jwks_url, md.jwks_uri);
    const algs = md.id_token_signing_alg_values_supported.?;
    try testing.expectEqual(@as(usize, 2), algs.len);
    try testing.expectEqualStrings("RS256", algs[0]);
    try testing.expectEqualStrings("ES256", algs[1]);

    // Trailing slash on the requested issuer: same URL, same match.
    var stub2: ScriptFetcher = .{ .script = &.{
        .{ .url = test_wellknown_url, .body = test_discovery_json },
    } };
    var md2 = try discover(testing.allocator, stub2.fetcher(), "https://issuer.example/");
    defer md2.deinit();
    try testing.expectEqual(@as(usize, 1), stub2.calls);
    try testing.expectEqualStrings("https://issuer.example", md2.issuer);

    // The alg list is optional — a doc without it still resolves.
    var stub3: ScriptFetcher = .{ .script = &.{
        .{
            .url = test_wellknown_url,
            .body =
            \\{"issuer":"https://issuer.example","jwks_uri":"https://issuer.example/jwks"}
            ,
        },
    } };
    var md3 = try discover(testing.allocator, stub3.fetcher(), "https://issuer.example");
    defer md3.deinit();
    try testing.expect(md3.id_token_signing_alg_values_supported == null);
}

test "discover: issuer mismatch in the response → IssuerMismatch" {
    const gpa = testing.allocator;
    var stub: ScriptFetcher = .{ .script = &.{
        .{
            .url = test_wellknown_url,
            .body =
            \\{"issuer":"https://evil.example","jwks_uri":"https://issuer.example/jwks"}
            ,
        },
    } };
    try testing.expectError(
        error.IssuerMismatch,
        discover(gpa, stub.fetcher(), "https://issuer.example"),
    );

    // …but a trailing-slash-only difference is tolerated (both directions).
    var stub2: ScriptFetcher = .{ .script = &.{
        .{
            .url = test_wellknown_url,
            .body =
            \\{"issuer":"https://issuer.example/","jwks_uri":"https://issuer.example/jwks"}
            ,
        },
    } };
    var md = try discover(gpa, stub2.fetcher(), "https://issuer.example");
    defer md.deinit();
    try testing.expectEqualStrings("https://issuer.example/", md.issuer);
}

test "discover: non-200, garbage JSON, missing/mistyped members → typed errors" {
    const gpa = testing.allocator;
    const cases = [_]struct { step: ScriptFetcher.Step, want: DiscoverError }{
        .{
            .step = .{ .url = test_wellknown_url, .status = 404, .body = "not found" },
            .want = error.HttpStatus,
        },
        .{
            .step = .{ .url = test_wellknown_url, .status = 500, .body = test_discovery_json },
            .want = error.HttpStatus,
        },
        .{
            .step = .{ .url = test_wellknown_url, .body = "]]]not json" },
            .want = error.DiscoveryFailed,
        },
        .{
            .step = .{ .url = test_wellknown_url, .body = "[1,2,3]" },
            .want = error.DiscoveryFailed,
        },
        .{ // jwks_uri missing
            .step = .{ .url = test_wellknown_url, .body = "{\"issuer\":\"https://issuer.example\"}" },
            .want = error.DiscoveryFailed,
        },
        .{ // issuer missing
            .step = .{ .url = test_wellknown_url, .body = "{\"jwks_uri\":\"https://issuer.example/jwks\"}" },
            .want = error.DiscoveryFailed,
        },
        .{ // issuer of the wrong JSON type
            .step = .{
                .url = test_wellknown_url,
                .body = "{\"issuer\":42,\"jwks_uri\":\"https://issuer.example/jwks\"}",
            },
            .want = error.DiscoveryFailed,
        },
        .{ // alg list present but not an array of strings
            .step = .{
                .url = test_wellknown_url,
                .body = "{\"issuer\":\"https://issuer.example\"," ++
                    "\"jwks_uri\":\"https://issuer.example/jwks\"," ++
                    "\"id_token_signing_alg_values_supported\":[\"RS256\",42]}",
            },
            .want = error.DiscoveryFailed,
        },
    };
    for (cases) |case| {
        var stub: ScriptFetcher = .{ .script = &.{case.step} };
        try testing.expectError(
            case.want,
            discover(gpa, stub.fetcher(), "https://issuer.example"),
        );
    }

    // Transport failure propagates; an empty issuer never builds a URL.
    var dead: ScriptFetcher = .{ .script = &.{} };
    try testing.expectError(
        error.FetchFailed,
        discover(gpa, dead.fetcher(), "https://issuer.example"),
    );
    try testing.expectError(error.DiscoveryFailed, discover(gpa, dead.fetcher(), "///"));
}

test "fetchJwks: 200 parses via parseJwks; non-200 and garbage → typed errors" {
    const gpa = testing.allocator;
    const set = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"hs\",\"k\":\"c2VjcmV0\"}]}";

    var stub: ScriptFetcher = .{ .script = &.{.{ .url = test_jwks_url, .body = set }} };
    var jwks = try fetchJwks(gpa, stub.fetcher(), test_jwks_url);
    defer jwks.deinit();
    try testing.expectEqual(@as(usize, 1), jwks.keys.len);
    try testing.expectEqualStrings("hs", jwks.keys[0].kid.?);

    var stub2: ScriptFetcher = .{ .script = &.{
        .{ .url = test_jwks_url, .status = 503, .body = set },
    } };
    try testing.expectError(error.HttpStatus, fetchJwks(gpa, stub2.fetcher(), test_jwks_url));

    var stub3: ScriptFetcher = .{ .script = &.{
        .{ .url = test_jwks_url, .body = "<html>oops</html>" },
    } };
    try testing.expectError(error.InvalidJson, fetchJwks(gpa, stub3.fetcher(), test_jwks_url));

    var stub4: ScriptFetcher = .{ .script = &.{
        .{ .url = test_jwks_url, .body = "{\"nokeys\":true}" },
    } };
    try testing.expectError(error.NotAJwks, fetchJwks(gpa, stub4.fetcher(), test_jwks_url));
}

test "Provider by jwks_uri: RFC 7515 A.2 RS256 token through the turnkey call" {
    const gpa = testing.allocator;
    // The RFC A.2 key served as the issuer's JWKS; the RFC token has no kid,
    // so the single-usable-key path resolves it.
    const rfc_set = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"a2\",\"use\":\"sig\"," ++
        "\"n\":\"" ++ rfc7515_a2_n_b64 ++ "\",\"e\":\"" ++ rfc7515_a2_e_b64 ++ "\"}]}";
    var stub: ScriptFetcher = .{ .script = &.{
        .{ .url = test_jwks_url, .body = rfc_set },
    } };
    var provider = Provider.init(gpa, stub.fetcher(), .{
        .jwks_uri = test_jwks_url,
        .ttl_s = 1000000, // keep TTL out of this test's way
    });
    defer provider.deinit();

    // Lazy first fetch + verify (now before the token's 2011 exp).
    var verified = try provider.verify(gpa, rfc7515_a2_token, 1300819000, .{});
    defer verified.deinit();
    try testing.expectEqualStrings("joe", verified.claims.iss.?);
    try testing.expectEqual(@as(usize, 1), stub.calls);

    // Second verify inside the TTL: served from cache, no fetch.
    var again = try provider.verify(gpa, rfc7515_a2_token, 1300819100, .{});
    again.deinit();
    try testing.expectEqual(@as(usize, 1), stub.calls);

    // Signature fine but claims stale → Expired (still no fetch).
    try testing.expectError(
        error.Expired,
        provider.verify(gpa, rfc7515_a2_token, 1300819380 + 61, .{}),
    );
    try testing.expectEqual(@as(usize, 1), stub.calls);

    // A jwks_uri provider has no discovered issuer — but an explicit
    // ClaimOptions.issuer is enforced.
    try testing.expectError(
        error.IssuerMismatch,
        provider.verify(gpa, rfc7515_a2_token, 1300819000, .{ .issuer = "https://other" }),
    );
}

test "Provider by issuer: discovery + injected issuer end-to-end" {
    const gpa = testing.allocator;
    const enc = std.base64.url_safe_no_pad.Encoder;
    const secret = "provider-discovery-e2e-secret";
    var k_b64: [64]u8 = undefined;
    var set_buf: [256]u8 = undefined;
    const set = try std.fmt.bufPrint(&set_buf,
        \\{{"keys":[{{"kty":"oct","kid":"hs","k":"{s}"}}]}}
    , .{enc.encode(&k_b64, secret)});

    var stub: ScriptFetcher = .{ .script = &.{
        .{ .url = test_wellknown_url, .body = test_discovery_json },
        .{ .url = test_jwks_url, .body = set },
    } };
    var provider = Provider.init(gpa, stub.fetcher(), .{ .issuer = "https://issuer.example" });
    defer provider.deinit();

    // Token minted by "the issuer": right iss, right key, kid "hs".
    var buf: [512]u8 = undefined;
    const si = signingInputInto(&buf,
        \\{"alg":"HS256","kid":"hs"}
    ,
        \\{"iss":"https://issuer.example","aud":"api://svc","exp":2000,"scope":"read"}
    );
    var mac: [32]u8 = undefined;
    hmac_sha2.HmacSha256.create(&mac, si, secret);
    const token = finishToken(&buf, si.len, &mac);

    var verified = try provider.verify(gpa, token, 1000, .{ .audience = "api://svc" });
    defer verified.deinit();
    try testing.expectEqualStrings("read", verified.claims.claimStr("scope").?);
    // Exactly one discovery + one JWKS fetch; metadata is cached.
    try testing.expectEqual(@as(usize, 2), stub.calls);
    try testing.expectEqualStrings(test_jwks_url, provider.metadata.?.jwks_uri);

    // A validly signed token from the WRONG issuer: the discovered issuer is
    // injected as the expected `iss`, so it fails — no opt-in needed.
    var buf2: [512]u8 = undefined;
    const si2 = signingInputInto(&buf2,
        \\{"alg":"HS256","kid":"hs"}
    ,
        \\{"iss":"https://evil.example","aud":"api://svc","exp":2000}
    );
    var mac2: [32]u8 = undefined;
    hmac_sha2.HmacSha256.create(&mac2, si2, secret);
    const evil = finishToken(&buf2, si2.len, &mac2);
    try testing.expectError(error.IssuerMismatch, provider.verify(gpa, evil, 1000, .{}));

    // Audience policy still applies on top.
    try testing.expectError(
        error.AudienceMismatch,
        provider.verify(gpa, token, 1000, .{ .audience = "api://other" }),
    );
    // All of that ran from the cache.
    try testing.expectEqual(@as(usize, 2), stub.calls);
}

test "Provider: key rotation refreshes once, rate limit stops a bogus-kid flood, TTL re-fetches" {
    const gpa = testing.allocator;
    const enc = std.base64.url_safe_no_pad.Encoder;
    const secret_old = "rotation-secret-old";
    const secret_new = "rotation-secret-new";
    var old_b64: [64]u8 = undefined;
    var new_b64: [64]u8 = undefined;
    var v1_buf: [256]u8 = undefined;
    var v2_buf: [256]u8 = undefined;
    // v1: only kid "old". v2 (after rotation): only kid "new".
    const jwks_v1 = try std.fmt.bufPrint(&v1_buf,
        \\{{"keys":[{{"kty":"oct","kid":"old","k":"{s}"}}]}}
    , .{enc.encode(&old_b64, secret_old)});
    const jwks_v2 = try std.fmt.bufPrint(&v2_buf,
        \\{{"keys":[{{"kty":"oct","kid":"new","k":"{s}"}}]}}
    , .{enc.encode(&new_b64, secret_new)});

    var stub: ScriptFetcher = .{
        .script = &.{
            .{ .url = test_jwks_url, .body = jwks_v1 }, // lazy first load
            .{ .url = test_jwks_url, .body = jwks_v2 }, // rotation refresh
            .{ .url = test_jwks_url, .body = jwks_v2 }, // rate-limited bogus-kid retry
            .{ .url = test_jwks_url, .body = jwks_v2 }, // TTL re-fetch
        },
    };
    var provider = Provider.init(gpa, stub.fetcher(), .{
        .jwks_uri = test_jwks_url,
        .ttl_s = 300,
        .min_refresh_interval_s = 30,
    });
    defer provider.deinit();

    // Each token gets its own buffer — they are slices into it and must
    // all stay alive for the whole scenario.
    var buf_old: [512]u8 = undefined;
    var buf_new: [512]u8 = undefined;
    var buf_ghost: [512]u8 = undefined;
    var mac: [32]u8 = undefined;

    // t=1000: token signed with the OLD key verifies off the first load.
    const si_old = signingInputInto(&buf_old,
        \\{"alg":"HS256","kid":"old"}
    ,
        \\{"exp":90000}
    );
    hmac_sha2.HmacSha256.create(&mac, si_old, secret_old);
    const token_old = finishToken(&buf_old, si_old.len, &mac);
    var v_old = try provider.verify(gpa, token_old, 1000, .{});
    v_old.deinit();
    try testing.expectEqual(@as(usize, 1), stub.calls);

    // t=1040: the issuer rotated — a NEW-kid token arrives. Its kid is not
    // in the cached set, the rate-limit window (30s since t=1000) has
    // passed, so the provider refreshes ONCE and the token verifies.
    const si_new = signingInputInto(&buf_new,
        \\{"alg":"HS256","kid":"new"}
    ,
        \\{"exp":90000}
    );
    hmac_sha2.HmacSha256.create(&mac, si_new, secret_new);
    const token_new = finishToken(&buf_new, si_new.len, &mac);
    var v_new = try provider.verify(gpa, token_new, 1040, .{});
    v_new.deinit();
    try testing.expectEqual(@as(usize, 2), stub.calls);

    // t=1050 and t=1055: bogus-kid tokens inside the min-refresh window.
    // NoMatchingKey — and the fetcher is NOT called again (no fetch storm).
    const si_ghost = signingInputInto(&buf_ghost,
        \\{"alg":"HS256","kid":"ghost"}
    ,
        \\{"exp":90000}
    );
    hmac_sha2.HmacSha256.create(&mac, si_ghost, secret_new);
    const token_ghost = finishToken(&buf_ghost, si_ghost.len, &mac);
    try testing.expectError(error.NoMatchingKey, provider.verify(gpa, token_ghost, 1050, .{}));
    try testing.expectError(error.NoMatchingKey, provider.verify(gpa, token_ghost, 1055, .{}));
    try testing.expectEqual(@as(usize, 2), stub.calls);

    // t=1080: the window has passed — the bogus kid earns one (single,
    // rate-limited) refresh, which still doesn't know it → NoMatchingKey.
    try testing.expectError(error.NoMatchingKey, provider.verify(gpa, token_ghost, 1080, .{}));
    try testing.expectEqual(@as(usize, 3), stub.calls);

    // The rotated-in set stays live: the new-kid token verifies from cache.
    var v_new2 = try provider.verify(gpa, token_new, 1085, .{});
    v_new2.deinit();
    try testing.expectEqual(@as(usize, 3), stub.calls);

    // t=1400: past fetched_at(1080)+ttl(300) — the next verify re-fetches.
    var v_new3 = try provider.verify(gpa, token_new, 1400, .{});
    v_new3.deinit();
    try testing.expectEqual(@as(usize, 4), stub.calls);
    try testing.expectEqual(stub.script.len, stub.next); // script fully consumed
}

test "Provider: refresh failures are typed, old keys survive a failed refresh" {
    const gpa = testing.allocator;

    // Discovery-side failure → DiscoveryFailed.
    var bad_disco: ScriptFetcher = .{ .script = &.{
        .{ .url = test_wellknown_url, .status = 500, .body = "boom" },
    } };
    var p1 = Provider.init(gpa, bad_disco.fetcher(), .{ .issuer = "https://issuer.example" });
    defer p1.deinit();
    try testing.expectError(
        error.DiscoveryFailed,
        p1.verify(gpa, rfc7515_a2_token, 1000, .{}),
    );

    // JWKS-side failure → JwksFetchFailed (here: discovery fine, JWKS 503).
    var bad_jwks: ScriptFetcher = .{ .script = &.{
        .{ .url = test_wellknown_url, .body = test_discovery_json },
        .{ .url = test_jwks_url, .status = 503, .body = "later" },
    } };
    var p2 = Provider.init(gpa, bad_jwks.fetcher(), .{ .issuer = "https://issuer.example" });
    defer p2.deinit();
    try testing.expectError(
        error.JwksFetchFailed,
        p2.verify(gpa, rfc7515_a2_token, 1000, .{}),
    );

    // Malformed JWKS body is the same typed failure — and an explicit
    // refresh() that fails leaves the previously good set in place.
    const rfc_set = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"a2\"," ++
        "\"n\":\"" ++ rfc7515_a2_n_b64 ++ "\",\"e\":\"" ++ rfc7515_a2_e_b64 ++ "\"}]}";
    var flaky: ScriptFetcher = .{ .script = &.{
        .{ .url = test_jwks_url, .body = rfc_set },
        .{ .url = test_jwks_url, .body = "<garbage>" },
    } };
    var p3 = Provider.init(gpa, flaky.fetcher(), .{
        .jwks_uri = test_jwks_url,
        .ttl_s = 4000000000, // the 1970→2011 time jump below must not expire it
    });
    defer p3.deinit();
    try p3.refresh(1000);
    try testing.expectError(error.JwksFetchFailed, p3.refresh(2000));
    // The v1 set survived the failed swap: the RFC token still verifies.
    var verified = try p3.verify(gpa, rfc7515_a2_token, 1300819000, .{});
    verified.deinit();
    try testing.expectEqual(@as(usize, 2), flaky.calls);
}

test "HttpFetcher compiles (never dialed in tests)" {
    // Reference the real fetcher so it is semantically checked without any
    // network activity.
    _ = HttpFetcher.fetchFn;
    _ = HttpFetcher.fetcher;
    _ = http.Client.request;
}
