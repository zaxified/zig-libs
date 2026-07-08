// SPDX-License-Identifier: MIT

//! jwt — JWT/JWS validator for OAuth2/OIDC resource servers
//! (RFC 7515 compact JWS serialization + RFC 7519 JWT claims).
//!
//! Part 1 scope (this file): compact-token **parsing** into typed models and
//! **registered-claims validation** (`exp`/`nbf`/`iat`/`iss`/`aud`), with the
//! raw signing input and signature bytes preserved for the verify step.
//!
//! ## SECURITY — NO SIGNATURE VERIFICATION YET (Part 1)
//!
//! `parse()` only *decodes* a token — it does **not** verify the signature.
//! A `ParsedToken` is **UNTRUSTED, attacker-controlled input** until Part 2's
//! `verify(parsed, key)` (or the all-in-one `parseAndVerify`) has run.
//! Never make an authorization decision from a `ParsedToken` alone; anyone
//! can mint a syntactically valid token with any claims. The parsed
//! `signing_input` + `signature` + `alg` exist precisely so the verify step
//! can be layered on without re-parsing.
//!
//! Planned parts: P2 signature verify (HS*/dispatch skeleton) · P3 RSA ·
//! P4 JWKS key sets · P5 fetch/OIDC discovery · P6 resource-server
//! middleware.
//!
//! ## Usage
//!
//! ```zig
//! const jwt = @import("jwt");
//!
//! var parsed = try jwt.parse(gpa, bearer_token);
//! defer parsed.deinit();
//! // parsed is NOT verified — see the security note above.
//!
//! try jwt.validateClaims(parsed.claims, .{
//!     .now_s = now_seconds, // caller-supplied clock, no hidden time source
//!     .issuer = "https://issuer.example",
//!     .audience = "api://my-service",
//! });
//! const scope = parsed.claims.claimStr("scope") orelse "";
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
    .model_after = "RFC 7515 (JWS) + RFC 7519 (JWT); OAuth2/OIDC resource server",
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
