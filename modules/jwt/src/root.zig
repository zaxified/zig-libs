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
//! `<issuer>/.well-known/openid-configuration` to the issuer's `jwks_uri`,
//! `authorization_endpoint` and `token_endpoint`),
//! `fetchJwks`, and the cached `Provider` (TTL + key-rotation refresh with a
//! `min_refresh_interval_s` rate limit) whose `Provider.verify` is the
//! turnkey resource-server call. All I/O goes through the `Fetcher` seam
//! ("GET this URL, give me status + body"), so everything stays
//! offline-testable; `HttpFetcher` adapts our `http.Client` for real use.
//!
//! On top of the resource-server stack sits the **relying-party (RP) flow**
//! (P7): this module is now BOTH a token *validator* and an OAuth2/OIDC
//! *client*. PKCE (RFC 7636: `pkceGenerateS256`/`pkceGeneratePlain`/
//! `pkceChallengeS256`), CSRF `state` + OIDC `nonce` generation
//! (`generateState`/`generateNonce`), the authorization-request URL builder
//! (`buildAuthorizationUrl`), the authorization-code token-exchange request
//! builder (`buildTokenRequest` — returns method/url/headers/body, this
//! module does no I/O) + response parser (`parseTokenResponse`), and
//! ID-token RP-side acceptance (`acceptIdToken`/`acceptIdTokenJwks`/
//! `acceptIdTokenProvider`, OIDC Core §3.1.3.7) layered on the SAME
//! `verify`/`Provider` machinery P2-P5 already built — no duplicated crypto.
//! DPoP (RFC 9449) is DEFERRED; see SPEC.md.
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
//! On top of that sits the `router` layer (P6): `ResourceServer` is a
//! `router.Middleware` that reads `Authorization: Bearer <token>`, runs it
//! through `Provider.verify`, and either attaches the verified `Identity` to
//! the request (`identityOf(ctx)`) and continues, or short-circuits with the
//! RFC 6750 challenge — **401** `WWW-Authenticate: Bearer error="invalid_token"`
//! (or a bare `Bearer` when no credential was presented) and **403**
//! `error="insufficient_scope"` when a required scope is missing. For hosts
//! that don't use `router`, P6 also ships `Guard` — the same RFC 6750 (+
//! optional RFC 9068 `at+jwt` `typ`) enforcement as a framework-agnostic
//! `authenticate(req) AuthError!AuthContext` call, with `authStatus`/
//! `writeBearerChallenge` for the caller to render its own 401/403, and the
//! shared `scopeGranted`/`requireScope`/`requireAllScopes`/`requireAnyScope`
//! helpers.
//!
//! ## Usage
//!
//! ```zig
//! const jwt = @import("jwt");
//!
//! // One call: parse → verify signature → validate claims. Issuer and
//! // audience validation are MANDATORY: pin them with `.required`, or write
//! // `.any` to consciously opt out (never a silent skip — RFC 8725 §3.9).
//! var token = try jwt.parseAndVerify(gpa, bearer_token, .{ .hmac = secret }, .{
//!     .now_s = now_seconds, // caller-supplied clock, no hidden time source
//!     .issuer = .{ .required = "https://issuer.example" },
//!     .audience = .{ .required = "api://my-service" },
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
//!     .audience = .{ .required = "api://my-service" },
//!     // issuer defaults to `.provider` — the discovered/configured issuer is
//!     // enforced automatically (a jwks_uri-only provider with no issuer must
//!     // pin `.issuer = .{ .required = … }` or opt out with `.issuer = .any`).
//! });
//! defer t.deinit();
//!
//! // The router layer (P6): guard routes with the same Provider. Register
//! // the middleware once, before routes; it verifies each request's bearer
//! // token and hands the handler an Identity via `jwt.identityOf(ctx)`.
//! var rs = try jwt.ResourceServer.init(gpa, .{
//!     .provider = &provider,
//!     .claim_opts = .{ .audience = .{ .required = "api://my-service" } },
//!     .required_scopes = &.{"read"},
//! });
//! defer rs.deinit();
//! try my_router.use(rs.middleware());
//!
//! // With a JWKS you already hold (fully offline):
//! var jwks = try jwt.parseJwks(gpa, jwks_json);
//! defer jwks.deinit();
//! var token2 = try jwt.parseVerifyJwks(gpa, bearer_token, jwks, .{
//!     .now_s = now_seconds,
//!     .issuer = .{ .required = "https://issuer.example" },
//!     .audience = .{ .required = "api://my-service" },
//! });
//! defer token2.deinit();
//!
//! // Or step by step (e.g. pick the key from the header's `kid` first):
//! var parsed = try jwt.parse(gpa, bearer_token);
//! defer parsed.deinit();
//! const jwk = jwks.selectKey(parsed.header) orelse return error.NoMatchingKey;
//! try jwt.verify(&parsed, jwk.key);
//! try jwt.validateClaims(parsed.claims, .{
//!     .now_s = now_seconds,
//!     .issuer = .{ .required = "https://issuer.example" },
//!     .audience = .{ .required = "api://my-service" },
//! });
//!
//! // P7: the relying-party (RP) flow — starting an OIDC login.
//! var csprng = std.Random.DefaultCsprng.init(seed); // caller's real CSPRNG
//! const random = csprng.random();
//! const pkce = jwt.pkceGenerateS256(random);
//! const state = jwt.generateState(random);
//! const nonce = jwt.generateNonce(random);
//! // (persist pkce.verifier(), state and nonce server-side, e.g. in a
//! // session, keyed however the app likes — they are checked back in below)
//! const auth_url = try jwt.buildAuthorizationUrl(gpa, metadata.authorization_endpoint.?, .{
//!     .client_id = "my-client-id",
//!     .redirect_uri = "https://my-app.example/callback",
//!     .scope = "openid profile email",
//!     .state = &state,
//!     .nonce = &nonce,
//!     .code_challenge = pkce.challenge(),
//!     .code_challenge_method = pkce.method,
//! });
//! defer gpa.free(auth_url);
//! // redirect the user-agent to `auth_url` …
//!
//! // … the callback returns `code` (after checking `state` matches):
//! var token_req = try jwt.buildTokenRequest(gpa, metadata.token_endpoint.?, .{
//!     .code = code_from_callback,
//!     .redirect_uri = "https://my-app.example/callback",
//!     .client_id = "my-client-id",
//!     .code_verifier = pkce.verifier(),
//! });
//! defer token_req.deinit(gpa);
//! // send `token_req` (method/url/content_type/body) with your HTTP client …
//! var token_resp = try jwt.parseTokenResponse(gpa, response_body_json);
//! defer token_resp.deinit();
//! var id_token = try jwt.acceptIdToken(gpa, token_resp.id_token.?, .{ .hmac = secret }, .{
//!     .now_s = now_seconds,
//!     .issuer = "https://issuer.example",
//!     .client_id = "my-client-id",
//!     .nonce = &nonce, // MUST match — replay/injection defense
//! });
//! defer id_token.deinit();
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
const builtin = @import("builtin");
const http = @import("http");
const router = @import("router");

pub const meta = .{
    .platform = .any, // pure logic over the Fetcher seam; HttpFetcher uses `http`
    .role = .both, // P6 = a `router` middleware guarding routes (server); P7 = an OAuth2/OIDC client building auth/token requests and accepting ID Tokens (relying party).
    .concurrency = .reentrant, // except Provider — one mutable cache, external sync (inject ResourceServer.lock under a threaded server)
    .model_after = "RFC 7515 (JWS) + RFC 7519 (JWT) + RFC 7518 (JWA) verify incl. RS256 (RSASSA-PKCS1-v1_5, RFC 8017) + RFC 7517 (JWK/JWKS key sets), RFC 8725 hardening + OpenID Connect Discovery 1.0 / RFC 8414 (issuer metadata -> jwks_uri/authorization_endpoint/token_endpoint) with cached, rotation-aware Provider; RFC 6750 Bearer resource-server middleware; RFC 7636 PKCE + OIDC Core 1.0 §3.1 authorization code flow + §3.1.3.7 ID Token validation; OAuth2/OIDC resource server AND relying party",
    .deps = .{ "http", "router", "p256" }, // p256 supplies the fast ES256 curve (byte-exact to std.crypto.sign.ecdsa.EcdsaP256Sha256)
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
    /// `crit` (RFC 7515 §4.1.11) is present but malformed: not an array, an
    /// empty array, a non-string or empty-string entry, a duplicate entry, a
    /// name that is not itself present in the JOSE header, or an
    /// RFC-registered header parameter name (all of which the RFC forbids in
    /// `crit`).
    InvalidCrit,
    /// `crit` is well-formed but lists an extension header parameter this
    /// implementation does not understand *and* process. RFC 7515 §4.1.11 is a
    /// MUST ("if any of the listed extension Header Parameters are not
    /// understood and supported by the recipient, then the JWS is invalid"),
    /// restated by RFC 8725 §3.3 — so the token is rejected, not ignored.
    UnsupportedCritHeader,
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
    /// `Options.issuer` is `.required` and `iss` is absent or different.
    IssuerMismatch,
    /// `Options.audience` is `.required` and the value is not contained in
    /// `aud` (RFC 8725 §3.9 confused-deputy defence).
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
    /// RFC 7515 §4.1.11 `crit` — the extension header parameter names the
    /// producer marked critical, exposed so a caller can inspect them.
    /// A `ParsedToken` only ever reaches a caller with this non-null when
    /// **every** listed name is in `understood_crit_headers`; `parse` rejects
    /// the token otherwise (`InvalidCrit` / `UnsupportedCritHeader`). Since
    /// this library implements no JWS extension, that set is empty today and
    /// any `crit` token fails closed.
    crit: ?[]const []const u8 = null,
};

/// Header parameter names this implementation both **understands and
/// actually processes** when a producer lists them in `crit` (RFC 7515
/// §4.1.11). Deliberately empty: this library implements no JWS extension
/// (no RFC 7797 `b64`, no OIDC `at_hash`-style header extension), so there is
/// no name it may honour a `crit` marking for. Adding an extension means
/// adding its name here *and* processing it — never one without the other.
pub const understood_crit_headers: []const []const u8 = &.{};

/// Header parameter names registered by RFC 7515 §4.1 / RFC 7516 §4.1 /
/// RFC 7518, which "MUST NOT" appear in `crit` (RFC 7515 §4.1.11: the list
/// carries *extension* parameters only). Note `b64` (RFC 7797) is absent on
/// purpose — it is an extension whose spec *requires* a `crit` marking.
const registered_header_params = [_][]const u8{
    // RFC 7515 §4.1 (JWS) — incl. the ones this module reads.
    "alg", "jku", "jwk",  "kid", "x5u", "x5c", "x5t", "x5t#S256",
    "typ", "cty", "crit",
    // RFC 7516 §4.1 / RFC 7518 §4.6-4.8 (JWE / key management) — equally
    // registered, so equally forbidden in a `crit` list.
    "enc", "zip", "epk", "apu", "apv",
    "iv",  "tag", "p2s",  "p2c",
};

fn isRegisteredHeaderParam(name: []const u8) bool {
    for (registered_header_params) |r| {
        if (std.mem.eql(u8, r, name)) return true;
    }
    return false;
}

fn isUnderstoodCritHeader(name: []const u8) bool {
    for (understood_crit_headers) |u| {
        if (std.mem.eql(u8, u, name)) return true;
    }
    return false;
}

/// RFC 7515 §4.1.11 `crit`: parse the list, enforce every syntactic rule the
/// RFC states, then fail closed on any name this implementation does not
/// understand. Called from `parse`, so **every** entry point (offline verify,
/// JWKS, `Provider`, `ResourceServer`, `Guard`, the RP's `acceptIdToken*`)
/// inherits the rejection — a critical extension can never be silently
/// ignored.
fn extractCrit(arena: std.mem.Allocator, obj: std.json.ObjectMap) ParseError!?[]const []const u8 {
    const v = obj.get("crit") orelse return null;
    // "the value MUST be an array of Header Parameter names" …
    if (v != .array) return error.InvalidCrit;
    const items = v.array.items;
    // … "MUST NOT be empty" (nor may producers emit an empty entry).
    if (items.len == 0) return error.InvalidCrit;

    const out = try arena.alloc([]const u8, items.len);
    for (items, 0..) |item, i| {
        const name = switch (item) {
            .string => |s| s,
            else => return error.InvalidCrit,
        };
        if (name.len == 0) return error.InvalidCrit;
        // "MUST NOT include Header Parameter names defined by [RFC 7515] or
        // [RFC 7518]".
        if (isRegisteredHeaderParam(name)) return error.InvalidCrit;
        // "MUST NOT include … any Header Parameter … not present in the JOSE
        // Header".
        if (obj.get(name) == null) return error.InvalidCrit;
        // "MUST NOT include duplicate names" — a recipient may treat the JWS
        // as invalid, and this one does.
        for (out[0..i]) |seen| {
            if (std.mem.eql(u8, seen, name)) return error.InvalidCrit;
        }
        out[i] = name;
    }
    // The MUST-reject itself: understood *and* processed, or the JWS is
    // invalid.
    for (out) |name| {
        if (!isUnderstoodCritHeader(name)) return error.UnsupportedCritHeader;
    }
    return out;
}

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
///
/// One header rule IS enforced here, because it is a property of this
/// implementation rather than of caller policy: RFC 7515 §4.1.11 `crit`
/// (see `extractCrit`). A token marking any extension header parameter
/// critical is rejected — never parsed-and-ignored — so no downstream path
/// can accept it.
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
        .crit = try extractCrit(arena, header_obj),
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

/// Audience-validation policy (RFC 7519 §4.1.3 + RFC 8725 §3.9). There is
/// deliberately NO default and NO "skip" that a caller can reach by leaving a
/// field unset: audience validation is mandatory, and the ONLY way to run
/// without it is to write `.any` — a conscious, greppable opt-out. This is the
/// fix for the confused-deputy foot-gun where a same-IdP token minted for a
/// different service was silently accepted.
pub const AudiencePolicy = union(enum) {
    /// The token's `aud` MUST contain this value (else `AudienceMismatch`).
    required: []const u8,
    /// Explicitly skip audience validation. Choosing this accepts the
    /// RFC 8725 §3.9 confused-deputy risk (a token minted for any sibling
    /// service at the same issuer will pass) — only correct when the token's
    /// `aud` is enforced elsewhere or the deployment has a single audience.
    any,
};

/// Issuer-validation policy (RFC 7519 §4.1.1). Same shape and rationale as
/// `AudiencePolicy`: no default, no silent skip — issuer validation is
/// mandatory unless the caller consciously writes `.any`.
pub const IssuerPolicy = union(enum) {
    /// `iss` MUST be present and equal to this value (else `IssuerMismatch`).
    required: []const u8,
    /// Explicitly skip issuer validation (conscious opt-out).
    any,
};

/// Claims-validation options. `now_s` is REQUIRED and caller-supplied
/// (seconds since epoch) — this module has no hidden clock. `issuer` and
/// `audience` are REQUIRED too and have no default: the caller must either
/// pin a value (`.required = …`) or consciously opt out (`.any`). Neither can
/// be silently skipped.
pub const Options = struct {
    /// Current time, seconds since the Unix epoch.
    now_s: i64,
    /// Clock-skew allowance applied to `exp`/`nbf`/`iat` (RFC 7519 §4.1.4
    /// "usually no more than a few minutes").
    leeway_s: u32 = 60,
    /// Expected `iss` — `.required = "…"` enforces it, `.any` opts out. No
    /// default: the choice is mandatory (RFC 8725 §3.8/§3.9 hardening).
    issuer: IssuerPolicy,
    /// Expected `aud` — `.required = "…"` must be contained in the token's
    /// `aud`, `.any` opts out. No default: the choice is mandatory.
    audience: AudiencePolicy,
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
    switch (opts.issuer) {
        .required => |want| {
            const iss = claims.iss orelse return error.IssuerMismatch;
            if (!std.mem.eql(u8, iss, want)) return error.IssuerMismatch;
        },
        .any => {},
    }
    switch (opts.audience) {
        .required => |want| {
            if (!claims.aud.contains(want)) return error.AudienceMismatch;
        },
        .any => {},
    }
}

// ── signature verification (RFC 7515 §5.2, RFC 7518, RFC 8037) ─────────────

/// The asm-accelerated P-256 module — supplies the ES256 key/signature types
/// and the fast vartime verify on the P2 HTTPS per-request hot path.
const p256_mod = @import("p256");

/// std signature schemes re-exported so callers (and P4's JWKS) can name the
/// key types without spelling out the std.crypto paths. ES256 (the P2 HTTPS
/// per-request hot path) runs on the asm-accelerated `p256` module: the key
/// type is a byte-exact drop-in for `std.crypto.sign.ecdsa.EcdsaP256Sha256`,
/// and verification routes through p256's combined 2-base vartime verify
/// (`verifyEs256Fast` below), ~2.7× faster than std. P384 and Ed25519 stay on
/// std (p256 covers only the P-256 curve).
pub const EcdsaP256Sha256 = p256_mod.EcdsaP256Sha256;
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
            .ecdsa_p256 => |pk| try verifyEs256Fast(pk, parsed),
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

/// ES256 fast path — the P2 HTTPS per-request hot path (RFC 7518 §3.4: JWS
/// signature is the raw 64-byte fixed-width big-endian `R‖S`). Routes through
/// p256's combined 2-base vartime verify (`mulDoubleBasePublic`: one
/// multi-scalar `u1·G + u2·Q` instead of std's two separate `mulPublic` +
/// add), ~2.7× faster than `std.crypto.sign.ecdsa.EcdsaP256Sha256.verify` on
/// this host. Accept/reject is byte-identical to that struct's `verify`: same
/// SHA-256 digest, same rejection of a zero or non-canonical (≥ n) `r`/`s`,
/// same `x(u1·G + u2·Q) mod n == r` acceptance (validated in p256's
/// `oracle_test`/`kat_test` against std + RFC 6979). All inputs are public, so
/// the vartime path is the correct (and only) choice — no secret scalar.
fn verifyEs256Fast(public_key: EcdsaP256Sha256.PublicKey, parsed: *const ParsedToken) VerifyError!void {
    const sig_len = EcdsaP256Sha256.Signature.encoded_length; // 64 (R‖S)
    if (parsed.signature.len != sig_len) return error.BadSignature;
    const pk_sec1 = public_key.toUncompressedSec1();
    if (!p256_mod.sign.ecdsaVerify(&pk_sec1, parsed.signing_input, parsed.signature[0..64].*))
        return error.BadSignature;
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
    /// A `kty:"oct"` (symmetric/HMAC) key appeared in a JWKS fetched over the
    /// network. Refused: anyone who can read a published JWKS could otherwise
    /// mint HS* tokens with it (RFC 8725 §3.5 / §2.1 algorithm confusion).
    /// Symmetric keys are accepted ONLY from a locally-configured `parseJwks`.
    oct_from_network,
};

/// Where a JWKS came from — decides whether `kty:"oct"` symmetric keys are
/// trusted. A locally-configured set (`parseJwks`) may carry HMAC secrets; a
/// network-fetched set (`fetchJwks`/`Provider`) may NOT — a public JWKS is
/// readable by attackers, so an `oct` entry there is a forgery vector.
pub const JwkSource = enum { local, network };

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
/// - `kty:"oct"` — `k` → `.hmac`. Accepted ONLY here (a locally-configured,
///   trusted set for HS* dev/test setups); a *symmetric* key has no business
///   in a *published* JWKS — anyone who can read it can mint tokens — so the
///   network path (`fetchJwks`/`Provider`) refuses it (`oct_from_network`).
///
/// Individual JWKs that are malformed or unsupported are skipped and
/// recorded in `skipped` — a set-wide error is returned only when the
/// document itself is not a JWKS. Arbitrary bytes never panic.
pub fn parseJwks(gpa: std.mem.Allocator, json: []const u8) JwksError!JwkSet {
    return parseJwksSource(gpa, json, .local);
}

/// `parseJwks` with an explicit trust source (see `JwkSource`). The public
/// `parseJwks` is the `.local` (trusted) entry point; `fetchJwks` uses
/// `.network`, which refuses `kty:"oct"` symmetric keys.
pub fn parseJwksSource(gpa: std.mem.Allocator, json: []const u8, source: JwkSource) JwksError!JwkSet {
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
        const jwk = jwkFromValue(arena, item, source) catch |err| switch (err) {
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
    OctFromNetwork,
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
        error.OctFromNetwork => .oct_from_network,
    };
}

/// Convert one `keys` array element into a `Jwk` (RFC 7517 §4 members +
/// RFC 7518 §6 / RFC 8037 §2 key material).
fn jwkFromValue(
    arena: std.mem.Allocator,
    val: std.json.Value,
    source: JwkSource,
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
            // RFC 7518 §6.4.1: k — the symmetric secret. A symmetric key in a
            // network-fetched (public) JWKS is a forgery vector — anyone who
            // reads it can mint HS* tokens — so it is refused there and only
            // trusted from a locally-configured set. See parseJwks doc.
            if (source == .network) return error.OctFromNetwork;
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
    /// Where to send the user-agent to start the P7 authorization code flow
    /// (OIDC Discovery §3 `authorization_endpoint` — REQUIRED by the spec for
    /// an OP offering the code flow; optional here so a resource-server-only
    /// discovery document, this struct's original P5 scope, keeps parsing
    /// unchanged when it omits it).
    authorization_endpoint: ?[]const u8 = null,
    /// Where P7's `buildTokenRequest` exchanges a code for tokens (OIDC
    /// Discovery §3 `token_endpoint`) — same optionality rationale.
    token_endpoint: ?[]const u8 = null,
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

    // Optional (P7): present in any OP that offers the authorization code
    // flow, but this struct's original P5 (resource-server) scope never
    // required them, so absence is not an error — only a wrong JSON type is.
    const authorization_endpoint: ?[]const u8 = blk: {
        const v = obj.get("authorization_endpoint") orelse break :blk null;
        break :blk switch (v) {
            .string => |s| s,
            else => return error.DiscoveryFailed,
        };
    };
    const token_endpoint: ?[]const u8 = blk: {
        const v = obj.get("token_endpoint") orelse break :blk null;
        break :blk switch (v) {
            .string => |s| s,
            else => return error.DiscoveryFailed,
        };
    };

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
        .authorization_endpoint = authorization_endpoint,
        .token_endpoint = token_endpoint,
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

/// GET `jwks_uri` and parse the body via `parseJwksSource(…, .network)` (P4):
/// the fetched set is trusted for asymmetric keys only — `kty:"oct"` entries
/// are refused (`oct_from_network`). The returned set owns arena copies of
/// everything — the transfer buffer dies here.
pub fn fetchJwks(
    gpa: std.mem.Allocator,
    fetcher: Fetcher,
    jwks_uri: []const u8,
) FetchJwksError!JwkSet {
    const body_buf = try gpa.alloc(u8, max_response_bytes);
    defer gpa.free(body_buf);
    const res = try fetcher.fetch(jwks_uri, body_buf);
    if (res.status != 200) return error.HttpStatus;
    // `.network`: a fetched JWKS is untrusted for symmetric keys — `oct`
    // entries are refused (an attacker who reads the public set could
    // otherwise forge HS* tokens).
    return parseJwksSource(gpa, res.body, .network);
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

    /// How `Provider.verify` decides the expected `iss`. Unlike the low-level
    /// `IssuerPolicy`, the sensible default here is "enforce the provider's
    /// own issuer", so `.provider` is the default — but a jwks_uri-only
    /// provider that configured NO issuer has nothing to enforce, and rather
    /// than silently skip (the old foot-gun) `verify` then fails closed with
    /// `error.IssuerNotConfigured` unless the caller consciously picks `.any`.
    pub const IssuerCheck = union(enum) {
        /// Enforce the provider's issuer: the OIDC discovery document's
        /// `issuer` (issuer-configured providers) or the configured
        /// `ProviderOptions.issuer`. `error.IssuerNotConfigured` when neither
        /// exists (raw jwks_uri, no issuer) — pick `.required`/`.any` instead.
        provider,
        /// Enforce this exact issuer, overriding the provider's own.
        required: []const u8,
        /// Consciously skip issuer validation (RFC 8725 §3.9 risk accepted).
        any,
    };

    /// Claim policy for `Provider.verify` — `Options` minus `now_s` (passed
    /// per call). `audience` has NO default: binding the token to this
    /// resource server is mandatory (`.required = "…"` or a conscious
    /// `.any`). `issuer` defaults to `.provider` (enforce the discovered /
    /// configured issuer); it is never silently skipped.
    pub const ClaimOptions = struct {
        leeway_s: u32 = 60,
        /// Expected `iss` policy — see `IssuerCheck`. Default `.provider`.
        issuer: IssuerCheck = .provider,
        /// Expected `aud` — `.required = "…"` or a conscious `.any`. No
        /// default: the choice is mandatory (RFC 8725 §3.9).
        audience: AudiencePolicy,
        require_exp: bool = true,
        reject_future_iat: bool = false,
    };

    pub const Error = ParseAndVerifyError || RefreshError || error{
        /// `ClaimOptions.issuer` was `.provider` (the default) but this
        /// provider has no issuer to enforce (raw jwks_uri, none configured).
        /// Fail closed: pin `.issuer = .{ .required = … }` or opt out `.any`.
        IssuerNotConfigured,
    };

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

        // Resolve the mandatory issuer policy. `.provider` (the default) uses
        // the discovered/configured issuer, and fails closed when there is
        // none — issuer validation is never silently skipped.
        const issuer_policy: IssuerPolicy = switch (claim_opts.issuer) {
            .required => |s| .{ .required = s },
            .any => .any,
            .provider => blk: {
                const iss = if (p.metadata) |m| m.issuer else p.options.issuer;
                break :blk .{ .required = iss orelse return error.IssuerNotConfigured };
            },
        };
        try validateClaims(parsed.claims, .{
            .now_s = now_s,
            .leeway_s = claim_opts.leeway_s,
            .issuer = issuer_policy,
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

// ── Part 6: RFC 6750 Bearer resource-server middleware ───────────────────────
//
// A `router.Middleware` that turns a `Provider` into a route guard. The wire
// contract mirrors the aaa-gate sibling: a denied request is answered here
// (401/403 + `WWW-Authenticate`) and the chain is short-circuited (the handler
// never runs); an admitted request carries an `Identity` on `ctx.data` for the
// duration of the inner chain, then `ctx.data` is restored.

/// Wall-clock source giving `now_s` (Unix epoch seconds) to `Provider.verify`
/// — injected so tests are deterministic, mirroring the module's caller-clock
/// rule. Only the default `.system` clock ever touches the OS.
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (?*anyopaque) i64,

    /// The OS wall clock (`std.time.timestamp`). The production default.
    pub const system: Clock = .{ .nowFn = systemNowS };

    pub fn now(c: Clock) i64 {
        return c.nowFn(c.ctx);
    }
};

fn systemNowS(_: ?*anyopaque) i64 {
    // Wall clock (Unix epoch seconds). std has no `time.timestamp` in 0.16.
    switch (builtin.os.tag) {
        .windows => {
            // 100 ns ticks since 1601-01-01; shift to the Unix epoch.
            const hns: i64 = std.os.windows.ntdll.RtlGetSystemTimePrecise();
            return @divFloor(hns - 116444736000000000, 10_000_000);
        },
        else => {
            var ts: std.posix.timespec = undefined;
            if (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts)) != .SUCCESS) return 0;
            return @intCast(ts.sec);
        },
    }
}

/// Serialization seam for the `Provider` under a multi-threaded server.
///
/// `Provider` keeps one mutable JWKS cache and is **not** internally
/// synchronized (see its docs). `http.Server` serves from several connection
/// threads, so `ResourceServer.middleware` calls `Provider.verify` under this
/// lock. It is a *blocking* lock, not a spinlock: `verify` may, rarely, refresh
/// the JWKS over the network while holding it (TTL expiry / key rotation), so a
/// spin would burn a core for the duration of a fetch.
///
/// The default `.none` is a no-op — correct for a single-threaded server or
/// when the caller synchronizes the `Provider` some other way. For the default
/// threaded `http.Server`, plug a real mutex in (`std.Thread.Mutex` when
/// threading is enabled), e.g.:
///
/// ```zig
/// var mu: std.Thread.Mutex = .{};
/// const lock: jwt.Lock = .{
///     .ctx = &mu,
///     .lockFn = struct { fn f(c: ?*anyopaque) void {
///         @as(*std.Thread.Mutex, @ptrCast(@alignCast(c.?))).lock();
///     } }.f,
///     .unlockFn = struct { fn f(c: ?*anyopaque) void {
///         @as(*std.Thread.Mutex, @ptrCast(@alignCast(c.?))).unlock();
///     } }.f,
/// };
/// ```
pub const Lock = struct {
    ctx: ?*anyopaque = null,
    lockFn: *const fn (?*anyopaque) void = noop,
    unlockFn: *const fn (?*anyopaque) void = noop,

    /// No synchronization (single-threaded / caller-synchronized Provider).
    pub const none: Lock = .{};

    fn noop(_: ?*anyopaque) void {}
    fn acquire(l: Lock) void {
        l.lockFn(l.ctx);
    }
    fn release(l: Lock) void {
        l.unlockFn(l.ctx);
    }
};

/// Which methods require a valid token.
pub const Protect = enum {
    /// Every method is gated (the default — secure by default). Register
    /// `cors` before this middleware so browser preflights (which cannot carry
    /// Authorization) are answered before they would 401.
    all,
    /// Only mutations (POST/PUT/PATCH/DELETE) are gated; GET/HEAD/OPTIONS stay
    /// open (no token, no `Identity`).
    mutations,
};

/// What the middleware attaches to `ctx.data` for admitted requests. It
/// borrows the verified `ParsedToken` on the middleware's stack frame — valid
/// only for the inner chain + handler call; do not retain it past the handler.
pub const Identity = struct {
    /// The verified token. Its claims are trustworthy: signature checked
    /// against the JWKS and `exp`/`nbf`/`iss`/`aud` validated per `claim_opts`.
    token: *const ParsedToken,

    /// The `sub` (subject) claim, or null when the token omits it.
    pub fn subject(id: Identity) ?[]const u8 {
        return id.token.claims.sub;
    }

    /// The full verified claim set (registered fields + `claim*` accessors).
    pub fn claims(id: Identity) Claims {
        return id.token.claims;
    }

    /// Iterate the granted scopes — the space-delimited `scope` claim
    /// (RFC 8693 §4.2 / OAuth2 RFC 6749 §3.3). Empty when `scope` is absent.
    pub fn scopes(id: Identity) ScopeIter {
        return .{ .rest = id.token.claims.claimStr("scope") orelse "" };
    }

    /// Whether the granted scopes include `want` (exact token match). Checks
    /// both the `scope` string and the `scp` claim — see `scopeGranted`.
    pub fn hasScope(id: Identity, want: []const u8) bool {
        return scopeGranted(id.token.claims, want);
    }
};

/// Splits a `scope` claim value into individual scope tokens on ASCII space
/// (RFC 6749 §3.3 uses one SP; runs and surrounding SP are tolerated).
pub const ScopeIter = struct {
    rest: []const u8,

    pub fn next(it: *ScopeIter) ?[]const u8 {
        while (it.rest.len > 0 and it.rest[0] == ' ') it.rest = it.rest[1..];
        if (it.rest.len == 0) return null;
        const end = std.mem.indexOfScalar(u8, it.rest, ' ') orelse it.rest.len;
        const tok = it.rest[0..end];
        it.rest = it.rest[end..];
        return tok;
    }
};

/// Whether `claims` grants the scope `want`. An access token may carry its
/// authorized scopes two ways, and both are checked (case-sensitive, exact
/// token match):
///   * `scope` — the space-delimited string of RFC 6749 §3.3 / RFC 8693 §4.2,
///     the representation RFC 9068 §2.2.3 prescribes for `at+jwt`; and
///   * `scp`   — used by some issuers (notably Microsoft identity platform)
///     and appearing in RFC 9068's own examples; either a JSON array of
///     strings or a single space-delimited string.
/// An empty `want` never matches.
pub fn scopeGranted(claims: Claims, want: []const u8) bool {
    if (want.len == 0) return false;
    if (claims.claimStr("scope")) |s| {
        var it: ScopeIter = .{ .rest = s };
        while (it.next()) |tok| if (std.mem.eql(u8, tok, want)) return true;
    }
    if (claims.claim("scp")) |v| switch (v) {
        .array => |arr| for (arr.items) |el| switch (el) {
            .string => |es| if (std.mem.eql(u8, es, want)) return true,
            else => {},
        },
        .string => |s| {
            var it: ScopeIter = .{ .rest = s };
            while (it.next()) |tok| if (std.mem.eql(u8, tok, want)) return true;
        },
        else => {},
    };
    return false;
}

/// Raised by the `require*Scope*` helpers when the granted scopes do not
/// satisfy the policy. Maps to RFC 6750 §3.1 `insufficient_scope` (HTTP 403).
pub const ScopeError = error{InsufficientScope};

/// Require the single scope `want` (RFC 6750 §3.1).
pub fn requireScope(claims: Claims, want: []const u8) ScopeError!void {
    if (!scopeGranted(claims, want)) return error.InsufficientScope;
}

/// Require EVERY scope in `wants` (conjunction). An empty `wants` is a no-op
/// (no scope constraint) — a granted scope set is unordered (RFC 6749 §3.3).
pub fn requireAllScopes(claims: Claims, wants: []const []const u8) ScopeError!void {
    for (wants) |w| if (!scopeGranted(claims, w)) return error.InsufficientScope;
}

/// Require AT LEAST ONE scope in `wants` (disjunction). An empty `wants` is a
/// no-op (no scope constraint), matching `requireAllScopes`.
pub fn requireAnyScope(claims: Claims, wants: []const []const u8) ScopeError!void {
    if (wants.len == 0) return;
    for (wants) |w| if (scopeGranted(claims, w)) return;
    return error.InsufficientScope;
}

/// Retrieve the `Identity` a `ResourceServer` attached, or null (out-of-scope
/// method, or no such middleware ran). Only valid inside the middleware's inner
/// chain. NOTE: `ctx.data` is a single shared slot — do not stack this behind
/// another identity-attaching middleware (e.g. aaa-gate) on the same routes.
pub fn identityOf(ctx: *const router.Ctx) ?*Identity {
    return @ptrCast(@alignCast(ctx.data orelse return null));
}

/// A `router.Middleware` enforcing a JWT Bearer policy backed by a `Provider`.
/// Precomputes its `WWW-Authenticate` challenge strings at `init` (they must be
/// stable memory — `router`'s response writer stores header slices, it does not
/// copy them). The `ResourceServer` and its `Provider` must outlive the Router,
/// at stable addresses (the middleware's `state` points at the ResourceServer).
pub const ResourceServer = struct {
    gpa: std.mem.Allocator,
    provider: *Provider,
    claim_opts: Provider.ClaimOptions,
    protect: Protect,
    clock: Clock,
    lock: Lock,
    /// Required scopes (conjunction — every one must be present), gpa-owned.
    required_scopes: [][]const u8,
    /// `WWW-Authenticate` for a missing/malformed credential (bare `Bearer`,
    /// no `error=` — RFC 6750 §3), gpa-owned.
    challenge_missing: []const u8,
    /// `WWW-Authenticate` for a present-but-rejected token
    /// (`error="invalid_token"`), gpa-owned.
    challenge_invalid: []const u8,
    /// `WWW-Authenticate` for a missing scope
    /// (`error="insufficient_scope", scope="…"`); null when no scope is
    /// required. gpa-owned.
    challenge_scope: ?[]const u8,

    pub const Options = struct {
        /// The verifier backing the guard. Must outlive the Router.
        provider: *Provider,
        /// Claim policy handed to `Provider.verify`. REQUIRED — no default:
        /// `Provider.ClaimOptions.audience` must be set (`.required = "…"` to
        /// bind tokens to this resource server per RFC 8725 §3.9, or a
        /// conscious `.any`). Issuer is enforced automatically for
        /// issuer-configured providers.
        claim_opts: Provider.ClaimOptions,
        /// Scopes every in-scope request must carry (ALL required). Empty ⇒
        /// authenticate only, no scope check.
        required_scopes: []const []const u8 = &.{},
        /// Which methods require a token.
        protect: Protect = .all,
        /// Wall clock for `now_s`. Injected for tests; `.system` in production.
        clock: Clock = .system,
        /// Serialization for the Provider cache under a threaded server (see
        /// `Lock`). Default `.none` = single-threaded / externally synced.
        lock: Lock = .none,
        /// Optional protection-space label placed in the challenge
        /// (`Bearer realm="…"`). Must not contain '"', CR, LF or NUL.
        realm: ?[]const u8 = null,
    };

    pub const InitError = error{ OutOfMemory, InvalidRealm };

    pub fn init(gpa: std.mem.Allocator, options: ResourceServer.Options) InitError!ResourceServer {
        if (options.realm) |r| try validateRealm(r);

        // Precompute the challenge strings (stable memory — `router`'s response
        // writer stores header slices without copying) via the shared helpers.
        const challenge_missing = try allocBearerChallenge(gpa, .{ .realm = options.realm });
        errdefer gpa.free(challenge_missing);
        const challenge_invalid = try allocBearerChallenge(gpa, .{
            .realm = options.realm,
            .error_code = "invalid_token",
        });
        errdefer gpa.free(challenge_invalid);

        // Own the required scopes (the config slice may be transient) and, if
        // any, precompute the space-joined insufficient-scope challenge.
        const scopes = try dupeScopeList(gpa, options.required_scopes);
        errdefer freeScopeList(gpa, scopes);

        const challenge_scope: ?[]const u8 = if (options.required_scopes.len == 0)
            null
        else
            try allocBearerChallenge(gpa, .{
                .realm = options.realm,
                .error_code = "insufficient_scope",
                .scopes = options.required_scopes,
            });

        return .{
            .gpa = gpa,
            .provider = options.provider,
            .claim_opts = options.claim_opts,
            .protect = options.protect,
            .clock = options.clock,
            .lock = options.lock,
            .required_scopes = scopes,
            .challenge_missing = challenge_missing,
            .challenge_invalid = challenge_invalid,
            .challenge_scope = challenge_scope,
        };
    }

    pub fn deinit(rs: *ResourceServer) void {
        for (rs.required_scopes) |s| rs.gpa.free(s);
        rs.gpa.free(rs.required_scopes);
        rs.gpa.free(rs.challenge_missing);
        rs.gpa.free(rs.challenge_invalid);
        if (rs.challenge_scope) |c| rs.gpa.free(c);
        rs.* = undefined;
    }

    /// A `router.Middleware` enforcing this policy (`state` = the
    /// ResourceServer). Register it once, before routes.
    pub fn middleware(rs: *ResourceServer) router.Middleware {
        return .{ .state = rs, .run = middlewareRun };
    }
};

fn resourceMethodMutating(m: http.Method) bool {
    return switch (m) {
        .post, .put, .delete, .patch => true,
        .get, .head, .options => false,
    };
}

/// The bearer token of the request, or null when the Authorization header is
/// absent, uses another scheme, or is malformed. Never panics; scheme match is
/// case-insensitive (RFC 9110), surrounding whitespace tolerated.
fn resourceBearerToken(req: *const http.Server.Request) ?[]const u8 {
    const auth = req.header("authorization") orelse return null;
    const value = std.mem.trim(u8, auth, " \t");
    if (value.len < "Bearer ".len) return null;
    if (!std.ascii.eqlIgnoreCase(value[0..6], "Bearer")) return null;
    if (value[6] != ' ') return null;
    const tok = std.mem.trim(u8, value[7..], " \t");
    if (tok.len == 0) return null;
    return tok;
}

/// Human-readable reason for the 401 body — the `WWW-Authenticate` header
/// carries only the RFC 6750 error *code*; the specific cause goes in the body
/// (written through the response writer, which copies, so a transient string is
/// fine here). Nothing token-derived is echoed.
fn resourceInvalidReason(err: anyerror) []const u8 {
    return switch (err) {
        error.Expired => "token expired",
        error.NotYetValid => "token not yet valid",
        error.IssuedInFuture => "token issued in the future",
        error.IssuerMismatch => "issuer mismatch",
        error.AudienceMismatch => "audience mismatch",
        error.MissingExp => "token missing exp",
        error.BadSignature => "bad signature",
        error.UnsecuredToken => "unsecured token rejected",
        error.AlgKeyMismatch, error.UnsupportedAlg => "unsupported algorithm",
        error.NoMatchingKey => "no matching key",
        error.IssuerNotConfigured => "issuer not configured",
        error.DiscoveryFailed, error.JwksFetchFailed => "key set unavailable",
        error.MalformedToken, error.InvalidBase64, error.InvalidJson, error.NotAnObject => "malformed token",
        else => "invalid token",
    };
}

fn resourceDeny(
    ctx: *router.Ctx,
    status: u16,
    challenge: []const u8,
    body: []const u8,
) anyerror!void {
    ctx.res.setStatus(status);
    try ctx.res.setHeader("WWW-Authenticate", challenge);
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll(body);
}

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const rs: *ResourceServer = @ptrCast(@alignCast(state.?));

    const in_scope = switch (rs.protect) {
        .all => true,
        .mutations => resourceMethodMutating(ctx.req.method),
    };
    if (!in_scope) return next.run(ctx);

    const token = resourceBearerToken(ctx.req) orelse
        return resourceDeny(ctx, 401, rs.challenge_missing, "Unauthorized\n");

    const now_s = rs.clock.now();
    rs.lock.acquire();
    const verify_result = rs.provider.verify(rs.gpa, token, now_s, rs.claim_opts);
    rs.lock.release();

    var verified = verify_result catch |err| {
        // Provider.verify only fails the request — it never leaks a token.
        // OOM is a server fault (500), not an auth failure: propagate it.
        if (err == error.OutOfMemory) return err;
        return resourceDeny(ctx, 401, rs.challenge_invalid, resourceInvalidReason(err));
    };
    defer verified.deinit();

    var ident: Identity = .{ .token = &verified };
    for (rs.required_scopes) |need| {
        if (!ident.hasScope(need))
            return resourceDeny(ctx, 403, rs.challenge_scope.?, "Insufficient scope\n");
    }

    const saved = ctx.data;
    ctx.data = &ident;
    defer ctx.data = saved;
    return next.run(ctx);
}

// ── Part 6b: framework-agnostic Bearer guard + WWW-Authenticate helper ───────
//
// `ResourceServer` above is the `router`-native middleware. `Guard` is the SAME
// RFC 6750 + RFC 9068 policy without a web framework: `authenticate(req)`
// returns a validated `AuthContext` or a structured `AuthError` the caller maps
// to 401/403 with `challengeFor`. Both wrap the exact same `Provider.verify` and
// scope/challenge helpers — no signature verification is duplicated.

/// RFC 6750 §3 `WWW-Authenticate: Bearer` challenge parameters.
pub const BearerChallengeParams = struct {
    /// Optional protection-space label (`realm="…"`). Callers building the
    /// header directly must ensure it contains no '"', CR, LF or NUL;
    /// `Guard.init`/`ResourceServer.init` validate it (`error.InvalidRealm`).
    realm: ?[]const u8 = null,
    /// RFC 6750 §3.1 error code (`"invalid_token"`, `"insufficient_scope"`, …),
    /// or null for the bare challenge returned when NO credential was supplied.
    error_code: ?[]const u8 = null,
    /// Scopes advertised as `scope="a b c"` — space-joined and emitted ONLY
    /// when non-empty (i.e. alongside `insufficient_scope`, RFC 6750 §3.1).
    scopes: []const []const u8 = &.{},
};

/// Write an RFC 6750 §3 `WWW-Authenticate: Bearer …` header *value* to `w` —
/// the header-value helper a resource server uses for its 401/403 challenges.
/// `Guard` and `ResourceServer` precompute their challenge strings with it.
///
/// Grammar (RFC 7235 §2.1): `challenge = auth-scheme [ 1*SP ( token68 /
/// #auth-param ) ]`. `#auth-param` is a **comma**-delimited list (RFC 7230
/// §7), which is also the form of RFC 6750 §3's own example
/// (`Bearer realm="example", error="invalid_token", …`): one space after the
/// scheme, then `", "` between parameters. Space-separated parameters are
/// malformed — a conforming `1#challenge` parser splitting on commas would
/// read the tail as a second challenge with a bogus auth-scheme.
pub fn writeBearerChallenge(w: *Writer, p: BearerChallengeParams) Writer.Error!void {
    try w.writeAll("Bearer");
    var wrote_param = false;
    if (p.realm) |r| {
        try writeAuthParamSep(w, &wrote_param);
        try w.writeAll("realm=\"");
        try w.writeAll(r);
        try w.writeByte('"');
    }
    if (p.error_code) |code| {
        try writeAuthParamSep(w, &wrote_param);
        try w.writeAll("error=\"");
        try w.writeAll(code);
        try w.writeByte('"');
    }
    if (p.scopes.len != 0) {
        try writeAuthParamSep(w, &wrote_param);
        try w.writeAll("scope=\"");
        for (p.scopes, 0..) |s, i| {
            if (i != 0) try w.writeByte(' ');
            try w.writeAll(s);
        }
        try w.writeByte('"');
    }
}

/// The `auth-scheme`→first-param separator is SP; every later one is `", "`
/// (RFC 7235 §2.1 + RFC 7230 §7 list syntax).
fn writeAuthParamSep(w: *Writer, wrote_param: *bool) Writer.Error!void {
    try w.writeAll(if (wrote_param.*) ", " else " ");
    wrote_param.* = true;
}

fn allocBearerChallenge(gpa: std.mem.Allocator, p: BearerChallengeParams) error{OutOfMemory}![]const u8 {
    var aw: Writer.Allocating = .init(gpa);
    defer aw.deinit();
    writeBearerChallenge(&aw.writer, p) catch |err| switch (err) {
        error.WriteFailed => return error.OutOfMemory, // Allocating writer: alloc failure
    };
    return aw.toOwnedSlice();
}

/// A realm string is embedded verbatim in a `"…"`-quoted header parameter, so
/// it must not carry a character that would break out of the quoting.
fn validateRealm(realm: []const u8) error{InvalidRealm}!void {
    for (realm) |c| if (c == '"' or c == '\r' or c == '\n' or c == 0) return error.InvalidRealm;
}

/// Deep-copy a (possibly transient) scope list so a guard can outlive the
/// caller's config slice. Frees partial work on OOM.
fn dupeScopeList(gpa: std.mem.Allocator, scopes: []const []const u8) error{OutOfMemory}![][]const u8 {
    const out = try gpa.alloc([]const u8, scopes.len);
    errdefer gpa.free(out);
    var owned: usize = 0;
    errdefer for (out[0..owned]) |s| gpa.free(s);
    for (scopes, 0..) |s, i| {
        out[i] = try gpa.dupe(u8, s);
        owned = i + 1;
    }
    return out;
}

fn freeScopeList(gpa: std.mem.Allocator, scopes: [][]const u8) void {
    for (scopes) |s| gpa.free(s);
    gpa.free(scopes);
}

/// The outcome of `Guard.authenticate` on failure. `authStatus` maps each to
/// its RFC 6750 §3.1 HTTP status; `Guard.challengeFor` to its challenge string.
pub const AuthError = error{
    /// No Authorization header, a non-Bearer scheme, or an empty token —
    /// RFC 6750 §3: answer 401 with the bare `Bearer` challenge (no `error=`).
    MissingToken,
    /// A Bearer token was present but failed signature/claim validation or the
    /// `at+jwt` typ policy — RFC 6750 §3.1 `invalid_token` (401).
    InvalidToken,
    /// The token is valid but lacks a required scope — RFC 6750 §3.1
    /// `insufficient_scope` (403).
    InsufficientScope,
    /// Server-side allocation failure — NOT an authentication decision. Map to
    /// 500 and send no `WWW-Authenticate`.
    OutOfMemory,
};

/// The RFC 6750 §3.1 HTTP status for an `AuthError` (`OutOfMemory` ⇒ 500, a
/// server fault rather than an auth denial).
pub fn authStatus(err: AuthError) u16 {
    return switch (err) {
        error.MissingToken, error.InvalidToken => 401,
        error.InsufficientScope => 403,
        error.OutOfMemory => 500,
    };
}

/// The validated principal `Guard.authenticate` returns. It OWNS the verified
/// token (unlike the middleware's borrowed `Identity`); call `deinit` when the
/// request is done. Every claim it exposes is trustworthy: the signature was
/// checked against the JWKS and `exp`/`nbf`/`iss`/`aud` validated.
pub const AuthContext = struct {
    token: ParsedToken,

    pub fn deinit(self: *AuthContext) void {
        self.token.deinit();
    }

    /// The `sub` (subject) claim, or null when absent.
    pub fn subject(self: *const AuthContext) ?[]const u8 {
        return self.token.claims.sub;
    }

    /// The full verified claim set.
    pub fn claims(self: *const AuthContext) Claims {
        return self.token.claims;
    }

    /// Whether the granted scopes include `want` (`scope` or `scp`).
    pub fn hasScope(self: *const AuthContext, want: []const u8) bool {
        return scopeGranted(self.token.claims, want);
    }

    /// Iterate the space-delimited `scope` claim (see `ScopeIter`).
    pub fn scopes(self: *const AuthContext) ScopeIter {
        return .{ .rest = self.token.claims.claimStr("scope") orelse "" };
    }
};

/// RFC 9068 §2.1: the `at+jwt` (or media-type `application/at+jwt`) header
/// `typ`, matched case-insensitively.
fn isAtJwtTyp(typ: ?[]const u8) bool {
    const t = typ orelse return false;
    return std.ascii.eqlIgnoreCase(t, "at+jwt") or
        std.ascii.eqlIgnoreCase(t, "application/at+jwt");
}

/// A framework-agnostic RFC 6750 Bearer + RFC 9068 access-token guard over a
/// `Provider`. Configure it once (it precomputes its `WWW-Authenticate`
/// challenge strings at `init` — stable memory the caller may hand to any
/// response writer) and call `authenticate` per request. The `Guard` and its
/// `Provider` must outlive every in-flight request, at stable addresses.
pub const Guard = struct {
    gpa: std.mem.Allocator,
    provider: *Provider,
    claim_opts: Provider.ClaimOptions,
    /// Scopes every request must carry (conjunction — ALL required), gpa-owned.
    required_scopes: [][]const u8,
    /// Enforce RFC 9068 §2.1 `typ: at+jwt` on the JOSE header.
    require_at_jwt_typ: bool,
    clock: Clock,
    lock: Lock,
    challenge_missing: []const u8,
    challenge_invalid: []const u8,
    challenge_scope: ?[]const u8,

    pub const Options = struct {
        /// The verifier backing the guard. Must outlive every request.
        provider: *Provider,
        /// Claim policy handed to `Provider.verify`. REQUIRED — `audience`
        /// has no default (`.required = "…"` to bind tokens to this resource
        /// server per RFC 8725 §3.9, or a conscious `.any`).
        claim_opts: Provider.ClaimOptions,
        /// Scopes every request must carry (ALL required). Empty ⇒ authenticate
        /// only, no scope check.
        required_scopes: []const []const u8 = &.{},
        /// Enforce RFC 9068 §2.1 `typ: at+jwt`. Off by default (many issuers
        /// still omit it); turn on for RFC 9068 access tokens.
        require_at_jwt_typ: bool = false,
        /// Wall clock for `now_s`. Injected for tests; `.system` in production.
        clock: Clock = .system,
        /// Serialization for the Provider cache under a threaded server (see
        /// `Lock`). Default `.none` = single-threaded / externally synced.
        lock: Lock = .none,
        /// Optional protection-space label placed in the challenge
        /// (`Bearer realm="…"`). Must not contain '"', CR, LF or NUL.
        realm: ?[]const u8 = null,
    };

    pub const InitError = error{ OutOfMemory, InvalidRealm };

    pub fn init(gpa: std.mem.Allocator, options: Guard.Options) InitError!Guard {
        if (options.realm) |r| try validateRealm(r);

        const challenge_missing = try allocBearerChallenge(gpa, .{ .realm = options.realm });
        errdefer gpa.free(challenge_missing);
        const challenge_invalid = try allocBearerChallenge(gpa, .{
            .realm = options.realm,
            .error_code = "invalid_token",
        });
        errdefer gpa.free(challenge_invalid);

        const scopes = try dupeScopeList(gpa, options.required_scopes);
        errdefer freeScopeList(gpa, scopes);

        const challenge_scope: ?[]const u8 = if (options.required_scopes.len == 0)
            null
        else
            try allocBearerChallenge(gpa, .{
                .realm = options.realm,
                .error_code = "insufficient_scope",
                .scopes = options.required_scopes,
            });

        return .{
            .gpa = gpa,
            .provider = options.provider,
            .claim_opts = options.claim_opts,
            .required_scopes = scopes,
            .require_at_jwt_typ = options.require_at_jwt_typ,
            .clock = options.clock,
            .lock = options.lock,
            .challenge_missing = challenge_missing,
            .challenge_invalid = challenge_invalid,
            .challenge_scope = challenge_scope,
        };
    }

    pub fn deinit(g: *Guard) void {
        freeScopeList(g.gpa, g.required_scopes);
        g.gpa.free(g.challenge_missing);
        g.gpa.free(g.challenge_invalid);
        if (g.challenge_scope) |c| g.gpa.free(c);
        g.* = undefined;
    }

    /// Validate the request's Bearer access token against the full policy and
    /// return the principal, or a structured `AuthError`. The steps, in order:
    /// extract the `Bearer` credential (RFC 6750 §2.1) → `Provider.verify`
    /// (signature + `exp`/`nbf`/`iat`/`iss`/`aud`) → optional RFC 9068 `at+jwt`
    /// typ → required scopes. `tok_gpa` allocates the returned `AuthContext`
    /// (deinit it when done); `OutOfMemory` is a server fault, not a denial.
    pub fn authenticate(
        g: *Guard,
        tok_gpa: std.mem.Allocator,
        req: *const http.Server.Request,
    ) AuthError!AuthContext {
        const token = resourceBearerToken(req) orelse return error.MissingToken;

        const now_s = g.clock.now();
        g.lock.acquire();
        const verify_result = g.provider.verify(tok_gpa, token, now_s, g.claim_opts);
        g.lock.release();

        var verified = verify_result catch |err| {
            // verify frees its own partial token on failure and never leaks it.
            if (err == error.OutOfMemory) return error.OutOfMemory;
            return error.InvalidToken;
        };
        errdefer verified.deinit();

        if (g.require_at_jwt_typ and !isAtJwtTyp(verified.header.typ))
            return error.InvalidToken;

        for (g.required_scopes) |need| {
            if (!scopeGranted(verified.claims, need)) return error.InsufficientScope;
        }

        return .{ .token = verified };
    }

    /// The precomputed `WWW-Authenticate` value for a denial (null for
    /// `OutOfMemory`, which is a 500 and carries no challenge). Stable memory —
    /// safe to hand to a response writer that stores the slice without copying.
    pub fn challengeFor(g: *const Guard, err: AuthError) ?[]const u8 {
        return switch (err) {
            error.MissingToken => g.challenge_missing,
            error.InvalidToken => g.challenge_invalid,
            error.InsufficientScope => g.challenge_scope,
            error.OutOfMemory => null,
        };
    }
};

// ── Part 7: OAuth2/OIDC relying-party (RP) flow ─────────────────────────────
// Clean-room from RFC 6749 (OAuth 2.0 Authorization Framework), RFC 7636
// (PKCE) and OpenID Connect Core 1.0 §3.1 (Authorization Code Flow) + §3.1.3.7
// (ID Token Validation). This is what turns the module from a resource-server
// -only *validator* into a relying party too: build the authorization
// request, build the code→token exchange request (the caller performs the
// actual HTTP — see the module's I/O philosophy, same `Fetcher`-seam spirit
// as P5), parse the token response, and accept the returned ID Token through
// the SAME `verify`/`Provider` machinery Parts 2-5 already built — no
// duplicated crypto, no new dependency (still std-only over what P1-P6
// already import).
//
// DPoP (RFC 9449, proof-of-possession access tokens) is explicitly DEFERRED
// — it needs client-held key management and a per-request proof JWT, a
// materially bigger and separable feature; see SPEC.md.

/// RFC 7636 §4.2: the `code_challenge_method`.
pub const ChallengeMethod = enum {
    /// `code_challenge = base64url(SHA-256(code_verifier))` — RECOMMENDED,
    /// the only method OIDC Core requires every conformant OP to support.
    S256,
    /// `code_challenge = code_verifier`, verbatim (RFC 7636 §4.2) —
    /// DISCOURAGED: it only protects against a *code* interception that does
    /// not also observe the (identical) challenge on the wire, which is a
    /// much weaker guarantee than S256's one-way hash. Use only against an
    /// AS/OP known not to support S256.
    plain,

    /// The wire value sent as `code_challenge_method` (and compared against
    /// an AS's advertised `code_challenge_methods_supported`).
    pub fn wireName(m: ChallengeMethod) []const u8 {
        return switch (m) {
            .S256 => "S256",
            .plain => "plain",
        };
    }
};

/// `code_verifier` length: `base64url(32 CSPRNG bytes)`, no padding = 43
/// characters — within RFC 7636 §4.1's required 43-128 range, entirely
/// unreserved-alphabet, and exactly how the RFC's own Appendix B example is
/// constructed (`pkceChallengeS256` reproduces that vector byte-exact).
pub const pkce_verifier_len: usize = 43;
/// S256 challenge length: `base64url(SHA-256(verifier))`, no padding = 43.
pub const pkce_challenge_len: usize = 43;

/// A generated `code_verifier`/`code_challenge` pair (RFC 7636 §4.1/§4.2).
/// Send `verifier()` in the token-exchange request
/// (`TokenRequestParams.code_verifier`) and keep it only where the client
/// that will redeem the code can read it (session, closure — never logged);
/// send `challenge()` + `method` in the authorization request
/// (`AuthorizationRequest.code_challenge`/`.code_challenge_method`).
pub const Pkce = struct {
    verifier_buf: [pkce_verifier_len]u8,
    challenge_buf: [pkce_challenge_len]u8,
    method: ChallengeMethod,

    pub fn verifier(p: *const Pkce) []const u8 {
        return &p.verifier_buf;
    }

    /// The `code_challenge` to send in the authorization request: the S256
    /// digest for `.S256`, or the verifier itself (per `.plain`'s
    /// definition) for `.plain`.
    pub fn challenge(p: *const Pkce) []const u8 {
        return switch (p.method) {
            .S256 => &p.challenge_buf,
            .plain => &p.verifier_buf,
        };
    }
};

/// Generate a PKCE pair with the RECOMMENDED `S256` method (RFC 7636 §4.2) —
/// use this unless the authorization server is known not to support it (then
/// see `pkceGeneratePlain`). `random` MUST be a cryptographically secure
/// source: this module has no hidden RNG, the same caller-injected seam the
/// `jwe` sibling uses (std 0.16 removed `std.crypto.random`) —
/// `std.Random.DefaultCsprng` seeded from real OS entropy in production,
/// deterministic in tests. See `pkceChallengeS256` to derive a challenge
/// from an externally-supplied verifier instead of generating one.
pub fn pkceGenerateS256(random: std.Random) Pkce {
    var verifier_buf: [pkce_verifier_len]u8 = undefined;
    var raw: [32]u8 = undefined;
    random.bytes(&raw);
    _ = std.base64.url_safe_no_pad.Encoder.encode(&verifier_buf, &raw);
    var challenge_buf: [pkce_challenge_len]u8 = undefined;
    pkceChallengeS256(&verifier_buf, &challenge_buf);
    return .{ .verifier_buf = verifier_buf, .challenge_buf = challenge_buf, .method = .S256 };
}

/// Generate a PKCE pair with the `plain` fallback (RFC 7636 §4.2) —
/// DISCOURAGED, see `ChallengeMethod.plain`'s doc. Only for an AS/OP that
/// does not support `S256`.
pub fn pkceGeneratePlain(random: std.Random) Pkce {
    var verifier_buf: [pkce_verifier_len]u8 = undefined;
    var raw: [32]u8 = undefined;
    random.bytes(&raw);
    _ = std.base64.url_safe_no_pad.Encoder.encode(&verifier_buf, &raw);
    return .{ .verifier_buf = verifier_buf, .challenge_buf = verifier_buf, .method = .plain };
}

/// Compute the S256 `code_challenge` for an arbitrary `code_verifier` (RFC
/// 7636 §4.2): `base64url(SHA-256(ASCII(verifier)))`, no padding. Exposed
/// separately from generation so a challenge can be derived from an
/// externally-supplied verifier — e.g. to reproduce the RFC's own KAT
/// (Appendix B): verifier `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` →
/// challenge `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM`.
pub fn pkceChallengeS256(verifier: []const u8, out: *[pkce_challenge_len]u8) void {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(verifier, &digest, .{});
    _ = std.base64.url_safe_no_pad.Encoder.encode(out, &digest);
}

/// Length of a generated `state`/`nonce`: `base64url(32 CSPRNG bytes)`, no
/// padding — 43 characters, ~256 bits of entropy.
pub const csrf_token_len: usize = 43;

/// Generate the CSRF `state` parameter (RFC 6749 §10.12) — an opaque,
/// unguessable value the RP stores (session / signed cookie) and compares
/// byte-for-byte against the value the AS/OP echoes back on redirect. This is
/// what stops an attacker from tricking a victim's browser into completing
/// *the attacker's* authorization flow (login CSRF). `random` MUST be a real
/// CSPRNG — see `pkceGenerateS256`'s note.
pub fn generateState(random: std.Random) [csrf_token_len]u8 {
    return generateCsrfToken(random);
}

/// Generate the OIDC `nonce` parameter (OIDC Core §3.1.2.1) — bound into the
/// ID Token and checked by `acceptIdToken`/`acceptIdTokenJwks`/
/// `acceptIdTokenProvider` to bind the token to THIS authorization attempt,
/// preventing ID Token replay/injection across attempts. `random` MUST be a
/// real CSPRNG.
pub fn generateNonce(random: std.Random) [csrf_token_len]u8 {
    return generateCsrfToken(random);
}

fn generateCsrfToken(random: std.Random) [csrf_token_len]u8 {
    var raw: [32]u8 = undefined;
    random.bytes(&raw);
    var out: [csrf_token_len]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&out, &raw);
    return out;
}

/// Inputs for `buildAuthorizationUrl` (OIDC Core §3.1.2.1 / RFC 6749 §4.1.1).
/// Always emits `response_type=code` — this module builds the authorization
/// *code* flow (with mandatory PKCE); implicit/hybrid response types are out
/// of scope.
pub const AuthorizationRequest = struct {
    client_id: []const u8,
    redirect_uri: []const u8,
    /// Space-delimited scopes (RFC 6749 §3.3). OIDC requires at least
    /// `"openid"` to get an ID Token back.
    scope: []const u8 = "openid",
    /// CSRF defense — from `generateState`; the caller verifies the callback
    /// echoes it back before trusting anything else in the response.
    state: []const u8,
    /// ID-token replay defense — from `generateNonce`.
    nonce: []const u8,
    /// From `Pkce.challenge()`.
    code_challenge: []const u8,
    /// From the same `Pkce`'s `.method`.
    code_challenge_method: ChallengeMethod,
};

pub const BuildRequestError = error{OutOfMemory};

/// Build the full authorization-request URL against `authorization_endpoint`
/// (from Discovery's `Metadata.authorization_endpoint`, or an endpoint
/// configured directly) — redirect the user-agent here to start the flow.
/// Every value is percent-encoded (RFC 3986 §2.1, unreserved-characters-only
/// — conservative and always correct for a URI query component, and
/// compatible with `http.body.urlencoded`'s decoder). gpa-owned; caller
/// frees.
pub fn buildAuthorizationUrl(
    gpa: std.mem.Allocator,
    authorization_endpoint: []const u8,
    req: AuthorizationRequest,
) BuildRequestError![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(gpa);
    try buf.appendSlice(gpa, authorization_endpoint);
    try buf.append(gpa, if (std.mem.indexOfScalar(u8, authorization_endpoint, '?') == null) '?' else '&');

    var first = true;
    try appendUrlEncodedField(gpa, &buf, &first, "response_type", "code");
    try appendUrlEncodedField(gpa, &buf, &first, "client_id", req.client_id);
    try appendUrlEncodedField(gpa, &buf, &first, "redirect_uri", req.redirect_uri);
    try appendUrlEncodedField(gpa, &buf, &first, "scope", req.scope);
    try appendUrlEncodedField(gpa, &buf, &first, "state", req.state);
    try appendUrlEncodedField(gpa, &buf, &first, "nonce", req.nonce);
    try appendUrlEncodedField(gpa, &buf, &first, "code_challenge", req.code_challenge);
    try appendUrlEncodedField(gpa, &buf, &first, "code_challenge_method", req.code_challenge_method.wireName());
    return buf.toOwnedSlice(gpa);
}

/// Client authentication for the token-endpoint request (RFC 6749 §2.3).
pub const ClientAuth = union(enum) {
    /// Public client — PKCE alone authenticates the code exchange (the
    /// typical SPA/native-app flow; no client secret exists to leak).
    none,
    /// Confidential client, `client_secret_post` (RFC 6749 §2.3.1): the
    /// secret travels in the request body. `client_secret_basic` (HTTP Basic
    /// auth on the request itself) is a caller concern — set the
    /// `Authorization` header on the returned `TokenRequest` yourself; this
    /// builder only produces the body.
    client_secret_post: []const u8,
};

/// Inputs to `buildTokenRequest` — the authorization-code grant (RFC 6749
/// §4.1.3) plus the PKCE `code_verifier` (RFC 7636 §4.5).
pub const TokenRequestParams = struct {
    /// The `code` the AS/OP returned on the callback.
    code: []const u8,
    /// MUST be byte-identical to the `redirect_uri` sent in the
    /// authorization request (RFC 6749 §4.1.3).
    redirect_uri: []const u8,
    client_id: []const u8,
    /// From the `Pkce` generated for this flow — `Pkce.verifier()`.
    code_verifier: []const u8,
    client_auth: ClientAuth = .none,
};

/// A prepared token-endpoint request: method/url/content-type/body for the
/// caller's HTTP client to send (this module does no I/O — see the
/// module-level design notes, same seam philosophy as P5's `Fetcher`). `url`
/// borrows `token_endpoint` (keep it alive until sent); `body` is gpa-owned —
/// free it via `deinit`.
pub const TokenRequest = struct {
    method: http.Method = .post,
    url: []const u8,
    content_type: []const u8 = "application/x-www-form-urlencoded",
    body: []u8,

    pub fn deinit(self: *TokenRequest, gpa: std.mem.Allocator) void {
        gpa.free(self.body);
        self.* = undefined;
    }
};

/// Build the authorization-code token-exchange request (RFC 6749 §4.1.3,
/// PKCE §4.5) against `token_endpoint` (from Discovery's
/// `Metadata.token_endpoint`, or an endpoint configured directly).
pub fn buildTokenRequest(
    gpa: std.mem.Allocator,
    token_endpoint: []const u8,
    params: TokenRequestParams,
) BuildRequestError!TokenRequest {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(gpa);
    var first = true;
    try appendUrlEncodedField(gpa, &buf, &first, "grant_type", "authorization_code");
    try appendUrlEncodedField(gpa, &buf, &first, "code", params.code);
    try appendUrlEncodedField(gpa, &buf, &first, "redirect_uri", params.redirect_uri);
    try appendUrlEncodedField(gpa, &buf, &first, "client_id", params.client_id);
    try appendUrlEncodedField(gpa, &buf, &first, "code_verifier", params.code_verifier);
    switch (params.client_auth) {
        .none => {},
        .client_secret_post => |secret| try appendUrlEncodedField(gpa, &buf, &first, "client_secret", secret),
    }
    return .{ .url = token_endpoint, .body = try buf.toOwnedSlice(gpa) };
}

/// Append one `name=value` field, percent-encoding `value` (RFC 3986 §2.1,
/// unreserved-only). `first.*` tracks whether a `&` separator is needed —
/// used for both the query string (after the endpoint + `?`) and the
/// `application/x-www-form-urlencoded` body, which share the same encoding
/// rule at this conservative (unreserved-only) encoding level.
fn appendUrlEncodedField(
    gpa: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    first: *bool,
    name: []const u8,
    value: []const u8,
) error{OutOfMemory}!void {
    if (first.*) {
        first.* = false;
    } else {
        try buf.append(gpa, '&');
    }
    try buf.appendSlice(gpa, name); // field names here are fixed ASCII tokens
    try buf.append(gpa, '=');
    try appendPercentEncoded(gpa, buf, value);
}

fn appendPercentEncoded(gpa: std.mem.Allocator, buf: *std.ArrayList(u8), raw: []const u8) error{OutOfMemory}!void {
    const hex = "0123456789ABCDEF";
    for (raw) |c| {
        if (isUnreservedByte(c)) {
            try buf.append(gpa, c);
        } else {
            try buf.appendSlice(gpa, &[_]u8{ '%', hex[c >> 4], hex[c & 0xF] });
        }
    }
}

/// RFC 3986 §2.3 unreserved characters — the only bytes this module ever
/// emits unescaped in a query/form value.
fn isUnreservedByte(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
        else => false,
    };
}

/// A successful token-endpoint response (RFC 6749 §5.1 + OIDC Core §3.1.3.3
/// `id_token`). Everything it references lives in its internal arena; call
/// `deinit()` when done.
pub const TokenResponse = struct {
    /// REQUIRED (RFC 6749 §5.1).
    access_token: []const u8,
    /// REQUIRED (RFC 6749 §5.1), e.g. `"Bearer"`.
    token_type: []const u8,
    /// The ID Token (OIDC Core §3.1.3.3) — present for an `openid`-scoped
    /// request; feed it to `acceptIdToken`/`acceptIdTokenJwks`/
    /// `acceptIdTokenProvider`.
    id_token: ?[]const u8 = null,
    expires_in: ?i64 = null,
    refresh_token: ?[]const u8 = null,
    scope: ?[]const u8 = null,

    arena: *std.heap.ArenaAllocator,

    pub fn deinit(self: *TokenResponse) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
        self.* = undefined;
    }
};

/// Errors from `parseTokenResponse`. A non-200 / OAuth2 error response (RFC
/// 6749 §5.2: `{"error": "...", "error_description": "..."}`) is a caller
/// concern — check the HTTP status before calling this (it assumes a 200
/// success body).
pub const TokenResponseError = error{
    InvalidJson,
    NotAnObject,
    /// `access_token` absent or not a string.
    MissingAccessToken,
    /// `token_type` absent or not a string.
    MissingTokenType,
    /// A present optional member has the wrong JSON type.
    InvalidField,
    OutOfMemory,
};

/// Parse a 200-status token-endpoint JSON body (RFC 6749 §5.1) into a typed
/// `TokenResponse`.
pub fn parseTokenResponse(gpa: std.mem.Allocator, json: []const u8) TokenResponseError!TokenResponse {
    const arena_state = try gpa.create(std.heap.ArenaAllocator);
    errdefer gpa.destroy(arena_state);
    arena_state.* = .init(gpa);
    errdefer arena_state.deinit();
    const arena = arena_state.allocator();

    const val = std.json.parseFromSliceLeaky(std.json.Value, arena, json, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidJson,
    };
    if (val != .object) return error.NotAnObject;
    const obj = val.object;

    const access_token = (try tokenStringMember(obj, "access_token")) orelse return error.MissingAccessToken;
    const token_type = (try tokenStringMember(obj, "token_type")) orelse return error.MissingTokenType;
    const id_token = try tokenStringMember(obj, "id_token");
    const refresh_token = try tokenStringMember(obj, "refresh_token");
    const scope = try tokenStringMember(obj, "scope");
    const expires_in: ?i64 = blk: {
        const v = obj.get("expires_in") orelse break :blk null;
        break :blk switch (v) {
            .integer => |i| i,
            else => return error.InvalidField,
        };
    };

    return .{
        .access_token = access_token,
        .token_type = token_type,
        .id_token = id_token,
        .expires_in = expires_in,
        .refresh_token = refresh_token,
        .scope = scope,
        .arena = arena_state,
    };
}

/// Optional string member of a token response; wrong JSON type is an error
/// (never silently dropped), absence is `null`.
fn tokenStringMember(obj: std.json.ObjectMap, name: []const u8) error{InvalidField}!?[]const u8 {
    const v = obj.get(name) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => error.InvalidField,
    };
}

/// Errors from `acceptIdToken`/`acceptIdTokenJwks`/`acceptIdTokenProvider` —
/// the underlying parse/verify/claims errors (signature, `exp`/`nbf`,
/// mandatory `iss`/`aud`) plus the ID-Token-specific RP checks (OIDC Core
/// §3.1.3.7).
pub const IdTokenError = ParseAndVerifyError || error{
    /// The authorized-party check failed (OIDC Core §3.1.3.7 steps 3-4):
    /// either `azp` is present and is not exactly this `client_id` — at ANY
    /// `aud` arity, step 4 has no audience-count precondition — or `aud` has
    /// more than one value and `azp` is absent (step 3).
    AzpMismatch,
    /// The ID Token has no `nonce` claim at all, though this RP's
    /// authorization request always sends one — a conforming OP echoes it
    /// back verbatim (OIDC Core §3.1.3.7 step 11).
    MissingNonce,
    /// `nonce` is present but does not equal the value generated for THIS
    /// authorization request — replay/injection defense: rejects an
    /// otherwise-validly-signed ID Token minted for a different login
    /// attempt (fixation) or replayed from an earlier one.
    NonceMismatch,
};

/// RP-side acceptance options for an ID Token (OIDC Core §3.1.3.7). Unlike
/// `Options`/`ClaimOptions` elsewhere in this module, `issuer` and the
/// audience check (via `client_id`) have no `.any` opt-out here: an OIDC
/// relying party MUST perform both — there is no supported RP configuration
/// that skips them.
pub const IdTokenOptions = struct {
    now_s: i64,
    leeway_s: u32 = 60,
    /// Expected `iss` — the OP's issuer identifier.
    issuer: []const u8,
    /// This RP's client_id — checked against `aud` (MUST be contained) and
    /// against `azp` whenever that claim is present (OIDC Core §3.1.3.7
    /// step 4); with multiple audiences `azp` must additionally be there at
    /// all (step 3).
    client_id: []const u8,
    /// The nonce generated for this authorization request (`generateNonce`)
    /// — MUST match the token's `nonce` claim exactly.
    nonce: []const u8,
};

/// Accept an ID Token against a directly-supplied verification `key`
/// (offline — mirrors `parseAndVerify`). Runs the EXISTING parse → verify →
/// validateClaims pipeline (signature, iss/aud/exp/nbf, all P1-P2 machinery)
/// and layers the OIDC-specific `azp`/`nonce` checks on top.
pub fn acceptIdToken(
    gpa: std.mem.Allocator,
    id_token: []const u8,
    key: Key,
    opts: IdTokenOptions,
) IdTokenError!ParsedToken {
    var parsed = try parseAndVerify(gpa, id_token, key, .{
        .now_s = opts.now_s,
        .leeway_s = opts.leeway_s,
        .issuer = .{ .required = opts.issuer },
        .audience = .{ .required = opts.client_id },
    });
    errdefer parsed.deinit();
    try enforceIdTokenRpChecks(&parsed, opts.client_id, opts.nonce);
    return parsed;
}

/// Accept an ID Token against a `JwkSet` (mirrors `parseVerifyJwks`) — the
/// OP's JWKS, resolved by the token's `kid`.
pub fn acceptIdTokenJwks(
    gpa: std.mem.Allocator,
    id_token: []const u8,
    jwks: JwkSet,
    opts: IdTokenOptions,
) IdTokenError!ParsedToken {
    var parsed = try parseVerifyJwks(gpa, id_token, jwks, .{
        .now_s = opts.now_s,
        .leeway_s = opts.leeway_s,
        .issuer = .{ .required = opts.issuer },
        .audience = .{ .required = opts.client_id },
    });
    errdefer parsed.deinit();
    try enforceIdTokenRpChecks(&parsed, opts.client_id, opts.nonce);
    return parsed;
}

/// Options for `acceptIdTokenProvider` — same as `IdTokenOptions` minus
/// `issuer`: the `Provider` already enforces its own discovered/configured
/// issuer (`Provider.ClaimOptions.issuer` defaults to `.provider`), the same
/// default the resource-server side (`Provider.verify`) uses.
pub const IdTokenProviderOptions = struct {
    leeway_s: u32 = 60,
    client_id: []const u8,
    nonce: []const u8,
};

/// Accept an ID Token through the turnkey `Provider` (mirrors
/// `Provider.verify`) — lazy-load/TTL/rotation-aware JWKS resolution, the
/// SAME cache Parts 5-6 already run for access tokens.
pub fn acceptIdTokenProvider(
    provider: *Provider,
    gpa: std.mem.Allocator,
    id_token: []const u8,
    now_s: i64,
    opts: IdTokenProviderOptions,
) (Provider.Error || IdTokenError)!ParsedToken {
    var parsed = try provider.verify(gpa, id_token, now_s, .{
        .leeway_s = opts.leeway_s,
        .audience = .{ .required = opts.client_id },
    });
    errdefer parsed.deinit();
    try enforceIdTokenRpChecks(&parsed, opts.client_id, opts.nonce);
    return parsed;
}

fn enforceIdTokenRpChecks(parsed: *const ParsedToken, client_id: []const u8, nonce: []const u8) IdTokenError!void {
    // OIDC Core §3.1.3.7 step 4 — "If an `azp` Claim is present, the Client
    // SHOULD verify that its client_id is the Claim Value" — carries NO
    // audience-count precondition. Enforce it whenever `azp` is present, at
    // any `aud` arity: a token minted **for another client** at the same OP
    // but audienced at us is not our login (the cross-client-identity /
    // Authorized-Party shape). A non-string `azp` is a wrong-typed identity
    // claim, so it fails the same way rather than being ignored.
    if (parsed.claims.claim("azp")) |azp_val| {
        const azp = switch (azp_val) {
            .string => |s| s,
            else => return error.AzpMismatch,
        };
        if (!std.mem.eql(u8, azp, client_id)) return error.AzpMismatch;
    } else if (parsed.claims.aud == .many and parsed.claims.aud.many.len > 1) {
        // Step 3: with multiple audiences `azp` SHOULD be present — an OP is
        // not trusted to imply which of several audiences authorized it.
        return error.AzpMismatch;
    }
    // Step 11: the nonce this RP generated MUST come back unchanged.
    const nonce_claim = parsed.claims.claimStr("nonce") orelse return error.MissingNonce;
    if (!std.mem.eql(u8, nonce_claim, nonce)) return error.NonceMismatch;
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

    // Well past exp + leeway. (This test is about time, not iss/aud, so both
    // policies opt out explicitly with `.any` — the mandatory-choice API.)
    try testing.expectError(error.Expired, validateClaims(parsed.claims, .{
        .now_s = 1061,
        .leeway_s = 60,
        .issuer = .any,
        .audience = .any,
    }));
    // Just expired but inside the leeway window.
    try validateClaims(parsed.claims, .{ .now_s = 1030, .leeway_s = 60, .issuer = .any, .audience = .any });
    // Exactly at the edge (exp + leeway == now) is still acceptable.
    try validateClaims(parsed.claims, .{ .now_s = 1060, .leeway_s = 60, .issuer = .any, .audience = .any });
    // Zero leeway: one second past exp fails.
    try testing.expectError(error.Expired, validateClaims(parsed.claims, .{
        .now_s = 1001,
        .leeway_s = 0,
        .issuer = .any,
        .audience = .any,
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
        .issuer = .any,
        .audience = .any,
    }));
    // Inside leeway of nbf: acceptable.
    try validateClaims(parsed.claims, .{ .now_s = 4950, .leeway_s = 60, .issuer = .any, .audience = .any });
    try validateClaims(parsed.claims, .{ .now_s = 6000, .leeway_s = 60, .issuer = .any, .audience = .any });
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
    try validateClaims(parsed.claims, .{ .now_s = 1000, .issuer = .any, .audience = .any });
    // Opt-in strictness.
    try testing.expectError(error.IssuedInFuture, validateClaims(parsed.claims, .{
        .now_s = 1000,
        .reject_future_iat = true,
        .issuer = .any,
        .audience = .any,
    }));
    try validateClaims(parsed.claims, .{
        .now_s = 4950,
        .leeway_s = 60,
        .reject_future_iat = true,
        .issuer = .any,
        .audience = .any,
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

    try validateClaims(parsed.claims, .{ .now_s = 1000, .issuer = .{ .required = "https://issuer.example" }, .audience = .any });
    try testing.expectError(error.IssuerMismatch, validateClaims(parsed.claims, .{
        .now_s = 1000,
        .issuer = .{ .required = "https://evil.example" },
        .audience = .any,
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
        .issuer = .{ .required = "https://issuer.example" },
        .audience = .any,
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
    try validateClaims(p1.claims, .{ .now_s = 1000, .issuer = .any, .audience = .{ .required = "api://svc" } });
    try testing.expectError(error.AudienceMismatch, validateClaims(p1.claims, .{
        .now_s = 1000,
        .issuer = .any,
        .audience = .{ .required = "api://other" },
    }));

    var buf2: [512]u8 = undefined;
    const many = buildToken(&buf2,
        \\{"alg":"HS256"}
    ,
        \\{"exp":100000,"aud":["api://a","api://b"]}
    );
    var p2 = try parse(testing.allocator, many);
    defer p2.deinit();
    try validateClaims(p2.claims, .{ .now_s = 1000, .issuer = .any, .audience = .{ .required = "api://b" } });
    try testing.expectError(error.AudienceMismatch, validateClaims(p2.claims, .{
        .now_s = 1000,
        .issuer = .any,
        .audience = .{ .required = "api://c" },
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
        .issuer = .any,
        .audience = .{ .required = "api://svc" },
    }));
}

test "SECURITY: mandatory audience — a token for a sibling service is rejected by default (RFC 8725 §3.9)" {
    // The confused-deputy scenario: the SAME issuer mints a token whose `aud`
    // names a DIFFERENT service ("api://billing"). Our resource server is
    // "api://orders". With the mandatory-audience API there is no way to reach
    // the validator WITHOUT a choice, so the cross-service token cannot slip
    // through by omission.
    const gpa = testing.allocator;
    const secret = "mandatory-audience-secret";
    var buf: [512]u8 = undefined;
    const si = signingInputInto(&buf,
        \\{"alg":"HS256"}
    ,
        \\{"iss":"https://issuer.example","aud":"api://billing","exp":2000}
    );
    var mac: [32]u8 = undefined;
    hmac_sha2.HmacSha256.create(&mac, si, secret);
    const token = finishToken(&buf, si.len, &mac);

    // (1) Safe default: a validator that pins ITS OWN audience rejects the
    //     sibling-service token — the whole point of the hardening.
    try testing.expectError(error.AudienceMismatch, parseAndVerify(gpa, token, .{ .hmac = secret }, .{
        .now_s = 1000,
        .issuer = .{ .required = "https://issuer.example" },
        .audience = .{ .required = "api://orders" },
    }));

    // (2) Accepted only when the audience actually matches …
    var ok = try parseAndVerify(gpa, token, .{ .hmac = secret }, .{
        .now_s = 1000,
        .issuer = .{ .required = "https://issuer.example" },
        .audience = .{ .required = "api://billing" },
    });
    ok.deinit();

    // (3) … or when the operator CONSCIOUSLY opts out with `.any` (the only
    //     way to skip the check — a greppable, deliberate decision).
    var skipped = try parseAndVerify(gpa, token, .{ .hmac = secret }, .{
        .now_s = 1000,
        .issuer = .{ .required = "https://issuer.example" },
        .audience = .any,
    });
    skipped.deinit();

    // Pure claim-level check mirrors the same three outcomes.
    var parsed = try parse(gpa, token);
    defer parsed.deinit();
    try testing.expectError(error.AudienceMismatch, validateClaims(parsed.claims, .{
        .now_s = 1000,
        .issuer = .any,
        .audience = .{ .required = "api://orders" },
    }));
    try validateClaims(parsed.claims, .{ .now_s = 1000, .issuer = .any, .audience = .{ .required = "api://billing" } });
    try validateClaims(parsed.claims, .{ .now_s = 1000, .issuer = .any, .audience = .any });
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

    try testing.expectError(error.MissingExp, validateClaims(parsed.claims, .{ .now_s = 1000, .issuer = .any, .audience = .any }));
    try validateClaims(parsed.claims, .{ .now_s = 1000, .require_exp = false, .issuer = .any, .audience = .any });
}

test "validateClaims: RFC 7519 example token against its own exp" {
    var parsed = try parse(testing.allocator, rfc7519_example_token);
    defer parsed.deinit();
    // Just before exp: fine (with issuer pinned).
    try validateClaims(parsed.claims, .{ .now_s = 1300819380 - 100, .issuer = .{ .required = "joe" }, .audience = .any });
    // Past exp + leeway: expired.
    try testing.expectError(error.Expired, validateClaims(parsed.claims, .{
        .now_s = 1300819380 + 61,
        .issuer = .any,
        .audience = .any,
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
    try validateClaims(parsed.claims, .{ .now_s = 0, .leeway_s = 60, .issuer = .any, .audience = .any });
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

test "fuzz: parse never panics on arbitrary compact-JWT bytes" {
    try testing.fuzz({}, fuzzParse, .{});
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var parsed = parse(testing.allocator, buf[0..len]) catch return;
    parsed.deinit();
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

test "SECURITY: RFC 7515 §4.1.11 `crit` — an unsupported critical header fails closed" {
    const gpa = testing.allocator;
    var buf: [512]u8 = undefined;

    // A well-formed `crit` naming an extension header parameter that is also
    // really present in the header. This module implements NO JWS extension,
    // so the RFC's MUST applies: the JWS is invalid, not "verify and ignore".
    try testing.expectError(error.UnsupportedCritHeader, parse(gpa, buildToken(&buf,
        \\{"alg":"HS256","http://example.com/exp2":true,"crit":["http://example.com/exp2"]}
    ,
        \\{"iss":"joe"}
    )));
    // RFC 7797 `b64` is the canonical real-world case: an extension whose own
    // spec REQUIRES the `crit` marking. Unsupported here ⇒ rejected.
    try testing.expectError(error.UnsupportedCritHeader, parse(gpa, buildToken(&buf,
        \\{"alg":"HS256","b64":false,"crit":["b64"]}
    ,
        \\{"iss":"joe"}
    )));
    // Two names, only the second unknown — the whole list must be understood.
    try testing.expectError(error.UnsupportedCritHeader, parse(gpa, buildToken(&buf,
        \\{"alg":"HS256","b64":false,"x":1,"crit":["b64","x"]}
    ,
        \\{"iss":"joe"}
    )));

    // A token with NO crit still parses — the check must not be a blanket
    // rejection of every header.
    var ok = try parse(gpa, buildToken(&buf,
        \\{"alg":"HS256","kid":"k1"}
    ,
        \\{"iss":"joe"}
    ));
    defer ok.deinit();
    try testing.expectEqual(@as(?[]const []const u8, null), ok.header.crit);
}

test "RFC 7515 §4.1.11 `crit`: every degenerate form the RFC calls out is rejected" {
    const gpa = testing.allocator;
    var buf: [512]u8 = undefined;

    // Not an array.
    try testing.expectError(error.InvalidCrit, parse(gpa, buildToken(&buf,
        \\{"alg":"HS256","b64":false,"crit":"b64"}
    ,
        \\{"iss":"joe"}
    )));
    // Empty array ("MUST NOT be empty").
    try testing.expectError(error.InvalidCrit, parse(gpa, buildToken(&buf,
        \\{"alg":"HS256","crit":[]}
    ,
        \\{"iss":"joe"}
    )));
    // Non-string entry.
    try testing.expectError(error.InvalidCrit, parse(gpa, buildToken(&buf,
        \\{"alg":"HS256","crit":[42]}
    ,
        \\{"iss":"joe"}
    )));
    // Empty-string entry.
    try testing.expectError(error.InvalidCrit, parse(gpa, buildToken(&buf,
        \\{"alg":"HS256","":1,"crit":[""]}
    ,
        \\{"iss":"joe"}
    )));
    // Duplicate entry.
    try testing.expectError(error.InvalidCrit, parse(gpa, buildToken(&buf,
        \\{"alg":"HS256","b64":false,"crit":["b64","b64"]}
    ,
        \\{"iss":"joe"}
    )));
    // A name that is not present in the JOSE header at all.
    try testing.expectError(error.InvalidCrit, parse(gpa, buildToken(&buf,
        \\{"alg":"HS256","crit":["b64"]}
    ,
        \\{"iss":"joe"}
    )));
    // RFC-registered names are forbidden in `crit` — including the ones this
    // module itself reads, which is exactly the shape that would let a
    // producer "critically" redefine `alg`/`kid`/`typ`.
    const registered_headers = [_][]const u8{
        \\{"alg":"HS256","crit":["alg"]}
        ,
        \\{"alg":"HS256","crit":["crit"]}
        ,
        \\{"alg":"HS256","kid":"k","crit":["kid"]}
        ,
        \\{"alg":"HS256","typ":"JWT","crit":["typ"]}
        ,
        \\{"alg":"HS256","cty":"x","crit":["cty"]}
        ,
        \\{"alg":"HS256","enc":"x","crit":["enc"]}
        ,
        \\{"alg":"HS256","zip":"DEF","crit":["zip"]}
        ,
        \\{"alg":"HS256","x5t#S256":"x","crit":["x5t#S256"]}
        ,
    };
    for (registered_headers) |header| {
        try testing.expectError(error.InvalidCrit, parse(gpa, buildToken(&buf, header,
            \\{"iss":"joe"}
        )));
    }
}

test "SECURITY: a cryptographically VALID token carrying `crit` is still rejected end-to-end" {
    // Positive control for the fail-closed claim: the HMAC is genuine, every
    // claim is fine, and the ONLY defect is the critical extension header.
    // A recipient that verified-and-ignored it would honour a token whose
    // producer explicitly said "do not process this without understanding
    // my extension" (RFC 8725 §3.3).
    const gpa = testing.allocator;
    const secret = "crit-test-secret";
    var buf: [512]u8 = undefined;
    const si = signingInputInto(&buf,
        \\{"alg":"HS256","http://example.com/UNDEFINED":true,"crit":["http://example.com/UNDEFINED"]}
    ,
        \\{"iss":"https://issuer.example","aud":"api://svc","exp":100000}
    );
    var mac: [32]u8 = undefined;
    hmac_sha2.HmacSha256.create(&mac, si, secret);
    const token = finishToken(&buf, si.len, &mac);

    // The same signing input + MAC, minus the crit header, DOES verify — so
    // the rejection below is provably about `crit`, not a broken signature.
    {
        var plain_buf: [512]u8 = undefined;
        const plain_si = signingInputInto(&plain_buf,
            \\{"alg":"HS256"}
        ,
            \\{"iss":"https://issuer.example","aud":"api://svc","exp":100000}
        );
        var plain_mac: [32]u8 = undefined;
        hmac_sha2.HmacSha256.create(&plain_mac, plain_si, secret);
        var good = try parseAndVerify(gpa, finishToken(&plain_buf, plain_si.len, &plain_mac), .{ .hmac = secret }, .{
            .now_s = 1000,
            .issuer = .{ .required = "https://issuer.example" },
            .audience = .{ .required = "api://svc" },
        });
        good.deinit();
    }

    try testing.expectError(error.UnsupportedCritHeader, parseAndVerify(gpa, token, .{ .hmac = secret }, .{
        .now_s = 1000,
        .issuer = .{ .required = "https://issuer.example" },
        .audience = .{ .required = "api://svc" },
    }));
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

    // Good token + key + claims → the one call succeeds (issuer + audience
    // pinned, proving both are enforced end-to-end).
    var verified = try parseAndVerify(gpa, token, .{ .hmac = secret }, .{
        .now_s = 1000,
        .issuer = .{ .required = "https://issuer.example" },
        .audience = .{ .required = "api://svc" },
    });
    defer verified.deinit();
    try testing.expectEqualStrings("read write", verified.claims.claimStr("scope").?);

    // Bad signature → BadSignature (and no leak — testing.allocator checks).
    // These failure-stage checks fail before/independent of iss/aud, so both
    // policies opt out with `.any`.
    try testing.expectError(error.BadSignature, parseAndVerify(
        gpa,
        token,
        .{ .hmac = "wrong" },
        .{ .now_s = 1000, .issuer = .any, .audience = .any },
    ));
    // Wrong key type → AlgKeyMismatch.
    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{3} ** 32);
    try testing.expectError(error.AlgKeyMismatch, parseAndVerify(
        gpa,
        token,
        .{ .ed25519 = kp.public_key },
        .{ .now_s = 1000, .issuer = .any, .audience = .any },
    ));
    // Valid signature but expired claims → Expired.
    try testing.expectError(error.Expired, parseAndVerify(
        gpa,
        token,
        .{ .hmac = secret },
        .{ .now_s = 5000, .issuer = .any, .audience = .any },
    ));
    // Malformed token → the parse error surfaces unchanged.
    try testing.expectError(error.MalformedToken, parseAndVerify(
        gpa,
        "not-a-token",
        .{ .hmac = secret },
        .{ .now_s = 1000, .issuer = .any, .audience = .any },
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
        .issuer = .{ .required = "https://issuer.example" },
        .audience = .{ .required = "api://svc" },
    });
    defer verified.deinit();
    try testing.expectEqualStrings("read", verified.claims.claimStr("scope").?);

    // Valid signature but expired → Expired (and no leak on the way out).
    try testing.expectError(error.Expired, parseAndVerify(gpa, token, key, .{ .now_s = 5000, .issuer = .any, .audience = .any }));
    // Wrong key type → AlgKeyMismatch.
    try testing.expectError(error.AlgKeyMismatch, parseAndVerify(
        gpa,
        token,
        .{ .hmac = "secret" },
        .{ .now_s = 1000, .issuer = .any, .audience = .any },
    ));
    // RFC KAT through the one-call API (its exp is long past → Expired
    // proves the signature check passed first and claims ran).
    try testing.expectError(error.Expired, parseAndVerify(
        gpa,
        rfc7515_a2_token,
        key,
        .{ .now_s = 1600000000, .issuer = .any, .audience = .any },
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

test "fuzz: parseJwks never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzParseJwks, .{});
}

fn fuzzParseJwks(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    // Individual malformed JWKs are skipped (never a set-wide error), and
    // per parseJwks's own doc comment "Arbitrary bytes never panic" — this
    // is the fuzz harness proving that claim for both `.local` and
    // `.network` trust sources (the latter has an extra oct-key rejection
    // branch `.local` never takes).
    var local = parseJwksSource(testing.allocator, buf[0..len], .local) catch return;
    local.deinit();
    var network = parseJwksSource(testing.allocator, buf[0..len], .network) catch return;
    network.deinit();
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
        .issuer = .{ .required = "https://issuer.example" },
        .audience = .{ .required = "api://svc" },
    });
    defer verified.deinit();
    try testing.expectEqualStrings("read", verified.claims.claimStr("scope").?);

    // Valid signature but expired → Expired (and nothing leaks on the way out).
    try testing.expectError(error.Expired, parseVerifyJwks(gpa, token, jwks, .{
        .now_s = 5000,
        .issuer = .any,
        .audience = .any,
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
        .issuer = .any,
        .audience = .any,
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
        .issuer = .any,
        .audience = .any,
    }));

    // Malformed token → the parse error surfaces unchanged.
    try testing.expectError(error.MalformedToken, parseVerifyJwks(gpa, "nope", jwks, .{
        .now_s = 1000,
        .issuer = .any,
        .audience = .any,
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

test "fetchJwks: 200 parses (network source); oct keys refused; non-200 and garbage → typed errors" {
    const gpa = testing.allocator;
    // A fetched set with an asymmetric key (kept) AND a symmetric oct key. The
    // oct key is REFUSED on the network path (a public JWKS is attacker-
    // readable, so an oct entry would let anyone forge HS* tokens) — it lands
    // in `skipped` as `oct_from_network`, only the RSA key survives.
    const set = "{\"keys\":[" ++
        "{\"kty\":\"RSA\",\"kid\":\"rs\",\"n\":\"" ++ rfc7515_a2_n_b64 ++ "\",\"e\":\"AQAB\"}," ++
        "{\"kty\":\"oct\",\"kid\":\"hs\",\"k\":\"c2VjcmV0\"}" ++
        "]}";

    var stub: ScriptFetcher = .{ .script = &.{.{ .url = test_jwks_url, .body = set }} };
    var jwks = try fetchJwks(gpa, stub.fetcher(), test_jwks_url);
    defer jwks.deinit();
    try testing.expectEqual(@as(usize, 1), jwks.keys.len);
    try testing.expectEqualStrings("rs", jwks.keys[0].kid.?);
    try testing.expectEqual(@as(usize, 1), jwks.skipped.len);
    try testing.expectEqual(JwkSkipReason.oct_from_network, jwks.skipped[0].reason);

    // The SAME oct-only document is fine when configured LOCALLY (trusted).
    const oct_only = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"hs\",\"k\":\"c2VjcmV0\"}]}";
    var local = try parseJwks(gpa, oct_only);
    defer local.deinit();
    try testing.expectEqual(@as(usize, 1), local.keys.len);
    try testing.expectEqualStrings("hs", local.keys[0].kid.?);

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

    // A jwks_uri provider has NO configured issuer, so the default
    // `.issuer = .provider` policy has nothing to enforce and FAILS CLOSED
    // rather than silently skipping issuer validation (the old foot-gun).
    try testing.expectError(
        error.IssuerNotConfigured,
        provider.verify(gpa, rfc7515_a2_token, 1300819000, .{ .audience = .any }),
    );

    // Lazy first fetch + verify (now before the token's 2011 exp). The token
    // carries iss "joe"/no aud, so this consciously opts out of both.
    var verified = try provider.verify(gpa, rfc7515_a2_token, 1300819000, .{ .issuer = .any, .audience = .any });
    defer verified.deinit();
    try testing.expectEqualStrings("joe", verified.claims.iss.?);
    try testing.expectEqual(@as(usize, 1), stub.calls);

    // Second verify inside the TTL: served from cache, no fetch.
    var again = try provider.verify(gpa, rfc7515_a2_token, 1300819100, .{ .issuer = .any, .audience = .any });
    again.deinit();
    try testing.expectEqual(@as(usize, 1), stub.calls);

    // Signature fine but claims stale → Expired (still no fetch).
    try testing.expectError(
        error.Expired,
        provider.verify(gpa, rfc7515_a2_token, 1300819380 + 61, .{ .issuer = .any, .audience = .any }),
    );
    try testing.expectEqual(@as(usize, 1), stub.calls);

    // An explicit ClaimOptions.issuer override is still enforced.
    try testing.expectError(
        error.IssuerMismatch,
        provider.verify(gpa, rfc7515_a2_token, 1300819000, .{ .issuer = .{ .required = "https://other" }, .audience = .any }),
    );
}

test "Provider by issuer: discovery + injected issuer end-to-end" {
    const gpa = testing.allocator;
    const enc = std.base64.url_safe_no_pad.Encoder;
    // Asymmetric (Ed25519) key: a fetched JWKS may not carry symmetric `oct`
    // keys (they would be forgeable), so the issuer publishes a public key and
    // signs with EdDSA.
    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x51} ** 32);
    const pub_bytes = kp.public_key.toBytes();
    var x_b64: [43]u8 = undefined;
    var set_buf: [256]u8 = undefined;
    const set = try std.fmt.bufPrint(&set_buf,
        \\{{"keys":[{{"kty":"OKP","kid":"ed","crv":"Ed25519","x":"{s}"}}]}}
    , .{enc.encode(&x_b64, &pub_bytes)});

    var stub: ScriptFetcher = .{ .script = &.{
        .{ .url = test_wellknown_url, .body = test_discovery_json },
        .{ .url = test_jwks_url, .body = set },
    } };
    var provider = Provider.init(gpa, stub.fetcher(), .{ .issuer = "https://issuer.example" });
    defer provider.deinit();

    // Token minted by "the issuer": right iss, right key, kid "ed".
    var buf: [512]u8 = undefined;
    const si = signingInputInto(&buf,
        \\{"alg":"EdDSA","kid":"ed"}
    ,
        \\{"iss":"https://issuer.example","aud":"api://svc","exp":2000,"scope":"read"}
    );
    const sig = (try kp.sign(si, null)).toBytes();
    const token = finishToken(&buf, si.len, &sig);

    var verified = try provider.verify(gpa, token, 1000, .{ .audience = .{ .required = "api://svc" } });
    defer verified.deinit();
    try testing.expectEqualStrings("read", verified.claims.claimStr("scope").?);
    // Exactly one discovery + one JWKS fetch; metadata is cached.
    try testing.expectEqual(@as(usize, 2), stub.calls);
    try testing.expectEqualStrings(test_jwks_url, provider.metadata.?.jwks_uri);

    // A validly signed token from the WRONG issuer: the discovered issuer is
    // injected as the expected `iss` (the default `.provider` policy), so it
    // fails — no opt-in needed.
    var buf2: [512]u8 = undefined;
    const si2 = signingInputInto(&buf2,
        \\{"alg":"EdDSA","kid":"ed"}
    ,
        \\{"iss":"https://evil.example","aud":"api://svc","exp":2000}
    );
    const sig2 = (try kp.sign(si2, null)).toBytes();
    const evil = finishToken(&buf2, si2.len, &sig2);
    try testing.expectError(error.IssuerMismatch, provider.verify(gpa, evil, 1000, .{ .audience = .{ .required = "api://svc" } }));

    // Audience policy still applies on top.
    try testing.expectError(
        error.AudienceMismatch,
        provider.verify(gpa, token, 1000, .{ .audience = .{ .required = "api://other" } }),
    );
    // All of that ran from the cache.
    try testing.expectEqual(@as(usize, 2), stub.calls);
}

test "Provider: key rotation refreshes once, rate limit stops a bogus-kid flood, TTL re-fetches" {
    const gpa = testing.allocator;
    const enc = std.base64.url_safe_no_pad.Encoder;
    // Asymmetric (Ed25519) keys — a fetched JWKS may not carry `oct` secrets.
    const kp_old = try Ed25519.KeyPair.generateDeterministic([_]u8{0x61} ** 32);
    const kp_new = try Ed25519.KeyPair.generateDeterministic([_]u8{0x62} ** 32);
    const pub_old = kp_old.public_key.toBytes();
    const pub_new = kp_new.public_key.toBytes();
    var old_b64: [43]u8 = undefined;
    var new_b64: [43]u8 = undefined;
    var v1_buf: [256]u8 = undefined;
    var v2_buf: [256]u8 = undefined;
    // v1: only kid "old". v2 (after rotation): only kid "new".
    const jwks_v1 = try std.fmt.bufPrint(&v1_buf,
        \\{{"keys":[{{"kty":"OKP","kid":"old","crv":"Ed25519","x":"{s}"}}]}}
    , .{enc.encode(&old_b64, &pub_old)});
    const jwks_v2 = try std.fmt.bufPrint(&v2_buf,
        \\{{"keys":[{{"kty":"OKP","kid":"new","crv":"Ed25519","x":"{s}"}}]}}
    , .{enc.encode(&new_b64, &pub_new)});

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
    // all stay alive for the whole scenario. These tokens carry no iss/aud, so
    // every verify consciously opts out of both (jwks_uri-only provider).
    const opts: Provider.ClaimOptions = .{ .issuer = .any, .audience = .any };
    var buf_old: [512]u8 = undefined;
    var buf_new: [512]u8 = undefined;
    var buf_ghost: [512]u8 = undefined;

    // t=1000: token signed with the OLD key verifies off the first load.
    const si_old = signingInputInto(&buf_old,
        \\{"alg":"EdDSA","kid":"old"}
    ,
        \\{"exp":90000}
    );
    const sig_old = (try kp_old.sign(si_old, null)).toBytes();
    const token_old = finishToken(&buf_old, si_old.len, &sig_old);
    var v_old = try provider.verify(gpa, token_old, 1000, opts);
    v_old.deinit();
    try testing.expectEqual(@as(usize, 1), stub.calls);

    // t=1040: the issuer rotated — a NEW-kid token arrives. Its kid is not
    // in the cached set, the rate-limit window (30s since t=1000) has
    // passed, so the provider refreshes ONCE and the token verifies.
    const si_new = signingInputInto(&buf_new,
        \\{"alg":"EdDSA","kid":"new"}
    ,
        \\{"exp":90000}
    );
    const sig_new = (try kp_new.sign(si_new, null)).toBytes();
    const token_new = finishToken(&buf_new, si_new.len, &sig_new);
    var v_new = try provider.verify(gpa, token_new, 1040, opts);
    v_new.deinit();
    try testing.expectEqual(@as(usize, 2), stub.calls);

    // t=1050 and t=1055: bogus-kid tokens inside the min-refresh window.
    // NoMatchingKey — and the fetcher is NOT called again (no fetch storm).
    const si_ghost = signingInputInto(&buf_ghost,
        \\{"alg":"EdDSA","kid":"ghost"}
    ,
        \\{"exp":90000}
    );
    const sig_ghost = (try kp_new.sign(si_ghost, null)).toBytes();
    const token_ghost = finishToken(&buf_ghost, si_ghost.len, &sig_ghost);
    try testing.expectError(error.NoMatchingKey, provider.verify(gpa, token_ghost, 1050, opts));
    try testing.expectError(error.NoMatchingKey, provider.verify(gpa, token_ghost, 1055, opts));
    try testing.expectEqual(@as(usize, 2), stub.calls);

    // t=1080: the window has passed — the bogus kid earns one (single,
    // rate-limited) refresh, which still doesn't know it → NoMatchingKey.
    try testing.expectError(error.NoMatchingKey, provider.verify(gpa, token_ghost, 1080, opts));
    try testing.expectEqual(@as(usize, 3), stub.calls);

    // The rotated-in set stays live: the new-kid token verifies from cache.
    var v_new2 = try provider.verify(gpa, token_new, 1085, opts);
    v_new2.deinit();
    try testing.expectEqual(@as(usize, 3), stub.calls);

    // t=1400: past fetched_at(1080)+ttl(300) — the next verify re-fetches.
    var v_new3 = try provider.verify(gpa, token_new, 1400, opts);
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
        p1.verify(gpa, rfc7515_a2_token, 1000, .{ .audience = .any }),
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
        p2.verify(gpa, rfc7515_a2_token, 1000, .{ .audience = .any }),
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
    // The v1 set survived the failed swap: the RFC token still verifies
    // (jwks_uri-only provider, so iss/aud opt out).
    var verified = try p3.verify(gpa, rfc7515_a2_token, 1300819000, .{ .issuer = .any, .audience = .any });
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

// ── tests: resource-server middleware (Part 6) ───────────────────────────────
// End-to-end over a real `router` + `http.Server.serveStream`, offline: the
// Provider's JWKS comes from a scripted fetcher, tokens are minted with the RFC
// A.2 RSA key, and the clock is a fixed virtual `now_s`.

const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// The RFC 7515 A.2 RSA public key served as the issuer's JWKS under kid "rs".
const rs_jwks_json = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"rs\",\"use\":\"sig\"," ++
    "\"n\":\"" ++ rfc7515_a2_n_b64 ++ "\",\"e\":\"" ++ rfc7515_a2_e_b64 ++ "\"}]}";

/// Mint an RS256 token (kid "rs") over `payload_json`, signed with the A.2 key,
/// into `buf`. Returns the compact token.
fn mintRs256(buf: []u8, payload_json: []const u8) []const u8 {
    var n_buf: [256]u8 = undefined;
    var d_buf: [256]u8 = undefined;
    const n_bytes = b64uDecode(&n_buf, rfc7515_a2_n_b64);
    const d_bytes = b64uDecode(&d_buf, rfc7515_a2_d_b64);
    const si = signingInputInto(buf,
        \\{"alg":"RS256","kid":"rs"}
    , payload_json);
    const sig = rsaTestSign(sha2.Sha256, 256, si, n_bytes, d_bytes);
    return finishToken(buf, si.len, &sig);
}

/// A fixed virtual clock for the middleware under test.
const FixedClock = struct {
    now_s: i64,
    fn clock(fc: *const FixedClock) Clock {
        return .{ .ctx = @constCast(fc), .nowFn = read };
    }
    fn read(ctx: ?*anyopaque) i64 {
        return @as(*const FixedClock, @ptrCast(@alignCast(ctx.?))).now_s;
    }
};

fn resRunWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [512]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = r,
        .server_name = null,
        .peer = null,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn resWire(buf: []u8, method: []const u8, target: []const u8, auth: ?[]const u8) []const u8 {
    if (auth) |a| {
        return std.fmt.bufPrint(buf, "{s} {s} HTTP/1.1\r\nHost: t\r\nAuthorization: {s}\r\nConnection: close\r\n\r\n", .{ method, target, a }) catch unreachable;
    }
    return std.fmt.bufPrint(buf, "{s} {s} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", .{ method, target }) catch unreachable;
}

fn resExpectStatus(got: []const u8, comptime status: []const u8) !void {
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 " ++ status));
}

fn resExpectHeaderLine(got: []const u8, comptime line: []const u8) !void {
    try testing.expect(std.mem.indexOf(u8, got, "\r\n" ++ line ++ "\r\n") != null);
}

var res_test_hits: u32 = 0;

/// Protected handler: proves the identity is attached and trustworthy.
fn resProtectedHandler(ctx: *router.Ctx) anyerror!void {
    const id = identityOf(ctx) orelse return error.NoIdentity;
    try testing.expectEqualStrings("alice", id.subject().?);
    try testing.expect(id.hasScope("read"));
    res_test_hits += 1;
    try ctx.res.writeAll("ok");
}

/// Handler asserting NO identity was attached (out-of-scope read).
fn resNoIdentityHandler(ctx: *router.Ctx) anyerror!void {
    try testing.expectEqual(@as(?*Identity, null), identityOf(ctx));
    res_test_hits += 1;
    try ctx.res.writeAll("open");
}

test "ResourceServer: valid token → 200 + identity; missing/invalid/expired/insufficient short-circuit" {
    const gpa = testing.allocator;
    var stub: ScriptFetcher = .{ .script = &.{
        .{ .url = test_jwks_url, .body = rs_jwks_json },
    } };
    var provider = Provider.init(gpa, stub.fetcher(), .{
        .jwks_uri = test_jwks_url,
        .ttl_s = 1000000,
    });
    defer provider.deinit();

    var fc: FixedClock = .{ .now_s = 1000 };
    var rs = try ResourceServer.init(gpa, .{
        .provider = &provider,
        .claim_opts = .{ .issuer = .{ .required = "https://issuer.example" }, .audience = .{ .required = "api://svc" } },
        .required_scopes = &.{"read"},
        .clock = fc.clock(),
    });
    defer rs.deinit();

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(rs.middleware());
    try r.get("/data", resProtectedHandler);

    const good_claims =
        \\{"iss":"https://issuer.example","aud":"api://svc","sub":"alice","exp":2000,"scope":"read write"}
    ;
    var tok_buf: [1024]u8 = undefined;
    const good = mintRs256(&tok_buf, good_claims);
    var bearer_buf: [1100]u8 = undefined;
    const bearer = std.fmt.bufPrint(&bearer_buf, "Bearer {s}", .{good}) catch unreachable;

    var req_buf: [1400]u8 = undefined;
    var out_buf: [1024]u8 = undefined;

    // Valid token → handler runs, 200.
    res_test_hits = 0;
    {
        const req = resWire(&req_buf, "GET", "/data", bearer);
        const got = resRunWire(&r, req, &out_buf);
        try resExpectStatus(got, "200");
        try testing.expectEqual(@as(u32, 1), res_test_hits);
    }

    // No Authorization → 401, bare Bearer challenge, handler never runs.
    {
        const req = resWire(&req_buf, "GET", "/data", null);
        const got = resRunWire(&r, req, &out_buf);
        try resExpectStatus(got, "401");
        try resExpectHeaderLine(got, "WWW-Authenticate: Bearer");
        try testing.expectEqual(@as(u32, 1), res_test_hits);
    }

    // Garbage token → 401 invalid_token.
    {
        const req = resWire(&req_buf, "GET", "/data", "Bearer not.a.jwt");
        const got = resRunWire(&r, req, &out_buf);
        try resExpectStatus(got, "401");
        try resExpectHeaderLine(got, "WWW-Authenticate: Bearer error=\"invalid_token\"");
    }

    // Wrong scheme → treated as missing credential (bare challenge, 401).
    {
        const req = resWire(&req_buf, "GET", "/data", "Basic Zm9vOmJhcg==");
        const got = resRunWire(&r, req, &out_buf);
        try resExpectStatus(got, "401");
        try resExpectHeaderLine(got, "WWW-Authenticate: Bearer");
    }
}

test "ResourceServer: expired and insufficient-scope tokens, and the scope challenge" {
    const gpa = testing.allocator;
    var stub: ScriptFetcher = .{ .script = &.{
        .{ .url = test_jwks_url, .body = rs_jwks_json },
    } };
    var provider = Provider.init(gpa, stub.fetcher(), .{ .jwks_uri = test_jwks_url, .ttl_s = 1000000 });
    defer provider.deinit();

    var fc: FixedClock = .{ .now_s = 1000 };
    var rs = try ResourceServer.init(gpa, .{
        .provider = &provider,
        // These tokens carry no iss (jwks_uri-only provider), so issuer
        // validation is consciously opted out; audience stays enforced.
        .claim_opts = .{ .issuer = .any, .audience = .{ .required = "api://svc" } },
        .required_scopes = &.{"admin"},
        .clock = fc.clock(),
        .realm = "svc",
    });
    defer rs.deinit();

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(rs.middleware());
    try r.get("/data", resProtectedHandler);

    var req_buf: [1400]u8 = undefined;
    var out_buf: [1024]u8 = undefined;
    var tok_buf: [1024]u8 = undefined;
    var bearer_buf: [1100]u8 = undefined;

    // Valid signature but expired (exp 500 < now 1000) → 401 invalid_token
    // (challenge carries the configured realm).
    {
        const expired = mintRs256(&tok_buf,
            \\{"aud":"api://svc","sub":"alice","exp":500,"scope":"admin"}
        );
        const bearer = std.fmt.bufPrint(&bearer_buf, "Bearer {s}", .{expired}) catch unreachable;
        const req = resWire(&req_buf, "GET", "/data", bearer);
        const got = resRunWire(&r, req, &out_buf);
        try resExpectStatus(got, "401");
        try resExpectHeaderLine(got, "WWW-Authenticate: Bearer realm=\"svc\", error=\"invalid_token\"");
    }

    // Valid + fresh but missing the required "admin" scope → 403.
    {
        const narrow = mintRs256(&tok_buf,
            \\{"aud":"api://svc","sub":"alice","exp":2000,"scope":"read"}
        );
        const bearer = std.fmt.bufPrint(&bearer_buf, "Bearer {s}", .{narrow}) catch unreachable;
        const req = resWire(&req_buf, "GET", "/data", bearer);
        const got = resRunWire(&r, req, &out_buf);
        try resExpectStatus(got, "403");
        try resExpectHeaderLine(got, "WWW-Authenticate: Bearer realm=\"svc\", error=\"insufficient_scope\", scope=\"admin\"");
    }
}

test "ResourceServer: protect=.mutations lets unauthenticated reads through with no identity" {
    const gpa = testing.allocator;
    var stub: ScriptFetcher = .{ .script = &.{
        .{ .url = test_jwks_url, .body = rs_jwks_json },
    } };
    var provider = Provider.init(gpa, stub.fetcher(), .{ .jwks_uri = test_jwks_url, .ttl_s = 1000000 });
    defer provider.deinit();

    var fc: FixedClock = .{ .now_s = 1000 };
    var rs = try ResourceServer.init(gpa, .{
        .provider = &provider,
        // claim_opts is mandatory even though reads are out of scope here and
        // never reach the Provider; both policies opt out.
        .claim_opts = .{ .issuer = .any, .audience = .any },
        .protect = .mutations,
        .clock = fc.clock(),
    });
    defer rs.deinit();

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(rs.middleware());
    try r.get("/data", resNoIdentityHandler);

    var req_buf: [512]u8 = undefined;
    var out_buf: [1024]u8 = undefined;
    res_test_hits = 0;
    const req = resWire(&req_buf, "GET", "/data", null);
    const got = resRunWire(&r, req, &out_buf);
    try resExpectStatus(got, "200");
    try testing.expectEqual(@as(u32, 1), res_test_hits);
    // The JWKS was never fetched — a read never touched the Provider.
    try testing.expectEqual(@as(usize, 0), stub.calls);
}

test "ResourceServer: ScopeIter splits on single/multiple spaces; InvalidRealm rejected" {
    var it: ScopeIter = .{ .rest = "  read   write openid " };
    try testing.expectEqualStrings("read", it.next().?);
    try testing.expectEqualStrings("write", it.next().?);
    try testing.expectEqualStrings("openid", it.next().?);
    try testing.expectEqual(@as(?[]const u8, null), it.next());

    var empty: ScopeIter = .{ .rest = "" };
    try testing.expectEqual(@as(?[]const u8, null), empty.next());

    var provider = Provider.init(testing.allocator, undefined, .{ .jwks_uri = "https://x/jwks" });
    defer provider.deinit();
    try testing.expectError(error.InvalidRealm, ResourceServer.init(testing.allocator, .{
        .provider = &provider,
        .claim_opts = .{ .issuer = .any, .audience = .any },
        .realm = "bad\"realm",
    }));
}

// ── tests: framework-agnostic Guard + scope/challenge helpers (Part 6b) ──────

/// Mint an RS256 token (kid "rs") over `payload_json` with an EXPLICIT JOSE
/// header `header_json`, signed with the RFC 7515 A.2 key. Lets a test set
/// `typ` or a mismatched `alg` the plain `mintRs256` cannot.
fn mintRs256WithHeader(buf: []u8, header_json: []const u8, payload_json: []const u8) []const u8 {
    var n_buf: [256]u8 = undefined;
    var d_buf: [256]u8 = undefined;
    const n_bytes = b64uDecode(&n_buf, rfc7515_a2_n_b64);
    const d_bytes = b64uDecode(&d_buf, rfc7515_a2_d_b64);
    const si = signingInputInto(buf, header_json, payload_json);
    const sig = rsaTestSign(sha2.Sha256, 256, si, n_bytes, d_bytes);
    return finishToken(buf, si.len, &sig);
}

/// Mint an unsecured (`alg:"none"`, kid "rs") token with an empty signature.
fn mintNoneToken(buf: []u8, payload_json: []const u8) []const u8 {
    const si = signingInputInto(buf,
        \\{"alg":"none","kid":"rs"}
    , payload_json);
    return finishToken(buf, si.len, "");
}

/// Parse a claims-only payload (unsecured; parse does not verify) so a test can
/// exercise the scope helpers directly on a `Claims`.
fn scopeClaimsOf(gpa: std.mem.Allocator, payload_json: []const u8) ParseError!ParsedToken {
    var buf: [1024]u8 = undefined;
    const si = signingInputInto(&buf, "{\"alg\":\"none\"}", payload_json);
    const tok = finishToken(&buf, si.len, "");
    return parse(gpa, tok);
}

var test_guard: ?*Guard = null;

/// Route handler that runs `Guard.authenticate` on the real request and maps
/// the outcome onto the RFC 6750 wire response (status + challenge).
fn guardTestHandler(ctx: *router.Ctx) anyerror!void {
    const g = test_guard.?;
    var actx = g.authenticate(testing.allocator, ctx.req) catch |err| {
        ctx.res.setStatus(authStatus(err));
        if (g.challengeFor(err)) |ch| try ctx.res.setHeader("WWW-Authenticate", ch);
        try ctx.res.setHeader("Content-Type", "text/plain");
        try ctx.res.writeAll("denied");
        return;
    };
    defer actx.deinit();
    ctx.res.setStatus(200);
    try ctx.res.writeAll(actx.subject() orelse "?");
}

test "scope helpers: scopeGranted + require single/all/any over `scope` string and `scp` array" {
    const gpa = testing.allocator;

    var t1 = try scopeClaimsOf(gpa,
        \\{"scope":"read write openid"}
    );
    defer t1.deinit();
    const c1 = t1.claims;
    try testing.expect(scopeGranted(c1, "read"));
    try testing.expect(scopeGranted(c1, "openid"));
    try testing.expect(!scopeGranted(c1, "admin"));
    try testing.expect(!scopeGranted(c1, "")); // empty never matches

    try requireScope(c1, "read");
    try testing.expectError(error.InsufficientScope, requireScope(c1, "admin"));
    try requireAllScopes(c1, &.{ "read", "write" });
    try testing.expectError(error.InsufficientScope, requireAllScopes(c1, &.{ "read", "admin" }));
    try requireAnyScope(c1, &.{ "admin", "openid" });
    try testing.expectError(error.InsufficientScope, requireAnyScope(c1, &.{ "admin", "delete" }));
    // Empty requirement is a deliberate no-op (no scope constraint).
    try requireAllScopes(c1, &.{});
    try requireAnyScope(c1, &.{});

    // `scp` as a JSON array of strings (RFC 9068 / Microsoft-identity style).
    var t2 = try scopeClaimsOf(gpa,
        \\{"scp":["user.read","mail.send"]}
    );
    defer t2.deinit();
    try testing.expect(scopeGranted(t2.claims, "user.read"));
    try testing.expect(scopeGranted(t2.claims, "mail.send"));
    try testing.expect(!scopeGranted(t2.claims, "user.write"));

    // `scp` as a single space-delimited string.
    var t3 = try scopeClaimsOf(gpa,
        \\{"scp":"a b c"}
    );
    defer t3.deinit();
    try testing.expect(scopeGranted(t3.claims, "b"));
    try testing.expect(!scopeGranted(t3.claims, "d"));
}

/// Read one of this module's shipped Markdown docs for the doc-drift test.
/// Tries the repo-root-relative path first (`zig build` runs test binaries
/// with the build root as cwd) and the module dir second; if neither exists
/// the test FAILS rather than skipping — an unreadable doc must not read as
/// an in-sync doc.
fn readModuleDoc(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cwd = std.Io.Dir.cwd();
    var path_buf: [128]u8 = undefined;
    const candidates = [_][]const u8{ "modules/jwt/", "", "../" };
    for (candidates) |prefix| {
        const path = std.fmt.bufPrint(&path_buf, "{s}{s}", .{ prefix, name }) catch unreachable;
        return cwd.readFileAlloc(io, path, gpa, .limited(1 << 20)) catch continue;
    }
    return error.ModuleDocNotFound;
}

test "docs track the code: no std-only-crypto claim, `p256` listed everywhere deps are" {
    // Doc drift is invisible to every other test in this file, so the two
    // provenance claims that outlived the code (`3403d47` moved ES256 onto
    // the in-repo `p256`) are pinned against the shipped Markdown itself.
    const gpa = testing.allocator;
    const spec_md = try readModuleDoc(gpa, "SPEC.md");
    defer gpa.free(spec_md);
    const readme_md = try readModuleDoc(gpa, "README.md");
    defer gpa.free(readme_md);

    // `pub const meta` is the canonical dep list — SPEC.md's Status line must
    // agree with it, name for name.
    inline for (meta.deps) |d| {
        try testing.expect(std.mem.indexOf(u8, spec_md, "`" ++ d ++ "`") != null);
        try testing.expect(std.mem.indexOf(u8, readme_md, d) != null);
    }
    try testing.expect(std.mem.indexOf(u8, spec_md, "deps `http`, `router`, `p256`") != null);

    // Neither document may claim the crypto is std-only any more.
    try testing.expect(std.mem.indexOf(u8, spec_md, "std-only") == null);
    try testing.expect(std.mem.indexOf(u8, readme_md, "std-only") == null);
}

test "writeBearerChallenge: RFC 6750 §3 header-value formatting" {
    var buf: [256]u8 = undefined;
    {
        var w: Writer = .fixed(&buf);
        try writeBearerChallenge(&w, .{});
        try testing.expectEqualStrings("Bearer", w.buffered());
    }
    {
        var w: Writer = .fixed(&buf);
        try writeBearerChallenge(&w, .{ .realm = "svc" });
        try testing.expectEqualStrings("Bearer realm=\"svc\"", w.buffered());
    }
    {
        var w: Writer = .fixed(&buf);
        try writeBearerChallenge(&w, .{ .error_code = "invalid_token" });
        try testing.expectEqualStrings("Bearer error=\"invalid_token\"", w.buffered());
    }
    {
        var w: Writer = .fixed(&buf);
        try writeBearerChallenge(&w, .{
            .realm = "svc",
            .error_code = "insufficient_scope",
            .scopes = &.{ "read", "write" },
        });
        try testing.expectEqualStrings(
            "Bearer realm=\"svc\", error=\"insufficient_scope\", scope=\"read write\"",
            w.buffered(),
        );
    }
    // Every non-first auth-param is comma-delimited (RFC 7235 §2.1
    // `#auth-param` + RFC 7230 §7), not SP-delimited. Checked structurally as
    // well as by the exact strings above: parse the value the way a strict
    // `1#challenge` recipient does — split on commas — and require that only
    // the FIRST element carries the auth-scheme and that every element is a
    // single `name="value"` pair.
    {
        var w: Writer = .fixed(&buf);
        try writeBearerChallenge(&w, .{
            .realm = "svc",
            .error_code = "insufficient_scope",
            .scopes = &.{ "read", "write" },
        });
        const value = w.buffered();
        var it = std.mem.splitScalar(u8, value, ',');
        const first = it.next().?;
        try testing.expectEqualStrings("Bearer realm=\"svc\"", first);
        var params: usize = 1;
        while (it.next()) |raw_part| {
            const part = std.mem.trimStart(u8, raw_part, " ");
            // No element after the first may look like a new challenge, i.e.
            // it must be exactly one auth-param: `name="…"`, no interior SP
            // outside the quoted value.
            const eq = std.mem.indexOfScalar(u8, part, '=') orelse return error.TestUnexpectedResult;
            try testing.expect(eq > 0);
            try testing.expect(std.mem.indexOfScalar(u8, part[0..eq], ' ') == null);
            try testing.expectEqual(@as(u8, '"'), part[eq + 1]);
            try testing.expectEqual(@as(u8, '"'), part[part.len - 1]);
            params += 1;
        }
        try testing.expectEqual(@as(usize, 3), params);
    }
}

test "Guard.authenticate: valid → context; missing/garbage/expired/insufficient/none-alg/confusion denied" {
    const gpa = testing.allocator;
    var stub: ScriptFetcher = .{ .script = &.{
        .{ .url = test_jwks_url, .body = rs_jwks_json },
    } };
    var provider = Provider.init(gpa, stub.fetcher(), .{ .jwks_uri = test_jwks_url, .ttl_s = 1000000 });
    defer provider.deinit();

    var fc: FixedClock = .{ .now_s = 1000 };
    var guard = try Guard.init(gpa, .{
        .provider = &provider,
        .claim_opts = .{ .issuer = .{ .required = "https://issuer.example" }, .audience = .{ .required = "api://svc" } },
        .required_scopes = &.{"read"},
        .clock = fc.clock(),
        .realm = "svc",
    });
    defer guard.deinit();
    test_guard = &guard;
    defer test_guard = null;

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.get("/data", guardTestHandler);

    var tok_buf: [1024]u8 = undefined;
    var bearer_buf: [1100]u8 = undefined;
    var req_buf: [1400]u8 = undefined;
    var out_buf: [1024]u8 = undefined;

    // Valid, scoped token → 200 with the subject echoed in the body.
    {
        const good = mintRs256(&tok_buf,
            \\{"iss":"https://issuer.example","aud":"api://svc","sub":"alice","exp":2000,"scope":"read write"}
        );
        const bearer = std.fmt.bufPrint(&bearer_buf, "Bearer {s}", .{good}) catch unreachable;
        const got = resRunWire(&r, resWire(&req_buf, "GET", "/data", bearer), &out_buf);
        try resExpectStatus(got, "200");
        try testing.expect(std.mem.indexOf(u8, got, "alice") != null);
    }
    // No credential → 401, bare realm challenge (no error=).
    {
        const got = resRunWire(&r, resWire(&req_buf, "GET", "/data", null), &out_buf);
        try resExpectStatus(got, "401");
        try resExpectHeaderLine(got, "WWW-Authenticate: Bearer realm=\"svc\"");
    }
    // Garbage token → 401 invalid_token.
    {
        const got = resRunWire(&r, resWire(&req_buf, "GET", "/data", "Bearer not.a.jwt"), &out_buf);
        try resExpectStatus(got, "401");
        try resExpectHeaderLine(got, "WWW-Authenticate: Bearer realm=\"svc\", error=\"invalid_token\"");
    }
    // Valid signature but expired (exp 500 < now 1000) → 401 invalid_token.
    {
        const expired = mintRs256(&tok_buf,
            \\{"iss":"https://issuer.example","aud":"api://svc","sub":"alice","exp":500,"scope":"read"}
        );
        const bearer = std.fmt.bufPrint(&bearer_buf, "Bearer {s}", .{expired}) catch unreachable;
        const got = resRunWire(&r, resWire(&req_buf, "GET", "/data", bearer), &out_buf);
        try resExpectStatus(got, "401");
    }
    // Valid + fresh but missing the required "read" scope → 403.
    {
        const narrow = mintRs256(&tok_buf,
            \\{"iss":"https://issuer.example","aud":"api://svc","sub":"alice","exp":2000,"scope":"write"}
        );
        const bearer = std.fmt.bufPrint(&bearer_buf, "Bearer {s}", .{narrow}) catch unreachable;
        const got = resRunWire(&r, resWire(&req_buf, "GET", "/data", bearer), &out_buf);
        try resExpectStatus(got, "403");
        try resExpectHeaderLine(got, "WWW-Authenticate: Bearer realm=\"svc\", error=\"insufficient_scope\", scope=\"read\"");
    }
    // Unsecured alg:none (kid rs) → 401 invalid_token — never trusted (RFC 8725 §2.1).
    {
        const none_tok = mintNoneToken(&tok_buf,
            \\{"iss":"https://issuer.example","aud":"api://svc","sub":"mallory","exp":2000,"scope":"read"}
        );
        const bearer = std.fmt.bufPrint(&bearer_buf, "Bearer {s}", .{none_tok}) catch unreachable;
        const got = resRunWire(&r, resWire(&req_buf, "GET", "/data", bearer), &out_buf);
        try resExpectStatus(got, "401");
        try resExpectHeaderLine(got, "WWW-Authenticate: Bearer realm=\"svc\", error=\"invalid_token\"");
    }
    // alg confusion: an HS256 header pointing at the RSA verification key
    // (the classic RS→HS downgrade). The alg/key TYPE mismatch is caught
    // before any MAC is computed → 401. RSA-signed bytes are irrelevant.
    {
        const confused = mintRs256WithHeader(&tok_buf,
            \\{"alg":"HS256","kid":"rs"}
        ,
            \\{"iss":"https://issuer.example","aud":"api://svc","sub":"m","exp":2000,"scope":"read"}
        );
        const bearer = std.fmt.bufPrint(&bearer_buf, "Bearer {s}", .{confused}) catch unreachable;
        const got = resRunWire(&r, resWire(&req_buf, "GET", "/data", bearer), &out_buf);
        try resExpectStatus(got, "401");
    }
}

test "Guard: RFC 9068 at+jwt typ enforcement (on/off) and end-to-end `scp` array scope" {
    const gpa = testing.allocator;
    var stub: ScriptFetcher = .{ .script = &.{
        .{ .url = test_jwks_url, .body = rs_jwks_json },
    } };
    var provider = Provider.init(gpa, stub.fetcher(), .{ .jwks_uri = test_jwks_url, .ttl_s = 1000000 });
    defer provider.deinit();
    var fc: FixedClock = .{ .now_s = 1000 };

    var tok_buf: [1024]u8 = undefined;
    var bearer_buf: [1100]u8 = undefined;
    var req_buf: [1400]u8 = undefined;
    var out_buf: [1024]u8 = undefined;

    // typ enforcement ON: a token lacking `typ` is rejected; `at+jwt` passes.
    {
        var guard = try Guard.init(gpa, .{
            .provider = &provider,
            .claim_opts = .{ .issuer = .any, .audience = .{ .required = "api://svc" } },
            .require_at_jwt_typ = true,
            .clock = fc.clock(),
        });
        defer guard.deinit();
        test_guard = &guard;
        defer test_guard = null;
        var r = router.Router.init(gpa);
        defer r.deinit();
        try r.get("/d", guardTestHandler);

        {
            const tok = mintRs256(&tok_buf,
                \\{"aud":"api://svc","sub":"a","exp":2000}
            );
            const bearer = std.fmt.bufPrint(&bearer_buf, "Bearer {s}", .{tok}) catch unreachable;
            const got = resRunWire(&r, resWire(&req_buf, "GET", "/d", bearer), &out_buf);
            try resExpectStatus(got, "401"); // no typ → invalid_token
        }
        {
            const tok = mintRs256WithHeader(&tok_buf,
                \\{"alg":"RS256","kid":"rs","typ":"at+jwt"}
            ,
                \\{"aud":"api://svc","sub":"a","exp":2000}
            );
            const bearer = std.fmt.bufPrint(&bearer_buf, "Bearer {s}", .{tok}) catch unreachable;
            const got = resRunWire(&r, resWire(&req_buf, "GET", "/d", bearer), &out_buf);
            try resExpectStatus(got, "200");
        }
    }

    // typ enforcement OFF (default): a token WITHOUT `typ` passes, and a
    // required scope carried in an `scp` array is honored end to end.
    {
        var guard = try Guard.init(gpa, .{
            .provider = &provider,
            .claim_opts = .{ .issuer = .any, .audience = .{ .required = "api://svc" } },
            .required_scopes = &.{"read"},
            .clock = fc.clock(),
        });
        defer guard.deinit();
        test_guard = &guard;
        defer test_guard = null;
        var r = router.Router.init(gpa);
        defer r.deinit();
        try r.get("/d", guardTestHandler);

        const tok = mintRs256(&tok_buf,
            \\{"aud":"api://svc","sub":"a","exp":2000,"scp":["read","write"]}
        );
        const bearer = std.fmt.bufPrint(&bearer_buf, "Bearer {s}", .{tok}) catch unreachable;
        const got = resRunWire(&r, resWire(&req_buf, "GET", "/d", bearer), &out_buf);
        try resExpectStatus(got, "200");
    }
}

// ── tests: OAuth2/OIDC relying-party flow (Part 7) ──────────────────────────

fn isBase64UrlChar(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '_' => true,
        else => false,
    };
}

test "PKCE: RFC 7636 Appendix B known-answer vector (S256 challenge)" {
    // The RFC's own worked example: a code_verifier and its S256 challenge,
    // both transcribed verbatim.
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    try testing.expectEqual(@as(usize, pkce_verifier_len), verifier.len);
    var challenge_buf: [pkce_challenge_len]u8 = undefined;
    pkceChallengeS256(verifier, &challenge_buf);
    try testing.expectEqualStrings("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", &challenge_buf);
}

test "PKCE: pkceGenerateS256 — lengths, cross-checks pkceChallengeS256, distinct across calls" {
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x70} ** 32);
    const random = csprng.random();

    const p1 = pkceGenerateS256(random);
    try testing.expectEqual(ChallengeMethod.S256, p1.method);
    try testing.expectEqual(@as(usize, pkce_verifier_len), p1.verifier().len);
    try testing.expectEqual(@as(usize, pkce_challenge_len), p1.challenge().len);
    try testing.expectEqualStrings("S256", p1.method.wireName());

    // The generated challenge must be exactly what pkceChallengeS256 computes
    // from the generated verifier — no separate code path drifting from it.
    var expect_challenge: [pkce_challenge_len]u8 = undefined;
    pkceChallengeS256(p1.verifier(), &expect_challenge);
    try testing.expectEqualStrings(&expect_challenge, p1.challenge());

    // Every character is in the base64url alphabet (a strict subset of RFC
    // 7636's allowed unreserved set) — safe unencoded in a query value.
    for (p1.verifier()) |c| try testing.expect(isBase64UrlChar(c));
    for (p1.challenge()) |c| try testing.expect(isBase64UrlChar(c));

    // A second draw from the same CSPRNG stream must differ — this is a
    // random generator, not a fixed constant.
    const p2 = pkceGenerateS256(random);
    try testing.expect(!std.mem.eql(u8, p1.verifier(), p2.verifier()));
    try testing.expect(!std.mem.eql(u8, p1.challenge(), p2.challenge()));
}

test "SECURITY: pkceGenerate* deliver the CSPRNG's next 32 bytes verbatim (entropy pin)" {
    // Found by mutating `pkceGenerateS256` the same way `generateCsrfToken`
    // was mutated: draw 4 bytes, zero-fill the other 28 — a 32-bit
    // `code_verifier` — and the whole suite stayed green. RFC 7636 §7.1
    // requires the verifier to have at least 256 bits of entropy, and it is
    // the ONLY thing standing between an intercepted authorization code and
    // token redemption, so the delivered draw is pinned like `state`/`nonce`.
    var oracle = std.Random.DefaultCsprng.init([_]u8{0x4d} ** 32);
    var raw: [32]u8 = undefined;
    oracle.random().bytes(&raw);
    var expect: [43]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&expect, &raw);

    var s256_rng = std.Random.DefaultCsprng.init([_]u8{0x4d} ** 32);
    const s256 = pkceGenerateS256(s256_rng.random());
    try testing.expectEqualStrings(&expect, s256.verifier());

    var plain_rng = std.Random.DefaultCsprng.init([_]u8{0x4d} ** 32);
    const plain = pkceGeneratePlain(plain_rng.random());
    try testing.expectEqualStrings(&expect, plain.verifier());

    // 43 chars = base64url of exactly 32 bytes (24 bytes → 32 chars,
    // 16 bytes → 22): written as literals, not as the module's constants.
    try testing.expectEqual(@as(usize, 43), s256.verifier().len);
}

test "PKCE: pkceGeneratePlain — challenge equals verifier verbatim (discouraged fallback)" {
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x71} ** 32);
    const p = pkceGeneratePlain(csprng.random());
    try testing.expectEqual(ChallengeMethod.plain, p.method);
    try testing.expectEqualStrings("plain", p.method.wireName());
    try testing.expectEqualStrings(p.verifier(), p.challenge());
    try testing.expectEqual(@as(usize, pkce_verifier_len), p.verifier().len);
}

test "generateState / generateNonce: non-empty, correct length, high entropy, base64url alphabet" {
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x72} ** 32);
    const random = csprng.random();

    const s1 = generateState(random);
    const s2 = generateState(random);
    const n1 = generateNonce(random);

    try testing.expectEqual(@as(usize, csrf_token_len), s1.len);
    try testing.expectEqual(@as(usize, csrf_token_len), n1.len);
    // Distinct draws from the CSPRNG stream — not a fixed/reused value.
    try testing.expect(!std.mem.eql(u8, &s1, &s2));
    try testing.expect(!std.mem.eql(u8, &s1, &n1));
    for (s1) |c| try testing.expect(isBase64UrlChar(c));
    for (n1) |c| try testing.expect(isBase64UrlChar(c));
}

test "SECURITY: generateState/generateNonce deliver the CSPRNG's next 32 bytes verbatim (entropy pin)" {
    // The test above pins LENGTH and ALPHABET only, and both survive gutting
    // the entropy (draw 4 bytes, zero-fill the rest: still 43 base64url
    // characters, still all-distinct across calls — and only 32 bits to
    // guess). `state` (RFC 6749 §10.12, login CSRF) and `nonce` (OIDC Core
    // §3.1.2.1, ID-Token replay) are precisely the values whose security IS
    // their unguessability, so the delivered draw itself is pinned here.

    // (a) Literal pin: this seed, through the shipped code path, produces
    //     exactly these 43 characters. Any change to how much randomness is
    //     drawn, or to how it is encoded, changes them.
    {
        var csprng = std.Random.DefaultCsprng.init([_]u8{0x72} ** 32);
        const s = generateState(csprng.random());
        try testing.expectEqualStrings("2-3w7lc6IlUMeknpJ4FakX5bquD-YmXDpYbbdfGdcAc", &s);
        const n = generateNonce(csprng.random());
        try testing.expectEqualStrings("ItOi8Swzi4OA9Zk-XTh6WCLdWEL12tDTPg-CXrt-tYM", &n);
    }

    // (b) Independent oracle for WHAT those characters are: base64url of the
    //     generator's next 32 bytes — nothing truncated, padded, reused or
    //     zero-filled. `32` and `43` are written as literals on purpose; a
    //     test phrased in terms of the module's own constants would only
    //     re-assert them.
    {
        var oracle = std.Random.DefaultCsprng.init([_]u8{0x91} ** 32);
        var raw: [32]u8 = undefined;
        oracle.random().bytes(&raw);
        var expect: [43]u8 = undefined;
        _ = std.base64.url_safe_no_pad.Encoder.encode(&expect, &raw);

        var csprng = std.Random.DefaultCsprng.init([_]u8{0x91} ** 32);
        const s = generateState(csprng.random());
        try testing.expectEqualStrings(&expect, &s);

        // Same for `nonce`: it must consume the same 32-byte draw, not a
        // narrower one.
        var csprng2 = std.Random.DefaultCsprng.init([_]u8{0x91} ** 32);
        const n = generateNonce(csprng2.random());
        try testing.expectEqualStrings(&expect, &n);

        // And the pinned draw really is the full 32 bytes: base64url of 32
        // bytes is 43 chars, of 24 bytes 32 chars, of 16 bytes 22.
        try testing.expectEqual(@as(usize, 43), s.len);
    }
}

test "buildAuthorizationUrl: builds the OIDC/RFC 6749 query, percent-encoded" {
    const gpa = testing.allocator;
    const url = try buildAuthorizationUrl(gpa, "https://issuer.example/authorize", .{
        .client_id = "my client+id", // exercises space + '+' encoding
        .redirect_uri = "https://app.example/callback?x=1",
        .scope = "openid profile email",
        .state = "state-abc123",
        .nonce = "nonce-xyz789",
        .code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        .code_challenge_method = .S256,
    });
    defer gpa.free(url);
    try testing.expectEqualStrings(
        "https://issuer.example/authorize?response_type=code" ++
            "&client_id=my%20client%2Bid" ++
            "&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback%3Fx%3D1" ++
            "&scope=openid%20profile%20email" ++
            "&state=state-abc123&nonce=nonce-xyz789" ++
            "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" ++
            "&code_challenge_method=S256",
        url,
    );
}

test "buildAuthorizationUrl: endpoint already carrying a query string joins with '&'; default scope" {
    const gpa = testing.allocator;
    const url = try buildAuthorizationUrl(gpa, "https://issuer.example/authorize?tenant=acme", .{
        .client_id = "c1",
        .redirect_uri = "https://app.example/cb",
        .state = "s1",
        .nonce = "n1",
        .code_challenge = "chal",
        .code_challenge_method = .plain,
    });
    defer gpa.free(url);
    try testing.expect(std.mem.startsWith(u8, url, "https://issuer.example/authorize?tenant=acme&response_type=code"));
    try testing.expect(std.mem.endsWith(u8, url, "code_challenge_method=plain"));
    try testing.expect(std.mem.indexOf(u8, url, "scope=openid") != null); // default AuthorizationRequest.scope
}

test "buildTokenRequest: application/x-www-form-urlencoded body, public and confidential client" {
    const gpa = testing.allocator;
    var req = try buildTokenRequest(gpa, "https://issuer.example/token", .{
        .code = "auth-code-1",
        .redirect_uri = "https://app.example/callback",
        .client_id = "my-client",
        .code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    });
    defer req.deinit(gpa);
    try testing.expectEqual(http.Method.post, req.method);
    try testing.expectEqualStrings("https://issuer.example/token", req.url);
    try testing.expectEqualStrings("application/x-www-form-urlencoded", req.content_type);
    try testing.expectEqualStrings(
        "grant_type=authorization_code&code=auth-code-1" ++
            "&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback" ++
            "&client_id=my-client" ++
            "&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        req.body,
    );

    // Confidential client: client_secret_post appends the secret.
    var req2 = try buildTokenRequest(gpa, "https://issuer.example/token", .{
        .code = "c2",
        .redirect_uri = "https://app.example/cb",
        .client_id = "conf-client",
        .code_verifier = "v",
        .client_auth = .{ .client_secret_post = "s3cr3t" },
    });
    defer req2.deinit(gpa);
    try testing.expect(std.mem.endsWith(u8, req2.body, "&client_secret=s3cr3t"));
}

test "buildTokenRequest: body round-trips through http.body.urlencoded (compatible encoding)" {
    const gpa = testing.allocator;
    var req = try buildTokenRequest(gpa, "https://issuer.example/token", .{
        .code = "a b&c=d", // exercises space + reserved chars needing encoding
        .redirect_uri = "https://app.example/cb?x=1",
        .client_id = "id",
        .code_verifier = "v",
    });
    defer req.deinit(gpa);
    const owned = try gpa.dupe(u8, req.body);
    defer gpa.free(owned);

    var it = http.body.urlencoded(owned);
    const p1 = it.next().?;
    try testing.expectEqualStrings("grant_type", p1.name);
    try testing.expectEqualStrings("authorization_code", p1.value);
    const p2 = it.next().?;
    try testing.expectEqualStrings("code", p2.name);
    try testing.expectEqualStrings("a b&c=d", p2.value);
    const p3 = it.next().?;
    try testing.expectEqualStrings("redirect_uri", p3.name);
    try testing.expectEqualStrings("https://app.example/cb?x=1", p3.value);
    const p4 = it.next().?;
    try testing.expectEqualStrings("client_id", p4.name);
    try testing.expectEqualStrings("id", p4.value);
    const p5 = it.next().?;
    try testing.expectEqualStrings("code_verifier", p5.name);
    try testing.expectEqualStrings("v", p5.value);
    try testing.expectEqual(@as(?http.body.FormPair, null), it.next());
}

test "fuzz: parseTokenResponse never panics on arbitrary or near-valid token bodies" {
    try testing.fuzz({}, fuzzParseTokenResponse, .{});
}

/// Adversarial JSON values a hostile or broken OP could put in a
/// token-endpoint member: wrong types, extremes, empties, and numbers that do
/// not fit an `i64`.
const token_response_values = [_][]const u8{
    "\"at\"",
    "\"\"",
    "0",
    "-1",
    "9223372036854775807",
    "-9223372036854775808",
    "12345678901234567890123456789",
    "3.5",
    "-0.0",
    "1e400",
    "-1e400",
    "true",
    "false",
    "null",
    "{}",
    "[]",
    "[\"a\"]",
    "{\"a\":1}",
    "\"\\u0000\\u001f\"",
};

const token_response_members = [_][]const u8{
    "access_token", "token_type", "id_token", "expires_in", "refresh_token", "scope", "unknown_ext",
};

/// `parseTokenResponse` is untrusted-wire input like `parse` and `parseJwks`:
/// the body arrives over TLS from the OP, but a compromised or simply broken
/// OP still controls every byte. Two regions per iteration:
///   (a) pure garbage bytes — the shape the two sibling harnesses use;
///   (b) a *well-formed* JSON object with the right member names, sweeping
///       every adversarial value through every member. A byte fuzzer would
///       essentially never reach that region on its own, and it is where the
///       typed extraction actually lives, so the sweep is exhaustive rather
///       than smith-sampled — one iteration covers the whole table.
fn fuzzParseTokenResponse(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    {
        smith.bytes(&buf);
        const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
        // NB: a typed error here must NOT abandon the iteration — nearly every
        // random byte string is a parse error, and an early `return` would
        // silently skip the structured sweep below (the skip-as-pass shape).
        if (parseTokenResponse(testing.allocator, buf[0..len])) |ok| {
            var resp = ok;
            resp.deinit();
        } else |_| {}
    }

    // Valid filler for the members not under test, so the value under test is
    // always reached rather than short-circuited by a missing required member.
    const filler = [token_response_members.len][]const u8{
        "\"at\"", "\"Bearer\"", "\"x.y.z\"", "3600", "\"rt\"", "\"openid\"", "1",
    };
    for (token_response_members, 0..) |_, under_test| {
        for (token_response_values) |value| {
            var w: Writer = .fixed(&buf);
            w.writeByte('{') catch continue;
            for (token_response_members, 0..) |name, i| {
                if (i != 0) w.writeByte(',') catch continue;
                w.writeByte('"') catch continue;
                w.writeAll(name) catch continue;
                w.writeAll("\":") catch continue;
                w.writeAll(if (i == under_test) value else filler[i]) catch continue;
            }
            w.writeByte('}') catch continue;
            var resp = parseTokenResponse(testing.allocator, w.buffered()) catch continue;
            resp.deinit();
        }
    }
}

test "parseTokenResponse: full response, missing-required and wrong-typed-optional errors" {
    const gpa = testing.allocator;
    var resp = try parseTokenResponse(gpa,
        \\{"access_token":"at-1","token_type":"Bearer","id_token":"idt-1",
        \\ "expires_in":3600,"refresh_token":"rt-1","scope":"openid profile"}
    );
    defer resp.deinit();
    try testing.expectEqualStrings("at-1", resp.access_token);
    try testing.expectEqualStrings("Bearer", resp.token_type);
    try testing.expectEqualStrings("idt-1", resp.id_token.?);
    try testing.expectEqual(@as(?i64, 3600), resp.expires_in);
    try testing.expectEqualStrings("rt-1", resp.refresh_token.?);
    try testing.expectEqualStrings("openid profile", resp.scope.?);

    // Minimal REQUIRED-only response: optionals stay null.
    var resp2 = try parseTokenResponse(gpa, "{\"access_token\":\"at-2\",\"token_type\":\"bearer\"}");
    defer resp2.deinit();
    try testing.expect(resp2.id_token == null);
    try testing.expect(resp2.expires_in == null);
    try testing.expect(resp2.refresh_token == null);
    try testing.expect(resp2.scope == null);

    try testing.expectError(error.MissingAccessToken, parseTokenResponse(gpa, "{\"token_type\":\"Bearer\"}"));
    try testing.expectError(error.MissingTokenType, parseTokenResponse(gpa, "{\"access_token\":\"at\"}"));
    try testing.expectError(error.InvalidField, parseTokenResponse(
        gpa,
        "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":\"not-a-number\"}",
    ));
    try testing.expectError(error.InvalidJson, parseTokenResponse(gpa, "]][not json"));
    try testing.expectError(error.NotAnObject, parseTokenResponse(gpa, "[1,2,3]"));
}

const id_token_issuer = "https://issuer.example";
const id_token_client_id = "my-client-id";
const id_token_secret = "id-token-hmac-secret";
const id_token_nonce = "nonce-1234567890abcdef";

/// Build an HS256-signed ID Token from a payload template (test-only —
/// exercises `acceptIdToken` through the EXISTING HS256 verify path used
/// throughout Parts 1-2).
fn buildIdToken(buf: []u8, payload_json: []const u8) []const u8 {
    const si = signingInputInto(buf,
        \\{"alg":"HS256","typ":"JWT"}
    , payload_json);
    var mac: [32]u8 = undefined;
    hmac_sha2.HmacSha256.create(&mac, si, id_token_secret);
    return finishToken(buf, si.len, &mac);
}

test "acceptIdToken: happy path — cryptographically valid, right iss/aud/nonce" {
    var buf: [512]u8 = undefined;
    const token = buildIdToken(
        &buf,
        "{\"iss\":\"" ++ id_token_issuer ++ "\",\"aud\":\"" ++ id_token_client_id ++ "\"," ++
            "\"exp\":100000,\"sub\":\"user-42\",\"nonce\":\"" ++ id_token_nonce ++ "\"}",
    );
    var accepted = try acceptIdToken(testing.allocator, token, .{ .hmac = id_token_secret }, .{
        .now_s = 1000,
        .issuer = id_token_issuer,
        .client_id = id_token_client_id,
        .nonce = id_token_nonce,
    });
    defer accepted.deinit();
    try testing.expectEqualStrings("user-42", accepted.claims.sub.?);
}

test "SECURITY: acceptIdToken rejects a cryptographically-VALID token carrying the WRONG nonce" {
    // Positive control: the signature and every other claim are fine — only
    // the nonce is wrong (as if an attacker replayed/injected an ID Token
    // from a different login attempt). This MUST be rejected — nonce is the
    // defense against exactly that.
    var buf: [512]u8 = undefined;
    const token = buildIdToken(
        &buf,
        "{\"iss\":\"" ++ id_token_issuer ++ "\",\"aud\":\"" ++ id_token_client_id ++ "\"," ++
            "\"exp\":100000,\"nonce\":\"a-DIFFERENT-nonce-entirely\"}",
    );
    // Prove the token really does verify cryptographically on its own merits
    // first (so the rejection below is provably about the nonce, not a
    // broken signature).
    var parsed = try parse(testing.allocator, token);
    defer parsed.deinit();
    try verify(&parsed, .{ .hmac = id_token_secret });

    try testing.expectError(error.NonceMismatch, acceptIdToken(testing.allocator, token, .{ .hmac = id_token_secret }, .{
        .now_s = 1000,
        .issuer = id_token_issuer,
        .client_id = id_token_client_id,
        .nonce = id_token_nonce,
    }));
}

test "acceptIdToken: missing nonce claim → MissingNonce" {
    var buf: [512]u8 = undefined;
    const token = buildIdToken(
        &buf,
        "{\"iss\":\"" ++ id_token_issuer ++ "\",\"aud\":\"" ++ id_token_client_id ++ "\",\"exp\":100000}",
    );
    try testing.expectError(error.MissingNonce, acceptIdToken(testing.allocator, token, .{ .hmac = id_token_secret }, .{
        .now_s = 1000,
        .issuer = id_token_issuer,
        .client_id = id_token_client_id,
        .nonce = id_token_nonce,
    }));
}

test "acceptIdToken: iss / aud / exp failures are each rejected with the right typed error" {
    const gpa = testing.allocator;
    // Wrong issuer.
    {
        var buf: [512]u8 = undefined;
        const token = buildIdToken(
            &buf,
            "{\"iss\":\"https://evil.example\",\"aud\":\"" ++ id_token_client_id ++ "\"," ++
                "\"exp\":100000,\"nonce\":\"" ++ id_token_nonce ++ "\"}",
        );
        try testing.expectError(error.IssuerMismatch, acceptIdToken(gpa, token, .{ .hmac = id_token_secret }, .{
            .now_s = 1000,
            .issuer = id_token_issuer,
            .client_id = id_token_client_id,
            .nonce = id_token_nonce,
        }));
    }
    // Wrong audience.
    {
        var buf: [512]u8 = undefined;
        const token = buildIdToken(
            &buf,
            "{\"iss\":\"" ++ id_token_issuer ++ "\",\"aud\":\"someone-else\"," ++
                "\"exp\":100000,\"nonce\":\"" ++ id_token_nonce ++ "\"}",
        );
        try testing.expectError(error.AudienceMismatch, acceptIdToken(gpa, token, .{ .hmac = id_token_secret }, .{
            .now_s = 1000,
            .issuer = id_token_issuer,
            .client_id = id_token_client_id,
            .nonce = id_token_nonce,
        }));
    }
    // Expired.
    {
        var buf: [512]u8 = undefined;
        const token = buildIdToken(
            &buf,
            "{\"iss\":\"" ++ id_token_issuer ++ "\",\"aud\":\"" ++ id_token_client_id ++ "\"," ++
                "\"exp\":100,\"nonce\":\"" ++ id_token_nonce ++ "\"}",
        );
        try testing.expectError(error.Expired, acceptIdToken(gpa, token, .{ .hmac = id_token_secret }, .{
            .now_s = 1000,
            .issuer = id_token_issuer,
            .client_id = id_token_client_id,
            .nonce = id_token_nonce,
        }));
    }
}

test "acceptIdToken: multiple audiences require a matching azp (OIDC Core §3.1.3.7)" {
    const gpa = testing.allocator;
    // Multiple aud, no azp at all → AzpMismatch.
    {
        var buf: [512]u8 = undefined;
        const token = buildIdToken(
            &buf,
            "{\"iss\":\"" ++ id_token_issuer ++ "\",\"aud\":[\"" ++ id_token_client_id ++ "\",\"other-svc\"]," ++
                "\"exp\":100000,\"nonce\":\"" ++ id_token_nonce ++ "\"}",
        );
        try testing.expectError(error.AzpMismatch, acceptIdToken(gpa, token, .{ .hmac = id_token_secret }, .{
            .now_s = 1000,
            .issuer = id_token_issuer,
            .client_id = id_token_client_id,
            .nonce = id_token_nonce,
        }));
    }
    // Multiple aud, azp names a DIFFERENT client → AzpMismatch.
    {
        var buf: [512]u8 = undefined;
        const token = buildIdToken(
            &buf,
            "{\"iss\":\"" ++ id_token_issuer ++ "\",\"aud\":[\"" ++ id_token_client_id ++ "\",\"other-svc\"]," ++
                "\"azp\":\"someone-else\",\"exp\":100000,\"nonce\":\"" ++ id_token_nonce ++ "\"}",
        );
        try testing.expectError(error.AzpMismatch, acceptIdToken(gpa, token, .{ .hmac = id_token_secret }, .{
            .now_s = 1000,
            .issuer = id_token_issuer,
            .client_id = id_token_client_id,
            .nonce = id_token_nonce,
        }));
    }
    // Multiple aud, azp correctly names THIS client → accepted.
    {
        var buf: [512]u8 = undefined;
        const token = buildIdToken(
            &buf,
            "{\"iss\":\"" ++ id_token_issuer ++ "\",\"aud\":[\"" ++ id_token_client_id ++ "\",\"other-svc\"]," ++
                "\"azp\":\"" ++ id_token_client_id ++ "\",\"exp\":100000,\"nonce\":\"" ++ id_token_nonce ++ "\"}",
        );
        var accepted = try acceptIdToken(gpa, token, .{ .hmac = id_token_secret }, .{
            .now_s = 1000,
            .issuer = id_token_issuer,
            .client_id = id_token_client_id,
            .nonce = id_token_nonce,
        });
        accepted.deinit();
    }
}

test "SECURITY: a SINGLE-aud ID Token whose azp names a DIFFERENT client is rejected (OIDC Core §3.1.3.7 step 4)" {
    const gpa = testing.allocator;
    // The cross-client-identity shape: the OP minted this token FOR
    // `attacker-client` (that is what `azp` states) and merely audienced it
    // at us. Every other check passes — signature, iss, aud contains our
    // client_id, exp, nonce. Step 4 has no `aud`-count precondition, so the
    // authorized party must be verified here too.
    {
        var buf: [512]u8 = undefined;
        const token = buildIdToken(
            &buf,
            "{\"iss\":\"" ++ id_token_issuer ++ "\",\"aud\":\"" ++ id_token_client_id ++ "\"," ++
                "\"azp\":\"attacker-client\",\"exp\":100000,\"nonce\":\"" ++ id_token_nonce ++ "\"}",
        );
        // Positive control: it really is cryptographically valid on its own.
        var parsed = try parse(gpa, token);
        defer parsed.deinit();
        try verify(&parsed, .{ .hmac = id_token_secret });

        try testing.expectError(error.AzpMismatch, acceptIdToken(gpa, token, .{ .hmac = id_token_secret }, .{
            .now_s = 1000,
            .issuer = id_token_issuer,
            .client_id = id_token_client_id,
            .nonce = id_token_nonce,
        }));
    }
    // Same shape with a single-element `aud` ARRAY — the arity, not the JSON
    // encoding, is what used to gate the check.
    {
        var buf: [512]u8 = undefined;
        const token = buildIdToken(
            &buf,
            "{\"iss\":\"" ++ id_token_issuer ++ "\",\"aud\":[\"" ++ id_token_client_id ++ "\"]," ++
                "\"azp\":\"attacker-client\",\"exp\":100000,\"nonce\":\"" ++ id_token_nonce ++ "\"}",
        );
        try testing.expectError(error.AzpMismatch, acceptIdToken(gpa, token, .{ .hmac = id_token_secret }, .{
            .now_s = 1000,
            .issuer = id_token_issuer,
            .client_id = id_token_client_id,
            .nonce = id_token_nonce,
        }));
    }
    // A wrong-typed `azp` is not a free pass either.
    {
        var buf: [512]u8 = undefined;
        const token = buildIdToken(
            &buf,
            "{\"iss\":\"" ++ id_token_issuer ++ "\",\"aud\":\"" ++ id_token_client_id ++ "\"," ++
                "\"azp\":42,\"exp\":100000,\"nonce\":\"" ++ id_token_nonce ++ "\"}",
        );
        try testing.expectError(error.AzpMismatch, acceptIdToken(gpa, token, .{ .hmac = id_token_secret }, .{
            .now_s = 1000,
            .issuer = id_token_issuer,
            .client_id = id_token_client_id,
            .nonce = id_token_nonce,
        }));
    }
    // Controls: single `aud` with a CORRECT `azp`, and single `aud` with no
    // `azp` at all, both still accepted (step 3 only demands `azp` when the
    // audience is ambiguous).
    {
        var buf: [512]u8 = undefined;
        const token = buildIdToken(
            &buf,
            "{\"iss\":\"" ++ id_token_issuer ++ "\",\"aud\":\"" ++ id_token_client_id ++ "\"," ++
                "\"azp\":\"" ++ id_token_client_id ++ "\",\"exp\":100000,\"nonce\":\"" ++ id_token_nonce ++ "\"}",
        );
        var accepted = try acceptIdToken(gpa, token, .{ .hmac = id_token_secret }, .{
            .now_s = 1000,
            .issuer = id_token_issuer,
            .client_id = id_token_client_id,
            .nonce = id_token_nonce,
        });
        accepted.deinit();
    }
    {
        var buf: [512]u8 = undefined;
        const token = buildIdToken(
            &buf,
            "{\"iss\":\"" ++ id_token_issuer ++ "\",\"aud\":\"" ++ id_token_client_id ++ "\"," ++
                "\"exp\":100000,\"nonce\":\"" ++ id_token_nonce ++ "\"}",
        );
        var accepted = try acceptIdToken(gpa, token, .{ .hmac = id_token_secret }, .{
            .now_s = 1000,
            .issuer = id_token_issuer,
            .client_id = id_token_client_id,
            .nonce = id_token_nonce,
        });
        accepted.deinit();
    }
}

test "IdTokenOptions.leeway_s: the default clock-skew window is exactly 60 s (blind-constant pin)" {
    const gpa = testing.allocator;
    // The default is a security parameter — it is how long an EXPIRED ID
    // Token stays acceptable. Nothing pinned it: the only bound in the suite
    // was a 900 s-stale token, leaving the whole [60, 899] band invisible.
    // These two cases sit either side of the boundary, so the default cannot
    // be widened OR narrowed without this test going red.

    // exp = 940 with now = 1000 → expired by exactly 60 s → still inside the
    // default leeway.
    {
        var buf: [512]u8 = undefined;
        const token = buildIdToken(
            &buf,
            "{\"iss\":\"" ++ id_token_issuer ++ "\",\"aud\":\"" ++ id_token_client_id ++ "\"," ++
                "\"exp\":940,\"nonce\":\"" ++ id_token_nonce ++ "\"}",
        );
        var accepted = try acceptIdToken(gpa, token, .{ .hmac = id_token_secret }, .{
            .now_s = 1000,
            .issuer = id_token_issuer,
            .client_id = id_token_client_id,
            .nonce = id_token_nonce,
        });
        accepted.deinit();
    }
    // exp = 939 → expired by 61 s → one second outside it.
    {
        var buf: [512]u8 = undefined;
        const token = buildIdToken(
            &buf,
            "{\"iss\":\"" ++ id_token_issuer ++ "\",\"aud\":\"" ++ id_token_client_id ++ "\"," ++
                "\"exp\":939,\"nonce\":\"" ++ id_token_nonce ++ "\"}",
        );
        try testing.expectError(error.Expired, acceptIdToken(gpa, token, .{ .hmac = id_token_secret }, .{
            .now_s = 1000,
            .issuer = id_token_issuer,
            .client_id = id_token_client_id,
            .nonce = id_token_nonce,
        }));
    }
}

test "IdTokenProviderOptions.leeway_s: the default clock-skew window is exactly 60 s (blind-constant pin)" {
    // Same boundary, through the Provider path — whose `leeway_s` default was
    // never set OR checked by any test at all.
    const gpa = testing.allocator;
    const enc = std.base64.url_safe_no_pad.Encoder;
    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x71} ** 32);
    const pub_bytes = kp.public_key.toBytes();
    var x_b64: [43]u8 = undefined;
    var set_buf: [256]u8 = undefined;
    const set = try std.fmt.bufPrint(&set_buf,
        \\{{"keys":[{{"kty":"OKP","kid":"op-key","crv":"Ed25519","x":"{s}"}}]}}
    , .{enc.encode(&x_b64, &pub_bytes)});

    var stub: ScriptFetcher = .{ .script = &.{
        .{ .url = test_wellknown_url, .body = test_discovery_json },
        .{ .url = test_jwks_url, .body = set },
    } };
    var provider = Provider.init(gpa, stub.fetcher(), .{ .issuer = "https://issuer.example" });
    defer provider.deinit();

    // exp = 940, now = 1000 → 60 s stale → accepted under the default.
    {
        var buf: [512]u8 = undefined;
        const si = signingInputInto(
            &buf,
            \\{"alg":"EdDSA","kid":"op-key"}
        ,
            "{\"iss\":\"https://issuer.example\",\"aud\":\"" ++ id_token_client_id ++ "\"," ++
                "\"exp\":940,\"nonce\":\"" ++ id_token_nonce ++ "\"}",
        );
        const sig = (try kp.sign(si, null)).toBytes();
        var accepted = try acceptIdTokenProvider(&provider, gpa, finishToken(&buf, si.len, &sig), 1000, .{
            .client_id = id_token_client_id,
            .nonce = id_token_nonce,
        });
        accepted.deinit();
    }
    // exp = 939 → 61 s stale → rejected.
    {
        var buf: [512]u8 = undefined;
        const si = signingInputInto(
            &buf,
            \\{"alg":"EdDSA","kid":"op-key"}
        ,
            "{\"iss\":\"https://issuer.example\",\"aud\":\"" ++ id_token_client_id ++ "\"," ++
                "\"exp\":939,\"nonce\":\"" ++ id_token_nonce ++ "\"}",
        );
        const sig = (try kp.sign(si, null)).toBytes();
        try testing.expectError(error.Expired, acceptIdTokenProvider(&provider, gpa, finishToken(&buf, si.len, &sig), 1000, .{
            .client_id = id_token_client_id,
            .nonce = id_token_nonce,
        }));
    }
}

test "acceptIdTokenJwks: resolves by kid against a local JWKS, enforces nonce" {
    const gpa = testing.allocator;
    var k_b64: [64]u8 = undefined;
    const k_s = std.base64.url_safe_no_pad.Encoder.encode(&k_b64, id_token_secret);
    var set_buf: [256]u8 = undefined;
    const set = try std.fmt.bufPrint(&set_buf,
        \\{{"keys":[{{"kty":"oct","kid":"idp-1","k":"{s}"}}]}}
    , .{k_s});
    var jwks = try parseJwks(gpa, set);
    defer jwks.deinit();

    var buf: [512]u8 = undefined;
    const si = signingInputInto(
        buf[0..],
        \\{"alg":"HS256","kid":"idp-1"}
    ,
        "{\"iss\":\"" ++ id_token_issuer ++ "\",\"aud\":\"" ++ id_token_client_id ++ "\"," ++
            "\"exp\":100000,\"nonce\":\"" ++ id_token_nonce ++ "\"}",
    );
    var mac: [32]u8 = undefined;
    hmac_sha2.HmacSha256.create(&mac, si, id_token_secret);
    const token = finishToken(&buf, si.len, &mac);

    var accepted = try acceptIdTokenJwks(gpa, token, jwks, .{
        .now_s = 1000,
        .issuer = id_token_issuer,
        .client_id = id_token_client_id,
        .nonce = id_token_nonce,
    });
    accepted.deinit();

    try testing.expectError(error.NonceMismatch, acceptIdTokenJwks(gpa, token, jwks, .{
        .now_s = 1000,
        .issuer = id_token_issuer,
        .client_id = id_token_client_id,
        .nonce = "wrong-nonce",
    }));
}

test "acceptIdTokenProvider: turnkey ID Token acceptance through the cached Provider" {
    const gpa = testing.allocator;
    const enc = std.base64.url_safe_no_pad.Encoder;
    // A fetched JWKS may not carry symmetric `oct` keys, so the OP signs
    // with EdDSA over a published public key — same rule Provider tests use.
    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x53} ** 32);
    const pub_bytes = kp.public_key.toBytes();
    var x_b64: [43]u8 = undefined;
    var set_buf: [256]u8 = undefined;
    const set = try std.fmt.bufPrint(&set_buf,
        \\{{"keys":[{{"kty":"OKP","kid":"op-key","crv":"Ed25519","x":"{s}"}}]}}
    , .{enc.encode(&x_b64, &pub_bytes)});

    var stub: ScriptFetcher = .{ .script = &.{
        .{ .url = test_wellknown_url, .body = test_discovery_json },
        .{ .url = test_jwks_url, .body = set },
    } };
    var provider = Provider.init(gpa, stub.fetcher(), .{ .issuer = "https://issuer.example" });
    defer provider.deinit();

    var buf: [512]u8 = undefined;
    const si = signingInputInto(
        &buf,
        \\{"alg":"EdDSA","kid":"op-key"}
    ,
        "{\"iss\":\"https://issuer.example\",\"aud\":\"" ++ id_token_client_id ++ "\"," ++
            "\"exp\":2000,\"nonce\":\"" ++ id_token_nonce ++ "\"}",
    );
    const sig = (try kp.sign(si, null)).toBytes();
    const token = finishToken(&buf, si.len, &sig);

    var accepted = try acceptIdTokenProvider(&provider, gpa, token, 1000, .{
        .client_id = id_token_client_id,
        .nonce = id_token_nonce,
    });
    defer accepted.deinit();
    try testing.expectEqualStrings("https://issuer.example", accepted.claims.iss.?);

    // Wrong nonce, same otherwise-valid token → NonceMismatch, cache reused
    // (no extra fetch).
    try testing.expectError(error.NonceMismatch, acceptIdTokenProvider(&provider, gpa, token, 1000, .{
        .client_id = id_token_client_id,
        .nonce = "not-the-right-nonce",
    }));
    try testing.expectEqual(@as(usize, 2), stub.calls);
}
