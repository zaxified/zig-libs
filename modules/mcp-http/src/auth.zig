// SPDX-License-Identifier: MIT
//! MCP authorization, resource-server side (MCP spec 2026-07-28
//! basic/authorization; RFC 6750 bearer tokens, RFC 9728 Protected Resource
//! Metadata, RFC 8707 audience). The official SDKs' gate: TypeScript
//! `requireBearerAuth` + `mcpAuthMetadataRouter` + `requireScopes` /
//! `scopeChallenge`, Python `AuthSettings` + `TokenVerifier`, Go
//! `auth.RequireBearerToken` + the protected-resource handler.
//!
//! Set `Transport.auth` to an `Auth` and the transport:
//!   - serves the RFC 9728 document (`Auth.metadata`) at
//!     `/.well-known/oauth-protected-resource<Transport.path>` (unauthenticated,
//!     `Access-Control-Allow-Origin: *`, as a browser-based client fetches it);
//!   - reads `Authorization: Bearer <token>` on every request to the endpoint
//!     and hands the token to `Auth.verify` (local JWT check, RFC 7662
//!     introspection, an identity provider — the caller's choice);
//!   - answers 401 with `WWW-Authenticate: Bearer resource_metadata="…"` for a
//!     missing token (no `error` code, RFC 6750 §3.1) and `error="invalid_token"`
//!     for a malformed, unknown, expired or wrong-audience one; 403
//!     `error="insufficient_scope", scope="…"` for a valid token without
//!     `required_scopes` or the scopes `scope_for` names for this operation;
//!     every challenge (the 401s too) carries `scope="…"` when scopes are
//!     required, as RFC 6750 §3 allows, so a client learns what to ask for
//!     on its first try; 500 when the verifier itself fails;
//!   - passes the token's `mcp.AuthInfo` to every handler of the request
//!     (`call.auth`), through `router.Ctx.setTyped`. A middleware of the
//!     caller's own that stores an `mcp.AuthInfo` the same way is forwarded too.
//!
//! Not here: issuing tokens or running an authorization server (the SDKs
//! verify only; their v1 authorization-server helpers are frozen), the RFC 8414
//! mirror of the authorization server's metadata, and scope hierarchies (scope
//! names compare exactly, as in the TypeScript SDK).

const std = @import("std");
const mcp = @import("mcp");
const clock_lib = @import("clock");
const aaa_gate = @import("aaa-gate");

/// RFC 9728 §2 Protected Resource Metadata. Only what is set is written;
/// `resource` is REQUIRED and must be the endpoint's canonical URL (RFC 8707:
/// the `resource` a client asks its authorization server for).
pub const ProtectedResourceMetadata = struct {
    resource: []const u8,
    /// Issuer URLs of the authorization servers that can issue tokens for it.
    authorization_servers: []const []const u8 = &.{},
    scopes_supported: []const []const u8 = &.{},
    /// How a token may be presented; this transport reads only the header.
    bearer_methods_supported: []const []const u8 = &.{"header"},
    jwks_uri: ?[]const u8 = null,
    resource_name: ?[]const u8 = null,
    resource_documentation: ?[]const u8 = null,
    resource_policy_uri: ?[]const u8 = null,
    resource_tos_uri: ?[]const u8 = null,

    /// The JSON document, into `w`.
    pub fn write(self: *const ProtectedResourceMetadata, w: *std.Io.Writer) std.Io.Writer.Error!void {
        var jw: std.json.Stringify = .{ .writer = w };
        try jw.beginObject();
        try jw.objectField("resource");
        try jw.write(self.resource);
        inline for (.{ "authorization_servers", "scopes_supported", "bearer_methods_supported" }) |f| {
            const list = @field(self, f);
            if (list.len != 0) {
                try jw.objectField(f);
                try jw.write(list);
            }
        }
        inline for (.{ "jwks_uri", "resource_name", "resource_documentation", "resource_policy_uri", "resource_tos_uri" }) |f| {
            if (@field(self, f)) |v| {
                try jw.objectField(f);
                try jw.write(v);
            }
        }
        try jw.endObject();
    }
};

/// What the verifier says about a token: `.ok` with what the token grants, or
/// `.invalid` (unknown, revoked, not a token of ours) with a short reason for
/// `error_description`. A verifier that cannot decide (its introspection
/// endpoint is down) returns `error.VerifierFailed`, answered 500.
pub const Verdict = union(enum) {
    ok: mcp.AuthInfo,
    invalid: []const u8,
};

/// Verify one bearer token. `arena` lives as long as the request: the
/// `AuthInfo`'s slices may point into it.
pub const VerifyFn = *const fn (ctx: ?*anyopaque, arena: std.mem.Allocator, token: []const u8) error{ OutOfMemory, VerifierFailed }!Verdict;

/// One operation the per-operation scope check is asked about.
pub const Operation = struct {
    /// The JSON-RPC method (`tools/call`), or "" when the body names none. The
    /// check runs for POSTed JSON-RPC requests only: a `GET` stream and a
    /// `DELETE` are gated by the token and `required_scopes`, not per operation.
    method: []const u8,
    /// `params.name` (a tool or prompt) or `params.uri` (a resource), when given.
    target: ?[]const u8,
    auth: *const mcp.AuthInfo,
};

/// The scopes `op` needs beyond `Auth.required_scopes` (TS `scopeChallenge`);
/// an empty slice = none. The result must outlive the request.
pub const ScopeFn = *const fn (ctx: ?*anyopaque, op: Operation) []const []const u8;

pub const Auth = struct {
    verify: VerifyFn,
    ctx: ?*anyopaque = null,
    /// Absolute URL of the metadata document, put into every challenge.
    /// Usually `<origin>/.well-known/oauth-protected-resource<Transport.path>`.
    resource_metadata_url: []const u8,
    /// Served by the transport at `metadataPath(Transport.path)`; null = the
    /// caller serves it elsewhere.
    metadata: ?ProtectedResourceMetadata = null,
    /// Every request needs all of these (exact names).
    required_scopes: []const []const u8 = &.{},
    /// When set, a token is accepted only if its `AuthInfo.resource` equals
    /// this, ignoring one trailing `/` (RFC 8707 audience check; TS
    /// `expectedResource`). A token without `resource` is refused.
    expected_resource: ?[]const u8 = null,
    /// A token without `expires_at` is refused, as in the TypeScript SDK
    /// (populate it from a JWT `exp` or an introspection `exp`).
    require_expiry: bool = true,
    scope_for: ?ScopeFn = null,
    scope_ctx: ?*anyopaque = null,
    clock: clock_lib.WallClock = .system,
};

pub const well_known_prefix = "/.well-known/oauth-protected-resource";

/// Where the transport serves the document for an endpoint at `path` (RFC 9728
/// §3.1: the well-known segment goes before the resource's path).
pub fn metadataPath(buf: []u8, path: []const u8) ?[]const u8 {
    const tail = if (std.mem.eql(u8, path, "/")) "" else path;
    if (well_known_prefix.len + tail.len > buf.len) return null;
    @memcpy(buf[0..well_known_prefix.len], well_known_prefix);
    @memcpy(buf[well_known_prefix.len..][0..tail.len], tail);
    return buf[0 .. well_known_prefix.len + tail.len];
}

/// Why a request was refused.
pub const Refusal = struct {
    status: u16,
    /// RFC 6750 §3.1 error code; null for a request that sent no token.
    code: ?[]const u8,
    description: []const u8,
    /// The scopes to name in the challenge (`insufficient_scope`).
    scopes: []const []const u8 = &.{},
};

pub const Outcome = union(enum) {
    ok: mcp.AuthInfo,
    refused: Refusal,
};

/// The gate's decision for one request: `authorization` is the request's
/// `Authorization` value (null = absent; `repeated` = more than one field).
pub fn check(a: *const Auth, arena: std.mem.Allocator, authorization: ?[]const u8, repeated: bool) error{ OutOfMemory, VerifierFailed }!Outcome {
    const raw = authorization orelse
        return .{ .refused = .{ .status = 401, .code = null, .description = "Missing bearer token", .scopes = a.required_scopes } };
    if (repeated) return refuse401("More than one Authorization header", a);
    const token = aaa_gate.bearerTokenOf(raw) orelse return refuse401("Malformed or non-bearer Authorization header", a);
    const info = switch (try a.verify(a.ctx, arena, token)) {
        .ok => |i| i,
        .invalid => |why| return refuse401(if (why.len != 0) why else "Invalid token", a),
    };
    if (info.expires_at) |exp| {
        if (exp <= a.clock.nowS()) return refuse401("Token has expired", a);
    } else if (a.require_expiry) return refuse401("Token has no expiration time", a);
    if (a.expected_resource) |want| {
        const got = info.resource orelse return refuse401("Token is not bound to this resource", a);
        if (!sameResource(want, got)) return refuse401("Token was issued for another resource", a);
    }
    if (missingScope(&info, a.required_scopes)) |_|
        return .{ .refused = .{ .status = 403, .code = "insufficient_scope", .description = "Insufficient scope", .scopes = a.required_scopes } };
    return .{ .ok = info };
}

fn refuse401(why: []const u8, a: *const Auth) Outcome {
    return .{ .refused = .{ .status = 401, .code = "invalid_token", .description = why, .scopes = a.required_scopes } };
}

/// `a` and `b` equal, ignoring one trailing `/` on either (TS rule).
pub fn sameResource(a: []const u8, b: []const u8) bool {
    const x = if (std.mem.endsWith(u8, a, "/")) a[0 .. a.len - 1] else a;
    const y = if (std.mem.endsWith(u8, b, "/")) b[0 .. b.len - 1] else b;
    return std.mem.eql(u8, x, y);
}

/// The first scope of `need` that `info` lacks, or null.
pub fn missingScope(info: *const mcp.AuthInfo, need: []const []const u8) ?[]const u8 {
    for (need) |s| if (!info.hasScope(s)) return s;
    return null;
}

/// The per-operation check (after `check` accepted the token): a refusal when
/// `scope_for` names a scope the token lacks, else null.
pub fn checkOperation(a: *const Auth, op: Operation) ?Refusal {
    const f = a.scope_for orelse return null;
    const need = f(a.scope_ctx, op);
    if (missingScope(op.auth, need) == null) return null;
    return .{ .status = 403, .code = "insufficient_scope", .description = "Insufficient scope for this operation", .scopes = need };
}

/// The `WWW-Authenticate` value for `r` (RFC 6750 §3; every parameter a
/// quoted-string, `"` and `\` escaped).
pub fn challenge(w: *std.Io.Writer, a: *const Auth, r: Refusal) std.Io.Writer.Error!void {
    try w.writeAll("Bearer");
    var first = true;
    if (r.code) |c| {
        try param(w, &first, "error", c);
        try param(w, &first, "error_description", r.description);
    }
    if (r.scopes.len != 0) {
        try w.writeAll(if (first) " " else ", ");
        first = false;
        try w.writeAll("scope=\"");
        for (r.scopes, 0..) |s, i| {
            if (i != 0) try w.writeByte(' ');
            try quoted(w, s);
        }
        try w.writeByte('"');
    }
    try param(w, &first, "resource_metadata", a.resource_metadata_url);
}

fn param(w: *std.Io.Writer, first: *bool, name: []const u8, value: []const u8) std.Io.Writer.Error!void {
    try w.writeAll(if (first.*) " " else ", ");
    first.* = false;
    try w.writeAll(name);
    try w.writeAll("=\"");
    try quoted(w, value);
    try w.writeByte('"');
}

/// The inside of a quoted-string: `"` and `\` escaped, CR/LF and other
/// controls dropped (they would split the header).
fn quoted(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    for (s) |c| switch (c) {
        '"', '\\' => {
            try w.writeByte('\\');
            try w.writeByte(c);
        },
        0...0x1f, 0x7f => {},
        else => try w.writeByte(c),
    };
}

/// The JSON body of a refusal (`{"error":…,"error_description":…}`, as the
/// TypeScript SDK answers).
pub fn refusalBody(w: *std.Io.Writer, r: Refusal) std.Io.Writer.Error!void {
    var jw: std.json.Stringify = .{ .writer = w };
    try jw.beginObject();
    try jw.objectField("error");
    try jw.write(r.code orelse "invalid_request");
    try jw.objectField("error_description");
    try jw.write(r.description);
    try jw.endObject();
}

/// The method and target of a JSON-RPC request body, for `scope_for`: a
/// single-pass scan (the authoritative parse is `mcp`'s). The target is
/// `params.uri` for a `resources/*` method and `params.name` otherwise, each
/// falling back to the other when absent, so a body carrying both cannot make
/// the check look at the field the method does not use. Strings of any length
/// are read (a decoded token is never longer than its source, so the arena use
/// is bounded by the body, which the transport caps with `max_body`); a method
/// or target that is not a string is "" / null.
///
/// `error.Unreadable`: the body is not one well-formed JSON object. The
/// transport then refuses the request (400) instead of asking `scope_for` about
/// an operation it could not read -- `mcp` would answer such a body with a parse
/// error anyway, so no legitimate request is lost. Reading must never give up
/// early on a body that IS well-formed: an early "empty operation" is what let
/// a request name an operation `scope_for` never saw (sweep HS-2).
///
/// A duplicate key does not make the scan and `mcp` disagree: `mcp`'s parse
/// refuses an object with a repeated key, so the request that is executed has
/// each key once.
pub const RequestOp = struct { method: []const u8 = "", target: ?[]const u8 = null };

pub fn operationOf(gpa: std.mem.Allocator, arena: std.mem.Allocator, body: []const u8) error{ OutOfMemory, Unreadable }!RequestOp {
    var scanner: std.json.Scanner = .initCompleteInput(gpa, body);
    defer scanner.deinit();
    var method: []const u8 = "";
    var name: ?[]const u8 = null;
    var uri: ?[]const u8 = null;
    if ((scanner.next() catch return error.Unreadable) != .object_begin) return error.Unreadable;
    while (try takeKey(&scanner, arena)) |key| {
        if (std.mem.eql(u8, key, "method")) {
            method = (try takeValueString(&scanner, arena)) orelse "";
        } else if (std.mem.eql(u8, key, "params") and (scanner.peekNextTokenType() catch return error.Unreadable) == .object_begin) {
            _ = scanner.next() catch return error.Unreadable;
            while (try takeKey(&scanner, arena)) |pk| {
                if (std.mem.eql(u8, pk, "name")) {
                    name = try takeValueString(&scanner, arena);
                } else if (std.mem.eql(u8, pk, "uri")) {
                    uri = try takeValueString(&scanner, arena);
                } else try skipOne(&scanner);
            }
        } else try skipOne(&scanner);
    }
    if ((scanner.next() catch return error.Unreadable) != .end_of_document) return error.Unreadable;
    const target = if (std.mem.startsWith(u8, method, "resources/")) uri orelse name else name orelse uri;
    return .{ .method = method, .target = target };
}

/// The next object key, or null at the object's end. Anything else is unreadable.
fn takeKey(scanner: *std.json.Scanner, arena: std.mem.Allocator) error{ OutOfMemory, Unreadable }!?[]const u8 {
    const tok = scanner.nextAlloc(arena, .alloc_always) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Unreadable,
    };
    return switch (tok) {
        .allocated_string => |s| s,
        .object_end => null,
        else => error.Unreadable,
    };
}

/// The next value when it is a string (null for any other well-formed value,
/// which is consumed whole).
fn takeValueString(scanner: *std.json.Scanner, arena: std.mem.Allocator) error{ OutOfMemory, Unreadable }!?[]const u8 {
    if ((scanner.peekNextTokenType() catch return error.Unreadable) != .string) {
        try skipOne(scanner);
        return null;
    }
    const tok = scanner.nextAlloc(arena, .alloc_always) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Unreadable,
    };
    return switch (tok) {
        .allocated_string => |s| s,
        else => error.Unreadable,
    };
}

fn skipOne(scanner: *std.json.Scanner) error{Unreadable}!void {
    switch (scanner.peekNextTokenType() catch return error.Unreadable) {
        .object_end, .array_end, .end_of_document => return error.Unreadable,
        else => {},
    }
    scanner.skipValue() catch return error.Unreadable;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn fixedNow(_: ?*anyopaque) i64 {
    return 1_000 * std.time.ns_per_s;
}

const test_scopes = [_][]const u8{ "mcp:read", "mcp:tools" };

fn testVerify(_: ?*anyopaque, arena: std.mem.Allocator, token: []const u8) error{ OutOfMemory, VerifierFailed }!Verdict {
    if (std.mem.eql(u8, token, "boom")) return error.VerifierFailed;
    if (std.mem.eql(u8, token, "good")) return .{ .ok = .{ .client_id = "c1", .scopes = &test_scopes, .expires_at = 2_000, .resource = "https://mcp.example/mcp/" } };
    if (std.mem.eql(u8, token, "expired")) return .{ .ok = .{ .scopes = &test_scopes, .expires_at = 1_000, .resource = "https://mcp.example/mcp" } };
    if (std.mem.eql(u8, token, "noexp")) return .{ .ok = .{ .scopes = &test_scopes, .resource = "https://mcp.example/mcp" } };
    if (std.mem.eql(u8, token, "other")) return .{ .ok = .{ .scopes = &test_scopes, .expires_at = 2_000, .resource = "https://evil.example/mcp" } };
    if (std.mem.eql(u8, token, "noaud")) return .{ .ok = .{ .scopes = &test_scopes, .expires_at = 2_000 } };
    if (std.mem.eql(u8, token, "weak")) return .{ .ok = .{ .scopes = test_scopes[0..1], .expires_at = 2_000, .resource = "https://mcp.example/mcp" } };
    return .{ .invalid = try arena.dupe(u8, "Unknown token") };
}

const test_auth: Auth = .{
    .verify = testVerify,
    .resource_metadata_url = "https://mcp.example/.well-known/oauth-protected-resource/mcp",
    .required_scopes = test_scopes[0..1],
    .expected_resource = "https://mcp.example/mcp",
    .clock = .{ .nowFn = fixedNow },
};

test "check: every refusal of the TypeScript gate, and the accepted token" {
    var st: std.heap.ArenaAllocator = .init(testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    const cases = [_]struct { ?[]const u8, bool, u16, ?[]const u8 }{
        .{ null, false, 401, null },
        .{ "Basic dXNlcjpwYXNz", false, 401, "invalid_token" },
        .{ "Bearer", false, 401, "invalid_token" },
        .{ "Bearer good", true, 401, "invalid_token" },
        .{ "Bearer nope", false, 401, "invalid_token" },
        .{ "Bearer expired", false, 401, "invalid_token" }, // expires_at == now
        .{ "Bearer noexp", false, 401, "invalid_token" },
        .{ "Bearer other", false, 401, "invalid_token" },
        .{ "Bearer noaud", false, 401, "invalid_token" },
    };
    for (cases) |c| {
        const o = try check(&test_auth, a, c[0], c[1]);
        try testing.expectEqual(c[2], o.refused.status);
        if (c[3]) |code| try testing.expectEqualStrings(code, o.refused.code.?) else try testing.expect(o.refused.code == null);
    }
    try testing.expectError(error.VerifierFailed, check(&test_auth, a, "Bearer boom", false));
    // `resource` with a trailing slash matches; the scheme is case-insensitive.
    const ok = try check(&test_auth, a, "bearer good", false);
    try testing.expectEqualStrings("c1", ok.ok.client_id);
    // A valid token without a required scope is 403.
    var strict = test_auth;
    strict.required_scopes = &.{ "mcp:read", "mcp:admin" };
    const r = (try check(&strict, a, "Bearer good", false)).refused;
    try testing.expectEqual(@as(u16, 403), r.status);
    try testing.expectEqualStrings("insufficient_scope", r.code.?);
    // Expiry not required: a token without one is accepted.
    var lax = test_auth;
    lax.require_expiry = false;
    try testing.expect((try check(&lax, a, "Bearer noexp", false)) == .ok);
}

fn needAdminForDelete(_: ?*anyopaque, op: Operation) []const []const u8 {
    if (std.mem.eql(u8, op.method, "tools/call") and op.target != null and std.mem.eql(u8, op.target.?, "delete")) return &.{"mcp:admin"};
    return &.{};
}

test "checkOperation: scope_for names extra scopes per operation" {
    var a = test_auth;
    a.scope_for = needAdminForDelete;
    const info: mcp.AuthInfo = .{ .scopes = &test_scopes };
    try testing.expect(checkOperation(&a, .{ .method = "tools/call", .target = "echo", .auth = &info }) == null);
    const r = checkOperation(&a, .{ .method = "tools/call", .target = "delete", .auth = &info }).?;
    try testing.expectEqual(@as(u16, 403), r.status);
    try testing.expectEqualStrings("mcp:admin", r.scopes[0]);
    a.scope_for = null;
    try testing.expect(checkOperation(&a, .{ .method = "tools/call", .target = "delete", .auth = &info }) == null);
}

test "challenge: RFC 6750 parameters, quoted and escaped; no error code without a token" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try challenge(&w, &test_auth, .{ .status = 401, .code = null, .description = "x", .scopes = test_scopes[0..1] });
    try testing.expectEqualStrings("Bearer scope=\"mcp:read\", resource_metadata=\"https://mcp.example/.well-known/oauth-protected-resource/mcp\"", w.buffered());
    w = .fixed(&buf);
    try challenge(&w, &test_auth, .{ .status = 403, .code = "insufficient_scope", .description = "say \"hi\"\\\r\n", .scopes = &test_scopes });
    try testing.expectEqualStrings("Bearer error=\"insufficient_scope\", error_description=\"say \\\"hi\\\"\\\\\", scope=\"mcp:read mcp:tools\", resource_metadata=\"https://mcp.example/.well-known/oauth-protected-resource/mcp\"", w.buffered());
}

test "metadata: RFC 9728 document with only what is set, and its well-known path" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    const as = [_][]const u8{"https://auth.example"};
    try (ProtectedResourceMetadata{ .resource = "https://mcp.example/mcp", .authorization_servers = &as, .scopes_supported = &test_scopes, .resource_name = "Example" }).write(&aw.writer);
    try testing.expectEqualStrings(
        \\{"resource":"https://mcp.example/mcp","authorization_servers":["https://auth.example"],"scopes_supported":["mcp:read","mcp:tools"],"bearer_methods_supported":["header"],"resource_name":"Example"}
    , aw.written());
    var b: [128]u8 = undefined;
    try testing.expectEqualStrings("/.well-known/oauth-protected-resource/mcp", metadataPath(&b, "/mcp").?);
    try testing.expectEqualStrings("/.well-known/oauth-protected-resource", metadataPath(&b, "/").?);
    var small: [8]u8 = undefined;
    try testing.expect(metadataPath(&small, "/mcp") == null);
}

test "operationOf: a body that is not one JSON object is unreadable, not an empty operation" {
    var st: std.heap.ArenaAllocator = .init(testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    for ([_][]const u8{ "[1]", "{\"method\":", "{\"a\":}", "", "{} x", "{\"method\":\"tools/call\"}{}", "{\"params\":{\"name\":}}" }) |bad|
        try testing.expectError(error.Unreadable, operationOf(testing.allocator, a, bad));
}

test "operationOf: long keys and values are read, not given up on (sweep HS-2)" {
    var st: std.heap.ArenaAllocator = .init(testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    const long = try a.alloc(u8, 9 * 1024);
    @memset(long, 'k');
    // A 9 KiB top-level key ahead of `method`, a 9 KiB key inside `params`.
    const b1 = try std.fmt.allocPrint(a, "{{\"{s}\":1,\"method\":\"tools/call\",\"params\":{{\"{s}\":[1,{{}}],\"name\":\"delete\"}}}}", .{ long, long });
    const op1 = try operationOf(testing.allocator, a, b1);
    try testing.expectEqualStrings("tools/call", op1.method);
    try testing.expectEqualStrings("delete", op1.target.?);
    // A 9 KiB uri and a 9 KiB ignored value are kept / skipped, whatever the order.
    const b2 = try std.fmt.allocPrint(a, "{{\"params\":{{\"uri\":\"{s}\"}},\"x\":\"{s}\",\"method\":\"resources/read\"}}", .{ long, long });
    const op2 = try operationOf(testing.allocator, a, b2);
    try testing.expectEqualStrings("resources/read", op2.method);
    try testing.expectEqualStrings(long, op2.target.?);
    // A body with both `name` and `uri` is checked on the field its method uses.
    const op3 = try operationOf(testing.allocator, a, "{\"method\":\"tools/call\",\"params\":{\"name\":\"delete\",\"uri\":\"x://a\"}}");
    try testing.expectEqualStrings("delete", op3.target.?);
    const op4 = try operationOf(testing.allocator, a, "{\"method\":\"resources/read\",\"params\":{\"uri\":\"x://a\",\"name\":\"n\"}}");
    try testing.expectEqualStrings("x://a", op4.target.?);
}

test "operationOf: method and name/uri at the top level only, anything else empty" {
    var st: std.heap.ArenaAllocator = .init(testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    const cases = [_]struct { []const u8, []const u8, ?[]const u8 }{
        .{ "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"name\":\"x\"}}}", "tools/call", "echo" },
        .{ "{\"params\":{\"arguments\":{\"name\":\"inner\"},\"uri\":\"x://a\"},\"method\":\"resources/read\"}", "resources/read", "x://a" },
        .{ "{\"method\":\"tools/list\"}", "tools/list", null },
        .{ "{\"method\":\"tools/call\",\"params\":{\"name\":7}}", "tools/call", null },
        .{ "{\"method\":\"tools/call\",\"params\":[1]}", "tools/call", null },
        .{ "{\"id\":1,\"result\":{}}", "", null },
    };
    for (cases) |c| {
        const op = try operationOf(testing.allocator, a, c[0]);
        try testing.expectEqualStrings(c[1], op.method);
        if (c[2]) |t| try testing.expectEqualStrings(t, op.target.?) else try testing.expect(op.target == null);
    }
}
