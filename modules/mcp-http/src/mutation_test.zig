// SPDX-License-Identifier: MIT

//! Tests that came out of the 2026-11-27 delta mutation run (`auth.zig` whole,
//! the new `root.zig` / `modern.zig` code since the 2026-11-20 card). Each one
//! pins a decision a mutant could flip without an existing test noticing.
//! Expected values come from RFC 6750 / RFC 8707 / RFC 9728 and the module's
//! documented contract, never from running the code.

const std = @import("std");
const testing = std.testing;
const mcp = @import("mcp");
const root = @import("root.zig");
const auth = root.auth;

test "mutation 2026-11-27: the RFC 9728 path fits a buffer of exactly its length, not one byte less" {
    const want = auth.well_known_prefix ++ "/mcp";
    var exact: [want.len]u8 = undefined;
    try testing.expectEqualStrings(want, auth.metadataPath(&exact, "/mcp").?);
    var short: [want.len - 1]u8 = undefined;
    try testing.expect(auth.metadataPath(&short, "/mcp") == null);
    // A root endpoint has no path component: the well-known URI alone.
    var root_buf: [auth.well_known_prefix.len]u8 = undefined;
    try testing.expectEqualStrings(auth.well_known_prefix, auth.metadataPath(&root_buf, "/").?);
}

const Counter = struct {
    calls: usize = 0,
    fn verify(ctx: ?*anyopaque, _: std.mem.Allocator, token: []const u8) error{ OutOfMemory, VerifierFailed }!auth.Verdict {
        const self: *Counter = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        _ = token;
        // A verifier that accepts every token it is handed.
        return .{ .ok = .{ .scopes = &.{"mcp:read"}, .expires_at = 4_000_000_000, .resource = "https://mcp.example/mcp" } };
    }
};

const scopes_needed = [_][]const u8{ "mcp:read", "mcp:write" };

test "mutation 2026-11-27: a header that is not a well-formed Bearer credential is refused before the verifier sees it" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var counter: Counter = .{};
    const gate: auth.Auth = .{
        .verify = Counter.verify,
        .ctx = &counter,
        .resource_metadata_url = "https://mcp.example/.well-known/oauth-protected-resource/mcp",
    };
    // RFC 6750 section 2.1 / RFC 7235: only the `Bearer` scheme carries a token.
    for ([_][]const u8{ "Basic dXNlcjpwYXNz", "Bearer", "Bearer ", "Token abc", "abc" }) |h| {
        const o = try auth.check(&gate, a, h, false);
        try testing.expectEqual(@as(u16, 401), o.refused.status);
        try testing.expectEqualStrings("invalid_token", o.refused.code.?);
    }
    try testing.expectEqual(@as(usize, 0), counter.calls);
    const ok = try auth.check(&gate, a, "Bearer tok", false);
    try testing.expect(ok == .ok);
    try testing.expectEqual(@as(usize, 1), counter.calls);
}

test "mutation 2026-11-27: every refusal names the required scopes in its challenge (401 and 403)" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var counter: Counter = .{};
    // The verifier's token holds only `mcp:read`; the gate needs both scopes.
    const gate: auth.Auth = .{
        .verify = Counter.verify,
        .ctx = &counter,
        .resource_metadata_url = "https://mcp.example/.well-known/oauth-protected-resource/mcp",
        .required_scopes = &scopes_needed,
    };
    // 403 insufficient_scope: RFC 6750 section 3.1 names the scope the resource needs.
    const forbidden = (try auth.check(&gate, a, "Bearer tok", false)).refused;
    try testing.expectEqual(@as(u16, 403), forbidden.status);
    try testing.expectEqualStrings("insufficient_scope", forbidden.code.?);
    try testing.expectEqual(@as(usize, 2), forbidden.scopes.len);
    var hv: std.Io.Writer.Allocating = .init(a);
    try auth.challenge(&hv.writer, &gate, forbidden);
    try testing.expect(std.mem.find(u8, hv.written(), "scope=\"mcp:read mcp:write\"") != null);
    // 401 invalid_token (a malformed header here) carries the same scope parameter as the
    // 401 without a token (MCP authorization, scope selection: the challenge names the scopes).
    const bad = (try auth.check(&gate, a, "Basic x", false)).refused;
    try testing.expectEqual(@as(u16, 401), bad.status);
    try testing.expectEqual(@as(usize, 2), bad.scopes.len);
    // The same for a token the verifier calls invalid.
    const Rejecting = struct {
        fn verify(_: ?*anyopaque, _: std.mem.Allocator, _: []const u8) error{ OutOfMemory, VerifierFailed }!auth.Verdict {
            return .{ .invalid = "revoked" };
        }
    };
    var rejecting = gate;
    rejecting.verify = Rejecting.verify;
    const revoked = (try auth.check(&rejecting, a, "Bearer tok", false)).refused;
    try testing.expectEqual(@as(u16, 401), revoked.status);
    try testing.expectEqualStrings("revoked", revoked.description);
    try testing.expectEqual(@as(usize, 2), revoked.scopes.len);
}

test "mutation 2026-11-27: the audience check ignores exactly one trailing slash on either side" {
    // RFC 8707: the resource indicator is compared as the URI it is; the
    // module documents "ignoring one trailing `/`" for both operands.
    try testing.expect(auth.sameResource("https://mcp.example/mcp/", "https://mcp.example/mcp"));
    try testing.expect(auth.sameResource("https://mcp.example/mcp", "https://mcp.example/mcp/"));
    try testing.expect(auth.sameResource("https://mcp.example/mcp/", "https://mcp.example/mcp/"));
    try testing.expect(auth.sameResource("https://mcp.example/mcp", "https://mcp.example/mcp"));
    // Only ONE slash is ignored, and a different path is a different resource.
    try testing.expect(!auth.sameResource("https://mcp.example/mcp//", "https://mcp.example/mcp"));
    try testing.expect(!auth.sameResource("https://mcp.example/mcp", "https://mcp.example/mcp//"));
    try testing.expect(!auth.sameResource("https://mcp.example/mcp/", "https://mcp.example/other"));
    try testing.expect(!auth.sameResource("https://mcp.example/mcp", "https://mcp.example/other/"));
}

test "mutation 2026-11-27: operationOf takes uri for resources/* and name otherwise, each falling back to the other" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // resources/*: uri first, name when no uri.
    const both = try auth.operationOf(testing.allocator, a, "{\"method\":\"resources/read\",\"params\":{\"name\":\"n\",\"uri\":\"u\"}}");
    try testing.expectEqualStrings("u", both.target.?);
    const only_name = try auth.operationOf(testing.allocator, a, "{\"method\":\"resources/read\",\"params\":{\"name\":\"n\"}}");
    try testing.expectEqualStrings("n", only_name.target.?);
    // anything else: name first, uri when no name.
    const both2 = try auth.operationOf(testing.allocator, a, "{\"method\":\"tools/call\",\"params\":{\"uri\":\"u\",\"name\":\"n\"}}");
    try testing.expectEqualStrings("n", both2.target.?);
    const only_uri = try auth.operationOf(testing.allocator, a, "{\"method\":\"tools/call\",\"params\":{\"uri\":\"u\"}}");
    try testing.expectEqualStrings("u", only_uri.target.?);
    const none = try auth.operationOf(testing.allocator, a, "{\"method\":\"tools/list\"}");
    try testing.expect(none.target == null);
}
