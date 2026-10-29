// SPDX-License-Identifier: MIT

//! No-panic sweep tests (wave GI, 2026-10-29): one test per finding, named
//! "(sweep OA-n)". Each uses only the public API, so the file also builds
//! against the pre-fix `root.zig` (that is how the tests were shown to fail
//! without the fixes). The timing tests use inputs whose quadratic scan costs
//! tens of seconds and whose linear one a few milliseconds, and assert a
//! generous budget.

const std = @import("std");
const router = @import("router");
const oa = @import("root.zig");

const testing = std.testing;
const Allocator = std.mem.Allocator;
const Generator = oa.Generator;

fn monoNs() u64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

/// Generous: the linear work is milliseconds, the quadratic one tens of seconds.
const budget_ns: u64 = 5 * std.time.ns_per_s;

fn expectFast(started_ns: u64) !void {
    const took = monoNs() - started_ns;
    if (took > budget_ns) {
        std.debug.print("took {d} ms, budget {d} ms\n", .{ took / std.time.ns_per_ms, budget_ns / std.time.ns_per_ms });
        return error.TooSlow;
    }
}

/// `{"a":[[[...0...]]]}`: nesting depth `depth` (>= 1).
fn nestedObject(arena: Allocator, depth: usize) ![]const u8 {
    var s: std.ArrayList(u8) = .empty;
    try s.appendSlice(arena, "{\"a\":");
    try s.appendNTimes(arena, '[', depth - 1);
    try s.append(arena, '0');
    try s.appendNTimes(arena, ']', depth - 1);
    try s.append(arena, '}');
    return s.items;
}

const info0: oa.Info = .{ .title = "T", .version = "1" };

fn buildOne(gpa: Allocator, route: router.Route, info: oa.Info) oa.BuildError!void {
    const routes = [_]router.Route{route};
    const json = try Generator.buildRoutes(gpa, &routes, info);
    gpa.free(json);
}

test "validateOpenApi31: a document nested 500000 deep does not overflow the stack (sweep OA-1)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(arena, "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"t\",\"version\":\"1\"},\"paths\":{},\"x\":");
    try text.appendNTimes(arena, '[', 500_000);
    try text.appendNTimes(arena, ']', 500_000);
    try text.append(arena, '}');
    const doc = try std.json.parseFromSliceLeaky(std.json.Value, arena, text.items, .{});
    try oa.validateOpenApi31(testing.allocator, doc);
}

test "validateOpenApi31: many refs into one large object stay linear (sweep OA-2)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const n = 30_000;
    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(arena, "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"t\",\"version\":\"1\"},\"components\":{\"schemas\":{");
    for (0..n) |i| {
        if (i != 0) try text.append(arena, ',');
        // every schema points at the LAST key: the old scan walked all keys per ref
        try text.appendSlice(arena, try arena.print("\"s{d}\":{{\"$ref\":\"#/components/schemas/s{d}\"}}", .{ i, n - 1 }));
    }
    try text.appendSlice(arena, "}}}");
    const doc = try std.json.parseFromSliceLeaky(std.json.Value, arena, text.items, .{});
    const t0 = monoNs();
    try oa.validateOpenApi31(testing.allocator, doc);
    try expectFast(t0);
}

test "validateOpenApi31: a ref with an escaped or percent-encoded token still resolves, a wrong one dangles (sweep OA-2)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const head = "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"t\",\"version\":\"1\"},\"paths\":{\"/a/{id}\":{\"get\":{" ++
        "\"parameters\":[{\"name\":\"id\",\"in\":\"path\",\"required\":true,\"schema\":{}}],\"responses\":{\"200\":{\"description\":\"d\"}}}}},";
    const ok = [_][]const u8{
        "#/paths/~1a~1{id}/get",
        "#/paths/~1a~1%7Bid%7D/get",
        "#/paths/~1a~1%7bid%7d/get/parameters/0",
        "#/paths/%2Fa%2F%7Bid%7D",
    };
    const bad = [_][]const u8{
        "#/paths/~1a~1{id}/post",
        "#/paths/~1a~1%7Bid%7D/get/parameters/1",
        "#/paths/~1a~1%7Bid/get",
        "#/paths/~0a/get",
    };
    for (ok) |ref| {
        const text = try arena.print("{s}\"x\":{{\"$ref\":\"{s}\"}}}}", .{ head, ref });
        const doc = try std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{});
        try oa.validateOpenApi31(testing.allocator, doc);
    }
    for (bad) |ref| {
        const text = try arena.print("{s}\"x\":{{\"$ref\":\"{s}\"}}}}", .{ head, ref });
        const doc = try std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{});
        try testing.expectError(error.DanglingRef, oa.validateOpenApi31(testing.allocator, doc));
    }
}

test "validateOpenApi31: 30000 parameters and 20000 template variables on one path stay linear (sweep OA-3)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const head = "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"t\",\"version\":\"1\"},\"paths\":{";
    {
        // 30000 distinct query parameters in one list (the duplicate check)
        var text: std.ArrayList(u8) = .empty;
        try text.appendSlice(arena, head);
        try text.appendSlice(arena, "\"/x\":{\"get\":{\"responses\":{\"200\":{\"description\":\"d\"}},\"parameters\":[");
        for (0..30_000) |i| {
            if (i != 0) try text.append(arena, ',');
            try text.appendSlice(arena, try arena.print("{{\"name\":\"p{d}\",\"in\":\"query\",\"schema\":{{}}}}", .{i}));
        }
        try text.appendSlice(arena, "]}}}}");
        const doc = try std.json.parseFromSliceLeaky(std.json.Value, arena, text.items, .{});
        const t0 = monoNs();
        try oa.validateOpenApi31(testing.allocator, doc);
        try expectFast(t0);
    }
    {
        // 20000 template variables, each with its path parameter (both directions)
        const n = 20_000;
        var text: std.ArrayList(u8) = .empty;
        try text.appendSlice(arena, head);
        try text.appendSlice(arena, "\"/");
        for (0..n) |i| try text.appendSlice(arena, try arena.print("{{p{d}}}/", .{i}));
        try text.appendSlice(arena, "\":{\"get\":{\"responses\":{\"200\":{\"description\":\"d\"}},\"parameters\":[");
        for (0..n) |i| {
            if (i != 0) try text.append(arena, ',');
            try text.appendSlice(arena, try arena.print("{{\"name\":\"p{d}\",\"in\":\"path\",\"required\":true,\"schema\":{{}}}}", .{i}));
        }
        try text.appendSlice(arena, "]}}}}");
        const doc = try std.json.parseFromSliceLeaky(std.json.Value, arena, text.items, .{});
        const t0 = monoNs();
        try oa.validateOpenApi31(testing.allocator, doc);
        try expectFast(t0);
    }
}

test "validateOpenApi31: duplicate and undeclared path parameters are still found (sweep OA-3)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const pre = "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"t\",\"version\":\"1\"},\"paths\":{";
    const cases = [_]struct { path: []const u8, params: []const u8, want: anyerror }{
        .{ .path = "/x/{id}", .params = "[{\"name\":\"id\",\"in\":\"path\",\"required\":true,\"schema\":{}},{\"name\":\"id\",\"in\":\"path\",\"required\":true,\"schema\":{}}]", .want = error.DuplicateParameter },
        .{ .path = "/x/{id}", .params = "[{\"name\":\"q\",\"in\":\"query\",\"schema\":{}},{\"name\":\"id\",\"in\":\"path\",\"required\":true,\"schema\":{}},{\"name\":\"q\",\"in\":\"query\",\"schema\":{}}]", .want = error.DuplicateParameter },
        .{ .path = "/x/{id}", .params = "[{\"name\":\"id\",\"in\":\"path\",\"required\":true,\"schema\":{}},{\"name\":\"id\",\"in\":\"query\",\"schema\":{}}]", .want = error.OK },
        .{ .path = "/x/{id}", .params = "[]", .want = error.UnresolvedPathParameter },
        .{ .path = "/x/{id}", .params = "[{\"$ref\":\"#/components/parameters/p\"}]", .want = error.DanglingRef },
        .{ .path = "/x", .params = "[{\"name\":\"id\",\"in\":\"path\",\"required\":true,\"schema\":{}}]", .want = error.UndeclaredPathParameter },
        .{ .path = "/x/{a}/{b}", .params = "[{\"name\":\"a\",\"in\":\"path\",\"required\":true,\"schema\":{}}]", .want = error.UnresolvedPathParameter },
        .{ .path = "/x/{a", .params = "[]", .want = error.InvalidPathKey },
    };
    for (cases) |c| {
        const text = try arena.print("{s}\"{s}\":{{\"get\":{{\"responses\":{{\"200\":{{\"description\":\"d\"}}}},\"parameters\":{s}}}}}}}}}", .{ pre, c.path, c.params });
        const doc = try std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{});
        if (c.want == error.OK) {
            try oa.validateOpenApi31(testing.allocator, doc);
        } else {
            try testing.expectError(c.want, oa.validateOpenApi31(testing.allocator, doc));
        }
    }
}

test "build: JSON text nested more than 128 deep is refused, 128 is accepted (sweep OA-4)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const ok = try nestedObject(arena, 128);
    const deep = try nestedObject(arena, 129);

    const doc_ok: router.RouteDoc = .{ .request_schema = ok, .responses = &.{.{ .status = 200, .description = "d", .schema = ok }} };
    try buildOne(testing.allocator, .{ .method = .post, .pattern = "/x", .doc = &doc_ok }, info0);

    for ([_][]const u8{deep}) |bad| {
        const req: router.RouteDoc = .{ .request_schema = bad };
        try testing.expectError(error.InvalidRequestSchema, buildOne(testing.allocator, .{ .method = .post, .pattern = "/x", .doc = &req }, info0));
        const resp: router.RouteDoc = .{ .responses = &.{.{ .status = 200, .description = "d", .schema = bad }} };
        try testing.expectError(error.InvalidResponseSchema, buildOne(testing.allocator, .{ .method = .get, .pattern = "/x", .doc = &resp }, info0));
        // query_schema: the text itself (an object schema) nests too deep
        const q: router.RouteDoc = .{ .query_schema = bad };
        try testing.expectError(error.InvalidQuerySchema, buildOne(testing.allocator, .{ .method = .get, .pattern = "/x", .doc = &q }, info0));
        try testing.expectError(error.InvalidComponentSchema, buildOne(testing.allocator, .{ .method = .get, .pattern = "/x" }, .{
            .title = "T",
            .version = "1",
            .schemas = &.{.{ .name = "S", .schema = bad }},
        }));
        const route_x: router.Route = .{ .method = .get, .pattern = "/x" };
        try testing.expectError(error.InvalidExample, buildOne(testing.allocator, route_x, .{
            .title = "T",
            .version = "1",
            .route_extras = &.{.{ .method = .get, .pattern = "/x", .request_example = bad }},
        }));
        try testing.expectError(error.InvalidExample, buildOne(testing.allocator, route_x, .{
            .title = "T",
            .version = "1",
            .route_extras = &.{.{ .method = .get, .pattern = "/x", .response_examples = &.{.{ .status = 200, .json = bad }} }},
        }));
        try testing.expectError(error.InvalidParameterSchema, buildOne(testing.allocator, route_x, .{
            .title = "T",
            .version = "1",
            .route_extras = &.{.{ .method = .get, .pattern = "/x", .header_parameters = &.{.{ .name = "h", .schema = bad }} }},
        }));
    }

    // a query property that nests 126 deep (text depth 128) builds, with the
    // allOf wrapping a repeated property adds
    const prop = try nestedObject(arena, 126);
    const qtext = try arena.print("{{\"properties\":{{\"p\":{s}}}}}", .{prop});
    const qdoc: router.RouteDoc = .{ .query_schema = qtext };
    try buildOne(testing.allocator, .{ .method = .get, .pattern = "/x", .doc = &qdoc }, info0);
}

test "build: a request_schema nested 300000 deep is refused, not a crash (sweep OA-4)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const huge = try nestedObject(arena_state.allocator(), 300_000);
    const req: router.RouteDoc = .{ .request_schema = huge };
    try testing.expectError(error.InvalidRequestSchema, buildOne(testing.allocator, .{ .method = .post, .pattern = "/x", .doc = &req }, info0));
}

test "build: 12 segments joined by '/' or '_' (4096 routes, one operationId base) stay linear (sweep OA-5)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const segs = 13;
    const count = 1 << (segs - 1);
    const routes = try arena.alloc(router.Route, count);
    for (routes, 0..) |*rt, mask| {
        var p: std.ArrayList(u8) = .empty;
        try p.appendSlice(arena, "/s");
        for (0..segs - 1) |bit| {
            try p.append(arena, if (mask >> @intCast(bit) & 1 == 1) '/' else '_');
            try p.append(arena, 's');
        }
        rt.* = .{ .method = .get, .pattern = p.items };
    }
    const t0 = monoNs();
    const json = try Generator.buildRoutes(testing.allocator, routes, info0);
    defer testing.allocator.free(json);
    try expectFast(t0);
    // every operation got its own id: the first keeps the base, the rest _2.._4096
    try testing.expect(std.mem.find(u8, json, "\"operationId\":\"get_s_s_s_s_s_s_s_s_s_s_s_s_s_4096\"") != null);
}

test "build: a query_schema with 30000 properties and 30000 required names stays linear (sweep OA-5)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const n = 30_000;
    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(arena, "{\"properties\":{");
    for (0..n) |i| {
        if (i != 0) try text.append(arena, ',');
        try text.appendSlice(arena, try arena.print("\"p{d}\":{{\"type\":\"string\"}}", .{i}));
    }
    try text.appendSlice(arena, "},\"required\":[");
    for (0..n) |i| {
        if (i != 0) try text.append(arena, ',');
        try text.appendSlice(arena, try arena.print("\"p{d}\"", .{n - 1 - i}));
    }
    try text.appendSlice(arena, "]}");
    const doc: router.RouteDoc = .{ .query_schema = text.items };
    const t0 = monoNs();
    try buildOne(testing.allocator, .{ .method = .get, .pattern = "/x", .doc = &doc }, info0);
    try expectFast(t0);
}

test "build: a buildRoutes pattern with 20000 captures stays linear (sweep OA-5)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var p: std.ArrayList(u8) = .empty;
    for (0..20_000) |i| try p.appendSlice(arena, try arena.print("/:p{d}", .{i}));
    const t0 = monoNs();
    try buildOne(testing.allocator, .{ .method = .get, .pattern = p.items }, info0);
    try expectFast(t0);
}

test "build: a 40000-entry schema registry and 40000 security schemes stay linear (sweep OA-5)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const n = 40_000;
    const schemas = try arena.alloc(oa.NamedSchema, n);
    const schemes = try arena.alloc(oa.SecurityScheme, n);
    for (schemas, schemes, 0..) |*s, *c, i| {
        s.* = .{ .name = try arena.print("s{d}", .{i}), .schema = "{}" };
        c.* = .{ .name = try arena.print("a{d}", .{i}), .kind = .http_basic };
    }
    const t0 = monoNs();
    try buildOne(testing.allocator, .{ .method = .get, .pattern = "/x" }, .{ .title = "T", .version = "1", .schemas = schemas, .security_schemes = schemes });
    try expectFast(t0);
}

test "build: 30000 route_extras matched to 30000 routes stay linear, first entry wins (sweep OA-5)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const n = 30_000;
    const routes = try arena.alloc(router.Route, n);
    const extras = try arena.alloc(oa.RouteExtra, n + 1);
    for (routes, extras[0..n], 0..) |*rt, *x, i| {
        const pat = try arena.print("/r{d}", .{i});
        rt.* = .{ .method = .get, .pattern = pat };
        x.* = .{ .method = .get, .pattern = pat, .request_example = "1" };
    }
    // a later entry for /r0 must lose against the first one
    extras[n] = .{ .method = .get, .pattern = "/r0", .request_example = "2" };
    const t0 = monoNs();
    const json = try Generator.buildRoutes(testing.allocator, routes, .{ .title = "T", .version = "1", .route_extras = extras });
    defer testing.allocator.free(json);
    try expectFast(t0);
    try testing.expect(std.mem.find(u8, json, "\"/r0\":{\"get\":{\"operationId\":\"get_r0\",\"requestBody\":{\"content\":{\"application/json\":{\"example\":1}}") != null);
}
