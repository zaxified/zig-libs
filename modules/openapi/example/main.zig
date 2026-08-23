// SPDX-License-Identifier: MIT

//! What a service exposing a self-documenting API does with `openapi`:
//! register `Endpoint.middleware()` before the routes it documents (chi's
//! rule), attach `RouteDoc` metadata to one route, drive a real
//! `GET /openapi.json` request through the socket-free `http` codec, and
//! validate the emitted document two ways — this module's own
//! `validateOpenApi31` structural checker (offline, part of the published
//! API) AND a real, independently-installed OpenAPI 3.1 validator. Then see
//! a malformed request-body JSON Schema rejected by the generator's own
//! NAMED error before any document is emitted.
//!
//! External judge: `openapi-spec-validator` (Python, the reference OpenAPI
//! 3.1 validator; NOT installed anywhere in this repo or its CI — the
//! module's own SPEC.md/root.zig record that none was available on that
//! machine when it was written). It IS available here via `pipx run`
//! (network-fetched once into a pipx-managed venv), so it was actually run
//! against the exact bytes this example generates (captured to a file,
//! reproduced below verbatim):
//!
//!   {"openapi":"3.1.0","info":{"title":"Example API","version":"1.0.0"},
//!    "paths":{"/health":{"get":{"responses":{"200":{"description":
//!    "Successful Response"}}}},"/users":{"post":{"tags":["users"],
//!    "summary":"Create a user","requestBody":{"content":{"application/json":
//!    {"schema":{"type":"object","required":["name"]}}},"required":true},
//!    "responses":{"201":{"description":"Created"}}}},"/users/{id}":{"get":
//!    {"tags":["users"],"summary":"Fetch a user","parameters":[{"name":"id",
//!    "in":"path","required":true,"schema":{"type":"string"}}],"responses":
//!    {"200":{"description":"OK"}}}}}}
//!
//!   pipx run --no-cache openapi-spec-validator --schema 3.1 /tmp/openapi-example.json
//!   -> /tmp/openapi-example.json: OK
//!
//! Because invoking `pipx run` needs network on first use, the compiled
//! example itself stays offline/deterministic: it repeats the check with
//! `validateOpenApi31`, the same structural checker `root.zig` already
//! ships (info.title/version required, `paths`/`webhooks`/`components`
//! present, every operation's `responses` non-empty with a `description`
//! per response) — verified against the real external tool above, not
//! merely asserted.
//!
//! Built by `zig build check-examples` against the PUBLISHED module — no
//! access to anything `openapi` (or `router`/`http`) does not export.

const std = @import("std");
const http = @import("http");
const router = @import("router");
const openapi = @import("openapi");

fn hHealth(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}
fn hCreateUser(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(201);
    try ctx.res.writeAll("{}");
}
fn hGetUser(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll(ctx.params.get("id").?);
}

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(bytes);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [8192]u8 = undefined;
    var chunk_buf: [512]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = r,
        .server_name = null,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn bodyOf(got: []const u8) []const u8 {
    const i = std.mem.indexOf(u8, got, "\r\n\r\n") orelse return "";
    return got[i + 4 ..];
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var r = router.Router.init(gpa);
    defer r.deinit();

    var docs: openapi.Endpoint = .{
        .gpa = gpa,
        .router = &r,
        .info = .{ .title = "Example API", .version = "1.0.0" },
    };
    defer docs.deinit();
    try r.use(docs.middleware()); // BEFORE the documented routes (chi's rule)

    try r.get("/health", hHealth); // undocumented -> minimal default 200
    try r.addDoc(.post, "/users", hCreateUser, .{
        .summary = "Create a user",
        .tags = &.{"users"},
        .request_schema = "{\"type\":\"object\",\"required\":[\"name\"]}",
        .responses = &.{.{ .status = 201, .description = "Created" }},
    });
    try r.addDoc(.get, "/users/:id", hGetUser, .{
        .summary = "Fetch a user",
        .tags = &.{"users"},
        .responses = &.{.{ .status = 200, .description = "OK" }},
    });

    // ── the real endpoint, over real HTTP wire bytes ────────────────────
    var buf: [8192]u8 = undefined;
    const got = runWire(&r, "GET /openapi.json HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf);
    const doc_text = bodyOf(got);
    std.debug.print("GET /openapi.json: {d} bytes\n", .{doc_text.len});

    // ── this module's own structural OpenAPI 3.1 checker ────────────────
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, doc_text, .{});
    defer parsed.deinit();
    try openapi.validateOpenApi31(parsed.value);
    std.debug.print("validateOpenApi31: structurally valid OpenAPI 3.1\n", .{});

    // Sanity on the actual shape asserted: path param converted, tag/schema
    // surfaced, the undocumented route still got its default response.
    const paths = parsed.value.object.get("paths").?.object;
    if (paths.get("/users/{id}") == null) return error.MissingConvertedPathParam;
    const create = paths.get("/users").?.object.get("post").?.object;
    if (!std.mem.eql(u8, create.get("tags").?.array.items[0].string, "users"))
        return error.MissingTag;
    if (create.get("requestBody") == null) return error.MissingRequestBody;
    const health_get = paths.get("/health").?.object.get("get").?.object;
    if (health_get.get("responses").?.object.get("200") == null) return error.MissingDefaultResponse;
    std.debug.print("path params converted, tags/requestBody surfaced, default 200 present: OK\n", .{});

    // ── negative case, asserted by the generator's own NAMED error: a
    // route with a malformed request_schema must fail closed, not emit a
    // partial/invalid document ──────────────────────────────────────────
    var r2 = router.Router.init(gpa);
    defer r2.deinit();
    try r2.addDoc(.post, "/bad", hCreateUser, .{
        .request_schema = "{not valid json",
    });
    if (openapi.Generator.build(gpa, &r2, .{ .title = "Bad", .version = "0.0.1" })) |doc| {
        gpa.free(doc);
        return error.UnexpectedSuccess;
    } else |err| switch (err) {
        error.InvalidRequestSchema => std.debug.print("malformed request_schema: InvalidRequestSchema (expected)\n", .{}),
        else => return err,
    }
}
