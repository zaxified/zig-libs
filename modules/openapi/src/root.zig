// SPDX-License-Identifier: MIT

//! openapi — OpenAPI 3.1 document generation from a `router` route table,
//! plus a ready-made `GET /openapi.json` endpoint middleware.
//!
//! Model after **FastAPI's auto-generated spec** (the shape of the emitted
//! document — operation key order, path-parameter objects, the default
//! `"Successful Response"` 200) and **utoipa** (Rust; the
//! route-metadata-to-spec mapping). "Self-documentation": the spec is
//! derived from the live route table (`Router.routes()` + per-route
//! `RouteDoc`), so the docs cannot drift from the code.
//!
//! Layers:
//! - **`Generator`** — walks `Router.routes()` and emits a valid OpenAPI
//!   3.1 JSON document: `openapi: "3.1.0"`, `info` from `Info`, `paths`
//!   with router patterns converted to templates (`:id` → `{id}`,
//!   `*rest` → `{rest}`), methods grouped per path. Documented routes
//!   surface `summary`/`description`/`tags`/`requestBody`/`responses`/
//!   `deprecated`; undocumented ones get a minimal operation with a
//!   default `200`. Output is deterministic: paths in first-registration
//!   order, methods per path in `http.Method` declaration order, fixed key
//!   order inside every object (minified, no whitespace).
//! - **`Endpoint`** — an *intercepting* `router.Middleware` (the
//!   `metrics.Endpoint` pattern — `router.Handler` is a stateless fn
//!   pointer, it cannot close over state) serving the generated document
//!   on `GET /openapi.json` as `application/json`. The document is
//!   generated per request from the live Router, so the endpoint can (and
//!   must, chi's rule) be registered *before* the routes it documents.
//!   Optionally serves a tiny self-contained docs HTML page (`docs_path`)
//!   — **no external assets**: Swagger-UI needs CDN JS/CSS, so instead a
//!   minimal vanilla-JS viewer fetches the spec and lists the operations.
//!
//! Documented choices (matching FastAPI's generated-spec shape):
//! - Only registered routes are emitted — the implicit HEAD→GET auto-route
//!   and the 404/405 fallbacks are dispatch behavior, not operations.
//! - Path params always get `required: true` + `schema: {type: "string"}`
//!   (router captures are raw path bytes). A `*wildcard` becomes a regular
//!   `{param}` — OpenAPI has no cross-segment template, same compromise as
//!   FastAPI's `:path` converter.
//! - `RouteDoc.request_schema` (JSON Schema as text) is validated by
//!   parsing and re-emitted normalized (minified) under
//!   `requestBody.content."application/json".schema`, `required: true`;
//!   malformed text fails `build` with `error.InvalidRequestSchema`.
//! - `operationId` is omitted (optional in OpenAPI; no stable naming
//!   source in a fn-pointer table).
//! - Routes whose *converted* path collides (only possible with a literal
//!   `{`/`}` static segment) merge into one path item; the first
//!   registration wins per method — duplicate JSON keys are never emitted.

const std = @import("std");
const router = @import("router");
const http = @import("http");

pub const meta = .{
    .status = .gap,
    .platform = .any,
    .role = .util,
    // Pure function of an immutable (post-build) Router — no shared state;
    // the Endpoint generates per request on the dispatching thread.
    .concurrency = .reentrant,
    .model_after = "FastAPI auto-docs (generated-spec shape) + utoipa (Rust) / OpenAPI 3.1 spec",
    .deps = .{ "router", "http" },
};

const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;

// ── the document metadata ───────────────────────────────────────────────────

/// The OpenAPI `info` object (title + version are required by the spec).
pub const Info = struct {
    title: []const u8,
    version: []const u8,
    /// Optional `info.description` (omitted when null).
    description: ?[]const u8 = null,
};

pub const BuildError = error{
    OutOfMemory,
    /// A `RouteDoc.request_schema` is not valid JSON.
    InvalidRequestSchema,
};

// ── the generator ───────────────────────────────────────────────────────────

/// OpenAPI 3.1 document generation — see the module doc for the shape.
/// Namespace only (stateless): every call walks the Router's route table.
pub const Generator = struct {
    /// Build the document as owned JSON text (minified, deterministic).
    /// Caller frees with `gpa`. The Router must be done registering routes
    /// (a built Router is immutable, so this is safe from any thread).
    pub fn build(gpa: Allocator, r: *const router.Router, info: Info) BuildError![]u8 {
        var out: Writer.Allocating = .init(gpa);
        defer out.deinit();
        write(gpa, r, info, &out.writer) catch |err| switch (err) {
            // The allocating writer fails only on allocation failure.
            error.WriteFailed => return error.OutOfMemory,
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidRequestSchema => return error.InvalidRequestSchema,
        };
        return out.toOwnedSlice();
    }

    /// Stream the document into any writer. `gpa` is scratch (path
    /// conversion + request-schema validation) — everything is freed
    /// before returning.
    pub fn write(gpa: Allocator, r: *const router.Router, info: Info, w: *Writer) (BuildError || Writer.Error)!void {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const rs = r.routes();
        // Converted (templated) path per route, index-aligned with `rs`.
        const converted = try arena.alloc([]const u8, rs.len);
        for (converted, rs) |*slot, rt| slot.* = try convertPattern(arena, rt.pattern);
        // Unique paths in first-registration order.
        var paths: std.ArrayList([]const u8) = .empty;
        for (converted) |p| {
            for (paths.items) |seen| {
                if (std.mem.eql(u8, seen, p)) break;
            } else try paths.append(arena, p);
        }

        var jw: std.json.Stringify = .{ .writer = w, .options = .{} };
        try jw.beginObject();
        try jw.objectField("openapi");
        try jw.write("3.1.0");
        try jw.objectField("info");
        try jw.beginObject();
        try jw.objectField("title");
        try jw.write(info.title);
        try jw.objectField("version");
        try jw.write(info.version);
        if (info.description) |d| {
            try jw.objectField("description");
            try jw.write(d);
        }
        try jw.endObject();
        try jw.objectField("paths");
        try jw.beginObject();
        for (paths.items) |path| {
            try jw.objectField(path);
            try jw.beginObject();
            // Methods in http.Method declaration order — deterministic
            // regardless of registration order; first registration wins on
            // a (method, path) collision.
            inline for (@typeInfo(http.Method).@"enum".fields) |f| {
                const method: http.Method = @enumFromInt(f.value);
                for (rs, converted) |rt, cp| {
                    if (rt.method == method and std.mem.eql(u8, cp, path)) {
                        try writeOperation(&jw, arena, rt);
                        break;
                    }
                }
            }
            try jw.endObject();
        }
        try jw.endObject();
        try jw.endObject();
    }
};

/// `:param` / `*wild` segments → `{param}` / `{wild}` OpenAPI templates;
/// static segments pass through byte-for-byte.
fn convertPattern(arena: Allocator, pattern: []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.splitScalar(u8, pattern, '/');
    var first = true;
    while (it.next()) |seg| {
        if (!first) try out.append(arena, '/');
        first = false;
        if (seg.len != 0 and (seg[0] == ':' or seg[0] == '*')) {
            try out.append(arena, '{');
            try out.appendSlice(arena, seg[1..]);
            try out.append(arena, '}');
        } else {
            try out.appendSlice(arena, seg);
        }
    }
    return out.items;
}

/// One `"<method>": {operation}` member, FastAPI key order: tags, summary,
/// description, parameters, requestBody, responses, deprecated.
fn writeOperation(jw: *std.json.Stringify, arena: Allocator, rt: router.Route) (BuildError || Writer.Error)!void {
    try jw.objectField(@tagName(rt.method)); // OpenAPI method keys are lowercase
    try jw.beginObject();
    if (rt.doc) |d| {
        if (d.tags.len != 0) {
            try jw.objectField("tags");
            try jw.write(d.tags);
        }
        if (d.summary) |s| {
            try jw.objectField("summary");
            try jw.write(s);
        }
        if (d.description) |s| {
            try jw.objectField("description");
            try jw.write(s);
        }
    }
    try writePathParameters(jw, rt.pattern);
    if (rt.doc) |d| {
        if (d.request_schema) |schema_text| {
            const schema = std.json.parseFromSliceLeaky(std.json.Value, arena, schema_text, .{}) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidRequestSchema,
            };
            try jw.objectField("requestBody");
            try jw.beginObject();
            try jw.objectField("content");
            try jw.beginObject();
            try jw.objectField("application/json");
            try jw.beginObject();
            try jw.objectField("schema");
            try jw.write(schema); // re-emitted normalized (minified)
            try jw.endObject();
            try jw.endObject();
            try jw.objectField("required");
            try jw.write(true);
            try jw.endObject();
        }
    }
    try jw.objectField("responses");
    try jw.beginObject();
    if (rt.doc != null and rt.doc.?.responses.len != 0) {
        for (rt.doc.?.responses) |resp| {
            var code_buf: [5]u8 = undefined;
            const code = std.fmt.bufPrint(&code_buf, "{d}", .{resp.status}) catch unreachable;
            try jw.objectField(code);
            try jw.beginObject();
            try jw.objectField("description");
            try jw.write(resp.description);
            try jw.endObject();
        }
    } else {
        // FastAPI's default for an undocumented (or response-less) route.
        try jw.objectField("200");
        try jw.beginObject();
        try jw.objectField("description");
        try jw.write("Successful Response");
        try jw.endObject();
    }
    try jw.endObject();
    if (rt.doc) |d| {
        if (d.deprecated) {
            try jw.objectField("deprecated");
            try jw.write(true);
        }
    }
    try jw.endObject();
}

/// `parameters` for every `:param`/`*wild` in the pattern — path params
/// are always `required: true` with a string schema (raw path bytes).
fn writePathParameters(jw: *std.json.Stringify, pattern: []const u8) Writer.Error!void {
    var it = std.mem.splitScalar(u8, pattern, '/');
    var any = false;
    while (it.next()) |seg| {
        if (seg.len < 2 or (seg[0] != ':' and seg[0] != '*')) continue;
        if (!any) {
            try jw.objectField("parameters");
            try jw.beginArray();
            any = true;
        }
        try jw.beginObject();
        try jw.objectField("name");
        try jw.write(seg[1..]);
        try jw.objectField("in");
        try jw.write("path");
        try jw.objectField("required");
        try jw.write(true);
        try jw.objectField("schema");
        try jw.beginObject();
        try jw.objectField("type");
        try jw.write("string");
        try jw.endObject();
        try jw.endObject();
    }
    if (any) try jw.endArray();
}

// ── the /openapi.json endpoint ──────────────────────────────────────────────

/// The ready-made spec endpoint, as an *intercepting* `router.Middleware`
/// (the `metrics.Endpoint` pattern): `GET`/`HEAD` on `path` answers the
/// generated document (`application/json`) and never calls `next`; any
/// other method on `path` answers 405 + `Allow`; everything else passes
/// through. When `docs_path` is set, the same interception serves a tiny
/// **self-contained** docs HTML page there (vanilla JS fetching the spec —
/// deliberately not Swagger-UI, which would pull external JS/CSS).
///
/// The document is generated per request from the live Router — register
/// the middleware router-level *before* the routes (chi's rule); the spec
/// still reflects everything registered by serve time. Generation is
/// read-only over an immutable Router, so concurrent requests are safe.
/// The Endpoint must outlive the Router, at a stable address.
pub const Endpoint = struct {
    /// Per-request generation scratch; must be thread-safe when the server
    /// dispatches on multiple connection threads.
    gpa: Allocator,
    router: *const router.Router,
    info: Info,
    /// Byte-exact request path to intercept (router raw-matching rules).
    path: []const u8 = "/openapi.json",
    /// Optional docs-page path (e.g. "/docs"); null = no docs page.
    docs_path: ?[]const u8 = null,

    pub fn middleware(e: *Endpoint) router.Middleware {
        return .{ .state = e, .run = endpointRun };
    }
};

fn endpointRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const e: *Endpoint = @ptrCast(@alignCast(state.?));
    if (std.mem.eql(u8, ctx.req.path, e.path)) return serveIntercepted(e, ctx, .spec);
    if (e.docs_path) |dp| {
        if (std.mem.eql(u8, ctx.req.path, dp)) return serveIntercepted(e, ctx, .docs);
    }
    return next.run(ctx);
}

fn serveIntercepted(e: *Endpoint, ctx: *router.Ctx, what: enum { spec, docs }) anyerror!void {
    switch (ctx.req.method) {
        .get, .head => switch (what) {
            .spec => {
                const json = try Generator.build(e.gpa, e.router, e.info);
                defer e.gpa.free(json);
                ctx.res.setStatus(200);
                try ctx.res.setHeader("Content-Type", "application/json");
                try ctx.res.writeAll(json);
            },
            .docs => {
                ctx.res.setStatus(200);
                try ctx.res.setHeader("Content-Type", "text/html; charset=utf-8");
                try ctx.res.writeAll(docs_html_head);
                try ctx.res.writeAll(e.path);
                try ctx.res.writeAll(docs_html_tail);
            },
        },
        else => {
            ctx.res.setStatus(405);
            try ctx.res.setHeader("Allow", "GET, HEAD");
            try ctx.res.setHeader("Content-Type", "text/plain");
            try ctx.res.writeAll("Method Not Allowed\n");
        },
    }
}

// The minimal self-contained docs page: zero external assets (strict-CSP
// friendly), vanilla JS fetches the spec from the Endpoint's `path`
// (spliced between the two halves) and lists every operation.
const docs_html_head =
    \\<!doctype html>
    \\<meta charset="utf-8">
    \\<meta name="viewport" content="width=device-width,initial-scale=1">
    \\<title>API documentation</title>
    \\<style>
    \\body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:60rem;padding:0 1rem;color:#1a1a2e}
    \\h1{margin-bottom:.25rem}#v{color:#666;margin-top:0}
    \\.op{border:1px solid #ddd;border-radius:6px;padding:.6rem .8rem;margin:.5rem 0}
    \\.m{display:inline-block;min-width:4.5rem;text-align:center;font-weight:700;border-radius:4px;padding:.1rem .4rem;margin-right:.6rem;background:#e8eef9}
    \\code{font-size:1.05em}.dep{text-decoration:line-through;opacity:.6}
    \\.sum{color:#444;margin:.3rem 0 0 5.1rem}.tags{color:#888;font-size:.85em;margin-left:.6rem}
    \\</style>
    \\<h1 id="t"></h1><p id="v"></p><p id="d"></p><div id="ops"></div>
    \\<script>
    \\fetch("
;
const docs_html_tail =
    \\").then(function(r){return r.json()}).then(function(s){
    \\document.getElementById("t").textContent=s.info.title;
    \\document.getElementById("v").textContent="version "+s.info.version+" — OpenAPI "+s.openapi;
    \\document.getElementById("d").textContent=s.info.description||"";
    \\var ops=document.getElementById("ops");
    \\Object.keys(s.paths).forEach(function(p){
    \\  Object.keys(s.paths[p]).forEach(function(m){
    \\    var o=s.paths[p][m],div=document.createElement("div");div.className="op";
    \\    var head=document.createElement("div");
    \\    var b=document.createElement("span");b.className="m";b.textContent=m.toUpperCase();head.appendChild(b);
    \\    var c=document.createElement("code");c.textContent=p;if(o.deprecated)c.className="dep";head.appendChild(c);
    \\    if(o.tags){var tg=document.createElement("span");tg.className="tags";tg.textContent=o.tags.join(", ");head.appendChild(tg);}
    \\    div.appendChild(head);
    \\    if(o.summary){var su=document.createElement("div");su.className="sum";su.textContent=o.summary;div.appendChild(su);}
    \\    ops.appendChild(div);
    \\  });
    \\});
    \\});
    \\</script>
;

// ── tests: generation (offline) ─────────────────────────────────────────────

const testing = std.testing;

fn hOk(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}
fn hHello(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("hello");
}

test "generate: golden OpenAPI 3.1 document for a known route set" {
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/health", hOk); // undocumented → minimal operation
    try r.addDoc(.get, "/users/:id", hOk, .{
        .summary = "Fetch a user",
        .description = "Returns one user by id.",
        .tags = &.{"users"},
        .responses = &.{
            .{ .status = 200, .description = "The user" },
            .{ .status = 404, .description = "No such user" },
        },
    });
    try r.addDoc(.post, "/users", hOk, .{
        .summary = "Create a user",
        .request_schema = "{\"type\":\"object\",\"required\":[\"name\"]}",
        .responses = &.{.{ .status = 201, .description = "Created" }},
    });
    try r.addDoc(.delete, "/users/:id", hOk, .{ .deprecated = true });
    try r.get("/static/*path", hOk);

    const json = try Generator.build(testing.allocator, &r, .{
        .title = "Test API",
        .version = "1.2.3",
        .description = "A test.",
    });
    defer testing.allocator.free(json);

    try testing.expectEqualStrings("{\"openapi\":\"3.1.0\"," ++
        "\"info\":{\"title\":\"Test API\",\"version\":\"1.2.3\",\"description\":\"A test.\"}," ++
        "\"paths\":{" ++
        "\"/health\":{\"get\":{\"responses\":{\"200\":{\"description\":\"Successful Response\"}}}}," ++
        "\"/users/{id}\":{" ++
        "\"get\":{\"tags\":[\"users\"],\"summary\":\"Fetch a user\",\"description\":\"Returns one user by id.\"," ++
        "\"parameters\":[{\"name\":\"id\",\"in\":\"path\",\"required\":true,\"schema\":{\"type\":\"string\"}}]," ++
        "\"responses\":{\"200\":{\"description\":\"The user\"},\"404\":{\"description\":\"No such user\"}}}," ++
        "\"delete\":{" ++
        "\"parameters\":[{\"name\":\"id\",\"in\":\"path\",\"required\":true,\"schema\":{\"type\":\"string\"}}]," ++
        "\"responses\":{\"200\":{\"description\":\"Successful Response\"}},\"deprecated\":true}}," ++
        "\"/users\":{\"post\":{\"summary\":\"Create a user\"," ++
        "\"requestBody\":{\"content\":{\"application/json\":{\"schema\":{\"type\":\"object\",\"required\":[\"name\"]}}},\"required\":true}," ++
        "\"responses\":{\"201\":{\"description\":\"Created\"}}}}," ++
        "\"/static/{path}\":{\"get\":{" ++
        "\"parameters\":[{\"name\":\"path\",\"in\":\"path\",\"required\":true,\"schema\":{\"type\":\"string\"}}]," ++
        "\"responses\":{\"200\":{\"description\":\"Successful Response\"}}}}" ++
        "}}", json);

    // The golden text is also *valid JSON* with the right top-level shape.
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, json, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("3.1.0", parsed.value.object.get("openapi").?.string);
    try testing.expectEqualStrings("Test API", parsed.value.object.get("info").?.object.get("title").?.string);
    try testing.expectEqual(@as(usize, 4), parsed.value.object.get("paths").?.object.count());
}

test "generate: empty router → valid empty-paths document, no panic" {
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    const json = try Generator.build(testing.allocator, &r, .{ .title = "T", .version = "0.0.0" });
    defer testing.allocator.free(json);
    try testing.expectEqualStrings("{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"T\",\"version\":\"0.0.0\"},\"paths\":{}}", json);
    // ...and it parses.
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, json, .{});
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 0), parsed.value.object.get("paths").?.object.count());
}

test "generate: method grouping is deterministic (enum order, not registration order)" {
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.post("/thing", hOk); // registered before get...
    try r.get("/thing", hOk);
    const json = try Generator.build(testing.allocator, &r, .{ .title = "T", .version = "1" });
    defer testing.allocator.free(json);
    // ...but emitted in http.Method declaration order: get before post.
    try testing.expectEqualStrings("{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"T\",\"version\":\"1\"}," ++
        "\"paths\":{\"/thing\":{" ++
        "\"get\":{\"responses\":{\"200\":{\"description\":\"Successful Response\"}}}," ++
        "\"post\":{\"responses\":{\"200\":{\"description\":\"Successful Response\"}}}" ++
        "}}}", json);
}

test "generate: malformed request_schema → error.InvalidRequestSchema" {
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.addDoc(.post, "/x", hOk, .{ .request_schema = "{nope" });
    try testing.expectError(
        error.InvalidRequestSchema,
        Generator.build(testing.allocator, &r, .{ .title = "T", .version = "1" }),
    );
}

// ── tests: endpoint over the socket-free server codec ───────────────────────

const Reader = std.Io.Reader;

/// Drive a router through `http.Server.serveStream` with canned wire bytes
/// (same harness as the router/metrics tests).
fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [8192]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = r,
        .server_name = null, // keep assertions free of Server/Date noise
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn wire(comptime method: []const u8, comptime target: []const u8) []const u8 {
    return method ++ " " ++ target ++ " HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
}

fn expectStatus(got: []const u8, comptime status: []const u8) !void {
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 " ++ status));
}

fn expectHeaderLine(got: []const u8, comptime line: []const u8) !void {
    try testing.expect(std.mem.indexOf(u8, got, "\r\n" ++ line ++ "\r\n") != null);
}

fn bodyOf(got: []const u8) []const u8 {
    return got[std.mem.indexOf(u8, got, "\r\n\r\n").? + 4 ..];
}

test "endpoint: serves the spec, 405 on other methods, passthrough elsewhere" {
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    var e: Endpoint = .{
        .gpa = testing.allocator,
        .router = &r,
        .info = .{ .title = "Wired API", .version = "2.0" },
    };
    // Middleware first (chi's rule) — the spec is generated per request,
    // so it still sees the routes registered below.
    try r.use(e.middleware());
    try r.get("/hello", hHello);
    try r.addDoc(.get, "/users/:id", hOk, .{ .summary = "Fetch" });

    var buf: [16384]u8 = undefined;
    { // GET /openapi.json → 200 application/json, parses, contains the routes
        const got = runWire(&r, wire("GET", "/openapi.json"), &buf);
        try expectStatus(got, "200");
        try expectHeaderLine(got, "Content-Type: application/json");
        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, bodyOf(got), .{});
        defer parsed.deinit();
        const paths = parsed.value.object.get("paths").?.object;
        try testing.expect(paths.get("/hello") != null);
        const get_users = paths.get("/users/{id}").?.object.get("get").?.object;
        try testing.expectEqualStrings("Fetch", get_users.get("summary").?.string);
        try testing.expectEqualStrings("Wired API", parsed.value.object.get("info").?.object.get("title").?.string);
    }
    { // wrong method on the spec path → 405 + Allow
        const got = runWire(&r, wire("POST", "/openapi.json"), &buf);
        try expectStatus(got, "405");
        try expectHeaderLine(got, "Allow: GET, HEAD");
    }
    { // other paths pass through to the routes
        const got = runWire(&r, wire("GET", "/hello"), &buf);
        try expectStatus(got, "200");
        try testing.expectEqualStrings("hello", bodyOf(got));
    }
    { // no docs page unless enabled
        try expectStatus(runWire(&r, wire("GET", "/docs"), &buf), "404");
    }
}

test "endpoint: self-contained docs page (no external assets)" {
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    var e: Endpoint = .{
        .gpa = testing.allocator,
        .router = &r,
        .info = .{ .title = "T", .version = "1" },
        .docs_path = "/docs",
    };
    try r.use(e.middleware());
    try r.get("/hello", hHello);

    var buf: [16384]u8 = undefined;
    const got = runWire(&r, wire("GET", "/docs"), &buf);
    try expectStatus(got, "200");
    try expectHeaderLine(got, "Content-Type: text/html; charset=utf-8");
    const body = bodyOf(got);
    try testing.expect(std.mem.startsWith(u8, body, "<!doctype html>"));
    // The page fetches the endpoint's spec path...
    try testing.expect(std.mem.indexOf(u8, body, "fetch(\"/openapi.json\")") != null);
    // ...and pulls nothing external: no URLs, no src=/href= at all.
    try testing.expect(std.mem.indexOf(u8, body, "http://") == null);
    try testing.expect(std.mem.indexOf(u8, body, "https://") == null);
    try testing.expect(std.mem.indexOf(u8, body, "src=") == null);
    try testing.expect(std.mem.indexOf(u8, body, "href=") == null);
}

// ── tests: in-process integration (http.Server + http.Client) ───────────────

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

test "integration: GET /openapi.json over a real socket returns the documented routes" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    var e: Endpoint = .{
        .gpa = testing.allocator,
        .router = &r,
        .info = .{ .title = "Integration API", .version = "0.1.0" },
    };
    try r.use(e.middleware());
    try r.get("/hello", hHello);
    try r.addDoc(.post, "/users", hOk, .{
        .summary = "Create a user",
        .responses = &.{.{ .status = 201, .description = "Created" }},
    });
    try r.get("/users/:id", hOk);

    var server = http.Server.init(io, testing.allocator, .{
        .handler = r.handler(),
        .context = &r,
    });
    defer server.deinit();
    server.bind() catch |err| {
        std.debug.print("loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();

    const port = server.boundAddress().getPort();
    var client = http.Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;

    { // the spec endpoint
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/openapi.json", .{port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("application/json", res.header("content-type").?);
        const body = try res.readAllAlloc(testing.allocator, 65536);
        defer testing.allocator.free(body);

        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, body, .{});
        defer parsed.deinit();
        try testing.expectEqualStrings("3.1.0", parsed.value.object.get("openapi").?.string);
        const paths = parsed.value.object.get("paths").?.object;
        try testing.expect(paths.get("/hello") != null);
        try testing.expect(paths.get("/users/{id}") != null);
        const post_users = paths.get("/users").?.object.get("post").?.object;
        try testing.expectEqualStrings("Create a user", post_users.get("summary").?.string);
        try testing.expect(post_users.get("responses").?.object.get("201") != null);
    }
    { // documented routes still dispatch normally alongside the endpoint
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/hello", .{port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        const body = try res.readAllAlloc(testing.allocator, 1024);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("hello", body);
    }
}
