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
//!   on `GET /openapi.json` as `application/json`. The document is built
//!   once, lazily, on the first request and cached thereafter (the Router
//!   is immutable once serving), so the endpoint can (and must, chi's rule)
//!   be registered *before* the routes it documents.
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
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "OpenAPI 3.1 spec generated from the route table + `/openapi.json`",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    // `Generator.build` itself is a pure function of an immutable
    // (post-build) Router — reentrant, no shared state. `Endpoint.spec`
    // adds one piece of shared mutable state (the cache) behind a spinlock,
    // so the middleware as a whole is `.threadsafe`, not `.reentrant`.
    .concurrency = .threadsafe,
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
    /// Optional per-route filter: return `false` to omit a route from the
    /// generated document entirely (FastAPI's `include_in_schema=False`,
    /// utoipa's opt-in `#[utoipa::path(...)]`) — audit finding openapi-F11.
    /// `null` (default) includes every registered route, the pre-fix
    /// behavior. An excluded route's metadata is never even UTF-8-checked
    /// or written, so it also cannot trigger `error.InvalidUtf8` or
    /// `error.PathCollision` against a route that IS included.
    include: ?*const fn (router.Route) bool = null,
    /// Declare HTTP bearer authentication (`components.securitySchemes.
    /// bearerAuth`, RFC 6750) and require it on every operation (top-level
    /// `security`). For an API whose every route sits behind a bearer token.
    bearer_auth: bool = false,
};

pub const BuildError = error{
    OutOfMemory,
    /// A `RouteDoc.request_schema` is not valid JSON.
    InvalidRequestSchema,
    /// A `RouteDoc.Response.schema` is not valid JSON.
    InvalidResponseSchema,
    /// Route/document metadata (`Info` field, `RouteDoc` field, or a route
    /// pattern) is not valid UTF-8 (audit finding openapi-F4). JSON text
    /// MUST be valid UTF-8 (RFC 8259 §8.1); `std.json.Stringify.write`
    /// does not enforce that for `[]const u8` — it silently switches a
    /// non-UTF-8 string to a JSON array of byte values instead, and via
    /// `objectField` (used for path/parameter/response-code keys, which
    /// skip that switch entirely) invalid bytes go out raw, unescaped, and
    /// unparseable. Checked up front, before any output is written, so a
    /// bad byte anywhere fails the whole build atomically rather than
    /// emitting a partial document.
    InvalidUtf8,
    /// Two different routes convert to the same `(path, method)` --
    /// e.g. `/f/:p` and `/f/*p` both become `/f/{p}`, or a literal
    /// `/f/{p}` collides with `/f/:p` (audit finding openapi-F5).
    /// `router` accepts both as distinct, independently dispatchable
    /// routes (different trie edge types), so silently keeping only the
    /// first (the pre-fix "first registration wins" rule, still correct
    /// for a genuinely duplicate key -- see F3/F6) would make a real,
    /// reachable route disappear from the document without a trace.
    PathCollision,
    /// This module's own generated JSON failed to parse back (F9's
    /// self-check, below) -- would mean a bug in the generator itself,
    /// not a caller input problem; surfaced rather than served.
    SelfCheckMalformed,
} || ConformanceError;

// ── the generator ───────────────────────────────────────────────────────────

/// OpenAPI 3.1 document generation — see the module doc for the shape.
/// Namespace only (stateless): every call walks the Router's route table.
pub const Generator = struct {
    /// Build the document as owned JSON text (minified, deterministic).
    /// Caller frees with `gpa`. The Router must be done registering routes
    /// (a built Router is immutable, so this is safe from any thread).
    ///
    /// Runs this module's OWN `validateOpenApi31` on its OWN output before
    /// returning (audit finding openapi-F9): the checker already existed
    /// and already catches exactly the defects `write` cannot rule out by
    /// construction alone (F4's non-UTF-8-turned-array is caught up front
    /// instead, but an empty `info.title`/`info.version`, say, was not),
    /// yet used to run only in this module's own tests, never on a real
    /// document before it reached a client. Costs one extra parse of the
    /// whole document -- paid once per `Endpoint`'s lifetime, since F1's
    /// fix already caches the build outcome (success or failure) after the
    /// first call.
    pub fn build(gpa: Allocator, r: *const router.Router, info: Info) BuildError![]u8 {
        return buildRoutes(gpa, r.routes(), info);
    }

    /// `build` over a plain route slice -- for a server whose route table is
    /// not a `router.Router` (a comptime `router.Static` table, or its own),
    /// which describes its routes as `router.Route` values: method, full
    /// pattern in `Router.add` syntax, optional `RouteDoc`.
    pub fn buildRoutes(gpa: Allocator, routes: []const router.Route, info: Info) BuildError![]u8 {
        var out: Writer.Allocating = .init(gpa);
        defer out.deinit();
        writeRoutes(gpa, routes, info, &out.writer) catch |err| switch (err) {
            // The allocating writer fails only on allocation failure.
            error.WriteFailed => return error.OutOfMemory,
            else => |e| return e,
        };
        const json = out.writer.buffered();
        const parsed = std.json.parseFromSlice(std.json.Value, gpa, json, .{}) catch
            return error.SelfCheckMalformed;
        defer parsed.deinit();
        try validateOpenApi31(parsed.value);
        return out.toOwnedSlice();
    }

    /// Stream the document into any writer. `gpa` is scratch (path
    /// conversion + request-schema validation) — everything is freed
    /// before returning.
    pub fn write(gpa: Allocator, r: *const router.Router, info: Info, w: *Writer) (BuildError || Writer.Error)!void {
        return writeRoutes(gpa, r.routes(), info, w);
    }

    /// `write` over a plain route slice; see `buildRoutes`.
    pub fn writeRoutes(gpa: Allocator, routes: []const router.Route, info: Info, w: *Writer) (BuildError || Writer.Error)!void {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        // F4 (A1/openapi.md): every byte this function is about to hand to
        // `std.json.Stringify` must be valid UTF-8 BEFORE any output is
        // written -- checked here, atomically, rather than discovered
        // mid-document (a `[]const u8` field silently becomes a JSON array
        // of byte values instead of a string; an `objectField` key goes out
        // raw and unescaped, producing text `std.json` itself refuses to
        // re-parse).
        try checkUtf8(info.title);
        try checkUtf8(info.version);
        if (info.description) |d| try checkUtf8(d);

        // F11 (A1/openapi.md): `info.include` filters BEFORE anything else
        // touches a route -- an excluded route's metadata is never
        // UTF-8-checked, converted, or written, so it cannot trigger
        // `error.InvalidUtf8`/`error.PathCollision` against a route that
        // IS included, and it never appears in the document at all.
        const rs: []const router.Route = if (info.include) |shouldInclude| blk: {
            var kept: std.ArrayList(router.Route) = .empty;
            for (routes) |rt| {
                if (shouldInclude(rt)) try kept.append(arena, rt);
            }
            break :blk kept.items;
        } else routes;
        for (rs) |rt| {
            try checkUtf8(rt.pattern); // covers the converted path too --
            // `convertPattern` only rewrites `:`/`*`/`{`/`}`, all ASCII
            if (rt.doc) |d| {
                if (d.summary) |s| try checkUtf8(s);
                if (d.description) |s| try checkUtf8(s);
                for (d.tags) |t| try checkUtf8(t);
                for (d.responses) |resp| {
                    try checkUtf8(resp.description);
                    try checkUtf8(resp.media_type);
                }
            }
        }

        // Converted (templated) path per route, index-aligned with `rs`.
        const converted = try arena.alloc([]const u8, rs.len);
        for (converted, rs) |*slot, rt| slot.* = try convertPattern(arena, rt.pattern);
        // Unique paths in first-registration order, with the (registration-
        // order) list of route indices at each path — one hashmap pass
        // instead of the old O(routes·paths) linear-scan dedup, and the
        // per-path route lists below turn the method-grouping loop from
        // O(paths·13·routes) into O(routes·13): each route is visited once
        // to build its group, then each group (summing to `routes` total)
        // is scanned once per HTTP method.
        var paths: std.ArrayList([]const u8) = .empty;
        var path_index: std.StringArrayHashMapUnmanaged(usize) = .empty;
        var route_groups: std.ArrayList(std.ArrayList(usize)) = .empty;
        for (converted, 0..) |p, i| {
            const gop = try path_index.getOrPut(arena, p);
            if (!gop.found_existing) {
                gop.value_ptr.* = paths.items.len;
                try paths.append(arena, p);
                try route_groups.append(arena, .empty);
            }
            try route_groups.items[gop.value_ptr.*].append(arena, i);
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
        if (info.bearer_auth) {
            try jw.objectField("security");
            try jw.beginArray();
            try jw.beginObject();
            try jw.objectField("bearerAuth");
            try jw.beginArray();
            try jw.endArray();
            try jw.endObject();
            try jw.endArray();
        }
        try jw.objectField("paths");
        try jw.beginObject();
        for (paths.items, route_groups.items) |path, group| {
            try jw.objectField(path);
            try jw.beginObject();
            // Methods in http.Method declaration order — deterministic
            // regardless of registration order. `group` already holds only
            // the routes at THIS path (registration order), so this inner
            // scan is bounded by that path's own route count, not by all
            // routes. F5 (A1/openapi.md): TWO DIFFERENT routes converting
            // to the same (path, method) -- e.g. `/f/:p` and `/f/*p`, both
            // `router`-legal, both independently dispatchable, both
            // becoming `/f/{p}` here -- used to silently keep only the
            // first and drop the other from the document entirely. That is
            // different from a genuinely duplicate key (F3/F6, where
            // "first wins" is correct because there is only ONE underlying
            // route/value); here it is `error.PathCollision`, not a silent
            // merge.
            inline for (@typeInfo(http.Method).@"enum".fields) |f| {
                const method: http.Method = @enumFromInt(f.value);
                var match: ?usize = null;
                for (group.items) |i| {
                    if (rs[i].method == method) {
                        if (match != null) return error.PathCollision;
                        match = i;
                    }
                }
                if (match) |i| {
                    try writeOperation(&jw, arena, rs[i], path);
                }
            }
            try jw.endObject();
        }
        try jw.endObject();
        if (info.bearer_auth) {
            try jw.objectField("components");
            try jw.beginObject();
            try jw.objectField("securitySchemes");
            try jw.beginObject();
            try jw.objectField("bearerAuth");
            try jw.beginObject();
            try jw.objectField("type");
            try jw.write("http");
            try jw.objectField("scheme");
            try jw.write("bearer");
            try jw.endObject();
            try jw.endObject();
            try jw.endObject();
        }
        try jw.endObject();
    }
};

/// F4 (A1/openapi.md): JSON text MUST be valid UTF-8 (RFC 8259 §8.1).
fn checkUtf8(s: []const u8) BuildError!void {
    if (!std.unicode.utf8ValidateSlice(s)) return error.InvalidUtf8;
}

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
/// description, operationId, parameters, requestBody, responses, deprecated.
fn writeOperation(
    jw: *std.json.Stringify,
    arena: Allocator,
    rt: router.Route,
    converted_path: []const u8,
) (BuildError || Writer.Error)!void {
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
    try writeOperationId(jw, arena, rt.method, converted_path);
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
        // F3 (wave-2 audit): two `RouteDoc.Response`s sharing a `status`
        // used to both get written, producing a duplicate JSON object key
        // -- a document `std.json`, the very parser this module's own
        // tests and docs page use, refuses to re-read
        // (`error.DuplicateField`), contradicting this module's own doc
        // comment ("duplicate JSON keys are never emitted"). Same "first
        // registration wins" rule `writePathParameters` already applies to
        // a duplicate path-parameter name (F6) -- code brought in line
        // with the documented contract (P2), not a new error: the
        // pre-fix output was not valid JSON at all, so there is no
        // well-formed behavior being taken away.
        var seen_buf: [32]u16 = undefined;
        var seen_count: usize = 0;
        for (rt.doc.?.responses) |resp| {
            const dup = for (seen_buf[0..seen_count]) |s| {
                if (s == resp.status) break true;
            } else false;
            if (dup) continue;
            if (seen_count < seen_buf.len) {
                seen_buf[seen_count] = resp.status;
                seen_count += 1;
            }
            var code_buf: [5]u8 = undefined;
            const code = std.fmt.bufPrint(&code_buf, "{d}", .{resp.status}) catch unreachable;
            try jw.objectField(code);
            try jw.beginObject();
            try jw.objectField("description");
            try jw.write(resp.description);
            if (resp.schema) |schema_text| {
                const schema = std.json.parseFromSliceLeaky(std.json.Value, arena, schema_text, .{}) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.InvalidResponseSchema,
                };
                try jw.objectField("content");
                try jw.beginObject();
                try jw.objectField(resp.media_type);
                try jw.beginObject();
                try jw.objectField("schema");
                try jw.write(schema);
                try jw.endObject();
                try jw.endObject();
            }
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

/// Deterministic `operationId` (audit finding openapi-F13): lowercase
/// method + `_` + the converted path's segments joined by `_`, with a
/// templated segment's `{`/`}` stripped (keeping the capture's own name).
/// `/users/{id}` + GET -> `get_users_id`; root `/` + GET -> `get` (no
/// segments to append). Unique across one document BY CONSTRUCTION: this
/// is textually `(method, converted_path)`, and F5's `error.PathCollision`
/// already guarantees that pair cannot repeat. `operationId` is optional
/// in OpenAPI 3.1, but omitting it (the pre-fix behavior, justified only
/// as "no stable naming source in a fn-pointer table") gave up a real one
/// most generators rely on: without it, SDK generators invent method
/// names themselves, and those names are not stable across regenerations.
fn writeOperationId(
    jw: *std.json.Stringify,
    arena: Allocator,
    method: http.Method,
    converted_path: []const u8,
) (BuildError || Writer.Error)!void {
    var id: std.ArrayList(u8) = .empty;
    try id.appendSlice(arena, @tagName(method));
    var it = std.mem.splitScalar(u8, converted_path, '/');
    while (it.next()) |seg| {
        if (seg.len == 0) continue;
        try id.append(arena, '_');
        if (seg.len >= 2 and seg[0] == '{' and seg[seg.len - 1] == '}') {
            try id.appendSlice(arena, seg[1 .. seg.len - 1]);
        } else {
            try id.appendSlice(arena, seg);
        }
    }
    try jw.objectField("operationId");
    try jw.write(id.items);
}

/// `parameters` for every `:param`/`*wild` in the pattern — path params
/// are always `required: true` with a string schema (raw path bytes).
///
/// A pattern that captures the same name twice (`/:id/.../:id`) would
/// otherwise emit a duplicate `(name, in)` pair, which OAS 3.1 §4.8.10
/// explicitly forbids ("The list MUST NOT include duplicated
/// parameters."). `router` itself now refuses to register such a pattern
/// (audit finding router-F8, closing this module's own Š2 seam), so no
/// live caller can reach this anymore — the capped array of seen names
/// below (path segments are bounded in practice; router patterns are
/// short) stays as defense in depth, deduping without allocating.
fn writePathParameters(jw: *std.json.Stringify, pattern: []const u8) Writer.Error!void {
    var it = std.mem.splitScalar(u8, pattern, '/');
    var any = false;
    var seen_buf: [64][]const u8 = undefined;
    var seen_count: usize = 0;
    while (it.next()) |seg| {
        if (seg.len < 2 or (seg[0] != ':' and seg[0] != '*')) continue;
        const name = seg[1..];
        const dup = for (seen_buf[0..seen_count]) |s| {
            if (std.mem.eql(u8, s, name)) break true;
        } else false;
        if (dup) continue;
        if (seen_count < seen_buf.len) {
            seen_buf[seen_count] = name;
            seen_count += 1;
        }
        if (!any) {
            try jw.objectField("parameters");
            try jw.beginArray();
            any = true;
        }
        try jw.beginObject();
        try jw.objectField("name");
        try jw.write(name);
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
/// The document is generated **once**, lazily, on the first request that
/// needs it — register the middleware router-level *before* the routes
/// (chi's rule). **All registration (`add`/`addDoc`/`group`) must finish
/// before the Router is handed to `http.Server`/any concurrent dispatch —
/// same precondition `Generator.build` itself documents, and the same
/// "building is single-owner" phase `router/SPEC.md` §Concurrency already
/// requires** (audit finding openapi-F10): `r.routes()` is read once,
/// unsynchronized, on whichever thread's request happens to trigger the
/// build, so a route registered concurrently with that read — not merely
/// *before* it in wall-clock time, but genuinely racing it — is a data
/// race on `Router`'s own backing slice, not something this module (or
/// `router`) makes safe. Once registration has fully completed and dispatch
/// begins, though, `router.Router` is immutable for the rest of its life
/// (`router/SPEC.md` §Concurrency), so a document generated once stays
/// correct for the Endpoint's whole lifetime — caching it removes the
/// per-request re-walk-and-re-parse cost with no invalidation to get wrong.
/// A build that FAILS (an invalid `RouteDoc.request_schema`) caches too —
/// it fails identically every time, so there is nothing to gain by paying
/// full cost again on the next request. The Endpoint must outlive the
/// Router, at a stable address.
pub const Endpoint = struct {
    /// Generation scratch and the cache's owner.
    gpa: Allocator,
    router: *const router.Router,
    info: Info,
    /// Byte-exact request path to intercept (router raw-matching rules).
    path: []const u8 = "/openapi.json",
    /// Optional docs-page path (e.g. "/docs"); null = no docs page.
    docs_path: ?[]const u8 = null,

    /// The cached build outcome, resolved on first access; `null` until
    /// then. Guarded by `lock` — `spec()` may race across the server's
    /// per-connection threads on the first request. A FAILED build is
    /// cached too (as `.err`): a `RouteDoc.request_schema` that fails to
    /// parse fails identically on every call (the Router is immutable
    /// once serving), so recomputing it per request buys nothing but cost
    /// — see the F1 regression test below.
    cached: ?CachedResult = null,
    lock: std.atomic.Mutex = .unlocked,

    pub fn middleware(e: *Endpoint) router.Middleware {
        return .{ .state = e, .run = endpointRun };
    }

    /// Free the cached document, if one was ever built. Call when the
    /// Endpoint is done serving.
    pub fn deinit(e: *Endpoint) void {
        if (e.cached) |c| switch (c) {
            .ok => |doc| e.gpa.free(doc.json),
            .err => {},
        };
        e.* = undefined;
    }

    /// The generated document (with its precomputed ETag), resolving it
    /// (once) on first use — success or failure both stick, so a later
    /// call never repeats the walk.
    fn spec(e: *Endpoint) BuildError!CachedDoc {
        // Fast path: someone already resolved it. Peek-under-lock only —
        // no work happens while `lock` is held, so this never blocks a
        // concurrent builder for longer than a pointer copy.
        lockSpin(&e.lock);
        const resolved = e.cached;
        e.lock.unlock();
        if (resolved) |c| return c.unwrap();

        // Slow path: build OUTSIDE the lock. Concurrent first-callers may
        // duplicate the walk once (bounded — never more than `nthreads`
        // rebuilds, never the O(N²) pile-up a build-under-lock produces),
        // but none of them spins on a lock held across hundreds of ms of
        // work; see F2 in the audit for the wall-time cost of that.
        const result: CachedResult = if (Generator.build(e.gpa, e.router, e.info)) |doc|
            .{ .ok = .{ .json = doc, .etag = etagOf(doc) } }
        else |err|
            .{ .err = err };

        lockSpin(&e.lock);
        defer e.lock.unlock();
        if (e.cached == null) {
            e.cached = result;
        } else if (result == .ok) {
            // Lost the race — another thread already published. Free our
            // redundant copy rather than leak it.
            e.gpa.free(result.ok.json);
        }
        return e.cached.?.unwrap();
    }
};

/// The generated document plus its precomputed strong `ETag` (F14): the
/// document is immutable for the Endpoint's whole lifetime (that is the
/// entire premise of caching it — see the struct doc above), so hashing it
/// once at build time and handing 304s to clients that already have it is
/// the same insight the cache itself is built on, just applied to the wire
/// instead of the CPU.
const CachedDoc = struct {
    json: []const u8,
    /// Quoted strong ETag, e.g. `"0123456789abcdef"` — a fixed-seed Wyhash
    /// fingerprint of `json` (same pattern as `filestore.versionOf`).
    etag: [18]u8,
};

/// Fixed seed ("openapi__" truncated to 8 bytes) so the ETag is stable
/// across process restarts serving the identical document, not derived
/// from ASLR/pointer/PID.
const etag_seed: u64 = 0x6f70656e6170695f;

fn etagOf(json: []const u8) [18]u8 {
    const h = std.hash.Wyhash.hash(etag_seed, json);
    var buf: [18]u8 = undefined;
    buf[0] = '"';
    _ = std.fmt.bufPrint(buf[1..17], "{x:0>16}", .{h}) catch unreachable;
    buf[17] = '"';
    return buf;
}

/// A resolved `Endpoint.spec()` outcome — success or the `BuildError` that
/// would otherwise have to be reproduced (at full cost) on every request.
const CachedResult = union(enum) {
    ok: CachedDoc,
    err: BuildError,

    fn unwrap(c: CachedResult) BuildError!CachedDoc {
        return switch (c) {
            .ok => |doc| doc,
            .err => |err| err,
        };
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

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
                const doc = try e.spec();
                // F14: the document is provably immutable for the
                // Endpoint's whole lifetime (see CachedDoc doc comment), so
                // a client that already has it can be told so with a 304
                // instead of re-sending the whole body every scrape.
                // `http.conditional` already implements the RFC 9110 §8.8.3
                // comparison (weak match, `*`, multi-value lists) and stages
                // the 304 (with `ETag`, no body) on a match; reuse it rather
                // than re-deriving those rules here.
                if (try http.conditional.apply(ctx.req, ctx.res, .{ .etag = &doc.etag })) return;
                ctx.res.setStatus(200);
                try ctx.res.setHeader("Content-Type", "application/json");
                try ctx.res.writeAll(doc.json);
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

// ── conformance: a real OpenAPI 3.1 structural validator ────────────────────
//
// Every generation test below checked the emitted JSON only for (a) exact
// byte-identity with a hand-typed string and (b) `std.json` well-formedness —
// which proves the writer produces *some* JSON matching what a human typed,
// never that the document is *valid OpenAPI*. No OpenAPI validator
// (`openapi-spec-validator`, `redocly`/`spectral`) is installed on this
// machine (checked: no matching Python package, no `node`/`npm` at all), and
// this task must not install one, so the tool-oracle route is blocked here.
//
// This module only ever *generates* documents — it has no parser for
// arbitrary third-party OpenAPI text, so "adopt an official example and feed
// it through our parser" (the suggested alternative) does not apply as
// written. What plays the equivalent role: `oai_webhook_example` below is a
// frozen, verbatim copy of the OpenAPI Initiative's OWN official example
// document (see NOTICE for provenance/license), and `validateOpenApi31`
// implements the structural rules a real OpenAPI 3.1 document must satisfy
// (info.title/version required; at least one of paths/webhooks/components —
// the actual 3.1 relaxation of 3.0's "paths always required"; every
// operation's `responses` non-empty with a `description` per response).
// That checker is run against BOTH the adopted official document — which
// deliberately omits `paths` entirely in favor of `webhooks`+`components`,
// exercising a shape none of this module's own tests produce — and this
// module's own generated goldens below, closing the actual gap: those
// goldens now assert structural OpenAPI validity, not merely a string match
// against what a human transcribed.
pub const ConformanceError = error{
    NotAnObject,
    MissingOpenApiVersion,
    UnsupportedOpenApiVersion,
    MissingInfo,
    MissingInfoTitle,
    MissingInfoVersion,
    MissingTopLevelContent,
    InvalidPathKey,
    InvalidPathItem,
    InvalidOperation,
    MissingResponses,
    EmptyResponses,
    InvalidResponse,
    MissingResponseDescription,
};

pub fn validateOpenApi31(doc: std.json.Value) ConformanceError!void {
    if (doc != .object) return error.NotAnObject;
    const root = doc.object;

    const openapi_val = root.get("openapi") orelse return error.MissingOpenApiVersion;
    if (openapi_val != .string) return error.MissingOpenApiVersion;
    if (!std.mem.startsWith(u8, openapi_val.string, "3.1.")) return error.UnsupportedOpenApiVersion;

    const info_val = root.get("info") orelse return error.MissingInfo;
    if (info_val != .object) return error.MissingInfo;
    const title = info_val.object.get("title") orelse return error.MissingInfoTitle;
    if (title != .string or title.string.len == 0) return error.MissingInfoTitle;
    const version = info_val.object.get("version") orelse return error.MissingInfoVersion;
    if (version != .string or version.string.len == 0) return error.MissingInfoVersion;

    // OAS 3.1 §4.8.1: unlike 3.0 (where `paths` was always required), 3.1
    // makes `paths` optional PROVIDED `webhooks` or `components` describes
    // something instead — a document with none of the three describes
    // nothing at all.
    if (root.get("paths") == null and root.get("webhooks") == null and root.get("components") == null) {
        return error.MissingTopLevelContent;
    }

    if (root.get("paths")) |v| try validatePathsObject(v, .paths);
    if (root.get("webhooks")) |v| try validatePathsObject(v, .webhooks);
}

const PathsKind = enum { paths, webhooks };

fn validatePathsObject(paths_val: std.json.Value, comptime kind: PathsKind) ConformanceError!void {
    if (paths_val != .object) return error.InvalidPathItem;
    var it = paths_val.object.iterator();
    while (it.next()) |entry| {
        if (kind == .paths and (entry.key_ptr.len == 0 or entry.key_ptr.*[0] != '/')) return error.InvalidPathKey;
        try validatePathItem(entry.value_ptr.*);
    }
}

const http_method_keys = [_][]const u8{ "get", "put", "post", "delete", "options", "head", "patch", "trace" };

fn validatePathItem(item_val: std.json.Value) ConformanceError!void {
    if (item_val != .object) return error.InvalidPathItem;
    var it = item_val.object.iterator();
    while (it.next()) |entry| {
        var is_method = false;
        for (http_method_keys) |m| {
            if (std.mem.eql(u8, entry.key_ptr.*, m)) {
                is_method = true;
                break;
            }
        }
        // Non-method keys ($ref, summary, description, servers, parameters)
        // are legal path-item members this checker does not deeply verify.
        if (!is_method) continue;
        try validateOperation(entry.value_ptr.*);
    }
}

fn validateOperation(op_val: std.json.Value) ConformanceError!void {
    if (op_val != .object) return error.InvalidOperation;
    const responses_val = op_val.object.get("responses") orelse return error.MissingResponses;
    if (responses_val != .object) return error.MissingResponses;
    if (responses_val.object.count() == 0) return error.EmptyResponses;
    var rit = responses_val.object.iterator();
    while (rit.next()) |rentry| {
        if (rentry.value_ptr.* != .object) return error.InvalidResponse;
        const desc = rentry.value_ptr.*.object.get("description") orelse return error.MissingResponseDescription;
        if (desc != .string) return error.MissingResponseDescription;
    }
}

/// A frozen, verbatim copy of `examples/v3.1/webhook-example.json` from the
/// OpenAPI Initiative's own `OAI/OpenAPI-Specification` repository, pinned at
/// the `3.1.0` tag (fetched 2026-08-01; Apache License 2.0 — see NOTICE).
/// Deliberately chosen because it omits `paths` entirely (using `webhooks` +
/// `components` instead) — a shape this module's own generator never
/// produces (it always emits a `paths` key, even when empty), so validating
/// this document exercises a real branch of `validateOpenApi31` that this
/// module's own goldens below cannot reach on their own.
const oai_webhook_example =
    \\{
    \\  "openapi": "3.1.0",
    \\  "info": {
    \\    "title": "Webhook Example",
    \\    "version": "1.0.0"
    \\  },
    \\  "webhooks": {
    \\    "newPet": {
    \\      "post": {
    \\        "requestBody": {
    \\          "description": "Information about a new pet in the system",
    \\          "content": {
    \\            "application/json": {
    \\              "schema": {
    \\                "$ref": "#/components/schemas/Pet"
    \\              }
    \\            }
    \\          }
    \\        },
    \\        "responses": {
    \\          "200": {
    \\            "description": "Return a 200 status to indicate that the data was received successfully"
    \\          }
    \\        }
    \\      }
    \\    }
    \\  },
    \\  "components": {
    \\    "schemas": {
    \\      "Pet": {
    \\        "required": [
    \\          "id",
    \\          "name"
    \\        ],
    \\        "properties": {
    \\          "id": {
    \\            "type": "integer",
    \\            "format": "int64"
    \\          },
    \\          "name": {
    \\            "type": "string"
    \\          },
    \\          "tag": {
    \\            "type": "string"
    \\          }
    \\        }
    \\      }
    \\    }
    \\  }
    \\}
;

test "conformance: the checker accepts the OpenAPI Initiative's own published v3.1 example" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, oai_webhook_example, .{});
    defer parsed.deinit();
    try validateOpenApi31(parsed.value);
}

test "conformance: the checker rejects documents missing required structure (sanity: it is not vacuous)" {
    const allocator = std.testing.allocator;
    {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"T\",\"version\":\"1\"}}", .{});
        defer parsed.deinit();
        try testing.expectError(error.MissingTopLevelContent, validateOpenApi31(parsed.value));
    }
    {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"T\",\"version\":\"1\"},\"paths\":{\"/x\":{\"get\":{}}}}", .{});
        defer parsed.deinit();
        try testing.expectError(error.MissingResponses, validateOpenApi31(parsed.value));
    }
    {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, "{\"openapi\":\"2.0\",\"info\":{\"title\":\"T\",\"version\":\"1\"},\"paths\":{}}", .{});
        defer parsed.deinit();
        try testing.expectError(error.UnsupportedOpenApiVersion, validateOpenApi31(parsed.value));
    }
}

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
        "\"/health\":{\"get\":{\"operationId\":\"get_health\",\"responses\":{\"200\":{\"description\":\"Successful Response\"}}}}," ++
        "\"/users/{id}\":{" ++
        "\"get\":{\"tags\":[\"users\"],\"summary\":\"Fetch a user\",\"description\":\"Returns one user by id.\"," ++
        "\"operationId\":\"get_users_id\"," ++
        "\"parameters\":[{\"name\":\"id\",\"in\":\"path\",\"required\":true,\"schema\":{\"type\":\"string\"}}]," ++
        "\"responses\":{\"200\":{\"description\":\"The user\"},\"404\":{\"description\":\"No such user\"}}}," ++
        "\"delete\":{\"operationId\":\"delete_users_id\"," ++
        "\"parameters\":[{\"name\":\"id\",\"in\":\"path\",\"required\":true,\"schema\":{\"type\":\"string\"}}]," ++
        "\"responses\":{\"200\":{\"description\":\"Successful Response\"}},\"deprecated\":true}}," ++
        "\"/users\":{\"post\":{\"summary\":\"Create a user\",\"operationId\":\"post_users\"," ++
        "\"requestBody\":{\"content\":{\"application/json\":{\"schema\":{\"type\":\"object\",\"required\":[\"name\"]}}},\"required\":true}," ++
        "\"responses\":{\"201\":{\"description\":\"Created\"}}}}," ++
        "\"/static/{path}\":{\"get\":{\"operationId\":\"get_static_path\"," ++
        "\"parameters\":[{\"name\":\"path\",\"in\":\"path\",\"required\":true,\"schema\":{\"type\":\"string\"}}]," ++
        "\"responses\":{\"200\":{\"description\":\"Successful Response\"}}}}" ++
        "}}", json);

    // The golden text is also *valid JSON* with the right top-level shape.
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, json, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("3.1.0", parsed.value.object.get("openapi").?.string);
    try testing.expectEqualStrings("Test API", parsed.value.object.get("info").?.object.get("title").?.string);
    try testing.expectEqual(@as(usize, 4), parsed.value.object.get("paths").?.object.count());
    // Byte-identity with our own hand-typed string, and bare JSON
    // well-formedness, prove nothing about real OpenAPI 3.1 validity (see the
    // conformance-checker section above) — also run the real structural
    // checker against it.
    try validateOpenApi31(parsed.value);
}

test "generate: buildRoutes over a plain slice equals build over the Router with the same routes" {
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    const user_doc: router.RouteDoc = .{
        .summary = "Fetch a user",
        .tags = &.{"users"},
        .responses = &.{.{ .status = 200, .description = "The user" }},
    };
    try r.get("/health", hOk);
    try r.addDoc(.get, "/users/:id", hOk, user_doc);
    try r.get("/static/*path", hOk);

    const plain = [_]router.Route{
        .{ .method = .get, .pattern = "/health" },
        .{ .method = .get, .pattern = "/users/:id", .doc = &user_doc },
        .{ .method = .get, .pattern = "/static/*path" },
    };
    const info: Info = .{ .title = "T", .version = "1" };
    const from_router = try Generator.build(testing.allocator, &r, info);
    defer testing.allocator.free(from_router);
    const from_slice = try Generator.buildRoutes(testing.allocator, &plain, info);
    defer testing.allocator.free(from_slice);
    try testing.expectEqualStrings(from_router, from_slice);
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
    try validateOpenApi31(parsed.value); // an empty `paths` object still satisfies §4.8.1
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
        "\"get\":{\"operationId\":\"get_thing\",\"responses\":{\"200\":{\"description\":\"Successful Response\"}}}," ++
        "\"post\":{\"operationId\":\"post_thing\",\"responses\":{\"200\":{\"description\":\"Successful Response\"}}}" ++
        "}}}", json);
}

test "generate: colliding (method, path) from two different patterns is a build error, not a silent drop (F5)" {
    // "/users/:id" and the literal "/users/{id}" both convert to the same
    // OpenAPI path template, and both are legal, independently
    // dispatchable `router` routes. Before the F5 fix, the module silently
    // kept only the FIRST registration and dropped the second's
    // `RouteDoc` (and, for a param/wildcard pair, the second's entire
    // documented operation) from the document without a trace. That is a
    // different situation from a genuinely duplicate key (F3: two
    // `RouteDoc.Response`s sharing a status code, one underlying route --
    // "first wins" there is correct because there is only ONE value to
    // pick from), so it is now `error.PathCollision` instead.
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.addDoc(.get, "/users/:id", hOk, .{ .summary = "First" });
    try r.addDoc(.get, "/users/{id}", hOk, .{ .summary = "Second" });

    try testing.expectError(
        error.PathCollision,
        Generator.build(testing.allocator, &r, .{ .title = "T", .version = "1" }),
    );
}

test "generate: /f/:p and /f/*p collide too (F5) — audit's own repro" {
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.addDoc(.get, "/f/:p", hOk, .{ .summary = "param" });
    try r.addDoc(.get, "/f/*p", hOk, .{ .summary = "wildcard" });

    try testing.expectError(
        error.PathCollision,
        Generator.build(testing.allocator, &r, .{ .title = "T", .version = "1" }),
    );
}

test "generate: same converted path, DIFFERENT methods, is NOT a collision (F5 does not over-fire)" {
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.addDoc(.get, "/f/:p", hOk, .{ .summary = "read" });
    try r.addDoc(.post, "/f/*p", hOk, .{ .summary = "write" });

    const json = try Generator.build(testing.allocator, &r, .{ .title = "T", .version = "1" });
    defer testing.allocator.free(json);
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, json, .{});
    defer parsed.deinit();
    const path_item = parsed.value.object.get("paths").?.object.get("/f/{p}").?.object;
    try testing.expectEqual(@as(usize, 2), path_item.count()); // "get" AND "post", both present
    try testing.expectEqualStrings("read", path_item.get("get").?.object.get("summary").?.string);
    try testing.expectEqualStrings("write", path_item.get("post").?.object.get("summary").?.string);
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

fn excludeInternal(rt: router.Route) bool {
    return !std.mem.startsWith(u8, rt.pattern, "/internal");
}
test "generate: Info.include filters a route out of the document entirely (F11)" {
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/public", hOk);
    try r.get("/internal/rotate-key", hOk);

    // Without a filter: both routes appear (pre-fix, and still the default).
    {
        const json = try Generator.build(testing.allocator, &r, .{ .title = "T", .version = "1" });
        defer testing.allocator.free(json);
        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, json, .{});
        defer parsed.deinit();
        const paths = parsed.value.object.get("paths").?.object;
        try testing.expect(paths.get("/public") != null);
        try testing.expect(paths.get("/internal/rotate-key") != null);
    }
    // With a filter: the excluded route is gone, not merely marked.
    {
        const json = try Generator.build(testing.allocator, &r, .{
            .title = "T",
            .version = "1",
            .include = excludeInternal,
        });
        defer testing.allocator.free(json);
        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, json, .{});
        defer parsed.deinit();
        const paths = parsed.value.object.get("paths").?.object;
        try testing.expect(paths.get("/public") != null);
        try testing.expect(paths.get("/internal/rotate-key") == null);
        try testing.expectEqual(@as(usize, 1), paths.count());
    }
}

test "generate: non-UTF-8 metadata is rejected, not silently turned into a JSON array (F4)" {
    // Before this fix: `std.json.Stringify.write([]const u8)` does not
    // validate UTF-8 -- it switches a non-UTF-8 slice from a JSON string
    // to a JSON array of byte values instead, silently, contradicting a
    // PASS-log claim ("route metadata cannot break the document
    // structure") this audit round falsified. JSON text MUST be valid
    // UTF-8 (RFC 8259 §8.1).
    const bad = "Acme\xffAPI";
    try testing.expect(!std.unicode.utf8ValidateSlice(bad)); // the fixture is genuinely invalid

    {
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.get("/x", hOk);
        try testing.expectError(
            error.InvalidUtf8,
            Generator.build(testing.allocator, &r, .{ .title = bad, .version = "1" }),
        );
    }
    {
        // Route metadata (not just Info), and the pattern/path itself.
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.addDoc(.get, "/x", hOk, .{ .summary = bad });
        try testing.expectError(
            error.InvalidUtf8,
            Generator.build(testing.allocator, &r, .{ .title = "T", .version = "1" }),
        );
    }
    {
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.addDoc(.get, "/bad" ++ "\xff" ++ "seg", hOk, .{});
        try testing.expectError(
            error.InvalidUtf8,
            Generator.build(testing.allocator, &r, .{ .title = "T", .version = "1" }),
        );
    }
    // Valid UTF-8 (including non-ASCII) keeps working.
    {
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.get("/x", hOk);
        const json = try Generator.build(testing.allocator, &r, .{ .title = "Acmé API", .version = "1" });
        defer testing.allocator.free(json);
        try testing.expect(std.unicode.utf8ValidateSlice(json));
    }
}

test "generate: Generator.build now runs its own validateOpenApi31 on its own output (F9), closing F12 (empty title) as a side effect" {
    // F9: the checker existed and already caught this class of defect
    // (`MissingInfoTitle`) in this module's own tests, but `build` never
    // ran it on a real document before handing it to a caller. F12 (empty
    // `info.title`/`version` silently emitted) is a strict subset of F9 --
    // wiring the checker in closes both with one fix, verified here.
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/x", hOk);
    try testing.expectError(
        error.MissingInfoTitle,
        Generator.build(testing.allocator, &r, .{ .title = "", .version = "1" }),
    );
    try testing.expectError(
        error.MissingInfoVersion,
        Generator.build(testing.allocator, &r, .{ .title = "T", .version = "" }),
    );
    // A well-formed document still builds and still passes the checker
    // (proving the self-check isn't just rejecting everything).
    const json = try Generator.build(testing.allocator, &r, .{ .title = "T", .version = "1" });
    defer testing.allocator.free(json);
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, json, .{});
    defer parsed.deinit();
    try validateOpenApi31(parsed.value);
}

// ── external anchor: independently validated by `openapi_spec_validator` ───
//
// The structural checker above (`validateOpenApi31`) and the adopted OAI
// example prove this module accepts a real document and that its own hand-
// written rules fire — neither proves a real, schema-driven OpenAPI 3.1
// validator agrees. `openapi_spec_validator` (the JSON-Schema-backed
// reference implementation, `/usr/bin/openapi-spec-validator`, installed by
// the user 2026-09-11 for exactly this — Q6, `QUESTIONS-ROUND-2.md`) was run
// offline against four documents:
//
//   1. The exact JSON this module's own `Generator.build` produces for the
//      route set in "generate: golden OpenAPI 3.1 document for a known
//      route set" below (reproduced verbatim as `own_generated_document`,
//      RE-VERIFIED 2026-09-11 after openapi-F13 added `operationId`):
//      `openapi-spec-validator --schema 3.1 own_generated_document.json` ->
//      `OK`, exit 0 — a real, independent, schema-based validator confirms
//      this module's own output, `operationId` included, is a genuinely
//      valid OpenAPI 3.1 document, not merely "well-formed JSON that
//      satisfies our own checker".
//   2. A deliberately invalid document, `response_missing_description`,
//      missing the (real, OAS-required) `description` on a response object.
//      `openapi_spec_validator` rejected it: `OpenAPIValidationError:
//      'description' is a required property` (2026-08-01, verbatim) — the
//      SAME reason this module's own `validateOpenApi31` already reports as
//      `error.MissingResponseDescription`, confirmed against the real spec
//      rather than assumed.
//   3. openapi-F13 (2026-09-11): a document with two operations sharing one
//      `operationId` (OAS 3.1 §4.8.10: "operationId... MUST be unique among
//      all operations described in the API") — `openapi_spec_validator`
//      REJECTED it: `Operation ID 'dupe' for 'get' in '/b' is not unique`,
//      exit 1. This is the property `writeOperationId`'s doc comment claims
//      "by construction" (`operationId` is textually `(method,
//      converted_path)`, and F5's `error.PathCollision` already guarantees
//      that pair cannot repeat in one document) — independently confirmed
//      to be a real, checked constraint, not an assumed one.
//   4. The SAME golden document with `operationId` REMOVED from one
//      operation, everything else unchanged — `openapi_spec_validator`
//      still accepts it (`operationId` is optional per OAS 3.1), confirming
//      #1's PASS is not an artifact of every operation having one.
//
// **No disagreement was found** for any of the four. Per the governing
// rule, the tool is run offline and its verdict frozen in this comment;
// the committed tests do not shell out or open a socket. No `/NOTICE`
// entry: `openapi_spec_validator` is used purely as a black-box validating
// oracle (root NOTICE §0, the relationship already recorded for
// `protobuf`/`syslog`/`opcua`/
// `wireguard`/`xmlsec1`) — the module's existing NOTICE for the adopted OAI
// example document is unrelated and unaffected.
const own_generated_document = "{\"openapi\":\"3.1.0\"," ++
    "\"info\":{\"title\":\"Test API\",\"version\":\"1.2.3\",\"description\":\"A test.\"}," ++
    "\"paths\":{" ++
    "\"/health\":{\"get\":{\"operationId\":\"get_health\",\"responses\":{\"200\":{\"description\":\"Successful Response\"}}}}," ++
    "\"/users/{id}\":{" ++
    "\"get\":{\"tags\":[\"users\"],\"summary\":\"Fetch a user\",\"description\":\"Returns one user by id.\"," ++
    "\"operationId\":\"get_users_id\"," ++
    "\"parameters\":[{\"name\":\"id\",\"in\":\"path\",\"required\":true,\"schema\":{\"type\":\"string\"}}]," ++
    "\"responses\":{\"200\":{\"description\":\"The user\"},\"404\":{\"description\":\"No such user\"}}}," ++
    "\"delete\":{\"operationId\":\"delete_users_id\"," ++
    "\"parameters\":[{\"name\":\"id\",\"in\":\"path\",\"required\":true,\"schema\":{\"type\":\"string\"}}]," ++
    "\"responses\":{\"200\":{\"description\":\"Successful Response\"}},\"deprecated\":true}}," ++
    "\"/users\":{\"post\":{\"summary\":\"Create a user\",\"operationId\":\"post_users\"," ++
    "\"requestBody\":{\"content\":{\"application/json\":{\"schema\":{\"type\":\"object\",\"required\":[\"name\"]}}},\"required\":true}," ++
    "\"responses\":{\"201\":{\"description\":\"Created\"}}}}," ++
    "\"/static/{path}\":{\"get\":{\"operationId\":\"get_static_path\"," ++
    "\"parameters\":[{\"name\":\"path\",\"in\":\"path\",\"required\":true,\"schema\":{\"type\":\"string\"}}]," ++
    "\"responses\":{\"200\":{\"description\":\"Successful Response\"}}}}" ++
    "}}";

test "external anchor: our generator's own output is genuinely valid OpenAPI 3.1 (frozen 2026-08-01)" {
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.get("/health", hOk);
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

    // The exact bytes `openapi_spec_validator.validate()` accepted with no
    // exception raised.
    try testing.expectEqualStrings(own_generated_document, json);
}

test "external anchor: response schemas and bearer auth (frozen 2026-09-22)" {
    const routes = [_]router.Route{
        .{ .method = .post, .pattern = "/users", .doc = &.{
            .summary = "Create a user",
            .request_schema = "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}},\"required\":[\"name\"]}",
            .responses = &.{
                .{ .status = 201, .description = "Created", .schema = "{\"type\":\"object\",\"properties\":{\"id\":{\"type\":\"integer\"}}}" },
                .{ .status = 422, .description = "Invalid body", .media_type = "application/problem+json", .schema = "{\"type\":\"object\"}" },
                .{ .status = 401, .description = "No valid token" },
            },
        } },
    };
    const json = try Generator.buildRoutes(testing.allocator, &routes, .{
        .title = "T",
        .version = "1",
        .bearer_auth = true,
    });
    defer testing.allocator.free(json);
    // The exact bytes `openapi_spec_validator.validate()` 0.7.1 accepted.
    try testing.expectEqualStrings(
        \\{"openapi":"3.1.0","info":{"title":"T","version":"1"},"security":[{"bearerAuth":[]}],"paths":{"/users":{"post":{"summary":"Create a user","operationId":"post_users","requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}}},"required":true},"responses":{"201":{"description":"Created","content":{"application/json":{"schema":{"type":"object","properties":{"id":{"type":"integer"}}}}}},"422":{"description":"Invalid body","content":{"application/problem+json":{"schema":{"type":"object"}}}},"401":{"description":"No valid token"}}}}},"components":{"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer"}}}}
    , json);
}

test "generate: malformed response schema -> error.InvalidResponseSchema" {
    const routes = [_]router.Route{.{ .method = .get, .pattern = "/x", .doc = &.{
        .responses = &.{.{ .status = 200, .description = "ok", .schema = "{nope" }},
    } }};
    try testing.expectError(error.InvalidResponseSchema, Generator.buildRoutes(testing.allocator, &routes, .{ .title = "T", .version = "1" }));
}

test "external anchor: a document our checker rejects, a real validator rejects too — same reason (frozen 2026-08-01)" {
    const allocator = testing.allocator;
    const response_missing_description =
        \\{"openapi":"3.1.0","info":{"title":"Bad API","version":"1.0.0"},
        \\ "paths":{"/broken":{"get":{"responses":{"200":{}}}}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, response_missing_description, .{});
    defer parsed.deinit();
    // Our own checker: error.MissingResponseDescription.
    // openapi_spec_validator (2026-08-01, verbatim): OpenAPIValidationError:
    // 'description' is a required property (validating
    // .paths./broken.get.responses.200 against the OAS 3.1 Response Object
    // schema) — the same structural defect, independently confirmed.
    try testing.expectError(error.MissingResponseDescription, validateOpenApi31(parsed.value));
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
    defer e.deinit();
    // Middleware first (chi's rule) — the spec is generated lazily on first
    // request, so it still sees the routes registered below.
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
    { // HEAD is accepted too (the Allow header above advertises it)
        const got = runWire(&r, wire("HEAD", "/openapi.json"), &buf);
        try expectStatus(got, "200");
        try expectHeaderLine(got, "Content-Type: application/json");
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

test "endpoint: the spec is built once and cached, not regenerated per request (F1)" {
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    var e: Endpoint = .{
        .gpa = testing.allocator,
        .router = &r,
        .info = .{ .title = "T", .version = "1" },
    };
    defer e.deinit();
    try r.use(e.middleware());
    try r.get("/hello", hHello);

    var buf: [16384]u8 = undefined;
    // First request builds (and caches) the document — "/late" is not
    // registered yet, so it must be absent.
    const first = runWire(&r, wire("GET", "/openapi.json"), &buf);
    try expectStatus(first, "200");
    try testing.expect(std.mem.indexOf(u8, bodyOf(first), "/late") == null);

    // Register a route AFTER the cache was populated. A per-request
    // generator (the old behavior) would pick this up on the very next
    // request; a cache must not.
    try r.get("/late", hHello);
    const second = runWire(&r, wire("GET", "/openapi.json"), &buf);
    try expectStatus(second, "200");
    try testing.expect(std.mem.indexOf(u8, bodyOf(second), "/late") == null);
}

fn clkNs(comptime which: std.os.linux.clockid_t) u64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(which, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}
fn cpuNs() u64 {
    return clkNs(.PROCESS_CPUTIME_ID);
}
fn monoNs() u64 {
    return clkNs(.MONOTONIC);
}

fn addBenchRoutes(r: *router.Router, n: usize, poison_last: bool) !void {
    var name_buf: [64]u8 = undefined;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const p = try std.fmt.bufPrint(&name_buf, "/api/v1/resource{d}/:id", .{i});
        const last = (i == n - 1);
        try r.addDoc(.get, p, hOk, .{
            .summary = "Fetch one",
            .description = "Returns a single resource by its identifier.",
            .tags = &.{"resources"},
            .request_schema = if (last and poison_last)
                "{\"type\":\"object\"," // truncated -> InvalidRequestSchema
            else
                "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\"}}}",
            .responses = &.{.{ .status = 200, .description = "OK" }},
        });
    }
}

test "endpoint: a malformed request_schema fails once, then a CACHED error on every later call (F1)" {
    // Debug-mode timing is too noisy for the ratio assertion below (GC
    // pauses, no optimization); the correctness half (same error every
    // time) still runs, at a smaller N so Debug stays fast.
    const release = @import("builtin").mode != .Debug;
    const n: usize = if (release) 3000 else 200;
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try addBenchRoutes(&r, n, true);
    var e: Endpoint = .{ .gpa = testing.allocator, .router = &r, .info = .{ .title = "T", .version = "1" } };
    defer e.deinit();

    const c0 = cpuNs();
    try testing.expectError(error.InvalidRequestSchema, e.spec());
    const c1 = cpuNs();
    try testing.expectError(error.InvalidRequestSchema, e.spec());
    const c2 = cpuNs();
    try testing.expectError(error.InvalidRequestSchema, e.spec());
    const c3 = cpuNs();

    const first = c1 - c0;
    const second = c2 - c1;
    const third = c3 - c2;
    // Diagnostic only. The lane turns stderr from a PASSING test into a FAIL
    // (scripts/lib/test-lib.sh), so the number is opt-in; the assertions below run
    // either way.
    if (std.process.Environ.getPosix(std.testing.environ, "OPENAPI_VERBOSE") != null) {
        std.debug.print("\n[F1] {d} routes, first={d}ns second={d}ns third={d}ns\n", .{ n, first, second, third });
    }
    // Before the fix (`if (e.cached == null) e.cached = try Generator.build(...)`),
    // the error branch never populated `e.cached`, so EVERY call re-walked
    // the whole route table — measured in A1/openapi.md F1 as 173-191ms per
    // call, 5 calls straight, never converging. After it, only the first
    // call does that work; every later call returns the cached error.
    if (release) {
        try testing.expect(second * 20 < first);
        try testing.expect(third * 20 < first);
    }
}

const SpecWorkerCtx = struct { e: *Endpoint, err_count: std.atomic.Value(u32) = .init(0) };

fn specWorker(c: *SpecWorkerCtx) void {
    _ = c.e.spec() catch {
        _ = c.err_count.fetchAdd(1, .monotonic);
    };
}

/// An allocator that, on every call, records whether the Endpoint's lock was
/// held at that moment. `Generator.build` allocates through `Endpoint.gpa`,
/// so this sees the lock from INSIDE the build.
const LockProbeAllocator = struct {
    inner: Allocator,
    lock: *std.atomic.Mutex,
    calls: usize = 0,
    calls_under_lock: usize = 0,

    fn allocator(p: *LockProbeAllocator) Allocator {
        return .{ .ptr = p, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn probe(p: *LockProbeAllocator) void {
        p.calls += 1;
        if (p.lock.tryLock()) p.lock.unlock() else p.calls_under_lock += 1;
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const p: *LockProbeAllocator = @ptrCast(@alignCast(ctx));
        p.probe();
        return p.inner.rawAlloc(len, a, ra);
    }
    fn resize(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) bool {
        const p: *LockProbeAllocator = @ptrCast(@alignCast(ctx));
        p.probe();
        return p.inner.rawResize(m, a, n, ra);
    }
    fn remap(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const p: *LockProbeAllocator = @ptrCast(@alignCast(ctx));
        p.probe();
        return p.inner.rawRemap(m, a, n, ra);
    }
    fn free(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
        const p: *LockProbeAllocator = @ptrCast(@alignCast(ctx));
        p.inner.rawFree(m, a, ra);
    }
};

test "endpoint: the document is built with the lock released (F2)" {
    // F2: `spec()` held its spinlock across the whole `Generator.build`, so
    // concurrent first callers spun behind hundreds of ms of work (932 ->
    // 1762 ms wall with more callers, A1/openapi.md F2). The fix builds
    // outside the lock. This checks that structurally rather than by wall
    // time, which a loaded CI runner cannot be trusted with: every
    // allocation the build makes looks at the lock, and none may find it
    // held. (The only allocation-free work under the lock is the cache peek
    // and publish.)
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try addBenchRoutes(&r, 50, false);

    var e: Endpoint = .{ .gpa = undefined, .router = &r, .info = .{ .title = "T", .version = "1" } };
    var probe: LockProbeAllocator = .{ .inner = testing.allocator, .lock = &e.lock };
    e.gpa = probe.allocator();
    defer e.deinit();

    _ = try e.spec();
    try testing.expect(probe.calls > 0); // the build did allocate, so it was observed
    try testing.expectEqual(@as(usize, 0), probe.calls_under_lock);
}

test "endpoint: concurrent first callers all get the one cached document (F2)" {
    // testing.allocator is thread-safe and reports a leak, so a loser of the
    // publish race that kept its duplicate document fails this test.
    const gpa = testing.allocator;
    var r = router.Router.init(gpa);
    defer r.deinit();
    try addBenchRoutes(&r, 400, false);

    var e: Endpoint = .{ .gpa = gpa, .router = &r, .info = .{ .title = "T", .version = "1" } };
    defer e.deinit();
    var ctx: SpecWorkerCtx = .{ .e = &e };
    var threads: [8]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, specWorker, .{&ctx});
    for (threads) |t| t.join();
    try testing.expectEqual(@as(u32, 0), ctx.err_count.load(.monotonic));
    // Every later call returns the one published document.
    const a = try e.spec();
    const b = try e.spec();
    try testing.expect(a.json.ptr == b.json.ptr);
}

test "generate: route-table build time scales linearly, not quadratically, with route count (F7)" {
    if (@import("builtin").mode == .Debug) return; // timing assertion needs ReleaseFast
    const gpa = std.heap.smp_allocator;
    const small = try benchBuildNs(gpa, 500);
    const big = try benchBuildNs(gpa, 4000); // 8x the routes
    // Printed only when the bound below fails, as in F2.
    errdefer std.debug.print("\n[F7] 500 routes={d}ns, 4000 routes={d}ns, ratio={d:.2}\n", .{
        small, big, @as(f64, @floatFromInt(big)) / @as(f64, @floatFromInt(small)),
    });
    // The old O(routes·paths) dedup scan + O(paths·13·routes) grouping scan
    // cost ~4x per doubling (measured in A1/openapi.md F7: 11.2 -> 46.0 ->
    // 159.4 -> 728.4 ms across 1000/2000/4000/8000 routes) — an 8x route
    // increase would cost roughly 8^2 = 64x. A linear implementation costs
    // ~8x plus constant overhead. 20x is a generous ceiling that separates
    // the two without being sensitive to measurement noise.
    try testing.expect(big < small * 20);
}

fn benchBuildNs(gpa: Allocator, n: usize) !u64 {
    var r = router.Router.init(gpa);
    defer r.deinit();
    var name_buf: [64]u8 = undefined;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const p = try std.fmt.bufPrint(&name_buf, "/api/v1/resource{d}/:id", .{i});
        try r.addDoc(.get, p, hOk, .{ .summary = "s", .responses = &.{.{ .status = 200, .description = "OK" }} });
    }
    const w0 = monoNs();
    const json = try Generator.build(gpa, &r, .{ .title = "T", .version = "1" });
    const dt = monoNs() - w0;
    gpa.free(json);
    return dt;
}

test "router: an empty pattern segment (\"//x\") is now rejected outright, so it can never reach openapi's paths object (F13, half of it)" {
    // Half of openapi-F13 was "`//x` passes as a key in `paths`" -- that
    // was `router`'s own gap (audit finding router-F11: an empty segment
    // anywhere but a single trailing one used to be silently accepted
    // into the trie), not something `openapi` could filter after the
    // fact without inventing its own pattern-syntax opinion. Closed at
    // the source: `router.add("//x", ...)` itself now refuses to
    // register, so `Router.routes()` can never contain such a pattern for
    // this module to convert into a `paths` key.
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try testing.expectError(error.InvalidPattern, r.get("//x", hOk));
}

test "router: a repeated capture name is now rejected outright, not just deduped downstream (router F8 closes Š2)" {
    // `router`'s own audit finding F8 (A1/router.md) closes the seam this
    // test used to exercise from the openapi side: `/a/:id/b/:id` used to
    // be ACCEPTED by `router` (a footgun there — `params.get` silently
    // returned only the first value) and it was `openapi`'s job to not
    // turn that into a document violating OAS 3.1 §4.8.10 ("The list MUST
    // NOT include duplicated parameters."). Now `router.add` itself
    // refuses the pattern at registration time, so this module's own
    // `writePathParameters` dedup (kept below as defense in depth) is no
    // longer reachable through any live caller.
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try testing.expectError(error.DuplicateParamName, r.get("/a/:id/b/:id", hOk));
}

test "generate: writePathParameters dedupes a repeated capture name (F6) — defense in depth, unreachable via router since router-F8" {
    var buf: [512]u8 = undefined;
    var aw: Writer = .fixed(&buf);
    var jw: std.json.Stringify = .{ .writer = &aw, .options = .{} };
    try jw.beginObject();
    try writePathParameters(&jw, "/a/:id/b/:id");
    try jw.endObject();

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, aw.buffered(), .{});
    defer parsed.deinit();
    const params = parsed.value.object.get("parameters").?.array;
    try testing.expectEqual(@as(usize, 1), params.items.len);
    try testing.expectEqualStrings("id", params.items[0].object.get("name").?.string);
}

test "generate: two responses sharing a status code dedupe (first wins) instead of emitting a duplicate JSON key (F3)" {
    // The pre-fix document here was not even well-formed: `std.json` --
    // the same parser this module uses everywhere else -- refuses to
    // re-parse an object with a duplicate key at all.
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.addDoc(.get, "/dup", hOk, .{
        .responses = &.{
            .{ .status = 200, .description = "first" },
            .{ .status = 200, .description = "second" },
        },
    });
    const json = try Generator.build(testing.allocator, &r, .{ .title = "T", .version = "1" });
    defer testing.allocator.free(json);

    // The whole point: this must parse at all (DuplicateField would fail
    // it before the fix), and must round-trip through this module's own
    // conformance checker.
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, json, .{});
    defer parsed.deinit();
    try validateOpenApi31(parsed.value);
    const responses = parsed.value.object.get("paths").?.object.get("/dup").?.object
        .get("get").?.object.get("responses").?.object;
    try testing.expectEqual(@as(usize, 1), responses.count());
    try testing.expectEqualStrings("first", responses.get("200").?.object.get("description").?.string);
}

test "endpoint: byte-exact spec path — a neighboring route sharing the prefix is NOT shadowed (F15/M10)" {
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    var e: Endpoint = .{ .gpa = testing.allocator, .router = &r, .info = .{ .title = "T", .version = "1" } };
    defer e.deinit();
    try r.use(e.middleware());
    try r.get("/openapi.json.sig", hHello); // shares the PREFIX with e.path

    var buf: [16384]u8 = undefined;
    const got = runWire(&r, wire("GET", "/openapi.json.sig"), &buf);
    try expectStatus(got, "200");
    try testing.expectEqualStrings("hello", bodyOf(got));
}

test "endpoint: byte-exact docs path — a neighboring route sharing the prefix is NOT shadowed (F15/M16)" {
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    var e: Endpoint = .{
        .gpa = testing.allocator,
        .router = &r,
        .info = .{ .title = "T", .version = "1" },
        .docs_path = "/docs",
    };
    defer e.deinit();
    try r.use(e.middleware());
    try r.get("/docs-internal", hHello); // shares the PREFIX with e.docs_path

    var buf: [16384]u8 = undefined;
    const got = runWire(&r, wire("GET", "/docs-internal"), &buf);
    try expectStatus(got, "200");
    try testing.expectEqualStrings("hello", bodyOf(got));
}

test "endpoint: ETag is served, and a matching If-None-Match gets 304 with no body (F14)" {
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    var e: Endpoint = .{ .gpa = testing.allocator, .router = &r, .info = .{ .title = "T", .version = "1" } };
    defer e.deinit();
    try r.use(e.middleware());
    try r.get("/hello", hHello);

    var buf: [16384]u8 = undefined;
    const first = runWire(&r, wire("GET", "/openapi.json"), &buf);
    try expectStatus(first, "200");
    const etag_prefix = "\r\nETag: ";
    const at = std.mem.indexOf(u8, first, etag_prefix).?;
    const rest = first[at + etag_prefix.len ..];
    const etag = rest[0..std.mem.indexOf(u8, rest, "\r\n").?];

    var buf2: [16384]u8 = undefined;
    var req_buf: [256]u8 = undefined;
    const req = try std.fmt.bufPrint(&req_buf, "GET /openapi.json HTTP/1.1\r\nHost: t\r\nConnection: close\r\nIf-None-Match: {s}\r\n\r\n", .{etag});
    const second = runWire(&r, req, &buf2);
    try expectStatus(second, "304");
    try testing.expectEqualStrings("", bodyOf(second));

    // A stale/mismatched ETag must still get the full 200 body.
    const third = runWire(&r, "GET /openapi.json HTTP/1.1\r\nHost: t\r\nConnection: close\r\nIf-None-Match: \"stale\"\r\n\r\n", &buf2);
    try expectStatus(third, "200");
    try testing.expect(bodyOf(third).len > 0);
}

test "conformance: the checker rejects an empty responses object (F16/M14)" {
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        testing.allocator,
        "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"T\",\"version\":\"1\"},\"paths\":{\"/x\":{\"get\":{\"responses\":{}}}}}",
        .{},
    );
    defer parsed.deinit();
    try testing.expectError(error.EmptyResponses, validateOpenApi31(parsed.value));
}

test "conformance: the checker rejects a paths key that does not start with '/' (F16/M15)" {
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        testing.allocator,
        "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"T\",\"version\":\"1\"},\"paths\":{\"x\":{\"get\":{\"responses\":{\"200\":{\"description\":\"OK\"}}}}}}",
        .{},
    );
    defer parsed.deinit();
    try testing.expectError(error.InvalidPathKey, validateOpenApi31(parsed.value));
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
    defer e.deinit();
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
    defer e.deinit();
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
