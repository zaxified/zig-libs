// SPDX-License-Identifier: MIT

//! openapi's fuzz harnesses and deterministic driver (added 2026-10-11).
//!
//! openapi takes untrusted bytes in two places:
//!   * `validateOpenApi31` -- a parsed document of unknown origin (the
//!     `spec` harness: raw bytes as JSON, or a valid generated document
//!     damaged at the byte level and by structural token swaps);
//!   * `Generator.buildRoutes` / `writeRoutes` -- route patterns, metadata
//!     strings and JSON-text schemas, examples and parameters (the `build`
//!     harness: a whole `Info` + route table drawn from a byte script, then
//!     the document built twice by two paths that must agree).
//! `schemaRef` is a comptime helper and is not a target.
//!
//! Driver: `OPENAPI_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there). Harness names:
//! `build`, `spec`.
//!
//! Invariants: no panic, no leak (the driver's allocator), a document that
//! built is valid for the checker, `buildRoutes` == `writeRoutes` ==
//! `buildRoutes` again (byte for byte), and a build that succeeded saw no
//! non-UTF-8 in any field the generator promises to check (audit F4).

const std = @import("std");
const testkit = @import("testkit");
const router = @import("router");
const http = @import("http");
const oa = @import("root.zig");

const testing = std.testing;
const Allocator = std.mem.Allocator;
const Cursor = testkit.fuzz.Cursor;
const fuzzseed = testkit.fuzz;
const fuzz_driver = fuzzseed.driver;
const Generator = oa.Generator;

// ── reach labels and the source adapter ─────────────────────────────────────

pub const Label = enum { build_ok, build_rejected, build_utf8, spec_json_invalid, spec_rejected, spec_accepted };
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

pub fn mark(l: Label) void {
    reach[@backingInt(l)] += 1;
    switch (l) {
        inline else => |c| fuzz_driver.hit(@tagName(c)),
    }
}

pub fn resetReach() void {
    reach = @splat(0);
}

pub fn count(l: Label) usize {
    return reach[@backingInt(l)];
}

/// Reach before verdict: every label was seen since `resetReach`.
pub fn expectAllReached() !void {
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and
/// every choice is read from them by a cursor -- so each seed is its own input.
pub const ScriptSource = struct {
    cur: Cursor,

    pub fn valueRangeAtMost(self: *ScriptSource, comptime T: type, at_least: T, at_most: T) T {
        return @intCast(self.cur.ranged(at_least, at_most));
    }
    pub fn value(self: *ScriptSource, comptime T: type) T {
        return switch (T) {
            bool => self.cur.byte() & 1 == 1,
            u8 => self.cur.byte(),
            u16 => self.cur.word(),
            else => @compileError("ScriptSource.value: unsupported type"),
        };
    }
    pub fn bytes(self: *ScriptSource, buf: []u8) void {
        for (buf) |*b| b.* = self.cur.byte();
    }
    pub fn index(self: *ScriptSource, len: usize) usize {
        return self.cur.ranged(0, @intCast(len - 1));
    }
    pub fn slice(self: *ScriptSource, buf: []u8) u32 {
        const left = self.cur.bytes.len -| self.cur.at;
        const n = @min(buf.len, left);
        @memcpy(buf[0..n], self.cur.bytes[self.cur.at..][0..n]);
        self.cur.at += n;
        return @intCast(n);
    }
};

const script_len = 1024;

// ── the `build` harness: a drawn Info + route table ─────────────────────────

const seg_pool = [_][]const u8{ "users", "pets", ":id", "*rest", "{name}", "f.{ext}", "a", "v1" };
const title_pool = [_][]const u8{ "API", "Pets", "Orders API", "" };
const version_pool = [_][]const u8{ "1.0", "2", "0.1.0-rc.1", "1" };
const desc_pool = [_][]const u8{ "A thing", "", "caf\xc3\xa9 \"quoted\" \\ slash", "line\nbreak" };
const tag_pool = [_][]const u8{ "pets", "admin", "x" };
const media_pool = [_][]const u8{ "application/json", "text/plain", "application/problem+json", "" };
const url_pool = [_][]const u8{ "https://api.example.com", "/v1", "http://localhost:8080" };
const status_pool = [_]u16{ 200, 201, 204, 404, 500, 0, 999 };
const schema_name_pool = [_][]const u8{ "Pet", "User", "A.b-c_d", "bad name" };
const scheme_name_pool = [_][]const u8{ "apiKeyAuth", "basicAuth", "oauth", "oidc", "bearerAuth" };

const schema_ok = [_][]const u8{
    "{\"type\":\"object\"}",
    "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}},\"required\":[\"name\"]}",
    "{\"type\":\"array\",\"items\":{\"type\":\"integer\"}}",
    oa.schemaRef("User"),
};
const schema_bad = [_][]const u8{
    "not json",
    "",
    "[1,",
    "{\"$ref\":\"#/components/schemas/Ghost\"}",
};
const query_ok = [_][]const u8{
    "{\"type\":\"object\",\"properties\":{\"q\":{\"type\":\"string\"},\"n\":{\"type\":\"integer\"}},\"required\":[\"q\"]}",
    "{\"allOf\":[{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\"}}},{\"type\":\"object\",\"properties\":{\"b\":{\"type\":\"integer\"}},\"required\":[\"b\"]}]}",
};
const query_bad = [_][]const u8{
    "{\"type\":\"string\"}",
    "{\"type\":\"object\"}",
    "[]",
};

const no_scopes: []const []const u8 = &.{};
const read_scope: []const []const u8 = &.{"read"};
const no_params: []const oa.Parameter = &.{};
const one_param: []const oa.Parameter = &.{.{ .name = "X-Trace" }};
const no_security: []const oa.SecurityRequirement = &.{};

/// Draws the pieces of one `Info` + route table from a byte script. In dirty
/// mode (a quarter of the scripts) the fields the generator promises to
/// UTF-8-check now and then take raw script bytes; `bad_utf8` records that one
/// did not decode.
const Gen = struct {
    cur: Cursor,
    arena: Allocator,
    dirty: bool,
    bad_utf8: bool = false,

    fn pick(g: *Gen, pool: []const []const u8) []const u8 {
        return pool[g.cur.ranged(0, @intCast(pool.len - 1))];
    }

    fn chance(g: *Gen, one_in: u32) bool {
        return g.cur.ranged(0, one_in - 1) == 0;
    }

    /// A string from `pool`; in dirty mode now and then a few raw bytes.
    fn text(g: *Gen, pool: []const []const u8) ![]const u8 {
        if (g.dirty and g.cur.ranged(0, 9) == 9) {
            const buf = try g.arena.alloc(u8, g.cur.ranged(0, 6));
            for (buf) |*b| b.* = g.cur.byte();
            if (!std.unicode.utf8ValidateSlice(buf)) g.bad_utf8 = true;
            return buf;
        }
        return g.pick(pool);
    }

    fn jsonSchema(g: *Gen) []const u8 {
        return if (g.chance(8)) g.pick(&schema_bad) else g.pick(&schema_ok);
    }

    fn pattern(g: *Gen) ![]const u8 {
        var list: std.ArrayList(u8) = .empty;
        const segs = g.cur.ranged(1, 3);
        for (0..segs) |_| {
            try list.append(g.arena, '/');
            try list.appendSlice(g.arena, try g.text(&seg_pool));
        }
        return list.items;
    }

    fn responses(g: *Gen) ![]const router.RouteDoc.Response {
        const out = try g.arena.alloc(router.RouteDoc.Response, g.cur.ranged(0, 2));
        for (out) |*r| {
            r.* = .{
                .status = status_pool[g.cur.ranged(0, status_pool.len - 1)],
                .description = try g.text(&desc_pool),
                .schema = if (g.chance(2)) g.jsonSchema() else null,
                .media_type = g.pick(&media_pool),
            };
        }
        return out;
    }

    fn doc(g: *Gen) !?*const router.RouteDoc {
        if (g.cur.ranged(0, 2) == 0) return null;
        const d = try g.arena.create(router.RouteDoc);
        const tags = try g.arena.alloc([]const u8, g.cur.ranged(0, 2));
        for (tags) |*t| t.* = try g.text(&tag_pool);
        d.* = .{
            .summary = if (g.chance(2)) try g.text(&desc_pool) else null,
            .description = if (g.chance(3)) try g.text(&desc_pool) else null,
            .tags = tags,
            .request_schema = if (g.chance(2)) g.jsonSchema() else null,
            .query_schema = if (g.chance(3)) (if (g.chance(8)) g.pick(&query_bad) else g.pick(&query_ok)) else null,
            .responses = try g.responses(),
            .deprecated = g.chance(4),
        };
        return d;
    }

    fn routes(g: *Gen) ![]router.Route {
        const methods = std.enums.values(http.Method);
        const out = try g.arena.alloc(router.Route, g.cur.ranged(0, 3));
        for (out) |*r| {
            r.* = .{
                .method = methods[g.cur.ranged(0, methods.len - 1)],
                .pattern = try g.pattern(),
                .doc = try g.doc(),
            };
        }
        return out;
    }

    fn scheme(g: *Gen) oa.SecurityScheme {
        const name = g.pick(&scheme_name_pool);
        const kind: oa.SecurityScheme.Kind = switch (g.cur.ranged(0, 4)) {
            0 => .{ .api_key = .{ .in = @fromBackingInt(@intCast(g.cur.ranged(0, 2))), .name = "X-Key" } },
            1 => .http_basic,
            2 => .{ .http_bearer = .{ .format = "JWT" } },
            3 => if (g.chance(5)) .{ .oauth2 = .{} } else .{ .oauth2 = .{ .implicit = .{
                .authorization_url = "https://x.example/auth",
                .scopes = &.{.{ .name = "read", .description = "Read" }},
            } } },
            else => .{ .openid_connect = "https://x.example/.well-known/openid-configuration" },
        };
        return .{ .name = name, .kind = kind };
    }

    fn info(g: *Gen, rs: []const router.Route) !oa.Info {
        var inf: oa.Info = .{
            .title = try g.text(&title_pool),
            .version = try g.text(&version_pool),
        };
        if (g.chance(2)) inf.description = try g.text(&desc_pool);
        inf.bearer_auth = g.chance(3);

        const servers = try g.arena.alloc(oa.Server, g.cur.ranged(0, 2));
        for (servers) |*s| s.* = .{
            .url = g.pick(&url_pool),
            .description = if (g.chance(2)) g.pick(&desc_pool) else null,
        };
        inf.servers = servers;

        // `User` is registered most of the time, so `schemaRef("User")` mostly
        // resolves and the build path past the checker is reached.
        var schemas: std.ArrayList(oa.NamedSchema) = .empty;
        if (!g.chance(4)) try schemas.append(g.arena, .{ .name = "User", .schema = "{\"type\":\"object\"}" });
        if (g.chance(3)) try schemas.append(g.arena, .{ .name = g.pick(&schema_name_pool), .schema = g.pick(&schema_ok) });
        inf.schemas = schemas.items;

        var names: std.ArrayList([]const u8) = .empty;
        if (inf.bearer_auth) try names.append(g.arena, "bearerAuth");
        var schemes: std.ArrayList(oa.SecurityScheme) = .empty;
        if (g.chance(2)) {
            const sc = g.scheme();
            try schemes.append(g.arena, sc);
            try names.append(g.arena, sc.name);
        }
        inf.security_schemes = schemes.items;

        const reqs = try g.arena.alloc(oa.SecurityRequirement, g.cur.ranged(0, 2));
        for (reqs) |*r| {
            r.* = .{
                .name = if (names.items.len > 0 and !g.chance(8)) names.items[g.cur.ranged(0, @intCast(names.items.len - 1))] else "ghost",
                .scopes = if (g.chance(2)) read_scope else no_scopes,
            };
        }
        inf.security = reqs;

        if (rs.len > 0 and g.chance(4)) {
            const rt = rs[g.cur.ranged(0, @intCast(rs.len - 1))];
            const extras = try g.arena.alloc(oa.RouteExtra, 1);
            extras[0] = .{
                .method = rt.method,
                .pattern = if (g.chance(8)) "/nope" else rt.pattern,
                .header_parameters = if (g.chance(2)) one_param else no_params,
                .security = if (g.chance(3)) no_security else null,
                .request_example = if (g.chance(2)) (if (g.chance(8)) "{" else "{\"a\":1}") else null,
            };
            inf.route_extras = extras;
        }
        return inf;
    }
};

pub fn buildHarness(comptime S: type, src: *S, gpa: Allocator) anyerror!void {
    var raw: [script_len]u8 = undefined;
    const n: usize = src.slice(&raw);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var g: Gen = .{ .cur = .{ .bytes = raw[0..n] }, .arena = arena_state.allocator(), .dirty = false };
    g.dirty = g.cur.byte() % 4 == 0;
    const routes = try g.routes();
    const info = try g.info(routes);

    const built = Generator.buildRoutes(gpa, routes, info) catch |err| switch (err) {
        error.OutOfMemory => return err,
        error.InvalidUtf8 => {
            mark(.build_utf8);
            return;
        },
        else => {
            mark(.build_rejected);
            return;
        },
    };
    defer gpa.free(built);

    // Audit F4: no field the generator checks may carry non-UTF-8 into a
    // document that was accepted.
    if (g.bad_utf8) return error.InvalidUtf8Accepted;

    // Two paths that must agree: the streaming writer and the checked build.
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try Generator.writeRoutes(gpa, routes, info, &out.writer);
    try testing.expectEqualStrings(built, out.writer.buffered());

    // Deterministic: a second build is byte-identical.
    const again = try Generator.buildRoutes(gpa, routes, info);
    defer gpa.free(again);
    try testing.expectEqualStrings(built, again);

    // And the output is valid JSON the checker accepts, independently of
    // `buildRoutes`'s own self-check.
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, built, .{});
    defer parsed.deinit();
    try oa.validateOpenApi31(parsed.value);
    mark(.build_ok);
}

// ── the `spec` harness: the document checker on hostile documents ───────────

const base_doc: router.RouteDoc = .{
    .summary = "Create",
    .tags = &.{"pets"},
    .request_schema = "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}},\"required\":[\"name\"]}",
    .responses = &.{
        .{ .status = 201, .description = "Created", .schema = "{\"$ref\":\"#/components/schemas/Pet\"}" },
        .{ .status = 404, .description = "Missing" },
    },
};
const base_routes = [_]router.Route{
    .{ .method = .get, .pattern = "/pets/:id" },
    .{ .method = .post, .pattern = "/pets", .doc = &base_doc },
};
const base_info: oa.Info = .{
    .title = "Pets",
    .version = "1.0",
    .bearer_auth = true,
    .servers = &.{.{ .url = "https://api.example.com" }},
    .schemas = &.{.{ .name = "Pet", .schema = "{\"type\":\"object\"}" }},
    .security_schemes = &.{.{ .name = "key", .kind = .{ .api_key = .{ .in = .header, .name = "X-Key" } } }},
    .security = &.{.{ .name = "key" }},
};

const Swap = struct { from: []const u8, to: []const u8 };
/// Structural damage: each swap breaks (or subtly moves) one rule the checker
/// enforces, which random byte flips almost never hit.
const swaps = [_]Swap{
    .{ .from = "\"openapi\"", .to = "\"openapx\"" },
    .{ .from = "3.1.0", .to = "3.0.0" },
    .{ .from = "\"paths\"", .to = "\"pathz\"" },
    .{ .from = "\"$ref\"", .to = "\"ref\"" },
    .{ .from = "#/components/schemas/Pet", .to = "#/components/schemas/Nope" },
    .{ .from = "\"required\":true", .to = "\"required\":false" },
    .{ .from = "\"in\":\"path\"", .to = "\"in\":\"query\"" },
    .{ .from = "\"responses\"", .to = "\"respons\"" },
    .{ .from = "\"bearerAuth\"", .to = "\"ghostAuth\"" },
    .{ .from = "\"title\":\"Pets\"", .to = "\"title\":\"\"" },
    .{ .from = "\"type\":\"http\"", .to = "\"type\":\"nope\"" },
    .{ .from = "/pets/{id}", .to = "/pets/{ix}" },
    .{ .from = "\"description\":\"Missing\"", .to = "\"description\":7" },
    .{ .from = "\"security\":[", .to = "\"security\":[{\"zzz\":[]}," },
};

fn mutate(cur: *Cursor, arena: Allocator, doc: []const u8) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    try buf.appendSlice(arena, doc);
    const rounds = cur.ranged(1, 4);
    for (0..rounds) |_| {
        const at: usize = if (buf.items.len == 0) 0 else cur.word() % buf.items.len;
        switch (cur.ranged(0, 4)) {
            0 => if (buf.items.len > 0) {
                buf.items[at] = cur.byte();
            },
            1 => if (buf.items.len > 0) {
                _ = buf.orderedRemove(at);
            },
            2 => try buf.insert(arena, at, cur.byte()),
            3 => {
                const s = swaps[cur.ranged(0, swaps.len - 1)];
                if (std.mem.find(u8, buf.items, s.from)) |p| {
                    var next: std.ArrayList(u8) = .empty;
                    try next.appendSlice(arena, buf.items[0..p]);
                    try next.appendSlice(arena, s.to);
                    try next.appendSlice(arena, buf.items[p + s.from.len ..]);
                    buf = next;
                }
            },
            else => buf.shrinkRetainingCapacity(at),
        }
    }
    return buf.items;
}

/// Parse `text` and run the checker; `base` is the undamaged document when
/// `text` descends from it (unchanged, it must be accepted).
fn checkText(gpa: Allocator, text: []const u8, base: ?[]const u8) !void {
    const parsed = std.json.parseFromSlice(std.json.Value, gpa, text, .{}) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => {
            mark(.spec_json_invalid);
            return;
        },
    };
    defer parsed.deinit();
    oa.validateOpenApi31(parsed.value) catch {
        if (base) |b| if (std.mem.eql(u8, b, text)) return error.BaseDocumentRejected;
        mark(.spec_rejected);
        return;
    };
    mark(.spec_accepted);
}

/// Octet 0 selects: a multiple of four means the rest of the script IS the
/// document, verbatim; anything else means the rest damages a valid generated
/// document.
pub fn specHarness(comptime S: type, src: *S, gpa: Allocator) anyerror!void {
    var raw: [script_len]u8 = undefined;
    const n: usize = src.slice(&raw);
    const mode: u8 = if (n > 0) raw[0] else 0;
    if (mode % 4 == 0) return checkText(gpa, raw[@min(1, n)..n], null);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const base = try Generator.buildRoutes(gpa, &base_routes, base_info);
    defer gpa.free(base);
    var cur: Cursor = .{ .bytes = raw[1..n] };
    const text = try mutate(&cur, arena_state.allocator(), base);
    try checkText(gpa, text, base);
}

// ── corpus ──────────────────────────────────────────────────────────────────

const doc_min = "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"T\",\"version\":\"1\"},\"paths\":{\"/x\":{\"get\":{\"responses\":{\"200\":{\"description\":\"ok\"}}}}}}";
const doc_no_paths = "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"T\",\"version\":\"1\"}}";

const spec_seeds = [_][]const u8{
    fuzzseed.seed("\x00" ++ doc_min), // accepted verbatim
    fuzzseed.seed("\x00" ++ doc_no_paths), // parses, refused by the checker
    fuzzseed.seed("\x00" ++ "{not json"), // not JSON
    fuzzseed.seed("\x01\x01\x00\x00\x00"), // damage: one byte replaced
    fuzzseed.seed("\x01\x04\x03\x03\x00\x03\x04"), // damage: structural swaps
    fuzzseed.seed("\x01\x03\x02\x00\x01\x02\x03\x04\x00"), // damage: insert
    fuzzseed.seed(""), // the empty script
};

const build_seeds = [_][]const u8{
    fuzzseed.seed(""), // zero script: no routes, defaults
    fuzzseed.seed("\x01"), // clean mode, every choice from one repeating octet
    fuzzseed.seed("\x04\x09\x09\x09\x09\x09\x09\x09\x01\x02"), // dirty mode, raw-byte branch
    fuzzseed.seed("\x03\x02\x01\x00\x03\x02\x01\x00\x02\x02\x07\x01\x05"), // clean, mixed
    fuzzseed.seed("\x05\x03\x02\x03\x02\x04\x01\x00\x01\x01\x01\x05\x06\x07"), // clean, three routes
};

// ── tests ───────────────────────────────────────────────────────────────────

fn runSeed(comptime h: anytype, sd: []const u8) !void {
    var smith: std.testing.Smith = .{ .in = sd };
    var raw: [script_len]u8 = undefined;
    const n: usize = smith.slice(&raw);
    var src: ScriptSource = .{ .cur = .{ .bytes = raw[0..n] } };
    try h(ScriptSource, &src, testing.allocator);
}

test "fuzz: the document checker never panics on arbitrary or damaged documents" {
    try testing.fuzz({}, fuzzSpec, .{ .corpus = &spec_seeds });
}

fn fuzzSpec(_: void, smith: *std.testing.Smith) !void {
    var raw: [script_len]u8 = undefined;
    const n: usize = smith.slice(&raw);
    var src: ScriptSource = .{ .cur = .{ .bytes = raw[0..n] } };
    try specHarness(ScriptSource, &src, testing.allocator);
}

test "fuzz: the generator never panics, and its two paths agree, on arbitrary route tables" {
    try testing.fuzz({}, fuzzBuild, .{ .corpus = &build_seeds });
}

fn fuzzBuild(_: void, smith: *std.testing.Smith) !void {
    var raw: [script_len]u8 = undefined;
    const n: usize = smith.slice(&raw);
    var src: ScriptSource = .{ .cur = .{ .bytes = raw[0..n] } };
    try buildHarness(ScriptSource, &src, testing.allocator);
}

test "fuzz driver: OPENAPI_FUZZ (build, spec)" {
    try fuzz_driver.run(buildHarness, .{ .prefix = "OPENAPI_FUZZ", .name = "build" });
    try fuzz_driver.run(specHarness, .{ .prefix = "OPENAPI_FUZZ", .name = "spec" });
}

test "fuzz harnesses: 500 seeds each in every test run, and they get everywhere" {
    resetReach();
    inline for (.{ buildHarness, specHarness }, .{ "build", "spec" }) |h, name| {
        for (0..500) |seed| {
            var prng = std.Random.DefaultPrng.init(seed);
            var rng: fuzz_driver.Rng = .{ .r = prng.random() };
            h(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                std.debug.print("openapi {s} seed {d}: {t}\n", .{ name, seed, err });
                return err;
            };
        }
    }
    try expectAllReached();
}

test "corpus: every seed runs clean, and the verbatim spec seeds land where they are meant to" {
    for (build_seeds) |sd| try runSeed(buildHarness, sd);
    resetReach();
    for (spec_seeds) |sd| try runSeed(specHarness, sd);
    // The first three seeds carry the document verbatim: one each of accepted,
    // refused by the checker, and not JSON.
    try testing.expect(count(.spec_accepted) >= 1);
    try testing.expect(count(.spec_rejected) >= 1);
    try testing.expect(count(.spec_json_invalid) >= 1);
}
