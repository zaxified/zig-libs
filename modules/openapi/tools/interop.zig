// SPDX-License-Identifier: MIT

//! The generated documents against openapi-spec-validator: `tools/spec_oracle.py`
//! draws route tables, this program registers each on a `router.Router` and
//! builds its document with `Generator.build`, and the validator (run as a
//! black box) judges every document and mutations of it. Frozen in
//! `src/spec_oracle_vectors.zig`, replayed by `src/spec_oracle_test.zig` in
//! `test-openapi`.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-openapi` runs it and
//! `zig build check-interop` compiles it. It needs python3 with the
//! `openapi-spec-validator` package; no network. A missing one is a failure.
//!
//!   zig build interop-openapi              # re-take, write src/spec_oracle_vectors.zig
//!   zig build interop-openapi -- --check   # re-take, compare with the committed file

const std = @import("std");
const http = @import("http");
const router = @import("router");
const openapi = @import("openapi");

const scratch = ".zig-cache/interop-openapi";
const script = "modules/openapi/tools/spec_oracle.py";
const vectors = "modules/openapi/src/spec_oracle_vectors.zig";

const RouteIn = struct { method: []const u8, pattern: []const u8, doc: ?router.RouteDoc };
const Table = struct { title: []const u8, version: []const u8, description: ?[]const u8, bearer: bool, routes: []const RouteIn };

fn noop(_: *router.Ctx) anyerror!void {}

fn python(io: std.Io, arena: std.mem.Allocator, env: *const std.process.Environ.Map, argv: []const []const u8, stdout_path: ?[]const u8) !u8 {
    var child = std.process.spawn(io, .{
        .argv = argv,
        .environ_map = env,
        .stdin = .close,
        .stdout = if (stdout_path != null) .pipe else .inherit,
        .stderr = .inherit,
    }) catch |e| {
        std.debug.print("could not spawn python3 ({t}) -- the oracle needs it\n", .{e});
        return error.NoPython;
    };
    if (stdout_path) |p| {
        var rbuf: [4096]u8 = undefined;
        var r = child.stdout.?.readerStreaming(io, &rbuf);
        const all = try r.interface.allocRemaining(arena, .limited(64 << 20));
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = p, .data = all });
    }
    const term = try child.wait(io);
    return switch (term) {
        .exited => |code| code,
        else => 1,
    };
}

fn afterLine(text: []const u8, n: usize) []const u8 {
    var rest = text;
    for (0..n) |_| {
        const nl = std.mem.indexOfScalar(u8, rest, '\n') orelse return "";
        rest = rest[nl + 1 ..];
    }
    return rest;
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var check = false;
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--check")) {
            check = true;
        } else {
            std.debug.print("usage: interop-openapi [--check]\n", .{});
            return 2;
        }
    }

    const cwd = std.Io.Dir.cwd();
    cwd.createDirPath(io, scratch) catch {};
    const env = try init.environ.createMap(arena);
    const tables_path = scratch ++ "/tables.json";
    const docs_path = scratch ++ "/docs.json";
    const fresh_path = scratch ++ "/spec_oracle_vectors.zig";
    if (try python(io, arena, &env, &.{ "python3", script, "gen" }, tables_path) != 0) return 1;

    const text = try cwd.readFileAlloc(io, tables_path, arena, .limited(64 << 20));
    const tables = try std.json.parseFromSliceLeaky([]const Table, arena, text, .{});
    var out: std.Io.Writer.Allocating = .init(arena);
    var s: std.json.Stringify = .{ .writer = &out.writer };
    try s.beginArray();
    for (tables) |t| {
        var r = router.Router.init(gpa);
        defer r.deinit();
        try s.beginObject();
        try s.objectField("accepted");
        try s.beginArray();
        for (t.routes) |rt| {
            const m = std.meta.stringToEnum(http.Method, rt.method) orelse return error.BadTable;
            const ok = if (rt.doc) |d| r.addDoc(m, rt.pattern, noop, d) else r.add(m, rt.pattern, noop);
            try s.write(if (ok) |_| true else |_| false);
        }
        try s.endArray();
        const doc = openapi.Generator.build(gpa, &r, .{
            .title = t.title,
            .version = t.version,
            .description = t.description,
            .bearer_auth = t.bearer,
        });
        try s.objectField("doc");
        if (doc) |d| {
            defer gpa.free(d);
            try s.write(d);
        } else |_| try s.write(null);
        try s.objectField("err");
        try s.write(if (doc) |_| "" else |e| @errorName(e));
        try s.endObject();
    }
    try s.endArray();
    try cwd.writeFile(io, .{ .sub_path = docs_path, .data = out.written() });

    try cwd.writeFile(io, .{ .sub_path = fresh_path, .data = "" });
    const rc = try python(io, arena, &env, &.{ "python3", script, "judge", tables_path, docs_path, fresh_path }, null);
    // zig fmt's layout, so the committed file passes the pre-commit hook.
    const raw = try cwd.readFileAlloc(io, fresh_path, arena, .limited(64 << 20));
    var ast = try std.zig.Ast.parse(arena, try arena.dupeZ(u8, raw), .zig);
    if (ast.errors.len != 0) {
        std.debug.print("interop-openapi: the generated vectors do not parse as Zig\n", .{});
        return 1;
    }
    const fresh = try ast.renderAlloc(arena);
    if (check) {
        const old = try cwd.readFileAlloc(io, vectors, arena, .limited(64 << 20));
        if (!std.mem.eql(u8, afterLine(old, 2), afterLine(fresh, 2))) {
            std.debug.print("interop-openapi: committed vectors differ from a fresh run\n", .{});
            return 1;
        }
        std.debug.print("interop-openapi: vectors fresh\n", .{});
    } else {
        try cwd.writeFile(io, .{ .sub_path = vectors, .data = fresh });
    }
    return rc;
}
