// SPDX-License-Identifier: MIT

//! JSON Lines and logfmt against foreign readers: `tools/json_oracle.py`
//! draws entries (hostile strings, ill-formed UTF-8, extreme numbers), this
//! program writes each with `writeJsonLines` and `writeLogfmt`, and Python's
//! json, Go's encoding/json (`tools/go_json`) and jq must each read the JSON
//! line back to the entry exactly, go-logfmt (`tools/go_logfmt`) the logfmt
//! one. Frozen in `src/json_oracle_vectors.zig`, replayed by
//! `src/json_oracle_test.zig` in `test-accesslog`.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-accesslog` runs it and
//! `zig build check-interop` compiles it. It needs python3, go (stdlib only,
//! GOPROXY=off) and jq; no network. A missing one is a failure.
//!
//!   zig build interop-accesslog              # re-take, write src/json_oracle_vectors.zig
//!   zig build interop-accesslog -- --check   # re-take, compare with the committed file

const std = @import("std");
const accesslog = @import("accesslog");

const scratch = ".zig-cache/interop-accesslog";
const script = "modules/accesslog/tools/json_oracle.py";
const vectors = "modules/accesslog/src/json_oracle_vectors.zig";

/// An entry as the generator describes it: strings hex-encoded (they may be
/// ill-formed UTF-8, which JSON cannot carry).
const EntryIn = struct {
    timestamp_ns: i64,
    method: []const u8,
    target: []const u8,
    protocol: []const u8,
    status: u16,
    remote_addr: ?[]const u8 = null,
    user: ?[]const u8 = null,
    user_agent: ?[]const u8 = null,
    referer: ?[]const u8 = null,
    request_id: ?[]const u8 = null,
    trace_id: ?[]const u8 = null,
    span_id: ?[]const u8 = null,
    request_bytes: ?u64 = null,
    response_bytes: ?u64 = null,
    latency_ns: ?u64 = null,
};

fn unhex(a: std.mem.Allocator, h: []const u8) ![]const u8 {
    const out = try a.alloc(u8, h.len / 2);
    _ = try std.fmt.hexToBytes(out, h);
    return out;
}

fn unhexOpt(a: std.mem.Allocator, h: ?[]const u8) !?[]const u8 {
    return if (h) |v| try unhex(a, v) else null;
}

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
            std.debug.print("usage: interop-accesslog [--check]\n", .{});
            return 2;
        }
    }

    const cwd = std.Io.Dir.cwd();
    cwd.createDirPath(io, scratch) catch {};
    const env = try init.environ.createMap(arena);
    const entries_path = scratch ++ "/entries.json";
    const ours_path = scratch ++ "/ours.json";
    const fresh_path = scratch ++ "/json_oracle_vectors.zig";
    if (try python(io, arena, &env, &.{ "python3", script, "gen" }, entries_path) != 0) return 1;

    const text = try cwd.readFileAlloc(io, entries_path, arena, .limited(64 << 20));
    const entries = try std.json.parseFromSliceLeaky([]const EntryIn, arena, text, .{});
    var out: std.Io.Writer.Allocating = .init(arena);
    var s: std.json.Stringify = .{ .writer = &out.writer };
    try s.beginArray();
    for (entries) |e| {
        const entry: accesslog.Entry = .{
            .timestamp_ns = e.timestamp_ns,
            .method = try unhex(arena, e.method),
            .target = try unhex(arena, e.target),
            .protocol = try unhex(arena, e.protocol),
            .status = e.status,
            .remote_addr = try unhexOpt(arena, e.remote_addr),
            .user = try unhexOpt(arena, e.user),
            .user_agent = try unhexOpt(arena, e.user_agent),
            .referer = try unhexOpt(arena, e.referer),
            .request_id = try unhexOpt(arena, e.request_id),
            .trace_id = try unhexOpt(arena, e.trace_id),
            .span_id = try unhexOpt(arena, e.span_id),
            .request_bytes = e.request_bytes,
            .response_bytes = e.response_bytes,
            .latency_ns = e.latency_ns,
        };
        var json_line: std.Io.Writer.Allocating = .init(arena);
        try accesslog.writeJsonLines(entry, &json_line.writer);
        var logfmt_line: std.Io.Writer.Allocating = .init(arena);
        try accesslog.writeLogfmt(entry, &logfmt_line.writer);
        try s.beginArray();
        try s.print("\"{x}\"", .{json_line.written()});
        try s.print("\"{x}\"", .{logfmt_line.written()});
        try s.endArray();
    }
    try s.endArray();
    try cwd.writeFile(io, .{ .sub_path = ours_path, .data = out.written() });

    try cwd.writeFile(io, .{ .sub_path = fresh_path, .data = "" });
    const rc = try python(io, arena, &env, &.{ "python3", script, "judge", entries_path, ours_path, fresh_path }, null);
    const raw = try cwd.readFileAlloc(io, fresh_path, arena, .limited(64 << 20));
    var ast = try std.zig.Ast.parse(arena, try arena.dupeZ(u8, raw), .zig);
    if (ast.errors.len != 0) {
        std.debug.print("interop-accesslog: the generated vectors do not parse as Zig\n", .{});
        return 1;
    }
    const fresh = try ast.renderAlloc(arena);
    if (check) {
        const old = try cwd.readFileAlloc(io, vectors, arena, .limited(64 << 20));
        if (!std.mem.eql(u8, afterLine(old, 2), afterLine(fresh, 2))) {
            std.debug.print("interop-accesslog: committed vectors differ from a fresh run\n", .{});
            return 1;
        }
        std.debug.print("interop-accesslog: vectors fresh\n", .{});
    } else {
        try cwd.writeFile(io, .{ .sub_path = vectors, .data = fresh });
    }
    return rc;
}
