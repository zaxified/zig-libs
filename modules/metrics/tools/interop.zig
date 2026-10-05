// SPDX-License-Identifier: MIT

//! The registry and its exposition against Prometheus's own code:
//! `tools/go_oracle` generates operation scripts, this program runs each on
//! a `metrics.Registry` and records `writeText`, and the Go side runs the
//! same operations on client_golang and judges our text with two foreign
//! parsers (prometheus/common expfmt and the Prometheus server's
//! model/textparse). The scripts and our bytes are frozen in
//! `src/go_oracle_vectors.zig`, replayed by `src/go_oracle_test.zig` in
//! `test-metrics`.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-metrics` runs it and
//! `zig build check-interop` compiles it. It needs `go` with the modules in
//! its cache (GOPROXY=off -- no network); a missing one is a failure.
//!
//!   zig build interop-metrics              # re-take, write src/go_oracle_vectors.zig
//!   zig build interop-metrics -- --check   # re-take, compare with the committed file

const std = @import("std");
const metrics = @import("metrics");

const scratch = ".zig-cache/interop-metrics";
const go_dir = "modules/metrics/tools/go_oracle";
const vectors = "modules/metrics/src/go_oracle_vectors.zig";

const Family = struct { name: []const u8, help: []const u8, kind: []const u8, labels: []const []const u8, buckets: []const []const u8 };
const Op = struct { fam: usize, values: []const []const u8, op: []const u8, n: u64, v: []const u8 };
const Script = struct { families: []const Family, ops: []const Op };

/// One script on a fresh registry; its exposition. Mirrors `apply` in
/// src/go_oracle_test.zig, which replays the frozen scripts.
fn run(gpa: std.mem.Allocator, arena: std.mem.Allocator, sc: Script) ![]const u8 {
    var r = metrics.Registry.init(gpa);
    defer r.deinit();
    for (sc.ops) |op| {
        const f = sc.families[op.fam];
        const ls = try arena.alloc(metrics.Label, f.labels.len);
        for (ls, f.labels, op.values) |*l, n, v| l.* = .{ .name = n, .value = v };
        const v = try std.fmt.parseFloat(f64, op.v);
        if (std.mem.eql(u8, f.kind, "counter")) {
            const c = try r.counter(f.name, f.help, ls);
            if (std.mem.eql(u8, op.op, "inc")) c.inc() else c.add(op.n);
        } else if (std.mem.eql(u8, f.kind, "gauge")) {
            const g = try r.gauge(f.name, f.help, ls);
            const which = std.meta.stringToEnum(enum { set, add, sub, inc, dec }, op.op) orelse return error.BadScript;
            switch (which) {
                .set => g.set(v),
                .add => g.add(v),
                .sub => g.sub(v),
                .inc => g.inc(),
                .dec => g.dec(),
            }
        } else {
            const bs = try arena.alloc(f64, f.buckets.len);
            for (bs, f.buckets) |*b, s| b.* = try std.fmt.parseFloat(f64, s);
            const h = try r.histogram(f.name, f.help, ls, bs);
            h.observe(v);
        }
    }
    var out: std.Io.Writer.Allocating = .init(arena);
    try r.writeText(&out.writer);
    return out.written();
}

fn goCmd(io: std.Io, arena: std.mem.Allocator, env: *const std.process.Environ.Map, argv: []const []const u8, stdout_path: ?[]const u8) !u8 {
    var child = std.process.spawn(io, .{
        .argv = argv,
        .environ_map = env,
        .stdin = .close,
        .stdout = if (stdout_path != null) .pipe else .inherit,
        .stderr = .inherit,
    }) catch |e| {
        std.debug.print("could not spawn go ({t}) -- the oracle needs it\n", .{e});
        return error.NoGo;
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
            std.debug.print("usage: interop-metrics [--check]\n", .{});
            return 2;
        }
    }

    const cwd = std.Io.Dir.cwd();
    cwd.createDirPath(io, scratch) catch {};
    var env = try init.environ.createMap(arena);
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=mod");
    const scripts_path = scratch ++ "/scripts.json";
    const ours_path = scratch ++ "/ours.json";
    const abs = struct {
        fn of(a: std.mem.Allocator, io_: std.Io, p: []const u8) ![]const u8 {
            return std.Io.Dir.cwd().realPathFileAlloc(io_, p, a);
        }
    };

    if (try goCmd(io, arena, &env, &.{ "go", "-C", go_dir, "run", ".", "gen" }, scripts_path) != 0) return 1;

    const text = try cwd.readFileAlloc(io, scripts_path, arena, .limited(64 << 20));
    const scripts = try std.json.parseFromSliceLeaky([]const Script, arena, text, .{});
    var out: std.Io.Writer.Allocating = .init(arena);
    var s: std.json.Stringify = .{ .writer = &out.writer };
    try s.beginArray();
    for (scripts) |sc| try s.write(try run(gpa, arena, sc));
    try s.endArray();
    try cwd.writeFile(io, .{ .sub_path = ours_path, .data = out.written() });

    const fresh_path = scratch ++ "/go_oracle_vectors.zig";
    try cwd.writeFile(io, .{ .sub_path = fresh_path, .data = "" });
    const rc = try goCmd(io, arena, &env, &.{
        "go",                                "-C",                             go_dir,                            "run", ".", "judge",
        try abs.of(arena, io, scripts_path), try abs.of(arena, io, ours_path), try abs.of(arena, io, fresh_path),
    }, null);
    // zig fmt's layout, so the committed file passes the pre-commit hook.
    const raw = try cwd.readFileAlloc(io, fresh_path, arena, .limited(64 << 20));
    var ast = try std.zig.Ast.parse(arena, try arena.dupeZ(u8, raw), .zig);
    if (ast.errors.len != 0) {
        std.debug.print("interop-metrics: the generated vectors do not parse as Zig\n", .{});
        return 1;
    }
    const fresh = try ast.renderAlloc(arena);
    if (check) {
        const old = try cwd.readFileAlloc(io, vectors, arena, .limited(64 << 20));
        // The generator line names the Go version; compare what follows it.
        if (!std.mem.eql(u8, afterLine(old, 2), afterLine(fresh, 2))) {
            std.debug.print("interop-metrics: committed vectors differ from a fresh run\n", .{});
            return 1;
        }
        std.debug.print("interop-metrics: vectors fresh\n", .{});
    } else {
        try cwd.writeFile(io, .{ .sub_path = vectors, .data = fresh });
    }
    return rc;
}

fn afterLine(text: []const u8, n: usize) []const u8 {
    var rest = text;
    for (0..n) |_| {
        const nl = std.mem.indexOfScalar(u8, rest, '\n') orelse return "";
        rest = rest[nl + 1 ..];
    }
    return rest;
}
