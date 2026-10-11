// SPDX-License-Identifier: MIT

//! Re-takes datefmt's two oracles and compares (`--check`) or rewrites
//! (default) their committed vectors, which `test-datefmt` replays
//! (`src/go_oracle_test.zig`):
//!  - `tools/go_time_oracle`     Go time: ParseDuration, Duration.String,
//!                               the RFC1123Z layout → `src/go_time_vectors.zig`
//!  - `tools/mail_date_oracle.py` Python email.utils.parsedate_tz
//!                               → `src/mail_date_vectors.zig`
//! The Python check ignores the `// GENERATED … (version)` line: a runner
//! with another Python build passes when every verdict agrees.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-datefmt` runs it and
//! `zig build check-interop` compiles it. Needs python3, go 1.26.0 (stdlib
//! only, `GOPROXY=off`) and `zig` on PATH; no network. Run from the
//! repository root.
//!
//!   zig build interop-datefmt              # re-take both, rewrite the vectors
//!   zig build interop-datefmt -- --check   # re-take, compare with the committed vectors

const std = @import("std");

const tools = "modules/datefmt/tools";
const src = "modules/datefmt/src";

const Oracle = struct {
    name: []const u8,
    /// Arguments after the interpreter; `--check` is appended in check mode.
    check_argv: []const []const u8,
    /// Rewrite mode: argv, and the file its stdout goes to (null = the tool
    /// writes the file itself).
    write_argv: []const []const u8,
    write_stdout_to: ?[]const u8,
    cwd: ?[]const u8 = null,
};

const oracles = [_]Oracle{
    .{
        .name = "go time (ParseDuration, Duration.String, RFC1123Z)",
        .check_argv = &.{ "go", "run", ".", "-check", "../../src/go_time_vectors.zig" },
        .write_argv = &.{ "go", "run", ".", "-out", "../../src/go_time_vectors.zig" },
        .write_stdout_to = null,
        .cwd = tools ++ "/go_time_oracle",
    },
    .{
        .name = "mail date (Python email.utils)",
        .check_argv = &.{ "python3", "-I", tools ++ "/mail_date_oracle.py", "--check" },
        .write_argv = &.{ "python3", "-I", tools ++ "/mail_date_oracle.py" },
        .write_stdout_to = src ++ "/mail_date_vectors.zig",
    },
};

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

    var args = init.args.iterate();
    _ = args.next();
    var check = false;
    if (args.next()) |a| {
        if (!std.mem.eql(u8, a, "--check")) {
            std.debug.print("usage: interop-datefmt [--check]\n", .{});
            return 2;
        }
        check = true;
    }

    // Go: the pinned toolchain, offline (the module cache is filled ahead).
    var env = try init.environ.createMap(arena);
    try env.put("GOTOOLCHAIN", "go1.26.0");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");

    const cwd = std.Io.Dir.cwd();
    var failed: usize = 0;
    for (oracles) |o| {
        std.debug.print("interop-datefmt: {s} ...\n", .{o.name});
        var out_file: ?std.Io.File = null;
        defer if (out_file) |f| f.close(io);
        if (!check) if (o.write_stdout_to) |path| {
            out_file = try cwd.createFile(io, path, .{});
        };
        var child = std.process.spawn(io, .{
            .argv = if (check) o.check_argv else o.write_argv,
            .environ_map = &env,
            .cwd = if (o.cwd) |p| .{ .path = p } else .inherit,
            .stdin = .close,
            .stdout = if (out_file) |f| .{ .file = f } else .inherit,
        }) catch |e| {
            std.debug.print("interop-datefmt: could not spawn {s} ({t}) -- the oracle needs it\n", .{ o.check_argv[0], e });
            failed += 1;
            continue;
        };
        const ok = switch (try child.wait(io)) {
            .exited => |code| code == 0,
            else => false,
        };
        if (!ok) {
            std.debug.print("interop-datefmt: {s} FAILED\n", .{o.name});
            failed += 1;
        }
    }
    if (failed != 0) {
        std.debug.print("interop-datefmt: {d} of {d} oracles failed\n", .{ failed, oracles.len });
        return 1;
    }
    std.debug.print("interop-datefmt: {d} oracles {s}\n", .{ oracles.len, if (check) "fresh" else "re-taken" });
    return 0;
}
