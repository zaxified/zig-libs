// SPDX-License-Identifier: MIT

//! Re-takes validate's three differential oracles and compares (`--check`) or
//! rewrites (default) their committed vectors, which `test-validate` replays:
//!  - `tools/schema_oracle.py`  python-jsonschema + ajv 8 (under bun) verdicts
//!                              on generated rule sets' JSON Schema exports
//!                              → `src/schema_oracle_vectors.zig`
//!  - `tools/query_oracle.py`   query decoding by Python, Go `net/url` and
//!                              WHATWG `URLSearchParams`; value coercion
//!                              judged by pydantic → `src/query_oracle_vectors.zig`
//!  - `tools/format_oracle.py`  go-playground/validator v10.30.5's own format
//!                              verdicts (`tools/go_formats`) → `src/go_format_vectors.zig`
//! Each vectors file names the peers' versions, so `--check` against another
//! release reports it stale: re-take, read the diff, re-judge the classes
//! (tools/README.md).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-validate` runs it and
//! `zig build check-interop` compiles it. Needs: `python3` with `jsonschema`,
//! `bun` with `ajv@8.20.0` in its cache, `go` (stdlib only), `zig` on PATH
//! (`zig fmt`), and a Python with pydantic 2 at `$VALIDATE_QUERY_PYTHON`,
//! default `~/.local/share/zig-libs/oracle-venvs/fastapi/bin/python`. No
//! network. Run from the repository root.
//!
//!   zig build interop-validate              # re-take, rewrite the vectors
//!   zig build interop-validate -- --check   # re-take, compare with the committed vectors

const std = @import("std");

const Oracle = struct {
    name: []const u8,
    script: []const u8,
    vectors: []const u8,
};

const schema: Oracle = .{
    .name = "schema (jsonschema + ajv)",
    .script = "modules/validate/tools/schema_oracle.py",
    .vectors = "modules/validate/src/schema_oracle_vectors.zig",
};
const formats: Oracle = .{
    .name = "formats (go-playground)",
    .script = "modules/validate/tools/format_oracle.py",
    .vectors = "modules/validate/src/go_format_vectors.zig",
};
const query: Oracle = .{
    .name = "query (pydantic, net/url, URLSearchParams)",
    .script = "modules/validate/tools/query_oracle.py",
    .vectors = "modules/validate/src/query_oracle_vectors.zig",
};

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded: std.Io.Threaded = .init(gpa, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.args.iterate();
    _ = args.next();
    var check = false;
    if (args.next()) |a| {
        if (!std.mem.eql(u8, a, "--check")) {
            std.debug.print("usage: interop-validate [--check]\n", .{});
            return 2;
        }
        check = true;
    }

    // Go (query_oracle's go_query, format_oracle's go_formats): the pinned
    // toolchain, offline.
    var env = try init.environ.createMap(arena);
    try env.put("GOTOOLCHAIN", "go1.26.0");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    const query_python = env.get("VALIDATE_QUERY_PYTHON") orelse blk: {
        const home = env.get("HOME") orelse {
            std.debug.print("interop-validate: neither VALIDATE_QUERY_PYTHON nor HOME is set\n", .{});
            return 1;
        };
        break :blk try std.fmt.allocPrint(arena, "{s}/.local/share/zig-libs/oracle-venvs/fastapi/bin/python", .{home});
    };

    var failed = false;
    inline for (.{ .{ schema, "python3" }, .{ query, "" }, .{ formats, "python3" } }) |o| {
        const python: []const u8 = if (o[1].len != 0) o[1] else query_python;
        if (!try run(io, &env, o[0], python, check)) failed = true;
    }
    if (failed) return 1;
    std.debug.print("interop-validate: all three oracles {s}\n", .{if (check) "fresh" else "re-taken"});
    return 0;
}

fn run(io: std.Io, env: *const std.process.Environ.Map, o: Oracle, python: []const u8, check: bool) !bool {
    std.debug.print("interop-validate: {s} ({s}) ...\n", .{ o.name, python });
    var out_file: ?std.Io.File = null;
    defer if (out_file) |f| f.close(io);
    if (!check) out_file = try std.Io.Dir.cwd().createFile(io, o.vectors, .{});
    const argv: []const []const u8 = if (check) &.{ python, o.script, "--check" } else &.{ python, o.script };
    var child = std.process.spawn(io, .{
        .argv = argv,
        .environ_map = env,
        .stdin = .close,
        .stdout = if (out_file) |f| .{ .file = f } else .inherit,
    }) catch |e| {
        std.debug.print("interop-validate: could not run {s} ({t}) -- the oracle needs it\n", .{ python, e });
        return false;
    };
    const ok = switch (try child.wait(io)) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!ok) std.debug.print("interop-validate: {s} oracle FAILED\n", .{o.name});
    return ok;
}
