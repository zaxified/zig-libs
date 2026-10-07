// SPDX-License-Identifier: MIT

//! Re-takes regex's Go-generated files and compares (`--check`) or rewrites
//! (default) the committed ones, which `test-regex` uses:
//!  - `tools/go_regexp_oracle`   Go `regexp`, black box → `src/go_vectors.zig`
//!  - `tools/go_casefold`        Go `unicode.SimpleFold` → `src/casefold.zig`
//!  - `tools/go_unicode`         Go `unicode` categories + scripts → `src/unicode_tables.zig`
//! The check ignores the `// GENERATED … (Go version)` line: a runner with
//! another Go patch release passes when every answer agrees.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-regex` runs it and
//! `zig build check-interop` compiles it. Needs go 1.26.0 (standard library
//! only; `GOPROXY=off`) and `zig` on PATH; no network. Run from the
//! repository root.
//!
//!   zig build interop-regex              # re-take, rewrite the vectors
//!   zig build interop-regex -- --check   # re-take, compare with the committed vectors

const std = @import("std");

const Tool = struct { name: []const u8, dir: []const u8, file: []const u8 };
const tools = [_]Tool{
    .{ .name = "Go regexp oracle", .dir = "modules/regex/tools/go_regexp_oracle", .file = "../../src/go_vectors.zig" },
    .{ .name = "Go case-folding table", .dir = "modules/regex/tools/go_casefold", .file = "../../src/casefold.zig" },
    .{ .name = "Go Unicode class tables", .dir = "modules/regex/tools/go_unicode", .file = "../../src/unicode_tables.zig" },
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
            std.debug.print("usage: interop-regex [--check]\n", .{});
            return 2;
        }
        check = true;
    }

    // Go: the pinned toolchain, offline (the module cache is filled ahead).
    var env = try init.environ.createMap(arena);
    try env.put("GOTOOLCHAIN", "go1.26.0");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");

    for (tools) |t| {
        std.debug.print("interop-regex: {s} ...\n", .{t.name});
        const argv: []const []const u8 = if (check)
            &.{ "go", "run", ".", "-check", t.file }
        else
            &.{ "go", "run", ".", "-out", t.file };
        var child = std.process.spawn(io, .{
            .argv = argv,
            .environ_map = &env,
            .cwd = .{ .path = t.dir },
            .stdin = .close,
        }) catch |e| {
            std.debug.print("interop-regex: could not spawn go ({t}) -- the oracle needs it\n", .{e});
            return 1;
        };
        const ok = switch (try child.wait(io)) {
            .exited => |code| code == 0,
            else => false,
        };
        if (!ok) {
            std.debug.print("interop-regex: {s} FAILED\n", .{t.name});
            return 1;
        }
        std.debug.print("interop-regex: {s} {s}\n", .{ t.name, if (check) "fresh" else "re-taken" });
    }
    return 0;
}
