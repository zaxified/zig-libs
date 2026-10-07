// SPDX-License-Identifier: MIT

//! Re-takes router's chi oracle and compares (`--check`) or rewrites (default)
//! its committed vectors, which `test-router` replays:
//!  - `tools/go_chi_oracle`   go-chi/chi v5.3.2, black box → `src/chi_vectors.zig`
//! The check ignores the `// GENERATED … (Go version)` line: a runner with
//! another Go patch release passes when every answer agrees.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-router` runs it and
//! `zig build check-interop` compiles it. Needs go 1.26.0 with
//! github.com/go-chi/chi/v5 in the module cache (`GOPROXY=off`;
//! `scripts/lib/ci-environment.sh interop` downloads it) and `zig` on PATH;
//! no network. Run from the repository root.
//!
//!   zig build interop-router              # re-take, rewrite the vectors
//!   zig build interop-router -- --check   # re-take, compare with the committed vectors

const std = @import("std");

const oracle_dir = "modules/router/tools/go_chi_oracle";

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
            std.debug.print("usage: interop-router [--check]\n", .{});
            return 2;
        }
        check = true;
    }

    // Go: the pinned toolchain, offline (the module cache is filled ahead).
    var env = try init.environ.createMap(arena);
    try env.put("GOTOOLCHAIN", "go1.26.0");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");

    std.debug.print("interop-router: chi (go-chi/chi v5.3.2) ...\n", .{});
    const argv: []const []const u8 = if (check)
        &.{ "go", "run", ".", "-check", "../../src/chi_vectors.zig" }
    else
        &.{ "go", "run", ".", "-out", "../../src/chi_vectors.zig" };
    var child = std.process.spawn(io, .{
        .argv = argv,
        .environ_map = &env,
        .cwd = .{ .path = oracle_dir },
        .stdin = .close,
    }) catch |e| {
        std.debug.print("interop-router: could not spawn go ({t}) -- the oracle needs it\n", .{e});
        return 1;
    };
    const ok = switch (try child.wait(io)) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!ok) {
        std.debug.print("interop-router: chi oracle FAILED\n", .{});
        return 1;
    }
    std.debug.print("interop-router: chi oracle {s}\n", .{if (check) "fresh" else "re-taken"});
    return 0;
}
