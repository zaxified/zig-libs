// SPDX-License-Identifier: MIT

//! Re-takes staticfiles' Go oracle and compares (`--check`) or rewrites
//! (default) its committed vectors, which `test-staticfiles` replays
//! (`src/go_oracle_test.zig`):
//!  - `tools/go_oracle`   Go net/http `FileServer(http.Dir)` and `ServeContent`,
//!                        black box over a real loopback socket with this
//!                        module's own request bytes and file tree
//!                        → `src/go_oracle_vectors.zig`
//! The vectors' `// GENERATED …` line names the Go version, so `--check` on
//! another toolchain reports the file stale even when every answer agrees:
//! re-take, read the diff, re-judge the divergences.
//! (The starlette Range/ETag answers in `src/root.zig` are a frozen transcript;
//! they are not re-taken here.)
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-staticfiles` runs it and
//! `zig build check-interop` compiles it. Needs go 1.26.0 (stdlib only,
//! `GOPROXY=off`); no network beyond loopback. Run from the repository root.
//!
//!   zig build interop-staticfiles              # re-take, rewrite the vectors
//!   zig build interop-staticfiles -- --check   # re-take, compare with the committed vectors

const std = @import("std");

const oracle_dir = "modules/staticfiles/tools/go_oracle";
const vectors_rel = "../../src/go_oracle_vectors.zig";

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
            std.debug.print("usage: interop-staticfiles [--check]\n", .{});
            return 2;
        }
        check = true;
    }

    // Go: the pinned toolchain, offline (stdlib only).
    var env = try init.environ.createMap(arena);
    try env.put("GOTOOLCHAIN", "go1.26.0");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");

    std.debug.print("interop-staticfiles: Go net/http FileServer/ServeContent ...\n", .{});
    const argv: []const []const u8 = if (check)
        &.{ "go", "run", ".", "-check", vectors_rel }
    else
        &.{ "go", "run", ".", "-out", vectors_rel };
    var child = std.process.spawn(io, .{
        .argv = argv,
        .environ_map = &env,
        .cwd = .{ .path = oracle_dir },
        .stdin = .close,
    }) catch |e| {
        std.debug.print("interop-staticfiles: could not run go ({t}) -- the oracle needs it\n", .{e});
        return 1;
    };
    const ok = switch (try child.wait(io)) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!ok) {
        std.debug.print("interop-staticfiles: Go oracle FAILED\n", .{});
        return 1;
    }
    std.debug.print("interop-staticfiles: Go oracle {s}\n", .{if (check) "fresh" else "re-taken"});
    return 0;
}
