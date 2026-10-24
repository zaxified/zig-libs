// SPDX-License-Identifier: MIT

//! Re-takes tracecontext's OpenTelemetry oracle and compares (`--check`) or
//! rewrites (default) its committed vectors, which `test-tracecontext`
//! replays (`src/otel_oracle_test.zig`):
//!  - `tools/go_oracle`   OpenTelemetry Go v1.46.0 `propagation.TraceContext`,
//!                        black box over this module's own request headers
//!                        → `src/otel_vectors.zig`
//! The vectors' `// GENERATED …` line names the Go and otel versions, so
//! `--check` on another toolchain reports the file stale even when every
//! answer agrees: re-take, read the diff, re-judge the divergences.
//! (The W3C conformance corpus `src/w3c_vectors.zig` is a vendored transcript
//! of a Python suite that needs a live server; it is not re-taken here.)
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-tracecontext` runs it and
//! `zig build check-interop` compiles it. Needs go 1.26.0 with otel v1.46.0 in
//! the module cache (`GOPROXY=off`); no network. Run from the repository root.
//!
//!   zig build interop-tracecontext              # re-take, rewrite the vectors
//!   zig build interop-tracecontext -- --check   # re-take, compare with the committed vectors

const std = @import("std");

const oracle_dir = "modules/tracecontext/tools/go_oracle";
const vectors = "modules/tracecontext/src/otel_vectors.zig";

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
            std.debug.print("usage: interop-tracecontext [--check]\n", .{});
            return 2;
        }
        check = true;
    }

    // Go: the pinned toolchain, offline (the module cache is filled ahead).
    var env = try init.environ.createMap(arena);
    try env.put("GOTOOLCHAIN", "go1.26.0");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");

    std.debug.print("interop-tracecontext: OpenTelemetry Go TraceContext ...\n", .{});
    var out_file: ?std.Io.File = null;
    defer if (out_file) |f| f.close(io);
    if (!check) out_file = try std.Io.Dir.cwd().createFile(io, vectors, .{});
    const argv: []const []const u8 = if (check)
        &.{ "go", "run", ".", "-check", "../../src/otel_vectors.zig" }
    else
        &.{ "go", "run", "." };
    var child = std.process.spawn(io, .{
        .argv = argv,
        .environ_map = &env,
        .cwd = .{ .path = oracle_dir },
        .stdin = .close,
        .stdout = if (out_file) |f| .{ .file = f } else .inherit,
    }) catch |e| {
        std.debug.print("interop-tracecontext: could not run go ({t}) -- the oracle needs it\n", .{e});
        return 1;
    };
    const ok = switch (try child.wait(io)) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!ok) {
        std.debug.print("interop-tracecontext: OpenTelemetry oracle FAILED\n", .{});
        return 1;
    }
    std.debug.print("interop-tracecontext: OpenTelemetry oracle {s}\n", .{if (check) "fresh" else "re-taken"});
    return 0;
}
