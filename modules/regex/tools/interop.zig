// SPDX-License-Identifier: MIT

//! Re-takes regex's generated files and compares (`--check`) or rewrites
//! (default) the committed ones, which `test-regex` uses:
//!  - `tools/go_regexp_oracle`   Go `regexp`, black box → `src/go_vectors.zig`
//!  - `tools/rust_regex_oracle`  Rust `regex`, black box → `src/rust_vectors.zig`
//!  - `tools/rust_unicode`       Rust `regex-syntax` → `src/unicode16_tables.zig`,
//!                               `src/casefold16.zig`
//! The checks ignore the `// GENERATED …` line: a runner with another Go
//! patch release passes when every answer agrees.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-regex` runs it and
//! `zig build check-interop` compiles it. Needs go 1.26.0 (standard library
//! only; `GOPROXY=off`), cargo with the pinned crates in its registry
//! (`--offline`; `regex` 1.13.1 and its four dependencies, read 2026-10-27)
//! and `zig` on PATH; no network. Run from the repository root.
//!
//!   zig build interop-regex              # re-take, rewrite the files
//!   zig build interop-regex -- --check   # re-take, compare with the committed files

const std = @import("std");

const Kind = enum { go, cargo };
const Tool = struct { name: []const u8, kind: Kind, dir: []const u8, target: []const u8, crate_arg: bool = false };
const tools = [_]Tool{
    .{ .name = "Go regexp oracle", .kind = .go, .dir = "modules/regex/tools/go_regexp_oracle", .target = "../../src/go_vectors.zig" },
    .{ .name = "Rust regex oracle", .kind = .cargo, .dir = "modules/regex/tools/rust_regex_oracle", .target = "../../src/rust_vectors.zig" },
    .{ .name = "Rust Unicode tables", .kind = .cargo, .dir = "modules/regex/tools/rust_unicode", .target = "../../src", .crate_arg = true },
};

/// The registry copy of regex-syntax 0.8.11 (`rust_unicode` reads its alias
/// lists): `$CARGO_HOME` or `~/.cargo`, any registry index.
fn regexSyntaxDir(arena: std.mem.Allocator, io: std.Io, env: *const std.process.Environ.Map) ![]const u8 {
    const home = env.get("CARGO_HOME") orelse try std.fs.path.join(arena, &.{ env.get("HOME") orelse return error.NoHome, ".cargo" });
    const src = try std.fs.path.join(arena, &.{ home, "registry", "src" });
    var dir = try std.Io.Dir.cwd().openDir(io, src, .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        const cand = try std.fs.path.join(arena, &.{ src, e.name, "regex-syntax-0.8.11" });
        std.Io.Dir.cwd().access(io, cand, .{}) catch continue;
        return cand;
    }
    return error.RegexSyntaxNotInRegistry;
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
        var argv: std.ArrayList([]const u8) = .empty;
        switch (t.kind) {
            .go => try argv.appendSlice(arena, &.{ "go", "run", "." }),
            .cargo => try argv.appendSlice(arena, &.{ "cargo", "run", "--release", "--offline", "--quiet", "--" }),
        }
        if (t.crate_arg) try argv.appendSlice(arena, &.{ "--crate", try regexSyntaxDir(arena, io, &env) });
        try argv.appendSlice(arena, &.{ if (check) "-check" else "-out", t.target });
        var child = std.process.spawn(io, .{
            .argv = argv.items,
            .environ_map = &env,
            .cwd = .{ .path = t.dir },
            .stdin = .close,
        }) catch |e| {
            std.debug.print("interop-regex: could not spawn {t} ({t}) -- the tool needs it\n", .{ t.kind, e });
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
