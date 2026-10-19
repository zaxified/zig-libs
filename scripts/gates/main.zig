// SPDX-License-Identifier: MIT
//! `zl-gates` -- the repository gates as one host program (Zig 0.17).
//!
//!     zl-gates <gate> [--module=<m>]... [--dark-module=<m>]...
//!              [--zig=<path>] [--cache-dir=<path>]
//!
//! Run by `build.zig`'s gate steps (`zig build <gate>`), never by hand: the
//! step sets the cwd to the build root and passes `-Dmodule` / `-Ddark-module`
//! through, plus the zig and local cache of the outer build for the gates that
//! start a sub-build. Exit 0 = the gate passed; 1 = it failed, with the reason
//! on stderr as `error: ...` lines; 2 = it could not run (bad arguments).
//!
//! This file is also the stand-in for the slice of `std.Build` /
//! `std.Build.Step` the 0.16 make functions used (`gates.zig`), so they moved
//! without a rewrite: `step.owner` is a `Build` whose `build_root` is the cwd,
//! and `step.fail` logs the message and returns `error.MakeFailed`.
//!
//! Known gaps (review of the 0.17 gate rewrite, 2026-10-18; all LOW, open):
//! - `check-uapi` / `check-dark-tests` warn and exit 0 when `python3` / `bash`
//!   is missing (as on 0.16). CI does not assert the runner has them, so a
//!   slimmer image would be a false green; a "require" env flag would close it.
//! - `declared_dirs` and `gateTool(b)` in `build.zig` are file-level globals,
//!   deduped by relative path: a consumer graph that instantiates zig-libs from
//!   TWO package roots (live `.path` dependencies only; fetched packages are
//!   immutable) declares the second root's directories never and reuses the
//!   first root's gate exe.
//! - Comments in `gates.zig` still describe the 0.16 `build()` pass numbers and
//!   `b.step` behaviour; behaviour is unaffected.

const std = @import("std");
const gates = @import("gates.zig");

pub const Build = struct {
    allocator: std.mem.Allocator,
    build_root: Root,
    graph: *Graph,
    /// The outer build's local cache dir (`--cache-dir=`), for sub-builds.
    local_cache_dir: ?[]const u8 = null,

    pub const Root = struct {
        handle: std.Io.Dir,
        /// Always null: paths are relative to the cwd, which IS the root.
        path: ?[]const u8 = null,
    };

    pub const Graph = struct {
        io: std.Io,
        environ_map: *std.process.Environ.Map,
        /// The outer build's zig (`--zig=`); "zig" when not given.
        zig_exe: []const u8,
    };

    pub fn fmt(b: *Build, comptime format: []const u8, args: anytype) []u8 {
        return std.fmt.allocPrint(b.allocator, format, args) catch @panic("OOM");
    }

    pub fn dupe(b: *Build, bytes: []const u8) []u8 {
        return b.allocator.dupe(u8, bytes) catch @panic("OOM");
    }

    /// Relative to the cwd, which is the build root.
    pub fn pathFromRoot(b: *Build, sub_path: []const u8) []u8 {
        return b.dupe(sub_path);
    }
};

pub const Step = struct {
    owner: *Build,
    name: []const u8,

    pub fn fail(step: *Step, comptime format: []const u8, args: anytype) error{MakeFailed} {
        _ = step;
        std.log.err(format, args);
        return error.MakeFailed;
    }
};

/// The 0.16 make functions took one and ignored it.
pub const MakeOptions = struct {};

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const argv = try init.minimal.args.toSlice(arena);

    if (argv.len < 2) {
        std.log.err("usage: zl-gates <gate> [--module=<m>]... (run by `zig build <gate>`)", .{});
        return 2;
    }
    const gate = std.meta.stringToEnum(gates.Gate, argv[1]) orelse {
        std.log.err("zl-gates: unknown gate '{s}'", .{argv[1]});
        return 2;
    };

    var modules: std.ArrayList([]const u8) = .empty;
    var dark: std.ArrayList([]const u8) = .empty;
    var zig_exe: []const u8 = "zig";
    var cache_dir: ?[]const u8 = null;
    for (argv[2..]) |arg| {
        if (std.mem.cutPrefix(u8, arg, "--module=")) |v| {
            try modules.append(arena, v);
        } else if (std.mem.cutPrefix(u8, arg, "--dark-module=")) |v| {
            try dark.append(arena, v);
        } else if (std.mem.cutPrefix(u8, arg, "--zig=")) |v| {
            zig_exe = v;
        } else if (std.mem.cutPrefix(u8, arg, "--cache-dir=")) |v| {
            cache_dir = v;
        } else {
            std.log.err("zl-gates: unknown argument '{s}'", .{arg});
            return 2;
        }
    }
    gates.selected_modules = modules.items;

    var graph: Build.Graph = .{ .io = io, .environ_map = init.environ_map, .zig_exe = zig_exe };
    var b: Build = .{
        .allocator = arena,
        .build_root = .{ .handle = std.Io.Dir.cwd() },
        .graph = &graph,
        .local_cache_dir = cache_dir,
    };
    gates.run(&b, gate, dark.items) catch |err| switch (err) {
        error.MakeFailed => return 1,
        else => {
            std.log.err("{s}: {t}", .{ argv[1], err });
            return 1;
        },
    };
    return 0;
}
