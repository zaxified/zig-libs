// SPDX-License-Identifier: MIT

//! Re-takes netaddr's three oracles and compares (`--check`) or rewrites
//! (default) their committed vectors, which `test-netaddr` replays:
//!  - `tools/parse_oracle.py`   glibc inet_pton/inet_ntop + Python ipaddress
//!                              → `src/parse_vectors.zig`
//!  - `tools/rfc6724_oracle.py` glibc getaddrinfo + the Linux kernel, inside
//!                              its own `unshare -rnm` → `src/rfc6724_vectors.zig`
//!  - `tools/go_netip_oracle`   Go net/netip + go4.org/netipx
//!                              → `src/netip_vectors.zig`
//! The Python checks ignore the `// GENERATED … (versions)` line: a runner
//! with another kernel or Python build passes when every verdict agrees.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-netaddr` runs it and
//! `zig build check-interop` compiles it. Needs python3, `unshare` (user
//! namespaces), `ip`, `mount`, go 1.26.0 with go4.org/netipx in the module
//! cache (`GOPROXY=off`; `scripts/lib/ci-environment.sh interop` downloads it)
//! and `zig` on PATH; no root, no network. Run from the repository root.
//!
//!   zig build interop-netaddr              # re-take all three, rewrite the vectors
//!   zig build interop-netaddr -- --check   # re-take, compare with the committed vectors

const std = @import("std");

const tools = "modules/netaddr/tools";
const src = "modules/netaddr/src";

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
        .name = "parse (glibc + Python ipaddress)",
        .check_argv = &.{ "python3", tools ++ "/parse_oracle.py", "--check" },
        .write_argv = &.{ "python3", tools ++ "/parse_oracle.py" },
        .write_stdout_to = src ++ "/parse_vectors.zig",
    },
    .{
        .name = "rfc6724 (glibc getaddrinfo + Linux source selection)",
        .check_argv = &.{ "python3", tools ++ "/rfc6724_oracle.py", "--check" },
        .write_argv = &.{ "python3", tools ++ "/rfc6724_oracle.py" },
        .write_stdout_to = src ++ "/rfc6724_vectors.zig",
    },
    .{
        .name = "netip (Go net/netip + netipx)",
        .check_argv = &.{ "go", "run", ".", "-check", "../../src/netip_vectors.zig" },
        .write_argv = &.{ "go", "run", ".", "-out", "../../src/netip_vectors.zig" },
        .write_stdout_to = null,
        .cwd = tools ++ "/go_netip_oracle",
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
            std.debug.print("usage: interop-netaddr [--check]\n", .{});
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
        std.debug.print("interop-netaddr: {s} ...\n", .{o.name});
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
            std.debug.print("interop-netaddr: could not spawn {s} ({t}) -- the oracle needs it\n", .{ o.check_argv[0], e });
            failed += 1;
            continue;
        };
        const ok = switch (try child.wait(io)) {
            .exited => |code| code == 0,
            else => false,
        };
        if (!ok) {
            std.debug.print("interop-netaddr: {s} FAILED\n", .{o.name});
            failed += 1;
        }
    }
    if (failed != 0) {
        std.debug.print("interop-netaddr: {d} of {d} oracles failed\n", .{ failed, oracles.len });
        return 1;
    }
    std.debug.print("interop-netaddr: {d} oracles {s}\n", .{ oracles.len, if (check) "fresh" else "re-taken" });
    return 0;
}
