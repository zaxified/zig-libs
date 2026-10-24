// SPDX-License-Identifier: MIT

//! Re-takes mcp's SDK oracle and compares (`--check`) or rewrites (default)
//! its committed transcript, which `test-mcp` replays:
//!  - `tools/sdk_oracle/drive.py`   the official MCP Python SDK, black box,
//!                                  drives `tools/sdk_oracle/server.zig` over
//!                                  stdio → `src/sdk_oracle_vectors.zig`
//! The transcript's `// GENERATED …` line names the SDK version, so `--check`
//! against another SDK release reports the file stale: re-take and read the
//! diff.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-mcp` runs it and
//! `zig build check-interop` compiles it. Needs a Python venv with the `mcp`
//! package at `$MCP_ORACLE_VENV`, default `~/.local/share/zig-libs/
//! oracle-venvs/mcp` (`python3 -m venv $V && $V/bin/pip install mcp`), and
//! `zig` on PATH (drive.py builds the server); no network. Run from the
//! repository root.
//!
//!   zig build interop-mcp              # re-take, rewrite the transcript
//!   zig build interop-mcp -- --check   # re-take, compare with the committed one

const std = @import("std");

const script = "modules/mcp/tools/sdk_oracle/drive.py";

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
            std.debug.print("usage: interop-mcp [--check]\n", .{});
            return 2;
        }
        check = true;
    }

    const env = try init.environ.createMap(arena);
    const venv = env.get("MCP_ORACLE_VENV") orelse blk: {
        const home = env.get("HOME") orelse {
            std.debug.print("interop-mcp: neither MCP_ORACLE_VENV nor HOME is set\n", .{});
            return 1;
        };
        break :blk try std.fmt.allocPrint(arena, "{s}/.local/share/zig-libs/oracle-venvs/mcp", .{home});
    };
    const python = try std.fmt.allocPrint(arena, "{s}/bin/python", .{venv});

    std.debug.print("interop-mcp: MCP Python SDK ({s}) ...\n", .{venv});
    const argv: []const []const u8 = if (check) &.{ python, script, "--check" } else &.{ python, script };
    var child = std.process.spawn(io, .{ .argv = argv, .stdin = .close }) catch |e| {
        std.debug.print("interop-mcp: could not run {s} ({t}) -- the oracle needs the venv\n", .{ python, e });
        return 1;
    };
    const ok = switch (try child.wait(io)) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!ok) {
        std.debug.print("interop-mcp: SDK oracle FAILED\n", .{});
        return 1;
    }
    std.debug.print("interop-mcp: SDK oracle {s}\n", .{if (check) "fresh" else "re-taken"});
    return 0;
}
