// SPDX-License-Identifier: MIT

//! Re-takes json5's reference oracle and compares (`--check`) or rewrites
//! (default) its committed vectors, which `test-json5` replays:
//!  - `tools/ref_oracle.js`   json5/json5 2.2.3 under bun, black box over
//!                            this module's own generated documents
//!                            → `src/ref_oracle_vectors.zig`
//! The script's `// GENERATED …` line names the bun version, so `--check` on
//! another bun reports the file stale even when every answer agrees: re-take
//! and read the diff.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-json5` runs it and
//! `zig build check-interop` compiles it. Needs `bun` with the `json5@2.2.3`
//! package in its install cache (`bun add json5@2.2.3` once, anywhere;
//! JSON5_REF=<path to lib/index.js> overrides); no network. Run from the
//! repository root.
//!
//!   zig build interop-json5              # re-take, rewrite the vectors
//!   zig build interop-json5 -- --check   # re-take, compare with the committed vectors

const std = @import("std");

const script = "modules/json5/tools/ref_oracle.js";
const vectors = "modules/json5/src/ref_oracle_vectors.zig";

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
            std.debug.print("usage: interop-json5 [--check]\n", .{});
            return 2;
        }
        check = true;
    }

    std.debug.print("interop-json5: reference json5/json5 2.2.3 (bun) ...\n", .{});
    const argv: []const []const u8 = if (check) &.{ "bun", script, "--check" } else &.{ "bun", script };
    const r = std.process.run(arena, io, .{ .argv = argv, .stdout_limit = .limited(64 << 20) }) catch |e| {
        std.debug.print("interop-json5: could not run bun ({t}) -- the oracle needs it\n", .{e});
        return 1;
    };
    const ok = switch (r.term) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!ok) {
        std.debug.print("{s}interop-json5: reference oracle FAILED\n", .{r.stderr});
        return 1;
    }
    if (!check) try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = vectors, .data = r.stdout });
    std.debug.print("interop-json5: reference oracle {s}\n", .{if (check) "fresh" else "re-taken"});
    return 0;
}
