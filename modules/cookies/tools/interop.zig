// SPDX-License-Identifier: MIT

//! The Public Suffix List algorithm against **libpsl** (MIT) over the FULL
//! system list: every rule yields a handful of host names (the rule's own
//! name, one and two labels below it, the wildcard's base), libpsl answers
//! them through `tools/psl_oracle.py`, and `cookies.psl` must give the same
//! public suffix and registrable domain for each. The hermetic half (libpsl
//! over our own mini list) is `src/psl_oracle.zig`, in `test-cookies`.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-cookies` runs it,
//! `zig build check-interop` compiles it. It needs no network, but it needs
//! python3, libpsl.so.5 and the list (`publicsuffix` package); a missing one
//! is a failure, not a skip.
//!
//!   zig build interop-cookies                     # /usr/share/publicsuffix/public_suffix_list.dat
//!   zig build interop-cookies -- --list PATH      # another copy of the list

const std = @import("std");
const cookies = @import("cookies");

const scratch = ".zig-cache/interop-cookies";

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

    var list_path: []const u8 = "/usr/share/publicsuffix/public_suffix_list.dat";
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--list")) {
            list_path = args.next() orelse return 2;
        } else {
            std.debug.print("usage: interop-cookies [--list PATH]\n", .{});
            return 2;
        }
    }

    const cwd = std.Io.Dir.cwd();
    cwd.createDirPath(io, scratch) catch {};
    const text = try cwd.readFileAlloc(io, list_path, arena, .limited(16 << 20));
    var list = try cookies.PublicSuffixList.parse(gpa, text);
    defer list.deinit();

    // Hosts from every rule, ASCII as a client sees them.
    var hosts: std.ArrayList(u8) = .empty;
    var n_hosts: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or std.mem.startsWith(u8, line, "//")) continue;
        var rule = line[0 .. std.mem.indexOfAny(u8, line, " \t") orelse line.len];
        if (rule[0] == '!') rule = rule[1..];
        if (std.mem.startsWith(u8, rule, "*.")) rule = rule[2..];
        const name = cookies.psl.toAscii(arena, rule) catch continue;
        for ([_][]const u8{ "", "x.", "y.x.", "z.y.x." }) |prefix| {
            try hosts.print(arena, "{s}{s}\n", .{ prefix, name });
            n_hosts += 1;
        }
    }
    const in_path = scratch ++ "/hosts.txt";
    const out_path = scratch ++ "/libpsl.txt";
    try cwd.writeFile(io, .{ .sub_path = in_path, .data = hosts.items });

    const env = try init.environ.createMap(arena);
    var child = std.process.spawn(io, .{
        .argv = &.{ "python3", "modules/cookies/tools/psl_oracle.py", "check", list_path, in_path, out_path },
        .environ_map = &env,
        .stdin = .close,
        .stdout = .inherit,
        .stderr = .inherit,
    }) catch |e| {
        std.debug.print("could not spawn python3 ({t}) -- the oracle is required, not optional\n", .{e});
        return 1;
    };
    switch (try child.wait(io)) {
        .exited => |code| if (code != 0) return 1,
        else => return 1,
    }

    const answers = try cwd.readFileAlloc(io, out_path, arena, .limited(256 << 20));
    var checked: usize = 0;
    var bad: usize = 0;
    var it = std.mem.splitScalar(u8, answers, '\n');
    while (it.next()) |row| {
        if (row.len == 0) continue;
        var cols = std.mem.splitScalar(u8, row, '\t');
        const host = cols.next().?;
        const want_ps = cols.next().?;
        const want_reg = cols.next().?;
        const ps = list.publicSuffix(host);
        const reg = list.registrableDomain(host) orelse "-";
        checked += 1;
        if (std.mem.eql(u8, ps, want_ps) and std.mem.eql(u8, reg, want_reg)) continue;
        bad += 1;
        if (bad <= 30) std.debug.print("  {s}: libpsl {s} / {s}, ours {s} / {s}\n", .{ host, want_ps, want_reg, ps, reg });
    }
    std.debug.print("libpsl over {s}: {d} hosts ({d} generated), {d} differ -- {s}\n", .{
        list_path, checked, n_hosts, bad, if (bad == 0 and checked == n_hosts) "OK" else "NOT OK",
    });
    return if (bad == 0 and checked == n_hosts) 0 else 1;
}
