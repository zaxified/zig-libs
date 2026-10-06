// SPDX-License-Identifier: MIT

//! Re-takes the Go archive/tar oracle (`tools/go_oracle`, replayed by
//! `src/go_oracle.zig`).
//!
//! THIS IS A PROGRAM, NOT A TEST. Built and run by `zig build interop-tar`,
//! compiled (never run) by `zig build check-interop`, never part of `test-tar`.
//!
//! It writes this module's Writer output for the `write_cases` table below
//! into scratch (one archive per case, "<id>.<gnu|pax>.tar"), runs the Go
//! generator over them, and checks two things:
//!  - Go read every entry of every archive as the entry it was written from
//!    (the live half of the write-path anchor; the replay pins the bytes);
//!  - the fresh vectors equal the committed `src/go_oracle_vectors.zig` -- a
//!    newer Go answering differently, a case table edited without
//!    regenerating, or a Writer whose output moved.
//! Needs `go` on PATH, no network.
//!
//!   zig build interop-tar               # check
//!   zig build interop-tar -- --regen    # check, then overwrite the committed vectors

const std = @import("std");
const tar = @import("tar");

const scratch = ".zig-cache/interop-tar";
const go_oracle_dir = "modules/tar/tools/go_oracle";
const go_vectors = "modules/tar/src/go_oracle_vectors.zig";

const Item = struct { entry: tar.Entry, content: []const u8 = "" };
const WriteCase = struct { id: []const u8, mode: tar.LongNames, items: []const Item, tgz: bool = false };

fn f(path: []const u8, content: []const u8) Item {
    return .{ .entry = .{ .path = path, .mode = 0o644, .uid = 1000, .gid = 1000, .mtime = 1_600_000_000 }, .content = content };
}

fn with(item: Item, comptime field: []const u8, value: anytype) Item {
    var it = item;
    @field(it.entry, field) = value;
    return it;
}

const long150 = "d" ** 49 ++ "/" ++ "e" ** 100;
const long300 = "p" ** 300;

const basic = [_]Item{
    f("a.txt", "hello\n"),
    .{ .entry = .{ .path = "d/", .kind = .dir, .mode = 0o755, .mtime = 1_600_000_000 } },
    .{ .entry = .{ .path = "d/link", .kind = .symlink, .mode = 0o777, .mtime = 1_600_000_000, .link_target = "../a.txt" } },
    .{ .entry = .{ .path = "hard", .kind = .hardlink, .mode = 0o644, .mtime = 1_600_000_000, .link_target = "a.txt" } },
    f("empty", ""),
    f("b512", "x" ** 512),
    f("b513", "y" ** 513),
    with(f("setuid", "s"), "mode", 0o4755),
    with(f("allbits", "a"), "mode", 0o7777),
    f("\xc4\x8d.txt", "c\n"),
};

const long = [_]Item{
    f(long150, "split\n"),
    f(long300, "whole\n"),
    .{ .entry = .{ .path = "l", .kind = .symlink, .mode = 0o777, .mtime = 1_600_000_000, .link_target = "t" ** 150 } },
    .{ .entry = .{ .path = "h", .kind = .hardlink, .mode = 0o644, .mtime = 1_600_000_000, .link_target = long300 } },
};

const gnu_limits = [_]Item{
    with(with(f("maxid", "m"), "uid", 0o7777777), "gid", 0o7777777),
    with(f("maxtime", "t"), "mtime", 0o77777777777),
    with(f("epoch", "e"), "mtime", 0),
};

const pax_ids = [_]Item{
    with(with(f("bigid", "b"), "uid", 3_000_000), "gid", 4_000_001),
    with(f("maxu32", "u"), "uid", std.math.maxInt(u32)),
    with(f("edge", "e"), "uid", 0o7777777 + 1),
};

const pax_times = [_]Item{
    with(f("neg1", "n"), "mtime", -1),
    with(with(f("negfrac", "n"), "mtime", -3), "mtime_nsec", 250_000_000),
    with(with(f("nsec", "n"), "mtime", 1_727_700_007), "mtime_nsec", 123_456_789),
    with(with(f("onens", "n"), "mtime", 0), "mtime_nsec", 1),
    with(f("far", "f"), "mtime", 10_000_000_000),
    with(f("1960", "s"), "mtime", -315_619_200),
};

const write_cases = [_]WriteCase{
    // Not a Writer mode: "pack.tgz" is packTarGz over `basic` (see writeArchives).
    .{ .id = "pack", .mode = .gnu, .items = &basic, .tgz = true },
    .{ .id = "basic", .mode = .gnu, .items = &basic },
    .{ .id = "basic", .mode = .pax, .items = &basic },
    .{ .id = "long", .mode = .gnu, .items = &long },
    .{ .id = "long", .mode = .pax, .items = &long },
    .{ .id = "limits", .mode = .gnu, .items = &gnu_limits },
    .{ .id = "limits", .mode = .pax, .items = &gnu_limits },
    .{ .id = "ids", .mode = .pax, .items = &pax_ids },
    .{ .id = "times", .mode = .pax, .items = &pax_times },
};

fn writeArchives(io: std.Io, gpa: std.mem.Allocator, comptime dir: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    for (write_cases) |c| {
        if (c.tgz) continue;
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        const w = tar.Writer.initOptions(&out.writer, .{ .long_names = c.mode });
        for (c.items) |it| try w.writeEntry(it.entry, it.content);
        try w.finish();
        var name_buf: [256]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "{s}/{s}.{t}.tar", .{ dir, c.id, c.mode });
        try cwd.writeFile(io, .{ .sub_path = name, .data = out.written() });
    }
    // packTarGz: the gzip framing around the default (GNU-mode) writer.
    var entries: [basic.len]tar.ContentEntry = undefined;
    for (basic, &entries) |it, *e| e.* = .{ .entry = it.entry, .content = it.content };
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try tar.packTarGz(gpa, &out.writer, &entries);
    try cwd.writeFile(io, .{ .sub_path = dir ++ "/pack.tgz", .data = out.written() });
}

/// The Go verdict's view of one write case must be the entries it was
/// written from, modulo what the mode cannot carry (GNU drops nanoseconds).
/// Checked on the fresh vectors text: each written path must appear there
/// as an entry name with its uid and mtime.
fn checkGoReadsWhatWeWrote(fresh: []const u8) bool {
    var ok = true;
    for (write_cases) |c| {
        var id_buf: [64]u8 = undefined;
        const id_line = (if (c.tgz)
            std.fmt.bufPrint(&id_buf, ".id = \"{s}.tgz\"", .{c.id})
        else
            std.fmt.bufPrint(&id_buf, ".id = \"{s}.{t}\"", .{ c.id, c.mode })) catch unreachable;
        const at = std.mem.indexOf(u8, fresh, id_line) orelse {
            std.debug.print("go oracle: case {s} missing from the fresh vectors\n", .{id_line});
            ok = false;
            continue;
        };
        const end = std.mem.indexOfPos(u8, fresh, at, "\n    },\n") orelse fresh.len;
        const body = fresh[at..end];
        if (std.mem.indexOf(u8, body, ".err = null") == null) {
            std.debug.print("go oracle: Go refused our {s}.{t} archive\n", .{ c.id, c.mode });
            ok = false;
        }
        for (c.items) |it| {
            const e = it.entry;
            const nsec: u32 = if (c.mode == .gnu) 0 else e.mtime_nsec;
            var want_buf: [1024]u8 = undefined;
            var want: std.Io.Writer = .fixed(&want_buf);
            want.print(".mode = {d}, .uid = {d}, .gid = {d}, .mtime = {d}, .nsec = {d}", .{ e.mode, e.uid, e.gid, e.mtime, nsec }) catch unreachable;
            var name_buf: [1024]u8 = undefined;
            var name: std.Io.Writer = .fixed(&name_buf);
            zigStr(&name, e.path) catch unreachable;
            const name_at = std.mem.indexOf(u8, body, name.buffered());
            // One entry per line: the fields must be on the name's own line.
            const found = if (name_at) |n| std.mem.indexOf(u8, std.mem.sliceTo(body[n..], '\n'), want.buffered()) != null else false;
            if (!found) {
                std.debug.print("go oracle: {s}.{t}: Go did not read \"{s}\" as written ({s})\n", .{ c.id, c.mode, e.path, want.buffered() });
                ok = false;
            }
        }
    }
    return ok;
}

/// The generator's string rendering (`zigStr` in tools/go_oracle/main.go),
/// so a path can be found in its output.
fn zigStr(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeAll(".name = \"");
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        0x20...0x21, 0x23...0x5b, 0x5d...0x7e => try w.writeByte(c),
        else => try w.print("\\x{x:0>2}", .{c}),
    };
    try w.writeByte('"');
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

    var regen = false;
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--regen")) {
            regen = true;
        } else {
            std.debug.print("unknown argument '{s}'\nusage: interop-tar [--regen]\n", .{a});
            return 2;
        }
    }

    const cwd = std.Io.Dir.cwd();
    const write_dir = scratch ++ "/go_write";
    cwd.createDirPath(io, write_dir) catch {};
    try writeArchives(io, gpa, write_dir);

    // `env` is passed on explicitly: a child spawned without a map gets an
    // empty environment, and `go` needs HOME (or GOCACHE) for its build cache.
    var env = try init.environ.createMap(arena);
    // The oracle's version is part of the claim: the committed vectors were
    // taken with go1.26.0, and the CI runner's own Go gave different verdicts
    // (interop lane, 2026-10-07). Pin it; `go` fetches that toolchain when the
    // installed one differs. Bump deliberately, then review every changed
    // verdict before `--regen`.
    try env.put("GOTOOLCHAIN", "go1.26.0");
    const fresh_path = scratch ++ "/go_oracle_vectors.zig";
    var child = std.process.spawn(io, .{
        // Paths are relative to the generator's directory, four levels down.
        .argv = &.{ "go", "run", ".", "-write", "../../../../" ++ write_dir, "-out", "../../../../" ++ fresh_path },
        .cwd = .{ .path = go_oracle_dir },
        .environ_map = &env,
        .stdin = .close,
        .stdout = .inherit,
        .stderr = .inherit,
    }) catch |e| {
        std.debug.print("could not spawn go ({t}) -- the oracle is required, not optional\n", .{e});
        return 1;
    };
    switch (try child.wait(io)) {
        .exited => |code| if (code != 0) {
            std.debug.print("go oracle: generator exited {d}\n", .{code});
            return 1;
        },
        else => {
            std.debug.print("go oracle: generator did not exit normally\n", .{});
            return 1;
        },
    }
    const fresh = try cwd.readFileAlloc(io, fresh_path, arena, .limited(16 << 20));
    var ok = checkGoReadsWhatWeWrote(fresh);

    if (regen) {
        try cwd.writeFile(io, .{ .sub_path = go_vectors, .data = fresh });
        std.debug.print("go oracle: wrote {s}\n", .{go_vectors});
    } else {
        const want = try cwd.readFileAlloc(io, go_vectors, arena, .limited(16 << 20));
        if (std.mem.eql(u8, want, fresh)) {
            std.debug.print("go oracle: {s} matches a fresh run\n", .{go_vectors});
        } else {
            std.debug.print("go oracle: a fresh run differs from {s}\n" ++
                "  diff {s} {s}; if Go changed, review every changed verdict, then --regen\n", .{ go_vectors, go_vectors, fresh_path });
            ok = false;
        }
    }
    std.debug.print("interop-tar: {s}\n", .{if (ok) "OK" else "NOT OK"});
    return if (ok) 0 else 1;
}
