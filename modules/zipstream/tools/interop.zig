// SPDX-License-Identifier: MIT

//! Re-takes the Go archive/zip oracle (`tools/go_oracle`, replayed by
//! `src/go_oracle.zig`).
//!
//! THIS IS A PROGRAM, NOT A TEST. Built and run by `zig build interop-zipstream`,
//! compiled (never run) by `zig build check-interop`, never part of
//! `test-zipstream`.
//!
//! It writes this module's ArchiveWriter output for the `write_cases` table
//! below into scratch ("<id>.zip"), runs the Go generator over them, and
//! checks two things:
//!  - Go read every entry of every archive as the entry it was written from
//!    (the live half of the write-path anchor; the replay pins the bytes);
//!  - the fresh vectors equal the committed `src/go_oracle_vectors.zig`.
//! Needs `go` on PATH, no network.
//!
//!   zig build interop-zipstream               # check
//!   zig build interop-zipstream -- --regen    # check, then overwrite the committed vectors
//!
//! Every case gives an mtime of 1970 or later: before that the writer has no
//! UT field and the DOS fields clamp to 1980 (documented), so Go would read a
//! different time than was given and the replay could not reproduce the bytes.

const std = @import("std");
const zipstream = @import("zipstream");

const scratch = ".zig-cache/interop-zipstream";
const go_oracle_dir = "modules/zipstream/tools/go_oracle";
const go_vectors = "modules/zipstream/src/go_oracle_vectors.zig";

const Item = struct { name: []const u8, data: []const u8, opts: zipstream.AddEntryOptions };
const WriteCase = struct { id: []const u8, items: []const Item };

const t0: i64 = 1_727_700_007;

const big = "the quick brown fox jumps over the lazy dog 0123456789\n" ** 1300;

const basic = [_]Item{
    .{ .name = "a.txt", .data = "hello\n", .opts = .{ .mtime = t0 } },
    .{ .name = "s.txt", .data = "stored\n", .opts = .{ .method = .store, .mtime = t0 } },
    .{ .name = "empty-deflate", .data = "", .opts = .{ .mtime = t0 } },
    .{ .name = "empty-store", .data = "", .opts = .{ .method = .store, .mtime = t0 } },
    .{ .name = "big.txt", .data = big, .opts = .{ .mtime = t0 } },
    .{ .name = "sub/dir/f.txt", .data = "nested\n", .opts = .{ .mtime = t0 } },
};

const modes = [_]Item{
    .{ .name = "m644", .data = "m", .opts = .{ .method = .store, .mtime = t0, .mode = 0o644 } },
    .{ .name = "m755", .data = "m", .opts = .{ .method = .store, .mtime = t0, .mode = 0o755 } },
    .{ .name = "m4755", .data = "m", .opts = .{ .method = .store, .mtime = t0, .mode = 0o4755 } },
    .{ .name = "m7777", .data = "m", .opts = .{ .method = .store, .mtime = t0, .mode = 0o7777 } },
    .{ .name = "m0600-deflate", .data = "mm", .opts = .{ .mtime = t0, .mode = 0o600 } },
};

const times = [_]Item{
    .{ .name = "epoch", .data = "t", .opts = .{ .method = .store, .mtime = 0 } },
    .{ .name = "dos-min", .data = "t", .opts = .{ .method = .store, .mtime = 315_532_800 } },
    .{ .name = "odd-second", .data = "t", .opts = .{ .method = .store, .mtime = t0 } },
    .{ .name = "past-2038", .data = "t", .opts = .{ .method = .store, .mtime = 2_147_483_648 } },
    .{ .name = "y2100", .data = "t", .opts = .{ .method = .store, .mtime = 4_102_444_800 } },
    .{ .name = "u32-max", .data = "t", .opts = .{ .method = .store, .mtime = std.math.maxInt(u32) } },
};

const names = [_]Item{
    .{ .name = "\xc4\x8d.txt", .data = "c", .opts = .{ .method = .store, .mtime = t0 } },
    .{ .name = "a b.txt", .data = "s", .opts = .{ .method = .store, .mtime = t0 } },
    .{ .name = "n" ** 300, .data = "l", .opts = .{ .method = .store, .mtime = t0 } },
};

const write_cases = [_]WriteCase{
    .{ .id = "basic", .items = &basic },
    .{ .id = "modes", .items = &modes },
    .{ .id = "names", .items = &names },
    .{ .id = "times", .items = &times },
};

fn writeArchives(io: std.Io, gpa: std.mem.Allocator, comptime dir: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    for (write_cases) |c| {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var w = zipstream.ArchiveWriter.init(gpa, &out.writer);
        defer w.deinit();
        for (c.items) |it| try w.addEntry(it.name, it.data, it.opts);
        try w.finish();
        var name_buf: [256]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "{s}/{s}.zip", .{ dir, c.id });
        try cwd.writeFile(io, .{ .sub_path = name, .data = out.written() });
    }
}

/// Each written entry must appear in Go's view with its name, mtime, mode
/// and content, and Go must not have flagged a non-ASCII name as non-UTF-8.
fn checkGoReadsWhatWeWrote(arena: std.mem.Allocator, fresh: []const u8) !bool {
    var ok = true;
    for (write_cases) |c| {
        var id_buf: [64]u8 = undefined;
        const id_line = std.fmt.bufPrint(&id_buf, ".id = \"{s}\"", .{c.id}) catch unreachable;
        const at = std.mem.indexOf(u8, fresh, id_line) orelse {
            std.debug.print("go oracle: case {s} missing from the fresh vectors\n", .{c.id});
            ok = false;
            continue;
        };
        const end = std.mem.indexOfPos(u8, fresh, at, "\n    },\n") orelse fresh.len;
        const body = fresh[at..end];
        if (std.mem.indexOf(u8, body, ".err = null") == null) {
            std.debug.print("go oracle: Go refused our {s} archive\n", .{c.id});
            ok = false;
        }
        for (c.items) |it| {
            var name: std.Io.Writer.Allocating = .init(arena);
            try zigStr(&name.writer, ".name = ", it.name);
            var want: std.Io.Writer.Allocating = .init(arena);
            const w = &want.writer;
            try w.print(".mtime = {d}, .mode = ", .{it.opts.mtime.?});
            if (it.opts.mode) |m| try w.print("{d}", .{m}) else try w.writeAll("null");
            try w.writeAll(", .non_utf8 = false, ");
            try zigStr(w, ".content = ", it.data);
            try w.writeAll(", .open_err = null");
            const line = if (std.mem.indexOf(u8, body, name.written())) |n| std.mem.sliceTo(body[n..], '\n') else "";
            if (std.mem.indexOf(u8, line, want.written()) == null) {
                std.debug.print("go oracle: {s}: Go did not read \"{s}\" as written\n  want: {s}\n  got:  {s}\n", .{ c.id, it.name, want.written()[0..@min(want.written().len, 200)], line[0..@min(line.len, 300)] });
                ok = false;
            }
        }
    }
    return ok;
}

/// The generator's string rendering (`zigStr` in tools/go_oracle/zig.go).
fn zigStr(w: *std.Io.Writer, prefix: []const u8, s: []const u8) !void {
    try w.writeAll(prefix);
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\r' => try w.writeAll("\\r"),
        '\n' => try w.writeAll("\\n"),
        '\t' => try w.writeAll("\\t"),
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
            std.debug.print("unknown argument '{s}'\nusage: interop-zipstream [--regen]\n", .{a});
            return 2;
        }
    }

    const cwd = std.Io.Dir.cwd();
    const write_dir = scratch ++ "/go_write";
    cwd.createDirPath(io, write_dir) catch {};
    try writeArchives(io, gpa, write_dir);

    // `env` is passed on explicitly: a child spawned without a map gets an
    // empty environment, and `go` needs HOME (or GOCACHE) for its build cache.
    const env = try init.environ.createMap(arena);
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
    var ok = try checkGoReadsWhatWeWrote(arena, fresh);

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
    std.debug.print("interop-zipstream: {s}\n", .{if (ok) "OK" else "NOT OK"});
    return if (ok) 0 else 1;
}
