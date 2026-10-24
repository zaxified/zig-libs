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

/// How an item is written: `addEntry` (file), `beginEntry`/`endEntry` with
/// the data in one `writeAll` (stream; a data descriptor), `addDirectory`
/// (`data` unused), `addSymlink` (`data` is the target).
const Kind = enum { file, stream, dir, symlink };
const Item = struct { name: []const u8, data: []const u8 = "", opts: zipstream.AddEntryOptions, kind: Kind = .file };
const WriteCase = struct { id: []const u8, items: []const Item, comment: []const u8 = "" };

const t0: i64 = 1_727_700_007;

const big = strRepeat("the quick brown fox jumps over the lazy dog 0123456789\n", 1300);

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
    .{ .name = strRepeat("n", 300), .data = "l", .opts = .{ .method = .store, .mtime = t0 } },
};

const streamed = [_]Item{
    .{ .name = "d-small", .data = "streamed\n", .opts = .{ .mtime = t0 }, .kind = .stream },
    .{ .name = "s-small", .data = "streamed\n", .opts = .{ .method = .store, .mtime = t0 }, .kind = .stream },
    .{ .name = "d-empty", .data = "", .opts = .{ .mtime = t0 }, .kind = .stream },
    .{ .name = "s-empty", .data = "", .opts = .{ .method = .store, .mtime = t0 }, .kind = .stream },
    .{ .name = "d-big", .data = big, .opts = .{ .mtime = t0 }, .kind = .stream },
    .{ .name = "s-big", .data = big, .opts = .{ .method = .store, .mtime = t0 }, .kind = .stream },
    .{ .name = "d-mode", .data = "m", .opts = .{ .mtime = t0, .mode = 0o640 }, .kind = .stream },
    .{ .name = "after", .data = "a plain entry after streamed ones\n", .opts = .{ .mtime = t0 } },
};

const zip64 = [_]Item{
    .{ .name = "buf-deflate", .data = "zip64 buffered\n", .opts = .{ .mtime = t0, .force_zip64 = true } },
    .{ .name = "buf-store", .data = "zip64 buffered\n", .opts = .{ .method = .store, .mtime = t0, .force_zip64 = true } },
    .{ .name = "buf-empty", .data = "", .opts = .{ .method = .store, .mtime = t0, .force_zip64 = true } },
    .{ .name = "str-deflate", .data = big, .opts = .{ .mtime = t0, .force_zip64 = true }, .kind = .stream },
    .{ .name = "str-store", .data = "zip64 streamed\n", .opts = .{ .method = .store, .mtime = t0, .force_zip64 = true }, .kind = .stream },
    .{ .name = "str-empty", .data = "", .opts = .{ .mtime = t0, .force_zip64 = true }, .kind = .stream },
    .{ .name = "dir/", .opts = .{ .mtime = t0, .force_zip64 = true }, .kind = .dir },
    .{ .name = "link", .data = "buf-store", .opts = .{ .mtime = t0, .force_zip64 = true }, .kind = .symlink },
    .{ .name = "plain", .data = "not forced\n", .opts = .{ .mtime = t0 } },
};

const comments = [_]Item{
    .{ .name = "a", .data = "a", .opts = .{ .mtime = t0, .comment = "first" } },
    .{ .name = "b", .data = "b", .opts = .{ .method = .store, .mtime = t0 } },
    .{ .name = "c", .data = "c", .opts = .{ .method = .store, .mtime = t0, .comment = "comment" }, .kind = .stream },
    .{ .name = "u", .data = "c", .opts = .{ .method = .store, .mtime = t0, .comment = "\xc4\x8d comment" } },
    .{ .name = "d/", .opts = .{ .mtime = t0, .comment = "a directory" }, .kind = .dir },
    .{ .name = "l", .data = "a", .opts = .{ .mtime = t0, .comment = "a link" }, .kind = .symlink },
    .{ .name = "long", .data = "l", .opts = .{ .method = .store, .mtime = t0, .comment = strRepeat("long ", 200) } },
};

const rec_cafe = "\xfe\xca\x04\x00\x01\x02\x03\x04"; // id 0xcafe, 4 data bytes
const rec_empty = "\xef\xbe\x00\x00"; // id 0xbeef, no data

const extras = [_]Item{
    .{ .name = "x-mtime", .data = "x", .opts = .{ .method = .store, .mtime = t0, .extra = rec_cafe } },
    .{ .name = "x-nomtime", .data = "x", .opts = .{ .method = .store, .mtime = 0, .extra = rec_cafe ++ rec_empty } },
    .{ .name = "x-stream", .data = "x", .opts = .{ .mtime = t0, .extra = rec_cafe }, .kind = .stream },
    .{ .name = "x-zip64", .data = "x", .opts = .{ .mtime = t0, .extra = rec_cafe, .force_zip64 = true } },
    .{ .name = "x-dir/", .opts = .{ .mtime = t0, .extra = rec_empty }, .kind = .dir },
};

const dirs_links = [_]Item{
    .{ .name = "d", .opts = .{ .mtime = t0 }, .kind = .dir },
    .{ .name = "d/e/", .opts = .{ .mtime = t0, .mode = 0o700 }, .kind = .dir },
    .{ .name = "d/f", .data = "in d\n", .opts = .{ .mtime = t0 } },
    .{ .name = "d/link", .data = "f", .opts = .{ .mtime = t0 }, .kind = .symlink },
    .{ .name = "d/link-mode", .data = "../d/f", .opts = .{ .mtime = t0, .mode = 0o755 }, .kind = .symlink },
    .{ .name = "d/empty-link", .data = "", .opts = .{ .mtime = t0 }, .kind = .symlink },
    .{ .name = "setgid/", .opts = .{ .mtime = t0, .mode = 0o2775 }, .kind = .dir },
};

const unicode = [_]Item{
    .{ .name = "\xc4\x8d/", .opts = .{ .mtime = t0 }, .kind = .dir },
    .{ .name = "\xc4\x8d/\xc5\xbe.txt", .data = "z", .opts = .{ .mtime = t0 }, .kind = .stream },
    .{ .name = "\xe2\x82\xac-link", .data = "\xc5\xbe.txt", .opts = .{ .mtime = t0 }, .kind = .symlink },
    .{ .name = "\xf0\x9f\x98\x80", .data = "emoji", .opts = .{ .method = .store, .mtime = t0, .comment = "\xf0\x9f\x98\x80" } },
};

const write_cases = [_]WriteCase{
    .{ .id = "streamed", .items = &streamed },
    .{ .id = "zip64", .items = &zip64, .comment = "zip64 archive" },
    .{ .id = "comments", .items = &comments, .comment = "archive comment \xc4\x8d" },
    .{ .id = "extras", .items = &extras },
    .{ .id = "dirs_links", .items = &dirs_links },
    .{ .id = "unicode", .items = &unicode },
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
        w.comment = c.comment;
        for (c.items) |it| switch (it.kind) {
            .file => try w.addEntry(it.name, it.data, it.opts),
            .stream => {
                const sw = try w.beginEntry(it.name, it.opts);
                try sw.writeAll(it.data);
                try w.endEntry();
            },
            .dir => try w.addDirectory(it.name, it.opts),
            .symlink => try w.addSymlink(it.name, it.data, it.opts),
        };
        try w.finish();
        var name_buf: [256]u8 = undefined;
        const name = try std.mem.print(&name_buf, "{s}/{s}.zip", .{ dir, c.id });
        try cwd.writeFile(io, .{ .sub_path = name, .data = out.written() });
    }
}

/// Each written entry must appear in Go's view with its name, mtime, mode,
/// content, comment and type (directory, symlink), the data-descriptor and
/// UTF-8 flag bits as written, and the archive comment; Go must not have
/// flagged a non-ASCII name as non-UTF-8.
fn checkGoReadsWhatWeWrote(arena: std.mem.Allocator, fresh: []const u8) !bool {
    var ok = true;
    for (write_cases) |c| {
        var id_buf: [64]u8 = undefined;
        const id_line = std.mem.print(&id_buf, ".id = \"{s}\"", .{c.id}) catch unreachable;
        const at = std.mem.find(u8, fresh, id_line) orelse {
            std.debug.print("go oracle: case {s} missing from the fresh vectors\n", .{c.id});
            ok = false;
            continue;
        };
        const end = std.mem.findPos(u8, fresh, at, "\n    },\n") orelse fresh.len;
        const body = fresh[at..end];
        if (std.mem.find(u8, body, ".err = null") == null) {
            std.debug.print("go oracle: Go refused our {s} archive\n", .{c.id});
            ok = false;
        }
        var cmt: std.Io.Writer.Allocating = .init(arena);
        try zigStr(&cmt.writer, ".comment = ", c.comment);
        try cmt.writer.writeAll(",\n        .entries");
        if (std.mem.find(u8, body, cmt.written()) == null) {
            std.debug.print("go oracle: {s}: Go did not read the archive comment as written\n", .{c.id});
            ok = false;
        }
        for (c.items) |it| {
            var name: std.Io.Writer.Allocating = .init(arena);
            // addDirectory adds the trailing '/'.
            const slash = it.kind == .dir and !std.mem.endsWith(u8, it.name, "/");
            const full_name = if (slash) try std.mem.concat(arena, u8, &.{ it.name, "/" }) else it.name;
            try zigStr(&name.writer, ".name = ", full_name);
            var want: std.Io.Writer.Allocating = .init(arena);
            const w = &want.writer;
            try w.print(".mtime = {d}, .mode = ", .{it.opts.mtime.?});
            const mode: ?u16 = it.opts.mode orelse switch (it.kind) {
                .file, .stream => null,
                .dir => 0o755,
                .symlink => 0o777,
            };
            if (mode) |m| try w.print("{d}", .{m}) else try w.writeAll("null");
            try w.writeAll(", .non_utf8 = false, ");
            try zigStr(w, ".content = ", if (it.kind == .dir) "" else it.data);
            try w.writeAll(", .open_err = null");
            try zigStr(w, ", .comment = ", it.opts.comment);
            var non_ascii = false;
            for ([_][]const u8{ it.name, it.opts.comment }) |str| {
                for (str) |ch| non_ascii = non_ascii or ch >= 0x80;
            }
            const flags: u16 = (if (it.kind == .stream) @as(u16, 8) else 0) | (if (non_ascii) @as(u16, 1 << 11) else 0);
            var tail: std.Io.Writer.Allocating = .init(arena);
            try tail.writer.print(".flags = {d}, ", .{flags});
            var kind_tail: std.Io.Writer.Allocating = .init(arena);
            try kind_tail.writer.print(".is_dir = {s}, .is_symlink = {s} }}", .{ if (it.kind == .dir) "true" else "false", if (it.kind == .symlink) "true" else "false" });
            var extra: std.Io.Writer.Allocating = .init(arena);
            try zigStr(&extra.writer, "", it.opts.extra);
            const line = if (std.mem.find(u8, body, name.written())) |n| std.mem.sliceTo(body[n..], '\n') else "";
            // The caller's extra records sit inside Go's whole extra field (after our UT).
            const extra_ok = std.mem.find(u8, line, std.mem.trim(u8, extra.written(), "\"")) != null;
            if (std.mem.find(u8, line, want.written()) == null or std.mem.find(u8, line, tail.written()) == null or std.mem.find(u8, line, kind_tail.written()) == null or !extra_ok) {
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

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}
