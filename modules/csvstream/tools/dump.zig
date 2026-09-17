// SPDX-License-Identifier: MIT
//
// Third leg of the csvstream differential oracle (CONVENTIONS.md §9): reads
// the same hex vectors `gen.py` wrote and reports what THIS module's own
// public API (`LineIterator` + `splitFields`, quote='"', delimiter=',') makes
// of each -- so `compare.py` can hold three independently written CSV readers
// (Python `csv`, Go `encoding/csv`, this module) against one another.
//
// Talks to csvstream ONLY through `@import("csvstream")`'s public root.zig
// exports -- no module source is copied here.
//
// WHAT IT NEEDS: the live module, nothing foreign.
// WHAT IT PRODUCES: one line per input line on stdin --
//   ERR          -- splitFields failed on the first record (buffer too small;
//                    not expected to happen on these short vectors)
//   MULTI:N:f... -- LineIterator produced more than one non-empty record (a
//                    bare '\n' inside the vector); N/fields describe the
//                    FIRST record only, same convention as the Go oracle
//   N:f1|f2|...  -- exactly one record; N fields, hex-encoded, '|'-joined
//                    (N may be 0, for an empty input: LineIterator yields no
//                    records at all)
//
// Build (against the LIVE module):
//   zig build-exe -O ReleaseFast --dep csvstream \
//       -Mmain=dump.zig -Mcsvstream=../src/root.zig \
//       --cache-dir <scratch>/zc -femit-bin=<scratch>/dump
// Run:
//   ./dump < zz_vectors.hex

const std = @import("std");
const csvstream = @import("csvstream");

fn writeOut(bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = std.os.linux.write(1, bytes.ptr + off, bytes.len - off);
        const signed: isize = @bitCast(rc);
        if (signed < 0) {
            if (signed == -4) continue; // EINTR
            return error.WriteFailed;
        }
        if (signed == 0) return error.WriteFailed;
        off += @intCast(signed);
    }
}

fn hexEncode(w: *std.Io.Writer, s: []const u8) !void {
    for (s) |c| try w.print("{x:0>2}", .{c});
}

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // Raw read(2) loop on stdin -- no Io instance, no argv API churn.
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(gpa);
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const n = std.posix.read(0, &chunk) catch |e| return e;
        if (n == 0) break;
        try input.appendSlice(gpa, chunk[0..n]);
    }

    const out_buf = try gpa.alloc(u8, 4 << 20);
    defer gpa.free(out_buf);
    var fw = std.Io.Writer.fixed(out_buf);
    const w = &fw;

    var decoded: std.ArrayList(u8) = .empty;
    defer decoded.deinit(gpa);
    var fields_buf: [64][]const u8 = undefined;

    // Strip exactly one trailing newline so a file of N newline-terminated
    // lines splits into exactly N tokens -- an input LINE may legitimately be
    // empty (the '' vector hex-encodes to an empty line), so "skip blank
    // lines" would silently drop that vector and desync line numbers against
    // the other two oracles.
    var body = input.items;
    if (body.len > 0 and body[body.len - 1] == '\n') body = body[0 .. body.len - 1];

    var lines = std.mem.splitScalar(u8, body, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");

        decoded.clearRetainingCapacity();
        try decoded.resize(gpa, line.len / 2);
        _ = std.fmt.hexToBytes(decoded.items, line) catch {
            try w.writeAll("ERR\n");
            continue;
        };
        const bytes = decoded.items;

        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        var it = csvstream.LineIterator.init(bytes, '"', 0);
        const first = it.next();
        const multi = if (first != null) it.next() != null else false;

        if (first == null) {
            try w.writeAll("0:\n");
            continue;
        }

        const fields = csvstream.splitFields(first.?.bytes, &fields_buf, ',', '"', arena) catch {
            try w.writeAll("ERR\n");
            continue;
        };

        if (multi) try w.writeAll("MULTI:");
        try w.print("{d}:", .{fields.len});
        for (fields, 0..) |fld, i| {
            if (i != 0) try w.writeAll("|");
            try hexEncode(w, fld);
        }
        try w.writeAll("\n");
    }

    try writeOut(w.buffered());
}
