// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor: Python's `csv` and Go's `encoding/csv` as
//! independent readers and writers (`tools/oracle.py`, answers frozen in
//! `oracle_vectors.zig`). No Python, no Go at test time.
//!
//! Reading: each input is read to the end by `LineIterator` in span mode
//! (`QuotedNewlines.span`, RFC 4180 multi-line quoted fields -- what both
//! other readers do) and split with `splitFields`; where Python and Go agree
//! we must give the same records, where they disagree we must give one of
//! their answers -- and every difference of either kind belongs to a listed
//! class. Inputs without a line feed are read in the default (lazy) mode too,
//! which must agree with span mode there.
//!
//! Writing: `writeRecord` must produce Python's bytes (QUOTE_MINIMAL, CRLF)
//! -- bytes Go reads back as the fields written -- and this module must read
//! its own output back to the same fields.

const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const csv = @import("root.zig");
const vectors = @import("oracle_vectors.zig");

const Records = []const []const []const u8;

const Read = struct { records: Records, offsets: []const u64, unbalanced: bool };

fn readAll(arena: mem.Allocator, text: []const u8, span: bool) !Read {
    var it = if (span) csv.LineIterator.initSpan(text, '"', 0, .{}) else csv.LineIterator.init(text, '"', 0);
    var recs: std.ArrayList([]const []const u8) = .empty;
    var offsets: std.ArrayList(u64) = .empty;
    var unbalanced = false;
    while (it.next()) |ls| {
        unbalanced = unbalanced or ls.unbalanced_quote;
        try offsets.append(arena, ls.byte_offset);
        const buf = try arena.alloc([]const u8, 64);
        const fields = try csv.splitFieldsOpts(ls.bytes, buf, ',', '"', arena, .{ .trailing_empty_field = true });
        try recs.append(arena, try arena.dupe([]const u8, fields));
    }
    return .{ .records = recs.items, .offsets = offsets.items, .unbalanced = unbalanced };
}

fn eqlRecords(a: ?Records, b: ?Records) bool {
    if (a == null or b == null) return a == null and b == null;
    if (a.?.len != b.?.len) return false;
    for (a.?, b.?) |ra, rb| {
        if (ra.len != rb.len) return false;
        for (ra, rb) |fa, fb| if (!mem.eql(u8, fa, fb)) return false;
    }
    return true;
}

fn printRecords(label: []const u8, r: ?Records) void {
    std.debug.print("   {s}:", .{label});
    const recs = r orelse return std.debug.print(" ERR\n", .{});
    for (recs) |rec| {
        std.debug.print(" [", .{});
        for (rec, 0..) |f, i| std.debug.print("{s}{f}", .{ if (i == 0) "" else ",", std.zig.fmtString(f) });
        std.debug.print("]", .{});
    }
    std.debug.print("\n", .{});
}

test "oracle: records as Python's csv and Go's encoding/csv read them" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var bad: usize = 0;
    var both: usize = 0;
    var like_py: usize = 0;
    var like_go: usize = 0;
    var unbalanced: usize = 0;
    var blank_lines: usize = 0;
    var offsets_checked: usize = 0;
    for (vectors.reads) |c| {
        const read = try readAll(arena, c.text, true);
        const ours = read.records;
        if (mem.indexOfScalar(u8, c.text, '\n') == null) {
            const lazy = (try readAll(arena, c.text, false)).records;
            if (!eqlRecords(lazy, ours)) {
                bad += 1;
                std.debug.print("lazy != span for {f}\n", .{std.zig.fmtString(c.text)});
            }
        }
        const py: ?Records = c.py;
        const go: ?Records = c.go;
        const m_py = eqlRecords(ours, py);
        const m_go = eqlRecords(ours, go);
        // Where we read Go's records, each must start where Go says it does
        // (its FieldPos(0)) -- the byte offset is this module's own feature,
        // and this is its outside answer.
        if (m_go) {
            const want = c.go_offsets;
            var same = want.len == read.offsets.len;
            if (same) for (want, read.offsets) |a, b| {
                if (a != b) same = false;
            };
            if (!same) {
                bad += 1;
                std.debug.print("offsets differ for {f}: go {any}, ours {any}\n", .{ std.zig.fmtString(c.text), want, read.offsets });
            } else offsets_checked += want.len;
        }
        if (m_py and m_go) {
            both += 1;
            continue;
        }
        if (m_py) like_py += 1;
        if (m_go) like_go += 1;
        if (m_py or m_go) continue;
        // A quote left open to the end of input: Python and Go take every
        // byte after it, line breaks included, into the field. Span mode
        // ends that record at its first line break and says so on the
        // record (`unbalanced_quote`) -- the documented bound, a stray quote
        // costs one record, never the rest of the file.
        if (read.unbalanced) {
            unbalanced += 1;
            continue;
        }
        // Python yields an empty record for a blank line, Go skips it, and
        // so do we (`LineIterator` skips empty lines); Go also drops the CR
        // of a CRLF inside a quoted field, which Python and we keep. A
        // document with both is answered by neither alone -- it must be
        // Python's records without the empty ones.
        if (c.py) |py_recs| {
            var kept: std.ArrayList([]const []const u8) = .empty;
            for (py_recs) |r| if (r.len != 0) try kept.append(arena, r);
            if (eqlRecords(ours, kept.items)) {
                blank_lines += 1;
                continue;
            }
        }
        bad += 1;
        if (bad <= 50) {
            std.debug.print("{f}\n", .{std.zig.fmtString(c.text)});
            printRecords("py  ", py);
            printRecords("go  ", go);
            printRecords("ours", ours);
        }
    }
    if (bad != 0) std.debug.print("reads: {d} all agree, {d} like Python only, {d} like Go only, {d} unbalanced, {d} blank-line+CRLF, {d} offsets checked, {d} bad\n", .{ both, like_py, like_go, unbalanced, blank_lines, offsets_checked, bad });
    try testing.expectEqual(@as(usize, 0), bad);
    // 2026-10-05: 767 all agree, 124 like Python, 820 like Go, 107
    // unbalanced, 15 blank-line+CRLF, 1882 record offsets equal to Go's;
    // most evidence is agreement.
    try testing.expect(both >= 700 and offsets_checked >= 1800);
}

test "oracle: writeRecord writes Python's bytes, which Go reads back as the fields" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var bad: usize = 0;
    for (vectors.writes) |c| {
        var aw: std.Io.Writer.Allocating = .init(arena);
        try csv.writeRecord(&aw.writer, c.fields, .{});
        const ours = aw.written();
        const back = (try readAll(arena, ours, true)).records;
        const want: Records = &.{c.fields};
        const ok_bytes = mem.eql(u8, ours, c.py);
        const ok_back = eqlRecords(back, want);
        // Go drops the CR of a CRLF inside a quoted field (its documented
        // normalization), so it is asked for the fields with that applied.
        const go_want_fields = try arena.alloc([]const u8, c.fields.len);
        for (c.fields, go_want_fields) |f, *g| g.* = try mem.replaceOwned(u8, arena, f, "\r\n", "\n");
        const go_want: Records = &.{go_want_fields};
        const go_ok = eqlRecords(c.go_reads_py, go_want);
        if (ok_bytes and ok_back and go_ok) continue;
        bad += 1;
        if (bad <= 30) {
            std.debug.print("fields {any}: py {f} go {f} ours {f}; ours reads back ok={} go reads py ok={}\n", .{
                c.fields, std.zig.fmtString(c.py), std.zig.fmtString(c.go), std.zig.fmtString(ours), ok_back, go_ok,
            });
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
}
