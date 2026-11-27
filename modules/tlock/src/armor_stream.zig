// SPDX-License-Identifier: MIT
//! Streaming ASCII armor (`tle -a`), the shape of age's own `armor.NewWriter`
//! / `armor.NewReader` (filippo.io/age/armor, which `tle` puts in front of the
//! binary stream): `ArmorWriter` is a `std.Io.Writer` that writes the armored
//! form of what it is given to another writer, `ArmorReader` a `std.Io.Reader`
//! that yields the binary bytes of an armored stream. Composed with
//! `age.encryptStream`/`age.decryptStream` they armor and de-armor a file of
//! any size in bounded memory. Byte for byte what `age.armor` writes, and as
//! strict as `age.dearmor` reads: 64-column lines, padding only on the last
//! line, canonical base64, CRLF accepted, whitespace only around the block.

const std = @import("std");
const age = @import("age.zig");
const Writer = std.Io.Writer;
const Reader = std.Io.Reader;

const b64 = std.base64.standard;
const per_line = age.columns / 4 * 3; // 48 binary bytes per 64-column line

/// A `std.Io.Writer` (`.writer`) whose bytes reach `out` armored. Call
/// `finish` after the last write: it writes the last line and the END line
/// (an armored file is not complete without it). `out` is not flushed.
pub const ArmorWriter = struct {
    out: *Writer,
    pending: [per_line]u8 = undefined,
    pending_len: usize = 0,
    started: bool = false,
    writer: Writer,

    /// `buffer` may be empty (every write then reaches `drain`).
    pub fn init(out: *Writer, buffer: []u8) ArmorWriter {
        return .{ .out = out, .writer = .{ .buffer = buffer, .vtable = &.{ .drain = drain } } };
    }

    fn begin(self: *ArmorWriter) Writer.Error!void {
        if (self.started) return;
        try self.out.writeAll(age.armor_begin ++ "\n");
        self.started = true;
    }

    fn line(self: *ArmorWriter, bin: []const u8) Writer.Error!void {
        var enc: [age.columns]u8 = undefined;
        try self.out.writeAll(b64.Encoder.encode(&enc, bin));
        try self.out.writeByte('\n');
    }

    fn feed(self: *ArmorWriter, bytes: []const u8) Writer.Error!void {
        if (bytes.len == 0) return;
        try self.begin();
        var rest = bytes;
        while (rest.len != 0) {
            const take = @min(per_line - self.pending_len, rest.len);
            @memcpy(self.pending[self.pending_len..][0..take], rest[0..take]);
            self.pending_len += take;
            rest = rest[take..];
            if (self.pending_len == per_line) {
                try self.line(&self.pending);
                self.pending_len = 0;
            }
        }
    }

    fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const self: *ArmorWriter = @alignCast(@fieldParentPtr("writer", w));
        try self.feed(w.buffered());
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try self.feed(d);
            n += d.len;
        }
        for (0..splat) |_| try self.feed(data[data.len - 1]);
        return n + splat * data[data.len - 1].len;
    }

    /// Write the buffered bytes, the last (short) line and the END line.
    pub fn finish(self: *ArmorWriter) Writer.Error!void {
        try self.writer.flush();
        try self.begin();
        if (self.pending_len != 0) try self.line(self.pending[0..self.pending_len]);
        self.pending_len = 0;
        try self.out.writeAll(age.armor_end ++ "\n");
    }
};

/// A `std.Io.Reader` (`.reader`) of the binary bytes of the armored stream
/// `in`. A malformed armor ends the stream with `error.ReadFailed` and
/// `err = error.MalformedArmor`; a failure of `in` is `ReadFailed` with
/// `err = null` (the cause is `in`'s). `in` needs a buffer of at least 72
/// bytes (one armor line with CRLF). After the END line the rest of `in` is
/// read to its end and must be whitespace.
pub const ArmorReader = struct {
    in: *Reader,
    err: ?age.ArmorError = null,
    state: enum { begin, body, last_seen, done } = .begin,
    line_buf: [per_line]u8 = undefined,
    line_pos: usize = 0,
    line_len: usize = 0,
    reader: Reader,

    pub fn init(in: *Reader, buffer: []u8) ArmorReader {
        return .{ .in = in, .reader = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 } };
    }

    fn malformed(self: *ArmorReader) error{ReadFailed} {
        self.err = error.MalformedArmor;
        return error.ReadFailed;
    }

    /// The next line without its terminator, or null at the end of `in`.
    fn nextLine(self: *ArmorReader) error{ReadFailed}!?[]const u8 {
        const raw = self.in.takeDelimiterInclusive('\n') catch |e| switch (e) {
            error.EndOfStream => {
                // A last line without a newline.
                const rest = self.in.buffered();
                if (rest.len == 0) return null;
                self.in.toss(rest.len);
                return std.mem.trimEnd(u8, rest, "\r");
            },
            error.StreamTooLong => return self.malformed(),
            error.ReadFailed => return error.ReadFailed,
        };
        var l = raw[0 .. raw.len - 1];
        if (std.mem.endsWith(u8, l, "\r")) l = l[0 .. l.len - 1];
        return l;
    }

    fn fill(self: *ArmorReader) error{ ReadFailed, EndOfStream }!void {
        while (true) switch (self.state) {
            .begin => {
                const l = (try self.nextLine()) orelse return self.malformed();
                const t = std.mem.trim(u8, l, " \t\r");
                if (t.len == 0) continue; // leading whitespace
                if (!std.mem.eql(u8, t, age.armor_begin)) return self.malformed();
                self.state = .body;
                // The first body line must not be END (no empty armor).
                const first = (try self.nextLine()) orelse return self.malformed();
                if (std.mem.eql(u8, first, age.armor_end)) return self.malformed();
                try self.decodeLine(first);
                return;
            },
            .body, .last_seen => {
                const l = (try self.nextLine()) orelse return self.malformed();
                if (std.mem.eql(u8, std.mem.trimEnd(u8, l, " \t"), age.armor_end)) {
                    self.state = .done;
                    // Only whitespace may follow.
                    while (try self.nextLine()) |tail| {
                        if (std.mem.trim(u8, tail, " \t\r").len != 0) return self.malformed();
                    }
                    return error.EndOfStream;
                }
                if (self.state == .last_seen) return self.malformed();
                try self.decodeLine(l);
                return;
            },
            .done => return error.EndOfStream,
        };
    }

    fn decodeLine(self: *ArmorReader, l: []const u8) error{ReadFailed}!void {
        if (l.len == 0 or l.len > age.columns) return self.malformed();
        const short = l.len != age.columns or std.mem.findScalar(u8, l, '=') != null;
        const n = b64.Decoder.calcSizeForSlice(l) catch return self.malformed();
        b64.Decoder.decode(self.line_buf[0..n], l) catch return self.malformed();
        self.line_pos = 0;
        self.line_len = n;
        if (short) self.state = .last_seen;
    }

    fn stream(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const self: *ArmorReader = @alignCast(@fieldParentPtr("reader", r));
        if (self.line_pos == self.line_len) {
            self.fill() catch |e| switch (e) {
                error.EndOfStream => return error.EndOfStream,
                error.ReadFailed => return error.ReadFailed,
            };
        }
        const avail = self.line_buf[self.line_pos..self.line_len];
        const n = try w.write(limit.slice(avail));
        self.line_pos += n;
        return n;
    }
};

// ── tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

fn pattern(buf: []u8) void {
    for (buf, 0..) |*b, i| b.* = @truncate(i *% 131 +% 17);
}

test "ArmorWriter writes exactly what age.armor writes, whatever the write sizes" {
    const gpa = testing.allocator;
    var bin: [300]u8 = undefined;
    pattern(&bin);
    for ([_]usize{ 1, 47, 48, 49, 96, 97, 300 }) |len| {
        const want = try gpa.alloc(u8, age.armoredLen(len));
        defer gpa.free(want);
        _ = try age.armor(want, bin[0..len]);
        for ([_]usize{ 1, 5, 48, 1000 }) |step| {
            var sink: Writer.Allocating = .init(gpa);
            defer sink.deinit();
            var small: [7]u8 = undefined;
            var aw = ArmorWriter.init(&sink.writer, &small);
            var i: usize = 0;
            while (i < len) : (i += step) try aw.writer.writeAll(bin[i..@min(len, i + step)]);
            try aw.finish();
            try testing.expectEqualStrings(want, sink.written());
        }
    }
}

fn readAll(gpa: std.mem.Allocator, armored: []const u8) ![]u8 {
    var src: Reader = .fixed(armored);
    var buf: [5]u8 = undefined;
    var ar = ArmorReader.init(&src, &buf);
    var sink: Writer.Allocating = .init(gpa);
    errdefer sink.deinit();
    _ = ar.reader.streamRemaining(&sink.writer) catch |e| {
        if (ar.err) |ae| return ae;
        return e;
    };
    return sink.toOwnedSlice();
}

test "ArmorReader yields what age.dearmor yields, CRLF and surrounding whitespace included" {
    const gpa = testing.allocator;
    var bin: [300]u8 = undefined;
    pattern(&bin);
    for ([_]usize{ 1, 47, 48, 49, 96, 300 }) |len| {
        const arm = try gpa.alloc(u8, age.armoredLen(len));
        defer gpa.free(arm);
        _ = try age.armor(arm, bin[0..len]);
        const got = try readAll(gpa, arm);
        defer gpa.free(got);
        try testing.expectEqualSlices(u8, bin[0..len], got);
        // CRLF line endings and whitespace around the block.
        var crlf: Writer.Allocating = .init(gpa);
        defer crlf.deinit();
        try crlf.writer.writeAll(" \n\t\n");
        for (arm) |c| {
            if (c == '\n') try crlf.writer.writeByte('\r');
            try crlf.writer.writeByte(c);
        }
        try crlf.writer.writeAll("\n  \n");
        const got2 = try readAll(gpa, crlf.written());
        defer gpa.free(got2);
        try testing.expectEqualSlices(u8, bin[0..len], got2);
    }
}

test "ArmorReader refuses what age.dearmor refuses" {
    const gpa = testing.allocator;
    var bin: [100]u8 = undefined;
    pattern(&bin);
    var arm: [age.armoredLen(100)]u8 = undefined;
    _ = try age.armor(&arm, &bin);
    const good: []const u8 = &arm;
    const first_nl = std.mem.findScalar(u8, good, '\n').?;
    const bad_cases = [_][]const u8{
        "",
        "junk\n",
        age.armor_begin ++ "\n" ++ age.armor_end ++ "\n", // empty
        age.armor_begin ++ "\nQUJD\n", // no END
        age.armor_begin ++ "\nQUI=\nQUJD\n" ++ age.armor_end ++ "\n", // a line after the padded one
        age.armor_begin ++ "\nQUJ!\n" ++ age.armor_end ++ "\n", // not base64
        age.armor_begin ++ "\nQUJ=\n" ++ age.armor_end ++ "\n", // non-canonical trailing bits
    };
    for (bad_cases) |c| {
        try testing.expect(std.meta.isError(readAll(gpa, c)));
        var scratch: [64]u8 = undefined;
        try testing.expect(std.meta.isError(age.dearmor(&scratch, c)));
    }
    // A short line in the middle, and trailing junk after END.
    var mid: Writer.Allocating = .init(gpa);
    defer mid.deinit();
    try mid.writer.writeAll(good[0 .. first_nl + 1]);
    try mid.writer.writeAll("QUJD\n");
    try mid.writer.writeAll(good[first_nl + 1 ..]);
    try testing.expectError(error.MalformedArmor, readAll(gpa, mid.written()));
    var tail: Writer.Allocating = .init(gpa);
    defer tail.deinit();
    try tail.writer.writeAll(good);
    try tail.writer.writeAll("x\n");
    try testing.expectError(error.MalformedArmor, readAll(gpa, tail.written()));
}

// ── mutation 2026-11-25 (delta run over this file) ─────────────────────────

fn armoredOf(gpa: std.mem.Allocator, bin: []const u8) ![]u8 {
    const arm = try gpa.alloc(u8, age.armoredLen(bin.len));
    errdefer gpa.free(arm);
    _ = try age.armor(arm, bin);
    return arm;
}

test "mutation 2026-11-25: an empty drain writes nothing, an untouched writer finishes as an empty block" {
    const gpa = testing.allocator;
    var sink: Writer.Allocating = .init(gpa);
    defer sink.deinit();
    var small: [7]u8 = undefined;
    var aw = ArmorWriter.init(&sink.writer, &small);
    _ = try ArmorWriter.drain(&aw.writer, &.{""}, 1);
    try testing.expectEqual(@as(usize, 0), sink.written().len);
    try aw.finish();
    try testing.expectEqualStrings(age.armor_begin ++ "\n" ++ age.armor_end ++ "\n", sink.written());
}

test "mutation 2026-11-25: ArmorReader accepts a missing final newline and blanks after END, refuses everything else dearmor refuses" {
    const gpa = testing.allocator;
    var bin: [100]u8 = undefined;
    pattern(&bin);
    const arm = try armoredOf(gpa, &bin);
    defer gpa.free(arm);
    var lines: [6][]const u8 = undefined; // BEGIN, 64, 64, short, END, ""
    var it = std.mem.splitScalar(u8, arm, '\n');
    for (&lines) |*l| l.* = it.next().?;

    const long_line = try std.fmt.allocPrint(gpa, "{s}AAAA", .{lines[1]});
    defer gpa.free(long_line);
    const padded_64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const cases = [_]struct { name: []const u8, text: []const u8, ok: bool }{
        .{ .name = "no final newline", .text = try std.fmt.allocPrint(gpa, "{s}\n{s}\n{s}\n{s}\n{s}", .{ lines[0], lines[1], lines[2], lines[3], lines[4] }), .ok = true },
        .{ .name = "blanks after END", .text = try std.fmt.allocPrint(gpa, "{s}\n{s}\n{s}\n{s}\n{s}  \t\n \n", .{ lines[0], lines[1], lines[2], lines[3], lines[4] }), .ok = true },
        .{ .name = "garbage before BEGIN", .text = try std.fmt.allocPrint(gpa, "garbage\n{s}\n{s}\n{s}\n{s}\n", .{ lines[1], lines[2], lines[3], lines[4] }), .ok = false },
        .{ .name = "blank line in the body", .text = try std.fmt.allocPrint(gpa, "{s}\n{s}\n{s}\n\n{s}\n", .{ lines[0], lines[1], lines[2], lines[4] }), .ok = false },
        .{ .name = "over-long line", .text = try std.fmt.allocPrint(gpa, "{s}\n{s}\n{s}\n{s}\n{s}\n", .{ lines[0], long_line, lines[2], lines[3], lines[4] }), .ok = false },
        .{ .name = "padded full-width line then more", .text = try std.fmt.allocPrint(gpa, "{s}\n{s}\n{s}\n{s}\n", .{ lines[0], padded_64, lines[1], lines[4] }), .ok = false },
        .{ .name = "line after the short one", .text = try std.fmt.allocPrint(gpa, "{s}\n{s}\n{s}\n{s}\n{s}\n", .{ lines[0], lines[1], lines[3], lines[2], lines[4] }), .ok = false },
        .{ .name = "data after END", .text = try std.fmt.allocPrint(gpa, "{s}\n{s}\n{s}\n{s}\n{s}\nAAAA\n", .{ lines[0], lines[1], lines[2], lines[3], lines[4] }), .ok = false },
        .{ .name = "empty armor", .text = try std.fmt.allocPrint(gpa, "{s}\n{s}\n", .{ lines[0], lines[4] }), .ok = false },
    };
    defer for (cases) |c| gpa.free(c.text);
    for (cases) |c| {
        errdefer std.debug.print("case: {s}\n", .{c.name});
        if (c.ok) {
            const got = try readAll(gpa, c.text);
            defer gpa.free(got);
            try testing.expectEqualSlices(u8, &bin, got);
        } else {
            try testing.expectError(error.MalformedArmor, readAll(gpa, c.text));
        }
    }
}

test "mutation 2026-11-25: ArmorReader reports a line longer than its input buffer as MalformedArmor, and stays at the end after END" {
    const gpa = testing.allocator;
    var junk: [300]u8 = @splat('A');
    var src: Reader = .fixed(&junk);
    var lbuf: [72]u8 = undefined;
    var lim = src.limited(.unlimited, &lbuf);
    var rb: [8]u8 = undefined;
    var ar = ArmorReader.init(&lim.interface, &rb);
    try testing.expectError(error.ReadFailed, ar.reader.takeByte());
    try testing.expectEqual(@as(?age.ArmorError, error.MalformedArmor), ar.err);

    var bin: [100]u8 = undefined;
    pattern(&bin);
    const arm = try armoredOf(gpa, &bin);
    defer gpa.free(arm);
    var src2: Reader = .fixed(arm);
    var buf2: [5]u8 = undefined;
    var ar2 = ArmorReader.init(&src2, &buf2);
    var sink: Writer.Allocating = .init(gpa);
    defer sink.deinit();
    _ = try ar2.reader.streamRemaining(&sink.writer);
    try testing.expectError(error.EndOfStream, ar2.reader.takeByte());
    try testing.expectEqual(@as(?age.ArmorError, null), ar2.err);
}
