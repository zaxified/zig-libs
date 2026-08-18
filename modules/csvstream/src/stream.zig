// SPDX-License-Identifier: MIT
//! Streaming layer: read a file (or any positional `std.Io.File`) in bounded
//! memory, yielding CSV records with their ABSOLUTE file byte offsets.
//!
//! `ChunkReader` slices a file into record-aligned chunks (each ending on the
//! last '\n' in its window) so peak memory is bounded by the chunk size, not
//! the file size. `StreamReader` composes `ChunkReader` with an in-memory
//! `LineIterator` per chunk so a caller pulls one record at a time and every
//! record carries `chunk_start_in_file + record_start_in_chunk` — the exact
//! source byte offset, so a consumer can seek back to the original bytes.
//!
//! Provenance: original work of the zig-libs authors (MIT).

const std = @import("std");
const line = @import("line.zig");

pub const LineSlice = line.LineSlice;
pub const LineIterator = line.LineIterator;

/// Default target chunk size (10 MiB), and the floor for a single record's
/// size cap. The buffer may grow above the target for a long record, but never
/// past `max_record_len` (see `ChunkReader.max_record_len`): a newline-free
/// input is rejected with `error.RecordTooLong` rather than buffering the whole
/// file.
pub const default_chunk_size: usize = 10 * 1024 * 1024;

/// Returns the index of the LAST '\n' in `bytes`, or null if there is none.
/// Every '\n' is a record boundary (no multi-line quoted fields — see
/// `LineIterator`), so this is just the last newline. This is what bounds chunk
/// memory: an unbalanced quote can no longer hide every newline and force the
/// buffer to grow without limit.
fn findLastBoundary(bytes: []const u8) ?usize {
    return std.mem.lastIndexOfScalar(u8, bytes, '\n');
}

/// Streaming file reader that yields chunks ending on record boundaries. Owns a
/// backing `buffer` that holds residual bytes between calls. The slice returned
/// by `nextChunk` is valid only until the next call.
pub const ChunkReader = struct {
    io: std.Io,
    file: std.Io.File,
    buffer: std.array_list.Managed(u8),
    /// Target chunk size; the read window per rotation. Configurable so tests
    /// (and memory-constrained callers) can force many small chunks.
    chunk_size: usize,
    /// Number of bytes returned by the previous nextChunk() call. Those bytes
    /// are discarded from the front of `buffer` at the start of the next call
    /// so only residual remains.
    last_emit_len: usize,
    /// Total file size (from stat at init); used to right-size the buffer so
    /// files smaller than `chunk_size` do not pay for a full allocation.
    total_size: u64,
    bytes_read: u64,
    eof: bool,
    /// File byte offset of `buffer.items[0]`. Incremented by `last_emit_len`
    /// whenever a previously returned chunk is dropped (at the start of
    /// `nextChunk`). Callers compute the absolute file offset of any returned
    /// byte as `byte_index_in_chunk + chunk_start_in_file`.
    chunk_start_in_file: u64,
    /// Hard cap on a single record (bytes accumulated with no '\n'). A
    /// newline-free input would otherwise grow `buffer` to the whole file size
    /// (memory DoS); once the buffer reaches this without a record boundary, a
    /// non-EOF read errors with `error.RecordTooLong`. Set to at least the
    /// target chunk size (and never below the 10 MiB default).
    max_record_len: usize,

    pub fn init(io: std.Io, alloc: std.mem.Allocator, file: std.Io.File, chunk_size: usize) !ChunkReader {
        const stat = try file.stat(io);
        const resolved_chunk = if (chunk_size == 0) default_chunk_size else chunk_size;
        return .{
            .io = io,
            .file = file,
            .buffer = std.array_list.Managed(u8).init(alloc),
            .chunk_size = resolved_chunk,
            .last_emit_len = 0,
            .total_size = stat.size,
            .bytes_read = 0,
            .eof = false,
            .chunk_start_in_file = 0,
            .max_record_len = @max(resolved_chunk, default_chunk_size),
        };
    }

    pub fn deinit(self: *ChunkReader) void {
        self.buffer.deinit();
    }

    /// Returns the next chunk of bytes ending at a record boundary (the last
    /// '\n' in the window). At EOF, returns the remaining bytes verbatim.
    /// Returns null when nothing is left.
    pub fn nextChunk(self: *ChunkReader) !?[]const u8 {
        // Drop bytes returned by the previous call so only residual remains.
        if (self.last_emit_len > 0) {
            const tail_len = self.buffer.items.len - self.last_emit_len;
            if (tail_len > 0) {
                std.mem.copyForwards(
                    u8,
                    self.buffer.items[0..tail_len],
                    self.buffer.items[self.last_emit_len..],
                );
            }
            self.buffer.items.len = tail_len;
            // The bytes that used to sit at buffer.items[0..last_emit_len] are
            // gone; the residual that shifted forward starts at the file offset
            // previously occupied by the dropped prefix.
            self.chunk_start_in_file += self.last_emit_len;
            self.last_emit_len = 0;
        }
        while (true) {
            if (findLastBoundary(self.buffer.items)) |boundary| {
                self.last_emit_len = boundary + 1;
                return self.buffer.items[0..self.last_emit_len];
            }
            if (self.eof) {
                if (self.buffer.items.len == 0) return null;
                self.last_emit_len = self.buffer.items.len;
                return self.buffer.items;
            }
            // Right-size the next read: never reserve more than what the file
            // still has to offer, so a tiny file caps the buffer at its size.
            const remaining: u64 = if (self.bytes_read >= self.total_size)
                0
            else
                self.total_size - self.bytes_read;
            if (remaining == 0) {
                self.eof = true;
                continue;
            }
            // Bound memory on a newline-free input: if we have already buffered a
            // whole record's worth (max_record_len) with no boundary and there is
            // still more file to read, the record is pathological — fail closed
            // instead of growing the buffer to the entire file size.
            if (self.buffer.items.len >= self.max_record_len) return error.RecordTooLong;
            const want_cap: usize = @intCast(@min(@as(u64, self.chunk_size), remaining));
            try self.buffer.ensureUnusedCapacity(want_cap);
            const dest = self.buffer.unusedCapacitySlice();
            const want = @min(dest.len, want_cap);
            // Positional read at the running file offset (`bytes_read`). Zig
            // 0.16 has no stateful `File.read`; positional reads also mean a
            // fresh ChunkReader starts at offset 0 with no seek.
            const n = try self.file.readPositionalAll(self.io, dest[0..want], self.bytes_read);
            self.buffer.items.len += n;
            self.bytes_read += n;
            if (n == 0) self.eof = true;
        }
    }
};

/// Unified streaming CSV reader: composes `ChunkReader` (file → record-aligned
/// chunks) with a per-chunk `LineIterator` (chunk → records). `next()` returns
/// one `LineSlice` at a time with an ABSOLUTE file byte offset, in bounded
/// memory regardless of file size.
///
/// Because chunks always end on a '\n', no record ever spans a chunk boundary,
/// so each chunk's iterator drains cleanly before the next chunk loads.
///
/// Borrow contract: the `bytes` of a returned `LineSlice` point into the
/// reader's internal buffer and stay valid only until the next `next()` call
/// that advances into a new chunk. Copy out anything you must retain.
pub const StreamReader = struct {
    chunks: ChunkReader,
    quote: u8,
    /// Field delimiter, threaded through to `nextFields`'s `splitFields` call.
    /// `next()` itself is delimiter-agnostic (it only returns whole-record
    /// bytes), so storing this here is purely for `nextFields` convenience —
    /// callers who split fields themselves may still pass any delimiter they
    /// like to `splitFields` directly.
    delimiter: u8,
    lines: LineIterator,
    /// Set once the first chunk has been inspected for a leading UTF-8 BOM
    /// (only the very first bytes of the whole stream can carry one).
    checked_bom: bool = false,

    pub const Options = struct {
        /// Quoting char (0 disables quoting; '"' = RFC 4180).
        quote: u8 = '"',
        /// Field delimiter, used by `nextFields` (see field doc).
        delimiter: u8 = ',',
        /// Target chunk size in bytes (0 = `default_chunk_size`).
        chunk_size: usize = default_chunk_size,
    };

    pub fn init(io: std.Io, alloc: std.mem.Allocator, file: std.Io.File, opts: Options) !StreamReader {
        return .{
            .chunks = try ChunkReader.init(io, alloc, file, opts.chunk_size),
            .quote = opts.quote,
            .delimiter = opts.delimiter,
            .lines = LineIterator.init("", opts.quote, 0),
        };
    }

    pub fn deinit(self: *StreamReader) void {
        self.chunks.deinit();
    }

    /// Returns the next CSV record with its absolute file byte offset, or null
    /// at EOF. A leading UTF-8 BOM on the very first chunk is detected and
    /// stripped before records are split out of it; the byte offset of the
    /// first record therefore starts right after the BOM, not at 0.
    pub fn next(self: *StreamReader) !?LineSlice {
        while (true) {
            if (self.lines.next()) |rec| return rec;
            const chunk = (try self.chunks.nextChunk()) orelse return null;
            var bytes = chunk;
            var base_offset = self.chunks.chunk_start_in_file;
            if (!self.checked_bom) {
                self.checked_bom = true;
                if (base_offset == 0) {
                    const without_bom = line.stripBom(chunk);
                    if (without_bom.len != chunk.len) {
                        bytes = without_bom;
                        base_offset += chunk.len - without_bom.len;
                    }
                }
            }
            self.lines = LineIterator.init(bytes, self.quote, base_offset);
        }
    }

    /// Convenience: `next()` followed by `splitFields` using the reader's
    /// configured `delimiter`/`quote`. Returns null at EOF. See `splitFields`
    /// for the `buf`/allocator contract (fields borrow the record's bytes
    /// except for escaped-quote fields, which are allocated from `alloc`) —
    /// the same borrow contract as `next()`'s `LineSlice.bytes` therefore
    /// applies transitively to the returned field slices.
    pub fn nextFields(self: *StreamReader, buf: [][]const u8, alloc: std.mem.Allocator) !?[][]const u8 {
        const rec = (try self.next()) orelse return null;
        return try line.splitFields(rec.bytes, buf, self.delimiter, self.quote, alloc);
    }
};

// ============================================================
// Tests
// ============================================================

const t = std.testing;

test "ChunkReader: residual + chunk_start_in_file bookkeeping" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const body = "a,1\nb,2\nc,3\n";
    try tmp.dir.writeFile(t.io, .{ .sub_path = "in.csv", .data = body });
    var f = try tmp.dir.openFile(t.io, "in.csv", .{});
    defer f.close(t.io);
    var cr = try ChunkReader.init(t.io, t.allocator, f, default_chunk_size);
    defer cr.deinit();
    // File is far below chunk_size, so the whole body comes back as one chunk
    // ending on its final '\n'; offset starts at 0.
    const c0 = (try cr.nextChunk()) orelse return error.TestUnexpectedResult;
    try t.expectEqualStrings(body, c0);
    try t.expectEqual(@as(u64, 0), cr.chunk_start_in_file);
    // Nothing left after the trailing newline.
    try t.expect((try cr.nextChunk()) == null);
}

test "ChunkReader: chunk_size 0 falls back to default_chunk_size, not a zero-length read" {
    // init's ternary (chunk_size == 0 -> default_chunk_size) was never
    // exercised — every existing test passes a nonzero chunk_size or the
    // named default constant directly. A dropped fallback silently reads
    // zero bytes per iteration and yields no records at all.
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const body = "a,1\nb,2\n";
    try tmp.dir.writeFile(t.io, .{ .sub_path = "in.csv", .data = body });
    var f = try tmp.dir.openFile(t.io, "in.csv", .{});
    defer f.close(t.io);
    var cr = try ChunkReader.init(t.io, t.allocator, f, 0);
    defer cr.deinit();
    try t.expectEqual(default_chunk_size, cr.chunk_size);
    const c0 = (try cr.nextChunk()) orelse return error.TestUnexpectedResult;
    try t.expectEqualStrings(body, c0);
}

test "ChunkReader: max_record_len floor tracks a configured chunk_size larger than the default" {
    // max_record_len = @max(resolved_chunk, default_chunk_size); every other
    // test uses a chunk_size well below the 10 MiB default, so the branch
    // where the CONFIGURED size wins the max (not the default) was dead.
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(t.io, .{ .sub_path = "in.csv", .data = "x\n" });
    var f = try tmp.dir.openFile(t.io, "in.csv", .{});
    defer f.close(t.io);
    const big: usize = default_chunk_size + 1024;
    var cr = try ChunkReader.init(t.io, t.allocator, f, big);
    defer cr.deinit();
    try t.expectEqual(big, cr.max_record_len);
}

test "ChunkReader: a newline-free record past max_record_len is rejected, not buffered unbounded (audit MED)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    // 32 bytes with no '\n': the old ChunkReader grew its buffer to the whole
    // file size (memory DoS). It must now fail closed once past max_record_len.
    const body = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    try tmp.dir.writeFile(t.io, .{ .sub_path = "in.csv", .data = body });
    var f = try tmp.dir.openFile(t.io, "in.csv", .{});
    defer f.close(t.io);
    var cr = try ChunkReader.init(t.io, t.allocator, f, 4);
    defer cr.deinit();
    cr.max_record_len = 8; // shrink the cap for a cheap test (production floor is 10 MiB)
    try t.expectError(error.RecordTooLong, cr.nextChunk());
}

test "ChunkReader: tiny chunk_size splits on record boundaries across many chunks" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const body = "aa,1\nbb,2\ncc,3\ndd,4\n"; // 4 records, 5 bytes each = 20 bytes
    try tmp.dir.writeFile(t.io, .{ .sub_path = "in.csv", .data = body });
    var f = try tmp.dir.openFile(t.io, "in.csv", .{});
    defer f.close(t.io);
    // chunk_size 6 → each window holds at most one 5-byte record boundary.
    var cr = try ChunkReader.init(t.io, t.allocator, f, 6);
    defer cr.deinit();
    var seen: usize = 0;
    var chunks: usize = 0;
    while (try cr.nextChunk()) |chunk| {
        // Every emitted chunk must end on a newline (or be the EOF remainder;
        // here the body ends in '\n' so all chunks end on it).
        try t.expectEqual(@as(u8, '\n'), chunk[chunk.len - 1]);
        // The chunk's bytes must equal the source at chunk_start_in_file.
        // `chunk_start_in_file` is `u64` deliberately (a real file offset can
        // exceed a 32-bit `usize`); this test slices a 20-byte in-memory
        // `body`, so the live value is always tiny and the narrowing cast is
        // safe here without changing the field's production type.
        try t.expectEqualStrings(body[@as(usize, @intCast(cr.chunk_start_in_file))..][0..chunk.len], chunk);
        seen += chunk.len;
        chunks += 1;
    }
    try t.expectEqual(body.len, seen);
    try t.expect(chunks >= 2); // proves multi-chunk streaming actually happened
}

test "StreamReader: records carry absolute file offsets across chunk boundaries" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const body = "aa,1\nbb,2\ncc,3\ndd,4\nee,5\n";
    try tmp.dir.writeFile(t.io, .{ .sub_path = "in.csv", .data = body });
    var f = try tmp.dir.openFile(t.io, "in.csv", .{});
    defer f.close(t.io);
    // Force many small chunks so records come from different chunks.
    var sr = try StreamReader.init(t.io, t.allocator, f, .{ .quote = '"', .chunk_size = 7 });
    defer sr.deinit();

    const expect = [_]struct { bytes: []const u8, off: u64 }{
        .{ .bytes = "aa,1", .off = 0 },
        .{ .bytes = "bb,2", .off = 5 },
        .{ .bytes = "cc,3", .off = 10 },
        .{ .bytes = "dd,4", .off = 15 },
        .{ .bytes = "ee,5", .off = 20 },
    };
    var crossed_chunk = false;
    for (expect) |e| {
        const rec = (try sr.next()) orelse return error.TestUnexpectedResult;
        try t.expectEqualStrings(e.bytes, rec.bytes);
        try t.expectEqual(e.off, rec.byte_offset);
        // THE POINT: the reported offset indexes the exact source bytes.
        // `byte_offset` is `u64` deliberately (a real file offset can exceed a
        // 32-bit `usize`), same as `chunk_start_in_file` above; this test
        // slices a 25-byte in-memory `body`, so the live value is always tiny
        // and the narrowing cast is safe without changing the field's
        // production type.
        try t.expectEqualStrings(body[@as(usize, @intCast(rec.byte_offset))..][0..rec.bytes.len], rec.bytes);
        if (rec.byte_offset >= 7) crossed_chunk = true;
    }
    try t.expect((try sr.next()) == null);
    try t.expect(crossed_chunk); // at least one record came from a later chunk

    // Prove seek-back works: re-open the file and positionally read the bytes
    // for record #3 ("cc,3") at its reported offset.
    var g = try tmp.dir.openFile(t.io, "in.csv", .{});
    defer g.close(t.io);
    var back: [4]u8 = undefined;
    const n = try g.readPositionalAll(t.io, &back, 10);
    try t.expectEqual(@as(usize, 4), n);
    try t.expectEqualStrings("cc,3", &back);
}

test "StreamReader: CRLF + quoted embedded delimiter over small chunks" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    // Second record has a quoted field with an embedded comma; CRLF endings.
    const body = "a,b\r\n\"x,y\",z\r\nc,d\r\n";
    try tmp.dir.writeFile(t.io, .{ .sub_path = "in.csv", .data = body });
    var f = try tmp.dir.openFile(t.io, "in.csv", .{});
    defer f.close(t.io);
    var sr = try StreamReader.init(t.io, t.allocator, f, .{ .chunk_size = 8 });
    defer sr.deinit();

    const r1 = (try sr.next()).?;
    try t.expectEqualStrings("a,b", r1.bytes); // CR stripped
    const r2 = (try sr.next()).?;
    try t.expectEqualStrings("\"x,y\",z", r2.bytes); // one record, comma protected
    try t.expect(!r2.unbalanced_quote);

    // Split the streamed record into fields with the in-memory splitter — do it
    // NOW, before advancing: the borrow contract says r2.bytes is only valid
    // until the next `next()` that crosses into a new chunk.
    var fbuf: [8][]const u8 = undefined;
    const fields = try line.splitFields(r2.bytes, &fbuf, ',', '"', t.allocator);
    try t.expectEqual(@as(usize, 2), fields.len);
    try t.expectEqualStrings("x,y", fields[0]);
    try t.expectEqualStrings("z", fields[1]);

    const r3 = (try sr.next()).?;
    try t.expectEqualStrings("c,d", r3.bytes);
    try t.expect((try sr.next()) == null);
}

test "StreamReader: empty file yields no records" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(t.io, .{ .sub_path = "empty.csv", .data = "" });
    var f = try tmp.dir.openFile(t.io, "empty.csv", .{});
    defer f.close(t.io);
    var sr = try StreamReader.init(t.io, t.allocator, f, .{});
    defer sr.deinit();
    try t.expect((try sr.next()) == null);
}

test "StreamReader: last record without trailing newline is still emitted" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const body = "a,1\nb,2\nc,3"; // no final '\n'
    try tmp.dir.writeFile(t.io, .{ .sub_path = "in.csv", .data = body });
    var f = try tmp.dir.openFile(t.io, "in.csv", .{});
    defer f.close(t.io);
    var sr = try StreamReader.init(t.io, t.allocator, f, .{ .chunk_size = 5 });
    defer sr.deinit();
    _ = (try sr.next()).?;
    _ = (try sr.next()).?;
    const r3 = (try sr.next()).?;
    try t.expectEqualStrings("c,3", r3.bytes);
    try t.expectEqual(@as(u64, 8), r3.byte_offset);
    try t.expect((try sr.next()) == null);
}

test "StreamReader: leading UTF-8 BOM is detected and stripped, offsets shift past it" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const body = "\xEF\xBB\xBFname,age\nalice,30\n";
    try tmp.dir.writeFile(t.io, .{ .sub_path = "bom.csv", .data = body });
    var f = try tmp.dir.openFile(t.io, "bom.csv", .{});
    defer f.close(t.io);
    var sr = try StreamReader.init(t.io, t.allocator, f, .{});
    defer sr.deinit();

    const r1 = (try sr.next()).?;
    try t.expectEqualStrings("name,age", r1.bytes); // no BOM bytes leaked in
    try t.expectEqual(@as(u64, 3), r1.byte_offset); // offset starts right after the 3-byte BOM
    const r2 = (try sr.next()).?;
    try t.expectEqualStrings("alice,30", r2.bytes);
    try t.expect((try sr.next()) == null);
}

test "StreamReader: no BOM present leaves the first record and offset untouched" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const body = "a,1\nb,2\n";
    try tmp.dir.writeFile(t.io, .{ .sub_path = "in.csv", .data = body });
    var f = try tmp.dir.openFile(t.io, "in.csv", .{});
    defer f.close(t.io);
    var sr = try StreamReader.init(t.io, t.allocator, f, .{});
    defer sr.deinit();
    const r1 = (try sr.next()).?;
    try t.expectEqualStrings("a,1", r1.bytes);
    try t.expectEqual(@as(u64, 0), r1.byte_offset);
}

test "StreamReader.nextFields: configured delimiter splits fields without the caller repeating it" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const body = "name;age\nalice;30\nbob;25\n";
    try tmp.dir.writeFile(t.io, .{ .sub_path = "semi.csv", .data = body });
    var f = try tmp.dir.openFile(t.io, "semi.csv", .{});
    defer f.close(t.io);
    var sr = try StreamReader.init(t.io, t.allocator, f, .{ .delimiter = ';' });
    defer sr.deinit();

    var buf: [8][]const u8 = undefined;
    const r1 = (try sr.nextFields(&buf, t.allocator)).?;
    try t.expectEqual(@as(usize, 2), r1.len);
    try t.expectEqualStrings("name", r1[0]);
    try t.expectEqualStrings("age", r1[1]);
    const r2 = (try sr.nextFields(&buf, t.allocator)).?;
    try t.expectEqualStrings("alice", r2[0]);
    try t.expectEqualStrings("30", r2[1]);
    const r3 = (try sr.nextFields(&buf, t.allocator)).?;
    try t.expectEqualStrings("bob", r3[0]);
    try t.expectEqualStrings("25", r3[1]);
    try t.expect((try sr.nextFields(&buf, t.allocator)) == null);
}

test "StreamReader.nextFields: default delimiter still splits on comma (non-breaking default)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const body = "a,b,c\n";
    try tmp.dir.writeFile(t.io, .{ .sub_path = "in.csv", .data = body });
    var f = try tmp.dir.openFile(t.io, "in.csv", .{});
    defer f.close(t.io);
    var sr = try StreamReader.init(t.io, t.allocator, f, .{});
    defer sr.deinit();
    var buf: [8][]const u8 = undefined;
    const fields = (try sr.nextFields(&buf, t.allocator)).?;
    try t.expectEqual(@as(usize, 3), fields.len);
    try t.expectEqualStrings("a", fields[0]);
    try t.expectEqualStrings("b", fields[1]);
    try t.expectEqualStrings("c", fields[2]);
}
