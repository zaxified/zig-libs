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

/// Default target chunk size (10 MiB). The buffer may grow above this when a
/// single record is longer than the target (no '\n' within the window).
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

    pub fn init(io: std.Io, alloc: std.mem.Allocator, file: std.Io.File, chunk_size: usize) !ChunkReader {
        const stat = try file.stat(io);
        return .{
            .io = io,
            .file = file,
            .buffer = std.array_list.Managed(u8).init(alloc),
            .chunk_size = if (chunk_size == 0) default_chunk_size else chunk_size,
            .last_emit_len = 0,
            .total_size = stat.size,
            .bytes_read = 0,
            .eof = false,
            .chunk_start_in_file = 0,
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
    lines: LineIterator,

    pub const Options = struct {
        /// Quoting char (0 disables quoting; '"' = RFC 4180).
        quote: u8 = '"',
        /// Target chunk size in bytes (0 = `default_chunk_size`).
        chunk_size: usize = default_chunk_size,
    };

    pub fn init(io: std.Io, alloc: std.mem.Allocator, file: std.Io.File, opts: Options) !StreamReader {
        return .{
            .chunks = try ChunkReader.init(io, alloc, file, opts.chunk_size),
            .quote = opts.quote,
            .lines = LineIterator.init("", opts.quote, 0),
        };
    }

    pub fn deinit(self: *StreamReader) void {
        self.chunks.deinit();
    }

    /// Returns the next CSV record with its absolute file byte offset, or null
    /// at EOF.
    pub fn next(self: *StreamReader) !?LineSlice {
        while (true) {
            if (self.lines.next()) |rec| return rec;
            const chunk = (try self.chunks.nextChunk()) orelse return null;
            self.lines = LineIterator.init(chunk, self.quote, self.chunks.chunk_start_in_file);
        }
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
        try t.expectEqualStrings(body[cr.chunk_start_in_file..][0..chunk.len], chunk);
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
        try t.expectEqualStrings(body[rec.byte_offset..][0..rec.bytes.len], rec.bytes);
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
