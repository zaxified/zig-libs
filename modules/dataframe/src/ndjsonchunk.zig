// SPDX-License-Identifier: MIT
//! `NdjsonChunkReader`: newline-delimited JSON read `n` rows at a time from a `std.Io.Reader`,
//! in memory bounded by the chunk (pandas `read_json(lines=True, chunksize=n)`). Lines are cut
//! out of the stream here (a line is whatever ends at `\n`; the JSON inside is `readNdjson`'s
//! business), the next `n` non-blank ones go through `readNdjson` as one text, so every cell
//! reads exactly as in a whole-input read.
//!
//! polars has no public chunked ndjson reader (`read_ndjson` has `batch_size`, which only sizes
//! its internal batches, and `scan_ndjson` streams without handing out chunks), so pandas is the
//! engine followed. Like pandas, each chunk is typed on its own and has the keys that chunk
//! has: a key one chunk lacks is a column the next one may have, and a column can change type
//! between chunks. `JsonReadOptions.types` fixes a column's type in every chunk (a key it names
//! that a chunk lacks is `error.NoSuchColumn` there, as for a whole read).

const std = @import("std");
const jsonread = @import("jsonread.zig");
const frame_mod = @import("frame.zig");

const Frame = frame_mod.Frame;
const JsonReadOptions = jsonread.JsonReadOptions;
const JsonReadError = jsonread.JsonReadError;

pub const NdjsonChunkError = JsonReadError || error{ReadFailed};

/// Reads `n` non-blank lines per call. Every `JsonReadOptions` field means what it means for
/// `readNdjson`, with these differences: `max_bytes` caps one chunk's text and one line (not the
/// stream); `max_rows` and `max_cells` apply to one chunk; `n_rows` to the whole stream. The
/// reader borrows the slices in `opts`: keep them alive.
pub const NdjsonChunkReader = struct {
    gpa: std.mem.Allocator,
    r: *std.Io.Reader,
    opts: JsonReadOptions,
    /// Stream bytes not yet turned into lines.
    win: std.ArrayList(u8) = .empty,
    /// `win[0..pos]` is used up.
    pos: usize = 0,
    eof: bool = false,
    /// Non-blank lines handed out.
    taken: usize = 0,
    chunk: std.ArrayList(u8) = .empty,

    /// `gpa` holds the byte window and the chunk text (freed by `deinit`, bounded by
    /// `max_bytes`). `r` needs a buffer of at least one byte, as every `std.Io.Reader` has.
    pub fn init(gpa: std.mem.Allocator, r: *std.Io.Reader, opts: JsonReadOptions) NdjsonChunkReader {
        return .{ .gpa = gpa, .r = r, .opts = opts };
    }

    pub fn deinit(s: *NdjsonChunkReader) void {
        s.win.deinit(s.gpa);
        s.chunk.deinit(s.gpa);
    }

    /// The next `n` rows (fewer at the end) as a frame in `a`, or null when the stream is used
    /// up. Pass an arena and reset it between chunks. `n` of 0 is `error.BadShape`.
    pub fn next(s: *NdjsonChunkReader, a: std.mem.Allocator, n: usize) NdjsonChunkError!?Frame {
        if (n == 0) return error.BadShape;
        var want = n;
        if (s.opts.n_rows) |lim| want = @min(want, lim -| s.taken);
        if (want == 0) return null;
        s.chunk.clearRetainingCapacity();
        var got: usize = 0;
        var lines: usize = 0;
        while (got < want) {
            const line = (try s.nextLine()) orelse break;
            try s.chunk.appendSlice(s.gpa, line);
            try s.chunk.append(s.gpa, '\n');
            lines += 1;
            // The cap is on the lines' bytes, not on the terminators this file adds.
            if (s.chunk.items.len - lines > s.opts.max_bytes) return error.InputTooLarge;
            if (std.mem.trim(u8, line, " \t\r").len != 0) got += 1;
        }
        if (got == 0) return null;
        s.taken += got;
        var o = s.opts;
        o.n_rows = null;
        // Enforced above on the lines; the chunk text also holds the terminators added here.
        o.max_bytes = std.math.maxInt(usize);
        return try jsonread.readNdjson(a, s.chunk.items, o);
    }

    /// The next line without its `\n`, borrowed until the next call; null at the end.
    fn nextLine(s: *NdjsonChunkReader) NdjsonChunkError!?[]const u8 {
        var scanned: usize = 0;
        while (true) {
            if (std.mem.findScalarPos(u8, s.win.items, s.pos + scanned, '\n')) |i| {
                const line = s.win.items[s.pos..i];
                s.pos = i + 1;
                return line;
            }
            scanned = s.win.items.len - s.pos;
            if (s.eof) {
                if (s.pos >= s.win.items.len) return null;
                const line = s.win.items[s.pos..];
                s.pos = s.win.items.len;
                return line;
            }
            // Drop the used part before growing, so the window stays one line and one read.
            if (s.pos > 0) {
                const rest = s.win.items.len - s.pos;
                std.mem.copyForwards(u8, s.win.items[0..rest], s.win.items[s.pos..]);
                s.win.shrinkRetainingCapacity(rest);
                s.pos = 0;
            }
            if (s.win.items.len > s.opts.max_bytes) return error.InputTooLarge;
            s.r.fill(1) catch |e| switch (e) {
                error.EndOfStream => {
                    s.eof = true;
                    continue;
                },
                error.ReadFailed => return error.ReadFailed,
            };
            const got = s.r.buffered();
            try s.win.appendSlice(s.gpa, got);
            s.r.toss(got.len);
        }
    }
};
