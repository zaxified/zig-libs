// SPDX-License-Identifier: MIT
//! `CsvChunkReader`: `read_csv` in chunks over a `std.Io.Reader`, in memory bounded by the
//! chunk and not by the input (pandas `read_csv(chunksize=n)` / `iterator=True` +
//! `get_chunk(n)`, polars `read_csv_batched` + `next_batches(n)`).
//!
//! This file has no CSV scanning of its own. Records are cut out of the stream with the
//! record scanner `readCsv` uses (csvstream's `SpanScanner`/`LineIterator`, configured by
//! `csvio.recordSpanConfig`), the next `n` of them are joined behind the header, and that
//! text goes through `readCsv` itself, so every cell, null marker, limit and option reads
//! exactly as in a whole-input read. What this file adds is what a stream needs on top:
//! the carried partial record at a read boundary, the schema that stays fixed from one
//! chunk to the next, and the counters that run across chunks (`n_rows`, `row_index_offset`,
//! `skip_rows_after_header`, the 1-based input line of a bad cell).

const std = @import("std");
const csvstream = @import("csvstream");
const csvio = @import("csvio.zig");
const frame_mod = @import("frame.zig");
const value = @import("value.zig");

const Frame = frame_mod.Frame;
const CsvReadOptions = csvio.CsvReadOptions;
const CsvReadError = csvio.CsvReadError;
const TypeOverride = csvio.TypeOverride;
const ColumnType = value.ColumnType;

/// How the column types are decided across chunks.
pub const ChunkSchema = enum {
    /// polars (`read_csv_batched` infers once, from `infer_schema_length` rows): the types
    /// are fixed from `CsvReadOptions.types` where given and inferred from the first
    /// `infer_rows` rows (default: the first chunk), then kept. A later cell that does not
    /// parse under them is `error.BadValue` (polars raises as well; see `ignore_errors`).
    first_chunk,
    /// pandas (`read_csv(chunksize=)`): each chunk is inferred on its own, so a column
    /// can be int in one chunk and float or text in the next, and a column that is all
    /// null in a chunk is text there. This is pandas' own behaviour, kept on purpose.
    per_chunk,
};

pub const ChunkOptions = struct {
    /// See `ChunkSchema`. Default: polars.
    schema: ChunkSchema = .first_chunk,
    /// `.first_chunk` only: rows the types are inferred from (polars `infer_schema_length`;
    /// 0 is `error.BadOptions`). `null` is the first chunk. The first chunk is still `n` rows:
    /// more than `n` makes the rows read ahead wait in memory for the next call, fewer makes
    /// the chunk's later rows be read under the types of the first `infer_rows` (and a cell that
    /// does not fit them `error.BadValue`, as in polars). Costs `max(n, infer_rows)` rows of
    /// memory, once.
    infer_rows: ?usize = null,
    /// A cell that does not parse under a fixed type becomes null instead of
    /// `error.BadValue` (polars `ignore_errors=True`). Needs a null marker to write the
    /// null with (`null_values`, `extra_null_values`, or one for that column); without one
    /// the cell stays an error. pandas has no such option (it raises, or falls back to text
    /// per chunk); a cell that is not in the category list of `enums` stays an error either way.
    ignore_errors: bool = false,
};

pub const ChunkError = CsvReadError || error{
    /// An option that needs the whole input: `skipfooter`. pandas' C engine refuses it
    /// with `chunksize` too (only the python engine reads it, and also not in chunks).
    UnsupportedOption,
};

/// A CSV stream read `n` rows at a time (pandas `chunksize`/`get_chunk`, polars
/// `next_batches`). Each call to `next` returns the next `n` data rows as a `Frame` and
/// `null` at the end; a stream with a header and no rows yields nothing (polars; pandas yields
/// one empty chunk with the header's columns). Every `CsvReadOptions` field means what it means for `readCsv`, with these
/// differences:
///
/// - `max_bytes` caps one chunk's record bytes (terminators not counted; and so the rows read
///   ahead), not the stream: a chunk past it is `error.InputTooLarge`, never a larger buffer.
///   It also bounds the read-ahead window, so a line with no end in sight (a record, a comment
///   or a `skip_rows` line) costs at most `max_bytes` of memory before `error.InputTooLarge`;
///   `max_record_bytes` is checked on each header and data record as read, as `readCsv` does;
/// - `max_rows`, `max_cells` apply to one chunk; `n_rows` to the whole stream;
/// - a newline as `delimiter` or `quote`, or `delimiter == quote`, is `error.BadOptions` (records are
///   rejoined with `\n` and re-quoted);
/// - `skipfooter` is `error.UnsupportedOption` (it needs the end of the input);
/// - `row_index_offset` continues from chunk to chunk;
/// - `bad_lines_skipped` receives the count over all chunks so far; a skipped record is
///   not one of the `n` rows of its chunk (pandas counts parsed rows too).
///
/// An error ends the reader's usefulness (the stream position is past the failure);
/// after `error.BadValue` `error_line` names the 1-based input line of the record, so
/// the caller can report it (polars' message names the row too).
///
/// The reader borrows the slices in `opts` (names, types, markers...): keep them alive.
pub const CsvChunkReader = struct {
    gpa: std.mem.Allocator,
    r: *std.Io.Reader,
    opts: CsvReadOptions,
    copts: ChunkOptions,
    /// Persistent small state (header text, schema), freed by `deinit`.
    state: std.heap.ArenaAllocator,

    // The record cutter: `win` holds stream bytes not yet turned into records;
    // `win[0..cut]` is the part cut at a record boundary, which `it` walks.
    win: std.ArrayList(u8) = .empty,
    cut: usize = 0,
    it: csvstream.LineIterator = csvstream.LineIterator.init("", 0, 0),
    /// 1-based input line of `win[0]`.
    line: u64 = 1,
    eof: bool = false,
    bom_done: bool = false,
    /// Window length at the last scan that found no record boundary (see `refill`).
    scanned: usize = 0,

    started: bool = false,
    width: usize = 0,
    /// The header text, `\n`-ended; the first `hdr_len` bytes of `buf`.
    hdr_len: usize = 0,
    /// Header text, then the queued data records each `\n`-ended; `ends` and `lines` hold,
    /// per record, where it ends and the input line it starts on.
    buf: std.ArrayList(u8) = .empty,
    ends: std.ArrayList(usize) = .empty,
    lines: std.ArrayList(u64) = .empty,
    /// A header-less file's first record, until it is queued.
    pending: ?[]const u8 = null,
    pending_line: u64 = 0,
    pending_unbalanced: bool = false,
    /// Scratch for a re-encoded record.
    enc: std.ArrayList(u8) = .empty,
    skip_left: usize = 0,
    /// Data rows handed out, and records dropped as bad lines.
    emitted: usize = 0,
    taken: usize = 0,
    bad: usize = 0,
    schema: ?[]const TypeOverride = null,
    /// The file's column names when `names` is not given (the header's, mangled as `readCsv`
    /// does, or `column_0`...); the options carry them to every chunk.
    gen_names: ?[]const []const u8 = null,

    /// After `error.BadValue`: the 1-based input line of the offending record (0: unknown).
    error_line: u64 = 0,

    /// `gpa` holds the reader's own state (the byte window, the queued records, the header,
    /// the schema); it is freed by `deinit` and never grows past a chunk and one record.
    /// `r` needs a buffer of at least one byte, as every `std.Io.Reader` has.
    pub fn init(gpa: std.mem.Allocator, r: *std.Io.Reader, opts: CsvReadOptions, copts: ChunkOptions) ChunkError!CsvChunkReader {
        if (opts.skipfooter != 0) return error.UnsupportedOption;
        // Records are rejoined with `\n`: a newline as delimiter or quote would read differently there.
        if (opts.delimiter == '\n' or opts.quote == '\n') return error.BadOptions;
        // A record that fell back to one line is stored re-quoted; with the quote byte also the
        // delimiter no quoting can tell its fields apart (fuzz seed 4996).
        if (opts.quote != 0 and opts.delimiter == opts.quote) return error.BadOptions;
        if (opts.bad_lines_skipped) |p| p.* = 0;
        return .{
            .gpa = gpa,
            .r = r,
            .opts = opts,
            .copts = copts,
            .state = std.heap.ArenaAllocator.init(gpa),
            .skip_left = opts.skip_rows_after_header,
        };
    }

    pub fn deinit(s: *CsvChunkReader) void {
        s.win.deinit(s.gpa);
        s.buf.deinit(s.gpa);
        s.ends.deinit(s.gpa);
        s.lines.deinit(s.gpa);
        s.enc.deinit(s.gpa);
        s.state.deinit();
    }

    /// The next `n` data rows (fewer at the end), or null when the stream is used up.
    /// The returned frame is owned by the caller and lives in `a`, as does everything `readCsv`
    /// needs on the way: pass an arena and reset it between chunks, that is what keeps the memory at one chunk.
    /// `n` of 0 is `error.BadOptions`.
    pub fn next(s: *CsvChunkReader, a: std.mem.Allocator, n: usize) ChunkError!?Frame {
        if (n == 0) return error.BadOptions;
        s.error_line = 0;
        try s.begin();
        const infer = s.copts.schema == .first_chunk and s.schema == null;
        const infer_n = if (infer) (s.copts.infer_rows orelse n) else n;
        if (infer_n == 0) return error.BadOptions;
        try s.fill(@max(n, infer_n));
        const queued = s.ends.items.len;
        if (queued == 0) return null;
        const take = @min(n, queued);
        var frame: Frame = undefined;
        if (infer) {
            const k = @min(infer_n, queued);
            if (k == take) {
                frame = try s.parse(a, take);
                s.schema = try s.schemaOf(frame);
            } else {
                // The types come from `k` rows, the chunk is `take` rows read under them.
                var tmp = std.heap.ArenaAllocator.init(s.gpa);
                defer tmp.deinit();
                const head = try s.parse(tmp.allocator(), k);
                s.schema = try s.schemaOf(head);
                frame = try s.parse(a, take);
            }
        } else frame = try s.parse(a, take);
        s.drop(take);
        s.emitted +%= take;
        return frame;
    }

    // ── what one `readCsv` call is given ────────────────────────────────────

    /// The options for one `readCsv` over `hdr ++ records`.
    fn chunkOptions(s: *CsvChunkReader, types: []const TypeOverride) CsvReadOptions {
        var o = s.opts;
        o.skip_rows = 0;
        o.skip_rows_after_header = 0;
        o.n_rows = null;
        o.has_header = true;
        o.types = types;
        o.bad_lines_skipped = null;
        o.row_index_offset = s.opts.row_index_offset +% @as(i64, @bitCast(@as(u64, s.emitted)));
        // A header-less file's names are `names` or the generated ones; every read checks them.
        o.names = s.opts.names orelse s.gen_names;
        // Bad lines were dropped while queueing.
        o.on_bad_lines = .@"error";
        // `max_bytes` is enforced on the stream itself (`begin` for the header, `fill` for each
        // chunk's records); the text handed to `readCsv` adds the header and the terminators
        // `appendRecord` writes, so the caller's cap applied to it would refuse an input the whole
        // read takes (fuzz seed 2422: a 3-byte header-only input at `max_bytes = 3`).
        o.max_bytes = std.math.maxInt(usize);
        // Likewise `max_record_bytes`: `nextData` checked each record as read, and a fallen-back
        // record stored re-quoted is longer than it was; under the cap the internal scan could
        // also fall back again inside the re-quoted text and cut it somewhere else.
        o.max_record_bytes = std.math.maxInt(usize);
        return o;
    }

    /// `types` for a chunk: the schema first, the caller's own entries after (they win).
    fn typesFor(s: *CsvChunkReader, a: std.mem.Allocator) std.mem.Allocator.Error![]const TypeOverride {
        const sch = s.schema orelse return s.opts.types;
        const out = try a.alloc(TypeOverride, sch.len + s.opts.types.len);
        @memcpy(out[0..sch.len], sch);
        @memcpy(out[sch.len..], s.opts.types);
        return out;
    }

    /// Reads the first `take` queued records as one `readCsv`.
    fn parse(s: *CsvChunkReader, a: std.mem.Allocator, take: usize) ChunkError!Frame {
        var scratch = std.heap.ArenaAllocator.init(s.gpa);
        defer scratch.deinit();
        const types = try s.typesFor(scratch.allocator());
        const co = s.chunkOptions(types);
        const end = s.ends.items[take - 1];
        if (csvio.readCsv(a, s.buf.items[0..end], co)) |f| return f else |e| {
            if (e != error.BadValue) return e;
        }
        if (s.copts.ignore_errors and try s.sanitize(take)) {
            const end2 = s.ends.items[take - 1];
            if (csvio.readCsv(a, s.buf.items[0..end2], co)) |f| return f else |e| {
                if (e != error.BadValue) return e;
            }
        }
        s.locateBadLine(co, take);
        return error.BadValue;
    }

    /// Sets `error_line` to the first of the first `take` records that does not read alone.
    fn locateBadLine(s: *CsvChunkReader, co: CsvReadOptions, take: usize) void {
        var arena = std.heap.ArenaAllocator.init(s.gpa);
        defer arena.deinit();
        // `one` is on `gpa`: the arena is reset every round, which would pull its buffer away.
        var one: std.ArrayList(u8) = .empty;
        defer one.deinit(s.gpa);
        var start = s.hdr_len;
        for (0..take) |i| {
            const end = s.ends.items[i];
            defer start = end;
            _ = arena.reset(.retain_capacity);
            one.clearRetainingCapacity();
            one.appendSlice(s.gpa, s.buf.items[0..s.hdr_len]) catch return;
            one.appendSlice(s.gpa, s.buf.items[start..end]) catch return;
            if (csvio.readCsv(arena.allocator(), one.items, co)) |_| {} else |e| {
                if (e == error.BadValue) {
                    s.error_line = s.lines.items[i];
                    return;
                }
            }
        }
    }

    /// The types of `f`'s columns that the caller did not fix: what later chunks are read as.
    fn schemaOf(s: *CsvChunkReader, f: Frame) std.mem.Allocator.Error![]const TypeOverride {
        const a = s.state.allocator();
        var out: std.ArrayList(TypeOverride) = .empty;
        cols: for (f.columns) |c| {
            if (s.opts.row_index_name) |rn| if (std.mem.eql(u8, rn, c.name)) continue;
            for (s.opts.types) |t| if (std.mem.eql(u8, t.name, c.name)) continue :cols;
            for (s.opts.enums) |e| if (std.mem.eql(u8, e.name, c.name)) continue :cols;
            try out.append(a, .{ .name = try a.dupe(u8, c.name), .type = c.type });
        }
        return out.items;
    }

    fn typeOfName(s: *const CsvChunkReader, name: []const u8) ?ColumnType {
        var ty: ?ColumnType = null;
        if (s.schema) |sch| for (sch) |t| if (std.mem.eql(u8, t.name, name)) {
            ty = t.type;
        };
        for (s.opts.types) |t| if (std.mem.eql(u8, t.name, name)) {
            ty = t.type;
        };
        return ty;
    }

    // ── ignore_errors ───────────────────────────────────────────────────────

    /// The marker a bad cell of column `name` is replaced by, if the options have one.
    fn nullMarker(s: *const CsvChunkReader, name: []const u8) ?[]const u8 {
        const o = &s.opts;
        if (!o.na_filter) return null;
        for (o.column_null_values) |c| if (std.mem.eql(u8, c.name, name) and c.values.len != 0) return c.values[0];
        for ([_][]const []const u8{ o.null_values, o.extra_null_values }) |list| {
            for (list) |m| if (m.len != 0 or o.empty_string_is_null) return m;
        }
        return null;
    }

    fn fileNames(s: *CsvChunkReader) ChunkError![]const []const u8 {
        return s.opts.names orelse s.gen_names.?;
    }

    /// Whether the cell `cell` of column `name` reads under `ty`: a one-cell `readCsv`
    /// with the chunk's cell rules.
    fn cellReads(s: *CsvChunkReader, scratch: std.mem.Allocator, name: []const u8, ty: ColumnType, cell: []const u8) ChunkError!bool {
        var o = s.opts;
        o.delimiter = ',';
        o.quote = '"';
        o.escape_char = 0;
        o.double_quote = true;
        o.skipinitialspace = false;
        o.comment = 0;
        o.skip_rows = 0;
        o.skip_rows_after_header = 0;
        o.n_rows = null;
        o.has_header = true;
        o.names = null;
        o.columns = null;
        o.enums = &.{};
        o.row_index_name = null;
        o.bad_lines_skipped = null;
        o.on_bad_lines = .@"error";
        o.truncate_ragged = false;
        o.max_quoted_lines = null;
        o.strict_quotes = true;
        // The probe text is longer than the cell (quotes doubled, header, terminators); the stream's
        // caps already passed the cell, so a cap here would fail the read instead of nulling it.
        o.max_bytes = std.math.maxInt(usize);
        o.max_record_bytes = std.math.maxInt(usize);
        const one_type = [_]TypeOverride{.{ .name = "c", .type = ty }};
        o.types = &one_type;
        var cn: []const csvio.ColumnNulls = &.{};
        for (s.opts.column_null_values) |c| if (std.mem.eql(u8, c.name, name)) {
            const e = try scratch.alloc(csvio.ColumnNulls, 1);
            e[0] = .{ .name = "c", .values = c.values };
            cn = e;
        };
        o.column_null_values = cn;
        var text: std.ArrayList(u8) = .empty;
        try text.appendSlice(scratch, "c\n\"");
        for (cell) |ch| {
            if (ch == '"') try text.append(scratch, '"');
            try text.append(scratch, ch);
        }
        try text.appendSlice(scratch, "\"\n");
        if (csvio.readCsv(scratch, text.items, o)) |_| return true else |e| switch (e) {
            error.BadValue => return false,
            else => return e,
        }
    }

    /// Rewrites the cells of the first `take` queued records that do not read under their
    /// column's type to a null marker. True when any record changed.
    fn sanitize(s: *CsvChunkReader, take: usize) ChunkError!bool {
        const names = try s.fileNames();
        var arena = std.heap.ArenaAllocator.init(s.gpa);
        defer arena.deinit();
        const sa = arena.allocator();
        var nb: std.ArrayList(u8) = .empty;
        var nends: std.ArrayList(usize) = .empty;
        try nb.appendSlice(sa, s.buf.items[0..s.hdr_len]);
        const fields = try sa.alloc([]const u8, s.width + 1);
        var changed = false;
        var start = s.hdr_len;
        var sp = csvio.recordSplitOptions(&s.opts);
        sp.on_overflow = .truncate;
        for (0..s.ends.items.len) |i| {
            const end = s.ends.items[i];
            defer start = end;
            const rec = storedRecord(s.buf.items[start..end]);
            var row_changed = false;
            var cells: []const []const u8 = &.{};
            if (i < take) {
                var rowa = std.heap.ArenaAllocator.init(s.gpa);
                defer rowa.deinit();
                if (csvstream.splitFieldsOpts(rec, fields, s.opts.delimiter, s.opts.quote, rowa.allocator(), sp)) |got| {
                    const out = try rowa.allocator().alloc([]const u8, got.len);
                    for (got, 0..) |cell, j| {
                        out[j] = cell;
                        if (j >= names.len) continue;
                        const ty = s.typeOfName(names[j]) orelse continue;
                        if (!try s.cellReads(sa, names[j], ty, cell)) {
                            out[j] = s.nullMarker(names[j]) orelse continue;
                            row_changed = true;
                        }
                    }
                    cells = out;
                    if (row_changed) {
                        var w: std.Io.Writer.Allocating = .init(sa);
                        const wo: csvstream.WriteOptions = .{
                            .delimiter = s.opts.delimiter,
                            .quote = s.opts.quote,
                            .escape = if (s.opts.double_quote) 0 else s.opts.escape_char,
                            .quote_style = .always,
                        };
                        for (cells, 0..) |c, j| {
                            if (j != 0) w.writer.writeByte(s.opts.delimiter) catch return error.OutOfMemory;
                            if (s.opts.quote == 0) w.writer.writeAll(c) catch return error.OutOfMemory else csvstream.writeField(&w.writer, c, wo) catch return error.OutOfMemory;
                        }
                        try appendRecord(&nb, sa, w.written());
                        changed = true;
                    }
                } else |_| {}
            }
            if (!row_changed) try nb.appendSlice(sa, s.buf.items[start..end]);
            try nends.append(sa, nb.items.len);
        }
        if (!changed) return false;
        s.buf.shrinkRetainingCapacity(0);
        try s.buf.appendSlice(s.gpa, nb.items);
        @memcpy(s.ends.items, nends.items);
        return true;
    }

    // ── the queue of records ────────────────────────────────────────────────

    /// Drops the first `k` queued records.
    fn drop(s: *CsvChunkReader, k: usize) void {
        const cutp = s.ends.items[k - 1];
        const tail = s.buf.items[cutp..];
        std.mem.copyForwards(u8, s.buf.items[s.hdr_len..][0..tail.len], tail);
        s.buf.shrinkRetainingCapacity(s.hdr_len + tail.len);
        const left = s.ends.items.len - k;
        for (0..left) |i| s.ends.items[i] = s.ends.items[i + k] - (cutp - s.hdr_len);
        s.ends.shrinkRetainingCapacity(left);
        std.mem.copyForwards(u64, s.lines.items[0..left], s.lines.items[k..]);
        s.lines.shrinkRetainingCapacity(left);
    }

    /// Queues data records until `target` are there, the stream or `n_rows` ends.
    fn fill(s: *CsvChunkReader, target: usize) ChunkError!void {
        while (s.ends.items.len < target) {
            if (s.opts.n_rows) |lim| if (s.taken >= lim) return;
            const rec = (try s.nextData()) orelse return;
            if (s.opts.max_rows <= s.taken -| s.emitted) return error.TooManyRows;
            // A fallen-back record is stored fully quoted: the text behind it in this chunk is not
            // the text behind it in the stream, and must not be able to close its open quote
            // (fuzz seed 3206). Any other record closes its own quotes, so it re-reads alone.
            // Reserve both queue slots first: an OOM after `buf` grew but before `ends` and `lines`
            // did would leave them out of step, and `drop`/`locateBadLine` would index past `lines`.
            try s.ends.ensureUnusedCapacity(s.gpa, 1);
            try s.lines.ensureUnusedCapacity(s.gpa, 1);
            try appendRecord(&s.buf, s.gpa, if (rec.unbalanced) try s.reencode(rec.bytes) else rec.bytes);
            // The cap is on the records' bytes, not on the terminators this file adds (seed 15628).
            if (s.buf.items.len - s.hdr_len - (s.ends.items.len + 1) > s.opts.max_bytes) return error.InputTooLarge;
            s.ends.appendAssumeCapacity(s.buf.items.len);
            s.lines.appendAssumeCapacity(rec.line);
            s.taken += 1;
        }
    }

    /// `rec` split as `readCsv` splits it and written with every field quoted.
    fn reencode(s: *CsvChunkReader, rec: []const u8) ChunkError![]const u8 {
        if (s.opts.quote == 0) return rec;
        var arena = std.heap.ArenaAllocator.init(s.gpa);
        defer arena.deinit();
        const aa = arena.allocator();
        const fields = try aa.alloc([]const u8, s.width + 1);
        var sp = csvio.recordSplitOptions(&s.opts);
        sp.on_overflow = .truncate;
        const got = csvstream.splitFieldsOpts(rec, fields, s.opts.delimiter, s.opts.quote, aa, sp) catch return rec;
        var w: std.Io.Writer.Allocating = .init(aa);
        const wo: csvstream.WriteOptions = .{
            .delimiter = s.opts.delimiter,
            .quote = s.opts.quote,
            .escape = if (s.opts.double_quote) 0 else s.opts.escape_char,
            .quote_style = .always,
        };
        for (got, 0..) |c, j| {
            if (j != 0) w.writer.writeByte(s.opts.delimiter) catch return error.OutOfMemory;
            csvstream.writeField(&w.writer, c, wo) catch return error.OutOfMemory;
        }
        s.enc.clearRetainingCapacity();
        try s.enc.appendSlice(s.gpa, w.written());
        return s.enc.items;
    }

    const Rec = struct { bytes: []const u8, line: u64, unbalanced: bool };

    /// The next data record: past the header and `skip_rows_after_header`, bad lines dropped
    /// (`on_bad_lines = .skip`).
    fn nextData(s: *CsvChunkReader) ChunkError!?Rec {
        while (true) {
            var rec: Rec = undefined;
            var unbalanced = false;
            if (s.pending) |p| {
                s.pending = null;
                unbalanced = s.pending_unbalanced;
                rec = .{ .bytes = p, .line = s.pending_line, .unbalanced = unbalanced };
            } else {
                const r = (try s.nextRecord()) orelse return null;
                unbalanced = r.unbalanced_quote;
                rec = .{ .bytes = r.bytes, .line = r.line_number, .unbalanced = unbalanced };
            }
            if (s.skip_left > 0) {
                s.skip_left -= 1;
                continue;
            }
            // A record that fell back to one line with its quote still open: `strict_quotes`
            // refuses it here, as the whole read does when it reaches the record.
            if (unbalanced and s.opts.strict_quotes) return error.UnterminatedQuote;
            // The record cap on the record as read (a re-quoted record is longer; see `chunkOptions`).
            if (rec.bytes.len > s.opts.max_record_bytes) return error.RecordTooLarge;
            if (s.opts.on_bad_lines == .skip and !s.opts.truncate_ragged) {
                const n = csvstream.countFieldsOpts(rec.bytes, s.opts.delimiter, s.opts.quote, csvio.recordSplitOptions(&s.opts));
                if (n > s.width) {
                    s.bad += 1;
                    if (s.opts.bad_lines_skipped) |p| p.* = s.bad;
                    continue;
                }
            }
            return rec;
        }
    }

    // ── the header ──────────────────────────────────────────────────────────

    fn begin(s: *CsvChunkReader) ChunkError!void {
        if (s.started) return;
        for (0..s.opts.skip_rows) |_| _ = (try s.nextRecord()) orelse return error.EmptyInput;
        const rec = (try s.nextRecord()) orelse return error.EmptyInput;
        if (s.opts.has_header and rec.bytes.len > s.opts.max_bytes) return error.InputTooLarge;
        s.width = csvstream.countFieldsOpts(rec.bytes, s.opts.delimiter, s.opts.quote, csvio.recordSplitOptions(&s.opts));
        if (s.width > s.opts.max_columns) return error.TooManyColumns;
        const st = s.state.allocator();
        if (s.opts.has_header) {
            // The names come from the header record read ALONE: a record that fell back to one
            // physical line (a quote that never closes) falls back at the end of this text just
            // as it did in the stream. It is never stored behind the chunk's own records, whose
            // text could close that quote (fuzz seed 3206). The stream's BOM is already gone, so
            // a BOM `readCsv` strips is put in front: a header that itself starts with one (a
            // doubled BOM) keeps it in its first name, as in the whole read (seed 135671).
            try s.buf.appendSlice(s.gpa, csvstream.utf8_bom);
            try appendRecord(&s.buf, s.gpa, rec.bytes);
            var o = s.opts;
            o.skip_rows = 0;
            o.skip_rows_after_header = 0;
            o.n_rows = null;
            o.columns = null;
            o.types = &.{};
            o.enums = &.{};
            o.row_index_name = null;
            o.column_null_values = &.{};
            o.bad_lines_skipped = null;
            o.on_bad_lines = .@"error";
            o.max_bytes = std.math.maxInt(usize);
            var tmp0 = std.heap.ArenaAllocator.init(s.gpa);
            defer tmp0.deinit();
            const hf = try csvio.readCsv(tmp0.allocator(), s.buf.items, o);
            const gen = try st.alloc([]const u8, hf.columns.len);
            for (gen, hf.columns) |*g, c| g.* = try st.dupe(u8, c.name);
            s.gen_names = gen;
            s.buf.clearRetainingCapacity();
        } else {
            // The first record is data.
            s.pending = try st.dupe(u8, rec.bytes);
            s.pending_line = rec.line_number;
            s.pending_unbalanced = rec.unbalanced_quote;
            if (s.opts.names) |nm| {
                if (nm.len != s.width) return error.BadNames;
            } else {
                const gen = try st.alloc([]const u8, s.width);
                for (gen, 0..) |*g, j| g.* = try std.fmt.allocPrint(st, "column_{d}", .{j});
                s.gen_names = gen;
            }
        }
        // The header text only gives the width (one filler byte per field); the names travel in
        // the options, so no quoting rule and no neighbouring record can disturb them.
        var filler: u8 = 'x';
        for ("xyzXYZ0123456789") |c| {
            if (c != s.opts.delimiter and c != s.opts.quote and c != s.opts.comment) {
                filler = c;
                break;
            }
        }
        for (0..s.width) |j| {
            if (j != 0) try s.buf.append(s.gpa, s.opts.delimiter);
            try s.buf.append(s.gpa, filler);
        }
        try s.buf.append(s.gpa, '\n');
        s.hdr_len = s.buf.items.len;
        s.started = true;
        // The header alone must read: the errors a whole read gives for it (a bad name list,
        // an option naming a missing column, a record that is too long) come out now.
        var tmp = std.heap.ArenaAllocator.init(s.gpa);
        defer tmp.deinit();
        _ = try csvio.readCsv(tmp.allocator(), s.buf.items[0..s.hdr_len], s.chunkOptions(s.opts.types));
    }

    // ── the record cutter ───────────────────────────────────────────────────

    /// Appends one record's content and a terminator that `readCsv` reads back as exactly that
    /// content: the line iterator drops one `\r` before a `\n` (CRLF), so content ending in
    /// `\r` gets `\r\n` (fuzz seed 542: a header name ending in `\r` lost it, and the fixed
    /// `types` then named a column the chunk did not have).
    fn appendRecord(list: *std.ArrayList(u8), a: std.mem.Allocator, content: []const u8) std.mem.Allocator.Error!void {
        try list.appendSlice(a, content);
        if (content.len > 0 and content[content.len - 1] == '\r') try list.append(a, '\r');
        try list.append(a, '\n');
    }

    /// The content `appendRecord` stored as `stored` (terminator included).
    fn storedRecord(stored: []const u8) []const u8 {
        var r = stored[0 .. stored.len - 1];
        if (r.len > 0 and r[r.len - 1] == '\r') r = r[0 .. r.len - 1];
        return r;
    }

    /// The next record (borrowed: valid until the next call), or null at the end.
    fn nextRecord(s: *CsvChunkReader) ChunkError!?csvstream.LineSlice {
        while (true) {
            if (s.it.next()) |rec| return rec;
            // Drained: drop what was cut, find the next run of whole records.
            if (s.cut > 0) {
                s.line = s.it.line;
                const rest = s.win.items.len - s.cut;
                std.mem.copyForwards(u8, s.win.items[0..rest], s.win.items[s.cut..]);
                s.win.shrinkRetainingCapacity(rest);
                s.cut = 0;
                s.scanned = 0;
            }
            if (!try s.refill()) return null;
        }
    }

    /// Cuts `win` at a record boundary (`cut`, `it`); reads more until it can. False at the end.
    fn refill(s: *CsvChunkReader) ChunkError!bool {
        // The window is capped by `max_bytes`, not `max_record_bytes`: it also holds comment lines
        // and `skip_rows` lines, which the whole read never measures against the record cap
        // (fuzz seed 23955), and a record's terminator and the quote look-ahead need a few bytes
        // past it (seed 5169). Whatever the window holds is part of the input, so a window past
        // `max_bytes` is an input the whole read refuses too. The record cap itself is checked on
        // each record's own bytes (`begin`, `nextData`), where `readCsv` checks it.
        const max_win = s.opts.max_bytes +| 8;
        while (true) {
            if (!s.bom_done and (s.win.items.len >= 3 or s.eof)) {
                s.bom_done = true;
                const bytes = csvstream.stripBom(s.win.items);
                const k = s.win.items.len - bytes.len;
                if (k != 0) {
                    std.mem.copyForwards(u8, s.win.items[0..bytes.len], bytes);
                    s.win.shrinkRetainingCapacity(bytes.len);
                }
            }
            if (s.bom_done and s.win.items.len > 0) {
                // Rescan only after the window grew by half since the last fruitless scan
                // (a record of M bytes read in small pieces then costs O(M), not O(M^2)),
                // and always at the cap and at the end.
                const due = s.eof or s.win.items.len >= max_win or s.win.items.len >= s.scanned + s.scanned / 2 + 1;
                if (due) {
                    const c = s.findCut();
                    if (c > 0) {
                        s.cut = c;
                        var it = csvio.recordIterator(s.win.items[0..c], &s.opts);
                        it.line = s.line;
                        s.it = it;
                        return true;
                    }
                    s.scanned = s.win.items.len;
                    if (!s.eof and s.win.items.len >= max_win) return error.InputTooLarge;
                }
            }
            if (s.eof) return false;
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

    /// One past the last whole record in `win` (all of it at the end of the stream), 0 for none.
    fn findCut(s: *CsvChunkReader) usize {
        const bytes = s.win.items;
        if (csvio.recordSpanConfig(&s.opts)) |cfg| {
            var scanner = csvstream.SpanScanner.init(s.opts.quote, cfg);
            var pos: usize = 0;
            while (pos < bytes.len) {
                switch (scanner.scan(bytes, pos, s.eof)) {
                    .incomplete => break,
                    .record => |rec| pos = rec.next,
                }
            }
            return pos;
        }
        if (s.eof) return bytes.len;
        return if (std.mem.findScalarLast(u8, bytes, '\n')) |i| i + 1 else 0;
    }
};
