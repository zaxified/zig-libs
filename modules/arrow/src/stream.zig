// SPDX-License-Identifier: MIT

//! A whole `dataframe.Frame` to and from the Arrow IPC stream format: the type
//! mapping (wave A2) and the stream writer and reader (wave A3).
//!
//! Writer: one `Schema` message, one `DictionaryBatch` per dictionary-encoded
//! column (the whole dictionary, before any record batch), the rows in
//! `RecordBatch`es of `WriteOptions.rows_per_batch`, end of stream. The
//! DECLARED `ColumnType` picks the Arrow type; the cells are read through
//! `ColumnData.get`, so any storage that holds values of that type is written
//! (a `.float` column stored as ints, a `.categorical` stored as text). A cell
//! the declared type cannot hold, and `.boxed` storage, are
//! `error.Unsupported`.
//!
//! Reader: every batch of every column is decoded into one dataframe array; the
//! frame and everything in it is allocated from the caller's arena and borrows
//! nothing from the input. Every length, offset, index and buffer is checked:
//! a hostile stream is `error.Malformed` (or `Unsupported` / `LimitExceeded`),
//! never a crash.

const std = @import("std");
const df = @import("dataframe");
const fb = @import("fb.zig");
const schema = @import("schema.zig");
const ipc = @import("ipc.zig");
const zstd = @import("zstd");

const Allocator = std.mem.Allocator;
const Column = df.Column;
const ColumnType = df.ColumnType;
const ColumnData = df.ColumnData;
const Value = df.Value;

/// `InvalidUtf8`: a `.text` cell that is not UTF-8 on write (Arrow's Utf8 requires it, and
/// other readers refuse the file), or a Utf8 / LargeUtf8 value that is not on read (unless
/// `ReadOptions.validate_utf8` is off).
/// `UnknownColumn`: a `ReadOptions.columns` entry naming no field of the schema (or a name
/// two fields share), an index past the last field, or a column selected twice.
pub const Error = error{ OutOfMemory, Malformed, Unsupported, LimitExceeded, InvalidUtf8, UnknownColumn };

pub const WriteOptions = struct {
    /// Rows per `RecordBatch`; 0 writes the whole frame as one batch.
    rows_per_batch: usize = 1 << 16,
    /// A text or binary column (or dictionary) holding at least this many bytes is
    /// written as LargeUtf8 / LargeBinary (64-bit offsets). The default is where 32-bit
    /// offsets stop; 0 writes every one Large.
    large_from: u64 = 1 << 31,
    /// Body compression (`BodyCompression`, method BUFFER): every buffer of every record and
    /// dictionary batch compressed on its own, after an `int64` of its uncompressed length; a
    /// buffer that does not shrink is stored raw (length -1), as Arrow C++ and arrow-rs do.
    compression: Compression = .none,
    /// The zstd level (`zstd.Options.level`: 1..22, negative for the fast levels, 0 = zstd's
    /// default, 3).
    compression_level: i32 = 0,
    /// The schema's key/value metadata (`Schema.custom_metadata`: Pandas metadata,
    /// provenance tags), written as given.
    schema_metadata: []const KeyValue = &.{},
    /// Key/value metadata per column, by position: entry `i` goes on column `i`'s field,
    /// its `children` on the field's children in order (a list's item, a struct's fields).
    /// `name` is not looked at. More entries than columns is `error.Unsupported`; more
    /// `children` than the field has (a run-end encoded field's, read and written back
    /// plain) are dropped, the field's own metadata kept.
    field_metadata: []const FieldMetadata = &.{},
    /// The file footer's `custom_metadata` (`writeFile` only; a stream has no footer).
    footer_metadata: []const KeyValue = &.{},
};

/// One `KeyValue` of Arrow's custom metadata.
pub const KeyValue = schema.KeyValue;

/// A field's key/value metadata (`Field.custom_metadata`) and its children's, in field
/// order: what `ARROW:extension:name`, Pandas and provenance tags live in.
pub const FieldMetadata = struct {
    name: []const u8 = "",
    metadata: []const KeyValue = &.{},
    children: []const FieldMetadata = &.{},
};

/// The key/value metadata a read found, allocated from the read's arena (nothing borrows
/// the input): the schema's, each column's field (parallel to `Frame.columns`) with its
/// children, and a file footer's (empty for a stream).
pub const Metadata = struct {
    schema: []const KeyValue = &.{},
    fields: []const FieldMetadata = &.{},
    footer: []const KeyValue = &.{},
};

/// Body compression codecs the writer offers. LZ4_FRAME is read as `error.Unsupported`
/// until the collection has an LZ4 codec.
pub const Compression = enum { none, zstd };

pub const ReadOptions = struct {
    /// Most rows any one array of the stream may claim (frame rows summed over the
    /// batches, list elements, dictionary entries); past it `error.LimitExceeded`.
    /// Bounds the memory a small hostile stream can ask for where a length is not
    /// backed by bytes (a Null column, a list of nulls, a struct without fields).
    max_rows: u64 = 1 << 27,
    /// The most bytes the compressed message bodies of the WHOLE read may expand to: the
    /// uncompressed lengths every buffer of every record and dictionary batch declares,
    /// summed over the stream (or over every block of a file, which `openFile` inflates at
    /// once); past it `error.LimitExceeded`. Bounds what a small compressed input (zstd
    /// reaches ~32 000:1 on a run of one byte) can make the reader allocate.
    max_body_bytes: u64 = 1 << 31,
    /// The most array slots the whole read may decode: the length of every array — each
    /// column, each list's or fixed-size list's child, each struct field, each dictionary —
    /// summed over every batch, plus the rows a dictionary column copies out of its
    /// dictionary; past it `error.LimitExceeded`. `max_rows` bounds one array; this bounds
    /// their number times their length, which matters where rows cost no body bytes (a
    /// FixedSizeBinary(0) or FixedSizeList(0) column, a Null child): the reader spends up
    /// to ~16 bytes per slot on offsets and selectors. `File.readBatch` / `readAll` decode
    /// within what the file's metadata left of it, each call afresh.
    max_cells: u64 = 1 << 28,
    /// Utf8 / LargeUtf8 values (a categorical's dictionary included) must be UTF-8, as the
    /// format requires: `error.InvalidUtf8` otherwise (arrow-rs checks by default too).
    /// `false` skips the check for a trusted input; the frame may then hold text the
    /// writer refuses.
    validate_utf8: bool = true,
    /// A value `dataframe` cannot hold, or holds only inexactly, no longer fails the whole
    /// read with `error.Unsupported`:
    /// - read as a null cell: a Decimal128 that does not fit 12 fractional digits in an
    ///   i128, or with more digits than its declared precision; a time of day outside
    ///   `[0, 24h)` (Arrow allows 24:00:00); a date outside the years 0000-9999; a
    ///   timestamp or duration in s/ms whose microseconds overflow i64;
    /// - truncated toward zero: a nanosecond timestamp, duration or time with digits past
    ///   the microsecond (`dataframe` keeps microseconds);
    /// - floored to its calendar day: a Date64 that is not on a day boundary (-1 ms is
    ///   1969-12-31, the day that contains the instant);
    /// - a timestamp zone `dataframe`'s `tz` does not know reads as a naive column (the
    ///   instants are UTC either way; only the `time_zone` tag is dropped).
    /// Nothing else changes: a malformed stream is still an error.
    lossy: bool = false,
    /// When set, filled with the schema's, the fields' and (a file's) the footer's
    /// key/value metadata, allocated from the read's arena. `dataframe.Frame` has no
    /// slot for it, so it comes out here. Its bytes are charged against the schema
    /// decode budget like names (one long value behind many entries is `Malformed`).
    metadata: ?*Metadata = null,
    /// Column projection: only these top-level columns are decoded, in this order (the
    /// frame's columns, and `Metadata.fields`, follow it). A name must name exactly one
    /// field; an index counts the schema's fields from 0; a column may be selected once
    /// (`error.UnknownColumn` otherwise). The other columns' buffers are neither
    /// decompressed nor decoded, and their slots are not charged to `max_cells` (their
    /// metadata — node and buffer counts, lengths within `max_rows` — is still checked).
    /// A dictionary only unprojected columns use is skipped the same way: its batches'
    /// metadata is checked, its body is not read. `null` reads every column.
    columns: ?[]const ColumnRef = null,
};

/// A column picked by `ReadOptions.columns`: by field name or by position in the schema.
pub const ColumnRef = union(enum) { name: []const u8, index: usize };

/// A selector entry meaning "a null cell" (also what `ColumnData.get` reads past the end).
const none = std.math.maxInt(usize);
const us_per_day: i64 = 86_400 * df.timestamp_units_per_second;
const ms_per_day: i64 = 86_400_000;

/// The physical layouts both directions handle.
const Kind = enum { null_, i8, i16, i32, i64, u8, u16, u32, u64, f16, f32, f64, bool_, dec, date32, date64, time32, time64, ts, dur, var32, var64, fsb, dict, list32, list64, fsl, struct_, ree, view, lview32, lview64 };

// ── writer ──────────────────────────────────────────────────────────────────

const WField = struct {
    kind: Kind,
    ty: ColumnType,
    arrow: schema.Type,
    name: []const u8,
    data: ColumnData,
    width: u32 = 0,
    dict: ?usize = null,
    children: []WField = &.{},

    fn setInt(f: *WField, k: Kind, bits: u8, signed: bool) void {
        f.kind = k;
        f.arrow = .{ .int = .{ .bits = bits, .signed = signed } };
    }
};

const WDict = struct {
    ordered: bool,
    /// The dictionary's values: a text column, written as one DictionaryBatch.
    values: WField,
    len: usize,
    /// Set for a categorical column stored as text: each distinct text's code.
    lookup: ?std.StringHashMapUnmanaged(u32) = null,
};

const Writer = struct {
    gpa: Allocator,
    arena: Allocator,
    tmp: Allocator,
    opts: WriteOptions,
    dicts: std.ArrayList(WDict) = .empty,
    /// Set when `opts.compression` is `.zstd`; reused for every buffer.
    zc: ?zstd.Compressor = null,

    fn plan(w: *Writer, name: []const u8, decl: ?Column, data: ColumnData, rows: usize, depth: usize) Error!WField {
        if (depth >= schema.max_depth) return error.Unsupported;
        if (data == .boxed) return error.Unsupported; // no Arrow type short of a dense union
        const ty: ColumnType = if (decl) |d| d.type else storageType(data) orelse
            return .{ .kind = .null_, .ty = .text, .arrow = .null, .name = name, .data = data };
        var f: WField = .{ .kind = .null_, .ty = ty, .arrow = .null, .name = name, .data = data };
        switch (ty) {
            .int => f.setInt(.i64, 64, true),
            .int8 => f.setInt(.i8, 8, true),
            .int16 => f.setInt(.i16, 16, true),
            .int32 => f.setInt(.i32, 32, true),
            .uint8 => f.setInt(.u8, 8, false),
            .uint16 => f.setInt(.u16, 16, false),
            .uint32 => f.setInt(.u32, 32, false),
            .uint64 => f.setInt(.u64, 64, false),
            .float => {
                f.kind = .f64;
                f.arrow = .{ .float = .double };
            },
            .float32 => {
                f.kind = .f32;
                f.arrow = .{ .float = .single };
            },
            .bool => {
                f.kind = .bool_;
                f.arrow = .bool;
            },
            .decimal => {
                f.kind = .dec;
                f.arrow = .{ .decimal = .{ .precision = try decimalPrecision(data, rows), .scale = decimal_digits } };
            },
            .text, .binary => {
                const large = textBytes(data, rows) >= w.opts.large_from;
                f.kind = if (large) .var64 else .var32;
                f.arrow = if (ty == .text)
                    (if (large) .large_utf8 else .utf8)
                else
                    (if (large) .large_binary else .binary);
            },
            .date => {
                f.kind = .date32;
                f.arrow = .{ .date = .day };
            },
            .timestamp => {
                f.kind = .ts;
                f.arrow = .{ .timestamp = .{ .unit = .microsecond, .tz = if (decl) |d| d.time_zone else null } };
            },
            .duration => {
                f.kind = .dur;
                f.arrow = .{ .duration = .microsecond };
            },
            .time => {
                f.kind = .time64;
                f.arrow = .{ .time = .{ .unit = .microsecond, .bits = 64 } };
            },
            .categorical => return w.planDict(f, data, rows, depth),
            .list, .array => {
                if (data != .list and data != .nulls) return error.Unsupported;
                const inner: ?Column = if (decl) |d| (if (d.inner.len > 0) d.inner[0] else null) else null;
                const items: ColumnData = if (data == .list) data.list.items.* else .nulls;
                const kids = try w.arena.alloc(WField, 1);
                kids[0] = try w.plan("item", inner, items, items.storedLen() orelse 0, depth + 1);
                f.children = kids;
                if (ty == .list) {
                    f.kind = .list32;
                    f.arrow = .list;
                } else {
                    const width = if (decl) |d| d.array_width else 0;
                    if (width > std.math.maxInt(i32)) return error.Unsupported;
                    f.kind = .fsl;
                    f.width = width;
                    f.arrow = .{ .fixed_size_list = @intCast(width) };
                }
            },
            .@"struct" => {
                f.kind = .struct_;
                f.arrow = .@"struct";
                const inner: []const Column = if (decl) |d| d.inner else &.{};
                switch (data) {
                    .@"struct" => |sc| {
                        const kids = try w.arena.alloc(WField, sc.names.len);
                        for (kids, sc.names, 0..) |*k, n, i| {
                            const cd: ColumnData = if (i < sc.children.len) sc.children[i] else .nulls;
                            const cdecl: ?Column = if (i < inner.len and std.mem.eql(u8, inner[i].name, n)) inner[i] else null;
                            k.* = try w.plan(n, cdecl, cd, sc.len, depth + 1);
                        }
                        f.children = kids;
                    },
                    .nulls => {
                        const kids = try w.arena.alloc(WField, inner.len);
                        for (kids, inner) |*k, c| k.* = try w.plan(c.name, c, .nulls, 0, depth + 1);
                        f.children = kids;
                    },
                    else => return error.Unsupported,
                }
            },
        }
        return f;
    }

    fn planDict(w: *Writer, base: WField, data: ColumnData, rows: usize, depth: usize) Error!WField {
        var f = base;
        var wd: WDict = .{ .ordered = false, .values = undefined, .len = 0 };
        var dict: df.TextColumn = undefined;
        switch (data) {
            .categorical => |c| {
                dict = c.dict;
                wd.ordered = c.ordered;
                wd.len = c.dict.offsets.len -| 1;
            },
            else => {
                // Text storage under a categorical declaration: the distinct texts, lexically
                // ordered (what `dataframe` makes of a cast to categorical).
                var map: std.StringHashMapUnmanaged(u32) = .empty;
                var list: std.ArrayList([]const u8) = .empty;
                for (0..rows) |r| switch (data.get(r)) {
                    .null => {},
                    .text => |t| {
                        const gop = try map.getOrPut(w.arena, t);
                        if (!gop.found_existing) try list.append(w.arena, t);
                    },
                    else => return error.Unsupported,
                };
                std.mem.sort([]const u8, list.items, {}, lessText);
                const offs = try w.arena.alloc(usize, list.items.len + 1);
                var bytes: std.ArrayList(u8) = .empty;
                offs[0] = 0;
                for (list.items, 0..) |t, i| {
                    try bytes.appendSlice(w.arena, t);
                    offs[i + 1] = bytes.items.len;
                    map.getPtr(t).?.* = std.math.cast(u32, i) orelse return error.Unsupported;
                }
                dict = .{ .offsets = offs, .bytes = bytes.items };
                wd.len = list.items.len;
                wd.lookup = map;
            },
        }
        if (wd.len > std.math.maxInt(i32)) return error.Unsupported; // int32 indices
        wd.values = try w.plan("", .{ .name = "", .type = .text }, .{ .text = dict }, wd.len, depth);
        f.kind = .dict;
        f.arrow = wd.values.arrow;
        f.dict = w.dicts.items.len;
        try w.dicts.append(w.arena, wd);
        return f;
    }

    fn toField(w: *Writer, wf: *const WField, md: ?FieldMetadata) Error!schema.Field {
        var f: schema.Field = .{ .name = wf.name, .type = wf.arrow };
        if (wf.dict) |di| f.dictionary = .{ .id = @intCast(di), .ordered = w.dicts.items[di].ordered };
        // Metadata for more children than the field has (a run-end encoded field read, now
        // written plain without its two children) no longer has their shape: the children's
        // is dropped, the field's own kept.
        const kmd: []const FieldMetadata = if (md) |m| (if (m.children.len <= wf.children.len) m.children else &.{}) else &.{};
        if (md) |m| f.metadata = m.metadata;
        const kids = try w.arena.alloc(schema.Field, wf.children.len);
        for (kids, wf.children, 0..) |*k, *c, i| k.* = try w.toField(c, if (i < kmd.len) kmd[i] else null);
        f.children = kids;
        return f;
    }

    /// One message holding `fields` over the rows `sel` (a DictionaryBatch when `dict_id` is
    /// set); returns where it landed in `out`.
    fn emit(w: *Writer, out: *std.ArrayList(u8), fields: []const WField, sel: []const usize, dict_id: ?usize) Error!Block {
        const at = out.items.len;
        var bo: BatchOut = .{};
        defer bo.deinit(w.gpa);
        for (fields) |*f| try w.writeArray(&bo, f, sel);
        var packed_body: ipc.BodyBuilder = .{};
        defer packed_body.deinit(w.gpa);
        var codec: ?ipc.Codec = null;
        const bb: *const ipc.BodyBuilder = if (w.zc != null) blk: {
            try w.compressBody(&bo.body, &packed_body);
            codec = .zstd;
            break :blk &packed_body;
        } else &bo.body;
        var b = fb.Builder.init(w.gpa);
        defer b.deinit();
        const rb: ipc.RecordBatch = .{ .length = @intCast(sel.len), .nodes = bo.nodes.items, .buffers = bb.locs.items, .compression = codec };
        const body_len: i64 = @intCast(bb.bytes.items.len);
        const meta = if (dict_id) |id|
            try ipc.encodeDictionaryBatchMessage(&b, .{ .id = @intCast(id), .data = rb, .is_delta = false }, body_len)
        else
            try ipc.encodeRecordBatchMessage(&b, rb, body_len);
        try ipc.writeMessage(w.gpa, out, meta, bb.bytes.items);
        const body = bb.bytes.items.len;
        return .{ .offset = @intCast(at), .meta_len = @intCast(out.items.len - at - body), .body_len = @intCast(body) };
    }

    /// Every buffer of `src` zstd-compressed into `dst`, behind its uncompressed length as an
    /// `int64`; a buffer that would not shrink is stored raw behind -1, an absent one stays
    /// absent.
    fn compressBody(w: *Writer, src: *const ipc.BodyBuilder, dst: *ipc.BodyBuilder) Error!void {
        const zc = &w.zc.?;
        for (src.locs.items) |l| {
            const raw = src.bytes.items[@intCast(l.offset)..][0..@intCast(l.length)];
            if (raw.len == 0) {
                try dst.addEmpty(w.gpa);
                continue;
            }
            const buf = try w.tmp.alloc(u8, 8 + @max(raw.len, zstd.compressBound(raw.len)));
            const n = zc.compress(buf[8..], raw, .{ .level = w.opts.compression_level }) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.Unsupported, // a level zstd refuses
            };
            var len = 8 + n;
            if (n < raw.len) {
                std.mem.writeInt(i64, buf[0..8], @intCast(raw.len), .little);
            } else {
                std.mem.writeInt(i64, buf[0..8], -1, .little);
                @memcpy(buf[8..][0..raw.len], raw);
                len = 8 + raw.len;
            }
            try dst.add(w.gpa, buf[0..len]);
        }
    }

    fn pushNode(w: *Writer, bo: *BatchOut, n: usize, bits: Bits) Error!void {
        try bo.nodes.append(w.gpa, .{ .length = @intCast(n), .null_count = @intCast(bits.nulls) });
        if (bits.nulls == 0) try bo.body.addEmpty(w.gpa) else try bo.body.add(w.gpa, bits.bytes);
    }

    fn writeArray(w: *Writer, bo: *BatchOut, wf: *const WField, sel: []const usize) Error!void {
        const a = w.tmp;
        switch (wf.kind) {
            .null_ => try bo.nodes.append(w.gpa, .{ .length = @intCast(sel.len), .null_count = @intCast(sel.len) }),
            inline .i8, .i16, .i32, .i64, .u8, .u16, .u32, .u64, .f32, .f64, .dec, .date32, .time64, .ts, .dur => |k| {
                const T = RawOf(k);
                var bits = try Bits.init(a, sel.len);
                const bytes = try a.alloc(u8, sel.len * @sizeOf(T));
                for (sel, 0..) |row, i| {
                    const v = cellAt(wf.data, row);
                    const x: T = if (v == .null) 0 else try rawCell(k, v);
                    bits.set(i, v != .null);
                    putLe(T, bytes[i * @sizeOf(T) ..][0..@sizeOf(T)], x);
                }
                try w.pushNode(bo, sel.len, bits);
                try bo.body.add(w.gpa, bytes);
            },
            .bool_ => {
                var bits = try Bits.init(a, sel.len);
                var vals = try Bits.init(a, sel.len);
                for (sel, 0..) |row, i| {
                    const v = cellAt(wf.data, row);
                    bits.set(i, v != .null);
                    switch (v) {
                        .null => {},
                        .bool => |x| vals.set(i, x),
                        else => return error.Unsupported,
                    }
                }
                try w.pushNode(bo, sel.len, bits);
                try bo.body.add(w.gpa, vals.bytes);
            },
            .var32, .var64 => {
                const wide = wf.kind == .var64;
                var bits = try Bits.init(a, sel.len);
                const ow: usize = if (wide) 8 else 4;
                const offs = try a.alloc(u8, (sel.len + 1) * ow);
                var data: std.ArrayList(u8) = .empty;
                putOff(offs, 0, wide, 0);
                for (sel, 0..) |row, i| {
                    const v = cellAt(wf.data, row);
                    bits.set(i, v != .null);
                    switch (v) {
                        .null => {},
                        .text => |t| {
                            // Utf8 must hold UTF-8: other readers refuse the whole file otherwise.
                            if (wf.ty == .text and !std.unicode.utf8ValidateSlice(t)) return error.InvalidUtf8;
                            try data.appendSlice(a, t);
                        },
                        else => return error.Unsupported,
                    }
                    if (!wide and data.items.len > std.math.maxInt(i32)) return error.Unsupported;
                    putOff(offs, i + 1, wide, data.items.len);
                }
                try w.pushNode(bo, sel.len, bits);
                try bo.body.add(w.gpa, offs);
                try bo.body.add(w.gpa, data.items);
            },
            .dict => {
                const wd = &w.dicts.items[wf.dict.?];
                var bits = try Bits.init(a, sel.len);
                const bytes = try a.alloc(u8, sel.len * 4);
                for (sel, 0..) |row, i| {
                    const v = cellAt(wf.data, row);
                    bits.set(i, v != .null);
                    var code: u32 = 0;
                    if (v != .null) {
                        if (wd.lookup) |map| {
                            if (v != .text) return error.Unsupported;
                            code = map.get(v.text) orelse return error.Unsupported;
                        } else code = wf.data.categorical.codes.values[row]; // non-null: the row and its code are valid
                    }
                    std.mem.writeInt(u32, bytes[i * 4 ..][0..4], code, .little);
                }
                try w.pushNode(bo, sel.len, bits);
                try bo.body.add(w.gpa, bytes);
            },
            .list32, .fsl => {
                var bits = try Bits.init(a, sel.len);
                var kids: std.ArrayList(usize) = .empty;
                const is_fsl = wf.kind == .fsl;
                var offs: []u8 = &.{};
                if (!is_fsl) {
                    offs = try a.alloc(u8, (sel.len + 1) * 4);
                    putOff(offs, 0, false, 0);
                }
                for (sel, 0..) |row, i| {
                    const v = cellAt(wf.data, row);
                    bits.set(i, v != .null);
                    switch (v) {
                        .null => if (is_fsl) try kids.appendNTimes(a, none, wf.width),
                        .list => |lv| {
                            if (is_fsl and lv.len() != wf.width) return error.Unsupported;
                            var k: usize = lv.start;
                            while (k < lv.end) : (k += 1) try kids.append(a, k);
                        },
                        else => return error.Unsupported,
                    }
                    if (!is_fsl) {
                        if (kids.items.len > std.math.maxInt(i32)) return error.Unsupported;
                        putOff(offs, i + 1, false, kids.items.len);
                    }
                }
                try w.pushNode(bo, sel.len, bits);
                if (!is_fsl) try bo.body.add(w.gpa, offs);
                try w.writeArray(bo, &wf.children[0], kids.items);
            },
            .struct_ => {
                var bits = try Bits.init(a, sel.len);
                for (sel, 0..) |row, i| {
                    const v = cellAt(wf.data, row);
                    if (v != .null and v != .record) return error.Unsupported;
                    bits.set(i, v != .null);
                }
                try w.pushNode(bo, sel.len, bits);
                for (wf.children) |*c| try w.writeArray(bo, c, sel);
            },
            .f16, .date64, .time32, .fsb, .list64, .ree, .view, .lview32, .lview64 => return error.Unsupported, // never planned
        }
    }
};

const BatchOut = struct {
    nodes: std.ArrayList(ipc.FieldNode) = .empty,
    body: ipc.BodyBuilder = .{},

    fn deinit(bo: *BatchOut, gpa: Allocator) void {
        bo.nodes.deinit(gpa);
        bo.body.deinit(gpa);
    }
};

/// A bitmap being written (Arrow's LSB-first bit order), counting the clear bits.
const Bits = struct {
    bytes: []u8,
    nulls: usize = 0,

    fn init(a: Allocator, n: usize) Error!Bits {
        const b = try a.alloc(u8, (n + 7) / 8);
        @memset(b, 0);
        return .{ .bytes = b };
    }

    fn set(self: *Bits, i: usize, on: bool) void {
        if (on) self.bytes[i / 8] |= @as(u8, 1) << @as(u3, @truncate(i)) else self.nulls += 1;
    }
};

/// The 12 fractional digits of `dataframe`'s decimal (`df.decimal_scale`).
const decimal_digits = 12;

/// Decimal128 holds at most 38 digits.
const max_precision = 38;

/// 10^k for k in 0..38 (10^38 still fits a u128).
const pow10 = blk: {
    var t: [max_precision + 1]u128 = undefined;
    t[0] = 1;
    for (1..t.len) |i| t[i] = t[i - 1] * 10;
    break :blk t;
};

/// 10^k for k in 0..76: the precisions of Decimal256 (10^76 still fits a u256).
const pow10_256 = blk: {
    @setEvalBranchQuota(10_000);
    var t: [77]u256 = undefined;
    t[0] = 1;
    for (1..t.len) |i| t[i] = t[i - 1] * 10;
    break :blk t;
};

/// Digits of |x| (1 for 0); 39 for anything Decimal128 cannot hold.
fn digitCount(x: i128) i32 {
    const u = @abs(x);
    var n: usize = 1;
    while (n <= max_precision and u >= pow10[n]) n += 1;
    return @intCast(n);
}

/// The precision a decimal column is written with: the digits of its widest value, at
/// least the scale (so scale <= precision, which some readers require); a value of more
/// than 38 digits has no Decimal128 form (`Unsupported`).
fn decimalPrecision(data: ColumnData, rows: usize) Error!i32 {
    var p: i32 = decimal_digits;
    for (0..rows) |r| switch (data.get(r)) {
        .decimal => |x| {
            const d = digitCount(x);
            if (d > max_precision) return error.Unsupported;
            p = @max(p, d);
        },
        else => {},
    };
    return p;
}

fn storageType(data: ColumnData) ?ColumnType {
    return switch (data) {
        .nulls, .boxed => null,
        .int => .int,
        .float => .float,
        .bool => .bool,
        .decimal => .decimal,
        .text => .text,
        .categorical => .categorical,
        .list => .list,
        .@"struct" => .@"struct",
        .int8 => .int8,
        .int16 => .int16,
        .int32 => .int32,
        .uint8 => .uint8,
        .uint16 => .uint16,
        .uint32 => .uint32,
        .uint64 => .uint64,
        .float32 => .float32,
    };
}

fn textBytes(data: ColumnData, rows: usize) u64 {
    var n: u64 = 0;
    for (0..rows) |r| switch (data.get(r)) {
        .text => |t| n += t.len,
        else => {},
    };
    return n;
}

fn lessText(_: void, x: []const u8, y: []const u8) bool {
    return std.mem.order(u8, x, y) == .lt;
}

fn cellAt(data: ColumnData, row: usize) Value {
    return if (row == none) .null else data.get(row);
}

fn RawOf(comptime k: Kind) type {
    return switch (k) {
        .i8 => i8,
        .i16 => i16,
        .i32, .date32, .time32 => i32,
        .i64, .ts, .dur, .time64, .date64 => i64,
        .u8 => u8,
        .u16 => u16,
        .u32 => u32,
        .u64 => u64,
        .f16 => f16,
        .f32 => f32,
        .f64 => f64,
        .dec => i128,
        else => @compileError("no fixed-width raw type"),
    };
}

fn intCell(comptime T: type, v: Value) Error!T {
    return switch (v) {
        .int => |x| std.math.cast(T, x) orelse error.Unsupported,
        .uint => |x| std.math.cast(T, x) orelse error.Unsupported,
        else => error.Unsupported,
    };
}

/// A non-null cell as the raw value of layout `k`; a cell the type cannot hold is `Unsupported`.
fn rawCell(comptime k: Kind, v: Value) Error!RawOf(k) {
    return switch (k) {
        .f64 => switch (v) {
            .float => |x| x,
            .int => |x| @floatFromInt(x),
            else => error.Unsupported,
        },
        .f32 => switch (v) {
            .float => |x| @floatCast(x),
            .int => |x| @floatFromInt(x),
            else => error.Unsupported,
        },
        .dec => switch (v) {
            .decimal => |x| x,
            else => error.Unsupported,
        },
        .date32 => switch (v) {
            .text => |t| blk: {
                const d = df.parseIsoDate(t) orelse return error.Unsupported;
                break :blk std.math.cast(i32, d.ordinal()) orelse error.Unsupported;
            },
            else => error.Unsupported,
        },
        .time64 => blk: {
            const x = try intCell(i64, v);
            if (x < 0 or x >= us_per_day) return error.Unsupported;
            break :blk x;
        },
        else => intCell(RawOf(k), v),
    };
}

fn putLe(comptime T: type, dst: *[@sizeOf(T)]u8, x: T) void {
    const U = @Int(.unsigned, @bitSizeOf(T));
    std.mem.writeInt(U, dst, @bitCast(x), .little);
}

fn getLe(comptime T: type, src: *const [@sizeOf(T)]u8) T {
    const U = @Int(.unsigned, @bitSizeOf(T));
    return @bitCast(std.mem.readInt(U, src, .little));
}

fn putOff(offs: []u8, i: usize, wide: bool, v: usize) void {
    if (wide) std.mem.writeInt(i64, offs[i * 8 ..][0..8], @intCast(v), .little) else std.mem.writeInt(i32, offs[i * 4 ..][0..4], @intCast(v), .little);
}

/// The frame as an Arrow IPC stream (caller frees with `gpa`).
pub fn writeStream(gpa: Allocator, f: df.Frame, opts: WriteOptions) Error![]u8 {
    return write(gpa, f, opts, false);
}

/// The frame as an Arrow IPC file (`ARROW1`, the stream, a footer locating every
/// dictionary and record batch); caller frees with `gpa`.
pub fn writeFile(gpa: Allocator, f: df.Frame, opts: WriteOptions) Error![]u8 {
    return write(gpa, f, opts, true);
}

const magic = "ARROW1";

/// A message's place in a file (`File.fbs` `Block`): `meta_len` counts the framing
/// prefix and the padded metadata.
const Block = struct { offset: i64, meta_len: i32, body_len: i64 };

fn write(gpa: Allocator, f: df.Frame, opts: WriteOptions, file: bool) Error![]u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var tmp_state = std.heap.ArenaAllocator.init(gpa);
    defer tmp_state.deinit();
    var w: Writer = .{ .gpa = gpa, .arena = arena_state.allocator(), .tmp = tmp_state.allocator(), .opts = opts };
    if (opts.compression == .zstd) w.zc = zstd.Compressor.init(gpa);
    defer if (w.zc) |*c| c.deinit();

    const fields = try w.arena.alloc(WField, f.columns.len);
    for (fields, f.columns, 0..) |*wf, c, ci| wf.* = try w.plan(c.name, c, f.columnAt(ci), f.len, 0);
    if (opts.field_metadata.len > fields.len) return error.Unsupported; // metadata for columns the frame has not
    const sfields = try w.arena.alloc(schema.Field, fields.len);
    for (sfields, fields, 0..) |*s, *wf, i| s.* = try w.toField(wf, if (i < opts.field_metadata.len) opts.field_metadata[i] else null);
    const sch: schema.Schema = .{ .fields = sfields, .metadata = opts.schema_metadata };

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    if (file) try out.appendSlice(gpa, magic ++ "\x00\x00");
    {
        var b = fb.Builder.init(gpa);
        defer b.deinit();
        try ipc.writeMessage(gpa, &out, try schema.encodeSchemaMessage(&b, sch), &.{});
    }
    var dict_blocks: std.ArrayList(Block) = .empty;
    var batch_blocks: std.ArrayList(Block) = .empty;
    for (w.dicts.items, 0..) |*d, id| {
        try dict_blocks.append(w.arena, try w.emit(&out, (&d.values)[0..1], try iota(w.tmp, 0, d.len), id));
        _ = tmp_state.reset(.retain_capacity);
    }
    const per = if (opts.rows_per_batch == 0) f.len else opts.rows_per_batch;
    var start: usize = 0;
    while (start < f.len) {
        const end = start + @min(per, f.len - start);
        try batch_blocks.append(w.arena, try w.emit(&out, fields, try iota(w.tmp, start, end), null));
        _ = tmp_state.reset(.retain_capacity);
        start = end;
    }
    try ipc.writeEos(gpa, &out);
    if (file) {
        var b = fb.Builder.init(gpa);
        defer b.deinit();
        const sref = try schema.encodeSchema(&b, sch);
        const dv = try blockVector(&b, w.tmp, dict_blocks.items);
        const rv = try blockVector(&b, w.tmp, batch_blocks.items);
        const fmd = try schema.encodeKeyValues(&b, opts.footer_metadata);
        b.startTable();
        try b.addScalarForce(0, schema.MetadataVersion, .v5);
        try b.addOffset(1, sref);
        try b.addOffset(2, dv);
        try b.addOffset(3, rv);
        if (fmd) |m| try b.addOffset(4, m);
        const footer = try b.finish(try b.endTable());
        const flen = std.math.cast(i32, footer.len) orelse return error.Unsupported;
        try out.appendSlice(gpa, footer);
        try out.appendSlice(gpa, &std.mem.toBytes(std.mem.nativeToLittle(i32, flen)));
        try out.appendSlice(gpa, magic);
    }
    return out.toOwnedSlice(gpa);
}

fn blockVector(b: *fb.Builder, a: Allocator, blocks: []const Block) Error!fb.Ref {
    const bytes = try a.alloc(u8, blocks.len * 24);
    @memset(bytes, 0);
    for (blocks, 0..) |x, i| {
        std.mem.writeInt(i64, bytes[i * 24 ..][0..8], x.offset, .little);
        std.mem.writeInt(i32, bytes[i * 24 + 8 ..][0..4], x.meta_len, .little);
        std.mem.writeInt(i64, bytes[i * 24 + 16 ..][0..8], x.body_len, .little);
    }
    return b.createStructVector(bytes, 24, 8);
}

fn iota(a: Allocator, start: usize, end: usize) Error![]usize {
    const s = try a.alloc(usize, end - start);
    for (s, start..) |*x, i| x.* = i;
    return s;
}

// ── reader ──────────────────────────────────────────────────────────────────

/// One batch ready to decode: its fixed buffers in schema order (`rb.buffers`, one set
/// per field as `plan` counted them) and, per view-typed field, its variadic data
/// buffers (`variadic[RField.view]`), all located in `body`.
const Chunk = struct { rb: ipc.RecordBatch, body: []const u8, variadic: []const []const ipc.BufferLoc = &.{} };

const RField = struct {
    kind: Kind,
    col: Column,
    node_ix: usize,
    buf_ix: usize,
    unit: schema.TimeUnit = .microsecond,
    /// FixedSizeBinary width, FixedSizeList size.
    width: usize = 0,
    /// Decimal scale, precision and width (32, 64, 128 or 256 bits).
    scale: i32 = 0,
    precision: i32 = max_precision,
    dec_bits: u16 = 128,
    /// Dictionary index type.
    index: schema.IntType = .{ .bits = 32, .signed = true },
    /// A view-typed field's ordinal among its message's view fields (`Chunk.variadic`).
    view: usize = 0,
    children: []RField = &.{},
    dict: ?*RDict = null,
};

const RDict = struct {
    id: i64,
    /// The schema field that declared it (without its dictionary encoding): a second field
    /// sharing the id must have the same value type.
    field: schema.Field,
    value: RField,
    /// The nodes, buffers and view fields a DictionaryBatch of it has.
    ctr: Counter,
    ordered: bool,
    categorical: bool,
    chunks: std.ArrayList(Chunk) = .empty,
    data: ColumnData = .nulls,
    len: usize = 0,
    /// Batches seen (a second non-delta one is a replacement).
    batches: usize = 0,
    /// Whether a projected column reads it; an unused dictionary's bodies are not read.
    used: bool = true,
};

/// What a message's metadata must hold for a schema: nodes, fixed buffers, and for each
/// BinaryView / Utf8View field in pre-order the index of its views buffer (its variadic
/// data buffers follow that buffer in the message).
const Counter = struct { nodes: usize = 0, bufs: usize = 0, views: std.ArrayList(usize) = .empty };

const Reader = struct {
    a: Allocator,
    opts: ReadOptions,
    dicts: std.ArrayList(*RDict) = .empty,
    by_id: std.AutoHashMapUnmanaged(i64, *RDict) = .empty,
    /// Made at the first zstd-compressed buffer (its tables come from the arena).
    zd: ?zstd.Decompressor = null,
    /// Bytes inflated so far, against `ReadOptions.max_body_bytes`.
    inflated: u64 = 0,
    /// Array slots so far, against `ReadOptions.max_cells`.
    cells: u64 = 0,

    /// Counts `n` array slots against `ReadOptions.max_cells`.
    fn charge(r: *Reader, n: u64) Error!void {
        r.cells +|= n;
        if (r.cells > r.opts.max_cells) return error.LimitExceeded;
    }

    /// Whether `n` more slots fit `ReadOptions.max_cells` (checked before allocating for
    /// work that `gather` charges after).
    fn afford(r: *const Reader, n: u64) Error!void {
        if (r.cells +| n > r.opts.max_cells) return error.LimitExceeded;
    }

    fn plan(r: *Reader, f: schema.Field, ctr: *Counter, depth: usize, in_dict: bool) Error!RField {
        if (depth >= schema.max_depth) return error.Malformed;
        var rf: RField = .{ .kind = .null_, .col = .{ .name = try r.a.dupe(u8, f.name), .type = .text }, .node_ix = ctr.nodes, .buf_ix = ctr.bufs };
        ctr.nodes += 1;
        if (f.dictionary) |d| {
            if (in_dict) return error.Unsupported; // a dictionary inside a dictionary's values
            ctr.bufs += 2;
            rf.kind = .dict;
            rf.index = d.index;
            var vf = f;
            vf.dictionary = null;
            if (r.by_id.get(d.id)) |rd| {
                // Two fields sharing one dictionary, which Arrow allows: their value types
                // must agree (each field keeps its own index type).
                if (!sameValueType(rd.field, vf)) return error.Malformed;
                if (rd.ordered != d.ordered) return error.Unsupported; // one dictionary, two orders
                rf.dict = rd;
                rf.col = rd.value.col;
                rf.col.name = try r.a.dupe(u8, f.name);
                if (rd.categorical) rf.col.type = .categorical;
                return rf;
            }
            var vctr: Counter = .{};
            const rd = try r.a.create(RDict);
            rd.* = .{
                .id = d.id,
                .field = vf,
                .value = try r.plan(vf, &vctr, depth, true),
                .ctr = vctr,
                .ordered = d.ordered,
                .categorical = vf.type == .utf8 or vf.type == .large_utf8 or vf.type == .utf8_view,
            };
            try r.dicts.append(r.a, rd);
            try r.by_id.put(r.a, d.id, rd);
            rf.dict = rd;
            rf.col = rd.value.col;
            if (rd.categorical) rf.col.type = .categorical;
            return rf;
        }
        var bufs: usize = 2;
        switch (f.type) {
            .null => {
                bufs = 0;
                rf.kind = .null_;
            },
            .int => |it| {
                const map: struct { Kind, ColumnType } = switch (it.bits) {
                    8 => if (it.signed) .{ .i8, .int8 } else .{ .u8, .uint8 },
                    16 => if (it.signed) .{ .i16, .int16 } else .{ .u16, .uint16 },
                    32 => if (it.signed) .{ .i32, .int32 } else .{ .u32, .uint32 },
                    64 => if (it.signed) .{ .i64, .int } else .{ .u64, .uint64 },
                    else => return error.Malformed,
                };
                rf.kind = map[0];
                rf.col.type = map[1];
            },
            .float => |p| {
                rf.kind = switch (p) {
                    .half => .f16,
                    .single => .f32,
                    .double => .f64,
                };
                rf.col.type = if (p == .double) .float else .float32;
            },
            .bool => {
                rf.kind = .bool_;
                rf.col.type = .bool;
            },
            .decimal => |d| {
                // The precisions each width can hold (Decimal32 9 digits, Decimal64 18,
                // Decimal128 38, Decimal256 76); the schema decoder admits only these widths.
                const most: i32 = switch (d.bits) {
                    32 => 9,
                    64 => 18,
                    128 => max_precision,
                    256 => 76,
                    else => return error.Malformed,
                };
                if (d.precision < 1 or d.precision > most) return error.Malformed;
                rf.kind = .dec;
                rf.scale = d.scale;
                rf.precision = d.precision;
                rf.dec_bits = @intCast(d.bits);
                rf.col.type = .decimal;
            },
            .date => |u| {
                rf.kind = if (u == .day) .date32 else .date64;
                rf.col.type = .date;
            },
            .time => |t| {
                const narrow = t.unit == .second or t.unit == .millisecond;
                if ((t.bits == 32) != narrow) return error.Malformed;
                rf.kind = if (narrow) .time32 else .time64;
                rf.unit = t.unit;
                rf.col.type = .time;
            },
            .timestamp => |t| {
                rf.kind = .ts;
                rf.unit = t.unit;
                rf.col.type = .timestamp;
                if (t.tz) |z| {
                    rf.col.time_zone = try r.a.dupe(u8, z);
                    rf.col.checkZone() catch {
                        // A zone `dataframe` does not know; `lossy` reads the instants as a naive column.
                        if (!r.opts.lossy) return error.Unsupported;
                        rf.col.time_zone = null;
                    };
                }
            },
            .duration => |u| {
                rf.kind = .dur;
                rf.unit = u;
                rf.col.type = .duration;
            },
            .utf8, .large_utf8, .binary, .large_binary => {
                bufs = 3;
                rf.kind = if (f.type == .utf8 or f.type == .binary) .var32 else .var64;
                rf.col.type = if (f.type == .utf8 or f.type == .large_utf8) .text else .binary;
            },
            .fixed_size_binary => |w| {
                rf.kind = .fsb;
                rf.width = std.math.cast(usize, w) orelse return error.Malformed;
                rf.col.type = .binary;
            },
            .list, .large_list, .fixed_size_list => {
                if (f.children.len != 1) return error.Malformed;
                switch (f.type) {
                    .fixed_size_list => |n| {
                        bufs = 1;
                        rf.kind = .fsl;
                        rf.width = std.math.cast(usize, n) orelse return error.Malformed;
                        rf.col.type = .array;
                        rf.col.array_width = std.math.cast(u32, n) orelse return error.Malformed;
                    },
                    else => {
                        rf.kind = if (f.type == .list) .list32 else .list64;
                        rf.col.type = .list;
                    },
                }
                ctr.bufs += bufs;
                bufs = 0;
                const kids = try r.a.alloc(RField, 1);
                kids[0] = try r.plan(f.children[0], ctr, depth + 1, in_dict);
                rf.children = kids;
                rf.col.inner = try r.a.dupe(Column, &.{kids[0].col});
            },
            .@"struct" => {
                ctr.bufs += 1;
                bufs = 0;
                rf.kind = .struct_;
                rf.col.type = .@"struct";
                const kids = try r.a.alloc(RField, f.children.len);
                const inner = try r.a.alloc(Column, f.children.len);
                for (kids, inner, f.children) |*k, *c, cf| {
                    k.* = try r.plan(cf, ctr, depth + 1, in_dict);
                    c.* = k.col;
                }
                rf.children = kids;
                rf.col.inner = inner;
            },
            .binary_view, .utf8_view => {
                // Validity and 16-byte views; the variadic data buffers follow the views in
                // the message, as many as its `variadicBufferCounts` entry says.
                rf.kind = .view;
                rf.col.type = if (f.type == .utf8_view) .text else .binary;
                rf.view = ctr.views.items.len;
                try ctr.views.append(r.a, rf.buf_ix + 1);
            },
            .list_view, .large_list_view => {
                // Validity, offsets, sizes; one child.
                if (f.children.len != 1) return error.Malformed;
                rf.kind = if (f.type == .list_view) .lview32 else .lview64;
                rf.col.type = .list;
                ctr.bufs += 3;
                bufs = 0;
                const kids = try r.a.alloc(RField, 1);
                kids[0] = try r.plan(f.children[0], ctr, depth + 1, in_dict);
                rf.children = kids;
                rf.col.inner = try r.a.dupe(Column, &.{kids[0].col});
            },
            .run_end_encoded => {
                // No buffers of its own; `run_ends` (signed Int16/32/64, no nulls) and `values`.
                // Read as a plain column of the values' type, the runs expanded.
                if (f.children.len != 2) return error.Malformed;
                const ends = f.children[0];
                if (ends.dictionary != null or ends.children.len != 0) return error.Malformed;
                switch (ends.type) {
                    .int => |it| if (!it.signed or it.bits < 16) return error.Malformed,
                    else => return error.Malformed,
                }
                bufs = 0;
                rf.kind = .ree;
                const kids = try r.a.alloc(RField, 2);
                for (kids, f.children) |*k, cf| k.* = try r.plan(cf, ctr, depth + 1, in_dict);
                rf.children = kids;
                const name = rf.col.name;
                rf.col = kids[1].col;
                rf.col.name = name;
            },
            .unsupported => return error.Unsupported,
        }
        ctr.bufs += bufs;
        return rf;
    }

    fn planAll(r: *Reader, s: schema.Schema) Error!Top {
        var ctr: Counter = .{};
        const fields = try r.a.alloc(RField, s.fields.len);
        for (fields, s.fields) |*rf, f| rf.* = try r.plan(f, &ctr, 0, false);
        var top: Top = .{ .fields = fields, .ctr = ctr, .pick = try iota(r.a, 0, fields.len) };
        if (r.opts.columns) |cols| try r.project(&top, cols);
        return top;
    }

    /// Resolves `ReadOptions.columns`: the picked fields, the nodes and buffers they own
    /// (a top-level field's are contiguous, up to the next field's), the dictionaries
    /// they read.
    fn project(r: *Reader, top: *Top, cols: []const ColumnRef) Error!void {
        const fields = top.fields;
        const pick = try r.a.alloc(usize, cols.len);
        const taken = try r.a.alloc(bool, fields.len);
        @memset(taken, false);
        for (pick, cols) |*p, c| {
            const i: usize = switch (c) {
                .index => |i| if (i < fields.len) i else return error.UnknownColumn,
                .name => |nm| blk: {
                    var found: ?usize = null;
                    for (fields, 0..) |f, i| if (std.mem.eql(u8, f.col.name, nm)) {
                        if (found != null) return error.UnknownColumn; // two fields of that name
                        found = i;
                    };
                    break :blk found orelse return error.UnknownColumn;
                },
            };
            if (taken[i]) return error.UnknownColumn; // selected twice
            taken[i] = true;
            p.* = i;
        }
        const nodes = try r.a.alloc(bool, top.ctr.nodes);
        const bufs = try r.a.alloc(bool, top.ctr.bufs);
        @memset(nodes, false);
        @memset(bufs, false);
        for (r.dicts.items) |d| d.used = false;
        for (pick) |i| {
            const f = &fields[i];
            const node_end = if (i + 1 < fields.len) fields[i + 1].node_ix else top.ctr.nodes;
            const buf_end = if (i + 1 < fields.len) fields[i + 1].buf_ix else top.ctr.bufs;
            @memset(nodes[f.node_ix..node_end], true);
            @memset(bufs[f.buf_ix..buf_end], true);
            markUsed(f);
        }
        top.pick = pick;
        top.need = .{ .nodes = nodes, .bufs = bufs };
    }

    fn markUsed(f: *const RField) void {
        if (f.dict) |d| d.used = true;
        for (f.children) |*c| markUsed(c);
    }

    fn takeBatch(r: *Reader, top: *const Top, msg: schema.Message, body: []const u8) Error!Chunk {
        const h = msg.header orelse return error.Malformed;
        const rb = ipc.decodeRecordBatch(r.a, h, body.len) catch |e| return noEos(e);
        try r.checkBatch(rb, top.ctr, top.fields, top.need, true);
        return r.prepare(rb, body, top.ctr, if (top.need) |n| n.bufs else null);
    }

    fn takeDict(r: *Reader, msg: schema.Message, body: []const u8) Error!void {
        const h = msg.header orelse return error.Malformed;
        const db = ipc.decodeDictionaryBatch(r.a, h, body.len) catch |e| return noEos(e);
        const d = r.by_id.get(db.id) orelse return error.Malformed;
        if (!db.is_delta and d.batches > 0) return error.Unsupported; // replacement
        d.batches += 1;
        // A dictionary no projected column reads: its metadata is checked, its body is not
        // read (as an unprojected column's buffers are not).
        try r.checkBatch(db.data, d.ctr, (&d.value)[0..1], null, d.used);
        if (!d.used) return;
        try d.chunks.append(r.a, try r.prepare(db.data, body, d.ctr, null));
    }

    fn finishDicts(r: *Reader) Error!void {
        for (r.dicts.items) |d| {
            if (!d.used) continue;
            var n: u64 = 0;
            for (d.chunks.items) |c| n += @intCast(c.rb.length);
            if (n > r.opts.max_rows) return error.LimitExceeded;
            d.len = @intCast(n);
            d.data = try r.decode(&d.value, d.chunks.items);
        }
    }

    fn frame(r: *Reader, top: *const Top, chunks: []const Chunk) Error!df.Frame {
        // What decoding copies out of dictionaries counts against `max_cells` for this
        // call only: `File.readBatch` may decode the same batch again.
        const saved = r.cells;
        defer r.cells = saved;
        var total: u64 = 0;
        for (chunks) |c| total += @intCast(c.rb.length);
        if (total > r.opts.max_rows) return error.LimitExceeded;
        const columns = try r.a.alloc(Column, top.pick.len);
        const data = try r.a.alloc(ColumnData, top.pick.len);
        for (columns, data, top.pick) |*c, *dd, i| {
            const rf = &top.fields[i];
            c.* = rf.col;
            dd.* = try r.decode(rf, chunks);
        }
        return .{ .columns = columns, .data = data, .len = @intCast(total) };
    }

    /// A batch's shape against the schema: node and buffer counts, every length within
    /// `max_rows`, every top-level column as long as the batch; the length of every array
    /// that will be decoded (`need`: the projected ones; `count = false`: none) counted
    /// against `max_cells`.
    fn checkBatch(r: *Reader, rb: ipc.RecordBatch, ctr: Counter, top: []const RField, need: ?Need, count: bool) Error!void {
        // One variadic count per view field (none without them); the buffers are the fixed
        // ones plus every variadic one.
        if (rb.variadic_counts.len != ctr.views.items.len) return error.Malformed;
        var bufs: u64 = ctr.bufs;
        for (rb.variadic_counts) |x| bufs +|= @intCast(x); // decodeRecordBatch refused negatives
        if (rb.nodes.len != ctr.nodes or rb.buffers.len != bufs) return error.Malformed;
        if (@as(u64, @intCast(rb.length)) > r.opts.max_rows) return error.LimitExceeded;
        for (rb.nodes, 0..) |nd, i| {
            const n = try r.rows(nd);
            if (count and (need == null or need.?.nodes[i])) try r.charge(n);
        }
        for (top) |f| if (rb.nodes[f.node_ix].length != rb.length) return error.Malformed;
    }

    /// A batch as `decode` reads it: the variadic data buffers of its view fields moved out
    /// of the buffer list (into `Chunk.variadic`), so every field's fixed buffers sit where
    /// `plan` counted them; then inflated. `need` marks the fixed buffers a projection
    /// reads (a view field's variadic buffers go with its views buffer). `checkBatch` has
    /// matched the counts.
    fn prepare(r: *Reader, rb: ipc.RecordBatch, body: []const u8, ctr: Counter, need: ?[]const bool) Error!Chunk {
        const nv = ctr.views.items.len;
        if (nv == 0) return r.inflate(rb, body, need);
        const all = try r.a.alloc(ipc.BufferLoc, rb.buffers.len);
        const mask: ?[]bool = if (need != null) try r.a.alloc(bool, rb.buffers.len) else null;
        const starts = try r.a.alloc(usize, nv + 1);
        var src: usize = 0;
        var tail: usize = ctr.bufs;
        var k: usize = 0;
        for (0..ctr.bufs) |j| {
            all[j] = rb.buffers[src];
            src += 1;
            if (mask) |m| m[j] = need.?[j];
            if (k < nv and ctr.views.items[k] == j) {
                starts[k] = tail;
                for (0..@intCast(rb.variadic_counts[k])) |_| {
                    all[tail] = rb.buffers[src];
                    if (mask) |m| m[tail] = need.?[j];
                    src += 1;
                    tail += 1;
                }
                k += 1;
            }
        }
        starts[nv] = tail;
        var arranged = rb;
        arranged.buffers = all;
        var c = try r.inflate(arranged, body, mask);
        const vs = try r.a.alloc([]const ipc.BufferLoc, nv);
        for (vs, starts[0..nv], starts[1..]) |*v, lo, hi| v.* = c.rb.buffers[lo..hi];
        c.rb.buffers = c.rb.buffers[0..ctr.bufs];
        c.variadic = vs;
        return c;
    }

    /// A batch whose body is compressed, with every buffer decompressed into one fresh body
    /// (a batch without compression is returned as it is). Each non-empty buffer starts with
    /// its uncompressed length as an `int64`: -1 means the rest is stored raw.
    fn inflate(r: *Reader, rb: ipc.RecordBatch, body: []const u8, need: ?[]const bool) Error!Chunk {
        const codec = rb.compression orelse return .{ .rb = rb, .body = body };
        // LZ4_FRAME: the collection has no LZ4 codec yet; any other value is not Arrow's.
        if (codec != .zstd) return error.Unsupported;
        // The cap is over the whole read, not this message: K small messages of RLE frames
        // would otherwise expand K times the cap. Buffers no projected column reads (`need`)
        // are left compressed and become empty.
        var total: u64 = 0;
        for (rb.buffers, 0..) |l, i| {
            const src = locBytes(body, l);
            if (src.len == 0 or (need != null and !need.?[i])) continue;
            total +|= try rawLen(src);
            if (r.inflated +| total > r.opts.max_body_bytes) return error.LimitExceeded;
        }
        r.inflated += total;
        const out = try r.a.alloc(u8, @intCast(total));
        const locs = try r.a.alloc(ipc.BufferLoc, rb.buffers.len);
        var at: usize = 0;
        for (rb.buffers, locs, 0..) |l, *o, i| {
            const src = locBytes(body, l);
            var n: usize = 0;
            if (src.len > 0 and (need == null or need.?[i])) {
                n = @intCast(try rawLen(src));
                const dst = out[at..][0..n];
                if (std.mem.readInt(i64, src[0..8], .little) == -1) {
                    @memcpy(dst, src[8..]);
                } else if (n > 0) {
                    const frames = src[8..];
                    // A frame declaring more than it can hold is refused before decoding.
                    const bound = zstd.decompressBound(frames) catch return error.Malformed;
                    if (n > bound) return error.Malformed;
                    if (r.zd == null) r.zd = try zstd.Decompressor.init(r.a, .{});
                    const got = r.zd.?.decompress(dst, frames) catch return error.Malformed;
                    if (got != n) return error.Malformed;
                }
            }
            o.* = .{ .offset = @intCast(at), .length = @intCast(n) };
            at += n;
        }
        var plain = rb;
        plain.buffers = locs;
        plain.compression = null;
        return .{ .rb = plain, .body = out };
    }

    fn rows(r: *const Reader, node: ipc.FieldNode) Error!usize {
        if (@as(u64, @intCast(node.length)) > r.opts.max_rows) return error.LimitExceeded;
        return std.math.cast(usize, node.length) orelse error.LimitExceeded;
    }

    /// The whole column `rf` over every chunk, as one dataframe array.
    fn decode(r: *Reader, rf: *const RField, chunks: []const Chunk) Error!ColumnData {
        var n: usize = 0;
        for (chunks) |c| {
            n += try r.rows(c.rb.nodes[rf.node_ix]);
            if (n > r.opts.max_rows) return error.LimitExceeded;
        }
        if (rf.kind == .null_) return .nulls;
        if (rf.kind == .ree) return r.runEnded(rf, chunks, n);
        var valid = try r.validity(rf, chunks, n);
        return switch (rf.kind) {
            .null_ => .nulls,
            .i8 => typed("int8", try r.raw(i8, rf, chunks, n, valid), valid, n),
            .i16 => typed("int16", try r.raw(i16, rf, chunks, n, valid), valid, n),
            .i32 => typed("int32", try r.raw(i32, rf, chunks, n, valid), valid, n),
            .i64 => typed("int", try r.raw(i64, rf, chunks, n, valid), valid, n),
            .u8 => typed("uint8", try r.raw(u8, rf, chunks, n, valid), valid, n),
            .u16 => typed("uint16", try r.raw(u16, rf, chunks, n, valid), valid, n),
            .u32 => typed("uint32", try r.raw(u32, rf, chunks, n, valid), valid, n),
            .u64 => typed("uint64", try r.raw(u64, rf, chunks, n, valid), valid, n),
            .f32 => typed("float32", try r.raw(f32, rf, chunks, n, valid), valid, n),
            .f64 => typed("float", try r.raw(f64, rf, chunks, n, valid), valid, n),
            .f16 => blk: {
                const h = try r.raw(f16, rf, chunks, n, valid);
                const out = try r.a.alloc(f32, n);
                for (out, h) |*o, x| o.* = x;
                break :blk typed("float32", out, valid, n);
            },
            .dec => blk: {
                const v = try r.decimals(rf, chunks, n, &valid);
                for (v, 0..) |*x, i| {
                    // More digits than the declared precision is not a value of this type;
                    // more than 38 at 12 fractional digits has no Decimal128 form to write back.
                    // (A Decimal256 wider than 38 digits was dropped or narrowed by `decimals`.)
                    const fits = rf.precision > max_precision or @abs(x.*) < pow10[@intCast(rf.precision)];
                    x.* = (if (fits) rescale(x.*, rf.scale) else error.Unsupported) catch try r.drop(&valid, n, i);
                    if (digitCount(x.*) > max_precision) x.* = try r.drop(&valid, n, i);
                }
                break :blk typed("decimal", v, valid, n);
            },
            .ts, .dur => blk: {
                const v = try r.raw(i64, rf, chunks, n, valid);
                for (v, 0..) |*x, i| x.* = toMicros(x.*, rf.unit, r.opts.lossy) catch try r.drop(&valid, n, i);
                break :blk typed("int", v, valid, n);
            },
            .time32, .time64 => blk: {
                const v = try r.a.alloc(i64, n);
                if (rf.kind == .time32) {
                    for (v, try r.raw(i32, rf, chunks, n, valid)) |*o, x| o.* = x;
                } else @memcpy(v, try r.raw(i64, rf, chunks, n, valid));
                for (v, 0..) |*x, i| {
                    x.* = toMicros(x.*, rf.unit, r.opts.lossy) catch try r.drop(&valid, n, i);
                    // 24:00:00 and beyond: no `.time` value.
                    if (x.* < 0 or x.* >= us_per_day) x.* = try r.drop(&valid, n, i);
                }
                break :blk typed("int", v, valid, n);
            },
            .date32, .date64 => blk: {
                const days = try r.a.alloc(i64, n);
                if (rf.kind == .date32) {
                    for (days, try r.raw(i32, rf, chunks, n, valid)) |*o, x| o.* = x;
                } else {
                    // Date64 counts milliseconds of whole days; anything between is an inexact
                    // date (null slots are 0).
                    for (days, try r.raw(i64, rf, chunks, n, valid)) |*o, x| {
                        if (@rem(x, ms_per_day) != 0 and !r.opts.lossy) return error.Unsupported;
                        // Floor, not truncation: the calendar day that contains the instant
                        // (-1 ms is 1969-12-31).
                        o.* = @divFloor(x, ms_per_day);
                    }
                }
                for (days, 0..) |*d, i| {
                    if (!isSet(valid, i)) continue;
                    const date = df.Date.fromOrdinal(d.*) orelse {
                        d.* = try r.drop(&valid, n, i);
                        continue;
                    };
                    if (date.y < 0 or date.y > 9999) d.* = try r.drop(&valid, n, i); // no 4-digit ISO form
                }
                break :blk try r.dateText(days, valid, n);
            },
            .bool_ => try r.bools(rf, chunks, n, valid),
            .var32, .var64, .fsb => try r.text(rf, chunks, n, valid),
            .dict => try r.dictColumn(rf, chunks, n, valid),
            .list32, .list64, .fsl => try r.list(rf, chunks, n, valid),
            .view => try r.viewColumn(rf, chunks, n, valid),
            .lview32, .lview64 => try r.listView(rf, chunks, n, valid),
            .ree => unreachable, // returned above
            .struct_ => blk: {
                for (chunks) |c| {
                    const len = c.rb.nodes[rf.node_ix].length;
                    for (rf.children) |k| if (c.rb.nodes[k.node_ix].length != len) return error.Malformed;
                }
                const kids = try r.a.alloc(ColumnData, rf.children.len);
                const names = try r.a.alloc([]const u8, rf.children.len);
                for (kids, names, rf.children) |*k, *nm, *c| {
                    k.* = try r.decode(c, chunks);
                    nm.* = c.col.name;
                }
                if (allNull(valid, n)) break :blk .nulls;
                const sc = try r.a.create(df.StructColumn);
                sc.* = .{ .names = names, .children = kids, .len = n, .valid = valid };
                break :blk .{ .@"struct" = sc };
            },
        };
    }

    /// Every chunk's decimals of any width as i128 (null slots zeroed). Decimal32 and
    /// Decimal64 widen exactly; a Decimal256 value with more digits than its declared
    /// precision, or outside i128, is a value `dataframe` cannot hold (`drop`).
    fn decimals(r: *Reader, rf: *const RField, chunks: []const Chunk, n: usize, valid: *?[]u64) Error![]i128 {
        switch (rf.dec_bits) {
            inline 32, 64 => |bits| {
                // `raw` checks the buffers against the nodes before anything is allocated.
                const narrow = try r.raw(@Int(.signed, bits), rf, chunks, n, valid.*);
                const out = try r.a.alloc(i128, n);
                for (out, narrow) |*o, x| o.* = x;
                return out;
            },
            256 => {
                const wide = try r.raw(i256, rf, chunks, n, valid.*);
                const out = try r.a.alloc(i128, n);
                const p: usize = @intCast(rf.precision);
                for (out, wide, 0..) |*o, x, i| {
                    o.* = if (@abs(x) < pow10_256[p]) std.math.cast(i128, x) orelse try r.drop(valid, n, i) else try r.drop(valid, n, i);
                }
                return out;
            },
            else => return r.raw(i128, rf, chunks, n, valid.*),
        }
    }

    /// A RunEndEncoded column expanded into a plain one: row `i` of a batch is the value of
    /// the first run whose end exceeds `i`. Run ends must be positive, strictly increasing
    /// and the last at least the batch's length (greater for a sliced array: only the
    /// batch's rows are expanded), with no nulls (nulls live in the values); the parent
    /// has no validity of its own. The expansion (one selector per row, then the copy)
    /// is charged to `max_cells` before it is allocated.
    fn runEnded(r: *Reader, rf: *const RField, chunks: []const Chunk, n: usize) Error!ColumnData {
        const ends_f = &rf.children[0];
        const vals_f = &rf.children[1];
        var runs: usize = 0;
        for (chunks) |c| {
            const ends = c.rb.nodes[ends_f.node_ix];
            if (c.rb.nodes[rf.node_ix].null_count != 0 or ends.null_count != 0) return error.Malformed;
            if (ends.length != c.rb.nodes[vals_f.node_ix].length) return error.Malformed;
            runs += try r.rows(ends);
            if (runs > r.opts.max_rows) return error.LimitExceeded;
        }
        // `plan` admitted signed Int16/32/64 only.
        const ends: []const i64 = switch (ends_f.kind) {
            inline .i16, .i32 => |k| blk: {
                const narrow = try r.raw(RawOf(k), ends_f, chunks, runs, null);
                const wide = try r.a.alloc(i64, runs);
                for (wide, narrow) |*w, x| w.* = x;
                break :blk wide;
            },
            else => try r.raw(i64, ends_f, chunks, runs, null),
        };
        // Every run end checked before the expansion is sized.
        var at: usize = 0;
        for (chunks) |c| {
            const len = c.rb.nodes[rf.node_ix].length;
            const k: usize = @intCast(c.rb.nodes[ends_f.node_ix].length);
            var prev: i64 = 0;
            for (ends[at..][0..k]) |e| {
                if (e <= prev) return error.Malformed; // not strictly increasing (or not positive)
                prev = e;
            }
            if (prev < len) return error.Malformed; // the runs must cover the length
            at += k;
        }
        try r.afford(n);
        const sel = try r.a.alloc(usize, n);
        var row: usize = 0;
        at = 0;
        for (chunks) |c| {
            const len = c.rb.nodes[rf.node_ix].length;
            const k: usize = @intCast(c.rb.nodes[ends_f.node_ix].length);
            const base = row;
            for (ends[at..][0..k], at..) |e, run| {
                // Runs past the length (a sliced array's) fill nothing.
                const end = base + @as(usize, @intCast(@min(e, len)));
                while (row < end) : (row += 1) sel[row] = run;
            }
            at += k;
        }
        const values = try r.decode(vals_f, chunks);
        return gather(r, values, sel);
    }

    /// A value `dataframe` cannot hold at row `i`: `error.Unsupported`, or under
    /// `ReadOptions.lossy` a null cell (the 0 returned is the slot's value).
    fn drop(r: *Reader, valid: *?[]u64, n: usize, i: usize) Error!i64 {
        if (!r.opts.lossy) return error.Unsupported;
        if (valid.* == null) {
            const w = try r.a.alloc(u64, (n + 63) / 64);
            @memset(w, ~@as(u64, 0));
            valid.* = w;
        }
        valid.*.?[i / 64] &= ~(@as(u64, 1) << @as(u6, @truncate(i)));
        return 0;
    }

    /// The merged validity bitmap of all chunks (null: no null anywhere).
    fn validity(r: *Reader, rf: *const RField, chunks: []const Chunk, n: usize) Error!?[]u64 {
        var words: ?[]u64 = null;
        var base: usize = 0;
        for (chunks) |c| {
            const node = c.rb.nodes[rf.node_ix];
            const len: usize = @intCast(node.length);
            if (node.null_count > 0) {
                const bm = bufOf(c, rf.buf_ix);
                if (bm.len < (len + 7) / 8) return error.Malformed;
                if (words == null) {
                    const wds = try r.a.alloc(u64, (n + 63) / 64);
                    @memset(wds, ~@as(u64, 0));
                    words = wds;
                }
                for (0..len) |i| {
                    if ((bm[i / 8] >> @as(u3, @truncate(i))) & 1 == 0) {
                        const j = base + i;
                        words.?[j / 64] &= ~(@as(u64, 1) << @as(u6, @truncate(j)));
                    }
                }
            }
            base += len;
        }
        return words;
    }

    /// Buffer 1 of every chunk as `n` values of `T` (null slots zeroed).
    fn raw(r: *Reader, comptime T: type, rf: *const RField, chunks: []const Chunk, n: usize, valid: ?[]const u64) Error![]T {
        const S = @sizeOf(T);
        for (chunks) |c| {
            const len: usize = @intCast(c.rb.nodes[rf.node_ix].length);
            if (len > 0 and bufOf(c, rf.buf_ix + 1).len / S < len) return error.Malformed;
        }
        const out = try r.a.alloc(T, n);
        var base: usize = 0;
        for (chunks) |c| {
            const len: usize = @intCast(c.rb.nodes[rf.node_ix].length);
            if (len == 0) continue;
            const b = bufOf(c, rf.buf_ix + 1);
            for (0..len) |i| out[base + i] = if (isSet(valid, base + i)) getLe(T, b[i * S ..][0..S]) else 0;
            base += len;
        }
        return out;
    }

    fn bools(r: *Reader, rf: *const RField, chunks: []const Chunk, n: usize, valid: ?[]const u64) Error!ColumnData {
        for (chunks) |c| {
            const len: usize = @intCast(c.rb.nodes[rf.node_ix].length);
            if (len > 0 and bufOf(c, rf.buf_ix + 1).len < (len + 7) / 8) return error.Malformed;
        }
        const out = try r.a.alloc(bool, n);
        var base: usize = 0;
        for (chunks) |c| {
            const len: usize = @intCast(c.rb.nodes[rf.node_ix].length);
            if (len == 0) continue;
            const b = bufOf(c, rf.buf_ix + 1);
            for (0..len) |i| out[base + i] = isSet(valid, base + i) and (b[i / 8] >> @as(u3, @truncate(i))) & 1 == 1;
            base += len;
        }
        return typed("bool", out, valid, n);
    }

    fn text(r: *Reader, rf: *const RField, chunks: []const Chunk, n: usize, valid: ?[]u64) Error!ColumnData {
        const wide = rf.kind == .var64;
        const ow: usize = if (wide) 8 else 4;
        // Utf8 / LargeUtf8 (Binary and FixedSizeBinary read as `.binary`).
        const check = r.opts.validate_utf8 and rf.col.type == .text;
        for (chunks) |c| {
            const len: usize = @intCast(c.rb.nodes[rf.node_ix].length);
            if (len == 0) continue;
            if (rf.kind == .fsb) {
                const need = std.math.mul(usize, len, rf.width) catch return error.Malformed;
                if (bufOf(c, rf.buf_ix + 1).len < need) return error.Malformed;
            } else if (bufOf(c, rf.buf_ix + 1).len / ow < len + 1) return error.Malformed;
        }
        const offsets = try r.a.alloc(usize, n + 1);
        offsets[0] = 0;
        var bytes: std.ArrayList(u8) = .empty;
        var base: usize = 0;
        for (chunks) |c| {
            const len: usize = @intCast(c.rb.nodes[rf.node_ix].length);
            if (len == 0) continue;
            const data = bufOf(c, rf.buf_ix + if (rf.kind == .fsb) @as(usize, 1) else 2);
            const offs = bufOf(c, rf.buf_ix + 1);
            for (0..len) |i| {
                var lo: usize = undefined;
                var hi: usize = undefined;
                if (rf.kind == .fsb) {
                    lo = i * rf.width;
                    hi = lo + rf.width;
                } else {
                    lo = try readOff(offs, i, wide);
                    hi = try readOff(offs, i + 1, wide);
                    if (lo > hi or hi > data.len) return error.Malformed;
                }
                if (isSet(valid, base + i)) {
                    const s = data[lo..hi];
                    if (check and !std.unicode.utf8ValidateSlice(s)) return error.InvalidUtf8;
                    try bytes.appendSlice(r.a, s);
                }
                offsets[base + i + 1] = bytes.items.len;
            }
            base += len;
        }
        if (allNull(valid, n)) return .nulls;
        return .{ .text = .{ .offsets = offsets, .bytes = bytes.items, .valid = valid } };
    }

    /// BinaryView / Utf8View: each valid row's 16-byte view — its length, then the bytes
    /// inline (12 at most) or a 4-byte prefix, a data buffer index and an offset — checked
    /// against its batch's variadic buffers (index, offset and length in range, the prefix
    /// equal to the data's first bytes) and copied out. Views may share bytes, so every
    /// copied byte is charged to `max_cells` before the copy is allocated; null rows'
    /// views are not looked at. Utf8View values are UTF-8 checked like Utf8.
    fn viewColumn(r: *Reader, rf: *const RField, chunks: []const Chunk, n: usize, valid: ?[]u64) Error!ColumnData {
        const check = r.opts.validate_utf8 and rf.col.type == .text;
        var total: u64 = 0;
        var base: usize = 0;
        for (chunks) |c| {
            const len: usize = @intCast(c.rb.nodes[rf.node_ix].length);
            if (len > 0 and bufOf(c, rf.buf_ix + 1).len / 16 < len) return error.Malformed;
            const vb = bufOf(c, rf.buf_ix + 1);
            for (0..len) |i| {
                if (!isSet(valid, base + i)) continue;
                total +|= (try viewBytes(c, rf.view, vb[i * 16 ..][0..16])).len;
            }
            base += len;
        }
        try r.charge(total);
        const offsets = try r.a.alloc(usize, n + 1);
        const bytes = try r.a.alloc(u8, @intCast(total));
        offsets[0] = 0;
        var at: usize = 0;
        base = 0;
        for (chunks) |c| {
            const len: usize = @intCast(c.rb.nodes[rf.node_ix].length);
            const vb = bufOf(c, rf.buf_ix + 1);
            for (0..len) |i| {
                if (isSet(valid, base + i)) {
                    const v = try viewBytes(c, rf.view, vb[i * 16 ..][0..16]);
                    if (check and !std.unicode.utf8ValidateSlice(v)) return error.InvalidUtf8;
                    @memcpy(bytes[at..][0..v.len], v);
                    at += v.len;
                }
                offsets[base + i + 1] = at;
            }
            base += len;
        }
        if (allNull(valid, n)) return .nulls;
        return .{ .text = .{ .offsets = offsets, .bytes = bytes, .valid = valid } };
    }

    /// ListView / LargeListView: each valid row's elements are `sizes[i]` child slots from
    /// `offsets[i]` (any order, overlapping allowed), within its batch's child. The rows
    /// are copied out of the child as a `list`; the selectors are checked against
    /// `max_cells` before they are allocated and `gather` charges the copy. Null rows'
    /// offsets and sizes are not looked at.
    fn listView(r: *Reader, rf: *const RField, chunks: []const Chunk, n: usize, valid: ?[]u64) Error!ColumnData {
        const child = &rf.children[0];
        const wide = rf.kind == .lview64;
        const ow: usize = if (wide) 8 else 4;
        for (chunks) |c| {
            const len: usize = @intCast(c.rb.nodes[rf.node_ix].length);
            if (len > 0 and (bufOf(c, rf.buf_ix + 1).len / ow < len or bufOf(c, rf.buf_ix + 2).len / ow < len)) return error.Malformed;
        }
        const offsets = try r.a.alloc(u32, n + 1);
        offsets[0] = 0;
        var total: u64 = 0;
        var base: usize = 0;
        for (chunks) |c| {
            const len: usize = @intCast(c.rb.nodes[rf.node_ix].length);
            const clen: usize = @intCast(c.rb.nodes[child.node_ix].length);
            for (0..len) |i| {
                if (isSet(valid, base + i)) {
                    const lo = try readOff(bufOf(c, rf.buf_ix + 1), i, wide);
                    const size = try readOff(bufOf(c, rf.buf_ix + 2), i, wide);
                    if (lo > clen or size > clen - lo) return error.Malformed;
                    total += size;
                    if (total > std.math.maxInt(u32)) return error.Unsupported; // dataframe's u32 offsets
                }
                offsets[base + i + 1] = @intCast(total);
            }
            base += len;
        }
        var items = try r.decode(child, chunks);
        if (items != .nulls) {
            try r.afford(total);
            const sel = try r.a.alloc(usize, @intCast(total));
            var k: usize = 0;
            var child_base: usize = 0;
            base = 0;
            for (chunks) |c| {
                const len: usize = @intCast(c.rb.nodes[rf.node_ix].length);
                for (0..len) |i| {
                    if (!isSet(valid, base + i)) continue;
                    const lo = try readOff(bufOf(c, rf.buf_ix + 1), i, wide);
                    const size = try readOff(bufOf(c, rf.buf_ix + 2), i, wide);
                    for (sel[k..][0..size], child_base + lo..) |*x, e| x.* = e;
                    k += size;
                }
                child_base += @intCast(c.rb.nodes[child.node_ix].length);
                base += len;
            }
            items = try gather(r, items, sel);
        }
        if (allNull(valid, n)) return .nulls;
        const ip = try r.a.create(ColumnData);
        ip.* = items;
        return .{ .list = .{ .offsets = offsets, .items = ip, .valid = valid } };
    }

    fn dateText(r: *Reader, days: []const i64, valid: ?[]u64, n: usize) Error!ColumnData {
        if (allNull(valid, n)) return .nulls;
        const offsets = try r.a.alloc(usize, n + 1);
        const bytes = try r.a.alloc(u8, n * 10);
        var len: usize = 0;
        offsets[0] = 0;
        for (days, 0..) |d, i| {
            if (isSet(valid, i)) {
                const date = df.Date.fromOrdinal(d) orelse return error.Unsupported;
                if (date.y < 0 or date.y > 9999) return error.Unsupported; // no 4-digit ISO form
                fmtDate(bytes[len..][0..10], date);
                len += 10;
            }
            offsets[i + 1] = len;
        }
        return .{ .text = .{ .offsets = offsets, .bytes = bytes[0..len], .valid = valid } };
    }

    fn dictColumn(r: *Reader, rf: *const RField, chunks: []const Chunk, n: usize, valid: ?[]u64) Error!ColumnData {
        const d = rf.dict.?;
        const size: usize = rf.index.bits / 8;
        for (chunks) |c| {
            const len: usize = @intCast(c.rb.nodes[rf.node_ix].length);
            if (len > 0 and bufOf(c, rf.buf_ix + 1).len / size < len) return error.Malformed;
        }
        const codes = try r.a.alloc(u32, n);
        var base: usize = 0;
        for (chunks) |c| {
            const len: usize = @intCast(c.rb.nodes[rf.node_ix].length);
            if (len == 0) continue;
            const b = bufOf(c, rf.buf_ix + 1);
            for (0..len) |i| {
                codes[base + i] = 0;
                if (!isSet(valid, base + i)) continue;
                const x = readIndex(b[i * size ..][0..size], rf.index);
                if (x < 0 or x >= d.len) return error.Malformed;
                codes[base + i] = std.math.cast(u32, x) orelse return error.Unsupported;
            }
            base += len;
        }
        if (d.categorical) return r.categorical(d, codes, valid, n);
        const sel = try r.a.alloc(usize, n);
        for (sel, codes, 0..) |*s, k, i| s.* = if (isSet(valid, i)) k else none;
        return gather(r, d.data, sel);
    }

    /// A dictionary-encoded text column as `dataframe` keeps one: an unordered
    /// dictionary deduplicated and sorted lexically, an ordered one deduplicated in its
    /// order; null entries dropped (their rows become null).
    fn categorical(r: *Reader, d: *const RDict, codes: []u32, valid_in: ?[]u64, n: usize) Error!ColumnData {
        const gone = std.math.maxInt(u32);
        const remap = try r.a.alloc(u32, d.len);
        var offs: std.ArrayList(usize) = .empty;
        var bytes: std.ArrayList(u8) = .empty;
        try offs.append(r.a, 0);
        if (d.ordered) {
            var seen: std.StringHashMapUnmanaged(u32) = .empty;
            for (remap, 0..) |*m, k| {
                const t = textAt(d.data, k) orelse {
                    m.* = gone;
                    continue;
                };
                const gop = try seen.getOrPut(r.a, t);
                if (!gop.found_existing) {
                    gop.value_ptr.* = @intCast(offs.items.len - 1);
                    try bytes.appendSlice(r.a, t);
                    try offs.append(r.a, bytes.items.len);
                }
                m.* = gop.value_ptr.*;
            }
        } else {
            var order: std.ArrayList(u32) = .empty;
            for (remap, 0..) |*m, k| {
                m.* = gone;
                if (textAt(d.data, k) != null) try order.append(r.a, @intCast(k));
            }
            std.mem.sort(u32, order.items, d.data, lessEntry);
            var prev: ?[]const u8 = null;
            for (order.items) |k| {
                const t = textAt(d.data, k).?;
                if (prev == null or !std.mem.eql(u8, prev.?, t)) {
                    try bytes.appendSlice(r.a, t);
                    try offs.append(r.a, bytes.items.len);
                    prev = t;
                }
                remap[k] = @intCast(offs.items.len - 2);
            }
        }
        var valid = valid_in;
        for (codes, 0..) |*cd, i| {
            if (!isSet(valid, i)) continue;
            const m = remap[cd.*];
            if (m == gone) {
                if (valid == null) {
                    const wds = try r.a.alloc(u64, (n + 63) / 64);
                    @memset(wds, ~@as(u64, 0));
                    valid = wds;
                }
                valid.?[i / 64] &= ~(@as(u64, 1) << @as(u6, @truncate(i)));
                cd.* = 0;
            } else cd.* = m;
        }
        return .{ .categorical = .{
            .codes = .{ .values = codes, .valid = valid },
            .dict = .{ .offsets = offs.items, .bytes = bytes.items },
            .ordered = d.ordered,
        } };
    }

    fn list(r: *Reader, rf: *const RField, chunks: []const Chunk, n: usize, valid: ?[]u64) Error!ColumnData {
        const child = &rf.children[0];
        const fsl = rf.kind == .fsl;
        const wide = rf.kind == .list64;
        const ow: usize = if (wide) 8 else 4;
        for (chunks) |c| {
            const len: usize = @intCast(c.rb.nodes[rf.node_ix].length);
            if (!fsl and len > 0 and bufOf(c, rf.buf_ix + 1).len / ow < len + 1) return error.Malformed;
        }
        // Pass 1: check every offset, size the output, see whether the child is used as it is.
        const offsets = try r.a.alloc(u32, n + 1);
        offsets[0] = 0;
        var total: u64 = 0;
        var identity = true;
        var base: usize = 0;
        for (chunks) |c| {
            const len: usize = @intCast(c.rb.nodes[rf.node_ix].length);
            const clen: usize = @intCast(c.rb.nodes[child.node_ix].length);
            if (fsl) {
                const need = std.math.mul(usize, len, rf.width) catch return error.Malformed;
                if (clen < need) return error.Malformed;
                if (clen != need) identity = false;
            }
            var expect: usize = 0;
            for (0..len) |i| {
                var lo: usize = undefined;
                var hi: usize = undefined;
                if (fsl) {
                    lo = i * rf.width;
                    hi = lo + rf.width;
                } else {
                    const offs = bufOf(c, rf.buf_ix + 1);
                    lo = try readOff(offs, i, wide);
                    hi = try readOff(offs, i + 1, wide);
                    if (lo > hi or hi > clen) return error.Malformed;
                }
                const on = isSet(valid, base + i);
                if (lo != expect or (!on and hi != lo)) identity = false;
                expect = if (on) hi else lo;
                if (on) total += hi - lo;
                if (total > std.math.maxInt(u32)) return error.Unsupported; // dataframe's u32 offsets
                offsets[base + i + 1] = @intCast(total);
            }
            if (!fsl and expect != clen) identity = false;
            base += len;
        }
        var items = try r.decode(child, chunks);
        // A child of nulls has no storage to select from (and its length may be unbacked).
        if (!identity and items != .nulls) {
            const sel = try r.a.alloc(usize, @intCast(total));
            var k: usize = 0;
            var child_base: usize = 0;
            base = 0;
            for (chunks) |c| {
                const len: usize = @intCast(c.rb.nodes[rf.node_ix].length);
                for (0..len) |i| {
                    if (!isSet(valid, base + i)) continue;
                    var lo: usize = undefined;
                    var hi: usize = undefined;
                    if (fsl) {
                        lo = i * rf.width;
                        hi = lo + rf.width;
                    } else {
                        const offs = bufOf(c, rf.buf_ix + 1);
                        lo = try readOff(offs, i, wide);
                        hi = try readOff(offs, i + 1, wide);
                    }
                    for (lo..hi) |e| {
                        sel[k] = child_base + e;
                        k += 1;
                    }
                }
                child_base += @intCast(c.rb.nodes[child.node_ix].length);
                base += len;
            }
            items = try gather(r, items, sel);
        }
        if (allNull(valid, n)) return .nulls;
        const ip = try r.a.create(ColumnData);
        ip.* = items;
        return .{ .list = .{ .offsets = offsets, .items = ip, .valid = valid } };
    }
};

/// Whether two dictionary value fields describe the same values: type (zone included),
/// children by name and type, recursively. Nullability and metadata do not matter.
fn sameValueType(x: schema.Field, y: schema.Field) bool {
    if (std.meta.activeTag(x.type) != std.meta.activeTag(y.type)) return false;
    const same = switch (x.type) {
        .timestamp => |t| t.unit == y.type.timestamp.unit and
            ((t.tz == null and y.type.timestamp.tz == null) or
                (t.tz != null and y.type.timestamp.tz != null and std.mem.eql(u8, t.tz.?, y.type.timestamp.tz.?))),
        else => std.meta.eql(x.type, y.type),
    };
    if (!same or x.children.len != y.children.len) return false;
    if ((x.dictionary == null) != (y.dictionary == null)) return false;
    for (x.children, y.children) |p, q| {
        if (!std.mem.eql(u8, p.name, q.name) or !sameValueType(p, q)) return false;
    }
    return true;
}

/// The bytes one 16-byte view names: inline (length at most 12) or in variadic data
/// buffer `index` of its field (`k`) at `offset`; `error.Malformed` when they lie outside
/// it or the view's 4-byte prefix is not their start.
fn viewBytes(c: Chunk, k: usize, v: *const [16]u8) Error![]const u8 {
    const len = std.math.cast(usize, std.mem.readInt(i32, v[0..4], .little)) orelse return error.Malformed;
    if (len <= 12) return v[4..][0..len];
    const index = std.math.cast(usize, std.mem.readInt(i32, v[8..12], .little)) orelse return error.Malformed;
    const offset = std.math.cast(usize, std.mem.readInt(i32, v[12..16], .little)) orelse return error.Malformed;
    const bufs = c.variadic[k];
    if (index >= bufs.len) return error.Malformed;
    const data = locBytes(c.body, bufs[index]);
    if (offset > data.len or len > data.len - offset) return error.Malformed;
    const s = data[offset..][0..len];
    if (!std.mem.eql(u8, s[0..4], v[4..8])) return error.Malformed; // the prefix must be the data's
    return s;
}

fn bufOf(c: Chunk, ix: usize) []const u8 {
    // `decodeRecordBatch` checked every location against the body.
    const l = c.rb.buffers[ix];
    return c.body[@intCast(l.offset)..][0..@intCast(l.length)];
}

fn locBytes(body: []const u8, l: ipc.BufferLoc) []const u8 {
    // `decodeRecordBatch` checked every location against the body.
    return body[@intCast(l.offset)..][0..@intCast(l.length)];
}

/// The uncompressed length a compressed buffer declares (its first 8 bytes; -1: the rest
/// is stored raw).
fn rawLen(src: []const u8) Error!u64 {
    if (src.len < 8) return error.Malformed;
    const x = std.mem.readInt(i64, src[0..8], .little);
    if (x == -1) return src.len - 8;
    return std.math.cast(u64, x) orelse error.Malformed;
}

fn readOff(offs: []const u8, i: usize, wide: bool) Error!usize {
    // The caller checked `offs` holds the entry.
    const x: i64 = if (wide) std.mem.readInt(i64, offs[i * 8 ..][0..8], .little) else std.mem.readInt(i32, offs[i * 4 ..][0..4], .little);
    return std.math.cast(usize, x) orelse error.Malformed;
}

fn readIndex(b: []const u8, it: schema.IntType) i128 {
    return switch (it.bits) {
        8 => if (it.signed) @as(i8, @bitCast(b[0])) else b[0],
        16 => if (it.signed) std.mem.readInt(i16, b[0..2], .little) else std.mem.readInt(u16, b[0..2], .little),
        32 => if (it.signed) std.mem.readInt(i32, b[0..4], .little) else std.mem.readInt(u32, b[0..4], .little),
        else => if (it.signed) std.mem.readInt(i64, b[0..8], .little) else std.mem.readInt(u64, b[0..8], .little),
    };
}

fn isSet(valid: ?[]const u64, i: usize) bool {
    const v = valid orelse return true;
    return (v[i / 64] >> @as(u6, @truncate(i))) & 1 == 1;
}

/// Whether no row of `n` is valid (false for no rows: an empty column keeps its storage kind).
fn allNull(valid: ?[]const u64, n: usize) bool {
    const v = valid orelse return false;
    if (n == 0) return false;
    for (0..n) |i| if (isSet(v, i)) return false;
    return true;
}

fn typed(comptime tag: []const u8, values: anytype, valid: ?[]const u64, n: usize) ColumnData {
    if (allNull(valid, n)) return .nulls;
    return @unionInit(ColumnData, tag, .{ .values = values, .valid = valid });
}

fn textAt(data: ColumnData, k: usize) ?[]const u8 {
    return switch (data.get(k)) {
        .text => |t| t,
        else => null,
    };
}

fn lessEntry(data: ColumnData, x: u32, y: u32) bool {
    return std.mem.order(u8, textAt(data, x).?, textAt(data, y).?) == .lt;
}

fn rescale(x: i128, scale: i32) Error!i128 {
    if (scale == decimal_digits) return x;
    if (x == 0) return 0;
    const k: i64 = @as(i64, decimal_digits) - scale;
    if (k > 38 or k < -38) return error.Unsupported;
    var p: i128 = 1;
    for (0..@as(usize, @intCast(@abs(k)))) |_| p *= 10;
    if (k > 0) return std.math.mul(i128, x, p) catch error.Unsupported;
    if (@rem(x, p) != 0) return error.Unsupported; // digits `dataframe` cannot hold
    return @divExact(x, p);
}

fn toMicros(x: i64, unit: schema.TimeUnit, lossy: bool) Error!i64 {
    return switch (unit) {
        .second => std.math.mul(i64, x, 1_000_000) catch error.Unsupported,
        .millisecond => std.math.mul(i64, x, 1_000) catch error.Unsupported,
        .microsecond => x,
        // `dataframe` keeps microseconds: digits past them are an inexact conversion, like a
        // decimal's — refused, or under `lossy` truncated toward zero.
        .nanosecond => if (@rem(x, 1_000) != 0 and !lossy) error.Unsupported else @divTrunc(x, 1_000),
    };
}

fn fmtDate(out: *[10]u8, d: df.Date) void {
    const y: u32 = @intCast(d.y);
    out[0] = '0' + @as(u8, @intCast(y / 1000));
    out[1] = '0' + @as(u8, @intCast(y / 100 % 10));
    out[2] = '0' + @as(u8, @intCast(y / 10 % 10));
    out[3] = '0' + @as(u8, @intCast(y % 10));
    out[4] = '-';
    out[5] = '0' + d.m / 10;
    out[6] = '0' + d.m % 10;
    out[7] = '-';
    out[8] = '0' + d.d / 10;
    out[9] = '0' + d.d % 10;
}

/// Lazily allocated validity words for `n` rows.
const ValidOut = struct {
    words: ?[]u64 = null,

    fn clear(self: *ValidOut, a: Allocator, n: usize, i: usize) Error!void {
        if (self.words == null) {
            const w = try a.alloc(u64, (n + 63) / 64);
            @memset(w, ~@as(u64, 0));
            self.words = w;
        }
        self.words.?[i / 64] &= ~(@as(u64, 1) << @as(u6, @truncate(i)));
    }
};

/// The rows `sel` of `data` (an entry `none` is a null row), as fresh storage. Every row,
/// list element and text byte copied counts against `ReadOptions.max_cells`: a dictionary
/// entry of N elements or bytes selected by M rows costs N x M, which the input does not.
fn gather(r: *Reader, data: ColumnData, sel: []const usize) Error!ColumnData {
    const a = r.a;
    try r.charge(sel.len);
    switch (data) {
        .nulls => return .nulls,
        .boxed => return error.Unsupported,
        .text => |t| {
            const offsets = try a.alloc(usize, sel.len + 1);
            var bytes: std.ArrayList(u8) = .empty;
            var vo: ValidOut = .{};
            offsets[0] = 0;
            for (sel, 0..) |row, i| {
                if (t.at(row)) |s| {
                    try r.charge(s.len);
                    try bytes.appendSlice(a, s);
                } else if (!t.isValid(row)) try vo.clear(a, sel.len, i);
                offsets[i + 1] = bytes.items.len;
            }
            return .{ .text = .{ .offsets = offsets, .bytes = bytes.items, .valid = vo.words } };
        },
        .categorical => |c| {
            const codes = try gather(r, .{ .uint32 = c.codes }, sel);
            const cc: df.TypedColumn(u32) = switch (codes) {
                .uint32 => |x| x,
                else => blk: {
                    // All rows null.
                    const z = try a.alloc(u32, sel.len);
                    @memset(z, 0);
                    var vo: ValidOut = .{};
                    for (0..sel.len) |i| try vo.clear(a, sel.len, i);
                    break :blk .{ .values = z, .valid = vo.words };
                },
            };
            return .{ .categorical = .{ .codes = cc, .dict = c.dict, .ordered = c.ordered } };
        },
        .list => |l| {
            const offsets = try a.alloc(u32, sel.len + 1);
            var kids: std.ArrayList(usize) = .empty;
            var vo: ValidOut = .{};
            offsets[0] = 0;
            for (sel, 0..) |row, i| {
                if (l.at(row)) |lv| {
                    try r.charge(lv.len());
                    for (lv.start..lv.end) |e| try kids.append(a, e);
                } else try vo.clear(a, sel.len, i);
                offsets[i + 1] = std.math.cast(u32, kids.items.len) orelse return error.Unsupported;
            }
            const ip = try a.create(ColumnData);
            ip.* = try gather(r, l.items.*, kids.items);
            return .{ .list = .{ .offsets = offsets, .items = ip, .valid = vo.words } };
        },
        .@"struct" => |s| {
            var vo: ValidOut = .{};
            for (sel, 0..) |row, i| if (!s.isValid(row)) try vo.clear(a, sel.len, i);
            const kids = try a.alloc(ColumnData, s.children.len);
            for (kids, s.children) |*k, c| k.* = try gather(r, c, sel);
            const sc = try a.create(df.StructColumn);
            sc.* = .{ .names = s.names, .children = kids, .len = sel.len, .valid = vo.words };
            return .{ .@"struct" = sc };
        },
        inline else => |c, tag| {
            const T = @TypeOf(c.values[0]);
            const values = try a.alloc(T, sel.len);
            var vo: ValidOut = .{};
            for (sel, values, 0..) |row, *o, i| {
                if (c.isValid(row)) o.* = c.values[row] else {
                    o.* = std.mem.zeroes(T);
                    try vo.clear(a, sel.len, i);
                }
            }
            return @unionInit(ColumnData, @tagName(tag), .{ .values = values, .valid = vo.words });
        },
    }
}

fn noEos(e: ipc.Error) Error {
    return switch (e) {
        error.EndOfStream => error.Malformed,
        else => |x| x,
    };
}

/// The schema's, the picked fields' (in the frame's column order) and the footer's
/// key/value metadata, copied into `arena` (the decoded schema points into the input).
fn copyMetadata(arena: Allocator, s: schema.Schema, pick: []const usize, footer: []const KeyValue) Error!Metadata {
    const fields = try arena.alloc(schema.Field, pick.len);
    for (fields, pick) |*f, i| f.* = s.fields[i];
    return .{
        .schema = try copyKeyValues(arena, s.metadata),
        .fields = try copyFieldMetadata(arena, fields),
        .footer = try copyKeyValues(arena, footer),
    };
}

fn copyKeyValues(arena: Allocator, kvs: []const KeyValue) Error![]const KeyValue {
    const out = try arena.alloc(KeyValue, kvs.len);
    for (out, kvs) |*o, kv| o.* = .{ .key = try arena.dupe(u8, kv.key), .value = try arena.dupe(u8, kv.value) };
    return out;
}

fn copyFieldMetadata(arena: Allocator, fields: []const schema.Field) Error![]const FieldMetadata {
    // The decoded schema is at most `schema.max_depth` deep and its size is bounded by the
    // decode budget, so this copy is too.
    const out = try arena.alloc(FieldMetadata, fields.len);
    for (out, fields) |*o, f| o.* = .{
        .name = try arena.dupe(u8, f.name),
        .metadata = try copyKeyValues(arena, f.metadata),
        .children = try copyFieldMetadata(arena, f.children),
    };
    return out;
}

/// Reads an Arrow IPC stream into a frame allocated from `arena` (free it all with the
/// arena; nothing borrows `bytes`). Dictionary deltas are appended; ZSTD body compression
/// is read. A dictionary REPLACED mid-stream, LZ4_FRAME body compression, a metadata
/// version before V4, and the types `dataframe` has no column for (Interval, Union, Map,
/// the view types) are `error.Unsupported`.
pub fn readStream(arena: Allocator, bytes: []const u8, opts: ReadOptions) Error!df.Frame {
    var r: Reader = .{ .a = arena, .opts = opts };
    var pos: usize = 0;
    const first = ipc.readMessage(bytes, &pos) catch |e| return noEos(e); // no schema
    if (first.msg.header_type != .schema) return error.Malformed;
    const s = try schema.decodeSchema(arena, first.msg.header orelse return error.Malformed);
    const top = try r.planAll(s);
    if (opts.metadata) |m| m.* = try copyMetadata(arena, s, top.pick, &.{});

    var batches: std.ArrayList(Chunk) = .empty;
    while (true) {
        const m = ipc.readMessage(bytes, &pos) catch |e| switch (e) {
            error.EndOfStream => break,
            else => |x| return x,
        };
        switch (m.msg.header_type) {
            .record_batch => try batches.append(arena, try r.takeBatch(&top, m.msg, m.enc.body)),
            .dictionary_batch => try r.takeDict(m.msg, m.enc.body),
            .schema => return error.Malformed, // a second schema
            else => return error.Unsupported, // tensors
        }
    }
    try r.finishDicts();
    return r.frame(&top, batches.items);
}

/// An Arrow IPC file opened for random access to its record batches. Everything is
/// allocated from the arena given to `openFile`; nothing borrows the file's bytes
/// after a batch is read.
pub const File = struct {
    r: Reader,
    top: Top,
    batches: []const Chunk,

    pub fn batchCount(self: *const File) usize {
        return self.batches.len;
    }

    /// The rows of batch `i`; `error.Unsupported` past the last batch (as `readBatch`).
    pub fn batchRows(self: *const File, i: usize) Error!usize {
        if (i >= self.batches.len) return error.Unsupported;
        return @intCast(self.batches[i].rb.length);
    }

    /// Batch `i` alone as a frame; `error.Unsupported` past the last batch.
    pub fn readBatch(self: *File, i: usize) Error!df.Frame {
        if (i >= self.batches.len) return error.Unsupported;
        return self.r.frame(&self.top, self.batches[i..][0..1]);
    }

    /// Every batch, in file order, as one frame.
    pub fn readAll(self: *File) Error!df.Frame {
        return self.r.frame(&self.top, self.batches);
    }
};

/// Opens an Arrow IPC file: checks both `ARROW1` marks and the footer's metadata version,
/// reads the footer's schema, decodes every dictionary and checks every record batch's
/// metadata (not its data, which `File.readBatch` decodes on demand). Every footer block
/// must describe the message at its offset (framing + metadata length, body length), and
/// no two blocks may share bytes (`error.Malformed`): otherwise K blocks naming one small
/// message would make the reader inflate and decode it K times.
pub fn openFile(arena: Allocator, bytes: []const u8, opts: ReadOptions) Error!File {
    if (bytes.len < 8 + 10) return error.Malformed;
    if (!std.mem.eql(u8, bytes[0..6], magic) or !std.mem.eql(u8, bytes[bytes.len - 6 ..], magic)) return error.Malformed;
    const fend = bytes.len - 10;
    const flen = std.mem.readInt(i32, bytes[fend..][0..4], .little);
    if (flen <= 0 or @as(usize, @intCast(flen)) > fend - 8) return error.Malformed;
    const fstart = fend - @as(usize, @intCast(flen));
    const footer = try fb.root(bytes[fstart..fend]);
    try schema.checkVersion(try footer.scalar(schema.MetadataVersion, 0, .v1));
    var r: Reader = .{ .a = arena, .opts = opts };
    const s = try schema.decodeSchema(arena, try footer.table(1) orelse return error.Malformed);
    const top = try r.planAll(s);
    if (opts.metadata) |m| m.* = try copyMetadata(arena, s, top.pick, try schema.decodeKeyValues(arena, footer, 4));

    // The messages live between the leading mark and the footer. Every block is located
    // and checked before anything is inflated.
    const region = bytes[0..fstart];
    const dv = try footer.vector(2);
    const bv = try footer.vector(3);
    const nd: usize = if (dv) |v| v.len else 0;
    const nb: usize = if (bv) |v| v.len else 0;
    const msgs = try arena.alloc(ipc.Read, nd + nb);
    const spans = try arena.alloc(Span, nd + nb);
    for (msgs, spans, 0..) |*m, *sp, i| {
        const raw = if (i < nd) try dv.?.structAt(i, 24) else try bv.?.structAt(i - nd, 24);
        m.* = try readBlock(region, raw, sp);
        const want: schema.HeaderType = if (i < nd) .dictionary_batch else .record_batch;
        if (m.msg.header_type != want) return error.Malformed;
    }
    std.mem.sort(Span, spans, {}, Span.before);
    if (spans.len > 1) for (spans[1..], spans[0 .. spans.len - 1]) |x, prev| if (x.start < prev.end) return error.Malformed;

    for (msgs[0..nd]) |m| try r.takeDict(m.msg, m.enc.body);
    const batches = try arena.alloc(Chunk, nb);
    var total: u64 = 0;
    for (batches, msgs[nd..]) |*c, m| {
        c.* = try r.takeBatch(&top, m.msg, m.enc.body);
        total += @intCast(c.rb.length);
        if (total > opts.max_rows) return error.LimitExceeded;
    }
    try r.finishDicts();
    return .{ .r = r, .top = top, .batches = batches };
}

/// Every record batch of an Arrow IPC file as one frame (`openFile` + `File.readAll`).
pub fn readFile(arena: Allocator, bytes: []const u8, opts: ReadOptions) Error!df.Frame {
    var f = try openFile(arena, bytes, opts);
    return f.readAll();
}

/// The bytes one footer block's message occupies.
const Span = struct {
    start: usize,
    end: usize,

    fn before(_: void, x: Span, y: Span) bool {
        return x.start < y.start;
    }
};

/// The message a footer `Block` points at. The block's `metaDataLength` (framing and
/// padded metadata) and `bodyLength` must be the message's own: other readers read by
/// them, so a writer's wrong value would pass here and fail there.
fn readBlock(region: []const u8, raw: []const u8, span: *Span) Error!ipc.Read {
    const off = std.mem.readInt(i64, raw[0..8], .little);
    const meta_len = std.mem.readInt(i32, raw[8..12], .little);
    const body_len = std.mem.readInt(i64, raw[16..24], .little);
    if (off < 8 or off >= region.len) return error.Malformed;
    const start: usize = @intCast(off);
    var pos = start;
    const m = ipc.readMessage(region, &pos) catch |e| return noEos(e);
    const body_at = pos - m.enc.body.len;
    if (meta_len < 0 or body_len < 0) return error.Malformed;
    if (@as(usize, @intCast(meta_len)) != body_at - start or @as(u64, @intCast(body_len)) != m.enc.body.len) return error.Malformed;
    span.* = .{ .start = start, .end = pos };
    return m;
}

/// The planned top-level columns and the node/buffer counts a record batch must have;
/// the columns a projection picked (all, in order, without one) and the nodes and buffers
/// they own (null: all).
const Top = struct { fields: []RField, ctr: Counter, pick: []const usize, need: ?Need = null };

/// Which nodes and buffers of a record batch a projection decodes.
const Need = struct { nodes: []const bool, bufs: []const bool };
