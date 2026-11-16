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

pub const Error = error{ OutOfMemory, Malformed, Unsupported, LimitExceeded };

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
    /// The most bytes one compressed message body may expand to (the uncompressed lengths
    /// its buffers declare, summed); past it `error.LimitExceeded`. Bounds what a small
    /// compressed stream can make the reader allocate.
    max_body_bytes: u64 = 1 << 31,
    /// A value `dataframe` cannot hold reads as a null cell instead of failing the whole
    /// read with `error.Unsupported`: a Decimal128 that does not fit 12 fractional digits in
    /// an i128, a time of day outside `[0, 24h)` (Arrow allows 24:00:00), a date outside
    /// the years 0000-9999, a timestamp or duration in s/ms whose microseconds overflow
    /// i64. A timestamp zone `dataframe`'s `tz` does not know reads as a naive column (the
    /// instants are UTC either way; only the `time_zone` tag is dropped). Nothing else
    /// changes: a malformed stream is still an error.
    lossy: bool = false,
};

/// A selector entry meaning "a null cell" (also what `ColumnData.get` reads past the end).
const none = std.math.maxInt(usize);
const us_per_day: i64 = 86_400 * df.timestamp_units_per_second;

/// The physical layouts both directions handle.
const Kind = enum { null_, i8, i16, i32, i64, u8, u16, u32, u64, f16, f32, f64, bool_, dec, date32, date64, time32, time64, ts, dur, var32, var64, fsb, dict, list32, list64, fsl, struct_ };

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
                f.arrow = .{ .decimal = .{ .precision = 38, .scale = decimal_digits } };
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

    fn toField(w: *Writer, wf: *const WField) Error!schema.Field {
        var f: schema.Field = .{ .name = wf.name, .type = wf.arrow };
        if (wf.dict) |di| f.dictionary = .{ .id = @intCast(di), .ordered = w.dicts.items[di].ordered };
        const kids = try w.arena.alloc(schema.Field, wf.children.len);
        for (kids, wf.children) |*k, *c| k.* = try w.toField(c);
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
                        .text => |t| try data.appendSlice(a, t),
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
            .f16, .date64, .time32, .fsb, .list64 => return error.Unsupported, // never planned
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
    const sfields = try w.arena.alloc(schema.Field, fields.len);
    for (sfields, fields) |*s, *wf| s.* = try w.toField(wf);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    if (file) try out.appendSlice(gpa, magic ++ "\x00\x00");
    {
        var b = fb.Builder.init(gpa);
        defer b.deinit();
        try ipc.writeMessage(gpa, &out, try schema.encodeSchemaMessage(&b, .{ .fields = sfields }), &.{});
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
        const sref = try schema.encodeSchema(&b, .{ .fields = sfields });
        const dv = try blockVector(&b, w.tmp, dict_blocks.items);
        const rv = try blockVector(&b, w.tmp, batch_blocks.items);
        b.startTable();
        try b.addScalarForce(0, schema.MetadataVersion, .v5);
        try b.addOffset(1, sref);
        try b.addOffset(2, dv);
        try b.addOffset(3, rv);
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

const Chunk = struct { rb: ipc.RecordBatch, body: []const u8 };

const RField = struct {
    kind: Kind,
    col: Column,
    node_ix: usize,
    buf_ix: usize,
    unit: schema.TimeUnit = .microsecond,
    /// FixedSizeBinary width, FixedSizeList size.
    width: usize = 0,
    /// Decimal scale.
    scale: i32 = 0,
    /// Dictionary index type.
    index: schema.IntType = .{ .bits = 32, .signed = true },
    children: []RField = &.{},
    dict: ?*RDict = null,
};

const RDict = struct {
    id: i64,
    value: RField,
    nodes: usize,
    bufs: usize,
    ordered: bool,
    categorical: bool,
    chunks: std.ArrayList(Chunk) = .empty,
    data: ColumnData = .nulls,
    len: usize = 0,
};

const Counter = struct { nodes: usize = 0, bufs: usize = 0 };

const Reader = struct {
    a: Allocator,
    opts: ReadOptions,
    dicts: std.ArrayList(*RDict) = .empty,
    /// Made at the first zstd-compressed buffer (its tables come from the arena).
    zd: ?zstd.Decompressor = null,

    fn plan(r: *Reader, f: schema.Field, ctr: *Counter, depth: usize, in_dict: bool) Error!RField {
        if (depth >= schema.max_depth) return error.Malformed;
        var rf: RField = .{ .kind = .null_, .col = .{ .name = try r.a.dupe(u8, f.name), .type = .text }, .node_ix = ctr.nodes, .buf_ix = ctr.bufs };
        ctr.nodes += 1;
        if (f.dictionary) |d| {
            if (in_dict) return error.Unsupported; // a dictionary inside a dictionary's values
            for (r.dicts.items) |x| if (x.id == d.id) return error.Malformed;
            ctr.bufs += 2;
            rf.kind = .dict;
            rf.index = d.index;
            var vf = f;
            vf.dictionary = null;
            var vctr: Counter = .{};
            const rd = try r.a.create(RDict);
            rd.* = .{
                .id = d.id,
                .value = try r.plan(vf, &vctr, depth, true),
                .nodes = vctr.nodes,
                .bufs = vctr.bufs,
                .ordered = d.ordered,
                .categorical = vf.type == .utf8 or vf.type == .large_utf8,
            };
            try r.dicts.append(r.a, rd);
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
                if (d.bits != 128) return error.Unsupported;
                rf.kind = .dec;
                rf.scale = d.scale;
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
            .unsupported => return error.Unsupported,
        }
        ctr.bufs += bufs;
        return rf;
    }

    fn planAll(r: *Reader, s: schema.Schema) Error!Top {
        var ctr: Counter = .{};
        const fields = try r.a.alloc(RField, s.fields.len);
        for (fields, s.fields) |*rf, f| rf.* = try r.plan(f, &ctr, 0, false);
        return .{ .fields = fields, .ctr = ctr };
    }

    fn takeBatch(r: *Reader, top: *const Top, msg: schema.Message, body: []const u8) Error!Chunk {
        const h = msg.header orelse return error.Malformed;
        const rb = ipc.decodeRecordBatch(r.a, h, body.len) catch |e| return noEos(e);
        try r.checkBatch(rb, top.ctr, top.fields);
        return r.inflate(rb, body);
    }

    fn takeDict(r: *Reader, msg: schema.Message, body: []const u8) Error!void {
        const h = msg.header orelse return error.Malformed;
        const db = ipc.decodeDictionaryBatch(r.a, h, body.len) catch |e| return noEos(e);
        const d = for (r.dicts.items) |x| {
            if (x.id == db.id) break x;
        } else return error.Malformed;
        if (!db.is_delta and d.chunks.items.len > 0) return error.Unsupported; // replacement
        try r.checkBatch(db.data, .{ .nodes = d.nodes, .bufs = d.bufs }, (&d.value)[0..1]);
        try d.chunks.append(r.a, try r.inflate(db.data, body));
    }

    fn finishDicts(r: *Reader) Error!void {
        for (r.dicts.items) |d| {
            var n: u64 = 0;
            for (d.chunks.items) |c| n += @intCast(c.rb.length);
            if (n > r.opts.max_rows) return error.LimitExceeded;
            d.len = @intCast(n);
            d.data = try r.decode(&d.value, d.chunks.items);
        }
    }

    fn frame(r: *Reader, top: *const Top, chunks: []const Chunk) Error!df.Frame {
        var total: u64 = 0;
        for (chunks) |c| total += @intCast(c.rb.length);
        if (total > r.opts.max_rows) return error.LimitExceeded;
        const columns = try r.a.alloc(Column, top.fields.len);
        const data = try r.a.alloc(ColumnData, top.fields.len);
        for (columns, data, top.fields) |*c, *dd, *rf| {
            c.* = rf.col;
            dd.* = try r.decode(rf, chunks);
        }
        return .{ .columns = columns, .data = data, .len = @intCast(total) };
    }

    /// A batch's shape against the schema: node and buffer counts, every length within
    /// `max_rows`, every top-level column as long as the batch.
    fn checkBatch(r: *const Reader, rb: ipc.RecordBatch, ctr: Counter, top: []const RField) Error!void {
        if (rb.nodes.len != ctr.nodes or rb.buffers.len != ctr.bufs) return error.Malformed;
        if (@as(u64, @intCast(rb.length)) > r.opts.max_rows) return error.LimitExceeded;
        for (rb.nodes) |nd| _ = try r.rows(nd);
        for (top) |f| if (rb.nodes[f.node_ix].length != rb.length) return error.Malformed;
    }

    /// A batch whose body is compressed, with every buffer decompressed into one fresh body
    /// (a batch without compression is returned as it is). Each non-empty buffer starts with
    /// its uncompressed length as an `int64`: -1 means the rest is stored raw.
    fn inflate(r: *Reader, rb: ipc.RecordBatch, body: []const u8) Error!Chunk {
        const codec = rb.compression orelse return .{ .rb = rb, .body = body };
        // LZ4_FRAME: the collection has no LZ4 codec yet; any other value is not Arrow's.
        if (codec != .zstd) return error.Unsupported;
        var total: u64 = 0;
        for (rb.buffers) |l| {
            const src = locBytes(body, l);
            if (src.len == 0) continue;
            total +|= try rawLen(src);
            if (total > r.opts.max_body_bytes) return error.LimitExceeded;
        }
        const out = try r.a.alloc(u8, @intCast(total));
        const locs = try r.a.alloc(ipc.BufferLoc, rb.buffers.len);
        var at: usize = 0;
        for (rb.buffers, locs) |l, *o| {
            const src = locBytes(body, l);
            var n: usize = 0;
            if (src.len > 0) {
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
                const v = try r.raw(i128, rf, chunks, n, valid);
                for (v, 0..) |*x, i| x.* = rescale(x.*, rf.scale) catch try r.drop(&valid, n, i);
                break :blk typed("decimal", v, valid, n);
            },
            .ts, .dur => blk: {
                const v = try r.raw(i64, rf, chunks, n, valid);
                for (v, 0..) |*x, i| x.* = toMicros(x.*, rf.unit) catch try r.drop(&valid, n, i);
                break :blk typed("int", v, valid, n);
            },
            .time32, .time64 => blk: {
                const v = try r.a.alloc(i64, n);
                if (rf.kind == .time32) {
                    for (v, try r.raw(i32, rf, chunks, n, valid)) |*o, x| o.* = x;
                } else @memcpy(v, try r.raw(i64, rf, chunks, n, valid));
                for (v, 0..) |*x, i| {
                    x.* = toMicros(x.*, rf.unit) catch try r.drop(&valid, n, i);
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
                    for (days, try r.raw(i64, rf, chunks, n, valid)) |*o, x| o.* = @divFloor(x, 86_400_000);
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
                if (isSet(valid, base + i)) try bytes.appendSlice(r.a, data[lo..hi]);
                offsets[base + i + 1] = bytes.items.len;
            }
            base += len;
        }
        if (allNull(valid, n)) return .nulls;
        return .{ .text = .{ .offsets = offsets, .bytes = bytes.items, .valid = valid } };
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
        return gather(r.a, d.data, sel);
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
            items = try gather(r.a, items, sel);
        }
        if (allNull(valid, n)) return .nulls;
        const ip = try r.a.create(ColumnData);
        ip.* = items;
        return .{ .list = .{ .offsets = offsets, .items = ip, .valid = valid } };
    }
};

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

fn toMicros(x: i64, unit: schema.TimeUnit) Error!i64 {
    return switch (unit) {
        .second => std.math.mul(i64, x, 1_000_000) catch error.Unsupported,
        .millisecond => std.math.mul(i64, x, 1_000) catch error.Unsupported,
        .microsecond => x,
        // `dataframe` keeps microseconds; the digits past them are dropped (toward the earlier instant).
        .nanosecond => @divFloor(x, 1_000),
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

/// The rows `sel` of `data` (an entry `none` is a null row), as fresh storage.
fn gather(a: Allocator, data: ColumnData, sel: []const usize) Error!ColumnData {
    switch (data) {
        .nulls => return .nulls,
        .boxed => return error.Unsupported,
        .text => |t| {
            const offsets = try a.alloc(usize, sel.len + 1);
            var bytes: std.ArrayList(u8) = .empty;
            var vo: ValidOut = .{};
            offsets[0] = 0;
            for (sel, 0..) |row, i| {
                if (t.at(row)) |s| try bytes.appendSlice(a, s) else if (!t.isValid(row)) try vo.clear(a, sel.len, i);
                offsets[i + 1] = bytes.items.len;
            }
            return .{ .text = .{ .offsets = offsets, .bytes = bytes.items, .valid = vo.words } };
        },
        .categorical => |c| {
            const codes = try gather(a, .{ .uint32 = c.codes }, sel);
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
                    for (lv.start..lv.end) |e| try kids.append(a, e);
                } else try vo.clear(a, sel.len, i);
                offsets[i + 1] = std.math.cast(u32, kids.items.len) orelse return error.Unsupported;
            }
            const ip = try a.create(ColumnData);
            ip.* = try gather(a, l.items.*, kids.items);
            return .{ .list = .{ .offsets = offsets, .items = ip, .valid = vo.words } };
        },
        .@"struct" => |s| {
            var vo: ValidOut = .{};
            for (sel, 0..) |row, i| if (!s.isValid(row)) try vo.clear(a, sel.len, i);
            const kids = try a.alloc(ColumnData, s.children.len);
            for (kids, s.children) |*k, c| k.* = try gather(a, c, sel);
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

/// Reads an Arrow IPC stream into a frame allocated from `arena` (free it all with the
/// arena; nothing borrows `bytes`). Dictionary deltas are appended; a dictionary
/// REPLACED mid-stream, body compression, and the types `dataframe` has no column for
/// (Interval, Union, Map, the view types, Decimal other than 128-bit) are
/// `error.Unsupported`.
pub fn readStream(arena: Allocator, bytes: []const u8, opts: ReadOptions) Error!df.Frame {
    var r: Reader = .{ .a = arena, .opts = opts };
    var pos: usize = 0;
    const first = ipc.readMessage(bytes, &pos) catch |e| return noEos(e); // no schema
    if (first.msg.header_type != .schema) return error.Malformed;
    const s = try schema.decodeSchema(arena, first.msg.header orelse return error.Malformed);
    const top = try r.planAll(s);

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

    /// The rows of batch `i` (`i < batchCount()`).
    pub fn batchRows(self: *const File, i: usize) usize {
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

/// Opens an Arrow IPC file: checks both `ARROW1` marks, reads the footer's schema,
/// decodes every dictionary and checks every record batch's metadata (not its data,
/// which `File.readBatch` decodes on demand).
pub fn openFile(arena: Allocator, bytes: []const u8, opts: ReadOptions) Error!File {
    if (bytes.len < 8 + 10) return error.Malformed;
    if (!std.mem.eql(u8, bytes[0..6], magic) or !std.mem.eql(u8, bytes[bytes.len - 6 ..], magic)) return error.Malformed;
    const fend = bytes.len - 10;
    const flen = std.mem.readInt(i32, bytes[fend..][0..4], .little);
    if (flen <= 0 or @as(usize, @intCast(flen)) > fend - 8) return error.Malformed;
    const fstart = fend - @as(usize, @intCast(flen));
    const footer = try fb.root(bytes[fstart..fend]);
    var r: Reader = .{ .a = arena, .opts = opts };
    const s = try schema.decodeSchema(arena, try footer.table(1) orelse return error.Malformed);
    const top = try r.planAll(s);

    // The messages live between the leading mark and the footer.
    const region = bytes[0..fstart];
    if (try footer.vector(2)) |v| for (0..v.len) |i| {
        const m = try readBlock(region, try v.structAt(i, 24));
        if (m.msg.header_type != .dictionary_batch) return error.Malformed;
        try r.takeDict(m.msg, m.enc.body);
    };
    var batches: []Chunk = &.{};
    if (try footer.vector(3)) |v| {
        batches = try arena.alloc(Chunk, v.len);
        var total: u64 = 0;
        for (batches, 0..) |*c, i| {
            const m = try readBlock(region, try v.structAt(i, 24));
            if (m.msg.header_type != .record_batch) return error.Malformed;
            c.* = try r.takeBatch(&top, m.msg, m.enc.body);
            total += @intCast(c.rb.length);
            if (total > opts.max_rows) return error.LimitExceeded;
        }
    }
    try r.finishDicts();
    return .{ .r = r, .top = top, .batches = batches };
}

/// Every record batch of an Arrow IPC file as one frame (`openFile` + `File.readAll`).
pub fn readFile(arena: Allocator, bytes: []const u8, opts: ReadOptions) Error!df.Frame {
    var f = try openFile(arena, bytes, opts);
    return f.readAll();
}

fn readBlock(region: []const u8, raw: []const u8) Error!ipc.Read {
    const off = std.mem.readInt(i64, raw[0..8], .little);
    if (off < 8 or off >= region.len) return error.Malformed;
    var pos: usize = @intCast(off);
    return ipc.readMessage(region, &pos) catch |e| return noEos(e);
}

/// The planned top-level columns and the node/buffer counts a record batch must have.
const Top = struct { fields: []RField, ctr: Counter };
