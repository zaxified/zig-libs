// SPDX-License-Identifier: MIT
//! dataset — the canonical in-memory columnar-typed table: the seam between
//! data sources (SQL, JSON, synthetic) and consumers (widgets, reports, ETL).
//!
//! Every origin is normalized to one shape: `{ columns: [{name,type}], rows:
//! [[Value…]] }`. A row is a slice of `Value` with `row.len == columns.len`.
//! Consumers never see a source schema — only a `Dataset`.
//!
//! **Memory model (pure transform algebra):** a `Dataset` is an *immutable
//! view*. Transforms are `dataset → dataset`: they take an allocator
//! (normally an arena the caller owns for the whole pipeline) and return a
//! NEW `Dataset`. Structural arrays (columns, rows, per-row `Value` slices)
//! are allocated from that allocator; text payloads may be **borrowed** from
//! the input (shared slices — valid for the arena's lifetime) or freshly
//! allocated. Nothing is mutated in place, so borrowing is safe. Free
//! everything at once via the arena.
//!
//! Provenance: original work of the zig-libs authors (MIT). Modeled
//! loosely after the Arrow/Polars minimal-columnar-subset shape and the
//! pandas DataFrame mental model, but this is a row-major boxed-cell
//! representation (see the DEFER note below), not true columnar storage.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "Arrow/Polars minimal columnar subset; pandas DataFrame shape",
    .deps = .{},
};

// ── public API ──────────────────────────────────────────────────────────────

pub const ColumnType = enum {
    int,
    float,
    text,
    bool,
    /// ISO "YYYY-MM-DD" text, tagged so temporal transforms (resample/pivot/
    /// clamp_range) know to parse it. The cell value is still `Value.text`.
    date,
    /// Exact fixed-point money/quantity type. The cell value is `Value.decimal`
    /// (a raw `i128` at the sibling `decimal` module's scale — see there for
    /// the convention). Appended last so its ordinal (4→5 shift point) never
    /// collides with an already-serialized `.date` byte; do not reorder.
    decimal,
};

pub const Column = struct {
    name: []const u8,
    type: ColumnType,
};

/// Fixed-point scale for `Value.decimal`'s raw `i128`, matching the sibling
/// `decimal` module's `Decimal.scale_factor` (12 fractional digits). `dataset`
/// intentionally does NOT depend on the `decimal` module (stays a leaf
/// container) — it only stores/moves the raw integer. Consumers that need
/// arithmetic or display formatting wrap it themselves:
/// `decimal.Decimal{ .raw = value.decimal }`.
pub const decimal_scale: i128 = 1_000_000_000_000;

/// A single cell. `date` values live in `.text` (ISO); the column's
/// `ColumnType` carries the temporal intent. `decimal` is a raw fixed-point
/// `i128` at `decimal_scale` — see that constant's doc comment.
pub const Value = union(enum) {
    null,
    int: i64,
    float: f64,
    text: []const u8,
    bool: bool,
    decimal: i128,

    /// Coerce a numeric cell to f64 (int→float, float→float, decimal→float by
    /// dividing out the scale — lossy for values needing exact precision, use
    /// the raw `i128` directly for that). `null`/text/bool → null.
    pub fn asFloat(self: Value) ?f64 {
        return switch (self) {
            .int => |i| @floatFromInt(i),
            .float => |f| f,
            .decimal => |r| @as(f64, @floatFromInt(r)) / @as(f64, @floatFromInt(decimal_scale)),
            else => null,
        };
    }

    /// Coerce a numeric cell to i64. `int` passes through; `float` truncates
    /// toward zero; `decimal` truncates toward zero after dividing out the
    /// scale (null if the whole-unit part doesn't fit i64). `null`/text/bool
    /// → null.
    pub fn asInt(self: Value) ?i64 {
        return switch (self) {
            .int => |i| i,
            .float => |f| @intFromFloat(f),
            .decimal => |r| std.math.cast(i64, @divTrunc(r, decimal_scale)),
            else => null,
        };
    }

    pub fn asText(self: Value) ?[]const u8 {
        return switch (self) {
            .text => |t| t,
            else => null,
        };
    }

    pub fn isNull(self: Value) bool {
        return self == .null;
    }

    /// Value equality for group keys / dedup. Numeric int/float compare by
    /// f64; two `decimal`s compare exactly on the raw `i128` (not through the
    /// lossy f64 path) so equal-money values never spuriously mismatch or
    /// collide.
    pub fn eql(a: Value, b: Value) bool {
        if (a == .decimal and b == .decimal) return a.decimal == b.decimal;
        if (a.asFloat()) |af| {
            if (b.asFloat()) |bf| return af == bf;
            return false;
        }
        return switch (a) {
            .null => b == .null,
            .bool => |ab| b == .bool and b.bool == ab,
            .text => |at| if (b.asText()) |bt| std.mem.eql(u8, at, bt) else false,
            else => false,
        };
    }

    /// Ordering for sort. null sorts first; numerics (int/float/decimal) by
    /// value — two `decimal`s compare exactly on the raw `i128`; text
    /// lexicographic; bool false<true. Mixed types order by a stable type rank.
    pub fn order(a: Value, b: Value) std.math.Order {
        if (a == .decimal and b == .decimal) return std.math.order(a.decimal, b.decimal);
        if (a.asFloat()) |af| {
            if (b.asFloat()) |bf| return std.math.order(af, bf);
        }
        const ra = typeRank(a);
        const rb = typeRank(b);
        if (ra != rb) return std.math.order(ra, rb);
        return switch (a) {
            .text => |at| std.mem.order(u8, at, b.text),
            .bool => |ab| std.math.order(@intFromBool(ab), @intFromBool(b.bool)),
            else => .eq, // both null
        };
    }

    fn typeRank(v: Value) u8 {
        return switch (v) {
            .null => 0,
            .bool => 1,
            .int, .float, .decimal => 2,
            .text => 3,
        };
    }

    /// Coerce this cell to a target `ColumnType`, mirroring `asFloat`/`asInt`/
    /// `asText`'s conversion rules plus a couple of cheap widenings:
    /// int/float → bool is "nonzero" (matching how most SQL engines cast
    /// numerics to boolean); text/null → bool is not attempted (returns null,
    /// same as `asFloat`/`asInt` do for non-numeric input) since there is no
    /// single sane string-to-bool convention to bake in here. `date` uses the
    /// same representation as `text` (the column tag carries the intent), so
    /// coercing to `.date` just re-tags a `.text` cell; anything else → null.
    /// `.decimal` accepts `decimal` passthrough, `int` (widen ×scale) and
    /// `float` (multiply by scale, truncate toward zero; null on non-finite
    /// input) — text→decimal is intentionally NOT attempted here (parsing a
    /// decimal literal is the sibling `decimal` module's job; adding it here
    /// would require depending on it, which this module avoids).
    pub fn cast(self: Value, to: ColumnType) ?Value {
        return switch (to) {
            .int => if (self.asInt()) |i| .{ .int = i } else null,
            .float => if (self.asFloat()) |f| .{ .float = f } else null,
            .text, .date => if (self.asText()) |t| .{ .text = t } else null,
            .bool => switch (self) {
                .bool => self,
                .int => |i| .{ .bool = i != 0 },
                .float => |f| .{ .bool = f != 0 },
                else => null,
            },
            .decimal => switch (self) {
                .decimal => self,
                .int => |i| .{ .decimal = @as(i128, i) * decimal_scale },
                .float => |f| if (std.math.isFinite(f))
                    .{ .decimal = @intFromFloat(f * @as(f64, @floatFromInt(decimal_scale))) }
                else
                    null,
                else => null,
            },
        };
    }
};

pub const Dataset = struct {
    columns: []const Column,
    rows: []const []const Value,

    pub const ConcatError = error{ OutOfMemory, SchemaMismatch };

    /// Index of the column named `name`, or null.
    pub fn columnIndex(self: Dataset, name: []const u8) ?usize {
        for (self.columns, 0..) |c, i| {
            if (std.mem.eql(u8, c.name, name)) return i;
        }
        return null;
    }

    pub fn columnType(self: Dataset, name: []const u8) ?ColumnType {
        const i = self.columnIndex(name) orelse return null;
        return self.columns[i].type;
    }

    pub fn rowCount(self: Dataset) usize {
        return self.rows.len;
    }

    /// The cell at (row, column-name), or null if the column is absent.
    pub fn cell(self: Dataset, row: usize, name: []const u8) ?Value {
        const i = self.columnIndex(name) orelse return null;
        return self.rows[row][i];
    }

    // ── projections (thin; transforms/widgets own role→column projection at
    //    bind time, these exist for Zig-side transforms/tests) ──────────────

    /// Collect a numeric column into an owned `[]f64` (non-numeric/null → 0).
    pub fn floatColumn(self: Dataset, a: std.mem.Allocator, name: []const u8) ![]f64 {
        const i = self.columnIndex(name) orelse return error.NoSuchColumn;
        const out = try a.alloc(f64, self.rows.len);
        for (self.rows, 0..) |r, ri| out[ri] = r[i].asFloat() orelse 0;
        return out;
    }

    /// Project two columns into an owned `[][2]f64` series (x,y). Non-numeric x
    /// (e.g. a date column) → the row index as x.
    pub fn seriesXY(self: Dataset, a: std.mem.Allocator, x: []const u8, y: []const u8) ![]const [2]f64 {
        const xi = self.columnIndex(x) orelse return error.NoSuchColumn;
        const yi = self.columnIndex(y) orelse return error.NoSuchColumn;
        const out = try a.alloc([2]f64, self.rows.len);
        for (self.rows, 0..) |r, ri| {
            const xv = r[xi].asFloat() orelse @as(f64, @floatFromInt(ri));
            out[ri] = .{ xv, r[yi].asFloat() orelse 0 };
        }
        return out;
    }

    /// Append the rows of `other` after `self`'s, producing a NEW `Dataset`
    /// (per the module's transform-algebra memory model: nothing is mutated
    /// in place). `other` must have the same column count, names and types,
    /// in the same order — otherwise `error.SchemaMismatch`. Row slices are
    /// borrowed from both inputs (no cell copying); only the new `rows`
    /// backing array is freshly allocated from `a`.
    pub fn concat(self: Dataset, a: std.mem.Allocator, other: Dataset) ConcatError!Dataset {
        if (self.columns.len != other.columns.len) return error.SchemaMismatch;
        for (self.columns, other.columns) |sc, oc| {
            if (sc.type != oc.type or !std.mem.eql(u8, sc.name, oc.name))
                return error.SchemaMismatch;
        }
        const rows = try a.alloc([]const Value, self.rows.len + other.rows.len);
        @memcpy(rows[0..self.rows.len], self.rows);
        @memcpy(rows[self.rows.len..], other.rows);
        return .{ .columns = self.columns, .rows = rows };
    }
};

/// Incremental row-at-a-time construction, for building a `Dataset` from a
/// source that doesn't know its row count up front (a streamed query result,
/// an iterator-shaped parse, …) without pre-sizing an array. Follows the same
/// memory model as the rest of the module: `init` takes the allocator (and
/// the already-known column schema — schema is fixed for the life of the
/// builder, only rows stream in), `appendRow` copies the row's `Value` slice
/// (structural array, per the module's borrow rule — the `Value`s themselves,
/// e.g. `.text` payloads, may still point at caller-owned/borrowed memory),
/// and `toOwned` hands back a normal immutable `Dataset` backed by the same
/// allocator. Not thread-safe (a builder is a single-writer accumulator).
pub const Builder = struct {
    a: std.mem.Allocator,
    columns: []const Column,
    rows: std.ArrayList([]const Value) = .empty,

    pub fn init(a: std.mem.Allocator, columns: []const Column) Builder {
        return .{ .a = a, .columns = columns };
    }

    /// Append one row. `cells.len` must equal `columns.len` (asserted — a
    /// column-count mismatch is a caller bug, not a runtime data condition).
    /// The `cells` slice itself is copied (duped) into the builder's
    /// allocator; individual `Value`s (e.g. borrowed `.text` slices) are not
    /// deep-copied, matching the module's general borrow model.
    pub fn appendRow(self: *Builder, cells: []const Value) std.mem.Allocator.Error!void {
        std.debug.assert(cells.len == self.columns.len);
        const owned = try self.a.dupe(Value, cells);
        try self.rows.append(self.a, owned);
    }

    /// Finalize into an immutable `Dataset`. The builder's row list becomes
    /// the `Dataset`'s `rows` backing array (no extra copy); the builder must
    /// not be reused afterward (its `rows` list has been handed off).
    pub fn toOwned(self: *Builder) std.mem.Allocator.Error!Dataset {
        return .{ .columns = self.columns, .rows = try self.rows.toOwnedSlice(self.a) };
    }
};

// ── binary (de)serialization ────────────────────────────────────────────────
// Compact self-describing encoding so a Dataset can be stored in a byte-based
// cache (or shipped over a wire). Little-endian. Round-trips exactly.

pub const SerializeError = error{ OutOfMemory, TooLarge };
pub const DeserializeError = error{ Corrupt, OutOfMemory };

fn putU32(buf: *std.ArrayList(u8), a: std.mem.Allocator, v: u32) SerializeError!void {
    try buf.appendSlice(a, &std.mem.toBytes(v));
}

/// Narrow a `usize` length to the `u32` wire field, rejecting (rather than
/// silently truncating via `@intCast`) anything that would not round-trip.
fn lenU32(v: usize) SerializeError!u32 {
    return std.math.cast(u32, v) orelse error.TooLarge;
}

pub fn serialize(a: std.mem.Allocator, d: Dataset) SerializeError![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    try putU32(&buf, a, try lenU32(d.columns.len));
    for (d.columns) |col| {
        try putU32(&buf, a, try lenU32(col.name.len));
        try buf.appendSlice(a, col.name);
        try buf.append(a, @intFromEnum(col.type));
    }
    try putU32(&buf, a, try lenU32(d.rows.len));
    for (d.rows) |row| {
        for (row) |v| {
            switch (v) {
                .null => try buf.append(a, 0),
                .int => |i| {
                    try buf.append(a, 1);
                    try buf.appendSlice(a, &std.mem.toBytes(i));
                },
                .float => |f| {
                    try buf.append(a, 2);
                    try buf.appendSlice(a, &std.mem.toBytes(f));
                },
                .text => |t| {
                    try buf.append(a, 3);
                    try putU32(&buf, a, try lenU32(t.len));
                    try buf.appendSlice(a, t);
                },
                .bool => |b| {
                    try buf.append(a, 4);
                    try buf.append(a, if (b) 1 else 0);
                },
                // Tag 5 — appended, not inserted: existing 0..4 tags (and
                // whatever already-serialized bytes use them) never renumber.
                .decimal => |r| {
                    try buf.append(a, 5);
                    try buf.appendSlice(a, &std.mem.toBytes(r));
                },
            }
        }
    }
    return buf.toOwnedSlice(a);
}

const Cursor = struct {
    bytes: []const u8,
    pos: usize = 0,
    fn take(self: *Cursor, n: usize) DeserializeError![]const u8 {
        if (self.pos + n > self.bytes.len) return DeserializeError.Corrupt;
        defer self.pos += n;
        return self.bytes[self.pos .. self.pos + n];
    }
    fn u32v(self: *Cursor) DeserializeError!u32 {
        return std.mem.bytesToValue(u32, try self.take(4));
    }
    fn byte(self: *Cursor) DeserializeError!u8 {
        return (try self.take(1))[0];
    }
    fn remaining(self: *const Cursor) usize {
        return self.bytes.len - self.pos;
    }
};

/// Fewest bytes a single column's header can occupy: a 4-byte name length, a
/// zero-length name, and a 1-byte type tag.
const min_encoded_column_bytes = 5;

pub fn deserialize(a: std.mem.Allocator, bytes: []const u8) DeserializeError!Dataset {
    var cur = Cursor{ .bytes = bytes };
    const ncol = try cur.u32v();
    // ⚠ `ncol` is an attacker-supplied u32 and the next statement hands it
    // straight to an allocator. Unbounded, a 12-byte input can claim 4.29e9
    // columns and reserve ~100 GB — observed as a 32 GB `total-vm` OOM kill
    // during the first real fuzz sweep, which is how this was found.
    //
    // The bound is not an arbitrary cap but a consequence of the encoding:
    // every column costs at least `min_encoded_column_bytes`, so a claim
    // larger than the remaining input can supply is provably a lie and can be
    // rejected before a single byte is allocated. Same shape as the `raft`,
    // `df-elect` and `threshold_ecdsa` findings.
    if (ncol > cur.remaining() / min_encoded_column_bytes) return DeserializeError.Corrupt;
    const cols = try a.alloc(Column, ncol);
    for (cols) |*col| {
        const nlen = try cur.u32v();
        col.name = try a.dupe(u8, try cur.take(nlen));
        const tb = try cur.byte();
        if (tb >= @typeInfo(ColumnType).@"enum".fields.len) return DeserializeError.Corrupt;
        col.type = @enumFromInt(tb);
    }
    const nrow = try cur.u32v();
    // Same rule for rows, and it multiplies: each row allocates `ncol` values,
    // so an unchecked `nrow` scales an already-large per-row cost. Every value
    // costs at least its 1-byte type tag, so a row costs at least `ncol`
    // bytes. `@max(1, ...)` covers the degenerate zero-column case, where a
    // row encodes to nothing at all and the count would otherwise stay
    // unbounded — such rows carry no data, so bounding them by the input
    // length loses nothing.
    if (nrow > cur.remaining() / @max(1, ncol)) return DeserializeError.Corrupt;
    const rows = try a.alloc([]const Value, nrow);
    for (rows) |*row| {
        const r = try a.alloc(Value, ncol);
        for (r) |*v| {
            v.* = switch (try cur.byte()) {
                0 => .null,
                1 => .{ .int = std.mem.bytesToValue(i64, try cur.take(8)) },
                2 => .{ .float = std.mem.bytesToValue(f64, try cur.take(8)) },
                3 => blk: {
                    const tlen = try cur.u32v();
                    break :blk .{ .text = try a.dupe(u8, try cur.take(tlen)) };
                },
                4 => .{ .bool = (try cur.byte()) != 0 },
                5 => .{ .decimal = std.mem.bytesToValue(i128, try cur.take(16)) },
                else => return DeserializeError.Corrupt,
            };
        }
        row.* = r;
    }
    return .{ .columns = cols, .rows = rows };
}

// ── JSON encoding ────────────────────────────────────────────────────────────
// Emits a fixed, dependency-free shape:
//   {"columns":[{"name":..,"type":..}],"rows":[[..],..]}
// Non-finite floats and null cells become JSON null.

pub fn toJson(a: std.mem.Allocator, d: Dataset) SerializeError![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    try buf.appendSlice(a, "{\"columns\":[");
    for (d.columns, 0..) |col, i| {
        if (i > 0) try buf.append(a, ',');
        try buf.appendSlice(a, "{\"name\":");
        try appendJsonString(a, &buf, col.name);
        try buf.appendSlice(a, ",\"type\":\"");
        try buf.appendSlice(a, @tagName(col.type));
        try buf.appendSlice(a, "\"}");
    }
    try buf.appendSlice(a, "],\"rows\":[");
    for (d.rows, 0..) |row, ri| {
        if (ri > 0) try buf.append(a, ',');
        try buf.append(a, '[');
        for (row, 0..) |v, ci| {
            if (ci > 0) try buf.append(a, ',');
            try appendJsonValue(a, &buf, v);
        }
        try buf.append(a, ']');
    }
    try buf.appendSlice(a, "]}");
    return buf.toOwnedSlice(a);
}

fn appendJsonValue(a: std.mem.Allocator, buf: *std.ArrayList(u8), v: Value) SerializeError!void {
    switch (v) {
        .null => try buf.appendSlice(a, "null"),
        .bool => |b| try buf.appendSlice(a, if (b) "true" else "false"),
        .int => |i| try buf.print(a, "{d}", .{i}),
        .float => |f| if (std.math.isFinite(f)) try buf.print(a, "{d}", .{f}) else try buf.appendSlice(a, "null"),
        .text => |t| try appendJsonString(a, buf, t),
        .decimal => |r| try appendJsonDecimal(a, buf, r),
    }
}

/// Emit a `decimal` raw `i128` as an EXACT JSON number literal (not the lossy
/// f64 path `appendJsonValue` uses for `.float`): place the decimal point by
/// `decimal_scale` directly on the integer, so e.g. raw `1_500_000_000_000`
/// (scale 1e12) becomes the literal `1.5`, never a binary-float
/// approximation. Trailing fractional zeros are trimmed; a whole-unit value
/// (zero fraction) is emitted with no decimal point at all.
fn appendJsonDecimal(a: std.mem.Allocator, buf: *std.ArrayList(u8), raw: i128) SerializeError!void {
    if (raw < 0) try buf.append(a, '-');
    const mag: u128 = @intCast(@abs(raw));
    const scale: u128 = @intCast(decimal_scale);
    const int_part = mag / scale;
    const frac = mag % scale;
    try buf.print(a, "{d}", .{int_part});
    if (frac != 0) {
        // Zero-pad the fraction to the scale's digit width, then trim
        // trailing zeros (e.g. 500_000_000_000 / 1e12 -> "5", not
        // "500000000000").
        var digits: [12]u8 = undefined;
        comptime std.debug.assert(digits.len == std.math.log10_int(@as(u128, @intCast(decimal_scale))));
        var tmp = frac;
        var i: usize = digits.len;
        while (i > 0) {
            i -= 1;
            digits[i] = '0' + @as(u8, @intCast(tmp % 10));
            tmp /= 10;
        }
        var end: usize = digits.len;
        while (end > 0 and digits[end - 1] == '0') end -= 1;
        try buf.append(a, '.');
        try buf.appendSlice(a, digits[0..end]);
    }
}

fn appendJsonString(a: std.mem.Allocator, buf: *std.ArrayList(u8), s: []const u8) SerializeError!void {
    try buf.append(a, '"');
    for (s) |ch| {
        switch (ch) {
            '"' => try buf.appendSlice(a, "\\\""),
            '\\' => try buf.appendSlice(a, "\\\\"),
            '\n' => try buf.appendSlice(a, "\\n"),
            '\r' => try buf.appendSlice(a, "\\r"),
            '\t' => try buf.appendSlice(a, "\\t"),
            0...8, 11, 12, 14...31 => try buf.print(a, "\\u{x:0>4}", .{ch}),
            else => try buf.append(a, ch),
        }
    }
    try buf.append(a, '"');
}

// ── date helpers (ISO YYYY-MM-DD) ───────────────────────────────────────────

pub const Date = struct {
    y: i32,
    m: u8,
    d: u8,

    /// A monotonic comparable ordinal (proleptic-Gregorian day count via
    /// Howard Hinnant's days-from-civil algorithm). Good for range filtering
    /// and ordering: equal dates compare equal, later dates compare greater.
    /// **Not asserted to be calendar-exact beyond that monotonicity** (e.g. it
    /// is not independently verified against every historical calendar
    /// reform) — treat it as an ordering key, not a source of truth for
    /// calendar arithmetic.
    pub fn ordinal(self: Date) i64 {
        var y: i64 = self.y;
        var m: i64 = self.m;
        // shift Jan/Feb to end of previous year (Howard Hinnant's days algorithm)
        if (m <= 2) {
            y -= 1;
            m += 12;
        }
        const era = @divFloor(if (y >= 0) y else y - 399, 400);
        const yoe = y - era * 400;
        const doy = @divFloor(153 * (m - 3) + 2, 5) + self.d - 1;
        const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
        return era * 146097 + doe - 719468;
    }
};

/// Parse "YYYY-MM-DD" (extra trailing time is ignored). Returns null on malformed.
pub fn parseIsoDate(s: []const u8) ?Date {
    if (s.len < 10) return null;
    if (s[4] != '-' or s[7] != '-') return null;
    const y = std.fmt.parseInt(i32, s[0..4], 10) catch return null;
    const m = std.fmt.parseInt(u8, s[5..7], 10) catch return null;
    const d = std.fmt.parseInt(u8, s[8..10], 10) catch return null;
    if (m < 1 or m > 12 or d < 1 or d > 31) return null;
    return .{ .y = y, .m = m, .d = d };
}

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;

test "columnIndex / cell / floatColumn" {
    const cols = [_]Column{
        .{ .name = "sym", .type = .text },
        .{ .name = "mv", .type = .float },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "AAA" }, .{ .float = 10 } },
        &.{ .{ .text = "BBB" }, .{ .int = 20 } },
    };
    const ds = Dataset{ .columns = &cols, .rows = &rows };
    try testing.expectEqual(@as(?usize, 1), ds.columnIndex("mv"));
    try testing.expectEqual(@as(?usize, null), ds.columnIndex("nope"));
    try testing.expectEqualStrings("BBB", ds.cell(1, "sym").?.text);

    const mv = try ds.floatColumn(testing.allocator, "mv");
    defer testing.allocator.free(mv);
    try testing.expectEqual(@as(f64, 10), mv[0]);
    try testing.expectEqual(@as(f64, 20), mv[1]); // int coerced
}

test "Dataset.seriesXY: projects distinct x/y columns; non-numeric x falls back to the row index" {
    // Zero call sites anywhere else in the module — this is the only test.
    const cols = [_]Column{
        .{ .name = "sym", .type = .text },
        .{ .name = "day", .type = .int },
        .{ .name = "mv", .type = .float },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "AAA" }, .{ .int = 1 }, .{ .float = 10 } },
        &.{ .{ .text = "BBB" }, .{ .int = 2 }, .{ .float = 20 } },
    };
    const ds = Dataset{ .columns = &cols, .rows = &rows };

    // Numeric x: uses the actual column value, and y is genuinely the OTHER
    // column (a swapped x/y bug would still pass if this test only checked
    // one of the two coordinates against the same source column).
    const xy = try ds.seriesXY(testing.allocator, "day", "mv");
    defer testing.allocator.free(xy);
    try testing.expectEqual(@as(f64, 1), xy[0][0]);
    try testing.expectEqual(@as(f64, 10), xy[0][1]);
    try testing.expectEqual(@as(f64, 2), xy[1][0]);
    try testing.expectEqual(@as(f64, 20), xy[1][1]);

    // Non-numeric x (text column) -> the row index is used as x instead.
    const xy2 = try ds.seriesXY(testing.allocator, "sym", "mv");
    defer testing.allocator.free(xy2);
    try testing.expectEqual(@as(f64, 0), xy2[0][0]);
    try testing.expectEqual(@as(f64, 10), xy2[0][1]);
    try testing.expectEqual(@as(f64, 1), xy2[1][0]);
    try testing.expectEqual(@as(f64, 20), xy2[1][1]);

    try testing.expectError(error.NoSuchColumn, ds.seriesXY(testing.allocator, "nope", "mv"));
    try testing.expectError(error.NoSuchColumn, ds.seriesXY(testing.allocator, "day", "nope"));
}

test "Value.eql and order" {
    try testing.expect(Value.eql(.{ .int = 3 }, .{ .float = 3.0 }));
    try testing.expect(!Value.eql(.{ .text = "a" }, .{ .text = "b" }));
    try testing.expectEqual(std.math.Order.lt, Value.order(.{ .float = 1 }, .{ .float = 2 }));
    try testing.expectEqual(std.math.Order.lt, Value.order(.null, .{ .int = 0 }));
}

test "Value.eql/order: bool values compared by actual value, and bool's type rank sits between null and numeric" {
    // Neither eql's .bool arm nor order's .bool arm (nor typeRank's bool=1
    // placement) had ANY test anywhere in this suite before this — every
    // existing eql/order test used int/float/text/decimal/null only.
    try testing.expect(Value.eql(.{ .bool = true }, .{ .bool = true }));
    try testing.expect(Value.eql(.{ .bool = false }, .{ .bool = false }));
    try testing.expect(!Value.eql(.{ .bool = true }, .{ .bool = false }));
    try testing.expect(!Value.eql(.{ .bool = false }, .{ .bool = true }));

    try testing.expectEqual(std.math.Order.eq, Value.order(.{ .bool = true }, .{ .bool = true }));
    try testing.expectEqual(std.math.Order.lt, Value.order(.{ .bool = false }, .{ .bool = true }));
    try testing.expectEqual(std.math.Order.gt, Value.order(.{ .bool = true }, .{ .bool = false }));

    // Documented ordering: null < bool < numeric < text.
    try testing.expectEqual(std.math.Order.lt, Value.order(.null, .{ .bool = false }));
    try testing.expectEqual(std.math.Order.lt, Value.order(.{ .bool = true }, .{ .int = 0 }));
    try testing.expectEqual(std.math.Order.lt, Value.order(.{ .bool = true }, .{ .text = "" }));
}

test "Value.asInt and cast" {
    try testing.expectEqual(@as(?i64, 3), (Value{ .int = 3 }).asInt());
    try testing.expectEqual(@as(?i64, 3), (Value{ .float = 3.9 }).asInt()); // truncates
    try testing.expectEqual(@as(?i64, null), (Value{ .text = "x" }).asInt());

    try testing.expectEqual(@as(?f64, 3.0), (Value{ .int = 3 }).cast(.float).?.asFloat());
    try testing.expect((Value{ .float = 1.0 }).cast(.bool).?.bool);
    try testing.expect(!(Value{ .int = 0 }).cast(.bool).?.bool);
    try testing.expectEqual(@as(?Value, null), (Value{ .text = "x" }).cast(.bool));
    try testing.expectEqualStrings("AAA", (Value{ .text = "AAA" }).cast(.date).?.text);
    try testing.expectEqual(@as(?Value, null), (Value{ .bool = true }).cast(.int));
}

test "serialize / deserialize round-trip" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{
        .{ .name = "sym", .type = .text },
        .{ .name = "mv", .type = .float },
        .{ .name = "qty", .type = .int },
        .{ .name = "flag", .type = .bool },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "AAA" }, .{ .float = 100.5 }, .{ .int = 3 }, .{ .bool = true } },
        &.{ .null, .{ .float = -0.25 }, .{ .int = -7 }, .{ .bool = false } },
    };
    const src = Dataset{ .columns = &cols, .rows = &rows };
    const bytes = try serialize(a, src);
    const out = try deserialize(a, bytes);
    try testing.expectEqual(src.columns.len, out.columns.len);
    try testing.expectEqual(src.rows.len, out.rows.len);
    try testing.expectEqualStrings("AAA", out.cell(0, "sym").?.text);
    try testing.expectEqual(@as(f64, 100.5), out.cell(0, "mv").?.float);
    try testing.expectEqual(@as(i64, -7), out.cell(1, "qty").?.int);
    try testing.expect(out.cell(0, "flag").?.bool);
    try testing.expect(out.cell(1, "sym").?.isNull());
    try testing.expectEqual(ColumnType.bool, out.columns[3].type);
    try testing.expectError(DeserializeError.Corrupt, deserialize(a, bytes[0 .. bytes.len - 3]));
}

test "serialize rejects a length that overflows the u32 wire field" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // A slice whose *length* exceeds u32 max (its bytes are never touched: the
    // guard fires before any iteration/copy). Crafting the fat pointer this way
    // avoids allocating >4 GiB just to exercise the boundary. Previously this
    // reached `@intCast`, which panics in safe builds instead of erroring.
    var one = [_]Column{.{ .name = "x", .type = .int }};
    const oversized: []const Column = @as([*]const Column, &one)[0..(@as(usize, 1) << 33)];
    try testing.expectError(error.TooLarge, serialize(a, .{ .columns = oversized, .rows = &.{} }));

    // Same guard on an over-long text cell value.
    var byte = [_]u8{0};
    const huge_text: []const u8 = @as([*]const u8, &byte)[0..(@as(usize, 1) << 33)];
    const cols = [_]Column{.{ .name = "t", .type = .text }};
    const rows = [_][]const Value{&.{.{ .text = huge_text }}};
    try testing.expectError(error.TooLarge, serialize(a, .{ .columns = &cols, .rows = &rows }));
}

test "toJson emits the {columns,rows} shape" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{
        .{ .name = "sym", .type = .text },
        .{ .name = "mv", .type = .float },
        .{ .name = "qty", .type = .int },
    };
    const rows = [_][]const Value{
        &.{ .{ .text = "A\"B" }, .{ .float = 100.5 }, .{ .int = 3 } },
        &.{ .null, .{ .float = std.math.inf(f64) }, .{ .int = -7 } },
    };
    const json = try toJson(a, .{ .columns = &cols, .rows = &rows });
    try testing.expectEqualStrings(
        "{\"columns\":[{\"name\":\"sym\",\"type\":\"text\"},{\"name\":\"mv\",\"type\":\"float\"},{\"name\":\"qty\",\"type\":\"int\"}]," ++
            "\"rows\":[[\"A\\\"B\",100.5,3],[null,null,-7]]}",
        json,
    );
}

test "parseIsoDate and ordinal monotonicity" {
    const a = parseIsoDate("2024-01-31").?;
    const b = parseIsoDate("2024-02-01").?;
    try testing.expect(a.ordinal() < b.ordinal());
    try testing.expectEqual(@as(i64, 1), b.ordinal() - a.ordinal());
    try testing.expectEqual(@as(?Date, null), parseIsoDate("bad"));
    // a well-known anchor: 1970-01-01 is ordinal 0
    try testing.expectEqual(@as(i64, 0), (parseIsoDate("1970-01-01").?).ordinal());
}

test "Dataset.concat appends rows of a same-schema dataset" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{
        .{ .name = "sym", .type = .text },
        .{ .name = "mv", .type = .float },
    };
    const rows1 = [_][]const Value{
        &.{ .{ .text = "AAA" }, .{ .float = 10 } },
    };
    const rows2 = [_][]const Value{
        &.{ .{ .text = "BBB" }, .{ .float = 20 } },
        &.{ .{ .text = "CCC" }, .{ .float = 30 } },
    };
    const d1 = Dataset{ .columns = &cols, .rows = &rows1 };
    const d2 = Dataset{ .columns = &cols, .rows = &rows2 };

    const out = try d1.concat(a, d2);
    try testing.expectEqual(@as(usize, 3), out.rowCount());
    try testing.expectEqualStrings("AAA", out.cell(0, "sym").?.text);
    try testing.expectEqualStrings("BBB", out.cell(1, "sym").?.text);
    try testing.expectEqualStrings("CCC", out.cell(2, "sym").?.text);
    try testing.expectEqual(@as(f64, 30), out.cell(2, "mv").?.float);

    // Mismatched schema (different column name) -> error.
    const other_cols = [_]Column{
        .{ .name = "sym", .type = .text },
        .{ .name = "qty", .type = .float }, // renamed
    };
    const d3 = Dataset{ .columns = &other_cols, .rows = &rows2 };
    try testing.expectError(error.SchemaMismatch, d1.concat(a, d3));

    // Mismatched column count -> error.
    const d4 = Dataset{ .columns = cols[0..1], .rows = &rows2 };
    try testing.expectError(error.SchemaMismatch, d1.concat(a, d4));
}

// ── decimal ──────────────────────────────────────────────────────────────────

test "Value.decimal: asFloat/asInt coercion" {
    const v = Value{ .decimal = 1_500_000_000_000 }; // 1.5 at scale 1e12
    try testing.expectEqual(@as(f64, 1.5), v.asFloat().?);
    try testing.expectEqual(@as(?i64, 1), v.asInt().?); // truncates toward zero

    const neg = Value{ .decimal = -2_250_000_000_000 }; // -2.25
    try testing.expectEqual(@as(f64, -2.25), neg.asFloat().?);
    try testing.expectEqual(@as(?i64, -2), neg.asInt().?);

    try testing.expectEqual(@as(?[]const u8, null), v.asText());
}

test "Value.decimal: eql/order compare exactly on the raw i128, not lossy f64" {
    const a = Value{ .decimal = 1_000_000_000_001 }; // 1.000000000001
    const b = Value{ .decimal = 1_000_000_000_002 }; // 1.000000000002 — 1 ULP apart at scale 1e12
    try testing.expect(!Value.eql(a, b));
    try testing.expectEqual(std.math.Order.lt, Value.order(a, b));
    try testing.expect(Value.eql(a, .{ .decimal = 1_000_000_000_001 }));

    // Cross-type: decimal vs int/float still compares numerically via the
    // asFloat path (documented lossy fallback for mixed-type comparison).
    try testing.expect(Value.eql(.{ .decimal = 3_000_000_000_000 }, .{ .int = 3 }));
    try testing.expectEqual(std.math.Order.lt, Value.order(.{ .decimal = 1_000_000_000_000 }, .{ .int = 2 }));

    // null < bool < numeric(int/float/decimal) < text — decimal shares the
    // numeric rank.
    try testing.expectEqual(std.math.Order.lt, Value.order(.null, .{ .decimal = 0 }));
    try testing.expectEqual(std.math.Order.lt, Value.order(.{ .decimal = 0 }, .{ .text = "x" }));
}

test "Value.cast: float<->decimal and int<->decimal coercion" {
    const from_int = (Value{ .int = 7 }).cast(.decimal).?;
    try testing.expectEqual(@as(i128, 7_000_000_000_000), from_int.decimal);

    const from_float = (Value{ .float = 2.5 }).cast(.decimal).?;
    try testing.expectEqual(@as(i128, 2_500_000_000_000), from_float.decimal);

    // -0.5 is exact in binary floating point, so this exercises the negative
    // path with no rounding ambiguity.
    const from_neg_float = (Value{ .float = -0.5 }).cast(.decimal).?;
    try testing.expectEqual(@as(i128, -500_000_000_000), from_neg_float.decimal);

    // non-finite float -> null, not a crash/UB.
    try testing.expectEqual(@as(?Value, null), (Value{ .float = std.math.inf(f64) }).cast(.decimal));
    try testing.expectEqual(@as(?Value, null), (Value{ .float = std.math.nan(f64) }).cast(.decimal));

    // decimal -> float / int round-trips through the general asFloat/asInt path.
    const d = Value{ .decimal = 4_250_000_000_000 };
    try testing.expectEqual(@as(f64, 4.25), d.cast(.float).?.float);
    try testing.expectEqual(@as(i64, 4), d.cast(.int).?.int);

    // decimal passthrough.
    try testing.expectEqual(@as(i128, 4_250_000_000_000), d.cast(.decimal).?.decimal);

    // text -> decimal intentionally not attempted (documented: would need the
    // `decimal` module's parser).
    try testing.expectEqual(@as(?Value, null), (Value{ .text = "1.5" }).cast(.decimal));
}

test "decimal serialize/deserialize round-trips exactly (positive control: exact money sum)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{
        .{ .name = "sym", .type = .text },
        .{ .name = "price", .type = .decimal },
    };
    // 0.1 + 0.2 in f64 famously != 0.3; exact decimal cents must not drift.
    const rows = [_][]const Value{
        &.{ .{ .text = "A" }, .{ .decimal = 100_000_000_000 } }, // 0.1
        &.{ .{ .text = "B" }, .{ .decimal = 200_000_000_000 } }, // 0.2
    };
    const src = Dataset{ .columns = &cols, .rows = &rows };
    const bytes = try serialize(a, src);
    const out = try deserialize(a, bytes);

    try testing.expectEqual(ColumnType.decimal, out.columns[1].type);
    const sum = out.cell(0, "price").?.decimal + out.cell(1, "price").?.decimal;
    try testing.expectEqual(@as(i128, 300_000_000_000), sum); // exact 0.3, no f64 rounding noise
    try testing.expect(Value.eql(.{ .decimal = 300_000_000_000 }, .{ .decimal = sum }));

    // A well-formed header (1 int column, 1 row) whose sole cell tag byte is
    // 99 (not one of the valid 0..5 tags) must error, not panic.
    const bad_tag = [_]u8{
        1, 0, 0, 0, // ncol = 1
        0, 0, 0, 0, // column-name length = 0
        0, // column type = int (0)
        1, 0, 0, 0, // nrow = 1
        99, // cell tag — invalid
    };
    try testing.expectError(DeserializeError.Corrupt, deserialize(a, &bad_tag));
}

test "toJson emits decimal as an exact placed-point number, not lossy f64" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{.{ .name = "amt", .type = .decimal }};
    const rows = [_][]const Value{
        &.{.{ .decimal = 1_500_000_000_000 }}, // 1.5
        &.{.{ .decimal = -2_000_000_000_000 }}, // -2 (whole unit, no fraction)
        &.{.{ .decimal = 1 }}, // 0.000000000001 (smallest sub-unit)
        &.{.{ .decimal = 0 }}, // 0
    };
    const json = try toJson(a, .{ .columns = &cols, .rows = &rows });
    try testing.expectEqualStrings(
        "{\"columns\":[{\"name\":\"amt\",\"type\":\"decimal\"}]," ++
            "\"rows\":[[1.5],[-2],[0.000000000001],[0]]}",
        json,
    );
}

test "Builder: incremental row-at-a-time construction" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{
        .{ .name = "sym", .type = .text },
        .{ .name = "qty", .type = .decimal },
    };
    var b = Builder.init(a, &cols);
    try b.appendRow(&.{ .{ .text = "A" }, .{ .decimal = 1_000_000_000_000 } });
    try b.appendRow(&.{ .{ .text = "B" }, .{ .decimal = 2_500_000_000_000 } });
    const ds = try b.toOwned();

    try testing.expectEqual(@as(usize, 2), ds.rowCount());
    try testing.expectEqualStrings("B", ds.cell(1, "sym").?.text);
    try testing.expectEqual(@as(i128, 2_500_000_000_000), ds.cell(1, "qty").?.decimal);

    // Round-trips through the normal Dataset machinery (serialize included).
    const bytes = try serialize(a, ds);
    const back = try deserialize(a, bytes);
    try testing.expectEqual(@as(i128, 1_000_000_000_000), back.cell(0, "qty").?.decimal);
}

// ── fuzz: deserialize is the untrusted-input decode surface (an arbitrary
// wire buffer, e.g. from a cache file or network peer) — must never panic
// or read/write out of bounds, only return the typed dataset or
// `DeserializeError.Corrupt`/`OutOfMemory`. Uses an arena (the module's
// documented ownership model — `Dataset` has no per-field free) so a
// successful decode is cleaned up in one shot regardless of how many
// strings it allocated.

test "deserialize: a wire-supplied count larger than the input can supply is rejected before allocating" {
    // The regression for the OOM found by the first real fuzz sweep. Twelve
    // bytes claiming 4.29e9 columns used to reach `alloc` and reserve tens of
    // GB; the process died to the cgroup's OOM killer rather than returning an
    // error. Both counts get their own case, because the row bound multiplies
    // by `ncol` and could plausibly be fixed for one and not the other.
    // Every case runs on an arena: this module's memory model is that a
    // failed `deserialize` does NOT unwind its partial allocations, because
    // callers own an arena for the whole pipeline. Handing it
    // `testing.allocator` reports a leak that is really the contract working.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // ncol = 0xFFFFFFFF, nothing else. Nowhere near 5 bytes per column left.
    const huge_ncol = "\xff\xff\xff\xff";
    try testing.expectError(DeserializeError.Corrupt, deserialize(a, huge_ncol));

    // One real column, then nrow = 0xFFFFFFFF with no row bytes behind it.
    const huge_nrow = "\x01\x00\x00\x00" ++ // ncol = 1
        "\x00\x00\x00\x00" ++ // name length 0
        "\x01" ++ // type tag
        "\xff\xff\xff\xff"; // nrow = 4294967295
    try testing.expectError(DeserializeError.Corrupt, deserialize(a, huge_nrow));

    // And the bound must not reject a legitimate document: a truncated-but-
    // plausible claim still has to fail on the DATA, not on the count, so the
    // check cannot simply be "reject anything large".
    const built = try deserialize(a, huge_nrow[0..9] ++ "\x00\x00\x00\x00");
    try testing.expectEqual(@as(usize, 1), built.columns.len);
    try testing.expectEqual(@as(usize, 0), built.rows.len);
}

test "fuzz: deserialize never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDeserialize, .{});
}

fn fuzzDeserialize(_: void, smith: *std.testing.Smith) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const d = deserialize(arena.allocator(), buf[0..len]) catch return;
    _ = d;
}
