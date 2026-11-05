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
//!
//! `Frame` (2026-11) is the same table stored by column, next to `Dataset`, with the
//! same wire format and JSON document. See the section "Frame" below.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Canonical in-memory columnar-typed table — the normalization seam between data sources and consumers.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
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
    /// An instant on the UTC timeline. The cell value is `Value.int`: whole
    /// MICROseconds since 1970-01-01T00:00:00Z (`timestamp_units_per_second`),
    /// the unit of PostgreSQL's and DuckDB's `TIMESTAMP` and of Arrow's
    /// `timestamp[us]`. Like `.date`, the column tag carries the intent and the
    /// cell reuses an existing `Value` variant — so the wire format gets no new
    /// value tag and no consumer `switch` over `Value` breaks. Text in, text
    /// out: `parseIsoTimestamp` / `formatIsoTimestamp`; `toJson` renders the
    /// cells of a `.timestamp` column as RFC 3339 strings. Appended last (wire
    /// ordinal 6); do not reorder.
    timestamp,
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

/// Unit of a `.timestamp` cell: `Value.int` counts microseconds since the Unix
/// epoch (UTC). An `i64` of microseconds spans roughly ±292 000 years, so every
/// instant `parseIsoTimestamp` accepts (years 0000–9999) fits with room to spare.
pub const timestamp_units_per_second: i64 = 1_000_000;
const us_per_day: i64 = 86_400 * timestamp_units_per_second;

/// A single cell. `date` values live in `.text` (ISO) and `timestamp` values in
/// `.int` (microseconds since the epoch); the column's `ColumnType` carries the
/// temporal intent. `decimal` is a raw fixed-point `i128` at `decimal_scale` —
/// see that constant's doc comment.
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

    /// Truncate an `f64` toward zero into `T`, or null if it does not fit.
    ///
    /// ⚠ `@intFromFloat` on an out-of-range or non-finite operand is
    /// **undefined behaviour**: it panics in Debug and ReleaseSafe and yields
    /// silent garbage in ReleaseFast, so it is not a conversion a caller can
    /// hand untrusted numbers to. Two sites here did exactly that, and one of
    /// them checked the WRONG VALUE — `isFinite(f)` guarding a cast of
    /// `f * decimal_scale`, which is a different number by twelve orders of
    /// magnitude. `1e30` is finite; `1e42` does not fit `i128`.
    ///
    /// The comparison is done in `f64` against the bound converted to `f64`,
    /// and uses `<`/`>` on values that are exactly representable, so the
    /// rounding at the edge cannot let an out-of-range value through.
    pub fn floatToInt(comptime T: type, f: f64) ?T {
        if (!std.math.isFinite(f)) return null;
        const lo: f64 = @floatFromInt(std.math.minInt(T));
        const hi: f64 = @floatFromInt(std.math.maxInt(T));
        // `hi` rounds UP to the nearest representable f64 for wide T, so a
        // value equal to it may still not fit; `>=` is the safe comparison.
        if (f < lo or f >= hi) return null;
        return @intFromFloat(f);
    }

    /// Coerce a numeric cell to i64. `int` passes through; `float` truncates
    /// toward zero (null if it does not fit i64, including NaN and infinity);
    /// `decimal` truncates toward zero after dividing out the scale (null if
    /// the whole-unit part doesn't fit i64). `null`/text/bool → null.
    pub fn asInt(self: Value) ?i64 {
        return switch (self) {
            .int => |i| i,
            .float => |f| floatToInt(i64, f),
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

    /// Value equality for group keys / dedup. Numerics (int / float / decimal)
    /// compare by EXACT value across all three kinds -- never through a lossy
    /// `f64` -- so `eql` agrees with `order` (`order == .eq`) and two distinct
    /// ints above 2^53 are never equal; a NaN equals nothing, itself included.
    pub fn eql(a: Value, b: Value) bool {
        if (isNumeric(a) and isNumeric(b)) {
            if (isNanValue(a) or isNanValue(b)) return false;
            return orderNumeric(a, b) == .eq;
        }
        return switch (a) {
            .null => b == .null,
            .bool => |ab| b == .bool and b.bool == ab,
            .text => |at| if (b.asText()) |bt| std.mem.eql(u8, at, bt) else false,
            else => false,
        };
    }

    /// Ordering for sort: a strict weak order (total on equivalence classes),
    /// which `std.sort` needs -- its block sort documents that it "only works
    /// when the comparison is less-than or greater-than" (`std/sort/block.zig`)
    /// and a comparator that is not transitive can leave it with wrong output.
    /// null sorts first; numerics (int/float/decimal) by EXACT value across the
    /// three kinds (an `i64` above 2^53 is not rounded to a float, a decimal's
    /// raw `i128` is compared against ints and floats without rounding); text
    /// lexicographic; bool false<true. Mixed kinds order by a stable type rank.
    /// **NaN sorts last** (greater than every other numeric value, including
    /// +inf; two NaNs compare equal to each other) -- see `orderNumeric`.
    /// `deserialize` can hand a `.float` cell any bit pattern from 8 wire
    /// bytes, NaN included, with no finiteness check.
    pub fn order(a: Value, b: Value) std.math.Order {
        if (isNumeric(a) and isNumeric(b)) return orderNumeric(a, b);
        const ra = typeRank(a);
        const rb = typeRank(b);
        if (ra != rb) return std.math.order(ra, rb);
        return switch (a) {
            .text => |at| std.mem.order(u8, at, b.text),
            .bool => |ab| std.math.order(@intFromBool(ab), @intFromBool(b.bool)),
            else => .eq, // both null
        };
    }

    fn isNumeric(v: Value) bool {
        return switch (v) {
            .int, .float, .decimal => true,
            else => false,
        };
    }

    fn isNanValue(v: Value) bool {
        return v == .float and std.math.isNan(v.float);
    }

    /// Exact three-kind numeric order, NaN last. `std.math.order(af, bf)`
    /// reaches `unreachable` whenever an operand is NaN (every one of
    /// `==`/`<`/`>` is false), which is why NaN is handled first: Debug and
    /// ReleaseSafe would panic and ReleaseFast would return garbage on input
    /// `deserialize` accepts from 8 arbitrary wire bytes.
    fn orderNumeric(a: Value, b: Value) std.math.Order {
        const an = isNanValue(a);
        const bn = isNanValue(b);
        if (an or bn) {
            if (an and bn) return .eq;
            return if (an) .gt else .lt;
        }
        return switch (a) {
            .int => |x| switch (b) {
                .int => |y| std.math.order(x, y),
                .float => |y| orderFloatInt(y, x).invert(),
                .decimal => |y| std.math.order(@as(i128, x) * decimal_scale, y),
                else => unreachable, // callers pass numerics only (isNumeric)
            },
            .float => |x| switch (b) {
                .int => |y| orderFloatInt(x, y),
                .float => |y| std.math.order(x, y),
                .decimal => |y| orderFloatDecimal(x, y),
                else => unreachable, // callers pass numerics only (isNumeric)
            },
            .decimal => |x| switch (b) {
                .int => |y| std.math.order(x, @as(i128, y) * decimal_scale),
                .float => |y| orderFloatDecimal(y, x).invert(),
                .decimal => |y| std.math.order(x, y),
                else => unreachable, // callers pass numerics only (isNumeric)
            },
            else => unreachable, // callers pass numerics only (isNumeric)
        };
    }

    /// Order of the (non-NaN) float `f` against the integer `i`, exactly.
    fn orderFloatInt(f: f64, i: i64) std.math.Order {
        if (f >= 9223372036854775808.0) return .gt; // 2^63: above every i64
        if (f < -9223372036854775808.0) return .lt;
        const fl = @floor(f);
        const fi: i64 = @intFromFloat(fl); // in range: checked above
        const o = std.math.order(fi, i);
        if (o != .eq) return o;
        return if (f > fl) .gt else .eq;
    }

    /// Order of the (non-NaN) float `f` against the decimal `raw / decimal_scale`,
    /// exactly: integer parts as `i128`, then the fractions `frac(f)` and
    /// `rem / scale` by an integer cross-multiplication (`frac(f)` is
    /// `m * 2^-s` with a 53-bit `m`, so `frac(f) * scale` is `m * scale >> s`
    /// with a remainder, all in `u128`).
    fn orderFloatDecimal(f: f64, raw: i128) std.math.Order {
        const lim = 170141183460469231731687303715884105728.0; // 2^127
        if (f >= lim) return .gt;
        if (f < -lim) return .lt;
        const fl = @floor(f);
        const qf: i128 = @intFromFloat(fl); // in range: checked above
        const qd = @divFloor(raw, decimal_scale);
        const o = std.math.order(qf, qd);
        if (o != .eq) return o;
        const rem: u128 = @intCast(@mod(raw, decimal_scale)); // [0, scale)
        const frac = f - fl; // exact, in [0, 1)
        if (frac == 0) return if (rem == 0) .eq else .lt;
        const bits: u64 = @bitCast(frac);
        const exp: u64 = (bits >> 52) & 0x7ff;
        const mant: u64 = bits & ((1 << 52) - 1);
        const m: u128 = if (exp == 0) mant else mant | (1 << 52);
        const s: u64 = if (exp == 0) 1074 else 1075 - exp; // frac = m * 2^-s, s >= 1
        const n: u128 = m * @as(u128, @intCast(decimal_scale)); // < 2^53 * 2^40
        const q: u128 = if (s >= 128) 0 else n >> @intCast(s);
        const low_nonzero = if (s >= 128) true else (n & ((@as(u128, 1) << @intCast(s)) - 1)) != 0;
        // frac * scale == q + (low_nonzero ? something in (0,1) : 0)
        if (rem < q) return .gt;
        if (rem > q) return .lt;
        return if (low_nonzero) .gt else .eq;
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
    /// `.timestamp` keeps an `int` (already microseconds), truncates a `float`
    /// like `.int` does, and parses `text` with `parseIsoTimestamp` (so an ISO
    /// date cell becomes its UTC midnight); anything else → null.
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
                // The scaled product is what is converted, so the scaled
                // product is what must be in range — `isFinite(f)` alone let
                // `1e30` through into a cast of `1e42`.
                .float => |f| if (floatToInt(i128, f * @as(f64, @floatFromInt(decimal_scale)))) |d|
                    .{ .decimal = d }
                else
                    null,
                else => null,
            },
            .timestamp => switch (self) {
                .int => self,
                .float => |f| if (floatToInt(i64, f)) |i| .{ .int = i } else null,
                .text => |t| if (parseIsoTimestamp(t)) |us| .{ .int = us } else null,
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

    /// The cell at (row, column-name), or null if the column is absent, `row`
    /// is past the last row, or the row is shorter than the column index (a
    /// hand-built ragged row; `deserialize` and `Builder` never produce one).
    pub fn cell(self: Dataset, row: usize, name: []const u8) ?Value {
        const i = self.columnIndex(name) orelse return null;
        if (row >= self.rows.len) return null;
        const r = self.rows[row];
        if (i >= r.len) return null;
        return r[i];
    }

    // ── projections (thin; transforms/widgets own role→column projection at
    //    bind time, these exist for Zig-side transforms/tests) ──────────────

    /// Collect a numeric column into an owned `[]f64` (non-numeric/null → 0).
    pub fn floatColumn(self: Dataset, a: std.mem.Allocator, name: []const u8) ![]f64 {
        const i = self.columnIndex(name) orelse return error.NoSuchColumn;
        const out = try a.alloc(f64, self.rows.len);
        // A row shorter than the schema (hand-built; never from `deserialize`
        // or `Builder`) reads as a missing cell, not as an out-of-bounds index.
        for (self.rows, 0..) |r, ri| out[ri] = if (i < r.len) r[i].asFloat() orelse 0 else 0;
        return out;
    }

    /// Project two columns into an owned `[][2]f64` series (x,y). Non-numeric x
    /// (e.g. a date column) → the row index as x.
    pub fn seriesXY(self: Dataset, a: std.mem.Allocator, x: []const u8, y: []const u8) ![]const [2]f64 {
        const xi = self.columnIndex(x) orelse return error.NoSuchColumn;
        const yi = self.columnIndex(y) orelse return error.NoSuchColumn;
        const out = try a.alloc([2]f64, self.rows.len);
        for (self.rows, 0..) |r, ri| {
            // Short (hand-built) rows read as missing cells; see `floatColumn`.
            const xv = (if (xi < r.len) r[xi].asFloat() else null) orelse @as(f64, @floatFromInt(ri));
            out[ri] = .{ xv, (if (yi < r.len) r[yi].asFloat() else null) orelse 0 };
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

const builder_row_len_msg = "dataset: Builder.appendRow: cells.len != columns.len";

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

    /// Append one row. `cells.len` must equal `columns.len`; a mismatch is a
    /// caller bug, not a runtime data condition, and panics with
    /// "dataset: Builder.appendRow: cells.len != columns.len" in EVERY build
    /// mode (a bare `assert` is undefined behaviour in ReleaseFast, and would
    /// build a row `deserialize`'s and every transform's `row.len == columns.len`
    /// contract does not hold for). Check the length at the call site if the
    /// row's width comes from data.
    /// The `cells` slice itself is copied (duped) into the builder's
    /// allocator; individual `Value`s (e.g. borrowed `.text` slices) are not
    /// deep-copied, matching the module's general borrow model.
    pub fn appendRow(self: *Builder, cells: []const Value) std.mem.Allocator.Error!void {
        if (cells.len != self.columns.len) @panic(builder_row_len_msg);
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
// cache (or shipped over a wire). Little-endian on the wire — enforced via
// explicit `std.mem.writeInt`/`readInt(..., .little)` on every multi-byte
// field (u32 lengths, i64/f64 cells via bit pattern, i128 decimal cells),
// independent of host endianness. Round-trips exactly, and a fixed golden
// byte vector (below) pins the on-wire byte layout itself, not just
// same-process round-tripping.

pub const SerializeError = error{ OutOfMemory, TooLarge };
pub const DeserializeError = error{ Corrupt, OutOfMemory };

// Every multi-byte wire field is written (`Out`) and read (`Cursor`) as explicit
// little-endian: `std.mem.toBytes`/`bytesToValue` use the *native* byte order,
// only accidentally little-endian on every host this has run on. Floats go
// through their IEEE-754 bit pattern: the layout of the bits is
// host-independent, only their byte order varies, so bit-casting to a
// same-width integer and writing THAT as little-endian is right on a
// big-endian host too.

/// Narrow a `usize` length to the `u32` wire field, rejecting (rather than
/// silently truncating via `@intCast`) anything that would not round-trip.
fn lenU32(v: usize) SerializeError!u32 {
    return std.math.cast(u32, v) orelse error.TooLarge;
}

/// Wire bytes of one cell (tag included).
fn cellWireLen(v: Value) SerializeError!usize {
    return switch (v) {
        .null => 1,
        .int, .float => 9,
        .text => |t| 5 + @as(usize, try lenU32(t.len)),
        .bool => 2,
        .decimal => 17,
    };
}

/// Fixed-size output cursor for `serialize`: the size pass has already proved
/// every write fits, so these are plain stores (a slice index still checks).
const Out = struct {
    buf: []u8,
    pos: usize = 0,
    fn byte(o: *Out, v: u8) void {
        o.buf[o.pos] = v;
        o.pos += 1;
    }
    fn u32v(o: *Out, v: u32) void {
        std.mem.writeInt(u32, o.buf[o.pos..][0..4], v, .little);
        o.pos += 4;
    }
    fn i64v(o: *Out, v: i64) void {
        std.mem.writeInt(i64, o.buf[o.pos..][0..8], v, .little);
        o.pos += 8;
    }
    fn i128v(o: *Out, v: i128) void {
        std.mem.writeInt(i128, o.buf[o.pos..][0..16], v, .little);
        o.pos += 16;
    }
    fn bytes(o: *Out, v: []const u8) void {
        @memcpy(o.buf[o.pos..][0..v.len], v);
        o.pos += v.len;
    }
};

pub fn serialize(a: std.mem.Allocator, d: Dataset) SerializeError![]u8 {
    // One pass over the cells (a second pass over a table larger than the
    // cache re-reads it from memory): each row's byte length is summed while
    // its cells are hot, the buffer is grown once per row if needed, then the
    // row is written with plain stores. The first row's length times the row
    // count is the initial capacity guess; a wrong guess only costs ordinary
    // growth. `TooLarge` is raised exactly where the former append-per-cell
    // encoder raised it. The bytes are those of that encoder (golden vector).
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(a);
    _ = try lenU32(d.columns.len);
    var header: usize = 8;
    for (d.columns) |col| header = std.math.add(usize, header, 5 + @as(usize, try lenU32(col.name.len))) catch return error.TooLarge;
    _ = try lenU32(d.rows.len);
    const first: usize = if (d.rows.len > 0) try rowWireLen(d.rows[0]) else 0;
    const guess = std.math.mul(usize, first, d.rows.len) catch max_initial_capacity;
    try buf.ensureTotalCapacity(a, std.math.add(usize, header, @min(guess, max_initial_capacity)) catch return error.TooLarge);
    {
        var o = try growTo(&buf, a, header);
        o.u32v(@intCast(d.columns.len));
        for (d.columns) |col| {
            o.u32v(@intCast(col.name.len));
            o.bytes(col.name);
            o.byte(@backingInt(col.type));
        }
        o.u32v(@intCast(d.rows.len));
    }
    for (d.rows) |row| {
        var o = try growTo(&buf, a, try rowWireLen(row));
        for (row) |v| {
            switch (v) {
                .null => o.byte(0),
                .int => |i| {
                    o.byte(1);
                    o.i64v(i);
                },
                // Floats go through their IEEE-754 bit pattern (see the note above `lenU32`).
                .float => |f| {
                    o.byte(2);
                    o.i64v(@bitCast(f));
                },
                .text => |t| {
                    o.byte(3);
                    o.u32v(@intCast(t.len));
                    o.bytes(t);
                },
                .bool => |b| {
                    o.byte(4);
                    o.byte(if (b) 1 else 0);
                },
                // Tag 5 -- appended, not inserted: existing 0..4 tags (and
                // whatever already-serialized bytes use them) never renumber.
                .decimal => |r| {
                    o.byte(5);
                    o.i128v(r);
                },
            }
        }
        std.debug.assert(o.pos == o.buf.len);
    }
    return buf.toOwnedSlice(a);
}

const max_initial_capacity = 1 << 26;

fn rowWireLen(row: []const Value) SerializeError!usize {
    var n: usize = 0;
    for (row) |v| n = std.math.add(usize, n, try cellWireLen(v)) catch return error.TooLarge;
    return n;
}

/// Extend `buf` by `n` bytes and return a writer over exactly that tail.
fn growTo(buf: *std.ArrayList(u8), a: std.mem.Allocator, n: usize) SerializeError!Out {
    try buf.ensureUnusedCapacity(a, n);
    const start = buf.items.len;
    buf.items.len = start + n;
    return .{ .buf = buf.items[start..] };
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
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }
    fn i64v(self: *Cursor) DeserializeError!i64 {
        return std.mem.readInt(i64, (try self.take(8))[0..8], .little);
    }
    /// See the note above `lenU32`: read the bits as explicit little-endian, then reinterpret
    /// as f64 — the inverse of the host-independent bit-pattern trick used to
    /// write it, so this is correct on a big-endian host too.
    fn f64v(self: *Cursor) DeserializeError!f64 {
        return @bitCast(try self.i64v());
    }
    fn i128v(self: *Cursor) DeserializeError!i128 {
        return std.mem.readInt(i128, (try self.take(16))[0..16], .little);
    }
    fn byte(self: *Cursor) DeserializeError!u8 {
        return (try self.take(1))[0];
    }
    fn remaining(self: *const Cursor) usize {
        return self.bytes.len - self.pos;
    }
};

/// Rows whose `Value` arrays `deserialize` allocates in one piece.
const row_chunk = 256;

/// Bytes per shared text slab in `deserialize`.
const text_slab = 16 * 1024;

/// Fewest bytes a single column's header can occupy: a 4-byte name length, a
/// zero-length name, and a 1-byte type tag.
const min_encoded_column_bytes = 5;

/// Decode `bytes` (as produced by `serialize`) into a `Dataset`, defensively:
/// every wire count and length is bounds-checked against what the remaining
/// input can actually supply, and any truncation, unknown tag, or oversized
/// claim returns `DeserializeError.Corrupt` rather than panicking or reading/
/// writing out of bounds (see SPEC.md's threat-model note — this is the one
/// function in the module that treats its input as untrusted).
///
/// **On `error.Corrupt`, partial allocations from `a` are NOT freed.** This
/// module's memory model is a caller-owned arena for the whole pipeline (see
/// the module doc comment at the top of this file); a failed decode is not a
/// special case of that contract, it is the same contract: free everything at
/// once via the arena, succeeded or not. A caller that hands `deserialize` a
/// general-purpose allocator and calls it in a loop over untrusted input (a
/// cache file, a network peer) owns an unbounded leak on the error path.
///
/// **The `ncol`/`nrow` guards below bound the wire COUNTS `bytes` can prove,
/// not the memory the accepted document then occupies.** Each accepted cell
/// costs `@sizeOf(Value)` (32 B) plus its row's amortized slice header
/// (16 B / `ncol`) versus a wire-minimum of 1 B — a measured **48×** blowup
/// at `ncol = 1` (the worst case), flat across input sizes from 64 KB to
/// 8 MB. A 10 MB cached blob is a legitimate ~480 MB `Dataset`. There is no
/// caller-known cap on the RESULT here to check against (that would be a new
/// parameter — a signature change, and a decision about what a reasonable
/// caller-facing cap even is); a caller with an untrusted-size budget must
/// size it around this factor, not around `bytes.len`.
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
        if (tb >= @typeInfo(ColumnType).@"enum".field_names.len) return DeserializeError.Corrupt;
        col.type = @fromBackingInt(@intCast(tb));
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
    // The per-row `Value` arrays are carved from chunks of `row_chunk` rows
    // (one allocation per chunk, not per row). A chunk is never bigger than
    // the rows still claimed, and those are bounded by the input above, so a
    // corrupt document still fails before it has reserved much.
    var chunk: []Value = &.{};
    var tslab: []u8 = &.{};
    for (rows, 0..) |*row, ri| {
        if (chunk.len < ncol) {
            const want = std.math.mul(usize, ncol, @min(row_chunk, nrow - ri)) catch return DeserializeError.Corrupt;
            chunk = try a.alloc(Value, want);
        }
        const r = chunk[0..ncol];
        chunk = chunk[ncol..];
        for (r) |*v| {
            v.* = switch (try cur.byte()) {
                0 => .null,
                1 => .{ .int = try cur.i64v() },
                2 => .{ .float = try cur.f64v() },
                3 => blk: {
                    const tlen = try cur.u32v();
                    const src = try cur.take(tlen);
                    // Short texts are copied into a shared slab (one
                    // allocation per `text_slab` bytes, not per cell); a long
                    // one gets its own.
                    if (tlen > text_slab / 4) break :blk .{ .text = try a.dupe(u8, src) };
                    if (tslab.len < tlen) tslab = try a.alloc(u8, text_slab);
                    const dst = tslab[0..tlen];
                    @memcpy(dst, src);
                    tslab = tslab[tlen..];
                    break :blk .{ .text = dst };
                },
                4 => .{ .bool = (try cur.byte()) != 0 },
                5 => .{ .decimal = try cur.i128v() },
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
// Non-finite floats and null cells become JSON null. An `.int` cell of a
// `.timestamp` column becomes an RFC 3339 string (`formatIsoTimestamp`): a bare
// number would leave the reader to guess the unit (pandas' `to_json` emits
// epoch MILLIseconds by default, this module stores microseconds), while the
// string is unambiguous and `Date.parse` in every browser reads it.

/// Render `d` as JSON. **Output size has no bound tied to input size**: a
/// single `.float` cell prints its full decimal expansion (`{d}`, not
/// scientific notation), so one 9-byte wire float can become 379 bytes of
/// JSON (`5e-324`, measured) — a `deserialize`-produced `Dataset` from an
/// untrusted 9-byte payload is not a 9-byte JSON document. A pipeline that
/// decodes untrusted bytes and re-serializes them as JSON should size any
/// output budget around cell count × worst-case float width, not around the
/// original wire length.
pub fn toJson(a: std.mem.Allocator, d: Dataset) SerializeError![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    try appendJsonColumns(a, &buf, d.columns);
    for (d.rows, 0..) |row, ri| {
        if (ri > 0) try buf.append(a, ',');
        try buf.append(a, '[');
        for (row, 0..) |v, ci| {
            if (ci > 0) try buf.append(a, ',');
            // A hand-built row may be longer than `columns` (only `deserialize`
            // and `Builder` guarantee the lengths match), so the column lookup
            // is bounds-checked; a cell past the schema renders untyped.
            const timestamp_col = ci < d.columns.len and d.columns[ci].type == .timestamp;
            if (timestamp_col and v == .int) {
                var tb: [max_iso_timestamp_len]u8 = undefined;
                try appendJsonString(a, &buf, formatIsoTimestamp(&tb, v.int));
            } else try appendJsonValue(a, &buf, v);
        }
        try buf.append(a, ']');
    }
    try buf.appendSlice(a, "]}");
    return buf.toOwnedSlice(a);
}

/// Everything up to the first row of the JSON document.
fn appendJsonColumns(a: std.mem.Allocator, buf: *std.ArrayList(u8), columns: []const Column) SerializeError!void {
    try buf.appendSlice(a, "{\"columns\":[");
    for (columns, 0..) |col, i| {
        if (i > 0) try buf.append(a, ',');
        try buf.appendSlice(a, "{\"name\":");
        try appendJsonString(a, buf, col.name);
        try buf.appendSlice(a, ",\"type\":\"");
        try buf.appendSlice(a, @tagName(col.type));
        try buf.appendSlice(a, "\"}");
    }
    try buf.appendSlice(a, "],\"rows\":[");
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

/// `deserialize` never validates UTF-8 on a `.text` cell (the wire format
/// only bounds LENGTH, not content — see the doc comment on `deserialize`),
/// so `s` here can carry arbitrary bytes decoded straight from an untrusted
/// peer or cache file. Escaping byte-at-a-time and trusting `s` to already be
/// valid UTF-8 would copy those bytes into the output verbatim, producing a
/// document that is not valid UTF-8 and that a strict JSON receiver rejects
/// WHOLE, not just the bad cell. Every multi-byte sequence is validated
/// before it is copied; anything that does not decode is replaced with
/// U+FFFD one byte at a time, so a single bad byte inside an otherwise-valid
/// string costs one substitution, not the rest of the string.
fn appendJsonString(a: std.mem.Allocator, buf: *std.ArrayList(u8), s: []const u8) SerializeError!void {
    try buf.append(a, '"');
    var i: usize = 0;
    while (i < s.len) {
        const ch = s[i];
        if (ch < 0x80) {
            switch (ch) {
                '"' => try buf.appendSlice(a, "\\\""),
                '\\' => try buf.appendSlice(a, "\\\\"),
                '\n' => try buf.appendSlice(a, "\\n"),
                '\r' => try buf.appendSlice(a, "\\r"),
                '\t' => try buf.appendSlice(a, "\\t"),
                0...8, 11, 12, 14...31 => try buf.print(a, "\\u{x:0>4}", .{ch}),
                else => try buf.append(a, ch),
            }
            i += 1;
            continue;
        }
        const seq_len = std.unicode.utf8ByteSequenceLength(ch) catch {
            try buf.appendSlice(a, &std.unicode.replacement_character_utf8);
            i += 1;
            continue;
        };
        if (i + seq_len > s.len or !std.unicode.utf8ValidateSlice(s[i .. i + seq_len])) {
            try buf.appendSlice(a, &std.unicode.replacement_character_utf8);
            i += 1;
            continue;
        }
        try buf.appendSlice(a, s[i .. i + seq_len]);
        i += seq_len;
    }
    try buf.append(a, '"');
}

// ── Frame: the columnar table ───────────────────────────────────────────────
// `Dataset` is row-major and boxed: a 32-byte `Value` per cell, a cache line per
// row visited by a column read. `Frame` holds the same table as one typed array
// per column. It is additive: `Dataset` and every function on it are unchanged.
//
// **Physical storage follows the cells, not the declared `ColumnType`.** `Builder`
// and hand-built tables do not check a cell against its column, and a SQLite column
// has no fixed storage class, so a column declared `.float` may hold `.int` cells or
// a mix. All cells of one `Value` tag (or null) get that tag's array; a mix gets
// `.boxed`, a plain `[]Value`. So `Frame.fromDataset` then `toDataset` gives back the
// same cells, bit for bit, whatever they were, and `.date` stays text and
// `.timestamp` stays int as they do in `Dataset`.

/// One typed column's cells. A null cell holds 0 in `values`, and `valid` has its
/// bit clear; `valid == null` means no cell is null. NaN is a value, not a null.
pub fn TypedColumn(comptime T: type) type {
    return struct {
        const Self = @This();
        values: []const T,
        /// Bit `i % 64` of word `i / 64` set: row `i` is not null.
        valid: ?[]const u64 = null,

        /// Row `row` is present and not null.
        pub inline fn isValid(self: Self, row: usize) bool {
            if (row >= self.values.len) return false;
            const v = self.valid orelse return true;
            const w = row / 64;
            return w < v.len and (v[w] >> @intCast(row % 64)) & 1 == 1;
        }
    };
}

/// Text cells: row `i` is `bytes[offsets[i]..offsets[i + 1]]`. A null cell is empty
/// and has its `valid` bit clear, so it differs from an empty string.
pub const TextColumn = struct {
    offsets: []const usize,
    bytes: []const u8,
    valid: ?[]const u64 = null,

    pub inline fn isValid(self: TextColumn, row: usize) bool {
        if (row >= self.offsets.len -| 1) return false;
        const v = self.valid orelse return true;
        const w = row / 64;
        return w < v.len and (v[w] >> @intCast(row % 64)) & 1 == 1;
    }

    /// Row `row`'s text; null if it is null or past the end.
    pub inline fn at(self: TextColumn, row: usize) ?[]const u8 {
        if (!self.isValid(row)) return null;
        const lo = self.offsets[row];
        const hi = self.offsets[row + 1];
        if (lo > hi or hi > self.bytes.len) return null;
        return self.bytes[lo..hi];
    }
};

pub const ColumnData = union(enum) {
    /// Every cell is null, or there are no rows. No storage.
    nulls,
    int: TypedColumn(i64),
    float: TypedColumn(f64),
    bool: TypedColumn(bool),
    decimal: TypedColumn(i128),
    text: TextColumn,
    /// Cells of more than one `Value` tag.
    boxed: []const Value,

    /// The cell at `row` as a `Value`. A row past the end reads as `.null`. `.text`
    /// borrows from the column.
    pub inline fn get(self: ColumnData, row: usize) Value {
        switch (self) {
            .nulls => return .null,
            .int => |c| return if (c.isValid(row)) .{ .int = c.values[row] } else .null,
            .float => |c| return if (c.isValid(row)) .{ .float = c.values[row] } else .null,
            .bool => |c| return if (c.isValid(row)) .{ .bool = c.values[row] } else .null,
            .decimal => |c| return if (c.isValid(row)) .{ .decimal = c.values[row] } else .null,
            .text => |c| return if (c.at(row)) |t| .{ .text = t } else .null,
            .boxed => |c| return if (row < c.len) c[row] else .null,
        }
    }
};

/// One column's storage from its cells, the array their tags call for. Text is copied.
pub fn columnFromCells(a: std.mem.Allocator, cells: []const Value) std.mem.Allocator.Error!ColumnData {
    var b: ColBuilder = .{ .a = a, .hint = cells.len };
    for (cells) |c| try b.append(c);
    return b.finish();
}

/// A child for an `ArenaAllocator` that holds big frames: a block of 2 MiB or more comes
/// aligned to that and advised for transparent huge pages, everything else is
/// `page_allocator`. A fresh arena's 4 KiB page faults are most of what a columnar verb
/// costs on a big table: measured in `tabular`'s bench, `mutate` over 1 M rows 2.47 to 0.82x
/// pandas. Where the kernel says `transparent_hugepage/enabled = never`, or off Linux, it
/// is just `page_allocator`. No state, safe from any thread.
pub const big_block_allocator: std.mem.Allocator = .{ .ptr = undefined, .vtable = &big_block_vtable };

const big_block_size = 2 * 1024 * 1024;

const big_block_vtable: std.mem.Allocator.VTable = .{
    .alloc = bigBlockAlloc,
    .resize = std.mem.Allocator.noResize,
    .remap = std.mem.Allocator.noRemap,
    .free = bigBlockFree,
};

fn bigBlockAlloc(_: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
    const pa = std.heap.page_allocator; // global-alloc-ok: this IS an allocator, over the OS's pages
    if (len < big_block_size) return pa.rawAlloc(len, alignment, ret);
    // The page allocator adds the alignment to the length unchecked.
    if (len > std.math.maxInt(usize) - 2 * big_block_size) return null;
    const al = std.mem.Alignment.fromByteUnits(@max(alignment.toByteUnits(), big_block_size));
    const p = pa.rawAlloc(len, al, ret) orelse return null;
    if (@import("builtin").os.tag == .linux) {
        // Advice only: a refusal leaves ordinary pages.
        _ = std.os.linux.madvise(@alignCast(p), len, std.os.linux.MADV.HUGEPAGE);
    }
    return p;
}

fn bigBlockFree(_: *anyopaque, mem: []u8, alignment: std.mem.Alignment, ret: usize) void {
    std.heap.page_allocator.rawFree(mem, alignment, ret); // global-alloc-ok: see bigBlockAlloc
}

pub const FrameError = error{ OutOfMemory, RaggedRow };
pub const FrameBuilderError = error{ OutOfMemory, RowLength };

/// A table as one typed array per column. Immutable, and like `Dataset` allocated
/// from an arena the caller frees at once: the arrays may be longer than `len`
/// behind the slices' capacity, so a general-purpose allocator would leak them.
/// Build one with `Frame.fromDataset`, `FrameBuilder` or `deserializeFrame`; a
/// hand-built one with arrays shorter than `len` reads as null past their end.
pub const Frame = struct {
    columns: []const Column,
    data: []const ColumnData,
    len: usize,

    /// The same table as `d`, text copied. A row whose length differs from the
    /// schema (hand-built; `Builder` and `deserialize` never make one) is
    /// `error.RaggedRow`: `Dataset` reads such a row as missing cells, which a
    /// round trip could not give back.
    pub fn fromDataset(a: std.mem.Allocator, d: Dataset) FrameError!Frame {
        for (d.rows) |r| if (r.len != d.columns.len) return error.RaggedRow;
        const data = try a.alloc(ColumnData, d.columns.len);
        for (data, 0..) |*out, ci| {
            var b: ColBuilder = .{ .a = a, .hint = d.rows.len };
            for (d.rows) |r| try b.append(r[ci]);
            out.* = b.finish();
        }
        return .{ .columns = d.columns, .data = data, .len = d.rows.len };
    }

    /// The same table as a `Dataset`. `.text` cells borrow from this frame.
    pub fn toDataset(self: Frame, a: std.mem.Allocator) std.mem.Allocator.Error!Dataset {
        const rows = try a.alloc([]const Value, self.len);
        const w = self.columns.len;
        const n = std.math.mul(usize, w, self.len) catch return error.OutOfMemory;
        const cells = try a.alloc(Value, n);
        for (0..w) |ci| {
            const col = columnOrNulls(self, ci);
            for (0..self.len) |ri| cells[ri * w + ci] = col.get(ri);
        }
        for (rows, 0..) |*r, ri| r.* = cells[ri * w ..][0..w];
        return .{ .columns = self.columns, .rows = rows };
    }

    /// Index of the column named `name`, or null.
    pub fn columnIndex(self: Frame, name: []const u8) ?usize {
        for (self.columns, 0..) |c, i| {
            if (std.mem.eql(u8, c.name, name)) return i;
        }
        return null;
    }

    pub fn columnType(self: Frame, name: []const u8) ?ColumnType {
        const i = self.columnIndex(name) orelse return null;
        return self.columns[i].type;
    }

    pub fn rowCount(self: Frame) usize {
        return self.len;
    }

    /// The cell at (row, column-name), or null if the column is absent or `row` is
    /// past the last row. As `Dataset.cell`.
    pub fn cell(self: Frame, row: usize, name: []const u8) ?Value {
        const i = self.columnIndex(name) orelse return null;
        if (row >= self.len or i >= self.data.len) return null;
        return self.data[i].get(row);
    }

    /// The column's storage, or null if there is no such column.
    pub fn column(self: Frame, name: []const u8) ?ColumnData {
        const i = self.columnIndex(name) orelse return null;
        return if (i < self.data.len) self.data[i] else null;
    }

    /// A numeric column as `[]f64`, the same numbers as `Dataset.floatColumn`
    /// (non-numeric and null read as 0). **Borrows the frame's array when every cell
    /// is `.float` (no allocation)**, otherwise allocates from `a`. The borrowed array
    /// relies on a null cell holding 0, which only a hand-built frame can break.
    pub fn floatColumn(self: Frame, a: std.mem.Allocator, name: []const u8) ![]const f64 {
        const col = self.column(name) orelse return error.NoSuchColumn;
        if (col == .float and col.float.values.len == self.len) return col.float.values;
        const out = try a.alloc(f64, self.len);
        for (out, 0..) |*x, ri| x.* = col.get(ri).asFloat() orelse 0;
        return out;
    }

    /// Two columns as an owned `[][2]f64` series, as `Dataset.seriesXY`: a
    /// non-numeric x reads as the row index, a non-numeric y as 0.
    pub fn seriesXY(self: Frame, a: std.mem.Allocator, x: []const u8, y: []const u8) ![]const [2]f64 {
        const xc = self.column(x) orelse return error.NoSuchColumn;
        const yc = self.column(y) orelse return error.NoSuchColumn;
        const out = try a.alloc([2]f64, self.len);
        for (out, 0..) |*p, ri| {
            p.* = .{ xc.get(ri).asFloat() orelse @as(f64, @floatFromInt(ri)), yc.get(ri).asFloat() orelse 0 };
        }
        return out;
    }
};

/// One column under construction. Starts with no storage; the first non-null cell
/// picks the array, the first cell of another tag moves everything to `.boxed`.
const ColBuilder = struct {
    a: std.mem.Allocator,
    /// Rows expected, the capacity reserved when the array is picked. `deserializeFrame`
    /// passes a count the input has proved.
    hint: usize,
    /// Most text bytes to reserve up front. A decoder passes its column's share of
    /// the input: the whole of it per column let 1000 columns of 2 MB reserve 1 GB.
    text_cap: usize = 1 << 20,
    kind: Kind = .nulls,
    len: usize = 0,
    has_null: bool = false,
    ints: std.ArrayList(i64) = .empty,
    floats: std.ArrayList(f64) = .empty,
    bools: std.ArrayList(bool) = .empty,
    decimals: std.ArrayList(i128) = .empty,
    offsets: std.ArrayList(usize) = .empty,
    bytes: std.ArrayList(u8) = .empty,
    boxed: std.ArrayList(Value) = .empty,
    valid: std.ArrayList(u64) = .empty,

    const Kind = enum { nulls, int, float, bool, decimal, text, boxed };

    fn pick(s: *ColBuilder, k: Kind) std.mem.Allocator.Error!void {
        const cap = @max(s.hint, s.len + 1);
        // Every cell so far was null: zeros in the array, and clear bits.
        switch (k) {
            .int => try s.ints.appendNTimes(s.a, 0, s.len),
            .float => try s.floats.appendNTimes(s.a, 0, s.len),
            .bool => try s.bools.appendNTimes(s.a, false, s.len),
            .decimal => try s.decimals.appendNTimes(s.a, 0, s.len),
            .text => try s.offsets.appendNTimes(s.a, 0, s.len + 1),
            .nulls, .boxed => unreachable,
        }
        switch (k) {
            .int => try s.ints.ensureTotalCapacity(s.a, cap),
            .float => try s.floats.ensureTotalCapacity(s.a, cap),
            .bool => try s.bools.ensureTotalCapacity(s.a, cap),
            .decimal => try s.decimals.ensureTotalCapacity(s.a, cap),
            .text => try s.offsets.ensureTotalCapacity(s.a, cap + 1),
            .nulls, .boxed => unreachable,
        }
        if (s.len > 0) {
            s.has_null = true;
            try s.valid.appendNTimes(s.a, 0, s.len / 64 + 1);
        }
        s.kind = k;
    }

    /// Every cell so far, as `Value`s. Text stays in `bytes`, which is not freed.
    fn toBoxed(s: *ColBuilder) std.mem.Allocator.Error!void {
        try s.boxed.ensureTotalCapacity(s.a, @max(s.hint, s.len + 1));
        const col = s.finish();
        for (0..s.len) |ri| s.boxed.appendAssumeCapacity(col.get(ri));
        s.kind = .boxed;
    }

    fn setBit(s: *ColBuilder, value: bool) std.mem.Allocator.Error!void {
        const w = s.len / 64;
        while (s.valid.items.len <= w) try s.valid.append(s.a, 0);
        if (value) s.valid.items[w] |= @as(u64, 1) << @intCast(s.len % 64);
    }

    /// A cell of the kind the column already is, into reserved capacity: the common
    /// case, decided in two compares. Anything else goes through `appendSlow`.
    inline fn push(s: *ColBuilder, comptime k: Kind, comptime field: []const u8, x: anytype) std.mem.Allocator.Error!void {
        const list = &@field(s, field);
        if (s.kind == k and list.items.len < list.capacity) {
            list.appendAssumeCapacity(x);
            if (s.has_null) try s.setBit(true);
            s.len += 1;
            return;
        }
        return s.appendSlow(@unionInit(Value, @tagName(k), x));
    }

    inline fn pushText(s: *ColBuilder, x: []const u8) std.mem.Allocator.Error!void {
        if (s.kind == .text and s.offsets.items.len < s.offsets.capacity) {
            try s.bytes.appendSlice(s.a, x);
            s.offsets.appendAssumeCapacity(s.bytes.items.len);
            if (s.has_null) try s.setBit(true);
            s.len += 1;
            return;
        }
        return s.appendSlow(.{ .text = x });
    }

    inline fn append(s: *ColBuilder, v: Value) std.mem.Allocator.Error!void {
        switch (v) {
            .null => return s.appendNull(),
            .int => |x| return s.push(.int, "ints", x),
            .float => |x| return s.push(.float, "floats", x),
            .bool => |x| return s.push(.bool, "bools", x),
            .decimal => |x| return s.push(.decimal, "decimals", x),
            .text => |x| return s.pushText(x),
        }
    }

    fn appendSlow(s: *ColBuilder, v: Value) std.mem.Allocator.Error!void {
        const k: Kind = switch (v) {
            .null => unreachable,
            .int => .int,
            .float => .float,
            .bool => .bool,
            .decimal => .decimal,
            .text => .text,
        };
        if (s.kind != k and s.kind != .boxed) {
            if (s.kind == .nulls) {
                try s.pick(k);
                // One guess at the column's text from its first cell; a wrong one
                // only costs ordinary growth.
                if (k == .text) try s.bytes.ensureTotalCapacity(s.a, @min(s.text_cap, v.text.len *| s.hint));
            } else try s.toBoxed();
        }
        switch (s.kind) {
            .int => try s.ints.append(s.a, v.int),
            .float => try s.floats.append(s.a, v.float),
            .bool => try s.bools.append(s.a, v.bool),
            .decimal => try s.decimals.append(s.a, v.decimal),
            .text => {
                try s.bytes.appendSlice(s.a, v.text);
                try s.offsets.append(s.a, s.bytes.items.len);
            },
            // `bytes` stops growing once boxed (the slices `toBoxed` took point
            // into it), so a later text gets its own copy.
            .boxed => try s.boxed.append(s.a, if (v == .text) .{ .text = try s.a.dupe(u8, v.text) } else v),
            .nulls => unreachable,
        }
        if (s.has_null and s.kind != .boxed) try s.setBit(true);
        s.len += 1;
    }

    fn appendNull(s: *ColBuilder) std.mem.Allocator.Error!void {
        switch (s.kind) {
            .nulls => {
                s.len += 1;
                return;
            },
            .boxed => {
                try s.boxed.append(s.a, .null);
                s.len += 1;
                return;
            },
            .int => try s.ints.append(s.a, 0),
            .float => try s.floats.append(s.a, 0),
            .bool => try s.bools.append(s.a, false),
            .decimal => try s.decimals.append(s.a, 0),
            .text => try s.offsets.append(s.a, s.bytes.items.len),
        }
        if (!s.has_null) {
            // The first null: every earlier row was not.
            s.has_null = true;
            try s.valid.appendNTimes(s.a, ~@as(u64, 0), s.len / 64);
            if (s.len % 64 != 0) try s.valid.append(s.a, (@as(u64, 1) << @intCast(s.len % 64)) - 1);
        }
        try s.setBit(false);
        s.len += 1;
    }

    fn finish(s: *const ColBuilder) ColumnData {
        const valid: ?[]const u64 = if (s.has_null) s.valid.items else null;
        return switch (s.kind) {
            .nulls => .nulls,
            .int => .{ .int = .{ .values = s.ints.items, .valid = valid } },
            .float => .{ .float = .{ .values = s.floats.items, .valid = valid } },
            .bool => .{ .bool = .{ .values = s.bools.items, .valid = valid } },
            .decimal => .{ .decimal = .{ .values = s.decimals.items, .valid = valid } },
            .text => .{ .text = .{ .offsets = s.offsets.items, .bytes = s.bytes.items, .valid = valid } },
            .boxed => .{ .boxed = s.boxed.items },
        };
    }
};

/// Row-at-a-time construction of a `Frame`. The cells are copied, text included, so
/// the caller's buffers may go after `appendRow` returns. `expected_rows` only
/// reserves capacity; 0 is fine.
pub const FrameBuilder = struct {
    a: std.mem.Allocator,
    columns: []const Column,
    cols: []ColBuilder,
    len: usize = 0,
    /// A failed allocation may have left some columns one cell ahead of the others.
    failed: bool = false,

    pub fn init(a: std.mem.Allocator, columns: []const Column, expected_rows: usize) std.mem.Allocator.Error!FrameBuilder {
        const cols = try a.alloc(ColBuilder, columns.len);
        for (cols) |*c| c.* = .{ .a = a, .hint = expected_rows };
        return .{ .a = a, .columns = columns, .cols = cols };
    }

    /// `error.RowLength` if `cells.len != columns.len`, and the row is not added.
    /// After `error.OutOfMemory` the builder is spent: this and `toOwned` keep
    /// returning it, rather than giving a table whose columns disagree on the rows.
    pub fn appendRow(self: *FrameBuilder, cells: []const Value) FrameBuilderError!void {
        if (self.failed) return error.OutOfMemory;
        if (cells.len != self.cols.len) return error.RowLength;
        errdefer self.failed = true;
        for (self.cols, cells) |*c, v| try c.append(v);
        self.len += 1;
    }

    /// The frame shares the builder's arrays, so the builder must not be used after
    /// this, as with `Builder.toOwned`.
    pub fn toOwned(self: *const FrameBuilder) std.mem.Allocator.Error!Frame {
        if (self.failed) return error.OutOfMemory;
        const data = try self.a.alloc(ColumnData, self.cols.len);
        for (data, self.cols) |*d, *c| d.* = c.finish();
        return .{ .columns = self.columns, .data = data, .len = self.len };
    }
};

/// `serialize`'s bytes for this table: the same format, and for the same cells the
/// same bytes, so a reader cannot tell which one wrote them.
pub fn serializeFrame(a: std.mem.Allocator, f: Frame) SerializeError![]u8 {
    _ = try lenU32(f.columns.len);
    _ = try lenU32(f.len);
    var total: usize = 8;
    for (f.columns) |col| total = std.math.add(usize, total, 5 + @as(usize, try lenU32(col.name.len))) catch return error.TooLarge;
    for (f.columns, 0..) |_, ci| {
        const n = try columnWireLen(columnOrNulls(f, ci), f.len);
        total = std.math.add(usize, total, n) catch return error.TooLarge;
    }
    const buf = try a.alloc(u8, total);
    var o: Out = .{ .buf = buf };
    o.u32v(@intCast(f.columns.len));
    for (f.columns) |col| {
        o.u32v(@intCast(col.name.len));
        o.bytes(col.name);
        o.byte(@backingInt(col.type));
    }
    o.u32v(@intCast(f.len));
    const nc = f.columns.len;
    for (0..f.len) |ri| {
        for (0..nc) |ci| {
            switch (columnOrNulls(f, ci).*) {
                .nulls => o.byte(0),
                .int => |*c| if (c.isValid(ri)) {
                    o.byte(1);
                    o.i64v(c.values[ri]);
                } else o.byte(0),
                .float => |*c| if (c.isValid(ri)) {
                    o.byte(2);
                    o.i64v(@bitCast(c.values[ri]));
                } else o.byte(0),
                .bool => |*c| if (c.isValid(ri)) {
                    o.byte(4);
                    o.byte(if (c.values[ri]) 1 else 0);
                } else o.byte(0),
                .decimal => |*c| if (c.isValid(ri)) {
                    o.byte(5);
                    o.i128v(c.values[ri]);
                } else o.byte(0),
                .text => |*c| if (c.at(ri)) |x| {
                    o.byte(3);
                    o.u32v(@intCast(x.len));
                    o.bytes(x);
                } else o.byte(0),
                .boxed => |c| writeBoxed(&o, if (ri < c.len) c[ri] else .null),
            }
        }
    }
    std.debug.assert(o.pos == buf.len);
    return buf;
}

fn writeBoxed(o: *Out, v: Value) void {
    switch (v) {
        .null => o.byte(0),
        .int => |i| {
            o.byte(1);
            o.i64v(i);
        },
        .float => |x| {
            o.byte(2);
            o.i64v(@bitCast(x));
        },
        .text => |x| {
            o.byte(3);
            o.u32v(@intCast(x.len));
            o.bytes(x);
        },
        .bool => |b| {
            o.byte(4);
            o.byte(if (b) 1 else 0);
        },
        .decimal => |r| {
            o.byte(5);
            o.i128v(r);
        },
    }
}

/// A valid cell's wire bytes beyond its tag, per the rows that `isValid` passes: a
/// null or a row past the arrays is the tag alone.
fn validCells(valid: ?[]const u64, values_len: usize, rows: usize) usize {
    const m = @min(values_len, rows);
    const v = valid orelse return m;
    var n: usize = 0;
    const whole = m / 64;
    for (v[0..@min(whole, v.len)]) |w| n += @popCount(w);
    if (whole < v.len and m % 64 != 0) n += @popCount(v[whole] & ((@as(u64, 1) << @intCast(m % 64)) - 1));
    return n;
}

fn columnWireLen(col: *const ColumnData, rows: usize) SerializeError!usize {
    var extra: usize = 0;
    switch (col.*) {
        .nulls => {},
        .int => |c| extra = validCells(c.valid, c.values.len, rows) * 8,
        .float => |c| extra = validCells(c.valid, c.values.len, rows) * 8,
        .bool => |c| extra = validCells(c.valid, c.values.len, rows),
        .decimal => |c| extra = validCells(c.valid, c.values.len, rows) * 16,
        .text => |c| for (0..rows) |ri| {
            if (c.at(ri)) |x| extra = std.math.add(usize, extra, 4 + @as(usize, try lenU32(x.len))) catch return error.TooLarge;
        },
        .boxed => |c| for (0..rows) |ri| {
            const cell: Value = if (ri < c.len) c[ri] else .null;
            extra = std.math.add(usize, extra, try cellWireLen(cell) - 1) catch return error.TooLarge;
        },
    }
    return std.math.add(usize, rows, extra) catch error.TooLarge;
}

const nulls_column: ColumnData = .nulls;

/// A hand-built frame with fewer `data` entries than `columns` reads as nulls there.
inline fn columnOrNulls(f: Frame, ci: usize) *const ColumnData {
    return if (ci < f.data.len) &f.data[ci] else &nulls_column;
}

/// `deserialize` into a `Frame`: accepts and refuses exactly what `deserialize` does,
/// with the same bounds on the wire counts, and on `error.Corrupt` leaves its
/// allocations to the arena in the same way. An accepted document costs at most 16
/// bytes a cell, plus its text; a column that starts typed and turns mixed keeps both
/// arrays, at most 48 bytes a cell, what `Dataset` costs at one column. Size a budget
/// for untrusted input around that, as for `deserialize`.
pub fn deserializeFrame(a: std.mem.Allocator, bytes: []const u8) DeserializeError!Frame {
    var cur = Cursor{ .bytes = bytes };
    const ncol = try cur.u32v();
    if (ncol > cur.remaining() / min_encoded_column_bytes) return DeserializeError.Corrupt;
    const cols = try a.alloc(Column, ncol);
    for (cols) |*col| {
        const nlen = try cur.u32v();
        col.name = try a.dupe(u8, try cur.take(nlen));
        const tb = try cur.byte();
        if (tb >= @typeInfo(ColumnType).@"enum".field_names.len) return DeserializeError.Corrupt;
        col.type = @fromBackingInt(@intCast(tb));
    }
    const nrow = try cur.u32v();
    if (nrow > cur.remaining() / @max(1, ncol)) return DeserializeError.Corrupt;
    const builders = try a.alloc(ColBuilder, ncol);
    const text_share = cur.remaining() / @max(1, ncol);
    for (builders) |*b| b.* = .{ .a = a, .hint = nrow, .text_cap = text_share };
    for (0..nrow) |_| {
        for (builders) |*b| {
            switch (try cur.byte()) {
                0 => try b.appendNull(),
                1 => try b.push(.int, "ints", try cur.i64v()),
                2 => try b.push(.float, "floats", try cur.f64v()),
                3 => {
                    const tlen = try cur.u32v();
                    try b.pushText(try cur.take(tlen));
                },
                4 => try b.push(.bool, "bools", (try cur.byte()) != 0),
                5 => try b.push(.decimal, "decimals", try cur.i128v()),
                else => return DeserializeError.Corrupt,
            }
        }
    }
    const data = try a.alloc(ColumnData, ncol);
    for (data, builders) |*d, *b| d.* = b.finish();
    return .{ .columns = cols, .data = data, .len = nrow };
}

/// `toJson`'s document for this table, byte for byte. Its note on output size holds.
pub fn frameToJson(a: std.mem.Allocator, f: Frame) SerializeError![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    try appendJsonColumns(a, &buf, f.columns);
    for (0..f.len) |ri| {
        if (ri > 0) try buf.append(a, ',');
        try buf.append(a, '[');
        for (f.columns, 0..) |c, ci| {
            if (ci > 0) try buf.append(a, ',');
            const v = columnOrNulls(f, ci).*.get(ri);
            if (c.type == .timestamp and v == .int) {
                var tb: [max_iso_timestamp_len]u8 = undefined;
                try appendJsonString(a, &buf, formatIsoTimestamp(&tb, v.int));
            } else try appendJsonValue(a, &buf, v);
        }
        try buf.append(a, ']');
    }
    try buf.appendSlice(a, "]}");
    return buf.toOwnedSlice(a);
}

// ── date helpers (ISO YYYY-MM-DD) ───────────────────────────────────────────

pub const Date = struct {
    y: i32,
    m: u8,
    d: u8,

    /// Days since 1970-01-01 in the proleptic Gregorian calendar (Howard
    /// Hinnant's days-from-civil), the inverse of `fromOrdinal`: equal dates
    /// compare equal, later dates compare greater, consecutive days differ by
    /// one (checked day by day over ~5 400 years in the tests). Proleptic:
    /// there is no Julian calendar before 1582, so it is not a tool for
    /// historical (pre-reform) dates.
    pub fn ordinal(self: Date) i64 {
        var y: i64 = self.y;
        var m: i64 = self.m;
        // shift Jan/Feb to end of previous year (Howard Hinnant's days algorithm)
        if (m <= 2) {
            y -= 1;
            m += 12;
        }
        // `@divFloor`, not Hinnant's `(y >= 0 ? y : y - 399) / 400`: that
        // expression emulates floor division with C's TRUNCATING `/`, and
        // combined with a division that already floors it put every year
        // in [-400, -2] one era (146097 days) too early — found 2026-10-04 by
        // the day-by-day calendar walk in the `fromOrdinal` test.
        const era = @divFloor(y, 400);
        const yoe = y - era * 400;
        const doy = @divFloor(153 * (m - 3) + 2, 5) + self.d - 1;
        const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
        return era * 146097 + doe - 719468;
    }

    /// The inverse of `ordinal`: the proleptic-Gregorian date `days` after
    /// 1970-01-01 (Howard Hinnant's civil-from-days). Null only when the year
    /// does not fit `Date.y` (|days| beyond ~7.8e11, far outside any timestamp).
    pub fn fromOrdinal(days: i64) ?Date {
        const z = std.math.add(i64, days, 719468) catch return null;
        const era = @divFloor(z, 146097);
        const doe = z - era * 146097; // [0, 146096]
        const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365); // [0, 399]
        const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100)); // [0, 365]
        const mp = @divFloor(5 * doy + 2, 153); // [0, 11], March-based
        const d = doy - @divFloor(153 * mp + 2, 5) + 1; // [1, 31]
        const m = if (mp < 10) mp + 3 else mp - 9; // [1, 12]
        const y = yoe + era * 400 + @intFromBool(m <= 2);
        return .{ .y = std.math.cast(i32, y) orelse return null, .m = @intCast(m), .d = @intCast(d) };
    }

    /// Days in month `m` (1–12) of year `y`, Gregorian leap rule.
    pub fn daysInMonth(y: i32, m: u8) u8 {
        return switch (m) {
            2 => if (@mod(y, 4) == 0 and (@mod(y, 100) != 0 or @mod(y, 400) == 0)) 29 else 28,
            4, 6, 9, 11 => 30,
            else => 31,
        };
    }
};

/// `n` ASCII digits at `s[i..]` as an integer, or null. Unlike
/// `std.fmt.parseInt` it refuses a sign, so `"+1"` is not a month.
fn digitsAt(s: []const u8, i: usize, n: usize) ?u32 {
    if (i + n > s.len) return null;
    var v: u32 = 0;
    for (s[i .. i + n]) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
    }
    return v;
}

/// Parse "YYYY-MM-DD" (extra trailing text is ignored). Returns null on
/// malformed input: every field must be ASCII digits (no sign, no blank) and the
/// day must exist in that month — `2023-02-29` and `2024-04-31` are refused.
pub fn parseIsoDate(s: []const u8) ?Date {
    if (s.len < 10) return null;
    if (s[4] != '-' or s[7] != '-') return null;
    const y = digitsAt(s, 0, 4) orelse return null;
    const m = digitsAt(s, 5, 2) orelse return null;
    const d = digitsAt(s, 8, 2) orelse return null;
    if (m < 1 or m > 12) return null;
    const date: Date = .{ .y = @intCast(y), .m = @intCast(m), .d = @intCast(d) };
    if (d < 1 or d > Date.daysInMonth(date.y, date.m)) return null;
    return date;
}

/// Parse an ISO 8601 / RFC 3339 instant into microseconds since the epoch
/// (the `.timestamp` cell unit). Accepted, and nothing else:
///
///   `YYYY-MM-DD`                                   → UTC midnight
///   `YYYY-MM-DD(T|t| )HH:MM[:SS[(.|,)F…]][zone]`
///   zone = `Z` | `z` | `±HH:MM` | `±HHMM` | `±HH`   (absent → UTC)
///
/// The fraction may have 1–9 digits; digits past the sixth are truncated
/// (toward the earlier instant — the fraction only ever adds). Hours 0–23,
/// minutes 0–59, seconds 0–59: a leap second `:60` is refused, as Python's
/// `datetime.fromisoformat` refuses it; so is `24:00`. A string with no zone is
/// read as UTC — the same convention as Arrow's timezone-less timestamp, whose
/// stored value is the wall-clock time as if it were UTC. Offsets up to ±23:59.
///
/// No overflow is possible: a 4-digit year bounds the result to about ±2.6e17 µs.
pub fn parseIsoTimestamp(s: []const u8) ?i64 {
    if (s.len < 10) return null;
    const date = parseIsoDate(s[0..10]) orelse return null;
    const day_us = date.ordinal() * us_per_day;
    if (s.len == 10) return day_us;

    var i: usize = 10;
    if (s[i] != 'T' and s[i] != 't' and s[i] != ' ') return null;
    i += 1;
    const hh = digitsAt(s, i, 2) orelse return null;
    if (i + 2 >= s.len or s[i + 2] != ':') return null;
    const mm = digitsAt(s, i + 3, 2) orelse return null;
    i += 5;
    var ss: u32 = 0;
    if (i < s.len and s[i] == ':') {
        ss = digitsAt(s, i + 1, 2) orelse return null;
        i += 3;
    }
    if (hh > 23 or mm > 59 or ss > 59) return null;

    var frac_us: i64 = 0;
    if (i < s.len and (s[i] == '.' or s[i] == ',')) {
        i += 1;
        var n: usize = 0;
        while (i < s.len and s[i] >= '0' and s[i] <= '9') : (i += 1) {
            if (n == 9) return null;
            if (n < 6) frac_us = frac_us * 10 + (s[i] - '0');
            n += 1;
        }
        if (n == 0) return null;
        var pad = n;
        while (pad < 6) : (pad += 1) frac_us *= 10;
    }

    var offset_s: i64 = 0;
    if (i < s.len) {
        switch (s[i]) {
            'Z', 'z' => i += 1,
            '+', '-' => {
                const sign: i64 = if (s[i] == '-') -1 else 1;
                const oh = digitsAt(s, i + 1, 2) orelse return null;
                i += 3;
                var om: u32 = 0;
                if (i < s.len) {
                    const at = if (s[i] == ':') i + 1 else i;
                    om = digitsAt(s, at, 2) orelse return null;
                    i = at + 2;
                }
                if (oh > 23 or om > 59) return null;
                offset_s = sign * @as(i64, oh * 3600 + om * 60);
            },
            else => return null,
        }
    }
    if (i != s.len) return null;

    const secs: i64 = @as(i64, hh) * 3600 + @as(i64, mm) * 60 + ss - offset_s;
    return day_us + secs * timestamp_units_per_second + frac_us;
}

/// Longest string `formatIsoTimestamp` can produce: `-292278-12-31T23:59:59.999999Z`
/// plus slack.
pub const max_iso_timestamp_len = 40;

/// Render a `.timestamp` cell (microseconds since the epoch) as RFC 3339 in UTC:
/// `YYYY-MM-DDTHH:MM:SS[.F]Z`, the fraction present only when nonzero and with
/// its trailing zeros trimmed (Go's `RFC3339Nano` layout). Every `i64` is
/// accepted. A year outside 0000–9999 is written in ISO 8601's expanded form
/// (`-0001-…`, `+10000-…`), which `parseIsoTimestamp` does not read back.
pub fn formatIsoTimestamp(buf: *[max_iso_timestamp_len]u8, us: i64) []const u8 {
    const days = @divFloor(us, us_per_day);
    const in_day = @mod(us, us_per_day); // [0, us_per_day)
    // |days| <= maxInt(i64) / us_per_day ~ 1.07e8, so the year always fits.
    const date = Date.fromOrdinal(days).?;
    const secs = @divFloor(in_day, timestamp_units_per_second);
    const frac: u64 = @intCast(@mod(in_day, timestamp_units_per_second));
    var w: std.Io.Writer = .fixed(buf);
    if (date.y < 0) {
        w.print("-{d:0>4}", .{@abs(date.y)}) catch unreachable;
    } else if (date.y > 9999) {
        w.print("+{d}", .{date.y}) catch unreachable;
    } else w.print("{d:0>4}", .{@as(u32, @intCast(date.y))}) catch unreachable;
    w.print("-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}", .{
        date.m,                                    date.d,
        @as(u64, @intCast(@divFloor(secs, 3600))), @as(u64, @intCast(@mod(@divFloor(secs, 60), 60))),
        @as(u64, @intCast(@mod(secs, 60))),
    }) catch unreachable;
    if (frac != 0) {
        var fb: [6]u8 = undefined;
        _ = std.mem.print(&fb, "{d:0>6}", .{frac}) catch unreachable;
        var end: usize = fb.len;
        while (fb[end - 1] == '0') end -= 1;
        w.writeByte('.') catch unreachable;
        w.writeAll(fb[0..end]) catch unreachable;
    }
    w.writeByte('Z') catch unreachable;
    return w.buffered();
}

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;

test {
    _ = @import("sweep_test.zig");
    _ = @import("frame_test.zig");
}

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

test "Value.order: NaN sorts as the greatest value, not `unreachable` -- F1" {
    // `deserialize` hands a `.float` cell any wire bit pattern with no
    // finiteness check (tag `2`, `Cursor.f64v`), so NaN is directly
    // reachable from 8 attacker-supplied bytes. `std.math.order(af, bf)`
    // used to reach `unreachable` on it: Debug/ReleaseSafe panic, ReleaseFast
    // undefined behaviour. Before the fix this test panicked on its first
    // line instead of reaching any `expectEqual` -- that IS the regression.
    const nan = std.math.nan(f64);
    try testing.expectEqual(std.math.Order.gt, Value.order(.{ .float = nan }, .{ .float = 1.0 }));
    try testing.expectEqual(std.math.Order.lt, Value.order(.{ .float = 1.0 }, .{ .float = nan }));
    try testing.expectEqual(std.math.Order.gt, Value.order(.{ .float = nan }, .{ .float = std.math.inf(f64) }));
    try testing.expectEqual(std.math.Order.eq, Value.order(.{ .float = nan }, .{ .float = nan }));
    // Sibling `eql` already handled NaN without panicking (`af == bf` is
    // `false` for any NaN operand) -- pin that it still does, so the two
    // don't drift into disagreeing about what NaN means.
    try testing.expect(!Value.eql(.{ .float = nan }, .{ .float = nan }));
    try testing.expect(!Value.eql(.{ .float = nan }, .{ .float = 1.0 }));
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

test "serialize / deserialize: row counts around the decode chunk, ragged text lengths, every cell type" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{
        .{ .name = "i", .type = .int },
        .{ .name = "t", .type = .text },
        .{ .name = "m", .type = .decimal },
        .{ .name = "f", .type = .float },
        .{ .name = "b", .type = .bool },
    };
    const text = "0123456789abcdefghij";
    for ([_]usize{ 0, 1, row_chunk - 1, row_chunk, row_chunk + 1, 2 * row_chunk, 2 * row_chunk + 5 }) |n| {
        var b = Builder.init(a, &cols);
        for (0..n) |i| {
            const cells = [_]Value{
                if (i % 5 == 0) .null else .{ .int = @as(i64, @intCast(i)) - 100 },
                .{ .text = text[0 .. i % text.len] },
                .{ .decimal = @as(i128, @intCast(i)) * decimal_scale + 7 },
                .{ .float = @as(f64, @floatFromInt(i)) / 8 },
                .{ .bool = i % 2 == 1 },
            };
            try b.appendRow(&cells);
        }
        const src = try b.toOwned();
        const bytes = try serialize(a, src);
        const out = try deserialize(a, bytes);
        try testing.expectEqual(n, out.rows.len);
        for (src.rows, out.rows) |sr, orow| {
            try testing.expectEqual(sr.len, orow.len);
            for (sr, orow) |x, y| try testing.expect(x.eql(y) or (x.isNull() and y.isNull()));
        }
        // Re-encoding the decoded table yields the same bytes.
        try testing.expectEqualSlices(u8, bytes, try serialize(a, out));
    }
}

test "serialize / deserialize: a table with no columns round-trips only with no rows (rows carry nothing to bound them)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rows = [_][]const Value{ &.{}, &.{} };
    const bytes = try serialize(a, .{ .columns = &.{}, .rows = &rows });
    try testing.expectEqual(@as(usize, 8), bytes.len);
    // Unchanged behaviour: the row count is bounded by the bytes left (0), so
    // two empty rows are refused rather than allocated on a bare claim.
    try testing.expectError(DeserializeError.Corrupt, deserialize(a, bytes));
    const empty = try deserialize(a, try serialize(a, .{ .columns = &.{}, .rows = &.{} }));
    try testing.expectEqual(@as(usize, 0), empty.rows.len);
}

test "serialize: golden vector — fixed little-endian bytes, computed independently of this module" {
    // This is the test that actually catches an endianness bug: a round-trip
    // (encode-then-decode in the same process) passes on ANY host, because
    // whatever byte order `serialize` chooses, `deserialize` undoes the same
    // way. It cannot tell native-endian encoding apart from the documented
    // little-endian contract. This test can, because `golden` below is a
    // LITERAL byte constant — never a value read back out of `serialize`,
    // `std.mem.nativeToLittle`, or any other code under test — computed
    // independently with Python's `struct.pack('<...', ...)` (a
    // well-established, host-endianness-independent oracle for
    // little-endian wire encoding) from this exact Dataset. It pins the
    // documented contract (little-endian on the wire, regardless of host),
    // not merely today's behavior on this (little-endian) CI host.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // One column of every `ColumnType` (int/float/text/bool/date/decimal),
    // exercising every cell tag (0..5) across two rows: row 0 has a real
    // value in every column, row 1 is all-null (so the null tag, and every
    // column's "does a null cell round-trip" path, is covered too).
    const cols = [_]Column{
        .{ .name = "n", .type = .int },
        .{ .name = "f", .type = .float },
        .{ .name = "t", .type = .text },
        .{ .name = "b", .type = .bool },
        .{ .name = "d", .type = .date },
        .{ .name = "m", .type = .decimal },
    };
    const rows = [_][]const Value{
        &.{
            .{ .int = 7 },
            .{ .float = 1.25 },
            .{ .text = "hi" },
            .{ .bool = true },
            .{ .text = "2024-01-31" }, // date column, Value.text representation
            .{ .decimal = 1_500_000_000_000 }, // 1.5 at decimal_scale
        },
        &.{ .null, .null, .null, .null, .null, .null },
    };
    const src = Dataset{ .columns = &cols, .rows = &rows };

    // Computed by: python3 -c "
    //   import struct
    //   def u32(v): return struct.pack('<I', v)
    //   def i64(v): return struct.pack('<q', v)
    //   def f64(v): return struct.pack('<d', v)
    //   def i128(v):
    //       if v < 0: v += 1 << 128
    //       return v.to_bytes(16, 'little')
    //   ..." (full script run once, output pasted below verbatim).
    const golden = [_]u8{
        // ncol = 6
        0x06, 0x00, 0x00, 0x00,
        // col "n": name_len=1, "n", type=int(0)
        0x01, 0x00, 0x00, 0x00,
        0x6e, 0x00,
        // col "f": name_len=1, "f", type=float(1)
        0x01, 0x00,
        0x00, 0x00, 0x66, 0x01,
        // col "t": name_len=1, "t", type=text(2)
        0x01, 0x00, 0x00, 0x00,
        0x74, 0x02,
        // col "b": name_len=1, "b", type=bool(3)
        0x01, 0x00,
        0x00, 0x00, 0x62, 0x03,
        // col "d": name_len=1, "d", type=date(4)
        0x01, 0x00, 0x00, 0x00,
        0x64, 0x04,
        // col "m": name_len=1, "m", type=decimal(5)
        0x01, 0x00,
        0x00, 0x00, 0x6d, 0x05,
        // nrow = 2
        0x02, 0x00, 0x00, 0x00,
        // row0: n = int 7 (tag 1, i64 LE)
        0x01, 0x07, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00,
        // row0: f = float 1.25 (tag 2, f64 LE bit pattern)
        0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xf4, 0x3f,
        // row0: t = text "hi" (tag 3, u32 LE len=2, bytes)
        0x03, 0x02,
        0x00, 0x00, 0x00, 0x68,
        0x69,
        // row0: b = bool true (tag 4, 0x01)
        0x04, 0x01,
        // row0: d = text "2024-01-31" (tag 3, u32 LE len=10, bytes)
        0x03,
        0x0a, 0x00, 0x00, 0x00,
        0x32, 0x30, 0x32, 0x34,
        0x2d, 0x30, 0x31, 0x2d,
        0x33, 0x31,
        // row0: m = decimal 1_500_000_000_000 (tag 5, i128 LE)
        0x05, 0x00,
        0x98, 0xf7, 0x3e, 0x5d,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
        // row1: all six cells null (tag 0)
        0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00,
    };

    const bytes = try serialize(a, src);
    try testing.expectEqualSlices(u8, &golden, bytes);

    // Feed the SAME literal golden bytes (not `bytes` from above) into
    // deserialize, so a bug that made both serialize AND deserialize agree on
    // some other (wrong) byte order — which the byte-comparison above would
    // also catch, but belt-and-suspenders — is caught here too.
    const out = try deserialize(a, &golden);
    try testing.expectEqual(@as(i64, 7), out.cell(0, "n").?.int);
    try testing.expectEqual(@as(f64, 1.25), out.cell(0, "f").?.float);
    try testing.expectEqualStrings("hi", out.cell(0, "t").?.text);
    try testing.expect(out.cell(0, "b").?.bool);
    try testing.expectEqualStrings("2024-01-31", out.cell(0, "d").?.text);
    try testing.expectEqual(@as(i128, 1_500_000_000_000), out.cell(0, "m").?.decimal);
    try testing.expect(out.cell(1, "n").?.isNull());
    try testing.expect(out.cell(1, "f").?.isNull());
    try testing.expect(out.cell(1, "t").?.isNull());
    try testing.expect(out.cell(1, "b").?.isNull());
    try testing.expect(out.cell(1, "d").?.isNull());
    try testing.expect(out.cell(1, "m").?.isNull());
}

test "serialize rejects a length that overflows the u32 wire field" {
    // The whole scenario needs a `usize` length that exceeds `u32::max`. On a
    // 32-bit target `usize` and `u32` share the same range, so no such length
    // is representable at all there — the guard this test exercises can never
    // fire on that target, and the `1 << 33` literal used to construct the
    // fixture doesn't fit `Log2Int(usize)` (`u5`) either. `@sizeOf(usize)` is
    // comptime-known, so this branches away at compile time rather than
    // skipping at runtime — the alternative would still need `1 << 33` to
    // type-check on a target where it cannot.
    if (@sizeOf(usize) < 8) return error.SkipZigTest;

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

test "toJson: invalid UTF-8 in a .text cell is replaced, not propagated -- F5" {
    // `deserialize` never validates UTF-8 on `.text` (only LENGTH is
    // bounds-checked), so a `.text` cell can carry arbitrary bytes. Before
    // the fix, `appendJsonString` copied them byte-for-byte and produced a
    // document that was not valid UTF-8 at all -- a strict receiver would
    // reject the WHOLE document, not just the bad cell.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{.{ .name = "t", .type = .text }};
    const rows = [_][]const Value{&.{.{ .text = "\x80\xff" }}};
    const json = try toJson(a, .{ .columns = &cols, .rows = &rows });
    try testing.expect(std.unicode.utf8ValidateSlice(json));
    try testing.expectEqualStrings(
        "{\"columns\":[{\"name\":\"t\",\"type\":\"text\"}],\"rows\":[[\"\u{FFFD}\u{FFFD}\"]]}",
        json,
    );

    // Positive control: valid multi-byte UTF-8 (including a 4-byte sequence)
    // passes through unchanged, and a valid sequence adjacent to an invalid
    // byte is not itself corrupted by the substitution.
    const rows2 = [_][]const Value{&.{.{ .text = "café\u{1F600}\xff" }}};
    const json2 = try toJson(a, .{ .columns = &cols, .rows = &rows2 });
    try testing.expect(std.unicode.utf8ValidateSlice(json2));
    try testing.expectEqualStrings(
        "{\"columns\":[{\"name\":\"t\",\"type\":\"text\"}],\"rows\":[[\"café\u{1F600}\u{FFFD}\"]]}",
        json2,
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

test "parseIsoDate: digits only, and the day must exist in its month" {
    // Gregorian leap rule: divisible by 4, except centuries, except every 400th.
    try testing.expect(parseIsoDate("2024-02-29") != null);
    try testing.expect(parseIsoDate("2000-02-29") != null);
    try testing.expectEqual(@as(?Date, null), parseIsoDate("2023-02-29"));
    try testing.expectEqual(@as(?Date, null), parseIsoDate("1900-02-29"));
    try testing.expectEqual(@as(?Date, null), parseIsoDate("2024-04-31")); // April has 30
    try testing.expect(parseIsoDate("2024-12-31") != null);
    try testing.expectEqual(@as(?Date, null), parseIsoDate("2024-00-10"));
    try testing.expectEqual(@as(?Date, null), parseIsoDate("2024-13-10"));
    try testing.expectEqual(@as(?Date, null), parseIsoDate("2024-01-00"));
    // `std.fmt.parseInt` takes a sign; a date field must not.
    try testing.expectEqual(@as(?Date, null), parseIsoDate("2024-+1-01"));
    try testing.expectEqual(@as(?Date, null), parseIsoDate("+024-01-01"));
    try testing.expectEqual(@as(?Date, null), parseIsoDate("2024-01- 1"));
    // Trailing text is still ignored (the documented contract).
    try testing.expectEqual(Date{ .y = 2024, .m = 1, .d = 2 }, parseIsoDate("2024-01-02T10:00").?);
}

test "Date.fromOrdinal inverts ordinal, anchored on known day counts" {
    // 0000-01-01 is 719528 days before the epoch: Python's
    // date(1970,1,1).toordinal() - date(1,1,1).toordinal() = 719162, plus the
    // 366 days of the (leap) year 0 that Python's calendar does not have.
    try testing.expectEqual(@as(i64, -719528), (Date{ .y = 0, .m = 1, .d = 1 }).ordinal());
    try testing.expectEqual(Date{ .y = 0, .m = 1, .d = 1 }, Date.fromOrdinal(-719528).?);
    try testing.expectEqual(Date{ .y = -1, .m = 12, .d = 31 }, Date.fromOrdinal(-719529).?);
    // -0400-03-01 is exactly one 400-year era (146097 days) before 0000-03-01,
    // which is 0000-01-01 + 31 + 29 (year 0 is a leap year) = -719468. The
    // pre-fix `ordinal` put it one more era earlier.
    try testing.expectEqual(@as(i64, -719468), (Date{ .y = 0, .m = 3, .d = 1 }).ordinal());
    try testing.expectEqual(@as(i64, -719468 - 146097), (Date{ .y = -400, .m = 3, .d = 1 }).ordinal());
    try testing.expectEqual(@as(i64, -719528 - 365), (Date{ .y = -1, .m = 1, .d = 1 }).ordinal()); // -1 is not leap
    try testing.expectEqual(Date{ .y = 1970, .m = 1, .d = 1 }, Date.fromOrdinal(0).?);
    try testing.expectEqual(Date{ .y = 1969, .m = 12, .d = 31 }, Date.fromOrdinal(-1).?);
    // 2000-03-01 is day 11017 (Unix time 951868800 / 86400): just past a
    // 400-year leap day, the case the era arithmetic exists for.
    try testing.expectEqual(Date{ .y = 2000, .m = 3, .d = 1 }, Date.fromOrdinal(11017).?);
    try testing.expectEqual(Date{ .y = 2000, .m = 2, .d = 29 }, Date.fromOrdinal(11016).?);
    // Round trip over five 400-year eras around the epoch, each step checked
    // against the calendar itself (the day after d is d+1, or the 1st of the
    // next month, or 1 January), not against the code under test.
    var prev = Date.fromOrdinal(-1_000_000).?;
    var day: i64 = -999_999;
    while (day <= 1_000_000) : (day += 1) {
        const d = Date.fromOrdinal(day).?;
        try testing.expectEqual(day, d.ordinal());
        if (prev.d < Date.daysInMonth(prev.y, prev.m)) {
            try testing.expectEqual(Date{ .y = prev.y, .m = prev.m, .d = prev.d + 1 }, d);
        } else if (prev.m < 12) {
            try testing.expectEqual(Date{ .y = prev.y, .m = prev.m + 1, .d = 1 }, d);
        } else try testing.expectEqual(Date{ .y = prev.y + 1, .m = 1, .d = 1 }, d);
        prev = d;
    }
    try testing.expectEqual(@as(?Date, null), Date.fromOrdinal(std.math.maxInt(i64)));
}

test "parseIsoTimestamp: well-known Unix times, offsets and fractions" {
    const s = timestamp_units_per_second;
    try testing.expectEqual(@as(?i64, 0), parseIsoTimestamp("1970-01-01T00:00:00Z"));
    try testing.expectEqual(@as(?i64, 0), parseIsoTimestamp("1970-01-01"));
    // Published anchors: Y2K = 946684800, the "1234567890" moment, and the
    // last second a signed 32-bit time_t can hold.
    try testing.expectEqual(@as(?i64, 946684800 * s), parseIsoTimestamp("2000-01-01T00:00:00Z"));
    try testing.expectEqual(@as(?i64, 1234567890 * s), parseIsoTimestamp("2009-02-13T23:31:30Z"));
    try testing.expectEqual(@as(?i64, 2147483647 * s), parseIsoTimestamp("2038-01-19T03:14:07Z"));
    // The same instant in other zones: local = UTC + offset.
    try testing.expectEqual(@as(?i64, 1234567890 * s), parseIsoTimestamp("2009-02-14T00:31:30+01:00"));
    try testing.expectEqual(@as(?i64, 1234567890 * s), parseIsoTimestamp("2009-02-13T18:01:30-05:30"));
    try testing.expectEqual(@as(?i64, 1234567890 * s), parseIsoTimestamp("2009-02-13T18:01:30-0530"));
    try testing.expectEqual(@as(?i64, 1234567890 * s), parseIsoTimestamp("2009-02-14T00:31:30+01"));
    // Separators: `t` and a space are RFC 3339 §5.6's allowed alternatives to `T`.
    try testing.expectEqual(@as(?i64, 1234567890 * s), parseIsoTimestamp("2009-02-13 23:31:30z"));
    try testing.expectEqual(@as(?i64, 1234567890 * s), parseIsoTimestamp("2009-02-13t23:31:30"));
    // Seconds are optional; no zone means UTC.
    try testing.expectEqual(@as(?i64, 1234567860 * s), parseIsoTimestamp("2009-02-13T23:31"));
    // Fractions: scaled to microseconds, digits 7..9 dropped, `,` accepted.
    try testing.expectEqual(@as(?i64, 500_000), parseIsoTimestamp("1970-01-01T00:00:00.5Z"));
    try testing.expectEqual(@as(?i64, 250_000), parseIsoTimestamp("1970-01-01T00:00:00,25"));
    try testing.expectEqual(@as(?i64, 123_456), parseIsoTimestamp("1970-01-01T00:00:00.123456789Z"));
    try testing.expectEqual(@as(?i64, 1), parseIsoTimestamp("1970-01-01T00:00:00.000001Z"));
    // Before the epoch: the fraction still counts forward from its second.
    try testing.expectEqual(@as(?i64, -1), parseIsoTimestamp("1969-12-31T23:59:59.999999Z"));
    try testing.expectEqual(@as(?i64, -s), parseIsoTimestamp("1969-12-31T23:59:59Z"));
    // Extremes of the accepted range: 0000-01-01 is day -719528 (see the
    // fromOrdinal test); 10000-01-01 is 253402300800 (9999-12-31T23:59:59 is
    // the commonly quoted 253402300799).
    try testing.expectEqual(@as(?i64, -719528 * 86400 * s), parseIsoTimestamp("0000-01-01"));
    try testing.expectEqual(@as(?i64, 253402300799 * s + 999_999), parseIsoTimestamp("9999-12-31T23:59:59.999999Z"));
}

test "parseIsoTimestamp: refuses everything outside the grammar" {
    const bad = [_][]const u8{
        "",                "2024-01-0",        "2024-02-30",
        "2024-01-01T",     "2024-01-01T10",    "2024-01-01T10:0",
        "2024-01-01T1:00", "2024-01-01X10:00", "2024-01-01T24:00:00Z",
        "2024-01-01T23:60:00Z", "2024-01-01T23:59:60Z", // no leap second
        "2024-01-01T10:00:",    "2024-01-01T10:00:5",
        "2024-01-01T10:00:00.",
        "2024-01-01T10:00:00.Z",     "2024-01-01T10:00:00.1234567890Z", // 10 fraction digits
        "2024-01-01T10:00:00Zjunk",  "2024-01-01T10:00:00+24:00",
        "2024-01-01T10:00:00+01:60", "2024-01-01T10:00:00+1",
        "2024-01-01T10:00:00+01:",   "2024-01-01T10:00:00+01:0",
        "2024-01-01T10:00:00 ",      "2024-01-01T+1:00",
        "2024-01-01T10:00:00+0100x", "2024-01-01T10:00:00Q",
    };
    for (bad) |b| {
        if (parseIsoTimestamp(b)) |v| {
            std.debug.print("accepted {s} as {d}\n", .{ b, v });
            return error.TestUnexpectedResult;
        }
    }
}

test "formatIsoTimestamp: RFC 3339 UTC, trimmed fraction, expanded years" {
    var buf: [max_iso_timestamp_len]u8 = undefined;
    const s = timestamp_units_per_second;
    try testing.expectEqualStrings("1970-01-01T00:00:00Z", formatIsoTimestamp(&buf, 0));
    try testing.expectEqualStrings("2009-02-13T23:31:30.123456Z", formatIsoTimestamp(&buf, 1234567890 * s + 123_456));
    try testing.expectEqualStrings("1970-01-01T00:00:00.5Z", formatIsoTimestamp(&buf, 500_000));
    try testing.expectEqualStrings("1970-01-01T00:00:00.00001Z", formatIsoTimestamp(&buf, 10));
    try testing.expectEqualStrings("1969-12-31T23:59:59.999999Z", formatIsoTimestamp(&buf, -1));
    try testing.expectEqualStrings("9999-12-31T23:59:59Z", formatIsoTimestamp(&buf, 253402300799 * s));
    try testing.expectEqualStrings("+10000-01-01T00:00:00Z", formatIsoTimestamp(&buf, 253402300800 * s));
    try testing.expectEqualStrings("-0001-12-31T00:00:00Z", formatIsoTimestamp(&buf, -719529 * 86400 * s));
    // The i64 limits, as numpy prints datetime64[us] at +/-(2**63-1)
    // ('294247-01-10T04:00:54.775807', '-290308-12-21T19:59:05.224193'),
    // and minInt is one microsecond before the latter. DuckDB documents the
    // same maximum for its microsecond TIMESTAMP.
    try testing.expectEqualStrings("+294247-01-10T04:00:54.775807Z", formatIsoTimestamp(&buf, std.math.maxInt(i64)));
    try testing.expectEqualStrings("-290308-12-21T19:59:05.224192Z", formatIsoTimestamp(&buf, std.math.minInt(i64)));
}

test "formatIsoTimestamp / parseIsoTimestamp round-trip across years 0000..9999" {
    var prng = std.Random.DefaultPrng.init(0x7173);
    const r = prng.random();
    const lo: i64 = -719528 * us_per_day;
    const hi: i64 = 253402300800 * timestamp_units_per_second - 1;
    var buf: [max_iso_timestamp_len]u8 = undefined;
    for (0..20_000) |_| {
        const us = r.intRangeAtMost(i64, lo, hi);
        const text = formatIsoTimestamp(&buf, us);
        try testing.expectEqual(@as(?i64, us), parseIsoTimestamp(text));
    }
}

test "Value.cast(.timestamp) and toJson of a timestamp column" {
    const s = timestamp_units_per_second;
    try testing.expectEqual(Value{ .int = 42 }, (Value{ .int = 42 }).cast(.timestamp).?);
    try testing.expectEqual(Value{ .int = -3 }, (Value{ .float = -3.9 }).cast(.timestamp).?);
    try testing.expectEqual(@as(?Value, null), (Value{ .float = std.math.nan(f64) }).cast(.timestamp));
    try testing.expectEqual(Value{ .int = 1234567890 * s }, (Value{ .text = "2009-02-13T23:31:30Z" }).cast(.timestamp).?);
    try testing.expectEqual(Value{ .int = 946684800 * s }, (Value{ .text = "2000-01-01" }).cast(.timestamp).?);
    try testing.expectEqual(@as(?Value, null), (Value{ .text = "yesterday" }).cast(.timestamp));
    try testing.expectEqual(@as(?Value, null), (Value{ .bool = true }).cast(.timestamp));
    try testing.expectEqual(@as(?Value, null), (@as(Value, .null)).cast(.timestamp));
    try testing.expectEqual(@as(?Value, null), (Value{ .decimal = 1 }).cast(.timestamp));

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "at", .type = .timestamp }, .{ .name = "n", .type = .int } };
    const r0 = [_]Value{ .{ .int = 1234567890 * s + 500_000 }, .{ .int = 7 } };
    const r1 = [_]Value{ .null, .{ .int = 1234567890 * s } };
    // A hand-built row longer than the schema: the extra cell renders untyped.
    const r2 = [_]Value{ .{ .text = "raw" }, .{ .int = 1 }, .{ .int = 5 } };
    const rows = [_][]const Value{ &r0, &r1, &r2 };
    const json = try toJson(a, .{ .columns = &cols, .rows = &rows });
    try testing.expectEqualStrings(
        \\{"columns":[{"name":"at","type":"timestamp"},{"name":"n","type":"int"}],"rows":[["2009-02-13T23:31:30.5Z",7],[null,1234567890000000],["raw",1,5]]}
    , json);
}

test "wire: a timestamp column round-trips, and column type 7 is still refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{.{ .name = "t", .type = .timestamp }};
    const r0 = [_]Value{.{ .int = -1 }};
    const rows = [_][]const Value{&r0};
    const bytes = try serialize(a, .{ .columns = &cols, .rows = &rows });
    // ncol=1 | name len 1 | "t" | type 6 | nrow=1 | int tag 1 | -1 as i64 LE.
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 0, 0, 0, 1, 0, 0, 0, 't', 6, 1, 0, 0, 0, 1 } ++ @as([8]u8, @splat(0xff)), bytes);
    const back = try deserialize(a, bytes);
    try testing.expectEqual(ColumnType.timestamp, back.columns[0].type);
    try testing.expectEqual(Value{ .int = -1 }, back.rows[0][0]);
    var bad = try a.dupe(u8, bytes);
    bad[9] = 7;
    try testing.expectError(error.Corrupt, deserialize(a, bad));
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

test "deserialize: the column bound is 5 bytes per column, checked before any allocation" {
    // Mutation 2026-10-04: weakening the bound to `ncol > remaining` survived,
    // because every existing case either claimed 4e9 columns or was honest.
    // Five columns need at least 5 x 5 = 25 bytes (u32 name length + 1 type
    // byte each, `min_encoded_column_bytes`); 24 are present, so the claim is
    // provably a lie and must be refused without touching the allocator. A
    // failing allocator turns any allocation into OutOfMemory, so getting
    // Corrupt proves nothing was allocated.
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const claim = "\x05\x00\x00\x00" ++ strRepeat("\x00", 24);
    try testing.expectError(DeserializeError.Corrupt, deserialize(failing.allocator(), claim));
    // With 25 bytes the claim is plausible: the decoder allocates (and here
    // gets OutOfMemory, which shows the bound let it through).
    try testing.expectError(DeserializeError.OutOfMemory, deserialize(failing.allocator(), claim ++ "\x00"));
}

test "edge cases the mutation run asked for" {
    // Two decimals 1 raw unit apart at 2^60: f64 has a 53-bit significand, so
    // both convert to the same float and only the exact i128 compare tells
    // them apart (killed: dropping the decimal fast path in `eql`).
    const big: i128 = 1 << 60;
    try testing.expectEqual((Value{ .decimal = big }).asFloat().?, (Value{ .decimal = big + 1 }).asFloat().?);
    try testing.expect(!Value.eql(.{ .decimal = big }, .{ .decimal = big + 1 }));
    try testing.expect(Value.eql(.{ .decimal = big }, .{ .decimal = big }));
    // 2^63 is exactly representable as f64 and is one past maxInt(i64), so it
    // must be refused (killed: `f > hi` instead of `f >= hi`, which reached
    // `@intFromFloat` with an out-of-range operand).
    try testing.expectEqual(@as(?i64, null), Value.floatToInt(i64, 9223372036854775808.0));
    try testing.expectEqual(@as(?i64, -9223372036854775807 - 1), Value.floatToInt(i64, -9223372036854775808.0));
    // Same names, different type: still a schema mismatch.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const c1 = [_]Column{.{ .name = "x", .type = .int }};
    const c2 = [_]Column{.{ .name = "x", .type = .float }};
    const d1: Dataset = .{ .columns = &c1, .rows = &.{} };
    const d2: Dataset = .{ .columns = &c2, .rows = &.{} };
    try testing.expectError(error.SchemaMismatch, d1.concat(arena.allocator(), d2));
    // The second separator is checked too.
    try testing.expectEqual(@as(?Date, null), parseIsoDate("2024-01x01"));
}

// ── fuzz: `deserialize` is the untrusted-input surface ─────────────────────
//
// ⚠ This harness opened with `smith.bytes(&buf)` followed by
// `smith.valueRangeAtMost(u16, 0, buf.len)`. `bytes` copies `min(buf.len,
// in.len)` octets and the ranged draw then reads EIGHT more as a little-endian
// u64, returning the range minimum when fewer remain — so the length was 0 on
// every input a corpus can carry and `deserialize` was handed an empty slice,
// which fails on the very first `u32v()`. It also had no corpus, so outside
// `--fuzz` it ran that one empty input for ever: the `ncol`/`nrow` bounds above
// (both found by an actual fuzz sweep, one of them a 32 GB OOM) had no
// regression coverage from this target at all.

const testkit = @import("testkit");

/// `testkit.fuzz.seedHex`, aliased so the corpus below reads as the wire images
/// it is. A corpus entry is not the frame: `Smith.slice` reads a little-endian
/// `u32` length first, so a raw image would arrive minus its own first four
/// octets.
const seed = testkit.fuzz.seedHex;

/// Malformed images, in the format the length draw reads. Every refusal the
/// value tests above pin, expressed at the wire level: the two count-bound
/// rejections, a truncated header, an out-of-range type tag, and an unknown
/// value tag.
const malformed_seeds = [_][]const u8{
    seed(""), // no `ncol` field at all
    seed("01"), // `ncol` truncated mid-field
    seed("ffffffff"), // ncol = 4294967295 with nothing behind it — the OOM bound
    seed("0100000000000000" ++ "01" ++ "ffffffff"), // one column, then nrow = 4294967295
    seed("0100000000000000" ++ "ff" ++ "00000000"), // type tag 255 is not a `ColumnType`
    seed("0100000000000000" ++ "01" ++ "01000000" ++ "07"), // one row whose value tag is 7
    seed("0100000000000000" ++ "01" ++ "01000000" ++ "01" ++ "0102"), // an `int` cell truncated to 2 octets
    seed("01000000" ++ "ffffffff" ++ "00"), // a column name claiming 4 GB
    seed("0100000000000000" ++ "02" ++ "01000000" ++ "03" ++ "ffffffff"), // a `text` cell claiming 4 GB
    seed("00000000" ++ "ffffffff"), // zero columns, nrow = 4294967295 (the `@max(1, ncol)` case)
};

/// The whole corpus: the malformed images above, plus every image this module
/// ACCEPTS — and those have no captured form here, they are what `serialize`
/// produces. So the positive half is built by the module's own encoder at run
/// time rather than freezing a paste of it.
///
/// ⭐ The harness and the guard below both build it from HERE. A guard
/// measuring a different corpus from the one the harness gets is not a guard,
/// and this corpus scores 0 accepted without the built images: ten seeds, every
/// one of which `deserialize` refuses by construction.
const Corpus = struct {
    scratch: [4096]u8 = undefined,
    store: [3][4 + 256]u8 = undefined,
    entries: [malformed_seeds.len + 3][]const u8 = undefined,

    fn build(self: *Corpus) ![]const []const u8 {
        var fba = std.heap.FixedBufferAllocator.init(&self.scratch);
        const a = fba.allocator();
        @memcpy(self.entries[0..malformed_seeds.len], &malformed_seeds);

        // Empty but well-formed: no columns, no rows. Legal, and the shortest
        // image `serialize` can emit.
        const empty = try serialize(a, .{ .columns = &.{}, .rows = &.{} });
        self.entries[malformed_seeds.len + 0] = testkit.fuzz.seedInto(&self.store[0], empty);

        // Every column type and every value tag, including the appended
        // `timestamp` column type 6 and `decimal` tag 5 — the one whose ordinal the comment in `serialize`
        // warns must never renumber.
        const cols = [_]Column{
            .{ .name = "i", .type = .int },
            .{ .name = "f", .type = .float },
            .{ .name = "t", .type = .text },
            .{ .name = "b", .type = .bool },
            .{ .name = "d", .type = .date },
            .{ .name = "m", .type = .decimal },
            .{ .name = "s", .type = .timestamp },
        };
        const r0 = [_]Value{ .{ .int = -1 }, .{ .float = 1.5 }, .{ .text = "hi" }, .{ .bool = true }, .{ .text = "2026-09-07" }, .{ .decimal = 12345 }, .{ .int = 0 } };
        const r1 = [_]Value{ .null, .null, .{ .text = "" }, .{ .bool = false }, .null, .{ .decimal = -1 }, .null };
        const rows = [_][]const Value{ &r0, &r1 };
        const full = try serialize(a, .{ .columns = &cols, .rows = &rows });
        self.entries[malformed_seeds.len + 1] = testkit.fuzz.seedInto(&self.store[1], full);

        // The same image with its last octet removed: a well-formed prefix that
        // must fail on the DATA rather than on a count, which is the case the
        // "must not reject a legitimate document" test above is about.
        self.entries[malformed_seeds.len + 2] = testkit.fuzz.seedInto(&self.store[2], full[0 .. full.len - 1]);
        return &self.entries;
    }
};

test {
    _ = @import("fuzz_test.zig");
}

test "fuzz: deserialize never panics on arbitrary bytes" {
    var corpus: Corpus = .{};
    try testing.fuzz({}, fuzzDeserialize, .{ .corpus = try corpus.build() });
}

fn fuzzDeserialize(_: void, smith: *std.testing.Smith) !void {
    const ft = @import("fuzz_test.zig");
    var script: [300]u8 = undefined;
    const n: usize = smith.slice(&script);
    var src: ft.ScriptSource = .{ .cur = .{ .bytes = script[0..n] } };
    try ft.deserializeHarness(ft.ScriptSource, &src, testing.allocator);
}

test "corpus: every seed reaches deserialize, and the cells decoded are pinned" {
    // ⭐ Cells decoded is the second number, and it is the one that matters:
    // `deserialize("")` is not legal here (it fails on the first `u32v`), but
    // the empty well-formed image IS accepted and carries no cells — so an
    // "accepted > 0" guard would read green on a corpus that decodes nothing.
    // A cell count cannot be produced by any input the collapsed draw could
    // deliver.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var cells: usize = 0;
    var corpus: Corpus = .{};
    const entries = try corpus.build();
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const d = deserialize(arena.allocator(), buf[0..len]) catch continue;
        accepted += 1;
        for (d.rows) |row| cells += row.len;
    }
    // The first seed is deliberately the empty image, so it is `len - 1`.
    try testing.expectEqual(entries.len - 1, nonempty);
    // Measured 2026-09-07: with the collapsing draw every seed arrived empty,
    // 0 were accepted and 0 cells were decoded. After: 2 accepted, 12 cells;
    // 14 since the `.timestamp` column joined the built image (2 rows x 7).
    try testing.expectEqual(@as(usize, 2), accepted);
    try testing.expectEqual(@as(usize, 14), cells);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}
