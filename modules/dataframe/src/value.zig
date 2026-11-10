// SPDX-License-Identifier: MIT
//! The cell model: `ColumnType`, `Column`, `Value`, and the ISO date and timestamp
//! helpers a cast needs. Taken from `dataset` (the same authors, MIT), unchanged in
//! meaning so that `dataset`'s row verbs stay a differential oracle for this module
//! until they retire: equal cells order, compare and cast the same way in both.

const std = @import("std");
const datefmt = @import("datefmt");
const dtype = @import("dtype.zig");
const tz = @import("tz");

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
    /// the convention). The order of the tags is `dataset`'s; do not reorder.
    decimal,
    /// An instant on the UTC timeline. The cell value is `Value.int`: whole
    /// MICROseconds since 1970-01-01T00:00:00Z (`timestamp_units_per_second`),
    /// the unit of PostgreSQL's and DuckDB's `TIMESTAMP` and of Arrow's
    /// `timestamp[us]`. Like `.date`, the column tag carries the intent and the
    /// cell reuses an existing `Value` variant, so no consumer `switch` over
    /// `Value` gets a new arm. Text in, text out: `parseIsoTimestamp` /
    /// `formatIsoTimestamp`.
    timestamp,
    /// Text drawn from a small set of values (pandas `category`, polars `Categorical`).
    /// The cell value is `Value.text`, so every verb reads it as text and sorts it
    /// lexically, as both engines do. `cast` to it stores the column dictionary-encoded
    /// (`ColumnData.categorical`: one `u32` code per row, the distinct values once,
    /// lexically ordered, so the codes are pandas' `cat.codes`); a column declared
    /// categorical may also hold plain text storage, which reads the same.
    categorical,
    /// A signed length of time. The cell value is `Value.int`: whole MICROseconds, the
    /// unit of `.timestamp` (polars `Duration("us")`, pandas `timedelta64[us]`).
    /// `ts - ts` is a duration, `ts ± duration` a timestamp (`Expr`). Text in and out:
    /// `parseDurationCell` / `formatIsoDuration` (ISO 8601, polars' JSON form).
    duration,
    /// A variable-length list of cells per row (polars `List`, Arrow `list`). The cell
    /// value is `Value.list`, a view of its elements; the storage is
    /// `ColumnData.list` (Arrow's layout: `u32` offsets into one column of elements).
    /// `Column.inner[0]` declares the element column (its type; its name is not used).
    list,
    /// A record of named fields per row (polars `Struct`, Arrow `struct`). The cell
    /// value is `Value.record`, a view of the row's fields; the storage is
    /// `ColumnData.@"struct"`, which holds the field names. `Column.inner` declares the
    /// fields, in order.
    @"struct",
    /// Fixed-width numbers (wave W11), polars `Int8`..`UInt64`, `Float32`; `.int` is Int64
    /// and `.float` Float64. A column of one of these holds its own array
    /// (`ColumnData.int8`.., `frame.conform`); its cells read as `Value.int` (`Value.uint`
    /// for a UInt64 above `maxInt(i64)`) and `Value.float` (a Float32 widened exactly).
    /// Predicates, ranges and the meeting type of two operands: `dtype.zig`.
    int8,
    int16,
    int32,
    uint8,
    uint16,
    uint32,
    uint64,
    float32,
    /// A time of day (polars `Time`, pandas' `datetime.time` cells). The cell value is
    /// `Value.int`: whole MICROseconds since midnight, `[0, us_per_day)` (pandas'
    /// precision; polars counts nanoseconds and the digits past the sixth are dropped on
    /// the way in). Text in and out: `parseTimeOfDay` / `formatTimeOfDay`.
    time,
    /// A fixed-size array per row (polars `Array(inner, n)`, Arrow `fixed_size_list`). It
    /// is a `.list` column with a declared width: the cell value is `Value.list`, the
    /// storage `ColumnData.list`, `Column.inner[0]` the element column and
    /// `Column.array_width` the length every valid row has (`frame.arraysConform`).
    array,
};

pub const Column = struct {
    name: []const u8,
    type: ColumnType,
    /// The element column of a `.list` (one entry), the fields of a `.struct`; empty for
    /// every other type. An empty list column still knows its element type through it
    /// (polars `List(Int64)`); a nested column without it is read by its storage alone.
    inner: []const Column = &.{},
    /// The IANA zone a `.timestamp` column carries (polars `Datetime("us", time_zone=...)`,
    /// pandas `datetime64[us, zone]`); null is a naive column, today's behaviour. **Schema
    /// metadata only: the cells stay UTC microseconds** (both engines store UTC and carry the
    /// zone as a tag), so sorting, joining, grouping and comparing work on instants, and a verb
    /// that passes the column on keeps the tag. Valid on `.timestamp` only (see `checkZone`);
    /// the name is one `tz.find` knows. Read by the `dt` fields, `truncate`, `strftime`,
    /// `resample` and the writers, which show the zone's wall clock.
    time_zone: ?[]const u8 = null,
    /// The length every valid row of an `.array` column has (polars `Array(inner, width)`);
    /// 0 is a legal width (`[[], []]`). Meaningless for every other type, where it stays 0.
    array_width: u32 = 0,

    /// `error.BadArgument` when `time_zone` is set on a column that is not a `.timestamp`, is
    /// empty or names no zone `tz` knows; checked down the declared inner columns too. Every
    /// entry that accepts a schema from the caller (`readCsv`/`readJson` `types`,
    /// `matchToSchema`, `cast`) calls it.
    pub fn checkZone(self: Column) error{BadArgument}!void {
        return checkZoneAt(self, 0);
    }

    fn checkZoneAt(self: Column, depth: u8) error{BadArgument}!void {
        if (self.time_zone) |z| {
            if (self.type != .timestamp or tz.find(z) == null) return error.BadArgument;
        }
        if (depth >= max_nesting_depth) return;
        for (self.inner) |c| try checkZoneAt(c, depth + 1);
    }

    /// The zone a column of type `ty` derived from `src` keeps: `src`'s when both are
    /// timestamps (a timestamp aggregate such as `min`, `first`, `mean`), else none.
    pub fn zoneFor(src: Column, ty: ColumnType) ?[]const u8 {
        return if (ty == .timestamp and src.type == .timestamp) src.time_zone else null;
    }

    /// `self` with the element column and width of `src` when both are `.array` columns: the
    /// shape a verb that keeps an array column's type keeps with it (`array_width` is part of
    /// the type, as `time_zone` is a timestamp's).
    pub fn withShape(self: Column, src: Column) Column {
        var c = self;
        if (self.type == .array and src.type == .array) {
            c.inner = src.inner;
            c.array_width = src.array_width;
        }
        return c;
    }

    /// The declared element column of a `.list`, or the field `i` of a `.struct` named
    /// `name`; null when the schema does not say.
    pub fn innerAt(self: Column, i: usize, name: []const u8) ?Column {
        if (self.type == .list or self.type == .array) return if (self.inner.len > 0) self.inner[0] else null;
        if (i < self.inner.len and std.mem.eql(u8, self.inner[i].name, name)) return self.inner[i];
        for (self.inner) |c| if (std.mem.eql(u8, c.name, name)) return c;
        return null;
    }
};

/// The deepest a nested value goes: a `.list` or `.record` cell this many levels below a
/// column reads as null in every walker (comparison, keys, gather, building, the writers),
/// so a hand-built storage that points back at itself ends there, never in a stack
/// overflow. Arrow's IPC readers use the same bound. The readers keep a value nested
/// deeper than this as its JSON text.
pub const max_nesting_depth: u8 = 64;

const frame = @import("frame.zig");

/// A `.list` cell: elements `start..end` of `items`, borrowed from the column.
pub const ListView = struct {
    items: *const frame.ColumnData,
    start: u32,
    end: u32,

    /// A hand-built view running backwards (`start > end`) is empty, never an overflow.
    pub fn len(self: ListView) usize {
        return self.end -| self.start;
    }

    /// Element `i` (`i < len()`); an element past the storage's end reads as null.
    pub fn get(self: ListView, i: usize) Value {
        return self.items.get(@as(usize, self.start) + i);
    }
};

/// A `.record` cell: row `row` of a struct column, borrowed from it.
pub const RecordView = struct {
    fields: *const frame.StructColumn,
    row: usize,

    pub fn len(self: RecordView) usize {
        return self.fields.names.len;
    }

    pub fn name(self: RecordView, i: usize) []const u8 {
        return self.fields.names[i];
    }

    /// Field `i` (`i < len()`); a field with no storage reads as null.
    pub fn get(self: RecordView, i: usize) Value {
        return if (i < self.fields.children.len) self.fields.children[i].get(self.row) else .null;
    }

    /// The field named `n`, or null when the record has none.
    pub fn field(self: RecordView, n: []const u8) ?Value {
        for (self.fields.names, 0..) |x, i| if (std.mem.eql(u8, x, n)) return self.get(i);
        return null;
    }
};

/// Fixed-point scale for `Value.decimal`'s raw `i128`, matching the sibling
/// `decimal` module's `Decimal.scale_factor` (12 fractional digits). This module
/// stores and moves the raw integer and does no decimal arithmetic of its own. Consumers that need
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
/// see that constant's doc comment. `list` and `record` are views into a nested
/// column (`ListView`, `RecordView`), borrowed as `.text` is.
pub const Value = union(enum) {
    null,
    int: i64,
    float: f64,
    text: []const u8,
    bool: bool,
    decimal: i128,
    list: ListView,
    record: RecordView,
    /// A UInt64 cell above `maxInt(i64)`; every smaller one is `.int`. Numeric like
    /// `.int`: it orders, compares, keys and converts by its exact value.
    uint: u64,

    /// Coerce a numeric cell to f64 (int→float, float→float, decimal→float by
    /// dividing out the scale — lossy for values needing exact precision, use
    /// the raw `i128` directly for that). `null`/text/bool → null.
    pub fn asFloat(self: Value) ?f64 {
        return switch (self) {
            .int => |i| @floatFromInt(i),
            .uint => |u| @floatFromInt(u),
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
            .list, .record => nestedEql(a, b, 0),
            else => false,
        };
    }

    /// `eql` element by element (a list) or field by field in order (a record), as polars
    /// compares nested values; past `max_nesting_depth` both sides read as null.
    fn nestedEql(a: Value, b: Value, depth: u8) bool {
        if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
        switch (a) {
            .list => |x| {
                const y = b.list;
                if (x.len() != y.len()) return false;
                for (0..x.len()) |i| if (!elemEql(x.get(i), y.get(i), depth + 1)) return false;
                return true;
            },
            .record => |x| {
                const y = b.record;
                if (x.len() != y.len()) return false;
                for (0..x.len()) |i| if (!elemEql(x.get(i), y.get(i), depth + 1)) return false;
                return true;
            },
            else => unreachable, // the callers pass nested values
        }
    }

    fn elemEql(a: Value, b: Value, depth: u8) bool {
        const x = capped(a, depth);
        const y = capped(b, depth);
        if (isNested(x) or isNested(y)) return nestedEql(x, y, depth);
        return x.eql(y);
    }

    /// `v`, or null for a nested value at `max_nesting_depth`: what every walker reads there.
    pub fn capped(v: Value, depth: u8) Value {
        return if (depth >= max_nesting_depth and isNested(v)) .null else v;
    }

    pub fn isNested(v: Value) bool {
        return v == .list or v == .record;
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
    /// A `.float` cell may hold any bit pattern, NaN included: nothing on the
    /// way in checks finiteness.
    pub fn order(a: Value, b: Value) std.math.Order {
        if (isNumeric(a) and isNumeric(b)) return orderNumeric(a, b);
        const ra = typeRank(a);
        const rb = typeRank(b);
        if (ra != rb) return std.math.order(ra, rb);
        return switch (a) {
            .text => |at| std.mem.order(u8, at, b.text),
            .bool => |ab| std.math.order(@intFromBool(ab), @intFromBool(b.bool)),
            .list, .record => nestedOrder(a, b, 0),
            else => .eq, // both null
        };
    }

    /// Lexicographic: element by element (field by field, in order), then the shorter
    /// first — polars' order of lists and structs. Same tag on both sides (the rank).
    fn nestedOrder(a: Value, b: Value, depth: u8) std.math.Order {
        switch (a) {
            .list => |x| {
                const y = b.list;
                for (0..@min(x.len(), y.len())) |i| {
                    const o = elemOrder(x.get(i), y.get(i), depth + 1);
                    if (o != .eq) return o;
                }
                return std.math.order(x.len(), y.len());
            },
            .record => |x| {
                const y = b.record;
                for (0..@min(x.len(), y.len())) |i| {
                    const o = elemOrder(x.get(i), y.get(i), depth + 1);
                    if (o != .eq) return o;
                }
                return std.math.order(x.len(), y.len());
            },
            else => unreachable, // the callers pass nested values
        }
    }

    fn elemOrder(a: Value, b: Value, depth: u8) std.math.Order {
        const x = capped(a, depth);
        const y = capped(b, depth);
        if (isNested(x) and std.meta.activeTag(x) == std.meta.activeTag(y)) return nestedOrder(x, y, depth);
        return x.order(y); // ranks differ, or neither is nested
    }

    fn isNumeric(v: Value) bool {
        return switch (v) {
            .int, .uint, .float, .decimal => true,
            else => false,
        };
    }

    fn isNanValue(v: Value) bool {
        return v == .float and std.math.isNan(v.float);
    }

    /// Exact three-kind numeric order, NaN last. `std.math.order(af, bf)`
    /// reaches `unreachable` whenever an operand is NaN (every one of
    /// `==`/`<`/`>` is false), which is why NaN is handled first: Debug and
    /// ReleaseSafe would panic and ReleaseFast would return garbage on a NaN cell.
    fn orderNumeric(a: Value, b: Value) std.math.Order {
        const an = isNanValue(a);
        const bn = isNanValue(b);
        if (an or bn) {
            if (an and bn) return .eq;
            return if (an) .gt else .lt;
        }
        // Integers (`.int`, `.uint`) as i128: a UInt64 above 2^63 against an i64 is exact.
        const ai: ?i128 = switch (a) {
            .int => |x| x,
            .uint => |x| x,
            else => null,
        };
        const bi: ?i128 = switch (b) {
            .int => |x| x,
            .uint => |x| x,
            else => null,
        };
        if (ai) |x| {
            if (bi) |y| return std.math.order(x, y);
            return switch (b) {
                .float => |y| orderFloatInt(y, x).invert(),
                .decimal => |y| std.math.order(x * decimal_scale, y), // |x| < 2^64: fits i128 ×10^12
                else => unreachable, // callers pass numerics only (isNumeric)
            };
        }
        return switch (a) {
            .float => |x| if (bi) |y| orderFloatInt(x, y) else switch (b) {
                .float => |y| std.math.order(x, y),
                .decimal => |y| orderFloatDecimal(x, y),
                else => unreachable, // callers pass numerics only (isNumeric)
            },
            .decimal => |x| if (bi) |y| std.math.order(x, y * decimal_scale) else switch (b) {
                .float => |y| orderFloatDecimal(y, x).invert(),
                .decimal => |y| std.math.order(x, y),
                else => unreachable, // callers pass numerics only (isNumeric)
            },
            else => unreachable, // callers pass numerics only (isNumeric)
        };
    }

    /// Order of the (non-NaN) float `f` against the integer `i` (an i64 or a u64), exactly.
    fn orderFloatInt(f: f64, i: i128) std.math.Order {
        if (f >= 18446744073709551616.0) return .gt; // 2^64: above every i64 and u64
        if (f < -9223372036854775808.0) return .lt;
        const fl = @floor(f);
        const fi: i128 = @intFromFloat(fl); // in range: checked above
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
            .int, .uint, .float, .decimal => 2,
            .text => 3,
            .list => 4,
            .record => 5,
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
    /// date cell becomes its UTC midnight); anything else → null. `.categorical`
    /// is `.text`'s rule (the encoding is the column's, not the cell's); `.duration`
    /// is `.timestamp`'s with `parseDurationCell` for text. `.list` and `.struct` keep a
    /// cell of their kind and make nothing else one (text is not parsed as JSON here).
    pub fn cast(self: Value, to: ColumnType) ?Value {
        return switch (to) {
            // Toward zero, then the width's range: out of it is null (`dtype.fitInt`).
            .int, .int8, .int16, .int32, .uint8, .uint16, .uint32, .uint64 => if (dtype.truncInt(self)) |x| dtype.fitInt(x, to) else null,
            .float => if (self.asFloat()) |f| .{ .float = f } else null,
            // Rounded to the nearest f32; past its range ±infinity, as polars' cast.
            .float32 => if (self.asFloat()) |f| .{ .float = dtype.roundF32(f) } else null,
            .text, .date, .categorical => if (self.asText()) |t| .{ .text = t } else null,
            .bool => switch (self) {
                .bool => self,
                .int => |i| .{ .bool = i != 0 },
                .uint => .{ .bool = true }, // above maxInt(i64): never zero
                .float => |f| .{ .bool = f != 0 },
                else => null,
            },
            .decimal => switch (self) {
                .decimal => self,
                .int => |i| .{ .decimal = @as(i128, i) * decimal_scale },
                .uint => |u| .{ .decimal = @as(i128, u) * decimal_scale }, // < 2^64 × 10^12 < 2^127
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
            .duration => switch (self) {
                .int => self,
                .float => |f| if (floatToInt(i64, f)) |i| .{ .int = i } else null,
                .text => |t| if (parseDurationCell(t)) |us| .{ .int = us } else null,
                else => null,
            },
            // An int (or a duration's int) is microseconds since midnight; text is
            // `parseTimeOfDay`'s; outside one day null (polars refuses the row).
            .time => switch (self) {
                .int => |i| if (isTimeOfDay(i)) self else null,
                .float => |f| if (floatToInt(i64, f)) |i| (if (isTimeOfDay(i)) Value{ .int = i } else null) else null,
                .text => |t| if (parseTimeOfDay(t)) |us| .{ .int = us } else null,
                else => null,
            },
            // A nested cell keeps its kind; nothing else becomes one.
            .list, .array => if (self == .list) self else null,
            .@"struct" => if (self == .record) self else null,
        };
    }
};

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
        return datefmt.ymdToEpochDay(self.y, self.m, self.d);
    }

    /// The inverse of `ordinal`: the proleptic-Gregorian date `days` after
    /// 1970-01-01 (Howard Hinnant's civil-from-days). Null only when the year
    /// does not fit `Date.y` (|days| beyond ~7.8e11, far outside any timestamp).
    pub fn fromOrdinal(days: i64) ?Date {
        const p = datefmt.epochDayToYmd(days);
        // `datefmt` saturates where the year leaves the i32 range; a saturated
        // result does not map back to `days`, which is the null case here.
        if (datefmt.ymdToEpochDay(p.year, p.month, p.day) != days) return null;
        return .{ .y = p.year, .m = @intCast(p.month), .d = @intCast(p.day) };
    }

    /// Days in month `m` (1–12) of year `y`, Gregorian leap rule.
    pub fn daysInMonth(y: i32, m: u8) u8 {
        // Outside 1-12 the historical answer is 31 (`datefmt` says 0).
        if (m < 1 or m > 12) return 31;
        return @intCast(datefmt.daysInMonth(y, m));
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

// ── times of day (`.time` cells: `Value.int` microseconds since midnight) ───

/// Longest string `formatTimeOfDay` writes: `HH:MM:SS.ffffff`.
pub const max_time_len = 15;

/// A time of day as microseconds since midnight, or null: `H[H]:M[M][:S[S][.F]]` after
/// leading blanks and tabs (polars' `str.to_time` and pandas read `1:2:3` and ` 01:02:03`, oracle2k
/// `time-str-to-time`), hours 0-23, minutes and seconds 0-59, the fraction one or more digits
/// with those past the sixth dropped (polars keeps nine as nanoseconds). No sign, no trailing
/// blank. `H:M` is pandas'; polars' `str.to_time()` wants the seconds, so this reads a
/// superset. `24:00` and a leap second `23:59:60` are null (Python's `time` refuses both).
pub fn parseTimeOfDay(s: []const u8) ?i64 {
    var i: usize = 0;
    while (i < s.len and (s[i] == ' ' or s[i] == '\t')) i += 1;
    const h = fieldAt(s, &i) orelse return null;
    if (i >= s.len or s[i] != ':') return null;
    i += 1;
    const m = fieldAt(s, &i) orelse return null;
    var sec: u32 = 0;
    var frac: i64 = 0;
    if (i < s.len) {
        if (s[i] != ':') return null;
        i += 1;
        sec = fieldAt(s, &i) orelse return null;
        if (i < s.len) {
            if (s[i] != '.' or i + 1 == s.len) return null;
            var k: usize = 0;
            for (s[i + 1 ..]) |c| {
                if (c < '0' or c > '9') return null;
                if (k < 6) frac = frac * 10 + (c - '0');
                k += 1;
            }
            while (k < 6) : (k += 1) frac *= 10;
        }
    }
    if (h > 23 or m > 59 or sec > 59) return null;
    return (@as(i64, h) * 3600 + @as(i64, m) * 60 + sec) * timestamp_units_per_second + frac;
}

/// One or two digits at `s[i..]`, `i` moved past them.
fn fieldAt(s: []const u8, i: *usize) ?u32 {
    var n: u32 = 0;
    var k: usize = 0;
    while (k < 2 and i.* < s.len and s[i.*] >= '0' and s[i.*] <= '9') : (k += 1) {
        n = n * 10 + (s[i.*] - '0');
        i.* += 1;
    }
    return if (k == 0) null else n;
}

/// True when `us` is a time of day a `.time` cell can hold.
pub fn isTimeOfDay(us: i64) bool {
    return us >= 0 and us < us_per_day;
}

/// A `.time` cell as polars prints it (chrono's display, also polars' JSON form):
/// `HH:MM:SS`, then the fraction when nonzero in groups of three digits, as few as hold
/// it (`00:00:00.120`, `12:00:00.000005`). Null outside `[0, us_per_day)`.
/// `parseTimeOfDay` reads every result back.
pub fn formatTimeOfDay(buf: *[max_time_len]u8, us: i64) ?[]const u8 {
    if (!isTimeOfDay(us)) return null;
    const per = timestamp_units_per_second;
    const secs = @divTrunc(us, per);
    const frac: u64 = @intCast(@mod(us, per));
    var w: std.Io.Writer = .fixed(buf);
    w.print("{d:0>2}:{d:0>2}:{d:0>2}", .{ @as(u64, @intCast(@divTrunc(secs, 3600))), @as(u64, @intCast(@mod(@divTrunc(secs, 60), 60))), @as(u64, @intCast(@mod(secs, 60))) }) catch unreachable;
    if (frac != 0) {
        if (frac % 1000 == 0) w.print(".{d:0>3}", .{frac / 1000}) catch unreachable else w.print(".{d:0>6}", .{frac}) catch unreachable;
    }
    return w.buffered();
}

// ── durations (`.duration` cells: `Value.int` microseconds) ────────────────

/// Longest string `formatIsoDuration` or `formatDuration` can produce, with slack:
/// `-PT9223372036854.775808S`, `-106751991d -4h -0m -54s -775ms -808µs`.
pub const max_duration_len = 64;

/// Parse a duration into microseconds (the `.duration` cell unit), or null. Two forms,
/// and nothing else:
///
///   ISO 8601: `[-]P[nW][nD][T[nH][nM][n[.F]S]]` — every unit fixed (no years or
///   months, which have no fixed length), at least one, the fraction on the seconds
///   only, 1–9 digits with those past the sixth truncated. `P0D` and `PT90S` (what
///   `formatIsoDuration` writes, as polars' JSON does) read back.
///   pandas: `[-]N day[s][,] HH:MM:SS[.F]` or `[-]HH:MM:SS[.F]` — the text `to_csv`
///   writes for a timedelta; `-1 days +23:58:30` (pandas' own negative form) too.
///
/// Null past `i64` microseconds (about ±292 000 years).
pub fn parseDurationCell(s: []const u8) ?i64 {
    if (s.len == 0) return null;
    var i: usize = 0;
    var neg = false;
    if (s[0] == '-' or s[0] == '+') {
        neg = s[0] == '-';
        i = 1;
    }
    if (i < s.len and (s[i] == 'P' or s[i] == 'p')) {
        // In i128, so that `-PT9223372036854.775808S` (minInt) reads back.
        const v = parseIsoDurationBody(s[i + 1 ..]) orelse return null;
        return std.math.cast(i64, if (neg) -v else v);
    }
    return parsePandasDuration(s[i..], neg);
}

/// Digits at `s[i.*..]` as an unsigned number, advancing `i`; null with none or past i64.
fn digitsRun(s: []const u8, i: *usize) ?i64 {
    const start = i.*;
    var v: i64 = 0;
    while (i.* < s.len and s[i.*] >= '0' and s[i.*] <= '9') : (i.* += 1) {
        v = std.math.mul(i64, v, 10) catch return null;
        v = std.math.add(i64, v, s[i.*] - '0') catch return null;
    }
    return if (i.* == start) null else v;
}

/// A fraction's digits at `s[i.*..]` as microseconds (1–9 digits, past the sixth truncated).
fn fractionUs(s: []const u8, i: *usize) ?i64 {
    var n: usize = 0;
    var us: i64 = 0;
    while (i.* < s.len and s[i.*] >= '0' and s[i.*] <= '9') : (i.* += 1) {
        if (n == 9) return null;
        if (n < 6) us = us * 10 + (s[i.*] - '0');
        n += 1;
    }
    if (n == 0) return null;
    while (n < 6) : (n += 1) us *= 10;
    return us;
}

fn addScaled(total: i64, n: i64, unit: i64) ?i64 {
    const part = std.math.mul(i64, n, unit) catch return null;
    return std.math.add(i64, total, part) catch null;
}

/// The magnitude, in i128: each part is at most i64 times a week of microseconds, five
/// parts at most, so the sum cannot overflow; the caller checks it fits i64.
fn parseIsoDurationBody(s: []const u8) ?i128 {
    const sec = timestamp_units_per_second;
    var i: usize = 0;
    var total: i128 = 0;
    var any = false;
    var in_time = false;
    // Units must come in order, each at most once: rank of the last one read.
    var last: u8 = 0;
    while (i < s.len) {
        if (s[i] == 'T' or s[i] == 't') {
            if (in_time) return null;
            in_time = true;
            i += 1;
            if (i == s.len) return null; // `PT` with nothing after it
            continue;
        }
        const n = digitsRun(s, &i) orelse return null;
        var frac: i64 = 0;
        var has_frac = false;
        if (i < s.len and (s[i] == '.' or s[i] == ',')) {
            i += 1;
            frac = fractionUs(s, &i) orelse return null;
            has_frac = true;
        }
        if (i == s.len) return null;
        const u = std.ascii.toUpper(s[i]);
        i += 1;
        const rank: u8, const unit: i128 = if (!in_time) switch (u) {
            'W' => .{ 1, 7 * 86_400 * sec },
            'D' => .{ 2, 86_400 * sec },
            else => return null,
        } else switch (u) {
            'H' => .{ 3, 3600 * sec },
            'M' => .{ 4, 60 * sec },
            'S' => .{ 5, sec },
            else => return null,
        };
        if (rank <= last) return null;
        if (has_frac and u != 'S') return null;
        last = rank;
        total += @as(i128, n) * unit + frac;
        any = true;
    }
    return if (any) total else null;
}

/// `neg`: the text began with `-`. With a day count the sign is the days' alone
/// (`-1 days +23:58:30` is -90 s), without one it is the clock's.
fn parsePandasDuration(s: []const u8, neg: bool) ?i64 {
    const sec = timestamp_units_per_second;
    var i: usize = 0;
    var days: i64 = 0;
    // `N day[s]` first, if the text has it.
    if (std.mem.indexOf(u8, s, "day") != null) {
        days = digitsRun(s, &i) orelse return null;
        if (i < s.len and s[i] == ' ') i += 1;
        if (!std.mem.startsWith(u8, s[i..], "day")) return null;
        i += 3;
        if (i < s.len and s[i] == 's') i += 1;
        if (i < s.len and s[i] == ',') i += 1;
        if (neg) days = -days;
        if (i == s.len) return std.math.mul(i64, days, 86_400 * sec) catch null;
        if (s[i] != ' ') return null;
        i += 1;
    }
    // pandas writes a negative timedelta as `-1 days +23:58:30`: the clock part signed.
    const has_days = std.mem.indexOf(u8, s, "day") != null;
    var clock_neg = neg and !has_days;
    if (has_days and i < s.len and (s[i] == '+' or s[i] == '-')) {
        clock_neg = s[i] == '-';
        i += 1;
    }
    const hh = digitsRun(s, &i) orelse return null;
    if (i >= s.len or s[i] != ':') return null;
    i += 1;
    const mm = digitsAt(s, i, 2) orelse return null;
    i += 2;
    if (i >= s.len or s[i] != ':') return null;
    i += 1;
    const ss = digitsAt(s, i, 2) orelse return null;
    i += 2;
    if (mm > 59 or ss > 59) return null;
    var frac: i64 = 0;
    if (i < s.len and s[i] == '.') {
        i += 1;
        frac = fractionUs(s, &i) orelse return null;
    }
    if (i != s.len) return null;
    var clock = addScaled(0, hh, 3600 * sec) orelse return null;
    clock = addScaled(clock, mm, 60 * sec) orelse return null;
    clock = addScaled(clock, ss, sec) orelse return null;
    clock = std.math.add(i64, clock, frac) catch return null;
    if (clock_neg) clock = -clock;
    const d = std.math.mul(i64, days, 86_400 * sec) catch return null;
    return std.math.add(i64, d, clock) catch null;
}

/// A `.duration` cell as ISO 8601 in seconds, polars' JSON form: `P0D` for zero,
/// else `[-]PT<s>[.F]S` with the fraction's trailing zeros trimmed (`PT93784.5S`,
/// `-PT90S`). Every `i64` is accepted; `parseDurationCell` reads every result back.
pub fn formatIsoDuration(buf: *[max_duration_len]u8, us: i64) []const u8 {
    if (us == 0) return "P0D";
    var w: std.Io.Writer = .fixed(buf);
    const mag: u64 = @abs(us);
    const per: u64 = @intCast(timestamp_units_per_second);
    if (us < 0) w.writeByte('-') catch unreachable;
    w.print("PT{d}", .{mag / per}) catch unreachable;
    writeFraction(&w, mag % per);
    w.writeByte('S') catch unreachable;
    return w.buffered();
}

fn writeFraction(w: *std.Io.Writer, frac: u64) void {
    if (frac == 0) return;
    var fb: [6]u8 = undefined;
    _ = std.mem.print(&fb, "{d:0>6}", .{frac}) catch unreachable;
    var end: usize = fb.len;
    while (fb[end - 1] == '0') end -= 1;
    w.writeByte('.') catch unreachable;
    w.writeAll(fb[0..end]) catch unreachable;
}

/// A `.duration` cell as polars prints it: the nonzero parts of days, hours, minutes,
/// seconds, milliseconds and microseconds, each with the sign (`1d 2h 3m 4s 500ms`,
/// `-1m -30s`), `0µs` for zero. For display (`format`, `toMarkdown`), not for reading
/// back: the text formats write `formatIsoDuration`.
pub fn formatDuration(buf: *[max_duration_len]u8, us: i64) []const u8 {
    if (us == 0) return "0µs";
    var w: std.Io.Writer = .fixed(buf);
    var mag: u64 = @abs(us);
    const sign: []const u8 = if (us < 0) "-" else "";
    const units = [_]struct { n: u64, s: []const u8 }{
        .{ .n = 86_400_000_000, .s = "d" }, .{ .n = 3_600_000_000, .s = "h" },
        .{ .n = 60_000_000, .s = "m" },     .{ .n = 1_000_000, .s = "s" },
        .{ .n = 1_000, .s = "ms" },
        .{ .n = 1, .s = "µs" },
    };
    var first = true;
    for (units) |u| {
        const q = mag / u.n;
        mag %= u.n;
        if (q == 0) continue;
        if (!first) w.writeByte(' ') catch unreachable;
        w.print("{s}{d}{s}", .{ sign, q, u.s }) catch unreachable;
        first = false;
    }
    return w.buffered();
}
