// SPDX-License-Identifier: MIT
//! The cell model: `ColumnType`, `Column`, `Value`, and the ISO date and timestamp
//! helpers a cast needs. Taken from `dataset` (the same authors, MIT), unchanged in
//! meaning so that `dataset`'s row verbs stay a differential oracle for this module
//! until they retire: equal cells order, compare and cast the same way in both.

const std = @import("std");

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
};

pub const Column = struct {
    name: []const u8,
    type: ColumnType,
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
    /// ReleaseSafe would panic and ReleaseFast would return garbage on a NaN cell.
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
