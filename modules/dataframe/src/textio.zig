// SPDX-License-Identifier: MIT
//! How one cell becomes text, shared by the CSV and JSON writers and the text rendering:
//! floats as Python's `repr` (pandas, and the shortest digits that read back exactly),
//! timestamps, exact decimals, and the number grammar the CSV reader infers types with.

const std = @import("std");
const value = @import("value.zig");

/// Longest `formatFloat` result: `-1.7976931348623157e+308`.
pub const max_float_len = 32;

/// `f` as Python's `repr(float)` does: the shortest digits that read back to the same
/// number, in plain decimal with at least one fractional digit (`1.0`, `0.1`, `100.0`),
/// or in scientific notation (`1e-05`, `1.5e+16`, two exponent digits at least) when the
/// decimal exponent is below -4 or above 15. The caller handles NaN and infinities.
pub fn formatFloat(buf: *[max_float_len]u8, f: f64) []const u8 {
    std.debug.assert(std.math.isFinite(f));
    var tmp: [48]u8 = undefined;
    // `{e}` prints the shortest round-trip digits: `1.2345e2`, `-5e-324`, `0e0`.
    const s = std.fmt.bufPrint(&tmp, "{e}", .{f}) catch unreachable;
    var digits: [24]u8 = undefined;
    var nd: usize = 0;
    var neg = false;
    var i: usize = 0;
    if (s[0] == '-') {
        neg = true;
        i = 1;
    }
    while (i < s.len and s[i] != 'e') : (i += 1) {
        if (s[i] == '.') continue;
        digits[nd] = s[i];
        nd += 1;
    }
    const exp = std.fmt.parseInt(i32, s[i + 1 ..], 10) catch unreachable;
    var w: std.Io.Writer = .fixed(buf);
    if (neg) w.writeByte('-') catch unreachable;
    if (exp < -4 or exp >= 16) {
        w.writeByte(digits[0]) catch unreachable;
        if (nd > 1) {
            w.writeByte('.') catch unreachable;
            w.writeAll(digits[1..nd]) catch unreachable;
        }
        w.print("e{c}{d:0>2}", .{ @as(u8, if (exp < 0) '-' else '+'), @abs(exp) }) catch unreachable;
        return w.buffered();
    }
    const pt: i32 = exp + 1; // digits before the decimal point
    if (pt <= 0) {
        w.writeAll("0.") catch unreachable;
        for (0..@as(usize, @intCast(-pt))) |_| w.writeByte('0') catch unreachable;
        w.writeAll(digits[0..nd]) catch unreachable;
    } else if (pt >= nd) {
        w.writeAll(digits[0..nd]) catch unreachable;
        for (0..@as(usize, @intCast(pt)) - nd) |_| w.writeByte('0') catch unreachable;
        w.writeAll(".0") catch unreachable;
    } else {
        const p: usize = @intCast(pt);
        w.writeAll(digits[0..p]) catch unreachable;
        w.writeByte('.') catch unreachable;
        w.writeAll(digits[p..nd]) catch unreachable;
    }
    return w.buffered();
}

/// `f` with exactly `decimals` fractional digits, correctly rounded from the exact binary
/// value (ties to even), as C's `%.Nf` and so pandas' `float_format="%.2f"` do: `2.675` to two
/// digits is `2.67`, because the double is just under 2.675. Exact up to 22 digits and
/// a magnitude below 2^127; past that the shortest digits are rounded instead.
pub fn formatFloatFixed(buf: []u8, f: f64, decimals: u8) []const u8 {
    if (std.math.isFinite(f) and decimals <= 22) {
        if (formatFixedExact(buf, f, decimals)) |s| return s;
    }
    return std.fmt.bufPrint(buf, "{d:.[1]}", .{ f, @as(usize, decimals) }) catch "";
}

fn formatFixedExact(buf: []u8, f: f64, d: u8) ?[]const u8 {
    const bits: u64 = @bitCast(f);
    const neg = (bits >> 63) != 0;
    const bexp: i32 = @intCast((bits >> 52) & 0x7ff);
    const mant: u64 = bits & ((1 << 52) - 1);
    const m: u128 = if (bexp == 0) mant else mant | (1 << 52);
    const e: i32 = if (bexp == 0) -1074 else bexp - 1075;
    var q: u128 = undefined;
    if (e >= 0) {
        if (e > 74) return null;
        const whole = m << @intCast(e);
        q = std.math.mul(u128, whole, std.math.pow(u128, 10, d)) catch return null;
    } else {
        const sh: i32 = -e;
        const num = m * std.math.pow(u128, 10, d); // < 2^53 * 2^74
        if (sh > 127) {
            q = 0;
        } else {
            const s: u7 = @intCast(sh);
            q = num >> s;
            const rem = num & ((@as(u128, 1) << s) - 1);
            const half = @as(u128, 1) << (s - 1);
            if (rem > half or (rem == half and (q & 1) == 1)) q += 1;
        }
    }
    var digits: [48]u8 = undefined;
    var nd: usize = 0;
    var t = q;
    while (t != 0) : (t /= 10) {
        digits[nd] = '0' + @as(u8, @intCast(t % 10));
        nd += 1;
    }
    while (nd < @as(usize, d) + 1) : (nd += 1) digits[nd] = '0'; // at least one integer digit
    var w: std.Io.Writer = .fixed(buf);
    if (neg) w.writeByte('-') catch return null;
    var k: usize = nd;
    while (k > 0) {
        k -= 1;
        w.writeByte(digits[k]) catch return null;
        if (k == d and d != 0) w.writeByte('.') catch return null;
    }
    return w.buffered();
}

test "formatFloatFixed rounds the exact value, ties to even" {
    var b: [400]u8 = undefined;
    const c = [_]struct { f: f64, d: u8, s: []const u8 }{
        .{ .f = 2.675, .d = 2, .s = "2.67" },
        .{ .f = 2.5, .d = 0, .s = "2" },
        .{ .f = 3.5, .d = 0, .s = "4" },
        .{ .f = 0.125, .d = 2, .s = "0.12" },
        .{ .f = 0.375, .d = 2, .s = "0.38" },
        .{ .f = 1.005, .d = 2, .s = "1.00" },
        .{ .f = -0.0, .d = 1, .s = "-0.0" },
        .{ .f = 5e-324, .d = 3, .s = "0.000" },
        .{ .f = 123456.789, .d = 1, .s = "123456.8" },
        .{ .f = -3.14159, .d = 2, .s = "-3.14" },
        .{ .f = 1e22, .d = 1, .s = "10000000000000000000000.0" },
        .{ .f = 100.0, .d = 2, .s = "100.00" },
        .{ .f = 0.5, .d = 0, .s = "0" },
        .{ .f = 1.5, .d = 0, .s = "2" },
        .{ .f = 0.1, .d = 20, .s = "0.10000000000000000555" },
    };
    for (c) |x| try std.testing.expectEqualStrings(x.s, formatFloatFixed(&b, x.f, x.d));
}

pub const max_decimal_len = 64;

/// A `.decimal` cell as an exact number: the integer part, then the fraction with its
/// trailing zeros trimmed; a whole number has no point.
pub fn formatDecimal(buf: *[max_decimal_len]u8, raw: i128) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    if (raw < 0) w.writeByte('-') catch unreachable;
    const mag: u128 = @abs(raw);
    const scale: u128 = @intCast(value.decimal_scale);
    w.print("{d}", .{mag / scale}) catch unreachable;
    const frac = mag % scale;
    if (frac != 0) {
        var digits: [12]u8 = undefined;
        var t = frac;
        var k: usize = digits.len;
        while (k > 0) {
            k -= 1;
            digits[k] = '0' + @as(u8, @intCast(t % 10));
            t /= 10;
        }
        var end: usize = digits.len;
        while (end > 0 and digits[end - 1] == '0') end -= 1;
        w.writeByte('.') catch unreachable;
        w.writeAll(digits[0..end]) catch unreachable;
    }
    return w.buffered();
}

pub const max_stamp_len = value.max_iso_timestamp_len + 8;

/// A `.timestamp` cell as `YYYY-MM-DD HH:MM:SS` followed by a fraction of `digits`
/// digits when `digits` is 3 or 6 (pandas `to_csv` gives every cell of a column the same).
pub fn formatStampSpace(buf: *[max_stamp_len]u8, us: i64, digits: u8) []const u8 {
    var tmp: [value.max_iso_timestamp_len]u8 = undefined;
    const iso = value.formatIsoTimestamp(&tmp, us);
    const t = std.mem.findScalar(u8, iso, 'T').?;
    const dot = std.mem.findScalar(u8, iso, '.') orelse iso.len - 1; // the trailing Z
    @memcpy(buf[0..dot], iso[0..dot]);
    buf[t] = ' ';
    var n: usize = dot;
    if (digits != 0) {
        const frac: u64 = @intCast(@mod(us, value.timestamp_units_per_second));
        var w: std.Io.Writer = .fixed(buf[n..]);
        if (digits == 3) w.print(".{d:0>3}", .{frac / 1000}) catch unreachable else w.print(".{d:0>6}", .{frac}) catch unreachable;
        n += w.buffered().len;
    }
    return buf[0..n];
}

/// The fraction digits pandas writes for a column of timestamps: none when no cell has a
/// fraction, 3 when every fraction is whole milliseconds, else 6.
pub fn fractionDigits(us: i64, so_far: u8) u8 {
    const frac = @mod(us, value.timestamp_units_per_second);
    if (frac == 0) return so_far;
    return if (@mod(frac, 1000) == 0) @max(so_far, 3) else 6;
}

/// True when some micro-of-second part of a `.timestamp` cell is not zero.
pub fn hasFraction(us: i64) bool {
    return @mod(us, value.timestamp_units_per_second) != 0;
}

// ── the number grammar of the CSV reader ────────────────────────────────────

/// Token with ASCII blanks (space, tab) cut off both ends: pandas reads ` 4` as 4.
pub fn trimBlank(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t");
}

/// `[+-]?[0-9]+`
pub fn isIntGrammar(t: []const u8) bool {
    var i: usize = 0;
    if (t.len > 0 and (t[0] == '+' or t[0] == '-')) i = 1;
    if (i == t.len) return false;
    for (t[i..]) |c| if (c < '0' or c > '9') return false;
    return true;
}

/// The decimal float grammar: `[+-]?(digits[.digits*]|.digits)([eE][+-]?digits)?`, or
/// `inf`, `infinity`, `nan` in any case with an optional sign (pandas; polars reads
/// `inf` and `NaN` only).
pub fn isFloatGrammar(t: []const u8) bool {
    var i: usize = 0;
    if (t.len > 0 and (t[0] == '+' or t[0] == '-')) i = 1;
    const rest = t[i..];
    if (rest.len == 0) return false;
    if (std.ascii.eqlIgnoreCase(rest, "inf") or std.ascii.eqlIgnoreCase(rest, "infinity") or std.ascii.eqlIgnoreCase(rest, "nan")) return true;
    var int_digits: usize = 0;
    while (i < t.len and t[i] >= '0' and t[i] <= '9') : (i += 1) int_digits += 1;
    var frac_digits: usize = 0;
    if (i < t.len and t[i] == '.') {
        i += 1;
        while (i < t.len and t[i] >= '0' and t[i] <= '9') : (i += 1) frac_digits += 1;
    }
    if (int_digits + frac_digits == 0) return false;
    if (i < t.len and (t[i] == 'e' or t[i] == 'E')) {
        i += 1;
        if (i < t.len and (t[i] == '+' or t[i] == '-')) i += 1;
        var exp_digits: usize = 0;
        while (i < t.len and t[i] >= '0' and t[i] <= '9') : (i += 1) exp_digits += 1;
        if (exp_digits == 0) return false;
    }
    return i == t.len;
}

/// Parse a token `isFloatGrammar` accepted. `std.fmt.parseFloat` takes `5.` and `.5`; the
/// sign of `inf`/`nan` is applied here so `+inf` and `-nan` need no special case there.
pub fn parseFloatToken(t: []const u8) ?f64 {
    return std.fmt.parseFloat(f64, t) catch null;
}

/// A `.decimal` raw value from `[+-]?digits[.digits]` with at most 12 fractional digits
/// (`decimal_scale`); null for anything else or an overflow of i128.
pub fn parseDecimalToken(t: []const u8) ?i128 {
    var i: usize = 0;
    var neg = false;
    if (t.len > 0 and (t[0] == '+' or t[0] == '-')) {
        neg = t[0] == '-';
        i = 1;
    }
    var mag: i128 = 0;
    var int_digits: usize = 0;
    while (i < t.len and t[i] >= '0' and t[i] <= '9') : (i += 1) {
        mag = std.math.mul(i128, mag, 10) catch return null;
        mag = std.math.add(i128, mag, t[i] - '0') catch return null;
        int_digits += 1;
    }
    var frac_digits: usize = 0;
    if (i < t.len and t[i] == '.') {
        i += 1;
        while (i < t.len and t[i] >= '0' and t[i] <= '9') : (i += 1) {
            // Past the scale only zeros are exact (`1.0000000000000`); a digit would be lost.
            if (frac_digits == 12) {
                if (t[i] != '0') return null;
                continue;
            }
            mag = std.math.mul(i128, mag, 10) catch return null;
            mag = std.math.add(i128, mag, t[i] - '0') catch return null;
            frac_digits += 1;
        }
    }
    if (i != t.len or int_digits + frac_digits == 0) return null;
    while (frac_digits < 12) : (frac_digits += 1) mag = std.math.mul(i128, mag, 10) catch return null;
    return if (neg) -mag else mag;
}

test "formatFloat is Python's repr" {
    const cases = [_]struct { f: f64, s: []const u8 }{
        .{ .f = 1.0, .s = "1.0" },
        .{ .f = 0.1, .s = "0.1" },
        .{ .f = -0.0, .s = "-0.0" },
        .{ .f = 0.0, .s = "0.0" },
        .{ .f = 100.0, .s = "100.0" },
        .{ .f = 1e-4, .s = "0.0001" },
        .{ .f = 1e-5, .s = "1e-05" },
        .{ .f = 2.5e-5, .s = "2.5e-05" },
        .{ .f = 1.234e-300, .s = "1.234e-300" },
        .{ .f = 1e15, .s = "1000000000000000.0" },
        .{ .f = 9.99e15, .s = "9990000000000000.0" },
        .{ .f = 1e16, .s = "1e+16" },
        .{ .f = 1.5e16, .s = "1.5e+16" },
        .{ .f = 123456789012345678.0, .s = "1.2345678901234568e+17" },
        .{ .f = 123456789.12345679, .s = "123456789.12345679" },
        .{ .f = @as(f64, 0.1) + @as(f64, 0.2), .s = "0.30000000000000004" },
        .{ .f = 1.7976931348623157e308, .s = "1.7976931348623157e+308" },
        .{ .f = 5e-324, .s = "5e-324" },
        .{ .f = -1234567.0, .s = "-1234567.0" },
    };
    var buf: [max_float_len]u8 = undefined;
    for (cases) |c| try std.testing.expectEqualStrings(c.s, formatFloat(&buf, c.f));
}

test "the number grammar" {
    try std.testing.expect(isIntGrammar("-12") and isIntGrammar("+0") and !isIntGrammar("") and !isIntGrammar("-") and !isIntGrammar("1.0"));
    for ([_][]const u8{ "1.5", ".5", "5.", "1e5", "1E-5", "+1e+5", "inf", "-Infinity", "NaN", "-nan", "007" }) |s|
        try std.testing.expect(isFloatGrammar(s));
    for ([_][]const u8{ "", ".", "-", "e5", "1e", "1e+", "1.2.3", "0x10", "1_000", "1d", "infx", " 1" }) |s|
        try std.testing.expect(!isFloatGrammar(s));
    try std.testing.expectEqual(@as(?i128, 1_500_000_000_000), parseDecimalToken("1.5"));
    try std.testing.expectEqual(@as(?i128, null), parseDecimalToken("1.1234567890123"));
    try std.testing.expectEqual(@as(?i128, -250_000_000_000), parseDecimalToken("-.25"));
}

test "formatDecimal and the timestamp spellings" {
    var db: [max_decimal_len]u8 = undefined;
    try std.testing.expectEqualStrings("1.5", formatDecimal(&db, 1_500_000_000_000));
    try std.testing.expectEqualStrings("-0.000000000001", formatDecimal(&db, -1));
    try std.testing.expectEqualStrings("7", formatDecimal(&db, 7_000_000_000_000));
    var tb: [max_stamp_len]u8 = undefined;
    const us: i64 = 1609556645123456; // 2021-01-02 03:04:05.123456
    try std.testing.expectEqualStrings("2021-01-02 03:04:05.123456", formatStampSpace(&tb, us, 6));
    try std.testing.expectEqualStrings("2021-01-02 03:04:05.000000", formatStampSpace(&tb, 1609556645000000, 6));
    try std.testing.expectEqualStrings("2021-01-02 03:04:05", formatStampSpace(&tb, 1609556645000000, 0));
    try std.testing.expectEqualStrings("2021-01-02 03:04:05.120", formatStampSpace(&tb, 1609556645120000, 3));
    try std.testing.expectEqual(@as(u8, 3), fractionDigits(1609556645120000, 0));
    try std.testing.expectEqual(@as(u8, 6), fractionDigits(1609556645120001, 3));
    try std.testing.expectEqual(@as(u8, 6), fractionDigits(1609556645000000, 6));
}
