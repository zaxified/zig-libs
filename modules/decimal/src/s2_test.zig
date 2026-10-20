// SPDX-License-Identifier: MIT
//! Tests for the S2 operations (`round_05up`, `Decimal.rem/roundToMultiple/pow/
//! sqrt/...`, `BigDecimal.roundToPrecision/divPrec/divideInteger/remainderNear/
//! compareTotal/maxMag/minMag/adjusted/toSci/toEng/toStringFixed`).
//!
//! The bulk is a replay of `testdata/s2_oracle.vec`, frozen from Python's
//! `decimal` by `tools/py_oracle.py` (no Python at test time); the rest are
//! hand-written spot checks quoting the Python expression or GDA rule.
const std = @import("std");
const root = @import("root.zig");
const Decimal = root.Decimal;
const BigDecimal = root.BigDecimal;
const RoundingMode = root.RoundingMode;

const testing = std.testing;
const talloc = testing.allocator;

fn d(s: []const u8) Decimal {
    return Decimal.parse(s) catch unreachable;
}

fn mode_of(name: []const u8) RoundingMode {
    return std.meta.stringToEnum(RoundingMode, name) orelse std.debug.panic("unknown mode {s}", .{name});
}

/// `want` is `ERR:<name>` or a plain decimal; `got` an error union of `Decimal`.
fn expectDec(want: []const u8, got: anytype) !void {
    if (std.mem.startsWith(u8, want, "ERR:")) {
        if (got) |_| return error.ExpectedError else |err| try testing.expectEqualStrings(want[4..], @errorName(err));
        return;
    }
    const v = got catch |err| {
        std.debug.print("unexpected error {s}\n", .{@errorName(err)});
        return err;
    };
    try testing.expectEqual(d(want).raw, v.raw);
}

fn expectBig(want: []const u8, got_in: anytype) !void {
    if (std.mem.startsWith(u8, want, "ERR:")) {
        if (got_in) |v| {
            var vv = v;
            vv.deinit();
            return error.ExpectedError;
        } else |err| try testing.expectEqualStrings(want[4..], @errorName(err));
        return;
    }
    var v = got_in catch |err| {
        std.debug.print("unexpected error {s}\n", .{@errorName(err)});
        return err;
    };
    defer v.deinit();
    const s = try v.toSci(talloc);
    defer talloc.free(s);
    try testing.expectEqualStrings(want, s);
}

fn expectRounded(f: []const []const u8, got_in: anytype) !void {
    // f = [value, inexact, rounded]
    if (std.mem.startsWith(u8, f[0], "ERR:")) {
        if (got_in) |v| {
            var vv = v;
            vv.deinit();
            return error.ExpectedError;
        } else |err| try testing.expectEqualStrings(f[0][4..], @errorName(err));
        return;
    }
    var v = got_in catch |err| {
        std.debug.print("unexpected error {s}\n", .{@errorName(err)});
        return err;
    };
    defer v.deinit();
    const s = try v.value.toSci(talloc);
    defer talloc.free(s);
    try testing.expectEqualStrings(f[0], s);
    try testing.expectEqual(f[1][0] == '1', v.inexact);
    try testing.expectEqual(f[2][0] == '1', v.rounded);
}

fn big(s: []const u8) !BigDecimal {
    return BigDecimal.parse(talloc, s);
}

fn runLine(op: []const u8, f: []const []const u8) !void {
    // ---- Decimal ----
    if (std.mem.eql(u8, op, "d.rem")) return expectDec(f[2], d(f[0]).rem(d(f[1])));
    if (std.mem.eql(u8, op, "d.remnear")) return expectDec(f[2], d(f[0]).remainderNear(d(f[1])));
    if (std.mem.eql(u8, op, "d.divint")) {
        if (std.mem.startsWith(u8, f[2], "ERR:")) {
            if (d(f[0]).divideInteger(d(f[1]))) |_| return error.ExpectedError else |err| try testing.expectEqualStrings(f[2][4..], @errorName(err));
        } else {
            try testing.expectEqual(try std.fmt.parseInt(i128, f[2], 10), try d(f[0]).divideInteger(d(f[1])));
        }
        return;
    }
    if (std.mem.eql(u8, op, "d.maxmag")) return testing.expectEqual(d(f[2]).raw, d(f[0]).maxMag(d(f[1])).raw);
    if (std.mem.eql(u8, op, "d.minmag")) return testing.expectEqual(d(f[2]).raw, d(f[0]).minMag(d(f[1])).raw);
    if (std.mem.eql(u8, op, "d.max")) return testing.expectEqual(d(f[2]).raw, d(f[0]).max(d(f[1])).raw);
    if (std.mem.eql(u8, op, "d.min")) return testing.expectEqual(d(f[2]).raw, d(f[0]).min(d(f[1])).raw);
    if (std.mem.eql(u8, op, "d.signum")) return testing.expectEqual(try std.fmt.parseInt(i8, f[1], 10), d(f[0]).signum());
    if (std.mem.eql(u8, op, "d.mround")) return expectDec(f[3], d(f[1]).roundToMultiple(d(f[2]), mode_of(f[0])));
    if (std.mem.eql(u8, op, "d.pow")) return expectDec(f[2], d(f[0]).pow(talloc, try std.fmt.parseInt(i32, f[1], 10)));
    if (std.mem.eql(u8, op, "d.sqrt")) return expectDec(f[1], d(f[0]).sqrt());
    if (std.mem.eql(u8, op, "d.rescale"))
        return expectDec(f[3], d(f[1]).rescale(try std.fmt.parseInt(i32, f[2], 10), mode_of(f[0])));
    if (std.mem.eql(u8, op, "d.divround"))
        return expectDec(f[4], d(f[1]).divRound(d(f[2]), try std.fmt.parseInt(i32, f[3], 10), mode_of(f[0])));
    if (std.mem.eql(u8, op, "d.fixed")) {
        var buf: [64]u8 = undefined;
        const places = try std.fmt.parseInt(u32, f[2], 10);
        try testing.expect(buf.len >= Decimal.fixedBufLen(places));
        return testing.expectEqualStrings(f[3], try d(f[1]).toStringFixed(&buf, places, mode_of(f[0])));
    }
    if (std.mem.eql(u8, op, "d.fromfloat") or std.mem.eql(u8, op, "d.fromfloatshortest")) {
        const x = try std.fmt.parseFloat(f64, f[1]);
        const places = try std.fmt.parseInt(u32, f[2], 10);
        return expectDec(f[3], if (std.mem.eql(u8, op, "d.fromfloat"))
            Decimal.fromFloat(x, places, mode_of(f[0]))
        else
            Decimal.fromFloatShortest(x, places, mode_of(f[0])));
    }
    // ---- BigDecimal ----
    if (std.mem.eql(u8, op, "b.quant")) {
        var x = try big(f[1]);
        defer x.deinit();
        return expectBig(f[3], BigDecimal.rescale(talloc, x, try std.fmt.parseInt(i32, f[2], 10), mode_of(f[0])));
    }
    if (std.mem.eql(u8, op, "b.div")) {
        var a = try big(f[1]);
        defer a.deinit();
        var b = try big(f[2]);
        defer b.deinit();
        return expectBig(f[4], BigDecimal.div(talloc, a, b, try std.fmt.parseInt(i32, f[3], 10), mode_of(f[0])));
    }
    if (std.mem.eql(u8, op, "b.roundprec")) {
        var x = try big(f[1]);
        defer x.deinit();
        return expectRounded(f[3..], BigDecimal.roundToPrecision(talloc, x, try std.fmt.parseInt(u32, f[2], 10), mode_of(f[0])));
    }
    if (std.mem.eql(u8, op, "b.divprec")) {
        var a = try big(f[1]);
        defer a.deinit();
        var b = try big(f[2]);
        defer b.deinit();
        return expectRounded(f[4..], BigDecimal.divPrec(talloc, a, b, try std.fmt.parseInt(u32, f[3], 10), mode_of(f[0])));
    }
    if (std.mem.eql(u8, op, "b.divint") or std.mem.eql(u8, op, "b.remnear") or
        std.mem.eql(u8, op, "b.maxmag") or std.mem.eql(u8, op, "b.minmag") or std.mem.eql(u8, op, "b.cmptotal"))
    {
        var a = try big(f[0]);
        defer a.deinit();
        var b = try big(f[1]);
        defer b.deinit();
        if (std.mem.eql(u8, op, "b.divint")) return expectBig(f[2], BigDecimal.divideInteger(talloc, a, b));
        if (std.mem.eql(u8, op, "b.remnear")) return expectBig(f[2], BigDecimal.remainderNear(talloc, a, b));
        if (std.mem.eql(u8, op, "b.maxmag")) return expectBig(f[2], BigDecimal.maxMag(talloc, a, b));
        if (std.mem.eql(u8, op, "b.minmag")) return expectBig(f[2], BigDecimal.minMag(talloc, a, b));
        const o = try BigDecimal.compareTotal(talloc, a, b);
        const want: i8 = try std.fmt.parseInt(i8, f[2], 10);
        return testing.expectEqual(want, @as(i8, switch (o) {
            .lt => -1,
            .eq => 0,
            .gt => 1,
        }));
    }
    if (std.mem.eql(u8, op, "b.adjusted")) {
        var x = try big(f[0]);
        defer x.deinit();
        return testing.expectEqual(try std.fmt.parseInt(i64, f[1], 10), try x.adjusted(talloc));
    }
    if (std.mem.eql(u8, op, "b.sci") or std.mem.eql(u8, op, "b.eng")) {
        var x = try big(f[0]);
        defer x.deinit();
        const s = if (op[2] == 's') try x.toSci(talloc) else try x.toEng(talloc);
        defer talloc.free(s);
        return testing.expectEqualStrings(f[1], s);
    }
    if (std.mem.eql(u8, op, "b.fixed")) {
        var x = try big(f[1]);
        defer x.deinit();
        const s = try x.toStringFixed(talloc, try std.fmt.parseInt(i32, f[2], 10), mode_of(f[0]));
        defer talloc.free(s);
        return testing.expectEqualStrings(f[3], s);
    }
    if (std.mem.eql(u8, op, "b.exp") or std.mem.eql(u8, op, "b.ln") or std.mem.eql(u8, op, "b.log10")) {
        // mode|x|prec|value|inexact|rounded
        var x = try big(f[1]);
        defer x.deinit();
        const prec = try std.fmt.parseInt(u32, f[2], 10);
        const m = mode_of(f[0]);
        if (std.mem.eql(u8, op, "b.exp")) return expectRounded(f[3..], BigDecimal.exp(talloc, x, prec, m));
        if (std.mem.eql(u8, op, "b.ln")) return expectRounded(f[3..], BigDecimal.ln(talloc, x, prec, m));
        return expectRounded(f[3..], BigDecimal.log10(talloc, x, prec, m));
    }
    if (std.mem.eql(u8, op, "b.power")) {
        // mode|base|exponent|prec|value|inexact|rounded
        var a = try big(f[1]);
        defer a.deinit();
        var b = try big(f[2]);
        defer b.deinit();
        return expectRounded(f[4..], BigDecimal.power(talloc, a, b, try std.fmt.parseInt(u32, f[3], 10), mode_of(f[0])));
    }
    return error.UnknownOp;
}

test "oracle: S2 operations replay Python decimal (frozen s2_oracle.vec)" {
    var it = std.mem.splitScalar(u8, @embedFile("testdata/s2_oracle.vec"), '\n');
    var n: usize = 0;
    var line_no: usize = 0;
    var failed: usize = 0;
    while (it.next()) |raw| {
        line_no += 1;
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        var fields: [8][]const u8 = undefined;
        var parts = std.mem.splitScalar(u8, line, '|');
        const op = parts.next().?;
        var k: usize = 0;
        while (parts.next()) |p| : (k += 1) fields[k] = p;
        runLine(op, fields[0..k]) catch |err| {
            // Report up to 40 failing lines (one run shows the whole picture), then fail below.
            failed += 1;
            if (failed <= 40) std.debug.print("s2_oracle.vec line {d}: {s} -> {s}\n", .{ line_no, line, @errorName(err) });
        };
        n += 1;
    }
    try testing.expectEqual(@as(usize, 0), failed);
    try testing.expectEqual(@as(usize, 19843), n); // the whole file, not a prefix
}

// ---------------------------------------------------------------------------
// Hand-written spot checks. Each quotes the Python expression or GDA rule it
// is derived from; the replay above carries the volume.
// ---------------------------------------------------------------------------

fn expectD(want: []const u8, got: Decimal) !void {
    var buf: [Decimal.str_buf_len]u8 = undefined;
    try testing.expectEqualStrings(want, got.toString(&buf));
}

fn sci(s: []const u8) ![]u8 {
    var x = try big(s);
    defer x.deinit();
    return x.toSci(talloc);
}

fn expectSci(want: []const u8, s: []const u8) !void {
    const got = try sci(s);
    defer talloc.free(got);
    try testing.expectEqualStrings(want, got);
}

fn expectEng(want: []const u8, s: []const u8) !void {
    var x = try big(s);
    defer x.deinit();
    const got = try x.toEng(talloc);
    defer talloc.free(got);
    try testing.expectEqualStrings(want, got);
}

test "round_05up: GDA definition (Python ROUND_05UP)" {
    // Decimal('1.005').quantize(Decimal('0.01'), ROUND_05UP) -> 1.01   (last kept digit 0)
    // Decimal('1.051') -> 1.06 (5), Decimal('1.011') -> 1.01 (1, toward zero), Decimal('-1.001') -> -1.01
    try expectD("1.01", try d("1.005").rescale(2, .round_05up));
    try expectD("1.06", try d("1.051").rescale(2, .round_05up));
    try expectD("1.01", try d("1.011").rescale(2, .round_05up));
    try expectD("-1.01", try d("-1.001").rescale(2, .round_05up));
    // An exact result is never touched: Decimal('1.50').quantize(Decimal('0.1')) -> 1.5
    try expectD("1.5", try d("1.50").rescale(1, .round_05up));
    // The kept quotient is 0 (digit 0): Decimal('0.001').quantize(Decimal(1), ROUND_05UP) -> 1
    try expectD("1", try d("0.001").rescale(0, .round_05up));
    try expectD("-1", try d("-0.001").rescale(0, .round_05up));
    // Below half an ulp via the bridge: Decimal('1E-13').quantize(Decimal('1E-12'), ROUND_05UP) -> 1E-12
    var tiny = try big("1e-13");
    defer tiny.deinit();
    try expectD("0.000000000001", try Decimal.fromBigDecimal(talloc, tiny, .round_05up));
    // divRound: 10/3 at 0 places: kept 3 (not 0/5) -> 3; 50/3 = 16.67 at 0 places: kept 16 -> 16; 5/3 -> kept 1.
    try expectD("3", try d("10").divRound(d("3"), 0, .round_05up));
    try expectD("16", try d("50").divRound(d("3"), 0, .round_05up));
    try expectD("30", try d("100").divRound(d("3"), -1, .round_05up)); // 3.33 tens: kept 3 -> stays
    try expectD("1", try d("5").divRound(d("10"), 0, .round_05up)); // 0.5: kept 0 -> away
}

test "round_05up: rounding to n+1 digits first makes a later n-digit rounding single (the GDA use)" {
    // Python: Decimal('1.2349').quantize(Decimal('0.001'), ROUND_05UP) = 1.234 (4 -> stay), then
    // .quantize(Decimal('0.01'), ROUND_HALF_UP) = 1.23; direct half_up of 1.2349 is 1.23 as well.
    var x = try big("1.2350001");
    defer x.deinit();
    var a = try BigDecimal.rescale(talloc, x, -3, .round_05up); // kept 1.235 -> ...5 -> away: 1.236
    defer a.deinit();
    try expectBig("1.236", a.clone());
}

test "BigDecimal.sqrt: an exact root is exact in every mode (was: up/ceiling bumped it)" {
    // Python: Context(prec=2).sqrt(Decimal('100.00')) -> 10  (square-root is exact here)
    var x = try big("100.00");
    defer x.deinit();
    const modes = [_]RoundingMode{ .up, .ceiling, .round_05up, .half_even, .down, .floor, .half_up, .half_down };
    for (modes) |m| {
        try expectBig("10", BigDecimal.sqrt(talloc, x, 2, m));
    }
    // round_05up on an inexact root, by definition: sqrt(26) = 5.0990195...; at 2 digits the kept
    // digits are 5.0 (last digit 0) -> away -> 5.1; sqrt(2) at 3 digits kept 1.41 (1) -> stays 1.41.
    var y = try big("26");
    defer y.deinit();
    try expectBig("5.1", BigDecimal.sqrt(talloc, y, 2, .round_05up));
    var z = try big("2");
    defer z.deinit();
    try expectBig("1.41", BigDecimal.sqrt(talloc, z, 3, .round_05up));
}

test "Decimal.rem / divideInteger / remainderNear: signs and the i128 corner" {
    // Python: Decimal(-7) % Decimal(3) -> -1 ; Decimal(7) % Decimal(-3) -> 1
    try expectD("-1", try d("-7").rem(d("3")));
    try expectD("1", try d("7").rem(d("-3")));
    try expectD("0.4", try d("2.4").rem(d("1")));
    // |min raw| cannot be negated in i128; the remainder by -1e-12 is still 0, not a trap.
    const min = Decimal{ .raw = std.math.minInt(i128) };
    try expectD("0", try min.rem(Decimal{ .raw = -1 }));
    try testing.expectError(error.DivisionByZero, d("1").rem(Decimal.zero));
    // Python: Decimal(-7) // Decimal(2) -> -3 ; Decimal(10).remainder_near(4) -> 2 ; Decimal(7).remainder_near(2) -> -1
    try testing.expectEqual(@as(i128, -3), try d("-7").divideInteger(d("2")));
    try expectD("2", try d("10").remainderNear(d("4")));
    try expectD("-1", try d("7").remainderNear(d("2")));
    try expectD("1", try d("-7").remainderNear(d("2")));
    // The quotient can leave i128 only when the divisor is below 1.
    try testing.expectError(error.Overflow, min.divideInteger(Decimal{ .raw = -1 }));
}

test "Decimal.roundToMultiple: bxp MROUND semantics, any mode" {
    // MROUND(0.075, 0.05) = 0.1 (halves away), MROUND(12.37, 0.05) = 12.35, the sign of m is ignored.
    try expectD("0.1", try d("0.075").roundToMultiple(d("0.05"), .half_up));
    try expectD("0.1", try d("0.075").roundToMultiple(d("-0.05"), .half_up));
    try expectD("0.1", try d("0.075").roundToMultiple(d("0.05"), .half_even)); // 1.5 steps: tie -> even 2
    try expectD("0", try d("0.025").roundToMultiple(d("0.05"), .half_even)); // 0.5 steps: tie -> even 0
    try expectD("12.35", try d("12.37").roundToMultiple(d("0.05"), .half_up));
    try expectD("-12.35", try d("-12.37").roundToMultiple(d("0.05"), .half_up));
    try expectD("12.4", try d("12.37").roundToMultiple(d("0.05"), .ceiling));
    try testing.expectError(error.DivisionByZero, d("1").roundToMultiple(Decimal.zero, .half_up));
}

test "Decimal.pow: exact, half_even, typed errors" {
    // Python: Decimal('1.1') ** 2 -> 1.21 ; Decimal(3) ** -1 at 12 places -> 0.333333333333
    try expectD("1.21", try d("1.1").pow(talloc, 2));
    try expectD("0.333333333333", try d("3").pow(talloc, -1));
    try expectD("0.5", try d("2").pow(talloc, -1));
    try expectD("-8", try d("-2").pow(talloc, 3));
    try expectD("1", try Decimal.zero.pow(talloc, 0)); // as BigDecimal.pow and Java; Python raises
    try expectD("0", try Decimal.zero.pow(talloc, 5));
    try testing.expectError(error.DivisionByZero, Decimal.zero.pow(talloc, -1));
    try expectD("100000000000000000000000000", try d("10").pow(talloc, 26));
    try testing.expectError(error.Overflow, d("10").pow(talloc, 27));
    try testing.expectError(error.Overflow, d("2").pow(talloc, 88));
    try expectD("0", try d("0.5").pow(talloc, 41)); // 4.5e-13 < half an ulp
    try expectD("0.000000000002", try d("0.5").pow(talloc, 39)); // 1.8e-12
    // 1 and -1 never allocate and never overflow at any exponent.
    try expectD("1", try d("1").pow(talloc, std.math.minInt(i32)));
    try expectD("-1", try d("-1").pow(talloc, std.math.maxInt(i32)));
    // Honest limit: an exact power with more than max_result_digits digits.
    try testing.expectError(error.ResultTooLarge, d("1.000000000001").pow(talloc, 100_000));
}

test "Decimal.sqrt: correctly rounded, agrees with BigDecimal.sqrt rounded once" {
    try expectD("1.414213562373", try d("2").sqrt());
    try expectD("2.5", try d("6.25").sqrt());
    try expectD("0", try Decimal.zero.sqrt());
    try expectD("0.000001", try d("0.000000000001").sqrt());
    try testing.expectError(error.NegativeOperand, d("-1").sqrt());
    const vals = [_][]const u8{ "2", "3", "5", "0.5", "1e20", "123456789.123456789", "0.000000000002", "170141183460469231731687303.715884105727" };
    for (vals) |t| {
        const x = d(t);
        var b = try x.toBigDecimal(talloc);
        defer b.deinit();
        var r = try BigDecimal.sqrt(talloc, b, 60, .half_even);
        defer r.deinit();
        const via = try Decimal.fromBigDecimal(talloc, r, .half_even);
        try testing.expectEqual(via.raw, (try x.sqrt()).raw);
    }
}

test "Decimal.toStringFixed: pads, rounds, never overflows, reports a short buffer" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("2.500", try d("2.5").toStringFixed(&buf, 3, .half_even));
    try testing.expectEqualStrings("7.00", try d("7").toStringFixed(&buf, 2, .half_even));
    try testing.expectEqualStrings("2", try d("2.5").toStringFixed(&buf, 0, .half_even));
    try testing.expectEqualStrings("3", try d("2.5").toStringFixed(&buf, 0, .half_up));
    try testing.expectEqualStrings("0.00", try d("-0.004").toStringFixed(&buf, 2, .half_even)); // no negative zero
    try testing.expectEqualStrings("-0.01", try d("-0.004").toStringFixed(&buf, 2, .up));
    try testing.expectEqualStrings("1.5000000000000", try d("1.5").toStringFixed(&buf, 13, .down));
    // Rounding up at the range's last integer yields text for a value that is not a Decimal.
    const max = Decimal{ .raw = std.math.maxInt(i128) };
    try testing.expectEqualStrings("170141183460469231731687304", try max.toStringFixed(&buf, 0, .ceiling));
    try testing.expectEqualStrings("-170141183460469231731687303.715884105728", try (Decimal{ .raw = std.math.minInt(i128) }).toStringFixed(&buf, 12, .down));
    var small: [3]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, d("12345").toStringFixed(&small, 0, .down));
    try testing.expectEqual(@as(usize, 41), Decimal.fixedBufLen(12));
}

test "Decimal.signum / min / max / minMag / maxMag" {
    try testing.expectEqual(@as(i8, -1), d("-0.000000000001").signum());
    try testing.expectEqual(@as(i8, 0), Decimal.zero.signum());
    try expectD("-3", d("-3").min(d("2")));
    try expectD("2", d("-3").max(d("2")));
    try expectD("2", d("-3").minMag(d("2")));
    try expectD("-3", d("-3").maxMag(d("2")));
    // Python: Decimal(-3).max_mag(Decimal(3)) -> 3 (equal magnitude falls back to max); min_mag -> -3
    try expectD("3", d("-3").maxMag(d("3")));
    try expectD("-3", d("-3").minMag(d("3")));
}

test "BigDecimal.roundToPrecision: flags and the carry" {
    // Context(prec=2).plus(Decimal('1.200')) -> 1.2, Rounded only; plus(Decimal('1.25')) half_even -> 1.2 Inexact+Rounded
    var a = try big("1.200");
    defer a.deinit();
    var r = try BigDecimal.roundToPrecision(talloc, a, 2, .half_even);
    defer r.deinit();
    try expectBig("1.2", r.value.clone());
    try testing.expect(r.rounded and !r.inexact);
    var a2 = try big("9.99");
    defer a2.deinit();
    var r2 = try BigDecimal.roundToPrecision(talloc, a2, 2, .half_up); // 10, not 10.0 (Python: 10)
    defer r2.deinit();
    try expectBig("10", r2.value.clone());
    try testing.expect(r2.rounded and r2.inexact);
    var r3 = try BigDecimal.roundToPrecision(talloc, a, 9, .half_even); // fewer digits than prec: untouched
    defer r3.deinit();
    try expectBig("1.200", r3.value.clone());
    try testing.expect(!r3.rounded and !r3.inexact);
    try testing.expectError(error.InvalidPrecision, BigDecimal.roundToPrecision(talloc, a, 0, .half_even));
}

test "BigDecimal.divPrec: ideal exponent, flags, errors" {
    var one = try big("1");
    defer one.deinit();
    var three = try big("3");
    defer three.deinit();
    var zero = try big("0");
    defer zero.deinit();
    var r = try BigDecimal.divPrec(talloc, one, three, 5, .half_even); // Python: Decimal(1)/3 at prec 5 -> 0.33333
    defer r.deinit();
    try expectBig("0.33333", r.value.clone());
    try testing.expect(r.inexact and r.rounded);
    try testing.expectError(error.DivisionByZero, BigDecimal.divPrec(talloc, one, zero, 5, .half_even));
    try testing.expectError(error.InvalidPrecision, BigDecimal.divPrec(talloc, one, three, 0, .half_even));
    try testing.expectError(error.PrecisionTooLarge, BigDecimal.divPrec(talloc, one, three, BigDecimal.max_result_digits + 1, .half_even));
    // 1/3 at a large precision is still prec digits and not an exact result.
    var big_prec = try BigDecimal.divPrec(talloc, one, three, 500, .down);
    defer big_prec.deinit();
    try testing.expectEqual(@as(u32, 500), try big_prec.value.precision(talloc));
}

test "BigDecimal.divideInteger / remainderNear / compareTotal / maxMag / adjusted" {
    var a = try big("-7");
    defer a.deinit();
    var b = try big("2");
    defer b.deinit();
    try expectBig("-3", BigDecimal.divideInteger(talloc, a, b));
    try expectBig("1", BigDecimal.remainderNear(talloc, a, b)); // Python: Decimal(-7).remainder_near(2) -> 1
    var k = try big("1E+3");
    defer k.deinit();
    try expectBig("500", BigDecimal.divideInteger(talloc, k, b)); // exponent 0 (Python: Decimal('1E+3') // 2 -> 500)

    var p0 = try big("1.0");
    defer p0.deinit();
    var p00 = try big("1.00");
    defer p00.deinit();
    try testing.expectEqual(std.math.Order.gt, try BigDecimal.compareTotal(talloc, p0, p00)); // Decimal('1.0').compare_total('1.00') -> 1
    var n0 = try big("-1.0");
    defer n0.deinit();
    var n00 = try big("-1.00");
    defer n00.deinit();
    try testing.expectEqual(std.math.Order.lt, try BigDecimal.compareTotal(talloc, n0, n00));
    try testing.expectEqual(std.math.Order.eq, try BigDecimal.compareTotal(talloc, p0, p0));
    var z2 = try big("0E+2");
    defer z2.deinit();
    var z00 = try big("0.00");
    defer z00.deinit();
    try testing.expectEqual(std.math.Order.gt, try BigDecimal.compareTotal(talloc, z2, z00));

    var m5 = try big("-5");
    defer m5.deinit();
    var p3 = try big("3");
    defer p3.deinit();
    try expectBig("-5", BigDecimal.maxMag(talloc, m5, p3));
    try expectBig("3", BigDecimal.minMag(talloc, m5, p3));

    var x = try big("123E+2");
    defer x.deinit();
    try testing.expectEqual(@as(i64, 4), try x.adjusted(talloc));
    var y = try big("0.00123");
    defer y.deinit();
    try testing.expectEqual(@as(i64, -3), try y.adjusted(talloc));
}

test "BigDecimal.toSci / toEng: GDA examples and zero with scale" {
    // GDA to-scientific-string / Python str(Decimal(...)) and to_eng_string().
    try expectSci("123", "123");
    try expectSci("1.23E+3", "123E+1");
    try expectSci("1.23E+5", "123E+3");
    try expectSci("0.00123", "123E-5");
    try expectSci("0.000123", "123E-6");
    try expectSci("1.23E-7", "123E-9");
    try expectSci("-1.23E-7", "-123E-9");
    // Zero keeps its scale.
    try expectSci("0.00", "0.00");
    try expectSci("0E+2", "0E+2");
    try expectSci("0", "0");
    try expectSci("0E-7", "0E-7");
    try expectEng("0.00E+3", "0E+1");
    try expectEng("0E+3", "0E+3");
    try expectEng("10", "1E+1");
    try expectEng("1E+3", "1E+3");
    try expectEng("123.45E+3", "12345E+1");
    try expectEng("100E-9", "1E-7");
    try expectEng("1.2345E+6", "12345E+2");
}

test "BigDecimal.toStringFixed and {f}" {
    var x = try big("1250");
    defer x.deinit();
    const a = try x.toStringFixed(talloc, -2, .half_up);
    defer talloc.free(a);
    try testing.expectEqualStrings("1300", a);
    var z = try big("0");
    defer z.deinit();
    const b = try z.toStringFixed(talloc, 2, .half_even);
    defer talloc.free(b);
    try testing.expectEqualStrings("0.00", b);
    var y = try big("-0.004");
    defer y.deinit();
    const c = try y.toStringFixed(talloc, 2, .half_even);
    defer talloc.free(c);
    try testing.expectEqualStrings("0.00", c); // no negative zero
    const e = try y.toStringFixed(talloc, 3, .down);
    defer talloc.free(e);
    try testing.expectEqualStrings("-0.004", e);

    var buf: [64]u8 = undefined;
    var v = try big("-12.50");
    defer v.deinit();
    try testing.expectEqualStrings("-12.50", try std.mem.print(&buf, "{f}", .{v}));
    var zz = try big("0.00");
    defer zz.deinit();
    try testing.expectEqualStrings("0", try std.mem.print(&buf, "{f}", .{zz})); // same as toStringAlloc; toSci keeps the scale
}

test "BigDecimal.exp / ln / log10 / power: spot checks, flags, typed errors" {
    // Python: Context(prec=28).exp(Decimal(1)) -> 2.718281828459045235360287471
    var one = try big("1");
    defer one.deinit();
    var r = try BigDecimal.exp(talloc, one, 28, .half_even);
    defer r.deinit();
    try expectBig("2.718281828459045235360287471", r.value.clone());
    try testing.expect(r.inexact and r.rounded);
    // exact special cases: exp(0) = 1, ln(1) = 0, log10(1E+3) = 3, flags clear
    var zero = try big("0.00");
    defer zero.deinit();
    var e0 = try BigDecimal.exp(talloc, zero, 9, .up);
    defer e0.deinit();
    try expectBig("1", e0.value.clone());
    try testing.expect(!e0.inexact and !e0.rounded);
    var l1 = try BigDecimal.ln(talloc, one, 9, .up);
    defer l1.deinit();
    try expectBig("0", l1.value.clone());
    try testing.expect(!l1.inexact and !l1.rounded);
    var k3 = try big("1E+3");
    defer k3.deinit();
    var g3 = try BigDecimal.log10(talloc, k3, 9, .down);
    defer g3.deinit();
    try expectBig("3", g3.value.clone());
    try testing.expect(!g3.inexact);
    // Python: ln(10) = 2.302585092994045684017991455, log10(2) = 0.3010299956639811952137388947
    var ten = try big("10");
    defer ten.deinit();
    var two = try big("2");
    defer two.deinit();
    var ln10 = try BigDecimal.ln(talloc, ten, 28, .half_even);
    defer ln10.deinit();
    try expectBig("2.302585092994045684017991455", ln10.value.clone());
    var lg2 = try BigDecimal.log10(talloc, two, 28, .half_even);
    defer lg2.deinit();
    try expectBig("0.3010299956639811952137388947", lg2.value.clone());
    // the mode is honoured: ln(2) = 0.693147...; up/down differ in the last digit at 3 digits
    var up = try BigDecimal.ln(talloc, two, 3, .up);
    defer up.deinit();
    try expectBig("0.694", up.value.clone());
    var dn = try BigDecimal.ln(talloc, two, 3, .down);
    defer dn.deinit();
    try expectBig("0.693", dn.value.clone());
    // power: 2^0.5 at 28 digits; (-2)^3 exact; 4^0.5 is 2.0000 flagged inexact (as Python)
    var half = try big("0.5");
    defer half.deinit();
    var sq2 = try BigDecimal.power(talloc, two, half, 28, .half_even);
    defer sq2.deinit();
    try expectBig("1.414213562373095048801688724", sq2.value.clone());
    var m2 = try big("-2");
    defer m2.deinit();
    var c3 = try big("3");
    defer c3.deinit();
    var cube = try BigDecimal.power(talloc, m2, c3, 28, .half_even);
    defer cube.deinit();
    try expectBig("-8", cube.value.clone());
    try testing.expect(!cube.inexact);
    var four = try big("4");
    defer four.deinit();
    var fr = try BigDecimal.power(talloc, four, half, 5, .up);
    defer fr.deinit();
    try expectBig("2.0000", fr.value.clone());
    try testing.expect(fr.inexact and fr.rounded);
    // typed errors
    var neg = try big("-1");
    defer neg.deinit();
    var z = try big("0");
    defer z.deinit();
    try testing.expectError(error.NonPositiveOperand, BigDecimal.ln(talloc, z, 9, .half_even));
    try testing.expectError(error.NonPositiveOperand, BigDecimal.ln(talloc, neg, 9, .half_even));
    try testing.expectError(error.NonPositiveOperand, BigDecimal.log10(talloc, neg, 9, .half_even));
    try testing.expectError(error.NegativeBase, BigDecimal.power(talloc, neg, half, 9, .half_even));
    try testing.expectError(error.DivisionByZero, BigDecimal.power(talloc, z, neg, 9, .half_even));
    try testing.expectError(error.ZeroToZero, BigDecimal.power(talloc, z, z, 9, .half_even));
    try testing.expectError(error.InvalidPrecision, BigDecimal.exp(talloc, one, 0, .half_even));
    try testing.expectError(error.PrecisionTooLarge, BigDecimal.exp(talloc, one, BigDecimal.max_transcendental_prec + 1, .half_even));
    var huge = try big("1E+10");
    defer huge.deinit();
    try testing.expectError(error.Overflow, BigDecimal.exp(talloc, huge, 9, .half_even));
    // an argument close to 1 needs a wider working precision, not a different answer: Python agrees
    var near = try big("1.0000000000000000000000000000000000000000001"); // 1 + 1E-43
    defer near.deinit();
    var ln_near = try BigDecimal.ln(talloc, near, 20, .half_even);
    defer ln_near.deinit();
    try expectBig("1.0000000000000000000E-43", ln_near.value.clone()); // ln(1+d) = d - d^2/2 ...
}
