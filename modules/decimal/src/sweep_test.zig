// SPDX-License-Identifier: MIT
//! No-panic sweep (wave GN) regression tests for the decimal module.

const std = @import("std");
const testing = std.testing;
const big = @import("big.zig");
const BigDecimal = big.BigDecimal;
const Managed = std.math.big.int.Managed;
const Decimal = @import("root.zig").Decimal;

fn mk(coeff: i128, exponent: i32) !BigDecimal {
    return .{ .coeff = try std.math.big.int.Managed.initSet(testing.allocator, coeff), .exponent = exponent };
}

test "roundToPrecision: a carry at the top exponent is Overflow, not a cast panic (sweep DC-3)" {
    // 99E+(maxInt-1) at 1 digit: drop 1 -> exponent maxInt, 99/10 = 9 r 9 -> half_up 10 -> fold -> maxInt + 1.
    var a = try mk(99, std.math.maxInt(i32) - 1);
    defer a.deinit();
    try testing.expectError(error.Overflow, BigDecimal.roundToPrecision(testing.allocator, a, 1, .half_up));
    // Without the carry the same exponent is representable.
    var r = try BigDecimal.roundToPrecision(testing.allocator, a, 1, .down);
    defer r.deinit();
    try testing.expectEqual(@as(i32, std.math.maxInt(i32)), r.value.exponent);
}

test "div: target_scale == minInt(i32) is Overflow, not a negation panic (sweep DC-4)" {
    var zero = try mk(0, 0);
    defer zero.deinit();
    var one = try mk(1, 0);
    defer one.deinit();
    try testing.expectError(error.Overflow, BigDecimal.div(testing.allocator, zero, one, std.math.minInt(i32), .down));
    // A nonzero dividend takes the same early refusal: `-target_scale` is computed
    // before any shift arithmetic (the shift would be 0 here, but is never reached).
    var hi = try mk(1, std.math.maxInt(i32));
    defer hi.deinit();
    var lo = try mk(1, -1);
    defer lo.deinit();
    try testing.expectError(error.Overflow, BigDecimal.div(testing.allocator, hi, lo, std.math.minInt(i32), .down));
}

test "parse: more than max_parse_digits digits is Overflow before any conversion (sweep DC-2)" {
    const n = BigDecimal.max_parse_digits;
    const buf = try testing.allocator.alloc(u8, n + 2);
    defer testing.allocator.free(buf);
    @memset(buf, '7');
    // Exactly the cap parses; one digit more is Overflow (also with a '.' inside).
    var ok = try BigDecimal.parse(testing.allocator, buf[0..n]);
    ok.deinit();
    try testing.expectError(error.Overflow, BigDecimal.parse(testing.allocator, buf[0 .. n + 1]));
    buf[10] = '.';
    try testing.expectError(error.Overflow, BigDecimal.parse(testing.allocator, buf));
}

test "toStringAlloc / format refuse unbounded zero padding (sweep DC-1)" {
    const a = testing.allocator;
    // One zero past the cap first: a missing guard fails here, cheaply.
    var over = try BigDecimal.parse(a, "1e1000001");
    defer over.deinit();
    try testing.expectError(error.OutOfMemory, over.toStringAlloc(a));
    var huge = try BigDecimal.parse(a, "1e2000000000");
    defer huge.deinit();
    var tiny = try BigDecimal.parse(a, "1e-2000000000");
    defer tiny.deinit();
    try testing.expectError(error.OutOfMemory, huge.toStringAlloc(a));
    try testing.expectError(error.OutOfMemory, tiny.toStringAlloc(a));

    var w: std.Io.Writer.Allocating = .init(a);
    defer w.deinit();
    try testing.expectError(error.WriteFailed, w.writer.print("{f}", .{over}));
    try testing.expectError(error.WriteFailed, w.writer.print("{f}", .{tiny}));

    // The cap itself is allowed; toSci stays exponent-sized.
    var edge = try BigDecimal.parse(a, "1e1000000");
    defer edge.deinit();
    const s = try edge.toStringAlloc(a);
    defer a.free(s);
    try testing.expectEqual(@as(usize, 1_000_001), s.len);
    const sci = try huge.toSci(a);
    defer a.free(sci);
    try testing.expectEqualStrings("1E+2000000000", sci);
}

test "toStringFixed refuses unbounded zero padding (sweep DC-1)" {
    const a = testing.allocator;
    var zero = try BigDecimal.parse(a, "0");
    defer zero.deinit();
    // "0." plus 1000001 fraction zeros needs 1000001 padding zeros: one past the cap.
    try testing.expectError(error.Overflow, zero.toStringFixed(a, 1000002, .down));
    try testing.expectError(error.Overflow, zero.toStringFixed(a, 2000000000, .down));
    const ok = try zero.toStringFixed(a, 1000001, .down);
    defer a.free(ok);
    try testing.expectEqual(@as(usize, 1_000_003), ok.len);
    // A positive result exponent that is huge although the shift is 0.
    var huge = try BigDecimal.parse(a, "1e1000001");
    defer huge.deinit();
    try testing.expectError(error.Overflow, huge.toStringFixed(a, -1000001, .down));
}

// ---------------------------------------------------------------------------
// Review fixes (wave GN, second pass)
// ---------------------------------------------------------------------------

fn monoNs() u64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

/// `m * 10^zeros` at `exponent`, built without the quadratic decimal parser.
fn tenPow(a: std.mem.Allocator, mult: i128, zeros: u32, exponent: i32) !BigDecimal {
    var ten = try Managed.initSet(a, 10);
    defer ten.deinit();
    var p = try Managed.init(a);
    errdefer p.deinit();
    try p.pow(&ten, zeros);
    var m = try Managed.initSet(a, mult);
    defer m.deinit();
    var c = try Managed.init(a);
    errdefer c.deinit();
    try c.mul(&p, &m);
    p.deinit();
    return .{ .coeff = c, .exponent = exponent };
}

fn normalizeNs(zeros: u32) !u64 {
    var best: u64 = std.math.maxInt(u64);
    var v = try tenPow(testing.allocator, 1, zeros, 5);
    defer v.deinit();
    for (0..5) |_| {
        const t0 = monoNs();
        var n = try BigDecimal.normalize(testing.allocator, v);
        const dt = monoNs() - t0;
        defer n.deinit();
        try testing.expectEqual(@as(i32, 5 + @as(i32, @intCast(zeros))), n.exponent);
        try testing.expectEqual(@as(i32, 1), try n.coeff.toInt(i32));
        best = @min(best, dt);
    }
    return best;
}

/// The pre-fix algorithm, kept as the timing baseline.
fn naiveNormalizeNs(zeros: u32) !u64 {
    const a = testing.allocator;
    var v = try tenPow(a, 1, zeros, 5);
    defer v.deinit();
    var ten = try Managed.initSet(a, 10);
    defer ten.deinit();
    var q = try Managed.init(a);
    defer q.deinit();
    var rem = try Managed.init(a);
    defer rem.deinit();
    const t0 = monoNs();
    while (true) {
        try q.divTrunc(&rem, &v.coeff, &ten);
        if (!rem.eqlZero()) break;
        v.coeff.swap(&q);
        v.exponent += 1;
    }
    const dt = monoNs() - t0;
    try testing.expectEqual(@as(i32, 5 + @as(i32, @intCast(zeros))), v.exponent);
    return dt;
}

test "normalize strips 100000 trailing zeros at once, in linear-ish time (sweep DC-7)" {
    const a = testing.allocator;
    // Exact results first.
    var big_v = try tenPow(a, -7, 100_000, 3);
    defer big_v.deinit();
    var n = try BigDecimal.normalize(a, big_v);
    defer n.deinit();
    try testing.expectEqual(@as(i32, 100_003), n.exponent);
    try testing.expect(n.coeff.toInt(i32) catch 0 == -7);
    // A coefficient with many factors of 2 but few of 5, and the reverse.
    var two = try Managed.initSet(a, 3);
    defer two.deinit();
    try two.shiftLeft(&two, 5000);
    const pw = BigDecimal{ .coeff = two, .exponent = 0 };
    var same = try BigDecimal.normalize(a, pw);
    defer same.deinit();
    try testing.expectEqual(@as(i32, 0), same.exponent);
    try testing.expect(same.coeff.eql(pw.coeff));
    // Room for the exponent: stops at maxInt(i32).
    var top = try tenPow(a, 1, 50, std.math.maxInt(i32) - 20);
    defer top.deinit();
    var tn = try BigDecimal.normalize(a, top);
    defer tn.deinit();
    try testing.expectEqual(@as(i32, std.math.maxInt(i32)), tn.exponent);
    try testing.expectEqual(@as(usize, 31), try tn.precision(a)); // 10^30 left: 20 zeros went into the exponent
    // Against the one-digit-at-a-time definition on many shapes.
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const rnd = prng.random();
    for (0..300) |_| {
        const m: i128 = rnd.intRangeAtMost(i64, -1_000_000, 1_000_000);
        const z = rnd.intRangeAtMost(u32, 0, 70);
        var v = try tenPow(a, m, z, 0);
        defer v.deinit();
        var got = try BigDecimal.normalize(a, v);
        defer got.deinit();
        var want_m: i128 = m;
        var want_e: i32 = 0;
        while (want_m != 0 and @rem(want_m, 10) == 0) : (want_e += 1) want_m = @divExact(want_m, 10);
        if (m == 0) continue;
        want_e += @intCast(z);
        try testing.expectEqual(want_e, got.exponent);
        try testing.expectEqual(want_m, try got.coeff.toInt(i128));
    }
    // Against the old one-division-by-10-per-zero loop (machine independent: both
    // timed here). The old cost is zeros x limbs; the new one is a single division.
    const t_new = try normalizeNs(12_500);
    const t_old = try naiveNormalizeNs(12_500);
    try testing.expect(t_new * 5 < t_old);
}

test "order / eql / max / min compare far-apart exponents without aligning (sweep DC-5)" {
    const a = testing.allocator;
    var huge = try BigDecimal.parse(a, "1E+2000000");
    defer huge.deinit();
    var five = try BigDecimal.parse(a, "5");
    defer five.deinit();
    var nhuge = try BigDecimal.parse(a, "-1E+2000000");
    defer nhuge.deinit();
    try testing.expectEqual(std.math.Order.gt, try BigDecimal.order(a, huge, five));
    try testing.expectEqual(std.math.Order.lt, try BigDecimal.order(a, five, huge));
    try testing.expectEqual(std.math.Order.lt, try BigDecimal.order(a, nhuge, five));
    try testing.expectEqual(std.math.Order.lt, try BigDecimal.order(a, nhuge, huge));
    var nless = try BigDecimal.parse(a, "-1E+1999999");
    defer nless.deinit();
    try testing.expectEqual(std.math.Order.lt, try BigDecimal.order(a, nhuge, nless));
    try testing.expectEqual(false, try BigDecimal.eql(a, huge, five));
    var mx = try BigDecimal.max(a, huge, five);
    defer mx.deinit();
    try testing.expectEqual(@as(i32, 2_000_000), mx.exponent);
    var mn = try BigDecimal.min(a, huge, five);
    defer mn.deinit();
    try testing.expectEqual(@as(i32, 0), mn.exponent);
    // Equal values at different scales, same and different adjusted-exponent estimates.
    for ([_][2][]const u8{ .{ "1000", "1E+3" }, .{ "99", "99.0" }, .{ "-250", "-2.5E+2" }, .{ "0", "0E+5" } }) |pair| {
        var x = try BigDecimal.parse(a, pair[0]);
        defer x.deinit();
        var y = try BigDecimal.parse(a, pair[1]);
        defer y.deinit();
        try testing.expectEqual(std.math.Order.eq, try BigDecimal.order(a, x, y));
    }
    var n99 = try BigDecimal.parse(a, "99");
    defer n99.deinit();
    var e2 = try BigDecimal.parse(a, "1E+2");
    defer e2.deinit();
    try testing.expectEqual(std.math.Order.lt, try BigDecimal.order(a, n99, e2));
    var m99 = try BigDecimal.parse(a, "-99");
    defer m99.deinit();
    var me2 = try BigDecimal.parse(a, "-1E+2");
    defer me2.deinit();
    try testing.expectEqual(std.math.Order.gt, try BigDecimal.order(a, m99, me2));
}

test "results wider than max_coeff_digits are Overflow before the big work (sweep DC-6)" {
    const a = testing.allocator;
    const cap: i32 = BigDecimal.max_coeff_digits;
    var one = try BigDecimal.parse(a, "1");
    defer one.deinit();
    // rescale: 10^(cap-1) has cap digits; one more is refused.
    var ok = try BigDecimal.rescale(a, one, -(cap - 1), .down);
    ok.deinit();
    try testing.expectError(error.Overflow, BigDecimal.rescale(a, one, -cap, .down));
    // add / sub: the aligned operand is the wide one.
    var tiny_ok = try BigDecimal.parse(a, "1E-199999");
    defer tiny_ok.deinit();
    var sum = try BigDecimal.add(a, one, tiny_ok);
    sum.deinit();
    var tiny = try BigDecimal.parse(a, "1E-200000");
    defer tiny.deinit();
    try testing.expectError(error.Overflow, BigDecimal.add(a, one, tiny));
    try testing.expectError(error.Overflow, BigDecimal.sub(a, tiny, one));
    // The exact-count window: the bit-length bounds straddle the cap here.
    try testing.expectError(error.Overflow, BigDecimal.remainder(a, one, tiny));
    try testing.expectError(error.Overflow, BigDecimal.divideInteger(a, one, tiny));
    try testing.expectError(error.Overflow, BigDecimal.remainderNear(a, one, tiny));
    // mul: 10^100000 (100001 digits) times 10^99999 (100000 digits) = 200000 digits: allowed.
    var w1 = try tenPow(a, 1, 100_000, 0);
    defer w1.deinit();
    var w2 = try tenPow(a, 1, 99_998, 0);
    defer w2.deinit();
    var w3 = try tenPow(a, 1, 99_999, 0);
    defer w3.deinit();
    var p_ok = try BigDecimal.mul(a, w1, w3);
    p_ok.deinit();
    try testing.expectError(error.Overflow, BigDecimal.mul(a, w1, w1));
    var p2 = try BigDecimal.mul(a, w1, w2);
    p2.deinit();
    var w9 = try tenPow(a, 9, 150_000, 0);
    defer w9.deinit();
    try testing.expectError(error.Overflow, BigDecimal.mul(a, w9, w9));
    // div: the quotient of 1 / 1 at scale cap has cap + 1 digits.
    var q = try BigDecimal.div(a, one, one, cap - 1, .down);
    q.deinit();
    try testing.expectError(error.Overflow, BigDecimal.div(a, one, one, cap, .down));
    // toStringFixed goes through rescale.
    try testing.expectError(error.Overflow, one.toStringFixed(a, cap, .down));
    // fromFloat with a huge scale.
    try testing.expectError(error.Overflow, BigDecimal.fromFloat(a, 1.5, cap + 10, .down));
}

test "toFloat and toStringAlloc decide out-of-range values before any digit conversion (sweep DC-6)" {
    // A 150000-digit coefficient (a decimal conversion would take seconds).
    var wide = try tenPow(testing.allocator, 1, 150_000, 1000);
    defer wide.deinit();
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectEqual(std.math.inf(f64), try wide.toFloat(fa.allocator()));
    wide.exponent = -400_000;
    try testing.expectEqual(@as(f64, 0.0), try wide.toFloat(fa.allocator()));
    // Plain notation needing more than max_align_shift zeros: refused with no allocation at all.
    wide.exponent = 5_000_000;
    try testing.expectError(error.OutOfMemory, wide.toStringAlloc(fa.allocator()));
    wide.exponent = -1_300_000;
    try testing.expectError(error.OutOfMemory, wide.toStringAlloc(fa.allocator()));
    // No request reached the allocator (a failing allocator does not advance alloc_index).
    try testing.expect(!fa.has_induced_failure);
}

/// Fails exactly the `fail_at`-th allocation and serves every other one.
const OneShot = struct {
    fail_at: usize,
    n: usize = 0,
    failed: bool = false,

    const vtable: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };

    fn allocator(self: *OneShot) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *OneShot = @ptrCast(@alignCast(ctx));
        defer self.n += 1;
        if (self.n == self.fail_at) {
            self.failed = true;
            return null;
        }
        return testing.allocator.rawAlloc(len, a, ra);
    }

    fn resize(_: *anyopaque, m: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) bool {
        return testing.allocator.rawResize(m, a, new_len, ra);
    }

    fn remap(_: *anyopaque, m: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        return testing.allocator.rawRemap(m, a, new_len, ra);
    }

    fn free(_: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
        testing.allocator.rawFree(m, a, ra);
    }
};

test "exactPowerCandidate propagates OutOfMemory instead of swallowing it (sweep DC-8)" {
    // power(6.25, 0.5) = 2.5 exactly, a tie at 1 digit: the interval cannot decide, so the
    // exact-root candidate test runs. Every allocation failure on the way is an
    // OutOfMemory (a swallowed one would show as a success after the failed allocation; the
    // allocator fails exactly one request, because std's FailingAllocator keeps failing).
    var four = try BigDecimal.parse(testing.allocator, "6.25");
    defer four.deinit();
    var half = try BigDecimal.parse(testing.allocator, "0.5");
    defer half.deinit();
    var want = try BigDecimal.power(testing.allocator, four, half, 1, .half_even);
    defer want.deinit();
    const want_s = try want.value.toSci(testing.allocator);
    defer testing.allocator.free(want_s);
    var idx: usize = 0;
    var oom: usize = 0;
    while (idx < 4000) : (idx += 1) {
        var fa: OneShot = .{ .fail_at = idx };
        if (BigDecimal.power(fa.allocator(), four, half, 1, .half_even)) |r_ok| {
            var r = r_ok;
            defer r.deinit();
            try testing.expect(!fa.failed);
            const s = try r.value.toSci(testing.allocator);
            defer testing.allocator.free(s);
            try testing.expectEqualStrings(want_s, s);
        } else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            oom += 1;
        }
        if (!fa.failed) break;
    }
    try testing.expect(oom > 10);
}

test "Decimal.toStringFixed: an exactly-fitting buffer works (sweep DC-9)" {
    const d = try Decimal.parse("1.50");
    var buf4: [4]u8 = undefined;
    try testing.expectEqualStrings("1.50", try d.toStringFixed(&buf4, 2, .half_even));
    var buf3: [3]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, d.toStringFixed(&buf3, 2, .half_even));
    const n = try Decimal.parse("-0.25");
    var buf5: [5]u8 = undefined;
    try testing.expectEqualStrings("-0.25", try n.toStringFixed(&buf5, 2, .half_even));
    // places above 12 pad with zeros
    var buf16: [16]u8 = undefined;
    try testing.expectEqualStrings("1.5000000000000", try d.toStringFixed(&buf16, 13, .half_even));
    var buf14: [14]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, d.toStringFixed(&buf14, 13, .half_even));
    try testing.expect(Decimal.fixedBufLen(std.math.maxInt(u32)) > Decimal.fixedBufLen(12));
}

/// Serves requests up to `limit` bytes, fails bigger ones: a refusal decided
/// before the big work never asks for them.
const Capped = struct {
    limit: usize,
    refused: bool = false,

    const vtable: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };

    fn allocator(self: *Capped) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *Capped = @ptrCast(@alignCast(ctx));
        if (len > self.limit) {
            self.refused = true;
            return null;
        }
        return testing.allocator.rawAlloc(len, a, ra);
    }

    fn resize(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *Capped = @ptrCast(@alignCast(ctx));
        if (new_len > self.limit) return false;
        return testing.allocator.rawResize(m, a, new_len, ra);
    }

    fn remap(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *Capped = @ptrCast(@alignCast(ctx));
        if (new_len > self.limit) return null;
        return testing.allocator.rawRemap(m, a, new_len, ra);
    }

    fn free(_: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
        testing.allocator.rawFree(m, a, ra);
    }
};

test "mul and div refuse a too-wide result before allocating it (sweep DC-6)" {
    const a = testing.allocator;
    var w9 = try tenPow(a, 9, 150_000, 0); // 150001 digits
    defer w9.deinit();
    var one = try BigDecimal.parse(a, "1");
    defer one.deinit();
    // 16 KiB: far below a 300000-digit product or a 10^200000 scale factor (~83 KB).
    var cap: Capped = .{ .limit = 16 * 1024 };
    try testing.expectError(error.Overflow, BigDecimal.mul(cap.allocator(), w9, w9));
    try testing.expectError(error.Overflow, BigDecimal.div(cap.allocator(), one, one, BigDecimal.max_coeff_digits + 5, .down));
    try testing.expect(!cap.refused);
}

test "a sum one digit past max_coeff_digits is Overflow (sweep DC-6)" {
    const a = testing.allocator;
    var ten = try Managed.initSet(a, 10);
    defer ten.deinit();
    var p = try Managed.init(a);
    var wide = BigDecimal{ .coeff = p, .exponent = 0 }; // 10^200000 - 1: 200000 nines
    defer wide.deinit();
    try p.pow(&ten, BigDecimal.max_coeff_digits);
    try p.addScalar(&p, -1);
    wide.coeff = p;
    try testing.expectError(error.Overflow, BigDecimal.add(a, wide, wide));
    // 10^199999 doubled still has 200000 digits.
    var half = try tenPow(a, 1, BigDecimal.max_coeff_digits - 1, 0);
    defer half.deinit();
    var ok = try BigDecimal.add(a, half, half);
    ok.deinit();
}

test "toStringAlloc: the exact padding is the limit, not the digit-count bound (sweep audit GN-DA-4)" {
    const a = testing.allocator;
    // 64 has 2 digits but 7 bits (bound: at most 3 digits), so the bound alone
    // would let exactly one zero too many through.
    var over = try BigDecimal.parse(a, "64e-1000003"); // 1_000_001 padding zeros
    defer over.deinit();
    try testing.expectError(error.OutOfMemory, over.toStringAlloc(a));
    var edge = try BigDecimal.parse(a, "64e-1000002"); // exactly 1_000_000
    defer edge.deinit();
    const s = try edge.toStringAlloc(a);
    defer a.free(s);
    try testing.expectEqual(@as(usize, 2 + 1_000_000 + 2), s.len);
}

test "toStringFixed: a zero at a huge positive exponent prints a bare 0 (sweep audit GN-DA-23)" {
    const a = testing.allocator;
    var z = try BigDecimal.parse(a, "0");
    defer z.deinit();
    const s = try z.toStringFixed(a, -2_000_000, .down);
    defer a.free(s);
    try testing.expectEqualStrings("0", s);
}

test "remainder / divideInteger / remainderNear refuse a too-wide divisor alignment (sweep audit GN-DA-45)" {
    const a = testing.allocator;
    var one = try BigDecimal.parse(a, "1");
    defer one.deinit();
    var tiny = try BigDecimal.parse(a, "1E-200000");
    defer tiny.deinit();
    // The divisor (second operand) is the one scaled up here.
    try testing.expectError(error.Overflow, BigDecimal.remainder(a, tiny, one));
    try testing.expectError(error.Overflow, BigDecimal.divideInteger(a, tiny, one));
    try testing.expectError(error.Overflow, BigDecimal.remainderNear(a, tiny, one));
}

test "a coefficient of exactly max_coeff_digits digits is accepted by the exact-count path (sweep audit GN-DA-30)" {
    const a = testing.allocator;
    const cap: i32 = BigDecimal.max_coeff_digits;
    var one = try BigDecimal.parse(a, "1");
    defer one.deinit();
    var x = try BigDecimal.rescale(a, one, -(cap - 1), .down); // cap digits
    defer x.deinit();
    var s = try BigDecimal.add(a, x, x); // 2 * 10^(cap-1): still cap digits
    s.deinit();
    var t = try BigDecimal.rescale(a, x, -(cap - 1), .down); // same exponent: no growth
    t.deinit();
    var y = try tenPow(a, 9, 199_999, 0); // 9 * 10^199999: cap digits, near the bit-length window
    defer y.deinit();
    var zero = try BigDecimal.parse(a, "0");
    defer zero.deinit();
    var s2 = try BigDecimal.add(a, y, zero);
    s2.deinit();
    var m = try BigDecimal.mul(a, y, one);
    m.deinit();
    var r = try BigDecimal.rescale(a, y, 0, .down);
    r.deinit();
    var y2 = try tenPow(a, 1, 199_999, 0);
    defer y2.deinit();
    var r2 = try BigDecimal.rescale(a, y2, 0, .down);
    r2.deinit();
}
