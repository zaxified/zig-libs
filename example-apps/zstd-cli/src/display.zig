// SPDX-License-Identifier: BSD-3-Clause AND MIT
//! What the `zstd` command prints, and how: display levels, the progress
//! setting, human-readable sizes (`UTIL_makeHumanReadableSize`), and the
//! printf conversions its messages use (`%6.2f`, `%-20s`, ...) with glibc's
//! rounding, so that a message here is the same bytes as libzstd 1.5.7's
//! `programs/` prints.

const std = @import("std");

/// `g_displayLevel`: 0 nothing, 1 errors, 2 results and warnings (the
/// default), 3 progress, 4 information.
pub var level: i32 = 2;

pub const Progress = enum { auto, never, always };
/// `g_display_prefs.progressSetting`.
pub var progress: Progress = .auto;

var err_buf: [4096]u8 = undefined;
var out_buf: [4096]u8 = undefined;
var err_writer: std.Io.File.Writer = undefined;
var out_writer: std.Io.File.Writer = undefined;

pub fn init(io: std.Io) void {
    err_writer = std.Io.File.stderr().writerStreaming(io, &err_buf);
    out_writer = std.Io.File.stdout().writerStreaming(io, &out_buf);
}

/// `DISPLAY`: stderr, unbuffered as in C (flushed after every message).
pub fn err() *std.Io.Writer {
    return &err_writer.interface;
}

/// `DISPLAYOUT`: stdout.
pub fn out() *std.Io.Writer {
    return &out_writer.interface;
}

pub fn flush() void {
    err_writer.interface.flush() catch {};
    out_writer.interface.flush() catch {};
}

/// `DISPLAYLEVEL(l, ...)`.
pub fn at(l: i32, comptime fmt: []const u8, args: anytype) void {
    if (level < l) return;
    err_writer.interface.print(fmt, args) catch {};
    err_writer.interface.flush() catch {};
}

/// `DISPLAY(...)`: whatever the level.
pub fn always(comptime fmt: []const u8, args: anytype) void {
    err_writer.interface.print(fmt, args) catch {};
    err_writer.interface.flush() catch {};
}

/// `SHOULD_DISPLAY_SUMMARY()`.
pub fn shouldSummary() bool {
    return level >= 2 or progress == .always;
}

/// `SHOULD_DISPLAY_PROGRESS()`.
pub fn shouldProgress() bool {
    return progress != .never and shouldSummary();
}

/// `DISPLAY_SUMMARY(...)`.
pub fn summary(comptime fmt: []const u8, args: anytype) void {
    if (shouldSummary()) at(1, fmt, args);
}

/// `DISPLAY_PROGRESS("\r%79s\r", "")`: clear the progress line.
pub fn clearProgress() void {
    if (shouldProgress()) at(1, "\r" ++ " " ** 79 ++ "\r", .{});
}

/// `UTIL_HumanReadableSize_t`.
pub const Hrs = struct {
    value: f64,
    precision: u8,
    suffix: []const u8,

    /// `%.*f%s` (width 0), or `%W.*f%s` through `fixedWidth`.
    pub fn format(h: Hrs, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try fixed(w, h.value, 0, h.precision);
        try w.writeAll(h.suffix);
    }
};

/// `UTIL_makeHumanReadableSize`: above level 3, whole bytes.
pub fn hrs(size: u64) Hrs {
    if (level > 3) {
        if (size >= 1 << 53) return .{ .value = @as(f64, @floatFromInt(size)) / (1 << 20), .suffix = " MiB", .precision = 2 };
        return .{ .value = @floatFromInt(size), .suffix = " B", .precision = 0 };
    }
    const units = [_]struct { shift: u6, suffix: []const u8 }{
        .{ .shift = 60, .suffix = " EiB" }, .{ .shift = 50, .suffix = " PiB" },
        .{ .shift = 40, .suffix = " TiB" }, .{ .shift = 30, .suffix = " GiB" },
        .{ .shift = 20, .suffix = " MiB" }, .{ .shift = 10, .suffix = " KiB" },
    };
    var h: Hrs = .{ .value = @floatFromInt(size), .suffix = " B", .precision = 0 };
    for (units) |u| {
        if (size >= @as(u64, 1) << u.shift) {
            h.value = @as(f64, @floatFromInt(size)) / @as(f64, @floatFromInt(@as(u64, 1) << u.shift));
            h.suffix = u.suffix;
            break;
        }
    }
    h.precision = if (h.value >= 100 or @as(u64, @intFromFloat(h.value)) == size)
        0
    else if (h.value >= 10)
        1
    else if (h.value > 1)
        2
    else
        3;
    return h;
}

/// `%W.Pf`: right-aligned in `width`, `prec` decimals, rounded as glibc's
/// printf rounds -- the exact binary value to the nearest, ties to even.
/// `value` is finite and not negative (sizes, percentages, ratios).
pub fn fixed(w: *std.Io.Writer, value: f64, width: usize, prec: u8) std.Io.Writer.Error!void {
    var buf: [64]u8 = undefined;
    const s = fixedString(&buf, value, prec);
    if (s.len < width) try w.splatByteAll(' ', width - s.len);
    try w.writeAll(s);
}

fn fixedString(buf: []u8, value: f64, prec: u8) []const u8 {
    std.debug.assert(value >= 0 and std.math.isFinite(value) and prec <= 9);
    // value = m * 2^e exactly; scaled = value * 10^prec = m * 10^prec * 2^e
    const bits: u64 = @bitCast(value);
    const exp_bits: i32 = @intCast((bits >> 52) & 0x7ff);
    const frac: u64 = bits & ((1 << 52) - 1);
    const m: u128 = if (exp_bits == 0) frac else frac | (1 << 52);
    const e: i32 = (if (exp_bits == 0) @as(i32, 1) else exp_bits) - 1075;
    const p10: u128 = std.math.powi(u128, 10, prec) catch unreachable;
    var q: u128 = undefined;
    if (e >= 0) {
        // integral: a size fits 64 bits, so the shift never overflows here
        q = (m << @intCast(e)) * p10;
    } else {
        const k: u32 = @intCast(-e);
        const n = m * p10; // < 2^53 * 10^9 < 2^84
        if (k >= 100) {
            q = 0; // below 2^-47: rounds to 0 at any precision used here
        } else {
            q = n >> @intCast(k);
            const rem = n - (q << @intCast(k));
            const half = @as(u128, 1) << @intCast(k - 1);
            if (rem > half or (rem == half and q & 1 == 1)) q += 1;
        }
    }
    const int_part = q / p10;
    const frac_part = q % p10;
    var w: std.Io.Writer = .fixed(buf);
    w.print("{d}", .{int_part}) catch unreachable;
    if (prec > 0) {
        w.writeByte('.') catch unreachable;
        var digits: [9]u8 = undefined;
        var f = frac_part;
        var i: usize = prec;
        while (i > 0) : (i -= 1) {
            digits[i - 1] = '0' + @as(u8, @intCast(f % 10));
            f /= 10;
        }
        w.writeAll(digits[0..prec]) catch unreachable;
    }
    return w.buffered();
}

/// `%-Ws`: left-aligned, padded to `width`.
pub fn left(w: *std.Io.Writer, s: []const u8, width: usize) std.Io.Writer.Error!void {
    try w.writeAll(s);
    if (s.len < width) try w.splatByteAll(' ', width - s.len);
}

/// `%Ws` / `%Wd`: right-aligned, padded to `width`.
pub fn right(w: *std.Io.Writer, s: []const u8, width: usize) std.Io.Writer.Error!void {
    if (s.len < width) try w.splatByteAll(' ', width - s.len);
    try w.writeAll(s);
}

test "fixed rounds the exact binary value, ties to even, as glibc" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("0.12", fixedString(&buf, 0.125, 2)); // exact tie -> even
    try std.testing.expectEqualStrings("0.38", fixedString(&buf, 0.375, 2));
    try std.testing.expectEqualStrings("1.13", fixedString(&buf, 1.125000001, 2));
    try std.testing.expectEqualStrings("0.1", fixedString(&buf, 0.15, 1)); // 0.1499999...
    try std.testing.expectEqualStrings("2", fixedString(&buf, 2.5, 0));
    try std.testing.expectEqualStrings("4", fixedString(&buf, 3.5, 0));
    try std.testing.expectEqualStrings("100.00", fixedString(&buf, 99.999, 2));
    try std.testing.expectEqualStrings("1234567", fixedString(&buf, 1234567, 0));
    try std.testing.expectEqualStrings("0.0000", fixedString(&buf, 0, 4));
}

test "human-readable sizes pick the unit and precision as UTIL_makeHumanReadableSize" {
    const H = struct { size: u64, want: []const u8 };
    for ([_]H{
        .{ .size = 0, .want = "0 B" },
        .{ .size = 1023, .want = "1023 B" },
        .{ .size = 1024, .want = "1.000 KiB" },
        .{ .size = 1536, .want = "1.50 KiB" },
        .{ .size = 15 * 1024 + 512, .want = "15.5 KiB" },
        .{ .size = 150 * 1024, .want = "150 KiB" },
        .{ .size = 3 << 20, .want = "3.00 MiB" },
    }) |c| {
        var buf: [64]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try w.print("{f}", .{hrs(c.size)});
        try std.testing.expectEqualStrings(c.want, w.buffered());
    }
}
