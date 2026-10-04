// SPDX-License-Identifier: MIT
//! RFC 8949 §8 diagnostic notation for a `Value` — the human-readable text
//! the RFC's own examples are written in (`[1, {"a": h'0102'}, 1(1363896240)]`).
//!
//! Output is ASCII-only, in the form RFC 8949 Appendix A prints:
//!   - integers in decimal, negative ones down to -18446744073709551616;
//!   - floats as their shortest round-trip decimal, always with a `.` or an
//!     exponent so they read as floats (`1.0`, `100000.0`, `1.0e+300`,
//!     `5.960464477539063e-8`, `0.00006103515625`), plus `-0.0`, `Infinity`,
//!     `-Infinity`, `NaN` — the layout is ECMAScript's Number-to-String with
//!     `.0` added to a mantissa that has no point, which is what the RFC's
//!     table shows; a binary16/32 value prints as the binary64 value it is;
//!   - byte strings `h'0102'`, text strings JSON-escaped with every
//!     non-ASCII character as `\uXXXX` (a surrogate pair above U+FFFF);
//!   - `[a, b]`, `{k: v}`, `N(item)` for a tag, `simple(N)`, `true`,
//!     `false`, `null`, `undefined`.
//!
//! Not shown: encoding indicators (`_`, `_1`, …) — a decoded `Value` does not
//! keep the wire form, so an indefinite-length item prints as its definite
//! twin. Bignums (tags 2/3) print as the tag over its byte string,
//! `2(h'010000000000000000')`, which is valid diagnostic notation; the RFC's
//! table shows their numeric value instead.
//!
//! Recursion follows the `Value` tree: a tree from `decode` is at most
//! `DecodeOptions.max_depth` deep; a hand-built tree is the caller's.

const std = @import("std");
const root = @import("root.zig");
const Value = root.Value;
const Writer = std.Io.Writer;

/// Write `v` in diagnostic notation.
pub fn write(w: *Writer, v: Value) Writer.Error!void {
    switch (v) {
        .uint => |u| try w.print("{d}", .{u}),
        .negint => |n| try w.print("-{d}", .{@as(u65, n) + 1}),
        .bytes => |b| {
            try w.writeAll("h'");
            for (b) |c| try w.print("{x:0>2}", .{c});
            try w.writeByte('\'');
        },
        .text => |t| try writeText(w, t),
        .array => |items| {
            try w.writeByte('[');
            for (items, 0..) |it, i| {
                if (i != 0) try w.writeAll(", ");
                try write(w, it);
            }
            try w.writeByte(']');
        },
        .map => |entries| {
            try w.writeByte('{');
            for (entries, 0..) |e, i| {
                if (i != 0) try w.writeAll(", ");
                try write(w, e.key);
                try w.writeAll(": ");
                try write(w, e.value);
            }
            try w.writeByte('}');
        },
        .tag => |t| {
            try w.print("{d}(", .{t.number});
            try write(w, t.value.*);
            try w.writeByte(')');
        },
        .simple => |s| try w.print("simple({d})", .{s}),
        .bool => |b| try w.writeAll(if (b) "true" else "false"),
        .null_value => try w.writeAll("null"),
        .undefined_value => try w.writeAll("undefined"),
        .f16 => |f| try writeFloat(w, f),
        .f32 => |f| try writeFloat(w, f),
        .f64 => |f| try writeFloat(w, f),
    }
}

/// `write` into a new `gpa`-owned slice.
pub fn alloc(gpa: std.mem.Allocator, v: Value) std.mem.Allocator.Error![]u8 {
    var aw: Writer.Allocating = .init(gpa);
    defer aw.deinit();
    write(&aw.writer, v) catch return error.OutOfMemory;
    return aw.toOwnedSlice();
}

fn writeText(w: *Writer, t: []const u8) Writer.Error!void {
    try w.writeByte('"');
    var i: usize = 0;
    while (i < t.len) {
        const c = t[i];
        if (c < 0x80) {
            switch (c) {
                '"' => try w.writeAll("\\\""),
                '\\' => try w.writeAll("\\\\"),
                '\n' => try w.writeAll("\\n"),
                '\r' => try w.writeAll("\\r"),
                '\t' => try w.writeAll("\\t"),
                0x08 => try w.writeAll("\\b"),
                0x0c => try w.writeAll("\\f"),
                0x00...0x07, 0x0b, 0x0e...0x1f, 0x7f => try w.print("\\u{x:0>4}", .{c}),
                else => try w.writeByte(c),
            }
            i += 1;
            continue;
        }
        // Non-ASCII. A decoded text is valid UTF-8; a hand-built one may not
        // be, and an invalid byte prints as U+FFFD rather than failing.
        const len = std.unicode.utf8ByteSequenceLength(c) catch {
            try w.writeAll("\\ufffd");
            i += 1;
            continue;
        };
        if (len > t.len - i) {
            try w.writeAll("\\ufffd");
            i += 1;
            continue;
        }
        const cp = std.unicode.utf8Decode(t[i..][0..len]) catch {
            try w.writeAll("\\ufffd");
            i += 1;
            continue;
        };
        if (cp > 0xffff) {
            const u = cp - 0x10000;
            try w.print("\\u{x:0>4}\\u{x:0>4}", .{ 0xd800 + (u >> 10), 0xdc00 + (u & 0x3ff) });
        } else {
            try w.print("\\u{x:0>4}", .{cp});
        }
        i += len;
    }
    try w.writeByte('"');
}

fn writeFloat(w: *Writer, x: f64) Writer.Error!void {
    if (std.math.isNan(x)) return w.writeAll("NaN");
    if (std.math.signbit(x)) try w.writeByte('-');
    const a = @abs(x);
    if (std.math.isInf(a)) return w.writeAll("Infinity");

    // Shortest round-trip digits and the decimal exponent, from `{e}`
    // ("d.ddde-N"): digits d0 d1 ... and x = 0.d0d1... * 10^n.
    var sbuf: [64]u8 = undefined;
    const sci = std.fmt.bufPrint(&sbuf, "{e}", .{a}) catch unreachable;
    const e_at = std.mem.indexOfScalar(u8, sci, 'e').?;
    var digits_buf: [32]u8 = undefined;
    var k: usize = 0;
    for (sci[0..e_at]) |c| if (c != '.') {
        digits_buf[k] = c;
        k += 1;
    };
    while (k > 1 and digits_buf[k - 1] == '0') k -= 1;
    const digits = digits_buf[0..k];
    const exp10 = std.fmt.parseInt(i32, sci[e_at + 1 ..], 10) catch unreachable;
    const n: i32 = exp10 + 1;
    const ki: i32 = @intCast(k);

    if (ki <= n and n <= 21) {
        // An integer value: the digits, zeros, and ".0".
        try w.writeAll(digits);
        try w.splatByteAll('0', @intCast(n - ki));
        try w.writeAll(".0");
    } else if (0 < n and n <= 21) {
        try w.writeAll(digits[0..@intCast(n)]);
        try w.writeByte('.');
        try w.writeAll(digits[@intCast(n)..]);
    } else if (-6 < n and n <= 0) {
        try w.writeAll("0.");
        try w.splatByteAll('0', @intCast(-n));
        try w.writeAll(digits);
    } else {
        try w.writeByte(digits[0]);
        try w.writeByte('.');
        if (k > 1) try w.writeAll(digits[1..]) else try w.writeByte('0');
        const e = n - 1;
        try w.print("e{c}{d}", .{ @as(u8, if (e < 0) '-' else '+'), @abs(e) });
    }
}
