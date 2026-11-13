// SPDX-License-Identifier: MIT
//! Python-compatible text primitives behind the `format`, `wordwrap` and
//! `filesizeformat` filters: `str % args`, `textwrap.wrap` and exact
//! `%e`/`%f`/`%g` float rendering.
//!
//! Everything here works on plain values and an arena (no filter context), so
//! `filters.zig` owns the argument handling and this file owns the algorithms.
//! Every output is bounded by `value.max_alloc` and every width/precision that
//! comes from template data is checked before it becomes an allocation size.

const std = @import("std");
const value = @import("value.zig");
const ut = @import("unitext");

const Value = value.Value;
pub const Error = value.Error;

/// Cap on a float precision (`%.5000f`): the exact expansion is O(precision^2).
const max_float_prec: usize = 4096;

// ── exact float digits ──────────────────────────────────────────────────────
//
// CPython rounds `'%.2f' % 2.675` from the EXACT binary value (`2.67`), not
// from the shortest round-trip digits (`2.675`) that std's float printer
// rounds. So the exact decimal expansion is built here with a tiny bignum.

const Big = struct {
    limbs: std.ArrayList(u32) = .empty,

    fn fromU64(a: std.mem.Allocator, v: u64) !Big {
        var b: Big = .{};
        try b.limbs.append(a, @truncate(v));
        try b.limbs.append(a, @truncate(v >> 32));
        return b;
    }

    fn mulSmall(self: *Big, a: std.mem.Allocator, m: u32) !void {
        var carry: u64 = 0;
        for (self.limbs.items) |*l| {
            const t = @as(u64, l.*) * m + carry;
            l.* = @truncate(t);
            carry = t >> 32;
        }
        if (carry != 0) try self.limbs.append(a, @truncate(carry));
    }

    fn shl(self: *Big, a: std.mem.Allocator, bits: usize) !void {
        const sh: u6 = @intCast(bits % 32);
        if (sh != 0) {
            var carry: u64 = 0;
            for (self.limbs.items) |*l| {
                const t = (@as(u64, l.*) << sh) | carry;
                l.* = @truncate(t);
                carry = t >> 32;
            }
            if (carry != 0) try self.limbs.append(a, @truncate(carry));
        }
        const words = bits / 32;
        if (words != 0) {
            const zeros = try a.alloc(u32, words);
            @memset(zeros, 0);
            try self.limbs.insertSlice(a, 0, zeros);
        }
    }

    /// Decimal digits, most significant first, no leading zeros (empty for 0).
    fn toDecimal(self: *Big, a: std.mem.Allocator) ![]u8 {
        var chunks: std.ArrayList(u32) = .empty;
        const items = try a.dupe(u32, self.limbs.items);
        var len = items.len;
        while (len > 0 and items[len - 1] == 0) len -= 1;
        while (len > 0) {
            var rem: u64 = 0;
            var i = len;
            while (i > 0) {
                i -= 1;
                const t = (rem << 32) | items[i];
                items[i] = @intCast(t / 1_000_000_000);
                rem = t % 1_000_000_000;
            }
            try chunks.append(a, @intCast(rem));
            while (len > 0 and items[len - 1] == 0) len -= 1;
        }
        var out: std.ArrayList(u8) = .empty;
        var k = chunks.items.len;
        var first = true;
        while (k > 0) {
            k -= 1;
            var tmp: [9]u8 = undefined;
            var v = chunks.items[k];
            var j: usize = 9;
            while (j > 0) {
                j -= 1;
                tmp[j] = '0' + @as(u8, @intCast(v % 10));
                v /= 10;
            }
            if (first) {
                var s: usize = 0;
                while (s < 8 and tmp[s] == '0') s += 1;
                try out.appendSlice(a, tmp[s..]);
                first = false;
            } else try out.appendSlice(a, &tmp);
        }
        return out.items;
    }
};

/// `0.d1d2… × 10^…` as `d1.d2… × 10^x`; `digits` has no leading and no
/// trailing zeros, and is empty for zero.
const Dec = struct { digits: []const u8, x: i32 };

fn exactDecimal(a: std.mem.Allocator, f_abs: f64) !Dec {
    const bits: u64 = @bitCast(f_abs);
    const exp_bits: u32 = @intCast((bits >> 52) & 0x7ff);
    const frac: u64 = bits & ((1 << 52) - 1);
    if (exp_bits == 0 and frac == 0) return .{ .digits = "", .x = 0 };
    var m: u64 = if (exp_bits == 0) frac else frac | (1 << 52);
    var e: i32 = if (exp_bits == 0) -1074 else @as(i32, @intCast(exp_bits)) - 1075;
    while (m & 1 == 0) {
        m >>= 1;
        e += 1;
    }
    var big = try Big.fromU64(a, m);
    var point: i32 = 0; // decimal digits that sit after the point
    if (e >= 0) {
        try big.shl(a, @intCast(e));
    } else {
        var k: u32 = @intCast(-e);
        point = @intCast(k);
        while (k >= 13) : (k -= 13) try big.mulSmall(a, 1_220_703_125); // 5^13
        var r: u32 = 1;
        var q: u32 = 0;
        while (q < k) : (q += 1) r *= 5;
        if (r != 1) try big.mulSmall(a, r);
    }
    const s = try big.toDecimal(a);
    var end = s.len;
    while (end > 0 and s[end - 1] == '0') end -= 1;
    return .{ .digits = s[0..end], .x = @as(i32, @intCast(s.len)) - 1 - point };
}

/// Round to `keep` leading digits, half to even on the exact value.
fn roundDigits(a: std.mem.Allocator, d: Dec, keep: i64) !Dec {
    if (d.digits.len == 0) return d;
    if (keep >= @as(i64, @intCast(d.digits.len))) return d;
    if (keep < 0) return .{ .digits = "", .x = 0 };
    const k: usize = @intCast(keep);
    const first = d.digits[k] - '0';
    var tail_nonzero = false;
    for (d.digits[k + 1 ..]) |c| if (c != '0') {
        tail_nonzero = true;
    };
    const odd = k > 0 and (d.digits[k - 1] - '0') % 2 == 1;
    const up = first > 5 or (first == 5 and (tail_nonzero or odd));
    if (k == 0) return if (up) .{ .digits = "1", .x = d.x + 1 } else .{ .digits = "", .x = 0 };
    const out = try a.dupe(u8, d.digits[0..k]);
    if (up) {
        var i = k;
        while (i > 0) {
            i -= 1;
            if (out[i] == '9') {
                out[i] = '0';
            } else {
                out[i] += 1;
                return .{ .digits = out, .x = d.x };
            }
        }
        // 99…9 carried out of the top.
        out[0] = '1';
        return .{ .digits = out[0..1], .x = d.x + 1 };
    }
    return .{ .digits = out, .x = d.x };
}

fn digitAt(d: Dec, idx: i64) u8 {
    if (idx < 0 or idx >= d.digits.len) return '0';
    return d.digits[@intCast(idx)];
}

fn renderFixed(a: std.mem.Allocator, d: Dec, prec: usize, alt: bool) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    if (d.digits.len == 0 or d.x < 0) {
        try out.append(a, '0');
    } else {
        var i: i64 = 0;
        while (i <= d.x) : (i += 1) try out.append(a, digitAt(d, i));
    }
    if (prec > 0 or alt) try out.append(a, '.');
    var j: usize = 0;
    while (j < prec) : (j += 1) {
        const idx: i64 = @as(i64, d.x) + 1 + @as(i64, @intCast(j));
        try out.append(a, if (d.digits.len == 0) '0' else digitAt(d, idx));
    }
    return out.items;
}

fn renderSci(a: std.mem.Allocator, d: Dec, prec: usize, alt: bool, upper: bool) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.append(a, if (d.digits.len == 0) '0' else d.digits[0]);
    if (prec > 0 or alt) try out.append(a, '.');
    var j: usize = 0;
    while (j < prec) : (j += 1)
        try out.append(a, if (d.digits.len == 0) '0' else digitAt(d, @intCast(j + 1)));
    const x: i32 = if (d.digits.len == 0) 0 else d.x;
    try out.append(a, if (upper) 'E' else 'e');
    try out.append(a, if (x < 0) '-' else '+');
    const ax: u32 = @abs(x);
    if (ax < 10) try out.append(a, '0');
    var tmp: [12]u8 = undefined;
    try out.appendSlice(a, utoa(&tmp, ax, 10, false));
    return out.items;
}

/// `%e` / `%f` / `%g` body of a finite or special `f_abs >= 0` (no sign).
/// `conv` is lower-case `e`, `f` or `g`.
pub fn floatBody(a: std.mem.Allocator, f_abs: f64, conv: u8, prec: usize, alt: bool, upper: bool) Error![]const u8 {
    if (std.math.isNan(f_abs)) return if (upper) "NAN" else "nan";
    if (std.math.isInf(f_abs)) return if (upper) "INF" else "inf";
    if (prec > max_float_prec) return error.OutOfRange;
    const d = try exactDecimal(a, f_abs);
    switch (conv) {
        'f' => {
            const r = try roundDigits(a, d, @as(i64, d.x) + 1 + @as(i64, @intCast(prec)));
            return try renderFixed(a, r, prec, alt);
        },
        'e' => {
            const r = try roundDigits(a, d, @as(i64, @intCast(prec)) + 1);
            return try renderSci(a, r, prec, alt, upper);
        },
        else => {
            const p: usize = if (prec == 0) 1 else prec;
            const r = try roundDigits(a, d, @intCast(p));
            const x: i32 = if (r.digits.len == 0) 0 else r.x;
            var body: []u8 = undefined;
            if (x >= -4 and x < @as(i32, @intCast(p))) {
                body = try renderFixed(a, r, @intCast(@as(i32, @intCast(p)) - 1 - x), alt);
            } else {
                body = try renderSci(a, r, p - 1, alt, upper);
            }
            if (alt) return body;
            return try stripZeros(a, body);
        },
    }
}

/// `%g` drops trailing zeros of the mantissa (and a bare `.`), keeping any
/// exponent suffix.
fn stripZeros(a: std.mem.Allocator, body: []const u8) ![]const u8 {
    var e_at: usize = body.len;
    for (body, 0..) |c, i| if (c == 'e' or c == 'E') {
        e_at = i;
        break;
    };
    const dot = std.mem.findScalar(u8, body[0..e_at], '.') orelse return body;
    var end = e_at;
    while (end > dot + 1 and body[end - 1] == '0') end -= 1;
    if (end == dot + 1) end = dot;
    if (end == e_at) return body;
    return try std.mem.concat(a, u8, &.{ body[0..end], body[e_at..] });
}

fn utoa(buf: []u8, v_in: u64, base: u8, upper: bool) []const u8 {
    var v = v_in;
    var i: usize = buf.len;
    if (v == 0) {
        i -= 1;
        buf[i] = '0';
    }
    while (v > 0) {
        i -= 1;
        const dgt: u8 = @intCast(v % base);
        const letter: u8 = if (upper) 'A' else 'a';
        buf[i] = if (dgt < 10) '0' + dgt else letter + dgt - 10;
        v /= base;
    }
    return buf[i..];
}

// ── str % args ──────────────────────────────────────────────────────────────

const Spec = struct {
    left: bool = false,
    plus: bool = false,
    space: bool = false,
    zero: bool = false,
    alt: bool = false,
    width: usize = 0,
    prec: ?usize = null,
};

fn cpLen(s: []const u8) usize {
    return std.unicode.utf8CountCodepoints(s) catch s.len;
}

/// The byte length of the first `n` code points of `s`.
fn cpPrefix(s: []const u8, n: usize) usize {
    var i: usize = 0;
    var k: usize = 0;
    while (i < s.len and k < n) : (k += 1) {
        const l = std.unicode.utf8ByteSequenceLength(s[i]) catch 1;
        i += @min(l, s.len - i);
    }
    return i;
}

fn emit(a: std.mem.Allocator, out: *std.ArrayList(u8), spec: Spec, prefix: []const u8, body: []const u8, zero_ok: bool) Error!void {
    const len = cpLen(prefix) + cpLen(body);
    const pad = if (spec.width > len) spec.width - len else 0;
    if (out.items.len + len + pad > value.max_alloc) return error.OutOfRange;
    if (spec.left) {
        try out.appendSlice(a, prefix);
        try out.appendSlice(a, body);
        try out.appendNTimes(a, ' ', pad);
    } else if (spec.zero and zero_ok) {
        try out.appendSlice(a, prefix);
        try out.appendNTimes(a, '0', pad);
        try out.appendSlice(a, body);
    } else {
        try out.appendNTimes(a, ' ', pad);
        try out.appendSlice(a, prefix);
        try out.appendSlice(a, body);
    }
}

fn parseNum(fmt: []const u8, i: *usize) Error!usize {
    var n: usize = 0;
    while (i.* < fmt.len and fmt[i.*] >= '0' and fmt[i.*] <= '9') : (i.* += 1) {
        n = std.math.mul(usize, n, 10) catch return error.OutOfRange;
        n = std.math.add(usize, n, fmt[i.*] - '0') catch return error.OutOfRange;
        if (n > value.max_alloc) return error.OutOfRange;
    }
    return n;
}

const Source = struct {
    pos: []const Value,
    named: ?value.Map,
    next: usize = 0,
    mapping_taken: bool = false,

    fn take(self: *Source) Error!Value {
        if (self.named) |m| {
            // `'%s' % {…}` formats the mapping itself, once.
            if (self.mapping_taken) return error.BadArgument;
            self.mapping_taken = true;
            return .{ .map = m };
        }
        if (self.next >= self.pos.len) return error.BadArgument; // not enough arguments
        defer self.next += 1;
        return self.pos[self.next];
    }
};

fn intOfArg(v: Value, allow_float: bool) Error!i64 {
    return switch (v) {
        .integer => |i| i,
        .boolean => |b| @intFromBool(b),
        .float => |f| blk: {
            if (!allow_float) return error.TypeMismatch;
            if (!std.math.isFinite(f)) return error.BadArgument;
            const t = @trunc(f);
            if (t < -9223372036854775808.0 or t >= 9223372036854775808.0) return error.OutOfRange;
            break :blk @intFromFloat(t);
        },
        .undef => error.UndefinedValue,
        else => error.TypeMismatch,
    };
}

fn floatOfArg(v: Value) Error!f64 {
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .boolean => |b| if (b) 1.0 else 0.0,
        .float => |f| f,
        .undef => error.UndefinedValue,
        else => error.TypeMismatch,
    };
}

/// Python's `fmt % args` for the conversions `s r d i u x X o c e E f F g G %`,
/// flags `-+ 0#`, width/precision (also `*`), and `%(key)` lookups into
/// `named`. `markup` is `Markup.__mod__`: `%s`/`%r` operands are escaped
/// unless they already are markup. A conversion this engine does not
/// implement (`%a`) is `error.BadArgument`, as are too few or too many
/// arguments (`TypeError` in the reference).
pub fn percentFormat(
    a: std.mem.Allocator,
    fmt: []const u8,
    pos: []const Value,
    named: ?value.Map,
    markup: bool,
    strict: bool,
) Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var src: Source = .{ .pos = pos, .named = named };
    var i: usize = 0;
    while (i < fmt.len) {
        if (fmt[i] != '%') {
            var j = i;
            while (j < fmt.len and fmt[j] != '%') j += 1;
            if (out.items.len + (j - i) > value.max_alloc) return error.OutOfRange;
            try out.appendSlice(a, fmt[i..j]);
            i = j;
            continue;
        }
        i += 1;
        if (i >= fmt.len) return error.BadArgument; // incomplete format
        var spec: Spec = .{};
        var arg: ?Value = null;
        if (fmt[i] == '(') {
            var depth: usize = 1;
            var j = i + 1;
            while (j < fmt.len and depth > 0) : (j += 1) {
                if (fmt[j] == '(') depth += 1;
                if (fmt[j] == ')') depth -= 1;
            }
            if (depth != 0) return error.BadArgument;
            const key = fmt[i + 1 .. j - 1];
            const m = named orelse return error.BadArgument; // format requires a mapping
            arg = m.get(key) orelse return error.BadArgument; // KeyError
            i = j;
        }
        flags: while (i < fmt.len) : (i += 1) switch (fmt[i]) {
            '-' => spec.left = true,
            '+' => spec.plus = true,
            ' ' => spec.space = true,
            '0' => spec.zero = true,
            '#' => spec.alt = true,
            else => break :flags,
        };
        if (i < fmt.len and fmt[i] == '*') {
            const w = try intOfArg(try src.take(), false);
            if (w < 0) spec.left = true;
            spec.width = @intCast(@abs(w));
            if (spec.width > value.max_alloc) return error.OutOfRange;
            i += 1;
        } else spec.width = try parseNum(fmt, &i);
        if (i < fmt.len and fmt[i] == '.') {
            i += 1;
            if (i < fmt.len and fmt[i] == '*') {
                const p = try intOfArg(try src.take(), false);
                spec.prec = if (p < 0) 0 else @intCast(p);
                if (spec.prec.? > value.max_alloc) return error.OutOfRange;
                i += 1;
            } else spec.prec = try parseNum(fmt, &i);
        }
        while (i < fmt.len and (fmt[i] == 'h' or fmt[i] == 'l' or fmt[i] == 'L')) i += 1;
        if (i >= fmt.len) return error.BadArgument;
        const conv = fmt[i];
        i += 1;
        if (conv == '%') {
            try out.append(a, '%');
            continue;
        }
        const v = arg orelse try src.take();
        switch (conv) {
            's', 'r' => {
                if (v == .undef and strict) return error.UndefinedValue;
                var text: []const u8 = undefined;
                if (conv == 's') {
                    text = try value.strAlloc(a, v);
                    if (markup and !(v == .string and v.string.safe)) text = try value.escapeAlloc(a, text);
                } else {
                    var aw: std.Io.Writer.Allocating = .init(a);
                    try value.reprTo(&aw.writer, v);
                    text = aw.written();
                    if (markup) text = try value.escapeAlloc(a, text);
                }
                if (spec.prec) |p| text = text[0..cpPrefix(text, p)];
                try emit(a, &out, spec, "", text, false);
            },
            'c' => {
                var buf: [4]u8 = undefined;
                const text: []const u8 = switch (v) {
                    .string => |s| blk: {
                        if (cpLen(s.bytes) != 1) return error.TypeMismatch;
                        break :blk s.bytes;
                    },
                    else => blk: {
                        const n = try intOfArg(v, false);
                        if (n < 0 or n > 0x10ffff) return error.OutOfRange;
                        const cp: u21 = @intCast(n);
                        const l = std.unicode.utf8Encode(cp, &buf) catch return error.OutOfRange;
                        break :blk buf[0..l];
                    },
                };
                try emit(a, &out, spec, "", text, false);
            },
            'd', 'i', 'u', 'x', 'X', 'o' => {
                const n = try intOfArg(v, conv == 'd' or conv == 'i' or conv == 'u');
                const mag: u64 = @abs(n);
                var tmp: [72]u8 = undefined;
                const base: u8 = switch (conv) {
                    'x', 'X' => 16,
                    'o' => 8,
                    else => 10,
                };
                var digits: []const u8 = utoa(&tmp, mag, base, conv == 'X');
                if (spec.prec) |p| {
                    if (p > digits.len) {
                        const padded = try a.alloc(u8, p);
                        @memset(padded[0 .. p - digits.len], '0');
                        @memcpy(padded[p - digits.len ..], digits);
                        digits = padded;
                    }
                }
                var pre: std.ArrayList(u8) = .empty;
                if (n < 0) try pre.append(a, '-') else if (spec.plus) try pre.append(a, '+') else if (spec.space) try pre.append(a, ' ');
                if (spec.alt) switch (conv) {
                    'x' => try pre.appendSlice(a, "0x"),
                    'X' => try pre.appendSlice(a, "0X"),
                    'o' => try pre.appendSlice(a, "0o"),
                    else => {},
                };
                // A precision switches the `0` flag off, as in C and Python.
                try emit(a, &out, spec, pre.items, digits, spec.prec == null);
            },
            'e', 'E', 'f', 'F', 'g', 'G' => {
                const f = try floatOfArg(v);
                const lower: u8 = std.ascii.toLower(conv);
                const upper = conv == 'E' or conv == 'F' or conv == 'G';
                const neg = !std.math.isNan(f) and std.math.signbit(f);
                const body = try floatBody(a, @abs(f), lower, spec.prec orelse 6, spec.alt, upper);
                const sign: []const u8 = if (neg) "-" else if (spec.plus) "+" else if (spec.space) " " else "";
                try emit(a, &out, spec, sign, body, std.math.isFinite(f));
            },
            else => return error.BadArgument,
        }
    }
    // `'a' % (1, 2)` is a TypeError; a mapping or a lone mapping never is.
    if (named == null and src.next < pos.len) return error.BadArgument;
    return out.items;
}

// ── filesizeformat ──────────────────────────────────────────────────────────

/// Jinja2's `do_filesizeformat` for an already-converted number.
pub fn fileSize(a: std.mem.Allocator, bytes: f64, binary: bool) Error![]const u8 {
    if (bytes == 1) return "1 Byte";
    const base: u128 = if (binary) 1024 else 1000;
    const basef: f64 = @floatFromInt(base);
    if (bytes < basef) {
        if (!std.math.isFinite(bytes)) return error.BadArgument; // int(-inf)
        const t = @trunc(bytes);
        // Python prints an arbitrary-precision int here; `i64` cannot (D3).
        if (t < -9223372036854775808.0) return error.OutOfRange;
        var aw: std.Io.Writer.Allocating = .init(a);
        aw.writer.print("{d} Bytes", .{@as(i64, @intFromFloat(t))}) catch return error.OutOfMemory;
        return aw.written();
    }
    const prefixes = [_][2][]const u8{
        .{ "KiB", "kB" }, .{ "MiB", "MB" }, .{ "GiB", "GB" }, .{ "TiB", "TB" },
        .{ "PiB", "PB" }, .{ "EiB", "EB" }, .{ "ZiB", "ZB" }, .{ "YiB", "YB" },
    };
    var unit: f64 = 0;
    var pick: usize = prefixes.len - 1;
    var p: u128 = base;
    for (prefixes, 0..) |_, k| {
        p *= base;
        unit = @floatFromInt(p);
        pick = k;
        if (bytes < unit) break;
    }
    const scaled = basef * bytes / unit;
    const num = try floatBody(a, @abs(scaled), 'f', 1, false, false);
    var aw: std.Io.Writer.Allocating = .init(a);
    aw.writer.print("{s}{s} {s}", .{
        if (!std.math.isNan(scaled) and std.math.signbit(scaled)) "-" else "",
        num,
        prefixes[pick][if (binary) 0 else 1],
    }) catch return error.OutOfMemory;
    return aw.written();
}

// ── textwrap.wrap ───────────────────────────────────────────────────────────

const Chunk = struct { start: usize, end: usize };

fn isWrapWs(c: u21) bool {
    return switch (c) {
        '\t', '\n', 0x0b, 0x0c, '\r', ' ' => true,
        else => false,
    };
}
fn isWordCp(c: u21) bool {
    return c == '_' or ut.isAlnumCp(c);
}
fn isLetterCp(c: u21) bool {
    return isWordCp(c) and !ut.isDecimalCp(c);
}
fn isWordPunct(c: u21) bool {
    return isWordCp(c) or switch (c) {
        '!', '"', '\'', '&', '.', ',', '?' => true,
        else => false,
    };
}

/// `textwrap`'s `wordsep_re` split (`break_on_hyphens=True`), by hand.
fn splitHyphen(a: std.mem.Allocator, c: []const u21) ![]Chunk {
    var out: std.ArrayList(Chunk) = .empty;
    const n = c.len;
    var i: usize = 0;
    while (i < n) {
        if (isWrapWs(c[i])) {
            var j = i;
            while (j < n and isWrapWs(c[j])) j += 1;
            try out.append(a, .{ .start = i, .end = j });
            i = j;
            continue;
        }
        if (c[i] == '-' and i > 0 and isWordPunct(c[i - 1])) {
            var j = i;
            while (j < n and c[j] == '-') j += 1;
            if (j - i >= 2 and j < n and isWordCp(c[j])) {
                try out.append(a, .{ .start = i, .end = j });
                i = j;
                continue;
            }
        }
        var p = i + 1;
        while (true) {
            if (p >= n or isWrapWs(c[p])) {
                try out.append(a, .{ .start = i, .end = p });
                i = p;
                break;
            }
            if (c[p] == '-') {
                const behind = (p >= 2 and isLetterCp(c[p - 2]) and isLetterCp(c[p - 1])) or
                    (p >= 3 and isLetterCp(c[p - 3]) and c[p - 2] == '-' and isLetterCp(c[p - 1]));
                const ahead = (p + 2 < n and isLetterCp(c[p + 1]) and isLetterCp(c[p + 2])) or
                    (p + 3 < n and isLetterCp(c[p + 1]) and c[p + 2] == '-' and isLetterCp(c[p + 3]));
                if (behind and ahead) {
                    try out.append(a, .{ .start = i, .end = p + 1 });
                    i = p + 1;
                    break;
                }
                // em-dash run after a word-punctuation character
                if (isWordPunct(c[p - 1])) {
                    var j = p;
                    while (j < n and c[j] == '-') j += 1;
                    if (j - p >= 2 and j < n and isWordCp(c[j])) {
                        try out.append(a, .{ .start = i, .end = p });
                        i = p;
                        break;
                    }
                }
            }
            p += 1;
        }
    }
    return out.items;
}

fn splitSimple(a: std.mem.Allocator, c: []const u21) ![]Chunk {
    var out: std.ArrayList(Chunk) = .empty;
    var i: usize = 0;
    while (i < c.len) {
        const ws = isWrapWs(c[i]);
        var j = i;
        while (j < c.len and isWrapWs(c[j]) == ws) j += 1;
        try out.append(a, .{ .start = i, .end = j });
        i = j;
    }
    return out.items;
}

/// `str.strip() == ''` for the code points of a chunk (true when empty).
fn blankChunk(c: []const u21, ch: Chunk) bool {
    for (c[ch.start..ch.end]) |cp| if (!ut.isSpaceCp(cp)) return false;
    return true;
}

fn wrapLine(
    a: std.mem.Allocator,
    out: *std.ArrayList(u8),
    have_lines: *bool,
    line: []const u8,
    width: usize,
    break_long: bool,
    hyphens: bool,
    wrapstring: []const u8,
) Error!void {
    var cps: std.ArrayList(u21) = .empty;
    var off: std.ArrayList(usize) = .empty;
    var i: usize = 0;
    while (i < line.len) {
        try off.append(a, i);
        const l = std.unicode.utf8ByteSequenceLength(line[i]) catch 0;
        if (l != 0 and i + l <= line.len) {
            if (std.unicode.utf8Decode(line[i .. i + l])) |cp| {
                try cps.append(a, cp);
                i += l;
                continue;
            } else |_| {}
        }
        try cps.append(a, 0x110000); // an ill-formed byte: never a word, never space
        i += 1;
    }
    try off.append(a, line.len);
    const c = cps.items;
    const chunks = if (hyphens) try splitHyphen(a, c) else try splitSimple(a, c);

    var ci: usize = 0;
    var cur: std.ArrayList(Chunk) = .empty;
    while (ci < chunks.len) {
        cur.clearRetainingCapacity();
        var cur_len: usize = 0;
        if (have_lines.* and blankChunk(c, chunks[ci])) {
            ci += 1;
            if (ci >= chunks.len) break;
        }
        while (ci < chunks.len) {
            const l = chunks[ci].end - chunks[ci].start;
            if (cur_len + l <= width) {
                try cur.append(a, chunks[ci]);
                cur_len += l;
                ci += 1;
            } else break;
        }
        if (ci < chunks.len and chunks[ci].end - chunks[ci].start > width) {
            // `_handle_long_word`
            const space_left: usize = if (width < 1) 1 else width - cur_len;
            if (break_long) {
                const ch = chunks[ci];
                var end: usize = space_left;
                const clen = ch.end - ch.start;
                if (hyphens and clen > space_left) {
                    // rfind('-', 0, space_left)
                    var h: usize = space_left;
                    var found: ?usize = null;
                    while (h > 0) {
                        h -= 1;
                        if (c[ch.start + h] == '-') {
                            found = h;
                            break;
                        }
                    }
                    if (found) |hy| if (hy > 0) {
                        var other = false;
                        for (c[ch.start .. ch.start + hy]) |cp| if (cp != '-') {
                            other = true;
                        };
                        if (other) end = hy + 1;
                    };
                }
                end = @min(end, clen);
                try cur.append(a, .{ .start = ch.start, .end = ch.start + end });
                chunks[ci].start = ch.start + end;
            } else if (cur.items.len == 0) {
                try cur.append(a, chunks[ci]);
                ci += 1;
            }
        }
        if (cur.items.len != 0 and blankChunk(c, cur.items[cur.items.len - 1])) _ = cur.pop();
        if (cur.items.len != 0) {
            if (have_lines.*) {
                if (out.items.len + wrapstring.len > value.max_alloc) return error.OutOfRange;
                try out.appendSlice(a, wrapstring);
            }
            for (cur.items) |pc| {
                const piece = line[off.items[pc.start]..off.items[pc.end]];
                if (out.items.len + piece.len > value.max_alloc) return error.OutOfRange;
                try out.appendSlice(a, piece);
            }
            have_lines.* = true;
        }
    }
}

/// Python `str.splitlines()` boundaries on UTF-8 bytes.
fn nextLine(s: []const u8, start: usize) struct { end: usize, next: usize } {
    var i = start;
    while (i < s.len) {
        switch (s[i]) {
            '\n', 0x0b, 0x0c, 0x1c, 0x1d, 0x1e => return .{ .end = i, .next = i + 1 },
            '\r' => return .{ .end = i, .next = if (i + 1 < s.len and s[i + 1] == '\n') i + 2 else i + 1 },
            0xc2 => if (i + 1 < s.len and s[i + 1] == 0x85) return .{ .end = i, .next = i + 2 },
            0xe2 => if (i + 2 < s.len and s[i + 1] == 0x80 and (s[i + 2] == 0xa8 or s[i + 2] == 0xa9))
                return .{ .end = i, .next = i + 3 },
            else => {},
        }
        i += 1;
    }
    return .{ .end = s.len, .next = s.len };
}

/// Jinja2's `do_wordwrap`: `textwrap.wrap` per line of `s` (tabs kept,
/// whitespace not replaced), the wrapped lines joined by `wrapstring`.
/// `width < 1` is `error.BadArgument` (`ValueError` in `textwrap`).
pub fn wordwrap(
    a: std.mem.Allocator,
    s: []const u8,
    width: i64,
    break_long: bool,
    wrapstring: []const u8,
    hyphens: bool,
) Error![]const u8 {
    if (width < 1) return error.BadArgument;
    if (s.len > value.max_alloc) return error.OutOfRange;
    const w: usize = @intCast(width);
    var out: std.ArrayList(u8) = .empty;
    var first_source_line = true;
    var pos: usize = 0;
    while (pos < s.len) {
        const nl = nextLine(s, pos);
        // `wrapstring.join([…])`: a source line that wraps to nothing still
        // contributes an empty element, so the separator is emitted for it.
        if (!first_source_line) {
            if (out.items.len + wrapstring.len > value.max_alloc) return error.OutOfRange;
            try out.appendSlice(a, wrapstring);
        }
        first_source_line = false;
        var have_lines = false;
        try wrapLine(a, &out, &have_lines, s[pos..nl.end], w, break_long, hyphens, wrapstring);
        pos = nl.next;
    }
    return out.items;
}
