// SPDX-License-Identifier: MIT
//! The element functions `expr.zig` added after the move (survey rows 35-39, 92, 96):
//! rounding to decimals and significant figures, trigonometry and the other math,
//! bitwise integer functions, NaN tests, missing-aware equality, `is_close`, and the
//! plain string methods. Each cell function takes `Value`s and returns a `Value`; the
//! semantics are pandas' and polars' documented ones, the choice stated where they
//! differ. Text is handled as UTF-8 code points where it is valid UTF-8 and as bytes
//! where it is not (as `length` does); case functions are ASCII (survey row 93 is a
//! separate item). Original work of the zig-libs authors (MIT).

const std = @import("std");
const vm = @import("value.zig");
const keys = @import("keys.zig");
const Value = vm.Value;
const isMissing = keys.isMissing;

/// Most bytes one text function may build (`repeat`, `pad`, `zfill`): a width or count
/// is cell data, and past this the cell is `error.TooLarge`, not an allocation of
/// whatever a typo asked for.
pub const max_text_result: usize = 1 << 24;

pub const RoundMode = enum {
    /// Ties to the even neighbour (numpy and pandas; polars' default `half_to_even`).
    half_even,
    /// Ties away from zero (polars `mode="half_away_from_zero"`).
    half_away,
};

pub const PadSide = enum {
    /// Fill on the left (pandas `pad(side="left")`, `rjust`; polars `pad_start`).
    left,
    /// Fill on the right (pandas `ljust`; polars `pad_end`).
    right,
    /// Both sides (pandas `center`, Python's split of an odd fill).
    both,
};

pub const StripSide = enum { both, start, end };

// ── numbers ─────────────────────────────────────────────────────────────────

fn roundF(x: f64, mode: RoundMode) f64 {
    const r = @round(x); // half away from zero
    if (mode == .half_away or @abs(x - @trunc(x)) != 0.5) return r;
    return 2 * @round(x / 2);
}

fn pow10f(n: u32) f64 {
    return std.math.pow(f64, 10, @floatFromInt(n));
}

/// numpy's rounding (`round(x * 10^d) / 10^d`, the scale divided out for `d < 0`), the
/// scaling polars does too: `2.675` at 2 decimals is `2.68`, since `2.675 * 100` rounds
/// to the tie 267.5 (Python's correctly rounded `round` gives 2.67).
fn roundFloat(x: f64, d: i32, mode: RoundMode) f64 {
    if (!std.math.isFinite(x)) return x;
    if (d >= 0) {
        if (d > 330) return x;
        const p = pow10f(@intCast(d));
        const y = x * p;
        if (!std.math.isFinite(y)) return x;
        return roundF(y, mode) / p;
    }
    if (-d > 330) return std.math.copysign(@as(f64, 0), x);
    const p = pow10f(@intCast(-d));
    return roundF(x / p, mode) * p;
}

const pow10_i128 = blk: {
    var t: [39]i128 = undefined;
    t[0] = 1;
    for (1..39) |i| t[i] = t[i - 1] * 10;
    break :blk t;
};

/// `x` rounded to a multiple of `10^k` exactly; null when the result leaves `i128`.
fn roundExact(x: i128, k: u32, mode: RoundMode) ?i128 {
    if (k == 0) return x;
    if (k > 38) return 0;
    const p = pow10_i128[k];
    const q = @divFloor(x, p);
    const r = x - q * p; // 0 <= r < p
    const twice = @as(u128, @intCast(r)) * 2;
    const up = if (twice > @as(u128, @intCast(p)))
        true
    else if (twice < @as(u128, @intCast(p)))
        false
    else switch (mode) {
        .half_even => @mod(q, 2) != 0,
        .half_away => x >= 0, // q*p < x < (q+1)*p: away from zero is up when positive
    };
    const qq = if (up) std.math.add(i128, q, 1) catch return null else q;
    return std.math.mul(i128, qq, p) catch null;
}

/// pandas `round(decimals)`, polars `round(decimals, mode)`. An int stays an int (to
/// tens and up for `decimals < 0`), a decimal is rounded exactly at its scale, a float
/// as numpy does; a negative `decimals` rounds left of the point.
pub fn round(v: Value, decimals: i32, mode: RoundMode) Value {
    switch (v) {
        .int => |i| {
            if (decimals >= 0) return v;
            const r = roundExact(i, @intCast(@min(-@as(i64, decimals), 39)), mode) orelse return .null;
            return if (std.math.cast(i64, r)) |x| .{ .int = x } else .null;
        },
        .decimal => |raw| {
            const scale_digits: i64 = 12;
            const k = scale_digits - decimals;
            if (k <= 0) return v;
            return if (roundExact(raw, @intCast(@min(k, 39)), mode)) |r| .{ .decimal = r } else .null;
        },
        .float => |x| return .{ .float = roundFloat(x, decimals, mode) },
        else => return .null,
    }
}

/// polars `round_sig_figs(digits)`: `digits` significant digits, ties to even. Zero
/// stays zero; an int stays an int. `digits = 0` is refused by the compiler.
pub fn roundSigFigs(v: Value, digits: u32) Value {
    const x = v.asFloat() orelse return .null;
    if (x == 0 or !std.math.isFinite(x)) return v;
    const mag: i64 = @intFromFloat(@floor(std.math.log10(@abs(x))));
    const d64 = @as(i64, digits) - 1 - mag;
    const d: i32 = @intCast(std.math.clamp(d64, -400, 400));
    return round(v, d, .half_even);
}

/// The error function, to about 1e-15: its Maclaurin series below 2 and the
/// continued fraction of `erfc` above (Lentz), 1 past 6. `std.math` has no `erf`.
pub fn erf(x: f64) f64 {
    if (std.math.isNan(x)) return x;
    const ax = @abs(x);
    var r: f64 = undefined;
    if (ax < 2.0) {
        const x2 = ax * ax;
        var term = ax;
        var sum = ax;
        var n: f64 = 0;
        while (n < 200) {
            n += 1;
            term *= -x2 / n;
            const t = term / (2 * n + 1);
            sum += t;
            if (@abs(t) < 1e-17 * @abs(sum)) break;
        }
        r = sum * 2 / @sqrt(std.math.pi);
    } else if (ax < 6.0) {
        // erfc x = exp(-x^2) / sqrt(pi) / (x + (1/2)/(x + 1/(x + (3/2)/(x + ...)))).
        const tiny = 1e-300;
        var f: f64 = ax;
        var c: f64 = ax;
        var dd: f64 = 0;
        var k: f64 = 1;
        while (k < 500) : (k += 1) {
            const an = k / 2;
            dd = ax + an * dd;
            if (@abs(dd) < tiny) dd = tiny;
            c = ax + an / c;
            if (@abs(c) < tiny) c = tiny;
            dd = 1 / dd;
            const delta = c * dd;
            f *= delta;
            if (@abs(delta - 1) < 1e-16) break;
        }
        r = 1 - @exp(-ax * ax) / @sqrt(std.math.pi) / f;
    } else r = 1;
    return if (x < 0) -r else r;
}

/// polars `is_close`: `|x - y| <= max(rel_tol * max(|x|, |y|), abs_tol)`, equal
/// infinities close; a NaN is close to nothing unless `nans_equal` and both are NaN.
/// Null or a non-number: null.
pub fn isClose(l: Value, r: Value, rel_tol: f64, abs_tol: f64, nans_equal: bool) Value {
    if (l == .null or r == .null) return .null;
    const x = l.asFloat() orelse return .null;
    const y = r.asFloat() orelse return .null;
    const xn = std.math.isNan(x);
    const yn = std.math.isNan(y);
    if (xn or yn) return .{ .bool = nans_equal and xn and yn };
    if (x == y) return .{ .bool = true };
    if (std.math.isInf(x) or std.math.isInf(y)) return .{ .bool = false };
    return .{ .bool = @abs(x - y) <= @max(rel_tol * @max(@abs(x), @abs(y)), abs_tol) };
}

/// Missing-aware equality (polars `eq_missing`): two missing cells are equal, a
/// missing and a present one are not, numbers by value, text and bool by kind; any
/// other pair is not equal (never null).
pub fn eqMissing(l: Value, r: Value) bool {
    const lm = isMissing(l);
    const rm = isMissing(r);
    if (lm or rm) return lm and rm;
    const ln = l == .int or l == .float or l == .decimal;
    const rn = r == .int or r == .float or r == .decimal;
    if (ln != rn) return false;
    if (!ln and std.meta.activeTag(l) != std.meta.activeTag(r)) return false;
    return l.order(r) == .eq;
}

// ── text ────────────────────────────────────────────────────────────────────

/// Byte offset of each character's start, and the end: code points for valid UTF-8,
/// bytes otherwise.
pub fn charStarts(a: std.mem.Allocator, t: []const u8) error{OutOfMemory}![]usize {
    var out: std.ArrayList(usize) = .empty;
    try out.ensureTotalCapacity(a, t.len + 1);
    if (std.unicode.utf8ValidateSlice(t)) {
        var i: usize = 0;
        while (i < t.len) {
            out.appendAssumeCapacity(i);
            i += std.unicode.utf8ByteSequenceLength(t[i]) catch 1;
        }
    } else {
        for (0..t.len) |i| out.appendAssumeCapacity(i);
    }
    out.appendAssumeCapacity(t.len);
    return out.items;
}

fn charCount(t: []const u8) usize {
    return std.unicode.utf8CountCodepoints(t) catch t.len;
}

/// Characters `offset ..` for `length` of them (polars `str.slice`): a negative offset
/// counts from the end, null length runs to the end; a range past either end is cut.
pub fn slice(a: std.mem.Allocator, t: []const u8, offset: i64, length: ?usize) error{OutOfMemory}![]const u8 {
    const st = try charStarts(a, t);
    defer a.free(st);
    const n: i64 = @intCast(st.len - 1);
    var lo: i64 = if (offset < 0) n + offset else offset;
    if (lo < 0) lo = 0;
    if (lo > n) lo = n;
    const avail: usize = @intCast(n - lo);
    const want = if (length) |l| @min(l, avail) else avail;
    const s: usize = @intCast(lo);
    return t[st[s]..st[s + want]];
}

/// polars `str.head(n)`: the first `n` characters; a negative `n` all but the last `-n`.
pub fn head(a: std.mem.Allocator, t: []const u8, n: i64) error{OutOfMemory}![]const u8 {
    if (n >= 0) return slice(a, t, 0, @intCast(n));
    const c: i64 = @intCast(charCount(t));
    return slice(a, t, 0, @intCast(@max(c + n, 0)));
}

/// polars `str.tail(n)`: the last `n` characters; a negative `n` all but the first `-n`.
pub fn tail(a: std.mem.Allocator, t: []const u8, n: i64) error{OutOfMemory}![]const u8 {
    const c: i64 = @intCast(charCount(t));
    if (n >= 0) return slice(a, t, @max(c - n, 0), null);
    return slice(a, t, @min(-n, c), null);
}

/// pandas `str.get(i)`: the character at `i`, a negative one from the end; out of
/// range null.
pub fn charAt(a: std.mem.Allocator, t: []const u8, i: i64) error{OutOfMemory}!?[]const u8 {
    const st = try charStarts(a, t);
    defer a.free(st);
    const n: i64 = @intCast(st.len - 1);
    const k = if (i < 0) n + i else i;
    if (k < 0 or k >= n) return null;
    const u: usize = @intCast(k);
    return t[st[u]..st[u + 1]];
}

pub fn reverse(a: std.mem.Allocator, t: []const u8) error{OutOfMemory}![]const u8 {
    const st = try charStarts(a, t);
    defer a.free(st);
    const out = try a.alloc(u8, t.len);
    var at: usize = 0;
    var k = st.len - 1;
    while (k > 0) : (k -= 1) {
        const piece = t[st[k - 1]..st[k]];
        @memcpy(out[at..][0..piece.len], piece);
        at += piece.len;
    }
    return out;
}

fn encodeFill(fill: u21, buf: *[4]u8) error{TooLarge}![]const u8 {
    const n = std.unicode.utf8Encode(fill, buf) catch return error.TooLarge;
    return buf[0..n];
}

/// Fill to `width` characters with `fill` (pandas `pad`/`ljust`/`rjust`/`center`,
/// polars `pad_start`/`pad_end`). A text already that wide is unchanged. `both` splits
/// as CPython's `center`: the odd character goes left when `width` is odd.
pub fn pad(a: std.mem.Allocator, t: []const u8, width: usize, side: PadSide, fill: u21) error{ OutOfMemory, TooLarge }![]const u8 {
    const n = charCount(t);
    if (n >= width) return t;
    var fb: [4]u8 = undefined;
    const f = try encodeFill(fill, &fb);
    const marg = width - n;
    const total = std.math.add(usize, t.len, std.math.mul(usize, marg, f.len) catch return error.TooLarge) catch return error.TooLarge;
    if (total > max_text_result) return error.TooLarge;
    const left: usize = switch (side) {
        .left => marg,
        .right => 0,
        .both => marg / 2 + (marg & width & 1),
    };
    const out = try a.alloc(u8, total);
    var at: usize = 0;
    for (0..left) |_| {
        @memcpy(out[at..][0..f.len], f);
        at += f.len;
    }
    @memcpy(out[at..][0..t.len], t);
    at += t.len;
    while (at < total) {
        @memcpy(out[at..][0..f.len], f);
        at += f.len;
    }
    return out;
}

/// pandas `str.zfill(width)`, polars `zfill`: zeros on the left to `width` characters,
/// after a leading `+` or `-`.
pub fn zfill(a: std.mem.Allocator, t: []const u8, width: i64) error{ OutOfMemory, TooLarge }![]const u8 {
    if (width <= 0) return t;
    const w: usize = std.math.cast(usize, width) orelse return error.TooLarge;
    const n = charCount(t);
    if (n >= w) return t;
    if (w - n > max_text_result) return error.TooLarge;
    const signed = t.len > 0 and (t[0] == '+' or t[0] == '-');
    const out = try a.alloc(u8, t.len + (w - n));
    var at: usize = 0;
    if (signed) {
        out[0] = t[0];
        at = 1;
    }
    @memset(out[at..][0 .. w - n], '0');
    at += w - n;
    const rest = if (signed) t[1..] else t;
    @memcpy(out[at..][0..rest.len], rest);
    return out;
}

/// Python's `str * n`: `n <= 0` is empty.
pub fn repeat(a: std.mem.Allocator, t: []const u8, n: i64) error{ OutOfMemory, TooLarge }![]const u8 {
    if (n <= 0) return "";
    const k: usize = std.math.cast(usize, n) orelse return error.TooLarge;
    const total = std.math.mul(usize, t.len, k) catch return error.TooLarge;
    if (total > max_text_result) return error.TooLarge;
    const out = try a.alloc(u8, total);
    for (0..k) |i| @memcpy(out[i * t.len ..][0..t.len], t);
    return out;
}

fn decodeAt(t: []const u8, i: usize, valid: bool) struct { cp: u21, len: usize } {
    if (!valid) return .{ .cp = t[i], .len = 1 };
    const l = std.unicode.utf8ByteSequenceLength(t[i]) catch return .{ .cp = t[i], .len = 1 };
    const cp = std.unicode.utf8Decode(t[i..][0..l]) catch return .{ .cp = t[i], .len = 1 };
    return .{ .cp = cp, .len = l };
}

fn inSet(set: []const u8, cp: u21) bool {
    const valid = std.unicode.utf8ValidateSlice(set);
    var i: usize = 0;
    while (i < set.len) {
        const d = decodeAt(set, i, valid);
        if (d.cp == cp) return true;
        i += d.len;
    }
    return false;
}

const whitespace = " \t\r\n\x0b\x0c";

/// Strip the characters of `chars` (whitespace when null) from `side` (pandas
/// `strip(to_strip)`/`lstrip`/`rstrip`, polars `strip_chars`/`_start`/`_end`).
pub fn stripChars(t: []const u8, chars: ?[]const u8, side: StripSide) []const u8 {
    const set = chars orelse whitespace;
    const valid = std.unicode.utf8ValidateSlice(t);
    var lo: usize = 0;
    var hi: usize = t.len;
    if (side != .end) {
        while (lo < hi) {
            const d = decodeAt(t, lo, valid);
            if (!inSet(set, d.cp)) break;
            lo += d.len;
        }
    }
    if (side != .start) {
        while (hi > lo) {
            // The start of the last character before `hi`.
            var s = hi - 1;
            if (valid) {
                while (s > lo and t[s] & 0xC0 == 0x80) s -= 1;
            }
            const d = decodeAt(t, s, valid);
            if (!inSet(set, d.cp)) break;
            hi = s;
        }
    }
    return t[lo..hi];
}

/// pandas `str.translate`: each character of `from` becomes the one at the same
/// position of `to`, each of `delete` goes. The compiler checks the counts agree.
pub fn translate(a: std.mem.Allocator, t: []const u8, from: []const u8, to: []const u8, delete: []const u8) error{OutOfMemory}![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.ensureTotalCapacity(a, t.len);
    const valid = std.unicode.utf8ValidateSlice(t);
    const fs = try charStarts(a, from);
    defer a.free(fs);
    const ts = try charStarts(a, to);
    defer a.free(ts);
    var i: usize = 0;
    while (i < t.len) {
        const d = decodeAt(t, i, valid);
        const piece = t[i..][0..d.len];
        i += d.len;
        if (inSet(delete, d.cp)) continue;
        var mapped: ?[]const u8 = null;
        const fvalid = std.unicode.utf8ValidateSlice(from);
        for (0..fs.len - 1) |k| {
            if (decodeAt(from, fs[k], fvalid).cp == d.cp) {
                mapped = to[ts[k]..ts[k + 1]];
                break;
            }
        }
        try out.appendSlice(a, mapped orelse piece);
    }
    return out.items;
}

pub fn charCountOf(t: []const u8) usize {
    return charCount(t);
}

/// polars `str.to_integer(base)`: an optional sign and digits of `base` (2 to 36, any
/// case), nothing else; overflow or anything else null.
pub fn toInteger(t: []const u8, base: u8) Value {
    if (t.len == 0) return .null;
    // `parseInt` also takes `_` separators and a `0x` prefix with base 0; neither is
    // a digit here.
    for (t, 0..) |c, i| {
        if ((c == '+' or c == '-') and i == 0) continue;
        if (!std.ascii.isAlphanumeric(c)) return .null;
    }
    return if (std.fmt.parseInt(i64, t, base)) |x| .{ .int = x } else |_| .null;
}

/// Python's `capitalize` over ASCII: the first character upper, the rest lower.
pub fn capitalize(a: std.mem.Allocator, t: []const u8) error{OutOfMemory}![]const u8 {
    const out = try std.ascii.allocLowerString(a, t);
    if (out.len > 0) out[0] = std.ascii.toUpper(out[0]);
    return out;
}

/// Python's `title` over ASCII: a letter after a non-letter upper, other letters lower.
pub fn title(a: std.mem.Allocator, t: []const u8) error{OutOfMemory}![]const u8 {
    const out = try a.dupe(u8, t);
    var prev_cased = false;
    for (out) |*c| {
        if (std.ascii.isAlphabetic(c.*)) {
            c.* = if (prev_cased) std.ascii.toLower(c.*) else std.ascii.toUpper(c.*);
            prev_cased = true;
        } else prev_cased = false;
    }
    return out;
}

pub fn swapcase(a: std.mem.Allocator, t: []const u8) error{OutOfMemory}![]const u8 {
    const out = try a.dupe(u8, t);
    for (out) |*c| {
        if (std.ascii.isUpper(c.*)) c.* = std.ascii.toLower(c.*) else if (std.ascii.isLower(c.*)) c.* = std.ascii.toUpper(c.*);
    }
    return out;
}

pub const CharClass = enum { alpha, digit, alnum, space, lower, upper, title };

/// Python's `isalpha` … `istitle` over ASCII (pandas `str.isalpha` …): false for the
/// empty text and for any byte past ASCII. `lower`/`upper` need at least one cased
/// character and no character of the other case; `title` Python's `istitle`.
pub fn isClass(t: []const u8, class: CharClass) bool {
    if (t.len == 0) return false;
    for (t) |c| if (c >= 0x80) return false;
    switch (class) {
        .alpha => for (t) |c| {
            if (!std.ascii.isAlphabetic(c)) return false;
        },
        .digit => for (t) |c| {
            if (!std.ascii.isDigit(c)) return false;
        },
        .alnum => for (t) |c| {
            if (!std.ascii.isAlphanumeric(c)) return false;
        },
        .space => for (t) |c| {
            if (std.mem.findScalar(u8, whitespace, c) == null and c != 0x1c and c != 0x1d and c != 0x1e and c != 0x1f) return false;
        },
        .lower, .upper => {
            var cased = false;
            for (t) |c| {
                if (class == .lower and std.ascii.isUpper(c)) return false;
                if (class == .upper and std.ascii.isLower(c)) return false;
                cased = cased or std.ascii.isAlphabetic(c);
            }
            return cased;
        },
        .title => {
            var cased = false;
            var prev_cased = false;
            for (t) |c| {
                if (std.ascii.isUpper(c)) {
                    if (prev_cased) return false;
                    prev_cased = true;
                    cased = true;
                } else if (std.ascii.isLower(c)) {
                    if (!prev_cased) return false;
                    prev_cased = true;
                    cased = true;
                } else prev_cased = false;
            }
            return cased;
        },
    }
    return true;
}

fn eqFold(x: []const u8, y: []const u8, fold: bool) bool {
    return if (fold) std.ascii.eqlIgnoreCase(x, y) else std.mem.eql(u8, x, y);
}

/// polars `str.contains_any(patterns, ascii_case_insensitive)`: some pattern occurs.
pub fn containsAny(t: []const u8, patterns: []const []const u8, fold: bool) bool {
    for (patterns) |p| {
        if (p.len == 0) return true;
        if (p.len > t.len) continue;
        var i: usize = 0;
        while (i + p.len <= t.len) : (i += 1) {
            if (eqFold(t[i..][0..p.len], p, fold)) return true;
        }
    }
    return false;
}

/// polars `str.replace_many(patterns, replace_with)`: leftmost-first, non-overlapping,
/// as its Aho-Corasick does; `with` has one entry for every pattern or one for all. An
/// empty pattern is refused by the compiler.
pub fn replaceMany(a: std.mem.Allocator, t: []const u8, patterns: []const []const u8, with: []const []const u8, fold: bool) error{ OutOfMemory, TooLarge }![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < t.len) {
        var hit: ?usize = null;
        for (patterns, 0..) |p, k| {
            if (p.len <= t.len - i and eqFold(t[i..][0..p.len], p, fold)) {
                hit = k;
                break;
            }
        }
        if (hit) |k| {
            try out.appendSlice(a, if (with.len == 1) with[0] else with[k]);
            i += patterns[k].len;
        } else {
            try out.append(a, t[i]);
            i += 1;
        }
        if (out.items.len > max_text_result) return error.TooLarge;
    }
    return out.items;
}

/// Non-overlapping occurrences of `p` (Python's `count`; an empty `p` matches between
/// every two characters and at both ends).
pub fn countMatches(t: []const u8, p: []const u8) usize {
    if (p.len == 0) return charCount(t) + 1;
    return std.mem.count(u8, t, p);
}
