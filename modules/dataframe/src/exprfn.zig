// SPDX-License-Identifier: MIT
//! The element functions `expr.zig` added after the move (survey rows 35-39, 92, 96):
//! rounding to decimals and significant figures, trigonometry and the other math,
//! bitwise integer functions, NaN tests, missing-aware equality, `is_close`, and the
//! plain string methods. Each cell function takes `Value`s and returns a `Value`; the
//! semantics are pandas' and polars' documented ones, the choice stated where they
//! differ. Text is handled as UTF-8 code points where it is valid UTF-8 and as bytes
//! where it is not (as `length` does). Case mapping, `normalize`, `unaccent` and the `is*`
//! classes are Unicode (the `unitext` module: CPython's `str`, which pandas calls, and
//! Rust's `to_lowercase`, which polars calls); a cell that is not valid UTF-8 has no code
//! points to map, so it is treated as bytes, once and for the whole module: the case
//! functions change its ASCII letters only, `normalize`/`unaccent` return it unchanged, and
//! every `is*` class is false. Original work of the zig-libs authors (MIT).

const std = @import("std");
const vm = @import("value.zig");
const keys = @import("keys.zig");
const ut = @import("unitext");
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
    /// Toward zero, whatever the dropped digits (a truncation at `decimals`, as numpy's
    /// `trunc` scaled; neither pandas nor polars has a `decimals` argument for it).
    toward_zero,
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
    if (mode == .toward_zero) return @trunc(x);
    const r = @round(x); // half away from zero
    if (mode == .half_away or @abs(x - @trunc(x)) != 0.5) return r;
    return 2 * @round(x / 2);
}

/// `10^n` correctly rounded, as Python's `10.0 ** n` that numpy's `round` scales by:
/// `std.math.pow` multiplies its way there and is off by ulps above 1e22
/// (1e308 came out 1.0000000000000006e308; review 2026-11-07). Past 1e308: inf.
fn pow10f(n: u32) f64 {
    return if (n < pow10_f64.len) pow10_f64[n] else std.math.inf(f64);
}

const pow10_f64 = blk: {
    @setEvalBranchQuota(400_000);
    var t: [309]f64 = undefined;
    for (&t, 0..) |*p, i| p.* = std.fmt.parseFloat(f64, std.fmt.comptimePrint("1e{d}", .{i})) catch unreachable;
    break :blk t;
};

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
    // `d < -308`, not `-d > 330`: negating minInt(i32) traps, and past 1e308
    // `p` is inf and `0 * inf` NaN (review 2026-11-07, HIGH 1).
    if (d < -308) return std.math.copysign(@as(f64, 0), x);
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
    if (mode == .toward_zero) return @divTrunc(x, p) * p; // |result| <= |x|: no overflow
    const q = @divFloor(x, p);
    // `@mod`, not `x - q * p`: near minInt(i128) `q * p` leaves i128 (review
    // 2026-11-07, MED 4); the result is formed with checked arithmetic below.
    const r = @mod(x, p); // 0 <= r < p
    const twice = @as(u128, @intCast(r)) * 2;
    const up = if (twice > @as(u128, @intCast(p)))
        true
    else if (twice < @as(u128, @intCast(p)))
        false
    else switch (mode) {
        .half_even => @mod(q, 2) != 0,
        .toward_zero => false, // returned above; never reached
        .half_away => x >= 0, // q*p < x < (q+1)*p: away from zero is up when positive
    };
    return if (up)
        std.math.add(i128, x, p - r) catch null
    else
        std.math.sub(i128, x, r) catch null;
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

/// polars `round_sig_figs(digits)`: `digits` significant digits, ties away from zero
/// (measured: 2.5 to one digit is 3, 25 is 30; `round` is the one that goes to even). Zero
/// stays zero; an int stays an int. `digits = 0` is refused by the compiler.
pub fn roundSigFigs(v: Value, digits: u32) Value {
    const x = v.asFloat() orelse return .null;
    if (x == 0 or !std.math.isFinite(x)) return v;
    const mag: i64 = @intFromFloat(@floor(std.math.log10(@abs(x))));
    const d64 = @as(i64, digits) - 1 - mag;
    const d: i32 = @intCast(std.math.clamp(d64, -400, 400));
    return round(v, d, .half_away);
}

/// Rust `regex::escape`: a backslash before each of `\ . + * ? ( ) | [ ] { } ^ $ # & - ~`.
/// More than `max_text_result` bytes out is `error.TooLarge`.
pub fn escapeRegex(a: std.mem.Allocator, t: []const u8) error{ OutOfMemory, TooLarge }![]const u8 {
    const meta = "\\.+*?()|[]{}^$#&-~";
    var extra: usize = 0;
    for (t) |c| extra += @intFromBool(std.mem.findScalar(u8, meta, c) != null);
    if (t.len + extra > max_text_result) return error.TooLarge;
    const out = try a.alloc(u8, t.len + extra);
    var i: usize = 0;
    for (t) |c| {
        if (std.mem.findScalar(u8, meta, c) != null) {
            out[i] = '\\';
            i += 1;
        }
        out[i] = c;
        i += 1;
    }
    return out;
}

/// The error function, to about 1e-15: its Maclaurin series below 2 and the
/// continued fraction of `erfc` above (Lentz), 1 past 6. `std.math` has no `erf`.
pub fn erf(x: f64) f64 {
    if (std.math.isNan(x)) return x;
    const ax = @abs(x);
    const r: f64 = if (ax < 2.0) erfSeries(ax) else if (ax < 6.0) 1 - erfcFraction(ax) else 1;
    return if (x < 0) -r else r;
}

/// `erf x` for `0 <= x < 2`: the Maclaurin series.
fn erfSeries(ax: f64) f64 {
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
    return sum * 2 / @sqrt(std.math.pi);
}

/// `erfc x` for `x >= 2`: exp(-x^2) / sqrt(pi) / (x + (1/2)/(x + 1/(x + (3/2)/(x + ...)))).
fn erfcFraction(ax: f64) f64 {
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
    return @exp(-ax * ax) / @sqrt(std.math.pi) / f;
}

/// The complementary error function `1 - erf x`, scipy's `erfc`, to about 1e-15 relative
/// error also in the tail (where `1 - erf x` would lose every digit): underflows to 0 past
/// x = 27, is 2 for large negative x. `std.math` has no `erfc`.
pub fn erfc(x: f64) f64 {
    if (std.math.isNan(x)) return x;
    const ax = @abs(x);
    const r: f64 = if (ax < 2.0) 1 - erfSeries(ax) else if (ax < 27.0) erfcFraction(ax) else 0;
    return if (x < 0) 2 - r else r;
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
    // Owned, so `free` gets the length it was given (the capacity was the byte count; a
    // shorter slice freed under `expr`'s budget drifted its count, review R2 L3).
    return out.toOwnedSlice(a);
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
    // The window is cut after it is placed: a start before the first character shortens
    // it (polars: `slice(-3, 2)` of "a" is empty, the window being characters -2 and -1).
    const lo_raw: i64 = if (offset < 0) n + offset else offset;
    const hi_raw: i64 = if (length) |l| lo_raw +| @as(i64, @intCast(@min(l, std.math.maxInt(i64)))) else n;
    const lo = std.math.clamp(lo_raw, 0, n);
    const hi = std.math.clamp(hi_raw, lo, n);
    return t[st[@intCast(lo)]..st[@intCast(hi)]];
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
    // `-n` of minInt(i64) does not fit: that skips everything anyway.
    return slice(a, t, if (n == std.math.minInt(i64)) c else @min(-n, c), null);
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
    if (n <= 0 or t.len == 0) return ""; // "" * 2^63 is "", not 2^63 empty copies (review 2026-11-07, HIGH 3)
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

/// The characters a null `chars` strips. A valid UTF-8 cell: Python's `str.isspace`
/// (`unitext.isSpaceCp`, pandas `strip()`; polars' White_Space is the same except U+001C..U+001F,
/// which only Python counts). An ill-formed cell is bytes: the six ASCII whitespace bytes.
fn isStripSpace(cp: u21, valid: bool) bool {
    if (valid) return ut.isSpaceCp(cp);
    return cp < 0x80 and std.mem.findScalar(u8, whitespace, @intCast(cp)) != null;
}

/// Strip the characters of `chars` (Unicode whitespace when null, see `isStripSpace`) from `side`
/// (pandas `strip(to_strip)`/`lstrip`/`rstrip`, polars `strip_chars`/`_start`/`_end`). Explicit
/// `chars` is a set of characters, matched exactly.
pub fn stripChars(t: []const u8, chars: ?[]const u8, side: StripSide) []const u8 {
    const set = chars orelse "";
    const valid = std.unicode.utf8ValidateSlice(t);
    var lo: usize = 0;
    var hi: usize = t.len;
    if (side != .end) {
        while (lo < hi) {
            const d = decodeAt(t, lo, valid);
            if (!(if (chars == null) isStripSpace(d.cp, valid) else inSet(set, d.cp))) break;
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
            if (!(if (chars == null) isStripSpace(d.cp, valid) else inSet(set, d.cp))) break;
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

/// The Unicode normalization forms of `normalize` (`unitext.Form`: `.nfc`, `.nfd`, `.nfkc`, `.nfkd`).
pub const NormalForm = ut.Form;

/// The options of every `unitext` call: ill-formed input never reaches it (each caller
/// checks `validUtf8` first and takes the byte path), the output is capped like `pad`.
const ut_opts: ut.Options = .{ .invalid_utf8 = .reject, .max_output = max_text_result };

fn validUtf8(t: []const u8) bool {
    return std.unicode.utf8ValidateSlice(t);
}

fn isAsciiText(t: []const u8) bool {
    for (t) |c| if (c >= 0x80) return false;
    return true;
}

/// pandas `str.lower` / Python `str.lower` and polars `to_lowercase` (Rust): the full
/// Unicode lower-case mapping, final sigma included (`ΣΑΣ` is `σας`). The two engines
/// agree; Turkish `İ` becomes `i̇` (i + U+0307) in both. A cell that is not valid UTF-8
/// has its ASCII letters lowered and the other bytes kept.
pub fn lower(a: std.mem.Allocator, t: []const u8) error{ OutOfMemory, TooLarge }![]const u8 {
    if (isAsciiText(t) or !validUtf8(t)) return std.ascii.allocLowerString(a, t);
    return ut.lower(a, t, ut_opts) catch |e| switch (e) {
        error.InvalidUtf8 => try std.ascii.allocLowerString(a, t),
        else => |x| return x,
    };
}

/// pandas `str.upper` / Python `str.upper` and polars `to_uppercase`: the full Unicode
/// upper-case mapping (`ß` is `SS`, `ŉ` is `ʼN`); the engines agree. Not valid UTF-8:
/// the ASCII letters only.
pub fn upper(a: std.mem.Allocator, t: []const u8) error{ OutOfMemory, TooLarge }![]const u8 {
    if (isAsciiText(t) or !validUtf8(t)) return std.ascii.allocUpperString(a, t);
    return ut.upper(a, t, ut_opts) catch |e| switch (e) {
        error.InvalidUtf8 => try std.ascii.allocUpperString(a, t),
        else => |x| return x,
    };
}

/// pandas `str.casefold` / Python `str.casefold` (full case folding: `ß` is `ss`, final
/// sigma `ς` is `σ`). polars has no `casefold`; `to_lowercase` is the nearest and differs
/// on exactly those letters. Not valid UTF-8: ASCII lower case.
pub fn casefold(a: std.mem.Allocator, t: []const u8) error{ OutOfMemory, TooLarge }![]const u8 {
    if (isAsciiText(t) or !validUtf8(t)) return std.ascii.allocLowerString(a, t);
    return ut.casefold(a, t, ut_opts) catch |e| switch (e) {
        error.InvalidUtf8 => try std.ascii.allocLowerString(a, t),
        else => |x| return x,
    };
}

/// pandas `str.normalize(form)` / Python `unicodedata.normalize`. polars has no
/// `normalize` in `str` (its `unicode-normalization` feature is in `polars-plan` as
/// `str.normalize` only from some versions; the pandas answer is the reference). Not valid
/// UTF-8: the cell is returned unchanged.
pub fn normalize(a: std.mem.Allocator, t: []const u8, form: ut.Form) error{ OutOfMemory, TooLarge }![]const u8 {
    if (isAsciiText(t) or !validUtf8(t)) return t;
    return ut.normalize(a, t, form, ut_opts) catch |e| switch (e) {
        error.InvalidUtf8 => t,
        else => |x| return x,
    };
}

/// Accent folding (`unitext.unaccent`: NFD, drop every nonspacing mark, NFC, plus `ł`
/// to `l`, `ß` to `ss`, `æ` to `ae`, ...). Neither pandas nor polars has it built in; the
/// pandas recipe is `str.normalize("NFKD")` then dropping the combining marks (scikit-learn's
/// `strip_accents_unicode`), which leaves `ł`, `ß` and `æ` alone and also folds
/// compatibility forms (`ﬁ`, `²`), so the two differ there. Not valid UTF-8: unchanged.
pub fn unaccent(a: std.mem.Allocator, t: []const u8) error{ OutOfMemory, TooLarge }![]const u8 {
    if (isAsciiText(t) or !validUtf8(t)) return t;
    return ut.unaccent(a, t, .{ .max_output = max_text_result }) catch |e| switch (e) {
        error.InvalidUtf8 => t,
        else => |x| return x,
    };
}

/// Python's `capitalize` (pandas `str.capitalize`): the first character title-cased
/// (`ǆ` is `ǅ`), the rest lower-cased. polars has no `capitalize`; its `to_titlecase`
/// differs (it title-cases every word). Not valid UTF-8: ASCII only.
pub fn capitalize(a: std.mem.Allocator, t: []const u8) error{ OutOfMemory, TooLarge }![]const u8 {
    if (validUtf8(t) and !isAsciiText(t)) {
        if (ut.capitalize(a, t, ut_opts)) |r| return r else |e| switch (e) {
            error.InvalidUtf8 => {},
            else => |x| return x,
        }
    }
    const out = try std.ascii.allocLowerString(a, t);
    if (out.len > 0) out[0] = std.ascii.toUpper(out[0]);
    return out;
}

/// Python's `title` (pandas `str.title`): a cased letter after a non-cased one is
/// title-cased, the other cased letters lower-cased (`they're` is `They'Re`). polars'
/// `to_titlecase` treats apostrophes as part of the word (`They're`); pandas' is kept.
/// Not valid UTF-8: the ASCII rule, a non-ASCII byte counting as a letter.
pub fn title(a: std.mem.Allocator, t: []const u8) error{ OutOfMemory, TooLarge }![]const u8 {
    if (validUtf8(t) and !isAsciiText(t)) {
        if (ut.title(a, t, ut_opts)) |r| return r else |e| switch (e) {
            error.InvalidUtf8 => {},
            else => |x| return x,
        }
    }
    const out = try a.dupe(u8, t);
    var prev_cased = false;
    for (out) |*c| {
        if (std.ascii.isAlphabetic(c.*)) {
            c.* = if (prev_cased) std.ascii.toLower(c.*) else std.ascii.toUpper(c.*);
            prev_cased = true;
        } else prev_cased = c.* >= 0x80;
    }
    return out;
}

/// Python's `swapcase` (pandas `str.swapcase`, polars has none): upper letters lower and
/// lower upper, by the full mappings (`ß` becomes `SS`). Not valid UTF-8: ASCII only.
pub fn swapcase(a: std.mem.Allocator, t: []const u8) error{ OutOfMemory, TooLarge }![]const u8 {
    if (validUtf8(t) and !isAsciiText(t)) {
        if (ut.swapcase(a, t, ut_opts)) |r| return r else |e| switch (e) {
            error.InvalidUtf8 => {},
            else => |x| return x,
        }
    }
    const out = try a.dupe(u8, t);
    for (out) |*c| {
        if (std.ascii.isUpper(c.*)) c.* = std.ascii.toLower(c.*) else if (std.ascii.isLower(c.*)) c.* = std.ascii.toUpper(c.*);
    }
    return out;
}

pub const CharClass = enum { alpha, digit, alnum, space, lower, upper, title, decimal, numeric };

/// Python's `isalpha` … `istitle` (pandas `str.isalpha` …; polars has none of them, its
/// regex classes are the nearest): false for the empty text. `lower`/`upper` need at least
/// one cased character and no character of the other case; `title` is Python's `istitle`;
/// `digit`, `decimal` and `numeric` are Python's three nested numeric classes (`²` is a
/// digit and numeric but not decimal, `½` and `Ⅻ` are numeric only). An all-ASCII text takes
/// the byte path (exactly Python's answer for ASCII); one that is not valid UTF-8 is false.
pub fn isClass(t: []const u8, class: CharClass) bool {
    if (t.len == 0) return false;
    if (!isAsciiText(t)) {
        if (!validUtf8(t)) return false;
        const r = switch (class) {
            .alpha => ut.isAlpha(t, ut_opts),
            .digit => ut.isDigit(t, ut_opts),
            .alnum => ut.isAlnum(t, ut_opts),
            .space => ut.isSpace(t, ut_opts),
            .lower => ut.isLower(t, ut_opts),
            .upper => ut.isUpper(t, ut_opts),
            .title => ut.isTitle(t, ut_opts),
            .decimal => ut.isDecimal(t, ut_opts),
            .numeric => ut.isNumeric(t, ut_opts),
        };
        return r catch false;
    }
    switch (class) {
        .alpha => for (t) |c| {
            if (!std.ascii.isAlphabetic(c)) return false;
        },
        .digit, .decimal, .numeric => for (t) |c| {
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

/// polars `str.replace_many(patterns, replace_with)`: non-overlapping, the match that
/// ENDS first wins, and of those that end together the longest (measured against the
/// engine: "lo" loses to "l" in "hello" whichever comes first, "bc" beats "abcd" in
/// "abcd", and "ab" beats "b" in "abc" whichever comes first); `with` has one entry for
/// every pattern or one for all. An empty pattern is refused by the compiler.
pub fn replaceMany(a: std.mem.Allocator, t: []const u8, patterns: []const []const u8, with: []const []const u8, fold: bool) error{ OutOfMemory, TooLarge }![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0; // text before `i` is done
    scan: while (i < t.len) {
        var e: usize = i + 1;
        while (e <= t.len) : (e += 1) {
            var best: ?usize = null;
            for (patterns, 0..) |p, k| {
                if (p.len == 0 or p.len > e - i or !eqFold(t[e - p.len .. e], p, fold)) continue;
                if (best == null or p.len > patterns[best.?].len) best = k;
            }
            if (best) |k| {
                const len = patterns[k].len;
                try out.appendSlice(a, t[i .. e - len]);
                try out.appendSlice(a, if (with.len == 1) with[0] else with[k]);
                if (out.items.len > max_text_result) return error.TooLarge;
                i = e;
                continue :scan;
            }
        }
        try out.appendSlice(a, t[i..]);
        break;
    }
    if (out.items.len > max_text_result) return error.TooLarge;
    return out.items;
}

/// Non-overlapping occurrences of `p` (Python's `count`; an empty `p` matches between
/// every two characters and at both ends).
pub fn countMatches(t: []const u8, p: []const u8) usize {
    if (p.len == 0) return charCount(t) + 1;
    return std.mem.count(u8, t, p);
}

// ── substring search on cell-sized needles ──────────────────────────────────
// `std.mem.find` is Boyer-Moore-Horspool: O(text x needle) worst case. With a short needle
// that is linear in the text; with the needle itself a cell (`contains(a, b)` of two
// columns) two 1 MiB cells cost 2^40 steps. Needles past `long_needle` go through
// Knuth-Morris-Pratt, O(text + needle) with a failure table of one `usize` per byte.

/// Longest needle `std.mem` searches directly.
pub const long_needle: usize = 64;

fn kmpTable(a: std.mem.Allocator, p: []const u8) error{OutOfMemory}![]usize {
    const fail = try a.alloc(usize, p.len);
    fail[0] = 0;
    var k: usize = 0;
    for (1..p.len) |i| {
        while (k > 0 and p[i] != p[k]) k = fail[k - 1];
        if (p[i] == p[k]) k += 1;
        fail[i] = k;
    }
    return fail;
}

/// The first (or, `last`, the last, overlaps allowed) start of `p` in `h`; `p` is not empty.
fn kmpFind(h: []const u8, p: []const u8, fail: []const usize, last: bool) ?usize {
    var k: usize = 0;
    var res: ?usize = null;
    for (h, 0..) |c, i| {
        while (k > 0 and c != p[k]) k = fail[k - 1];
        if (c == p[k]) k += 1;
        if (k == p.len) {
            const m = i + 1 - p.len;
            if (!last) return m;
            res = m;
            k = fail[k - 1];
        }
    }
    return res;
}

/// `std.mem.find(u8, h, p)` in O(h + p).
pub fn findIn(a: std.mem.Allocator, h: []const u8, p: []const u8) error{OutOfMemory}!?usize {
    if (p.len <= long_needle or p.len > h.len) return std.mem.find(u8, h, p);
    const fail = try kmpTable(a, p);
    defer a.free(fail);
    return kmpFind(h, p, fail, false);
}

/// `std.mem.findLast(u8, h, p)` in O(h + p).
pub fn findLastIn(a: std.mem.Allocator, h: []const u8, p: []const u8) error{OutOfMemory}!?usize {
    if (p.len <= long_needle or p.len > h.len) return std.mem.findLast(u8, h, p);
    const fail = try kmpTable(a, p);
    defer a.free(fail);
    return kmpFind(h, p, fail, true);
}

/// `countMatches` in O(t + p).
pub fn countMatchesIn(a: std.mem.Allocator, t: []const u8, p: []const u8) error{OutOfMemory}!usize {
    if (p.len <= long_needle or p.len > t.len) return countMatches(t, p);
    const fail = try kmpTable(a, p);
    defer a.free(fail);
    var k: usize = 0;
    var n: usize = 0;
    for (t) |c| {
        while (k > 0 and c != p[k]) k = fail[k - 1];
        if (c == p[k]) k += 1;
        if (k == p.len) {
            n += 1;
            k = 0;
        }
    }
    return n;
}
