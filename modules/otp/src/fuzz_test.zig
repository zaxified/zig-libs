// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for otp (added 2026-10-10): `OTP_FUZZ=<runs>[,<first seed>]`
//! (testkit's driver; `_ONLY` selects a harness by name). Harness names:
//! `otp-uri` (a `KeyUri` formatted by this module round-trips field for
//! field; the same URI with 0-3 octets damaged and maybe truncated is parsed
//! without a panic, and whatever is accepted re-formats and re-parses to the
//! same fields) and `otp-code` (hotp / totp / totpVerify checked against an
//! independent window enumeration: the genuine code is accepted, a code one
//! off or outside the skew window is not, formatted codes are `digits`
//! decimal characters that parse back to the code).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;
pub const Cursor = testkit.fuzz.Cursor;

/// Reach counters for one harness's labels. `mark` also feeds the driver's
/// `REACH` report; `reach` runs `seeds` seeds in the ordinary test binary and
/// fails with `error.HarnessDoesNotReach` if a label never fired.
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

/// `frame` into `buf` with 0-3 octets damaged and maybe truncated.
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        buf[src.index(n)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Deterministic bytes from a knob cursor (its first octets seed a PRNG).
pub fn expand(knobs: *Cursor, out: []u8) void {
    var s: u64 = 0;
    for (0..8) |_| s = (s << 8) | knobs.byte();
    var prng = std.Random.DefaultPrng.init(s);
    prng.random().bytes(out);
}

/// Smith-side wrapper so `--fuzz` keeps working: the harness bodies are
/// generic over `S`; `testing.fuzz` hands them a `std.testing.Smith`.
pub fn smithWrap(comptime harness: anytype) fn (void, *std.testing.Smith) anyerror!void {
    return struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            try harness(std.testing.Smith, smith, testing.allocator);
        }
    }.f;
}

const otp = @import("root.zig");
const otpauth = @import("otpauth.zig");
const Algorithm = otp.Algorithm;

fn algOf(knobs: *Cursor) Algorithm {
    return switch (knobs.ranged(0, 2)) {
        0 => .sha1,
        1 => .sha256,
        else => .sha512,
    };
}

const UriMark = Marker(enum { genuine_roundtrip, damaged_accepted, damaged_refused, hotp, totp, issuer, code_computed });

fn fuzzUri(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [24]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    // Whole code points, ':' deliberately absent (illegal in labels).
    const cps = [_][]const u8{ "a", "Z", "7", " ", "/", "?", "#", "&", "=", "+", "%", "@", "\u{e9}", "\u{17e}", "\u{4e2d}", "\u{1f600}", "-", ".", "_", "~" };
    var secret: [60]u8 = undefined;
    expand(&knobs, &secret);
    const sl = knobs.ranged(1, 60);
    var acct: [40]u8 = undefined;
    var iss: [40]u8 = undefined;
    var al: usize = 0;
    var il: usize = 0;
    for (0..knobs.ranged(1, 6)) |_| {
        const cp = cps[knobs.ranged(0, cps.len - 1)];
        @memcpy(acct[al..][0..cp.len], cp);
        al += cp.len;
    }
    if (acct[0] == ' ') acct[0] = 'a';
    const with_issuer = knobs.byte() & 1 == 1;
    if (with_issuer) {
        for (0..knobs.ranged(1, 6)) |_| {
            const cp = cps[knobs.ranged(0, cps.len - 1)];
            @memcpy(iss[il..][0..cp.len], cp);
            il += cp.len;
        }
    }
    const k: otpauth.KeyUri = .{
        .kind = if (knobs.byte() & 1 == 0) .totp else .hotp,
        .secret = secret[0..sl],
        .account = acct[0..al],
        .issuer = if (with_issuer) iss[0..il] else null,
        .algorithm = algOf(&knobs),
        .digits = @intCast(knobs.ranged(6, 8)),
        .period = knobs.ranged(1, 3600),
        .counter = std.mem.readInt(u64, &.{ knobs.byte(), knobs.byte(), knobs.byte(), knobs.byte(), knobs.byte(), knobs.byte(), knobs.byte(), knobs.byte() }, .little),
    };
    var text: [2048]u8 = undefined;
    var w = std.Io.Writer.fixed(&text);
    otpauth.format(&w, k) catch return; // too long for the buffer: a size limit
    const uri = w.buffered();
    if (uri.len > otpauth.max_uri_len) return;
    var b1: [2048]u8 = undefined;
    const back = otpauth.parse(uri, &b1) catch return error.GenuineUriRefused;
    if (back.kind != k.kind or !std.mem.eql(u8, back.secret, k.secret) or !std.mem.eql(u8, back.account, k.account) or
        (back.issuer == null) != (k.issuer == null) or back.algorithm != k.algorithm or back.digits != k.digits)
        return error.RoundtripDiffers;
    if (k.issuer) |i| if (!std.mem.eql(u8, back.issuer.?, i)) return error.RoundtripDiffers;
    if (k.kind == .totp and back.period != k.period) return error.RoundtripDiffers;
    if (k.kind == .hotp and back.counter != k.counter) return error.RoundtripDiffers;
    UriMark.mark(.genuine_roundtrip);
    if (k.kind == .hotp) UriMark.mark(.hotp) else UriMark.mark(.totp);
    if (k.issuer != null) UriMark.mark(.issuer);

    // Damaged: never a panic; accepted URIs re-format and re-parse to the same fields.
    var buf: [2048]u8 = undefined;
    const n = damage(src, &buf, uri);
    var b2: [2048]u8 = undefined;
    const got = otpauth.parse(buf[0..n], &b2) catch {
        UriMark.mark(.damaged_refused);
        return;
    };
    UriMark.mark(.damaged_accepted);
    if (got.kind == .totp) {
        _ = got.totpCode(1_700_000_000) catch {};
    } else {
        _ = got.hotpCode(got.counter) catch {};
    }
    UriMark.mark(.code_computed);
    var out: [2048]u8 = undefined;
    var w2 = std.Io.Writer.fixed(&out);
    otpauth.format(&w2, got) catch |e| switch (e) {
        error.WriteFailed => return,
        else => return e,
    };
    if (w2.buffered().len > otpauth.max_uri_len) return;
    var b3: [2048]u8 = undefined;
    const again = try otpauth.parse(w2.buffered(), &b3);
    if (!std.mem.eql(u8, got.secret, again.secret) or !std.mem.eql(u8, got.account, again.account) or got.algorithm != again.algorithm or got.digits != again.digits)
        return error.AcceptedUriDoesNotRoundtrip;
}

test "fuzz: otp uri, genuine round-trips / damaged never panics" {
    try testing.fuzz({}, smithWrap(fuzzUri), .{});
}
test "fuzz driver: OTP_FUZZ (uri)" {
    try fuzz_driver.run(fuzzUri, .{ .prefix = "OTP_FUZZ", .name = "otp-uri" });
}
test "fuzz harness: uri, 400 seeds, reaches every outcome" {
    try UriMark.reach(fuzzUri, "otp-uri", 400);
}

const CodeMark = Marker(enum { genuine_accepted, off_by_one_refused, skew_edge_accepted, outside_window_refused, formatted, small_out_refused });

fn fuzzCode(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [24]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    var key: [80]u8 = undefined;
    expand(&knobs, &key);
    const k = key[0..knobs.ranged(0, 80)];
    const alg = algOf(&knobs);
    const digits: u5 = @intCast(knobs.ranged(1, 9));
    const period: u32 = knobs.ranged(1, 120);
    const t0: u64 = knobs.byte();
    const now: u64 = t0 + std.mem.readInt(u32, &.{ knobs.byte(), knobs.byte(), knobs.byte(), knobs.byte() }, .little);
    const skew: u32 = knobs.ranged(0, 3);
    const step = otp.timeStep(now, period, t0);
    const mod: u32 = std.math.pow(u32, 10, digits);

    switch (alg) {
        inline else => |a| {
            const code = otp.totp(a, k, now, period, t0, digits);
            if (code >= mod) return error.CodeTooWide;
            if (!otp.totpVerify(a, k, now, period, t0, digits, code, skew)) return error.GenuineCodeRefused;
            CodeMark.mark(.genuine_accepted);
            // One off (mod 10^digits): refused unless it is also in the window.
            const off = (code + 1) % mod;
            var in_window = false;
            var s: u64 = if (step >= skew) step - skew else 0;
            while (s <= step + skew) : (s += 1) {
                if (otp.hotp(a, k, s, digits) == off) in_window = true;
            }
            if (otp.totpVerify(a, k, now, period, t0, digits, off, skew) != in_window) return error.VerifyDisagreesWithWindow;
            if (!in_window) CodeMark.mark(.off_by_one_refused);
            // The edges of the window are accepted, one step beyond is not (unless it collides).
            if (skew > 0) {
                const lo = otp.hotp(a, k, if (step >= skew) step - skew else 0, digits);
                if (!otp.totpVerify(a, k, now, period, t0, digits, lo, skew)) return error.WindowEdgeRefused;
                CodeMark.mark(.skew_edge_accepted);
            }
            const beyond = otp.hotp(a, k, step + skew + 1, digits);
            var collides = false;
            s = if (step >= skew) step - skew else 0;
            while (s <= step + skew) : (s += 1) {
                if (otp.hotp(a, k, s, digits) == beyond) collides = true;
            }
            if (!collides) {
                if (otp.totpVerify(a, k, now, period, t0, digits, beyond, skew)) return error.OutsideWindowAccepted;
                CodeMark.mark(.outside_window_refused);
            }
            // Formatting.
            var out: [9]u8 = undefined;
            const text = try otp.fmtCode(code, digits, &out);
            if (text.len != digits) return error.WrongWidth;
            const back = std.fmt.parseInt(u32, text, 10) catch return error.NotDecimal;
            if (back != code) return error.FormatDiffers;
            CodeMark.mark(.formatted);
            if (digits > 1) {
                if (otp.fmtCode(code, digits, out[0 .. digits - 1])) |_| return error.ShortBufferAccepted else |_| CodeMark.mark(.small_out_refused);
            }
        },
    }
}

test "fuzz: otp codes agree with an independent window enumeration" {
    try testing.fuzz({}, smithWrap(fuzzCode), .{});
}
test "fuzz driver: OTP_FUZZ (code)" {
    try fuzz_driver.run(fuzzCode, .{ .prefix = "OTP_FUZZ", .name = "otp-code" });
}
test "fuzz harness: code, 400 seeds, reaches every outcome" {
    try CodeMark.reach(fuzzCode, "otp-code", 400);
}
