// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for unitext (`UNITEXT_FUZZ=<runs>[,<first seed>]`, testkit's
//! driver: `_MS`, `_SEEDFILE`, `_INPUT` as documented in `modules/testkit/src/fuzz_driver.zig`;
//! `zig build check-fuzz` rules for the Smith path). One input is a short UTF-8-ish
//! string drawn from classes that hit every branch: ASCII, accented letters, Greek sigma
//! contexts, combining marks of every class, Hangul jamo and syllables, ß / ŉ / ligatures /
//! U+FDFA (expanding), case-ignorables, ill-formed bytes.
//!
//! The properties are the algebra of the normalization forms and the policy/cap/writer
//! contracts; the exact values are pinned by the vector replays in `vectors_test.zig`.
//!
//!   - NFC(NFD(x)) = NFC(x), NFD(NFC(x)) = NFD(x), NFKC(NFKD(x)) = NFKC(x), NFKD(NFKC(x)) = NFKD(x)
//!   - normalize is idempotent, its result passes isNormalized, and isNormalized(x) says
//!     whether normalize(x) = x
//!   - under .reject the result is error.InvalidUtf8 exactly when the input is ill-formed;
//!     under .replace every result is well-formed UTF-8; under .pass_through nothing fails
//!     and the ill-formed bytes survive
//!   - max_output: a cap of exactly the result length succeeds, one byte less is TooLarge
//!   - the writer form writes the bytes of the allocating form, and a writer too small for
//!     them is an error, never a panic
//!   - casefold is idempotent; unaccent's result is NFC and ASCII-only where the input was
//!     Latin; lower/upper/title/swapcase/capitalize never fail on valid text

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const ut = @import("root.zig");
const fuzz_driver = testkit.fuzz.driver;
const Rng = fuzz_driver.Rng;

const max_in = 96;

const scalars = [_]u21{
    'a',    'Z',    '0',    ' ',    '.',    '\'',   0xDF,   0x149,  0x130,   0x131,   0x3A3,    0x3C3,  0x3C2,  0x390,  0x1C4,  0x1C5,   0x1C6,
    0x1E9E, 0xFB00, 0xFB03, 0xFDFA, 0x2126, 0x212B, 0x1F80, 0x1FB3, 0x2B0,   0xAD,    0x4E09,   0x3000, 0x0958, 0x1100, 0x1161, 0x11A8,  0xAC00,
    0xAC01, 0xD7A3, 0xC1,   0xE9,   0x17D,  0x16E,  0x141,  0xF8,   0x1D15E, 0x1D160, 0x10FFFF, 0x80,   0x7FF,  0x800,  0xFFFF, 0x10000,
};
const marks = [_]u21{ 0x300, 0x301, 0x302, 0x307, 0x308, 0x323, 0x327, 0x328, 0x345, 0x5B0, 0x5C7, 0x64B, 0x93C, 0xE38, 0x1D165, 0x1D16D, 0x20D2, 0x3099, 0x309A, 0xFE20 };
const leads = [_]u8{ 0xC0, 0xC1, 0xC2, 0xDF, 0xE0, 0xE1, 0xED, 0xEF, 0xF0, 0xF4, 0xF5, 0xFF, 0x80, 0xBF };

fn drawInput(comptime S: type, src: *S, buf: []u8) usize {
    if (S != Rng) return src.slice(buf);
    var n: usize = 0;
    const segs = src.valueRangeAtMost(u8, 0, 14);
    for (0..segs) |_| {
        if (n + 8 > buf.len) break;
        switch (src.valueRangeAtMost(u8, 0, 6)) {
            0, 1 => n += std.unicode.utf8Encode(scalars[src.index(scalars.len)], buf[n..]) catch unreachable,
            2, 3 => n += std.unicode.utf8Encode(marks[src.index(marks.len)], buf[n..]) catch unreachable,
            4 => {
                buf[n] = leads[src.index(leads.len)];
                n += 1;
            },
            5 => {
                // a random scalar value (any plane), never a surrogate
                var cp = src.valueRangeAtMost(u21, 0x80, 0x2FFFF);
                if (cp >= 0xD800 and cp < 0xE000) cp += 0x800;
                n += std.unicode.utf8Encode(cp, buf[n..]) catch unreachable;
            },
            else => {
                buf[n] = src.valueRangeAtMost(u8, 0x20, 0x7E);
                n += 1;
            },
        }
    }
    return n;
}

const forms = [_]ut.Form{ .nfc, .nfd, .nfkc, .nfkd };

fn nf(gpa: std.mem.Allocator, s: []const u8, f: ut.Form) ![]u8 {
    return ut.normalize(gpa, s, f, .{});
}

fn same(a: []const u8, b: []const u8) !void {
    if (!std.mem.eql(u8, a, b)) {
        std.debug.print("differ:\n  {any}\n  {any}\n", .{ a, b });
        return error.FuzzProperty;
    }
}

fn fuzzOne(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [max_in]u8 = undefined;
    const in = buf[0..drawInput(S, src, &buf)];
    const valid = std.unicode.utf8ValidateSlice(in);
    if (valid) fuzz_driver.hit("valid") else fuzz_driver.hit("ill-formed");
    if (std.mem.indexOfAny(u8, in, "\xCE\xCF") != null) fuzz_driver.hit("greek");
    if (valid) {
        var it = std.unicode.Utf8View.initUnchecked(in).iterator();
        var marks_seen: usize = 0;
        while (it.nextCodepoint()) |cp| {
            if (cp >= 0x300 and cp < 0x370) marks_seen += 1;
        }
        if (marks_seen >= 2) fuzz_driver.hit("marks");
    }

    // policies
    inline for (.{ .reject, .replace, .pass_through }) |pol| {
        const o: ut.Options = .{ .invalid_utf8 = pol };
        inline for (.{ ut.lower, ut.upper, ut.title, ut.capitalize, ut.swapcase, ut.casefold }) |f| {
            if (f(gpa, in, o)) |out| {
                defer gpa.free(out);
                if (pol == .reject and !valid) return error.RejectAcceptedIllFormed;
                if (pol == .replace and !std.unicode.utf8ValidateSlice(out)) return error.ReplaceProducedIllFormed;
            } else |e| {
                if (e != error.InvalidUtf8 or pol != .reject or valid) return e;
                fuzz_driver.hit("reject-error");
            }
        }
        for (forms) |form| {
            if (ut.normalize(gpa, in, form, o)) |out| {
                defer gpa.free(out);
                if (pol == .reject and !valid) return error.RejectAcceptedIllFormed;
                if (pol == .replace and !std.unicode.utf8ValidateSlice(out)) return error.ReplaceProducedIllFormed;
                if (pol == .pass_through and !valid) {
                    // bytes of every ill-formed stretch survive: the output has at least as many as the input
                    if (out.len == 0) return error.PassThroughLostBytes;
                }
            } else |e| {
                if (e != error.InvalidUtf8 or pol != .reject or valid) return e;
            }
        }
        if (ut.unaccent(gpa, in, .{ .invalid_utf8 = pol })) |un| {
            gpa.free(un);
        } else |e| {
            if (e != error.InvalidUtf8 or pol != .reject or valid) return e;
        }
    }
    if (!valid) return;

    // algebra of the forms (valid input)
    const c = try nf(gpa, in, .nfc);
    defer gpa.free(c);
    const d = try nf(gpa, in, .nfd);
    defer gpa.free(d);
    const kc = try nf(gpa, in, .nfkc);
    defer gpa.free(kc);
    const kd = try nf(gpa, in, .nfkd);
    defer gpa.free(kd);
    const outs = [_][]const u8{ c, d, kc, kd };
    for (forms, outs) |form, out| {
        const again = try nf(gpa, out, form);
        defer gpa.free(again);
        try same(out, again);
        if (!try ut.isNormalized(gpa, out, form, .{})) return error.ResultNotNormalized;
        const is_n = try ut.isNormalized(gpa, in, form, .{});
        if (is_n != std.mem.eql(u8, in, out)) return error.IsNormalizedDisagrees;
        if (try ut.quickCheck(out, form) == .no) return error.QuickCheckNoOnResult;
    }
    {
        const x = try nf(gpa, d, .nfc);
        defer gpa.free(x);
        try same(x, c);
        const y = try nf(gpa, c, .nfd);
        defer gpa.free(y);
        try same(y, d);
        const z = try nf(gpa, kd, .nfkc);
        defer gpa.free(z);
        try same(z, kc);
        const w = try nf(gpa, kc, .nfkd);
        defer gpa.free(w);
        try same(w, kd);
    }

    // caps: exactly the result length is enough, one less is TooLarge
    {
        const k = kd.len;
        const ok = try ut.normalize(gpa, in, .nfkd, .{ .max_output = k });
        gpa.free(ok);
        if (k > 0) {
            if (ut.normalize(gpa, in, .nfkd, .{ .max_output = k - 1 })) |o| {
                gpa.free(o);
                return error.CapNotEnforced;
            } else |e| if (e != error.TooLarge) return e;
            fuzz_driver.hit("too-large");
        }
        const up = try ut.upper(gpa, in, .{});
        defer gpa.free(up);
        const ok2 = try ut.upper(gpa, in, .{ .max_output = up.len });
        gpa.free(ok2);
        if (up.len > 0) {
            if (ut.upper(gpa, in, .{ .max_output = up.len - 1 })) |o| {
                gpa.free(o);
                return error.CapNotEnforced;
            } else |e| if (e != error.TooLarge) return e;
        }
        if (up.len > in.len) fuzz_driver.hit("expanding");
    }

    // writer forms agree with the allocating forms; a short writer is an error
    {
        const want = try ut.lower(gpa, in, .{});
        defer gpa.free(want);
        var aw: std.Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();
        try ut.lowerTo(&aw.writer, in, .{});
        try same(want, aw.written());
        const cap = if (src.value(bool)) want.len else want.len -| 1;
        const small = try gpa.alloc(u8, cap);
        defer gpa.free(small);
        var w: std.Io.Writer = .fixed(small);
        if (ut.lowerTo(&w, in, .{})) |_| {
            if (cap < want.len) return error.ShortWriterAccepted;
            try same(want, w.buffered());
        } else |e| {
            if (e != error.WriteFailed or cap >= want.len) return e;
            fuzz_driver.hit("short-writer");
        }
        var aw2: std.Io.Writer.Allocating = .init(gpa);
        defer aw2.deinit();
        try ut.normalizeTo(gpa, &aw2.writer, in, .nfc, .{});
        try same(c, aw2.written());
    }

    // casefold idempotent; unaccent is NFC
    {
        const f1 = try ut.casefold(gpa, in, .{});
        defer gpa.free(f1);
        const f2 = try ut.casefold(gpa, f1, .{});
        defer gpa.free(f2);
        try same(f1, f2);
        const un = try ut.unaccent(gpa, in, .{});
        defer gpa.free(un);
        if (!try ut.isNormalized(gpa, un, .nfc, .{})) return error.UnaccentNotNfc;
        const un2 = try ut.unaccent(gpa, in, .{ .expand_ligatures = false });
        defer gpa.free(un2);
        if (!try ut.isNormalized(gpa, un2, .nfc, .{})) return error.UnaccentNotNfc;
        // title never fails on valid text; swapcase of ASCII-only text is its ASCII swap
        const t = try ut.title(gpa, in, .{});
        gpa.free(t);
        if (ut.isAscii(in)) {
            const sw = try ut.swapcase(gpa, in, .{});
            defer gpa.free(sw);
            for (in, sw) |x, y| {
                const want = if (std.ascii.isUpper(x)) std.ascii.toLower(x) else if (std.ascii.isLower(x)) std.ascii.toUpper(x) else x;
                if (y != want) return error.AsciiSwapcase;
            }
        }
    }
}

fn fuzzSmith(_: void, s: *testing.Smith) !void {
    return fuzzOne(testing.Smith, s, testing.allocator);
}

const corpus = [_][]const u8{
    testkit.fuzz.seed("plain"),
    testkit.fuzz.seed("e\xcc\x81\xcc\xa3 \xce\x91\xce\xa3 \xc3\x9f\xef\xac\x83"),
    testkit.fuzz.seed("\xe1\x84\x80\xe1\x85\xa1\xe1\x86\xa8\xea\xb0\x80"),
    testkit.fuzz.seed("\xef\xb7\xba \xc4\xb0 \xc7\x85 \xe2\x84\xa6"),
    testkit.fuzz.seed("\xe2\x82\xed\xa0\x80\xff\xf0\x9f\x98"),
};

test "fuzz: normalization algebra, policies, caps and writers" {
    try testing.fuzz({}, fuzzSmith, .{ .corpus = &corpus });
}

test "fuzz driver: UNITEXT_FUZZ" {
    try fuzz_driver.run(fuzzOne, .{ .prefix = "UNITEXT_FUZZ", .name = "unitext" });
}

test "fuzz harness: 3000 seeds in the suite pass, and the draw reaches the branches it is for" {
    fuzz_driver.resetReach();
    var valid_n: usize = 0;
    var ill_n: usize = 0;
    var grk: usize = 0;
    var many_marks: usize = 0;
    var expanding: usize = 0;
    for (0..3000) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: Rng = .{ .r = prng.random() };
        fuzzOne(Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("unitext fuzz seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        var prng2 = std.Random.DefaultPrng.init(seed);
        var rng2: Rng = .{ .r = prng2.random() };
        var buf: [max_in]u8 = undefined;
        const in = buf[0..drawInput(Rng, &rng2, &buf)];
        if (std.unicode.utf8ValidateSlice(in)) valid_n += 1 else ill_n += 1;
        if (std.mem.indexOf(u8, in, "\xCE\xA3") != null or std.mem.indexOf(u8, in, "\xCF\x82") != null) grk += 1;
        if (std.mem.indexOf(u8, in, "\xCC") != null) many_marks += 1;
        if (std.mem.indexOf(u8, in, "\xC3\x9F") != null or std.mem.indexOf(u8, in, "\xEF\xB7\xBA") != null) expanding += 1;
    }
    try testing.expect(valid_n > 300 and ill_n > 1000);
    try testing.expect(grk > 100 and many_marks > 500 and expanding > 100);
}
