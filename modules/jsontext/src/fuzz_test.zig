// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for jsontext (added 2026-11-08).
//!
//! `JSONTEXT_FUZZ=<runs>[,<first seed>]` runs the harness over seeds in the
//! ordinary test binary (testkit's driver: `_MS`, `_SEEDFILE`, `_INPUT` as
//! documented in `modules/testkit/src/fuzz_driver.zig`). Under `std.testing.fuzz`
//! the harness reads one `Smith.slice`.
//!
//! The oracle is independent of `root.zig`: the expected text for `.replace` /
//! `.escape_bytes` comes from a WHATWG-style decoder state machine written here
//! (not the table-driven `utf8Step`), the JSON check is `std.json`, and the
//! depth reference scans strings with an explicit end-finder instead of a state
//! flag.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const jsontext = @import("root.zig");
const fuzz_driver = testkit.fuzz.driver;
const Rng = fuzz_driver.Rng;

const max_in = 128;

// ── input draw ──────────────────────────────────────────────────────────────

const leads = [_]u8{ 0xC0, 0xC1, 0xC2, 0xDF, 0xE0, 0xE1, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF3, 0xF4, 0xF5, 0xFF };
const specials = [_]u8{ '"', '\\', '<', '>', '&', 0x7F, '/', 0x00, 0x1F, 0x08, 0x0C, '\n' };
const scalars = [_]u21{ 0x80, 0x7FF, 0x800, 0xD7FF, 0xE000, 0xFFFD, 0xFFFF, 0x10000, 0x10FFFF, 0x2027, 0x2028, 0x2029, 0x202A, 0x20AC, 0x1F600 };

/// One harness input into `buf`; returns its length. Under `Smith` it is
/// `src.slice` (corpus seeds replay verbatim); under the driver's `Rng` it is
/// a concatenation of segments that hit the escape table, valid scalars,
/// ill-formed leads and truncated sequences.
fn drawInput(comptime S: type, src: *S, buf: []u8) usize {
    if (S != Rng) return src.slice(buf);
    var n: usize = 0;
    const segs = src.valueRangeAtMost(u8, 0, 24);
    for (0..segs) |_| {
        if (n + 8 > buf.len) break;
        switch (src.valueRangeAtMost(u8, 0, 7)) {
            0 => for (0..src.valueRangeAtMost(u8, 1, 6)) |_| {
                buf[n] = src.valueRangeAtMost(u8, 0x20, 0x7E);
                n += 1;
            },
            1 => {
                buf[n] = src.valueRangeAtMost(u8, 0x00, 0x1F);
                n += 1;
            },
            2 => {
                buf[n] = specials[src.index(specials.len)];
                n += 1;
            },
            3 => n += std.unicode.utf8Encode(scalars[src.index(scalars.len)], buf[n..]) catch unreachable,
            4 => {
                buf[n] = leads[src.index(leads.len)];
                n += 1;
            },
            5 => {
                buf[n] = src.valueRangeAtMost(u8, 0x80, 0xBF);
                n += 1;
            },
            6 => {
                // A valid scalar missing its last 1..3 bytes.
                var tmp: [4]u8 = undefined;
                const cp = scalars[src.index(scalars.len)];
                const full = std.unicode.utf8Encode(cp, &tmp) catch unreachable;
                const keep = full - src.valueRangeAtMost(u8, 1, @intCast(full - 1));
                @memcpy(buf[n..][0..keep], tmp[0..keep]);
                n += keep;
            },
            else => {
                buf[n] = src.value(u8);
                n += 1;
            },
        }
    }
    return n;
}

// ── references ──────────────────────────────────────────────────────────────

const Policy = enum { replace, escape_bytes };

/// WHATWG Encoding Standard UTF-8 decoder, as a byte-at-a-time state machine:
/// the expected decoded text of `in`, as UTF-8, where an error is U+FFFD
/// (`.replace`) or one U+00XX per byte of the offending subpart (`.escape_bytes`).
fn refDecode(a: std.mem.Allocator, in: []const u8, comptime policy: Policy) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    var needed: u8 = 0;
    var lower: u8 = 0x80;
    var upper: u8 = 0xBF;
    var start: usize = 0; // first byte of the sequence in progress
    var i: usize = 0;
    while (i < in.len) {
        const b = in[i];
        if (needed == 0) {
            start = i;
            switch (b) {
                0x00...0x7F => try out.append(a, b),
                0xC2...0xDF => needed = 1,
                0xE0 => {
                    lower = 0xA0;
                    needed = 2;
                },
                0xE1...0xEC, 0xEE...0xEF => needed = 2,
                0xED => {
                    upper = 0x9F;
                    needed = 2;
                },
                0xF0 => {
                    lower = 0x90;
                    needed = 3;
                },
                0xF1...0xF3 => needed = 3,
                0xF4 => {
                    upper = 0x8F;
                    needed = 3;
                },
                else => try refError(a, &out, in[i .. i + 1], policy),
            }
            i += 1;
            continue;
        }
        if (b < lower or b > upper) {
            // The sequence in progress ends here; `b` is looked at again.
            try refError(a, &out, in[start..i], policy);
            needed = 0;
            lower = 0x80;
            upper = 0xBF;
            continue;
        }
        lower = 0x80;
        upper = 0xBF;
        needed -= 1;
        i += 1;
        if (needed == 0) try out.appendSlice(a, in[start..i]);
    }
    if (needed != 0) try refError(a, &out, in[start..], policy);
    return out.toOwnedSlice(a);
}

fn refError(a: std.mem.Allocator, out: *std.ArrayList(u8), bad: []const u8, comptime policy: Policy) !void {
    switch (policy) {
        .replace => try out.appendSlice(a, "\u{fffd}"),
        .escape_bytes => for (bad) |b| {
            var tmp: [4]u8 = undefined;
            const n = std.unicode.utf8Encode(b, &tmp) catch unreachable;
            try out.appendSlice(a, tmp[0..n]);
        },
    }
}

/// The largest nesting `depthWithin` must tolerate: strings are skipped by
/// finding their end, closers saturate at zero.
fn refMaxDepth(bytes: []const u8) usize {
    var depth: usize = 0;
    var max: usize = 0;
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        switch (bytes[i]) {
            '"' => {
                i += 1;
                while (i < bytes.len and bytes[i] != '"') i += if (bytes[i] == '\\') 2 else 1;
            },
            '[', '{' => {
                depth += 1;
                max = @max(max, depth);
            },
            ']', '}' => if (depth > 0) {
                depth -= 1;
            },
            else => {},
        }
    }
    return max;
}

// ── the harness ─────────────────────────────────────────────────────────────

fn fuzzOne(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [max_in]u8 = undefined;
    const n = drawInput(S, src, &buf);
    const in = buf[0..n];
    const valid = std.unicode.utf8ValidateSlice(in);
    if (valid) fuzz_driver.hit("valid") else fuzz_driver.hit("ill-formed");

    const want_replace = try refDecode(gpa, in, .replace);
    defer gpa.free(want_replace);
    const want_escape = try refDecode(gpa, in, .escape_bytes);
    defer gpa.free(want_escape);
    if (valid and !std.mem.eql(u8, want_replace, in)) return error.ReferenceDisagreesOnValidInput;

    inline for ([_]bool{ false, true }) |ascii| inline for ([_]bool{ false, true }) |html| inline for (.{ .replace, .escape_bytes, .reject }) |pol| {
        const opts: jsontext.StringOptions = .{ .ascii_only = ascii, .html_safe = html, .invalid_utf8 = pol };
        var aw: std.Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();
        const r = jsontext.writeString(&aw.writer, in, opts);
        if (pol == .reject and !valid) {
            fuzz_driver.hit("reject-error");
            try testing.expectError(error.InvalidUtf8, r);
        } else {
            try r;
            const out = aw.written();
            try checkLiteral(gpa, out, if (pol == .escape_bytes) want_escape else want_replace, ascii, html);
            // The writer failing at any size is an error, never a panic, and a
            // buffer of exactly the output's size is enough.
            const cap = if (src.value(bool)) out.len else out.len -| 1;
            var small: std.Io.Writer = .fixed(try gpa.alloc(u8, cap));
            defer gpa.free(small.buffer);
            if (jsontext.writeString(&small, in, opts)) |_| {
                if (cap < out.len) return error.ShortWriterAccepted;
                try testing.expectEqualStrings(out, small.buffered());
            } else |e| {
                if (cap >= out.len or e != error.WriteFailed) return error.ShortWriterWrongError;
                fuzz_driver.hit("short-writer");
            }
        }
    };

    // depthWithin against the reference, on the raw bytes and on the same
    // bytes mapped onto a bracket/quote/escape alphabet.
    var mapped: [max_in]u8 = undefined;
    for (in, 0..) |b, i| mapped[i] = "[]{}\"\\xa"[b & 7];
    for ([_][]const u8{ in, mapped[0..n] }) |text| {
        const md = refMaxDepth(text);
        if (md >= 3) fuzz_driver.hit("deep");
        for (0..@min(md + 2, 40)) |m| {
            if (jsontext.depthWithin(text, m) != (md <= m)) return error.DepthDisagrees;
        }
        if (!jsontext.depthWithin(text, std.math.maxInt(usize))) return error.DepthRefusesAtMax;
    }
}

/// `out` is a JSON string literal, ASCII / HTML-safe when asked, whose decoded
/// text is `want`.
fn checkLiteral(gpa: std.mem.Allocator, out: []const u8, want: []const u8, ascii: bool, html: bool) !void {
    for (out) |b| {
        if (b < 0x20) return error.RawControlInOutput;
        if (ascii and b >= 0x80) return error.NonAsciiInAsciiOutput;
        if (html and (b == '<' or b == '>' or b == '&')) return error.HtmlCharInOutput;
    }
    if (html and (std.mem.find(u8, out, "\xe2\x80\xa8") != null or std.mem.find(u8, out, "\xe2\x80\xa9") != null))
        return error.LineSeparatorInHtmlOutput;
    var parsed = std.json.parseFromSlice(std.json.Value, gpa, out, .{}) catch return error.OutputIsNotJson;
    defer parsed.deinit();
    const got = switch (parsed.value) {
        .string => |s| s,
        else => return error.OutputIsNotAString,
    };
    if (!std.mem.eql(u8, got, want)) {
        std.debug.print("decoded {any}\nwanted  {any}\n", .{ got, want });
        return error.DecodedTextDiffers;
    }
}

fn fuzzSmith(_: void, s: *testing.Smith) !void {
    return fuzzOne(testing.Smith, s, testing.allocator);
}

const corpus = [_][]const u8{
    testkit.fuzz.seed("plain"),
    testkit.fuzz.seed("a\"b\\c<d>&e\x7f\x00\x1f"),
    testkit.fuzz.seed("\xe2\x82\xac\xf0\x9f\x98\x80\xe2\x80\xa8\xe2\x80\xa9"),
    testkit.fuzz.seed("\xe2\x82\xf0\x9f\x98\xed\xa0\x80\xc0\xaf\xf4\x90\x80\x80\xff"),
    testkit.fuzz.seed("{\"a\":[\"\\\"[[\",{\"b\":[]}]}"),
};

test "fuzz: every option combination yields a literal that decodes to the reference text" {
    try testing.fuzz({}, fuzzSmith, .{ .corpus = &corpus });
}

test "fuzz driver: JSONTEXT_FUZZ" {
    try fuzz_driver.run(fuzzOne, .{ .prefix = "JSONTEXT_FUZZ", .name = "jsontext-string-depth" });
}

test "fuzz harness: 4000 seeds in the suite pass, and the draw reaches both halves of the input space" {
    fuzz_driver.resetReach();
    var valid_n: usize = 0;
    var ill_n: usize = 0;
    var deep_n: usize = 0;
    var many_escapes: usize = 0;
    for (0..4000) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: Rng = .{ .r = prng.random() };
        fuzzOne(Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("jsontext fuzz seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        // The same draw again, to classify it (`hit` has no reader outside the driver).
        var prng2 = std.Random.DefaultPrng.init(seed);
        var rng2: Rng = .{ .r = prng2.random() };
        var buf: [max_in]u8 = undefined;
        const in = buf[0..drawInput(Rng, &rng2, &buf)];
        if (std.unicode.utf8ValidateSlice(in)) valid_n += 1 else ill_n += 1;
        var mapped: [max_in]u8 = undefined;
        for (in, 0..) |b, i| mapped[i] = "[]{}\"\\xa"[b & 7];
        if (refMaxDepth(mapped[0..in.len]) >= 3) deep_n += 1;
        if (std.mem.countScalar(u8, mapped[0..in.len], '"') + std.mem.countScalar(u8, mapped[0..in.len], '\\') >= 2) many_escapes += 1;
    }
    try testing.expect(valid_n > 200 and ill_n > 1000);
    try testing.expect(deep_n > 400 and many_escapes > 1000);
}
