// SPDX-License-Identifier: MIT

//! Fuzz harness: every decoder here against `std.base64` (a foreign
//! implementation — table-driven, written independently), every encoder
//! byte for byte against std.
//!
//! One draw, the script. Its first octets pick the variant and the mode; the
//! rest is either the octets to encode (then mutated) or a text built from a
//! biased alphabet — mostly alphabet characters, some `=`, whitespace and raw
//! octets — because uniformly random octets are almost never base64 and the
//! accept paths would go unwalked.
//!
//! Oracles, per mode:
//!  - decode: std's verdict, bytes and error on the same text;
//!  - decodeIgnoring: std's verdict on the text with the ignored characters
//!    removed (by a plain filter here, not by the code under test);
//!  - decodePrefix: what it decoded equals decodeIgnoring of what it says it
//!    consumed, and it stopped on a character the prefix may not contain;
//!  - encode / encodeWrapped: std's output, and the wrapped lines join to it.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const fuzzseed = @import("testkit").fuzz;
const fuzz_driver = fuzzseed.driver;

const max_script = 200;

const Reach = enum { accept, reject_char, reject_pad, ignored, prefix_short, wrapped, url };
var reach: [@typeInfo(Reach).@"enum".fields.len]usize = @splat(0);

fn mark(comptime l: Reach) void {
    reach[@intFromEnum(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

const seeds = [_][]const u8{
    fuzzseed.seed(""),
    fuzzseed.seed("\x00\x00foobar"), // standard, decode of mutated encoding
    fuzzseed.seed("\x01\x01Zm9vYmE="), // no-pad, decode of a text
    fuzzseed.seed("\x02\x02QUJD\nQUI=\n"), // url, ignoring
    fuzzseed.seed("\x03\x03QQ==;rest"), // url no-pad, prefix
    fuzzseed.seed("\x00\x04" ++ "\xfb\xff\x00" ** 30), // wrapped encode
    fuzzseed.seed("\x00\x01" ++ "\x10\x20\x30\x40\xc8\xd0\xe0\xf0" ** 8),
};

test "fuzz: b64ct against std.base64" {
    try testing.fuzz({}, fuzzOne, .{ .corpus = &seeds });
}

fn fuzzOne(_: void, smith: *testing.Smith) !void {
    var buf: [max_script]u8 = undefined;
    const n = smith.slice(&buf);
    var src: Replay = .{ .data = buf[0..n] };
    return harness(Replay, &src, testing.allocator);
}

const Replay = struct {
    data: []const u8,
    pub fn slice(self: *Replay, out: []u8) u32 {
        @memcpy(out[0..self.data.len], self.data);
        return @intCast(self.data.len);
    }
};

/// Generic over the choice source (`testing.Smith` under `--fuzz`, the
/// driver's `Rng`): the only draw is the one `slice`.
pub fn harness(comptime Src: type, src: *Src, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var script_buf: [max_script]u8 = undefined;
    const n = src.slice(&script_buf);
    const script = script_buf[0..n];
    var cur: fuzzseed.Cursor = .{ .bytes = script };
    const variant = cur.byte() % 4;
    const mode = cur.byte() % 5;
    const body = if (script.len > 2) script[2..] else script[0..0];
    switch (variant) {
        0 => try one(root.standard, std.base64.standard, mode, body, &cur),
        1 => try one(root.standard_no_pad, std.base64.standard_no_pad, mode, body, &cur),
        2 => try one(root.url_safe, std.base64.url_safe, mode, body, &cur),
        3 => try one(root.url_safe_no_pad, std.base64.url_safe_no_pad, mode, body, &cur),
        else => unreachable,
    }
    if (variant >= 2) mark(.url);
}

/// Builds a text from `body`: octet b → an alphabet character (b < 200), `=`
/// (< 215), one of " \t\r\n" (< 235), else b itself.
fn textFrom(comptime S: anytype, body: []const u8, out: []u8) []u8 {
    const chars = S.Encoder.alphabet_chars;
    for (body, out[0..body.len]) |b, *o| o.* = if (b < 200)
        chars[b % 64]
    else if (b < 215)
        '='
    else if (b < 235)
        " \t\r\n"[b % 4]
    else
        b;
    return out[0..body.len];
}

fn stdDecode(comptime S: anytype, out: []u8, s: []const u8) root.Error![]u8 {
    const len = try S.Decoder.calcSizeForSlice(s);
    if (len > out.len) return error.NoSpaceLeft;
    try S.Decoder.decode(out[0..len], s);
    return out[0..len];
}

fn markVerdict(r: root.Error![]u8) void {
    if (r) |_| mark(.accept) else |e| switch (e) {
        error.InvalidCharacter => mark(.reject_char),
        error.InvalidPadding => mark(.reject_pad),
        error.NoSpaceLeft => {},
    }
}

/// std's verdict and bytes; its error too, for the unpadded variants (see
/// root.zig's "decode accepts exactly what std accepts" for why not padded).
fn expectSame(comptime pads: bool, want: root.Error![]u8, got: root.Error![]u8) !void {
    if (want) |w| {
        try testing.expectEqualSlices(u8, w, try got);
    } else |e| if (pads)
        try testing.expect(std.meta.isError(got))
    else
        try testing.expectError(e, got);
}

fn one(comptime C: type, comptime S: anytype, mode: u8, body: []const u8, cur: *fuzzseed.Cursor) !void {
    oneMode(C, S, mode, body, cur) catch |e| {
        std.debug.print("b64ct fuzz: {s} pad={} mode {d} body {x}\n", .{ @tagName(C.alphabet_kind), C.pads, mode, body });
        return e;
    };
}

fn oneMode(comptime C: type, comptime S: anytype, mode: u8, body: []const u8, cur: *fuzzseed.Cursor) !void {
    var text_buf: [512]u8 = undefined;
    var ours: [512]u8 = undefined;
    var theirs: [512]u8 = undefined;
    switch (mode) {
        // decode: a valid encoding of `body`, then up to three mutations.
        0 => {
            var enc: [300]u8 = undefined;
            const e = S.Encoder.encode(&enc, body);
            @memcpy(text_buf[0..e.len], e);
            var len = e.len;
            const muts = cur.ranged(0, 3);
            for (0..muts) |_| {
                if (len == 0) break;
                const at = cur.ranged(0, @intCast(len - 1));
                switch (cur.byte() % 3) {
                    0 => text_buf[at] = cur.byte(), // overwrite
                    1 => len -= 1, // truncate
                    else => text_buf[at] = if (C.pads) '=' else S.Encoder.alphabet_chars[cur.byte() % 64],
                }
            }
            const t = text_buf[0..len];
            const want = stdDecode(S, &theirs, t);
            const got = C.decode(&ours, t);
            markVerdict(got);
            try expectSame(C.pads, want, got);
            try expectSame(C.pads, want, C.decodeIgnoring(&ours, t, ""));
        },
        // decode of an arbitrary text from the biased alphabet.
        1 => {
            const t = textFrom(S, body, &text_buf);
            const want = stdDecode(S, &theirs, t);
            @memset(&ours, 0);
            const got = C.decode(&ours, t);
            markVerdict(got);
            try expectSame(C.pads, want, got);
            // A rejected text leaves nothing in `out`.
            if (got) |_| {} else |_| try testing.expect(std.mem.allEqual(u8, &ours, 0));
            // Exact-size output: the decoded length, never more.
            if (want) |w| try testing.expectEqualSlices(u8, w, try C.decode(ours[0..w.len], t)) else |_| {}
        },
        // decodeIgnoring: std on the text with the ignored characters filtered out.
        2 => {
            const t = textFrom(S, body, &text_buf);
            var filtered: [512]u8 = undefined;
            var k: usize = 0;
            for (t) |c| {
                if (std.mem.indexOfScalar(u8, root.pem_whitespace, c) != null) continue;
                filtered[k] = c;
                k += 1;
            }
            if (k < t.len) mark(.ignored);
            const want = stdDecode(S, &theirs, filtered[0..k]);
            @memset(&ours, 0);
            const got = C.decodeIgnoring(&ours, t, root.pem_whitespace);
            markVerdict(got);
            if (got) |_| {} else |_| try testing.expect(std.mem.allEqual(u8, &ours, 0));
            try expectSame(C.pads, want, got);
            if (want) |w| try testing.expectEqualSlices(u8, w, try C.decodeIgnoring(ours[0..w.len], t, root.pem_whitespace)) else |_| {}
        },
        // decodePrefix: self-consistency of where it stops.
        3 => {
            const t = textFrom(S, body, &text_buf);
            const r = C.decodePrefix(&ours, t, root.pem_whitespace) catch |e| {
                markVerdict(e);
                return;
            };
            mark(.accept);
            try testing.expect(r.consumed <= t.len);
            var again: [512]u8 = undefined;
            try testing.expectEqualSlices(u8, try C.decodeIgnoring(&again, t[0..r.consumed], root.pem_whitespace), r.data);
            if (r.consumed < t.len) {
                mark(.prefix_short);
                const c = t[r.consumed];
                // It stopped on a character that cannot continue the prefix:
                // never an ignored one, and an alphabet one only after the
                // padding closed the data.
                try testing.expect(std.mem.indexOfScalar(u8, root.pem_whitespace, c) == null);
                if (std.mem.indexOfScalar(u8, t[0..r.consumed], '=') == null)
                    try testing.expect(std.mem.indexOfScalar(u8, &S.Encoder.alphabet_chars, c) == null);
            }
        },
        // encode / encodeWrapped against std.
        4 => {
            const want = S.Encoder.encode(&theirs, body);
            try testing.expectEqualStrings(want, C.encode(&ours, body));
            const eol: root.LineEnding = if (cur.byte() & 1 == 0) .lf else .crlf;
            var w: [1024]u8 = undefined;
            const pick = cur.byte() % 5;
            const ll: usize = switch (pick) {
                0 => 4,
                1 => 8,
                2 => 16,
                3 => 64,
                else => 76,
            };
            const wrapped = switch (pick) {
                0 => C.encodeWrapped(&w, body, 4, eol),
                1 => C.encodeWrapped(&w, body, 8, eol),
                2 => C.encodeWrapped(&w, body, 16, eol),
                3 => C.encodeWrapped(&w, body, 64, eol),
                else => C.encodeWrapped(&w, body, 76, eol),
            };
            var joined: [512]u8 = undefined;
            var j: usize = 0;
            var lines = std.mem.splitSequence(u8, wrapped, eol.bytes());
            while (lines.next()) |line| {
                try testing.expect(line.len <= ll);
                @memcpy(joined[j..][0..line.len], line);
                j += line.len;
            }
            try testing.expectEqualStrings(want, joined[0..j]);
            mark(.wrapped);
        },
        else => unreachable,
    }
}

test "fuzz driver: B64CT_FUZZ" {
    try fuzz_driver.run(harness, .{ .prefix = "B64CT_FUZZ", .name = "b64ct" });
}

test "fuzz harness: 2000 seeds in every test run, and it gets everywhere" {
    reach = @splat(0);
    for (0..2000) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |e| {
            std.debug.print("seed {d}: {t}\n", .{ seed, e });
            return e;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 2000 seeds\n", .{@as(Reach, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}

test "corpus: every seed runs the harness clean" {
    for (seeds) |sd| {
        var smith: testing.Smith = .{ .in = sd };
        var buf: [max_script]u8 = undefined;
        const n = smith.slice(&buf);
        var r: Replay = .{ .data = buf[0..n] };
        try harness(Replay, &r, testing.allocator);
    }
}
