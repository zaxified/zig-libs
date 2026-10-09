// SPDX-License-Identifier: MIT

//! Shared plumbing for http's deterministic fuzz driver (added 2026-10-09).
//!
//! The harness BODIES stay in the files whose private items they exercise
//! (`h1.zig`, `h2.zig`, `hpack.zig`, `body.zig`, `range.zig`, `multipart.zig`);
//! each is generic over its source of choices, `fn(comptime S, *S, gpa)`. This
//! file holds what they share: the adapter `testing.fuzz` feeds them through,
//! the reach counters with the N-seed in-suite check, and the input draw.
//!
//! Driver: `HTTP_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and
/// every choice is read from them by a cursor.
pub const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    pub fn valueRangeAtMost(self: *ScriptSource, comptime T: type, at_least: T, at_most: T) T {
        return @intCast(self.cur.ranged(at_least, at_most));
    }
    pub fn value(self: *ScriptSource, comptime T: type) T {
        if (T == bool) return self.cur.byte() & 1 == 1;
        var v: T = 0;
        for (0..@sizeOf(T)) |_| v = std.math.shl(T, v, 8) | self.cur.byte();
        return v;
    }
    pub fn bytes(self: *ScriptSource, buf: []u8) void {
        for (buf) |*b| b.* = self.cur.byte();
    }
    pub fn index(self: *ScriptSource, len: usize) usize {
        return self.cur.ranged(0, @intCast(len - 1));
    }
    /// What `Smith.slice` would have returned for this script: up to
    /// `buf.len` of the remaining script bytes, and their count.
    pub fn slice(self: *ScriptSource, buf: []u8) u32 {
        const left = self.cur.bytes.len -| self.cur.at;
        const n = @min(buf.len, left);
        @memcpy(buf[0..n], self.cur.bytes[self.cur.at..][0..n]);
        self.cur.at += n;
        return @intCast(n);
    }
};

pub const script_cap = 1024;

/// The body of a `testing.fuzz` callback after its first draw: `first` is the
/// bytes the callback drew with `smith.slice` (the callback makes that draw
/// itself, in its own body, so the seed is read before anything else).
pub fn runFrom(comptime harness: anytype, smith: *std.testing.Smith, first: []const u8) anyerror!void {
    _ = smith;
    var src: ScriptSource = .{ .cur = .{ .bytes = first } };
    try harness(ScriptSource, &src, testing.allocator);
}

/// One harness input into `buf`; returns its length. Under `Smith` or a
/// `ScriptSource` (`--fuzz`, `_INPUT` replay) it is exactly `src.slice`. Under
/// the driver's `Rng` half the draws are instead a corpus entry (`seed` frames
/// carry a 4-octet length header, dropped here) with 0-3 octets damaged and
/// maybe truncated: random bytes alone almost never get past the first
/// grammar check of these parsers.
pub fn drawInput(comptime S: type, src: *S, buf: []u8, corpus: []const []const u8) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf);
    if (corpus.len == 0 or !src.value(bool)) return src.slice(buf);
    const entry = corpus[src.index(corpus.len)][4..];
    var n = @min(entry.len, buf.len);
    @memcpy(buf[0..n], entry[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        buf[src.index(n)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Reach counters for one harness file's labels. `mark` also feeds the
/// driver's `REACH` report; `reach` runs `seeds` seeds in the ordinary test
/// binary and fails with `error.HarnessDoesNotReach` if a label never fired.
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

test "drawInput: Rng takes damaged corpus entries, other sources the plain slice" {
    const seeds = [_][]const u8{testkit.fuzz.seed("GET / HTTP/1.1\r\n\r\n")};
    var prng = std.Random.DefaultPrng.init(1);
    var rng: fuzz_driver.Rng = .{ .r = prng.random() };
    var buf: [64]u8 = undefined;
    var from_corpus = false;
    for (0..64) |_| {
        const n = drawInput(fuzz_driver.Rng, &rng, &buf, &seeds);
        if (n >= 4 and std.mem.startsWith(u8, buf[0..n], "GET")) from_corpus = true;
    }
    try testing.expect(from_corpus);

    var script: ScriptSource = .{ .cur = .{ .bytes = "abc" } };
    try testing.expectEqual(@as(usize, 3), drawInput(ScriptSource, &script, &buf, &seeds));
    try testing.expectEqualStrings("abc", buf[0..3]);
}
