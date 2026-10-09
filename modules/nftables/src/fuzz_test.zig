// SPDX-License-Identifier: MIT

//! Shared plumbing for nftables's deterministic fuzz driver (added 2026-10-09).
//!
//! The harness BODIES stay in the files whose private items they exercise;
//! each is generic over its source of choices, `fn(comptime S, *S, gpa)`, and
//! `testing.fuzz` hands it a `std.testing.Smith` directly (every harness here
//! is byte-first: its first draw is one `slice`, so corpus seeds replay as
//! before). This file holds what they share: the reach counters with the
//! N-seed in-suite check, and the input draw.
//!
//! Driver: `NFTABLES_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY` selects
//! a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;

/// One harness input into `buf`; returns its length. Under `Smith` (`--fuzz`,
/// `_INPUT` replay) it is exactly `src.slice`. Under the driver's `Rng` half
/// the draws are instead a corpus entry (frames carry a little-endian u32
/// length header; the octets after the frame, if any, are dropped) with 0-3
/// octets damaged and maybe truncated: random bytes alone almost never get
/// past the first grammar check of these parsers.
pub fn drawInput(comptime S: type, src: *S, buf: []u8, corpus: []const []const u8) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf);
    if (corpus.len == 0 or !src.value(bool)) return src.slice(buf);
    const entry = corpus[src.index(corpus.len)];
    const flen = std.mem.readInt(u32, entry[0..4], .little);
    const frame = entry[4..][0..@min(flen, entry.len - 4)];
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        buf[src.index(n)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// `Smith.eos` where the source has it, else a coin flip (the driver's `Rng`).
pub fn eos(src: anytype) bool {
    return if (@hasDecl(@TypeOf(src.*), "eos")) src.eos() else src.value(bool);
}

/// `testing.fuzz`'s source: the harness's FIRST `slice` is the one draw made
/// here, up front (bytes first, which is what `check-fuzz-reach` wants to see);
/// every other draw goes to the same `Smith` afterwards, so a corpus entry's
/// tail (knob words after the frame) is read exactly as before.
pub const SplitSource = struct {
    first: []const u8,
    taken: bool = false,
    rest: *std.testing.Smith,

    pub fn valueRangeAtMost(self: *SplitSource, comptime T: type, at_least: T, at_most: T) T {
        return self.rest.valueRangeAtMost(T, at_least, at_most);
    }
    pub fn value(self: *SplitSource, comptime T: type) T {
        return self.rest.value(T);
    }
    pub fn eos(self: *SplitSource) bool {
        return self.rest.eos();
    }
    pub fn bytes(self: *SplitSource, buf: []u8) void {
        self.rest.bytes(buf);
    }
    pub fn index(self: *SplitSource, len: usize) usize {
        return self.rest.index(len);
    }
    pub fn slice(self: *SplitSource, buf: []u8) u32 {
        if (self.taken) return self.rest.slice(buf);
        self.taken = true;
        const n = @min(buf.len, self.first.len);
        @memcpy(buf[0..n], self.first[0..n]);
        return @intCast(n);
    }
};

pub const script_cap = 4096;

/// The body of a `testing.fuzz` callback after its first draw: `first` is the
/// bytes the callback drew with `smith.slice` (the callback makes that draw
/// itself, in its own body, so the seed is read before anything else).
pub fn runFrom(comptime harness: anytype, smith: *std.testing.Smith, first: []const u8) anyerror!void {
    var src: SplitSource = .{ .first = first, .rest = smith };
    try harness(SplitSource, &src, testing.allocator);
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

test "drawInput: Rng takes damaged corpus entries, Smith the plain slice" {
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

    var smith: std.testing.Smith = .{ .in = seeds[0] };
    try testing.expectEqual(@as(usize, 18), drawInput(std.testing.Smith, &smith, &buf, &seeds));
    try testing.expectEqualStrings("GET /", buf[0..5]);
}
