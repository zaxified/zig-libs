// SPDX-License-Identifier: MIT

//! Shared plumbing for ocspcache's deterministic fuzz driver (added 2026-10-09).
//!
//! The harness BODIES stay in `root.zig`, beside the private transport and
//! DER builders they use; each is generic over its source of choices,
//! `fn(comptime S, *S, gpa)`, and `testing.fuzz` hands it a `std.testing.Smith`
//! (both harnesses are byte-first: their first draw is one `slice`, so corpus
//! seeds replay as before). This file holds the reach counters with the N-seed
//! in-suite check.
//!
//! Driver: `OCSPCACHE_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver;
//! `_ONLY` selects a harness by name -- `aia`, `refresh` --, `_MS`, `_SEEDFILE`,
//! `_INPUT` as documented there).

const std = @import("std");
const testing = std.testing;
pub const fuzz_driver = @import("testkit").fuzz.driver;

/// One harness input into `buf`; returns its length. Under `Smith` (`--fuzz`,
/// `_INPUT` replay) it is exactly `src.slice`. Under the driver's `Rng` half
/// the draws are instead a corpus entry (frames carry a little-endian u32
/// length header; the octets after the frame, if any, are dropped) with 0-3
/// octets damaged and maybe truncated: random bytes alone never spell a URL
/// behind an AccessDescription.
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

test "drawInput: Rng takes damaged corpus entries, Smith the plain slice" {
    const seeds = [_][]const u8{@import("testkit").fuzz.seed("http://ocsp.example.org/")};
    var prng = std.Random.DefaultPrng.init(1);
    var rng: fuzz_driver.Rng = .{ .r = prng.random() };
    var buf: [64]u8 = undefined;
    var from_corpus = false;
    for (0..64) |_| {
        const n = drawInput(fuzz_driver.Rng, &rng, &buf, &seeds);
        if (n >= 8 and std.mem.startsWith(u8, buf[0..n], "http:")) from_corpus = true;
    }
    try testing.expect(from_corpus);

    var smith: std.testing.Smith = .{ .in = seeds[0] };
    try testing.expectEqual(@as(usize, 24), drawInput(std.testing.Smith, &smith, &buf, &seeds));
    try testing.expectEqualStrings("http:", buf[0..5]);
}
