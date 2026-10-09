// SPDX-License-Identifier: MIT

//! Shared plumbing for xmlenc's deterministic fuzz driver (added 2026-10-09).
//!
//! The harness BODY stays in `test_roundtrip.zig`, beside the encryption helpers and the
//! private algorithm tables it uses; it is generic over its source of choices,
//! `fn(comptime S, *S, gpa)`, and `testing.fuzz` hands it a
//! `std.testing.Smith` (it is byte-first: the first draw is one `slice`, the
//! script every other choice is read from, so corpus seeds replay as before).
//! This file holds what is shared: the reach counters with the N-seed in-suite
//! check, and the fixture pre-warm.
//!
//! Driver: `XMLENC_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name -- `decrypt` --, `_MS`, `_SEEDFILE`, `_INPUT` as
//! documented there).

const std = @import("std");
const testing = std.testing;
pub const fuzz_driver = @import("testkit").fuzz.driver;

/// True when the driver was asked to run (or replay) with `prefix`: fixtures
/// that cost key generation and RSA operations are built up front then, inside no watchdog, and
/// not at all in an ordinary test run.
pub fn driverRequested(comptime prefix: []const u8) bool {
    return testing.environ.getPosix(prefix) != null or testing.environ.getPosix(prefix ++ "_INPUT") != null;
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
