// SPDX-License-Identifier: MIT
//! No-panic sweep (wave GN) regression tests for the tz module.

const std = @import("std");
const tz = @import("root.zig");
const testing = std.testing;

const min_i64 = std.math.minInt(i64);
const max_i64 = std.math.maxInt(i64);

// An instant whose year does not fit `DateParts.year` (i32) saturates it;
// the `year +/- 1` window arithmetic around it used to overflow.
test "nextTransition / prevTransition at the i64 edges never panic (sweep TZ-1)" {
    const edges = [_]i64{ min_i64, min_i64 + 1, max_i64, max_i64 - 1, 1 << 62, -(1 << 62) };
    for ([_][]const u8{ "Europe/Prague", "UTC", "America/Sao_Paulo", "Asia/Kolkata" }) |name| {
        const z = tz.find(name).?;
        for (edges) |e| {
            _ = tz.nextTransition(z, e);
            _ = tz.prevTransition(z, e);
        }
    }
}

test "resolveLocal / localToUtc at the i64 edges never panic (sweep TZ-1)" {
    const edges = [_]i64{ min_i64, min_i64 + 1, max_i64, max_i64 - 1, 1 << 62, -(1 << 62) };
    for ([_][]const u8{ "Europe/Prague", "UTC", "America/New_York" }) |name| {
        const z = tz.find(name).?;
        for (edges) |e| {
            _ = tz.resolveLocal(z, e);
            for ([_]tz.Disambiguation{ .compatible, .earlier, .later, .reject }) |p|
                _ = tz.localToUtc(z, e, p) catch {};
            _ = tz.offsetAt(z, e);
            _ = tz.abbrevAt(z, e);
        }
    }
}

test "hand-built zone with a footer at the i64 edges never panics (sweep TZ-1)" {
    const z: tz.Zone = .{ .name = "Test/edge", .init_off = 0, .init_dst = false, .trans = &.{}, .posix = "AAA+1BBB-2,M3.5.0,M10.5.0/3" };
    for ([_]i64{ min_i64, max_i64, 1 << 62, -(1 << 62) }) |e| {
        _ = tz.nextTransition(&z, e);
        _ = tz.prevTransition(&z, e);
        _ = tz.resolveLocal(&z, e);
    }
}

test "abbrevAt: a hand-built state with an abbreviation index past the table is empty (sweep TZ-2)" {
    const trans = [_]tz.Transition{.{ .ts = 100, .off = 3600, .dst = false, .abbr = std.math.maxInt(u16) }};
    const z: tz.Zone = .{ .name = "Test/abbr", .init_off = 0, .init_dst = false, .init_abbr = std.math.maxInt(u16), .trans = &trans, .posix = "" };
    try testing.expectEqualStrings("", tz.abbrevAt(&z, 0));
    try testing.expectEqualStrings("", tz.abbrevAt(&z, 200));
    try testing.expectEqualStrings("", tz.nextTransition(&z, 0).?.abbr);
    try testing.expectEqualStrings("", tz.prevTransition(&z, 200).?.abbr);
}

test "a hand-built footer with a Jn rule of minInt(i32) never panics (sweep TZ-4)" {
    const f: tz.Footer = .{
        .std_abbr = "AAA",
        .utc_std = 0,
        .dst = .{
            .abbr = "BBB",
            .utc_dst = 3600,
            .start = .{ .julian = std.math.minInt(i32) },
            .start_time = 0,
            .end = .{ .julian = std.math.maxInt(i32) },
            .end_time = 0,
        },
    };
    const z: tz.Zone = .{ .name = "Test/julian", .init_off = 0, .init_dst = false, .trans = &.{}, .posix = "", .footer = &f };
    for ([_]i64{ 0, 1 << 40, -(1 << 40) }) |e| {
        _ = tz.offsetAt(&z, e);
        _ = tz.nextTransition(&z, e);
    }
}
