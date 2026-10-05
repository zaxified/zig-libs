// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor for `offsetAt` past the explicit transitions,
//! where the POSIX-TZ footer rule decides. Vectors (`posix_kat.zig`) come
//! from `tools/gen_posix_kat.py`, never from this module:
//!  - `zone_rows`: every zone of the table, 2037..2050, from Python's zoneinfo
//!    (its own footer parser) over the same tzdata release;
//!  - `rule_rows`: POSIX strings no release ships -- Jn and n day forms, rule
//!    times past 24 h or negative, offsets with minutes, rules that cross the
//!    UTC year -- answered by the majority of glibc, Python zoneinfo and Go's
//!    time package (the dissenter, or a three-way split, is in `dissent`).
//!
//! For each zone or string: the offset at the range start, and at every
//! change the new offset at the instant itself, the old one a second before,
//! and the old one halfway since the previous change.

const std = @import("std");
const testing = std.testing;
const tz = @import("root.zig");
const kat = @import("posix_kat.zig");

fn expectRows(rows: []const kat.Row, zoneFor: anytype, label: anytype) !void {
    var failed: usize = 0;
    var prev: ?kat.Row = null;
    for (rows) |r| {
        const z = zoneFor.get(r.i);
        const same_group = if (prev) |p| p.i == r.i else false;
        var checks: [3]struct { at: i64, want: kat.Row } = undefined;
        var n: usize = 0;
        checks[n] = .{ .at = r.ts, .want = r };
        n += 1;
        if (same_group) {
            const p = prev.?;
            checks[n] = .{ .at = r.ts - 1, .want = p };
            n += 1;
            checks[n] = .{ .at = p.ts + @divFloor(r.ts - p.ts, 2), .want = p };
            n += 1;
        }
        for (checks[0..n]) |c| {
            const got = tz.offsetAt(z, c.at);
            if (got.off != c.want.off or got.dst != c.want.dst) {
                if (failed < 20) std.debug.print("posix kat: {s} at {d}: ours {d}/{}, want {d}/{}\n", .{ label.get(r.i), c.at, got.off, got.dst, c.want.off, c.want.dst });
                failed += 1;
            }
        }
        prev = r;
    }
    if (failed != 0) {
        std.debug.print("posix kat: {d} mismatches\n", .{failed});
        return error.PosixKatMismatch;
    }
}

const ZoneByIndex = struct {
    fn get(_: ZoneByIndex, i: u16) *const tz.Zone {
        return tz.find(kat.zone_names[i]).?;
    }
};
const ZoneLabel = struct {
    fn get(_: ZoneLabel, i: u16) []const u8 {
        return kat.zone_names[i];
    }
};

/// A zone with no explicit transitions: `offsetAt` goes straight to the
/// POSIX rule.
const rule_zones = blk: {
    var zs: [kat.rule_strings.len]tz.Zone = undefined;
    for (kat.rule_strings, &zs) |s, *z| z.* = .{ .name = s, .init_off = 0, .init_dst = false, .trans = &.{}, .posix = s };
    break :blk zs;
};
const RuleByIndex = struct {
    fn get(_: RuleByIndex, i: u16) *const tz.Zone {
        return &rule_zones[i];
    }
};
const RuleLabel = struct {
    fn get(_: RuleLabel, i: u16) []const u8 {
        return kat.rule_strings[i];
    }
};

test "posix kat: every zone's footer era matches Python zoneinfo (2037..2050)" {
    try testing.expectEqual(tz.zones.len, kat.zone_names.len);
    try expectRows(&kat.zone_rows, ZoneByIndex{}, ZoneLabel{});
}

test "posix kat: POSIX strings no release ships match the glibc/Python/Go majority" {
    try expectRows(&kat.rule_rows, RuleByIndex{}, RuleLabel{});
}
