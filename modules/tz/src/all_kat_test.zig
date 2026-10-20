// SPDX-License-Identifier: MIT

//! All-zones differential anchor: every zone of the table against Python's
//! zoneinfo (black box, same pinned tzdata release) over 1970..2050 -- the
//! table era and the POSIX-footer era alike. The vectors are `all_kat.bin`
//! from `tools/gen_all_kat.py` (format documented there); this file decodes
//! them and derives every probe from the recorded state changes:
//!  - the state (offset, DST flag, abbreviation) at the start, at each change
//!    instant, one second before and after it, and midway to the neighbours;
//!  - `nextTransition`/`prevTransition` land on exactly the recorded changes;
//!  - the five local wall-clock times around every offset change resolve as
//!    recorded, and `localToUtc`/`localToUnix` follow each policy.

const std = @import("std");
const testing = std.testing;
const datefmt = @import("datefmt");
const tz = @import("root.zig");

const bin = @embedFile("all_kat.bin");
const range_end: i64 = 2524608000; // 2050-01-01T00:00:00Z

const Reader = struct {
    b: []const u8,
    at: usize = 0,

    fn byte(r: *Reader) u8 {
        defer r.at += 1;
        return r.b[r.at];
    }
    fn varint(r: *Reader) u64 {
        var v: u64 = 0;
        var shift: u6 = 0;
        while (true) {
            const x = r.byte();
            v |= @as(u64, x & 0x7f) << shift;
            if (x & 0x80 == 0) return v;
            shift += 7;
        }
    }
    fn zigzag(r: *Reader) i64 {
        const v = r.varint();
        const half: i64 = @intCast(v >> 1);
        return if (v & 1 == 0) half else -half - 1;
    }
    fn bytes(r: *Reader, n: usize) []const u8 {
        defer r.at += n;
        return r.b[r.at..][0..n];
    }
};

const State = struct { off: i32, dst: bool, abbr: []const u8 };

fn expectState(z: *const tz.Zone, at: i64, want: State, what: []const u8) !void {
    const got = tz.offsetAt(z, at);
    const ab = tz.abbrevAt(z, at);
    if (got.off != want.off or got.dst != want.dst or !std.mem.eql(u8, ab, want.abbr)) {
        std.debug.print("all kat: {s} {s} at {d}: ours {d}/{}/{s}, want {d}/{}/{s}\n", .{
            z.name, what, at, got.off, got.dst, ab, want.off, want.dst, want.abbr,
        });
        return error.AllKatMismatch;
    }
}

fn expectChange(c: ?tz.Change, ts: i64, want: State, z: *const tz.Zone, what: []const u8) !void {
    const got = c orelse {
        std.debug.print("all kat: {s} {s}: no transition, want one at {d}\n", .{ z.name, what, ts });
        return error.AllKatMismatch;
    };
    if (got.ts != ts or got.off != want.off or got.dst != want.dst or !std.mem.eql(u8, got.abbr, want.abbr)) {
        std.debug.print("all kat: {s} {s}: ours {d} {d}/{}/{s}, want {d} {d}/{}/{s}\n", .{
            z.name, what, got.ts, got.off, got.dst, got.abbr, ts, want.off, want.dst, want.abbr,
        });
        return error.AllKatMismatch;
    }
}

const Counts = struct { zones: usize = 0, states: usize = 0, changes: usize = 0, locals: [4]usize = @splat(0) };

fn checkLocal(z: *const tz.Zone, local: i64, code: u2, before: i32, after: i32, counts: *Counts) !void {
    const b: i64 = before;
    const a: i64 = after;
    const want: tz.LocalTime = switch (code) {
        0 => .{ .unique = local - b },
        1 => .{ .unique = local - a },
        2 => .{ .ambiguous = .{ .earlier = local - b, .later = local - a } },
        3 => .{ .nonexistent = .{ .earlier = local - a, .later = local - b } },
    };
    const got = tz.resolveLocal(z, local);
    if (!std.meta.eql(got, want)) {
        std.debug.print("all kat: {s} local {d}: ours {any}, want {any}\n", .{ z.name, local, got, want });
        return error.AllKatMismatch;
    }
    counts.locals[code] += 1;
    // The policies, from the recorded answer.
    const p = datefmt.unixToParts(local);
    for ([_]tz.Disambiguation{ .compatible, .earlier, .later, .reject }) |policy| {
        const expect: tz.LocalToUtcError!i64 = switch (want) {
            .unique => |u| u,
            .ambiguous => |m| switch (policy) {
                .compatible, .earlier => m.earlier,
                .later => m.later,
                .reject => error.AmbiguousLocalTime,
            },
            .nonexistent => |g| switch (policy) {
                .compatible, .later => g.later,
                .earlier => g.earlier,
                .reject => error.NonexistentLocalTime,
            },
        };
        try testing.expectEqual(expect, tz.localToUtc(z, local, policy));
        try testing.expectEqual(expect, tz.localToUnix(z, p.year, p.month, p.day, p.hour, p.minute, p.second, policy));
    }
}

test "all kat: every zone matches Python zoneinfo, 1970..2050 (state, transitions, local time)" {
    var r: Reader = .{ .b = bin };
    try testing.expectEqualStrings("TZKAT1\n", r.bytes(7));
    const rel = r.bytes(r.byte());
    try testing.expectEqualStrings("2026a", rel);
    const n_abbr = r.varint();
    var abbrs: [256][]const u8 = undefined;
    for (0..n_abbr) |i| abbrs[i] = r.bytes(r.byte());

    var seen: [tz.zones.len]bool = @splat(false);
    var counts: Counts = .{};
    const n_traces = r.varint();
    for (0..n_traces) |_| {
        const n_zones = r.varint();
        var names: [128][]const u8 = undefined;
        for (0..n_zones) |i| names[i] = r.bytes(@intCast(r.varint()));
        const off0: i32 = @intCast(r.zigzag());
        const fl0 = r.varint();
        const start: State = .{ .off = off0, .dst = fl0 & 1 != 0, .abbr = abbrs[fl0 >> 1] };
        const n_ch = r.varint();

        // Decode the trace once, check it against each zone sharing it.
        const Ch = struct { ts: i64, st: State, codes: ?u16 };
        var chs: [1024]Ch = undefined;
        var prev_ts: i64 = 0;
        var prev_off = off0;
        for (0..n_ch) |i| {
            prev_ts += @intCast(r.varint());
            const off: i32 = @intCast(r.zigzag());
            const fl = r.varint();
            var codes: ?u16 = null;
            if (off != prev_off) codes = @as(u16, r.byte()) | @as(u16, r.byte()) << 8;
            chs[i] = .{ .ts = prev_ts, .st = .{ .off = off, .dst = fl & 1 != 0, .abbr = abbrs[fl >> 1] }, .codes = codes };
            prev_off = off;
        }

        for (names[0..n_zones]) |name| {
            const z = tz.find(name) orelse {
                std.debug.print("all kat: zone {s} is not in the table\n", .{name});
                return error.AllKatMismatch;
            };
            for (tz.zones, 0..) |tzz, zi| if (std.mem.eql(u8, tzz.name, name)) {
                seen[zi] = true;
            };
            counts.zones += 1;

            try expectState(z, 0, start, "start");
            var before = start;
            var before_ts: i64 = 0;
            for (chs[0..n_ch], 0..) |c, i| {
                const next_ts: i64 = if (i + 1 < n_ch) chs[i + 1].ts else range_end;
                try expectState(z, c.ts, c.st, "at change");
                try expectState(z, c.ts - 1, before, "before change");
                if (c.ts + 1 < next_ts) try expectState(z, c.ts + 1, c.st, "after change");
                try expectState(z, c.ts - @divFloor(c.ts - before_ts, 2), before, "before, midway");
                try expectState(z, c.ts + @divFloor(next_ts - c.ts, 2), c.st, "after, midway");
                counts.states += 5;

                // The same change through the transition API.
                try expectChange(tz.nextTransition(z, if (i == 0) 0 else chs[i - 1].ts), c.ts, c.st, z, "next");
                try expectChange(tz.nextTransition(z, c.ts - 1), c.ts, c.st, z, "next (-1)");
                try expectChange(tz.prevTransition(z, c.ts + 1), c.ts, c.st, z, "prev");
                if (i > 0) {
                    try expectChange(tz.prevTransition(z, c.ts), chs[i - 1].ts, chs[i - 1].st, z, "prev (strict)");
                } else if (tz.prevTransition(z, c.ts)) |p| try testing.expect(p.ts <= 0);
                counts.changes += 1;

                if (c.codes) |codes| {
                    const lo = c.ts + @min(before.off, c.st.off);
                    const hi = c.ts + @max(before.off, c.st.off);
                    const locals = [5]i64{ lo - 1, lo, @divFloor(lo + hi, 2), hi - 1, hi };
                    for (locals, 0..) |l, k| {
                        const code: u2 = @intCast((codes >> @intCast(2 * k)) & 3);
                        try checkLocal(z, l, code, before.off, c.st.off, &counts);
                    }
                }
                before = c.st;
                before_ts = c.ts;
            }
            // Past the last recorded change nothing changes before 2050.
            if (tz.nextTransition(z, if (n_ch == 0) 0 else chs[n_ch - 1].ts)) |nx| try testing.expect(nx.ts >= range_end);
        }
    }
    try testing.expectEqual(r.b.len, r.at);
    for (seen, 0..) |s, i| if (!s) {
        std.debug.print("all kat: table zone {s} has no vectors\n", .{tz.zones[i].name});
        return error.AllKatMismatch;
    };
    try testing.expectEqual(tz.zones.len, counts.zones);
    // Teeth: the vectors cover every kind of local answer in quantity.
    for (counts.locals) |n| try testing.expect(n >= 1000);
    try testing.expect(counts.states > 100_000);
}
