// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over tz's two existing `testing.fuzz` harnesses
//! (`find`, and the POSIX-TZ footer grammar through `offsetAt`; added
//! 2026-10-09). The bodies live here, generic over their source of choices
//! (`fn(comptime S, *S, gpa)`); `root.zig`'s `testing.fuzz` tests feed them
//! through the cursor adapter below, the driver feeds them a PRNG.
//!
//! Driver: `TZ_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const tz = @import("root.zig");

pub const Label = enum { find_miss, find_hit, generated_dst, generated_std };
var reach: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@intFromEnum(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and
/// every choice is read from them by a cursor -- so each seed is its own input.
pub const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

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

/// `find` never panics on arbitrary zone-name bytes.
pub fn findHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [64]u8 = undefined;
    const len: usize = src.slice(&buf);
    const name = nameFromScript(buf[0..len], &buf);
    if (tz.find(name)) |z| {
        // A hit must be the zone asked for, never a neighbour of the search.
        if (!std.mem.eql(u8, z.name, name)) return error.FindReturnedWrongZone;
        mark(.find_hit);
    } else mark(.find_miss);
}

/// Octet 0 printable (every zone name, so the `--fuzz` corpus in root.zig
/// replays unchanged): the bytes are the name verbatim. A control octet
/// (< 0x20, 1 in 8 under the driver): a real zone name picked by octets 1-2, then (octet 3 mod 4) 0/1 untouched, 2 one octet replaced,
/// 3 truncated -- so hits, near misses and neighbours of the binary search are
/// all reached from random bytes, not only from the `--fuzz` corpus.
fn nameFromScript(script: []const u8, buf: *[64]u8) []const u8 {
    if (script.len == 0) return script;
    if (script[0] >= 0x20) return script;
    var cur: testkit.fuzz.Cursor = .{ .bytes = script[1..] };
    const real = tz.zones[cur.word() % tz.zones.len].name;
    const n = @min(real.len, buf.len);
    var out: [64]u8 = undefined;
    @memcpy(out[0..n], real[0..n]);
    switch (cur.byte() % 4) {
        2 => if (n != 0) {
            out[cur.byte() % n] = cur.byte();
        },
        3 => if (n != 0) {
            const cut = cur.byte() % n;
            @memcpy(buf[0..cut], out[0..cut]);
            return buf[0..cut];
        },
        else => {},
    }
    @memcpy(buf[0..n], out[0..n]);
    return buf[0..n];
}

/// `offsetAt`'s POSIX-TZ footer parser never panics: the drawn bytes as a
/// footer verbatim, then the same bytes as a script for the grammar generator.
pub fn footerHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [128]u8 = undefined;
    const len: usize = src.slice(&buf);
    const drawn = buf[0..len];
    var cur: testkit.fuzz.Cursor = .{ .bytes = drawn };

    // (a) The drawn bytes AS a footer, verbatim.
    const z = zoneWithFooter(drawn);
    // (A verbatim footer reaching DST is not a label: random bytes are not a
    // POSIX-TZ string; the corpus replay under `--fuzz` carries those.)
    _ = tz.offsetAt(&z, footerInstant(&cur));

    // (b) The same bytes as a SCRIPT for the grammar generator. The
    // generator's choices come from the `Cursor`, not from later draws.
    var gen_buf: [128]u8 = undefined;
    const gen = buildPosixFooter(&cur, &gen_buf);
    const gz = zoneWithFooter(gen);
    if (tz.offsetAt(&gz, footerInstant(&cur)).dst) mark(.generated_dst) else mark(.generated_std);
}

pub fn zoneWithFooter(posix: []const u8) tz.Zone {
    return .{
        .name = "Fuzz/Zone",
        .init_off = 0,
        .init_dst = false,
        .trans = &[_]tz.Transition{},
        .posix = posix,
    };
}

/// A wide but bounded instant, in whole years, derived from the drawn bytes.
/// Far enough past/before epoch to reach every rule form's year math without
/// courting unrelated `i64*86400` overflow in datefmt, which is not this
/// module's decode surface.
pub fn footerInstant(cur: *testkit.fuzz.Cursor) i64 {
    // ⚠ Two components, not one. A whole-year step alone lands every instant
    // within a few days of January, which is never DST in the northern
    // hemisphere — the day-of-year term is what makes the summer branch of a
    // `M3.5.0,M10.5.0` rule reachable at all.
    const years = @as(i64, cur.ranged(0, 200)) - 100;
    const days = @as(i64, cur.ranged(0, 364));
    return years * (365 * 86400) + days * 86400;
}

/// Assembles `stdoffset[dst[offset][,start[/time],end[/time]]]` — the grammar
/// `posixOffset` walks — with each optional piece independently present or
/// absent, so both the "no DST" short-circuit and the full two-rule path get
/// exercised, not just whichever one arbitrary bytes happen to stumble into.
pub fn buildPosixFooter(cur: *testkit.fuzz.Cursor, buf: []u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    writeAbbrev(cur, &w);
    writeFooterOffset(cur, &w);
    if (cur.byte() & 1 == 0) return w.buffered();
    writeAbbrev(cur, &w);
    if (cur.byte() & 1 == 1) writeFooterOffset(cur, &w);
    if (cur.byte() & 1 == 0) return w.buffered();
    w.writeByte(',') catch return w.buffered();
    writeRuleText(cur, &w);
    writeRuleTimeText(cur, &w);
    w.writeByte(',') catch return w.buffered();
    writeRuleText(cur, &w);
    writeRuleTimeText(cur, &w);
    return w.buffered();
}

fn writeAbbrev(cur: *testkit.fuzz.Cursor, w: *std.Io.Writer) void {
    const letters = "ABCXYZ";
    const len = cur.ranged(1, 4);
    var i: u32 = 0;
    while (i < len) : (i += 1) {
        w.writeByte(letters[cur.ranged(0, letters.len - 1)]) catch return;
    }
}

fn writeFooterOffset(cur: *testkit.fuzz.Cursor, w: *std.Io.Writer) void {
    if (cur.byte() & 1 == 1) w.writeByte(if (cur.byte() & 1 == 1) '+' else '-') catch return;
    w.print("{d}", .{cur.ranged(0, 23)}) catch return;
    if (cur.byte() & 1 == 0) return;
    w.print(":{d:0>2}", .{cur.ranged(0, 59)}) catch return;
    if (cur.byte() & 1 == 1) w.print(":{d:0>2}", .{cur.ranged(0, 59)}) catch return;
}

fn writeRuleText(cur: *testkit.fuzz.Cursor, w: *std.Io.Writer) void {
    switch (cur.ranged(0, 2)) {
        0 => w.print("M{d}.{d}.{d}", .{
            cur.ranged(1, 12),
            cur.ranged(1, 5),
            cur.ranged(0, 6),
        }) catch {},
        1 => w.print("J{d}", .{cur.ranged(1, 365)}) catch {},
        else => w.print("{d}", .{cur.ranged(0, 365)}) catch {},
    }
}

fn writeRuleTimeText(cur: *testkit.fuzz.Cursor, w: *std.Io.Writer) void {
    if (cur.byte() & 1 == 0) return;
    w.writeByte('/') catch return;
    writeFooterOffset(cur, w);
}

test "fuzz driver: TZ_FUZZ" {
    try fuzz_driver.run(findHarness, .{ .prefix = "TZ_FUZZ", .name = "tz-find" });
    try fuzz_driver.run(footerHarness, .{ .prefix = "TZ_FUZZ", .name = "tz-footer" });
}

test "fuzz harness: 500 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..500) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        findHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("tz find seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        footerHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("tz footer seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 500 seeds\n", .{@as(Label, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}
