// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver support for l2disco's four parser harnesses
//! (added 2026-10-09). The harnesses stay in `dhcp.zig`, `lldp.zig`, `arp.zig`
//! and `cdp.zig` (they use those files' private walkers and corpora), now
//! generic over their source of choices (`fn(comptime S, *S, gpa)`); this file
//! holds what they share: the cursor adapter `testing.fuzz` feeds them
//! through, the reach counters, the "damaged corpus entry" input builder and
//! the in-suite reach run.
//!
//! Driver: `L2DISCO_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there). Random bytes almost
//! never form a frame, so every parser has a "mutated" twin: a corpus entry, a
//! few octets damaged, maybe cut short.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;

pub const Label = enum { rejected, parsed };
var reach: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

pub fn mark(comptime l: Label) void {
    reach[@intFromEnum(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and
/// every choice is read from them by a cursor -- so each seed is its own input
/// (a ranged `Smith` draw first collapses every seed to one, `check-fuzz-reach`).
pub const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    pub fn valueRangeAtMost(self: *ScriptSource, comptime T: type, at_least: T, at_most: T) T {
        return @intCast(self.cur.ranged(at_least, at_most));
    }
    pub fn value(self: *ScriptSource, comptime T: type) T {
        return switch (T) {
            bool => self.cur.byte() & 1 == 1,
            u8 => self.cur.byte(),
            u16 => self.cur.word(),
            else => @compileError("ScriptSource.value: unsupported type"),
        };
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

/// `testing.fuzz`'s callback for a harness; `max` bounds the script (the
/// first `slice` draw) and so the largest input a corpus seed may carry.
pub fn fuzzScript(comptime harness: anytype, comptime max: usize) fn (void, *testing.Smith) anyerror!void {
    return struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            var script: [max]u8 = undefined;
            const n = smith.slice(&script);
            var src: ScriptSource = .{ .cur = .{ .bytes = script[0..n] } };
            return harness(ScriptSource, &src, testing.allocator);
        }
    }.f;
}

/// A corpus entry (a `Smith.slice` frame) read into `buf`, a few octets
/// damaged -- half of them in the first 24, where the headers live -- and
/// maybe cut short.
pub fn damaged(comptime S: type, src: *S, entries: []const []const u8, buf: []u8) []const u8 {
    var smith: testing.Smith = .{ .in = entries[src.index(entries.len)] };
    var len: usize = smith.slice(buf);
    if (len == 0) return buf[0..0];
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        const at = if (src.value(bool)) src.index(@min(len, 24)) else src.index(len);
        buf[at] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) len = src.index(len) + 1;
    return buf[0..len];
}

/// The in-suite run: `n` seeds through every harness, which must reach every
/// label (rejected and parsed) between them.
pub fn checkReach(comptime name: []const u8, comptime harnesses: anytype, n: usize) !void {
    reach = @splat(0);
    inline for (harnesses, 0..) |h, which| {
        for (0..n) |sd| {
            var prng = std.Random.DefaultPrng.init(sd);
            var rng: fuzz_driver.Rng = .{ .r = prng.random() };
            h(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                std.debug.print(name ++ " harness {d} seed {d}: {t}\n", .{ which, sd, err });
                return err;
            };
        }
    }
    for (reach, 0..) |c, i| if (c == 0) {
        std.debug.print(name ++ " reach: label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), n });
        return error.HarnessDoesNotReach;
    };
}
