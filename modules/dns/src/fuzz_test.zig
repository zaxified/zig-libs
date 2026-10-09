// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over dns's wire decoder (added 2026-10-09). Two
//! harnesses, both generic over their source of choices
//! (`fn(comptime S, *S, gpa)`):
//!
//!   - `decode`: arbitrary bytes, as `testing.fuzz` always drew them. Random
//!     bytes almost never carry a header whose counts the body satisfies, so
//!     this one is the "rejected" side;
//!   - `decode-mutated`: one of the six live captures (`goldens.zig`), a few
//!     octets damaged, maybe cut short -- reaches the record parsers.
//!
//! Driver: `DNS_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const message = @import("message.zig");
const goldens = @import("goldens.zig");

pub const Label = enum { rejected, decoded, with_records };
var reach: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@intFromEnum(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and
/// every choice is read from them by a cursor -- so each seed is its own input
/// (a ranged `Smith` draw first collapses every seed to one, `check-fuzz-reach`).
const ScriptSource = struct {
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

fn walk(gpa: std.mem.Allocator, packet: []const u8) !void {
    var msg = message.decode(gpa, packet) catch {
        mark(.rejected);
        return;
    };
    defer msg.deinit();
    mark(.decoded);
    if (msg.answers.len + msg.authorities.len + msg.additionals.len != 0) mark(.with_records);
}

fn decodeHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var packet: [512]u8 = undefined;
    // One `slice` draw -- never `bytes` followed by a ranged length.
    const len: usize = src.slice(&packet);
    try walk(gpa, packet[0..len]);
}

const captures = [_][]const u8{
    goldens.a_example_com,
    goldens.aaaa_example_com,
    goldens.cname_chain_wikipedia,
    goldens.mx_iana_org,
    goldens.txt_example_com,
    goldens.nxdomain_zig_libs_test,
};

fn mutatedHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var packet: [512]u8 = undefined;
    const g = captures[src.index(captures.len)];
    @memcpy(packet[0..g.len], g);
    var len: usize = g.len;
    for (0..src.valueRangeAtMost(u8, 0, 4)) |_| {
        const at = src.index(len);
        packet[at] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) len = src.index(len) + 1;
    try walk(gpa, packet[0..len]);
}

fn fuzzScript(comptime harness: anytype) fn (void, *testing.Smith) anyerror!void {
    return struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            var script: [1024]u8 = undefined;
            const n = smith.slice(&script);
            var src: ScriptSource = .{ .cur = .{ .bytes = script[0..n] } };
            return harness(ScriptSource, &src, testing.allocator);
        }
    }.f;
}

const decode_seeds = [_][]const u8{
    testkit.fuzz.seed(goldens.a_example_com),
    testkit.fuzz.seed(goldens.aaaa_example_com),
    testkit.fuzz.seed(goldens.cname_chain_wikipedia),
    testkit.fuzz.seed(goldens.mx_iana_org),
    testkit.fuzz.seed(goldens.txt_example_com),
    testkit.fuzz.seed(goldens.nxdomain_zig_libs_test),
    testkit.fuzz.seed("\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++ "\x01a\xc0\x0c" ++ "\x00\x01\x00\x01"), // pointer cycle
    testkit.fuzz.seed("\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00" ++ "\x01a\x00\x00\x01"), // hostile ANCOUNT
    testkit.fuzz.seed("\x00\x00\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++ "\x01a\x00" ++ "\x00\x10\x00\x01" ++ "\x00\x00\x00\x00" ++ "\x00\x03" ++ "\x09ab"), // TXT string past RDATA
};

test "fuzz: decoder never crashes or leaks on arbitrary bytes" {
    try testing.fuzz({}, fuzzScript(decodeHarness), .{ .corpus = &decode_seeds });
}

test "fuzz: decoder never crashes or leaks on damaged captures" {
    try testing.fuzz({}, fuzzScript(mutatedHarness), .{});
}

test "fuzz driver: DNS_FUZZ" {
    try fuzz_driver.run(decodeHarness, .{ .prefix = "DNS_FUZZ", .name = "dns-decode" });
    try fuzz_driver.run(mutatedHarness, .{ .prefix = "DNS_FUZZ", .name = "dns-decode-mutated" });
}

test "fuzz harness: 500 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..500) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        decodeHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("dns decode seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        mutatedHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("dns mutated seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 500 seeds\n", .{@as(Label, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}
