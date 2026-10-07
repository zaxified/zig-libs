// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over netaddr's text parsers (added 2026-10-07 with
//! the single-pass `parseIp4`/`parseIp6`): every parser of untrusted text must
//! never trap, and whatever parses must survive a round trip — format it, parse
//! the text again, get the same value back. The round trip is the oracle: a
//! parser that accepts a malformed literal, or keeps the wrong groups, produces
//! a value whose canonical text parses to something else, or not at all.
//!
//! Inputs are built from the tokens an address is made of (`:`, `::`, `.`,
//! `%zone`, `/bits`, `[`, `]`, decimal and hex numbers) and from valid
//! addresses with one byte changed, so most runs reach the parsers' interiors
//! instead of failing at the first byte.
//!
//! Driver: `NETADDR_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT` as documented there). 500 seeds also run in every
//! ordinary test run.

const std = @import("std");
const testing = std.testing;
const netaddr = @import("root.zig");
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;

const Label = enum { ip4, ip6, prefix, zoned, addr_port, host_port, mutated_valid };
var reach: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@intFromEnum(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

fn append(buf: []u8, len: *usize, s: []const u8) void {
    if (len.* + s.len > buf.len) return;
    @memcpy(buf[len.*..][0..s.len], s);
    len.* += s.len;
}

fn buildText(comptime S: type, src: *S, buf: []u8) []const u8 {
    var len: usize = 0;
    if (src.valueRangeAtMost(u8, 0, 2) == 0) {
        // A valid address (sometimes with a prefix length, zone or port),
        // then at most one byte changed.
        var a: [16]u8 = undefined;
        src.bytes(&a);
        if (src.value(bool)) @memset(a[src.index(8)..][0..src.index(8)], 0);
        const ip: netaddr.Ip = if (src.value(bool)) .{ .v4 = a[0..4].* } else .{ .v6 = a };
        var fb: [netaddr.max_ip_text_len]u8 = undefined;
        const t = netaddr.formatIp(ip, &fb);
        switch (src.valueRangeAtMost(u8, 0, 3)) {
            0 => append(buf, &len, t),
            1 => {
                append(buf, &len, t);
                var nb: [8]u8 = undefined;
                append(buf, &len, std.fmt.bufPrint(&nb, "/{d}", .{src.valueRangeAtMost(u8, 0, 130)}) catch unreachable);
            },
            2 => {
                append(buf, &len, "[");
                append(buf, &len, t);
                var nb: [8]u8 = undefined;
                append(buf, &len, std.fmt.bufPrint(&nb, "]:{d}", .{src.value(u16)}) catch unreachable);
            },
            else => {
                append(buf, &len, t);
                append(buf, &len, "%eth0");
            },
        }
        if (len > 0 and src.value(bool)) {
            const tokens = ":.%/[]0f9g ";
            buf[src.index(len)] = tokens[src.index(tokens.len)];
        }
        mark(.mutated_valid);
        return buf[0..len];
    }
    const n = src.valueRangeAtMost(u8, 0, 24);
    for (0..n) |_| {
        var nb: [8]u8 = undefined;
        const tok: []const u8 = switch (src.valueRangeAtMost(u8, 0, 11)) {
            0 => ":",
            1 => "::",
            2 => ".",
            3 => "%",
            4 => "/",
            5 => "[",
            6 => "]",
            7 => std.fmt.bufPrint(&nb, "{d}", .{src.valueRangeAtMost(u16, 0, 300)}) catch unreachable,
            8 => std.fmt.bufPrint(&nb, "{x}", .{src.valueRangeAtMost(u32, 0, 0x1ffff)}) catch unreachable,
            9 => "ffff",
            10 => blk: {
                const k = src.valueRangeAtMost(u8, 1, 3);
                src.bytes(nb[0..k]);
                break :blk nb[0..k];
            },
            else => "0",
        };
        append(buf, &len, tok);
    }
    return buf[0..len];
}

pub fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [96]u8 = undefined;
    const text = buildText(S, src, &buf);

    if (netaddr.parseIp(text)) |ip| {
        switch (ip) {
            .v4 => mark(.ip4),
            .v6 => mark(.ip6),
        }
        var fb: [netaddr.max_ip_text_len]u8 = undefined;
        const canon = netaddr.formatIp(ip, &fb);
        const back = netaddr.parseIp(canon) orelse return error.CanonicalTextDoesNotParse;
        if (!back.eql(ip)) return error.IpRoundTrip;
    }
    if (netaddr.parsePrefix(text)) |p| {
        mark(.prefix);
        var fb: [netaddr.max_prefix_text_len]u8 = undefined;
        const back = netaddr.parsePrefix(netaddr.formatPrefix(p, &fb)) orelse return error.CanonicalTextDoesNotParse;
        if (!back.eql(p)) return error.PrefixRoundTrip;
    }
    if (netaddr.parseIpZoned(text)) |z| {
        mark(.zoned);
        var fb: [netaddr.max_zoned_ip_text_len]u8 = undefined;
        const back = netaddr.parseIpZoned(netaddr.formatIpZoned(z, &fb)) orelse return error.CanonicalTextDoesNotParse;
        if (back.compare(z) != .eq) return error.ZonedRoundTrip;
    }
    if (netaddr.parseAddrPort(text)) |ap| {
        mark(.addr_port);
        var fb: [netaddr.max_addr_port_text_len]u8 = undefined;
        const back = netaddr.parseAddrPort(netaddr.formatAddrPort(ap, &fb)) orelse return error.CanonicalTextDoesNotParse;
        if (back.compare(ap) != .eq) return error.AddrPortRoundTrip;
    }
    if (netaddr.parseHostPort(text) != null) mark(.host_port);
    _ = netaddr.parsePrefixOrAddr(text);
    _ = netaddr.parseIpRange(text);
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
};

fn fuzzOne(_: void, smith: *testing.Smith) anyerror!void {
    var script: [256]u8 = undefined;
    const n = smith.slice(&script);
    var src: ScriptSource = .{ .cur = .{ .bytes = script[0..n] } };
    return harness(ScriptSource, &src, testing.allocator);
}

test "fuzz: text parsers never trap, and what parses round-trips" {
    try testing.fuzz({}, fuzzOne, .{});
}

test "fuzz driver: NETADDR_FUZZ" {
    try fuzz_driver.run(harness, .{ .prefix = "NETADDR_FUZZ", .name = "netaddr" });
}

test "fuzz harness: 500 seeds in every test run, and it gets everywhere" {
    reach = @splat(0);
    for (0..500) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |e| {
            std.debug.print("seed {d}: {t}\n", .{ seed, e });
            return e;
        };
    }
    // Reach before verdict: every round trip had something to judge.
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 500 seeds\n", .{@as(Label, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}
