// SPDX-License-Identifier: MIT
//! Reference-model tests for the shape predicates: each model is written a different way
//! from the code under test (label splitting and `std.fmt.parseInt` instead of a state
//! machine and a hand-rolled accumulator) and the two are compared on an exhaustive
//! enumeration of short strings over an alphabet of every byte class that matters, then
//! on seeded mutations of long valid ones. Deterministic: no clock, no entropy.
const std = @import("std");
const testing = std.testing;
const argsafe = @import("root.zig");

fn modelHostname(s: []const u8) bool {
    if (s.len == 0 or s.len > 253) return false;
    var it = std.mem.splitScalar(u8, s, '.');
    while (it.next()) |l| {
        if (l.len == 0 or l.len > 63) return false;
        if (l[0] == '-' or l[l.len - 1] == '-') return false;
        for (l) |c| if (!std.ascii.isAlphanumeric(c) and c != '-') return false;
    }
    return true;
}

fn modelUint(s: []const u8, min: u64, max: u64) bool {
    for (s) |c| if (c < '0' or c > '9') return false; // parseInt would take '_' and '+'
    if (s.len > 1 and s[0] == '0') return false;
    const n = std.fmt.parseInt(u64, s, 10) catch return false;
    return n >= min and n <= max;
}

fn modelIfname(s: []const u8) bool {
    if (s.len < 1 or s.len > 15) return false;
    if (std.mem.find(u8, s, "..") != null) return false;
    for (s, 0..) |c, i| {
        const alnum = std.ascii.isAlphanumeric(c);
        if (i == 0 and !alnum) return false;
        if (!alnum and std.mem.findScalar(u8, "._-", c) == null) return false;
    }
    return true;
}

const alphabet = "aZ09-._:/+ \x00\xff";

/// Calls `f` with every string of length 0..max_len over `alphabet`.
fn enumerate(comptime max_len: usize, ctx: anytype, comptime f: fn (@TypeOf(ctx), []const u8) anyerror!void) !void {
    var buf: [max_len]u8 = undefined;
    var idx: [max_len]usize = @splat(0);
    var len: usize = 0;
    while (len <= max_len) : (len += 1) {
        @memset(&idx, 0);
        while (true) {
            for (0..len) |i| buf[i] = alphabet[idx[i]];
            try f(ctx, buf[0..len]);
            var k: usize = 0;
            while (k < len) : (k += 1) {
                idx[k] += 1;
                if (idx[k] < alphabet.len) break;
                idx[k] = 0;
            }
            if (k == len) break;
        }
    }
}

fn compareAll(_: void, s: []const u8) anyerror!void {
    try testing.expectEqual(modelHostname(s), argsafe.isSafeHostname(s));
    try testing.expectEqual(modelIfname(s), argsafe.isSafeIfname(s));
    try testing.expectEqual(modelUint(s, 1, 65535), argsafe.isSafePort(s));
    try testing.expectEqual(modelUint(s, 0, std.math.maxInt(u64)), argsafe.isSafeUint(s, 0, std.math.maxInt(u64)));
    try testing.expectEqual(modelUint(s, 7, 120), argsafe.isSafeUint(s, 7, 120));
}

test "model: hostname, ifname, port and uint agree with the reference models on every short string" {
    try enumerate(5, {}, compareAll); // 13^0 + ... + 13^5 = 402 234 strings
}

test "model: seeded mutations of long valid names and numbers" {
    var prng = std.Random.DefaultPrng.init(0x61726773);
    const r = prng.random();
    var buf: [300]u8 = undefined;
    const pool = "aZ09-._:/+ \x00\xff\"'$`;";
    var n: usize = 0;
    while (n < 20000) : (n += 1) {
        // start from a valid-looking name of random length (edges at 15, 63, 253)
        const lens = [_]usize{ 1, 14, 15, 16, 62, 63, 64, 100, 252, 253, 254 };
        const len = lens[r.uintLessThan(usize, lens.len)];
        for (buf[0..len], 0..) |*c, i| {
            c.* = if (i % 64 == 63 and r.boolean()) '.' else "abcXYZ019-"[r.uintLessThan(usize, 10)];
        }
        var cur: usize = len;
        for (0..r.uintLessThan(usize, 3)) |_| {
            const p = r.uintLessThan(usize, cur + 1);
            const c = pool[r.uintLessThan(usize, pool.len)];
            if (p < cur and r.boolean()) buf[p] = c else if (cur < buf.len) {
                std.mem.copyBackwards(u8, buf[p + 1 .. cur + 1], buf[p..cur]);
                buf[p] = c;
                cur += 1;
            }
        }
        try compareAll({}, buf[0..cur]);
    }
}

test "model: uint at the u64 edges" {
    const max = std.math.maxInt(u64);
    try testing.expect(argsafe.isSafeUint("18446744073709551615", 0, max));
    try testing.expect(!argsafe.isSafeUint("18446744073709551616", 0, max));
    try testing.expect(!argsafe.isSafeUint("99999999999999999999", 0, max));
    try testing.expect(!argsafe.isSafeUint("100000000000000000000", 0, max)); // 21 digits
    try testing.expect(argsafe.isSafeUint("0", 0, 0));
    try testing.expect(!argsafe.isSafeUint("1", 5, 3)); // min > max accepts nothing
    try testing.expect(!argsafe.isSafeUint("", 0, max));
    try testing.expect(!argsafe.isSafeUint("00", 0, max));
    try testing.expect(!argsafe.isSafeUint("-0", 0, max));
}

test "shapes: documented allow/reject tables" {
    const ok_hosts = [_][]const u8{ "localhost", "a", "a.b", "1.2.3.4", "xn--bcher-kva.example", "a-b.c-d", "A.B" };
    for (ok_hosts) |h| try testing.expect(argsafe.isSafeHostname(h));
    const bad_hosts = [_][]const u8{ "", ".", "a.", ".a", "a..b", "-a", "a-", "a.-b", "a-.b", "a b", "a_b", "a/b", "a\x00", "é", "-", "--help" };
    for (bad_hosts) |h| try testing.expect(!argsafe.isSafeHostname(h));
    var big: [260]u8 = undefined;
    @memset(&big, 'a');
    try testing.expect(argsafe.isSafeHostname(big[0..63]));
    try testing.expect(!argsafe.isSafeHostname(big[0..64]));
    for ([_]usize{ 63, 127, 191 }) |dot| big[dot] = '.'; // labels of 63; total 253 is the cap
    try testing.expect(argsafe.isSafeHostname(big[0..253]));
    try testing.expect(!argsafe.isSafeHostname(big[0..254]));
    big[252] = '.';
    try testing.expect(!argsafe.isSafeHostname(big[0..253])); // trailing dot

    for ([_][]const u8{ "1", "80", "65535", "10" }) |p| try testing.expect(argsafe.isSafePort(p));
    for ([_][]const u8{ "", "0", "65536", "080", "+80", "-1", "8 0", "0x50", "1e3", "8_0", "８０" }) |p| try testing.expect(!argsafe.isSafePort(p));

    for ([_][]const u8{ "lo", "eth0", "eth0.100", "br-lan", "wg_0", "123456789012345" }) |n| try testing.expect(argsafe.isSafeIfname(n));
    for ([_][]const u8{ "", ".", "..", "-a", "_a", "a b", "a/b", "a:b", "a@b", "a..b", "1234567890123456", "a\n", "é" }) |n| try testing.expect(!argsafe.isSafeIfname(n));
}
