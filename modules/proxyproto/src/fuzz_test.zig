// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for proxyproto (added 2026-11-15):
//! `PROXYPROTO_FUZZ=<runs>[,<first seed>]` (testkit's driver; `_ONLY` selects a
//! harness by name). Harness `proxyproto-parse`: inputs are random bytes, a
//! genuine header from the writer (every family, with TLVs and CRC) with 0-3
//! damaged octets and maybe truncated, or an untouched one. Checks: `parse`
//! never panics; a header's `consumed` is within the input and re-parsing
//! exactly those bytes gives the same result; every shorter prefix of an
//! accepted header asks for more; an untouched genuine header parses back to
//! what was written; the reader over a chunked, possibly failing transport
//! agrees with `parse` and consumes nothing on any non-header outcome.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const netaddr = @import("netaddr");
pub const fuzz_driver = testkit.fuzz.driver;
const pp = @import("root.zig");

pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@backingInt(l)] += 1;
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
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @fromBackingInt(@intCast(i))), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

pub fn smithWrap(comptime harness: anytype) fn (void, *std.testing.Smith) anyerror!void {
    return struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            try harness(std.testing.Smith, smith, testing.allocator);
        }
    }.f;
}

const Mark = Marker(enum { random_bytes, genuine, damaged, v1_header, v2_header, local_header, absent, need_more, malformed, too_large, bad_crc, prefix_checked, roundtrip, read_agrees, read_fault, read_untrusted, tlv_walked });

fn drawIp(comptime S: type, src: *S, v6: bool) netaddr.Ip {
    if (v6) {
        var b: [16]u8 = undefined;
        src.bytes(&b);
        return .{ .v6 = b };
    }
    var b: [4]u8 = undefined;
    src.bytes(&b);
    return .{ .v4 = b };
}

fn drawAddr(comptime S: type, src: *S, v6: bool) pp.Addr {
    return .{ .inet = .{ .ip = drawIp(S, src, v6), .port = src.value(u16) } };
}

/// A genuine header (written by the module's own writer) in `out`; the header
/// value written and its length.
fn genuine(comptime S: type, src: *S, out: []u8, store: *[216]u8, tl: *[96]u8) struct { h: pp.Header, n: usize, v1: bool, area: usize } {
    var w: std.Io.Writer = .fixed(out);
    const kind = src.valueRangeAtMost(u8, 0, 9);
    var h: pp.Header = .{};
    if (kind < 2) {
        h.version = 1;
        if (kind == 0) {
            const v6 = src.valueRangeAtMost(u8, 0, 1) == 1;
            h.family = if (v6) .tcp6 else .tcp4;
            h.source = drawAddr(S, src, v6);
            h.destination = drawAddr(S, src, v6);
        }
        pp.writeV1(&w, h) catch unreachable;
        return .{ .h = h, .n = w.buffered().len, .v1 = true, .area = 0 };
    }
    switch (src.valueRangeAtMost(u8, 0, 6)) {
        0 => h.family = .tcp4,
        1 => h.family = .udp4,
        2 => h.family = .tcp6,
        3 => h.family = .udp6,
        4 => h.family = .unix_stream,
        5 => h.family = .unix_dgram,
        else => h.family = .unspec,
    }
    if (src.valueRangeAtMost(u8, 0, 9) == 0) h.command = .local;
    switch (h.family) {
        .tcp4, .udp4, .tcp6, .udp6 => {
            const v6 = h.family == .tcp6 or h.family == .udp6;
            h.source = drawAddr(S, src, v6);
            h.destination = drawAddr(S, src, v6);
        },
        .unix_stream, .unix_dgram => {
            src.bytes(store);
            for (store) |*c| if (c.* == 0) {
                c.* = 'z';
            };
            const a: usize = src.valueRangeAtMost(u8, 0, 108);
            const b: usize = src.valueRangeAtMost(u8, 0, 108);
            h.source = .{ .unix = store[0..a] };
            h.destination = .{ .unix = store[108..][0..b] };
        },
        .unspec => {},
    }
    var tn: usize = 0;
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        const l = src.valueRangeAtMost(u8, 0, 20);
        if (tn + 3 + l > tl.len) break;
        var t = src.value(u8);
        if (t == pp.tlv_type.crc32c) t = pp.tlv_type.noop;
        tl[tn] = t;
        std.mem.writeInt(u16, tl[tn + 1 ..][0..2], l, .big);
        src.bytes(tl[tn + 3 ..][0..l]);
        tn += 3 + l;
    }
    const crc = src.valueRangeAtMost(u8, 0, 1) == 1;
    if (crc) pp.writeV2Crc(&w, h, tl[0..tn]) catch unreachable else pp.writeV2(&w, h, tl[0..tn]) catch unreachable;
    return .{ .h = h, .n = w.buffered().len, .v1 = false, .area = tn };
}

fn fuzzParse(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [700]u8 = undefined;
    var store: [216]u8 = undefined;
    var tl: [96]u8 = undefined;
    var input_len: usize = 0;
    var genuine_h: ?pp.Header = null;
    var untouched = false;
    switch (src.valueRangeAtMost(u8, 0, 3)) {
        0 => {
            input_len = src.slice(&raw);
            Mark.mark(.random_bytes);
        },
        else => {
            const g = genuine(S, src, &raw, &store, &tl);
            input_len = g.n;
            Mark.mark(.genuine);
            const hits = src.valueRangeAtMost(u8, 0, 3);
            if (hits == 0) {
                untouched = true;
                genuine_h = g.h;
            } else {
                for (0..hits) |_| {
                    if (input_len == 0) break;
                    raw[src.index(input_len)] = src.value(u8);
                }
                if (src.valueRangeAtMost(u8, 0, 3) == 0) input_len = src.index(input_len + 1);
                Mark.mark(.damaged);
            }
        },
    }
    const input = raw[0..input_len];
    const res = pp.parse(input) catch |e| {
        switch (e) {
            error.Malformed => Mark.mark(.malformed),
            error.TooLarge => Mark.mark(.too_large),
            error.BadChecksum => Mark.mark(.bad_crc),
        }
        if (untouched) return error.GenuineRefused;
        try readAgrees(S, src, input, null);
        return;
    };
    switch (res) {
        .absent => {
            Mark.mark(.absent);
            if (untouched) return error.GenuineRefused;
        },
        .need_more => |n| {
            Mark.mark(.need_more);
            if (n == 0) return error.ZeroNeedMore;
            if (untouched) return error.GenuineRefused;
        },
        .header => |p| {
            if (p.consumed > input.len or p.consumed == 0) return error.ConsumedOutOfRange;
            if (p.h.version == 1) Mark.mark(.v1_header) else if (p.h.command == .local) Mark.mark(.local_header) else Mark.mark(.v2_header);
            // Same header from exactly the consumed bytes.
            const again = try pp.parse(input[0..p.consumed]);
            if (again != .header or again.header.consumed != p.consumed) return error.ReparseDiffers;
            // Every shorter prefix wants more.
            const k = src.index(p.consumed);
            switch (try pp.parse(input[0..k])) {
                .need_more => |n| if (k + n > p.consumed) return error.NeedMoreOvershoots,
                else => return error.PrefixNotNeedMore,
            }
            Mark.mark(.prefix_checked);
            // The TLV area is walkable without a panic.
            var it = p.h.tlvIterator();
            while (it.next() catch null) |_| {}
            Mark.mark(.tlv_walked);
            if (untouched) {
                const g = genuine_h.?;
                if (p.h.command != g.command) return error.RoundTripFamily;
                const has = g.command == .proxy and g.family != .unspec;
                if (g.command == .proxy and p.h.family != g.family) return error.RoundTripFamily;
                if (has != (p.h.source != null)) return error.RoundTripAddr;
                if (has and (!g.source.?.eql(p.h.source.?) or !g.destination.?.eql(p.h.destination.?))) return error.RoundTripAddr;
                Mark.mark(.roundtrip);
            }
        },
    }
    try readAgrees(S, src, input, res);
}

/// The reader over a chunked, maybe failing transport agrees with `parse`.
fn readAgrees(comptime S: type, src: *S, input: []const u8, res: ?pp.ParseResult) anyerror!void {
    var rbuf: [pp.default_max_v2_len]u8 = undefined;
    var buf: [pp.default_max_v2_len]u8 = undefined;
    const plan = testkit.fuzz.FaultPlan.draw(src, input.len);
    var cr = testkit.fuzz.ChunkedReader.init(input, plan, &rbuf);
    const trusted = src.valueRangeAtMost(u8, 0, 3) != 0;
    const lb: netaddr.Prefix = .{ .addr = .{ .v4 = .{ 10, 0, 0, 0 } }, .bits = 8 };
    const out = pp.read(&cr.interface, &buf, .{
        .peer = .{ .v4 = .{ 10, 0, 0, 7 } },
        .trusted = if (trusted) &.{lb} else &.{},
    });
    if (out) |maybe| {
        if (maybe) |h| {
            if (!trusted) return error.UntrustedAccepted;
            const p = (res orelse return error.ReadAcceptedWhatParseRefused);
            if (p != .header) return error.ReadAcceptedWhatParseRefused;
            if (h.family != p.header.h.family or h.command != p.header.h.command) return error.ReadDiffers;
            if (cr.interface.seek != p.header.consumed) return error.ReadConsumedWrong;
            Mark.mark(.read_agrees);
        } else {
            if (cr.interface.seek != 0) return error.AbsentConsumed;
            if (res) |p| if (p == .header) return error.ReadMissedHeader;
        }
    } else |e| {
        if (cr.interface.seek != 0) return error.ErrorConsumed;
        switch (e) {
            error.ReadFailed => Mark.mark(.read_fault),
            error.UntrustedPeer => {
                if (trusted) return error.TrustedRefused;
                Mark.mark(.read_untrusted);
            },
            else => {},
        }
    }
}

test "fuzz: proxyproto parse and read" {
    try testing.fuzz({}, smithWrap(fuzzParse), .{});
}
test "fuzz driver: PROXYPROTO_FUZZ (parse)" {
    try fuzz_driver.run(fuzzParse, .{ .prefix = "PROXYPROTO_FUZZ", .name = "proxyproto-parse" });
}
test "fuzz harness: parse, 600 seeds, reaches every outcome" {
    try Mark.reach(fuzzParse, "proxyproto-parse", 600);
}
