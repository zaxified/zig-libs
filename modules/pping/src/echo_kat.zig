// SPDX-License-Identifier: MIT

//! echo_kat — ICMP / ICMPv6 Echo RTT through the whole pipeline:
//! `parseIpEcho` -> `IpEcho.direction` -> `Estimator.observeEcho`.
//!
//! **Anchors.**
//!   - IPv4, EXTERNAL: ten real IP packets captured on 2026-10-06 by
//!     `tools/capture_icmp_echo.sh` — iputils `ping` 20240117 from 127.0.0.1
//!     to 127.0.0.2 inside a throwaway `unshare --net` namespace, recorded by
//!     `tcpdump -i lo` 4.99.4 with nanosecond timestamps. The 14-octet
//!     loopback link header is dropped; every other octet is as captured. The
//!     expected RTTs are the differences between the capture timestamps
//!     tcpdump wrote, and each is cross-checked against the `time=` ping itself
//!     printed for that sequence number: the wire RTT must be positive and no
//!     larger than ping's, which also counts its own send and receive path.
//!     The `wrap` run is `ping -f -c 65537`, filtered to sequence 65535 and 0
//!     — a real wrap of the 16-bit sequence number.
//!   - IPv6, SELF-DERIVED: this kernel has no IPv6, so no real `ping -6` run
//!     exists. The six packets are built by `tools/icmpv6_crosscheck.py` and
//!     cross-checked by an independent dissector: `tcpdump -vv` decodes each
//!     as the stated type, id and seq with "[icmp6 sum ok]". Their timestamps
//!     are made up.
//!   - The scenario tests (duplicates, unmatched replies, table pressure,
//!     aging, cross-pinging hosts) are SELF-DERIVED: hand-built sequences with
//!     hand-computed expected samples; where they replay a captured frame it is
//!     named.

const std = @import("std");
const root = @import("root.zig");
const hex = @import("testkit").hex;
const testing = std.testing;
const Estimator = root.Estimator;
const IcmpEcho = root.IcmpEcho;

// ── IPv4 captures (EXTERNAL) ────────────────────────────────────────────────

const Frame = struct { t_ns: u64, ip: []const u8 };

// `ping -n -c 3 -i 0.2 -I 127.0.0.1 127.0.0.2`; id 7749 (0x1e45).
// ping printed: icmp_seq=1 time=0.689 ms, seq=2 0.044 ms, seq=3 0.036 ms.
const v4_run = blk: {
    @setEvalBranchQuota(100_000);
    break :blk [_]Frame{
        .{ .t_ns = 1791281879159318480, .ip = &hex.bytes(84, "450000543afc4000400101aa7f0000017f00000208006e441e450001d7cac46a000000000e6d020000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637") },
        .{ .t_ns = 1791281879159679292, .ip = &hex.bytes(84, "45000054a8d000004001d3d57f0000027f000001000076441e450001d7cac46a000000000e6d020000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637") },
        .{ .t_ns = 1791281879361328040, .ip = &hex.bytes(84, "450000543b044000400101a27f0000017f0000020800282d1e450002d7cac46a000000005183050000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637") },
        .{ .t_ns = 1791281879361341542, .ip = &hex.bytes(84, "45000054a8fd00004001d3a87f0000027f0000010000302d1e450002d7cac46a000000005183050000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637") },
        .{ .t_ns = 1791281879565415983, .ip = &hex.bytes(84, "450000543b354000400101717f0000017f0000020800e80e1e450003d7cac46a000000008ea0080000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637") },
        .{ .t_ns = 1791281879565426376, .ip = &hex.bytes(84, "45000054a90200004001d3a37f0000027f0000010000f00e1e450003d7cac46a000000008ea0080000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637") },
    };
};
const v4_ping_reported_ns = [_]u64{ 689_000, 44_000, 36_000 };

// `ping -n -q -f -c 65537 -I 127.0.0.1 127.0.0.2`, filtered by tcpdump to
// `icmp[6:2] = 65535 or icmp[6:2] = 0`; id 7753 (0x1e49). ping printed only
// its summary: rtt min/avg/max = 0.001/0.002/0.115 ms.
const wrap_run = blk: {
    @setEvalBranchQuota(100_000);
    break :blk [_]Frame{
        .{ .t_ns = 1791281881880410953, .ip = &hex.bytes(84, "450000543c864000400100207f0000017f0000020800593f1e49ffffd9cac46a00000000166f0d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637") },
        .{ .t_ns = 1791281881880413306, .ip = &hex.bytes(84, "45000054a93000004001d3757f0000027f0000010000613f1e49ffffd9cac46a00000000166f0d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637") },
        .{ .t_ns = 1791281881880417934, .ip = &hex.bytes(84, "450000543c8740004001001f7f0000017f00000208004f3f1e490000d9cac46a00000000206f0d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637") },
        .{ .t_ns = 1791281881880419825, .ip = &hex.bytes(84, "45000054a93100004001d3747f0000027f0000010000573f1e490000d9cac46a00000000206f0d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637") },
    };
};
const wrap_ping_max_ns: u64 = 115_000;

// ── IPv6 packets (SELF-DERIVED, tcpdump-checked) ────────────────────────────

// fd00::1 <-> fd00::2, id 0x5a5a, payload "pping-v6"; seq 1, 65535, 0.
const v6_run = blk: {
    @setEvalBranchQuota(100_000);
    break :blk [_]Frame{
        .{ .t_ns = 1_000, .ip = &hex.bytes(56, "6000000000103a40fd000000000000000000000000000001fd000000000000000000000000000002800074125a5a00017070696e672d7636") },
        .{ .t_ns = 1_250, .ip = &hex.bytes(56, "6000000000103a40fd000000000000000000000000000002fd000000000000000000000000000001810073125a5a00017070696e672d7636") },
        .{ .t_ns = 2_000, .ip = &hex.bytes(56, "6000000000103a40fd000000000000000000000000000001fd000000000000000000000000000002800074135a5affff7070696e672d7636") },
        .{ .t_ns = 2_400, .ip = &hex.bytes(56, "6000000000103a40fd000000000000000000000000000002fd000000000000000000000000000001810073135a5affff7070696e672d7636") },
        .{ .t_ns = 3_000, .ip = &hex.bytes(56, "6000000000103a40fd000000000000000000000000000001fd000000000000000000000000000002800074135a5a00007070696e672d7636") },
        .{ .t_ns = 3_070, .ip = &hex.bytes(56, "6000000000103a40fd000000000000000000000000000002fd000000000000000000000000000001810073135a5a00007070696e672d7636") },
    };
};

/// Feed one frame through the pipeline the README documents.
fn feed(est: *Estimator, f: Frame) !?root.RttSample {
    const e = (try root.parseIpEcho(f.ip)).?;
    return est.observeEcho(.{ .dir = e.direction(), .echo = e.echo, .now = f.t_ns });
}

test "golden: real ping run (IPv4) — decode, pair, and RTT within ping's own report" {
    // The decoder against what tcpdump printed for the same frames.
    for (v4_run, 0..) |f, i| {
        const e = (try root.parseIpEcho(f.ip)).?;
        try testing.expectEqual(root.IcmpFamily.v4, e.echo.family);
        try testing.expectEqual(@as(u16, 7749), e.echo.identifier);
        try testing.expectEqual(@as(u16, @intCast(i / 2 + 1)), e.echo.sequence);
        const is_req = i % 2 == 0;
        try testing.expectEqual(if (is_req) root.EchoKind.request else root.EchoKind.reply, e.echo.kind);
        try testing.expectEqualSlices(u8, if (is_req) &.{ 127, 0, 0, 1 } else &.{ 127, 0, 0, 2 }, &e.src.v4);
    }
    // RFC 792: the reply carries the request's payload back unchanged.
    try testing.expectEqualSlices(u8, v4_run[0].ip[28..], v4_run[1].ip[28..]);

    var est = try Estimator.init(testing.allocator, .{ .capacity = 8, .max_age = std.time.ns_per_s });
    defer est.deinit(testing.allocator);
    const expect_rtt = [_]u64{ 360_812, 13_502, 10_393 };
    var got: usize = 0;
    for (v4_run, 0..) |f, i| {
        const s = try feed(&est, f);
        if (i % 2 == 0) {
            try testing.expectEqual(@as(?root.RttSample, null), s);
            continue;
        }
        const k = i / 2;
        try testing.expectEqual(root.RttSample{
            .rtt = expect_rtt[k],
            .tsval = 0x1e45_0000 | @as(u32, @intCast(k + 1)),
            .at = f.t_ns,
            .proto = .icmp_echo,
        }, s.?);
        try testing.expectEqual(@as(u16, @intCast(k + 1)), s.?.echoSequence());
        try testing.expectEqual(@as(u16, 7749), s.?.echoIdentifier());
        try testing.expect(s.?.rtt > 0 and s.?.rtt <= v4_ping_reported_ns[k]);
        got += 1;
    }
    try testing.expectEqual(@as(usize, 3), got);
    try testing.expectEqual(@as(usize, 0), est.tableCount(.a_to_b));
    try testing.expectEqual(@as(usize, 0), est.tableCount(.b_to_a));
}

test "golden: real 16-bit sequence wrap (ping -f, seq 65535 then 0)" {
    var est = try Estimator.init(testing.allocator, .{ .capacity = 8, .max_age = std.time.ns_per_s });
    defer est.deinit(testing.allocator);
    try testing.expectEqual(@as(?root.RttSample, null), try feed(&est, wrap_run[0]));
    const a = (try feed(&est, wrap_run[1])).?;
    try testing.expectEqual(@as(?root.RttSample, null), try feed(&est, wrap_run[2]));
    const b = (try feed(&est, wrap_run[3])).?;
    try testing.expectEqual(@as(u16, 65535), a.echoSequence());
    try testing.expectEqual(@as(u64, 2_353), a.rtt);
    try testing.expectEqual(@as(u16, 0), b.echoSequence());
    try testing.expectEqual(@as(u64, 1_891), b.rtt);
    try testing.expect(a.rtt <= wrap_ping_max_ns and b.rtt <= wrap_ping_max_ns);
}

test "golden: a replayed real reply (ping's DUP!) yields no second sample" {
    var est = try Estimator.init(testing.allocator, .{ .max_age = std.time.ns_per_s });
    defer est.deinit(testing.allocator);
    _ = try feed(&est, v4_run[0]);
    try testing.expect((try feed(&est, v4_run[1])) != null);
    var dup = v4_run[1];
    dup.t_ns += 5_000;
    try testing.expectEqual(@as(?root.RttSample, null), try feed(&est, dup));
    try testing.expectEqual(@as(u64, 1), est.samples_emitted);
}

test "SELF-DERIVED (tcpdump-checked packets): ICMPv6 run with a wrap" {
    var est = try Estimator.init(testing.allocator, .{});
    defer est.deinit(testing.allocator);
    const expect = [_]struct { seq: u16, rtt: u64 }{ .{ .seq = 1, .rtt = 250 }, .{ .seq = 65535, .rtt = 400 }, .{ .seq = 0, .rtt = 70 } };
    for (v6_run, 0..) |f, i| {
        const s = try feed(&est, f);
        if (i % 2 == 0) {
            try testing.expectEqual(@as(?root.RttSample, null), s);
        } else {
            const e = expect[i / 2];
            try testing.expectEqual(root.Proto.icmpv6_echo, s.?.proto);
            try testing.expectEqual(@as(u16, 0x5a5a), s.?.echoIdentifier());
            try testing.expectEqual(e.seq, s.?.echoSequence());
            try testing.expectEqual(e.rtt, s.?.rtt);
        }
    }
}

// ── scenarios (SELF-DERIVED) ────────────────────────────────────────────────

fn req(id: u16, seq: u16) IcmpEcho {
    return .{ .family = .v4, .kind = .request, .identifier = id, .sequence = seq };
}
fn rep(id: u16, seq: u16) IcmpEcho {
    return .{ .family = .v4, .kind = .reply, .identifier = id, .sequence = seq };
}

test "scenario: unmatched reply emits nothing and leaves no state" {
    var est = try Estimator.init(testing.allocator, .{});
    defer est.deinit(testing.allocator);
    try testing.expectEqual(@as(?root.RttSample, null), est.observeEcho(.{ .dir = .b_to_a, .echo = rep(1, 1), .now = 10 }));
    try testing.expectEqual(@as(usize, 0), est.tableCount(.a_to_b));
    try testing.expectEqual(@as(usize, 0), est.tableCount(.b_to_a));
    // A reply with the right id but another seq, or going the wrong way, is unmatched too.
    _ = est.observeEcho(.{ .dir = .a_to_b, .echo = req(1, 2), .now = 20 });
    try testing.expectEqual(@as(?root.RttSample, null), est.observeEcho(.{ .dir = .b_to_a, .echo = rep(1, 3), .now = 30 }));
    try testing.expectEqual(@as(?root.RttSample, null), est.observeEcho(.{ .dir = .a_to_b, .echo = rep(1, 2), .now = 30 }));
    try testing.expectEqual(@as(?root.RttSample, null), est.observeEcho(.{ .dir = .b_to_a, .echo = rep(2, 2), .now = 30 }));
    try testing.expectEqual(@as(u64, 40), est.observeEcho(.{ .dir = .b_to_a, .echo = rep(1, 2), .now = 60 }).?.rtt);
}

test "scenario: a duplicated request keeps its first time; one reply, one sample" {
    var est = try Estimator.init(testing.allocator, .{});
    defer est.deinit(testing.allocator);
    _ = est.observeEcho(.{ .dir = .a_to_b, .echo = req(7, 9), .now = 100 });
    _ = est.observeEcho(.{ .dir = .a_to_b, .echo = req(7, 9), .now = 130 });
    try testing.expectEqual(@as(usize, 1), est.tableCount(.a_to_b));
    try testing.expectEqual(@as(u64, 50), est.observeEcho(.{ .dir = .b_to_a, .echo = rep(7, 9), .now = 150 }).?.rtt);
    try testing.expectEqual(@as(?root.RttSample, null), est.observeEcho(.{ .dir = .b_to_a, .echo = rep(7, 9), .now = 160 }));
}

test "scenario: a key reused after its match (sequence wrapped all the way) is a fresh probe" {
    var est = try Estimator.init(testing.allocator, .{});
    defer est.deinit(testing.allocator);
    _ = est.observeEcho(.{ .dir = .a_to_b, .echo = req(1, 5), .now = 0 });
    try testing.expectEqual(@as(u64, 10), est.observeEcho(.{ .dir = .b_to_a, .echo = rep(1, 5), .now = 10 }).?.rtt);
    _ = est.observeEcho(.{ .dir = .a_to_b, .echo = req(1, 5), .now = 100 });
    try testing.expectEqual(@as(u64, 30), est.observeEcho(.{ .dir = .b_to_a, .echo = rep(1, 5), .now = 130 }).?.rtt);
}

test "scenario: replies out of order still pair by sequence" {
    var est = try Estimator.init(testing.allocator, .{});
    defer est.deinit(testing.allocator);
    _ = est.observeEcho(.{ .dir = .a_to_b, .echo = req(1, 1), .now = 0 });
    _ = est.observeEcho(.{ .dir = .a_to_b, .echo = req(1, 2), .now = 10 });
    try testing.expectEqual(@as(u64, 15), est.observeEcho(.{ .dir = .b_to_a, .echo = rep(1, 2), .now = 25 }).?.rtt);
    try testing.expectEqual(@as(u64, 30), est.observeEcho(.{ .dir = .b_to_a, .echo = rep(1, 1), .now = 30 }).?.rtt);
}

test "scenario: two hosts pinging each other with the same id and seq do not cross-match" {
    var est = try Estimator.init(testing.allocator, .{});
    defer est.deinit(testing.allocator);
    _ = est.observeEcho(.{ .dir = .a_to_b, .echo = req(1, 1), .now = 0 }); // A pings B
    _ = est.observeEcho(.{ .dir = .b_to_a, .echo = req(1, 1), .now = 5 }); // B pings A
    // B answers A's ping: travels b_to_a, pairs with the request that went a_to_b.
    try testing.expectEqual(@as(u64, 20), est.observeEcho(.{ .dir = .b_to_a, .echo = rep(1, 1), .now = 20 }).?.rtt);
    // A answers B's ping.
    try testing.expectEqual(@as(u64, 22), est.observeEcho(.{ .dir = .a_to_b, .echo = rep(1, 1), .now = 27 }).?.rtt);
}

test "scenario: table pressure evicts the oldest request; memory stays at capacity" {
    var est = try Estimator.init(testing.allocator, .{ .capacity = 4, .max_age = 1_000_000 });
    defer est.deinit(testing.allocator);
    var seq: u16 = 0;
    while (seq < 6) : (seq += 1) {
        _ = est.observeEcho(.{ .dir = .a_to_b, .echo = req(3, seq), .now = seq });
        try testing.expect(est.tableCount(.a_to_b) <= 4);
    }
    // seq 0 and 1 were the oldest and were evicted for 4 and 5.
    try testing.expectEqual(@as(?root.RttSample, null), est.observeEcho(.{ .dir = .b_to_a, .echo = rep(3, 0), .now = 100 }));
    try testing.expectEqual(@as(?root.RttSample, null), est.observeEcho(.{ .dir = .b_to_a, .echo = rep(3, 1), .now = 100 }));
    seq = 2;
    while (seq < 6) : (seq += 1) {
        try testing.expectEqual(@as(u64, 100 - seq), est.observeEcho(.{ .dir = .b_to_a, .echo = rep(3, seq), .now = 100 }).?.rtt);
    }
    // A request flood (every key distinct) never grows the table.
    var i: u32 = 0;
    while (i < 70_000) : (i += 1) {
        _ = est.observeEcho(.{ .dir = .a_to_b, .echo = req(@truncate(i >> 16), @truncate(i)), .now = 200 + i });
        try testing.expect(est.tableCount(.a_to_b) <= 4);
    }
    try testing.expectEqual(@as(usize, 4), est.tables[0].capacity());
}

test "scenario: a reply after max_age finds its request aged out" {
    var est = try Estimator.init(testing.allocator, .{ .max_age = 100 });
    defer est.deinit(testing.allocator);
    _ = est.observeEcho(.{ .dir = .a_to_b, .echo = req(1, 1), .now = 0 });
    _ = est.observeEcho(.{ .dir = .a_to_b, .echo = req(1, 2), .now = 50 });
    try testing.expectEqual(@as(?root.RttSample, null), est.observeEcho(.{ .dir = .b_to_a, .echo = rep(1, 1), .now = 101 }));
    try testing.expectEqual(@as(u64, 51), est.observeEcho(.{ .dir = .b_to_a, .echo = rep(1, 2), .now = 101 }).?.rtt);
}

test "scenario: one estimator is one kind of traffic — mixing is refused, reset re-arms" {
    var est = try Estimator.init(testing.allocator, .{});
    defer est.deinit(testing.allocator);
    // TCP first: TSval 0x00010001 is exactly the key of (id 1, seq 1).
    _ = est.observe(.{ .dir = .a_to_b, .tsval = 0x0001_0001, .tsecr = 0, .now = 0 });
    try testing.expectEqual(@as(?root.RttSample, null), est.observeEcho(.{ .dir = .b_to_a, .echo = rep(1, 1), .now = 10 }));
    try testing.expectEqual(@as(u64, 1), est.observations_refused);
    try testing.expectEqual(@as(usize, 1), est.tableCount(.a_to_b)); // untouched
    try testing.expectEqual(Estimator.Traffic.tcp_timestamps, est.traffic);

    est.reset();
    try testing.expectEqual(Estimator.Traffic.unset, est.traffic);
    try testing.expectEqual(@as(u64, 0), est.observations_refused);
    _ = est.observeEcho(.{ .dir = .a_to_b, .echo = req(1, 1), .now = 0 });
    try testing.expectEqual(@as(?root.RttSample, null), est.observe(.{ .dir = .b_to_a, .tsval = 9, .tsecr = 0x0001_0001, .now = 10 }));
    try testing.expectEqual(@as(u64, 1), est.observations_refused);
    try testing.expectEqual(@as(u64, 2), est.observations_total);
    try testing.expectEqual(@as(usize, 0), est.tableCount(.b_to_a));
}

test "scenario: TCP samples keep the default .tcp_timestamps tag" {
    var est = try Estimator.init(testing.allocator, .{});
    defer est.deinit(testing.allocator);
    _ = est.observe(.{ .dir = .a_to_b, .tsval = 1, .tsecr = 0, .now = 0 });
    try testing.expectEqual(root.Proto.tcp_timestamps, est.observe(.{ .dir = .b_to_a, .tsval = 2, .tsecr = 1, .now = 4 }).?.proto);
}
