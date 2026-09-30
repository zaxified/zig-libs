// SPDX-License-Identifier: MIT

//! frr_test — the preference-based DF choice against FRRouting's, observed
//! as a black box by `tools/frr/` (FRR 10.7.1 EVPN multihoming, three PEs
//! 10.0.0.1..3 on one Ethernet Segment, image pinned there; the raw
//! observations are `tools/frr/observed/*.jsonl`). Every row below is one
//! SETTLED phase of those runs: which PEs had the ES up, with which
//! `es-df-pref`, and which PE FRR reported as DF. `preferenceDf` must name
//! the same PE. Oracle EXTERNAL for this algorithm's choice.
//!
//! What this does NOT compare: timing (FRR fails over on BGP route
//! withdrawal, this module on Hello staleness and `df_wait`) and the
//! transient windows — FRR's are described in SPEC.md "Compared with";
//! e.g. after a PE restart FRR held two DFs for 20–30 s
//! (`df-pe-crash.jsonl`: the restarted PE reports DF with no BGP peers while
//! the stand-in DF keeps the role until the sessions come back).

const std = @import("std");
const types = @import("types.zig");
const election = @import("election.zig");

const testing = std.testing;

const Pe = struct { addr: u32, pref: u16 };

const Phase = struct {
    /// Source file and the event after which the phase settled.
    what: []const u8,
    /// The PEs with the ES up in this phase.
    up: []const Pe,
    /// The DF FRR reported.
    df: u32,
};

fn ip(last: u8) u32 {
    return 0x0a00_0000 | @as(u32, last);
}

const phases = [_]Phase{
    .{ .what = "steady-equal-pref: prefs 100 100 100", .up = &.{ .{ .addr = ip(1), .pref = 100 }, .{ .addr = ip(2), .pref = 100 }, .{ .addr = ip(3), .pref = 100 } }, .df = ip(1) },
    .{ .what = "steady-pref: prefs 100 200 300", .up = &.{ .{ .addr = ip(1), .pref = 100 }, .{ .addr = ip(2), .pref = 200 }, .{ .addr = ip(3), .pref = 300 } }, .df = ip(3) },
    .{ .what = "steady-pref: set_pref 10.0.0.1 400", .up = &.{ .{ .addr = ip(1), .pref = 400 }, .{ .addr = ip(2), .pref = 200 }, .{ .addr = ip(3), .pref = 300 } }, .df = ip(1) },
    .{ .what = "steady-pref: set_pref 10.0.0.1 50", .up = &.{ .{ .addr = ip(1), .pref = 50 }, .{ .addr = ip(2), .pref = 200 }, .{ .addr = ip(3), .pref = 300 } }, .df = ip(3) },
    .{ .what = "steady-pref: no_pref 10.0.0.3 (default 32767)", .up = &.{ .{ .addr = ip(1), .pref = 50 }, .{ .addr = ip(2), .pref = 200 }, .{ .addr = ip(3), .pref = 32767 } }, .df = ip(3) },
    .{ .what = "df-link-down: 100 200 300, link_down 10.0.0.3", .up = &.{ .{ .addr = ip(1), .pref = 100 }, .{ .addr = ip(2), .pref = 200 } }, .df = ip(2) },
    .{ .what = "df-link-down: link_up 10.0.0.3", .up = &.{ .{ .addr = ip(1), .pref = 100 }, .{ .addr = ip(2), .pref = 200 }, .{ .addr = ip(3), .pref = 300 } }, .df = ip(3) },
    .{ .what = "df-link-down: equal prefs, link_down 10.0.0.1", .up = &.{ .{ .addr = ip(2), .pref = 100 }, .{ .addr = ip(3), .pref = 100 } }, .df = ip(2) },
    .{ .what = "df-link-down: link_up 10.0.0.1", .up = &.{ .{ .addr = ip(1), .pref = 100 }, .{ .addr = ip(2), .pref = 100 }, .{ .addr = ip(3), .pref = 100 } }, .df = ip(1) },
    .{ .what = "df-pe-crash: 100 200 300, pe_down 10.0.0.3", .up = &.{ .{ .addr = ip(1), .pref = 100 }, .{ .addr = ip(2), .pref = 200 } }, .df = ip(2) },
    .{ .what = "df-pe-crash: pe_up 10.0.0.3 (settled)", .up = &.{ .{ .addr = ip(1), .pref = 100 }, .{ .addr = ip(2), .pref = 200 }, .{ .addr = ip(3), .pref = 300 } }, .df = ip(3) },
    .{ .what = "df-pe-crash: equal prefs, pe_down 10.0.0.1", .up = &.{ .{ .addr = ip(2), .pref = 100 }, .{ .addr = ip(3), .pref = 100 } }, .df = ip(2) },
};

test "EXTERNAL: preferenceDf names the DF FRRouting chose in every settled phase" {
    for (phases) |ph| {
        var buf: [types.max_members]types.Member = undefined;
        for (ph.up, 0..) |pe, i| buf[i] = .{ .node = @intCast(pe.addr & 0xff), .addr = pe.addr, .pref = pe.pref };
        const df = election.preferenceDf(buf[0..ph.up.len]).?;
        if (df != (ph.df & 0xff)) {
            std.debug.print("phase '{s}': FRR chose .{d}, preferenceDf chose .{d}\n", .{ ph.what, ph.df & 0xff, df });
            return error.DisagreesWithFrr;
        }
    }
}

test "EXTERNAL control: the other two algorithms do NOT reproduce FRR's choices" {
    // If they did, the phases above would not discriminate the algorithm.
    for ([_]types.Algorithm{ .modulo, .hrw }) |alg| {
        var agree: usize = 0;
        for (phases) |ph| {
            var buf: [types.max_members]types.Member = undefined;
            for (ph.up, 0..) |pe, i| buf[i] = .{ .node = @intCast(pe.addr & 0xff), .addr = pe.addr, .pref = pe.pref };
            // FRR elects per ES; try the VNIs the lab carried (1000, 1001).
            const d0 = election.designatedForwarder(alg, @splat(0), buf[0..ph.up.len], 1000).?;
            const d1 = election.designatedForwarder(alg, @splat(0), buf[0..ph.up.len], 1001).?;
            if (d0 == ph.df & 0xff and d1 == ph.df & 0xff) agree += 1;
        }
        try testing.expect(agree < phases.len);
    }
}
