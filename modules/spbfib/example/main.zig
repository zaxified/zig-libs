// SPDX-License-Identifier: MIT

//! What an SPBM backbone edge bridge does with `spbfib`: take an
//! already-computed `isis-spf.RouteTable` (built directly from its public
//! fields here, exactly as `spbfib`'s own tests do — this module's declared
//! deps are `isis-spf` + `std` only, no `isis-lsdb`, so there is no LSDB to
//! run `isis-spf.compute` over) plus a system-id -> B-MAC map, and derive
//! the unicast B-MAC FIB `Fib.build` computes: assert the exact entries,
//! including the sharpest property of the whole design — a multi-hop
//! destination is keyed by its OWN B-MAC (the frame DA never changes
//! hop-by-hop) while its next-hop B-MAC differs (it selects the egress
//! adjacency only). Then rebuild over a changed, larger topology, and
//! exercise Part B (the SPBM group multicast-DA construction) against its
//! own worked examples.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). Declared
//! deps: `isis-spf`.

const std = @import("std");
const spf = @import("isis-spf");
const spbfib = @import("spbfib");

fn sysId(last: u8) spf.SystemId {
    return .{ 0, 0, 0, 0, 0, last };
}
fn bmac(last: u8) spbfib.BMac {
    return .{ 0x02, 0, 0, 0, 0, last }; // locally-administered, unicast
}

/// Wrap a hand-derived route slice in a real `isis-spf.RouteTable` — the
/// type, its `lookup`, and its `deinit` are the genuine `isis-spf` ones,
/// just constructed from literal routes instead of `isis_spf.compute` over
/// an LSDB (which this module cannot reach: no `isis-lsdb` in its deps).
fn makeTable(gpa: std.mem.Allocator, routes: []const spf.Route) !spf.RouteTable {
    return .{ .gpa = gpa, .routes = try gpa.dupe(spf.Route, routes) };
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    const a = sysId(0xA);
    const b = sysId(0xB);
    const c = sysId(0xC);

    // ── run 1: the line A-B(10)-C(10) route table isis-spf would compute ─────
    {
        var table = try makeTable(gpa, &.{
            .{ .dest = a, .next_hop = a, .metric = 0 },
            .{ .dest = b, .next_hop = b, .metric = 10 },
            .{ .dest = c, .next_hop = b, .metric = 20 }, // C is two hops, via B
        });
        defer table.deinit();

        const map = [_]spbfib.BmacEntry{
            .{ .system_id = a, .b_mac = bmac(0xA) },
            .{ .system_id = b, .b_mac = bmac(0xB) },
            .{ .system_id = c, .b_mac = bmac(0xC) },
        };
        var fib = try spbfib.build(gpa, &table, &map);
        defer fib.deinit();

        std.debug.assert(fib.entries.len == 3);

        // Self route: local delivery.
        const self_e = fib.lookup(bmac(0xA)).?;
        std.debug.assert(self_e.local and self_e.metric == 0);
        std.debug.assert(std.mem.eql(u8, &self_e.next_hop_bmac, &bmac(0xA)));

        // Direct neighbour B: next-hop B-MAC == dest B-MAC (one hop, no
        // distinction between "who to address" and "who to hand it to").
        const b_e = fib.lookup(bmac(0xB)).?;
        std.debug.assert(!b_e.local and b_e.metric == 10);
        std.debug.assert(std.mem.eql(u8, &b_e.next_hop_bmac, &bmac(0xB)));

        // C: the load-bearing property. The frame DA (what the FIB is keyed
        // by, and what every transit node forwards on unchanged) is C's OWN
        // B-MAC — but the entry's next-hop B-MAC is B's, selecting the
        // egress adjacency toward the real next router, NOT the destination.
        const c_e = fib.lookup(bmac(0xC)).?;
        std.debug.assert(!c_e.local and c_e.metric == 20);
        std.debug.assert(std.mem.eql(u8, &c_e.dest_bmac, &bmac(0xC))); // keyed by DEST
        std.debug.assert(std.mem.eql(u8, &c_e.next_hop_bmac, &bmac(0xB))); // egress != dest
        std.debug.assert(!std.mem.eql(u8, &c_e.dest_bmac, &c_e.next_hop_bmac));

        // A destination whose B-MAC the caller never supplied is skipped,
        // not a crash and not a partial/wrong entry — the FIB never carries
        // an entry it could not actually forward on.
        var fib2 = try spbfib.build(gpa, &table, map[0..2]); // C's B-MAC withheld
        defer fib2.deinit();
        std.debug.assert(fib2.entries.len == 2);
        std.debug.assert(fib2.lookup(bmac(0xC)) == null);
        std.debug.print("run 1 (A-B-C line): self/direct/multi-hop FIB entries match; unknown B-MAC skipped\n", .{});
    }

    // ── run 2: topology change — a 4th node D added two hops past C ─────────
    // A fresh, larger route table (as if the fabric grew a node), rebuilt
    // from scratch in the same process: any state `Fib.build` held between
    // calls (it holds none) would show up here as a leak or a stale entry.
    {
        const d = sysId(0xD);
        var table = try makeTable(gpa, &.{
            .{ .dest = a, .next_hop = a, .metric = 0 },
            .{ .dest = b, .next_hop = b, .metric = 10 },
            .{ .dest = c, .next_hop = b, .metric = 20 },
            .{ .dest = d, .next_hop = b, .metric = 30 }, // D: three hops, still via B
        });
        defer table.deinit();

        const map = [_]spbfib.BmacEntry{
            .{ .system_id = a, .b_mac = bmac(0xA) },
            .{ .system_id = b, .b_mac = bmac(0xB) },
            .{ .system_id = c, .b_mac = bmac(0xC) },
            .{ .system_id = d, .b_mac = bmac(0xD) },
        };
        var fib = try spbfib.build(gpa, &table, &map);
        defer fib.deinit();

        std.debug.assert(fib.entries.len == 4);
        const d_e = fib.lookup(bmac(0xD)).?;
        std.debug.assert(d_e.metric == 30);
        std.debug.assert(std.mem.eql(u8, &d_e.dest_bmac, &bmac(0xD)));
        std.debug.assert(std.mem.eql(u8, &d_e.next_hop_bmac, &bmac(0xB))); // still egresses via B

        // Entries are sorted ascending by key B-MAC — a caller relies on
        // this for the binary-search `lookup` itself.
        for (fib.entries[0 .. fib.entries.len - 1], fib.entries[1..]) |x, y|
            std.debug.assert(std.mem.order(u8, &x.dest_bmac, &y.dest_bmac) == .lt);
        std.debug.print("run 2 (topology grew a 4th node D): rebuilt FIB has 4 entries, D still egresses via B\n", .{});
    }

    // ── Part B: the SPBM group multicast-DA, against RFC 6329 worked examples ─
    {
        // RFC 6329 §4.4 worked example: SPSourceID 0x04001, I-SID 200 (0xC8).
        const da1 = spbfib.groupDa(0x04001, 200);
        std.debug.assert(std.mem.eql(u8, &da1, &.{ 0x03, 0x40, 0x01, 0x00, 0x00, 0xC8 }));
        const back1 = spbfib.parseGroupDa(da1).?;
        std.debug.assert(back1.spsourceid == 0x04001 and back1.isid == 200);

        // A non-SPBM DA (broadcast) is rejected, not misparsed.
        std.debug.assert(spbfib.parseGroupDa(.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }) == null);
        std.debug.print("groupDa/parseGroupDa: RFC 6329 worked example round-trips, non-SPBM DA rejected\n", .{});
    }

    // ── a failure path that allocates and returns early, by NAMED error ─────
    // `Fib.buildWith` allocates the system-id->B-MAC index before it ever
    // produces an entry; drive that under a `FailingAllocator` on a fresh
    // build so the very first allocation fails and the error propagates as
    // `error.OutOfMemory`, not a partially-built FIB.
    {
        var table = try makeTable(gpa, &.{.{ .dest = a, .next_hop = a, .metric = 0 }});
        defer table.deinit();
        const map = [_]spbfib.BmacEntry{.{ .system_id = a, .b_mac = bmac(0xA) }};

        var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
        if (spbfib.build(failing.allocator(), &table, &map)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.OutOfMemory => std.debug.print("build under a FailingAllocator: OutOfMemory (expected)\n", .{}),
        }
    }
}
