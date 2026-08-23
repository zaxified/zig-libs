// SPDX-License-Identifier: MIT

//! What an IS-IS fabric integrator does with `isis-spf`: populate an
//! `isis-lsdb` with a hand-built topology whose shortest-path answer is
//! worked out BY HAND below (an equal-cost tie and a dangling, unreachable
//! neighbour included), run `compute`, and assert the exact routes and
//! costs against that hand-worked answer — not merely that a table came
//! back. Then change one link's metric and assert the paths change the way
//! they must (the tie resolves to a single, no-longer-tied winner).
//!
//! Topology (all metrics symmetric unless noted), from the local system A:
//!
//! ```
//!        B --- D
//!       /       \
//!      A         (B-D and C-D both cost 10)
//!       \       /
//!        C --- D
//!
//!   A-B = 10, A-C = 10, B-D = 10, C-D = 10
//!   B-E = 15  (advertised by B only — E never reciprocates: E has no LSP
//!              of its own at all, ISO §7.2.8.2 two-way check drops it)
//! ```
//!
//! By hand: dist(A)=0, dist(B)=10, dist(C)=10, dist(D)=min(10+10,10+10)=20
//! via EITHER B or C (a genuine tie), dist(E) = unreachable (one-way only).
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). Declared
//! deps: `isis`, `isis-lsdb`, `spf-ect`.

const std = @import("std");
const isis = @import("isis");
const lsdb = @import("isis-lsdb");
const isis_spf = @import("isis-spf");

fn sysId(last: u8) isis_spf.SystemId {
    return .{ 0, 0, 0, 0, 0, last };
}

const a = sysId(0xA);
const b = sysId(0xB);
const c = sysId(0xC);
const d = sysId(0xD);
const e = sysId(0xE); // dangling: mentioned by B, never originates its own LSP

/// Insert one LSP for `origin` advertising Extended IS Reachability (#22) to
/// each `(neighbour, metric)` pair, at sequence `seq`. Mirrors what a real
/// IS-IS originator emits; local origination (`arrival_iface = null`), so no
/// checksum stamping is required (`isis-lsdb.insert`'s §7.3.14.2 gate is a
/// receive-only rule).
fn insertReach(
    db: *lsdb.Lsdb,
    origin: isis_spf.SystemId,
    seq: u32,
    reach: []const struct { nbr: isis_spf.SystemId, metric: u24 },
) !void {
    var buf: [256]u8 = undefined;
    var lb = try isis.pdu.LspBuilder.init(&buf, .{
        .remaining_lifetime = 1000,
        .lsp_id = .{ origin[0], origin[1], origin[2], origin[3], origin[4], origin[5], 0, 0 },
        .sequence_number = seq,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    });
    for (reach) |r| {
        const nbr7: [7]u8 = .{ r.nbr[0], r.nbr[1], r.nbr[2], r.nbr[3], r.nbr[4], r.nbr[5], 0 };
        try isis.tlvs.addExtendedIsReach(&lb.tlvs, nbr7, r.metric, &.{});
    }
    _ = try db.insert(lb.finish(), null, 0);
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var db = lsdb.Lsdb.init(gpa, .{ .local_system_id = a, .interface_count = 2, .capacity = 32 });
    defer db.deinit();

    // A—B(10), A—C(10), B—D(10), C—D(10), plus B's one-way mention of E(15).
    try insertReach(&db, a, 1, &.{ .{ .nbr = b, .metric = 10 }, .{ .nbr = c, .metric = 10 } });
    try insertReach(&db, b, 1, &.{ .{ .nbr = a, .metric = 10 }, .{ .nbr = d, .metric = 10 }, .{ .nbr = e, .metric = 15 } });
    try insertReach(&db, c, 1, &.{ .{ .nbr = a, .metric = 10 }, .{ .nbr = d, .metric = 10 } });
    try insertReach(&db, d, 1, &.{ .{ .nbr = b, .metric = 10 }, .{ .nbr = c, .metric = 10 } });
    // No LSP for E at all — a dangling neighbour, never reciprocates.

    // ── run 1: compute over the tied diamond, assert the hand-worked answer ──
    {
        var table = try isis_spf.compute(gpa, &db, a, 0);
        defer table.deinit();

        std.debug.assert(table.routes.len == 4); // A, B, C, D — never E
        std.debug.assert(std.meta.eql(table.lookup(a).?, .{ .dest = a, .next_hop = a, .metric = 0 }));
        std.debug.assert(std.meta.eql(table.lookup(b).?, .{ .dest = b, .next_hop = b, .metric = 10 }));
        std.debug.assert(std.meta.eql(table.lookup(c).?, .{ .dest = c, .next_hop = c, .metric = 10 }));
        std.debug.assert(table.lookup(e) == null); // dangling neighbour: never reachable

        // D is a genuine tie: cost is exact (20), the winning next hop is
        // NOT — either B or C is a legitimate answer. Assert what a tie
        // actually promises: the exact cost, that the winner is one of the
        // two real candidates (never some third, wrong value), and that the
        // ECT tie-break is deterministic (recomputing gives the SAME winner,
        // not a coin flip per call).
        const d_route = table.lookup(d).?;
        std.debug.assert(d_route.metric == 20);
        std.debug.assert(std.mem.eql(u8, &d_route.next_hop, &b) or std.mem.eql(u8, &d_route.next_hop, &c));

        var table2 = try isis_spf.compute(gpa, &db, a, 0);
        defer table2.deinit();
        std.debug.assert(std.mem.eql(u8, &d_route.next_hop, &table2.lookup(d).?.next_hop)); // stable
        std.debug.print("run 1 (tied diamond): A=0 B=10 C=10 D=20 (tie, stable), E unreachable\n", .{});
    }

    // ── topology change: raise A-B's metric so the tie breaks toward C ───────
    // A-C stays 10, so A-C-D (20) becomes strictly cheaper than the new
    // A-B-D (100+10=110): D's route must now resolve to C alone, no tie.
    //
    // The first hand-worked version of this step stopped there and asserted
    // B's OWN route stayed direct at cost 100 — wrong, caught by actually
    // running it (not just reasoning about it): raising A-B's cost also
    // exposes a CHEAPER indirect path to B itself, A-C-D-B (10+10+10=30),
    // which beats the now-expensive direct link (100). So B's route changes
    // too: next hop C, cost 30, not next hop B, cost 100. This is the
    // realistic SPF behaviour a naive "only the changed link's own
    // destination moves" intuition misses, and exactly why the instruction
    // is to assert the RUN's answer, not a hand-derived one nobody checked
    // against the algorithm.
    try insertReach(&db, a, 2, &.{ .{ .nbr = b, .metric = 100 }, .{ .nbr = c, .metric = 10 } });
    try insertReach(&db, b, 2, &.{ .{ .nbr = a, .metric = 100 }, .{ .nbr = d, .metric = 10 }, .{ .nbr = e, .metric = 15 } });

    {
        var table = try isis_spf.compute(gpa, &db, a, 0);
        defer table.deinit();

        // B: no longer worth reaching directly (100) now that A-C-D-B (30)
        // is cheaper — the indirect path wins and B's next hop becomes C.
        const b_route = table.lookup(b).?;
        std.debug.assert(b_route.metric == 30);
        std.debug.assert(std.mem.eql(u8, &b_route.next_hop, &c));
        // D: the tie is GONE — A-C-D (20) beats A-B-D (110) outright, so the
        // next hop is C alone, deterministically, not a stable-pick-of-two.
        const d_route = table.lookup(d).?;
        std.debug.assert(d_route.metric == 20);
        std.debug.assert(std.mem.eql(u8, &d_route.next_hop, &c));
        std.debug.print("after A-B: 10->100: D routes via C only (tie gone); B itself rerouted to cost 30 via C-D-B\n", .{});
    }

    // ── negative: asymmetric metrics, opt-in rejection by NAMED error ────────
    // A fresh small database on a separate pair: X advertises Y at cost 10,
    // Y advertises X back at cost 20 — a legal-but-asymmetric IS-IS link
    // (ISO §7.2.8.2 explicitly permits it). `computeWith(reject_asymmetric =
    // true)` is the opt-in fabric-hygiene check some callers (e.g. an
    // 802.1aq/SPB fabric that REQUIRES symmetry) want instead of a silently
    // asymmetric-but-correct table.
    {
        const x = sysId(0x50);
        const y = sysId(0x60);
        var xy_db = lsdb.Lsdb.init(gpa, .{ .local_system_id = x, .interface_count = 1, .capacity = 8 });
        defer xy_db.deinit();
        try insertReach(&xy_db, x, 1, &.{.{ .nbr = y, .metric = 10 }});
        try insertReach(&xy_db, y, 1, &.{.{ .nbr = x, .metric = 20 }});

        // Default (reject_asymmetric = false): computed exactly, each
        // direction at its own advertised metric, and reported.
        {
            var table = try isis_spf.compute(gpa, &xy_db, x, 0);
            defer table.deinit();
            std.debug.assert(table.lookup(y).?.metric == 10); // X->Y uses X's own advertised metric
            std.debug.assert(table.asymmetric_links == 1);
        }
        // Opt-in rejection: this is the failure path that allocates (the
        // topology-extraction pass already built the `directed` map before
        // the asymmetry check fires) and returns early by a NAMED error —
        // never a blanket catch.
        if (isis_spf.computeWith(gpa, &xy_db, x, 0, .{ .reject_asymmetric = true })) |_| {
            unreachable;
        } else |err| switch (err) {
            error.AsymmetricMetric => std.debug.print("asymmetric X<->Y link with reject_asymmetric=true: AsymmetricMetric (expected)\n", .{}),
            else => return err,
        }
    }
}
