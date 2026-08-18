// SPDX-License-Identifier: MIT
//! loopfree-reconv — loop-free reconvergence transitions for a link-state fabric.
//!
//! The #1 jewel of the S1b fabric (see ~/CML/S1B-scada-l2vpn-venture-plan.md §5):
//! during convergence, nodes hold inconsistent FIBs and a transient forwarding loop
//! on an L2 overlay is a broadcast storm. This module computes an ordered-FIB / RPF
//! transition schedule so that no transient loop can form, verified in `netsim` with
//! the invariant "no frame ever revisits a node" across fuzzed reconvergence schedules.
//! Builds on `spf-ect` for the shortest-path trees.
//!
//! **Status: complete.** See `../SPEC.md` for the full design and proof.
//!
//! - **`fib.zig`'s `computeUpdateOrder` — the ordering core.** Given a
//!   destination's shortest-path tree before and after a topology change,
//!   produces the per-node FIB-update order that is PROVABLY loop-free at
//!   every intermediate step, not just at the start and end: the two-class
//!   ordered-FIB schedule (decreasing-distance nodes first in ascending
//!   new-distance order, increasing-distance nodes last in descending
//!   old-distance order). See that function's doc comment for the full
//!   loop-freedom proof (Francois/Filsfils/Evans/Bonaventure ordered-FIB
//!   conditions, generalized to arbitrary old/new tree pairs).
//! - **`fabric.zig` — the `netsim.Protocol` consumer + conductor.** A 4-node
//!   ring, per-node FIB, hop-by-hop frame forwarding, the loop invariant
//!   checker (`error.ForwardingLoop`) that gives this module its teeth, and
//!   the conductor that drives topology changes through the ordering and
//!   SERIALIZES overlapping transitions (a new transition's ordered window
//!   never starts until the previous one has fully applied) so that even
//!   back-to-back reconvergences stay loop-free.
//! - **`fib.zig`'s `naiveBadOrder`.** The deliberately-WRONG "apply all FIBs
//!   instantly" baseline ordering, used only as the positive control: it
//!   proves the invariant checker actually catches a real forwarding loop.
//! - **`harness.zig`.** `run`/`findFailing`/`shrink` wrappers around
//!   `netsim`'s own drivers (see that file's doc comment for why a thin
//!   wrapper layer is needed at all).
//!
//! `zig build test-loopfree-reconv` compiles and passes cleanly: the smoke
//! test, the positive-control and shrink tests (all `.naive_bad` mode), and
//! the 5000-seed sweep over the real `.ordered_fable` ordering all pass with
//! no forwarding loop, no crash, and no leak.

const std = @import("std");
const netsim = @import("netsim");
const spf = @import("spf-ect");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "ordered-FIB / RPF loop-free convergence (IS-IS/SPB), TTL backstop",
    .deps = .{ "netsim", "spf-ect" },
};

// ── public API ──────────────────────────────────────────────────────────────

const fib_mod = @import("fib.zig");
/// NOT a stub — see `fib.zig`.
pub const naiveBadOrder = fib_mod.naiveBadOrder;
/// FABLE tier — see `fib.zig`.
pub const computeUpdateOrder = fib_mod.computeUpdateOrder;
pub const changedNodes = fib_mod.changedNodes;

const fabric_mod = @import("fabric.zig");
pub const Fabric = fabric_mod.Fabric;
pub const Mode = fabric_mod.Mode;
pub const scenario = fabric_mod.scenario;
pub const NODE_COUNT = fabric_mod.NODE_COUNT;

const harness = @import("harness.zig");
pub const run = harness.run;
pub const findFailing = harness.findFailing;
pub const shrink = harness.shrink;
pub const Failing = harness.Failing;
pub const ShrinkResult = harness.ShrinkResult;

// ── property-test harness ────────────────────────────────────────────────
//
// Topology + numbers used below (ring 0-1-2-3-0, weights 1/1/1/10, dest=0,
// origin=1) are derived in `fabric.zig`'s module doc; the concrete timing
// derivation for the hand-built positive control is spelled out inline.

const testing = std.testing;

test "smoke: no faults, frames flow origin->dest cleanly, compiles without touching the Fable stub" {
    const gpa = testing.allocator;
    var f = Fabric.init(gpa, .naive_bad);
    const case = netsim.Case{ .seed = 1, .scenario = scenario, .protocol = f.protocol(), .until = 200 };
    const r = try netsim.replay(gpa, case, &.{}, null);
    try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);
}

test "positive control: naive instant FIB ordering DOES cause a transient forwarding loop (checker has teeth)" {
    // Derivation (see fabric.zig's module doc for the full topology):
    // severing edge 1-0 flips node1's next-hop 0->2 and node2's next-hop
    // 1->3. naiveBadOrder applies changed nodes ascending by id, so node1
    // updates first. A frame originated at node1 AFTER its own update
    // (next_hop[1]=2) but delivered to node2 BEFORE node2's update lands
    // (next_hop[2] still the stale 1) bounces straight back to node1, which
    // has already visited itself for that frame — the classic two-node
    // "ships passing" transient loop.
    //
    // Numbers: link_down(1,0) at t=105. naiveBadOrder = [1, 2, (3)];
    // step_gap=50 means node1's update lands at t=105, node2's at t=155.
    // origin period=20 means frames originate at t=20,40,...,100,120,...;
    // the t=100 frame is unaffected (predates the change); the t=120 frame
    // is originated with next_hop[1] already =2, forwarded to node2
    // (latency 5, arrives t=125 — well before node2's t=155 update), which
    // still has the stale next_hop[2]=1 and bounces it back to node1
    // (arrives t=130), which has already visited itself at t=120: loop.
    const gpa = testing.allocator;
    var f = Fabric.init(gpa, .naive_bad);
    const case = netsim.Case{ .seed = 1, .scenario = scenario, .protocol = f.protocol(), .until = 300 };
    const trace = [_]netsim.FaultEvent{
        .{ .time = 105, .kind = .{ .link_down = .{ .a = 1, .b = 0 } } },
    };
    f.setSchedule(&trace);
    const r = try netsim.replay(gpa, case, &trace, null);
    try testing.expectEqual(netsim.RunOutcome.violated, r.outcome);
    try testing.expectEqual(error.ForwardingLoop, r.violation.?.err);
}

test "shrink: netsim's own fuzzer finds a naive-ordering loop across seeds; minimizes to a still-reproducing core" {
    const gpa = testing.allocator;
    var f = Fabric.init(gpa, .naive_bad);
    const template = netsim.Case{ .seed = 0, .scenario = scenario, .protocol = f.protocol(), .until = 800 };
    const fault_cfg = netsim.FaultConfig{
        .max_events = 6,
        .horizon = 700,
        .enable_partition = false, // spf-ect's Graph has no partition concept; out of scope here
        .enable_crash = false,
        .enable_clock_jump = false,
    };

    var failing = (try findFailing(gpa, &f, template, fault_cfg, 1, 2000)) orelse return error.NoFailingSeedFound;
    defer failing.deinit();
    try testing.expectEqual(error.ForwardingLoop, failing.err);

    var res = try shrink(gpa, &f, &failing);
    defer res.deinit();
    try testing.expect(res.after >= 1);
    try testing.expect(res.after <= res.before);

    // The minimized trace still reproduces the exact same violation.
    f.setSchedule(res.trace.events);
    const r = try netsim.replay(gpa, failing.case, res.trace.events, null);
    try testing.expectEqual(netsim.RunOutcome.violated, r.outcome);
    try testing.expectEqual(error.ForwardingLoop, r.violation.?.err);
}

test "teeth-at-scale (Fable core): seed sweep over the REAL ordering finds no forwarding loop" {
    // Exercises the FINAL, real ordering strategy (`.ordered_fable`, i.e.
    // `computeUpdateOrder`) plus the conductor's transition-serialization
    // (see `fabric.zig`). The sweep accumulates a large cumulative event
    // count (up to 5000 seeds x up to ~8 fault events x a few hundred
    // forwarded frames per run over `until=2000`) without ever tripping
    // `error.ForwardingLoop`: a correct ordering algorithm — driven by a
    // conductor that completes each ordered convergence before starting the
    // next — must survive every seed in the range. (Seed 464 is the tightest
    // case: a `link_down 0-1 @894` immediately superseded by `link_up 0-1
    // @940`, which a non-serializing conductor lets loop.)
    const gpa = testing.allocator;
    var f = Fabric.init(gpa, .ordered_fable);
    const template = netsim.Case{ .seed = 0, .scenario = scenario, .protocol = f.protocol(), .until = 2000 };
    const fault_cfg = netsim.FaultConfig{ .max_events = 8, .horizon = 1800 };
    var failing = try findFailing(gpa, &f, template, fault_cfg, 1, 5000);
    // A correct ordering algorithm finds no failing seed at all; free the
    // captured trace on the failure path so a regression reports the loop
    // rather than masking it behind a leak error.
    defer if (failing) |*fl| fl.deinit();
    try testing.expect(failing == null);
}

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────────

test {
    std.testing.refAllDecls(@This());
    _ = netsim;
    _ = spf;
    _ = @import("fib.zig");
    _ = @import("fabric.zig");
    _ = @import("harness.zig");
}
