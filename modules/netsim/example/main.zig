// SPDX-License-Identifier: MIT

//! What a fabric-algorithm author does with `netsim`: plug a small relay
//! protocol into a 4-node chain topology, replay it clean to confirm the
//! invariant holds, then replay the SAME case with one injected duplicate
//! fault to show the invariant hook catching the resulting forwarding loop
//! — netsim's whole reason to exist is making that bug reproducible on
//! demand instead of a rare flake.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! no `test_deps`, no access to anything the module does not export). If a
//! type needed to call the API is not public, or an error cannot be named
//! from outside, this file stops compiling. The module's own tests cannot
//! notice either, because they live inside it.

const std = @import("std");
const netsim = @import("netsim");

const node_count = 4;
const dest: netsim.NodeId = node_count - 1;

/// A deliberately buggy line-relay: forwards a packet one hop toward `dest`
/// on first receipt, but bounces it BACK to the sender on any repeat
/// receipt instead of dropping the duplicate — a single duplicated packet
/// makes two adjacent nodes ping-pong forever.
const Relay = struct {
    visits: [node_count]u32 = .{0} ** node_count,
    threshold: u32 = 3,

    fn protocol(self: *Relay) netsim.Protocol {
        return .{
            .ctx = self,
            .onStartFn = onStart,
            .onMessageFn = onMessage,
            .checkFn = check,
            .resetFn = reset,
        };
    }

    fn cast(ctx: *anyopaque) *Relay {
        return @ptrCast(@alignCast(ctx));
    }

    fn reset(ctx: *anyopaque) void {
        cast(ctx).* = .{};
    }

    fn onStart(ctx: *anyopaque, sim: *netsim.Sim, node: netsim.NodeId) anyerror!void {
        if (node != 0) return;
        try sim.send(0, 1, "x");
        _ = ctx;
    }

    fn onMessage(ctx: *anyopaque, sim: *netsim.Sim, node: netsim.NodeId, from: netsim.NodeId, payload: []const u8) anyerror!void {
        const self = cast(ctx);
        self.visits[node] += 1;
        if (node == dest) return; // consumed at the destination
        if (self.visits[node] == 1) {
            try sim.send(node, node + 1, payload); // correct: one hop toward dest
        } else {
            try sim.send(node, from, payload); // BUG: bounce the duplicate back
        }
    }

    fn check(ctx: *anyopaque, sim: *const netsim.Sim) anyerror!void {
        _ = sim;
        const self = cast(ctx);
        for (self.visits) |v| {
            if (v > self.threshold) return error.ForwardingLoop;
        }
    }
};

fn chainScenario(sim: *netsim.Sim) anyerror!void {
    var i: usize = 0;
    while (i < node_count) : (i += 1) _ = try sim.addNode(.{});
    const cfg = netsim.LinkConfig{ .latency = 10 };
    var j: netsim.NodeId = 0;
    while (j + 1 < node_count) : (j += 1) try sim.addBiLink(j, j + 1, cfg);
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var relay = Relay{};
    const case = netsim.Case{ .seed = 1, .scenario = chainScenario, .protocol = relay.protocol(), .until = 200 };

    // Clean run: no faults, no duplicate, invariant holds throughout.
    const clean = try netsim.replay(gpa, case, &.{}, null);
    std.debug.print("clean run: outcome={s} events={d}\n", .{ @tagName(clean.outcome), clean.events_processed });
    if (clean.outcome != .ok) return error.ExpectedCleanRun;

    // One duplicate on the forward link 1->2, scheduled at t=0, starts the
    // ping-pong loop the invariant is watching for. It must target a hop
    // AFTER the origin: `dup_once` arms by sitting in the event queue at
    // t=0, but a node's `onStart` send happens synchronously during
    // bootstrap, before the queue is drained — so faulting the origin link
    // (0->1) would arm too late to catch that first send. Targeting 1->2
    // (a queue-driven forward, not a bootstrap send) is what makes this
    // fire reliably, same as the module's own "invariant hook catches a
    // forwarding loop" test.
    const trace = [_]netsim.FaultEvent{.{ .time = 0, .kind = .{ .dup_once = .{ .a = 1, .b = 2 } } }};
    const bad = try netsim.replay(gpa, case, &trace, null);
    std.debug.print("faulty run: outcome={s}\n", .{@tagName(bad.outcome)});
    if (bad.outcome != .violated) return error.ExpectedViolation;

    // The violation names the exact error the invariant returned — a caller
    // triaging a fuzzer finding needs this to be a real, nameable error, not
    // an opaque bool.
    const violation = bad.violation orelse return error.ExpectedViolationDetail;
    if (violation.err != error.ForwardingLoop) return error.UnexpectedViolationKind;
    std.debug.print("invariant caught: {s} at t={d}\n", .{ @errorName(violation.err), violation.time });
}
