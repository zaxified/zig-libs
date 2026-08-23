// SPDX-License-Identifier: MIT

//! What a router's IS-IS control plane does with `isis-adj`: own one
//! `Adjacency` per point-to-point circuit, feed it the neighbour's IIH bytes
//! as they arrive off the wire, and drive it through the RFC 5303 three-way
//! handshake (Down -> Initializing -> Up) using the caller's own clock. This
//! example plays both sides of a single circuit to show a full convergence,
//! then feeds one malformed PDU to show a decode failure is a named,
//! recoverable error rather than a corrupted FSM.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const isis_adj = @import("isis-adj");

const sys_a: isis_adj.SystemId = .{ 0, 0, 0, 0, 0, 0xA };
const sys_b: isis_adj.SystemId = .{ 0, 0, 0, 0, 0, 0xB };

fn wire(buf: []u8, hf: isis_adj.HelloFields) []const u8 {
    return isis_adj.buildHello(buf, hf) catch unreachable;
}

pub fn main() !void {
    var a = isis_adj.Adjacency.init(.{ .system_id = sys_a, .extended_local_circuit_id = 0xA1, .hello_interval = 10 });
    var b = isis_adj.Adjacency.init(.{ .system_id = sys_b, .extended_local_circuit_id = 0xB1, .hello_interval = 10 });

    var abuf: [128]u8 = undefined;
    var bbuf: [128]u8 = undefined;

    // t = 0: both circuits come up and emit their first IIH.
    var wa = wire(&abuf, a.start(0).send_hello.?);
    var wb = wire(&bbuf, b.start(0).send_hello.?);
    std.debug.print("t=0: a={s} b={s}\n", .{ @tagName(a.currentState()), @tagName(b.currentState()) });

    // A malformed PDU must fail with a nameable decode error and leave the
    // FSM untouched — a real router sees garbage on the wire routinely
    // (corruption, a mid-negotiation link flap) and must not crash on it.
    const garbage = [_]u8{0xFF} ** 24;
    if (a.rxHelloBytes(&garbage, 1)) |_| {
        return error.GarbagePduUnexpectedlyAccepted;
    } else |err| switch (err) {
        error.BadDiscriminator => std.debug.print("garbage PDU correctly rejected, FSM unchanged (state={s})\n", .{@tagName(a.currentState())}),
        else => return err,
    }

    var t: isis_adj.Time = 1;
    var round: usize = 0;
    while (round < 6 and !(a.currentState() == .up and b.currentState() == .up)) : (round += 1) {
        const ea = try a.rxHelloBytes(wb, t);
        const eb = try b.rxHelloBytes(wa, t);
        if (ea.transition) |tr| std.debug.print("t={d}: a {s} -> {s}\n", .{ t, @tagName(tr.from), @tagName(tr.to) });
        if (eb.transition) |tr| std.debug.print("t={d}: b {s} -> {s}\n", .{ t, @tagName(tr.from), @tagName(tr.to) });
        wa = wire(&abuf, a.helloFields());
        wb = wire(&bbuf, b.helloFields());
        t += 1;
    }

    std.debug.print("converged: a={s} b={s}\n", .{ @tagName(a.currentState()), @tagName(b.currentState()) });
    // The retry loop above is bounded (6 rounds) precisely so a stalled
    // handshake does not hang the example forever — but a bound that is
    // never reached under correct behavior must not be silently accepted as
    // "the loop ended, so print whatever state we're in". Both sides must
    // actually have reached .up.
    if (a.currentState() != .up or b.currentState() != .up) return error.AdjacencyUnexpectedlyNotConverged;

    // Once Up, a hold-timer expiry (no more hellos arriving) must bring the
    // adjacency back down — the other half of the lifecycle a caller drives.
    const hold_deadline = t + a.nextHelloDue() + 100;
    const down_effect = a.tick(hold_deadline);
    const reason = down_effect.adjacency_down orelse return error.HoldExpiryUnexpectedlyDidNotBringAdjacencyDown;
    std.debug.print("hold expiry: adjacency down, reason={s}\n", .{@tagName(reason)});
}
