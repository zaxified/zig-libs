// SPDX-License-Identifier: MIT

//! A shrinker over a fleet's OWN inputs: the `Fault`s scheduled and the frames
//! submitted. `netsim`'s trace shrinker (`vopr.shrinkTrace`) minimises the
//! fault schedule of a netsim run; what it cannot express is a failure that
//! needs a particular submitted frame, or a fleet-level fault (`silent`,
//! `trouble`, `restart` ...) that no netsim event stands for. This one takes
//! both kinds as one list of `Input`s and runs the same Zeller ddmin
//! (`netsim.ddmin`) over it: the caller's oracle builds a fresh fleet, applies
//! a candidate list with `apply`, runs it and says whether the failure
//! reproduced; the result is a 1-minimal list (no single input can be removed).
//!
//! Inputs keep their times, so a kept subset replays at the same simulated
//! instants and the run stays a deterministic function of (seed, subset).

const std = @import("std");
const netsim = @import("netsim");
const fleet_mod = @import("fleet.zig");

const Allocator = std.mem.Allocator;

pub const Submit = struct {
    node: fleet_mod.NodeId,
    at_ms: fleet_mod.Time,
    /// Borrowed: must outlive the shrink.
    frame: []const u8,
};

pub const Input = union(enum) {
    fault: fleet_mod.Fault,
    submit: Submit,
};

/// Schedule every input in `inputs` on `fleet` (faults through `addFault`, frames
/// through `submit`, both at their own times). The caller then `advance`s.
/// A `QueueFull` / `FrameTooLarge` on a submit is the run's own business (the fleet
/// counts it) and does not stop the rest.
pub fn apply(fleet: *fleet_mod.Fleet, inputs: []const Input) fleet_mod.Error!void {
    for (inputs) |in| switch (in) {
        .fault => |f| try fleet.addFault(f),
        .submit => |s| fleet.submit(s.node, s.frame, s.at_ms) catch |e| switch (e) {
            error.QueueFull, error.FrameTooLarge => {},
            else => return e,
        },
    };
}

/// ddmin over `inputs`. `ctx.fails(subset: []const Input) Allocator.Error!bool` runs
/// the candidate and says whether the failure still happens (an error other than
/// OutOfMemory is the oracle's to turn into `false`). Returns the kept inputs
/// (caller frees); when the failure needs no input at all, the empty list.
pub fn shrinkInputs(gpa: Allocator, inputs: []const Input, ctx: anytype) Allocator.Error![]Input {
    const Adapter = struct {
        gpa: Allocator,
        all: []const Input,
        user: @TypeOf(ctx),

        pub fn keeps(self: *@This(), subset: []const usize) Allocator.Error!bool {
            const picked = try self.gpa.alloc(Input, subset.len);
            defer self.gpa.free(picked);
            for (subset, picked) |i, *p| p.* = self.all[i];
            return self.user.fails(picked);
        }
    };
    var ad: Adapter = .{ .gpa = gpa, .all = inputs, .user = ctx };
    const kept = try netsim.ddmin(gpa, inputs.len, &ad);
    defer gpa.free(kept);
    const out = try gpa.alloc(Input, kept.len);
    for (kept, out) |i, *o| o.* = inputs[i];
    return out;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const adapters = @import("adapters.zig");
const modbus = @import("modbus");

const Oracle = struct {
    runs: usize = 0,

    /// The failure: a Modbus exception reply (0x83) was emitted. It needs a `trouble`
    /// fault AND a read submitted after it.
    pub fn fails(self: *Oracle, subset: []const Input) Allocator.Error!bool {
        self.runs += 1;
        var holding = [_]u16{ 1, 2, 3 };
        var slave = adapters.Modbus.init(.{ .unit_id = 1, .framing = .tcp }, .{ .holding_registers = .{ .base = 0, .values = &holding } });
        var fleet = try fleet_mod.Fleet.init(testing.allocator, .{ .seed = 3 });
        defer fleet.deinit();
        _ = try fleet.addNode(.{ .node = slave.node() });
        apply(&fleet, subset) catch return false;
        var seen = false;
        var t: fleet_mod.Time = 0;
        while (t <= 1000) : (t += 100) {
            _ = fleet.advance(t) catch return false;
            for (fleet.outbound()) |f| {
                const adu = modbus.tcp.decodeAdu(fleet.frameBytes(f)) catch continue;
                if (adu.pdu.len > 0 and adu.pdu[0] == 0x83) seen = true;
            }
        }
        return seen;
    }
};

test "shrinkInputs reduces a noisy run to the one fault and the one frame that matter" {
    var req_buf: [8][modbus.tcp.max_adu_len]u8 = undefined;
    var pdu: [8]u8 = undefined;
    const p = try modbus.pdu.encodeReadRequest(&pdu, .read_holding_registers, 0, 1);
    var inputs: [14]Input = undefined;
    var n: usize = 0;
    // Noise faults, a trouble fault at 400, eight reads from 0 to 700 ms.
    for ([_]fleet_mod.FaultKind{ .{ .link = .{ .delay_ms = 3 } }, .{ .drop_next = .{ .count = 0 } }, .heal, .{ .dup_next = .{ .count = 0 } }, .{ .delay_next = .{ .count = 0, .extra_ms = 1 } } }, 0..) |k, i| {
        inputs[n] = .{ .fault = .{ .at_ms = i * 90, .node = 0, .kind = k } };
        n += 1;
    }
    inputs[n] = .{ .fault = .{ .at_ms = 400, .node = 0, .kind = .{ .trouble = .{ .on = true } } } };
    n += 1;
    for (&req_buf, 0..) |*b, i| {
        const adu = try modbus.tcp.encodeAdu(b, @intCast(i + 1), 1, p);
        inputs[n] = .{ .submit = .{ .node = 0, .at_ms = i * 100, .frame = adu } };
        n += 1;
    }
    try testing.expectEqual(inputs.len, n);
    var oracle: Oracle = .{};
    try testing.expect(try oracle.fails(&inputs)); // the whole run fails ...
    const kept = try shrinkInputs(testing.allocator, &inputs, &oracle);
    defer testing.allocator.free(kept);
    // ... and two inputs are enough: the trouble fault and a read after it.
    try testing.expectEqual(@as(usize, 2), kept.len);
    var faults: usize = 0;
    for (kept) |k| switch (k) {
        .fault => |f| {
            faults += 1;
            try testing.expect(f.kind == .trouble);
        },
        .submit => |s| try testing.expect(s.at_ms >= 400),
    };
    try testing.expectEqual(@as(usize, 1), faults);
    // A failure that needs nothing shrinks to nothing.
    const Always = struct {
        pub fn fails(_: *@This(), _: []const Input) Allocator.Error!bool {
            return true;
        }
    };
    var always: Always = .{};
    const none = try shrinkInputs(testing.allocator, &inputs, &always);
    defer testing.allocator.free(none);
    try testing.expectEqual(@as(usize, 0), none.len);
}
