// SPDX-License-Identifier: MIT
//! The tcplan **output model**: an ordered `Plan` of `tc` operations.
//!
//! An `Operation` is a tagged union over exactly the `(target, spec)` pairs the
//! sibling `tc` module's request builders consume — so the caller turns a plan
//! into netlink bytes by feeding each op straight through
//! `tc.message.buildQdiscSet`/`buildClassSet`/`buildFilterSetWith` (or the
//! `Operation.buildRequest` convenience) and driving a `tc.Socket`. tcplan does
//! **no** I/O itself.
//!
//! The plan is emitted in a kernel-valid order — mq root → per-queue HTB roots
//! → HTB classes (parents before children) → CAKE leaves → steering filters —
//! and every op is plain value data (no owned slices), so a `Plan` owns nothing
//! but the `ops` array. See SPEC.md for the ordering contract.

const std = @import("std");
const tc = @import("tc");
const handles = @import("handles.zig");

/// A qdisc operation: attach `spec` at `target` (the mq root, a per-queue HTB
/// root, or a per-subscriber CAKE leaf).
pub const QdiscOp = struct { target: tc.QdiscTarget, spec: tc.QdiscSpec };
/// A class operation: an HTB class in the rate/ceil hierarchy.
pub const ClassOp = struct { target: tc.ClassTarget, spec: tc.ClassSpec };
/// A filter operation: steer one subscriber's traffic into its leaf class.
pub const FilterOp = struct { target: tc.FilterTarget, spec: tc.FilterSpec };

/// One tc operation. The three variants map one-to-one onto tc's three request
/// builders.
pub const Operation = union(enum) {
    qdisc: QdiscOp,
    class: ClassOp,
    filter: FilterOp,

    /// Build the rtnetlink request bytes for this op through the real `tc`
    /// builders. `create` picks add/replace/change semantics (a reconciling
    /// shaper uses `.replace` throughout for idempotence). Caller owns the
    /// returned slice (`gpa.free`).
    pub fn buildRequest(
        self: Operation,
        gpa: std.mem.Allocator,
        seq: u32,
        create: tc.Create,
        ps: tc.Psched,
    ) tc.BuildError![]u8 {
        return switch (self) {
            .qdisc => |q| tc.message.buildQdiscSet(gpa, seq, create, q.target, q.spec, ps),
            .class => |c| tc.message.buildClassSet(gpa, seq, create, c.target, c.spec, ps),
            .filter => |f| tc.message.buildFilterSetWith(gpa, seq, create, f.target, f.spec, ps),
        };
    }

    /// The qdisc/class handle this op installs, or null for a filter (which
    /// installs no handle of its own).
    pub fn installedHandle(self: Operation) ?tc.Handle {
        return switch (self) {
            .qdisc => |q| q.target.handle,
            .class => |c| c.target.handle,
            .filter => null,
        };
    }

    /// The attach point this op depends on existing first.
    pub fn parentHandle(self: Operation) tc.Handle {
        return switch (self) {
            .qdisc => |q| q.target.parent,
            .class => |c| c.target.parent,
            .filter => |f| f.target.parent,
        };
    }
};

/// An ordered, executable plan. Owns only `ops`.
pub const Plan = struct {
    ops: []Operation,

    pub fn deinit(self: *Plan, gpa: std.mem.Allocator) void {
        gpa.free(self.ops);
        self.* = undefined;
    }

    /// A duplicate qdisc/class handle anywhere in the plan, or null when every
    /// installed handle is unique. This is both an invariant a valid plan must
    /// satisfy and the hook the permanent positive-control test drives RED by
    /// forging a collision.
    pub fn findHandleCollision(self: Plan) ?tc.Handle {
        for (self.ops, 0..) |a, i| {
            const ha = a.installedHandle() orelse continue;
            for (self.ops[i + 1 ..]) |b| {
                const hb = b.installedHandle() orelse continue;
                if (ha.raw == hb.raw) return ha;
            }
        }
        return null;
    }

    /// The index of the first op whose parent attach point was not emitted by
    /// an earlier op, or null when the whole plan is parent-before-child valid.
    ///
    /// The `mq` root's parent is `TC_H_ROOT`; a per-queue HTB root's parent is
    /// an `mq` *child* (`0x7FFF:q`) the kernel auto-creates, so it counts as
    /// available once the `mq` qdisc itself has been emitted. Every other
    /// parent must equal an already-installed qdisc or class handle.
    pub fn firstOrderingViolation(self: Plan, gpa: std.mem.Allocator) std.mem.Allocator.Error!?usize {
        var seen: std.ArrayList(u32) = .empty;
        defer seen.deinit(gpa);
        var mq_seen = false;

        for (self.ops, 0..) |op, i| {
            const parent = op.parentHandle();
            const ok = parent.isRoot() or
                (parent.major() == handles.mq_root_major and mq_seen) or
                contains(seen.items, parent.raw);
            if (!ok) return i;

            if (op.installedHandle()) |h| {
                try seen.append(gpa, h.raw);
                if (h.raw == handles.mqRoot().raw) mq_seen = true;
            }
        }
        return null;
    }
};

fn contains(haystack: []const u32, needle: u32) bool {
    for (haystack) |v| if (v == needle) return true;
    return false;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "findHandleCollision flags a forged duplicate (positive control)" {
    const gpa = testing.allocator;
    const ops = try gpa.alloc(Operation, 2);
    // Two class ops deliberately sharing handle 1:10 — a broken allocator.
    const dup = tc.Handle.init(1, 0x10);
    ops[0] = .{ .class = .{
        .target = .{ .ifindex = 1, .handle = dup, .parent = tc.Handle.init(1, 0) },
        .spec = .{ .htb = .{ .rate = 1000 } },
    } };
    ops[1] = .{ .class = .{
        .target = .{ .ifindex = 1, .handle = dup, .parent = tc.Handle.init(1, 0) },
        .spec = .{ .htb = .{ .rate = 1000 } },
    } };
    var plan: Plan = .{ .ops = ops };
    defer plan.deinit(gpa);
    const hit = plan.findHandleCollision() orelse return error.TestExpectedCollision;
    try testing.expectEqual(dup.raw, hit.raw);
}

test "firstOrderingViolation catches a child before its parent" {
    const gpa = testing.allocator;
    const ops = try gpa.alloc(Operation, 1);
    // A class whose parent qdisc was never emitted.
    ops[0] = .{ .class = .{
        .target = .{ .ifindex = 1, .handle = tc.Handle.init(1, 0x10), .parent = tc.Handle.init(1, 0) },
        .spec = .{ .htb = .{ .rate = 1000 } },
    } };
    var plan: Plan = .{ .ops = ops };
    defer plan.deinit(gpa);
    try testing.expectEqual(@as(?usize, 0), try plan.firstOrderingViolation(gpa));
}
