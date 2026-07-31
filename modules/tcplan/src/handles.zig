// SPDX-License-Identifier: MIT
//! Deterministic `tc` handle allocation for a compiled plan.
//!
//! The scheme (see SPEC.md for the full contract):
//!
//!   * the `mq` root qdisc is fixed at `mq_root_major:0` (0x7FFF:0), matching
//!     LibreQoS' convention; the kernel auto-creates its per-queue children
//!     `0x7FFF:1 … 0x7FFF:queue_count`;
//!   * CPU `c` (0-based) owns HTB **major `c+1`**: its per-queue HTB root qdisc
//!     is `(c+1):0`, attached under `mq` child `0x7FFF:(c+1)`. Folding the
//!     queue index into the major is what makes the cpumap→MQ→per-CPU
//!     alignment structural — every class of a CPU-`c` subtree is a `(c+1):…`
//!     handle and cannot be confused with another queue's;
//!   * class **minors** are handed out per queue from 1 upward, in the plan's
//!     canonical traversal order (queues ascending, DFS pre-order within a
//!     queue), so a parent's minor is always lower than — and emitted before —
//!     its children's;
//!   * each subscriber's CAKE **leaf qdisc** needs its own globally-unique
//!     major (a qdisc major must be unique across the interface). These come
//!     from one global counter starting at `queue_count+1` (so they never
//!     collide with an HTB major `1…queue_count`), skipping `mq_root_major`;
//!   * filter **priorities** are handed out per queue from 1 upward (a filter
//!     is keyed by (parent, protocol, prio), and all of a queue's steering
//!     filters share the parent `(c+1):0`).
//!
//! All counters advance in a single fixed traversal, so the same topology +
//! CPU assignment always yields byte-identical handles.

const std = @import("std");
const tc = @import("tc");

/// The `mq` root qdisc's major (`0x7FFF`, LibreQoS' convention). Also the
/// ceiling on `queue_count`: HTB majors run `1…queue_count` and must stay
/// below this.
pub const mq_root_major: u16 = 0x7FFF;

/// The largest major any handle may use (`0xFFFE`; `0xFFFF` overlaps the low
/// half of `TC_H_ROOT`).
pub const max_major: u32 = 0xFFFE;

/// The `mq` root qdisc handle, `0x7FFF:0`.
pub fn mqRoot() tc.Handle {
    return tc.Handle.init(mq_root_major, 0);
}

/// The `mq` child a CPU-`c` HTB root attaches under, `0x7FFF:(c+1)`.
pub fn mqParent(cpu: u16) tc.Handle {
    return tc.Handle.init(mq_root_major, cpuToQueue(cpu));
}

/// A CPU-`c` HTB root qdisc handle, `(c+1):0`.
pub fn htbRoot(cpu: u16) tc.Handle {
    return tc.Handle.init(cpuToQueue(cpu), 0);
}

fn cpuToQueue(cpu: u16) u16 {
    return @intCast(@as(u32, cpu) + 1);
}

pub const Error = error{
    /// A per-queue minor/prio counter ran past `0xFFFF`, or the global CAKE
    /// major counter ran past `max_major`.
    HandleExhausted,
};

/// The mutable counters for one compile. `init` allocates the per-queue
/// arrays; `deinit` frees them.
pub const HandleSpace = struct {
    /// Next class minor per CPU (index by cpu); each starts at 1.
    minor_next: []u32,
    /// Next filter prio per CPU; each starts at 1.
    prio_next: []u32,
    /// Next global CAKE-leaf qdisc major; starts at `queue_count+1`.
    cake_major_next: u32,

    pub fn init(gpa: std.mem.Allocator, queue_count: u16) std.mem.Allocator.Error!HandleSpace {
        const minor_next = try gpa.alloc(u32, queue_count);
        errdefer gpa.free(minor_next);
        const prio_next = try gpa.alloc(u32, queue_count);
        @memset(minor_next, 1);
        @memset(prio_next, 1);
        return .{
            .minor_next = minor_next,
            .prio_next = prio_next,
            .cake_major_next = @as(u32, queue_count) + 1,
        };
    }

    pub fn deinit(self: *HandleSpace, gpa: std.mem.Allocator) void {
        gpa.free(self.minor_next);
        gpa.free(self.prio_next);
        self.* = undefined;
    }

    /// Allocate the next class minor for CPU `c` (1, 2, 3, …).
    pub fn nextClassMinor(self: *HandleSpace, cpu: u16) Error!u16 {
        if (self.minor_next[cpu] > 0xFFFF) return error.HandleExhausted;
        const v: u16 = @intCast(self.minor_next[cpu]);
        self.minor_next[cpu] += 1;
        return v;
    }

    /// Allocate the next filter prio for CPU `c` (1, 2, 3, …).
    pub fn nextPrio(self: *HandleSpace, cpu: u16) Error!u16 {
        if (self.prio_next[cpu] > 0xFFFF) return error.HandleExhausted;
        const v: u16 = @intCast(self.prio_next[cpu]);
        self.prio_next[cpu] += 1;
        return v;
    }

    /// Allocate the next globally-unique CAKE-leaf qdisc major, skipping the
    /// reserved `mq_root_major`.
    pub fn nextCakeMajor(self: *HandleSpace) Error!u16 {
        if (self.cake_major_next == mq_root_major) self.cake_major_next += 1;
        if (self.cake_major_next > max_major) return error.HandleExhausted;
        const v: u16 = @intCast(self.cake_major_next);
        self.cake_major_next += 1;
        return v;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "static handles fold the queue index into the major" {
    try testing.expectEqual(@as(u32, 0x7FFF0000), mqRoot().raw);
    try testing.expectEqual(@as(u32, 0x7FFF0001), mqParent(0).raw); // cpu 0 ⇒ mq child 1
    try testing.expectEqual(@as(u32, 0x7FFF0002), mqParent(1).raw);
    try testing.expectEqual(@as(u32, 0x00010000), htbRoot(0).raw); // cpu 0 ⇒ major 1
    try testing.expectEqual(@as(u32, 0x00020000), htbRoot(1).raw);
}

test "per-queue minor/prio counters are independent; cake majors are global" {
    const gpa = testing.allocator;
    var hs = try HandleSpace.init(gpa, 2);
    defer hs.deinit(gpa);

    try testing.expectEqual(@as(u16, 1), try hs.nextClassMinor(0));
    try testing.expectEqual(@as(u16, 2), try hs.nextClassMinor(0));
    try testing.expectEqual(@as(u16, 1), try hs.nextClassMinor(1)); // queue 1 independent

    // Cake majors start above the queue majors (1,2) and never collide.
    try testing.expectEqual(@as(u16, 3), try hs.nextCakeMajor());
    try testing.expectEqual(@as(u16, 4), try hs.nextCakeMajor());

    try testing.expectEqual(@as(u16, 1), try hs.nextPrio(0));
    try testing.expectEqual(@as(u16, 1), try hs.nextPrio(1)); // per-queue prio
}

test "exhaustion: class minor, prio and cake major all fail closed past their ceiling" {
    const gpa = testing.allocator;
    var hs = try HandleSpace.init(gpa, 1);
    defer hs.deinit(gpa);

    hs.minor_next[0] = 0xFFFF;
    try testing.expectEqual(@as(u16, 0xFFFF), try hs.nextClassMinor(0));
    try testing.expectError(error.HandleExhausted, hs.nextClassMinor(0));

    hs.prio_next[0] = 0xFFFF;
    try testing.expectEqual(@as(u16, 0xFFFF), try hs.nextPrio(0));
    try testing.expectError(error.HandleExhausted, hs.nextPrio(0));

    hs.cake_major_next = max_major;
    try testing.expectEqual(@as(u16, max_major), try hs.nextCakeMajor());
    try testing.expectError(error.HandleExhausted, hs.nextCakeMajor());
}

test "cake major counter skips the reserved mq major" {
    const gpa = testing.allocator;
    var hs = try HandleSpace.init(gpa, 1);
    defer hs.deinit(gpa);
    hs.cake_major_next = mq_root_major - 1;
    try testing.expectEqual(@as(u16, mq_root_major - 1), try hs.nextCakeMajor());
    // The next value would be mq_root_major, which is skipped.
    try testing.expectEqual(@as(u16, mq_root_major + 1), try hs.nextCakeMajor());
}
