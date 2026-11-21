// SPDX-License-Identifier: MIT

//! Arbitrary topology and fault-schedule input for the fabric harness.
//!
//! `Spec` is a fabric a user DESCRIBES instead of hard-coding: a text format
//! (`parse`), a seeded random generator of connected fabrics with a fault
//! schedule that never partitions them (`random`), a way to build and run it
//! (`Spec.build`, `Spec.run`), the end-to-end verdict (`Spec.verify`) and a
//! greedy minimiser that shrinks a failing schedule (`minimize`), the role
//! `netsim.shrink` plays for netsim's own faults. A spec is validated before
//! it reaches `Fabric.init`, whose structural checks are assertions.
//!
//! ## Text format
//! One directive per line, `#` starts a comment, numbers are decimal:
//!
//! ```text
//! nodes 6                      # how many routers (0..n-1)
//! edge 0 1 10                  # a point-to-point link and its metric (default 10)
//! lan 10 3 4:100 5             # a LAN: metric, then members node[:priority]
//! fail 3000 0 1                # sever the link 0-1 at that time
//! priority 4000 0 5 120        # at time, LAN 0: node 5 advertises priority 120
//! crash 5000 2                 # stop node 2 for good
//! restart 6000 1               # cold-restart node 1 (control plane)
//! ```
//!
//! Every directive's failure is a typed error, never an assertion.

const std = @import("std");
const Allocator = std.mem.Allocator;
const netsim = @import("netsim");
const fabric = @import("fabric.zig");

const NodeId = netsim.NodeId;
const Time = netsim.Time;
const Fabric = fabric.Fabric;
const Edge = fabric.Edge;
const Lan = fabric.Lan;
const LanMember = fabric.LanMember;

pub const Fail = struct { time: Time, a: NodeId, b: NodeId };
pub const Priority = struct { time: Time, lan: u16, node: NodeId, priority: u7 };
pub const NodeTime = struct { node: NodeId, time: Time };

pub const ParseError = error{
    UnknownDirective,
    MissingNodes,
    BadNumber,
    MissingArgument,
    NodeOutOfRange,
    SelfLoop,
    DuplicateEdge,
    DuplicateLanMember,
    LanSize,
    PairOnEdgeAndLan,
    NoSuchEdge,
    NoSuchLan,
    NotALanMember,
    TooManyLans,
    OutOfMemory,
};

pub const Spec = struct {
    arena: std.heap.ArenaAllocator,
    node_count: u32,
    edges: []Edge,
    lans: []Lan,
    failures: []Fail,
    priorities: []Priority,
    crash: ?NodeTime = null,
    restart: ?NodeTime = null,

    pub fn deinit(self: *Spec) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn topology(self: *const Spec) fabric.Topology {
        return .{ .node_count = self.node_count, .edges = self.edges, .lans = self.lans };
    }

    /// Build the fabric and register the schedule. The caller drives it with
    /// `runToConvergence` (or uses `run`) and owns the result (`deinit`).
    pub fn build(self: *const Spec, gpa: Allocator, opts: fabric.Options, seed: u64) !Fabric {
        var fab = try Fabric.initWithOptions(gpa, self.topology(), seed, opts);
        errdefer fab.deinit();
        for (self.failures) |f| try fab.failLinkAt(f.a, f.b, f.time);
        for (self.priorities) |p| try fab.setLanPriorityAt(p.lan, p.node, p.priority, p.time);
        if (self.crash) |c| fab.crash = .{ .node = c.node, .time = c.time };
        if (self.restart) |r| fab.restart = .{ .node = r.node, .time = r.time };
        return fab;
    }

    /// The last scheduled event time plus a margin: a horizon that lets the
    /// fabric settle after the schedule.
    pub fn horizon(self: *const Spec) Time {
        var t: Time = 0;
        for (self.failures) |f| t = @max(t, f.time);
        for (self.priorities) |p| t = @max(t, p.time);
        if (self.crash) |c| t = @max(t, c.time);
        if (self.restart) |r| t = @max(t, r.time);
        return t + 4000;
    }

    /// Build, run to the schedule's horizon, and return the fabric.
    pub fn run(self: *const Spec, gpa: Allocator, opts: fabric.Options, seed: u64) !struct { fab: Fabric, outcome: fabric.Outcome } {
        var fab = try self.build(gpa, opts, seed);
        errdefer fab.deinit();
        const outcome = try fab.runToConvergence(self.horizon());
        return .{ .fab = fab, .outcome = outcome };
    }

    /// Which nodes can still reach which, after every `fail` and a `crash`:
    /// component labels over the surviving point-to-point links and LANs.
    pub fn components(self: *const Spec, gpa: Allocator) Allocator.Error![]u32 {
        return componentsOf(gpa, self.node_count, self.edges, self.lans, self.failures, self.crash);
    }

    fn componentsOf(gpa: Allocator, n: u32, edges: []const Edge, lans: []const Lan, failures: []const Fail, crash: ?NodeTime) Allocator.Error![]u32 {
        const label = try gpa.alloc(u32, n);
        for (label, 0..) |*l, i| l.* = @intCast(i);
        const Ctx = struct {
            label: []u32,
            fn find(c: @This(), x: u32) u32 {
                var r = x;
                while (c.label[r] != r) r = c.label[r];
                return r;
            }
            fn join(c: @This(), a: u32, b: u32) void {
                const ra = c.find(a);
                const rb = c.find(b);
                if (ra != rb) c.label[@max(ra, rb)] = @min(ra, rb);
            }
        };
        const ctx = Ctx{ .label = label };
        const dead: ?NodeId = if (crash) |c| c.node else null;
        for (edges) |e| {
            if (dead != null and (e.a == dead.? or e.b == dead.?)) continue;
            var failed = false;
            for (failures) |f| {
                if ((f.a == e.a and f.b == e.b) or (f.a == e.b and f.b == e.a)) failed = true;
            }
            if (!failed) ctx.join(e.a, e.b);
        }
        for (lans) |l| {
            var first: ?u32 = null;
            for (l.members) |m| {
                if (dead != null and m.node == dead.?) continue;
                if (first) |f| ctx.join(f, m.node) else first = m.node;
            }
        }
        for (label, 0..) |*l, i| l.* = ctx.find(@intCast(i));
        return label;
    }

    pub const Verdict = enum {
        ok,
        not_converged,
        lsdbs_disagree,
        unreachable_pair,
        reaches_across_partition,
    };

    /// The end-to-end property of a finished run: it quiesced, every pair of
    /// surviving nodes in one component has a route and no pair across
    /// components does, and in a connected survivor set the LSDBs agree. A
    /// spec with a `crash` is judged on the survivors only (the dead node's
    /// LSP lives on until it ages, which is the aging scenario's business).
    pub fn verify(self: *const Spec, gpa: Allocator, fab: *const Fabric, outcome: fabric.Outcome) Allocator.Error!Verdict {
        if (outcome != .converged) return .not_converged;
        const label = try self.components(gpa);
        defer gpa.free(label);
        const dead: ?NodeId = if (self.crash) |c| c.node else null;
        var connected = true;
        for (label, 0..) |l, i| {
            if (dead != null and i == dead.?) continue;
            for (label, 0..) |m, j| {
                if (dead != null and j == dead.?) continue;
                if (l != m) connected = false;
            }
        }
        if (connected and dead == null and !fab.lsdbsAgree()) return .lsdbs_disagree;
        for (0..self.node_count) |i| {
            if (dead != null and i == dead.?) continue;
            for (0..self.node_count) |j| {
                if (i == j or (dead != null and j == dead.?)) continue;
                const hop = try fab.reaches(gpa, @intCast(i), @intCast(j));
                const same = label[i] == label[j];
                if (same and hop == null) return .unreachable_pair;
                if (!same and hop != null) return .reaches_across_partition;
            }
        }
        return .ok;
    }
};

// ── parsing ──────────────────────────────────────────────────────────────

fn num(comptime T: type, tok: []const u8) ParseError!T {
    return std.fmt.parseInt(T, tok, 10) catch return error.BadNumber;
}

pub fn parse(gpa: Allocator, text: []const u8) ParseError!Spec {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    var node_count: ?u32 = null;
    var edges: std.ArrayList(Edge) = .empty;
    var lans: std.ArrayList(Lan) = .empty;
    var failures: std.ArrayList(Fail) = .empty;
    var prios: std.ArrayList(Priority) = .empty;
    var crash: ?NodeTime = null;
    var restart: ?NodeTime = null;

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = if (std.mem.indexOfScalar(u8, raw, '#')) |i| raw[0..i] else raw;
        var it = std.mem.tokenizeAny(u8, line, " \t\r");
        const word = it.next() orelse continue;
        if (std.mem.eql(u8, word, "nodes")) {
            node_count = try num(u32, it.next() orelse return error.MissingArgument);
            if (node_count.? == 0) return error.MissingNodes;
        } else if (std.mem.eql(u8, word, "edge")) {
            const n = node_count orelse return error.MissingNodes;
            const x = try num(u32, it.next() orelse return error.MissingArgument);
            const y = try num(u32, it.next() orelse return error.MissingArgument);
            const metric: u24 = if (it.next()) |m| try num(u24, m) else 10;
            if (x >= n or y >= n) return error.NodeOutOfRange;
            if (x == y) return error.SelfLoop;
            for (edges.items) |e| {
                if ((e.a == x and e.b == y) or (e.a == y and e.b == x)) return error.DuplicateEdge;
            }
            try edges.append(a, .{ .a = x, .b = y, .metric = metric });
        } else if (std.mem.eql(u8, word, "lan")) {
            const n = node_count orelse return error.MissingNodes;
            const metric = try num(u24, it.next() orelse return error.MissingArgument);
            var members: std.ArrayList(LanMember) = .empty;
            while (it.next()) |tok| {
                var parts = std.mem.splitScalar(u8, tok, ':');
                const node = try num(u32, parts.next().?);
                const prio: u7 = if (parts.next()) |p| std.math.cast(u7, try num(u16, p)) orelse return error.BadNumber else 64;
                if (node >= n) return error.NodeOutOfRange;
                for (members.items) |m| if (m.node == node) return error.DuplicateLanMember;
                try members.append(a, .{ .node = node, .priority = prio });
            }
            if (members.items.len == 0 or members.items.len > fabric.max_lan_members) return error.LanSize;
            if (lans.items.len >= 254) return error.TooManyLans;
            try lans.append(a, .{ .members = members.items, .metric = metric });
        } else if (std.mem.eql(u8, word, "fail")) {
            const t = try num(Time, it.next() orelse return error.MissingArgument);
            const x = try num(u32, it.next() orelse return error.MissingArgument);
            const y = try num(u32, it.next() orelse return error.MissingArgument);
            try failures.append(a, .{ .time = t, .a = x, .b = y });
        } else if (std.mem.eql(u8, word, "priority")) {
            const t = try num(Time, it.next() orelse return error.MissingArgument);
            const l = try num(u16, it.next() orelse return error.MissingArgument);
            const node = try num(u32, it.next() orelse return error.MissingArgument);
            const p = std.math.cast(u7, try num(u16, it.next() orelse return error.MissingArgument)) orelse return error.BadNumber;
            try prios.append(a, .{ .time = t, .lan = l, .node = node, .priority = p });
        } else if (std.mem.eql(u8, word, "crash") or std.mem.eql(u8, word, "restart")) {
            const t = try num(Time, it.next() orelse return error.MissingArgument);
            const node = try num(u32, it.next() orelse return error.MissingArgument);
            const nt: NodeTime = .{ .node = node, .time = t };
            if (word[0] == 'c') crash = nt else restart = nt;
        } else return error.UnknownDirective;
    }
    const n = node_count orelse return error.MissingNodes;

    // Cross-checks that `Fabric.init` would only assert.
    for (lans.items, 0..) |l, li| {
        for (l.members, 0..) |m, i| {
            for (l.members[i + 1 ..]) |o| {
                for (edges.items) |e| {
                    if ((e.a == m.node and e.b == o.node) or (e.a == o.node and e.b == m.node)) return error.PairOnEdgeAndLan;
                }
                for (lans.items[li + 1 ..]) |l2| {
                    var ina = false;
                    var inb = false;
                    for (l2.members) |m2| {
                        if (m2.node == m.node) ina = true;
                        if (m2.node == o.node) inb = true;
                    }
                    if (ina and inb) return error.PairOnEdgeAndLan;
                }
            }
        }
    }
    for (failures.items) |f| {
        if (f.a >= n or f.b >= n) return error.NodeOutOfRange;
        var found = false;
        for (edges.items) |e| {
            if ((e.a == f.a and e.b == f.b) or (e.a == f.b and e.b == f.a)) found = true;
        }
        if (!found) return error.NoSuchEdge;
    }
    for (prios.items) |p| {
        if (p.lan >= lans.items.len) return error.NoSuchLan;
        var member = false;
        for (lans.items[p.lan].members) |m| if (m.node == p.node) {
            member = true;
        };
        if (!member) return error.NotALanMember;
    }
    if (crash) |c| if (c.node >= n) return error.NodeOutOfRange;
    if (restart) |r| if (r.node >= n) return error.NodeOutOfRange;
    return .{
        .arena = arena,
        .node_count = n,
        .edges = edges.items,
        .lans = lans.items,
        .failures = failures.items,
        .priorities = prios.items,
        .crash = crash,
        .restart = restart,
    };
}

// ── random fabrics ───────────────────────────────────────────────────────

pub const RandomParams = struct {
    min_nodes: u32 = 3,
    max_nodes: u32 = 16,
    /// Extra edges beyond the spanning tree, per mille of the possible pairs.
    extra_edges_permille: u32 = 120,
    max_metric: u24 = 20,
    max_failures: u32 = 3,
    /// Scheduled failures are drawn in [first_fail, first_fail + 2000).
    first_fail: Time = 1000,
};

/// A connected fabric of random size and metrics with up to `max_failures`
/// scheduled link failures that never disconnect it (each is a non-bridge of
/// what remains), drawn from `rnd`. Deterministic in the generator state.
pub fn random(gpa: Allocator, rnd: std.Random, p: RandomParams) Allocator.Error!Spec {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    const n = rnd.intRangeAtMost(u32, p.min_nodes, p.max_nodes);
    var edges: std.ArrayList(Edge) = .empty;
    var i: u32 = 1;
    while (i < n) : (i += 1) {
        try edges.append(a, .{ .a = rnd.intRangeLessThan(u32, 0, i), .b = i, .metric = rnd.intRangeAtMost(u24, 1, p.max_metric) });
    }
    var x: u32 = 0;
    while (x < n) : (x += 1) {
        var y = x + 1;
        while (y < n) : (y += 1) {
            var have = false;
            for (edges.items) |e| {
                if ((e.a == x and e.b == y) or (e.a == y and e.b == x)) have = true;
            }
            if (!have and rnd.intRangeLessThan(u32, 0, 1000) < p.extra_edges_permille) {
                try edges.append(a, .{ .a = x, .b = y, .metric = rnd.intRangeAtMost(u24, 1, p.max_metric) });
            }
        }
    }
    var failures: std.ArrayList(Fail) = .empty;
    var tries: u32 = 0;
    while (failures.items.len < p.max_failures and tries < 20) : (tries += 1) {
        const e = edges.items[rnd.intRangeLessThan(usize, 0, edges.items.len)];
        var already = false;
        for (failures.items) |f| {
            if ((f.a == e.a and f.b == e.b) or (f.a == e.b and f.b == e.a)) already = true;
        }
        if (already) continue;
        try failures.append(a, .{ .time = p.first_fail + rnd.intRangeLessThan(Time, 0, 2000), .a = e.a, .b = e.b });
        // Keep the fabric connected: drop the failure again if it is a cut set.
        const label = try Spec.componentsOf(gpa, n, edges.items, &.{}, failures.items, null);
        defer gpa.free(label);
        for (label) |l| if (l != 0) {
            _ = failures.pop();
            break;
        };
    }
    return .{ .arena = arena, .node_count = n, .edges = edges.items, .lans = &.{}, .failures = failures.items, .priorities = &.{} };
}

// ── minimiser ────────────────────────────────────────────────────────────

/// Shrink a failing spec: drop failures one at a time and keep each removal
/// that still fails `stillFails`. Returns how many failures remain. A greedy
/// pass is enough here: the schedule is a handful of events.
pub fn minimize(spec: *Spec, ctx: anytype, comptime stillFails: fn (@TypeOf(ctx), *const Spec) anyerror!bool) anyerror!usize {
    var i: usize = 0;
    while (i < spec.failures.len) {
        const saved = spec.failures;
        var trial = try spec.arena.allocator().alloc(Fail, saved.len - 1);
        @memcpy(trial[0..i], saved[0..i]);
        @memcpy(trial[i..], saved[i + 1 ..]);
        spec.failures = trial;
        if (try stillFails(ctx, spec)) continue; // removal kept; same index now holds the next
        spec.failures = saved;
        i += 1;
    }
    return spec.failures.len;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "parse: every directive, defaults, comments and the resulting topology" {
    var s = try parse(testing.allocator,
        \\# a LAN of three with a tail
        \\nodes 6
        \\edge 0 1          # default metric
        \\edge 1 2 25
        \\lan 10 3:100 4 5
        \\edge 2 3 7
        \\fail 3000 1 2
        \\priority 4000 0 5 120
        \\crash 5000 0
        \\restart 6000 1
    );
    defer s.deinit();
    try testing.expectEqual(@as(u32, 6), s.node_count);
    try testing.expectEqual(@as(usize, 3), s.edges.len);
    try testing.expectEqual(@as(u24, 10), s.edges[0].metric);
    try testing.expectEqual(@as(u24, 25), s.edges[1].metric);
    try testing.expectEqual(@as(usize, 1), s.lans.len);
    try testing.expectEqual(@as(usize, 3), s.lans[0].members.len);
    try testing.expectEqual(@as(u7, 100), s.lans[0].members[0].priority);
    try testing.expectEqual(@as(u7, 64), s.lans[0].members[1].priority);
    try testing.expectEqual(@as(Time, 3000), s.failures[0].time);
    try testing.expectEqual(@as(u7, 120), s.priorities[0].priority);
    try testing.expectEqual(@as(NodeId, 0), s.crash.?.node);
    try testing.expectEqual(@as(Time, 6000), s.restart.?.time);
    try testing.expectEqual(@as(Time, 10_000), s.horizon());
}

test "parse: every malformed input is a typed error, never an assertion" {
    const cases = [_]struct { text: []const u8, err: ParseError }{
        .{ .text = "edge 0 1", .err = error.MissingNodes },
        .{ .text = "", .err = error.MissingNodes },
        .{ .text = "nodes 0", .err = error.MissingNodes },
        .{ .text = "nodes x", .err = error.BadNumber },
        .{ .text = "nodes", .err = error.MissingArgument },
        .{ .text = "nodes 3\nfoo", .err = error.UnknownDirective },
        .{ .text = "nodes 3\nedge 0 3", .err = error.NodeOutOfRange },
        .{ .text = "nodes 3\nedge 1 1", .err = error.SelfLoop },
        .{ .text = "nodes 3\nedge 0 1\nedge 1 0", .err = error.DuplicateEdge },
        .{ .text = "nodes 3\nlan 10", .err = error.LanSize },
        .{ .text = "nodes 12\nlan 10 0 1 2 3 4 5 6 7 8", .err = error.LanSize },
        .{ .text = "nodes 3\nlan 10 0 0", .err = error.DuplicateLanMember },
        .{ .text = "nodes 3\nlan 10 0:200 1", .err = error.BadNumber },
        .{ .text = "nodes 3\nedge 0 1\nlan 10 0 1", .err = error.PairOnEdgeAndLan },
        .{ .text = "nodes 4\nlan 10 0 1 2\nlan 10 1 2 3", .err = error.PairOnEdgeAndLan },
        .{ .text = "nodes 3\nedge 0 1\nfail 5 1 2", .err = error.NoSuchEdge },
        .{ .text = "nodes 3\nlan 10 0 1\npriority 5 1 0 9", .err = error.NoSuchLan },
        .{ .text = "nodes 3\nlan 10 0 1\npriority 5 0 2 9", .err = error.NotALanMember },
        .{ .text = "nodes 3\ncrash 5 9", .err = error.NodeOutOfRange },
    };
    for (cases) |c| try testing.expectError(c.err, parse(testing.allocator, c.text));
}

test "a described fabric runs: a ring with a mid-run failure converges and every node still reaches every other" {
    var s = try parse(testing.allocator,
        \\nodes 6
        \\edge 0 1
        \\edge 1 2
        \\edge 2 3
        \\edge 3 4
        \\edge 4 5
        \\edge 5 0
        \\fail 2000 2 3
    );
    defer s.deinit();
    var r = try s.run(testing.allocator, .{}, 7);
    defer r.fab.deinit();
    try testing.expectEqual(fabric.Outcome.converged, r.outcome);
    try testing.expectEqual(Spec.Verdict.ok, try s.verify(testing.allocator, &r.fab, r.outcome));
    // 2 -> 3 now goes the long way round.
    try testing.expectEqual(fabric.systemIdForNode(1), (try r.fab.reaches(testing.allocator, 2, 3)).?);
}

test "a described partition is detected: the verdict wants no route across the cut" {
    var s = try parse(testing.allocator,
        \\nodes 4
        \\edge 0 1
        \\edge 1 2
        \\edge 2 3
        \\fail 2000 1 2
    );
    defer s.deinit();
    var r = try s.run(testing.allocator, .{}, 3);
    defer r.fab.deinit();
    try testing.expectEqual(Spec.Verdict.ok, try s.verify(testing.allocator, &r.fab, r.outcome));
    const label = try s.components(testing.allocator);
    defer testing.allocator.free(label);
    try testing.expect(label[0] == label[1] and label[2] == label[3] and label[0] != label[2]);
}

test "a described LAN fabric with a priority change preempts the DIS" {
    var s = try parse(testing.allocator,
        \\nodes 5
        \\lan 10 0 1 2:90
        \\edge 2 3
        \\edge 3 4
        \\priority 3000 0 0 127
    );
    defer s.deinit();
    var r = try s.run(testing.allocator, .{}, 11);
    defer r.fab.deinit();
    try testing.expectEqual(Spec.Verdict.ok, try s.verify(testing.allocator, &r.fab, r.outcome));
    try testing.expect(r.fab.isDis(0, 0));
}

test "verify has teeth: a broken drain is reported, not ok" {
    var s = try parse(testing.allocator, "nodes 4\nedge 0 1\nedge 1 2\nedge 2 3\n");
    defer s.deinit();
    var fab = try s.build(testing.allocator, .{}, 1);
    defer fab.deinit();
    fab.broken_no_drain = true;
    const outcome = try fab.runToConvergence(s.horizon());
    try testing.expect((try s.verify(testing.allocator, &fab, outcome)) != .ok);
}

test "random fabrics up to 24 nodes with up to 3 non-partitioning failures all converge and route" {
    var prng = std.Random.DefaultPrng.init(0x15_15_51);
    var seed: u64 = 0;
    while (seed < 24) : (seed += 1) {
        var s = try random(testing.allocator, prng.random(), .{ .max_nodes = 24 });
        defer s.deinit();
        var r = try s.run(testing.allocator, .{}, seed);
        defer r.fab.deinit();
        const v = try s.verify(testing.allocator, &r.fab, r.outcome);
        if (v != .ok) return error.RandomFabricFailed;
    }
}

test "random fabrics are deterministic in the generator state" {
    var p1 = std.Random.DefaultPrng.init(99);
    var p2 = std.Random.DefaultPrng.init(99);
    var a = try random(testing.allocator, p1.random(), .{});
    defer a.deinit();
    var b = try random(testing.allocator, p2.random(), .{});
    defer b.deinit();
    try testing.expectEqual(a.node_count, b.node_count);
    try testing.expectEqual(a.edges.len, b.edges.len);
    for (a.edges, b.edges) |x, y| try testing.expectEqual(x, y);
    try testing.expectEqual(a.failures.len, b.failures.len);
}

const BrokenCtx = struct { gpa: Allocator };

fn brokenStillFails(ctx: BrokenCtx, s: *const Spec) anyerror!bool {
    var fab = try s.build(ctx.gpa, .{}, 5);
    defer fab.deinit();
    fab.broken_no_drain = true;
    const outcome = try fab.runToConvergence(s.horizon());
    return (try s.verify(ctx.gpa, &fab, outcome)) != .ok;
}

test "minimize: a failure that does not depend on the schedule shrinks to no scheduled failures" {
    var s = try parse(testing.allocator,
        \\nodes 5
        \\edge 0 1
        \\edge 1 2
        \\edge 2 3
        \\edge 3 4
        \\edge 4 0
        \\edge 0 2
        \\fail 1000 0 1
        \\fail 1500 3 4
    );
    defer s.deinit();
    const left = try minimize(&s, BrokenCtx{ .gpa = testing.allocator }, brokenStillFails);
    try testing.expectEqual(@as(usize, 0), left);
}

test "minimize: a failure that needs a scheduled link failure keeps exactly it" {
    // A line 0-1-2-3 cut at 1-2 is only a failure for the check below.
    var s = try parse(testing.allocator,
        \\nodes 4
        \\edge 0 1
        \\edge 1 2
        \\edge 2 3
        \\edge 0 3
        \\fail 1000 0 1
        \\fail 1200 2 3
    );
    defer s.deinit();
    const Needs = struct {
        fn f(_: void, sp: *const Spec) anyerror!bool {
            // "fails" while the schedule still severs 2-3.
            for (sp.failures) |x| if (x.a == 2 and x.b == 3) return true;
            return false;
        }
    };
    const left = try minimize(&s, {}, Needs.f);
    try testing.expectEqual(@as(usize, 1), left);
    try testing.expectEqual(@as(NodeId, 2), s.failures[0].a);
}
