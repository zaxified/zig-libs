// SPDX-License-Identifier: MIT
//! isis-spf — the IS-IS decision process (ISO/IEC 10589 §7.2): turn the
//! synchronised link-state database (`isis-lsdb`) into a forwarding table.
//!
//! The pipeline, pure and deterministic:
//!   1. **Topology extraction.** Walk every LSP currently in the LSDB; for each,
//!      take its originating system-id (the LSP-ID's first six octets) and its
//!      IS-reachability TLVs (#22 Extended IS Reachability, RFC 5305; and the
//!      old-style #2 IS Neighbours, ISO 10589 §9.8) into `(neighbour, metric)`
//!      directed advertisements.
//!   2. **Two-way reachability (ISO §7.2.5).** An edge A–B is used only when A
//!      advertises B *and* B advertises A. A one-way advertisement (a
//!      half-formed adjacency, or a neighbour that just left) is dropped — this
//!      is the classic SPF stability rule, and it is what keeps a stale
//!      one-directional LSP from poisoning the tree.
//!   3. **SPF.** Intern each system-id to a dense `spf-ect` `NodeId`, build the
//!      `spf-ect.Graph`, and run `shortestPathTree` from the local system.
//!      `spf-ect` owns Dijkstra *and* the ECT (802.1aq / RFC 6329) tie-break, so
//!      equal-cost path selection is symmetric and loop-free by construction;
//!      this module only consumes the resolved tree.
//!   4. **Route table.** For every reachable destination system-id, resolve the
//!      first hop after the root (walking the tree's predecessor chain) and the
//!      total metric, emitting `dest → { next_hop, metric }`, sorted by dest.
//!
//! Scope: **point-to-point topology → SPF → next-hop table**. LAN pseudonodes,
//! multi-level (L1/L2) leaking, IP/prefix reachability leaves, the overload
//! bit's transit exclusion, and incremental SPF are deferred — see `SPEC.md`.

const std = @import("std");
const isis = @import("isis");
const lsdb = @import("isis-lsdb");
const spf = @import("spf-ect");

const Allocator = std.mem.Allocator;

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "ISO/IEC 10589 §7.2 decision process (SPF) + IEEE 802.1aq ECT",
    .deps = .{ "isis", "isis-lsdb", "spf-ect" },
};

/// A 6-octet IS-IS system-id — the node identity in the topology (the LSP-ID's
/// first six octets, and each 7-octet neighbour-id's first six).
pub const SystemId = [6]u8;

/// The caller's time unit, forwarded to `isis-lsdb` so lifetimes age to `now`.
pub const Time = lsdb.Time;

/// One resolved forwarding entry. `next_hop == dest` for a directly-adjacent
/// destination; `next_hop == dest == local` (metric 0) for the local "self"
/// route.
pub const Route = struct {
    dest: SystemId,
    next_hop: SystemId,
    /// Total path cost from the local system (a sum of `spf-ect` edge weights).
    metric: u64,
};

/// Tuning for `computeWith`. The default is the correct ISO §7.2.5 behaviour;
/// the non-default exists only for the permanent positive control.
pub const Options = struct {
    /// The ISO §7.2.5 two-way reachability check. When `true` (default,
    /// correct) an undirected edge A–B is admitted to SPF only if BOTH A
    /// advertises B and B advertises A. When `false` a *single* directed
    /// advertisement is enough — deliberately WRONG (a one-way/stale
    /// advertisement poisons the tree); kept solely to prove, in a permanent
    /// test, that the two-way check is load-bearing.
    require_two_way: bool = true,
};

/// The computed forwarding table — routes sorted ascending by destination
/// system-id. Caller-owned; free with `deinit`.
pub const RouteTable = struct {
    gpa: Allocator,
    routes: []Route,

    pub fn deinit(self: *RouteTable) void {
        self.gpa.free(self.routes);
        self.* = undefined;
    }

    /// The route to `dest`, or `null` if `dest` is not reachable. O(log n) —
    /// `routes` is sorted by `dest`.
    pub fn lookup(self: *const RouteTable, dest: SystemId) ?Route {
        var lo: usize = 0;
        var hi: usize = self.routes.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            switch (std.mem.order(u8, &self.routes[mid].dest, &dest)) {
                .eq => return self.routes[mid],
                .lt => lo = mid + 1,
                .gt => hi = mid,
            }
        }
        return null;
    }

    /// The next-hop system-id toward `dest`, or `null` if unreachable.
    pub fn nextHop(self: *const RouteTable, dest: SystemId) ?SystemId {
        return if (self.lookup(dest)) |r| r.next_hop else null;
    }
};

/// Compute the forwarding table from `db` as seen at `now`, rooted at the
/// `local` system-id, with the correct ISO §7.2.5 two-way check. See
/// `computeWith` for the details and the degenerate cases.
pub fn compute(gpa: Allocator, db: *const lsdb.Lsdb, local: SystemId, now: Time) Allocator.Error!RouteTable {
    return computeWith(gpa, db, local, now, .{});
}

/// `compute` with explicit `Options`.
///
/// Degenerate cases (all documented, none panic):
///   - **Empty LSDB / local has no LSP** — the local system is not in the graph,
///     so an empty table is returned (no self route).
///   - **Local present but isolated** — a table with only the self route
///     (`{ local, local, 0 }`).
///   - **Dangling neighbour** (advertised but with no LSP of its own) — never
///     advertises back, so with the two-way check it contributes no edge and is
///     simply unreachable; never a crash.
///   - **Malformed reachability TLV** — the bounds-checked `isis` parse stops at
///     the bad record; the rest of that LSP up to it is used and every other LSP
///     is unaffected.
pub fn computeWith(
    gpa: Allocator,
    db: *const lsdb.Lsdb,
    local: SystemId,
    now: Time,
    opts: Options,
) Allocator.Error!RouteTable {
    // ── 1. extract directed advertisements + the set of LSP origins ──────────
    // directed: (from ++ to) → best (minimum) advertised metric, from ⟶ to.
    var directed: std.AutoHashMapUnmanaged([12]u8, spf.Weight) = .empty;
    defer directed.deinit(gpa);
    // origins: every system-id that originated at least one (non-pseudonode) LSP.
    var origins: std.AutoHashMapUnmanaged(SystemId, void) = .empty;
    defer origins.deinit(gpa);

    var view_it = db.iterator(now);
    while (view_it.next()) |ev| {
        // Request placeholders carry no bytes; skip them.
        if (ev.is_request or ev.bytes.len == 0) continue;
        // A stored LSP is well-formed at the header/framing level, but decode
        // defensively anyway — a decode failure just skips this LSP.
        const lsp = isis.Lsp.decode(ev.bytes) catch continue;
        // This increment models P2P only: skip pseudonode LSPs (LSP-ID octet 6).
        if (lsp.lsp_id[6] != 0) continue;
        const from: SystemId = lsp.lsp_id[0..6].*;
        try origins.put(gpa, from, {});

        var tlv_it = lsp.tlvIterator();
        // A malformed TLV terminates this LSP's walk safely (no over-read); the
        // records parsed before it still count.
        while (tlv_it.next() catch break) |t| switch (t.code) {
            isis.tlvs.code.extended_is_reachability => {
                var eit = isis.tlvs.ExtIsReachIterator.init(t.value);
                while (eit.next() catch break) |e| {
                    if (e.neighbour_id[6] != 0) continue; // pseudonode neighbour
                    try addDirected(gpa, &directed, from, e.neighbour_id[0..6].*, e.metric);
                }
            },
            isis.tlvs.code.is_neighbours_lsp => {
                var iit = isis.tlvs.IsReachIterator.init(t.value) catch continue;
                while (iit.next() catch break) |e| {
                    if (e.neighbour_id[6] != 0) continue; // pseudonode neighbour
                    // Old-style default metric: the value is the low 6 bits; the
                    // high bits are I/E / supported flags.
                    try addDirected(gpa, &directed, from, e.neighbour_id[0..6].*, e.default_metric & 0x3f);
                }
            },
            else => {},
        };
    }

    // ── 2. two-way reachability → unordered edges ────────────────────────────
    // pairs: canonical (lo ++ hi), lo < hi → the undirected edge weight.
    var pairs: std.AutoHashMapUnmanaged([12]u8, spf.Weight) = .empty;
    defer pairs.deinit(gpa);

    var dit = directed.iterator();
    while (dit.next()) |kv| {
        const a: SystemId = kv.key_ptr[0..6].*;
        const b: SystemId = kv.key_ptr[6..12].*;
        // Canonicalise so each unordered pair is considered once.
        const lo_first = std.mem.order(u8, &a, &b) == .lt;
        const lo = if (lo_first) a else b;
        const hi = if (lo_first) b else a;
        var canon: [12]u8 = undefined;
        canon[0..6].* = lo;
        canon[6..12].* = hi;
        if (pairs.contains(canon)) continue;

        const lo_hi = directed.get(canon); // lo ⟶ hi advertisement, if any
        var rev: [12]u8 = undefined;
        rev[0..6].* = hi;
        rev[6..12].* = lo;
        const hi_lo = directed.get(rev); // hi ⟶ lo advertisement, if any

        if (opts.require_two_way and !(lo_hi != null and hi_lo != null)) continue;

        // Undirected engine: one weight per edge. Use the lo⟶hi advertisement
        // (the endpoint with the lexicographically-smaller system-id) as the
        // canonical weight so the choice is deterministic and independent of
        // LSDB iteration order; SPB requires symmetric metrics, in which case
        // this is exact. When only hi⟶lo exists (positive-control mode) fall
        // back to it.
        const weight = lo_hi orelse hi_lo.?;
        try pairs.put(gpa, canon, weight);
    }

    // ── 3. intern system-ids → dense NodeIds (sorted, deterministic) ─────────
    // Node set = every edge endpoint, plus `local` if it originated an LSP (so
    // an isolated local system still yields a self route). Sorting the ids and
    // assigning NodeIds in ascending order makes the mapping independent of
    // hash-map iteration order AND aligns the ECT "low path id" tie-break with
    // the canonical lowest-system-id rule.
    var id_set: std.AutoArrayHashMapUnmanaged(SystemId, void) = .empty;
    defer id_set.deinit(gpa);
    {
        var pit = pairs.iterator();
        while (pit.next()) |kv| {
            try id_set.put(gpa, kv.key_ptr[0..6].*, {});
            try id_set.put(gpa, kv.key_ptr[6..12].*, {});
        }
        if (origins.contains(local)) try id_set.put(gpa, local, {});
    }

    // Local not in the graph → degenerate empty table (documented).
    if (!id_set.contains(local)) {
        return .{ .gpa = gpa, .routes = try gpa.alloc(Route, 0) };
    }

    const node_count: u32 = @intCast(id_set.count());
    const node_to_id = try gpa.alloc(SystemId, node_count);
    defer gpa.free(node_to_id);
    for (id_set.keys(), 0..) |k, i| node_to_id[i] = k;
    std.mem.sort(SystemId, node_to_id, {}, lessSystemId);

    var id_to_node: std.AutoHashMapUnmanaged(SystemId, spf.NodeId) = .empty;
    defer id_to_node.deinit(gpa);
    for (node_to_id, 0..) |id, i| try id_to_node.put(gpa, id, @intCast(i));

    // ── 4. build the graph + run SPF ─────────────────────────────────────────
    var graph = spf.Graph.init(gpa);
    defer graph.deinit();
    try graph.ensureNode(node_count - 1);

    var pit = pairs.iterator();
    while (pit.next()) |kv| {
        const na = id_to_node.get(kv.key_ptr[0..6].*).?;
        const nb = id_to_node.get(kv.key_ptr[6..12].*).?;
        graph.addEdge(na, nb, kv.value_ptr.*) catch |err| switch (err) {
            // Pairs are deduped and lo != hi, so these never fire; a positive
            // weight is guaranteed by `addDirected`'s clamp. Swallow the
            // structural ones, propagate OOM.
            error.DuplicateEdge, error.SelfLoop, error.ZeroWeight => {},
            error.OutOfMemory => return error.OutOfMemory,
        };
    }

    const local_node = id_to_node.get(local).?;
    var tree = try spf.shortestPathTree(gpa, &graph, local_node);
    defer tree.deinit();

    // ── 5. route table: first-hop + total metric per reachable destination ───
    // Node ids are in ascending system-id order, so iterating them yields
    // routes already sorted by destination.
    var routes: std.ArrayList(Route) = .empty;
    errdefer routes.deinit(gpa);
    var node: spf.NodeId = 0;
    while (node < node_count) : (node += 1) {
        if (!tree.reachable(node)) continue;
        const next_node = if (node == local_node) local_node else firstHop(&tree, local_node, node);
        try routes.append(gpa, .{
            .dest = node_to_id[node],
            .next_hop = node_to_id[next_node],
            .metric = tree.distanceTo(node),
        });
    }

    return .{ .gpa = gpa, .routes = try routes.toOwnedSlice(gpa) };
}

/// Record a directed advertisement `from ⟶ to`, keeping the minimum metric if
/// the same ordered pair is advertised more than once (e.g. via both #2 and #22,
/// or across LSP fragments). A self-advertisement (`from == to`) is ignored.
/// The metric is clamped to `>= 1`: `spf-ect` rejects a zero weight (it could
/// otherwise form a predecessor cycle), and a genuinely 0-cost IS-IS link is
/// treated as cost 1.
fn addDirected(
    gpa: Allocator,
    directed: *std.AutoHashMapUnmanaged([12]u8, spf.Weight),
    from: SystemId,
    to: SystemId,
    raw_metric: anytype,
) Allocator.Error!void {
    if (std.mem.eql(u8, &from, &to)) return;
    const weight: spf.Weight = @max(@as(spf.Weight, 1), @as(spf.Weight, raw_metric));
    var key: [12]u8 = undefined;
    key[0..6].* = from;
    key[6..12].* = to;
    const gop = try directed.getOrPut(gpa, key);
    if (!gop.found_existing or weight < gop.value_ptr.*) gop.value_ptr.* = weight;
}

/// The first hop after `root` on the tree path to `dest` (`dest` reachable and
/// `!= root`): walk the predecessor chain until the node whose predecessor is
/// the root. Allocation-free — no `pathTo` slice is built.
fn firstHop(tree: *const spf.Tree, root: spf.NodeId, dest: spf.NodeId) spf.NodeId {
    var cur = dest;
    while (true) {
        const p = tree.pred[cur].?;
        if (p == root) return cur;
        cur = p;
    }
}

fn lessSystemId(_: void, a: SystemId, b: SystemId) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

// ─────────────────────────────────────────────────────────────────────────────
// tests
// ─────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn sysId(last: u8) SystemId {
    return .{ 0, 0, 0, 0, 0, last };
}

/// Insert one LSP for `origin` that advertises Extended IS Reachability (#22) to
/// each `(neighbour, metric)` in `reach`. One LSP per call keeps the fixtures
/// legible (real LSPs may fragment; extraction keys by system-id regardless).
fn insertReachLsp(
    db: *lsdb.Lsdb,
    origin: SystemId,
    seq: u32,
    reach: []const struct { nbr: SystemId, metric: u24 },
) !void {
    var buf: [512]u8 = undefined;
    var b = try isis.pdu.LspBuilder.init(&buf, .{
        .remaining_lifetime = 1000,
        .lsp_id = .{ origin[0], origin[1], origin[2], origin[3], origin[4], origin[5], 0, 0 },
        .sequence_number = seq,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    });
    for (reach) |r| {
        const nbr7: [7]u8 = .{ r.nbr[0], r.nbr[1], r.nbr[2], r.nbr[3], r.nbr[4], r.nbr[5], 0 };
        try isis.tlvs.addExtendedIsReach(&b.tlvs, nbr7, r.metric, &.{});
    }
    _ = try db.insert(b.finish(), null, 0);
}

fn cfgFor(local: SystemId) lsdb.Config {
    return .{ .local_system_id = local, .interface_count = 2, .capacity = 64 };
}

test "golden line topology A-B-C: exact routes, next-hops, metrics" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    const c = sysId(0xC);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();

    // A—B (10), B—C (10), each advertised both ways (two-way).
    try insertReachLsp(&db, a, 1, &.{.{ .nbr = b, .metric = 10 }});
    try insertReachLsp(&db, b, 1, &.{ .{ .nbr = a, .metric = 10 }, .{ .nbr = c, .metric = 10 } });
    try insertReachLsp(&db, c, 1, &.{.{ .nbr = b, .metric = 10 }});

    var table = try compute(testing.allocator, &db, a, 0);
    defer table.deinit();

    try testing.expectEqual(@as(usize, 3), table.routes.len);
    // self
    try testing.expectEqual(Route{ .dest = a, .next_hop = a, .metric = 0 }, table.lookup(a).?);
    // direct neighbour B: next-hop is B, metric 10
    try testing.expectEqual(Route{ .dest = b, .next_hop = b, .metric = 10 }, table.lookup(b).?);
    // two hops to C via B: next-hop is B (NOT C), metric 20
    try testing.expectEqual(Route{ .dest = c, .next_hop = b, .metric = 20 }, table.lookup(c).?);
}

test "next-hop over a 4-node path A-B-C-D: first hop to D is B" {
    const a = sysId(1);
    const b = sysId(2);
    const c = sysId(3);
    const d = sysId(4);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();

    try insertReachLsp(&db, a, 1, &.{.{ .nbr = b, .metric = 5 }});
    try insertReachLsp(&db, b, 1, &.{ .{ .nbr = a, .metric = 5 }, .{ .nbr = c, .metric = 5 } });
    try insertReachLsp(&db, c, 1, &.{ .{ .nbr = b, .metric = 5 }, .{ .nbr = d, .metric = 5 } });
    try insertReachLsp(&db, d, 1, &.{.{ .nbr = c, .metric = 5 }});

    var table = try compute(testing.allocator, &db, a, 0);
    defer table.deinit();

    try testing.expectEqual(sysId(2), table.nextHop(sysId(4)).?); // to D via B
    try testing.expectEqual(@as(u64, 15), table.lookup(sysId(4)).?.metric);
    try testing.expectEqual(sysId(2), table.nextHop(sysId(3)).?); // to C via B
}

test "diamond A-{B,C}-D: equal-cost ECT pick is deterministic and stable" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    const c = sysId(0xC);
    const d = sysId(0xD);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();

    // Two equal-cost paths A→B→D and A→C→D (all weights 10).
    try insertReachLsp(&db, a, 1, &.{ .{ .nbr = b, .metric = 10 }, .{ .nbr = c, .metric = 10 } });
    try insertReachLsp(&db, b, 1, &.{ .{ .nbr = a, .metric = 10 }, .{ .nbr = d, .metric = 10 } });
    try insertReachLsp(&db, c, 1, &.{ .{ .nbr = a, .metric = 10 }, .{ .nbr = d, .metric = 10 } });
    try insertReachLsp(&db, d, 1, &.{ .{ .nbr = b, .metric = 10 }, .{ .nbr = c, .metric = 10 } });

    var t1 = try compute(testing.allocator, &db, a, 0);
    defer t1.deinit();
    // D is cost 20 via either B or C; ECT resolves to exactly one, and it is one
    // of the two legitimate first hops.
    const nh = t1.nextHop(d).?;
    try testing.expect(std.mem.eql(u8, &nh, &b) or std.mem.eql(u8, &nh, &c));
    try testing.expectEqual(@as(u64, 20), t1.lookup(d).?.metric);

    // Stable across independent recomputations (byte-for-byte).
    var t2 = try compute(testing.allocator, &db, a, 0);
    defer t2.deinit();
    try testing.expectEqualSlices(Route, t1.routes, t2.routes);
}

test "two-way check: a one-way advertisement yields no edge; adding the reverse creates it" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();

    // A advertises B, but B advertises nothing back (B still has an LSP).
    try insertReachLsp(&db, a, 1, &.{.{ .nbr = b, .metric = 10 }});
    try insertReachLsp(&db, b, 1, &.{});

    {
        var table = try compute(testing.allocator, &db, a, 0);
        defer table.deinit();
        // Only the self route: the A→B edge is one-way, so B is unreachable.
        try testing.expectEqual(@as(usize, 1), table.routes.len);
        try testing.expect(table.lookup(b) == null);
    }

    // Now B advertises A back → the edge forms.
    try insertReachLsp(&db, b, 2, &.{.{ .nbr = a, .metric = 10 }});
    {
        var table = try compute(testing.allocator, &db, a, 0);
        defer table.deinit();
        try testing.expectEqual(@as(usize, 2), table.routes.len);
        try testing.expectEqual(Route{ .dest = b, .next_hop = b, .metric = 10 }, table.lookup(b).?);
    }
}

test "positive control: disabling the two-way check DOES use the one-way edge" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();

    // Exactly the one-way scenario above.
    try insertReachLsp(&db, a, 1, &.{.{ .nbr = b, .metric = 10 }});
    try insertReachLsp(&db, b, 1, &.{});

    // Correct behaviour: B unreachable.
    {
        var table = try computeWith(testing.allocator, &db, a, 0, .{ .require_two_way = true });
        defer table.deinit();
        try testing.expect(table.lookup(b) == null);
    }
    // Deliberately-broken control: the one-way edge is admitted, so B routes —
    // proving the two-way check is exactly what excludes it above.
    {
        var table = try computeWith(testing.allocator, &db, a, 0, .{ .require_two_way = false });
        defer table.deinit();
        try testing.expectEqual(Route{ .dest = b, .next_hop = b, .metric = 10 }, table.lookup(b).?);
    }
}

test "reconvergence: removing a link reroutes the table" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    const c = sysId(0xC);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();

    // Triangle with a cheap direct A—C and a two-hop A—B—C.
    //   A—B: 10, B—C: 10, A—C: 5  → C is direct (metric 5).
    try insertReachLsp(&db, a, 1, &.{ .{ .nbr = b, .metric = 10 }, .{ .nbr = c, .metric = 5 } });
    try insertReachLsp(&db, b, 1, &.{ .{ .nbr = a, .metric = 10 }, .{ .nbr = c, .metric = 10 } });
    try insertReachLsp(&db, c, 1, &.{ .{ .nbr = a, .metric = 5 }, .{ .nbr = b, .metric = 10 } });

    {
        var table = try compute(testing.allocator, &db, a, 0);
        defer table.deinit();
        try testing.expectEqual(Route{ .dest = c, .next_hop = c, .metric = 5 }, table.lookup(c).?);
    }

    // The A—C link fails: A re-originates without C, C re-originates without A.
    // Now the only path to C is via B (metric 20).
    try insertReachLsp(&db, a, 2, &.{.{ .nbr = b, .metric = 10 }});
    try insertReachLsp(&db, c, 2, &.{.{ .nbr = b, .metric = 10 }});
    {
        var table = try compute(testing.allocator, &db, a, 0);
        defer table.deinit();
        try testing.expectEqual(Route{ .dest = c, .next_hop = b, .metric = 20 }, table.lookup(c).?);
    }
}

test "old-style #2 IS reachability is extracted too" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();

    // Hand-build LSPs whose reachability is the old-style #2 TLV.
    inline for (.{ .{ a, b }, .{ b, a } }) |pair| {
        var buf: [128]u8 = undefined;
        var lb = try isis.pdu.LspBuilder.init(&buf, .{
            .remaining_lifetime = 1000,
            .lsp_id = .{ pair[0][0], pair[0][1], pair[0][2], pair[0][3], pair[0][4], pair[0][5], 0, 0 },
            .sequence_number = 1,
            .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
        });
        // #2 value: virtual flag (0) + one 11-octet entry: 4 metrics + 7-octet
        // neighbour-id. Default metric 7 (low 6 bits); neighbour = pair[1].
        const nbr = pair[1];
        const val = [_]u8{0} // virtual flag
            ++ [_]u8{ 7, 0x80, 0x80, 0x80 } // default 7, others "not supported"
            ++ [_]u8{ nbr[0], nbr[1], nbr[2], nbr[3], nbr[4], nbr[5], 0 };
        try lb.tlvs.addTlv(isis.tlvs.code.is_neighbours_lsp, &val);
        _ = try db.insert(lb.finish(), null, 0);
    }

    var table = try compute(testing.allocator, &db, a, 0);
    defer table.deinit();
    try testing.expectEqual(Route{ .dest = b, .next_hop = b, .metric = 7 }, table.lookup(b).?);
}

test "robustness: a malformed reachability TLV is skipped; the valid rest still routes" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    const x = sysId(0xF);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();

    // A—B is a clean two-way edge.
    try insertReachLsp(&db, a, 1, &.{.{ .nbr = b, .metric = 10 }});
    try insertReachLsp(&db, b, 1, &.{.{ .nbr = a, .metric = 10 }});

    // X's LSP carries a #22 TLV whose sub-TLV length lies past the value — the
    // bounds-checked ExtIsReachIterator trips on it. X must not appear, and A—B
    // must still route, no panic.
    {
        var buf: [128]u8 = undefined;
        var lb = try isis.pdu.LspBuilder.init(&buf, .{
            .remaining_lifetime = 1000,
            .lsp_id = .{ x[0], x[1], x[2], x[3], x[4], x[5], 0, 0 },
            .sequence_number = 1,
            .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
        });
        // neighbour(7) + metric(3) + sub_len=200, but zero sub bytes present.
        const bad = [_]u8{ 0, 0, 0, 0, 0, 0xB, 0 } ++ [_]u8{ 0, 0, 5 } ++ [_]u8{200};
        try lb.tlvs.addTlv(isis.tlvs.code.extended_is_reachability, &bad);
        _ = try db.insert(lb.finish(), null, 0);
    }

    var table = try compute(testing.allocator, &db, a, 0);
    defer table.deinit();
    try testing.expectEqual(Route{ .dest = b, .next_hop = b, .metric = 10 }, table.lookup(b).?);
    try testing.expect(table.lookup(x) == null);
}

test "dangling neighbour (advertised, no LSP of its own) is unreachable, not a crash" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    const ghost = sysId(0x9);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();

    // A—B two-way, and B also advertises a ghost that has no LSP (one-way).
    try insertReachLsp(&db, a, 1, &.{.{ .nbr = b, .metric = 10 }});
    try insertReachLsp(&db, b, 1, &.{ .{ .nbr = a, .metric = 10 }, .{ .nbr = ghost, .metric = 10 } });

    var table = try compute(testing.allocator, &db, a, 0);
    defer table.deinit();
    try testing.expectEqual(@as(usize, 2), table.routes.len); // A, B only
    try testing.expect(table.lookup(ghost) == null);
}

test "empty LSDB → empty table; local absent → empty table" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    const c = sysId(0xC);

    // Empty database.
    {
        var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
        defer db.deinit();
        var table = try compute(testing.allocator, &db, a, 0);
        defer table.deinit();
        try testing.expectEqual(@as(usize, 0), table.routes.len);
    }
    // A populated database, but the local system-id has no LSP of its own.
    {
        var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
        defer db.deinit();
        try insertReachLsp(&db, b, 1, &.{.{ .nbr = c, .metric = 10 }});
        try insertReachLsp(&db, c, 1, &.{.{ .nbr = b, .metric = 10 }});
        var table = try compute(testing.allocator, &db, a, 0);
        defer table.deinit();
        try testing.expectEqual(@as(usize, 0), table.routes.len);
    }
}

test "local present but isolated → only the self route" {
    const a = sysId(0xA);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();
    try insertReachLsp(&db, a, 1, &.{}); // A has an LSP but advertises nobody

    var table = try compute(testing.allocator, &db, a, 0);
    defer table.deinit();
    try testing.expectEqual(@as(usize, 1), table.routes.len);
    try testing.expectEqual(Route{ .dest = a, .next_hop = a, .metric = 0 }, table.routes[0]);
}

test "determinism: identical databases yield byte-identical tables" {
    const ids = [_]SystemId{ sysId(1), sysId(2), sysId(3), sysId(4), sysId(5) };
    const Build = struct {
        fn run(gpa: Allocator, local: SystemId) !RouteTable {
            var db = lsdb.Lsdb.init(gpa, .{ .local_system_id = local, .interface_count = 2, .capacity = 64 });
            defer db.deinit();
            // A small mesh (all weights 10).
            try insertReachLsp(&db, sysId(1), 1, &.{ .{ .nbr = sysId(2), .metric = 10 }, .{ .nbr = sysId(3), .metric = 10 } });
            try insertReachLsp(&db, sysId(2), 1, &.{ .{ .nbr = sysId(1), .metric = 10 }, .{ .nbr = sysId(4), .metric = 10 } });
            try insertReachLsp(&db, sysId(3), 1, &.{ .{ .nbr = sysId(1), .metric = 10 }, .{ .nbr = sysId(4), .metric = 10 } });
            try insertReachLsp(&db, sysId(4), 1, &.{ .{ .nbr = sysId(2), .metric = 10 }, .{ .nbr = sysId(3), .metric = 10 }, .{ .nbr = sysId(5), .metric = 10 } });
            try insertReachLsp(&db, sysId(5), 1, &.{.{ .nbr = sysId(4), .metric = 10 }});
            return compute(gpa, &db, local, 0);
        }
    };
    for (ids) |local| {
        var t1 = try Build.run(testing.allocator, local);
        defer t1.deinit();
        var t2 = try Build.run(testing.allocator, local);
        defer t2.deinit();
        try testing.expectEqualSlices(Route, t1.routes, t2.routes);
        // Every route is sorted by destination.
        for (t1.routes[0..t1.routes.len -| 1], t1.routes[1..]) |x, y| {
            try testing.expect(std.mem.order(u8, &x.dest, &y.dest) == .lt);
        }
    }
}

test "asymmetric metrics: the lower-system-id endpoint's advertisement wins" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();

    // A (lower id) advertises B with 7; B advertises A with 99. The canonical
    // undirected weight is A's (7).
    try insertReachLsp(&db, a, 1, &.{.{ .nbr = b, .metric = 7 }});
    try insertReachLsp(&db, b, 1, &.{.{ .nbr = a, .metric = 99 }});

    var table = try compute(testing.allocator, &db, a, 0);
    defer table.deinit();
    try testing.expectEqual(@as(u64, 7), table.lookup(b).?.metric);
}

test "addDirected: the same ordered pair advertised twice keeps the minimum metric" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();

    // A's LSP advertises B twice (e.g. duplicate/fragmented entries): 20 then 5.
    // The directed a->b advertisement must keep the minimum (5), not the last
    // or the first value seen.
    try insertReachLsp(&db, a, 1, &.{ .{ .nbr = b, .metric = 20 }, .{ .nbr = b, .metric = 5 } });
    try insertReachLsp(&db, b, 1, &.{.{ .nbr = a, .metric = 5 }});

    var table = try compute(testing.allocator, &db, a, 0);
    defer table.deinit();
    try testing.expectEqual(@as(u64, 5), table.lookup(b).?.metric);
}

test "two-way check with require_two_way=false: only the hi->lo advertisement exists (hi_lo fallback)" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();

    // Only B (the lexicographically-larger id) advertises A; A advertises
    // nothing. This exercises the `hi_lo` fallback in the undirected-weight
    // selection (the `lo_hi` advertisement is absent).
    try insertReachLsp(&db, a, 1, &.{});
    try insertReachLsp(&db, b, 1, &.{.{ .nbr = a, .metric = 15 }});

    var table = try computeWith(testing.allocator, &db, a, 0, .{ .require_two_way = false });
    defer table.deinit();
    try testing.expectEqual(Route{ .dest = b, .next_hop = b, .metric = 15 }, table.lookup(b).?);
}

test "meta is well-formed" {
    try testing.expectEqual(.any, meta.platform);
    try testing.expectEqual(.util, meta.role);
    try testing.expectEqual(.single_owner, meta.concurrency);
}
