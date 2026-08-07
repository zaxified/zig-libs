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
//!   2. **Two-way connectivity check (ISO §7.2.8.2: "The Decision Process shall
//!      not utilise a link between two Intermediate Systems unless both ISs
//!      report the link").** A link A–B is used only when A advertises B *and*
//!      B advertises A. A one-way advertisement (a half-formed adjacency, or a
//!      neighbour that just left) is dropped — this is the classic SPF
//!      stability rule, and it is what keeps a stale one-directional LSP from
//!      poisoning the tree. The check admits the link; it does **not** merge
//!      the two metrics — the same clause says "It is permissible for two
//!      endpoints to report different defined values of the same metric for the
//!      same link. In this case, routes may be asymmetric."
//!   3. **SPF.** Intern each system-id to a dense `spf-ect` `NodeId`, add one
//!      *directed arc* per admitted direction at that direction's own
//!      advertised metric (ISO Annex C.2.4 Step 1: `dist(P,N) = d(P) +
//!      metric_k(P,N)`, where "metric_k(P,N) is the cost of the link from P to
//!      N as reported in P's Link State PDU"), and run `shortestPathTree` from
//!      the local system.
//!      `spf-ect` owns Dijkstra *and* the ECT (802.1aq / RFC 6329) tie-break, so
//!      equal-cost path selection is loop-free by construction — and, on a
//!      symmetric-metric fabric (which 802.1aq requires), congruent in both
//!      directions; this module only consumes the resolved tree.
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

/// Tuning for `computeWith`. The defaults are the correct/safe behaviour;
/// `require_two_way = false` exists only for the permanent positive control.
pub const Options = struct {
    /// The ISO §7.2.8.2 two-way connectivity check. When `true` (default,
    /// correct) the link A–B is admitted to SPF only if BOTH A advertises B
    /// and B advertises A; each direction then relaxes at its own advertised
    /// metric. When `false` a *single* directed advertisement is enough, and
    /// the missing direction is mirrored from the one that exists —
    /// deliberately WRONG (a one-way/stale advertisement poisons the tree);
    /// kept solely to prove, in a permanent test, that the two-way check is
    /// load-bearing.
    require_two_way: bool = true,

    /// Refuse a database that carries an asymmetric link at all — an
    /// **opt-in fabric-hygiene check, not a correctness guard**.
    ///
    /// IS-IS metrics are per-interface and therefore directional, and ISO
    /// 10589 §7.2.8.2 explicitly permits the two endpoints to report
    /// different values for the same link ("routes may be asymmetric"). Since
    /// `55752d4`'s successor this module honours that: each direction becomes
    /// its own `spf-ect` arc at its own advertised metric, so an asymmetric
    /// database now produces the *right* table (the FRR anchor at the bottom
    /// of this file is the measured proof: FRR 10.3 reaches r3 at cost 15 via
    /// r5, and so do we). This flag therefore no longer defends against a
    /// wrong answer, and its default is `false`.
    ///
    /// What it is still good for: an 802.1aq/SPB fabric REQUIRES symmetric
    /// metrics, because congruent forward/reverse paths are what make its
    /// reverse-path check and its ECT tie-break meaningful. Such a caller can
    /// set this and get `error.AsymmetricMetric` on a misconfigured fabric
    /// rather than a correct-but-asymmetric table it cannot use. Either way
    /// `RouteTable.asymmetric_links` reports the count.
    reject_asymmetric: bool = false,
};

/// `computeWith` fails for two reasons only.
pub const Error = Allocator.Error || error{
    /// A link was advertised in both directions with **different** metrics,
    /// and `Options.reject_asymmetric` was set. The engine represents this
    /// fine; the caller asked to be told instead. See that option.
    AsymmetricMetric,
};

/// The computed forwarding table — routes sorted ascending by destination
/// system-id. Caller-owned; free with `deinit`.
pub const RouteTable = struct {
    gpa: Allocator,
    routes: []Route,
    /// How many admitted links were advertised in both directions with
    /// **different** metrics. Informational: the routes are computed with
    /// each direction's own metric (ISO Annex C.2.4 Step 1), so a non-zero
    /// count does **not** make the table approximate — it used to, when the
    /// engine was undirected and had to pick one of the two metrics.
    ///
    /// It is still worth reporting, because a fabric that requires symmetric
    /// metrics (802.1aq/SPB, whose forward/reverse congruency this stack
    /// relies on) is misconfigured if this is non-zero — see
    /// `Options.reject_asymmetric`.
    asymmetric_links: u32 = 0,

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
/// `local` system-id, with the correct ISO §7.2.8.2 two-way connectivity
/// check. See `computeWith` for the details and the degenerate cases.
///
/// This entry point cannot fail on anything but OOM (its error set is part of
/// a signature other modules compile against) and does not need to: an
/// asymmetric link is *computed*, not approximated — each direction relaxes at
/// its own advertised metric. `RouteTable.asymmetric_links` still reports how
/// many such links there were, for callers (802.1aq fabrics) that require
/// symmetry for reasons of their own.
pub fn compute(gpa: Allocator, db: *const lsdb.Lsdb, local: SystemId, now: Time) Allocator.Error!RouteTable {
    return computeWith(gpa, db, local, now, .{ .reject_asymmetric = false }) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        // Unreachable by construction: only `reject_asymmetric` raises it.
        error.AsymmetricMetric => unreachable,
    };
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
) Error!RouteTable {
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

    // ── 2. two-way connectivity check → admitted directed arcs ───────────────
    // arcs: (from ++ to) → the weight to relax that arc with. Per ISO Annex
    // C.2.4 Step 1 that weight is `metric_k(P,N)`, "the cost of the link from
    // P to N as reported in P's Link State PDU" — i.e. the *originator's own*
    // advertisement, for the direction actually being traversed. The two
    // directions of one link are two arcs and may differ (§7.2.8.2 permits it
    // in as many words), which is why nothing here merges them into a single
    // per-link number: no such number exists, because which direction of a
    // link a path uses is decided by the tree being computed.
    var arcs: std.AutoHashMapUnmanaged([12]u8, spf.Weight) = .empty;
    defer arcs.deinit(gpa);

    // Links whose two endpoints advertised different metrics. Counted per
    // unordered pair (at the lo⟶hi entry, so exactly once). Informational —
    // the routes are exact either way; see `Options.reject_asymmetric`.
    var asymmetric_links: u32 = 0;

    var dit = directed.iterator();
    while (dit.next()) |kv| {
        const a: SystemId = kv.key_ptr[0..6].*;
        const b: SystemId = kv.key_ptr[6..12].*;
        const fwd = kv.value_ptr.*; // a ⟶ b, a's own advertised metric
        var rev_key: [12]u8 = undefined;
        rev_key[0..6].* = b;
        rev_key[6..12].* = a;
        const rev = directed.get(rev_key); // b ⟶ a advertisement, if any

        // §7.2.8.2: both ISs must report the link, or it is not used at all.
        if (opts.require_two_way and rev == null) continue;

        // Report the asymmetry once per unordered pair (at the lower id's
        // entry). The metrics themselves are NOT reconciled — each arc keeps
        // its own.
        if (rev != null and rev.? != fwd and std.mem.order(u8, &a, &b) == .lt) {
            if (opts.reject_asymmetric) return error.AsymmetricMetric;
            asymmetric_links += 1;
        }

        var key: [12]u8 = undefined;
        key[0..6].* = a;
        key[6..12].* = b;
        try arcs.put(gpa, key, fwd);

        // Positive-control path only (`require_two_way = false`): a link
        // reported by just one endpoint has no metric for the other
        // direction, so mirror the one advertisement onto the reverse arc.
        // That reproduces exactly what the old undirected admission did with
        // a one-way advertisement, which is what the deliberately-broken
        // control tests below pin.
        if (rev == null) try arcs.put(gpa, rev_key, fwd);
    }

    // ── 3. intern system-ids → dense NodeIds (sorted, deterministic) ─────────
    // Node set = every arc endpoint, plus `local` if it originated an LSP (so
    // an isolated local system still yields a self route). Sorting the ids and
    // assigning NodeIds in ascending order makes the mapping independent of
    // hash-map iteration order AND aligns the ECT "low path id" tie-break with
    // the canonical lowest-system-id rule.
    var id_set: std.AutoArrayHashMapUnmanaged(SystemId, void) = .empty;
    defer id_set.deinit(gpa);
    {
        var ait = arcs.iterator();
        while (ait.next()) |kv| {
            try id_set.put(gpa, kv.key_ptr[0..6].*, {});
            try id_set.put(gpa, kv.key_ptr[6..12].*, {});
        }
        if (origins.contains(local)) try id_set.put(gpa, local, {});
    }

    // Local not in the graph → degenerate empty table (documented).
    if (!id_set.contains(local)) {
        return .{ .gpa = gpa, .routes = try gpa.alloc(Route, 0), .asymmetric_links = asymmetric_links };
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

    var pit = arcs.iterator();
    while (pit.next()) |kv| {
        const na = id_to_node.get(kv.key_ptr[0..6].*).?;
        const nb = id_to_node.get(kv.key_ptr[6..12].*).?;
        // One directed arc per admitted direction, at that direction's own
        // advertised metric — ISO Annex C.2.4 Step 1's `metric_k(P,N)`.
        graph.addArc(na, nb, kv.value_ptr.*) catch |err| switch (err) {
            // Arcs are keyed by ordered pair (so no duplicates) and from != to,
            // so these never fire; a positive weight is guaranteed by
            // `addDirected`'s clamp. Swallow the structural ones, propagate OOM.
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

    return .{ .gpa = gpa, .routes = try routes.toOwnedSlice(gpa), .asymmetric_links = asymmetric_links };
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

/// Like `insertReachLsp`, but the caller supplies the full 7-octet neighbour
/// id (system-id + pseudonode octet) instead of a plain `SystemId` — needed to
/// build fixtures that reference an actual LAN pseudonode (octet 6 != 0).
fn insertReachLspRaw(
    db: *lsdb.Lsdb,
    origin: SystemId,
    seq: u32,
    reach: []const struct { nbr7: [7]u8, metric: u24 },
) !void {
    var buf: [512]u8 = undefined;
    var b = try isis.pdu.LspBuilder.init(&buf, .{
        .remaining_lifetime = 1000,
        .lsp_id = .{ origin[0], origin[1], origin[2], origin[3], origin[4], origin[5], 0, 0 },
        .sequence_number = seq,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    });
    for (reach) |r| {
        try isis.tlvs.addExtendedIsReach(&b.tlvs, r.nbr7, r.metric, &.{});
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

// ── LAN pseudonode neighbour filter ──────────────────────────────────────────
//
// A LAN's designated IS (DIS) originates a pseudonode LSP whose LSP-ID has a
// non-zero pseudonode octet (octet 6), and every router on the LAN — including
// the DIS's own *real* LSP — advertises reachability to that pseudonode id,
// not to each other directly (ISO 10589 §7.2.5 / RFC 1195). This module's
// scope note (top of file) is explicit that LAN transit through the
// pseudonode-as-zero-cost-vertex is NOT modelled here (deferred); the filter
// at the two `neighbour_id[6] != 0` sites exists so that a reachability entry
// *pointing at* a pseudonode is simply dropped rather than being silently
// mistaken for a direct edge to whatever router happens to share the
// pseudonode's first six octets (its DIS).
//
// A bare single-LAN fixture (three routers, one pseudonode, nothing else)
// cannot distinguish "filter present" from "filter deleted": every non-DIS
// router's entry collapses to an edge *into* the DIS, but the DIS's own
// mirror entry collapses to a self-loop that `addDirected` already drops
// unconditionally — so the two-way check fails identically whether or not the
// filter runs, and the route table comes out empty either way (a green-
// either-way trap). The fixture below adds one genuine, independently-two-way
// point-to-point adjacency between the DIS and one LAN member, deliberately
// costed *higher* than the LAN's advertised cost to the pseudonode. If the
// filter is deleted, the cheap LAN-collapsed entry merges into the same
// (from, to) directed key as the real P2P entry and `addDirected` keeps the
// minimum — silently undercutting a real link's metric with a bogus one. That
// corruption is exactly what the filter prevents, and it shows up as a wrong
// `Route.metric`, not as a missing/extra route — so it survives even though
// the edge exists (and is two-way-valid) in both cases.
test "pseudonode neighbour filter (#22 extended): a LAN must not cheapen a real router adjacency" {
    const d = sysId(0x50); // the LAN's DIS; owns the pseudonode
    const x = sysId(0x10); // LAN member; also has a genuine, pricier P2P link to D
    const y = sysId(0x90); // LAN-only member: no other connectivity, stays unreachable

    const pn_d: [7]u8 = .{ d[0], d[1], d[2], d[3], d[4], d[5], 0x01 }; // D's pseudonode neighbour id
    const d7: [7]u8 = .{ d[0], d[1], d[2], d[3], d[4], d[5], 0 };
    const x7: [7]u8 = .{ x[0], x[1], x[2], x[3], x[4], x[5], 0 };

    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(x));
    defer db.deinit();

    // The pseudonode's own LSP (LSP-ID octet 6 = 0x01): lists every attached
    // router at cost 0, per ISO 10589. Included for fixture realism; this
    // module's separate P2P-only *origin* filter (root.zig, `lsp.lsp_id[6] !=
    // 0`) skips this LSP entirely regardless of the filter under test here.
    {
        var buf: [256]u8 = undefined;
        var lb = try isis.pdu.LspBuilder.init(&buf, .{
            .remaining_lifetime = 1000,
            .lsp_id = .{ d[0], d[1], d[2], d[3], d[4], d[5], 0x01, 0 },
            .sequence_number = 1,
            .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
        });
        try isis.tlvs.addExtendedIsReach(&lb.tlvs, x7, 0, &.{});
        try isis.tlvs.addExtendedIsReach(&lb.tlvs, d7, 0, &.{});
        const y7: [7]u8 = .{ y[0], y[1], y[2], y[3], y[4], y[5], 0 };
        try isis.tlvs.addExtendedIsReach(&lb.tlvs, y7, 0, &.{});
        _ = try db.insert(lb.finish(), null, 0);
    }

    // X: reachability to the pseudonode (cheap, cost 5) AND a genuine,
    // independent P2P adjacency to D (expensive, cost 100).
    try insertReachLspRaw(&db, x, 1, &.{
        .{ .nbr7 = pn_d, .metric = 5 },
        .{ .nbr7 = d7, .metric = 100 },
    });
    // D: its own mirror reachability to the pseudonode (collapses to a
    // self-loop; `addDirected` drops it) AND the reciprocal P2P to X.
    try insertReachLspRaw(&db, d, 1, &.{
        .{ .nbr7 = pn_d, .metric = 5 },
        .{ .nbr7 = x7, .metric = 100 },
    });
    // Y: LAN-only — its sole advertisement is to the pseudonode.
    try insertReachLspRaw(&db, y, 1, &.{
        .{ .nbr7 = pn_d, .metric = 5 },
    });

    var table = try compute(testing.allocator, &db, x, 0);
    defer table.deinit();

    // Correct (filter present): the LAN contributes no edges at all. The only
    // route is the real P2P adjacency to D, at its real cost (100) — NOT the
    // LAN's cost (5). Y is unreachable (its one-way LAN advertisement never
    // gets a reciprocal, regardless of this filter).
    try testing.expectEqual(@as(usize, 2), table.routes.len);
    try testing.expectEqual(Route{ .dest = x, .next_hop = x, .metric = 0 }, table.lookup(x).?);
    try testing.expectEqual(Route{ .dest = d, .next_hop = d, .metric = 100 }, table.lookup(d).?);
    try testing.expect(table.lookup(y) == null);
}

test "pseudonode neighbour filter (#2 old-style): a LAN must not cheapen a real router adjacency" {
    const d = sysId(0x51);
    const x = sysId(0x11);
    const y = sysId(0x91);

    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(x));
    defer db.deinit();

    const Entry = struct { origin: SystemId, seq: u32, reach: []const struct { nbr7: [7]u8, metric: u8 } };
    const pn_d: [7]u8 = .{ d[0], d[1], d[2], d[3], d[4], d[5], 0x01 };
    const d7: [7]u8 = .{ d[0], d[1], d[2], d[3], d[4], d[5], 0 };
    const x7: [7]u8 = .{ x[0], x[1], x[2], x[3], x[4], x[5], 0 };
    const entries = [_]Entry{
        .{ .origin = x, .seq = 1, .reach = &.{ .{ .nbr7 = pn_d, .metric = 5 }, .{ .nbr7 = d7, .metric = 50 } } },
        .{ .origin = d, .seq = 1, .reach = &.{ .{ .nbr7 = pn_d, .metric = 5 }, .{ .nbr7 = x7, .metric = 50 } } },
        .{ .origin = y, .seq = 1, .reach = &.{.{ .nbr7 = pn_d, .metric = 5 }} },
    };
    for (entries) |e| {
        var buf: [256]u8 = undefined;
        var lb = try isis.pdu.LspBuilder.init(&buf, .{
            .remaining_lifetime = 1000,
            .lsp_id = .{ e.origin[0], e.origin[1], e.origin[2], e.origin[3], e.origin[4], e.origin[5], 0, 0 },
            .sequence_number = e.seq,
            .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
        });
        var val: [128]u8 = undefined;
        var n: usize = 1; // leading virtual flag, left 0
        val[0] = 0;
        for (e.reach) |r| {
            val[n + 0] = r.metric;
            val[n + 1] = 0x80;
            val[n + 2] = 0x80;
            val[n + 3] = 0x80;
            @memcpy(val[n + 4 ..][0..7], &r.nbr7);
            n += 11;
        }
        try lb.tlvs.addTlv(isis.tlvs.code.is_neighbours_lsp, val[0..n]);
        _ = try db.insert(lb.finish(), null, 0);
    }

    var table = try compute(testing.allocator, &db, x, 0);
    defer table.deinit();

    try testing.expectEqual(@as(usize, 2), table.routes.len);
    try testing.expectEqual(Route{ .dest = x, .next_hop = x, .metric = 0 }, table.lookup(x).?);
    try testing.expectEqual(Route{ .dest = d, .next_hop = d, .metric = 50 }, table.lookup(d).?);
    try testing.expect(table.lookup(y) == null);
}

// ── LAN pseudonode *origin*-side filter ──────────────────────────────────────
//
// The companion filter, at the OTHER site (root.zig, `lsp.lsp_id[6] != 0`,
// near the top of the main LSP walk): it skips the pseudonode's *own* LSP
// entirely, so that LSP never becomes a source of directed advertisements —
// per ISO 10589 the pseudonode LSP lists every attached router at cost 0, and
// without this filter it would let the LAN silently supply a bogus zero(ish)-
// cost edge between whichever two attached routers, exactly like the
// neighbour-side finding above but injected from the *origin* end instead of
// the *neighbour* end of an entry.
//
// The fixture above (and bab3b37's) is blind to THIS filter for a subtly
// different reason than the bare-LAN trap documented there: `computeWith`
// picks its canonical undirected weight from the advertisement running from
// the lexicographically-LOWER system-id to the higher one (`lo_hi`, see the
// comment at its use site). In that fixture the DIS (0x50/0x51) is the
// numerically-HIGHER id, so the canonical weight is always the untouched
// member→DIS advertisement; corruption injected into the DIS's own outgoing
// entry (which is what the pseudonode LSP, parsed as an origin, would add)
// never gets selected. Reversing which endpoint is numerically lower flips
// that: here the DIS is deliberately the LOWER id, so its outgoing entry IS
// the canonical weight, and the pseudonode LSP's fake zero-cost entry to the
// same neighbour lands directly on top of the real, expensive P2P metric via
// `addDirected`'s min-merge — this is the origin-side counterpart to the
// undercutting bab3b37 proved on the neighbour side.
test "pseudonode ORIGIN filter: the pseudonode's own LSP must not itself supply a route" {
    const d = sysId(0x10); // the LAN's DIS — a LOWER system-id than the member below
    const x = sysId(0x50); // LAN member with a genuine, pricier P2P link to D

    const pn_d: [7]u8 = .{ d[0], d[1], d[2], d[3], d[4], d[5], 0x01 }; // D's pseudonode id
    const d7: [7]u8 = .{ d[0], d[1], d[2], d[3], d[4], d[5], 0 };
    const x7: [7]u8 = .{ x[0], x[1], x[2], x[3], x[4], x[5], 0 };

    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(x));
    defer db.deinit();

    // The pseudonode's own LSP (LSP-ID octet 6 = 0x01): lists X and D (itself)
    // at cost 0, per ISO 10589. If the origin filter is disabled, this LSP is
    // walked as if D originated it, injecting a fake D→X advertisement at the
    // clamped-minimum cost of 1.
    {
        var buf: [256]u8 = undefined;
        var lb = try isis.pdu.LspBuilder.init(&buf, .{
            .remaining_lifetime = 1000,
            .lsp_id = .{ d[0], d[1], d[2], d[3], d[4], d[5], 0x01, 0 },
            .sequence_number = 1,
            .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
        });
        try isis.tlvs.addExtendedIsReach(&lb.tlvs, x7, 0, &.{});
        try isis.tlvs.addExtendedIsReach(&lb.tlvs, d7, 0, &.{}); // self; addDirected ignores it anyway
        _ = try db.insert(lb.finish(), null, 0);
    }

    // D's own real LSP: the genuine, expensive P2P adjacency to X.
    try insertReachLspRaw(&db, d, 1, &.{
        .{ .nbr7 = pn_d, .metric = 5 }, // dropped by the neighbour-side filter regardless
        .{ .nbr7 = x7, .metric = 100 },
    });
    // X: reciprocal P2P to D, plus its own LAN entry to the pseudonode.
    try insertReachLspRaw(&db, x, 1, &.{
        .{ .nbr7 = pn_d, .metric = 5 },
        .{ .nbr7 = d7, .metric = 100 },
    });

    var table = try compute(testing.allocator, &db, x, 0);
    defer table.deinit();

    // Correct (origin filter present): the pseudonode LSP contributes nothing;
    // D is reachable only via the real P2P link, at its real cost (100) — NOT
    // the fake cost (1) the pseudonode LSP would otherwise inject.
    try testing.expectEqual(@as(usize, 2), table.routes.len);
    try testing.expectEqual(Route{ .dest = d, .next_hop = d, .metric = 100 }, table.lookup(d).?);
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

test "asymmetric metrics: each direction relaxes at its own advertised metric" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();

    // A advertises B with 7; B advertises A with 99. ISO Annex C.2.4 Step 1:
    // the arc A→B relaxes at A's own 7, the arc B→A at B's own 99.
    try insertReachLsp(&db, a, 1, &.{.{ .nbr = b, .metric = 7 }});
    try insertReachLsp(&db, b, 1, &.{.{ .nbr = a, .metric = 99 }});

    // From A: 7. (This value was also what the old rule -- "the
    // lexicographically-lower system-id's advertisement wins" -- produced,
    // because here A *is* the lower id. That coincidence is why this fixture
    // alone could never see the defect, and why the second half exists.)
    var from_a = try compute(testing.allocator, &db, a, 0);
    defer from_a.deinit();
    try testing.expectEqual(@as(u64, 7), from_a.lookup(b).?.metric);
    try testing.expectEqual(@as(u32, 1), from_a.asymmetric_links);

    // From B, over the very same link: 99, not 7. The old rule answered 7
    // here — the same wrong number for both directions.
    var from_b = try compute(testing.allocator, &db, b, 0);
    defer from_b.deinit();
    try testing.expectEqual(@as(u64, 99), from_b.lookup(a).?.metric);
    try testing.expectEqual(a, from_b.nextHop(a).?);
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

// ── FRR anchor: capture-and-freeze against a real IS-IS speaker ─────────────
//
// Everything above this point rests on our own reading of ISO/IEC 10589
// §7.2 — hand-built topologies, routes we believe the spec requires, tests
// and implementation sharing one author's interpretation of one document
// (see README.md, "Not anchored" — now superseded by this section for the
// cases below). This test fixes that for the cases a real router can grade:
// it is `frr`'s own `isisd` (10.3), run inside this repo's throwaway Debian
// VM lane (`scripts/vm/`, `frr` in `VM_DEBIAN_PACKAGES`), computing SPF over
// a topology we built, from the LSPs it actually flooded.
//
// Licence note (read before touching this block): FRR is GPL-2.0-or-later;
// this repo is MIT. Nothing here is copied from FRR's source, and nothing
// here is FRR's own test data (its GPL-licensed `tests/topotests/isis_topo1`
// fixtures were deliberately never opened for this task). What is frozen
// below is FRR's *output* for a topology this task authored from scratch.
// GPLv2 §0 restricts the covered *Program*, and expressly limits itself to
// output only "if its contents constitute a work based on the Program" — a
// routing table `isisd` computed for our own hand-built topology is not a
// work based on FRR any more than a compiler's object code is a work based
// on the compiler. This is the same capture-and-freeze pattern already used
// in this repo against goaccess and Wireshark (also GPL), and the run is
// ONE-SHOT: nothing below boots a VM, invokes FRR, or touches the network —
// the values are literals from here on.
//
// ── the topology (5 routers, 7 links, one asymmetric pair, one ECMP tie) ──
//
//   r1(0000.0000.0001) --10-- r2(...0002)
//   r1 --100-- r3(...0003)
//   r1 --20-- r4(...0004)
//   r1 --10-- r5(...0005)
//   r2 --10-- r4
//   r3 --10-- r4
//   r3 --50--> r5   (r3's OWN outgoing metric, level-1, toward r5)
//   r5 --5--> r3    (r5's OWN outgoing metric, level-1, toward r3 -- the
//                    asymmetric pair: same physical link, different cost
//                    per direction, exactly ISO 10589's per-interface metric
//                    model and exactly what a single-weight undirected
//                    engine (spf-ect) cannot represent, see SPEC.md §3.3)
//
// All five `isisd` instances ran as real p2p adjacencies (`isis network
// point-to-point`, `is-type level-1`, `metric-style wide`) in their own
// network namespace, joined by veth pairs, each with a `/30` (an IPv4
// address turned out to be load-bearing for the P2P 3-way handshake to
// leave Down even though Hellos were already flowing both ways at L2 --
// found by tcpdump, fixed by addressing the interfaces).
//
// `vtysh -c "show version"` (once, after convergence):
//   FRRouting 10.3 (localhost) on Linux(6.12.96+deb13-amd64).
//
// `vtysh -c "show isis database detail"` on r1 (verifies the LSDB the
// fixture below encodes is the SAME graph FRR actually converged on, not
// just what this task intended to configure -- the two are not
// automatically the same, and this is what makes them so; only the
// Extended Reachability lines are quoted, one per originating LSP):
//   r1.00-00: Extended Reachability: 0000.0000.0002.00 (Metric: 10)
//             Extended Reachability: 0000.0000.0003.00 (Metric: 100)
//             Extended Reachability: 0000.0000.0004.00 (Metric: 20)
//             Extended Reachability: 0000.0000.0005.00 (Metric: 10)
//   r2.00-00: Extended Reachability: 0000.0000.0001.00 (Metric: 10)
//             Extended Reachability: 0000.0000.0004.00 (Metric: 10)
//   r3.00-00: Extended Reachability: 0000.0000.0001.00 (Metric: 100)
//             Extended Reachability: 0000.0000.0004.00 (Metric: 10)
//             Extended Reachability: 0000.0000.0005.00 (Metric: 50)
//   r4.00-00: Extended Reachability: 0000.0000.0001.00 (Metric: 20)
//             Extended Reachability: 0000.0000.0002.00 (Metric: 10)
//             Extended Reachability: 0000.0000.0003.00 (Metric: 10)
//   r5.00-00: Extended Reachability: 0000.0000.0001.00 (Metric: 10)
//             Extended Reachability: 0000.0000.0003.00 (Metric: 5)
//
// `vtysh -c "show isis topology"` on r1 (the oracle; IP-prefix leaf rows
// omitted -- out of this module's scope, SPEC.md §6):
//    Vertex  Type  Metric  Next-Hop  Interface  Parent
//    r1
//    r2      TE-IS   10     r2        eth-r2     r1(4)
//    r5      TE-IS   10     r5        eth-r5     r1(4)
//    r3      TE-IS   15     r5        eth-r5     r5(4)
//    r4      TE-IS   20     r4        eth-r4     r1(4)
//                            r2        eth-r2     r2(4)
//
// ── reading the result: all five rows now match ──
//
// r2, r5 (direct neighbours) and r4 (the ECMP tie) always matched FRR: the
// old undirected approximation (one weight per link, taken from the
// LOWER-system-id endpoint's advertisement) happened to equal the true
// directed cost on every link those three use, because the root (r1) is the
// lower-id endpoint of every link it uses directly, and {r2,r4} / {r1,r4}
// are symmetric.
//
// r3 did not, and that was the whole finding. FRR's directed SPF reaches r3
// over the r5→r3 arc at r5's OWN advertised metric -- 5, total 15. The
// undirected engine had to pick ONE weight for the {r3,r5} pair and picked
// the lower id's (r3's 50), regardless of which direction a path needs, which
// made the r4 branch (20 + 10 = 30) look cheaper than the r5 branch
// (10 + 50 = 60). A router loading that table sent r3's traffic the wrong way
// and billed it at twice the true cost. `55752d4` made the module detect and
// refuse such a database instead -- honest, still not an answer.
//
// It is an answer now. `spf-ect` grew `Graph.addArc` (one directed arc, one
// weight, per direction) and step 2 above admits one arc per advertised
// direction at that direction's own metric, which is precisely ISO/IEC 10589
// Annex C.2.4 Step 1: `dist(P,N) = d(P) + metric_k(P,N)`, where
// "metric_k(P,N) is the cost of the link from P to N as reported in P's Link
// State PDU". Nothing merges the two advertisements, because §7.2.8.2 says
// they are allowed to differ ("routes may be asymmetric") -- the two-way
// check decides whether a link is USED, never what it COSTS.
//
// So the assertions below changed direction: they used to pin our
// disagreement with the oracle (asserting our 30, and that `computeWith`
// refuses); they now pin agreement with it (15 via r5). Every other claim the
// old tests made is still made -- five routes, the asymmetric-link count of
// 1, r2/r5 exact, r4's ECMP tie -- plus the explicit statement that the old
// wrong answer (30 via r4/r2) is NOT what comes back, so the regression
// cannot return unnoticed.

/// FRR 10.3's answer for this topology, read off the `show isis topology`
/// transcript above. These are the oracle's values, not ours.
const frr_r3_metric: u64 = 15;
/// FRR's next hop for r3, same transcript row ("r3 TE-IS 15 r5 eth-r5 r5(4)").
const frr_r3_next_hop: SystemId = .{ 0, 0, 0, 0, 0, 5 };
/// What the undirected engine used to answer instead. Asserted against, so
/// the closed defect cannot creep back in silently.
const undirected_wrong_r3_metric: u64 = 30;

fn frrTopology(db: *lsdb.Lsdb) !void {
    const r1 = sysId(1);
    const r2 = sysId(2);
    const r3 = sysId(3);
    const r4 = sysId(4);
    const r5 = sysId(5);
    try insertReachLsp(db, r1, 1, &.{
        .{ .nbr = r2, .metric = 10 },
        .{ .nbr = r3, .metric = 100 },
        .{ .nbr = r4, .metric = 20 },
        .{ .nbr = r5, .metric = 10 },
    });
    try insertReachLsp(db, r2, 1, &.{
        .{ .nbr = r1, .metric = 10 },
        .{ .nbr = r4, .metric = 10 },
    });
    try insertReachLsp(db, r3, 1, &.{
        .{ .nbr = r1, .metric = 100 },
        .{ .nbr = r4, .metric = 10 },
        .{ .nbr = r5, .metric = 50 }, // r3's own outgoing metric (asymmetric)
    });
    try insertReachLsp(db, r4, 1, &.{
        .{ .nbr = r1, .metric = 20 },
        .{ .nbr = r2, .metric = 10 },
        .{ .nbr = r3, .metric = 10 },
    });
    try insertReachLsp(db, r5, 1, &.{
        .{ .nbr = r1, .metric = 10 },
        .{ .nbr = r3, .metric = 5 }, // r5's own outgoing metric (asymmetric)
    });
}

test "FRR anchor: the asymmetric database FRR routes at 15 is ANSWERED at 15 via r5" {
    // The whole point of the row. On the exact input where a real IS-IS
    // router reaches r3 at cost 15 via r5, the default decision process here
    // must produce 15 via r5 -- not the old undirected 30 via r4, and no
    // longer a refusal either. `require_two_way` is left at its correct
    // default so nothing else is in play.
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(sysId(1)));
    defer db.deinit();
    try frrTopology(&db);

    var table = try computeWith(testing.allocator, &db, sysId(1), 0, .{});
    defer table.deinit();

    const r3 = table.lookup(sysId(3)).?;
    try testing.expectEqual(frr_r3_metric, r3.metric);
    try testing.expectEqual(frr_r3_next_hop, r3.next_hop);
    // The claim the superseded version of this test made, kept verbatim in
    // substance: the old confident wrong answer must not come back.
    try testing.expect(r3.metric != undirected_wrong_r3_metric);

    // The refusal is now opt-in, and still works: a caller that needs a
    // symmetric fabric (802.1aq) can still be told this database is not one.
    try testing.expectError(
        error.AsymmetricMetric,
        computeWith(testing.allocator, &db, sysId(1), 0, .{ .reject_asymmetric = true }),
    );
}

test "FRR anchor: the r5 arc is what carries it — flipping r5's advertisement moves the route" {
    // Teeth for the direction rule specifically. ISO Annex C.2.4 Step 1 uses
    // "the cost of the link from P to N as reported in P's Link State PDU",
    // so the r5→r3 arc's weight is r5's 5 and the r3→r5 arc's is r3's 50.
    // Reading the wrong endpoint's advertisement (what the undirected engine
    // did) is invisible on a symmetric fixture, so this one asserts BOTH
    // trees over the same database: from r1 the cheap arc is available (15
    // via r5) and from r3 it is not (r3→r5 costs 50, so r3 reaches r1 at 30
    // via r4, not at 60 via r5 and not at 15).
    const r1 = sysId(1);
    const r3 = sysId(3);
    const r4 = sysId(4);
    const r5 = sysId(5);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(r1));
    defer db.deinit();
    try frrTopology(&db);

    var from_r1 = try compute(testing.allocator, &db, r1, 0);
    defer from_r1.deinit();
    try testing.expectEqual(@as(u64, 15), from_r1.lookup(r3).?.metric);
    try testing.expectEqual(r5, from_r1.nextHop(r3).?);
    // r5 itself is still a direct neighbour at 10 (r1's own advertisement).
    try testing.expectEqual(@as(u64, 10), from_r1.lookup(r5).?.metric);

    var from_r3 = try compute(testing.allocator, &db, r3, 0);
    defer from_r3.deinit();
    // r3 → r1: 30 via r4 (10 + 20) beats 60 via r5 (50 + 10) and 100 direct.
    try testing.expectEqual(@as(u64, 30), from_r3.lookup(r1).?.metric);
    try testing.expectEqual(r4, from_r3.nextHop(r1).?);
    // The {r3,r5} link traversed the OTHER way costs r3 its own 50, which is
    // no longer competitive: r3 reaches r5 at 40, the long way round via
    // r4—r1. An undirected engine cannot produce this at all — it has one
    // number for the link and therefore one distance for both directions.
    try testing.expectEqual(@as(u64, 40), from_r3.lookup(r5).?.metric);
    try testing.expectEqual(r4, from_r3.nextHop(r5).?);

    var from_r5 = try compute(testing.allocator, &db, r5, 0);
    defer from_r5.deinit();
    // …while r5 reaches r3 at 5, over that same link. 5 one way, 40 the
    // other: the asymmetry is the point.
    try testing.expectEqual(@as(u64, 5), from_r5.lookup(r3).?.metric);
    try testing.expectEqual(r3, from_r5.nextHop(r3).?);
}

test "FRR anchor: `compute` reproduces every row of FRR's table, and still flags the link" {
    const r1 = sysId(1);
    const r2 = sysId(2);
    const r3 = sysId(3);
    const r4 = sysId(4);
    const r5 = sysId(5);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(r1));
    defer db.deinit();
    try frrTopology(&db);

    var table = try compute(testing.allocator, &db, r1, 0);
    defer table.deinit();

    try testing.expectEqual(@as(usize, 5), table.routes.len);

    // Exactly one link ({r3,r5}, 50 one way and 5 the other) is asymmetric.
    // The count no longer means "approximated" -- the routes below are exact
    // -- but it is still the signal an 802.1aq fabric needs, and counting it
    // exactly once per unordered pair is still a claim worth pinning.
    try testing.expectEqual(@as(u32, 1), table.asymmetric_links);

    // Direct neighbours: exact match with FRR ("show isis topology": r2/r5,
    // metric 10, next-hop themselves).
    try testing.expectEqual(Route{ .dest = r2, .next_hop = r2, .metric = 10 }, table.lookup(r2).?);
    try testing.expectEqual(Route{ .dest = r5, .next_hop = r5, .metric = 10 }, table.lookup(r5).?);

    // r4: FRR shows an ECMP tie (direct @20, via r2 @20); this module
    // resolves to exactly one of the two legitimate first hops (spf-ect's
    // ECT tie-break), same shape as the pre-existing "diamond" test above.
    const r4_route = table.lookup(r4).?;
    try testing.expectEqual(@as(u64, 20), r4_route.metric);
    try testing.expect(std.mem.eql(u8, &r4_route.next_hop, &r4) or std.mem.eql(u8, &r4_route.next_hop, &r2));

    // r3: the row that used to diverge, asserted AS agreement. FRR's
    // transcript says "r3 TE-IS 15 r5 eth-r5 r5(4)"; so do we, both fields.
    const r3_route = table.lookup(r3).?;
    try testing.expectEqual(frr_r3_metric, r3_route.metric);
    try testing.expectEqual(frr_r3_next_hop, r3_route.next_hop);
    try testing.expect(std.mem.eql(u8, &r3_route.next_hop, &r5));
    // …and the specific wrong shape the undirected engine produced (30, via
    // r4 or r2) is named and excluded, so its return is a test failure and
    // not a quiet regression.
    try testing.expect(r3_route.metric != undirected_wrong_r3_metric);
    try testing.expect(!std.mem.eql(u8, &r3_route.next_hop, &r4));
    try testing.expect(!std.mem.eql(u8, &r3_route.next_hop, &r2));
}

test "asymmetry detection does not fire on a symmetric database" {
    // The refusal above is only worth anything if it is specific: a symmetric
    // fabric -- which is what 802.1aq requires and what this stack actually
    // runs -- must go through untouched, with the count at zero. Same topology
    // as the FRR one with the single asymmetric pair made symmetric (both
    // endpoints 50), so the difference between the two tests is exactly the
    // one advertisement.
    const r1 = sysId(1);
    const r3 = sysId(3);
    const r5 = sysId(5);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(r1));
    defer db.deinit();
    try insertReachLsp(&db, r1, 1, &.{
        .{ .nbr = sysId(2), .metric = 10 },
        .{ .nbr = r3, .metric = 100 },
        .{ .nbr = sysId(4), .metric = 20 },
        .{ .nbr = r5, .metric = 10 },
    });
    try insertReachLsp(&db, sysId(2), 1, &.{
        .{ .nbr = r1, .metric = 10 },
        .{ .nbr = sysId(4), .metric = 10 },
    });
    try insertReachLsp(&db, r3, 1, &.{
        .{ .nbr = r1, .metric = 100 },
        .{ .nbr = sysId(4), .metric = 10 },
        .{ .nbr = r5, .metric = 50 },
    });
    try insertReachLsp(&db, sysId(4), 1, &.{
        .{ .nbr = r1, .metric = 20 },
        .{ .nbr = sysId(2), .metric = 10 },
        .{ .nbr = r3, .metric = 10 },
    });
    try insertReachLsp(&db, r5, 1, &.{
        .{ .nbr = r1, .metric = 10 },
        .{ .nbr = r3, .metric = 50 }, // symmetric now
    });

    var table = try computeWith(testing.allocator, &db, r1, 0, .{});
    defer table.deinit();
    try testing.expectEqual(@as(u32, 0), table.asymmetric_links);
    try testing.expectEqual(@as(usize, 5), table.routes.len);
    // With the {r3,r5} link genuinely costing 50 both ways, 30 via r4 IS the
    // right answer, and now it is asserted about a database where it is right.
    try testing.expectEqual(@as(u64, 30), table.lookup(r3).?.metric);
}

test "meta is well-formed" {
    try testing.expectEqual(.any, meta.platform);
    try testing.expectEqual(.util, meta.role);
    try testing.expectEqual(.single_owner, meta.concurrency);
}
