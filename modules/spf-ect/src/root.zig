// SPDX-License-Identifier: MIT
//! spf-ect — deterministic symmetric shortest-path core with ECT-style tie-breaking.
//!
//! Dijkstra shortest-path plus a totally-ordered, direction-independent tie-break
//! (the SPB/802.1aq ECT idea, portable to IP/ECMP) so that path(A→B) is always the
//! reverse of path(B→A), and a disjointness-minimizing second-tree variant (PRP
//! mode) — a greedy, equal-cost tie-break that steers onto unused links wherever
//! the graph offers one, not a max-flow disjoint-path guarantee. Pure graph
//! algorithm, zero I/O. Shared kernel of the SPB simulator (S1) and the
//! encrypted SCADA L2VPN fabric (S1b). See ~/CML/S1B-scada-l2vpn-venture-plan.md §5/§9.
//!
//! **Status: complete — both tiers implemented and property-tested.**
//! - **Graph, Dijkstra, public API, property-test harness (Sonnet scaffold).**
//!   Textbook single-source Dijkstra over a `Graph` builder with deterministic
//!   (sorted-by-neighbor-id) adjacency, plus the plumbing that calls out to the
//!   tie-break on every distance-tying relaxation.
//! - **`comparePaths` / `comparePathsDisjoint` (Fable core).** The genuinely hard
//!   part: a deterministic, *direction-independent* total order over equal-cost
//!   candidate paths (see each function's doc comment for the exact contract — the
//!   RFC 6329 / IEEE 802.1aq ECT path-vector idea, generalized off VLAN fabrics
//!   onto a plain weighted graph). Implemented as a lexicographic composite of a
//!   sorted node multiset (+inf-padded, extension-consistent), a sorted undirected
//!   edge multiset, and a forward-order totality backstop reachable only at
//!   identical sequences. The first two keys are preserved by path reversal, which
//!   is what makes `path(a, b) == reverse(path(b, a))`; `comparePathsDisjoint` adds
//!   a leading primary-tree overlap key for the overlap-minimizing PRP second tree.
//! - **Tests.** The property-test harness (symmetry, strict total order,
//!   brute-force `<=7`-node cross-check, disjoint-tree validity + disjointness)
//!   passes in full in both Debug and ReleaseFast.
//!
//! ## Usage
//! ```zig
//! const spf = @import("spf-ect");
//! var g = spf.Graph.init(gpa);
//! defer g.deinit();
//! try g.addEdge(0, 1, 4);
//! try g.addEdge(1, 2, 3);
//! const path = try spf.shortestPath(gpa, &g, 0, 2); // [0, 1, 2]
//! defer gpa.free(path);
//! ```

const std = @import("std");
const Allocator = std.mem.Allocator;
const Order = std.math.Order;

pub const meta = .{
    .platform = .any,
    .role = .util,
    // Each Graph/Tree instance is caller-owned, single-threaded value state —
    // safe to use concurrently as long as distinct instances aren't shared.
    .concurrency = .reentrant,
    .model_after = "IEEE 802.1aq / RFC 6329 SPB ECT + Dijkstra",
    .deps = .{}, // std only
};

// ── graph ─────────────────────────────────────────────────────────────────

/// Node identity — a dense id in `[0, graph.nodeCount())`. Callers assign
/// ids; there is no separate "label" type.
pub const NodeId = u32;

/// Positive edge weight. `addEdge` REJECTS 0 (`error.ZeroWeight`): a 0-weight
/// edge can make `dist[u] == dist[v]` for adjacent `u`/`v`, which the ECT
/// tie-break can resolve into a `pred[u] == v, pred[v] == u` predecessor
/// 2-cycle — and `Tree.pathTo` walks that chain unbounded (a DoS). Requiring
/// `weight >= 1` keeps predecessor chains acyclic, exactly the invariant
/// Dijkstra's tie handling and PRP-style loop-free trees rely on.
pub const Weight = u32;

/// Path cost accumulator — wide enough that summing `Weight` edges along any
/// path in a graph with `< 2^32` nodes cannot overflow.
pub const Distance = u64;

/// Sentinel for "no path found" in `Tree.dist`.
pub const unreachable_dist: Distance = std.math.maxInt(Distance);

/// One directed half of an undirected edge, as stored in `Graph`'s adjacency.
pub const Edge = struct {
    to: NodeId,
    weight: Weight,
};

/// A candidate (or resolved) path, source-first, destination-last.
pub const Path = []const NodeId;

/// Weighted undirected graph. Nodes are the dense range `[0, nodeCount())`;
/// `ensureNode`/`addEdge` grow that range as needed (isolated nodes are
/// allowed — e.g. to reserve an id before its first edge exists).
///
/// Adjacency lists are kept sorted by neighbor `NodeId` at all times, so
/// `neighbors(n)` — and therefore Dijkstra's relaxation order — never
/// depends on the order edges were added in. That determinism is what makes
/// the tie-break's job well-defined: the ONLY source of nondeterminism left
/// for a tie to resolve is genuine equal-cost alternative paths, never
/// incidental insertion order.
pub const Graph = struct {
    gpa: Allocator,
    /// `adj.items[n]` = node `n`'s outgoing edges, sorted by `.to`. Length
    /// is always `nodeCount()`; every id below it is a valid node.
    adj: std.ArrayList(std.ArrayList(Edge)),

    pub fn init(gpa: Allocator) Graph {
        return .{ .gpa = gpa, .adj = .empty };
    }

    pub fn deinit(self: *Graph) void {
        for (self.adj.items) |*list| list.deinit(self.gpa);
        self.adj.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn nodeCount(self: *const Graph) u32 {
        return @intCast(self.adj.items.len);
    }

    /// Grow the node table so `id` is a valid node (new nodes start
    /// isolated, no edges). Idempotent — a no-op if `id` already exists.
    pub fn ensureNode(self: *Graph, id: NodeId) Allocator.Error!void {
        if (id < self.nodeCount()) return;
        const old_len = self.adj.items.len;
        try self.adj.resize(self.gpa, @as(usize, id) + 1);
        for (self.adj.items[old_len..]) |*list| list.* = .empty;
    }

    pub const AddEdgeError = error{
        /// `a == b` — undirected simple graphs only, no self-loops.
        SelfLoop,
        /// This unordered pair already has an edge; call `addEdge` once per
        /// pair (there's no update-in-place — remove-then-readd if needed).
        DuplicateEdge,
        /// `weight == 0` — shortest paths require strictly positive weights
        /// (see `Weight`): a 0-weight edge can yield a predecessor 2-cycle
        /// that makes `Tree.pathTo` loop unbounded.
        ZeroWeight,
    } || Allocator.Error;

    /// Add undirected edge `a <-> b` with `weight` (must be `>= 1`). Both
    /// endpoints are auto-created via `ensureNode`. Fails atomically: on
    /// `DuplicateEdge` or OOM partway through, the graph is left exactly as
    /// it was before the call (no half-added edge).
    pub fn addEdge(self: *Graph, a: NodeId, b: NodeId, weight: Weight) AddEdgeError!void {
        if (a == b) return error.SelfLoop;
        if (weight == 0) return error.ZeroWeight;
        try self.ensureNode(@max(a, b));
        try insertSorted(self.gpa, &self.adj.items[a], .{ .to = b, .weight = weight });
        errdefer removeSorted(&self.adj.items[a], b);
        try insertSorted(self.gpa, &self.adj.items[b], .{ .to = a, .weight = weight });
    }

    /// `node`'s edges, sorted by neighbor id. Valid until the next mutating
    /// call on this graph.
    pub fn neighbors(self: *const Graph, node: NodeId) []const Edge {
        return self.adj.items[node].items;
    }
};

fn insertSorted(gpa: Allocator, list: *std.ArrayList(Edge), e: Edge) Graph.AddEdgeError!void {
    var i: usize = 0;
    while (i < list.items.len and list.items[i].to < e.to) : (i += 1) {}
    if (i < list.items.len and list.items[i].to == e.to) return error.DuplicateEdge;
    try list.insert(gpa, i, e);
}

fn removeSorted(list: *std.ArrayList(Edge), to: NodeId) void {
    for (list.items, 0..) |e, i| {
        if (e.to == to) {
            _ = list.orderedRemove(i);
            return;
        }
    }
}

// ── shortest-path tree ───────────────────────────────────────────────────

/// A single-source shortest-path tree, as built by `shortestPathTree`.
/// Owns `dist`/`pred` (freed by `deinit`); indices are `NodeId`s in
/// `[0, node_count)` as of the `Graph` passed to the build call.
pub const Tree = struct {
    gpa: Allocator,
    root: NodeId,
    /// `dist[n]` — shortest cost from `root` to `n`, or `unreachable_dist`.
    dist: []Distance,
    /// `pred[n]` — `n`'s predecessor on the resolved shortest-path tree, or
    /// `null` for `root` and for unreached nodes. Acyclic by construction
    /// as long as every edge weight used to build the tree was `>= 1` (see
    /// `Weight`'s doc comment).
    pred: []?NodeId,

    pub fn deinit(self: *Tree) void {
        self.gpa.free(self.dist);
        self.gpa.free(self.pred);
        self.* = undefined;
    }

    pub fn distanceTo(self: *const Tree, target: NodeId) Distance {
        return self.dist[target];
    }

    pub fn reachable(self: *const Tree, target: NodeId) bool {
        return self.dist[target] != unreachable_dist;
    }

    pub const PathError = error{Unreachable} || Allocator.Error;

    /// Reconstruct the resolved `root..target` path (inclusive both ends),
    /// caller-owned. `[root]` when `target == root`. `error.Unreachable`
    /// when no path exists.
    pub fn pathTo(self: *const Tree, gpa: Allocator, target: NodeId) PathError![]NodeId {
        if (self.dist[target] == unreachable_dist) return error.Unreachable;
        var rev: std.ArrayList(NodeId) = .empty;
        defer rev.deinit(gpa);
        var cur = target;
        try rev.append(gpa, cur);
        while (cur != self.root) {
            cur = self.pred[cur].?;
            try rev.append(gpa, cur);
        }
        const path = try gpa.alloc(NodeId, rev.items.len);
        for (rev.items, 0..) |id, i| path[path.len - 1 - i] = id;
        return path;
    }
};

// ── the tie-break contract (Fable core) ──────────────────────────────────

/// Symmetric, direction-independent tie-break between two equal-cost
/// candidate paths between the SAME pair of endpoints (source first,
/// destination last — see `Path`). This is the SPB/802.1aq "ECT path-vector"
/// idea (RFC 6329 §C / IEEE 802.1aq cl. 28), generalized off VLAN fabrics
/// onto a plain weighted graph.
///
/// Called by `shortestPathTree`'s Dijkstra pass every time relaxing an edge
/// finds a distance TIE (a new candidate predecessor whose path cost to a
/// node exactly matches the currently-recorded one): `a` is the path
/// through the edge just relaxed, `b` is the path through the currently
/// recorded predecessor. `.lt` means "`a` wins" (Dijkstra adopts it as the
/// new predecessor); the running "keep the total-order-best candidate seen
/// so far" reduction is what turns pairwise relaxation-time comparisons
/// into the correct total-order winner over the FULL set of equal-cost
/// candidates into a node (a basic property of any genuine total order —
/// see the "keep-running-best" argument in SPEC.md if written, or just: a
/// linear scan that keeps replacing the incumbent with a strictly-better
/// challenger always ends on the true maximum, independent of visitation
/// order).
///
/// Contract — ALL of the following are REQUIRED for
/// `shortestPath(gpa, g, a, b)` to equal
/// `reverse(shortestPath(gpa, g, b, a))` (this is exactly what the
/// `"property: symmetry"` test below checks, over many random graphs):
///
///  1. **Strict total order.** For any two candidate paths `p`, `q`:
///     - irreflexive/antisymmetric: `compare(p, q)` and `compare(q, p)` are
///       never both `.lt` (or both `.gt`); if `p` and `q` are distinct node
///       sequences, exactly one of `.lt`/`.gt` holds.
///     - transitive: `compare(p, q) == .lt and compare(q, r) == .lt`
///       implies `compare(p, r) == .lt`.
///     - `.eq` is returned ONLY when `p` and `q` are the identical node
///       sequence (`std.mem.eql`) — never for two genuinely distinct paths,
///       even same-cost ones. (Otherwise the tie-break wouldn't actually
///       break the tie.)
///  2. **Reversal-invariant** — THE crux property, and the one naive
///     "compare node-id sequences front-to-back" implementations get wrong:
///     `comparePaths(reverse(p), reverse(q)) == comparePaths(p, q)` for
///     every candidate pair. Dijkstra-from-A and Dijkstra-from-B walk the
///     *same* underlying shortest-path DAG in opposite directions; only a
///     comparator whose verdict survives reversing BOTH candidates at once
///     can make the two independent single-source runs agree on which of
///     two tied sub-paths wins, all the way out to the A↔B endpoints. A
///     plain lexicographic first-point-of-difference compare over the
///     forward node-id sequence is NOT reversal-invariant (the first
///     difference from the front and from the back are different
///     positions in general) — RFC 6329's actual ECT algorithms derive
///     their comparison key from a function of the path that's symmetric
///     under reversal (e.g. built from the SET of node ids on the path, or
///     from a canonically-oriented digest of it), not from positional
///     front-to-back order. That derivation is the actual hard part; this
///     doc comment is the spec, `@panic` below is the TODO.
///
/// `a`/`b` may have different lengths (equal path COST does not imply equal
/// hop count when weights vary).
pub fn comparePaths(a: Path, b: Path) Order {
    // Lexicographic composite of three keys, most-significant first.
    //
    // Key 1 — RFC 6329 "low PATH ID", generalized: the ascending-sorted
    // MULTISET of node ids on the path, compared lexicographically. A path
    // and its reverse traverse the same node multiset, so this key is
    // reversal-invariant by construction. It is also extension-consistent
    // (appending the shared next hop inserts the same id into both sides'
    // multisets, which preserves the +inf-padded sorted-lex order — see
    // `orderItemMultisets`), which is what lets Dijkstra's local pairwise
    // "keep the best candidate so far" reduction compute the true global
    // minimum over all equal-cost paths into every node.
    const by_nodes = orderItemMultisets(.node, a, b);
    if (by_nodes != .eq) return by_nodes;

    // Key 2 — the same idea over the multiset of undirected edges (as
    // canonical (lo, hi) pairs), covering the corner where two DISTINCT
    // equal-cost simple paths visit the exact same node set (e.g. the
    // 4-cycle a-x-b-y-a plus chord x-y: a→x→y→b vs a→y→x→b). Two simple
    // paths with the same node multiset AND the same edge multiset are the
    // same path graph, i.e. identical up to orientation — and orientation
    // is fixed by the shared (source, destination) endpoints, so for
    // genuine candidates key 1 + key 2 equal implies identical sequences.
    // Edge sets are direction-free, so this key is reversal-invariant too,
    // and extension-consistent (appending the shared final hop adds the
    // same edge to both sides).
    const by_edges = orderItemMultisets(.edge, a, b);
    if (by_edges != .eq) return by_edges;

    // Key 3 — totality backstop only. For real same-endpoint candidates it
    // is reached only when a == b (see key 2's argument); it exists so the
    // comparator is a strict total order over ARBITRARY node sequences
    // (including non-simple ones and reversal pairs like [1,2] vs [2,1],
    // which share both multisets but can never both be candidates between
    // the same ordered endpoint pair — any pair on which plain forward
    // order breaks reversal-invariance is exactly such a pair, so the
    // candidate-domain invariance is untouched).
    return std.mem.order(NodeId, a, b);
}

/// Which per-position item `orderItemMultisets` streams out of a path:
/// its node ids, or its undirected edges packed canonically as
/// `(@min(u,v) << 32) | @max(u,v)`.
const PathItem = enum { node, edge };

fn pathItemCount(comptime kind: PathItem, p: Path) usize {
    return switch (kind) {
        .node => p.len,
        .edge => p.len -| 1,
    };
}

fn pathItemAt(comptime kind: PathItem, p: Path, i: usize) u64 {
    return switch (kind) {
        .node => p[i],
        .edge => (@as(u64, @min(p[i], p[i + 1])) << 32) | @max(p[i], p[i + 1]),
    };
}

/// Streams the multiset {pathItemAt(kind, p, i)} in ascending order without
/// materializing it (comparators get no allocator): each `next` is an O(len)
/// "smallest value strictly greater than the last emitted one, with its
/// duplicate count" scan, O(len^2) per full comparison — fine for tie-break
/// candidates, which are single paths.
fn SortedItemCursor(comptime kind: PathItem) type {
    return struct {
        p: Path,
        emitted_any: bool = false,
        cur: u64 = 0,
        dup: usize = 0,

        fn next(self: *@This()) ?u64 {
            if (self.dup > 0) {
                self.dup -= 1;
                return self.cur;
            }
            var best: ?u64 = null;
            var copies: usize = 0;
            for (0..pathItemCount(kind, self.p)) |i| {
                const v = pathItemAt(kind, self.p, i);
                if (self.emitted_any and v <= self.cur) continue;
                if (best == null or v < best.?) {
                    best = v;
                    copies = 1;
                } else if (v == best.?) {
                    copies += 1;
                }
            }
            self.cur = best orelse return null;
            self.dup = copies - 1;
            self.emitted_any = true;
            return self.cur;
        }
    };
}

/// Lexicographic comparison of the ascending-sorted item multisets of `a`
/// and `b`. Exhaustion convention: missing positions read as +infinity, so
/// the side that runs out first is the GREATER one. This — and NOT the
/// "shorter prefix wins" convention — is the order preserved by inserting
/// one common item into both sides (insertion before the first point of
/// difference shifts both sides identically; insertion after it leaves the
/// difference in place; +inf padding makes the run-out case just another
/// "after the difference" case), and that preservation is exactly the
/// extension consistency `comparePaths`'s correctness argument needs.
fn orderItemMultisets(comptime kind: PathItem, a: Path, b: Path) Order {
    var ca: SortedItemCursor(kind) = .{ .p = a };
    var cb: SortedItemCursor(kind) = .{ .p = b };
    while (true) {
        const x = ca.next();
        const y = cb.next();
        if (x == null and y == null) return .eq;
        if (x == null) return .gt; // a exhausted first: pads to +inf > y
        if (y == null) return .lt;
        if (x.? != y.?) return if (x.? < y.?) .lt else .gt;
    }
}

/// Secondary tie-break used to build `disjointTrees`' second ("backup"/PRP)
/// tree. Same strict-total-order + reversal-invariance contract as
/// `comparePaths` (see its doc comment), PLUS it should prefer candidates
/// that reuse fewer of `primary`'s tree edges, so the resulting tree overlaps
/// `primary` as little as tie-breaking among equal-cost paths allows —
/// 802.1aq defines a second ECT algorithm for exactly this (its 16-way
/// multi-tree scheme alternates "low path id" / "high path id" variants);
/// PRP/HSR-style dual delivery just needs two, as disjoint as the topology
/// and its equal-cost alternatives allow (this is a greedy heuristic, not a
/// guarantee of graph-theoretic maximum edge-disjointness).
///
/// `primary` is a FINISHED tree (`shortestPathTree` already returned) by
/// the time this is called — inspect `primary.pred`/`primary.dist` freely,
/// do not mutate.
///
/// Documented disjointness metric (see the `"property: disjointness"` test
/// below for how it's checked): the fraction of `secondary`'s tree edges
/// that also appear in `primary`'s tree edge set,
/// `|E(primary) ∩ E(secondary)| / |E(primary)|`, should be strictly less
/// than the trivial baseline of reusing `comparePaths` again (which — same
/// deterministic input, same deterministic comparator — reproduces
/// `primary` exactly, i.e. 100% overlap) whenever the graph actually offers
/// a link-disjoint alternative.
pub fn comparePathsDisjoint(primary: *const Tree, a: Path, b: Path) Order {
    // Most-significant key: how many of the candidate's undirected edges
    // are also edges of `primary`'s tree — fewer wins, steering the second
    // tree onto links the first one left unused wherever an equal-cost
    // alternative exists. The count is over the path's edge SET (canonical
    // unordered endpoint pairs), so it is reversal-invariant; and appending
    // the shared final hop adds the very same edge — hence the same 0 or 1
    // — to both candidates' counts, so it is extension-consistent, keeping
    // the whole composite inside `comparePaths`'s correctness argument.
    const overlap = std.math.order(primaryOverlap(primary, a), primaryOverlap(primary, b));
    if (overlap != .eq) return overlap;
    // Equal overlap: fall back to the primary comparator, which supplies
    // strictness (.eq only for identical sequences) and totality.
    return comparePaths(a, b);
}

/// Is undirected edge `{x, y}` one of `primary`'s resolved tree edges
/// (`pred[child] == parent` in either orientation)?
fn isPrimaryTreeEdge(primary: *const Tree, x: NodeId, y: NodeId) bool {
    if (x < primary.pred.len) {
        if (primary.pred[x]) |p| if (p == y) return true;
    }
    if (y < primary.pred.len) {
        if (primary.pred[y]) |p| if (p == x) return true;
    }
    return false;
}

/// `|edges(p) ∩ E(primary)|` — the disjointness metric documented on
/// `comparePathsDisjoint`, counted over `p`'s consecutive-hop edges.
fn primaryOverlap(primary: *const Tree, p: Path) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i + 1 < p.len) : (i += 1) {
        if (isPrimaryTreeEdge(primary, p[i], p[i + 1])) n += 1;
    }
    return n;
}

// ── Dijkstra (done) ──────────────────────────────────────────────────────

const QueueItem = struct { node: NodeId, dist: Distance };

fn queueOrder(_: void, a: QueueItem, b: QueueItem) Order {
    return std.math.order(a.dist, b.dist);
}

const PQ = std.PriorityQueue(QueueItem, void, queueOrder);

/// Tie-break as an indirect call: `ctx` carries whatever state `compare`
/// needs (`comparePathsDisjoint` needs the primary tree; `comparePaths`
/// needs nothing). Internal — the public entry points below wire up the two
/// Fable-core comparators; callers never construct a `TieBreak` directly.
const TieBreak = struct {
    ctx: ?*anyopaque = null,
    compare: *const fn (ctx: ?*anyopaque, a: Path, b: Path) Order,
};

fn comparePathsAdapter(_: ?*anyopaque, a: Path, b: Path) Order {
    return comparePaths(a, b);
}

fn comparePathsDisjointAdapter(ctx: ?*anyopaque, a: Path, b: Path) Order {
    const primary: *const Tree = @ptrCast(@alignCast(ctx.?));
    return comparePathsDisjoint(primary, a, b);
}

/// Reconstruct `root .. via .. target` (via's own predecessor chain, plus
/// the final hop to `target`) into `alloc`-owned memory. Used only for
/// tie-break candidate construction — `Tree.pathTo` has its own simpler
/// direct version.
fn reconstructVia(alloc: Allocator, pred: []const ?NodeId, root: NodeId, via: NodeId, target: NodeId) Allocator.Error![]NodeId {
    var rev: std.ArrayList(NodeId) = .empty;
    defer rev.deinit(alloc);
    try rev.append(alloc, target);
    var cur = via;
    try rev.append(alloc, cur);
    while (cur != root) {
        cur = pred[cur].?;
        try rev.append(alloc, cur);
    }
    const path = try alloc.alloc(NodeId, rev.items.len);
    for (rev.items, 0..) |id, i| path[path.len - 1 - i] = id;
    return path;
}

/// Textbook single-source Dijkstra (lazy-deletion binary heap, O((V+E) log
/// V)), generalized over `tie_break` so both `shortestPathTree` (plain
/// `comparePaths`) and `disjointTrees`' second pass (`comparePathsDisjoint`,
/// needs the primary tree as context) share this one implementation.
///
/// Whenever relaxing edge `(u, v)` finds `dist[u] + w == dist[v]` (a
/// genuine cost tie, not an improvement), the two full candidate paths
/// `root..u..v` and `root..pred[v]..v` are reconstructed and handed to
/// `tie_break`; `.lt` for the new candidate adopts `u` as `v`'s
/// predecessor. See `comparePaths`'s doc comment for why a plain per-edge
/// local comparison here is enough to reduce to the correct GLOBAL
/// tie-break winner (transitivity of the total order).
fn dijkstraWithTieBreak(gpa: Allocator, graph: *const Graph, root: NodeId, tie_break: TieBreak) Allocator.Error!Tree {
    const n = graph.nodeCount();
    const dist = try gpa.alloc(Distance, n);
    errdefer gpa.free(dist);
    @memset(dist, unreachable_dist);
    const pred = try gpa.alloc(?NodeId, n);
    errdefer gpa.free(pred);
    @memset(pred, null);

    dist[root] = 0;

    var pq: PQ = .empty;
    defer pq.deinit(gpa);
    try pq.push(gpa, .{ .node = root, .dist = 0 });

    // Scratch arena for candidate-path reconstruction during tie-breaks;
    // reset after every comparison so it never grows past ~one path.
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();

    while (pq.pop()) |item| {
        if (item.dist != dist[item.node]) continue; // stale heap entry
        const u = item.node;
        for (graph.neighbors(u)) |e| {
            const nd = dist[u] + e.weight;
            if (nd < dist[e.to]) {
                dist[e.to] = nd;
                pred[e.to] = u;
                try pq.push(gpa, .{ .node = e.to, .dist = nd });
            } else if (nd == dist[e.to] and e.to != root and pred[e.to] != null) {
                _ = scratch.reset(.retain_capacity);
                const sa = scratch.allocator();
                const challenger = try reconstructVia(sa, pred, root, u, e.to);
                const incumbent = try reconstructVia(sa, pred, root, pred[e.to].?, e.to);
                if (tie_break.compare(tie_break.ctx, challenger, incumbent) == .lt) {
                    pred[e.to] = u;
                }
            }
        }
    }

    return .{ .gpa = gpa, .root = root, .dist = dist, .pred = pred };
}

// ── public entry points ──────────────────────────────────────────────────

/// Build the single-source shortest-path tree rooted at `root`, using
/// `comparePaths` to resolve cost ties. `graph` must have `root` as a valid
/// node (`root < graph.nodeCount()`).
pub fn shortestPathTree(gpa: Allocator, graph: *const Graph, root: NodeId) Allocator.Error!Tree {
    return dijkstraWithTieBreak(gpa, graph, root, .{ .compare = comparePathsAdapter });
}

/// `root..target` inclusive shortest path, deterministic per `comparePaths`.
/// Once `comparePaths` satisfies its documented contract,
/// `shortestPath(gpa, g, a, b)` is guaranteed equal to
/// `reverse(shortestPath(gpa, g, b, a))`.
pub fn shortestPath(gpa: Allocator, graph: *const Graph, a: NodeId, b: NodeId) (Allocator.Error || Tree.PathError)![]NodeId {
    var tree = try shortestPathTree(gpa, graph, a);
    defer tree.deinit();
    return tree.pathTo(gpa, b);
}

/// Two shortest-path trees rooted at `root`: `[0]` is the primary tree
/// (`comparePaths`), `[1]` is the overlap-minimizing secondary/backup tree
/// (`comparePathsDisjoint`, PRP mode — see its doc comment for what
/// guarantee this is and isn't). Both are caller-owned — `deinit`
/// each independently.
pub fn disjointTrees(gpa: Allocator, graph: *const Graph, root: NodeId) Allocator.Error![2]Tree {
    var primary = try shortestPathTree(gpa, graph, root);
    errdefer primary.deinit();
    const secondary = try dijkstraWithTieBreak(gpa, graph, root, .{
        .ctx = @ptrCast(&primary),
        .compare = comparePathsDisjointAdapter,
    });
    return .{ primary, secondary };
}

// ── tests: graph builder (no tie-break involved) ────────────────────────

const testing = std.testing;

test "graph builder: neighbors sorted, isolated nodes, self-loop/duplicate rejected" {
    var g = Graph.init(testing.allocator);
    defer g.deinit();

    try g.addEdge(2, 0, 5);
    try g.addEdge(2, 1, 3);
    try testing.expectEqual(@as(u32, 3), g.nodeCount());
    // Sorted by neighbor id regardless of insertion order.
    try testing.expectEqualSlices(Edge, &.{ .{ .to = 0, .weight = 5 }, .{ .to = 1, .weight = 3 } }, g.neighbors(2));
    try testing.expectEqualSlices(Edge, &.{.{ .to = 2, .weight = 5 }}, g.neighbors(0));

    try testing.expectError(error.SelfLoop, g.addEdge(1, 1, 1));
    try testing.expectError(error.DuplicateEdge, g.addEdge(2, 0, 9));
    // Rejected duplicate must not have mutated either side.
    try testing.expectEqualSlices(Edge, &.{ .{ .to = 0, .weight = 5 }, .{ .to = 1, .weight = 3 } }, g.neighbors(2));

    try g.ensureNode(5);
    try testing.expectEqual(@as(u32, 6), g.nodeCount());
    try testing.expectEqual(@as(usize, 0), g.neighbors(5).len);
    // Idempotent.
    try g.ensureNode(0);
    try testing.expectEqual(@as(u32, 6), g.nodeCount());
}

test "graph builder: addEdge rejects a 0-weight edge (predecessor-cycle DoS guard)" {
    var g = Graph.init(testing.allocator);
    defer g.deinit();
    // A 0-weight edge is what could give Dijkstra's ECT tie-break a
    // pred[u]==v / pred[v]==u 2-cycle, hanging Tree.pathTo forever.
    try testing.expectError(error.ZeroWeight, g.addEdge(0, 1, 0));
    // Rejected atomically: neither endpoint (nor any node) was created.
    try testing.expectEqual(@as(u32, 0), g.nodeCount());
    // A positive weight on the same pair still works.
    try g.addEdge(0, 1, 1);
    try testing.expectEqual(@as(u32, 2), g.nodeCount());
}

// ── tests: Dijkstra without ties (never touches the Fable stubs) ────────

test "smoke: unique-shortest-path graph, both directions, no stub touched" {
    // 0 --4-- 1 --3-- 2
    //  \-------9------/
    // Unique shortest path 0->2 is via 1 (cost 7 < 9); weights are distinct
    // enough that no relaxation ever ties, so comparePaths is never called.
    var g = Graph.init(testing.allocator);
    defer g.deinit();
    try g.addEdge(0, 1, 4);
    try g.addEdge(1, 2, 3);
    try g.addEdge(0, 2, 9);

    const fwd = try shortestPath(testing.allocator, &g, 0, 2);
    defer testing.allocator.free(fwd);
    try testing.expectEqualSlices(NodeId, &.{ 0, 1, 2 }, fwd);

    const bwd = try shortestPath(testing.allocator, &g, 2, 0);
    defer testing.allocator.free(bwd);
    try testing.expectEqualSlices(NodeId, &.{ 2, 1, 0 }, bwd);

    var tree = try shortestPathTree(testing.allocator, &g, 0);
    defer tree.deinit();
    try testing.expectEqual(@as(Distance, 0), tree.distanceTo(0));
    try testing.expectEqual(@as(Distance, 4), tree.distanceTo(1));
    try testing.expectEqual(@as(Distance, 7), tree.distanceTo(2));
}

test "dijkstra: distances and predecessors on a tie-free weighted graph" {
    // Classic 5-node graph, weights chosen to avoid any cost tie.
    //     (1)--2--(3)
    //    / |        \
    //  10  1          4
    //  /   |           \
    //(0)   |           (4)
    //  \   |           /
    //   3  |          6
    //    \ |         /
    //     (2)--------
    var g = Graph.init(testing.allocator);
    defer g.deinit();
    try g.addEdge(0, 1, 10);
    try g.addEdge(0, 2, 3);
    try g.addEdge(1, 2, 1);
    try g.addEdge(1, 3, 2);
    try g.addEdge(2, 4, 15);
    try g.addEdge(3, 4, 4);

    var tree = try shortestPathTree(testing.allocator, &g, 0);
    defer tree.deinit();
    try testing.expectEqual(@as(Distance, 0), tree.distanceTo(0));
    try testing.expectEqual(@as(Distance, 4), tree.distanceTo(1)); // 0->2->1 (3+1)
    try testing.expectEqual(@as(Distance, 3), tree.distanceTo(2)); // 0->2
    try testing.expectEqual(@as(Distance, 6), tree.distanceTo(3)); // 0->2->1->3
    try testing.expectEqual(@as(Distance, 10), tree.distanceTo(4)); // 0->2->1->3->4

    const path = try tree.pathTo(testing.allocator, 4);
    defer testing.allocator.free(path);
    try testing.expectEqualSlices(NodeId, &.{ 0, 2, 1, 3, 4 }, path);
}

test "dijkstra: unreachable node reports error.Unreachable" {
    var g = Graph.init(testing.allocator);
    defer g.deinit();
    try g.addEdge(0, 1, 1);
    try g.ensureNode(2); // isolated, no edges

    var tree = try shortestPathTree(testing.allocator, &g, 0);
    defer tree.deinit();
    try testing.expectEqual(unreachable_dist, tree.distanceTo(2));
    try testing.expect(!tree.reachable(2));
    try testing.expectError(error.Unreachable, tree.pathTo(testing.allocator, 2));
}

// ── property-test harness (calls the Fable-stubbed comparators) ─────────
//
// Everything below this line exercises `comparePaths`/`comparePathsDisjoint`
// and therefore PANICS with the stubs in place — that is expected. This
// harness is what proves a filled-in core correct: once the stubs are
// implemented, every test in this section must pass unmodified.

fn reversedAlloc(gpa: Allocator, path: Path) ![]NodeId {
    const out = try gpa.alloc(NodeId, path.len);
    for (path, 0..) |id, i| out[path.len - 1 - i] = id;
    return out;
}

/// Deterministic seeded random graph generator (fixed seed per call site —
/// tests must be reproducible). Small `weight_max` keeps ties frequent.
fn randomGraph(gpa: Allocator, seed: u64, n: u32, edge_pct: u8, weight_max: Weight) !Graph {
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();
    var g = Graph.init(gpa);
    errdefer g.deinit();
    if (n == 0) return g;
    try g.ensureNode(n - 1);
    var a: NodeId = 0;
    while (a < n) : (a += 1) {
        var b: NodeId = a + 1;
        while (b < n) : (b += 1) {
            if (rand.uintLessThan(u8, 100) < edge_pct) {
                const w = rand.intRangeAtMost(Weight, 1, weight_max);
                try g.addEdge(a, b, w);
            }
        }
    }
    return g;
}

test "property: symmetry — shortestPath(a,b) == reverse(shortestPath(b,a))" {
    const gpa = testing.allocator;
    var graph_idx: u32 = 0;
    while (graph_idx < 24) : (graph_idx += 1) {
        const n = 4 + (graph_idx % 12); // 4..15 nodes
        var g = try randomGraph(gpa, 0xC0FFEE_00 + graph_idx, n, 45, 4);
        defer g.deinit();

        var a: NodeId = 0;
        while (a < n) : (a += 1) {
            var b: NodeId = a + 1;
            while (b < n) : (b += 1) {
                const fwd = shortestPath(gpa, &g, a, b) catch |err| switch (err) {
                    error.Unreachable => continue,
                    else => return err,
                };
                defer gpa.free(fwd);
                const bwd = try shortestPath(gpa, &g, b, a);
                defer gpa.free(bwd);

                const bwd_reversed = try reversedAlloc(gpa, bwd);
                defer gpa.free(bwd_reversed);
                try testing.expectEqualSlices(NodeId, fwd, bwd_reversed);
            }
        }
    }
}

test "property: comparePaths is a strict total order (antisymmetric, transitive)" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x707A1_0DE5);
    const rand = prng.random();

    var buf: [3][8]NodeId = undefined;
    var i: u32 = 0;
    while (i < 200) : (i += 1) {
        for (&buf) |*p| {
            const len = 2 + rand.uintLessThan(usize, 6);
            for (p[0..len]) |*slot| slot.* = rand.uintLessThan(NodeId, 20);
        }
        const len0 = 2 + (i % 6);
        const p = buf[0][0..len0];
        const q = buf[1][0 .. 2 + ((i + 1) % 6)];
        const r = buf[2][0 .. 2 + ((i + 2) % 6)];

        // Identity: a path compares equal to an independent copy of itself.
        const p_copy = try gpa.dupe(NodeId, p);
        defer gpa.free(p_copy);
        try testing.expectEqual(Order.eq, comparePaths(p, p_copy));

        if (!std.mem.eql(NodeId, p, q)) {
            const pq = comparePaths(p, q);
            const qp = comparePaths(q, p);
            try testing.expect(pq != .eq);
            try testing.expectEqual(pq, if (qp == .lt) Order.gt else Order.lt);
        }

        // Transitivity, only when the sampled triple happens to form a chain.
        if (comparePaths(p, q) == .lt and comparePaths(q, r) == .lt) {
            try testing.expectEqual(Order.lt, comparePaths(p, r));
        }
    }
}

/// All simple `a..b` paths in `graph`, via exhaustive DFS — the brute-force
/// ground truth for the cross-check test. Only usable on small graphs
/// (node_count <= ~7): worst case is `O(n!)` candidate paths.
fn enumerateSimplePaths(gpa: Allocator, graph: *const Graph, a: NodeId, b: NodeId, out: *std.ArrayList([]NodeId)) !void {
    const visited = try gpa.alloc(bool, graph.nodeCount());
    defer gpa.free(visited);
    @memset(visited, false);
    var stack: std.ArrayList(NodeId) = .empty;
    defer stack.deinit(gpa);
    try dfsPaths(gpa, graph, a, b, visited, &stack, out);
}

fn dfsPaths(gpa: Allocator, graph: *const Graph, cur: NodeId, target: NodeId, visited: []bool, stack: *std.ArrayList(NodeId), out: *std.ArrayList([]NodeId)) !void {
    visited[cur] = true;
    try stack.append(gpa, cur);
    defer {
        _ = stack.pop();
        visited[cur] = false;
    }
    if (cur == target) {
        try out.append(gpa, try gpa.dupe(NodeId, stack.items));
        return;
    }
    for (graph.neighbors(cur)) |e| {
        if (!visited[e.to]) try dfsPaths(gpa, graph, e.to, target, visited, stack, out);
    }
}

fn pathCost(graph: *const Graph, path: Path) Distance {
    var total: Distance = 0;
    for (path[0 .. path.len - 1], path[1..]) |u, v| {
        for (graph.neighbors(u)) |e| {
            if (e.to == v) {
                total += e.weight;
                break;
            }
        }
    }
    return total;
}

test "property: brute-force cross-check on small (<=7 node) graphs" {
    const gpa = testing.allocator;
    var graph_idx: u32 = 0;
    while (graph_idx < 16) : (graph_idx += 1) {
        const n = 3 + (graph_idx % 5); // 3..7 nodes
        var g = try randomGraph(gpa, 0xB44CE_000 + graph_idx, n, 55, 3);
        defer g.deinit();

        var a: NodeId = 0;
        while (a < n) : (a += 1) {
            var b: NodeId = a + 1;
            while (b < n) : (b += 1) {
                var candidates: std.ArrayList([]NodeId) = .empty;
                defer {
                    for (candidates.items) |p| gpa.free(p);
                    candidates.deinit(gpa);
                }
                try enumerateSimplePaths(gpa, &g, a, b, &candidates);
                if (candidates.items.len == 0) continue; // unreachable pair

                var min_cost: Distance = unreachable_dist;
                for (candidates.items) |p| min_cost = @min(min_cost, pathCost(&g, p));

                const got = try shortestPath(gpa, &g, a, b);
                defer gpa.free(got);

                // Genuine shortest path (cost-optimal regardless of the
                // tie-break's specific choice among equal-cost candidates).
                try testing.expectEqual(min_cost, pathCost(&g, got));

                // Never beaten by a legitimate equal-cost alternative.
                for (candidates.items) |p| {
                    if (pathCost(&g, p) != min_cost) continue;
                    if (std.mem.eql(NodeId, got, p)) continue;
                    try testing.expect(comparePaths(got, p) != .gt);
                }

                // Symmetry, cross-checked on the same exhaustively-verified graph.
                const got_rev = try shortestPath(gpa, &g, b, a);
                defer gpa.free(got_rev);
                const got_rev_reversed = try reversedAlloc(gpa, got_rev);
                defer gpa.free(got_rev_reversed);
                try testing.expectEqualSlices(NodeId, got, got_rev_reversed);
            }
        }
    }
}

const TreeEdge = struct { lo: NodeId, hi: NodeId };

fn treeEdgeSet(gpa: Allocator, tree: *const Tree) ![]TreeEdge {
    var edges: std.ArrayList(TreeEdge) = .empty;
    errdefer edges.deinit(gpa);
    for (tree.pred, 0..) |p, v| {
        const pred = p orelse continue;
        const child: NodeId = @intCast(v);
        try edges.append(gpa, .{ .lo = @min(pred, child), .hi = @max(pred, child) });
    }
    const owned = try edges.toOwnedSlice(gpa);
    std.mem.sort(TreeEdge, owned, {}, struct {
        fn lessThan(_: void, a: TreeEdge, b: TreeEdge) bool {
            if (a.lo != b.lo) return a.lo < b.lo;
            return a.hi < b.hi;
        }
    }.lessThan);
    return owned;
}

fn overlapCount(a: []const TreeEdge, b: []const TreeEdge) usize {
    var i: usize = 0;
    var j: usize = 0;
    var n: usize = 0;
    while (i < a.len and j < b.len) {
        if (a[i].lo == b[j].lo and a[i].hi == b[j].hi) {
            n += 1;
            i += 1;
            j += 1;
        } else if (a[i].lo < b[j].lo or (a[i].lo == b[j].lo and a[i].hi < b[j].hi)) {
            i += 1;
        } else {
            j += 1;
        }
    }
    return n;
}

/// Two disjoint chains of `chain_len` fresh intermediate nodes between a
/// shared root (id 0) and a shared sink (last id) — guarantees a genuinely
/// link-disjoint equal-cost alternative exists, so `disjointTrees` has
/// something real to find.
fn parallelChainsGraph(gpa: Allocator, chains: u32, chain_len: u32) !Graph {
    var g = Graph.init(gpa);
    errdefer g.deinit();
    const root: NodeId = 0;
    var next_id: NodeId = 1;
    var c: u32 = 0;
    // Reserve the sink id up front so every chain (built after) connects to it.
    const sink: NodeId = 1 + chains * chain_len;
    try g.ensureNode(sink);
    while (c < chains) : (c += 1) {
        var prev = root;
        var step: u32 = 0;
        while (step < chain_len) : (step += 1) {
            const cur = next_id;
            next_id += 1;
            try g.addEdge(prev, cur, 1);
            prev = cur;
        }
        try g.addEdge(prev, sink, 1);
    }
    return g;
}

test "property: disjointTrees both trees are valid spanning structures" {
    const gpa = testing.allocator;
    var g = try parallelChainsGraph(gpa, 3, 2);
    defer g.deinit();
    const root: NodeId = 0;
    const n = g.nodeCount();

    var trees = try disjointTrees(gpa, &g, root);
    defer trees[0].deinit();
    defer trees[1].deinit();

    for (trees) |tree| {
        var v: NodeId = 0;
        while (v < n) : (v += 1) {
            if (!tree.reachable(v)) continue;
            // pred chain reaches root within node_count steps (acyclic).
            var cur = v;
            var steps: u32 = 0;
            while (cur != root) {
                cur = tree.pred[cur].?;
                steps += 1;
                try testing.expect(steps <= n);
            }
        }
    }
}

test "property: disjointness — secondary overlaps primary less than the trivial (same-comparator) baseline" {
    const gpa = testing.allocator;
    var g = try parallelChainsGraph(gpa, 3, 2);
    defer g.deinit();
    const root: NodeId = 0;

    var trees = try disjointTrees(gpa, &g, root);
    defer trees[0].deinit();
    defer trees[1].deinit();

    const primary_edges = try treeEdgeSet(gpa, &trees[0]);
    defer gpa.free(primary_edges);
    const secondary_edges = try treeEdgeSet(gpa, &trees[1]);
    defer gpa.free(secondary_edges);

    const overlap = overlapCount(primary_edges, secondary_edges);
    // Trivial baseline: reusing `comparePaths` (same deterministic input,
    // same comparator) reproduces `primary` exactly => 100% overlap.
    try testing.expectEqual(primary_edges.len, overlapCount(primary_edges, primary_edges));
    // The graph offers a fully link-disjoint 3rd chain, so a real
    // disjointness-aware tie-break must beat the trivial baseline.
    try testing.expect(overlap < primary_edges.len);
}
