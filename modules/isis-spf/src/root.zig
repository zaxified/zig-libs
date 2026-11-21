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
//! Scope: **point-to-point and LAN topology → SPF → next-hop table**. A LAN
//! pseudonode is transit only: members it lists and that list it back are
//! joined by arcs at each member's own metric.
//! Also, by `Options`: the overload bit's transit exclusion (default on), ECMP
//! next-hop sets (`max_paths`), IP/IPv6 prefix routes (`prefixes`, #135/#236),
//! the attached-bit default route, and (in `leak`) L1/L2 prefix leaking
//! planning. Incremental SPF is not done — see `SPEC.md`.

const std = @import("std");
const isis = @import("isis");
const lsdb = @import("isis-lsdb");
const spf = @import("spf-ect");

const Allocator = std.mem.Allocator;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Computes IS-IS shortest-path forwarding table from an `isis-lsdb` — TLVs → topology graph → Dijkstra + ECT tie-break → route table (dest → next-hop + metric); pure",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "ISO/IEC 10589 §7.2 decision process (SPF) + IEEE 802.1aq ECT",
    .deps = .{ "isis", "isis-lsdb", "spf-ect" },
};

/// A 6-octet IS-IS system-id — the node identity in the topology (the LSP-ID's
/// first six octets, and each 7-octet neighbour-id's first six).
pub const SystemId = [6]u8;

/// Multi-level route leaking between an L1 and an L2 computation.
pub const leak = @import("leak.zig");

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

/// An IP prefix a system advertises (#135 / #236). The address bytes past
/// `len` bits are zero; an IPv4 address sits in `addr[0..4]`.
pub const Prefix = struct {
    pub const Family = enum { ipv4, ipv6 };
    family: Family,
    addr: [16]u8,
    len: u8,

    /// Total order: family (IPv4 first), address bytes, length.
    pub fn order(a: Prefix, b: Prefix) std.math.Order {
        if (a.family != b.family) return std.math.order(@backingInt(a.family), @backingInt(b.family));
        const o = std.mem.order(u8, &a.addr, &b.addr);
        if (o != .eq) return o;
        return std.math.order(a.len, b.len);
    }
};

/// The selected route to one prefix. `metric` is the total: the distance to
/// the advertising system plus the metric it advertised (RFC 5305 §4:
/// "the metric of the prefix is added to the cost to reach the router").
pub const PrefixRoute = struct {
    prefix: Prefix,
    metric: u64,
    /// The first hop toward the advertising system; `origin == next_hop ==
    /// local` for a prefix the local system advertises itself. With
    /// `Options.max_paths > 1` this is the lowest of the equal-cost hops.
    next_hop: SystemId,
    /// The advertising system (the lowest system-id among equal candidates).
    origin: SystemId,
    /// The Up/Down bit of the selected advertisement (RFC 5302: the prefix
    /// was leaked from L2 into L1).
    up_down: bool = false,
    /// The IPv6 X bit of the selected advertisement.
    external: bool = false,
    /// Synthesised from an attached L1/L2 system (`Options.attached_default`),
    /// not advertised by anybody.
    attached_default: bool = false,
};

/// RFC 5305 §3: "If a link is advertised with the maximum link metric
/// (2^24 - 1), this link MUST NOT be considered during the normal SPF
/// computation. This will allow advertisement of a link for purposes other than
/// building the normal Shortest Path Tree." The mechanism a TE-only / MPLS-TE /
/// LFA-staging link uses to stay advertised (so its existence is still visible
/// to traffic engineering) while being excluded from ordinary shortest-path
/// routing.
///
/// ⚠ This comment used to quote the RFC as "A value of 'MaxLinkMetric' ... MUST
/// NOT be advertised", which the RFC does not say — it never uses the token
/// `MaxLinkMetric` at all — and which **inverts** the rule: the whole point is
/// that the link STAYS advertised, as the sentence right above already said.
/// `scripts/gen/check-citations.py` had been reporting the MISMATCH. Corrected.
///
/// RFC 5305 §3 also defines `MAX_PATH_METRIC` (0xFE000000), a ceiling on the
/// SUMMED cost along a path, which this module does NOT enforce.
///
/// ⚠ The reason recorded here for that deferral was false in both halves and is
/// restated. It claimed such a path is "not a fixture that can be driven RED at
/// a defensible size" — a 300-router line reaches 5,016,386,986, past the
/// ceiling by 754,974,122, in 22 ms (measured; the fixture is below). And the RFC's
/// own rationale for the ceiling is that "MAX_PATH_METRIC plus a single link
/// metric does not overflow ... 32 bits"; `Route.metric` here is a `u64`, so
/// that rationale does not bite and nothing overflows.
///
/// What is actually left is a CONFORMANCE difference, not a safety one: above
/// the ceiling an RFC-conformant peer treats all path costs as equal, while
/// this module keeps ordering them by their true sums — so an equal-cost
/// tie-break could be resolved differently at metrics above 2^32. Closing it
/// properly means clamping during relaxation, which lives in the sibling
/// `spf-ect`, not here; clamping only the REPORTED metric would hide the
/// divergence rather than remove it, which is worse than leaving it stated.
pub const max_link_metric: u32 = 0xFFFFFF;

/// Tuning for `computeWith`. The defaults are the correct/safe behaviour.
///
/// This struct deliberately does NOT expose a way to disable the ISO §7.2.8.2
/// two-way connectivity check — internal audit W2 `isis-spf` F6: that
/// knob used to be a public field here (`require_two_way: bool = true`),
/// reachable by any production caller with nothing stopping it from being
/// passed `false` by accident. The deliberately-WRONG two-way-disabled path
/// still exists, as `computeWithBrokenTwoWayForTesting` below, but that
/// function is NOT `pub` — it is unreachable from outside this file (and
/// therefore from every other module) by construction, not by convention.
pub const Options = struct {
    /// Equal-cost next hops to keep per destination (the `max_paths` of
    /// holo-isis). 1 (the default, and 0) is the single deterministic ECT
    /// path SPB needs. More: `RouteTable.nextHops` / `prefixNextHops` list every
    /// first hop on any shortest path, sorted by system-id and cut to this many,
    /// and `Route.next_hop` / `PrefixRoute.next_hop` is the lowest of them.
    max_paths: u8 = 1,
    /// ISO/IEC 10589 §7.2.8.1 / RFC 3787: an LSP (fragment 0) with the overload
    /// bit set marks its system as not to be used for transit, so the SPF
    /// does not relax arcs out of it; the system stays reachable as a
    /// destination, and the local system's own bit is ignored. FRR, holo-isis
    /// and goisis all honour it by default. `false` computes as before.
    honour_overload: bool = true,
    /// Also select IP prefix routes from #135/#236 into `RouteTable.prefixes`.
    prefixes: bool = false,
    /// The database is level 2: ignore the Up/Down bit (RFC 5302 §3.3 "RECOMMENDED
    /// that implementations ignore the up/down bit in L2 LSPs"). Default is
    /// level 1: a prefix with the bit clear is preferred to one with it set
    /// (RFC 5302 §3.1: L1 intra-area before L2->L1 inter-area).
    level2: bool = false,
    /// A level-1 system whose own LSP is not L1/L2 installs a default route
    /// (0.0.0.0/0, ::/0) to the nearest reachable system that sets the
    /// attached bit (ISO/IEC 10589 §7.2.9.2 / RFC 1195), if that system
    /// supports the family. Needs `prefixes`.
    attached_default: bool = false,
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

/// `computeWith` fails for three reasons only.
pub const Error = Allocator.Error || error{
    /// A link was advertised in both directions with **different** metrics,
    /// and `Options.reject_asymmetric` was set. The engine represents this
    /// fine; the caller asked to be told instead. See that option.
    AsymmetricMetric,
    /// The LSDB advertised more distinct system-ids than `spf.Graph.max_nodes`
    /// (2^20). Node ids here are assigned densely (`0..node_count`) from the
    /// sorted id set, so reaching this means the database itself holds over a
    /// million routers — far past any real IS-IS area, and reachable only by a
    /// flooded/forged LSDB. Surfaced rather than turned into a multi-gigabyte
    /// allocation.
    NodeIdTooLarge,
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
    /// IP prefix routes (`Options.prefixes`), sorted by family, address, length.
    prefixes: []PrefixRoute = &.{},
    /// Equal-cost hop sets (`Options.max_paths > 1`): `route_hops[i]` is the
    /// span of `hop_pool` for `routes[i]`, `prefix_hops[i]` for `prefixes[i]`;
    /// both empty when `max_paths <= 1`.
    route_hops: []HopSpan = &.{},
    prefix_hops: []HopSpan = &.{},
    hop_pool: []SystemId = &.{},

    pub fn deinit(self: *RouteTable) void {
        self.gpa.free(self.routes);
        self.gpa.free(self.prefixes);
        self.gpa.free(self.route_hops);
        self.gpa.free(self.prefix_hops);
        self.gpa.free(self.hop_pool);
        self.* = undefined;
    }

    /// Every equal-cost first hop toward `dest` (sorted by system-id, at most
    /// `Options.max_paths`), or `null` if unreachable. Without `max_paths > 1`
    /// it is the single `next_hop`. The slice lives as long as the table.
    pub fn nextHops(self: *const RouteTable, dest: SystemId) ?[]const SystemId {
        var lo: usize = 0;
        var hi: usize = self.routes.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            switch (std.mem.order(u8, &self.routes[mid].dest, &dest)) {
                .eq => {
                    if (self.route_hops.len == 0) return @as(*const [1]SystemId, @ptrCast(&self.routes[mid].next_hop));
                    const sp = self.route_hops[mid];
                    return self.hop_pool[sp.start..][0..sp.len];
                },
                .lt => lo = mid + 1,
                .gt => hi = mid,
            }
        }
        return null;
    }

    /// The route to the exact prefix, or `null`. O(log n).
    pub fn prefixRoute(self: *const RouteTable, prefix: Prefix) ?PrefixRoute {
        const i = self.prefixIndex(prefix) orelse return null;
        return self.prefixes[i];
    }

    /// Equal-cost first hops toward `prefix` (see `nextHops`).
    pub fn prefixNextHops(self: *const RouteTable, prefix: Prefix) ?[]const SystemId {
        const i = self.prefixIndex(prefix) orelse return null;
        if (self.prefix_hops.len == 0) return @as(*const [1]SystemId, @ptrCast(&self.prefixes[i].next_hop));
        const sp = self.prefix_hops[i];
        return self.hop_pool[sp.start..][0..sp.len];
    }

    fn prefixIndex(self: *const RouteTable, prefix: Prefix) ?usize {
        var lo: usize = 0;
        var hi: usize = self.prefixes.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            switch (self.prefixes[mid].prefix.order(prefix)) {
                .eq => return mid,
                .lt => lo = mid + 1,
                .gt => hi = mid,
            }
        }
        return null;
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
        // Reachable in principle (an LSDB with >2^20 system-ids), and folded
        // into OOM rather than widening this convenience wrapper's contract:
        // it IS the allocation refusal it stands for — `spf.Graph` declined to
        // materialise a node table it could not have completed. Callers that
        // want to tell the two apart call `computeWith`, whose error set names
        // it.
        error.NodeIdTooLarge => error.OutOfMemory,
    };
}

/// `compute` with explicit `Options`. Always runs with the correct ISO
/// §7.2.8.2 two-way connectivity check — see `Options` for why that is not a
/// choice this function offers.
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
    return computeInternal(gpa, db, local, now, .{
        .require_two_way = true,
        .reject_asymmetric = opts.reject_asymmetric,
        .max_paths = opts.max_paths,
        .honour_overload = opts.honour_overload,
        .prefixes = opts.prefixes,
        .level2 = opts.level2,
        .attached_default = opts.attached_default,
    });
}

/// The two-way-check-disabled path — deliberately WRONG (a one-way/stale
/// advertisement poisons the tree) — kept solely so a permanent test can
/// prove the two-way check in `computeInternal` is load-bearing (W2
/// `isis-spf` F6). NOT `pub`: unreachable outside this file, so no production
/// caller can pass `require_two_way = false` by accident the way the old
/// public `Options` field allowed.
fn computeWithBrokenTwoWayForTesting(
    gpa: Allocator,
    db: *const lsdb.Lsdb,
    local: SystemId,
    now: Time,
    reject_asymmetric: bool,
) Error!RouteTable {
    return computeInternal(gpa, db, local, now, .{ .require_two_way = false, .reject_asymmetric = reject_asymmetric });
}

const InternalOptions = struct {
    require_two_way: bool,
    reject_asymmetric: bool,
    max_paths: u8 = 1,
    honour_overload: bool = false,
    prefixes: bool = false,
    level2: bool = false,
    attached_default: bool = false,
};

fn computeInternal(
    gpa: Allocator,
    db: *const lsdb.Lsdb,
    local: SystemId,
    now: Time,
    opts: InternalOptions,
) Error!RouteTable {
    // ── 1. extract directed advertisements + the set of LSP origins ──────────
    // directed: (from ++ to) → best (minimum) advertised metric, from ⟶ to.
    var directed: std.AutoHashMapUnmanaged([12]u8, spf.Weight) = .empty;
    defer directed.deinit(gpa);
    // origins: every system-id that originated at least one (non-pseudonode) LSP.
    var origins: std.AutoHashMapUnmanaged(SystemId, void) = .empty;
    defer origins.deinit(gpa);
    // LAN transit (ISO 10589 §7.2 / Annex C, RFC 1195): a pseudonode is named
    // by 7 octets (the DIS system-id + circuit id). `pn_lists` holds
    // (pseudonode ++ member) for every IS a pseudonode LSP lists; `to_pn`
    // holds (member ++ pseudonode) → the member's own advertised metric
    // toward the pseudonode.
    var pn_lists: std.AutoHashMapUnmanaged([13]u8, void) = .empty;
    defer pn_lists.deinit(gpa);
    var to_pn: std.AutoHashMapUnmanaged([13]u8, spf.Weight) = .empty;
    defer to_pn.deinit(gpa);
    // Per-system facts of fragment 0 (the only fragment whose flags count,
    // ISO 10589 §9.8) and the prefixes advertised in any fragment.
    var overloaded: std.AutoHashMapUnmanaged(SystemId, void) = .empty;
    defer overloaded.deinit(gpa);
    var attached: std.AutoHashMapUnmanaged(SystemId, void) = .empty;
    defer attached.deinit(gpa);
    var families: std.AutoHashMapUnmanaged(SystemId, u2) = .empty; // bit 0 IPv4, bit 1 IPv6 (#129)
    defer families.deinit(gpa);
    var local_is_l1l2 = false;
    var cands: std.ArrayList(Candidate) = .empty;
    defer cands.deinit(gpa);

    var view_it = db.iterator(now);
    while (view_it.next()) |ev| {
        // Request placeholders carry no bytes; skip them.
        if (ev.is_request or ev.bytes.len == 0) continue;
        // ISO/IEC 10589 §7.3.17: an LSP whose Remaining Lifetime has reached
        // zero is excluded from the Decision Process. `ev.remaining_lifetime`
        // is already aged to `now` by `isis-lsdb`, which is the whole reason
        // `now` is threaded down here — and previously nothing read it.
        //
        // ⚠ The `bytes.len == 0` test above is NOT this check. `isis-lsdb`
        // drops an expired LSP's bytes inside `Lsdb.tick`, which is
        // caller-driven and wholly independent of `compute`: between two ticks,
        // or in any caller whose `now` runs ahead of its last tick, the entry is
        // still fully present. Measured on a two-router database inserted with
        // a lifetime of 5 and computed at `now = 1000`: the LSDB reported
        // `remaining_lifetime = 0` for both, with 40 bytes each, and SPF
        // returned 2 routes over them.
        //
        // That matters because Remaining Lifetime is the ONLY mechanism IS-IS
        // has for retiring an LSP whose originator can no longer speak — a purge
        // needs the originator or a neighbour to send one. Without this line a
        // one-shot injected LSP does not have to be maintained: it keeps
        // attracting traffic for as long as its entry sits in the database.
        if (ev.remaining_lifetime == 0 or ev.is_purge) continue;
        // A stored LSP is well-formed at the header/framing level, but decode
        // defensively anyway — a decode failure just skips this LSP.
        const lsp = isis.Lsp.decode(ev.bytes) catch continue;
        if (lsp.lsp_id[6] != 0) {
            // A pseudonode LSP: record which ISs it lists (their metric is 0 by
            // definition and not used). It is not an origin — a pseudonode is
            // never a route destination.
            try collectPseudonodeMembers(gpa, &pn_lists, lsp);
            continue;
        }
        const from: SystemId = lsp.lsp_id[0..6].*;
        try origins.put(gpa, from, {});
        if (lsp.lsp_id[7] == 0) {
            if (lsp.flags.overload) try overloaded.put(gpa, from, {});
            if (lsp.flags.attached & 1 != 0) try attached.put(gpa, from, {});
            if (std.mem.eql(u8, &from, &local) and lsp.flags.is_type == 3) local_is_l1l2 = true;
        }

        var tlv_it = lsp.tlvIterator();
        // A malformed TLV terminates this LSP's walk safely (no over-read); the
        // records parsed before it still count.
        while (tlv_it.next() catch break) |t| switch (t.code) {
            isis.tlvs.code.extended_is_reachability => {
                var eit = isis.tlvs.ExtIsReachIterator.init(t.value);
                while (eit.next() catch break) |e| {
                    // RFC 5305 §3 max-link-metric: this direction MUST NOT be
                    // considered during normal SPF. Excluded outright — not
                    // added as an edge at all — rather than admitted at its
                    // (very expensive) face value, so it cannot become the
                    // path of last resort when nothing else reaches the
                    // destination.
                    if (e.metric == max_link_metric) continue;
                    if (e.neighbour_id[6] != 0) {
                        try addToPseudonode(gpa, &to_pn, from, e.neighbour_id, e.metric);
                        continue;
                    }
                    try addDirected(gpa, &directed, from, e.neighbour_id[0..6].*, e.metric);
                }
            },
            isis.tlvs.code.is_neighbours_lsp => {
                var iit = isis.tlvs.IsReachIterator.init(t.value) catch continue;
                while (iit.next() catch break) |e| {
                    // Old-style default metric: the value is the low 6 bits; the
                    // high bits are I/E / supported flags.
                    if (e.neighbour_id[6] != 0) {
                        try addToPseudonode(gpa, &to_pn, from, e.neighbour_id, e.default_metric & 0x3f);
                        continue;
                    }
                    try addDirected(gpa, &directed, from, e.neighbour_id[0..6].*, e.default_metric & 0x3f);
                }
            },
            isis.tlvs.code.protocols_supported => {
                if (!opts.prefixes) continue;
                const gop = try families.getOrPut(gpa, from);
                if (!gop.found_existing) gop.value_ptr.* = 0;
                for (t.value) |n| {
                    if (n == isis.tlvs.nlpid_ipv4) gop.value_ptr.* |= 1;
                    if (n == isis.tlvs.nlpid_ipv6) gop.value_ptr.* |= 2;
                }
            },
            isis.tlvs.code.extended_ip_reachability => {
                if (!opts.prefixes) continue;
                var pit = isis.tlvs.ExtIpReachIterator.init(t.value);
                while (pit.next() catch break) |e| {
                    var addr: [16]u8 = @splat(0);
                    addr[0..4].* = e.prefix;
                    try cands.append(gpa, .{
                        .prefix = .{ .family = .ipv4, .addr = addr, .len = e.prefix_len },
                        .origin = from,
                        .metric = e.metric,
                        .up_down = e.up_down,
                    });
                }
            },
            isis.tlvs.code.ipv6_reachability => {
                if (!opts.prefixes) continue;
                var pit = isis.tlvs.Ipv6ReachIterator.init(t.value);
                while (pit.next() catch break) |e| {
                    try cands.append(gpa, .{
                        .prefix = .{ .family = .ipv6, .addr = e.prefix, .len = e.prefix_len },
                        .origin = from,
                        .metric = e.metric,
                        .up_down = e.up_down,
                        .external = e.external,
                    });
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

    // ── 2b. LAN transit through pseudonodes ─────────────────────────────────
    try addLanArcs(gpa, &arcs, &pn_lists, &to_pn, opts.require_two_way);

    // ── 2c. overload bit: no transit through an overloaded system ─────────────
    // Its arcs out are dropped (it stays a destination through the arcs in);
    // the local system's own bit does not apply to its own computation.
    if (opts.honour_overload and overloaded.count() != 0) {
        var drop: std.ArrayList([12]u8) = .empty;
        defer drop.deinit(gpa);
        var oit = arcs.iterator();
        while (oit.next()) |kv| {
            const f: SystemId = kv.key_ptr[0..6].*;
            if (overloaded.contains(f) and !std.mem.eql(u8, &f, &local)) try drop.append(gpa, kv.key_ptr.*);
        }
        for (drop.items) |k| _ = arcs.remove(k);
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
            // Cannot fire here — `ensureNode(node_count - 1)` above already
            // admitted the whole id range — but propagated rather than
            // asserted: `unreachable` is undefined behaviour in ReleaseFast,
            // and this arm costs nothing.
            error.NodeIdTooLarge => return error.NodeIdTooLarge,
        };
    }

    const local_node = id_to_node.get(local).?;
    var tree = try spf.shortestPathTree(gpa, &graph, local_node);
    defer tree.deinit();

    // ── 5. first hops per reachable node ─────────────────────────────────────
    // `hops` holds, per node, the first hops of its shortest paths: the single
    // ECT choice by default, every equal-cost one (sorted, cut to `max_paths`)
    // with `Options.max_paths > 1`. NodeIds ascend with system-id, so sorting
    // NodeIds sorts by system-id.
    const max_paths: usize = @max(1, opts.max_paths);
    const ecmp = max_paths > 1;
    const spans = try gpa.alloc(HopSpan, node_count);
    defer gpa.free(spans);
    @memset(spans, .{ .start = 0, .len = 0 });
    var hops: std.ArrayList(spf.NodeId) = .empty;
    defer hops.deinit(gpa);
    if (!ecmp) {
        var node: spf.NodeId = 0;
        while (node < node_count) : (node += 1) {
            if (!tree.reachable(node)) continue;
            const nh = if (node == local_node) local_node else firstHop(&tree, local_node, node);
            spans[node] = .{ .start = @intCast(hops.items.len), .len = 1 };
            try hops.append(gpa, nh);
        }
    } else {
        try ecmpHops(gpa, &arcs, &id_to_node, &tree, local_node, node_count, max_paths, spans, &hops);
    }

    // ── 6. route table: first-hop + total metric per reachable destination ───
    // Node ids are in ascending system-id order, so iterating them yields
    // routes already sorted by destination.
    var routes: std.ArrayList(Route) = .empty;
    errdefer routes.deinit(gpa);
    var pool: std.ArrayList(SystemId) = .empty;
    errdefer pool.deinit(gpa);
    var route_hops: std.ArrayList(HopSpan) = .empty;
    errdefer route_hops.deinit(gpa);
    var node: spf.NodeId = 0;
    while (node < node_count) : (node += 1) {
        if (!tree.reachable(node)) continue;
        const sp = spans[node];
        try routes.append(gpa, .{
            .dest = node_to_id[node],
            .next_hop = node_to_id[hops.items[sp.start]],
            .metric = tree.distanceTo(node),
        });
        if (ecmp) {
            try route_hops.append(gpa, .{ .start = @intCast(pool.items.len), .len = sp.len });
            for (hops.items[sp.start..][0..sp.len]) |h| try pool.append(gpa, node_to_id[h]);
        }
    }

    // ── 7. IP prefix routes ─────────────────────────────────────────────────
    var prefix_routes: std.ArrayList(PrefixRoute) = .empty;
    errdefer prefix_routes.deinit(gpa);
    var prefix_hops: std.ArrayList(HopSpan) = .empty;
    errdefer prefix_hops.deinit(gpa);
    if (opts.prefixes) {
        if (opts.attached_default and !local_is_l1l2) {
            try addAttachedDefaults(gpa, &cands, &attached, &families, local);
        }
        try selectPrefixes(gpa, cands.items, &id_to_node, &tree, local_node, spans, hops.items, node_to_id, opts, ecmp, max_paths, &prefix_routes, &prefix_hops, &pool);
    }

    return .{
        .gpa = gpa,
        .routes = try routes.toOwnedSlice(gpa),
        .asymmetric_links = asymmetric_links,
        .prefixes = try prefix_routes.toOwnedSlice(gpa),
        .route_hops = try route_hops.toOwnedSlice(gpa),
        .prefix_hops = try prefix_hops.toOwnedSlice(gpa),
        .hop_pool = try pool.toOwnedSlice(gpa),
    };
}

/// A span of `RouteTable.hop_pool`.
pub const HopSpan = struct { start: u32, len: u32 };

/// One advertised prefix, before selection.
const Candidate = struct {
    prefix: Prefix,
    origin: SystemId,
    metric: u32,
    up_down: bool = false,
    external: bool = false,
    attached_default: bool = false,
};

/// 0.0.0.0/0 and ::/0 toward every attached system that supports the family,
/// ranked below any advertised prefix by `selectPrefixes`.
fn addAttachedDefaults(
    gpa: Allocator,
    cands: *std.ArrayList(Candidate),
    attached: *const std.AutoHashMapUnmanaged(SystemId, void),
    families: *const std.AutoHashMapUnmanaged(SystemId, u2),
    local: SystemId,
) Allocator.Error!void {
    var it = attached.iterator();
    while (it.next()) |kv| {
        const sys = kv.key_ptr.*;
        if (std.mem.eql(u8, &sys, &local)) continue;
        const fam = families.get(sys) orelse 0;
        if (fam & 1 != 0) try cands.append(gpa, .{ .prefix = .{ .family = .ipv4, .addr = @splat(0), .len = 0 }, .origin = sys, .metric = 0, .attached_default = true });
        if (fam & 2 != 0) try cands.append(gpa, .{ .prefix = .{ .family = .ipv6, .addr = @splat(0), .len = 0 }, .origin = sys, .metric = 0, .attached_default = true });
    }
}

/// Equal-cost first hops for every reachable node (`Options.max_paths > 1`).
/// A first hop of `d` is every first hop of a predecessor `p` of `d` with
/// `dist(p) + w(p, d) == dist(d)` (for `p == root`, `d` itself). Nodes are
/// processed in ascending distance; weights are >= 1, so predecessors come
/// first.
fn ecmpHops(
    gpa: Allocator,
    arcs: *const std.AutoHashMapUnmanaged([12]u8, spf.Weight),
    id_to_node: *const std.AutoHashMapUnmanaged(SystemId, spf.NodeId),
    tree: *const spf.Tree,
    root: spf.NodeId,
    node_count: u32,
    max_paths: usize,
    spans: []HopSpan,
    hops: *std.ArrayList(spf.NodeId),
) Allocator.Error!void {
    const Pred = struct { from: spf.NodeId, to: spf.NodeId };
    var preds: std.ArrayList(Pred) = .empty;
    defer preds.deinit(gpa);
    var ait = arcs.iterator();
    while (ait.next()) |kv| {
        const a = id_to_node.get(kv.key_ptr[0..6].*).?;
        const b = id_to_node.get(kv.key_ptr[6..12].*).?;
        if (!tree.reachable(a) or !tree.reachable(b)) continue;
        if (tree.distanceTo(a) + kv.value_ptr.* == tree.distanceTo(b)) try preds.append(gpa, .{ .from = a, .to = b });
    }
    // Group by destination, then by node id (determinism).
    std.mem.sort(Pred, preds.items, {}, struct {
        fn lt(_: void, x: Pred, y: Pred) bool {
            if (x.to != y.to) return x.to < y.to;
            return x.from < y.from;
        }
    }.lt);
    const order = try gpa.alloc(spf.NodeId, node_count);
    defer gpa.free(order);
    var n_order: usize = 0;
    var nd: spf.NodeId = 0;
    while (nd < node_count) : (nd += 1) {
        if (tree.reachable(nd)) {
            order[n_order] = nd;
            n_order += 1;
        }
    }
    std.mem.sort(spf.NodeId, order[0..n_order], tree, struct {
        fn lt(t: *const spf.Tree, x: spf.NodeId, y: spf.NodeId) bool {
            const dx = t.distanceTo(x);
            const dy = t.distanceTo(y);
            if (dx != dy) return dx < dy;
            return x < y;
        }
    }.lt);
    var tmp: std.ArrayList(spf.NodeId) = .empty;
    defer tmp.deinit(gpa);
    // preds are sorted by `to`; walk them with a cursor per node in order of
    // ascending distance via binary search of the group start.
    for (order[0..n_order]) |node| {
        if (node == root) {
            spans[node] = .{ .start = @intCast(hops.items.len), .len = 1 };
            try hops.append(gpa, root);
            continue;
        }
        tmp.clearRetainingCapacity();
        // First pred with `to >= node`.
        var lo: usize = 0;
        var hi: usize = preds.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (preds.items[mid].to < node) lo = mid + 1 else hi = mid;
        }
        var i = lo;
        while (i < preds.items.len and preds.items[i].to == node) : (i += 1) {
            const p = preds.items[i].from;
            if (p == root) {
                try tmp.append(gpa, node);
            } else {
                const sp = spans[p];
                try tmp.appendSlice(gpa, hops.items[sp.start..][0..sp.len]);
            }
        }
        std.mem.sort(spf.NodeId, tmp.items, {}, std.sort.asc(spf.NodeId));
        var n: usize = 0;
        for (tmp.items, 0..) |h, k| {
            if (k != 0 and h == tmp.items[n - 1]) continue;
            tmp.items[n] = h;
            n += 1;
        }
        n = @min(n, max_paths);
        spans[node] = .{ .start = @intCast(hops.items.len), .len = @intCast(n) };
        try hops.appendSlice(gpa, tmp.items[0..n]);
    }
}

/// Best advertisement per prefix. Rank, first difference wins: a real
/// advertisement before an attached-bit default; Up/Down clear before set
/// (level 1 only, RFC 5302 §3.1/§3.3); internal before external; the lower
/// total metric (distance to the advertiser + advertised metric); then the
/// lower advertiser id. With ECMP every candidate equal in all but the
/// advertiser contributes its first hops.
fn selectPrefixes(
    gpa: Allocator,
    cands: []const Candidate,
    id_to_node: *const std.AutoHashMapUnmanaged(SystemId, spf.NodeId),
    tree: *const spf.Tree,
    local_node: spf.NodeId,
    spans: []const HopSpan,
    hops: []const spf.NodeId,
    node_to_id: []const SystemId,
    opts: InternalOptions,
    ecmp: bool,
    max_paths: usize,
    out: *std.ArrayList(PrefixRoute),
    out_hops: *std.ArrayList(HopSpan),
    pool: *std.ArrayList(SystemId),
) Allocator.Error!void {
    _ = local_node;
    const Ranked = struct {
        c: Candidate,
        node: spf.NodeId,
        total: u64,
        ud: bool,
    };
    var ranked: std.ArrayList(Ranked) = .empty;
    defer ranked.deinit(gpa);
    for (cands) |c| {
        const node = id_to_node.get(c.origin) orelse continue;
        if (!tree.reachable(node)) continue;
        try ranked.append(gpa, .{
            .c = c,
            .node = node,
            .total = tree.distanceTo(node) + c.metric,
            .ud = c.up_down and !opts.level2,
        });
    }
    const Ctx = struct {
        fn lt(_: void, x: Ranked, y: Ranked) bool {
            const po = x.c.prefix.order(y.c.prefix);
            if (po != .eq) return po == .lt;
            if (x.c.attached_default != y.c.attached_default) return !x.c.attached_default;
            if (x.ud != y.ud) return !x.ud;
            if (x.c.external != y.c.external) return !x.c.external;
            if (x.total != y.total) return x.total < y.total;
            return x.node < y.node;
        }
        fn sameRank(x: Ranked, y: Ranked) bool {
            return x.c.prefix.order(y.c.prefix) == .eq and x.c.attached_default == y.c.attached_default and
                x.ud == y.ud and x.c.external == y.c.external and x.total == y.total;
        }
    };
    std.mem.sort(Ranked, ranked.items, {}, Ctx.lt);
    var tmp: std.ArrayList(spf.NodeId) = .empty;
    defer tmp.deinit(gpa);
    var i: usize = 0;
    while (i < ranked.items.len) {
        const best = ranked.items[i];
        var j = i + 1;
        while (j < ranked.items.len and ranked.items[j].c.prefix.order(best.c.prefix) == .eq) : (j += 1) {}
        const sp = spans[best.node];
        try out.append(gpa, .{
            .prefix = best.c.prefix,
            .metric = best.total,
            .next_hop = node_to_id[hops[sp.start]],
            .origin = node_to_id[best.node],
            .up_down = best.c.up_down,
            .external = best.c.external,
            .attached_default = best.c.attached_default,
        });
        if (ecmp) {
            tmp.clearRetainingCapacity();
            var k = i;
            while (k < j and Ctx.sameRank(ranked.items[k], best)) : (k += 1) {
                const ks = spans[ranked.items[k].node];
                try tmp.appendSlice(gpa, hops[ks.start..][0..ks.len]);
            }
            std.mem.sort(spf.NodeId, tmp.items, {}, std.sort.asc(spf.NodeId));
            var n: usize = 0;
            for (tmp.items, 0..) |h, q| {
                if (q != 0 and h == tmp.items[n - 1]) continue;
                tmp.items[n] = h;
                n += 1;
            }
            n = @min(n, max_paths);
            try out_hops.append(gpa, .{ .start = @intCast(pool.items.len), .len = @intCast(n) });
            for (tmp.items[0..n]) |h| try pool.append(gpa, node_to_id[h]);
            out.items[out.items.len - 1].next_hop = node_to_id[tmp.items[0]];
        }
        i = j;
    }
}

/// Record a directed advertisement `from ⟶ to`, keeping the minimum metric if
/// the same ordered pair is advertised more than once (e.g. via both #2 and #22,
/// or across LSP fragments). A self-advertisement (`from == to`) is ignored.
/// The metric is clamped to `>= 1`: `spf-ect` rejects a zero weight (it could
/// otherwise form a predecessor cycle), and a genuinely 0-cost IS-IS link is
/// treated as cost 1.
/// Record `from`'s advertisement of pseudonode `pn` at `raw_metric`
/// (clamped to ≥ 1 like every arc weight; the minimum wins).
fn addToPseudonode(
    gpa: Allocator,
    to_pn: *std.AutoHashMapUnmanaged([13]u8, spf.Weight),
    from: SystemId,
    pn: [7]u8,
    raw_metric: anytype,
) Allocator.Error!void {
    const weight: spf.Weight = @max(@as(spf.Weight, 1), @as(spf.Weight, raw_metric));
    var key: [13]u8 = undefined;
    key[0..6].* = from;
    key[6..13].* = pn;
    const gop = try to_pn.getOrPut(gpa, key);
    if (!gop.found_existing or weight < gop.value_ptr.*) gop.value_ptr.* = weight;
}

/// Every IS (neighbour-id octet 6 = 0) a pseudonode LSP lists, keyed
/// (pseudonode ++ member). All fragments of one pseudonode land in the same
/// set. Metrics from a pseudonode are 0 by definition and are not read.
fn collectPseudonodeMembers(
    gpa: Allocator,
    pn_lists: *std.AutoHashMapUnmanaged([13]u8, void),
    lsp: isis.Lsp,
) Allocator.Error!void {
    const pn: [7]u8 = lsp.lsp_id[0..7].*;
    var tlv_it = lsp.tlvIterator();
    while (tlv_it.next() catch return) |t| switch (t.code) {
        isis.tlvs.code.extended_is_reachability => {
            var eit = isis.tlvs.ExtIsReachIterator.init(t.value);
            while (eit.next() catch break) |e| {
                if (e.neighbour_id[6] != 0) continue;
                try pn_lists.put(gpa, pnKey(pn, e.neighbour_id[0..6].*), {});
            }
        },
        isis.tlvs.code.is_neighbours_lsp => {
            var iit = isis.tlvs.IsReachIterator.init(t.value) catch continue;
            while (iit.next() catch break) |e| {
                if (e.neighbour_id[6] != 0) continue;
                try pn_lists.put(gpa, pnKey(pn, e.neighbour_id[0..6].*), {});
            }
        },
        else => {},
    };
}

fn pnKey(pn: [7]u8, member: SystemId) [13]u8 {
    var key: [13]u8 = undefined;
    key[0..7].* = pn;
    key[7..13].* = member;
    return key;
}

/// A LAN as SPF sees it (ISO 10589 Annex C / RFC 1195): member X reaches the
/// pseudonode P at X's own advertised metric, and P reaches every member at
/// cost 0. The zero-cost second half is folded in here: for every pair of
/// ADMITTED members X ≠ Y of P, an arc X ⟶ Y at metric(X ⟶ P) — the same
/// distances without a zero-weight arc (which `spf-ect` rejects) and without
/// a pseudonode vertex that could be mistaken for a destination. A member is
/// admitted only when the two-way check passes on the LAN too: X lists P and
/// P's LSP lists X (§7.2.8.2's rule, with the pseudonode speaking for the
/// LAN). Where a point-to-point arc X ⟶ Y exists as well, the cheaper wins.
/// With `require_two_way = false` (the broken positive control only) a member
/// that lists P is admitted without P's confirmation.
fn addLanArcs(
    gpa: Allocator,
    arcs: *std.AutoHashMapUnmanaged([12]u8, spf.Weight),
    pn_lists: *const std.AutoHashMapUnmanaged([13]u8, void),
    to_pn: *const std.AutoHashMapUnmanaged([13]u8, spf.Weight),
    require_two_way: bool,
) Allocator.Error!void {
    const Admitted = struct { member: SystemId, pn: [7]u8, metric: spf.Weight };
    var admitted: std.ArrayList(Admitted) = .empty;
    defer admitted.deinit(gpa);
    var it = to_pn.iterator();
    while (it.next()) |kv| {
        const member: SystemId = kv.key_ptr[0..6].*;
        const pn: [7]u8 = kv.key_ptr[6..13].*;
        if (require_two_way and !pn_lists.contains(pnKey(pn, member))) continue;
        try admitted.append(gpa, .{ .member = member, .pn = pn, .metric = kv.value_ptr.* });
    }
    for (admitted.items) |x| for (admitted.items) |y| {
        if (!std.mem.eql(u8, &x.pn, &y.pn) or std.mem.eql(u8, &x.member, &y.member)) continue;
        var key: [12]u8 = undefined;
        key[0..6].* = x.member;
        key[6..12].* = y.member;
        const gop = try arcs.getOrPut(gpa, key);
        if (!gop.found_existing or x.metric < gop.value_ptr.*) gop.value_ptr.* = x.metric;
    };
}

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

/// Like `insertReachLsp`, but with a caller-chosen Remaining Lifetime, so a
/// fixture can age an LSP past its own expiry.
fn insertReachLspLifetime(
    db: *lsdb.Lsdb,
    origin: SystemId,
    seq: u32,
    lifetime: u16,
    reach: []const struct { nbr: SystemId, metric: u24 },
) !void {
    var buf: [512]u8 = undefined;
    var b = try isis.pdu.LspBuilder.init(&buf, .{
        .remaining_lifetime = lifetime,
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
        var table = try computeWith(testing.allocator, &db, a, 0, .{});
        defer table.deinit();
        try testing.expect(table.lookup(b) == null);
    }
    // Deliberately-broken control: the one-way edge is admitted, so B routes —
    // proving the two-way check is exactly what excludes it above.
    {
        var table = try computeWithBrokenTwoWayForTesting(testing.allocator, &db, a, 0, false);
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

test "old-style #2 default metric: the I/E bit is masked off, not folded into the value (ISO 10589 §9.8)" {
    // The octet's high bit is the I/E (internal/external) flag; only the low
    // 6 bits are the metric value. An LSP advertising an EXTERNAL default
    // metric of 7 (I/E=1) is encoded as 0x87 = 0b1000_0111. Reading the whole
    // byte instead of masking would extract 135, a 19x error.
    const a = sysId(0xA);
    const b = sysId(0xB);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();

    inline for (.{ .{ a, b }, .{ b, a } }) |pair| {
        var buf: [128]u8 = undefined;
        var lb = try isis.pdu.LspBuilder.init(&buf, .{
            .remaining_lifetime = 1000,
            .lsp_id = .{ pair[0][0], pair[0][1], pair[0][2], pair[0][3], pair[0][4], pair[0][5], 0, 0 },
            .sequence_number = 1,
            .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
        });
        const nbr = pair[1];
        const val = [_]u8{0} // virtual flag
            ++ [_]u8{ 0x87, 0x80, 0x80, 0x80 } // I/E=1, value=7 (others "not supported")
            ++ [_]u8{ nbr[0], nbr[1], nbr[2], nbr[3], nbr[4], nbr[5], 0 };
        try lb.tlvs.addTlv(isis.tlvs.code.is_neighbours_lsp, &val);
        _ = try db.insert(lb.finish(), null, 0);
    }

    var table = try compute(testing.allocator, &db, a, 0);
    defer table.deinit();
    try testing.expectEqual(Route{ .dest = b, .next_hop = b, .metric = 7 }, table.lookup(b).?);
}

// ── LAN transit through a pseudonode ─────────────────────────────────────────
//
// A LAN's designated IS (DIS) originates a pseudonode LSP whose LSP-ID has a
// non-zero pseudonode octet (octet 6), and every router on the LAN — the DIS's
// own real LSP included — advertises reachability to that pseudonode id, not to
// each other (ISO 10589 §7.2.5 / RFC 1195). `addLanArcs` turns that into arcs
// between the admitted members. Until this module dropped every
// pseudonode entry (LAN transit was deferred); these fixtures pinned the drop
// and now pin the transit.
//
// What the first fixture discriminates: the classic wrong reading maps the
// pseudonode id onto its DIS (the first six octets), which makes X and Y
// neighbours of D but never of each other. Y's route (via the LAN, next hop
// Y itself, cost 5) exists only with real pseudonode transit.
test "LAN transit (#22 extended): members reach each other through the pseudonode at their own metric" {
    const d = sysId(0x50); // the LAN's DIS; owns the pseudonode
    const x = sysId(0x10); // LAN member; also has a pricier P2P link to D
    const y = sysId(0x90); // LAN-only member

    const pn_d: [7]u8 = .{ d[0], d[1], d[2], d[3], d[4], d[5], 0x01 }; // D's pseudonode neighbour id
    const d7: [7]u8 = .{ d[0], d[1], d[2], d[3], d[4], d[5], 0 };
    const x7: [7]u8 = .{ x[0], x[1], x[2], x[3], x[4], x[5], 0 };

    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(x));
    defer db.deinit();

    // The pseudonode's own LSP (LSP-ID octet 6 = 0x01): lists every attached
    // router at cost 0, per ISO 10589.
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

    // X: the LAN (cost 5) AND an independent P2P adjacency to D (cost 100).
    try insertReachLspRaw(&db, x, 1, &.{
        .{ .nbr7 = pn_d, .metric = 5 },
        .{ .nbr7 = d7, .metric = 100 },
    });
    try insertReachLspRaw(&db, d, 1, &.{
        .{ .nbr7 = pn_d, .metric = 5 },
        .{ .nbr7 = x7, .metric = 100 },
    });
    try insertReachLspRaw(&db, y, 1, &.{
        .{ .nbr7 = pn_d, .metric = 5 },
    });

    var table = try compute(testing.allocator, &db, x, 0);
    defer table.deinit();

    // The LAN is the cheaper path to D (5 < 100) and the only one to Y; the
    // pseudonode itself is never a destination.
    try testing.expectEqual(@as(usize, 3), table.routes.len);
    try testing.expectEqual(Route{ .dest = x, .next_hop = x, .metric = 0 }, table.lookup(x).?);
    try testing.expectEqual(Route{ .dest = d, .next_hop = d, .metric = 5 }, table.lookup(d).?);
    try testing.expectEqual(Route{ .dest = y, .next_hop = y, .metric = 5 }, table.lookup(y).?);
}

// Without the pseudonode's own LSP the LAN fails the two-way check (nobody
// speaks for the LAN), so it contributes nothing and the real P2P metric
// stands — the same guard the old "neighbour filter" test pinned, now for the
// right reason.
test "LAN (#2 old-style) without a pseudonode LSP: not admitted, the real P2P metric stands" {
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
// ⚠ The fixture below was rewritten. Its predecessor justified
// itself by a mechanism the directed rewrite (`6634cbb7`) DELETED: it argued
// that `computeWith` "picks its canonical undirected weight from the
// advertisement running from the lexicographically-LOWER system-id to the
// higher one (`lo_hi`)", and therefore that making the DIS the lower id put the
// corrupted advertisement on the canonical side. There is no canonical
// per-link weight any more — each direction is its own arc at its own metric —
// so the fake arc the pseudonode LSP injects (`d→x`) simply was not on the
// root's (x's) path to d, and the assertion held with the filter deleted.
// Measured: the whole 28-test suite stayed GREEN with `lsp.lsp_id[6] != 0`
// removed.
//
// What discriminates under the directed engine is putting the corrupted arc ON
// the root's own path: a third router behind the DIS, so that x→z necessarily
// traverses d→z, which is exactly the advertisement the pseudonode LSP forges.
test "pseudonode ORIGIN filter: the pseudonode's own LSP must not itself supply a route" {
    const x = sysId(0x50); // the root
    const d = sysId(0x10); // the LAN's DIS
    const z = sysId(0x60); // a router BEHIND the DIS — this is what makes it bite

    const pn_d: [7]u8 = .{ d[0], d[1], d[2], d[3], d[4], d[5], 0x01 }; // D's pseudonode id
    const d7: [7]u8 = .{ d[0], d[1], d[2], d[3], d[4], d[5], 0 };
    const x7: [7]u8 = .{ x[0], x[1], x[2], x[3], x[4], x[5], 0 };
    const z7: [7]u8 = .{ z[0], z[1], z[2], z[3], z[4], z[5], 0 };

    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(x));
    defer db.deinit();

    // The pseudonode's own LSP (LSP-ID octet 6 = 0x01): per ISO 10589 it lists
    // every attached router at cost 0. With the origin filter disabled this LSP
    // is walked as though D had originated it, injecting fake D→X and D→Z
    // advertisements at the clamped-minimum cost of 1 — and D→Z lies on the
    // root's path to Z, so the min-merge in `addDirected` overwrites the real,
    // expensive metric.
    {
        var buf: [256]u8 = undefined;
        var lb = try isis.pdu.LspBuilder.init(&buf, .{
            .remaining_lifetime = 1000,
            .lsp_id = .{ d[0], d[1], d[2], d[3], d[4], d[5], 0x01, 0 },
            .sequence_number = 1,
            .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
        });
        try isis.tlvs.addExtendedIsReach(&lb.tlvs, x7, 0, &.{});
        try isis.tlvs.addExtendedIsReach(&lb.tlvs, z7, 0, &.{});
        _ = try db.insert(lb.finish(), null, 0);
    }

    // The genuine, expensive P2P adjacencies: X—D 100 and D—Z 100, both ways.
    try insertReachLspRaw(&db, d, 1, &.{
        .{ .nbr7 = pn_d, .metric = 5 }, // dropped by the neighbour-side filter regardless
        .{ .nbr7 = x7, .metric = 100 },
        .{ .nbr7 = z7, .metric = 100 },
    });
    try insertReachLspRaw(&db, x, 1, &.{
        .{ .nbr7 = pn_d, .metric = 5 },
        .{ .nbr7 = d7, .metric = 100 },
    });
    try insertReachLspRaw(&db, z, 1, &.{
        .{ .nbr7 = d7, .metric = 100 },
    });

    var table = try compute(testing.allocator, &db, x, 0);
    defer table.deinit();

    // Correct (origin filter present): the pseudonode LSP contributes nothing,
    // so Z costs the two real hops. With the filter deleted this reads 101 —
    // a silently WRONG metric, not a missing route, which is the shape that
    // makes it worth a test at all.
    try testing.expectEqual(@as(usize, 3), table.routes.len);
    try testing.expectEqual(Route{ .dest = d, .next_hop = d, .metric = 100 }, table.lookup(d).?);
    try testing.expectEqual(Route{ .dest = z, .next_hop = d, .metric = 200 }, table.lookup(z).?);
}

/// A pseudonode LSP for `dis`/circuit 1 listing `members`.
fn insertPseudonodeLsp(db: *lsdb.Lsdb, dis: SystemId, members: []const SystemId) !void {
    var buf: [512]u8 = undefined;
    var lb = try isis.pdu.LspBuilder.init(&buf, .{
        .remaining_lifetime = 1000,
        .lsp_id = .{ dis[0], dis[1], dis[2], dis[3], dis[4], dis[5], 0x01, 0 },
        .sequence_number = 1,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    });
    for (members) |m| try isis.tlvs.addExtendedIsReach(&lb.tlvs, .{ m[0], m[1], m[2], m[3], m[4], m[5], 0 }, 0, &.{});
    _ = try db.insert(lb.finish(), null, 0);
}

fn pnOf(dis: SystemId) [7]u8 {
    return .{ dis[0], dis[1], dis[2], dis[3], dis[4], dis[5], 0x01 };
}

test "LAN transit: a 4-member LAN is a full mesh at each member's own metric, asymmetric where the metrics are" {
    const a = sysId(0x01);
    const b = sysId(0x02);
    const c = sysId(0x03);
    const e = sysId(0x04);
    const pn = pnOf(b); // B is the DIS
    for ([_]SystemId{ a, c }) |root| {
        var db = lsdb.Lsdb.init(testing.allocator, cfgFor(root));
        defer db.deinit();
        try insertPseudonodeLsp(&db, b, &.{ a, b, c, e });
        try insertReachLspRaw(&db, a, 1, &.{.{ .nbr7 = pn, .metric = 10 }});
        try insertReachLspRaw(&db, b, 1, &.{.{ .nbr7 = pn, .metric = 20 }});
        try insertReachLspRaw(&db, c, 1, &.{.{ .nbr7 = pn, .metric = 30 }});
        try insertReachLspRaw(&db, e, 1, &.{.{ .nbr7 = pn, .metric = 40 }});
        var table = try compute(testing.allocator, &db, root, 0);
        defer table.deinit();
        try testing.expectEqual(@as(usize, 4), table.routes.len);
        // Every other member is one LAN hop away at the ROOT's metric toward
        // the pseudonode: 10 from A, 30 from C.
        const cost: u32 = if (std.mem.eql(u8, &root, &a)) 10 else 30;
        for ([_]SystemId{ a, b, c, e }) |dst| {
            if (std.mem.eql(u8, &dst, &root)) continue;
            try testing.expectEqual(Route{ .dest = dst, .next_hop = dst, .metric = cost }, table.lookup(dst).?);
        }
    }
}

test "LAN transit: a LAN and a P2P tail compose — the tail is reached through the LAN member" {
    const a = sysId(0x01);
    const b = sysId(0x02);
    const c = sysId(0x03);
    const z = sysId(0x09);
    const pn = pnOf(a);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();
    try insertPseudonodeLsp(&db, a, &.{ a, b, c });
    try insertReachLspRaw(&db, a, 1, &.{.{ .nbr7 = pn, .metric = 10 }});
    try insertReachLspRaw(&db, b, 1, &.{.{ .nbr7 = pn, .metric = 10 }});
    try insertReachLspRaw(&db, c, 1, &.{ .{ .nbr7 = pn, .metric = 10 }, .{ .nbr7 = .{ z[0], z[1], z[2], z[3], z[4], z[5], 0 }, .metric = 5 } });
    try insertReachLspRaw(&db, z, 1, &.{.{ .nbr7 = .{ c[0], c[1], c[2], c[3], c[4], c[5], 0 }, .metric = 5 }});
    var table = try compute(testing.allocator, &db, a, 0);
    defer table.deinit();
    try testing.expectEqual(Route{ .dest = c, .next_hop = c, .metric = 10 }, table.lookup(c).?);
    try testing.expectEqual(Route{ .dest = z, .next_hop = c, .metric = 15 }, table.lookup(z).?);
}

test "LAN transit: a member the pseudonode does not list back is not admitted (two-way on the LAN)" {
    const a = sysId(0x01);
    const b = sysId(0x02);
    const c = sysId(0x03);
    const pn = pnOf(a);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();
    try insertPseudonodeLsp(&db, a, &.{ a, b }); // C is not listed
    try insertReachLspRaw(&db, a, 1, &.{.{ .nbr7 = pn, .metric = 10 }});
    try insertReachLspRaw(&db, b, 1, &.{.{ .nbr7 = pn, .metric = 10 }});
    try insertReachLspRaw(&db, c, 1, &.{.{ .nbr7 = pn, .metric = 1 }});
    var table = try compute(testing.allocator, &db, a, 0);
    defer table.deinit();
    try testing.expectEqual(Route{ .dest = b, .next_hop = b, .metric = 10 }, table.lookup(b).?);
    try testing.expect(table.lookup(c) == null);

    // The broken positive control (no two-way check) admits C: the check,
    // not an accident of the fixture, is what kept it out.
    var broken = try computeWithBrokenTwoWayForTesting(testing.allocator, &db, a, 0, false);
    defer broken.deinit();
    try testing.expect(broken.lookup(c) != null);
}

test "LAN transit: a pseudonode that lists nobody, or only one member, adds no arc" {
    const a = sysId(0x01);
    const b = sysId(0x02);
    const pn = pnOf(a);
    for ([_][]const SystemId{ &.{}, &.{a} }) |listed| {
        var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
        defer db.deinit();
        try insertPseudonodeLsp(&db, a, listed);
        try insertReachLspRaw(&db, a, 1, &.{.{ .nbr7 = pn, .metric = 10 }});
        try insertReachLspRaw(&db, b, 1, &.{.{ .nbr7 = pn, .metric = 10 }});
        var table = try compute(testing.allocator, &db, a, 0);
        defer table.deinit();
        try testing.expect(table.lookup(b) == null);
    }
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

// Regression (audit W2 `isis-spf` F2): RFC 5305 §3's max-link-metric
// (0xFFFFFF) MUST NOT be considered during normal SPF — it is the mechanism a
// TE-only / MPLS-TE / LFA-staging link uses to stay advertised while being
// excluded from ordinary routing. Before the fix, `e.metric` went straight
// into `addDirected` unfiltered, so a max-metric link became a usable (if
// very expensive) edge and could still be selected as the path of last
// resort when nothing else reached the destination — exactly the case here.
test "RFC 5305 max-link-metric (0xFFFFFF): excluded from SPF, destination unreachable when it is the only path" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();

    // A—B is the ONLY link, and it is advertised (both ways, so the two-way
    // check would otherwise admit it) at the max-link-metric value.
    try insertReachLsp(&db, a, 1, &.{.{ .nbr = b, .metric = max_link_metric }});
    try insertReachLsp(&db, b, 1, &.{.{ .nbr = a, .metric = max_link_metric }});

    var table = try compute(testing.allocator, &db, a, 0);
    defer table.deinit();
    // Only the self route: B is excluded, not admitted at cost 16777215.
    try testing.expectEqual(@as(usize, 1), table.routes.len);
    try testing.expect(table.lookup(b) == null);
}

test "RFC 5305 max-link-metric: a normal alternate path is still used when one direction is max-metric" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    const c = sysId(0xC);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();

    // A—B direct is max-metric (excluded); A—C—B is a normal 20-cost detour.
    try insertReachLsp(&db, a, 1, &.{ .{ .nbr = b, .metric = max_link_metric }, .{ .nbr = c, .metric = 10 } });
    try insertReachLsp(&db, b, 1, &.{ .{ .nbr = a, .metric = max_link_metric }, .{ .nbr = c, .metric = 10 } });
    try insertReachLsp(&db, c, 1, &.{ .{ .nbr = a, .metric = 10 }, .{ .nbr = b, .metric = 10 } });

    var table = try compute(testing.allocator, &db, a, 0);
    defer table.deinit();
    const r = table.lookup(b).?;
    try testing.expectEqual(c, r.next_hop); // via C, not the direct (excluded) link
    try testing.expectEqual(@as(u64, 20), r.metric);
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

    // A's LSP advertises B twice (e.g. duplicate/fragmented entries).
    //
    // ⚠ Order matters, and this fixture used to carry only ONE of them: with
    // `{20, 5}` alone, "keep the minimum" and "keep the LAST" give the same
    // answer, so a keep-last mutation stayed green across the whole suite while
    // the comment claimed the test excluded "the last or the first value seen".
    // It excluded the first. Both orders are now driven, which is what makes
    // the claim true.
    try insertReachLsp(&db, a, 1, &.{ .{ .nbr = b, .metric = 20 }, .{ .nbr = b, .metric = 5 } });
    try insertReachLsp(&db, b, 1, &.{.{ .nbr = a, .metric = 5 }});

    var table = try compute(testing.allocator, &db, a, 0);
    defer table.deinit();
    try testing.expectEqual(@as(u64, 5), table.lookup(b).?.metric);

    // The reverse order: minimum FIRST, so keep-last would report 20.
    const c = sysId(0xC);
    const d = sysId(0xD);
    var db2 = lsdb.Lsdb.init(testing.allocator, cfgFor(c));
    defer db2.deinit();
    try insertReachLsp(&db2, c, 1, &.{ .{ .nbr = d, .metric = 5 }, .{ .nbr = d, .metric = 20 } });
    try insertReachLsp(&db2, d, 1, &.{.{ .nbr = c, .metric = 5 }});

    var table2 = try compute(testing.allocator, &db2, c, 0);
    defer table2.deinit();
    try testing.expectEqual(@as(u64, 5), table2.lookup(d).?.metric);
}

test "two-way check with require_two_way=false: only the hi->lo advertisement exists (hi_lo fallback)" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();

    // Only B advertises A; A advertises nothing, so the b→a arc exists and the
    // a→b arc does not. (This comment used to describe a `hi_lo` fallback in an
    // "undirected-weight selection" — a mechanism the directed rewrite deleted.
    // There is no canonical per-link weight any more: each direction is its own
    // arc, and what this fixture exercises is a one-way arc surviving with the
    // two-way check disabled.)
    try insertReachLsp(&db, a, 1, &.{});
    try insertReachLsp(&db, b, 1, &.{.{ .nbr = a, .metric = 15 }});

    var table = try computeWithBrokenTwoWayForTesting(testing.allocator, &db, a, 0, false);
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

// Regression (audit W2 `isis-spf` F6): the ISO §7.2.8.2 two-way-check toggle
// must not be reachable through the public API `Options` struct — that is
// precisely what let production code disable it by accident before this fix
// (`require_two_way: bool = true` was a plain field on `pub const Options`,
// and `computeWith` took `Options` directly). The disabled-two-way path still
// exists (`computeWithBrokenTwoWayForTesting`, used by the two tests above),
// but it is a bare, non-`pub` function — invisible to every other module,
// which can only see this file's `pub` declarations. `@hasField` pins the
// compile-time fact that closes this gap: if `require_two_way` (or any field
// spelled like it) is ever added back to `Options`, this test catches it
// immediately, without needing a separate cross-module compile-fail harness.
test "the two-way-check toggle is not a field of the public Options struct" {
    try testing.expect(!@hasField(Options, "require_two_way"));
    // Guard against the same gap under a different name.
    const info = @typeInfo(Options).@"struct";
    inline for (info.field_names) |name| {
        try testing.expect(std.mem.find(u8, name, "two_way") == null);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// coverage-guided fuzz (audit W2 `isis-spf` F4)
// ─────────────────────────────────────────────────────────────────────────────
//
// `computeWith` is not a leaf. Every call re-decodes the LSDB's stored bytes
// (`isis.Lsp.decode`) and walks `tlvIterator` / `ExtIsReachIterator` /
// `IsReachIterator` over them — and those bytes arrive from the network via
// `isis-lsdb`. The module had no `testing.fuzz` harness, which also kept it out
// of `scripts/fuzz-sweep.sh` entirely: that script derives its target list with
// `grep -rl 'testing\.fuzz(' modules/*/src/*.zig`, so a module with no harness
// is not "clean", it is *absent* — and absent looks the same as covered from
// the outside. The harness below puts it in the list.
//
// ⭐ THE HARNESS MUST REACH THE TRAVERSAL, NOT JUST THE FRONT DOOR. Feeding raw
// fuzz bytes to `Lsdb.insert` alone would be near-useless: essentially every
// random buffer fails `Lsp.decode`'s framing checks, the LSDB stays empty, and
// `compute` returns an empty table without ever touching a TLV iterator — a
// harness structurally unable to reach its target. So the input is ALSO spliced
// into the TLV region of a WELL-FORMED, correctly-checksummed LSP header, once
// per plausible originator, which is what gets the iterators actually walking
// attacker-chosen bytes. Reachability was demonstrated, not assumed: with
// `addDirected`'s `@max(1, …)` metric clamp replaced by
// `std.debug.assert(raw_metric != 0)` — the shape this code had before the
// clamp — the harness panics in seconds on an input carrying a zero-metric
// extended-IS-reachability entry.

/// `testkit.fuzz.seedHex`. A corpus entry is not the TLV region: `Smith.slice`
/// reads a little-endian u32 length first, so a raw region would arrive minus
/// its own first TLV header.
const seed = @import("testkit").fuzz.seedHex;

/// One Extended IS Reachability (#22) TLV naming `nbr` with `metric`, as the
/// hex the module's own `addExtendedIsReach` emits: code, length, a 7-octet
/// neighbour id (system id + pseudonode octet), a 24-bit metric, and a
/// zero sub-TLV length.
fn extReach(comptime nbr: []const u8, comptime metric: []const u8) []const u8 {
    return "160B" ++ "0000000000" ++ nbr ++ "00" ++ metric ++ "00";
}

/// LSP TLV regions, in the format `Smith.slice` reads.
///
/// The harness stamps the SAME region into two LSPs (originators 0xA and 0xB),
/// so a region naming BOTH of them is what makes the two-way check succeed —
/// a region naming only its neighbour is asymmetric by construction here. That
/// is why the first seed carries two TLVs.
///
/// Uniform random octets essentially never spell TLV #22 with a length that is
/// a multiple of 11 and agrees with the region, so without these the SPF ran
/// over a graph with no edges at all.
const spf_seeds = [_][]const u8{
    seed(extReach("0A", "00000A") ++ extReach("0B", "00000A")), // a two-way A↔B link, metric 10
    seed(extReach("0A", "000001") ++ extReach("0B", "FFFFFE") ++ extReach("0C", "000005")), // three neighbours, one at the metric ceiling's edge
    seed(extReach("0A", "FFFFFF") ++ extReach("0B", "FFFFFF")), // max_link_metric: excluded outright (RFC 5305 §3)
    seed(extReach("0B", "00000A")), // names only 0xB: no two-way pair, so no route
    seed("160C" ++ "0000000000" ++ "0A" ++ "00" ++ "00000A" ++ "0000"), // a length one octet past the 11-octet record
    seed("16FF" ++ "0000000000" ++ "0A" ++ "00" ++ "00000A" ++ "00"), // a TLV length that lies about the region
    seed("831B010614010003001B0384AABBCCDDEEFF0703800000070000D7"), // a whole LSP as the region: the front door, not the traversal
    seed("DEADBEEF"), // four octets that are not a TLV
    seed(""), // the empty region
};

/// Everything the harness does with one buffer of untrusted octets. Shared with
/// the corpus guard below, so the guard measures the harness's own corpus and
/// not a paraphrase of it.
fn driveSpf(gpa: std.mem.Allocator, input: []const u8) !usize {
    const local = sysId(0xA);
    var db = lsdb.Lsdb.init(gpa, cfgFor(local));
    defer db.deinit();

    // (1) The front door: raw bytes straight at the LSDB's framing/validation
    // path, exactly as a hostile neighbour would send them.
    _ = db.insert(input, null, 0) catch {};

    // (2) The traversal: the same bytes as the TLV region of a well-formed LSP.
    // Two originators so the two-way check has something to correlate and the
    // graph-building stage is reachable, not just the extraction stage.
    for ([_]u8{ 0xA, 0xB }) |last| {
        const origin = sysId(last);
        var buf: [1500]u8 = undefined;
        var b = isis.pdu.LspBuilder.init(&buf, .{
            .remaining_lifetime = 1000,
            .lsp_id = .{ origin[0], origin[1], origin[2], origin[3], origin[4], origin[5], 0, 0 },
            .sequence_number = 1,
            .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
        }) catch continue;
        const room = buf.len - isis.pdu.lsp_fixed_len;
        const take = @min(input.len, room);
        @memcpy(buf[isis.pdu.lsp_fixed_len..][0..take], input[0..take]);
        b.tlvs.pos = take;
        _ = db.insert(b.finishStamped(), null, 0) catch {};
    }

    // Both entry points, including the one with the extra failure mode.
    var routes: usize = 0;
    var rt = compute(gpa, &db, local, 0) catch |e| switch (e) {
        error.OutOfMemory => return 0,
    };
    routes = rt.routes.len;
    rt.deinit();

    var rt2 = computeWith(gpa, &db, local, 0, .{ .reject_asymmetric = true }) catch |e| switch (e) {
        error.OutOfMemory, error.AsymmetricMetric, error.NodeIdTooLarge => return routes,
    };
    rt2.deinit();
    return routes;
}

const fz = @import("fuzz_test.zig");
const ComputeMark = fz.Marker(enum { empty, edges, self_only, front_door_stored });
const ModelMark = fz.Marker(enum { reachable_agrees, unreachable_agrees, one_way_dropped, max_metric_dropped, multi_hop });

fn fuzzComputeOverLsdbSmith(_: void, smith: *testing.Smith) anyerror!void {
    try fuzzComputeOverLsdb(testing.Smith, smith, testing.allocator);
}

fn fuzzModelSmith(_: void, smith: *testing.Smith) anyerror!void {
    try fuzzModel(testing.Smith, smith, testing.allocator);
}

fn fuzzComputeOverLsdb(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var input_buf: [512]u8 = undefined;
    // ⚠ One `slice` call, never `bytes` followed by a ranged length. `bytes`
    // takes `@min(buf.len, in.len)` octets and the ranged draw then finds fewer
    // than the eight it needs and returns the range MINIMUM -- so the region
    // was ZERO octets long on every input a seed can carry. The buffer is also
    // raised 256 -> 512, to match the region size the module's own
    // `insertReachLsp` fixtures build into. Under the driver's `Rng`, half the
    // draws are a corpus entry with 0-3 octets damaged.
    const len: usize = fz.drawInput(S, src, &input_buf, &spf_seeds);
    if (len == 0) ComputeMark.mark(.empty);
    const n = try driveSpf(gpa, input_buf[0..len]);
    if (n > 1) ComputeMark.mark(.edges) else ComputeMark.mark(.self_only);
    if (n == 0) return;
    ComputeMark.mark(.front_door_stored);
}

test "fuzz driver: ISIS_SPF_FUZZ (compute)" {
    try fz.fuzz_driver.run(fuzzComputeOverLsdb, .{ .prefix = "ISIS_SPF_FUZZ", .name = "isis-spf-compute" });
}

test "fuzz harness: compute, 500 seeds, reaches every outcome" {
    try ComputeMark.reach(fuzzComputeOverLsdb, "isis-spf-compute", 500);
}

test "fuzz: SPF against a Floyd-Warshall model on random two-way graphs" {
    try testing.fuzz({}, fuzzModelSmith, .{});
}

test "fuzz driver: ISIS_SPF_FUZZ (model)" {
    try fz.fuzz_driver.run(fuzzModel, .{ .prefix = "ISIS_SPF_FUZZ", .name = "isis-spf-model" });
}

test "fuzz harness: model, 300 seeds, reaches every outcome" {
    try ModelMark.reach(fuzzModel, "isis-spf-model", 300);
}

/// The oracle the byte-feeding harness cannot be: a random topology of up to 6
/// systems, each directed adjacency advertised (or not) at its own metric,
/// goes through the real LSDB and `compute`; the table must equal a
/// Floyd-Warshall shortest-path matrix over the arcs both ends advertise
/// (the two-way check) below the RFC 5305 max-link-metric, each direction at
/// its own metric, and every next hop must lie on a shortest path.
fn fuzzModel(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [96]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var cur: @import("testkit").fuzz.Cursor = .{ .bytes = raw[0..raw_len] };
    const n: usize = cur.ranged(2, 6);
    const inf: u64 = std.math.maxInt(u64) / 4;
    var adv: [6][6]u32 = undefined; // advertised metric u->v, 0 = not advertised
    for (0..n) |u| for (0..n) |v| {
        adv[u][v] = 0;
        if (u == v) continue;
        const m = cur.byte();
        if (m < 80) continue;
        adv[u][v] = if (m == 255) 0xFFFFFF else 1 + @as(u32, (m - 80) % 20);
    };

    var db = lsdb.Lsdb.init(gpa, cfgFor(sysId(1)));
    defer db.deinit();
    for (0..n) |u| {
        var buf: [512]u8 = undefined;
        const origin = sysId(@intCast(u + 1));
        var lb = try isis.pdu.LspBuilder.init(&buf, .{
            .remaining_lifetime = 1000,
            .lsp_id = .{ origin[0], origin[1], origin[2], origin[3], origin[4], origin[5], 0, 0 },
            .sequence_number = 1,
            .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
        });
        for (0..n) |v| if (adv[u][v] != 0) {
            const nbr7: [7]u8 = .{ 0, 0, 0, 0, 0, @intCast(v + 1), 0 };
            try isis.tlvs.addExtendedIsReach(&lb.tlvs, nbr7, @intCast(adv[u][v]), &.{});
        };
        _ = try db.insert(lb.finish(), null, 0);
    }

    // The model: an arc u->v exists iff both ends advertise and neither is at
    // the max link metric; it costs u's advertised metric.
    var d: [6][6]u64 = undefined;
    for (0..n) |u| for (0..n) |v| {
        d[u][v] = if (u == v) 0 else inf;
        if (u == v or adv[u][v] == 0 or adv[v][u] == 0) {
            if (u != v and (adv[u][v] != 0) != (adv[v][u] != 0)) ModelMark.mark(.one_way_dropped);
            continue;
        }
        if (adv[u][v] == 0xFFFFFF or adv[v][u] == 0xFFFFFF) {
            ModelMark.mark(.max_metric_dropped);
            continue;
        }
        d[u][v] = adv[u][v];
    };
    for (0..n) |k| for (0..n) |i| for (0..n) |j| {
        if (d[i][k] + d[k][j] < d[i][j]) d[i][j] = d[i][k] + d[k][j];
    };

    var rt = try compute(gpa, &db, sysId(1), 0);
    defer rt.deinit();
    var seen = @as([6]bool, @splat(false));
    for (rt.routes) |r| {
        const v: usize = r.dest[5] - 1;
        seen[v] = true;
        if (d[0][v] >= inf) return error.RouteToUnreachableSystem;
        if (r.metric != d[0][v]) return error.RouteMetricDiffersFromModel;
        if (v != 0) {
            // The next hop is a neighbour of local on a shortest path.
            const h: usize = r.next_hop[5] - 1;
            if (d[0][h] >= inf or adv[0][h] == 0 or d[0][h] + d[h][v] != d[0][v]) return error.NextHopNotOnShortestPath;
            if (d[0][v] > d[0][h]) ModelMark.mark(.multi_hop);
        }
        ModelMark.mark(.reachable_agrees);
    }
    for (0..n) |v| if (d[0][v] < inf and !seen[v]) return error.ReachableSystemMissing;
    for (0..n) |v| if (d[0][v] >= inf and !seen[v]) ModelMark.mark(.unreachable_agrees);
}

test "corpus: every SPF seed reaches the graph builder, and the route count is pinned" {
    // Two numbers, built from the same `driveSpf` the harness runs. `nonempty`
    // is the reach claim; `routes` is the one an empty region cannot produce.
    // It has to be here: `compute` over an LSDB holding two LSPs with EMPTY TLV
    // regions returns successfully every time — no error, no panic — so a guard
    // that only asked whether the harness came back clean would have scored full
    // marks while the shortest-path search had no edges to search.
    var nonempty: usize = 0;
    var routes: usize = 0;
    var with_edges: usize = 0;
    for (spf_seeds) |sd| {
        var smith: testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const n = try driveSpf(testing.allocator, buf[0..len]);
        routes += n;
        if (n > 1) with_edges += 1; // more than the local self route
    }
    try testing.expectEqual(spf_seeds.len - 1, nonempty); // the empty region is deliberate
    try testing.expectEqual(@as(usize, 8), routes);
    try testing.expectEqual(@as(usize, 2), with_edges);

    // The "before", executable rather than written in a comment: what the
    // collapsed draw produced for EVERY seed, since it handed `driveSpf` a
    // zero-length region no matter what the seed said.
    try testing.expectEqual(@as(usize, 1), try driveSpf(testing.allocator, ""));
}

test "TEETH: an LSP whose Remaining Lifetime has aged to zero is excluded from SPF" {
    // ISO/IEC 10589 §7.3.17. `now` was accepted, forwarded to `isis-lsdb` (whose
    // `EntryView.remaining_lifetime` is aged to exactly that `now`), documented
    // as ageing lifetimes — and then never read. The only filter was
    // `bytes.len == 0`, which catches an entry `Lsdb.tick` has already reduced
    // to a header, and `tick` is caller-driven and independent of `compute`.
    //
    // ⚠ `isis-sim`, the harness that drives this module, calls
    // `isis_spf.compute(gpa, …, 0)` with `now` hardcoded to 0, so every
    // simulated SPF runs at t=0 where nothing has aged. The harness structurally
    // could not see this.
    const gpa = testing.allocator;
    const a = sysId(1);
    const b = sysId(2);
    var db = lsdb.Lsdb.init(gpa, cfgFor(a));
    defer db.deinit();
    try insertReachLspLifetime(&db, a, 1, 5, &.{.{ .nbr = b, .metric = 10 }});
    try insertReachLspLifetime(&db, b, 1, 5, &.{.{ .nbr = a, .metric = 10 }});

    // The premise, asserted rather than assumed: the database itself calls both
    // entries dead at this `now`, and still holds their bytes. Without the
    // second half the test would pass for the wrong reason.
    {
        var it = db.iterator(1000);
        var seen: usize = 0;
        while (it.next()) |ev| {
            try testing.expectEqual(@as(u16, 0), ev.remaining_lifetime);
            try testing.expect(ev.bytes.len > 0);
            seen += 1;
        }
        try testing.expectEqual(@as(usize, 2), seen);
    }

    // Well inside the lifetime the topology routes normally — the control, so
    // an empty table below cannot be a broken fixture.
    {
        var early = try compute(gpa, &db, a, 1);
        defer early.deinit();
        try testing.expectEqual(@as(usize, 2), early.routes.len);
        try testing.expectEqual(@as(u64, 10), early.lookup(b).?.metric);
    }

    // Past it, nothing is routable — not even the local self route, because the
    // local router's own LSP has expired too and `origins` is built from the
    // same walk.
    var table = try compute(gpa, &db, a, 1000);
    defer table.deinit();
    try testing.expectEqual(@as(usize, 0), table.routes.len);
}

test "RFC 5305 §3 MAX_PATH_METRIC: the ceiling is exceeded, and the gap is stated rather than assumed" {
    // The deferral of the MAX_PATH_METRIC clamp used to be justified by "not a
    // fixture that can be driven RED at a defensible size". This is that
    // fixture: 300 routers, 22 ms. It asserts the CURRENT behaviour — the
    // summed metric runs past 0xFE000000 unclamped — so the deferral is pinned
    // by a measurement instead of by a claim, and whoever later clamps in
    // `spf-ect` will meet this test and have to change it deliberately.
    const gpa = testing.allocator;
    const n: usize = 300;
    var db = lsdb.Lsdb.init(gpa, .{ .local_system_id = sysId(0), .interface_count = 2, .capacity = 512 });
    defer db.deinit();
    var ids: [300]SystemId = undefined;
    for (0..n) |i| {
        ids[i] = .{ 0, 0, 0, 0, @intCast(i >> 8), @intCast(i & 0xff) };
    }
    const near_max: u24 = 0xFFFFFE; // one below max_link_metric, which is excluded outright
    for (0..n) |i| {
        if (i == 0) {
            try insertReachLsp(&db, ids[i], 1, &.{.{ .nbr = ids[1], .metric = near_max }});
        } else if (i + 1 == n) {
            try insertReachLsp(&db, ids[i], 1, &.{.{ .nbr = ids[i - 1], .metric = near_max }});
        } else {
            try insertReachLsp(&db, ids[i], 1, &.{
                .{ .nbr = ids[i - 1], .metric = near_max },
                .{ .nbr = ids[i + 1], .metric = near_max },
            });
        }
    }
    var table = try compute(gpa, &db, ids[0], 0);
    defer table.deinit();
    try testing.expectEqual(@as(usize, n), table.routes.len);

    const max_path_metric: u64 = 0xFE000000;
    const far = table.lookup(ids[n - 1]).?;
    // The exact sum, so a change in either the metric type or the accumulation
    // shows up here rather than being absorbed by an inequality.
    try testing.expectEqual(@as(u64, 299) * near_max, far.metric);
    try testing.expect(far.metric > max_path_metric);
    // And nothing overflowed: the RFC's own rationale for the ceiling is a
    // 32-bit accumulator, and `Route.metric` is a u64.
    try testing.expect(far.metric > std.math.maxInt(u32));
}

// ── whole-module mutation audit ───────────────────────────────────

fn id7(s: SystemId) [7]u8 {
    return .{ s[0], s[1], s[2], s[3], s[4], s[5], 0 };
}

/// An LSP (`lsp_id7` = system-id ++ pseudonode octet) that carries ONE #2 (old
/// style) IS Neighbours TLV with a default metric octet and a 7-octet
/// neighbour-id per entry. The metric octet is stored verbatim, flag bits and all.
fn insertOldStyleLsp(
    db: *lsdb.Lsdb,
    lsp_id7: [7]u8,
    seq: u32,
    entries: []const struct { nbr7: [7]u8, metric: u8 },
) !void {
    var buf: [256]u8 = undefined;
    var lb = try isis.pdu.LspBuilder.init(&buf, .{
        .remaining_lifetime = 1000,
        .lsp_id = .{ lsp_id7[0], lsp_id7[1], lsp_id7[2], lsp_id7[3], lsp_id7[4], lsp_id7[5], lsp_id7[6], 0 },
        .sequence_number = seq,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    });
    var val: [1 + 11 * 8]u8 = undefined;
    val[0] = 0; // virtual flag
    var n: usize = 1;
    for (entries) |e| {
        val[n..][0..4].* = .{ e.metric, 0x80, 0x80, 0x80 };
        val[n + 4 ..][0..7].* = e.nbr7;
        n += 11;
    }
    try lb.tlvs.addTlv(isis.tlvs.code.is_neighbours_lsp, val[0..n]);
    _ = try db.insert(lb.finish(), null, 0);
}

/// A pseudonode LSP (#22) for `dis`/circuit 1 listing the given raw 7-octet
/// neighbour-ids, which may themselves be pseudonode ids.
fn insertPseudonodeLspRaw(db: *lsdb.Lsdb, dis: SystemId, listed: []const [7]u8) !void {
    var buf: [512]u8 = undefined;
    var lb = try isis.pdu.LspBuilder.init(&buf, .{
        .remaining_lifetime = 1000,
        .lsp_id = .{ dis[0], dis[1], dis[2], dis[3], dis[4], dis[5], 0x01, 0 },
        .sequence_number = 1,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    });
    for (listed) |l| try isis.tlvs.addExtendedIsReach(&lb.tlvs, l, 0, &.{});
    _ = try db.insert(lb.finish(), null, 0);
}

test "LAN transit over #2 (old-style) TLVs: members and the pseudonode LSP; the metric octet keeps only its low 6 bits" {
    const d = sysId(0x50);
    const x = sysId(0x10);
    const y = sysId(0x90);
    const pn = pnOf(d);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(x));
    defer db.deinit();
    try insertOldStyleLsp(&db, pn, 1, &.{ .{ .nbr7 = id7(x), .metric = 0 }, .{ .nbr7 = id7(d), .metric = 0 }, .{ .nbr7 = id7(y), .metric = 0 } });
    try insertOldStyleLsp(&db, id7(x), 1, &.{.{ .nbr7 = pn, .metric = 0xC5 }}); // bits 8 and 7 set, value 5
    try insertOldStyleLsp(&db, id7(d), 1, &.{.{ .nbr7 = pn, .metric = 5 }});
    try insertOldStyleLsp(&db, id7(y), 1, &.{.{ .nbr7 = pn, .metric = 0x45 }}); // bit 7 set, value 5
    var table = try compute(testing.allocator, &db, x, 0);
    defer table.deinit();
    try testing.expectEqual(@as(usize, 3), table.routes.len);
    try testing.expectEqual(Route{ .dest = d, .next_hop = d, .metric = 5 }, table.lookup(d).?);
    try testing.expectEqual(Route{ .dest = y, .next_hop = y, .metric = 5 }, table.lookup(y).?);
}

test "old-style #2 default metric: bit 7 (0x40) is masked off too, and bit 6 (0x20) is part of the value" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();
    try insertOldStyleLsp(&db, id7(a), 1, &.{.{ .nbr7 = id7(b), .metric = 0x47 }});
    try insertOldStyleLsp(&db, id7(b), 1, &.{.{ .nbr7 = id7(a), .metric = 0xE7 }}); // 0x20 is value bit 6: 0x27 = 39
    var table = try compute(testing.allocator, &db, a, 0);
    defer table.deinit();
    try testing.expectEqual(@as(u64, 7), table.lookup(b).?.metric); // a's own advertisement
    // the reverse direction is b's: 39, so the route from b to a costs 39
    var back = try compute(testing.allocator, &db, b, 0);
    defer back.deinit();
    try testing.expectEqual(@as(u64, 39), back.lookup(a).?.metric);
}

test "a metric of 0 is clamped to 1 on a point-to-point link and on a LAN" {
    const a = sysId(1);
    const b = sysId(2);
    const c = sysId(3);
    const e = sysId(4);
    const pn = pnOf(c);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();
    try insertReachLsp(&db, a, 1, &.{ .{ .nbr = b, .metric = 0 }, .{ .nbr = c, .metric = 0 } });
    try insertReachLsp(&db, b, 1, &.{.{ .nbr = a, .metric = 0 }});
    // LAN of A, C and E (DIS C); A and C also face the LAN at metric 0
    try insertPseudonodeLsp(&db, c, &.{ a, c, e });
    try insertReachLspRaw(&db, a, 2, &.{ .{ .nbr7 = id7(b), .metric = 0 }, .{ .nbr7 = id7(c), .metric = 0 }, .{ .nbr7 = pn, .metric = 0 } });
    try insertReachLspRaw(&db, c, 1, &.{ .{ .nbr7 = id7(a), .metric = 0 }, .{ .nbr7 = pn, .metric = 0 } });
    try insertReachLspRaw(&db, e, 1, &.{.{ .nbr7 = pn, .metric = 0 }});
    var table = try compute(testing.allocator, &db, a, 0);
    defer table.deinit();
    try testing.expectEqual(@as(u64, 1), table.lookup(b).?.metric);
    try testing.expectEqual(@as(u64, 1), table.lookup(c).?.metric);
    try testing.expectEqual(Route{ .dest = e, .next_hop = e, .metric = 1 }, table.lookup(e).?);
}

test "a pseudonode LSP that lists a pseudonode id does not admit that system as a LAN member" {
    const a = sysId(1);
    const b = sysId(2);
    const pn = pnOf(a);
    const b_circuit_2: [7]u8 = .{ b[0], b[1], b[2], b[3], b[4], b[5], 0x02 }; // a pseudonode, not an IS
    // via #22, then via #2
    for ([_]bool{ false, true }) |old_style| {
        var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
        defer db.deinit();
        if (old_style) {
            try insertOldStyleLsp(&db, pn, 1, &.{ .{ .nbr7 = id7(a), .metric = 0 }, .{ .nbr7 = b_circuit_2, .metric = 0 } });
        } else {
            try insertPseudonodeLspRaw(&db, a, &.{ id7(a), b_circuit_2 });
        }
        try insertReachLspRaw(&db, a, 1, &.{.{ .nbr7 = pn, .metric = 10 }});
        try insertReachLspRaw(&db, b, 1, &.{.{ .nbr7 = pn, .metric = 10 }});
        var table = try compute(testing.allocator, &db, a, 0);
        defer table.deinit();
        try testing.expect(table.lookup(b) == null);
    }
}

test "LAN transit: a member listed by ANOTHER pseudonode is not admitted into this one; two LANs sharing a member do not merge" {
    const a = sysId(1);
    const b = sysId(2);
    const c = sysId(3);
    const d = sysId(4);
    {
        // C faces the LAN of A but only D's pseudonode lists C
        var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
        defer db.deinit();
        try insertPseudonodeLsp(&db, a, &.{ a, b });
        try insertPseudonodeLsp(&db, d, &.{ d, c });
        try insertReachLspRaw(&db, a, 1, &.{.{ .nbr7 = pnOf(a), .metric = 10 }});
        try insertReachLspRaw(&db, b, 1, &.{.{ .nbr7 = pnOf(a), .metric = 10 }});
        try insertReachLspRaw(&db, c, 1, &.{.{ .nbr7 = pnOf(a), .metric = 1 }});
        try insertReachLspRaw(&db, d, 1, &.{.{ .nbr7 = pnOf(d), .metric = 10 }});
        var table = try compute(testing.allocator, &db, a, 0);
        defer table.deinit();
        try testing.expect(table.lookup(c) == null);
        try testing.expectEqual(@as(u64, 10), table.lookup(b).?.metric);
    }
    {
        // LAN 1 = {A, B}, LAN 2 = {B, C}: C is reached THROUGH B only
        var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
        defer db.deinit();
        try insertPseudonodeLsp(&db, a, &.{ a, b });
        try insertPseudonodeLsp(&db, c, &.{ b, c });
        try insertReachLspRaw(&db, a, 1, &.{.{ .nbr7 = pnOf(a), .metric = 10 }});
        try insertReachLspRaw(&db, b, 1, &.{ .{ .nbr7 = pnOf(a), .metric = 10 }, .{ .nbr7 = pnOf(c), .metric = 10 } });
        try insertReachLspRaw(&db, c, 1, &.{.{ .nbr7 = pnOf(c), .metric = 10 }});
        var table = try compute(testing.allocator, &db, a, 0);
        defer table.deinit();
        try testing.expectEqual(Route{ .dest = c, .next_hop = b, .metric = 20 }, table.lookup(c).?);
    }
}

test "LAN transit: a cheaper point-to-point link beats a dearer LAN arc; the cheaper advertisement of a pseudonode wins" {
    const a = sysId(1);
    const b = sysId(2);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();
    try insertPseudonodeLsp(&db, a, &.{ a, b });
    // P2P 5 both ways, and the LAN at 50; A advertises the pseudonode twice (50, then 40)
    try insertReachLspRaw(&db, a, 1, &.{ .{ .nbr7 = id7(b), .metric = 5 }, .{ .nbr7 = pnOf(a), .metric = 50 }, .{ .nbr7 = pnOf(a), .metric = 40 } });
    try insertReachLspRaw(&db, b, 1, &.{ .{ .nbr7 = id7(a), .metric = 5 }, .{ .nbr7 = pnOf(a), .metric = 50 } });
    {
        var table = try compute(testing.allocator, &db, a, 0);
        defer table.deinit();
        try testing.expectEqual(@as(u64, 5), table.lookup(b).?.metric);
    }
    // without the P2P link the LAN carries it, at A's CHEAPER advertisement (40)
    try insertReachLspRaw(&db, a, 2, &.{ .{ .nbr7 = pnOf(a), .metric = 50 }, .{ .nbr7 = pnOf(a), .metric = 40 } });
    try insertReachLspRaw(&db, b, 2, &.{.{ .nbr7 = pnOf(a), .metric = 50 }});
    {
        var table = try compute(testing.allocator, &db, a, 0);
        defer table.deinit();
        try testing.expectEqual(@as(u64, 40), table.lookup(b).?.metric);
    }
}

test "the asymmetric-link count survives an empty table (local absent)" {
    const a = sysId(1);
    const b = sysId(2);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(sysId(9)));
    defer db.deinit();
    try insertReachLsp(&db, a, 1, &.{.{ .nbr = b, .metric = 10 }});
    try insertReachLsp(&db, b, 1, &.{.{ .nbr = a, .metric = 20 }});
    var table = try compute(testing.allocator, &db, sysId(9), 0);
    defer table.deinit();
    try testing.expectEqual(@as(usize, 0), table.routes.len);
    try testing.expectEqual(@as(u32, 1), table.asymmetric_links);
}

// ── overload, ECMP, prefixes, attached default ───────────────────────────────

const Nbr = struct { nbr: SystemId, metric: u24 };
const V4 = struct { addr: [4]u8, len: u8, metric: u32, ud: bool = false };
const V6 = struct { addr: [16]u8, len: u8, metric: u32, ud: bool = false, x: bool = false };
const NodeSpec = struct {
    reach: []const Nbr = &.{},
    overload: bool = false,
    attached: bool = false,
    is_type: u2 = 1,
    nlpids: []const u8 = &.{},
    v4: []const V4 = &.{},
    v6: []const V6 = &.{},
    fragment: u8 = 0,
};

fn insertNode(db: *lsdb.Lsdb, origin: SystemId, seq: u32, spec: NodeSpec) !void {
    var buf: [1024]u8 = undefined;
    var b = try isis.pdu.LspBuilder.init(&buf, .{
        .remaining_lifetime = 1000,
        .lsp_id = .{ origin[0], origin[1], origin[2], origin[3], origin[4], origin[5], 0, spec.fragment },
        .sequence_number = seq,
        .flags = .{ .partition_repair = false, .attached = if (spec.attached) 1 else 0, .overload = spec.overload, .is_type = spec.is_type },
    });
    if (spec.nlpids.len != 0) try isis.tlvs.addProtocolsSupported(&b.tlvs, spec.nlpids);
    for (spec.reach) |r| {
        const nbr7: [7]u8 = .{ r.nbr[0], r.nbr[1], r.nbr[2], r.nbr[3], r.nbr[4], r.nbr[5], 0 };
        try isis.tlvs.addExtendedIsReach(&b.tlvs, nbr7, r.metric, &.{});
    }
    for (spec.v4) |p| try isis.tlvs.addExtIpReach(&b.tlvs, .{ .metric = p.metric, .prefix_len = p.len, .prefix = p.addr, .up_down = p.ud });
    for (spec.v6) |p| try isis.tlvs.addIpv6Reach(&b.tlvs, .{ .metric = p.metric, .prefix_len = p.len, .prefix = p.addr, .up_down = p.ud, .external = p.x });
    _ = try db.insert(b.finishStamped(), null, 0);
}

fn v4p(a: u8, b: u8, c: u8, d: u8, len: u8) Prefix {
    return .{ .family = .ipv4, .addr = .{ a, b, c, d } ++ @as([12]u8, @splat(0)), .len = len };
}

fn v6p(first: [2]u8, len: u8) Prefix {
    var addr: [16]u8 = @splat(0);
    addr[0..2].* = first;
    return .{ .family = .ipv6, .addr = addr, .len = len };
}

fn linkSpec(nbrs: []const Nbr) NodeSpec {
    return .{ .reach = nbrs };
}

test "overload bit: an overloaded system is a destination but not a transit" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    const c = sysId(0xC);
    const d = sysId(0xD);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();
    // A-B-C line plus a costly detour A-D-C. B is overloaded: C must go via D.
    try insertNode(&db, a, 1, linkSpec(&.{ .{ .nbr = b, .metric = 10 }, .{ .nbr = d, .metric = 50 } }));
    try insertNode(&db, b, 1, .{ .reach = &.{ .{ .nbr = a, .metric = 10 }, .{ .nbr = c, .metric = 10 } }, .overload = true });
    try insertNode(&db, c, 1, linkSpec(&.{ .{ .nbr = b, .metric = 10 }, .{ .nbr = d, .metric = 50 } }));
    try insertNode(&db, d, 1, linkSpec(&.{ .{ .nbr = a, .metric = 50 }, .{ .nbr = c, .metric = 50 } }));
    var t = try compute(testing.allocator, &db, a, 0);
    defer t.deinit();
    try testing.expectEqual(Route{ .dest = b, .next_hop = b, .metric = 10 }, t.lookup(b).?);
    try testing.expectEqual(Route{ .dest = c, .next_hop = d, .metric = 100 }, t.lookup(c).?);
    // Off: the old behaviour, through B.
    var t2 = try computeWith(testing.allocator, &db, a, 0, .{ .honour_overload = false });
    defer t2.deinit();
    try testing.expectEqual(Route{ .dest = c, .next_hop = b, .metric = 20 }, t2.lookup(c).?);
    // The root's own overload bit does not apply to its own computation.
    var db2 = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db2.deinit();
    try insertNode(&db2, a, 1, .{ .reach = &.{.{ .nbr = b, .metric = 10 }}, .overload = true });
    try insertNode(&db2, b, 1, linkSpec(&.{.{ .nbr = a, .metric = 10 }}));
    var t3 = try compute(testing.allocator, &db2, a, 0);
    defer t3.deinit();
    try testing.expectEqual(@as(u64, 10), t3.lookup(b).?.metric);
}

test "overload bit: only fragment 0 counts, and a fully overloaded destination stays reachable" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();
    try insertNode(&db, a, 1, linkSpec(&.{.{ .nbr = b, .metric = 10 }}));
    try insertNode(&db, b, 1, .{ .reach = &.{.{ .nbr = a, .metric = 10 }} });
    // A second fragment of B with the bit set: ignored.
    try insertNode(&db, b, 1, .{ .overload = true, .fragment = 1 });
    var t = try compute(testing.allocator, &db, a, 0);
    defer t.deinit();
    try testing.expectEqual(@as(u64, 10), t.lookup(b).?.metric);
    // Setting it in fragment 0 keeps B reachable as a destination (arcs into B).
    try insertNode(&db, b, 2, .{ .reach = &.{.{ .nbr = a, .metric = 10 }}, .overload = true });
    var t2 = try compute(testing.allocator, &db, a, 0);
    defer t2.deinit();
    try testing.expectEqual(@as(u64, 10), t2.lookup(b).?.metric);
}

fn diamond(db: *lsdb.Lsdb, a: SystemId, b: SystemId, c: SystemId, d: SystemId, wb: u24, wc: u24) !void {
    try insertNode(db, a, 1, linkSpec(&.{ .{ .nbr = b, .metric = wb }, .{ .nbr = c, .metric = wc } }));
    try insertNode(db, b, 1, linkSpec(&.{ .{ .nbr = a, .metric = wb }, .{ .nbr = d, .metric = 10 } }));
    try insertNode(db, c, 1, linkSpec(&.{ .{ .nbr = a, .metric = wc }, .{ .nbr = d, .metric = 10 } }));
    try insertNode(db, d, 1, linkSpec(&.{ .{ .nbr = b, .metric = 10 }, .{ .nbr = c, .metric = 10 } }));
}

test "ECMP: max_paths lists every equal-cost first hop, sorted, and cuts to the limit" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    const c = sysId(0xC);
    const d = sysId(0xD);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();
    try diamond(&db, a, b, c, d, 10, 10);
    var t = try computeWith(testing.allocator, &db, a, 0, .{ .max_paths = 4 });
    defer t.deinit();
    const hops = t.nextHops(d).?;
    try testing.expectEqual(@as(usize, 2), hops.len);
    try testing.expectEqualSlices(u8, &b, &hops[0]);
    try testing.expectEqualSlices(u8, &c, &hops[1]);
    try testing.expectEqualSlices(u8, &b, &t.lookup(d).?.next_hop); // the lowest
    try testing.expectEqual(@as(usize, 1), t.nextHops(b).?.len);
    try testing.expectEqualSlices(u8, &a, &t.nextHops(a).?[0]);
    try testing.expect(t.nextHops(sysId(9)) == null);
    // Cut to 1 keeps the lowest.
    var t1 = try computeWith(testing.allocator, &db, a, 0, .{ .max_paths = 2 });
    defer t1.deinit();
    try testing.expectEqual(@as(usize, 2), t1.nextHops(d).?.len);
    // Unequal costs: a single hop.
    var db2 = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db2.deinit();
    try diamond(&db2, a, b, c, d, 10, 11);
    var t2 = try computeWith(testing.allocator, &db2, a, 0, .{ .max_paths = 4 });
    defer t2.deinit();
    try testing.expectEqual(@as(usize, 1), t2.nextHops(d).?.len);
    try testing.expectEqualSlices(u8, &b, &t2.nextHops(d).?[0]);
    // Default options: nextHops is the single next_hop.
    var t3 = try compute(testing.allocator, &db, a, 0);
    defer t3.deinit();
    try testing.expectEqual(@as(usize, 1), t3.nextHops(d).?.len);
}

test "ECMP: a multi-stage fan-out collects first hops through the DAG" {
    // A -> {B,C} -> {D,E} (full bipartite) -> F: F has the two first hops B and C.
    const a = sysId(0xA);
    const b = sysId(0xB);
    const c = sysId(0xC);
    const d = sysId(0xD);
    const e = sysId(0xE);
    const f = sysId(0xF);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();
    try insertNode(&db, a, 1, linkSpec(&.{ .{ .nbr = b, .metric = 1 }, .{ .nbr = c, .metric = 1 } }));
    try insertNode(&db, b, 1, linkSpec(&.{ .{ .nbr = a, .metric = 1 }, .{ .nbr = d, .metric = 1 }, .{ .nbr = e, .metric = 1 } }));
    try insertNode(&db, c, 1, linkSpec(&.{ .{ .nbr = a, .metric = 1 }, .{ .nbr = d, .metric = 1 }, .{ .nbr = e, .metric = 1 } }));
    try insertNode(&db, d, 1, linkSpec(&.{ .{ .nbr = b, .metric = 1 }, .{ .nbr = c, .metric = 1 }, .{ .nbr = f, .metric = 1 } }));
    try insertNode(&db, e, 1, linkSpec(&.{ .{ .nbr = b, .metric = 1 }, .{ .nbr = c, .metric = 1 }, .{ .nbr = f, .metric = 1 } }));
    try insertNode(&db, f, 1, linkSpec(&.{ .{ .nbr = d, .metric = 1 }, .{ .nbr = e, .metric = 1 } }));
    var t = try computeWith(testing.allocator, &db, a, 0, .{ .max_paths = 8 });
    defer t.deinit();
    try testing.expectEqual(@as(u64, 3), t.lookup(f).?.metric);
    try testing.expectEqual(@as(usize, 2), t.nextHops(f).?.len);
    try testing.expectEqual(@as(usize, 2), t.nextHops(d).?.len);
}

test "prefixes: total metric, next hop and the local prefix; opt-in only" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    const c = sysId(0xC);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();
    try insertNode(&db, a, 1, .{ .reach = &.{.{ .nbr = b, .metric = 10 }}, .v4 = &.{.{ .addr = .{ 10, 0, 0, 0 }, .len = 24, .metric = 1 }} });
    try insertNode(&db, b, 1, .{ .reach = &.{ .{ .nbr = a, .metric = 10 }, .{ .nbr = c, .metric = 5 } } });
    try insertNode(&db, c, 1, .{
        .reach = &.{.{ .nbr = b, .metric = 5 }},
        .v4 = &.{ .{ .addr = .{ 192, 0, 2, 0 }, .len = 24, .metric = 100 }, .{ .addr = .{ 0, 0, 0, 0 }, .len = 0, .metric = 1 } },
        .v6 = &.{.{ .addr = (@as([2]u8, .{ 0x20, 0x01 }) ++ @as([14]u8, @splat(0))), .len = 32, .metric = 7 }},
    });
    var off = try compute(testing.allocator, &db, a, 0);
    defer off.deinit();
    try testing.expectEqual(@as(usize, 0), off.prefixes.len);
    var t = try computeWith(testing.allocator, &db, a, 0, .{ .prefixes = true });
    defer t.deinit();
    try testing.expectEqual(@as(usize, 4), t.prefixes.len);
    const local_p = t.prefixRoute(v4p(10, 0, 0, 0, 24)).?;
    try testing.expectEqual(@as(u64, 1), local_p.metric);
    try testing.expectEqualSlices(u8, &a, &local_p.next_hop);
    const remote = t.prefixRoute(v4p(192, 0, 2, 0, 24)).?;
    try testing.expectEqual(@as(u64, 115), remote.metric);
    try testing.expectEqualSlices(u8, &b, &remote.next_hop);
    try testing.expectEqualSlices(u8, &c, &remote.origin);
    try testing.expectEqual(@as(u64, 16), t.prefixRoute(v4p(0, 0, 0, 0, 0)).?.metric);
    try testing.expectEqual(@as(u64, 22), t.prefixRoute(v6p(.{ 0x20, 0x01 }, 32)).?.metric);
    try testing.expect(t.prefixRoute(v4p(10, 0, 0, 0, 25)) == null);
    // Sorted: IPv4 before IPv6, addresses ascending.
    try testing.expect(t.prefixes[0].prefix.family == .ipv4 and t.prefixes[3].prefix.family == .ipv6);
    try testing.expect(t.prefixes[0].prefix.len == 0);
}

test "prefixes: the best advertiser wins by total metric; ties go to the lowest id, or ECMP" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    const c = sysId(0xC);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();
    const anycast = [_]V4{.{ .addr = .{ 198, 51, 100, 0 }, .len = 24, .metric = 5 }};
    try insertNode(&db, a, 1, linkSpec(&.{ .{ .nbr = b, .metric = 10 }, .{ .nbr = c, .metric = 10 } }));
    try insertNode(&db, b, 1, .{ .reach = &.{.{ .nbr = a, .metric = 10 }}, .v4 = &anycast });
    try insertNode(&db, c, 1, .{ .reach = &.{.{ .nbr = a, .metric = 10 }}, .v4 = &anycast });
    var t = try computeWith(testing.allocator, &db, a, 0, .{ .prefixes = true });
    defer t.deinit();
    const p = t.prefixRoute(v4p(198, 51, 100, 0, 24)).?;
    try testing.expectEqual(@as(u64, 15), p.metric);
    try testing.expectEqualSlices(u8, &b, &p.origin);
    try testing.expectEqual(@as(usize, 1), t.prefixNextHops(p.prefix).?.len);
    var e = try computeWith(testing.allocator, &db, a, 0, .{ .prefixes = true, .max_paths = 4 });
    defer e.deinit();
    const hops = e.prefixNextHops(p.prefix).?;
    try testing.expectEqual(@as(usize, 2), hops.len);
    try testing.expectEqualSlices(u8, &b, &hops[0]);
    try testing.expectEqualSlices(u8, &c, &hops[1]);
    // A cheaper advertisement from C wins outright.
    try insertNode(&db, c, 2, .{ .reach = &.{.{ .nbr = a, .metric = 10 }}, .v4 = &.{.{ .addr = .{ 198, 51, 100, 0 }, .len = 24, .metric = 1 }} });
    var t2 = try computeWith(testing.allocator, &db, a, 0, .{ .prefixes = true, .max_paths = 4 });
    defer t2.deinit();
    try testing.expectEqualSlices(u8, &c, &t2.prefixRoute(p.prefix).?.origin);
    try testing.expectEqual(@as(usize, 1), t2.prefixNextHops(p.prefix).?.len);
}

test "prefixes: Up/Down set loses to clear at any metric in a level-1 database, and is ignored at level 2; external ranks below internal" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    const c = sysId(0xC);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();
    try insertNode(&db, a, 1, linkSpec(&.{ .{ .nbr = b, .metric = 10 }, .{ .nbr = c, .metric = 10 } }));
    // B leaks the prefix from L2 (Up/Down set, cheap); C has it natively (clear, dear).
    try insertNode(&db, b, 1, .{ .reach = &.{.{ .nbr = a, .metric = 10 }}, .v4 = &.{.{ .addr = .{ 203, 0, 113, 0 }, .len = 24, .metric = 1, .ud = true }} });
    try insertNode(&db, c, 1, .{ .reach = &.{.{ .nbr = a, .metric = 10 }}, .v4 = &.{.{ .addr = .{ 203, 0, 113, 0 }, .len = 24, .metric = 50 }} });
    const pfx = v4p(203, 0, 113, 0, 24);
    var l1 = try computeWith(testing.allocator, &db, a, 0, .{ .prefixes = true });
    defer l1.deinit();
    try testing.expectEqualSlices(u8, &c, &l1.prefixRoute(pfx).?.origin);
    try testing.expect(!l1.prefixRoute(pfx).?.up_down);
    var l2 = try computeWith(testing.allocator, &db, a, 0, .{ .prefixes = true, .level2 = true });
    defer l2.deinit();
    try testing.expectEqualSlices(u8, &b, &l2.prefixRoute(pfx).?.origin);
    // IPv6: external (X) ranks below internal even when cheaper.
    var db2 = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db2.deinit();
    const pa: [16]u8 = @as([2]u8, .{ 0x20, 0x01 }) ++ @as([14]u8, @splat(0));
    try insertNode(&db2, a, 1, linkSpec(&.{ .{ .nbr = b, .metric = 10 }, .{ .nbr = c, .metric = 10 } }));
    try insertNode(&db2, b, 1, .{ .reach = &.{.{ .nbr = a, .metric = 10 }}, .v6 = &.{.{ .addr = pa, .len = 32, .metric = 1, .x = true }} });
    try insertNode(&db2, c, 1, .{ .reach = &.{.{ .nbr = a, .metric = 10 }}, .v6 = &.{.{ .addr = pa, .len = 32, .metric = 40 }} });
    var t6 = try computeWith(testing.allocator, &db2, a, 0, .{ .prefixes = true });
    defer t6.deinit();
    const r = t6.prefixRoute(v6p(.{ 0x20, 0x01 }, 32)).?;
    try testing.expectEqualSlices(u8, &c, &r.origin);
    try testing.expect(!r.external);
}

test "prefixes: a prefix of an unreachable or two-way-less system is not routed; a malformed TLV is cut at the bad entry" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    const z = sysId(0xF);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();
    try insertNode(&db, a, 1, linkSpec(&.{.{ .nbr = b, .metric = 10 }}));
    try insertNode(&db, b, 1, .{ .reach = &.{.{ .nbr = a, .metric = 10 }}, .v4 = &.{.{ .addr = .{ 10, 1, 0, 0 }, .len = 16, .metric = 1 }} });
    try insertNode(&db, z, 1, .{ .v4 = &.{.{ .addr = .{ 10, 9, 0, 0 }, .len = 16, .metric = 1 }} });
    var t = try computeWith(testing.allocator, &db, a, 0, .{ .prefixes = true });
    defer t.deinit();
    try testing.expect(t.prefixRoute(v4p(10, 1, 0, 0, 16)) != null);
    try testing.expect(t.prefixRoute(v4p(10, 9, 0, 0, 16)) == null);
    // A bad /33 entry after a good one: the good one still counts.
    var buf: [128]u8 = undefined;
    var lb = try isis.pdu.LspBuilder.init(&buf, .{
        .remaining_lifetime = 1000,
        .lsp_id = .{ b[0], b[1], b[2], b[3], b[4], b[5], 0, 1 },
        .sequence_number = 1,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    });
    try lb.tlvs.addTlv(isis.tlvs.code.extended_ip_reachability, &.{ 0, 0, 0, 1, 8, 172, 0, 0, 0, 1, 33, 1, 2, 3, 4, 5 });
    _ = try db.insert(lb.finishStamped(), null, 0);
    var t2 = try computeWith(testing.allocator, &db, a, 0, .{ .prefixes = true });
    defer t2.deinit();
    try testing.expect(t2.prefixRoute(v4p(172, 0, 0, 0, 8)) != null);
    try testing.expectEqual(@as(usize, 2), t2.prefixes.len);
}

test "attached default: nearest attached system, per supported family, only for a level-1-only local" {
    const a = sysId(0xA);
    const b = sysId(0xB);
    const c = sysId(0xC);
    var db = lsdb.Lsdb.init(testing.allocator, cfgFor(a));
    defer db.deinit();
    const v4only = [_]u8{isis.tlvs.nlpid_ipv4};
    const both = [_]u8{ isis.tlvs.nlpid_ipv4, isis.tlvs.nlpid_ipv6 };
    try insertNode(&db, a, 1, linkSpec(&.{ .{ .nbr = b, .metric = 10 }, .{ .nbr = c, .metric = 5 } }));
    try insertNode(&db, b, 1, .{ .reach = &.{.{ .nbr = a, .metric = 10 }}, .attached = true, .is_type = 3, .nlpids = &both });
    try insertNode(&db, c, 1, .{ .reach = &.{.{ .nbr = a, .metric = 5 }}, .attached = true, .is_type = 3, .nlpids = &v4only });
    var t = try computeWith(testing.allocator, &db, a, 0, .{ .prefixes = true, .attached_default = true });
    defer t.deinit();
    const d4 = t.prefixRoute(v4p(0, 0, 0, 0, 0)).?;
    try testing.expect(d4.attached_default);
    try testing.expectEqualSlices(u8, &c, &d4.next_hop); // nearer
    try testing.expectEqual(@as(u64, 5), d4.metric);
    const d6 = t.prefixRoute(.{ .family = .ipv6, .addr = @splat(0), .len = 0 }).?;
    try testing.expectEqualSlices(u8, &b, &d6.next_hop); // only B supports IPv6
    // An advertised 0/0 beats the synthesised one even when dearer.
    try insertNode(&db, b, 2, .{ .reach = &.{.{ .nbr = a, .metric = 10 }}, .attached = true, .is_type = 3, .nlpids = &both, .v4 = &.{.{ .addr = .{ 0, 0, 0, 0 }, .len = 0, .metric = 100 }} });
    var t2 = try computeWith(testing.allocator, &db, a, 0, .{ .prefixes = true, .attached_default = true });
    defer t2.deinit();
    try testing.expect(!t2.prefixRoute(v4p(0, 0, 0, 0, 0)).?.attached_default);
    // Off by default; and not for an L1/L2 local system.
    var t3 = try computeWith(testing.allocator, &db, a, 0, .{ .prefixes = true });
    defer t3.deinit();
    try testing.expect(t3.prefixRoute(.{ .family = .ipv6, .addr = @splat(0), .len = 0 }) == null);
    try insertNode(&db, a, 2, .{ .reach = &.{ .{ .nbr = b, .metric = 10 }, .{ .nbr = c, .metric = 5 } }, .is_type = 3 });
    var t4 = try computeWith(testing.allocator, &db, a, 0, .{ .prefixes = true, .attached_default = true });
    defer t4.deinit();
    try testing.expect(t4.prefixRoute(.{ .family = .ipv6, .addr = @splat(0), .len = 0 }) == null);
}

test {
    _ = leak;
    _ = @import("bench.zig");
}
