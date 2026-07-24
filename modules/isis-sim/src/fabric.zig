// SPDX-License-Identifier: MIT

//! The IS-IS fabric harness: a `netsim.Protocol` whose opaque context is a
//! `Fabric` holding per-node isis control-plane state (an `isis-lsdb.Lsdb`, an
//! `isis-flood.Scheduler`, the node's own LSP sequence number, and its static
//! neighbour list), plus the small driver that runs it to convergence.
//!
//! ## How the isis stack plugs into netsim's Protocol vtable
//! netsim owns topology + scheduling and calls four hooks; the `Fabric` owns all
//! per-node isis state in `ctx`:
//!   - **onStart(node)** — the node originates its own LSP (Extended IS
//!     Reachability #22 to each currently-up neighbour, sequence 1), inserts it
//!     self-originated (`arrival_iface = null` → SRM set on every circuit), arms
//!     the first flooding poll, and arms one timer per *scheduled link failure*
//!     it is an endpoint of.
//!   - **onMessage(node, from, payload)** — decode the PDU (`isis.decode`): an
//!     LSP is `lsdb.insert`ed on its arrival interface (sets SRM to flood onward
//!     + SSN to ack), a CSNP/PSNP is `reconcileCsnp`/`reconcilePsnp`d. A flooding
//!     poll is then armed so the next `poll` drains the freshly-set flags.
//!   - **onTimer(node, id)** — id 0 = "poll the flooding scheduler now": call
//!     `isis-flood.poll`, `sim.send` each effect (LSP/PSNP/CSNP) to the neighbour
//!     on its interface, and re-arm while work remains. id ≥ `fail_timer_base` =
//!     "a link you are an endpoint of just failed": mark that circuit down, then
//!     re-originate this node's LSP without the lost neighbour at a bumped
//!     sequence number, and flood.
//!   - **check** — a safety invariant checked after every event: no node's LSDB
//!     ever holds more than `node_count` distinct LSP-IDs (a runaway/corruption
//!     tripwire; correct flooding stores exactly one LSP per originator).
//!
//! ## Why link-state changes are driven by a timer, not observed
//! netsim delivers no fault notification to the protocol (its `neighbors` view
//! ignores `link.up`, and there is no adjacency FSM here), so a topology change
//! is modelled as a **scheduled re-origination**: `runToConvergence` injects a
//! netsim `link_down` fault (severing transport) *and* the two endpoints hold a
//! pre-armed timer at the same simulated time that re-originates their LSPs. The
//! pair together models "hello-timeout detected the adjacency down; the LSP was
//! re-originated" without an `isis-adj` FSM. See `SPEC.md`.
//!
//! ## Node ↔ system-id mapping
//! netsim `NodeId` *n* maps to the 6-octet IS-IS system-id `00:00:00:00:HH:LL`
//! of `n + 1` (deterministic, dense, never all-zero). One LSP per node
//! (LSP-number 0, no pseudonodes — P2P only).
//!
//! ## Convergence, quiescence, and termination
//! `runToConvergence` drives `netsim.replay` under a hard step cap (`until` time
//! bound + `max_events_cap` event bound → guaranteed termination). Afterwards it
//! inspects the ctx: the fabric is **quiescent** iff no node has any SRM (flood)
//! or SSN (ack) flag set — i.e. flooding has drained and a further poll would
//! send nothing. Quiescence within the cap ⇒ `.converged`; otherwise
//! `.step_cap_exceeded`. Database *agreement* (`lsdbsAgree`) and route
//! consistency (`routes`/`reaches`) are separate assertions the caller makes on
//! the converged state — a partition quiesces too, and is then detected as an
//! unreachable destination in SPF rather than as a hang.

const std = @import("std");
const Allocator = std.mem.Allocator;

const netsim = @import("netsim");
const isis = @import("isis");
const isis_lsdb = @import("isis-lsdb");
const isis_flood = @import("isis-flood");
const isis_spf = @import("isis-spf");

const NodeId = netsim.NodeId;
const Time = netsim.Time;

/// A 6-octet IS-IS system-id — the node identity in the topology.
pub const SystemId = [6]u8;

/// The deterministic node ↔ system-id map: netsim node *n* ⇒ system-id of
/// `n + 1`, so node 0 is `…:00:01` (never the all-zero id).
pub fn systemIdForNode(node: NodeId) SystemId {
    const v: u16 = @intCast(node + 1);
    return .{ 0, 0, 0, 0, @intCast(v >> 8), @intCast(v & 0xFF) };
}

fn lspIdOf(sys: SystemId, lsp_num: u8) isis_lsdb.LspId {
    return .{ sys[0], sys[1], sys[2], sys[3], sys[4], sys[5], 0, lsp_num };
}

fn neighbourId7(sys: SystemId) [7]u8 {
    return .{ sys[0], sys[1], sys[2], sys[3], sys[4], sys[5], 0 };
}

// ── topology description (the harness input) ─────────────────────────────────

/// One undirected, symmetric-metric adjacency between two nodes.
pub const Edge = struct {
    a: NodeId,
    b: NodeId,
    /// The IS-IS metric advertised in both directions (SPB requires symmetric
    /// metrics). Clamped to ≥ 1 by `isis-spf`.
    metric: u24 = 10,
};

/// A small P2P fabric: how many nodes, and the weighted adjacency list.
pub const Topology = struct {
    node_count: u32,
    edges: []const Edge,
};

/// The result of `runToConvergence`.
pub const Outcome = enum {
    /// The fabric reached a quiesced steady state within the step cap (no SRM/SSN
    /// flag set anywhere). Inspect `lsdbsAgree`/`routes` for the resulting state.
    converged,
    /// The step cap (event/time bound) was hit, or the safety invariant tripped,
    /// before the fabric quiesced.
    step_cap_exceeded,
};

// ── timing knobs (abstract netsim ticks) ─────────────────────────────────────

const link_latency: Time = 2;
/// Delay from an onStart / a receive to the flooding poll that drains the flags.
const poll_delay: Time = 1;
/// Larger than any run horizon: since the medium is lossless every flooded LSP is
/// acknowledged (SRM cleared) long before this fires, so retransmission is inert.
/// This makes flooding purely event-driven — the onMessage-armed poll is the sole
/// drain path, which is exactly what the positive control breaks.
const min_lsp_interval: Time = 10_000_000_000;
/// Larger than any run horizon: exactly one (initial) CSNP per circuit fires;
/// convergence is proven by SRM/SSN flooding, with the one CSNP exercising the
/// SNP reconcile path. No periodic CSNP churn to spoil the quiescence proof.
const csnp_interval: Time = 1_000_000_000;
/// Remaining Lifetime stamped into every originated LSP. The harness never
/// `tick`s the LSDBs, so nothing ages; this only has to stay non-zero.
const lsp_lifetime: u16 = 65_535;

const timer_poll: u64 = 0;
/// Failure-reaction timer ids start here (distinct from `timer_poll`); the
/// failure index is added on.
const fail_timer_base: u64 = 1 << 32;

// ── per-node state ───────────────────────────────────────────────────────────

const Neighbour = struct {
    /// The netsim node on the other end of this circuit.
    node: NodeId,
    metric: u24,
};

const NodeState = struct {
    system_id: SystemId,
    /// One entry per circuit; the circuit index is the array index and is the
    /// `iface` used throughout the isis stack.
    neighbours: []Neighbour,
    /// Per-circuit "this link has failed" flag, mutated during a run by the
    /// failure-reaction timer. Reset to all-false each drive.
    link_failed: []bool,
    lsdb: isis_lsdb.Lsdb,
    sched: isis_flood.Scheduler,
    /// Sequence number of this node's own LSP; bumped on each (re-)origination.
    seq: u32,
};

const Failure = struct { time: Time, a: NodeId, b: NodeId };

// ── the Fabric (the Protocol context) ────────────────────────────────────────

/// A small IS-IS/SPB fabric and the state to run it through netsim. Single-owner;
/// build with `init`, drive with `runToConvergence`, tear down with `deinit`.
pub const Fabric = struct {
    gpa: Allocator,
    nodes: []NodeState,
    seed: u64,
    failures: std.ArrayListUnmanaged(Failure) = .empty,
    /// The current run's time horizon (`until`), so a hook never arms a timer
    /// past the end of the run. Set by `runToConvergence`.
    horizon: Time = 0,
    /// Positive control: when true, `onMessage` inserts the LSP but does NOT arm
    /// the drain poll, so SRM is never flooded onward and far nodes stay ignorant
    /// — deliberately breaks convergence (a permanent test flips it on).
    broken_no_drain: bool = false,

    pub fn init(gpa: Allocator, topo: Topology, seed: u64) Allocator.Error!Fabric {
        const nodes = try gpa.alloc(NodeState, topo.node_count);
        errdefer gpa.free(nodes);

        // Count each node's degree first so we can size its neighbour list.
        var initialized: usize = 0;
        errdefer for (nodes[0..initialized]) |*ns| {
            ns.lsdb.deinit();
            ns.sched.deinit();
            gpa.free(ns.neighbours);
            gpa.free(ns.link_failed);
        };

        for (nodes, 0..) |*ns, i| {
            const node: NodeId = @intCast(i);
            var degree: usize = 0;
            for (topo.edges) |e| {
                if (e.a == node or e.b == node) degree += 1;
            }
            std.debug.assert(degree <= isis_lsdb.max_interfaces);

            const neighbours = try gpa.alloc(Neighbour, degree);
            errdefer gpa.free(neighbours);
            var k: usize = 0;
            for (topo.edges) |e| {
                if (e.a == node) {
                    neighbours[k] = .{ .node = e.b, .metric = e.metric };
                    k += 1;
                } else if (e.b == node) {
                    neighbours[k] = .{ .node = e.a, .metric = e.metric };
                    k += 1;
                }
            }

            const link_failed = try gpa.alloc(bool, degree);
            errdefer gpa.free(link_failed);
            @memset(link_failed, false);

            const sys = systemIdForNode(node);
            ns.* = .{
                .system_id = sys,
                .neighbours = neighbours,
                .link_failed = link_failed,
                .lsdb = isis_lsdb.Lsdb.init(gpa, lsdbConfig(sys, degree, topo.node_count)),
                .sched = isis_flood.Scheduler.init(gpa, schedConfig(sys)),
                .seq = 0,
            };
            initialized += 1;
        }

        return .{ .gpa = gpa, .nodes = nodes, .seed = seed };
    }

    pub fn deinit(self: *Fabric) void {
        for (self.nodes) |*ns| {
            ns.lsdb.deinit();
            ns.sched.deinit();
            self.gpa.free(ns.neighbours);
            self.gpa.free(ns.link_failed);
        }
        self.gpa.free(self.nodes);
        self.failures.deinit(self.gpa);
        self.* = undefined;
    }

    fn lsdbConfig(sys: SystemId, degree: usize, node_count: u32) isis_lsdb.Config {
        return .{
            .local_system_id = sys,
            .interface_count = @intCast(degree),
            // One LSP per originator + slack; bounds the store, never hit here.
            .capacity = node_count + 8,
        };
    }

    fn schedConfig(sys: SystemId) isis_flood.Config {
        return .{
            .local_system_id = sys,
            .min_lsp_transmission_interval = min_lsp_interval,
            .complete_snp_interval = csnp_interval,
        };
    }

    // ── topology-change registration ─────────────────────────────────────────

    /// Register a link failure to inject partway through the next
    /// `runToConvergence`, at a default time comfortably after initial
    /// convergence.
    pub fn failLink(self: *Fabric, a: NodeId, b: NodeId) Allocator.Error!void {
        try self.failLinkAt(a, b, 5_000);
    }

    /// Register a link failure at an explicit simulated time.
    pub fn failLinkAt(self: *Fabric, a: NodeId, b: NodeId, time: Time) Allocator.Error!void {
        try self.failures.append(self.gpa, .{ .time = time, .a = a, .b = b });
    }

    // ── the netsim Protocol vtable ───────────────────────────────────────────

    fn protocol(self: *Fabric) netsim.Protocol {
        return .{
            .ctx = self,
            .onStartFn = onStart,
            .onMessageFn = onMessage,
            .onTimerFn = onTimer,
            .checkFn = check,
            .resetFn = reset,
        };
    }

    fn cast(ctx: *anyopaque) *Fabric {
        return @ptrCast(@alignCast(ctx));
    }

    /// Clear every node's LSDB/scheduler/sequence/link state to the t=0 baseline
    /// so the ctx can be replayed repeatedly. Allocation-free: `deinit` frees, the
    /// re-`init`s allocate nothing.
    fn reset(ctx: *anyopaque) void {
        const self = cast(ctx);
        for (self.nodes, 0..) |*ns, i| {
            const node_count: u32 = @intCast(self.nodes.len);
            ns.lsdb.deinit();
            ns.lsdb = isis_lsdb.Lsdb.init(self.gpa, lsdbConfig(ns.system_id, ns.neighbours.len, node_count));
            ns.sched.deinit();
            ns.sched = isis_flood.Scheduler.init(self.gpa, schedConfig(ns.system_id));
            ns.seq = 0;
            @memset(ns.link_failed, false);
            _ = i;
        }
    }

    fn onStart(ctx: *anyopaque, sim: *netsim.Sim, node: NodeId) anyerror!void {
        const self = cast(ctx);
        const now = sim.timeNow();
        try self.originate(node, now);
        try sim.setTimer(node, poll_delay, timer_poll);
        // Pre-arm the failure-reaction timers for links this node terminates.
        for (self.failures.items, 0..) |f, k| {
            if (f.a == node or f.b == node) {
                try sim.setTimer(node, f.time, fail_timer_base + k);
            }
        }
    }

    fn onMessage(ctx: *anyopaque, sim: *netsim.Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const self = cast(ctx);
        const ns = &self.nodes[node];
        const iface = self.ifaceOf(node, from) orelse return; // not a known neighbour
        const now = sim.timeNow();

        const pdu = isis.decode(payload) catch return; // hostile/short bytes: ignore
        switch (pdu) {
            .lsp => _ = try ns.lsdb.insert(payload, iface, now),
            .csnp => |c| ns.lsdb.reconcileCsnp(c, iface, now),
            .psnp => |p| ns.lsdb.reconcilePsnp(p, iface, now),
            else => return,
        }

        // Positive control: skipping this arm leaves SRM/SSN undrained forever.
        if (self.broken_no_drain) return;
        try sim.setTimer(node, poll_delay, timer_poll);
    }

    fn onTimer(ctx: *anyopaque, sim: *netsim.Sim, node: NodeId, timer_id: u64) anyerror!void {
        const self = cast(ctx);
        const now = sim.timeNow();

        if (timer_id >= fail_timer_base) {
            const ns = &self.nodes[node];
            const f = self.failures.items[timer_id - fail_timer_base];
            const other = if (f.a == node) f.b else f.a;
            if (self.ifaceOf(node, other)) |iface| ns.link_failed[iface] = true;
            // Re-originate without the lost neighbour, at a higher sequence.
            try self.originate(node, now);
        }
        try self.pollAndSend(sim, node, now);
    }

    fn check(ctx: *anyopaque, sim: *const netsim.Sim) anyerror!void {
        _ = sim;
        const self = cast(ctx);
        for (self.nodes) |*ns| {
            // Correct flooding stores exactly one LSP per originator; anything
            // beyond the node count is a runaway/corruption bug.
            if (ns.lsdb.count() > self.nodes.len) return error.LsdbOverflow;
        }
    }

    // ── hook helpers ─────────────────────────────────────────────────────────

    /// (Re-)originate `node`'s own LSP: one Extended IS Reachability #22 entry per
    /// currently-up neighbour, at a freshly bumped sequence number, inserted
    /// self-originated (floods out every circuit).
    fn originate(self: *Fabric, node: NodeId, now: Time) anyerror!void {
        const ns = &self.nodes[node];
        ns.seq += 1;

        var buf: [1024]u8 = undefined;
        var b = try isis.pdu.LspBuilder.init(&buf, .{
            .remaining_lifetime = lsp_lifetime,
            .lsp_id = lspIdOf(ns.system_id, 0),
            .sequence_number = ns.seq,
            .checksum = 0, // "checksumming not in use": equal-seq copies compare .same
            .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
        });
        for (ns.neighbours, 0..) |nb, iface| {
            if (ns.link_failed[iface]) continue;
            const nbr_sys = self.nodes[nb.node].system_id;
            try isis.tlvs.addExtendedIsReach(&b.tlvs, neighbourId7(nbr_sys), nb.metric, &.{});
        }
        _ = try ns.lsdb.insert(b.finish(), null, now);
    }

    /// Run one flooding poll for `node` and physically send every effect to the
    /// neighbour on its circuit; re-arm the poll while flooding work remains.
    fn pollAndSend(self: *Fabric, sim: *netsim.Sim, node: NodeId, now: Time) anyerror!void {
        const ns = &self.nodes[node];
        const up = self.upInterfaces(node);

        var out: [64]isis_flood.Effect = undefined;
        var scratch: [4096]u8 = undefined;
        const r = ns.sched.poll(now, up, &ns.lsdb, &out, &scratch);

        for (r.effects) |e| {
            const nbr = ns.neighbours[e.iface].node;
            try sim.send(node, nbr, e.bytes);
        }

        // Self-terminating: only re-arm when we actually sent something (a
        // zero-effect poll means SRM/SSN drained → quiesce). Never arm past the
        // run horizon.
        if (r.truncated) {
            if (now + 1 <= self.horizon) try sim.setTimer(node, 1, timer_poll);
        } else if (r.effects.len > 0) {
            if (r.next_wakeup) |w| {
                if (w > now and w <= self.horizon) try sim.setTimer(node, w - now, timer_poll);
            }
        }
    }

    fn ifaceOf(self: *const Fabric, node: NodeId, neighbour: NodeId) ?u8 {
        for (self.nodes[node].neighbours, 0..) |nb, i| {
            if (nb.node == neighbour) return @intCast(i);
        }
        return null;
    }

    fn upInterfaces(self: *const Fabric, node: NodeId) isis_flood.InterfaceSet {
        var s = isis_flood.InterfaceSet.initEmpty();
        const ns = &self.nodes[node];
        for (ns.link_failed, 0..) |failed, i| {
            if (!failed) s.set(@intCast(i));
        }
        return s;
    }

    // ── the driver ───────────────────────────────────────────────────────────

    /// Drive the fabric through `netsim.replay` until it quiesces or the hard step
    /// cap is hit. `max_steps` bounds both the simulated-time horizon and (× a
    /// small factor) the processed-event count — so this ALWAYS terminates.
    pub fn runToConvergence(self: *Fabric, max_steps: Time) anyerror!Outcome {
        self.horizon = max_steps;

        // Build the fault trace: sever each scheduled link (both directions) at
        // its time. The endpoints' pre-armed timers re-originate in lock-step.
        var trace: std.ArrayListUnmanaged(netsim.FaultEvent) = .empty;
        defer trace.deinit(self.gpa);
        for (self.failures.items) |f| {
            try trace.append(self.gpa, .{ .time = f.time, .kind = .{ .link_down = .{ .a = f.a, .b = f.b } } });
            try trace.append(self.gpa, .{ .time = f.time, .kind = .{ .link_down = .{ .a = f.b, .b = f.a } } });
        }

        const case = netsim.Case{
            .seed = self.seed,
            .scenario = buildScenario,
            .protocol = self.protocol(),
            .until = max_steps,
            // A ≤6-node lossless fabric processes a few hundred events; this hard
            // ceiling bounds memory even against a non-terminating bug.
            .max_events_cap = 200_000,
        };

        g_active_fabric = self;
        defer g_active_fabric = null;

        const result = try netsim.replay(self.gpa, case, trace.items, null);
        if (result.outcome == .violated) return .step_cap_exceeded;
        if (result.events_processed >= case.max_events_cap) return .step_cap_exceeded;
        if (!self.allQuiescent()) return .step_cap_exceeded;
        return .converged;
    }

    // ── convergence / quiescence inspection ──────────────────────────────────

    /// A node is quiescent when it has nothing left to flood (no SRM) and nothing
    /// left to acknowledge (no SSN) on any *up* circuit — a further poll would send
    /// nothing. SRM/SSN left set on a *failed* circuit is intentionally ignored: a
    /// down link never acks, so the re-origination that set SRM on it can never
    /// clear it, and that circuit is never polled.
    fn quiescent(self: *const Fabric, node: NodeId) bool {
        const ns = &self.nodes[node];
        const up = self.upInterfaces(node);
        var srm = ns.lsdb.interfacesWithSrm();
        srm.setIntersection(up);
        if (srm.count() != 0) return false;
        var iface: u8 = 0;
        while (iface < ns.neighbours.len) : (iface += 1) {
            if (!up.isSet(iface)) continue;
            var it = ns.lsdb.ssnIterator(iface);
            if (it.next() != null) return false;
        }
        return true;
    }

    fn allQuiescent(self: *const Fabric) bool {
        var node: NodeId = 0;
        while (node < self.nodes.len) : (node += 1) {
            if (!self.quiescent(node)) return false;
        }
        return true;
    }

    /// Whether every node's LSDB agrees on the stored `(originator → sequence)`
    /// for every originator — the convergence invariant. Compares each node to
    /// node 0 over all originators; a partitioned fabric will NOT agree (use the
    /// SPF-reachability accessors there instead).
    pub fn lsdbsAgree(self: *const Fabric) bool {
        const now: Time = 0;
        var origin: NodeId = 0;
        while (origin < self.nodes.len) : (origin += 1) {
            const id = lspIdOf(systemIdForNode(origin), 0);
            const ref = self.nodes[0].lsdb.get(id, now);
            var node: NodeId = 1;
            while (node < self.nodes.len) : (node += 1) {
                const got = self.nodes[node].lsdb.get(id, now);
                if ((ref == null) != (got == null)) return false;
                if (ref) |rv| {
                    if (rv.sequence_number != got.?.sequence_number) return false;
                }
            }
        }
        return true;
    }

    /// The stored sequence number a given node holds for `origin`'s LSP, or `null`
    /// if it holds none.
    pub fn storedSequence(self: *const Fabric, node: NodeId, origin: NodeId) ?u32 {
        const id = lspIdOf(systemIdForNode(origin), 0);
        const v = self.nodes[node].lsdb.get(id, 0) orelse return null;
        return v.sequence_number;
    }

    /// The current sequence number of `node`'s own LSP (how many times it has
    /// originated).
    pub fn selfSequence(self: *const Fabric, node: NodeId) u32 {
        return self.nodes[node].seq;
    }

    /// The system-id `node` was assigned.
    pub fn systemIdOf(self: *const Fabric, node: NodeId) SystemId {
        return self.nodes[node].system_id;
    }

    /// Compute `node`'s SPF forwarding table from its (converged) LSDB. Caller
    /// owns the result — call `.deinit()`.
    pub fn routes(self: *const Fabric, gpa: Allocator, node: NodeId) Allocator.Error!isis_spf.RouteTable {
        return isis_spf.compute(gpa, &self.nodes[node].lsdb, self.nodes[node].system_id, 0);
    }

    /// Whether `from` can reach `to` in its SPF table, and if so the next-hop
    /// system-id — a one-call reachability probe.
    pub fn reaches(self: *const Fabric, gpa: Allocator, from: NodeId, to: NodeId) Allocator.Error!?SystemId {
        var table = try self.routes(gpa, from);
        defer table.deinit();
        return table.nextHop(systemIdForNode(to));
    }
};

// ── the netsim Scenario seam ─────────────────────────────────────────────────
//
// netsim's `Scenario` is a bare `fn (*Sim)` with no context, so the active
// Fabric is handed in through a thread-local set by `runToConvergence` around
// the single-threaded `replay`. This is the only way to parameterise the
// topology the engine builds; it is deterministic because the sim is driven on
// one thread and the pointer is set before, and cleared after, each replay.
threadlocal var g_active_fabric: ?*Fabric = null;

fn buildScenario(sim: *netsim.Sim) anyerror!void {
    const fab = g_active_fabric orelse return error.NoActiveFabric;
    var i: usize = 0;
    while (i < fab.nodes.len) : (i += 1) _ = try sim.addNode(.{});
    // One bidirectional link per neighbour pair. Iterate node 0's view and add
    // each undirected edge once (a < b) to avoid double links.
    for (fab.nodes, 0..) |ns, a| {
        for (ns.neighbours) |nb| {
            if (@as(usize, nb.node) > a) {
                try sim.addBiLink(@intCast(a), nb.node, .{ .latency = link_latency });
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// tests
// ─────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A ≤6-node fabric runs to convergence well within this many ticks.
const step_cap: Time = 100_000;

fn lineTopology(edges: *[3]Edge) Topology {
    // A(0)—B(1)—C(2)—D(3), metric 10 each.
    edges.* = .{
        .{ .a = 0, .b = 1, .metric = 10 },
        .{ .a = 1, .b = 2, .metric = 10 },
        .{ .a = 2, .b = 3, .metric = 10 },
    };
    return .{ .node_count = 4, .edges = edges };
}

test "convergence: a 4-node line synchronises every LSDB to all 4 originators" {
    var edges: [3]Edge = undefined;
    const topo = lineTopology(&edges);
    var fab = try Fabric.init(testing.allocator, topo, 0xA11CE);
    defer fab.deinit();

    try testing.expectEqual(Outcome.converged, try fab.runToConvergence(step_cap));
    try testing.expect(fab.lsdbsAgree());

    // Every node holds every originator's LSP at sequence 1.
    var node: NodeId = 0;
    while (node < 4) : (node += 1) {
        var origin: NodeId = 0;
        while (origin < 4) : (origin += 1) {
            try testing.expectEqual(@as(?u32, 1), fab.storedSequence(node, origin));
        }
    }
}

test "convergence: a 5-node topology with a cycle converges; all DBs agree" {
    // A square A-B-C-D-A (cycle) plus a stub E hanging off C.
    const edges = [_]Edge{
        .{ .a = 0, .b = 1, .metric = 10 },
        .{ .a = 1, .b = 2, .metric = 10 },
        .{ .a = 2, .b = 3, .metric = 10 },
        .{ .a = 3, .b = 0, .metric = 10 },
        .{ .a = 2, .b = 4, .metric = 10 },
    };
    var fab = try Fabric.init(testing.allocator, .{ .node_count = 5, .edges = &edges }, 0xC0FFEE);
    defer fab.deinit();

    try testing.expectEqual(Outcome.converged, try fab.runToConvergence(step_cap));
    try testing.expect(fab.lsdbsAgree());
    var origin: NodeId = 0;
    while (origin < 5) : (origin += 1) {
        try testing.expectEqual(@as(?u32, 1), fab.storedSequence(0, origin));
    }
}

test "SPF consistency: on the line every node reaches every other, with exact next-hops" {
    var edges: [3]Edge = undefined;
    const topo = lineTopology(&edges);
    var fab = try Fabric.init(testing.allocator, topo, 1);
    defer fab.deinit();
    try testing.expectEqual(Outcome.converged, try fab.runToConvergence(step_cap));

    // Every node reaches every other.
    var from: NodeId = 0;
    while (from < 4) : (from += 1) {
        var to: NodeId = 0;
        while (to < 4) : (to += 1) {
            if (from == to) continue;
            try testing.expect((try fab.reaches(testing.allocator, from, to)) != null);
        }
    }

    // D(3) toward A(0): next hop is C(2). A(0) toward D(3): next hop is B(1).
    try testing.expectEqual(systemIdForNode(2), (try fab.reaches(testing.allocator, 3, 0)).?);
    try testing.expectEqual(systemIdForNode(1), (try fab.reaches(testing.allocator, 0, 3)).?);

    // Exact metric A→D over three hops of 10.
    var ta = try fab.routes(testing.allocator, 0);
    defer ta.deinit();
    try testing.expectEqual(@as(u64, 30), ta.lookup(systemIdForNode(3)).?.metric);
}

test "reconvergence: failing A-B on a square reroutes A→B the long way, seqs bumped" {
    // Square A(0)-B(1)-C(2)-D(3)-A, all metric 10. An alternate path A-D-C-B
    // exists, so failing A-B reroutes rather than partitions.
    const edges = [_]Edge{
        .{ .a = 0, .b = 1, .metric = 10 },
        .{ .a = 1, .b = 2, .metric = 10 },
        .{ .a = 2, .b = 3, .metric = 10 },
        .{ .a = 3, .b = 0, .metric = 10 },
    };
    var fab = try Fabric.init(testing.allocator, .{ .node_count = 4, .edges = &edges }, 42);
    defer fab.deinit();

    // Pre-failure: A reaches B directly (metric 10).
    try fab.failLinkAt(0, 1, 5_000);
    try testing.expectEqual(Outcome.converged, try fab.runToConvergence(step_cap));

    // After the mid-run failure the fabric re-converged: databases agree again,
    // and A and B re-originated (their own LSPs are at sequence 2).
    try testing.expect(fab.lsdbsAgree());
    try testing.expectEqual(@as(u32, 2), fab.selfSequence(0));
    try testing.expectEqual(@as(u32, 2), fab.selfSequence(1));

    // A now reaches B via D (the long way A-D-C-B), metric 30, next-hop D.
    var ta = try fab.routes(testing.allocator, 0);
    defer ta.deinit();
    const rb = ta.lookup(systemIdForNode(1)).?;
    try testing.expectEqual(systemIdForNode(3), rb.next_hop); // via D
    try testing.expectEqual(@as(u64, 30), rb.metric);
}

test "partition: failing a leaf's only link makes it unreachable everywhere, not a hang" {
    // Line A(0)-B(1)-C(2)-D(3); D is a leaf. Failing C-D partitions D.
    var edges: [3]Edge = undefined;
    const topo = lineTopology(&edges);
    var fab = try Fabric.init(testing.allocator, topo, 7);
    defer fab.deinit();

    try fab.failLinkAt(2, 3, 5_000);
    // Still returns .converged (both sides quiesce — a partition is a steady
    // state, not a spin).
    try testing.expectEqual(Outcome.converged, try fab.runToConvergence(step_cap));

    // D is unreachable from every node on the main side (A, B, C).
    var from: NodeId = 0;
    while (from < 3) : (from += 1) {
        try testing.expect((try fab.reaches(testing.allocator, from, 3)) == null);
    }
    // And the main side is still fully connected among itself.
    try testing.expect((try fab.reaches(testing.allocator, 0, 2)) != null);
}

test "quiescence: a converged fabric has no pending SRM/SSN and would send nothing more" {
    var edges: [3]Edge = undefined;
    const topo = lineTopology(&edges);
    var fab = try Fabric.init(testing.allocator, topo, 3);
    defer fab.deinit();
    try testing.expectEqual(Outcome.converged, try fab.runToConvergence(step_cap));

    // No SRM (flood) or SSN (ack) flag remains set on any node — flooding fully
    // drained; a further poll on any circuit would emit nothing.
    var node: NodeId = 0;
    while (node < 4) : (node += 1) {
        try testing.expect(fab.quiescent(node));
    }
    try testing.expect(fab.allQuiescent());
}

test "determinism: identical fabric + fault schedule yields identical final LSDBs" {
    const Build = struct {
        fn run(gpa: Allocator) !Fabric {
            const edges = [_]Edge{
                .{ .a = 0, .b = 1, .metric = 10 },
                .{ .a = 1, .b = 2, .metric = 10 },
                .{ .a = 2, .b = 3, .metric = 10 },
                .{ .a = 3, .b = 0, .metric = 10 },
            };
            var fab = try Fabric.init(gpa, .{ .node_count = 4, .edges = &edges }, 0xD37);
            errdefer fab.deinit();
            try fab.failLinkAt(0, 1, 5_000);
            _ = try fab.runToConvergence(step_cap);
            return fab;
        }
    };
    var f1 = try Build.run(testing.allocator);
    defer f1.deinit();
    var f2 = try Build.run(testing.allocator);
    defer f2.deinit();

    // Every node holds the identical (originator → sequence) map in both runs.
    var node: NodeId = 0;
    while (node < 4) : (node += 1) {
        var origin: NodeId = 0;
        while (origin < 4) : (origin += 1) {
            try testing.expectEqual(f1.storedSequence(node, origin), f2.storedSequence(node, origin));
        }
        try testing.expectEqual(f1.selfSequence(node), f2.selfSequence(node));
    }
}

test "positive control: breaking the flood-drain leaves far nodes ignorant (RED)" {
    // With drain armed (correct) the line converges — asserted above. Break it:
    // onMessage inserts but never floods onward, so 2+-hop LSPs never propagate.
    var edges: [3]Edge = undefined;
    const topo = lineTopology(&edges);
    var fab = try Fabric.init(testing.allocator, topo, 99);
    defer fab.deinit();
    fab.broken_no_drain = true;

    _ = try fab.runToConvergence(step_cap);

    // The databases do NOT agree: D (node 3) never learns A (node 0), two hops
    // away. This is the sentinel that the flood-propagation wiring is required.
    try testing.expect(!fab.lsdbsAgree());
    try testing.expect(fab.storedSequence(3, 0) == null); // D lacks A's LSP
}
