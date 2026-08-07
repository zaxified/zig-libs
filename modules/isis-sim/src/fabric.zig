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
//!     on its interface, and re-arm while work remains. id 1 = "you cold-
//!     restarted": drop this node's LSDB and flooding state and re-originate
//!     (`coldRestart` — the only divergence a P2P fabric cannot repair by
//!     retransmission, and hence the one that measures the CSNP resync path).
//!     id ≥ `fail_timer_base` = "a link you are an endpoint of just failed":
//!     mark that circuit down, then re-originate this node's LSP without the
//!     lost neighbour at a bumped sequence number, and flood.
//!   - **check** — the safety invariants checked after every event: (1) no
//!     node's LSDB ever holds more than `node_count` distinct LSP-IDs (a
//!     runaway/corruption tripwire; correct flooding stores exactly one LSP per
//!     originator), and (2) no node's stored sequence number for an originator
//!     ever decreases, and no LSP it already holds ever disappears (nothing ages
//!     or is purged here). Both have a permanent positive control in the tests,
//!     so each is known to be capable of firing — see `extra_fragments` and
//!     `broken_wipe_node`. A violation is recorded in `Fabric.violation` as well
//!     as stopping the run.
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
/// "This node cold-restarted": drop its LSDB and its flooding state and
/// re-originate (see `Fabric.restart`).
const timer_restart: u64 = 1;
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

/// How the run is configured beyond the topology. The defaults reproduce the
/// original harness exactly — a **perfect** medium with retransmission switched
/// off — so every pre-existing test is unaffected. The wave-2 audit's HIGH
/// finding was that this was the *only* configuration ever exercised, i.e. the
/// one condition under which IS-IS flooding is trivially correct.
pub const Options = struct {
    /// The per-link medium handed to `netsim`. `netsim` models loss,
    /// duplication, reordering and jitter on every link; turning them on is
    /// what makes the flooding result mean something.
    link: netsim.LinkConfig = .{ .latency = link_latency },
    /// `isis-flood`'s minimum LSP transmission interval — the **retransmit**
    /// timer. The default is larger than any run horizon, so retransmission is
    /// inert; that is only sound on a lossless medium. Any run with
    /// `link.loss_permille > 0` (or a `drop_once` fault) MUST lower this, or a
    /// dropped LSP is never resent and the fabric provably cannot converge.
    retransmit_interval: Time = min_lsp_interval,
    /// `isis-flood`'s periodic CSNP interval. Lowering it turns the
    /// database-summary resync path from a single startup event into a live
    /// repair mechanism — which is what actually recovers a database after
    /// loss.
    csnp_interval: Time = csnp_interval,
};

// ── the Fabric (the Protocol context) ────────────────────────────────────────

/// A small IS-IS/SPB fabric and the state to run it through netsim. Single-owner;
/// build with `init`, drive with `runToConvergence`, tear down with `deinit`.
pub const Fabric = struct {
    gpa: Allocator,
    nodes: []NodeState,
    seed: u64,
    opts: Options = .{},
    failures: std.ArrayListUnmanaged(Failure) = .empty,
    /// Extra one-shot / partition fault events merged into the trace built by
    /// `runToConvergence`, on top of the `link_down` pairs `failures` produces.
    /// `netsim` has always supported these; nothing used to add any.
    extra_faults: std.ArrayListUnmanaged(netsim.FaultEvent) = .empty,
    /// The current run's time horizon (`until`), so a hook never arms a timer
    /// past the end of the run. Set by `runToConvergence`.
    horizon: Time = 0,
    /// Positive control: when true, `onMessage` inserts the LSP but does NOT arm
    /// the drain poll, so SRM is never flooded onward and far nodes stay ignorant
    /// — deliberately breaks convergence (a permanent test flips it on).
    broken_no_drain: bool = false,

    /// Per-(node, originator) high-water mark of the stored sequence number,
    /// `nodes.len * nodes.len` entries indexed `node * n + origin`. Zero means
    /// "never seen". Maintained by `check` after every event so a *transient*
    /// regression — one that self-heals before the run ends and is therefore
    /// invisible to every end-of-run assertion — is still caught.
    seen_seq: []u32,

    /// The first safety-invariant `check` raised during the last run, or null.
    /// Recorded here as well as inside netsim because `runToConvergence`
    /// collapses "invariant violated", "event cap hit" and "did not quiesce"
    /// into the single `.step_cap_exceeded` value, so the outcome alone cannot
    /// say *which* happened.
    violation: ?anyerror = null,

    /// Positive control for the LSDB-count tripwire: originate this many extra
    /// LSP fragments (LSP-numbers 1..n) alongside the real LSP-number 0. Every
    /// fragment is a distinct LSP-ID, so each node's database grows past the
    /// "exactly one LSP per originator" bound that `check` asserts. Zero (the
    /// default) is the normal, correct fabric.
    extra_fragments: u8 = 0,

    /// Positive control for the sequence-monotonicity invariant: the first time
    /// this node receives a message while already holding ≥ 2 LSPs, its whole
    /// LSDB is dropped and re-initialised — the shape of a store that loses
    /// entries. `null` (the default) is the normal fabric.
    broken_wipe_node: ?NodeId = null,
    wipe_done: bool = false,

    /// A scheduled **cold restart**: at `time`, `node` loses its whole LSDB and
    /// its flooding state and re-originates its own LSP (see `coldRestart`).
    ///
    /// This is the one divergence a point-to-point fabric cannot repair by
    /// retransmission, and therefore the only way to measure the CSNP resync
    /// path at all. On P2P, `isis-lsdb` clears SRM only when the neighbour has
    /// demonstrably got the LSP (a PSNP ack, or a summary that compares
    /// `.same`), so *every* undelivered LSP leaves SRM set at the sender and the
    /// retransmit timer alone repairs it — a CSNP can only ever re-set an SRM
    /// that is already set. After a restart the opposite holds: the neighbours
    /// were acked long ago, hold no SRM toward the restarted node, and nothing
    /// but a database summary can discover that it is missing anything.
    restart: ?struct { node: NodeId, time: Time } = null,

    /// Positive control for the SNP path: when true, `onMessage` drops every
    /// CSNP and PSNP, so `reconcileCsnp`/`reconcilePsnp` never run. Flooding
    /// (LSP + SRM + retransmit) is untouched. Every lossy test in this module
    /// repaired itself by retransmission, so the SNP path had no control of its
    /// own and no test would have noticed it doing nothing.
    ignore_snp: bool = false,

    pub fn init(gpa: Allocator, topo: Topology, seed: u64) Allocator.Error!Fabric {
        return initWithOptions(gpa, topo, seed, .{});
    }

    pub fn initWithOptions(
        gpa: Allocator,
        topo: Topology,
        seed: u64,
        opts: Options,
    ) Allocator.Error!Fabric {
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
                .sched = isis_flood.Scheduler.init(gpa, schedConfig(sys, opts)),
                .seq = 0,
            };
            initialized += 1;
        }

        // Sized n×n; the `initialized`/`nodes` errdefers above still cover a
        // failure here, so no extra unwind is needed.
        const seen_seq = try gpa.alloc(u32, topo.node_count * topo.node_count);
        @memset(seen_seq, 0);

        return .{ .gpa = gpa, .nodes = nodes, .seed = seed, .opts = opts, .seen_seq = seen_seq };
    }

    pub fn deinit(self: *Fabric) void {
        for (self.nodes) |*ns| {
            ns.lsdb.deinit();
            ns.sched.deinit();
            self.gpa.free(ns.neighbours);
            self.gpa.free(ns.link_failed);
        }
        self.gpa.free(self.seen_seq);
        self.gpa.free(self.nodes);
        self.failures.deinit(self.gpa);
        self.extra_faults.deinit(self.gpa);
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

    fn schedConfig(sys: SystemId, opts: Options) isis_flood.Config {
        return .{
            .local_system_id = sys,
            .min_lsp_transmission_interval = opts.retransmit_interval,
            .complete_snp_interval = opts.csnp_interval,
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
            ns.sched = isis_flood.Scheduler.init(self.gpa, schedConfig(ns.system_id, self.opts));
            ns.seq = 0;
            @memset(ns.link_failed, false);
            _ = i;
        }
        // Per-run invariant state (netsim calls `reset` at the top of every
        // drive, so this is the run's baseline).
        @memset(self.seen_seq, 0);
        self.violation = null;
        self.wipe_done = false;
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
        // Pre-arm the cold restart, if this is the node that suffers one.
        if (self.restart) |r| {
            if (r.node == node and r.time <= self.horizon) try sim.setTimer(node, r.time, timer_restart);
        }
    }

    /// A cold restart of `node`: its link-state database and its whole flooding
    /// state (SRM/SSN, the last-sent pacing map, the CSNP cadence) are gone, and
    /// it re-originates its own LSP at a bumped sequence number — ISO/IEC 10589
    /// §7.3.16.1 forbids it from adopting the copy its neighbours still hold.
    ///
    /// Its neighbours are unaffected and, crucially, hold **no SRM** toward it:
    /// they were acked before the restart. So nothing they do on their own will
    /// re-send it anything, and the LSPs it lost come back only if a database
    /// summary discovers the divergence.
    fn coldRestart(self: *Fabric, node: NodeId, now: Time) anyerror!void {
        const ns = &self.nodes[node];
        const n = self.nodes.len;
        ns.lsdb.deinit();
        ns.lsdb = isis_lsdb.Lsdb.init(self.gpa, lsdbConfig(ns.system_id, ns.neighbours.len, @intCast(n)));
        ns.sched.deinit();
        ns.sched = isis_flood.Scheduler.init(self.gpa, schedConfig(ns.system_id, self.opts));
        // `check`'s monotonicity invariant is "no stored sequence goes backwards
        // *absent a restart*". This is the restart, and it clears the high-water
        // marks of the restarting node only — every other node's row, and this
        // node's own future, stay under the invariant.
        @memset(self.seen_seq[node * n ..][0..n], 0);
        try self.originate(node, now);
    }

    fn onMessage(ctx: *anyopaque, sim: *netsim.Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const self = cast(ctx);
        const ns = &self.nodes[node];
        const iface = self.ifaceOf(node, from) orelse return; // not a known neighbour
        const now = sim.timeNow();

        const pdu = isis.decode(payload) catch return; // hostile/short bytes: ignore
        switch (pdu) {
            .lsp => _ = try ns.lsdb.insert(payload, iface, now),
            // The SNP positive control: drop the summary rather than reconcile
            // it, leaving flooding as the only mechanism in the fabric.
            .csnp => |c| {
                if (self.ignore_snp) return;
                ns.lsdb.reconcileCsnp(c, iface, now);
            },
            .psnp => |p| {
                if (self.ignore_snp) return;
                ns.lsdb.reconcilePsnp(p, iface, now);
            },
            else => return,
        }

        // Positive control for `check`'s monotonicity invariant: drop this
        // node's whole database once it has learned something. Nothing in the
        // end-of-run assertions would notice (the fabric re-floods and
        // re-converges); only a per-event hook can.
        if (self.broken_wipe_node) |wn| {
            if (!self.wipe_done and node == wn and ns.lsdb.count() >= 2) {
                self.wipe_done = true;
                ns.lsdb.deinit();
                ns.lsdb = isis_lsdb.Lsdb.init(
                    self.gpa,
                    lsdbConfig(ns.system_id, ns.neighbours.len, @intCast(self.nodes.len)),
                );
            }
        }

        // Positive control: skipping this arm leaves SRM/SSN undrained forever.
        if (self.broken_no_drain) return;
        try sim.setTimer(node, poll_delay, timer_poll);
    }

    fn onTimer(ctx: *anyopaque, sim: *netsim.Sim, node: NodeId, timer_id: u64) anyerror!void {
        const self = cast(ctx);
        const now = sim.timeNow();

        if (timer_id == timer_restart) {
            try self.coldRestart(node, now);
        } else if (timer_id >= fail_timer_base) {
            const ns = &self.nodes[node];
            const f = self.failures.items[timer_id - fail_timer_base];
            const other = if (f.a == node) f.b else f.a;
            if (self.ifaceOf(node, other)) |iface| ns.link_failed[iface] = true;
            // Re-originate without the lost neighbour, at a higher sequence.
            try self.originate(node, now);
        }
        try self.pollAndSend(sim, node, now);
    }

    /// Record and raise a safety-invariant violation. `check` never overwrites
    /// an earlier one (netsim stops the run on the first).
    fn violate(self: *Fabric, e: anyerror) anyerror!void {
        if (self.violation == null) self.violation = e;
        return e;
    }

    /// The per-event safety hook — netsim calls this after EVERY event, so it is
    /// the harness's only continuous oracle. Everything else (`lsdbsAgree`,
    /// routes, quiescence) is asserted once, at the end, and therefore cannot
    /// see a violation that repairs itself before the run finishes.
    ///
    /// Both invariants below have a permanent positive control in the tests
    /// (`extra_fragments` for the first, `broken_wipe_node` for the second), so
    /// each is known to be *capable* of firing and its bound is known to be
    /// tight. An invariant that has never been watched fire is decoration.
    fn check(ctx: *anyopaque, sim: *const netsim.Sim) anyerror!void {
        _ = sim;
        const self = cast(ctx);
        const n = self.nodes.len;
        for (self.nodes, 0..) |*ns, node| {
            // (1) Correct flooding stores exactly one LSP per originator;
            // anything beyond the node count is a runaway/corruption bug.
            if (ns.lsdb.count() > n) return self.violate(error.LsdbOverflow);

            // (2) A stored sequence number never goes backwards, and an LSP a
            // node already holds never disappears (this harness never ticks
            // lifetimes, so nothing ages out and nothing is purged). Absence is
            // modelled as sequence 0, so "held, then gone" is caught by the
            // same comparison as "held, then rolled back".
            var origin: usize = 0;
            while (origin < n) : (origin += 1) {
                const id = lspIdOf(systemIdForNode(@intCast(origin)), 0);
                const cur: u32 = if (ns.lsdb.get(id, 0)) |v| v.sequence_number else 0;
                const slot = &self.seen_seq[node * n + origin];
                if (cur < slot.*) return self.violate(error.SequenceRegression);
                slot.* = cur;
            }
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
            .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
        });
        for (ns.neighbours, 0..) |nb, iface| {
            if (ns.link_failed[iface]) continue;
            const nbr_sys = self.nodes[nb.node].system_id;
            try isis.tlvs.addExtendedIsReach(&b.tlvs, neighbourId7(nbr_sys), nb.metric, &.{});
        }
        // ISO 10589 §7.3.11: the *source* IS computes the LSP Checksum when the
        // LSP is generated. This is that source, so it stamps — and it must, or
        // the very first hop's `insert` (which arrives on a circuit, and so runs
        // the §7.3.14.2 e) receive check) discards the LSP as corrupt and the
        // fabric never floods anything. Two nodes holding the same LSP hold the
        // same bytes, so equal-sequence copies still compare `.same`.
        _ = try ns.lsdb.insert(b.finishStamped(), null, now);

        // Positive control for `check`'s LSDB-count tripwire: emit additional
        // LSP fragments for this system. Each is a distinct LSP-ID, so the
        // "exactly one LSP per originator" bound is exceeded within a couple of
        // flooding hops — at a count just above `node_count`, not orders of
        // magnitude above it.
        var frag: u8 = 1;
        while (frag <= self.extra_fragments) : (frag += 1) {
            var fbuf: [1024]u8 = undefined;
            var fb = try isis.pdu.LspBuilder.init(&fbuf, .{
                .remaining_lifetime = lsp_lifetime,
                .lsp_id = lspIdOf(ns.system_id, frag),
                .sequence_number = ns.seq,
                .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
            });
            _ = try ns.lsdb.insert(fb.finishStamped(), null, now);
        }
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

        // Self-terminating: re-arm only while flooding work remains, and never
        // past the run horizon.
        //
        // The `effects.len > 0` clause used to guard this, which quietly made
        // **retransmission unreachable**: a poll whose LSP was dropped by the
        // medium emits nothing (the pacing gate holds it) yet reports a
        // `next_wakeup` at the retransmit deadline — and with no timer armed
        // for it, the node parked forever with SRM still set. Honouring
        // `next_wakeup` regardless of the effect count is what lets the
        // retransmit path run at all, and it is still self-terminating because
        // `poll` returns `next_wakeup == null` once SRM/SSN have drained.
        if (r.truncated) {
            if (now + 1 <= self.horizon) try sim.setTimer(node, 1, timer_poll);
        } else if (r.next_wakeup) |w| {
            if (w > now and w <= self.horizon) try sim.setTimer(node, w - now, timer_poll);
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
        // One-shot drops / duplications / delays and partition+heal pairs the
        // caller registered. `netsim.replay` sorts by time, so append order
        // does not matter.
        try trace.appendSlice(self.gpa, self.extra_faults.items);

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
                try sim.addBiLink(@intCast(a), nb.node, fab.opts.link);
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

// ── TEETH for the per-event safety hook (`check`) ───────────────────────────
//
// `check` is the only oracle that runs *during* a simulation; everything else
// is asserted once, at the end. It used to assert a single bound
// (`lsdb.count() > node_count`) that no test came anywhere near, so the bound
// could be loosened a thousandfold and the whole suite stayed green: the
// tripwire had never fired and was not known to be able to. These two tests
// make each invariant fire on demand, and pin the bound tight enough that
// loosening it is caught.

test "TEETH: the LSDB-count tripwire fires, and its bound is tight" {
    var edges: [3]Edge = undefined;
    const topo = lineTopology(&edges);
    var fab = try Fabric.init(testing.allocator, topo, 0x1CE);
    defer fab.deinit();

    // Each node now originates three distinct LSP-IDs instead of one, so the
    // "exactly one LSP per originator" bound is breached during flooding.
    fab.extra_fragments = 2;

    // The run must STOP on the invariant — not merely fail to converge.
    try testing.expectEqual(Outcome.step_cap_exceeded, try fab.runToConvergence(step_cap));
    try testing.expectEqual(@as(?anyerror, error.LsdbOverflow), fab.violation);

    // Tightness: the hook must catch this while the database is barely over the
    // bound. Any loosening of `count() > nodes.len` — the exact mutation that
    // previously left 9/9 green — pushes the trip point past this window and
    // the assertions above stop holding.
    var max_count: usize = 0;
    for (fab.nodes) |*ns| max_count = @max(max_count, ns.lsdb.count());
    try testing.expect(max_count > topo.node_count);
    try testing.expect(max_count <= topo.node_count * 2);
}

test "TEETH: a stored sequence that goes backwards is caught during the run" {
    var edges: [3]Edge = undefined;
    const topo = lineTopology(&edges);
    var fab = try Fabric.init(testing.allocator, topo, 0x5E9);
    defer fab.deinit();

    // C (node 2) loses its whole database once it has learned two LSPs. The
    // fabric would re-flood and re-converge, so no end-of-run assertion would
    // ever see it; only the per-event hook can.
    fab.broken_wipe_node = 2;

    try testing.expectEqual(Outcome.step_cap_exceeded, try fab.runToConvergence(step_cap));
    try testing.expectEqual(@as(?anyerror, error.SequenceRegression), fab.violation);
}

test "control: a correct run trips neither invariant" {
    var edges: [3]Edge = undefined;
    const topo = lineTopology(&edges);
    var fab = try Fabric.init(testing.allocator, topo, 0xA11CE);
    defer fab.deinit();
    try testing.expectEqual(Outcome.converged, try fab.runToConvergence(step_cap));
    try testing.expectEqual(@as(?anyerror, null), fab.violation);

    // And the monotonicity high-water marks match the final state, i.e. the
    // hook really did observe every node's database, not an empty one.
    var node: usize = 0;
    while (node < topo.node_count) : (node += 1) {
        var origin: usize = 0;
        while (origin < topo.node_count) : (origin += 1) {
            try testing.expectEqual(
                @as(u32, 1),
                fab.seen_seq[node * topo.node_count + origin],
            );
        }
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

// ── the imperfect medium (wave-2 W2-54) ──────────────────────────────────────
//
// Everything above this line runs over a perfect network: no loss, no
// duplication, no reordering, and `min_lsp_transmission_interval` set past the
// horizon so the retransmit path is dead code. That is the one condition under
// which IS-IS flooding is trivially correct. The tests below turn on the
// medium `netsim` has always modelled.

/// Retransmit + CSNP intervals for the lossy runs. Both must be well inside the
/// run horizon or a dropped LSP is never resent and a diverged database is
/// never resynchronised — the two mechanisms that make flooding robust.
/// Only the retransmit timer is restored; the periodic CSNP is left inert (its
/// module default), so **retransmission** is the sole repair path in every test
/// below. Measured, not assumed — 16 seeds, 200%o loss, 20 000 ticks:
///
///   * `retransmit_interval = 40`, CSNP inert  → converged **16/16**
///   * CSNP at 400, `retransmit_interval` inert → converged **0/16**
///
/// The second row is not evidence that CSNP resync is broken: this knob is
/// `isis-flood`'s `min_lsp_transmission_interval`, which paces *every* LSP
/// transmission on a circuit, so while it sits past the run horizon no
/// mechanism can re-send a dropped LSP — a CSNP-driven PSNP request included.
///
/// The CSNP path is no longer unmeasured (audit BD-16). It is measured by the
/// `MEASURED:` tests at the bottom of this file, on the divergence a P2P fabric
/// cannot retransmit its way out of — a **restart**, where the sender holds no
/// SRM at all — with the retransmit interval left inert in every run:
///
///   * restart, SNPs dropped      → the restarted node recovers **1 of 4**
///     originators (only the one it re-originates itself)
///   * restart, SNPs reconciled   → **4 of 4**, databases agree
///   * restart, SNPs reconciled, periodic CSNP *also* inert → **4 of 4**
///     (the single adjacency-up CSNP the restarted node emits is enough)
///
/// So the answer to "does CSNP resync repair a loss on its own" is yes, by two
/// independent sub-paths: the restarted node's own CSNP claims the whole LSP-ID
/// space while listing almost nothing, and each neighbour's §7.3.15.2
/// completeness sweep floods the difference back; and, when a cadence is
/// running, the neighbours' CSNPs make the restarted node *request* what it
/// lacks by PSNP. Disabling the completeness sweep alone kills the first but not
/// the second — verified by mutation.
const lossy_opts_base = Options{
    .retransmit_interval = 40,
};

/// A shorter horizon than `step_cap`, because a retransmit timer that keeps
/// re-arming spends `netsim`'s 200 000-event ceiling on steady-state churn long
/// after the fabric has converged — and `runToConvergence` reports the event cap
/// as `.step_cap_exceeded` even when the fabric is quiesced and agreeing (the
/// outcome collapsing the audit records separately). 20 000 ticks is ~500
/// retransmit periods, far more than convergence needs.
const lossy_step_cap: Time = 20_000;

test "lossy medium: a 4-node line still converges when 20% of messages are dropped" {
    var edges: [3]Edge = undefined;
    const topo = lineTopology(&edges);
    var opts = lossy_opts_base;
    opts.link = .{ .latency = link_latency, .loss_permille = 200 };

    var fab = try Fabric.initWithOptions(testing.allocator, topo, 0xA11CE, opts);
    defer fab.deinit();

    try testing.expectEqual(Outcome.converged, try fab.runToConvergence(lossy_step_cap));
    try testing.expect(fab.lsdbsAgree());
    var node: NodeId = 0;
    while (node < 4) : (node += 1) {
        var origin: NodeId = 0;
        while (origin < 4) : (origin += 1) {
            try testing.expectEqual(@as(?u32, 1), fab.storedSequence(node, origin));
        }
    }
    try testing.expectEqual(@as(?anyerror, null), fab.violation);
}

test "lossy medium: duplication, reordering and jitter do not corrupt any LSDB" {
    const edges = [_]Edge{
        .{ .a = 0, .b = 1, .metric = 10 },
        .{ .a = 1, .b = 2, .metric = 10 },
        .{ .a = 2, .b = 3, .metric = 10 },
        .{ .a = 3, .b = 0, .metric = 10 },
        .{ .a = 2, .b = 4, .metric = 10 },
    };
    var opts = lossy_opts_base;
    opts.link = .{
        .latency = link_latency,
        .jitter = 3,
        .loss_permille = 100,
        .dup_permille = 250,
        .reorder_permille = 250,
        .reorder_extra = 7,
    };
    var fab = try Fabric.initWithOptions(
        testing.allocator,
        .{ .node_count = 5, .edges = &edges },
        0xC0FFEE,
        opts,
    );
    defer fab.deinit();

    try testing.expectEqual(Outcome.converged, try fab.runToConvergence(lossy_step_cap));
    try testing.expect(fab.lsdbsAgree());
    // The per-event invariants (no sequence regression, no LSDB overflow) held
    // throughout, not just at the end.
    try testing.expectEqual(@as(?anyerror, null), fab.violation);
    var origin: NodeId = 0;
    while (origin < 5) : (origin += 1) {
        try testing.expectEqual(@as(?u32, 1), fab.storedSequence(0, origin));
    }
}

test "lossy medium: a seed sweep, not one hard-coded draw" {
    // The audit's F1: every result above rested on a single fixed seed. Sweep
    // instead — each seed is a different loss/duplication/reorder schedule, and
    // convergence must hold on all of them.
    var edges: [3]Edge = undefined;
    const topo = lineTopology(&edges);
    var opts = lossy_opts_base;
    opts.link = .{
        .latency = link_latency,
        .loss_permille = 150,
        .dup_permille = 150,
        .reorder_permille = 150,
        .reorder_extra = 5,
    };

    var seed: u64 = 1;
    while (seed <= 32) : (seed += 1) {
        var fab = try Fabric.initWithOptions(testing.allocator, topo, seed *% 0x9E3779B97F4A7C15, opts);
        defer fab.deinit();
        const outcome = try fab.runToConvergence(lossy_step_cap);
        if (outcome != .converged or !fab.lsdbsAgree()) {
            std.debug.print(
                "seed {d} did not converge: outcome={t} agree={} violation={?}\n",
                .{ seed, outcome, fab.lsdbsAgree(), fab.violation },
            );
            return error.LossySeedDidNotConverge;
        }
    }
}

test "one-shot faults: a dropped first LSP is repaired by retransmission" {
    var edges: [3]Edge = undefined;
    const topo = lineTopology(&edges);
    // No probabilistic loss at all — the single scheduled `drop_once` is the
    // whole fault, so if this converges it is retransmission (or CSNP resync)
    // that did it, not luck.
    var fab = try Fabric.initWithOptions(testing.allocator, topo, 4242, lossy_opts_base);
    defer fab.deinit();
    try fab.extra_faults.append(testing.allocator, .{
        .time = 0,
        .kind = .{ .drop_once = .{ .a = 0, .b = 1 } },
    });
    try fab.extra_faults.append(testing.allocator, .{
        .time = 0,
        .kind = .{ .dup_once = .{ .a = 1, .b = 2 } },
    });
    try fab.extra_faults.append(testing.allocator, .{
        .time = 0,
        .kind = .{ .delay_once = .{ .a = 2, .b = 3, .extra = 37 } },
    });

    try testing.expectEqual(Outcome.converged, try fab.runToConvergence(lossy_step_cap));
    try testing.expect(fab.lsdbsAgree());
    try testing.expectEqual(@as(?u32, 1), fab.storedSequence(3, 0)); // A's LSP reached D
    try testing.expectEqual(@as(?anyerror, null), fab.violation);
}

// ── the CSNP resync path, MEASURED (audit BD-16) ────────────────────────────
//
// Every lossy test above repairs itself by **retransmission**: on a P2P circuit
// `isis-lsdb` clears SRM only once the neighbour demonstrably holds the LSP (a
// PSNP ack, or a summary comparing `.same`), so an undelivered LSP always leaves
// SRM set at the sender and the retransmit timer alone brings it back. A CSNP in
// that situation can only re-set an SRM that is already set — which is why the
// audit's sweep with the retransmit interval left inert converged 0/16 and the
// CSNP path's own repair ability stayed unmeasured. (`min_lsp_transmission_
// interval` paces *every* transmission on a circuit, so parking it past the run
// horizon stops the send whatever set the flag.)
//
// The divergence a P2P fabric cannot retransmit its way out of is one where the
// sender holds no SRM at all: a **restart**. `Fabric.restart` builds it, and the
// two runs below differ in exactly one thing — whether CSNP/PSNP PDUs are
// reconciled — with the retransmit interval left at its inert default in BOTH,
// so retransmission cannot be what repaired anything.

const restart_node: NodeId = 2;
const restart_time: Time = 5_000;

/// Run the line topology with node 2 cold-restarting mid-run, and report how
/// many of the four originators it holds at the end.
fn runRestart(ignore_snp: bool, csnp_interval_ticks: Time) !struct { held: usize, agree: bool, violation: ?anyerror } {
    var edges: [3]Edge = undefined;
    const topo = lineTopology(&edges);
    // Retransmission is INERT (the module default): whatever repairs the
    // restarted database, it is not the retransmit timer.
    var fab = try Fabric.initWithOptions(testing.allocator, topo, 0xB16, .{
        .csnp_interval = csnp_interval_ticks,
    });
    defer fab.deinit();
    fab.restart = .{ .node = restart_node, .time = restart_time };
    fab.ignore_snp = ignore_snp;

    _ = try fab.runToConvergence(lossy_step_cap);

    var held: usize = 0;
    var origin: NodeId = 0;
    while (origin < 4) : (origin += 1) {
        if (fab.storedSequence(restart_node, origin) != null) held += 1;
    }
    return .{ .held = held, .agree = fab.lsdbsAgree(), .violation = fab.violation };
}

test "MEASURED: the CSNP path repairs a restarted database that retransmission cannot" {
    // Control: SNPs dropped. The restarted node re-originates its own LSP and
    // that is all it ever holds again — its neighbours have no SRM toward it, so
    // nothing re-floods them and no timer can help.
    const without = try runRestart(true, 400);
    try testing.expectEqual(@as(usize, 1), without.held); // its own LSP only
    try testing.expect(!without.agree);
    try testing.expectEqual(@as(?anyerror, null), without.violation);

    // The measurement: with SNPs reconciled — same topology, same seed, same
    // inert retransmit interval — the database comes back in full.
    const with = try runRestart(false, 400);
    try testing.expectEqual(@as(usize, 4), with.held);
    try testing.expect(with.agree);
    try testing.expectEqual(@as(?anyerror, null), with.violation);
}

test "MEASURED: the repair survives an inert CSNP cadence (the adjacency-up CSNP does it)" {
    // ISO §7.3.15.2 has a P2P circuit send a CSNP when the adjacency comes up,
    // not only on a cadence. The restarted node's fresh scheduler emits exactly
    // that one CSNP; it claims the whole LSP-ID space while listing only its own
    // LSP, so each neighbour's completeness sweep flags everything else for
    // flooding back. Measured with the periodic cadence parked past the horizon.
    const with = try runRestart(false, csnp_interval);
    try testing.expectEqual(@as(usize, 4), with.held);
    try testing.expect(with.agree);
}

test "one-shot faults: a partition that heals re-synchronises both sides" {
    const edges = [_]Edge{
        .{ .a = 0, .b = 1, .metric = 10 },
        .{ .a = 1, .b = 2, .metric = 10 },
        .{ .a = 2, .b = 3, .metric = 10 },
    };
    const topo = Topology{ .node_count = 4, .edges = &edges };
    var fab = try Fabric.initWithOptions(testing.allocator, topo, 0x5EED, lossy_opts_base);
    defer fab.deinit();

    // Cut {0,1} from {2,3} before anything has flooded, then heal well before
    // the horizon. A partition is not a `link_down`: it is applied by netsim as
    // a cut across the whole graph and reversed by id, and nothing in this
    // module used it.
    const cut = [_]NodeId{ 0, 1 };
    try fab.extra_faults.append(testing.allocator, .{
        .time = 0,
        .kind = .{ .partition = .{ .id = 1, .cut = &cut } },
    });
    try fab.extra_faults.append(testing.allocator, .{
        .time = 300,
        .kind = .{ .heal = .{ .id = 1 } },
    });

    try testing.expectEqual(Outcome.converged, try fab.runToConvergence(lossy_step_cap));
    // After the heal every node must hold every originator again — the state a
    // partition-only run (which the harness used to stop at) cannot reach.
    try testing.expect(fab.lsdbsAgree());
    var node: NodeId = 0;
    while (node < 4) : (node += 1) {
        var origin: NodeId = 0;
        while (origin < 4) : (origin += 1) {
            try testing.expect(fab.storedSequence(node, origin) != null);
        }
    }
    try testing.expectEqual(@as(?anyerror, null), fab.violation);
}
