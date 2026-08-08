// SPDX-License-Identifier: MIT

//! The pure IS-IS LAN Designated-IS election (ISO/IEC 10589 §8.4.5) for ONE LAN
//! circuit at one level.
//!
//! On a broadcast (LAN) circuit exactly one router is the Designated IS (DIS);
//! it originates the *pseudonode* LSP that represents the LAN as a virtual node.
//! Which router that is follows a single, order-independent rule over the set of
//! candidates = the local system + every router with an Up LAN adjacency:
//!
//!   The DIS is the candidate with the **numerically highest priority**; ties are
//!   broken by the **numerically highest SNPA** (the router's MAC on this LAN,
//!   compared as an unsigned 48-bit big-endian integer). — ISO 10589 §8.4.5.
//!
//! Both directions are *highest-wins*. This is the classic footgun: OSPF's DR is
//! highest-Router-ID and *non-preemptive*; IS-IS is highest-SNPA and preemptive.
//! A permanent positive-control test pins the highest-SNPA direction.
//!
//! `elect` is a pure function: no allocation, no clock, no I/O. It scans the
//! caller-supplied neighbour slice once and is independent of that slice's
//! order: `(priority, snpa, system_id)` is a strict total order, so no two
//! distinct candidates compare equal — the system-id level only matters when
//! two candidates share an SNPA (a duplicate/spoofed MAC), which ISO 10589
//! itself leaves undefined; system-ids are always unique, so it still
//! guarantees a deterministic winner rather than falling back to slice order.
//! The caller derives the candidate set from received LAN Hellos + adjacency
//! state; this file does not parse Hellos or track adjacency — it takes the
//! neighbour view as input.

const std = @import("std");

/// A 6-octet IS-IS system id (the default, MAC-sized id — the only width the
/// sibling `isis` typed bodies model).
pub const SystemId = [6]u8;

/// A Subnetwork Point of Attachment: the router's 6-octet MAC address on *this*
/// LAN circuit. The DIS tie-break compares SNPAs as unsigned 48-bit big-endian
/// integers, and SNPAs are unique per LAN — the property that makes the election
/// order-independent.
pub const Snpa = [6]u8;

/// One election candidate: a router seen on the LAN (or the local system).
pub const Candidate = struct {
    /// The router's 6-octet system id.
    system_id: SystemId,
    /// The router's configured LAN priority (7-bit field, ISO 10589 §9.5 — the
    /// LAN IIH carries it as `u7`). 0 is legal ("never want to be DIS") but a
    /// priority-0 router still participates and can win if it is the sole/highest
    /// candidate.
    priority: u7,
    /// The router's SNPA (MAC) on this LAN circuit — the tie-break key.
    snpa: Snpa,
    /// The pseudonode id this router uses for this LAN when it is the DIS. For the
    /// local candidate this is the circuit's configured pseudonode id (a nonzero
    /// u8, unique per LAN circuit on this router). For a neighbour it is the
    /// pseudonode id observed in that neighbour's Hello `lan_id` (0 until/unless it
    /// is the DIS). Only the *winner's* value is used — it becomes `Result.lan_id`.
    pseudonode_id: u8 = 0,
};

/// The election outcome for the current candidate set.
pub const Result = struct {
    /// The elected DIS's system id.
    dis_system_id: SystemId,
    /// The elected DIS's SNPA (MAC on this LAN).
    dis_snpa: Snpa,
    /// True iff the local system is the DIS (⇒ it originates the pseudonode LSP).
    is_local_dis: bool,
    /// The LAN id a Hello advertises = DIS system id (6) ‖ DIS pseudonode id (1).
    /// When the local system is DIS this is our system id ‖ our pseudonode id;
    /// otherwise it is the winning neighbour's system id ‖ its observed pseudonode
    /// id, which the caller can compare against incoming Hellos' `lan_id`.
    lan_id: [7]u8,

    /// The pseudonode LSP id = `lan_id` (system id ‖ pseudonode id) ‖ LSP number
    /// (0). An 8-octet id in the exact shape `isis.Lsp.lsp_id` expects. This
    /// identifies the pseudonode LSP the DIS originates; generating that LSP's
    /// *content* is a separate LSP-origination concern (see SPEC).
    pub fn pseudonodeLspId(r: Result) [8]u8 {
        var id: [8]u8 = undefined;
        @memcpy(id[0..7], &r.lan_id);
        id[7] = 0; // LSP number 0
        return id;
    }
};

/// Returns true iff candidate `a` outranks `b` for DIS: higher priority wins;
/// on equal priority the numerically higher SNPA wins (unsigned big-endian
/// compare); on equal priority AND equal SNPA the numerically higher system-id
/// wins. Strict — equal `(priority, snpa, system_id)` returns false — so the
/// max-scan is deterministic and total regardless of the caller's slice order.
///
/// SNPAs are supposed to be unique per LAN (ISO 10589 §8.4.5 implicitly assumes
/// it, since it defines only the two-level tie-break), so the third level is a
/// belt-and-braces total order for the one case ISO 10589 leaves undefined: a
/// duplicate or spoofed SNPA on the LAN. System-ids ARE guaranteed unique (it is
/// the router's own identity), so this makes the comparison a strict total order
/// under every input, not just the well-formed one — without it, a duplicate
/// SNPA made `(priority, snpa)` a non-total preorder, and the winner silently
/// became whichever candidate the caller happened to list first, i.e.
/// order-dependent and possibly disagreeing router-to-router on the same LAN.
fn outranks(a: Candidate, b: Candidate) bool {
    if (a.priority != b.priority) return a.priority > b.priority;
    const snpa_order = std.mem.order(u8, &a.snpa, &b.snpa);
    if (snpa_order != .eq) return snpa_order == .gt;
    return std.mem.order(u8, &a.system_id, &b.system_id) == .gt;
}

/// Elect the DIS over `{local} ∪ neighbours`. Pure, allocation-free, and
/// independent of the order of `neighbours` (a single max-scan under a strict
/// total order). `neighbours` is the set of routers with an Up LAN adjacency, as
/// derived by the caller from received Hellos + adjacency state.
///
/// Preemption is implicit: there is no hold-down and no timer. The DIS is simply
/// the winner of *this* candidate set, so a caller that recomputes on every
/// membership change gets immediate, backoff-free preemption (ISO 10589 §8.4.5) —
/// unlike OSPF's DR. The FSM wrapper (`fsm.zig`) turns a change of winner into a
/// DIS-change effect.
pub fn elect(local: Candidate, neighbours: []const Candidate) Result {
    var best = local;
    var best_is_local = true;
    for (neighbours) |n| {
        if (outranks(n, best)) {
            best = n;
            best_is_local = false;
        }
    }
    var lan_id: [7]u8 = undefined;
    @memcpy(lan_id[0..6], &best.system_id);
    lan_id[6] = best.pseudonode_id;
    return .{
        .dis_system_id = best.system_id,
        .dis_snpa = best.snpa,
        .is_local_dis = best_is_local,
        .lan_id = lan_id,
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn snpa(last: u8) Snpa {
    return .{ 0x00, 0x00, 0x00, 0x00, 0x00, last };
}

const local_a: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 0xA }, .priority = 64, .snpa = snpa(0x0A), .pseudonode_id = 1 };

test "single candidate: local alone is the DIS" {
    const r = elect(local_a, &.{});
    try testing.expect(r.is_local_dis);
    try testing.expectEqual(local_a.system_id, r.dis_system_id);
    // lan_id = local system id ‖ local pseudonode id.
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0xA, 1 }, &r.lan_id);
    // pseudonode LSP id = lan_id ‖ LSP-number 0.
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0xA, 1, 0 }, &r.pseudonodeLspId());
}

test "highest priority wins; tie between the two 64s goes to the higher SNPA" {
    // Priorities {10, 64, 64}: the DIS must be one of the two 64s, specifically
    // the one with the higher SNPA. Construct SNPAs so it is unambiguous.
    const local: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 1 }, .priority = 10, .snpa = snpa(0xFF), .pseudonode_id = 1 };
    const nb_lo: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 2 }, .priority = 64, .snpa = snpa(0x11) };
    const nb_hi: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 3 }, .priority = 64, .snpa = snpa(0x22) };
    const r = elect(local, &.{ nb_lo, nb_hi });
    try testing.expectEqual(nb_hi.system_id, r.dis_system_id);
    try testing.expectEqual(nb_hi.snpa, r.dis_snpa);
    try testing.expect(!r.is_local_dis);
    // Even though local has the highest SNPA (0xFF), its lower priority loses:
    // priority dominates the tie-break.
}

test "SNPA tie-break is HIGHEST-wins (the footgun); would FAIL under lowest-wins" {
    // Two routers, equal priority, SNPAs ...:01 vs ...:02. Highest SNPA (…:02)
    // must win. If the tie-break were lowest-SNPA this assertion goes RED.
    const local: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 1 }, .priority = 64, .snpa = snpa(0x01), .pseudonode_id = 1 };
    const nb: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 2 }, .priority = 64, .snpa = snpa(0x02), .pseudonode_id = 7 };
    const r = elect(local, &.{nb});
    try testing.expectEqual(nb.system_id, r.dis_system_id);
    try testing.expectEqual(snpa(0x02), r.dis_snpa);
    try testing.expect(!r.is_local_dis);
    // The winner's pseudonode id populates lan_id.
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 2, 7 }, &r.lan_id);
}

test "local highest priority => is_local_dis with local lan_id" {
    const nb: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 2 }, .priority = 40, .snpa = snpa(0xFF) };
    const r = elect(local_a, &.{nb}); // local priority 64 > 40
    try testing.expect(r.is_local_dis);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0xA, 1 }, &r.lan_id);
}

test "priority 0 local participates and wins when it is the sole candidate" {
    const p0: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 9 }, .priority = 0, .snpa = snpa(0x33), .pseudonode_id = 4 };
    const r = elect(p0, &.{});
    try testing.expect(r.is_local_dis);
    try testing.expectEqual(p0.system_id, r.dis_system_id);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 9, 4 }, &r.lan_id);
}

test "priority 0 local loses to any positive-priority neighbour" {
    const p0: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 9 }, .priority = 0, .snpa = snpa(0xFF) };
    const nb: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 2 }, .priority = 1, .snpa = snpa(0x01) };
    const r = elect(p0, &.{nb});
    try testing.expect(!r.is_local_dis);
    try testing.expectEqual(nb.system_id, r.dis_system_id);
}

test "determinism: the winner is independent of neighbour-slice order" {
    const local: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 1 }, .priority = 30, .snpa = snpa(0x05), .pseudonode_id = 1 };
    const n1: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 2 }, .priority = 64, .snpa = snpa(0x10) };
    const n2: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 3 }, .priority = 64, .snpa = snpa(0x40) }; // winner
    const n3: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 4 }, .priority = 50, .snpa = snpa(0xFF) };
    const orders = [_][3]Candidate{
        .{ n1, n2, n3 },
        .{ n3, n2, n1 },
        .{ n2, n1, n3 },
        .{ n3, n1, n2 },
    };
    const want = elect(local, &orders[0]);
    for (orders) |o| {
        const got = elect(local, &o);
        try testing.expectEqual(want.dis_system_id, got.dis_system_id);
        try testing.expectEqual(want.dis_snpa, got.dis_snpa);
        try testing.expectEqual(want.is_local_dis, got.is_local_dis);
        try testing.expectEqualSlices(u8, &want.lan_id, &got.lan_id);
    }
    try testing.expectEqual(n2.system_id, want.dis_system_id);
}

// Regression (audit W2 `isis-dis` F3): a duplicate/spoofed SNPA must still
// yield a deterministic, order-independent winner. Before the fix,
// `(priority, snpa)` was not a total order when two candidates shared an
// SNPA — `outranks` returned false both ways, so the max-scan's first-wins
// fallback made the result depend on the caller's slice order (different
// routers on the same LAN, fed the same candidate SET in different orders,
// could elect different DISes). The system-id tie-break makes the order
// total again.
test "duplicate SNPA: the winner is still deterministic and order-independent" {
    const local: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 1 }, .priority = 10, .snpa = snpa(0x01) };
    // n1 and n2 share an SNPA (spoofed/misconfigured) but differ in system-id.
    const n1: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 2 }, .priority = 64, .snpa = snpa(0xAA) };
    const n2: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 9 }, .priority = 64, .snpa = snpa(0xAA) }; // same SNPA, higher system-id
    const orders = [_][2]Candidate{ .{ n1, n2 }, .{ n2, n1 } };
    const want = elect(local, &orders[0]);
    for (orders) |o| {
        const got = elect(local, &o);
        try testing.expectEqual(want.dis_system_id, got.dis_system_id);
    }
    // The higher system-id (n2) must win the tie, not whichever came first.
    try testing.expectEqual(n2.system_id, want.dis_system_id);
}

// Permanent positive control (CONVENTIONS/brief): a deliberately WRONG election
// that breaks the SNPA tie-break to lowest-wins. It must pick the opposite winner
// from the correct `elect` on an equal-priority pair — proving the highest-SNPA
// direction in `elect` has teeth. If `elect` regressed to lowest-SNPA, this test
// would find them AGREEING and go RED.
fn electLowestSnpaWrong(local: Candidate, neighbours: []const Candidate) Result {
    var best = local;
    for (neighbours) |n| {
        const wins = if (n.priority != best.priority)
            n.priority > best.priority
        else
            std.mem.order(u8, &n.snpa, &best.snpa) == .lt; // WRONG: lowest SNPA
        if (wins) best = n;
    }
    return .{ .dis_system_id = best.system_id, .dis_snpa = best.snpa, .is_local_dis = false, .lan_id = undefined };
}

test "positive control: lowest-SNPA election disagrees with the correct one" {
    const local: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 1 }, .priority = 64, .snpa = snpa(0x01) };
    const nb: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 2 }, .priority = 64, .snpa = snpa(0x02) };
    const correct = elect(local, &.{nb});
    const wrong = electLowestSnpaWrong(local, &.{nb});
    // Correct picks the HIGHEST SNPA (…:02); the broken one picks the lowest
    // (…:01). They MUST differ — that difference is what the positive control
    // guarantees.
    try testing.expectEqual(nb.system_id, correct.dis_system_id); // …:02
    try testing.expectEqual(local.system_id, wrong.dis_system_id); // …:01
    try testing.expect(!std.mem.eql(u8, &correct.dis_system_id, &wrong.dis_system_id));
}

// ── FRR anchor: capture-and-freeze against a real IS-IS speaker ─────────────
//
// Every expectation above (like every isis-dis expectation before this section)
// rests on our own reading of ISO/IEC 10589 §8.4.5 — hand-built candidate sets,
// winners we believed the spec requires, tests and implementation sharing one
// author's interpretation of one document. Unlike the wire-visible fields the
// sibling `goldens.zig` already checked against Wireshark's dissector (lan_id,
// priority, the pseudonode LSP-ID split), the election RESULT — which router
// wins — has no bytes of its own on the wire for a dissector to grade. But it
// is not unobservable: a real IS-IS speaker computes it internally and reports
// it back, both in its own state (`show isis interface detail`, "is/is not
// DIS") and, in a real deployment, on the wire (who starts emitting the
// periodic CSNP). This section closes that gap the same way `isis-spf` closed
// its SPF-result gap: `frr`'s own `isisd` (10.3), run inside this repo's
// throwaway Debian VM lane (`scripts/vm/`, `frr` already in
// `VM_DEBIAN_PACKAGES` since isis-spf's anchor), computing a real LAN DIS
// election over inputs this task chose, read back and frozen.
//
// Licence note (same reasoning as `isis-spf`'s anchor, read before touching
// this block): FRR is GPL-2.0-or-later; this repo is MIT. Nothing here is
// copied from FRR's source, and nothing here is FRR's own test data. What is
// frozen below is FRR's *election outcome* for a topology and priority/SNPA
// assignment this task authored from scratch — GPLv2 §0 restricts the covered
// *Program*, not a state value it reports about our own configuration. The run
// was ONE-SHOT (twice, to get two independent input assignments): nothing
// below boots a VM, invokes FRR, or touches the network — the values are
// literals from here on.
//
// ── the topology (one LAN, 3 routers, one broadcast circuit, level-1) ──────
//
//   r1(0000.0000.0001) ─┐
//   r2(0000.0000.0002) ─┼─ br0 (Linux bridge, one shared LAN segment)
//   r3(0000.0000.0003) ─┘
//
// All three `isisd` instances ran as real LAN adjacencies (`isis network
// broadcast`, the default for an Ethernet-type interface; `is-type level-1`;
// `metric-style wide`) in their own network namespace (`ip netns`), each
// with one veth leg plugged into a single Linux bridge (`br0`) in the host
// namespace — a real, single, shared broadcast domain, not three separate
// point-to-point links. Each namespace ran its own `zebra`/`isisd` pair,
// isolated from the others via FRR's `-N <name>` pathspace flag (separate vty
// sockets) *and* the network namespace (separate interfaces/L2 domain) —
// `ip netns exec r1 /usr/lib/frr/isisd -N r1 -f /etc/frr/r1/isisd.conf -d`,
// one per router. A `/24` IPv4 address per interface (not load-bearing for
// LAN election itself, but kept for parity with the isis-spf lab and because
// P2P adjacencies in that lab needed IPv4 to leave Down at all).
//
// `dpkg -l frr` / `isisd -v` (once, before configuring anything):
//   frr  10.3-3+deb13u1  amd64
//   isisd version 10.3
//
// ── run A: priorities {10, 64, 64} — decided by priority, confirms the tie ──
//
// Interface config (`isis priority <N>`), SNPA = the interface's own MAC
// (`ip link set eth0 address <mac>`, set once before bringing the link up):
//   r1: priority 10, SNPA 02:00:00:00:00:01
//   r2: priority 64, SNPA 02:00:00:00:00:02
//   r3: priority 64, SNPA 02:00:00:00:00:03
//
// `vtysh -N <r> -c "show isis interface detail"` on each, after convergence
// (~20s; the LAN Hello interval here is 3s, holddown 10 — several Hellos
// exchanged), the exact "LAN Priority" / DIS lines:
//   r1: "LAN Priority: 10, is not DIS"
//   r2: "LAN Priority: 64, is not DIS"
//   r3: "LAN Priority: 64, is DIS"
// (`show isis neighbor` on r1 independently confirms both r2 and r3 reached
// State Up with SNPA 0200.0000.0002 / 0200.0000.0003 — the adjacencies this
// election ran over were real, not assumed.)
//
// r2 and r3 (priority 64) both outrank r1 (priority 10) — the priority rule.
// Between r2 and r3, tied at 64, r3's SNPA (…03) is numerically higher than
// r2's (…02) and r3 wins — the tie-break rule, exactly as SPEC.md §3 states
// it and exactly what `elect` computes below.
//
// ── run B: same priorities, SNPAs swapped between r2 and r3 ────────────────
//
// A second, independent capture — not just a restatement of run A — chosen to
// rule out the result tracking something incidental (hostname, hand-config
// order, numerically-higher system-id) rather than the SNPA itself: keep every
// system-id and priority as in run A, but reassign the physical MACs so the
// PREVIOUS loser of the tie-break now holds the higher SNPA.
//   r1: priority 10, SNPA 02:00:00:00:00:01 (unchanged)
//   r2: priority 64, SNPA 02:00:00:00:00:09 (was …02 in run A)
//   r3: priority 64, SNPA 02:00:00:00:00:05 (was …03 in run A)
//
// `vtysh -N <r> -c "show isis interface detail"` after convergence:
//   r1: "LAN Priority: 10, is not DIS"
//   r2: "LAN Priority: 64, is DIS"      -- flipped from run A
//   r3: "LAN Priority: 64, is not DIS"  -- flipped from run A
//
// The winner tracked the SNPA reassignment exactly (r2 now has the higher
// SNPA and is now DIS) with priority and system-ids held fixed — first try,
// both runs, no adjustment made to `elect` to match.
/// The lab's literal captured SNPAs (`02:00:00:00:00:0N`, set via `ip link
/// set eth0 address <mac>` before bringing each link up — see the run A/B
/// comments above) — distinct from the generic `snpa()` helper (`00:...`)
/// every OTHER test in this file uses for hand-built candidates. F4 (wave-2
/// audit): the FRR-anchor test below used to route through `snpa()` too, so
/// its fixture was an order-preserving stand-in rather than a literal
/// transcription of what the lab actually captured — the ordering conclusion
/// was unaffected (only the last octet ever varies in any comparison here),
/// but a capture-and-freeze anchor should be re-checkable against the literal
/// captured bytes without re-deriving them.
fn capturedSnpa(last: u8) Snpa {
    return .{ 0x02, 0x00, 0x00, 0x00, 0x00, last };
}

test "FRR anchor: LAN DIS election, priority + SNPA tie-break, two independent runs" {
    // Run A: r2/r3 tied at priority 64, decided by SNPA (…03 > …02).
    {
        const r1: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 1 }, .priority = 10, .snpa = capturedSnpa(0x01) };
        const r2: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 2 }, .priority = 64, .snpa = capturedSnpa(0x02) };
        const r3: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 3 }, .priority = 64, .snpa = capturedSnpa(0x03) };

        // From r1's vantage point (its own Up-neighbour view: r2, r3): the
        // elected DIS is r3 — matches FRR's r1 AND r3's own "is/is not DIS".
        const from_r1 = elect(r1, &.{ r2, r3 });
        try testing.expectEqual(r3.system_id, from_r1.dis_system_id);
        try testing.expectEqual(r3.snpa, from_r1.dis_snpa);
        try testing.expect(!from_r1.is_local_dis);

        // From r3's own vantage point: it correctly sees itself as DIS.
        const from_r3 = elect(r3, &.{ r1, r2 });
        try testing.expect(from_r3.is_local_dis);
        try testing.expectEqual(r3.system_id, from_r3.dis_system_id);

        // From r2's own vantage point: it correctly sees itself as NOT DIS.
        const from_r2 = elect(r2, &.{ r1, r3 });
        try testing.expect(!from_r2.is_local_dis);
        try testing.expectEqual(r3.system_id, from_r2.dis_system_id);
    }

    // Run B: same priorities/system-ids, SNPAs swapped between r2 and r3 —
    // the winner must flip to r2.
    {
        const r1: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 1 }, .priority = 10, .snpa = capturedSnpa(0x01) };
        const r2: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 2 }, .priority = 64, .snpa = capturedSnpa(0x09) };
        const r3: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 3 }, .priority = 64, .snpa = capturedSnpa(0x05) };

        const from_r1 = elect(r1, &.{ r2, r3 });
        try testing.expectEqual(r2.system_id, from_r1.dis_system_id);
        try testing.expectEqual(r2.snpa, from_r1.dis_snpa);

        const from_r2 = elect(r2, &.{ r1, r3 });
        try testing.expect(from_r2.is_local_dis);

        const from_r3 = elect(r3, &.{ r1, r2 });
        try testing.expect(!from_r3.is_local_dis);
        try testing.expectEqual(r2.system_id, from_r3.dis_system_id);
    }
}
