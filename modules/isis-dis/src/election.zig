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
//! caller-supplied neighbour slice once and is independent of that slice's order
//! (SNPAs are unique per LAN, so `(priority, snpa)` is a strict total order — no
//! two distinct candidates compare equal). The caller derives the candidate set
//! from received LAN Hellos + adjacency state; this file does not parse Hellos or
//! track adjacency — it takes the neighbour view as input.

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
/// compare). Strict — equal `(priority, snpa)` returns false — so the max-scan is
/// deterministic. SNPAs are unique per LAN, so no two distinct candidates ever
/// reach the `.eq` case in practice.
fn outranks(a: Candidate, b: Candidate) bool {
    if (a.priority != b.priority) return a.priority > b.priority;
    return std.mem.order(u8, &a.snpa, &b.snpa) == .gt;
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
