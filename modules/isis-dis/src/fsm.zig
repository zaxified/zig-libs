// SPDX-License-Identifier: MIT

//! The DIS-election FSM wrapper for ONE LAN circuit at one level (ISO/IEC 10589
//! §8.4.5). It holds the last-elected DIS, recomputes the election over the
//! current candidate set, and emits a **DIS-change effect** when the winner flips
//! — including the `became_dis` / `resigned_dis` flags the caller needs to start
//! or stop originating the LAN's pseudonode LSP.
//!
//! ## No hold-down — the election is a pure recompute
//! Unlike OSPF's DR, IS-IS DIS election is **preemptive with no backoff** (ISO
//! 10589 §8.4.5): a newly-appeared higher-priority (or higher-SNPA) router
//! becomes DIS immediately, and a departed DIS is replaced immediately. There is
//! therefore no timer and no hold-down state here — `recompute` just runs `elect`
//! over whatever candidate set the caller passes and diffs the winner against the
//! stored one. The caller drives it on every membership/priority change.
//!
//! ## Time-injection contract
//! Consistent with the sibling P2P FSM (`isis-adj`), `recompute` takes a
//! caller-supplied monotonic `now: Time`. The DIS election has no timer, so `now`
//! is used *only* to timestamp the emitted change (`DisChange.at`); the election
//! result itself is independent of it. It is carried for family consistency and
//! because a caller correlating DIS flips with adjacency events already has a
//! `now` in hand. The FSM never reads a clock.

const std = @import("std");
const election = @import("election.zig");

pub const SystemId = election.SystemId;
pub const Snpa = election.Snpa;
pub const Candidate = election.Candidate;
pub const Result = election.Result;
pub const elect = election.elect;

/// A caller-supplied monotonic timestamp (abstract ticks in the caller's own
/// unit). See the time-injection note above — used only to stamp `DisChange.at`.
pub const Time = u64;

/// Emitted when the elected DIS changes (a different router wins, or the first
/// election establishes one). Carries both the old→new identity and the two
/// local-perspective triggers.
pub const DisChange = struct {
    /// The previously-elected DIS system id, or null on the first election.
    old_dis: ?SystemId,
    /// The newly-elected DIS system id.
    new_dis: SystemId,
    /// True iff the local system JUST became the DIS (was not, now is) — the
    /// trigger to originate this LAN's pseudonode LSP.
    became_dis: bool,
    /// True iff the local system JUST resigned as DIS (was, now is not) — the
    /// trigger to purge the pseudonode LSP it had been originating.
    resigned_dis: bool,
    /// The `now` passed to the `recompute` that produced this change (timestamp
    /// only; the election does not depend on it).
    at: Time,
};

/// The outcome of a `recompute`: the current election `Result` always, plus a
/// `change` iff the elected DIS flipped this call.
pub const Effect = struct {
    /// The election result for the candidate set just passed.
    result: Result,
    /// Set iff the elected DIS changed on this call (old→new + became/resigned).
    change: ?DisChange = null,
};

/// The per-circuit DIS election state. Single-owner: one caller/loop drives it;
/// it is lock-free and holds no shared state. It stores only the local candidate
/// and the last-elected `Result`.
pub const Election = struct {
    /// The local system as an election candidate. `pseudonode_id` here is the
    /// circuit's configured pseudonode id (nonzero) used when we are the DIS.
    local: Candidate,
    /// The last election result, or null before the first `recompute`.
    current: ?Result = null,

    pub fn init(local: Candidate) Election {
        return .{ .local = local };
    }

    /// The current DIS result, or null before the first `recompute`.
    pub fn currentResult(self: *const Election) ?Result {
        return self.current;
    }

    /// True iff the local system is currently the DIS (false before the first
    /// `recompute`).
    pub fn isLocalDis(self: *const Election) bool {
        return if (self.current) |r| r.is_local_dis else false;
    }

    /// Recompute the election over `{local} ∪ neighbours` and diff the winner
    /// against the stored one. Returns the fresh `Result` and, iff the elected
    /// DIS system id changed, a `DisChange` with the became/resigned flags.
    /// `neighbours` = the routers with an Up LAN adjacency (caller-derived);
    /// `now` timestamps the change only (no hold-down — see the file docs).
    pub fn recompute(self: *Election, neighbours: []const Candidate, now: Time) Effect {
        const r = elect(self.local, neighbours);
        var eff: Effect = .{ .result = r };

        // Keyed on `lan_id` (system id ‖ pseudonode id), not `dis_system_id`
        // alone: `lan_id` is what a Hello advertises and what
        // `pseudonodeLspId()` is derived from, so it is what a caller must
        // track to know when to stop chasing the OLD pseudonode LSP. The
        // same system id can keep winning while its pseudonode byte changes
        // (a DIS restart picking a different circuit id, or a neighbour's
        // `lan_id` going from 0 to nonzero the moment it becomes DIS) — a
        // system-id-only key would miss that and leave the caller tracking
        // a stale pseudonode LSP-ID.
        const flipped = if (self.current) |old|
            !std.mem.eql(u8, &old.lan_id, &r.lan_id)
        else
            true; // the first election always establishes a DIS

        if (flipped) {
            const was_local = if (self.current) |old| old.is_local_dis else false;
            eff.change = .{
                .old_dis = if (self.current) |old| old.dis_system_id else null,
                .new_dis = r.dis_system_id,
                .became_dis = r.is_local_dis and !was_local,
                .resigned_dis = was_local and !r.is_local_dis,
                .at = now,
            };
        }
        self.current = r;
        return eff;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn snpa(last: u8) Snpa {
    return .{ 0x00, 0x00, 0x00, 0x00, 0x00, last };
}

const me: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 0xA }, .priority = 64, .snpa = snpa(0x0A), .pseudonode_id = 1 };
const higher: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 0xB }, .priority = 100, .snpa = snpa(0x0B) };

test "pre-recompute: isLocalDis and currentResult default before any recompute" {
    var e = Election.init(me);
    try testing.expect(!e.isLocalDis());
    try testing.expectEqual(@as(?Result, null), e.currentResult());
}

test "first recompute (local alone) establishes local as DIS via became_dis" {
    var e = Election.init(me);
    const eff = e.recompute(&.{}, 1);
    try testing.expect(eff.result.is_local_dis);
    const c = eff.change.?;
    try testing.expectEqual(@as(?SystemId, null), c.old_dis);
    try testing.expectEqual(me.system_id, c.new_dis);
    try testing.expect(c.became_dis);
    try testing.expect(!c.resigned_dis);
    try testing.expectEqual(@as(Time, 1), c.at);
    try testing.expect(e.isLocalDis());
}

test "no change => no effect on a steady recompute" {
    var e = Election.init(me);
    _ = e.recompute(&.{}, 1);
    const eff = e.recompute(&.{}, 2); // same candidate set
    try testing.expect(eff.change == null);
    try testing.expect(eff.result.is_local_dis);
}

test "preemption sequence: higher-priority neighbour appears then departs" {
    var e = Election.init(me);
    // t=1: local alone → local is DIS (became_dis).
    const e1 = e.recompute(&.{}, 1);
    try testing.expect(e1.change.?.became_dis);
    try testing.expect(e.isLocalDis());

    // t=2: a higher-priority neighbour appears → immediate preemption, local
    // resigns, the neighbour is DIS. No hold-down.
    const e2 = e.recompute(&.{higher}, 2);
    const c2 = e2.change.?;
    try testing.expect(!e2.result.is_local_dis);
    try testing.expectEqual(me.system_id, c2.old_dis.?);
    try testing.expectEqual(higher.system_id, c2.new_dis);
    try testing.expect(c2.resigned_dis);
    try testing.expect(!c2.became_dis);
    try testing.expect(!e.isLocalDis());

    // t=3: the neighbour departs → local is DIS again (became_dis), immediately.
    const e3 = e.recompute(&.{}, 3);
    const c3 = e3.change.?;
    try testing.expect(e3.result.is_local_dis);
    try testing.expectEqual(higher.system_id, c3.old_dis.?);
    try testing.expectEqual(me.system_id, c3.new_dis);
    try testing.expect(c3.became_dis);
    try testing.expect(!c3.resigned_dis);
}

test "a DIS flip between two remote routers is a change with neither became nor resigned" {
    // Local is low priority and never DIS; the DIS moves from one neighbour to a
    // higher one. The change fires but the local flags stay false.
    const low_local: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 1 }, .priority = 1, .snpa = snpa(0x01), .pseudonode_id = 1 };
    const r1: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 2 }, .priority = 40, .snpa = snpa(0x20), .pseudonode_id = 5 };
    const r2: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 3 }, .priority = 80, .snpa = snpa(0x30), .pseudonode_id = 6 };
    var e = Election.init(low_local);
    _ = e.recompute(&.{r1}, 1); // r1 is DIS
    const eff = e.recompute(&.{ r1, r2 }, 2); // r2 preempts r1
    const c = eff.change.?;
    try testing.expectEqual(r1.system_id, c.old_dis.?);
    try testing.expectEqual(r2.system_id, c.new_dis);
    try testing.expect(!c.became_dis);
    try testing.expect(!c.resigned_dis);
    // lan_id tracks the winning neighbour's advertised pseudonode id.
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 3, 6 }, &eff.result.lan_id);
}

test "DisChange keys on lan_id, not just dis_system_id: a stale pseudonode byte still fires a change" {
    // A remote router keeps the SAME system id but its advertised
    // pseudonode id changes between recomputes — e.g. it restarts and picks
    // a different circuit id, or its Hello's lan_id was 0 until it declared
    // itself DIS. `dis_system_id` alone would see no change here (F1); the
    // caller needs a DisChange so it stops tracking the old pseudonode
    // LSP-ID and starts tracking the new one.
    const low_local: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 1 }, .priority = 1, .snpa = snpa(0x01), .pseudonode_id = 1 };
    const remote_old_pn: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 2 }, .priority = 90, .snpa = snpa(0x20), .pseudonode_id = 5 };
    const remote_new_pn: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 2 }, .priority = 90, .snpa = snpa(0x20), .pseudonode_id = 7 };

    var e = Election.init(low_local);
    const e1 = e.recompute(&.{remote_old_pn}, 1);
    try testing.expect(e1.change != null);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 2, 5 }, &e1.result.lan_id);

    // Same winning system id, only the pseudonode byte changed.
    const e2 = e.recompute(&.{remote_new_pn}, 2);
    try testing.expectEqual(remote_old_pn.system_id, e2.result.dis_system_id);
    try testing.expectEqual(remote_new_pn.system_id, e2.result.dis_system_id); // same system id either side
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 2, 7 }, &e2.result.lan_id);
    const c2 = e2.change orelse return error.TestExpectedChangeOnPseudonodeFlip;
    try testing.expectEqual(remote_old_pn.system_id, c2.old_dis.?);
    try testing.expectEqual(remote_new_pn.system_id, c2.new_dis);
}

test "determinism: identical (candidate-set, now) streams yield identical effects" {
    const Run = struct {
        fn drive() [3]bool {
            var e = Election.init(me);
            var seq: [3]bool = undefined;
            seq[0] = e.recompute(&.{}, 1).result.is_local_dis;
            seq[1] = e.recompute(&.{higher}, 2).result.is_local_dis;
            seq[2] = e.recompute(&.{}, 3).result.is_local_dis;
            return seq;
        }
    };
    try testing.expectEqual(Run.drive(), Run.drive());
    try testing.expectEqual([3]bool{ true, false, true }, Run.drive());
}
