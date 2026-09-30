// SPDX-License-Identifier: MIT

//! election — the Designated-Forwarder decision for an N-member edge segment:
//! which member delivers multi-destination (BUM) traffic for each
//! `<segment, Ethernet tag>`, derived from the member's own link-state view
//! (a Hello flood, no BGP), with failover when a member disappears.
//!
//! Three pure pieces, composed by `protocol.zig`:
//!
//!  - **The DF function** (`designatedForwarder`): given the candidate list
//!    (the members this node currently believes alive, itself included) and a
//!    tag, name the DF. Three algorithms: `modulo` — RFC 7432 §8.5 service
//!    carving, ordinal `tag mod N` over the list sorted by address; `hrw` —
//!    RFC 8584 §3.2 Highest Random Weight over `(tag, ESI, address)`; and
//!    `preference` — highest per-member preference, one DF per segment, the
//!    rule FRRouting runs (checked against it in `frr_test.zig`).
//!  - **The role state machine** (`stepRole`): a member gives a DF role up
//!    the moment its view stops naming it, and takes one only after its view
//!    has named it continuously for `df_wait` — RFC 7432 §8.5 step 2's timer
//!    and RFC 8584 §2.1's DF_Wait, reduced to the one asymmetry that matters.
//!  - **Split-horizon** (`allowForward`): never deliver a frame back into the
//!    segment it ingressed from (RFC 7432 §8.3), independent of DF state.
//!
//! ## What is guaranteed, and why duplicates are bounded rather than zero
//!
//! Until 2026-09-30 this module elected a STATIC owner that never changed —
//! `is_df` ignored liveness completely. That bought zero duplicate delivery
//! and cost availability without bound: a dead owner black-holed its segment
//! for ever. The argument for it still stands and says exactly what failover
//! costs: `decide` sees only the local view, a Hello flood cannot tell "peer
//! dead" from "peer unreachable from me", and after a partition heals a BUM
//! frame and the next Hello race across the healed cut. Any rule that lets a
//! survivor take over a role will, in that race, briefly have two members
//! answering DF for one `<segment, tag>` while one frame reaches both. EVPN
//! accepts the same window (RFC 8584 §1.3 discusses it). So the guarantees
//! are now:
//!
//!  1. **Split-horizon: zero tolerance**, always — unchanged.
//!  2. **Duplicates only right after connectivity is restored**: a duplicate
//!     delivery must follow a heal / link-up / restart within
//!     `checks.maxDuplicateWindow` — the time for the next Hello to cross.
//!     Anywhere else it is a bug. In particular startup is duplicate-free:
//!     every member starts with a view containing only itself (so every view
//!     names itself DF for every tag), and `df_wait > hello_period` + flood
//!     delay lets the first Hellos arrive and shrink that claim before any
//!     role is taken. `df_wait = 0` makes the startup race visible again —
//!     `protocol.zig` keeps that as a negative control.
//!  3. **Zero-DF bounded**: after the DF for `<segment, tag>` dies, some
//!     surviving member holds the role within `checks.maxZeroDfWindow`
//!     (detection `stale_after` + `df_wait` + evaluation granularity).
//!  4. **Partitions elect per side**: each side of a partition that holds
//!     members carves the tags among its own members. Two DFs for one tag on
//!     opposite sides is not a fault — no frame reaches both — and closes on
//!     heal as in (2).
//!
//! ## Why losing is immediate and gaining waits
//!
//! Dual DF needs two members that each believe they hold the role. Giving a
//! role up as soon as the view says so shortens every dual window to the time
//! the loser needs to HEAR the other member; making the gain wait means a
//! transiently wrong view (the empty view at startup, a view skewed by a
//! delayed Hello) is corrected before it acts. The asymmetry cannot remove
//! the heal race — both sides legitimately held the role during the
//! partition — which is why (2) is a window and not zero.

const std = @import("std");
const netsim = @import("netsim");
const types = @import("types.zig");

const NodeId = netsim.NodeId;
const Time = netsim.Time;
const SegmentId = types.SegmentId;
const Tag = types.Tag;
const Member = types.Member;
const Algorithm = types.Algorithm;

/// RFC 7432 §8.5 step 3: `candidates` sorted by ascending address (the
/// caller keeps them in `EdgeSegment.members` order, which `validate`
/// requires to be sorted); the member with ordinal `tag mod N` is DF.
pub fn moduloDf(candidates: []const Member, tag: Tag) ?NodeId {
    if (candidates.len == 0) return null;
    return candidates[tag % candidates.len].node;
}

/// RFC 8584 §3.2: `D(V, Es)` is CRC-32 of the 4-octet tag followed by the
/// 10-octet ESI, both in network byte order, with the most significant bit
/// dropped.
pub fn hrwDigest(tag: Tag, esi: [10]u8) u32 {
    var stream: [14]u8 = undefined;
    std.mem.writeInt(u32, stream[0..4], tag, .big);
    stream[4..14].* = esi;
    return std.hash.Crc32.hash(&stream) & 0x7fff_ffff;
}

/// RFC 8584 §3.2:
/// `Wrand(V, Es, Si) = (1103515245((1103515245.Si+12345) XOR D(V, Es))+12345) (mod 2^31)`.
/// Only the low 31 bits of `addr` matter; multiplication, addition and XOR
/// all commute with reduction mod 2^31, so wrapping `u32` arithmetic masked
/// at the end is exact.
pub fn hrwWeight(tag: Tag, esi: [10]u8, addr: u32) u32 {
    const inner = 1103515245 *% addr +% 12345;
    return (1103515245 *% (inner ^ hrwDigest(tag, esi)) +% 12345) & 0x7fff_ffff;
}

/// RFC 8584 §3.2 step 1: the highest weight wins; on a tie, the numerically
/// least address.
pub fn hrwDf(candidates: []const Member, tag: Tag, esi: [10]u8) ?NodeId {
    var best: ?Member = null;
    var best_w: u32 = 0;
    for (candidates) |m| {
        const w = hrwWeight(tag, esi, m.addr);
        if (best == null or w > best_w or (w == best_w and m.addr < best.?.addr)) {
            best = m;
            best_w = w;
        }
    }
    return if (best) |b| b.node else null;
}

/// Preference-based DF: highest `pref`, ties to the numerically least
/// address; the same member for every tag (FRR elects per Ethernet Segment).
pub fn preferenceDf(candidates: []const Member) ?NodeId {
    var best: ?Member = null;
    for (candidates) |m| {
        if (best == null or m.pref > best.?.pref or (m.pref == best.?.pref and m.addr < best.?.addr)) best = m;
    }
    return if (best) |b| b.node else null;
}

/// The DF for `tag` among `candidates` under `algorithm`, or `null` if there
/// is no candidate. Pure: two members with the same candidate list always
/// name the same DF — that is what makes the election need no vote.
pub fn designatedForwarder(algorithm: Algorithm, esi: [10]u8, candidates: []const Member, tag: Tag) ?NodeId {
    return switch (algorithm) {
        .modulo => moduloDf(candidates, tag),
        .hrw => hrwDf(candidates, tag, esi),
        .preference => preferenceDf(candidates),
    };
}

/// One member's standing for one `<segment, tag>`.
pub const Role = struct {
    is_df: bool = false,
    /// When the view started naming this member DF while it did not hold the
    /// role yet; `null` when no gain is pending.
    want_since: ?Time = null,
};

/// Advance a role given whether the member's current view names it DF.
/// Losing is immediate (and cancels a pending gain); gaining needs the view
/// to have named it continuously for `df_wait`. `df_wait = 0` gains at the
/// first evaluation — only the negative control uses that.
pub fn stepRole(role: Role, named: bool, now: Time, df_wait: Time) Role {
    if (!named) return .{};
    if (role.is_df) return role;
    const since = role.want_since orelse now;
    if (now -| since >= df_wait) return .{ .is_df = true };
    return .{ .want_since = since };
}

/// Split-horizon (RFC 7432 §8.3 local bias): may a frame that ingressed from
/// `ingress_segment` (`null` = network side) be delivered to `this_segment`?
/// Deliberately independent of DF state and liveness — it must hold with
/// zero tolerance even inside a dual-DF window. `types.no_ingress` differs
/// from every real segment id, so it needs no special case.
pub fn allowForward(ingress_segment: ?SegmentId, this_segment: SegmentId) bool {
    const ingress = ingress_segment orelse return true;
    return ingress != this_segment;
}

// ── tests ──────────────────────────────────────────────────────────────────
// Byte-level agreement of the two DF functions with an independent
// re-derivation lives in `kat_test.zig`; these are the local properties.

const testing = std.testing;

const three = [_]Member{
    .{ .node = 3, .addr = 0x0a00_0001 },
    .{ .node = 4, .addr = 0x0a00_0002 },
    .{ .node = 5, .addr = 0x0a00_0003 },
};

test "moduloDf: ordinal tag mod N over the address-sorted list (RFC 7432 §8.5)" {
    try testing.expectEqual(@as(?NodeId, 3), moduloDf(&three, 0));
    try testing.expectEqual(@as(?NodeId, 4), moduloDf(&three, 10)); // 10 mod 3 = 1
    try testing.expectEqual(@as(?NodeId, 5), moduloDf(&three, 11));
    try testing.expectEqual(@as(?NodeId, 3), moduloDf(&three, 12));
    // A member drops out: the carving is recomputed over the survivors.
    try testing.expectEqual(@as(?NodeId, 5), moduloDf(&.{ three[0], three[2] }, 11));
    try testing.expectEqual(@as(?NodeId, null), moduloDf(&.{}, 11));
}

test "moduloDf: every tag has exactly one DF and the load is even" {
    var count = [_]usize{ 0, 0, 0 };
    var tag: Tag = 0;
    while (tag < 300) : (tag += 1) {
        const df = moduloDf(&three, tag).?;
        count[df - 3] += 1;
    }
    try testing.expectEqual([_]usize{ 100, 100, 100 }, count);
}

test "hrwDf: highest weight wins, ties go to the least address, and it is minimally disruptive" {
    const esi = [10]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    var tag: Tag = 0;
    var moved: usize = 0;
    var had_3: usize = 0;
    while (tag < 200) : (tag += 1) {
        const df = hrwDf(&three, tag, esi).?;
        // The winner's weight is at least every other member's.
        const w = hrwWeight(tag, esi, three[df - 3].addr);
        for (three) |m| try testing.expect(w >= hrwWeight(tag, esi, m.addr));
        // Removing a member that is NOT the DF never moves the role (RFC 8584
        // §3.2's "no needless disruption"); removing the DF always does.
        const without_5 = hrwDf(&.{ three[0], three[1] }, tag, esi).?;
        if (df != 5) try testing.expectEqual(df, without_5) else moved += 1;
        if (df == 3) had_3 += 1;
    }
    try testing.expect(moved > 0 and moved < 200);
    try testing.expect(had_3 > 0 and had_3 < 200);

    // Tie: two members with the same low 31 address bits have equal weight;
    // the numerically least address wins.
    const tied = [_]Member{ .{ .node = 8, .addr = 0x8000_0005 }, .{ .node = 7, .addr = 0x0000_0005 } };
    try testing.expectEqual(hrwWeight(1, esi, tied[0].addr), hrwWeight(1, esi, tied[1].addr));
    try testing.expectEqual(@as(?NodeId, 7), hrwDf(&tied, 1, esi));
}

test "hrwWeight: masked to 31 bits and sensitive to the ESI" {
    const a = [10]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    const b = [10]u8{ 9, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    var differ: usize = 0;
    var tag: Tag = 0;
    while (tag < 64) : (tag += 1) {
        try testing.expect(hrwWeight(tag, a, 0x0a00_0001) < 0x8000_0000);
        if (hrwWeight(tag, a, 0x0a00_0001) != hrwWeight(tag, b, 0x0a00_0001)) differ += 1;
    }
    try testing.expect(differ > 60);
}

test "stepRole: losing is immediate, gaining waits df_wait of continuous naming" {
    var r: Role = .{};
    r = stepRole(r, true, 100, 150);
    try testing.expect(!r.is_df);
    try testing.expectEqual(@as(?Time, 100), r.want_since);
    r = stepRole(r, true, 249, 150);
    try testing.expect(!r.is_df);
    r = stepRole(r, true, 250, 150);
    try testing.expect(r.is_df);
    // Still named: keeps the role, no new wait.
    r = stepRole(r, true, 900, 150);
    try testing.expect(r.is_df);
    // Not named: loses at once.
    r = stepRole(r, false, 901, 150);
    try testing.expect(!r.is_df);
    try testing.expectEqual(@as(?Time, null), r.want_since);

    // An interruption restarts the wait.
    r = stepRole(.{}, true, 0, 150);
    r = stepRole(r, false, 100, 150);
    r = stepRole(r, true, 120, 150);
    r = stepRole(r, true, 200, 150);
    try testing.expect(!r.is_df);
    r = stepRole(r, true, 270, 150);
    try testing.expect(r.is_df);

    // df_wait = 0 gains at the first evaluation (the negative control's mode).
    try testing.expect(stepRole(.{}, true, 5, 0).is_df);
}

test "preferenceDf: highest preference, ties to the least address, one DF for every tag" {
    const m = [_]Member{
        .{ .node = 3, .addr = 0x0a00_0001, .pref = 100 },
        .{ .node = 4, .addr = 0x0a00_0002, .pref = 300 },
        .{ .node = 5, .addr = 0x0a00_0003, .pref = 300 },
    };
    try testing.expectEqual(@as(?NodeId, 4), preferenceDf(&m));
    for ([_]Tag{ 0, 10, 4094 }) |tag| try testing.expectEqual(@as(?NodeId, 4), designatedForwarder(.preference, @splat(0), &m, tag));
    // Default preferences everywhere: the least address.
    try testing.expectEqual(@as(?NodeId, 3), preferenceDf(&three));
    try testing.expectEqual(@as(?NodeId, null), preferenceDf(&.{}));
}

test "allowForward: everywhere except back onto the ingress segment" {
    try testing.expect(allowForward(null, 1));
    try testing.expect(allowForward(types.no_ingress, 1));
    try testing.expect(allowForward(2, 1));
    try testing.expect(!allowForward(1, 1));
}
