// SPDX-License-Identifier: MIT
//! spbfib — SPB (IEEE 802.1aq / RFC 6329) forwarding addressing: the two pure
//! address computations an SPBM backbone node needs, over the already-computed
//! `isis-spf` route table. The unicast counterpart to the multicast `bumtree`.
//!
//!   **Part A — the unicast B-MAC FIB.** `isis-spf`'s `RouteTable` maps a
//!   destination *system-id* to a next-hop *system-id*. But in SPBM the
//!   data-plane forwarding key is the destination's **backbone MAC (B-MAC)**,
//!   not its system-id: the ingress backbone edge bridge sets the frame's DA to
//!   the *destination* node's B-MAC and every transit node forwards on that DA
//!   unchanged (the DA is not rewritten hop-by-hop). Given the route table and a
//!   caller-supplied **system-id → B-MAC map** (each node's B-MAC lives in its
//!   SPBM-SI sub-TLV, RFC 6329 §3.5.4 — the caller extracts it; see `isis/spb`),
//!   `Fib.build` re-keys every reachable destination by its **destination B-MAC**
//!   and resolves the next-hop system-id to the **next-hop's B-MAC** (which
//!   selects the egress adjacency, not the DA). SPB installs exactly ONE path per
//!   destination — the single congruent ECT path `isis-spf` already selected —
//!   so there is **no per-flow ECMP hashing** at the data plane. (The 16 ECT
//!   algorithms spread paths across I-SIDs/B-VIDs, not within a flow.)
//!
//!   **Part B — the SPBM group multicast-DA.** A BUM frame for an I-SID uses a
//!   group destination B-MAC derived from the source node's 20-bit **SPSourceID**
//!   and the 24-bit **I-SID** — the very DA whose per-source distribution tree
//!   `bumtree` computes. `groupDa`/`parseGroupDa` implement the RFC 6329 §4.4
//!   Figure-1 construction (bit layout documented on `groupDa`).
//!
//! Pure, deterministic, leak-free; `isis-spf` + `std` only. The system-id→B-MAC
//! map and each node's SPSourceID are INPUTS the caller extracts from the SPB
//! TLVs — this module parses no TLVs and recomputes no SPF. See `SPEC.md`.

const std = @import("std");
const spf = @import("isis-spf");

const Allocator = std.mem.Allocator;

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "IEEE 802.1aq SPBM unicast B-MAC FIB + group-DA construction (RFC 6329 §4.4)",
    .deps = .{"isis-spf"},
};

/// A 6-octet IS-IS system-id — the node identity in the topology. Re-exported
/// from `isis-spf` so a consumer of the FIB need not also import it.
pub const SystemId = spf.SystemId;

/// A 48-bit backbone MAC (B-MAC), MSB-first (octet 0 first on the wire). The
/// SPBM data-plane forwarding key.
pub const BMac = [6]u8;

// ─────────────────────────────────────────────────────────────────────────────
// Part A — the unicast B-MAC FIB
// ─────────────────────────────────────────────────────────────────────────────

/// One `(system-id, B-MAC)` binding — the caller extracts each node's B-MAC from
/// its SPBM-SI sub-TLV (RFC 6329 §3.5.4; see `isis/spb.SpbmServiceId.b_mac`) or
/// from configuration, and passes the set to `Fib.build`. Order is irrelevant
/// (the FIB is deterministic regardless); a repeated `system_id` keeps the FIRST
/// binding and ignores later ones (documented, so the result is independent of
/// input order).
pub const BmacEntry = struct {
    system_id: SystemId,
    b_mac: BMac,
};

/// One resolved unicast forwarding entry, keyed by the DESTINATION's B-MAC
/// (`dest_bmac`, the data-plane DA). `next_hop_bmac` is the adjacent bridge the
/// frame egresses toward — it selects the outgoing adjacency and is generally
/// **different** from `dest_bmac` for a multi-hop destination (the DA is not
/// rewritten; only the egress port is chosen by the next hop). For the local
/// self route, `local` is set and `next_hop_* == dest_*` (local delivery,
/// metric 0).
pub const Entry = struct {
    /// The FIB key: the destination node's B-MAC (the frame DA).
    dest_bmac: BMac,
    /// The destination node's system-id (the route's `dest`).
    dest_system_id: SystemId,
    /// The next-hop bridge's B-MAC — selects the egress adjacency. Equals
    /// `dest_bmac` for a directly-adjacent destination and for the self route.
    next_hop_bmac: BMac,
    /// The next-hop bridge's system-id (the route's `next_hop`).
    next_hop_system_id: SystemId,
    /// Total path cost from the local system (the `isis-spf` route metric).
    metric: u64,
    /// The local "self" route → local delivery rather than a real forward.
    local: bool,
};

/// Tuning for `buildWith`. The default is the correct SPBM behaviour; the
/// non-default exists only for the permanent positive control.
pub const Options = struct {
    /// The FIB key. When `false` (default, correct) each entry is keyed by the
    /// **destination's** B-MAC — the frame DA the whole fabric forwards on. When
    /// `true` the entry is instead keyed by the **next-hop's** B-MAC —
    /// deliberately WRONG (a multi-hop destination would then be unreachable by
    /// its own DA, and several destinations sharing a next hop would collide on
    /// one key); kept solely to prove, in a permanent test, that keying by the
    /// destination B-MAC is load-bearing.
    key_by_next_hop_bmac: bool = false,
};

/// The computed unicast B-MAC forwarding table — entries sorted ascending by
/// their key B-MAC (ties broken by destination system-id, so the order is total
/// and deterministic). Caller-owned; free with `deinit`.
pub const Fib = struct {
    gpa: Allocator,
    entries: []Entry,

    pub fn deinit(self: *Fib) void {
        self.gpa.free(self.entries);
        self.* = undefined;
    }

    /// The entry whose key B-MAC is `dest_bmac`, or `null` if none. O(log n) —
    /// `entries` is sorted by `dest_bmac`. (In the default/correct build the key
    /// IS the destination B-MAC, so this is "look up by destination DA".)
    pub fn lookup(self: *const Fib, dest_bmac: BMac) ?Entry {
        var lo: usize = 0;
        var hi: usize = self.entries.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            switch (std.mem.order(u8, &self.entries[mid].dest_bmac, &dest_bmac)) {
                .eq => return self.entries[mid],
                .lt => lo = mid + 1,
                .gt => hi = mid,
            }
        }
        return null;
    }
};

/// Build the unicast B-MAC FIB from `route_table` (an already-computed
/// `isis-spf.RouteTable`) and `bmac_map` (each node's system-id → B-MAC), with
/// correct destination-B-MAC keying. See `buildWith` for the skip rules and the
/// degenerate cases.
pub fn build(
    gpa: Allocator,
    route_table: *const spf.RouteTable,
    bmac_map: []const BmacEntry,
) Allocator.Error!Fib {
    return buildWith(gpa, route_table, bmac_map, .{});
}

/// `build` with explicit `Options`.
///
/// For every route in `route_table` (which contains only reachable
/// destinations, already sorted by destination system-id):
///   - The **self route** (`metric == 0`, the local system) becomes a
///     `local`-delivery entry: `next_hop_bmac == dest_bmac`, metric 0.
///   - A **remote/adjacent** destination is keyed by its own B-MAC, with the
///     next-hop system-id resolved to the next-hop's B-MAC.
///
/// Skip rules (documented; an entry you cannot forward on is worse than an
/// absent one, so the FIB never carries an unusable entry):
///   - **Destination B-MAC unknown** (`dest` not in `bmac_map`) → the route is
///     skipped; that destination has no FIB entry.
///   - **Next-hop B-MAC unknown** (`next_hop` not in `bmac_map`, for a non-self
///     route) → skipped too: without the next-hop B-MAC the egress adjacency is
///     unresolvable, so the entry could not forward.
///
/// Degenerate cases (all defined, none panic):
///   - **Empty route table** → empty FIB.
///   - **Local-only table** (just the self route) → a single `local` entry.
///   - An **unreachable** destination never appears in an `isis-spf` route table
///     in the first place, so it is naturally absent from the FIB.
///
/// Determinism: destinations are taken in the route table's sorted order and the
/// result is re-sorted by key B-MAC (ties → destination system-id); `bmac_map`
/// is consulted only by point lookup, so the FIB is identical regardless of
/// `bmac_map` order.
pub fn buildWith(
    gpa: Allocator,
    route_table: *const spf.RouteTable,
    bmac_map: []const BmacEntry,
    opts: Options,
) Allocator.Error!Fib {
    // system-id → B-MAC, first binding wins (⇒ order-independent).
    var by_id: std.AutoHashMapUnmanaged(SystemId, BMac) = .empty;
    defer by_id.deinit(gpa);
    for (bmac_map) |e| {
        const gop = try by_id.getOrPut(gpa, e.system_id);
        if (!gop.found_existing) gop.value_ptr.* = e.b_mac;
    }

    var entries: std.ArrayList(Entry) = .empty;
    errdefer entries.deinit(gpa);

    for (route_table.routes) |r| {
        const dest_bmac = by_id.get(r.dest) orelse continue; // dest B-MAC unknown → skip
        const is_local = r.metric == 0;
        const next_hop_bmac = if (is_local)
            dest_bmac // self route: local delivery, no distinct next hop
        else
            (by_id.get(r.next_hop) orelse continue); // next-hop B-MAC unknown → skip

        const key = if (opts.key_by_next_hop_bmac) next_hop_bmac else dest_bmac;
        try entries.append(gpa, .{
            .dest_bmac = key,
            .dest_system_id = r.dest,
            .next_hop_bmac = next_hop_bmac,
            .next_hop_system_id = r.next_hop,
            .metric = r.metric,
            .local = is_local,
        });
    }

    const owned = try entries.toOwnedSlice(gpa);
    std.mem.sort(Entry, owned, {}, lessEntry);
    return .{ .gpa = gpa, .entries = owned };
}

/// Total order on entries: by key B-MAC, then by destination system-id (so the
/// order is deterministic even if two destinations were to share a key B-MAC).
fn lessEntry(_: void, a: Entry, b: Entry) bool {
    return switch (std.mem.order(u8, &a.dest_bmac, &b.dest_bmac)) {
        .lt => true,
        .gt => false,
        .eq => std.mem.order(u8, &a.dest_system_id, &b.dest_system_id) == .lt,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Part B — the SPBM group multicast-DA
// ─────────────────────────────────────────────────────────────────────────────

/// The decoded (SPSourceID, I-SID) pair of an SPBM group multicast DA.
pub const GroupDa = struct {
    spsourceid: u20,
    isid: u24,
};

/// The low-nibble flag bits of octet 0 of an SPBM group DA: **M** (I/G multicast
/// bit, `0x01`) + **L** (locally-administered bit, `0x02`), with **TYP** = 00
/// (`0x0C` clear — the only SPSourceID type defined). RFC 6329 §4.4 Figure 1.
pub const group_da_flags: u8 = 0x03;

/// Construct the 48-bit SPBM group multicast destination B-MAC for a BUM frame
/// sourced by SPSourceID `spsourceid` on service `isid` (RFC 6329 §4.4, Fig. 1):
///
/// ```text
///     M L TYP
///   +-+-+-+-+-------+---------------+---------------+---------------+
///   |1|1|0|0|SPSrcMS|  SPSrc[8:15]  |  SPSrc[0:7]   | I-SID[16:23]  |  octets 0..3
///   +-+-+-+-+-------+---------------+---------------+---------------+
///   | I-SID[8:15]   |  I-SID[0:7]   |                                  octets 4..5
///   +---------------+---------------+
/// ```
///
/// RFC 6329's figure numbers bits least-significant-first within each octet (its
/// note: "the index numbering from less significant bit to more significant bit
/// … gives the wire order … the IEEE convention … reverses the bits within an
/// octet compared with IETF practice"), so the leftmost cell **M** is the
/// canonical `0x01` bit of octet 0 — the ordinary Ethernet I/G bit. Concretely:
///   - **octet 0** = `M(0x01) | L(0x02) | (SPSrcMS << 4)`, where SPSrcMS is the
///     top 4 bits of the SPSourceID — TYP occupies `0x04|0x08` and is left 0.
///   - **octets 1–2** = the remaining 16 bits of the SPSourceID (big-endian).
///   - **octets 3–5** = the 24-bit I-SID (big-endian, the low 24 bits of the DA).
///
/// Cross-checked byte-for-byte against RFC-6329-derived worked examples:
/// `groupDa(0x04001, 200) == 03:40:01:00:00:C8` and
/// `groupDa(0xE8607, 0x0006E9) == E3:86:07:00:06:E9`. Total function; the result
/// is always a well-formed group + locally-administered MAC. Inverse:
/// `parseGroupDa`.
pub fn groupDa(spsourceid: u20, isid: u24) BMac {
    const sp: u32 = spsourceid;
    const id: u32 = isid;
    const sp_ms: u8 = @intCast((sp >> 16) & 0x0F); // top 4 bits → octet-0 high nibble
    return .{
        group_da_flags | (sp_ms << 4),
        @intCast((sp >> 8) & 0xFF),
        @intCast(sp & 0xFF),
        @intCast((id >> 16) & 0xFF),
        @intCast((id >> 8) & 0xFF),
        @intCast(id & 0xFF),
    };
}

/// Decode an SPBM group multicast DA back to its `(spsourceid, isid)`, or `null`
/// if `da` is not a well-formed SPBM group DA — i.e. its octet-0 flag nibble is
/// not exactly M+L with TYP 00 (`da[0] & 0x0F != group_da_flags`). Exact inverse
/// of `groupDa`: `parseGroupDa(groupDa(sp, isid)) == .{ sp, isid }`.
pub fn parseGroupDa(da: BMac) ?GroupDa {
    if (da[0] & 0x0F != group_da_flags) return null;
    const sp_ms: u20 = @as(u20, da[0] >> 4); // octet-0 high nibble = top 4 bits
    return .{
        .spsourceid = (sp_ms << 16) | (@as(u20, da[1]) << 8) | @as(u20, da[2]),
        .isid = (@as(u24, da[3]) << 16) | (@as(u24, da[4]) << 8) | @as(u24, da[5]),
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// tests
// ─────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn sysId(last: u8) SystemId {
    return .{ 0, 0, 0, 0, 0, last };
}

/// A distinct, locally-administered B-MAC per node (0x02 = local, unicast).
fn bmac(last: u8) BMac {
    return .{ 0x02, 0, 0, 0, 0, last };
}

/// Build a real `isis-spf.RouteTable` from hand-derived routes. Within this
/// module's dependency budget (`isis-spf` + `std` only, no `isis-lsdb`) the table
/// is constructed from its public fields directly rather than via
/// `isis-spf.compute` over an LSDB — the routes below are exactly what that
/// compute emits for the stated topology (they mirror `isis-spf`'s own golden
/// line-topology test: A—B(10), B—C(10) ⇒ {a,a,0},{b,b,10},{c,b,20}). The type,
/// its `lookup`, and its `deinit` are the genuine `isis-spf` ones.
fn makeTable(gpa: Allocator, routes: []const spf.Route) !spf.RouteTable {
    return .{ .gpa = gpa, .routes = try gpa.dupe(spf.Route, routes) };
}

// ── Part A ───────────────────────────────────────────────────────────────────

test "golden line A-B-C: exact dest-B-MAC FIB incl. a multi-hop next hop" {
    const gpa = testing.allocator;
    const a = sysId(0xA);
    const b = sysId(0xB);
    const c = sysId(0xC);

    // The route table isis-spf produces for the line A—B(10)—C(10), rooted at A.
    var table = try makeTable(gpa, &.{
        .{ .dest = a, .next_hop = a, .metric = 0 }, // self
        .{ .dest = b, .next_hop = b, .metric = 10 }, // direct
        .{ .dest = c, .next_hop = b, .metric = 20 }, // via B
    });
    defer table.deinit();

    const map = [_]BmacEntry{
        .{ .system_id = a, .b_mac = bmac(0xA) },
        .{ .system_id = b, .b_mac = bmac(0xB) },
        .{ .system_id = c, .b_mac = bmac(0xC) },
    };

    var fib = try build(gpa, &table, &map);
    defer fib.deinit();

    try testing.expectEqual(@as(usize, 3), fib.entries.len);

    // Self route → local delivery, next hop == dest, metric 0.
    try testing.expectEqual(Entry{
        .dest_bmac = bmac(0xA),
        .dest_system_id = a,
        .next_hop_bmac = bmac(0xA),
        .next_hop_system_id = a,
        .metric = 0,
        .local = true,
    }, fib.lookup(bmac(0xA)).?);

    // Direct neighbour B: next-hop B-MAC == dest B-MAC.
    try testing.expectEqual(Entry{
        .dest_bmac = bmac(0xB),
        .dest_system_id = b,
        .next_hop_bmac = bmac(0xB),
        .next_hop_system_id = b,
        .metric = 10,
        .local = false,
    }, fib.lookup(bmac(0xB)).?);

    // Multi-hop C: keyed by C's B-MAC, but the next-hop B-MAC is B's (≠ dest).
    const c_entry = fib.lookup(bmac(0xC)).?;
    try testing.expectEqual(bmac(0xC), c_entry.dest_bmac);
    try testing.expectEqual(bmac(0xB), c_entry.next_hop_bmac); // next hop ≠ dest
    try testing.expectEqual(b, c_entry.next_hop_system_id);
    try testing.expectEqual(@as(u64, 20), c_entry.metric);
    try testing.expect(!c_entry.local);
}

test "unknown destination B-MAC is skipped (not a crash)" {
    const gpa = testing.allocator;
    const a = sysId(0xA);
    const b = sysId(0xB);
    const c = sysId(0xC);

    var table = try makeTable(gpa, &.{
        .{ .dest = a, .next_hop = a, .metric = 0 },
        .{ .dest = b, .next_hop = b, .metric = 10 },
        .{ .dest = c, .next_hop = b, .metric = 20 },
    });
    defer table.deinit();

    // C reachable, but its B-MAC is not in the map.
    const map = [_]BmacEntry{
        .{ .system_id = a, .b_mac = bmac(0xA) },
        .{ .system_id = b, .b_mac = bmac(0xB) },
    };

    var fib = try build(gpa, &table, &map);
    defer fib.deinit();

    try testing.expectEqual(@as(usize, 2), fib.entries.len);
    try testing.expect(fib.lookup(bmac(0xC)) == null); // C skipped
    try testing.expect(fib.lookup(bmac(0xB)) != null);
}

test "next-hop with no B-MAC: the reachable destination is skipped (documented rule)" {
    const gpa = testing.allocator;
    const a = sysId(0xA);
    const b = sysId(0xB);
    const f = sysId(0xF);
    const g = sysId(0x9); // the next hop toward F, deliberately absent from the map

    var table = try makeTable(gpa, &.{
        .{ .dest = a, .next_hop = a, .metric = 0 },
        .{ .dest = b, .next_hop = b, .metric = 10 },
        .{ .dest = f, .next_hop = g, .metric = 30 }, // F reachable via G
    });
    defer table.deinit();

    // F's own B-MAC IS known, but its next hop G's is not → cannot resolve egress.
    const map = [_]BmacEntry{
        .{ .system_id = a, .b_mac = bmac(0xA) },
        .{ .system_id = b, .b_mac = bmac(0xB) },
        .{ .system_id = f, .b_mac = bmac(0xF) },
    };

    var fib = try build(gpa, &table, &map);
    defer fib.deinit();

    try testing.expectEqual(@as(usize, 2), fib.entries.len);
    try testing.expect(fib.lookup(bmac(0xF)) == null); // F skipped: no next-hop B-MAC
}

test "determinism: shuffled bmac_map order yields a byte-identical FIB" {
    const gpa = testing.allocator;
    const a = sysId(0xA);
    const b = sysId(0xB);
    const c = sysId(0xC);
    const d = sysId(0xD);

    var table = try makeTable(gpa, &.{
        .{ .dest = a, .next_hop = a, .metric = 0 },
        .{ .dest = b, .next_hop = b, .metric = 10 },
        .{ .dest = c, .next_hop = b, .metric = 20 },
        .{ .dest = d, .next_hop = b, .metric = 30 },
    });
    defer table.deinit();

    const order1 = [_]BmacEntry{
        .{ .system_id = a, .b_mac = bmac(0xA) },
        .{ .system_id = b, .b_mac = bmac(0xB) },
        .{ .system_id = c, .b_mac = bmac(0xC) },
        .{ .system_id = d, .b_mac = bmac(0xD) },
    };
    const order2 = [_]BmacEntry{
        .{ .system_id = d, .b_mac = bmac(0xD) },
        .{ .system_id = c, .b_mac = bmac(0xC) },
        .{ .system_id = b, .b_mac = bmac(0xB) },
        .{ .system_id = a, .b_mac = bmac(0xA) },
    };

    var f1 = try build(gpa, &table, &order1);
    defer f1.deinit();
    var f2 = try build(gpa, &table, &order2);
    defer f2.deinit();

    try testing.expectEqualSlices(Entry, f1.entries, f2.entries);
    // And sorted ascending by key B-MAC.
    for (f1.entries[0..f1.entries.len -| 1], f1.entries[1..]) |x, y| {
        try testing.expect(std.mem.order(u8, &x.dest_bmac, &y.dest_bmac) == .lt);
    }
}

test "duplicate binding: the first B-MAC for a system-id wins, order-independently" {
    const gpa = testing.allocator;
    const a = sysId(0xA);
    const b = sysId(0xB);

    var table = try makeTable(gpa, &.{
        .{ .dest = a, .next_hop = a, .metric = 0 },
        .{ .dest = b, .next_hop = b, .metric = 10 },
    });
    defer table.deinit();

    // Two bindings for B; the first (0xB) must win.
    const map = [_]BmacEntry{
        .{ .system_id = a, .b_mac = bmac(0xA) },
        .{ .system_id = b, .b_mac = bmac(0xB) },
        .{ .system_id = b, .b_mac = bmac(0x7) }, // ignored
    };

    var fib = try build(gpa, &table, &map);
    defer fib.deinit();
    try testing.expect(fib.lookup(bmac(0xB)) != null);
    try testing.expect(fib.lookup(bmac(0x7)) == null);
}

test "degenerate: empty route table → empty FIB; local-only → one local entry" {
    const gpa = testing.allocator;
    const a = sysId(0xA);

    // Empty table.
    {
        var table = try makeTable(gpa, &.{});
        defer table.deinit();
        var fib = try build(gpa, &table, &.{});
        defer fib.deinit();
        try testing.expectEqual(@as(usize, 0), fib.entries.len);
        try testing.expect(fib.lookup(bmac(0xA)) == null);
    }
    // Local-only table (just the self route).
    {
        var table = try makeTable(gpa, &.{.{ .dest = a, .next_hop = a, .metric = 0 }});
        defer table.deinit();
        const map = [_]BmacEntry{.{ .system_id = a, .b_mac = bmac(0xA) }};
        var fib = try build(gpa, &table, &map);
        defer fib.deinit();
        try testing.expectEqual(@as(usize, 1), fib.entries.len);
        try testing.expect(fib.entries[0].local);
        try testing.expectEqual(bmac(0xA), fib.entries[0].next_hop_bmac);
    }
}

test "positive control: keying by the next hop makes the golden dest lookup RED" {
    const gpa = testing.allocator;
    const a = sysId(0xA);
    const b = sysId(0xB);
    const c = sysId(0xC);

    var table = try makeTable(gpa, &.{
        .{ .dest = a, .next_hop = a, .metric = 0 },
        .{ .dest = b, .next_hop = b, .metric = 10 },
        .{ .dest = c, .next_hop = b, .metric = 20 }, // multi-hop via B
    });
    defer table.deinit();
    const map = [_]BmacEntry{
        .{ .system_id = a, .b_mac = bmac(0xA) },
        .{ .system_id = b, .b_mac = bmac(0xB) },
        .{ .system_id = c, .b_mac = bmac(0xC) },
    };

    // Correct: C is reachable by its own B-MAC, and its entry is well-formed.
    {
        var fib = try buildWith(gpa, &table, &map, .{ .key_by_next_hop_bmac = false });
        defer fib.deinit();
        try testing.expect(fib.lookup(bmac(0xC)) != null);
    }
    // Broken control: C's entry is mis-keyed under its next hop (B's B-MAC), so a
    // lookup by C's own DA finds nothing — the golden assertion would go RED.
    // This is what proves destination-B-MAC keying is load-bearing.
    {
        var fib = try buildWith(gpa, &table, &map, .{ .key_by_next_hop_bmac = true });
        defer fib.deinit();
        try testing.expect(fib.lookup(bmac(0xC)) == null);
    }
}

// ── Part B ───────────────────────────────────────────────────────────────────

test "groupDa: exact bytes vs RFC 6329 §4.4 hand-derived worked examples" {
    // I-SID 200 (0xC8), SPSourceID 0x04001 ⇒ 03:40:01:00:00:C8.
    try testing.expectEqual(
        BMac{ 0x03, 0x40, 0x01, 0x00, 0x00, 0xC8 },
        groupDa(0x04001, 200),
    );
    // SPSourceID 0xE8607, I-SID 0x0006E9 ⇒ E3:86:07:00:06:E9 (first octet 0xE3 =
    // 1110 SPSrcMS · 00 TYP · 1 L · 1 M).
    try testing.expectEqual(
        BMac{ 0xE3, 0x86, 0x07, 0x00, 0x06, 0xE9 },
        groupDa(0xE8607, 0x0006E9),
    );
}

test "groupDa: M (group) + L (local) bits set, TYP zero, for any input" {
    const cases = [_]struct { sp: u20, id: u24 }{
        .{ .sp = 0, .id = 0 },
        .{ .sp = 0xFFFFF, .id = 0xFFFFFF },
        .{ .sp = 0x12345, .id = 0xABCDEF },
        .{ .sp = 0x04001, .id = 200 },
    };
    for (cases) |c| {
        const da = groupDa(c.sp, c.id);
        try testing.expect(da[0] & 0x01 != 0); // M: group / multicast
        try testing.expect(da[0] & 0x02 != 0); // L: locally administered
        try testing.expectEqual(@as(u8, 0), da[0] & 0x0C); // TYP == 00
    }
}

test "parseGroupDa round-trips groupDa across the field extremes" {
    const cases = [_]struct { sp: u20, id: u24 }{
        .{ .sp = 0, .id = 0 },
        .{ .sp = 0xFFFFF, .id = 0xFFFFFF },
        .{ .sp = 0xFFFFF, .id = 0 },
        .{ .sp = 0, .id = 0xFFFFFF },
        .{ .sp = 0x12345, .id = 0x67890A },
        .{ .sp = 0xE8607, .id = 0x0006E9 },
    };
    for (cases) |c| {
        const back = parseGroupDa(groupDa(c.sp, c.id)).?;
        try testing.expectEqual(c.sp, back.spsourceid);
        try testing.expectEqual(c.id, back.isid);
    }
}

test "distinct (spsourceid, isid) pairs → distinct DAs" {
    const cases = [_]GroupDa{
        .{ .spsourceid = 1, .isid = 100 },
        .{ .spsourceid = 2, .isid = 100 },
        .{ .spsourceid = 1, .isid = 101 },
        .{ .spsourceid = 0x10000, .isid = 100 }, // differs only in SPSrcMS nibble
        .{ .spsourceid = 1, .isid = 0x010000 }, // differs only in I-SID high octet
    };
    for (cases, 0..) |x, i| {
        for (cases[i + 1 ..]) |y| {
            const dx = groupDa(x.spsourceid, x.isid);
            const dy = groupDa(y.spsourceid, y.isid);
            try testing.expect(!std.mem.eql(u8, &dx, &dy));
        }
    }
}

test "field isolation: I-SID lives in octets 3-5, SPSourceID in octets 0-2" {
    const base = groupDa(0x12345, 0x0000FF);
    // Change ONLY the I-SID → only octets 3-5 move.
    const id_moved = groupDa(0x12345, 0x0100FF);
    try testing.expectEqualSlices(u8, base[0..3], id_moved[0..3]); // SPSourceID octets unchanged
    try testing.expect(!std.mem.eql(u8, base[3..6], id_moved[3..6]));
    // Change ONLY the SPSourceID → only octets 0-2 move.
    const sp_moved = groupDa(0x12300, 0x0000FF);
    try testing.expectEqualSlices(u8, base[3..6], sp_moved[3..6]); // I-SID octets unchanged
    try testing.expect(!std.mem.eql(u8, base[0..3], sp_moved[0..3]));
}

test "parseGroupDa rejects a non-SPBM DA (bad flag nibble)" {
    try testing.expect(parseGroupDa(.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }) == null); // broadcast
    try testing.expect(parseGroupDa(.{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x64 }) == null); // TYP/M/L clear
    try testing.expect(parseGroupDa(.{ 0x01, 0x00, 0x5E, 0x00, 0x00, 0x01 }) == null); // IPv4 mcast: L clear
    // A well-formed one is accepted.
    try testing.expect(parseGroupDa(.{ 0x03, 0x40, 0x01, 0x00, 0x00, 0xC8 }) != null);
}

test "positive control: mis-placing the I-SID bits breaks the exact-byte DA" {
    // A deliberately-wrong construction that writes the I-SID where the
    // SPSourceID belongs (and vice-versa). It must differ from the correct DA —
    // proving the golden byte assertion actually pins the field positions.
    const sp: u32 = 0x12345;
    const id: u32 = 0xABCDEF;
    const wrong: BMac = .{
        group_da_flags | (@as(u8, @intCast((id >> 16) & 0x0F)) << 4), // I-SID in the SPSrcMS nibble
        @intCast((id >> 8) & 0xFF),
        @intCast(id & 0xFF),
        @intCast((sp >> 16) & 0xFF),
        @intCast((sp >> 8) & 0xFF),
        @intCast(sp & 0xFF),
    };
    try testing.expect(!std.mem.eql(u8, &wrong, &groupDa(0x12345, 0xABCDEF)));
}

test "meta is well-formed" {
    try testing.expectEqual(.any, meta.platform);
    try testing.expectEqual(.util, meta.role);
    try testing.expectEqual(.single_owner, meta.concurrency);
}
