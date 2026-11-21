// SPDX-License-Identifier: MIT
//! Local LSP generation for the IS-IS update process (ISO/IEC 10589 §7.3.7,
//! §7.3.8, §7.3.9): build this system's LSP — fragment 0 and as many further
//! fragments as the content needs — from a description of its state, manage
//! the sequence numbers, and hand the result to the database with
//! `Lsdb.insert(bytes, null, now)`, the way the update process's own LSPs
//! enter it.
//!
//! The generator is a function over the database, not a second state holder:
//! which fragments exist, their sequence numbers, which ones were challenged
//! by a neighbour (`EntryView.challenge_sequence`) and which are due a refresh
//! (`Lsdb.refreshPending`) are all read from the `Lsdb`, so the two cannot
//! disagree. Pure and time-injected like the store: it allocates nothing, the
//! caller supplies `now` and a scratch buffer.
//!
//! ## What one call does
//! `generate` rebuilds the LSP described by an `Origin` and, fragment by
//! fragment, inserts the ones that are new, changed (TLV content or flags,
//! ignoring the Authentication TLV's digest), challenged, due for refresh
//! or `Origin.force`d, each at `max(stored sequence, challenge sequence) + 1`
//! (§7.3.16.1 own-LSP rule; 1 for a fragment the database does not hold).
//! An unchanged fragment is left alone, so its sequence number does not move
//! and nothing is flooded. Stored fragments past the last one now needed are
//! purged at their next sequence number (§7.3.4: an LSP that is no longer
//! needed is purged, not left to age out).
//!
//! The checksum is stamped (§7.3.11); with `Config.auth_keys` set every
//! fragment carries a #10 signed with `auth_keys[0]` (RFC 5304 / 5310),
//! because the keyed peers refuse an LSP without one. The overload bit is set
//! when `Origin.overload` is or while the store is in the LSPDBOverload state
//! (`Lsdb.isOverloaded`, §7.3.19), so shedding an LSP makes the next
//! `generate` advertise it; call `generate` again when `AgeReport.overload_cleared`
//! says it ended.
//!
//! ## Packing
//! Fragment 0 carries, in order, Authentication, Area Addresses (#1),
//! Protocols Supported (#129) and Dynamic Hostname (#137) when given — a
//! system's identity must be in fragment 0, so if they do not fit it is
//! `error.FragmentTooSmall`, never a spill. Then the IS neighbours (one
//! Extended IS Reachability #22 entry per TLV) and the caller's raw TLVs
//! (`Origin.tlvs`, e.g. IP reachability or SPB TLVs the `isis` codec builds),
//! first-fit: when one does not fit, the next fragment begins. A pseudonode
//! LSP (`Origin.pseudonode != 0`) carries only the neighbours and raw TLVs.
//!
//! Clean-room from ISO/IEC 10589 §7.3.4–§7.3.9; behaviour cross-checked
//! against holo-isis `lsp_build*` (MIT, docs level) and FRR `lsp_generate`
//! as documented. No source ported.

const std = @import("std");
const isis = @import("isis");
const store = @import("store.zig");

const Lsdb = store.Lsdb;
const Time = store.Time;
const LspId = store.LspId;

/// ISO/IEC 10589 `originatingL1LSPBufferSize` / `originatingL2LSPBufferSize`
/// default: the largest LSP this system generates, in octets.
pub const default_buffer_size: usize = 1492;

/// ISO/IEC 10589 `MaxAge`, the lifetime a freshly generated LSP starts with.
pub const default_lifetime: u16 = 1200;

/// The smallest `Origin.buffer_size`: the LSP header plus one maximal-value
/// TLV is not required, but a fragment must at least hold its header and a
/// signed Authentication TLV.
pub const min_buffer_size: usize = 512;

/// One IS neighbour, advertised as an Extended IS Reachability (#22) entry.
pub const Neighbour = struct {
    /// System id (6) and pseudonode id (1) of the neighbour; the pseudonode id
    /// is non-zero for a LAN's DIS.
    id: [7]u8,
    metric: u24 = 10,
    /// An already-serialised sub-TLV block (RFC 5305), at most 244 octets.
    sub_tlvs: []const u8 = &.{},
};

/// What this system's LSP says.
pub const Origin = struct {
    /// 0 for the system's own LSP, a circuit's pseudonode id for the pseudonode
    /// LSP this system generates as DIS (only neighbours and `tlvs`).
    pseudonode: u8 = 0,
    is_l2: bool = false,
    /// Remaining Lifetime of a generated fragment.
    lifetime: u16 = default_lifetime,
    /// Set the overload bit regardless of the store's LSPDBOverload state.
    overload: bool = false,
    /// The default-metric Attached bit (L1 LSPs of an L1/L2 system that reaches
    /// another area).
    attached: bool = false,
    /// Area addresses (#1), Protocols Supported (#129) NLPIDs, Dynamic Hostname
    /// (#137): fragment 0 of the system's own LSP only.
    area_addresses: []const []const u8 = &.{},
    protocols_supported: []const u8 = &.{},
    hostname: ?[]const u8 = null,
    neighbours: []const Neighbour = &.{},
    /// Further TLVs, emitted verbatim after the neighbours.
    tlvs: []const isis.RawTlv = &.{},
    /// Largest LSP to generate, in octets (<= the scratch buffer).
    buffer_size: usize = default_buffer_size,
    /// Insert every fragment even when it is unchanged and not due.
    force: bool = false,
};

pub const GenerateError = store.InsertError || error{
    /// The scratch buffer is smaller than `Origin.buffer_size`, or that is
    /// below `min_buffer_size`.
    BufferTooSmall,
    /// Fragment 0's identity TLVs, or a single TLV, do not fit one fragment.
    FragmentTooSmall,
    /// More than 256 fragments would be needed.
    TooManyFragments,
    /// A TLV value is longer than 255 octets (a raw TLV, or sub-TLVs over 244).
    ValueTooLong,
    /// An area address does not fit Area Addresses (#1).
    BadAreaAddress,
};

pub const Result = struct {
    /// Fragments the LSP now consists of (1 + the highest fragment number).
    fragments: u16 = 0,
    /// Fragments inserted by this call (new, changed, challenged, refreshed).
    written: u16 = 0,
    /// Stored fragments past the last needed one that were purged.
    purged: u16 = 0,
};

fn lspId(db: *const Lsdb, pseudonode: u8, fragment: u8) LspId {
    var id: LspId = undefined;
    @memcpy(id[0..6], &db.cfg.local_system_id);
    id[6] = pseudonode;
    id[7] = fragment;
    return id;
}

/// The next sequence number for `id`: above the stored copy and above any
/// neighbour's claim for it. `SequenceExhausted` when that passes 2^32-1.
fn nextSequence(db: *const Lsdb, id: LspId, now: Time) error{SequenceExhausted}!u32 {
    const v = db.get(id, now) orelse return 1;
    const base = @max(v.sequence_number, v.challenge_sequence);
    if (base == store.max_sequence_number) return error.SequenceExhausted;
    return base + 1;
}

/// Same TLV content (ignoring #10) and same flags.
fn sameContent(old: []const u8, new: []const u8) bool {
    const a = isis.Lsp.decode(old) catch return false;
    const b = isis.Lsp.decode(new) catch return false;
    if (a.flags.toByte() != b.flags.toByte()) return false;
    var ia = a.tlvIterator();
    var ib = b.tlvIterator();
    while (true) {
        const ta = nextNonAuth(&ia) orelse {
            return nextNonAuth(&ib) == null;
        };
        const tb = nextNonAuth(&ib) orelse return false;
        if (ta.code != tb.code or !std.mem.eql(u8, ta.value, tb.value)) return false;
    }
}

fn nextNonAuth(it: *isis.TlvIterator) ?isis.RawTlv {
    while (true) {
        const t = (it.next() catch return null) orelse return null;
        if (t.code != isis.auth.tlv_code) return t;
    }
}

const Gen = struct {
    db: *Lsdb,
    o: Origin,
    now: Time,
    buf: []u8,
    keyed: bool,
    frag: u16 = 0,
    b: isis.pdu.LspBuilder = undefined,
    seq: u32 = 0,
    /// Fragment 0's identity TLVs must not spill.
    strict: bool = true,
    res: Result = .{},

    fn flags(g: *const Gen) isis.pdu.LspFlags {
        return .{
            .partition_repair = false,
            .attached = if (g.o.attached) 1 else 0,
            .overload = g.o.overload or g.db.isOverloaded(),
            .is_type = if (g.o.is_l2) 3 else 1,
        };
    }

    fn begin(g: *Gen) GenerateError!void {
        const id = lspId(g.db, g.o.pseudonode, @intCast(g.frag));
        g.seq = try nextSequence(g.db, id, g.now);
        g.b = try isis.pdu.LspBuilder.init(g.buf, .{
            .is_l2 = g.o.is_l2,
            .remaining_lifetime = g.o.lifetime,
            .lsp_id = id,
            .sequence_number = g.seq,
            .flags = g.flags(),
        });
        if (g.keyed) isis.auth.addPlaceholder(&g.b.tlvs, g.db.cfg.auth_keys[0]) catch return error.FragmentTooSmall;
    }

    /// Close the current fragment and insert it unless it is unchanged.
    fn finish(g: *Gen) GenerateError!void {
        const id = lspId(g.db, g.o.pseudonode, @intCast(g.frag));
        var wire = g.b.finish();
        if (g.keyed) {
            isis.auth.sign(g.buf[0..wire.len], g.db.cfg.auth_keys[0]) catch return error.FragmentTooSmall;
        } else {
            _ = isis.pdu.stampLspChecksum(g.buf[0..wire.len]) catch unreachable;
        }
        wire = g.buf[0..wire.len];
        g.res.fragments += 1;
        if (!g.o.force) if (g.db.get(id, g.now)) |v| {
            if (!v.is_purge and !v.is_request and v.challenge_sequence == 0 and
                !g.db.refreshPending(id) and sameContent(v.bytes, wire)) return;
        };
        _ = try g.db.insert(wire, null, g.now);
        g.res.written += 1;
    }

    fn rollover(g: *Gen) GenerateError!void {
        try g.finish();
        if (g.frag == 255) return error.TooManyFragments;
        g.frag += 1;
        try g.begin();
    }

    fn add(g: *Gen, code: u8, value: []const u8) GenerateError!void {
        g.b.tlvs.addTlv(code, value) catch |e| switch (e) {
            error.ValueTooLong => return error.ValueTooLong,
            error.BufferTooSmall => {
                if (g.strict) return error.FragmentTooSmall;
                try g.rollover();
                g.b.tlvs.addTlv(code, value) catch return error.FragmentTooSmall;
            },
        };
    }

    fn addNeighbour(g: *Gen, n: Neighbour) GenerateError!void {
        var tmp: [isis.tlv.max_value_len + 2]u8 = undefined;
        var tb = isis.tlv.Builder.init(&tmp);
        isis.tlvs.addExtendedIsReach(&tb, n.id, n.metric, n.sub_tlvs) catch return error.ValueTooLong;
        const w = tb.written();
        try g.add(w[0], w[2..]);
    }
};

/// Generate (or refresh) this system's LSP described by `o` and insert the
/// fragments that need it. `scratch` is the build buffer, at least
/// `o.buffer_size` octets. If an insert fails (`DatabaseFull`,
/// `SequenceExhausted`) the fragments before it stay inserted and the call
/// can simply be repeated: unchanged fragments are skipped.
pub fn generate(db: *Lsdb, o: Origin, now: Time, scratch: []u8) GenerateError!Result {
    if (o.buffer_size < min_buffer_size or scratch.len < o.buffer_size) return error.BufferTooSmall;
    var g: Gen = .{
        .db = db,
        .o = o,
        .now = now,
        .buf = scratch[0..o.buffer_size],
        .keyed = db.cfg.auth_keys.len != 0,
    };
    try g.begin();
    if (o.pseudonode == 0) {
        if (o.area_addresses.len != 0) {
            var tmp: [isis.tlv.max_value_len + 2]u8 = undefined;
            var tb = isis.tlv.Builder.init(&tmp);
            isis.tlvs.addAreaAddresses(&tb, o.area_addresses) catch return error.BadAreaAddress;
            const w = tb.written();
            try g.add(w[0], w[2..]);
        }
        if (o.protocols_supported.len != 0) try g.add(isis.tlvs.code.protocols_supported, o.protocols_supported);
        if (o.hostname) |h| try g.add(isis.tlvs.code.dynamic_hostname, h);
    }
    g.strict = false;
    for (o.neighbours) |n| try g.addNeighbour(n);
    for (o.tlvs) |t| try g.add(t.code, t.value);
    try g.finish();
    const last: u16 = g.frag;
    var res = g.res;
    res.purged = try purgeFragments(db, o.pseudonode, o.is_l2, last + 1, now, scratch);
    return res;
}

/// Purge this system's stored fragments `first_fragment..255` of the LSP
/// `pseudonode` (all of a pseudonode LSP the system stops generating when it
/// resigns as DIS: `first_fragment = 0`), each at its next sequence number
/// with Remaining Lifetime 0. Returns how many were purged. Also the answer to
/// `InsertResult.self_challenge` for a fragment the store holds no copy of
/// (the neighbour's copy is purged by inserting a purge above its sequence:
/// use `purgeAt`).
pub fn purgeFragments(db: *Lsdb, pseudonode: u8, is_l2: bool, first_fragment: u16, now: Time, scratch: []u8) GenerateError!u16 {
    var n: u16 = 0;
    var f: u16 = first_fragment;
    while (f <= 255) : (f += 1) {
        const id = lspId(db, pseudonode, @intCast(f));
        const v = db.get(id, now) orelse continue;
        if (v.is_purge or v.is_request) continue;
        try purgeAt(db, id, is_l2, @max(v.sequence_number, v.challenge_sequence), now, scratch);
        n += 1;
    }
    return n;
}

/// Insert a purge (Remaining Lifetime 0, no body) of the own LSP `id` at
/// sequence `above + 1`. With `Config.auth_keys` the purge carries a signed
/// #10 (RFC 5304 §2). `scratch` needs 600 octets.
pub fn purgeAt(db: *Lsdb, id: LspId, is_l2: bool, above: u32, now: Time, scratch: []u8) GenerateError!void {
    if (scratch.len < min_buffer_size) return error.BufferTooSmall;
    if (above == store.max_sequence_number) return error.SequenceExhausted;
    var b = try isis.pdu.LspBuilder.init(scratch, .{
        .is_l2 = is_l2,
        .remaining_lifetime = 0,
        .lsp_id = id,
        .sequence_number = above + 1,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = if (is_l2) 3 else 1 },
    });
    const keyed = db.cfg.auth_keys.len != 0;
    if (keyed) isis.auth.addPlaceholder(&b.tlvs, db.cfg.auth_keys[0]) catch return error.FragmentTooSmall;
    var wire = b.finish();
    if (keyed) {
        isis.auth.sign(scratch[0..wire.len], db.cfg.auth_keys[0]) catch return error.FragmentTooSmall;
    } else {
        _ = isis.pdu.stampLspChecksum(scratch[0..wire.len]) catch unreachable;
    }
    wire = scratch[0..wire.len];
    _ = try db.insert(wire, null, now);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const sys_local: [6]u8 = .{ 0, 0, 0, 0, 0, 0xA };
const sys_peer: [6]u8 = .{ 0, 0, 0, 0, 0, 0xB };

fn newDb() Lsdb {
    return Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 64 });
}

fn ownId(pn: u8, frag: u8) LspId {
    return .{ 0, 0, 0, 0, 0, 0xA, pn, frag };
}

fn peerLspBytes(buf: []u8, seq: u32, id: LspId, life: u16) []const u8 {
    var b = isis.pdu.LspBuilder.init(buf, .{
        .remaining_lifetime = life,
        .lsp_id = id,
        .sequence_number = seq,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    }) catch unreachable;
    return b.finishStamped();
}

const area49: []const u8 = &.{ 0x49, 0x00, 0x01 };

fn basicOrigin(neighbours: []const Neighbour) Origin {
    return .{
        .area_addresses = &.{area49},
        .protocols_supported = &.{isis.tlvs.nlpid_ipv4},
        .hostname = "r1",
        .neighbours = neighbours,
    };
}

test "fragment 0 carries identity TLVs then neighbours, with a valid checksum, and enters the database" {
    var db = newDb();
    defer db.deinit();
    var scratch: [default_buffer_size]u8 = undefined;
    const nb = [_]Neighbour{.{ .id = .{ 0, 0, 0, 0, 0, 0xB, 0 }, .metric = 20 }};
    const r = try generate(&db, basicOrigin(&nb), 100, &scratch);
    try testing.expectEqual(@as(u16, 1), r.fragments);
    try testing.expectEqual(@as(u16, 1), r.written);
    const v = db.get(ownId(0, 0), 100).?;
    try testing.expectEqual(@as(u32, 1), v.sequence_number);
    try testing.expect(v.self_originated);
    try testing.expectEqual(@as(u16, 1200), v.remaining_lifetime);
    try testing.expectEqual(isis.pdu.ChecksumStatus.good, try isis.pdu.checkLspChecksum(v.bytes));
    const lsp = try isis.Lsp.decode(v.bytes);
    var it = lsp.tlvIterator();
    try testing.expectEqual(@as(u8, 1), (try it.next()).?.code);
    try testing.expectEqual(@as(u8, 129), (try it.next()).?.code);
    try testing.expectEqual(@as(u8, 137), (try it.next()).?.code);
    const t = (try it.next()).?;
    try testing.expectEqual(@as(u8, 22), t.code);
    var ei = isis.tlvs.ExtIsReachIterator.init(t.value);
    const e = (try ei.next()).?;
    try testing.expectEqual(@as(u24, 20), e.metric);
    try testing.expect((try it.next()) == null);
    // Flooded everywhere.
    try testing.expect(db.srmIsSet(ownId(0, 0), 0) and db.srmIsSet(ownId(0, 0), 1));
}

test "an unchanged LSP is not regenerated; a changed one moves to sequence + 1; refresh_pending and force regenerate" {
    var db = newDb();
    defer db.deinit();
    var scratch: [default_buffer_size]u8 = undefined;
    const nb1 = [_]Neighbour{.{ .id = .{ 0, 0, 0, 0, 0, 0xB, 0 } }};
    _ = try generate(&db, basicOrigin(&nb1), 0, &scratch);
    const same = try generate(&db, basicOrigin(&nb1), 10, &scratch);
    try testing.expectEqual(@as(u16, 0), same.written);
    try testing.expectEqual(@as(u32, 1), db.get(ownId(0, 0), 10).?.sequence_number);
    const nb2 = [_]Neighbour{ nb1[0], .{ .id = .{ 0, 0, 0, 0, 0, 0xC, 0 } } };
    const chg = try generate(&db, basicOrigin(&nb2), 20, &scratch);
    try testing.expectEqual(@as(u16, 1), chg.written);
    try testing.expectEqual(@as(u32, 2), db.get(ownId(0, 0), 20).?.sequence_number);
    // Refresh: aging flags it, generate re-issues the same content at seq + 1.
    _ = db.tick(20 + 1200 - 300);
    try testing.expect(db.refreshPending(ownId(0, 0)));
    const rf = try generate(&db, basicOrigin(&nb2), 920, &scratch);
    try testing.expectEqual(@as(u16, 1), rf.written);
    try testing.expectEqual(@as(u32, 3), db.get(ownId(0, 0), 920).?.sequence_number);
    try testing.expectEqual(@as(u16, 1200), db.get(ownId(0, 0), 920).?.remaining_lifetime);
    try testing.expect(!db.refreshPending(ownId(0, 0)));
    // force
    var o = basicOrigin(&nb2);
    o.force = true;
    try testing.expectEqual(@as(u16, 1), (try generate(&db, o, 921, &scratch)).written);
    try testing.expectEqual(@as(u32, 4), db.get(ownId(0, 0), 921).?.sequence_number);
}

test "a neighbour's challenge raises the next sequence above its claim" {
    var db = newDb();
    defer db.deinit();
    var scratch: [default_buffer_size]u8 = undefined;
    const o = basicOrigin(&.{});
    _ = try generate(&db, o, 0, &scratch);
    var buf: [128]u8 = undefined;
    const r = try db.insert(peerLspBytes(&buf, 500, ownId(0, 0), 1000), 0, 1);
    try testing.expectEqual(@as(?u32, 500), r.self_challenge);
    const g = try generate(&db, o, 2, &scratch);
    try testing.expectEqual(@as(u16, 1), g.written);
    try testing.expectEqual(@as(u32, 501), db.get(ownId(0, 0), 2).?.sequence_number);
    try testing.expectEqual(@as(u32, 0), db.get(ownId(0, 0), 2).?.challenge_sequence);
}

test "many neighbours spill into fragments 1.. and shrinking purges the surplus fragments" {
    var db = newDb();
    defer db.deinit();
    var scratch: [default_buffer_size]u8 = undefined;
    var ns: [400]Neighbour = undefined;
    for (&ns, 0..) |*n, i| n.* = .{ .id = .{ 0, 0, 1, 0, @intCast(i >> 8), @intCast(i & 0xff), 0 } };
    const r = try generate(&db, basicOrigin(&ns), 0, &scratch);
    try testing.expect(r.fragments >= 3);
    try testing.expectEqual(r.fragments, r.written);
    var total: usize = 0;
    var f: u8 = 0;
    while (f < r.fragments) : (f += 1) {
        const v = db.get(ownId(0, f), 0).?;
        try testing.expect(v.bytes.len <= default_buffer_size);
        try testing.expectEqual(isis.pdu.ChecksumStatus.good, try isis.pdu.checkLspChecksum(v.bytes));
        var it = (try isis.Lsp.decode(v.bytes)).tlvIterator();
        while (try it.next()) |t| {
            if (t.code == 22) total += 1;
            // identity TLVs only in fragment 0
            if (f != 0) try testing.expect(t.code == 22);
        }
    }
    try testing.expectEqual(@as(usize, 400), total);
    // Shrink to one fragment: the others are purged at seq + 1.
    const few = [_]Neighbour{ns[0]};
    const s = try generate(&db, basicOrigin(&few), 5, &scratch);
    try testing.expectEqual(@as(u16, 1), s.fragments);
    try testing.expectEqual(r.fragments - 1, s.purged);
    const v1 = db.get(ownId(0, 1), 5).?;
    try testing.expect(v1.is_purge);
    try testing.expectEqual(@as(u32, 2), v1.sequence_number);
    // Idempotent: a second call purges nothing more.
    try testing.expectEqual(@as(u16, 0), (try generate(&db, basicOrigin(&few), 6, &scratch)).purged);
}

test "a pseudonode LSP carries only neighbours; purgeFragments withdraws it" {
    var db = newDb();
    defer db.deinit();
    var scratch: [default_buffer_size]u8 = undefined;
    const members = [_]Neighbour{ .{ .id = .{ 0, 0, 0, 0, 0, 0xA, 0 }, .metric = 0 }, .{ .id = .{ 0, 0, 0, 0, 0, 0xB, 0 }, .metric = 0 } };
    var o = basicOrigin(&members); // identity fields must be ignored for a pseudonode
    o.pseudonode = 3;
    o.is_l2 = true;
    _ = try generate(&db, o, 0, &scratch);
    const v = db.get(ownId(3, 0), 0).?;
    const lsp = try isis.Lsp.decode(v.bytes);
    try testing.expectEqual(isis.PduType.l2_lsp, lsp.header.pdu_type);
    var it = lsp.tlvIterator();
    while (try it.next()) |t| try testing.expectEqual(@as(u8, 22), t.code);
    try testing.expectEqual(@as(u16, 1), try purgeFragments(&db, 3, true, 0, 1, &scratch));
    try testing.expect(db.get(ownId(3, 0), 1).?.is_purge);
}

test "overload bit follows the option and the LSPDBOverload state; a change regenerates fragment 0" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 2, .overload_recovery = 10 });
    defer db.deinit();
    var scratch: [default_buffer_size]u8 = undefined;
    var o = basicOrigin(&.{});
    _ = try generate(&db, o, 0, &scratch);
    try testing.expect(!db.get(ownId(0, 0), 0).?.flags.overload);
    var buf: [128]u8 = undefined;
    _ = try db.insert(peerLspBytes(&buf, 1, .{ 0, 0, 0, 0, 0, 0xB, 0, 0 }, 1000), 0, 0);
    try testing.expectError(error.DatabaseFull, db.insert(peerLspBytes(&buf, 1, .{ 0, 0, 0, 0, 0, 0xC, 0, 0 }, 1000), 0, 0));
    try testing.expect(db.isOverloaded());
    const g = try generate(&db, o, 1, &scratch);
    try testing.expectEqual(@as(u16, 1), g.written);
    try testing.expect(db.get(ownId(0, 0), 1).?.flags.overload);
    // Explicit option on a healthy store.
    var db2 = newDb();
    defer db2.deinit();
    o.overload = true;
    _ = try generate(&db2, o, 0, &scratch);
    try testing.expect(db2.get(ownId(0, 0), 0).?.flags.overload);
}

test "with auth keys every fragment and purge carries a signed #10 that verifies" {
    const key: isis.auth.Key = .{ .algorithm = .hmac_sha256, .id = 7, .secret = "secret" };
    const keys = [_]isis.auth.Key{key};
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 64, .auth_keys = &keys });
    defer db.deinit();
    var scratch: [default_buffer_size]u8 = undefined;
    var ns: [120]Neighbour = undefined;
    for (&ns, 0..) |*n, i| n.* = .{ .id = .{ 0, 0, 1, 0, 0, @intCast(i), 0 } };
    const r = try generate(&db, basicOrigin(&ns), 0, &scratch);
    try testing.expect(r.fragments >= 2);
    var f: u8 = 0;
    while (f < r.fragments) : (f += 1) {
        const v = db.get(ownId(0, f), 0).?;
        try testing.expectEqual(@as(usize, 0), try isis.auth.verify(v.bytes, &keys));
        try testing.expectEqual(isis.pdu.ChecksumStatus.good, try isis.pdu.checkLspChecksum(v.bytes));
    }
    // Unchanged content is recognised despite the changing digest.
    try testing.expectEqual(@as(u16, 0), (try generate(&db, basicOrigin(&ns), 1, &scratch)).written);
    // Purge of the surplus: signed.
    _ = try generate(&db, basicOrigin(ns[0..1]), 2, &scratch);
    const p = db.get(ownId(0, 1), 2).?;
    try testing.expect(p.is_purge);
    try testing.expectEqual(@as(usize, 0), try isis.auth.verify(p.bytes, &keys));
}

test "sequence exhaustion and size limits are errors, not wraparound" {
    var db = newDb();
    defer db.deinit();
    var scratch: [default_buffer_size]u8 = undefined;
    const o = basicOrigin(&.{});
    _ = try generate(&db, o, 0, &scratch);
    var buf: [128]u8 = undefined;
    // A neighbour claims the top of the space for our fragment: refused by the
    // own-LSP rule, recorded as the challenge; generating again cannot go on.
    _ = try db.insert(peerLspBytes(&buf, store.max_sequence_number, ownId(0, 0), 1000), 0, 1);
    try testing.expectError(error.SequenceExhausted, generate(&db, o, 2, &scratch));
    try testing.expectError(error.BufferTooSmall, generate(&db, .{ .buffer_size = 100 }, 0, &scratch));
    try testing.expectError(error.BufferTooSmall, generate(&db, o, 0, scratch[0..600]));
    // Identity TLVs that cannot fit fragment 0 do not spill.
    var o2 = o;
    o2.buffer_size = min_buffer_size;
    const area13: [13]u8 = @splat(1);
    const areas18: [18][]const u8 = @splat(&area13);
    o2.area_addresses = &areas18;
    const nlpids: [250]u8 = @splat(isis.tlvs.nlpid_ipv4);
    o2.protocols_supported = &nlpids;
    var db3 = newDb();
    defer db3.deinit();
    try testing.expectError(error.FragmentTooSmall, generate(&db3, o2, 0, &scratch));
}

test "a database that cannot take the LSP reports DatabaseFull and a repeat finishes the job" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 1 });
    defer db.deinit();
    var scratch: [default_buffer_size]u8 = undefined;
    var ns: [200]Neighbour = undefined;
    for (&ns, 0..) |*n, i| n.* = .{ .id = .{ 0, 0, 1, 0, 0, @intCast(i), 0 } };
    try testing.expectError(error.DatabaseFull, generate(&db, basicOrigin(&ns), 0, &scratch));
    try testing.expect(db.get(ownId(0, 0), 0) != null);
}
