//! pseudonode.zig -- what the DIS puts on the wire and on the LAN once it is
//! elected (ISO/IEC 10589 §7.3.8, §8.4.1): the pseudonode LSP, its purge, the
//! DIS Hello cadence and the per-circuit pseudonode-id.
//!
//! Pure and allocation-free like the election: the caller passes the system ids
//! of the Up LAN neighbours and a buffer, and gets the wire bytes of one LSP
//! fragment back.

const std = @import("std");
const isis = @import("isis");
const election = @import("election.zig");

pub const SystemId = election.SystemId;
pub const Result = election.Result;

/// Octets of one Extended IS Reachability entry without sub-TLVs: neighbour id
/// (7) + metric (3) + sub-TLV length (1).
const entry_len = 11;
/// Entries of one #22 TLV (value at most 255 octets).
const entries_per_tlv = isis.tlv.max_value_len / entry_len;

pub const BuildError = error{
    /// The local system is not the DIS in `result`: only the DIS originates the pseudonode LSP.
    NotDis,
    /// The buffer cannot hold the LSP header and one entry.
    BufferTooSmall,
    /// `first` is past the last entry.
    OutOfRange,
};

pub const Options = struct {
    /// Level 2 (default Level 1).
    is_l2: bool = false,
    /// Sequence number of this fragment; the first origination is 1.
    sequence_number: u32 = 1,
    /// Remaining lifetime in seconds (ISO 10589 `MaxAge` is 1200).
    remaining_lifetime: u16 = 1200,
    /// LSP number of this fragment (the last octet of the LSP-ID); 0 is the first.
    fragment: u8 = 0,
    /// The `isis` IS-Type field: 1 = L1 only, 3 = L1/L2.
    is_type: u2 = 1,
};

/// One built fragment.
pub const Fragment = struct {
    /// The LSP PDU, checksum stamped (§7.3.11).
    wire: []const u8,
    /// Index of the first entry the next fragment starts at; `entry_count`
    /// (= `members.len + 1`) when this one was the last.
    next: usize,
};

/// Build one fragment of the pseudonode LSP the DIS originates for `r`:
/// metric-0 Extended IS Reachability (#22) entries binding the DIS itself and
/// every system in `members` (the Up LAN neighbours, without the local system)
/// to the pseudonode, each as `system-id ‖ 0` (ISO 10589 §7.3.8, RFC 5305 §3).
/// Entries are numbered from 0 (the DIS itself); the fragment starts at entry
/// `first` and takes as many as `buf` holds. A caller whose LAN does not fit
/// builds the following fragments with `first = fragment.next` and
/// `opts.fragment + 1` until `next == members.len + 1`.
///
/// The LSP-ID is `r.pseudonodeLspId()` with `opts.fragment` as the LSP number;
/// the flags are zero (a pseudonode LSP carries no overload or attached bits).
pub fn buildFragment(buf: []u8, r: Result, members: []const SystemId, first: usize, opts: Options) BuildError!Fragment {
    if (!r.is_local_dis) return error.NotDis;
    const total = members.len + 1;
    if (first >= total) return error.OutOfRange;
    var id = r.pseudonodeLspId();
    id[7] = opts.fragment;
    var b = isis.pdu.LspBuilder.init(buf, .{
        .is_l2 = opts.is_l2,
        .remaining_lifetime = opts.remaining_lifetime,
        .lsp_id = id,
        .sequence_number = opts.sequence_number,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = opts.is_type },
    }) catch return error.BufferTooSmall;
    var idx = first;
    while (idx < total) {
        var value: [entries_per_tlv * entry_len]u8 = undefined;
        var n: usize = 0;
        while (n < entries_per_tlv and idx + n < total) : (n += 1) {
            const member: SystemId = if (idx + n == 0) r.dis_system_id else members[idx + n - 1];
            const e = value[n * entry_len ..][0..entry_len];
            @memcpy(e[0..6], &member);
            e[6] = 0; // pseudonode octet of the neighbour: a real system
            std.mem.writeInt(u24, e[7..10], 0, .big); // metric 0 toward a pseudonode member (§7.3.8)
            e[10] = 0; // no sub-TLVs
        }
        // Whole TLV or, when the buffer is short, as many entries as fit.
        while (n > 0) : (n -= 1) {
            b.tlvs.addTlv(isis.tlvs.code.extended_is_reachability, value[0 .. n * entry_len]) catch continue;
            break;
        }
        if (n == 0) {
            if (idx == first) return error.BufferTooSmall;
            break;
        }
        idx += n;
    }
    return .{ .wire = b.finishStamped(), .next = idx };
}

/// The purge of a pseudonode LSP fragment (ISO 10589 §7.3.16.4): the LSP header
/// with remaining lifetime 0 and no TLVs, the sequence number one past the last
/// one originated. Call it for every fragment on `resigned_dis` (and flood it).
pub fn buildPurge(buf: []u8, r: Result, fragment: u8, sequence_number: u32, is_l2: bool) BuildError![]const u8 {
    var id = r.pseudonodeLspId();
    id[7] = fragment;
    var b = isis.pdu.LspBuilder.init(buf, .{
        .is_l2 = is_l2,
        .remaining_lifetime = 0,
        .lsp_id = id,
        .sequence_number = sequence_number,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    }) catch return error.BufferTooSmall;
    return b.finishStamped();
}

/// The interval at which the DIS sends its LAN Hellos, in milliseconds: one
/// third of the configured Hello interval (ISO 10589 §8.4.1.2:
/// `iSISDRISISHelloTimer`), at least 1 ms. A non-DIS keeps the configured one.
pub fn disHelloIntervalMs(hello_interval_s: u16) u32 {
    return @max(1, @as(u32, hello_interval_s) * 1000 / 3);
}

/// The Hello interval to use on a LAN circuit: `disHelloIntervalMs` when the
/// local system is the DIS, the configured interval otherwise.
pub fn helloIntervalMs(hello_interval_s: u16, is_dis: bool) u32 {
    return if (is_dis) disHelloIntervalMs(hello_interval_s) else @as(u32, hello_interval_s) * 1000;
}

/// Hands out the pseudonode ids (the 1-octet circuit id, ISO 10589 §7.3.8) of the
/// LAN circuits of one system: nonzero, distinct per circuit, so a router that
/// is DIS on several LANs never reuses an id. 255 circuits at most.
pub const PseudonodeIdAllocator = struct {
    used: [4]u64 = @splat(0),

    pub const empty: PseudonodeIdAllocator = .{};

    /// The lowest free id (1..255), or null when all are taken.
    pub fn alloc(a: *PseudonodeIdAllocator) ?u8 {
        for (&a.used, 0..) |*w, i| {
            // Bit 0 of word 0 is id 0, never handed out.
            const free = ~(w.* | (if (i == 0) @as(u64, 1) else 0));
            if (free == 0) continue;
            const bit: u6 = @intCast(@ctz(free));
            w.* |= @as(u64, 1) << bit;
            return @intCast(i * 64 + bit);
        }
        return null;
    }

    /// Reserve a specific id (a configured circuit id); false when it is 0 or taken.
    pub fn take(a: *PseudonodeIdAllocator, id: u8) bool {
        if (id == 0 or a.isUsed(id)) return false;
        a.used[id >> 6] |= @as(u64, 1) << @as(u6, @intCast(id & 63));
        return true;
    }

    /// Give `id` back (a circuit went away). Releasing a free id is harmless.
    pub fn release(a: *PseudonodeIdAllocator, id: u8) void {
        if (id == 0) return;
        a.used[id >> 6] &= ~(@as(u64, 1) << @as(u6, @intCast(id & 63)));
    }

    pub fn isUsed(a: PseudonodeIdAllocator, id: u8) bool {
        return a.used[id >> 6] & (@as(u64, 1) << @as(u6, @intCast(id & 63))) != 0;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn sys(last: u8) SystemId {
    return .{ 0, 0, 0, 0, 0, last };
}

fn localDis() Result {
    const local: election.Candidate = .{ .system_id = sys(1), .priority = 64, .snpa = .{ 0, 0, 0, 0, 0, 0xAA }, .pseudonode_id = 5 };
    return election.elect(local, &.{});
}

/// All (neighbour id, metric) pairs of every #22 TLV in `wire`, in order.
fn entries(wire: []const u8, out: *std.ArrayListUnmanaged([7]u8)) !void {
    const lsp = try isis.Lsp.decode(wire);
    var it = lsp.tlvIterator();
    while (try it.next()) |t| {
        if (t.code != isis.tlvs.code.extended_is_reachability) continue;
        var e = isis.tlvs.ExtIsReachIterator.init(t.value);
        while (try e.next()) |x| {
            try testing.expectEqual(@as(u24, 0), x.metric);
            try testing.expectEqual(@as(usize, 0), x.sub_tlvs.len);
            try out.append(testing.allocator, x.neighbour_id);
        }
    }
}

test "pseudonode LSP lists the DIS and every member at metric 0, with a valid checksum" {
    const r = localDis();
    var buf: [512]u8 = undefined;
    const f = try buildFragment(&buf, r, &.{ sys(2), sys(3) }, 0, .{ .sequence_number = 7 });
    try testing.expectEqual(@as(usize, 3), f.next);
    const lsp = try isis.Lsp.decode(f.wire);
    try testing.expectEqual(r.pseudonodeLspId(), lsp.lsp_id);
    try testing.expectEqual(@as(u32, 7), lsp.sequence_number);
    try testing.expectEqual(@as(u16, 1200), lsp.remaining_lifetime);
    try testing.expectEqual(isis.pdu.ChecksumStatus.good, try isis.pdu.checkLspChecksum(f.wire));
    var got: std.ArrayListUnmanaged([7]u8) = .empty;
    defer got.deinit(testing.allocator);
    try entries(f.wire, &got);
    try testing.expectEqual(@as(usize, 3), got.items.len);
    try testing.expectEqualSlices(u8, &(sys(1) ++ [_]u8{0}), &got.items[0]);
    try testing.expectEqualSlices(u8, &(sys(3) ++ [_]u8{0}), &got.items[2]);
}

test "a LAN larger than one fragment splits across fragments with no entry lost or repeated" {
    const r = localDis();
    var members: [100]SystemId = undefined;
    for (&members, 0..) |*m, i| m.* = .{ 0, 0, 0, 0, @as(u8, @intCast(i >> 8)), @as(u8, @intCast(i & 0xff)) + 10 };
    var all: std.ArrayListUnmanaged([7]u8) = .empty;
    defer all.deinit(testing.allocator);
    var first: usize = 0;
    var frag: u8 = 0;
    // 140 octets of buffer: the 27-octet header plus 10 entries.
    var buf: [140]u8 = undefined;
    while (first < members.len + 1) : (frag += 1) {
        const f = try buildFragment(&buf, r, &members, first, .{ .fragment = frag });
        try testing.expect(f.next > first);
        const lsp = try isis.Lsp.decode(f.wire);
        try testing.expectEqual(frag, lsp.lsp_id[7]);
        try entries(f.wire, &all);
        first = f.next;
    }
    try testing.expectEqual(@as(usize, 101), all.items.len);
    for (members, 0..) |m, i| try testing.expectEqualSlices(u8, &(m ++ [_]u8{0}), &all.items[i + 1]);
}

test "refusals: not the DIS, first past the end, buffer too small" {
    const local: election.Candidate = .{ .system_id = sys(1), .priority = 1, .snpa = .{ 0, 0, 0, 0, 0, 1 }, .pseudonode_id = 1 };
    const other: election.Candidate = .{ .system_id = sys(2), .priority = 100, .snpa = .{ 0, 0, 0, 0, 0, 2 } };
    const lost = election.elect(local, &.{other});
    var buf: [256]u8 = undefined;
    try testing.expectError(error.NotDis, buildFragment(&buf, lost, &.{}, 0, .{}));
    const r = localDis();
    try testing.expectError(error.OutOfRange, buildFragment(&buf, r, &.{}, 1, .{}));
    var tiny: [30]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, buildFragment(&tiny, r, &.{}, 0, .{}));
    var none: [10]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, buildFragment(&none, r, &.{}, 0, .{}));
}

test "purge: lifetime 0, no TLVs, fragment in the id, checksum valid" {
    const r = localDis();
    var buf: [64]u8 = undefined;
    const wire = try buildPurge(&buf, r, 2, 9, true);
    const lsp = try isis.Lsp.decode(wire);
    try testing.expectEqual(@as(u16, 0), lsp.remaining_lifetime);
    try testing.expectEqual(@as(u8, 2), lsp.lsp_id[7]);
    try testing.expectEqual(@as(u8, 5), lsp.lsp_id[6]);
    try testing.expectEqual(@as(u32, 9), lsp.sequence_number);
    var it = lsp.tlvIterator();
    try testing.expectEqual(@as(?isis.RawTlv, null), try it.next());
}

test "DIS hello interval is a third of the configured one" {
    try testing.expectEqual(@as(u32, 3333), disHelloIntervalMs(10));
    try testing.expectEqual(@as(u32, 1), disHelloIntervalMs(0));
    try testing.expectEqual(@as(u32, 21845000), disHelloIntervalMs(65535));
    try testing.expectEqual(@as(u32, 3333), helloIntervalMs(10, true));
    try testing.expectEqual(@as(u32, 10000), helloIntervalMs(10, false));
}

test "pseudonode id allocator: nonzero, distinct, lowest free, exhausts at 255, release reuses" {
    var a: PseudonodeIdAllocator = .empty;
    try testing.expectEqual(@as(?u8, 1), a.alloc());
    try testing.expectEqual(@as(?u8, 2), a.alloc());
    try testing.expect(!a.take(2));
    try testing.expect(!a.take(0));
    try testing.expect(a.take(200));
    a.release(1);
    try testing.expectEqual(@as(?u8, 1), a.alloc());
    a.release(0); // never allocated, never freed
    try testing.expect(!a.isUsed(0));
    var n: usize = 3; // 1, 2 and 200 are used; 252 more fit
    while (a.alloc()) |id| : (n += 1) try testing.expect(id != 0 and id != 200);
    try testing.expectEqual(@as(usize, 255), n);
    try testing.expectEqual(@as(?u8, null), a.alloc());
    a.release(255);
    try testing.expectEqual(@as(?u8, 255), a.alloc());
}
