// SPDX-License-Identifier: MIT
//! rtnetlink request construction for the tc message families: qdiscs
//! (`RTM_*QDISC`), classes (`RTM_*TCLASS`) and filters (`RTM_*TFILTER`).
//!
//! Every builder emits `nlmsghdr` + `struct tcmsg` + `TCA_KIND` +
//! `TCA_OPTIONS`, and is pure (allocator in, owned byte slice out) so the
//! whole layer is golden-testable against bytes captured from real
//! `iproute2` — see `goldens.zig`.
//!
//! The `TCA_OPTIONS` nest is written **without** `NLA_F_NESTED`, matching
//! iproute2's `addattr_nest` (the kernel's validators ignore the bit; sending
//! it would make every request differ from `tc`'s by one bit and defeat
//! byte-exact goldens).

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const native_endian = builtin.cpu.arch.endian();

const netlink = @import("netlink");
const codec = netlink.codec;

const handle_mod = @import("handle.zig");
const Handle = handle_mod.Handle;
const ratespec = @import("ratespec.zig");
const Psched = ratespec.Psched;
const qdisc = @import("qdisc.zig");
const filter = @import("filter.zig");
const action = @import("action.zig");

pub const tcmsg_len = qdisc.tcmsg_len;
/// `sizeof(struct tcamsg)` — the fixed header of the **standalone** action
/// family. It is only 4 bytes (family + two pads), not the 20-byte `tcmsg`;
/// sending a `tcmsg` on an `RTM_*ACTION` shifts every attribute by 16 bytes
/// and the kernel rejects the message.
pub const tcamsg_len = action.tcamsg_len;

// ── rtnetlink message types ─────────────────────────────────────────────────

pub const RTM_NEWQDISC: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_NEWQDISC);
pub const RTM_DELQDISC: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_DELQDISC);
pub const RTM_GETQDISC: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_GETQDISC);
pub const RTM_NEWTCLASS: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_NEWTCLASS);
pub const RTM_DELTCLASS: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_DELTCLASS);
pub const RTM_GETTCLASS: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_GETTCLASS);
pub const RTM_NEWTFILTER: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_NEWTFILTER);
pub const RTM_DELTFILTER: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_DELTFILTER);
pub const RTM_GETTFILTER: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_GETTFILTER);
pub const RTM_NEWACTION: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_NEWACTION);
pub const RTM_DELACTION: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_DELACTION);
pub const RTM_GETACTION: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_GETACTION);

/// How a create-style request behaves when the object already exists.
/// Mirrors `netlink.Create` for the tc families.
pub const Create = enum {
    /// `NLM_F_CREATE|NLM_F_EXCL` — fail with `error.Exists` if present
    /// (`tc … add`).
    add,
    /// `NLM_F_CREATE|NLM_F_REPLACE` — create or overwrite (`tc … replace`).
    replace,
    /// No create bits — modify an existing object only (`tc … change`).
    change,

    pub fn flags(c: Create) u16 {
        const base = codec.NLM_F_REQUEST | codec.NLM_F_ACK;
        return switch (c) {
            .add => base | codec.NLM_F_CREATE | codec.NLM_F_EXCL,
            .replace => base | codec.NLM_F_CREATE | codec.NLM_F_REPLACE,
            .change => base,
        };
    }
};

pub const BuildError = qdisc.EncodeError || filter.EncodeError;

// ── request targets ─────────────────────────────────────────────────────────

/// Which qdisc a request addresses.
pub const QdiscTarget = struct {
    ifindex: u32,
    /// The handle to give the qdisc (`handle 1:`); `unspec` lets the kernel
    /// pick one.
    handle: Handle = Handle.unspec,
    /// Where to attach — `Handle.root`, `Handle.ingress`, or a class handle
    /// for a leaf qdisc under an htb class.
    parent: Handle = Handle.root,
};

/// Which class a request addresses.
pub const ClassTarget = struct {
    ifindex: u32,
    /// The class id (`classid 1:10`).
    handle: Handle,
    /// The qdisc or class it hangs under (`parent 1:` / `parent 1:10`).
    /// `unspec` is what `tc class del dev X classid 1:10` sends — the kernel
    /// finds the parent from the handle.
    parent: Handle = Handle.unspec,
};

/// Which filter a request addresses. `prio` + `eth_type` are packed into
/// `tcm_info`, not into attributes.
pub const FilterTarget = struct {
    ifindex: u32,
    /// The attach point (`parent 1:`, `parent ffff:` for ingress, …).
    parent: Handle = Handle.root,
    /// `prio`/`pref`; 0 lets the kernel allocate one.
    prio: u16 = 0,
    /// `protocol` as a host-order ethertype (`filter.ETH_P.IP`).
    eth_type: u16 = filter.ETH_P.ALL,
    /// The filter handle (`handle 800::800`); `unspec` lets the kernel pick.
    handle: Handle = Handle.unspec,
};

// ── primitives ──────────────────────────────────────────────────────────────

/// Append a `struct tcmsg`: u8 family, u8 pad1, u16 pad2, i32 ifindex,
/// u32 handle, u32 parent, u32 info.
pub fn appendTcmsg(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    ifindex: u32,
    handle: Handle,
    parent: Handle,
    info: u32,
) std.mem.Allocator.Error!void {
    var buf: [tcmsg_len]u8 = @splat(0); // family/pad1/pad2 stay 0
    std.mem.writeInt(i32, buf[4..8], @bitCast(ifindex), native_endian);
    std.mem.writeInt(u32, buf[8..12], handle.raw, native_endian);
    std.mem.writeInt(u32, buf[12..16], parent.raw, native_endian);
    std.mem.writeInt(u32, buf[16..20], info, native_endian);
    try codec.appendPadded(gpa, list, &buf);
}

fn appendKind(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    kind: []const u8,
) std.mem.Allocator.Error!void {
    codec.appendAttrString(gpa, list, qdisc.TCA.KIND, kind) catch |err| switch (err) {
        error.AttrTooLong => unreachable, // kind strings are <= IFNAMSIZ
        error.OutOfMemory => return error.OutOfMemory,
    };
}

// ── qdisc ───────────────────────────────────────────────────────────────────

/// Build an `RTM_NEWQDISC` request (`tc qdisc add|replace|change`).
pub fn buildQdiscSet(
    gpa: std.mem.Allocator,
    seq: u32,
    op: Create,
    target: QdiscTarget,
    spec: qdisc.QdiscSpec,
    ps: Psched,
) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(gpa, &list, RTM_NEWQDISC, op.flags(), seq, 0);
    try appendTcmsg(gpa, &list, target.ifindex, target.handle, target.parent, 0);
    try appendKind(gpa, &list, spec.kind());
    // `mq` (and any future kind whose children the kernel populates) carries no
    // `TCA_OPTIONS` at all; every other kind gets a nest, empty when it has no
    // knobs, exactly as `tc` does.
    if (spec.carriesOptions()) {
        const nest = try codec.nestBegin(gpa, &list, qdisc.TCA.OPTIONS);
        try spec.appendOptions(gpa, &list, ps);
        codec.nestEnd(&list, nest);
    }
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Build an `RTM_DELQDISC` request (`tc qdisc del`).
pub fn buildQdiscDel(
    gpa: std.mem.Allocator,
    seq: u32,
    target: QdiscTarget,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        RTM_DELQDISC,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK,
        seq,
        0,
    );
    try appendTcmsg(gpa, &list, target.ifindex, target.handle, target.parent, 0);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

// ── class ───────────────────────────────────────────────────────────────────

/// Build an `RTM_NEWTCLASS` request (`tc class add|replace|change`).
pub fn buildClassSet(
    gpa: std.mem.Allocator,
    seq: u32,
    op: Create,
    target: ClassTarget,
    spec: qdisc.ClassSpec,
    ps: Psched,
) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(gpa, &list, RTM_NEWTCLASS, op.flags(), seq, 0);
    try appendTcmsg(gpa, &list, target.ifindex, target.handle, target.parent, 0);
    try appendKind(gpa, &list, spec.kind());
    const nest = try codec.nestBegin(gpa, &list, qdisc.TCA.OPTIONS);
    try spec.appendOptions(gpa, &list, ps);
    codec.nestEnd(&list, nest);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Build an `RTM_DELTCLASS` request (`tc class del`).
pub fn buildClassDel(
    gpa: std.mem.Allocator,
    seq: u32,
    target: ClassTarget,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        RTM_DELTCLASS,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK,
        seq,
        0,
    );
    try appendTcmsg(gpa, &list, target.ifindex, target.handle, target.parent, 0);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

// ── filter ──────────────────────────────────────────────────────────────────

/// Build an `RTM_NEWTFILTER` request (`tc filter add|replace|change`).
///
/// Kept at its v2 signature for source compatibility; it pins
/// `Psched.fallback`, which only matters for a `police` action's burst
/// ticks. Use `buildFilterSetWith` (or `Socket.filterAdd`, which passes the
/// socket's own calibration) when the spec carries actions.
pub fn buildFilterSet(
    gpa: std.mem.Allocator,
    seq: u32,
    op: Create,
    target: FilterTarget,
    spec: filter.FilterSpec,
) BuildError![]u8 {
    return buildFilterSetWith(gpa, seq, op, target, spec, Psched.fallback);
}

/// `buildFilterSet` with an explicit psched calibration.
pub fn buildFilterSetWith(
    gpa: std.mem.Allocator,
    seq: u32,
    op: Create,
    target: FilterTarget,
    spec: filter.FilterSpec,
    ps: Psched,
) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(gpa, &list, RTM_NEWTFILTER, op.flags(), seq, 0);
    const info = filter.makeInfo(target.prio, target.eth_type);
    try appendTcmsg(gpa, &list, target.ifindex, target.handle, target.parent, info);
    try appendKind(gpa, &list, spec.kind());
    const nest = try codec.nestBegin(gpa, &list, qdisc.TCA.OPTIONS);
    try spec.appendOptionsWith(gpa, &list, ps);
    codec.nestEnd(&list, nest);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Build an `RTM_DELTFILTER` request (`tc filter del`). `kind` is optional:
/// `tc filter del dev X parent 1: protocol ip prio 1` sends no `TCA_KIND` at
/// all, and the kernel matches on (parent, prio, protocol, handle) alone.
pub fn buildFilterDel(
    gpa: std.mem.Allocator,
    seq: u32,
    target: FilterTarget,
    kind: ?[]const u8,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        RTM_DELTFILTER,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK,
        seq,
        0,
    );
    const info = filter.makeInfo(target.prio, target.eth_type);
    try appendTcmsg(gpa, &list, target.ifindex, target.handle, target.parent, info);
    if (kind) |k| try appendKind(gpa, &list, k);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

// ── standalone actions (the shared action table) ────────────────────────────

/// Append a `struct tcamsg`: u8 family, u8 pad1, u16 pad2 — all zero, exactly
/// what `tc actions …` sends.
pub fn appendTcamsg(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
) std.mem.Allocator.Error!void {
    const buf: [tcamsg_len]u8 = @splat(0);
    try codec.appendPadded(gpa, list, &buf);
}

/// Build an `RTM_NEWACTION` request (`tc actions add|replace|change`) that
/// installs one or more actions in the shared table. Each spec's `index`
/// picks its table slot; 0 lets the kernel allocate one.
pub fn buildActionSet(
    gpa: std.mem.Allocator,
    seq: u32,
    op: Create,
    actions: []const action.ActionSpec,
    ps: Psched,
) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(gpa, &list, RTM_NEWACTION, op.flags(), seq, 0);
    try appendTcamsg(gpa, &list);
    try action.appendActionList(gpa, &list, action.TCA_ACT_TAB, actions, ps);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Build an `RTM_DELACTION` request (`tc actions del action KIND index N`).
/// Actions are addressed by `(kind, index)`, not by any attach point.
pub fn buildActionDel(
    gpa: std.mem.Allocator,
    seq: u32,
    refs: []const action.ActionRef,
) BuildError![]u8 {
    return buildActionRefMsg(gpa, seq, RTM_DELACTION, codec.NLM_F_REQUEST | codec.NLM_F_ACK, refs);
}

/// Build an `RTM_GETACTION` request for one specific action
/// (`tc actions get action KIND index N`). Unlike the dump form this carries
/// no `NLM_F_DUMP` and no `NLM_F_ACK`: the kernel answers with a single
/// `RTM_NEWACTION` message.
pub fn buildActionGet(
    gpa: std.mem.Allocator,
    seq: u32,
    refs: []const action.ActionRef,
) BuildError![]u8 {
    return buildActionRefMsg(gpa, seq, RTM_GETACTION, codec.NLM_F_REQUEST, refs);
}

fn buildActionRefMsg(
    gpa: std.mem.Allocator,
    seq: u32,
    msg_type: u16,
    flags: u16,
    refs: []const action.ActionRef,
) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(gpa, &list, msg_type, flags, seq, 0);
    try appendTcamsg(gpa, &list);
    try action.appendActionRefs(gpa, &list, action.TCA_ACT_TAB, refs);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Build the `RTM_GETACTION` **dump** request (`tc actions ls action KIND`):
/// a one-entry table naming the kind, plus the `TCA_ROOT_FLAGS` bitfield with
/// `TCA_ACT_FLAG_LARGE_DUMP_ON` — which `tc` always sets, and without which
/// the kernel truncates the table at one message.
pub fn buildActionDump(
    gpa: std.mem.Allocator,
    seq: u32,
    kind: []const u8,
) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        RTM_GETACTION,
        codec.NLM_F_REQUEST | codec.NLM_F_DUMP,
        seq,
        0,
    );
    try appendTcamsg(gpa, &list);
    try action.appendActionRefs(gpa, &list, action.TCA_ACT_TAB, &.{.{ .kind = kind }});
    try action.appendRootFlags(
        gpa,
        &list,
        action.TCA_ACT_FLAG.LARGE_DUMP_ON,
        action.TCA_ACT_FLAG.LARGE_DUMP_ON,
    );
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

// ── dumps ───────────────────────────────────────────────────────────────────

/// Build one `RTM_GET{QDISC,TCLASS,TFILTER}` dump request. `ifindex` and
/// `parent` are passed in the fixed header as a courtesy to kernels that
/// honour them; both are always re-checked client-side (the same
/// belt-and-braces approach `netlink` takes for its own dump filters).
pub fn buildDump(
    gpa: std.mem.Allocator,
    seq: u32,
    msg_type: u16,
    ifindex: u32,
    parent: Handle,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        msg_type,
        codec.NLM_F_REQUEST | codec.NLM_F_DUMP,
        seq,
        0,
    );
    try appendTcmsg(gpa, &list, ifindex, Handle.unspec, parent, 0);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "message types agree with the kernel UAPI" {
    try testing.expectEqual(@as(u16, 36), RTM_NEWQDISC);
    try testing.expectEqual(@as(u16, 37), RTM_DELQDISC);
    try testing.expectEqual(@as(u16, 38), RTM_GETQDISC);
    try testing.expectEqual(@as(u16, 40), RTM_NEWTCLASS);
    try testing.expectEqual(@as(u16, 41), RTM_DELTCLASS);
    try testing.expectEqual(@as(u16, 42), RTM_GETTCLASS);
    try testing.expectEqual(@as(u16, 44), RTM_NEWTFILTER);
    try testing.expectEqual(@as(u16, 45), RTM_DELTFILTER);
    try testing.expectEqual(@as(u16, 46), RTM_GETTFILTER);
    try testing.expectEqual(@as(u16, 48), RTM_NEWACTION);
    try testing.expectEqual(@as(u16, 49), RTM_DELACTION);
    try testing.expectEqual(@as(u16, 50), RTM_GETACTION);
    // The action family's fixed header is 4 bytes, not tcmsg's 20.
    try testing.expectEqual(@as(usize, 4), tcamsg_len);
    try testing.expectEqual(@as(usize, 20), tcmsg_len);
}

test "standalone action messages carry tcamsg, not tcmsg" {
    const gpa = testing.allocator;
    const req = try buildActionSet(gpa, 9, .add, &.{
        .{ .gact = .{ .action = .shot, .index = 1 } },
    }, ratespec.golden_psched);
    defer gpa.free(req);

    var it: codec.MessageIterator = .{ .buf = req };
    const m = (try it.next()).?;
    try testing.expectEqual(RTM_NEWACTION, m.type);
    try testing.expectEqual(Create.add.flags(), m.flags);
    // Four zero bytes of tcamsg, then straight into TCA_ACT_TAB.
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, m.payload[0..4]);
    var at: codec.AttrIterator = .{ .buf = m.payload[tcamsg_len..] };
    const tab = (try at.next()).?;
    try testing.expectEqual(action.TCA_ACT_TAB, tab.type);

    var ait: action.ActionIterator = .init(tab.data);
    const a = (ait.next() catch unreachable).?;
    try testing.expectEqualStrings("gact", a.kind());
    try testing.expectEqual(@as(u16, 1), a.order);
    try testing.expectEqual(@as(u32, 1), a.gen.index);
}

test "the action dump request sets LARGE_DUMP_ON like tc does" {
    const gpa = testing.allocator;
    const req = try buildActionDump(gpa, 3, "gact");
    defer gpa.free(req);
    var it: codec.MessageIterator = .{ .buf = req };
    const m = (try it.next()).?;
    try testing.expectEqual(RTM_GETACTION, m.type);
    try testing.expectEqual(codec.NLM_F_REQUEST | codec.NLM_F_DUMP, m.flags);
    var at: codec.AttrIterator = .{ .buf = m.payload[tcamsg_len..] };
    _ = (try at.next()).?; // TCA_ACT_TAB
    const flags = (try at.next()).?;
    try testing.expectEqual(action.TCA_ROOT.FLAGS, flags.type);
    try testing.expectEqual(@as(usize, 8), flags.data.len);
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, flags.data[0..4], native_endian));
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, flags.data[4..8], native_endian));
}

test "action get is a bare request; action del asks for an ACK" {
    const gpa = testing.allocator;
    const get = try buildActionGet(gpa, 1, &.{.{ .kind = "gact", .index = 1 }});
    defer gpa.free(get);
    const del = try buildActionDel(gpa, 1, &.{.{ .kind = "gact", .index = 1 }});
    defer gpa.free(del);

    var it1: codec.MessageIterator = .{ .buf = get };
    try testing.expectEqual(codec.NLM_F_REQUEST, (try it1.next()).?.flags);
    var it2: codec.MessageIterator = .{ .buf = del };
    const m = (try it2.next()).?;
    try testing.expectEqual(RTM_DELACTION, m.type);
    try testing.expectEqual(codec.NLM_F_REQUEST | codec.NLM_F_ACK, m.flags);
    // Same body either way: kind + index, no options nest.
    try testing.expectEqualSlices(u8, get[codec.header_len..], del[codec.header_len..]);
}

test "Create.flags matches tc's add/replace/change semantics" {
    try testing.expectEqual(@as(u16, 0x0605), Create.add.flags()); // REQUEST|ACK|EXCL|CREATE
    try testing.expectEqual(@as(u16, 0x0505), Create.replace.flags()); // REQUEST|ACK|REPLACE|CREATE
    try testing.expectEqual(@as(u16, 0x0005), Create.change.flags()); // REQUEST|ACK
}

test "TCA_OPTIONS is nested the way iproute2 nests it (no NLA_F_NESTED)" {
    const gpa = testing.allocator;
    const req = try buildQdiscSet(
        gpa,
        1,
        .add,
        .{ .ifindex = 1, .handle = Handle.init(1, 0) },
        .{ .fq_codel = .{} },
        ratespec.golden_psched,
    );
    defer gpa.free(req);
    var it: codec.AttrIterator = .{ .buf = req[codec.header_len + tcmsg_len ..] };
    _ = (try it.next()).?; // TCA_KIND
    const opts = (try it.next()).?;
    try testing.expectEqual(qdisc.TCA.OPTIONS, opts.type);
    try testing.expectEqual(qdisc.TCA.OPTIONS, opts.raw_type); // no 0x8000 bit
    try testing.expectEqual(@as(usize, 0), opts.data.len); // fq_codel with no knobs
}

test "dump requests carry the ifindex and parent filter" {
    const gpa = testing.allocator;
    const req = try buildDump(gpa, 7, RTM_GETTFILTER, 3, Handle.init(1, 0));
    defer gpa.free(req);
    try testing.expectEqual(@as(usize, codec.header_len + tcmsg_len), req.len);
    var it: codec.MessageIterator = .{ .buf = req };
    const m = (try it.next()).?;
    try testing.expectEqual(RTM_GETTFILTER, m.type);
    try testing.expectEqual(codec.NLM_F_REQUEST | codec.NLM_F_DUMP, m.flags);
    try testing.expectEqual(@as(u32, 7), m.seq);
    try testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, m.payload[4..8], native_endian));
    try testing.expectEqual(@as(u32, 0x00010000), std.mem.readInt(u32, m.payload[12..16], native_endian));
}

test "filter requests put prio + protocol in tcm_info, not in an attribute" {
    const gpa = testing.allocator;
    const req = try buildFilterSet(gpa, 1, .add, .{
        .ifindex = 1,
        .parent = Handle.init(1, 0),
        .prio = 2,
        .eth_type = filter.ETH_P.IPV6,
    }, .{ .flower = .{ .eth_type = filter.ETH_P.IPV6 } });
    defer gpa.free(req);
    const info = std.mem.readInt(u32, req[codec.header_len + 16 ..][0..4], native_endian);
    try testing.expectEqual(@as(u32, 0x0002dd86), info);
}
