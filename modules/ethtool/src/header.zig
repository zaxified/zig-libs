// SPDX-License-Identifier: MIT
//! The `ETHTOOL_A_*_HEADER` nest that every ethtool-netlink message — request,
//! reply and notification — carries as its first attribute.
//!
//! ```text
//! ETHTOOL_A_<CMD>_HEADER  (nest)
//!   ETHTOOL_A_HEADER_DEV_INDEX  u32     ─┐ at least one identifies the device
//!   ETHTOOL_A_HEADER_DEV_NAME   string  ─┘ (a reply carries both)
//!   ETHTOOL_A_HEADER_FLAGS      u32       request only; changes the reply shape
//! ```
//!
//! The nest's *attribute type* differs per command (`ETHTOOL_A_RINGS_HEADER`,
//! `ETHTOOL_A_STATS_HEADER`, …) and is not always 1 — `STATS` puts it at 2 —
//! so it is passed in rather than assumed.
//!
//! `FLAGS` is the reason this is not boilerplate: `ETHTOOL_FLAG_COMPACT_BITSETS`
//! decides which of the two bitset encodings comes back, `ETHTOOL_FLAG_STATS`
//! decides whether optional statistics nests are attached, and
//! `ETHTOOL_FLAG_OMIT_REPLY` decides whether a SET answers with anything at all.
//! See `bitset.zig` and `features.zig`.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const genl = @import("genetlink");
const uapi = @import("uapi.zig");

pub const Error = error{ OutOfMemory, InvalidRequest };

/// Which bitset encoding to ask the kernel for. Verbose costs bytes and gives
/// names; compact is cheap and gives bare bit numbers whose meaning has to come
/// from a `stringSet` lookup. See `bitset.zig`.
///
/// It lives here because the only thing it decides is one bit of the request
/// header's `FLAGS` word; `client.BitsetForm` is an alias of it.
pub const BitsetForm = enum {
    verbose,
    compact,

    pub fn compactFlag(f: BitsetForm) bool {
        return f == .compact;
    }
};

// ── the message frame ──────────────────────────────────────────────────────
//
// Every ethtool request is an `nlmsghdr` + a `genlmsghdr` + attributes. That
// frame is spelled **once**, here: the per-operation `buildX` encoders in
// `link.zig`, `params.zig`, `features.zig`, `stats.zig` and `moduleinfo.zig`
// all open with `beginRequest` and close with `finishRequest`, and the client
// in `client.zig` sends what those encoders return rather than assembling a
// second copy of its own.

/// The runtime facts a request frame needs. `family_id` and `seq` belong to the
/// socket, which is why an offline encoder takes them from its caller.
pub const RequestFrame = struct {
    /// The `ethtool` family id nlctrl assigned on this boot — never a constant.
    family_id: u16,
    /// `ETHTOOL_MSG_*` (`uapi.MSG`).
    cmd: u8,
    /// `nlmsg_seq`. The kernel echoes it; a client matches replies on it.
    seq: u32,
    /// `NLM_F_*` bits beyond the `REQUEST | ACK` every ethtool request carries.
    /// `codec.NLM_F_DUMP` here is what turns a request with an empty header
    /// nest into a walk of every device.
    extra_flags: u16 = 0,
    /// `genlmsghdr.version`; the family has only ever used 1.
    version: u8 = uapi.family_version,
};

/// Open a request message: `nlmsghdr` then `genlmsghdr`. Returns the offset
/// `finishRequest` needs to back-patch `nlmsg_len`.
pub fn beginRequest(
    gpa: std.mem.Allocator,
    msg: *std.ArrayList(u8),
    frame: RequestFrame,
) std.mem.Allocator.Error!usize {
    const flags = codec.NLM_F_REQUEST | codec.NLM_F_ACK | frame.extra_flags;
    const h = try codec.appendHeader(gpa, msg, frame.family_id, flags, frame.seq, 0);
    try genl.appendHeader(gpa, msg, frame.cmd, frame.version);
    return h;
}

/// Back-patch `nlmsg_len` and hand the finished message to the caller.
pub fn finishRequest(
    gpa: std.mem.Allocator,
    msg: *std.ArrayList(u8),
    h: usize,
) std.mem.Allocator.Error![]u8 {
    codec.finishHeader(msg, h);
    return msg.toOwnedSlice(gpa);
}

/// How a request names the device. `ethtool` itself sends the name; an ifindex
/// is stabler against renames and is what a reply always carries.
pub const Target = union(enum) {
    name: []const u8,
    index: u32,

    pub fn byName(n: []const u8) Target {
        return .{ .name = n };
    }
    pub fn byIndex(i: u32) Target {
        return .{ .index = i };
    }
};

/// Request-header options: the device plus the flags that reshape the reply.
pub const Options = struct {
    target: Target,
    /// Ask for compact (word-array) bitsets instead of the verbose per-bit
    /// nest. `ethtool` sets this whenever it does not need the kernel's names.
    compact_bitsets: bool = false,
    /// Ask a SET/ACT request to answer with a bare ACK and no `*_SET_REPLY`.
    /// **Costs information:** the reply is how a caller learns which parts of a
    /// SET were actually honoured, so this module never sets it implicitly.
    omit_reply: bool = false,
    /// Ask the driver for the optional statistics nests.
    stats: bool = false,

    pub fn flagBits(o: Options) u32 {
        var f: u32 = 0;
        if (o.compact_bitsets) f |= uapi.FLAG.COMPACT_BITSETS;
        if (o.omit_reply) f |= uapi.FLAG.OMIT_REPLY;
        if (o.stats) f |= uapi.FLAG.STATS;
        return f;
    }
};

/// Append the header nest of type `attr_type`. A zero flag word is omitted
/// entirely — that is what `ethtool` does, and it keeps the goldens byte-exact.
pub fn append(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    opts: Options,
) Error!void {
    const nest = try codec.nestBegin(gpa, list, attr_type | codec.NLA_F_NESTED);
    switch (opts.target) {
        .index => |i| try codec.appendAttrU32(gpa, list, uapi.HEADER.DEV_INDEX, i),
        .name => |n| {
            // The kernel's policy caps this at IFNAMSIZ including the NUL, and
            // rejects an empty name; catching both here turns a would-be
            // EINVAL round-trip into a local error.
            if (n.len == 0 or n.len >= uapi.ifnamesize) return error.InvalidRequest;
            if (std.mem.indexOfScalar(u8, n, 0) != null) return error.InvalidRequest;
            codec.appendAttrString(gpa, list, uapi.HEADER.DEV_NAME, n) catch |e| switch (e) {
                error.AttrTooLong => return error.InvalidRequest,
                error.OutOfMemory => return error.OutOfMemory,
            };
        },
    }
    const flags = opts.flagBits();
    if (flags != 0) try codec.appendAttrU32(gpa, list, uapi.HEADER.FLAGS, flags);
    codec.nestEnd(list, nest);
}

/// Append a header nest that names **no device**. Not every ethtool request is
/// about one interface: a `STRSET_GET` of a global string set (features, link
/// modes, the standard statistics groups) is answered by the kernel itself, and
/// `ethtool` sends a header nest containing nothing at all for it. An empty
/// nest is not the same as omitting the header — the kernel's policy requires
/// the attribute to be present.
pub fn appendGlobal(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    flags: u32,
) Error!void {
    const nest = try codec.nestBegin(gpa, list, attr_type | codec.NLA_F_NESTED);
    if (flags != 0) try codec.appendAttrU32(gpa, list, uapi.HEADER.FLAGS, flags);
    codec.nestEnd(list, nest);
}

/// The device a reply/notification header identifies. The name is copied into
/// the struct, so it outlives the receive buffer.
pub const Device = struct {
    index: ?u32 = null,
    name_buf: [uapi.ifnamesize]u8 = @splat(0),
    name_len: u8 = 0,

    pub fn name(d: *const Device) []const u8 {
        return d.name_buf[0..d.name_len];
    }
};

/// Decode a header nest's contents (`attr.data` of the `*_HEADER` attribute).
pub fn parse(nest_bytes: []const u8) codec.Error!Device {
    var d: Device = .{};
    var it: codec.AttrIterator = .{ .buf = nest_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.HEADER.DEV_INDEX => d.index = try a.asU32(),
        uapi.HEADER.DEV_NAME => {
            const s = a.asString();
            if (s.len >= uapi.ifnamesize) return error.BadLength;
            @memcpy(d.name_buf[0..s.len], s);
            d.name_len = @intCast(s.len);
        },
        else => {},
    };
    return d;
}

/// Decode the header of a message whose *command* is not known in advance —
/// a notification off the `monitor` group, where the header nest's attribute
/// type depends on which `*_NTF` it is.
///
/// Every ethtool message puts its header nest first, so this reads the leading
/// attribute and interprets it as one. It returns null when that attribute
/// yields neither a device index nor a name, which is how a message that is
/// *not* shaped like an ethtool reply fails safely instead of producing a
/// plausible-looking wrong device.
pub fn parseLeading(attr_bytes: []const u8) codec.Error!?Device {
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    const first = (try it.next()) orelse return null;
    // A leading attribute that does not even walk as a nest is not a header.
    const d = parse(first.data) catch return null;
    if (d.index == null and d.name_len == 0) return null;
    return d;
}

/// Find and decode the header nest inside a message's attribute bytes.
/// Returns null when the message carries none (which a well-formed ethtool
/// message never does).
pub fn find(attr_bytes: []const u8, attr_type: u16) codec.Error!?Device {
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| {
        if (a.type == attr_type) return try parse(a.data);
    }
    return null;
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;
const native_endian = @import("builtin").cpu.arch.endian();

test "beginRequest/finishRequest frame: REQUEST|ACK, the family id, the seq and the genlmsghdr" {
    const gpa = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try beginRequest(gpa, &msg, .{ .family_id = 23, .cmd = uapi.MSG.RINGS_GET, .seq = 9 });
    try append(gpa, &msg, uapi.RINGS.HEADER, .{ .target = .byIndex(2) });
    const out = try finishRequest(gpa, &msg, h);
    defer gpa.free(out);

    var it: codec.MessageIterator = .{ .buf = out };
    const m = (try it.next()).?;
    try testing.expectEqual(@as(u16, 23), m.type);
    try testing.expectEqual(codec.NLM_F_REQUEST | codec.NLM_F_ACK, m.flags);
    try testing.expectEqual(@as(u32, 9), m.seq);
    // `nlmsg_pid` is left at 0 for the kernel to fill in.
    try testing.expectEqual(@as(u32, 0), m.pid);
    // …and `finishHeader` really back-patched the length: the iterator found
    // exactly one message covering the whole buffer.
    try testing.expect((try it.next()) == null);

    const p = try genl.splitPayload(m.payload);
    try testing.expectEqual(uapi.MSG.RINGS_GET, p.cmd);
    const d = (try find(p.attrs, uapi.RINGS.HEADER)).?;
    try testing.expectEqual(@as(?u32, 2), d.index);
}

test "beginRequest: NLM_F_DUMP is part of the message, not of the sending" {
    const gpa = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try beginRequest(gpa, &msg, .{
        .family_id = 23,
        .cmd = uapi.MSG.RINGS_GET,
        .seq = 1,
        .extra_flags = codec.NLM_F_DUMP,
    });
    // A dump is the empty-header-nest form: every device, no target.
    try appendGlobal(gpa, &msg, uapi.RINGS.HEADER, 0);
    const out = try finishRequest(gpa, &msg, h);
    defer gpa.free(out);

    var it: codec.MessageIterator = .{ .buf = out };
    const m = (try it.next()).?;
    try testing.expectEqual(
        codec.NLM_F_REQUEST | codec.NLM_F_ACK | codec.NLM_F_DUMP,
        m.flags,
    );
    // …and without `extra_flags` the very same call leaves it clear.
    var plain: std.ArrayList(u8) = .empty;
    errdefer plain.deinit(gpa);
    const h2 = try beginRequest(gpa, &plain, .{ .family_id = 23, .cmd = uapi.MSG.RINGS_GET, .seq = 1 });
    try appendGlobal(gpa, &plain, uapi.RINGS.HEADER, 0);
    const out2 = try finishRequest(gpa, &plain, h2);
    defer gpa.free(out2);
    var it2: codec.MessageIterator = .{ .buf = out2 };
    try testing.expectEqual(@as(u16, 0), (try it2.next()).?.flags & codec.NLM_F_DUMP);
}

test "header by name, no flags — the shape ethtool sends for a plain GET" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try append(gpa, &list, uapi.RINGS.HEADER, .{ .target = .byName("enp0s31f6") });
    try testing.expectEqualSlices(u8, &.{
        0x14, 0x00, 0x01, 0x80, // nest len 20, type 1 | NLA_F_NESTED
        0x0e, 0x00, 0x02, 0x00, // len 14, DEV_NAME
        'e',  'n',  'p',  '0',
        's',  '3',  '1',  'f',
        '6', 0x00, 0x00, 0x00, // NUL + pad
    }, list.items);
}

test "header by name with COMPACT_BITSETS — the shape ethtool -a sends" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try append(gpa, &list, uapi.LINKMODES.HEADER, .{
        .target = .byName("enp0s31f6"),
        .compact_bitsets = true,
    });
    try testing.expectEqualSlices(u8, &.{
        0x1c, 0x00, 0x01, 0x80,
        0x0e, 0x00, 0x02, 0x00,
        'e',  'n',  'p',  '0',
        's',  '3',  '1',  'f',
        '6',  0x00, 0x00, 0x00,
        0x08, 0x00, 0x03, 0x00, // FLAGS
        0x01, 0x00, 0x00, 0x00, // ETHTOOL_FLAG_COMPACT_BITSETS
    }, list.items);
}

test "header by ifindex" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try append(gpa, &list, uapi.STATS.HEADER, .{ .target = .byIndex(2) });
    try testing.expectEqualSlices(u8, &.{
        0x0c, 0x00, 0x02, 0x80, // STATS puts its header at attribute 2
        0x08, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x00, 0x00,
    }, list.items);
}

test "flag bits combine the way the kernel enum defines them" {
    try testing.expectEqual(@as(u32, 0), (Options{ .target = .byIndex(1) }).flagBits());
    try testing.expectEqual(@as(u32, 1), (Options{ .target = .byIndex(1), .compact_bitsets = true }).flagBits());
    try testing.expectEqual(@as(u32, 2), (Options{ .target = .byIndex(1), .omit_reply = true }).flagBits());
    try testing.expectEqual(@as(u32, 7), (Options{
        .target = .byIndex(1),
        .compact_bitsets = true,
        .omit_reply = true,
        .stats = true,
    }).flagBits());
}

test "an impossible device name is rejected locally, not by the kernel" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try testing.expectError(error.InvalidRequest, append(gpa, &list, 1, .{ .target = .byName("") }));
    try testing.expectError(error.InvalidRequest, append(gpa, &list, 1, .{
        .target = .byName("an-interface-name-far-too-long"),
    }));
    try testing.expectError(error.InvalidRequest, append(gpa, &list, 1, .{ .target = .byName("eth\x000") }));
    // Exactly IFNAMSIZ-1 characters is the longest legal name.
    try append(gpa, &list, 1, .{ .target = .byName("a" ** (uapi.ifnamesize - 1)) });
}

test "parse recovers index and name, and bounds the name" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try codec.appendAttrU32(gpa, &list, uapi.HEADER.DEV_INDEX, 7);
    try codec.appendAttrString(gpa, &list, uapi.HEADER.DEV_NAME, "eth0");
    const d = try parse(list.items);
    try testing.expectEqual(@as(?u32, 7), d.index);
    try testing.expectEqualStrings("eth0", d.name());

    // A name longer than IFNAMSIZ is a malformed reply, not a buffer overrun.
    list.clearRetainingCapacity();
    try codec.appendAttrString(gpa, &list, uapi.HEADER.DEV_NAME, "0123456789abcdef0");
    try testing.expectError(error.BadLength, parse(list.items));

    // A truncated TLV.
    try testing.expectError(error.Truncated, parse(&.{ 0x08, 0x00, 0x01 }));
}

test "find locates the header nest among sibling attributes" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try codec.appendAttrU32(gpa, &list, uapi.RINGS.RX, 256);
    try append(gpa, &list, uapi.RINGS.HEADER, .{ .target = .byIndex(3) });
    const d = (try find(list.items, uapi.RINGS.HEADER)).?;
    try testing.expectEqual(@as(?u32, 3), d.index);
    try testing.expect((try find(list.items, uapi.STATS.HEADER)) == null);
}
