// SPDX-License-Identifier: MIT
//! Hardware resources: `DEVLINK_CMD_RESOURCE_DUMP`.
//!
//! A resource is a chunk of on-device memory a driver divides between
//! functions — a switch ASIC's KVD linear area, its hash tables, its counter
//! banks. The interesting part of this message is that **the list is
//! recursive**: a resource can be subdivided into sub-resources, which can be
//! subdivided again.
//!
//! ```text
//! BUS_NAME / DEV_NAME
//! RESOURCE_LIST                nest
//!   RESOURCE                   nest
//!     RESOURCE_NAME            string
//!     RESOURCE_ID              u64     the id a RESOURCE_SET addresses
//!     RESOURCE_SIZE            u64     current
//!     RESOURCE_SIZE_NEW        u64     set but not applied until a reload
//!     RESOURCE_SIZE_VALID      u8      SIZE_NEW is meaningful
//!     RESOURCE_SIZE_MIN/MAX    u64     what a SET may ask for
//!     RESOURCE_SIZE_GRAN       u64     …and in what increments
//!     RESOURCE_UNIT            u8      entries (the only unit defined)
//!     RESOURCE_OCC             u64     how much is in use right now
//!     RESOURCE_LIST            nest    ← the recursion
//! ```
//!
//! ## Bounding the recursion
//!
//! Nothing on the wire bounds the nesting depth. A netlink message is at most
//! 64 KiB and every nest header costs 4 bytes, so a hostile (or merely
//! corrupt) message can nest thousands of levels deep — enough to overflow the
//! stack of a naive recursive-descent parser well before the buffer runs out.
//!
//! So the decoder carries an explicit `max_depth` and refuses beyond it with
//! `error.TooDeep`, and it counts nodes against `max_nodes` as well: the
//! per-node struct is far larger than the 4 bytes of wire that produce it, so
//! depth alone does not bound the memory. Real drivers use two levels
//! (mlxsw's `kvd` → `linear`/`hash_single`/`hash_double`); the defaults are
//! generous multiples of that. The hostile cases are pinned by tests.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const handle = @import("handle.zig");
const request = @import("request.zig");
const genl = @import("genetlink");

/// How deep a `RESOURCE_LIST` chain may nest before the stream is rejected.
/// Real hardware uses 2.
pub const max_depth = 8;
/// How many resources one dump may describe in total, across every level.
pub const max_nodes = 1024;

pub const ParseError = codec.Error || error{ OutOfMemory, TooDeep, TooManyResources };

/// One resource, with its sub-resources.
pub const Resource = struct {
    name_buf: [uapi.name_max]u8 = @splat(0),
    name_len: u8 = 0,
    id: ?u64 = null,
    /// The size in effect now.
    size: ?u64 = null,
    /// A size a previous `RESOURCE_SET` asked for; takes effect at the next
    /// reload. Only meaningful when `size_valid` is true.
    size_new: ?u64 = null,
    size_valid: ?bool = null,
    size_min: ?u64 = null,
    size_max: ?u64 = null,
    size_gran: ?u64 = null,
    unit: ?uapi.ResourceUnit = null,
    /// Current occupancy. Absent on a driver that does not track it.
    occ: ?u64 = null,
    /// Sub-resources. Owned by the `Resources` this belongs to.
    children: []Resource = &.{},

    pub fn name(r: *const Resource) []const u8 {
        return r.name_buf[0..r.name_len];
    }

    /// Is a `RESOURCE_SET` on this resource pending a reload?
    pub fn hasPendingSize(r: Resource) bool {
        return (r.size_valid orelse false) and r.size_new != null;
    }

    /// Depth-first search by name over this subtree, this node included.
    pub fn find(r: *const Resource, n: []const u8) ?*const Resource {
        if (std.mem.eql(u8, r.name(), n)) return r;
        for (r.children) |*c| {
            if (c.find(n)) |hit| return hit;
        }
        return null;
    }

    /// This node plus every descendant.
    pub fn count(r: Resource) usize {
        var total: usize = 1;
        for (r.children) |c| total += c.count();
        return total;
    }
};

/// A device's whole resource tree. Free with `deinit`.
pub const Resources = struct {
    handle: handle.Owned = .{},
    roots: []Resource = &.{},

    /// Depth-first search by name across every root.
    pub fn find(rs: *const Resources, n: []const u8) ?*const Resource {
        for (rs.roots) |*r| {
            if (r.find(n)) |hit| return hit;
        }
        return null;
    }

    /// Every resource in the tree.
    pub fn count(rs: Resources) usize {
        var total: usize = 0;
        for (rs.roots) |r| total += r.count();
        return total;
    }

    pub fn deinit(rs: *Resources, gpa: std.mem.Allocator) void {
        freeChildren(gpa, rs.roots);
        rs.roots = &.{};
    }
};

/// Free what the nodes of `list` own, but not `list` itself — for a slice
/// still owned by an `ArrayList`.
fn freeNodes(gpa: std.mem.Allocator, list: []Resource) void {
    for (list) |*r| freeChildren(gpa, r.children);
}

/// Free an owned slice of resources and everything below it.
fn freeChildren(gpa: std.mem.Allocator, list: []Resource) void {
    freeNodes(gpa, list);
    gpa.free(list);
}

/// Decoder state that has to be shared across the recursion: the allocator and
/// the running node budget.
const Ctx = struct {
    gpa: std.mem.Allocator,
    remaining_nodes: usize,
};

/// Decode one `RESOURCE_LIST` nest into an owned slice of resources.
/// `depth` counts the lists already entered; `max_depth` is the ceiling.
fn parseList(ctx: *Ctx, nest_bytes: []const u8, depth: usize) ParseError![]Resource {
    if (depth >= max_depth) return error.TooDeep;

    var out: std.ArrayList(Resource) = .empty;
    errdefer {
        freeNodes(ctx.gpa, out.items);
        out.deinit(ctx.gpa);
    }

    var it: codec.AttrIterator = .{ .buf = nest_bytes };
    while (try it.next()) |entry| {
        if (entry.type != uapi.ATTR.RESOURCE) continue;
        if (ctx.remaining_nodes == 0) return error.TooManyResources;
        ctx.remaining_nodes -= 1;

        var r: Resource = .{};
        // The child list is decoded after the scalar pass so that a failure
        // deeper down cannot leave a half-built node in `out` unfreed: `r` is
        // only appended once it is complete.
        var child_bytes: ?[]const u8 = null;
        var inner: codec.AttrIterator = .{ .buf = entry.data };
        while (try inner.next()) |a| switch (a.type) {
            uapi.ATTR.RESOURCE_NAME => try uapi.copyName(&r.name_buf, &r.name_len, a),
            uapi.ATTR.RESOURCE_ID => r.id = try uapi.asU64(a),
            uapi.ATTR.RESOURCE_SIZE => r.size = try uapi.asU64(a),
            uapi.ATTR.RESOURCE_SIZE_NEW => r.size_new = try uapi.asU64(a),
            uapi.ATTR.RESOURCE_SIZE_VALID => r.size_valid = (try a.asU8()) != 0,
            uapi.ATTR.RESOURCE_SIZE_MIN => r.size_min = try uapi.asU64(a),
            uapi.ATTR.RESOURCE_SIZE_MAX => r.size_max = try uapi.asU64(a),
            uapi.ATTR.RESOURCE_SIZE_GRAN => r.size_gran = try uapi.asU64(a),
            uapi.ATTR.RESOURCE_UNIT => r.unit = @enumFromInt(try a.asU8()),
            uapi.ATTR.RESOURCE_OCC => r.occ = try uapi.asU64(a),
            uapi.ATTR.RESOURCE_LIST => child_bytes = a.data,
            else => {},
        };
        if (child_bytes) |b| r.children = try parseList(ctx, b, depth + 1);
        errdefer freeChildren(ctx.gpa, r.children);
        try out.append(ctx.gpa, r);
    }
    return out.toOwnedSlice(ctx.gpa);
}

/// Decode one `DEVLINK_CMD_RESOURCE_DUMP` reply. Free with `deinit`.
pub fn parse(gpa: std.mem.Allocator, attr_bytes: []const u8) ParseError!Resources {
    var rs: Resources = .{};
    errdefer rs.deinit(gpa);
    var ctx: Ctx = .{ .gpa = gpa, .remaining_nodes = max_nodes };

    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.ATTR.BUS_NAME => try uapi.copyName(&rs.handle.bus_buf, &rs.handle.bus_len, a),
        uapi.ATTR.DEV_NAME => try uapi.copyName(&rs.handle.dev_buf, &rs.handle.dev_len, a),
        uapi.ATTR.RESOURCE_LIST => {
            // A second top-level list would leak the first.
            if (rs.roots.len != 0) continue;
            rs.roots = try parseList(&ctx, a.data, 0);
        },
        else => {},
    };
    return rs;
}

// ── request builders ───────────────────────────────────────────────────────

/// Attributes of a `DEVLINK_CMD_RESOURCE_DUMP` — just the device handle.
pub fn appendDump(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    h: handle.Handle,
) handle.Error!void {
    try handle.append(gpa, list, h);
}

/// Attributes of a `DEVLINK_CMD_RESOURCE_SET`: the handle, the resource id and
/// the requested size. Needs **CAP_NET_ADMIN**, and takes effect only after a
/// `devlink dev reload` — which is why `RESOURCE_SIZE_NEW` exists in the dump.
pub fn appendSet(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    h: handle.Handle,
    resource_id: u64,
    size: u64,
) handle.Error!void {
    try handle.append(gpa, list, h);
    try uapi.appendAttrU64(gpa, list, uapi.ATTR.RESOURCE_ID, resource_id);
    try uapi.appendAttrU64(gpa, list, uapi.ATTR.RESOURCE_SIZE, size);
}

// ── complete requests ──────────────────────────────────────────────────────

/// Build a `DEVLINK_CMD_RESOURCE_DUMP` — what `Devlink.resources` sends.
///
/// Despite the name this is a `doit`, not a netlink dump: the whole tree comes
/// back in one message, so the message carries no `NLM_F_DUMP`. Note also that
/// this module asks for an ACK where the real `devlink` binary does not — see
/// the capture pinned in `goldens.zig`.
pub fn buildResources(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    h: handle.Handle,
) request.Error![]u8 {
    return request.buildSimple(gpa, family_id, seq, uapi.CMD.RESOURCE_DUMP, false, h);
}

/// Build a `DEVLINK_CMD_RESOURCE_SET` — what `Devlink.setResourceSize` sends.
/// Needs **CAP_NET_ADMIN**, and takes effect at the next `devlink dev reload`.
pub fn buildSetResourceSize(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    h: handle.Handle,
    resource_id: u64,
    size: u64,
) request.Error![]u8 {
    var b = try request.begin(gpa, family_id, seq, uapi.CMD.RESOURCE_SET, false);
    errdefer b.deinit();
    try appendSet(gpa, &b.list, h, resource_id, size);
    return b.finish();
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

const Spec = struct {
    name: []const u8,
    id: u64,
    size: u64,
    children: []const Spec = &.{},
};

fn appendResource(gpa: std.mem.Allocator, list: *std.ArrayList(u8), s: Spec) !void {
    const nest = try codec.nestBegin(gpa, list, uapi.ATTR.RESOURCE);
    try codec.appendAttrString(gpa, list, uapi.ATTR.RESOURCE_NAME, s.name);
    try uapi.appendAttrU64(gpa, list, uapi.ATTR.RESOURCE_ID, s.id);
    try uapi.appendAttrU64(gpa, list, uapi.ATTR.RESOURCE_SIZE, s.size);
    try uapi.appendAttrU64(gpa, list, uapi.ATTR.RESOURCE_SIZE_GRAN, 1);
    try codec.appendAttrU8(gpa, list, uapi.ATTR.RESOURCE_UNIT, 0);
    if (s.children.len != 0) {
        const sub = try codec.nestBegin(gpa, list, uapi.ATTR.RESOURCE_LIST);
        for (s.children) |c| try appendResource(gpa, list, c);
        codec.nestEnd(list, sub);
    }
    codec.nestEnd(list, nest);
}

fn appendTree(gpa: std.mem.Allocator, list: *std.ArrayList(u8), roots: []const Spec) !void {
    const top = try codec.nestBegin(gpa, list, uapi.ATTR.RESOURCE_LIST);
    for (roots) |r| try appendResource(gpa, list, r);
    codec.nestEnd(list, top);
}

/// A nest chain `depth` levels deep, each level holding one resource.
fn buildDeep(gpa: std.mem.Allocator, list: *std.ArrayList(u8), depth: usize) !void {
    var opens: std.ArrayList(usize) = .empty;
    defer opens.deinit(gpa);
    var i: usize = 0;
    while (i < depth) : (i += 1) {
        try opens.append(gpa, try codec.nestBegin(gpa, list, uapi.ATTR.RESOURCE_LIST));
        try opens.append(gpa, try codec.nestBegin(gpa, list, uapi.ATTR.RESOURCE));
        try codec.appendAttrString(gpa, list, uapi.ATTR.RESOURCE_NAME, "r");
    }
    while (opens.items.len != 0) codec.nestEnd(list, opens.pop().?);
}

test "parse decodes the two-level tree a switch ASIC reports" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try handle.append(gpa, &list, .{ .bus = "pci", .dev = "0000:03:00.0" });
    try appendTree(gpa, &list, &.{.{
        .name = "kvd",
        .id = 1,
        .size = 245760,
        .children = &.{
            .{ .name = "linear", .id = 2, .size = 98304 },
            .{
                .name = "hash_double",
                .id = 3,
                .size = 60416,
                .children = &.{.{ .name = "singles", .id = 5, .size = 128 }},
            },
            .{ .name = "hash_single", .id = 4, .size = 87040 },
        },
    }});

    var rs = try parse(gpa, list.items);
    defer rs.deinit(gpa);

    try testing.expectEqualStrings("0000:03:00.0", rs.handle.dev());
    try testing.expectEqual(@as(usize, 1), rs.roots.len);
    try testing.expectEqual(@as(usize, 5), rs.count());

    const kvd = rs.roots[0];
    try testing.expectEqualStrings("kvd", kvd.name());
    try testing.expectEqual(@as(?u64, 245760), kvd.size);
    try testing.expectEqual(@as(?u64, 1), kvd.id);
    try testing.expectEqual(@as(?uapi.ResourceUnit, .entry), kvd.unit);
    try testing.expectEqual(@as(usize, 3), kvd.children.len);

    // The recursion really nested: `singles` is two levels below the root.
    const singles = rs.find("singles").?;
    try testing.expectEqual(@as(?u64, 128), singles.size);
    try testing.expectEqual(@as(usize, 0), singles.children.len);
    try testing.expectEqual(@as(?u64, 98304), rs.find("linear").?.size);
    try testing.expect(rs.find("nope") == null);
    // The sub-resources sum to less than their parent — the slack is the
    // ASIC's, not this decoder's business, so nothing here asserts otherwise.
    try testing.expect(!kvd.hasPendingSize());
}

test "parse reports a pending RESOURCE_SET" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const top = try codec.nestBegin(gpa, &list, uapi.ATTR.RESOURCE_LIST);
    const one = try codec.nestBegin(gpa, &list, uapi.ATTR.RESOURCE);
    try codec.appendAttrString(gpa, &list, uapi.ATTR.RESOURCE_NAME, "linear");
    try uapi.appendAttrU64(gpa, &list, uapi.ATTR.RESOURCE_SIZE, 98304);
    try uapi.appendAttrU64(gpa, &list, uapi.ATTR.RESOURCE_SIZE_NEW, 65536);
    try codec.appendAttrU8(gpa, &list, uapi.ATTR.RESOURCE_SIZE_VALID, 1);
    try uapi.appendAttrU64(gpa, &list, uapi.ATTR.RESOURCE_OCC, 17);
    codec.nestEnd(&list, one);
    codec.nestEnd(&list, top);

    var rs = try parse(gpa, list.items);
    defer rs.deinit(gpa);
    const r = rs.roots[0];
    try testing.expect(r.hasPendingSize());
    try testing.expectEqual(@as(?u64, 65536), r.size_new);
    try testing.expectEqual(@as(?u64, 17), r.occ);

    // SIZE_NEW without SIZE_VALID is not a pending change.
    var list2: std.ArrayList(u8) = .empty;
    defer list2.deinit(gpa);
    const t2 = try codec.nestBegin(gpa, &list2, uapi.ATTR.RESOURCE_LIST);
    const o2 = try codec.nestBegin(gpa, &list2, uapi.ATTR.RESOURCE);
    try uapi.appendAttrU64(gpa, &list2, uapi.ATTR.RESOURCE_SIZE_NEW, 1);
    codec.nestEnd(&list2, o2);
    codec.nestEnd(&list2, t2);
    var rs2 = try parse(gpa, list2.items);
    defer rs2.deinit(gpa);
    try testing.expect(!rs2.roots[0].hasPendingSize());
}

test "a hostile deeply-nested stream is refused, not recursed into" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    // Comfortably past max_depth, and far past what any driver emits. Without
    // the bound this is a stack overflow, not an error.
    try buildDeep(gpa, &list, 2000);
    try testing.expectError(error.TooDeep, parse(gpa, list.items));

    // Exactly at the ceiling is still refused; one below it is accepted.
    list.clearRetainingCapacity();
    try buildDeep(gpa, &list, max_depth + 1);
    try testing.expectError(error.TooDeep, parse(gpa, list.items));

    list.clearRetainingCapacity();
    try buildDeep(gpa, &list, max_depth);
    var rs = try parse(gpa, list.items);
    defer rs.deinit(gpa);
    try testing.expectEqual(@as(usize, max_depth), rs.count());
}

test "the node budget bounds a wide tree as well as a deep one" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    // A flat list of empty RESOURCE nests: 4 bytes of wire each, but a whole
    // struct apiece once decoded.
    const top = try codec.nestBegin(gpa, &list, uapi.ATTR.RESOURCE_LIST);
    var i: usize = 0;
    while (i < max_nodes + 1) : (i += 1) {
        const one = try codec.nestBegin(gpa, &list, uapi.ATTR.RESOURCE);
        codec.nestEnd(&list, one);
    }
    codec.nestEnd(&list, top);
    try testing.expectError(error.TooManyResources, parse(gpa, list.items));
}

test "truncated and wrong-width resource attributes are typed errors" {
    const gpa = testing.allocator;
    // A RESOURCE_LIST claiming more than the buffer holds.
    try testing.expectError(error.Truncated, parse(gpa, &.{ 0x40, 0x00, 0x3f, 0x00, 0x01 }));

    // RESOURCE_SIZE is u64; a u32 payload must not be read as one.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const top = try codec.nestBegin(gpa, &list, uapi.ATTR.RESOURCE_LIST);
    const one = try codec.nestBegin(gpa, &list, uapi.ATTR.RESOURCE);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.RESOURCE_SIZE, 1);
    codec.nestEnd(&list, one);
    codec.nestEnd(&list, top);
    try testing.expectError(error.BadLength, parse(gpa, list.items));

    // A truncated inner TLV inside an otherwise valid nest.
    try testing.expectError(error.Truncated, parse(gpa, &.{
        0x0c, 0x00, 0x3f, 0x00, // RESOURCE_LIST, len 12
        0x08, 0x00, 0x40, 0x00, // RESOURCE, len 8
        0x40, 0x00, 0x41, 0x00, // NAME claiming 64 bytes, 4 present
    }));
}

test "a second top-level RESOURCE_LIST does not leak the first" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendTree(gpa, &list, &.{.{ .name = "a", .id = 1, .size = 1 }});
    try appendTree(gpa, &list, &.{.{ .name = "b", .id = 2, .size = 2 }});
    var rs = try parse(gpa, list.items);
    defer rs.deinit(gpa);
    // The first list wins; the testing allocator would flag a leak otherwise.
    try testing.expectEqual(@as(usize, 1), rs.count());
    try testing.expect(rs.find("a") != null);
    try testing.expect(rs.find("b") == null);
}

test "appendSet builds the id/size pair a RESOURCE_SET carries" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendSet(gpa, &list, .pci("0000:00:00.0"), 2, 98304);
    var it: codec.AttrIterator = .{ .buf = list.items[28..] };
    const id = (try it.next()).?;
    try testing.expectEqual(uapi.ATTR.RESOURCE_ID, id.type);
    try testing.expectEqual(@as(u64, 2), try uapi.asU64(id));
    const size = (try it.next()).?;
    try testing.expectEqual(uapi.ATTR.RESOURCE_SIZE, size.type);
    try testing.expectEqual(@as(u64, 98304), try uapi.asU64(size));
}

test "fuzz: resource decoding never crashes or runs away" {
    try testing.fuzz({}, fuzzResource, .{});
}

fn fuzzResource(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    smith.bytes(&buf);
    const len = smith.valueRangeAtMost(u16, 0, buf.len);
    if (parse(testing.allocator, buf[0..len])) |rs| {
        var v = rs;
        _ = v.count();
        _ = v.find("x");
        v.deinit(testing.allocator);
    } else |_| {}
}

test "buildSetResourceSize frames a whole RESOURCE_SET, headers and all" {
    const gpa = testing.allocator;
    const msg = try buildSetResourceSize(gpa, 0x19, 12, .pci("0000:65:00.0"), 2, 98304);
    defer gpa.free(msg);

    var it: codec.MessageIterator = .{ .buf = msg };
    const m = (try it.next()).?;
    try testing.expect((try it.next()) == null);
    try testing.expectEqual(@as(u16, 0x19), m.type);
    // This module asks for an ACK where the `devlink` binary does not — the
    // capture in goldens.zig pins iproute2's ACK-less form separately.
    try testing.expectEqual(@as(u16, codec.NLM_F_REQUEST | codec.NLM_F_ACK), m.flags);
    try testing.expect(m.flags & codec.NLM_F_DUMP == 0);
    try testing.expectEqual(@as(u32, 12), m.seq);
    try testing.expectEqual(@as(u32, 0), m.pid);
    const p = try genl.splitPayload(m.payload);
    try testing.expectEqual(uapi.CMD.RESOURCE_SET, p.cmd);
    try testing.expectEqual(uapi.family_version, m.payload[1]);

    var id: ?u64 = null;
    var size: ?u64 = null;
    var attrs: codec.AttrIterator = .{ .buf = p.attrs };
    while (try attrs.next()) |a| switch (a.type) {
        uapi.ATTR.RESOURCE_ID => id = try uapi.asU64(a),
        uapi.ATTR.RESOURCE_SIZE => size = try uapi.asU64(a),
        else => {},
    };
    try testing.expectEqual(@as(?u64, 2), id);
    try testing.expectEqual(@as(?u64, 98304), size);
    const h = try handle.parse(p.attrs);
    try testing.expectEqualStrings("0000:65:00.0", h.dev());
}

test "buildResources sends the handle and nothing else" {
    const gpa = testing.allocator;
    const msg = try buildResources(gpa, 0x19, 5, .pci("0000:65:00.0"));
    defer gpa.free(msg);
    var it: codec.MessageIterator = .{ .buf = msg };
    const m = (try it.next()).?;
    // Despite the name, RESOURCE_DUMP is a `doit`: no NLM_F_DUMP.
    try testing.expect(m.flags & codec.NLM_F_DUMP == 0);
    const p = try genl.splitPayload(m.payload);
    try testing.expectEqual(uapi.CMD.RESOURCE_DUMP, p.cmd);
    var attrs: codec.AttrIterator = .{ .buf = p.attrs };
    var n: usize = 0;
    while (try attrs.next()) |a| : (n += 1) {
        try testing.expect(a.type == uapi.ATTR.BUS_NAME or a.type == uapi.ATTR.DEV_NAME);
    }
    // Exactly the two handle attributes: no stray RESOURCE_SIZE, which is
    // what iproute2's own capture carries.
    try testing.expectEqual(@as(usize, 2), n);

    try testing.expectError(error.InvalidRequest, buildResources(gpa, 0x19, 1, .{ .bus = "pci", .dev = "" }));
    try testing.expectError(error.InvalidRequest, buildSetResourceSize(gpa, 0x19, 1, .{
        .bus = "",
        .dev = "d",
    }, 1, 2));
}
