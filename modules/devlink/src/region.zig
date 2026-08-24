// SPDX-License-Identifier: MIT
//! Regions and snapshots: `DEVLINK_CMD_REGION_GET`, `REGION_NEW`,
//! `REGION_DEL` and `REGION_READ`.
//!
//! A region is a window onto device memory a driver exposes for debugging —
//! `cr-space`, `fw-health`, `nvm-flash`. A *snapshot* freezes one, so it can
//! be read at leisure after the event that motivated it.
//!
//! ```text
//! REGION_GET reply:
//!   BUS_NAME / DEV_NAME  (+ PORT_INDEX for a per-port region)
//!   REGION_NAME           string
//!   REGION_SIZE           u64
//!   REGION_MAX_SNAPSHOTS  u32
//!   REGION_SNAPSHOTS      nest
//!     REGION_SNAPSHOT     nest
//!       REGION_SNAPSHOT_ID u32
//! ```
//!
//! ## `REGION_READ` — the chunked reply
//!
//! `REGION_READ` is a **dump**: the kernel answers one request with as many
//! messages as it needs, each carrying a `REGION_CHUNKS` nest of one or more
//! `REGION_CHUNK`s:
//!
//! ```text
//!   REGION_CHUNKS         nest
//!     REGION_CHUNK        nest
//!       REGION_CHUNK_DATA binary   ← the bytes
//!       REGION_CHUNK_ADDR u64      ← where in the region they came from
//! ```
//!
//! Note what is **not** there: a length. A chunk's length is its `DATA`
//! attribute's length, and `REGION_CHUNK_LEN` appears only in the *request*.
//! Note also that the reply is addressed, not sequential: chunk boundaries are
//! the kernel's business (it fills messages up to the netlink buffer size and
//! splits wherever that lands), and a caller must reassemble by address rather
//! than by concatenation. `Assembler` does that, and answers the question
//! concatenation cannot: *did every byte actually arrive?*
//!
//! ```zig
//! var asm_ = try region.Assembler.init(gpa, 0x1000, 512);
//! defer asm_.deinit(gpa);
//! // …feed each REGION_READ reply message…
//! try asm_.feed(reply_attrs);
//! const data = asm_.finish();
//! if (!data.isComplete()) { /* the device returned less than was asked for */ }
//! ```

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const handle = @import("handle.zig");
const request = @import("request.zig");
const genl = @import("genetlink");

pub const ParseError = codec.Error || error{OutOfMemory};
pub const BuildError = error{ OutOfMemory, InvalidRequest };

/// The most snapshots kept for one region. The kernel's own
/// `REGION_MAX_SNAPSHOTS` is a small single-digit number per driver.
pub const max_snapshots = 64;

/// The largest single `REGION_READ` this module will assemble, so a bad
/// `length` argument cannot turn into a huge allocation. 16 MiB is far more
/// than any region a driver exposes.
pub const max_read_len = 16 * 1024 * 1024;

// ── REGION_GET ─────────────────────────────────────────────────────────────

/// One region of a device. Self-contained; no allocation.
pub const Region = struct {
    handle: handle.Owned = .{},
    /// Present on a per-port region.
    port_index: ?u32 = null,
    name_buf: [uapi.name_max]u8 = @splat(0),
    name_len: u8 = 0,
    size: ?u64 = null,
    max_snapshots_allowed: ?u32 = null,
    snapshot_ids: [max_snapshots]u32 = @splat(0),
    snapshot_count: u8 = 0,

    pub fn name(r: *const Region) []const u8 {
        return r.name_buf[0..r.name_len];
    }

    pub fn snapshots(r: *const Region) []const u32 {
        return r.snapshot_ids[0..r.snapshot_count];
    }

    pub fn hasSnapshot(r: *const Region, id: u32) bool {
        return std.mem.indexOfScalar(u32, r.snapshots(), id) != null;
    }

    /// Can another snapshot be taken, or is the driver's slot budget full?
    /// Null when the kernel did not report a maximum.
    pub fn canSnapshot(r: *const Region) ?bool {
        const max = r.max_snapshots_allowed orelse return null;
        return r.snapshot_count < max;
    }
};

/// Decode one `DEVLINK_CMD_REGION_GET`/`REGION_NEW` message.
pub fn parseRegion(attr_bytes: []const u8) codec.Error!Region {
    var r: Region = .{};
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.ATTR.BUS_NAME => try uapi.copyName(&r.handle.bus_buf, &r.handle.bus_len, a),
        uapi.ATTR.DEV_NAME => try uapi.copyName(&r.handle.dev_buf, &r.handle.dev_len, a),
        uapi.ATTR.PORT_INDEX => r.port_index = try a.asU32(),
        uapi.ATTR.REGION_NAME => try uapi.copyName(&r.name_buf, &r.name_len, a),
        uapi.ATTR.REGION_SIZE => r.size = try uapi.asU64(a),
        uapi.ATTR.REGION_MAX_SNAPSHOTS => r.max_snapshots_allowed = try a.asU32(),
        uapi.ATTR.REGION_SNAPSHOT_ID => {
            // A `REGION_NEW` reply reports the new snapshot's id at the top
            // level rather than inside a `REGION_SNAPSHOTS` nest.
            if (r.snapshot_count >= max_snapshots) return error.BadLength;
            r.snapshot_ids[r.snapshot_count] = try a.asU32();
            r.snapshot_count += 1;
        },
        uapi.ATTR.REGION_SNAPSHOTS => {
            var snaps: codec.AttrIterator = .{ .buf = a.data };
            while (try snaps.next()) |s| {
                if (s.type != uapi.ATTR.REGION_SNAPSHOT) continue;
                var inner: codec.AttrIterator = .{ .buf = s.data };
                while (try inner.next()) |x| {
                    if (x.type != uapi.ATTR.REGION_SNAPSHOT_ID) continue;
                    if (r.snapshot_count >= max_snapshots) return error.BadLength;
                    r.snapshot_ids[r.snapshot_count] = try x.asU32();
                    r.snapshot_count += 1;
                }
            }
        },
        else => {},
    };
    return r;
}

// ── REGION_READ reassembly ─────────────────────────────────────────────────

/// The bytes read out of a region, plus how much of the window the device
/// actually filled. Free with `deinit`.
pub const Data = struct {
    /// The address the read started at — `bytes[0]` is this address.
    address: u64 = 0,
    /// The requested window, zero-filled where nothing arrived.
    bytes: []u8 = &.{},
    /// How many bytes were actually delivered. Less than `bytes.len` when the
    /// device returned a short read.
    covered: u64 = 0,

    pub fn isComplete(d: Data) bool {
        return d.covered == d.bytes.len;
    }

    pub fn deinit(d: *Data, gpa: std.mem.Allocator) void {
        gpa.free(d.bytes);
        d.* = .{};
    }
};

/// Reassembles the chunks of one `REGION_READ` dump into a contiguous buffer.
///
/// Chunks are placed by **address**, not by arrival order, and a chunk that
/// falls outside the requested window — or that overlaps one already placed —
/// is a malformed reply rather than something to paper over. Both are what a
/// buggy driver or a spoofed message would produce, and silently accepting
/// either would hand the caller a buffer whose contents do not correspond to
/// the addresses it asked for.
pub const Assembler = struct {
    base: u64,
    buf: []u8,
    /// One bit per byte of `buf`, so an overlap is detectable rather than
    /// merely suspected. Sized `ceil(len/8)`.
    seen: []u8,
    covered: u64 = 0,

    pub fn init(gpa: std.mem.Allocator, address: u64, length: usize) error{ OutOfMemory, InvalidRequest }!Assembler {
        if (length == 0 or length > max_read_len) return error.InvalidRequest;
        // The window must not wrap the address space.
        if (@addWithOverflow(address, @as(u64, length))[1] != 0) return error.InvalidRequest;
        const buf = try gpa.alloc(u8, length);
        errdefer gpa.free(buf);
        @memset(buf, 0);
        const seen = try gpa.alloc(u8, (length + 7) / 8);
        @memset(seen, 0);
        return .{ .base = address, .buf = buf, .seen = seen };
    }

    pub fn deinit(a: *Assembler, gpa: std.mem.Allocator) void {
        gpa.free(a.buf);
        gpa.free(a.seen);
        a.* = undefined;
    }

    /// Feed one `REGION_READ` reply message's attribute bytes. Safe to call
    /// with a message that carries no chunks (the kernel sends those).
    pub fn feed(a: *Assembler, attr_bytes: []const u8) codec.Error!void {
        var it: codec.AttrIterator = .{ .buf = attr_bytes };
        while (try it.next()) |top| {
            if (top.type != uapi.ATTR.REGION_CHUNKS) continue;
            var chunks: codec.AttrIterator = .{ .buf = top.data };
            while (try chunks.next()) |c| {
                if (c.type != uapi.ATTR.REGION_CHUNK) continue;
                var addr: ?u64 = null;
                var data: ?[]const u8 = null;
                var inner: codec.AttrIterator = .{ .buf = c.data };
                while (try inner.next()) |x| switch (x.type) {
                    uapi.ATTR.REGION_CHUNK_ADDR => addr = try uapi.asU64(x),
                    uapi.ATTR.REGION_CHUNK_DATA => data = x.data,
                    else => {},
                };
                // A chunk missing either half places nothing and means
                // nothing; the kernel always sends both.
                const at = addr orelse return error.BadLength;
                const bytes = data orelse return error.BadLength;
                try a.place(at, bytes);
            }
        }
    }

    fn place(a: *Assembler, addr: u64, bytes: []const u8) codec.Error!void {
        if (bytes.len == 0) return;
        if (addr < a.base) return error.BadLength;
        const off = addr - a.base;
        const end = @addWithOverflow(off, @as(u64, bytes.len));
        if (end[1] != 0 or end[0] > a.buf.len) return error.BadLength;
        const start: usize = @intCast(off);
        const stop: usize = @intCast(end[0]);
        // Range-check the WHOLE span against the overlap bitmap first, then
        // `@memcpy` the payload in one bulk op instead of a per-byte
        // read-modify-write (WAVE-2 devlink F3 / CAMPAIGN K1) — the bitmap
        // bit-tests stay a cheap byte-wise loop (not the expensive part; the
        // per-byte *data* copy against a vectorised `memcpy` was), and
        // checking before copying means an overlap is now rejected with the
        // buffer untouched by this call, rather than partially written up to
        // the overlap point as the old single fused loop left it.
        for (start..stop) |i| {
            if (a.seen[i / 8] & (@as(u8, 1) << @intCast(i % 8)) != 0) return error.BadLength;
        }
        @memcpy(a.buf[start..stop], bytes);
        for (start..stop) |i| {
            a.seen[i / 8] |= @as(u8, 1) << @intCast(i % 8);
        }
        a.covered += bytes.len;
    }

    /// Hand over the assembled buffer. The assembler must not be used
    /// afterwards; `deinit` is then the caller's `Data.deinit`.
    pub fn finish(a: *Assembler, gpa: std.mem.Allocator) Data {
        gpa.free(a.seen);
        const d: Data = .{ .address = a.base, .bytes = a.buf, .covered = a.covered };
        a.* = undefined;
        return d;
    }
};

// ── request builders ───────────────────────────────────────────────────────

fn appendRegionName(gpa: std.mem.Allocator, list: *std.ArrayList(u8), n: []const u8) BuildError!void {
    if (n.len == 0 or n.len > uapi.name_max) return error.InvalidRequest;
    if (std.mem.indexOfScalar(u8, n, 0) != null) return error.InvalidRequest;
    codec.appendAttrString(gpa, list, uapi.ATTR.REGION_NAME, n) catch |e| switch (e) {
        error.AttrTooLong => return error.InvalidRequest,
        error.OutOfMemory => return error.OutOfMemory,
    };
}

/// Attributes of a `DEVLINK_CMD_REGION_GET` for one named region.
pub fn appendGet(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    h: handle.Handle,
    region_name: []const u8,
) BuildError!void {
    try handle.append(gpa, list, h);
    try appendRegionName(gpa, list, region_name);
}

/// Attributes of a `DEVLINK_CMD_REGION_NEW` — take a snapshot. Needs
/// **CAP_NET_ADMIN**. A null `snapshot_id` lets the kernel pick one and report
/// it back in the reply; naming one lets the caller correlate.
pub fn appendNewSnapshot(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    h: handle.Handle,
    region_name: []const u8,
    snapshot_id: ?u32,
) BuildError!void {
    try handle.append(gpa, list, h);
    try appendRegionName(gpa, list, region_name);
    if (snapshot_id) |id| try codec.appendAttrU32(gpa, list, uapi.ATTR.REGION_SNAPSHOT_ID, id);
}

/// Attributes of a `DEVLINK_CMD_REGION_DEL`. The snapshot id is mandatory —
/// there is no "delete them all".
pub fn appendDelSnapshot(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    h: handle.Handle,
    region_name: []const u8,
    snapshot_id: u32,
) BuildError!void {
    try handle.append(gpa, list, h);
    try appendRegionName(gpa, list, region_name);
    try codec.appendAttrU32(gpa, list, uapi.ATTR.REGION_SNAPSHOT_ID, snapshot_id);
}

/// What to read out of a region.
pub const ReadRequest = struct {
    region: []const u8,
    /// Which snapshot to read. Null asks for a **direct** read of live device
    /// memory, which the kernel only allows on a region whose driver opted in
    /// (`DEVLINK_ATTR_REGION_DIRECT`), and never on a snapshot-only region.
    snapshot_id: ?u32 = null,
    address: u64 = 0,
    length: u64,
};

/// Attributes of a `DEVLINK_CMD_REGION_READ`. Sent with `NLM_F_DUMP`: the
/// reply is chunked. Needs **CAP_NET_ADMIN**.
pub fn appendRead(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    h: handle.Handle,
    req: ReadRequest,
) BuildError!void {
    if (req.length == 0 or req.length > max_read_len) return error.InvalidRequest;
    if (@addWithOverflow(req.address, req.length)[1] != 0) return error.InvalidRequest;
    try handle.append(gpa, list, h);
    try appendRegionName(gpa, list, req.region);
    if (req.snapshot_id) |id| {
        try codec.appendAttrU32(gpa, list, uapi.ATTR.REGION_SNAPSHOT_ID, id);
    } else {
        codec.appendAttr(gpa, list, uapi.ATTR.REGION_DIRECT, &.{}) catch |e| switch (e) {
            error.AttrTooLong => unreachable, // empty payload
            error.OutOfMemory => return error.OutOfMemory,
        };
    }
    try uapi.appendAttrU64(gpa, list, uapi.ATTR.REGION_CHUNK_ADDR, req.address);
    try uapi.appendAttrU64(gpa, list, uapi.ATTR.REGION_CHUNK_LEN, req.length);
}

// ── complete requests ──────────────────────────────────────────────────────

/// Build a `DEVLINK_CMD_REGION_GET` **dump** — every region on the system,
/// which is what `Devlink.regions` sends. The `filter` that method takes is
/// applied to the replies, not to this message.
pub fn buildRegions(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
) request.Error![]u8 {
    return request.buildSimple(gpa, family_id, seq, uapi.CMD.REGION_GET, true, null);
}

/// Build a `DEVLINK_CMD_REGION_GET` for one named region — what
/// `Devlink.region` sends.
pub fn buildRegion(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    h: handle.Handle,
    region_name: []const u8,
) request.Error![]u8 {
    var b = try request.begin(gpa, family_id, seq, uapi.CMD.REGION_GET, false);
    errdefer b.deinit();
    try appendGet(gpa, &b.list, h, region_name);
    return b.finish();
}

/// Build a `DEVLINK_CMD_REGION_NEW` — what `Devlink.newSnapshot` sends. Needs
/// **CAP_NET_ADMIN**.
pub fn buildNewSnapshot(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    h: handle.Handle,
    region_name: []const u8,
    snapshot_id: ?u32,
) request.Error![]u8 {
    var b = try request.begin(gpa, family_id, seq, uapi.CMD.REGION_NEW, false);
    errdefer b.deinit();
    try appendNewSnapshot(gpa, &b.list, h, region_name, snapshot_id);
    return b.finish();
}

/// Build a `DEVLINK_CMD_REGION_DEL` — what `Devlink.delSnapshot` sends.
pub fn buildDelSnapshot(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    h: handle.Handle,
    region_name: []const u8,
    snapshot_id: u32,
) request.Error![]u8 {
    var b = try request.begin(gpa, family_id, seq, uapi.CMD.REGION_DEL, false);
    errdefer b.deinit();
    try appendDelSnapshot(gpa, &b.list, h, region_name, snapshot_id);
    return b.finish();
}

/// Build a `DEVLINK_CMD_REGION_READ` — what `Devlink.readRegion` sends. This
/// one **is** a dump: the reply is chunked across as many messages as the
/// kernel needs, and `Assembler` puts them back together. Needs
/// **CAP_NET_ADMIN**.
pub fn buildReadRegion(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    h: handle.Handle,
    req: ReadRequest,
) request.Error![]u8 {
    var b = try request.begin(gpa, family_id, seq, uapi.CMD.REGION_READ, true);
    errdefer b.deinit();
    try appendRead(gpa, &b.list, h, req);
    return b.finish();
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;
const native_endian = @import("builtin").cpu.arch.endian();

fn buildRegionReply(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    n: []const u8,
    size: u64,
    max: u32,
    ids: []const u32,
) !void {
    try handle.append(gpa, list, .pci("0000:65:00.0"));
    try codec.appendAttrString(gpa, list, uapi.ATTR.REGION_NAME, n);
    try uapi.appendAttrU64(gpa, list, uapi.ATTR.REGION_SIZE, size);
    try codec.appendAttrU32(gpa, list, uapi.ATTR.REGION_MAX_SNAPSHOTS, max);
    const snaps = try codec.nestBegin(gpa, list, uapi.ATTR.REGION_SNAPSHOTS);
    for (ids) |id| {
        const one = try codec.nestBegin(gpa, list, uapi.ATTR.REGION_SNAPSHOT);
        try codec.appendAttrU32(gpa, list, uapi.ATTR.REGION_SNAPSHOT_ID, id);
        codec.nestEnd(list, one);
    }
    codec.nestEnd(list, snaps);
}

/// Build one `REGION_READ` reply message carrying the given chunks.
fn buildChunks(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    chunks: []const struct { addr: u64, data: []const u8 },
) !void {
    try handle.append(gpa, list, .pci("0000:65:00.0"));
    try codec.appendAttrString(gpa, list, uapi.ATTR.REGION_NAME, "cr-space");
    const top = try codec.nestBegin(gpa, list, uapi.ATTR.REGION_CHUNKS);
    for (chunks) |c| {
        const one = try codec.nestBegin(gpa, list, uapi.ATTR.REGION_CHUNK);
        try codec.appendAttr(gpa, list, uapi.ATTR.REGION_CHUNK_DATA, c.data);
        try uapi.appendAttrU64(gpa, list, uapi.ATTR.REGION_CHUNK_ADDR, c.addr);
        codec.nestEnd(list, one);
    }
    codec.nestEnd(list, top);
}

test "parseRegion reads the size, the snapshot budget and the snapshot ids" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try buildRegionReply(gpa, &list, "cr-space", 1048576, 4, &.{ 1, 7 });

    const r = try parseRegion(list.items);
    try testing.expectEqualStrings("cr-space", r.name());
    try testing.expectEqual(@as(?u64, 1048576), r.size);
    try testing.expectEqual(@as(?u32, 4), r.max_snapshots_allowed);
    try testing.expectEqualSlices(u32, &.{ 1, 7 }, r.snapshots());
    try testing.expect(r.hasSnapshot(7));
    try testing.expect(!r.hasSnapshot(2));
    try testing.expectEqual(@as(?bool, true), r.canSnapshot());
}

test "parseRegion reports a full snapshot budget" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try buildRegionReply(gpa, &list, "fw-health", 64, 2, &.{ 0, 1 });
    const r = try parseRegion(list.items);
    try testing.expectEqual(@as(?bool, false), r.canSnapshot());

    // No reported maximum ⇒ no answer, rather than a guessed one.
    list.clearRetainingCapacity();
    try codec.appendAttrString(gpa, &list, uapi.ATTR.REGION_NAME, "x");
    try testing.expectEqual(@as(?bool, null), (try parseRegion(list.items)).canSnapshot());
}

test "parseRegion takes a REGION_NEW's top-level snapshot id" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try handle.append(gpa, &list, .pci("0000:65:00.0"));
    try codec.appendAttrString(gpa, &list, uapi.ATTR.REGION_NAME, "cr-space");
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.REGION_SNAPSHOT_ID, 5);
    const r = try parseRegion(list.items);
    try testing.expectEqualSlices(u32, &.{5}, r.snapshots());
}

test "parseRegion bounds a snapshot list instead of overrunning" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    var ids: [max_snapshots + 1]u32 = undefined;
    for (&ids, 0..) |*id, i| id.* = @intCast(i);
    try buildRegionReply(gpa, &list, "x", 1, 99, &ids);
    try testing.expectError(error.BadLength, parseRegion(list.items));
}

test "Assembler reassembles out-of-order chunks by address" {
    const gpa = testing.allocator;
    var a = try Assembler.init(gpa, 0x1000, 12);
    errdefer a.deinit(gpa);

    // Three messages, deliberately not in address order.
    var m1: std.ArrayList(u8) = .empty;
    defer m1.deinit(gpa);
    try buildChunks(gpa, &m1, &.{.{ .addr = 0x1008, .data = &.{ 9, 10, 11, 12 } }});
    var m2: std.ArrayList(u8) = .empty;
    defer m2.deinit(gpa);
    try buildChunks(gpa, &m2, &.{
        .{ .addr = 0x1000, .data = &.{ 1, 2, 3, 4 } },
        .{ .addr = 0x1004, .data = &.{ 5, 6, 7, 8 } },
    });

    try a.feed(m1.items);
    try a.feed(m2.items);
    var d = a.finish(gpa);
    defer d.deinit(gpa);

    try testing.expectEqual(@as(u64, 0x1000), d.address);
    try testing.expect(d.isComplete());
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }, d.bytes);
}

test "Assembler reports a short read rather than pretending it is complete" {
    const gpa = testing.allocator;
    var a = try Assembler.init(gpa, 0, 8);
    errdefer a.deinit(gpa);
    var m: std.ArrayList(u8) = .empty;
    defer m.deinit(gpa);
    try buildChunks(gpa, &m, &.{.{ .addr = 0, .data = &.{ 0xaa, 0xbb } }});
    try a.feed(m.items);
    var d = a.finish(gpa);
    defer d.deinit(gpa);

    try testing.expect(!d.isComplete());
    try testing.expectEqual(@as(u64, 2), d.covered);
    // The untouched tail is zero, not uninitialised memory.
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0, 0, 0, 0, 0, 0 }, d.bytes);
}

test "Assembler tolerates a message with no chunks at all" {
    const gpa = testing.allocator;
    var a = try Assembler.init(gpa, 0, 4);
    errdefer a.deinit(gpa);
    var m: std.ArrayList(u8) = .empty;
    defer m.deinit(gpa);
    try handle.append(gpa, &m, .pci("0000:65:00.0"));
    try a.feed(m.items);
    try a.feed(&.{});
    var d = a.finish(gpa);
    defer d.deinit(gpa);
    try testing.expectEqual(@as(u64, 0), d.covered);
}

test "Assembler refuses a chunk outside the requested window" {
    const gpa = testing.allocator;
    var a = try Assembler.init(gpa, 0x1000, 8);
    defer a.deinit(gpa);

    var before: std.ArrayList(u8) = .empty;
    defer before.deinit(gpa);
    try buildChunks(gpa, &before, &.{.{ .addr = 0x0fff, .data = &.{1} }});
    try testing.expectError(error.BadLength, a.feed(before.items));

    var past: std.ArrayList(u8) = .empty;
    defer past.deinit(gpa);
    try buildChunks(gpa, &past, &.{.{ .addr = 0x1004, .data = &.{ 1, 2, 3, 4, 5 } }});
    try testing.expectError(error.BadLength, a.feed(past.items));

    var wild: std.ArrayList(u8) = .empty;
    defer wild.deinit(gpa);
    try buildChunks(gpa, &wild, &.{.{ .addr = std.math.maxInt(u64), .data = &.{1} }});
    try testing.expectError(error.BadLength, a.feed(wild.items));
}

test "Assembler refuses overlapping chunks" {
    const gpa = testing.allocator;
    var a = try Assembler.init(gpa, 0, 8);
    defer a.deinit(gpa);
    var m: std.ArrayList(u8) = .empty;
    defer m.deinit(gpa);
    try buildChunks(gpa, &m, &.{
        .{ .addr = 0, .data = &.{ 1, 2, 3, 4 } },
        .{ .addr = 3, .data = &.{ 9, 9 } }, // byte 3 twice
    });
    try testing.expectError(error.BadLength, a.feed(m.items));
}

test "Assembler refuses a chunk missing its address or its data" {
    const gpa = testing.allocator;
    var a = try Assembler.init(gpa, 0, 8);
    defer a.deinit(gpa);
    var m: std.ArrayList(u8) = .empty;
    defer m.deinit(gpa);
    const top = try codec.nestBegin(gpa, &m, uapi.ATTR.REGION_CHUNKS);
    const one = try codec.nestBegin(gpa, &m, uapi.ATTR.REGION_CHUNK);
    try codec.appendAttr(gpa, &m, uapi.ATTR.REGION_CHUNK_DATA, &.{ 1, 2 });
    codec.nestEnd(&m, one);
    codec.nestEnd(&m, top);
    try testing.expectError(error.BadLength, a.feed(m.items));
}

test "Assembler.init bounds the window" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidRequest, Assembler.init(gpa, 0, 0));
    try testing.expectError(error.InvalidRequest, Assembler.init(gpa, 0, max_read_len + 1));
    // A window that would wrap the 64-bit address space.
    try testing.expectError(error.InvalidRequest, Assembler.init(gpa, std.math.maxInt(u64) - 3, 8));
}

test "Assembler.feed reports a truncated nest instead of reading past it" {
    const gpa = testing.allocator;
    var a = try Assembler.init(gpa, 0, 8);
    defer a.deinit(gpa);
    try testing.expectError(error.Truncated, a.feed(&.{ 0x40, 0x00, 0x5d, 0x00, 0x01 }));
}

test "appendRead builds the addr/len pair, and REGION_DIRECT when no snapshot" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendRead(gpa, &list, .pci("0000:00:00.0"), .{
        .region = "cr-space",
        .snapshot_id = 5,
        .address = 0,
        .length = 16,
    });
    try testing.expectEqualSlices(u8, &.{
        0x0d, 0x00, 0x58, 0x00, // REGION_NAME
        'c',  'r',  '-',  's',
        'p',  'a',  'c',  'e',
        0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x5c, 0x00, // REGION_SNAPSHOT_ID
        0x05, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x60, 0x00, // REGION_CHUNK_ADDR (u64)
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x61, 0x00, // REGION_CHUNK_LEN (u64)
        0x10, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    }, list.items[28..]);

    // Without a snapshot id the request must say REGION_DIRECT — otherwise
    // the kernel reads snapshot 0, which is a different thing entirely.
    list.clearRetainingCapacity();
    try appendRead(gpa, &list, .pci("0000:00:00.0"), .{ .region = "cr-space", .length = 16 });
    var it: codec.AttrIterator = .{ .buf = list.items[28..] };
    _ = try it.next(); // REGION_NAME
    const direct = (try it.next()).?;
    try testing.expectEqual(uapi.ATTR.REGION_DIRECT, direct.type);
    try testing.expectEqual(@as(usize, 0), direct.data.len);
}

test "appendRead and the snapshot builders reject impossible arguments" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const h: handle.Handle = .pci("0000:00:00.0");
    try testing.expectError(error.InvalidRequest, appendRead(gpa, &list, h, .{ .region = "r", .length = 0 }));
    try testing.expectError(error.InvalidRequest, appendRead(gpa, &list, h, .{
        .region = "r",
        .length = max_read_len + 1,
    }));
    try testing.expectError(error.InvalidRequest, appendRead(gpa, &list, h, .{
        .region = "r",
        .address = std.math.maxInt(u64),
        .length = 2,
    }));
    try testing.expectError(error.InvalidRequest, appendRead(gpa, &list, h, .{ .region = "", .length = 4 }));
    try testing.expectError(error.InvalidRequest, appendNewSnapshot(gpa, &list, h, "a\x00b", null));
    try testing.expectError(error.InvalidRequest, appendDelSnapshot(
        gpa,
        &list,
        h,
        "r" ** (uapi.name_max + 1),
        1,
    ));
}

test "appendNewSnapshot omits the id when the kernel is to pick one" {
    const gpa = testing.allocator;
    var with: std.ArrayList(u8) = .empty;
    defer with.deinit(gpa);
    var without: std.ArrayList(u8) = .empty;
    defer without.deinit(gpa);
    try appendNewSnapshot(gpa, &with, .pci("0000:00:00.0"), "cr-space", 5);
    try appendNewSnapshot(gpa, &without, .pci("0000:00:00.0"), "cr-space", null);
    try testing.expectEqual(without.items.len + 8, with.items.len);
}

test "fuzz: region decoding and chunk reassembly never crash" {
    try testing.fuzz({}, fuzzRegion, .{});
}

fn fuzzRegion(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len = smith.valueRangeAtMost(u16, 0, buf.len);
    if (parseRegion(buf[0..len])) |r| std.mem.doNotOptimizeAway(&r) else |_| {}

    var a = Assembler.init(testing.allocator, 0, 256) catch return;
    defer a.deinit(testing.allocator);
    a.feed(buf[0..len]) catch {};
}

fn attrPresent(attr_bytes: []const u8, want: u16) codec.Error!bool {
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| {
        if (a.type == want) return true;
    }
    return false;
}

test "buildNewSnapshot leaves the id out when the kernel is to pick one" {
    const gpa = testing.allocator;
    const h: handle.Handle = .pci("0000:65:00.0");

    const with = try buildNewSnapshot(gpa, 0x19, 6, h, "cr-space", 5);
    defer gpa.free(with);
    var it: codec.MessageIterator = .{ .buf = with };
    var m = (try it.next()).?;
    try testing.expectEqual(@as(u16, codec.NLM_F_REQUEST | codec.NLM_F_ACK), m.flags);
    var p = try genl.splitPayload(m.payload);
    try testing.expectEqual(uapi.CMD.REGION_NEW, p.cmd);
    try testing.expectEqualSlices(u32, &.{5}, (try parseRegion(p.attrs)).snapshots());

    const without = try buildNewSnapshot(gpa, 0x19, 6, h, "cr-space", null);
    defer gpa.free(without);
    it = .{ .buf = without };
    m = (try it.next()).?;
    p = try genl.splitPayload(m.payload);
    // The optional attribute is ABSENT, not zero: snapshot 0 is a real id.
    try testing.expect(!(try attrPresent(p.attrs, uapi.ATTR.REGION_SNAPSHOT_ID)));
    try testing.expectEqual(@as(usize, 0), (try parseRegion(p.attrs)).snapshots().len);
    try testing.expectEqualStrings("cr-space", (try parseRegion(p.attrs)).name());
    try testing.expectEqual(with.len - 8, without.len);
}

test "buildReadRegion is the one read sent as a dump" {
    const gpa = testing.allocator;
    const h: handle.Handle = .pci("0000:65:00.0");

    const snap = try buildReadRegion(gpa, 0x19, 8, h, .{
        .region = "cr-space",
        .snapshot_id = 5,
        .address = 0x1000,
        .length = 32,
    });
    defer gpa.free(snap);
    var it: codec.MessageIterator = .{ .buf = snap };
    var m = (try it.next()).?;
    try testing.expectEqual(
        @as(u16, codec.NLM_F_REQUEST | codec.NLM_F_ACK | codec.NLM_F_DUMP),
        m.flags,
    );
    try testing.expectEqual(@as(u32, 8), m.seq);
    var p = try genl.splitPayload(m.payload);
    try testing.expectEqual(uapi.CMD.REGION_READ, p.cmd);
    try testing.expectEqual(uapi.family_version, m.payload[1]);
    var addr: ?u64 = null;
    var len: ?u64 = null;
    var attrs: codec.AttrIterator = .{ .buf = p.attrs };
    while (try attrs.next()) |a| switch (a.type) {
        uapi.ATTR.REGION_CHUNK_ADDR => addr = try uapi.asU64(a),
        uapi.ATTR.REGION_CHUNK_LEN => len = try uapi.asU64(a),
        else => {},
    };
    try testing.expectEqual(@as(?u64, 0x1000), addr);
    try testing.expectEqual(@as(?u64, 32), len);
    try testing.expect(try attrPresent(p.attrs, uapi.ATTR.REGION_SNAPSHOT_ID));
    // A snapshot read is not a direct read.
    try testing.expect(!(try attrPresent(p.attrs, uapi.ATTR.REGION_DIRECT)));

    const direct = try buildReadRegion(gpa, 0x19, 8, h, .{ .region = "cr-space", .length = 32 });
    defer gpa.free(direct);
    it = .{ .buf = direct };
    m = (try it.next()).?;
    p = try genl.splitPayload(m.payload);
    try testing.expect(!(try attrPresent(p.attrs, uapi.ATTR.REGION_SNAPSHOT_ID)));
    try testing.expect(try attrPresent(p.attrs, uapi.ATTR.REGION_DIRECT));
}

test "buildRegions dumps, buildRegion and buildDelSnapshot name one region" {
    const gpa = testing.allocator;
    const h: handle.Handle = .pci("0000:65:00.0");

    const dump = try buildRegions(gpa, 0x19, 1);
    defer gpa.free(dump);
    var it: codec.MessageIterator = .{ .buf = dump };
    var m = (try it.next()).?;
    try testing.expect(m.flags & codec.NLM_F_DUMP != 0);
    var p = try genl.splitPayload(m.payload);
    try testing.expectEqual(uapi.CMD.REGION_GET, p.cmd);
    try testing.expectEqual(@as(usize, 0), p.attrs.len);

    const one = try buildRegion(gpa, 0x19, 1, h, "fw-health");
    defer gpa.free(one);
    it = .{ .buf = one };
    m = (try it.next()).?;
    try testing.expect(m.flags & codec.NLM_F_DUMP == 0);
    p = try genl.splitPayload(m.payload);
    try testing.expectEqual(uapi.CMD.REGION_GET, p.cmd);
    try testing.expectEqualStrings("fw-health", (try parseRegion(p.attrs)).name());
    try testing.expect(!(try attrPresent(p.attrs, uapi.ATTR.REGION_SNAPSHOT_ID)));

    const del = try buildDelSnapshot(gpa, 0x19, 1, h, "fw-health", 3);
    defer gpa.free(del);
    it = .{ .buf = del };
    m = (try it.next()).?;
    p = try genl.splitPayload(m.payload);
    try testing.expectEqual(uapi.CMD.REGION_DEL, p.cmd);
    // A delete always names the snapshot: there is no "delete them all".
    try testing.expectEqualSlices(u32, &.{3}, (try parseRegion(p.attrs)).snapshots());

    try testing.expectError(error.InvalidRequest, buildRegion(gpa, 0x19, 1, h, ""));
    try testing.expectError(error.InvalidRequest, buildReadRegion(gpa, 0x19, 1, h, .{
        .region = "cr-space",
        .length = 0,
    }));
}
