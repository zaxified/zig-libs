// SPDX-License-Identifier: MIT
//! `TPACKET_V3` receive ring: the kernel fills blocks of a memory map shared
//! with this process and retires a whole block at a time, so a busy capture
//! costs one wake-up per block instead of one `recvfrom` per frame (what
//! libpcap does by default on Linux). Opt-in: a `Ring` is created on a
//! `Socket` and costs nothing for a program that never names this file.
//!
//! ```text
//! var ring = try Ring.init(sock, .{});          // block_size / block_nr, defaults below
//! defer ring.deinit();
//! while (try ring.next(1000)) |blk| {           // null = timeout, nothing ready
//!     var it = blk;                             // a Block is its own packet iterator
//!     while (try it.nextPacket()) |p| use(p.bytes, p.wire_len, p.ts_ns, p.vlan_tci);
//!     try ring.release(blk);                    // hand the block back to the kernel
//! }
//! const st = try ring.stats();                  // packets, drops, freezes since the last call
//! ```
//!
//! A packet's `bytes` borrow the shared mapping and are valid until the block
//! is released. The mapping is written by the kernel, so every header read
//! from it is treated as hostile input: each field is copied once, then
//! checked against the block bounds before a slice is formed (`BadBlock`,
//! never a panic or a read outside the block), see `Block`. A bad BLOCK header
//! seen by `next` marks the ring `failed`: `next` returns the same error from
//! then on (a corrupt ring is not resynchronised). A bad PACKET header seen by
//! `Block.nextPacket` is returned to the caller and does not fail the ring: the
//! caller still hands the block back with `release` and the ring goes on.
//!
//! Misuse is an error, never UB: `next` or `release` after `deinit` is
//! `Closed`; `next` while a block is still held is `BlockHeld`; `release` of a
//! block that is not the held one is `NotHeld` / `WrongBlock` and moves nothing.
//!
//! Drops are never silent: `stats()` returns the kernel's packet, drop and
//! queue-freeze counters (`tpacket_stats_v3`), which the kernel resets on
//! every read, so the `Ring` accumulates them. `packets` INCLUDES the dropped
//! ones (a netns run: 80 packets seen by the socket, 54 dropped, 26 delivered
//! to the ring). `next` returns null on a timeout AND when `poll` was
//! interrupted by a signal (EINTR): a caller loops. The ring is a MAP_SHARED
//! mapping and the cursor is plain state in the `Ring`: do not use one `Ring`
//! from two threads, and do not use it after `fork` in both processes (the
//! child inherits the socket and the map; give the ring to one of them).

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const root = @import("root.zig");

pub const tpacket_v3: c_int = 2;
const status_kernel: u32 = 0;
const status_user: u32 = 1;
const status_vlan_valid: u32 = 1 << 4;
const status_vlan_tpid_valid: u32 = 1 << 6;
/// `sizeof(struct tpacket_block_desc)` up to and including `hdr.bh1` (48).
pub const block_header_len = 48;
/// `sizeof(struct tpacket3_hdr)` (48): the per-packet header.
pub const packet_header_len = 48;

pub const Options = struct {
    /// Bytes per block: a multiple of the page size, 4 KiB ..= `max_block_size`.
    block_size: u32 = 1 << 20,
    /// Blocks in the ring: `min_blocks` ..= `max_blocks`.
    block_nr: u32 = 4,
    /// The kernel's `tp_frame_size`: a multiple of 16, at least 128, at most
    /// `block_size`. It only has to be valid in V3 (packets are packed back to
    /// back), the default fits one MTU-sized frame with its headers.
    frame_size: u32 = 2048,
    /// Retire a partly filled block after this many milliseconds (`tp_retire_blk_tov`),
    /// so a trickle of traffic is not held back until a block fills. 0 = the
    /// kernel's own estimate.
    retire_ms: u32 = 60,
};

pub const max_block_size: u32 = 16 << 20;
pub const min_blocks: u32 = 2;
pub const max_blocks: u32 = 1024;
/// The whole map is at most this many bytes (checked in 64 bits before anything
/// is mapped, so a 32-bit target cannot overflow `usize`).
pub const max_total: u64 = 256 << 20;

pub const InitError = error{
    /// Sizes outside the limits above, or not page / 16-byte aligned.
    BadSize,
    /// `CAP_NET_RAW` missing.
    AccessDenied,
    /// The kernel or the socket refuses `TPACKET_V3` (old kernel, a socket
    /// that is not AF_PACKET, a link type without ring support, a ring already
    /// set up on this socket).
    RingUnsupported,
    /// The kernel could not allocate the ring or the map could not be created.
    OutOfMemory,
};

pub const Error = error{
    /// A block header or a packet header in the shared map is inconsistent
    /// with its block (a block header seen by `next` leaves the ring `failed`).
    BadBlock,
    /// `next` or `stats` on a ring that was `deinit`ed.
    Closed,
    /// `next` while the previous block is still held (not released).
    BlockHeld,
    /// `poll` failed (not a timeout).
    PollFailed,
    /// The socket reported an error condition (`POLLERR` / `POLLNVAL`).
    SocketError,
    StatsFailed,
};

pub const Packet = struct {
    /// The captured bytes (a borrow of the map, valid until the block is released).
    bytes: []const u8,
    /// Length on the wire.
    wire_len: u32,
    /// Kernel receive time, nanoseconds since the epoch.
    ts_ns: u64,
    /// The 802.1Q tag the kernel stripped (TCI), when it did.
    vlan_tci: ?u16,
    /// The tag's TPID (0x8100, 0x88a8 ...) when the kernel reported it.
    vlan_tpid: ?u16,
};

pub const ReleaseError = error{ Closed, NotHeld, WrongBlock };

pub const Stats = struct { packets: u64 = 0, drops: u64 = 0, freezes: u64 = 0 };

/// One retired block: a pure view over a byte slice, so the hostile-header
/// checks run on any buffer (the tests and the fuzz harness hand it crafted
/// ones). `init` checks the block header; `nextPacket` checks each packet.
pub const Block = struct {
    bytes: []const u8,
    /// Which block of the ring this is (for `Ring.release`).
    index: u32 = 0,
    /// The hand-out `Ring.next` gave this block: 0 for a block made by `init`.
    /// `Ring.release` accepts only the handle of the block that is held now, so
    /// a stale copy (the same index after a wrap) or a forged one is `WrongBlock`.
    ticket: u64 = 0,
    num_pkts: u32,
    /// Offset of the next packet header in `bytes`.
    next_off: usize,
    seen: u32 = 0,
    blk_len: usize,

    /// `bytes` is the whole block (`block_size` bytes). Everything read from it
    /// is copied once and checked.
    pub fn init(bytes: []const u8) error{BadBlock}!Block {
        if (bytes.len < block_header_len) return error.BadBlock;
        // struct tpacket_block_desc: version u32, offset_to_priv u32, then
        // hdr.bh1 { block_status u32, num_pkts u32, offset_to_first_pkt u32,
        // blk_len u32, seq_num u64, ts_first_pkt, ts_last_pkt }.
        const num_pkts = rd32(bytes, 12);
        const first = rd32(bytes, 16);
        const blk_len = rd32(bytes, 20);
        if (blk_len < block_header_len or blk_len > bytes.len) return error.BadBlock;
        // Every packet takes at least its header: more claimed than fit is hostile.
        if (num_pkts > (blk_len - block_header_len) / packet_header_len) return error.BadBlock;
        if (num_pkts != 0 and (first < block_header_len or first > blk_len - packet_header_len)) return error.BadBlock;
        return .{ .bytes = bytes, .num_pkts = num_pkts, .next_off = first, .blk_len = blk_len };
    }

    /// The next packet, or null after `num_pkts`. `BadBlock` ends the block: every
    /// later call is null, so nothing past a bad header is handed out.
    pub fn nextPacket(b: *Block) error{BadBlock}!?Packet {
        if (b.seen == b.num_pkts) return null;
        errdefer b.seen = b.num_pkts;
        const off = b.next_off;
        if (off > b.blk_len or b.blk_len - off < packet_header_len) return error.BadBlock;
        const h = b.bytes[off..][0..packet_header_len];
        // struct tpacket3_hdr: next_offset, sec, nsec, snaplen, len, status (u32 each),
        // mac, net (u16 each), then hdr_variant1 { rxhash, vlan_tci u32, vlan_tpid u16 }.
        const next = rd32(h, 0);
        const sec = rd32(h, 4);
        const nsec = rd32(h, 8);
        const snaplen = rd32(h, 12);
        const wire = rd32(h, 16);
        const status = rd32(h, 20);
        const mac = std.mem.readInt(u16, h[24..26], builtin.cpu.arch.endian());
        const tci = rd32(h, 32);
        if (nsec >= 1_000_000_000) return error.BadBlock;
        // The data lies inside the block, after the header.
        if (mac < packet_header_len or mac > b.blk_len - off) return error.BadBlock;
        if (snaplen > b.blk_len - off - mac) return error.BadBlock;
        b.seen += 1;
        if (b.seen < b.num_pkts) {
            // The next header must lie after this packet's data and inside the block.
            if (next == 0 or next > b.blk_len - off) return error.BadBlock;
            b.next_off = off + next;
            if (b.next_off < off + mac + snaplen) return error.BadBlock;
        }
        return .{
            .bytes = b.bytes[off + mac ..][0..snaplen],
            .wire_len = wire,
            .ts_ns = @as(u64, sec) * std.time.ns_per_s + nsec,
            .vlan_tci = if (status & status_vlan_valid != 0) @truncate(tci) else null,
            .vlan_tpid = if (status & status_vlan_tpid_valid != 0) std.mem.readInt(u16, h[36..38], builtin.cpu.arch.endian()) else null,
        };
    }
};

fn rd32(b: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, b[off..][0..4], builtin.cpu.arch.endian());
}

/// `struct tpacket_req3`.
const Req3 = extern struct {
    block_size: u32,
    block_nr: u32,
    frame_size: u32,
    frame_nr: u32,
    retire_blk_tov: u32,
    sizeof_priv: u32,
    feature_req_word: u32,
};

pub const Ring = struct {
    fd: i32,
    map: []align(std.heap.page_size_min) u8,
    block_size: u32,
    block_nr: u32,
    /// The block to look at next.
    cur: u32 = 0,
    /// Set by the first `BadBlock`: the same error from every later `next`.
    failed: bool = false,
    /// A block returned by `next` and not yet released.
    held: bool = false,
    /// Hand-out counter (never 0) and the ticket of the held block.
    next_ticket: u64 = 1,
    held_ticket: u64 = 0,
    closed: bool = false,
    /// False for `fromMap`: nothing to unmap or free.
    owns_map: bool = true,
    totals: Stats = .{},

    /// A ring over caller-provided memory and no socket: the state machine
    /// (`next`, `release`, wrap, status) runs on it unchanged, which is how it
    /// is tested without privileges. `next` never waits on it (null when no
    /// block is ready) and `stats` returns the totals.
    pub fn fromMap(map: []align(std.heap.page_size_min) u8, block_size: u32, block_nr: u32) error{BadSize}!Ring {
        if (block_nr == 0 or block_size < block_header_len or @as(u64, block_size) * block_nr > map.len) return error.BadSize;
        // `status` and `release` read a u32 inside each block: an unaligned block is a panic.
        if (block_size % @alignOf(u32) != 0) return error.BadSize;
        return .{ .fd = -1, .map = map, .block_size = block_size, .block_nr = block_nr, .owns_map = false };
    }

    /// Switch `sock` to `TPACKET_V3` and map its receive ring. The caller keeps
    /// owning (and closing) the socket; `deinit` unmaps and frees the ring.
    pub fn init(sock: root.Socket, opts: Options) InitError!Ring {
        if (opts.block_size == 0 or opts.block_size > max_block_size or opts.block_size % std.heap.pageSize() != 0) return error.BadSize;
        if (opts.block_nr < min_blocks or opts.block_nr > max_blocks) return error.BadSize;
        if (opts.frame_size < 128 or opts.frame_size % 16 != 0 or opts.frame_size > opts.block_size) return error.BadSize;
        const total: u64 = @as(u64, opts.block_size) * opts.block_nr;
        if (total > max_total or total > std.math.maxInt(usize)) return error.BadSize;

        const ver: c_int = tpacket_v3;
        try setOpt(sock.fd, linux.PACKET.VERSION, std.mem.asBytes(&ver));
        const req: Req3 = .{
            .block_size = opts.block_size,
            .block_nr = opts.block_nr,
            .frame_size = opts.frame_size,
            .frame_nr = @intCast(@as(u64, opts.block_size / opts.frame_size) * opts.block_nr),
            .retire_blk_tov = opts.retire_ms,
            .sizeof_priv = 0,
            .feature_req_word = 0,
        };
        try setOpt(sock.fd, linux.PACKET.RX_RING, std.mem.asBytes(&req));
        const rc = linux.mmap(null, @intCast(total), .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED }, sock.fd, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .NOMEM, .AGAIN => {
                freeRing(sock.fd);
                return error.OutOfMemory;
            },
            else => {
                freeRing(sock.fd);
                return error.RingUnsupported;
            },
        }
        const ptr: [*]align(std.heap.page_size_min) u8 = @ptrFromInt(rc);
        return .{ .fd = sock.fd, .map = ptr[0..@intCast(total)], .block_size = opts.block_size, .block_nr = opts.block_nr };
    }

    fn setOpt(fd: i32, opt: u32, bytes: []const u8) InitError!void {
        switch (linux.errno(linux.setsockopt(fd, linux.SOL.PACKET, opt, bytes.ptr, @intCast(bytes.len)))) {
            .SUCCESS => {},
            .PERM, .ACCES => return error.AccessDenied,
            .NOMEM, .NOBUFS => return error.OutOfMemory,
            else => return error.RingUnsupported, // ENOPROTOOPT, EINVAL, EBUSY, ...
        }
    }

    /// Tell the kernel to drop the ring (a zeroed request).
    fn freeRing(fd: i32) void {
        const zero: Req3 = std.mem.zeroes(Req3);
        _ = linux.setsockopt(fd, linux.SOL.PACKET, linux.PACKET.RX_RING, std.mem.asBytes(&zero).ptr, @sizeOf(Req3));
    }

    /// Unmap and free the ring. The socket stays open; it is back in `TPACKET_V3`
    /// mode with no ring, so `recv` should not be used on it afterwards. A `Block`
    /// or `Packet` still held points into the unmapped ring: do not read it.
    pub fn deinit(r: *Ring) void {
        if (r.closed) return;
        r.closed = true;
        r.held = false;
        if (r.owns_map) {
            _ = linux.munmap(r.map.ptr, r.map.len);
            freeRing(r.fd);
        }
        r.map = r.map[0..0];
    }

    fn blockBytes(r: *const Ring, i: u32) []u8 {
        return r.map[@as(usize, i) * r.block_size ..][0..r.block_size];
    }

    fn status(r: *const Ring, i: u32) u32 {
        const p: *const u32 = @ptrCast(@alignCast(r.blockBytes(i)[8..12]));
        return @atomicLoad(u32, p, .acquire);
    }

    /// Wait up to `timeout_ms` (-1 = forever) for the next retired block.
    /// Null = timeout. The returned block must be given back with `release`.
    pub fn next(r: *Ring, timeout_ms: i32) Error!?Block {
        if (r.closed) return error.Closed;
        if (r.failed) return error.BadBlock;
        if (r.held) return error.BlockHeld;
        if (r.status(r.cur) & status_user == 0) {
            if (r.fd < 0) return null;
            var pfd = [1]linux.pollfd{.{ .fd = r.fd, .events = linux.POLL.IN, .revents = 0 }};
            const rc = linux.poll(&pfd, 1, timeout_ms);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => return null,
                else => return error.PollFailed,
            }
            if (pfd[0].revents & (linux.POLL.ERR | linux.POLL.NVAL) != 0) return error.SocketError;
            if (r.status(r.cur) & status_user == 0) return null;
        }
        var blk = Block.init(r.blockBytes(r.cur)) catch |e| {
            r.failed = true;
            return e;
        };
        blk.index = r.cur;
        blk.ticket = r.next_ticket;
        r.held_ticket = r.next_ticket;
        r.next_ticket +%= 1;
        if (r.next_ticket == 0) r.next_ticket = 1;
        r.held = true;
        return blk;
    }

    /// Give a block back to the kernel (all of its packets' `bytes` are invalid
    /// from here) and move to the next one.
    pub fn release(r: *Ring, blk: Block) ReleaseError!void {
        if (r.closed) return error.Closed;
        if (!r.held) return error.NotHeld;
        // The handle `next` gave out for the held block, over this ring's own memory.
        if (blk.index != r.cur or blk.ticket != r.held_ticket or blk.bytes.ptr != r.blockBytes(r.cur).ptr) return error.WrongBlock;
        r.held = false;
        const p: *u32 = @ptrCast(@alignCast(r.blockBytes(blk.index)[8..12]));
        @atomicStore(u32, p, status_kernel, .release);
        r.cur = (blk.index + 1) % r.block_nr;
    }

    /// The kernel's counters since the last call, added to the running totals
    /// (`tpacket_stats_v3`: the kernel clears them on every read).
    pub fn stats(r: *Ring) Error!Stats {
        if (r.closed) return error.Closed;
        if (r.fd < 0) return r.totals;
        var st: [3]u32 = @splat(0);
        var len: linux.socklen_t = @sizeOf(@TypeOf(st));
        if (linux.errno(linux.getsockopt(r.fd, linux.SOL.PACKET, linux.PACKET.STATISTICS, std.mem.asBytes(&st).ptr, &len)) != .SUCCESS or len < 12) return error.StatsFailed;
        r.totals.packets += st[0];
        r.totals.drops += st[1];
        r.totals.freezes += st[2];
        return r.totals;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A block image with `n` packets of `len` bytes each, built by hand in the
/// kernel's layout (`TPACKET_V3`, native byte order).
fn buildBlock(buf: []u8, n: u32, len: u32) void {
    @memset(buf, 0);
    const e = builtin.cpu.arch.endian();
    var off: usize = block_header_len;
    const stride = (packet_header_len + len + 15) & ~@as(usize, 15);
    std.mem.writeInt(u32, buf[0..4], 3, e); // version
    std.mem.writeInt(u32, buf[8..12], status_user, e);
    std.mem.writeInt(u32, buf[12..16], n, e);
    std.mem.writeInt(u32, buf[16..20], block_header_len, e);
    for (0..n) |i| {
        const h = buf[off..];
        const last = i + 1 == n;
        std.mem.writeInt(u32, h[0..4], if (last) 0 else @intCast(stride), e);
        std.mem.writeInt(u32, h[4..8], 1000 + @as(u32, @intCast(i)), e);
        std.mem.writeInt(u32, h[8..12], 5, e);
        std.mem.writeInt(u32, h[12..16], len, e);
        std.mem.writeInt(u32, h[16..20], len + 4, e);
        std.mem.writeInt(u16, h[24..26], packet_header_len, e);
        @memset(h[packet_header_len..][0..len], @intCast(i + 1));
        off += stride;
    }
    std.mem.writeInt(u32, buf[20..24], @intCast(off), e);
}

test "Block: reads a well-formed block packet by packet" {
    var buf: [4096]u8 = undefined;
    buildBlock(&buf, 3, 60);
    var b = try Block.init(&buf);
    var i: u8 = 1;
    while (try b.nextPacket()) |p| : (i += 1) {
        try testing.expectEqual(@as(usize, 60), p.bytes.len);
        try testing.expectEqual(i, p.bytes[0]);
        try testing.expectEqual(@as(u32, 64), p.wire_len);
        try testing.expectEqual((1000 + @as(u64, i) - 1) * std.time.ns_per_s + 5, p.ts_ns);
        try testing.expect(p.vlan_tci == null);
    }
    try testing.expectEqual(@as(u8, 4), i);
    try testing.expect((try b.nextPacket()) == null);
}

test "Block: hostile headers are BadBlock, never a read outside the block" {
    const e = builtin.cpu.arch.endian();
    var base: [4096]u8 = undefined;
    buildBlock(&base, 3, 60);
    const Case = struct { off: usize, val: u32 };
    // Block header: num_pkts huge, first packet before the header / past the end, blk_len past the buffer or short.
    const block_cases = [_]Case{
        .{ .off = 12, .val = 0xffffffff },
        .{ .off = 12, .val = 100000 },
        .{ .off = 16, .val = 0 },
        .{ .off = 16, .val = 4090 },
        .{ .off = 16, .val = 0xffffffff },
        .{ .off = 20, .val = 5000 },
        .{ .off = 20, .val = 10 },
        .{ .off = 20, .val = 0xffffffff },
    };
    for (block_cases) |c| {
        var buf = base;
        std.mem.writeInt(u32, buf[c.off..][0..4], c.val, e);
        var failed = false;
        if (Block.init(&buf)) |b0| {
            var b = b0;
            while (b.nextPacket() catch blk: {
                failed = true;
                break :blk null;
            }) |p| try testing.expect(@intFromPtr(p.bytes.ptr) + p.bytes.len <= @intFromPtr(&buf) + buf.len);
        } else |_| failed = true;
        try testing.expect(failed);
    }
    // Packet headers: next_offset zero/backwards/past the end, snaplen or mac past the block, nsec out of range.
    const pkt_cases = [_]Case{
        .{ .off = block_header_len + 0, .val = 0 }, // next = 0 with packets left
        .{ .off = block_header_len + 0, .val = 8 }, // next inside this header
        .{ .off = block_header_len + 0, .val = 0xffffffff },
        .{ .off = block_header_len + 8, .val = 1_000_000_000 },
        .{ .off = block_header_len + 12, .val = 0xffffffff },
        .{ .off = block_header_len + 12, .val = 4000 },
        .{ .off = block_header_len + 24, .val = 0xffff }, // mac (low 16 bits)
    };
    for (pkt_cases) |c| {
        var buf = base;
        if (c.off == block_header_len + 24) {
            std.mem.writeInt(u16, buf[c.off..][0..2], @intCast(c.val), e);
        } else std.mem.writeInt(u32, buf[c.off..][0..4], c.val, e);
        var b = try Block.init(&buf);
        var failed = false;
        while (b.nextPacket() catch blk: {
            failed = true;
            break :blk null;
        }) |p| try testing.expect(@intFromPtr(p.bytes.ptr) + p.bytes.len <= @intFromPtr(&buf) + buf.len);
        try testing.expect(failed);
    }
    // A block shorter than its own header.
    try testing.expectError(error.BadBlock, Block.init(base[0 .. block_header_len - 1]));
}

test "Block: the boundaries are exact (data ends at the block's end; one packet more than fits; a data offset inside the header)" {
    const e = builtin.cpu.arch.endian();
    var buf: [4096]u8 = undefined;
    buildBlock(&buf, 1, 60);
    // The packet's data ends exactly at blk_len: fine.
    std.mem.writeInt(u32, buf[20..24], block_header_len + packet_header_len + 60, e);
    var b = try Block.init(&buf);
    try testing.expectEqual(@as(usize, 60), (try b.nextPacket()).?.bytes.len);
    // One byte more is claimed than the block holds.
    std.mem.writeInt(u32, buf[20..24], block_header_len + packet_header_len + 59, e);
    b = try Block.init(&buf);
    try testing.expectError(error.BadBlock, b.nextPacket());
    // Exactly as many packets as fit by header size are plausible; one more is not.
    buildBlock(&buf, 2, 0);
    std.mem.writeInt(u32, buf[20..24], block_header_len + 2 * packet_header_len, e);
    _ = try Block.init(&buf);
    std.mem.writeInt(u32, buf[12..16], 3, e);
    try testing.expectError(error.BadBlock, Block.init(&buf));
    // A data offset (tp_mac) inside the 48-byte header is hostile.
    buildBlock(&buf, 1, 60);
    for ([_]u16{ 0, 1, 47 }) |mac| {
        std.mem.writeInt(u16, buf[block_header_len + 24 ..][0..2], mac, e);
        var bb = try Block.init(&buf);
        try testing.expectError(error.BadBlock, bb.nextPacket());
    }
}

test "Ring.init refuses sizes outside the limits before touching the socket (32-bit safe: checked in 64 bits)" {
    const dummy: root.Socket = .{ .fd = -1 };
    const bad = [_]Options{
        .{ .block_size = 0 },
        .{ .block_size = 4097 },
        .{ .block_size = max_block_size + 4096 },
        .{ .block_nr = 1 },
        .{ .block_nr = max_blocks + 1 },
        .{ .frame_size = 100 },
        .{ .frame_size = 2049 },
        .{ .block_size = 16 << 20, .block_nr = 1024 }, // 16 GiB total: over max_total, and over a 32-bit usize
        .{ .block_size = 8 << 20, .block_nr = 64 }, // 512 MiB: over max_total
        .{ .frame_size = (1 << 20) + 16 },
    };
    for (bad) |o| try testing.expectError(error.BadSize, Ring.init(dummy, o));
}

test "Ring.init: the limits themselves are accepted by the size checks (the syscall on fd -1 is what refuses)" {
    const dummy: root.Socket = .{ .fd = -1 };
    const edge = [_]Options{
        .{ .block_size = 4096, .block_nr = min_blocks },
        .{ .block_size = 4096, .block_nr = max_blocks },
        .{ .frame_size = 128 },
        .{ .block_size = max_block_size, .block_nr = @intCast(max_total / max_block_size), .frame_size = 2048 }, // exactly max_total
        .{ .block_size = max_block_size, .block_nr = min_blocks },
        .{ .block_size = 4096, .block_nr = max_blocks, .frame_size = 4096 },
    };
    for (edge) |o| {
        if (Ring.init(dummy, o)) |_| return error.UnexpectedSuccess else |e| try testing.expect(e != error.BadSize);
    }
}

/// A fake mapping: `n` blocks of `bs` bytes, each holding `pkts` packets, the first `ready` of them retired to user space.
fn fakeMap(map: []u8, bs: usize, n: usize, pkts: u32, ready: usize) void {
    for (0..n) |i| {
        const blk = map[i * bs ..][0..bs];
        buildBlock(blk, pkts, 40);
        if (i >= ready) std.mem.writeInt(u32, blk[8..12], status_kernel, builtin.cpu.arch.endian());
    }
}

test "Ring state machine on a fake mapping (no privileges): next, release, wrap, misuse" {
    var map: [4 * 4096]u8 align(std.heap.page_size_min) = undefined;
    fakeMap(&map, 4096, 4, 2, 2);
    var r = try Ring.fromMap(&map, 4096, 4);
    const b0 = (try r.next(0)).?;
    try testing.expectEqual(@as(u32, 0), b0.index);
    // A second `next` while one is held, a release of another block, a double release: errors, nothing moves.
    try testing.expectError(error.BlockHeld, r.next(0));
    var other = b0;
    other.index = 1;
    try testing.expectError(error.WrongBlock, r.release(other));
    try r.release(b0);
    try testing.expectError(error.NotHeld, r.release(b0));
    try testing.expectEqual(@as(u32, 1), r.cur);
    // The kernel's side of the handshake: the released block went back to status 0.
    try testing.expectEqual(status_kernel, std.mem.readInt(u32, map[8..12], builtin.cpu.arch.endian()));
    const b1 = (try r.next(0)).?;
    try testing.expectEqual(@as(u32, 1), b1.index);
    try r.release(b1);
    // Blocks 2 and 3 are not retired: nothing to read, nothing waits.
    try testing.expect((try r.next(0)) == null);
    // The kernel retires 2, 3 and (after the wrap) 0 again: the cursor wraps.
    for ([_]usize{ 2, 3, 0 }) |i| {
        buildBlock(map[i * 4096 ..][0..4096], 1, 60);
        const blk = (try r.next(0)).?;
        try testing.expectEqual(@as(u32, @intCast(i)), blk.index);
        var it = blk;
        try testing.expect((try it.nextPacket()) != null);
        try r.release(blk);
    }
    try testing.expectEqual(@as(u32, 1), r.cur);
    const st = try r.stats();
    try testing.expectEqual(@as(u64, 0), st.drops);
    // After deinit every call is `Closed`, a second deinit is a no-op.
    r.deinit();
    try testing.expectError(error.Closed, r.next(0));
    try testing.expectError(error.Closed, r.stats());
    try testing.expectError(error.Closed, r.release(b1));
    r.deinit();
}

test "Ring.release: a stale copy of an old handle and a forged Block are WrongBlock and move nothing" {
    var map: [2 * 4096]u8 align(std.heap.page_size_min) = undefined;
    fakeMap(&map, 4096, 2, 1, 2);
    var r = try Ring.fromMap(&map, 4096, 2);
    const first = (try r.next(0)).?; // block 0, ticket 1
    try r.release(first);
    const second = (try r.next(0)).?; // block 1
    try r.release(second);
    // The kernel refills block 0; the cursor wrapped back to it: the same index as `first` has.
    buildBlock(map[0..4096], 1, 60);
    const again = (try r.next(0)).?;
    try testing.expectEqual(first.index, again.index);
    try testing.expect(again.ticket != first.ticket);
    // The stale handle names the held block's index and still must not release it.
    try testing.expectError(error.WrongBlock, r.release(first));
    try testing.expect(r.held and r.cur == 0);
    // A Block made from other bytes (or the same bytes by `init`) is not the hand-out either.
    var forged = try Block.init(map[0..4096]);
    forged.index = 0;
    try testing.expectError(error.WrongBlock, r.release(forged));
    var elsewhere: [4096]u8 = undefined;
    buildBlock(&elsewhere, 1, 60);
    var forged2 = try Block.init(&elsewhere);
    forged2.index = 0;
    forged2.ticket = again.ticket;
    try testing.expectError(error.WrongBlock, r.release(forged2));
    try testing.expect(r.held and r.cur == 0);
    // A copy of the real one (the iteration idiom) still works, once.
    var it = again;
    _ = try it.nextPacket();
    try r.release(again);
    try testing.expect(!r.held and r.cur == 1);
}

test "Block: the vlan status bits select tp_vlan_tci / tp_vlan_tpid, at the offsets of struct tpacket3_hdr" {
    const e = builtin.cpu.arch.endian();
    var buf: [4096]u8 = undefined;
    buildBlock(&buf, 2, 60);
    const h0 = block_header_len;
    // Offsets from <linux/if_packet.h>: tp_rxhash 28, tp_vlan_tci 32 (u32), tp_vlan_tpid 36 (u16), tp_padding 38.
    std.mem.writeInt(u32, buf[h0 + 28 ..][0..4], 0xdeadbeef, e); // decoy: the rxhash
    std.mem.writeInt(u32, buf[h0 + 32 ..][0..4], 0x0123, e);
    std.mem.writeInt(u16, buf[h0 + 36 ..][0..2], 0x88a8, e);
    std.mem.writeInt(u16, buf[h0 + 38 ..][0..2], 0xbeef, e); // decoy: the padding
    const st = h0 + 20;
    // Neither bit: the fields are ignored.
    var b = try Block.init(&buf);
    var p = (try b.nextPacket()).?;
    try testing.expect(p.vlan_tci == null and p.vlan_tpid == null);
    // The tag bit alone: the id, no TPID.
    std.mem.writeInt(u32, buf[st..][0..4], status_vlan_valid, e);
    b = try Block.init(&buf);
    p = (try b.nextPacket()).?;
    try testing.expectEqual(@as(?u16, 0x0123), p.vlan_tci);
    try testing.expect(p.vlan_tpid == null);
    // The TPID bit alone: the TPID, no id.
    std.mem.writeInt(u32, buf[st..][0..4], status_vlan_tpid_valid, e);
    b = try Block.init(&buf);
    p = (try b.nextPacket()).?;
    try testing.expect(p.vlan_tci == null);
    try testing.expectEqual(@as(?u16, 0x88a8), p.vlan_tpid);
    // Both, and the second packet (whose bits are off) stays untagged.
    std.mem.writeInt(u32, buf[st..][0..4], status_vlan_valid | status_vlan_tpid_valid, e);
    b = try Block.init(&buf);
    p = (try b.nextPacket()).?;
    try testing.expectEqual(@as(?u16, 0x0123), p.vlan_tci);
    try testing.expectEqual(@as(?u16, 0x88a8), p.vlan_tpid);
    p = (try b.nextPacket()).?;
    try testing.expect(p.vlan_tci == null and p.vlan_tpid == null);
    // The id is 16 bits: the kernel's u32 keeps the tag in the low half.
    std.mem.writeInt(u32, buf[h0 + 32 ..][0..4], 0xabcd1234, e);
    b = try Block.init(&buf);
    p = (try b.nextPacket()).?;
    try testing.expectEqual(@as(?u16, 0x1234), p.vlan_tci);
}

test "Ring: a hostile block header fails the ring for good; a hostile packet header does not" {
    const e = builtin.cpu.arch.endian();
    var map: [2 * 4096]u8 align(std.heap.page_size_min) = undefined;
    fakeMap(&map, 4096, 2, 2, 2);
    std.mem.writeInt(u32, map[12..16], 0xffffffff, e); // block 0: num_pkts absurd
    var r = try Ring.fromMap(&map, 4096, 2);
    try testing.expectError(error.BadBlock, r.next(0));
    try testing.expectError(error.BadBlock, r.next(0));
    try testing.expect(r.failed and !r.held);
    // Block header fine, packet header hostile: the packet read fails, the block is still released, the ring goes on.
    fakeMap(&map, 4096, 2, 2, 2);
    std.mem.writeInt(u32, map[block_header_len + 12 ..][0..4], 0xffffffff, e); // snaplen
    var r2 = try Ring.fromMap(&map, 4096, 2);
    var blk = (try r2.next(0)).?;
    try testing.expectError(error.BadBlock, blk.nextPacket());
    try r2.release(blk);
    blk = (try r2.next(0)).?;
    try testing.expect((try blk.nextPacket()) != null);
    try r2.release(blk);
    // Sizes the mapping cannot hold.
    try testing.expectError(error.BadSize, Ring.fromMap(&map, 4096, 3));
    try testing.expectError(error.BadSize, Ring.fromMap(&map, 4, 1));
    try testing.expectError(error.BadSize, Ring.fromMap(&map, 4096, 0));
    try testing.expectError(error.BadSize, Ring.fromMap(&map, 1025, 2)); // unaligned block status
}

// ── fuzz: the block parser over arbitrary bytes ─────────────────────────────

const testkit = @import("testkit");
const fz = @import("fuzz_test.zig");
const RingMark = fz.Marker(enum { rejected, packets });

fn blockImage() [512]u8 {
    @setEvalBranchQuota(200000);
    var img: [512]u8 = undefined;
    buildBlock(&img, 3, 60);
    return img;
}

/// A real block image as a corpus seed: built at comptime in the kernel's layout.
const image = blockImage();
const ring_seeds = [_][]const u8{ testkit.fuzz.seed(&image), testkit.fuzz.seed(image[0..block_header_len]), testkit.fuzz.seed("") };

test "fuzz: Block over hostile bytes stays inside them" {
    try testing.fuzz({}, fuzzRingSmith, .{ .corpus = &ring_seeds });
}

test "fuzz driver: RAWSOCK_FUZZ (ring)" {
    try fz.fuzz_driver.run(fuzzRing, .{ .prefix = "RAWSOCK_FUZZ", .name = "rawsock-ring" });
}

test "fuzz harness: ring block, 300 seeds, reaches every outcome" {
    try RingMark.reach(fuzzRing, "rawsock-ring", 300);
}

fn fuzzRingSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [fz.script_cap]u8 = undefined;
    const n = smith.slice(&script);
    try fz.runFrom(fuzzRing, smith, script[0..n]);
}

fn fuzzRing(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [512]u8 = undefined;
    const len: usize = fz.drawInput(S, smith, &buf, &ring_seeds);
    const bytes = buf[0..len];
    var b = Block.init(bytes) catch return RingMark.mark(.rejected);
    var n: u32 = 0;
    while (b.nextPacket() catch return RingMark.mark(.rejected)) |p| : (n += 1) {
        if (n > len) return error.DidNotTerminate;
        const lo = @intFromPtr(bytes.ptr);
        try testing.expect(@intFromPtr(p.bytes.ptr) >= lo and @intFromPtr(p.bytes.ptr) + p.bytes.len <= lo + len);
    }
    if (n > 0) RingMark.mark(.packets) else RingMark.mark(.rejected);
}

// ── fuzz: the ring state machine over hostile block sequences ───────────────

const SeqMark = fz.Marker(enum { failed, delivered, idle, misuse });

test "fuzz: Ring over a fake mapping and random operations never panics" {
    try testing.fuzz({}, fuzzSeqSmith, .{ .corpus = &ring_seeds });
}

test "fuzz driver: RAWSOCK_FUZZ (ring sequence)" {
    try fz.fuzz_driver.run(fuzzSeq, .{ .prefix = "RAWSOCK_FUZZ", .name = "rawsock-ring-seq" });
}

test "fuzz harness: ring sequence, 300 seeds, reaches every outcome" {
    try SeqMark.reach(fuzzSeq, "rawsock-ring-seq", 300);
}

fn fuzzSeqSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [fz.script_cap]u8 = undefined;
    const n = smith.slice(&script);
    try fz.runFrom(fuzzSeq, smith, script[0..n]);
}

fn fuzzSeq(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [512]u8 = undefined;
    const len: usize = fz.drawInput(S, smith, &buf, &ring_seeds);
    // Four 512-byte blocks: block i starts as the input rotated by i, with a
    // status word taken from the input; the operation script is the rest.
    var map: [4 * 512]u8 align(std.heap.page_size_min) = undefined;
    for (0..4) |i| {
        for (0..512) |j| map[i * 512 + j] = if (len == 0) 0 else buf[(j + i * 37) % len];
        std.mem.writeInt(u32, map[i * 512 + 8 ..][0..4], if (len > i and buf[i] & 1 != 0) status_user else status_kernel, builtin.cpu.arch.endian());
    }
    var r = try Ring.fromMap(&map, 512, 4);
    var held: ?Block = null;
    var stale: ?Block = null; // a handle that was released
    // The model of the cursor: where `next` looks, and whether a block is out.
    var m_cur: u32 = 0;
    var m_held = false;
    var m_failed = false;
    for (0..24) |step| {
        const act: u8 = if (len == 0) 0 else buf[(step * 5 + 3) % len] % 5;
        switch (act) {
            0, 1 => {
                if (r.next(0)) |maybe| {
                    if (maybe) |blk| {
                        try testing.expect(!m_held and !m_failed);
                        try testing.expectEqual(m_cur, blk.index);
                        m_held = true;
                        held = blk;
                        var it = blk;
                        var n: u32 = 0;
                        while (it.nextPacket() catch null) |p| : (n += 1) {
                            const lo = @intFromPtr(&map);
                            try testing.expect(@intFromPtr(p.bytes.ptr) >= lo and @intFromPtr(p.bytes.ptr) + p.bytes.len <= lo + map.len);
                            if (n > map.len) return error.DidNotTerminate;
                        }
                        SeqMark.mark(.delivered);
                    } else SeqMark.mark(.idle);
                } else |e| {
                    // BlockHeld exactly while a block is out; BadBlock is terminal.
                    try testing.expect(e == error.BadBlock or (e == error.BlockHeld and m_held and !m_failed));
                    if (e == error.BadBlock) {
                        m_failed = true;
                        SeqMark.mark(.failed);
                    } else SeqMark.mark(.misuse);
                }
            },
            2 => if (held) |b| {
                try r.release(b);
                held = null;
                stale = b;
                try testing.expect(m_held);
                m_held = false;
                m_cur = (m_cur + 1) % 4;
                // The kernel refills the block it was given back.
                std.mem.writeInt(u32, map[@as(usize, b.index) * 512 + 8 ..][0..4], status_user, builtin.cpu.arch.endian());
            },
            3 => {
                // Misuse: a forged handle, any index, ticket 0 or a guessed one: never accepted.
                var fake = Block.init(map[0..512]) catch continue;
                fake.index = @intCast(step % 4);
                fake.ticket = if (step % 2 == 0) 0 else 1000 + step;
                if (r.release(fake)) |_| return error.ForgedHandleAccepted else |_| SeqMark.mark(.misuse);
            },
            else => if (stale) |sb| {
                // A released handle again: never accepted, whatever is held now.
                if (r.release(sb)) |_| return error.StaleHandleAccepted else |_| SeqMark.mark(.misuse);
            },
        }
        try testing.expectEqual(m_cur, r.cur);
        try testing.expectEqual(m_held, r.held);
    }
    r.deinit();
    try testing.expectError(error.Closed, r.next(0));
}

// ── delta audit 2026-11-04: the exact boundaries of the checks ──────────────

test "Block: every header check accepts its limit exactly and refuses one past it" {
    const e = builtin.cpu.arch.endian();
    // An empty block of exactly the header size: blk_len == bytes.len == 48, no packets, first_pkt 0.
    var empty: [block_header_len]u8 = @splat(0);
    std.mem.writeInt(u32, empty[20..24], block_header_len, e);
    var b0 = try Block.init(&empty);
    try testing.expect((try b0.nextPacket()) == null);

    // One packet whose header is the last 48 bytes of the block and which carries no data:
    // first == blk_len - 48, mac == blk_len - off, snaplen 0.
    var one: [2 * packet_header_len]u8 = @splat(0);
    std.mem.writeInt(u32, one[12..16], 1, e);
    std.mem.writeInt(u32, one[16..20], block_header_len, e);
    std.mem.writeInt(u32, one[20..24], one.len, e);
    std.mem.writeInt(u16, one[block_header_len + 24 ..][0..2], packet_header_len, e);
    var b1 = try Block.init(&one);
    const p = (try b1.nextPacket()).?;
    try testing.expectEqual(@as(usize, 0), p.bytes.len);

    // The same header started inside the block header (offset 40, before the first valid offset) is hostile.
    var inside: [2 * packet_header_len]u8 = @splat(0);
    std.mem.writeInt(u32, inside[12..16], 1, e);
    std.mem.writeInt(u32, inside[16..20], 40, e);
    std.mem.writeInt(u32, inside[20..24], inside.len, e);
    std.mem.writeInt(u16, inside[40 + 24 ..][0..2], packet_header_len, e);
    try testing.expectError(error.BadBlock, Block.init(&inside));

    // `next_off` is a public field: a caller's stray value past the block is BadBlock, not an underflow.
    var stray = try Block.init(&one);
    stray.next_off = one.len + 1000;
    try testing.expectError(error.BadBlock, stray.nextPacket());
    stray = try Block.init(&one);
    stray.next_off = one.len + 1;
    try testing.expectError(error.BadBlock, stray.nextPacket());

    // A packet whose next header would start exactly at the block's end is itself delivered; the
    // missing header is the next call's error.
    var two: [3 * packet_header_len]u8 = @splat(0);
    std.mem.writeInt(u32, two[12..16], 2, e);
    std.mem.writeInt(u32, two[16..20], block_header_len, e);
    std.mem.writeInt(u32, two[20..24], two.len, e);
    std.mem.writeInt(u32, two[block_header_len..][0..4], two.len - block_header_len, e); // next_offset
    std.mem.writeInt(u16, two[block_header_len + 24 ..][0..2], packet_header_len, e);
    var b2 = try Block.init(&two);
    try testing.expect((try b2.nextPacket()) != null);
    try testing.expectError(error.BadBlock, b2.nextPacket());
}

test "Block: an error ends the block; a consumer looping on `catch continue` gets no packet of it and does not spin" {
    const e = builtin.cpu.arch.endian();
    var buf: [4096]u8 = undefined;

    // The chain after the first packet is bad (next_offset 0): the check fires after `seen` moved.
    buildBlock(&buf, 3, 64);
    std.mem.writeInt(u32, buf[block_header_len..][0..4], 0, e);
    var chain = try Block.init(&buf);
    try testing.expectError(error.BadBlock, chain.nextPacket());
    try testing.expect((try chain.nextPacket()) == null);

    // The first packet's own header is bad (mac inside the header): the check fires before `seen` moves.
    buildBlock(&buf, 3, 64);
    std.mem.writeInt(u16, buf[block_header_len + 24 ..][0..2], 0, e);
    var head = try Block.init(&buf);
    try testing.expectError(error.BadBlock, head.nextPacket());
    try testing.expect((try head.nextPacket()) == null);
}

test "Block: packets packed back to back (the next header starts exactly where the data ends) are all delivered" {
    var buf: [4096]u8 = undefined;
    buildBlock(&buf, 3, 64); // 48 + 64 is a multiple of 16: no padding between packets
    var b = try Block.init(&buf);
    var n: usize = 0;
    while (try b.nextPacket()) |p| : (n += 1) try testing.expectEqual(@as(usize, 64), p.bytes.len);
    try testing.expectEqual(@as(usize, 3), n);
}

test "Ring.fromMap: a block of exactly the header size, a sticky failure, and a wait-free next" {
    var map: [4096]u8 align(std.heap.page_size_min) = undefined;
    _ = try Ring.fromMap(&map, block_header_len, 1);
    try testing.expectError(error.BadSize, Ring.fromMap(&map, block_header_len - 4, 1));
    var big: [2 * 4096]u8 align(std.heap.page_size_min) = undefined;
    fakeMap(&big, 4096, 2, 1, 2);
    var r = try Ring.fromMap(&big, 4096, 2);
    // A hostile block: BadBlock, and still BadBlock after the memory looks fine again (never resynchronised).
    std.mem.writeInt(u32, big[20..24], 7, builtin.cpu.arch.endian());
    try testing.expectError(error.BadBlock, r.next(0));
    buildBlock(big[0..4096], 1, 60);
    try testing.expectError(error.BadBlock, r.next(0));
    // No socket, nothing ready: null at once even for an infinite timeout.
    var r2 = try Ring.fromMap(&map, 4096, 1);
    std.mem.writeInt(u32, map[8..12], status_kernel, builtin.cpu.arch.endian());
    try testing.expect((try r2.next(-1)) == null);
}
