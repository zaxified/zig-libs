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
//!     ring.release(blk);                        // hand the block back to the kernel
//! }
//! const st = try ring.stats();                  // packets, drops, freezes since the last call
//! ```
//!
//! A packet's `bytes` borrow the shared mapping and are valid until the block
//! is released. The mapping is written by the kernel, so every header read
//! from it is treated as hostile input: each field is copied once, then
//! checked against the block bounds before a slice is formed (`BadBlock`,
//! never a panic or a read outside the block), see `Block`. After a
//! `BadBlock` the ring is `failed`: `next` returns the same error from then on
//! (a corrupt ring is not resynchronised).
//!
//! Drops are never silent: `stats()` returns the kernel's packet, drop and
//! queue-freeze counters (`tpacket_stats_v3`), which the kernel resets on
//! every read, so the `Ring` accumulates them.

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
    /// with its block. The ring is `failed` from here on.
    BadBlock,
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
};

pub const Stats = struct { packets: u64 = 0, drops: u64 = 0, freezes: u64 = 0 };

/// One retired block: a pure view over a byte slice, so the hostile-header
/// checks run on any buffer (the tests and the fuzz harness hand it crafted
/// ones). `init` checks the block header; `nextPacket` checks each packet.
pub const Block = struct {
    bytes: []const u8,
    /// Which block of the ring this is (for `Ring.release`).
    index: u32 = 0,
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

    /// The next packet, or null after `num_pkts`.
    pub fn nextPacket(b: *Block) error{BadBlock}!?Packet {
        if (b.seen == b.num_pkts) return null;
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
    totals: Stats = .{},

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
    /// mode with no ring, so `recv` should not be used on it afterwards.
    pub fn deinit(r: *Ring) void {
        _ = linux.munmap(r.map.ptr, r.map.len);
        freeRing(r.fd);
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
        if (r.failed) return error.BadBlock;
        if (r.status(r.cur) & status_user == 0) {
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
        return blk;
    }

    /// Give a block back to the kernel (all of its packets' `bytes` are invalid
    /// from here) and move to the next one.
    pub fn release(r: *Ring, blk: Block) void {
        const p: *u32 = @ptrCast(@alignCast(r.blockBytes(blk.index)[8..12]));
        @atomicStore(u32, p, status_kernel, .release);
        r.cur = (blk.index + 1) % r.block_nr;
    }

    /// The kernel's counters since the last call, added to the running totals
    /// (`tpacket_stats_v3`: the kernel clears them on every read).
    pub fn stats(r: *Ring) Error!Stats {
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
