// SPDX-License-Identifier: MIT

//! The host's counter files — what a gopsutil / procfs user reads first:
//!
//!   `/proc/net/dev`         per-interface byte/packet/error counters
//!   `/proc/stat`            CPU time per state, context switches, boot time
//!   `/proc/meminfo`         memory, typed
//!   `/proc/diskstats`       per-block-device I/O counters
//!   `/proc/net/ipv6_route`  the IPv6 routing table (`/proc/net/route` is v4 only)
//!
//! Formats are the kernel's documented ones — proc(5),
//! `Documentation/admin-guide/iostats.rst`, `Documentation/filesystems/
//! proc.rst` — and every fixture in the tests is a real capture (sanitized
//! names/addresses). Same hostile-input rule as the rest of the module: a row
//! that does not have the documented shape is skipped, never fatal; numbers
//! are parsed, never trusted to fit.

const std = @import("std");
const netaddr = @import("netaddr");
const procnet = @import("root.zig");

fn parseU64(tok: []const u8) ?u64 {
    return std.fmt.parseInt(u64, tok, 10) catch null;
}

// ── /proc/net/dev ────────────────────────────────────────────────────────────

/// One interface row of `/proc/net/dev`: the 8 receive and 8 transmit
/// counters in the file's column order (proc(5)). Counters are cumulative
/// since the interface appeared and may wrap (they are kernel `u64`s; a
/// 32-bit driver may still wrap at 2^32) — compute rates from differences.
pub const NetDevEntry = struct {
    name_buf: [procnet.if_name_max]u8 = @splat(0),
    name_len: u8 = 0,
    rx_bytes: u64,
    rx_packets: u64,
    rx_errs: u64,
    rx_drop: u64,
    rx_fifo: u64,
    rx_frame: u64,
    rx_compressed: u64,
    rx_multicast: u64,
    tx_bytes: u64,
    tx_packets: u64,
    tx_errs: u64,
    tx_drop: u64,
    tx_fifo: u64,
    tx_colls: u64,
    tx_carrier: u64,
    tx_compressed: u64,

    pub fn name(e: *const NetDevEntry) []const u8 {
        return e.name_buf[0..e.name_len];
    }
};

/// Parse `/proc/net/dev`: two header lines, then `name: 16 counters`. The
/// name is everything before the row's first `:` (trimmed; it is
/// right-aligned and may touch the colon), so a row is split there, not on
/// blanks. Rows with fewer than 16 counters or a non-numeric one are
/// skipped. Caller owns the slice.
pub fn parseNetDev(gpa: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]NetDevEntry {
    var out: std.ArrayList(NetDevEntry) = .empty;
    errdefer out.deinit(gpa);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue; // headers have none
        const nm = std.mem.trim(u8, line[0..colon], " \t");
        if (nm.len == 0 or nm.len > procnet.if_name_max) continue;
        var vals: [16]u64 = undefined;
        var it = std.mem.tokenizeAny(u8, line[colon + 1 ..], " \t\r");
        var n: usize = 0;
        const ok = while (it.next()) |tok| {
            if (n == vals.len) break true; // extra columns: ignore (future kernels)
            vals[n] = parseU64(tok) orelse break false;
            n += 1;
        } else n == vals.len;
        if (!ok) continue;
        var e: NetDevEntry = .{
            .rx_bytes = vals[0],
            .rx_packets = vals[1],
            .rx_errs = vals[2],
            .rx_drop = vals[3],
            .rx_fifo = vals[4],
            .rx_frame = vals[5],
            .rx_compressed = vals[6],
            .rx_multicast = vals[7],
            .tx_bytes = vals[8],
            .tx_packets = vals[9],
            .tx_errs = vals[10],
            .tx_drop = vals[11],
            .tx_fifo = vals[12],
            .tx_colls = vals[13],
            .tx_carrier = vals[14],
            .tx_compressed = vals[15],
        };
        e.name_len = @intCast(procnet.copyClamped(&e.name_buf, nm));
        try out.append(gpa, e);
    }
    return out.toOwnedSlice(gpa);
}

/// Read + parse the live `/proc/net/dev` (missing file → empty slice).
pub fn readNetDev(gpa: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error![]NetDevEntry {
    const text = procnet.readVirtualFile(gpa, io, "/proc/net/dev", 1 << 20) orelse return &.{};
    defer gpa.free(text);
    return parseNetDev(gpa, text);
}

// ── /proc/stat ───────────────────────────────────────────────────────────────

/// CPU time per state, in USER_HZ ticks (`sysconf(_SC_CLK_TCK)`, 100 on
/// every mainstream architecture), columns as proc(5) lists them. Columns a
/// kernel does not print (fewer on old kernels) read 0. `guest`/`guest_nice`
/// are ALREADY included in `user`/`nice` (proc(5)), so `total` leaves them out.
pub const CpuTimes = struct {
    user: u64 = 0,
    nice: u64 = 0,
    system: u64 = 0,
    idle: u64 = 0,
    iowait: u64 = 0,
    irq: u64 = 0,
    softirq: u64 = 0,
    steal: u64 = 0,
    guest: u64 = 0,
    guest_nice: u64 = 0,

    /// Every tick, counted once (guest time is inside user/nice).
    pub fn total(c: CpuTimes) u64 {
        return c.user +| c.nice +| c.system +| c.idle +| c.iowait +| c.irq +| c.softirq +| c.steal;
    }

    /// Ticks not idle and not waiting for I/O (iowait is idle time with I/O
    /// outstanding — the convention of `top`, `mpstat` and gopsutil's
    /// `Percent`).
    pub fn busy(c: CpuTimes) u64 {
        return c.total() -| c.idle -| c.iowait;
    }

    /// Fraction of time busy between two samples of the same CPU, in [0, 1];
    /// null when no tick elapsed or a counter went backwards (a CPU taken
    /// offline and back resets its row).
    pub fn busyFraction(prev: CpuTimes, cur: CpuTimes) ?f64 {
        if (cur.total() <= prev.total() or cur.busy() < prev.busy()) return null;
        const dt: f64 = @floatFromInt(cur.total() - prev.total());
        const db: f64 = @floatFromInt(cur.busy() - prev.busy());
        return @min(1.0, db / dt);
    }
};

pub const Stat = struct {
    /// The aggregate `cpu` line.
    cpu: CpuTimes = .{},
    /// `cpuN` lines in file order (an offline CPU has no line). Owned.
    cpus: []CpuTimes = &.{},
    /// Context switches since boot.
    ctxt: u64 = 0,
    /// Boot time, seconds since the epoch.
    btime: u64 = 0,
    /// Forks since boot.
    processes: u64 = 0,
    procs_running: u64 = 0,
    procs_blocked: u64 = 0,

    pub fn deinit(s: Stat, gpa: std.mem.Allocator) void {
        gpa.free(s.cpus);
    }
};

fn parseCpuLine(rest: []const u8) ?CpuTimes {
    var c: CpuTimes = .{};
    const fields = [_]*u64{ &c.user, &c.nice, &c.system, &c.idle, &c.iowait, &c.irq, &c.softirq, &c.steal, &c.guest, &c.guest_nice };
    var it = std.mem.tokenizeAny(u8, rest, " \t\r");
    var n: usize = 0;
    while (it.next()) |tok| : (n += 1) {
        if (n == fields.len) break;
        fields[n].* = parseU64(tok) orelse return null;
    }
    // proc(5): user, nice, system and idle are present on every kernel.
    if (n < 4) return null;
    return c;
}

/// Parse `/proc/stat`. A malformed `cpu` row is skipped (and a malformed
/// scalar line leaves its field 0); the other lines (`intr`, `softirq`, …)
/// are not read. Caller frees with `Stat.deinit`.
pub fn parseStat(gpa: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error!Stat {
    var s: Stat = .{};
    var cpus: std.ArrayList(CpuTimes) = .empty;
    errdefer cpus.deinit(gpa);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var it = std.mem.tokenizeAny(u8, line, " \t\r");
        const key = it.next() orelse continue;
        const rest = it.rest();
        if (std.mem.eql(u8, key, "cpu")) {
            if (parseCpuLine(rest)) |c| s.cpu = c;
        } else if (std.mem.startsWith(u8, key, "cpu")) {
            _ = std.fmt.parseInt(u32, key[3..], 10) catch continue;
            if (parseCpuLine(rest)) |c| try cpus.append(gpa, c);
        } else {
            const v = parseU64(it.next() orelse continue) orelse continue;
            if (std.mem.eql(u8, key, "ctxt")) s.ctxt = v else if (std.mem.eql(u8, key, "btime")) s.btime = v else if (std.mem.eql(u8, key, "processes")) s.processes = v else if (std.mem.eql(u8, key, "procs_running")) s.procs_running = v else if (std.mem.eql(u8, key, "procs_blocked")) s.procs_blocked = v;
        }
    }
    s.cpus = try cpus.toOwnedSlice(gpa);
    return s;
}

/// Read + parse the live `/proc/stat` (missing file → all zero).
pub fn readStat(gpa: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error!Stat {
    const text = procnet.readVirtualFile(gpa, io, "/proc/stat", 1 << 20) orelse return .{};
    defer gpa.free(text);
    return parseStat(gpa, text);
}

// ── /proc/meminfo ────────────────────────────────────────────────────────────

/// `/proc/meminfo`, typed: every field in kB as the file prints it, null
/// when this kernel does not print the line (`MemAvailable` appeared in
/// 3.14, the `S*Reclaimable` split in 2.6.19, …) so "absent" and "0" stay
/// distinct. `HugePages_*` counts are pages, not kB.
pub const MemInfo = struct {
    mem_total: ?u64 = null,
    mem_free: ?u64 = null,
    mem_available: ?u64 = null,
    buffers: ?u64 = null,
    cached: ?u64 = null,
    swap_cached: ?u64 = null,
    active: ?u64 = null,
    inactive: ?u64 = null,
    shmem: ?u64 = null,
    slab: ?u64 = null,
    s_reclaimable: ?u64 = null,
    s_unreclaim: ?u64 = null,
    swap_total: ?u64 = null,
    swap_free: ?u64 = null,
    dirty: ?u64 = null,
    writeback: ?u64 = null,
    anon_pages: ?u64 = null,
    mapped: ?u64 = null,
    page_tables: ?u64 = null,
    committed_as: ?u64 = null,
    hugepages_total: ?u64 = null,
    hugepages_free: ?u64 = null,
    hugepage_size: ?u64 = null,

    /// gopsutil's / `free`'s "used": total − available when the kernel
    /// reports MemAvailable, else total − free − buffers − cached (the
    /// pre-3.14 estimate). Null without MemTotal.
    pub fn used(m: MemInfo) ?u64 {
        const t = m.mem_total orelse return null;
        if (m.mem_available) |a| return t -| a;
        return t -| (m.mem_free orelse 0) -| (m.buffers orelse 0) -| (m.cached orelse 0);
    }
};

const meminfo_keys = .{
    .{ "MemTotal", "mem_total" },              .{ "MemFree", "mem_free" },
    .{ "MemAvailable", "mem_available" },      .{ "Buffers", "buffers" },
    .{ "Cached", "cached" },                   .{ "SwapCached", "swap_cached" },
    .{ "Active", "active" },                   .{ "Inactive", "inactive" },
    .{ "Shmem", "shmem" },                     .{ "Slab", "slab" },
    .{ "SReclaimable", "s_reclaimable" },      .{ "SUnreclaim", "s_unreclaim" },
    .{ "SwapTotal", "swap_total" },            .{ "SwapFree", "swap_free" },
    .{ "Dirty", "dirty" },                     .{ "Writeback", "writeback" },
    .{ "AnonPages", "anon_pages" },            .{ "Mapped", "mapped" },
    .{ "PageTables", "page_tables" },          .{ "Committed_AS", "committed_as" },
    .{ "HugePages_Total", "hugepages_total" }, .{ "HugePages_Free", "hugepages_free" },
    .{ "Hugepagesize", "hugepage_size" },
};

/// Parse `/proc/meminfo` (`Key:   value [kB]` per line). The key must match
/// exactly up to its colon — `Active(anon):` is not `Active:`, and
/// `Cached:` is not `SwapCached:` (the substring trap a scan for "Cached:"
/// falls into). A value that does not parse leaves the field null.
pub fn parseMeminfo(text: []const u8) MemInfo {
    var m: MemInfo = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const key = line[0..colon];
        var it = std.mem.tokenizeAny(u8, line[colon + 1 ..], " \t\r");
        const v = parseU64(it.next() orelse continue) orelse continue;
        inline for (meminfo_keys) |kv| {
            if (std.mem.eql(u8, key, kv[0])) @field(m, kv[1]) = v;
        }
    }
    return m;
}

/// Read + parse the live `/proc/meminfo` (missing file → every field null).
pub fn readMeminfo(gpa: std.mem.Allocator, io: std.Io) MemInfo {
    const text = procnet.readVirtualFile(gpa, io, "/proc/meminfo", 64 * 1024) orelse return .{};
    defer gpa.free(text);
    return parseMeminfo(text);
}

// ── /proc/diskstats ──────────────────────────────────────────────────────────

/// Kernel `DISK_NAME_LEN`.
pub const disk_name_max = 32;

/// One `/proc/diskstats` row, fields as `Documentation/admin-guide/iostats.rst`
/// numbers them. Sectors are 512-byte units whatever the device's sector
/// size; times are milliseconds. The discard group (fields 12–15, kernel
/// 4.18+) and flush group (16–17, 5.5+) are null on kernels that do not
/// print them.
pub const DiskStat = struct {
    major: u32,
    minor: u32,
    name_buf: [disk_name_max]u8 = @splat(0),
    name_len: u8 = 0,
    reads_completed: u64,
    reads_merged: u64,
    sectors_read: u64,
    read_ms: u64,
    writes_completed: u64,
    writes_merged: u64,
    sectors_written: u64,
    write_ms: u64,
    ios_in_progress: u64,
    io_ms: u64,
    weighted_io_ms: u64,
    discard: ?struct { completed: u64, merged: u64, sectors: u64, ms: u64 } = null,
    flush: ?struct { completed: u64, ms: u64 } = null,

    pub fn name(d: *const DiskStat) []const u8 {
        return d.name_buf[0..d.name_len];
    }
};

/// Parse `/proc/diskstats`: `major minor name` + 11, 15 or 17 counters. A row
/// with fewer than 11 counters, a non-numeric field, or a name longer than
/// `disk_name_max` is skipped. Caller owns the slice.
pub fn parseDiskstats(gpa: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]DiskStat {
    var out: std.ArrayList(DiskStat) = .empty;
    errdefer out.deinit(gpa);
    var lines = std.mem.splitScalar(u8, text, '\n');
    row: while (lines.next()) |line| {
        var it = std.mem.tokenizeAny(u8, line, " \t\r");
        const major = std.fmt.parseInt(u32, it.next() orelse continue, 10) catch continue;
        const minor = std.fmt.parseInt(u32, it.next() orelse continue, 10) catch continue;
        const nm = it.next() orelse continue;
        if (nm.len > disk_name_max) continue;
        var v: [17]u64 = undefined;
        var n: usize = 0;
        while (it.next()) |tok| {
            if (n == v.len) break;
            v[n] = parseU64(tok) orelse continue :row;
            n += 1;
        }
        if (n < 11) continue;
        var d: DiskStat = .{
            .major = major,
            .minor = minor,
            .reads_completed = v[0],
            .reads_merged = v[1],
            .sectors_read = v[2],
            .read_ms = v[3],
            .writes_completed = v[4],
            .writes_merged = v[5],
            .sectors_written = v[6],
            .write_ms = v[7],
            .ios_in_progress = v[8],
            .io_ms = v[9],
            .weighted_io_ms = v[10],
        };
        if (n >= 15) d.discard = .{ .completed = v[11], .merged = v[12], .sectors = v[13], .ms = v[14] };
        if (n >= 17) d.flush = .{ .completed = v[15], .ms = v[16] };
        d.name_len = @intCast(procnet.copyClamped(&d.name_buf, nm));
        try out.append(gpa, d);
    }
    return out.toOwnedSlice(gpa);
}

/// Read + parse the live `/proc/diskstats` (missing file → empty slice).
pub fn readDiskstats(gpa: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error![]DiskStat {
    const text = procnet.readVirtualFile(gpa, io, "/proc/diskstats", 1 << 20) orelse return &.{};
    defer gpa.free(text);
    return parseDiskstats(gpa, text);
}

// ── /proc/net/ipv6_route ─────────────────────────────────────────────────────

/// One IPv6 route. Unlike `/proc/net/route`, addresses here are printed as
/// 32 hex digits in NETWORK byte order (`%pi6`-style, no host-endian swap),
/// so there is no endianness to get wrong.
pub const Ipv6RouteEntry = struct {
    dest: netaddr.Prefix,
    /// Source-routing prefix (`::/0` for an ordinary route).
    src: netaddr.Prefix,
    /// Null when the next hop is `::` (on-link).
    next_hop: ?netaddr.Ip,
    metric: u32,
    refcnt: u32,
    use: u32,
    /// Raw `RTF_*` flags (`linux/ipv6_route.h`: `0x1` UP, `0x2` GATEWAY,
    /// `0x200` REJECT, `0x00200000` LOCAL, …).
    flags: u32,
    iface_buf: [procnet.if_name_max]u8 = @splat(0),
    iface_len: u8 = 0,

    pub fn iface(e: *const Ipv6RouteEntry) []const u8 {
        return e.iface_buf[0..e.iface_len];
    }
};

fn parseHex128(tok: []const u8) ?[16]u8 {
    if (tok.len != 32) return null;
    var out: [16]u8 = undefined;
    for (&out, 0..) |*b, i| b.* = std.fmt.parseInt(u8, tok[2 * i .. 2 * i + 2], 16) catch return null;
    return out;
}

fn parseHexU32(tok: []const u8) ?u32 {
    if (tok.len != 8) return null;
    for (tok) |c| if (!std.ascii.isHex(c)) return null;
    return std.fmt.parseInt(u32, tok, 16) catch null;
}

fn parsePrefixLen(tok: []const u8) ?u8 {
    if (tok.len != 2) return null;
    for (tok) |c| if (!std.ascii.isHex(c)) return null;
    const v = std.fmt.parseInt(u8, tok, 16) catch return null;
    return if (v <= 128) v else null;
}

/// Parse `/proc/net/ipv6_route` (no header): `dest dest_len src src_len
/// next_hop metric refcnt use flags device`, hex throughout. A row whose
/// fields are not exactly that width, or a prefix length over 128, is
/// skipped. Caller owns the slice.
pub fn parseIpv6Routes(gpa: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]Ipv6RouteEntry {
    var out: std.ArrayList(Ipv6RouteEntry) = .empty;
    errdefer out.deinit(gpa);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var it = std.mem.tokenizeAny(u8, line, " \t\r");
        const dst = parseHex128(it.next() orelse continue) orelse continue;
        const dst_len = parsePrefixLen(it.next() orelse continue) orelse continue;
        const src = parseHex128(it.next() orelse continue) orelse continue;
        const src_len = parsePrefixLen(it.next() orelse continue) orelse continue;
        const nh = parseHex128(it.next() orelse continue) orelse continue;
        const metric = parseHexU32(it.next() orelse continue) orelse continue;
        const refcnt = parseHexU32(it.next() orelse continue) orelse continue;
        const use = parseHexU32(it.next() orelse continue) orelse continue;
        const flags = parseHexU32(it.next() orelse continue) orelse continue;
        const dev = it.next() orelse continue;
        var e: Ipv6RouteEntry = .{
            .dest = .{ .addr = .{ .v6 = dst }, .bits = dst_len },
            .src = .{ .addr = .{ .v6 = src }, .bits = src_len },
            .next_hop = if (std.mem.allEqual(u8, &nh, 0)) null else .{ .v6 = nh },
            .metric = metric,
            .refcnt = refcnt,
            .use = use,
            .flags = flags,
        };
        e.iface_len = @intCast(procnet.copyClamped(&e.iface_buf, dev));
        try out.append(gpa, e);
    }
    return out.toOwnedSlice(gpa);
}

/// Read + parse the live `/proc/net/ipv6_route` (no IPv6 → empty slice).
pub fn readIpv6Routes(gpa: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error![]Ipv6RouteEntry {
    const text = procnet.readVirtualFile(gpa, io, "/proc/net/ipv6_route", 4 << 20) orelse return &.{};
    defer gpa.free(text);
    return parseIpv6Routes(gpa, text);
}

// ── tests ────────────────────────────────────────────────────────────────────
//
// Fixtures are real captures from a 7.0 x86_64 kernel (interface name and
// global IPv6 prefix sanitized). Expected values are read off the fixture
// TEXT by column position as the kernel documentation numbers the columns —
// not taken from what the parser returned.

const testing = std.testing;

fn findDev(es: []const NetDevEntry, nm: []const u8) ?NetDevEntry {
    for (es) |e| if (std.mem.eql(u8, e.name(), nm)) return e;
    return null;
}

test "parseNetDev: real /proc/net/dev" {
    const es = try parseNetDev(testing.allocator, @embedFile("testdata/net_dev.txt"));
    defer testing.allocator.free(es);
    try testing.expectEqual(@as(usize, 7), es.len);
    const lo = findDev(es, "lo").?;
    try testing.expectEqual(@as(u64, 1148794975), lo.rx_bytes);
    try testing.expectEqual(@as(u64, 3450235), lo.rx_packets);
    try testing.expectEqual(lo.rx_bytes, lo.tx_bytes); // loopback: everything sent is received
    const w = findDev(es, "wlp2s0").?;
    try testing.expectEqual(@as(u64, 30493341738), w.rx_bytes); // > 2^32
    try testing.expectEqual(@as(u64, 28619702), w.rx_packets);
    try testing.expectEqual(@as(u64, 5183444852), w.tx_bytes); // column 9
    try testing.expectEqual(@as(u64, 13274106), w.tx_packets);
    try testing.expectEqual(@as(u64, 117), w.tx_drop); // column 12
    const wg = findDev(es, "wg0").?;
    try testing.expectEqual(@as(u64, 8), wg.tx_errs);
    try testing.expectEqual(@as(u64, 1), wg.tx_drop);
    try testing.expectEqual(@as(u64, 93), findDev(es, "virbr0").?.tx_drop);
    const v1 = findDev(es, "vmnet1").?;
    try testing.expectEqual(@as(u64, 97550), v1.rx_packets);
    try testing.expectEqual(@as(u64, 14), v1.rx_drop); // column 4
    try testing.expectEqual(@as(u64, 98382), v1.tx_packets);
    try testing.expectEqual(@as(u64, 0), v1.rx_multicast);
}

test "parseNetDev: every column lands in its own field; malformed rows are skipped" {
    const text =
        \\hdr
        \\hdr
        \\eth9:1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16
        \\  short: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
        \\  bad: 1 2 3 x 5 6 7 8 9 10 11 12 13 14 15 16
        \\abcdefghijklmnopq: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16
        \\ : 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16
        \\  neg: -1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16
        \\  more: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17
        \\
    ;
    const es = try parseNetDev(testing.allocator, text);
    defer testing.allocator.free(es);
    try testing.expectEqual(@as(usize, 2), es.len);
    const e = es[0];
    try testing.expectEqualStrings("eth9", e.name()); // name touching the colon
    const got = [_]u64{ e.rx_bytes, e.rx_packets, e.rx_errs, e.rx_drop, e.rx_fifo, e.rx_frame, e.rx_compressed, e.rx_multicast, e.tx_bytes, e.tx_packets, e.tx_errs, e.tx_drop, e.tx_fifo, e.tx_colls, e.tx_carrier, e.tx_compressed };
    for (got, 1..) |g, want| try testing.expectEqual(@as(u64, want), g);
    try testing.expectEqualStrings("more", es[1].name()); // a 17th column is ignored
    try testing.expectEqual(@as(u64, 16), es[1].tx_compressed);
}

test "parseStat: real /proc/stat" {
    const s = try parseStat(testing.allocator, @embedFile("testdata/stat.txt"));
    defer s.deinit(testing.allocator);
    try testing.expectEqual(CpuTimes{ .user = 16342003, .nice = 18315354, .system = 5535881, .idle = 143213629, .iowait = 1264030, .irq = 0, .softirq = 198898, .steal = 0, .guest = 0, .guest_nice = 0 }, s.cpu);
    try testing.expectEqual(@as(usize, 8), s.cpus.len); // cpu0..cpu7
    try testing.expectEqual(@as(u64, 2069402), s.cpus[0].user);
    try testing.expectEqual(@as(u64, 77992), s.cpus[7].softirq);
    try testing.expectEqual(@as(u64, 3928214925), s.ctxt);
    try testing.expectEqual(@as(u64, 1790873715), s.btime);
    try testing.expectEqual(@as(u64, 1777933), s.processes);
    try testing.expectEqual(@as(u64, 1), s.procs_running);
    try testing.expectEqual(@as(u64, 0), s.procs_blocked);
    // Sum of the first eight columns, by hand: 184869795; minus idle and
    // iowait: 40392136.
    try testing.expectEqual(@as(u64, 184869795), s.cpu.total());
    try testing.expectEqual(@as(u64, 40392136), s.cpu.busy());
}

test "CpuTimes: guest is not counted twice; busyFraction between samples" {
    // proc(5): guest time is already inside user. 10 user incl. 4 guest + 90
    // idle = 100 ticks, not 104.
    const c: CpuTimes = .{ .user = 10, .idle = 90, .guest = 4 };
    try testing.expectEqual(@as(u64, 100), c.total());
    const prev: CpuTimes = .{ .user = 100, .idle = 900 };
    const cur: CpuTimes = .{ .user = 150, .idle = 1100, .iowait = 50 };
    // 300 ticks elapsed, 50 of them busy (iowait counts as idle).
    try testing.expectApproxEqRel(@as(f64, 1.0 / 6.0), CpuTimes.busyFraction(prev, cur).?, 1e-12);
    try testing.expectEqual(@as(?f64, null), CpuTimes.busyFraction(cur, cur)); // no tick
    try testing.expectEqual(@as(?f64, null), CpuTimes.busyFraction(cur, prev)); // backwards
    // busy went backwards while total grew (a CPU's row reset): null.
    try testing.expectEqual(@as(?f64, null), CpuTimes.busyFraction(.{ .user = 100, .idle = 0 }, .{ .user = 50, .idle = 100 }));
    // Saturating: hostile counters near u64 max do not overflow.
    const huge: CpuTimes = .{ .user = std.math.maxInt(u64), .nice = 5 };
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), huge.total());
}

test "parseStat: old four-column cpu lines, malformed lines" {
    const text =
        \\cpu 1 2 3 4
        \\cpu0 1 2 3
        \\cpu1 1 2 3 4 5
        \\cpux 9 9 9 9
        \\cpu2 1 2 x 4
        \\ctxt notanumber
        \\btime 42
        \\
    ;
    const s = try parseStat(testing.allocator, text);
    defer s.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 10), s.cpu.total());
    try testing.expectEqual(@as(u64, 0), s.cpu.iowait);
    try testing.expectEqual(@as(usize, 1), s.cpus.len); // only cpu1 is well-formed
    try testing.expectEqual(@as(u64, 5), s.cpus[0].iowait);
    try testing.expectEqual(@as(u64, 0), s.ctxt);
    try testing.expectEqual(@as(u64, 42), s.btime);
}

test "parseMeminfo: real /proc/meminfo, exact keys" {
    const m = parseMeminfo(@embedFile("testdata/meminfo.txt"));
    try testing.expectEqual(@as(?u64, 32705196), m.mem_total);
    try testing.expectEqual(@as(?u64, 1209236), m.mem_free);
    try testing.expectEqual(@as(?u64, 16081392), m.mem_available);
    try testing.expectEqual(@as(?u64, 2670584), m.buffers);
    try testing.expectEqual(@as(?u64, 7605848), m.cached); // not SwapCached's 34256
    try testing.expectEqual(@as(?u64, 34256), m.swap_cached);
    try testing.expectEqual(@as(?u64, 9162040), m.active); // not Active(anon)
    try testing.expectEqual(@as(?u64, 17007196), m.inactive);
    try testing.expectEqual(@as(?u64, 3268996), m.s_reclaimable);
    try testing.expectEqual(@as(?u64, 653596), m.s_unreclaim);
    try testing.expectEqual(@as(?u64, 38869920), m.committed_as);
    try testing.expectEqual(@as(?u64, 0), m.hugepages_total); // present, and zero
    try testing.expectEqual(@as(?u64, 2048), m.hugepage_size);
    // used = total − available = 32705196 − 16081392.
    try testing.expectEqual(@as(?u64, 16623804), m.used());
}

test "parseMeminfo: absent stays null; used falls back without MemAvailable" {
    const m = parseMeminfo(
        \\MemTotal:       1000 kB
        \\MemFree:         100 kB
        \\Buffers:          50 kB
        \\SwapCached:      999 kB
        \\Cached:          200 kB
        \\Active(anon):      7 kB
        \\Dirty:           bad kB
        \\
    );
    try testing.expectEqual(@as(?u64, null), m.mem_available);
    try testing.expectEqual(@as(?u64, 200), m.cached);
    try testing.expectEqual(@as(?u64, null), m.active);
    try testing.expectEqual(@as(?u64, null), m.dirty);
    try testing.expectEqual(@as(?u64, 650), m.used()); // 1000 − 100 − 50 − 200
    try testing.expectEqual(@as(?u64, null), parseMeminfo("").used());
    // A hostile file cannot underflow `used`.
    try testing.expectEqual(@as(?u64, 0), parseMeminfo("MemTotal: 5 kB\nMemAvailable: 9 kB\n").used());
}

test "parseDiskstats: real /proc/diskstats, 17-field kernel" {
    const ds = try parseDiskstats(testing.allocator, @embedFile("testdata/diskstats.txt"));
    defer testing.allocator.free(ds);
    try testing.expectEqual(@as(usize, 40), ds.len);
    var sda: ?DiskStat = null;
    var nvme: ?DiskStat = null;
    for (ds) |d| {
        if (std.mem.eql(u8, d.name(), "sda")) sda = d;
        if (std.mem.eql(u8, d.name(), "nvme0n1")) nvme = d;
    }
    const s = sda.?;
    try testing.expectEqual(@as(u32, 8), s.major);
    try testing.expectEqual(@as(u32, 0), s.minor);
    try testing.expectEqual(@as(u64, 5443869), s.reads_completed); // field 1
    try testing.expectEqual(@as(u64, 602162), s.reads_merged);
    try testing.expectEqual(@as(u64, 151454106), s.sectors_read);
    try testing.expectEqual(@as(u64, 2099768), s.read_ms);
    try testing.expectEqual(@as(u64, 151233), s.writes_completed); // field 5
    try testing.expectEqual(@as(u64, 1665979), s.writes_merged);
    try testing.expectEqual(@as(u64, 434240776), s.sectors_written);
    try testing.expectEqual(@as(u64, 18519148), s.write_ms);
    try testing.expectEqual(@as(u64, 0), s.ios_in_progress); // field 9
    try testing.expectEqual(@as(u64, 2954616), s.io_ms);
    try testing.expectEqual(@as(u64, 20961037), s.weighted_io_ms); // field 11
    try testing.expectEqual(@as(u64, 0), s.discard.?.completed);
    try testing.expectEqual(@as(u64, 1141), s.flush.?.completed); // field 16
    try testing.expectEqual(@as(u64, 342120), s.flush.?.ms); // field 17
    try testing.expectEqual(@as(u32, 259), nvme.?.major);
    try testing.expectEqual(@as(u64, 680829474), nvme.?.sectors_written);
}

test "parseDiskstats: 11- and 15-field kernels, malformed rows" {
    const text =
        \\   8 0 old 1 2 3 4 5 6 7 8 9 10 11
        \\   8 1 mid 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
        \\   8 2 short 1 2 3 4 5 6 7 8 9 10
        \\   8 3 bad 1 2 3 4 5 6 7 8 9 10 x
        \\   x 4 badmajor 1 2 3 4 5 6 7 8 9 10 11
        \\   8 5 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 2 3 4 5 6 7 8 9 10 11
        \\   8 6
        \\   8 7 fourteen 1 2 3 4 5 6 7 8 9 10 11 12 13 14
        \\
    ;
    const ds = try parseDiskstats(testing.allocator, text);
    defer testing.allocator.free(ds);
    try testing.expectEqual(@as(usize, 3), ds.len);
    try testing.expectEqualStrings("old", ds[0].name());
    // 14 counters is neither documented shape: the partial discard group is
    // not reported (no kernel prints it; a hostile file might).
    try testing.expectEqualStrings("fourteen", ds[2].name());
    try testing.expect(ds[2].discard == null and ds[2].flush == null);
    try testing.expectEqual(@as(u64, 11), ds[0].weighted_io_ms);
    try testing.expect(ds[0].discard == null and ds[0].flush == null);
    try testing.expectEqual(@as(u64, 15), ds[1].discard.?.ms); // fields 12..15 = 12 13 14 15
    try testing.expectEqual(@as(u64, 12), ds[1].discard.?.completed);
    try testing.expect(ds[1].flush == null);
}

test "parseIpv6Routes: real /proc/net/ipv6_route (prefix sanitized)" {
    const rs = try parseIpv6Routes(testing.allocator, @embedFile("testdata/ipv6_route.txt"));
    defer testing.allocator.free(rs);
    try testing.expectEqual(@as(usize, 17), rs.len);
    // Row 2: 2001:db8:0:a1::/64 on-link via wlp2s0, metric 0x258 = 600.
    const r = rs[1];
    try testing.expectEqual(netaddr.Ip{ .v6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0xa1, 0, 0, 0, 0, 0, 0, 0, 0 } }, r.dest.addr);
    try testing.expectEqual(@as(u8, 64), r.dest.bits);
    try testing.expectEqual(@as(u8, 0), r.src.bits);
    try testing.expect(r.next_hop == null);
    try testing.expectEqual(@as(u32, 600), r.metric);
    try testing.expectEqual(@as(u32, 9), r.refcnt);
    try testing.expectEqual(@as(u32, 1), r.flags); // RTF_UP
    try testing.expectEqualStrings("wlp2s0", r.iface());
    // Row 6: the default route ::/0 via fe80::1, flags 0x08000003 (UP|GATEWAY|…).
    const d = rs[5];
    try testing.expectEqual(@as(u8, 0), d.dest.bits);
    try testing.expectEqual(netaddr.Ip{ .v6 = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } }, d.next_hop.?);
    try testing.expectEqual(@as(u32, 0x08000003), d.flags);
    // Row 1: the lo reject route, metric 0xffffffff.
    try testing.expectEqual(@as(u32, 0xffffffff), rs[0].metric);
    try testing.expectEqual(@as(u32, 0x00200200), rs[0].flags);
    // Row 7: ::1/128 on lo.
    try testing.expectEqual(@as(u8, 128), rs[6].dest.bits);
    try testing.expectEqual(@as(u8, 1), rs[6].dest.addr.v6[15]);
    // Multicast ff00::/8.
    try testing.expectEqual(@as(u8, 8), rs[13].dest.bits);
    try testing.expectEqual(@as(u8, 0xff), rs[13].dest.addr.v6[0]);
}

test "parseIpv6Routes: rows not of the exact widths are skipped" {
    const z = "00000000000000000000000000000000";
    const ok = z ++ " 00 " ++ z ++ " 00 " ++ z ++ " 00000001 00000000 00000000 00000001 eth0\n";
    const text = ok ++
        z ++ " 81 " ++ z ++ " 00 " ++ z ++ " 00000001 00000000 00000000 00000001 eth0\n" ++ // prefix 129
        z[0..30] ++ " 00 " ++ z ++ " 00 " ++ z ++ " 00000001 00000000 00000000 00000001 eth0\n" ++ // short addr
        z ++ "00 00 " ++ z ++ " 00 " ++ z ++ " 00000001 00000000 00000000 00000001 eth0\n" ++ // 34-digit addr
        z ++ " 00 " ++ z ++ " 00 " ++ z ++ " 0000001 00000000 00000000 00000001 eth0\n" ++ // 7-digit metric
        z ++ " 00 " ++ z ++ " 00 " ++ z ++ " 0000000g 00000000 00000000 00000001 eth0\n" ++ // not hex
        z ++ " 0g " ++ z ++ " 00 " ++ z ++ " 00000001 00000000 00000000 00000001 eth0\n" ++
        z ++ " 00 " ++ z ++ " 00 " ++ z ++ " 00000001 00000000 00000000 00000001\n" ++ // no device
        z ++ " 00 " ++ z ++ " 80 " ++ z ++ " +0000001 00000000 00000000 00000001 eth0\n";
    const rs = try parseIpv6Routes(testing.allocator, text);
    defer testing.allocator.free(rs);
    try testing.expectEqual(@as(usize, 1), rs.len);
    try testing.expectEqual(@as(u32, 1), rs[0].metric);
}

// ── hostile input: every parser on every damaged sample ─────────────────────

const fuzzsample = @import("fuzzsample.zig");

const counter_samples = [_][]const u8{
    @embedFile("testdata/net_dev.txt"),
    @embedFile("testdata/stat.txt"),
    @embedFile("testdata/meminfo.txt"),
    @embedFile("testdata/diskstats.txt"),
    @embedFile("testdata/ipv6_route.txt"),
};

/// Feed one text to all five parsers — a meminfo text handed to the diskstats
/// parser is as much "not the documented shape" as random bytes are.
fn parseAll(text: []const u8) !usize {
    const a = testing.allocator;
    var rows: usize = 0;
    const nd = try parseNetDev(a, text);
    rows += nd.len;
    a.free(nd);
    const st = try parseStat(a, text);
    rows += st.cpus.len;
    st.deinit(a);
    _ = parseMeminfo(text).used();
    const dk = try parseDiskstats(a, text);
    rows += dk.len;
    a.free(dk);
    const r6 = try parseIpv6Routes(a, text);
    rows += r6.len;
    a.free(r6);
    return rows;
}

const counter_seeds = [_][]const u8{
    fuzzsample.seed(&.{ 0, 1, 0, 0xff, 0xff }), // net/dev, whole
    fuzzsample.seed(&.{ 1, 1, 3, 0xff, 0xff, 0, 10, ':', 0, 40, ' ', 0, 90, '-' }), // stat, 3 damaged octets
    fuzzsample.seed(&.{ 2, 1, 0, 0, 200 }), // meminfo, cut mid-line
    fuzzsample.seed(&.{ 3, 1, 2, 0xff, 0xff, 0, 5, 'x', 1, 0, '\n' }), // diskstats
    fuzzsample.seed(&.{ 4, 1, 1, 0xff, 0xff, 0, 33, 'g' }), // ipv6_route, a non-hex digit
    fuzzsample.seed(&.{ 0, 0, 0, 0, 64 }), // arbitrary bytes
};

test "fuzz: counter parsers never panic, overflow or leak" {
    try std.testing.fuzz({}, fuzzCounters, .{ .corpus = &counter_seeds });
}

fn fuzzCounters(_: void, smith: *std.testing.Smith) !void {
    var script: [512]u8 = undefined;
    const n: usize = smith.slice(&script);
    var buf: [4096]u8 = undefined;
    var choice: fuzzsample.Choice = .{};
    _ = try parseAll(fuzzsample.build(script[0..n], &counter_samples, &buf, &choice));
}

test "driver: 3000 PRNG scripts through every counter parser (deterministic)" {
    // The verdict run (~/.claude/fuzzing.md): a seeded PRNG writes the SCRIPT,
    // so every choice — sample, mode, damage, truncation — is exercised, and a
    // failure reproduces from its iteration number.
    var prng = std.Random.DefaultPrng.init(0x9e3779b97f4a7c15);
    const r = prng.random();
    var rows: usize = 0;
    var mutated: usize = 0;
    for (0..3000) |_| {
        var script: [128]u8 = undefined;
        r.bytes(&script);
        var buf: [4096]u8 = undefined;
        var choice: fuzzsample.Choice = .{};
        const text = fuzzsample.build(&script, &counter_samples, &buf, &choice);
        rows += try parseAll(text);
        mutated += choice.mutations;
    }
    // Reach, not just "it ran": real rows were decoded from damaged samples.
    try testing.expect(rows > 10_000);
    try testing.expect(mutated > 10_000);
}
