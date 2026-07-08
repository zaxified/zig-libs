// SPDX-License-Identifier: MIT

//! procnet — Linux `/proc` + `/sys` parsers (arp/route/tcp/udp/conntrack,
//! meminfo, loadavg, per-process stat, system snapshot) returning typed
//! values (`netaddr.Ip`/`Prefix`, not allocated dotted-string IPs).
//!
//! Layout mirrors the `dns`/`http` modules: this file owns the shared file
//! -reading primitive (`readVirtualFile`) and the system `snapshot`; each
//! `/proc/net/*` table gets its own pure, offline-testable parser file
//! (`arp.zig`, `routes.zig`, `sockets.zig`, `conntrack.zig`, `process.zig`).
//!
//! Every parser is split `parseX(gpa, text) → []Entry` (pure, golden-text
//! tested, never touches I/O) plus a thin `readX(gpa, io) → []Entry`
//! convenience that reads the live file and calls the pure parser. A missing
//! or unreadable file yields an empty result, not an error — these tables
//! are legitimately absent (module not loaded, feature disabled, no
//! permission) often enough that "no data" beats "hard failure".
//!
//! Result types use fixed inline buffers for their (kernel-bounded) strings
//! — device/interface names (`IFNAMSIZ` = 16), process names
//! (`TASK_COMM_LEN` = 16) — so a whole result slice frees with one
//! `gpa.free(slice)`, no arena required (same shape as the `netlink`
//! module's typed results).
//!
//! ```zig
//! var threaded = std.Io.Threaded.init(gpa, .{});
//! defer threaded.deinit();
//! const io = threaded.io();
//!
//! const neighbors = try procnet.readArp(gpa, io);
//! defer gpa.free(neighbors);
//! for (neighbors) |n| _ = .{ n.ip, n.mac, n.device() };
//!
//! var snap = try procnet.snapshot(gpa, io);
//! defer snap.deinit(gpa);
//! ```

const std = @import("std");
const builtin = @import("builtin");
const netaddr = @import("netaddr");

pub const meta = .{
    .status = .extract, // seed: axp-core/src/task.zig /proc parsers
    .platform = .linux,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "gopsutil (Go) / procps-ng",
    .deps = .{"netaddr"},
};

/// The kernel's `IFNAMSIZ` (`linux/if.h`) — every Linux interface name,
/// including the NUL, fits in this many bytes. Shared by `arp.zig` and
/// `routes.zig` for their inline device/iface buffers.
pub const if_name_max = 16;

/// The kernel's `TASK_COMM_LEN` (`linux/sched.h`) — `/proc/<pid>/stat`'s
/// `comm` field (including NUL) never exceeds this. Shared with `process.zig`.
pub const comm_max = 16;

pub const arp = @import("arp.zig");
pub const routes = @import("routes.zig");
pub const sockets = @import("sockets.zig");
pub const conntrack = @import("conntrack.zig");
pub const process = @import("process.zig");

// Flattened re-exports — the primary type + functions of each submodule, so
// `procnet.parseArp(...)` works without reaching through the namespace.
pub const ArpEntry = arp.ArpEntry;
pub const parseArp = arp.parseArp;
pub const readArp = arp.readArp;

pub const RouteEntry = routes.RouteEntry;
pub const parseRoutes = routes.parseRoutes;
pub const readRoutes = routes.readRoutes;

pub const Proto = sockets.Proto;
pub const SockState = sockets.SockState;
pub const SocketEntry = sockets.SocketEntry;
pub const parseTcp = sockets.parseTcp;
pub const parseUdp = sockets.parseUdp;
pub const readSockets = sockets.readSockets;

pub const ConntrackFlow = conntrack.ConntrackFlow;
pub const ConntrackResult = conntrack.ConntrackResult;
pub const parseConntrack = conntrack.parseConntrack;
pub const readConntrack = conntrack.readConntrack;

pub const ProcessEntry = process.ProcessEntry;
pub const parseProcStat = process.parseProcStat;
pub const listProcesses = process.listProcesses;

// ── virtual-file reading ────────────────────────────────────────────────────

/// Read a `/proc` or `/sys` file (or any regular file up to `limit` bytes),
/// or null if it cannot be opened / read. Uses a *streaming* reader: `/proc`
/// and `/sys` files report size 0 from `stat` (they are generated on read,
/// not backed by disk blocks), so the default positional whole-file read
/// would come back empty — streaming to EOF is the only correct way to read
/// them. Caller owns the returned slice (`gpa.free`).
pub fn readVirtualFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8, limit: usize) ?[]u8 {
    var file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return null;
    defer file.close(io);
    var buf: [4096]u8 = undefined;
    var fr = std.Io.File.Reader.initStreaming(file, io, &buf);
    return fr.interface.allocRemaining(gpa, .limited(limit)) catch null;
}

/// Copy as much of `s` as fits into `buf`, truncating rather than failing —
/// every caller here copies a kernel-bounded string (interface/process name)
/// into a buffer already sized to the kernel's own limit, so truncation is a
/// defensive belt-and-braces measure, not the expected path. Returns the
/// copied length.
pub fn copyClamped(buf: []u8, s: []const u8) u8 {
    const n = @min(s.len, buf.len);
    @memcpy(buf[0..n], s[0..n]);
    return @intCast(n);
}

/// The first whitespace-separated token of `text` parsed as a float, or 0.
fn firstFloat(text: []const u8) f64 {
    var it = std.mem.tokenizeAny(u8, text, " \t\n");
    const tok = it.next() orelse return 0;
    return std.fmt.parseFloat(f64, tok) catch 0;
}

/// The kB value following `key` (e.g. "MemTotal:") in `/proc/meminfo`, or 0.
fn meminfoKb(text: []const u8, key: []const u8) u64 {
    const idx = std.mem.indexOf(u8, text, key) orelse return 0;
    var it = std.mem.tokenizeAny(u8, text[idx + key.len ..], " \t");
    const tok = it.next() orelse return 0;
    return std.fmt.parseInt(u64, tok, 10) catch 0;
}

// ── system snapshot ─────────────────────────────────────────────────────────

/// One `/sys/class/thermal/thermal_zone*` reading.
pub const ThermalZone = struct {
    zone_buf: [24]u8 = @splat(0), // "thermal_zoneNN"
    zone_len: u8 = 0,
    kind_buf: [32]u8 = @splat(0), // the zone's "type" file (e.g. "x86_pkg_temp")
    kind_len: u8 = 0,
    temp_c: f64,

    /// The zone's directory name (e.g. "thermal_zone0").
    pub fn zone(z: *const ThermalZone) []const u8 {
        return z.zone_buf[0..z.zone_len];
    }

    /// The zone's `type` (e.g. "x86_pkg_temp", "acpitz"); empty if unread.
    pub fn kind(z: *const ThermalZone) []const u8 {
        return z.kind_buf[0..z.kind_len];
    }
};

/// `nf_conntrack_count`/`nf_conntrack_max` from `/proc/sys/net/netfilter`.
pub const Conntrack = struct { count: u64, max: u64 };

/// A device health snapshot — the richest single read in this module: load,
/// memory, thermal and conntrack pressure in one shot. All fields come from
/// `/proc` + `/sys` reads (no privilege needed), so it also runs on a plain
/// dev box for testing. Optional fields are null when the kernel does not
/// expose them (e.g. no thermal zone, conntrack module not loaded).
///
/// Deliberately excludes per-interface link state: that is `netlink.Socket
/// .links`'s job now (a real rtnetlink dump beats `/sys/class/net/*
/// /operstate` scraping) — don't duplicate it here.
pub const Snapshot = struct {
    uptime_s: u64,
    load: [3]f64, // 1/5/15-minute load average
    mem_total_kb: u64,
    mem_free_kb: u64,
    mem_available_kb: u64,
    /// The hottest reading across every discovered thermal zone; null if
    /// none were found.
    thermal_c: ?f64,
    /// Every zone found under `/sys/class/thermal`. Owned; free via `deinit`.
    thermal_zones: []const ThermalZone,
    conntrack: ?Conntrack,

    pub fn deinit(s: Snapshot, gpa: std.mem.Allocator) void {
        gpa.free(s.thermal_zones);
    }
};

/// Read a device health record from `/proc` + `/sys`. Never fails except on
/// allocation failure — every individual source is best-effort (a missing
/// file just leaves its field at a zero/null default).
pub fn snapshot(gpa: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error!Snapshot {
    const uptime_s: u64 = blk: {
        const t = readVirtualFile(gpa, io, "/proc/uptime", 256) orelse break :blk 0;
        defer gpa.free(t);
        break :blk @intFromFloat(firstFloat(t));
    };

    var load = [3]f64{ 0, 0, 0 };
    if (readVirtualFile(gpa, io, "/proc/loadavg", 256)) |t| {
        defer gpa.free(t);
        var it = std.mem.tokenizeAny(u8, t, " \t\n");
        inline for (0..3) |i| {
            if (it.next()) |tok| load[i] = std.fmt.parseFloat(f64, tok) catch 0;
        }
    }

    var mem_total: u64 = 0;
    var mem_free: u64 = 0;
    var mem_avail: u64 = 0;
    if (readVirtualFile(gpa, io, "/proc/meminfo", 16 * 1024)) |mi| {
        defer gpa.free(mi);
        mem_total = meminfoKb(mi, "MemTotal:");
        mem_free = meminfoKb(mi, "MemFree:");
        mem_avail = meminfoKb(mi, "MemAvailable:");
    }

    const zones = try readThermalZones(gpa, io);
    errdefer gpa.free(zones);
    var thermal_c: ?f64 = null;
    for (zones) |z| {
        if (thermal_c == null or z.temp_c > thermal_c.?) thermal_c = z.temp_c;
    }

    var conn: ?Conntrack = null;
    if (readVirtualFile(gpa, io, "/proc/sys/net/netfilter/nf_conntrack_count", 64)) |c| {
        defer gpa.free(c);
        const count = std.fmt.parseInt(u64, std.mem.trim(u8, c, " \t\r\n"), 10) catch 0;
        var max: u64 = 0;
        if (readVirtualFile(gpa, io, "/proc/sys/net/netfilter/nf_conntrack_max", 64)) |m| {
            defer gpa.free(m);
            max = std.fmt.parseInt(u64, std.mem.trim(u8, m, " \t\r\n"), 10) catch 0;
        }
        conn = .{ .count = count, .max = max };
    }

    return .{
        .uptime_s = uptime_s,
        .load = load,
        .mem_total_kb = mem_total,
        .mem_free_kb = mem_free,
        .mem_available_kb = mem_avail,
        .thermal_c = thermal_c,
        .thermal_zones = zones,
        .conntrack = conn,
    };
}

/// Enumerate every `/sys/class/thermal/thermal_zone*` and read its `temp` (+
/// `type`). The seed hardcoded `thermal_zone0`; real hardware commonly has
/// several (package, per-core, NVMe, Wi-Fi …) — enumerating is the only way
/// to see all of them.
fn readThermalZones(gpa: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error![]ThermalZone {
    var out: std.ArrayList(ThermalZone) = .empty;
    errdefer out.deinit(gpa);

    var dir = std.Io.Dir.cwd().openDir(io, "/sys/class/thermal", .{ .iterate = true }) catch
        return out.toOwnedSlice(gpa);
    defer dir.close(io);

    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        if (!std.mem.startsWith(u8, entry.name, "thermal_zone")) continue;

        var tpb: [80]u8 = undefined;
        const temp_path = std.fmt.bufPrint(&tpb, "/sys/class/thermal/{s}/temp", .{entry.name}) catch continue;
        const temp_text = readVirtualFile(gpa, io, temp_path, 64) orelse continue;
        defer gpa.free(temp_text);
        const milli = std.fmt.parseInt(i64, std.mem.trim(u8, temp_text, " \t\r\n"), 10) catch continue;

        var z: ThermalZone = .{ .temp_c = @as(f64, @floatFromInt(milli)) / 1000.0 };
        z.zone_len = copyClamped(&z.zone_buf, entry.name);

        var kpb: [80]u8 = undefined;
        if (std.fmt.bufPrint(&kpb, "/sys/class/thermal/{s}/type", .{entry.name}) catch null) |kind_path| {
            if (readVirtualFile(gpa, io, kind_path, 64)) |kind_text| {
                defer gpa.free(kind_text);
                z.kind_len = copyClamped(&z.kind_buf, std.mem.trim(u8, kind_text, " \t\r\n"));
            }
        }

        try out.append(gpa, z);
    }
    return out.toOwnedSlice(gpa);
}

// ── dark-tests aggregator ────────────────────────────────────────────────────
// Each submodule's `test` blocks only run if referenced from here (or from
// another file `zig build test-procnet` compiles) — see CONVENTIONS.md.

test {
    _ = arp;
    _ = routes;
    _ = sockets;
    _ = conntrack;
    _ = process;
}

const testing = std.testing;

test "meminfoKb / firstFloat" {
    try testing.expectEqual(@as(f64, 12345.67), firstFloat("12345.67 98765.43\n"));
    try testing.expectEqual(@as(f64, 0), firstFloat(""));
    const mi = "MemTotal:       16330328 kB\nMemFree:         1234567 kB\n";
    try testing.expectEqual(@as(u64, 16330328), meminfoKb(mi, "MemTotal:"));
    try testing.expectEqual(@as(u64, 1234567), meminfoKb(mi, "MemFree:"));
    try testing.expectEqual(@as(u64, 0), meminfoKb(mi, "MemAvailable:"));
}

test "copyClamped truncates instead of overflowing" {
    var buf: [4]u8 = undefined;
    const n = copyClamped(&buf, "hello");
    try testing.expectEqual(@as(u8, 4), n);
    try testing.expectEqualStrings("hell", buf[0..n]);
}

// Gated live smoke test: exercises the real `/proc` + `/sys` tree end to end.
// No root required (RTM_GET*-equivalent reads are all world-readable); skips
// cleanly off Linux.
test "smoke: snapshot() and listProcesses() run against the real /proc" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var snap = try snapshot(testing.allocator, io);
    defer snap.deinit(testing.allocator);
    // The real assertion is "this ran to completion without erroring or
    // panicking against a live kernel"; uptime > 0 confirms /proc/uptime
    // was actually read (not silently defaulted).
    try testing.expect(snap.uptime_s > 0);

    const procs = try listProcesses(testing.allocator, io, 64);
    defer testing.allocator.free(procs);
    try testing.expect(procs.len > 0); // at least this test process itself
}
