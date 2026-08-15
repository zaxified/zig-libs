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
/// `type`). Real hardware commonly has several zones (package, per-core, NVMe,
/// Wi-Fi …) — enumerating is the only way to see all of them.
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

// Gated live smoke test: `readSockets`/`readArp`/`readRoutes`/`readConntrack`
// (mutation guard) -- unlike `snapshot`/`listProcesses` above, NOTHING in the
// test suite ever called these four `readX` convenience wrappers before this
// test existed: not the golden-fixture parser tests (which call `parseX`
// directly on embedded text, never touching `readVirtualFile`), and not any
// other smoke test. A typo'd path (e.g. "/proc/net/xcp") or a dropped table
// in `readSockets`'s four-file loop would have silently returned fewer/zero
// entries and nothing would have noticed. Cross-checking each against an
// independent direct read + parse of the same file(s) catches exactly that,
// rather than merely proving "ran without crashing".
// ⚠ THE ORACLE IS LIVE KERNEL STATE, WHICH MOVES WHILE YOU MEASURE IT. Written
// as a single direct-read-then-wrapper-read pair, this test asserted that two
// samples of /proc taken microseconds apart were equal — true on a quiet
// machine, and false the moment anything opened a socket in between. It failed
// exactly that way on the ReleaseSafe amd64 lane of tag 2026-08-15 with
// "expected 96, found 97": one socket appeared mid-test, in a step that runs
// 211 modules' tests concurrently, many of which open sockets on purpose.
//
// A tolerance window would have been the wrong repair. The mutation this guards
// is a wrong path or a dropped table, which moves the count by a whole table --
// and a window wide enough to absorb the churn is wide enough to absorb that.
//
// ⚠ AND A SANDWICH OF COUNTS IS NOT THE REPAIR EITHER, which is worth writing
// down because it was the first attempt and it looked obviously sufficient:
// read the count, run the wrapper, read the count again, and trust the
// comparison only when the two agree. A count can go UP AND BACK DOWN inside
// that window, so equal endpoints do not mean the table held still. Measured,
// not reasoned: under a loop opening and closing listeners, that version failed
// on the `before == after` branch itself.
//
// What holds far better than size is a statement about CONTENT. An entry the
// oracle reports both before and after the wrapper ran was almost certainly
// there for the whole window, so a wrapper reading the right file must have seen
// it. Entries that appeared or vanished mid-window are excluded from the claim
// rather than counted. This is also a STRONGER wiring oracle than the count ever
// was, since it checks the parsed fields and not merely how many rows came back.
//
// ⚠ "ALMOST CERTAINLY", and that word is doing real work — the entry types are
// not uniquely identifying. `SocketEntry` is {proto, local, port, state} with no
// inode, so a listener can close and a DIFFERENT socket can reuse the port
// before the second read, presenting as the same entry across a window it was
// absent from. Measured: 1 failure in 20 runs under a loop that closes thirty
// listeners at a time and immediately reopens them.
//
// So the last of it is closed by what actually distinguishes the two cases,
// which is not the size of a window but REPEATABILITY. A wrong path or a
// dropped table is deterministic: it misses the same entries on every attempt.
// A recycled port is stochastic. Requiring all of `max_attempts` to fail before
// reporting keeps every mutation red on the first attempt and drives the
// artifact to nothing — both mutations below fail 8 of 8, the churn artifact
// about 1 in 20 once.
//
// ⚠ AN EMPTY INTERSECTION WOULD PASS VACUOUSLY, which is the failure mode this
// whole test exists to prevent, so it is handled explicitly: with a genuinely
// empty table (conntrack unloaded, no ARP neighbours) both sides must agree on
// empty; a non-empty table that never yields a persistent entry is reported as
// an unmeasurable claim, never as a pass.
fn expectWiredTo(
    comptime T: type,
    comptime direct: fn (std.mem.Allocator, std.Io) anyerror![]T,
    comptime wrapper: fn (std.mem.Allocator, std.Io) anyerror![]T,
    io: std.Io,
    what: []const u8,
) !void {
    const gpa = testing.allocator;
    const max_attempts = 8;
    var missed = false;
    var attempt: usize = 0;
    while (attempt < max_attempts) : (attempt += 1) {
        const before = try direct(gpa, io);
        defer gpa.free(before);
        const got = try wrapper(gpa, io);
        defer gpa.free(got);
        const after = try direct(gpa, io);
        defer gpa.free(after);

        if (before.len == 0 and after.len == 0) {
            // The table is absent or empty on both sides of the window. The
            // wrapper must see the same nothing — a wrapper inventing rows from
            // a table the direct read cannot find is as much a wiring bug as
            // one finding none.
            return testing.expectEqual(@as(usize, 0), got.len);
        }

        var persistent: usize = 0;
        missed = false;
        for (before) |e| {
            var survived = false;
            for (after) |f| {
                if (std.meta.eql(e, f)) {
                    survived = true;
                    break;
                }
            }
            if (!survived) continue; // came and went inside the window
            persistent += 1;
            var seen = false;
            for (got) |g| {
                if (std.meta.eql(e, g)) {
                    seen = true;
                    break;
                }
            }
            if (!seen) {
                missed = true;
                break; // this attempt is spent; a real defect repeats
            }
        }
        if (persistent > 0 and !missed) return;
    }
    if (missed) {
        std.debug.print(
            "procnet: {s} missed an entry present throughout its own read, on all {d} attempts\n",
            .{ what, max_attempts },
        );
        return error.WrapperMissedPersistentEntry;
    }
    std.debug.print(
        "procnet: {s} had no entry survive a single one of {d} windows — the wiring claim could not be measured\n",
        .{ what, max_attempts },
    );
    return error.NoPersistentEntryToCheck;
}

test "smoke: readSockets/readArp/readRoutes/readConntrack are wired to the right /proc files" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const P = struct {
        // readSockets combines four tables (tcp/tcp6/udp/udp6); the direct side
        // reads and parses each one independently, so a table dropped from the
        // wrapper's loop shows up as that table's own long-lived listeners
        // going missing.
        //
        // ⚠ `parseTcp` labels every row `.tcp` whatever file it came from, so
        // the direct side would disagree with the wrapper on `proto` for the
        // two udp tables — a difference in the ORACLE, not in the code under
        // test. Compare on the fields both sides derive the same way.
        const Key = struct { local: netaddr.Ip, port: u16, state: SockState };
        fn keys(gpa: std.mem.Allocator, rows: []const SocketEntry) anyerror![]Key {
            const out = try gpa.alloc(Key, rows.len);
            for (rows, out) |r, *k| k.* = .{ .local = r.local, .port = r.port, .state = r.state };
            return out;
        }
        fn directSockets(gpa: std.mem.Allocator, io_: std.Io) anyerror![]Key {
            var acc: std.ArrayList(SocketEntry) = .empty;
            defer acc.deinit(gpa);
            inline for (.{ "/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6" }) |path| {
                if (readVirtualFile(gpa, io_, path, 512 * 1024)) |text| {
                    defer gpa.free(text);
                    const rows = try parseTcp(gpa, text);
                    defer gpa.free(rows);
                    try acc.appendSlice(gpa, rows);
                }
            }
            return keys(gpa, acc.items);
        }
        fn wrapSockets(gpa: std.mem.Allocator, io_: std.Io) anyerror![]Key {
            const socks = try readSockets(gpa, io_);
            defer gpa.free(socks);
            return keys(gpa, socks);
        }

        fn directArp(gpa: std.mem.Allocator, io_: std.Io) anyerror![]ArpEntry {
            const text = readVirtualFile(gpa, io_, "/proc/net/arp", 256 * 1024) orelse
                return gpa.alloc(ArpEntry, 0);
            defer gpa.free(text);
            return parseArp(gpa, text);
        }
        fn wrapArp(gpa: std.mem.Allocator, io_: std.Io) anyerror![]ArpEntry {
            return readArp(gpa, io_);
        }

        fn directRoutes(gpa: std.mem.Allocator, io_: std.Io) anyerror![]RouteEntry {
            const text = readVirtualFile(gpa, io_, "/proc/net/route", 256 * 1024) orelse
                return gpa.alloc(RouteEntry, 0);
            defer gpa.free(text);
            return parseRoutes(gpa, text);
        }
        fn wrapRoutes(gpa: std.mem.Allocator, io_: std.Io) anyerror![]RouteEntry {
            return readRoutes(gpa, io_);
        }

        // The conntrack module may not be loaded, or may need root — both sides
        // then consistently see "file absent", which expectWiredTo handles as
        // "empty on both sides" rather than as a vacuous pass.
        fn directConntrack(gpa: std.mem.Allocator, io_: std.Io) anyerror![]ConntrackFlow {
            const text = readVirtualFile(gpa, io_, "/proc/net/nf_conntrack", 4 * 1024 * 1024) orelse
                return gpa.alloc(ConntrackFlow, 0);
            defer gpa.free(text);
            const parsed = try parseConntrack(gpa, text, 64);
            return parsed.flows;
        }
        fn wrapConntrack(gpa: std.mem.Allocator, io_: std.Io) anyerror![]ConntrackFlow {
            const ct = try readConntrack(gpa, io_, 64);
            return ct.flows;
        }
    };

    try expectWiredTo(P.Key, P.directSockets, P.wrapSockets, io, "readSockets");
    try expectWiredTo(ArpEntry, P.directArp, P.wrapArp, io, "readArp");
    try expectWiredTo(RouteEntry, P.directRoutes, P.wrapRoutes, io, "readRoutes");
    try expectWiredTo(ConntrackFlow, P.directConntrack, P.wrapConntrack, io, "readConntrack");
}
