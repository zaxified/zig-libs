// SPDX-License-Identifier: MIT
//! The two `SIOCETHTOOL` calls that have no netlink message: `drvinfo()`
//! (`ETHTOOL_GDRVINFO`, what `ethtool -i` prints) and `driverStats()`
//! (`ETHTOOL_GSSET_INFO` + `ETHTOOL_GSTRINGS` + `ETHTOOL_GSTATS`, what plain
//! `ethtool -S` prints).
//!
//! This is a deliberate, bounded exception to the module's netlink-only design
//! (SPEC.md, "Decided 2026-09-30"): the kernel offers no netlink equivalent
//! for either call and keeps these ioctls as stable uAPI. **No other ioctl
//! command belongs here.** Pure `std.os.linux` syscalls — a throw-away
//! `AF_INET`/`SOCK_DGRAM` socket carries the ioctl — no libc.
//!
//! Both calls are unprivileged reads.
//!
//! ## The stats count can change under you
//!
//! The counter count is asked for first (`GSSET_INFO`), then names
//! (`GSTRINGS`) and values (`GSTATS`) are fetched with separate calls, and a
//! driver reconfiguration (queue count change) can alter the count in between.
//! The kernel sizes its copy-out by ITS current count, not by the size of the
//! buffer offered, so the scratch buffers are always allocated for the maximum
//! (`max_stats`), never for the count just read; a grown count therefore cannot
//! overrun them. The three counts must agree; on a mismatch the whole sequence
//! is retried once, and a second mismatch is `error.StatsChanged`. More than
//! `max_stats` counters is `error.TooManyStats`.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

/// Longest interface name the kernel takes (`IFNAMSIZ` 16, minus the NUL).
pub const max_name_len = 15;
/// Upper bound on the driver counters `driverStats` will accept.
pub const max_stats: u32 = 65536;
/// Width of one name field in the `GSTRINGS` reply (`ETH_GSTRING_LEN`).
pub const gstring_len = 32;

const SIOCETHTOOL: u32 = 0x8946;
const ETHTOOL_GDRVINFO: u32 = 0x03;
const ETHTOOL_GSTRINGS: u32 = 0x1b;
const ETHTOOL_GSTATS: u32 = 0x1d;
const ETHTOOL_GSSET_INFO: u32 = 0x37;
const ETH_SS_STATS: u32 = 1;

/// `struct ethtool_drvinfo` as the kernel lays it out.
pub const RawDrvinfo = extern struct {
    cmd: u32,
    driver: [32]u8,
    version: [32]u8,
    fw_version: [32]u8,
    bus_info: [32]u8,
    erom_version: [32]u8,
    reserved2: [12]u8,
    n_priv_flags: u32,
    n_stats: u32,
    testinfo_len: u32,
    eedump_len: u32,
    regdump_len: u32,
};

const SsetInfo = extern struct {
    cmd: u32,
    reserved: u32,
    sset_mask: u64,
    data: [1]u32,
};

/// `struct ifreq`: the name and the pointer member of the union, padded to the
/// union's full size.
const Ifreq = extern struct {
    name: [16]u8,
    data: usize,
    pad: [40 - 16 - @sizeOf(usize)]u8 = @splat(0),
};

comptime {
    std.debug.assert(@sizeOf(RawDrvinfo) == 196);
    std.debug.assert(@offsetOf(RawDrvinfo, "n_priv_flags") == 176);
    std.debug.assert(@sizeOf(SsetInfo) == 24);
    std.debug.assert(@offsetOf(SsetInfo, "data") == 16);
    std.debug.assert(@sizeOf(Ifreq) == 40);
    std.debug.assert(builtin.os.tag != .linux or @sizeOf(usize) == 8);
}

pub const Error = error{
    /// The name is empty, longer than 15 bytes, or holds NUL, '/', ':' or
    /// whitespace. Reported before any syscall.
    InvalidInterfaceName,
    /// No such interface (`ENODEV`).
    NoSuchDevice,
    /// The driver does not implement the operation (`EOPNOTSUPP`).
    NotSupported,
    /// `EPERM` / `EACCES`.
    PermissionDenied,
    /// `EINVAL`: the kernel rejected the request.
    InvalidRequest,
    /// Out of memory or descriptors in the kernel.
    SystemResources,
    /// Any errno not listed above.
    Unexpected,
};

pub const StatsError = Error || error{
    OutOfMemory,
    /// The driver reports more than `max_stats` counters.
    TooManyStats,
    /// The counter count kept changing between the calls (retried once).
    StatsChanged,
    /// The kernel's reply is malformed: unterminated name, wrong echoed
    /// command or length.
    BadReply,
};

/// `ethtool -i` fields. The text accessors slice into the value, so the value
/// must outlive (and not move under) the slices.
pub const DriverInfo = struct {
    raw: RawDrvinfo,

    pub fn driver(d: *const DriverInfo) []const u8 {
        return trim(&d.raw.driver);
    }
    pub fn version(d: *const DriverInfo) []const u8 {
        return trim(&d.raw.version);
    }
    pub fn firmwareVersion(d: *const DriverInfo) []const u8 {
        return trim(&d.raw.fw_version);
    }
    pub fn busInfo(d: *const DriverInfo) []const u8 {
        return trim(&d.raw.bus_info);
    }
    pub fn eromVersion(d: *const DriverInfo) []const u8 {
        return trim(&d.raw.erom_version);
    }
    pub fn statsCount(d: DriverInfo) u32 {
        return d.raw.n_stats;
    }
    pub fn privFlagsCount(d: DriverInfo) u32 {
        return d.raw.n_priv_flags;
    }
    pub fn testCount(d: DriverInfo) u32 {
        return d.raw.testinfo_len;
    }
    pub fn eepromSize(d: DriverInfo) u32 {
        return d.raw.eedump_len;
    }
    pub fn regdumpSize(d: DriverInfo) u32 {
        return d.raw.regdump_len;
    }

    /// Decode a raw 196-byte reply image (native byte order).
    pub fn fromBytes(bytes: *const [@sizeOf(RawDrvinfo)]u8) DriverInfo {
        return .{ .raw = std.mem.bytesToValue(RawDrvinfo, bytes) };
    }
};

fn trim(field: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, field, 0) orelse field.len;
    return field[0..end];
}

/// The driver's private counters: parallel arrays of names and values.
pub const DriverStats = struct {
    /// `count * gstring_len` bytes, each name NUL-padded.
    name_bytes: []u8 = &.{},
    values: []u64 = &.{},

    pub fn count(s: DriverStats) usize {
        return s.values.len;
    }

    pub fn name(s: DriverStats, index: usize) []const u8 {
        return trim(s.name_bytes[index * gstring_len ..][0..gstring_len]);
    }

    pub fn value(s: DriverStats, index: usize) u64 {
        return s.values[index];
    }

    pub fn find(s: DriverStats, wanted: []const u8) ?u64 {
        for (0..s.values.len) |i| {
            if (std.mem.eql(u8, s.name(i), wanted)) return s.values[i];
        }
        return null;
    }

    pub fn deinit(s: *DriverStats, gpa: std.mem.Allocator) void {
        gpa.free(s.name_bytes);
        gpa.free(s.values);
        s.* = .{};
    }
};

/// Check an interface name before it reaches the kernel.
pub fn validateName(name: []const u8) error{InvalidInterfaceName}!void {
    if (name.len == 0 or name.len > max_name_len) return error.InvalidInterfaceName;
    for (name) |c| switch (c) {
        0, '/', ':', ' ', '\t', '\n', '\r', 0x0b, 0x0c => return error.InvalidInterfaceName,
        else => {},
    };
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.InvalidInterfaceName;
}

fn mapErrno(e: linux.E) Error {
    return switch (e) {
        .NODEV => error.NoSuchDevice,
        .OPNOTSUPP, .AFNOSUPPORT => error.NotSupported,
        .PERM, .ACCES => error.PermissionDenied,
        .INVAL => error.InvalidRequest,
        .NOMEM, .NOBUFS, .MFILE, .NFILE => error.SystemResources,
        else => error.Unexpected,
    };
}

/// Issue one `SIOCETHTOOL` with `data` (whose first u32 is the command).
fn ethtoolIoctl(name: []const u8, data: [*]u8) Error!void {
    try validateName(name);
    var req: Ifreq = .{ .name = @splat(0), .data = @intFromPtr(data) };
    @memcpy(req.name[0..name.len], name);

    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |e| return mapErrno(e),
    }
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);

    while (true) {
        switch (linux.errno(linux.ioctl(fd, SIOCETHTOOL, @intFromPtr(&req)))) {
            .SUCCESS => return,
            .INTR => continue,
            else => |e| return mapErrno(e),
        }
    }
}

/// `ETHTOOL_GDRVINFO` for `ifname`.
pub fn drvinfo(ifname: []const u8) Error!DriverInfo {
    var raw = std.mem.zeroes(RawDrvinfo);
    raw.cmd = ETHTOOL_GDRVINFO;
    try ethtoolIoctl(ifname, @ptrCast(&raw));
    return .{ .raw = raw };
}

/// The driver's private counters (`ethtool -S`). The caller owns the result.
pub fn driverStats(gpa: std.mem.Allocator, ifname: []const u8) StatsError!DriverStats {
    try validateName(ifname);
    var attempt: u2 = 0;
    while (true) : (attempt += 1) {
        const n = try statsCount(ifname);
        if (n > max_stats) return error.TooManyStats;
        if (n == 0) return .{};
        if (fetchStats(gpa, ifname, n)) |s| return s else |e| switch (e) {
            error.StatsChanged => if (attempt >= 1) return e,
            else => return e,
        }
    }
}

/// `GSSET_INFO` for `ETH_SS_STATS`: the number of counters.
fn statsCount(ifname: []const u8) Error!u32 {
    var info = std.mem.zeroes(SsetInfo);
    info.cmd = ETHTOOL_GSSET_INFO;
    info.sset_mask = @as(u64, 1) << ETH_SS_STATS;
    try ethtoolIoctl(ifname, @ptrCast(&info));
    // The mask is rewritten to the sets the driver supports; a cleared bit
    // means no entry follows.
    if (info.sset_mask & (@as(u64, 1) << ETH_SS_STATS) == 0) return error.NotSupported;
    return info.data[0];
}

fn fetchStats(gpa: std.mem.Allocator, ifname: []const u8, n: u32) StatsError!DriverStats {
    // Sized for the maximum, not for `n`: see the module doc.
    const str_buf = try gpa.alignedAlloc(u8, .of(u32), strings_header + @as(usize, max_stats) * gstring_len);
    defer gpa.free(str_buf);
    const val_buf = try gpa.alignedAlloc(u8, .of(u64), stats_header + @as(usize, max_stats) * 8);
    defer gpa.free(val_buf);
    @memset(str_buf[0..strings_header], 0);
    @memset(val_buf[0..stats_header], 0);

    std.mem.writeInt(u32, str_buf[0..4], ETHTOOL_GSTRINGS, builtin.cpu.arch.endian());
    std.mem.writeInt(u32, str_buf[4..8], ETH_SS_STATS, builtin.cpu.arch.endian());
    try ethtoolIoctl(ifname, str_buf.ptr);
    std.mem.writeInt(u32, val_buf[0..4], ETHTOOL_GSTATS, builtin.cpu.arch.endian());
    try ethtoolIoctl(ifname, val_buf.ptr);

    return assembleStats(gpa, n, str_buf, val_buf);
}

const strings_header = 12;
const stats_header = 8;

/// Turn the two kernel replies (header included) into a `DriverStats`,
/// checking every count against `n`. Pure; the tests drive it with hand-built
/// images. `error.StatsChanged` = counts disagree; `error.BadReply` = the
/// image is malformed.
pub fn assembleStats(
    gpa: std.mem.Allocator,
    n: u32,
    strings_reply: []const u8,
    stats_reply: []const u8,
) StatsError!DriverStats {
    const endian = builtin.cpu.arch.endian();
    if (strings_reply.len < strings_header or stats_reply.len < stats_header) return error.BadReply;
    if (std.mem.readInt(u32, strings_reply[0..4], endian) != ETHTOOL_GSTRINGS) return error.BadReply;
    if (std.mem.readInt(u32, strings_reply[4..8], endian) != ETH_SS_STATS) return error.BadReply;
    if (std.mem.readInt(u32, stats_reply[0..4], endian) != ETHTOOL_GSTATS) return error.BadReply;
    const str_len = std.mem.readInt(u32, strings_reply[8..12], endian);
    const val_len = std.mem.readInt(u32, stats_reply[4..8], endian);
    if (str_len != n or val_len != n) return error.StatsChanged;
    if (n > max_stats) return error.TooManyStats;
    const names_end = strings_header + @as(usize, n) * gstring_len;
    const vals_end = stats_header + @as(usize, n) * 8;
    if (strings_reply.len < names_end or stats_reply.len < vals_end) return error.BadReply;

    const names_src = strings_reply[strings_header..names_end];
    var i: usize = 0;
    while (i < n) : (i += 1) {
        // Every name field must hold a NUL; an unterminated one was cut off.
        if (std.mem.indexOfScalar(u8, names_src[i * gstring_len ..][0..gstring_len], 0) == null)
            return error.BadReply;
    }

    const names = try gpa.dupe(u8, names_src);
    errdefer gpa.free(names);
    const values = try gpa.alloc(u64, n);
    errdefer gpa.free(values);
    for (values, 0..) |*v, k| {
        v.* = std.mem.readInt(u64, stats_reply[stats_header + k * 8 ..][0..8], endian);
    }
    return .{ .name_bytes = names, .values = values };
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;
const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;

fn skip(comptime what: []const u8) error{SkipZigTest} {
    if (verboseSkip()) std.debug.print("SKIPPED: {s}\n", .{what});
    return error.SkipZigTest;
}

fn putStr(dst: []u8, s: []const u8) void {
    @memcpy(dst[0..s.len], s);
}

test "drvinfo image decodes field by field" {
    var img = std.mem.zeroes([196]u8);
    const e = builtin.cpu.arch.endian();
    std.mem.writeInt(u32, img[0..4], ETHTOOL_GDRVINFO, e);
    putStr(img[4..36], "e1000e");
    putStr(img[36..68], "7.0.0-test");
    putStr(img[68..100], "0.1-3");
    putStr(img[100..132], "0000:00:1f.6");
    std.mem.writeInt(u32, img[176..180], 7, e);
    std.mem.writeInt(u32, img[180..184], 60, e);
    std.mem.writeInt(u32, img[184..188], 5, e);
    std.mem.writeInt(u32, img[188..192], 4096, e);
    std.mem.writeInt(u32, img[192..196], 1024, e);

    const d = DriverInfo.fromBytes(&img);
    try testing.expectEqualStrings("e1000e", d.driver());
    try testing.expectEqualStrings("7.0.0-test", d.version());
    try testing.expectEqualStrings("0.1-3", d.firmwareVersion());
    try testing.expectEqualStrings("0000:00:1f.6", d.busInfo());
    try testing.expectEqualStrings("", d.eromVersion());
    try testing.expectEqual(@as(u32, 7), d.privFlagsCount());
    try testing.expectEqual(@as(u32, 60), d.statsCount());
    try testing.expectEqual(@as(u32, 5), d.testCount());
    try testing.expectEqual(@as(u32, 4096), d.eepromSize());
    try testing.expectEqual(@as(u32, 1024), d.regdumpSize());
}

test "a full-width drvinfo field (no NUL) is returned whole" {
    var img = std.mem.zeroes([196]u8);
    @memset(img[4..36], 'x');
    const d = DriverInfo.fromBytes(&img);
    try testing.expectEqual(@as(usize, 32), d.driver().len);
}

test "assembleStats decodes hand-built GSTRINGS and GSTATS replies" {
    const e = builtin.cpu.arch.endian();
    var s = std.mem.zeroes([strings_header + 3 * gstring_len]u8);
    std.mem.writeInt(u32, s[0..4], ETHTOOL_GSTRINGS, e);
    std.mem.writeInt(u32, s[4..8], ETH_SS_STATS, e);
    std.mem.writeInt(u32, s[8..12], 3, e);
    putStr(s[12..], "rx_packets");
    putStr(s[12 + 32 ..], "tx_packets");
    putStr(s[12 + 64 ..], "rx_bytes");
    var v = std.mem.zeroes([stats_header + 3 * 8]u8);
    std.mem.writeInt(u32, v[0..4], ETHTOOL_GSTATS, e);
    std.mem.writeInt(u32, v[4..8], 3, e);
    std.mem.writeInt(u64, v[8..16], 11, e);
    std.mem.writeInt(u64, v[16..24], 22, e);
    std.mem.writeInt(u64, v[24..32], 0xFFFF_FFFF_FFFF_FFFF, e);

    var st = try assembleStats(testing.allocator, 3, &s, &v);
    defer st.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 3), st.count());
    try testing.expectEqualStrings("rx_packets", st.name(0));
    try testing.expectEqualStrings("tx_packets", st.name(1));
    try testing.expectEqualStrings("rx_bytes", st.name(2));
    try testing.expectEqual(@as(u64, 22), st.value(1));
    try testing.expectEqual(@as(?u64, 0xFFFF_FFFF_FFFF_FFFF), st.find("rx_bytes"));
    try testing.expectEqual(@as(?u64, null), st.find("nope"));
}

test "assembleStats rejects mismatched counts and malformed replies" {
    const e = builtin.cpu.arch.endian();
    var s = std.mem.zeroes([strings_header + 2 * gstring_len]u8);
    std.mem.writeInt(u32, s[0..4], ETHTOOL_GSTRINGS, e);
    std.mem.writeInt(u32, s[4..8], ETH_SS_STATS, e);
    std.mem.writeInt(u32, s[8..12], 2, e);
    putStr(s[12..], "a");
    putStr(s[12 + 32 ..], "b");
    var v = std.mem.zeroes([stats_header + 2 * 8]u8);
    std.mem.writeInt(u32, v[0..4], ETHTOOL_GSTATS, e);
    std.mem.writeInt(u32, v[4..8], 2, e);

    // Count asked for differs from what came back.
    try testing.expectError(error.StatsChanged, assembleStats(testing.allocator, 3, &s, &v));
    // Values reply count differs.
    std.mem.writeInt(u32, v[4..8], 1, e);
    try testing.expectError(error.StatsChanged, assembleStats(testing.allocator, 2, &s, &v));
    std.mem.writeInt(u32, v[4..8], 2, e);
    // Wrong echoed command.
    std.mem.writeInt(u32, v[0..4], 0, e);
    try testing.expectError(error.BadReply, assembleStats(testing.allocator, 2, &s, &v));
    std.mem.writeInt(u32, v[0..4], ETHTOOL_GSTATS, e);
    // Truncated image.
    try testing.expectError(error.BadReply, assembleStats(testing.allocator, 2, s[0..40], &v));
    try testing.expectError(error.BadReply, assembleStats(testing.allocator, 2, &s, v[0..12]));
    // Unterminated name.
    @memset(s[12..44], 'z');
    try testing.expectError(error.BadReply, assembleStats(testing.allocator, 2, &s, &v));
    // Beyond the bound.
    std.mem.writeInt(u32, s[8..12], max_stats + 1, e);
    std.mem.writeInt(u32, v[4..8], max_stats + 1, e);
    try testing.expectError(error.TooManyStats, assembleStats(testing.allocator, max_stats + 1, &s, &v));
}

test "validateName" {
    try validateName("eth0");
    try validateName("123456789012345");
    try testing.expectError(error.InvalidInterfaceName, validateName(""));
    try testing.expectError(error.InvalidInterfaceName, validateName("1234567890123456"));
    try testing.expectError(error.InvalidInterfaceName, validateName("a/b"));
    try testing.expectError(error.InvalidInterfaceName, validateName("a\x00b"));
    try testing.expectError(error.InvalidInterfaceName, validateName("a b"));
    try testing.expectError(error.InvalidInterfaceName, validateName("a:b"));
    try testing.expectError(error.InvalidInterfaceName, validateName(".."));
}

test "invalid names fail before any syscall; unknown device is NoSuchDevice" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    try testing.expectError(error.InvalidInterfaceName, drvinfo("this-name-is-far-too-long"));
    try testing.expectError(error.InvalidInterfaceName, driverStats(testing.allocator, ""));
    try testing.expectError(error.NoSuchDevice, drvinfo("nosuch0"));
    try testing.expectError(error.NoSuchDevice, driverStats(testing.allocator, "nosuch0"));
}

// ── live comparison against the `ethtool` binary ──────────────────────────

fn runEthtool(gpa: std.mem.Allocator, args: []const []const u8, ifname: []const u8) ![]u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.append(gpa, "ethtool");
    try argv.appendSlice(gpa, args);
    try argv.append(gpa, ifname);
    const res = std.process.run(gpa, testing.io, .{ .argv = argv.items }) catch
        return skip("no `ethtool` binary to compare against");
    defer gpa.free(res.stderr);
    errdefer gpa.free(res.stdout);
    switch (res.term) {
        .exited => |c| if (c != 0) return skip("`ethtool` failed on this interface"),
        else => return skip("`ethtool` did not exit normally"),
    }
    return res.stdout;
}

/// Value of `key: value` in `ethtool -i` output ("" when the value is empty).
fn infoField(text: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (line.len > key.len and std.mem.startsWith(u8, line, key) and line[key.len] == ':') {
            return std.mem.trim(u8, line[key.len + 1 ..], " ");
        }
    }
    return null;
}

const Parsed = struct {
    names: std.ArrayList([]const u8) = .empty,
    values: std.ArrayList(u64) = .empty,

    fn deinit(p: *Parsed, gpa: std.mem.Allocator) void {
        p.names.deinit(gpa);
        p.values.deinit(gpa);
    }
};

/// Parse `ethtool -S` output; the slices point into `text`.
fn parseStats(gpa: std.mem.Allocator, text: []const u8) !Parsed {
    var p: Parsed = .{};
    errdefer p.deinit(gpa);
    var it = std.mem.splitScalar(u8, text, '\n');
    _ = it.next(); // "NIC statistics:"
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.lastIndexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " ");
        const v = std.fmt.parseInt(u64, std.mem.trim(u8, line[colon + 1 ..], " "), 10) catch continue;
        try p.names.append(gpa, name);
        try p.values.append(gpa, v);
    }
    return p;
}

fn candidateInterface(gpa: std.mem.Allocator, out: *std.ArrayList([]u8)) !void {
    var dir = std.Io.Dir.openDirAbsolute(testing.io, "/sys/class/net", .{ .iterate = true }) catch return;
    defer dir.close(testing.io);
    var it = dir.iterate();
    while (it.next(testing.io) catch null) |ent| {
        if (std.mem.eql(u8, ent.name, "lo")) continue;
        try out.append(gpa, try gpa.dupe(u8, ent.name));
    }
}

test "LIVE drvinfo and driverStats agree with ethtool -i / -S" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;

    var cands: std.ArrayList([]u8) = .empty;
    defer {
        for (cands.items) |c| gpa.free(c);
        cands.deinit(gpa);
    }
    try candidateInterface(gpa, &cands);
    if (cands.items.len == 0) return skip("no non-loopback interface");

    var did_info = false;
    var did_stats = false;
    for (cands.items) |ifname| {
        if (ifname.len > max_name_len) continue;

        // ── -i ──
        info: {
            const d = drvinfo(ifname) catch |e| switch (e) {
                error.NotSupported, error.PermissionDenied => break :info,
                else => return e,
            };
            const text = runEthtool(gpa, &.{"-i"}, ifname) catch |e| switch (e) {
                error.SkipZigTest => break :info,
                else => return e,
            };
            defer gpa.free(text);
            try testing.expectEqualStrings(infoField(text, "driver").?, d.driver());
            try testing.expectEqualStrings(infoField(text, "version").?, d.version());
            try testing.expectEqualStrings(infoField(text, "firmware-version").?, d.firmwareVersion());
            try testing.expectEqualStrings(infoField(text, "bus-info").?, d.busInfo());
            try testing.expectEqualStrings(infoField(text, "expansion-rom-version").?, d.eromVersion());
            did_info = true;
        }

        // ── -S ──
        stats: {
            const before_text = runEthtool(gpa, &.{"-S"}, ifname) catch |e| switch (e) {
                error.SkipZigTest => break :stats,
                else => return e,
            };
            defer gpa.free(before_text);
            var st = driverStats(gpa, ifname) catch |e| switch (e) {
                error.NotSupported, error.PermissionDenied => break :stats,
                else => return e,
            };
            defer st.deinit(gpa);
            const after_text = try runEthtool(gpa, &.{"-S"}, ifname);
            defer gpa.free(after_text);

            var before = try parseStats(gpa, before_text);
            defer before.deinit(gpa);
            var after = try parseStats(gpa, after_text);
            defer after.deinit(gpa);

            try testing.expectEqual(before.names.items.len, st.count());
            try testing.expectEqual(after.names.items.len, st.count());
            for (0..st.count()) |i| {
                try testing.expectEqualStrings(before.names.items[i], st.name(i));
                try testing.expectEqualStrings(after.names.items[i], st.name(i));
                // Only pure traffic counters are monotone; gauges may move
                // either way.
                const nm = st.name(i);
                if (std.mem.endsWith(u8, nm, "_packets") or std.mem.endsWith(u8, nm, "_bytes")) {
                    try testing.expect(st.value(i) >= before.values.items[i]);
                    try testing.expect(st.value(i) <= after.values.items[i]);
                }
            }
            did_stats = true;
        }
        if (did_info and did_stats) break;
    }
    if (!did_info and !did_stats) return skip("no interface answers SIOCETHTOOL drvinfo/stats");
}
