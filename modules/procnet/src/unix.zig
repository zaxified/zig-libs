// SPDX-License-Identifier: MIT

//! `/proc/net/unix` — the AF_UNIX socket table (`ss -x`, `netstat -x`).
//!
//!     Num       RefCount Protocol Flags    Type St Inode Path
//!     0000000000000000: 00000003 00000000 00000000 0001 03 52466207 /run/user/1000/bus
//!
//! Same split as every table here: `parseUnix` is pure, `readUnix` reads the
//! live file. Rows are fixed-size (the path lives inline, clamped to
//! `path_max`), so one `gpa.free` releases everything.

const std = @import("std");
const procnet = @import("root.zig");

/// The most path bytes an entry keeps. `sun_path` is 108 bytes; an abstract
/// name is printed with a leading `@`; this leaves room for either.
pub const path_max = 128;

/// The most of `/proc/net/unix` `readUnix` reads: 16 MiB (~180 000 sockets).
pub const read_limit: usize = 16 << 20;

pub const UnixEntry = struct {
    /// The `Num` column: the kernel's address of the socket, printed `%pK` —
    /// all zeroes unless `kptr_restrict` allows it. Not a key; use `inode`.
    kernel_ptr: u64,
    ref_count: u32,
    protocol: u32,
    /// `__SO_ACCEPTCON` (`0x10000`) marks a listening socket; see `isListening`.
    flags: u32,
    /// `SOCK_STREAM` 1, `SOCK_DGRAM` 2, `SOCK_SEQPACKET` 5.
    sock_type: u16,
    /// `SS_UNCONNECTED` 1, `SS_CONNECTING` 2, `SS_CONNECTED` 3, `SS_DISCONNECTING` 4.
    state: u8,
    /// 0 when the kernel is too old to print the column.
    inode: u64,
    path_buf: [path_max]u8 = @splat(0),
    path_len: u8 = 0,

    /// The bound path; empty for an unnamed (connected-client / socketpair)
    /// socket. A name starting with `@` is in the abstract namespace. A path
    /// longer than `path_max` is cut.
    pub fn path(e: *const UnixEntry) []const u8 {
        return e.path_buf[0..e.path_len];
    }

    pub fn isListening(e: *const UnixEntry) bool {
        return e.flags & 0x10000 != 0;
    }

    pub fn isAbstract(e: *const UnixEntry) bool {
        return e.path_len > 0 and e.path_buf[0] == '@';
    }

    pub fn typeName(e: *const UnixEntry) []const u8 {
        return switch (e.sock_type) {
            1 => "stream",
            2 => "dgram",
            5 => "seqpacket",
            else => "unknown",
        };
    }

    pub fn stateName(e: *const UnixEntry) []const u8 {
        return switch (e.state) {
            1 => "unconnected",
            2 => "connecting",
            3 => "connected",
            4 => "disconnecting",
            else => "unknown",
        };
    }
};

pub const UnixTable = struct {
    entries: []UnixEntry,
    /// The file was longer than `read_limit`; `entries` is missing the tail.
    truncated: bool,

    pub fn deinit(t: UnixTable, gpa: std.mem.Allocator) void {
        gpa.free(t.entries);
    }
};

fn isSep(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r';
}

/// The next whitespace-delimited token of `rest`, advancing it.
fn nextTok(rest: *[]const u8) ?[]const u8 {
    var i: usize = 0;
    const s = rest.*;
    while (i < s.len and isSep(s[i])) i += 1;
    if (i == s.len) {
        rest.* = s[s.len..];
        return null;
    }
    var j = i;
    while (j < s.len and !isSep(s[j])) j += 1;
    rest.* = s[j..];
    return s[i..j];
}

fn parseRow(line: []const u8, has_inode: bool) ?UnixEntry {
    var rest = line;
    var ptr_tok = nextTok(&rest) orelse return null;
    if (ptr_tok.len > 0 and ptr_tok[ptr_tok.len - 1] == ':') ptr_tok = ptr_tok[0 .. ptr_tok.len - 1];
    const refs = nextTok(&rest) orelse return null;
    const proto = nextTok(&rest) orelse return null;
    const flags = nextTok(&rest) orelse return null;
    const typ = nextTok(&rest) orelse return null;
    const st = nextTok(&rest) orelse return null;
    const inode_tok: []const u8 = if (has_inode) (nextTok(&rest) orelse return null) else "0";

    var e: UnixEntry = .{
        .kernel_ptr = std.fmt.parseInt(u64, ptr_tok, 16) catch return null,
        .ref_count = std.fmt.parseInt(u32, refs, 16) catch return null,
        .protocol = std.fmt.parseInt(u32, proto, 16) catch return null,
        .flags = std.fmt.parseInt(u32, flags, 16) catch return null,
        .sock_type = std.fmt.parseInt(u16, typ, 16) catch return null,
        .state = std.fmt.parseInt(u8, st, 16) catch return null,
        .inode = std.fmt.parseInt(u64, inode_tok, 10) catch return null,
    };
    // The path is the rest of the line, spaces included (a socket may be
    // named `/run/my app/sock`); only the separator before it is skipped.
    var p = rest;
    while (p.len > 0 and isSep(p[0])) p = p[1..];
    p = std.mem.trimEnd(u8, p, "\r");
    e.path_len = @intCast(procnet.copyClamped(&e.path_buf, p));
    return e;
}

/// Parse `/proc/net/unix`. The header decides whether rows carry an `Inode`
/// column (kernels before 2.6 did not; then `inode` is 0). A row that is not
/// the documented shape is skipped. Caller frees the slice.
pub fn parseUnix(gpa: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]UnixEntry {
    var out: std.ArrayList(UnixEntry) = .empty;
    errdefer out.deinit(gpa);

    var lines = std.mem.splitScalar(u8, text, '\n');
    var has_inode = true;
    var first = true;
    while (lines.next()) |line| {
        if (first) {
            first = false;
            if (std.mem.startsWith(u8, std.mem.trimStart(u8, line, " "), "Num")) {
                has_inode = std.mem.indexOf(u8, line, "Inode") != null;
                continue;
            }
        }
        if (line.len == 0) continue;
        const e = parseRow(line, has_inode) orelse continue;
        try out.append(gpa, e);
    }
    return out.toOwnedSlice(gpa);
}

/// Read and parse the live `/proc/net/unix` (the caller's network namespace —
/// unix sockets are per network namespace too). Empty when absent.
pub fn readUnix(gpa: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error!UnixTable {
    const f = procnet.readVirtualFileReporting(gpa, io, "/proc/net/unix", read_limit) orelse
        return .{ .entries = try gpa.alloc(UnixEntry, 0), .truncated = false };
    defer gpa.free(f.bytes);
    return .{ .entries = try parseUnix(gpa, f.bytes), .truncated = f.truncated };
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const builtin = @import("builtin");

const real_unix = @embedFile("testdata/unix.txt");

test "parseUnix: real capture, every column" {
    const rows = try parseUnix(testing.allocator, real_unix);
    defer testing.allocator.free(rows);

    var lines: usize = 0;
    var it = std.mem.splitScalar(u8, real_unix, '\n');
    while (it.next()) |l| {
        if (l.len > 0) lines += 1;
    }
    try testing.expectEqual(lines - 1, rows.len); // every row but the header

    const e = rows[0];
    try testing.expectEqual(@as(u64, 0), e.kernel_ptr);
    try testing.expectEqual(@as(u32, 2), e.ref_count);
    try testing.expectEqual(@as(u32, 0), e.protocol);
    try testing.expectEqual(@as(u32, 0x10000), e.flags);
    try testing.expectEqual(@as(u16, 1), e.sock_type);
    try testing.expectEqual(@as(u8, 1), e.state);
    try testing.expectEqual(@as(u64, 25161), e.inode);
    try testing.expectEqualStrings("/var/run/vmnat.2530", e.path());
    try testing.expect(e.isListening());
    try testing.expect(!e.isAbstract());
    try testing.expectEqualStrings("stream", e.typeName());
    try testing.expectEqualStrings("unconnected", e.stateName());

    const c = rows[1];
    try testing.expect(!c.isListening());
    try testing.expectEqual(@as(u32, 3), c.ref_count);
    try testing.expectEqual(@as(u8, 3), c.state);
    try testing.expectEqual(@as(u64, 52466207), c.inode);
    try testing.expectEqualStrings("connected", c.stateName());

    // Unnamed rows exist and have no path; dgram rows exist.
    var unnamed: usize = 0;
    var dgram: usize = 0;
    for (rows) |r| {
        if (r.path().len == 0) unnamed += 1;
        if (r.sock_type == 2) dgram += 1;
    }
    try testing.expect(unnamed >= 4);
    try testing.expect(dgram >= 2);
}

test "parseUnix: abstract names, spaces in paths, seqpacket, old kernels, junk" {
    const t =
        "Num       RefCount Protocol Flags    Type St Inode Path\n" ++
        "ffff8881: 00000002 00000000 00010000 0001 01 777 @/tmp/.X11-unix/X0\n" ++
        "ffff8882: 00000003 00000000 00000000 0005 04 778 /run/my app/sock x\n" ++
        "ffff8883: 00000002 00000000 00000000 0002 01 779\r\n" ++
        "0000000000000000: 00000001 00000000 00000000 0009 07 780 /p\n" ++ // unknown type/state
        "short row\n" ++
        "zz: 00000002 00000000 00000000 0001 01 1 /bad-ptr\n" ++
        "ffff8884: 00000002 00000000 00000000 0001 01 notnum /bad-inode\n" ++
        "ffff8885: 00000002 00000000 00000000 0001 01\n" ++ // inode column missing in a has-inode table
        "ffff8886: 100000000 00000000 00000000 0001 01 5 /refs-overflow-u32\n" ++
        "\n";
    const rows = try parseUnix(testing.allocator, t);
    defer testing.allocator.free(rows);
    try testing.expectEqual(@as(usize, 4), rows.len);
    try testing.expectEqual(@as(u64, 0xffff8881), rows[0].kernel_ptr);
    try testing.expect(rows[0].isAbstract());
    try testing.expect(rows[0].isListening());
    try testing.expectEqualStrings("@/tmp/.X11-unix/X0", rows[0].path());
    try testing.expectEqualStrings("/run/my app/sock x", rows[1].path());
    try testing.expectEqualStrings("seqpacket", rows[1].typeName());
    try testing.expectEqualStrings("disconnecting", rows[1].stateName());
    try testing.expectEqualStrings("", rows[2].path());
    try testing.expectEqualStrings("dgram", rows[2].typeName());
    try testing.expectEqualStrings("unknown", rows[3].typeName());
    try testing.expectEqualStrings("unknown", rows[3].stateName());

    // A header without Inode: rows have no inode column and the path starts one token earlier.
    const old = try parseUnix(testing.allocator, "Num       RefCount Protocol Flags    Type St Path\nffff: 00000002 00000000 00000000 0001 01 /old/sock\n");
    defer testing.allocator.free(old);
    try testing.expectEqual(@as(usize, 1), old.len);
    try testing.expectEqual(@as(u64, 0), old[0].inode);
    try testing.expectEqualStrings("/old/sock", old[0].path());

    // No header at all: the first line is a row.
    const nh = try parseUnix(testing.allocator, "ffff: 00000002 00000000 00000000 0001 01 9 /x\n");
    defer testing.allocator.free(nh);
    try testing.expectEqual(@as(usize, 1), nh.len);
    try testing.expectEqual(@as(u64, 9), nh[0].inode);

    // Overlong path is clamped, not dropped.
    const long = try parseUnix(testing.allocator, "ffff: 00000002 00000000 00000000 0001 01 9 /" ++ strRepeat("p", 300) ++ "\n");
    defer testing.allocator.free(long);
    try testing.expectEqual(@as(usize, 1), long.len);
    try testing.expectEqual(@as(usize, path_max), long[0].path().len);

    const empty = try parseUnix(testing.allocator, "");
    defer testing.allocator.free(empty);
    try testing.expectEqual(@as(usize, 0), empty.len);
}

test "live: readUnix sees a listener this process binds" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // An abstract-namespace listener: no file to clean up.
    var name_buf: [64]u8 = undefined;
    const pid: u32 = @intCast(std.os.linux.getpid());
    const addr_path = std.fmt.bufPrint(&name_buf, "\x00procnet-unix-test-{d}", .{pid}) catch unreachable;
    const addr = std.Io.net.UnixAddress.init(addr_path) catch return error.SkipZigTest;
    var server = addr.listen(io, .{}) catch return error.SkipZigTest;
    defer server.deinit(io);

    const t = try readUnix(testing.allocator, io);
    defer t.deinit(testing.allocator);
    if (t.entries.len == 0) return error.SkipZigTest; // no /proc/net/unix here
    try testing.expect(!t.truncated);

    var want_buf: [64]u8 = undefined;
    const want = std.fmt.bufPrint(&want_buf, "@procnet-unix-test-{d}", .{pid}) catch unreachable;
    var found = false;
    for (t.entries) |e| {
        // std's bind appends a NUL to the name, which the kernel prints as a
        // trailing `@` — so match the prefix.
        if (std.mem.startsWith(u8, e.path(), want)) {
            found = true;
            try testing.expect(e.isListening());
            try testing.expect(e.isAbstract());
            try testing.expectEqualStrings("stream", e.typeName());
            try testing.expect(e.inode != 0);
        }
    }
    try testing.expect(found);
}

test "parseUnix: tabs and CRLF separate columns; 0x20000 is not the listening bit" {
    const gpa = testing.allocator;
    const text = "Num       RefCount Protocol Flags    Type St Inode Path\r\n" ++
        "0000000000000000:\t00000002\t00000000\t00020000\t0001\t01\t77\t/tmp/a b\r\n";
    const es = try parseUnix(gpa, text);
    defer gpa.free(es);
    try testing.expectEqual(@as(usize, 1), es.len);
    try testing.expectEqualStrings("/tmp/a b", es[0].path());
    try testing.expectEqual(@as(u64, 77), es[0].inode);
    try testing.expect(!es[0].isListening());
    try testing.expect(!es[0].isAbstract());
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    const rep_result = comptime blk: {
        @setEvalBranchQuota(n * (s.len + 4) + 1000);
        var buf: [s.len * n:0]u8 = undefined;
        for (0..n) |i| @memcpy(buf[i * s.len ..][0..s.len], s);
        const rep_final = buf;
        break :blk rep_final;
    };
    return &rep_result;
}
