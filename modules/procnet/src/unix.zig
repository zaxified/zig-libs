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

/// Bounds for `parseUnix`/`readUnix`.
pub const UnixOptions = struct {
    /// The most rows kept. Default 524 288 (1 << 19) rows x 176 B = about 92 MB
    /// live, the same order as `SocketOwnerOptions.max_owners` (1 Mi x 88 B).
    /// A real host stays far below it (the 16 MiB read limit holds ~180 000
    /// honest rows); only forged short rows inside socket names (about 17 B of
    /// text per 176 B entry) can reach it. Rows past the cap are dropped and
    /// `UnixTable.truncated` is set; exactly `max_entries` rows are not
    /// truncated.
    max_entries: usize = 1 << 19,
};

pub const UnixTable = struct {
    entries: []UnixEntry,
    /// `entries` is missing the tail: `readUnix` found the file longer than
    /// `read_limit`, or more than `UnixOptions.max_entries` rows were present.
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

/// ⚠ NOT A TRUST BOUNDARY. The `Path` column is a name a local user chose, and
/// the kernel prints it raw: a pathname socket may contain `\n`, so an
/// unprivileged user can bind `"x\n0000000000000000: 00000002 00000000
/// 00010000 0001 01 12345 /run/forged"` and the rest of that name parses as a
/// further, well-formed row (any inode, any path). The text cannot tell the
/// two apart; where the table feeds a decision about who owns or listens on a
/// socket, ask the kernel through `NETLINK_SOCK_DIAG` instead.
///
/// Parse `/proc/net/unix`. The header decides whether rows carry an `Inode`
/// column (kernels before 2.6 did not; then `inode` is 0). A row that is not
/// the documented shape is skipped. Caller frees the slice.
///
/// ⚠ Memory amplification: forged short rows inside socket names (see above)
/// are about 17 bytes of text but a 176-byte `UnixEntry`, so hostile text can
/// grow ~12× (~185 MB from the 16 MiB `readUnix` read limit). `opts.max_entries`
/// (default 524 288 rows, about 92 MB) bounds the result; the first row past
/// it stops the parse and sets `truncated`. Caller frees with `deinit`.
pub fn parseUnix(gpa: std.mem.Allocator, text: []const u8, opts: UnixOptions) std.mem.Allocator.Error!UnixTable {
    var out: std.ArrayList(UnixEntry) = .empty;
    errdefer out.deinit(gpa);

    var lines = std.mem.splitScalar(u8, text, '\n');
    var has_inode = true;
    var first = true;
    var truncated = false;
    while (lines.next()) |line| {
        if (first) {
            first = false;
            if (std.mem.startsWith(u8, std.mem.trimStart(u8, line, " "), "Num")) {
                has_inode = std.mem.find(u8, line, "Inode") != null;
                continue;
            }
        }
        if (line.len == 0) continue;
        const e = parseRow(line, has_inode) orelse continue;
        if (out.items.len >= opts.max_entries) {
            truncated = true;
            break;
        }
        try out.append(gpa, e);
    }
    return .{ .entries = try out.toOwnedSlice(gpa), .truncated = truncated };
}

/// Read and parse the live `/proc/net/unix` (the caller's network namespace —
/// unix sockets are per network namespace too). Empty when absent. `truncated`
/// is set when the read limit or `opts.max_entries` cut the table.
pub fn readUnix(gpa: std.mem.Allocator, io: std.Io, opts: UnixOptions) std.mem.Allocator.Error!UnixTable {
    const f = procnet.readVirtualLinesReporting(gpa, io, "/proc/net/unix", read_limit) orelse
        return .{ .entries = try gpa.alloc(UnixEntry, 0), .truncated = false };
    defer gpa.free(f.bytes);
    var t = try parseUnix(gpa, f.bytes, opts);
    t.truncated = t.truncated or f.truncated;
    return t;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const builtin = @import("builtin");

const real_unix = @embedFile("testdata/unix.txt");

test "parseUnix: real capture, every column" {
    const tab = try parseUnix(testing.allocator, real_unix, .{});
    defer tab.deinit(testing.allocator);
    try testing.expect(!tab.truncated);
    const rows = tab.entries;

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
    const tab = try parseUnix(testing.allocator, t, .{});
    defer tab.deinit(testing.allocator);
    const rows = tab.entries;
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
    const old_t = try parseUnix(testing.allocator, "Num       RefCount Protocol Flags    Type St Path\nffff: 00000002 00000000 00000000 0001 01 /old/sock\n", .{});
    defer old_t.deinit(testing.allocator);
    const old = old_t.entries;
    try testing.expectEqual(@as(usize, 1), old.len);
    try testing.expectEqual(@as(u64, 0), old[0].inode);
    try testing.expectEqualStrings("/old/sock", old[0].path());

    // No header at all: the first line is a row.
    const nh_t = try parseUnix(testing.allocator, "ffff: 00000002 00000000 00000000 0001 01 9 /x\n", .{});
    defer nh_t.deinit(testing.allocator);
    const nh = nh_t.entries;
    try testing.expectEqual(@as(usize, 1), nh.len);
    try testing.expectEqual(@as(u64, 9), nh[0].inode);

    // Overlong path is clamped, not dropped.
    const long_t = try parseUnix(testing.allocator, "ffff: 00000002 00000000 00000000 0001 01 9 /" ++ strRepeat("p", 300) ++ "\n", .{});
    defer long_t.deinit(testing.allocator);
    const long = long_t.entries;
    try testing.expectEqual(@as(usize, 1), long.len);
    try testing.expectEqual(@as(usize, path_max), long[0].path().len);

    const empty = try parseUnix(testing.allocator, "", .{});
    defer empty.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), empty.entries.len);
}

test "live: readUnix sees a listener this process binds" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // An abstract-namespace listener: no file to clean up.
    var name_buf: [64]u8 = undefined;
    const pid: u32 = @intCast(std.os.linux.getpid());
    const addr_path = std.mem.print(&name_buf, "\x00procnet-unix-test-{d}", .{pid}) catch unreachable;
    const addr = std.Io.net.UnixAddress.init(addr_path) catch return error.SkipZigTest;
    var server = addr.listen(io, .{}) catch return error.SkipZigTest;
    defer server.deinit(io);

    const t = try readUnix(testing.allocator, io, .{});
    defer t.deinit(testing.allocator);
    if (t.entries.len == 0) return error.SkipZigTest; // no /proc/net/unix here
    try testing.expect(!t.truncated);

    var want_buf: [64]u8 = undefined;
    const want = std.mem.print(&want_buf, "@procnet-unix-test-{d}", .{pid}) catch unreachable;
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
    const es_t = try parseUnix(gpa, text, .{});
    defer es_t.deinit(gpa);
    const es = es_t.entries;
    try testing.expectEqual(@as(usize, 1), es.len);
    try testing.expectEqualStrings("/tmp/a b", es[0].path());
    try testing.expectEqual(@as(u64, 77), es[0].inode);
    try testing.expect(!es[0].isListening());
    try testing.expect(!es[0].isAbstract());
}

test "parseUnix: max_entries caps forged short rows; exactly the cap is not truncated, one more is" {
    const gpa = testing.allocator;
    const hdr = "Num       RefCount Protocol Flags    Type St Inode Path\n";
    const row = "0: 00000002 00000000 00000000 0001 01 7\n"; // a short well-formed row
    const n = 50;
    const text = hdr ++ strRepeat(row, n);

    const all = try parseUnix(gpa, text, .{ .max_entries = n });
    defer all.deinit(gpa);
    try testing.expectEqual(@as(usize, n), all.entries.len);
    try testing.expect(!all.truncated);

    const over = try parseUnix(gpa, text, .{ .max_entries = n - 1 });
    defer over.deinit(gpa);
    try testing.expectEqual(@as(usize, n - 1), over.entries.len);
    try testing.expect(over.truncated);

    // The default is far above this text; zero keeps nothing and flags any row.
    const dflt = try parseUnix(gpa, text, .{});
    defer dflt.deinit(gpa);
    try testing.expectEqual(@as(usize, n), dflt.entries.len);
    try testing.expect(!dflt.truncated);
    const none = try parseUnix(gpa, text, .{ .max_entries = 0 });
    defer none.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), none.entries.len);
    try testing.expect(none.truncated);

    // Junk rows past the cap are not rows: they must not set `truncated`.
    const junk = try parseUnix(gpa, text ++ "short row\n\n", .{ .max_entries = n });
    defer junk.deinit(gpa);
    try testing.expect(!junk.truncated);
}

test "readUnix: max_entries cuts the live table and reports it; the default pins the documented bound" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    try testing.expectEqual(@as(usize, 524_288), (UnixOptions{}).max_entries);
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    // A listener of our own guarantees at least one row on a host that has /proc/net/unix.
    var name_buf: [64]u8 = undefined;
    const pid: u32 = @intCast(std.os.linux.getpid());
    const name = std.mem.print(&name_buf, "\x00procnet-unix-cap-{d}", .{pid}) catch unreachable;
    const addr = std.Io.net.UnixAddress.init(name) catch return error.SkipZigTest;
    var server = addr.listen(io, .{}) catch return error.SkipZigTest;
    defer server.deinit(io);
    const full = try readUnix(testing.allocator, io, .{});
    defer full.deinit(testing.allocator);
    if (full.entries.len == 0) return error.SkipZigTest; // no /proc/net/unix here
    const none = try readUnix(testing.allocator, io, .{ .max_entries = 0 });
    defer none.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), none.entries.len);
    try testing.expect(none.truncated);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}
