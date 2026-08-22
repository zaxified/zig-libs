// SPDX-License-Identifier: MIT

//! `/proc/<pid>/stat` — the per-process accounting line: name, scheduling
//! state, parent pid and resident memory, for every running process — plus
//! the `/proc/<pid>/fd` scan that joins a socket inode back to the processes
//! holding it (`indexSocketOwners`), which is how `ss -p` and `lsof -i`
//! answer "who owns this port".

const std = @import("std");
const builtin = @import("builtin");
const procnet = @import("root.zig");

/// One process's `stat` snapshot.
pub const ProcessEntry = struct {
    pid: u32,
    /// `man proc(5)` single-letter state code: `R` running, `S` sleeping,
    /// `D` uninterruptible sleep, `Z` zombie, `T` stopped, `I` idle, ...
    state: u8,
    ppid: u32,
    rss_kb: u64,
    name_buf: [procnet.comm_max]u8 = @splat(0),
    name_len: u8 = 0,

    /// The process name as `/proc/<pid>/stat` renders it — truncated to
    /// `procnet.comm_max` (64) bytes if the kernel's own render is longer
    /// still (e.g. an adversarial `comm` set via `prctl(PR_SET_NAME)`-then
    /// -argv-rewrite games). This is never necessarily the full argv0 of a
    /// long command line — `comm` itself is a separate, shorter kernel
    /// field — but for `PF_WQ_WORKER` kernel threads it does include the
    /// full workqueue-suffixed name (`kworker/0:0H-kblockd`), which the
    /// old 16-byte bound used to cut off.
    pub fn name(e: *const ProcessEntry) []const u8 {
        return e.name_buf[0..e.name_len];
    }
};

/// Parse one `/proc/<pid>/stat` line. Format: `<pid> (<comm>) <state> <ppid>
/// <pgrp> ... <rss>`. `comm` sits between the *first* `(` and the *last*
/// `)` — the kernel does not escape parens or spaces the process put in its
/// own name (`(sd-pam)`, `(my (weird) name)`), so scanning from the outside
/// in is the only robust split. The space-separated fields after `comm` are
/// 0-indexed from `state`; `rss` (in pages, converted to kB) is field 24 of
/// the `proc(5)` table, i.e. token index 21 counting from `state` = 0.
/// Returns null if the line has no balanced `(...)` or too few fields.
pub fn parseProcStat(line: []const u8) ?ProcessEntry {
    const lp = std.mem.indexOfScalar(u8, line, '(') orelse return null;
    const rp = std.mem.lastIndexOfScalar(u8, line, ')') orelse return null;
    if (rp <= lp) return null;

    const pid_s = std.mem.trim(u8, line[0..lp], " \t\n");
    const pid = std.fmt.parseInt(u32, pid_s, 10) catch return null;
    const name = line[lp + 1 .. rp];

    var f = std.mem.tokenizeAny(u8, line[rp + 1 ..], " \t\n");
    const state_s = f.next() orelse return null; // field 3
    if (state_s.len == 0) return null;
    const ppid_s = f.next() orelse return null; // field 4

    var i: usize = 2;
    var rss_s: []const u8 = "0";
    while (i <= 21) : (i += 1) {
        const t = f.next() orelse break;
        if (i == 21) rss_s = t; // field 24: resident set size, in pages
    }

    var e: ProcessEntry = .{
        .pid = pid,
        .state = state_s[0],
        .ppid = std.fmt.parseInt(u32, ppid_s, 10) catch 0,
        // Saturating multiply: a crafted/corrupt `rss` field near
        // maxInt(u64) must not panic (checked `*` overflows) or wrap
        // (ReleaseFast UB) — it saturates to maxInt(u64) instead, matching
        // this parser's "malformed input degrades gracefully" contract.
        .rss_kb = (std.fmt.parseInt(u64, rss_s, 10) catch 0) *| 4, // 4 KB pages
    };
    e.name_len = procnet.copyClamped(&e.name_buf, name);
    return e;
}

/// Enumerate up to `max` processes from the live `/proc` tree. Each PID's
/// `stat` is read independently, so a process that exits mid-scan (a race
/// inherent to `/proc`) is simply absent from the result, not an error.
/// Caller owns the returned slice (`gpa.free`).
pub fn listProcesses(gpa: std.mem.Allocator, io: std.Io, max: usize) std.mem.Allocator.Error![]ProcessEntry {
    var out: std.ArrayList(ProcessEntry) = .empty;
    errdefer out.deinit(gpa);

    var dir = std.Io.Dir.cwd().openDir(io, "/proc", .{ .iterate = true }) catch
        return out.toOwnedSlice(gpa);
    defer dir.close(io);

    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        if (out.items.len >= max) break;
        _ = std.fmt.parseInt(u32, entry.name, 10) catch continue; // numeric dirs = pids

        var pb: [64]u8 = undefined;
        const path = std.fmt.bufPrint(&pb, "/proc/{s}/stat", .{entry.name}) catch continue;
        const text = procnet.readVirtualFile(gpa, io, path, 4096) orelse continue;
        defer gpa.free(text);
        const pe = parseProcStat(text) orelse continue;
        try out.append(gpa, pe);
    }
    return out.toOwnedSlice(gpa);
}

// ── socket inode → process join ──────────────────────────────────────────────

/// One process's hold on a socket: which pid, under which descriptor, and
/// the process name as `/proc/<pid>/stat` renders it.
///
/// One inode can have several of these. A socket survives `fork(2)` and can
/// be passed over a unix socket with `SCM_RIGHTS`, so "the" owner is not a
/// function — `ss -p` prints the whole set (`users:(("nginx",pid=2,fd=6),
/// ("nginx",pid=3,fd=6))`) and so does `SocketOwnerIndex.findAll`.
pub const SocketOwner = struct {
    inode: u64,
    pid: u32,
    /// The descriptor number under `/proc/<pid>/fd` that points at the
    /// socket — `ss -p`'s `fd=N`.
    fd: u32,
    name_buf: [procnet.comm_max]u8 = @splat(0),
    name_len: u8 = 0,

    /// The owning process's name, same rendering as `ProcessEntry.name`.
    pub fn name(o: *const SocketOwner) []const u8 {
        return o.name_buf[0..o.name_len];
    }
};

/// Tuning for `indexSocketOwners`. Both bounds exist because the scan's cost
/// is the product of two numbers a caller does not control; see that
/// function's cost note.
pub const SocketOwnerOptions = struct {
    /// Stop after this many processes have been scanned.
    max_processes: usize = 4096,
    /// Stop scanning one process's descriptors after this many. A process
    /// with a million open descriptors is a real (if rare) thing, and it
    /// must not be able to stall a listing on its own.
    max_fds_per_process: usize = 8192,
};

/// The result of one `/proc/<pid>/fd` sweep: every socket-holding descriptor
/// found, plus an honest account of what the sweep could not see.
///
/// ⚠ `owners` is a PARTIAL view by design, not by failure. `/proc/<pid>/fd`
/// is `0500` and owned by the process's uid, so an unprivileged scan reads
/// its own processes and is refused every other user's — which is exactly
/// what `ss -p` does too: verified live, it leaves the process column blank
/// for sockets the calling uid does not own, in a plain non-root run, and
/// prints no error. `denied` counts those refusals so a caller can say "17
/// processes were not visible to this uid" rather than implying the machine
/// had no other owners.
pub const SocketOwnerIndex = struct {
    /// Sorted ascending by `inode`, so `findAll` is a binary search and the
    /// several owners of one inode are contiguous.
    owners: []SocketOwner,
    /// Processes whose descriptor directory was opened and read.
    scanned: u32,
    /// Processes whose `/proc/<pid>/fd` was refused — another user's, or
    /// one this uid otherwise cannot look into. The sockets they hold are
    /// absent from `owners`.
    denied: u32,
    /// Processes that disappeared mid-scan (`/proc` races by construction:
    /// a pid can exit between the directory listing and the open). Not an
    /// error, and distinct from `denied` because it says nothing about
    /// privilege.
    vanished: u32,
    /// True if `max_processes` or some `max_fds_per_process` cut the sweep
    /// short, so a caller never mistakes a capped view for a complete one.
    truncated: bool,

    pub fn deinit(idx: SocketOwnerIndex, gpa: std.mem.Allocator) void {
        gpa.free(idx.owners);
    }

    /// Every process found holding the socket with this inode. Empty if none
    /// was found — which means either nothing holds it (an orphaned or
    /// `TIME_WAIT` socket, whose `/proc/net/*` inode column is `0`) or its
    /// holder was not visible to this uid (`denied`). Those two are not
    /// distinguishable from the result alone; that is the honest state of
    /// the world, and `denied` is what a caller reports alongside.
    ///
    /// Inode `0` never matches: the kernel prints it for a socket that has
    /// no inode at all, so it is a value many rows share rather than a key.
    pub fn findAll(idx: SocketOwnerIndex, inode: u64) []const SocketOwner {
        if (inode == 0) return &.{};
        var lo: usize = 0;
        var hi: usize = idx.owners.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (idx.owners[mid].inode < inode) lo = mid + 1 else hi = mid;
        }
        var end = lo;
        while (end < idx.owners.len and idx.owners[end].inode == inode) end += 1;
        return idx.owners[lo..end];
    }

    /// The first owner of `inode`, or null. Sugar over `findAll` for the
    /// common single-holder case; a caller rendering an `ss -p`-style column
    /// wants `findAll`.
    pub fn find(idx: SocketOwnerIndex, inode: u64) ?SocketOwner {
        const all = idx.findAll(inode);
        return if (all.len == 0) null else all[0];
    }
};

/// Decode a `/proc/<pid>/fd/<n>` symlink target into the socket inode it
/// names, or null if the descriptor is not a socket. The kernel renders a
/// socket descriptor as exactly `socket:[<decimal inode>]` (`fs/`'s
/// `sockfs_dname`); every other descriptor is a path, a pipe (`pipe:[N]`),
/// an anon inode (`anon_inode:[eventfd]`) and so on, and must not match —
/// a pipe and a socket can carry the SAME inode number in different inode
/// namespaces, so matching loosely on `:[N]` would invent owners.
pub fn parseSocketInode(link_target: []const u8) ?u64 {
    const prefix = "socket:[";
    if (!std.mem.startsWith(u8, link_target, prefix)) return null;
    if (!std.mem.endsWith(u8, link_target, "]")) return null;
    const digits = link_target[prefix.len .. link_target.len - 1];
    if (digits.len == 0) return null;
    return std.fmt.parseInt(u64, digits, 10) catch null;
}

/// Build the socket-inode → process index that `SocketEntry.inode` joins
/// against: walk `/proc/<pid>/fd/*` and record every descriptor whose
/// symlink target is `socket:[<inode>]`.
///
/// **This is deliberately opt-in — `readSockets` does not call it, and there
/// is no combined convenience wrapper.** Two reasons, and the first is cost:
/// the sweep is one `openat` + one `readlinkat` per open descriptor of every
/// visible process, i.e. O(processes × descriptors), where both factors are
/// the machine's business and not the caller's. It is the most expensive
/// call in this module by a wide margin — measured on an ordinary desktop
/// (390 processes, 157 of them readable by the calling uid, ~6 900
/// descriptors): 45 ms, repeatably, against well under a millisecond for a
/// `readSockets` of all four tables. A monitoring loop sampling sockets every
/// second has no business paying that unless it wants the owner column, and
/// on a machine with more processes it grows with both factors at once. The
/// second reason is that the result is honestly partial (see
/// `SocketOwnerIndex`), so folding it into `SocketEntry` would put a field on
/// every row that is null for reasons the row cannot explain.
///
/// Amortization is the caller's, and it is cheap to get right: build the
/// index ONCE and join every socket against it, which is what the example
/// does. Building it per socket would turn an O(P×F) scan into O(S×P×F).
///
/// Never fails on a permission error: a `/proc/<pid>/fd` this uid may not
/// read is counted in `denied` and skipped, matching every other parser in
/// this module ("a missing or unreadable file yields an empty result, not an
/// error") and matching `ss -p`'s own behaviour. Caller owns the result
/// (`idx.deinit(gpa)`).
pub fn indexSocketOwners(
    gpa: std.mem.Allocator,
    io: std.Io,
    opts: SocketOwnerOptions,
) std.mem.Allocator.Error!SocketOwnerIndex {
    var out: std.ArrayList(SocketOwner) = .empty;
    errdefer out.deinit(gpa);

    var scanned: u32 = 0;
    var denied: u32 = 0;
    var vanished: u32 = 0;
    var truncated = false;

    var proc_dir = std.Io.Dir.cwd().openDir(io, "/proc", .{ .iterate = true }) catch
        return .{ .owners = try out.toOwnedSlice(gpa), .scanned = 0, .denied = 0, .vanished = 0, .truncated = false };
    defer proc_dir.close(io);

    var it = proc_dir.iterate();
    while (it.next(io) catch null) |entry| {
        const pid = std.fmt.parseInt(u32, entry.name, 10) catch continue; // numeric dirs = pids
        if (scanned + denied + vanished >= opts.max_processes) {
            truncated = true;
            break;
        }

        var fd_path_buf: [64]u8 = undefined;
        const fd_path = std.fmt.bufPrint(&fd_path_buf, "/proc/{d}/fd", .{pid}) catch continue;
        var fd_dir = std.Io.Dir.cwd().openDir(io, fd_path, .{ .iterate = true }) catch |err| {
            switch (err) {
                // The two refusals `/proc/<pid>/fd` actually produces for a
                // process this uid does not own. Counted, never fatal.
                error.AccessDenied, error.PermissionDenied => denied += 1,
                // The pid exited between the listing and this open.
                error.FileNotFound => vanished += 1,
                else => vanished += 1,
            }
            continue;
        };
        defer fd_dir.close(io);
        scanned += 1;

        // Read the process name lazily — only once this pid turns out to
        // hold at least one socket. Most processes hold none, and paying a
        // `/proc/<pid>/stat` read for each of them would roughly double the
        // sweep's syscall count for nothing.
        var name_buf: [procnet.comm_max]u8 = @splat(0);
        var name_len: u8 = 0;
        var name_read = false;

        var fds = fd_dir.iterate();
        var fd_count: usize = 0;
        while (fds.next(io) catch null) |fd_entry| {
            if (fd_count >= opts.max_fds_per_process) {
                truncated = true;
                break;
            }
            fd_count += 1;
            const fd = std.fmt.parseInt(u32, fd_entry.name, 10) catch continue;

            var link_buf: [64]u8 = undefined;
            const n = fd_dir.readLink(io, fd_entry.name, &link_buf) catch continue;
            const inode = parseSocketInode(link_buf[0..n]) orelse continue;

            if (!name_read) {
                name_read = true;
                var sp_buf: [64]u8 = undefined;
                if (std.fmt.bufPrint(&sp_buf, "/proc/{d}/stat", .{pid}) catch null) |sp| {
                    if (procnet.readVirtualFile(gpa, io, sp, 4096)) |text| {
                        defer gpa.free(text);
                        if (parseProcStat(text)) |pe| name_len = procnet.copyClamped(&name_buf, pe.name());
                    }
                }
            }

            try out.append(gpa, .{
                .inode = inode,
                .pid = pid,
                .fd = fd,
                .name_buf = name_buf,
                .name_len = name_len,
            });
        }
    }

    const owners = try out.toOwnedSlice(gpa);
    std.mem.sortUnstable(SocketOwner, owners, {}, struct {
        fn lessThan(_: void, a: SocketOwner, b: SocketOwner) bool {
            if (a.inode != b.inode) return a.inode < b.inode;
            if (a.pid != b.pid) return a.pid < b.pid;
            return a.fd < b.fd;
        }
    }.lessThan);

    return .{
        .owners = owners,
        .scanned = scanned,
        .denied = denied,
        .vanished = vanished,
        .truncated = truncated,
    };
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "parseProcStat: real /proc/1/stat-shaped line (systemd)" {
    const line = "1 (systemd) S 0 1 1 0 -1 4194560 55321 3271011 40 4482 106 88 1058 621 20 0 1 0 3 170939904 2237 18446744073709551615 0 0 0 0 0 0 671173123 4096 1260 1 0 0 17 3 0 0 0 0 0 0 0 0 0 0";
    const e = parseProcStat(line).?;
    try testing.expectEqual(@as(u32, 1), e.pid);
    try testing.expectEqualStrings("systemd", e.name());
    try testing.expectEqual(@as(u8, 'S'), e.state);
    try testing.expectEqual(@as(u32, 0), e.ppid);
    try testing.expectEqual(@as(u64, 2237 * 4), e.rss_kb);
}

test "parseProcStat: name containing its own parens (sd-pam-style)" {
    const line = "1234 ((sd-pam)) S 1233 1233 1233 0 -1 1077936384 10 0 0 0 0 0 0 0 20 0 1 0 5 170000000 200 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0";
    const e = parseProcStat(line).?;
    try testing.expectEqual(@as(u32, 1234), e.pid);
    try testing.expectEqualStrings("(sd-pam)", e.name());
    try testing.expectEqual(@as(u32, 1233), e.ppid);
}

test "parseProcStat: name containing spaces and a lone close-paren" {
    const line = "42 (my weird) name) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0 300 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0";
    const e = parseProcStat(line).?;
    try testing.expectEqualStrings("my weird) name", e.name());
    try testing.expectEqual(@as(u8, 'R'), e.state);
    try testing.expectEqual(@as(u64, 300 * 4), e.rss_kb);
}

test "parseProcStat: name longer than comm_max is truncated, not dropped" {
    // 105 bytes — past `comm_max` (64) — asserted against a concrete
    // expected string, not a length derived from the constant under test:
    // that form passes vacuously whatever `comm_max` happens to be (it did,
    // silently, when this test read `procnet.comm_max` on both sides before
    // this fix — see the CHANGELOG entry for `comm_max` 16→64).
    const line = "7 (this-process-name-is-way-too-long-for-the-kernel-and-then-some-padding-to-exceed-the-64-byte-parse-buffer) Z 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0";
    const e = parseProcStat(line).?;
    try testing.expectEqualStrings("this-process-name-is-way-too-long-for-the-kernel-and-then-some-p", e.name());
    try testing.expectEqual(@as(u8, 'Z'), e.state);
}

test "parseProcStat: malformed lines return null, not a panic" {
    try testing.expectEqual(@as(?ProcessEntry, null), parseProcStat(""));
    try testing.expectEqual(@as(?ProcessEntry, null), parseProcStat("no-parens-here S 1 1"));
    try testing.expectEqual(@as(?ProcessEntry, null), parseProcStat("1 (ok S 1 1")); // no close paren
    try testing.expectEqual(@as(?ProcessEntry, null), parseProcStat("bad-pid (ok) S 1 1"));
    try testing.expectEqual(@as(?ProcessEntry, null), parseProcStat("1 (ok) S")); // missing ppid
}

test "parseProcStat: real long kernel-thread line, full workqueue name survives" {
    // Captured verbatim from a live host: `/proc/10/stat`, a PF_WQ_WORKER
    // kernel thread whose comm is "kworker/0:0H-kblockd" (20 bytes) — the
    // kernel's proc_task_name() (fs/proc/array.c) appends the workqueue
    // description past TASK_COMM_LEN (16), so this is legitimately longer
    // than the kernel-internal comm bound. `comm_max` sizes the *parse*
    // buffer, not the kernel-internal one, and must be big enough to hold
    // this without truncating.
    const line = "10 (kworker/0:0H-kblockd) I 2 0 0 0 -1 69238880 0 0 0 0 0 0 0 0 0 -20 1 0 18 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
    const e = parseProcStat(line).?;
    try testing.expectEqual(@as(u32, 10), e.pid);
    try testing.expectEqualStrings("kworker/0:0H-kblockd", e.name());
    try testing.expectEqual(@as(u8, 'I'), e.state);
    try testing.expectEqual(@as(u32, 2), e.ppid);
}

test "parseProcStat: too few trailing fields still yields rss 0, not an error" {
    const line = "9 (short) S 1 1";
    const e = parseProcStat(line).?;
    try testing.expectEqual(@as(u64, 0), e.rss_kb);
    try testing.expectEqual(@as(u32, 1), e.ppid);
}

test "parseProcStat: near-maxInt(u64) rss field saturates instead of panicking" {
    // Reproduces the audit's finding: `(parseInt(...) catch 0) * 4` used to
    // hit a checked-arithmetic overflow panic (Debug/ReleaseSafe) on a
    // crafted rss field near maxInt(u64)/4. Must now saturate cleanly.
    const line = "9 (evil) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0";
    const e = parseProcStat(line).?;
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), e.rss_kb);
    try testing.expectEqual(@as(u32, 9), e.pid);
}

test "parseSocketInode: only a socket:[N] target yields an inode" {
    try testing.expectEqual(@as(?u64, 5194665), parseSocketInode("socket:[5194665]"));
    try testing.expectEqual(@as(?u64, 0), parseSocketInode("socket:[0]"));

    // Every other descriptor shape the kernel renders. `pipe:[N]` and
    // `anon_inode:` matter most: a pipe's inode number lives in a different
    // namespace and can collide with a socket's, so a loose ":[N]" match
    // would attach a real pid to the wrong socket.
    try testing.expectEqual(@as(?u64, null), parseSocketInode("pipe:[5194665]"));
    try testing.expectEqual(@as(?u64, null), parseSocketInode("anon_inode:[eventfd]"));
    try testing.expectEqual(@as(?u64, null), parseSocketInode("anon_inode:inotify"));
    try testing.expectEqual(@as(?u64, null), parseSocketInode("/dev/null"));
    try testing.expectEqual(@as(?u64, null), parseSocketInode("/tmp/socket:[7]")); // a real FILE so named
    try testing.expectEqual(@as(?u64, null), parseSocketInode("socket:[]"));
    try testing.expectEqual(@as(?u64, null), parseSocketInode("socket:[12")); // truncated
    try testing.expectEqual(@as(?u64, null), parseSocketInode("socket:[-1]"));
    try testing.expectEqual(@as(?u64, null), parseSocketInode("socket:[nope]"));
    try testing.expectEqual(@as(?u64, null), parseSocketInode(""));
}

test "SocketOwnerIndex.findAll: contiguous run per inode, and inode 0 never matches" {
    // Hand-built index (the lookup is pure and the sweep is not, so it is
    // tested on its own): two processes sharing inode 200 — a socket that
    // survived a fork, which is what makes `find` alone insufficient.
    var owners = [_]SocketOwner{
        .{ .inode = 0, .pid = 9, .fd = 1 },
        .{ .inode = 0, .pid = 10, .fd = 1 },
        .{ .inode = 100, .pid = 11, .fd = 3 },
        .{ .inode = 200, .pid = 12, .fd = 6 },
        .{ .inode = 200, .pid = 13, .fd = 6 },
        .{ .inode = 300, .pid = 14, .fd = 4 },
    };
    const idx: SocketOwnerIndex = .{
        .owners = &owners,
        .scanned = 6,
        .denied = 0,
        .vanished = 0,
        .truncated = false,
    };

    try testing.expectEqual(@as(usize, 1), idx.findAll(100).len);
    try testing.expectEqual(@as(u32, 11), idx.find(100).?.pid);

    const shared = idx.findAll(200);
    try testing.expectEqual(@as(usize, 2), shared.len);
    try testing.expectEqual(@as(u32, 12), shared[0].pid);
    try testing.expectEqual(@as(u32, 13), shared[1].pid);

    try testing.expectEqual(@as(usize, 1), idx.findAll(300).len); // last run
    try testing.expectEqual(@as(usize, 0), idx.findAll(150).len); // between runs
    try testing.expectEqual(@as(usize, 0), idx.findAll(999).len); // past the end

    // ⚠ Inode 0 is the kernel's "this socket has no inode" (TIME_WAIT and
    // other orphans), printed for many rows at once. Two entries with inode
    // 0 are sitting in this index precisely so that a plain binary search
    // WOULD find them; the guard is what stops every orphaned socket in a
    // listing from being attributed to pid 9.
    try testing.expectEqual(@as(usize, 0), idx.findAll(0).len);
    try testing.expectEqual(@as(?SocketOwner, null), idx.find(0));
}

// Gated live test: the join against the real `/proc`. Uses a socket this
// test process opens itself, so the claim is not "some socket matched" (a
// listing of hundreds will match something by luck) but "the one socket
// whose owner we KNOW was attributed to this pid, under the fd we hold".
test "smoke: indexSocketOwners attributes a socket this process itself opened" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // A listener on an ephemeral port: the kernel gives it an inode, and
    // this process holds the only descriptor for it.
    const addr: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } };
    var listener = addr.listen(io, .{ .mode = .stream }) catch
        return error.SkipZigTest; // no loopback (a locked-down sandbox)
    defer listener.deinit(io);

    const self_pid: u32 = @intCast(std.os.linux.getpid());

    // Find our own socket's inode from the kernel's own table, the same way
    // a caller would: read /proc/net/tcp, match the port we were given.
    const bound_port = listener.socket.address.getPort();
    const text = procnet.readVirtualFile(testing.allocator, io, "/proc/net/tcp", 512 * 1024) orelse
        return error.SkipZigTest;
    defer testing.allocator.free(text);
    const rows = try procnet.parseTcp(testing.allocator, text);
    defer testing.allocator.free(rows);

    var want_inode: ?u64 = null;
    for (rows) |r| {
        if (r.state == .listen and r.local_port == bound_port) want_inode = r.inode;
    }
    if (want_inode == null) return error.SkipZigTest; // v6-only /proc/net/tcp, or no table

    var idx = try indexSocketOwners(testing.allocator, io, .{});
    defer idx.deinit(testing.allocator);

    const found = idx.findAll(want_inode.?);
    try testing.expect(found.len >= 1);
    var mine = false;
    for (found) |o| {
        if (o.pid == self_pid) mine = true;
    }
    try testing.expect(mine);

    // The sweep saw at least this process, and the partial-result accounting
    // is populated rather than left at zero.
    try testing.expect(idx.scanned > 0);
}

// ── fuzz: parseProcStat never panics, arbitrary or real-shaped bytes ───────
//
// `/proc/<pid>/stat` is emitted by the kernel, but this decode entry point
// is exactly as hostile-input-facing as any wire parser: a container's
// `/proc` can be bind-mounted/faked, and the process's own name (`comm`) is
// attacker-influenced (any process can name itself anything, including more
// parens than the format's own outside-in scan expects). Allocation-free —
// the result lives in a fixed buffer — so the property is "never panics or
// reads OOB", not a leak oracle.
const proc_stat_corpus = [_][]const u8{
    "1 (systemd) S 0 1 1 0 -1 4194560 55321 3271011 40 4482 106 88 1058 621 20 0 1 0 3 170939904 2237 18446744073709551615 0 0 0 0 0 0 671173123 4096 1260 1 0 0 17 3 0 0 0 0 0 0 0 0 0 0",
    "1234 ((sd-pam)) S 1233 1233 1233 0 -1 1077936384 10 0 0 0 0 0 0 0 20 0 1 0 5 170000000 200 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0",
    "42 (my weird) name) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0 300 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0",
    "",
    "no-parens-here S 1 1",
};

test "fuzz: parseProcStat never panics, arbitrary or mutated-real bytes" {
    try std.testing.fuzz({}, fuzzParseProcStatNeverPanics, .{ .corpus = &proc_stat_corpus });
}

fn fuzzParseProcStatNeverPanics(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    const line = mutateSample(smith, proc_stat_corpus[0], &buf);
    _ = parseProcStat(line);
}

/// One draw in five is pure arbitrary bytes; the rest starts from a real
/// `/proc/<pid>/stat` line and applies a handful of byte-level mutations —
/// arbitrary bytes essentially never spell a balanced `(...)` around a
/// plausible `comm`, so mutating a known-good sample reaches the parser's
/// interior (the field-counting loop past `comm`) far more often than a
/// from-scratch random string would.
fn mutateSample(smith: *std.testing.Smith, sample: []const u8, buf: []u8) []const u8 {
    if (smith.valueRangeAtMost(u8, 0, 4) == 0) {
        smith.bytes(buf);
        const len = smith.valueRangeAtMost(u16, 0, @intCast(buf.len));
        return buf[0..len];
    }
    const len = @min(sample.len, buf.len);
    @memcpy(buf[0..len], sample[0..len]);
    const n_mutations = smith.valueRangeAtMost(u8, 0, 16);
    var i: u8 = 0;
    while (i < n_mutations) : (i += 1) {
        if (len == 0) break;
        buf[smith.index(len)] = smith.value(u8);
    }
    const out_len = smith.valueRangeAtMost(u16, 0, @intCast(len));
    return buf[0..out_len];
}
