// SPDX-License-Identifier: MIT

//! The smaller per-process files: `/proc/<pid>/limits`, `io`, `status`,
//! `cmdline`, `cgroup`, and the open-descriptor count of `/proc/<pid>/fd`.
//! `stat` lives in `pidstat.zig`. Every reader takes a `ProcRef`
//! (`.self` or `.{ .pid = n }`); every parser is pure and takes bytes.
//!
//! Two failure shapes, as everywhere in this module: a file that cannot be
//! read (the process exited, or `/proc/<pid>/io` of another user's process
//! — `0400`, owner only) is null; a line that is not the documented shape is
//! skipped, never fatal.

const std = @import("std");
const procnet = @import("root.zig");

// ── /proc/<pid>/limits ───────────────────────────────────────────────────────

/// A resource row of `/proc/<pid>/limits` (`getrlimit(2)`'s `RLIMIT_*`),
/// named as the kernel's `Max ...` label.
pub const Resource = enum {
    cpu_time,
    file_size,
    data_size,
    stack_size,
    core_file_size,
    resident_set,
    processes,
    open_files,
    locked_memory,
    address_space,
    file_locks,
    pending_signals,
    msgqueue_size,
    nice_priority,
    realtime_priority,
    realtime_timeout,

    /// The row label, e.g. `"Max open files"`.
    pub fn label(r: Resource) []const u8 {
        return switch (r) {
            .cpu_time => "Max cpu time",
            .file_size => "Max file size",
            .data_size => "Max data size",
            .stack_size => "Max stack size",
            .core_file_size => "Max core file size",
            .resident_set => "Max resident set",
            .processes => "Max processes",
            .open_files => "Max open files",
            .locked_memory => "Max locked memory",
            .address_space => "Max address space",
            .file_locks => "Max file locks",
            .pending_signals => "Max pending signals",
            .msgqueue_size => "Max msgqueue size",
            .nice_priority => "Max nice priority",
            .realtime_priority => "Max realtime priority",
            .realtime_timeout => "Max realtime timeout",
        };
    }

    /// The unit of the row's numbers: `seconds`, `bytes`, `us`, or a count
    /// (`files`, `processes`, `signals`, `locks`; priorities have none: "").
    pub fn unit(r: Resource) []const u8 {
        return switch (r) {
            .cpu_time => "seconds",
            .file_size, .data_size, .stack_size, .core_file_size, .resident_set, .locked_memory, .address_space, .msgqueue_size => "bytes",
            .processes => "processes",
            .open_files => "files",
            .file_locks => "locks",
            .pending_signals => "signals",
            .nice_priority, .realtime_priority => "",
            .realtime_timeout => "us",
        };
    }
};

/// One limit: soft and hard value, each `null` for `unlimited`.
pub const Limit = struct {
    soft: ?u64,
    hard: ?u64,
};

/// All rows of one `limits` file. A row the file lacks (an older kernel) is
/// null in `get`.
pub const Limits = struct {
    rows: [@typeInfo(Resource).@"enum".field_names.len]?Limit = @splat(null),
    /// Rows that matched no known `Max ...` label, or whose numbers were not
    /// `unlimited` / decimal. They are skipped, not fatal.
    skipped_rows: u32 = 0,

    pub fn get(l: *const Limits, r: Resource) ?Limit {
        return l.rows[@backingInt(r)];
    }

    /// `process_max_fds`: the soft `Max open files`; null = unlimited or absent.
    pub fn maxOpenFiles(l: *const Limits) ?u64 {
        const x = l.get(.open_files) orelse return null;
        return x.soft;
    }

    /// `process_virtual_memory_max_bytes`: the soft `Max address space`.
    pub fn maxAddressSpace(l: *const Limits) ?u64 {
        const x = l.get(.address_space) orelse return null;
        return x.soft;
    }
};

fn parseLimitValue(tok: []const u8) error{Bad}!?u64 {
    if (std.mem.eql(u8, tok, "unlimited")) return null;
    return std.fmt.parseInt(u64, tok, 10) catch error.Bad;
}

/// Parse `/proc/<pid>/limits`. The columns are fixed-width for the kernel's
/// own labels but a label contains spaces, so a row is matched by its known
/// `Max ...` label and the next two tokens are soft and hard. Pure,
/// allocation-free.
pub fn parseLimits(text: []const u8) Limits {
    var out: Limits = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    var first = true;
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, " \t\r");
        if (first) {
            first = false;
            if (std.mem.startsWith(u8, line, "Limit")) continue; // the header
        }
        if (line.len == 0) continue;
        var matched = false;
        inline for (@typeInfo(Resource).@"enum".field_names, @typeInfo(Resource).@"enum".field_values) |_, f_value| {
            const r: Resource = @fromBackingInt(@intCast(f_value));
            const lab = comptime r.label();
            if (!matched and std.mem.startsWith(u8, line, lab) and
                (line.len == lab.len or line[lab.len] == ' ' or line[lab.len] == '\t'))
            {
                matched = true;
                var it = std.mem.tokenizeAny(u8, line[lab.len..], " \t");
                const soft = it.next();
                const hard = it.next();
                if (soft != null and hard != null) {
                    const s = parseLimitValue(soft.?);
                    const h = parseLimitValue(hard.?);
                    if (s) |sv| {
                        if (h) |hv| {
                            out.rows[f_value] = .{ .soft = sv, .hard = hv };
                        } else |_| out.skipped_rows +|= 1;
                    } else |_| out.skipped_rows +|= 1;
                } else out.skipped_rows +|= 1;
            }
        }
        if (!matched) out.skipped_rows +|= 1;
    }
    return out;
}

/// Read and parse `/proc/<pid>/limits`. Null if unreadable. No allocation.
pub fn readPidLimits(io: std.Io, ref: procnet.ProcRef) ?Limits {
    var pb: [64]u8 = undefined;
    const path = ref.path(&pb, "limits") orelse return null;
    var buf: [4096]u8 = undefined;
    const text = procnet.readVirtualFileInto(io, path, &buf) orelse return null;
    return parseLimits(text);
}

// ── /proc/<pid>/io ───────────────────────────────────────────────────────────

/// `/proc/<pid>/io`. A counter the file lacks reads 0; `fields` counts the
/// ones it had (7 on every kernel built with `CONFIG_TASK_IO_ACCOUNTING`).
pub const PidIo = struct {
    /// Bytes passed to read-like syscalls (page cache hits included).
    rchar: u64 = 0,
    wchar: u64 = 0,
    syscr: u64 = 0,
    syscw: u64 = 0,
    /// Bytes this process caused to be fetched from the storage layer.
    read_bytes: u64 = 0,
    write_bytes: u64 = 0,
    cancelled_write_bytes: u64 = 0,
    fields: u8 = 0,
};

fn firstUint(v: []const u8) u64 {
    var it = std.mem.tokenizeAny(u8, v, " \t\r");
    const t = it.next() orelse return 0;
    return std.fmt.parseInt(u64, t, 10) catch 0;
}

/// Parse `/proc/<pid>/io` (`key: value` lines, any order). Pure.
pub fn parsePidIo(text: []const u8) PidIo {
    var out: PidIo = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const key = std.mem.trim(u8, line[0..colon], " \t");
        const v = firstUint(line[colon + 1 ..]);
        const dst: *u64 = if (std.mem.eql(u8, key, "rchar")) &out.rchar else if (std.mem.eql(u8, key, "wchar")) &out.wchar else if (std.mem.eql(u8, key, "syscr")) &out.syscr else if (std.mem.eql(u8, key, "syscw")) &out.syscw else if (std.mem.eql(u8, key, "read_bytes")) &out.read_bytes else if (std.mem.eql(u8, key, "write_bytes")) &out.write_bytes else if (std.mem.eql(u8, key, "cancelled_write_bytes")) &out.cancelled_write_bytes else continue;
        dst.* = v;
        out.fields +|= 1;
    }
    return out;
}

/// Read `/proc/<pid>/io`. Null if unreadable — which is the normal answer for
/// another user's process (the file is `0400`) and for a kernel without I/O
/// accounting. No allocation.
pub fn readPidIo(io: std.Io, ref: procnet.ProcRef) ?PidIo {
    var pb: [64]u8 = undefined;
    const path = ref.path(&pb, "io") orelse return null;
    var buf: [1024]u8 = undefined;
    const text = procnet.readVirtualFileInto(io, path, &buf) orelse return null;
    return parsePidIo(text);
}

// ── /proc/<pid>/status ───────────────────────────────────────────────────────

/// An inclusive CPU range from `Cpus_allowed_list` (`0-3` is `{0, 3}`, `7` is `{7, 7}`).
pub const CpuRange = struct { first: u64, last: u64 };

const max_nspid = 32; // the kernel's MAX_PID_NS_LEVEL
const max_cpu_ranges = 32;

/// `/proc/<pid>/status`: the fields `prometheus/procfs` `ProcStatus` reads,
/// plus `state`, `ppid`, `threads`. Memory figures are BYTES (the file prints
/// kB). A field the file lacks reads 0 — kernel threads have no `Vm*` lines.
pub const PidStatus = struct {
    name_buf: [procnet.comm_max]u8 = @splat(0),
    name_len: u8 = 0,
    state: u8 = 0,
    tgid: u64 = 0,
    pid: u64 = 0,
    ppid: u64 = 0,
    threads: u64 = 0,
    /// `NSpid`: the pid in each nested PID namespace, outermost first.
    nspid: [max_nspid]u64 = @splat(0),
    nspid_len: u8 = 0,
    vm_peak: u64 = 0,
    vm_size: u64 = 0,
    vm_lck: u64 = 0,
    vm_pin: u64 = 0,
    vm_hwm: u64 = 0,
    vm_rss: u64 = 0,
    rss_anon: u64 = 0,
    rss_file: u64 = 0,
    rss_shmem: u64 = 0,
    vm_data: u64 = 0,
    vm_stk: u64 = 0,
    vm_exe: u64 = 0,
    vm_lib: u64 = 0,
    vm_pte: u64 = 0,
    vm_pmd: u64 = 0,
    vm_swap: u64 = 0,
    hugetlb_pages: u64 = 0,
    voluntary_ctxt_switches: u64 = 0,
    nonvoluntary_ctxt_switches: u64 = 0,
    /// Real, effective, saved-set, filesystem.
    uids: [4]u64 = @splat(0),
    gids: [4]u64 = @splat(0),
    /// `Cpus_allowed_list` as ranges (kept as ranges because `0-8191` is one
    /// entry, not 8192). Parts beyond 32 are counted in `cpus_allowed_count`
    /// but not stored.
    cpus_allowed: [max_cpu_ranges]CpuRange = @splat(.{ .first = 0, .last = 0 }),
    cpus_allowed_len: u8 = 0,
    /// Total CPUs in the list (saturating).
    cpus_allowed_count: u64 = 0,
    cap_inh: u64 = 0,
    cap_prm: u64 = 0,
    cap_eff: u64 = 0,
    cap_bnd: u64 = 0,
    cap_amb: u64 = 0,
    /// Set by `readPidStatus` when the file was longer than the read buffer
    /// (a process with thousands of supplementary groups): fields past the cut
    /// read 0.
    truncated: bool = false,

    pub fn name(s: *const PidStatus) []const u8 {
        return s.name_buf[0..s.name_len];
    }

    pub fn nspids(s: *const PidStatus) []const u64 {
        return s.nspid[0..s.nspid_len];
    }

    pub fn cpuRanges(s: *const PidStatus) []const CpuRange {
        return s.cpus_allowed[0..s.cpus_allowed_len];
    }

    /// `voluntary_ctxt_switches + nonvoluntary_ctxt_switches`, saturating.
    pub fn totalCtxtSwitches(s: *const PidStatus) u64 {
        return s.voluntary_ctxt_switches +| s.nonvoluntary_ctxt_switches;
    }
};

const StatusKey = enum {
    Name,
    State,
    Tgid,
    Pid,
    PPid,
    Threads,
    Uid,
    Gid,
    NSpid,
    VmPeak,
    VmSize,
    VmLck,
    VmPin,
    VmHWM,
    VmRSS,
    RssAnon,
    RssFile,
    RssShmem,
    VmData,
    VmStk,
    VmExe,
    VmLib,
    VmPTE,
    VmPMD,
    VmSwap,
    HugetlbPages,
    voluntary_ctxt_switches,
    nonvoluntary_ctxt_switches,
    Cpus_allowed_list,
    CapInh,
    CapPrm,
    CapEff,
    CapBnd,
    CapAmb,
};

fn kbToBytes(v: []const u8) u64 {
    return firstUint(v) *| 1024;
}

fn hexUint(v: []const u8) u64 {
    var it = std.mem.tokenizeAny(u8, v, " \t\r");
    const t = it.next() orelse return 0;
    return std.fmt.parseInt(u64, t, 16) catch 0;
}

fn fillUints(dst: []u64, v: []const u8) usize {
    var it = std.mem.tokenizeAny(u8, v, " \t\r");
    var n: usize = 0;
    while (it.next()) |t| {
        if (n == dst.len) break;
        dst[n] = std.fmt.parseInt(u64, t, 10) catch 0;
        n += 1;
    }
    return n;
}

fn parseCpuList(s: *PidStatus, v: []const u8) void {
    var parts = std.mem.splitScalar(u8, v, ',');
    while (parts.next()) |part_raw| {
        const part = std.mem.trim(u8, part_raw, " \t\r");
        if (part.len == 0) continue;
        var first: u64 = undefined;
        var last: u64 = undefined;
        if (std.mem.findScalar(u8, part, '-')) |d| {
            first = std.fmt.parseInt(u64, part[0..d], 10) catch continue;
            last = std.fmt.parseInt(u64, part[d + 1 ..], 10) catch continue;
        } else {
            first = std.fmt.parseInt(u64, part, 10) catch continue;
            last = first;
        }
        if (last < first) continue;
        s.cpus_allowed_count +|= (last - first) +| 1;
        if (s.cpus_allowed_len < max_cpu_ranges) {
            s.cpus_allowed[s.cpus_allowed_len] = .{ .first = first, .last = last };
            s.cpus_allowed_len += 1;
        }
    }
}

/// Parse `/proc/<pid>/status`. Pure, allocation-free; never fails — an
/// unknown key, a line without `:` or a non-numeric value is skipped or reads 0.
pub fn parsePidStatus(text: []const u8) PidStatus {
    var s: PidStatus = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const key = std.meta.stringToEnum(StatusKey, std.mem.trim(u8, line[0..colon], " \t")) orelse continue;
        const v = std.mem.trim(u8, line[colon + 1 ..], " \t\r");
        switch (key) {
            .Name => s.name_len = @intCast(procnet.copyClamped(&s.name_buf, v)),
            .State => s.state = if (v.len > 0) v[0] else 0,
            .Tgid => s.tgid = firstUint(v),
            .Pid => s.pid = firstUint(v),
            .PPid => s.ppid = firstUint(v),
            .Threads => s.threads = firstUint(v),
            .Uid => _ = fillUints(&s.uids, v),
            .Gid => _ = fillUints(&s.gids, v),
            .NSpid => s.nspid_len = @intCast(fillUints(&s.nspid, v)),
            .VmPeak => s.vm_peak = kbToBytes(v),
            .VmSize => s.vm_size = kbToBytes(v),
            .VmLck => s.vm_lck = kbToBytes(v),
            .VmPin => s.vm_pin = kbToBytes(v),
            .VmHWM => s.vm_hwm = kbToBytes(v),
            .VmRSS => s.vm_rss = kbToBytes(v),
            .RssAnon => s.rss_anon = kbToBytes(v),
            .RssFile => s.rss_file = kbToBytes(v),
            .RssShmem => s.rss_shmem = kbToBytes(v),
            .VmData => s.vm_data = kbToBytes(v),
            .VmStk => s.vm_stk = kbToBytes(v),
            .VmExe => s.vm_exe = kbToBytes(v),
            .VmLib => s.vm_lib = kbToBytes(v),
            .VmPTE => s.vm_pte = kbToBytes(v),
            .VmPMD => s.vm_pmd = kbToBytes(v),
            .VmSwap => s.vm_swap = kbToBytes(v),
            .HugetlbPages => s.hugetlb_pages = kbToBytes(v),
            .voluntary_ctxt_switches => s.voluntary_ctxt_switches = firstUint(v),
            .nonvoluntary_ctxt_switches => s.nonvoluntary_ctxt_switches = firstUint(v),
            .Cpus_allowed_list => {
                s.cpus_allowed_len = 0;
                s.cpus_allowed_count = 0;
                parseCpuList(&s, v);
            },
            .CapInh => s.cap_inh = hexUint(v),
            .CapPrm => s.cap_prm = hexUint(v),
            .CapEff => s.cap_eff = hexUint(v),
            .CapBnd => s.cap_bnd = hexUint(v),
            .CapAmb => s.cap_amb = hexUint(v),
        }
    }
    return s;
}

/// Read `/proc/<pid>/status`. Null if unreadable. No allocation (16 KiB read
/// buffer on the stack; `truncated` says if the file was longer).
pub fn readPidStatus(io: std.Io, ref: procnet.ProcRef) ?PidStatus {
    var pb: [64]u8 = undefined;
    const path = ref.path(&pb, "status") orelse return null;
    var buf: [16 * 1024]u8 = undefined;
    const text = procnet.readVirtualFileInto(io, path, &buf) orelse return null;
    var s = parsePidStatus(text);
    s.truncated = text.len == buf.len;
    return s;
}

// ── /proc/<pid>/cmdline ──────────────────────────────────────────────────────

/// How much of a command line `readPidCmdline` keeps: 1 MiB (the kernel allows
/// up to a quarter of the stack rlimit; real ones are a few hundred bytes).
pub const cmdline_read_limit: usize = 1 << 20;

/// Iterator over the NUL-separated arguments of a `cmdline` blob.
pub const ArgIterator = struct {
    rest: ?[]const u8,

    pub fn next(it: *ArgIterator) ?[]const u8 {
        const r = it.rest orelse return null;
        if (std.mem.findScalar(u8, r, 0)) |i| {
            it.rest = r[i + 1 ..];
            // The final NUL terminates the last argument; it does not start a new one.
            if (it.rest.?.len == 0) it.rest = null;
            return r[0..i];
        }
        it.rest = null;
        return r; // a process that rewrote its title with no trailing NUL
    }
};

/// A process's command line as the kernel gives it: arguments each terminated
/// by NUL. Empty for a kernel thread and for a zombie.
pub const Cmdline = struct {
    bytes: []u8,
    /// The command line was longer than `cmdline_read_limit`.
    truncated: bool,

    pub fn deinit(c: Cmdline, gpa: std.mem.Allocator) void {
        gpa.free(c.bytes);
    }

    pub fn args(c: *const Cmdline) ArgIterator {
        return cmdlineArgs(c.bytes);
    }
};

/// Split a `cmdline` blob into its arguments. An empty blob has none; an empty
/// argument in the middle (`a\0\0b\0`) is yielded as "". A process that
/// rewrote its own title without NULs (`setproctitle`) is one argument.
pub fn cmdlineArgs(bytes: []const u8) ArgIterator {
    return .{ .rest = if (bytes.len == 0) null else bytes };
}

/// Read `/proc/<pid>/cmdline`. Null if unreadable (or out of memory). Caller
/// owns the result (`deinit`).
pub fn readPidCmdline(gpa: std.mem.Allocator, io: std.Io, ref: procnet.ProcRef) ?Cmdline {
    var pb: [64]u8 = undefined;
    const path = ref.path(&pb, "cmdline") orelse return null;
    const f = procnet.readVirtualFileReporting(gpa, io, path, cmdline_read_limit) orelse return null;
    return .{ .bytes = f.bytes, .truncated = f.truncated };
}

// ── /proc/<pid>/cgroup ───────────────────────────────────────────────────────

/// One line of `/proc/<pid>/cgroup`: `hierarchy-id:controller-list:path`.
/// cgroup v2 has one line `0::/path` with an empty controller list.
pub const CgroupEntry = struct {
    hierarchy_id: u32,
    /// Comma-separated controllers (`cpu,cpuacct`); empty for v2. Borrowed from the text.
    controllers: []const u8,
    /// The group path relative to its hierarchy's mount, as printed
    /// (a deleted group carries a ` (deleted)` suffix). Borrowed from the text.
    path: []const u8,

    pub fn controllerIterator(e: *const CgroupEntry) std.mem.SplitIterator(u8, .scalar) {
        return std.mem.splitScalar(u8, e.controllers, ',');
    }
};

/// The cgroup entries of one process and, when read from `/proc`, the text
/// they point into.
pub const CgroupList = struct {
    entries: []CgroupEntry,
    /// Non-null when this list owns the bytes `entries` borrow from.
    text: ?[]u8 = null,

    pub fn deinit(l: CgroupList, gpa: std.mem.Allocator) void {
        gpa.free(l.entries);
        if (l.text) |t| gpa.free(t);
    }
};

/// Parse `/proc/<pid>/cgroup`. The entries BORROW `text` (it must outlive
/// them); free with `deinit` (frees only the entries when `text` is null here).
/// A line that is not `<number>:<controllers>:<path>` is skipped. The path is
/// everything after the second `:` — it may itself contain colons.
pub fn parseCgroups(gpa: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error!CgroupList {
    var out: std.ArrayList(CgroupEntry) = .empty;
    errdefer out.deinit(gpa);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        const c1 = std.mem.findScalar(u8, line, ':') orelse continue;
        const c2 = std.mem.findScalarPos(u8, line, c1 + 1, ':') orelse continue;
        const id = std.fmt.parseInt(u32, line[0..c1], 10) catch continue;
        try out.append(gpa, .{
            .hierarchy_id = id,
            .controllers = line[c1 + 1 .. c2],
            .path = line[c2 + 1 ..],
        });
    }
    return .{ .entries = try out.toOwnedSlice(gpa) };
}

/// Read and parse `/proc/<pid>/cgroup`; null if unreadable. Owns its text.
pub fn readPidCgroups(gpa: std.mem.Allocator, io: std.Io, ref: procnet.ProcRef) std.mem.Allocator.Error!?CgroupList {
    var pb: [64]u8 = undefined;
    const path = ref.path(&pb, "cgroup") orelse return null;
    const text = procnet.readVirtualFile(gpa, io, path, 64 * 1024) orelse return null;
    errdefer gpa.free(text);
    var l = try parseCgroups(gpa, text);
    l.text = text;
    return l;
}

// ── open descriptors ─────────────────────────────────────────────────────────

/// The number of open file descriptors of a process — `process_open_fds`.
///
/// The rule is `prometheus/procfs`'s `FileDescriptorsLen`: on Linux >= 6.2 the
/// size `stat(2)` reports for `/proc/<pid>/fd` IS the descriptor count (one
/// syscall, no directory walk); if the kernel reports 0 (older), the
/// directory is listed and its entries counted. ⚠ The listing opens a
/// descriptor of its own, so on an older kernel the count includes it for
/// `.self` (procfs behaves the same). Null if the process is gone or its
/// `fd` directory cannot be read (another user's: `0500`).
pub fn countFds(io: std.Io, ref: procnet.ProcRef) ?u64 {
    var pb: [64]u8 = undefined;
    const path = ref.path(&pb, "fd") orelse return null;
    const st = std.Io.Dir.cwd().statFile(io, path, .{}) catch return null;
    if (st.size > 0) return st.size;

    var dir = std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch return null;
    defer dir.close(io);
    var n: u64 = 0;
    var it = dir.iterate();
    while (it.next(io) catch return null) |e| {
        _ = std.fmt.parseInt(u32, e.name, 10) catch continue;
        n += 1;
    }
    return n;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const builtin = @import("builtin");

const real_limits = @embedFile("testdata/pid_limits.txt");
const real_io = @embedFile("testdata/pid_io.txt");
const real_status = @embedFile("testdata/pid_status.txt");
const real_cgroup = @embedFile("testdata/pid_cgroup.txt");

test "parseLimits: every row of a real capture, unlimited as null" {
    const l = parseLimits(real_limits);
    try testing.expectEqual(@as(u32, 0), l.skipped_rows);
    for (0..l.rows.len) |i| try testing.expect(l.rows[i] != null);
    const cpu = l.get(.cpu_time).?;
    try testing.expectEqual(@as(?u64, null), cpu.soft);
    try testing.expectEqual(@as(?u64, null), cpu.hard);
    const stack = l.get(.stack_size).?;
    try testing.expectEqual(@as(?u64, 8388608), stack.soft);
    try testing.expectEqual(@as(?u64, null), stack.hard);
    try testing.expectEqual(@as(?u64, 524288), l.get(.open_files).?.soft);
    try testing.expectEqual(@as(?u64, 524288), l.get(.open_files).?.hard);
    try testing.expectEqual(@as(?u64, 524288), l.maxOpenFiles());
    try testing.expectEqual(@as(?u64, null), l.maxAddressSpace()); // unlimited
    try testing.expectEqual(@as(?u64, 115850), l.get(.processes).?.soft);
    try testing.expectEqual(@as(?u64, 8388608), l.get(.locked_memory).?.soft);
    try testing.expectEqual(@as(?u64, 819200), l.get(.msgqueue_size).?.soft);
    try testing.expectEqual(@as(?u64, 0), l.get(.nice_priority).?.soft); // a row with no units column
    try testing.expectEqual(@as(?u64, 0), l.get(.realtime_priority).?.hard);
    try testing.expectEqual(@as(?u64, null), l.get(.realtime_timeout).?.soft);
    try testing.expectEqualStrings("us", Resource.realtime_timeout.unit());
    try testing.expectEqualStrings("Max open files", Resource.open_files.label());
}

test "parseLimits: hostile and odd rows" {
    // Missing rows, unknown rows, bad numbers: skipped, not fatal.
    const t =
        "Limit Soft Limit Hard Limit Units\n" ++
        "Max open files 1024 4096 files\n" ++ // single spaces
        "Max stack size 8388608\n" ++ // no hard column
        "Max nonsense 1 2 x\n" ++ // unknown label
        "Max cpu time abc unlimited seconds\n" ++ // bad number
        "Max processes 18446744073709551616 1 processes\n" ++ // overflow u64
        "Max file size\tunlimited\tunlimited\tbytes\r\n" ++ // tabs, CRLF
        "Max file sizes 1 1 bytes\n" ++ // label is only a prefix of this row
        "\n";
    const l = parseLimits(t);
    try testing.expectEqual(@as(?u64, 1024), l.get(.open_files).?.soft);
    try testing.expectEqual(@as(?u64, 4096), l.get(.open_files).?.hard);
    try testing.expect(l.get(.stack_size) == null);
    try testing.expect(l.get(.cpu_time) == null);
    try testing.expect(l.get(.processes) == null);
    try testing.expect(l.get(.file_size) != null);
    try testing.expectEqual(@as(u32, 5), l.skipped_rows);
    // Empty and header-only input.
    try testing.expectEqual(@as(u32, 0), parseLimits("").skipped_rows);
    try testing.expect(parseLimits("Limit Soft Limit Hard Limit Units\n").maxOpenFiles() == null);
    // No header at all still parses rows.
    try testing.expectEqual(@as(?u64, 7), parseLimits("Max open files 7 7 files\n").maxOpenFiles());
}

test "parsePidIo: real capture and variants" {
    const a = parsePidIo(real_io);
    try testing.expectEqual(@as(u64, 18423), a.rchar);
    try testing.expectEqual(@as(u64, 0), a.wchar);
    try testing.expectEqual(@as(u64, 24), a.syscr);
    try testing.expectEqual(@as(u8, 7), a.fields);

    const b = parsePidIo("rchar: 1\nwchar: 2\nsyscr: 3\nsyscw: 4\nread_bytes: 5\nwrite_bytes: 6\ncancelled_write_bytes: 7\nfuture: 8\n");
    try testing.expectEqual(@as(u64, 1), b.rchar);
    try testing.expectEqual(@as(u64, 2), b.wchar);
    try testing.expectEqual(@as(u64, 3), b.syscr);
    try testing.expectEqual(@as(u64, 4), b.syscw);
    try testing.expectEqual(@as(u64, 5), b.read_bytes);
    try testing.expectEqual(@as(u64, 6), b.write_bytes);
    try testing.expectEqual(@as(u64, 7), b.cancelled_write_bytes);
    try testing.expectEqual(@as(u8, 7), b.fields);

    // Reordered, partial, garbage: tolerated.
    const c = parsePidIo("write_bytes: 9\nrchar: xx\nno colon here\nsyscw:\n");
    try testing.expectEqual(@as(u64, 9), c.write_bytes);
    try testing.expectEqual(@as(u64, 0), c.rchar);
    try testing.expectEqual(@as(u8, 3), c.fields);
    try testing.expectEqual(@as(u8, 0), parsePidIo("").fields);
}

test "parsePidStatus: real capture" {
    const s = parsePidStatus(real_status);
    try testing.expectEqualStrings("cat", s.name());
    try testing.expectEqual(@as(u8, 'R'), s.state);
    try testing.expectEqual(@as(u64, 3667454), s.tgid);
    try testing.expectEqual(@as(u64, 3667454), s.pid);
    try testing.expectEqual(@as(u64, 3667449), s.ppid);
    try testing.expectEqual(@as(u64, 1), s.threads);
    try testing.expectEqual([4]u64{ 1000, 1000, 1000, 1000 }, s.uids);
    try testing.expectEqual([4]u64{ 1000, 1000, 1000, 1000 }, s.gids);
    try testing.expectEqual(@as(usize, 1), s.nspids().len);
    try testing.expectEqual(@as(u64, 3667454), s.nspids()[0]);
    try testing.expectEqual(@as(u64, 17788 * 1024), s.vm_peak);
    try testing.expectEqual(@as(u64, 17788 * 1024), s.vm_size);
    try testing.expectEqual(@as(u64, 7708 * 1024), s.vm_hwm);
    try testing.expectEqual(@as(u64, 7708 * 1024), s.vm_rss);
    try testing.expectEqual(@as(u64, 1384 * 1024), s.rss_anon);
    try testing.expectEqual(@as(u64, 6324 * 1024), s.rss_file);
    try testing.expectEqual(@as(u64, 0), s.rss_shmem);
    try testing.expectEqual(@as(u64, 424 * 1024), s.vm_data);
    try testing.expectEqual(@as(u64, 136 * 1024), s.vm_stk);
    try testing.expectEqual(@as(u64, 4928 * 1024), s.vm_exe);
    try testing.expectEqual(@as(u64, 3972 * 1024), s.vm_lib);
    try testing.expectEqual(@as(u64, 76 * 1024), s.vm_pte);
    try testing.expectEqual(@as(u64, 0), s.vm_swap);
    try testing.expectEqual(@as(u64, 0), s.voluntary_ctxt_switches);
    try testing.expectEqual(@as(u64, 0x800000000), s.cap_inh);
    try testing.expectEqual(@as(u64, 0), s.cap_prm);
    try testing.expectEqual(@as(u64, 0x1ffffffffff), s.cap_bnd);
    try testing.expectEqual(@as(usize, 1), s.cpuRanges().len);
    try testing.expectEqual(CpuRange{ .first = 0, .last = 7 }, s.cpuRanges()[0]);
    try testing.expectEqual(@as(u64, 8), s.cpus_allowed_count);
    try testing.expectEqual(@as(u64, 2), s.nonvoluntary_ctxt_switches);
    try testing.expectEqual(@as(u64, 2), s.totalCtxtSwitches());
}

test "parsePidStatus: kernel thread, nested namespaces, cpu lists, hostile values" {
    const kt = parsePidStatus("Name:\tkworker/0:0H-kblockd\nState:\tI (idle)\nPid:\t10\nPPid:\t2\nUid:\t0\t0\t0\t0\nvoluntary_ctxt_switches:\t5\nnonvoluntary_ctxt_switches:\t7\n");
    try testing.expectEqualStrings("kworker/0:0H-kblockd", kt.name());
    try testing.expectEqual(@as(u8, 'I'), kt.state);
    try testing.expectEqual(@as(u64, 0), kt.vm_rss); // no Vm* lines
    try testing.expectEqual(@as(u64, 12), kt.totalCtxtSwitches());

    const ns = parsePidStatus("NSpid:\t4242\t17\t1\nCpus_allowed_list:\t0-2,5,8-9\nGid:\t5\t6\nCapEff:\tffffffffffffffff\n");
    try testing.expectEqual(@as(usize, 3), ns.nspids().len);
    try testing.expectEqual(@as(u64, 1), ns.nspids()[2]);
    try testing.expectEqual(@as(usize, 3), ns.cpuRanges().len);
    try testing.expectEqual(@as(u64, 3 + 1 + 2), ns.cpus_allowed_count);
    try testing.expectEqual(CpuRange{ .first = 5, .last = 5 }, ns.cpuRanges()[1]);
    try testing.expectEqual(@as(u64, 5), ns.gids[0]);
    try testing.expectEqual(@as(u64, 0), ns.gids[2]);
    try testing.expectEqual(std.math.maxInt(u64), ns.cap_eff);

    // Hostile: a huge range does not expand, bad ranges are skipped, kB overflow saturates.
    const h = parsePidStatus("Cpus_allowed_list:\t0-18446744073709551615,9-3,x,-4,2-\nVmRSS:\t18446744073709551615 kB\nNSpid:\t1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34\nName:\t" ++ strRepeat("n", 200) ++ "\n:\n\nNoColon\n");
    try testing.expectEqual(@as(usize, 1), h.cpuRanges().len);
    try testing.expectEqual(std.math.maxInt(u64), h.cpus_allowed_count);
    try testing.expectEqual(std.math.maxInt(u64), h.vm_rss);
    try testing.expectEqual(@as(usize, 32), h.nspids().len);
    try testing.expectEqual(@as(usize, procnet.comm_max), h.name().len);
    // 40 ranges: stored 32, counted 40.
    const many = parsePidStatus("Cpus_allowed_list:\t" ++ "0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38,40,42,44,46,48,50,52,54,56,58,60,62,64,66,68,70,72,74,76,78" ++ "\n");
    try testing.expectEqual(@as(usize, 32), many.cpuRanges().len);
    try testing.expectEqual(@as(u64, 40), many.cpus_allowed_count);
}

test "cmdlineArgs: NUL-separated, empty arguments, no trailing NUL" {
    var it = cmdlineArgs("prog\x00--flag\x00a b c\x00");
    try testing.expectEqualStrings("prog", it.next().?);
    try testing.expectEqualStrings("--flag", it.next().?);
    try testing.expectEqualStrings("a b c", it.next().?);
    try testing.expectEqual(@as(?[]const u8, null), it.next());

    var e = cmdlineArgs("a\x00\x00b\x00");
    try testing.expectEqualStrings("a", e.next().?);
    try testing.expectEqualStrings("", e.next().?);
    try testing.expectEqualStrings("b", e.next().?);
    try testing.expectEqual(@as(?[]const u8, null), e.next());

    var t = cmdlineArgs("nginx: master process"); // setproctitle: spaces, no NUL
    try testing.expectEqualStrings("nginx: master process", t.next().?);
    try testing.expectEqual(@as(?[]const u8, null), t.next());

    var z = cmdlineArgs(""); // kernel thread
    try testing.expectEqual(@as(?[]const u8, null), z.next());
    var one = cmdlineArgs("\x00"); // a single empty argument
    try testing.expectEqualStrings("", one.next().?);
    try testing.expectEqual(@as(?[]const u8, null), one.next());
}

test "parseCgroups: v2 capture, v1 lines, colons in the path, junk" {
    const a = try parseCgroups(testing.allocator, real_cgroup);
    defer a.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), a.entries.len);
    try testing.expectEqual(@as(u32, 0), a.entries[0].hierarchy_id);
    try testing.expectEqualStrings("", a.entries[0].controllers);
    try testing.expect(std.mem.startsWith(u8, a.entries[0].path, "/user.slice/user-1000.slice/"));

    const v1 = "12:cpu,cpuacct:/docker/abc\n11:pids:/a:b:c\n1:name=systemd:/\n0::/x (deleted)\nbad\nx:y:/z\n5::\n";
    const b = try parseCgroups(testing.allocator, v1);
    defer b.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 5), b.entries.len);
    try testing.expectEqual(@as(u32, 12), b.entries[0].hierarchy_id);
    try testing.expectEqualStrings("cpu,cpuacct", b.entries[0].controllers);
    var ci = b.entries[0].controllerIterator();
    try testing.expectEqualStrings("cpu", ci.next().?);
    try testing.expectEqualStrings("cpuacct", ci.next().?);
    try testing.expectEqualStrings("/a:b:c", b.entries[1].path);
    try testing.expectEqualStrings("name=systemd", b.entries[2].controllers);
    try testing.expectEqualStrings("/x (deleted)", b.entries[3].path);
    try testing.expectEqualStrings("", b.entries[4].path);

    const e = try parseCgroups(testing.allocator, "");
    defer e.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), e.entries.len);
}

// ── live readers against this process ────────────────────────────────────────

test "live: readPidLimits / readPidIo / readPidStatus / cmdline / cgroup for self" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const lim = readPidLimits(io, .self) orelse return error.SkipZigTest;
    try testing.expectEqual(@as(u32, 0), lim.skipped_rows);
    try testing.expect(lim.get(.open_files) != null);
    // Compare against the kernel's own answer: getrlimit(RLIMIT_NOFILE).
    const rl = try std.posix.getrlimit(.NOFILE);
    const want: ?u64 = if (rl.cur == std.math.maxInt(@TypeOf(rl.cur))) null else rl.cur;
    try testing.expectEqual(want, lim.maxOpenFiles());

    if (readPidIo(io, .self)) |pio| {
        try testing.expect(pio.fields >= 4);
        try testing.expect(pio.rchar > 0); // this test binary has read files
    }

    const st = readPidStatus(io, .self) orelse return error.SkipZigTest;
    const my_pid: u64 = @intCast(std.os.linux.getpid());
    try testing.expectEqual(my_pid, st.pid);
    try testing.expect(st.vm_rss > 0);
    try testing.expect(st.vm_rss <= st.vm_hwm);
    try testing.expect(st.threads >= 1);
    try testing.expectEqual(@as(u64, std.os.linux.getuid()), st.uids[0]);
    try testing.expect(st.cpus_allowed_count >= 1);
    try testing.expect(!st.truncated);
    try testing.expect(st.name().len > 0);
    // status VmRSS agrees with stat's rss * page size to within a few pages' churn
    // (not under qemu-user, whose `/proc/self/stat` is synthetic: vsize and rss 0).
    const ps = procnet.readPidStat(io, .self).?;
    if (ps.vsize != 0) {
        const a = st.vm_rss;
        const b = ps.residentBytesNow();
        try testing.expect(@max(a, b) - @min(a, b) < 4 * 1024 * 1024);
    }

    const cl = readPidCmdline(testing.allocator, io, .self) orelse return error.SkipZigTest;
    defer cl.deinit(testing.allocator);
    var ai = cl.args();
    const argv0 = ai.next() orelse return error.SkipZigTest; // (a sandbox may hide it)
    try testing.expect(argv0.len > 0);
    try testing.expect(!cl.truncated);
    try testing.expectEqual(@as(u8, 0), cl.bytes[cl.bytes.len - 1]); // NUL-terminated
    // The same blob, read by explicit pid.
    const by_pid = readPidCmdline(testing.allocator, io, .{ .pid = @intCast(my_pid) }).?;
    defer by_pid.deinit(testing.allocator);
    try testing.expectEqualStrings(cl.bytes, by_pid.bytes);

    if (try readPidCgroups(testing.allocator, io, .self)) |cg| {
        defer cg.deinit(testing.allocator);
        try testing.expect(cg.entries.len >= 1);
    }
}

test "countFds: tracks descriptors this process opens" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const before = countFds(io, .self) orelse return error.SkipZigTest;
    try testing.expect(before >= 1);
    var files: [5]std.Io.File = undefined;
    var opened: usize = 0;
    defer for (files[0..opened]) |f| f.close(io);
    while (opened < files.len) : (opened += 1)
        files[opened] = try std.Io.Dir.cwd().openFile(io, "/dev/null", .{});
    const after = countFds(io, .self).?;
    try testing.expectEqual(before + 5, after);

    // The same count by pid; and against a manual listing (which holds one
    // more descriptor, its own).
    const my_pid: u32 = @intCast(std.os.linux.getpid());
    try testing.expectEqual(after, countFds(io, .{ .pid = my_pid }).?);
    var dir = try std.Io.Dir.cwd().openDir(io, "/proc/self/fd", .{ .iterate = true });
    defer dir.close(io);
    var manual: u64 = 0;
    var it = dir.iterate();
    while (try it.next(io)) |_| manual += 1;
    try testing.expect(manual == after or manual == after + 1);

    try testing.expectEqual(@as(?u64, null), countFds(io, .{ .pid = 4_294_967_000 }));
}

test "parseLimits: a label must end at a word boundary; soft and hard are told apart" {
    const glued = parseLimits("Max open files5 6 7\n");
    try testing.expect(glued.get(.open_files) == null);
    try testing.expectEqual(@as(u32, 1), glued.skipped_rows);

    const l = parseLimits("Limit Soft Limit Hard Limit Units\n" ++
        "Max open files            1024                 4096                 files\n" ++
        "Max address space         unlimited            8192                 bytes\n");
    try testing.expectEqual(@as(?u64, 1024), l.maxOpenFiles());
    try testing.expect(l.maxAddressSpace() == null);
    try testing.expectEqual(@as(?u64, 8192), l.get(.address_space).?.hard);
    try testing.expectEqual(@as(?u64, 4096), l.get(.open_files).?.hard);
    try testing.expectEqual(@as(u32, 0), l.skipped_rows);
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
