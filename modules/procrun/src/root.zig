// SPDX-License-Identifier: MIT
//! procrun — subprocess runner with a reap-race-tolerant wait, deadlock-free
//! capped stdio capture, and env/cwd/timeout/signal control.
//!
//! The hard core is the *reap-race-tolerant* wait. In a host process where a
//! sibling thread calls `wait4(-1)` (reaps ANY child — e.g. a language VM's
//! exit-code handler, or a shell that left `SIGCHLD` as `SIG_IGN` so the kernel
//! auto-reaps), our child can be reaped out from under us. Zig 0.16's
//! `std.process.Child.wait` treats the resulting `ECHILD` as an `errnoBug`
//! (double-free) and panics. `waitTolerant` reaps via a path that maps `ECHILD`
//! to `.unknown` (child gone, status unreadable) and closes the child's stdio
//! handles manually, so it never panics.
//!
//! Capture is deadlock-free: stdin is written from its own thread while stdout
//! and stderr drain from theirs, so a stdin body larger than the pipe buffer
//! cannot deadlock against a child that withholds stdout until it has consumed
//! stdin. Draining is capped but non-lossy at the boundary — it KEEPS the
//! prefix up to `max_output_bytes` and keeps reading past the cap (so the child
//! can flush and exit), reporting truncation rather than discarding everything
//! the way `std.process.run`'s `error.StreamTooLong` does.

const std = @import("std");
const builtin = @import("builtin");
const argsafe = @import("argsafe");

pub const meta = .{
    .platform = .any, // full behavior on POSIX; Windows compiles (reap-race is POSIX-only)
    .role = .util,
    .concurrency = .reentrant, // no shared module state (aside from the SIGCHLD-fixup guard)
    .model_after = "Python subprocess.run/Popen; Go os/exec",
    .deps = .{"argsafe"}, // opt-in argv sanitization, see runValidated/buildValidatedArgv
};

// ── public types ──────────────────────────────────────────────────────────

/// Re-exported so callers get the exit status losslessly (`.exited` code,
/// `.signal`/`.stopped` `std.posix.SIG`, or `.unknown` raw status) instead of
/// a lossy re-encoding to `i32`.
pub const Term = std.process.Child.Term;

/// Default per-stream capture cap. A child may emit more; the prefix up to this
/// many bytes is kept and `truncated_*` is set.
pub const default_max_output_bytes: usize = 64 * 1024 * 1024;

/// Default number of un-acked stdout chunks a streaming consumer may fall
/// behind by before the reader thread blocks (see `Handle.ack`).
pub const default_stream_permits: usize = 32;

/// How a child's standard stream is wired.
pub const StdioMode = enum {
    /// Spawn the child with the stream closed (advanced; child may hit EBADF).
    close,
    /// Share the parent's stream.
    inherit,
    /// Create a pipe. For stdout/stderr this enables capture; for stdin it
    /// enables writing `stdin_body`.
    pipe,
};

/// How the child's environment is derived.
pub const EnvMode = enum {
    /// Child inherits the parent environment; `Spec.env` is ignored.
    inherit,
    /// Child gets ONLY `Spec.env` (empty if `env == null`).
    clear,
    /// Child gets the parent environment with `Spec.env` overlaid on top.
    /// The parent snapshot is read libc-free from `/proc/self/environ` on
    /// Linux and from the PEB on Windows; on other POSIX targets (no
    /// `/proc`) the parent snapshot may be empty — prefer `.clear` there.
    merge,
};

/// A process to run. `argv[0]` is resolved via `PATH` if it has no '/' —
/// prefer an absolute `argv[0]` when the caller controls it, to avoid PATH-
/// resolution ambiguity entirely. Note that this PATH lookup ALWAYS reads
/// from the real parent process environment, regardless of `env_mode`: even
/// under `.clear` (child gets only `Spec.env`) or `.merge`, the `PATH` used
/// to resolve `argv[0]` is the parent's actual `PATH`, not whatever `PATH`
/// ends up in the child's environment (`std.process.SpawnOptions.
/// environ_map`'s `PATH` is never consulted for this resolution).
pub const Spec = struct {
    argv: []const []const u8,
    /// Overriding / explicit environment. Interpreted per `env_mode`.
    env: ?*const std.process.Environ.Map = null,
    env_mode: EnvMode = .inherit,
    /// Working directory for the child; null = inherit the parent's.
    cwd: ?[]const u8 = null,
    stdin: StdioMode = .close,
    stdout: StdioMode = .pipe,
    stderr: StdioMode = .pipe,
    /// Per-stream capture cap for `run`/`runTimeout`.
    max_output_bytes: usize = default_max_output_bytes,
    /// Backpressure permit count for `spawnStreaming` (stdout only).
    stream_permits: usize = default_stream_permits,
    /// Spawn the child as the leader of its own process group
    /// (`setpgid(0, 0)`, applied by the kernel between fork and exec)
    /// instead of inheriting the parent's group. Needed for
    /// `Handle.killGroup`/`cancelGroup`/`signalGroup` and for `runTimeout`'s
    /// deadline kill to reach descendants the child forks on its own (e.g.
    /// `sh -c 'long-runner &'`) — those grandchildren stay in the group the
    /// kernel assigns them at fork (their parent's), so a signal to `-pgid`
    /// reaches the whole tree, unlike a signal to the direct child alone.
    /// Since `setpgid(0, 0)` makes the new group id equal the child's own
    /// pid, no separate id needs to be tracked. POSIX-only; has no effect on
    /// Windows (no process-group concept exposed here).
    new_process_group: bool = false,
    /// Optional rlimit sandbox applied to the child before it execs the
    /// caller's program — see `RlimitSpec`. `null` (default) applies no
    /// limits. POSIX-only; `error.OperationUnsupported` on Windows.
    rlimit: ?RlimitSpec = null,
};

/// rlimit knobs applied to the child before it execs the real program (see
/// `Spec.rlimit`). Each field is optional; an unset field leaves that
/// resource at whatever the child would otherwise inherit. POSIX-only.
///
/// Implementation note: `std.process.spawn` (the `Io.Threaded` POSIX
/// backend) has no post-fork/pre-exec hook to run arbitrary code in the
/// child, so this is applied by inserting a small `/bin/sh -c '<ulimit
/// ...>; exec "$@"'` wrapper in front of `Spec.argv` — the IMMEDIATE child
/// (the shell) sets its own limits via the POSIX `ulimit` builtin (itself a
/// thin wrapper over `setrlimit`), which POSIX guarantees are inherited
/// across `exec`, then the shell replaces itself with the real program
/// image. `Spec.argv`'s elements are passed to the shell as positional
/// parameters (`"$@"`) — never re-parsed as shell syntax — so this
/// introduces no shell-injection surface; only the numeric limit VALUES
/// (formatted by this module, never caller-supplied text) are embedded in
/// the generated script.
pub const RlimitSpec = struct {
    /// `RLIMIT_CPU`, seconds. The kernel delivers `SIGXCPU` once the
    /// process's cumulative CPU time reaches the limit (default
    /// disposition: terminate).
    cpu_seconds: ?u64 = null,
    /// `RLIMIT_AS`, bytes. Caps total virtual address space; further
    /// allocation (mmap/brk) fails with `ENOMEM` once reached. Rounded UP
    /// to the whole kilobytes `ulimit -v` takes, so the requested byte cap
    /// is never silently loosened.
    address_space_bytes: ?u64 = null,
    /// `RLIMIT_NOFILE`, count. Caps simultaneously open file descriptors.
    open_files: ?u64 = null,
    /// `RLIMIT_FSIZE`, bytes. Caps the size of any file the process writes;
    /// exceeding it delivers `SIGXFSZ` (default disposition: terminate) on
    /// the write that would cross the limit. Rounded UP to the whole
    /// 512-byte blocks `ulimit -f` takes, so the requested byte cap is
    /// never silently loosened.
    file_size_bytes: ?u64 = null,
};

/// Result of a blocking `run`/`runTimeout`. Caller owns `stdout`/`stderr`.
pub const Output = struct {
    term: Term,
    stdout: []u8,
    stderr: []u8,
    /// Child emitted more than `max_output_bytes` on the respective stream;
    /// the returned slice is the kept prefix.
    truncated_stdout: bool,
    truncated_stderr: bool,

    pub fn deinit(self: *Output, gpa: std.mem.Allocator) void {
        gpa.free(self.stdout);
        gpa.free(self.stderr);
        self.* = undefined;
    }
};

// ── SIGCHLD reaping fixup ───────────────────────────────────────────────────

var reaping_guard = std.atomic.Value(bool).init(false);

/// Ensure the process's `SIGCHLD` disposition lets `waitpid` observe exited
/// children. If the disposition is inherited as `SIG_IGN`, the kernel
/// auto-reaps every child and every later `waitpid` returns `ECHILD`; we flip
/// ONLY `SIG_IGN` → `SIG_DFL`. A real installed handler is left untouched (a
/// handler without `SA_NOCLDWAIT` still leaves children reapable). Idempotent,
/// threadsafe, and a no-op on Windows. Called automatically before every spawn;
/// exposed for callers who fork/spawn children by other means.
pub fn ensureChildReaping() void {
    switch (builtin.os.tag) {
        .windows => {},
        else => if (!reaping_guard.swap(true, .acq_rel)) restoreChildReaping(),
    }
}

fn restoreChildReaping() void {
    switch (builtin.os.tag) {
        .windows => {},
        else => {
            const posix = std.posix;
            var current: posix.Sigaction = undefined;
            posix.sigaction(posix.SIG.CHLD, null, &current);
            if (current.handler.handler == posix.SIG.IGN) {
                const act: posix.Sigaction = .{
                    .handler = .{ .handler = posix.SIG.DFL },
                    .mask = posix.sigemptyset(),
                    .flags = 0,
                };
                posix.sigaction(posix.SIG.CHLD, &act, null);
            }
        },
    }
}

// ── reap-race-tolerant wait ─────────────────────────────────────────────────

const have_wait4 = switch (builtin.os.tag) {
    .linux => @hasField(std.os.linux.SYS, "wait4"),
    .dragonfly, .freebsd, .netbsd, .openbsd, .illumos, .serenity, .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => true,
    else => false,
};

/// A `Child.wait` that survives the child being reaped out-of-band by another
/// in-process `wait4(-1)` waiter. On POSIX we reap the pid ourselves through a
/// path that maps `ECHILD` to `.unknown` (rather than the panic `Child.wait`
/// would raise) and close the child's still-open pipe ends manually. On Windows
/// there is no `wait4(-1)` reaper, so we defer to std.
///
/// Design decision: we use `std.posix.system.wait4`/`waitpid` (the same syscall
/// interface std itself uses) rather than `std.c.waitpid`. On Linux
/// `posix.system` is `std.os.linux`, i.e. raw syscalls — so this stays
/// libc-free, which is the whole point of the workspace. `std.posix.waitpid`
/// does not exist in 0.16, and `std.process.Child.wait` deliberately panics on
/// `ECHILD`, so a hand-rolled reap is unavoidable.
pub fn waitTolerant(io: std.Io, child: *std.process.Child) Term {
    switch (builtin.os.tag) {
        .windows => return child.wait(io) catch Term{ .unknown = 0 },
        else => {
            const term: Term = if (child.id) |pid| reapTolerantPosix(pid) else .{ .unknown = 0 };
            // Mark reaped so a later std `kill`/`wait` is a safe no-op, and
            // close any pipe ends we still own (the new Child no longer
            // auto-closes them the way the old blocking wait did).
            child.id = null;
            if (child.stdin) |f| {
                f.close(io);
                child.stdin = null;
            }
            if (child.stdout) |f| {
                f.close(io);
                child.stdout = null;
            }
            if (child.stderr) |f| {
                f.close(io);
                child.stderr = null;
            }
            return term;
        },
    }
}

fn reapTolerantPosix(pid: std.posix.pid_t) Term {
    const posix = std.posix;
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    if (have_wait4) {
        while (true) switch (posix.errno(posix.system.wait4(pid, &status, 0, null))) {
            .SUCCESS => return statusToTerm(@bitCast(status)),
            .INTR => continue,
            // Reaped out-of-band (or auto-reaped): child is gone but its status
            // is unreadable. This is the case std would panic on.
            .CHILD => return .{ .unknown = 0 },
            else => return .{ .unknown = 0 },
        };
    }
    while (true) switch (posix.errno(posix.system.waitpid(pid, &status, 0))) {
        .SUCCESS => return statusToTerm(@bitCast(status)),
        .INTR => continue,
        .CHILD => return .{ .unknown = 0 },
        else => return .{ .unknown = 0 },
    };
}

fn statusToTerm(status: u32) Term {
    const W = std.posix.W;
    return if (W.IFEXITED(status))
        .{ .exited = W.EXITSTATUS(status) }
    else if (W.IFSIGNALED(status))
        .{ .signal = W.TERMSIG(status) }
    else if (W.IFSTOPPED(status))
        .{ .stopped = W.STOPSIG(status) }
    else
        .{ .unknown = status };
}

// ── signal delivery ─────────────────────────────────────────────────────────

const SigKind = enum { term, kill, raw };

fn deliver(child: *std.process.Child, kind: SigKind, raw: u8) void {
    const id = child.id orelse return;
    switch (builtin.os.tag) {
        .windows => {
            const K = struct {
                extern "kernel32" fn TerminateProcess(h: std.os.windows.HANDLE, code: std.os.windows.UINT) callconv(.winapi) std.os.windows.BOOL;
            };
            _ = K.TerminateProcess(id, 1);
        },
        else => {
            const sig: std.posix.SIG = switch (kind) {
                .term => .TERM,
                .kill => .KILL,
                .raw => @enumFromInt(raw),
            };
            std.posix.kill(id, sig) catch {};
        },
    }
}

/// Like `deliver`, but signals the child's entire process GROUP
/// (`kill(-pgid, sig)`) instead of just the direct child, reaching
/// descendants the child forked into the same group (e.g. a shell's
/// background jobs). Only takes effect if `grouped` is true (i.e.
/// `Spec.new_process_group` was set at spawn time, so the group id is
/// known to equal the child's own pid) — otherwise a documented no-op, so a
/// caller can never accidentally signal ITS OWN process group (which the
/// child would still belong to without `new_process_group`). Falls back to
/// `deliver` on Windows, which has no POSIX process-group concept.
fn deliverGroup(child: *std.process.Child, kind: SigKind, raw: u8, grouped: bool) void {
    if (!grouped) return;
    switch (builtin.os.tag) {
        .windows => deliver(child, kind, raw),
        else => {
            const id = child.id orelse return;
            const sig: std.posix.SIG = switch (kind) {
                .term => .TERM,
                .kill => .KILL,
                .raw => @enumFromInt(raw),
            };
            std.posix.kill(-id, sig) catch {};
        },
    }
}

// ── spawn helper ────────────────────────────────────────────────────────────

fn toStdIo(m: StdioMode) std.process.SpawnOptions.StdIo {
    return switch (m) {
        .close => .close,
        .inherit => .inherit,
        .pipe => .pipe,
    };
}

fn spawnChild(gpa: std.mem.Allocator, io: std.Io, spec: Spec) !std.process.Child {
    var env_holder: ?std.process.Environ.Map = null;
    defer if (env_holder) |*m| m.deinit();

    const env_ptr: ?*const std.process.Environ.Map = switch (spec.env_mode) {
        .inherit => null,
        .clear => blk: {
            var m = std.process.Environ.Map.init(gpa);
            errdefer m.deinit();
            if (spec.env) |src| try copyEnv(&m, src);
            env_holder = m;
            break :blk &env_holder.?;
        },
        .merge => blk: {
            var m = std.process.Environ.Map.init(gpa);
            errdefer m.deinit();
            try loadParentEnv(gpa, io, &m);
            if (spec.env) |src| try copyEnv(&m, src);
            env_holder = m;
            break :blk &env_holder.?;
        },
    };

    const cwd: std.process.Child.Cwd = if (spec.cwd) |p| .{ .path = p } else .inherit;

    // rlimit sandbox: wrap argv through a small ulimit-then-exec shell (see
    // `RlimitSpec`). The wrapper's own storage only needs to stay alive for
    // the duration of the spawn call below (fork+exec is synchronous), so it
    // is freed via `defer` right here rather than escaping this function.
    var rlimit_wrap: ?RlimitWrap = null;
    defer if (rlimit_wrap) |*w| w.deinit(gpa);
    const effective_argv: []const []const u8 = blk: {
        const r = spec.rlimit orelse break :blk spec.argv;
        if (builtin.os.tag == .windows) return error.OperationUnsupported;
        rlimit_wrap = try buildRlimitWrap(gpa, spec.argv, r);
        break :blk rlimit_wrap.?.argv;
    };

    // fd-hygiene note: any parent fd NOT marked FD_CLOEXEC is inherited by
    // the child across this spawn — `Spec` only controls stdin/stdout/stderr
    // (`StdioMode`), it does not close arbitrary other open fds. Callers that
    // hold sensitive fds open (sockets, secret-bearing files, …) must set
    // FD_CLOEXEC on them themselves if the child must not inherit them.
    return std.process.spawn(io, .{
        .argv = effective_argv,
        .cwd = cwd,
        .environ_map = env_ptr,
        .stdin = toStdIo(spec.stdin),
        .stdout = toStdIo(spec.stdout),
        .stderr = toStdIo(spec.stderr),
        .create_no_window = true,
        .pgid = if (spec.new_process_group) 0 else null,
    });
}

const RlimitWrap = struct {
    /// `["/bin/sh", "-c", script, "sh", <spec.argv...>]`. `argv[2]` (the
    /// script) borrows `script`'s storage; every other element borrows
    /// either a literal or the caller's `spec.argv`.
    argv: []const []const u8,
    script: []u8,

    fn deinit(w: *RlimitWrap, gpa: std.mem.Allocator) void {
        gpa.free(w.argv);
        gpa.free(w.script);
    }
};

fn ceilDiv(numerator: u64, denominator: u64) u64 {
    return (numerator + denominator - 1) / denominator;
}

/// Builds the `/bin/sh -c '<ulimit ...>; exec "$@"' sh <argv...>` wrapper
/// documented on `RlimitSpec`. `sh`'s `ulimit` takes `-f` in 512-byte blocks
/// and `-v` in kilobytes (POSIX/dash/bash agree on this); `-t` (seconds) and
/// `-n` (fd count) are unit-for-unit. Each `ulimit` call is guarded with
/// `|| exit 121` so a platform that rejects a particular limit fails the
/// spawn loudly (surfacing as a non-.exited `Term`) instead of silently
/// running unsandboxed.
fn buildRlimitWrap(gpa: std.mem.Allocator, argv: []const []const u8, r: RlimitSpec) !RlimitWrap {
    var script: std.ArrayList(u8) = .empty;
    errdefer script.deinit(gpa);
    if (r.cpu_seconds) |v| try script.print(gpa, "ulimit -t {d} || exit 121\n", .{v});
    if (r.file_size_bytes) |v| try script.print(gpa, "ulimit -f {d} || exit 121\n", .{ceilDiv(v, 512)});
    if (r.address_space_bytes) |v| try script.print(gpa, "ulimit -v {d} || exit 121\n", .{ceilDiv(v, 1024)});
    if (r.open_files) |v| try script.print(gpa, "ulimit -n {d} || exit 121\n", .{v});
    try script.print(gpa, "exec \"$@\"\n", .{});

    // Finalize the script buffer BEFORE it is referenced from `wrapped`:
    // `toOwnedSlice` is permitted to reallocate-and-copy (not just shrink
    // in place) if the allocator's `remap` declines, which would leave a
    // slice captured from `script.items` beforehand dangling.
    const script_owned = try script.toOwnedSlice(gpa);
    errdefer gpa.free(script_owned);

    var wrapped: std.ArrayList([]const u8) = .empty;
    errdefer wrapped.deinit(gpa);
    try wrapped.append(gpa, "/bin/sh");
    try wrapped.append(gpa, "-c");
    try wrapped.append(gpa, script_owned);
    try wrapped.append(gpa, "sh"); // becomes $0 inside the script; exec "$@" starts at spec.argv[0]
    try wrapped.appendSlice(gpa, argv);

    return .{ .argv = try wrapped.toOwnedSlice(gpa), .script = script_owned };
}

fn copyEnv(dst: *std.process.Environ.Map, src: *const std.process.Environ.Map) !void {
    var it = src.iterator();
    while (it.next()) |e| try dst.put(e.key_ptr.*, e.value_ptr.*);
}

fn loadParentEnv(gpa: std.mem.Allocator, io: std.Io, map: *std.process.Environ.Map) !void {
    switch (builtin.os.tag) {
        .windows => {
            const env: std.process.Environ = .{ .block = .global };
            var parent = try env.createMap(gpa);
            defer parent.deinit();
            try copyEnv(map, &parent);
        },
        else => {
            // /proc/self/environ is the libc-free way to read the ambient
            // environment without an `Init`. Absent on non-Linux POSIX → the
            // parent snapshot is simply empty (documented on EnvMode.merge).
            var file = std.Io.Dir.cwd().openFile(io, "/proc/self/environ", .{}) catch return;
            defer file.close(io);
            var rbuf: [4096]u8 = undefined;
            var reader = file.reader(io, &rbuf);
            const data = reader.interface.allocRemaining(gpa, .unlimited) catch return;
            defer gpa.free(data);
            var it = std.mem.splitScalar(u8, data, 0);
            while (it.next()) |entry| {
                if (entry.len == 0) continue;
                const eq = std.mem.indexOfScalar(u8, entry, '=') orelse continue;
                if (eq == 0) continue;
                try map.put(entry[0..eq], entry[eq + 1 ..]);
            }
        },
    }
}

// ── capped, deadlock-free stdio pumps ───────────────────────────────────────

const Drainer = struct {
    io: std.Io,
    file: std.Io.File,
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    cap: usize,
    truncated: *std.atomic.Value(bool),
    err: *?anyerror,
};

fn drainLoop(d: Drainer) void {
    defer d.file.close(d.io);
    var rbuf: [8192]u8 = undefined;
    while (true) {
        const n = d.file.readStreaming(d.io, &.{rbuf[0..]}) catch return;
        if (n == 0) return;
        const have = d.list.items.len;
        if (have >= d.cap) {
            // Keep draining past the cap so the child can flush + exit, but
            // store nothing more.
            d.truncated.store(true, .release);
            continue;
        }
        const take = @min(n, d.cap - have);
        d.list.appendSlice(d.gpa, rbuf[0..take]) catch |e| {
            d.err.* = e;
            return;
        };
        if (take < n) d.truncated.store(true, .release);
    }
}

const WriteJob = struct {
    io: std.Io,
    file: std.Io.File,
    data: []const u8,
    err: *?anyerror,
};

fn writeLoop(w: WriteJob) void {
    defer w.file.close(w.io);
    w.file.writeStreamingAll(w.io, w.data) catch |e| {
        w.err.* = e;
    };
}

/// Owns the up-to-three pump threads for a blocking run. Lives on the caller's
/// stack; the threads hold pointers into it and are always joined before it
/// goes out of scope.
const Pumps = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    child: *std.process.Child,
    out_list: std.ArrayList(u8) = .empty,
    err_list: std.ArrayList(u8) = .empty,
    trunc_out: std.atomic.Value(bool) = .init(false),
    trunc_err: std.atomic.Value(bool) = .init(false),
    out_err: ?anyerror = null,
    err_err: ?anyerror = null,
    in_err: ?anyerror = null,
    t_out: ?std.Thread = null,
    t_err: ?std.Thread = null,
    t_in: ?std.Thread = null,

    /// Transfer each piped stdio handle to its own thread. On a thread-spawn
    /// failure, force the child down so any threads already started hit EOF,
    /// join them, and propagate the error — never leaving a detached thread
    /// writing into buffers the caller is about to free.
    fn start(p: *Pumps, cap: usize, stdin_body: []const u8) !void {
        p.startInner(cap, stdin_body) catch |e| {
            p.child.kill(p.io);
            p.join();
            return e;
        };
    }

    fn startInner(p: *Pumps, cap: usize, stdin_body: []const u8) !void {
        const child = p.child;
        if (child.stdout) |f| {
            child.stdout = null; // transfer ownership; drainer closes it
            p.t_out = std.Thread.spawn(.{}, drainLoop, .{Drainer{
                .io = p.io,
                .file = f,
                .gpa = p.gpa,
                .list = &p.out_list,
                .cap = cap,
                .truncated = &p.trunc_out,
                .err = &p.out_err,
            }}) catch |e| {
                f.close(p.io);
                return e;
            };
        }
        if (child.stderr) |f| {
            child.stderr = null;
            p.t_err = std.Thread.spawn(.{}, drainLoop, .{Drainer{
                .io = p.io,
                .file = f,
                .gpa = p.gpa,
                .list = &p.err_list,
                .cap = cap,
                .truncated = &p.trunc_err,
                .err = &p.err_err,
            }}) catch |e| {
                f.close(p.io);
                return e;
            };
        }
        if (child.stdin) |f| {
            child.stdin = null;
            p.t_in = std.Thread.spawn(.{}, writeLoop, .{WriteJob{
                .io = p.io,
                .file = f,
                .data = stdin_body,
                .err = &p.in_err,
            }}) catch |e| {
                f.close(p.io);
                return e;
            };
        }
    }

    fn join(p: *Pumps) void {
        if (p.t_in) |t| t.join();
        if (p.t_out) |t| t.join();
        if (p.t_err) |t| t.join();
    }

    fn firstErr(p: *Pumps) ?anyerror {
        if (p.in_err) |e| return e;
        if (p.out_err) |e| return e;
        if (p.err_err) |e| return e;
        return null;
    }

    fn deinit(p: *Pumps) void {
        p.out_list.deinit(p.gpa);
        p.err_list.deinit(p.gpa);
    }
};

// ── blocking run ────────────────────────────────────────────────────────────

/// Spawn `spec`, write `stdin_body` (only if `spec.stdin == .pipe`), capture
/// stdout/stderr up to `spec.max_output_bytes`, and wait reap-race-tolerantly.
/// Caller owns `Output.stdout`/`Output.stderr` (`Output.deinit`).
pub fn run(gpa: std.mem.Allocator, io: std.Io, spec: Spec, stdin_body: []const u8) !Output {
    ensureChildReaping();
    var child = try spawnChild(gpa, io, spec);
    errdefer child.kill(io);

    var pumps: Pumps = .{ .io = io, .gpa = gpa, .child = &child };
    errdefer pumps.deinit();
    try pumps.start(spec.max_output_bytes, stdin_body);
    pumps.join();

    if (pumps.firstErr()) |e| return e;
    const term = waitTolerant(io, &child);
    return finish(&pumps, term);
}

/// Like `run`, but if the child has not finished within `timeout_ns` it is
/// SIGKILL'd (TerminateProcess on Windows) and reaped. On timeout the returned
/// `Output.term` is `.signal` (SIGKILL); the partial output captured so far is
/// still returned.
pub fn runTimeout(
    gpa: std.mem.Allocator,
    io: std.Io,
    spec: Spec,
    stdin_body: []const u8,
    timeout_ns: u64,
) !Output {
    ensureChildReaping();
    var child = try spawnChild(gpa, io, spec);
    errdefer child.kill(io);

    var pumps: Pumps = .{ .io = io, .gpa = gpa, .child = &child };
    errdefer pumps.deinit();
    try pumps.start(spec.max_output_bytes, stdin_body);

    var done = std.atomic.Value(bool).init(false);
    const killer = try std.Thread.spawn(.{}, killerLoop, .{KillJob{
        .child = &child,
        .timeout_ns = timeout_ns,
        .done = &done,
        .grouped = spec.new_process_group,
    }});

    // Pumps finish when the child exits — naturally, or because the killer
    // forced it. Then stop the killer BEFORE reaping so no signal can race a
    // reaped (and possibly reused) pid.
    pumps.join();
    done.store(true, .release);
    killer.join();

    if (pumps.firstErr()) |e| return e;
    const term = waitTolerant(io, &child);
    return finish(&pumps, term);
}

fn finish(pumps: *Pumps, term: Term) !Output {
    const out = try pumps.out_list.toOwnedSlice(pumps.gpa);
    errdefer pumps.gpa.free(out);
    const err = try pumps.err_list.toOwnedSlice(pumps.gpa);
    return .{
        .term = term,
        .stdout = out,
        .stderr = err,
        .truncated_stdout = pumps.trunc_out.load(.acquire),
        .truncated_stderr = pumps.trunc_err.load(.acquire),
    };
}

const KillJob = struct {
    child: *std.process.Child,
    timeout_ns: u64,
    done: *std.atomic.Value(bool),
    /// Kill the child's whole process group instead of just the child
    /// itself — set from `Spec.new_process_group`; see `deliverGroup`.
    grouped: bool = false,
};

fn killerLoop(j: KillJob) void {
    const step: u64 = 5 * std.time.ns_per_ms;
    var slept: u64 = 0;
    while (slept < j.timeout_ns) {
        if (j.done.load(.acquire)) return;
        const chunk = @min(step, j.timeout_ns - slept);
        sleepNs(chunk);
        slept += chunk;
    }
    if (j.done.load(.acquire)) return;
    if (j.grouped) deliverGroup(j.child, .kill, 0, true) else deliver(j.child, .kill, 0);
}

fn sleepNs(ns: u64) void {
    switch (builtin.os.tag) {
        .windows => {
            const K = struct {
                extern "kernel32" fn Sleep(ms: std.os.windows.DWORD) callconv(.winapi) void;
            };
            K.Sleep(@intCast((ns + std.time.ns_per_ms - 1) / std.time.ns_per_ms));
        },
        else => {
            var req: std.posix.timespec = .{
                .sec = @intCast(ns / std.time.ns_per_s),
                .nsec = @intCast(ns % std.time.ns_per_s),
            };
            while (true) {
                var rem: std.posix.timespec = undefined;
                if (std.posix.errno(std.posix.system.nanosleep(&req, &rem)) == .INTR) {
                    req = rem;
                    continue;
                }
                return;
            }
        },
    }
}

// ── argsafe integration (opt-in) ────────────────────────────────────────────

/// Opt-in `argsafe` integration (see module SPEC "Threat model"): ordinary
/// `run`/`runTimeout`/`spawnStreaming` do NOT validate `Spec.argv` — it is
/// trusted-by-construction per module convention, the caller's
/// responsibility. `runValidated`/`buildValidatedArgv` are for callers
/// assembling a child's argv from untrusted input (e.g. request parameters)
/// who want the `argsafe` discipline (reject flag-injection / NUL / control
/// bytes / `..`, per `program_ok`/`args_ok`) applied uniformly, with the
/// rejection surfacing as `argsafe.Error.Rejected` BEFORE any process is
/// spawned, rather than hand-rolling the check at every call site.
///
/// `program` (argv[0]) and `args` (argv[1..]) are validated against separate
/// predicates because they typically have different shapes — `program` is
/// often an absolute path (`argsafe.isSafePath`) while `args` are identifiers
/// / values (`argsafe.isSafeIdentifier`, `argsafe.isSafeKvValue`, a
/// `CharClass.predicate()`, …). Pass the same predicate for both if that
/// distinction doesn't apply.
pub fn buildValidatedArgv(
    gpa: std.mem.Allocator,
    program: []const u8,
    program_ok: *const fn ([]const u8) bool,
    args: []const []const u8,
    args_ok: *const fn ([]const u8) bool,
) (argsafe.Error || std.mem.Allocator.Error)![]const []const u8 {
    if (!program_ok(program)) return argsafe.Error.Rejected;
    for (args) |a| {
        if (!args_ok(a)) return argsafe.Error.Rejected;
    }

    const full = try gpa.alloc([]const u8, args.len + 1);
    errdefer gpa.free(full);
    full[0] = program;
    @memcpy(full[1..], args);
    return full;
}

/// `run`, but `spec_rest.argv` is ignored and instead built from `program` +
/// `args` via `buildValidatedArgv` — see its docs. Spawns nothing if
/// validation rejects a token.
pub fn runValidated(
    gpa: std.mem.Allocator,
    io: std.Io,
    program: []const u8,
    program_ok: *const fn ([]const u8) bool,
    args: []const []const u8,
    args_ok: *const fn ([]const u8) bool,
    spec_rest: Spec,
    stdin_body: []const u8,
) !Output {
    const argv = try buildValidatedArgv(gpa, program, program_ok, args, args_ok);
    defer gpa.free(argv);
    var spec = spec_rest;
    spec.argv = argv;
    return run(gpa, io, spec, stdin_body);
}

// ── streaming run ───────────────────────────────────────────────────────────

/// Native (non-FFI) streaming callbacks. Each fires synchronously on a
/// procrun-owned reader thread; the `chunk` slice is valid only for the
/// duration of the call — copy it if you need it to outlive the callback.
pub const Callbacks = struct {
    ctx: ?*anyopaque = null,
    on_stdout: ?*const fn (ctx: ?*anyopaque, chunk: []const u8) void = null,
    on_stderr: ?*const fn (ctx: ?*anyopaque, chunk: []const u8) void = null,
    /// Fires once from `Handle.wait`, after both reader threads have drained.
    on_exit: ?*const fn (ctx: ?*anyopaque, term: Term) void = null,
};

const StreamCtx = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    child: std.process.Child,
    cb: Callbacks,
    permits: usize,
    sema: std.Io.Semaphore,
    /// Mirrors `Spec.new_process_group` — gates `Handle.*Group` methods so
    /// they can never signal a group the child wasn't actually made leader
    /// of (see `deliverGroup`).
    grouped: bool,
    t_out: ?std.Thread = null,
    t_err: ?std.Thread = null,
};

/// Returned by `Handle.writeStdin`/`closeStdin` when there is no writable
/// stdin pipe left — either `Spec.stdin` was not `.pipe` at spawn time, or
/// it was already closed by a prior `closeStdin` (or by `wait`). Any actual
/// write failure against a still-open pipe (broken pipe because the child
/// exited/closed its end, disk-adjacent errors, …) instead surfaces as its
/// own typed error from the underlying `Io.File` write — most commonly
/// `error.BrokenPipe`.
pub const StdinError = error{StdinUnavailable};

/// A running streaming child. The caller MUST eventually call `wait` exactly
/// once — it joins the reader threads, reaps the child, fires `on_exit`, and
/// frees the handle's state. After `wait` returns, the handle is invalid.
pub const Handle = struct {
    ctx: *StreamCtx,

    /// Ask the child to terminate (SIGTERM; TerminateProcess on Windows).
    pub fn cancel(h: Handle) void {
        deliver(&h.ctx.child, .term, 0);
        wake(h.ctx);
    }

    /// Force the child to terminate now (SIGKILL; TerminateProcess on Windows).
    pub fn kill(h: Handle) void {
        deliver(&h.ctx.child, .kill, 0);
        wake(h.ctx);
    }

    /// Send an arbitrary POSIX signal number. No-op mapping on Windows
    /// (routes to TerminateProcess).
    pub fn signal(h: Handle, sig: u8) void {
        deliver(&h.ctx.child, .raw, sig);
    }

    /// Ask the child's entire process GROUP to terminate (`SIGTERM` to
    /// `-pgid`) rather than just the direct child, reaching descendants the
    /// child forked on its own (e.g. a shell's background jobs). Only takes
    /// effect if `Spec.new_process_group` was set at spawn time; otherwise a
    /// documented no-op — see `grouped`.
    pub fn cancelGroup(h: Handle) void {
        deliverGroup(&h.ctx.child, .term, 0, h.ctx.grouped);
        wake(h.ctx);
    }

    /// Force the child's entire process GROUP to terminate now (`SIGKILL`
    /// to `-pgid`). Only takes effect if `Spec.new_process_group` was set at
    /// spawn time; otherwise a documented no-op — see `grouped`.
    pub fn killGroup(h: Handle) void {
        deliverGroup(&h.ctx.child, .kill, 0, h.ctx.grouped);
        wake(h.ctx);
    }

    /// Send an arbitrary POSIX signal number to the child's entire process
    /// GROUP. Only takes effect if `Spec.new_process_group` was set at spawn
    /// time; otherwise a documented no-op — see `grouped`.
    pub fn signalGroup(h: Handle, sig: u8) void {
        deliverGroup(&h.ctx.child, .raw, sig, h.ctx.grouped);
    }

    /// True iff this child was spawned with `Spec.new_process_group = true`,
    /// i.e. `cancelGroup`/`killGroup`/`signalGroup` will actually reach the
    /// group rather than being a no-op.
    pub fn grouped(h: Handle) bool {
        return h.ctx.grouped;
    }

    /// Release one stdout backpressure permit (call after consuming a chunk).
    pub fn ack(h: Handle) void {
        h.ctx.sema.post(h.ctx.io);
    }

    /// Write to the child's stdin (requires `Spec.stdin = .pipe`). Safe to
    /// call repeatedly over the child's lifetime — unlike `run`'s one-shot
    /// `stdin_body`, this lets a caller stream a request/response protocol
    /// (e.g. an MCP stdio transport) incrementally after spawn. Blocks the
    /// calling thread (not a reader thread) until the whole of `data` is
    /// written or an error occurs; internally loops over partial writes so a
    /// short write never silently drops a suffix. If the child has exited or
    /// closed its stdin, this surfaces as `error.BrokenPipe` (from the
    /// underlying `Io.File` write) rather than blocking or panicking.
    ///
    /// MUST NOT be called concurrently with itself, with `closeStdin`, or
    /// with `wait` (all three touch the same `Io.File` / `child.stdin`
    /// field without a lock — serialize them, e.g. from the thread that owns
    /// the `Handle`) — matches the module's documented `wait`-owns-cleanup
    /// contract.
    pub fn writeStdin(h: Handle, data: []const u8) !void {
        const f = h.ctx.child.stdin orelse return error.StdinUnavailable;
        try f.writeStreamingAll(h.ctx.io, data);
    }

    /// Close the child's stdin, signalling EOF to it (many programs — `cat`,
    /// a line-based protocol — only respond/exit once stdin closes). Safe to
    /// call at most once; a second call is rejected with
    /// `error.StdinUnavailable` rather than double-closing the fd. `wait`
    /// also closes stdin if still open, so calling this before `wait` is
    /// optional — it exists for callers that need EOF delivered BEFORE they
    /// start waiting (e.g. to make the child produce its final output).
    ///
    /// MUST NOT be called concurrently with `writeStdin` or `wait` — see
    /// `writeStdin`.
    pub fn closeStdin(h: Handle) StdinError!void {
        const f = h.ctx.child.stdin orelse return error.StdinUnavailable;
        f.close(h.ctx.io);
        h.ctx.child.stdin = null;
    }

    /// Block until the child exits, then reap + fire `on_exit` + free state.
    pub fn wait(h: Handle) Term {
        const ctx = h.ctx;
        if (ctx.t_out) |t| t.join();
        if (ctx.t_err) |t| t.join();
        const term = waitTolerant(ctx.io, &ctx.child);
        if (ctx.cb.on_exit) |f| f(ctx.cb.ctx, term);
        const gpa = ctx.gpa;
        gpa.destroy(ctx);
        return term;
    }
};

fn wake(ctx: *StreamCtx) void {
    // Unblock a reader parked on the backpressure semaphore so a cancel/kill
    // can't leave it stuck past the child's death.
    var i: usize = 0;
    while (i <= ctx.permits) : (i += 1) ctx.sema.post(ctx.io);
}

/// Spawn `spec` and stream stdout/stderr to `cb` in real time. stdout chunks
/// are subject to `spec.stream_permits` backpressure (the reader blocks until
/// the consumer `ack`s); stderr is delivered unthrottled. Returns a `Handle`
/// the caller must `wait` on.
pub fn spawnStreaming(gpa: std.mem.Allocator, io: std.Io, spec: Spec, cb: Callbacks) !Handle {
    ensureChildReaping();
    const ctx = try gpa.create(StreamCtx);
    errdefer gpa.destroy(ctx);

    // Everything downstream operates on ctx.child (a single owner); the reader
    // threads null its pipe fields as they take them over.
    ctx.* = .{
        .gpa = gpa,
        .io = io,
        .child = try spawnChild(gpa, io, spec),
        .cb = cb,
        .permits = spec.stream_permits,
        .sema = .{ .permits = spec.stream_permits },
        .grouped = spec.new_process_group,
    };
    errdefer ctx.child.kill(io);

    if (ctx.child.stdout != null) {
        ctx.t_out = try std.Thread.spawn(.{}, streamOutLoop, .{ctx});
    }
    errdefer if (ctx.t_out) |t| {
        // On a later failure, force the child down so the reader unblocks
        // (past any backpressure), then join it before the chain kills + frees.
        deliver(&ctx.child, .kill, 0);
        wake(ctx);
        t.join();
    };

    if (ctx.child.stderr != null) {
        ctx.t_err = try std.Thread.spawn(.{}, streamErrLoop, .{ctx});
    }

    // Ownership handed to the reader threads / the returned Handle.
    return .{ .ctx = ctx };
}

fn streamOutLoop(ctx: *StreamCtx) void {
    const io = ctx.io;
    var f = ctx.child.stdout.?;
    ctx.child.stdout = null;
    defer f.close(io);
    var rbuf: [8192]u8 = undefined;
    while (true) {
        const n = f.readStreaming(io, &.{rbuf[0..]}) catch break;
        if (n == 0) break;
        ctx.sema.waitUncancelable(io);
        if (ctx.cb.on_stdout) |cbf| cbf(ctx.cb.ctx, rbuf[0..n]);
    }
}

fn streamErrLoop(ctx: *StreamCtx) void {
    const io = ctx.io;
    var f = ctx.child.stderr.?;
    ctx.child.stderr = null;
    defer f.close(io);
    var rbuf: [8192]u8 = undefined;
    while (true) {
        const n = f.readStreaming(io, &.{rbuf[0..]}) catch break;
        if (n == 0) break;
        if (ctx.cb.on_stderr) |cbf| cbf(ctx.cb.ctx, rbuf[0..n]);
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn monoNowNs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

test "run: echo captures stdout and exits 0" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var out = try run(testing.allocator, io, .{
        .argv = &.{ "/bin/echo", "hello" },
    }, "");
    defer out.deinit(testing.allocator);

    try testing.expect(out.term == .exited);
    try testing.expectEqual(@as(u8, 0), out.term.exited);
    try testing.expectEqualStrings("hello\n", out.stdout);
    try testing.expect(!out.truncated_stdout);
}

test "run: stream separation and non-zero exit" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var out = try run(testing.allocator, io, .{
        .argv = &.{ "sh", "-c", "echo out; echo err 1>&2; exit 3" },
    }, "");
    defer out.deinit(testing.allocator);

    try testing.expect(out.term == .exited);
    try testing.expectEqual(@as(u8, 3), out.term.exited);
    try testing.expectEqualStrings("out\n", out.stdout);
    try testing.expectEqualStrings("err\n", out.stderr);
}

test "run: cat round-trips a small stdin body" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var out = try run(testing.allocator, io, .{
        .argv = &.{"cat"},
        .stdin = .pipe,
    }, "round trip");
    defer out.deinit(testing.allocator);

    try testing.expectEqualStrings("round trip", out.stdout);
    try testing.expect(out.term == .exited);
}

test "run: cat round-trips a >1 MiB stdin body without deadlock" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const big = try testing.allocator.alloc(u8, 3 * 1024 * 1024);
    defer testing.allocator.free(big);
    for (big, 0..) |*b, i| b.* = @intCast(i % 251);

    var out = try run(testing.allocator, io, .{
        .argv = &.{"cat"},
        .stdin = .pipe,
    }, big);
    defer out.deinit(testing.allocator);

    try testing.expect(out.term == .exited);
    try testing.expectEqual(big.len, out.stdout.len);
    try testing.expect(std.mem.eql(u8, big, out.stdout));
}

test "run: output past max_output_bytes keeps prefix and reports truncation" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // 100_000 bytes from the child; cap capture at 1000.
    var out = try run(testing.allocator, io, .{
        .argv = &.{ "sh", "-c", "head -c 100000 /dev/zero" },
        .max_output_bytes = 1000,
    }, "");
    defer out.deinit(testing.allocator);

    try testing.expect(out.term == .exited);
    try testing.expectEqual(@as(usize, 1000), out.stdout.len);
    try testing.expect(out.truncated_stdout);
}

test "runTimeout: kills a child that outlives the deadline" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const start = monoNowNs();
    var out = try runTimeout(testing.allocator, io, .{
        .argv = &.{ "sleep", "10" },
    }, "", 100 * std.time.ns_per_ms);
    defer out.deinit(testing.allocator);
    const elapsed = monoNowNs() - start;

    try testing.expect(out.term == .signal); // SIGKILL'd, not exited
    try testing.expect(elapsed < 5 * std.time.ns_per_s); // returned promptly
}

test "spawnStreaming: separates streams and reports exit 3" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const Sink = struct {
        out: std.ArrayList(u8) = .empty,
        err: std.ArrayList(u8) = .empty,
        gpa: std.mem.Allocator,
        h: ?Handle = null,
        fn onOut(cx: ?*anyopaque, chunk: []const u8) void {
            const s: *@This() = @ptrCast(@alignCast(cx.?));
            s.out.appendSlice(s.gpa, chunk) catch {};
            if (s.h) |h| h.ack();
        }
        fn onErr(cx: ?*anyopaque, chunk: []const u8) void {
            const s: *@This() = @ptrCast(@alignCast(cx.?));
            s.err.appendSlice(s.gpa, chunk) catch {};
        }
    };
    var sink = Sink{ .gpa = testing.allocator };
    defer sink.out.deinit(testing.allocator);
    defer sink.err.deinit(testing.allocator);

    const h = try spawnStreaming(testing.allocator, io, .{
        .argv = &.{ "sh", "-c", "echo out; echo err 1>&2; exit 3" },
    }, .{ .ctx = &sink, .on_stdout = Sink.onOut, .on_stderr = Sink.onErr });
    sink.h = h;

    const term = h.wait();
    try testing.expect(term == .exited);
    try testing.expectEqual(@as(u8, 3), term.exited);
    try testing.expectEqualStrings("out\n", sink.out.items);
    try testing.expectEqualStrings("err\n", sink.err.items);
}

test "spawnStreaming: cancel terminates a long sleep promptly" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const h = try spawnStreaming(testing.allocator, io, .{
        .argv = &.{ "sleep", "10" },
    }, .{});

    const start = monoNowNs();
    h.cancel();
    const term = h.wait();
    const elapsed = monoNowNs() - start;

    try testing.expect(term == .signal);
    try testing.expect(elapsed < 5 * std.time.ns_per_s);
}

test "spawnStreaming: kill escalation terminates promptly" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const h = try spawnStreaming(testing.allocator, io, .{
        .argv = &.{ "sleep", "10" },
    }, .{});

    const start = monoNowNs();
    h.kill();
    const term = h.wait();
    const elapsed = monoNowNs() - start;

    try testing.expect(term == .signal);
    try testing.expect(elapsed < 5 * std.time.ns_per_s);
}

test "waitTolerant: ECHILD after out-of-band reap yields .unknown (no panic)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    ensureChildReaping();
    var child = try std.process.spawn(io, .{
        .argv = &.{"true"},
        .stdin = .close,
        .stdout = .ignore,
        .stderr = .ignore,
    });

    // Reap the child out-of-band (as a sibling wait4(-1) reaper would),
    // BEFORE procrun gets to wait. This is the exact condition std's
    // Child.wait panics on.
    const pid = child.id.?;
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    while (true) {
        const rc = std.posix.system.wait4(pid, &status, 0, null);
        if (std.posix.errno(rc) == .INTR) continue;
        break;
    }

    const term = waitTolerant(io, &child);
    try testing.expect(term == .unknown);
}

test "ensureChildReaping: idempotent and leaves a real disposition alone" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const posix = std.posix;
    var saved: posix.Sigaction = undefined;
    posix.sigaction(posix.SIG.CHLD, null, &saved);
    defer posix.sigaction(posix.SIG.CHLD, &saved, null);

    // Inherited SIG_IGN is the crash trigger: flip it to SIG_DFL.
    const ign: posix.Sigaction = .{
        .handler = .{ .handler = posix.SIG.IGN },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.CHLD, &ign, null);
    restoreChildReaping();
    var after: posix.Sigaction = undefined;
    posix.sigaction(posix.SIG.CHLD, null, &after);
    try testing.expect(after.handler.handler == posix.SIG.DFL);

    // A non-IGN disposition must be left untouched.
    restoreChildReaping();
    posix.sigaction(posix.SIG.CHLD, null, &after);
    try testing.expect(after.handler.handler == posix.SIG.DFL);
}

test "run: merge env overlays the child environment" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // needs /proc
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var env = std.process.Environ.Map.init(testing.allocator);
    defer env.deinit();
    try env.put("PROCRUN_TEST_VAR", "merged");

    var out = try run(testing.allocator, io, .{
        .argv = &.{ "sh", "-c", "printf %s \"$PROCRUN_TEST_VAR\"" },
        .env = &env,
        .env_mode = .merge,
    }, "");
    defer out.deinit(testing.allocator);

    try testing.expect(out.term == .exited);
    try testing.expectEqualStrings("merged", out.stdout);
}

// ── process-group tree-kill tests ───────────────────────────────────────────

/// Reads `/proc/<pid>/stat`'s state character (`R`/`S`/`D`/`Z`/…), or `null`
/// if the pid no longer exists at all. Used to tell "really still running"
/// (exists, not a zombie) apart from "gone" (doesn't exist OR zombie —
/// `kill(pid, 0)` alone can't make this distinction: it succeeds against a
/// not-yet-reaped zombie too, which would make a kill-then-check-liveness
/// test flaky against reaper-thread timing).
fn procStatState(pid: std.posix.pid_t) ?u8 {
    var path_buf: [64:0]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/stat", .{pid}) catch return null;

    // Deliberately raw syscalls with a manual `errno` switch (not
    // `Io.Dir`/`Io.File`, and not even the higher-level `std.posix.openatZ`/
    // `.read` wrappers): reading a THIRD process's `/proc/pid/stat` while it
    // is mid-exit (as `procReallyRunning` does, right after a kill) can hit
    // `ESRCH` between `openat` succeeding and `read` running, or other rare
    // errno values a typed wrapper doesn't enumerate — a documented procfs
    // race, not a bug. Zig's typed wrappers route anything they don't
    // enumerate through `unexpectedErrno`, which unconditionally dumps a
    // stack trace in Debug builds EVEN THOUGH the caller goes on to handle
    // the resulting error — noisy but harmless on its own; a raw syscall +
    // our own `errno` switch avoids that path entirely. Matches this
    // module's established libc-free raw-syscall style (see
    // `reapTolerantPosix`). `/proc/pid/stat` is always returned complete by
    // a single `read(2)`, so one shot is enough — no retry loop needed.
    const posix = std.posix;
    const fd: posix.fd_t = fd: {
        const rc = posix.system.openat(posix.AT.FDCWD, path, .{}, 0);
        switch (posix.errno(rc)) {
            .SUCCESS => break :fd @intCast(rc),
            else => return null, // includes ENOENT: pid already fully gone
        }
    };
    defer _ = posix.system.close(fd);

    var buf: [256]u8 = undefined;
    const n: usize = n: {
        const rc = posix.system.read(fd, &buf, buf.len);
        switch (posix.errno(rc)) {
            .SUCCESS => break :n rc,
            else => return null, // e.g. ESRCH: died between openat and read
        }
    };
    if (n == 0) return null;

    var it = std.mem.tokenizeScalar(u8, buf[0..n], ' ');
    _ = it.next() orelse return null; // pid
    _ = it.next() orelse return null; // (comm) — assumed space-free (true for "sleep")
    const state = it.next() orelse return null;
    return if (state.len > 0) state[0] else null;
}

fn procReallyRunning(pid: std.posix.pid_t) bool {
    const s = procStatState(pid) orelse return false;
    return s != 'Z';
}

test "Spec.new_process_group + Handle.killGroup: reaps a grandchild, not just the direct child" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // /proc-based liveness check
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const Sink = struct {
        buf: std.ArrayList(u8) = .empty,
        gpa: std.mem.Allocator,
        fn onOut(cx: ?*anyopaque, chunk: []const u8) void {
            const s: *@This() = @ptrCast(@alignCast(cx.?));
            s.buf.appendSlice(s.gpa, chunk) catch {};
        }
    };
    var sink = Sink{ .gpa = testing.allocator };
    defer sink.buf.deinit(testing.allocator);

    // The direct child (`sh`) backgrounds `sleep 100` — a GRANDCHILD from
    // procrun's point of view — prints its pid, then blocks in `wait`.
    // Without process-group tree-kill, killing only the direct child leaves
    // `sleep` running (it's the classic "sh -c 'long-runner &'" orphan).
    const h = try spawnStreaming(testing.allocator, io, .{
        .argv = &.{ "sh", "-c", "sleep 100 & echo $!; wait" },
        .new_process_group = true,
    }, .{ .ctx = &sink, .on_stdout = Sink.onOut });

    var grandchild_pid: std.posix.pid_t = 0;
    var waited_ns: u64 = 0;
    while (waited_ns < 2 * std.time.ns_per_s) : (waited_ns += 10 * std.time.ns_per_ms) {
        if (std.mem.indexOfScalar(u8, sink.buf.items, '\n')) |nl| {
            const digits = std.mem.trim(u8, sink.buf.items[0..nl], " \t\r\n");
            if (digits.len > 0) {
                if (std.fmt.parseInt(std.posix.pid_t, digits, 10) catch null) |p| {
                    grandchild_pid = p;
                    break;
                }
            }
        }
        sleepNs(10 * std.time.ns_per_ms);
    }
    try testing.expect(grandchild_pid != 0);

    // Confirm the grandchild is genuinely running before we touch anything.
    var confirmed_alive = false;
    waited_ns = 0;
    while (waited_ns < 1 * std.time.ns_per_s) : (waited_ns += 10 * std.time.ns_per_ms) {
        if (procReallyRunning(grandchild_pid)) {
            confirmed_alive = true;
            break;
        }
        sleepNs(10 * std.time.ns_per_ms);
    }
    try testing.expect(confirmed_alive);

    h.killGroup();
    const term = h.wait();
    try testing.expect(term == .signal);

    // The grandchild must be gone (or a not-yet-reaped zombie) shortly
    // after — proving the group signal, not just the direct child, reached
    // it. Poll instead of a single check to tolerate scheduling jitter.
    var confirmed_dead = false;
    waited_ns = 0;
    while (waited_ns < 2 * std.time.ns_per_s) : (waited_ns += 10 * std.time.ns_per_ms) {
        if (!procReallyRunning(grandchild_pid)) {
            confirmed_dead = true;
            break;
        }
        sleepNs(10 * std.time.ns_per_ms);
    }
    try testing.expect(confirmed_dead);
}

test "Handle.killGroup is a documented no-op without Spec.new_process_group" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const h = try spawnStreaming(testing.allocator, io, .{
        .argv = &.{ "sleep", "10" },
    }, .{});
    try testing.expect(!h.grouped());
    h.killGroup(); // must not touch the test runner's own process group
    // The direct child is still alive and must be cleaned up explicitly.
    h.kill();
    const term = h.wait();
    try testing.expect(term == .signal);
}

// ── rlimit sandbox tests ────────────────────────────────────────────────────

test "RlimitSpec.file_size_bytes: exceeding it kills the child with SIGXFSZ" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_abs_len = try tmp.dir.realPath(io, &path_buf);
    const of_arg = try std.fmt.allocPrint(testing.allocator, "of={s}/fsize_target", .{path_buf[0..dir_abs_len]});
    defer testing.allocator.free(of_arg);

    // 200 blocks of 4096 bytes each, capped to 512 bytes (1 block): the
    // very first write already overshoots, so this fails fast.
    var out = try run(testing.allocator, io, .{
        .argv = &.{ "dd", "if=/dev/zero", of_arg, "bs=4096", "count=200" },
        .rlimit = .{ .file_size_bytes = 512 },
    }, "");
    defer out.deinit(testing.allocator);

    try testing.expect(out.term == .signal);
    try testing.expectEqual(std.posix.SIG.XFSZ, out.term.signal);

    // The limit actually bit — the file must not have grown past the cap.
    var f = try tmp.dir.openFile(io, "fsize_target", .{});
    defer f.close(io);
    const stat = try f.stat(io);
    try testing.expect(stat.size <= 512);
}

test "RlimitSpec.cpu_seconds: a busy loop is terminated well inside a generous safety timeout" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const start = monoNowNs();
    // `runTimeout`'s own deadline (8s) is only a safety net in case the
    // rlimit somehow fails to fire; asserting the elapsed time is well
    // under it is what proves the 1-second CPU cap — not the 8-second
    // safety net — is what actually terminated the child.
    var out = try runTimeout(testing.allocator, io, .{
        .argv = &.{ "sh", "-c", "while :; do :; done" },
        .rlimit = .{ .cpu_seconds = 1 },
    }, "", 8 * std.time.ns_per_s);
    defer out.deinit(testing.allocator);
    const elapsed = monoNowNs() - start;

    try testing.expect(out.term == .signal);
    try testing.expect(elapsed < 5 * std.time.ns_per_s);
}

test "RlimitSpec: generous limits do not disturb an ordinary command" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var out = try run(testing.allocator, io, .{
        .argv = &.{ "/bin/echo", "hello" },
        .rlimit = .{ .cpu_seconds = 30, .open_files = 256, .file_size_bytes = 1 << 20, .address_space_bytes = 1 << 30 },
    }, "");
    defer out.deinit(testing.allocator);

    try testing.expect(out.term == .exited);
    try testing.expectEqual(@as(u8, 0), out.term.exited);
    try testing.expectEqualStrings("hello\n", out.stdout);
}

// ── streaming stdin tests ───────────────────────────────────────────────────

test "Handle.writeStdin/closeStdin: streams bytes to cat incrementally after spawn" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const Sink = struct {
        buf: std.ArrayList(u8) = .empty,
        gpa: std.mem.Allocator,
        fn onOut(cx: ?*anyopaque, chunk: []const u8) void {
            const s: *@This() = @ptrCast(@alignCast(cx.?));
            s.buf.appendSlice(s.gpa, chunk) catch {};
        }
    };
    var sink = Sink{ .gpa = testing.allocator };
    defer sink.buf.deinit(testing.allocator);

    const h = try spawnStreaming(testing.allocator, io, .{
        .argv = &.{"cat"},
        .stdin = .pipe,
    }, .{ .ctx = &sink, .on_stdout = Sink.onOut });

    // Written across multiple calls, well after spawn — the point of this
    // gap: `run`'s `stdin_body` is one fixed buffer written before capture
    // even starts, but a caller of `spawnStreaming` can drive stdin as its
    // own protocol dictates.
    try h.writeStdin("hello, ");
    try h.writeStdin("streaming ");
    try h.writeStdin("world");
    try h.closeStdin();

    const term = h.wait();
    try testing.expect(term == .exited);
    try testing.expectEqualStrings("hello, streaming world", sink.buf.items);
}

test "Handle.writeStdin: error.StdinUnavailable when Spec.stdin is not .pipe" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const h = try spawnStreaming(testing.allocator, io, .{
        .argv = &.{ "sleep", "1" },
    }, .{});
    try testing.expectError(error.StdinUnavailable, h.writeStdin("x"));
    try testing.expectError(error.StdinUnavailable, h.closeStdin());
    h.kill();
    _ = h.wait();
}

test "Handle.closeStdin: a second close is rejected, not a double-close" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const h = try spawnStreaming(testing.allocator, io, .{
        .argv = &.{"cat"},
        .stdin = .pipe,
    }, .{});
    try h.closeStdin();
    try testing.expectError(error.StdinUnavailable, h.closeStdin());

    const term = h.wait();
    try testing.expect(term == .exited); // cat sees immediate EOF and exits 0
}

// ── argsafe integration tests ───────────────────────────────────────────────

test "runValidated: rejects a known-bad (flag-injection) arg before spawning anything" {
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const result = runValidated(
        testing.allocator,
        io,
        "/bin/echo",
        argsafe.isSafePath,
        &.{"-rf"}, // flag-injection shaped argument
        argsafe.isSafeIdentifier,
        .{ .argv = &.{} },
        "",
    );
    try testing.expectError(argsafe.Error.Rejected, result);
}

test "runValidated: accepts sanitized argv and actually runs it" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var out = try runValidated(
        testing.allocator,
        io,
        "/bin/echo",
        argsafe.isSafePath,
        &.{"hello"},
        argsafe.isSafeIdentifier,
        .{ .argv = &.{} },
        "",
    );
    defer out.deinit(testing.allocator);

    try testing.expect(out.term == .exited);
    try testing.expectEqualStrings("hello\n", out.stdout);
}

test "runValidated: a bad program path is rejected independently of args" {
    if (!std.process.can_spawn) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const result = runValidated(
        testing.allocator,
        io,
        "relative/not/absolute", // isSafePath requires a leading '/'
        argsafe.isSafePath,
        &.{"hello"},
        argsafe.isSafeIdentifier,
        .{ .argv = &.{} },
        "",
    );
    try testing.expectError(argsafe.Error.Rejected, result);
}
