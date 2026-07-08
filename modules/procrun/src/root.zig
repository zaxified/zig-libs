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

pub const meta = .{
    .status = .extract, // seed: bxp bxp-gui-bridge/src/main.zig (reap-race core)
    .platform = .any, // full behavior on POSIX; Windows compiles (reap-race is POSIX-only)
    .role = .util,
    .concurrency = .reentrant, // no shared module state (aside from the SIGCHLD-fixup guard)
    .model_after = "Python subprocess.run/Popen; Go os/exec",
    .deps = .{},
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

/// A process to run. `argv[0]` is resolved via `PATH` if it has no '/'.
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

    return std.process.spawn(io, .{
        .argv = spec.argv,
        .cwd = cwd,
        .environ_map = env_ptr,
        .stdin = toStdIo(spec.stdin),
        .stdout = toStdIo(spec.stdout),
        .stderr = toStdIo(spec.stderr),
        .create_no_window = true,
    });
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
    deliver(j.child, .kill, 0);
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
    t_out: ?std.Thread = null,
    t_err: ?std.Thread = null,
};

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

    /// Release one stdout backpressure permit (call after consuming a chunk).
    pub fn ack(h: Handle) void {
        h.ctx.sema.post(h.ctx.io);
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
