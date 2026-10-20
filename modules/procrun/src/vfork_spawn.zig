// SPDX-License-Identifier: MIT

//! Linux process spawning with `clone(CLONE_VM | CLONE_VFORK)` instead of
//! `fork()` — what musl's and glibc's `posix_spawn`, Go's `os/exec` and Rust's
//! `std::process` do.
//!
//! Why: Zig 0.17's `std.process.spawn` forks, and `fork` copies the parent's
//! page tables, so a spawn costs time proportional to the parent's mapped
//! memory — measured 2026-10-20: 0.65 ms at 0 MiB, 7.5 ms at 128 MiB, 31 ms at
//! 512 MiB per `/bin/true`, against a flat ~0.6 ms for Go and Rust; with 8
//! threads spawning, the page-table copies also serialise on the mm lock (5×
//! Go). A `CLONE_VM` child shares the parent's memory until it execs, and
//! `CLONE_VFORK` suspends the parent until then, so nothing is copied.
//!
//! The child shares memory with the parent, so the rules musl's posix_spawn
//! follows apply here too (the structure of `child` below is ported from musl
//! 1.2.5 `src/process/posix_spawn.c`, MIT — see ../NOTICE):
//!
//!   * everything the child needs (argv, envp, the PATH-search buffer, its
//!     stack) is allocated by the parent BEFORE the clone; the child allocates
//!     nothing, takes no lock and touches no thread-local (it runs on the
//!     parent's TLS pointer);
//!   * all signals are blocked across the clone, and the child resets every
//!     signal that has a handler to `SIG_DFL` before restoring the mask — a
//!     parent handler must never run in the child while memory is shared;
//!   * the child reports a failure as a code on a CLOEXEC pipe and exits; on
//!     success `execve` closes the pipe, so the parent learns the outcome as
//!     soon as `clone` returns (the vfork parent resumes only after exec/exit).
//!
//! The steps run in `std.process.spawn`'s order and map errors to the same
//! `std.process.SpawnError` values, so a caller cannot tell the two apart
//! except by speed.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;

/// Whether this target uses the clone spawner (otherwise callers keep std's).
pub const supported = builtin.os.tag == .linux and
    (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64);

pub const Stdio = union(enum) {
    inherit,
    close,
    /// `/dev/null`, opened by `spawn` for the duration of the call.
    ignore,
    /// dup2'd onto the stream (the caller keeps and closes it).
    fd: posix.fd_t,
};

pub const Options = struct {
    argv: []const []const u8,
    /// Changed in the child before anything else; relative argv[0] (with a
    /// `/`) then resolves against it, as with std.
    cwd: ?[]const u8 = null,
    /// The child's environment block entries (`KEY=VALUE`); argv[0] is
    /// searched on `search_path` (the PARENT's PATH, as std does).
    env: []const []const u8,
    search_path: []const u8,
    stdin: Stdio = .inherit,
    stdout: Stdio = .inherit,
    stderr: Stdio = .inherit,
    /// CLOEXEC is cleared on these in the child (same fd numbers).
    pass_fds: []const posix.fd_t = &.{},
    uid: ?posix.uid_t = null,
    gid: ?posix.gid_t = null,
    pgid: ?posix.pid_t = null,
};

pub const Error = std.process.SpawnError;

/// The failures the child can report, as a small code on the pipe.
const ChildErr = enum(u32) {
    ok = 0,
    access_denied,
    permission_denied,
    file_not_found,
    not_dir,
    is_dir,
    invalid_exe,
    file_system,
    file_busy,
    system_resources,
    process_fd_quota,
    system_fd_quota,
    name_too_long,
    sym_link_loop,
    bad_path_name,
    resource_limit,
    invalid_user_id,
    invalid_process_group_id,
    process_already_exec,
    unexpected,

    fn toError(c: ChildErr) Error {
        return switch (c) {
            .ok, .unexpected => error.Unexpected,
            .access_denied => error.AccessDenied,
            .permission_denied => error.PermissionDenied,
            .file_not_found => error.FileNotFound,
            .not_dir => error.NotDir,
            .is_dir => error.IsDir,
            .invalid_exe => error.InvalidExe,
            .file_system => error.FileSystem,
            .file_busy => error.FileBusy,
            .system_resources => error.SystemResources,
            .process_fd_quota => error.ProcessFdQuotaExceeded,
            .system_fd_quota => error.SystemFdQuotaExceeded,
            .name_too_long => error.NameTooLong,
            .sym_link_loop => error.SymLinkLoop,
            .bad_path_name => error.BadPathName,
            .resource_limit => error.ResourceLimitReached,
            .invalid_user_id => error.InvalidUserId,
            .invalid_process_group_id => error.InvalidProcessGroupId,
            .process_already_exec => error.ProcessAlreadyExec,
        };
    }
};

/// What the child reads — prepared entirely by the parent, in parent memory
/// the suspended parent does not touch until the child has exec'd or exited.
const ChildArgs = struct {
    err_fd: posix.fd_t,
    cwd: ?[*:0]const u8,
    argv: [*:null]?[*:0]const u8,
    envp: [*:null]?[*:0]const u8,
    arg0: []const u8,
    search_path: []const u8,
    /// The child builds PATH candidates here (never on the parent's stack).
    path_buf: *[posix.PATH_MAX]u8,
    stdio_src: [3]posix.fd_t, // -1 = no dup2
    stdio_close: [3]bool,
    pass_fds: []const posix.fd_t,
    uid: ?posix.uid_t,
    gid: ?posix.gid_t,
    pgid: ?posix.pid_t,
    old_mask: linux.sigset_t,
};

/// The kernel's `struct sigaction` for rt_sigaction on x86_64 and aarch64
/// (handler, flags, restorer, mask) — used raw so the child can walk every
/// signal number without std's typed wrapper.
const KSigaction = extern struct {
    handler: usize,
    flags: c_ulong,
    restorer: usize,
    mask: u64,
};

const child_stack_size = 64 * 1024;

/// Spawn `opts.argv` and return the child's pid. On error no child is left
/// running (a child that failed before exec is reaped here).
pub fn spawn(gpa: std.mem.Allocator, opts: Options) Error!posix.pid_t {
    comptime std.debug.assert(supported);
    if (opts.argv.len == 0) return error.FileNotFound;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const argv = try arena.allocSentinel(?[*:0]const u8, opts.argv.len, null);
    for (opts.argv, 0..) |a, i| argv[i] = (try arena.dupeSentinel(u8, a, 0)).ptr;
    const envp = try arena.allocSentinel(?[*:0]const u8, opts.env.len, null);
    for (opts.env, 0..) |e, i| envp[i] = (try arena.dupeSentinel(u8, e, 0)).ptr;
    const cwd: ?[*:0]const u8 = if (opts.cwd) |c| (try arena.dupeSentinel(u8, c, 0)).ptr else null;
    const path_buf = try arena.create([posix.PATH_MAX]u8);
    const stack = try gpa.alignedAlloc(u8, .@"16", child_stack_size);
    defer gpa.free(stack);

    // /dev/null for `.ignore`, opened once (≥ 3, CLOEXEC).
    var dev_null: posix.fd_t = -1;
    defer if (dev_null >= 0) closeFd(dev_null);
    if (opts.stdin == .ignore or opts.stdout == .ignore or opts.stderr == .ignore) {
        const rc = linux.openat(linux.AT.FDCWD, "/dev/null", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => dev_null = @intCast(rc),
            .NODEV => return error.NoDevice,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            else => return error.Unexpected,
        }
        dev_null = try liftFd(dev_null);
    }

    // A dup2 source below 3 could be overwritten by an earlier dup2 in the
    // child (e.g. a pipe that landed on fd 1 because the parent had closed
    // it); move such fds out of the way first. The copies are closed on exit.
    var lifted: [3]posix.fd_t = .{ -1, -1, -1 };
    defer for (lifted) |fd| if (fd >= 0) closeFd(fd);
    var args: ChildArgs = .{
        .err_fd = -1,
        .cwd = cwd,
        .argv = argv.ptr,
        .envp = envp.ptr,
        .arg0 = opts.argv[0],
        .search_path = opts.search_path,
        .path_buf = path_buf,
        .stdio_src = .{ -1, -1, -1 },
        .stdio_close = .{ false, false, false },
        .pass_fds = opts.pass_fds,
        .uid = opts.uid,
        .gid = opts.gid,
        .pgid = opts.pgid,
        .old_mask = undefined,
    };
    for ([_]Stdio{ opts.stdin, opts.stdout, opts.stderr }, 0..) |s, i| switch (s) {
        .inherit => {},
        .close => args.stdio_close[i] = true,
        .ignore => args.stdio_src[i] = dev_null,
        .fd => |fd| {
            if (fd < 3 and fd != @as(posix.fd_t, @intCast(i))) {
                lifted[i] = try liftFd(try dupCloexec(fd));
                args.stdio_src[i] = lifted[i];
            } else args.stdio_src[i] = fd;
        },
    };

    // The error pipe; its write end must not be one of 0..2 either.
    var ep: [2]posix.fd_t = undefined;
    switch (linux.errno(linux.pipe2(&ep, .{ .CLOEXEC = true }))) {
        .SUCCESS => {},
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        else => return error.Unexpected,
    }
    defer closeFd(ep[0]);
    ep[1] = liftFd(ep[1]) catch |e| {
        closeFd(ep[1]);
        return e;
    };
    args.err_fd = ep[1];

    // Block every signal across the clone (restored in both processes).
    const all = linux.sigfillset();
    _ = linux.sigprocmask(linux.SIG.SETMASK, &all, &args.old_mask);
    const rc = linux.clone(
        childMain,
        @intFromPtr(stack.ptr) + stack.len,
        linux.CLONE.VM | linux.CLONE.VFORK | @as(u32, @backingInt(linux.SIG.CHLD)),
        @intFromPtr(&args),
        null,
        0,
        null,
    );
    _ = linux.sigprocmask(linux.SIG.SETMASK, &args.old_mask, null);
    closeFd(ep[1]);
    const pid: posix.pid_t = switch (linux.errno(rc)) {
        .SUCCESS => @intCast(@as(isize, @bitCast(rc))),
        .AGAIN, .NOMEM => return error.SystemResources,
        else => return error.Unexpected,
    };

    // The child has exec'd (pipe closed by CLOEXEC → 0 bytes) or exited
    // after writing its code.
    var code: u32 = 0;
    const n = readAll(ep[0], std.mem.asBytes(&code));
    if (n == @sizeOf(u32)) {
        var status: i32 = 0;
        while (true) switch (linux.errno(linux.wait4(pid, &status, 0, null))) {
            .INTR => continue,
            else => break,
        };
        const c = std.enums.fromInt(ChildErr, code) orelse .unexpected;
        return c.toError();
    }
    return pid;
}

fn closeFd(fd: posix.fd_t) void {
    _ = linux.close(fd);
}

fn readAll(fd: posix.fd_t, buf: []u8) usize {
    var got: usize = 0;
    while (got < buf.len) {
        const rc = linux.read(fd, buf[got..].ptr, buf.len - got);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) break;
                got += rc;
            },
            .INTR => continue,
            else => break,
        }
    }
    return got;
}

fn dupCloexec(fd: posix.fd_t) Error!posix.fd_t {
    const rc = linux.fcntl(fd, linux.F.DUPFD_CLOEXEC, 0);
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .MFILE => error.ProcessFdQuotaExceeded,
        else => error.Unexpected,
    };
}

/// `fd` moved to a number ≥ 3 (CLOEXEC); the original is closed if it moved.
fn liftFd(fd: posix.fd_t) Error!posix.fd_t {
    if (fd >= 3) return fd;
    const rc = linux.fcntl(fd, linux.F.DUPFD_CLOEXEC, 3);
    return switch (linux.errno(rc)) {
        .SUCCESS => blk: {
            closeFd(fd);
            break :blk @intCast(rc);
        },
        .MFILE => error.ProcessFdQuotaExceeded,
        else => error.Unexpected,
    };
}

// ── the child (runs on its own stack, in the parent's memory) ───────────────
//
// No allocation, no locks, no thread-locals, no safety-checked arithmetic
// that could reach the panic handler: only raw syscalls on data the parent
// prepared. Ported from musl 1.2.5 posix_spawn.c `child` (structure: signal
// reset, credentials, fd actions, mask restore, exec, report-and-exit).

fn childMain(arg: usize) callconv(.c) u8 {
    @setRuntimeSafety(false);
    const a: *const ChildArgs = @ptrFromInt(arg);

    // Every signal with a handler goes back to SIG_DFL (SIG_IGN stays): a
    // parent handler must not run here while memory is shared.
    var sig: usize = 1;
    while (sig < linux.NSIG) : (sig += 1) {
        if (sig == @backingInt(linux.SIG.KILL) or sig == @backingInt(linux.SIG.STOP)) continue;
        var old: KSigaction = undefined;
        if (linux.errno(linux.syscall4(.rt_sigaction, sig, 0, @intFromPtr(&old), 8)) != .SUCCESS) continue;
        if (old.handler == 0 or old.handler == 1) continue; // SIG_DFL / SIG_IGN
        const dfl: KSigaction = .{ .handler = 0, .flags = 0, .restorer = 0, .mask = 0 };
        _ = linux.syscall4(.rt_sigaction, sig, @intFromPtr(&dfl), 0, 8);
    }

    if (a.cwd) |c| switch (linux.errno(linux.chdir(c))) {
        .SUCCESS => {},
        .ACCES => bail(a, .access_denied),
        .NOENT => bail(a, .file_not_found),
        .NOTDIR => bail(a, .not_dir),
        .LOOP => bail(a, .sym_link_loop),
        .NAMETOOLONG => bail(a, .name_too_long),
        .NOMEM => bail(a, .system_resources),
        .IO => bail(a, .file_system),
        .ILSEQ => bail(a, .bad_path_name),
        else => bail(a, .unexpected),
    };

    for (a.pass_fds) |fd| {
        if (linux.errno(linux.fcntl(fd, linux.F.SETFD, 0)) != .SUCCESS) bail(a, .unexpected);
    }

    var i: usize = 0;
    while (i < 3) : (i += 1) {
        const target: posix.fd_t = @intCast(i);
        if (a.stdio_close[i]) {
            _ = linux.close(target);
        } else if (a.stdio_src[i] >= 0) {
            if (a.stdio_src[i] == target) {
                // Already in place: only make sure it survives exec.
                _ = linux.fcntl(target, linux.F.SETFD, 0);
            } else if (linux.errno(linux.dup3(a.stdio_src[i], target, 0)) != .SUCCESS) {
                bail(a, .unexpected);
            }
        }
    }

    if (a.gid) |gid| switch (linux.errno(linux.setregid(gid, gid))) {
        .SUCCESS => {},
        .AGAIN => bail(a, .resource_limit),
        .INVAL => bail(a, .invalid_user_id),
        .PERM => bail(a, .permission_denied),
        else => bail(a, .unexpected),
    };
    if (a.uid) |uid| switch (linux.errno(linux.setreuid(uid, uid))) {
        .SUCCESS => {},
        .AGAIN => bail(a, .resource_limit),
        .INVAL => bail(a, .invalid_user_id),
        .PERM => bail(a, .permission_denied),
        else => bail(a, .unexpected),
    };
    if (a.pgid) |pgid| switch (linux.errno(linux.setpgid(0, pgid))) {
        .SUCCESS => {},
        .ACCES => bail(a, .process_already_exec),
        .INVAL => bail(a, .invalid_process_group_id),
        .PERM => bail(a, .permission_denied),
        else => bail(a, .unexpected),
    };

    _ = linux.sigprocmask(linux.SIG.SETMASK, &a.old_mask, null);

    // argv[0] with a `/` is a path (relative to the new cwd); otherwise it is
    // searched on PATH, keeping std's precedence: AccessDenied from any
    // candidate wins over FileNotFound/NotDir from the others.
    const has_slash = for (a.arg0) |ch| {
        if (ch == '/') break true;
    } else false;
    if (has_slash) bail(a, execErr(linux.errno(linux.execve(a.argv[0].?, a.argv, a.envp))));

    var best: ChildErr = .file_not_found;
    var it = std.mem.tokenizeScalar(u8, a.search_path, ':');
    while (it.next()) |dir| {
        const len = dir.len + 1 + a.arg0.len;
        if (len + 1 > a.path_buf.len) bail(a, .name_too_long);
        @memcpy(a.path_buf[0..dir.len], dir);
        a.path_buf[dir.len] = '/';
        @memcpy(a.path_buf[dir.len + 1 ..][0..a.arg0.len], a.arg0);
        a.path_buf[len] = 0;
        const e = execErr(linux.errno(linux.execve(a.path_buf[0..len :0], a.argv, a.envp)));
        switch (e) {
            .access_denied => best = .access_denied,
            .file_not_found, .not_dir => if (best != .access_denied) {
                best = e;
            },
            else => bail(a, e),
        }
    }
    bail(a, best);
}

fn execErr(e: linux.E) ChildErr {
    return switch (e) {
        .@"2BIG", .NOMEM => .system_resources,
        .MFILE => .process_fd_quota,
        .NFILE => .system_fd_quota,
        .NAMETOOLONG => .name_too_long,
        .ACCES => .access_denied,
        .PERM => .permission_denied,
        .INVAL, .NOEXEC, .LIBBAD => .invalid_exe,
        .IO, .LOOP => .file_system,
        .ISDIR => .is_dir,
        .NOENT => .file_not_found,
        .NOTDIR => .not_dir,
        .TXTBSY => .file_busy,
        else => .unexpected,
    };
}

fn bail(a: *const ChildArgs, c: ChildErr) noreturn {
    @setRuntimeSafety(false);
    const code: u32 = @backingInt(c);
    _ = linux.write(a.err_fd, std.mem.asBytes(&code).ptr, @sizeOf(u32));
    linux.exit_group(127);
}
