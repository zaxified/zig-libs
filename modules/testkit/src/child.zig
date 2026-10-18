// SPDX-License-Identifier: MIT
//! Run a function in a forked child and say how it ended: exited with a code,
//! killed by a signal, or still running at the limit (killed, `hang`).
//!
//! The one way for a test to observe a crash or a hang without dying of it:
//! the shrinker classifies every candidate input this way, and `guard`'s
//! tests prove a read past the end really faults.
//!
//! The child is the calling thread alone (fork(2)); it inherits memory
//! copy-on-write, writes nothing to the parent's stdout (the build runner's
//! protocol channel under `zig build test`), and leaves with `exit_group`,
//! so nothing of the parent's is flushed or torn down twice. Its stderr goes
//! to /dev/null unless `show_stderr`. Linux only (`supported`).

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const supported = builtin.os.tag == .linux and @bitSizeOf(usize) == 64;

pub const Outcome = union(enum) {
    exited: u8,
    signaled: u32,
    hang,

    pub fn eql(a: Outcome, b: Outcome) bool {
        return switch (a) {
            .exited => |x| b == .exited and b.exited == x,
            .signaled => |x| b == .signaled and b.signaled == x,
            .hang => b == .hang,
        };
    }
};

pub const Options = struct {
    limit_ms: u64,
    show_stderr: bool = false,
};

var debug_info_warm = false;

/// Load this executable's debug info once, here, before the first fork. A
/// child that panics or faults prints a stack trace (to /dev/null, usually),
/// and symbolizing it from a cold start — opening and parsing the DWARF — is
/// paid again by every child; forked after this, they inherit the parsed
/// info. Measured 2026-10-17 on this module's panic-shrink test (Debug,
/// ~20 crashing children): 2.5 s cold, 0.07 s warm.
fn warmDebugInfo() void {
    if (debug_info_warm) return;
    debug_info_warm = true;
    var buf: [256]u8 = undefined;
    var sink: std.Io.Writer.Discarding = .init(&buf);
    std.debug.writeCurrentStackTrace(.{}, .{ .writer = &sink.writer, .mode = .no_color }) catch {};
}

/// Fork; the child runs `f(args)` and exits with the `u8` it returns.
pub fn run(f: anytype, args: anytype, opts: Options) error{ ForkFailed, WaitFailed }!Outcome {
    warmDebugInfo();
    const pid_rc = linux.fork();
    if (linux.errno(pid_rc) != .SUCCESS) return error.ForkFailed;
    const pid: linux.pid_t = @intCast(pid_rc);
    if (pid == 0) {
        // No core dump: under a piped `core_pattern` (systemd-coredump) every
        // crashing candidate was a process handed to the dump handler and a
        // journal entry (the same test: 4.5 s with dumps, 0.07 s without).
        _ = linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 0, 0, 0, 0);
        const no_core: linux.rlimit = .{ .cur = 0, .max = 0 };
        _ = linux.setrlimit(.CORE, &no_core);
        const null_fd = linux.open("/dev/null", .{ .ACCMODE = .WRONLY }, 0);
        if (linux.errno(null_fd) == .SUCCESS) {
            _ = linux.dup2(@intCast(null_fd), 1);
            if (!opts.show_stderr) _ = linux.dup2(@intCast(null_fd), 2);
        }
        const code: u8 = @call(.auto, f, args);
        linux.exit_group(code);
    }

    var timed_out = false;
    const pfd_rc = linux.pidfd_open(pid, 0);
    if (linux.errno(pfd_rc) == .SUCCESS) {
        const pfd: i32 = @intCast(pfd_rc);
        defer _ = linux.close(pfd);
        var fds = [_]linux.pollfd{.{ .fd = pfd, .events = linux.POLL.IN, .revents = 0 }};
        const ms: i32 = @intCast(@min(opts.limit_ms, std.math.maxInt(i32)));
        while (true) {
            const rc = linux.poll(&fds, 1, ms);
            if (linux.errno(rc) == .INTR) continue;
            timed_out = linux.errno(rc) == .SUCCESS and rc == 0;
            break;
        }
    } else {
        // No pidfd (kernel < 5.3): poll the child with WNOHANG.
        const deadline = nowMs() + opts.limit_ms;
        while (true) {
            var st: i32 = 0;
            const rc = linux.wait4(pid, &st, linux.W.NOHANG, null);
            if (linux.errno(rc) != .SUCCESS) return error.WaitFailed;
            if (rc != 0) return decode(@bitCast(st));
            if (nowMs() >= deadline) {
                timed_out = true;
                break;
            }
            const req: linux.timespec = .{ .sec = 0, .nsec = std.time.ns_per_ms };
            _ = linux.nanosleep(&req, null);
        }
    }
    if (timed_out) _ = linux.kill(pid, .KILL);
    var st: i32 = 0;
    while (true) {
        const rc = linux.wait4(pid, &st, 0, null);
        if (linux.errno(rc) == .INTR) continue;
        if (linux.errno(rc) != .SUCCESS) return error.WaitFailed;
        break;
    }
    return if (timed_out) .hang else decode(@bitCast(st));
}

fn decode(st: u32) Outcome {
    if (linux.W.IFEXITED(st)) return .{ .exited = linux.W.EXITSTATUS(st) };
    return .{ .signaled = @backingInt(linux.W.TERMSIG(st)) };
}

fn nowMs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn exitWith(code: u8) u8 {
    return code;
}

fn raise(sig: linux.SIG) u8 {
    _ = linux.kill(linux.getpid(), sig);
    return 0;
}

fn spin() u8 {
    while (true) {
        const req: linux.timespec = .{ .sec = 1, .nsec = 0 };
        _ = linux.nanosleep(&req, null);
    }
}

test "run: an exit code, a signal and a hang are told apart" {
    if (!supported) return error.SkipZigTest;
    try testing.expect((try run(exitWith, .{0}, .{ .limit_ms = 5000 })).eql(.{ .exited = 0 }));
    try testing.expect((try run(exitWith, .{37}, .{ .limit_ms = 5000 })).eql(.{ .exited = 37 }));
    try testing.expect((try run(raise, .{linux.SIG.USR1}, .{ .limit_ms = 5000 })).eql(.{ .signaled = @backingInt(linux.SIG.USR1) }));
    try testing.expect((try run(spin, .{}, .{ .limit_ms = 50 })).eql(.hang));
}

test "Outcome.eql: same kind and same value only" {
    try testing.expect(!(Outcome{ .exited = 1 }).eql(.{ .exited = 2 }));
    try testing.expect(!(Outcome{ .exited = 6 }).eql(.{ .signaled = 6 }));
    try testing.expect(!(Outcome{ .signaled = 6 }).eql(.hang));
    try testing.expect((Outcome{ .signaled = 6 }).eql(.{ .signaled = 6 }));
}
