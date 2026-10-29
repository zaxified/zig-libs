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

fn realPoll(fds: []linux.pollfd, ms: i32) usize {
    return linux.poll(fds.ptr, fds.len, ms);
}

const Wait = enum { ready, timed_out, failed };

/// Poll `fds` until one is ready or `deadline` (ms, monotonic) passes. After
/// a signal the time LEFT is polled, not the whole limit again, and a limit
/// past `poll`'s `i32` milliseconds is polled in pieces.
fn waitReadable(comptime pollFn: anytype, fds: []linux.pollfd, deadline: u64) Wait {
    while (true) {
        const left = deadline -| nowMs();
        const ms: i32 = @intCast(@min(left, std.math.maxInt(i32)));
        const rc = pollFn(fds, ms);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                if (rc != 0) return .ready;
                if (nowMs() >= deadline) return .timed_out;
            },
            .INTR => {},
            else => return .failed,
        }
    }
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
        const deadline = deadlineAfter(nowMs(), opts.limit_ms);
        // A poll that fails (not a signal) cannot bound the wait: the child
        // is killed and reaped below and reported as a hang.
        timed_out = waitReadable(realPoll, &fds, deadline) != .ready;
    } else {
        // No pidfd (kernel < 5.3): poll the child with WNOHANG.
        const deadline = deadlineAfter(nowMs(), opts.limit_ms);
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

/// `now + limit`, saturating (`limit_ms` is the caller's; maxInt = "no limit").
fn deadlineAfter(now: u64, limit_ms: u64) u64 {
    return now +| limit_ms;
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

test "deadlineAfter saturates on an unlimited limit_ms (sweep TK-4)" {
    try testing.expectEqual(@as(u64, 1500), deadlineAfter(1000, 500));
    try testing.expectEqual(std.math.maxInt(u64), deadlineAfter(1000, std.math.maxInt(u64)));
}

var fake_calls: u32 = 0;
var fake_ms: [3]i32 = undefined;

fn eintrThenReady(_: []linux.pollfd, ms: i32) usize {
    fake_ms[fake_calls] = ms;
    fake_calls += 1;
    if (fake_calls == 1) {
        const nap: linux.timespec = .{ .sec = 0, .nsec = 300 * std.time.ns_per_ms };
        _ = linux.nanosleep(&nap, null);
        return @bitCast(-@as(isize, @backingInt(linux.E.INTR)));
    }
    return 1;
}

fn pollFails(_: []linux.pollfd, _: i32) usize {
    // A retrying waiter would end here (after 3 calls: "ready"), not loop.
    fake_calls += 1;
    if (fake_calls > 3) return 1;
    return @bitCast(-@as(isize, @backingInt(linux.E.INVAL)));
}

test "waitReadable: after EINTR the time left is polled, not the full limit again (review R-TK-5)" {
    var fds = [_]linux.pollfd{.{ .fd = 0, .events = linux.POLL.IN, .revents = 0 }};
    fake_calls = 0;
    try testing.expectEqual(Wait.ready, waitReadable(eintrThenReady, &fds, nowMs() + 1000));
    try testing.expectEqual(@as(u32, 2), fake_calls);
    try testing.expect(fake_ms[0] > 900);
    try testing.expect(fake_ms[1] < 800);
}

test "waitReadable: a poll error is a failure, not a retry (review R-TK-5)" {
    var fds = [_]linux.pollfd{.{ .fd = 0, .events = linux.POLL.IN, .revents = 0 }};
    fake_calls = 0;
    try testing.expectEqual(Wait.failed, waitReadable(pollFails, &fds, nowMs() + 1000));
}

fn spuriousZeroThenReady(_: []linux.pollfd, ms: i32) usize {
    fake_ms[fake_calls] = ms;
    fake_calls += 1;
    return if (fake_calls < 3) 0 else 1;
}

test "waitReadable: a poll that returns 0 before the deadline is polled again, not a timeout (audit TK-13)" {
    var fds = [_]linux.pollfd{.{ .fd = 0, .events = linux.POLL.IN, .revents = 0 }};
    fake_calls = 0;
    try testing.expectEqual(Wait.ready, waitReadable(spuriousZeroThenReady, &fds, nowMs() + 60_000));
    try testing.expectEqual(@as(u32, 3), fake_calls);
}
