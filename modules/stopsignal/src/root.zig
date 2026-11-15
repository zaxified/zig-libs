// SPDX-License-Identifier: MIT

//! stopsignal — the process's own stop signals (SIGTERM, SIGINT, SIGHUP, ...)
//! as a readable event source, for a daemon that must flush its state and exit
//! cleanly. The Go `signal.NotifyContext` / tokio `signal::unix` job, built on
//! a Linux `signalfd` instead of a global handler: no handler runs, no global
//! state is touched, and the arrival is a value the caller reads.
//!
//! ```zig
//! var stop = try stopsignal.StopSignals.init(.{});   // SIGTERM + SIGINT
//! defer stop.deinit();
//! // ... start worker threads AFTER init, never before ...
//! const which = try stop.wait(io);                   // blocks until one arrives
//! ```
//!
//! READ THIS BEFORE CALLING `init`:
//!
//!   * **Call `init` before any other thread is started.** It blocks the
//!     signals in the CALLING thread only (`rt_sigprocmask` is per thread) and
//!     a new thread inherits its creator's mask. A thread that already exists
//!     keeps the signal unblocked, and the kernel delivers a process-directed
//!     signal (`kill`, Ctrl-C) to ANY thread that does not block it: the signal
//!     would run its default action (terminate) and never reach `wait`. Where
//!     other threads must exist already, block the set in each of them too.
//!   * **A blocked mask is inherited across `fork`/`exec`.** A child started
//!     while the stop signals are blocked cannot be stopped by them either:
//!     SIGTERM stays pending in the child until it unblocks. `procrun`'s
//!     Linux spawner starts children with an empty mask by default
//!     (`Spec.reset_signal_mask`); std's `process.spawn` does not, so a child
//!     spawned through it inherits the blocked set. See `childMask`.
//!   * `deinit` must run in the thread that called `init`.
//!   * One reader per `StopSignals`: `poll`/`wait` from two threads at once
//!     compete for the same queue.
//!
//! Linux only (`error.Unsupported` elsewhere). Standard signals coalesce: two
//! SIGTERMs sent before the first is read arrive as one.

const std = @import("std");
const builtin = @import("builtin");

const linux = std.os.linux;

pub const meta = .{
    .doc = "The process's own stop signals (SIGTERM/SIGINT/SIGHUP...) via blocked mask + signalfd: wait/poll/fd, no global handler (Go signal.NotifyContext, tokio signal::unix).",
    .platform_note = "linux (signalfd); error.Unsupported elsewhere",
    .targets = .{.linux64},
    .platform = .linux,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "Go os/signal NotifyContext; tokio signal::unix",
    .deps = .{},
};

pub const Error = error{
    /// Not Linux: there is no `signalfd` here.
    Unsupported,
    /// `Set` has no member enabled; nothing to wait for.
    EmptySet,
    /// The kernel refused the signalfd (fd or memory limit).
    SystemResources,
    /// A syscall failed in a way this module does not model.
    Unexpected,
};

pub const WaitError = Error || error{Canceled};

/// The signals this module can watch.
pub const Signo = enum {
    term,
    int,
    hup,
    quit,
    usr1,
    usr2,

    fn sig(self: Signo) linux.SIG {
        return switch (self) {
            .term => .TERM,
            .int => .INT,
            .hup => .HUP,
            .quit => .QUIT,
            .usr1 => .USR1,
            .usr2 => .USR2,
        };
    }

    fn fromRaw(n: u32) ?Signo {
        inline for (.{ Signo.term, Signo.int, Signo.hup, Signo.quit, Signo.usr1, Signo.usr2 }) |s| {
            if (n == @backingInt(s.sig())) return s;
        }
        return null;
    }
};

/// Which signals to take over. The default is SIGTERM and SIGINT, what a
/// service manager and a terminal send.
pub const Set = struct {
    term: bool = true,
    int: bool = true,
    hup: bool = false,
    quit: bool = false,
    usr1: bool = false,
    usr2: bool = false,

    fn any(self: Set) bool {
        return self.term or self.int or self.hup or self.quit or self.usr1 or self.usr2;
    }
};

pub const StopSignals = struct {
    fd_: linux.fd_t,
    /// Every signal of the set (what the signalfd delivers).
    mask: linux.sigset_t,
    /// The subset THIS instance moved from unblocked to blocked; `deinit`
    /// unblocks exactly these, so a signal the caller had blocked before stays
    /// blocked.
    newly_blocked: linux.sigset_t,

    /// Block `set` in the calling thread and open a signalfd for it. See the
    /// module header: call it before starting any other thread.
    pub fn init(set: Set) Error!StopSignals {
        if (builtin.os.tag != .linux) return error.Unsupported;
        if (!set.any()) return error.EmptySet;

        var mask = linux.sigemptyset();
        if (set.term) linux.sigaddset(&mask, .TERM);
        if (set.int) linux.sigaddset(&mask, .INT);
        if (set.hup) linux.sigaddset(&mask, .HUP);
        if (set.quit) linux.sigaddset(&mask, .QUIT);
        if (set.usr1) linux.sigaddset(&mask, .USR1);
        if (set.usr2) linux.sigaddset(&mask, .USR2);

        var old = linux.sigemptyset();
        if (linux.errno(linux.sigprocmask(linux.SIG.BLOCK, &mask, &old)) != .SUCCESS)
            return error.Unexpected;
        var newly = mask;
        for (&newly, old) |*n, o| n.* &= ~o;

        const rc = linux.signalfd(-1, &mask, linux.SFD.CLOEXEC);
        const got: ?linux.fd_t = switch (linux.errno(rc)) {
            .SUCCESS => std.math.cast(linux.fd_t, rc),
            else => null,
        };
        if (got == null) {
            const e = linux.errno(rc);
            _ = linux.sigprocmask(linux.SIG.UNBLOCK, &newly, null);
            return switch (e) {
                .MFILE, .NFILE, .NOMEM, .NODEV => error.SystemResources,
                else => error.Unexpected,
            };
        }
        return .{ .fd_ = got.?, .mask = mask, .newly_blocked = newly };
    }

    /// Close the fd and unblock the signals `init` blocked (in the calling
    /// thread, which must be the one that called `init`). A signal still
    /// pending at that moment is then delivered with its default action —
    /// usually terminating the process — so drain the queue first if that
    /// matters.
    pub fn deinit(self: *StopSignals) void {
        if (builtin.os.tag != .linux) return;
        _ = linux.sigprocmask(linux.SIG.UNBLOCK, &self.newly_blocked, null);
        _ = linux.close(self.fd_);
        self.* = undefined;
    }

    /// The signalfd, for a caller's own epoll/io_uring loop. Readable when a
    /// signal is pending; read `signalfd_siginfo` records from it, or call
    /// `poll`. Closed by `deinit`; do not close it yourself.
    pub fn fd(self: *const StopSignals) linux.fd_t {
        return self.fd_;
    }

    /// The set of signals blocked by this instance, for a caller that starts
    /// children with its own pre-exec code and wants to unblock them there
    /// (`rt_sigprocmask(SIG_UNBLOCK, &mask, null)` before `exec`). procrun
    /// does this itself (`Spec.reset_signal_mask`, default on).
    pub fn childMask(self: *const StopSignals) linux.sigset_t {
        return self.newly_blocked;
    }

    /// Non-blocking: the next pending signal, or `null` when none is queued.
    /// The "flag form" for a loop that checks between units of work.
    pub fn poll(self: *const StopSignals) Error!?Signo {
        var pfd = [1]linux.pollfd{.{ .fd = self.fd_, .events = linux.POLL.IN }};
        while (true) {
            const rc = linux.poll(&pfd, 1, 0);
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return null;
                    break;
                },
                .INTR => continue,
                else => return error.Unexpected,
            }
        }
        var info: linux.signalfd_siginfo = undefined;
        while (true) {
            const n = linux.read(self.fd_, std.mem.asBytes(&info).ptr, @sizeOf(linux.signalfd_siginfo));
            switch (linux.errno(n)) {
                .SUCCESS => {},
                .INTR => continue,
                .AGAIN => return null,
                else => return error.Unexpected,
            }
            if (n != @sizeOf(linux.signalfd_siginfo)) return error.Unexpected;
            return Signo.fromRaw(info.signo) orelse error.Unexpected;
        }
    }

    /// Block until a signal arrives and return it. The read goes through `io`,
    /// so cancelling the task returns `error.Canceled`.
    pub fn wait(self: *const StopSignals, io: std.Io) WaitError!Signo {
        var info: linux.signalfd_siginfo = undefined;
        var bufs = [1][]u8{std.mem.asBytes(&info)};
        const file: std.Io.File = .{ .handle = self.fd_, .flags = .{ .nonblocking = false } };
        const n = file.readStreaming(io, &bufs) catch |e| switch (e) {
            error.Canceled => return error.Canceled,
            else => return error.Unexpected,
        };
        if (n != @sizeOf(linux.signalfd_siginfo)) return error.Unexpected;
        return Signo.fromRaw(info.signo) orelse error.Unexpected;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────
//
// Signals are sent to the test's own thread (tgkill on gettid), so a blocked
// signal stays pending for that thread and cannot reach another one.

const testing = std.testing;

fn sendSelf(s: linux.SIG) !void {
    if (linux.errno(linux.tgkill(linux.getpid(), linux.gettid(), s)) != .SUCCESS) return error.SendFailed;
}

fn isBlocked(s: linux.SIG) bool {
    var cur = linux.sigemptyset();
    _ = linux.sigprocmask(linux.SIG.BLOCK, null, &cur);
    return linux.sigismember(&cur, s);
}

test "wait returns the signal that arrived" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var st = try StopSignals.init(.{});
    defer st.deinit();
    try sendSelf(.TERM);
    try testing.expectEqual(Signo.term, try st.wait(testing.io));
    try sendSelf(.INT);
    try testing.expectEqual(Signo.int, try st.wait(testing.io));
}

test "poll on an empty queue is null, then sees the signal once" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var st = try StopSignals.init(.{});
    defer st.deinit();
    try testing.expectEqual(@as(?Signo, null), try st.poll());
    try sendSelf(.TERM);
    try testing.expectEqual(@as(?Signo, .term), try st.poll());
    try testing.expectEqual(@as(?Signo, null), try st.poll());
}

test "two different signals pending are both delivered" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var st = try StopSignals.init(.{ .term = true, .int = true, .usr1 = true });
    defer st.deinit();
    try sendSelf(.USR1);
    try sendSelf(.TERM);
    const a = (try st.poll()).?;
    const b = (try st.poll()).?;
    try testing.expect(a != b);
    try testing.expect((a == .usr1 and b == .term) or (a == .term and b == .usr1));
    try testing.expectEqual(@as(?Signo, null), try st.poll());
}

test "the same signal sent twice coalesces into one" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var st = try StopSignals.init(.{});
    defer st.deinit();
    try sendSelf(.TERM);
    try sendSelf(.TERM);
    try testing.expectEqual(@as(?Signo, .term), try st.poll());
    try testing.expectEqual(@as(?Signo, null), try st.poll());
}

test "every Set member maps to its own Signo" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const cases = [_]struct { set: Set, sig: linux.SIG, want: Signo }{
        .{ .set = .{ .term = true, .int = false }, .sig = .TERM, .want = .term },
        .{ .set = .{ .term = false, .int = true }, .sig = .INT, .want = .int },
        .{ .set = .{ .term = false, .int = false, .hup = true }, .sig = .HUP, .want = .hup },
        .{ .set = .{ .term = false, .int = false, .quit = true }, .sig = .QUIT, .want = .quit },
        .{ .set = .{ .term = false, .int = false, .usr1 = true }, .sig = .USR1, .want = .usr1 },
        .{ .set = .{ .term = false, .int = false, .usr2 = true }, .sig = .USR2, .want = .usr2 },
    };
    for (cases) |c| {
        var st = try StopSignals.init(c.set);
        defer st.deinit();
        try testing.expect(isBlocked(c.sig));
        try sendSelf(c.sig);
        try testing.expectEqual(c.want, try st.wait(testing.io));
    }
}

test "a signal outside the set is not taken over" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var st = try StopSignals.init(.{ .term = true, .int = false });
    defer st.deinit();
    try testing.expect(isBlocked(.TERM));
    try testing.expect(!isBlocked(.INT));
}

test "deinit restores the mask, but keeps what the caller had blocked" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var pre = linux.sigemptyset();
    linux.sigaddset(&pre, .USR2);
    _ = linux.sigprocmask(linux.SIG.BLOCK, &pre, null);
    defer _ = linux.sigprocmask(linux.SIG.UNBLOCK, &pre, null);

    try testing.expect(!isBlocked(.USR1));
    var st = try StopSignals.init(.{ .term = false, .int = false, .usr1 = true, .usr2 = true });
    try testing.expect(isBlocked(.USR1));
    try testing.expect(isBlocked(.USR2));
    st.deinit();
    try testing.expect(!isBlocked(.USR1));
    try testing.expect(isBlocked(.USR2)); // was blocked before init
}

test "init refuses an empty set; deinit unblocks nothing then" {
    try testing.expectError(error.EmptySet, StopSignals.init(.{ .term = false, .int = false }));
}

test "wait blocks until another thread sends" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var st = try StopSignals.init(.{ .term = false, .int = false, .usr1 = true });
    defer st.deinit();
    const tid = linux.gettid();
    const t = try std.Thread.spawn(.{}, struct {
        fn run(target: linux.pid_t) void {
            _ = linux.tgkill(linux.getpid(), target, .USR1);
        }
    }.run, .{tid});
    defer t.join();
    try testing.expectEqual(Signo.usr1, try st.wait(testing.io));
}

test "fd is pollable and childMask names the blocked set" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var st = try StopSignals.init(.{});
    defer st.deinit();
    var pfd = [1]linux.pollfd{.{ .fd = st.fd(), .events = linux.POLL.IN }};
    try testing.expectEqual(@as(usize, 0), linux.poll(&pfd, 1, 0));
    try sendSelf(.INT);
    try testing.expectEqual(@as(usize, 1), linux.poll(&pfd, 1, 0));
    try testing.expectEqual(@as(?Signo, .int), try st.poll());
    const cm = st.childMask();
    try testing.expect(linux.sigismember(&cm, .TERM) and linux.sigismember(&cm, .INT));
    try testing.expect(!linux.sigismember(&cm, .HUP));
}

test "the signalfd is close-on-exec, and deinit closes it (mutation 2026-11-15)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var st = try StopSignals.init(.{});
    const raw = st.fd();
    const flags = linux.fcntl(raw, linux.F.GETFD, 0);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(flags));
    try testing.expect(flags & linux.FD_CLOEXEC != 0);
    st.deinit();
    try testing.expectEqual(linux.E.BADF, linux.errno(linux.fcntl(raw, linux.F.GETFD, 0)));
}

test "childMask is what this instance blocked; mask is the whole set (mutation 2026-11-15)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var pre = linux.sigemptyset();
    linux.sigaddset(&pre, .TERM);
    _ = linux.sigprocmask(linux.SIG.BLOCK, &pre, null);
    defer _ = linux.sigprocmask(linux.SIG.UNBLOCK, &pre, null);
    var st = try StopSignals.init(.{});
    defer st.deinit();
    const cm = st.childMask();
    try testing.expect(linux.sigismember(&cm, .INT));
    try testing.expect(!linux.sigismember(&cm, .TERM)); // blocked before init: not ours to unblock
    try testing.expect(linux.sigismember(&st.mask, .INT));
    try testing.expect(linux.sigismember(&st.mask, .TERM));
    try testing.expect(!linux.sigismember(&st.mask, .HUP));
}

test "an fd limit refusal is SystemResources and leaves the mask as it was (mutation 2026-11-15)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    try testing.expect(!isBlocked(.TERM));
    var old: linux.rlimit = undefined;
    if (linux.errno(linux.getrlimit(.NOFILE, &old)) != .SUCCESS) return error.SkipZigTest;
    const tight: linux.rlimit = .{ .cur = 0, .max = old.max };
    if (linux.errno(linux.setrlimit(.NOFILE, &tight)) != .SUCCESS) return error.SkipZigTest;
    const res = StopSignals.init(.{});
    _ = linux.setrlimit(.NOFILE, &old);
    try testing.expectError(error.SystemResources, res);
    try testing.expect(!isBlocked(.TERM));
    try testing.expect(!isBlocked(.INT));
}

/// A `StopSignals` whose descriptor is the read end of a pipe holding `bytes`
/// (then EOF): lets a test feed `poll`/`wait` records the kernel never would.
fn pipeFed(bytes: []const u8) !StopSignals {
    var p: [2]i32 = undefined;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.pipe2(&p, .{ .CLOEXEC = true })));
    if (bytes.len != 0) try testing.expectEqual(bytes.len, linux.write(p[1], bytes.ptr, bytes.len));
    _ = linux.close(p[1]);
    return .{ .fd_ = p[0], .mask = linux.sigemptyset(), .newly_blocked = linux.sigemptyset() };
}

fn record(signo: u32) linux.signalfd_siginfo {
    var r = std.mem.zeroes(linux.signalfd_siginfo);
    r.signo = signo;
    return r;
}

test "poll and wait read exactly one whole record and refuse anything else (mutation 2026-11-15)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // a well-formed record of a modelled signal is returned
    const term = record(@backingInt(linux.SIG.TERM));
    var a = try pipeFed(std.mem.asBytes(&term));
    try testing.expectEqual(@as(?Signo, .term), try a.poll());
    _ = linux.close(a.fd_);
    var b = try pipeFed(std.mem.asBytes(&term));
    try testing.expectEqual(Signo.term, try b.wait(testing.io));
    _ = linux.close(b.fd_);

    // a record of a signal the module does not model is an error, not a guess
    const kill = record(@backingInt(linux.SIG.KILL));
    var c = try pipeFed(std.mem.asBytes(&kill));
    try testing.expectError(error.Unexpected, c.poll());
    _ = linux.close(c.fd_);
    var d = try pipeFed(std.mem.asBytes(&kill));
    try testing.expectError(error.Unexpected, d.wait(testing.io));
    _ = linux.close(d.fd_);

    // a short read is an error, even when the bytes that did arrive name a signal
    var e = try pipeFed(std.mem.asBytes(&term)[0..4]);
    try testing.expectError(error.Unexpected, e.poll());
    _ = linux.close(e.fd_);
    var f = try pipeFed(std.mem.asBytes(&term)[0..4]);
    try testing.expectError(error.Unexpected, f.wait(testing.io));
    _ = linux.close(f.fd_);

    // a descriptor that is not open at all
    var g = try pipeFed("");
    _ = linux.close(g.fd_);
    try testing.expectError(error.Unexpected, g.wait(testing.io));
}

test "Signo.fromRaw: every modelled number maps back, others are null (mutation 2026-11-15)" {
    inline for (.{ Signo.term, Signo.int, Signo.hup, Signo.quit, Signo.usr1, Signo.usr2 }) |s| {
        try testing.expectEqual(@as(?Signo, s), Signo.fromRaw(@backingInt(s.sig())));
    }
    for ([_]linux.SIG{ .KILL, .CHLD, .STOP, .PIPE }) |s| try testing.expectEqual(@as(?Signo, null), Signo.fromRaw(@backingInt(s)));
    try testing.expectEqual(@as(?Signo, null), Signo.fromRaw(0));
    try testing.expectEqual(@as(?Signo, null), Signo.fromRaw(std.math.maxInt(u32)));
}

test "wait reports error.Canceled when its task is canceled (mutation 2026-11-15)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var st = try StopSignals.init(.{ .term = false, .int = false, .usr1 = true });
    defer st.deinit();
    var fut = testing.io.concurrent(StopSignals.wait, .{ &st, testing.io }) catch return error.SkipZigTest;
    try testing.expectError(error.Canceled, fut.cancel(testing.io));
}
