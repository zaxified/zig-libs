// SPDX-License-Identifier: MIT
//! `Logger`: the one-liner a program wants from a syslog library, as Go's
//! `syslog.Writer` and Rust's `syslog::Logger` give it. It keeps the facility and
//! the sender's identity (detected unless given), reads the clock, formats into
//! the stack and hands the line to a `Sink`. `stdLogFn` routes `std.log` through
//! one.
//!
//! It allocates nothing and never panics. A line past `Options.max_line` goes out
//! cut, with a marker. Safe to call from several threads: formatting happens on
//! the caller's stack and only the sink's send is under the lock.

const std = @import("std");
const linux = std.os.linux;
const message = @import("message.zig");
const bsd = @import("bsd.zig");
const transport = @import("transport.zig");
const unix = @import("unix.zig");

const Facility = message.Facility;
const Severity = message.Severity;
const Timestamp = message.Timestamp;

/// Largest line `Options.max_line` can ask for: the buffer is on the stack.
pub const max_line_limit: usize = 8192;

/// The marker a cut line ends with.
pub const trunc_marker = transport.default_trunc_marker;

/// Where a `Logger` sends. Build one with a `from…` or fill in `sendFn` for a
/// transport of your own; the emitter must outlive the sink.
pub const Sink = struct {
    /// What a sink may answer, the sum of the module's emitters.
    pub const Error = unix.UnixEmitter.SendError || transport.ReconnectingEmitter.SendError ||
        transport.WriterEmitter.SendError;

    ctx: *anyopaque,
    sendFn: *const fn (ctx: *anyopaque, line: []const u8) Error!void,
    /// A local daemon: the receiver knows the host, and journald (the `/dev/log`
    /// of a systemd host) reads RFC 3164 only. `Logger` then defaults to RFC 3164
    /// and omits the HOSTNAME, as `UnixEmitter.sendBsd` does.
    local: bool = false,

    pub fn fromUnix(e: *unix.UnixEmitter) Sink {
        const S = struct {
            fn send(ctx: *anyopaque, line: []const u8) Error!void {
                const em: *unix.UnixEmitter = @ptrCast(@alignCast(ctx));
                return em.sendRaw(line);
            }
        };
        return .{ .ctx = e, .sendFn = S.send, .local = true };
    }

    pub fn fromUdp(e: *transport.UdpEmitter) Sink {
        const S = struct {
            fn send(ctx: *anyopaque, line: []const u8) Error!void {
                const em: *transport.UdpEmitter = @ptrCast(@alignCast(ctx));
                em.sendRaw(line) catch |err| return switch (err) {
                    error.Canceled => error.Canceled,
                    else => error.WriteFailed,
                };
            }
        };
        return .{ .ctx = e, .sendFn = S.send };
    }

    /// A reconnecting stream, TCP or local: `local` as the target says.
    pub fn fromReconnecting(e: *transport.ReconnectingEmitter) Sink {
        const S = struct {
            fn send(ctx: *anyopaque, line: []const u8) Error!void {
                const em: *transport.ReconnectingEmitter = @ptrCast(@alignCast(ctx));
                return em.sendRaw(line);
            }
        };
        return .{ .ctx = e, .sendFn = S.send, .local = e.target == .unix };
    }

    /// A frame onto any writer: the way to a TLS session (RFC 5425).
    pub fn fromWriter(e: *transport.WriterEmitter) Sink {
        const S = struct {
            fn send(ctx: *anyopaque, line: []const u8) Error!void {
                const em: *transport.WriterEmitter = @ptrCast(@alignCast(ctx));
                return em.sendRaw(line);
            }
        };
        return .{ .ctx = e, .sendFn = S.send };
    }
};

pub const Logger = struct {
    pub const Format = enum { rfc5424, rfc3164 };

    pub const Options = struct {
        /// `null`: RFC 3164 for a local sink, RFC 5424 otherwise.
        format: ?Format = null,
        facility: Facility = .user,
        /// `null`: detected (`uname`). `""`: none (NILVALUE, or left out in RFC
        /// 3164). A local sink never sends it in RFC 3164.
        hostname: ?[]const u8 = null,
        /// `null`: the executable's name (`/proc/self/exe`). `""`: none.
        app_name: ?[]const u8 = null,
        /// `null`: this process's pid. `""`: none.
        procid: ?[]const u8 = null,
        /// Lines less severe than this are skipped (`setlogmask`).
        max_severity: Severity = .debug,
        /// A line longer than this goes out cut, with `trunc_marker`. Clamped to
        /// `max_line_limit`. 2048 is what RFC 5424 §6.1 says receivers SHOULD take.
        max_line: usize = 2048,
        /// The clock; a test or a caller with its own time replaces it.
        now: *const fn () Timestamp = wallClock,
    };

    sink: Sink,
    format: Format,
    facility: Facility,
    max_severity: Severity,
    max_line: usize,
    now: *const fn () Timestamp,
    // By value, not slices of this struct or the caller's: a `Logger` can be
    // moved, and the options need not outlive `init`.
    host_buf: [message.max_hostname]u8 = undefined,
    host_len: u16 = 0,
    app_buf: [message.max_app_name]u8 = undefined,
    app_len: u8 = 0,
    proc_buf: [24]u8 = undefined,
    proc_len: u8 = 0,
    /// Lines `stdLogFn` could not hand over (it cannot return an error), and
    /// lines refused because the sink called back into this logger.
    dropped: std.atomic.Value(u64) = .init(0),
    locked: std.atomic.Value(u32) = .init(0),

    pub fn init(sink: Sink, options: Options) Logger {
        var l: Logger = .{
            .sink = sink,
            .format = options.format orelse if (sink.local) .rfc3164 else .rfc5424,
            .facility = options.facility,
            .max_severity = options.max_severity,
            .max_line = @min(options.max_line, max_line_limit),
            .now = options.now,
        };
        l.host_len = @intCast(copyPrefix(&l.host_buf, options.hostname orelse detectHostname(&l.host_buf)));
        l.app_len = @intCast(copyPrefix(&l.app_buf, options.app_name orelse detectAppName(&l.app_buf)));
        if (options.procid) |p| {
            l.proc_len = @intCast(copyPrefix(&l.proc_buf, p));
        } else {
            const pid = std.fmt.bufPrint(&l.proc_buf, "{d}", .{linux.getpid()}) catch "";
            l.proc_len = @intCast(pid.len);
        }
        return l;
    }

    pub fn hostname(l: *const Logger) []const u8 {
        return l.host_buf[0..l.host_len];
    }
    pub fn appName(l: *const Logger) []const u8 {
        return l.app_buf[0..l.app_len];
    }
    pub fn procId(l: *const Logger) []const u8 {
        return l.proc_buf[0..l.proc_len];
    }

    /// One line at `severity`.
    pub fn log(l: *Logger, severity: Severity, msg: []const u8) Sink.Error!void {
        return l.logFull(severity, null, &.{}, msg);
    }

    /// One line with a MSGID and structured data. RFC 3164 has neither: there
    /// they are left out.
    pub fn logFull(l: *Logger, severity: Severity, msgid: ?[]const u8, sd: []const message.SdElement, msg: []const u8) Sink.Error!void {
        if (@backingInt(severity) > @backingInt(l.max_severity)) return;
        var buf: [max_line_limit]u8 = undefined;
        return l.sendLine(l.render(&buf, severity, msgid, sd, msg));
    }

    /// One formatted line. Text past 4 KiB is cut (and `max_line` still holds).
    pub fn print(l: *Logger, severity: Severity, comptime fmt: []const u8, args: anytype) Sink.Error!void {
        if (@backingInt(severity) > @backingInt(l.max_severity)) return;
        var text: [text_buf_len]u8 = undefined;
        return l.log(severity, formatText(&text, fmt, args));
    }

    pub fn emerg(l: *Logger, msg: []const u8) Sink.Error!void {
        return l.log(.emerg, msg);
    }
    pub fn alert(l: *Logger, msg: []const u8) Sink.Error!void {
        return l.log(.alert, msg);
    }
    pub fn crit(l: *Logger, msg: []const u8) Sink.Error!void {
        return l.log(.crit, msg);
    }
    pub fn err(l: *Logger, msg: []const u8) Sink.Error!void {
        return l.log(.err, msg);
    }
    pub fn warning(l: *Logger, msg: []const u8) Sink.Error!void {
        return l.log(.warning, msg);
    }
    pub fn notice(l: *Logger, msg: []const u8) Sink.Error!void {
        return l.log(.notice, msg);
    }
    pub fn info(l: *Logger, msg: []const u8) Sink.Error!void {
        return l.log(.info, msg);
    }
    pub fn debug(l: *Logger, msg: []const u8) Sink.Error!void {
        return l.log(.debug, msg);
    }

    fn render(l: *const Logger, buf: *[max_line_limit]u8, severity: Severity, msgid: ?[]const u8, sd: []const message.SdElement, msg: []const u8) []const u8 {
        const opts: transport.Options = .{ .udp_limit = l.max_line };
        switch (l.format) {
            .rfc5424 => {
                const m: message.Message = .{
                    .facility = l.facility,
                    .severity = severity,
                    .timestamp = l.now(),
                    .hostname = l.hostname(),
                    .app_name = l.appName(),
                    .procid = l.procId(),
                    .msgid = msgid,
                    .structured_data = sd,
                    .msg = msg,
                };
                return transport.buildDatagram(&m, buf, opts);
            },
            .rfc3164 => {
                const m: bsd.Message = .{
                    .facility = l.facility,
                    .severity = severity,
                    .timestamp = l.now(),
                    .hostname = if (l.sink.local) null else l.hostname(),
                    .tag = l.appName(),
                    .pid = if (l.proc_len == 0) null else l.procId(),
                    .msg = msg,
                };
                return transport.buildDatagramBsd(&m, buf, opts);
            },
        }
    }

    fn sendLine(l: *Logger, line: []const u8) Sink.Error!void {
        if (in_sink) {
            _ = l.dropped.fetchAdd(1, .monotonic);
            return;
        }
        l.lock();
        defer l.unlock();
        in_sink = true;
        defer in_sink = false;
        return l.sink.sendFn(l.sink.ctx, line);
    }

    fn lock(l: *Logger) void {
        var spins: u32 = 0;
        while (l.locked.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            spins +%= 1;
            if (spins < 64) {
                std.atomic.spinLoopHint();
            } else {
                // The holder may be waiting out a send deadline: no busy wait.
                const ts: linux.timespec = .{ .sec = 0, .nsec = 100 * std.time.ns_per_us };
                _ = linux.nanosleep(&ts, null);
            }
        }
    }

    fn unlock(l: *Logger) void {
        l.locked.store(0, .release);
    }
};

/// True on a thread inside a sink, so that a sink that logs cannot deadlock on
/// its own logger or recurse.
threadlocal var in_sink: bool = false;

const text_buf_len = 4096;

/// `fmt` into `buf`; a text that does not fit ends with the marker.
fn formatText(buf: []u8, comptime fmt: []const u8, args: anytype) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.print(fmt, args) catch return transport.markTruncated(buf, w.buffered(), buf.len, trunc_marker);
    return w.buffered();
}

/// The `Logger` default clock: `nowTimestamp`.
fn wallClock() Timestamp {
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.REALTIME, &ts)) != .SUCCESS) return .{ .unix_ms = 0 };
    return .{ .unix_ms = @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000) };
}

fn copyPrefix(dst: []u8, src: []const u8) usize {
    const n = @min(dst.len, src.len);
    // `src` may be a slice of `dst` (a detected name).
    std.mem.copyForwards(u8, dst[0..n], src[0..n]);
    return n;
}

/// `uname`'s node name into `buf`; "" when there is none. Linux's own "(none)"
/// means unset.
fn detectHostname(buf: []u8) []const u8 {
    var u: linux.utsname = undefined;
    if (linux.errno(linux.uname(&u)) != .SUCCESS) return "";
    const name = std.mem.sliceTo(&u.nodename, 0);
    if (std.mem.eql(u8, name, "(none)")) return "";
    const n = copyPrefix(buf, name);
    return buf[0..n];
}

/// The last path component of `/proc/self/exe` into `buf`; "" when unreadable.
/// Go takes `os.Args[0]`, Rust's crate `current_exe`: the same name for a program
/// started normally, and this one needs no `argv`.
fn detectAppName(buf: []u8) []const u8 {
    var path: [4096]u8 = undefined;
    const rc = linux.readlink("/proc/self/exe", &path, path.len);
    if (linux.errno(rc) != .SUCCESS) return "";
    const full = path[0..rc];
    const base = if (std.mem.findScalarLast(u8, full, '/')) |i| full[i + 1 ..] else full;
    const n = copyPrefix(buf, base);
    return buf[0..n];
}

// ── std.log ─────────────────────────────────────────────────────────────────

var std_logger: std.atomic.Value(?*Logger) = .init(null);

/// The logger `stdLogFn` writes to; `null` falls back to `std.log.defaultLog`.
pub fn setStdLogger(l: ?*Logger) void {
    std_logger.store(l, .release);
}

/// `std.log` through syslog:
///
///     pub const std_options: std.Options = .{ .logFn = syslog.stdLogFn };
///     // in main:
///     var em = try syslog.UnixEmitter.openDefault();
///     var logger = syslog.Logger.init(.fromUnix(&em), .{ .facility = .daemon });
///     syslog.setStdLogger(&logger);
///
/// `err`, `warn`, `info`, `debug` map to the syslog severities of the same name.
/// A scope becomes the MSGID (RFC 5424) or a `scope: ` prefix of MSG (RFC 3164).
/// A log call cannot return an error: a line the sink refused is counted in
/// `Logger.dropped`.
pub fn stdLogFn(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    const l = std_logger.load(.acquire) orelse return std.log.defaultLog(level, scope, format, args);
    const severity = severityOf(level);
    if (@backingInt(severity) > @backingInt(l.max_severity)) return;
    const has_scope = scope != .default;
    var text: [text_buf_len]u8 = undefined;
    const msg = if (has_scope and l.format == .rfc3164)
        formatText(&text, @tagName(scope) ++ ": " ++ format, args)
    else
        formatText(&text, format, args);
    l.logFull(severity, if (has_scope) @tagName(scope) else null, &.{}, msg) catch {
        _ = l.dropped.fetchAdd(1, .monotonic);
    };
}

fn severityOf(comptime level: std.log.Level) Severity {
    return switch (level) {
        .err => .err,
        .warn => .warning,
        .info => .info,
        .debug => .debug,
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const t = std.testing;
const parser = @import("parse.zig");

const Capture = struct {
    buf: [max_line_limit]u8 = undefined,
    len: usize = 0,
    count: usize = 0,
    fail: ?Sink.Error = null,

    fn sink(c: *Capture, local: bool) Sink {
        return .{ .ctx = c, .sendFn = send, .local = local };
    }

    fn send(ctx: *anyopaque, bytes: []const u8) Sink.Error!void {
        const c: *Capture = @ptrCast(@alignCast(ctx));
        c.count += 1;
        if (c.fail) |e| return e;
        @memcpy(c.buf[0..bytes.len], bytes);
        c.len = bytes.len;
    }

    fn line(c: *const Capture) []const u8 {
        return c.buf[0..c.len];
    }
};

fn fixedClock() Timestamp {
    return .{ .unix_ms = 1783600496123 };
}

const identity: Logger.Options = .{ .hostname = "web-1", .app_name = "api", .procid = "42", .now = fixedClock };

test "Logger: RFC 5424 over a network sink, with what the caller gave" {
    var c: Capture = .{};
    var l = Logger.init(c.sink(false), identity);
    try l.info("hello");
    try t.expectEqualStrings("<14>1 2026-07-09T12:34:56.123Z web-1 api 42 - - hello", c.line());
    try l.logFull(.crit, "ID1", &.{.{ .id = "a@1", .params = &.{.{ .name = "k", .value = "v" }} }}, "x");
    try t.expectEqualStrings("<10>1 2026-07-09T12:34:56.123Z web-1 api 42 ID1 [a@1 k=\"v\"] x", c.line());
}

test "Logger: a local sink defaults to RFC 3164 and sends no hostname" {
    var c: Capture = .{};
    var l = Logger.init(c.sink(true), identity);
    try l.warning("hello");
    try t.expectEqualStrings("<12>Jul  9 12:34:56 api[42]: hello", c.line());

    var r = Logger.init(c.sink(false), blk: {
        var o = identity;
        o.format = .rfc3164;
        o.facility = .daemon;
        break :blk o;
    });
    try r.err("x");
    try t.expectEqualStrings("<27>Jul  9 12:34:56 web-1 api[42]: x", c.line());
}

test "Logger: each severity method, and the mask" {
    var c: Capture = .{};
    var o = identity;
    o.format = .rfc5424;
    o.facility = .kern;
    var l = Logger.init(c.sink(false), o);
    const fns = [_]struct { *const fn (*Logger, []const u8) Sink.Error!void, Severity }{
        .{ Logger.emerg, .emerg },     .{ Logger.alert, .alert },   .{ Logger.crit, .crit }, .{ Logger.err, .err },
        .{ Logger.warning, .warning }, .{ Logger.notice, .notice }, .{ Logger.info, .info }, .{ Logger.debug, .debug },
    };
    for (fns) |f| {
        try f[0](&l, "m");
        const m = try parser.parse(c.line());
        try t.expectEqual(f[1], m.severity);
    }
    l.max_severity = .warning;
    const before = c.count;
    try l.notice("skipped");
    try l.print(.debug, "skipped {d}", .{1});
    try t.expectEqual(before, c.count);
    try l.warning("kept");
    try t.expectEqual(before + 1, c.count);
}

test "Logger: detected identity is the host, the program and the pid" {
    var c: Capture = .{};
    var l = Logger.init(c.sink(false), .{ .now = fixedClock });
    var u: linux.utsname = undefined;
    try t.expectEqual(linux.E.SUCCESS, linux.errno(linux.uname(&u)));
    try t.expectEqualStrings(std.mem.sliceTo(&u.nodename, 0), l.hostname());
    try t.expect(l.appName().len > 0);
    var pid_buf: [24]u8 = undefined;
    try t.expectEqualStrings(try std.fmt.bufPrint(&pid_buf, "{d}", .{linux.getpid()}), l.procId());
    // A moved logger keeps them: they are by value.
    var moved = l;
    try moved.info("x");
    try t.expectEqualStrings(l.hostname(), (try parser.parse(c.line())).hostname.?);
}

test "Logger: empty identity is the NILVALUE; too long is cut to the RFC limit" {
    var c: Capture = .{};
    var l = Logger.init(c.sink(false), .{ .hostname = "", .app_name = "", .procid = "", .now = fixedClock });
    try l.info("x");
    const m = try parser.parse(c.line());
    try t.expectEqual(@as(?[]const u8, null), m.hostname);
    try t.expectEqual(@as(?[]const u8, null), m.app_name);
    try t.expectEqual(@as(?[]const u8, null), m.procid);

    var o = Logger.init(c.sink(false), .{ .hostname = &@as([300]u8, @splat('h')), .app_name = &@as([300]u8, @splat('a')), .procid = &@as([300]u8, @splat('p')), .now = fixedClock });
    try o.info("x");
    const n = try parser.parse(c.line());
    try t.expectEqual(@as(usize, message.max_hostname), n.hostname.?.len);
    try t.expectEqual(@as(usize, message.max_app_name), n.app_name.?.len);
    try t.expectEqual(@as(usize, 24), n.procid.?.len);
}

test "Logger: a long line goes out cut with the marker, at any max_line" {
    var c: Capture = .{};
    var o = identity;
    o.max_line = 128;
    var l = Logger.init(c.sink(false), o);
    try l.info(&@as([1000]u8, @splat('x')));
    try t.expectEqual(@as(usize, 128), c.len);
    try t.expect(std.mem.endsWith(u8, c.line(), trunc_marker));

    o.max_line = std.math.maxInt(usize);
    var big = Logger.init(c.sink(false), o);
    try big.info(&@as([2 * max_line_limit]u8, @splat('x')));
    try t.expectEqual(max_line_limit, c.len);
    try t.expect(std.mem.endsWith(u8, c.line(), trunc_marker));

    o.max_line = 0;
    var none = Logger.init(c.sink(false), o);
    try none.info("x");
    try t.expectEqual(@as(usize, 0), c.len);
}

test "Logger.print: formats, and cuts what does not fit" {
    var c: Capture = .{};
    var o = identity;
    o.max_line = max_line_limit;
    var l = Logger.init(c.sink(false), o);
    try l.print(.info, "n={d} s={s}", .{ 7, "z" });
    try t.expect(std.mem.endsWith(u8, c.line(), " n=7 s=z"));
    try l.print(.info, "{s}", .{&@as([5000]u8, @splat('y'))});
    try t.expect(std.mem.endsWith(u8, c.line(), trunc_marker));
    try t.expect(c.len < 4200);
}

test "Logger: a sink's error comes back" {
    var c: Capture = .{ .fail = error.WouldBlock };
    var l = Logger.init(c.sink(false), identity);
    try t.expectError(error.WouldBlock, l.info("x"));
}

test "Logger: a sink that logs through its own logger does not deadlock" {
    const Re = struct {
        var logger: Logger = undefined;
        var seen: usize = 0;
        fn send(_: *anyopaque, _: []const u8) Sink.Error!void {
            seen += 1;
            try logger.info("from inside the sink");
        }
    };
    var dummy: u8 = 0;
    Re.seen = 0;
    Re.logger = Logger.init(.{ .ctx = &dummy, .sendFn = Re.send }, identity);
    try Re.logger.info("x");
    try t.expectEqual(@as(usize, 1), Re.seen);
    try t.expectEqual(@as(u64, 1), Re.logger.dropped.load(.monotonic));
}

test "Logger from several threads: every line is whole" {
    const Count = struct {
        total: std.atomic.Value(usize) = .init(0),
        fn send(ctx: *anyopaque, line: []const u8) Sink.Error!void {
            const s: *@This() = @ptrCast(@alignCast(ctx));
            if (!std.mem.endsWith(u8, line, " payload")) return error.WriteFailed;
            _ = s.total.fetchAdd(1, .monotonic);
        }
        fn run(l: *Logger) void {
            for (0..2000) |_| l.info("payload") catch @panic("send");
        }
    };
    var c: Count = .{};
    var l = Logger.init(.{ .ctx = &c, .sendFn = Count.send }, identity);
    var threads: [4]std.Thread = undefined;
    for (&threads) |*th| th.* = try std.Thread.spawn(.{}, Count.run, .{&l});
    for (threads) |th| th.join();
    try t.expectEqual(@as(usize, 8000), c.total.load(.monotonic));
}

test "stdLogFn: levels, scope as MSGID, and a refused line is counted" {
    var c: Capture = .{};
    var l = Logger.init(c.sink(false), identity);
    setStdLogger(&l);
    defer setStdLogger(null);

    stdLogFn(.err, .default, "bad {d}", .{1});
    var m = try parser.parse(c.line());
    try t.expectEqual(Severity.err, m.severity);
    try t.expectEqual(@as(?[]const u8, null), m.msgid);
    try t.expectEqualStrings("bad 1", m.msg);

    stdLogFn(.warn, .myscope, "w", .{});
    m = try parser.parse(c.line());
    try t.expectEqual(Severity.warning, m.severity);
    try t.expectEqualStrings("myscope", m.msgid.?);

    stdLogFn(.info, .default, "i", .{});
    try t.expectEqual(Severity.info, (try parser.parse(c.line())).severity);
    stdLogFn(.debug, .default, "d", .{});
    try t.expectEqual(Severity.debug, (try parser.parse(c.line())).severity);

    c.fail = error.WouldBlock;
    stdLogFn(.info, .default, "lost", .{});
    try t.expectEqual(@as(u64, 1), l.dropped.load(.monotonic));
}

test "stdLogFn: RFC 3164 has no MSGID, so the scope prefixes MSG; a mask skips" {
    var c: Capture = .{};
    var o = identity;
    o.format = .rfc3164;
    var l = Logger.init(c.sink(false), o);
    setStdLogger(&l);
    defer setStdLogger(null);
    stdLogFn(.info, .db, "up {s}", .{"now"});
    try t.expectEqualStrings("<14>Jul  9 12:34:56 web-1 api[42]: db: up now", c.line());

    l.max_severity = .err;
    const before = c.count;
    stdLogFn(.info, .db, "skipped", .{});
    try t.expectEqual(before, c.count);
}
