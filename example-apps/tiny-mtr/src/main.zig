//! tiny-mtr: a continuous traceroute with a live table.
//!
//! Three threads, so that none of them ever waits for another's slow work:
//! the main thread owns the terminal and only ever blocks in `poll`, the prober
//! owns the sockets and spends its life inside `Mtr.round`, and the namer owns
//! the DNS resolver. A key is read and answered at once, whatever a round is
//! doing. They meet in `Shared` and `Names`, under a lock held for a copy, and
//! anything that has news writes the eventfd that `poll` watches.
const std = @import("std");
const dns = @import("dns");
const netaddr = @import("netaddr");
const traceroute = @import("traceroute");
const cli = @import("cli.zig");
const view = @import("view.zig");

const linux = std.os.linux;
const Io = std.Io;
const MtrHop = traceroute.MtrHop;
const Probe = traceroute.Probe;

// ── waking the main thread ──────────────────────────────────────────────────

var wake_fd: linux.fd_t = -1;
var signal_quit: std.atomic.Value(bool) = .init(false);
var signal_resize: std.atomic.Value(bool) = .init(false);

/// Safe from a signal handler: one syscall on a descriptor that never closes.
fn wake() void {
    const one: u64 = 1;
    _ = linux.write(wake_fd, std.mem.asBytes(&one), @sizeOf(u64));
}

fn onQuitSignal(_: linux.SIG) callconv(.c) void {
    signal_quit.store(true, .release);
    wake();
}

fn onResize(_: linux.SIG) callconv(.c) void {
    signal_resize.store(true, .release);
    wake();
}

fn handle(sig: linux.SIG, f: *const fn (linux.SIG) callconv(.c) void) void {
    const act: linux.Sigaction = .{ .handler = .{ .handler = f }, .mask = linux.sigemptyset(), .flags = 0 };
    _ = linux.sigaction(sig, &act, null);
}

// ── the terminal ────────────────────────────────────────────────────────────

var saved_termios: ?std.posix.termios = null;
var terminal_taken: std.atomic.Value(bool) = .init(false);

const enter_screen = "\x1b[?1049h\x1b[?25l";
const leave_screen = "\x1b[?25h\x1b[?1049l";

/// Every way out goes through here: a normal exit, a signal, a panic on any
/// thread. Only the first caller acts.
fn restoreTerminal() void {
    if (!terminal_taken.swap(false, .acq_rel)) return;
    _ = linux.write(1, leave_screen, leave_screen.len);
    if (saved_termios) |t| std.posix.tcsetattr(0, .FLUSH, t) catch {};
}

fn takeTerminal() !void {
    const original = try std.posix.tcgetattr(0);
    var raw = original;
    raw.lflag.ICANON = false;
    raw.lflag.ECHO = false;
    raw.lflag.IEXTEN = false;
    // Ctrl-C arrives as a byte, and takes the same way out as `q`.
    raw.lflag.ISIG = false;
    raw.iflag.IXON = false;
    raw.iflag.ICRNL = false;
    raw.cc[@backingInt(linux.V.MIN)] = 1;
    raw.cc[@backingInt(linux.V.TIME)] = 0;
    saved_termios = original;
    terminal_taken.store(true, .release);
    try std.posix.tcsetattr(0, .FLUSH, raw);
    _ = linux.write(1, enter_screen, enter_screen.len);
}

const panicHandler = struct {
    fn call(msg: []const u8, ra: ?usize) noreturn {
        restoreTerminal();
        std.debug.defaultPanic(msg, ra);
    }
}.call;
pub const panic = std.debug.FullPanic(panicHandler);

const WindowSize = struct { width: usize, height: usize };

fn windowSize() WindowSize {
    var ws: std.posix.winsize = undefined;
    const rc = linux.ioctl(1, linux.T.IOCGWINSZ, @intFromPtr(&ws));
    // A fresh pty reports 0 x 0.
    if (linux.errno(rc) != .SUCCESS or ws.col == 0 or ws.row == 0) return .{ .width = 80, .height = 24 };
    return .{ .width = ws.col, .height = ws.row };
}

// ── host names ──────────────────────────────────────────────────────────────

/// PTR answers, looked up one at a time on the namer's thread: one slow
/// server delays other names, never the table.
const Names = struct {
    io: Io,
    gpa: std.mem.Allocator,
    mutex: Io.Mutex = .init,
    has_work: Io.Condition = .init,
    /// Null: asked, no answer (yet). Names live as long as the process.
    known: std.AutoHashMapUnmanaged(netaddr.Ip, ?[]const u8) = .empty,
    queue: std.ArrayList(netaddr.Ip) = .empty,
    busy: bool = false,

    /// A path has a few dozen routers; this bounds a hostile one that answers
    /// from a new address each time.
    const max_known = 1024;

    /// The name if known; otherwise asks for it, once.
    fn get(n: *Names, ip: netaddr.Ip) ?[]const u8 {
        n.mutex.lockUncancelable(n.io);
        defer n.mutex.unlock(n.io);
        if (n.known.get(ip)) |name| return name;
        if (n.known.count() >= max_known) return null;
        n.known.put(n.gpa, ip, null) catch return null;
        n.queue.append(n.gpa, ip) catch return null;
        n.has_work.signal(n.io);
        return null;
    }

    fn idle(n: *Names) bool {
        n.mutex.lockUncancelable(n.io);
        defer n.mutex.unlock(n.io);
        return n.queue.items.len == 0 and !n.busy;
    }

    fn run(n: *Names) void {
        var r = dns.Resolver.init(n.io, n.gpa, .{ .timeout_ms = 1500, .attempts = 1, .call_timeout_ms = 2000 });
        defer r.deinit();
        while (true) {
            n.mutex.lockUncancelable(n.io);
            n.busy = false;
            while (n.queue.items.len == 0) n.has_work.waitUncancelable(n.io, &n.mutex);
            const ip = n.queue.pop().?;
            n.busy = true;
            n.mutex.unlock(n.io);

            const name = n.ask(&r, ip);

            n.mutex.lockUncancelable(n.io);
            if (name) |text| n.known.put(n.gpa, ip, text) catch {};
            n.mutex.unlock(n.io);
            if (name != null) wake();
        }
    }

    fn ask(n: *Names, r: *dns.Resolver, ip: netaddr.Ip) ?[]const u8 {
        const answers = r.reverse(ip) catch return null;
        defer r.freeNames(answers);
        if (answers.len == 0) return null;
        const raw = std.mem.trimEnd(u8, answers[0], ".");
        if (raw.len == 0) return null;
        const out = n.gpa.alloc(u8, raw.len) catch return null;
        return view.sanitize(out, raw);
    }
};

// ── probing ─────────────────────────────────────────────────────────────────

/// What the prober publishes. `live` is this round's answers as they come;
/// `hops` the statistics as of the last finished round.
const Shared = struct {
    io: Io,
    mutex: Io.Mutex = .init,
    hops: []MtrHop,
    hop_count: usize = 0,
    live: []?Probe,
    rounds: u64 = 0,
    failure: ?traceroute.TransportError = null,
    /// A reset cannot touch the `Mtr` while a round runs, so the prober does
    /// it between rounds. Meanwhile the table is already empty and stays so.
    reset_pending: bool = false,
    finished: bool = false,
    paused: std.atomic.Value(bool) = .init(false),
    count: ?u64,

    fn onAnswer(ctx: *anyopaque, ttl: u8, probe: Probe) void {
        const s: *Shared = @ptrCast(@alignCast(ctx));
        s.mutex.lockUncancelable(s.io);
        if (!s.reset_pending) s.live[ttl - 1] = probe;
        s.mutex.unlock(s.io);
        wake();
    }

    fn requestReset(s: *Shared) void {
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        s.reset_pending = true;
        s.hop_count = 0;
        s.rounds = 0;
        s.failure = null;
        @memset(s.live, null);
    }

    fn nowMs(s: *Shared) i64 {
        return Io.Clock.awake.now(s.io).toMilliseconds();
    }

    /// `round` would wait out the interval itself, and nothing can reach it
    /// there. Waiting here instead, a pause or a reset takes effect during a
    /// long interval, not after it; a round only blocks for its probes.
    fn run(s: *Shared, m: *traceroute.LiveMtr) void {
        var due = s.nowMs();
        while (true) {
            s.mutex.lockUncancelable(s.io);
            if (s.reset_pending) {
                m.mtr.reset();
                s.reset_pending = false;
            }
            s.mutex.unlock(s.io);
            if (s.paused.load(.acquire) or s.nowMs() < due) {
                s.io.sleep(.fromMilliseconds(50), .awake) catch {};
                continue;
            }
            due = s.nowMs() + m.mtr.opts.interval_ms;
            const outcome = m.round();
            s.mutex.lockUncancelable(s.io);
            if (s.reset_pending) {
                m.mtr.reset();
                s.reset_pending = false;
            } else {
                if (outcome) |_| {
                    s.failure = null;
                    s.rounds += 1;
                    const hops = m.mtr.hops();
                    @memcpy(s.hops[0..hops.len], hops);
                    s.hop_count = hops.len;
                } else |err| s.failure = err;
                @memset(s.live, null);
            }
            const done = if (s.count) |c| s.rounds >= c else false;
            s.finished = done;
            s.mutex.unlock(s.io);
            wake();
            if (done) return;
        }
    }
};

// ── the screen ──────────────────────────────────────────────────────────────

const Screen = struct {
    shared: *Shared,
    names: *Names,
    show_names: bool,
    target: []const u8,
    address: netaddr.Ip,
    method: []const u8,
    // The main thread's copy, so that drawing holds no lock.
    hops: []MtrHop,
    live: []?Probe,
    rows: []view.Row,
    rounds: u64 = 0,
    hop_count: usize = 0,
    failure: ?traceroute.TransportError = null,
    finished: bool = false,

    fn copy(sc: *Screen) void {
        const s = sc.shared;
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        @memcpy(sc.hops[0..s.hop_count], s.hops[0..s.hop_count]);
        @memcpy(sc.live, s.live);
        sc.hop_count = s.hop_count;
        sc.rounds = s.rounds;
        sc.failure = s.failure;
        sc.finished = s.finished;
    }

    /// The rows for the copy: `live` is left out for a final report, where
    /// only what the rounds counted belongs.
    fn buildRows(sc: *Screen, with_live: bool) []const view.Row {
        const n = if (with_live) view.rowCount(sc.hop_count, sc.live) else sc.hop_count;
        for (sc.rows[0..n], 0..) |*r, i| {
            const hop: MtrHop = if (i < sc.hop_count) sc.hops[i] else .{ .ttl = @intCast(i + 1) };
            r.* = .{ .hop = hop, .live = if (with_live) sc.live[i] else null };
            const address = if (r.live) |p| p.address orelse hop.address else hop.address;
            if (sc.show_names) {
                if (address) |a| r.name = sc.names.get(a);
            }
        }
        return sc.rows[0..n];
    }

    fn draw(sc: *Screen, w: *Io.Writer, size: WindowSize) Io.Writer.Error!void {
        sc.copy();
        try view.writeFrame(w, .{
            .target = sc.target,
            .address = sc.address,
            .method = sc.method,
            .rounds = sc.rounds,
            .paused = sc.shared.paused.load(.acquire),
            .show_names = sc.show_names,
            .failure = if (sc.failure) |f| failureText(f) else null,
            .rows = sc.buildRows(true),
            .width = size.width,
            .height = size.height,
        });
        try w.flush();
    }

    /// Runs until `q`, a signal, the last round of `-c`, or a terminal that
    /// is gone. Blocks only in `poll`.
    fn loop(sc: *Screen, w: *Io.Writer) void {
        var fds = [_]linux.pollfd{
            .{ .fd = 0, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = wake_fd, .events = linux.POLL.IN, .revents = 0 },
        };
        var size = windowSize();
        sc.draw(w, size) catch return;
        // After a resize what the old width left behind is not overwritten
        // otherwise. Written only with a frame: a clear still in the buffer
        // when the screen is left would hit the user's own screen.
        var clear = false;
        while (true) {
            const rc = linux.poll(&fds, fds.len, -1);
            if (linux.errno(rc) != .SUCCESS and linux.errno(rc) != .INTR) return;
            if (fds[1].revents != 0) {
                var counter: u64 = 0;
                _ = linux.read(wake_fd, std.mem.asBytes(&counter), @sizeOf(u64));
            }
            if (signal_quit.load(.acquire)) return;
            if (signal_resize.swap(false, .acq_rel)) {
                size = windowSize();
                clear = true;
            }
            if (fds[0].revents & linux.POLL.IN != 0) {
                var keys: [64]u8 = undefined;
                const got = linux.read(0, &keys, keys.len);
                if (linux.errno(got) == .SUCCESS and got > 0) {
                    var it: view.KeyIter = .{ .bytes = keys[0..got] };
                    while (it.next()) |k| switch (k) {
                        .quit => return,
                        .reset => sc.shared.requestReset(),
                        .names => sc.show_names = !sc.show_names,
                        .pause => sc.shared.paused.store(!sc.shared.paused.load(.acquire), .release),
                    };
                } else if (linux.errno(got) != .INTR and linux.errno(got) != .AGAIN) {
                    fds[0].fd = -1; // End of input: not to wake for it again.
                }
            } else if (fds[0].revents != 0) {
                fds[0].fd = -1;
            }
            if (clear) w.writeAll("\x1b[2J") catch return;
            clear = false;
            sc.draw(w, size) catch return;
            if (sc.finished) return;
        }
    }
};

fn failureText(err: traceroute.TransportError) []const u8 {
    return switch (err) {
        error.SendFailed => "cannot send probes (no route, or the network is down)",
        error.RecvFailed => "cannot read answers",
    };
}

// ── the report ──────────────────────────────────────────────────────────────

fn writeReport(w: *Io.Writer, target: []const u8, address: netaddr.Ip, method: []const u8, rounds: u64, rows: []const view.Row, show_names: bool) Io.Writer.Error!void {
    var longest: usize = 0;
    for (rows) |r| {
        var b: [512]u8 = undefined;
        longest = @max(longest, view.hostText(&b, r, show_names).len);
    }
    const l = view.Layout.forHosts(longest);
    try w.print("tiny-mtr to {s} ({f}), {s}, {d} rounds\n", .{ target, address, method, rounds });
    try view.writeHeader(w, l);
    try w.writeByte('\n');
    for (rows) |r| {
        try view.writeRow(w, l, r, show_names);
        try w.writeByte('\n');
    }
    try w.flush();
}

/// A report's rows and its names: every address asked at the end, and a
/// little time for the answers, since a name is not worth holding up a script.
fn collectReportRows(gpa: std.mem.Allocator, io: Io, hops: []const MtrHop, names: ?*Names) ![]view.Row {
    const rows = try gpa.alloc(view.Row, hops.len);
    const n = names orelse {
        for (rows, hops) |*r, h| r.* = .{ .hop = h };
        return rows;
    };
    for (hops) |h| {
        if (h.address) |a| _ = n.get(a);
    }
    var waited: u32 = 0;
    while (!n.idle() and waited < 150) : (waited += 1) {
        io.sleep(.fromMilliseconds(20), .awake) catch {};
    }
    for (rows, hops) |*r, h| r.* = .{ .hop = h, .name = if (h.address) |a| n.get(a) else null };
    return rows;
}

// ── main ────────────────────────────────────────────────────────────────────

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("tiny-mtr: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

fn resolveTarget(io: Io, gpa: std.mem.Allocator, c: cli.Config) netaddr.Ip {
    if (netaddr.parseIp(c.target)) |ip| {
        const family_ok = switch (c.family) {
            .any => true,
            .v4 => ip == .v4,
            .v6 => ip == .v6,
        };
        if (!family_ok) fail("{s} is not an address of the family asked for", .{c.target});
        return ip;
    }
    var r = dns.Resolver.init(io, gpa, .{
        .call_timeout_ms = 5000,
        .family = switch (c.family) {
            .any => .any,
            .v4 => .v4,
            .v6 => .v6,
        },
    });
    defer r.deinit();
    const ips = r.lookupIp(c.target) catch |err| fail("cannot resolve the host: {t}", .{err});
    defer gpa.free(ips);
    if (ips.len == 0) fail("the host has no address", .{});
    return ips[0];
}

fn openMtr(gpa: std.mem.Allocator, ip: netaddr.Ip, opts: traceroute.MtrOptions) traceroute.LiveMtr {
    return traceroute.LiveMtr.open(gpa, ip, opts) catch |err| switch (err) {
        error.PermissionDenied => fail(
            \\no socket for probes: this needs CAP_NET_RAW, or for ICMP a group inside
            \\net.ipv4.ping_group_range (sysctl), or sudo setcap cap_net_raw+ep on this binary
        , .{}),
        else => fail("cannot open a socket for probes: {t}", .{err}),
    };
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    const c = switch (cli.parse(args[1..])) {
        .run => |config| config,
        .help => {
            var buf: [1024]u8 = undefined;
            var out = Io.File.stdout().writer(io, &buf);
            try out.interface.writeAll(cli.usage);
            try out.interface.flush();
            return;
        },
        .bad => |why| {
            std.debug.print("tiny-mtr: {s}\n\n{s}", .{ why, cli.usage });
            std.process.exit(2);
        },
    };

    const wake_rc = linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
    if (linux.errno(wake_rc) != .SUCCESS) fail("cannot create an eventfd", .{});
    wake_fd = @intCast(wake_rc);

    // A reader that went away (`| head`) is a failed write, not a death.
    const ignore: linux.Sigaction = .{ .handler = .{ .handler = linux.SIG.IGN }, .mask = linux.sigemptyset(), .flags = 0 };
    _ = linux.sigaction(.PIPE, &ignore, null);

    const address = resolveTarget(io, gpa, c);
    var target_buf: [255]u8 = undefined;
    const target = view.sanitize(&target_buf, c.target);
    const method = switch (c.mtr.method) {
        .icmp => "icmp",
        .udp => "udp",
        .tcp => "tcp",
    };

    var live_mtr = openMtr(gpa, address, c.mtr);

    var names: Names = .{ .io = io, .gpa = gpa };
    const namer = try std.Thread.spawn(.{}, Names.run, .{&names});
    namer.detach();

    var out_buf: [32768]u8 = undefined;
    var out = Io.File.stdout().writer(io, &out_buf);
    const w = &out.interface;

    const stdin_tty = Io.File.stdin().isTty(io) catch false;
    const stdout_tty = Io.File.stdout().isTty(io) catch false;
    const report = c.report or !stdin_tty or !stdout_tty;

    const cap: usize = @as(usize, c.mtr.max_hops);
    if (report) {
        const count = c.count orelse 10;
        var failure: ?traceroute.TransportError = null;
        var rounds: u64 = 0;
        var i: u64 = 0;
        while (i < count) : (i += 1) {
            live_mtr.round() catch |err| {
                failure = err;
                continue;
            };
            rounds += 1;
        }
        if (rounds == 0) fail("{s}", .{failureText(failure orelse error.SendFailed)});
        const rows = try collectReportRows(gpa, io, live_mtr.mtr.hops(), if (c.names) &names else null);
        writeReport(w, target, address, method, rounds, rows, c.names) catch std.process.exit(1);
        std.process.exit(0);
    }

    var shared: Shared = .{
        .io = io,
        .hops = try gpa.alloc(MtrHop, cap),
        .live = try gpa.alloc(?Probe, cap),
        .count = c.count,
    };
    @memset(shared.live, null);
    live_mtr.mtr.on_answer = .{ .ctx = &shared, .func = Shared.onAnswer };

    var screen: Screen = .{
        .shared = &shared,
        .names = &names,
        .show_names = c.names,
        .target = target,
        .address = address,
        .method = method,
        .hops = try gpa.alloc(MtrHop, cap),
        .live = try gpa.alloc(?Probe, cap),
        .rows = try gpa.alloc(view.Row, cap),
    };

    handle(.INT, onQuitSignal);
    handle(.TERM, onQuitSignal);
    handle(.HUP, onQuitSignal);
    handle(.WINCH, onResize);
    // Before the terminal is taken: failing here must not leave it raw.
    const prober = try std.Thread.spawn(.{}, Shared.run, .{ &shared, &live_mtr });
    prober.detach();
    takeTerminal() catch |err| fail("cannot set up the terminal: {t}", .{err});

    screen.loop(w);
    restoreTerminal();
    _ = w.consumeAll(); // A frame a failed write left: not for the normal screen.

    // The table stays on the normal screen once the window is gone. The
    // prober may be inside a round, and nothing here waits for it to end:
    // the process exits, and that closes its sockets.
    screen.copy();
    const rows = screen.buildRows(false);
    writeReport(w, target, address, method, screen.rounds, rows, screen.show_names) catch {};
    std.process.exit(0);
}

test {
    _ = cli;
    _ = view;
}
