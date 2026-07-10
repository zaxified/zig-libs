// SPDX-License-Identifier: MIT

//! probe — a service-reachability prober: TCP-connect probes (up / down +
//! connect latency), fanned out over many targets with bounded concurrency
//! and per-target latency aggregation. It complements the sibling `icmp`
//! (host liveness) and `traceroute` (path) modules with the third
//! network-tail question: *is this service accepting connections, and how
//! fast?*
//!
//! The technique is `nmap -sT` / `fping`-style: attempt a TCP connection to
//! a `host:port`; a completed handshake means the service is `up` (with the
//! measured connect RTT), an actively refused connection is `refused` (a
//! definitive, fast negative — the host is there, the port is closed), no
//! answer within the timeout is `timeout`, and a DNS/other failure is
//! `error`. Repeat N times per target to get min/avg/max/loss (via the
//! sibling `latency-stats`), and fan out across a target list with a worker
//! limit.
//!
//! Layers:
//!
//!  * `probeTcp` — one connect attempt → `Result { kind, rtt_ns }`.
//!  * `probeTarget` — N repetitions of a target aggregated into a
//!    `TargetResult { target, samples, stats }`.
//!  * `probeMany` — a target list run with **bounded concurrency**: at most
//!    `Options.max_concurrent` connects are ever in flight at once. Results
//!    are returned in input order.
//!
//! The actual connect goes through an injectable `Connector` seam
//! (`connect(target, timeout_ns) -> ConnectOutcome`), so the fan-out,
//! repetition, aggregation and classification are fully offline-testable
//! against a scripted fake connector with deterministic outcomes and RTTs —
//! the tests never open a socket. The default `LiveConnector` uses
//! `std.Io.net` TCP connect (connect, measure, immediate close).
//!
//! Nothing here panics on bad input: a malformed `host:port` is a typed
//! `Target.ParseError`; a DNS/connect failure is an `error` `Result`; the
//! target count and repetition count are bounded.
//!
//! Basic usage (live):
//!
//! ```zig
//! const probe = @import("probe");
//! var lc: probe.LiveConnector = .{ .io = io };
//! const results = try probe.probeMany(gpa, &.{
//!     try probe.Target.parse("example.com:443"),
//!     try probe.Target.parse("[::1]:22"),
//! }, .{ .connector = lc.connector(), .count = 3, .max_concurrent = 8 });
//! defer probe.freeResults(gpa, results);
//! for (results) |r| { const s = r.stats; _ = s; } // min/avg/max/loss
//! ```
//!
//! Provenance: clean-room — a TCP-connect reachability probe is a standard,
//! decades-old technique (nmap's `-sT` connect scan; fping's parallel
//! host sweep). Models behavior only; no nmap, fping or other third-party
//! source consulted or copied. See ../../NOTICE.

const std = @import("std");
const netaddr = @import("netaddr");
const latency = @import("latency-stats");

const net = std.Io.net;
const Allocator = std.mem.Allocator;

pub const meta = .{
    .platform = .any, // pure engine; the default connector uses std.Io.net (cross-OS)
    .role = .client,
    .concurrency = .single_owner, // one prober run owns its results; fan-out threads touch disjoint slots
    .model_after = "TCP-connect reachability probe / nmap -sT, fping-style fan-out",
    .deps = .{ "netaddr", "latency-stats" },
};

// ── result model ────────────────────────────────────────────────────────────

/// Outcome class of a single connect attempt.
///
///  * `up`      — the TCP handshake completed; the service accepts connections.
///  * `refused` — the peer actively refused (RST / ECONNREFUSED): a definitive
///                negative (host reachable, port closed) — a fast, useful signal.
///  * `timeout` — no answer within the timeout (filtered / dropped / slow).
///  * `error`   — DNS failure, unreachable network, or any other error.
pub const Status = enum { up, refused, timeout, @"error" };

/// One probe attempt's result. `rtt_ns` is the connect round-trip and is
/// non-null only for `.up`.
pub const Result = struct {
    kind: Status,
    rtt_ns: ?u64 = null,
};

/// What a `Connector` reports for one connect attempt. Same shape as `Result`;
/// the prober copies the status through and keeps `rtt_ns` only for `.up`.
pub const ConnectOutcome = struct {
    status: Status,
    rtt_ns: ?u64 = null,
};

/// A `host:port` target. `host` is borrowed (a name or an IP/`[v6]` literal);
/// the caller owns its storage for the lifetime of any probe using it.
pub const Target = struct {
    host: []const u8,
    port: u16,

    pub const ParseError = error{InvalidHostPort};

    /// Parse `host:port` / `[v6]:port` (Go `net.SplitHostPort` semantics via
    /// `netaddr.parseHostPort`; the port is required). `host` is a slice into
    /// `text` — brackets stripped, not otherwise validated.
    pub fn parse(text: []const u8) ParseError!Target {
        const hp = netaddr.parseHostPort(text) orelse return error.InvalidHostPort;
        return .{ .host = hp.host, .port = hp.port };
    }
};

/// A target's aggregated result over `samples.len` repetitions. `samples` is
/// owned (freed by `deinit`, or by `freeResults` for a `probeMany` batch).
/// `stats` are the `latency-stats` min/avg/max/stddev/jitter over the `.up`
/// samples, with every non-`up` repetition counted as a loss.
pub const TargetResult = struct {
    target: Target,
    samples: []Result,
    stats: latency.Stats,

    /// True if at least one repetition connected.
    pub fn reachable(self: TargetResult) bool {
        return self.stats.received > 0;
    }

    /// Packet-loss percentage over the repetitions (non-`up` = loss).
    pub fn lossPct(self: TargetResult) f64 {
        return self.stats.lossPct();
    }

    pub fn deinit(self: TargetResult, gpa: Allocator) void {
        gpa.free(self.samples);
    }
};

// ── injectable transport seam ───────────────────────────────────────────────

/// The connect seam. `connectFn` performs one TCP connect to `target` with a
/// budget of `timeout_ns` and reports the classified outcome (plus the RTT on
/// success). Injecting a fake here makes the whole engine offline-testable.
pub const Connector = struct {
    ctx: *anyopaque,
    connectFn: *const fn (ctx: *anyopaque, target: Target, timeout_ns: u64) ConnectOutcome,

    pub fn connect(c: Connector, target: Target, timeout_ns: u64) ConnectOutcome {
        return c.connectFn(c.ctx, target, timeout_ns);
    }
};

/// Optional caller-provided post-connect application check. Called only after
/// an `.up` connect; returning `false` downgrades that repetition to `.error`
/// (the socket opened but the service failed an app-level check). Keep it
/// cheap — it runs on the fan-out worker threads.
pub const AppCheck = struct {
    ctx: *anyopaque,
    checkFn: *const fn (ctx: *anyopaque, target: Target) bool,

    fn check(self: AppCheck, target: Target) bool {
        return self.checkFn(self.ctx, target);
    }
};

/// Probe knobs. `connector` is required (use `LiveConnector.connector()` for
/// the real path, or a fake in tests).
pub const Options = struct {
    /// The connect transport. Required.
    connector: Connector,
    /// Per-attempt connect timeout budget, milliseconds. Passed to the
    /// connector as nanoseconds.
    timeout_ms: u32 = 1000,
    /// Repetitions per target (clamped to `[1, max_repetitions]`).
    count: u16 = 1,
    /// Upper bound on connects in flight at once during `probeMany`.
    max_concurrent: u32 = 16,
    /// Reject a `probeMany` list longer than this.
    max_targets: usize = 65_536,
    /// Optional post-connect application check.
    app_check: ?AppCheck = null,
};

/// Hard cap on repetitions per target, independent of `Options.count`.
pub const max_repetitions: u16 = 4096;

pub const ManyError = error{ TooManyTargets, OutOfMemory };

fn effectiveCount(opts: Options) u16 {
    return @max(1, @min(opts.count, max_repetitions));
}

// ── single-attempt + single-target ──────────────────────────────────────────

/// One connect attempt to `target`. Never allocates, never panics.
pub fn probeTcp(target: Target, opts: Options) Result {
    const timeout_ns: u64 = @as(u64, opts.timeout_ms) * std.time.ns_per_ms;
    const out = opts.connector.connect(target, timeout_ns);
    if (out.status == .up) {
        if (opts.app_check) |ac| {
            if (!ac.check(target)) return .{ .kind = .@"error", .rtt_ns = null };
        }
        return .{ .kind = .up, .rtt_ns = out.rtt_ns };
    }
    return .{ .kind = out.status, .rtt_ns = null };
}

/// Run `effectiveCount(opts)` repetitions of one target and aggregate. The
/// returned `TargetResult` owns `samples`; free it with `deinit`.
pub fn probeTarget(gpa: Allocator, target: Target, opts: Options) Allocator.Error!TargetResult {
    const count = effectiveCount(opts);
    var r: TargetResult = .{
        .target = target,
        .samples = try gpa.alloc(Result, count),
        .stats = undefined,
    };
    probeInto(&r, opts);
    return r;
}

/// Fill `r.samples` and compute `r.stats`. Pure w.r.t. allocation (samples
/// already allocated) — safe to call from a worker thread.
fn probeInto(r: *TargetResult, opts: Options) void {
    for (r.samples) |*s| s.* = probeTcp(r.target, opts);
    var acc = latency.Accumulator.init();
    for (r.samples) |s| {
        if (s.kind == .up) acc.addSample(s.rtt_ns orelse 0) else acc.addLoss();
    }
    r.stats = acc.snapshot();
}

// ── fan-out with bounded concurrency ────────────────────────────────────────

/// Probe every target with at most `opts.max_concurrent` connects in flight.
/// Results are returned in the same order as `targets`. Free the whole batch
/// with `freeResults`.
///
/// Concurrency model: work is dealt out by an atomic next-target counter; the
/// calling thread plus up to `max_concurrent - 1` spawned worker threads each
/// grab targets and run all their repetitions. Each worker touches only its
/// own `TargetResult` slot, so no locking is needed and the number of
/// simultaneous in-flight connects never exceeds `max_concurrent`. If thread
/// spawning is unavailable it degrades to running inline on one thread.
pub fn probeMany(gpa: Allocator, targets: []const Target, opts: Options) ManyError![]TargetResult {
    if (targets.len > opts.max_targets) return error.TooManyTargets;
    const count = effectiveCount(opts);

    const results = try gpa.alloc(TargetResult, targets.len);
    errdefer gpa.free(results);

    var made: usize = 0;
    errdefer for (results[0..made]) |r| gpa.free(r.samples);
    for (results, targets) |*r, t| {
        r.* = .{ .target = t, .samples = try gpa.alloc(Result, count), .stats = undefined };
        made += 1;
    }

    runFanout(gpa, results, opts);
    return results;
}

/// Free a `probeMany` result batch.
pub fn freeResults(gpa: Allocator, results: []TargetResult) void {
    for (results) |r| gpa.free(r.samples);
    gpa.free(results);
}

const FanCtx = struct {
    results: []TargetResult,
    opts: Options,
    next: *std.atomic.Value(usize),
};

fn runInline(ctx: *FanCtx) void {
    const n = ctx.results.len;
    while (true) {
        const i = ctx.next.fetchAdd(1, .monotonic);
        if (i >= n) break;
        probeInto(&ctx.results[i], ctx.opts);
    }
}

fn workerMain(ctx: *FanCtx) void {
    runInline(ctx);
}

fn runFanout(gpa: Allocator, results: []TargetResult, opts: Options) void {
    const n = results.len;
    if (n == 0) return;

    var next = std.atomic.Value(usize).init(0);
    var ctx: FanCtx = .{ .results = results, .opts = opts, .next = &next };

    // At most `max_concurrent` connects in flight = the calling thread plus
    // `max_concurrent - 1` helpers, never more workers than targets.
    const total: usize = @max(1, @min(@as(usize, opts.max_concurrent), n));
    const helpers = total - 1;
    if (helpers == 0) {
        runInline(&ctx);
        return;
    }

    const threads = gpa.alloc(std.Thread, helpers) catch {
        runInline(&ctx); // OOM for the handle array → just run on this thread
        return;
    };
    defer gpa.free(threads);

    var spawned: usize = 0;
    for (threads) |*t| {
        t.* = std.Thread.spawn(.{}, workerMain, .{&ctx}) catch break;
        spawned += 1;
    }
    // The calling thread is one of the `total` workers.
    runInline(&ctx);
    for (threads[0..spawned]) |t| t.join();
}

// ── default live connector (std.Io.net) ─────────────────────────────────────

/// The real connect path over `std.Io.net`. Hold one and hand `connector()`
/// to `Options`; it must outlive any probe using it.
///
/// NOTE: `std.Io.Threaded` in Zig 0.16 panics ("TODO implement
/// netConnectIpPosix with timeout") if a connect timeout is passed, so the
/// per-attempt `timeout_ns` is currently advisory — the OS default connect
/// timeout applies. Re-enable native timeouts here once std implements them.
/// Monotonic clock in nanoseconds (std.time.Instant was removed in 0.16;
/// mirror the repo's proven CLOCK_MONOTONIC pattern). Linux, like the socket.
fn monoNs() u64 {
    const linux = std.os.linux;
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub const LiveConnector = struct {
    io: std.Io,

    pub fn connector(self: *LiveConnector) Connector {
        return .{ .ctx = self, .connectFn = connectImpl };
    }

    fn connectImpl(ctx: *anyopaque, target: Target, timeout_ns: u64) ConnectOutcome {
        _ = timeout_ns; // see NOTE above
        const self: *LiveConnector = @ptrCast(@alignCast(ctx));
        const io = self.io;
        const copts: net.IpAddress.ConnectOptions = .{ .mode = .stream };

        const start = monoNs();
        var stream: net.Stream = blk: {
            if (netaddr.parseIp(target.host) != null) {
                var addr = net.IpAddress.parse(target.host, target.port) catch
                    return .{ .status = .@"error" };
                break :blk addr.connect(io, copts) catch |e| return classifyErr(e);
            }
            const host_name = net.HostName.init(target.host) catch
                return .{ .status = .@"error" };
            break :blk host_name.connect(io, target.port, copts) catch |e| return classifyErr(e);
        };
        const rtt: u64 = monoNs() -| start;
        stream.close(io);
        return .{ .status = .up, .rtt_ns = rtt };
    }

    fn classifyErr(e: anyerror) ConnectOutcome {
        return switch (e) {
            error.ConnectionRefused => .{ .status = .refused },
            error.Timeout => .{ .status = .timeout },
            else => .{ .status = .@"error" },
        };
    }
};

// ── tests: scripted fake connector (fully offline) ──────────────────────────

const testing = std.testing;

/// A deterministic connector for tests. Each host maps to a cyclic script of
/// outcomes (RTTs come straight from the script — a virtual clock). It also
/// tracks the concurrent in-flight count so tests can assert the fan-out never
/// exceeds `max_concurrent`.
const FakeConnector = struct {
    const Script = struct {
        host: []const u8,
        outcomes: []const ConnectOutcome,
        idx: usize = 0,
    };

    scripts: []Script,
    in_flight: std.atomic.Value(u32) = .init(0),
    max_in_flight: std.atomic.Value(u32) = .init(0),
    total_calls: std.atomic.Value(u32) = .init(0),
    /// Busy-spin count inside connect to widen the overlap window so the
    /// concurrency assertion is meaningful with real threads.
    spins: usize = 20_000,

    fn connector(self: *FakeConnector) Connector {
        return .{ .ctx = self, .connectFn = connectImpl };
    }

    fn connectImpl(ctx: *anyopaque, target: Target, timeout_ns: u64) ConnectOutcome {
        _ = timeout_ns;
        const self: *FakeConnector = @ptrCast(@alignCast(ctx));

        const cur = self.in_flight.fetchAdd(1, .acq_rel) + 1;
        _ = self.max_in_flight.fetchMax(cur, .acq_rel);
        _ = self.total_calls.fetchAdd(1, .monotonic);

        var i: usize = 0;
        while (i < self.spins) : (i += 1) std.atomic.spinLoopHint();

        const out: ConnectOutcome = for (self.scripts) |*s| {
            if (std.mem.eql(u8, s.host, target.host)) {
                const o = s.outcomes[s.idx % s.outcomes.len];
                s.idx += 1;
                break o;
            }
        } else .{ .status = .@"error" };

        _ = self.in_flight.fetchSub(1, .acq_rel);
        return out;
    }
};

test "Target.parse KATs" {
    {
        const t = try Target.parse("example.com:443");
        try testing.expectEqualStrings("example.com", t.host);
        try testing.expectEqual(@as(u16, 443), t.port);
    }
    {
        const t = try Target.parse("[::1]:443");
        try testing.expectEqualStrings("::1", t.host);
        try testing.expectEqual(@as(u16, 443), t.port);
    }
    {
        const t = try Target.parse("192.0.2.7:22");
        try testing.expectEqualStrings("192.0.2.7", t.host);
        try testing.expectEqual(@as(u16, 22), t.port);
    }
    // bad inputs → typed error, never a panic
    try testing.expectError(error.InvalidHostPort, Target.parse(""));
    try testing.expectError(error.InvalidHostPort, Target.parse("host-no-port"));
    try testing.expectError(error.InvalidHostPort, Target.parse("host:"));
    try testing.expectError(error.InvalidHostPort, Target.parse("host:99999")); // > u16
    try testing.expectError(error.InvalidHostPort, Target.parse("::1:443")); // ambiguous unbracketed v6
    try testing.expectError(error.InvalidHostPort, Target.parse("host:80:extra"));
}

test "probeTcp classifies each outcome" {
    var scripts = [_]FakeConnector.Script{
        .{ .host = "up", .outcomes = &.{.{ .status = .up, .rtt_ns = 1234 }} },
        .{ .host = "refused", .outcomes = &.{.{ .status = .refused }} },
        .{ .host = "timeout", .outcomes = &.{.{ .status = .timeout }} },
        .{ .host = "err", .outcomes = &.{.{ .status = .@"error" }} },
    };
    var fake: FakeConnector = .{ .scripts = &scripts, .spins = 0 };
    const opts: Options = .{ .connector = fake.connector() };

    const up = probeTcp(.{ .host = "up", .port = 80 }, opts);
    try testing.expectEqual(Status.up, up.kind);
    try testing.expectEqual(@as(?u64, 1234), up.rtt_ns);

    const ref = probeTcp(.{ .host = "refused", .port = 80 }, opts);
    try testing.expectEqual(Status.refused, ref.kind);
    try testing.expectEqual(@as(?u64, null), ref.rtt_ns);

    try testing.expectEqual(Status.timeout, probeTcp(.{ .host = "timeout", .port = 80 }, opts).kind);
    try testing.expectEqual(Status.@"error", probeTcp(.{ .host = "err", .port = 80 }, opts).kind);
    // unknown host → error (script fallthrough)
    try testing.expectEqual(Status.@"error", probeTcp(.{ .host = "nope", .port = 80 }, opts).kind);
}

test "N repetitions aggregate to min/avg/max and loss%" {
    // 4 reps: up(10ms), timeout, up(20ms), up(30ms) → 3 up, 1 loss = 25%
    const ms = std.time.ns_per_ms;
    var scripts = [_]FakeConnector.Script{
        .{ .host = "svc", .outcomes = &.{
            .{ .status = .up, .rtt_ns = 10 * ms },
            .{ .status = .timeout },
            .{ .status = .up, .rtt_ns = 20 * ms },
            .{ .status = .up, .rtt_ns = 30 * ms },
        } },
    };
    var fake: FakeConnector = .{ .scripts = &scripts, .spins = 0 };

    const r = try probeTarget(testing.allocator, .{ .host = "svc", .port = 443 }, .{
        .connector = fake.connector(),
        .count = 4,
    });
    defer r.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 4), r.stats.sent);
    try testing.expectEqual(@as(u64, 3), r.stats.received);
    try testing.expectEqual(@as(u64, 10 * ms), r.stats.min_ns);
    try testing.expectEqual(@as(u64, 30 * ms), r.stats.max_ns);
    try testing.expectEqual(@as(f64, @floatFromInt(20 * ms)), r.stats.mean_ns);
    try testing.expectEqual(@as(f64, 25.0), r.lossPct());
    try testing.expect(r.reachable());
}

test "app_check downgrades an up connect to error" {
    const Checker = struct {
        fn reject(_: *anyopaque, _: Target) bool {
            return false;
        }
    };
    var reject_ctx: u8 = 0;
    var scripts = [_]FakeConnector.Script{
        .{ .host = "up", .outcomes = &.{.{ .status = .up, .rtt_ns = 5 }} },
    };
    var fake: FakeConnector = .{ .scripts = &scripts, .spins = 0 };
    const opts: Options = .{
        .connector = fake.connector(),
        .app_check = .{ .ctx = &reject_ctx, .checkFn = Checker.reject },
    };
    try testing.expectEqual(Status.@"error", probeTcp(.{ .host = "up", .port = 80 }, opts).kind);
}

test "probeMany over many targets: all returned, order stable, concurrency bounded" {
    const ms = std.time.ns_per_ms;
    const n = 50;
    var targets: [n]Target = undefined;
    var scripts: [n]FakeConnector.Script = undefined;
    var host_bufs: [n][16]u8 = undefined;

    for (0..n) |i| {
        const host = std.fmt.bufPrint(&host_bufs[i], "h{d}", .{i}) catch unreachable;
        // even → up with distinct rtt, odd → timeout
        const outcome: ConnectOutcome = if (i % 2 == 0)
            .{ .status = .up, .rtt_ns = @as(u64, i + 1) * ms }
        else
            .{ .status = .timeout };
        // store each host's single outcome in a stable static-ish slot
        scripts[i] = .{ .host = host, .outcomes = outcomes_slot(i, outcome) };
        targets[i] = .{ .host = host, .port = 80 };
    }

    var fake: FakeConnector = .{ .scripts = &scripts };
    const max_conc = 5;
    const results = try probeMany(testing.allocator, &targets, .{
        .connector = fake.connector(),
        .count = 1,
        .max_concurrent = max_conc,
    });
    defer freeResults(testing.allocator, results);

    try testing.expectEqual(@as(usize, n), results.len);
    // Order stable: results[i] corresponds to targets[i].
    for (0..n) |i| {
        try testing.expectEqualStrings(targets[i].host, results[i].target.host);
        if (i % 2 == 0) {
            try testing.expectEqual(Status.up, results[i].samples[0].kind);
            try testing.expectEqual(@as(u64, @as(u64, i + 1) * ms), results[i].stats.min_ns);
        } else {
            try testing.expectEqual(Status.timeout, results[i].samples[0].kind);
            try testing.expect(!results[i].reachable());
        }
    }
    // Every target was probed exactly once.
    try testing.expectEqual(@as(u32, n), fake.total_calls.load(.acquire));
    // Concurrency bound respected.
    try testing.expect(fake.max_in_flight.load(.acquire) <= max_conc);
    try testing.expect(fake.max_in_flight.load(.acquire) >= 1);
}

// Backing storage for per-host single-outcome slices used by the fan-out test.
var outcome_store: [64]ConnectOutcome = undefined;
fn outcomes_slot(i: usize, o: ConnectOutcome) []const ConnectOutcome {
    outcome_store[i] = o;
    return outcome_store[i .. i + 1];
}

test "probeMany rejects an over-long target list" {
    var scripts = [_]FakeConnector.Script{};
    var fake: FakeConnector = .{ .scripts = &scripts, .spins = 0 };
    var one = [_]Target{.{ .host = "x", .port = 1 }};
    try testing.expectError(error.TooManyTargets, probeMany(testing.allocator, &one, .{
        .connector = fake.connector(),
        .max_targets = 0,
    }));
}

test "probeMany with a single target and no helpers runs inline" {
    var scripts = [_]FakeConnector.Script{
        .{ .host = "solo", .outcomes = &.{.{ .status = .up, .rtt_ns = 7 }} },
    };
    var fake: FakeConnector = .{ .scripts = &scripts, .spins = 0 };
    const results = try probeMany(testing.allocator, &.{.{ .host = "solo", .port = 22 }}, .{
        .connector = fake.connector(),
        .max_concurrent = 1,
    });
    defer freeResults(testing.allocator, results);
    try testing.expectEqual(@as(usize, 1), results.len);
    try testing.expectEqual(Status.up, results[0].samples[0].kind);
    try testing.expectEqual(@as(u32, 1), fake.max_in_flight.load(.acquire));
}

// ── live test (hermetic, self-bound listener) — skipped on any error ────────

test "live: probe a self-bound TCP listener → up" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var addr = net.IpAddress.parse("127.0.0.1", 0) catch return error.SkipZigTest;
    var server = addr.listen(io, .{ .reuse_address = true }) catch return error.SkipZigTest;
    defer server.socket.close(io);
    const bound = server.socket.address;
    const port = bound.ip4.port;

    var host_buf: [24]u8 = undefined;
    const spec = std.fmt.bufPrint(&host_buf, "127.0.0.1:{d}", .{port}) catch
        return error.SkipZigTest;
    const target = Target.parse(spec) catch return error.SkipZigTest;

    var lc: LiveConnector = .{ .io = io };
    const r = probeTcp(target, .{ .connector = lc.connector(), .timeout_ms = 500 });
    // A bound-but-not-accepting listener still completes the handshake (backlog).
    try testing.expectEqual(Status.up, r.kind);
    try testing.expect(r.rtt_ns != null);
}
