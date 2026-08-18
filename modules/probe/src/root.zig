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
//! the tests never open a socket.
//!
//! Two live connectors ship, and the choice matters:
//!
//!  * **`PosixConnector` — recommended.** Non-blocking connect + `poll`
//!    bounded by the caller's budget + `getsockopt(SO_ERROR)`. `timeout_ns`
//!    is a **real** per-attempt timeout: measured against a black-holed
//!    target, a 200 ms budget returns in 200.3 ms and a 1 000 ms budget in
//!    1 000.9 ms.
//!  * **`LiveConnector`** — the portable `std.Io.net` path. Its
//!    `std.Io.Threaded` backend panics if a connect timeout is passed, so it
//!    cannot abort a connect: `timeout_ns` is applied to the RESULT only and
//!    the attempt still blocks for the OS default. Measured on the same
//!    black hole, same 200 ms budget: **134 367 ms**.
//!
//! Neither bounds name resolution — see `PosixConnector`'s DNS section, and
//! prefer `.literal_only` (plus resolving once, up front) when the wall clock
//! has to be bounded end to end.
//!
//! Nothing here panics on bad input: a malformed `host:port` is a typed
//! `Target.ParseError`; a DNS/connect failure is an `error` `Result`; the
//! target count and repetition count are bounded.
//!
//! Basic usage (live):
//!
//! ```zig
//! const probe = @import("probe");
//! var pc: probe.PosixConnector = .{ .io = io };
//! const results = try probe.probeMany(gpa, &.{
//!     try probe.Target.parse("example.com:443"),
//!     try probe.Target.parse("[::1]:22"),
//! }, .{ .connector = pc.connector(), .count = 3, .max_concurrent = 8 });
//! defer probe.freeResults(gpa, results);
//! for (results) |r| { const s = r.stats; _ = s; } // min/avg/max/loss
//! ```
//!
//! Provenance: clean-room — a TCP-connect reachability probe is a standard,
//! decades-old technique (nmap's `-sT` connect scan; fping's parallel
//! host sweep). Models behavior only; no nmap, fping or other third-party
//! source consulted or copied. See ../../NOTICE.

const std = @import("std");
const builtin = @import("builtin");
const netaddr = @import("netaddr");
const latency = @import("latency-stats");

const net = std.Io.net;
const Allocator = std.mem.Allocator;

pub const meta = .{
    // Pure engine; `LiveConnector` is cross-OS via std.Io.net. `PosixConnector`
    // is Linux, but its syscalls are only analysed if it is referenced, so a
    // non-Linux consumer of the engine still builds.
    .targets = .{ .linux64, .linux32 },
    .platform = .any,
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
/// non-null only for `.up`. `errno`/`err_name` carry whichever connector's
/// underlying-error representation produced a non-`.up` `Result` — see
/// `ConnectOutcome` for what each means and when it is set. Both are null
/// for `.up`, and for an `app_check`-downgraded `.error` (the socket
/// connected fine; nothing at the OS/transport level failed).
pub const Result = struct {
    kind: Status,
    rtt_ns: ?u64 = null,
    errno: ?i32 = null,
    err_name: ?[]const u8 = null,
};

/// What a `Connector` reports for one connect attempt. Same shape as `Result`;
/// the prober copies the status through and keeps `rtt_ns` only for `.up`.
pub const ConnectOutcome = struct {
    status: Status,
    rtt_ns: ?u64 = null,
    /// The raw `SO_ERROR`/`connect()` errno behind a non-`.up` outcome from
    /// `PosixConnector` — e.g. `111` = `ECONNREFUSED`, `110` = `ETIMEDOUT`.
    /// `classifyErrno` already folds this into `Status`; this keeps the
    /// value the classification was computed FROM, since distinct errnos can
    /// classify the same way (`EHOSTUNREACH`/`ENETUNREACH`/`EACCES` are all
    /// `.error`). Null for `.up`, and for outcomes `LiveConnector` produced —
    /// see `err_name` for that path.
    errno: ?i32 = null,
    /// The Zig error name behind a non-`.up` outcome from `LiveConnector`
    /// (`std.Io.net` reports an `anyerror`, not an errno, so there is no
    /// numeric code to carry). An `@errorName` result: a static string, never
    /// allocated or freed. Null for `.up`, and for outcomes `PosixConnector`
    /// produced — see `errno` for that path.
    err_name: ?[]const u8 = null,
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

/// Hard ceiling on the workers `probeMany` will use, independent of
/// `Options.max_concurrent` — same shape as `max_repetitions`, and for the
/// same reason: a knob a caller can set to anything should not be the only
/// thing standing between the module and its resource use.
///
/// Without it, `max_concurrent` sized the helper-thread count directly, so an
/// aggressive config (a large `max_concurrent` over a target list up to
/// `max_targets` = 65 536) asked the OS for tens of thousands of threads. It
/// never crashed — a failed `Thread.spawn` breaks the loop and the remainder
/// runs inline, and in-flight connects stayed bounded either way — but
/// "degrades gracefully once the OS says no" is a different property from
/// "never asks".
///
/// `max_concurrent` therefore remains an upper bound on connects in flight,
/// now clamped by this one: past 256 workers a probe sweep is limited by the
/// network and the peer, not by local parallelism.
pub const max_workers: u32 = 256;

/// Total workers (calling thread included) `probeMany` uses for `targets`
/// targets at `max_concurrent`. Split out as a pure function so the three
/// bounds it composes — the caller's knob, this module's ceiling, and "never
/// more workers than targets" — are testable without spawning anything.
pub fn workerCount(max_concurrent: u32, targets: usize) usize {
    const requested: usize = @min(@as(usize, max_concurrent), @as(usize, max_workers));
    return @max(1, @min(requested, targets));
}

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
            // Nothing at the OS level failed here — the handshake completed
            // and the app-level check is what rejected it — so there is no
            // underlying errno/err_name to carry.
            if (!ac.check(target)) return .{ .kind = .@"error", .rtt_ns = null };
        }
        return .{ .kind = .up, .rtt_ns = out.rtt_ns };
    }
    return .{ .kind = out.status, .rtt_ns = null, .errno = out.errno, .err_name = out.err_name };
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
    // `max_concurrent - 1` helpers, never more workers than targets, and never
    // more than `max_workers` no matter what the caller asked for.
    const total: usize = workerCount(opts.max_concurrent, n);
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

// ── portable live connector (std.Io.net) ────────────────────────────────────

/// Monotonic clock in nanoseconds (std.time.Instant was removed in 0.16;
/// mirror the repo's proven CLOCK_MONOTONIC pattern). Linux, like the socket.
fn monoNs() u64 {
    const linux = std.os.linux;
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Classify a *successful* connect against the caller's budget. Shared by
/// both live connectors, for two different reasons.
///
/// For `LiveConnector` it is the only budget there is: std cannot abort the
/// syscall (see the NOTE above), so the connect runs to the OS default no
/// matter what `timeout_ns` says, and only the RESULT can respect the budget.
/// A prober asked for "up within 1 s" learns nothing useful from a connect
/// that succeeded after 30; the code before `6f94fac` discarded `timeout_ns`
/// entirely and reported `.up`.
///
/// For `PosixConnector` the wall clock is already bounded, and this closes the
/// remaining gap: a connect that completed synchronously **after** a slow
/// name resolution is still a budget miss.
///
/// The rtt is kept on the timeout outcome — how long it actually took is the
/// interesting part of a budget miss.
fn overBudget(rtt: u64, timeout_ns: u64) ConnectOutcome {
    if (timeout_ns != 0 and rtt > timeout_ns)
        return .{ .status = .timeout, .rtt_ns = rtt };
    return .{ .status = .up, .rtt_ns = rtt };
}

/// The portable connect path, over `std.Io.net`. Hold one and hand
/// `connector()` to `Options`; it must outlive any probe using it.
///
/// **Prefer `PosixConnector` on Linux.** `std.Io.Threaded` in Zig 0.16 panics
/// ("TODO implement netConnectIpPosix with timeout") if a connect timeout is
/// passed, so this path cannot abort a connect: the OS default governs how
/// long an attempt BLOCKS, and only the RESULT respects the budget
/// (`overBudget` — a connect that succeeds after the budget is `.timeout`,
/// not `.up`). Measured against a black-holed loopback target with a 200 ms
/// budget: `error.Timeout` after **134 367 ms** (`tcp_syn_retries` = 6).
///
/// This is a limitation of one `std.Io` *backend*, not of `probe` and not of
/// `std.Io.net`'s API — and it never justified an unbounded probe. `probe`
/// owns the `Connector` seam, so `PosixConnector` simply does not go through
/// that backend. Kept here because it is the portable path (it is not tied to
/// Linux syscalls) and because the budget-on-the-result rule it introduced is
/// still needed by both connectors.
pub const LiveConnector = struct {
    io: std.Io,

    pub fn connector(self: *LiveConnector) Connector {
        return .{ .ctx = self, .connectFn = connectImpl };
    }

    fn connectImpl(ctx: *anyopaque, target: Target, timeout_ns: u64) ConnectOutcome {
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
        return overBudget(rtt, timeout_ns);
    }

    fn classifyErr(e: anyerror) ConnectOutcome {
        const status: Status = switch (e) {
            error.ConnectionRefused => .refused,
            error.Timeout => .timeout,
            else => .@"error",
        };
        // The classification above is unchanged; this only adds what
        // produced it. `@errorName` is a static, program-lifetime string —
        // nothing to allocate or free.
        return .{ .status = status, .err_name = @errorName(e) };
    }
};

// ── PosixConnector: a real per-attempt connect timeout ──────────────────────

/// How `PosixConnector` turns a `Target.host` that is **not** an IP literal
/// into an address.
pub const Resolve = enum {
    /// Never consult a resolver: a host that is not an IP literal is
    /// `.error`, immediately. This is the only mode whose **wall clock** is
    /// bounded by `timeout_ns` end to end, and it is the right one for a
    /// health checker over a fixed backend set — resolve once at
    /// configuration time, then probe literals on every tick.
    literal_only,
    /// Resolve names through `std.Io.net.HostName.lookup` (requires `io`).
    /// The lookup is bounded by the *system resolver's* timeout, not by
    /// `timeout_ns`. See the DNS section on `PosixConnector`.
    system,
};

/// The recommended live connector: a **real** per-attempt connect timeout.
///
/// Prefer this over `LiveConnector` on Linux. `LiveConnector` goes through
/// `std.Io.net`, whose `std.Io.Threaded` backend panics if a connect timeout
/// is passed ("TODO implement netConnectIpPosix with timeout"), so it cannot
/// abort a connect early: against a black-holed target one attempt blocks for
/// the OS default. Measured here, on a listener whose accept queue is full:
/// `std.Io.net` returned `error.Timeout` after **134 367 ms** for a 200 ms
/// budget; this connector returns in ~200 ms.
///
/// That is not an upstream block, and it never was: `std.Io.net` is an *API*
/// and `std.Io.Threaded` is one *implementation* behind it. `probe` owns the
/// `Connector` seam, so nothing forces the attempt through that layer.
///
/// ## How the budget is enforced
///
/// Non-blocking socket → `connect()` → `poll(POLLOUT)` bounded by the
/// caller's remaining budget → `getsockopt(SO_ERROR)` for the verdict.
///
///  * **Immediate success.** `connect()` returning 0 (loopback often
///    completes synchronously) is `.up` without polling.
///  * **Immediate failure.** `connect()` returning `ECONNREFUSED` is
///    `.refused` at once — the fast definitive negative, never `.timeout`.
///  * **`EINPROGRESS`** hands over to the poll loop. `EINTR` from `connect()`
///    does the same: POSIX says the handshake continues asynchronously and
///    the caller must poll, not re-`connect`.
///  * **`SO_ERROR` is authoritative.** A writable socket is *not* a
///    successful connect. Measured on this kernel, a refusal arrives as
///    `revents = 0x1c` (`POLLOUT|POLLERR|POLLHUP`) with `SO_ERROR = 111`;
///    a real success is `revents = 0x4` with `SO_ERROR = 0`. Reading
///    `POLLOUT` alone would call every refusal `.up`.
///  * **`POLLERR`/`POLLHUP` are distinct from `POLLOUT`.** `SO_ERROR` decides
///    first; if it is clear but `POLLOUT` is absent, the handshake did not
///    complete and the result is `.error`, not `.up`. `POLLNVAL` is
///    `.error` (unreachable — this code owns the descriptor).
///  * **`EINTR` and short polls recompute the REMAINING budget** from the
///    monotonic clock on every iteration. Restarting the full timeout after
///    each interruption would multiply the budget by the signal rate on a
///    signal-heavy host — the exact "1 s timeout that waits 10 s" this
///    connector exists to remove.
///  * **IPv4 and IPv6** both work (`Target.parse` accepts `[v6]:port`); the
///    socket family follows the address. IPv6 scope/zone ids are not carried
///    (`sin6_scope_id = 0`), so a link-local literal needing a zone is out of
///    scope.
///  * **The descriptor is closed on every path** — success, refusal,
///    timeout, socket error, resolver failure — by a single `defer` placed
///    immediately after the successful `socket()`.
///
/// ## DNS — what the budget does NOT cover
///
/// `poll` bounds the connect. It does nothing for name resolution, which is
/// the *other* place a `host:port` attempt can block.
///
/// What the current path does: `std.Io.Threaded`'s resolver on Linux is
/// pure-Zig (it deliberately bypasses libc's `getaddrinfo`). It short-circuits
/// IP literals, then `/etc/hosts`, then RFC 6761 `localhost`, and only then
/// sends DNS queries — bounded by its own deadline, `options timeout:` from
/// `/etc/resolv.conf`, **default 5 s** (`attempts` divides that span into
/// retries; it does not multiply it). So the resolver is bounded, but by a
/// budget that has nothing to do with `timeout_ns`: a 1 s probe of a name
/// whose nameserver is dark blocks ~5 s.
///
/// This connector therefore states the boundary rather than hiding it:
///
///  * `.literal_only` (bounded): no resolver call ever happens, so the wall
///    clock is `timeout_ns`. An IP literal takes this path in **either**
///    mode — `netaddr.parseIp` runs first, so a literal never reaches the
///    resolver even under `.system`.
///  * `.system` (not bounded): resolution time is **charged against the
///    budget** — it is measured, subtracted, and the connect gets only what
///    is left; a lookup that alone exceeds the budget returns `.timeout`
///    without connecting. That makes the *classification* honest. It does not
///    make the wall clock honest, and no amount of `poll` can: the wall clock
///    of a `.system` attempt is `timeout_ns` **plus** up to the resolver's own
///    timeout.
///
/// `rtt_ns` is the total elapsed time of the attempt, resolution included —
/// the same convention `LiveConnector` already uses.
///
/// ## Platform
///
/// Linux. Zig 0.16 removed the socket wrappers from `std.posix` (they moved
/// behind `std.Io.net`), so a libc-free build reaches `socket`/`connect`/
/// `poll`/`getsockopt` only through `std.os.linux` — the same raw-syscall
/// pattern the sibling `netaddr`, `icmp` and `rawsock` modules use. The
/// technique is plain POSIX; only the syscall bindings are Linux-specific.
pub const PosixConnector = struct {
    /// Required only when `resolve == .system`; ignored otherwise.
    io: ?std.Io = null,
    /// Name-resolution policy. `.system` matches `LiveConnector`'s behaviour;
    /// `.literal_only` is the fully bounded one.
    resolve: Resolve = .system,

    pub fn connector(self: *PosixConnector) Connector {
        return .{ .ctx = self, .connectFn = connectImpl };
    }

    fn connectImpl(ctx: *anyopaque, target: Target, timeout_ns: u64) ConnectOutcome {
        const self: *PosixConnector = @ptrCast(@alignCast(ctx));
        const start = monoNs();

        // An IP literal never reaches a resolver, in either mode.
        const ip: netaddr.Ip = netaddr.parseIp(target.host) orelse switch (self.resolve) {
            .literal_only => return .{ .status = .@"error" },
            .system => blk: {
                const io = self.io orelse return .{ .status = .@"error" };
                break :blk resolveFirst(io, target.host, target.port) orelse
                    return .{ .status = .@"error" };
            },
        };

        // Charge resolution against the budget: the connect gets the REMAINDER,
        // and a lookup that already blew the budget never connects at all.
        const spent = monoNs() -| start;
        const remaining: u64 = if (timeout_ns == 0)
            0 // 0 == "no budget", same convention as `overBudget`
        else if (spent >= timeout_ns)
            return .{ .status = .timeout, .rtt_ns = spent }
        else
            timeout_ns - spent;

        const v = connectBounded(ip, target.port, remaining);
        const rtt = monoNs() -| start;
        return switch (v.status) {
            // `overBudget` still guards the success path: a connect that
            // completed synchronously after a slow resolution is a budget
            // miss, not an OS-level error — no errno to carry either way.
            .up => overBudget(rtt, timeout_ns),
            .timeout => .{ .status = .timeout, .rtt_ns = rtt, .errno = v.errno },
            .refused, .@"error" => .{ .status = v.status, .errno = v.errno },
        };
    }

    /// `connectBounded`'s verdict: the classified `Status` plus the raw errno
    /// it was classified FROM, when one is known. `null` on `.up` (nothing
    /// failed) and on the handful of exits with no specific errno to name
    /// (`POLLNVAL`, "writable check came back clear but not writable").
    const Verdict = struct { status: Status, errno: ?i32 = null };

    /// One non-blocking connect bounded by `budget_ns` (0 = unbounded).
    /// Never allocates; closes its descriptor on every exit path.
    fn connectBounded(ip: netaddr.Ip, port: u16, budget_ns: u64) Verdict {
        if (comptime builtin.os.tag != .linux)
            @compileError("probe.PosixConnector is Linux-only (raw socket syscalls, no libc)");
        const linux = std.os.linux;

        const family: u32 = switch (ip) {
            .v4 => linux.AF.INET,
            .v6 => linux.AF.INET6,
        };
        const sock_rc = linux.socket(
            family,
            linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC,
            0,
        );
        if (linux.errno(sock_rc) != .SUCCESS) return .{ .status = .@"error" };
        const fd: i32 = @intCast(sock_rc);
        // The only descriptor this function owns, released on every path.
        defer _ = linux.close(fd);

        // Saturating: `Connector.connect` takes an arbitrary u64 from the
        // caller, and a plain `+` on a maxInt budget would trap in Debug.
        const deadline: ?u64 = if (budget_ns == 0) null else monoNs() +| budget_ns;

        const be_port = std.mem.nativeToBig(u16, port);
        var sa4: linux.sockaddr.in = undefined;
        var sa6: linux.sockaddr.in6 = undefined;
        const conn_rc = switch (ip) {
            .v4 => |q| blk: {
                sa4 = .{ .port = be_port, .addr = @bitCast(q) };
                break :blk linux.connect(fd, @ptrCast(&sa4), @sizeOf(linux.sockaddr.in));
            },
            .v6 => |b| blk: {
                // No zone/scope support: a link-local literal needing one is
                // outside this module's `Target` grammar anyway.
                sa6 = .{ .port = be_port, .flowinfo = 0, .addr = b, .scope_id = 0 };
                break :blk linux.connect(fd, @ptrCast(&sa6), @sizeOf(linux.sockaddr.in6));
            },
        };
        switch (linux.errno(conn_rc)) {
            // Loopback and same-host connects frequently complete right here.
            .SUCCESS => return .{ .status = .up },
            // The handshake is under way; EINTR means the same thing — POSIX
            // requires polling for completion, NOT a second connect().
            .INPROGRESS, .INTR => {},
            // Everything definitive arrives synchronously, ECONNREFUSED included.
            else => |e| return .{ .status = classifyErrno(@intFromEnum(e)), .errno = @intFromEnum(e) },
        }

        var pfd = [1]linux.pollfd{.{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 }};
        while (true) {
            // Recomputed from the clock every iteration. A signal storm must
            // not extend the budget, and a short poll must not shorten it.
            const wait_ms: i32 = blk: {
                const d = deadline orelse break :blk -1;
                const now = monoNs();
                if (now >= d) return .{ .status = .timeout };
                const left_ms = (d - now + std.time.ns_per_ms - 1) / std.time.ns_per_ms;
                break :blk @intCast(@min(left_ms, @as(u64, std.math.maxInt(i32))));
            };
            pfd[0].revents = 0;
            const poll_rc = linux.poll(&pfd, 1, wait_ms);
            switch (linux.errno(poll_rc)) {
                .SUCCESS => {},
                .INTR => continue, // budget recomputed at the top of the loop
                else => |e| return .{ .status = .@"error", .errno = @intFromEnum(e) },
            }
            if (poll_rc == 0) continue; // timed out (or short) — the top decides
            break;
        }

        const revents = pfd[0].revents;
        if (revents & linux.POLL.NVAL != 0) return .{ .status = .@"error" };

        // SO_ERROR decides, not POLLOUT: a refusal is POLLOUT|POLLERR|POLLHUP
        // with SO_ERROR = ECONNREFUSED (measured: revents 0x1c, SO_ERROR 111).
        var so_error: i32 = 0;
        var so_len: linux.socklen_t = @sizeOf(i32);
        const opt_rc = linux.getsockopt(
            fd,
            linux.SOL.SOCKET,
            linux.SO.ERROR,
            @ptrCast(&so_error),
            &so_len,
        );
        if (linux.errno(opt_rc) != .SUCCESS)
            return .{ .status = .@"error", .errno = @intFromEnum(linux.errno(opt_rc)) };
        // No pending error and not writable: POLLERR/POLLHUP on their own do
        // not mean a completed handshake.
        if (so_error == 0 and revents & linux.POLL.OUT == 0) return .{ .status = .@"error" };
        return .{ .status = classifyErrno(so_error), .errno = so_error };
    }

    /// First address `std.Io.net`'s resolver returns for `host`, or null.
    /// std has already applied its own ordering; this takes the head of it.
    fn resolveFirst(io: std.Io, host: []const u8, port: u16) ?netaddr.Ip {
        const host_name = net.HostName.init(host) catch return null;
        // `lookup` is documented not to block with capacity >= 16.
        var buf: [32]net.HostName.LookupResult = undefined;
        var queue: std.Io.Queue(net.HostName.LookupResult) = .init(&buf);
        host_name.lookup(io, &queue, .{ .port = port }) catch return null;
        while (queue.getOne(io)) |res| switch (res) {
            .address => |addr| return switch (addr) {
                .ip4 => |a| .{ .v4 = a.bytes },
                .ip6 => |a| .{ .v6 = a.bytes },
            },
            .canonical_name => continue,
        } else |_| return null;
    }
};

/// Map a raw `errno` value — including 0, the success case — to a `Status`.
///
/// Taken as an integer rather than a `linux.E` on purpose: `SO_ERROR` yields
/// whatever the kernel put there, and `@enumFromInt` on a value outside the
/// enum is illegal behaviour. `refused` must never collapse into `timeout` —
/// it is the fast definitive negative a prober most wants to distinguish.
fn classifyErrno(code: i32) Status {
    const E = std.os.linux.E;
    if (code == 0) return .up;
    if (code == @intFromEnum(E.CONNREFUSED)) return .refused;
    if (code == @intFromEnum(E.TIMEDOUT)) return .timeout;
    // EHOSTUNREACH / ENETUNREACH / ENETDOWN / EACCES and the rest are neither
    // "the port is closed" nor "no answer in time".
    return .@"error";
}

// ── tests: scripted fake connector (fully offline) ──────────────────────────

const testing = std.testing;
const testkit = @import("testkit");

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
    /// When non-zero, hold inside `connect` until this many calls are in
    /// flight at once (or the budget below runs out). Turns "the threads
    /// happened to overlap" into "every worker that exists is inside connect
    /// together", which is what makes an upper-bound assertion on
    /// `max_in_flight` able to FAIL when the bound is not enforced. Without
    /// it, spawn latency (~10 us/thread) outruns a fixed spin and the early
    /// workers finish before the late ones start — verified: a fault-injected
    /// `runFanout` that ignored the ceiling still passed.
    hold_until_in_flight: u32 = 0,
    /// Spin budget for the hold above, so a bound that IS enforced (and can
    /// therefore never reach the target) still terminates.
    hold_budget: usize = 50_000,

    fn connector(self: *FakeConnector) Connector {
        return .{ .ctx = self, .connectFn = connectImpl };
    }

    fn connectImpl(ctx: *anyopaque, target: Target, timeout_ns: u64) ConnectOutcome {
        _ = timeout_ns;
        const self: *FakeConnector = @ptrCast(@alignCast(ctx));

        const cur = self.in_flight.fetchAdd(1, .acq_rel) + 1;
        _ = self.max_in_flight.fetchMax(cur, .acq_rel);
        _ = self.total_calls.fetchAdd(1, .monotonic);

        if (self.hold_until_in_flight != 0) {
            // YIELD, do not spin: the workers are spawned one at a time by a
            // thread that needs CPU to finish the loop, and a few hundred
            // busy-spinning holders starve it — measured, the peak stalled at
            // 119 of 264 workers and the fault injection below passed.
            var waited: usize = 0;
            while (waited < self.hold_budget) : (waited += 1) {
                if (self.in_flight.load(.acquire) >= self.hold_until_in_flight) break;
                std.Thread.yield() catch std.atomic.spinLoopHint();
            }
            _ = self.max_in_flight.fetchMax(self.in_flight.load(.acquire), .acq_rel);
        }

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

test "LiveConnector.classifyErr: refused/timeout/other map to distinct Status" {
    // Only the `.up` path is reachable from the hermetic live test below (a
    // bound-but-not-accepting listener never actually refuses or times out),
    // so the connect-error classification is exercised directly here.
    try testing.expectEqual(Status.refused, LiveConnector.classifyErr(error.ConnectionRefused).status);
    try testing.expectEqual(Status.timeout, LiveConnector.classifyErr(error.Timeout).status);
    try testing.expectEqual(Status.@"error", LiveConnector.classifyErr(error.NameResolutionFailed).status);
    // None of the three collapse into each other.
    try testing.expect(LiveConnector.classifyErr(error.ConnectionRefused).status !=
        LiveConnector.classifyErr(error.Timeout).status);
}

test "LiveConnector.classifyErr carries the Zig error name, not just the Status" {
    // The classification (asserted above) is unchanged; this pins that the
    // underlying error survives alongside it instead of being discarded.
    try testing.expectEqualStrings(
        "ConnectionRefused",
        LiveConnector.classifyErr(error.ConnectionRefused).err_name.?,
    );
    try testing.expectEqualStrings("Timeout", LiveConnector.classifyErr(error.Timeout).err_name.?);
    try testing.expectEqualStrings(
        "NameResolutionFailed",
        LiveConnector.classifyErr(error.NameResolutionFailed).err_name.?,
    );
    // `PosixConnector`'s side of the same contract, not `LiveConnector`'s:
    // this outcome never went through `classifyErr`, so `err_name` must stay
    // null even though `errno` is set.
    try testing.expectEqual(@as(?[]const u8, null), (ConnectOutcome{
        .status = .refused,
        .errno = 111,
    }).err_name);
}

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

test "probeTcp carries the connector's underlying error through to Result, unclassified" {
    // Before this, ConnectOutcome's errno/err_name never reached probeTcp's
    // Result at all — the classification into Status was right, but a caller
    // that wanted to know WHY (not just THAT) a connect was refused had
    // nothing to read. This pins that the value survives the copy, and that
    // it does so without changing which Status it carries.
    const E = std.os.linux.E;
    var scripts = [_]FakeConnector.Script{
        .{ .host = "refused", .outcomes = &.{.{ .status = .refused, .errno = @intFromEnum(E.CONNREFUSED) }} },
        .{ .host = "posix-timeout", .outcomes = &.{.{ .status = .timeout, .errno = @intFromEnum(E.TIMEDOUT) }} },
        .{ .host = "live-refused", .outcomes = &.{.{ .status = .refused, .err_name = "ConnectionRefused" }} },
        .{ .host = "up", .outcomes = &.{.{ .status = .up, .rtt_ns = 5 }} },
    };
    var fake: FakeConnector = .{ .scripts = &scripts, .spins = 0 };
    const opts: Options = .{ .connector = fake.connector() };

    const ref = probeTcp(.{ .host = "refused", .port = 80 }, opts);
    try testing.expectEqual(Status.refused, ref.kind); // classification unchanged
    try testing.expectEqual(@as(?i32, @intFromEnum(E.CONNREFUSED)), ref.errno);
    try testing.expectEqual(@as(?[]const u8, null), ref.err_name);

    const to = probeTcp(.{ .host = "posix-timeout", .port = 80 }, opts);
    try testing.expectEqual(Status.timeout, to.kind);
    try testing.expectEqual(@as(?i32, @intFromEnum(E.TIMEDOUT)), to.errno);

    const live_ref = probeTcp(.{ .host = "live-refused", .port = 80 }, opts);
    try testing.expectEqual(Status.refused, live_ref.kind);
    try testing.expectEqual(@as(?i32, null), live_ref.errno);
    try testing.expectEqualStrings("ConnectionRefused", live_ref.err_name.?);

    // `.up` never carries either field, whatever the connector set — probeTcp
    // only reaches for rtt_ns on that path.
    const up = probeTcp(.{ .host = "up", .port = 80 }, opts);
    try testing.expectEqual(Status.up, up.kind);
    try testing.expectEqual(@as(?i32, null), up.errno);
    try testing.expectEqual(@as(?[]const u8, null), up.err_name);
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

test "count is clamped to [1, max_repetitions]" {
    var scripts = [_]FakeConnector.Script{
        .{ .host = "svc", .outcomes = &.{.{ .status = .up, .rtt_ns = 1 }} },
    };
    var fake: FakeConnector = .{ .scripts = &scripts, .spins = 0 };

    // count = 0 clamps up to 1, not 0 (which would allocate an empty, useless sample set).
    {
        const r = try probeTarget(testing.allocator, .{ .host = "svc", .port = 1 }, .{
            .connector = fake.connector(),
            .count = 0,
        });
        defer r.deinit(testing.allocator);
        try testing.expectEqual(@as(usize, 1), r.samples.len);
    }
    // count above the hard cap clamps down to `max_repetitions`, not the caller's value.
    {
        const r = try probeTarget(testing.allocator, .{ .host = "svc", .port = 1 }, .{
            .connector = fake.connector(),
            .count = max_repetitions + 1000,
        });
        defer r.deinit(testing.allocator);
        try testing.expectEqual(@as(usize, max_repetitions), r.samples.len);
    }
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
var outcome_store: [max_workers + 8]ConnectOutcome = undefined;
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

test "overBudget: a slow success is a timeout, not an up" {
    // `LiveConnector` cannot abort the connect syscall, so the budget is
    // enforced on the outcome. Before this, `timeout_ns` was discarded and a
    // 30s connect under a 1s budget reported `.up`. `PosixConnector` shares
    // the rule for the case its `poll` cannot bound: a slow name resolution
    // followed by an instant connect.
    const ms = std.time.ns_per_ms;
    try testing.expectEqual(Status.up, overBudget(5 * ms, 100 * ms).status);
    try testing.expectEqual(Status.up, overBudget(100 * ms, 100 * ms).status); // exactly on budget
    try testing.expectEqual(Status.timeout, overBudget(101 * ms, 100 * ms).status);

    // The measured rtt survives on both outcomes — how long a budget miss took
    // is the useful part.
    try testing.expectEqual(@as(u64, 101 * ms), overBudget(101 * ms, 100 * ms).rtt_ns);

    // A zero budget means "no budget", not "everything times out".
    try testing.expectEqual(Status.up, overBudget(30 * std.time.ns_per_s, 0).status);
}

test "worker count is bounded by the module, not only by the caller's knob" {
    // Audit finding probe-F1: helper threads were sized straight from
    // `Options.max_concurrent`, so an aggressive config over a `max_targets`
    // list asked the OS for tens of thousands of spawns. It degraded
    // gracefully (spawn failure → run inline), but nothing stopped it asking.
    //
    // Three bounds compose here, and each is pinned separately because each
    // has its own failure mode: the caller's knob (too many workers), the
    // target count (idle workers), and this module's ceiling (the finding).

    // The caller's knob decides while it is below the ceiling…
    try testing.expectEqual(@as(usize, 1), workerCount(1, 1000));
    try testing.expectEqual(@as(usize, 16), workerCount(16, 1000)); // the default
    try testing.expectEqual(@as(usize, 255), workerCount(255, 1000));
    // …and stops deciding at it. Literal values on both sides of the boundary.
    try testing.expectEqual(@as(usize, 256), workerCount(256, 1000));
    try testing.expectEqual(@as(usize, 256), workerCount(257, 1000));
    try testing.expectEqual(@as(usize, 256), workerCount(65_536, 100_000));
    try testing.expectEqual(
        @as(usize, 256),
        workerCount(std.math.maxInt(u32), std.math.maxInt(usize)),
    );
    // Never more workers than there is work…
    try testing.expectEqual(@as(usize, 3), workerCount(1000, 3));
    try testing.expectEqual(@as(usize, 1), workerCount(1000, 1));
    // …and never fewer than the calling thread, even for a degenerate config.
    try testing.expectEqual(@as(usize, 1), workerCount(0, 10));
    try testing.expectEqual(@as(usize, 1), workerCount(0, 0));

    // The ceiling itself, pinned — every assertion above is written against
    // this value, so this is what stops it drifting.
    try testing.expectEqual(@as(u32, 256), max_workers);
    // It must sit under `max_targets`, or it would never bind on a real sweep.
    try testing.expect(@as(usize, max_workers) < (Options{ .connector = undefined }).max_targets);
}

test "probeMany honors the ceiling end to end, not just in the arithmetic" {
    // The same claim through the real fanout: a caller asking for far more
    // concurrency than the module allows gets the module's number, and every
    // target is still probed exactly once.
    //
    // The target count deliberately EXCEEDS `max_workers`. At n < max_workers
    // the "never more workers than targets" bound already caps the fanout, so
    // a `runFanout` that computed its own count and skipped the ceiling would
    // pass — that exact fault injection was run and did pass, which is why the
    // list is this long.
    const n = max_workers + 8;
    var targets: [n]Target = undefined;
    var scripts: [n]FakeConnector.Script = undefined;
    var host_bufs: [n][16]u8 = undefined;
    for (0..n) |i| {
        const host = std.fmt.bufPrint(&host_bufs[i], "c{d}", .{i}) catch unreachable;
        scripts[i] = .{ .host = host, .outcomes = outcomes_slot(i, .{ .status = .up, .rtt_ns = 1 }) };
        targets[i] = .{ .host = host, .port = 80 };
    }

    // Hold every call inside `connect` until one MORE than the ceiling is in
    // flight. Correct code can never reach that (only `max_workers` workers
    // exist), so the hold falls through its budget; code that ignored the
    // ceiling has `n` workers, they all pile up, and `max_in_flight` blows
    // past the bound asserted below.
    var fake: FakeConnector = .{
        .scripts = &scripts,
        .spins = 0,
        .hold_until_in_flight = max_workers + 1,
    };
    const results = try probeMany(testing.allocator, &targets, .{
        .connector = fake.connector(),
        .count = 1,
        .max_concurrent = 100_000, // absurd on purpose
    });
    defer freeResults(testing.allocator, results);

    try testing.expectEqual(@as(usize, n), results.len);
    try testing.expectEqual(@as(u32, n), fake.total_calls.load(.acquire));
    // In flight never exceeded what the module permits, even though both the
    // caller's knob (100 000) and the target count are far above it.
    try testing.expect(fake.max_in_flight.load(.acquire) <= max_workers);
    try testing.expect(fake.max_in_flight.load(.acquire) >= 1);
}

// ── live tests for the bounded connector (hermetic: loopback only) ──────────
//
// These do open sockets, but never leave the host: every address is loopback,
// no name is ever sent to a resolver, and `probe` needs no network namespace
// (a fresh netns starts with `lo` down, which would turn all of this from pass
// into failure — the same reason `icmp` and `traceroute` are excluded from
// `NETNS_MODULES`).

const tl = std.os.linux;

fn sleepMs(ms: u64) void {
    var req: tl.timespec = .{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * std.time.ns_per_ms),
    };
    var rem: tl.timespec = undefined;
    while (tl.errno(tl.nanosleep(&req, &rem)) == .INTR) req = rem;
}

const TestListener = struct { fd: i32, port: u16 };

/// Bind and listen on loopback, ephemeral port. Returns a typed error rather
/// than skipping: on Linux this cannot legitimately fail for IPv4, and the
/// one case that can (no IPv6 on the host) is skipped LOUDLY at its call site.
fn listenLoopback(v6: bool, backlog: u32) error{ListenSetup}!TestListener {
    const fd: i32 = blk: {
        const rc = tl.socket(
            if (v6) tl.AF.INET6 else tl.AF.INET,
            tl.SOCK.STREAM | tl.SOCK.CLOEXEC,
            0,
        );
        if (tl.errno(rc) != .SUCCESS) return error.ListenSetup;
        break :blk @intCast(rc);
    };
    errdefer _ = tl.close(fd);

    const port: u16 = if (v6) p: {
        var sa: tl.sockaddr.in6 = .{
            .port = 0,
            .flowinfo = 0,
            .addr = [_]u8{0} ** 15 ++ [_]u8{1}, // ::1
            .scope_id = 0,
        };
        if (tl.errno(tl.bind(fd, @ptrCast(&sa), @sizeOf(tl.sockaddr.in6))) != .SUCCESS)
            return error.ListenSetup;
        var alen: tl.socklen_t = @sizeOf(tl.sockaddr.in6);
        if (tl.errno(tl.getsockname(fd, @ptrCast(&sa), &alen)) != .SUCCESS)
            return error.ListenSetup;
        break :p std.mem.bigToNative(u16, sa.port);
    } else p: {
        var sa: tl.sockaddr.in = .{ .port = 0, .addr = @bitCast([4]u8{ 127, 0, 0, 1 }) };
        if (tl.errno(tl.bind(fd, @ptrCast(&sa), @sizeOf(tl.sockaddr.in))) != .SUCCESS)
            return error.ListenSetup;
        var alen: tl.socklen_t = @sizeOf(tl.sockaddr.in);
        if (tl.errno(tl.getsockname(fd, @ptrCast(&sa), &alen)) != .SUCCESS)
            return error.ListenSetup;
        break :p std.mem.bigToNative(u16, sa.port);
    };

    if (tl.errno(tl.listen(fd, backlog)) != .SUCCESS) return error.ListenSetup;
    return .{ .fd = fd, .port = port };
}

/// A loopback destination that neither completes a connection nor refuses one.
///
/// `listen(fd, 1)` gives a one-slot accept queue; connections that are never
/// `accept`ed fill it, after which Linux **drops the incoming SYN**
/// (`sk_acceptq_is_full`) rather than answering it. The client then retries
/// SYN with exponential backoff for `tcp_syn_retries` rounds — 6 by default,
/// so ~127 s — which is exactly the unbounded wait `PosixConnector` removes.
///
/// This was measured on this kernel before being relied on, not assumed: a
/// closed port answered in 0.1 ms with `revents = 0x1c` / `SO_ERROR = 111`, an
/// empty accept queue in 0.1 ms with `revents = 0x4`, and a full accept queue
/// hung through both a 200 ms and a 3 000 ms poll. The tests re-assert that
/// property every run: a full-second budget that still returns `.timeout` is
/// something neither a listening peer nor a closed port can produce on
/// loopback, so a black hole that silently stopped being one fails the test
/// instead of quietly weakening it.
const BlackHole = struct {
    listener: i32,
    fillers: [16]i32,
    port: u16,

    fn init() error{BlackHoleSetup}!BlackHole {
        const ln = listenLoopback(false, 1) catch return error.BlackHoleSetup;
        var bh: BlackHole = .{ .listener = ln.fd, .fillers = @splat(-1), .port = ln.port };
        for (&bh.fillers) |*f| {
            const rc = tl.socket(tl.AF.INET, tl.SOCK.STREAM | tl.SOCK.NONBLOCK | tl.SOCK.CLOEXEC, 0);
            if (tl.errno(rc) != .SUCCESS) {
                bh.deinit();
                return error.BlackHoleSetup;
            }
            f.* = @intCast(rc);
            var sa: tl.sockaddr.in = .{
                .port = std.mem.nativeToBig(u16, bh.port),
                .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
            };
            // Non-blocking and never awaited: whichever of these fit into the
            // one-slot accept queue is enough to close it.
            _ = tl.connect(f.*, @ptrCast(&sa), @sizeOf(tl.sockaddr.in));
        }
        sleepMs(250); // let the handshakes that DO fit settle into the queue
        return bh;
    }

    fn deinit(self: *BlackHole) void {
        for (self.fillers) |f| if (f >= 0) {
            _ = tl.close(f);
        };
        _ = tl.close(self.listener);
    }

    fn target(self: *const BlackHole, buf: []u8) !Target {
        return Target.parse(try std.fmt.bufPrint(buf, "127.0.0.1:{d}", .{self.port}));
    }
};

test "live: a black hole returns on the budget, and the budget is what decides" {
    var bh = try BlackHole.init();
    defer bh.deinit();

    var pc: PosixConnector = .{ .resolve = .literal_only };
    const c = pc.connector();
    var buf: [24]u8 = undefined;
    const t = try bh.target(&buf);
    const ms = std.time.ns_per_ms;

    // 200 ms budget.
    const t0 = monoNs();
    const short = c.connect(t, 200 * ms);
    const short_el = monoNs() -| t0;
    try testing.expectEqual(Status.timeout, short.status);
    try testing.expect(short_el >= 190 * ms);
    // Generous on purpose (CI is loaded) — and still ~3 orders of magnitude
    // under the OS default measured on this same black hole: `std.Io.net`
    // took 134 367 ms for the same 200 ms budget.
    try testing.expect(short_el < 2 * std.time.ns_per_s);

    // 1 s budget on the same destination. Two things at once: it re-proves the
    // destination is a real black hole (a listening peer completes and a closed
    // port refuses, both in microseconds on loopback — neither can time out at
    // one second), and it proves the wall clock follows the BUDGET rather than
    // being some fixed internal constant.
    const t1 = monoNs();
    const long = c.connect(t, std.time.ns_per_s);
    const long_el = monoNs() -| t1;
    try testing.expectEqual(Status.timeout, long.status);
    try testing.expect(long_el >= 990 * ms);
    try testing.expect(long_el < 4 * std.time.ns_per_s);
    try testing.expect(long_el > short_el);
}

/// Context for the abandoned `LiveConnector` thread in the contrast test.
/// File-scope rather than allocated: the thread outlives the test by design,
/// so its context must outlive the test too — and a static has no owner to
/// leak from.
const LiveRace = struct {
    port: u16 = 0,
    done: std.atomic.Value(bool) = .init(false),

    fn run(self: *LiveRace) void {
        // page_allocator, not `testing.allocator`: this thread is abandoned
        // mid-syscall and never joined, so nothing may be checked for leaks
        // against it, and `threaded` is deliberately never deinitialized.
        var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{}); // global-alloc-ok: abandoned test-only thread, never joined, never deinit'd (see doc comment above)
        var lc: LiveConnector = .{ .io = threaded.io() };
        var buf: [24]u8 = undefined;
        const text = std.fmt.bufPrint(&buf, "127.0.0.1:{d}", .{self.port}) catch return;
        const t = Target.parse(text) catch return;
        _ = lc.connector().connect(t, 200 * std.time.ns_per_ms);
        self.done.store(true, .release);
    }
};

var live_race: LiveRace = .{};

test "live: the std path ignores the same budget — the contrast that makes this load-bearing" {
    // A green test on the new path alone would prove nothing: it has to be
    // shown that the OLD path, against the SAME destination with the SAME
    // budget, does not come back.
    var bh = try BlackHole.init();
    // Closing the listener at the end turns the abandoned thread's pending SYN
    // retries into an RST, so that thread finishes on its own moments later
    // instead of lingering for two minutes.
    defer bh.deinit();

    live_race = .{ .port = bh.port };
    var th = try std.Thread.spawn(.{}, LiveRace.run, .{&live_race});
    th.detach(); // it cannot be joined: it is stuck for ~134 s by construction

    // The new connector, same black hole, same 200 ms budget.
    var pc: PosixConnector = .{ .resolve = .literal_only };
    var buf: [24]u8 = undefined;
    const t = try bh.target(&buf);
    const t0 = monoNs();
    const out = pc.connector().connect(t, 200 * std.time.ns_per_ms);
    const el = monoNs() -| t0;
    try testing.expectEqual(Status.timeout, out.status);
    try testing.expect(el < 2 * std.time.ns_per_s);

    // Give `LiveConnector` ten times its own budget…
    sleepMs(2000);
    // …and it is still inside the connect. Run to completion once outside the
    // gate, it returned `error.Timeout` after 134 367 ms (tcp_syn_retries = 6).
    // The gate asserts the shape, not the two minutes.
    try testing.expect(!live_race.done.load(.acquire));
}

test "live: a closed loopback port is refused fast, and is never reported as a timeout" {
    // Bind to learn a port, then close it: nothing is listening there.
    const ln = try listenLoopback(false, 8);
    _ = tl.close(ln.fd);

    var pc: PosixConnector = .{ .resolve = .literal_only };
    var buf: [24]u8 = undefined;
    const t = try Target.parse(try std.fmt.bufPrint(&buf, "127.0.0.1:{d}", .{ln.port}));

    // A five-second budget it must not spend: `refused` is the fast definitive
    // negative. It arrives through `poll` as POLLOUT|POLLERR|POLLHUP with
    // SO_ERROR = ECONNREFUSED, so reading POLLOUT alone would call this `.up`
    // and mapping every non-writable wake to `.timeout` would call it that.
    const t0 = monoNs();
    const out = pc.connector().connect(t, 5 * std.time.ns_per_s);
    const el = monoNs() -| t0;
    try testing.expectEqual(Status.refused, out.status);
    try testing.expect(el < std.time.ns_per_s);
    // The classification is `.refused`, and the concrete errno it was
    // classified from also survives — measured on this kernel as SO_ERROR
    // 111 (see `classifyErrno`'s own pinned constant test).
    try testing.expectEqual(@as(?i32, @intFromEnum(std.os.linux.E.CONNREFUSED)), out.errno);
}

test "live: a listening loopback port is up, with a measured rtt" {
    const ln = try listenLoopback(false, 16);
    defer _ = tl.close(ln.fd);

    var pc: PosixConnector = .{ .resolve = .literal_only };
    var buf: [24]u8 = undefined;
    const t = try Target.parse(try std.fmt.bufPrint(&buf, "127.0.0.1:{d}", .{ln.port}));
    const out = pc.connector().connect(t, 5 * std.time.ns_per_s);
    try testing.expectEqual(Status.up, out.status);
    try testing.expect(out.rtt_ns != null);
    // Loopback frequently completes inside connect() itself; either way the
    // classification must be `.up`, not "writable, therefore unknown".
    try testing.expect(out.rtt_ns.? < std.time.ns_per_s);

    // A zero budget means "no budget", not "instant timeout" — the branch that
    // makes `poll` wait indefinitely, and the only one no other test reaches.
    try testing.expectEqual(Status.up, pc.connector().connect(t, 0).status);
}

/// The lowest free descriptor number, obtained by taking one and giving it
/// straight back. POSIX requires `dup` to return the LOWEST available number,
/// so this is a total order on "how many descriptors are held" without reading
/// `/proc` or depending on `std.fs`, whose API moved in 0.16. The absolute
/// value is uninteresting; the DIFFERENCE across a batch is the oracle.
fn lowestFreeFd() !i32 {
    const rc = tl.dup(0);
    const fd: i32 = @intCast(rc);
    if (fd < 0) return error.DupFailed;
    _ = tl.close(fd);
    return fd;
}

test "live: attempts do not leak a descriptor, on any outcome" {
    // The failure this exists to catch is invisible to every other test in this
    // file: a connector that never closes its socket passes all of them, and
    // then exhausts the process in production. That is not hypothetical for the
    // consumer this module exists for — `upstream`'s health checker probes the
    // same targets on a timer, forever, with up to 256 workers, so one leaked
    // descriptor per attempt is an outage on a clock.
    const up = try listenLoopback(false, 16);
    defer _ = tl.close(up.fd);
    const closed = try listenLoopback(false, 8);
    _ = tl.close(closed.fd);
    var hole = try BlackHole.init();
    defer hole.deinit();

    var pc: PosixConnector = .{ .resolve = .literal_only };
    var b1: [24]u8 = undefined;
    var b2: [24]u8 = undefined;
    var b3: [24]u8 = undefined;
    const t_up = try Target.parse(try std.fmt.bufPrint(&b1, "127.0.0.1:{d}", .{up.port}));
    const t_refused = try Target.parse(try std.fmt.bufPrint(&b2, "127.0.0.1:{d}", .{closed.port}));
    const t_hole = try hole.target(&b3);

    // One of each first, so any one-off allocation of a descriptor by the
    // machinery below (not by the connector) is already paid for and cannot be
    // mistaken for a leak.
    _ = pc.connector().connect(t_up, std.time.ns_per_s);
    _ = pc.connector().connect(t_refused, std.time.ns_per_s);
    _ = pc.connector().connect(t_hole, 20 * std.time.ns_per_ms);

    const before = try lowestFreeFd();
    const rounds = 12;
    for (0..rounds) |_| {
        try testing.expectEqual(Status.up, pc.connector().connect(t_up, std.time.ns_per_s).status);
        try testing.expectEqual(Status.refused, pc.connector().connect(t_refused, std.time.ns_per_s).status);
        try testing.expectEqual(Status.timeout, pc.connector().connect(t_hole, 20 * std.time.ns_per_ms).status);
    }
    const after = try lowestFreeFd();

    // Exact equality, not a threshold: the three outcomes take three different
    // exits out of the connector, and a leak on any ONE of them would show up
    // as `rounds` descriptors' worth of drift. A tolerance here would hide
    // exactly that.
    try testing.expectEqual(before, after);
}

test "live: IPv6 loopback works end to end through [v6]:port" {
    const ln = listenLoopback(true, 16) catch
        return testkit.skip("no IPv6 loopback here: bind([::1]:0) failed", .{});
    defer _ = tl.close(ln.fd);

    var pc: PosixConnector = .{ .resolve = .literal_only };
    var buf: [32]u8 = undefined;
    const t = try Target.parse(try std.fmt.bufPrint(&buf, "[::1]:{d}", .{ln.port}));
    try testing.expectEqualStrings("::1", t.host); // brackets stripped by Target.parse
    const out = pc.connector().connect(t, 5 * std.time.ns_per_s);
    try testing.expectEqual(Status.up, out.status);
    try testing.expect(out.rtt_ns != null);
}

test "live: the documented DNS boundary — a literal never reaches a resolver" {
    const ms = std.time.ns_per_ms;
    const name = try Target.parse("no-such-host.invalid:80");

    // `.literal_only`: a name is a typed negative, immediately, with no
    // resolver call. The timing is the assertion that matters — std's resolver
    // is bounded by /etc/resolv.conf `options timeout:` (default 5 s), which
    // this budget has no influence over, so anything that actually consulted
    // it could not come back in under 50 ms.
    var strict: PosixConnector = .{ .resolve = .literal_only };
    const t0 = monoNs();
    const out = strict.connector().connect(name, 200 * ms);
    const el = monoNs() -| t0;
    try testing.expectEqual(Status.@"error", out.status);
    try testing.expect(el < 50 * ms);

    // `.system` without an `io` is a configuration error, not a hang.
    var loose: PosixConnector = .{ .resolve = .system, .io = null };
    try testing.expectEqual(Status.@"error", loose.connector().connect(name, 200 * ms).status);

    // …and the same `.system` connector, still with no `io`, probes an IP
    // literal perfectly well: `netaddr.parseIp` runs before the policy, so a
    // literal never enters the resolver in EITHER mode. A definitive refusal
    // (not merely "no error") proves the connect really ran.
    const ln = try listenLoopback(false, 8);
    _ = tl.close(ln.fd);
    var buf: [24]u8 = undefined;
    const lit = try Target.parse(try std.fmt.bufPrint(&buf, "127.0.0.1:{d}", .{ln.port}));
    try testing.expectEqual(Status.refused, loose.connector().connect(lit, 200 * ms).status);
}

test "live: system resolution does resolve a name, without leaving the host" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    // RFC 6761 §6.3: `localhost` is answered from /etc/hosts or from std's own
    // special case, so no packet leaves the machine and the test stays
    // hermetic — while still exercising the real `HostName.lookup` path that
    // `.system` uses.
    const ip = PosixConnector.resolveFirst(threaded.io(), "localhost", 0) orelse
        return error.LocalhostDidNotResolve;
    const loopback = switch (ip) {
        .v4 => |q| q[0] == 127,
        .v6 => |b| std.mem.eql(u8, &b, &([_]u8{0} ** 15 ++ [_]u8{1})),
    };
    try testing.expect(loopback);
}

test "live: a fan-out over black-holed targets finishes on the budget" {
    // The `upstream` health-checker shape, which is why this module is being
    // fixed now: several dark backends, one small budget, workers that must
    // come back. With `LiveConnector` these eight attempts would hold their
    // workers for ~134 s each.
    var bh = try BlackHole.init();
    defer bh.deinit();

    var buf: [24]u8 = undefined;
    const t = try bh.target(&buf);
    const targets = [_]Target{t} ** 8;

    var pc: PosixConnector = .{ .resolve = .literal_only };
    const t0 = monoNs();
    const results = try probeMany(testing.allocator, &targets, .{
        .connector = pc.connector(),
        .timeout_ms = 200,
        .count = 1,
        .max_concurrent = 8,
    });
    defer freeResults(testing.allocator, results);
    const el = monoNs() -| t0;

    for (results) |r| {
        try testing.expectEqual(Status.timeout, r.samples[0].kind);
        try testing.expect(!r.reachable());
    }
    try testing.expect(el < 3 * std.time.ns_per_s);
}

test "classifyErrno keeps refused, timeout and error distinct" {
    const E = std.os.linux.E;
    try testing.expectEqual(Status.refused, classifyErrno(@intFromEnum(E.CONNREFUSED)));
    try testing.expectEqual(Status.timeout, classifyErrno(@intFromEnum(E.TIMEDOUT)));
    try testing.expectEqual(Status.@"error", classifyErrno(@intFromEnum(E.HOSTUNREACH)));
    try testing.expectEqual(Status.@"error", classifyErrno(@intFromEnum(E.NETUNREACH)));
    try testing.expectEqual(Status.@"error", classifyErrno(@intFromEnum(E.ACCES)));
    try testing.expectEqual(Status.up, classifyErrno(0));
    // Not an errno at all: taken as an integer precisely so this cannot be
    // illegal behaviour, and it must not be mistaken for a known code.
    try testing.expectEqual(Status.@"error", classifyErrno(0x7fff_ffff));
    try testing.expectEqual(Status.@"error", classifyErrno(-1));
    // The two that must never collapse into each other.
    try testing.expect(classifyErrno(@intFromEnum(E.CONNREFUSED)) !=
        classifyErrno(@intFromEnum(E.TIMEDOUT)));
    // The CONSTANTS, not just the mechanism: a mapping written in terms of
    // `E.CONNREFUSED` still passes if the enum is re-spelled, so pin the wire
    // values Linux actually reports through SO_ERROR.
    try testing.expectEqual(@as(i32, 111), @as(i32, @intFromEnum(E.CONNREFUSED)));
    try testing.expectEqual(@as(i32, 110), @as(i32, @intFromEnum(E.TIMEDOUT)));
    try testing.expectEqual(Status.refused, classifyErrno(111));
    try testing.expectEqual(Status.timeout, classifyErrno(110));
}

// ── EINTR: the budget must survive interruption without being restarted ─────

var eintr_seen: std.atomic.Value(u32) = .init(0);

fn eintrHandler(_: tl.SIG) callconv(.c) void {
    _ = eintr_seen.fetchAdd(1, .monotonic);
}

/// Interrupt one specific thread every 10 ms for `duration_ms`, then stop by
/// itself. Self-terminating on purpose: a storm that ran until the probe
/// returned could never fail a connector that never returns.
fn eintrStorm(tgid: tl.pid_t, tid: tl.pid_t, duration_ms: u64) void {
    const deadline = monoNs() + duration_ms * std.time.ns_per_ms;
    while (monoNs() < deadline) {
        _ = tl.tgkill(tgid, tid, .URG);
        sleepMs(10);
    }
}

test "live: a signal storm interrupts poll without extending the budget" {
    // The failure this pins is silent by construction: a connector that
    // restarts its full timeout after each EINTR is correct-looking, passes
    // every other test here, and multiplies the budget by the host's signal
    // rate in production.
    var bh = try BlackHole.init();
    defer bh.deinit();

    // SIGURG: unused here, and its default disposition is "ignore", so a
    // straggler arriving after the handler is restored does nothing. No
    // SA_RESTART — poll must come back EINTR.
    var saved: std.posix.Sigaction = undefined;
    const act: std.posix.Sigaction = .{
        .handler = .{ .handler = eintrHandler },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.URG, &act, &saved);
    defer std.posix.sigaction(.URG, &saved, null);

    eintr_seen.store(0, .release);
    const storm = try std.Thread.spawn(.{}, eintrStorm, .{ tl.getpid(), tl.gettid(), 600 });
    defer storm.join();

    var pc: PosixConnector = .{ .resolve = .literal_only };
    var buf: [24]u8 = undefined;
    const t = try bh.target(&buf);
    const t0 = monoNs();
    const out = pc.connector().connect(t, 200 * std.time.ns_per_ms);
    const el = monoNs() -| t0;

    // Without this the test asserts nothing: if no signal ever landed, the
    // "budget was not extended" claim is about a code path that never ran.
    try testing.expect(eintr_seen.load(.acquire) >= 5);
    try testing.expectEqual(Status.timeout, out.status);
    try testing.expect(el >= 190 * std.time.ns_per_ms);
    // The storm lasts 600 ms. A connector that restarted its budget on each
    // interruption could not return before ~800 ms; recomputing the remainder
    // returns at ~200 ms.
    try testing.expect(el < 500 * std.time.ns_per_ms);
}
