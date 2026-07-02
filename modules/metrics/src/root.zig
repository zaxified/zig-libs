// SPDX-License-Identifier: MIT

//! metrics — thread-safe metrics registry (Counter / Gauge / Histogram),
//! Prometheus text exposition, and a request-metrics `router` middleware
//! recording the golden signals (rate, errors, duration, in-flight).
//!
//! Model after **Prometheus client_golang** (registry/instrument semantics)
//! and the **Prometheus text exposition format 0.0.4** (the format Prometheus,
//! Grafana Agent and friends scrape; OpenMetrics is a superset — this module
//! emits the classic format, no `# EOF`). Where the two leave a choice, the
//! client_golang behavior wins; deviations are called out below.
//!
//! Layers:
//! - **`Registry`** — owns metric families. `counter`/`gauge`/`histogram` are
//!   *get-or-register*: the first call with a given (name, label values)
//!   creates the instrument, later calls return the same stable pointer
//!   (client_golang `GetMetricWithLabelValues`). All strings and bucket
//!   slices are copied into the registry's arena — callers may pass stack
//!   temporaries. `deinit` frees everything at once.
//! - **Instruments** — `Counter` is a monotonic `u64` (never negative by
//!   construction; deviation: client_golang counters accept float `Add`,
//!   ours are integer-valued — sufficient for event counts). `Gauge` is an
//!   `f64` with `set`/`inc`/`dec`/`add`/`sub`. `Histogram` has configurable
//!   `le` upper bounds and exposes cumulative buckets + `_sum` + `_count`
//!   with the implicit `le="+Inf"` bucket.
//! - **Exposition** — `Registry.writeText` emits the exact text format:
//!   `# HELP` (backslash/newline escaped) and `# TYPE` once per family,
//!   samples with escaped label values, histogram `_bucket`/`_sum`/`_count`.
//!   `Endpoint` serves it over `GET /metrics` as an intercepting
//!   `router.Middleware`; `Registry.respond` is the piece to call from a
//!   hand-written handler.
//! - **`RequestMetrics`** — the request middleware: a request counter
//!   (labels `method` + `code`, status *class* `2xx`/`3xx`/`4xx`/`5xx` by
//!   default to bound cardinality), a latency histogram in seconds (label
//!   `method`), an in-flight gauge (inc on entry, dec via `defer`, also on
//!   handler error), and an optional structured access-log callback.
//!
//! **Cardinality footgun (READ THIS):** every distinct label-value
//! combination is a separate time series that lives for the life of the
//! registry and is scraped forever. Label values must come from a *small,
//! fixed* set (method, status class, route pattern) — never from request
//! data (path, user id, query string), or the registry becomes an unbounded
//! memory leak and the scrape melts Prometheus. This is why the middleware
//! defaults to status *classes* and does not label by raw path.
//!
//! Thread-safety: counters and gauges are single atomics (`.monotonic` —
//! independent counts need no cross-metric ordering; a scrape is never a
//! consistent cross-instrument snapshot anyway, same as client_golang).
//! Registration (family/child lookup) and `Histogram.observe` take a
//! spinlock (`std.atomic.Mutex` + `spinLoopHint`, the std SmpAllocator
//! pattern — Zig 0.16 std has no io-less blocking mutex); critical sections
//! are a few string compares / adds. `writeText` holds the registry lock for
//! the whole write so racing registrations spin briefly during a scrape —
//! registration is get-or-register, so steady-state request paths only
//! *read* under the lock-free caches and never register.

const std = @import("std");
const router = @import("router");
const http = @import("http");

pub const meta = .{
    .status = .gap,
    .platform = .posix, // default latency clock uses the posix clock_gettime errno form
    .role = .util,
    // Internally synchronized: atomics for counter/gauge, documented
    // spinlocks for registration and histogram observe (see module doc).
    .concurrency = .threadsafe,
    .model_after = "Prometheus client_golang (registry/instrument semantics) + Prometheus text exposition format 0.0.4",
    .deps = .{ "router", "http" },
};

const Allocator = std.mem.Allocator;

/// Spinlock acquire (std SmpAllocator pattern) — see the module doc for why
/// a spinlock and what it guards.
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// ── clock injection ─────────────────────────────────────────────────────────

/// Monotonic time source for the latency histogram, injected so durations
/// are testable. Implementations must be non-decreasing; only differences
/// are used.
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (?*anyopaque) u64,

    /// The OS monotonic clock (CLOCK_MONOTONIC via the posix `clock_gettime`
    /// errno form) — the production default, and the only place in the
    /// module that touches a real clock.
    pub const monotonic: Clock = .{ .nowFn = monotonicNowNs };

    pub fn now(c: Clock) u64 {
        return c.nowFn(c.ctx);
    }
};

fn monotonicNowNs(_: ?*anyopaque) u64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS)
        return 0;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

// ── labels ──────────────────────────────────────────────────────────────────

/// One label pair. Values are free-form UTF-8 (escaped at exposition);
/// names must match `[a-zA-Z_][a-zA-Z0-9_]*` and not start with `__`
/// (reserved by Prometheus). Keep the *set of values* small and fixed —
/// see the cardinality footgun in the module doc.
pub const Label = struct {
    name: []const u8,
    value: []const u8,
};

/// Upper bound of labels per instrument — labels are a fixed small set by
/// design (cardinality), not a data channel.
pub const max_labels = 8;

// ── instruments ─────────────────────────────────────────────────────────────

/// Monotonic counter. Integer-valued (`u64`) — it can only go up, so
/// "never negative" holds by construction. Lock-free.
pub const Counter = struct {
    count: std.atomic.Value(u64) = .init(0),

    pub fn inc(c: *Counter) void {
        _ = c.count.fetchAdd(1, .monotonic);
    }

    /// Add `n` (≥ 0 by type — counters cannot decrease).
    pub fn add(c: *Counter, n: u64) void {
        _ = c.count.fetchAdd(n, .monotonic);
    }

    pub fn value(c: *const Counter) u64 {
        return c.count.load(.monotonic);
    }
};

/// Gauge: an `f64` that can go up and down (client_golang semantics).
/// Lock-free — `set` is an atomic store, `add`/`sub`/`inc`/`dec` are CAS
/// loops on the bit pattern.
pub const Gauge = struct {
    /// f64 bits (0 == 0.0, so zero-init is a zero gauge).
    bits: std.atomic.Value(u64) = .init(0),

    pub fn set(g: *Gauge, v: f64) void {
        g.bits.store(@bitCast(v), .monotonic);
    }

    pub fn add(g: *Gauge, delta: f64) void {
        var old = g.bits.load(.monotonic);
        while (true) {
            const new: f64 = @as(f64, @bitCast(old)) + delta;
            old = g.bits.cmpxchgWeak(old, @bitCast(new), .monotonic, .monotonic) orelse return;
        }
    }

    pub fn sub(g: *Gauge, delta: f64) void {
        g.add(-delta);
    }

    pub fn inc(g: *Gauge) void {
        g.add(1);
    }

    pub fn dec(g: *Gauge) void {
        g.add(-1);
    }

    pub fn value(g: *const Gauge) f64 {
        return @bitCast(g.bits.load(.monotonic));
    }
};

/// Histogram with fixed `le` upper bounds (shared by the whole family).
/// `observe` and the exposition snapshot run under the instrument's
/// spinlock (documented in the module doc) — a multi-word update (bucket +
/// count + sum) has no lock-free representation worth the complexity.
/// Buckets are stored per-bucket and *emitted* cumulative; the `+Inf`
/// bucket is implicit and always equals `_count`. An observation lands in
/// the first bucket with `v <= le` (Prometheus `le` is inclusive); NaN
/// observations count toward `_count`/`+Inf` and poison `_sum` (NaN),
/// matching client_golang.
pub const Histogram = struct {
    lock: std.atomic.Mutex = .unlocked,
    /// Sorted, strictly increasing, finite (arena-owned; +Inf implicit).
    upper_bounds: []const f64,
    /// Per-bucket (non-cumulative) observation counts, same length.
    bucket_counts: []u64,
    observation_count: u64 = 0,
    observation_sum: f64 = 0,

    pub fn observe(h: *Histogram, v: f64) void {
        lockSpin(&h.lock);
        defer h.lock.unlock();
        for (h.upper_bounds, 0..) |le, i| {
            if (v <= le) {
                h.bucket_counts[i] += 1;
                break;
            }
        }
        h.observation_count += 1;
        h.observation_sum += v;
    }

    /// Total number of observations (the `_count` sample).
    pub fn count(h: *Histogram) u64 {
        lockSpin(&h.lock);
        defer h.lock.unlock();
        return h.observation_count;
    }

    /// Sum of all observed values (the `_sum` sample).
    pub fn sum(h: *Histogram) f64 {
        lockSpin(&h.lock);
        defer h.lock.unlock();
        return h.observation_sum;
    }

    /// Cumulative count of observations ≤ `upper_bounds[i]` (what the
    /// `_bucket{le=...}` sample exposes).
    pub fn cumulativeBucket(h: *Histogram, i: usize) u64 {
        lockSpin(&h.lock);
        defer h.lock.unlock();
        var acc: u64 = 0;
        for (h.bucket_counts[0 .. i + 1]) |c| acc += c;
        return acc;
    }
};

/// client_golang `DefBuckets` — latency-in-seconds defaults.
pub const default_buckets = [_]f64{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 };

// ── the registry ────────────────────────────────────────────────────────────

pub const RegisterError = error{
    OutOfMemory,
    /// Metric name must match `[a-zA-Z_:][a-zA-Z0-9_:]*`.
    InvalidName,
    /// Label name must match `[a-zA-Z_][a-zA-Z0-9_]*`, not start with the
    /// reserved `__`, and not be `le` on a histogram.
    InvalidLabelName,
    /// Buckets must be finite and strictly increasing (deviation:
    /// client_golang silently strips a trailing `+Inf` and panics on
    /// unsorted input; we surface an error).
    InvalidBuckets,
    /// The name is already registered as a different instrument type.
    WrongType,
    /// The name is already registered with different help text
    /// (client_golang `AlreadyRegisteredError` — one docstring per family).
    HelpMismatch,
    /// The name is already registered with a different label-name set
    /// (a family's series must be label-consistent, in the same order).
    LabelMismatch,
    /// The histogram name is already registered with different buckets.
    BucketsMismatch,
    /// More than `max_labels` labels.
    TooManyLabels,
};

const Kind = enum { counter, gauge, histogram };

const Instrument = union(Kind) {
    counter: Counter,
    gauge: Gauge,
    histogram: Histogram,
};

/// One time series: a fixed label-value tuple + its instrument. Arena-owned,
/// stable address for the registry's lifetime.
const Child = struct {
    /// Values in the family's label-name order.
    label_values: []const []const u8,
    data: Instrument,
};

/// One metric family: `# HELP`/`# TYPE` emitted once, then every child.
const Family = struct {
    name: []const u8,
    help: []const u8,
    kind: Kind,
    /// Fixed label-name set (order matters; children match positionally).
    label_names: []const []const u8,
    /// Histogram families only, else empty.
    buckets: []const f64,
    children: std.ArrayList(*Child) = .empty,
};

/// Thread-safe metric registry — see the module doc. Instruments returned
/// by `counter`/`gauge`/`histogram` are arena-owned stable pointers, valid
/// until `deinit`. The Registry must outlive any Router its middleware /
/// endpoint is registered on, at a stable address.
pub const Registry = struct {
    arena: std.heap.ArenaAllocator,
    /// Guards `families` (lookup + registration) and `writeText` iteration.
    lock: std.atomic.Mutex = .unlocked,
    families: std.ArrayList(*Family) = .empty,

    pub fn init(gpa: Allocator) Registry {
        return .{ .arena = std.heap.ArenaAllocator.init(gpa) };
    }

    pub fn deinit(r: *Registry) void {
        r.arena.deinit();
        r.* = undefined;
    }

    /// Get-or-register a counter time series. `name`/`help`/`labels` are
    /// copied — pass anything. Same (name, label values) → the same
    /// `*Counter` every time.
    pub fn counter(r: *Registry, name: []const u8, help: []const u8, labels: []const Label) RegisterError!*Counter {
        const child = try r.getOrRegister(name, help, .counter, labels, &.{});
        return &child.data.counter;
    }

    /// Get-or-register a gauge time series (see `counter`).
    pub fn gauge(r: *Registry, name: []const u8, help: []const u8, labels: []const Label) RegisterError!*Gauge {
        const child = try r.getOrRegister(name, help, .gauge, labels, &.{});
        return &child.data.gauge;
    }

    /// Get-or-register a histogram time series (see `counter`). `buckets`
    /// are the `le` upper bounds — finite, strictly increasing, `+Inf`
    /// implicit (may be empty = only `+Inf`); the whole family shares the
    /// first registration's buckets.
    pub fn histogram(r: *Registry, name: []const u8, help: []const u8, labels: []const Label, buckets: []const f64) RegisterError!*Histogram {
        const child = try r.getOrRegister(name, help, .histogram, labels, buckets);
        return &child.data.histogram;
    }

    fn getOrRegister(r: *Registry, name: []const u8, help: []const u8, kind: Kind, labels: []const Label, buckets: []const f64) RegisterError!*Child {
        if (!validMetricName(name)) return error.InvalidName;
        if (labels.len > max_labels) return error.TooManyLabels;
        for (labels) |l| {
            if (!validLabelName(l.name)) return error.InvalidLabelName;
            // `le` is the histogram bucket label — user labels must not collide.
            if (kind == .histogram and std.mem.eql(u8, l.name, "le")) return error.InvalidLabelName;
        }
        if (kind == .histogram) {
            for (buckets, 0..) |b, i| {
                if (!std.math.isFinite(b)) return error.InvalidBuckets;
                if (i > 0 and b <= buckets[i - 1]) return error.InvalidBuckets;
            }
        }

        const a = r.arena.allocator();
        lockSpin(&r.lock);
        defer r.lock.unlock();

        const fam = for (r.families.items) |f| {
            if (std.mem.eql(u8, f.name, name)) break f;
        } else blk: {
            const f = try a.create(Family);
            f.* = .{
                .name = try a.dupe(u8, name),
                .help = try a.dupe(u8, help),
                .kind = kind,
                .label_names = try dupeStrings(a, labels, .name),
                .buckets = if (kind == .histogram) try a.dupe(f64, buckets) else &.{},
            };
            try r.families.append(a, f);
            break :blk f;
        };

        if (fam.kind != kind) return error.WrongType;
        if (!std.mem.eql(u8, fam.help, help)) return error.HelpMismatch;
        if (fam.label_names.len != labels.len) return error.LabelMismatch;
        for (fam.label_names, labels) |ln, l| {
            if (!std.mem.eql(u8, ln, l.name)) return error.LabelMismatch;
        }
        if (kind == .histogram) {
            if (fam.buckets.len != buckets.len) return error.BucketsMismatch;
            for (fam.buckets, buckets) |fb, b| {
                if (fb != b) return error.BucketsMismatch;
            }
        }

        child: for (fam.children.items) |c| {
            for (c.label_values, labels) |cv, l| {
                if (!std.mem.eql(u8, cv, l.value)) continue :child;
            }
            return c; // get: existing series
        }

        // Register: a new series in this family.
        const c = try a.create(Child);
        c.* = .{
            .label_values = try dupeStrings(a, labels, .value),
            .data = switch (kind) {
                .counter => .{ .counter = .{} },
                .gauge => .{ .gauge = .{} },
                .histogram => .{ .histogram = .{
                    .upper_bounds = fam.buckets,
                    .bucket_counts = blk: {
                        const counts = try a.alloc(u64, fam.buckets.len);
                        @memset(counts, 0);
                        break :blk counts;
                    },
                } },
            },
        };
        try fam.children.append(a, c);
        return c;
    }

    // ── exposition ──────────────────────────────────────────────────────

    /// Write the whole registry in the Prometheus text exposition format
    /// (version 0.0.4): per family `# HELP` (escaped) + `# TYPE`, then each
    /// series in registration order — counters/gauges as one sample,
    /// histograms as cumulative `_bucket{le=...}` lines (ending in
    /// `le="+Inf"`), `_sum` and `_count`. Deviation from client_golang: it
    /// sorts families by name and series by label values; we emit
    /// registration order (equally deterministic, no sort allocation —
    /// Prometheus does not require sorted input). Holds the registry lock
    /// for the duration (see module doc).
    pub fn writeText(r: *Registry, w: *std.Io.Writer) std.Io.Writer.Error!void {
        lockSpin(&r.lock);
        defer r.lock.unlock();
        for (r.families.items) |fam| {
            try w.print("# HELP {s} ", .{fam.name});
            try writeEscaped(w, fam.help, .help);
            try w.print("\n# TYPE {s} {t}\n", .{ fam.name, fam.kind });
            for (fam.children.items) |c| {
                switch (c.data) {
                    .counter => |*ctr| {
                        try w.writeAll(fam.name);
                        try writeLabels(w, fam.label_names, c.label_values, null);
                        try w.print(" {d}\n", .{ctr.value()});
                    },
                    .gauge => |*g| {
                        try w.writeAll(fam.name);
                        try writeLabels(w, fam.label_names, c.label_values, null);
                        try w.writeByte(' ');
                        try writeFloat(w, g.value());
                        try w.writeByte('\n');
                    },
                    .histogram => |*h| try writeHistogram(w, fam, c, h),
                }
            }
        }
    }

    /// Serve the exposition into a `ResponseWriter`: 200 + the Prometheus
    /// content type + `writeText`. The building block for a hand-written
    /// `/metrics` handler (fish the Registry out of your app state in
    /// `ctx.state`); `Endpoint` is the ready-made variant.
    pub fn respond(r: *Registry, res: *http.Server.ResponseWriter) anyerror!void {
        res.setStatus(200);
        try res.setHeader("Content-Type", content_type);
        try r.writeText(res.writer());
    }
};

fn dupeStrings(a: Allocator, labels: []const Label, comptime field: enum { name, value }) Allocator.Error![]const []const u8 {
    const out = try a.alloc([]const u8, labels.len);
    for (out, labels) |*slot, l| {
        slot.* = try a.dupe(u8, switch (field) {
            .name => l.name,
            .value => l.value,
        });
    }
    return out;
}

/// The scrape Content-Type for text format 0.0.4 (what promhttp sends).
pub const content_type = "text/plain; version=0.0.4; charset=utf-8";

fn writeHistogram(w: *std.Io.Writer, fam: *const Family, c: *const Child, h: *Histogram) std.Io.Writer.Error!void {
    // Snapshot + emit under the instrument lock: buckets/count/sum must be
    // one consistent observation set (the writer usually buffers, so the
    // critical section is memory-speed formatting).
    lockSpin(&h.lock);
    defer h.lock.unlock();
    var cumulative: u64 = 0;
    for (h.upper_bounds, h.bucket_counts) |le, n| {
        cumulative += n;
        try w.print("{s}_bucket", .{fam.name});
        try writeLabels(w, fam.label_names, c.label_values, le);
        try w.print(" {d}\n", .{cumulative});
    }
    try w.print("{s}_bucket", .{fam.name});
    try writeLabels(w, fam.label_names, c.label_values, std.math.inf(f64));
    try w.print(" {d}\n", .{h.observation_count});
    try w.print("{s}_sum", .{fam.name});
    try writeLabels(w, fam.label_names, c.label_values, null);
    try w.writeByte(' ');
    try writeFloat(w, h.observation_sum);
    try w.print("\n{s}_count", .{fam.name});
    try writeLabels(w, fam.label_names, c.label_values, null);
    try w.print(" {d}\n", .{h.observation_count});
}

/// Emit `{name="value",...}` (nothing when empty), appending `le` when given.
fn writeLabels(w: *std.Io.Writer, names: []const []const u8, values: []const []const u8, le: ?f64) std.Io.Writer.Error!void {
    if (names.len == 0 and le == null) return;
    try w.writeByte('{');
    for (names, values, 0..) |n, v, i| {
        if (i != 0) try w.writeByte(',');
        try w.print("{s}=\"", .{n});
        try writeEscaped(w, v, .label_value);
        try w.writeByte('"');
    }
    if (le) |bound| {
        if (names.len != 0) try w.writeByte(',');
        try w.writeAll("le=\"");
        try writeFloat(w, bound);
        try w.writeByte('"');
    }
    try w.writeByte('}');
}

/// Text-format escaping: HELP text escapes `\` and newline; label values
/// additionally escape `"` (both per the exposition-format spec).
fn writeEscaped(w: *std.Io.Writer, s: []const u8, comptime mode: enum { help, label_value }) std.Io.Writer.Error!void {
    var start: usize = 0;
    for (s, 0..) |ch, i| {
        const esc: []const u8 = switch (ch) {
            '\\' => "\\\\",
            '\n' => "\\n",
            '"' => if (mode == .label_value) "\\\"" else continue,
            else => continue,
        };
        try w.writeAll(s[start..i]);
        try w.writeAll(esc);
        start = i + 1;
    }
    try w.writeAll(s[start..]);
}

/// Sample/bound rendering: decimal shortest round-trip (`{d}`), with the
/// spec's spellings for the specials (`+Inf` / `-Inf` / `NaN`). Deviation
/// from client_golang: Go's `%g` switches to exponent notation for extreme
/// magnitudes, `{d}` stays decimal — both parse identically on the
/// Prometheus side.
fn writeFloat(w: *std.Io.Writer, v: f64) std.Io.Writer.Error!void {
    if (std.math.isNan(v)) return w.writeAll("NaN");
    if (std.math.isInf(v)) return w.writeAll(if (v > 0) "+Inf" else "-Inf");
    try w.print("{d}", .{v});
}

fn validMetricName(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s, 0..) |ch, i| {
        const ok = std.ascii.isAlphabetic(ch) or ch == '_' or ch == ':' or
            (i > 0 and std.ascii.isDigit(ch));
        if (!ok) return false;
    }
    return true;
}

fn validLabelName(s: []const u8) bool {
    if (s.len == 0) return false;
    if (std.mem.startsWith(u8, s, "__")) return false; // reserved
    for (s, 0..) |ch, i| {
        const ok = std.ascii.isAlphabetic(ch) or ch == '_' or
            (i > 0 and std.ascii.isDigit(ch));
        if (!ok) return false;
    }
    return true;
}

// ── the /metrics endpoint ───────────────────────────────────────────────────

/// The ready-made scrape endpoint, as an *intercepting* `router.Middleware`
/// (the `cors` pattern): `GET`/`HEAD` on `path` answers the exposition and
/// never calls `next`; any other method on `path` answers 405 + `Allow`;
/// everything else passes through. A middleware rather than the SPEC's
/// `metrics.handler(registry)` because `router.Handler` is a stateless fn
/// pointer — it cannot close over the Registry (`Registry.respond` covers
/// the write-your-own-handler case).
///
/// Register it router-level *before* `RequestMetrics.middleware` so scrapes
/// are not counted as traffic (or after, if you want them counted). The
/// Endpoint must outlive the Router, at a stable address.
pub const Endpoint = struct {
    registry: *Registry,
    /// Byte-exact request path to intercept (router raw-matching rules).
    path: []const u8 = "/metrics",

    pub fn middleware(e: *Endpoint) router.Middleware {
        return .{ .state = e, .run = endpointRun };
    }
};

fn endpointRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const e: *Endpoint = @ptrCast(@alignCast(state.?));
    if (!std.mem.eql(u8, ctx.req.path, e.path)) return next.run(ctx);
    switch (ctx.req.method) {
        .get, .head => try e.registry.respond(ctx.res),
        else => {
            ctx.res.setStatus(405);
            try ctx.res.setHeader("Allow", "GET, HEAD");
            try ctx.res.setHeader("Content-Type", "text/plain");
            try ctx.res.writeAll("Method Not Allowed\n");
        },
    }
}

// ── the request middleware ──────────────────────────────────────────────────

/// One record handed to the access-log hook — a *hook*, not a logger: the
/// callback formats/ships it however the app logs. Called on the request
/// thread after the response side of the chain finished (also when the
/// handler failed); keep it fast and thread-safe. `path` is only valid
/// during the callback.
pub const AccessEntry = struct {
    method: http.Method,
    /// Request path (no query). Borrowed — copy it to retain.
    path: []const u8,
    /// Response status; 500 when the handler errored before sending.
    status: u16,
    duration_ns: u64,
    /// Response body bytes when knowable: exact for buffered bodies,
    /// the declared Content-Length for identity streams, 0 for
    /// HEAD/204/304, null for chunked/until-close streams (the response
    /// writer keeps no running total).
    bytes: ?u64,
};

const method_count = @typeInfo(http.Method).@"enum".fields.len;
/// Status-class cache slots: index 1–5 = `1xx`–`5xx`, 0 = `other`.
const class_count = 6;

/// Request-metrics middleware state: per request a counter
/// (`method` + `code` labels), a latency histogram in seconds (`method`
/// label) and an in-flight gauge, recorded *around* `next` — so 404/405
/// fallbacks and inner short-circuits (429/503) are measured too, and the
/// in-flight decrement runs via `defer` even when the handler errors. A
/// handler error is recorded as the status the server will send: the
/// already-sent status when the head is on the wire, else 500.
///
/// Series are created lazily on first use (client_golang
/// `WithLabelValues` behavior — untouched combinations never appear in the
/// exposition) and memoized in lock-free atomic caches, so the steady-state
/// hot path takes no registry lock; `.code` granularity skips the counter
/// cache and does a locked registry lookup per request (bounded, documented
/// tradeoff). Failures to create a series (OOM) skip recording but never
/// fail the request.
///
/// Route-pattern label: deliberately absent — `router.Ctx` does not expose
/// the matched pattern (route enumeration is a planned router follow-up);
/// labeling by raw `path` instead would be the cardinality footgun.
pub const RequestMetrics = struct {
    registry: *Registry,
    options: Options,
    in_flight: *Gauge,
    counters: [method_count][class_count]std.atomic.Value(?*Counter) =
        @splat(@splat(.init(null))),
    histograms: [method_count]std.atomic.Value(?*Histogram) = @splat(.init(null)),

    pub const StatusGranularity = enum {
        /// `code="2xx"` … — bounded cardinality (default).
        class,
        /// `code="200"` … — exact codes; still bounded, but ~×10 series.
        code,
    };

    pub const Options = struct {
        counter_name: []const u8 = "http_requests_total",
        counter_help: []const u8 = "Total HTTP requests served, by method and status code class.",
        histogram_name: []const u8 = "http_request_duration_seconds",
        histogram_help: []const u8 = "HTTP request latency in seconds, by method.",
        in_flight_name: []const u8 = "http_requests_in_flight",
        in_flight_help: []const u8 = "HTTP requests currently being served.",
        /// Latency bucket upper bounds in seconds.
        buckets: []const f64 = &default_buckets,
        /// `code` label granularity — classes by default (cardinality).
        status: StatusGranularity = .class,
        /// Time source for the latency histogram — inject a fake in tests.
        clock: Clock = .monotonic,
        /// Optional structured access-log hook (see `AccessEntry`).
        on_request: ?*const fn (?*anyopaque, AccessEntry) void = null,
        /// Opaque context passed to `on_request`.
        on_request_ctx: ?*anyopaque = null,
    };

    /// Validates the metric names and registers the in-flight gauge up
    /// front (so misconfiguration fails here, not mid-request). The
    /// Registry must outlive the returned value; the returned value must
    /// sit at a stable address before `middleware()` is registered.
    pub fn init(registry: *Registry, options: Options) RegisterError!RequestMetrics {
        // Surface name/bucket problems now: touch each family once with a
        // throwaway series that real traffic will also use... except the
        // gauge, which is unlabeled and *is* the real series.
        if (!validMetricName(options.counter_name)) return error.InvalidName;
        if (!validMetricName(options.histogram_name)) return error.InvalidName;
        for (options.buckets, 0..) |b, i| {
            if (!std.math.isFinite(b)) return error.InvalidBuckets;
            if (i > 0 and b <= options.buckets[i - 1]) return error.InvalidBuckets;
        }
        return .{
            .registry = registry,
            .options = options,
            .in_flight = try registry.gauge(options.in_flight_name, options.in_flight_help, &.{}),
        };
    }

    /// The `router.Middleware` (`state` = this RequestMetrics). Register it
    /// router-level, before routes (chi's rule), typically *after* the
    /// `Endpoint` middleware so scrapes go unrecorded.
    pub fn middleware(m: *RequestMetrics) router.Middleware {
        return .{ .state = m, .run = requestRun };
    }

    fn counterFor(m: *RequestMetrics, method: http.Method, status: u16) RegisterError!*Counter {
        const mi = @intFromEnum(method);
        const ci: usize = if (status >= 100 and status <= 599) status / 100 else 0;
        if (m.options.status == .class) {
            if (m.counters[mi][ci].load(.acquire)) |c| return c;
        }
        var code_buf: [3]u8 = undefined;
        const code: []const u8 = switch (m.options.status) {
            .class => classLabel(ci),
            .code => std.fmt.bufPrint(&code_buf, "{d}", .{status}) catch classLabel(ci),
        };
        const c = try m.registry.counter(m.options.counter_name, m.options.counter_help, &.{
            .{ .name = "method", .value = @tagName(method) },
            .{ .name = "code", .value = code },
        });
        // Races publish the same registry-owned pointer — last store wins,
        // harmlessly.
        if (m.options.status == .class) m.counters[mi][ci].store(c, .release);
        return c;
    }

    fn histogramFor(m: *RequestMetrics, method: http.Method) RegisterError!*Histogram {
        const mi = @intFromEnum(method);
        if (m.histograms[mi].load(.acquire)) |h| return h;
        const h = try m.registry.histogram(m.options.histogram_name, m.options.histogram_help, &.{
            .{ .name = "method", .value = @tagName(method) },
        }, m.options.buckets);
        m.histograms[mi].store(h, .release);
        return h;
    }
};

fn classLabel(class_index: usize) []const u8 {
    return switch (class_index) {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        else => "other",
    };
}

fn requestRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const m: *RequestMetrics = @ptrCast(@alignCast(state.?));
    const t0 = m.options.clock.now();
    m.in_flight.inc();
    defer m.in_flight.dec();

    const result = next.run(ctx);
    // On handler error the serving loop sends a clean 500 when nothing hit
    // the wire yet; when the head already went out, what was sent is what
    // the client saw.
    const status: u16 = if (result) |_|
        ctx.res.status
    else |_| if (ctx.res.headSent()) ctx.res.status else 500;
    const duration_ns = m.options.clock.now() -| t0;

    if (m.counterFor(ctx.req.method, status)) |c| c.inc() else |_| {}
    if (m.histogramFor(ctx.req.method)) |h| {
        h.observe(@as(f64, @floatFromInt(duration_ns)) / std.time.ns_per_s);
    } else |_| {}

    if (m.options.on_request) |hook| hook(m.options.on_request_ctx, .{
        .method = ctx.req.method,
        .path = ctx.req.path,
        .status = status,
        .duration_ns = duration_ns,
        .bytes = responseBytes(ctx.res),
    });
    return result;
}

/// Best-effort response body size for the access-log hook — see
/// `AccessEntry.bytes` for the exact contract.
fn responseBytes(res: *const http.Server.ResponseWriter) ?u64 {
    return switch (res.body) {
        // Handler done, nothing drained yet: the buffer holds the whole
        // body (a declared Content-Length is enforced against it at end()).
        .buffering => res.declared_len orelse res.interface.end,
        // Streaming against a declared length — enforced exact at end().
        .identity => res.declared_len.?,
        .discard => 0, // HEAD / 204 / 304: no body on the wire
        .chunked, .until_close => null, // streamed; no running total kept
    };
}

// ── tests: instrument semantics (offline) ───────────────────────────────────

const testing = std.testing;

test "counter: inc/add are monotonic and exact; get-or-register returns the same series" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();

    const c = try reg.counter("jobs_total", "Jobs.", &.{});
    try testing.expectEqual(0, c.value());
    c.inc();
    c.add(41);
    try testing.expectEqual(42, c.value());
    c.add(0); // no-op, still fine
    try testing.expectEqual(42, c.value());

    // Same name + same (empty) labels → the same instrument.
    const again = try reg.counter("jobs_total", "Jobs.", &.{});
    try testing.expectEqual(c, again);

    // Distinct label values → a distinct series in the same family.
    const other = try reg.counter("errs_total", "E.", &.{.{ .name = "kind", .value = "io" }});
    const other2 = try reg.counter("errs_total", "E.", &.{.{ .name = "kind", .value = "parse" }});
    try testing.expect(other != other2);
    other.inc();
    try testing.expectEqual(1, other.value());
    try testing.expectEqual(0, other2.value());
    // ...and the same value → the same series again.
    try testing.expectEqual(other, try reg.counter("errs_total", "E.", &.{.{ .name = "kind", .value = "io" }}));
}

test "gauge: set/inc/dec/add/sub go up and down" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();

    const g = try reg.gauge("depth", "Queue depth.", &.{});
    try testing.expectEqual(0, g.value());
    g.inc();
    g.inc();
    try testing.expectEqual(2, g.value());
    g.dec();
    try testing.expectEqual(1, g.value());
    g.set(-3.5);
    try testing.expectEqual(-3.5, g.value());
    g.add(0.5);
    try testing.expectEqual(-3, g.value());
    g.sub(1);
    try testing.expectEqual(-4, g.value());
}

test "histogram: cumulative buckets (le inclusive), _sum and _count" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();

    const h = try reg.histogram("lat", "L.", &.{}, &.{ 0.25, 0.5, 2 });
    h.observe(0.25); // == first bound → first bucket (le is inclusive)
    h.observe(0.5);
    h.observe(0.75);
    h.observe(8); // above every bound → only +Inf
    try testing.expectEqual(4, h.count());
    try testing.expectEqual(9.5, h.sum());
    try testing.expectEqual(1, h.cumulativeBucket(0)); // ≤ 0.25
    try testing.expectEqual(2, h.cumulativeBucket(1)); // ≤ 0.5
    try testing.expectEqual(3, h.cumulativeBucket(2)); // ≤ 2

    // Empty bucket list is legal: only +Inf / _sum / _count.
    const h2 = try reg.histogram("lat2", "L.", &.{}, &.{});
    h2.observe(1);
    try testing.expectEqual(1, h2.count());
}

test "registration: validation and mismatch errors" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();

    // Names.
    try testing.expectError(error.InvalidName, reg.counter("", "x", &.{}));
    try testing.expectError(error.InvalidName, reg.counter("1st", "x", &.{}));
    try testing.expectError(error.InvalidName, reg.counter("has space", "x", &.{}));
    try testing.expectError(error.InvalidName, reg.counter("sneaky{", "x", &.{}));
    _ = try reg.counter("ns:sub_total", "x", &.{}); // colon is legal

    // Label names.
    try testing.expectError(error.InvalidLabelName, reg.counter("a_total", "x", &.{.{ .name = "__res", .value = "v" }}));
    try testing.expectError(error.InvalidLabelName, reg.counter("a_total", "x", &.{.{ .name = "0bad", .value = "v" }}));
    try testing.expectError(error.InvalidLabelName, reg.histogram("h1", "x", &.{.{ .name = "le", .value = "v" }}, &.{}));
    _ = try reg.counter("a_total", "x", &.{.{ .name = "le", .value = "v" }}); // `le` fine on counters

    // Too many labels.
    const many: [max_labels + 1]Label = @splat(.{ .name = "l", .value = "v" });
    try testing.expectError(error.TooManyLabels, reg.counter("b_total", "x", &many));

    // Buckets.
    try testing.expectError(error.InvalidBuckets, reg.histogram("h2", "x", &.{}, &.{ 1, 1 }));
    try testing.expectError(error.InvalidBuckets, reg.histogram("h2", "x", &.{}, &.{ 2, 1 }));
    try testing.expectError(error.InvalidBuckets, reg.histogram("h2", "x", &.{}, &.{ 1, std.math.inf(f64) }));
    try testing.expectError(error.InvalidBuckets, reg.histogram("h2", "x", &.{}, &.{std.math.nan(f64)}));

    // Family consistency.
    _ = try reg.counter("c_total", "help one", &.{.{ .name = "k", .value = "a" }});
    try testing.expectError(error.WrongType, reg.gauge("c_total", "help one", &.{.{ .name = "k", .value = "a" }}));
    try testing.expectError(error.HelpMismatch, reg.counter("c_total", "help two", &.{.{ .name = "k", .value = "a" }}));
    try testing.expectError(error.LabelMismatch, reg.counter("c_total", "help one", &.{}));
    try testing.expectError(error.LabelMismatch, reg.counter("c_total", "help one", &.{.{ .name = "other", .value = "a" }}));
    _ = try reg.histogram("h3", "x", &.{}, &.{ 1, 2 });
    try testing.expectError(error.BucketsMismatch, reg.histogram("h3", "x", &.{}, &.{ 1, 3 }));
    try testing.expectError(error.BucketsMismatch, reg.histogram("h3", "x", &.{}, &.{1}));
}

test "registration copies its inputs (stack temporaries are safe)" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();

    var c1: *Counter = undefined;
    {
        var name_buf: [16]u8 = undefined;
        var val_buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "tmp_{d}_total", .{1});
        const val = try std.fmt.bufPrint(&val_buf, "v{d}", .{7});
        c1 = try reg.counter(name, "Tmp.", &.{.{ .name = "k", .value = val }});
        name_buf = @splat(0xAA); // scribble the caller's memory
        val_buf = @splat(0xAA);
    }
    c1.inc();
    // Lookup with fresh strings still finds the same series...
    try testing.expectEqual(c1, try reg.counter("tmp_1_total", "Tmp.", &.{.{ .name = "k", .value = "v7" }}));
    // ...and the exposition renders the copied (unscribbled) strings.
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try reg.writeText(&w);
    try testing.expectEqualStrings(
        \\# HELP tmp_1_total Tmp.
        \\# TYPE tmp_1_total counter
        \\tmp_1_total{k="v7"} 1
        \\
    , w.buffered());
}

// ── tests: exposition golden bytes ──────────────────────────────────────────

test "writeText: golden exact bytes (families, ordering, histogram, +Inf, escaping)" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();

    const c1 = try reg.counter("api_requests_total", "Total API requests.", &.{
        .{ .name = "method", .value = "get" },
        .{ .name = "code", .value = "2xx" },
    });
    c1.inc();
    c1.add(2);
    const c2 = try reg.counter("api_requests_total", "Total API requests.", &.{
        .{ .name = "method", .value = "post" },
        .{ .name = "code", .value = "5xx" },
    });
    c2.inc();

    // Escaping: backslash + newline in help; backslash, quote, newline in a
    // label value.
    const g = try reg.gauge("queue_depth", "Depth\nwith \\ inside.", &.{
        .{ .name = "q", .value = "a\\b\"c\nd" },
    });
    g.set(42);

    const h = try reg.histogram("req_seconds", "Request latency.", &.{
        .{ .name = "route", .value = "/x" },
    }, &.{ 0.25, 0.5, 2 });
    h.observe(0.25);
    h.observe(0.5);
    h.observe(0.75);
    h.observe(8);

    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try reg.writeText(&w);
    try testing.expectEqualStrings("# HELP api_requests_total Total API requests.\n" ++
        "# TYPE api_requests_total counter\n" ++
        "api_requests_total{method=\"get\",code=\"2xx\"} 3\n" ++
        "api_requests_total{method=\"post\",code=\"5xx\"} 1\n" ++
        "# HELP queue_depth Depth\\nwith \\\\ inside.\n" ++
        "# TYPE queue_depth gauge\n" ++
        "queue_depth{q=\"a\\\\b\\\"c\\nd\"} 42\n" ++
        "# HELP req_seconds Request latency.\n" ++
        "# TYPE req_seconds histogram\n" ++
        "req_seconds_bucket{route=\"/x\",le=\"0.25\"} 1\n" ++
        "req_seconds_bucket{route=\"/x\",le=\"0.5\"} 2\n" ++
        "req_seconds_bucket{route=\"/x\",le=\"2\"} 3\n" ++
        "req_seconds_bucket{route=\"/x\",le=\"+Inf\"} 4\n" ++
        "req_seconds_sum{route=\"/x\"} 9.5\n" ++
        "req_seconds_count{route=\"/x\"} 4\n", w.buffered());
}

test "writeText: empty registry emits nothing; unlabeled histogram gets bare le braces" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try reg.writeText(&w);
    try testing.expectEqualStrings("", w.buffered());

    const h = try reg.histogram("t_seconds", "T.", &.{}, &.{1});
    h.observe(0.5);
    w = .fixed(&buf);
    try reg.writeText(&w);
    try testing.expectEqualStrings("# HELP t_seconds T.\n" ++
        "# TYPE t_seconds histogram\n" ++
        "t_seconds_bucket{le=\"1\"} 1\n" ++
        "t_seconds_bucket{le=\"+Inf\"} 1\n" ++
        "t_seconds_sum 0.5\n" ++
        "t_seconds_count 1\n", w.buffered());
}

test "writeText: NaN observations poison _sum, land in +Inf only (client_golang)" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const h = try reg.histogram("n_seconds", "N.", &.{}, &.{1});
    h.observe(std.math.nan(f64));
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try reg.writeText(&w);
    try testing.expectEqualStrings("# HELP n_seconds N.\n" ++
        "# TYPE n_seconds histogram\n" ++
        "n_seconds_bucket{le=\"1\"} 0\n" ++
        "n_seconds_bucket{le=\"+Inf\"} 1\n" ++
        "n_seconds_sum NaN\n" ++
        "n_seconds_count 1\n", w.buffered());
}

// ── tests: multi-thread stress ──────────────────────────────────────────────

test "stress: shared counter/gauge/histogram across threads lose no updates" {
    const n_threads = 8;
    const iters = 10_000;

    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const c = try reg.counter("s_total", "S.", &.{});
    const g = try reg.gauge("s_depth", "S.", &.{});
    const h = try reg.histogram("s_seconds", "S.", &.{}, &.{ 0.5, 1 });

    const Worker = struct {
        fn run(ctr: *Counter, gau: *Gauge, hist: *Histogram) void {
            for (0..iters) |_| {
                ctr.inc();
                gau.inc();
                hist.observe(1.0); // == second bound (inclusive)
                gau.dec();
            }
        }
    };
    var handles: [n_threads]std.Thread = undefined;
    for (&handles) |*t| t.* = try std.Thread.spawn(.{}, Worker.run, .{ c, g, h });
    for (handles) |t| t.join();

    try testing.expectEqual(n_threads * iters, c.value());
    try testing.expectEqual(0, g.value()); // every inc paired with a dec
    try testing.expectEqual(n_threads * iters, h.count());
    // f64 sums of 1.0 are exact far beyond this magnitude.
    try testing.expectEqual(@as(f64, n_threads * iters), h.sum());
    try testing.expectEqual(0, h.cumulativeBucket(0)); // nothing ≤ 0.5
    try testing.expectEqual(n_threads * iters, h.cumulativeBucket(1));
}

test "stress: concurrent get-or-register converges on one series per label set" {
    const n_threads = 8;
    const iters = 2_000;

    var reg = Registry.init(testing.allocator);
    defer reg.deinit();

    const Worker = struct {
        fn run(r: *Registry, id: usize) void {
            for (0..iters) |_| {
                // Everyone hammers the same series...
                const c = r.counter("racy_total", "R.", &.{}) catch return;
                c.inc();
                // ...and each thread also its own labeled series.
                var buf: [8]u8 = undefined;
                const v = std.fmt.bufPrint(&buf, "{d}", .{id}) catch return;
                const own = r.counter("per_thread_total", "P.", &.{.{ .name = "t", .value = v }}) catch return;
                own.inc();
            }
        }
    };
    var handles: [n_threads]std.Thread = undefined;
    for (&handles, 0..) |*t, id| t.* = try std.Thread.spawn(.{}, Worker.run, .{ &reg, id });
    for (handles) |t| t.join();

    const c = try reg.counter("racy_total", "R.", &.{});
    try testing.expectEqual(n_threads * iters, c.value());
    for (0..n_threads) |id| {
        var buf: [8]u8 = undefined;
        const v = try std.fmt.bufPrint(&buf, "{d}", .{id});
        const own = try reg.counter("per_thread_total", "P.", &.{.{ .name = "t", .value = v }});
        try testing.expectEqual(iters, own.value());
    }
}

// ── tests: middleware + endpoint over the socket-free server codec ──────────

const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// Drive a router through `http.Server.serveStream` with canned wire bytes
/// (same harness as the router/throttle/cors tests).
fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [4096]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = r,
        .server_name = null, // keep goldens free of Server/Date noise
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn wire(comptime method: []const u8, comptime target: []const u8) []const u8 {
    return method ++ " " ++ target ++ " HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
}

fn expectStatus(got: []const u8, comptime status: []const u8) !void {
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 " ++ status));
}

fn expectHeaderLine(got: []const u8, comptime line: []const u8) !void {
    try testing.expect(std.mem.indexOf(u8, got, "\r\n" ++ line ++ "\r\n") != null);
}

fn bodyOf(got: []const u8) []const u8 {
    return got[std.mem.indexOf(u8, got, "\r\n\r\n").? + 4 ..];
}

fn expectBodyLine(got: []const u8, comptime line: []const u8) !void {
    const body = bodyOf(got);
    const found = std.mem.indexOf(u8, body, line ++ "\n") != null;
    if (!found) std.debug.print("missing \"{s}\" in exposition:\n{s}\n", .{ line, body });
    try testing.expect(found);
    // A full line match: preceded by start-of-body or a newline.
    const idx = std.mem.indexOf(u8, body, line ++ "\n").?;
    try testing.expect(idx == 0 or body[idx - 1] == '\n');
}

/// Deterministic clock: every `now()` advances by `step_ns`, so each
/// request (two reads: entry + exit) measures exactly `step_ns`.
const FakeClock = struct {
    now_ns: u64 = 0,
    step_ns: u64,

    fn nowFn(ctx: ?*anyopaque) u64 {
        const f: *FakeClock = @ptrCast(@alignCast(ctx.?));
        f.now_ns += f.step_ns;
        return f.now_ns;
    }
    fn clock(f: *FakeClock) Clock {
        return .{ .ctx = f, .nowFn = nowFn };
    }
};

fn hOk(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}
fn hCreated(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(201);
    try ctx.res.writeAll("created");
}
fn hMoved(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(301);
    try ctx.res.setHeader("Location", "/ok");
}
fn hBoom(_: *router.Ctx) anyerror!void {
    return error.Boom;
}
/// Proves the in-flight gauge is up *during* the request (ctx.state is the
/// RequestMetrics in these tests; a failed expectation → error → 500).
fn hInFlightProbe(ctx: *router.Ctx) anyerror!void {
    const m: *RequestMetrics = @ptrCast(@alignCast(ctx.state.?));
    try testing.expectEqual(1, m.in_flight.value());
    try ctx.res.writeAll("ok");
}

test "middleware: counts by method + status class, times with the injected clock" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var fake: FakeClock = .{ .step_ns = 5 * std.time.ns_per_ms }; // 5 ms/request
    var rm = try RequestMetrics.init(&reg, .{ .clock = fake.clock() });
    var ep: Endpoint = .{ .registry = &reg };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &rm;
    try r.use(ep.middleware()); // outermost: scrapes are NOT recorded
    try r.use(rm.middleware());
    try r.get("/ok", hInFlightProbe);
    try r.post("/ok", hCreated);
    try r.get("/moved", hMoved);
    try r.get("/boom", hBoom);

    var buf: [8192]u8 = undefined;
    try expectStatus(runWire(&r, wire("GET", "/ok"), &buf), "200"); // also proves in-flight == 1 inside
    try expectStatus(runWire(&r, wire("GET", "/ok"), &buf), "200");
    try expectStatus(runWire(&r, wire("POST", "/ok"), &buf), "201");
    try expectStatus(runWire(&r, wire("GET", "/moved"), &buf), "301");
    try expectStatus(runWire(&r, wire("GET", "/nope"), &buf), "404"); // router 404 runs inside the chain
    try expectStatus(runWire(&r, wire("PUT", "/ok"), &buf), "405"); // 405 too
    try expectStatus(runWire(&r, wire("GET", "/boom"), &buf), "500"); // handler error

    // Registry state, straight from the instruments.
    try testing.expectEqual(0, rm.in_flight.value());
    try testing.expectEqual(2, (try reg.counter("http_requests_total", rm.options.counter_help, &.{
        .{ .name = "method", .value = "get" }, .{ .name = "code", .value = "2xx" },
    })).value());

    // And through a scrape.
    const got = runWire(&r, wire("GET", "/metrics"), &buf);
    try expectStatus(got, "200");
    try expectHeaderLine(got, "Content-Type: " ++ content_type);
    try expectBodyLine(got, "http_requests_total{method=\"get\",code=\"2xx\"} 2");
    try expectBodyLine(got, "http_requests_total{method=\"post\",code=\"2xx\"} 1");
    try expectBodyLine(got, "http_requests_total{method=\"get\",code=\"3xx\"} 1");
    try expectBodyLine(got, "http_requests_total{method=\"get\",code=\"4xx\"} 1");
    try expectBodyLine(got, "http_requests_total{method=\"put\",code=\"4xx\"} 1");
    try expectBodyLine(got, "http_requests_total{method=\"get\",code=\"5xx\"} 1");
    // Latency: every request took exactly 5 ms on the fake clock → the
    // le="0.005" bucket (inclusive) holds them all.
    try expectBodyLine(got, "http_request_duration_seconds_bucket{method=\"get\",le=\"0.005\"} 5");
    try expectBodyLine(got, "http_request_duration_seconds_bucket{method=\"get\",le=\"+Inf\"} 5");
    try expectBodyLine(got, "http_request_duration_seconds_sum{method=\"get\"} 0.025");
    try expectBodyLine(got, "http_request_duration_seconds_count{method=\"get\"} 5");
    try expectBodyLine(got, "http_request_duration_seconds_count{method=\"post\"} 1");
    try expectBodyLine(got, "http_request_duration_seconds_count{method=\"put\"} 1");
    // In-flight is back at zero — and the scrape itself was not counted
    // (the whole http_requests_total family sums to 7).
    try expectBodyLine(got, "http_requests_in_flight 0");
    try testing.expect(std.mem.indexOf(u8, bodyOf(got), "/metrics") == null);
}

test "middleware: .code granularity uses exact status codes" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var rm = try RequestMetrics.init(&reg, .{ .status = .code });
    var ep: Endpoint = .{ .registry = &reg };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(ep.middleware());
    try r.use(rm.middleware());
    try r.get("/ok", hOk);
    try r.post("/ok", hCreated);

    var buf: [8192]u8 = undefined;
    try expectStatus(runWire(&r, wire("GET", "/ok"), &buf), "200");
    try expectStatus(runWire(&r, wire("POST", "/ok"), &buf), "201");
    try expectStatus(runWire(&r, wire("GET", "/nope"), &buf), "404");

    const got = runWire(&r, wire("GET", "/metrics"), &buf);
    try expectBodyLine(got, "http_requests_total{method=\"get\",code=\"200\"} 1");
    try expectBodyLine(got, "http_requests_total{method=\"post\",code=\"201\"} 1");
    try expectBodyLine(got, "http_requests_total{method=\"get\",code=\"404\"} 1");
}

test "middleware: custom names and buckets" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var fake: FakeClock = .{ .step_ns = 30 * std.time.ns_per_ms };
    var rm = try RequestMetrics.init(&reg, .{
        .counter_name = "api_requests_total",
        .histogram_name = "api_latency_seconds",
        .in_flight_name = "api_in_flight",
        .buckets = &.{ 0.01, 0.1 },
        .clock = fake.clock(),
    });
    var ep: Endpoint = .{ .registry = &reg };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(ep.middleware());
    try r.use(rm.middleware());
    try r.get("/ok", hOk);

    var buf: [8192]u8 = undefined;
    try expectStatus(runWire(&r, wire("GET", "/ok"), &buf), "200");
    const got = runWire(&r, wire("GET", "/metrics"), &buf);
    try expectBodyLine(got, "api_requests_total{method=\"get\",code=\"2xx\"} 1");
    try expectBodyLine(got, "api_latency_seconds_bucket{method=\"get\",le=\"0.01\"} 0"); // 30 ms > 10 ms
    try expectBodyLine(got, "api_latency_seconds_bucket{method=\"get\",le=\"0.1\"} 1");
    try expectBodyLine(got, "api_in_flight 0");

    // Bad configuration fails at init, not mid-request.
    try testing.expectError(error.InvalidName, RequestMetrics.init(&reg, .{ .counter_name = "no way" }));
    try testing.expectError(error.InvalidBuckets, RequestMetrics.init(&reg, .{ .buckets = &.{ 2, 1 } }));
}

const HookCapture = struct {
    entries: [8]struct {
        method: http.Method,
        path_buf: [64]u8,
        path_len: usize,
        status: u16,
        duration_ns: u64,
        bytes: ?u64,
    } = undefined,
    len: usize = 0,

    fn hook(ctx: ?*anyopaque, e: AccessEntry) void {
        const c: *HookCapture = @ptrCast(@alignCast(ctx.?));
        var slot = &c.entries[c.len];
        slot.method = e.method;
        @memcpy(slot.path_buf[0..e.path.len], e.path); // path is borrowed — copy
        slot.path_len = e.path.len;
        slot.status = e.status;
        slot.duration_ns = e.duration_ns;
        slot.bytes = e.bytes;
        c.len += 1;
    }
};

test "middleware: access-log hook gets method/path/status/duration/bytes" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var fake: FakeClock = .{ .step_ns = 7 * std.time.ns_per_ms };
    var capture: HookCapture = .{};
    var rm = try RequestMetrics.init(&reg, .{
        .clock = fake.clock(),
        .on_request = HookCapture.hook,
        .on_request_ctx = &capture,
    });

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(rm.middleware());
    try r.get("/ok", hOk);
    try r.get("/boom", hBoom);

    var buf: [4096]u8 = undefined;
    try expectStatus(runWire(&r, wire("GET", "/ok"), &buf), "200");
    try expectStatus(runWire(&r, wire("GET", "/boom"), &buf), "500");
    try expectStatus(runWire(&r, wire("HEAD", "/ok"), &buf), "200");

    try testing.expectEqual(3, capture.len);
    const e0 = &capture.entries[0];
    try testing.expectEqual(http.Method.get, e0.method);
    try testing.expectEqualStrings("/ok", e0.path_buf[0..e0.path_len]);
    try testing.expectEqual(200, e0.status);
    try testing.expectEqual(7 * std.time.ns_per_ms, e0.duration_ns);
    try testing.expectEqual(2, e0.bytes.?); // "ok" — buffered, exact

    const e1 = &capture.entries[1];
    try testing.expectEqual(500, e1.status); // handler error recorded as the 500 the server sends
    try testing.expectEqual(0, e1.bytes.?); // nothing written before the error

    const e2 = &capture.entries[2];
    try testing.expectEqual(http.Method.head, e2.method);
    try testing.expectEqual(200, e2.status);
    // HEAD keeps GET's buffered framing bytes observable (body never sent).
    try testing.expectEqual(2, e2.bytes.?);
}

test "endpoint: golden exposition response, HEAD framing, 405, pass-through" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const c = try reg.counter("t_total", "T.", &.{});
    c.inc();
    var ep: Endpoint = .{ .registry = &reg };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(ep.middleware());
    try r.get("/ok", hOk);

    var buf: [4096]u8 = undefined;
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 51\r\n" ++
        "\r\n" ++
        "# HELP t_total T.\n" ++
        "# TYPE t_total counter\n" ++
        "t_total 1\n", runWire(&r, wire("GET", "/metrics"), &buf));

    // HEAD: same framing, no body.
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 51\r\n" ++
        "\r\n", runWire(&r, wire("HEAD", "/metrics"), &buf));

    // Other methods on the path: 405 with Allow.
    const post = runWire(&r, wire("POST", "/metrics"), &buf);
    try expectStatus(post, "405");
    try expectHeaderLine(post, "Allow: GET, HEAD");

    // Other paths pass through untouched (routes and 404s).
    try testing.expectEqualStrings("ok", bodyOf(runWire(&r, wire("GET", "/ok"), &buf)));
    try expectStatus(runWire(&r, wire("GET", "/metricsX"), &buf), "404");

    // Custom path.
    var ep2: Endpoint = .{ .registry = &reg, .path = "/internal/metrics" };
    var r2 = router.Router.init(testing.allocator);
    defer r2.deinit();
    try r2.use(ep2.middleware());
    try r2.get("/ok", hOk);
    try expectStatus(runWire(&r2, wire("GET", "/internal/metrics"), &buf), "200");
    try expectStatus(runWire(&r2, wire("GET", "/metrics"), &buf), "404");
}

// ── tests: in-process integration (router + http.Server + http.Client) ──────

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

test "integration: request middleware + /metrics endpoint over loopback" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var rm = try RequestMetrics.init(&reg, .{});
    var ep: Endpoint = .{ .registry = &reg };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(ep.middleware()); // scrapes not counted
    try r.use(rm.middleware());
    try r.get("/ok", hOk);
    try r.post("/ok", hCreated);
    try r.get("/moved", hMoved);
    try r.get("/boom", hBoom);

    var server = http.Server.init(io, testing.allocator, .{
        .handler = r.handler(),
        .context = &r,
    });
    defer server.deinit();
    server.bind() catch |err| {
        std.debug.print("loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();
    const port = server.boundAddress().getPort();

    var client = http.Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;

    // Mixed-status traffic: 2× 200, 1× 201 (POST), 1× 301, 1× 404, 1× 500.
    const Shot = struct { method: http.Method, target: []const u8, expect: u16 };
    const shots = [_]Shot{
        .{ .method = .get, .target = "/ok", .expect = 200 },
        .{ .method = .get, .target = "/ok", .expect = 200 },
        .{ .method = .post, .target = "/ok", .expect = 201 },
        .{ .method = .get, .target = "/moved", .expect = 301 },
        .{ .method = .get, .target = "/nope", .expect = 404 },
        .{ .method = .get, .target = "/boom", .expect = 500 },
    };
    for (shots) |shot| {
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}{s}", .{ port, shot.target });
        var res = try client.request(shot.method, url, .{ .follow_redirects = false });
        defer res.deinit();
        try testing.expectEqual(shot.expect, res.status);
        const body = try res.readAllAlloc(testing.allocator, 4096);
        testing.allocator.free(body);
    }

    // Scrape and assert the whole picture.
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/metrics", .{port});
    var res = try client.request(.get, url, .{});
    defer res.deinit();
    try testing.expectEqual(200, res.status);
    try testing.expectEqualStrings(content_type, res.header("content-type").?);
    const body = try res.readAllAlloc(testing.allocator, 64 * 1024);
    defer testing.allocator.free(body);

    const expected_lines = [_][]const u8{
        // Request counter with the right per-class counts.
        "http_requests_total{method=\"get\",code=\"2xx\"} 2",
        "http_requests_total{method=\"post\",code=\"2xx\"} 1",
        "http_requests_total{method=\"get\",code=\"3xx\"} 1",
        "http_requests_total{method=\"get\",code=\"4xx\"} 1",
        "http_requests_total{method=\"get\",code=\"5xx\"} 1",
        // Latency histogram present with every request observed.
        "http_request_duration_seconds_bucket{method=\"get\",le=\"+Inf\"} 5",
        "http_request_duration_seconds_count{method=\"get\"} 5",
        "http_request_duration_seconds_count{method=\"post\"} 1",
        // In-flight back at zero.
        "http_requests_in_flight 0",
    };
    for (expected_lines) |line| {
        var pattern_buf: [128]u8 = undefined;
        const pattern = try std.fmt.bufPrint(&pattern_buf, "{s}\n", .{line});
        if (std.mem.indexOf(u8, body, pattern) == null) {
            std.debug.print("missing \"{s}\" in exposition:\n{s}\n", .{ line, body });
            try testing.expect(false);
        }
    }
    // The sum is real time, not a fake clock: positive and plausible.
    try testing.expect(std.mem.indexOf(u8, body, "http_request_duration_seconds_sum{method=\"get\"} ") != null);
    // TYPE lines once per family.
    try testing.expectEqual(1, std.mem.count(u8, body, "# TYPE http_requests_total counter"));
    try testing.expectEqual(1, std.mem.count(u8, body, "# TYPE http_request_duration_seconds histogram"));
    try testing.expectEqual(1, std.mem.count(u8, body, "# TYPE http_requests_in_flight gauge"));
}
