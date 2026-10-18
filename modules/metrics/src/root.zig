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
//!   slices are copied — callers may pass stack temporaries. `deinit` frees
//!   everything at once. On a request path with labels, register a family
//!   once with `counterVec`/`gaugeVec`/`histogramVec` and call `with(values)`
//!   (client_golang `WithLabelValues`): one hash lookup, no re-validation.
//!   `Vec.delete`/`reset` and `Registry.unregister` remove series.
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
//!   handler error), and an optional per-request hook (`on_request`) — the
//!   place to write an access log from, with the `accesslog` module (its
//!   `Sink` used to live here as `AccessLog`, removed 2026-10-06).
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
//! are a few string compares / adds. `writeText` holds the registry lock
//! only long enough to snapshot the family/children pointers (O(number of
//! families), not O(series)) and formats from that snapshot with the lock
//! released — registering a new family/child never has to wait for a
//! scrape's formatting to finish (audit F2, fixed 2026-09-15). Registration
//! is get-or-register, so steady-state request paths only *read* under the
//! lock-free caches and never register.

const std = @import("std");
const builtin = @import("builtin");
const testkit = @import("testkit");
const router = @import("router");
const http = @import("http");
const procnet = @import("procnet");
/// The streaming-quantile engine behind `Summary` (CKMS, perks-compatible).
const summary_mod = @import("summary.zig");
pub const SummaryOptions = summary_mod.Options;
pub const Objective = summary_mod.Objective;
pub const SummarySnapshot = summary_mod.Snapshot;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Prometheus registry (counter/gauge/histogram) + `/metrics` + request middleware with a per-request hook (access logging: `accesslog`)",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "posix",
    .targets = .{.linux64},
    .platform = .posix, // default latency clock uses the posix clock_gettime errno form
    .role = .util,
    // Internally synchronized: atomics for counter/gauge, documented
    // spinlocks for registration and histogram observe (see module doc).
    .concurrency = .threadsafe,
    .model_after = "Prometheus client_golang (registry/instrument semantics) + Prometheus text exposition format 0.0.4",
    .deps = .{ "router", "http", "procnet" },
};

const Allocator = std.mem.Allocator;

/// Spinlock acquire (std SmpAllocator pattern) — see the module doc for why
/// a spinlock and what it guards.
///
/// History: a yield was tried once before and measured worse on an 8-core box
/// with 8 contending threads, where there is no idle core for `sched_yield`
/// to hand off to (audit F2/F4 disposition), so the lock stayed a pure spin
/// and F2 (2026-09-15) and F4 (2026-09-16) were fixed by shrinking the
/// critical sections instead — `writeText` snapshots under the lock and
/// formats outside it, and the access-log writer that used to live here
/// (now `accesslog.Sink`) never held the lock across writer I/O. That measurement never had more threads than cores; the bounded spin
/// below is for that case, and the F4 bench is re-measured with it.
fn lockSpin(m: *std.atomic.Mutex) void {
    var spins: u32 = 0;
    while (!m.tryLock()) {
        if (spins < spin_before_yield) {
            spins += 1;
            std.atomic.spinLoopHint();
        } else {
            // ⚠ Bounded spin, then yield (2026-09-18). A pure spin is only
            // fair while every contender has a core: with more runnable
            // threads than cores, a waiter burns its whole time slice while
            // the holder is descheduled. Measured on the `AccessLog F4` (now `accesslog.Sink F4`)
            // test (8 threads x 400 lines x 3 rounds, ReleaseSafe): 0.7 s on
            // 8 or 2 cores, 49.8 s on 1 core -- and past its 3-minute limit
            // on the 4-core arm64 CI runner, which runs many test binaries
            // at once. The yield only starts after `spin_before_yield`
            // failed tries, so an uncontended or briefly held lock never
            // reaches it.
            std.Thread.yield() catch {};
        }
    }
}

/// Failed `tryLock`s `lockSpin` spins through before it starts yielding.
const spin_before_yield = 64;

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

/// One label pair. Values must be valid UTF-8 — checked at registration
/// (`RegisterError.InvalidUtf8`; closes the module's audit F6, where an
/// unvalidated value could make the exposition invalid UTF-8 despite its
/// own `charset=utf-8` `Content-Type`). Values are escaped at exposition
/// (`\`, `"` and newline). Names must match `[a-zA-Z_][a-zA-Z0-9_]*`, not
/// start with `__` (reserved by Prometheus), not repeat within one call,
/// and not be `le` (reserved for a histogram's own bucket bound —
/// `RegisterError.ReservedLabelName`, any instrument kind; audit F13).
/// Keep the *set of values* small and fixed — see the cardinality footgun
/// in the module doc.
pub const Label = struct {
    name: []const u8,
    value: []const u8,
};

/// Upper bound of labels per instrument — labels are a fixed small set by
/// design (cardinality), not a data channel.
pub const max_labels = 8;

// ── instruments ─────────────────────────────────────────────────────────────

// ── exemplars ───────────────────────────────────────────────────────────────

/// client_golang `ExemplarMaxRunes`: names + values of one exemplar's labels.
pub const max_exemplar_runes = 128;

pub const ExemplarError = error{
    /// A label name not matching `[a-zA-Z_][a-zA-Z0-9_]*`, repeated, a value
    /// that is not UTF-8, or more than `max_exemplar_runes` runes in all
    /// (client_golang panics on these).
    InvalidExemplar,
    OutOfMemory,
    /// The instrument was not created by a `Registry` (a bare `Counter{}`)
    /// and has no allocator for its exemplar storage.
    NoExemplarStorage,
};

/// Worst case of the rendered `{name="value",...}`: 128 runes of 4 bytes,
/// values escaped (x2), plus `="",` per pair and the braces.
const exemplar_text_cap = 2 + max_exemplar_runes * 4 * 2 + max_exemplar_runes * 4;

/// The last exemplar of one sample, its label block pre-rendered (escaped,
/// as OpenMetrics writes it). Guarded by its own spinlock.
const ExemplarSlot = struct {
    lock: std.atomic.Mutex = .unlocked,
    set: bool = false,
    len: u16 = 0,
    value: f64 = 0,
    timestamp_s: ?f64 = null,
    text: [exemplar_text_cap]u8 = undefined,

    fn store(slot: *ExemplarSlot, rendered: []const u8, value: f64, timestamp_s: ?f64) void {
        lockSpin(&slot.lock);
        defer slot.lock.unlock();
        @memcpy(slot.text[0..rendered.len], rendered);
        slot.len = @intCast(rendered.len);
        slot.value = value;
        slot.timestamp_s = timestamp_s;
        slot.set = true;
    }
};

/// Lazily allocated exemplar slots of one instrument: nothing until the
/// first `*WithExemplar` call, so instruments that never see one cost two
/// words. Freed with the series.
const Exemplars = struct {
    slots: std.atomic.Value(?[*]ExemplarSlot) = .init(null),
    gpa: ?Allocator = null,

    fn get(e: *Exemplars, n: usize) ExemplarError![*]ExemplarSlot {
        if (e.slots.load(.acquire)) |p| return p;
        const gpa = e.gpa orelse return error.NoExemplarStorage;
        const fresh = try gpa.alloc(ExemplarSlot, n);
        for (fresh) |*x| x.* = .{};
        if (e.slots.cmpxchgStrong(null, fresh.ptr, .acq_rel, .acquire)) |won| {
            gpa.free(fresh);
            return won.?;
        }
        return fresh.ptr;
    }

    fn slot(e: *const Exemplars, i: usize) ?*ExemplarSlot {
        const p = e.slots.load(.acquire) orelse return null;
        return &p[i];
    }

    fn free(e: *Exemplars, n: usize) void {
        if (e.slots.load(.acquire)) |p| e.gpa.?.free(p[0..n]);
    }
};

/// Validate and render exemplar labels as OpenMetrics writes them.
fn renderExemplarLabels(buf: *[exemplar_text_cap]u8, labels: []const Label) ExemplarError![]const u8 {
    var runes: usize = 0;
    for (labels, 0..) |l, i| {
        if (!validLabelName(l.name)) return error.InvalidExemplar;
        for (labels[0..i]) |prev| if (std.mem.eql(u8, prev.name, l.name)) return error.InvalidExemplar;
        if (!std.unicode.utf8ValidateSlice(l.value)) return error.InvalidExemplar;
        runes += l.name.len; // label names are ASCII
        runes += std.unicode.utf8CountCodepoints(l.value) catch return error.InvalidExemplar;
    }
    if (runes > max_exemplar_runes) return error.InvalidExemplar;
    var w: std.Io.Writer = .fixed(buf);
    w.writeByte('{') catch unreachable;
    for (labels, 0..) |l, i| {
        if (i != 0) w.writeByte(',') catch unreachable;
        w.print("{s}=\"", .{l.name}) catch unreachable;
        writeEscaped(&w, l.value, .label_value) catch unreachable;
        w.writeByte('"') catch unreachable;
    }
    w.writeByte('}') catch unreachable;
    return w.buffered();
}

/// Monotonic counter. Integer-valued (`u64`) — it can only go up, so
/// "never negative" holds by construction. Lock-free.
pub const Counter = struct {
    count: std.atomic.Value(u64) = .init(0),
    exemplars: Exemplars = .{},

    /// `add` plus an exemplar (client_golang `AddWithExemplar`): `labels`
    /// (e.g. `trace_id`) and an optional Unix timestamp in seconds — the
    /// module reads no clock; client_golang stamps `time.Now()`. Only the
    /// OpenMetrics exposition shows exemplars. The counter is NOT
    /// incremented when the exemplar is refused.
    pub fn addWithExemplar(c: *Counter, n: u64, labels: []const Label, timestamp_s: ?f64) ExemplarError!void {
        var buf: [exemplar_text_cap]u8 = undefined;
        const rendered = try renderExemplarLabels(&buf, labels);
        const slots = try c.exemplars.get(1);
        slots[0].store(rendered, @floatFromInt(n), timestamp_s);
        c.add(n);
    }

    pub fn incWithExemplar(c: *Counter, labels: []const Label, timestamp_s: ?f64) ExemplarError!void {
        return c.addWithExemplar(1, labels, timestamp_s);
    }

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

    /// Set the gauge to the current Unix time in seconds (client_golang
    /// `SetToCurrentTime`), read from the wall clock of `io` — the module
    /// keeps no hidden clock. Nanosecond resolution is kept in the fraction
    /// as far as an `f64` carries it (~microseconds at today's epoch).
    pub fn setToCurrentTime(g: *Gauge, io: std.Io) void {
        const ns: i96 = std.Io.Clock.real.now(io).nanoseconds;
        const s: i96 = @divFloor(ns, std.time.ns_per_s);
        const frac: i96 = ns - s * std.time.ns_per_s;
        g.set(@as(f64, @floatFromInt(s)) + @as(f64, @floatFromInt(frac)) / std.time.ns_per_s);
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
    /// One slot per bucket plus `+Inf`, allocated on first use.
    exemplars: Exemplars = .{},

    /// `observe` plus an exemplar on the bucket `v` lands in (client_golang
    /// `ObserveWithExemplar`); see `Counter.addWithExemplar`.
    pub fn observeWithExemplar(h: *Histogram, v: f64, labels: []const Label, timestamp_s: ?f64) ExemplarError!void {
        var buf: [exemplar_text_cap]u8 = undefined;
        const rendered = try renderExemplarLabels(&buf, labels);
        const slots = try h.exemplars.get(h.upper_bounds.len + 1);
        var i: usize = h.upper_bounds.len;
        for (h.upper_bounds, 0..) |bound, j| {
            if (v <= bound) {
                i = j;
                break;
            }
        }
        slots[i].store(rendered, v, timestamp_s);
        h.observe(v);
    }

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

/// Summary: `_sum`/`_count` plus quantiles over a sliding time window
/// (client_golang `Summary` with `Objectives`; the engine is
/// `summary_mod.Summary`). Time comes from the registry's `clock`, captured
/// when the series is created. Quantiles are NaN while the window is
/// empty. Prefer a `Histogram` when series must be aggregated across
/// instances — summaries' quantiles cannot be.
pub const Summary = struct {
    inner: summary_mod.Summary,
    clock: Clock,

    pub fn observe(s: *Summary, v: f64) void {
        s.inner.observe(v, s.clock.now());
    }

    /// Cumulative count / sum and the window's quantiles, in the family's
    /// objective order (ascending quantile).
    pub fn snapshot(s: *Summary, out_quantiles: []f64) SummarySnapshot {
        return s.inner.snapshot(s.clock.now(), out_quantiles);
    }
};

/// client_golang's objectives are what the caller passes; it has no
/// default (an empty map = only `_sum`/`_count`). This is the set its docs
/// suggest, for convenience.
pub const default_objectives = [_]Objective{
    .{ .quantile = 0.5, .epsilon = 0.05 },
    .{ .quantile = 0.9, .epsilon = 0.01 },
    .{ .quantile = 0.99, .epsilon = 0.001 },
};

/// Upper bound on a summary's objectives (each is a sample line per series
/// and a query per scrape).
pub const max_objectives = 16;

/// client_golang `DefBuckets` — latency-in-seconds defaults.
pub const default_buckets = [_]f64{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 };

// ── bucket helpers (client_golang LinearBuckets / ExponentialBuckets) ───────
//
// Shape: the comptime functions take comptime arguments and return a
// `[count]f64` array (pass `&arr` as `buckets`); client_golang panics on bad
// arguments, these are compile errors. The `fill*` functions are the
// runtime variants: they write into a caller-provided slice and return
// `error.InvalidBuckets` on the same bad arguments. Values are identical to
// Go's (the same repeated add / repeated multiply / `pow` formulas).

/// `count` buckets `start, start+width, ...` (client_golang `LinearBuckets`).
pub fn linearBuckets(comptime start: f64, comptime width: f64, comptime count: usize) [count]f64 {
    return comptime blk: {
        var out: [count]f64 = undefined;
        fillLinearBuckets(&out, start, width) catch @compileError("linearBuckets needs a positive count");
        break :blk out;
    };
}

/// Runtime `linearBuckets`: fills `out` (`out.len` = count);
/// `error.InvalidBuckets` when `out` is empty.
pub fn fillLinearBuckets(out: []f64, start: f64, width: f64) error{InvalidBuckets}!void {
    if (out.len < 1) return error.InvalidBuckets;
    var v = start;
    for (out) |*b| {
        b.* = v;
        v += width;
    }
}

/// `count` buckets `start, start*factor, ...` (client_golang
/// `ExponentialBuckets`). Compile error for `count < 1`, `start <= 0` or
/// `factor <= 1`.
pub fn exponentialBuckets(comptime start: f64, comptime factor: f64, comptime count: usize) [count]f64 {
    return comptime blk: {
        var out: [count]f64 = undefined;
        fillExponentialBuckets(&out, start, factor) catch
            @compileError("exponentialBuckets needs count >= 1, start > 0 and factor > 1");
        break :blk out;
    };
}

/// Runtime `exponentialBuckets`: fills `out`; `error.InvalidBuckets` for an
/// empty `out`, `start <= 0` or `factor <= 1` (also NaN).
pub fn fillExponentialBuckets(out: []f64, start: f64, factor: f64) error{InvalidBuckets}!void {
    if (out.len < 1 or !(start > 0) or !(factor > 1)) return error.InvalidBuckets;
    var v = start;
    for (out) |*b| {
        b.* = v;
        v *= factor;
    }
}

/// `count` buckets from `min` to `max` growing by a constant factor
/// (client_golang `ExponentialBucketsRange`). Compile error for
/// `count < 1`, `min <= 0` or `max < min`.
pub fn exponentialBucketsRange(comptime min: f64, comptime max: f64, comptime count: usize) [count]f64 {
    return comptime blk: {
        @setEvalBranchQuota(100_000);
        var out: [count]f64 = undefined;
        fillExponentialBucketsRange(&out, min, max) catch
            @compileError("exponentialBucketsRange needs count >= 1, min > 0 and max >= min");
        break :blk out;
    };
}

/// Runtime `exponentialBucketsRange`: fills `out`; `error.InvalidBuckets`
/// for an empty `out`, `min <= 0` or `max < min` (Go only rejects the first
/// two; `max < min` would give a descending, unregisterable list).
pub fn fillExponentialBucketsRange(out: []f64, min: f64, max: f64) error{InvalidBuckets}!void {
    if (out.len < 1 or !(min > 0) or !(max >= min)) return error.InvalidBuckets;
    if (out.len == 1) {
        out[0] = min;
        return;
    }
    const growth = std.math.pow(f64, max / min, 1.0 / @as(f64, @floatFromInt(out.len - 1)));
    for (out, 0..) |*b, i| {
        b.* = min * std.math.pow(f64, growth, @floatFromInt(i));
    }
}

// ── Timer (client_golang timer.go) ──────────────────────────────────────────

/// Measures a duration on an injected `Clock` and records it in seconds into
/// a `Histogram` (client_golang `NewTimer` + `ObserveDuration`).
///
/// ```zig
/// const t = metrics.Timer.start(.monotonic);
/// defer _ = t.observeDuration(hist);
/// ```
///
/// There is no `Summary` instrument in this module, so only `*Histogram` is
/// accepted; `elapsedNs` serves anything else.
pub const Timer = struct {
    clock: Clock,
    begin_ns: u64,

    pub fn start(clock: Clock) Timer {
        return .{ .clock = clock, .begin_ns = clock.now() };
    }

    /// Nanoseconds since `start` (saturating at 0 if the clock went back).
    pub fn elapsedNs(t: Timer) u64 {
        return t.clock.now() -| t.begin_ns;
    }

    /// Observe the elapsed time in seconds into `h`; returns the duration in
    /// nanoseconds. May be called repeatedly (each call observes again).
    pub fn observeDuration(t: Timer, h: *Histogram) u64 {
        const ns = t.elapsedNs();
        h.observe(@as(f64, @floatFromInt(ns)) / std.time.ns_per_s);
        return ns;
    }

    /// `observeDuration` into a `Summary`.
    pub fn observeDurationSummary(t: Timer, s: *Summary) u64 {
        const ns = t.elapsedNs();
        s.observe(@as(f64, @floatFromInt(ns)) / std.time.ns_per_s);
        return ns;
    }
};

// ── the registry ────────────────────────────────────────────────────────────

pub const RegisterError = error{
    OutOfMemory,
    /// Metric name must match `[a-zA-Z_:][a-zA-Z0-9_:]*`.
    InvalidName,
    /// Label name must match `[a-zA-Z_][a-zA-Z0-9_]*`, not start with the
    /// reserved `__`, and not repeat another label of the same call. (`le`
    /// is rejected too, but as `ReservedLabelName`, not this.)
    InvalidLabelName,
    /// The label name `le` (reserved for a histogram's own bucket bound) was
    /// passed as a caller-supplied label — on ANY instrument kind, as
    /// client_golang refuses it (audit F13: previously only rejected on
    /// histograms, which let a counter or gauge register a `le` label that
    /// then collided with a same-named histogram's own bucket samples — see
    /// F5). `quantile` used to be refused too, on the claim that
    /// client_golang does; it reserves it only for summaries, which this
    /// module does not have, and takes it on every other kind
    /// (`go_register_test.zig`, 2026-10-06) — so does this module now.
    ReservedLabelName,
    /// A label value or the HELP text is not valid UTF-8 (audit F6): the
    /// exposition format's `Content-Type` promises `charset=utf-8`, so this
    /// is checked once here rather than emitting bytes that break that
    /// promise on every scrape.
    InvalidUtf8,
    /// This family's derived sample names (a histogram's `<name>_bucket`/
    /// `_sum`/`_count`) collide with an existing family's name, or a new
    /// family's name collides with an existing histogram's derived names,
    /// in either registration order (audit F5). Prometheus's text-format
    /// parser rejects the WHOLE scrape on a duplicate (name, labels) sample
    /// or a repeated `# TYPE` line, so one misnamed counter can blind
    /// monitoring for every family in the registry, not just itself.
    NameCollision,
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
    /// Summary options out of range: a quantile outside [0, 1], an epsilon
    /// outside [0, 1), a repeated quantile, more than `max_objectives`,
    /// `age_buckets`/`buf_cap` 0, or a `max_age_ns` shorter than
    /// `age_buckets` ns.
    InvalidObjectives,
    /// The summary name is already registered with other options.
    ObjectivesMismatch,
    /// The name (or, for a callback, the exact series) is already taken in
    /// a way that cannot be shared: a `counterFunc`/`gaugeFunc` series
    /// registered twice, a callback family asked for an ordinary series
    /// (or the reverse), or a `registerCollector` name that already exists
    /// (client_golang `AlreadyRegisteredError`).
    AlreadyRegistered,
};

/// An instrument kind — what a family's `# TYPE` line says.
pub const Kind = enum { counter, gauge, histogram, summary };

/// A value read at scrape time (client_golang `CounterFunc`/`GaugeFunc`):
/// `f(ctx)` is called by every scrape, from the scraping thread — it must
/// be thread-safe and fast. `ctx` must stay valid until the registry's
/// `deinit`: a scrape that started before an `unregister`/`delete`/`reset`
/// of the series may still call `f(ctx)` after that returned.
pub const ValueFn = *const fn (ctx: ?*anyopaque) f64;

const Func = struct {
    ctx: ?*anyopaque,
    f: ValueFn,
};

const Instrument = union(enum) {
    counter: Counter,
    gauge: Gauge,
    histogram: Histogram,
    summary: Summary,
    counter_func: Func,
    gauge_func: Func,
};

/// One time series: a fixed label-value tuple + its instrument. Owned by the
/// registry's general-purpose allocator (not the arena) so `delete`/`reset`/
/// `unregister` can give it back; a removed child is freed only once no
/// scrape can still be formatting it (`Registry.retired`).
const Child = struct {
    /// Values in the family's label-name order.
    label_values: []const []const u8,
    data: Instrument,

    fn destroy(c: *Child, gpa: Allocator) void {
        for (c.label_values) |v| gpa.free(v);
        gpa.free(c.label_values);
        switch (c.data) {
            .histogram => |*h| {
                h.exemplars.free(h.upper_bounds.len + 1);
                gpa.free(h.bucket_counts);
            },
            .counter => |*ctr| ctr.exemplars.free(1),
            .summary => |*sm| sm.inner.deinit(),
            else => {},
        }
        gpa.destroy(c);
    }
};

/// Hash of a label-value tuple: each value length-prefixed, so ("ab","c")
/// and ("a","bc") differ.
fn hashValues(values: []const []const u8) u64 {
    var h = std.hash.Wyhash.init(0);
    for (values) |v| {
        h.update(std.mem.asBytes(&v.len));
        h.update(v);
    }
    return h.final();
}

fn eqlValues(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!std.mem.eql(u8, x, y)) return false;
    return true;
}

/// `Family.index` context: children keyed by their own label values.
const ChildContext = struct {
    pub fn hash(_: ChildContext, c: *Child) u64 {
        return hashValues(c.label_values);
    }
    pub fn eql(_: ChildContext, a: *Child, b: *Child) bool {
        return eqlValues(a.label_values, b.label_values);
    }
};

/// Adapter: look a child up by a caller's value tuple without building one.
const ValuesAdapter = struct {
    pub fn hash(_: ValuesAdapter, values: []const []const u8) u64 {
        return hashValues(values);
    }
    pub fn eql(_: ValuesAdapter, values: []const []const u8, c: *Child) bool {
        return eqlValues(values, c.label_values);
    }
};

/// One metric family: `# HELP`/`# TYPE` emitted once, then every child.
/// The family itself and its strings live in the arena; its child list and
/// index use the general-purpose allocator (they shrink).
const Family = struct {
    name: []const u8,
    help: []const u8,
    kind: Kind,
    /// Fixed label-name set (order matters; children match positionally).
    label_names: []const []const u8,
    /// Histogram families only, else empty.
    buckets: []const f64,
    /// Summary families only: options with objectives sorted by quantile
    /// (arena copy) — every series of the family shares them.
    summary_options: SummaryOptions = .{},
    /// Registration order (exposition order).
    children: std.ArrayList(*Child) = .empty,
    /// Every series is a `counterFunc`/`gaugeFunc` callback.
    funcs: bool = false,
    /// Set for a family a `Collector` emits (it then has no children).
    collector: ?*CollectorEntry = null,
    /// This family's position in its collector's `descs`.
    desc_index: usize = 0,
    /// Removed by `unregister`: a collector's samples for it are dropped.
    removed: bool = false,
    /// Series pointers into this family are held by a component that never
    /// lets go of them (`RequestMetrics`): `delete`/`reset`/`unregister`
    /// refuse it, as freeing those series would be a use-after-free.
    pinned: bool = false,
    /// Label values -> child: O(1) get on the request path (a linear scan
    /// with string compares was the whole 1.66x of the `counter_vec` bench
    /// row against client_golang's hashed `WithLabelValues`, 2026-10-17).
    index: std.HashMapUnmanaged(*Child, void, ChildContext, std.hash_map.default_max_load_percentage) = .empty,
};

/// Thread-safe metric registry — see the module doc. Instruments returned
/// by `counter`/`gauge`/`histogram` and the `*Vec.with` handles are stable
/// pointers, valid until `deinit` — or until their series is removed with
/// `delete`/`reset`/`unregister`, after which the pointer must not be used
/// (see `CounterVec.delete`). The Registry must outlive any Router its
/// middleware / endpoint is registered on, at a stable address.
pub const Registry = struct {
    arena: std.heap.ArenaAllocator,
    /// Guards `families`/`family_index`, every family's `children`/`index`,
    /// `scrape_seq`, `scrapes` and `retired`.
    lock: std.atomic.Mutex = .unlocked,
    /// Registration order — `writeText` iterates this so exposition order
    /// stays deterministic (registration order, not sorted; see `writeText`).
    families: std.ArrayList(*Family) = .empty,
    /// Name -> family, O(1) get-or-register lookup. `families` stays the
    /// source of iteration order; this is purely an index into it.
    family_index: std.StringHashMapUnmanaged(*Family) = .empty,
    /// Ticket of the next scrape; every running scrape holds a smaller one.
    scrape_seq: u64 = 0,
    /// Tickets of the scrapes between their snapshot and the end of
    /// formatting (a handful: one per concurrent scraper).
    scrapes: std.ArrayList(u64) = .empty,
    /// Children removed while a scrape ran, oldest first, each with the
    /// `scrape_seq` of its removal: only scrapes with a smaller ticket can
    /// hold it in their snapshot, so it is freed as soon as the last of
    /// THOSE ends — not when every scrape has ended, which scrapers that
    /// overlap without a gap would never let happen (review L5, 2026-10-18).
    retired: std.ArrayList(Retired) = .empty,
    /// Families removed by `unregister` (arena list; see there).
    orphaned: std.ArrayList(*Family) = .empty,
    /// Advisory size of the last `writeText` output, used to pre-size the
    /// next scrape's transient buffer so a steady-state registry (typical:
    /// scrape interval far exceeds registration churn) does not repeatedly
    /// double-and-copy that buffer mid-format. A stale or zero hint just
    /// falls back to `Allocating`'s normal grow-as-needed behavior — this
    /// changes only how much is pre-reserved, never what gets emitted.
    exposition_size_hint: std.atomic.Value(usize) = .init(0),
    /// The error of the last collector that failed a scrape (`@intFromError`,
    /// 0 = none yet); see `lastCollectorError`.
    collector_error: std.atomic.Value(u16) = .init(0),
    /// Time source for summaries' sliding windows, captured by each summary
    /// series when it is created — set it before registering summaries.
    clock: Clock = .monotonic,

    pub fn init(gpa: Allocator) Registry {
        return .{ .arena = std.heap.ArenaAllocator.init(gpa) };
    }

    const Retired = struct { child: *Child, at: u64 };

    pub fn deinit(r: *Registry) void {
        const gpa = r.arena.child_allocator;
        for (r.families.items) |fam| freeFamilyChildren(gpa, fam);
        for (r.orphaned.items) |fam| freeFamilyChildren(gpa, fam);
        for (r.retired.items) |e| e.child.destroy(gpa);
        r.retired.deinit(gpa);
        r.scrapes.deinit(gpa);
        r.arena.deinit();
        r.* = undefined;
    }

    fn freeFamilyChildren(gpa: Allocator, fam: *Family) void {
        for (fam.children.items) |c| c.destroy(gpa);
        fam.children.deinit(gpa);
        fam.index.deinit(gpa);
    }

    /// Get-or-register a counter time series. `name`/`help`/`labels` are
    /// copied — pass anything. Same (name, label values) → the same
    /// `*Counter` every time. On a hot path with labels, register a
    /// `counterVec` once and call `with` instead: this validates the whole
    /// descriptor on every call.
    pub fn counter(r: *Registry, name: []const u8, help: []const u8, labels: []const Label) RegisterError!*Counter {
        const child = try r.getOrRegister(name, help, .counter, labels, &.{}, .{});
        return &child.data.counter;
    }

    /// Get-or-register a gauge time series (see `counter`).
    pub fn gauge(r: *Registry, name: []const u8, help: []const u8, labels: []const Label) RegisterError!*Gauge {
        const child = try r.getOrRegister(name, help, .gauge, labels, &.{}, .{});
        return &child.data.gauge;
    }

    /// Get-or-register a histogram time series (see `counter`). `buckets`
    /// are the `le` upper bounds — finite, strictly increasing, `+Inf`
    /// implicit (may be empty = only `+Inf`); the whole family shares the
    /// first registration's buckets.
    pub fn histogram(r: *Registry, name: []const u8, help: []const u8, labels: []const Label, buckets: []const f64) RegisterError!*Histogram {
        const child = try r.getOrRegister(name, help, .histogram, labels, buckets, .{});
        return &child.data.histogram;
    }

    /// Get-or-register a counter FAMILY with label names `label_names` and
    /// no series yet (client_golang `NewCounterVec` + `Register`). A family
    /// with no series is not exposed. Registering the same descriptor again
    /// returns a handle to the same family.
    pub fn counterVec(r: *Registry, name: []const u8, help: []const u8, label_names: []const []const u8) RegisterError!CounterVec {
        return .{ .registry = r, .family = try r.getOrRegisterFamily(name, help, .counter, label_names, &.{}, .{}) };
    }

    /// Get-or-register a gauge family (see `counterVec`).
    pub fn gaugeVec(r: *Registry, name: []const u8, help: []const u8, label_names: []const []const u8) RegisterError!GaugeVec {
        return .{ .registry = r, .family = try r.getOrRegisterFamily(name, help, .gauge, label_names, &.{}, .{}) };
    }

    /// Get-or-register a histogram family (see `counterVec`, `histogram`).
    pub fn histogramVec(r: *Registry, name: []const u8, help: []const u8, label_names: []const []const u8, buckets: []const f64) RegisterError!HistogramVec {
        return .{ .registry = r, .family = try r.getOrRegisterFamily(name, help, .histogram, label_names, buckets, .{}) };
    }

    /// Get-or-register a summary series (client_golang `Summary`). The whole
    /// family shares the first registration's `options` (objectives are
    /// kept sorted by quantile); a later call with other options is
    /// `ObjectivesMismatch`. `quantile` is a reserved label name here.
    pub fn summary(r: *Registry, name: []const u8, help: []const u8, labels: []const Label, options: SummaryOptions) RegisterError!*Summary {
        const child = try r.getOrRegister(name, help, .summary, labels, &.{}, options);
        return &child.data.summary;
    }

    /// Get-or-register a summary family (see `counterVec`, `summary`).
    pub fn summaryVec(r: *Registry, name: []const u8, help: []const u8, label_names: []const []const u8, options: SummaryOptions) RegisterError!SummaryVec {
        return .{ .registry = r, .family = try r.getOrRegisterFamily(name, help, .summary, label_names, &.{}, options) };
    }

    /// Remove the family `name` and every series in it (client_golang
    /// `Unregister`). Returns whether it was removed — false when it does
    /// not exist or is pinned (a family `RequestMetrics` records into). Pointers into it must not
    /// be used afterwards; the name may be registered again, with any
    /// descriptor. The family's own strings stay in the arena until `deinit`
    /// (a few bytes per unregister).
    pub fn unregister(r: *Registry, name: []const u8) bool {
        lockSpin(&r.lock);
        defer r.lock.unlock();
        if (r.family_index.get(name)) |f| if (f.pinned) return false;
        const kv = r.family_index.fetchRemove(name) orelse return false;
        const fam = kv.value;
        @atomicStore(bool, &fam.removed, true, .monotonic);
        for (r.families.items, 0..) |f, i| if (f == fam) {
            _ = r.families.orderedRemove(i);
            break;
        };
        r.retireAllLocked(fam);
        // A `*Vec` handle may outlive this and keep adding series, as a
        // client_golang vec keeps working after `Unregister` (just never
        // collected again): the family stays allocated, off the exposition,
        // and `deinit` still frees what it accumulates.
        r.orphaned.append(r.arena.allocator(), fam) catch {};
        return true;
    }

    /// Register a counter series whose value `f(ctx)` reads at scrape time
    /// (client_golang `CounterFunc`) — e.g. a total kept by another
    /// component. The value must not decrease. The family may hold several
    /// callback series (one per label-value tuple) but no ordinary ones.
    pub fn counterFunc(r: *Registry, name: []const u8, help: []const u8, labels: []const Label, ctx: ?*anyopaque, f: ValueFn) RegisterError!void {
        return r.registerFunc(name, help, .counter, labels, .{ .counter_func = .{ .ctx = ctx, .f = f } });
    }

    /// Register a gauge series read at scrape time (client_golang
    /// `GaugeFunc`); see `counterFunc`.
    pub fn gaugeFunc(r: *Registry, name: []const u8, help: []const u8, labels: []const Label, ctx: ?*anyopaque, f: ValueFn) RegisterError!void {
        return r.registerFunc(name, help, .gauge, labels, .{ .gauge_func = .{ .ctx = ctx, .f = f } });
    }

    fn registerFunc(r: *Registry, name: []const u8, help: []const u8, kind: Kind, labels: []const Label, data: Instrument) RegisterError!void {
        if (labels.len > max_labels) return error.TooManyLabels;
        var names: [max_labels][]const u8 = undefined;
        var values: [max_labels][]const u8 = undefined;
        for (labels, 0..) |l, i| {
            names[i] = l.name;
            values[i] = l.value;
        }
        try validateDescriptor(name, help, kind, names[0..labels.len], &.{}, .{});
        for (values[0..labels.len]) |v| if (!std.unicode.utf8ValidateSlice(v)) return error.InvalidUtf8;
        lockSpin(&r.lock);
        defer r.lock.unlock();
        const fam = try r.familyLocked(name, help, kind, names[0..labels.len], &.{}, .{});
        if (fam.collector != null) return error.AlreadyRegistered;
        if (!fam.funcs and fam.children.items.len != 0) return error.AlreadyRegistered;
        if (fam.index.getKeyAdapted(@as([]const []const u8, values[0..labels.len]), ValuesAdapter{}) != null) return error.AlreadyRegistered;
        const gpa = r.arena.child_allocator;
        try fam.children.ensureUnusedCapacity(gpa, 1);
        try fam.index.ensureUnusedCapacityContext(gpa, 1, ChildContext{});
        const c = try gpa.create(Child);
        errdefer gpa.destroy(c);
        const owned = try gpa.alloc([]const u8, labels.len);
        errdefer gpa.free(owned);
        var done: usize = 0;
        errdefer for (owned[0..done]) |v| gpa.free(v);
        for (owned, values[0..labels.len]) |*slot, v| {
            slot.* = try gpa.dupe(u8, v);
            done += 1;
        }
        c.* = .{ .label_values = owned, .data = data };
        fam.funcs = true;
        fam.children.appendAssumeCapacity(c);
        fam.index.putAssumeCapacityNoClobberContext(c, {}, ChildContext{});
    }

    /// Register a `Collector`: the families it emits, described up front
    /// (client_golang `Collector.Describe`), and the callback that emits
    /// their samples on every scrape (`Collect`). Every name must be new
    /// (`AlreadyRegistered` otherwise) — a collector owns its families.
    /// They are exposed in `descs` order, at this point of the registration
    /// order. `collector.ctx` must outlive the registry.
    pub fn registerCollector(r: *Registry, descs: []const Desc, collector: Collector) RegisterError!void {
        for (descs, 0..) |d, i| {
            try validateDescriptor(d.name, d.help, d.kind, d.label_names, &.{}, .{});
            for (descs[0..i]) |prev| {
                if (std.mem.eql(u8, prev.name, d.name)) return error.AlreadyRegistered;
                if (derivedCollision(prev, d) or derivedCollision(d, prev)) return error.NameCollision;
            }
        }
        lockSpin(&r.lock);
        defer r.lock.unlock();
        for (descs) |d| {
            if (r.family_index.contains(d.name)) return error.AlreadyRegistered;
            try r.checkSuffixCollisionLocked(d.name, d.kind);
        }
        const a = r.arena.allocator();
        const entry = try a.create(CollectorEntry);
        entry.* = .{ .collector = collector, .families = try a.alloc(*Family, descs.len) };
        try r.families.ensureUnusedCapacity(a, descs.len);
        try r.family_index.ensureUnusedCapacity(a, @intCast(descs.len));
        for (descs, entry.families, 0..) |d, *slot, i| {
            const f = try a.create(Family);
            f.* = .{
                .name = try a.dupe(u8, d.name),
                .help = try a.dupe(u8, d.help),
                .kind = d.kind,
                .label_names = blk: {
                    const out = try a.alloc([]const u8, d.label_names.len);
                    for (out, d.label_names) |*o, ln| o.* = try a.dupe(u8, ln);
                    break :blk out;
                },
                .buckets = &.{},
                .collector = entry,
                .desc_index = i,
            };
            slot.* = f;
        }
        for (entry.families) |f| {
            r.families.appendAssumeCapacity(f);
            r.family_index.putAssumeCapacity(f.name, f);
        }
    }

    /// Why the last failed scrape failed in a collector: its own error, or a
    /// `Sink` error for samples the descriptions do not allow (`OutOfOrder`,
    /// `InvalidDesc`, ...), where `write` returns only `error.WriteFailed`
    /// (promhttp logs the cause through `ErrorLog`; this is the hook for a
    /// caller's log). Null until a collector has failed; not cleared by a
    /// later good scrape.
    pub fn lastCollectorError(r: *const Registry) ?anyerror {
        const v = r.collector_error.load(.monotonic);
        return if (v == 0) null else @errorFromInt(v);
    }

    /// Mark a family as pinned (see `Family.pinned`).
    fn pin(r: *Registry, name: []const u8) void {
        lockSpin(&r.lock);
        defer r.lock.unlock();
        if (r.family_index.get(name)) |f| f.pinned = true;
    }

    fn validateDescriptor(name: []const u8, help: []const u8, kind: Kind, label_names: []const []const u8, buckets: []const f64, sopts: SummaryOptions) RegisterError!void {
        if (!validMetricName(name)) return error.InvalidName;
        if (!std.unicode.utf8ValidateSlice(help)) return error.InvalidUtf8;
        if (label_names.len > max_labels) return error.TooManyLabels;
        for (label_names, 0..) |ln, i| {
            if (!validLabelName(ln)) return error.InvalidLabelName;
            // ⛔ A repeated label name was accepted and written as
            // `m{a="1",a="2"}`, which Prometheus refuses -- the whole scrape
            // with it. client_golang refuses the descriptor
            // (`go_register_test.zig`, 2026-10-06).
            for (label_names[0..i]) |prev| if (std.mem.eql(u8, prev, ln)) return error.InvalidLabelName;
            // `le` is reserved on every kind (F13) — see
            // `RegisterError.ReservedLabelName`.
            if (std.mem.eql(u8, ln, "le")) return error.ReservedLabelName;
            // client_golang reserves `quantile` on summaries only.
            if (kind == .summary and std.mem.eql(u8, ln, "quantile")) return error.ReservedLabelName;
        }
        if (kind == .summary) {
            if (sopts.objectives.len > max_objectives) return error.InvalidObjectives;
            if (sopts.age_buckets == 0 or sopts.buf_cap == 0) return error.InvalidObjectives;
            if (sopts.max_age_ns / sopts.age_buckets == 0) return error.InvalidObjectives;
            for (sopts.objectives, 0..) |o, i| {
                if (!(o.quantile >= 0 and o.quantile <= 1)) return error.InvalidObjectives;
                if (!(o.epsilon >= 0 and o.epsilon < 1)) return error.InvalidObjectives;
                for (sopts.objectives[0..i]) |prev| if (prev.quantile == o.quantile) return error.InvalidObjectives;
            }
        }
        if (kind == .histogram) {
            for (buckets, 0..) |b, i| {
                if (!std.math.isFinite(b)) return error.InvalidBuckets;
                if (i > 0 and b <= buckets[i - 1]) return error.InvalidBuckets;
            }
        }
    }

    /// The family for this descriptor, registered if new. Caller holds
    /// `r.lock`; the descriptor is already validated.
    fn familyLocked(r: *Registry, name: []const u8, help: []const u8, kind: Kind, label_names: []const []const u8, buckets: []const f64, sopts: SummaryOptions) RegisterError!*Family {
        const a = r.arena.allocator();
        const fam = if (r.family_index.get(name)) |f| f else blk: {
            try r.checkSuffixCollisionLocked(name, kind);
            const f = try a.create(Family);
            f.* = .{
                .name = try a.dupe(u8, name),
                .help = try a.dupe(u8, help),
                .kind = kind,
                .label_names = blk2: {
                    const out = try a.alloc([]const u8, label_names.len);
                    for (out, label_names) |*slot, ln| slot.* = try a.dupe(u8, ln);
                    break :blk2 out;
                },
                .buckets = if (kind == .histogram) try a.dupe(f64, buckets) else &.{},
                .summary_options = if (kind == .summary) blk2: {
                    var o = sopts;
                    const objs = try a.dupe(Objective, sopts.objectives);
                    std.mem.sort(Objective, objs, {}, struct {
                        fn lt(_: void, x: Objective, y: Objective) bool {
                            return x.quantile < y.quantile;
                        }
                    }.lt);
                    o.objectives = objs;
                    break :blk2 o;
                } else .{},
            };
            try r.families.append(a, f);
            try r.family_index.put(a, f.name, f);
            break :blk f;
        };

        if (fam.kind != kind) return error.WrongType;
        if (!std.mem.eql(u8, fam.help, help)) return error.HelpMismatch;
        if (fam.label_names.len != label_names.len) return error.LabelMismatch;
        for (fam.label_names, label_names) |have, want| {
            if (!std.mem.eql(u8, have, want)) return error.LabelMismatch;
        }
        if (kind == .histogram) {
            if (fam.buckets.len != buckets.len) return error.BucketsMismatch;
            for (fam.buckets, buckets) |fb, b| {
                if (fb != b) return error.BucketsMismatch;
            }
        }
        if (kind == .summary and !sameSummaryOptions(fam.summary_options, sopts)) return error.ObjectivesMismatch;
        return fam;
    }

    fn getOrRegisterFamily(r: *Registry, name: []const u8, help: []const u8, kind: Kind, label_names: []const []const u8, buckets: []const f64, sopts: SummaryOptions) RegisterError!*Family {
        try validateDescriptor(name, help, kind, label_names, buckets, sopts);
        lockSpin(&r.lock);
        defer r.lock.unlock();
        return r.familyLocked(name, help, kind, label_names, buckets, sopts);
    }

    fn getOrRegister(r: *Registry, name: []const u8, help: []const u8, kind: Kind, labels: []const Label, buckets: []const f64, sopts: SummaryOptions) RegisterError!*Child {
        if (labels.len > max_labels) return error.TooManyLabels;
        var names: [max_labels][]const u8 = undefined;
        var values: [max_labels][]const u8 = undefined;
        for (labels, 0..) |l, i| {
            names[i] = l.name;
            values[i] = l.value;
        }
        try validateDescriptor(name, help, kind, names[0..labels.len], buckets, sopts);
        // Checked before the family is touched, so a bad value never leaves
        // a new, empty family registered behind its error.
        for (values[0..labels.len]) |v| if (!std.unicode.utf8ValidateSlice(v)) return error.InvalidUtf8;
        lockSpin(&r.lock);
        defer r.lock.unlock();
        const fam = try r.familyLocked(name, help, kind, names[0..labels.len], buckets, sopts);
        return r.childLocked(fam, values[0..labels.len]);
    }

    /// The series for `values` in `fam`, created if new. Caller holds
    /// `r.lock`. Values are UTF-8-checked only on creation: a lookup hit
    /// matched a value that was checked when it was stored.
    fn childLocked(r: *Registry, fam: *Family, values: []const []const u8) RegisterError!*Child {
        if (fam.funcs or fam.collector != null) return error.AlreadyRegistered;
        if (values.len != fam.label_names.len) return error.LabelMismatch;
        const gpa = r.arena.child_allocator;
        if (fam.index.getKeyAdapted(values, ValuesAdapter{})) |c| return c;

        for (values) |v| if (!std.unicode.utf8ValidateSlice(v)) return error.InvalidUtf8;
        try fam.children.ensureUnusedCapacity(gpa, 1);
        try fam.index.ensureUnusedCapacityContext(gpa, 1, ChildContext{});

        const c = try gpa.create(Child);
        errdefer gpa.destroy(c);
        const owned = try gpa.alloc([]const u8, values.len);
        errdefer gpa.free(owned);
        var done: usize = 0;
        errdefer for (owned[0..done]) |v| gpa.free(v);
        for (owned, values) |*slot, v| {
            slot.* = try gpa.dupe(u8, v);
            done += 1;
        }
        c.* = .{
            .label_values = owned,
            .data = switch (fam.kind) {
                .counter => .{ .counter = .{ .exemplars = .{ .gpa = gpa } } },
                .gauge => .{ .gauge = .{} },
                .summary => .{
                    .summary = .{
                        .inner = summary_mod.Summary.init(gpa, fam.summary_options) catch |e| switch (e) {
                            error.OutOfMemory => return error.OutOfMemory,
                            // validated at registration
                            else => return error.InvalidObjectives,
                        },
                        .clock = r.clock,
                    },
                },
                .histogram => .{ .histogram = .{
                    .exemplars = .{ .gpa = gpa },
                    .upper_bounds = fam.buckets,
                    .bucket_counts = blk: {
                        const counts = try gpa.alloc(u64, fam.buckets.len);
                        @memset(counts, 0);
                        break :blk counts;
                    },
                } },
            },
        };
        fam.children.appendAssumeCapacity(c);
        fam.index.putAssumeCapacityNoClobberContext(c, {}, ChildContext{});
        return c;
    }

    /// Give a removed child back — now, or after the scrapes that may still
    /// hold it in their snapshot. Caller holds `r.lock`.
    fn retireLocked(r: *Registry, c: *Child) void {
        const gpa = r.arena.child_allocator;
        if (r.scrapes.items.len == 0) return c.destroy(gpa);
        // Out of memory for the parking list: leak the series rather than
        // free memory a scrape may be reading.
        r.retired.append(gpa, .{ .child = c, .at = r.scrape_seq }) catch {};
    }

    /// Free every parked child no running scrape can hold: those removed
    /// at or before the oldest running scrape's start. Caller holds `r.lock`.
    fn reapLocked(r: *Registry) void {
        const gpa = r.arena.child_allocator;
        var oldest: u64 = std.math.maxInt(u64);
        for (r.scrapes.items) |t| oldest = @min(oldest, t);
        var n: usize = 0;
        while (n < r.retired.items.len and r.retired.items[n].at <= oldest) : (n += 1)
            r.retired.items[n].child.destroy(gpa);
        r.retired.replaceRangeAssumeCapacity(0, n, &.{});
    }

    fn retireAllLocked(r: *Registry, fam: *Family) void {
        for (fam.children.items) |c| r.retireLocked(c);
        fam.children.clearRetainingCapacity();
        fam.index.clearRetainingCapacity();
    }

    fn deleteLocked(r: *Registry, fam: *Family, values: []const []const u8) bool {
        if (fam.pinned) return false;
        const kv = fam.index.fetchRemoveAdapted(values, ValuesAdapter{}) orelse return false;
        const c = kv.key;
        for (fam.children.items, 0..) |x, i| if (x == c) {
            _ = fam.children.orderedRemove(i);
            break;
        };
        r.retireLocked(c);
        return true;
    }

    /// F5: reject a family whose derived sample names would collide with an
    /// existing family, in either direction — a new histogram named `h`
    /// when `h_bucket`/`h_sum`/`h_count` already exists as its own family,
    /// or a new family literally named `h_bucket` (etc.) when `h` already
    /// exists as a histogram. Must run under `r.lock`, and only for a
    /// `name` not already in `family_index` — an existing family's own
    /// get-or-register re-lookup cannot newly collide with itself.
    ///
    /// Metric names longer than the scratch buffer skip the "new histogram
    /// vs. existing derived name" half of the check (the other half, "new
    /// name vs. existing histogram", has no such limit — it slices `name`
    /// itself, not a formatted copy). Prometheus/client_golang metric names
    /// are conventionally well under this; the alternative is an
    /// allocation on every histogram registration to guard a case this
    /// module has never seen.
    fn checkSuffixCollisionLocked(r: *Registry, name: []const u8, kind: Kind) RegisterError!void {
        const suffixes = [_][]const u8{ "_bucket", "_sum", "_count" };
        if (kind == .histogram) {
            var buf: [256]u8 = undefined;
            for (suffixes) |suf| {
                const derived = std.fmt.bufPrint(&buf, "{s}{s}", .{ name, suf }) catch continue;
                if (r.family_index.contains(derived)) return error.NameCollision;
            }
        }
        for (suffixes) |suf| {
            if (!std.mem.endsWith(u8, name, suf)) continue;
            const base = name[0 .. name.len - suf.len];
            if (r.family_index.get(base)) |f| {
                if (f.kind == .histogram) return error.NameCollision;
            }
        }
    }

    // ── exposition ──────────────────────────────────────────────────────

    /// One family's identity plus a snapshot of its children list, taken
    /// under `r.lock` and then formatted without it (see `writeText`).
    const FamilySnapshot = struct {
        fam: *Family,
        children: []const *Child,
    };

    /// Write the whole registry in the Prometheus text exposition format
    /// (version 0.0.4): per family `# HELP` (escaped) + `# TYPE`, then each
    /// series in registration order — counters/gauges as one sample,
    /// histograms as cumulative `_bucket{le=...}` lines (ending in
    /// `le="+Inf"`), `_sum` and `_count`. Deviation from client_golang: it
    /// sorts families by name and series by label values; we emit
    /// registration order (equally deterministic, no sort allocation —
    /// Prometheus does not require sorted input). Holds the registry lock
    /// only to snapshot family/children pointers, not for the formatting
    /// itself (see the F2 comment inside).
    pub fn writeText(r: *Registry, w: *std.Io.Writer) std.Io.Writer.Error!void {
        return r.write(w, .text);
    }

    /// Write the whole registry as OpenMetrics 1.0 text (client_golang's
    /// output with `EnableOpenMetrics`, byte for byte as prometheus/common
    /// `expfmt` writes it): a counter family named `x_total` is announced
    /// as `x` and its sample keeps `x_total` (one without the suffix is
    /// `unknown`), HELP escapes `"` too, values are OpenMetrics floats
    /// (`1.0`, `1e+06`), and the output ends in `# EOF`. No `_created`
    /// samples (client_golang's default) and no exemplars.
    pub fn writeOpenMetrics(r: *Registry, w: *std.Io.Writer) std.Io.Writer.Error!void {
        return r.write(w, .openmetrics);
    }

    /// `writeText` or `writeOpenMetrics`. A collector that fails, or emits
    /// samples its descriptions do not allow, fails the whole scrape with
    /// `error.WriteFailed` (promhttp's default `HTTPErrorOnError`); the
    /// collector's own error is kept for `lastCollectorError`.
    pub fn write(r: *Registry, w: *std.Io.Writer, format: Format) std.Io.Writer.Error!void {
        // Format the whole exposition into memory (no socket I/O), then
        // flush to the caller's writer OUTSIDE the lock, so a
        // slow/stalling scraper cannot stall first-touch series registration on
        // request threads (which contend for the same lock). An allocation
        // failure surfaces through the Allocating writer as `WriteFailed`.
        //
        // Pre-sized from the last scrape's length (F8 in the module's audit:
        // an unhinted buffer's geometric growth holds the old *and* new copy
        // across a resize, measured at 4.33x the exposition's own size in
        // transient peak memory). A correct hint makes that resize
        // unnecessary; a stale or missing one (first scrape) just grows
        // as before.
        var buf: std.Io.Writer.Allocating = std.Io.Writer.Allocating.initCapacity(
            r.arena.child_allocator,
            r.exposition_size_hint.load(.monotonic),
        ) catch .init(r.arena.child_allocator);
        defer buf.deinit();
        const bw = &buf.writer;

        // F2: hold `r.lock` only long enough to copy the family and series
        // POINTERS (one flat array, O(series) word copies), then format from
        // that copy with the lock released. Formatting used to run inside
        // this same critical section: measured at 3.7x the CPU under 8
        // concurrent scrapers, and the registry's own wall clock got worse
        // under load because `lockSpin` never yields (audit F2).
        //
        // The copy is of pointers, not of the lists' slice headers: since
        // `delete`/`reset`/`unregister` (2026-10-17) the child lists shrink
        // and reallocate. A series removed while this scrape formats is
        // parked in `retired` and freed once every scrape that started before
        // its removal has ended, so every pointer in the copy stays valid.
        // Reading a Counter/Gauge needs no lock (atomics) and a Histogram
        // takes its OWN `h.lock` in `writeHistogram`.
        const gpa = r.arena.child_allocator;
        var fams: []FamilySnapshot = &.{};
        var kids: []*Child = &.{};
        var ticket: u64 = undefined;
        {
            lockSpin(&r.lock);
            defer r.lock.unlock();
            r.scrapes.ensureUnusedCapacity(gpa, 1) catch return error.WriteFailed;
            var n_kids: usize = 0;
            for (r.families.items) |fam| n_kids += fam.children.items.len;
            fams = gpa.alloc(FamilySnapshot, r.families.items.len) catch return error.WriteFailed;
            kids = gpa.alloc(*Child, n_kids) catch {
                gpa.free(fams);
                return error.WriteFailed;
            };
            var at: usize = 0;
            for (r.families.items, fams) |fam, *slot| {
                const n = fam.children.items.len;
                @memcpy(kids[at..][0..n], fam.children.items);
                slot.* = .{ .fam = fam, .children = kids[at..][0..n] };
                at += n;
            }
            ticket = r.scrape_seq;
            r.scrape_seq += 1;
            r.scrapes.appendAssumeCapacity(ticket);
        }
        defer {
            lockSpin(&r.lock);
            const i = std.mem.indexOfScalar(u64, r.scrapes.items, ticket).?;
            _ = r.scrapes.swapRemove(i);
            r.reapLocked();
            r.lock.unlock();
            gpa.free(kids);
            gpa.free(fams);
        }

        var last_collector: ?*CollectorEntry = null;
        for (fams) |entry| {
            const fam = entry.fam;
            if (fam.collector) |ce| {
                // A collector's families are contiguous (registered in one
                // call); run it once, at its first family still registered.
                if (ce != last_collector) {
                    last_collector = ce;
                    var sink: Sink = .{ .w = bw, .entry = ce, .format = format };
                    ce.collector.collect(ce.collector.ctx, &sink) catch |e| {
                        r.collector_error.store(@intFromError(e), .monotonic);
                        return error.WriteFailed;
                    };
                }
                continue;
            }
            // client_golang does not expose a family with no series (a
            // fresh `*Vec`, or one emptied by `delete`/`reset`).
            if (entry.children.len == 0) continue;
            try writeHeader(bw, fam.name, fam.help, fam.kind, format);
            for (entry.children) |c| {
                switch (c.data) {
                    .counter => |*ctr| try writeSampleEx(bw, fam.name, "", fam.label_names, c.label_values, null, .{ .count = ctr.value() }, format, ctr.exemplars.slot(0)),
                    .counter_func => |f| try writeSample(bw, fam.name, "", fam.label_names, c.label_values, null, .{ .float = f.f(f.ctx) }, format),
                    .gauge => |*g| try writeSample(bw, fam.name, "", fam.label_names, c.label_values, null, .{ .float = g.value() }, format),
                    .gauge_func => |f| try writeSample(bw, fam.name, "", fam.label_names, c.label_values, null, .{ .float = f.f(f.ctx) }, format),
                    .histogram => |*h| try writeHistogram(bw, fam, c, h, format),
                    .summary => |*sm| try writeSummary(bw, fam, c, sm, format),
                }
            }
        }
        if (format == .openmetrics) try bw.writeAll("# EOF\n");
        r.exposition_size_hint.store(buf.written().len, .monotonic);
        try w.writeAll(buf.written());
    }

    /// Serve the exposition into a `ResponseWriter`: 200 + the Prometheus
    /// content type + `writeText`. The building block for a hand-written
    /// `/metrics` handler (fish the Registry out of your app state in
    /// `ctx.state`); `Endpoint` is the ready-made variant.
    pub fn respond(r: *Registry, res: *http.Server.ResponseWriter) anyerror!void {
        return r.respondFormat(res, .text);
    }

    /// `respond` in the given format, with its content type.
    pub fn respondFormat(r: *Registry, res: *http.Server.ResponseWriter, format: Format) anyerror!void {
        res.setStatus(200);
        try res.setHeader("Content-Type", format.contentType());
        try r.write(res.writer(), format);
    }
};

/// One family a `Collector` emits (client_golang `Desc`).
pub const Desc = struct {
    name: []const u8,
    help: []const u8,
    kind: Kind,
    label_names: []const []const u8 = &.{},
};

/// Samples computed at scrape time for families described up front — the
/// client_golang `Collector` (what its process and Go-runtime collectors
/// are). `collect` is called once per scrape from the scraping thread, with
/// the registry lock NOT held, and may run concurrently with itself on
/// concurrent scrapes: it must be thread-safe. It emits through `Sink`, in
/// `descs` order (a family's samples together; families may be skipped).
pub const Collector = struct {
    ctx: ?*anyopaque = null,
    collect: *const fn (ctx: ?*anyopaque, sink: *Sink) anyerror!void,
};

const CollectorEntry = struct {
    collector: Collector,
    /// One per `Desc`, in order.
    families: []*Family,
};

/// Where a `Collector` writes its samples during a scrape. `desc` is the
/// index into the `descs` given to `registerCollector`; `values` are in that
/// desc's label-name order. Each call checks what the registry checks at
/// registration (value count, UTF-8, kind, order) — a violation is an error
/// the collector should return, failing the scrape.
pub const Sink = struct {
    w: *std.Io.Writer,
    entry: *CollectorEntry,
    format: Format,
    /// The desc whose header was written last.
    current: ?usize = null,

    pub const Error = std.Io.Writer.Error || error{
        /// `desc` is out of range, or of another kind than the call.
        InvalidDesc,
        /// `desc` is before one already emitted (samples must come in
        /// `descs` order so each family's lines stay together).
        OutOfOrder,
        LabelMismatch,
        InvalidUtf8,
        /// Histogram bounds not finite and strictly increasing, counts not
        /// one per bound, or not cumulative.
        InvalidBuckets,
    };

    /// A counter sample (float, like client_golang's `MustNewConstMetric`
    /// with `CounterValue` — e.g. CPU seconds).
    pub fn counter(s: *Sink, desc: usize, values: []const []const u8, v: f64) Error!void {
        const fam = try s.begin(desc, .counter, values) orelse return;
        try writeSample(s.w, fam.name, "", fam.label_names, values, null, .{ .float = v }, s.format);
    }

    pub fn gauge(s: *Sink, desc: usize, values: []const []const u8, v: f64) Error!void {
        const fam = try s.begin(desc, .gauge, values) orelse return;
        try writeSample(s.w, fam.name, "", fam.label_names, values, null, .{ .float = v }, s.format);
    }

    /// A histogram sample from CUMULATIVE bucket counts (client_golang
    /// `MustNewConstHistogram`): `cumulative[i]` observations ≤
    /// `upper_bounds[i]`; `+Inf` is `count`.
    pub fn histogram(s: *Sink, desc: usize, values: []const []const u8, upper_bounds: []const f64, cumulative: []const u64, sum: f64, count: u64) Error!void {
        if (upper_bounds.len != cumulative.len) return error.InvalidBuckets;
        for (upper_bounds, cumulative, 0..) |b, c, i| {
            if (!std.math.isFinite(b)) return error.InvalidBuckets;
            if (i > 0 and (b <= upper_bounds[i - 1] or c < cumulative[i - 1])) return error.InvalidBuckets;
            if (c > count) return error.InvalidBuckets;
        }
        const fam = try s.begin(desc, .histogram, values) orelse return;
        for (upper_bounds, cumulative) |b, c| try writeSample(s.w, fam.name, "_bucket", fam.label_names, values, leLabel(b), .{ .count = c }, s.format);
        try writeSample(s.w, fam.name, "_bucket", fam.label_names, values, leLabel(std.math.inf(f64)), .{ .count = count }, s.format);
        try writeSample(s.w, fam.name, "_sum", fam.label_names, values, null, .{ .float = sum }, s.format);
        try writeSample(s.w, fam.name, "_count", fam.label_names, values, null, .{ .count = count }, s.format);
    }

    /// A summary sample (client_golang `MustNewConstSummary`): quantiles as
    /// (quantile, value) pairs in ascending quantile order.
    pub fn summary(s: *Sink, desc: usize, values: []const []const u8, quantiles: []const Objective, quantile_values: []const f64, sum: f64, count: u64) Error!void {
        if (quantiles.len != quantile_values.len) return error.InvalidBuckets;
        for (quantiles, 0..) |q, i| {
            if (!(q.quantile >= 0 and q.quantile <= 1)) return error.InvalidBuckets;
            if (i > 0 and q.quantile <= quantiles[i - 1].quantile) return error.InvalidBuckets;
        }
        const fam = try s.begin(desc, .summary, values) orelse return;
        try writeSummaryLines(s.w, fam.name, fam.label_names, values, quantiles, quantile_values, sum, count, s.format);
    }

    /// Validate one sample and write its family's header on first use;
    /// null = the family was unregistered, drop the sample.
    fn begin(s: *Sink, desc: usize, kind: Kind, values: []const []const u8) Error!?*Family {
        if (desc >= s.entry.families.len) return error.InvalidDesc;
        const fam = s.entry.families[desc];
        if (fam.kind != kind) return error.InvalidDesc;
        if (values.len != fam.label_names.len) return error.LabelMismatch;
        for (values) |v| if (!std.unicode.utf8ValidateSlice(v)) return error.InvalidUtf8;
        if (s.current) |cur| {
            if (desc < cur) return error.OutOfOrder;
        }
        // `removed` is written under the registry lock; a racing unregister
        // at worst lets this scrape include the family one last time.
        if (@atomicLoad(bool, &fam.removed, .monotonic)) return null;
        if (s.current != desc) {
            s.current = desc;
            try writeHeader(s.w, fam.name, fam.help, fam.kind, s.format);
        }
        return fam;
    }
};

/// client_golang's process collector (`NewProcessCollector`), Linux /proc
/// through `procnet`: the nine `process_*` families Prometheus dashboards
/// expect, same names, help, types and values (CPU and start time at
/// USER_HZ 100, resident memory at the runtime page size, an `unlimited`
/// limit as 2^64-1, network bytes from the process's own network namespace
/// — `/proc/<pid>/net/netstat` `IpExt`, as procfs reads it). A file that
/// cannot be read drops its families from that scrape, as client_golang does
/// without `ReportErrors`.
pub const ProcessCollector = struct {
    gpa: Allocator,
    io: std.Io,
    /// Which process: this one (the usual) or another pid.
    ref: procnet.ProcRef = .self,
    /// Boot time (`/proc/stat` `btime`), read once by `register`.
    btime: u64 = 0,

    const base = [_]struct { []const u8, []const u8, Kind }{
        .{ "process_cpu_seconds_total", "Total user and system CPU time spent in seconds.", .counter },
        .{ "process_max_fds", "Maximum number of open file descriptors.", .gauge },
        .{ "process_network_receive_bytes_total", "Number of bytes received by the process over the network.", .counter },
        .{ "process_network_transmit_bytes_total", "Number of bytes sent by the process over the network.", .counter },
        .{ "process_open_fds", "Number of open file descriptors.", .gauge },
        .{ "process_resident_memory_bytes", "Resident memory size in bytes.", .gauge },
        .{ "process_start_time_seconds", "Start time of the process since unix epoch in seconds.", .gauge },
        .{ "process_virtual_memory_bytes", "Virtual memory size in bytes.", .gauge },
        .{ "process_virtual_memory_max_bytes", "Maximum amount of virtual memory available in bytes.", .gauge },
    };
    const cpu = 0;
    const max_fds = 1;
    const net_rx = 2;
    const net_tx = 3;
    const open_fds = 4;
    const rss = 5;
    const start = 6;
    const vsize = 7;
    const vsize_max = 8;

    /// Register the families on `r`, prefixed `<namespace>_` when
    /// `namespace` is not empty (client_golang `Namespace`). `pc` must
    /// outlive the registry.
    pub fn register(pc: *ProcessCollector, r: *Registry, namespace: []const u8) RegisterError!void {
        if (procnet.readStat(pc.gpa, pc.io)) |st| {
            defer st.deinit(pc.gpa);
            pc.btime = st.btime; // 0 when /proc/stat is unreadable: no start-time sample then
        } else |err| return err;
        var bufs: [base.len][128]u8 = undefined;
        var descs: [base.len]Desc = undefined;
        for (base, &descs, &bufs) |b, *d, *buf| {
            const name = if (namespace.len == 0)
                b[0]
            else
                std.fmt.bufPrint(buf, "{s}_{s}", .{ namespace, b[0] }) catch return error.InvalidName;
            d.* = .{ .name = name, .help = b[1], .kind = b[2] };
        }
        return r.registerCollector(&descs, .{ .ctx = pc, .collect = collect });
    }

    fn collect(ctx: ?*anyopaque, sink: *Sink) anyerror!void {
        const pc: *ProcessCollector = @ptrCast(@alignCast(ctx.?));
        const stat = procnet.readPidStat(pc.io, pc.ref);
        const limits = procnet.readPidLimits(pc.io, pc.ref);
        const fds = procnet.countFds(pc.io, pc.ref);
        const net = try procnet.readPidNetstat(pc.gpa, pc.io, pc.ref);
        defer net.deinit(pc.gpa);
        const octets = net.ipExtOctets();

        const unlimited: f64 = @floatFromInt(std.math.maxInt(u64));
        if (stat) |s| try sink.counter(cpu, &.{}, s.cpuSeconds());
        if (limits) |l| try sink.gauge(max_fds, &.{}, if (l.maxOpenFiles()) |v| @floatFromInt(v) else unlimited);
        if (net.entries.len != 0) {
            try sink.counter(net_rx, &.{}, if (octets) |o| @floatFromInt(o.in) else 0);
            try sink.counter(net_tx, &.{}, if (octets) |o| @floatFromInt(o.out) else 0);
        }
        if (fds) |n| try sink.gauge(open_fds, &.{}, @floatFromInt(n));
        if (stat) |s| {
            try sink.gauge(rss, &.{}, @floatFromInt(s.residentBytesNow()));
            // Without a boot time the value would be ~1970, not a start time.
            if (pc.btime != 0) try sink.gauge(start, &.{}, s.startTimeSeconds(pc.btime));
            try sink.gauge(vsize, &.{}, @floatFromInt(s.vsize));
        }
        if (limits) |l| try sink.gauge(vsize_max, &.{}, if (l.maxAddressSpace()) |v| @floatFromInt(v) else unlimited);
    }
};

/// A handle to one registered family, for the request path: `with` finds
/// (or creates) the series for a label-value tuple with one hash lookup
/// under the registry lock — the descriptor was validated once, at
/// `counterVec`/`gaugeVec`/`histogramVec`. client_golang `*Vec`.
pub fn Vec(comptime kind: Kind) type {
    return struct {
        const Self = @This();
        pub const Metric = switch (kind) {
            .counter => Counter,
            .gauge => Gauge,
            .histogram => Histogram,
            .summary => Summary,
        };

        registry: *Registry,
        family: *Family,

        /// The series for `values` (in the family's label-name order),
        /// created on first use (client_golang `GetMetricWithLabelValues`).
        /// `error.LabelMismatch` for a wrong value count,
        /// `error.InvalidUtf8` for a value that is not UTF-8.
        pub fn with(v: Self, values: []const []const u8) RegisterError!*Metric {
            lockSpin(&v.registry.lock);
            defer v.registry.lock.unlock();
            const c = try v.registry.childLocked(v.family, values);
            return &@field(c.data, @tagName(kind));
        }

        /// Remove the series for `values`; returns whether it was removed
        /// (client_golang `DeleteLabelValues`) — false when absent or the
        /// family is pinned (see `Registry.unregister`). ⚠ Unlike Go, the series'
        /// memory is given back: a pointer from `with` for these values must
        /// not be used after this returns (a later `with` creates a fresh,
        /// zeroed series). A scrape running concurrently is safe — the
        /// series is freed once it has finished.
        pub fn delete(v: Self, values: []const []const u8) bool {
            lockSpin(&v.registry.lock);
            defer v.registry.lock.unlock();
            return v.registry.deleteLocked(v.family, values);
        }

        /// Remove every series of the family (client_golang `Reset`); the
        /// family stays registered. Same pointer rule as `delete`. Returns
        /// false (and removes nothing) for a pinned family.
        pub fn reset(v: Self) bool {
            lockSpin(&v.registry.lock);
            defer v.registry.lock.unlock();
            if (v.family.pinned) return false;
            v.registry.retireAllLocked(v.family);
            return true;
        }

        /// Number of series currently in the family.
        pub fn len(v: Self) usize {
            lockSpin(&v.registry.lock);
            defer v.registry.lock.unlock();
            return v.family.children.items.len;
        }
    };
}

pub const CounterVec = Vec(.counter);
pub const GaugeVec = Vec(.gauge);
pub const HistogramVec = Vec(.histogram);
pub const SummaryVec = Vec(.summary);

/// Whether `h` (a histogram or summary) would emit a sample named like `x`.
fn derivedCollision(h: Desc, x: Desc) bool {
    if (h.kind != .histogram and h.kind != .summary) return false;
    const suffixes = [_][]const u8{ "_bucket", "_sum", "_count" };
    for (suffixes) |suf| {
        if (x.name.len == h.name.len + suf.len and std.mem.startsWith(u8, x.name, h.name) and std.mem.endsWith(u8, x.name, suf)) return true;
    }
    return false;
}

/// Same summary options, objectives compared as a set (`have` is sorted).
fn sameSummaryOptions(have: SummaryOptions, want: SummaryOptions) bool {
    if (have.max_age_ns != want.max_age_ns or have.age_buckets != want.age_buckets or have.buf_cap != want.buf_cap) return false;
    if (have.objectives.len != want.objectives.len) return false;
    for (want.objectives) |w| {
        for (have.objectives) |h| {
            if (h.quantile == w.quantile and h.epsilon == w.epsilon) break;
        } else return false;
    }
    return true;
}

/// The scrape Content-Type for text format 0.0.4 (what promhttp sends).
pub const content_type = "text/plain; version=0.0.4; charset=utf-8";

/// Exposition format (client_golang promhttp's two text formats).
pub const Format = enum {
    /// Prometheus text format 0.0.4 — what promhttp serves by default.
    text,
    /// OpenMetrics 1.0 text — what promhttp serves with `EnableOpenMetrics`
    /// to a scraper that asks for it (`Accept`), as Prometheus does.
    openmetrics,

    pub fn contentType(f: Format) []const u8 {
        return switch (f) {
            .text => content_type,
            .openmetrics => content_type_openmetrics,
        };
    }

    /// The format to answer a request with, as prometheus/common `expfmt`
    /// `NegotiateIncludingOpenMetrics` decides it among the formats this
    /// module writes: `Accept` clauses by descending `q` (ties: a concrete
    /// type before `*`), the first that matches OpenMetrics 1.0.0, OpenMetrics
    /// 0.0.1 (written as 1.0.0) or text 0.0.4 wins; nothing → text. Only the
    /// `version` parameter is compared (a missing one defaults to 0.0.1 for
    /// OpenMetrics, 0.0.4 for text); others — Prometheus 3's `escaping=` —
    /// are ignored, as expfmt does. Deviation: a `q=0` clause is skipped
    /// (RFC 9110 "not acceptable"; expfmt still matches it, last).
    pub fn negotiate(accept: []const u8) Format {
        var buf: [32]http.conneg.MediaRange = undefined;
        const ranges = http.conneg.parse(accept, &buf);
        std.sort.insertion(http.conneg.MediaRange, ranges, {}, struct {
            fn lt(_: void, a: http.conneg.MediaRange, b: http.conneg.MediaRange) bool {
                if (a.weight != b.weight) return a.weight > b.weight;
                const a_rank = @as(u2, @intFromBool(!std.mem.eql(u8, a.type, "*"))) + @intFromBool(!std.mem.eql(u8, a.subtype, "*"));
                const b_rank = @as(u2, @intFromBool(!std.mem.eql(u8, b.type, "*"))) + @intFromBool(!std.mem.eql(u8, b.subtype, "*"));
                return a_rank > b_rank;
            }
        }.lt);
        for (ranges) |r| {
            if (r.weight == 0) continue;
            if (acceptMatches(r, "application", "openmetrics-text", "1.0.0")) return .openmetrics;
            if (acceptMatches(r, "application", "openmetrics-text", "0.0.1")) return .openmetrics;
            if (acceptMatches(r, "text", "plain", "0.0.4")) return .text;
        }
        return .text;
    }

    /// expfmt `matchFormat` for one offer.
    fn acceptMatches(r: http.conneg.MediaRange, type_: []const u8, subtype: []const u8, version: []const u8) bool {
        if (!r.matches(type_, subtype)) return false;
        const exact_om = std.ascii.eqlIgnoreCase(r.type, "application") and std.ascii.eqlIgnoreCase(r.subtype, "openmetrics-text");
        const exact_text = std.ascii.eqlIgnoreCase(r.type, "text") and std.ascii.eqlIgnoreCase(r.subtype, "plain");
        const have = r.param("version") orelse
            (if (exact_om) "0.0.1" else if (exact_text) "0.0.4" else "");
        return std.mem.eql(u8, have, version);
    }
};

/// The scrape Content-Type for OpenMetrics 1.0 (what promhttp sends).
pub const content_type_openmetrics = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// The family name `# HELP`/`# TYPE` announce: OpenMetrics drops a
/// counter's `_total` (expfmt).
fn announcedName(name: []const u8, kind: Kind, format: Format) []const u8 {
    if (format == .openmetrics and kind == .counter and std.mem.endsWith(u8, name, "_total"))
        return name[0 .. name.len - "_total".len];
    return name;
}

fn writeHeader(w: *std.Io.Writer, name: []const u8, help: []const u8, kind: Kind, format: Format) std.Io.Writer.Error!void {
    const announced = announcedName(name, kind, format);
    try w.print("# HELP {s} ", .{announced});
    switch (format) {
        .text => try writeEscaped(w, help, .help),
        .openmetrics => try writeEscaped(w, help, .label_value),
    }
    const type_word: []const u8 = switch (kind) {
        // expfmt: a counter without the `_total` suffix is `unknown`.
        .counter => if (format == .openmetrics and !std.mem.endsWith(u8, name, "_total")) "unknown" else "counter",
        .gauge => "gauge",
        .histogram => "histogram",
        .summary => "summary",
    };
    try w.print("\n# TYPE {s} {s}\n", .{ announced, type_word });
}

const SampleValue = union(enum) {
    /// An integer count (`_count`, `_bucket`, a `Counter`).
    count: u64,
    float: f64,
};

/// A label with a float value appended after the series' own labels:
/// a histogram's `le`, a summary's `quantile`.
const ExtraLabel = struct { name: []const u8, value: f64 };

fn leLabel(bound: f64) ExtraLabel {
    return .{ .name = "le", .value = bound };
}

/// One sample line: `<name><suffix>{labels[,extra]} <value>`.
fn writeSample(w: *std.Io.Writer, name: []const u8, suffix: []const u8, label_names: []const []const u8, label_values: []const []const u8, extra: ?ExtraLabel, value: SampleValue, format: Format) std.Io.Writer.Error!void {
    return writeSampleEx(w, name, suffix, label_names, label_values, extra, value, format, null);
}

/// `writeSample` with the sample's exemplar slot: OpenMetrics appends
/// ` # {labels} value [timestamp]` (expfmt `writeExemplar`); the text
/// format has no exemplars.
fn writeSampleEx(w: *std.Io.Writer, name: []const u8, suffix: []const u8, label_names: []const []const u8, label_values: []const []const u8, extra: ?ExtraLabel, value: SampleValue, format: Format, exemplar: ?*ExemplarSlot) std.Io.Writer.Error!void {
    try w.writeAll(name);
    try w.writeAll(suffix);
    try writeLabels(w, label_names, label_values, extra, format);
    try w.writeByte(' ');
    switch (value) {
        // expfmt writes a counter's value as a float in OpenMetrics, and
        // `_count`/`_bucket` as integers in both formats.
        .count => |n| if (format == .openmetrics and suffix.len == 0)
            try writeOpenMetricsFloat(w, @floatFromInt(n))
        else
            try w.print("{d}", .{n}),
        .float => |v| switch (format) {
            .text => try writeFloat(w, v),
            .openmetrics => try writeOpenMetricsFloat(w, v),
        },
    }
    if (format == .openmetrics) if (exemplar) |slot| {
        lockSpin(&slot.lock);
        defer slot.lock.unlock();
        if (slot.set) {
            try w.writeAll(" # ");
            try w.writeAll(slot.text[0..slot.len]);
            try w.writeByte(' ');
            try writeOpenMetricsFloat(w, slot.value);
            if (slot.timestamp_s) |ts| {
                try w.writeByte(' ');
                try writeOpenMetricsFloat(w, ts);
            }
        }
    };
    try w.writeByte('\n');
}

fn writeHistogram(w: *std.Io.Writer, fam: *const Family, c: *const Child, h: *Histogram, format: Format) std.Io.Writer.Error!void {
    // Snapshot + emit under the instrument lock: buckets/count/sum must be
    // one consistent observation set (the writer usually buffers, so the
    // critical section is memory-speed formatting).
    lockSpin(&h.lock);
    defer h.lock.unlock();
    var cumulative: u64 = 0;
    for (h.upper_bounds, h.bucket_counts, 0..) |bound, n, i| {
        cumulative += n;
        try writeSampleEx(w, fam.name, "_bucket", fam.label_names, c.label_values, leLabel(bound), .{ .count = cumulative }, format, h.exemplars.slot(i));
    }
    try writeSampleEx(w, fam.name, "_bucket", fam.label_names, c.label_values, leLabel(std.math.inf(f64)), .{ .count = h.observation_count }, format, h.exemplars.slot(h.upper_bounds.len));
    try writeSample(w, fam.name, "_sum", fam.label_names, c.label_values, null, .{ .float = h.observation_sum }, format);
    try writeSample(w, fam.name, "_count", fam.label_names, c.label_values, null, .{ .count = h.observation_count }, format);
}

fn writeSummary(w: *std.Io.Writer, fam: *const Family, c: *const Child, sm: *Summary, format: Format) std.Io.Writer.Error!void {
    var qs: [max_objectives]f64 = undefined;
    const objs = fam.summary_options.objectives;
    const snap = sm.snapshot(qs[0..objs.len]);
    try writeSummaryLines(w, fam.name, fam.label_names, c.label_values, objs, qs[0..objs.len], snap.sum, snap.count, format);
}

fn writeSummaryLines(w: *std.Io.Writer, name: []const u8, label_names: []const []const u8, values: []const []const u8, objs: []const Objective, qs: []const f64, sum: f64, count: u64, format: Format) std.Io.Writer.Error!void {
    for (objs, qs) |o, v| try writeSample(w, name, "", label_names, values, .{ .name = "quantile", .value = o.quantile }, .{ .float = v }, format);
    try writeSample(w, name, "_sum", label_names, values, null, .{ .float = sum }, format);
    try writeSample(w, name, "_count", label_names, values, null, .{ .count = count }, format);
}

/// Emit `{name="value",...}` (nothing when empty), appending `extra`.
fn writeLabels(w: *std.Io.Writer, names: []const []const u8, values: []const []const u8, extra: ?ExtraLabel, format: Format) std.Io.Writer.Error!void {
    if (names.len == 0 and extra == null) return;
    try w.writeByte('{');
    for (names, values, 0..) |n, v, i| {
        if (i != 0) try w.writeByte(',');
        try w.print("{s}=\"", .{n});
        try writeEscaped(w, v, .label_value);
        try w.writeByte('"');
    }
    if (extra) |x| {
        if (names.len != 0) try w.writeByte(',');
        try w.print("{s}=\"", .{x.name});
        switch (format) {
            .text => try writeFloat(w, x.value),
            .openmetrics => try writeOpenMetricsFloat(w, x.value),
        }
        try w.writeByte('"');
    }
    try w.writeByte('}');
}

/// Text-format escaping: HELP text escapes `\` and newline; label values
/// (and OpenMetrics HELP) additionally escape `"` (both per the spec).
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

/// Sample/bound rendering in the text format, as expfmt writes it: the
/// spec's spellings for the specials (`+Inf` / `-Inf` / `NaN`), otherwise
/// Go's shortest `%g` (`goShortestG`: `1.2345675e+06`, `1e-05`, `0.5`).
/// (Before 2026-10-17 this was Zig's `{d}`, always decimal — it parsed the
/// same, but the bytes differed from client_golang's.)
fn writeFloat(w: *std.Io.Writer, v: f64) std.Io.Writer.Error!void {
    if (std.math.isNan(v)) return w.writeAll("NaN");
    if (std.math.isInf(v)) return w.writeAll(if (v > 0) "+Inf" else "-Inf");
    if (v == 0) return w.writeAll("0"); // -0 too, as expfmt (`f == 0`)
    var buf: [64]u8 = undefined;
    try w.writeAll(goShortestG(&buf, v));
}

/// expfmt's `writeOpenMetricsFloat`, byte for byte: `1.0`/`0.0`/`-1.0`,
/// the specials, otherwise Go's `strconv.FormatFloat(f, 'g', -1, 64)`
/// (`goShortestG`) with `.0` appended when that has neither `.` nor `e`.
fn writeOpenMetricsFloat(w: *std.Io.Writer, v: f64) std.Io.Writer.Error!void {
    if (v == 1) return w.writeAll("1.0");
    if (v == 0) return w.writeAll("0.0");
    if (v == -1) return w.writeAll("-1.0");
    if (std.math.isNan(v)) return w.writeAll("NaN");
    if (std.math.isInf(v)) return w.writeAll(if (v > 0) "+Inf" else "-Inf");
    var buf: [64]u8 = undefined;
    const g = goShortestG(&buf, v);
    try w.writeAll(g);
    if (std.mem.indexOfAny(u8, g, ".e") == null) try w.writeAll(".0");
}

/// Go `strconv.FormatFloat(v, 'g', -1, 64)` for a finite, non-zero `v`:
/// the shortest round-trip digits, printed as `%e` (`d.ddde±XX`, at least
/// two exponent digits) when the decimal exponent is < -4 or ≥ 6 (Go's
/// shortest `%g` fixes `eprec` at 6: `1234567` is `1.234567e+06`, `123456`
/// stays), else as `%f`. Boundary rows checked against Go 1.26 in the tests.
fn goShortestG(buf: []u8, v: f64) []const u8 {
    // Shortest digits and exponent from Zig's scientific rendering
    // ("d.ddde[-]X").
    var sci_buf: [64]u8 = undefined;
    const sci = std.fmt.bufPrint(&sci_buf, "{e}", .{v}) catch unreachable;
    const e_at = std.mem.indexOfScalar(u8, sci, 'e').?;
    const exp = std.fmt.parseInt(i32, sci[e_at + 1 ..], 10) catch unreachable;
    const neg = sci[0] == '-';
    const mant = sci[@intFromBool(neg)..e_at];
    var digits_buf: [32]u8 = undefined;
    var nd: usize = 0;
    for (mant) |ch| if (ch != '.') {
        digits_buf[nd] = ch;
        nd += 1;
    };
    const digits = digits_buf[0..nd];
    var out: std.Io.Writer = .fixed(buf);
    if (neg) out.writeByte('-') catch unreachable;
    if (exp < -4 or exp >= 6) {
        out.writeByte(digits[0]) catch unreachable;
        if (nd > 1) {
            out.writeByte('.') catch unreachable;
            out.writeAll(digits[1..]) catch unreachable;
        }
        out.print("e{c}{d:0>2}", .{ @as(u8, if (exp < 0) '-' else '+'), @abs(exp) }) catch unreachable;
    } else if (exp < 0) {
        out.writeAll("0.") catch unreachable;
        for (0..@intCast(-exp - 1)) |_| out.writeByte('0') catch unreachable;
        out.writeAll(digits) catch unreachable;
    } else {
        const int_len: usize = @intCast(exp + 1);
        if (nd <= int_len) {
            out.writeAll(digits) catch unreachable;
            for (0..int_len - nd) |_| out.writeByte('0') catch unreachable;
        } else {
            out.writeAll(digits[0..int_len]) catch unreachable;
            out.writeByte('.') catch unreachable;
            out.writeAll(digits[int_len..]) catch unreachable;
        }
    }
    return out.buffered();
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
/// Register it router-level *after* `RequestMetrics.middleware` (the safe
/// default, audit F12/R3): a scrape then gets measured like any other
/// request, so a flood of scrapes — otherwise the one kind of traffic that
/// leaves no trace in `http_requests_total` or `http_requests_in_flight`,
/// see the module's audit F2/F8 — is at least visible. Register it *before*
/// only as a deliberate opt-out: uncounted scrapes, in exchange for
/// request-rate numbers the scrape interval cannot skew. The Endpoint must
/// outlive the Router, at a stable address.
pub const Endpoint = struct {
    registry: *Registry,
    /// Byte-exact request path to intercept (router raw-matching rules).
    path: []const u8 = "/metrics",
    /// Answer OpenMetrics to a scraper that prefers it in `Accept`
    /// (`Format.negotiate`); off = always the text format. client_golang
    /// promhttp `HandlerOpts.EnableOpenMetrics`, same default.
    open_metrics: bool = false,
    /// Cap on concurrently served scrapes (promhttp `MaxRequestsInFlight`):
    /// a scrape arriving while this many are already being answered gets
    /// `503` with a short text body and never touches the registry. `null`
    /// = unlimited (default). `0` rejects every GET/HEAD scrape.
    max_in_flight: ?u32 = null,
    /// Scrapes being answered right now (one atomic; only counted while
    /// `max_in_flight` is set).
    in_flight: std.atomic.Value(u32) = .init(0),

    pub fn middleware(e: *Endpoint) router.Middleware {
        return .{ .state = e, .run = endpointRun };
    }
};

fn endpointRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const e: *Endpoint = @ptrCast(@alignCast(state.?));
    if (!std.mem.eql(u8, ctx.req.path, e.path)) return next.run(ctx);
    switch (ctx.req.method) {
        .get, .head => {
            const format: Format = if (e.open_metrics) Format.negotiate(ctx.req.header("accept") orelse "") else .text;
            if (e.max_in_flight) |max| {
                const before = e.in_flight.fetchAdd(1, .acq_rel);
                defer _ = e.in_flight.fetchSub(1, .acq_rel);
                if (before >= max) {
                    ctx.res.setStatus(503);
                    try ctx.res.setHeader("Content-Type", "text/plain; charset=utf-8");
                    var msg_buf: [96]u8 = undefined;
                    const msg = std.fmt.bufPrint(&msg_buf, "Limit of concurrent requests reached ({d}), try again later.\n", .{max}) catch unreachable;
                    try ctx.res.writeAll(msg);
                    return;
                }
                try e.registry.respondFormat(ctx.res, format);
            } else try e.registry.respondFormat(ctx.res, format);
        },
        else => {
            ctx.res.setStatus(405);
            try ctx.res.setHeader("Allow", "GET, HEAD");
            try ctx.res.setHeader("Content-Type", "text/plain");
            try ctx.res.writeAll("Method Not Allowed\n");
        },
    }
}

// ── the request middleware ──────────────────────────────────────────────────

/// One record handed to the `on_request` hook — a *hook*, not a logger.
/// Called on the request thread after the response side of the chain
/// finished (also when the handler failed); keep it fast and thread-safe.
/// Everything here, `req` and `res` included, is only valid during the
/// callback.
///
/// For an access log, hand `req`/`res` to the `accesslog` module, which
/// formats every field (client address, time, User-Agent, …) and writes
/// lines from many threads safely — taking `status` and `duration_ns` from
/// here, because `res.status` does not yet say 500 for a handler that failed
/// before sending:
///
/// ```zig
/// fn logRequest(ctx: ?*anyopaque, e: metrics.AccessEntry) void {
///     const sink: *accesslog.Sink = @ptrCast(@alignCast(ctx.?));
///     var addr_buf: [64]u8 = undefined;
///     var entry = accesslog.entryFromRequest(e.req, e.res, &addr_buf, .{
///         .timestamp_ns = wallClockNs(), // the module reads no clock
///         .latency_ns = e.duration_ns,
///     });
///     entry.status = e.status;
///     sink.log(entry);
/// }
/// // RequestMetrics.init(&reg, .{ .on_request = logRequest, .on_request_ctx = &sink })
/// ```
pub const AccessEntry = struct {
    method: http.Method,
    /// Request path (no query). Borrowed — copy it to retain.
    path: []const u8,
    /// Response status; 500 when the handler errored before sending.
    status: u16,
    duration_ns: u64,
    /// Response body bytes when knowable: exact for buffered bodies,
    /// the declared Content-Length for identity streams, 0 for
    /// HEAD/204/304, the body octets sent so far for a streamed body
    /// (`ResponseWriter.bodyBytesSent`; a compressed one counts what the
    /// encoder has emitted by then).
    bytes: ?u64,
    /// The request being answered (headers, peer address, target with its
    /// query). Borrowed for the callback only.
    req: *const http.Server.Request,
    /// Its response writer (status as set, bytes sent). Borrowed for the
    /// callback only.
    res: *const http.Server.ResponseWriter,
};

const method_count = @typeInfo(http.Method).@"enum".field_names.len;
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
    request_size_histograms: [method_count]std.atomic.Value(?*Histogram) = @splat(.init(null)),
    response_size_histograms: [method_count]std.atomic.Value(?*Histogram) = @splat(.init(null)),

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
        /// Request-size histogram bucket bounds in bytes (promhttp
        /// `InstrumentHandlerRequestSize`); `null` = not recorded, nothing
        /// is registered and the exposition is unchanged (default). The
        /// size is promhttp's approximation (see `approxRequestSize`).
        request_size_buckets: ?[]const f64 = null,
        request_size_name: []const u8 = "http_request_size_bytes",
        request_size_help: []const u8 = "Approximate HTTP request size in bytes, by method.",
        /// Response-size histogram bucket bounds in bytes (promhttp
        /// `InstrumentHandlerResponseSize`); `null` = not recorded (default).
        /// Body bytes as `AccessEntry.bytes`; a response whose size is not
        /// knowable is skipped, not recorded as 0.
        response_size_buckets: ?[]const f64 = null,
        response_size_name: []const u8 = "http_response_size_bytes",
        response_size_help: []const u8 = "HTTP response body size in bytes, by method.",
        /// Time source for the latency histogram — inject a fake in tests.
        clock: Clock = .monotonic,
        /// Optional structured access-log hook (see `AccessEntry`).
        on_request: ?*const fn (?*anyopaque, AccessEntry) void = null,
        /// Opaque context passed to `on_request`.
        on_request_ctx: ?*anyopaque = null,
    };

    /// Validates the metric names and registers the in-flight gauge, the
    /// request counter and the latency histogram families up front (so
    /// misconfiguration — including a name collision with a family the
    /// application already registered, audit F9 — fails here, not
    /// mid-request, silently and forever). The Registry must outlive the
    /// returned value; the returned value must sit at a stable address
    /// before `middleware()` is registered.
    pub fn init(registry: *Registry, options: Options) RegisterError!RequestMetrics {
        // Surface name/bucket problems now: touch each family once with the
        // exact label set real traffic uses for the common case (a
        // successful GET), so real traffic's first `counterFor`/
        // `histogramFor` call just gets back this same series (see
        // `getOrRegister`'s get-or-register semantics) rather than adding a
        // distinct one — the in-flight gauge is the same idea, one step
        // further: unlabeled, so the touch series *is* the real series.
        if (!validMetricName(options.counter_name)) return error.InvalidName;
        if (!validMetricName(options.histogram_name)) return error.InvalidName;
        for (options.buckets, 0..) |b, i| {
            if (!std.math.isFinite(b)) return error.InvalidBuckets;
            if (i > 0 and b <= options.buckets[i - 1]) return error.InvalidBuckets;
        }
        inline for (.{ options.request_size_buckets, options.response_size_buckets }) |ob| {
            if (ob) |bs| for (bs, 0..) |b, i| {
                if (!std.math.isFinite(b)) return error.InvalidBuckets;
                if (i > 0 and b <= bs[i - 1]) return error.InvalidBuckets;
            };
        }
        if (options.request_size_buckets != null and !validMetricName(options.request_size_name)) return error.InvalidName;
        if (options.response_size_buckets != null and !validMetricName(options.response_size_name)) return error.InvalidName;
        const in_flight = try registry.gauge(options.in_flight_name, options.in_flight_help, &.{});
        _ = try registry.counter(options.counter_name, options.counter_help, &.{
            .{ .name = "method", .value = @tagName(http.Method.get) },
            .{ .name = "code", .value = classLabel(2) },
        });
        _ = try registry.histogram(options.histogram_name, options.histogram_help, &.{
            .{ .name = "method", .value = @tagName(http.Method.get) },
        }, options.buckets);
        if (options.request_size_buckets) |bs| _ = try registry.histogram(options.request_size_name, options.request_size_help, &.{
            .{ .name = "method", .value = @tagName(http.Method.get) },
        }, bs);
        if (options.response_size_buckets) |bs| _ = try registry.histogram(options.response_size_name, options.response_size_help, &.{
            .{ .name = "method", .value = @tagName(http.Method.get) },
        }, bs);
        // This middleware keeps series pointers for its whole life: its
        // families must never be freed under it (review 2026-10-17, M1).
        registry.pin(options.in_flight_name);
        registry.pin(options.counter_name);
        registry.pin(options.histogram_name);
        if (options.request_size_buckets != null) registry.pin(options.request_size_name);
        if (options.response_size_buckets != null) registry.pin(options.response_size_name);
        return .{
            .registry = registry,
            .options = options,
            .in_flight = in_flight,
        };
    }

    /// The `router.Middleware` (`state` = this RequestMetrics). Register it
    /// router-level, before routes (chi's rule), and — by default —
    /// *before* the `Endpoint` middleware, so a scrape is measured like any
    /// other request instead of being the one kind of traffic telemetry
    /// never sees (audit F12/R3). Register it after `Endpoint` only when
    /// you have deliberately chosen scrape-noise-free request-rate numbers
    /// over that visibility.
    pub fn middleware(m: *RequestMetrics) router.Middleware {
        return .{ .state = m, .run = requestRun };
    }

    fn counterFor(m: *RequestMetrics, method: http.Method, status: u16) RegisterError!*Counter {
        const mi = @backingInt(method);
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
        const mi = @backingInt(method);
        if (m.histograms[mi].load(.acquire)) |h| return h;
        const h = try m.registry.histogram(m.options.histogram_name, m.options.histogram_help, &.{
            .{ .name = "method", .value = @tagName(method) },
        }, m.options.buckets);
        m.histograms[mi].store(h, .release);
        return h;
    }

    fn sizeHistogramFor(m: *RequestMetrics, method: http.Method, response: bool) RegisterError!?*Histogram {
        const buckets = (if (response) m.options.response_size_buckets else m.options.request_size_buckets) orelse return null;
        const cache = if (response) &m.response_size_histograms else &m.request_size_histograms;
        const mi = @backingInt(method);
        if (cache[mi].load(.acquire)) |h| return h;
        const h = try m.registry.histogram(
            if (response) m.options.response_size_name else m.options.request_size_name,
            if (response) m.options.response_size_help else m.options.request_size_help,
            &.{.{ .name = "method", .value = @tagName(method) }},
            buckets,
        );
        cache[mi].store(h, .release);
        return h;
    }
};

/// promhttp's `computeApproximateRequestSize`, on our request: request-target
/// + method + protocol + header names and values + declared `Content-Length`
/// (0 when absent or chunked — the number of body bytes the handler read is
/// not exposed by `http.Server.Request`). The `Host` header is counted as a
/// header (Go counts `r.Host` separately, same bytes); the protocol counts as
/// the 8 bytes of `HTTP/1.1` (`HTTP/2.0` is 8 as well).
pub fn approxRequestSize(req: *const http.Server.Request) u64 {
    var n: u64 = req.target.len + req.methodName().len + "HTTP/1.1".len;
    var it = req.iterateHeaders();
    while (it.next()) |h| n += h.name.len + h.value.len;
    n += req.head.content_length orelse 0;
    return n;
}

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

    if (m.sizeHistogramFor(ctx.req.method, false)) |mh| {
        if (mh) |h| h.observe(@floatFromInt(approxRequestSize(ctx.req)));
    } else |_| {}
    if (m.sizeHistogramFor(ctx.req.method, true)) |mh| {
        if (mh) |h| if (responseBytes(ctx.res)) |b| h.observe(@floatFromInt(b));
    } else |_| {}

    if (m.options.on_request) |hook| hook(m.options.on_request_ctx, .{
        .method = ctx.req.method,
        .path = ctx.req.path,
        .status = status,
        .duration_ns = duration_ns,
        .bytes = responseBytes(ctx.res),
        .req = ctx.req,
        .res = ctx.res,
    });
    return result;
}

/// Best-effort response body size for the access-log hook — see
/// `AccessEntry.bytes` for the exact contract.
fn responseBytes(res: *const http.Server.ResponseWriter) ?u64 {
    // One definition with accesslog's `%b`: `http` owns it, including the
    // `declared_len` (not the remaining-bytes budget) rule for an identity
    // body that audit F11 pinned. Streamed bodies are counted since
    // 2026-09-28; this used to answer null for them.
    return res.bodyBytesSent();
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
    try testing.expectError(error.ReservedLabelName, reg.histogram("h1", "x", &.{.{ .name = "le", .value = "v" }}, &.{}));
    // F13: `le` is reserved on EVERY instrument kind, as client_golang
    // reserves it. Previously it was accepted on a counter, which is the
    // exact mechanism F5's collision (`<h>_bucket{le=...}`) needed.
    // `quantile` is reserved by client_golang only for summaries, which this
    // module does not have, so it is an ordinary label here (it was refused
    // until the registration oracle, 2026-10-06).
    try testing.expectError(error.ReservedLabelName, reg.counter("a_total", "x", &.{.{ .name = "le", .value = "v" }}));
    _ = try reg.gauge("a_gauge", "x", &.{.{ .name = "quantile", .value = "0.5" }});
    // A label name twice in one call: Prometheus refuses the series it
    // would write (`m{a="1",a="2"}`), and the whole scrape with it.
    try testing.expectError(error.InvalidLabelName, reg.counter("d_total", "x", &.{ .{ .name = "a", .value = "1" }, .{ .name = "a", .value = "2" } }));

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

    // Label-name mismatch, same length AND same first byte, different rest
    // (F14 in the module's audit): a comparator weakened to "length + first
    // byte" would wrongly call these the same label and silently merge two
    // distinct metrics into one series. The mismatch above (`"k"` vs.
    // `"other"`) differs in length too, so it cannot catch that weakening —
    // this one can only pass if the full name is compared.
    _ = try reg.counter("d_total", "help", &.{.{ .name = "method", .value = "a" }});
    try testing.expectError(error.LabelMismatch, reg.counter("d_total", "help", &.{.{ .name = "mangle", .value = "a" }}));
}

// F5 in the module's audit (PROBE B): a histogram's derived sample names
// (`<name>_bucket`/`_sum`/`_count`) are not reserved against a *different*
// family taking the same name. Two samples with the identical (name,
// labels) tuple and different values -- or a `# TYPE` line that
// contradicts an earlier one for the same name -- make Prometheus reject
// the whole scrape, so one misnamed counter blinds monitoring for every
// other family in the registry. client_golang has `checkSuffixCollisions`
// for exactly this; this module had nothing.
test "registration: a histogram's derived names collide with another family, both directions (F5)" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();

    _ = try reg.histogram("job_seconds", "Job latency.", &.{}, &.{ 0.5, 1 });
    try testing.expectError(error.NameCollision, reg.counter("job_seconds_bucket", "Unrelated counter.", &.{}));
    try testing.expectError(error.NameCollision, reg.counter("job_seconds_sum", "x", &.{}));
    try testing.expectError(error.NameCollision, reg.counter("job_seconds_count", "x", &.{}));
    // Getting the SAME histogram again is not a collision with itself.
    _ = try reg.histogram("job_seconds", "Job latency.", &.{}, &.{ 0.5, 1 });

    // The other direction: the plain name arrives first, the histogram
    // whose derived name would collide with it arrives second.
    _ = try reg.counter("other_bucket", "x", &.{});
    try testing.expectError(error.NameCollision, reg.histogram("other", "x", &.{}, &.{}));
    // A non-histogram family named `<x>_bucket` does not collide with a
    // SAME-KIND family `<x>` -- only a histogram's reserved suffixes do.
    _ = try reg.counter("plain", "x", &.{});
    _ = try reg.counter("plain_bucket", "x", &.{});
}

// F6 in the module's audit (PROBE A): `Content-Type` promises
// `charset=utf-8`, but neither a label value nor HELP text was ever
// checked, so a caller-supplied byte outside UTF-8 (or a raw control byte)
// went to the wire unescaped and made the exposition invalid UTF-8 despite
// its own header. Checked once at registration, which is cheaper than
// checking it on every scrape (per-scrape checking was the audit's other
// option, rejected as more expensive for a caller-time defect).
test "registration: invalid UTF-8 in a label value or HELP text is rejected (F6)" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();

    try testing.expectError(error.InvalidUtf8, reg.counter("a_total", "x", &.{.{ .name = "l", .value = "a\xffb" }}));
    try testing.expectError(error.InvalidUtf8, reg.counter("a_total", "x", &.{.{ .name = "l", .value = "a\x80b" }}));
    try testing.expectError(error.InvalidUtf8, reg.counter("b_total", "bad\xffhelp", &.{}));
    // Valid multi-byte UTF-8 ("café") and plain control bytes that ARE
    // valid UTF-8 (a literal NUL) both still register -- this rejects
    // invalid BYTES, not the wider set of "bytes F6 also worried about".
    _ = try reg.counter("c_total", "valid utf8: caf\xc3\xa9", &.{});
    _ = try reg.counter("d_total", "x", &.{.{ .name = "l", .value = "a\x00b" }});
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

// ── conformance: exposition-format grammar checker ──────────────────────────
//
// The tests below this point compared `writeText` output only against
// hand-typed expected strings — which proves the encoder is *consistent with
// itself* (or with a human's transcription of the spec), never that the text
// is *valid Prometheus exposition format*. Neither `promtool` (Prometheus)
// nor any OpenAPI-style external validator binary/package is installed on
// this machine (checked: no `promtool` on PATH, no cached image, and this
// task must not install one), so the tool-oracle route from the module's
// sibling anchor-gap tasks is blocked here. Instead: the Prometheus project's
// own exposition-format documentation publishes worked examples of the text
// format it defines — an authoritative document this module needs no tool to
// consult. `promGoldenExample` below is a frozen excerpt of that published
// text (see NOTICE for provenance/license); `validateExpositionText` is a
// grammar checker for the format it documents (comment lines / `# HELP` /
// `# TYPE` / sample lines with an optional `{label="value",...}` block, a
// numeric-or-`+Inf`/`-Inf`/`NaN` value, and an optional integer timestamp).
// The checker is exercised two ways: against the frozen official example
// (proving it accepts real, externally-authored conformant text, not just
// this module's own shape) and against this module's OWN `writeText` output
// in the golden tests below (closing the actual gap — those goldens now
// assert grammar validity, not merely byte-identity with a hand-typed
// string). Per the governing rule, this checker is never used to invent a
// grammar to match our encoder; it existed before touching whether our
// encoder passes.
const ExpositionError = error{
    InvalidLine,
    InvalidMetricName,
    InvalidLabelName,
    InvalidLabelValue,
    InvalidValue,
    InvalidTimestamp,
    InvalidType,
    UnterminatedLabelBlock,
};

fn validateExpositionText(text: []const u8) ExpositionError!void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, " \r");
        if (line.len == 0) continue;
        if (line[0] == '#') {
            if (std.mem.startsWith(u8, line, "# HELP ")) {
                try validateHelpOrTypeLine(line["# HELP ".len..], .help);
            } else if (std.mem.startsWith(u8, line, "# TYPE ")) {
                try validateHelpOrTypeLine(line["# TYPE ".len..], .type);
            }
            // Any other `#` line is a free-form comment — ignored, per the
            // format (the published example uses these between families).
            continue;
        }
        try validateSampleLine(line);
    }
}

fn validateHelpOrTypeLine(rest: []const u8, comptime kind: enum { help, type }) ExpositionError!void {
    const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
    if (!validMetricName(rest[0..sp])) return error.InvalidMetricName;
    if (kind == .help) return; // anything after the name is free HELP text
    const type_str = if (sp < rest.len) rest[sp + 1 ..] else "";
    inline for (.{ "counter", "gauge", "histogram", "summary", "untyped" }) |known| {
        if (std.mem.eql(u8, type_str, known)) return;
    }
    return error.InvalidType;
}

fn validateSampleLine(line: []const u8) ExpositionError!void {
    var i: usize = 0;
    const name_start = i;
    while (i < line.len and (std.ascii.isAlphabetic(line[i]) or line[i] == '_' or line[i] == ':' or
        (i > name_start and std.ascii.isDigit(line[i])))) : (i += 1)
    {}
    if (i == name_start or !validMetricName(line[name_start..i])) return error.InvalidMetricName;

    if (i < line.len and line[i] == '{') {
        i = try validateLabelBlock(line, i + 1);
    }

    if (i >= line.len or line[i] != ' ') return error.InvalidLine;
    while (i < line.len and line[i] == ' ') : (i += 1) {}
    const value_start = i;
    while (i < line.len and line[i] != ' ') : (i += 1) {}
    if (!isValidExpositionNumber(line[value_start..i])) return error.InvalidValue;

    while (i < line.len and line[i] == ' ') : (i += 1) {}
    if (i == line.len) return; // no timestamp — legal
    const ts_start = i;
    while (i < line.len and line[i] != ' ') : (i += 1) {}
    if (!isValidExpositionInteger(line[ts_start..i])) return error.InvalidTimestamp;
    while (i < line.len and line[i] == ' ') : (i += 1) {}
    if (i != line.len) return error.InvalidLine; // nothing may follow the timestamp
}

/// Parse `name="value"(,name="value")*}` starting right after the opening
/// `{`; returns the index right after the closing `}`.
fn validateLabelBlock(line: []const u8, start: usize) ExpositionError!usize {
    var i = start;
    if (i < line.len and line[i] == '}') return i + 1; // `{}` — degenerate but not our concern to reject
    while (true) {
        const name_start = i;
        while (i < line.len and (std.ascii.isAlphabetic(line[i]) or line[i] == '_' or
            (i > name_start and std.ascii.isDigit(line[i])))) : (i += 1)
        {}
        if (i == name_start or !validLabelName(line[name_start..i])) return error.InvalidLabelName;
        if (i >= line.len or line[i] != '=') return error.InvalidLine;
        i += 1;
        if (i >= line.len or line[i] != '"') return error.InvalidLabelValue;
        i += 1;
        while (i < line.len and line[i] != '"') {
            if (line[i] == '\\') {
                i += 1;
                if (i >= line.len) return error.InvalidLabelValue;
                switch (line[i]) {
                    '\\', '"', 'n' => {},
                    else => return error.InvalidLabelValue,
                }
            }
            i += 1;
        }
        if (i >= line.len) return error.UnterminatedLabelBlock;
        i += 1; // consume the closing quote
        if (i < line.len and line[i] == ',') {
            i += 1;
            continue;
        }
        if (i < line.len and line[i] == '}') return i + 1;
        return error.UnterminatedLabelBlock;
    }
}

fn isValidExpositionNumber(tok: []const u8) bool {
    if (std.mem.eql(u8, tok, "+Inf") or std.mem.eql(u8, tok, "-Inf") or std.mem.eql(u8, tok, "NaN")) return true;
    if (tok.len == 0) return false;
    var i: usize = 0;
    if (tok[i] == '+' or tok[i] == '-') i += 1;
    var saw_digit = false;
    while (i < tok.len and std.ascii.isDigit(tok[i])) : (i += 1) saw_digit = true;
    if (i < tok.len and tok[i] == '.') {
        i += 1;
        while (i < tok.len and std.ascii.isDigit(tok[i])) : (i += 1) saw_digit = true;
    }
    if (!saw_digit) return false;
    if (i < tok.len and (tok[i] == 'e' or tok[i] == 'E')) {
        i += 1;
        if (i < tok.len and (tok[i] == '+' or tok[i] == '-')) i += 1;
        var saw_exp_digit = false;
        while (i < tok.len and std.ascii.isDigit(tok[i])) : (i += 1) saw_exp_digit = true;
        if (!saw_exp_digit) return false;
    }
    return i == tok.len;
}

fn isValidExpositionInteger(tok: []const u8) bool {
    if (tok.len == 0) return false;
    var i: usize = 0;
    if (tok[0] == '+' or tok[0] == '-') i += 1;
    if (i == tok.len) return false;
    while (i < tok.len) : (i += 1) {
        if (!std.ascii.isDigit(tok[i])) return false;
    }
    return true;
}

/// A frozen excerpt of the worked example from Prometheus's own exposition-
/// format documentation (`docs/instrumenting/exposition_formats/` on
/// prometheus.io, Apache-2.0 — see NOTICE), fetched once (2026-08-01) and
/// reproduced verbatim. Deliberately excludes the page's "UTF-8 metric and
/// label names" line: that is an OpenMetrics naming EXTENSION this module's
/// classic 0.0.4 writer never emits and `validateExpositionText` does not
/// (and need not) accept.
const prom_golden_example =
    \\# HELP http_requests_total The total number of HTTP requests.
    \\# TYPE http_requests_total counter
    \\http_requests_total{method="post",code="200"} 1027 1395066363000
    \\http_requests_total{method="post",code="400"}    3 1395066363000
    \\
    \\# Escaping in label values:
    \\msdos_file_access_time_seconds{path="C:\\DIR\\FILE.TXT",error="Cannot find file:\n\"FILE.TXT\""} 1.458255915e9
    \\
    \\# Minimalistic line:
    \\metric_without_timestamp_and_labels 12.47
    \\
    \\# A weird metric from before the epoch:
    \\something_weird{problem="division by zero"} +Inf -3982045
    \\
    \\# A histogram, which has a pretty complex representation in the text format:
    \\# HELP http_request_duration_seconds A histogram of the request duration.
    \\# TYPE http_request_duration_seconds histogram
    \\http_request_duration_seconds_bucket{le="0.05"} 24054
    \\http_request_duration_seconds_bucket{le="0.1"} 33444
    \\http_request_duration_seconds_bucket{le="0.2"} 100392
    \\http_request_duration_seconds_bucket{le="0.5"} 129389
    \\http_request_duration_seconds_bucket{le="1"} 133988
    \\http_request_duration_seconds_bucket{le="+Inf"} 144320
    \\http_request_duration_seconds_sum 53423
    \\http_request_duration_seconds_count 144320
;

test "conformance: the checker accepts Prometheus's own published exposition-format example" {
    try validateExpositionText(prom_golden_example);
}

test "conformance: the checker rejects an unterminated label value (sanity: it is not vacuous)" {
    try testing.expectError(error.UnterminatedLabelBlock, validateExpositionText(
        \\# TYPE x counter
        \\x{k="unterminated} 1
    ));
    try testing.expectError(error.InvalidValue, validateExpositionText(
        \\# TYPE x counter
        \\x not_a_number
    ));
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
    // Byte-identity with our own hand-typed string proves nothing about
    // real Prometheus conformance (see the conformance-checker section
    // above) — so also run the actual output through the same grammar
    // checker the published example was validated against.
    try validateExpositionText(w.buffered());
}

test "writeText: a literal quote in HELP text is NOT escaped (only label values escape quotes)" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const c = try reg.counter("x_total", "Has a \" quote, unescaped per spec.", &.{});
    c.inc();

    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try reg.writeText(&w);
    try testing.expectEqualStrings(
        "# HELP x_total Has a \" quote, unescaped per spec.\n" ++
            "# TYPE x_total counter\n" ++
            "x_total 1\n",
        w.buffered(),
    );
    try validateExpositionText(w.buffered());
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
    try validateExpositionText(w.buffered());
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
    try validateExpositionText(w.buffered());
}

// ── external anchor: independently parsed by `prometheus_client` ───────────
//
// The grammar checker above proves this module's text is syntactically valid
// exposition format; it does not prove a real Prometheus client parses out
// the families/samples/values this module actually intended. `prometheus_client`
// (`parser.text_string_to_metric_families`), an independent Python
// implementation of the reader Prometheus itself uses, was run ONCE, offline,
// against the exact byte string produced by the `Registry` below (identical
// setup to "writeText: golden exact bytes"), and what it parsed out is
// quoted verbatim here (2026-08-01):
//
//   FAMILY api_requests counter 'Total API requests.'
//     SAMPLE api_requests_total {'method': 'get', 'code': '2xx'} 3
//     SAMPLE api_requests_total {'method': 'post', 'code': '5xx'} 1
//   FAMILY queue_depth gauge 'Depth\nwith \\ inside.'
//     SAMPLE queue_depth {'q': 'a\\b"c\nd'} 42
//   FAMILY req_seconds histogram 'Request latency.'
//     SAMPLE req_seconds_bucket {'route': '/x', 'le': '0.25'} 1
//     SAMPLE req_seconds_bucket {'route': '/x', 'le': '0.5'} 2
//     SAMPLE req_seconds_bucket {'route': '/x', 'le': '2'} 3
//     SAMPLE req_seconds_bucket {'route': '/x', 'le': '+Inf'} 4
//     SAMPLE req_seconds_sum {'route': '/x'} 9.5
//     SAMPLE req_seconds_count {'route': '/x'} 4
//
// Every value, label and escape this module intended was extracted correctly
// — including the backslash/quote/newline escaping in both HELP text and a
// label value, and the cumulative histogram buckets. **No disagreement was
// found.** One thing this run taught that this module's own grammar checker
// has no notion of either way: `prometheus_client` strips the `_total`
// suffix from the *family* name (`api_requests`, not `api_requests_total`)
// while the per-sample name keeps it — a real client-library convention,
// confirmed here rather than assumed.
//
// Per the governing rule, the tool was run once and its verdict frozen; this
// test does not shell out or open a socket — it only re-runs this module's
// own `writeText` and checks the bytes are still what was fed to the real
// parser. No `/NOTICE` entry: `prometheus_client` is used purely as a
// black-box parsing oracle here (root NOTICE §0, the relationship already
// recorded for `protobuf`/`syslog`/`opcua`/`wireguard`/`xmlsec1`) — nothing
// was read from or copied out of its source; the module's own vendored
// exposition-format *documentation excerpt* NOTICE entry above is unrelated
// and unaffected.
test "external anchor: exposition text independently parsed by prometheus_client (frozen 2026-08-01)" {
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

    // The exact bytes fed to, and successfully parsed by, `prometheus_client`
    // into the families/samples quoted above.
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

/// A clock whose second reading is *before* its first — `clock_gettime`
/// failing once (which `monotonicNowNs` maps to `0`) is exactly this shape.
/// Exercises `requestRun`'s `-|` (saturating) subtraction.
const BackwardClock = struct {
    readings: [2]u64,
    i: usize = 0,

    fn nowFn(ctx: ?*anyopaque) u64 {
        const c: *BackwardClock = @ptrCast(@alignCast(ctx.?));
        const v = c.readings[c.i];
        c.i += 1;
        return v;
    }
    fn clock(c: *BackwardClock) Clock {
        return .{ .ctx = c, .nowFn = nowFn };
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
/// A declared `Content-Length` plus a body large enough to force a drain
/// before the handler returns — the wire framing `beginStreaming` picks is
/// `.identity`, not `.buffering` (see `responseBytes`, F11 in the module's
/// audit).
fn hIdentityStream(ctx: *router.Ctx) anyerror!void {
    try ctx.res.setHeader("Content-Length", "5000");
    var chunk: [512]u8 = undefined;
    @memset(&chunk, 'x');
    var sent: usize = 0;
    while (sent < 5000) {
        const take = @min(chunk.len, 5000 - sent);
        try ctx.res.writeAll(chunk[0..take]);
        sent += take;
    }
}
/// A status code outside the 100-599 HTTP range — exercises `classLabel`'s
/// `else => "other"` fallback (`counterFor`'s `ci = ... else 0` path).
fn hWeirdStatus(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(999);
    try ctx.res.writeAll("weird");
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
    try r.use(ep.middleware()); // opt-out order (F12): scrapes NOT recorded
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
    // In-flight is back at zero — and, in this opt-out order (F12), the
    // scrape itself was not counted (the whole http_requests_total family
    // sums to 7, not 8).
    try expectBodyLine(got, "http_requests_in_flight 0");
    try testing.expect(std.mem.indexOf(u8, bodyOf(got), "/metrics") == null);
}

// F12/R3 in the module's audit: the safe DEFAULT order (`RequestMetrics`
// registered before `Endpoint`, now the recommendation on both doc
// comments above) counts a scrape like any other request — the mirror
// image of the "opt-out order" test above, which put `Endpoint` first and
// got an UNcounted scrape. A flood of scrapes (audit F2/F8) is otherwise
// the one kind of traffic that leaves zero trace in `http_requests_total`
// or `http_requests_in_flight`.
test "middleware: registering RequestMetrics before Endpoint counts the scrape (F12 default)" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var rm = try RequestMetrics.init(&reg, .{});
    var ep: Endpoint = .{ .registry = &reg };

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(rm.middleware()); // default order (F12): scrapes ARE recorded
    try r.use(ep.middleware());
    try r.get("/ok", hOk);

    var buf: [8192]u8 = undefined;
    try expectStatus(runWire(&r, wire("GET", "/ok"), &buf), "200");

    // A scrape's own count is recorded only after its response is fully
    // written (the `defer` in `requestRun` runs after `next.run` returns),
    // so the FIRST scrape's body still reflects just the one prior "/ok"
    // request -- it cannot see itself.
    const scrape1 = runWire(&r, wire("GET", "/metrics"), &buf);
    try expectBodyLine(scrape1, "http_requests_total{method=\"get\",code=\"2xx\"} 1");

    // A SECOND scrape now sees the first scrape's own increment -- proof
    // that, in this order, a scrape is traffic like any other, not the
    // blind spot F12 describes.
    const scrape2 = runWire(&r, wire("GET", "/metrics"), &buf);
    try expectBodyLine(scrape2, "http_requests_total{method=\"get\",code=\"2xx\"} 2");
}

test "middleware: a status outside 100-599 falls into the 'other' class" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var rm = try RequestMetrics.init(&reg, .{});

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(rm.middleware());
    try r.get("/weird", hWeirdStatus);

    var buf: [8192]u8 = undefined;
    try expectStatus(runWire(&r, wire("GET", "/weird"), &buf), "999");

    try testing.expectEqual(1, (try reg.counter("http_requests_total", rm.options.counter_help, &.{
        .{ .name = "method", .value = "get" }, .{ .name = "code", .value = "other" },
    })).value());
}

// Regression for F15/M28 in the module's audit: mutating `-|` (saturating)
// to `-%` (wrapping) in `requestRun`'s duration calculation survived the
// whole suite — every clock in the existing tests only ever moves forward.
// A transient `clock_gettime` failure maps to `0` (see `monotonicNowNs`),
// so a backwards step is a real, if rare, input; wrapping would poison the
// latency histogram with ~2^64 ns (~5.8e11 seconds) instead of clamping to
// zero.
test "middleware: a clock that goes backwards saturates duration to zero" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var bc: BackwardClock = .{ .readings = .{ 1_000_000_000, 500_000_000 } }; // t1 < t0
    var rm = try RequestMetrics.init(&reg, .{ .clock = bc.clock() });

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(rm.middleware());
    try r.get("/ok", hOk);

    var buf: [4096]u8 = undefined;
    try expectStatus(runWire(&r, wire("GET", "/ok"), &buf), "200");

    const h = try reg.histogram(rm.options.histogram_name, rm.options.histogram_help, &.{
        .{ .name = "method", .value = "get" },
    }, rm.options.buckets);
    try testing.expectEqual(@as(u64, 1), h.observation_count);
    try testing.expectEqual(@as(f64, 0), h.observation_sum);
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

// F9 in the module's audit (PROBE J): the doc comment on `init` has always
// promised "misconfiguration fails here, not mid-request", but `init` only
// ever touched the in-flight gauge — never the counter or histogram
// families it is actually about. If the application registers
// `http_requests_total` itself first (the most common metric name in the
// whole Prometheus ecosystem), with a different type, help or label set,
// `init` returned OK, requests kept being served 200, and the request
// counter silently and permanently never appeared — no error, no log line,
// nowhere. The latency histogram (different family name) kept working,
// so a dashboard would show real latency with a zero request rate: it
// reads as "no traffic", not "broken metrics".
test "middleware: init fails when the request counter's name collides with an app-registered family (F9)" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();

    // The application registered its own "http_requests_total" first, as
    // a gauge instead of a counter — same shape as PROBE J.
    _ = try reg.gauge("http_requests_total", "some app metric", &.{});

    try testing.expectError(error.WrongType, RequestMetrics.init(&reg, .{}));

    // Same idea, but the histogram family this time — a different (but
    // equally real) way `init` used to let a collision through unnoticed.
    var reg2 = Registry.init(testing.allocator);
    defer reg2.deinit();
    _ = try reg2.gauge("http_request_duration_seconds", "some app metric", &.{});
    try testing.expectError(error.WrongType, RequestMetrics.init(&reg2, .{}));
}

const HookCapture = struct {
    entries: [8]struct {
        method: http.Method,
        path_buf: [64]u8,
        path_len: usize,
        status: u16,
        duration_ns: u64,
        bytes: ?u64,
        target_buf: [64]u8,
        target_len: usize,
        res_status: u16,
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
        @memcpy(slot.target_buf[0..e.req.target.len], e.req.target);
        slot.target_len = e.req.target.len;
        slot.res_status = e.res.status;
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

    // The live request/response ride along for a full access log
    // (`accesslog.entryFromRequest`): the target as sent, the status as set
    // — which is why `status` above is the one to log after a failure.
    try testing.expectEqualStrings("/ok", e0.target_buf[0..e0.target_len]);
    try testing.expectEqual(200, e0.res_status);
}

// Regression for F11 in the module's audit: `responseBytes`'s `.identity`
// branch had no test at all — mutating its `res.declared_len.?` unwrap to a
// hardcoded `0` left the whole suite green. This exercises exactly that
// branch (a declared Content-Length streamed in chunks, not buffered) so a
// future regression on the `.identity` count is caught here, not just by
// inspection.
test "middleware: access-log hook reports the declared length for a streamed (.identity) body" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var capture: HookCapture = .{};
    var rm = try RequestMetrics.init(&reg, .{
        .on_request = HookCapture.hook,
        .on_request_ctx = &capture,
    });

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(rm.middleware());
    try r.get("/big", hIdentityStream);

    var out_buf: [16384]u8 = undefined;
    try expectStatus(runWire(&r, wire("GET", "/big"), &out_buf), "200");

    try testing.expectEqual(1, capture.len);
    try testing.expectEqual(@as(?u64, 5000), capture.entries[0].bytes);
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

// ── tests: client_golang parity helpers ─────────────────────────────────────

test "gauge: setToCurrentTime stores Unix seconds from the wall clock of io" {
    var g: Gauge = .{};
    const before = std.Io.Clock.real.now(testing.io).nanoseconds;
    g.setToCurrentTime(testing.io);
    const after = std.Io.Clock.real.now(testing.io).nanoseconds;
    const v = g.value();
    const lo: f64 = @floatFromInt(@divFloor(before, std.time.ns_per_s));
    const hi: f64 = @floatFromInt(@divFloor(after, std.time.ns_per_s) + 1);
    try testing.expect(v >= lo and v <= hi);
    try testing.expect(v > 1.7e9); // fractional seconds, not millis or nanos
}

fn expectBits(comptime want: []const u64, got: []const f64) !void {
    try testing.expectEqual(want.len, got.len);
    inline for (want, 0..) |w, i| try testing.expectEqual(w, @as(u64, @bitCast(got[i])));
}

// Expected bit patterns are printed by client_golang v1.24.1 itself
// (Go program importing prometheus.LinearBuckets etc., 2026-10-17).
test "buckets: linearBuckets matches client_golang bit for bit" {
    try expectBits(&.{ 0x0000000000000000, 0x4024000000000000, 0x4034000000000000, 0x403e000000000000, 0x4044000000000000 }, &linearBuckets(0, 10, 5));
    try expectBits(&.{ 0x3fb999999999999a, 0x3fc999999999999a, 0x3fd3333333333334, 0x3fd999999999999a, 0x3fe0000000000000, 0x3fe3333333333333, 0x3fe6666666666666 }, &linearBuckets(0.1, 0.1, 7));
    try expectBits(&.{ 0xc014000000000000, 0xc004000000000000, 0x0000000000000000, 0x4004000000000000 }, &linearBuckets(-5, 2.5, 4));
    // runtime variant, same values; empty output is the error
    var buf: [4]f64 = undefined;
    try fillLinearBuckets(&buf, -5, 2.5);
    try expectBits(&.{ 0xc014000000000000, 0xc004000000000000, 0x0000000000000000, 0x4004000000000000 }, &buf);
    try testing.expectError(error.InvalidBuckets, fillLinearBuckets(buf[0..0], 0, 1));
}

test "buckets: exponentialBuckets matches client_golang bit for bit" {
    try expectBits(&.{ 0x3ff0000000000000, 0x4000000000000000, 0x4010000000000000, 0x4020000000000000, 0x4030000000000000, 0x4040000000000000, 0x4050000000000000, 0x4060000000000000 }, &exponentialBuckets(1, 2, 8));
    try expectBits(&.{ 0x3f50624dd2f1a9fc, 0x3f847ae147ae147b, 0x3fb999999999999a, 0x3ff0000000000000, 0x4024000000000000 }, &exponentialBuckets(0.001, 10, 5));
    try expectBits(&.{ 0x4059000000000000, 0x4062c00000000000, 0x406c200000000000, 0x4075180000000000, 0x407fa40000000000, 0x4087bb0000000000 }, &exponentialBuckets(100, 1.5, 6));
    var buf: [3]f64 = undefined;
    try fillExponentialBuckets(&buf, 1, 2);
    try testing.expectEqualSlices(f64, &.{ 1, 2, 4 }, &buf);
    try testing.expectError(error.InvalidBuckets, fillExponentialBuckets(&buf, 0, 2));
    try testing.expectError(error.InvalidBuckets, fillExponentialBuckets(&buf, 1, 1));
    try testing.expectError(error.InvalidBuckets, fillExponentialBuckets(buf[0..0], 1, 2));
    try testing.expectError(error.InvalidBuckets, fillExponentialBuckets(&buf, 1, std.math.nan(f64)));
}

// ExponentialBucketsRange goes through pow(): Go's and Zig's pow may differ
// in the last bits, so compare with a few ulps of slack (values still
// printed by client_golang), exactly for the endpoints that Go computes
// exactly.
fn expectNear(want: []const f64, got: []const f64) !void {
    try testing.expectEqual(want.len, got.len);
    for (want, got) |w, g| try testing.expect(@abs(w - g) <= @abs(w) * 4e-16);
}

test "buckets: exponentialBucketsRange matches client_golang (to 4e-16 relative)" {
    try expectNear(&.{ 1, 9.999999999999998, 99.99999999999997, 999.9999999999995 }, &exponentialBucketsRange(1, 1000, 4));
    try expectNear(&.{ 0.005, 0.017747683298777853, 0.06299605249474366, 0.223606797749979, 0.7937005259840999, 2.817269113847841, 10.000000000000002 }, &exponentialBucketsRange(0.005, 10, 7));
    try expectNear(&.{1}, &exponentialBucketsRange(1, 1, 1));
    try expectNear(&.{ 2, 2, 2 }, &exponentialBucketsRange(2, 2, 3));
    var buf: [4]f64 = undefined;
    try fillExponentialBucketsRange(&buf, 1, 1000);
    try expectNear(&.{ 1, 9.999999999999998, 99.99999999999997, 999.9999999999995 }, &buf);
    try testing.expectError(error.InvalidBuckets, fillExponentialBucketsRange(&buf, 0, 10));
    try testing.expectError(error.InvalidBuckets, fillExponentialBucketsRange(&buf, 10, 1));
    try testing.expectError(error.InvalidBuckets, fillExponentialBucketsRange(buf[0..0], 1, 10));
    // the generated lists are valid bucket bounds for a histogram
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    _ = try reg.histogram("lin", "L.", &.{}, &linearBuckets(1, 1, 3));
    _ = try reg.histogram("exp", "E.", &.{}, &exponentialBuckets(1, 2, 3));
}

test "Timer: observes elapsed seconds on the injected clock and returns ns" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const h = try reg.histogram("t_seconds", "T.", &.{}, &.{ 0.001, 0.01 });
    var fake: FakeClock = .{ .step_ns = 5 * std.time.ns_per_ms };
    const t = Timer.start(fake.clock()); // reads 5 ms
    try testing.expectEqual(@as(u64, 5_000_000), t.observeDuration(h)); // reads 10 ms
    try testing.expectEqual(@as(u64, 1), h.count());
    try testing.expectEqual(@as(f64, 0.005), h.sum());
    try testing.expectEqual(@as(u64, 0), h.cumulativeBucket(0)); // 5 ms > 1 ms
    try testing.expectEqual(@as(u64, 1), h.cumulativeBucket(1));
    // a clock going backwards saturates to 0
    var back: BackwardClock = .{ .readings = .{ 10, 3 } };
    const t2 = Timer.start(back.clock());
    try testing.expectEqual(@as(u64, 0), t2.elapsedNs());
}

test "endpoint: max_in_flight answers 503 beyond the limit and always releases its slot" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    _ = try reg.counter("t_total", "T.", &.{});
    var ep: Endpoint = .{ .registry = &reg, .max_in_flight = 1 };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(ep.middleware());

    var buf: [4096]u8 = undefined;
    // free slot: served, counter back to 0 afterwards
    try expectStatus(runWire(&r, wire("GET", "/metrics"), &buf), "200");
    try testing.expectEqual(@as(u32, 0), ep.in_flight.load(.acquire));

    // one scrape "in progress" (simulated): the next one is rejected, text body
    ep.in_flight.store(1, .release);
    const rej = runWire(&r, wire("GET", "/metrics"), &buf);
    try expectStatus(rej, "503");
    try expectHeaderLine(rej, "Content-Type: text/plain; charset=utf-8");
    try testing.expectEqualStrings("Limit of concurrent requests reached (1), try again later.\n", bodyOf(rej));
    try expectStatus(runWire(&r, wire("HEAD", "/metrics"), &buf), "503");
    // the rejected attempts did not leak a slot
    try testing.expectEqual(@as(u32, 1), ep.in_flight.load(.acquire));
    ep.in_flight.store(0, .release);
    try expectStatus(runWire(&r, wire("GET", "/metrics"), &buf), "200");

    // 405 is not a scrape and ignores the limit; unlimited by default
    ep.in_flight.store(1, .release);
    try expectStatus(runWire(&r, wire("POST", "/metrics"), &buf), "405");
    ep.in_flight.store(0, .release);
    ep.max_in_flight = 0; // rejects every scrape
    try expectStatus(runWire(&r, wire("GET", "/metrics"), &buf), "503");
    try testing.expectEqual(@as(u32, 0), ep.in_flight.load(.acquire));
    ep.max_in_flight = null;
    try expectStatus(runWire(&r, wire("GET", "/metrics"), &buf), "200");
}

test "middleware: request/response size histograms are off by default and unchanged output" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var rm = try RequestMetrics.init(&reg, .{});
    var ep: Endpoint = .{ .registry = &reg };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(rm.middleware());
    try r.use(ep.middleware());
    try r.get("/ok", hOk);
    var buf: [8192]u8 = undefined;
    _ = runWire(&r, wire("GET", "/ok"), &buf);
    const got = runWire(&r, wire("GET", "/metrics"), &buf);
    try testing.expect(std.mem.indexOf(u8, got, "size_bytes") == null);
}

test "middleware: request/response size histograms (opt-in, per method)" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var rm = try RequestMetrics.init(&reg, .{
        .request_size_buckets = &.{ 10, 50, 100 },
        .response_size_buckets = &.{ 1, 2, 3 },
    });
    var ep: Endpoint = .{ .registry = &reg };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(rm.middleware());
    try r.use(ep.middleware());
    try r.get("/ok", hOk);
    var buf: [8192]u8 = undefined;
    // "/ok" 3 + "GET" 3 + "HTTP/1.1" 8 + "Host"+"t" 5 + "Connection"+"close" 15 = 34 bytes
    // request; response body "ok" = 2 bytes.
    _ = runWire(&r, wire("GET", "/ok"), &buf);
    const got = runWire(&r, wire("GET", "/metrics"), &buf);
    try expectBodyLine(got, "http_request_size_bytes_bucket{method=\"get\",le=\"10\"} 0");
    try expectBodyLine(got, "http_request_size_bytes_bucket{method=\"get\",le=\"50\"} 1");
    try expectBodyLine(got, "http_request_size_bytes_sum{method=\"get\"} 34");
    try expectBodyLine(got, "http_response_size_bytes_bucket{method=\"get\",le=\"1\"} 0");
    try expectBodyLine(got, "http_response_size_bytes_bucket{method=\"get\",le=\"2\"} 1");
    try expectBodyLine(got, "http_response_size_bytes_sum{method=\"get\"} 2");
    try expectBodyLine(got, "http_response_size_bytes_count{method=\"get\"} 1");

    // misconfiguration fails at init
    try testing.expectError(error.InvalidBuckets, RequestMetrics.init(&reg, .{ .request_size_buckets = &.{ 5, 5 } }));
    try testing.expectError(error.InvalidBuckets, RequestMetrics.init(&reg, .{ .response_size_buckets = &.{std.math.inf(f64)} }));
    try testing.expectError(error.InvalidName, RequestMetrics.init(&reg, .{ .request_size_buckets = &.{1}, .request_size_name = "no way" }));
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
    try r.use(ep.middleware()); // opt-out order (F12): scrapes not counted
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
        return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
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

// ── F15 M29/M31/M32: does the lock actually get TAKEN? ─────────────────────
//
// The three stress tests above (and the module's own mutation audit, F15)
// converge on the same shape: racing many threads over MANY iterations and
// checking the aggregate is a race against a narrow window, and a critical
// section of a few string compares is too short for the window to ever
// open in practice — which is exactly why M29 (`writeText` dropping its
// `lockSpin`), M31 (`getOrRegister` dropping its `lockSpin`) and M32
// (`AccessLog.log` dropping its `lockSpin` even with `synchronized = true`;
// that writer and its test moved to `accesslog.Sink` on 2026-10-06)
// all survived those tests untouched. A prior pass concluded this needed
// either a flaky race or production instrumentation added just for
// testability, and left it there.
//
// Neither is true: don't wait for a narrow window, FORCE one. Take the lock
// from the test itself BEFORE the function under test ever runs, then check
// whether it made progress anyway. A correctly-locking function has no
// choice but to spin in `lockSpin` for as long as the test holds the lock;
// a mutated one proceeds immediately regardless. This is not a probabilistic
// race — as long as the test holds the lock for the whole sleep, a
// still-`false` `done` flag is not "we got lucky", it is the only possible
// outcome unless the lock was skipped. Zero production code touched: the
// lock field and `lockSpin` are already private symbols in this same file.

fn sleepMs(ms: u64) void {
    const ts: std.os.linux.timespec = .{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * 1_000_000),
    };
    _ = std.os.linux.nanosleep(&ts, null);
}

test "F15/M29: writeText actually takes the registry lock" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    _ = try reg.counter("m29_probe_total", "probe", &.{});

    lockSpin(&reg.lock); // held by the test, not by writeText

    var done = std.atomic.Value(bool).init(false);
    const Ctx = struct {
        reg: *Registry,
        done: *std.atomic.Value(bool),
        fn run(ctx: *@This()) void {
            var buf: [4096]u8 = undefined;
            var w: std.Io.Writer = .fixed(&buf);
            _ = ctx.reg.writeText(&w) catch {};
            ctx.done.store(true, .seq_cst);
        }
    };
    var ctx: Ctx = .{ .reg = &reg, .done = &done };
    const t = try std.Thread.spawn(.{}, Ctx.run, .{&ctx});

    sleepMs(50);
    // Still blocked on the lock the test is holding: this is only possible
    // if writeText itself blocks on it too. A dropped lockSpin would let
    // this thread finish and set `done` well within 50ms (a formatting pass
    // over one family is microseconds).
    try testing.expect(!done.load(.seq_cst));

    reg.lock.unlock();
    t.join();
    try testing.expect(done.load(.seq_cst));
}

test "F15/M31: getOrRegister actually takes the registry lock" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();

    lockSpin(&reg.lock);

    var done = std.atomic.Value(bool).init(false);
    const Ctx = struct {
        reg: *Registry,
        done: *std.atomic.Value(bool),
        fn run(ctx: *@This()) void {
            _ = ctx.reg.counter("m31_probe_total", "probe", &.{}) catch {};
            ctx.done.store(true, .seq_cst);
        }
    };
    var ctx: Ctx = .{ .reg = &reg, .done = &done };
    const t = try std.Thread.spawn(.{}, Ctx.run, .{&ctx});

    sleepMs(50);
    try testing.expect(!done.load(.seq_cst));

    reg.lock.unlock();
    t.join();
    try testing.expect(done.load(.seq_cst));
    _ = try reg.counter("m31_probe_total", "probe", &.{}); // registered, not lost
}

// ── *Vec handles, delete / reset / unregister (S2, 2026-10-17) ─────────────

fn scrapeInto(reg: *Registry, buf: []u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try reg.writeText(&w);
    return w.buffered();
}

test "Vec: with returns the same series as the get-or-register path" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const v = try reg.counterVec("vec_total", "h", &.{ "method", "code" });
    const a = try v.with(&.{ "GET", "200" });
    a.inc();
    const b = try reg.counter("vec_total", "h", &.{ .{ .name = "method", .value = "GET" }, .{ .name = "code", .value = "200" } });
    try testing.expectEqual(a, b);
    try testing.expectEqual(a, try v.with(&.{ "GET", "200" }));
    try testing.expect(a != try v.with(&.{ "GET", "500" }));
    // Length-prefixed hashing: ("ab","c") and ("a","bc") are two series.
    try testing.expect(try v.with(&.{ "ab", "c" }) != try v.with(&.{ "a", "bc" }));
    try testing.expectEqual(@as(usize, 4), v.len());
    // Same descriptor = same family; a different one is refused.
    const again = try reg.counterVec("vec_total", "h", &.{ "method", "code" });
    try testing.expectEqual(v.family, again.family);
    try testing.expectError(error.LabelMismatch, reg.counterVec("vec_total", "h", &.{"method"}));
    try testing.expectError(error.WrongType, reg.gaugeVec("vec_total", "h", &.{ "method", "code" }));
}

test "Vec: with refuses a wrong value count and invalid UTF-8, registering nothing" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const v = try reg.gaugeVec("vec_g", "h", &.{"room"});
    try testing.expectError(error.LabelMismatch, v.with(&.{}));
    try testing.expectError(error.LabelMismatch, v.with(&.{ "a", "b" }));
    try testing.expectError(error.InvalidUtf8, v.with(&.{"\xff"}));
    try testing.expectEqual(@as(usize, 0), v.len());
    // The get-or-register path checks values before touching the family.
    try testing.expectError(error.InvalidUtf8, reg.counter("fresh_total", "h", &.{.{ .name = "a", .value = "\xc3" }}));
    try testing.expect(reg.family_index.get("fresh_total") == null);
}

test "Vec: a family with no series is not exposed; delete and reset remove series" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var buf: [1024]u8 = undefined;
    const v = try reg.counterVec("del_total", "h", &.{"k"});
    try testing.expectEqualStrings("", try scrapeInto(&reg, &buf));

    (try v.with(&.{"a"})).add(3);
    (try v.with(&.{"b"})).add(5);
    (try v.with(&.{"c"})).add(7);
    try testing.expectEqualStrings(
        \\# HELP del_total h
        \\# TYPE del_total counter
        \\del_total{k="a"} 3
        \\del_total{k="b"} 5
        \\del_total{k="c"} 7
        \\
    , try scrapeInto(&reg, &buf));

    try testing.expect(v.delete(&.{"b"}));
    try testing.expect(!v.delete(&.{"b"}));
    try testing.expect(!v.delete(&.{"zz"}));
    try testing.expectEqualStrings(
        \\# HELP del_total h
        \\# TYPE del_total counter
        \\del_total{k="a"} 3
        \\del_total{k="c"} 7
        \\
    , try scrapeInto(&reg, &buf));
    // Re-created after delete: a fresh, zeroed series, appended last.
    (try v.with(&.{"b"})).inc();
    try testing.expectEqualStrings(
        \\# HELP del_total h
        \\# TYPE del_total counter
        \\del_total{k="a"} 3
        \\del_total{k="c"} 7
        \\del_total{k="b"} 1
        \\
    , try scrapeInto(&reg, &buf));

    try testing.expect(v.reset());
    try testing.expectEqual(@as(usize, 0), v.len());
    try testing.expectEqualStrings("", try scrapeInto(&reg, &buf));
    (try v.with(&.{"a"})).inc();
    try testing.expectEqual(@as(u64, 1), (try v.with(&.{"a"})).value());
}

test "Vec: histogram series are freed with their buckets (testing.allocator leak check)" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const v = try reg.histogramVec("del_seconds", "h", &.{"op"}, &default_buckets);
    (try v.with(&.{"read"})).observe(0.02);
    (try v.with(&.{"write"})).observe(3);
    try testing.expect(v.delete(&.{"read"}));
    try testing.expect(v.reset());
    (try v.with(&.{"read"})).observe(1);
    try testing.expectEqual(@as(u64, 1), (try v.with(&.{"read"})).count());
}

test "unregister: removes the family, frees its series, allows a new descriptor" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var buf: [1024]u8 = undefined;
    const v = try reg.counterVec("gone_total", "h", &.{"k"});
    (try v.with(&.{"a"})).inc();
    _ = try reg.gauge("kept", "h", &.{});
    try testing.expect(reg.unregister("gone_total"));
    try testing.expect(!reg.unregister("gone_total"));
    try testing.expectEqualStrings(
        \\# HELP kept h
        \\# TYPE kept gauge
        \\kept 0
        \\
    , try scrapeInto(&reg, &buf));
    // The name is free for any descriptor now.
    (try reg.gauge("gone_total", "other", &.{})).set(2);
    // A stale handle keeps working (client_golang: an unregistered vec is
    // simply never collected) and its series are still freed at deinit.
    (try v.with(&.{"b"})).inc();
    try testing.expectEqualStrings(
        \\# HELP kept h
        \\# TYPE kept gauge
        \\kept 0
        \\# HELP gone_total other
        \\# TYPE gone_total gauge
        \\gone_total 2
        \\
    , try scrapeInto(&reg, &buf));
}

test "delete during a scrape: the series is parked until the scrapes that may hold it end" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const v = try reg.counterVec("park_total", "h", &.{"k"});
    _ = try v.with(&.{"a"});
    _ = try v.with(&.{"b"});
    // Stand in for a scrape between its snapshot and its end (ticket 0).
    try reg.scrapes.append(testing.allocator, 0);
    reg.scrape_seq = 1;
    try testing.expect(v.delete(&.{"a"}));
    try testing.expect(v.reset());
    try testing.expectEqual(@as(usize, 2), reg.retired.items.len);
    // A scrape that starts and ends meanwhile cannot free them: ticket 0
    // may still be formatting both.
    var buf: [256]u8 = undefined;
    _ = try scrapeInto(&reg, &buf);
    try testing.expectEqual(@as(usize, 2), reg.retired.items.len);
    // Ticket 0 ends: drained.
    reg.scrapes.clearRetainingCapacity();
    reg.reapLocked();
    try testing.expectEqual(@as(usize, 0), reg.retired.items.len);
}

test "overlapping scrapes do not keep removed series parked forever (review L5)" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const v = try reg.counterVec("overlap_total", "h", &.{"k"});
    // Scrapes that overlap with no gap: A runs, B starts, A ends, C starts,
    // B ends, ... — the running count never reaches 0. Each removal must be
    // freed once the scrapes older than it are gone.
    var running: u64 = 0;
    try reg.scrapes.append(testing.allocator, running);
    reg.scrape_seq = 1;
    for (0..50) |i| {
        var key: [8]u8 = undefined;
        const k = std.fmt.bufPrint(&key, "k{d}", .{i}) catch unreachable;
        _ = try v.with(&.{k});
        try testing.expect(v.delete(&.{k})); // parked behind `running`
        // The next scrape starts before the previous one ends.
        const next = reg.scrape_seq;
        reg.scrape_seq += 1;
        try reg.scrapes.append(testing.allocator, next);
        _ = reg.scrapes.swapRemove(std.mem.indexOfScalar(u64, reg.scrapes.items, running).?);
        reg.reapLocked();
        running = next;
        // Only the removal made while `next` was not yet running survives
        // `running`'s predecessor; at most one series is ever parked.
        try testing.expect(reg.retired.items.len <= 1);
    }
    reg.scrapes.clearRetainingCapacity();
    reg.reapLocked();
    try testing.expectEqual(@as(usize, 0), reg.retired.items.len);
}

test "delete/with racing concurrent scrapes stays consistent (no UAF, no leak)" {
    if (builtin.single_threaded) return error.SkipZigTest;
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const v = try reg.counterVec("race_total", "h", &.{"k"});
    const keys = [_][]const u8{ "a", "b", "c", "d", "e", "f", "g", "h" };
    var stop = std.atomic.Value(bool).init(false);
    const Churn = struct {
        fn run(vec: CounterVec, s: *std.atomic.Value(bool)) void {
            var i: usize = 0;
            while (!s.load(.acquire)) : (i += 1) {
                const k = keys[i % keys.len];
                if (i % 3 == 0) _ = vec.delete(&.{k}) else (vec.with(&.{k}) catch unreachable).inc();
                if (i % 997 == 0) _ = vec.reset();
            }
        }
    };
    const Scrape = struct {
        fn run(r: *Registry, s: *std.atomic.Value(bool)) void {
            var buf: [4096]u8 = undefined;
            while (!s.load(.acquire)) {
                var w: std.Io.Writer = .fixed(&buf);
                r.writeText(&w) catch unreachable;
                validateExpositionText(w.buffered()) catch unreachable;
            }
        }
    };
    var ts: [4]std.Thread = undefined;
    ts[0] = try std.Thread.spawn(.{}, Churn.run, .{ v, &stop });
    ts[1] = try std.Thread.spawn(.{}, Churn.run, .{ v, &stop });
    ts[2] = try std.Thread.spawn(.{}, Scrape.run, .{ &reg, &stop });
    ts[3] = try std.Thread.spawn(.{}, Scrape.run, .{ &reg, &stop });
    sleepMs(200);
    stop.store(true, .release);
    for (ts) |t| t.join();
    try testing.expectEqual(@as(usize, 0), reg.retired.items.len);
}

// ── OpenMetrics, callbacks, collectors (S2, 2026-10-17) ────────────────────

/// client_golang v1.24.1 + prometheus/common v0.71.0 `expfmt` output for the
/// registry `goldenRegistry` builds, printed by `tools/go_golden` (families
/// named so Go's name sort = our registration order).
const golden_go_text =
    \\# HELP a_requests_total Requests "served" \\ by\nmethod.
    \\# TYPE a_requests_total counter
    \\a_requests_total{method="GET"} 3
    \\a_requests_total{method="POST"} 1
    \\# HELP b_events No _total suffix.
    \\# TYPE b_events counter
    \\b_events 0
    \\# HELP c_temp Gauge.
    \\# TYPE c_temp gauge
    \\c_temp{room="hall"} 1.2345675e+06
    \\c_temp{room="lab"} -1
    \\# HELP d_seconds Hist.
    \\# TYPE d_seconds histogram
    \\d_seconds_bucket{le="0.5"} 2
    \\d_seconds_bucket{le="1"} 2
    \\d_seconds_bucket{le="2.5"} 3
    \\d_seconds_bucket{le="1e+06"} 5
    \\d_seconds_bucket{le="+Inf"} 5
    \\d_seconds_sum 12.75
    \\d_seconds_count 5
    \\# HELP e_func Func.
    \\# TYPE e_func gauge
    \\e_func 1.2e-05
    \\# HELP f_cpu_seconds_total CPU.
    \\# TYPE f_cpu_seconds_total counter
    \\f_cpu_seconds_total 12.25
    \\# HELP g_lat_seconds Summary.
    \\# TYPE g_lat_seconds summary
    \\g_lat_seconds{op="read",quantile="0.5"} 5
    \\g_lat_seconds{op="read",quantile="0.9"} 9
    \\g_lat_seconds{op="read",quantile="0.99"} 9.9
    \\g_lat_seconds_sum{op="read"} 505
    \\g_lat_seconds_count{op="read"} 100
    \\
;

const golden_go_openmetrics =
    \\# HELP a_requests Requests \"served\" \\ by\nmethod.
    \\# TYPE a_requests counter
    \\a_requests_total{method="GET"} 3.0
    \\a_requests_total{method="POST"} 1.0
    \\# HELP b_events No _total suffix.
    \\# TYPE b_events unknown
    \\b_events 0.0
    \\# HELP c_temp Gauge.
    \\# TYPE c_temp gauge
    \\c_temp{room="hall"} 1.2345675e+06
    \\c_temp{room="lab"} -1.0
    \\# HELP d_seconds Hist.
    \\# TYPE d_seconds histogram
    \\d_seconds_bucket{le="0.5"} 2
    \\d_seconds_bucket{le="1.0"} 2
    \\d_seconds_bucket{le="2.5"} 3
    \\d_seconds_bucket{le="1e+06"} 5
    \\d_seconds_bucket{le="+Inf"} 5
    \\d_seconds_sum 12.75
    \\d_seconds_count 5
    \\# HELP e_func Func.
    \\# TYPE e_func gauge
    \\e_func 1.2e-05
    \\# HELP f_cpu_seconds CPU.
    \\# TYPE f_cpu_seconds counter
    \\f_cpu_seconds_total 12.25
    \\# HELP g_lat_seconds Summary.
    \\# TYPE g_lat_seconds summary
    \\g_lat_seconds{op="read",quantile="0.5"} 5.0
    \\g_lat_seconds{op="read",quantile="0.9"} 9.0
    \\g_lat_seconds{op="read",quantile="0.99"} 9.9
    \\g_lat_seconds_sum{op="read"} 505.0
    \\g_lat_seconds_count{op="read"} 100
    \\# EOF
    \\
;

fn constValue(ctx: ?*anyopaque) f64 {
    const v: *const f64 = @ptrCast(@alignCast(ctx.?));
    return v.*;
}

var golden_e: f64 = 0.000012;
var golden_f: f64 = 12.25;

fn goldenRegistry(reg: *Registry) !void {
    const a = try reg.counterVec("a_requests_total", "Requests \"served\" \\ by\nmethod.", &.{"method"});
    (try a.with(&.{"GET"})).add(3);
    (try a.with(&.{"POST"})).add(1);
    _ = try reg.counter("b_events", "No _total suffix.", &.{});
    const c = try reg.gaugeVec("c_temp", "Gauge.", &.{"room"});
    (try c.with(&.{"hall"})).set(1234567.5);
    (try c.with(&.{"lab"})).set(-1);
    const d = try reg.histogram("d_seconds", "Hist.", &.{}, &.{ 0.5, 1, 2.5, 1e6 });
    for ([_]f64{ 0.25, 0.5, 2, 3, 7 }) |v| d.observe(v);
    try reg.gaugeFunc("e_func", "Func.", &.{}, &golden_e, constValue);
    try reg.counterFunc("f_cpu_seconds_total", "CPU.", &.{}, &golden_f, constValue);
    // Objectives in another order than Go's map: the family sorts them.
    const g = try reg.summaryVec("g_lat_seconds", "Summary.", &.{"op"}, .{ .objectives = &.{
        .{ .quantile = 0.99, .epsilon = 0.001 },
        .{ .quantile = 0.5, .epsilon = 0.05 },
        .{ .quantile = 0.9, .epsilon = 0.01 },
    } });
    for (1..101) |i| (try g.with(&.{"read"})).observe(@as(f64, @floatFromInt(i)) / 10);
}

test "text format: byte-identical to client_golang/expfmt (golden from Go)" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    try goldenRegistry(&reg);
    var buf: [4096]u8 = undefined;
    try testing.expectEqualStrings(golden_go_text, try scrapeInto(&reg, &buf));
}

test "OpenMetrics: byte-identical to client_golang/expfmt (golden from Go)" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    try goldenRegistry(&reg);
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try reg.writeOpenMetrics(&w);
    try testing.expectEqualStrings(golden_go_openmetrics, w.buffered());
}

test "goShortestG: Go strconv.FormatFloat(v, 'g', -1, 64) boundary rows (Go 1.26)" {
    const rows = [_]struct { f64, []const u8 }{
        .{ 1e5, "100000" },           .{ 123456, "123456" },
        .{ 1234567, "1.234567e+06" }, .{ 1e6, "1e+06" },
        .{ 1.5e6, "1.5e+06" },        .{ 1e20, "1e+20" },
        .{ 1e21, "1e+21" },           .{ 123456789012345678901.0, "1.2345678901234568e+20" },
        .{ 0.0001, "0.0001" },        .{ 0.00001, "1e-05" },
        .{ 0.000123, "0.000123" },    .{ 12345.678, "12345.678" },
        .{ 3.14, "3.14" },            .{ 100, "100" },
        .{ 0.5, "0.5" },              .{ -2.5e-7, "-2.5e-07" },
        .{ 5e-324, "5e-324" },        .{ 1.7976931348623157e308, "1.7976931348623157e+308" },
    };
    for (rows) |row| {
        var buf: [64]u8 = undefined;
        try testing.expectEqualStrings(row[1], goShortestG(&buf, row[0]));
    }
}

test "callbacks: one family may hold several, never mixed with ordinary series" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var x: f64 = 1;
    try reg.gaugeFunc("cb", "h", &.{.{ .name = "k", .value = "a" }}, &x, constValue);
    try reg.gaugeFunc("cb", "h", &.{.{ .name = "k", .value = "b" }}, &x, constValue);
    try testing.expectError(error.AlreadyRegistered, reg.gaugeFunc("cb", "h", &.{.{ .name = "k", .value = "a" }}, &x, constValue));
    try testing.expectError(error.AlreadyRegistered, reg.gauge("cb", "h", &.{.{ .name = "k", .value = "c" }}));
    const v = try reg.gaugeVec("cb", "h", &.{"k"});
    try testing.expectError(error.AlreadyRegistered, v.with(&.{"a"}));
    _ = try reg.counter("plain_total", "h", &.{});
    try testing.expectError(error.AlreadyRegistered, reg.counterFunc("plain_total", "h", &.{}, &x, constValue));
    x = 7.5;
    var buf: [512]u8 = undefined;
    try testing.expectEqualStrings(
        \\# HELP cb h
        \\# TYPE cb gauge
        \\cb{k="a"} 7.5
        \\cb{k="b"} 7.5
        \\# HELP plain_total h
        \\# TYPE plain_total counter
        \\plain_total 0
        \\
    , try scrapeInto(&reg, &buf));
}

const TestCollector = struct {
    calls: std.atomic.Value(u32) = .init(0),
    fail: bool = false,
    out_of_order: bool = false,

    fn collect(ctx: ?*anyopaque, sink: *Sink) anyerror!void {
        const self: *TestCollector = @ptrCast(@alignCast(ctx.?));
        _ = self.calls.fetchAdd(1, .monotonic);
        if (self.fail) return error.ProcUnreadable;
        if (self.out_of_order) {
            try sink.gauge(1, &.{}, 1);
            try sink.counter(0, &.{"x"}, 1);
            return;
        }
        try sink.counter(0, &.{"user"}, 1.5);
        try sink.counter(0, &.{"system"}, 0.25);
        // desc 1 skipped this scrape: no header, no samples.
        try sink.histogram(2, &.{}, &.{ 1, 2 }, &.{ 3, 4 }, 9.5, 6);
    }
};

const test_descs = [_]Desc{
    .{ .name = "proc_cpu_seconds_total", .help = "CPU.", .kind = .counter, .label_names = &.{"mode"} },
    .{ .name = "proc_fds", .help = "FDs.", .kind = .gauge },
    .{ .name = "proc_lat", .help = "Lat.", .kind = .histogram },
};

test "collector: emits its described families once per scrape, in place" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    _ = try reg.counter("before_total", "h", &.{});
    var tc: TestCollector = .{};
    try reg.registerCollector(&test_descs, .{ .ctx = &tc, .collect = TestCollector.collect });
    _ = try reg.gauge("after", "h", &.{});
    var buf: [2048]u8 = undefined;
    try testing.expectEqualStrings(
        \\# HELP before_total h
        \\# TYPE before_total counter
        \\before_total 0
        \\# HELP proc_cpu_seconds_total CPU.
        \\# TYPE proc_cpu_seconds_total counter
        \\proc_cpu_seconds_total{mode="user"} 1.5
        \\proc_cpu_seconds_total{mode="system"} 0.25
        \\# HELP proc_lat Lat.
        \\# TYPE proc_lat histogram
        \\proc_lat_bucket{le="1"} 3
        \\proc_lat_bucket{le="2"} 4
        \\proc_lat_bucket{le="+Inf"} 6
        \\proc_lat_sum 9.5
        \\proc_lat_count 6
        \\# HELP after h
        \\# TYPE after gauge
        \\after 0
        \\
    , try scrapeInto(&reg, &buf));
    try testing.expectEqual(@as(u32, 1), tc.calls.load(.monotonic));

    // Names are owned by the collector.
    try testing.expectError(error.AlreadyRegistered, reg.counter("proc_cpu_seconds_total", "CPU.", &.{.{ .name = "mode", .value = "u" }}));
    try testing.expectError(error.AlreadyRegistered, reg.registerCollector(&.{.{ .name = "after", .help = "h", .kind = .gauge }}, .{ .ctx = &tc, .collect = TestCollector.collect }));
    try testing.expectError(error.NameCollision, reg.registerCollector(&.{.{ .name = "proc_lat_count", .help = "h", .kind = .gauge }}, .{ .ctx = &tc, .collect = TestCollector.collect }));

    // Unregistering one of its families drops just that family.
    try testing.expect(reg.unregister("proc_lat"));
    const out = try scrapeInto(&reg, &buf);
    try testing.expect(std.mem.indexOf(u8, out, "proc_lat") == null);
    try testing.expect(std.mem.indexOf(u8, out, "proc_cpu_seconds_total{mode=\"user\"} 1.5") != null);
}

test "collector: a failing or misbehaving collector fails the scrape" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var tc: TestCollector = .{ .fail = true };
    try reg.registerCollector(&test_descs, .{ .ctx = &tc, .collect = TestCollector.collect });
    var buf: [2048]u8 = undefined;
    try testing.expectEqual(@as(?anyerror, null), reg.lastCollectorError());
    try testing.expectError(error.WriteFailed, scrapeInto(&reg, &buf));
    // The cause is kept (review L9, 2026-10-18).
    try testing.expectEqual(@as(?anyerror, error.ProcUnreadable), reg.lastCollectorError());
    tc.fail = false;
    tc.out_of_order = true;
    try testing.expectError(error.WriteFailed, scrapeInto(&reg, &buf));
    try testing.expectEqual(@as(?anyerror, error.OutOfOrder), reg.lastCollectorError());
}

test "collector: Sink refuses wrong kind, value count, UTF-8 and buckets" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var tc: TestCollector = .{};
    try reg.registerCollector(&test_descs, .{ .ctx = &tc, .collect = TestCollector.collect });
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var sink: Sink = .{ .w = &w, .entry = reg.families.items[0].collector.?, .format = .text };
    try testing.expectError(error.InvalidDesc, sink.gauge(0, &.{"x"}, 1));
    try testing.expectError(error.InvalidDesc, sink.gauge(9, &.{}, 1));
    try testing.expectError(error.LabelMismatch, sink.counter(0, &.{}, 1));
    try testing.expectError(error.InvalidUtf8, sink.counter(0, &.{"\xff"}, 1));
    try testing.expectError(error.InvalidBuckets, sink.histogram(2, &.{}, &.{ 2, 1 }, &.{ 1, 2 }, 0, 2));
    try testing.expectError(error.InvalidBuckets, sink.histogram(2, &.{}, &.{ 1, 2 }, &.{ 2, 1 }, 0, 2));
    try testing.expectError(error.InvalidBuckets, sink.histogram(2, &.{}, &.{1}, &.{ 1, 2 }, 0, 2));
    try testing.expectError(error.InvalidBuckets, sink.histogram(2, &.{}, &.{1}, &.{5}, 0, 2));
    try testing.expectEqualStrings("", w.buffered());
}

test "Format.negotiate: OpenMetrics only when preferred (Prometheus's Accept)" {
    try testing.expectEqual(Format.text, Format.negotiate(""));
    try testing.expectEqual(Format.text, Format.negotiate("*/*"));
    try testing.expectEqual(Format.text, Format.negotiate("text/plain"));
    try testing.expectEqual(Format.openmetrics, Format.negotiate(
        "application/openmetrics-text;version=1.0.0;q=0.5,application/openmetrics-text;version=0.0.1;q=0.4,text/plain;version=0.0.4;q=0.3,*/*;q=0.2",
    ));
    try testing.expectEqual(Format.text, Format.negotiate("application/openmetrics-text;q=0.2,text/plain;q=0.9"));
    try testing.expectEqual(Format.text, Format.negotiate("application/json"));
    // Prometheus 3.x: `escaping=` parameters are not a reason to fall back.
    try testing.expectEqual(Format.openmetrics, Format.negotiate(
        "application/openmetrics-text;version=1.0.0;escaping=allow-utf-8;q=0.6,application/openmetrics-text;version=0.0.1;q=0.5,text/plain;version=1.0.0;escaping=allow-utf-8;q=0.4,text/plain;version=0.0.4;q=0.3,*/*;q=0.2",
    ));
    // A bare OpenMetrics range is 0.0.1 (served as 1.0.0); another version is not ours.
    try testing.expectEqual(Format.openmetrics, Format.negotiate("application/openmetrics-text"));
    try testing.expectEqual(Format.text, Format.negotiate("application/openmetrics-text;version=2.0.0"));
    // `q=0` is "not acceptable".
    try testing.expectEqual(Format.text, Format.negotiate("application/openmetrics-text;version=1.0.0;q=0"));
}

test "Endpoint: open_metrics negotiates, default stays text" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    _ = try reg.counter("hits_total", "h", &.{});
    inline for (.{ false, true }) |om| {
        var ep: Endpoint = .{ .registry = &reg, .open_metrics = om };
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(ep.middleware());
        var out_buf: [2048]u8 = undefined;
        const got = runWire(&r, "GET /metrics HTTP/1.1\r\nHost: x\r\nAccept: application/openmetrics-text;version=1.0.0;q=0.5,text/plain;version=0.0.4;q=0.3\r\nConnection: close\r\n\r\n", &out_buf);
        if (om) {
            try expectHeaderLine(got, "Content-Type: " ++ content_type_openmetrics);
            try testing.expect(std.mem.endsWith(u8, got, "# EOF\n"));
        } else {
            try expectHeaderLine(got, "Content-Type: " ++ content_type);
            try testing.expect(std.mem.indexOf(u8, got, "# EOF") == null);
        }
    }
}

test "summary: registration rules (reserved quantile, objectives checked and shared)" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const objs = default_objectives;
    _ = try reg.summary("s_seconds", "h", &.{}, .{ .objectives = &objs });
    try testing.expectError(error.ObjectivesMismatch, reg.summary("s_seconds", "h", &.{}, .{}));
    try testing.expectError(error.ObjectivesMismatch, reg.summary("s_seconds", "h", &.{}, .{ .objectives = &objs, .max_age_ns = 1000 }));
    // Same set, another order: the same family.
    _ = try reg.summary("s_seconds", "h", &.{}, .{ .objectives = &.{ objs[2], objs[0], objs[1] } });
    try testing.expectError(error.ReservedLabelName, reg.summaryVec("t", "h", &.{"quantile"}, .{}));
    _ = try reg.gauge("g_with_quantile", "h", &.{.{ .name = "quantile", .value = "x" }}); // only summaries reserve it
    try testing.expectError(error.InvalidObjectives, reg.summary("bad1", "h", &.{}, .{ .objectives = &.{.{ .quantile = 1.5, .epsilon = 0.1 }} }));
    try testing.expectError(error.InvalidObjectives, reg.summary("bad2", "h", &.{}, .{ .objectives = &.{.{ .quantile = 0.5, .epsilon = 1 }} }));
    try testing.expectError(error.InvalidObjectives, reg.summary("bad3", "h", &.{}, .{ .objectives = &.{ objs[0], objs[0] } }));
    try testing.expectError(error.InvalidObjectives, reg.summary("bad4", "h", &.{}, .{ .age_buckets = 0 }));
    try testing.expectError(error.InvalidObjectives, reg.summary("bad5", "h", &.{}, .{ .max_age_ns = 3, .age_buckets = 5 }));
    try testing.expectError(error.WrongType, reg.counter("s_seconds", "h", &.{}));
}

test "summary: quantiles follow the registry clock's window; sum/count stay cumulative" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var clock: FakeClock = .{ .step_ns = 0 };
    reg.clock = clock.clock();
    const s = try reg.summary("w_seconds", "h", &.{}, .{
        .objectives = &.{.{ .quantile = 0.5, .epsilon = 0.01 }},
        .max_age_ns = 1000,
        .age_buckets = 2,
    });
    for (0..10) |i| s.observe(@floatFromInt(i));
    var buf: [512]u8 = undefined;
    try testing.expectEqualStrings(
        \\# HELP w_seconds h
        \\# TYPE w_seconds summary
        \\w_seconds{quantile="0.5"} 4
        \\w_seconds_sum 45
        \\w_seconds_count 10
        \\
    , try scrapeInto(&reg, &buf));
    clock.now_ns += 5000; // the whole window passes
    try testing.expectEqualStrings(
        \\# HELP w_seconds h
        \\# TYPE w_seconds summary
        \\w_seconds{quantile="0.5"} NaN
        \\w_seconds_sum 45
        \\w_seconds_count 10
        \\
    , try scrapeInto(&reg, &buf));
}

test "collector: Sink.summary writes quantile lines, refuses unsorted quantiles" {
    const Coll = struct {
        fn collect(_: ?*anyopaque, sink: *Sink) anyerror!void {
            try sink.summary(0, &.{}, &.{ .{ .quantile = 0.5, .epsilon = 0 }, .{ .quantile = 0.99, .epsilon = 0 } }, &.{ 1.5, 7 }, 20, 9);
        }
        fn bad(_: ?*anyopaque, sink: *Sink) anyerror!void {
            try sink.summary(0, &.{}, &.{ .{ .quantile = 0.9, .epsilon = 0 }, .{ .quantile = 0.5, .epsilon = 0 } }, &.{ 1, 2 }, 0, 0);
        }
    };
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    try reg.registerCollector(&.{.{ .name = "cs", .help = "h", .kind = .summary }}, .{ .collect = Coll.collect });
    var buf: [512]u8 = undefined;
    try testing.expectEqualStrings(
        \\# HELP cs h
        \\# TYPE cs summary
        \\cs{quantile="0.5"} 1.5
        \\cs{quantile="0.99"} 7
        \\cs_sum 20
        \\cs_count 9
        \\
    , try scrapeInto(&reg, &buf));
    var reg2 = Registry.init(testing.allocator);
    defer reg2.deinit();
    try reg2.registerCollector(&.{.{ .name = "cs", .help = "h", .kind = .summary }}, .{ .collect = Coll.bad });
    try testing.expectError(error.WriteFailed, scrapeInto(&reg2, &buf));
}

test "ProcessCollector: client_golang's process_* families for this process" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var pc: ProcessCollector = .{ .gpa = testing.allocator, .io = testing.io };
    try pc.register(&reg, "");
    try testing.expect(pc.btime > 1_000_000_000); // a plausible Unix boot time

    var buf: [8192]u8 = undefined;
    const out = try scrapeInto(&reg, &buf);
    try validateExpositionText(out);
    // Families in client_golang's (sorted) order; the network pair only
    // where /proc/self/net/netstat exists, which it does on any Linux.
    const want = [_][]const u8{
        "# TYPE process_cpu_seconds_total counter\nprocess_cpu_seconds_total ",
        "# TYPE process_max_fds gauge\nprocess_max_fds ",
        "# TYPE process_network_receive_bytes_total counter\nprocess_network_receive_bytes_total ",
        "# TYPE process_network_transmit_bytes_total counter\nprocess_network_transmit_bytes_total ",
        "# TYPE process_open_fds gauge\nprocess_open_fds ",
        "# TYPE process_resident_memory_bytes gauge\nprocess_resident_memory_bytes ",
        "# TYPE process_start_time_seconds gauge\nprocess_start_time_seconds ",
        "# TYPE process_virtual_memory_bytes gauge\nprocess_virtual_memory_bytes ",
        "# TYPE process_virtual_memory_max_bytes gauge\nprocess_virtual_memory_max_bytes ",
    };
    var at: usize = 0;
    for (want) |w| {
        const i = std.mem.indexOfPos(u8, out, at, w) orelse {
            std.debug.print("missing or out of order: {s}\n---\n{s}\n", .{ w, out });
            return error.TestUnexpectedResult;
        };
        at = i + w.len;
    }
    // max_fds is RLIMIT_NOFILE's soft limit.
    var lim: std.posix.rlimit = undefined;
    lim = try std.posix.getrlimit(.NOFILE);
    var line_buf: [96]u8 = undefined;
    var lw: std.Io.Writer = .fixed(&line_buf);
    try lw.writeAll("\nprocess_max_fds ");
    if (lim.cur == std.posix.RLIM.INFINITY) try writeFloat(&lw, @floatFromInt(std.math.maxInt(u64))) else try writeFloat(&lw, @floatFromInt(lim.cur));
    try lw.writeByte('\n');
    try testing.expect(std.mem.indexOf(u8, out, lw.buffered()) != null);

    // Namespace prefix.
    var reg2 = Registry.init(testing.allocator);
    defer reg2.deinit();
    var pc2: ProcessCollector = .{ .gpa = testing.allocator, .io = testing.io };
    try pc2.register(&reg2, "app");
    const out2 = try scrapeInto(&reg2, &buf);
    try testing.expect(std.mem.indexOf(u8, out2, "\napp_process_open_fds ") != null);
    // Its names are taken now.
    try testing.expectError(error.AlreadyRegistered, pc2.register(&reg2, "app"));
}

test "ProcessCollector: a pid that does not exist yields no samples, not an error" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var pc: ProcessCollector = .{ .gpa = testing.allocator, .io = testing.io, .ref = .{ .pid = std.math.maxInt(u32) } };
    try pc.register(&reg, "");
    var buf: [1024]u8 = undefined;
    try testing.expectEqualStrings("", try scrapeInto(&reg, &buf));
}

/// `tools/go_golden`'s "exemplars" section (client_golang const metrics with
/// exemplars, fixed timestamp), plus the `# EOF` our whole-registry writer adds.
const golden_go_exemplars =
    \\# HELP x_hits Hits.
    \\# TYPE x_hits counter
    \\x_hits_total 3.0 # {trace_id="4bf92f\"x"} 2.0 1.7000000002499998e+09
    \\# HELP x_lat_seconds Lat.
    \\# TYPE x_lat_seconds histogram
    \\x_lat_seconds_bucket{le="1.0"} 1 # {span="a"} 0.5 1.7000000002499998e+09
    \\x_lat_seconds_bucket{le="5.0"} 2
    \\x_lat_seconds_bucket{le="+Inf"} 3 # {span="b"} 6.0 1.7000000002499998e+09
    \\x_lat_seconds_sum 9.5
    \\x_lat_seconds_count 3
    \\# EOF
    \\
;

test "exemplars: OpenMetrics lines byte-identical to client_golang; text format has none" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const ts: f64 = @as(f64, 1700000000250000000.0) / 1e9; // Go: UnixNano()/1e9
    const c = try reg.counter("x_hits_total", "Hits.", &.{});
    c.add(1);
    try c.addWithExemplar(2, &.{.{ .name = "trace_id", .value = "4bf92f\"x" }}, ts);
    const h = try reg.histogram("x_lat_seconds", "Lat.", &.{}, &.{ 1, 5 });
    try h.observeWithExemplar(0.5, &.{.{ .name = "span", .value = "a" }}, ts);
    h.observe(3);
    try h.observeWithExemplar(6, &.{.{ .name = "span", .value = "b" }}, ts);

    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try reg.writeOpenMetrics(&w);
    try testing.expectEqualStrings(golden_go_exemplars, w.buffered());
    const text = try scrapeInto(&reg, &buf);
    try testing.expect(std.mem.indexOf(u8, text, "#  {") == null);
    try testing.expect(std.mem.indexOf(u8, text, "span") == null);
}

test "exemplars: the last one per sample wins; no timestamp is allowed" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const c = try reg.counter("y_total", "h", &.{});
    try c.incWithExemplar(&.{.{ .name = "t", .value = "1" }}, null);
    try c.incWithExemplar(&.{.{ .name = "t", .value = "2" }}, null);
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try reg.writeOpenMetrics(&w);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "y_total 2.0 # {t=\"2\"} 1.0\n") != null);
}

test "exemplars: invalid labels are refused and change nothing" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const c = try reg.counter("z_total", "h", &.{});
    try testing.expectError(error.InvalidExemplar, c.incWithExemplar(&.{.{ .name = "0bad", .value = "x" }}, null));
    try testing.expectError(error.InvalidExemplar, c.incWithExemplar(&.{ .{ .name = "a", .value = "x" }, .{ .name = "a", .value = "y" } }, null));
    try testing.expectError(error.InvalidExemplar, c.incWithExemplar(&.{.{ .name = "a", .value = "\xff" }}, null));
    // 128 runes is the limit: name (1) + value (127) passes, one more fails.
    const ok_value = strRepeat("é", 127);
    try c.incWithExemplar(&.{.{ .name = "a", .value = ok_value }}, null);
    try testing.expectError(error.InvalidExemplar, c.incWithExemplar(&.{.{ .name = "a", .value = ok_value ++ "x" }}, null));
    try testing.expectEqual(@as(u64, 1), c.value());
    var bare: Counter = .{};
    try testing.expectError(error.NoExemplarStorage, bare.incWithExemplar(&.{}, null));
}

test "exemplars: concurrent writers and scrapers stay well-formed" {
    if (builtin.single_threaded) return error.SkipZigTest;
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const h = try reg.histogram("race_ex_seconds", "h", &.{}, &default_buckets);
    var stop = std.atomic.Value(bool).init(false);
    const W = struct {
        fn run(hh: *Histogram, s: *std.atomic.Value(bool)) void {
            var i: usize = 0;
            const vals = [_][]const u8{ "a", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "\"q\"" };
            while (!s.load(.acquire)) : (i += 1) {
                hh.observeWithExemplar(@as(f64, @floatFromInt(i % 13)), &.{.{ .name = "trace_id", .value = vals[i % 3] }}, null) catch unreachable;
            }
        }
    };
    const S = struct {
        fn run(r: *Registry, s: *std.atomic.Value(bool)) void {
            var buf: [8192]u8 = undefined;
            while (!s.load(.acquire)) {
                var w: std.Io.Writer = .fixed(&buf);
                r.writeOpenMetrics(&w) catch unreachable;
                const out = w.buffered();
                // every exemplar is one of the three whole label blocks
                var it = std.mem.splitScalar(u8, out, '\n');
                while (it.next()) |line| {
                    const at = std.mem.indexOf(u8, line, " # ") orelse continue;
                    const rest = line[at + 3 ..];
                    std.debug.assert(std.mem.startsWith(u8, rest, "{trace_id=\"a\"} ") or
                        std.mem.startsWith(u8, rest, "{trace_id=\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"} ") or
                        std.mem.startsWith(u8, rest, "{trace_id=\"\\\"q\\\"\"} "));
                }
            }
        }
    };
    var ts: [3]std.Thread = undefined;
    ts[0] = try std.Thread.spawn(.{}, W.run, .{ h, &stop });
    ts[1] = try std.Thread.spawn(.{}, W.run, .{ h, &stop });
    ts[2] = try std.Thread.spawn(.{}, S.run, .{ &reg, &stop });
    sleepMs(150);
    stop.store(true, .release);
    for (ts) |t| t.join();
}

test "Timer: observeDurationSummary records seconds into a Summary" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var clock: FakeClock = .{ .step_ns = 250_000_000 };
    reg.clock = clock.clock();
    const sm = try reg.summary("t_seconds", "h", &.{}, .{});
    const t = Timer.start(clock.clock());
    try testing.expectEqual(@as(u64, 250_000_000), t.observeDurationSummary(sm));
    var none: [0]f64 = .{};
    const snap = sm.snapshot(&none);
    try testing.expectEqual(@as(u64, 1), snap.count);
    try testing.expectEqual(@as(f64, 0.25), snap.sum);
}

test "pinned: RequestMetrics' families cannot be deleted, reset or unregistered under it" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var rm = try RequestMetrics.init(&reg, .{ .request_size_buckets = &.{ 100, 1000 } });
    _ = &rm;
    const opts: RequestMetrics.Options = .{};
    try testing.expect(!reg.unregister(opts.counter_name));
    try testing.expect(!reg.unregister(opts.in_flight_name));
    try testing.expect(!reg.unregister(opts.request_size_name));
    const v = try reg.counterVec(opts.counter_name, opts.counter_help, &.{ "method", "code" });
    try testing.expect(!v.reset());
    try testing.expect(!v.delete(&.{ "get", "2xx" }));
    try testing.expectEqual(@as(usize, 1), v.len());
    // An unpinned family still can.
    _ = try reg.counter("free_total", "h", &.{});
    try testing.expect(reg.unregister("free_total"));
}

test "registerCollector: a sibling desc colliding with a histogram's derived names is refused" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const Noop = struct {
        fn collect(_: ?*anyopaque, _: *Sink) anyerror!void {}
    };
    try testing.expectError(error.NameCollision, reg.registerCollector(&.{
        .{ .name = "lat", .help = "h", .kind = .histogram },
        .{ .name = "lat_count", .help = "h", .kind = .gauge },
    }, .{ .collect = Noop.collect }));
    try testing.expectError(error.NameCollision, reg.registerCollector(&.{
        .{ .name = "q_sum", .help = "h", .kind = .gauge },
        .{ .name = "q", .help = "h", .kind = .summary },
    }, .{ .collect = Noop.collect }));
}

// ── tests added by the 2026-10-18 mutation audit ────────────────────────────

test "exemplars: an observation equal to a bound carries its exemplar in that bucket" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const h = try reg.histogram("eq_seconds", "h", &.{}, &.{ 1, 5 });
    try h.observeWithExemplar(1, &.{.{ .name = "s", .value = "x" }}, null);
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try reg.writeOpenMetrics(&w);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "eq_seconds_bucket{le=\"1.0\"} 1 # {s=\"x\"} 1.0\n") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "eq_seconds_bucket{le=\"5.0\"} 1\n") != null);
}

test "buckets: fillExponentialBucketsRange accepts min == max, refuses a descending range" {
    var one: [1]f64 = undefined;
    try fillExponentialBucketsRange(&one, 2, 2);
    try testing.expectEqual(@as(f64, 2), one[0]);
    var three: [3]f64 = undefined;
    try fillExponentialBucketsRange(&three, 2, 2);
    for (three) |b| try testing.expectEqual(@as(f64, 2), b);
    try testing.expectError(error.InvalidBuckets, fillExponentialBucketsRange(&three, 2, 1));
    var none: [0]f64 = .{};
    try testing.expectError(error.InvalidBuckets, fillExponentialBucketsRange(&none, 1, 2));
    try testing.expectError(error.InvalidBuckets, fillLinearBuckets(&none, 1, 1));
}

test "summary: a refused descriptor leaves no family; options are compared field by field" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    // max_objectives distinct quantiles, the last one exactly 1, are fine;
    // one more is not.
    var objs: [max_objectives + 1]Objective = undefined;
    for (&objs, 0..) |*o, i| o.* = .{ .quantile = @as(f64, @floatFromInt(i)) / max_objectives, .epsilon = 0.01 };
    _ = try reg.summary("max_objs", "h", &.{}, .{ .objectives = objs[1..] });
    try testing.expectError(error.InvalidObjectives, reg.summary("too_many", "h", &.{}, .{ .objectives = &objs }));
    try testing.expect(reg.family_index.get("too_many") == null);

    const good: Objective = .{ .quantile = 0.5, .epsilon = 0.05 };
    try testing.expectError(error.InvalidObjectives, reg.summary("b_cap", "h", &.{}, .{ .objectives = &.{good}, .buf_cap = 0 }));
    try testing.expect(reg.family_index.get("b_cap") == null);
    try testing.expectError(error.InvalidObjectives, reg.summary("b_age", "h", &.{}, .{ .objectives = &.{good}, .max_age_ns = 4, .age_buckets = 5 }));
    try testing.expect(reg.family_index.get("b_age") == null);
    try testing.expectError(error.InvalidObjectives, reg.summary("b_eps", "h", &.{}, .{ .objectives = &.{.{ .quantile = 0.5, .epsilon = 1 }} }));
    try testing.expect(reg.family_index.get("b_eps") == null);

    const base: SummaryOptions = .{ .objectives = &.{good}, .max_age_ns = 1000, .age_buckets = 2, .buf_cap = 100 };
    _ = try reg.summary("mm", "h", &.{}, base);
    _ = try reg.summary("mm", "h", &.{}, base);
    var o = base;
    o.buf_cap = 200;
    try testing.expectError(error.ObjectivesMismatch, reg.summary("mm", "h", &.{}, o));
    o = base;
    o.age_buckets = 4;
    try testing.expectError(error.ObjectivesMismatch, reg.summary("mm", "h", &.{}, o));
    o = base;
    o.objectives = &.{.{ .quantile = 0.5, .epsilon = 0.06 }};
    try testing.expectError(error.ObjectivesMismatch, reg.summary("mm", "h", &.{}, o));
}

test "callbacks: refusals leave the family clean and never mix callbacks with other series" {
    const Noop = struct {
        fn collect(_: ?*anyopaque, _: *Sink) anyerror!void {}
    };
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var x: f64 = 1;
    try testing.expectError(error.InvalidUtf8, reg.gaugeFunc("u8_func", "h", &.{.{ .name = "k", .value = "\xff" }}, &x, constValue));
    try testing.expect(reg.family_index.get("u8_func") == null);
    // An ordinary series first, a callback with another label value second.
    _ = try reg.gauge("mixed", "h", &.{.{ .name = "k", .value = "a" }});
    try testing.expectError(error.AlreadyRegistered, reg.gaugeFunc("mixed", "h", &.{.{ .name = "k", .value = "b" }}, &x, constValue));
    // A collector's family takes no callbacks.
    try reg.registerCollector(&.{.{ .name = "owned", .help = "h", .kind = .gauge }}, .{ .collect = Noop.collect });
    try testing.expectError(error.AlreadyRegistered, reg.gaugeFunc("owned", "h", &.{}, &x, constValue));
}

test "registerCollector: a repeated name is refused; look-alike names are not collisions" {
    const Noop = struct {
        fn collect(_: ?*anyopaque, _: *Sink) anyerror!void {}
    };
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    try testing.expectError(error.AlreadyRegistered, reg.registerCollector(&.{
        .{ .name = "dup", .help = "h", .kind = .gauge },
        .{ .name = "dup", .help = "h", .kind = .gauge },
    }, .{ .collect = Noop.collect }));
    try testing.expect(reg.family_index.get("dup") == null);
    // `cc_sum` is not derived from a counter; `lat2_x_sum` has a middle part
    // `lat2` never emits; `bb_sum` has the length of `aa_sum` but another stem.
    try reg.registerCollector(&.{
        .{ .name = "cc", .help = "h", .kind = .counter },
        .{ .name = "cc_sum", .help = "h", .kind = .counter },
        .{ .name = "lat2", .help = "h", .kind = .histogram },
        .{ .name = "lat2_x_sum", .help = "h", .kind = .gauge },
        .{ .name = "aa", .help = "h", .kind = .histogram },
        .{ .name = "bb_sum", .help = "h", .kind = .gauge },
    }, .{ .collect = Noop.collect });
}

test "OpenMetrics: only a counter's _total suffix is dropped from the announced name" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    (try reg.gauge("level_total", "h", &.{})).set(2);
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try reg.writeOpenMetrics(&w);
    try testing.expectEqualStrings("# HELP level_total h\n# TYPE level_total gauge\nlevel_total 2.0\n# EOF\n", w.buffered());
}

test "collector: Sink refuses desc == len, non-finite or equal bounds, malformed quantile lists" {
    const Noop = struct {
        fn collect(_: ?*anyopaque, _: *Sink) anyerror!void {}
    };
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    try reg.registerCollector(&test_descs, .{ .collect = Noop.collect });
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var sink: Sink = .{ .w = &w, .entry = reg.families.items[0].collector.?, .format = .text };
    try testing.expectError(error.InvalidDesc, sink.gauge(test_descs.len, &.{}, 1));
    try testing.expectError(error.InvalidBuckets, sink.histogram(2, &.{}, &.{ 1, std.math.inf(f64) }, &.{ 1, 2 }, 0, 2));
    try testing.expectError(error.InvalidBuckets, sink.histogram(2, &.{}, &.{ 1, 1 }, &.{ 1, 2 }, 0, 2));
    try testing.expectEqualStrings("", w.buffered());

    var reg2 = Registry.init(testing.allocator);
    defer reg2.deinit();
    try reg2.registerCollector(&.{.{ .name = "cs", .help = "h", .kind = .summary }}, .{ .collect = Noop.collect });
    var buf2: [1024]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    var sink2: Sink = .{ .w = &w2, .entry = reg2.families.items[0].collector.?, .format = .text };
    const q5: Objective = .{ .quantile = 0.5, .epsilon = 0 };
    const q9: Objective = .{ .quantile = 0.9, .epsilon = 0 };
    try testing.expectError(error.InvalidBuckets, sink2.summary(0, &.{}, &.{ q5, q9 }, &.{1}, 1, 1));
    try testing.expectError(error.InvalidBuckets, sink2.summary(0, &.{}, &.{ q5, q5 }, &.{ 1, 2 }, 1, 1));
    try testing.expectEqualStrings("", w2.buffered());
    // A quantile of exactly 1 is allowed.
    try sink2.summary(0, &.{}, &.{.{ .quantile = 1, .epsilon = 0 }}, &.{3}, 3, 1);
    try testing.expect(std.mem.indexOf(u8, w2.buffered(), "cs{quantile=\"1\"} 3\n") != null);
}

test "Format.negotiate: equal weights prefer the concrete type; a foreign range never matches" {
    try testing.expectEqual(Format.text, Format.negotiate("*/*;version=1.0.0,text/plain"));
    try testing.expectEqual(Format.text, Format.negotiate("text/plain,*/*;version=1.0.0"));
    try testing.expectEqual(Format.text, Format.negotiate("application/json;version=1.0.0"));
}

test "middleware: the request size counts the declared Content-Length" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var rm = try RequestMetrics.init(&reg, .{ .request_size_buckets = &.{100} });
    var ep: Endpoint = .{ .registry = &reg };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(rm.middleware());
    try r.use(ep.middleware());
    try r.post("/p", hOk);
    var buf: [8192]u8 = undefined;
    // "/p" 2 + "POST" 4 + "HTTP/1.1" 8 + "Host"+"t" 5 + "Connection"+"close" 15
    // + "Content-Length"+"5" 15 + 5 declared body bytes = 54.
    _ = runWire(&r, "POST /p HTTP/1.1\r\nHost: t\r\nConnection: close\r\nContent-Length: 5\r\n\r\nhello", &buf);
    const got = runWire(&r, wire("GET", "/metrics"), &buf);
    try expectBodyLine(got, "http_request_size_bytes_sum{method=\"post\"} 54");
}

test "ProcessCollector: without a boot time there is no start-time sample" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var pc: ProcessCollector = .{ .gpa = testing.allocator, .io = testing.io };
    try pc.register(&reg, "");
    pc.btime = 0;
    var buf: [8192]u8 = undefined;
    const out = try scrapeInto(&reg, &buf);
    try testing.expect(std.mem.indexOf(u8, out, "process_start_time_seconds") == null);
    try testing.expect(std.mem.indexOf(u8, out, "process_open_fds ") != null);
}

test "Vec: delete with a wrong number of values never matches (the tuple comparison is length-safe)" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const v = try reg.counterVec("wl_total", "h", &.{ "a", "b" });
    for (0..8) |i| {
        var k: [8]u8 = undefined;
        const key = std.fmt.bufPrint(&k, "s{d}", .{i}) catch unreachable;
        _ = try v.with(&.{ key, "x" });
    }
    // The map compares a 7-bit fingerprint before the tuples, so over many
    // probes some land on a stored entry of another length.
    var removed: usize = 0;
    for (0..20000) |i| {
        var k: [16]u8 = undefined;
        const key = std.fmt.bufPrint(&k, "q{d}", .{i}) catch unreachable;
        if (v.delete(&.{key})) removed += 1;
    }
    try testing.expectEqual(@as(usize, 0), removed);
    try testing.expectEqual(@as(usize, 8), v.len());
}

test "retire/reap: freed at once with no scrape; the oldest running ticket decides" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const v = try reg.counterVec("rt_total", "h", &.{"k"});
    _ = try v.with(&.{"z"});
    try testing.expect(v.delete(&.{"z"}));
    try testing.expectEqual(@as(usize, 0), reg.retired.items.len);

    // Scrapes 3 and 5 are running; a removal at seq 4 is held by 3 only.
    try reg.scrapes.append(testing.allocator, 3);
    try reg.scrapes.append(testing.allocator, 5);
    reg.scrape_seq = 4;
    _ = try v.with(&.{"a"});
    try testing.expect(v.delete(&.{"a"}));
    reg.reapLocked();
    try testing.expectEqual(@as(usize, 1), reg.retired.items.len);
    // A removal at seq 5: scrape 5 started after it, scrape 3 did not.
    reg.scrape_seq = 5;
    _ = try v.with(&.{"b"});
    try testing.expect(v.delete(&.{"b"}));
    try testing.expectEqual(@as(usize, 2), reg.retired.items.len);
    // Scrape 3 ends: both are free (ticket 5 cannot hold a series removed at seq 5).
    _ = reg.scrapes.swapRemove(0);
    reg.reapLocked();
    try testing.expectEqual(@as(usize, 0), reg.retired.items.len);
}

// ── external anchor: client_golang + expfmt + textparse ────────────────────
// See go_oracle_test.zig / tools/interop.zig / tools/go_oracle.
test {
    _ = summary_mod;
    _ = @import("go_oracle_test.zig");
    _ = @import("go_register_test.zig");
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    const rep_result = comptime blk: {
        @setEvalBranchQuota(n * (s.len + 4) + 1000);
        var buf: [s.len * n:0]u8 = undefined;
        for (0..n) |i| @memcpy(buf[i * s.len ..][0..s.len], s);
        const rep_final = buf;
        break :blk rep_final;
    };
    return &rep_result;
}
