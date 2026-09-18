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
//! are a few string compares / adds. `writeText` holds the registry lock
//! only long enough to snapshot the family/children pointers (O(number of
//! families), not O(series)) and formats from that snapshot with the lock
//! released — registering a new family/child never has to wait for a
//! scrape's formatting to finish (audit F2, fixed 2026-09-15). Registration
//! is get-or-register, so steady-state request paths only *read* under the
//! lock-free caches and never register.

const std = @import("std");
const router = @import("router");
const http = @import("http");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Prometheus registry (counter/gauge/histogram) + `/metrics` + request middleware + access-log writer (combined/JSON)",
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
    .deps = .{ "router", "http" },
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
/// formats outside it, `AccessLog.log` never holds the lock across writer
/// I/O. That measurement never had more threads than cores; the bounded spin
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
            // the holder is descheduled. Measured on the `AccessLog F4`
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
/// start with `__` (reserved by Prometheus), and not be `le` or `quantile`
/// (reserved for a histogram's own bucket bound / a summary's own quantile
/// — `RegisterError.ReservedLabelName`, any instrument kind; audit F13).
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
    /// Label name must match `[a-zA-Z_][a-zA-Z0-9_]*` and not start with
    /// the reserved `__`. (`le`/`quantile` are rejected too, but as
    /// `ReservedLabelName`, not this.)
    InvalidLabelName,
    /// The label name `le` (reserved for a histogram's own bucket bound) or
    /// `quantile` (reserved for a summary, which this module does not
    /// implement) was passed as a caller-supplied label — on ANY
    /// instrument kind, matching client_golang's reserved-name check
    /// (audit F13: previously only rejected on histograms, which let a
    /// counter or gauge register a `le` label that then collided with a
    /// same-named histogram's own bucket samples — see F5).
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
    /// Guards `families`/`family_index` (lookup + registration) and
    /// `writeText` iteration.
    lock: std.atomic.Mutex = .unlocked,
    /// Registration order — `writeText` iterates this so exposition order
    /// stays deterministic (registration order, not sorted; see `writeText`).
    families: std.ArrayList(*Family) = .empty,
    /// Name -> family, O(1) get-or-register lookup. `families` stays the
    /// source of iteration order; this is purely an index into it.
    family_index: std.StringHashMapUnmanaged(*Family) = .empty,
    /// Advisory size of the last `writeText` output, used to pre-size the
    /// next scrape's transient buffer so a steady-state registry (typical:
    /// scrape interval far exceeds registration churn) does not repeatedly
    /// double-and-copy that buffer mid-format. A stale or zero hint just
    /// falls back to `Allocating`'s normal grow-as-needed behavior — this
    /// changes only how much is pre-reserved, never what gets emitted.
    exposition_size_hint: std.atomic.Value(usize) = .init(0),

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
        if (!std.unicode.utf8ValidateSlice(help)) return error.InvalidUtf8;
        if (labels.len > max_labels) return error.TooManyLabels;
        for (labels) |l| {
            if (!validLabelName(l.name)) return error.InvalidLabelName;
            // `le`/`quantile` are reserved on every kind (F13) — see
            // `RegisterError.ReservedLabelName`.
            if (std.mem.eql(u8, l.name, "le") or std.mem.eql(u8, l.name, "quantile"))
                return error.ReservedLabelName;
            if (!std.unicode.utf8ValidateSlice(l.value)) return error.InvalidUtf8;
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

        const fam = if (r.family_index.get(name)) |f| f else blk: {
            try r.checkSuffixCollisionLocked(name, kind);
            const f = try a.create(Family);
            f.* = .{
                .name = try a.dupe(u8, name),
                .help = try a.dupe(u8, help),
                .kind = kind,
                .label_names = try dupeStrings(a, labels, .name),
                .buckets = if (kind == .histogram) try a.dupe(f64, buckets) else &.{},
            };
            try r.families.append(a, f);
            try r.family_index.put(a, f.name, f);
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

        // F2: hold `r.lock` only long enough to copy the family/children
        // SLICE HEADERS (pointer + length; O(number of families) word
        // copies), then format from that snapshot with the lock released.
        // `families`/`family_index`/each family's `children` are
        // append-only over the arena (registration never removes or frees
        // a Child/Family, and `ArenaAllocator` never frees on grow
        // either), so a snapshot taken here just may miss a series
        // registered after this instant -- the same race a scrape already
        // has against registration, lock or no lock. What the lock
        // protects is the pair of memory words `ArrayList.append` writes
        // (`items.ptr`, `items.len`) from being read torn while another
        // thread is mid-append; it is not needed to read a Counter/Gauge
        // (lock-free/atomic, see their doc comments) or a Histogram
        // (guarded by its OWN per-instrument `h.lock` in `writeHistogram`,
        // independent of `r.lock`) once the pointer is in hand. Formatting
        // used to run inside this same critical section: measured at 3.7x
        // the CPU under 8 concurrent scrapers, and the registry's own wall
        // clock got worse under load because `lockSpin` never yields
        // (audit F2; re-measured in this A/B, see commit message).
        const snapshot: []const FamilySnapshot = blk: {
            lockSpin(&r.lock);
            defer r.lock.unlock();
            const out = r.arena.child_allocator.alloc(FamilySnapshot, r.families.items.len) catch
                return error.WriteFailed;
            for (r.families.items, out) |fam, *slot| slot.* = .{ .fam = fam, .children = fam.children.items };
            break :blk out;
        };
        defer r.arena.child_allocator.free(snapshot);

        for (snapshot) |entry| {
            const fam = entry.fam;
            try bw.print("# HELP {s} ", .{fam.name});
            try writeEscaped(bw, fam.help, .help);
            try bw.print("\n# TYPE {s} {t}\n", .{ fam.name, fam.kind });
            for (entry.children) |c| {
                switch (c.data) {
                    .counter => |*ctr| {
                        try bw.writeAll(fam.name);
                        try writeLabels(bw, fam.label_names, c.label_values, null);
                        try bw.print(" {d}\n", .{ctr.value()});
                    },
                    .gauge => |*g| {
                        try bw.writeAll(fam.name);
                        try writeLabels(bw, fam.label_names, c.label_values, null);
                        try bw.writeByte(' ');
                        try writeFloat(bw, g.value());
                        try bw.writeByte('\n');
                    },
                    .histogram => |*h| try writeHistogram(bw, fam, c, h),
                }
            }
        }
        r.exposition_size_hint.store(buf.written().len, .monotonic);
        try w.writeAll(buf.written());
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
        const in_flight = try registry.gauge(options.in_flight_name, options.in_flight_help, &.{});
        _ = try registry.counter(options.counter_name, options.counter_help, &.{
            .{ .name = "method", .value = @tagName(http.Method.get) },
            .{ .name = "code", .value = classLabel(2) },
        });
        _ = try registry.histogram(options.histogram_name, options.histogram_help, &.{
            .{ .name = "method", .value = @tagName(http.Method.get) },
        }, options.buckets);
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
        // Streaming against a declared length. `res.declared_len.?` is
        // deliberate, not `res.body.identity`: the latter looks like the
        // declared total but is actually `http`'s *remaining*-bytes budget
        // for the over/under-delivery guard — it decrements as the handler
        // writes and is mid-flight (not the declared length, and not 0
        // either) at the point this runs, still inside the handler's own
        // middleware frame, before `end()`'s final flush. Measured: reading
        // `res.body.identity` here for a declared 5000-byte body reported
        // 392. `declared_len` is the one field that stays the declared
        // total for the life of the response (see the module's audit, F11,
        // where the missing test for this branch let a mutation survive —
        // the branch had no coverage, not necessarily a wrong unwrap).
        .identity => res.declared_len.?,
        .discard => 0, // HEAD / 204 / 304: no body on the wire
        .chunked, .until_close, .gzip => null, // streamed; no running total kept
    };
}

// ── default access-log writer ───────────────────────────────────────────────

/// A ready-made structured access-log *writer* for the `AccessEntry` hook.
/// `RequestMetrics` exposes the hook but ships no writer; this is the default
/// one, so a caller need only wire the two together instead of hand-rolling a
/// formatter:
///
/// ```zig
/// var log_writer = std.fs.File.stdout().writer(&buf);
/// var access = metrics.AccessLog.init(&log_writer.interface, .{});
/// var rm = try metrics.RequestMetrics.init(&reg, .{
///     .on_request = metrics.AccessLog.onRequest,
///     .on_request_ctx = &access, // AccessLog must outlive the middleware
/// });
/// ```
///
/// **Default format is `.json`** — one object per line, machine-friendly for
/// log pipelines. `.combined` emits the Apache/NGINX Common/Combined Log
/// Format (a documented de-facto format).
///
/// Only the fields `AccessEntry` actually carries are emitted: method, path,
/// status, `duration_ns`, bytes. The Combined format's host / ident / user /
/// time / protocol / referer / user-agent slots have no counterpart on the
/// entry, so each is rendered as the CLF placeholder `-` (`[-]` for the time);
/// callers who want those must prepend/wrap their own. (A request-id field is
/// not on `AccessEntry` today; when one lands it can be added here.)
///
/// Thread-safety: the hook fires on each request task, so by default
/// (`synchronized = true`) concurrent calls share `writer` through a group
/// commit rather than a lock held across I/O (the module's audit, F4: the
/// spinlock used to be held across `writer.flush()`, so every other request
/// thread spun for the whole syscall — 25.4 µs of CPU per line at 8 threads
/// against 1.47 µs at one, into a plain file). Now:
///
/// - each line is formatted under the spinlock straight into an inline
///   pending batch (no syscall, no stack buffer, no allocation);
/// - at most one caller at a time — the *flusher* — touches `writer`, and it
///   does so with the spinlock released: it swaps the batch out, writes and
///   flushes it, and repeats until the batch is empty, so concurrent callers
///   only append;
/// - a line is never split: it enters the batch whole or not at all, and a
///   line too long for the batch is written whole by its own caller after it
///   becomes the flusher. Lines from different calls interleave only at line
///   boundaries; lines from one thread keep their call order;
/// - when the batch is full, a caller waits (lock released, watching a
///   progress counter rather than the lock) for the flusher to swap it out. The flusher hands the role to such a waiter after
///   each batch, so under a sustained rate the sink cannot keep up with, no
///   single request is left writing everyone else's lines indefinitely.
///
/// When no `log` call is in flight, every logged line has been handed to
/// `writer.writeAll` and flushed — the batch is empty — so there is no
/// `deinit` and nothing to drain before dropping an `AccessLog`. A call can
/// return while its line is still in the batch, but only when another call is
/// the flusher and is committed to writing it before it returns. Set
/// `synchronized = false` only when the caller already serializes writes to
/// `writer`; the batch is then unused and each call writes and flushes
/// directly.
///
/// Allocation-free: the pending batch is inline in the struct. The writer is
/// flushed after every batch, so records reach the sink promptly. Writer
/// errors are swallowed — an access log must never fail the request that
/// produced it; with batching, a failed write is swallowed by whichever call
/// was the flusher, and the lines it carried are lost exactly as a single
/// failed line was before (the error, if any, stays on the caller's writer,
/// e.g. `std.Io.File.Writer.err`). `path` is
/// unvalidated bytes from the request line — HTTP/2 does not bound them to
/// printable ASCII the way HTTP/1.1 does — but neither writer panics on
/// them, and neither can produce an injection (quote/backslash escaping
/// holds either way): the JSON writer escapes `"`, `\` and control bytes
/// 0x00-0x1F, and replaces any byte that is not part of a valid UTF-8
/// sequence with U+FFFD, one byte at a time, so its output is always valid
/// JSON and valid UTF-8 (closes the module's audit F3 — PROBE H no longer
/// reproduces); the CLF writer additionally escapes DEL (0x7F) as `\xHH`
/// and passes 0x80-0xFF through raw (CLF carries no UTF-8 promise to keep).
pub const AccessLog = struct {
    writer: *std.Io.Writer,
    options: Options,
    lock: std.atomic.Mutex = .unlocked,

    // Group-commit state (see the doc comment above). Every field below is
    // written only with `lock` held, and read only with it held except
    // `progress`. `pending[pending_idx]` is the
    // batch callers append to; the other buffer is the one the flusher may be
    // writing with the lock released, which is why a swap (not a copy or a
    // reset in place) is what hands a batch over.
    pending: [2][pending_capacity]u8 = undefined,
    pending_idx: u1 = 0,
    pending_len: usize = 0,
    /// Some call owns `writer` (is the flusher). Cleared only with the lock
    /// held and either `pending_len == 0` or `waiters > 0`.
    flushing: bool = false,
    /// Calls whose line did not fit while another call was the flusher,
    /// waiting with the lock released until they can append or take over.
    waiters: u32 = 0,
    /// Bumped, with the lock held, whenever a waiter's answer can change:
    /// the batch was swapped out (there is room) or the flusher role was
    /// given up. Waiters watch it WITHOUT the lock — the one field read
    /// outside it — so waiting never competes with the flusher for `lock`.
    progress: std.atomic.Value(u32) = .init(0),

    const pending_capacity = 4096;

    pub const Format = enum {
        /// One JSON object per line (default).
        json,
        /// Apache/NGINX Combined Log Format.
        combined,
    };

    pub const Options = struct {
        format: Format = .json,
        /// Guard the writer with the module spinlock so concurrent request
        /// tasks never interleave lines. Disable only if the caller serializes
        /// writes to `writer` itself.
        synchronized: bool = true,
    };

    pub fn init(writer: *std.Io.Writer, options: Options) AccessLog {
        return .{ .writer = writer, .options = options };
    }

    /// Adapter matching `RequestMetrics.Options.on_request`. Wire it as
    /// `on_request = AccessLog.onRequest` with `on_request_ctx = &your_access_log`.
    pub fn onRequest(ctx: ?*anyopaque, entry: AccessEntry) void {
        const self: *AccessLog = @ptrCast(@alignCast(ctx.?));
        self.log(entry);
    }

    /// Format one entry as a line and write it. Best-effort: writer errors are
    /// swallowed. When `synchronized`, the spinlock is held only while the
    /// line is formatted into the pending batch, never across `writer` I/O —
    /// see the type's doc comment for the group commit.
    pub fn log(self: *AccessLog, entry: AccessEntry) void {
        if (!self.options.synchronized) {
            writeLine(self.writer, self.options.format, entry) catch {};
            self.writer.flush() catch {};
            return;
        }
        lockSpin(&self.lock);
        var waiting = false;
        while (true) {
            if (waiting) {
                self.waiters -= 1;
                waiting = false;
            }
            if (self.appendPending(entry)) {
                // Someone else owns the writer and must write the batch
                // (including this line) before it gives the role up.
                if (self.flushing) return self.lock.unlock();
                self.flushing = true;
                self.writeBatch(); // this line is in it
                return self.finishFlushing();
            }
            if (!self.flushing) {
                // Too long for what is left of the batch (or for any batch).
                // Take the writer: first everything queued before this call,
                // then this line, whole, straight to the writer.
                self.flushing = true;
                self.writeBatch();
                self.lock.unlock();
                writeLine(self.writer, self.options.format, entry) catch {};
                self.writer.flush() catch {};
                lockSpin(&self.lock);
                return self.finishFlushing();
            }
            // Batch full and a flusher is active: wait for it to swap the
            // batch out or hand the role over. Never with the lock held, and
            // without touching the lock until `progress` moves: waiters that
            // re-took the lock on every spin kept the flusher from getting it
            // back after each write (F4 test past its 3-minute limit on the
            // 4-core arm64 CI runner; 15 s on 4 x86 cores vs 1.1 s on one).
            self.waiters += 1;
            waiting = true;
            const seen = self.progress.load(.monotonic);
            self.lock.unlock();
            waitForProgress(&self.progress, seen);
            lockSpin(&self.lock);
        }
    }

    /// Format `entry` into the current batch. Lock held. On overflow the
    /// partial bytes past `pending_len` are simply not committed.
    fn appendPending(self: *AccessLog, entry: AccessEntry) bool {
        var w: std.Io.Writer = .fixed(self.pending[self.pending_idx][self.pending_len..]);
        writeLine(&w, self.options.format, entry) catch return false;
        self.pending_len += w.end;
        return true;
    }

    /// Flusher only, lock held on entry and on return: swap the batch out,
    /// then write and flush it with the lock released. Appenders move on to
    /// the other buffer, which nobody is writing.
    fn writeBatch(self: *AccessLog) void {
        std.debug.assert(self.flushing);
        if (self.pending_len == 0) return;
        const idx = self.pending_idx;
        const len = self.pending_len;
        self.pending_idx ^= 1;
        self.pending_len = 0;
        _ = self.progress.fetchAdd(1, .monotonic);
        self.lock.unlock();
        self.writer.writeAll(self.pending[idx][0..len]) catch {};
        self.writer.flush() catch {};
        lockSpin(&self.lock);
    }

    /// Flusher only, lock held on entry, released on return. Keeps writing
    /// batches until none is left — or until a waiter exists, in which case
    /// the role is handed over with lines still queued: a waiter re-checks
    /// with the lock held and either appends while another call is flushing
    /// or becomes the flusher itself, so a non-empty batch is never orphaned.
    fn finishFlushing(self: *AccessLog) void {
        while (self.pending_len != 0 and self.waiters == 0) self.writeBatch();
        self.flushing = false;
        _ = self.progress.fetchAdd(1, .monotonic);
        self.lock.unlock();
    }

    /// Wait, lock released, until `progress` differs from `seen`. A bounded
    /// spin, then yields, as in `lockSpin`: with more waiters than cores the
    /// flusher needs the core. No ordering is needed — the waiter re-reads
    /// everything under `lock` afterwards; this only decides when to try.
    fn waitForProgress(progress: *const std.atomic.Value(u32), seen: u32) void {
        var spins: u32 = 0;
        while (progress.load(.monotonic) == seen) {
            if (spins < spin_before_yield) {
                spins += 1;
                std.atomic.spinLoopHint();
            } else {
                std.Thread.yield() catch {};
            }
        }
    }

    fn writeLine(w: *std.Io.Writer, format: Format, entry: AccessEntry) std.Io.Writer.Error!void {
        switch (format) {
            .json => {
                try w.writeAll("{\"method\":");
                try writeJsonString(w, entry.method.token());
                try w.writeAll(",\"path\":");
                try writeJsonString(w, entry.path);
                try w.print(
                    ",\"status\":{d},\"duration_ns\":{d},\"bytes\":",
                    .{ entry.status, entry.duration_ns },
                );
                if (entry.bytes) |b| try w.print("{d}", .{b}) else try w.writeAll("null");
                try w.writeAll("}\n");
            },
            .combined => {
                // host ident authuser [time] "request" status bytes "referer" "ua"
                // The entry carries none of host/ident/user/time/proto/referer/ua,
                // so those slots are the CLF placeholder "-".
                try w.writeAll("- - - [-] \"");
                try writeClfQuoted(w, entry.method.token());
                try w.writeByte(' ');
                try writeClfQuoted(w, entry.path);
                try w.print("\" {d} ", .{entry.status});
                if (entry.bytes) |b| try w.print("{d}", .{b}) else try w.writeByte('-');
                try w.writeAll(" \"-\" \"-\"\n");
            },
        }
    }
};

/// Write `s` as a double-quoted JSON string, escaping the characters JSON
/// requires (`"`, `\`, and control bytes 0x00-0x1F). Bytes >= 0x20 that
/// belong to a valid UTF-8 sequence pass through verbatim; a byte that does
/// not (F3 in the module's audit -- reachable in `entry.path` via h2, which
/// does not bound `:path` to printable ASCII the way h1 does) is replaced
/// with U+FFFD, one byte at a time, so a single bad byte cannot
/// desynchronize the rest of the string. RFC 9110's obs-text allows
/// 0x80-0xFF in a field value, so `http` is right not to reject it -- this
/// module is where "always valid JSON, always valid UTF-8" has to hold.
fn writeJsonString(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    try w.writeByte('"');
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        if (c < 0x80) {
            switch (c) {
                '"' => try w.writeAll("\\\""),
                '\\' => try w.writeAll("\\\\"),
                0x08 => try w.writeAll("\\b"),
                0x09 => try w.writeAll("\\t"),
                0x0A => try w.writeAll("\\n"),
                0x0C => try w.writeAll("\\f"),
                0x0D => try w.writeAll("\\r"),
                0x00...0x07, 0x0B, 0x0E...0x1F => try w.print("\\u{x:0>4}", .{c}),
                else => try w.writeByte(c),
            }
            i += 1;
            continue;
        }
        const seq_len = std.unicode.utf8ByteSequenceLength(c) catch {
            try w.writeAll("\u{FFFD}");
            i += 1;
            continue;
        };
        if (i + seq_len > s.len or !std.unicode.utf8ValidateSlice(s[i .. i + seq_len])) {
            try w.writeAll("\u{FFFD}");
            i += 1;
            continue;
        }
        try w.writeAll(s[i .. i + seq_len]);
        i += seq_len;
    }
    try w.writeByte('"');
}

/// Write `s` escaped for a Combined-Log-Format quoted field: `"` and `\` are
/// backslash-escaped, control bytes and DEL become `\xHH` (Apache convention).
fn writeClfQuoted(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        0x00...0x1F, 0x7F => try w.print("\\x{x:0>2}", .{c}),
        else => try w.writeByte(c),
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
    try testing.expectError(error.ReservedLabelName, reg.histogram("h1", "x", &.{.{ .name = "le", .value = "v" }}, &.{}));
    // F13: `le`/`quantile` are reserved on EVERY instrument kind now, not
    // just histograms/summaries — client_golang reserves both regardless of
    // kind, and this module's own bucket `le` / (unimplemented) summary
    // `quantile` never flow through this caller-supplied label path, so
    // there is no legitimate use of either name here. Previously `le` was
    // accepted on a counter, which is the exact mechanism F5's collision
    // (`<h>_bucket{le=...}`) needed.
    try testing.expectError(error.ReservedLabelName, reg.counter("a_total", "x", &.{.{ .name = "le", .value = "v" }}));
    try testing.expectError(error.ReservedLabelName, reg.gauge("a_gauge", "x", &.{.{ .name = "quantile", .value = "0.5" }}));

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

// ── tests: access-log writer ─────────────────────────────────────────────────

test "AccessLog: json format writes one object per request; specials escaped" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var access = AccessLog.init(&w, .{ .format = .json });

    // Drive it through the exact hook adapter a caller would wire.
    AccessLog.onRequest(&access, .{
        .method = .get,
        .path = "/api/\"weird\"\tpath",
        .status = 200,
        .duration_ns = 1500,
        .bytes = 1234,
    });

    try testing.expectEqualStrings(
        "{\"method\":\"GET\",\"path\":\"/api/\\\"weird\\\"\\tpath\"," ++
            "\"status\":200,\"duration_ns\":1500,\"bytes\":1234}\n",
        w.buffered(),
    );
}

// F3 in the module's audit: h2 does not bound `:path` to printable ASCII
// the way h1's `MalformedHead` guard does (`h1.zig:438` vs.
// `h2_server.zig:1416-1419`), so a byte that is not part of any valid UTF-8
// sequence is reachable in `entry.path` from the wire (PROBE H measured
// this end to end: a raw 0xFF made the whole access-log line fail both
// `std.unicode.utf8ValidateSlice` and `std.json`'s parse). RFC 9110's
// obs-text explicitly allows 0x80-0xFF in a field value, so the fix belongs
// on this side -- the module turning bytes into JSON -- not in `http`.
test "AccessLog: json format replaces an invalid UTF-8 byte with U+FFFD, one byte at a time (F3)" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var access = AccessLog.init(&w, .{ .format = .json });

    access.log(.{ .method = .get, .path = "/a\xffb", .status = 404, .duration_ns = 1, .bytes = 0 });

    const got = w.buffered();
    try testing.expectEqualStrings(
        "{\"method\":\"GET\",\"path\":\"/a\u{FFFD}b\"," ++
            "\"status\":404,\"duration_ns\":1,\"bytes\":0}\n",
        got,
    );
    try testing.expect(std.unicode.utf8ValidateSlice(got));
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, got, .{});
    defer parsed.deinit();
}

// A valid multi-byte UTF-8 sequence (unlike a lone invalid byte, above)
// must pass through unchanged -- the fix decodes one sequence at a time
// rather than rejecting every byte >= 0x80, which would mangle any
// legitimately non-ASCII path.
test "AccessLog: json format passes a valid multi-byte UTF-8 sequence through unchanged" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var access = AccessLog.init(&w, .{ .format = .json });

    access.log(.{ .method = .get, .path = "/caf\xc3\xa9", .status = 200, .duration_ns = 1, .bytes = 0 }); // "café"

    try testing.expectEqualStrings(
        "{\"method\":\"GET\",\"path\":\"/caf\xc3\xa9\"," ++
            "\"status\":200,\"duration_ns\":1,\"bytes\":0}\n",
        w.buffered(),
    );
}

// Regression for F15/M33 in the module's audit: the existing "specials
// escaped" test above only exercises control bytes with their own named
// escape (`\t`, 0x09) — `writeJsonString`'s *range* branch
// (0x00-0x07, 0x0B, 0x0E-0x1F -> `\uXXXX`) had no test at all, so mutating
// it away (JSON escaping is the only escaping in the module reachable from
// wire bytes — an h2 request path can carry these, see F3) survived the
// whole suite. 0x01 and 0x1F fall only into the range branch, not any
// single-character case above.
test "AccessLog: json format escapes range control bytes (0x01, 0x1F), not just the named ones" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var access = AccessLog.init(&w, .{ .format = .json });

    access.log(.{ .method = .get, .path = "/a\x01b\x1fc", .status = 200, .duration_ns = 1, .bytes = 0 });

    try testing.expectEqualStrings(
        "{\"method\":\"GET\",\"path\":\"/a\\u0001b\\u001fc\"," ++
            "\"status\":200,\"duration_ns\":1,\"bytes\":0}\n",
        w.buffered(),
    );
}

test "AccessLog: json bytes=null renders JSON null" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var access = AccessLog.init(&w, .{ .format = .json });

    access.log(.{ .method = .head, .path = "/x", .status = 204, .duration_ns = 7, .bytes = null });

    try testing.expectEqualStrings(
        "{\"method\":\"HEAD\",\"path\":\"/x\",\"status\":204,\"duration_ns\":7,\"bytes\":null}\n",
        w.buffered(),
    );
}

test "AccessLog: combined format is CLF with placeholders and a quoted, escaped request" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var access = AccessLog.init(&w, .{ .format = .combined });

    // bytes=null → the CLF "-"; the quote and space in the path stay inside
    // the quoted request field, with the quote backslash-escaped.
    access.log(.{
        .method = .post,
        .path = "/p a\"th",
        .status = 404,
        .duration_ns = 10,
        .bytes = null,
    });
    // A second record with a real byte count appends a whole second line.
    access.log(.{ .method = .get, .path = "/ok", .status = 200, .duration_ns = 1, .bytes = 0 });

    try testing.expectEqualStrings(
        "- - - [-] \"POST /p a\\\"th\" 404 - \"-\" \"-\"\n" ++
            "- - - [-] \"GET /ok\" 200 0 \"-\" \"-\"\n",
        w.buffered(),
    );
}

// Regression for F15/M34 in the module's audit: `writeJsonString` got a
// range-control-byte test (M33, above) but its CLF sibling `writeClfQuoted`
// never did, so the same class of mutation (drop the `0x00...0x1F, 0x7F =>
// \xHH` branch) survived the suite on the CLF side. Path is the only
// wire-reachable field in either format (see F3), so this is the CLF half
// of the same coverage gap.
test "AccessLog: combined format escapes control bytes and DEL (0x01, 0x7F) as \\xHH" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var access = AccessLog.init(&w, .{ .format = .combined });

    access.log(.{ .method = .get, .path = "/a\x01b\x7fc", .status = 200, .duration_ns = 1, .bytes = 0 });

    try testing.expectEqualStrings(
        "- - - [-] \"GET /a\\x01b\\x7fc\" 200 0 \"-\" \"-\"\n",
        w.buffered(),
    );
}

test "AccessLog: synchronized writes never interleave across threads" {
    var buf: [64 * 1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var access = AccessLog.init(&w, .{ .format = .json, .synchronized = true });

    const Worker = struct {
        fn run(a: *AccessLog, id: usize) void {
            var i: usize = 0;
            while (i < 100) : (i += 1) {
                a.log(.{
                    .method = .get,
                    .path = "/t",
                    .status = @intCast(200 + id),
                    .duration_ns = 1,
                    .bytes = 0,
                });
            }
        }
    };

    const n_threads = 4;
    var threads: [n_threads]std.Thread = undefined;
    for (&threads, 0..) |*t, id| t.* = try std.Thread.spawn(.{}, Worker.run, .{ &access, id });
    for (&threads) |t| t.join();

    // Every '\n'-delimited line must be a whole, well-formed record — proof
    // that no two threads' lines interleaved under the lock.
    var it = std.mem.tokenizeScalar(u8, w.buffered(), '\n');
    var count: usize = 0;
    while (it.next()) |line| {
        count += 1;
        try testing.expect(line.len > 2 and line[0] == '{' and line[line.len - 1] == '}');
        const ok = std.mem.indexOf(u8, line, "\"status\":200,") != null or
            std.mem.indexOf(u8, line, "\"status\":201,") != null or
            std.mem.indexOf(u8, line, "\"status\":202,") != null or
            std.mem.indexOf(u8, line, "\"status\":203,") != null;
        try testing.expect(ok);
    }
    try testing.expectEqual(@as(usize, n_threads * 100), count);
}

// ── F15 M29/M31/M32: does the lock actually get TAKEN? ─────────────────────
//
// The three stress tests above (and the module's own mutation audit, F15)
// converge on the same shape: racing many threads over MANY iterations and
// checking the aggregate is a race against a narrow window, and a critical
// section of a few string compares is too short for the window to ever
// open in practice — which is exactly why M29 (`writeText` dropping its
// `lockSpin`), M31 (`getOrRegister` dropping its `lockSpin`) and M32
// (`AccessLog.log` dropping its `lockSpin` even with `synchronized = true`)
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

test "F15/M32: AccessLog.log actually takes its lock when synchronized" {
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var access = AccessLog.init(&w, .{ .format = .json, .synchronized = true });

    lockSpin(&access.lock);

    var done = std.atomic.Value(bool).init(false);
    const Ctx = struct {
        access: *AccessLog,
        done: *std.atomic.Value(bool),
        fn run(ctx: *@This()) void {
            ctx.access.log(.{ .method = .get, .path = "/m32", .status = 200, .duration_ns = 1, .bytes = 0 });
            ctx.done.store(true, .seq_cst);
        }
    };
    var ctx: Ctx = .{ .access = &access, .done = &done };
    const t = try std.Thread.spawn(.{}, Ctx.run, .{&ctx});

    sleepMs(50);
    try testing.expect(!done.load(.seq_cst));

    access.lock.unlock();
    t.join();
    try testing.expect(done.load(.seq_cst));
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "/m32") != null);
}

// ── F4 bench (opt-in): AccessLog under concurrency into a real file ────────
//
//   METRICS_BENCH_F4=1 LINES=80 scripts/modtest metrics -Doptimize=ReleaseFast -Dtest-filter=F4
//
// The sink is a buffered `std.Io.File.Writer` on a file under `.zig-cache/tmp`
// (disk, not tmpfs), so every `flush()` is a real `pwritev`. Arms are
// interleaved inside every rep; each pass re-reads the file and fails unless it
// holds exactly threads × lines newline-terminated records.

fn f4ClockNs(clock: std.os.linux.clockid_t) u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(clock, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Arms: `spin_over_flush` is the pre-F4 `AccessLog.log`, verbatim (spinlock
/// held across `writeLine` AND `writer.flush()`), kept here only as the
/// bench's "before" arm; `group_commit` is the shipped `AccessLog.log`.
const F4Arm = enum { spin_over_flush, group_commit };

fn f4SpinOverFlush(self: *AccessLog, entry: AccessEntry) void {
    lockSpin(&self.lock);
    defer self.lock.unlock();
    AccessLog.writeLine(self.writer, self.options.format, entry) catch {};
    self.writer.flush() catch {};
}

/// The audit's BENCH E sink shape: every drain sleeps (so the time is a
/// blocked syscall, not CPU) and counts the newlines it swallowed.
const F4SlowSink = struct {
    interface: std.Io.Writer,
    delay_ns: u64,
    newlines: usize = 0,

    fn init(buf: []u8, delay_ns: u64) F4SlowSink {
        return .{ .interface = .{ .vtable = &.{ .drain = drain }, .buffer = buf }, .delay_ns = delay_ns };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *F4SlowSink = @alignCast(@fieldParentPtr("interface", w));
        self.newlines += std.mem.count(u8, w.buffered(), "\n");
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            self.newlines += std.mem.count(u8, d, "\n");
            n += d.len;
        }
        const last = data[data.len - 1];
        self.newlines += std.mem.count(u8, last, "\n") * splat;
        n += last.len * splat;
        const ts: std.os.linux.timespec = .{ .sec = 0, .nsec = @intCast(self.delay_ns) };
        _ = std.os.linux.nanosleep(&ts, null);
        return n;
    }
};

const F4Sink = enum { file, slow_0_2ms };

const F4Result = struct { cpu_ns: u64, wall_ns: u64 };

fn f4Run(access: *AccessLog, arm: F4Arm, threads: usize, lines: usize) !F4Result {
    const Worker = struct {
        fn run(a: *AccessLog, which: F4Arm, id: usize, n: usize) void {
            for (0..n) |i| {
                const e: AccessEntry = .{
                    .method = .get,
                    .path = "/api/v1/tasks/1234567?expand=owner",
                    .status = 200,
                    .duration_ns = id * 1_000_000 + i,
                    .bytes = 512,
                };
                switch (which) {
                    .spin_over_flush => f4SpinOverFlush(a, e),
                    .group_commit => a.log(e),
                }
            }
        }
    };
    var pool: [8]std.Thread = undefined;
    const c0 = f4ClockNs(.PROCESS_CPUTIME_ID);
    const w0 = f4ClockNs(.MONOTONIC);
    for (pool[0..threads], 0..) |*t, id| t.* = try std.Thread.spawn(.{}, Worker.run, .{ access, arm, id, lines });
    for (pool[0..threads]) |t| t.join();
    const w1 = f4ClockNs(.MONOTONIC);
    const c1 = f4ClockNs(.PROCESS_CPUTIME_ID);
    return .{ .cpu_ns = c1 - c0, .wall_ns = w1 - w0 };
}

fn f4Pass(arm: F4Arm, sink: F4Sink, threads: usize, lines: usize) !F4Result {
    var wbuf: [4096]u8 = undefined;
    switch (sink) {
        .file => {
            const io = testing.io;
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            const file = try tmp.dir.createFile(io, "f4.log", .{});
            var fw = file.writer(io, &wbuf);
            var access = AccessLog.init(&fw.interface, .{});
            const res = try f4Run(&access, arm, threads, lines);
            file.close(io);
            const data = try tmp.dir.readFileAlloc(io, "f4.log", testing.allocator, .unlimited);
            defer testing.allocator.free(data);
            try testing.expectEqual(threads * lines, std.mem.count(u8, data, "\n"));
            return res;
        },
        .slow_0_2ms => {
            var s = F4SlowSink.init(&wbuf, 200_000);
            var access = AccessLog.init(&s.interface, .{});
            const res = try f4Run(&access, arm, threads, lines);
            try testing.expectEqual(threads * lines, s.newlines + std.mem.count(u8, s.interface.buffered(), "\n"));
            return res;
        },
    }
}

test "bench (opt-in via METRICS_BENCH_F4): F4 AccessLog.log cost under concurrency" {
    if (@import("builtin").mode == .Debug or std.testing.environ.getPosix("METRICS_BENCH_F4") == null) return error.SkipZigTest;
    const reps = 7;
    const tcounts = [_]usize{ 1, 2, 4, 8 };
    const arms = comptime std.enums.values(F4Arm);
    const sinks = comptime std.enums.values(F4Sink);
    var cpu: [sinks.len][tcounts.len][arms.len][reps]f64 = undefined;
    var wall: [sinks.len][tcounts.len][arms.len][reps]f64 = undefined;
    // Every (sink, threads, arm) cell once per rep, arms adjacent, so drift
    // over the run lands on both arms of a pair alike.
    for (0..reps) |r| {
        for (sinks, 0..) |sink, si| {
            const lines: usize = if (sink == .file) 5000 else 100;
            for (tcounts, 0..) |tc, ti| {
                for (arms, 0..) |arm, ai| {
                    const res = try f4Pass(arm, sink, tc, lines);
                    const total: f64 = @floatFromInt(tc * lines);
                    cpu[si][ti][ai][r] = @as(f64, @floatFromInt(res.cpu_ns)) / total;
                    wall[si][ti][ai][r] = @as(f64, @floatFromInt(res.wall_ns)) / total;
                }
            }
        }
    }
    for (sinks, 0..) |sink, si| {
        for (tcounts, 0..) |tc, ti| {
            // Per-rep before/after ratio (one instant), then its spread.
            var ratio: [reps]f64 = undefined;
            for (0..reps) |r| ratio[r] = cpu[si][ti][0][r] / cpu[si][ti][1][r];
            std.mem.sort(f64, &ratio, {}, std.sort.asc(f64));
            for (arms, 0..) |arm, ai| {
                var c = cpu[si][ti][ai];
                var w = wall[si][ti][ai];
                std.mem.sort(f64, &c, {}, std.sort.asc(f64));
                std.mem.sort(f64, &w, {}, std.sort.asc(f64));
                std.debug.print("F4 {t:<10} T={d} {t:<15} CPU ns/line {d:>8.0} {d:>8.0} {d:>8.0}  wall ns/line {d:>8.0} {d:>8.0} {d:>8.0}\n", .{
                    sink, tc, arm, c[0], c[reps / 2], c[reps - 1], w[0], w[reps / 2], w[reps - 1],
                });
            }
            std.debug.print("F4 {t:<10} T={d} CPU before/after per rep: min={d:.2} med={d:.2} max={d:.2}\n", .{
                sink, tc, ratio[0], ratio[reps / 2], ratio[reps - 1],
            });
        }
    }
}

// ── F4 regression tests: the group commit keeps lines whole, once, in order ──

fn f4PollUntil(flag: *const std.atomic.Value(bool), timeout_ms: u64) bool {
    var waited: u64 = 0;
    while (!flag.load(.seq_cst)) : (waited += 1) {
        if (waited >= timeout_ms) return false;
        sleepMs(1);
    }
    return true;
}

fn f4AssertIdle(a: *AccessLog) !void {
    lockSpin(&a.lock);
    defer a.lock.unlock();
    try testing.expectEqual(@as(usize, 0), a.pending_len);
    try testing.expect(!a.flushing);
    try testing.expectEqual(@as(u32, 0), a.waiters);
}

/// Deterministic per-(thread, seq) path: "/t<id>/s<seq>/" + padding. Every
/// 37th line is longer than a whole batch (the owner path); the rest vary in
/// length so batch boundaries fall at every offset.
fn f4Path(buf: []u8, id: usize, seq: usize) []const u8 {
    const head = std.fmt.bufPrint(buf, "/t{d}/s{d}/", .{ id, seq }) catch unreachable;
    const pad: usize = if (seq % 37 == 5) AccessLog.pending_capacity + 300 else (id * 31 + seq * 7) % 180;
    @memset(buf[head.len..][0..pad], 'a' + @as(u8, @intCast((id + seq) % 26)));
    return buf[0 .. head.len + pad];
}

test "AccessLog F4: threads x lines into a real file -- every line whole, exactly once, in per-thread order" {
    const io = testing.io;
    const threads = 8;
    const lines = 400;
    const rounds: usize = if (std.testing.environ.getPosix("METRICS_F4_ROUNDS")) |s| std.fmt.parseInt(usize, s, 10) catch 3 else 3;

    const Worker = struct {
        fn run(a: *AccessLog, id: usize) void {
            var pbuf: [AccessLog.pending_capacity + 512]u8 = undefined;
            for (0..lines) |seq| a.log(.{
                .method = .get,
                .path = f4Path(&pbuf, id, seq),
                .status = 200,
                .duration_ns = id * 1_000_000 + seq,
                .bytes = seq,
            });
        }
    };
    const Line = struct { method: []const u8, path: []const u8, status: u16, duration_ns: u64, bytes: u64 };

    for (0..rounds) |_| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const file = try tmp.dir.createFile(io, "f4.log", .{});
        // A small writer buffer, so `writeAll`/`flush` drain constantly: any
        // two callers inside the writer at once show up as torn bytes.
        var wbuf: [256]u8 = undefined;
        var fw = file.writer(io, &wbuf);
        var access = AccessLog.init(&fw.interface, .{});

        var pool: [threads]std.Thread = undefined;
        for (&pool, 0..) |*t, id| t.* = try std.Thread.spawn(.{}, Worker.run, .{ &access, id });
        for (pool) |t| t.join();
        try f4AssertIdle(&access);
        file.close(io);

        const data = try tmp.dir.readFileAlloc(io, "f4.log", testing.allocator, .unlimited);
        defer testing.allocator.free(data);
        try testing.expect(data.len > 0 and data[data.len - 1] == '\n');

        var next_seq: [threads]usize = @splat(0);
        var count: usize = 0;
        var pbuf: [AccessLog.pending_capacity + 512]u8 = undefined;
        var it = std.mem.splitScalar(u8, data[0 .. data.len - 1], '\n');
        while (it.next()) |raw| {
            count += 1;
            const parsed = try std.json.parseFromSlice(Line, testing.allocator, raw, .{});
            defer parsed.deinit();
            const id = parsed.value.duration_ns / 1_000_000;
            const seq = parsed.value.duration_ns % 1_000_000;
            try testing.expect(id < threads);
            // Exactly once and in call order per thread: the next line of
            // thread `id` must be exactly the next sequence number.
            try testing.expectEqual(next_seq[id], seq);
            next_seq[id] += 1;
            try testing.expectEqual(seq, parsed.value.bytes);
            try testing.expectEqualStrings(f4Path(&pbuf, id, seq), parsed.value.path);
        }
        try testing.expectEqual(@as(usize, threads * lines), count);
    }
}

test "AccessLog F4: a writer that always fails neither hangs callers nor leaves the batch owned" {
    const Failing = struct {
        interface: std.Io.Writer,
        fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            _ = w;
            _ = data;
            _ = splat;
            return error.WriteFailed;
        }
    };
    var wbuf: [64]u8 = undefined;
    var sink: Failing = .{ .interface = .{ .vtable = &.{ .drain = Failing.drain }, .buffer = &wbuf } };
    var access = AccessLog.init(&sink.interface, .{});

    const threads = 4;
    var done: [threads]std.atomic.Value(bool) = @splat(std.atomic.Value(bool).init(false));
    const Worker = struct {
        fn run(a: *AccessLog, id: usize, flag: *std.atomic.Value(bool)) void {
            var pbuf: [AccessLog.pending_capacity + 512]u8 = undefined;
            for (0..300) |seq| a.log(.{ .method = .post, .path = f4Path(&pbuf, id, seq), .status = 500, .duration_ns = 1, .bytes = null });
            flag.store(true, .seq_cst);
        }
    };
    var pool: [threads]std.Thread = undefined;
    for (&pool, 0..) |*t, id| t.* = try std.Thread.spawn(.{}, Worker.run, .{ &access, id, &done[id] });
    var all = true;
    for (&done) |*d| all = all and f4PollUntil(d, 10_000);
    try testing.expect(all); // a stuck `flushing` would spin every caller forever
    for (pool) |t| t.join();
    try f4AssertIdle(&access);
}

/// A sink with no buffer (every write is one drain) whose drains each need a
/// permit from the test, so a test can park the flusher inside the write.
const F4Gate = struct {
    interface: std.Io.Writer,
    drains: std.atomic.Value(u32) = .init(0),
    permits: std.atomic.Value(u32) = .init(0),
    newlines: std.atomic.Value(usize) = .init(0),

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *F4Gate = @alignCast(@fieldParentPtr("interface", w));
        _ = self.drains.fetchAdd(1, .seq_cst);
        while (true) {
            const p = self.permits.load(.seq_cst);
            if (p > 0 and self.permits.cmpxchgWeak(p, p - 1, .seq_cst, .seq_cst) == null) break;
            sleepMs(1);
        }
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            _ = self.newlines.fetchAdd(std.mem.count(u8, d, "\n"), .seq_cst);
            n += d.len;
        }
        _ = self.newlines.fetchAdd(std.mem.count(u8, data[data.len - 1], "\n") * splat, .seq_cst);
        return n + data[data.len - 1].len * splat;
    }
};

test "AccessLog F4: a line appended while the flusher writes is written before the flusher returns" {
    // The promptness half of the contract: a call may return with its line
    // still queued only because an active flusher is committed to writing it.
    // Park the flusher A in its first drain, append B's line (B returns at
    // once), let A go: when A returns, B's line must be on the sink and the
    // batch empty. Without the flusher's re-check B's line would sit in the
    // batch until some later call happened to come along.
    var gate: F4Gate = .{ .interface = .{ .vtable = &.{ .drain = F4Gate.drain }, .buffer = &.{} } };
    var access = AccessLog.init(&gate.interface, .{});
    const entry: AccessEntry = .{ .method = .get, .path = "/p", .status = 200, .duration_ns = 1, .bytes = 0 };

    const Logger = struct {
        fn run(a: *AccessLog, e: AccessEntry, flag: *std.atomic.Value(bool)) void {
            a.log(e);
            flag.store(true, .seq_cst);
        }
    };
    var a_done = std.atomic.Value(bool).init(false);
    var b_done = std.atomic.Value(bool).init(false);
    const ta = try std.Thread.spawn(.{}, Logger.run, .{ &access, entry, &a_done });
    while (gate.drains.load(.seq_cst) < 1) sleepMs(1);
    const tb = try std.Thread.spawn(.{}, Logger.run, .{ &access, entry, &b_done });
    const b_returned = f4PollUntil(&b_done, 2_000); // B only appends
    gate.permits.store(1_000_000, .seq_cst);
    ta.join();
    tb.join();
    try testing.expect(b_returned);
    try testing.expectEqual(@as(usize, 2), gate.newlines.load(.seq_cst));
    try f4AssertIdle(&access);
}

test "AccessLog F4: the flusher hands off to a waiter instead of writing everyone's lines forever" {
    // A sink with no buffer (so every batch is one drain) whose drains each
    // need a permit from the test. Thread A becomes the flusher and parks in
    // its first drain; the test fills the batch; thread W arrives with a line
    // that does not fit and waits. One permit later A must RETURN — with W's
    // line and the fill still queued — rather than go on to write them.
    const Gate = F4Gate;
    var gate: Gate = .{ .interface = .{ .vtable = &.{ .drain = Gate.drain }, .buffer = &.{} } };
    var access = AccessLog.init(&gate.interface, .{});
    const entry: AccessEntry = .{ .method = .get, .path = "/fill", .status = 200, .duration_ns = 7, .bytes = 1 };

    const Logger = struct {
        fn run(a: *AccessLog, e: AccessEntry, flag: *std.atomic.Value(bool)) void {
            a.log(e);
            flag.store(true, .seq_cst);
        }
    };
    var a_done = std.atomic.Value(bool).init(false);
    var w_done = std.atomic.Value(bool).init(false);
    const ta = try std.Thread.spawn(.{}, Logger.run, .{ &access, entry, &a_done });
    while (gate.drains.load(.seq_cst) < 1) sleepMs(1);

    var one: [256]u8 = undefined;
    var ow: std.Io.Writer = .fixed(&one);
    try AccessLog.writeLine(&ow, .json, entry);
    const line_len = ow.end;
    // Bounded lock acquisition: an implementation that holds the lock across
    // writer I/O would park A inside the gated drain WITH the lock, and a
    // plain `lockSpin` here would hang the suite instead of failing it.
    const bounded = struct {
        fn lock(m: *std.atomic.Mutex) bool {
            for (0..2_000) |_| {
                if (m.tryLock()) return true;
                sleepMs(1);
            }
            return false;
        }
    };
    var fills: usize = 0;
    const filled = while (true) {
        if (!bounded.lock(&access.lock)) break false;
        const room = AccessLog.pending_capacity - access.pending_len;
        access.lock.unlock();
        if (room < line_len) break true;
        access.log(entry); // A is the flusher: this only appends
        fills += 1;
    };
    if (!filled) {
        gate.permits.store(1_000_000, .seq_cst);
        ta.join();
        return error.TestUnexpectedResult; // lock held across the sink write
    }

    const tw = try std.Thread.spawn(.{}, Logger.run, .{ &access, entry, &w_done });
    const saw_waiter = for (0..2_000) |_| {
        if (!bounded.lock(&access.lock)) break false;
        const waiting = access.waiters;
        access.lock.unlock();
        if (waiting == 1) break true;
        sleepMs(1);
    } else false;
    if (!saw_waiter) {
        gate.permits.store(1_000_000, .seq_cst);
        ta.join();
        tw.join();
        return error.TestUnexpectedResult; // W never became a waiter
    }

    gate.permits.store(1, .seq_cst);
    const handed_off = f4PollUntil(&a_done, 2_000);
    const drains_when_a_returned = gate.drains.load(.seq_cst);

    gate.permits.store(1_000_000, .seq_cst); // release everything before asserting
    ta.join();
    tw.join();
    try testing.expect(handed_off);
    try testing.expect(drains_when_a_returned <= 2); // A's one batch (+ W's, parked)
    try testing.expect(w_done.load(.seq_cst));
    try f4AssertIdle(&access);
    try testing.expectEqual(fills + 2, gate.newlines.load(.seq_cst));
}
