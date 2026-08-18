// SPDX-License-Identifier: MIT
//! jobqueue — durable background-job queue over the pure-Zig `kv` log:
//! enqueue / lease / ack / nack with retry+backoff, dead-letter queue, and
//! per-partition FIFO ordering under a priority override.
//!
//! ## Why an in-memory index over `kv`
//!
//! `kv` is a Bitcask-style point store: `put` / `get` / `delete` by key and
//! **nothing else** — no scan, no ordered iteration, its keydir is private.
//! A queue needs to *enumerate* ready work and pick the best candidate, so
//! jobqueue keeps its own in-memory index (a `jobs` map, the `pending`/`parts`
//! ready pair described at "the two ordered structures behind dispatch"
//! below, a `leased` table, a `dlq` set) and treats `kv` purely as the durable
//! record of truth. The index is rebuilt from `kv` on `open`.
//!
//! Dispatch order is **strict priority, ties FIFO by enqueue id, across
//! partitions as well as within one** — so high-priority work can starve
//! low-priority work indefinitely, by design. See `dequeue`.
//!
//! **Enumeration without scan — the durable id counter.** Every job is keyed
//! `j/<id>` where `<id>` comes from a durable, monotonically increasing
//! counter stored at `m/next_id`. `enqueue` writes the job record (fsync'd by
//! `kv`) and *then* bumps the counter (also fsync'd): a returned `enqueue`
//! is fully durable, and a crash between the two writes leaves an orphan
//! record that is simply never referenced (the counter still points before
//! it). Recovery is a bounded linear replay: for `id in 1..next_id`,
//! `kv.get(j/<id>)` — a `null` (acked ⇒ `kv.delete`d) is skipped, a present
//! record is decoded and re-indexed.
//!
//! ## Two clocks (both injected for deterministic tests)
//!
//! - **wall** (`WallClock`, `i64` ns since the Unix epoch) drives the
//!   *schedule*: a job's `run_at` (absolute) or `delay_ns` (relative) — when
//!   it first becomes visible — and the retry-backoff visibility after a
//!   `nack`.
//! - **monotonic** (`MonoClock`, `u64` ns) drives *lease expiry*: a dequeued
//!   job is invisible until either acked or its visibility timeout lapses.
//!   `std` has no `time.timestamp` in 0.16, so the OS defaults go straight
//!   through `clock_gettime` (posix); both are injectable.
//!
//! ## Delivery model (honesty note)
//!
//! This is **at-least-once**. A lease is an *in-memory*, single-process
//! reservation (there is no cross-process lock in `kv`); a crash re-exposes
//! every un-acked job as ready on the next `open`. Make your consumer
//! idempotent. See the DEFER list at the bottom of this doc comment for the
//! full set of v1 non-goals.

const std = @import("std");
const Allocator = std.mem.Allocator;
const kv = @import("kv");

pub const meta = .{
    // The OS-default wall/monotonic clocks use posix `clock_gettime`; both
    // are injectable, everything else is pure logic + the `kv` store.
    .targets = .{.linux64},
    .platform = .posix,
    .role = .both,
    // One owner drives the queue and the caller-driven maintenance sweep
    // (`reapExpiredLeases`); the in-memory index is not internally locked.
    .concurrency = .single_owner,
    .model_after = "Faktory / Sidekiq (lease + retry + DLQ) over a Bitcask log; injected-Clock pattern from resilience/jwt",
    .deps = .{"kv"},
};

// ── clocks ───────────────────────────────────────────────────────────────────

/// Wall-clock time source (Unix-epoch nanoseconds), injected so the schedule
/// (`run_at` / `delay_ns` / backoff visibility) is deterministic under test.
pub const WallClock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (?*anyopaque) i64,

    /// The OS wall clock (`CLOCK_REALTIME` via posix `clock_gettime`) — the
    /// production default. `std` has no `time.timestamp` in 0.16.
    pub const system: WallClock = .{ .nowFn = systemNowNs };

    pub fn now(c: WallClock) i64 {
        return c.nowFn(c.ctx);
    }
};

fn systemNowNs(_: ?*anyopaque) i64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts)) != .SUCCESS) return 0;
    return @as(i64, @intCast(ts.sec)) * std.time.ns_per_s + @as(i64, @intCast(ts.nsec));
}

/// Monotonic time source (nanoseconds, arbitrary origin), injected so lease
/// expiry is deterministic under test. Must be non-decreasing.
pub const MonoClock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (?*anyopaque) u64,

    /// The OS monotonic clock (`CLOCK_MONOTONIC` via posix `clock_gettime`) —
    /// the production default.
    pub const monotonic: MonoClock = .{ .nowFn = monotonicNowNs };

    pub fn now(c: MonoClock) u64 {
        return c.nowFn(c.ctx);
    }
};

fn monotonicNowNs(_: ?*anyopaque) u64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

// ── public value types ───────────────────────────────────────────────────────

/// Distinct durable job identifier (the monotonic counter value). Opaque —
/// use `@intFromEnum` only for logging.
pub const JobId = enum(u64) { _ };

/// Dispatch priority. Higher enum value = dispatched first; ties break FIFO
/// (oldest `JobId`). A real field — no id-arithmetic tricks.
pub const Priority = enum(u8) { low = 0, normal = 1, high = 2, critical = 3 };

/// Errors jobqueue adds on top of `kv`'s storage/allocation errors.
pub const Error = error{
    /// `payload` exceeds `Options.max_payload` — stash the blob elsewhere
    /// (e.g. the `blobstore` module) and enqueue a reference instead.
    PayloadTooLarge,
    /// `job_type` or `partition` exceeds `max_field_len`.
    FieldTooLarge,
    /// The lease no longer owns the job: its visibility timeout lapsed and it
    /// was reaped/re-leased, or it was already acked. The job (if still
    /// present) belongs to whoever holds the current lease — do nothing.
    StaleLease,
    /// A stored job record failed to decode (should never happen on a store
    /// this module wrote; `kv` already CRC-guards every record).
    CorruptRecord,
};

/// A reservation handed out by `dequeue`. Borrowed fields (`job_type`,
/// `payload`, `partition`) point into the queue's own memory and stay valid
/// until you `ack`/`nack` this lease **or** its visibility timeout lapses —
/// after which `reapExpiredLeases` may recycle the job. Copy them out if you
/// need them longer.
pub const Lease = struct {
    id: JobId,
    /// Delivery number: 1 on the first dispatch, incremented each redelivery.
    attempt: u32,
    job_type: []const u8,
    payload: []const u8,
    partition: []const u8,

    // Lease generation — guards against a stale lease acking a job that has
    // since been reaped and re-leased to someone else.
    epoch: u32,
};

/// A dead-lettered job, copied out for the caller (see `deadLetterList`).
pub const DeadLetter = struct {
    id: JobId,
    job_type: []const u8,
    payload: []const u8,
    partition: []const u8,
    attempts: u32,
};

pub const EnqueueOptions = struct {
    /// FIFO grouping key; "" = the default partition. Jobs within one
    /// partition dispatch oldest-first (under the priority override).
    partition: []const u8 = "",
    priority: Priority = .normal,
    /// Relative visibility delay from now (wall clock). Ignored if `run_at`
    /// is set.
    delay_ns: u64 = 0,
    /// Absolute earliest visibility (wall-clock ns since epoch). Overrides
    /// `delay_ns` when non-null.
    run_at: ?i64 = null,
    /// Total delivery attempts before dead-lettering. Must be ≥ 1.
    max_attempts: u32 = 5,
};

pub const DequeueOptions = struct {
    /// null = any partition; non-null = only this partition (the ex-taskqueue
    /// `nextFor(partition)` FIFO fold).
    partition: ?[]const u8 = null,
    /// How long (monotonic ns) the lease holds the job invisible before
    /// `reapExpiredLeases` may return it to the ready set.
    visibility_timeout_ns: u64,
};

pub const NackOptions = struct {
    /// Explicit requeue backoff (wall ns). null = the exponential policy
    /// (`Options.backoff_*`, optionally jittered by `Options.random`).
    backoff_ns: ?u64 = null,
};

pub const Options = struct {
    wall_clock: WallClock = .system,
    mono_clock: MonoClock = .monotonic,
    /// App-level cap on `payload` size. `kv` itself has no meaningful cap
    /// (a value is one whole record) — keep jobs small and reference large
    /// blobs out of band.
    max_payload: usize = 1 << 20, // 1 MiB
    /// Exponential retry backoff after a `nack` (no explicit `backoff_ns`):
    /// `base × factor^(attempt-1)`, capped at `max`. Shape mirrors
    /// resilience's `Retry`.
    backoff_base_ns: u64 = std.time.ns_per_s,
    backoff_factor: f64 = 2.0,
    backoff_max_ns: u64 = 300 * std.time.ns_per_s,
    /// Optional entropy for **full jitter** on the backoff (uniform in
    /// `[0, computed]`). null = deterministic (no jitter) — Debug and
    /// ReleaseFast agree.
    random: ?std.Random = null,
};

/// Largest `job_type` / `partition` accepted.
pub const max_field_len: usize = 4096;

// ── on-`kv` record format ────────────────────────────────────────────────────
//
//   [0]      version  u8 (= 1)
//   [1]      state    u8 (0 = ready, 1 = dead)
//   [2]      priority u8
//   [3..7)   attempts     u32 LE
//   [7..11)  max_attempts u32 LE
//   [11..19) run_at_ns    i64 LE
//   [19..23) job_type_len  u32 LE
//   [23..27) partition_len u32 LE
//   [27..31) payload_len   u32 LE
//   [31..]   job_type ++ partition ++ payload

const rec_version: u8 = 1;
const rec_fixed = 31;

const JobState = enum(u8) { ready = 0, dead = 1 };

const Job = struct {
    id: u64,
    job_type: []u8,
    payload: []u8,
    partition: []u8,
    priority: Priority,
    state: JobState,
    attempts: u32,
    max_attempts: u32,
    run_at_ns: i64,
    /// In-memory lease generation (durable state does not need it).
    lease_epoch: u32,
};

const meta_key = "m/next_id";

fn jobKey(buf: *[24]u8, id: u64) []const u8 {
    return std.fmt.bufPrint(buf, "j/{d}", .{id}) catch unreachable;
}

fn addNs(wall: i64, ns: u64) i64 {
    const clamped: i64 = @intCast(@min(ns, @as(u64, std.math.maxInt(i64))));
    return wall +| clamped;
}

// ── the two ordered structures behind dispatch ───────────────────────────────
//
// A job in the ready state is in exactly one of them:
//
//   `pending` — a single min-heap keyed by (`run_at_ns`, id): every ready job
//     whose schedule has not been observed to arrive yet. `delay_ns`/`run_at`
//     jobs and `nack` backoffs live here. Freshly enqueued jobs land here too
//     (with `run_at_ns` already in the past for the common no-delay case) so
//     that `enqueue` needs to reserve capacity in exactly one structure.
//
//   `parts[partition]` — one max-heap per partition keyed by (priority desc,
//     id asc): the jobs that are visible *now*.
//
// `dequeue` first drains every due entry out of `pending` into its partition
// heap, then picks a winner among the partition heap tops. That is the whole
// reason two structures are needed: a single heap ordered by priority would
// surface a job whose `run_at_ns` has not arrived, and popping past it to look
// for a visible one destroys the ordering.

/// Ready-but-not-yet-visible: ordered by schedule, ties by enqueue order.
const PendingEntry = struct { run_at_ns: i64, id: u64 };

fn pendingBefore(a: PendingEntry, b: PendingEntry) bool {
    if (a.run_at_ns != b.run_at_ns) return a.run_at_ns < b.run_at_ns;
    return a.id < b.id;
}

/// Visible now: highest priority first, ties by oldest id (FIFO). The id
/// tiebreak is what makes dispatch deterministic — never rely on heap layout.
const ReadyEntry = struct { priority: u8, id: u64 };

fn readyBefore(a: ReadyEntry, b: ReadyEntry) bool {
    if (a.priority != b.priority) return a.priority > b.priority;
    return a.id < b.id;
}

/// Minimal binary heap over an unmanaged array — `before(a, b)` = "a sits
/// closer to the root". Push is split into a fallible `ensureUnusedCapacity`
/// and an infallible `pushAssumeCapacity` so callers can reserve *before* the
/// durable write and keep the post-persist index commit unable to fail.
fn Heap(comptime T: type, comptime before: fn (T, T) bool) type {
    return struct {
        items: std.ArrayListUnmanaged(T) = .empty,

        const Self = @This();

        fn deinit(h: *Self, gpa: Allocator) void {
            h.items.deinit(gpa);
        }

        fn len(h: Self) usize {
            return h.items.items.len;
        }

        fn peek(h: Self) ?T {
            return if (h.items.items.len == 0) null else h.items.items[0];
        }

        fn ensureUnusedCapacity(h: *Self, gpa: Allocator, n: usize) Allocator.Error!void {
            return h.items.ensureUnusedCapacity(gpa, n);
        }

        fn pushAssumeCapacity(h: *Self, v: T) void {
            h.items.appendAssumeCapacity(v);
            var i = h.items.items.len - 1;
            while (i > 0) {
                const parent = (i - 1) / 2;
                if (!before(h.items.items[i], h.items.items[parent])) break;
                std.mem.swap(T, &h.items.items[i], &h.items.items[parent]);
                i = parent;
            }
        }

        fn pop(h: *Self) ?T {
            if (h.items.items.len == 0) return null;
            const top = h.items.items[0];
            const last = h.items.pop().?;
            if (h.items.items.len == 0) return top;
            h.items.items[0] = last;
            var i: usize = 0;
            while (true) {
                const l = 2 * i + 1;
                const r = l + 1;
                var best = i;
                if (l < h.items.items.len and before(h.items.items[l], h.items.items[best])) best = l;
                if (r < h.items.items.len and before(h.items.items[r], h.items.items[best])) best = r;
                if (best == i) break;
                std.mem.swap(T, &h.items.items[i], &h.items.items[best]);
                i = best;
            }
            return top;
        }
    };
}

const PendingHeap = Heap(PendingEntry, pendingBefore);
const PartitionHeap = Heap(ReadyEntry, readyBefore);

// ── Queue ────────────────────────────────────────────────────────────────────

pub const Queue = struct {
    gpa: Allocator,
    db: kv.Db,
    opts: Options,
    wall: WallClock,
    mono: MonoClock,

    /// The single source of live in-memory job state (owns every `*Job`).
    jobs: std.AutoHashMapUnmanaged(u64, *Job),
    /// Ready jobs whose schedule has not been observed to arrive: min-heap on
    /// (`run_at_ns`, id). Drained into `parts` by `dequeue`.
    pending: PendingHeap,
    /// Ready and visible now, one max-heap per partition on (priority, id).
    /// Keys are owned dupes; an entry is dropped once its heap empties, so a
    /// workload with unbounded distinct partitions does not accumulate them.
    parts: std.StringHashMapUnmanaged(PartitionHeap),
    /// Ready-set size = `pending` + every partition heap. Kept incrementally so
    /// `readyCount` stays O(1) (it used to be one hash map's `count`).
    ready_n: usize,
    /// Leased ids → monotonic expiry deadline.
    leased: std.AutoHashMapUnmanaged(u64, u64),
    /// Dead-lettered ids (state == dead).
    dlq: std.AutoHashMapUnmanaged(u64, void),

    /// Next id to hand out; mirrors the durable `m/next_id` counter.
    next_id: u64,

    /// Open (or create) the queue at `path` on the given `kv` `Storage`,
    /// replaying the log to rebuild the whole in-memory index.
    pub fn open(gpa: Allocator, store: kv.Storage, path: []const u8, options: Options) !Queue {
        std.debug.assert(options.backoff_factor >= 1.0 and std.math.isFinite(options.backoff_factor));
        var self = Queue{
            .gpa = gpa,
            .db = try kv.Db.open(gpa, store, path, .{}),
            .opts = options,
            .wall = options.wall_clock,
            .mono = options.mono_clock,
            .jobs = .empty,
            .pending = .{},
            .parts = .empty,
            .ready_n = 0,
            .leased = .empty,
            .dlq = .empty,
            .next_id = 1,
        };
        errdefer self.db.close();
        errdefer self.freeIndex();
        try self.recover();
        return self;
    }

    /// Close the underlying store and free all in-memory state.
    pub fn close(self: *Queue) void {
        self.freeIndex();
        self.db.close();
        self.* = undefined;
    }

    // ── enqueue ───────────────────────────────────────────────────────────────

    /// Append a new job and return its durable id. Durable when this returns:
    /// the job record and the bumped counter are both fsync'd.
    pub fn enqueue(self: *Queue, job_type: []const u8, payload: []const u8, opts: EnqueueOptions) !JobId {
        if (payload.len > self.opts.max_payload) return Error.PayloadTooLarge;
        if (job_type.len > max_field_len or opts.partition.len > max_field_len) return Error.FieldTooLarge;
        std.debug.assert(opts.max_attempts >= 1);

        const id = self.next_id;
        const wall = self.wall.now();
        const run_at = opts.run_at orelse addNs(wall, opts.delay_ns);

        const job = try self.gpa.create(Job);
        errdefer self.gpa.destroy(job);
        job.* = .{
            .id = id,
            .job_type = try self.gpa.dupe(u8, job_type),
            .payload = undefined,
            .partition = undefined,
            .priority = opts.priority,
            .state = .ready,
            .attempts = 0,
            .max_attempts = opts.max_attempts,
            .run_at_ns = run_at,
            .lease_epoch = 0,
        };
        errdefer self.gpa.free(job.job_type);
        job.payload = try self.gpa.dupe(u8, payload);
        errdefer self.gpa.free(job.payload);
        job.partition = try self.gpa.dupe(u8, opts.partition);
        errdefer self.gpa.free(job.partition);

        try self.jobs.ensureUnusedCapacity(self.gpa, 1);
        // Every new job enters through `pending` regardless of its schedule —
        // one structure to reserve, and `dequeue` migrates the due ones.
        try self.pending.ensureUnusedCapacity(self.gpa, 1);

        // Durable order: job record first, then the counter. A crash between
        // them orphans the record (never referenced) — a returned enqueue is
        // always fully durable.
        try self.persistJob(job);
        var nb: [8]u8 = undefined;
        std.mem.writeInt(u64, &nb, id + 1, .little);
        try self.db.put(meta_key, &nb);

        self.jobs.putAssumeCapacity(id, job);
        self.pending.pushAssumeCapacity(.{ .run_at_ns = run_at, .id = id });
        self.ready_n += 1;
        self.next_id = id + 1;
        return @enumFromInt(id);
    }

    // ── dequeue / lease ───────────────────────────────────────────────────────

    /// Reserve the best ready job: highest `Priority`, ties oldest-first
    /// (FIFO), respecting `run_at`/`delay` visibility and the optional
    /// partition filter. Returns null when nothing is dispatchable.
    ///
    /// Selection is heap-based (see "the two ordered structures" above): the
    /// due entries of the `pending` schedule heap migrate into their partition
    /// heaps, then the winner is the best of the partition-heap tops — O(1)
    /// lookup with `opts.partition` set, O(partitions) without, plus O(log n)
    /// for the pop, instead of the O(ready) scan v1 used.
    ///
    /// **Ordering is strict priority, ties FIFO by id — including across
    /// partitions.** A partition is a FIFO grouping key and a dispatch filter,
    /// not a fair-share class: an unfiltered `dequeue` still returns the
    /// globally best job, so a steady stream of `.critical` work *will* starve
    /// `.low` work indefinitely. That is deliberate (it is what a priority
    /// override means, and it is v1's behaviour unchanged); a caller that needs
    /// fairness dequeues with an explicit `.partition` per worker, which is
    /// isolated from every other partition's load.
    ///
    /// The wall clock is not required to be monotonic, so a job that migrated
    /// into a partition heap can become invisible again if wall time steps
    /// back. The pop below re-checks `run_at_ns` and demotes such a job back to
    /// `pending`, which keeps the visibility rule exactly the one the v1 scan
    /// enforced: visibility is decided at `dequeue` time, never cached.
    ///
    /// The ordering contract is pinned by tests: "partition FIFO ordering",
    /// "priority ordering: high before an earlier-enqueued low", "FIFO tiebreak
    /// within equal priority", "delay / run_at: a job is invisible until its
    /// schedule", the cross-partition independence pair, and crash recovery.
    pub fn dequeue(self: *Queue, opts: DequeueOptions) !?Lease {
        const wall_now = self.wall.now();
        try self.migrateDue(wall_now);

        const id = id: while (true) {
            const found = self.bestReady(opts.partition) orelse return null;
            const job = self.jobs.get(found.id).?;
            if (job.run_at_ns > wall_now) {
                // Wall clock regressed after this job migrated — put it back.
                try self.demote(found, job.run_at_ns);
                continue;
            }
            // Reserve the lease slot before the pop, so that once the job has
            // left the ready set the commit below cannot fail (v1 relied on the
            // same ordering to avoid dropping a job on OOM).
            try self.leased.ensureUnusedCapacity(self.gpa, 1);
            self.takeTop(found);
            self.ready_n -= 1;
            break :id found.id;
        };
        const job = self.jobs.get(id).?;

        self.leased.putAssumeCapacity(id, self.mono.now() +| opts.visibility_timeout_ns);
        job.lease_epoch +%= 1;
        return .{
            .id = @enumFromInt(id),
            .attempt = job.attempts + 1,
            .job_type = job.job_type,
            .payload = job.payload,
            .partition = job.partition,
            .epoch = job.lease_epoch,
        };
    }

    // ── ack / nack ────────────────────────────────────────────────────────────

    /// Mark the leased job done: a durable `kv.delete`. It never reappears.
    pub fn ack(self: *Queue, lease: Lease) !void {
        const id = try self.validate(lease);
        var kb: [24]u8 = undefined;
        try self.db.delete(jobKey(&kb, id));
        _ = self.leased.remove(id);
        self.removeJob(id);
    }

    /// Fail the leased job: increment its attempt count and requeue with
    /// backoff, or dead-letter it once `max_attempts` is reached.
    pub fn nack(self: *Queue, lease: Lease, opts: NackOptions) !void {
        const id = try self.validate(lease);
        const job = self.jobs.get(id).?;
        const backoff = opts.backoff_ns orelse self.computeBackoff(job.attempts + 1);
        try self.expireLease(id, backoff);
    }

    /// Caller-driven visibility-timeout sweep (like `kv`'s caller-driven
    /// `compact` — no module-owned thread): any lease whose monotonic
    /// deadline has passed is treated as an abandoned worker — the job's
    /// attempt count is bumped and it is returned to the ready set
    /// **immediately** (no backoff; a lost lease is not an app-signalled
    /// failure), or dead-lettered if it has exhausted `max_attempts`.
    /// Returns how many leases were reaped.
    pub fn reapExpiredLeases(self: *Queue) !usize {
        const now = self.mono.now();
        var expired: std.ArrayListUnmanaged(u64) = .empty;
        defer expired.deinit(self.gpa);
        var it = self.leased.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.* <= now) try expired.append(self.gpa, e.key_ptr.*);
        }
        for (expired.items) |id| try self.expireLease(id, 0);
        return expired.items.len;
    }

    // ── dead-letter inspection ────────────────────────────────────────────────

    pub fn deadLetterCount(self: *const Queue) usize {
        return self.dlq.count();
    }

    /// Snapshot every dead-lettered job, copied into `gpa` (free with
    /// `freeDeadLetterList`). Order is unspecified.
    pub fn deadLetterList(self: *Queue, gpa: Allocator) ![]DeadLetter {
        var list = try gpa.alloc(DeadLetter, self.dlq.count());
        var n: usize = 0;
        errdefer {
            for (list[0..n]) |dl| freeDeadLetter(gpa, dl);
            gpa.free(list);
        }
        var it = self.dlq.keyIterator();
        while (it.next()) |id_ptr| {
            const job = self.jobs.get(id_ptr.*).?;
            list[n] = .{
                .id = @enumFromInt(job.id),
                .job_type = try gpa.dupe(u8, job.job_type),
                .payload = try gpa.dupe(u8, job.payload),
                .partition = try gpa.dupe(u8, job.partition),
                .attempts = job.attempts,
            };
            n += 1;
        }
        return list;
    }

    pub fn freeDeadLetterList(gpa: Allocator, list: []DeadLetter) void {
        for (list) |dl| freeDeadLetter(gpa, dl);
        gpa.free(list);
    }

    // ── observability ─────────────────────────────────────────────────────────

    /// Ready (dispatchable, ignoring not-yet-visible `run_at`) job count.
    pub fn readyCount(self: *const Queue) usize {
        return self.ready_n;
    }
    /// Currently leased (in-flight) job count.
    pub fn leasedCount(self: *const Queue) usize {
        return self.leased.count();
    }
    /// All live jobs (ready + leased + dead-lettered).
    pub fn totalCount(self: *const Queue) usize {
        return self.jobs.count();
    }

    // ── internals ─────────────────────────────────────────────────────────────

    // ── dispatch index (`pending` ⇄ `parts`) ──────────────────────────────────

    /// A partition-heap top, plus what is needed to pop it.
    const Found = struct {
        /// The map-owned partition key (freed when the heap empties).
        key: []const u8,
        heap: *PartitionHeap,
        id: u64,
    };

    /// Move every `pending` entry whose schedule has arrived into its partition
    /// heap. Capacity for the destination is reserved *before* the source pop,
    /// so an allocation failure leaves the job in `pending` — never dropped —
    /// and the next `dequeue` retries it.
    ///
    /// This boundary is an *optimization* boundary, not the visibility gate:
    /// `dequeue` re-checks `run_at_ns` on the candidate it picks and demotes a
    /// job that is not due, so migrating too eagerly only costs churn and can
    /// never dispatch a job early. Both checks must be wrong together for a job
    /// to escape its schedule, which is what the nanosecond boundary tests pin.
    fn migrateDue(self: *Queue, wall_now: i64) Allocator.Error!void {
        while (self.pending.peek()) |top| {
            if (top.run_at_ns > wall_now) break; // heap is time-ordered: so is the rest
            const job = self.jobs.get(top.id).?;
            const heap = try self.reservePartition(job.partition);
            _ = self.pending.pop();
            heap.pushAssumeCapacity(.{ .priority = @intFromEnum(job.priority), .id = top.id });
        }
    }

    /// The partition's ready heap (created on demand) with room for one more
    /// entry. Leaves nothing behind on failure.
    fn reservePartition(self: *Queue, partition: []const u8) Allocator.Error!*PartitionHeap {
        if (self.parts.getPtr(partition)) |heap| {
            try heap.ensureUnusedCapacity(self.gpa, 1);
            return heap;
        }
        const key = try self.gpa.dupe(u8, partition);
        errdefer self.gpa.free(key);
        var heap: PartitionHeap = .{};
        errdefer heap.deinit(self.gpa);
        try heap.ensureUnusedCapacity(self.gpa, 1);
        try self.parts.put(self.gpa, key, heap);
        return self.parts.getPtr(key).?;
    }

    /// Best visible job: the partition's heap top under a filter, else the best
    /// top across all partitions (same (priority, id) order as within one).
    fn bestReady(self: *Queue, filter: ?[]const u8) ?Found {
        if (filter) |p| {
            const e = self.parts.getEntry(p) orelse return null;
            const top = e.value_ptr.peek() orelse return null;
            return .{ .key = e.key_ptr.*, .heap = e.value_ptr, .id = top.id };
        }
        var best: ?Found = null;
        var best_entry: ReadyEntry = undefined;
        var it = self.parts.iterator();
        while (it.next()) |e| {
            const top = e.value_ptr.peek() orelse continue;
            if (best == null or readyBefore(top, best_entry)) {
                best_entry = top;
                best = .{ .key = e.key_ptr.*, .heap = e.value_ptr, .id = top.id };
            }
        }
        return best;
    }

    /// Pop `found`'s top, reclaiming the partition entry once it runs dry.
    /// `found.heap` is dangling afterwards. Does not touch `ready_n`.
    fn takeTop(self: *Queue, found: Found) void {
        _ = found.heap.pop();
        if (found.heap.len() != 0) return;
        const kve = self.parts.fetchRemove(found.key).?;
        var heap = kve.value;
        heap.deinit(self.gpa);
        self.gpa.free(kve.key);
    }

    /// Return a no-longer-visible top to `pending`. Reserves first, so a
    /// failure leaves the job in its partition heap (still found, still
    /// re-checked) rather than losing it.
    fn demote(self: *Queue, found: Found, run_at_ns: i64) Allocator.Error!void {
        try self.pending.ensureUnusedCapacity(self.gpa, 1);
        const id = found.id;
        self.takeTop(found);
        self.pending.pushAssumeCapacity(.{ .run_at_ns = run_at_ns, .id = id });
    }

    /// Reserve room for one more ready job. Paired with `commitReady`, which
    /// cannot fail — the two bracket the durable write.
    fn reserveReady(self: *Queue) Allocator.Error!void {
        return self.pending.ensureUnusedCapacity(self.gpa, 1);
    }

    fn commitReady(self: *Queue, job: *const Job) void {
        self.pending.pushAssumeCapacity(.{ .run_at_ns = job.run_at_ns, .id = job.id });
        self.ready_n += 1;
    }

    fn validate(self: *Queue, lease: Lease) Error!u64 {
        const id = @intFromEnum(lease.id);
        const job = self.jobs.get(id) orelse return Error.StaleLease;
        if (job.lease_epoch != lease.epoch) return Error.StaleLease;
        if (!self.leased.contains(id)) return Error.StaleLease;
        return id;
    }

    /// Shared by `nack` and `reapExpiredLeases`: resolve a held lease by
    /// bumping the attempt count and either requeuing (with `backoff_ns`
    /// wall-visibility delay) or dead-lettering. Persists before mutating the
    /// index; a storage error leaves the job leased and unchanged.
    fn expireLease(self: *Queue, id: u64, backoff_ns: u64) !void {
        const job = self.jobs.get(id).?;
        // Reserve index slots up front so the post-persist commit cannot fail.
        // A requeued job re-enters through `pending` exactly like a fresh one,
        // so its backoff `run_at_ns` gates it and it rejoins its partition heap
        // (at its own priority, behind equal-priority older ids) when due.
        try self.reserveReady();
        try self.dlq.ensureUnusedCapacity(self.gpa, 1);

        const saved_attempts = job.attempts;
        const saved_state = job.state;
        const saved_run_at = job.run_at_ns;

        job.attempts += 1;
        if (job.attempts >= job.max_attempts) {
            job.state = .dead;
        } else {
            job.run_at_ns = addNs(self.wall.now(), backoff_ns);
        }
        self.persistJob(job) catch |e| {
            job.attempts = saved_attempts;
            job.state = saved_state;
            job.run_at_ns = saved_run_at;
            return e;
        };

        _ = self.leased.remove(id);
        job.lease_epoch +%= 1; // invalidate the just-consumed lease
        if (job.state == .dead) {
            self.dlq.putAssumeCapacity(id, {});
        } else {
            self.commitReady(job);
        }
    }

    fn computeBackoff(self: *const Queue, attempt: u32) u64 {
        std.debug.assert(attempt >= 1);
        const base: f64 = @floatFromInt(self.opts.backoff_base_ns);
        const grown = base * std.math.pow(f64, self.opts.backoff_factor, @floatFromInt(attempt - 1));
        const max_f: f64 = @floatFromInt(self.opts.backoff_max_ns);
        // The comparison is false for NaN/inf, so those cap too.
        const capped: u64 = if (!(grown < max_f)) self.opts.backoff_max_ns else @intFromFloat(grown);
        if (self.opts.random) |r| return r.uintAtMost(u64, capped); // full jitter
        return capped;
    }

    fn persistJob(self: *Queue, job: *const Job) !void {
        const buf = try self.encodeJob(job);
        defer self.gpa.free(buf);
        var kb: [24]u8 = undefined;
        try self.db.put(jobKey(&kb, job.id), buf);
    }

    fn encodeJob(self: *Queue, job: *const Job) ![]u8 {
        const total = rec_fixed + job.job_type.len + job.partition.len + job.payload.len;
        const buf = try self.gpa.alloc(u8, total);
        errdefer self.gpa.free(buf);
        buf[0] = rec_version;
        buf[1] = @intFromEnum(job.state);
        buf[2] = @intFromEnum(job.priority);
        std.mem.writeInt(u32, buf[3..7], job.attempts, .little);
        std.mem.writeInt(u32, buf[7..11], job.max_attempts, .little);
        std.mem.writeInt(i64, buf[11..19], job.run_at_ns, .little);
        std.mem.writeInt(u32, buf[19..23], @intCast(job.job_type.len), .little);
        std.mem.writeInt(u32, buf[23..27], @intCast(job.partition.len), .little);
        std.mem.writeInt(u32, buf[27..31], @intCast(job.payload.len), .little);
        var o: usize = rec_fixed;
        @memcpy(buf[o..][0..job.job_type.len], job.job_type);
        o += job.job_type.len;
        @memcpy(buf[o..][0..job.partition.len], job.partition);
        o += job.partition.len;
        @memcpy(buf[o..][0..job.payload.len], job.payload);
        return buf;
    }

    /// Decode a stored record into a freshly allocated, fully owned `*Job`.
    fn decodeJob(self: *Queue, id: u64, buf: []const u8) !*Job {
        if (buf.len < rec_fixed or buf[0] != rec_version) return Error.CorruptRecord;
        const state_raw = buf[1];
        const pri_raw = buf[2];
        if (state_raw > 1 or pri_raw > 3) return Error.CorruptRecord;
        const jt_len = std.mem.readInt(u32, buf[19..23], .little);
        const part_len = std.mem.readInt(u32, buf[23..27], .little);
        const pay_len = std.mem.readInt(u32, buf[27..31], .little);
        if (rec_fixed + @as(u64, jt_len) + part_len + pay_len != buf.len) return Error.CorruptRecord;

        var o: usize = rec_fixed;
        const jt = buf[o..][0..jt_len];
        o += jt_len;
        const part = buf[o..][0..part_len];
        o += part_len;
        const pay = buf[o..][0..pay_len];

        const job = try self.gpa.create(Job);
        errdefer self.gpa.destroy(job);
        job.* = .{
            .id = id,
            .job_type = try self.gpa.dupe(u8, jt),
            .payload = undefined,
            .partition = undefined,
            .priority = @enumFromInt(pri_raw),
            .state = @enumFromInt(state_raw),
            .attempts = std.mem.readInt(u32, buf[3..7], .little),
            .max_attempts = std.mem.readInt(u32, buf[7..11], .little),
            .run_at_ns = std.mem.readInt(i64, buf[11..19], .little),
            .lease_epoch = 0,
        };
        errdefer self.gpa.free(job.job_type);
        job.payload = try self.gpa.dupe(u8, pay);
        errdefer self.gpa.free(job.payload);
        job.partition = try self.gpa.dupe(u8, part);
        return job;
    }

    fn recover(self: *Queue) !void {
        if (try self.db.get(self.gpa, meta_key)) |v| {
            defer self.gpa.free(v);
            if (v.len == 8) self.next_id = std.mem.readInt(u64, v[0..8], .little);
        }
        var id: u64 = 1;
        while (id < self.next_id) : (id += 1) {
            var kb: [24]u8 = undefined;
            const val = (try self.db.get(self.gpa, jobKey(&kb, id))) orelse continue;
            defer self.gpa.free(val);
            const job = try self.decodeJob(id, val);
            errdefer self.freeJob(job);
            try self.jobs.put(self.gpa, id, job);
            switch (job.state) {
                // A job leased-but-not-acked at crash time was persisted as
                // `ready` (the lease was in-memory only) — it comes back ready.
                .ready => {
                    try self.reserveReady();
                    self.commitReady(job);
                },
                .dead => try self.dlq.put(self.gpa, id, {}),
            }
        }
    }

    fn removeJob(self: *Queue, id: u64) void {
        if (self.jobs.fetchRemove(id)) |kve| self.freeJob(kve.value);
    }

    fn freeJob(self: *Queue, job: *Job) void {
        self.gpa.free(job.job_type);
        self.gpa.free(job.payload);
        self.gpa.free(job.partition);
        self.gpa.destroy(job);
    }

    fn freeIndex(self: *Queue) void {
        var it = self.jobs.valueIterator();
        while (it.next()) |job_ptr| self.freeJob(job_ptr.*);
        self.jobs.deinit(self.gpa);
        self.pending.deinit(self.gpa);
        var pit = self.parts.iterator();
        while (pit.next()) |e| {
            e.value_ptr.deinit(self.gpa);
            self.gpa.free(e.key_ptr.*);
        }
        self.parts.deinit(self.gpa);
        self.leased.deinit(self.gpa);
        self.dlq.deinit(self.gpa);
    }
};

fn freeDeadLetter(gpa: Allocator, dl: DeadLetter) void {
    gpa.free(dl.job_type);
    gpa.free(dl.payload);
    gpa.free(dl.partition);
}

// ── tests (deterministic: fake clocks + kv.SimStorage, no real time/disk) ────

const testing = std.testing;

/// Controllable wall clock (epoch ns).
const FakeWall = struct {
    ns: i64 = 1_000_000_000, // a plausible non-zero epoch
    fn clock(f: *FakeWall) WallClock {
        return .{ .ctx = f, .nowFn = nowFn };
    }
    fn nowFn(ctx: ?*anyopaque) i64 {
        return @as(*FakeWall, @ptrCast(@alignCast(ctx.?))).ns;
    }
    fn advance(f: *FakeWall, ns: u64) void {
        f.ns += @intCast(ns);
    }
    /// Wall time is allowed to go backwards (NTP step) — `MonoClock` is the
    /// non-decreasing one, not this.
    fn retreat(f: *FakeWall, ns: u64) void {
        f.ns -= @intCast(ns);
    }
};

/// Controllable monotonic clock (ns).
const FakeMono = struct {
    ns: u64 = 0,
    fn clock(f: *FakeMono) MonoClock {
        return .{ .ctx = f, .nowFn = nowFn };
    }
    fn nowFn(ctx: ?*anyopaque) u64 {
        return @as(*FakeMono, @ptrCast(@alignCast(ctx.?))).ns;
    }
    fn advance(f: *FakeMono, ns: u64) void {
        f.ns += ns;
    }
};

/// Test harness: a SimStorage + fake clocks + an open Queue, all torn down
/// together. `sim` outlives reopen so crash-recovery can be exercised.
const Harness = struct {
    sim: kv.SimStorage,
    wall: FakeWall = .{},
    mono: FakeMono = .{},

    fn init(h: *Harness) void {
        h.* = .{ .sim = kv.SimStorage.init(testing.allocator) };
    }
    fn deinit(h: *Harness) void {
        h.sim.deinit();
    }
    fn openQueue(h: *Harness) !Queue {
        return Queue.open(testing.allocator, h.sim.storage(), "jq", .{
            .wall_clock = h.wall.clock(),
            .mono_clock = h.mono.clock(),
        });
    }
};

const one_ms: u64 = std.time.ns_per_ms;

test "enqueue -> lease -> ack: never reappears" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    var q = try h.openQueue();
    defer q.close();

    _ = try q.enqueue("email", "hello", .{});
    try testing.expectEqual(@as(usize, 1), q.readyCount());

    const lease = (try q.dequeue(.{ .visibility_timeout_ns = 1000 })).?;
    try testing.expectEqualStrings("email", lease.job_type);
    try testing.expectEqualStrings("hello", lease.payload);
    try testing.expectEqual(@as(u32, 1), lease.attempt);
    try testing.expectEqual(@as(usize, 0), q.readyCount());
    try testing.expectEqual(@as(usize, 1), q.leasedCount());

    try q.ack(lease);
    try testing.expectEqual(@as(usize, 0), q.totalCount());
    // Nothing left to dispatch, and a second ack is a stale no-op error.
    try testing.expect((try q.dequeue(.{ .visibility_timeout_ns = 1000 })) == null);
    try testing.expectError(Error.StaleLease, q.ack(lease));
}

test "visibility timeout: reap makes the job re-leasable and bumps the attempt" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    var q = try h.openQueue();
    defer q.close();

    _ = try q.enqueue("job", "x", .{});
    const lease1 = (try q.dequeue(.{ .visibility_timeout_ns = 10 * one_ms })).?;
    try testing.expectEqual(@as(u32, 1), lease1.attempt);

    // Not yet expired: nothing to reap, still leased, not dispatchable.
    h.mono.advance(5 * one_ms);
    try testing.expectEqual(@as(usize, 0), try q.reapExpiredLeases());
    try testing.expect((try q.dequeue(.{ .visibility_timeout_ns = one_ms })) == null);

    // Past the deadline: reaped back to ready, attempt count advanced.
    h.mono.advance(6 * one_ms);
    try testing.expectEqual(@as(usize, 1), try q.reapExpiredLeases());
    try testing.expectEqual(@as(usize, 1), q.readyCount());

    const lease2 = (try q.dequeue(.{ .visibility_timeout_ns = 10 * one_ms })).?;
    try testing.expectEqual(@as(u32, 2), lease2.attempt);
    // The first, now-stale lease can no longer ack the job.
    try testing.expectError(Error.StaleLease, q.ack(lease1));
    try q.ack(lease2);
}

test "dead-letter after max_attempts failures" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    var q = try h.openQueue();
    defer q.close();

    _ = try q.enqueue("flaky", "payload", .{ .max_attempts = 3 });

    // Three deliveries, each nacked with zero backoff so it re-dequeues at once.
    var attempt: u32 = 1;
    while (attempt <= 3) : (attempt += 1) {
        const lease = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
        try testing.expectEqual(attempt, lease.attempt);
        try q.nack(lease, .{ .backoff_ns = 0 });
    }

    try testing.expectEqual(@as(usize, 0), q.readyCount());
    try testing.expectEqual(@as(usize, 1), q.deadLetterCount());
    try testing.expect((try q.dequeue(.{ .visibility_timeout_ns = one_ms })) == null);

    const dl = try q.deadLetterList(testing.allocator);
    defer Queue.freeDeadLetterList(testing.allocator, dl);
    try testing.expectEqual(@as(usize, 1), dl.len);
    try testing.expectEqualStrings("flaky", dl[0].job_type);
    try testing.expectEqual(@as(u32, 3), dl[0].attempts);
}

test "partition FIFO ordering (the taskqueue-fold oracle)" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    var q = try h.openQueue();
    defer q.close();

    // Two partitions interleaved at enqueue time.
    _ = try q.enqueue("t", "a0", .{ .partition = "a" });
    _ = try q.enqueue("t", "b0", .{ .partition = "b" });
    _ = try q.enqueue("t", "a1", .{ .partition = "a" });
    _ = try q.enqueue("t", "b1", .{ .partition = "b" });
    _ = try q.enqueue("t", "a2", .{ .partition = "a" });

    // nextFor("a") folds partition "a" in strict enqueue (FIFO) order.
    const expect_a = [_][]const u8{ "a0", "a1", "a2" };
    for (expect_a) |want| {
        const lease = (try q.dequeue(.{ .partition = "a", .visibility_timeout_ns = one_ms })).?;
        try testing.expectEqualStrings(want, lease.payload);
        try testing.expectEqualStrings("a", lease.partition);
        try q.ack(lease);
    }
    // Partition "b" untouched and still FIFO.
    const lb = (try q.dequeue(.{ .partition = "b", .visibility_timeout_ns = one_ms })).?;
    try testing.expectEqualStrings("b0", lb.payload);
}

test "priority ordering: high before an earlier-enqueued low" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    var q = try h.openQueue();
    defer q.close();

    _ = try q.enqueue("t", "low-first", .{ .priority = .low }); // id 1, enqueued earlier
    _ = try q.enqueue("t", "normal", .{ .priority = .normal }); // id 2
    _ = try q.enqueue("t", "high-last", .{ .priority = .high }); // id 3, enqueued later

    // Priority wins over FIFO: high, then normal, then low.
    const l1 = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
    try testing.expectEqualStrings("high-last", l1.payload);
    try q.ack(l1);
    const l2 = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
    try testing.expectEqualStrings("normal", l2.payload);
    try q.ack(l2);
    const l3 = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
    try testing.expectEqualStrings("low-first", l3.payload);
    try q.ack(l3);
}

test "FIFO tiebreak within equal priority" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    var q = try h.openQueue();
    defer q.close();

    _ = try q.enqueue("t", "first", .{});
    _ = try q.enqueue("t", "second", .{});
    const a = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
    try testing.expectEqualStrings("first", a.payload);
    const b = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
    try testing.expectEqualStrings("second", b.payload);
}

test "priority ordering inside one partition" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    var q = try h.openQueue();
    defer q.close();

    // Enqueued in an order that contradicts the expected dispatch order.
    _ = try q.enqueue("t", "p-low", .{ .partition = "p", .priority = .low });
    _ = try q.enqueue("t", "p-critical", .{ .partition = "p", .priority = .critical });
    _ = try q.enqueue("t", "p-normal", .{ .partition = "p", .priority = .normal });
    _ = try q.enqueue("t", "p-high", .{ .partition = "p", .priority = .high });

    const want = [_][]const u8{ "p-critical", "p-high", "p-normal", "p-low" };
    for (want) |w| {
        const lease = (try q.dequeue(.{ .partition = "p", .visibility_timeout_ns = one_ms })).?;
        try testing.expectEqualStrings(w, lease.payload);
        try q.ack(lease);
    }
}

test "partition independence: a busy critical partition never reorders another" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    var q = try h.openQueue();
    defer q.close();

    // "hot" is all-critical, "cold" is all-normal, interleaved at enqueue time.
    _ = try q.enqueue("t", "cold0", .{ .partition = "cold" }); // id 1
    _ = try q.enqueue("t", "hot0", .{ .partition = "hot", .priority = .critical }); // id 2
    _ = try q.enqueue("t", "cold1", .{ .partition = "cold" }); // id 3
    _ = try q.enqueue("t", "hot1", .{ .partition = "hot", .priority = .critical }); // id 4
    _ = try q.enqueue("t", "cold2", .{ .partition = "cold" }); // id 5

    // A worker pinned to "cold" folds "cold" in strict FIFO — "hot"'s priority
    // and its heap churn are invisible to it.
    const cold = [_][]const u8{ "cold0", "cold1", "cold2" };
    for (cold) |w| {
        const lease = (try q.dequeue(.{ .partition = "cold", .visibility_timeout_ns = one_ms })).?;
        try testing.expectEqualStrings(w, lease.payload);
        try testing.expectEqualStrings("cold", lease.partition);
        try q.ack(lease);
    }
    try testing.expect((try q.dequeue(.{ .partition = "cold", .visibility_timeout_ns = one_ms })) == null);

    // "hot" was untouched by all of that, and is still FIFO within itself.
    const hot = [_][]const u8{ "hot0", "hot1" };
    for (hot) |w| {
        const lease = (try q.dequeue(.{ .partition = "hot", .visibility_timeout_ns = one_ms })).?;
        try testing.expectEqualStrings(w, lease.payload);
        try q.ack(lease);
    }
}

test "unfiltered dequeue is deterministic FIFO among equal priorities across partitions" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    var q = try h.openQueue();
    defer q.close();

    // Equal priority everywhere, alternating partitions: the only tiebreak left
    // is the enqueue sequence, and it must not depend on heap/hash layout.
    const seq = [_][]const u8{ "0", "1", "2", "3", "4", "5" };
    for (seq, 0..) |s, i| {
        _ = try q.enqueue("t", s, .{ .partition = if (i % 2 == 0) "x" else "y" });
    }
    for (seq) |s| {
        const lease = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
        try testing.expectEqualStrings(s, lease.payload);
        try q.ack(lease);
    }
    try testing.expect((try q.dequeue(.{ .visibility_timeout_ns = one_ms })) == null);
}

test "a scheduled critical job does not jump ahead of its own schedule" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    var q = try h.openQueue();
    defer q.close();

    // The highest-priority job in the queue is also the one that is not due:
    // the case a single (priority, id) heap gets wrong, because its top is
    // invisible and popping past it destroys the order.
    _ = try q.enqueue("t", "now-low", .{ .priority = .low });
    _ = try q.enqueue("t", "later-critical", .{ .priority = .critical, .delay_ns = 100 * one_ms });
    try testing.expectEqual(@as(usize, 2), q.readyCount());

    const l1 = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
    try testing.expectEqualStrings("now-low", l1.payload);
    try q.ack(l1);
    // Nothing else is due, even though a critical job is sitting there.
    try testing.expect((try q.dequeue(.{ .visibility_timeout_ns = one_ms })) == null);
    try testing.expectEqual(@as(usize, 1), q.readyCount());

    h.wall.advance(100 * one_ms);
    const l2 = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
    try testing.expectEqualStrings("later-critical", l2.payload);
}

test "the run_at boundary is exact to the nanosecond, from both sides" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    var q = try h.openQueue();
    defer q.close();

    // The visibility gate compares at nanosecond granularity, so this test
    // steps the clock at nanosecond granularity: a millisecond-scale step
    // pins "visible at run_at" but says nothing about "not visible just
    // before it", which is the half that the delay feature is actually for.
    const run_at = h.wall.ns + @as(i64, @intCast(50 * one_ms));
    _ = try q.enqueue("t", "scheduled", .{ .run_at = run_at, .priority = .critical });

    // One nanosecond early: still invisible, still ready-set member.
    h.wall.ns = run_at - 1;
    try testing.expect((try q.dequeue(.{ .visibility_timeout_ns = one_ms })) == null);
    try testing.expectEqual(@as(usize, 1), q.readyCount());

    // Exactly at run_at: dispatched. `run_at` is inclusive.
    h.wall.ns = run_at;
    const lease = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
    try testing.expectEqualStrings("scheduled", lease.payload);
}

test "a scheduled job becomes eligible and then wins on priority" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    var q = try h.openQueue();
    defer q.close();

    _ = try q.enqueue("t", "later-critical", .{ .priority = .critical, .delay_ns = 50 * one_ms });
    _ = try q.enqueue("t", "now-high", .{ .priority = .high });
    _ = try q.enqueue("t", "now-normal", .{ .priority = .normal });

    // Before the schedule arrives the visible best is the high job.
    const l1 = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
    try testing.expectEqualStrings("now-high", l1.payload);
    try q.ack(l1);

    // Once it is due it outranks the normal job that was dispatchable all along.
    h.wall.advance(50 * one_ms);
    const l2 = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
    try testing.expectEqualStrings("later-critical", l2.payload);
    try q.ack(l2);
    const l3 = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
    try testing.expectEqualStrings("now-normal", l3.payload);
}

test "a wall-clock step backwards re-hides an already-eligible job" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    var q = try h.openQueue();
    defer q.close();

    _ = try q.enqueue("t", "a", .{});
    _ = try q.enqueue("t", "b", .{});
    // This dequeue makes both eligible and consumes "a"; "b" stays eligible.
    const la = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
    try testing.expectEqualStrings("a", la.payload);
    try q.ack(la);

    // Eligibility is decided per call, never cached: an NTP step backwards
    // puts "b" behind its schedule again without losing it. One nanosecond is
    // enough — this comparison is exact too, not just the migration one.
    h.wall.retreat(1);
    try testing.expect((try q.dequeue(.{ .visibility_timeout_ns = one_ms })) == null);
    try testing.expectEqual(@as(usize, 1), q.readyCount());

    h.wall.retreat(10 * one_ms);
    try testing.expect((try q.dequeue(.{ .visibility_timeout_ns = one_ms })) == null);
    try testing.expectEqual(@as(usize, 1), q.readyCount());

    h.wall.advance(10 * one_ms + 1);
    const lb = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
    try testing.expectEqualStrings("b", lb.payload);
}

test "delay / run_at: a job is invisible until its schedule (wall clock)" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    var q = try h.openQueue();
    defer q.close();

    _ = try q.enqueue("t", "later", .{ .delay_ns = 100 * one_ms });
    try testing.expectEqual(@as(usize, 1), q.readyCount()); // indexed…
    // …but not yet visible.
    try testing.expect((try q.dequeue(.{ .visibility_timeout_ns = one_ms })) == null);

    h.wall.advance(100 * one_ms);
    const lease = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
    try testing.expectEqualStrings("later", lease.payload);
}

test "nack backoff delays redelivery until the wall clock catches up" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    var q = try h.openQueue();
    defer q.close();

    _ = try q.enqueue("t", "p", .{ .max_attempts = 5 });
    const lease = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
    try q.nack(lease, .{ .backoff_ns = 50 * one_ms });

    // Requeued but not visible until the backoff elapses on the wall clock.
    try testing.expect((try q.dequeue(.{ .visibility_timeout_ns = one_ms })) == null);
    h.wall.advance(50 * one_ms);
    const lease2 = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
    try testing.expectEqual(@as(u32, 2), lease2.attempt);
}

test "crash recovery: acked stays gone, leased-not-acked returns ready, no dup/loss" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();

    {
        var q = try h.openQueue();
        defer q.close();
        _ = try q.enqueue("t", "acked", .{ .priority = .low });
        _ = try q.enqueue("t", "leased", .{ .priority = .low });
        _ = try q.enqueue("t", "ready", .{ .priority = .low });

        // Ack one; lease another and DO NOT ack (simulating a crash mid-work).
        const la = (try q.dequeue(.{ .partition = "", .visibility_timeout_ns = one_ms })).?;
        try testing.expectEqualStrings("acked", la.payload); // id 1, FIFO
        try q.ack(la);
        const ll = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
        try testing.expectEqualStrings("leased", ll.payload);
        // no ack — the process "crashes" here
    }

    // Reopen over the SAME storage: rebuild the index from the kv log.
    var q = try h.openQueue();
    defer q.close();

    // Acked job is gone; the other two are back and ready (lease was in-memory).
    try testing.expectEqual(@as(usize, 2), q.totalCount());
    try testing.expectEqual(@as(usize, 2), q.readyCount());
    try testing.expectEqual(@as(usize, 0), q.leasedCount());
    try testing.expectEqual(@as(usize, 0), q.deadLetterCount());

    // Both survivors are dispatchable exactly once, no duplicates.
    var seen: [2][]const u8 = undefined;
    seen[0] = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?.payload;
    seen[1] = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?.payload;
    try testing.expect((try q.dequeue(.{ .visibility_timeout_ns = one_ms })) == null);
    const got_leased = std.mem.eql(u8, seen[0], "leased") or std.mem.eql(u8, seen[1], "leased");
    const got_ready = std.mem.eql(u8, seen[0], "ready") or std.mem.eql(u8, seen[1], "ready");
    try testing.expect(got_leased and got_ready);

    // The durable counter survived: the next id continues the sequence.
    const next = try q.enqueue("t", "fresh", .{});
    try testing.expectEqual(@as(u64, 4), @intFromEnum(next));
}

test "crash recovery: a dead-lettered job stays dead across reopen" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    {
        var q = try h.openQueue();
        defer q.close();
        _ = try q.enqueue("t", "doomed", .{ .max_attempts = 1 });
        const lease = (try q.dequeue(.{ .visibility_timeout_ns = one_ms })).?;
        try q.nack(lease, .{ .backoff_ns = 0 }); // attempts 1 >= max 1 -> dead
        try testing.expectEqual(@as(usize, 1), q.deadLetterCount());
    }
    var q = try h.openQueue();
    defer q.close();
    try testing.expectEqual(@as(usize, 1), q.deadLetterCount());
    try testing.expectEqual(@as(usize, 0), q.readyCount());
    const dl = try q.deadLetterList(testing.allocator);
    defer Queue.freeDeadLetterList(testing.allocator, dl);
    try testing.expectEqualStrings("doomed", dl[0].payload);
}

test "payload cap and field cap are enforced" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    var q = try Queue.open(testing.allocator, h.sim.storage(), "jq", .{
        .wall_clock = h.wall.clock(),
        .mono_clock = h.mono.clock(),
        .max_payload = 8,
    });
    defer q.close();

    try testing.expectError(Error.PayloadTooLarge, q.enqueue("t", "123456789", .{}));
    _ = try q.enqueue("t", "12345678", .{}); // exactly at the cap is fine
    const big_type = "x" ** (max_field_len + 1);
    try testing.expectError(Error.FieldTooLarge, q.enqueue(big_type, "ok", .{}));
}

test "computeBackoff: exponential progression, capped, deterministic without jitter" {
    var h: Harness = undefined;
    h.init();
    defer h.deinit();
    var q = try Queue.open(testing.allocator, h.sim.storage(), "jq", .{
        .backoff_base_ns = 100,
        .backoff_factor = 2.0,
        .backoff_max_ns = 1000,
    });
    defer q.close();

    try testing.expectEqual(@as(u64, 100), q.computeBackoff(1));
    try testing.expectEqual(@as(u64, 200), q.computeBackoff(2));
    try testing.expectEqual(@as(u64, 400), q.computeBackoff(3));
    try testing.expectEqual(@as(u64, 800), q.computeBackoff(4));
    try testing.expectEqual(@as(u64, 1000), q.computeBackoff(5)); // 1600 capped
    try testing.expectEqual(@as(u64, 1000), q.computeBackoff(60)); // overflow-safe
}
