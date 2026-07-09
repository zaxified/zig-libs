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
//! jobqueue keeps its own in-memory index (a `jobs` map, a `ready` set, a
//! `leased` table, a `dlq` set) and treats `kv` purely as the durable record
//! of truth. The index is rebuilt from `kv` on `open`.
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
    .status = .gap,
    // The OS-default wall/monotonic clocks use posix `clock_gettime`; both
    // are injectable, everything else is pure logic + the `kv` store.
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

// ── Queue ────────────────────────────────────────────────────────────────────

pub const Queue = struct {
    gpa: Allocator,
    db: kv.Db,
    opts: Options,
    wall: WallClock,
    mono: MonoClock,

    /// The single source of live in-memory job state (owns every `*Job`).
    jobs: std.AutoHashMapUnmanaged(u64, *Job),
    /// Ids currently dispatchable (subset of `jobs`; state == ready, not
    /// leased). Visibility (`run_at`) is checked at `dequeue` time.
    ready: std.AutoHashMapUnmanaged(u64, void),
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
            .ready = .empty,
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
        try self.ready.ensureUnusedCapacity(self.gpa, 1);

        // Durable order: job record first, then the counter. A crash between
        // them orphans the record (never referenced) — a returned enqueue is
        // always fully durable.
        try self.persistJob(job);
        var nb: [8]u8 = undefined;
        std.mem.writeInt(u64, &nb, id + 1, .little);
        try self.db.put(meta_key, &nb);

        self.jobs.putAssumeCapacity(id, job);
        self.ready.putAssumeCapacity(id, {});
        self.next_id = id + 1;
        return @enumFromInt(id);
    }

    // ── dequeue / lease ───────────────────────────────────────────────────────

    /// Reserve the best ready job: highest `Priority`, ties oldest-first
    /// (FIFO), respecting `run_at`/`delay` visibility and the optional
    /// partition filter. Returns null when nothing is dispatchable.
    pub fn dequeue(self: *Queue, opts: DequeueOptions) !?Lease {
        const wall_now = self.wall.now();
        var best_id: ?u64 = null;
        var best_pri: u8 = 0;

        var it = self.ready.keyIterator();
        while (it.next()) |id_ptr| {
            const id = id_ptr.*;
            const job = self.jobs.get(id).?;
            if (job.run_at_ns > wall_now) continue; // not yet visible
            if (opts.partition) |p| {
                if (!std.mem.eql(u8, p, job.partition)) continue;
            }
            const pri = @intFromEnum(job.priority);
            if (best_id == null or pri > best_pri or (pri == best_pri and id < best_id.?)) {
                best_id = id;
                best_pri = pri;
            }
        }

        const id = best_id orelse return null;
        const job = self.jobs.get(id).?;

        try self.leased.put(self.gpa, id, self.mono.now() +| opts.visibility_timeout_ns);
        _ = self.ready.remove(id);
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
        return self.ready.count();
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
        try self.ready.ensureUnusedCapacity(self.gpa, 1);
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
            self.ready.putAssumeCapacity(id, {});
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
                .ready => try self.ready.put(self.gpa, id, {}),
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
        self.ready.deinit(self.gpa);
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
