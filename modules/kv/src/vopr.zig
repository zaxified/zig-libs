// SPDX-License-Identifier: MIT

//! Randomized, seeded VOPR for the kv store.
//!
//! Where `fault_test.zig` sweeps ONE scripted workload across every
//! (injection point × crash mode) pair, this harness fuzzes recovery across
//! thousands of *randomized* fault schedules: for each seed it generates a
//! random workload (puts / deletes / gets / compactions over a bounded key
//! space) and a random fault plan (crash points under all three crash modes,
//! injected I/O errors with torn prefix writes, short reads, garbage bytes
//! appended to the media tail), runs them against `SimStorage`, then reboots,
//! reopens and model-checks the recovered state. Several crash/recover
//! epochs are chained per seed, so recovery output feeds the next crash.
//!
//! Everything — workload, values, fault schedule, even short-read split
//! points — derives from the seed via a local splitmix64: no clock, no OS
//! randomness, no thread nondeterminism. Any failure reproduces exactly by
//! re-running its seed, and the failure report prints the seed plus the full
//! op/fault trace.
//!
//! Invariants asserted after every crash + recovery (and every clean close):
//!
//!   1. durability — every acknowledged (fsync-returned) put/delete is
//!      present and byte-correct in the recovered state;
//!   2. atomicity of the tail — the recovered state is EXACTLY the
//!      acknowledged model, or the model with the single in-flight op
//!      applied (an unacknowledged op may atomically survive or vanish;
//!      nothing in between, and no other key may change);
//!   3. no torn/corrupt record is ever surfaced as valid (a garbage or torn
//!      tail must be truncated, never served — `error.Corrupt` from a
//!      recovered `get` is an invariant violation too);
//!   4. the keydir matches the replayed log (`get`/`exists`/`count` agree
//!      with the model for every key in the space);
//!   5. recovery never fails and never panics, and the recovered store
//!      accepts, serves and persists new writes (probe write per epoch —
//!      which also re-fsyncs the file, pinning the adopted state as durable);
//!   6. compaction and `open` change no logical state, whatever faults hit.
//!
//! The harness proves it has teeth two ways: the aggregate test asserts
//! minimum counts of actually-fired crashes / injected errors / short reads /
//! garbage tails (a schedule that never faults cannot pass), and a self-test
//! runs with `sabotage` enabled — a deliberately "broken recovery" that
//! silently loses committed media state — and requires the model checker to
//! catch every such loss.
//!
//! Provenance: the VOPR approach — deterministic storage simulation, fault
//! injection at I/O granularity, model-checked crash recovery, reproduction
//! from a seed — is modeled after TigerBeetle's VOPR (Apache-2.0; design
//! reference only, no TigerBeetle code consulted or copied; credited in the
//! repository NOTICE). The splitmix64 mixer is the public-domain algorithm
//! by Sebastiano Vigna. Implementation is clean-room on top of this module's
//! own `SimStorage`.

const std = @import("std");
const kv = @import("root.zig");
const Db = kv.Db;
const Storage = kv.Storage;
const SimStorage = kv.SimStorage;
const CrashMode = kv.CrashMode;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const scheduler_mod = @import("scheduler.zig");
/// Re-exported so `shrink.zig` (and any external consumer) can name the
/// scheduling seam via `vopr.FaultScheduler` without importing
/// `scheduler.zig` directly.
pub const FaultScheduler = scheduler_mod.FaultScheduler;
pub const Coverage = scheduler_mod.Coverage;

const db_name = "vopr.kv";
/// Reserved for the post-recovery liveness probe; outside the model space.
const probe_key = "!vopr-probe";
/// Bounded key space: index 0 is the empty key, 1..12 are "k01".."k12".
const key_count = 13;
/// Crosses replay's 4096-byte streaming-CRC chunk boundary.
const max_val_len = 6000;
/// Seeds per test run — sized to keep `zig build test-kv` fast in Debug.
const seed_count = 2000;

// ── seeded PRNG (splitmix64) ─────────────────────────────────────────────────
//
// Shared with `scheduler.zig` and `shrink.zig` — see `prng.zig`.

const Prng = @import("prng.zig").Prng;

// ── FaultStorage: seed-driven error/short-read injection over SimStorage ────
//
// Crashes (with their media-collapse semantics) stay in SimStorage; this
// wrapper adds the fault classes SimStorage does not model: transient I/O
// errors (ENOSPC / EIO) with a torn prefix write, and short reads.

const FaultStorage = struct {
    inner: Storage,
    prng: *Prng,
    /// One-shot scheduled error: fires at the N-th next side effect.
    error_countdown: ?usize = null,
    error_kind: Storage.Error = error.NoSpaceLeft,
    /// When set, `pread` may return fewer bytes than requested — legal
    /// POSIX behavior the store must absorb (via `preadFull`).
    short_reads: bool = false,
    /// The scheduled error fired (lets the runner tell an injected error
    /// from an unexpected one).
    fired: bool = false,
    injected_errors: usize = 0,
    injected_short_reads: usize = 0,

    fn storage(self: *FaultStorage) Storage {
        return .{ .ctx = self, .vtable = &vtable };
    }

    /// Count a side effect; true = the scheduled error fires on this op.
    fn fires(self: *FaultStorage) bool {
        if (self.error_countdown) |*n| {
            if (n.* == 0) {
                self.error_countdown = null;
                self.fired = true;
                self.injected_errors += 1;
                return true;
            }
            n.* -= 1;
        }
        return false;
    }

    const vtable = Storage.VTable{
        .open = vOpen,
        .size = vSize,
        .pread = vPread,
        .writeAll = vWriteAll,
        .sync = vSync,
        .truncate = vTruncate,
        .close = vClose,
        .rename = vRename,
        .delete = vDelete,
        .syncDir = vSyncDir,
        .tryLockExclusive = vTryLockExclusive,
    };

    fn cast(ctx: *anyopaque) *FaultStorage {
        return @ptrCast(@alignCast(ctx));
    }

    fn vOpen(ctx: *anyopaque, path: []const u8, mode: Storage.OpenMode) Storage.Error!Storage.Handle {
        const self = cast(ctx);
        if (self.fires()) return self.error_kind;
        return self.inner.open(path, mode);
    }

    fn vSize(ctx: *anyopaque, h: Storage.Handle) Storage.Error!u64 {
        return cast(ctx).inner.size(h);
    }

    fn vPread(ctx: *anyopaque, h: Storage.Handle, buf: []u8, off: u64) Storage.Error!usize {
        const self = cast(ctx);
        if (self.short_reads and buf.len >= 2 and self.prng.chance(1, 3)) {
            self.injected_short_reads += 1;
            const n = 1 + self.prng.below(buf.len - 1);
            return self.inner.pread(h, buf[0..n], off);
        }
        return self.inner.pread(h, buf, off);
    }

    fn vWriteAll(ctx: *anyopaque, h: Storage.Handle, bytes: []const u8, off: u64) Storage.Error!void {
        const self = cast(ctx);
        if (self.fires()) {
            // e.g. ENOSPC mid-record: a random prefix reached the page
            // cache before the error — a torn record recovery must discard.
            if (bytes.len > 1) {
                const keep = self.prng.below(bytes.len);
                if (keep > 0) try self.inner.writeAll(h, bytes[0..keep], off);
            }
            return self.error_kind;
        }
        return self.inner.writeAll(h, bytes, off);
    }

    fn vSync(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
        const self = cast(ctx);
        if (self.fires()) return self.error_kind;
        return self.inner.sync(h);
    }

    fn vTruncate(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!void {
        const self = cast(ctx);
        if (self.fires()) return self.error_kind;
        return self.inner.truncate(h, len);
    }

    fn vClose(ctx: *anyopaque, h: Storage.Handle) void {
        cast(ctx).inner.close(h);
    }

    fn vRename(ctx: *anyopaque, old_path: []const u8, new_path: []const u8) Storage.Error!void {
        const self = cast(ctx);
        if (self.fires()) return self.error_kind;
        return self.inner.rename(old_path, new_path);
    }

    fn vDelete(ctx: *anyopaque, path: []const u8) Storage.Error!void {
        const self = cast(ctx);
        if (self.fires()) return self.error_kind;
        return self.inner.delete(path);
    }

    fn vSyncDir(ctx: *anyopaque) Storage.Error!void {
        const self = cast(ctx);
        if (self.fires()) return self.error_kind;
        return self.inner.syncDir();
    }

    /// Taking the store's cross-process lock is a side effect like any other
    /// here: the scheduled error may fire on it, so `Db.open`'s lock-acquire
    /// path gets the same failure coverage as its write path.
    fn vTryLockExclusive(ctx: *anyopaque, h: Storage.Handle) Storage.Error!bool {
        const self = cast(ctx);
        if (self.fires()) return self.error_kind;
        return self.inner.tryLockExclusive(h);
    }
};

// ── the runner ───────────────────────────────────────────────────────────────

pub const Config = struct {
    /// Self-test mode: at recovery time, "lose" the committed media content
    /// (a deliberately broken recovery). The model checker MUST catch it.
    sabotage: bool = false,
    /// Suppress the failure report (for the self-test's expected failures).
    quiet: bool = false,
    /// Decides WHEN each epoch faults and WHICH fault fires — the mechanical
    /// fault *types* (crash modes, transient I/O errors) live in `sim.zig`
    /// and `FaultStorage` above; this seam only owns the timing/selection
    /// policy. Defaults to the module's original uniform-random policy
    /// (byte-identical to the pre-`scheduler.zig` inline logic — see
    /// `scheduler.uniformScheduler`'s doc comment). Swap in
    /// `scheduler.coverageGuidedScheduler(&state)` (bandit-style, cross-seed
    /// coverage feedback — see scheduler.zig) to bias fault selection toward
    /// under-exercised (class × timing) cells.
    scheduler: FaultScheduler = scheduler_mod.uniformScheduler(),
};

/// Aggregated across seeds by the caller; also the determinism witness.
pub const Stats = struct {
    epochs: usize = 0,
    acked_ops: usize = 0,
    crashes: usize = 0,
    io_errors: usize = 0,
    short_reads: usize = 0,
    garbage_tails: usize = 0,
    /// Crashes that persisted a non-contiguous subset of an un-synced
    /// multi-write window (a real hole) — the teeth witness for the
    /// `.reorder_unsynced` mode (out-of-order durability).
    reorder_holes: usize = 0,
    /// Recoveries where the unacknowledged in-flight op survived (candidate
    /// B adopted) — proves the atomic-tail branch is actually exercised.
    inflight_survived: usize = 0,
    sabotages: usize = 0,
    /// Mix of each seed's final media CRC — byte-level determinism witness.
    fingerprint: u64 = 0,
};

/// The one mutation that was in flight (issued, never acknowledged) when the
/// fault fired. Recovery may atomically keep or drop exactly this op.
const Inflight = union(enum) {
    none,
    put: struct { key: usize, val: []const u8 },
    del: usize,
};

pub const Event = struct {
    epoch: u16,
    code: Code,
    key: i32,
    len: u32,

    pub const Code = enum {
        open_ok,
        open_fault,
        put_ok,
        put_fault,
        del_ok,
        del_fault,
        compact_ok,
        compact_fault,
        close_clean,
        crash,
        garbage,
        sabotage,
        recover_exact,
        recover_inflight,
        probe_ok,
    };
};

/// Key for index 0..key_count-1: "" (empty key) or "k01".."k12".
fn keyName(buf: *[3]u8, idx: usize) []const u8 {
    if (idx == 0) return "";
    return std.fmt.bufPrint(buf, "k{d:0>2}", .{idx}) catch unreachable;
}

const Vopr = struct {
    gpa: Allocator,
    /// Owns all generated values for one seed (bulk-freed with the seed).
    arena: Allocator,
    cfg: Config,
    seed: u64,
    epoch: usize = 0,
    prng: *Prng,
    sim: *SimStorage,
    faults: *FaultStorage,
    st: Storage,
    /// The reference model: acknowledged-durable state per key index.
    model: [key_count]?[]const u8 = @splat(null),
    trace: std.ArrayList(Event) = .empty,
    stats: *Stats,

    fn event(v: *Vopr, code: Event.Code, key: i32, len: u32) !void {
        try v.trace.append(v.gpa, .{
            .epoch = @intCast(v.epoch),
            .code = code,
            .key = key,
            .len = len,
        });
    }

    fn liveCount(v: *const Vopr) usize {
        var n: usize = 0;
        for (v.model) |m| {
            if (m != null) n += 1;
        }
        return n;
    }

    /// Report an invariant violation: seed + full op/fault trace, so the
    /// failure reproduces exactly by re-running this seed.
    fn fail(v: *Vopr, comptime fmt: []const u8, args: anytype) error{InvariantViolation} {
        if (!v.cfg.quiet) {
            std.debug.print(
                "\nkv VOPR FAILURE: seed={d} epoch={d}: " ++ fmt ++ "\n",
                .{ v.seed, v.epoch } ++ args,
            );
            std.debug.print("op/fault trace ({d} events):\n", .{v.trace.items.len});
            for (v.trace.items) |ev| {
                std.debug.print(
                    "  e{d} {t} key={d} len={d}\n",
                    .{ ev.epoch, ev.code, ev.key, ev.len },
                );
            }
        }
        return error.InvariantViolation;
    }

    /// The fault an op died with must be the scheduled one (a crash or the
    /// armed injected error) — anything else is a bug, not a simulated fault.
    fn expectFault(v: *Vopr, e: anyerror) !void {
        if (e == error.Crashed) return;
        if (v.faults.fired and e == v.faults.error_kind) return;
        return v.fail("op failed with unscheduled error: {t}", .{e});
    }

    /// Does the store's state equal `model` exactly? `error.Corrupt` from a
    /// get means a torn/rotten record was surfaced into the keydir — that is
    /// a mismatch by definition (invariant 3).
    fn matches(v: *Vopr, db: *Db, model: *const [key_count]?[]const u8) !bool {
        return modelMatches(v.gpa, db, model);
    }

    /// One epoch: open the store and run random ops until the scheduled
    /// fault fires, or run to completion and close cleanly. Acknowledged
    /// mutations update the model; gets are checked against it live.
    fn runEpoch(v: *Vopr) !Inflight {
        var db = Db.open(v.gpa, v.st, db_name, .{}) catch |e| {
            try v.event(.open_fault, -1, 0);
            if (e == error.Crashed or v.faults.fired) return .none;
            return v.fail("unscheduled open error: {t}", .{e});
        };
        defer db.close();
        try v.event(.open_ok, -1, 0);

        const op_total = 4 + v.prng.below(40);
        var op: usize = 0;
        while (op < op_total) : (op += 1) {
            const roll = v.prng.below(100);
            if (roll < 55) { // put
                const k = v.prng.below(key_count);
                const vlen = if (v.prng.chance(1, 12))
                    v.prng.below(max_val_len + 1)
                else
                    v.prng.below(80);
                const val = try v.arena.alloc(u8, vlen);
                v.prng.fill(val);
                var kb: [3]u8 = undefined;
                db.put(keyName(&kb, k), val) catch |e| {
                    try v.event(.put_fault, @intCast(k), @intCast(vlen));
                    try v.expectFault(e);
                    return .{ .put = .{ .key = k, .val = val } };
                };
                v.model[k] = val;
                v.stats.acked_ops += 1;
                try v.event(.put_ok, @intCast(k), @intCast(vlen));
            } else if (roll < 75) { // delete (absent key = acked no-op)
                const k = v.prng.below(key_count);
                var kb: [3]u8 = undefined;
                db.delete(keyName(&kb, k)) catch |e| {
                    try v.event(.del_fault, @intCast(k), 0);
                    try v.expectFault(e);
                    return .{ .del = k };
                };
                v.model[k] = null;
                v.stats.acked_ops += 1;
                try v.event(.del_ok, @intCast(k), 0);
            } else if (roll < 92) { // get, checked against the live model
                const k = v.prng.below(key_count);
                var kb: [3]u8 = undefined;
                const got = db.get(v.gpa, keyName(&kb, k)) catch |e|
                    return v.fail("live get(key {d}) failed: {t}", .{ k, e });
                defer if (got) |g| v.gpa.free(g);
                const ok = if (v.model[k]) |want|
                    got != null and std.mem.eql(u8, got.?, want)
                else
                    got == null;
                if (!ok) return v.fail("live get(key {d}) disagrees with the model", .{k});
            } else if (roll < 97) { // compact (no logical state change)
                db.compact() catch |e| {
                    try v.event(.compact_fault, -1, 0);
                    try v.expectFault(e);
                    return .none;
                };
                try v.event(.compact_ok, -1, 0);
            } else { // keydir census
                if (db.count() != v.liveCount())
                    return v.fail("live count {d} != model {d}", .{ db.count(), v.liveCount() });
            }
        }
        try v.event(.close_clean, -1, 0);
        return .none;
    }

    /// Reboot the simulated machine, optionally rough up the media tail,
    /// reopen and model-check the recovered state (invariants 1–5), then
    /// adopt whichever legal state recovery chose.
    fn recoverAndVerify(v: *Vopr, inflight: Inflight) !void {
        if (v.sim.crashed) {
            v.stats.crashes += 1;
            try v.event(.crash, -1, 0);
        }
        v.faults.error_countdown = null;
        v.sim.reboot();

        // Garbage sector at the media tail (reordered/torn sector debris
        // landing after the last record — never inside acknowledged data,
        // which the append-only + fsync-per-ack model keeps as a prefix).
        if (v.prng.chance(1, 4)) {
            if (v.sim.fileContent(db_name)) |c| {
                if (c.len >= 8) {
                    var g: [24]u8 = undefined;
                    const n = 1 + v.prng.below(g.len);
                    v.prng.fill(g[0..n]);
                    try v.sim.appendDurable(db_name, g[0..n]);
                    v.stats.garbage_tails += 1;
                    try v.event(.garbage, -1, @intCast(n));
                }
            }
        }

        // Self-test sabotage: a "broken recovery" that loses all committed
        // records (media reset to the bare header). With >= 2 live keys
        // neither legal candidate state can match — the checker MUST fail.
        if (v.cfg.sabotage and v.liveCount() >= 2) {
            if (v.sim.fileContent(db_name)) |c| {
                if (c.len >= 8) {
                    var hdr: [8]u8 = undefined;
                    @memcpy(&hdr, c[0..8]);
                    try v.sim.installFile(db_name, &hdr);
                    v.stats.sabotages += 1;
                    try v.event(.sabotage, -1, 0);
                }
            }
        }

        var db = Db.open(v.gpa, v.st, db_name, .{}) catch |e|
            return v.fail("recovery open failed: {t}", .{e});
        defer db.close();

        if (try v.matches(&db, &v.model)) {
            try v.event(.recover_exact, -1, 0);
        } else {
            // Candidate B: the in-flight op atomically survived.
            var alt = v.model;
            var has_alt = true;
            switch (inflight) {
                .none => has_alt = false,
                .put => |p| alt[p.key] = p.val,
                .del => |k| alt[k] = null,
            }
            if (has_alt and try v.matches(&db, &alt)) {
                v.model = alt;
                v.stats.inflight_survived += 1;
                try v.event(.recover_inflight, -1, 0);
            } else {
                return v.fail(
                    "recovered state matches neither the acknowledged model nor model+in-flight",
                    .{},
                );
            }
        }

        // Invariant 5: the recovered store works — and this probe's fsync
        // also pins the adopted state as durable before the next epoch.
        db.put(probe_key, "alive") catch |e|
            return v.fail("post-recovery put failed: {t}", .{e});
        const got = db.get(v.gpa, probe_key) catch |e|
            return v.fail("post-recovery get failed: {t}", .{e});
        defer if (got) |g| v.gpa.free(g);
        if (got == null or !std.mem.eql(u8, got.?, "alive"))
            return v.fail("post-recovery probe served the wrong value", .{});
        db.delete(probe_key) catch |e|
            return v.fail("post-recovery delete failed: {t}", .{e});
        try v.event(.probe_ok, -1, 0);
    }
};

/// Does the store's state equal `model` exactly? Shared by the live `Vopr`
/// (`Vopr.matches`) and the trace `Replayer` so both check invariants 1–4
/// identically. `error.Corrupt` from a get = a torn record surfaced into the
/// keydir = a mismatch by definition (invariant 3).
fn modelMatches(gpa: Allocator, db: *Db, model: *const [key_count]?[]const u8) !bool {
    var live: usize = 0;
    var idx: usize = 0;
    while (idx < key_count) : (idx += 1) {
        var kb: [3]u8 = undefined;
        const key = keyName(&kb, idx);
        const got = db.get(gpa, key) catch |e| switch (e) {
            error.Corrupt => return false,
            else => |other| return other,
        };
        defer if (got) |g| gpa.free(g);
        if (model[idx]) |want| {
            live += 1;
            if (got == null or !std.mem.eql(u8, got.?, want)) return false;
        } else if (got != null) return false;
        if (db.exists(key) != (model[idx] != null)) return false;
    }
    return db.count() == live;
}

// ── recorded trace: a replayable capture of one seed's program ──────────────
//
// The live VOPR (`runSeedTraced`) derives its whole workload+fault schedule
// live from `Prng`, so its `Event` trace is an OBSERVATION, not a re-runnable
// program (deleting one event shifts every later PRNG draw — see shrink.zig).
// A `RecordedTrace` fixes that: it captures every structural decision as
// CONCRETE data (op list with actual value bytes, crash mode/timing/reorder
// seed, garbage-tail bytes, sabotage), so `replayTrace` can execute it — and a
// shrunk subset of it — without regenerating anything from a seed. This is the
// "trace-driven replay mode" the delta-debugging shrinker (`shrink.zig`) needs.

pub const RecordedOp = union(enum) {
    put: struct { key: usize, val: []const u8 },
    del: struct { key: usize },
    get: struct { key: usize },
    compact,
    census,
};

pub const RecordedFault = union(enum) {
    clean,
    crash: struct { mode: CrashMode, reorder_seed: u64, ops_until_crash: usize },
    io_error: struct { kind: Storage.Error, ops_until_crash: usize },
};

pub const RecordedEpoch = struct {
    fault: RecordedFault,
    short_reads: bool,
    ops: []const RecordedOp,
    /// Garbage bytes appended to the media tail at recovery (empty = none).
    garbage: []const u8 = &.{},
    sabotage: bool = false,
};

/// A captured, independently-replayable program. Owns everything (ops, value
/// bytes, garbage) in `arena`.
pub const RecordedTrace = struct {
    arena: std.heap.ArenaAllocator,
    seed: u64,
    cfg: Config,
    epochs: []RecordedEpoch,

    pub fn deinit(self: *RecordedTrace) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Total concrete ops across all epochs — the shrinker's size metric.
pub fn opCount(epochs: []const RecordedEpoch) usize {
    var n: usize = 0;
    for (epochs) |e| n += e.ops.len;
    return n;
}

/// Capture `seed`'s run as a concrete `RecordedTrace`. Draws the SAME kinds of
/// workload + fault decisions the live `runEpoch`/`recoverAndVerify` draw (so a
/// sabotage run reliably reaches ≥2 live keys and trips the checker), but
/// stores them — with actual value/garbage bytes — instead of executing, so the
/// result replays byte-faithfully via `replayTrace`.
pub fn generateTrace(gpa: Allocator, seed: u64, cfg: Config) !RecordedTrace {
    var arena_owner = std.heap.ArenaAllocator.init(gpa);
    errdefer arena_owner.deinit();
    const a = arena_owner.allocator();

    var prng = Prng.init(seed);
    var coverage: Coverage = .{};

    const epochs_n = 2 + prng.below(4);
    const epochs = try a.alloc(RecordedEpoch, epochs_n);
    for (epochs) |*ep| {
        const short_reads = prng.chance(1, 2);
        const fault: RecordedFault = switch (cfg.scheduler.plan(&prng, &coverage)) {
            .clean => .clean,
            .crash => |c| .{ .crash = .{ .mode = c.mode, .reorder_seed = c.reorder_seed, .ops_until_crash = c.ops_until_crash } },
            .io_error => |e| .{ .io_error = .{ .kind = e.kind, .ops_until_crash = e.ops_until_crash } },
        };

        const op_total = 4 + prng.below(40);
        const ops = try a.alloc(RecordedOp, op_total);
        for (ops) |*op| {
            const roll = prng.below(100);
            if (roll < 55) {
                const k = prng.below(key_count);
                const vlen = if (prng.chance(1, 12)) prng.below(max_val_len + 1) else prng.below(80);
                const val = try a.alloc(u8, vlen);
                prng.fill(val);
                op.* = .{ .put = .{ .key = k, .val = val } };
            } else if (roll < 75) {
                op.* = .{ .del = .{ .key = prng.below(key_count) } };
            } else if (roll < 92) {
                op.* = .{ .get = .{ .key = prng.below(key_count) } };
            } else if (roll < 97) {
                op.* = .compact;
            } else {
                op.* = .census;
            }
        }

        // Recovery perturbation: a garbage tail (mirrors recoverAndVerify's
        // 1-in-4 draw). Recorded bytes make replay byte-faithful; replay
        // applies them only when the media is >= 8 bytes, as the live path does.
        var garbage: []const u8 = &.{};
        if (prng.chance(1, 4)) {
            const n = 1 + prng.below(24);
            const g = try a.alloc(u8, n);
            prng.fill(g);
            garbage = g;
        }

        ep.* = .{ .fault = fault, .short_reads = short_reads, .ops = ops, .garbage = garbage, .sabotage = cfg.sabotage };
    }

    return .{ .arena = arena_owner, .seed = seed, .cfg = cfg, .epochs = epochs };
}

/// Trace-driven replay: execute a captured op/fault program against a fresh
/// `SimStorage` and re-check the SAME invariants the live VOPR checks — WITHOUT
/// drawing the workload/faults from a live `Prng`, so a shrunk candidate trace
/// is directly re-runnable. Returns `error.InvariantViolation` iff recovery
/// mis-behaves — the delta-debugging shrinker's oracle.
///
/// Every structural decision is fixed by the trace (op list + concrete value
/// bytes, crash mode/timing/reorder seed, garbage bytes, sabotage). The only
/// randomness left is `FaultStorage`'s internal draws (short-read split points
/// and the torn-prefix length of an injected write error), which never change
/// written media; they are re-derived from a dedicated `Prng(seed)` so replay
/// stays deterministic.
pub fn replayTrace(gpa: Allocator, seed: u64, epochs: []const RecordedEpoch) !void {
    var prng = Prng.init(seed);
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    var faults = FaultStorage{ .inner = sim.storage(), .prng = &prng };

    var r = Replayer{ .gpa = gpa, .sim = &sim, .faults = &faults, .st = faults.storage() };
    for (epochs, 0..) |ep, i| {
        r.epoch = i;
        faults.fired = false;
        faults.short_reads = ep.short_reads;
        switch (ep.fault) {
            .clean => {},
            .crash => |c| {
                sim.crash_mode = c.mode;
                sim.reorder_seed = c.reorder_seed;
                sim.ops_until_crash = c.ops_until_crash;
            },
            .io_error => |e| {
                faults.error_countdown = e.ops_until_crash;
                faults.error_kind = e.kind;
            },
        }
        const inflight = try r.runEpochOps(ep.ops);
        try r.recoverAndVerify(ep.garbage, ep.sabotage, inflight);
    }
}

/// The trace-consuming twin of `Vopr`: same store, same fault machinery, same
/// invariant checks (`modelMatches`), but its ops + faults come from a
/// `RecordedEpoch` list rather than from `Prng`. Any invariant breach is a
/// bare `error.InvariantViolation` (no per-event report — replay is a silent
/// oracle called in a tight ddmin loop).
const Replayer = struct {
    gpa: Allocator,
    epoch: usize = 0,
    sim: *SimStorage,
    faults: *FaultStorage,
    st: Storage,
    model: [key_count]?[]const u8 = @splat(null),

    fn liveCount(r: *const Replayer) usize {
        var n: usize = 0;
        for (r.model) |m| {
            if (m != null) n += 1;
        }
        return n;
    }

    fn expectFault(r: *Replayer, e: anyerror) !void {
        if (e == error.Crashed) return;
        if (r.faults.fired and e == r.faults.error_kind) return;
        return error.InvariantViolation;
    }

    fn runEpochOps(r: *Replayer, ops: []const RecordedOp) !Inflight {
        var db = Db.open(r.gpa, r.st, db_name, .{}) catch |e| {
            if (e == error.Crashed or r.faults.fired) return .none;
            return error.InvariantViolation;
        };
        defer db.close();

        for (ops) |op| {
            switch (op) {
                .put => |p| {
                    var kb: [3]u8 = undefined;
                    db.put(keyName(&kb, p.key), p.val) catch |e| {
                        try r.expectFault(e);
                        return .{ .put = .{ .key = p.key, .val = p.val } };
                    };
                    r.model[p.key] = p.val;
                },
                .del => |d| {
                    var kb: [3]u8 = undefined;
                    db.delete(keyName(&kb, d.key)) catch |e| {
                        try r.expectFault(e);
                        return .{ .del = d.key };
                    };
                    r.model[d.key] = null;
                },
                .get => |g| {
                    var kb: [3]u8 = undefined;
                    const got = db.get(r.gpa, keyName(&kb, g.key)) catch return error.InvariantViolation;
                    defer if (got) |x| r.gpa.free(x);
                    const ok = if (r.model[g.key]) |want|
                        got != null and std.mem.eql(u8, got.?, want)
                    else
                        got == null;
                    if (!ok) return error.InvariantViolation;
                },
                .compact => {
                    db.compact() catch |e| {
                        try r.expectFault(e);
                        return .none;
                    };
                },
                .census => {
                    if (db.count() != r.liveCount()) return error.InvariantViolation;
                },
            }
        }
        return .none;
    }

    fn recoverAndVerify(r: *Replayer, garbage: []const u8, sabotage: bool, inflight: Inflight) !void {
        r.faults.error_countdown = null;
        r.sim.reboot();

        if (garbage.len > 0) {
            if (r.sim.fileContent(db_name)) |c| {
                if (c.len >= 8) try r.sim.appendDurable(db_name, garbage);
            }
        }

        if (sabotage and r.liveCount() >= 2) {
            if (r.sim.fileContent(db_name)) |c| {
                if (c.len >= 8) {
                    var hdr: [8]u8 = undefined;
                    @memcpy(&hdr, c[0..8]);
                    try r.sim.installFile(db_name, &hdr);
                }
            }
        }

        var db = Db.open(r.gpa, r.st, db_name, .{}) catch return error.InvariantViolation;
        defer db.close();

        if (try modelMatches(r.gpa, &db, &r.model)) {
            // recovered state == acknowledged model (candidate A)
        } else {
            var alt = r.model;
            var has_alt = true;
            switch (inflight) {
                .none => has_alt = false,
                .put => |p| alt[p.key] = p.val,
                .del => |k| alt[k] = null,
            }
            if (has_alt and try modelMatches(r.gpa, &db, &alt)) {
                r.model = alt;
            } else {
                return error.InvariantViolation;
            }
        }

        db.put(probe_key, "alive") catch return error.InvariantViolation;
        const got = db.get(r.gpa, probe_key) catch return error.InvariantViolation;
        defer if (got) |g| r.gpa.free(g);
        if (got == null or !std.mem.eql(u8, got.?, "alive")) return error.InvariantViolation;
        db.delete(probe_key) catch return error.InvariantViolation;
    }
};

/// Run one full simulation for `seed`: several epochs of
/// open → random ops → scheduled fault → crash → recover → verify.
/// `stats` is updated incrementally (usable even when an error returns).
/// Thin wrapper over `runSeedTraced` for callers that don't need the trace.
pub fn runSeed(gpa: Allocator, seed: u64, cfg: Config, stats: *Stats) !void {
    return runSeedTraced(gpa, seed, cfg, stats, null);
}

/// Same as `runSeed`, but when `trace_out` is non-null the full op/fault
/// trace is cloned into it before returning — on success AND on failure
/// (captured via `defer`, so an early `try`-propagated `InvariantViolation`
/// still fills it in). This is what lets `shrink.zig`'s failing-seed search
/// hand back a real reproducer log instead of just an error code.
pub fn runSeedTraced(gpa: Allocator, seed: u64, cfg: Config, stats: *Stats, trace_out: ?*std.ArrayList(Event)) !void {
    var prng = Prng.init(seed);
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    var faults = FaultStorage{ .inner = sim.storage(), .prng = &prng };
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var coverage: Coverage = .{};

    var v = Vopr{
        .gpa = gpa,
        .arena = arena_state.allocator(),
        .cfg = cfg,
        .seed = seed,
        .prng = &prng,
        .sim = &sim,
        .faults = &faults,
        .st = faults.storage(),
        .stats = stats,
    };
    defer {
        if (trace_out) |out| {
            out.clearRetainingCapacity();
            // Best-effort: an OOM here must not shadow the real result
            // (a caught InvariantViolation, or success) with a spurious one.
            out.appendSlice(gpa, v.trace.items) catch {};
        }
        v.trace.deinit(gpa);
    }
    defer {
        stats.io_errors += faults.injected_errors;
        stats.short_reads += faults.injected_short_reads;
    }

    const epochs = 2 + prng.below(4);
    while (v.epoch < epochs) : (v.epoch += 1) {
        stats.epochs += 1;

        // Plan this epoch's single scheduled fault — all from the seed, via
        // the pluggable scheduling policy (`cfg.scheduler`, default
        // `scheduler.uniformScheduler()`; see scheduler.zig).
        faults.fired = false;
        faults.short_reads = prng.chance(1, 2);
        switch (cfg.scheduler.plan(&prng, &coverage)) {
            .clean => {}, // fault-free epoch: close + reopen must be exact
            .crash => |c| {
                sim.crash_mode = c.mode;
                sim.reorder_seed = c.reorder_seed;
                sim.ops_until_crash = c.ops_until_crash;
            },
            .io_error => |e| {
                faults.error_countdown = e.ops_until_crash;
                faults.error_kind = e.kind;
            },
        }

        const inflight = try v.runEpoch();
        try v.recoverAndVerify(inflight);
    }

    stats.reorder_holes += sim.holes_punched;

    // Per-seed fingerprint of the surviving media (determinism witness).
    const content = sim.fileContent(db_name) orelse "";
    var fp_prng = Prng.init(seed ^ std.hash.Crc32.hash(content));
    stats.fingerprint +%= fp_prng.next();
}

// ── tests ────────────────────────────────────────────────────────────────────

test "VOPR: randomized fault schedules across seeds, model-checked recovery" {
    var stats: Stats = .{};
    var seed: u64 = 1;
    while (seed <= seed_count) : (seed += 1) {
        try runSeed(testing.allocator, seed, .{}, &stats);
    }
    // Teeth: the schedules must have actually exercised faults — a harness
    // whose injections never fire (or a no-op simulator) cannot pass this.
    try testing.expect(stats.crashes >= seed_count / 2);
    try testing.expect(stats.io_errors >= seed_count / 10);
    try testing.expect(stats.short_reads >= seed_count);
    try testing.expect(stats.garbage_tails >= seed_count / 10);
    try testing.expect(stats.inflight_survived >= seed_count / 200);
    try testing.expect(stats.acked_ops >= seed_count * 10);
    // The non-contiguous durability mode must have actually punched holes in
    // an un-synced multi-write window (else out-of-order durability is untested).
    try testing.expect(stats.reorder_holes >= seed_count / 200);
}

test "VOPR: identical seed reproduces the identical run" {
    var a: Stats = .{};
    var b: Stats = .{};
    try runSeed(testing.allocator, 0xdead_beef, .{}, &a);
    try runSeed(testing.allocator, 0xdead_beef, .{}, &b);
    try testing.expectEqualDeep(a, b);
    try testing.expect(a.fingerprint != 0);
    try testing.expect(a.acked_ops > 0);
}

test "VOPR self-test: a recovery that loses committed data is caught" {
    var caught: usize = 0;
    var seed: u64 = 1;
    while (seed <= 12) : (seed += 1) {
        var stats: Stats = .{};
        if (runSeed(testing.allocator, seed, .{ .sabotage = true, .quiet = true }, &stats)) |_| {
            // Passing is only legal if the sabotage never got to fire
            // (model never reached 2 live keys at a recovery point).
            try testing.expectEqual(@as(usize, 0), stats.sabotages);
        } else |e| {
            try testing.expectEqual(error.InvariantViolation, e);
            try testing.expect(stats.sabotages >= 1);
            caught += 1;
        }
    }
    // The checker must have caught essentially all sabotaged runs.
    try testing.expect(caught >= 10);
}

test "record→replay: a generated trace replays deterministically and passes (no sabotage)" {
    var tr = try generateTrace(testing.allocator, 0xFEED_1234, .{});
    defer tr.deinit();
    try testing.expect(opCount(tr.epochs) > 0);
    // A correct store: replay of a faithfully-captured run raises no invariant
    // violation, and does so identically every time (determinism witness).
    try replayTrace(testing.allocator, tr.seed, tr.epochs);
    try replayTrace(testing.allocator, tr.seed, tr.epochs);
}

test "record→replay: a sabotage trace with >=2 live keys is caught on replay" {
    // Sabotage wipes committed media at recovery whenever >=2 keys are live —
    // most seeds reach that, so a failing recorded trace is easy to find, and
    // replaying it reproduces the SAME InvariantViolation with no live PRNG.
    var seed: u64 = 1;
    var found = false;
    while (seed <= 64) : (seed += 1) {
        var tr = try generateTrace(testing.allocator, seed, .{ .sabotage = true });
        defer tr.deinit();
        if (replayTrace(testing.allocator, tr.seed, tr.epochs)) |_| {
            continue;
        } else |e| {
            try testing.expectEqual(error.InvariantViolation, e);
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "VOPR coverage-guided scheduler drives a full seed sweep without regressions" {
    // The coverage-guided policy is a drop-in `Config.scheduler`: thread ONE
    // CoverageGuided across the seed loop and it must run the same model-checked
    // recovery clean, while converging its cross-seed tally to full coverage.
    var cg: scheduler_mod.CoverageGuided = .{};
    var stats: Stats = .{};
    var seed: u64 = 1;
    while (seed <= 200) : (seed += 1) {
        try runSeed(testing.allocator, seed, .{ .scheduler = cg.scheduler() }, &stats);
    }
    // Only the uncoverable (.clean, .late) cell may remain after 200 seeds.
    try testing.expectEqual(@as(usize, 1), cg.session.uncoveredCount());
    try testing.expect(stats.crashes > 0);
    try testing.expect(stats.io_errors > 0);
}
