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

const Prng = struct {
    state: u64,

    fn init(seed: u64) Prng {
        var p = Prng{ .state = seed };
        _ = p.next(); // decorrelate low-entropy seeds (0, 1, 2, …)
        return p;
    }

    fn next(p: *Prng) u64 {
        p.state +%= 0x9e3779b97f4a7c15;
        var z = p.state;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }

    /// Uniform-ish integer in [0, n). Modulo bias is irrelevant here.
    fn below(p: *Prng, n: usize) usize {
        std.debug.assert(n > 0);
        return @intCast(p.next() % @as(u64, n));
    }

    /// True with probability num/den.
    fn chance(p: *Prng, num: usize, den: usize) bool {
        return p.below(den) < num;
    }

    fn fill(p: *Prng, buf: []u8) void {
        var i: usize = 0;
        while (i < buf.len) : (i += 8) {
            var tmp: [8]u8 = undefined;
            std.mem.writeInt(u64, &tmp, p.next(), .little);
            const n = @min(@as(usize, 8), buf.len - i);
            @memcpy(buf[i..][0..n], tmp[0..n]);
        }
    }
};

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
};

// ── the runner ───────────────────────────────────────────────────────────────

const Config = struct {
    /// Self-test mode: at recovery time, "lose" the committed media content
    /// (a deliberately broken recovery). The model checker MUST catch it.
    sabotage: bool = false,
    /// Suppress the failure report (for the self-test's expected failures).
    quiet: bool = false,
};

/// Aggregated across seeds by the caller; also the determinism witness.
const Stats = struct {
    epochs: usize = 0,
    acked_ops: usize = 0,
    crashes: usize = 0,
    io_errors: usize = 0,
    short_reads: usize = 0,
    garbage_tails: usize = 0,
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

const Event = struct {
    epoch: u16,
    code: Code,
    key: i32,
    len: u32,

    const Code = enum {
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
        var live: usize = 0;
        var idx: usize = 0;
        while (idx < key_count) : (idx += 1) {
            var kb: [3]u8 = undefined;
            const key = keyName(&kb, idx);
            const got = db.get(v.gpa, key) catch |e| switch (e) {
                error.Corrupt => return false,
                else => |other| return other,
            };
            defer if (got) |g| v.gpa.free(g);
            if (model[idx]) |want| {
                live += 1;
                if (got == null or !std.mem.eql(u8, got.?, want)) return false;
            } else if (got != null) return false;
            if (db.exists(key) != (model[idx] != null)) return false;
        }
        return db.count() == live;
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

/// Run one full simulation for `seed`: several epochs of
/// open → random ops → scheduled fault → crash → recover → verify.
/// `stats` is updated incrementally (usable even when an error returns).
fn runSeed(gpa: Allocator, seed: u64, cfg: Config, stats: *Stats) !void {
    var prng = Prng.init(seed);
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    var faults = FaultStorage{ .inner = sim.storage(), .prng = &prng };
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

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
    defer v.trace.deinit(gpa);
    defer {
        stats.io_errors += faults.injected_errors;
        stats.short_reads += faults.injected_short_reads;
    }

    const epochs = 2 + prng.below(4);
    while (v.epoch < epochs) : (v.epoch += 1) {
        stats.epochs += 1;

        // Plan this epoch's single scheduled fault — all from the seed.
        faults.fired = false;
        faults.short_reads = prng.chance(1, 2);
        const plan = prng.below(10);
        if (plan < 6) { // crash the machine at a random side effect
            const modes = [_]CrashMode{ .lose_unsynced, .keep_unsynced, .torn_tail };
            sim.crash_mode = modes[prng.below(modes.len)];
            sim.ops_until_crash = if (prng.chance(1, 3)) prng.below(8) else prng.below(120);
        } else if (plan < 8) { // transient I/O error (with torn prefix write)
            faults.error_countdown = if (prng.chance(1, 3)) prng.below(8) else prng.below(100);
            faults.error_kind = if (prng.chance(1, 2)) error.NoSpaceLeft else error.InputOutput;
        } // else: clean epoch (fault-free close + reopen must be exact)

        const inflight = try v.runEpoch();
        try v.recoverAndVerify(inflight);
    }

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
