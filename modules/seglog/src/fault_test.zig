// SPDX-License-Identifier: MIT

//! The headline test: crash the simulated machine at every storage side
//! effect of a scripted workload, under every crash model, reboot, reopen,
//! and check what survived — `kv`'s mini-VOPR, pointed at this module.
//!
//! The recovered log must be exactly one of the states the workload could
//! have reached:
//!
//!   1. every step acknowledged before the crash is there — nothing a
//!      returned `append`, `rotate` or `dropBefore` did is lost;
//!   2. of the step in flight, only what its contract allows: an `append`
//!      whole or not at all; an `appendMany` as a whole-record prefix; a
//!      `rotate` not at all, fully, or with only the old segment sealed; a
//!      `dropBefore` not at all or fully;
//!   3. nothing else — no torn record served, no record moved, and every
//!      position consistent with the format's arithmetic;
//!   4. the recovered log accepts a new record and keeps it across a reopen.
//!
//! A second sweep crashes the machine again *inside* the recovering `open`,
//! because repair is where a store is most fragile and a first sweep never
//! reaches it.

const std = @import("std");
const seglog = @import("root.zig");
const Log = seglog.Log;
const Position = seglog.Position;
const SimStorage = seglog.SimStorage;
const CrashMode = seglog.CrashMode;
const testing = std.testing;
const gpa = testing.allocator;

// ── the scripted workload ────────────────────────────────────────────────────

const Step = union(enum) {
    rotate: u64,
    append: []const u8,
    append_many: []const []const u8,
    drop_before: u64,
    sync,
    /// `compact(id)`, dropping every payload that starts with "x".
    compact: u64,
    compress: u64,
};

fn dropX(_: void, r: seglog.Record) bool {
    return !std.mem.startsWith(u8, r.payload, "x");
}

const big = &@as([3000:0]u8, @splat('B'));

const script = [_]Step{
    .{ .rotate = 10 },
    .{ .append = "a" },
    .{ .append = "" }, // an empty payload is still a record
    .{ .append_many = &.{ "m1", "m2", "m3" } },
    .{ .rotate = 11 },
    .{ .append = big },
    .{ .rotate = 11 }, // the active id: must do no I/O at all
    .{ .append = "b" },
    .{ .rotate = 13 },
    .{ .drop_before = 13 }, // drops 10 and 11
    .{ .append_many = &.{ "n1", "n2" } },
    .{ .drop_before = 13 }, // nothing older than 13: no I/O
    .{ .rotate = 14 },
    .{ .append = "c" },
    .{ .drop_before = 100 }, // drops 13, and never the newest
    .{ .append = "d" },
};

/// The indices of steps that must perform no storage side effect.
const no_io_steps = [_]usize{ 6, 11 };

/// Every segment id the script creates.
const script_ids = [_]u64{ 10, 11, 13, 14 };

/// The same kinds of step with the sync deferred (`.manual`, and
/// `.every_bytes`, whose threshold syncs fall wherever the byte counts put
/// them): between syncs a crash may take any whole-record suffix of what was
/// appended, and never anything a sync covered.
const script_deferred = [_]Step{
    .{ .rotate = 20 },
    .{ .append = "a" },
    .{ .append = "" },
    .sync,
    .sync, // nothing waiting: no I/O
    .{ .append_many = &.{ "m1", "m2", "m3" } },
    .{ .append = "b" },
    .{ .rotate = 21 }, // the seal syncs what was waiting
    .{ .append = big },
    .{ .append = "c" },
    .sync,
    .{ .append = "d" },
    .{ .drop_before = 21 },
    .{ .append_many = &.{ "n1", "n2" } },
    .sync,
    .{ .rotate = 22 },
    .{ .append = "e" }, // left unsynced at the end
};

const deferred_ids = [_]u64{ 20, 21, 22 };

/// Compaction between everything else: a crash leaves the old segment or the
/// new, never a mix, and `COMPACT.tmp` never outlives the next `open`.
const script_compact = [_]Step{
    .{ .rotate = 30 },
    .{ .append = "x1" },
    .{ .append = "k1" },
    .{ .append_many = &.{ "x2", "k2" } },
    .{ .rotate = 31 },
    .{ .append = "k3" },
    .{ .append = "x3" },
    .{ .compact = 30 },
    .{ .rotate = 32 },
    .{ .compact = 31 },
    .{ .compact = 30 }, // again: already compacted
    .{ .append = "k4" },
    .{ .drop_before = 31 },
    .{ .append = "k5" },
};

const compact_ids = [_]u64{ 30, 31, 32 };

/// Compression between everything else: a crash leaves the raw segment or
/// the compressed one, the same records either way, and `open` keeps exactly
/// the file of the segment's form. Compacting a compressed segment too.
const script_compress = [_]Step{
    .{ .rotate = 40 },
    .{ .append = "a" },
    .{ .append_many = &.{ "x1", "k1" } },
    .{ .rotate = 41 },
    .{ .compress = 40 },
    .{ .append = "b" },
    .{ .compress = 40 }, // again: nothing changes
    .{ .rotate = 42 },
    .{ .compress = 41 },
    .{ .compact = 40 }, // compressed: stays compressed
    .{ .drop_before = 41 },
    .{ .append = "c" },
};

const compress_ids = [_]u64{ 40, 41, 42 };

/// The model, the driver and the recovery check for one script under one
/// sync policy.
/// `concurrent`: drive the script through `Concurrent` (one thread) instead
/// of `Log`, so its split sync — begun under the lock, run outside it,
/// finished under it again — meets every crash too.
/// `prealloc`: `Options.preallocate` — small, so that appends cross the
/// reservation often and crashes land on zero tails.
fn Sweep(comptime sc: []const Step, comptime ids: []const u64, comptime policy: seglog.SyncPolicy, comptime concurrent: bool, comptime prealloc: u64) type {
    return struct {
        const opts: seglog.Options = .{ .create = true, .sync = policy, .preallocate = prealloc };

        /// Reserved zeros `open` found past the newest segment's data and did not
        /// count as cut — the teeth of the preallocating sweeps.
        var zeros_absorbed: u64 = 0;

        // ── the model ────────────────────────────────────────────────────────────────

        const Rec = struct { seg: u64, lsn: u64, payload: []const u8 };

        const State = struct {
            live: std.ArrayList(u64) = .empty,
            recs: std.ArrayList(Rec) = .empty,
            active: ?u64 = null,
            /// LSNs count every record ever appended, dropped ones included.
            next_lsn: u64 = 1,
            /// Trailing records of the active segment no sync has covered yet —
            /// what a crash may take. Always 0 under `.always`.
            unsynced: usize = 0,

            fn deinit(s: *State) void {
                s.live.deinit(gpa);
                s.recs.deinit(gpa);
            }

            fn clone(s: *const State) !State {
                var c: State = .{ .active = s.active, .next_lsn = s.next_lsn, .unsynced = s.unsynced };
                errdefer c.deinit();
                try c.live.appendSlice(gpa, s.live.items);
                try c.recs.appendSlice(gpa, s.recs.items);
                return c;
            }

            fn apply(s: *State, step: Step) !void {
                switch (step) {
                    .rotate => |id| {
                        if (s.active) |a| if (a == id) return;
                        s.active = id;
                        s.unsynced = 0; // the seal synced them
                        try s.live.append(gpa, id);
                    },
                    .sync => s.unsynced = 0,
                    .compress => {},
                    .compact => |id| {
                        var i: usize = 0;
                        while (i < s.recs.items.len) {
                            const r = s.recs.items[i];
                            if (r.seg == id and std.mem.startsWith(u8, r.payload, "x")) _ = s.recs.orderedRemove(i) else i += 1;
                        }
                    },
                    .append => |p| try s.add(p),
                    .append_many => |ps| for (ps) |p| try s.add(p),
                    .drop_before => |id| {
                        const n = s.live.items.len;
                        var k: usize = 0;
                        while (k + 1 < n and s.live.items[k] < id) k += 1;
                        const first_kept = s.live.items[k];
                        try s.live.replaceRange(gpa, 0, k, &.{});
                        var i: usize = 0;
                        while (i < s.recs.items.len) {
                            if (s.recs.items[i].seg < first_kept) _ = s.recs.orderedRemove(i) else i += 1;
                        }
                    },
                }
            }

            fn add(s: *State, p: []const u8) !void {
                try s.recs.append(gpa, .{ .seg = s.active.?, .lsn = s.next_lsn, .payload = p });
                s.next_lsn += 1;
                if (policy != .always) s.unsynced += 1;
            }

            fn after(steps: []const Step) !State {
                var s: State = .{};
                errdefer s.deinit();
                for (steps) |st| try s.apply(st);
                return s;
            }

            fn eql(a: *const State, b: *const State) bool {
                if (a.active != b.active) return false;
                if (!std.mem.eql(u64, a.live.items, b.live.items)) return false;
                if (a.recs.items.len != b.recs.items.len) return false;
                for (a.recs.items, b.recs.items) |x, y| {
                    if (x.seg != y.seg or x.lsn != y.lsn or !std.mem.eql(u8, x.payload, y.payload)) return false;
                }
                return true;
            }
        };

        /// Every state a crash after `completed` acknowledged steps may legally
        /// leave behind.
        fn acceptable(completed: usize, crashed: bool) !std.ArrayList(State) {
            var out = try acceptableSteps(completed, crashed);
            errdefer {
                for (out.items) |*s| s.deinit();
                out.deinit(gpa);
            }
            // Deferred sync: of each, any whole-record suffix of what no sync covered
            // may be gone too.
            const n = out.items.len;
            for (0..n) |i| {
                for (1..out.items[i].unsynced + 1) |j| {
                    var t = try out.items[i].clone();
                    errdefer t.deinit();
                    t.recs.shrinkRetainingCapacity(t.recs.items.len - j);
                    t.unsynced -= j;
                    try out.append(gpa, t);
                }
            }
            return out;
        }

        fn acceptableSteps(completed: usize, crashed: bool) !std.ArrayList(State) {
            var out: std.ArrayList(State) = .empty;
            errdefer {
                for (out.items) |*s| s.deinit();
                out.deinit(gpa);
            }
            const base = try State.after(sc[0..completed]);
            try out.append(gpa, base);
            if (!crashed or completed == sc.len) return out;

            switch (sc[completed]) {
                .append, .drop_before, .sync, .compact, .compress => try out.append(gpa, try State.after(sc[0 .. completed + 1])),
                .append_many => |ps| for (1..ps.len + 1) |j| {
                    var s = try base.clone();
                    errdefer s.deinit();
                    try s.apply(.{ .append_many = ps[0..j] });
                    try out.append(gpa, s);
                },
                .rotate => {
                    // The old segment sealed, the new one not yet committed.
                    var sealed_only = try base.clone();
                    sealed_only.active = null;
                    try out.append(gpa, sealed_only);
                    try out.append(gpa, try State.after(sc[0 .. completed + 1]));
                },
            }
            return out;
        }

        // ── driver ───────────────────────────────────────────────────────────────────

        const Outcome = struct { completed: usize, crashed: bool };

        /// Run the workload. When `per_step` is given, record how many side effects
        /// each step performed.
        fn runScript(sim: *SimStorage, per_step: ?*[sc.len]usize) Outcome {
            return if (concurrent) runConcurrent(sim, per_step) else runLog(sim, per_step);
        }

        fn runConcurrent(sim: *SimStorage, per_step: ?*[sc.len]usize) Outcome {
            var c = seglog.Concurrent.open(gpa, sim.storage(), testing.io, opts) catch |e| switch (e) {
                error.Crashed => return .{ .completed = 0, .crashed = true },
                else => std.debug.panic("workload open failed with {t}, not a crash", .{e}),
            };
            defer c.close();
            for (sc, 0..) |step, i| {
                const before = sim.ops_seen;
                const result: anyerror!void = switch (step) {
                    .rotate => |id| c.rotate(id),
                    .append => |p| if (c.append(p)) |_| {} else |e| e,
                    .append_many => |ps| if (c.appendMany(ps)) |_| {} else |e| e,
                    .drop_before => |id| if (c.dropBefore(id)) |_| {} else |e| e,
                    .sync => c.sync(),
                    .compact => |id| if (c.compact(id, {}, dropX)) |_| {} else |e| e,
                    .compress => |id| if (c.compress(id)) |_| {} else |e| e,
                };
                result catch |e| switch (e) {
                    error.Crashed => return .{ .completed = i, .crashed = true },
                    else => std.debug.panic("workload step {d} failed with {t}, not a crash", .{ i, e }),
                };
                if (per_step) |ps| ps[i] = sim.ops_seen - before;
            }
            return .{ .completed = sc.len, .crashed = false };
        }

        fn runLog(sim: *SimStorage, per_step: ?*[sc.len]usize) Outcome {
            var log = Log.open(gpa, sim.storage(), opts) catch |e| switch (e) {
                error.Crashed => return .{ .completed = 0, .crashed = true },
                else => std.debug.panic("workload open failed with {t}, not a crash", .{e}),
            };
            defer log.close();
            for (sc, 0..) |step, i| {
                const before = sim.ops_seen;
                const result: anyerror!void = switch (step) {
                    .rotate => |id| log.rotate(id),
                    .append => |p| if (log.append(p)) |_| {} else |e| e,
                    .append_many => |ps| if (log.appendMany(ps)) |_| {} else |e| e,
                    .drop_before => |id| if (log.dropBefore(id)) |_| {} else |e| e,
                    .sync => log.sync(),
                    .compact => |id| if (log.compact(id, {}, dropX)) |_| {} else |e| e,
                    .compress => |id| if (log.compress(id)) |_| {} else |e| e,
                };
                result catch |e| switch (e) {
                    error.Crashed => return .{ .completed = i, .crashed = true },
                    else => std.debug.panic("workload step {d} failed with {t}, not a crash", .{ i, e }),
                };
                if (per_step) |ps| ps[i] = sim.ops_seen - before;
            }
            return .{ .completed = sc.len, .crashed = false };
        }

        /// What a recovered log holds, read through its public API only. Also checks
        /// every position against the format: a segment's first record at the end
        /// of its header, each later one exactly where the previous one said.
        fn observe(log: *Log) !State {
            var s: State = .{ .active = log.activeSegment() };
            errdefer s.deinit();
            try s.live.appendSlice(gpa, log.segments());
            var it = log.iterator(null);
            defer it.deinit();
            var prev: ?seglog.Record = null;
            while (try it.next()) |r| {
                if (prev) |p| {
                    if (p.pos.segment == r.pos.segment) {
                        try testing.expect(p.next.eql(r.pos)); // the place; a compacted gap may raise the LSN
                    } else {
                        try testing.expectEqual(seglog.segment_header_len, r.pos.offset);
                    }
                } else try testing.expectEqual(seglog.segment_header_len, r.pos.offset);
                // Payloads are compared by content; the model's are static slices.
                const payload = payloadFor(r.payload) orelse return error.UnknownPayload;
                try s.recs.append(gpa, .{ .seg = r.pos.segment, .lsn = r.lsn, .payload = payload });
                prev = .{ .pos = r.pos, .next = r.next, .lsn = r.lsn, .ts = r.ts, .payload = &.{} };
            }
            return s;
        }

        /// Map a read payload back to the script's own slice for it, so a
        /// recovered record that the workload never wrote is caught rather than
        /// compared as bytes that happen to match.
        fn payloadFor(bytes: []const u8) ?[]const u8 {
            for (sc) |step| switch (step) {
                .append => |p| if (std.mem.eql(u8, p, bytes)) return p,
                .append_many => |ps| for (ps) |p| if (std.mem.eql(u8, p, bytes)) return p,
                else => {},
            };
            if (std.mem.eql(u8, "probe", bytes)) return "probe";
            return null;
        }

        /// Reboot, reopen, and hold the recovered log to the invariants.
        fn verifyRecovery(sim: *SimStorage, out: Outcome, cut: ?*u64) !void {
            sim.reboot();
            var len_before: [ids.len]u64 = undefined;
            for (ids, &len_before) |id, *l| {
                var nb: [28]u8 = undefined;
                l.* = if (sim.fileContent(segFile(&nb, id))) |c| c.len else 0;
            }
            var log = try Log.open(gpa, sim.storage(), opts);
            if (cut) |c| c.* += log.bytesCutOnOpen();
            if (log.end()) |e| if (std.mem.findScalar(u64, ids, e.segment)) |i| {
                zeros_absorbed += len_before[i] -| (e.offset + log.bytesCutOnOpen());
            };

            {
                var got = try observe(&log);
                defer got.deinit();
                var legal = try acceptable(out.completed, out.crashed);
                defer {
                    for (legal.items) |*s| s.deinit();
                    legal.deinit(gpa);
                }
                for (legal.items) |*s| {
                    if (s.eql(&got)) break;
                } else {
                    log.close();
                    return error.RecoveredStateNotLegal;
                }
            }

            // The newest segment ends exactly where the log will append next: `open`
            // cut the tail rather than just deciding to write over it. Stated
            // directly, because the simulator's own tripwire for this is off under
            // `.keep_unsynced`.
            if (log.end()) |e| {
                var nb: [28]u8 = undefined;
                const name = std.mem.print(&nb, "seg-{d:0>20}.log", .{e.segment}) catch unreachable;
                const len = (sim.fileContent(name) orelse return error.SegmentWithoutFile).len;
                if (len != e.offset) {
                    log.close();
                    return error.TailNotCut;
                }
            }

            // A segment file exists exactly when its segment is live: no crash, at
            // any point, may leave a file the manifest does not name, or name one
            // that is not there. This is what the manifest-first orderings in
            // `rotate` and `dropBefore` are for, so it is checked, not assumed.
            // Of a live segment exactly one file, of its form: a compression a
            // crash interrupted leaves neither both nor none.
            for (ids) |id| {
                var nb: [28]u8 = undefined;
                const raw = sim.fileContent(std.mem.print(&nb, "seg-{d:0>20}.log", .{id}) catch unreachable) != null;
                const zst = sim.fileContent(std.mem.print(&nb, "seg-{d:0>20}.zst", .{id}) catch unreachable) != null;
                const live = std.mem.findScalar(u64, log.segments(), id) != null;
                if (raw and zst) {
                    log.close();
                    return error.BothForms;
                }
                if ((raw or zst) != live) {
                    log.close();
                    return if (raw or zst) error.FileWithoutSegment else error.SegmentWithoutFile;
                }
            }

            // `open` removed a compaction's temp file a crash left behind.
            if (sim.fileContent("COMPACT.tmp") != null or sim.fileContent("COMPRESS.tmp") != null) {
                log.close();
                return error.CompactTempLeft;
            }

            // The recovered log must take a new record and keep it.
            if (log.activeSegment() == null) try log.rotate((log.newest() orelse 0) + 1000);
            const want_lsn = log.nextLsn();
            const at = (try log.append("probe")).pos;
            try log.sync();
            log.close();

            var again = try Log.open(gpa, sim.storage(), .{});
            defer again.close();
            var it = again.iterator(at);
            defer it.deinit();
            const r = (try it.next()) orelse return error.ProbeLost;
            try testing.expectEqualStrings("probe", r.payload);
            try testing.expectEqual(want_lsn, r.lsn);
            try testing.expectEqual(@as(?seglog.Record, null), try it.next());
        }

        fn countSideEffects() !usize {
            var sim = SimStorage.init(gpa);
            defer sim.deinit();
            const out = runScript(&sim, null);
            try testing.expect(!out.crashed);
            return sim.ops_seen;
        }
    };
}

// ── the sweeps ───────────────────────────────────────────────────────────────

const Always = Sweep(&script, &script_ids, .always, false, 0);
const Manual = Sweep(&script_deferred, &deferred_ids, .manual, false, 0);
const EveryBytes = Sweep(&script_deferred, &deferred_ids, .{ .every_bytes = 60 }, false, 0);
const ConcurrentAlways = Sweep(&script, &script_ids, .always, true, 0);
const ConcurrentManual = Sweep(&script_deferred, &deferred_ids, .manual, true, 0);
const Compacting = Sweep(&script_compact, &compact_ids, .always, false, 0);
const Compressing = Sweep(&script_compress, &compress_ids, .always, false, 0);
const PreallocAlways = Sweep(&script, &script_ids, .always, false, 128);
const PreallocManual = Sweep(&script_deferred, &deferred_ids, .manual, false, 128);
const PreallocConcurrent = Sweep(&script, &script_ids, .always, true, 128);

/// A segment's file name.
fn segFile(buf: *[28]u8, id: u64) []const u8 {
    return std.mem.print(buf, "seg-{d:0>20}.log", .{id}) catch unreachable;
}

fn workloadIsSane(comptime S: type, comptime sc: []const Step, no_io: []const usize, min_ops: usize) !void {
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    var per_step: [sc.len]usize = undefined;
    const out = S.runScript(&sim, &per_step);
    try testing.expect(!out.crashed);
    try testing.expectEqual(sc.len, out.completed);
    for (no_io) |i| try testing.expectEqual(@as(usize, 0), per_step[i]);
    // Every other step touches storage, or the sweep would skip over it.
    for (per_step, 0..) |n, i| {
        if (std.mem.findScalar(usize, no_io, i) == null) try testing.expect(n > 0);
    }
    // The lock was really taken, so the sweep covers acquiring it.
    try testing.expect(sim.fileContent("LOCK") != null);
    try S.verifyRecovery(&sim, out, null);
    // Big enough to mean something, and identical on a repeat.
    const counted = try S.countSideEffects();
    try testing.expect(counted >= min_ops);
    try testing.expectEqual(counted, try S.countSideEffects());
}

fn sweepEveryModel(comptime S: type) !void {
    const total = try S.countSideEffects();
    var cut_total: u64 = 0;
    for ([_]CrashMode{ .lose_unsynced, .keep_unsynced, .torn_tail }) |mode| {
        var point: usize = 0;
        while (point < total) : (point += 1) {
            var sim = SimStorage.init(gpa);
            defer sim.deinit();
            sim.crash_mode = mode;
            sim.ops_until_crash = point;
            const out = S.runScript(&sim, null);
            try testing.expect(out.crashed);
            S.verifyRecovery(&sim, out, &cut_total) catch |e| {
                std.debug.print("fault sweep FAILED: mode={t} point={d}/{d} completed={d}\n", .{ mode, point, total, out.completed });
                return e;
            };
        }
    }
    // Teeth: some crash must have left a torn tail that `open` then cut, or
    // the sweep never exercised repair at all.
    try testing.expect(cut_total > 0);
}

/// Returns the holes the reorder model punched.
fn sweepReorder(comptime S: type) !usize {
    const total = try S.countSideEffects();
    var holes: usize = 0;
    for ([_]u64{ 1, 2, 3, 5, 8 }) |seed| {
        var point: usize = 0;
        while (point < total) : (point += 1) {
            var sim = SimStorage.init(gpa);
            defer sim.deinit();
            sim.crash_mode = .reorder_unsynced;
            sim.reorder_seed = seed;
            sim.ops_until_crash = point;
            const out = S.runScript(&sim, null);
            holes += sim.holes_punched;
            S.verifyRecovery(&sim, out, null) catch |e| {
                std.debug.print("reorder sweep FAILED: seed={d} point={d}/{d} completed={d}\n", .{ seed, point, total, out.completed });
                return e;
            };
        }
    }
    return holes;
}

fn sweepInsideRecovery(comptime S: type) !void {
    const total = try S.countSideEffects();
    var recovery_crashes: usize = 0;
    for ([_]CrashMode{ .lose_unsynced, .torn_tail }) |mode| {
        var point: usize = 0;
        while (point < total) : (point += 1) {
            // Crash the recovery at its 0th, 1st, 2nd … side effect until it
            // gets through without one.
            var second: usize = 0;
            while (true) : (second += 1) {
                var sim = SimStorage.init(gpa);
                defer sim.deinit();
                sim.crash_mode = mode;
                sim.ops_until_crash = point;
                const out = S.runScript(&sim, null);
                sim.reboot();
                sim.crash_mode = mode;
                sim.ops_until_crash = second;
                const recovered = if (Log.open(gpa, sim.storage(), S.opts)) |l| blk: {
                    var log = l;
                    log.close();
                    break :blk true;
                } else |e| switch (e) {
                    error.Crashed => false,
                    else => return e,
                };
                if (!recovered) recovery_crashes += 1;
                S.verifyRecovery(&sim, out, null) catch |e| {
                    std.debug.print("recovery sweep FAILED: mode={t} point={d} second={d} completed={d}\n", .{ mode, point, second, out.completed });
                    return e;
                };
                if (recovered) break;
            }
        }
    }
    // Teeth: recovery really was interrupted, and more than once per first
    // crash on average, or this sweep reached nothing the first one did not.
    try testing.expect(recovery_crashes > 2 * total);
}

test "the workload is sane: no-op steps do no I/O, and a clean run verifies" {
    try workloadIsSane(Always, &script, &no_io_steps, 60);
    // Deferred: the second of two syncs in a row has nothing to do.
    try workloadIsSane(Manual, &script_deferred, &.{4}, 50);
}

test "fault sweep: crash at every side effect, under every crash model" {
    try sweepEveryModel(Always);
}

test "fault sweep, deferred sync: a crash takes at most what no sync covered" {
    try sweepEveryModel(Manual);
    try sweepEveryModel(EveryBytes);
}

test "fault sweep: out-of-order durability can punch no hole in this format" {
    // Under `.always` every write seglog issues is followed by its own fsync
    // before the next one, so no sync window ever holds two writes, and a
    // disk that persists a later write while losing an earlier one has
    // nothing to reorder. This pins that as a property: the reorder model
    // runs, and finds no hole.
    try testing.expectEqual(@as(usize, 0), try sweepReorder(Always));
}

test "fault sweep, deferred sync: holes punched between syncs are cut as a torn tail" {
    // With several appends in one sync window the reorder model does punch
    // holes — a later record kept, an earlier lost. Recovery must still
    // come back to a prefix: the scan stops at the hole and cuts the rest.
    try testing.expect(try sweepReorder(Manual) > 0);
}

test "fault sweep: a crash inside the recovering open is recovered too" {
    try sweepInsideRecovery(Always);
    try sweepInsideRecovery(Manual);
}

test "fault sweep through Concurrent: the group fsync, split around the lock, loses nothing it acknowledged" {
    try workloadIsSane(ConcurrentAlways, &script, &no_io_steps, 60);
    try sweepEveryModel(ConcurrentAlways);
    try sweepEveryModel(ConcurrentManual);
    try testing.expectEqual(@as(usize, 0), try sweepReorder(ConcurrentAlways));
    try sweepInsideRecovery(ConcurrentAlways);
}

test "fault sweep with compaction: the old segment or the new, never a mix, and no temp file left" {
    try workloadIsSane(Compacting, &script_compact, &.{}, 60);
    try sweepEveryModel(Compacting);
    _ = try sweepReorder(Compacting); // the temp file's writes may reorder; it is thrown away
    try sweepInsideRecovery(Compacting);
}

test "fault sweep with compression: the raw segment or the compressed one, never both, never neither" {
    try workloadIsSane(Compressing, &script_compress, &.{}, 60);
    try sweepEveryModel(Compressing);
    _ = try sweepReorder(Compressing);
    try sweepInsideRecovery(Compressing);
}

test "fault sweep, preallocated: zeros past the data are the end of it, never damage and never a cut" {
    try workloadIsSane(PreallocAlways, &script, &no_io_steps, 60);
    try sweepEveryModel(PreallocAlways);
    try sweepEveryModel(PreallocManual);
    // Even under `.always` the reservation and the write into it share a
    // sync window, so reordering does punch holes here — the write kept, the
    // longer file length lost. Recovery still comes back to a prefix.
    try testing.expect(try sweepReorder(PreallocAlways) > 0);
    try testing.expect(try sweepReorder(PreallocManual) > 0);
    try sweepInsideRecovery(PreallocAlways);
    try sweepEveryModel(PreallocConcurrent);
    // Teeth: crashes did leave reserved zeros for `open` to recognise.
    try testing.expect(PreallocAlways.zeros_absorbed > 0);
    try testing.expect(PreallocManual.zeros_absorbed > 0);
}

test "fault sweep is deterministic" {
    for ([_]usize{ 5, 23, 41 }) |point| {
        var contents: [2][]u8 = undefined;
        for (&contents) |*c| {
            var sim = SimStorage.init(gpa);
            defer sim.deinit();
            sim.crash_mode = .torn_tail;
            sim.ops_until_crash = point;
            _ = Always.runScript(&sim, null);
            sim.reboot();
            c.* = try gpa.dupe(u8, sim.fileContent("MANIFEST") orelse "");
        }
        defer for (contents) |c| gpa.free(c);
        try testing.expectEqualSlices(u8, contents[0], contents[1]);
    }
}
