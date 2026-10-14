// SPDX-License-Identifier: MIT

//! Comparative benchmark: `lockfree` against crossbeam (Rust, the reference:
//! crossbeam-queue 0.3.14, crossbeam-deque 0.8.8, crossbeam-epoch 0.9.21), the
//! program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-lockfree` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `cargo` and the
//! three crates (+ crossbeam-utils) in the local registry (`cargo build
//! --offline`; pinned by `tools/rust_bench/Cargo.toml`/`Cargo.lock`). Run from
//! the repository root, on a quiet host: the rows are multi-threaded.
//!
//! Both sides run the SAME workloads (`tools/rust_bench/src/main.rs` mirrors
//! this file). One op is the whole row; producer p sends `(p << 32) | seq`,
//! seq in 1..=n/producers:
//!   bounded_1x1    ring of 1024, 1 producer, 1 consumer, 4 Mi items
//!                  (ours `BoundedQueue(u64, 1024, .{})`, crossbeam `ArrayQueue`)
//!   bounded_4x4    the same, 4 producers, 4 consumers
//!   bounded_4x1    4 producers, 1 consumer: ours `.consumers = .single` (the
//!                  CAS-free pop an MPSC user picks), crossbeam `ArrayQueue`
//!   unbounded_1x1  ours `Queue(u64)` over EBR, crossbeam `SegQueue`
//!   unbounded_4x4  the same, 4 producers, 4 consumers
//!   deque_owner    LIFO deque: push 1 Mi then pop all, one thread
//!   deque_steal    push 1 Mi, then the owner pops while 3 thieves steal one at
//!                  a time until empty
//!   epoch_pin      1 Mi pin + unpin by one registered participant
//! A full push / an empty pop spins (`spinLoopHint`) and retries on both sides.
//! Threads wait at a start flag; the clock runs from the flag to the last
//! join. Each side warms up once, then keeps the best of five; the sides
//! alternate for BENCH_ROUNDS (default 3) rounds, each keeping its best. Every
//! row's result is a checksum (items received, wrapping sum), compared. Ratios
//! are ours/crossbeam by wall time; the verdict is the WORST ratio. Arguments
//! filter rows by name prefix (`bounded` is not `unbounded`).

const std = @import("std");
const lockfree = @import("lockfree");

const bench_name = "bench-lockfree";
const cargo_manifest = "modules/lockfree/tools/rust_bench/Cargo.toml";
const rust_exe = "modules/lockfree/tools/rust_bench/target/release/lockfree_bench";
const ref_short = "crossbeam";
const ref_card = "crossbeam 0.8 (queue 0.3.14, deque 0.8.8, epoch 0.9.21)";

const n_queue: u64 = 4 << 20;
const n_deque: u64 = 1 << 20;
const n_pin: u64 = 1 << 20;
const ring = 1024;

const names = [_][]const u8{
    "bounded_1x1",   "bounded_4x4", "bounded_4x1", "unbounded_1x1",
    "unbounded_4x4", "deque_owner", "deque_steal", "epoch_pin",
};

const Result = struct { count: u64, sum: u64 };
const Row = struct { ns: f64, count: u64, sum: u64 };

fn waitStart(go: *const std.atomic.Value(bool)) void {
    while (!go.load(.acquire)) std.atomic.spinLoopHint();
}

/// Shared state of one producers/consumers run over any queue `Q` with
/// `push(q, v) bool` and `pop(q) ?u64` adapters.
fn Mpmc(comptime Q: type, comptime push: fn (*Q, u64) bool, comptime pop: fn (*Q) ?u64) type {
    return struct {
        // The read-only fields are copied into locals by every thread, and
        // the counters the consumers hammer sit on their own cache lines:
        // otherwise a producer's reload of `q` shares a line with
        // `received` and the harness, not the queue, is what gets measured
        // (as the Rust side's closures capture `q` and `per` by value).
        q: *Q,
        total: u64,
        per: u64,
        go: std.atomic.Value(bool) align(std.atomic.cache_line) = .init(false),
        received: std.atomic.Value(u64) align(std.atomic.cache_line) = .init(0),
        total_sum: std.atomic.Value(u64) align(std.atomic.cache_line) = .init(0),

        const Ctx = @This();

        fn producer(c: *Ctx, p: u64) void {
            const q = c.q;
            const per = c.per;
            waitStart(&c.go);
            var seq: u64 = 1;
            while (seq <= per) : (seq += 1) {
                const v = (p << 32) | seq;
                while (!push(q, v)) std.atomic.spinLoopHint();
            }
        }

        fn consumer(c: *Ctx) void {
            const q = c.q;
            const total = c.total;
            waitStart(&c.go);
            var sum: u64 = 0;
            while (true) {
                if (pop(q)) |v| {
                    sum +%= v;
                    if (c.received.fetchAdd(1, .monotonic) + 1 == total) break;
                } else {
                    if (c.received.load(.monotonic) == total) break;
                    std.atomic.spinLoopHint();
                }
            }
            _ = c.total_sum.fetchAdd(sum, .monotonic);
        }

        fn run(io: std.Io, q: *Q, producers: u64, consumers: u64) !struct { i96, Result } {
            const per = n_queue / producers;
            var c: Ctx = .{ .q = q, .total = per * producers, .per = per };
            var threads: [16]std.Thread = undefined;
            var n: usize = 0;
            for (0..producers) |p| {
                threads[n] = try std.Thread.spawn(.{}, producer, .{ &c, p });
                n += 1;
            }
            for (0..consumers) |_| {
                threads[n] = try std.Thread.spawn(.{}, consumer, .{&c});
                n += 1;
            }
            const t = std.Io.Clock.Timestamp.now(io, .awake);
            c.go.store(true, .release);
            for (threads[0..n]) |th| th.join();
            const ns = t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds;
            return .{ ns, .{ .count = c.received.load(.monotonic), .sum = c.total_sum.load(.monotonic) } };
        }
    };
}

// ---- bounded ----

fn BoundedRow(comptime consumers: lockfree.Consumers) type {
    return struct {
        const Q = lockfree.BoundedQueue(u64, ring, .{ .consumers = consumers });
        fn push(q: *Q, v: u64) bool {
            return q.push(v);
        }
        fn pop(q: *Q) ?u64 {
            return q.pop();
        }
        fn run(gpa: std.mem.Allocator, io: std.Io, producers: u64, cons: u64) !struct { i96, Result } {
            const q = try gpa.create(Q);
            defer gpa.destroy(q);
            q.init();
            return Mpmc(Q, push, pop).run(io, q, producers, cons);
        }
    };
}

// ---- unbounded: Queue(u64) over EBR. Each thread registers on first use. ----

const UQ = struct {
    q: lockfree.Queue(u64),
    domain: *lockfree.Domain,

    threadlocal var me: ?*lockfree.Participant = null;

    fn participant(u: *UQ) *lockfree.Participant {
        if (me) |p| return p;
        me = u.domain.register() catch @panic("register");
        return me.?;
    }
    fn push(u: *UQ, v: u64) bool {
        u.q.enqueue(u.participant(), v) catch @panic("enqueue");
        return true;
    }
    fn pop(u: *UQ) ?u64 {
        return u.q.dequeue(u.participant());
    }
};

fn unboundedRun(gpa: std.mem.Allocator, io: std.Io, producers: u64, consumers: u64) !struct { i96, Result } {
    var domain = try lockfree.Domain.init(gpa, .{ .max_participants = 64 });
    defer domain.deinit();
    var pool = lockfree.Queue(u64).Pool.init(gpa);
    defer pool.deinit();
    var u: UQ = .{ .q = try .init(&pool, &domain), .domain = &domain };
    defer u.q.deinit();
    // Worker threads register on first use and never unregister: they exit
    // unpinned, which `tryAdvance` scans like any idle slot. Each run gets a
    // fresh domain and fresh threads, so at most 8 of the 64 slots are taken.
    return Mpmc(UQ, UQ.push, UQ.pop).run(io, &u, producers, consumers);
}

// ---- deque ----

const DQ = lockfree.Deque(u64);

fn dequeOwner(gpa: std.mem.Allocator, io: std.Io) !struct { i96, Result } {
    var d = try DQ.init(gpa, 32);
    defer d.deinit();
    const t = std.Io.Clock.Timestamp.now(io, .awake);
    var v: u64 = 1;
    while (v <= n_deque) : (v += 1) try d.push(v);
    var r: Result = .{ .count = 0, .sum = 0 };
    while (d.pop()) |x| {
        r.count += 1;
        r.sum +%= x;
    }
    return .{ t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds, r };
}

const StealCtx = struct {
    d: *DQ,
    go: std.atomic.Value(bool) = .init(false),
    total: std.atomic.Value(u64) = .init(0),
    total_sum: std.atomic.Value(u64) = .init(0),

    fn thief(c: *StealCtx) void {
        waitStart(&c.go);
        var count: u64 = 0;
        var sum: u64 = 0;
        while (true) switch (c.d.steal()) {
            .success => |v| {
                count += 1;
                sum +%= v;
            },
            .retry => std.atomic.spinLoopHint(),
            .empty => break,
        };
        _ = c.total.fetchAdd(count, .monotonic);
        _ = c.total_sum.fetchAdd(sum, .monotonic);
    }
};

fn dequeSteal(gpa: std.mem.Allocator, io: std.Io) !struct { i96, Result } {
    var d = try DQ.init(gpa, 32);
    defer d.deinit();
    var v: u64 = 1;
    while (v <= n_deque) : (v += 1) try d.push(v);
    var c: StealCtx = .{ .d = &d };
    var threads: [3]std.Thread = undefined;
    for (&threads) |*th| th.* = try std.Thread.spawn(.{}, StealCtx.thief, .{&c});
    const t = std.Io.Clock.Timestamp.now(io, .awake);
    c.go.store(true, .release);
    var count: u64 = 0;
    var sum: u64 = 0;
    while (d.pop()) |x| {
        count += 1;
        sum +%= x;
    }
    for (threads) |th| th.join();
    const ns = t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds;
    return .{ ns, .{ .count = c.total.load(.monotonic) + count, .sum = c.total_sum.load(.monotonic) +% sum } };
}

// ---- epoch ----

fn epochPin(gpa: std.mem.Allocator, io: std.Io) !struct { i96, Result } {
    var domain = try lockfree.Domain.init(gpa, .{ .max_participants = 8 });
    defer domain.deinit();
    const p = try domain.register();
    defer domain.unregister(p);
    const t = std.Io.Clock.Timestamp.now(io, .awake);
    var i: u64 = 0;
    while (i < n_pin) : (i += 1) {
        const g = domain.enterCritical(p);
        std.mem.doNotOptimizeAway(&g);
        g.release();
    }
    return .{ t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds, .{ .count = n_pin, .sum = 0 } };
}

fn once(gpa: std.mem.Allocator, io: std.Io, w: usize) !struct { i96, Result } {
    return switch (w) {
        0 => BoundedRow(.multi).run(gpa, io, 1, 1),
        1 => BoundedRow(.multi).run(gpa, io, 4, 4),
        2 => BoundedRow(.single).run(gpa, io, 4, 1),
        3 => unboundedRun(gpa, io, 1, 1),
        4 => unboundedRun(gpa, io, 4, 4),
        5 => dequeOwner(gpa, io),
        6 => dequeSteal(gpa, io),
        7 => epochPin(gpa, io),
        else => unreachable,
    };
}

fn timeIt(gpa: std.mem.Allocator, io: std.Io, w: usize) !Row {
    _, const warm = try once(gpa, io, w);
    var best: i96 = std.math.maxInt(i96);
    for (0..5) |_| {
        const ns, const r = try once(gpa, io, w);
        if (r.count != warm.count or r.sum != warm.sum) return error.UnstableChecksum;
        best = @min(best, ns);
    }
    return .{ .ns = @floatFromInt(best), .count = warm.count, .sum = warm.sum };
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const gpa = std.heap.smp_allocator;
    const args = try init.minimal.args.toSlice(arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    try rustBuild(arena, io);

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<14} {s:>13} {s:>13} {s:>8} {s:>7} {s:>7}  count / sum\n", .{ "row", "ours ns", ref_short ++ " ns", "ratio", "spr us", "spr ref" });
    try w.flush();

    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    var mismatch = false;
    for (names, 0..) |name, wi| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.startsWith(u8, name, f);
            if (!hit) continue;
        }
        var ours: Side = .{};
        var ref: Side = .{};
        for (0..rounds) |_| {
            ref.add(try rustRun(arena, io, name));
            ours.add(try timeIt(gpa, io, wi));
        }
        const ratio = ours.best_ns / ref.best_ns;
        worst = @max(worst, ratio);
        best = @min(best, ratio);
        max_spread = @max(max_spread, @max(ours.spread(), ref.spread()));
        const same = ours.count == ref.count and ours.sum == ref.sum;
        mismatch = mismatch or !same;
        try w.print("{s:<14} {d:>13.0} {d:>13.0} {d:>8.3} {d:>6.1}% {d:>6.1}%  {d} / {d}{s}\n", .{
            name,       ours.best_ns,        ref.best_ns,
            ratio,      100 * ours.spread(), 100 * ref.spread(),
            ours.count, ours.sum,            if (same) "" else " != " ++ ref_short,
        });
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time; largest spread {d:.1}%{s}\n", .{ rounds, 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a result differs from the reference's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, worst, best });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured <today>)\n", .{ best, worst, ref_card });
    try w.flush();
    return 0;
}

// ---- comparison driver (as in every reference-benchmarked module) ----

const Side = struct {
    best_ns: f64 = std.math.inf(f64),
    worst_ns: f64 = 0,
    count: u64 = 0,
    sum: u64 = 0,
    fn add(s: *Side, r: Row) void {
        s.best_ns = @min(s.best_ns, r.ns);
        s.worst_ns = @max(s.worst_ns, r.ns);
        s.count = r.count;
        s.sum = r.sum;
    }
    fn spread(s: Side) f64 {
        return s.worst_ns / s.best_ns - 1;
    }
};

/// Build the Rust side once (`cargo build --release --offline`), so the timed
/// runs do not pay for it.
fn rustBuild(arena: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    const res = std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--offline", "--quiet", "--manifest-path", cargo_manifest },
    }) catch |e| {
        std.debug.print("{s}: could not run cargo ({t}) -- the benchmark needs it\n", .{ bench_name, e });
        return error.CargoBuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: cargo build failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.CargoBuildFailed;
    }
}

/// Run the Rust side for one row: `<exe> <name>` prints
/// `name \t ns/op \t count \t sum`.
fn rustRun(arena: std.mem.Allocator, io: std.Io, name: []const u8) !Row {
    const res = try std.process.run(arena, io, .{ .argv = &.{ rust_exe, name } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: Rust side failed on {s}:\n{s}\n", .{ bench_name, name, res.stderr });
        return error.ForeignFailed;
    }
    var f = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, res.stdout, "\n"), '\t');
    if (!std.mem.eql(u8, f.next() orelse return error.BadForeignOutput, name)) return error.BadForeignOutput;
    const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
    const sum = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
    return .{ .ns = ns, .count = count, .sum = sum };
}
