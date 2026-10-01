// SPDX-License-Identifier: MIT

//! M3 behaviour tests: host crash and restart, directed and partition
//! faults, scheduled one-shot faults, and the search layer (run, findFailing,
//! shrink, replay, checkDeterminism) finding a real bug in real `std.Io` code.

const std = @import("std");
const netsim = @import("netsim");
const sched = @import("sched.zig");
const search = @import("search.zig");

const Io = std.Io;
const net = Io.net;
const Sim = sched.Sim;
const Host = sched.Host;
const testing = std.testing;

const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

fn newSim(sim: *Sim, seed: u64) void {
    sim.init(testing.allocator, .{ .seed = seed, .stack_size = 512 * 1024 });
}

fn addr4(h: *const Host, port: u16) net.IpAddress {
    return .{ .ip4 = .{ .bytes = h.ip4, .port = port } };
}

// ── crash and restart ──────────────────────────────────────────────────────

const BootLog = struct { boots: u32 = 0, awake_at_boot: [4]i96 = @splat(0), woke_after_sleep: u32 = 0 };

fn bootTask(io: Io, gpa: std.mem.Allocator, log: *BootLog) !void {
    log.awake_at_boot[log.boots] = Io.Timestamp.now(io, .awake).nanoseconds;
    log.boots += 1;
    // Memory a crash must release: never freed by this task.
    _ = try gpa.alloc(u8, 4096);
    try io.sleep(.fromSeconds(10), .awake);
    log.woke_after_sleep += 1;
}

test "a crash stops tasks without unwinding, frees host memory; restart reboots them" {
    var sim: Sim = undefined;
    newSim(&sim, 1);
    defer sim.deinit();
    const h = try sim.addHost(.{});
    var log: BootLog = .{};
    try h.spawnBoot(bootTask, .{ h.io(), h.allocator(), &log });

    _ = sim.runFor(5 * ns_per_s);
    try testing.expectEqual(@as(u32, 1), log.boots);
    sim.crash(h);
    try testing.expect(!h.up);
    _ = sim.runFor(1 * ns_per_s);
    sim.restart(h);
    const r = sim.run();
    try testing.expectEqual(sched.Outcome.quiescent, r.outcome);
    try testing.expectEqual(@as(u32, 2), log.boots);
    // The first boot's 10 s timer (due at t = 10 s) died with its task; only
    // the second boot's sleep completed, at t = 16 s.
    try testing.expectEqual(@as(u32, 1), log.woke_after_sleep);
    try testing.expectEqual(@as(u64, 16 * ns_per_s), r.now_ns);
    // Monotonic time restarts with the host.
    try testing.expectEqual(log.awake_at_boot[0], log.awake_at_boot[1]);
    // The 4 KB of the second boot are still live; deinit releases them, and
    // the first boot's were released by the crash (testing.allocator would
    // report either as a leak).
}

fn crashServer(io: Io, port: u16) !void {
    var server = try net.IpAddress.listen(&.{ .ip4 = .unspecified(port) }, io, .{});
    defer server.deinit(io);
    while (true) {
        const s = try server.accept(io);
        _ = s; // held open until the crash
    }
}

const Ticker = struct { err: ?anyerror = null, at_ns: u64 = 0 };

fn ticker(io: Io, sim: *Sim, to: net.IpAddress, out: *Ticker) !void {
    const stream = try to.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var wbuf: [8]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    while (true) {
        w.interface.writeAll("t") catch {
            out.err = w.err.?;
            out.at_ns = sim.now;
            return;
        };
        w.interface.flush() catch {
            out.err = w.err.?;
            out.at_ns = sim.now;
            return;
        };
        try io.sleep(.fromSeconds(1), .awake);
    }
}

test "after a peer crashes and restarts, the old connection is reset" {
    var sim: Sim = undefined;
    newSim(&sim, 2);
    defer sim.deinit();
    const a = try sim.addHost(.{});
    const b = try sim.addHost(.{});
    try sim.link(a, b, .{ .latency_ns = 5 * ns_per_ms });
    var t: Ticker = .{};
    try b.spawnBoot(crashServer, .{ b.io(), 80 });
    try a.spawn(ticker, .{ a.io(), &sim, addr4(b, 80), &t });
    _ = sim.runFor(3 * ns_per_s);
    sim.crash(b);
    _ = sim.runFor(10 * ns_per_s); // writes pile up against a dead host
    try testing.expectEqual(@as(?anyerror, null), t.err);
    sim.restart(b);
    _ = sim.runFor(30 * ns_per_s);
    try testing.expectEqual(@as(?anyerror, error.ConnectionResetByPeer), t.err);
    try testing.expect(t.at_ns > 13 * ns_per_s);
}

// ── directed links and partitions ──────────────────────────────────────────

const Tally = struct { got: u32 = 0 };

fn sink(io: Io, port: u16, tally: *Tally) !void {
    const sock = try net.IpAddress.bind(&.{ .ip4 = .unspecified(port) }, io, .{ .mode = .dgram });
    defer sock.close(io);
    var buf: [16]u8 = undefined;
    while (true) {
        _ = sock.receiveTimeout(io, &buf, .{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } }) catch |err| switch (err) {
            error.Timeout => return,
            else => return err,
        };
        tally.got += 1;
    }
}

fn burst(io: Io, to: net.IpAddress, n: usize) !void {
    const sock = try net.IpAddress.bind(&.{ .ip4 = .unspecified(0) }, io, .{ .mode = .dgram });
    defer sock.close(io);
    for (0..n) |_| try sock.send(io, &to, "d");
}

test "a one-way failure drops traffic in one direction only" {
    var sim: Sim = undefined;
    newSim(&sim, 3);
    defer sim.deinit();
    const a = try sim.addHost(.{});
    const b = try sim.addHost(.{});
    try sim.link(a, b, .{});
    try sim.setLinkDirUp(a, b, false);
    var at_a: Tally = .{};
    var at_b: Tally = .{};
    try a.spawn(sink, .{ a.io(), 7, &at_a });
    try b.spawn(sink, .{ b.io(), 7, &at_b });
    try a.spawn(burst, .{ a.io(), addr4(b, 7), 5 });
    try b.spawn(burst, .{ b.io(), addr4(a, 7), 5 });
    _ = sim.run();
    try testing.expectEqual(@as(u32, 0), at_b.got);
    try testing.expectEqual(@as(u32, 5), at_a.got);
}

test "a partition separates its cut from the rest until healed" {
    var sim: Sim = undefined;
    newSim(&sim, 4);
    defer sim.deinit();
    const a = try sim.addHost(.{});
    const b = try sim.addHost(.{});
    const c = try sim.addHost(.{});
    try sim.linkAll(.{});
    const id = try sim.partition(&.{a});
    var at_a: Tally = .{};
    var at_c: Tally = .{};
    try a.spawn(sink, .{ a.io(), 7, &at_a });
    try c.spawn(sink, .{ c.io(), 7, &at_c });
    try b.spawn(burst, .{ b.io(), addr4(a, 7), 3 });
    try b.spawn(burst, .{ b.io(), addr4(c, 7), 3 });
    _ = sim.runFor(500 * ns_per_ms);
    try testing.expectEqual(@as(u32, 0), at_a.got);
    try testing.expectEqual(@as(u32, 3), at_c.got);
    sim.heal(id);
    try b.spawn(burst, .{ b.io(), addr4(a, 7), 3 });
    _ = sim.run();
    try testing.expectEqual(@as(u32, 3), at_a.got);
}

test "a scheduled one-shot drop loses exactly the next packet on that hop" {
    var sim: Sim = undefined;
    newSim(&sim, 5);
    defer sim.deinit();
    const a = try sim.addHost(.{});
    const b = try sim.addHost(.{});
    try sim.link(a, b, .{});
    try sim.scheduleFault(0, .{ .drop_once = .{ .from = a.id, .to = b.id } });
    var at_b: Tally = .{};
    try b.spawn(sink, .{ b.io(), 7, &at_b });
    try a.spawn(burst, .{ a.io(), addr4(b, 7), 4 });
    _ = sim.run();
    try testing.expectEqual(@as(u32, 3), at_b.got);
}

// ── the search layer on a real bug ─────────────────────────────────────────

/// "Durable" server state: test-owned, so it survives a server crash the way
/// a disk would (M4 replaces this with the simulated file system).
const Ledger = struct {
    increments: u32 = 0,
    seen: [8]bool = @splat(false),
    acked: bool = false,
    dedup: bool,
};

fn ledgerServer(io: Io, ledger: *Ledger) !void {
    const sock = try net.IpAddress.bind(&.{ .ip4 = .unspecified(9000) }, io, .{ .mode = .dgram });
    defer sock.close(io);
    var buf: [16]u8 = undefined;
    while (true) {
        const msg = try sock.receive(io, &buf);
        if (msg.data.len != 1) continue;
        const id = msg.data[0] % 8;
        if (!ledger.dedup or !ledger.seen[id]) ledger.increments += 1;
        ledger.seen[id] = true;
        try sock.send(io, &msg.from, msg.data);
    }
}

/// Exactly-once increment over UDP: retry until acknowledged.
fn ledgerClient(io: Io, server: net.IpAddress, ledger: *Ledger) !void {
    const sock = try net.IpAddress.bind(&.{ .ip4 = .unspecified(0) }, io, .{ .mode = .dgram });
    defer sock.close(io);
    var buf: [16]u8 = undefined;
    for (0..200) |_| {
        try sock.send(io, &server, &.{3});
        _ = sock.receiveTimeout(io, &buf, .{ .duration = .{ .raw = .fromMilliseconds(300), .clock = .awake } }) catch |err| switch (err) {
            error.Timeout => continue,
            else => return err,
        };
        ledger.acked = true;
        return;
    }
}

fn ledgerSetup(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    const ledger: *Ledger = @ptrCast(@alignCast(ctx.?));
    const client = try sim.addHost(.{});
    const server = try sim.addHost(.{});
    try sim.link(client, server, .{ .latency_ns = 20 * ns_per_ms });
    try server.spawnBoot(ledgerServer, .{ server.io(), ledger });
    try client.spawn(ledgerClient, .{ client.io(), addr4(server, 9000), ledger });
}

fn ledgerInvariant(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    _ = sim;
    const ledger: *const Ledger = @ptrCast(@alignCast(ctx.?));
    if (ledger.increments > 1) return error.CountedTwice;
}

fn ledgerReset(ctx: ?*anyopaque) void {
    const ledger: *Ledger = @ptrCast(@alignCast(ctx.?));
    ledger.* = .{ .dedup = ledger.dedup };
}

fn ledgerCase(ledger: *Ledger) search.Case {
    return .{
        .options = .{ .seed = 0, .stack_size = 256 * 1024 },
        .setup = ledgerSetup,
        .invariant = ledgerInvariant,
        .reset = ledgerReset,
        .ctx = ledger,
        .duration_ns = 20 * ns_per_s,
    };
}

const ledger_faults: search.FaultConfig = .{ .schedule = .{ .max_events = 6, .horizon = 3000 } };

test "search finds the double increment, shrinks it, and the replay reproduces it" {
    var ledger: Ledger = .{ .dedup = false };
    var failing = (try search.findFailing(testing.allocator, ledgerCase(&ledger), ledger_faults, 0, 300)) orelse
        return error.BugNotFound;
    defer failing.deinit();
    try testing.expectEqual(@as(anyerror, error.CountedTwice), failing.violation.err);

    var small = try search.shrink(testing.allocator, &failing);
    defer small.deinit();
    try testing.expect(small.after <= small.before);
    // A lost or duplicated packet (or a cut while one is in flight) is all it
    // takes; ddmin must get there.
    try testing.expect(small.after >= 1 and small.after <= 2);

    const again = try search.replay(testing.allocator, failing.case, small.trace.events, failing.tick_ns);
    try testing.expectEqual(@as(anyerror, error.CountedTwice), again.violation.?.err);
    // Without any fault the protocol is fine: the faults are the cause.
    const clean = try search.replay(testing.allocator, failing.case, &.{}, failing.tick_ns);
    try testing.expectEqual(@as(?search.Violation, null), clean.violation);
}

test "the deduplicating server survives the same search" {
    var ledger: Ledger = .{ .dedup = true };
    const failing = try search.findFailing(testing.allocator, ledgerCase(&ledger), ledger_faults, 0, 150);
    try testing.expect(failing == null);
}

test "a seed's run is reproducible: checkDeterminism passes on real code" {
    var ledger: Ledger = .{ .dedup = true };
    var case = ledgerCase(&ledger);
    for (0..10) |seed| {
        case.seed = seed;
        try search.checkDeterminism(testing.allocator, case, ledger_faults);
    }
}

var outside_state: u64 = 0;

fn leakySetup(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    _ = ctx;
    const h = try sim.addHost(.{});
    // State that outlives the run, as a global or a wall-clock read would.
    outside_state += 1;
    try h.spawn(leakySleep, .{ h.io(), outside_state });
}

fn leakySleep(io: Io, ms: u64) !void {
    try io.sleep(.fromMilliseconds(@intCast(ms)), .awake);
}

test "checkDeterminism catches code that depends on state outside the simulation" {
    const case: search.Case = .{ .options = .{ .seed = 0, .stack_size = 256 * 1024 }, .setup = leakySetup };
    try testing.expectError(error.Nondeterministic, search.checkDeterminism(testing.allocator, case, .{}));
}
