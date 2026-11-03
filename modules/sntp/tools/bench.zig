// SPDX-License-Identifier: MIT

//! Comparative benchmark: `sntp`'s exchange arithmetic (request encode, reply
//! decode and validation, origin check, offset / delay / MinError /
//! RootDistance, the RFC 5905 suitability checks) against beevik/ntp v1.6.0
//! (the reference, `tools/go_bench`), the program behind the
//! `**Performance:**` line of the maturity card (CONVENTIONS.md §9 kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-sntp` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26 and
//! beevik/ntp v1.6.0 in the module cache (`GOPROXY=off`). Run from the
//! repository root. No socket, no real clock: a query's time is the network's,
//! so only the CPU part is compared.
//!
//! One op = 64 complete exchanges over a fixed-seed corpus written into
//! `.zig-cache/bench-sntp/` (the Go side reads the same files). Each exchange:
//!   - build the 48-byte request with a fresh 8-byte random origin cookie
//!     (ours: `getrandom` + `Packet.encode`; Go: `crypto/rand` + its encoder),
//!   - take the canned reply, patched with the request's cookie as originate,
//!   - decode + validate it (ours `decodeResponse` + `verifyOriginate`; Go the
//!     response parser and origin check inside `QueryWithOptions`),
//!   - offset, round trip (clamped at 0), MinError, RootDistance,
//!   - the suitability checks (ours `checkSynchronization`; Go `Validate`).
//! The corpus holds 64 replies: valid ones, a leap-alarm (LI=3) one every 16th
//! and a Kiss-o'-Death RATE one every 16th; a refused exchange adds 1e12.
//! Timestamps are multiples of 2^-9 s and root values multiples of 2^-9 s so
//! that Go's round-half-up and ours' floor fraction conversion agree exactly:
//! the summed counts must be equal or the run fails.
//!
//! What Go does that ours does not: `QueryWithOptions` also dials, wraps the
//! connection and allocates the response (GC); what ours does that Go does
//! not: nothing extra. Go's two clock reads are fixed values here.
//! Ratios are ours/Go by wall time; the verdict is the WORST ratio.

const std = @import("std");
const bench = @import("testkit").bench;
const sntp = @import("sntp");

const ref_short = "Go";
const ref_card = "Go beevik/ntp v1.6.0, Go 1.26.8";
const bench_name = "bench-sntp";
const work_dir = ".zig-cache/bench-sntp";
const go_dir = "modules/sntp/tools/go_bench";
const N = 64;
const unit_frac: u32 = 1 << 23; // 2^-9 s
const t1_unix_s: u64 = 1_793_000_000;

const Op = enum { exchange };

const Ctx = struct {
    op: Op = .exchange,
    replies: [N][48]u8 = undefined,
    t1: sntp.Timestamp = .zero,
    t4: sntp.Timestamp = .zero,
};

fn unitsToTs(units: u64) sntp.Timestamp {
    return .{ .seconds = @intCast(units / 512), .fraction = @intCast((units % 512) * unit_frac) };
}

fn low(x: i128) u64 {
    return @truncate(@as(u128, @bitCast(x)));
}

fn once(c: *Ctx) u64 {
    var t: u64 = 0;
    for (&c.replies) |*rep| {
        var cookie: [8]u8 = undefined;
        _ = std.os.linux.getrandom(&cookie, 8, 0);
        const req = (sntp.Packet{ .version = 4, .mode = .client, .transmit = sntp.Timestamp.fromBytes(&cookie) }).encode();
        var wire = rep.*;
        @memcpy(wire[24..32], req[40..48]);
        const reply = sntp.decodeResponse(&wire, null) catch {
            t +%= 1_000_000_000_000;
            continue;
        };
        sntp.verifyOriginate(reply, sntp.Timestamp.fromBytes(req[40..48])) catch {
            t +%= 1_000_000_000_000;
            continue;
        };
        sntp.checkSynchronization(reply) catch {
            t +%= 1_000_000_000_000;
            continue;
        };
        const s: sntp.Sample = .{ .originate = c.t1, .receive = reply.receive, .transmit = reply.transmit, .destination = c.t4 };
        const off = s.offsetNanos();
        const rtt: i128 = @max(s.roundtripDelayNanos(), 0);
        const root: i128 = @divTrunc(rtt + reply.rootDelayNanos(), 2) + reply.rootDispersionNanos();
        t +%= low(off) +% low(rtt) +% low(s.minErrorNanos()) +% low(root);
    }
    return t;
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, c: *Ctx) !void {
    var prng = std.Random.DefaultPrng.init(0x5E7B_0001);
    const r = prng.random();
    const t1_units: u64 = (t1_unix_s + sntp.ntp_unix_offset_s) * 512;
    c.t1 = unitsToTs(t1_units);
    c.t4 = unitsToTs(t1_units + 16);
    var out: std.ArrayList(u8) = .empty;
    for (&c.replies, 0..) |*rep, i| {
        const off: i64 = r.intRangeAtMost(i64, -2000, 2000);
        const t2: u64 = @intCast(@as(i64, @intCast(t1_units)) + 4 + off);
        const t3 = t2 + r.intRangeAtMost(u64, 1, 8);
        const p: sntp.Packet = .{
            .leap = if (i % 16 == 7) .unsynchronized else .no_warning,
            .mode = .server,
            .stratum = if (i % 16 == 11) 0 else r.intRangeAtMost(u8, 1, 4),
            .poll = 6,
            .precision = -20,
            .root_delay = 128 * r.intRangeAtMost(u32, 0, 2000),
            .root_dispersion = 128 * r.intRangeAtMost(u32, 0, 2000),
            .reference_id = if (i % 16 == 11) "RATE".* else .{ 'G', 'P', 'S', 0 },
            .reference = unitsToTs(t3 - r.intRangeAtMost(u64, 1, 100_000)),
            .receive = unitsToTs(t2),
            .transmit = unitsToTs(t3),
        };
        rep.* = p.encode();
        try out.appendSlice(arena, &.{ 0, 48 });
        try out.appendSlice(arena, rep);
    }
    try dir.writeFile(io, .{ .sub_path = "replies.bin", .data = out.items });
    const unix_ns = struct {
        fn of(ts: sntp.Timestamp) u64 {
            return @intCast(ts.toUnixNanos());
        }
    }.of;
    var clk: [16]u8 = undefined;
    std.mem.writeInt(u64, clk[0..8], unix_ns(c.t1), .big);
    std.mem.writeInt(u64, clk[8..16], unix_ns(c.t4), .big);
    try dir.writeFile(io, .{ .sub_path = "clock.bin", .data = &clk });
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 5;

    var ctx: Ctx = .{};
    try setup(arena, io, dir, &ctx);

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    const W = bench.Work(Op);
    const ws = [_]W{
        .{ .name = "exchange", .op = .exchange, .ref = "exchange", .wall_only = true },
    };
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = bench.drive(io, arena, .{
        .name = bench_name,
        .exes = &.{exe},
        .abs = abs,
        .filters = if (args.len > 1) args[1..] else &.{},
        .rounds = rounds,
    }, &ctx, once, ws, w) catch |e| switch (e) {
        error.CountMismatch => return 1,
        else => return e,
    };
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, s.worst_ref, s.best_ref });
    if (args.len <= 1) try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref, ref_card });
    try w.flush();
    return 0;
}
