// SPDX-License-Identifier: MIT

//! Comparative benchmark: `nftables`'s native rule encoder and typed rule
//! decoder against github.com/google/nftables v0.3.0 (Apache-2.0,
//! `tools/go_bench`), the program behind the `**Performance:**` line of the
//! maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-nftables` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26 and
//! google/nftables v0.3.0 with its dependencies in the module cache
//! (`GOPROXY=off`; `go mod tidy` in `tools/go_bench` once, with the network
//! on, fills it). Run from the repository root. CPU-bound only: no socket and
//! no kernel is involved — Go side through the library's own test seam
//! (`WithTestDial`), so its `Flush` and `GetRules` run their real batching,
//! message building, reply handling and typed expression parsing against an
//! in-memory peer. A live ruleset change is kernel work and is not benchmarked.
//!
//! One op = 64 rules of a fixed seed, five shapes in rotation (the shapes a
//! firewall is made of), parameters written to `.zig-cache/bench-nftables/`
//! (the Go side reads the same files and builds the same rules):
//!   0 `tcp dport P counter accept`            (6 expressions)
//!   1 `ip saddr A/N drop`, N not a multiple of 8 (nfproto dependency, load,
//!     bitwise mask, compare, verdict)
//!   2 `ip saddr @blocked drop`                (set lookup)
//!   3 `iifname "lo" accept`                   (16-byte padded compare)
//!   4 `ct state … accept`                     (ct load, bitwise, compare)
//!   enc_rule  build the 64 rules and encode them as ONE batch. Ours
//!             `Program` helpers + `Batch.addRule` + `finish` into an arena
//!             reset per op; Go `AddRule` x64 + `Flush` (which batches and
//!             hands the netlink messages to the test dialer, no ACK read).
//!             Count: messages in the batch (BATCH_BEGIN + 64 + BATCH_END).
//!   dec_rule  the same 64 rules as a dump reply (built by our encoder, with
//!             a kernel-style rule handle and random counter values), decoded
//!             into typed expressions. Ours `wire.decodeRule` + `ExprIterator`
//!             + `decodeExpr` (pointer-free values borrowing the reply); Go
//!             `Conn.GetRules` (request build, `nltest` reply, per-rule
//!             `[]expr.Any` with a heap value per expression).
//! Both sides add up, per rule, the handle and per expression a fixed set of
//! its fields (kind, key, base/offset/len, operator, data length and first
//! byte, mask first byte, counter values, verdict code, set-name length);
//! the counts must agree or the run fails. Ratios are ours/Go by wall time;
//! the verdict is the WORST ratio. Arguments filter workloads.
//!
//! What ours does that Go does not (so the rows are fair, not equal): the
//! register model (a `cmp` on an unwritten register is an error), width
//! checks on every compare; what Go does that ours does not: allocate each
//! expression and its byte slices (GC), keep an `AddRule` queue under a lock.

const std = @import("std");
const bench = @import("testkit").bench;
const nft = @import("nftables");
const wire = nft.wire;
const expr = nft.expr;

const ref_short = "Go";
const ref_card = "Go google/nftables v0.3.0";
const bench_name = "bench-nftables";
const work_dir = ".zig-cache/bench-nftables";
const go_dir = "modules/nftables/tools/go_bench";
const N = 64;

const Op = enum { enc_rule, dec_rule };

const Params = struct {
    shape: u8,
    plen: u8,
    port: u16,
    addr: [4]u8,
    /// `ct state` mask in register (host) byte order.
    mask: u32,
};

const Ctx = struct {
    op: Op = .enc_rule,
    arena: std.heap.ArenaAllocator,
    params: [N]Params = undefined,
    /// NEWRULE message payloads (`nfgenmsg` + attributes).
    payloads: [N][]const u8 = undefined,
};

// ── the timed ops ────────────────────────────────────────────────────────────

fn program(gpa: std.mem.Allocator, r: Params, counter: bool, seed: u64) expr.Program {
    var p = expr.Program.init(gpa, .inet);
    switch (r.shape) {
        0 => {
            _ = p.tcpDport(r.port);
            if (counter) {
                _ = p.push(.{ .counter = .{ .packets = seed, .bytes = seed *% 1500 } });
            } else _ = p.counter();
            _ = p.accept();
        },
        1 => _ = p.ipSaddrPrefix(r.addr, @intCast(r.plen)).drop(),
        2 => _ = p.ipSaddrSet("blocked", null, false).drop(),
        3 => _ = p.ifnameCmp(.iifname, .eq, "lo").accept(),
        else => _ = p.ctStateAny(r.mask).accept(),
    }
    return p;
}

fn tally(v: expr.ExprView) u64 {
    const e = expr.decodeExpr(v) catch @panic("bench-nftables: decode");
    var t: u64 = 1;
    switch (e) {
        .meta_load => |m| t +%= m.key.key().?,
        .cmp => |c| {
            const d = c.data.value;
            t +%= c.op;
            t +%= d.len;
            t +%= d[0];
        },
        .payload_load => |p| {
            t +%= p.base.base();
            t +%= p.offset;
            t +%= p.len;
        },
        .bitwise => |b| {
            t +%= b.len;
            t +%= b.mask[0];
        },
        .ct_load => |c| t +%= c.key,
        .counter => |c| t +%= c.packets +% c.bytes,
        .immediate => |i| t +%= @as(u32, @bitCast(i.data.verdict.code)),
        .lookup => |l| t +%= l.set.len,
        else => @panic("bench-nftables: unexpected expression"),
    }
    return t;
}

fn once(c: *Ctx) u64 {
    switch (c.op) {
        .enc_rule => {
            _ = c.arena.reset(.retain_capacity);
            const a = c.arena.allocator();
            var b = wire.Batch.init(a, 1, .{}) catch @panic("bench-nftables: batch");
            for (c.params) |r| {
                var p = program(a, r, false, 0);
                b.addRule(.{
                    .family = .inet,
                    .table = "filter",
                    .chain = "input",
                    .exprs = p.finish() catch @panic("bench-nftables: program"),
                }) catch @panic("bench-nftables: addRule");
            }
            _ = b.finish() catch @panic("bench-nftables: finish");
            return b.commandCount() + 2;
        },
        .dec_rule => {
            var t: u64 = 0;
            for (c.payloads) |p| {
                const rule = wire.decodeRule(p) catch @panic("bench-nftables: decodeRule");
                t +%= rule.handle;
                var it = rule.exprIterator();
                while (it.next() catch @panic("bench-nftables: walk")) |v| t +%= tally(v);
            }
            return t;
        },
    }
}

// ── the corpus ───────────────────────────────────────────────────────────────

fn writeFrames(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, file: []const u8, frames: []const []const u8) !void {
    var out: std.ArrayList(u8) = .empty;
    var total: usize = 0;
    for (frames) |m| {
        try out.appendSlice(arena, &.{ @truncate(m.len >> 8), @truncate(m.len) });
        try out.appendSlice(arena, m);
        total += m.len;
    }
    try dir.writeFile(io, .{ .sub_path = file, .data = out.items });
    std.debug.print("{s}: {s}: {d} frames, {d} bytes ({d} avg)\n", .{ bench_name, file, frames.len, total, total / frames.len });
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, c: *Ctx) !void {
    var prng = std.Random.DefaultPrng.init(0x0f7a_b1e5);
    const r = prng.random();
    var recs: [N][]const u8 = undefined;
    for (&c.params, &recs, 0..) |*p, *rec, i| {
        var plen = r.intRangeAtMost(u8, 9, 31);
        while (plen % 8 == 0) plen = r.intRangeAtMost(u8, 9, 31);
        var addr: [4]u8 = undefined;
        r.bytes(&addr);
        p.* = .{
            .shape = @intCast(i % 5),
            .plen = plen,
            .port = r.intRangeAtMost(u16, 1, 65535),
            .addr = addr,
            .mask = r.intRangeAtMost(u32, 1, 15) << 1 | 2,
        };
        var b: [12]u8 = undefined;
        b[0] = p.shape;
        b[1] = p.plen;
        std.mem.writeInt(u16, b[2..4], p.port, .big);
        b[4..8].* = p.addr;
        std.mem.writeInt(u32, b[8..12], p.mask, @import("builtin").cpu.arch.endian());
        rec.* = try arena.dupe(u8, &b);
    }
    try writeFrames(arena, io, dir, "enc_rule.bin", &recs);
    // The dump reply: each rule alone in a batch, its message payload cut out
    // after the 16-byte header (BATCH_BEGIN is 20 bytes).
    for (&c.payloads, c.params, 0..) |*pl, p, i| {
        var prog = program(arena, p, true, r.int(u32));
        var b = try wire.Batch.init(arena, 1, .{ .ack = false });
        try b.addRule(.{
            .family = .inet,
            .table = "filter",
            .chain = "input",
            .exprs = try prog.finish(),
            .handle = 100 + i,
        });
        const bytes = try b.finish();
        const len = std.mem.readInt(u32, bytes[20..24], @import("builtin").cpu.arch.endian());
        pl.* = bytes[36..][0 .. len - 16];
    }
    try writeFrames(arena, io, dir, "dec_rule.bin", &c.payloads);
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

    var ctx: Ctx = .{ .arena = std.heap.ArenaAllocator.init(std.heap.page_allocator) };
    try setup(arena, io, dir, &ctx);

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    const W = bench.Work(Op);
    const ws = [_]W{
        .{ .name = "enc_rule", .op = .enc_rule, .ref = "enc_rule", .wall_only = true },
        .{ .name = "dec_rule", .op = .dec_rule, .ref = "dec_rule", .wall_only = true },
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
