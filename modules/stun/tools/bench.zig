// SPDX-License-Identifier: MIT

//! Comparative benchmark: `stun`'s message path against Go's
//! `github.com/pion/stun/v3` v3.1.6 (the reference, `tools/go_bench`) and
//! `gortc.io/stun` v1.23.0 (pion's BSD-3 ancestor, the "fastest" candidate,
//! `tools/go_bench_gortc`, same program, other import), the program behind the
//! `**Performance:**` line of the maturity card (CONVENTIONS.md §9, kept
//! instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-stun` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26 and, in
//! the module cache (`GOPROXY=off`), pion/stun v3.1.6 with its dependencies
//! (`go.sum` in `tools/go_bench`) and gortc.io/stun v1.23.0. Run from the
//! repository root. CPU-bound codec loops only: no socket is involved.
//!
//! One op = 64 inputs of a fixed seed, written by this driver into
//! `.zig-cache/bench-stun/` (the Go sides read the same files):
//!   enc_req      a Binding request with SOFTWARE, USERNAME, a short-term
//!                MESSAGE-INTEGRITY (HMAC-SHA1) and FINGERPRINT, a fresh
//!                transaction id per input (what an ICE connectivity check
//!                sends). Ours `Builder` into a reused stack buffer, no
//!                allocation; Go `Message.Build(...)` on ONE reused `Message`
//!                (its best case: `Build` resets and reuses the buffer), the
//!                setters boxed into a variadic slice. Count = sum of all
//!                output bytes, so the wire bytes must be identical.
//!   dec_resp     a Binding success response: SOFTWARE, XOR-MAPPED-ADDRESS (IPv4
//!                and IPv6 alternately), MESSAGE-INTEGRITY, FINGERPRINT. Ours
//!                `decode` + `mappedAddress` + `verifyFingerprint` +
//!                `verifyMessageIntegrity`; Go `Decode` into a reused
//!                `Message` (copy of the datagram first: `Decode` reads
//!                `m.Raw`), `XORMappedAddress.GetFrom`, `Fingerprint.Check`,
//!                `MessageIntegrity.Check`. Count = port + address octets +
//!                one per passing check.
//!   dec_garbage  64 datagrams a hostile peer can send: shorter than the
//!                header, a wrong cookie, a declared length past the buffer, an
//!                attribute whose declared length overruns the message. Every
//!                one must be rejected; the count is the number rejected. Go's
//!                `Decode` walks every attribute; ours `decode` checks the
//!                header only, so the driver also walks the attributes and
//!                counts a walk that ends before the message does as a
//!                rejection (the same strictness).
//! Ratios are ours/Go by wall time; the verdict is the WORST ratio.
//! Arguments filter workloads.
//!
//! What the Go side does that ours does not (so the rows are fair, not equal):
//! its `Message` keeps a decoded `[]RawAttribute` (grown, then reused), a
//! `net.IP` is allocated for the address, and the `Setter` values are heap
//! boxed. What ours does that Go does not: nothing extra; MESSAGE-INTEGRITY-
//! SHA256 (RFC 8489) has no row because neither Go library builds or checks
//! it.

const std = @import("std");
const bench = @import("testkit").bench;
const stun = @import("stun");
const netaddr = @import("netaddr");

const ref_short = "Go";
const ref_card = "Go pion/stun v3.1.6";
const bench_name = "bench-stun";
const work_dir = ".zig-cache/bench-stun";
const N = 64;
const password = "VOkJxbRl1RmTxUk/WvJxBt";

const Op = enum { enc_req, dec_resp, dec_garbage };

const Ctx = struct {
    op: Op = .enc_req,
    txids: [N]stun.TransactionId = undefined,
    resp: [N][]const u8 = undefined,
    garbage: [N][]const u8 = undefined,
};

// ── the timed ops ────────────────────────────────────────────────────────────

fn once(c: *Ctx) u64 {
    var t: u64 = 0;
    switch (c.op) {
        .enc_req => for (c.txids) |id| {
            var buf: [160]u8 = undefined;
            var b = stun.Builder.init(&buf, .request, .binding, id) catch @panic("bench-stun: buffer");
            b.addSoftware("zig-libs bench") catch @panic("bench-stun: buffer");
            b.addUsername("evtj:h6vY") catch @panic("bench-stun: buffer");
            b.addMessageIntegrity(password) catch @panic("bench-stun: buffer");
            b.addFingerprint() catch @panic("bench-stun: buffer");
            for (b.finish()) |x| t += x;
        },
        .dec_resp => for (c.resp) |m| {
            t +%= decodeOurs(m);
        },
        .dec_garbage => for (c.garbage) |m| {
            t +%= if (rejectedOurs(m)) 1 else 1000;
        },
    }
    return t;
}

fn decodeOurs(raw: []const u8) u64 {
    const m = stun.decode(raw) catch @panic("bench-stun: corpus does not decode");
    const ap = (m.mappedAddress() catch @panic("bench-stun: address")) orelse @panic("bench-stun: no address");
    var t: u64 = ap.port;
    switch (ap.ip) {
        .v4 => |a| for (a) |x| {
            t += x;
        },
        .v6 => |a| for (a) |x| {
            t += x;
        },
    }
    if (m.verifyFingerprint()) t += 1;
    if (m.verifyMessageIntegrity(password)) t += 1;
    return t;
}

/// Reject like Go's `Decode`: header problems, and an attribute walk that
/// does not end exactly at the end of the message.
fn rejectedOurs(raw: []const u8) bool {
    const m = stun.decode(raw) catch return true;
    var end: usize = stun.header_len;
    var it = m.attributes();
    while (it.next()) |a| end = a.offset + 4 + ((a.value.len + 3) & ~@as(usize, 3));
    return end != m.bytes.len;
}

// ── the corpus ───────────────────────────────────────────────────────────────

fn buildResponse(arena: std.mem.Allocator, r: std.Random, i: usize) ![]const u8 {
    var txid: stun.TransactionId = undefined;
    r.bytes(&txid);
    const buf = try arena.alloc(u8, 160);
    var b = try stun.Builder.init(buf, .success_response, .binding, txid);
    try b.addSoftware("zig-libs bench server");
    const ip: netaddr.Ip = if (i % 2 == 0)
        .{ .v4 = .{ r.int(u8), r.int(u8), r.int(u8), r.int(u8) } }
    else v6: {
        var a: [16]u8 = undefined;
        r.bytes(&a);
        break :v6 .{ .v6 = a };
    };
    try b.addMappedAddress(ip, r.int(u16), true);
    try b.addMessageIntegrity(password);
    try b.addFingerprint();
    return b.finish();
}

/// Four kinds of hostile datagram, in turn.
fn buildGarbage(arena: std.mem.Allocator, r: std.Random, i: usize) ![]const u8 {
    switch (i % 4) {
        0 => { // shorter than the header
            const m = try arena.alloc(u8, r.uintLessThan(usize, stun.header_len));
            r.bytes(m);
            return m;
        },
        1 => { // a valid message with the cookie corrupted
            const m: []u8 = @constCast(try buildResponse(arena, r, i));
            m[4 + r.uintLessThan(usize, 4)] ^= @as(u8, 1) << r.int(u3);
            return m;
        },
        2 => { // declared length past the buffer
            const m: []u8 = @constCast(try buildResponse(arena, r, i));
            std.mem.writeInt(u16, m[2..4], @intCast(m.len - stun.header_len + 4 * (1 + r.uintLessThan(usize, 8))), .big);
            return m;
        },
        else => { // a first attribute whose value length overruns the message
            const m = try arena.alloc(u8, 20 + 8 + 4 * r.uintLessThan(usize, 8));
            @memset(m, 0);
            m[1] = 1;
            std.mem.writeInt(u16, m[2..4], @intCast(m.len - 20), .big);
            std.mem.writeInt(u32, m[4..8], stun.magic_cookie, .big);
            r.bytes(m[8..20]);
            std.mem.writeInt(u16, m[20..22], 0x8022, .big);
            std.mem.writeInt(u16, m[22..24], @intCast(m.len - 24 + 1 + r.uintLessThan(usize, 40)), .big);
            return m;
        },
    }
}

fn writeMsgs(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, file: []const u8, msgs: []const []const u8) !void {
    var out: std.ArrayList(u8) = .empty;
    var total: usize = 0;
    for (msgs) |m| {
        try out.appendSlice(arena, &.{ @truncate(m.len >> 8), @truncate(m.len) });
        try out.appendSlice(arena, m);
        total += m.len;
    }
    try dir.writeFile(io, .{ .sub_path = file, .data = out.items });
    std.debug.print("{s}: {s}: {d} messages, {d} bytes ({d} avg)\n", .{ bench_name, file, msgs.len, total, total / msgs.len });
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, c: *Ctx) !void {
    var prng = std.Random.DefaultPrng.init(0x57a4_0001);
    const r = prng.random();
    var tx: [N][]const u8 = undefined;
    for (&c.txids, &tx) |*id, *s| {
        r.bytes(id);
        s.* = id;
    }
    try writeMsgs(arena, io, dir, "enc_req.bin", &tx);
    for (&c.resp, 0..) |*m, i| m.* = try buildResponse(arena, r, i);
    try writeMsgs(arena, io, dir, "dec_resp.bin", &c.resp);
    for (&c.garbage, 0..) |*m, i| m.* = try buildGarbage(arena, r, i);
    try writeMsgs(arena, io, dir, "dec_garbage.bin", &c.garbage);
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

    const pion = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = "modules/stun/tools/go_bench", .abs = abs });
    const gortc = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = "modules/stun/tools/go_bench_gortc", .abs = abs, .out = "go_bench_gortc" });
    const W = bench.Work(Op);
    const ws = [_]W{
        .{ .name = "enc_req", .op = .enc_req, .ref = "enc_req", .alt = "enc_req", .alt_exe = 1, .wall_only = true },
        .{ .name = "dec_resp", .op = .dec_resp, .ref = "dec_resp", .alt = "dec_resp", .alt_exe = 1, .wall_only = true },
        .{ .name = "dec_garbage", .op = .dec_garbage, .ref = "dec_garbage", .alt = "dec_garbage", .alt_exe = 1, .wall_only = true },
    };
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = bench.drive(io, arena, .{
        .name = bench_name,
        .exes = &.{ pion, gortc },
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
