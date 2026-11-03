// SPDX-License-Identifier: MIT

//! Comparative benchmark for `framing` (the program behind the card's
//! `**Performance:**` line). THIS IS A PROGRAM, NOT A TEST: `zig build
//! bench-framing` runs it (ReleaseFast); run it under `hw run`.
//!
//! Reference: tokio-util 0.7.19 `LengthDelimitedCodec` (MIT). Second
//! implementation in the field ("fastest" = the faster of the two per row):
//! asynchronous-codec 0.7.0 `LengthCodec` (MIT; fixed u64 big-endian length
//! field, no cap, no options). Both are built from source by `cargo build
//! --release` in tools/oracle (Cargo.lock pins them; the crate's own `target/`).
//!
//! One op = 64 frames of 64 B or 1 KiB with the one wire all three speak, a
//! u64 big-endian length field. What each side does PER OP, identically:
//!   dec_*  the 64-frame stream is copied into the codec's own buffer (ours:
//!          `Decoder.pending` via `feed`; Rust: `BytesMut::clear` +
//!          `extend_from_slice`), then the codec yields all 64 frames in
//!          place, no copy (ours: slices into `pending`; Rust: `split_to`,
//!          refcounted views). Count = sum of len + first + last byte of
//!          every frame.
//!   enc_*  64 frame writes of an existing payload into a reused destination
//!          (ours: `writeFrame` into a fixed `Writer`; Rust: `encode` of a
//!          refcounted `Bytes` into a cleared `BytesMut` with capacity kept).
//!          Count = output length + its last byte.
//! Not the same: tokio's buffer type does reference counting and growth
//! checks that ours has no counterpart for (the cost of its API); ours checks
//! the length cap and offers the blocking readers, which are not timed here.
//! Wall time only (the foreign side counts no cycles). Ratios are ours/ref.

const std = @import("std");
const bench = @import("testkit").bench;
const framing = @import("framing");

const bench_name = "bench-framing";
const work_dir = ".zig-cache/bench-framing";
const oracle = "modules/framing/tools/oracle/target/release/framing-oracle";
const N = 64;
const sizes = [_]usize{ 64, 1024 };

const Op = enum { dec_64, dec_1024, enc_64, enc_1024 };

const Ctx = struct {
    op: Op = .dec_64,
    gpa: std.mem.Allocator,
    streams: [2][]const u8 = undefined,
    payloads: [2][N][]const u8 = undefined,
    dec: framing.Decoder = undefined,
    out: [N * (1024 + 8)]u8 = undefined,
};

const limits: framing.Limits = .{ .max_frame = std.math.maxInt(u32), .prefix = .{ .width = .u64, .endian = .big } };

fn once(c: *Ctx) u64 {
    const k: usize = if (@backingInt(c.op) & 1 == 0) 0 else 1;
    var t: u64 = 0;
    switch (c.op) {
        .dec_64, .dec_1024 => {
            c.dec.pending.clearRetainingCapacity();
            c.dec.start = 0;
            c.dec.feed(c.gpa, c.streams[k]) catch @panic("bench-framing: feed");
            while (c.dec.next() catch @panic("bench-framing: next")) |f| t += f.len + f[0] + f[f.len - 1];
        },
        .enc_64, .enc_1024 => {
            var w: std.Io.Writer = .fixed(&c.out);
            for (c.payloads[k]) |p| framing.writeFrame(&w, p, limits) catch @panic("bench-framing: write");
            t = w.end + c.out[w.end - 1];
        },
    }
    return t;
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

    var ctx = try arena.create(Ctx);
    ctx.* = .{ .gpa = init.gpa };
    ctx.dec = .init(limits);
    for (sizes, 0..) |sz, k| {
        var stream: std.ArrayList(u8) = .empty;
        for (0..N) |f| {
            const p = try arena.alloc(u8, sz);
            for (p, 0..) |*b, i| b.* = @truncate(i * 31 + f * 7);
            ctx.payloads[k][f] = p;
            var hdr: [8]u8 = undefined;
            std.mem.writeInt(u64, &hdr, sz, .big);
            try stream.appendSlice(arena, &hdr);
            try stream.appendSlice(arena, p);
        }
        ctx.streams[k] = stream.items;
        try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "stream_{d}.bin", .{sz}), .data = stream.items });
    }
    const exe = try cwd.realPathFileAlloc(io, oracle, arena);

    const W = bench.Work(Op);
    const ws = [_]W{
        .{ .name = "dec_64", .op = .dec_64, .ref = "dec_64", .alt = "alt:dec_64", .wall_only = true },
        .{ .name = "dec_1024", .op = .dec_1024, .ref = "dec_1024", .alt = "alt:dec_1024", .wall_only = true },
        .{ .name = "enc_64", .op = .enc_64, .ref = "enc_64", .alt = "alt:enc_64", .wall_only = true },
        .{ .name = "enc_1024", .op = .enc_1024, .ref = "enc_1024", .alt = "alt:enc_1024", .wall_only = true },
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
    }, ctx, once, ws, w) catch |e| switch (e) {
        error.CountMismatch => return 1,
        else => return e,
    };
    try w.print("\nworst ours/tokio-util = {d:.2} (best {d:.2}); worst ours/fastest = {d:.2}\n", .{ s.worst_ref, s.best_ref, s.worst_fast orelse 0 });
    try w.flush();
    return 0;
}
