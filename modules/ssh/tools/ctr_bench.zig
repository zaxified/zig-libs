// SPDX-License-Identifier: MIT

//! Packet-rate A/B of the `aes*-ctr` keystream (`transport.zig`'s `aesCtrXor`):
//! the per-block loop it used to be, std's `modes.ctr`, and `aes192.ctrXor`
//! (what it is now), over ONE counter that runs on across packets, for the
//! AES-128/192/256 contexts, at the packet sizes a session moves (a whole number
//! of 16-byte blocks each: the transport's contract). The three sides run
//! interleaved, best of several rounds; the spread printed is
//! (worst − best) / best per side.
//!
//! THIS IS A PROGRAM, NOT A TEST, and not wired into build.zig. Build and run it
//! from the repository root (it needs only `std` and the `aes192` module):
//!
//!     zig build-exe -OReleaseFast -femit-bin=.zig-cache/ssh-ctr-bench \
//!         --dep aes192 -Mroot=modules/ssh/tools/ctr_bench.zig \
//!         -Maes192=modules/aes192/src/root.zig --name ssh-ctr-bench
//!     .zig-cache/ssh-ctr-bench
//!
//! An optional argument, `BENCH_ROUNDS` in the environment (default 5), sets the
//! rounds. Each cell is `ns per packet` and the ratio to the old per-block loop.

const std = @import("std");
const aes192 = @import("aes192");
const aes = std.crypto.core.aes;

/// The loop `aesCtrXor` was before 2026-11-24: one block per call, the counter
/// carried byte by byte.
fn oldPerBlock(ctx: anytype, counter: *[16]u8, data: []u8) void {
    var i: usize = 0;
    while (i < data.len) : (i += 16) {
        var ks: [16]u8 = undefined;
        ctx.encrypt(&ks, counter);
        const n = @min(@as(usize, 16), data.len - i);
        for (0..n) |j| data[i + j] ^= ks[j];
        var k: usize = 16;
        while (k > 0) {
            k -= 1;
            counter[k] +%= 1;
            if (counter[k] != 0) break;
        }
    }
}

fn stdCtr(ctx: anytype, counter: *[16]u8, data: []u8) void {
    std.crypto.core.modes.ctr(@TypeOf(ctx), ctx, data, data, counter.*, .big);
    var c = std.mem.readInt(u128, counter, .big);
    c +%= data.len / 16;
    std.mem.writeInt(u128, counter, c, .big);
}

fn newCtr(ctx: anytype, counter: *[16]u8, data: []u8) void {
    aes192.ctrXor(@TypeOf(ctx), ctx, data, data, counter);
}

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

const Side = enum { old, std_ctr, new };

/// Best ns/packet of one side over a >= 50 ms batch, best of three batches.
fn timeSide(comptime side: Side, ctx: anytype, buf: []u8, packet: usize) f64 {
    var counter: [16]u8 = @splat(0);
    var best: f64 = std.math.inf(f64);
    for (0..3) |_| {
        var iters: usize = 0;
        const t0 = nowNs();
        while (nowNs() - t0 < 50_000_000) : (iters += 1) {
            switch (side) {
                .old => oldPerBlock(ctx, &counter, buf[0..packet]),
                .std_ctr => stdCtr(ctx, &counter, buf[0..packet]),
                .new => newCtr(ctx, &counter, buf[0..packet]),
            }
            std.mem.doNotOptimizeAway(&buf[0]);
        }
        const per = @as(f64, @floatFromInt(nowNs() - t0)) / @as(f64, @floatFromInt(iters));
        best = @min(best, per);
    }
    return best;
}

pub fn main(init: std.process.Init) !void {
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |s| try std.fmt.parseInt(usize, s, 10) else 5;
    var key: [32]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);
    var buf: [32768]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @truncate(i *% 131 +% 5);

    var stdout_buf: [1024]u8 = undefined;
    var w = std.Io.File.stdout().writer(init.io, &stdout_buf);
    const out = &w.interface;
    try out.print("{s:<8} {s:>6} {s:>12} {s:>12} {s:>12} {s:>9} {s:>9}  spread old/std/new\n", .{ "cipher", "packet", "old ns", "std ns", "new ns", "std/old", "new/old" });
    inline for (.{ .{ "aes128", aes.Aes128 }, .{ "aes192", aes192.Aes192 }, .{ "aes256", aes.Aes256 } }) |c| {
        const ctx = c[1].initEnc(key[0 .. c[1].key_bits / 8].*);
        for ([_]usize{ 48, 112, 1504, 16384, 32768 }) |packet| {
            var best = [3]f64{ std.math.inf(f64), std.math.inf(f64), std.math.inf(f64) };
            var worst = [3]f64{ 0, 0, 0 };
            for (0..rounds) |_| {
                const v = [3]f64{ timeSide(.old, ctx, &buf, packet), timeSide(.std_ctr, ctx, &buf, packet), timeSide(.new, ctx, &buf, packet) };
                for (v, 0..) |x, i| {
                    best[i] = @min(best[i], x);
                    worst[i] = @max(worst[i], x);
                }
            }
            try out.print("{s:<8} {d:>6} {d:>12.1} {d:>12.1} {d:>12.1} {d:>9.2} {d:>9.2}  {d:.0}%/{d:.0}%/{d:.0}%\n", .{
                c[0],                                 packet,                               best[0],                              best[1], best[2], best[1] / best[0], best[2] / best[0],
                (worst[0] - best[0]) / best[0] * 100, (worst[1] - best[1]) / best[1] * 100, (worst[2] - best[2]) / best[2] * 100,
            });
        }
    }
    try out.flush();
}
