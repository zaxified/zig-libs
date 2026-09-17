// SPDX-License-Identifier: MIT
//
// WHY THIS EXISTS: `SPEC.md`'s "Performance" section asserts numbers — runtime
// loop 98–113 MiB/s, unrolled 340–362 MiB/s, ≈3.0–3.7× — and no test pins any
// of them. A test cannot: throughput is not a pass/fail property. This is the
// only way to re-derive the claim the SPEC makes, on this machine, today.
//
// ⚠ ReleaseFast, never Debug. A bare `zig build-exe` is a Debug build and then
// this measures the debug build, not the shipped one.
//
// ⚠ It reports best AND worst of 5 rounds plus the spread. A single number
// from a shared machine is not a measurement — if the spread is wide, the
// delta you are reading may be load, not code.
//
// WHAT IT NEEDS: the live module, and a reasonably quiet machine.
//
// WHAT IT PRODUCES: MiB/s per input size, one-shot vs 64-byte streaming at
// 1 MiB, and the per-call cost of `hash160(33 B)` — the compressed-pubkey size
// the Bitcoin consumers (`bech32`, `bitcoinscript`, `bip32`) actually use.
//
// Build (⚠ against the LIVE module, never a copy):
//   zig build-exe -O ReleaseFast --dep ripemd160 \
//       -Mmain=bench.zig -Mripemd160=../src/root.zig \
//       --cache-dir <scratch>/zc-bench -femit-bin=<scratch>/bench

const std = @import("std");
const rmd = @import("ripemd160");
const out = @import("out.zig");
const linux = std.os.linux;

fn nowNs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

var buf: [1 << 20]u8 = undefined;
var sink: u64 = 0;

const sizes = [_]usize{ 33, 64, 256, 1024, 8192, 16384, 262144, 1 << 20 };

pub fn main() !void {
    for (&buf, 0..) |*b, i| b.* = @intCast(i % 251);
    var d: [20]u8 = undefined;

    // target ~0.2 s of work per (size, mode) cell
    for (sizes) |n| {
        const msg = buf[0..n];
        var iters: usize = 16;
        while (true) {
            const t0 = nowNs();
            for (0..iters) |_| {
                rmd.Ripemd160.hash(msg, &d, .{});
                sink +%= d[0];
            }
            if (nowNs() - t0 > 200_000_000) break;
            iters *= 4;
            if (iters > 1 << 28) break;
        }
        var best: f64 = 0;
        var worst: f64 = 1e18;
        var rounds: usize = 0;
        while (rounds < 5) : (rounds += 1) {
            const t0 = nowNs();
            for (0..iters) |_| {
                rmd.Ripemd160.hash(msg, &d, .{});
                sink +%= d[0];
            }
            const dt = nowNs() - t0;
            const mibs = (@as(f64, @floatFromInt(n * iters)) / 1048576.0) / (@as(f64, @floatFromInt(dt)) / 1e9);
            if (mibs > best) best = mibs;
            if (mibs < worst) worst = mibs;
        }
        out.print("one-shot  n={d:>8}  best={d:.1} MiB/s  worst={d:.1} MiB/s  spread={d:.1}%\n", .{ n, best, worst, 100.0 * (best - worst) / best });
    }

    // streaming, 64-byte feeds (worst realistic chunking) vs one-shot, 1 MiB
    {
        const msg = buf[0..];
        const iters: usize = 64;
        var best_s: f64 = 0;
        var best_o: f64 = 0;
        for (0..5) |_| {
            var t0 = nowNs();
            for (0..iters) |_| {
                var h = rmd.Ripemd160.init(.{});
                var off: usize = 0;
                while (off < msg.len) : (off += 64) h.update(msg[off..][0..64]);
                h.final(&d);
                sink +%= d[0];
            }
            var dt = nowNs() - t0;
            const s = (@as(f64, @floatFromInt(msg.len * iters)) / 1048576.0) / (@as(f64, @floatFromInt(dt)) / 1e9);
            if (s > best_s) best_s = s;

            t0 = nowNs();
            for (0..iters) |_| {
                rmd.Ripemd160.hash(msg, &d, .{});
                sink +%= d[0];
            }
            dt = nowNs() - t0;
            const o = (@as(f64, @floatFromInt(msg.len * iters)) / 1048576.0) / (@as(f64, @floatFromInt(dt)) / 1e9);
            if (o > best_o) best_o = o;
        }
        out.print("1 MiB: one-shot={d:.1} MiB/s  streaming-in-64B-chunks={d:.1} MiB/s  ratio={d:.3}\n", .{ best_o, best_s, best_o / best_s });
    }

    // hash160 at 33 bytes: the actual Bitcoin address-derivation call
    {
        const msg = buf[0..33];
        const iters: usize = 2_000_000;
        var best: f64 = 1e18;
        for (0..5) |_| {
            const t0 = nowNs();
            for (0..iters) |_| {
                rmd.hash160(msg, &d);
                sink +%= d[0];
            }
            const ns = @as(f64, @floatFromInt(nowNs() - t0)) / @as(f64, @floatFromInt(iters));
            if (ns < best) best = ns;
        }
        out.print("hash160(33B): {d:.1} ns/call = {d:.0} calls/s\n", .{ best, 1e9 / best });
    }

    out.print("sink={d}\n", .{sink});
    out.flush();
}
