// SPDX-License-Identifier: MIT

//! bench — MB/s of std vs this module for SHA-256 and SHA-384. Off by default;
//! opt in with `SHA2_BENCH`, in ReleaseFast:
//!
//!   SHA2_BENCH=1 scripts/modtest --file modules/sha2/src/bench.zig -OReleaseFast --test-filter bench
//!
//! One-shot `hash` over a fixed buffer at 64 B, 1 KiB, 16 KiB and 1 MiB, about
//! 32 MB per measurement, best of 5. The `scalar` column is this module's
//! portable fallback forced through the test switch — what a target without
//! AVX2 gets. MB = 10^6 bytes. A loaded or thermally throttled machine moves
//! all columns together; read the ratios.

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

/// Best-of-5 MB/s of `H.hash` over `buf`.
fn measure(comptime H: type, buf: []u8) f64 {
    const total: usize = 32 * 1000 * 1000;
    const iters = @max(1, total / buf.len);
    var best: f64 = 0;
    for (0..5) |_| {
        var out: [H.digest_length]u8 = undefined;
        const t0 = nowNs();
        for (0..iters) |_| {
            H.hash(buf, &out, .{});
            // Feed the output back so no iteration is loop-invariant.
            buf[0] ^= out[0];
        }
        const dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(&out);
        const mbps = @as(f64, @floatFromInt(iters * buf.len)) / (@as(f64, @floatFromInt(dt)) / 1e9) / 1e6;
        best = @max(best, mbps);
    }
    return best;
}

test "bench (opt-in via SHA2_BENCH)" {
    if (builtin.os.tag != .linux or std.testing.environ.getPosix("SHA2_BENCH") == null) return error.SkipZigTest;

    const big = try std.testing.allocator.alloc(u8, 1 << 20);
    defer std.testing.allocator.free(big);
    var prng = std.Random.DefaultPrng.init(0x5ba2_be4c);
    prng.random().bytes(big);

    const sizes = [_]usize{ 64, 1024, 16 * 1024, 1 << 20 };
    std.debug.print("\nsha2 bench ({t}, backend 256={t} 384={t}), MB/s best of 5\n", .{ builtin.mode, root.Sha256.backend(), root.Sha384.backend() });
    std.debug.print("{s:<8} {s:>8} {s:>9} {s:>9} {s:>6} {s:>9}\n", .{ "hash", "bytes", "std", "sha2", "ratio", "scalar" });
    inline for (.{
        .{ "SHA-256", std.crypto.hash.sha2.Sha256, root.Sha256 },
        .{ "SHA-384", std.crypto.hash.sha2.Sha384, root.Sha384 },
    }) |row| {
        for (sizes) |n| {
            const buf = big[0..n];
            const s = measure(row[1], buf);
            const m = measure(row[2], buf);
            root.test_hooks.forced = .scalar;
            const sc = measure(row[2], buf);
            root.test_hooks.forced = null;
            std.debug.print("{s:<8} {d:>8} {d:>9.1} {d:>9.1} {d:>6.2} {d:>9.1}\n", .{ row[0], n, s, m, m / s, sc });
        }
    }
}
