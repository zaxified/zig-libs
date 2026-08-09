// SPDX-License-Identifier: MIT

//! bench — opt-in measurement of `answerRange`'s sharding overhead against
//! the whole-database `answer` it now shards (audit finding F4):
//!
//!   PIR_BENCH=1 zig build test-pir -Doptimize=ReleaseFast
//!
//! `pir` starts no threads (`root.zig`'s `meta.platform = .any`), so this
//! cannot measure a parallel speedup — that needs a caller-owned thread pool
//! this module deliberately does not provide (see `answerRange`'s doc
//! comment). What it CAN measure, and does: the single-threaded overhead of
//! splitting one `answer` call into `T` sequential `answerRange` shards plus
//! `accumulate`, against calling `answer` directly. `evalRangeWith`'s only
//! extra cost over `evalFullWith` is the two root-to-boundary descents per
//! shard (`O(domain_bits)` each, `fss/src/dpf.zig`), on top of the same
//! `O(N)` leaf work either way — this turns that asymptotic claim into a
//! measured ratio, so a caller deciding whether sharding is worth it for
//! their `T` and `N` has a real number instead of a guess. A caller running
//! the `T` shards on `T` separate cores would additionally divide the leaf
//! work by `T`; that part is NOT measured here (it would require threads,
//! which this module does not add — see `SPEC.md` on scope).
//!
//! Each shard-count's output is asserted equal to `answer`'s before its
//! timing is trusted, so the numbers below are provably timings of the same
//! computation, not two computations that happen to look similar.

const std = @import("std");
const pir = @import("root.zig");

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn benchShardOverhead(
    comptime domain_bits: usize,
    count: usize,
    record_len: usize,
    comptime shard_counts: []const usize,
) !void {
    const P = pir.Pir(domain_bits, 8);
    const gpa = std.heap.page_allocator;

    const bytes = try gpa.alloc(u8, count * record_len);
    defer gpa.free(bytes);
    for (bytes, 0..) |*b, i| b.* = @truncate(i *% 2654435761 +% 12345);
    const database = try pir.Database.init(bytes, record_len);
    const n_words = P.answerWords(record_len);

    const s0 = [_]u8{0x11} ** 16;
    const s1 = [_]u8{0x22} ** 16;
    const shares = try P.query(count / 3, s0, s1);

    const want = try gpa.alloc(P.Word, n_words);
    defer gpa.free(want);
    const got = try gpa.alloc(P.Word, n_words);
    defer gpa.free(got);
    const part = try gpa.alloc(P.Word, n_words);
    defer gpa.free(part);

    const reps = 3;

    var t_full: u64 = std.math.maxInt(u64);
    for (0..reps) |_| {
        const a = nowNs();
        try P.answer(0, shares[0], database, want);
        const b = nowNs();
        t_full = @min(t_full, b - a);
    }

    std.debug.print("\n--- domain_bits={d} N={d} record_len={d} ---\n", .{ domain_bits, count, record_len });
    std.debug.print("answer (whole DB, 1 walk):                {d:>10} ns\n", .{t_full});

    inline for (shard_counts) |shards| {
        var t_sharded: u64 = std.math.maxInt(u64);
        for (0..reps) |_| {
            @memset(got, 0);
            const a = nowNs();
            var lo: usize = 0;
            var s: usize = 0;
            while (s < shards) : (s += 1) {
                const remaining_shards = shards - s;
                const remaining = count - lo;
                const len = (remaining + remaining_shards - 1) / remaining_shards;
                const hi = @min(lo + len, count);
                try P.answerRange(0, shares[0], database, lo, hi, part);
                try P.accumulate(got, part);
                lo = hi;
            }
            const b = nowNs();
            t_sharded = @min(t_sharded, b - a);
        }
        // Correctness before the timing is trusted, every shard count.
        try std.testing.expectEqualSlices(P.Word, want, got);
        std.debug.print(
            "sum of {d:>4} answerRange shards (sequential): {d:>10} ns  (overhead {d:.3}x vs answer)\n",
            .{
                shards,
                t_sharded,
                @as(f64, @floatFromInt(t_sharded)) / @as(f64, @floatFromInt(t_full)),
            },
        );
    }
}

test "bench (opt-in via PIR_BENCH)" {
    if (std.testing.environ.getPosix("PIR_BENCH") == null) return error.SkipZigTest;
    std.debug.print(
        "\n=== pir answerRange sharding overhead (F4) — single-threaded sum-of-shards vs whole-DB answer ===\n",
        .{},
    );
    // Small working sets throughout (thousands of small records, not
    // millions) — this host has OOM-killed the editor from an unbounded
    // agent bench before; keep it that way.
    try benchShardOverhead(14, 4000, 32, &.{ 1, 2, 4, 8, 16 });
    try benchShardOverhead(18, 20000, 16, &.{ 1, 4, 16, 64 });
}
