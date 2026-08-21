// SPDX-License-Identifier: MIT

//! What a probe engine (an fping/mtr-style RTT prober) does with
//! `latency-stats`: feed one sample per reply (or a loss for a timeout) into
//! the zero-alloc `Accumulator` for the summary line, and in parallel feed
//! the same samples into an opt-in `Histogram` for percentiles, then print
//! both — exactly the pattern the module's own doc comment describes.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const latency_stats = @import("latency-stats");

/// One probe round's RTTs in nanoseconds, `null` meaning "no reply" (a
/// timeout the prober counts as a loss). Realistic LAN-ish jitter with one
/// dropped probe, like a `fping -c` run against a local gateway.
const round_rtts = [_]?u64{
    412_000, 438_000, null,    405_000,
    460_000, 421_000, 399_000, 512_000,
    2_100_000, 430_000, // one slow outlier: a real network occasionally does this
};

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // A caller must be able to reject a bad histogram config by name before
    // trusting it in a startup path — try an obviously wrong one first.
    _ = latency_stats.Histogram.init(gpa, .{ .lowest = 0, .highest = 1_000_000 }) catch |err| switch (err) {
        error.InvalidConfig => std.debug.print("rejected bad histogram config as expected\n", .{}),
        error.OutOfMemory => return err,
    };

    // The real config: nanosecond RTTs up to 10s, 3 significant decimal
    // digits — enough precision for a summary line without wasting memory.
    var hist = try latency_stats.Histogram.init(gpa, .{
        .highest = 10 * std.time.ns_per_s,
        .sigfigs = 3,
    });
    defer hist.deinit();

    var acc = latency_stats.Accumulator.init();
    for (round_rtts) |sample| {
        if (sample) |rtt_ns| {
            acc.addSample(rtt_ns);
            hist.record(rtt_ns); // losses never reach the histogram either
        } else {
            acc.addLoss();
        }
    }

    const stats = acc.snapshot();
    std.debug.print(
        "sent={d} recv={d} loss={d:.1}% min={d}ns max={d}ns mean={d:.0}ns stddev={d:.0}ns jitter={d:.0}ns\n",
        .{ stats.sent, stats.received, stats.lossPct(), stats.min_ns, stats.max_ns, stats.mean_ns, stats.stddev_ns, stats.jitter_ns },
    );

    const pct = hist.percentileSnapshot();
    std.debug.print(
        "percentiles: p50={d}ns p90={d}ns p95={d}ns p99={d}ns p999={d}ns max={d}ns\n",
        .{ pct.p50, pct.p90, pct.p95, pct.p99, pct.p999, pct.max },
    );

    // One-shot convenience over the same data must agree with the streaming
    // accumulator — a consumer that only has a finished slice (e.g. replaying
    // a log) reaches for this instead of building an Accumulator by hand.
    const one_shot = latency_stats.compute(&round_rtts);
    std.debug.print("one-shot compute: recv={d} mean={d:.0}ns\n", .{ one_shot.received, one_shot.mean_ns });
}
