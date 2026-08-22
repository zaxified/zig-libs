// SPDX-License-Identifier: MIT

//! What a passive network tap does with `pping`: parse the TCP Timestamps
//! option out of two segments going one way, feed both directions into an
//! `Estimator`, and read back an RTT sample the moment the echo arrives —
//! with zero active probing and zero cooperation from either endpoint. A
//! duplicate echo of the same TSecr (a dup ACK) must NOT produce a second,
//! inflated sample (the first-echo-only rule).
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! no `test_deps`, no access to anything the module does not export). If a
//! type needed to call the API is not public, or an error cannot be named
//! from outside, this file stops compiling. The module's own tests cannot
//! notice either, because they live inside it.

const std = @import("std");
const pping = @import("pping");

/// Builds a minimal RFC 7323 TCP Timestamps option: kind=8, len=10, TSval
/// and TSecr as 4-byte big-endian fields.
fn tsOption(tsval: u32, tsecr: u32) [10]u8 {
    var buf: [10]u8 = .{ 8, 10, 0, 0, 0, 0, 0, 0, 0, 0 };
    std.mem.writeInt(u32, buf[2..6], tsval, .big);
    std.mem.writeInt(u32, buf[6..10], tsecr, .big);
    return buf;
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var est = try pping.Estimator.init(gpa, .{ .capacity = 4, .max_age = 60_000 });
    defer est.deinit(gpa);

    // Segment A->B at t=0 carries TSval=100 (its own clock; TSecr is 0,
    // nothing to echo yet on a fresh flow).
    const seg1 = tsOption(100, 0);
    const ts1 = pping.parseTcpTimestamps(&seg1) orelse return error.NoTimestampsOption;
    _ = est.observe(.{ .dir = .a_to_b, .tsval = ts1.tsval, .tsecr = ts1.tsecr, .now = 0 });

    // Segment B->A at t=20 echoes TSecr=100 — this completes the round trip
    // A started at t=0.
    const seg2 = tsOption(9000, 100);
    const ts2 = pping.parseTcpTimestamps(&seg2) orelse return error.NoTimestampsOption;
    const sample = est.observe(.{ .dir = .b_to_a, .tsval = ts2.tsval, .tsecr = ts2.tsecr, .now = 20 });
    const got = sample orelse return error.ExpectedSample;
    std.debug.print("rtt sample: tsval={d} rtt={d} at={d}\n", .{ got.tsval, got.rtt, got.at });
    if (got.rtt != 20) return error.UnexpectedRtt;

    // A duplicate ACK re-echoing the SAME TSecr (loss/reordering, delayed
    // ACK) must NOT produce a second sample — the matched TSval was already
    // consumed.
    const dup = est.observe(.{ .dir = .b_to_a, .tsval = 9001, .tsecr = 100, .now = 25 });
    std.debug.print("duplicate echo produced a sample: {}\n", .{dup != null});
    if (dup != null) return error.DuplicateEchoShouldNotSample;

    std.debug.print("observations={d} samples={d}\n", .{ est.observations_total, est.samples_emitted });

    // Direct table access: `Estimator.tables` is part of the public shape,
    // so a caller can drive `TsTable` below the `observe` seam. Filling a
    // direction's table past `capacity` names its own error rather than
    // silently growing or overwriting.
    const dir_table = &est.tables[@intFromEnum(pping.Direction.a_to_b)];
    var filled: usize = 0;
    var tsval: u32 = 1000;
    while (true) : (tsval += 1) {
        dir_table.insert(tsval, 0) catch |err| switch (err) {
            error.Full => {
                std.debug.print("table correctly refused entry #{d}: full at capacity {d}\n", .{ filled + 1, dir_table.capacity() });
                break;
            },
        };
        filled += 1;
    }
}
