// SPDX-License-Identifier: MIT
//! No-panic sweep tests for sntp, wave GV. Finding SN-1, see
//! ~/CML/20261029-panic-sweep/sntp-sweep.report.md.
const std = @import("std");
const testing = std.testing;
const sntp = @import("root.zig");
const Timestamp = sntp.Timestamp;

test "fromUnixNanos: the largest i128 does not overflow the offset addition (sweep SN-1)" {
    // maxInt(i128) + the 1900 offset used to be a signed overflow.
    const t = Timestamp.fromUnixNanos(std.math.maxInt(i128));
    const secs: u128 = @as(u128, std.math.maxInt(i128)) / std.time.ns_per_s;
    try testing.expectEqual(@as(u32, @truncate(secs)), t.seconds);
}

test "fromUnixNanos: instants past the u64 nanosecond range wrap like the era rollover (sweep SN-1)" {
    const off = sntp.ntp_unix_offset_ns;
    const ns_per_s = std.time.ns_per_s;
    // NTP-ns == maxInt(u64) is the old edge and must be unchanged ...
    const edge = Timestamp.fromUnixNanos(@as(i128, std.math.maxInt(u64)) - off);
    try testing.expectEqual(Timestamp.fromNanosSinceNtpEpoch(std.math.maxInt(u64)), edge);
    // ... one nanosecond further (NTP-ns == 2^64) used to trap in `@intCast`.
    const past = Timestamp.fromUnixNanos((@as(i128, 1) << 64) - off);
    const ns: u128 = @as(u128, 1) << 64;
    const rem: u64 = @intCast(ns % ns_per_s);
    try testing.expectEqual(@as(u32, @truncate(ns / ns_per_s)), past.seconds);
    try testing.expectEqual(@as(u32, @intCast((rem << 32) / ns_per_s)), past.fraction);
    // The seconds field is periodic with 2^32 s, far beyond the u64 range too.
    const x: i128 = (@as(i128, 1) << 70) - off;
    const period: i128 = (@as(i128, 1) << 32) * ns_per_s;
    try testing.expectEqual(Timestamp.fromUnixNanos(x), Timestamp.fromUnixNanos(x + period));
    // Before 1900 stays the zero sentinel, including the most negative value.
    try testing.expectEqual(Timestamp.zero, Timestamp.fromUnixNanos(std.math.minInt(i128)));
}
