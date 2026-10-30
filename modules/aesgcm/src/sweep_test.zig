// SPDX-License-Identifier: MIT

//! No-panic sweep (wave GP) regression tests.

const std = @import("std");
const root = @import("root.zig");
const hooks = root.test_hooks;

test "length contract: mismatch and > 2^36 - 32 bytes are told apart (sweep AG-1)" {
    const max = root.max_message_len;
    try std.testing.expectEqual(hooks.Verdict.ok, hooks.verdict(0, 0));
    try std.testing.expectEqual(hooks.Verdict.ok, hooks.verdict(max, max));
    try std.testing.expectEqual(hooks.Verdict.too_long, hooks.verdict(max + 1, max + 1));
    try std.testing.expectEqual(hooks.Verdict.mismatch, hooks.verdict(3, 4));
    try std.testing.expectEqual(hooks.Verdict.mismatch, hooks.verdict(max + 1, 0));
}

test "decrypt refusal: a too-long verdict zeroes m and refuses, ok leaves m alone (sweep REV-AG-2)" {
    var m: [40]u8 = @splat(0xaa);
    try std.testing.expect(!hooks.refuse(&m, .ok));
    try std.testing.expectEqual(@as(u8, 0xaa), m[0]);
    try std.testing.expect(hooks.refuse(&m, .too_long));
    for (m) |b| try std.testing.expectEqual(@as(u8, 0), b);
}
