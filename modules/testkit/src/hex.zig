// SPDX-License-Identifier: MIT
//! Hex decoding for test vectors, in the three shapes this repo actually uses.
//!
//! Every one of these existed 18 times over before it lived here. They are
//! separate functions rather than one general one because the comptime form is
//! the common case and must stay allocation-free and `comptime`-evaluable —
//! `const g = hex.bytes(32, "ab...")` at container scope is how KAT vectors
//! are written.

const std = @import("std");

/// Decode a `comptime` hex string of known byte length. The length is a
/// parameter rather than inferred so a vector that is the wrong size is a
/// COMPILE error at the vector, not a runtime surprise inside an assertion.
pub fn bytes(comptime n: usize, comptime s: *const [2 * n:0]u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch @compileError("bad hex literal: " ++ s);
    return out;
}

/// Decode into a caller-owned buffer, returning the used prefix.
/// `error.NoSpaceLeft` if `out` is too small; `error.InvalidCharacter` /
/// `error.InvalidLength` from the decoder.
///
/// There is deliberately no odd-length guard here: `std.fmt.hexToBytes`
/// already returns `error.InvalidLength` for one, verified directly. An
/// earlier version duplicated the check, and a planted mutation removing it
/// changed nothing -- redundant code, not a toothless test. The tests below
/// still pin the behaviour, because the CONTRACT is ours whoever enforces it.
pub fn into(out: []u8, s: []const u8) ![]u8 {
    if (out.len < s.len / 2) return error.NoSpaceLeft;
    return std.fmt.hexToBytes(out[0 .. s.len / 2], s);
}

/// Decode into freshly allocated memory. The caller frees it.
///
/// This one DOES check the length first -- not for the error, which std would
/// give us anyway, but to avoid allocating a buffer we are about to throw
/// away. That is the whole difference from `into`.
pub fn alloc(gpa: std.mem.Allocator, s: []const u8) ![]u8 {
    if (s.len % 2 != 0) return error.InvalidLength;
    const out = try gpa.alloc(u8, s.len / 2);
    errdefer gpa.free(out);
    return std.fmt.hexToBytes(out, s);
}

const testing = std.testing;

test "bytes decodes at comptime" {
    const g = comptime bytes(4, "deadbeef");
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, &g);
}

test "into rejects an odd-length string rather than silently truncating" {
    var buf: [8]u8 = undefined;
    try testing.expectError(error.InvalidLength, into(&buf, "abc"));
}

test "into rejects a buffer that is too small" {
    var buf: [1]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, into(&buf, "deadbeef"));
}

test "into returns only the used prefix" {
    var buf: [8]u8 = undefined;
    const got = try into(&buf, "deadbeef");
    try testing.expectEqual(@as(usize, 4), got.len);
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, got);
}

test "alloc round-trips and rejects non-hex" {
    const got = try alloc(testing.allocator, "00ff10");
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0xff, 0x10 }, got);
    try testing.expectError(error.InvalidCharacter, alloc(testing.allocator, "00zz"));
    try testing.expectError(error.InvalidLength, alloc(testing.allocator, "abc"));
}

test "alloc rejects an odd length BEFORE allocating" {
    // The guard's only job is avoiding a doomed allocation, and no ordinary
    // test can see that -- removing it stays green. A failing allocator makes
    // the ordering observable: with the guard we get InvalidLength, without it
    // the allocation is attempted first and we get OutOfMemory.
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.InvalidLength, alloc(fa.allocator(), "abc"));
    try testing.expectEqual(@as(usize, 0), fa.allocations);
}

test "alloc leaks nothing when the decode fails" {
    // testing.allocator fails the test on a leak, so the errdefer above is
    // what this asserts. Without it the odd-length guard would be the only
    // thing standing between a bad vector and a leaked buffer.
    try testing.expectError(error.InvalidCharacter, alloc(testing.allocator, "zzzz"));
}
