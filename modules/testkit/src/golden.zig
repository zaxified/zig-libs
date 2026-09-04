// SPDX-License-Identifier: MIT
//! Golden comparison with a failure message you can act on.
//!
//! `std.testing.expectEqualSlices` prints both slices in full. For the goldens
//! this repo actually has — a 200-byte netlink datagram from `iproute2`, an
//! IEC 61850 GOOSE frame, a DER certificate — that is two walls of hex and the
//! reader still has to find the difference by eye. These name the first
//! differing OFFSET and show a window around it, which is what you need: a
//! golden failure is nearly always "one field moved", and the offset names the
//! field.
//!
//! A length mismatch is reported separately and first. A truncated or
//! over-long encode is a different bug from a wrong byte, and conflating them
//! costs a debugging cycle.
//!
//! ## Why the split into `diff` / `render` / `expect`
//!
//! The comparison and the formatting are pure functions, and the tests below
//! exercise ONLY those. The printing wrapper is the last thin layer. That is
//! not tidiness: a test that asserts "this comparison fails" would otherwise
//! print its own diagnostic on every green run, and this repo treats any
//! stderr from the suite as a real problem (the build runner prints
//! `failed command:` for a step that wrote to stderr even when it succeeded).
//! A self-test that makes the suite look broken is worse than no self-test.

const std = @import("std");
const hex = @import("hex.zig");

/// Bytes shown around the first difference, on each side.
pub const window = 8;

pub const Mismatch = union(enum) {
    /// The encodings are different lengths. Carries both, since which one is
    /// bigger is the first thing you want to know.
    length: struct { expected: usize, actual: usize },
    /// Same length, first differing byte at this offset.
    byte: usize,
};

/// The pure comparison. Null means equal.
pub fn diff(expected: []const u8, actual: []const u8) ?Mismatch {
    if (expected.len != actual.len)
        return .{ .length = .{ .expected = expected.len, .actual = actual.len } };
    const at = std.mem.indexOfDiff(u8, expected, actual) orelse return null;
    return .{ .byte = at };
}

/// Render one side's window into `buf`, marking the offending byte with
/// brackets so the eye lands on it without counting. Returns the used prefix.
///
/// Clamps at both ends: `at` may be 0 (the low edge would underflow) or the
/// last byte (the high edge would overrun), and a length mismatch means one
/// side can be shorter than `at` entirely.
pub fn render(buf: []u8, s: []const u8, at: usize) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    const lo = at -| window;
    const hi = @min(s.len, at +| window +| 1);
    var i = lo;
    while (i < hi) : (i += 1) {
        if (i == at) {
            w.print("[{x:0>2}]", .{s[i]}) catch break;
        } else {
            w.print(" {x:0>2} ", .{s[i]}) catch break;
        }
    }
    if (hi < s.len) w.writeAll(" ...") catch {};
    return w.buffered();
}

/// Compare `actual` against a hex-encoded golden.
///
/// The golden stays a hex string at the call site deliberately: it is what the
/// capture tool printed, so it can be diffed against a fresh capture without
/// decoding anything first.
pub fn expectHex(expected_hex: []const u8, actual: []const u8) !void {
    return hexVerdict(expected_hex, actual) catch |e| {
        switch (e) {
            // Not a silent fallback to a weaker check -- say so and fail.
            error.GoldenTooLarge => std.debug.print(
                "golden is {d} bytes, larger than expectHex's {d}-byte scratch; " ++
                    "decode it yourself and use expectBytes\n",
                .{ expected_hex.len / 2, scratch_len },
            ),
            error.TestExpectedEqual => {
                var buf: [scratch_len]u8 = undefined;
                // `hexVerdict` already decoded this successfully to reach a
                // byte verdict; `catch return e` rather than `unreachable`
                // because `unreachable` is not a guard in ReleaseFast.
                const expected = hex.into(&buf, expected_hex) catch return e;
                report(expected, actual);
            },
            else => std.debug.print("golden is not valid hex: {t}\n", .{e}),
        }
        return e;
    };
}

/// Bytes of scratch `expectHex` decodes a golden into.
pub const scratch_len = 4096;

/// `expectHex`'s decision, without a word of diagnostics.
///
/// ⚠ The split is what makes the FAILING direction testable at all. Every
/// refusal here used to live inside `expectHex` next to a `std.debug.print`,
/// and `scripts/test-lib.sh` fails any step that writes to stderr while
/// passing — so a self-test that let `expectHex` refuse would have failed the
/// gate, and consequently **no test asserted the refusals**. Measured at the
/// first audit (2026-09-04): both guards deleted cleanly with the suite green,
/// and swallowing the decode error made `expectHex("zz", &.{})` **pass** —
/// a malformed golden compared as if it were an empty one.
pub fn hexVerdict(expected_hex: []const u8, actual: []const u8) !void {
    var buf: [scratch_len]u8 = undefined;
    if (expected_hex.len / 2 > buf.len) return error.GoldenTooLarge;
    const expected = try hex.into(&buf, expected_hex);
    return verdict(expected, actual);
}

/// Compare two byte slices, reporting the first difference by offset.
pub fn expectBytes(expected: []const u8, actual: []const u8) !void {
    if (diff(expected, actual) != null) report(expected, actual);
    // ⚠ The error comes from `verdict`, not from a `return` written here, so
    // the wiring between the decision and the failure is load-bearing.
    // Measured at the first audit: deleting the bare
    // `return error.TestExpectedEqual` that used to sit at the end of this
    // function left the suite at 22/22 green while five of five unequal pairs
    // passed — `expectBytes` had become a printf.
    return verdict(expected, actual);
}

/// The decision, with no diagnostics: `diff` says unequal, this says so in the
/// type system. Testable in the failing direction precisely because it is
/// silent — see `hexVerdict`.
pub fn verdict(expected: []const u8, actual: []const u8) error{TestExpectedEqual}!void {
    if (diff(expected, actual) != null) return error.TestExpectedEqual;
}

/// Everything `expectBytes` prints when the comparison fails.
fn report(expected: []const u8, actual: []const u8) void {
    const m = diff(expected, actual) orelse return;

    const at = switch (m) {
        .length => |l| @min(l.expected, l.actual),
        .byte => |at| at,
    };
    switch (m) {
        .length => |l| std.debug.print(
            "\ngolden length mismatch: expected {d} bytes, got {d}\n",
            .{ l.expected, l.actual },
        ),
        .byte => std.debug.print(
            "\ngolden differs at offset {d} (0x{x}): expected 0x{x:0>2}, got 0x{x:0>2}\n",
            .{ at, at, expected[at], actual[at] },
        ),
    }

    var eb: [16 * window]u8 = undefined;
    var ab: [16 * window]u8 = undefined;
    std.debug.print("  offset {d}..\n", .{at -| window});
    std.debug.print("  expected: {s}\n", .{render(&eb, expected, at)});
    std.debug.print("  actual:   {s}\n", .{render(&ab, actual, at)});
}

const testing = std.testing;

test "verdict fails on every kind of inequality, and says nothing while doing it" {
    // TEETH for the wiring between `diff` and the returned error, and the
    // reason it can exist at all: `verdict` is silent, so the failing
    // direction can be asserted without writing to stderr — which
    // `scripts/test-lib.sh` treats as a failure even for a passing step.
    // Before this split, deleting the error return left the suite green.
    try testing.expectError(error.TestExpectedEqual, verdict(&.{ 1, 2, 3 }, &.{ 1, 2, 4 }));
    try testing.expectError(error.TestExpectedEqual, verdict(&.{ 1, 2, 3 }, &.{ 1, 2 }));
    try testing.expectError(error.TestExpectedEqual, verdict(&.{ 1, 2 }, &.{ 1, 2, 3 }));
    try testing.expectError(error.TestExpectedEqual, verdict(&.{}, &.{1}));
    try testing.expectError(error.TestExpectedEqual, verdict(&.{1}, &.{}));
    // ...and passes on every kind of equality, empties included.
    try verdict(&.{ 1, 2, 3 }, &.{ 1, 2, 3 });
    try verdict(&.{}, &.{});
}

test "hexVerdict refuses a malformed or oversized golden instead of comparing something weaker" {
    // TEETH for both of `expectHex`'s refusals. Neither had a test, because
    // both printed on the way out. Measured before the split: swallowing the
    // decode error made `expectHex("zz", &.{})` PASS — a malformed golden
    // compared as though it were an empty one, which is the worst possible
    // reading of a typo in a vector.
    try testing.expectError(error.InvalidCharacter, hexVerdict("zz", &.{}));
    try testing.expectError(error.InvalidCharacter, hexVerdict("0g", &.{0}));
    try testing.expectError(error.InvalidLength, hexVerdict("abc", &.{ 0xab, 0xc0 }));

    // Oversized: one byte of golden past the scratch buffer.
    const too_long = "ab" ** (scratch_len + 1);
    try testing.expectError(error.GoldenTooLarge, hexVerdict(too_long, &.{}));

    // And the honest cases still work.
    try hexVerdict("deadbeef", &.{ 0xde, 0xad, 0xbe, 0xef });
    try testing.expectError(error.TestExpectedEqual, hexVerdict("deadbeef", &.{ 0xde, 0xad, 0xbe, 0xee }));
    try hexVerdict("", &.{});
}

test "diff returns null only when the slices are equal" {
    try testing.expectEqual(@as(?Mismatch, null), diff(&.{ 1, 2, 3 }, &.{ 1, 2, 3 }));
    try testing.expectEqual(@as(?Mismatch, null), diff(&.{}, &.{}));
    try testing.expect(diff(&.{ 1, 2, 3 }, &.{ 1, 2, 4 }) != null);
}

test "diff reports the FIRST difference, not just any" {
    // Two differing bytes. A last-difference or scan-from-the-end
    // implementation passes every other test in this file.
    const m = diff(&.{ 1, 2, 3, 4, 5 }, &.{ 1, 9, 3, 9, 5 }).?;
    try testing.expectEqual(@as(usize, 1), m.byte);
}

test "a length mismatch is reported as such, never as a byte difference" {
    // The teeth that matter: a truncated encode whose surviving bytes are all
    // correct must NOT pass, and must not be described as a byte difference.
    const short = diff(&.{ 1, 2, 3, 4 }, &.{ 1, 2, 3 }).?;
    try testing.expectEqual(@as(usize, 4), short.length.expected);
    try testing.expectEqual(@as(usize, 3), short.length.actual);

    const long = diff(&.{ 1, 2, 3, 4 }, &.{ 1, 2, 3, 4, 0 }).?;
    try testing.expectEqual(@as(usize, 4), long.length.expected);
    try testing.expectEqual(@as(usize, 5), long.length.actual);
}

test "a length mismatch is found even when it is the only difference" {
    // An empty actual against a non-empty golden: indexOfDiff on a
    // zero-length slice would report "equal", so the length check must come
    // first and this must still be a mismatch.
    try testing.expect(diff(&.{ 1, 2, 3 }, &.{}) != null);
    try testing.expect(diff(&.{}, &.{ 1, 2, 3 }) != null);
}

test "render marks the offending byte and nothing else" {
    var buf: [256]u8 = undefined;
    const out = render(&buf, &.{ 0xaa, 0xbb, 0xcc }, 1);
    try testing.expectEqualStrings(" aa [bb] cc ", out);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "["));
}

test "render clamps at both ends" {
    var buf: [256]u8 = undefined;
    // at == 0: the low edge would underflow.
    try testing.expectEqualStrings("[aa] bb ", render(&buf, &.{ 0xaa, 0xbb }, 0));
    // at == last: the high edge would overrun.
    try testing.expectEqualStrings(" aa [bb]", render(&buf, &.{ 0xaa, 0xbb }, 1));
    // at beyond the slice (the shorter side of a length mismatch): no bytes to
    // show, and no crash.
    try testing.expectEqualStrings("", render(&buf, &.{}, 3));
}

test "render elides the tail rather than dumping the whole slice" {
    var buf: [1024]u8 = undefined;
    var big: [64]u8 = undefined;
    @memset(&big, 0x11);
    const out = render(&buf, &big, 0);
    try testing.expect(std.mem.endsWith(u8, out, " ..."));
    // window+1 bytes at 4 chars each, plus the ellipsis.
    try testing.expectEqual(@as(usize, (window + 1) * 4 + 4), out.len);
}

test "render truncates instead of overflowing a small buffer" {
    var tiny: [5]u8 = undefined;
    const out = render(&tiny, &.{ 0xaa, 0xbb, 0xcc }, 0);
    try testing.expect(out.len <= tiny.len);
}

test "expectHex accepts a matching golden" {
    // The passing direction is safe to call directly -- it prints nothing.
    try expectHex("deadbeef", &.{ 0xde, 0xad, 0xbe, 0xef });
    try expectBytes(&.{}, &.{});
}

test "hex-decoding the golden is checked before comparing" {
    // A malformed golden must be its own error, not silently an empty
    // expectation that anything matches. `diff` is the comparison, so this
    // asserts the guard in front of it without going through the printer.
    var buf: [8]u8 = undefined;
    try testing.expectError(error.InvalidLength, hex.into(&buf, "abc"));
    try testing.expectError(error.InvalidCharacter, hex.into(&buf, "zzzz"));
}
