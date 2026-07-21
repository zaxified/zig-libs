// SPDX-License-Identifier: MIT
//! Opt-in typed field coercion. Fields stay `[]const u8` everywhere else in
//! this module (no schema, no implicit typing) — these are thin, explicit
//! wrappers a caller reaches for only when it wants one field turned into an
//! int/float/bool, nothing more. No trimming: a field like `" 42"` is NOT
//! coerced to 42 — this module deliberately preserves field bytes verbatim
//! (see `splitFields`'s "spaces are preserved" test); trim first if your
//! source pads fields.
//!
//! Provenance: original work of the zig-libs authors (MIT).

const std = @import("std");

/// Parses `field` as a base-10 integer of type `T`. A thin, explicitly-named
/// wrapper over `std.fmt.parseInt` — no trimming, no locale handling.
pub fn parseInt(comptime T: type, field: []const u8) std.fmt.ParseIntError!T {
    return std.fmt.parseInt(T, field, 10);
}

/// Parses `field` as a floating-point value of type `T`.
pub fn parseFloat(comptime T: type, field: []const u8) std.fmt.ParseFloatError!T {
    return std.fmt.parseFloat(T, field);
}

pub const ParseBoolError = error{InvalidBool};

/// Parses `field` as a bool. Accepts `true`/`false` (case-insensitive) and
/// `1`/`0`. Anything else is `error.InvalidBool` — deliberately no "yes/no"
/// or "y/n" guessing; a caller with a wider dialect maps it before calling.
pub fn parseBool(field: []const u8) ParseBoolError!bool {
    if (std.ascii.eqlIgnoreCase(field, "true") or std.mem.eql(u8, field, "1")) return true;
    if (std.ascii.eqlIgnoreCase(field, "false") or std.mem.eql(u8, field, "0")) return false;
    return error.InvalidBool;
}

// ============================================================
// Tests
// ============================================================

const t = std.testing;

test "parseInt: valid decimal integers, signed and unsigned types" {
    try t.expectEqual(@as(i32, 42), try parseInt(i32, "42"));
    try t.expectEqual(@as(i32, -7), try parseInt(i32, "-7"));
    try t.expectEqual(@as(u8, 255), try parseInt(u8, "255"));
    try t.expectEqual(@as(i64, 0), try parseInt(i64, "0"));
}

test "parseInt: invalid input errors instead of silently coercing" {
    try t.expectError(error.InvalidCharacter, parseInt(i32, "abc"));
    try t.expectError(error.InvalidCharacter, parseInt(i32, ""));
    try t.expectError(error.InvalidCharacter, parseInt(i32, " 42")); // no trimming, by design
    try t.expectError(error.Overflow, parseInt(u8, "256"));
}

test "parseFloat: valid floats" {
    try t.expectApproxEqAbs(@as(f64, 3.14), try parseFloat(f64, "3.14"), 1e-9);
    try t.expectApproxEqAbs(@as(f64, -0.5), try parseFloat(f64, "-0.5"), 1e-9);
    try t.expectApproxEqAbs(@as(f32, 0.0), try parseFloat(f32, "0"), 1e-9);
}

test "parseFloat: invalid input errors" {
    try t.expectError(error.InvalidCharacter, parseFloat(f64, "not a number"));
    try t.expectError(error.InvalidCharacter, parseFloat(f64, ""));
}

test "parseBool: true/false and 1/0, case-insensitive" {
    try t.expectEqual(true, try parseBool("true"));
    try t.expectEqual(true, try parseBool("TRUE"));
    try t.expectEqual(true, try parseBool("True"));
    try t.expectEqual(true, try parseBool("1"));
    try t.expectEqual(false, try parseBool("false"));
    try t.expectEqual(false, try parseBool("FALSE"));
    try t.expectEqual(false, try parseBool("0"));
}

test "parseBool: unrecognized input errors rather than guessing" {
    try t.expectError(error.InvalidBool, parseBool("yes"));
    try t.expectError(error.InvalidBool, parseBool("no"));
    try t.expectError(error.InvalidBool, parseBool(""));
    try t.expectError(error.InvalidBool, parseBool("2"));
}
