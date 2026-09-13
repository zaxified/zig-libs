// SPDX-License-Identifier: MIT

//! json_uint — a `u64` JSON field read the way drand's Go reference reads it.
//!
//! drand's documents are decoded in Go with `encoding/json` into `uint64`
//! fields (`common.Beacon.Round`, `client.RandomData.Rnd`). That decoder
//! takes only a JSON number written as an integer: a string (`"1000"`) is
//! "cannot unmarshal string into … uint64" and an exponent or fraction
//! (`1e3`, `1000.0`) is "cannot unmarshal number 1e3 into … uint64".
//! `std.json` is looser on both counts — its integer path accepts a string
//! token and coerces an integral float — so a plain `u64` field made this
//! module accept documents the reference refuses (A1 audit, drand F7).
//!
//! Callers pair this type with `.duplicate_field_behavior = .use_last`,
//! which is the third half of the same finding: Go keeps the last of two
//! equal keys, `std.json` refuses the document by default.
//!
//! Three places deliberately stay stricter than Go, because following it
//! would turn a broken document into a plausible value:
//!   - `null` is refused. Go leaves the `uint64` at its zero value, which
//!     would read as round 0.
//!   - A key matches only in its exact case. Go folds case (`"Round"`).
//!   - Bytes after the document are refused (`std.json`'s own rule). Go's
//!     `Decoder.Decode` stops after the first value.

const std = @import("std");

pub const Uint64 = struct {
    value: u64,

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) std.json.ParseError(@TypeOf(source.*))!Uint64 {
        const token = try source.nextAllocMax(allocator, .alloc_if_needed, options.max_value_len.?);
        const slice = switch (token) {
            .number => |s| s,
            .allocated_number => |s| s,
            .allocated_string => |s| {
                allocator.free(s);
                return error.UnexpectedToken;
            },
            else => return error.UnexpectedToken,
        };
        defer if (token == .allocated_number) allocator.free(slice);
        // Digits only: `parseInt` refuses `e`, `E` and `.`, which is the
        // coercion `std.json` would otherwise apply to an integral float.
        if (slice[0] == '-') return error.InvalidNumber;
        return .{ .value = std.fmt.parseInt(u64, slice, 10) catch |e| switch (e) {
            error.Overflow => return error.Overflow,
            error.InvalidCharacter => return error.InvalidNumber,
        } };
    }
};

const testing = std.testing;

fn parse(doc: []const u8) !u64 {
    const S = struct { n: Uint64 };
    const parsed = try std.json.parseFromSlice(S, testing.allocator, doc, .{
        .duplicate_field_behavior = .use_last,
    });
    defer parsed.deinit();
    return parsed.value.n.value;
}

test "Uint64: an integer number is accepted, up to maxInt(u64)" {
    try testing.expectEqual(@as(u64, 1000), try parse("{\"n\":1000}"));
    try testing.expectEqual(@as(u64, 0), try parse("{\"n\":0}"));
    try testing.expectEqual(std.math.maxInt(u64), try parse("{\"n\":18446744073709551615}"));
}

test "Uint64: string, exponent, fraction, negative, null and overflow are refused, as Go's uint64 refuses them" {
    try testing.expectError(error.UnexpectedToken, parse("{\"n\":\"1000\"}"));
    try testing.expectError(error.InvalidNumber, parse("{\"n\":1e3}"));
    try testing.expectError(error.InvalidNumber, parse("{\"n\":1000.0}"));
    try testing.expectError(error.InvalidNumber, parse("{\"n\":-1}"));
    try testing.expectError(error.InvalidNumber, parse("{\"n\":-0}"));
    try testing.expectError(error.UnexpectedToken, parse("{\"n\":null}"));
    try testing.expectError(error.Overflow, parse("{\"n\":18446744073709551616}"));
}
