// SPDX-License-Identifier: MIT

//! The reference PARSER's verdict on every byte string in
//! `conformance.zig`'s `semantic_cases` -- shapes a canonical encoder
//! never emits, so no round trip through our own codec can settle any of
//! them. Captured from the Python `protobuf` package and committed, which
//! is what lets `interop_replay_test.zig` hold the same ground with no
//! python3 anywhere.
//!
//! Each entry is `msg.ParseFromString(input)` followed by
//! `SerializeToString(deterministic=True)`: the reference's own reading of
//! the input, written back out canonically. `null` means the reference
//! REFUSED the input (its parser raised), which for the `utf8_bad_*` cases
//! is the verdict being recorded.
//!
//! Why the canonical re-serialization rather than the reference's text
//! dump: it is the same information -- the dump lists every field
//! including defaults, and a value that decoded wrongly to a default
//! shortens the canonical bytes just as visibly -- without needing a Zig
//! re-implementation of Python's float formatting to compare against.
//!
//! GENERATED FILE. Regenerate:
//!
//!   zig build interop-protobuf -- --capture
//!
//! Reference: google.protobuf 4.21.12 on Python 3.14.4, 2026-09-11

pub const Verdict = struct {
    name: []const u8,
    /// The reference's canonical re-serialization of its own parse, or
    /// `null` when the reference refused the input.
    normalized: ?[]const u8,
};

pub const verdicts = [_]Verdict{
    .{ .name = "flipped_packing", .normalized = &.{ 0x0a, 0x04, 0x01, 0x02, 0x96, 0x01, 0x10, 0x01, 0x10, 0x02, 0x10, 0x96, 0x01 } },
    .{ .name = "merge_two_copies", .normalized = &.{ 0x8a, 0x01, 0x05, 0x08, 0x01, 0x12, 0x01, 0x78 } },
    .{ .name = "merge_rep_two", .normalized = &.{ 0x42, 0x02, 0x08, 0x01, 0x42, 0x03, 0x12, 0x01, 0x78 } },
    .{ .name = "utf8_bad_lone_ff", .normalized = null },
    .{ .name = "utf8_bad_overlong", .normalized = null },
    .{ .name = "utf8_bad_surrogate", .normalized = null },
    .{ .name = "utf8_bad_truncated", .normalized = null },
    .{ .name = "utf8_raw_ff_ok", .normalized = &.{ 0x82, 0x01, 0x01, 0xff } },
    .{ .name = "nonminimal_tag_stricter", .normalized = &.{ 0x90, 0x00, 0x05 } },
    .{ .name = "field_number_out_of_range_stricter", .normalized = &.{ 0x80, 0x80, 0x80, 0x80, 0x10, 0x00 } },
};
