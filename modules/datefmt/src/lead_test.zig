// SPDX-License-Identifier: MIT

//! The card's grammar lead (`**Ahead:**` in SPEC.md), pinned. Each row is an
//! input whose validity the RFC grammar decides -- RFC 3339 §5.6 for
//! `parseRfc3339`, RFC 5322 §3.3 (obsolete forms included, §4.3) for
//! `parseRfc2822` -- with what the Rust crates measured 2026-10-25 answered
//! (`tools/rust_fast_bench --probe`, pinned by its Cargo.lock: humantime
//! 2.4.0 `parse_rfc3339`, chrono 0.4.45 `parse_from_rfc3339` /
//! `parse_from_rfc2822`, jiff 0.2.38 temporal `parse_timestamp` / rfc2822
//! `parse_timestamp`). Ours agrees with the grammar on every row; humantime
//! departs from it twice, jiff four times, chrono once. The rows where every
//! parser agrees are here too, so the lead is not read as "stricter is
//! better".
//!
//! Not in the count, and stated so: a leap second (`23:59:60Z`) is valid RFC
//! 3339 and RFC 5322, which the three crates accept (as `:59`) and
//! `parseRfc3339`/`parseRfc2822` refuse by design -- `DateParts` cannot hold
//! second 60, as Go's `time` cannot; `parseXsdDateTime` accepts it.

const std = @import("std");
const testing = std.testing;
const datefmt = @import("root.zig");

const Grammar = enum { rfc3339, rfc5322 };

const Case = struct {
    input: []const u8,
    grammar: Grammar,
    /// The grammar's verdict: is this a valid date-time?
    valid: bool,
    /// What each crate answered (true = parsed it); null = not a parser of
    /// this grammar.
    humantime: ?bool,
    chrono: bool,
    jiff: bool,
};

const cases = [_]Case{
    // RFC 3339 §5.6
    .{ .input = "1994-11-06T08:49:37Z", .grammar = .rfc3339, .valid = true, .humantime = true, .chrono = true, .jiff = true },
    // time-secfrac = "." 1*DIGIT
    .{ .input = "1994-11-06T08:49:37.Z", .grammar = .rfc3339, .valid = false, .humantime = true, .chrono = false, .jiff = false },
    // time-secfrac has no upper bound on its digits
    .{ .input = "1994-11-06T08:49:37.1234567891Z", .grammar = .rfc3339, .valid = true, .humantime = true, .chrono = true, .jiff = false },
    // time-numoffset hour is time-hour, 00-23
    .{ .input = "1994-11-06T08:49:37+24:00", .grammar = .rfc3339, .valid = false, .humantime = false, .chrono = false, .jiff = true },
    // partial-time requires time-second
    .{ .input = "1994-11-06T08:49Z", .grammar = .rfc3339, .valid = false, .humantime = false, .chrono = false, .jiff = true },
    // §5.6 NOTE: "T" and "Z" may be lower case
    .{ .input = "1994-11-06t08:49:37z", .grammar = .rfc3339, .valid = true, .humantime = false, .chrono = true, .jiff = true },
    // date-mday is bounded by the month (§5.7)
    .{ .input = "1994-02-30T08:49:37Z", .grammar = .rfc3339, .valid = false, .humantime = false, .chrono = false, .jiff = false },
    .{ .input = "1994-11-06T24:00:00Z", .grammar = .rfc3339, .valid = false, .humantime = false, .chrono = false, .jiff = false },
    // RFC 5322 §3.3 / §4.3
    .{ .input = "Sun, 06 Nov 1994 08:49:37 GMT", .grammar = .rfc5322, .valid = true, .humantime = null, .chrono = true, .jiff = true },
    // obs-zone lists "UT" and "GMT", not "UTC"
    .{ .input = "Sun, 06 Nov 1994 08:49:37 UTC", .grammar = .rfc5322, .valid = false, .humantime = null, .chrono = false, .jiff = true },
    // date-time = [ day-of-week "," ] date time [CFWS]
    .{ .input = "Sun, 06 Nov 1994 08:49:37 GMT ", .grammar = .rfc5322, .valid = true, .humantime = null, .chrono = false, .jiff = true },
    // the day-of-week MUST be the day implied by the date (§3.3)
    .{ .input = "Mon, 06 Nov 1994 08:49:37 GMT", .grammar = .rfc5322, .valid = false, .humantime = null, .chrono = false, .jiff = false },
    // day = 1*2DIGIT; names are case-insensitive ABNF strings; obs-year
    .{ .input = "Sun, 6 Nov 1994 08:49:37 GMT", .grammar = .rfc5322, .valid = true, .humantime = null, .chrono = true, .jiff = true },
    .{ .input = "sun, 06 nov 1994 08:49:37 gmt", .grammar = .rfc5322, .valid = true, .humantime = null, .chrono = true, .jiff = true },
    .{ .input = "Sun, 06 Nov 94 08:49:37 GMT", .grammar = .rfc5322, .valid = true, .humantime = null, .chrono = true, .jiff = true },
};

fn ours(c: Case) bool {
    return switch (c.grammar) {
        .rfc3339 => if (datefmt.parseRfc3339(c.input)) |_| true else |_| false,
        .rfc5322 => if (datefmt.parseRfc2822(c.input)) |_| true else |_| false,
    };
}

test "lead: RFC 3339 / RFC 5322 grammar -- ours on every row, humantime off on 2, jiff on 4, chrono on 1" {
    var off_humantime: usize = 0;
    var off_chrono: usize = 0;
    var off_jiff: usize = 0;
    for (cases) |c| {
        testing.expectEqual(c.valid, ours(c)) catch |e| {
            std.debug.print("lead row {s}: ours disagrees with the grammar\n", .{c.input});
            return e;
        };
        if (c.humantime) |h| off_humantime += @intFromBool(h != c.valid);
        off_chrono += @intFromBool(c.chrono != c.valid);
        off_jiff += @intFromBool(c.jiff != c.valid);
    }
    try testing.expectEqual(@as(usize, 2), off_humantime);
    try testing.expectEqual(@as(usize, 1), off_chrono);
    try testing.expectEqual(@as(usize, 4), off_jiff);
}

test "lead: the leap second the count leaves out -- refused by design, xsd accepts it" {
    try testing.expectError(datefmt.ParseError.InvalidTime, datefmt.parseRfc3339("1994-12-31T23:59:60Z"));
    try testing.expectEqual(@as(i64, 788918400), try datefmt.parseXsdDateTime("1994-12-31T23:59:60Z"));
}
