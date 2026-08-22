// SPDX-License-Identifier: MIT

//! What a report generator does with `datefmt`: parse a user-supplied date
//! in a template-driven format, validate a SAML-style `xsd:dateTime`
//! assertion window, and roll a billing period forward using the
//! pre-1970-safe calendar arithmetic — never through a `u64` epoch that
//! would floor anything before 1970.

const std = @import("std");
const datefmt = @import("datefmt");

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer if (gpa_state.deinit() == .leak) @panic("leak");
    const gpa = gpa_state.allocator();

    // A template format a caller configured once, applied to raw input from
    // an upstream feed.
    const parts = try datefmt.parse("07/23/2026 14:05:09", "MM/DD/YYYY hh:mm:ss");
    std.debug.print("parsed: year={d} month={d} day={d} hour={d}\n", .{ parts.year, parts.month, parts.day, parts.hour });

    // A malformed month has to fail by NAME so a caller can tell "bad
    // template" from "bad data".
    if (datefmt.parse("2026-13-01", "YYYY-MM-DD")) |_| {
        std.debug.print("unexpected: month 13 accepted\n", .{});
    } else |err| switch (err) {
        error.InvalidDate => std.debug.print("parse(\"2026-13-01\"): InvalidDate (expected)\n", .{}),
        else => return err,
    }

    // Re-render the same parts in an operator-facing report format.
    const rendered = try datefmt.format(gpa, parts, "EEEE, MMMM D YYYY [at] ii:mm A");
    defer gpa.free(rendered);
    std.debug.print("rendered: {s}\n", .{rendered});

    // A SAML-style assertion validity window: strict xsd:dateTime, distinct
    // grammar from `parse` (colon-required offset, optional fractional
    // seconds, whole-string consumption) — see the module's doc comment for
    // why it is a separate entry point.
    const not_before = try datefmt.parseXsdDateTime("2026-07-23T14:05:09.500+02:00");
    const not_on_or_after = try datefmt.parseXsdDateTime("2026-07-23T15:05:09Z");
    std.debug.print("assertion window: {d}s wide\n", .{not_on_or_after - not_before});

    // Reject Feb 31 the way the module's own doc comment says it must —
    // NOT normalised forward into March.
    if (datefmt.parseXsdDateTime("2026-02-31T00:00:00Z")) |_| {
        std.debug.print("unexpected: 2026-02-31 accepted\n", .{});
    } else |err| switch (err) {
        error.InvalidDateTime => std.debug.print("parseXsdDateTime(\"2026-02-31...\"): InvalidDateTime (expected)\n", .{}),
    }

    // Billing period: this month's period end, then roll forward one
    // calendar month, clamping day-of-month like the doc comment promises
    // (Jan 31 + 1 month -> Feb 28/29, not Mar 3).
    const period_start = datefmt.DateParts{ .year = 2026, .month = 1, .day = 31 };
    const next_period = datefmt.addMonths(period_start, 1);
    std.debug.print("2026-01-31 + 1 month = {d:0>4}-{d:0>2}-{d:0>2}\n", .{ next_period.year, next_period.month, next_period.day });

    // The last Sunday of March/October — the DST-boundary primitive named
    // in the module's own doc comment.
    const dst_start = datefmt.nthWeekdayOfMonth(2026, 3, 7, -1).?;
    const dst_end = datefmt.nthWeekdayOfMonth(2026, 10, 7, -1).?;
    std.debug.print("EU summer time 2026: {d:0>2}-{d:0>2} .. {d:0>2}-{d:0>2}\n", .{ dst_start.month, dst_start.day, dst_end.month, dst_end.day });
}
