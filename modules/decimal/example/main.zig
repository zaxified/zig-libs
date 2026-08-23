// SPDX-License-Identifier: MIT

//! What a billing consumer does with `decimal`: parse line-item amounts out
//! of a CSV-shaped source, sum them exactly, add tax, and split the total
//! evenly across a number of invoices — the kind of money math that must
//! never drift by a cent to binary-float rounding.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const decimal = @import("decimal");
const Decimal = decimal.Decimal;

/// Three line items straight off an invoice, as text — the shape money
/// arrives in from a CSV column or a form field.
const line_items = [_][]const u8{ "19.99", "5.50", "100.00" };

pub fn main() !void {
    // Sum with exact decimal addition — no binary-float noise across the
    // three additions.
    var total = Decimal.zero;
    for (line_items) |s| {
        // Every line item above is well-formed, so a parse failure here would
        // mean the fixture and the module disagree about "well-formed".
        const amount = Decimal.parse(s) catch |err| switch (err) {
            error.InvalidCharacter, error.Overflow => return err,
        };
        // Three small amounts cannot overflow a decimal wide enough to hold
        // real invoice totals; a failure here is a module regression, not an
        // expected outcome.
        total = total.add(amount) catch |err| switch (err) {
            error.Overflow => return err,
        };
    }

    var buf: [Decimal.str_buf_len]u8 = undefined;
    std.debug.print("subtotal: {s}\n", .{total.toString(&buf)});
    // 19.99 + 5.50 + 100.00, worked out independently of the module.
    const expected_subtotal = try Decimal.parse("125.49");
    if (!total.eql(expected_subtotal)) return error.SubtotalWrong;

    // Add 8.25% sales tax. mul rounds the 12th fractional digit
    // half-away-from-zero, matching what a caller sees on a receipt.
    const tax_rate = try Decimal.parse("0.0825");
    const tax = try total.mul(tax_rate);
    const grand_total = try total.add(tax);
    std.debug.print("tax: {s}\n", .{tax.toString(&buf)});
    std.debug.print("grand total: {s}\n", .{grand_total.toString(&buf)});
    // 125.49 * 0.0825 = 10.352925, worked out by hand (well within mul's
    // 12-fractional-digit precision, so no rounding applies).
    const expected_tax = try Decimal.parse("10.352925");
    if (!tax.eql(expected_tax)) return error.TaxWrong;
    const expected_grand_total = try Decimal.parse("135.842925");
    if (!grand_total.eql(expected_grand_total)) return error.GrandTotalWrong;

    // Split the grand total across 3 invoices, rounded to the cent. divRound
    // computes the quotient at an explicit result scale, resolving the
    // discarded remainder with the caller's rounding mode — this is what a
    // real "split the bill" feature needs, not plain div (which always
    // rounds to the internal 12-digit scale).
    const three = try Decimal.fromInt(3);
    const share = grand_total.divRound(three, 2, .half_even) catch |err| switch (err) {
        error.DivisionByZero => unreachable, // three is a compile-time-known nonzero literal
        error.Overflow => return err, // a three-figure invoice split cannot overflow
    };
    std.debug.print("per-invoice share (of 3): {s}\n", .{share.toString(&buf)});
    // 135.842925 / 3 = 45.280975, half_even to 2dp: the digit after the
    // rounding position is 0 (< 5), so it rounds down to 45.28.
    const expected_share = try Decimal.parse("45.28");
    if (!share.eql(expected_share)) return error.ShareWrong;

    // A caller-triggered division by zero must be nameable from outside the
    // module, not just observable as "some error".
    if (Decimal.one.div(Decimal.zero)) |_| {
        return error.DivisionByZeroUnexpectedlyAccepted;
    } else |err| switch (err) {
        error.DivisionByZero => std.debug.print("division by zero correctly rejected\n", .{}),
        error.Overflow => return err,
    }

    // Re-quantize a raw sensor-style reading down to 2 fractional digits
    // with an explicit rounding mode, the way a report footer would.
    const raw_reading = try Decimal.parse("42.126");
    const rounded = try raw_reading.rescale(2, .half_even);
    std.debug.print("reading rounded to 2dp: {s}\n", .{rounded.toString(&buf)});
    // 42.126 half_even to 2dp: the digit after the rounding position is 6
    // (>= 5), so it rounds up to 42.13.
    const expected_rounded = try Decimal.parse("42.13");
    if (!rounded.eql(expected_rounded)) return error.RescaleWrong;
}
