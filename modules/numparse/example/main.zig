// SPDX-License-Identifier: MIT

//! What a locale-aware import job does with `numparse`: parse thousands-
//! grouped numbers off a CSV/report source under the American and European
//! conventions the module documents, cross-checked against what glibc's own
//! locale-aware `printf` formats on this machine (`en_US.UTF-8`), and show
//! the one gap that check surfaces: a real glibc locale's thousands
//! separator is not always the single ASCII byte this API's `u8` parameter
//! can express.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).

const std = @import("std");
const numparse = @import("numparse");
const Decimal = @import("decimal").Decimal;

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    var buf: [Decimal.str_buf_len]u8 = undefined;

    // American convention. `LC_ALL=en_US.UTF-8 printf "%'.2f" 1234.56` on
    // this machine prints exactly "1,234.56" — the external oracle for this
    // case.
    const american = numparse.parseGroupedNumber("1,234.56", ',', '.').?;
    std.debug.print("American \"1,234.56\" (glibc en_US.UTF-8 printf output) -> {s}\n", .{american.toString(&buf)});
    std.debug.assert(american.raw == (try Decimal.parse("1234.56")).raw);

    // European convention (thousands='.', decimal=','). No European glibc
    // locale is installed on this machine to shell out to, so this is
    // checked against the module's own documented convention (ICU CLDR's
    // published de_DE grouping) rather than a live oracle.
    const european = numparse.parseGroupedNumber("1.234.567,89", '.', ',').?;
    std.debug.print("European \"1.234.567,89\" (ICU CLDR de_DE grouping) -> {s}\n", .{european.toString(&buf)});
    std.debug.assert(european.raw == (try Decimal.parse("1234567.89")).raw);

    // A caller who takes the task description's "1 234,56" (plain ASCII
    // space) at face value gets a clean parse using thousands_sep=' ':
    const space_grouped = numparse.parseGroupedNumber("1 234,56", ' ', ',').?;
    std.debug.print("space-grouped \"1 234,56\" (ASCII 0x20 separator) -> {s}\n", .{space_grouped.toString(&buf)});
    std.debug.assert(space_grouped.raw == (try Decimal.parse("1234.56")).raw);

    // But that is not what glibc's own locale formatter actually emits.
    // `python3 -c "import locale; locale.setlocale(locale.LC_ALL,
    // 'cs_CZ.UTF-8'); print(locale.format_string('%.2f', 1234.56,
    // grouping=True))"` on this machine prints "1 234,56" — the
    // thousands separator is U+202F NARROW NO-BREAK SPACE, a 3-byte UTF-8
    // sequence (0xE2 0x80 0xAF), not the ASCII space (0x20) used above.
    // `thousands_sep` is typed `u8` — it cannot represent that separator at
    // all, so feeding this API the *actual* bytes glibc produces for a
    // Czech/French-style locale fails to parse, even with the "closest"
    // ASCII separator: the parser reads 0xE2 as the separator byte, then
    // requires 3 ASCII digits immediately after it, but the next byte is
    // 0x80 (continuation byte, not a digit).
    const glibc_cs_locale_bytes = "1\xe2\x80\xaf234,56"; // literal glibc cs_CZ.UTF-8 output
    const rejected = numparse.parseGroupedNumber(glibc_cs_locale_bytes, ' ', ',');
    std.debug.assert(rejected == null);
    std.debug.print("glibc cs_CZ.UTF-8 output (U+202F separator) rejected: numparse's u8 separator cannot express it (finding)\n", .{});

    // Structural validation: a lone 2-digit group is rejected outright
    // (grammar requires exactly 3 digits per group after the first).
    std.debug.assert(numparse.parseGroupedNumber("1,23", ',', '.') == null);
    std.debug.print("malformed group \"1,23\" (2 digits, not 3): rejected\n", .{});
}
