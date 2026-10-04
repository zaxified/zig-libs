// SPDX-License-Identifier: MIT
//! numparse — locale-aware grouped-number parsing (thousands + decimal
//! separators) into an exact `decimal`, with strict structural validation.
//!
//! v1 handles the western 3-digit grouping subset for two conventions:
//!   American  `thousands_sep = ','`, `decimal_sep = '.'`  → "1,234.56"
//!   European  `thousands_sep = '.'`, `decimal_sep = ','`  → "1.234,56"
//! The grammar is `[-]?d{1,3}(<thousands>d{3})+(<decimal>d+)?` with STRICT
//! structural validation (1–3 leading digits, then exact 3-digit groups, no
//! trailing junk). At least one thousands group is required, so plain
//! ungrouped numbers ("123", "1.5", "1,5") deliberately return null — those
//! are the caller's `decimal.Decimal.parse` responsibility. The strictness is
//! what prevents false positives on dates ("2025,06,01") or on American input
//! misread under European separators.
//!
//! Parsing normalizes the grouped string and hands it to
//! `decimal.Decimal.parse`.

const std = @import("std");
const Decimal = @import("decimal").Decimal;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Locale-aware grouped-number parsing (thousands/decimal separators) into an exact `decimal.Decimal`.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{ .linux64, .windows },
    .platform = .any, // pure logic, no OS calls
    .role = .util,
    .concurrency = .reentrant, // no shared state, no allocation
    .model_after = "ICU NumberFormat parse (western 3-digit grouping subset)",
    .deps = .{"decimal"},
};

/// Parses a number in thousands-grouped format, generalised over both
/// American (`thousands_sep=','`, `decimal_sep='.'`) and European
/// (`thousands_sep='.'`, `decimal_sep=','`) conventions. Accepts:
///   `[-]?d{1,3}(<thousands>d{3})+(<decimal>d+)?`
/// Requires at least one thousands group — plain numbers without grouping
/// (`"123"`, `"1,5"`, `"1.5"`) are the caller's `Decimal.parse` responsibility.
/// Returns null if `s` does not match the pattern for the given separators.
///
/// The strict structural validation (1–3 leading digits, exactly 3 digits
/// per group, no trailing non-numeric characters) is intentional. It
/// prevents false positives on strings like `"2025,06,01"` (date
/// components) or American thousands input misread as a European number.
///
/// Examples:
///   parseGroupedNumber("1,234.56", ',', '.') → 1234.56  (American)
///   parseGroupedNumber("1.234,56", '.', ',') → 1234.56  (European)
///   parseGroupedNumber("-1.234.567,89", '.', ',') → -1234567.89
pub fn parseGroupedNumber(s: []const u8, thousands_sep: u8, decimal_sep: u8) ?Decimal {
    var i: usize = 0;
    if (i < s.len and s[i] == '-') i += 1;
    // 1–3 leading digits before the first thousands group
    const leading_start = i;
    while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
    const leading = i - leading_start;
    if (leading == 0 or leading > 3) return null;
    // At least one '<thousands>ddd' group required
    var groups: usize = 0;
    while (i < s.len and s[i] == thousands_sep) {
        if (s.len < i + 4) return null;
        if (!std.ascii.isDigit(s[i + 1]) or
            !std.ascii.isDigit(s[i + 2]) or
            !std.ascii.isDigit(s[i + 3])) return null;
        i += 4;
        groups += 1;
        // A digit immediately after the group means >3 digits between separators → invalid
        if (i < s.len and std.ascii.isDigit(s[i])) return null;
    }
    if (groups == 0) return null;
    // Optional decimal part
    if (i < s.len) {
        if (s[i] != decimal_sep) return null;
        i += 1;
        if (i >= s.len or !std.ascii.isDigit(s[i])) return null;
        while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
    }
    if (i != s.len) return null;
    // Strip thousands and rewrite the decimal char to '.' into a stack
    // buffer, then re-parse with the fixed-point decimal parser. The 40-byte
    // buffer covers any value the fixed-point range can hold (≈27 integer
    // digits + dot + 12 fractional), far beyond what 3+N*4 digits can express.
    var buf: [40]u8 = undefined;
    var bi: usize = 0;
    for (s) |c| {
        if (c == thousands_sep) continue;
        if (bi >= buf.len) return null;
        buf[bi] = if (c == decimal_sep) '.' else c;
        bi += 1;
    }
    // Seed returned `?Decimal` (Decimal.parse was optional); the extracted
    // `decimal` module returns an error union, so a malformed/out-of-range
    // normalized string maps back to null.
    return Decimal.parse(buf[0..bi]) catch null;
}

// ---------------------------------------------------------------------------
// parse: one grammar, configurable symbols (2026-10-04)
// ---------------------------------------------------------------------------

/// How digits are grouped left of the decimal separator.
pub const Grouping = enum {
    /// Groups of three: `1,234,567` (most of CLDR).
    western,
    /// Indian lakh/crore: the last group three, the others two —
    /// `12,34,567` (CLDR pattern `#,##,##0`, e.g. `en_IN`, `hi`).
    indian,
};

/// What `parse` accepts. Every separator is a UTF-8 slice, so the space-like
/// separators of CLDR (U+00A0 in cs/ru/pl, U+202F in fr, `’` in de_CH) work.
/// Start from `locale("cs")` etc. and override fields, or fill it in by hand.
pub const Options = struct {
    group_sep: []const u8 = ",",
    decimal_sep: []const u8 = ".",
    grouping: Grouping = .western,
    /// Also accept any of ' ', U+00A0, U+202F, U+2009 as the group separator
    /// when `group_sep` is one of them — typed and exported text mixes them
    /// freely. CLDR (and Babel's strict mode) accept only the locale's own.
    /// One number still has to use ONE spelling throughout.
    lenient_spaces: bool = false,
    /// Refuse a number without any group separator (`"1234,5"`). The legacy
    /// `parseGroupedNumber` behaves as if this were true.
    require_grouping: bool = false,
    /// A leading `+`.
    allow_plus: bool = true,
    /// A trailing minus: `1,234.56-` (accounting / mainframe exports).
    trailing_minus: bool = false,
    /// Parenthesised negatives: `(1,234.56)` (accounting exports).
    parentheses: bool = false,
    /// Scientific notation on an UNGROUPED number: `1.5E3`, `2,5e-3` (`e` or
    /// `E`; CLDR's `×10^` forms are not read).
    exponent: bool = false,
    /// A trailing percent sign, optionally after one space-like character
    /// (`12,5 %` in cs/de/fr); the value is divided by 100.
    percent: bool = false,
};

/// CLDR number symbols for a handful of locales (group, decimal, grouping),
/// as CLDR 46 publishes them — read off Babel 2.17's data by
/// `tools/babel-oracle.py`, which also checks this table against it. Names
/// are `lang` or `lang_REGION`; an unknown name gives null.
pub fn locale(name: []const u8) ?Options {
    const nbsp = "\u{00A0}";
    const nnbsp = "\u{202F}";
    const Row = struct { []const u8, []const u8, []const u8, Grouping };
    const rows = [_]Row{
        .{ "en", ",", ".", .western },    .{ "en_US", ",", ".", .western },
        .{ "en_GB", ",", ".", .western }, .{ "en_IN", ",", ".", .indian },
        .{ "hi", ",", ".", .indian },     .{ "ja", ",", ".", .western },
        .{ "zh", ",", ".", .western },    .{ "de", ".", ",", .western },
        .{ "de_AT", ".", ",", .western }, .{ "de_CH", "\u{2019}", ".", .western },
        .{ "it", ".", ",", .western },    .{ "es", ".", ",", .western },
        .{ "pt_BR", ".", ",", .western }, .{ "nl", ".", ",", .western },
        .{ "da", ".", ",", .western },    .{ "fr", nnbsp, ",", .western },
        .{ "cs", nbsp, ",", .western },   .{ "sk", nbsp, ",", .western },
        .{ "pl", nbsp, ",", .western },   .{ "ru", nbsp, ",", .western },
        .{ "uk", nbsp, ",", .western },   .{ "sv", nbsp, ",", .western },
        .{ "fi", nbsp, ",", .western },   .{ "hu", nbsp, ",", .western },
        .{ "nb", nbsp, ",", .western },
    };
    for (rows) |r| if (std.mem.eql(u8, r[0], name))
        return .{ .group_sep = r[1], .decimal_sep = r[2], .grouping = r[3] };
    return null;
}

const space_likes = [_][]const u8{ " ", "\u{00A0}", "\u{202F}", "\u{2009}" };

fn isSpaceLike(s: []const u8) bool {
    for (space_likes) |sp| if (std.mem.eql(u8, s, sp)) return true;
    return false;
}

/// Parse a localized number into an exact `Decimal`, or null when `s` is not
/// one under `opts` (or is out of `Decimal`'s range). Grammar:
///
///     [sign] int [dec frac] [exp] [percent]      sign = '-' | U+2212 | '+'
///     int  = digits                 (no group separator anywhere), or
///            grouped                (one separator spelling throughout)
///     western grouped = d{1,3} (G d{3})+
///     indian  grouped = d{1,2} (G d{2})* G d{3}
///
/// plus `(…)` and a trailing `-` when `opts` allows them. A grouped number
/// must not start with `0` (`0.234` under `.` grouping is far more likely an
/// English decimal than 234), the fraction needs at least one digit (`5.` is
/// refused), `int` may be empty only before a fraction (`,5`), and an
/// exponent only follows an ungrouped number. Exact: the digits are handed to
/// `Decimal.parse` (12 fractional digits, half-away-from-zero beyond that).
/// No allocation.
pub fn parse(s: []const u8, opts: Options) ?Decimal {
    if (opts.decimal_sep.len == 0 or opts.group_sep.len == 0) return null;
    if (std.mem.eql(u8, opts.decimal_sep, opts.group_sep)) return null;

    var body = s;
    var negative = false;
    if (opts.parentheses and body.len >= 2 and body[0] == '(' and body[body.len - 1] == ')') {
        body = body[1 .. body.len - 1];
        negative = true;
    }

    // Percent comes off the end first: `12,5 %`.
    var percent = false;
    if (opts.percent and body.len > 0 and body[body.len - 1] == '%') {
        percent = true;
        body = body[0 .. body.len - 1];
        for (space_likes) |sp| {
            if (std.mem.endsWith(u8, body, sp)) {
                body = body[0 .. body.len - sp.len];
                break;
            }
        }
    }

    if (opts.trailing_minus and !negative and body.len > 0 and body[body.len - 1] == '-') {
        body = body[0 .. body.len - 1];
        negative = true;
    }

    var i: usize = 0;
    if (std.mem.startsWith(u8, body, "-")) {
        if (negative) return null; // `(-1)`, `-1-`
        negative = true;
        i = 1;
    } else if (std.mem.startsWith(u8, body, "\u{2212}")) {
        if (negative) return null;
        negative = true;
        i = 3;
    } else if (opts.allow_plus and std.mem.startsWith(u8, body, "+")) {
        if (negative) return null;
        i = 1;
    }

    // Normalized output: sign, digits, '.', digits, optional 'e'+exponent.
    var buf: [96]u8 = undefined;
    var n: usize = 0;
    const put = struct {
        fn f(b: *[96]u8, len: *usize, c: u8) bool {
            if (len.* >= b.len) return false;
            b[len.*] = c;
            len.* += 1;
            return true;
        }
    }.f;
    if (negative and !put(&buf, &n, '-')) return null;

    // Integer part: a run of digits, then group separators decide the shape.
    const first_start = i;
    while (i < body.len and std.ascii.isDigit(body[i])) i += 1;
    const first = body[first_start..i];
    for (first) |c| if (!put(&buf, &n, c)) return null;

    var grouped = false;
    if (sepAt(body, i, opts)) |g| {
        // Grouped: the first group's width and the rest follow the pattern.
        if (first.len == 0 or first[0] == '0') return null;
        const max_first: usize = if (opts.grouping == .western) 3 else 2;
        if (first.len > max_first) return null;
        grouped = true;
        var widths_seen: usize = 0;
        while (std.mem.startsWith(u8, body[i..], g)) {
            i += g.len;
            const gs = i;
            while (i < body.len and std.ascii.isDigit(body[i])) i += 1;
            const w = i - gs;
            for (body[gs..i]) |c| if (!put(&buf, &n, c)) return null;
            widths_seen += 1;
            const last = !std.mem.startsWith(u8, body[i..], g);
            switch (opts.grouping) {
                .western => if (w != 3) return null,
                .indian => if (last) {
                    if (w != 3) return null;
                } else if (w != 2) return null,
            }
        }
        // A different separator spelling later in the same number stops the
        // loop above and is then refused as trailing input (it is neither the
        // decimal separator nor the end).
    } else if (opts.require_grouping) {
        return null;
    }

    // Fraction.
    var has_frac = false;
    if (std.mem.startsWith(u8, body[i..], opts.decimal_sep)) {
        i += opts.decimal_sep.len;
        const fs = i;
        while (i < body.len and std.ascii.isDigit(body[i])) i += 1;
        if (i == fs) return null; // `5.`
        if (!put(&buf, &n, '.')) return null;
        for (body[fs..i]) |c| if (!put(&buf, &n, c)) return null;
        has_frac = true;
    }
    // Redundant with Decimal.parse refusing an empty mantissa (mutation
    // 2026-10-04 confirmed), kept because it states the grammar.
    if (first.len == 0 and !has_frac) return null;

    // Exponent (ungrouped only), with the percent folded into it.
    var exp: i64 = 0;
    if (opts.exponent and !grouped and i < body.len and (body[i] == 'e' or body[i] == 'E')) {
        i += 1;
        var exp_neg = false;
        if (i < body.len and (body[i] == '+' or body[i] == '-')) {
            exp_neg = body[i] == '-';
            i += 1;
        }
        const es = i;
        while (i < body.len and std.ascii.isDigit(body[i])) : (i += 1) {
            if (i - es >= 4) return null; // |exp| ≤ 9999, as Decimal.parse
            exp = exp * 10 + (body[i] - '0');
        }
        if (i == es) return null;
        if (exp_neg) exp = -exp;
    }
    if (i != body.len) return null;
    if (percent) exp -= 2;
    if (exp != 0) {
        var eb: [24]u8 = undefined;
        const es = std.fmt.bufPrint(&eb, "e{d}", .{exp}) catch return null;
        for (es) |c| if (!put(&buf, &n, c)) return null;
    }
    return Decimal.parse(buf[0..n]) catch null;
}

/// The group separator spelling that starts at `body[i]`, if any: the
/// configured one, or (with `lenient_spaces`) any space-like one when the
/// configured separator is space-like itself.
fn sepAt(body: []const u8, i: usize, opts: Options) ?[]const u8 {
    const rest = body[i..];
    if (std.mem.startsWith(u8, rest, opts.group_sep)) return opts.group_sep;
    if (opts.lenient_spaces and isSpaceLike(opts.group_sep)) {
        for (space_likes) |sp| if (std.mem.startsWith(u8, rest, sp)) return sp;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests — `Decimal.parse` returns an error union, so results are unwrapped
// with `try Decimal.parse(...)`.
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parseGroupedNumber: American format" {
    try testing.expectEqual((try Decimal.parse("1234.56")).raw, parseGroupedNumber("1,234.56", ',', '.').?.raw);
    try testing.expectEqual((try Decimal.parse("-1234567")).raw, parseGroupedNumber("-1,234,567", ',', '.').?.raw);
    try testing.expectEqual((try Decimal.parse("1000")).raw, parseGroupedNumber("1,000", ',', '.').?.raw);
    try testing.expect(parseGroupedNumber("123", ',', '.') == null);
    try testing.expect(parseGroupedNumber("1,5", ',', '.') == null);
    try testing.expect(parseGroupedNumber("1,2345", ',', '.') == null);
}

test "parseGroupedNumber: more than 3 leading digits before the first group is rejected" {
    // "1234,567" has 4 leading digits before the separator — the grammar
    // requires 1-3, even though "567" is itself a well-formed 3-digit group.
    try testing.expect(parseGroupedNumber("1234,567", ',', '.') == null);
}

test "parseGroupedNumber: trailing decimal separator with no digits after it is rejected" {
    try testing.expect(parseGroupedNumber("1,234.", ',', '.') == null);
}

test "parseGroupedNumber: European format" {
    try testing.expectEqual((try Decimal.parse("1234.56")).raw, parseGroupedNumber("1.234,56", '.', ',').?.raw);
    try testing.expectEqual((try Decimal.parse("-1234567.89")).raw, parseGroupedNumber("-1.234.567,89", '.', ',').?.raw);
    try testing.expectEqual((try Decimal.parse("1234")).raw, parseGroupedNumber("1.234", '.', ',').?.raw);
    try testing.expect(parseGroupedNumber("1.5", '.', ',') == null);
    try testing.expect(parseGroupedNumber("1.234.5", '.', ',') == null);
    try testing.expect(parseGroupedNumber("1,234.56", '.', ',') == null);
}

// ── parse (2026-10-04) ──────────────────────────────────────────────────────

fn dec(s: []const u8) Decimal {
    return Decimal.parse(s) catch unreachable;
}

fn expectParse(want: ?[]const u8, s: []const u8, opts: Options) !void {
    const got = parse(s, opts);
    if (want) |w| {
        if (got == null) {
            std.debug.print("refused {s}, want {s}\n", .{ s, w });
            return error.TestUnexpectedResult;
        }
        try testing.expectEqual(dec(w).raw, got.?.raw);
    } else if (got) |g| {
        std.debug.print("accepted {s} as raw {d}, want refusal\n", .{ s, g.raw });
        return error.TestUnexpectedResult;
    }
}

test "parse: differential against Babel's strict parse_decimal over CLDR locales" {
    // `tools/babel-oracle.py` wrote this file from Babel's own formatting of
    // random values plus systematic corruptions, each with Babel's verdict.
    const golden = @embedFile("testdata/babel_golden.txt");
    var lines = std.mem.splitScalar(u8, golden, '\n');
    var cases: usize = 0;
    var accepted: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var f = std.mem.splitScalar(u8, line, '\t');
        const name = f.next().?;
        const input = f.next().?;
        const want = f.next().?;
        const opts = locale(name) orelse return error.UnknownLocaleInGolden;
        try expectParse(if (std.mem.eql(u8, want, "-")) null else want, input, opts);
        cases += 1;
        if (!std.mem.eql(u8, want, "-")) accepted += 1;
    }
    // The file was generated with both outcomes in bulk; a truncated or empty
    // file must not pass as "no disagreement".
    try testing.expect(cases > 5000);
    try testing.expect(accepted > 1000);
}

test "parse: CLDR space-like and apostrophe separators" {
    // cs groups with U+00A0, fr with U+202F, de_CH with U+2019 (CLDR).
    try expectParse("1234567.89", "1\u{00A0}234\u{00A0}567,89", locale("cs").?);
    try expectParse("1234.5", "1\u{202F}234,5", locale("fr").?);
    try expectParse("1234.5", "1\u{2019}234.5", locale("de_CH").?);
    // Strict CLDR: a plain space is not cs's separator ...
    try expectParse(null, "1 234,5", locale("cs").?);
    // ... unless lenient_spaces, and then still one spelling per number.
    var cs = locale("cs").?;
    cs.lenient_spaces = true;
    try expectParse("1234567", "1 234 567", cs);
    try expectParse("1234567", "1\u{202F}234\u{202F}567", cs);
    try expectParse(null, "1 234\u{00A0}567", cs);
    // lenient_spaces never widens a non-space separator.
    var de = locale("de").?;
    de.lenient_spaces = true;
    try expectParse(null, "1 234,5", de);
}

test "parse: Indian grouping" {
    const in_ = locale("en_IN").?;
    // 1,23,45,678 = one crore twenty-three lakh forty-five thousand six
    // hundred seventy-eight.
    try expectParse("12345678", "1,23,45,678", in_);
    try expectParse("1234567.5", "12,34,567.5", in_);
    try expectParse("1234", "1,234", in_);
    try expectParse(null, "123,456", in_); // western shape: lakh group missing
    try expectParse(null, "1,234,567", in_);
    try expectParse(null, "1,23,4567", in_);
    try expectParse(null, "123,45,678", in_); // first group at most two
}

test "parse: signs, accounting negatives, percent and exponent" {
    var o: Options = .{};
    try expectParse("1234.5", "+1,234.5", o);
    try expectParse("-1234.5", "\u{2212}1,234.5", o); // U+2212 MINUS SIGN (sv, fi in CLDR)
    o.allow_plus = false;
    try expectParse(null, "+1,234.5", o);

    o = .{ .parentheses = true, .trailing_minus = true };
    try expectParse("-1234.56", "(1,234.56)", o);
    try expectParse("-1234.56", "1,234.56-", o);
    try expectParse(null, "(-1,234.56)", o); // two signs
    try expectParse(null, "(1,234.56)-", o);
    try expectParse(null, "(1,234.56", o);
    // Inside parentheses a trailing minus is a second sign, not a strip.
    try expectParse(null, "(1,234.56-)", o);
    try expectParse(null, "(1,234.56)", .{}); // off by default
    try expectParse(null, "1,234.56-", .{});

    var cs = locale("cs").?;
    cs.percent = true;
    try expectParse("0.125", "12,5\u{00A0}%", cs); // CLDR cs percent pattern "#,##0 %"
    try expectParse("0.125", "12,5%", cs);
    try expectParse("12.34567", "1\u{00A0}234,567\u{00A0}%", cs);
    try expectParse(null, "12,5 %", locale("cs").?); // percent off

    o = .{ .exponent = true };
    try expectParse("1500", "1.5E3", o);
    try expectParse("0.0025", "2.5e-3", o);
    try expectParse(null, "1,234.5E3", o); // exponent only on ungrouped numbers (Babel agrees)
    try expectParse(null, "1.5E", o);
    try expectParse(null, "1.5E12345", o);
    // An exponent long enough to overflow i64 is refused by the digit cap,
    // not accumulated (mutation 2026-10-04: without the cap this panicked).
    try expectParse(null, "1E" ++ "9" ** 25, o);
    try expectParse(null, "1.5E3", .{}); // off by default
    o.percent = true;
    try expectParse("15", "1.5E3%", o); // the percent folds into the exponent
}

test "parse: shape refusals" {
    const o: Options = .{};
    for ([_][]const u8{
        "",       "-",        "+",         ",",      ".",        "5.",       "1,234.",
        "0,234",  "01,234",   "1,23",      "1,2345", "1234,567", "1,234,56", "1,,234",
        "1,234 ", " 1,234",   "1,234.5.6", "abc",    "1,234x",   "--1",      "1,234,",
        ",234",   "\u{2212}",
    }) |s| try expectParse(null, s, o);
    // Separators that cannot work are refused up front.
    try expectParse(null, "1", .{ .group_sep = ".", .decimal_sep = "." });
    try expectParse(null, "1", .{ .group_sep = "" });
    // Ungrouped numbers are fine unless grouping is required.
    try expectParse("1234.5", "1234.5", o);
    try expectParse("0.5", ".5", o);
    try expectParse("123", "0123", o);
    try expectParse(null, "1234.5", .{ .require_grouping = true });
}

test "parse: exact past f64, and out of range is null" {
    // 17 significant digits: f64 cannot hold 12345678901234567.25 exactly.
    try expectParse("12345678901234567.25", "12,345,678,901,234,567.25", .{});
    // Beyond Decimal's ≈1.7e26 range.
    try expectParse(null, "999,999,999,999,999,999,999,999,999", .{});
    // A normalized form longer than the internal buffer is refused, not cut.
    try expectParse(null, "1" ++ "0" ** 120, .{});
}

test "parse agrees with parseGroupedNumber where both apply" {
    // require_grouping + no plus = the legacy grammar, except that `parse`
    // refuses a grouped number starting with 0 (see its doc comment).
    const opts_us: Options = .{ .require_grouping = true, .allow_plus = false };
    const opts_eu: Options = .{ .group_sep = ".", .decimal_sep = ",", .require_grouping = true, .allow_plus = false };
    var prng = std.Random.DefaultPrng.init(0x6e70);
    const r = prng.random();
    const alphabet = "0123456789,.-";
    var buf: [16]u8 = undefined;
    var compared: usize = 0;
    for (0..20_000) |_| {
        const len = r.intRangeAtMost(usize, 1, buf.len);
        for (buf[0..len]) |*c| c.* = alphabet[r.uintLessThan(usize, alphabet.len)];
        const s = buf[0..len];
        const lead = if (s[0] == '-') s[1..] else s;
        if (lead.len > 0 and lead[0] == '0') continue; // the documented divergence
        const a = parseGroupedNumber(s, ',', '.');
        const b = parse(s, opts_us);
        try testing.expectEqual(a == null, b == null);
        if (a) |x| try testing.expectEqual(x.raw, b.?.raw);
        const c = parseGroupedNumber(s, '.', ',');
        const d = parse(s, opts_eu);
        try testing.expectEqual(c == null, d == null);
        if (c) |x| try testing.expectEqual(x.raw, d.?.raw);
        compared += 1;
    }
    try testing.expect(compared > 15_000);
}
