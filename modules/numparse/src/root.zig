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
const cldr = @import("cldr_locales.zig");

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
        // A digit immediately after the group means >3 digits between separators → invalid.
        // Redundant with the decimal-part check below, which refuses that digit
        // too (mutation 2026-10-23: equivalent); kept because it states the grammar.
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
    // buffer holds ≈27 integer digits + dot + 12 fractional; a longer
    // normalized string (more fraction digits, or the very edge of the range
    // with its sign) is refused, not cut -- `parse` takes up to 96 bytes and
    // rounds the fraction instead (review 2026-10-23).
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

/// How digits are grouped left of the decimal separator. The variants are
/// CLDR's decimal-format patterns as Babel reads them: `#,##0` western,
/// `#,##,##0` indian, `#,#0` two (`tok`), `0` none (`en_US_POSIX`).
pub const Grouping = cldr.Grouping;

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
    /// A trailing ASCII percent sign, optionally after one space-like
    /// character (`12,5 %` in cs/de/fr); the value is divided by 100. Native
    /// percent signs (`٪`) and prefix percent (tr `%12`) are not read. It comes
    /// off before a trailing minus: `5-%` is -0.05, `5%-` is refused.
    percent: bool = false,
    /// Code point of a real digit zero (Unicode `Nd` with nine digits after
    /// it); the ten digits are `zero..zero+9`
    /// (UTF-8 in the input). The default reads ASCII digits. Native digits of a
    /// numbering system (`٠`, `०`, ...) come from `localeNative`. The result is
    /// always built from ASCII digits. Digits of an exponent stay ASCII.
    zero: u21 = '0',
};

/// Folds one name byte for lookup: ASCII case-insensitive, `-` is `_`.
fn fold(c: u8) u8 {
    return if (c == '-') '_' else std.ascii.toLower(c);
}

fn nameOrder(name: []const u8, row_name: []const u8) std.math.Order {
    // `row_name` is stored lowercased-sorted but keeps its CLDR case; fold both.
    const n = @min(name.len, row_name.len);
    for (name[0..n], row_name[0..n]) |a, b| {
        const fa = fold(a);
        const fb = fold(b);
        if (fa != fb) return std.math.order(fa, fb);
    }
    return std.math.order(name.len, row_name.len);
}

fn findRow(name: []const u8) ?*const cldr.Row {
    var lo: usize = 0;
    var hi: usize = cldr.rows.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        switch (nameOrder(name, cldr.rows[mid].name)) {
            .eq => return &cldr.rows[mid],
            .lt => hi = mid,
            .gt => lo = mid + 1,
        }
    }
    return null;
}

/// CLDR number symbols of every locale identifier Babel 2.17 knows (1066;
/// CLDR 46): group and decimal separator and grouping, with Latin digits —
/// the `numbering_system='latn'` reading of Babel's `parse_decimal`. Read off
/// Babel's data by `tools/babel-oracle.py --gen-table` into
/// `src/cldr_locales.zig`. `name` is a CLDR identifier (`en`, `pt_BR`,
/// `zh_Hant_TW`, `en_US_POSIX`), matched ASCII case-insensitively with `-` or
/// `_`; an unknown name gives null. Binary search, no allocation.
pub fn locale(name: []const u8) ?Options {
    const r = findRow(name) orelse return null;
    return .{ .group_sep = r.group, .decimal_sep = r.decimal, .grouping = r.grouping };
}

/// Like `locale`, but with the locale's own default numbering system: its
/// digits (`zero`) and its group/decimal symbols (`ar_EG` → Arabic-Indic digits,
/// `٬` and `٫`). For the 954 locales whose default is Latin this equals `locale`.
pub fn localeNative(name: []const u8) ?Options {
    const r = findRow(name) orelse return null;
    return .{
        .group_sep = r.native_group,
        .decimal_sep = r.native_decimal,
        .grouping = r.grouping,
        .zero = cldr.systems[r.native].zero,
    };
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
///     two     grouped = d{1,2} (G d{2})+
///     none            = a group separator is refused (digits only)
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
    const first_start = n;
    const first_len = scanDigits(body, &i, opts.zero, &buf, &n) orelse return null;
    const first_zero = first_len > 0 and buf[first_start] == '0';

    var grouped = false;
    if (sepAt(body, i, opts)) |g| {
        // Grouped: the first group's width and the rest follow the pattern.
        if (first_len == 0 or first_zero) return null;
        if (opts.grouping == .none) return null; // the locale does not group
        const max_first: usize = if (opts.grouping == .western) 3 else 2;
        if (first_len > max_first) return null;
        grouped = true;
        var widths_seen: usize = 0;
        while (std.mem.startsWith(u8, body[i..], g)) {
            i += g.len;
            const w = scanDigits(body, &i, opts.zero, &buf, &n) orelse return null;
            widths_seen += 1;
            const last = !std.mem.startsWith(u8, body[i..], g);
            switch (opts.grouping) {
                .western => if (w != 3) return null,
                .two => if (w != 2) return null,
                .none => unreachable,
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
        if (!put(&buf, &n, '.')) return null;
        const fl = scanDigits(body, &i, opts.zero, &buf, &n) orelse return null;
        if (fl == 0) return null; // `5.`
        has_frac = true;
    }
    // Redundant with Decimal.parse refusing an empty mantissa (mutation
    // 2026-10-04 confirmed), kept because it states the grammar.
    if (first_len == 0 and !has_frac) return null;

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
        const es = std.mem.print(&eb, "e{d}", .{exp}) catch return null;
        for (es) |c| if (!put(&buf, &n, c)) return null;
    }
    return Decimal.parse(buf[0..n]) catch null;
}

/// Appends the run of digits at `body[i.*..]` to `buf` as ASCII and advances
/// `i`. A digit is `'0'..'9'` when `zero == '0'`, else the UTF-8 encoded code
/// points `zero..zero+9`. Returns the digit count, or null when `buf` is full.
fn scanDigits(body: []const u8, i: *usize, zero: u21, buf: *[96]u8, n: *usize) ?usize {
    var count: usize = 0;
    while (i.* < body.len) {
        var d: u8 = undefined;
        var w: usize = 1;
        if (zero == '0') {
            if (!std.ascii.isDigit(body[i.*])) break;
            d = body[i.*];
        } else {
            w = std.unicode.utf8ByteSequenceLength(body[i.*]) catch break;
            if (i.* + w > body.len) break;
            const cp = std.unicode.utf8Decode(body[i.*..][0..w]) catch break;
            // `zero + 10` admitted by mistake would still be refused: it maps to
            // ':', which `Decimal.parse` rejects (mutation 2026-10-23: equivalent).
            if (cp < zero or cp > @as(u21, zero) + 9) break;
            d = '0' + @as(u8, @intCast(cp - zero));
        }
        if (n.* >= buf.len) return null;
        buf[n.*] = d;
        n.* += 1;
        i.* += w;
        count += 1;
    }
    return count;
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
    var native_cases: usize = 0;
    var locales_seen: usize = 0; // runs of equal names; the file is grouped by locale
    var last_name: []const u8 = "";
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var f = std.mem.splitScalar(u8, line, '\t');
        const full = f.next().?;
        const input = f.next().?;
        const want = f.next().?;
        // `name:native` lines are read with the locale's own numbering system.
        const native = std.mem.endsWith(u8, full, ":native");
        const name = if (native) full[0 .. full.len - ":native".len] else full;
        const opts = (if (native) localeNative(name) else locale(name)) orelse return error.UnknownLocaleInGolden;
        if (native) native_cases += 1;
        locales_seen += @intFromBool(!std.mem.eql(u8, name, last_name));
        last_name = name;
        try expectParse(if (std.mem.eql(u8, want, "-")) null else want, input, opts);
        cases += 1;
        if (!std.mem.eql(u8, want, "-")) accepted += 1;
    }
    // The file was generated with both outcomes in bulk; a truncated or empty
    // file must not pass as "no disagreement".
    try testing.expect(cases > 5000);
    try testing.expect(accepted > 1000);
    // The extended part: >= 40 locales in latn, native-digit lines among them.
    try testing.expect(locales_seen >= 40);
    try testing.expect(native_cases > 100);
}

test "locale: CLDR table lookup" {
    // The 25 original rows keep their Options.
    const de = locale("de").?;
    try testing.expectEqualStrings(".", de.group_sep);
    try testing.expectEqualStrings(",", de.decimal_sep);
    try testing.expectEqual(Grouping.western, de.grouping);
    try testing.expectEqualStrings("\u{202F}", locale("fr").?.group_sep);
    try testing.expectEqualStrings("\u{2019}", locale("de_CH").?.group_sep);
    try testing.expectEqual(Grouping.indian, locale("en_IN").?.grouping);
    // Case-insensitive, `-` and `_` alike.
    try testing.expectEqualStrings(locale("zh_Hant_TW").?.group_sep, locale("ZH-hant-tw").?.group_sep);
    try testing.expect(locale("pt-br") != null);
    try testing.expect(locale("EN_us_posix") != null);
    // Unknown, empty, a prefix of a real name, a real name plus junk.
    for ([_][]const u8{ "", "xx", "e", "en_U", "en_USS", "english", "en US", "zz_ZZ" }) |n| {
        try testing.expect(locale(n) == null);
        try testing.expect(localeNative(n) == null);
    }
    // Every row is found by its own name (sorted for the binary search) and
    // the table is strictly ordered.
    var prev: []const u8 = "";
    for (cldr.rows) |r| {
        try testing.expect(locale(r.name) != null);
        try testing.expect(nameOrder(prev, r.name) == .lt);
        prev = r.name;
    }
    try testing.expect(cldr.rows.len > 1000);
    // Native digits: ar_EG reads Arabic-Indic, a Latin locale keeps ASCII.
    try testing.expectEqual(@as(u21, 0x660), localeNative("ar_EG").?.zero);
    try testing.expectEqualStrings("\u{66C}", localeNative("ar_EG").?.group_sep);
    try testing.expectEqualStrings("\u{66B}", localeNative("ar_EG").?.decimal_sep);
    try testing.expectEqualStrings(",", locale("ar_EG").?.group_sep);
    try testing.expectEqual(@as(u21, '0'), locale("ar_EG").?.zero);
    try testing.expectEqual(@as(u21, '0'), localeNative("de").?.zero);
    // Grouping kinds present in CLDR 46 / Babel 2.17: 1010 / 53 / 2 / 1.
    var counts = [_]usize{ 0, 0, 0, 0 };
    for (cldr.rows) |r| counts[@backingInt(r.grouping)] += 1;
    try testing.expectEqual([_]usize{ 1010, 53, 2, 1 }, counts);
}

test "parse: native digits (ungrouped agree with Babel; grouped are ours alone)" {
    // Ungrouped native digits: also in the golden file, spelled out here.
    try expectParse("123.5", "\u{0661}\u{0662}\u{0663}\u{066B}\u{0665}", localeNative("ar_EG").?);
    // Grouped: Babel's strict mode refuses these (it re-formats with Latin
    // digits), so the expectations are hand-checked against the CLDR pattern.
    const ar = localeNative("ar_EG").?; // ٬ group, ٫ decimal, Arabic-Indic
    try expectParse("1234.5", "\u{0661}\u{066C}\u{0662}\u{0663}\u{0664}\u{066B}\u{0665}", ar);
    try expectParse("-1234567", "-\u{0661}\u{066C}\u{0662}\u{0663}\u{0664}\u{066C}\u{0665}\u{0666}\u{0667}", ar);
    try expectParse(null, "\u{0661}\u{066C}\u{0662}\u{0663}", ar); // group of two
    try expectParse(null, "1\u{066C}234", ar); // ASCII digits are not ar_EG's native ones
    try expectParse(null, "\u{0661}\u{0662}\u{0663}3", ar); // mixed digits
    // The digit range ends at zero+9: U+066A (percent sign) is no digit.
    try expectParse(null, "\u{0661}\u{066A}", ar);
    try expectParse(null, "\u{0661}\xD9", ar); // truncated sequence
    try expectParse(null, "\u{0661}\xFF\xFF", ar); // invalid UTF-8
    // Overlong forms, a surrogate, a lone continuation byte, a cut astral
    // sequence: each ends the digit run, never decodes to a digit (review 2026-10-23).
    for ([_][]const u8{ "\xC0\xA0", "\xE0\x80\xB1", "\xED\xA0\x80", "\x80", "\xF0\x9E\xA5" }) |bad| {
        var b: [16]u8 = undefined;
        const s = try std.mem.print(&b, "\u{0661}{s}", .{bad});
        try expectParse(null, s, ar);
    }
    // Devanagari with Indian grouping (ne: `,` group): 12,34,567.
    const ne = localeNative("ne").?;
    try testing.expectEqual(@as(u21, 0x966), ne.zero);
    try expectParse("1234567", "\u{0967}\u{0968},\u{0969}\u{096A},\u{096B}\u{096C}\u{096D}", ne);
    try expectParse(null, "\u{0967},\u{0968}\u{0969}\u{096A}\u{096B}", ne);
    // Extended Arabic-Indic (fa) and an astral zero (Adlam, U+1E950).
    const fa = localeNative("fa").?;
    try testing.expectEqual(@as(u21, 0x6F0), fa.zero);
    try expectParse("1234.5", "\u{06F1}\u{066C}\u{06F2}\u{06F3}\u{06F4}\u{066B}\u{06F5}", fa);
    const adlm = Options{ .zero = 0x1E950 };
    try expectParse("90.5", "\u{1E959}\u{1E950}.\u{1E955}", adlm);
    try expectParse(null, "\u{1E95A}", adlm);
    // Every system's ten digits map to 0..9, in order.
    for (cldr.systems) |sy| {
        var txt: [40]u8 = undefined;
        var len: usize = 0;
        for (1..10) |k| len += std.unicode.utf8Encode(@intCast(sy.zero + k), txt[len..]) catch unreachable;
        try expectParse("123456789", txt[0..len], .{ .zero = sy.zero });
        // zero+10 is not a digit.
        const past = std.unicode.utf8Encode(@intCast(sy.zero + 10), txt[len..]) catch unreachable;
        try expectParse(null, txt[0 .. len + past], .{ .zero = sy.zero });
    }
}

test "parse: groups of two (.two) and no grouping (.none)" {
    // tok: nbsp group, `,` decimal, pattern `#,#0.###`: d{1,2} (G d{2})+.
    const tok = locale("tok").?;
    try testing.expectEqual(Grouping.two, tok.grouping);
    try expectParse("1234", "12\u{00A0}34", tok);
    try expectParse("123", "1\u{00A0}23", tok);
    try expectParse("1234567.5", "1\u{00A0}23\u{00A0}45\u{00A0}67,5", tok);
    try expectParse(null, "123\u{00A0}45", tok); // first group at most two
    try expectParse(null, "12\u{00A0}345", tok); // later groups exactly two
    try expectParse(null, "12\u{00A0}3", tok);
    try expectParse(null, "12\u{00A0}34\u{00A0}5", tok);
    try expectParse(null, "0\u{00A0}12", tok); // leading-zero group
    try expectParse("12345", "12345", tok); // ungrouped is fine
    // en_US_POSIX: no grouping; digits and decimal only.
    const posix = locale("en_US_POSIX").?;
    try testing.expectEqual(Grouping.none, posix.grouping);
    try expectParse("1234.5", "1234.5", posix);
    try expectParse("0.25", "0.25", posix);
    try expectParse(null, "1,234", posix);
    try expectParse(null, "1,234.5", posix);
    try expectParse(null, "12,34", posix);
    try expectParse(null, ",234", posix);
    try expectParse(null, "1,", posix);
    // Also with a hand-built Options.
    try expectParse(null, "1;234", .{ .group_sep = ";", .grouping = .none });
    try expectParse("1234", "1234", .{ .group_sep = ";", .grouping = .none });
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
    // ONE space-like character before the sign, not a run of them
    // (mutation 2026-10-23: stripping every one survived).
    try expectParse(null, "12,5\u{00A0}\u{00A0}%", cs);
    try expectParse(null, "12,5\u{00A0} %", cs); // NBSP then space: the strip order

    o = .{ .exponent = true };
    try expectParse("1500", "1.5E3", o);
    try expectParse("0.0025", "2.5e-3", o);
    try expectParse(null, "1,234.5E3", o); // exponent only on ungrouped numbers (Babel agrees)
    try expectParse(null, "1.5E", o);
    try expectParse(null, "1.5E12345", o);
    // An exponent long enough to overflow i64 is refused by the digit cap,
    // not accumulated (mutation 2026-10-04: without the cap this panicked).
    try expectParse(null, "1E" ++ strRepeat("9", 25), o);
    // The cap counts digits, leading zeros included: four are read, a fifth
    // is refused (mutation 2026-10-23: a cap of five survived).
    try expectParse("1500", "1.5E0003", o);
    try expectParse(null, "1.5E00003", o);
    try expectParse(null, "1.5E3", .{}); // off by default
    o.percent = true;
    try expectParse("15", "1.5E3%", o); // the percent folds into the exponent

    // Nothing left after the strips is not a number (review 2026-10-23).
    const all: Options = .{ .parentheses = true, .trailing_minus = true, .percent = true };
    for ([_][]const u8{ "()", "(%)", "%", " %", "-%", "-", "(-)", "()-" }) |s| try expectParse(null, s, all);
    // Percent comes off before the trailing minus: the order is the grammar.
    try expectParse("-0.05", "5-%", all);
    try expectParse(null, "5%-", all);
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
    try expectParse(null, "1" ++ strRepeat("0", 120), .{});
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

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}
