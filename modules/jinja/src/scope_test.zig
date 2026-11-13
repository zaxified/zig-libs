// SPDX-License-Identifier: MIT
//! Tests for the Jinja2 3.1 built-ins added for scope S3: `format`,
//! `groupby`, `wordwrap`, `filesizeformat`, the `sameas`/`callable` tests and
//! Unicode case mapping. Expected values are the documented semantics of the
//! reference (Jinja2 docs "List of Builtin Filters/Tests", the Jinja2 test
//! suite examples, Python's `%` operator, `textwrap` and `str` methods); the
//! test names cite the source. Since 2026-11-13 every filter here is also in the
//! oracle corpus (`s3_*` cases of `tools/corpus.zig`, replayed from golden.json).

const std = @import("std");
const testing = std.testing;
const jinja = @import("root.zig");

fn renderOpts(gpa: std.mem.Allocator, opts: jinja.Options, src: []const u8) ![]u8 {
    var env = try jinja.Environment.init(gpa, opts);
    defer env.deinit();
    return env.renderAlloc(gpa, src, .{ .none = {} }, null);
}

fn expectOut(src: []const u8, want: []const u8) !void {
    const out = try renderOpts(testing.allocator, .{}, src);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(want, out);
}

fn expectOutEsc(src: []const u8, want: []const u8) !void {
    const out = try renderOpts(testing.allocator, .{ .autoescape = true }, src);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(want, out);
}

fn expectFails(src: []const u8, err: anyerror) !void {
    try testing.expectError(err, renderOpts(testing.allocator, .{}, src));
}

// ── format (Jinja2 docs `format`; Python `str % args`) ──────────────────────

test "format: docs example '%s - %s'|format('Hello?', 'Foo!') (filters/format)" {
    try expectOut("{{ '%s - %s'|format('Hello?', 'Foo!') }}", "Hello? - Foo!");
}

test "format: integer flags and width (printf-style docs, Python % operator)" {
    try expectOut("{{ '%d|%5d|%-5d|%05d|%+d|% d'|format(42, 42, 42, 42, 42, 42) }}", "42|   42|42   |00042|+42| 42");
    try expectOut("{{ '%x %X %o %#x %#o'|format(255, 255, 8, 255, 8) }}", "ff FF 10 0xff 0o10");
    try expectOut("{{ '%.3d|%d|%d|%i'|format(5, 3.9, -3.9, true) }}", "005|3|-3|1");
}

test "format: floats round the exact binary value, as Python does (2.675 -> 2.67)" {
    try expectOut("{{ '%.2f|%8.3f|%.0f|%.0f|%.0f|%.1f|%.1f'|format(2.675, 3.14159, 0.5, 1.5, 2.5, 0.05, 0.25) }}", "2.67|   3.142|0|2|2|0.1|0.2");
    try expectOut("{{ '%e|%E|%.0e|%g|%g|%g|%g'|format(12345.678, 0.00012, 5.5, 0.0001, 1234567.0, 100000.0, 1e6) }}", "1.234568e+04|1.200000E-04|6e+00|0.0001|1.23457e+06|100000|1e+06");
    try expectOut("{{ '%f|%f|%g'|format(-0.0, 1e22, 0.0) }}", "-0.000000|10000000000000000000000.000000|0");
}

test "format: inf and nan are zero-padded like Python (oracle s3_format_special_floats)" {
    try expectOut("{{ '%010f|%-6f|' |format(1e999, 1e999) }}", "0000000inf|inf   |");
}

test "format: %s %r %c %% and string precision" {
    try expectOut("{{ '%s %r|%5.1s|%c%c|100%%'|format('a', 'a', 'abc', 65, 'z') }}", "a 'a'|    a|Az|100%");
    try expectOut("{{ '%s %s %s'|format(none, true, [1, 'x']) }}", "None True [1, 'x']");
}

test "format: mapping form %(name)s with keyword arguments" {
    try expectOut("{{ '%(a)s-%(b)05.1f'|format(a=1, b=2.25) }}", "1-002.2");
}

test "format: wrong argument counts and types are errors (TypeError in the reference)" {
    try expectFails("{{ '%s %s'|format(1) }}", error.BadArgument);
    try expectFails("{{ '%s'|format(1, 2) }}", error.BadArgument);
    try expectFails("{{ '%d'|format('x') }}", error.TypeMismatch);
    try expectFails("{{ '%s'|format(1, a=2) }}", error.BadArgument);
    try expectFails("{{ '%(a)s'|format(1) }}", error.BadArgument);
    try expectFails("{{ '%'|format() }}", error.BadArgument);
    try expectFails("{{ '%y'|format(1) }}", error.BadArgument);
}

test "format: markup format string escapes its operands (markupsafe Markup.__mod__)" {
    try expectOutEsc("{{ '<%s>'|safe|format('<b>') }}", "<&lt;b&gt;>");
    try expectOutEsc("{{ '<%s>'|format('<b>') }}", "&lt;&lt;b&gt;&gt;");
}

test "format: width and precision from template data are bounded (no panic, no OOM)" {
    try expectFails("{{ '%99999999999d'|format(1) }}", error.OutOfRange);
    try expectFails("{{ '%*d'|format(99999999999, 1) }}", error.OutOfRange);
    try expectFails("{{ '%.99999999f'|format(1.5) }}", error.OutOfRange);
    try expectFails("{{ '%.5000f'|format(1.5) }}", error.OutOfRange);
    try expectFails("{{ '%99999999999999999999999d'|format(1) }}", error.OutOfRange);
}

// ── filesizeformat (Jinja2 test suite test_filesizeformat) ──────────────────

test "filesizeformat: decimal and binary prefixes (Jinja2 tests/test_filters.py)" {
    try expectOut("{{ [1, 100, 1000, 1500, 1000000, 1000000000, 1000000000000]|map('filesizeformat')|join('|') }}", "1 Byte|100 Bytes|1.0 kB|1.5 kB|1.0 MB|1.0 GB|1.0 TB");
    try expectOut("{{ 100|filesizeformat(true) }}|{{ 1000|filesizeformat(true) }}|{{ 1024|filesizeformat(true) }}|{{ 1000000|filesizeformat(true) }}|{{ 1048576|filesizeformat(true) }}|{{ 1073741824|filesizeformat(true) }}", "100 Bytes|1000 Bytes|1.0 KiB|976.6 KiB|1.0 MiB|1.0 GiB");
    try expectOut("{{ '2048'|filesizeformat }}|{{ -5|filesizeformat }}|{{ 0|filesizeformat }}", "2.0 kB|-5 Bytes|0 Bytes");
}

test "filesizeformat: a hugely negative number is OutOfRange, not a trap (sweep)" {
    try expectFails("{{ -1e300|filesizeformat }}", error.OutOfRange);
}

test "filesizeformat: huge values stop at the last prefix; non-numbers are errors" {
    try expectOut("{{ (5000000000.0 * 1000000000.0 * 1000000000.0)|filesizeformat }}", "5000.0 YB");
    try expectFails("{{ 'abc'|filesizeformat }}", error.BadArgument);
    try expectFails("{{ none|filesizeformat }}", error.TypeMismatch);
}

// ── wordwrap (Jinja2 test_wordwrap; Python textwrap.wrap) ───────────────────

test "wordwrap: Jinja2 test suite example, width 20" {
    try expectOut("{{ 'Hello!\\nThis is Jinja saying something.'|wordwrap(20) }}", "Hello!\nThis is Jinja saying\nsomething.");
}

test "wordwrap: textwrap rules (whitespace dropped at breaks, blank lines kept)" {
    try expectOut("{{ 'Hello world'|wordwrap(5) }}", "Hello\nworld");
    try expectOut("{{ 'a  b   c'|wordwrap(1, true, '<br>') }}", "a<br>b<br>c");
    try expectOut("{{ 'a\\n\\nb'|wordwrap(10) }}", "a\n\nb");
    try expectOut("{{ 'short'|wordwrap }}", "short");
    try expectOut("{{ ''|wordwrap(5) }}|{{ '   '|wordwrap(5) }}", "|");
}

test "wordwrap: long words break by default and stay whole with break_long_words=false" {
    try expectOut("{{ 'abcdefghij'|wordwrap(4) }}", "abcd\nefgh\nij");
    try expectOut("{{ 'abcdefghij kl'|wordwrap(4, false) }}", "abcdefghij\nkl");
}

test "wordwrap: hyphenated words break after the hyphen unless break_on_hyphens=false" {
    try expectOut("{{ 'well-known fact'|wordwrap(8) }}", "well-\nknown\nfact");
    try expectOut("{{ 'well-known fact'|wordwrap(8, true, none, false) }}", "well-kno\nwn fact");
}

test "wordwrap: widths count code points, not bytes" {
    try expectOut("{{ 'ěščř ěščř'|wordwrap(4) }}", "ěščř\něščř");
}

test "wordwrap: a width below 1 is an error and a huge width is harmless" {
    try expectFails("{{ 'a b'|wordwrap(0) }}", error.BadArgument);
    try expectFails("{{ 'a b'|wordwrap(-3) }}", error.BadArgument);
    try expectOut("{{ 'a b'|wordwrap(9223372036854775807) }}", "a b");
}

test "wordwrap: a hostile wrapstring cannot multiply past the output bound" {
    try expectFails("{{ ('a ' * 1500)|wordwrap(1, true, 'x' * 60000) }}", error.OutOfRange);
}

// ── groupby (Jinja2 docs `groupby`) ─────────────────────────────────────────

const users = "{% set xs = [{'name':'emma','city':'nyc'},{'name':'smith','city':'wa'},{'name':'john','city':'nyc'}] %}";

test "groupby: docs example, sorted by key with member order kept (filters/groupby)" {
    try expectOut(users ++ "{% for c, items in xs|groupby('city') %}{{ c }}: {{ items|map(attribute='name')|join(', ') }};{% endfor %}", "nyc: emma, john;wa: smith;");
}

test "groupby: grouper and list attributes of the namedtuple (docs: `group.grouper`, `group.list`)" {
    try expectOut(users ++ "{% for g in xs|groupby('city') %}{{ g.grouper }}={{ g.list|length }} {% endfor %}", "nyc=2 wa=1 ");
    try expectOut(users ++ "{{ (xs|groupby('city'))|map(attribute='grouper')|join(',') }}", "nyc,wa");
}

test "groupby: dotted and numeric attributes, `default` for missing keys (docs: default parameter)" {
    try expectOut("{% for g in [{'a':{'b':2}},{'a':{'b':1}},{'a':{'b':2}}]|groupby('a.b') %}{{ g.grouper }}:{{ g.list|length }} {% endfor %}", "1:1 2:2 ");
    try expectOut("{% for g in [{'k':'a'},{}]|groupby('k', default='z') %}{{ g.grouper }}:{{ g.list|length }} {% endfor %}", "a:1 z:1 ");
    try expectOut("{% for g in [[1,'x'],[0,'y'],[1,'z']]|groupby(0) %}{{ g.grouper }}:{{ g.list|length }} {% endfor %}", "0:1 1:2 ");
}

test "groupby: case-insensitive grouping by default, case_sensitive=true splits (docs: case_sensitive)" {
    // The grouper is the first member's own value (oracle `s3_groupby_case_insensitive`, SPEC D24).
    try expectOut("{% for g in [{'k':'B'},{'k':'a'},{'k':'A'},{'k':'b'}]|groupby('k') %}[{{ g.grouper }}:{{ g.list|length }}]{% endfor %}", "[a:2][B:2]");
    try expectOut("{% for g in [{'k':'A'},{'k':'a'},{'k':'B'}]|groupby('k') %}{{ g.list|length }} {% endfor %}", "2 1 ");
    try expectOut("{% for g in [{'k':'A'},{'k':'a'},{'k':'B'}]|groupby('k', none, true) %}{{ g.list|length }} {% endfor %}", "1 1 1 ");
}

test "groupby: empty input and keys that do not order" {
    try expectOut("{{ []|groupby('k')|length }}", "0");
    try expectFails("{{ [{'k':1},{'k':'a'}]|groupby('k') }}", error.TypeMismatch);
}

// ── tests ───────────────────────────────────────────────────────────────────

test "sameas: Python `is` on singletons, containers by identity (docs tests/sameas)" {
    try expectOut("{{ none is sameas none }}{{ true is sameas true }}{{ false is sameas none }}{{ false is sameas true }}", "TrueTrueFalseFalse");
    try expectOut("{% set l = [1] %}{{ l is sameas l }}{{ l is sameas [1] }}", "TrueFalse");
    // Empty containers have no distinguishable identity here (SPEC D26).
    try expectOut("{{ {} is sameas {} }}{{ [] is sameas [] }}", "FalseFalse");
}

test "callable: macros are callable, plain values are not (docs tests/callable)" {
    try expectOut("{% macro m() %}{% endmacro %}{{ m is callable }}{{ 1 is callable }}{{ 'x' is callable }}", "TrueFalseFalse");
}

// ── Unicode case mapping (Python str.upper/lower/title/capitalize) ──────────

test "upper/lower: full Unicode mapping, ß -> SS, final sigma" {
    try expectOut("{{ 'ěščř'|upper }}|{{ 'ÉCOLE ŘEČ'|lower }}|{{ 'straße'|upper }}|{{ 'ΑΣ'|lower }}", "ĚŠČŘ|école řeč|STRASSE|ας");
}

test "capitalize and the title filter: Unicode first letter, rest lowered" {
    try expectOut("{{ 'ěščř ŘEČ'|capitalize }}|{{ 'ěščř ŘEČ'|title }}|{{ 'hello-world (x)'|title }}", "Ěščř řeč|Ěščř Řeč|Hello-World (X)");
}

test "title() method follows Python str.title (apostrophe splits a word)" {
    try expectOut("{{ 'hello wörld'.title() }}|{{ \"it's ok\".title() }}", "Hello Wörld|It'S Ok");
}

test "is upper / is lower use Unicode case; case-insensitive filters fold Unicode" {
    try expectOut("{{ 'ĚŠČŘ' is upper }}{{ 'ěščř' is lower }}{{ 'Ěščř' is upper }}{{ '123' is upper }}", "TrueTrueFalseFalse");
    try expectOut("{{ ['É', 'é', 'e']|unique|list|length }}|{{ ['é', 'E', 'ž']|sort|join(',') }}", "2|E,é,ž");
}

test "case mapping keeps ill-formed UTF-8 bytes and markup" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const ctx = try jinja.valueFrom(arena.allocator(), .{ .s = "a\xffb" });
    var env = try jinja.Environment.init(testing.allocator, .{});
    defer env.deinit();
    const out = try env.renderAlloc(testing.allocator, "{{ s|upper }}", ctx, null);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("A\xffB", out);
    try expectOutEsc("{{ '<b>é</b>'|safe|upper }}", "<B>É</B>");
}

// ── no-panic sweep (deterministic PRNG, any error is a fine outcome) ────────

test "format and wordwrap never trip a safety check on random specs and text (sweep)" {
    const pytext = @import("pytext.zig");
    var prng = std.Random.DefaultPrng.init(0x5eed_5ca1e);
    const rnd = prng.random();
    const fmt_alpha = "%%%%%%ds.-+ #0*(x)lhrcefgEFGoXu123456789ab\xc3\xa9\xff";
    const text_alpha = "ab -\t\n\r\x0b\xc2\x85\xe2\x80\xa8-- \xc4\x9b\xff12_.!";
    const vals = [_]jinja.Value{
        .{ .integer = 0 },                     .{ .integer = -9223372036854775807 - 1 },
        .{ .integer = 255 },                   .{ .float = 2.675 },
        .{ .float = std.math.inf(f64) },       .{ .float = -std.math.nan(f64) },
        .{ .float = 1.7976931348623157e308 },  .{ .float = 5e-324 },
        .{ .string = .{ .bytes = "x\xffy" } }, .{ .none = {} },
    };
    var n: usize = 0;
    while (n < 3000) : (n += 1) {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const flen = rnd.uintLessThan(usize, 24);
        const fmt = try a.alloc(u8, flen);
        for (fmt) |*c| c.* = fmt_alpha[rnd.uintLessThan(usize, fmt_alpha.len)];
        var args: [4]jinja.Value = undefined;
        for (&args) |*v| v.* = vals[rnd.uintLessThan(usize, vals.len)];
        _ = pytext.percentFormat(a, fmt, args[0..rnd.uintLessThan(usize, 5)], null, rnd.boolean(), rnd.boolean()) catch {};

        const tlen = rnd.uintLessThan(usize, 80);
        const text = try a.alloc(u8, tlen);
        for (text) |*c| c.* = text_alpha[rnd.uintLessThan(usize, text_alpha.len)];
        _ = pytext.wordwrap(a, text, rnd.intRangeAtMost(i64, -1, 12), rnd.boolean(), "\n", rnd.boolean()) catch {};
        _ = pytext.fileSize(a, @bitCast(rnd.int(u64)), rnd.boolean()) catch {};
    }
}
