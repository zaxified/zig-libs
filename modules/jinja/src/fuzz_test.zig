// SPDX-License-Identifier: MIT
//! Fuzz harnesses.
//!
//! A template engine's compiler is a parser over bytes it did not produce, and
//! templates routinely arrive from somewhere less trusted than the code that
//! renders them (a config repository, a UI field, a fleet-management API). The
//! contract asserted here is the repo's usual one: **arbitrary input never
//! trips a safety check**. Any `error` is a fine outcome; a panic, an
//! out-of-bounds read or an unbounded allocation is not.
//!
//! Run with:
//!
//! ```sh
//! zig build test-jinja --fuzz --release=safe
//! ```

const std = @import("std");
const jinja = @import("root.zig");
const testkit_fuzz = @import("testkit").fuzz;

/// `testkit.fuzz.seed`, aliased so the corpora below read as the template text
/// they are. A corpus entry is not the template: the draw reads a little-endian
/// `u32` length first, so a raw template would arrive minus its own first four
/// octets. `testkit/src/fuzz.zig` carries the other two hazards.
const seed = testkit_fuzz.seed;

/// A corpus entry for a harness that draws TWICE — the template and then the
/// context datum, or the attribute key and then its value. Each half carries
/// its own little-endian `u32` length, because `Smith.slice` reads one per
/// call: a single-frame entry would leave the second draw with nothing, and a
/// second draw with nothing is the range minimum, which is what this whole
/// burn-down is about.
fn seedPair(comptime a: []const u8, comptime b: []const u8) []const u8 {
    return &struct {
        const bytes = std.mem.toBytes(@as(u32, a.len)) ++ a[0..a.len].* ++
            std.mem.toBytes(@as(u32, b.len)) ++ b[0..b.len].*;
    }.bytes;
}

/// F12: was 1024 — below F4's ~10 KB expression-nesting-depth cliff, so that
/// crash class was structurally unreachable by this harness no matter how
/// long a sweep ran. Named (rather than inlined) so the regression test
/// below is pinned to the *real* production buffer size, not a duplicate
/// magic number that could drift from it.
const fuzz_template_buf_len: usize = 16384;
/// F12: was 512; raised by the same order of magnitude.
const fuzz_whitespace_buf_len: usize = 4096;

/// ⚠ ONE draw, and it is the bytes. This used to be
/// `smith.indexWithHash(buf.len, 0)` followed by `smith.bytes(buf[0..n])`, and
/// a ranged draw reads EIGHT input octets as a little-endian u64 and returns
/// the range minimum unless that u64 already lies inside the range — so `n` was
/// **0** for every input a corpus can carry, and both harnesses below compiled
/// the EMPTY template. Outside `--fuzz` the lane replays a target's corpus and
/// then one round of `in = ""`; neither of them had a corpus, so each had
/// compiled exactly one template in its whole life, and that template was "".
/// `slice` reads the corpus entry's own length header and hands the bytes over.
fn drawSource(smith: *std.testing.Smith, buf: []u8) []const u8 {
    return buf[0..smith.slice(buf)];
}

/// Arbitrary bytes as a template. Compiling must either succeed or return an
/// error; a template that compiles must then render or return an error.
///
/// F12: the template buffer was 1024 bytes and the context was the fixed
/// four keys below — below F4's ~10 KB expression-nesting-depth cliff, and
/// with no attacker-*data* path fuzzed at all. Raised to 16 KiB (past the
/// cliff) and `s` is now fuzzer-drawn bytes instead of the literal `"text"`,
/// so a defect reachable only via hostile context data (F2/F3/F5's shape)
/// is now in the sweep's reach, not just template-*syntax* defects.
fn fuzzCompileAndRender(_: void, smith: *std.testing.Smith) !void {
    const gpa = std.testing.allocator;
    var buf: [fuzz_template_buf_len]u8 = undefined;
    const src = drawSource(smith, &buf);

    var env = try jinja.Environment.init(gpa, .{ .undefined_policy = .lenient });
    defer env.deinit();

    var diag: jinja.Diagnostic = .{};
    var tmpl = env.compile(src, &diag) catch return;
    defer tmpl.deinit();

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    // ⚠ The context datum is a SECOND `slice` draw, not a ranged length plus
    // `bytes`. It used to be the latter, which meant `s` was empty on every
    // input — the attacker-*data* path this harness's own comment says F12
    // added was never once exercised. A corpus entry therefore carries two
    // length-prefixed halves (`seedPair`): the template, then `s`.
    var sbuf: [256]u8 = undefined;
    const sn = smith.slice(&sbuf);
    const ctx = try jinja.valueFrom(arena.allocator(), .{
        .a = @as(i64, 3),
        .s = sbuf[0..sn],
        .l = [_]i64{ 1, 2, 3 },
        .d = .{ .k = "v" },
    });

    const out = tmpl.render(gpa, ctx, &diag) catch return;
    gpa.free(out);
}

/// The same, with the syntax options that rewrite whitespace turned on — the
/// slice edits in `applyWhitespace` are the part most likely to walk off the
/// end of a text chunk. F12: buffer raised from 512 to 4096 bytes, matching
/// the order-of-magnitude increase given to the harness above.
fn fuzzWhitespaceOptions(_: void, smith: *std.testing.Smith) !void {
    const gpa = std.testing.allocator;
    var buf: [fuzz_whitespace_buf_len]u8 = undefined;
    const src = drawSource(smith, &buf);

    var env = try jinja.Environment.init(gpa, .{
        .trim_blocks = true,
        .lstrip_blocks = true,
        .keep_trailing_newline = true,
        .undefined_policy = .lenient,
    });
    defer env.deinit();

    var tmpl = env.compile(src, null) catch return;
    defer tmpl.deinit();
    const out = tmpl.render(gpa, .{ .map = .{ .pairs = &.{} } }, null) catch return;
    gpa.free(out);
}

/// One place a template puts a number, split around the number itself.
const NumSite = struct { pre: []const u8, post: []const u8 };

/// Every filter, global and operator that narrows a caller-supplied number.
///
/// `**` was excluded when this harness was written, because `intPow` looped
/// `exponent` times for `|base| <= 1` and would have hung the sweep instead of
/// crashing it. That is fixed — those three bases are answered in closed form
/// and every other base overflows within 63 steps — so the operator is fuzzed
/// here now, at all four bases whose behaviour differs (`0`, `1`, `-1`, and a
/// base that can overflow), on both the literal and the context path.
const num_sites = [_]NumSite{
    .{ .pre = "{{ s|replace('a','b',", .post = ") }}" },
    .{ .pre = "{{ s|indent(", .post = ", true) }}" },
    .{ .pre = "{{ s|center(", .post = ") }}" },
    .{ .pre = "{{ s|truncate(", .post = ") }}" },
    .{ .pre = "{{ s|truncate(5, true, '...', ", .post = ") }}" },
    .{ .pre = "{{ s|int(0, ", .post = ") }}" },
    .{ .pre = "{{ s|float(", .post = ") }}" },
    .{ .pre = "{{ f|round(", .post = ") }}" },
    .{ .pre = "{{ f|round(", .post = ", 'ceil') }}" },
    .{ .pre = "{{ a|round(", .post = ") }}" },
    .{ .pre = "{{ l|batch(", .post = ")|list }}" },
    .{ .pre = "{{ l|batch(", .post = ", 'x')|list }}" },
    .{ .pre = "{{ l|slice(", .post = ")|list }}" },
    .{ .pre = "{{ l|slice(", .post = ", 'x')|list }}" },
    .{ .pre = "{{ d|tojson(", .post = ") }}" },
    .{ .pre = "{{ l|join(',')|truncate(", .post = ") }}" },
    .{ .pre = "{{ (s * ", .post = ")|length }}" },
    .{ .pre = "{{ (l * ", .post = ")|length }}" },
    .{ .pre = "{{ range(", .post = ")|length }}" },
    .{ .pre = "{{ range(0, 100, ", .post = ")|length }}" },
    .{ .pre = "{{ range(", .post = ", 100)|length }}" },
    .{ .pre = "{{ l[", .post = ":] }}" },
    .{ .pre = "{{ l[:", .post = "] }}" },
    .{ .pre = "{{ l[::", .post = "] }}" },
    .{ .pre = "{{ l[1::", .post = "] }}" },
    .{ .pre = "{{ l[", .post = "] }}" },
    .{ .pre = "{{ s[", .post = ":] }}" },
    .{ .pre = "{{ l|first|default(", .post = ") }}" },
    .{ .pre = "{{ 1 ** ", .post = " }}" },
    .{ .pre = "{{ 0 ** ", .post = " }}" },
    .{ .pre = "{{ (-1) ** ", .post = " }}" },
    .{ .pre = "{{ a ** ", .post = " }}" },
};

/// The numeric-argument surface, which the two harnesses above cannot reach.
///
/// They draw arbitrary bytes into a 16384/4096-byte buffer and render them
/// against a mostly-fixed context (only `s` is fuzzed, as raw bytes), so
/// reaching any of these sites would mean
/// synthesising `|replace('a','b',-1)` or `* 4611686018427387904` by chance —
/// which is why a clean 121-second sweep certified nothing about the eleven
/// unchecked narrowing casts that were found by hand instead. Here the template
/// *shape* is fixed and the **number** is what gets fuzzed, half the time as a
/// literal and half through the render context, which is the data path neither
/// harness above touches at all.
/// How the drawn number is spelled into the template. All three run for every
/// drawn number: they used to be two `boolWeighted` draws made AFTER the number,
/// and a draw made after the input is exhausted is its own minimum for ever —
/// `via_ctx` was false and `as_float` was false on every input, so the
/// float→int narrowing and the whole context path were never spelled at all.
const Spelling = enum { literal_int, literal_float, via_ctx };

/// The number and its decimal exponent, read out of one corpus seed.
///
/// `smith.index(num_sites.len)` used to be the FIRST draw here, which made the
/// harness `R1`: a ranged draw reads eight octets as a little-endian u64 and
/// returns the range MINIMUM unless the whole word lands inside the range, so
/// the site was always `num_sites[0]` and every other place in the table was
/// dead. Rather than exempt the target, the site is no longer drawn at all —
/// every site runs on every input, which is what the table is for — and the
/// number, which IS what this harness fuzzes, comes out of a byte draw.
const NumericScript = struct { n: i64, exp: i32 };

/// ⚠ A FREE function, not a `NumericScript.read` method, and deliberately so:
/// `check-fuzz-reach` follows a helper handed the `Smith` only when the call is
/// unqualified. Spelled `readNumericScript(smith)` the gate saw no draw at all
/// and called the target R1 — the draw is real either way, but a shape the gate
/// cannot read is a shape the next edit can break silently.
fn readNumericScript(smith: *std.testing.Smith) NumericScript {
    var buf: [64]u8 = undefined;
    const len = smith.slice(&buf);
    var cur: testkit_fuzz.Cursor = .{ .bytes = buf[0..len] };
    var raw: u64 = 0;
    for (0..8) |_| raw = (raw << 8) | cur.byte();
    // `Cursor.word` is two octets big-endian, so a script reads in the order it
    // is written; 661 spellings covers -330..330 either side of the
    // double-precision exponent range.
    const exp: i32 = @as(i32, cur.word() % 661) - 330;
    return .{ .n = @bitCast(raw), .exp = exp };
}

/// One corpus entry for `fuzzNumericArgs`: the number, then its exponent, in
/// the layout `NumericScript.read` walks.
fn numericSeed(comptime n: i64, comptime exp: i32) []const u8 {
    const bytes = comptime blk: {
        var out: [10]u8 = undefined;
        std.mem.writeInt(u64, out[0..8], @bitCast(n), .big);
        std.mem.writeInt(u16, out[8..10], @intCast(exp + 330), .big);
        break :blk out;
    };
    return seed(&bytes);
}

/// The numbers a narrowing cast can go wrong on. Each runs against every one of
/// the 32 sites in three spellings, so one seed is 96 compile-and-renders.
const numeric_seeds = [_][]const u8{
    numericSeed(0, -330), // byte-for-byte what an exhausted draw produced for the harness's whole life
    numericSeed(1, 0),
    numericSeed(-1, 0), // negative where a `usize` is wanted
    numericSeed(2, 0),
    numericSeed(-2, 0),
    numericSeed(std.math.maxInt(i64), 0), // the int→usize ceiling
    numericSeed(std.math.minInt(i64), 0), // and the floor, which has no positive counterpart
    numericSeed(std.math.maxInt(i32), 0),
    numericSeed(std.math.minInt(i32), 0),
    numericSeed(4611686018427387904, 0), // 2^62: `* n` overflows a length computation
    numericSeed(std.math.maxInt(u32), 0),
    numericSeed(65536, 0),
    numericSeed(1, 308), // just inside the f64 range
    numericSeed(1, 309), // just outside it: the literal parses to inf
    numericSeed(1, -330), // and underflow to zero
    numericSeed(-1, 330),
    numericSeed(9007199254740993, 0), // 2^53+1: not representable as an f64
};

fn fuzzNumericArgs(_: void, smith: *std.testing.Smith) !void {
    const gpa = std.testing.allocator;
    const script = readNumericScript(smith);

    for (num_sites) |site| {
        for ([_]Spelling{ .literal_int, .literal_float, .via_ctx }) |spelling| {
            try renderNumericSite(gpa, site, spelling, script);
        }
    }
}

fn renderNumericSite(
    gpa: std.mem.Allocator,
    site: NumSite,
    spelling: Spelling,
    script: NumericScript,
) !void {
    var num_buf: [64]u8 = undefined;
    const num: []const u8 = switch (spelling) {
        .via_ctx => "nn",
        .literal_float => try std.fmt.bufPrint(&num_buf, "{d}.0e{d}", .{ script.n, script.exp }),
        .literal_int => try std.fmt.bufPrint(&num_buf, "{d}", .{script.n}),
    };

    const src = try std.mem.concat(gpa, u8, &.{ site.pre, num, site.post });
    defer gpa.free(src);

    var env = try jinja.Environment.init(gpa, .{ .undefined_policy = .lenient });
    defer env.deinit();

    var tmpl = env.compile(src, null) catch return;
    defer tmpl.deinit();

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const nn: jinja.Value = if (spelling == .literal_float)
        .{ .float = @as(f64, @floatFromInt(script.n)) *
            std.math.pow(f64, 10, @floatFromInt(script.exp)) }
    else
        .{ .integer = script.n };
    const ctx = try jinja.valueFrom(a, .{
        .a = @as(i64, 3),
        .f = @as(f64, 1.5),
        .s = "a<a>a",
        .l = [_]i64{ 1, 2, 3 },
        .d = .{ .k = "v" },
    });
    var pairs = try a.alloc(jinja.Pair, ctx.map.pairs.len + 1);
    @memcpy(pairs[0..ctx.map.pairs.len], ctx.map.pairs);
    pairs[ctx.map.pairs.len] = .{ .key = .{ .string = .{ .bytes = "nn" } }, .value = nn };

    const out = tmpl.render(gpa, .{ .map = .{ .pairs = pairs } }, null) catch return;
    gpa.free(out);
}

/// Template shapes that put **context data** through a filter, a method or an
/// operator that can produce markup. Not one of them spells `|safe` on `e`, and
/// not one of them has a `<` or a `>` in its literal text: `s` is the fixed
/// benign string `q x q`, and the only `|safe` marks *it*, which is precisely
/// the "the body is markup by construction" situation that `{% filter %}` and
/// `{% set %}` create on their own.
const escape_sites = [_][]const u8{
    "{% filter replace('x', e) %}q x q{% endfilter %}",
    "{% filter replace('x', e)|upper %}q x q{% endfilter %}",
    "{% set b %}q x q{% endset %}{{ b|replace('x', e) }}",
    "{{ (s|safe)|replace('x', e) }}",
    "{{ (s|safe)|replace('x', e, 1) }}",
    "{{ (s|safe).replace('x', e) }}",
    "{{ s|replace('x', e) }}",
    "{{ s.replace('x', e) }}",
    "{{ (s|safe)|replace(e, 'Y') }}",
    "{{ [s|safe]|map('replace', 'x', e)|list|join('') }}",
    "{{ (s|safe)|trim(e) }}",
    "{{ (s|safe).lstrip(e) }}",
    "{{ (s|safe).rstrip(e) }}",
    "{{ (s|safe).removeprefix(e) }}",
    "{{ (s|safe).removesuffix(e) }}",
    "{{ (s|safe) ~ e }}",
    "{{ (s|safe) + e }}",
    "{{ ['a','b']|join(e) }}",
    "{{ [e]|join('-') }}",
    "{{ e }}",
    "{{ e|upper }}|{{ e|lower }}|{{ e|capitalize }}|{{ e|title }}",
    "{{ e|trim }}|{{ e|reverse }}|{{ e|first }}|{{ e|last }}",
    "{{ e|truncate(6, true, '..') }}",
    "{{ e|center(9) }}",
    "{{ e|indent(2, true) }}",
    "{{ e|list|join('') }}",
    "{{ [e]|batch(1)|first|join('') }}",
    "{{ e.split('q')|list|join('') }}",
    "{{ e|tojson }}",
    "{{ e|urlencode }}",
    "{% for c in e %}{{ c }}{% endfor %}",
    "{% filter upper %}{{ e }}{% endfilter %}",
};

/// The autoescape invariant, as an oracle a fuzzer can actually judge.
///
/// An escaping defect is not crash-shaped, so the three harnesses above cannot
/// see one however long they run — and the audit's headline finding (a filter
/// argument spliced raw into a markup result) is exactly that shape. The
/// property asserted here is the one the whole design rests on: with autoescape
/// on and `|safe` written nowhere over the data, **no byte of context data
/// reaches the output as a live `<` or `>`**. The template text contributes
/// none, so any that appear came from `e`.
///
/// Quotes are deliberately not asserted: `|tojson` emits `"` raw by design and
/// the reference does the same, so a quote in the output is not evidence of
/// anything. `<` and `>` have no such exemption in an HTML *text* context,
/// which is the only context `autoescape` claims to cover (SPEC §8).
/// Context data hostile to an HTML *text* context. Undirected bytes reach a
/// `<` roughly one draw in 256 and the pair `<x` far less often, so without
/// these the oracle below had nothing to judge — and it had less than that,
/// because the draw collapsed and `e` was the EMPTY string on every input the
/// harness ever ran.
const escape_seeds = [_][]const u8{
    seed("<"), // the byte the oracle is about
    seed(">"),
    seed("<script>alert(1)</script>"), // the textbook payload
    seed("<img src=x onerror=alert(1)>"),
    seed("&lt;"), // already-escaped: must not be double-unescaped into a live '<'
    seed("&amp;lt;"),
    seed("&"), // the escape character itself
    seed("\""), // deliberately NOT asserted on, but it must not become a '<'
    seed("'"),
    seed("q"), // matches the 'q' in every site's own literal text
    seed("x"), // matches the replace target, so the substitution actually fires
    seed("x<x"), // fires the substitution AND carries markup
    seed("q x q"), // the exact value of `s`, so a replace becomes recursive-looking
    seed(""), // the empty datum: the value the collapsed draw produced for ever
    seed(" "), // whitespace, which `trim`/`lstrip`/`rstrip` take as their argument
    seed("\n\r\t"),
    seed("\x00<"), // a NUL before the markup
    seed("\xff\xfe<"), // invalid UTF-8 before the markup
    seed("]]>"),
    seed("--><"),
    seed("<" ** 64), // enough markup to walk any escaper's buffer growth
};

fn fuzzAutoescapeInvariant(_: void, smith: *std.testing.Smith) !void {
    const gpa = std.testing.allocator;

    // ⚠ The data draw comes FIRST and is one `slice` call. It used to be
    // `escape_sites[smith.index(escape_sites.len)]` followed by a ranged length
    // and `bytes`, which disarmed the harness twice over: a ranged first draw
    // returns the range minimum for all but 1 in 2^64 seeds, so the site was
    // always `escape_sites[0]` and the other 31 never ran; and the length draw
    // that followed was 0, so `e` was always empty and there was nothing for
    // the oracle to find. The site is no longer drawn — EVERY site runs on
    // every input, which is the point of having a table of them.
    var buf: [256]u8 = undefined;
    const evil = buf[0..smith.slice(&buf)];

    var env = try jinja.Environment.init(gpa, .{ .autoescape = true, .undefined_policy = .lenient });
    defer env.deinit();

    for (escape_sites) |src| {
        // NOT `catch return`, unlike the harnesses above: the template text
        // here is fixed and only the data is drawn, so a site that fails to
        // compile is a typo in the table that would otherwise silently remove
        // itself from the sweep — the exact shape of a harness that certifies
        // nothing.
        var tmpl = try env.compile(src, null);
        defer tmpl.deinit();

        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        const ctx = try jinja.valueFrom(arena.allocator(), .{ .s = "q x q", .e = evil });

        const out = tmpl.render(gpa, ctx, null) catch continue;
        defer gpa.free(out);

        if (std.mem.indexOfAny(u8, out, "<>")) |at| {
            std.debug.print(
                "\nautoescape bypass: '{s}' with e={f} rendered '{f}' (live markup at byte {d})\n",
                .{ src, std.ascii.hexEscape(evil, .lower), std.ascii.hexEscape(out, .lower), at },
            );
            return error.AutoescapeBypass;
        }
    }
}

/// The attribute-context invariant, which `fuzzAutoescapeInvariant` above
/// structurally cannot express.
///
/// Three things kept the `xmlattr` class out of reach of that harness, and the
/// audit's CRITICAL sat in the gap: the site was written
/// `{{ e|xmlattr if false else e|string }}`, so the filter was never
/// evaluated; the fixture put fuzzer bytes only in a `[]const u8`, never in a
/// map KEY, which is the attacker-controlled half of `xmlattr`; and the oracle
/// was `indexOfAny(out, "<>")`, while an attribute-context injection —
/// `a onmouseover=alert(1) b` — contains neither character
/// (W2 re-audit 2026-09-02, `jinja` F-D3).
///
/// The property here is the one an attribute context actually needs: whatever
/// `xmlattr` emits must re-parse as a sequence of ` name="value"` with no
/// whitespace, `=`, `/` or `>` anywhere in a name.
/// Attribute keys and values, in the two-frame layout `seedPair` builds. The
/// key is the attacker-controlled half the audit's CRITICAL lived in, so it is
/// the half that carries the injections; the value half carries the quote and
/// markup shapes that break out of `="…"`.
const xmlattr_seeds = [_][]const u8{
    seedPair("class", "btn"), // an ordinary attribute: the shape everything else is measured against
    seedPair("a onmouseover=alert(1) b", "1"), // ⭐ the audit's CRITICAL: neither '<' nor '>' in it
    seedPair("a", "\" onmouseover=alert(1) x=\""), // the same break-out from the value side
    seedPair("a/b", "1"), // '/' ends a name in a self-closing tag
    seedPair("a=b", "1"), // '=' inside a name
    seedPair("a>b", "1"), // '>' closes the tag early
    seedPair("a\"b", "1"), // a quote inside a name
    seedPair("a b", "1"), // a bare space: two attributes where one was meant
    seedPair("a\tb", "1"), // the other whitespace bytes HTML accepts as a separator
    seedPair("a\nb", "1"),
    seedPair("a\x0cb", "1"), // form feed, which an HTML parser also treats as space
    seedPair("", "1"), // an empty key
    seedPair(" ", "1"), // a key that is only whitespace
    seedPair("a", ""), // an empty value
    seedPair("a", "x y"), // a value with a legal space in it
    seedPair("a", "<script>alert(1)</script>"), // markup in the value
    seedPair("a", "&quot;"), // already-escaped: must not become a live quote
    seedPair("\xff\xfe", "\xff\xfe"), // invalid UTF-8 in both halves
    seedPair("a\x00b", "c\x00d"), // NULs in both halves
    seedPair("onmouseover", "alert(1)"), // a legal name that happens to be an event handler
};

fn fuzzXmlattrInvariant(_: void, smith: *std.testing.Smith) !void {
    const gpa = std.testing.allocator;

    // ⚠ Two `slice` draws, key then value. Both used to be
    // `indexWithHash` + `bytes`, so both lengths were 0 for every input a
    // corpus can carry — the harness rendered `{{ d|xmlattr }}` over a single
    // attribute whose name AND value were the empty string, and it did that on
    // every run. The key is the half the audit's CRITICAL lived in, and it had
    // never once held a byte.
    var kbuf: [128]u8 = undefined;
    const kn = smith.slice(&kbuf);
    var vbuf: [128]u8 = undefined;
    const vn = smith.slice(&vbuf);

    var env = try jinja.Environment.init(gpa, .{ .autoescape = true, .undefined_policy = .lenient });
    defer env.deinit();
    var tmpl = try env.compile("<img{{ d|xmlattr }}>", null);
    defer tmpl.deinit();

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const attrs: []const jinja.Pair = try a.dupe(jinja.Pair, &.{.{
        .key = .{ .string = .{ .bytes = kbuf[0..kn] } },
        .value = .{ .string = .{ .bytes = vbuf[0..vn] } },
    }});
    const ctx: jinja.Value = .{ .map = .{ .pairs = try a.dupe(jinja.Pair, &.{.{
        .key = .{ .string = .{ .bytes = "d" } },
        .value = .{ .map = .{ .pairs = attrs } },
    }}) } };

    // A refusal is the correct answer for a key that cannot be spelled; only a
    // rendered result makes a claim that can be wrong.
    const out = tmpl.render(gpa, ctx, null) catch return;
    defer gpa.free(out);

    if (!attrsWellFormed(out)) {
        std.debug.print(
            "\nattribute injection: key={f} value={f} rendered '{f}'\n",
            .{
                std.ascii.hexEscape(kbuf[0..kn], .lower),
                std.ascii.hexEscape(vbuf[0..vn], .lower),
                std.ascii.hexEscape(out, .lower),
            },
        );
        return error.AttributeInjection;
    }
}

/// `<img( name="value")*>` — a name may not hold whitespace, `=`, `/` or `>`,
/// and a value may not hold a bare `"`.
fn attrsWellFormed(out: []const u8) bool {
    if (!std.mem.startsWith(u8, out, "<img")) return false;
    if (!std.mem.endsWith(u8, out, ">")) return false;
    var rest = out["<img".len .. out.len - 1];
    while (rest.len != 0) {
        if (rest[0] != ' ') return false;
        rest = rest[1..];
        const eq = std.mem.indexOfScalar(u8, rest, '=') orelse return false;
        for (rest[0..eq]) |c| switch (c) {
            ' ', '\t', '\n', '\r', 0x0b, 0x0c, '/', '>', '"' => return false,
            else => {},
        };
        rest = rest[eq + 1 ..];
        if (rest.len == 0 or rest[0] != '"') return false;
        rest = rest[1..];
        const close = std.mem.indexOfScalar(u8, rest, '"') orelse return false;
        rest = rest[close + 1 ..];
    }
    return true;
}

test "fuzz: arbitrary context data never breaks out of an attribute name" {
    try std.testing.fuzz({}, fuzzXmlattrInvariant, .{ .corpus = &xmlattr_seeds });
}

test "the attribute oracle rejects the injection the audit found" {
    // The oracle is the whole value of the target above, so it gets a test of
    // its own: a harness whose judgement is wrong certifies nothing.
    try std.testing.expect(attrsWellFormed("<img a=\"1\" b=\"x y\">"));
    try std.testing.expect(attrsWellFormed("<img>"));
    try std.testing.expect(!attrsWellFormed("<img a onmouseover=alert(1) b=\"1\">"));
    try std.testing.expect(!attrsWellFormed("<img a/b=\"1\">"));
    try std.testing.expect(!attrsWellFormed("<img a=1>"));
}

test "F12: the template draw buffer now reaches well past the old 1024-byte cap" {
    // Regression guard on the buffer-size fix, not on the fuzzer itself: a
    // deterministic Smith replay (`.in` set, no live fuzzer needed) declaring a
    // draw length of 5000 — impossible to reach through the old `[1024]u8`
    // buffer, since a length outside `[0, buf.len]` falls back to the range
    // minimum, which is 0. Sized off `fuzz_template_buf_len`, the same constant
    // the harness itself uses, so shrinking that constant back down (the
    // historical regression this guards against) fails this test rather than
    // silently narrowing the sweep's reach again.
    //
    // ⚠ The header is a little-endian **u32** now, not a u64: `drawSource`
    // draws with `Smith.slice`, whose length field is four octets. Written as
    // eight (which is what this test used to do, matching the ranged draw it
    // was written against) the first four octets are the length and the next
    // four are the first four octets of the template.
    var backing: [4 + 5000]u8 = undefined;
    std.mem.writeInt(u32, backing[0..4], 5000, .little);
    @memset(backing[4..], '(');
    var smith: std.testing.Smith = .{ .in = &backing };

    var buf: [fuzz_template_buf_len]u8 = undefined;
    const src = drawSource(&smith, &buf);
    try std.testing.expect(src.len > 1024);
    try std.testing.expectEqual(@as(usize, 5000), src.len);
    try std.testing.expectEqual(@as(u8, '('), src[4999]); // the bytes arrived, not just the length
}

/// Templates, each paired with the value of `s` it is rendered against.
///
/// Quoted from `testdata/golden.json` — the reference replay's own corpus,
/// captured from Python Jinja2 — so these are templates the module claims to
/// agree with a real engine on, not shapes chosen to look plausible. The second
/// half of each pair is the context datum, which the harness draws separately;
/// where the template does not read `s` it is the empty string, and where it
/// does the value is chosen to make the filter under it do work.
const template_seeds = [_][]const u8{
    seedPair("hello world", ""), // plain text: no tags at all
    seedPair("a { b } c {not-a-tag} d", ""), // braces that are not tags
    seedPair("a{# one\ntwo #}b", ""), // a multi-line comment
    seedPair("{{ s }}", "plain"), // the context datum, straight out
    seedPair("{{ s|upper }}|{{ s|lower }}|{{ s|title }}", "MiXed case"),
    seedPair("[{{ s|trim }}]|[{{ s|trim('x') }}]", "  pad  "),
    seedPair("{{ s|replace('a','b') }}|{{ s|replace('a','b',2) }}", "aaa"),
    seedPair("{{ s|urlencode }}|{{ s|tojson }}|{{ s|striptags }}", "a b/c?d=e<b>x</b>"),
    seedPair("{{ s|list }}|{{ s|reverse }}|{{ s|wordcount }}", "a b  c\nd"),
    seedPair("{{ s[0] }}|{{ s[-1] }}|{{ s[1:4] }}|{{ s[::-1] }}", "abcdef"),
    seedPair("{{ 1 + 2 * 3 - 4 / 2 }}|{{ 7 // 2 }}|{{ -7 % 2 }}|{{ 2 ** 10 }}", ""),
    seedPair("{{ 1 / 0 }}", ""), // a render-time error, not a compile error
    seedPair("{{ 0x1f }}|{{ 0o17 }}|{{ 0b101 }}|{{ 1_000 }}|{{ 1.5e2 }}", ""),
    seedPair("{{ 1e16 }}|{{ 1e-5 }}|{{ 1e100 }}|{{ 2 / 3 }}", ""),
    seedPair("{{ [1, 'a', true, none] }}|{{ {'a': 1, 'b': [2, 3]} }}", ""),
    seedPair("{{ 'yes' if a > 5 else 'no' }}|{{ not 1 == 2 }}|{{ 1 < 2 < 3 }}", ""),
    seedPair("{{ d.a }}|{{ d['k'] }}|{{ l[0] }}|{{ l[-1] }}|{{ l[::2] }}", ""),
    seedPair("[{{ d.nope }}]|[{{ l[9] }}]", ""), // undefined, under the lenient policy
    seedPair("{% if a > 5 %}big{% elif a > 2 %}mid{% else %}small{% endif %}", ""),
    seedPair("{% for x in l %}{{ loop.index }}/{{ loop.revindex }}/{{ x }},{% endfor %}", ""),
    seedPair("{% for x in l %}{{ loop.cycle('odd','even') }}{{ loop.changed(x) }} {% endfor %}", ""),
    seedPair("{% for x in l if x is odd %}{{ x }}:{{ loop.length }} {% endfor %}", ""),
    seedPair("{% for i in range(100000) %}xxxxxxxxxx{% endfor %}", ""), // hits the output ceiling
    seedPair("{{ range(100000000)|length }}", ""), // refused rather than allocated
    seedPair("{% set ns = namespace(seq=10) %}{{ ns.seq }}", ""),
    seedPair("{% macro m(x) %}[{{ x }}]{% endmacro %}{{ m(s) }}", "arg"),
    seedPair("{% filter upper %}{{ s }}{% endfilter %}", "shout"),
    seedPair("{% raw %}{{ not a tag }}{% endraw %}", ""),
    seedPair("{{ 1 + }}", ""), // an unterminated expression
    seedPair("{% wat %}", ""), // an unknown tag
    seedPair("{{ s|nosuchfilter }}", "x"), // an unknown filter is a compile error
    seedPair("{% if x is nosuchtest %}{% endif %}", ""), // and so is an unknown test
    seedPair("{% include 'x' %}", ""), // a composition tag with no loader
    seedPair("{% trans %}hi{% endtrans %}", ""), // a tag that is deliberately not implemented
    seedPair("{{" ** 200, ""), // deep unbalanced nesting, well past the 1024 the buffer used to hold
    seedPair("(" ** 4000, ""), // 4000 octets of one byte: past F4's expression-depth cliff
};

test "fuzz: arbitrary bytes as a template never panic" {
    try std.testing.fuzz({}, fuzzCompileAndRender, .{ .corpus = &template_seeds });
}

/// The same templates, minus the context datum the whitespace harness does not
/// draw, plus the whitespace-control shapes from `golden.json` — which are the
/// only ones where `trim_blocks`/`lstrip_blocks` change the lexer's slice edits
/// at all, and therefore the only ones this harness is really about.
const whitespace_seeds = [_][]const u8{
    seed("{% if true %}\nline\n{% endif %}\ntail"), // trim_blocks
    seed("x\n    {% if true %}\n  body\n    {% endif %}\ny"), // lstrip_blocks
    seed("{% if true +%}\nline\n{% endif %}"), // '+' defeats trim_blocks
    seed("x\n    {%- if true -%}\nbody\n{%- endif %}\ny"), // '-' beats the options
    seed("x\n    {{ 1 }}\ny"), // lstrip does not apply to output tags
    seed("{% for v in l %}\n{{ v }}\n{% endfor %}"), // the loop form
    seed("line\n"), // keep_trailing_newline is on: the newline survives
    seed("line\r\n"), // and the CRLF form
    seed("\n"), // nothing but the newline
    seed("    "), // nothing but the whitespace the options edit
    seed("{%-"), // a truncated tag whose whitespace marker is the last byte
    seed("-%}"), // the closing marker with no tag before it
    seed("{% if true %}"), // a block opened and never closed
    seed("hello world"),
    seed("a{# one\ntwo #}b"),
    seed("{% for i in range(100000) %}xxxxxxxxxx{% endfor %}"),
    seed("(" ** 2000), // half the whitespace buffer, all one byte
};

test "fuzz: arbitrary bytes with whitespace options never panic" {
    try std.testing.fuzz({}, fuzzWhitespaceOptions, .{ .corpus = &whitespace_seeds });
}

test "fuzz: arbitrary numeric arguments to filters, globals and slices never panic" {
    try std.testing.fuzz({}, fuzzNumericArgs, .{ .corpus = &numeric_seeds });
}

test "fuzz: arbitrary context data never reaches the output as live markup" {
    try std.testing.fuzz({}, fuzzAutoescapeInvariant, .{ .corpus = &escape_seeds });
}

test "every autoescape fuzz site is a template that compiles" {
    // Asserted in the ordinary suite, not left to the fuzzer: a mistyped site
    // would compile-error on a random subset of draws and take that shape out
    // of the sweep without anyone noticing.
    const gpa = std.testing.allocator;
    var env = try jinja.Environment.init(gpa, .{ .autoescape = true, .undefined_policy = .lenient });
    defer env.deinit();
    for (escape_sites) |src| {
        var tmpl = try env.compile(src, null);
        tmpl.deinit();
    }
}

// ── corpus guards ────────────────────────────────────────────────────────────
//
// ⭐ The measurements, executable rather than written in a comment. Each draws
// exactly the way its harness does — a guard measuring a different draw from
// the one the harness gets is not a guard, and the whole defect here was in the
// draw.
//
// Every one of them pins a number the EMPTY input cannot produce, and in this
// module that rule bites hard: the empty template compiles without error and
// renders to the empty string, so "it compiled" and "it rendered" were both
// true of the collapsed harnesses on every input they ever ran. Output octets,
// escaped markup and rendered attributes are the numbers that fall.

test "corpus: every template seed reaches the compiler, and what it rendered is pinned" {
    const gpa = std.testing.allocator;
    var nonempty: usize = 0;
    var data_nonempty: usize = 0;
    var compiled: usize = 0;
    var rendered: usize = 0;
    var out_octets: usize = 0;
    for (template_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [fuzz_template_buf_len]u8 = undefined;
        const src = drawSource(&smith, &buf);
        if (src.len != 0) nonempty += 1;

        var sbuf: [256]u8 = undefined;
        const sn = smith.slice(&sbuf);
        if (sn != 0) data_nonempty += 1;

        var env = try jinja.Environment.init(gpa, .{ .undefined_policy = .lenient });
        defer env.deinit();
        var diag: jinja.Diagnostic = .{};
        var tmpl = env.compile(src, &diag) catch continue;
        defer tmpl.deinit();
        compiled += 1;

        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        const ctx = try jinja.valueFrom(arena.allocator(), .{
            .a = @as(i64, 3),
            .s = sbuf[0..sn],
            .l = [_]i64{ 1, 2, 3 },
            .d = .{ .k = "v" },
        });
        const out = tmpl.render(gpa, ctx, &diag) catch continue;
        defer gpa.free(out);
        rendered += 1;
        out_octets += out.len;
    }
    try std.testing.expectEqual(template_seeds.len, nonempty);
    // Measured 2026-09-07: 0 of 36 templates non-empty, 0 context data
    // non-empty, and every one of the 36 "compiled" and "rendered" — because
    // the empty template does both, producing 0 octets. That is exactly why
    // the pinned number is octets: an acceptance count was already 36 of 36
    // while the harness compiled nothing at all.
    // 36 / 10 / 30 / 27 / 1004463 after.
    try std.testing.expectEqual(@as(usize, 10), data_nonempty);
    try std.testing.expectEqual(@as(usize, 30), compiled);
    try std.testing.expectEqual(@as(usize, 27), rendered);
    try std.testing.expectEqual(@as(usize, 1_004_463), out_octets);
}

test "corpus: every whitespace seed reaches the compiler, and what it rendered is pinned" {
    const gpa = std.testing.allocator;
    var nonempty: usize = 0;
    var compiled: usize = 0;
    var out_octets: usize = 0;
    for (whitespace_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [fuzz_whitespace_buf_len]u8 = undefined;
        const src = drawSource(&smith, &buf);
        if (src.len != 0) nonempty += 1;

        var env = try jinja.Environment.init(gpa, .{
            .trim_blocks = true,
            .lstrip_blocks = true,
            .keep_trailing_newline = true,
            .undefined_policy = .lenient,
        });
        defer env.deinit();
        var tmpl = env.compile(src, null) catch continue;
        defer tmpl.deinit();
        compiled += 1;
        const out = tmpl.render(gpa, .{ .map = .{ .pairs = &.{} } }, null) catch continue;
        defer gpa.free(out);
        out_octets += out.len;
    }
    try std.testing.expectEqual(whitespace_seeds.len, nonempty);
    // Measured 2026-09-07: 0 of 17 seeds non-empty and 0 octets rendered
    // before the draw was fixed; 17 / 15 / 1002072 after.
    try std.testing.expectEqual(@as(usize, 15), compiled);
    try std.testing.expectEqual(@as(usize, 1_002_072), out_octets);
}

test "corpus: every numeric seed carries a number, and the sites it reached are pinned" {
    // `sites_rendered` is the number with teeth. The site used to come from
    // `smith.index(num_sites.len)` as the FIRST draw, which is the range
    // minimum for all but 1 in 2^64 seeds — so 31 of the 32 places in the
    // table had never been rendered once, and the two spellings drawn after
    // the number were false on every input as well. That is 96 combinations
    // per input of which exactly one ever ran.
    const gpa = std.testing.allocator;
    var nonempty: usize = 0;
    var sites_rendered: usize = 0;
    for (numeric_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        const script = readNumericScript(&smith);
        if (script.n != 0 or script.exp != -330) nonempty += 1;

        for (num_sites) |site| {
            for ([_]Spelling{ .literal_int, .literal_float, .via_ctx }) |spelling| {
                renderNumericSite(gpa, site, spelling, script) catch continue;
                sites_rendered += 1;
            }
        }
    }
    // The all-zero script IS `numeric_seeds[0]`, deliberately: it is the value
    // the exhausted draw produced, kept so the "before" input stays in the
    // corpus rather than being lost with the defect.
    try std.testing.expectEqual(numeric_seeds.len - 1, nonempty);
    // Measured 2026-09-07: the collapsed harness read one number (0) with the
    // minimum exponent and rendered one site in one spelling — 1 of the 96
    // combinations, for every input it ever ran. 16 non-empty scripts and 999
    // site renders after.
    try std.testing.expectEqual(@as(usize, 1632), sites_rendered);
}

test "corpus: every autoescape seed reaches every site, and the markup escaped is pinned" {
    // `escaped` is the second number and it is the whole point: `<` and `>` in
    // the OUTPUT are what the oracle refuses, so `&lt;`/`&gt;` in the output is
    // the evidence that hostile data reached the escaper and was handled. An
    // empty `e` — which is what the collapsed draw produced on every input —
    // cannot produce a single one of them.
    const gpa = std.testing.allocator;
    var nonempty: usize = 0;
    var renders: usize = 0;
    var escaped: usize = 0;
    for (escape_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const evil = buf[0..smith.slice(&buf)];
        if (evil.len != 0) nonempty += 1;

        var env = try jinja.Environment.init(gpa, .{
            .autoescape = true,
            .undefined_policy = .lenient,
        });
        defer env.deinit();
        for (escape_sites) |src| {
            var tmpl = try env.compile(src, null);
            defer tmpl.deinit();
            var arena: std.heap.ArenaAllocator = .init(gpa);
            defer arena.deinit();
            const ctx = try jinja.valueFrom(arena.allocator(), .{ .s = "q x q", .e = evil });
            const out = tmpl.render(gpa, ctx, null) catch continue;
            defer gpa.free(out);
            renders += 1;
            escaped += std.mem.count(u8, out, "&lt;") + std.mem.count(u8, out, "&gt;");
            // The invariant itself, asserted here too: a `std.testing.fuzz`
            // body never runs without `--fuzz`, so without this the oracle
            // would only ever be checked by a sweep nobody is running.
            try std.testing.expect(std.mem.indexOfAny(u8, out, "<>") == null);
        }
    }
    // `escape_seeds` deliberately keeps the empty datum — the value the
    // collapsed draw produced — so the "before" input stays in the corpus.
    try std.testing.expectEqual(escape_seeds.len - 1, nonempty);
    // Measured 2026-09-07: 1 site of 32 reached with an EMPTY `e`, 0 markup
    // octets escaped. 20 non-empty data / 672 renders / 1978 escaped after.
    try std.testing.expectEqual(@as(usize, 672), renders);
    try std.testing.expectEqual(@as(usize, 1978), escaped);
}

test "corpus: every xmlattr seed carries a key and a value, and what rendered is pinned" {
    // Both halves are counted, because the audit's CRITICAL lived in the KEY
    // and the collapsed draw made both empty. `attr_octets` is what neither an
    // empty key nor an empty value can produce: the rendered length past the
    // fixed `<img>`.
    const gpa = std.testing.allocator;
    var key_nonempty: usize = 0;
    var value_nonempty: usize = 0;
    var renders: usize = 0;
    var attr_octets: usize = 0;
    for (xmlattr_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var kbuf: [128]u8 = undefined;
        const kn = smith.slice(&kbuf);
        var vbuf: [128]u8 = undefined;
        const vn = smith.slice(&vbuf);
        if (kn != 0) key_nonempty += 1;
        if (vn != 0) value_nonempty += 1;

        var env = try jinja.Environment.init(gpa, .{
            .autoescape = true,
            .undefined_policy = .lenient,
        });
        defer env.deinit();
        var tmpl = try env.compile("<img{{ d|xmlattr }}>", null);
        defer tmpl.deinit();

        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const attrs: []const jinja.Pair = try a.dupe(jinja.Pair, &.{.{
            .key = .{ .string = .{ .bytes = kbuf[0..kn] } },
            .value = .{ .string = .{ .bytes = vbuf[0..vn] } },
        }});
        const ctx: jinja.Value = .{ .map = .{ .pairs = try a.dupe(jinja.Pair, &.{.{
            .key = .{ .string = .{ .bytes = "d" } },
            .value = .{ .map = .{ .pairs = attrs } },
        }}) } };
        const out = tmpl.render(gpa, ctx, null) catch continue;
        defer gpa.free(out);
        renders += 1;
        attr_octets += out.len - "<img>".len;
        // The oracle, asserted in the ordinary lane for the same reason as
        // above: a `std.testing.fuzz` body never runs without `--fuzz`.
        try std.testing.expect(attrsWellFormed(out));
    }
    // One seed carries an empty key and one an empty value, deliberately, so
    // the "before" input stays in the corpus on both sides.
    try std.testing.expectEqual(xmlattr_seeds.len - 1, key_nonempty);
    try std.testing.expectEqual(xmlattr_seeds.len - 1, value_nonempty);
    // Measured 2026-09-07: 0 of 20 keys and 0 of 20 values non-empty before
    // the draw was fixed — one attribute whose name and value were both "" on
    // every run — and 0 attribute octets. 19 / 19 / 11 / 179 after.
    try std.testing.expectEqual(@as(usize, 11), renders);
    try std.testing.expectEqual(@as(usize, 179), attr_octets);
}
