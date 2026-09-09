// SPDX-License-Identifier: MIT
//! Unit tests for the *API* — the parts the conformance corpus cannot reach
//! because the reference implementation has no equivalent: compile-time name
//! resolution, diagnostics, custom filters, the Zig-native context adapter and
//! the output ceiling.
//!
//! Behavioural conformance lives in `corpus.zig` + `reference_test.zig` +
//! `golden_test.zig`; nothing here re-asserts what those cover.

const std = @import("std");
const testing = std.testing;
const jinja = @import("root.zig");

fn renderWith(gpa: std.mem.Allocator, opts: jinja.Options, src: []const u8, ctx: jinja.Value) ![]u8 {
    var env = try jinja.Environment.init(gpa, opts);
    defer env.deinit();
    return env.renderAlloc(gpa, src, ctx, null);
}

test "valueFrom maps a Zig struct in field order" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const ctx = try jinja.valueFrom(arena.allocator(), .{
        .name = "Gi0/1",
        .vlans = [_]u16{ 10, 20 },
        .up = true,
        .mtu = @as(?u32, null),
    });
    const out = try renderWith(gpa, .{}, "{{ name }} {{ vlans|join(',') }} {{ up }} {{ mtu }}", ctx);
    defer gpa.free(out);
    try testing.expectEqualStrings("Gi0/1 10,20 True None", out);
}

test "valueFrom keeps struct field order in the rendered mapping" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const ctx = try jinja.valueFrom(arena.allocator(), .{ .d = .{ .zeta = 1, .alpha = 2 } });
    const out = try renderWith(gpa, .{}, "{{ d }}", ctx);
    defer gpa.free(out);
    try testing.expectEqualStrings("{'zeta': 1, 'alpha': 2}", out);
}

test "an unknown filter is a COMPILE error, never a render-time surprise" {
    const gpa = testing.allocator;
    var env = try jinja.Environment.init(gpa, .{});
    defer env.deinit();
    var diag: jinja.Diagnostic = .{};
    try testing.expectError(error.TemplateSyntaxError, env.compile("{{ x|nosuchfilter }}", &diag));
    try testing.expect(std.mem.indexOf(u8, diag.message(), "unknown filter") != null);
}

test "an unknown test is a compile error too" {
    const gpa = testing.allocator;
    var env = try jinja.Environment.init(gpa, .{});
    defer env.deinit();
    try testing.expectError(error.TemplateSyntaxError, env.compile("{% if x is nosuchtest %}{% endif %}", null));
}

test "the tags that remain unimplemented are named as such, not as typos" {
    const gpa = testing.allocator;
    var env = try jinja.Environment.init(gpa, .{});
    defer env.deinit();
    for ([_][]const u8{
        "{% trans %}hi{% endtrans %}",
        "{% autoescape true %}{% endautoescape %}",
    }) |src| {
        var diag: jinja.Diagnostic = .{};
        try testing.expectError(error.TemplateSyntaxError, env.compile(src, &diag));
        try testing.expect(std.mem.indexOf(u8, diag.message(), "not implemented") != null);
    }
}

test "a composition tag without a loader is a named error, not a silent nothing" {
    const gpa = testing.allocator;
    var env = try jinja.Environment.init(gpa, .{});
    defer env.deinit();
    for ([_][]const u8{
        "{% include 'x' %}",
        "{% import 'x' as m %}",
        "{% extends 'x' %}{% block b %}{% endblock %}",
    }) |src| {
        var diag: jinja.Diagnostic = .{};
        const r = env.renderAlloc(gpa, src, .{ .map = .{ .pairs = &.{} } }, &diag);
        try testing.expectError(error.NoLoader, r);
        try testing.expect(std.mem.indexOf(u8, diag.message(), "no loader") != null);
    }
}

test "diagnostics carry the line the problem is on" {
    const gpa = testing.allocator;
    var env = try jinja.Environment.init(gpa, .{});
    defer env.deinit();
    var diag: jinja.Diagnostic = .{};
    try testing.expectError(error.TemplateSyntaxError, env.compile("a\nb\n{% wat %}\n", &diag));
    try testing.expectEqual(@as(usize, 3), diag.line);
}

test "a render-time diagnostic names the undefined variable" {
    const gpa = testing.allocator;
    var env = try jinja.Environment.init(gpa, .{});
    defer env.deinit();
    var tmpl = try env.compile("x\n{{ missing }}", null);
    defer tmpl.deinit();
    var diag: jinja.Diagnostic = .{};
    try testing.expectError(error.UndefinedValue, tmpl.render(gpa, .{ .map = .{ .pairs = &.{} } }, &diag));
    try testing.expect(std.mem.indexOf(u8, diag.message(), "missing") != null);
}

test "strict is the default undefined policy" {
    const gpa = testing.allocator;
    var env = try jinja.Environment.init(gpa, .{});
    defer env.deinit();
    try testing.expectError(
        error.UndefinedValue,
        env.renderAlloc(gpa, "{{ nope }}", .{ .map = .{ .pairs = &.{} } }, null),
    );
}

test "a caller can register its own filter and test" {
    const gpa = testing.allocator;
    var env = try jinja.Environment.init(gpa, .{});
    defer env.deinit();
    try env.addFilter("netmask", struct {
        fn f(ctx: *jinja.FilterCtx, input: jinja.Value, args: jinja.FilterArgs) jinja.FilterError!jinja.Value {
            _ = args;
            const bits = switch (input) {
                .integer => |i| i,
                else => return error.TypeMismatch,
            };
            const mask: u32 = if (bits == 0) 0 else @truncate(~@as(u64, 0) << @intCast(32 - bits));
            const s = try std.fmt.allocPrint(ctx.arena, "{d}.{d}.{d}.{d}", .{
                (mask >> 24) & 0xff, (mask >> 16) & 0xff, (mask >> 8) & 0xff, mask & 0xff,
            });
            return jinja.Value.str(s);
        }
    }.f);
    try env.addTest("private", struct {
        fn f(ctx: *jinja.FilterCtx, input: jinja.Value, args: jinja.FilterArgs) jinja.FilterError!bool {
            _ = args;
            const s = try ctx.toStr(input);
            return std.mem.startsWith(u8, s, "10.") or std.mem.startsWith(u8, s, "192.168.");
        }
    }.f);

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const ctx = try jinja.valueFrom(arena.allocator(), .{ .bits = 24, .addr = "10.1.2.3" });
    const out = try env.renderAlloc(gpa, "{{ bits|netmask }} {{ addr is private }}", ctx, null);
    defer gpa.free(out);
    try testing.expectEqualStrings("255.255.255.0 True", out);
}

test "a compiled template is reusable across renders" {
    const gpa = testing.allocator;
    var env = try jinja.Environment.init(gpa, .{});
    defer env.deinit();
    var tmpl = try env.compile("{{ n }}", null);
    defer tmpl.deinit();

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    for ([_]i64{ 1, 2, 3 }) |n| {
        const ctx = try jinja.valueFrom(arena.allocator(), .{ .n = n });
        const out = try tmpl.render(gpa, ctx, null);
        defer gpa.free(out);
        var buf: [8]u8 = undefined;
        try testing.expectEqualStrings(try std.fmt.bufPrint(&buf, "{d}", .{n}), out);
    }
}

test "renderTo writes into a caller-owned writer" {
    const gpa = testing.allocator;
    var env = try jinja.Environment.init(gpa, .{});
    defer env.deinit();
    var tmpl = try env.compile("hello {{ who }}", null);
    defer tmpl.deinit();

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const ctx = try jinja.valueFrom(arena.allocator(), .{ .who = "world" });

    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try tmpl.renderTo(gpa, &w, ctx, null);
    try testing.expectEqualStrings("hello world", w.buffered());
}

test "a runaway render hits the output ceiling instead of the machine" {
    const gpa = testing.allocator;
    var env = try jinja.Environment.init(gpa, .{ .max_output_bytes = 1024 });
    defer env.deinit();
    try testing.expectError(
        error.OutputTooLarge,
        env.renderAlloc(gpa, "{% for i in range(100000) %}xxxxxxxxxx{% endfor %}", .{ .map = .{ .pairs = &.{} } }, null),
    );
}

test "range() refuses an absurd request rather than allocating it" {
    const gpa = testing.allocator;
    var env = try jinja.Environment.init(gpa, .{});
    defer env.deinit();
    try testing.expectError(
        error.OutOfRange,
        env.renderAlloc(gpa, "{{ range(100000000)|length }}", .{ .map = .{ .pairs = &.{} } }, null),
    );
}

test "the one-shot helper works with default options" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const ctx = try jinja.valueFrom(arena.allocator(), .{ .x = 1 });
    const out = try jinja.renderAlloc(gpa, "x={{ x }}", ctx, .{}, null);
    defer gpa.free(out);
    try testing.expectEqualStrings("x=1", out);
}

test "valueFromJson preserves object order" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const parsed = try std.json.parseFromSlice(std.json.Value, a, "{\"z\":1,\"a\":2,\"m\":3}", .{});
    const ctx = try jinja.valueFromJson(a, parsed.value);
    const out = try renderWith(gpa, .{}, "{% for k in ctx %}{{ k }}{% endfor %}", .{ .map = .{ .pairs = &.{
        .{ .key = jinja.Value.str("ctx"), .value = ctx },
    } } });
    defer gpa.free(out);
    try testing.expectEqualStrings("zam", out);
}

test "an unterminated tag is rejected rather than swallowing the rest" {
    const gpa = testing.allocator;
    var env = try jinja.Environment.init(gpa, .{});
    defer env.deinit();
    for ([_][]const u8{
        "{{ 1 + }}",
        "{{ unclosed",
        "{% if true %}no end",
        "{# unclosed comment",
        "{% raw %}no end",
        "{{ 'unterminated }}",
    }) |src| {
        try testing.expectError(error.TemplateSyntaxError, env.compile(src, null));
    }
}

test "a macro in an imported template can use a filter the CALLER registered" {
    // The brief's sharpest composition question: loaded templates are compiled
    // against the same environment, so a custom filter registered before
    // compilation is available inside a template the loader supplies later.
    const gpa = testing.allocator;
    var map: jinja.MapLoader = .{ .entries = &.{
        .{ .name = "macros", .source = "{% macro cidr(a, b) %}{{ a }}/{{ b|netbits }}{% endmacro %}" },
    } };
    var env = try jinja.Environment.initWithLoader(gpa, .{}, map.loader());
    defer env.deinit();
    try env.addFilter("netbits", struct {
        fn f(ctx: *jinja.FilterCtx, input: jinja.Value, args: jinja.FilterArgs) jinja.FilterError!jinja.Value {
            _ = ctx;
            _ = args;
            const s = switch (input) {
                .string => |x| x.bytes,
                else => return error.TypeMismatch,
            };
            var bits: i64 = 0;
            var it = std.mem.splitScalar(u8, s, '.');
            while (it.next()) |octet| {
                const v = std.fmt.parseInt(u8, octet, 10) catch return error.BadArgument;
                bits += @popCount(v);
            }
            return .{ .integer = bits };
        }
    }.f);

    const out = try env.renderAlloc(
        gpa,
        "{% import 'macros' as m %}{{ m.cidr('10.0.0.0', '255.255.255.0') }}",
        .{ .map = .{ .pairs = &.{} } },
        null,
    );
    defer gpa.free(out);
    try testing.expectEqualStrings("10.0.0.0/24", out);
}

test "an unknown filter inside a LOADED template is still a resolution error" {
    // Part 1 resolves filter names when the entry template compiles. A loaded
    // template compiles when it is first reached, so the same guarantee holds
    // — just later, and it must not degrade into a render-time surprise with no
    // explanation.
    const gpa = testing.allocator;
    var map: jinja.MapLoader = .{ .entries = &.{.{ .name = "bad", .source = "{{ x|nosuchfilter }}" }} };
    var env = try jinja.Environment.initWithLoader(gpa, .{}, map.loader());
    defer env.deinit();

    var diag: jinja.Diagnostic = .{};
    try testing.expectError(
        error.TemplateSyntaxError,
        env.renderAlloc(gpa, "{% include 'bad' %}", .{ .map = .{ .pairs = &.{} } }, &diag),
    );
    try testing.expect(std.mem.indexOf(u8, diag.message(), "bad") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message(), "unknown filter") != null);
}

test "a Template stays immutable across renders that load other templates" {
    // The loader deliberately does NOT let the Environment cache compiled
    // templates: that would need a mutable environment at render time and
    // would cost the thread-safety Part 1 established. Caching is per render,
    // so two renders of the same Template are independent.
    const gpa = testing.allocator;
    var map: jinja.MapLoader = .{ .entries = &.{.{ .name = "row", .source = "<{{ n }}>" }} };
    var env = try jinja.Environment.initWithLoader(gpa, .{}, map.loader());
    defer env.deinit();

    var tmpl = try env.compile("{% include 'row' %}{% include 'row' %}", null);
    defer tmpl.deinit();

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    for ([_]i64{ 1, 2 }) |n| {
        const ctx = try jinja.valueFrom(arena.allocator(), .{ .n = n });
        const out = try tmpl.render(gpa, ctx, null);
        defer gpa.free(out);
        var buf: [16]u8 = undefined;
        try testing.expectEqualStrings(try std.fmt.bufPrint(&buf, "<{d}><{d}>", .{ n, n }), out);
    }
}

test "autoescape: context data cannot reach the output unescaped without |safe" {
    // The property the whole autoescape design rests on, asserted directly
    // rather than as a byte comparison: `|safe` is the ONLY way a template
    // spells "emit these bytes raw". It was false. `markupAware` re-marked a
    // filter result as markup whenever the INPUT was markup, and `replace`
    // spliced its `new` argument in without escaping it — so any template that
    // produced markup by construction leaked. `{% filter %}` and `{% set %}`
    // block bodies are markup by construction under autoescape
    // (`render.zig:310`, `:324`), which makes the first two templates below a
    // bypass in a template that never writes `|safe` at all.
    //
    // Not one of these templates has a literal `<` in its text, so any `<` in
    // the output came from the context. The reference (Jinja2 3.1.6) renders
    // every one of them escaped; `corpus.zig`'s `escape_replace_*` cases pin
    // the exact bytes against it.
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const ctx = try jinja.valueFrom(arena.allocator(), .{
        .s = "q x q",
        .evil = "<script>alert(1)</script>",
    });

    const Case = struct { src: []const u8, escaped: []const u8 };
    for ([_]Case{
        .{ .src = "{% filter replace('x', evil) %}q x q{% endfilter %}", .escaped = "&lt;script&gt;" },
        .{ .src = "{% set b %}q x q{% endset %}{{ b|replace('x', evil) }}", .escaped = "&lt;script&gt;" },
        // `|upper` runs on the markup, so the entities are uppercased too —
        // which is what the reference does (`Markup.upper()`).
        .{ .src = "{% filter replace('x', evil)|upper %}q x q{% endfilter %}", .escaped = "&LT;SCRIPT&GT;" },
        .{ .src = "{{ (s|safe)|replace('x', evil) }}", .escaped = "&lt;script&gt;" },
        .{ .src = "{{ (s|safe)|replace('x', evil)|replace('q', 'r') }}", .escaped = "&lt;script&gt;" },
        .{ .src = "{{ (s|safe).replace('x', evil) }}", .escaped = "&lt;script&gt;" },
        .{ .src = "{{ s|replace('x', evil) }}", .escaped = "&lt;script&gt;" },
        .{ .src = "{{ [s|safe]|map('replace', 'x', evil)|list|join('') }}", .escaped = "&lt;script&gt;" },
        .{ .src = "{% set b %}q x q{% endset %}{{ b|replace('x', evil, 1) }}", .escaped = "&lt;script&gt;" },
        .{ .src = "{% filter replace('x', evil)|trim %}q x q{% endfilter %}", .escaped = "&lt;script&gt;" },
    }) |c| {
        const out = try renderWith(gpa, .{ .autoescape = true }, c.src, ctx);
        defer gpa.free(out);
        if (std.mem.indexOfScalar(u8, out, '<') != null) {
            std.debug.print("\nautoescape bypass: '{s}' rendered '{s}'\n", .{ c.src, out });
            return error.AutoescapeBypass;
        }
        if (std.mem.indexOf(u8, out, c.escaped) == null) {
            std.debug.print("\n'{s}' rendered '{s}', which does not carry '{s}'\n", .{ c.src, out, c.escaped });
            return error.EscapedFormMissing;
        }
    }

    // The control: an argument the template explicitly marked safe still goes
    // through raw, so the check above is not just "we escape everything".
    const raw = try renderWith(gpa, .{ .autoescape = true }, "{{ (s|safe)|replace('x', evil|safe) }}", ctx);
    defer gpa.free(raw);
    try testing.expectEqualStrings("q <script>alert(1)</script> q", raw);
}

// ── unbounded work on attacker-chosen input ────────────────────────────────
//
// Templates in this module are untrusted input (see `fuzz_test.zig`'s
// docstring: a config repository, a UI field, a fleet-management API), and so
// is the context data. Both of the shapes below used to be a crash or a spin
// rather than an error.

const Parts = struct {
    pre: []const u8 = "",
    open: []const u8 = "",
    mid: []const u8 = "",
    close: []const u8 = "",
    post: []const u8 = "",
};

/// `pre ++ open*n ++ mid ++ close*n ++ post`.
fn nestedSrc(gpa: std.mem.Allocator, parts: Parts, n: usize) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    errdefer b.deinit(gpa);
    try b.appendSlice(gpa, parts.pre);
    for (0..n) |_| try b.appendSlice(gpa, parts.open);
    try b.appendSlice(gpa, parts.mid);
    for (0..n) |_| try b.appendSlice(gpa, parts.close);
    try b.appendSlice(gpa, parts.post);
    return b.toOwnedSlice(gpa);
}

const Nesting = struct {
    what: []const u8,
    parts: Parts,
    /// Deepest `n` that still compiles at `max_nesting_depth = 32`.
    fits_at_32: usize,
};

/// Every shape that recursed without a bound. The first three grow the
/// *parser's* stack; the rest are parsed by iterative loops and grow only the
/// **tree**, which `Renderer.eval` / `renderNodes` / `exprMentions` then
/// descend just as recursively — so a bound on the parser alone would have left
/// them crashing.
const nestings = [_]Nesting{
    .{ .what = "parentheses", .parts = .{ .pre = "{{ ", .open = "(", .mid = "1", .close = ")", .post = " }}" }, .fits_at_32 = 31 },
    .{ .what = "list literals", .parts = .{ .pre = "{{ ", .open = "[", .mid = "1", .close = "]", .post = " }}" }, .fits_at_32 = 31 },
    .{ .what = "unary minus", .parts = .{ .pre = "{{ ", .open = "-", .mid = "1", .post = " }}" }, .fits_at_32 = 31 },
    .{ .what = "filter chain", .parts = .{ .pre = "{{ 1", .mid = "", .close = "|string", .post = " }}" }, .fits_at_32 = 31 },
    .{ .what = "arithmetic chain", .parts = .{ .pre = "{{ 1", .mid = "", .close = "+1", .post = " }}" }, .fits_at_32 = 31 },
    .{ .what = "attribute chain", .parts = .{ .pre = "{{ x", .mid = "", .close = ".a", .post = " }}" }, .fits_at_32 = 31 },
    .{ .what = "chain inside a macro body", .parts = .{ .pre = "{% macro m() %}{{ 1", .mid = "", .close = "+1", .post = " }}{% endmacro %}" }, .fits_at_32 = 30 },
    .{ .what = "block nesting", .parts = .{ .open = "{% if 1 %}", .mid = "x", .close = "{% endif %}" }, .fits_at_32 = 15 },
    .{ .what = "elif chain", .parts = .{ .pre = "{% if 0 %}a", .mid = "", .close = "{% elif 0 %}b", .post = "{% endif %}" }, .fits_at_32 = 29 },
};

test "nesting deeper than the bound is a named error, not a stack overflow" {
    const gpa = testing.allocator;
    var env = try jinja.Environment.init(gpa, .{ .undefined_policy = .lenient });
    defer env.deinit();
    for (nestings) |c| {
        // 20 000 levels: every one of these was a SIGSEGV at this depth, in
        // templates of 20–420 KB. The default bound is 256, so the answer must
        // arrive as an error long before any stack is touched.
        const src = try nestedSrc(gpa, c.parts, 20_000);
        defer gpa.free(src);
        var diag: jinja.Diagnostic = .{};
        if (env.compile(src, &diag)) |tmpl| {
            var m = tmpl;
            m.deinit();
            std.debug.print("\n{s} nested 20000 deep compiled instead of being refused\n", .{c.what});
            return error.NestingNotBounded;
        } else |e| try testing.expectEqual(error.TooDeep, e);
        // Reported like every other template error: a typed error plus a
        // diagnostic, not a panic and not a silent truncation.
        try testing.expect(std.mem.indexOf(u8, diag.message(), "nested deeper than") != null);
    }
}

test "the nesting bound bites AT the bound, not somewhere past it" {
    const gpa = testing.allocator;
    var env = try jinja.Environment.init(gpa, .{ .max_nesting_depth = 32, .undefined_policy = .lenient });
    defer env.deinit();
    for (nestings) |c| {
        // Exactly at the limit: compiles.
        const ok_src = try nestedSrc(gpa, c.parts, c.fits_at_32);
        defer gpa.free(ok_src);
        var ok = env.compile(ok_src, null) catch |e| {
            std.debug.print("\n{s} at n={d} was refused ({s}); the bound is off by one\n", .{ c.what, c.fits_at_32, @errorName(e) });
            return error.BoundTooTight;
        };
        ok.deinit();

        // One level past it: refused. This is the interesting case — a test at
        // ten times the cap proves only that something eventually stops.
        const bad_src = try nestedSrc(gpa, c.parts, c.fits_at_32 + 1);
        defer gpa.free(bad_src);
        if (env.compile(bad_src, null)) |tmpl| {
            var m = tmpl;
            m.deinit();
            std.debug.print("\n{s} at n={d} compiled; the bound is off by one\n", .{ c.what, c.fits_at_32 + 1 });
            return error.BoundTooLoose;
        } else |e| try testing.expectEqual(error.TooDeep, e);
    }
}

fn monotonicNs() u64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

test "`**` with a base of 0, 1 or -1 answers in closed form" {
    const gpa = testing.allocator;
    // Pinned against CPython/Jinja2 3.1.6 on this host, which answers each of
    // these instantly: `1 ** 500000000` = 1, `0 ** 500000000` = 0, `0 ** 0` = 1,
    // `(-1) ** 500000000` = 1, `(-1) ** 500000001` = -1.
    for ([_]struct { src: []const u8, want: []const u8 }{
        .{ .src = "{{ 1 ** 500000000 }}", .want = "1" },
        .{ .src = "{{ 1 ** 9223372036854775807 }}", .want = "1" },
        .{ .src = "{{ 0 ** 500000000 }}", .want = "0" },
        .{ .src = "{{ 0 ** 0 }}", .want = "1" },
        .{ .src = "{{ (-1) ** 500000000 }}", .want = "1" },
        .{ .src = "{{ (-1) ** 500000001 }}", .want = "-1" },
        .{ .src = "{{ (-1) ** 9223372036854775807 }}", .want = "-1" },
        // The bases that do overflow still terminate — within 63 doublings —
        // and still say so.
        .{ .src = "{{ 2 ** 62 }}", .want = "4611686018427387904" },
    }) |c| {
        const out = try renderWith(gpa, .{}, c.src, .{ .map = .{ .pairs = &.{} } });
        defer gpa.free(out);
        try testing.expectEqualStrings(c.want, out);
    }
    try testing.expectError(
        error.OutOfRange,
        renderWith(gpa, .{}, "{{ 2 ** 64 }}", .{ .map = .{ .pairs = &.{} } }),
    );
}

test "`**` from context data cannot spin the renderer" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    // The reachable shape: neither operand is in the template. Before the fix
    // this loop ran `b` times producing nothing, so `max_output_bytes` — the
    // only exhaustion bound SPEC §8 offers — never fired; measured at ~7 s for
    // an exponent of 500 000 000, and ~10^6 years for i64's maximum.
    const ctx = try jinja.valueFrom(arena.allocator(), .{
        .a = @as(i64, 1),
        .b = @as(i64, 1_000_000_000),
    });
    const start = monotonicNs();
    const out = try renderWith(gpa, .{}, "{{ a ** b }}", ctx);
    defer gpa.free(out);
    const elapsed = monotonicNs() - start;
    try testing.expectEqualStrings("1", out);
    // Two orders of magnitude of headroom over the fixed path (microseconds)
    // and an order of magnitude under the unfixed one (~14 s at this exponent).
    if (elapsed > 2 * std.time.ns_per_s) {
        std.debug.print("\n`{{{{ a ** b }}}}` with b=1e9 took {d} ms\n", .{elapsed / std.time.ns_per_ms});
        return error.PowUnbounded;
    }
}

test "the one integer pair `//`, `%` and `divisibleby` cannot represent is an error, not a trap" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    // Reachable from context data alone: `@divTrunc`/`@rem`/`@mod` trap on
    // `minInt(i64) / -1`, which is a panic in Debug and a **SIGFPE** in
    // ReleaseFast — neither is catchable by a caller.
    const ctx = try jinja.valueFrom(arena.allocator(), .{
        .a = @as(i64, std.math.minInt(i64)),
        .b = @as(i64, -1),
    });
    try testing.expectError(error.OutOfRange, renderWith(gpa, .{}, "{{ a // b }}", ctx));

    // `%` and `divisibleby` have answers Python agrees with, so they render.
    {
        const out = try renderWith(gpa, .{}, "{{ a % b }}", ctx);
        defer gpa.free(out);
        try testing.expectEqualStrings("0", out);
    }
    {
        const out = try renderWith(gpa, .{}, "{{ a is divisibleby(b) }}", ctx);
        defer gpa.free(out);
        try testing.expectEqualStrings("True", out);
    }
    // The same pair reached from the template's own text, no context at all.
    try testing.expectError(
        error.OutOfRange,
        renderWith(gpa, .{}, "{{ (-9223372036854775807 - 1) // -1 }}", .{ .none = {} }),
    );
}

test "`xmlattr` refuses a key that could close the attribute" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    // Autoescape on, no `|safe` anywhere: the injection is the dict KEY, and
    // `escapeTo`'s `& < > " '` set does not touch a space or an `=`.
    inline for (.{
        "a onmouseover=alert(1) b",
        "a/b",
        "a>b",
        "a=b",
        "a\tb",
        "a\nb",
    }) |bad| {
        const attrs: []const jinja.Pair = try a.dupe(jinja.Pair, &.{.{
            .key = .{ .string = .{ .bytes = bad } },
            .value = .{ .string = .{ .bytes = "1" } },
        }});
        const ctx: jinja.Value = .{ .map = .{ .pairs = try a.dupe(jinja.Pair, &.{.{
            .key = .{ .string = .{ .bytes = "d" } },
            .value = .{ .map = .{ .pairs = attrs } },
        }}) } };
        try testing.expectError(
            error.BadArgument,
            renderWith(gpa, .{ .autoescape = true }, "<img{{ d|xmlattr }}>", ctx),
        );
    }
}

test "a value deeper than the value-depth cap is refused, not a stack overflow" {
    const gpa = testing.allocator;

    // A 103-byte template builds the value; `max_nesting_depth` bounds the
    // SOURCE tree and says nothing about this. Measured before the fix:
    // 60 000 levels rendered, 70 000 was a SIGSEGV in ReleaseFast (Debug
    // aborted at 40 000), and `{{ ns.v|length }}` on the same value answered
    // `1` in 17 ms — only printing it died.
    const src =
        \\{% set ns = namespace(v=[]) %}{% for i in range(2000) %}{% set ns.v = [ns.v] %}{% endfor %}{{ ns.v }}
    ;
    try testing.expectError(error.OutOfRange, renderWith(gpa, .{}, src, .{ .none = {} }));

    // …and through `|tojson`, which walks the same value with its own recursion.
    const as_json =
        \\{% set ns = namespace(v=[]) %}{% for i in range(2000) %}{% set ns.v = [ns.v] %}{% endfor %}{{ ns.v|tojson }}
    ;
    try testing.expectError(error.OutOfRange, renderWith(gpa, .{}, as_json, .{ .none = {} }));

    // Just inside the cap still renders, so the bound is a bound and not a ban.
    const shallow =
        \\{% set ns = namespace(v=[]) %}{% for i in range(200) %}{% set ns.v = [ns.v] %}{% endfor %}{{ ns.v|length }}
    ;
    const out = try renderWith(gpa, .{}, shallow, .{ .none = {} });
    defer gpa.free(out);
    try testing.expectEqualStrings("1", out);

    // The same depth reached the other way: pure context data through the
    // public `valueFromJson`, no template trick at all.
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const n = 2000;
    const json = try a.alloc(u8, n * 2);
    @memset(json[0..n], '[');
    @memset(json[n..], ']');
    const parsed = try std.json.parseFromSlice(std.json.Value, a, json, .{});
    try testing.expectError(error.OutOfRange, jinja.valueFromJson(a, parsed.value));
}

test "truncate keeps a spaceless prefix instead of emptying it" {
    const gpa = testing.allocator;
    // `rsplit(" ", 1)[0]` on a string with no space returns the whole string.
    // URLs, hostnames, interface names and base64 are exactly what a config
    // template truncates, and they were all silently reduced to the ellipsis.
    const cases = [_]struct { src: []const u8, want: []const u8 }{
        .{ .src = "{{ 'https://example.com/averylongpath'|truncate(20) }}", .want = "https://example.c..." },
        .{ .src = "{{ 'abcdefghijklmnop'|truncate(10) }}", .want = "abcdefg..." },
        .{ .src = "{{ 'abcdefghij'|truncate(9, false, '..', 0) }}", .want = "abcdefg.." },
        .{ .src = "{{ 'aaaaaaaaaaaaaaaaaa'|truncate(12, false, '') }}", .want = "aaaaaaaaaaaa" },
        // The vector the corpus already had still answers the same.
        .{ .src = "{{ 'the quick brown fox jumps'|truncate(15) }}", .want = "the quick..." },
    };
    for (cases) |c| {
        const out = try renderWith(gpa, .{}, c.src, .{ .none = {} });
        defer gpa.free(out);
        try testing.expectEqualStrings(c.want, out);
    }
}

test "an undefined numeric argument is refused, not quietly defaulted" {
    const gpa = testing.allocator;
    // The reference raises for every one of these under BOTH `Undefined` and
    // `StrictUndefined`; this module answered with the argument's default,
    // which is the silent-wrong-value failure its policy exists to prevent.
    inline for (.{
        "{{ x|int }}",
        "{{ x|float }}",
        "{{ 'a'|center(x) }}",
        "{{ 'abc'|truncate(x) }}",
        "{{ 'abc'|replace('a','b',x) }}",
        "{{ [1,2]|batch(x)|list }}",
        "{{ [1,2,3]|slice(x)|list }}",
        "{{ 'a'|indent(x) }}",
        "{{ 1.5|round(x) }}",
    }) |src| {
        try testing.expectError(
            error.UndefinedValue,
            renderWith(gpa, .{}, src, .{ .none = {} }),
        );
    }
}

test "`|int` with base 0 reads the literal's own prefix" {
    const gpa = testing.allocator;
    const cases = [_]struct { src: []const u8, want: []const u8 }{
        .{ .src = "{{ '0b101'|int(0, 0) }}", .want = "5" },
        .{ .src = "{{ '0o17'|int(0, 0) }}", .want = "15" },
        .{ .src = "{{ '0x1f'|int(0, 0) }}", .want = "31" },
        // The explicit bases keep working — the manual prefix strip is what
        // base 0 must not go through, not what base 16 must lose.
        .{ .src = "{{ '0x1f'|int(0, 16) }}", .want = "31" },
        .{ .src = "{{ '17'|int(0, 8) }}", .want = "15" },
    };
    for (cases) |c| {
        const out = try renderWith(gpa, .{}, c.src, .{ .none = {} });
        defer gpa.free(out);
        try testing.expectEqualStrings(c.want, out);
    }
}

test "a render's total work is bounded, not just its depth and its steps" {
    const gpa = testing.allocator;
    // 8 MiB so the test is fast; the point is that a bound exists at all.
    const opts: jinja.Options = .{ .max_render_bytes = 8 << 20 };

    // (a) Exponential macro fan-out. Depth 22 is a THIRD of `max_call_depth`,
    // so neither depth cap fires, and the output is zero bytes throughout, so
    // `max_output_bytes` never sees one. Measured before the fix: 3.8 GB.
    const fanout =
        \\{% macro m(n) %}{% if n %}{{ m(n-1) }}{{ m(n-1) }}{% endif %}{% endmacro %}{{ m(22) }}
    ;
    try testing.expectError(error.RenderBudgetExceeded, renderWith(gpa, opts, fanout, .{ .none = {} }));

    // (b) Two per-operation caps multiplied by one expression: `replace` with
    // an empty `old` inserts `new` at every codepoint gap, so the cost is
    // `len(s) × len(new)` and both operands are separately under `max_alloc`.
    const amplify = "{{ (('a' * 30000)|replace('', 'b' * 30000))|length }}";
    try testing.expectError(error.RenderBudgetExceeded, renderWith(gpa, opts, amplify, .{ .none = {} }));

    // (c) The same shape through a loop, where each step is individually legal.
    const looped = "{% for i in range(16) %}{{ ('x' * 67108000)|length }}{% endfor %}";
    try testing.expectError(error.RenderBudgetExceeded, renderWith(gpa, opts, looped, .{ .none = {} }));

    // A budget is a bound, not a ban: ordinary work still renders.
    const ok_src =
        \\{% macro m(n) %}{% if n %}{{ m(n-1) }}{{ m(n-1) }}{% endif %}x{% endmacro %}{{ m(8) }}
    ;
    const out = try renderWith(gpa, opts, ok_src, .{ .none = {} });
    defer gpa.free(out);
    try testing.expectEqual(@as(usize, 511), out.len);
}

test "F-B3: quadratic namespace-concat accumulation is bounded, not just documented" {
    const gpa = testing.allocator;
    // SPEC.md §8 names this shape explicitly: `{% set ns.s = ns.s ~ 'x' %}` is
    // O(n²) *memory* here (the reference's refcounted string is O(n)) because
    // the render arena never reclaims the discarded intermediate copies.
    // 8192 iterations of a 1-byte-per-step accumulation allocate roughly
    // sum(1..8192) ≈ 33.6 MiB in throwaway concat copies alone — comfortably
    // over an 8 MiB budget, so this is the F-B3 scenario itself, not a stand-in.
    const opts: jinja.Options = .{ .max_render_bytes = 8 << 20 };
    const src =
        \\{% set ns = namespace(s='') %}{% for i in range(8192) %}{% set ns.s = ns.s ~ 'x' %}{% endfor %}{{ ns.s|length }}
    ;
    try testing.expectError(error.RenderBudgetExceeded, renderWith(gpa, opts, src, .{ .none = {} }));

    // Sanity check the shape isn't rejected outright: a small accumulation
    // under budget still renders the accumulated length.
    const small_opts: jinja.Options = .{ .max_render_bytes = 8 << 20 };
    const small_src =
        \\{% set ns = namespace(s='') %}{% for i in range(50) %}{% set ns.s = ns.s ~ 'x' %}{% endfor %}{{ ns.s|length }}
    ;
    const out = try renderWith(gpa, small_opts, small_src, .{ .none = {} });
    defer gpa.free(out);
    try testing.expectEqualStrings("50", out);
}

test "wordcount, striptags and urlencode answer what the reference answers" {
    const gpa = testing.allocator;
    // Every expectation below was read off live Jinja2 3.1.6 on this host,
    // not from memory. SPEC.md claims everything not in a corpus case matches
    // the reference; these four did not (W2 re-audit, F-D2).
    const cases = [_]struct { src: []const u8, want: []const u8 }{
        // `\w+` runs, not whitespace-separated tokens.
        .{ .src = "{{ 'a-b-c'|wordcount }}", .want = "3" },
        .{ .src = "{{ 'foo.bar'|wordcount }}", .want = "2" },
        .{ .src = "{{ '<b>x</b>'|wordcount }}", .want = "3" },
        .{ .src = "{{ 'a_b'|wordcount }}", .want = "1" },
        .{ .src = "{{ ''|wordcount }}", .want = "0" },
        // The corpus vector still answers the same.
        .{ .src = "{{ 'a b  c\nd'|wordcount }}", .want = "4" },
        // An unterminated `<` is text, not the start of a tag that eats the rest.
        .{ .src = "{{ 'a<b'|striptags }}", .want = "a<b" },
        .{ .src = "{{ 'a<b>c'|striptags }}", .want = "ac" },
        // A mapping is query-string encoded: a space is `+`, not `%20`.
        .{ .src = "{{ {'k': 'a b'}|urlencode }}", .want = "k=a+b" },
        .{ .src = "{{ {'a b': 'c'}|urlencode }}", .want = "a+b=c" },
        .{ .src = "{{ {'k': 'a/b'}|urlencode }}", .want = "k=a%2Fb" },
        // …and an iterable of pairs is accepted, not repr'd.
        .{ .src = "{{ [('a', 'b c')]|urlencode }}", .want = "a=b+c" },
        // A bare string keeps the plain form, `/` safe and `%20` for a space.
        .{ .src = "{{ 'a b'|urlencode }}", .want = "a%20b" },
    };
    for (cases) |c| {
        const out = try renderWith(gpa, .{}, c.src, .{ .none = {} });
        defer gpa.free(out);
        try testing.expectEqualStrings(c.want, out);
    }
}
