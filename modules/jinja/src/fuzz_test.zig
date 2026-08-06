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

fn drawSource(smith: *std.testing.Smith, buf: []u8) []const u8 {
    const n = smith.indexWithHash(buf.len, 0);
    smith.bytes(buf[0..n]);
    return buf[0..n];
}

/// Arbitrary bytes as a template. Compiling must either succeed or return an
/// error; a template that compiles must then render or return an error.
fn fuzzCompileAndRender(_: void, smith: *std.testing.Smith) !void {
    const gpa = std.testing.allocator;
    var buf: [1024]u8 = undefined;
    const src = drawSource(smith, &buf);

    var env = try jinja.Environment.init(gpa, .{ .undefined_policy = .lenient });
    defer env.deinit();

    var diag: jinja.Diagnostic = .{};
    var tmpl = env.compile(src, &diag) catch return;
    defer tmpl.deinit();

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const ctx = try jinja.valueFrom(arena.allocator(), .{
        .a = @as(i64, 3),
        .s = "text",
        .l = [_]i64{ 1, 2, 3 },
        .d = .{ .k = "v" },
    });

    const out = tmpl.render(gpa, ctx, &diag) catch return;
    gpa.free(out);
}

/// The same, with the syntax options that rewrite whitespace turned on — the
/// slice edits in `applyWhitespace` are the part most likely to walk off the
/// end of a text chunk.
fn fuzzWhitespaceOptions(_: void, smith: *std.testing.Smith) !void {
    const gpa = std.testing.allocator;
    var buf: [512]u8 = undefined;
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
/// `**` is deliberately absent: its loop is unbounded for `|base| <= 1`, which
/// is a separate finding and would hang this harness rather than crash it.
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
};

/// The numeric-argument surface, which the two harnesses above cannot reach.
///
/// They draw arbitrary bytes into a 1024/512-byte buffer and render them
/// against a fixed four-key context, so reaching any of these sites would mean
/// synthesising `|replace('a','b',-1)` or `* 4611686018427387904` by chance —
/// which is why a clean 121-second sweep certified nothing about the eleven
/// unchecked narrowing casts that were found by hand instead. Here the template
/// *shape* is fixed and the **number** is what gets fuzzed, half the time as a
/// literal and half through the render context, which is the data path neither
/// harness above touches at all.
fn fuzzNumericArgs(_: void, smith: *std.testing.Smith) !void {
    const gpa = std.testing.allocator;
    const site = num_sites[smith.index(num_sites.len)];
    const n = smith.value(i64);

    // Three spellings of the same drawn number, so the float→int narrowing gets
    // reached as well as the int→usize one.
    var num_buf: [64]u8 = undefined;
    const via_ctx = smith.boolWeighted(1, 1);
    const as_float = smith.boolWeighted(2, 1);
    const exp: i32 = @intCast(smith.valueRangeAtMost(i16, -330, 330));
    const num: []const u8 = if (via_ctx)
        "nn"
    else if (as_float)
        try std.fmt.bufPrint(&num_buf, "{d}.0e{d}", .{ n, exp })
    else
        try std.fmt.bufPrint(&num_buf, "{d}", .{n});

    const src = try std.mem.concat(gpa, u8, &.{ site.pre, num, site.post });
    defer gpa.free(src);

    var env = try jinja.Environment.init(gpa, .{ .undefined_policy = .lenient });
    defer env.deinit();

    var tmpl = env.compile(src, null) catch return;
    defer tmpl.deinit();

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const nn: jinja.Value = if (as_float)
        .{ .float = @as(f64, @floatFromInt(n)) * std.math.pow(f64, 10, @floatFromInt(exp)) }
    else
        .{ .integer = n };
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

test "fuzz: arbitrary bytes as a template never panic" {
    try std.testing.fuzz({}, fuzzCompileAndRender, .{});
}

test "fuzz: arbitrary bytes with whitespace options never panic" {
    try std.testing.fuzz({}, fuzzWhitespaceOptions, .{});
}

test "fuzz: arbitrary numeric arguments to filters, globals and slices never panic" {
    try std.testing.fuzz({}, fuzzNumericArgs, .{});
}
