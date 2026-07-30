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

test "inheritance tags are named as unimplemented, not as typos" {
    const gpa = testing.allocator;
    var env = try jinja.Environment.init(gpa, .{});
    defer env.deinit();
    for ([_][]const u8{
        "{% extends 'base.html' %}",
        "{% block body %}{% endblock %}",
        "{% include 'x.html' %}",
        "{% macro m() %}{% endmacro %}",
        "{% import 'x.html' as x %}",
    }) |src| {
        var diag: jinja.Diagnostic = .{};
        try testing.expectError(error.TemplateSyntaxError, env.compile(src, &diag));
        try testing.expect(std.mem.indexOf(u8, diag.message(), "not implemented") != null);
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
