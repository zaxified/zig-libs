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

test "fuzz: arbitrary bytes as a template never panic" {
    try std.testing.fuzz({}, fuzzCompileAndRender, .{});
}

test "fuzz: arbitrary bytes with whitespace options never panic" {
    try std.testing.fuzz({}, fuzzWhitespaceOptions, .{});
}
