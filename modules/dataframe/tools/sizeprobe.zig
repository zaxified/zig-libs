// SPDX-License-Identifier: MIT
//! Size probe for the `small` lane (CONVENTIONS §4.2): what a consumer that cleans text columns
//! uses of dataframe, a frame of one text cell run through `mutate` with a regex test, the Unicode
//! case mapping and accent folding. Built at ReleaseSmall by `scripts/checks/small-sizes.sh` under
//! `-Dprofile=default` (everything) and under `-Dprofile=small` together with the explicit knobs
//! `-Ddataframe-regex=false -Ddataframe-unicode=false` (the profile itself leaves dataframe alone);
//! the difference is `regex`, `unitext` and their Unicode tables left out, held to its floor in
//! `scripts/checks/small-size-expected.tsv`.
const std = @import("std");
const df = @import("dataframe");

pub fn main(init: std.process.Init) !void {
    var it = init.minimal.args.iterate();
    _ = it.next();
    const text = it.next() orelse return error.MissingText;
    const pattern = it.next() orelse return error.MissingPattern;
    var arena = std.heap.ArenaAllocator.init(df.big_block_allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const cols = [_]df.Column{.{ .name = "x", .type = .text }};
    var b = try df.FrameBuilder.init(a, &cols, 1);
    try b.appendRow(&.{.{ .text = text }});
    const f = try b.toOwned();
    const x: df.Expr = .{ .col = "x" };
    var code: u8 = 0;
    const g = df.mutate(a, f, &.{
        .{ .out = "hit", .expr = .{ .contains_regex = .{ .x = &x, .pattern = pattern } } },
    }) catch blk: {
        code |= 1;
        break :blk f;
    };
    code |= @as(u8, @intFromBool(g.cell(0, "hit") != null)) << 1;
    const h = df.mutate(a, f, &.{
        .{ .out = "low", .expr = .{ .unary = .{ .op = .lower, .x = &x } } },
        .{ .out = "flat", .expr = .{ .unary = .{ .op = .unaccent, .x = &x } } },
    }) catch blk: {
        code |= 4;
        break :blk f;
    };
    code |= @as(u8, @intFromBool(h.cell(0, "low") != null)) << 3;
    std.process.exit(code);
}
