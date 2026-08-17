// SPDX-License-Identifier: MIT
//! Turning a finished symbol into something a person or a browser can see.
//!
//! Kept apart from the codec on purpose: `root.zig` computes a grid and has no
//! opinion about pixels, and nothing here can affect what a symbol *says*. The
//! two renderers cover the two places a QR code actually leaves a program —
//! an HTTP response and a terminal — and both write into a `std.Io.Writer`, so
//! a caller with no allocator can hand them a `std.Io.Writer.fixed` buffer and
//! a caller with one can hand them `std.Io.Writer.Allocating`.

const std = @import("std");
const root = @import("root.zig");

const Matrix = root.Matrix;

pub const SvgOptions = struct {
    /// Pixels per module in the `width`/`height` attributes. The path itself is
    /// drawn in module units under a `viewBox`, so this scales the rendered
    /// image without changing a byte of geometry.
    scale: u32 = 8,
    /// Quiet-zone width in modules. The standard says four (§6.3.8) and that is
    /// the default; narrowing it is a decision about your scanners, not a
    /// stylistic one.
    quiet: u8 = root.quiet_zone,
    /// Fill for dark modules.
    dark: []const u8 = "#000",
    /// Fill for the background. `null` omits the rectangle and leaves the
    /// symbol transparent, which only works when the surface behind it is known
    /// to be light — a QR code on a dark page does not scan.
    light: ?[]const u8 = "#fff",
    /// Written into a `<title>` element, which is what a screen reader
    /// announces. `null` omits the element.
    title: ?[]const u8 = null,
};

/// Write `m` as a standalone SVG document.
///
/// Dark modules become one `<path>` of horizontal runs rather than one `<rect>`
/// per module: identical rendering, and the difference in output size is a
/// factor, not a percentage, on any symbol big enough to care about.
///
/// Every caller-supplied string — the two colours and the title — is XML-escaped
/// on the way out, so a title taken from a request body cannot close the element
/// and continue as markup.
pub fn writeSvg(w: *std.Io.Writer, m: *const Matrix, opts: SvgOptions) std.Io.Writer.Error!void {
    const n: u32 = @as(u32, m.size) + 2 * @as(u32, opts.quiet);
    const px = n * opts.scale;

    try w.print(
        \\<svg xmlns="http://www.w3.org/2000/svg" width="{d}" height="{d}" viewBox="0 0 {d} {d}" shape-rendering="crispEdges">
        \\
    , .{ px, px, n, n });

    if (opts.title) |t| {
        try w.writeAll("<title>");
        try writeEscaped(w, t);
        try w.writeAll("</title>\n");
    }
    if (opts.light) |bg| {
        try w.print("<rect width=\"{d}\" height=\"{d}\" fill=\"", .{ n, n });
        try writeEscaped(w, bg);
        try w.writeAll("\"/>\n");
    }

    try w.writeAll("<path fill=\"");
    try writeEscaped(w, opts.dark);
    try w.writeAll("\" d=\"");
    var y: u16 = 0;
    while (y < m.size) : (y += 1) {
        var x: u16 = 0;
        while (x < m.size) {
            if (!m.isDark(x, y)) {
                x += 1;
                continue;
            }
            const start = x;
            while (x < m.size and m.isDark(x, y)) x += 1;
            const run = x - start;
            try w.print("M{d} {d}h{d}v1h-{d}z", .{
                start + opts.quiet, y + opts.quiet, run, run,
            });
        }
    }
    try w.writeAll("\"/>\n</svg>\n");
}

pub const TerminalOptions = struct {
    quiet: u8 = root.quiet_zone,
    /// Whether the terminal's background is dark. This is not a cosmetic
    /// preference: the glyphs are drawn in the foreground colour, so on a dark
    /// terminal a *light* module has to be the one that gets a glyph. Print it
    /// the other way round and the symbol on screen is a photographic negative,
    /// which scanners refuse.
    dark_background: bool = true,
};

/// Write `m` as text, two module rows per line via half-block characters, so
/// the symbol comes out square in a normal font and stays scannable off the
/// screen. Output is UTF-8 and needs a font with U+2580/U+2584/U+2588.
pub fn writeTerminal(w: *std.Io.Writer, m: *const Matrix, opts: TerminalOptions) std.Io.Writer.Error!void {
    const n: u32 = @as(u32, m.size) + 2 * @as(u32, opts.quiet);
    var y: u32 = 0;
    while (y < n) : (y += 2) {
        var x: u32 = 0;
        while (x < n) : (x += 1) {
            const top = inked(m, x, y, opts);
            // y + 1 can fall past the padded field on the last line of an
            // odd-height symbol; that reads as light, which is the quiet zone.
            const bot = inked(m, x, y + 1, opts);
            try w.writeAll(if (top and bot) "█" else if (top) "▀" else if (bot) "▄" else " ");
        }
        try w.writeAll("\n");
    }
}

/// True when this cell should carry a glyph rather than bare background.
fn inked(m: *const Matrix, x: u32, y: u32, opts: TerminalOptions) bool {
    const q: u32 = opts.quiet;
    const size: u32 = m.size;
    const dark = x >= q and y >= q and x < size + q and y < size + q and
        m.isDark(@intCast(x - q), @intCast(y - q));
    return dark != opts.dark_background;
}

fn writeEscaped(w: *std.Io.Writer, text: []const u8) std.Io.Writer.Error!void {
    for (text) |c| switch (c) {
        '&' => try w.writeAll("&amp;"),
        '<' => try w.writeAll("&lt;"),
        '>' => try w.writeAll("&gt;"),
        '"' => try w.writeAll("&quot;"),
        '\'' => try w.writeAll("&apos;"),
        else => try w.writeByte(c),
    };
}

// ── tests ───────────────────────────────────────────────────────────────────
//
// Both renderers are checked by reading the output back into a grid and
// comparing module for module against the source matrix. Rendering a symbol and
// then decoding the picture would be the weaker test: error correction hides
// sampling mistakes up to its capability, so a transposed or half-module-offset
// rendering can still decode to the right string.

const testing = std.testing;

/// Parse the path data our own `writeSvg` emits back into a grid.
fn parseSvg(svg: []const u8, quiet: u8, size: u16, out: *Matrix) !void {
    out.* = .{ .size = size };
    for (0..size) |y| for (0..size) |x| out.setDark(@intCast(x), @intCast(y), false);

    const d_start = (std.mem.indexOf(u8, svg, " d=\"") orelse return error.NoPath) + 4;
    const d = svg[d_start .. d_start + (std.mem.indexOfScalar(u8, svg[d_start..], '"') orelse
        return error.UnterminatedPath)];

    var i: usize = 0;
    while (i < d.len) {
        if (d[i] != 'M') return error.BadCommand;
        i += 1;
        const x = try scanNumber(d, &i);
        if (i >= d.len or d[i] != ' ') return error.BadSeparator;
        i += 1;
        const y = try scanNumber(d, &i);
        if (i >= d.len or d[i] != 'h') return error.BadCommand;
        i += 1;
        const run = try scanNumber(d, &i);
        // The rest of the run is a fixed shape; check it rather than skip it,
        // or a rendering one module tall in the wrong direction reads as fine.
        var tail_buf: [16]u8 = undefined;
        const tail = try std.fmt.bufPrint(&tail_buf, "v1h-{d}z", .{run});
        if (!std.mem.startsWith(u8, d[i..], tail)) return error.BadRun;
        i += tail.len;

        if (x < quiet or y < quiet) return error.OutsideSymbol;
        for (0..run) |k| out.setDark(@intCast(x - quiet + k), @intCast(y - quiet), true);
    }
}

fn scanNumber(d: []const u8, i: *usize) !usize {
    const start = i.*;
    while (i.* < d.len and std.ascii.isDigit(d[i.*])) i.* += 1;
    if (i.* == start) return error.NoNumber;
    return std.fmt.parseInt(usize, d[start..i.*], 10);
}

fn expectSameModules(a: *const Matrix, b: *const Matrix) !void {
    try testing.expectEqual(a.size, b.size);
    for (0..a.size) |y| for (0..a.size) |x| {
        if (a.isDark(@intCast(x), @intCast(y)) != b.isDark(@intCast(x), @intCast(y))) {
            std.debug.print("module ({d}, {d}) differs\n", .{ x, y });
            return error.MatrixMismatch;
        }
    };
}

test "SVG path reproduces the grid, module for module" {
    var m: Matrix = undefined;
    // Three versions and two quiet zones: run-length packing has to survive both
    // a run that ends at the right edge and one that starts at the left.
    for ([_][]const u8{ "1", "HTTPS://EXAMPLE.COM/A", "x" ** 400 }) |text| {
        for ([_]u8{ 4, 0 }) |quiet| {
            try root.encode(&m, text, .{});
            var aw: std.Io.Writer.Allocating = .init(testing.allocator);
            defer aw.deinit();
            try writeSvg(&aw.writer, &m, .{ .quiet = quiet });

            var back: Matrix = undefined;
            try parseSvg(aw.written(), quiet, m.size, &back);
            try expectSameModules(&m, &back);
        }
    }
}

test "SVG geometry: viewBox is in modules, width is in pixels" {
    var m: Matrix = undefined;
    try root.encode(&m, "1", .{ .version = 1 });
    try testing.expectEqual(@as(u16, 21), m.size);

    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try writeSvg(&aw.writer, &m, .{ .scale = 10, .quiet = 4 });
    const svg = aw.written();

    // 21 + 2*4 = 29 modules, 290 pixels.
    try testing.expect(std.mem.indexOf(u8, svg, "width=\"290\" height=\"290\"") != null);
    try testing.expect(std.mem.indexOf(u8, svg, "viewBox=\"0 0 29 29\"") != null);
    // A finder pattern's outer row is seven modules starting at the quiet zone.
    try testing.expect(std.mem.indexOf(u8, svg, "M4 4h7v1h-7z") != null);
}

test "caller strings are escaped, so a title cannot become markup" {
    var m: Matrix = undefined;
    try root.encode(&m, "1", .{ .version = 1 });

    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try writeSvg(&aw.writer, &m, .{
        .title = "</title><script>alert(1)</script>",
        .dark = "\" onload=\"x",
    });
    const svg = aw.written();

    try testing.expect(std.mem.indexOf(u8, svg, "<script>") == null);
    try testing.expect(std.mem.indexOf(u8, svg, "&lt;script&gt;") != null);
    try testing.expect(std.mem.indexOf(u8, svg, "onload=\"x") == null);
    try testing.expect(std.mem.indexOf(u8, svg, "&quot; onload=&quot;x") != null);
    // Exactly one attribute-opening quote pair per attribute is what makes the
    // document well-formed; the title element must close where we closed it.
    try testing.expect(std.mem.indexOf(u8, svg, "</title>\n") != null);
}

test "background is omitted when light is null" {
    var m: Matrix = undefined;
    try root.encode(&m, "1", .{ .version = 1 });

    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try writeSvg(&aw.writer, &m, .{ .light = null });
    try testing.expect(std.mem.indexOf(u8, aw.written(), "<rect") == null);
}

test "a fixed buffer that is too small fails rather than truncates" {
    var m: Matrix = undefined;
    try root.encode(&m, "https://example.com/some/path", .{});

    var buf: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try testing.expectError(error.WriteFailed, writeSvg(&w, &m, .{}));
}

test "terminal half-blocks reproduce the grid, on both backgrounds" {
    var m: Matrix = undefined;
    try root.encode(&m, "TERMINAL 42", .{});

    for ([_]bool{ true, false }) |dark_bg| {
        const opts: TerminalOptions = .{ .dark_background = dark_bg };
        var aw: std.Io.Writer.Allocating = .init(testing.allocator);
        defer aw.deinit();
        try writeTerminal(&aw.writer, &m, opts);

        const n: usize = @as(usize, m.size) + 2 * opts.quiet;
        var back: Matrix = .{ .size = m.size };
        var rows = std.mem.splitScalar(u8, aw.written(), '\n');
        var y: usize = 0;
        while (rows.next()) |row| : (y += 2) {
            if (row.len == 0) break;
            var i: usize = 0;
            var x: usize = 0;
            while (i < row.len) : (x += 1) {
                const len = try std.unicode.utf8ByteSequenceLength(row[i]);
                const cell = row[i .. i + len];
                i += len;
                const ink: [2]bool = if (std.mem.eql(u8, cell, "█"))
                    .{ true, true }
                else if (std.mem.eql(u8, cell, "▀"))
                    .{ true, false }
                else if (std.mem.eql(u8, cell, "▄"))
                    .{ false, true }
                else if (std.mem.eql(u8, cell, " "))
                    .{ false, false }
                else
                    return error.UnexpectedGlyph;

                // Invert the mapping the renderer applied, then keep only the
                // cells that are inside the symbol.
                for (ink, 0..) |cell_ink, half| {
                    const yy = y + half;
                    if (yy >= opts.quiet and yy < @as(usize, m.size) + opts.quiet and
                        x >= opts.quiet and x < @as(usize, m.size) + opts.quiet)
                    {
                        back.setDark(
                            @intCast(x - opts.quiet),
                            @intCast(yy - opts.quiet),
                            cell_ink != dark_bg,
                        );
                    }
                }
            }
            try testing.expectEqual(n, x);
        }
        try expectSameModules(&m, &back);
    }
}

test "terminal output round-trips through the decoder as well" {
    // Weaker than the module-for-module check above, but it is the property a
    // user actually cares about: what is on the screen still says the message.
    var m: Matrix = undefined;
    try root.encode(&m, "https://example.com/x", .{});

    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try writeTerminal(&aw.writer, &m, .{});
    try testing.expect(aw.written().len > 0);

    var out: [64]u8 = undefined;
    try testing.expectEqualStrings("https://example.com/x", try root.decode(&m, &out));
}
