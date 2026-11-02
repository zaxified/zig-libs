//! What the screen shows, as pure functions of the data: no terminal, no
//! threads, so all of it is tested by the `test` blocks below.
const std = @import("std");
const netaddr = @import("netaddr");
const traceroute = @import("traceroute");

const MtrHop = traceroute.MtrHop;
const Probe = traceroute.Probe;
const Writer = std.Io.Writer;

// ── input ───────────────────────────────────────────────────────────────────

pub const Key = enum { quit, reset, names, pause };

/// The commands in one read from the terminal. An escape sequence is dropped
/// whole: F4 arrives as `ESC O S`, and some keypad keys as `ESC O q`, whose
/// last byte must not quit.
pub const KeyIter = struct {
    bytes: []const u8,

    pub fn next(it: *KeyIter) ?Key {
        while (it.bytes.len > 0) {
            const c = it.bytes[0];
            it.bytes = it.bytes[1..];
            switch (c) {
                0x1b => it.bytes = it.bytes[escapeLen(it.bytes)..],
                'q', 'Q', 0x03 => return .quit,
                'r', 'R' => return .reset,
                'n', 'N' => return .names,
                'p', 'P' => return .pause,
                else => {},
            }
        }
        return null;
    }

    /// The bytes of an escape sequence after its ESC.
    fn escapeLen(b: []const u8) usize {
        if (b.len == 0) return 0;
        switch (b[0]) {
            'O' => return @min(b.len, 2),
            '[' => {
                for (b[1..], 1..) |c, i| {
                    if (c >= 0x40 and c <= 0x7e) return i + 1;
                }
                return b.len;
            },
            else => return 0,
        }
    }
};

// ── text from the network ───────────────────────────────────────────────────

/// A PTR record is written by whoever owns the address, and this goes to a
/// terminal: anything outside a host name's alphabet becomes `?`, so a hostile
/// name cannot carry an escape sequence onto the screen.
pub fn sanitize(out: []u8, raw: []const u8) []const u8 {
    const n = @min(out.len, raw.len);
    for (raw[0..n], out[0..n]) |c, *o| {
        o.* = switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '.', '-', '_', ':' => c,
            else => '?',
        };
    }
    return out[0..n];
}

// ── the table ───────────────────────────────────────────────────────────────

pub const Row = struct {
    hop: MtrHop,
    /// This round's answer, before the round's end counts it.
    live: ?Probe = null,
    /// Already sanitized.
    name: ?[]const u8 = null,

    fn address(r: Row) ?netaddr.Ip {
        if (r.live) |p| {
            if (p.address) |a| return a;
        }
        return r.hop.address;
    }

    fn lastNs(r: Row) ?u64 {
        if (r.live) |p| {
            if (p.rtt_ns) |t| return t;
        }
        return r.hop.last_ns;
    }
};

/// How many rows to draw: the counted hops, and this round's answers up to
/// the first one that ends the path. TTLs past the destination answer too
/// during the first round, and those are not hops.
pub fn rowCount(counted: usize, live: []const ?Probe) usize {
    var n = counted;
    for (live, 0..) |slot, i| {
        const p = slot orelse continue;
        n = @max(n, i + 1);
        if (p.kind == .reply or p.kind == .dest_unreachable) break;
    }
    return n;
}

pub const Layout = struct {
    /// Columns a line is cut to.
    width: usize,
    host: usize,
    stats: Stats,

    const Stats = enum { none, compact, full };
    const hop_w = 5;
    const full_w = 47;
    const compact_w = 26;
    const max_line = 1024;

    /// The columns that fit: every statistic, the commonest ones, or only the
    /// host when the window is that narrow.
    pub fn forWidth(width: usize) Layout {
        if (width >= hop_w + 24 + full_w) return .{ .width = width, .host = @min(width, max_line) - hop_w - full_w, .stats = .full };
        if (width >= hop_w + 14 + compact_w) return .{ .width = width, .host = width - hop_w - compact_w, .stats = .compact };
        return .{ .width = width, .host = width -| hop_w, .stats = .none };
    }

    /// A report has no window: the host column fits the longest host.
    pub fn forHosts(longest: usize) Layout {
        const host = std.math.clamp(longest, 24, max_line - hop_w - full_w);
        return .{ .width = max_line, .host = host, .stats = .full };
    }
};

fn writeClipped(w: *Writer, width: usize, line: []const u8) Writer.Error!void {
    try w.writeAll(line[0..@min(width, line.len)]);
}

fn pad(w: *Writer, n: usize) Writer.Error!void {
    try w.splatByteAll(' ', n);
}

fn right(w: *Writer, width: usize, text: []const u8) Writer.Error!void {
    try pad(w, width -| text.len);
    try w.writeAll(text);
}

fn writeMs(w: *Writer, width: usize, ns: ?u64) Writer.Error!void {
    const v = ns orelse return right(w, width, "-");
    const tenths = (v +| 50_000) / 100_000;
    var b: [32]u8 = undefined;
    const text = std.mem.print(&b, "{d}.{d}", .{ tenths / 10, tenths % 10 }) catch unreachable; // 20 digits at most
    try right(w, width, text);
}

pub fn writeHeader(w: *Writer, l: Layout) Writer.Error!void {
    var b: [Layout.max_line]u8 = undefined;
    var lw: Writer = .fixed(&b);
    lw.writeAll(" Hop Host") catch {};
    pad(&lw, l.host -| 4) catch {};
    switch (l.stats) {
        .none => {},
        .compact => lw.writeAll("  Loss%  Snt   Last    Avg") catch {},
        .full => lw.writeAll("  Loss%  Snt   Last    Avg   Best   Wrst  StDev") catch {},
    }
    try writeClipped(w, l.width, lw.buffered());
}

/// The host column's text: the name or the address, how many other routers
/// answered at this TTL, and the code of a Destination Unreachable.
pub fn hostText(out: []u8, r: Row, show_names: bool) []const u8 {
    var w: Writer = .fixed(out);
    if (r.address()) |a| {
        if (show_names and r.name != null) {
            w.print("{s} ({f})", .{ r.name.?, a }) catch {};
        } else {
            w.print("{f}", .{a}) catch {};
        }
    } else {
        w.writeAll("???") catch {};
    }
    if (r.hop.address_count > 1) w.print(" +{d}", .{r.hop.address_count - 1}) catch {};
    const code: ?u8 = if (r.live) |p| (if (p.kind == .dest_unreachable) p.code else r.hop.unreachable_code) else r.hop.unreachable_code;
    if (code) |c| w.print(" !{d}", .{c}) catch {};
    return w.buffered();
}

pub fn writeRow(w: *Writer, l: Layout, r: Row, show_names: bool) Writer.Error!void {
    var b: [Layout.max_line]u8 = undefined;
    var lw: Writer = .fixed(&b);
    var hb: [512]u8 = undefined;
    const host = hostText(&hb, r, show_names);
    lw.print("{d:>3}. ", .{r.hop.ttl}) catch {};
    lw.writeAll(host[0..@min(host.len, l.host)]) catch {};
    pad(&lw, l.host -| host.len) catch {};
    const h = r.hop;
    if (l.stats != .none) {
        const permille = h.lossPermille();
        var pb: [16]u8 = undefined;
        // Before the first counted probe there is no loss to speak of.
        const loss = if (h.sent == 0) "-" else std.mem.print(&pb, "{d}.{d}%", .{ permille / 10, permille % 10 }) catch unreachable;
        right(&lw, 7, loss) catch {};
        var sb: [16]u8 = undefined;
        right(&lw, 5, std.mem.print(&sb, "{d}", .{h.sent}) catch unreachable) catch {};
        writeMs(&lw, 7, r.lastNs()) catch {};
        writeMs(&lw, 7, h.avgNs()) catch {};
    }
    if (l.stats == .full) {
        writeMs(&lw, 7, h.best_ns) catch {};
        writeMs(&lw, 7, h.worst_ns) catch {};
        writeMs(&lw, 7, h.stddevNs()) catch {};
    }
    try writeClipped(w, l.width, lw.buffered());
}

// ── one screenful ───────────────────────────────────────────────────────────

pub const Frame = struct {
    target: []const u8,
    address: netaddr.Ip,
    method: []const u8,
    rounds: u64,
    paused: bool,
    show_names: bool,
    /// Why the last round failed, when it did.
    failure: ?[]const u8 = null,
    rows: []const Row,
    width: usize,
    height: usize,
};

/// Moves to the top left and overwrites, each line clearing only what is left
/// of it: nothing is erased first, so nothing flickers. The last line has no
/// line break, so a window of exactly this height does not scroll.
pub fn writeFrame(w: *Writer, f: Frame) Writer.Error!void {
    try w.writeAll("\x1b[H");
    var line: usize = 0;
    // One column short of the window: with the cursor past a full line, the
    // terminal's erase-to-end-of-line takes the line's last character with it.
    const cols = f.width -| 1;
    const l = Layout.forWidth(cols);
    const fixed_lines = 3;
    const shown = @min(f.rows.len, f.height -| fixed_lines);

    var b: [Layout.max_line]u8 = undefined;
    var lw: Writer = .fixed(&b);
    lw.print("tiny-mtr  {s} ({f})  {s}  rounds {d}", .{ f.target, f.address, f.method, f.rounds }) catch {};
    if (f.paused) lw.writeAll("  [paused]") catch {};
    if (try beginLine(w, &line, f.height)) try writeClipped(w, cols, lw.buffered());

    lw = .fixed(&b);
    if (f.failure) |why| {
        lw.print("round failed: {s}", .{why}) catch {};
    } else {
        lw.print("q quit  r reset  n names {s}  p pause", .{if (f.show_names) "on" else "off"}) catch {};
    }
    if (try beginLine(w, &line, f.height)) try writeClipped(w, cols, lw.buffered());

    if (try beginLine(w, &line, f.height)) try writeHeader(w, l);
    for (f.rows[0..shown], 0..) |r, i| {
        _ = try beginLine(w, &line, f.height);
        if (i + 1 == shown and shown < f.rows.len) {
            lw = .fixed(&b);
            lw.print("     ... {d} more hops, the window is too low", .{f.rows.len - shown + 1}) catch {};
            try writeClipped(w, cols, lw.buffered());
        } else {
            try writeRow(w, l, r, f.show_names);
        }
    }
    try w.writeAll("\x1b[K\x1b[J");
}

/// Ends the line before, if any. False once the window is full.
fn beginLine(w: *Writer, line: *usize, height: usize) Writer.Error!bool {
    if (line.* >= height) return false;
    if (line.* > 0) try w.writeAll("\x1b[K\r\n");
    line.* += 1;
    return true;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn testHop(ttl: u8) MtrHop {
    var h: MtrHop = .{ .ttl = ttl, .sent = 4, .received = 3, .last_ns = 1_250_000, .best_ns = 1_000_000, .worst_ns = 2_000_000, .sum_ns = 4_500_000 };
    h.address = netaddr.parseIp("192.0.2.1").?;
    h.addresses[0] = h.address.?;
    h.address_count = 1;
    return h;
}

test "keys: commands, and an escape sequence never reads as one" {
    var it: KeyIter = .{ .bytes = "qxr\x03nP" };
    const want = [_]Key{ .quit, .reset, .quit, .names, .pause };
    for (want) |k| try testing.expectEqual(k, it.next().?);
    try testing.expect(it.next() == null);

    // F4, an arrow, a keypad `ESC O q`, a CSI with parameters ending in `r`.
    for ([_][]const u8{ "\x1bOS", "\x1b[A", "\x1bOq", "\x1b[1;24r", "\x1b", "\x1b[" }) |seq| {
        var e: KeyIter = .{ .bytes = seq };
        try testing.expect(e.next() == null);
    }
    var after: KeyIter = .{ .bytes = "\x1b[Aq" };
    try testing.expectEqual(Key.quit, after.next().?);
}

test "a hostile name cannot put an escape sequence on the terminal" {
    var b: [64]u8 = undefined;
    try testing.expectEqualStrings("ok-1.example.net", sanitize(&b, "ok-1.example.net"));
    try testing.expectEqualStrings("??2Jevil?.?", sanitize(&b, "\x1b[2Jevil\r.\xff"));
    var short: [3]u8 = undefined;
    try testing.expectEqualStrings("abc", sanitize(&short, "abcdef"));
}

test "rowCount stops at the first answer that ends the path" {
    var live: [6]?Probe = @splat(null);
    try testing.expectEqual(@as(usize, 0), rowCount(0, &live));
    live[1] = .{ .kind = .time_exceeded };
    try testing.expectEqual(@as(usize, 2), rowCount(0, &live));
    // The destination at TTL 3 and again at 4 and 5.
    live[2] = .{ .kind = .reply };
    live[3] = .{ .kind = .reply };
    live[4] = .{ .kind = .reply };
    try testing.expectEqual(@as(usize, 3), rowCount(0, &live));
    // Counted hops stay, whatever this round has seen so far.
    try testing.expectEqual(@as(usize, 5), rowCount(5, &live));
}

test "rows: every width stays inside its window" {
    var buf: [2048]u8 = undefined;
    for ([_]usize{ 0, 1, 4, 5, 20, 44, 45, 75, 76, 80, 200, 1100, 5000 }) |width| {
        const l = Layout.forWidth(width);
        var w: Writer = .fixed(&buf);
        try writeRow(&w, l, .{ .hop = testHop(7), .name = "a-long-router-name.example.net" }, true);
        try testing.expect(w.buffered().len <= width);
        w = .fixed(&buf);
        try writeHeader(&w, l);
        try testing.expect(w.buffered().len <= width);
    }
    // A window wider than a line's buffer still gets every column.
    var wide: Writer = .fixed(&buf);
    try writeHeader(&wide, Layout.forWidth(5000));
    try testing.expect(std.mem.endsWith(u8, wide.buffered(), "StDev"));
    var w: Writer = .fixed(&buf);
    try writeRow(&w, Layout.forWidth(80), .{ .hop = testHop(7) }, false);
    try testing.expectEqualStrings(
        "  7. 192.0.2.1                     25.0%    4    1.3    1.5    1.0    2.0    0.0",
        w.buffered(),
    );
}

test "rows: a live answer shows before the round counts it; ??? and -" {
    var buf: [256]u8 = undefined;
    var w: Writer = .fixed(&buf);
    const a = netaddr.parseIp("198.51.100.9").?;
    try writeRow(&w, Layout.forWidth(80), .{ .hop = .{ .ttl = 2 }, .live = .{ .kind = .time_exceeded, .address = a, .rtt_ns = 3_000_000 } }, false);
    try testing.expectEqualStrings(
        "  2. 198.51.100.9                      -    0    3.0      -      -      -      -",
        w.buffered(),
    );
    w = .fixed(&buf);
    try writeRow(&w, Layout.forWidth(80), .{ .hop = .{ .ttl = 3, .sent = 2 } }, false);
    try testing.expectEqualStrings(
        "  3. ???                          100.0%    2      -      -      -      -      -",
        w.buffered(),
    );
}

test "host text: name only when shown, other routers, unreachable code" {
    var b: [128]u8 = undefined;
    var h = testHop(1);
    h.addresses[1] = netaddr.parseIp("192.0.2.2").?;
    h.address_count = 2;
    h.unreachable_code = 13;
    try testing.expectEqualStrings("r1.example (192.0.2.1) +1 !13", hostText(&b, .{ .hop = h, .name = "r1.example" }, true));
    try testing.expectEqualStrings("192.0.2.1 +1 !13", hostText(&b, .{ .hop = h, .name = "r1.example" }, false));
}

fn frameFor(buf: []u8, rows: []const Row, width: usize, height: usize) ![]const u8 {
    var w: Writer = .fixed(buf);
    try writeFrame(&w, .{
        .target = "example.net",
        .address = netaddr.parseIp("192.0.2.1").?,
        .method = "icmp",
        .rounds = 3,
        .paused = false,
        .show_names = false,
        .rows = rows,
        .width = width,
        .height = height,
    });
    return w.buffered();
}

test "frame: never more lines than the window, and the cut is announced" {
    var rows: [30]Row = undefined;
    for (&rows, 1..) |*r, ttl| r.* = .{ .hop = testHop(@intCast(ttl)) };
    var buf: [16384]u8 = undefined;
    for ([_]usize{ 0, 1, 2, 3, 4, 10, 33, 40 }) |height| {
        const f = try frameFor(&buf, &rows, 80, height);
        const breaks = std.mem.countScalar(u8, f, '\n');
        try testing.expect(breaks + 1 <= @max(height, 1));
    }
    const low = try frameFor(&buf, &rows, 80, 10);
    try testing.expect(std.mem.find(u8, low, "24 more hops") != null);
    const tall = try frameFor(&buf, &rows, 80, 40);
    try testing.expect(std.mem.find(u8, tall, "more hops") == null);
    // No line fills the window: the erase after it would eat its last column.
    var lines = std.mem.splitSequence(u8, tall, "\x1b[K\r\n");
    while (lines.next()) |text| try testing.expect(text.len <= 3 + 79 + 6);
    var line_buf: [256]u8 = undefined;
    var clipped: Writer = .fixed(&line_buf);
    try writeRow(&clipped, Layout.forWidth(79), rows[0], false);
    try testing.expect(std.mem.find(u8, tall, clipped.buffered()) != null);
    // Clears what an earlier, longer frame left, and starts at the top.
    try testing.expect(std.mem.startsWith(u8, tall, "\x1b[H"));
    try testing.expect(std.mem.endsWith(u8, tall, "\x1b[K\x1b[J"));
}
