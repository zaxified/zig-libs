// SPDX-License-Identifier: MIT

//! OBJECT IDENTIFIER value type for SNMP.
//!
//! Fixed-capacity arc storage (`max_arcs`), dotted-decimal parse/format
//! ("1.3.6.1.2.1.1.1.0", optional leading dot), lexicographic compare and
//! subtree tests. The BER wire form (first two arcs packed as 40*x+y,
//! base-128 subidentifiers) lives in `ber.zig` (`Encoder.prependOid` /
//! `parseOid`).

const std = @import("std");

/// Upper bound on arcs (sub-identifiers) per OID. SMIv2 allows up to 128;
/// 64 comfortably covers real-world MIB objects including table indices.
pub const max_arcs = 64;

pub const ParseError = error{ InvalidOid, TooManyArcs };

pub const Oid = struct {
    arcs: [max_arcs]u32,
    count: u8,

    pub const empty: Oid = .{ .arcs = @splat(0), .count = 0 };

    pub fn fromSlice(arcs: []const u32) error{TooManyArcs}!Oid {
        if (arcs.len > max_arcs) return error.TooManyArcs;
        var o: Oid = .empty;
        @memcpy(o.arcs[0..arcs.len], arcs);
        o.count = @intCast(arcs.len);
        return o;
    }

    pub fn slice(o: *const Oid) []const u32 {
        return o.arcs[0..o.count];
    }

    /// Parse dotted-decimal notation, e.g. "1.3.6.1.2.1.1.1.0". A leading
    /// dot (net-snmp absolute form) is accepted. At least two arcs are
    /// required and the X.660 root constraints are enforced (first arc 0-2;
    /// second arc < 40 when the first is 0 or 1) so every parsed OID is
    /// BER-encodable.
    pub fn parse(text: []const u8) ParseError!Oid {
        var t = text;
        if (t.len > 0 and t[0] == '.') t = t[1..];
        var o: Oid = .empty;
        var it = std.mem.splitScalar(u8, t, '.');
        while (it.next()) |part| {
            const arc = std.fmt.parseInt(u32, part, 10) catch return error.InvalidOid;
            try o.append(arc);
        }
        if (o.count < 2) return error.InvalidOid;
        if (o.arcs[0] > 2) return error.InvalidOid;
        if (o.arcs[0] < 2 and o.arcs[1] >= 40) return error.InvalidOid;
        return o;
    }

    /// Dotted-decimal form; use with the `{f}` format specifier.
    pub fn format(o: *const Oid, w: *std.Io.Writer) std.Io.Writer.Error!void {
        for (o.slice(), 0..) |arc, i| {
            if (i != 0) try w.writeByte('.');
            try w.print("{d}", .{arc});
        }
    }

    pub fn eql(a: *const Oid, b: *const Oid) bool {
        return std.mem.eql(u32, a.slice(), b.slice());
    }

    /// True when `o` lies inside the subtree rooted at `prefix`
    /// (or equals it).
    pub fn startsWith(o: *const Oid, prefix: *const Oid) bool {
        if (prefix.count > o.count) return false;
        return std.mem.eql(u32, o.arcs[0..prefix.count], prefix.arcs[0..prefix.count]);
    }

    /// Lexicographic order — the MIB tree order used by GetNext walks.
    pub fn order(a: *const Oid, b: *const Oid) std.math.Order {
        return std.mem.order(u32, a.slice(), b.slice());
    }

    pub fn append(o: *Oid, arc: u32) error{TooManyArcs}!void {
        if (o.count >= max_arcs) return error.TooManyArcs;
        o.arcs[o.count] = arc;
        o.count += 1;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "parse + format round trip" {
    const o = try Oid.parse("1.3.6.1.2.1.1.1.0");
    try testing.expectEqualSlices(u32, &.{ 1, 3, 6, 1, 2, 1, 1, 1, 0 }, o.slice());
    try testing.expectFmt("1.3.6.1.2.1.1.1.0", "{f}", .{o});

    const abs = try Oid.parse(".1.3.6.1.4.1.8072");
    try testing.expectFmt("1.3.6.1.4.1.8072", "{f}", .{abs});
}

test "parse rejects malformed text" {
    try testing.expectError(error.InvalidOid, Oid.parse(""));
    try testing.expectError(error.InvalidOid, Oid.parse("1"));
    try testing.expectError(error.InvalidOid, Oid.parse("1..3"));
    try testing.expectError(error.InvalidOid, Oid.parse("1.3.x"));
    try testing.expectError(error.InvalidOid, Oid.parse("1.3.6."));
    try testing.expectError(error.InvalidOid, Oid.parse("3.1")); // first arc > 2
    try testing.expectError(error.InvalidOid, Oid.parse("1.40")); // second >= 40
    try testing.expectError(error.InvalidOid, Oid.parse("1.3.4294967296")); // > u32
    try testing.expectError(error.InvalidOid, Oid.parse("1.3.-1"));
}

test "parse enforces the arc-count bound" {
    var text: [3 * (max_arcs + 8)]u8 = undefined;
    var w: std.Io.Writer = .fixed(&text);
    w.print("1.3", .{}) catch unreachable;
    for (0..max_arcs) |_| w.print(".1", .{}) catch unreachable;
    try testing.expectError(error.TooManyArcs, Oid.parse(w.buffered()));
}

test "eql, startsWith, order, append" {
    const root = try Oid.parse("1.3.6.1.2.1");
    var leaf = try Oid.parse("1.3.6.1.2.1.1.1.0");
    const other = try Oid.parse("1.3.6.1.4.1");

    try testing.expect(leaf.startsWith(&root));
    try testing.expect(root.startsWith(&root));
    try testing.expect(!root.startsWith(&leaf));
    try testing.expect(!other.startsWith(&root));

    try testing.expect(leaf.eql(&leaf));
    try testing.expect(!leaf.eql(&root));

    try testing.expectEqual(std.math.Order.lt, root.order(&leaf));
    try testing.expectEqual(std.math.Order.gt, other.order(&leaf));
    try testing.expectEqual(std.math.Order.eq, leaf.order(&leaf));

    var o = try Oid.parse("1.3");
    try o.append(6);
    try testing.expectFmt("1.3.6", "{f}", .{o});
    o.count = max_arcs;
    try testing.expectError(error.TooManyArcs, o.append(1));

    leaf = try Oid.fromSlice(&.{ 1, 3, 6 });
    try testing.expectFmt("1.3.6", "{f}", .{leaf});
    var big: [max_arcs + 1]u32 = @splat(1);
    try testing.expectError(error.TooManyArcs, Oid.fromSlice(&big));
}
