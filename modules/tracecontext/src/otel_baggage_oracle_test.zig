// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor for `baggage.zig`: OpenTelemetry Go's
//! `baggage.Parse` (otel v1.46.0, Apache-2.0) as an independent
//! implementation. The header values are ours (`tools/go_oracle/baggage.go`:
//! spec examples, OWS variants, properties, percent-encoding incl. invalid
//! escapes and non-UTF-8, empty members, duplicate keys, 64/65 members,
//! 8192/8193 bytes, every single-character substitution and deletion in one
//! valid header); what otel answers is in `otel_baggage_vectors.zig`: error or
//! not, the members it returned (also next to an error), and its
//! re-serialization. otel keeps members in a map, so their order is not an
//! answer; the vectors hold them sorted by key.
//!
//! Every case is parsed by `Baggage.parse` and `Baggage.parseLenient` and
//! compared with otel:
//!  - strict accepts exactly what otel accepts;
//!  - an accepted list has the same members, values and properties, and
//!    `write` gives the same text (members compared as a set);
//!  - when otel returns an error it still returns the members it could use
//!    (it drops the bad one): `parseLenient` must keep the same members.
//! Only otel's observable answers were recorded; no otel source was read.
//! A case answered differently must fall in one of `Class`, each decided by
//! the W3C text (W3C CR Snapshot 30 May 2024, section numbers below), and a
//! class nothing falls in any more fails the test: delete it.

const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const baggage = @import("baggage.zig");
const Baggage = baggage.Baggage;
const vectors = @import("otel_baggage_vectors.zig");

/// What differs from otel and why the W3C text decides for this module.
const Class = enum {
    /// `a=1;p=%zz`: otel Go refuses a property value with a bad percent escape;
    /// OpenTelemetry Java, JS and Python keep properties as an opaque string and
    /// accept it. §3.3.1.4 gives property keys and values "no specific meaning"
    /// and §3.3.1.3's decoding rule is stated for the list-member value only.
    /// Owner decision: accept it, as wire text (`decodeValue` decodes
    /// one on request).
    property_bad_escape,
    /// `a=1,a=2`: otel keeps the last of equal keys (a map). §3.3.1.1: "Uniqueness
    /// of keys ... is not guaranteed. The order of duplicate entries SHOULD be
    /// preserved when mutating the list"; we keep every entry in order (`get`
    /// returns the last, as otel does).
    duplicate_key,
    /// `a=1;p=%41`: otel percent-decodes property values (`A`); we keep them as on
    /// the wire. §3.3.1.4: "Property keys and values are given no specific
    /// meaning by this specification"; only the list-member value has a
    /// decoding rule (§3.3.1.3). `decodeValue` decodes a property value on
    /// request; the compared text of `write` differs for the same reason.
    property_value_decoded,
    /// A value past 8192 bytes: otel returns no member at all, `parseLenient`
    /// keeps the whole members that end within 8192 bytes. §3.3.2: a platform
    /// "MAY drop list-members until both conditions are met" (its choice which)
    /// and "SHOULD propagate as much baggage information as is reasonable";
    /// "MUST NOT propagate any partial list-members" holds on both sides.
    limit_keeps_prefix,
};
const n_classes = std.enums.values(Class).len;

const Reason = enum { strict_verdict, count, member, string, lenient };

fn isErr(r: anytype) bool {
    return if (r) |_| false else |_| true;
}

fn badEscapeAt(v: []const u8) bool {
    var i: usize = 0;
    while (i < v.len) : (i += 1) {
        if (v[i] != '%') continue;
        if (v.len - i < 3 or !std.ascii.isHex(v[i + 1]) or !std.ascii.isHex(v[i + 2])) return true;
    }
    return false;
}

/// True when a property of some member has a `%` that is not an escape.
fn propertyBadEscape(input: []const u8) bool {
    var it = mem.splitScalar(u8, input, ',');
    while (it.next()) |m| {
        var ps = mem.splitScalar(u8, m, ';');
        _ = ps.next();
        while (ps.next()) |p| {
            const eq = mem.findScalar(u8, p, '=') orelse continue;
            if (badEscapeAt(p[eq + 1 ..])) return true;
        }
    }
    return false;
}

/// `input` with every empty property piece (`;` followed by only OWS up to the
/// next `;` or `,`) removed; null when there was none.
fn withoutEmptyProperties(buf: []u8, input: []const u8) ?[]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    var found = false;
    var it = mem.splitScalar(u8, input, ',');
    var first = true;
    while (it.next()) |m| {
        if (!first) w.writeByte(',') catch unreachable;
        first = false;
        var ps = mem.splitScalar(u8, m, ';');
        w.writeAll(ps.next().?) catch unreachable;
        while (ps.next()) |p| {
            if (mem.trim(u8, p, " \t").len == 0) {
                found = true;
                continue;
            }
            w.writeByte(';') catch unreachable;
            w.writeAll(p) catch unreachable;
        }
    }
    return if (found) w.buffered() else null;
}

const Opt = struct {
    /// Compare our property values percent-decoded (otel decodes them).
    decode: bool = false,
};

fn memberEq(ours: Baggage.Member, theirs: vectors.Member, opt: Opt) bool {
    if (!mem.eql(u8, ours.key, theirs.key) or !mem.eql(u8, ours.value, theirs.value)) return false;
    var it = ours.propertyIterator();
    for (theirs.props) |tp| {
        // otel keeps an empty property it parsed (an empty key); we drop it.
        if (tp.key.len == 0) continue;
        const op = it.next() orelse return false;
        if (!mem.eql(u8, op.key, tp.key)) return false;
        if ((op.value == null) != (tp.value == null)) return false;
        if (op.value) |v| {
            var dec: [baggage.max_len]u8 = undefined;
            const got = if (opt.decode) baggage.decodeValue(v, &dec) catch return false else v;
            if (!mem.eql(u8, got, tp.value.?)) return false;
        }
    }
    return it.next() == null;
}

/// The members of `b` against otel's, as sets keyed by key; null = same. Equal
/// keys count once on our side, as the last of them (otel's map keeps the last).
fn membersDiffer(b: *const Baggage, theirs: []const vectors.Member, opt: Opt) ?Reason {
    var distinct: usize = 0;
    for (b.members(), 0..) |m, i| {
        var later = false;
        for (b.members()[i + 1 ..]) |n| if (mem.eql(u8, n.key, m.key)) {
            later = true;
        };
        if (!later) distinct += 1;
    }
    if (distinct != theirs.len) return .count;
    for (theirs) |t| {
        var last: ?Baggage.Member = null;
        for (b.members()) |m| if (mem.eql(u8, m.key, t.key)) {
            last = m;
        };
        if (last == null or !memberEq(last.?, t, opt)) return .member;
    }
    return if (distinct != b.len) .count else null;
}

/// `write` output with the comma-separated members sorted, the form otel's
/// vectors hold.
fn sortedWrite(out: []u8, b: *const Baggage) []const u8 {
    var tmp: [baggage.max_len + 64]u8 = undefined;
    const text = b.write(&tmp);
    var pieces: [baggage.max_members][]const u8 = undefined;
    var n: usize = 0;
    if (text.len != 0) {
        var it = mem.splitScalar(u8, text, ',');
        while (it.next()) |p| : (n += 1) pieces[n] = p;
    }
    std.mem.sort([]const u8, pieces[0..n], {}, struct {
        fn lt(_: void, a: []const u8, c: []const u8) bool {
            return mem.lessThan(u8, a, c);
        }
    }.lt);
    var w: std.Io.Writer = .fixed(out);
    for (pieces[0..n], 0..) |p, i| {
        if (i != 0) w.writeByte(',') catch unreachable;
        w.writeAll(p) catch unreachable;
    }
    return w.buffered();
}

const Verdict = struct { reason: ?Reason = null, dup: bool = false, decoded: bool = false };

fn judge(c: vectors.Case) !Verdict {
    var scratch: [baggage.max_len]u8 = undefined;
    var scratch2: [baggage.max_len]u8 = undefined;
    var v: Verdict = .{};
    const strict = Baggage.parse(c.input, &scratch);
    if (!c.wire_ok) {
        // A control character: the HTTP layer refuses the request, but a
        // parser handed the bytes must still never accept them.
        try testing.expect(isErr(strict));
        return v;
    }
    if (strict) |b| {
        if (!c.ok) {
            v.reason = .strict_verdict;
        } else if (membersDiffer(&b, c.members, .{})) |r| {
            if (r == .member and membersDiffer(&b, c.members, .{ .decode = true }) == null) {
                v.decoded = true; // the same members once our property values are decoded
            } else {
                v.reason = r;
                v.dup = r == .count and b.len != c.members.len;
            }
        } else {
            var out: [baggage.max_len + 64]u8 = undefined;
            var cl: [baggage.max_len + 64]u8 = undefined;
            // otel serializes an empty property it parsed (`k=v;`); we dropped it.
            const theirs = withoutEmptyProperties(&cl, c.string) orelse c.string;
            if (!mem.eql(u8, sortedWrite(&out, &b), theirs)) v.reason = .string;
        }
    } else |_| {
        if (c.ok) v.reason = .strict_verdict;
    }
    if (v.reason == null and !c.ok) {
        const lenient = try Baggage.parseLenient(c.input, &scratch2);
        if (membersDiffer(&lenient, c.members, .{})) |_| v.reason = .lenient;
    }
    return v;
}

fn classOf(c: vectors.Case, v: Verdict) ?Class {
    const reason = v.reason orelse return if (v.decoded) .property_value_decoded else null;
    switch (reason) {
        .strict_verdict, .lenient => {
            if (propertyBadEscape(c.input) and !c.ok) return .property_bad_escape;
            // otel returns nothing for a too long value; we keep the members
            // that end within 8192 bytes.
            if (reason == .lenient and c.input.len > baggage.max_len and c.members.len == 0) return .limit_keeps_prefix;
            return null;
        },
        .count, .member, .string => if (v.dup) return .duplicate_key,
    }
    return null;
}

test "otel baggage oracle: strict, lenient and write agree with OpenTelemetry Go except the listed classes" {
    var hits = @as([n_classes]usize, @splat(0));
    var bad: usize = 0;
    var agree: usize = 0;
    var accepted: usize = 0;
    var rejected: usize = 0;
    for (vectors.cases) |c| {
        const v = try judge(c);
        const reason = v.reason orelse {
            if (v.decoded) hits[@backingInt(Class.property_value_decoded)] += 1 else agree += 1;
            if (c.wire_ok) {
                if (c.ok) accepted += 1 else rejected += 1;
            }
            continue;
        };
        if (classOf(c, v)) |k| {
            hits[@backingInt(k)] += 1;
        } else {
            // Failure path only: an unexplained disagreement fails the test below.
            bad += 1;
            std.debug.print("{s}: {s} differs from otel; input {f}\n   otel ok={} string={f}\n", .{
                c.id, @tagName(reason), std.zig.fmtString(c.input[0..@min(c.input.len, 120)]), c.ok, std.zig.fmtString(c.string[0..@min(c.string.len, 120)]),
            });
        }
    }
    for (hits, 0..) |h, i| if (h == 0) {
        std.debug.print("class {s} agrees now: delete it\n", .{@tagName(@as(Class, @fromBackingInt(@intCast(i))))});
        bad += 1;
    };
    if (bad != 0) std.debug.print("{d} unexplained; agree {d}, hits {any}\n", .{ bad, agree, hits });
    try testing.expectEqual(@as(usize, 0), bad);
    //: the evidence is agreement (932 of 954); 22 cases fall in
    // the four classes below (property_bad_escape 7, duplicate_key 3,
    // property_value_decoded 11, limit_keeps_prefix 1).
    try testing.expectEqual(@as(usize, 954), vectors.cases.len);
    try testing.expectEqual(@as(usize, 932), agree);
    try testing.expectEqual([n_classes]usize{ 7, 3, 11, 1 }, hits);
    try testing.expect(accepted >= 150 and rejected >= 400);
}
