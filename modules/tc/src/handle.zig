// SPDX-License-Identifier: MIT
//! `tc` handle arithmetic — the `major:minor` u32 identifiers every qdisc,
//! class and filter parent is expressed in (`struct tcmsg.tcm_handle` /
//! `.tcm_parent`, kernel UAPI `linux/pkt_sched.h` `TC_H_*`).
//!
//! A handle packs two 16-bit halves into one u32: the **major** number in the
//! high half (the qdisc) and the **minor** in the low half (the class inside
//! it, or 0 for the qdisc itself). Three values are reserved:
//! `TC_H_UNSPEC` (0), `TC_H_ROOT` (0xFFFFFFFF — "the interface's root qdisc")
//! and `TC_H_INGRESS` (0xFFFFFFF1, also spelled `clsact`).
//!
//! **Handles are hexadecimal.** `tc class add … classid 1:10` means minor
//! 0x10 = 16, not 10 — iproute2 parses both halves with base 16 and prints
//! them the same way.
//!
//! `parse` accepts every form `tc show` prints, including the reserved values
//! spelled numerically (`ffff:fff1`, `0:`). `format` reproduces a real `tc`
//! binary's rendering (`iproute2-6.19.0`, verified live with
//! `unshare -rn tc qdisc show dev lo` / `tc qdisc add … clsact`):
//! `TC_H_ROOT` is the only reserved value with a symbolic form (`root`);
//! `TC_H_UNSPEC` prints as `0:`, not `none` — real `tc` uses the symbolic
//! `none` only for the *parent* field's absence, never for a handle, and this
//! type does not distinguish the two positions, so it follows the handle
//! rendering, the one directly observed; `TC_H_INGRESS`/`TC_H_CLSACT` have no
//! symbolic form either — they fall through to the plain `major:minor` hex
//! pair (`ffff:fff1`), matching the live `parent ffff:fff1` capture; and a
//! major-0 handle prints `:10`, not `0:10`, matching `print_tc_classid`'s
//! explicit `:%x` branch. `format` → `parse` still recovers the identical
//! `raw`, so the round-trip is value-exact.

const std = @import("std");

/// TC_H_UNSPEC — "not specified" (a dump filter, or a class delete that lets
/// the kernel find the parent itself).
pub const TC_H_UNSPEC: u32 = 0;
/// TC_H_ROOT — as a parent: "attach me as the interface's root qdisc".
pub const TC_H_ROOT: u32 = 0xFFFFFFFF;
/// TC_H_INGRESS — the ingress/clsact attach point.
pub const TC_H_INGRESS: u32 = 0xFFFFFFF1;
/// TC_H_CLSACT — the clsact qdisc shares TC_H_INGRESS's value.
pub const TC_H_CLSACT: u32 = TC_H_INGRESS;

pub const TC_H_MAJ_MASK: u32 = 0xFFFF0000;
pub const TC_H_MIN_MASK: u32 = 0x0000FFFF;

/// `TC_H_MAKE(maj, min)` — combine an already-shifted major with a minor.
/// Used verbatim for `tcm_info` on filters, where the "major" is
/// `prio << 16` and the "minor" is the protocol in network byte order.
pub fn make(maj: u32, min: u32) u32 {
    return (maj & TC_H_MAJ_MASK) | (min & TC_H_MIN_MASK);
}

/// A qdisc/class handle: `major:minor`, hexadecimal on the wire and in text.
pub const Handle = struct {
    raw: u32,

    pub const unspec: Handle = .{ .raw = TC_H_UNSPEC };
    pub const root: Handle = .{ .raw = TC_H_ROOT };
    pub const ingress: Handle = .{ .raw = TC_H_INGRESS };
    pub const clsact: Handle = .{ .raw = TC_H_CLSACT };

    /// Build `major:minor` from the two halves (both plain numbers, not
    /// pre-shifted).
    pub fn init(major_: u16, minor_: u16) Handle {
        return .{ .raw = (@as(u32, major_) << 16) | @as(u32, minor_) };
    }

    /// Wrap a raw wire value (e.g. straight out of a `tcmsg`).
    pub fn fromRaw(raw: u32) Handle {
        return .{ .raw = raw };
    }

    pub fn major(h: Handle) u16 {
        return @intCast(h.raw >> 16);
    }

    pub fn minor(h: Handle) u16 {
        return @truncate(h.raw);
    }

    pub fn isRoot(h: Handle) bool {
        return h.raw == TC_H_ROOT;
    }

    pub fn isIngress(h: Handle) bool {
        return h.raw == TC_H_INGRESS;
    }

    pub fn isUnspec(h: Handle) bool {
        return h.raw == TC_H_UNSPEC;
    }

    pub fn eql(a: Handle, b: Handle) bool {
        return a.raw == b.raw;
    }

    /// The handle of the **qdisc** this class lives under — `1:10` → `1:`.
    /// Reserved handles (root/ingress/unspec) are returned unchanged: they
    /// are not `major:minor` pairs and have no qdisc half.
    pub fn qdisc(h: Handle) Handle {
        if (h.isRoot() or h.isIngress() or h.isUnspec()) return h;
        return .{ .raw = h.raw & TC_H_MAJ_MASK };
    }

    /// The parent handle to hand a **child** of this qdisc/class. Attaching
    /// under a qdisc handle `1:` uses `1:` itself; attaching under class
    /// `1:10` uses `1:10`. Provided for symmetry with `qdisc` — the parent of
    /// a child is simply this handle.
    pub fn asParent(h: Handle) Handle {
        return h;
    }

    /// True when this is a class handle (`major` and `minor` both nonzero)
    /// rather than a bare qdisc handle (`major:0`).
    pub fn isClass(h: Handle) bool {
        return !h.isRoot() and !h.isIngress() and h.major() != 0 and h.minor() != 0;
    }

    pub const ParseError = error{
        /// Empty input, a missing `:`, or a half that is not hexadecimal.
        InvalidHandle,
        /// A half wider than 16 bits.
        HandleOverflow,
    };

    /// Parse iproute2 handle syntax — **hexadecimal**, `:` separated, either
    /// half optional:
    ///
    /// * `"1:10"` → major 1, minor 0x10
    /// * `"1:"` / `"1"` → major 1, minor 0
    /// * `":10"` → major 0, minor 0x10
    /// * `"root"` / `"none"` / `"ingress"` / `"clsact"` → the reserved values
    ///
    /// A leading `0x` is accepted on either half (iproute2's `strtoul` does).
    pub fn parse(s: []const u8) ParseError!Handle {
        if (s.len == 0) return error.InvalidHandle;
        if (std.mem.eql(u8, s, "root")) return root;
        if (std.mem.eql(u8, s, "none")) return unspec;
        if (std.mem.eql(u8, s, "ingress")) return ingress;
        if (std.mem.eql(u8, s, "clsact")) return clsact;

        const colon = std.mem.indexOfScalar(u8, s, ':');
        const maj_str = if (colon) |c| s[0..c] else s;
        const min_str = if (colon) |c| s[c + 1 ..] else "";
        const maj = try parseHalf(maj_str);
        const min = try parseHalf(min_str);
        return init(maj, min);
    }

    fn parseHalf(s: []const u8) ParseError!u16 {
        if (s.len == 0) return 0;
        var body = s;
        if (body.len > 2 and body[0] == '0' and (body[1] == 'x' or body[1] == 'X')) body = body[2..];
        if (body.len == 0) return error.InvalidHandle;
        var v: u32 = 0;
        for (body) |c| {
            const d: u32 = switch (c) {
                '0'...'9' => c - '0',
                'a'...'f' => c - 'a' + 10,
                'A'...'F' => c - 'A' + 10,
                else => return error.InvalidHandle,
            };
            v = v * 16 + d;
            if (v > std.math.maxInt(u16)) return error.HandleOverflow;
        }
        return @intCast(v);
    }

    /// Render in real `tc`'s form: `root`, `0:` (unspec), `1:` (minor 0),
    /// `:10` (major 0) or `1:10` — hexadecimal. See the file header for the
    /// live evidence behind each case; `TC_H_INGRESS`/`TC_H_CLSACT` have no
    /// symbolic form and fall through to the last `{x}:{x}` branch.
    pub fn format(h: Handle, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (h.isRoot()) return w.writeAll("root");
        if (h.isUnspec()) return w.print("{x}:", .{h.major()});
        if (h.major() == 0) return w.print(":{x}", .{h.minor()});
        if (h.minor() == 0) return w.print("{x}:", .{h.major()});
        return w.print("{x}:{x}", .{ h.major(), h.minor() });
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "handle constants match the kernel UAPI" {
    try testing.expectEqual(@as(u32, 0), TC_H_UNSPEC);
    try testing.expectEqual(@as(u32, 0xFFFFFFFF), TC_H_ROOT);
    try testing.expectEqual(@as(u32, 0xFFFFFFF1), TC_H_INGRESS);
    try testing.expectEqual(TC_H_INGRESS, TC_H_CLSACT);
}

test "major:minor packing" {
    const h = Handle.init(1, 0x10);
    try testing.expectEqual(@as(u32, 0x00010010), h.raw);
    try testing.expectEqual(@as(u16, 1), h.major());
    try testing.expectEqual(@as(u16, 0x10), h.minor());
    try testing.expect(h.isClass());
    try testing.expectEqual(@as(u32, 0x00010000), h.qdisc().raw);
    try testing.expect(!Handle.init(1, 0).isClass());
}

test "parse is hexadecimal, like iproute2" {
    // `classid 1:10` is minor 16, not 10 — the classic tc gotcha.
    try testing.expectEqual(@as(u32, 0x00010010), (try Handle.parse("1:10")).raw);
    try testing.expectEqual(@as(u32, 0x00010000), (try Handle.parse("1:")).raw);
    try testing.expectEqual(@as(u32, 0x00010000), (try Handle.parse("1")).raw);
    try testing.expectEqual(@as(u32, 0x00000010), (try Handle.parse(":10")).raw);
    try testing.expectEqual(@as(u32, 0xabcd1234), (try Handle.parse("abcd:1234")).raw);
    try testing.expectEqual(@as(u32, 0x00ff0001), (try Handle.parse("0xff:0x1")).raw);
    try testing.expectEqual(TC_H_ROOT, (try Handle.parse("root")).raw);
    try testing.expectEqual(TC_H_UNSPEC, (try Handle.parse("none")).raw);
    try testing.expectEqual(TC_H_INGRESS, (try Handle.parse("ingress")).raw);
    try testing.expectEqual(TC_H_INGRESS, (try Handle.parse("clsact")).raw);

    try testing.expectError(error.InvalidHandle, Handle.parse(""));
    try testing.expectError(error.InvalidHandle, Handle.parse("zz:1"));
    try testing.expectError(error.InvalidHandle, Handle.parse("0x"));
    try testing.expectError(error.HandleOverflow, Handle.parse("10000:0"));
}

test "format round-trips parse (identical spelling)" {
    var buf: [32]u8 = undefined;
    // ":10" (major-0) was the gap the audit found: `parse` already accepted
    // it (see "parse is hexadecimal, like iproute2" above) but no round-trip
    // case ever rendered it, so the `0:10` mis-format below went unnoticed.
    const cases = [_][]const u8{ "1:10", "1:", ":10", "abcd:1234", "root", "0:" };
    for (cases) |c| {
        const h = try Handle.parse(c);
        const s = try std.fmt.bufPrint(&buf, "{f}", .{h});
        try testing.expectEqualStrings(c, s);
        try testing.expectEqual(h.raw, (try Handle.parse(s)).raw);
    }
}

test "format round-trips parse (different spelling, same value) for ingress/unspec/clsact" {
    // `parse` still accepts the symbolic forms; `format` no longer produces
    // them (see the next test), so only the *value* survives the round trip.
    var buf: [32]u8 = undefined;
    const cases = [_][]const u8{ "ingress", "clsact", "none" };
    for (cases) |c| {
        const h = try Handle.parse(c);
        const s = try std.fmt.bufPrint(&buf, "{f}", .{h});
        try testing.expectEqual(h.raw, (try Handle.parse(s)).raw);
    }
}

test "format matches a real `tc` binary on the three cases where it used to diverge" {
    // Captured live, `iproute2-6.19.0`, `unshare -rn`:
    //   `tc qdisc add dev lo clsact; tc qdisc show dev lo`
    //     -> "qdisc clsact ffff: parent ffff:fff1" — the *parent* field
    //        (raw TC_H_INGRESS) prints as plain hex, not "ingress".
    //   `tc qdisc show dev lo` (no qdiscs added)
    //     -> "qdisc noqueue 0: root" — the qdisc's own handle (raw
    //        TC_H_UNSPEC = 0) prints "0:", not "none".
    // Pinned as literal strings, not derived from the constants, per the
    // audit's F2 finding (`tc.md`).
    var buf: [32]u8 = undefined;

    try testing.expectEqualStrings("ffff:fff1", try std.fmt.bufPrint(&buf, "{f}", .{Handle.ingress}));
    try testing.expectEqualStrings("ffff:fff1", try std.fmt.bufPrint(&buf, "{f}", .{Handle.clsact}));
    try testing.expectEqualStrings("0:", try std.fmt.bufPrint(&buf, "{f}", .{Handle.unspec}));
    // The major-0 case: matches iproute2's `print_tc_classid`'s explicit
    // `:%x` branch (not directly re-captured live, but a stable read of the
    // reference implementation's source shape — see the file header).
    try testing.expectEqualStrings(":10", try std.fmt.bufPrint(&buf, "{f}", .{Handle.init(0, 0x10)}));
}

test "TC_H_MAKE composes a filter's tcm_info (prio + protocol)" {
    // `protocol ip prio 1` → prio in the high half, ETH_P_IP big-endian in
    // the low half: 0x0800 byte-swapped = 0x0008.
    try testing.expectEqual(@as(u32, 0x00010008), make(@as(u32, 1) << 16, 0x0008));
    try testing.expectEqual(@as(u32, 0x0004dd86), make(@as(u32, 4) << 16, 0xdd86));
}
