// SPDX-License-Identifier: MIT
//! Multi-level (L1/L2) prefix leaking, RFC 5302 (Domain-wide Prefix
//! Distribution with Two-Level IS-IS): what an L1/L2 system advertises into
//! each level, from the route tables of its two level computations.
//!
//! A system that is L1/L2 keeps two link-state databases and runs the
//! decision process on each (`compute`/`computeWith` with `Options.prefixes`,
//! the L2 one with `Options.level2`). This layer turns the two `RouteTable`s
//! into the prefixes to advertise:
//!
//! - **L1 -> L2** (RFC 5302 §3.1, the default direction): every prefix the L1
//!   computation selected from an advertisement with the Up/Down bit clear,
//!   at the L1 total metric. A prefix whose L1 advertisement has Up/Down set was
//!   itself leaked down from L2: "Prefixes with the up/down bit set that are
//!   learned via L1 routing MUST NOT be advertised by L1L2 routers back into
//!   L2". The synthesised attached-bit default route is not advertised.
//! - **L2 -> L1** (RFC 5302 §3.2: only by policy, "route leaking ... is
//!   controlled by policy"): the L2 prefixes `Policy.l2_to_l1` covers, with the
//!   Up/Down bit set and the L2 total metric. A prefix the L1 computation
//!   already holds natively (Up/Down clear) is not leaked down (the L1 route is
//!   the preferred one, RFC 5302 §3.1 route preference, and leaking it back
//!   would only build a loop for the other L1/L2 systems to filter).
//!
//! The output is a plain list per direction, sorted by prefix, ready for
//! `addAdvert` (builds the #135 / #236 TLV) and then for the LSP generator
//! (`isis-lsdb`'s `generate`, `Origin.tlvs`). Metrics are clamped to
//! RFC 5305 §3 `MAX_PATH_METRIC` (0xFE000000).
//!
//! Pure: it allocates the two result slices from the caller's allocator and
//! nothing else.

const std = @import("std");
const isis = @import("isis");

const Allocator = std.mem.Allocator;
const root = @import("root.zig");

const Prefix = root.Prefix;
const RouteTable = root.RouteTable;

/// RFC 5305 §3: the largest path metric.
pub const max_path_metric: u32 = 0xFE000000;

/// One prefix to advertise.
pub const Advert = struct {
    prefix: Prefix,
    metric: u32,
    up_down: bool,
    /// The IPv6 X bit, carried over from the selected advertisement.
    external: bool = false,
};

pub const Policy = struct {
    /// L2 prefixes to leak into L1: a candidate is leaked when one of these
    /// covers it (same family, `entry.len <= prefix.len`, equal on the first
    /// `entry.len` bits). Empty (the default): nothing is leaked down.
    l2_to_l1: []const Prefix = &.{},
    /// L1 prefixes withheld from L2: the same covering test. Empty: the L1
    /// routes are all leaked up (RFC 5302 §3.1 default).
    l1_to_l2_deny: []const Prefix = &.{},
};

pub const Plan = struct {
    gpa: Allocator,
    into_l2: []Advert,
    into_l1: []Advert,

    pub fn deinit(self: *Plan) void {
        self.gpa.free(self.into_l2);
        self.gpa.free(self.into_l1);
        self.* = undefined;
    }
};

/// Does `outer` cover `inner` (same family, `outer.len <= inner.len`, equal
/// leading `outer.len` bits)?
pub fn covers(outer: Prefix, inner: Prefix) bool {
    if (outer.family != inner.family or outer.len > inner.len) return false;
    const full: usize = outer.len / 8;
    if (!std.mem.eql(u8, outer.addr[0..full], inner.addr[0..full])) return false;
    const rem: u3 = @intCast(outer.len % 8);
    if (rem == 0) return true;
    const mask: u8 = ~(@as(u8, 0xff) >> rem);
    return (outer.addr[full] & mask) == (inner.addr[full] & mask);
}

fn coveredByAny(list: []const Prefix, p: Prefix) bool {
    for (list) |e| if (covers(e, p)) return true;
    return false;
}

fn clamp(m: u64) u32 {
    return @intCast(@min(m, max_path_metric));
}

/// Compute what to advertise into each level from the two route tables.
pub fn plan(gpa: Allocator, l1: *const RouteTable, l2: *const RouteTable, policy: Policy) Allocator.Error!Plan {
    var up: std.ArrayList(Advert) = .empty;
    errdefer up.deinit(gpa);
    for (l1.prefixes) |r| {
        if (r.up_down or r.attached_default) continue;
        if (coveredByAny(policy.l1_to_l2_deny, r.prefix)) continue;
        try up.append(gpa, .{ .prefix = r.prefix, .metric = clamp(r.metric), .up_down = false, .external = r.external });
    }
    var down: std.ArrayList(Advert) = .empty;
    errdefer down.deinit(gpa);
    for (l2.prefixes) |r| {
        if (r.attached_default) continue;
        if (!coveredByAny(policy.l2_to_l1, r.prefix)) continue;
        if (l1.prefixRoute(r.prefix)) |native| if (!native.up_down and !native.attached_default) continue;
        try down.append(gpa, .{ .prefix = r.prefix, .metric = clamp(r.metric), .up_down = true, .external = r.external });
    }
    return .{ .gpa = gpa, .into_l2 = try up.toOwnedSlice(gpa), .into_l1 = try down.toOwnedSlice(gpa) };
}

/// Append the #135 (IPv4) or #236 (IPv6) TLV for `a` to `b`.
pub fn addAdvert(b: *isis.tlv.Builder, a: Advert) (isis.tlv.BuildError || isis.tlvs.ParseError)!void {
    switch (a.prefix.family) {
        .ipv4 => try isis.tlvs.addExtIpReach(b, .{
            .metric = a.metric,
            .up_down = a.up_down,
            .prefix_len = a.prefix.len,
            .prefix = a.prefix.addr[0..4].*,
        }),
        .ipv6 => try isis.tlvs.addIpv6Reach(b, .{
            .metric = a.metric,
            .up_down = a.up_down,
            .external = a.external,
            .prefix_len = a.prefix.len,
            .prefix = a.prefix.addr,
        }),
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn p4(a: u8, b: u8, c: u8, d: u8, len: u8) Prefix {
    return .{ .family = .ipv4, .addr = [4]u8{ a, b, c, d } ++ @as([12]u8, @splat(0)), .len = len };
}

fn table(rows: []const root.PrefixRoute) !RouteTable {
    const gpa = testing.allocator;
    return .{ .gpa = gpa, .routes = try gpa.alloc(root.Route, 0), .prefixes = try gpa.dupe(root.PrefixRoute, rows) };
}

fn row(p: Prefix, metric: u64, ud: bool) root.PrefixRoute {
    return .{ .prefix = p, .metric = metric, .next_hop = @splat(1), .origin = @splat(1), .up_down = ud };
}

test "covers: leading bits, family and length" {
    try testing.expect(covers(p4(10, 0, 0, 0, 8), p4(10, 20, 30, 0, 24)));
    try testing.expect(covers(p4(10, 16, 0, 0, 12), p4(10, 31, 0, 0, 16)));
    try testing.expect(!covers(p4(10, 16, 0, 0, 12), p4(10, 32, 0, 0, 16)));
    try testing.expect(!covers(p4(10, 0, 0, 0, 24), p4(10, 0, 0, 0, 8)));
    try testing.expect(covers(p4(0, 0, 0, 0, 0), p4(1, 2, 3, 4, 32)));
    var v6: Prefix = .{ .family = .ipv6, .addr = @splat(0), .len = 0 };
    try testing.expect(!covers(v6, p4(1, 2, 3, 4, 32)));
    v6.len = 64;
    try testing.expect(covers(v6, .{ .family = .ipv6, .addr = @splat(0), .len = 80 }));
}

test "L1 to L2: everything native is leaked up, Up/Down-set and attached defaults are not, deny list applies" {
    var l1 = try table(&.{
        row(p4(10, 1, 0, 0, 16), 30, false),
        row(p4(10, 2, 0, 0, 16), 30, true), // came down from L2
        row(p4(172, 16, 0, 0, 12), 5, false),
        .{ .prefix = p4(0, 0, 0, 0, 0), .metric = 9, .next_hop = @splat(1), .origin = @splat(1), .attached_default = true },
    });
    defer l1.deinit();
    var l2 = try table(&.{});
    defer l2.deinit();
    var pl = try plan(testing.allocator, &l1, &l2, .{ .l1_to_l2_deny = &.{p4(172, 16, 0, 0, 12)} });
    defer pl.deinit();
    try testing.expectEqual(@as(usize, 1), pl.into_l2.len);
    try testing.expectEqual(p4(10, 1, 0, 0, 16), pl.into_l2[0].prefix);
    try testing.expectEqual(@as(u32, 30), pl.into_l2[0].metric);
    try testing.expect(!pl.into_l2[0].up_down);
    try testing.expectEqual(@as(usize, 0), pl.into_l1.len);
}

test "L2 to L1: only by policy, Up/Down set, never over a native L1 route" {
    var l1 = try table(&.{row(p4(192, 0, 2, 0, 24), 10, false)});
    defer l1.deinit();
    var l2 = try table(&.{
        row(p4(10, 99, 0, 0, 16), 0x1_0000_0000, false), // metric clamps
        row(p4(192, 0, 2, 0, 24), 5, false), // native in L1 already
        row(p4(198, 51, 100, 0, 24), 40, false),
        row(p4(203, 0, 113, 0, 24), 7, false), // not covered by the policy
    });
    defer l2.deinit();
    const policy: Policy = .{ .l2_to_l1 = &.{ p4(192, 0, 2, 0, 24), p4(198, 51, 0, 0, 16), p4(10, 0, 0, 0, 8) } };
    var pl = try plan(testing.allocator, &l1, &l2, policy);
    defer pl.deinit();
    try testing.expectEqual(@as(usize, 2), pl.into_l1.len);
    try testing.expectEqual(p4(10, 99, 0, 0, 16), pl.into_l1[0].prefix);
    try testing.expectEqual(max_path_metric, pl.into_l1[0].metric);
    try testing.expect(pl.into_l1[0].up_down);
    try testing.expectEqual(p4(198, 51, 100, 0, 24), pl.into_l1[1].prefix);
    try testing.expectEqual(@as(u32, 40), pl.into_l1[1].metric);
    // Default policy leaks nothing down.
    var none = try plan(testing.allocator, &l1, &l2, .{});
    defer none.deinit();
    try testing.expectEqual(@as(usize, 0), none.into_l1.len);
}

test "an L1 route that came down from L2 (Up/Down set) does not block leaking the L2 prefix down, and is not leaked up" {
    var l1 = try table(&.{row(p4(198, 51, 100, 0, 24), 12, true)});
    defer l1.deinit();
    var l2 = try table(&.{row(p4(198, 51, 100, 0, 24), 3, false)});
    defer l2.deinit();
    var pl = try plan(testing.allocator, &l1, &l2, .{ .l2_to_l1 = &.{p4(198, 51, 100, 0, 24)} });
    defer pl.deinit();
    try testing.expectEqual(@as(usize, 1), pl.into_l1.len);
    try testing.expectEqual(@as(usize, 0), pl.into_l2.len);
}

test "addAdvert builds the #135 and #236 TLVs that the codec reads back" {
    var buf: [128]u8 = undefined;
    var b = isis.tlv.Builder.init(&buf);
    try addAdvert(&b, .{ .prefix = p4(203, 0, 113, 0, 24), .metric = 17, .up_down = true });
    var a6: [16]u8 = @splat(0);
    a6[0..2].* = .{ 0x20, 0x01 };
    try addAdvert(&b, .{ .prefix = .{ .family = .ipv6, .addr = a6, .len = 32 }, .metric = 4, .up_down = false, .external = true });
    var it = isis.tlv.TlvIterator.init(b.written());
    var e4 = isis.tlvs.ExtIpReachIterator.init((try it.next()).?.value);
    const x = (try e4.next()).?;
    try testing.expect(x.up_down);
    try testing.expectEqual(@as(u32, 17), x.metric);
    try testing.expectEqual(@as(u8, 24), x.prefix_len);
    var e6 = isis.tlvs.Ipv6ReachIterator.init((try it.next()).?.value);
    const y = (try e6.next()).?;
    try testing.expect(y.external and !y.up_down);
    try testing.expectEqual(@as(u8, 32), y.prefix_len);
}
