// SPDX-License-Identifier: MIT
//! The tcplan **input model**: a tree of shaping nodes on one egress
//! interface, in the shape a LibreQoS-style edge shaper thinks in.
//!
//! A `Topology` is a forest of `Node`s hung under an implicit `mq` root. Each
//! direct child of the root (a "site") is pinned to a CPU/hardware-TX-queue;
//! every descendant inherits that pin (see the cpumap→MQ→per-CPU invariant in
//! SPEC.md). Interior nodes are aggregation tiers (site, access-point) with a
//! committed rate (HTB `rate`) and a ceil rate (HTB `ceil`); leaf nodes are
//! subscribers, each additionally carrying a per-subscriber CAKE qdisc and a
//! classifier that steers its packets into its class.
//!
//! Everything here is plain typed data — no allocation, no I/O. The compiler
//! (`compile.zig`) turns it into an ordered `Plan` of `tc` operations.

const std = @import("std");
const tc = @import("tc");

/// Which direction of a subscriber's traffic the classifier matches. On the
/// egress-to-subscriber interface the download shaper keys on the
/// destination address; `.src` is offered for the symmetric upload case.
pub const Dir = enum { src, dst };

/// A subscriber's classifier key — the match that steers its packets into its
/// HTB leaf class. Modelled as a `flower` key so it stays fully value-typed
/// (no owned slices): an IPv4/IPv6 host or prefix in a chosen direction.
///
/// fwmark / `u32` raw-offset matching is deliberately out of scope (see
/// SPEC.md's deferred list): the tc module's `flower` covers L3 prefixes
/// without any owned-key-slice lifetime to manage in the plan.
pub const Match = union(enum) {
    ipv4: struct { addr: [4]u8, prefix_len: u6 = 32, dir: Dir = .dst },
    ipv6: struct { addr: [16]u8, prefix_len: u8 = 128, dir: Dir = .dst },

    /// The `protocol` ethertype the steering filter is installed under.
    pub fn ethType(self: Match) u16 {
        return switch (self) {
            .ipv4 => tc.ETH_P.IP,
            .ipv6 => tc.ETH_P.IPV6,
        };
    }

    /// Whether `prefix_len` fits the address family (`<= 32` / `<= 128`).
    /// The `tc` flower encoder clamps an over-long length silently, so the
    /// compiler refuses one instead (`error.InvalidPrefix`).
    pub fn prefixValid(self: Match) bool {
        return switch (self) {
            .ipv4 => |v| v.prefix_len <= 32,
            .ipv6 => |v| v.prefix_len <= 128,
        };
    }

    /// Whether `a` and `b` can match the same packet: same family, same
    /// direction, and the shorter of the two prefixes covers both addresses
    /// (an exact duplicate is the equal-length case). Host bits beyond the
    /// prefix are ignored, as the kernel's flower mask ignores them. Both
    /// must be `prefixValid`.
    pub fn overlaps(a: Match, b: Match) bool {
        return switch (a) {
            .ipv4 => |x| switch (b) {
                .ipv4 => |y| x.dir == y.dir and
                    samePrefix(&x.addr, &y.addr, @min(x.prefix_len, y.prefix_len)),
                .ipv6 => false,
            },
            .ipv6 => |x| switch (b) {
                .ipv6 => |y| x.dir == y.dir and
                    samePrefix(&x.addr, &y.addr, @min(x.prefix_len, y.prefix_len)),
                .ipv4 => false,
            },
        };
    }
};

/// Whether the leading `bits` bits of `a` and `b` are equal.
fn samePrefix(a: []const u8, b: []const u8, bits: u8) bool {
    std.debug.assert(a.len == b.len and bits <= a.len * 8);
    const whole = bits / 8;
    if (!std.mem.eql(u8, a[0..whole], b[0..whole])) return false;
    const rem: u4 = @intCast(bits % 8);
    if (rem == 0) return true;
    const mask: u8 = @as(u8, 0xFF) << @intCast(8 - rem);
    return (a[whole] & mask) == (b[whole] & mask);
}

/// The kernel's highest HTB class priority: `TC_HTB_NUMPRIO - 1` (= 7,
/// `include/uapi/linux/pkt_sched.h`). `sch_htb` silently clamps a larger
/// `prio` to it, so the compiler refuses one (`error.HtbPrioOutOfRange`).
pub const htb_max_prio: u32 = 7;

/// The optional HTB class knobs of a node, emitted verbatim into its class
/// op's `tc.HtbClass` (the fields of that builder with the same names). Every
/// zero value is `tc`'s own default, so a node that leaves `htb` at `.{}`
/// compiles exactly as before.
pub const HtbKnobs = struct {
    /// `burst` in bytes — how much may go out at `ceil` speed beyond the
    /// committed rate before the rate bucket runs dry. 0 derives
    /// `rate / HZ + mtu` (the `tc` default, computed by the `tc` builder).
    burst: u32 = 0,
    /// `cburst` in bytes — the same for the ceil bucket. 0 derives
    /// `ceil / HZ + mtu`.
    cburst: u32 = 0,
    /// `prio` — a lower value is offered spare bandwidth first.
    /// `0 ... htb_max_prio`.
    prio: u32 = 0,
    /// DRR `quantum` in bytes. 0 lets the kernel derive it from the HTB
    /// root's `r2q` (clamped into 1000..200000); an explicit value is used
    /// as given.
    quantum: u32 = 0,
};

/// One shaping node. Interior when it has children; a subscriber leaf when it
/// does not.
pub const Node = struct {
    /// A human name, unique across the whole topology (enforced at compile).
    /// Carried for diagnostics/reconciliation, never emitted on the wire.
    name: []const u8,
    /// Committed rate — HTB `rate`, the guaranteed share — in **bytes per
    /// second** (see `mbit`). Must be non-zero.
    rate_bps: u64,
    /// Ceil rate — HTB `ceil`, the burst-to maximum — in bytes per second.
    /// 0 means "same as `rate_bps`", exactly like `tc`'s htb default.
    ceil_bps: u64 = 0,
    /// The CPU / hardware-TX-queue this subtree egresses on. **Required on a
    /// direct child of the root** (a top-level site); on any descendant `null`
    /// means "inherit the ancestor's pin". A descendant that names a *different*
    /// CPU than its ancestor is a `CpuStraddle` compile error — a subscriber's
    /// class chain must never cross queues. CPUs are 0-based; CPU `c` maps to
    /// `mq` child `c+1` and HTB major `c+1` (see SPEC.md).
    cpu: ?u16 = null,
    /// The classifiers for a subscriber leaf — every address/prefix the
    /// subscriber owns (typically an IPv4 and an IPv6 prefix). Each entry
    /// becomes one steering filter, all of them targeting this node's single
    /// HTB class, so the entries share its rate. Filters are emitted in slice
    /// order, each taking the next per-queue filter prio. Must be empty on an
    /// interior node (`ClassifierOnInterior`) — only leaves are steered. A
    /// leaf with no entries gets its class + CAKE qdisc but no steering
    /// filter (documented). No two entries anywhere in the topology may
    /// overlap (`OverlappingMatch`).
    match: []const Match = &.{},
    /// Optional HTB class knobs (`burst`/`cburst`/`prio`/`quantum`) for this
    /// node's class, interior or leaf. The defaults leave them to `tc` and
    /// the kernel.
    htb: HtbKnobs = .{},
    /// The per-subscriber CAKE leaf qdisc configuration. Only used for a leaf;
    /// the default (`.{}`) is an unshaped CAKE doing pure AQM/fairness under
    /// the HTB class that already shapes it (the LibreQoS arrangement).
    cake: tc.Cake = .{},
    /// Child nodes. Empty ⇒ this is a subscriber leaf.
    children: []const Node = &.{},

    pub fn isLeaf(n: Node) bool {
        return n.children.len == 0;
    }

    /// The effective ceil after applying the "0 ⇒ rate" rule — the value the
    /// parent/child ceil invariant is checked against.
    pub fn effectiveCeil(n: Node) u64 {
        return if (n.ceil_bps == 0) n.rate_bps else n.ceil_bps;
    }
};

/// A complete shaping topology for one interface.
pub const Topology = struct {
    /// Number of hardware TX queues == number of CPUs the `mq` root spans.
    /// Must be non-zero and below `handles.mq_root_major` (0x7FFF).
    queue_count: u16,
    /// `htb default N` for every per-queue HTB root — the class minor
    /// unclassified traffic falls into. 0 (the default) installs no default,
    /// so unclassified traffic takes htb's direct/unshaped path.
    htb_defcls: u32 = 0,
    /// Top-level nodes (sites). Each must set `cpu`. May be empty, which
    /// compiles to a plan containing only the `mq` root qdisc.
    roots: []const Node = &.{},
};

/// Convenience: megabit/s → bytes/s (the unit `Node.rate_bps`/`ceil_bps` and
/// `tc`'s htb/cake rates use). 1 Mbit/s = 125 000 bytes/s.
pub fn mbit(mbits: u64) u64 {
    return mbits * 125_000;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "leaf/interior classification and effective ceil" {
    const leaf: Node = .{ .name = "s", .rate_bps = 1000 };
    try testing.expect(leaf.isLeaf());
    try testing.expectEqual(@as(u64, 1000), leaf.effectiveCeil()); // ceil 0 ⇒ rate

    const interior: Node = .{
        .name = "ap",
        .rate_bps = 1000,
        .ceil_bps = 2000,
        .children = &.{leaf},
    };
    try testing.expect(!interior.isLeaf());
    try testing.expectEqual(@as(u64, 2000), interior.effectiveCeil());
}

test "match overlap: family, direction, prefix containment, host bits" {
    const a: Match = .{ .ipv4 = .{ .addr = .{ 100, 64, 0, 0 }, .prefix_len = 24 } };
    const inside: Match = .{ .ipv4 = .{ .addr = .{ 100, 64, 0, 77 } } };
    const outside: Match = .{ .ipv4 = .{ .addr = .{ 100, 64, 1, 77 } } };
    const inside_src: Match = .{ .ipv4 = .{ .addr = .{ 100, 64, 0, 77 }, .dir = .src } };
    try testing.expect(a.overlaps(a)); // exact duplicate
    try testing.expect(a.overlaps(inside) and inside.overlaps(a)); // symmetric
    try testing.expect(!a.overlaps(outside));
    try testing.expect(!a.overlaps(inside_src)); // other direction
    // Host bits beyond the prefix do not matter: 100.64.0.9/24 == 100.64.0.0/24.
    const a_host: Match = .{ .ipv4 = .{ .addr = .{ 100, 64, 0, 9 }, .prefix_len = 24 } };
    try testing.expect(a.overlaps(a_host));
    // A non-byte-aligned boundary: /23 covers .0.x and .1.x but not .2.x.
    const a23: Match = .{ .ipv4 = .{ .addr = .{ 100, 64, 0, 0 }, .prefix_len = 23 } };
    try testing.expect(a23.overlaps(outside));
    try testing.expect(!a23.overlaps(.{ .ipv4 = .{ .addr = .{ 100, 64, 2, 1 } } }));
    // The last bit decides at /32 and /31.
    const h1: Match = .{ .ipv4 = .{ .addr = .{ 10, 0, 0, 1 } } };
    const h0_31: Match = .{ .ipv4 = .{ .addr = .{ 10, 0, 0, 0 }, .prefix_len = 31 } };
    const h2_31: Match = .{ .ipv4 = .{ .addr = .{ 10, 0, 0, 2 }, .prefix_len = 31 } };
    try testing.expect(!h1.overlaps(.{ .ipv4 = .{ .addr = .{ 10, 0, 0, 0 } } }));
    try testing.expect(h1.overlaps(h0_31));
    try testing.expect(!h1.overlaps(h2_31));
    // /0 covers everything of its family, nothing of the other.
    const any4: Match = .{ .ipv4 = .{ .addr = @splat(0), .prefix_len = 0 } };
    try testing.expect(any4.overlaps(outside));
    const v6: Match = .{ .ipv6 = .{ .addr = .{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 12, .prefix_len = 32 } };
    const v6_in: Match = .{ .ipv6 = .{ .addr = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 1 } ++ [_]u8{0} ** 10, .prefix_len = 56 } };
    const v6_out: Match = .{ .ipv6 = .{ .addr = .{ 0x20, 0x01, 0x0d, 0xb9 } ++ [_]u8{0} ** 12, .prefix_len = 48 } };
    try testing.expect(!any4.overlaps(v6));
    try testing.expect(v6.overlaps(v6_in) and v6_in.overlaps(v6));
    try testing.expect(!v6.overlaps(v6_out));
    const v6_host_a: Match = .{ .ipv6 = .{ .addr = [_]u8{0} ** 15 ++ .{1} } };
    const v6_host_b: Match = .{ .ipv6 = .{ .addr = [_]u8{0} ** 15 ++ .{2} } };
    try testing.expect(!v6_host_a.overlaps(v6_host_b));
    try testing.expect(v6_host_a.overlaps(v6_host_a));
}

test "match prefix length validity" {
    try testing.expect((Match{ .ipv4 = .{ .addr = @splat(0), .prefix_len = 32 } }).prefixValid());
    try testing.expect(!(Match{ .ipv4 = .{ .addr = @splat(0), .prefix_len = 33 } }).prefixValid());
    try testing.expect((Match{ .ipv6 = .{ .addr = @splat(0), .prefix_len = 128 } }).prefixValid());
    try testing.expect(!(Match{ .ipv6 = .{ .addr = @splat(0), .prefix_len = 129 } }).prefixValid());
}

test "match ethertype + mbit helper" {
    const m4: Match = .{ .ipv4 = .{ .addr = .{ 10, 0, 0, 1 } } };
    const m6: Match = .{ .ipv6 = .{ .addr = @splat(0) } };
    try testing.expectEqual(tc.ETH_P.IP, m4.ethType());
    try testing.expectEqual(tc.ETH_P.IPV6, m6.ethType());
    try testing.expectEqual(@as(u64, 125_000), mbit(1));
    try testing.expectEqual(@as(u64, 1_000_000_000), mbit(8000));
}
