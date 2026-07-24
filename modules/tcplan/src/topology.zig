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
    /// The classifier for a subscriber leaf. Ignored (and required to be null)
    /// on an interior node — only leaves are steered. A leaf with `null` here
    /// gets its class + CAKE qdisc but no steering filter (documented).
    match: ?Match = null,
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

test "match ethertype + mbit helper" {
    const m4: Match = .{ .ipv4 = .{ .addr = .{ 10, 0, 0, 1 } } };
    const m6: Match = .{ .ipv6 = .{ .addr = @splat(0) } };
    try testing.expectEqual(tc.ETH_P.IP, m4.ethType());
    try testing.expectEqual(tc.ETH_P.IPV6, m6.ethType());
    try testing.expectEqual(@as(u64, 125_000), mbit(1));
    try testing.expectEqual(@as(u64, 1_000_000_000), mbit(8000));
}
