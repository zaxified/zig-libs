//! isis-spf — compute the IS-IS shortest-path forwarding table from an
//! `isis-lsdb`: walk each LSP's IS-reachability TLVs into a topology graph
//! (system-id ↔ node), require two-way reachability per edge, run the M0
//! `spf-ect` Dijkstra + ECT tie-breaking from the local system, and emit a
//! route table (destination system-id → next-hop system-id + total metric).
//! Pure and deterministic — the bridge that turns the synchronised link-state
//! database into forwarding decisions. P2P first (LAN pseudonodes are a later
//! step).
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "ISO/IEC 10589 §7.2 decision process (SPF) + IEEE 802.1aq ECT",
    .deps = .{ "isis", "isis-lsdb", "spf-ect" },
};

test "smoke" {
    try std.testing.expect(true);
}
