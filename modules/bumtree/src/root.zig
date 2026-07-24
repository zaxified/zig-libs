//! bumtree — SPB per-source loop-free BUM (broadcast/unknown-unicast/multicast)
//! distribution tree + Reverse-Path-Forwarding check, over the M0 `spf-ect`
//! shortest-path engine. For one I-SID's member set and one source node it
//! computes, per node, the replication next-hops (children in the source's
//! shortest-path tree, pruned to branches that lead to a member) and the single
//! RPF ingress (the neighbour on the path back to the source — the only edge a
//! BUM frame from that source may legally arrive on). This is the control-plane
//! loop-free BUM tree that the data-plane `l2encap`/`l2forward` explicitly defer
//! to: source-PE split-horizon stops reflection, RPF + the tree stop transient
//! loops. Pure, deterministic (spf-ect's ECT tie-break makes trees congruent).
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "IEEE 802.1aq per-source SPT multicast trees + RPFC (SPBM)",
    .deps = .{"spf-ect"},
};

test "smoke" {
    try std.testing.expect(true);
}
