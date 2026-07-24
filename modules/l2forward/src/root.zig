//! l2forward — the E-LAN edge forwarding table for a multi-tenant L2VPN fabric:
//! per-I-SID customer-MAC learning (MAC → remote PE) with time-injected aging,
//! plus the BUM (broadcast/unknown-unicast/multicast) ingress-replication set
//! with split-horizon (never replicate back to the source PE). Given a frame's
//! destination MAC + I-SID + source PE it returns a forward decision: a single
//! remote PE for a known unicast, or the replication set for BUM/unknown. Pure,
//! deterministic, bounded (capacity-capped); pairs with `l2encap`. The caller
//! populates I-SID membership from the control plane and drives `now`/I/O.
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "EVPN/SPB ingress replication + 802.1D MAC learning FDB, per-I-SID",
    .deps = .{},
};

test "smoke" {
    try std.testing.expect(true);
}
