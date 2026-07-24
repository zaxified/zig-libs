//! spbfib — SPB (802.1aq) forwarding addressing: build the unicast B-MAC FIB
//! from an `isis-spf` route table (dest node → next-hop) re-keyed by each node's
//! backbone MAC, and construct the SPBM group multicast destination address from
//! a source's SPSourceID + an I-SID (the BUM DA whose tree `bumtree` computes).
//! SPB installs ONE congruent ECT path per destination (no per-flow ECMP hashing
//! at the data plane — the 16 ECT algorithms give path diversity across I-SIDs,
//! not within a flow). Pure, deterministic; the unicast counterpart to `bumtree`.
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "IEEE 802.1aq SPBM unicast B-MAC FIB + group-DA construction (RFC 6329)",
    .deps = .{"isis-spf"},
};

test "smoke" {
    try std.testing.expect(true);
}
