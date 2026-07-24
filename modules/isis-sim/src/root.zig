//! isis-sim — a headless multi-node IS-IS/SPB fabric convergence simulator: a
//! `netsim` Protocol that runs the isis control-plane stack (`isis-lsdb` +
//! `isis-flood`, with `isis-spf` for the resulting routes) on every node over
//! the simulated medium, and asserts the fabric CONVERGES — every node's LSDB
//! synchronises to the same set of LSPs — and RECONVERGES after a netsim-injected
//! link failure. The end-to-end proof that the five-layer P2P isis stack works
//! together. Adjacencies are the netsim links (up unless failed); the adjacency
//! FSM handshake is out of scope here (statically-configured neighbours).
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "netsim Protocol harness driving the isis-lsdb/flood/spf stack",
    .deps = .{ "netsim", "isis", "isis-lsdb", "isis-flood", "isis-spf" },
};

test "smoke" {
    try std.testing.expect(true);
}
