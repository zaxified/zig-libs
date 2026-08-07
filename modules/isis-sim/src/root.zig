// SPDX-License-Identifier: MIT

//! isis-sim — a headless multi-node IS-IS/SPB fabric convergence simulator: a
//! `netsim` Protocol that runs the isis control-plane stack (`isis-lsdb` +
//! `isis-flood`, with `isis-spf` for the resulting routes) on every node over
//! the simulated medium, and asserts the fabric CONVERGES — every node's LSDB
//! synchronises to the same set of LSPs — and RECONVERGES after a link failure.
//! The end-to-end proof that the five-layer P2P isis stack works together.
//!
//! Adjacencies are the netsim links (a link is up unless failed); the adjacency
//! FSM handshake (`isis-adj`) is out of scope here — neighbours are statically
//! configured by the topology. See `SPEC.md` for the node-state model, the
//! onStart/onMessage/onTimer/check wiring, the convergence + quiescence
//! invariants, the reconvergence/partition handling, and the deferred list.
//!
//! ## The harness API (see `fabric.zig`)
//!   - `Fabric.init(gpa, topology, seed)` — build a small P2P fabric from a node
//!     count + a weighted adjacency list.
//!   - `failLink(a, b)` / `failLinkAt(a, b, time)` — register a mid-run link
//!     failure (both endpoints re-originate; the netsim link is severed).
//!   - `runToConvergence(max_steps)` — drive the fabric through `netsim.replay`
//!     to a quiesced steady state, or `.safety_violated` / `.event_cap_exceeded`
//!     / `.not_quiescent` (see `Outcome`) short of it.
//!   - `lsdbsAgree`, `routes`, `reaches`, `selfSequence`, `systemIdOf` — inspect
//!     the converged state.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "netsim Protocol harness driving the isis-lsdb/flood/spf stack",
    .deps = .{ "netsim", "isis", "isis-lsdb", "isis-flood", "isis-spf" },
};

const fabric = @import("fabric.zig");

// ── the harness surface, re-exported ─────────────────────────────────────────
pub const Fabric = fabric.Fabric;
pub const Topology = fabric.Topology;
pub const Edge = fabric.Edge;
pub const Outcome = fabric.Outcome;
pub const SystemId = fabric.SystemId;
pub const systemIdForNode = fabric.systemIdForNode;

test {
    std.testing.refAllDecls(@This());
    _ = fabric;
}
