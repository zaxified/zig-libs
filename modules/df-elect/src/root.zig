// SPDX-License-Identifier: MIT
//! df-elect — Designated-Forwarder election + split-horizon, partition-correct.
//!
//! The #2 jewel of the S1b fabric (see ~/CML/S1B-scada-l2vpn-venture-plan.md §5): a
//! customer site dual-homed to two edge nodes forms an edge segment; exactly one node
//! must be the Designated Forwarder for BUM traffic toward the site, deterministically
//! from link-state, and — the hard part — correct under arbitrary network partition
//! (never two DFs beyond a bounded window, never zero DFs beyond a bounded window, no
//! duplicate/loop injection). Model-checked in `netsim` under partition/heal schedules
//! with explicit bounded-badness claims. Split-horizon prevents same-segment reflection.
//!
//! **Status: harness complete, core is a Fable stub.** The `netsim.Protocol`
//! consumer (Hello + BUM flooding, `protocol.zig`), both zero-tolerance
//! invariant checks and the bounded-DF-window post-run analyzer
//! (`checks.zig`), the property/shrink/teeth test harness, and a
//! deliberately-broken positive control (`protocol.BrokenAlwaysDf`) are all
//! real and pass today. The one thing that is NOT implemented is the
//! irreducible algorithm itself — `election.decide` — a
//! `@panic("TODO(fable/core): ...")` stub (see `election.zig`). Tests that
//! would call it transitively are gated behind `gate.fable_core_implemented`
//! and report SKIP, not PASS, until that flag flips.

const std = @import("std");
const netsim = @import("netsim");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "EVPN ESI/DF-election + split-horizon (RFC 7432), link-state derived",
    .deps = .{"netsim"},
};

// ── public API ──────────────────────────────────────────────────────────────

const types = @import("types.zig");
pub const SegmentId = types.SegmentId;
pub const EdgeSegment = types.EdgeSegment;
pub const ElectConfig = types.ElectConfig;
pub const Hello = types.Hello;
pub const BumFrame = types.BumFrame;
pub const no_ingress = types.no_ingress;

/// FABLE tier — see `election.zig`. `decide` is the irreducible algorithm;
/// everything else in this module (below) is fully real today.
const election = @import("election.zig");
pub const SegmentView = election.SegmentView;
pub const Decision = election.Decision;
pub const decide = election.decide;

const checks = @import("checks.zig");
pub const DeliveryChecker = checks.DeliveryChecker;
pub const DfTransition = checks.DfTransition;
pub const maxBadDfWindow = checks.maxBadDfWindow;
pub const worstBadDfWindow = checks.worstBadDfWindow;

const protocol = @import("protocol.zig");
pub const DfElect = protocol.DfElect;
/// Positive control — proves `DeliveryChecker` has teeth (see `protocol.zig`).
pub const BrokenAlwaysDf = protocol.BrokenAlwaysDf;
pub const scenario = protocol.scenario;
pub const segments = protocol.segments;

const gate = @import("gate.zig");
/// Flip once `election.decide` is a real implementation — see `gate.zig`.
pub const fable_core_implemented = gate.fable_core_implemented;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────────
//
// refAllDecls walks every pub declaration reachable from this file (including
// the sub-module re-exports above), which is what pulls types.zig /
// election.zig / checks.zig / protocol.zig / gate.zig's own `test` blocks
// into `zig build test-df-elect` — a bare `pub const x = @import("x.zig")`
// re-export alone does NOT do this (the dark-tests rule).

test {
    std.testing.refAllDecls(@This());
    _ = @import("types.zig");
    _ = @import("election.zig");
    _ = @import("checks.zig");
    _ = @import("protocol.zig");
    _ = @import("gate.zig");
}

test "smoke: module imports and re-exports resolve" {
    _ = netsim;
    _ = fable_core_implemented; // resolved regardless of its value
    try std.testing.expectEqual(@as(usize, 2), segments.len);
}
