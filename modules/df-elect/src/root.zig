// SPDX-License-Identifier: MIT
//! df-elect — Designated-Forwarder election + split-horizon, partition-correct.
//!
//! Built for an encrypted L2VPN fabric over WireGuard: a
//! customer site dual-homed to two edge nodes forms an edge segment; exactly one node
//! must be the Designated Forwarder for BUM traffic toward the site, deterministically
//! from link-state, and — the hard part — correct under arbitrary network partition
//! (never two DFs beyond a bounded window, never zero DFs beyond a bounded window, no
//! duplicate/loop injection). Model-checked in `netsim` under partition/heal schedules
//! with explicit bounded-badness claims. Split-horizon prevents same-segment reflection.
//!
//! **Status: complete — harness and core both implemented.** The
//! `netsim.Protocol` consumer (Hello + BUM flooding, `protocol.zig`), both
//! zero-tolerance invariant checks and the bounded-DF-window post-run
//! analyzer (`checks.zig`), the property/shrink/teeth test harness, and a
//! deliberately-broken positive control (`protocol.BrokenAlwaysDf`) are all
//! real and pass today. The irreducible algorithm itself — `election.decide`
//! (see `election.zig`) — is also implemented (no longer a stub); `gate.
//! fable_core_implemented` is `true`, so the tests that drive `DfElect`
//! through netsim's partition/heal fuzzer run for real and report PASS, not
//! SKIP.

const std = @import("std");
const netsim = @import("netsim");

pub const meta = .{
    .targets = .{.linux64},
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
/// Both wire decoders fail closed — see `types.zig`'s module doc.
pub const DecodeError = types.DecodeError;
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
