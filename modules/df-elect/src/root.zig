// SPDX-License-Identifier: MIT
//! df-elect — Designated-Forwarder election with failover + split-horizon for
//! an N-member multihomed edge segment, derived from a link-state Hello flood.
//!
//! Built for an encrypted L2VPN fabric over WireGuard, where there is no BGP to
//! carry EVPN's Ethernet Segment routes: a customer site multihomed to N edge
//! nodes forms an edge segment, and for each Ethernet tag exactly one member
//! must deliver multi-destination (BUM) traffic toward the site. The DF is
//! computed per `<segment, tag>` by RFC 7432 §8.5 service carving (`modulo`)
//! or RFC 8584 §3.2 Highest Random Weight (`hrw`) over the members a node
//! currently sees; a member gives a role up at once and takes one only after
//! `df_wait`. Model-checked in `netsim` under partition, link, crash, restart
//! and clock-jump faults: split-horizon never fails, duplicates occur only in
//! the heal race right after connectivity returns, and a dead DF is replaced
//! within a bounded window (`checks.zig`). See SPEC.md.

const std = @import("std");
const netsim = @import("netsim");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "EVPN-style Designated-Forwarder election for N-member segments (RFC 7432 mod-N, RFC 8584 HRW) with DF-wait failover + split-horizon, from a link-state flood; model-checked in netsim",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "EVPN DF election (RFC 7432 §8.5 service carving, RFC 8584 §2.1 DF wait + §3.2 HRW) + split-horizon (RFC 7432 §8.3), link-state derived; FRRouting EVPN multihoming observed as a black box",
    .deps = .{"netsim"},
};

// ── public API ──────────────────────────────────────────────────────────────

const types = @import("types.zig");
pub const SegmentId = types.SegmentId;
pub const Tag = types.Tag;
pub const Member = types.Member;
pub const max_members = types.max_members;
pub const EdgeSegment = types.EdgeSegment;
pub const Algorithm = types.Algorithm;
pub const ElectConfig = types.ElectConfig;
pub const Hello = types.Hello;
pub const BumFrame = types.BumFrame;
/// Both wire decoders fail closed — see `types.zig`'s module doc.
pub const DecodeError = types.DecodeError;
pub const no_ingress = types.no_ingress;
pub const no_segment = types.no_segment;

const election = @import("election.zig");
pub const designatedForwarder = election.designatedForwarder;
pub const moduloDf = election.moduloDf;
pub const hrwDf = election.hrwDf;
pub const hrwWeight = election.hrwWeight;
pub const preferenceDf = election.preferenceDf;
pub const Role = election.Role;
pub const stepRole = election.stepRole;
pub const allowForward = election.allowForward;

const checks = @import("checks.zig");
pub const DeliveryChecker = checks.DeliveryChecker;
pub const Duplicate = checks.Duplicate;
pub const DfTransition = checks.DfTransition;
pub const maxDuplicateWindow = checks.maxDuplicateWindow;
pub const maxZeroDfWindow = checks.maxZeroDfWindow;
pub const firstUnexplainedDuplicate = checks.firstUnexplainedDuplicate;
pub const worstZeroDfWindow = checks.worstZeroDfWindow;
pub const Origination = checks.Origination;
pub const Loss = checks.Loss;
pub const firstUnexplainedLoss = checks.firstUnexplainedLoss;

const protocol = @import("protocol.zig");
pub const DfElect = protocol.DfElect;
/// Positive control — proves `DeliveryChecker` has teeth (see `protocol.zig`).
pub const BrokenAlwaysDf = protocol.BrokenAlwaysDf;
pub const scenario = protocol.scenario;
pub const segments = protocol.segments;

const gate = @import("gate.zig");
/// See `gate.zig`.
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
    _ = @import("kat_test.zig");
    _ = @import("frr_test.zig");
}

test "smoke: module imports and re-exports resolve" {
    _ = netsim;
    _ = fable_core_implemented; // resolved regardless of its value
    try std.testing.expectEqual(@as(usize, 2), segments.len);
}
