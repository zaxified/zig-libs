// SPDX-License-Identifier: MIT
//! loopix — the Loopix mixnet (Piotrowska–Hayes–Elahi–Meiklejohn–Danezis,
//! USENIX Security 2017), the design underpinning Nym.
//!
//! Loopix's contribution is NOT crypto — its packet is Sphinx, which this repo
//! already ships (`sphinx`, reused here). Its contribution is the **anonymity
//! strategy**: a continuous-time **Poisson mix** (each mix holds every arrival
//! an independent exponential delay, whose memorylessness makes output timing
//! independent of input timing) plus **Poisson cover traffic** (loop + drop
//! chaff that keeps every mix's anonymity set large and detects active
//! attacks), over a **stratified** L-layer topology — giving provable
//! unlinkability against a **global passive adversary**. This module builds
//! and model-checks that strategy inside `netsim`.
//!
//! **Status: complete.** Everything that DEFINES and MEASURES anonymity is real:
//! the stratified topology + route selection (`routing.zig`, incl. a real
//! `sphinx` onion round-trip proving the packet substrate), the fixed-size
//! header codec (`types.zig`), the entire global-passive-adversary anonymity
//! measurement (`adversary.zig` — effective anonymity set + linking probability
//! under the mix's own delay law), and a deliberately-broken **FIFO positive
//! control** (`protocol.zig`) that the harness flags hard. The mixing core —
//! `mixing.sampleExpDelay` (discrete memoryless / geometric hold),
//! `mixing.scheduleRelease`, `mixing.nextCover` — is now implemented
//! (`gate.fable_core_implemented = true`): the real Poisson mix satisfies the
//! retuned `AnonymityBound` across a clean-run seed sweep, while the FIFO and
//! no-cover controls fail it under identical measurement (`protocol.zig`).
//!
//! Scoped OUT of Phase 1 (documented increments, see `SPEC.md`): full clients/
//! providers/PKI, sender-chosen per-hop delays in the real onion (the sim uses
//! the equivalent mix-chosen variant), n−1 active-attack detection via loop
//! cover, and end-to-end (compose-across-L-hops) anonymity vs the per-mix
//! anonymity Phase 1 measures.

const std = @import("std");
const netsim = @import("netsim");
const sphinx = @import("sphinx");

pub const meta = .{
    .platform = .any, // pure discrete-event simulation, no OS/network I/O
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "Loopix (Piotrowska et al., USENIX Security 2017) / Nym — Poisson mix + cover traffic over Sphinx; model-checked in netsim",
    .deps = .{ "netsim", "sphinx" },
};

// ── public API ───────────────────────────────────────────────────────────────

const types = @import("types.zig");
pub const LoopixConfig = types.LoopixConfig;
pub const AnonymityBound = types.AnonymityBound;
pub const MsgKind = types.MsgKind;
pub const MixHeader = types.MixHeader;

const routing = @import("routing.zig");
pub const pickRoute = routing.pickRoute;
pub const pickDestClient = routing.pickDestClient;
pub const HopInstruction = routing.HopInstruction;

/// The anonymity invariant + the global-passive adversary that measures it —
/// the module's real intellectual content (see `adversary.zig`).
const adversary = @import("adversary.zig");
pub const Transit = adversary.Transit;
pub const DelayModel = adversary.DelayModel;
pub const AnonymityResult = adversary.AnonymityResult;
pub const measure = adversary.measure;

/// FABLE tier — see `mixing.zig`. These three are the irreducible mixing core;
/// everything else in this module is fully real today.
const mixing = @import("mixing.zig");
pub const Prng = mixing.Prng;
pub const CoverEvent = mixing.CoverEvent;
pub const sampleExpDelay = mixing.sampleExpDelay;
pub const scheduleRelease = mixing.scheduleRelease;
pub const nextCover = mixing.nextCover;

const protocol = @import("protocol.zig");
pub const Loopix = protocol.Loopix;
/// Positive control — proves the anonymity harness has teeth (see `protocol.zig`).
pub const FifoMix = protocol.FifoMix;
pub const scenario = protocol.scenario;
pub const DEFAULT_CFG = protocol.DEFAULT_CFG;

const gate = @import("gate.zig");
/// Flip once `mixing.zig`'s three stubs are real implementations — see `gate.zig`.
pub const fable_core_implemented = gate.fable_core_implemented;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull x's own
// `test` blocks into `zig build test-loopix` — every submodule must be named
// here too (the dark-tests rule).

test {
    std.testing.refAllDecls(@This());
    _ = @import("types.zig");
    _ = @import("routing.zig");
    _ = @import("adversary.zig");
    _ = @import("mixing.zig");
    _ = @import("protocol.zig");
    _ = @import("gate.zig");
}

test "smoke: module imports and re-exports resolve" {
    _ = netsim;
    _ = sphinx;
    _ = fable_core_implemented; // resolves regardless of its value
    try std.testing.expectEqual(@as(usize, 12), DEFAULT_CFG.nodeCount());
}
