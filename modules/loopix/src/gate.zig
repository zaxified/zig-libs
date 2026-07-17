// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising the real,
//! stub-backed Poisson mix (`protocol.zig`'s `Loopix`, which calls
//! `mixing.scheduleRelease` / `mixing.nextCover`). Everything ELSE in this
//! module — the header/route codecs (`types.zig`, `routing.zig`), the entire
//! anonymity measurement (`adversary.zig`), and the `FifoMix` positive control
//! with its teeth tests (`protocol.zig`) — is fully real today and needs no
//! gate; it is the proof that the harness has teeth independent of whether the
//! mixing core is filled in yet.
//!
//! Flip this to `true` once `mixing.zig`'s three `@panic` stubs
//! (`sampleExpDelay` / `scheduleRelease` / `nextCover`) are implemented. The
//! gated test in `protocol.zig` will then drive the real `Loopix` mix through
//! netsim and enforce the anonymity invariant (`AnonymityBound`) against it
//! across a seed sweep.
//!
//! Leaving it `false` makes that test report **SKIP** (via
//! `error.SkipZigTest`), not PASS — a skip is not a green light. The gated
//! test still compiles (so the mix's call sites into `mixing.zig` are
//! type-checked), it just never calls into the panicking bodies.
pub const fable_core_implemented = true;
