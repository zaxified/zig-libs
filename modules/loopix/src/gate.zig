// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising the real
//! Poisson mix (`protocol.zig`'s `Loopix`, which calls
//! `mixing.scheduleRelease` / `mixing.nextCover`). Everything ELSE in this
//! module — the header/route codecs (`types.zig`, `routing.zig`), the entire
//! anonymity measurement (`adversary.zig`), and the `FifoMix` positive control
//! with its teeth tests (`protocol.zig`) — was fully real from the start and
//! needed no gate; it is the proof that the harness has teeth independent of
//! whether the mixing core was filled in yet.
//!
//! **Now `true`: `mixing.zig`'s three functions (`sampleExpDelay` /
//! `scheduleRelease` / `nextCover`) are real implementations, not `@panic`
//! stubs.** The gated test in `protocol.zig` now drives the real `Loopix` mix
//! through netsim and enforces the anonymity invariant (`AnonymityBound`)
//! against it across a seed sweep — see SPEC.md's "Part 2 result" for the
//! measured separation.
//!
//! Left `false`, that test would report **SKIP** (via `error.SkipZigTest`),
//! not PASS — a skip is not a green light. With the flag `true`, the test
//! actually runs (no skips in `zig build test-loopix`).
pub const fable_core_implemented = true;
