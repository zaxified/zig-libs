// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising the real,
//! stub-backed election protocol (`protocol.zig`'s `DfElect`, which calls
//! `election.decide`). Everything ELSE in this module — the wire codecs
//! (`types.zig`), both invariant checkers (`checks.zig`), and the
//! positive-control broken protocol with its property/shrink/teeth tests
//! (`protocol.zig`'s `BrokenAlwaysDf`) — is fully real today and needs no
//! gate; it is the proof that the harness has teeth independent of whether
//! the election core is filled in yet.
//!
//! Flip this to `true` once `election.zig`'s `decide()` is no longer a
//! `@panic` stub. The gated tests in `protocol.zig` will then actually drive
//! `DfElect` through netsim's partition/heal fuzzer and enforce the
//! bounded-DF-window + zero-tolerance invariants against the real algorithm.
//!
//! Leaving it `false` makes those tests report **SKIP** (via
//! `error.SkipZigTest`), not PASS — a skip is not a green light. A skipped
//! test still compiles (so `decide`'s signature is exercised by the type
//! checker), it just never calls into the panicking body.
pub const fable_core_implemented = true;
