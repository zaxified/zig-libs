// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising the real
//! consensus core (`server.zig`'s `RaftServer`, which calls the `safety.zig`
//! decision functions). **FLIPPED: the Fable core is implemented** — the gated
//! model-check tests now run for real. Everything ELSE in this module never
//! needed the gate:
//!   - the wire codecs (`types.zig`) and log container (`log.zig`);
//!   - the safety invariant checkers (`checks.zig`) with their synthetic teeth
//!     tests, which exercise EACH of Raft's five safety properties against
//!     hand-built states — proving the harness has teeth independent of whether
//!     the consensus core is filled in yet;
//!   - the deliberately-broken positive control (`server.zig`'s `BrokenRaft`),
//!     which reimplements a naive election that never calls `safety.zig`, so it
//!     runs today and MUST trip the live Election-Safety checker.
//!
//! With the flag `true`, the gated tests in `server.zig` drive `RaftServer`
//! through `netsim`'s partition/crash/reorder/clock-skew fuzzer and enforce all
//! five safety invariants against the real algorithm — a fuzzed 300-seed fault
//! sweep plus a quiet-network election-liveness sanity run.
//!
//! (History: while the core was still `@panic` stubs this was `false`, making
//! those tests report **SKIP** via `error.SkipZigTest` — a skip, not a fake
//! PASS — while the stub signatures stayed type-checked via `RaftServer`'s
//! call sites.)
pub const fable_core_implemented = true;
