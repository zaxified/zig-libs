// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising the real,
//! stub-backed consensus core (`server.zig`'s `RaftServer`, which calls the
//! `safety.zig` decision functions). Everything ELSE in this module is fully
//! real today and needs no gate:
//!   - the wire codecs (`types.zig`) and log container (`log.zig`);
//!   - the safety invariant checkers (`checks.zig`) with their synthetic teeth
//!     tests, which exercise EACH of Raft's five safety properties against
//!     hand-built states — proving the harness has teeth independent of whether
//!     the consensus core is filled in yet;
//!   - the deliberately-broken positive control (`server.zig`'s `BrokenRaft`),
//!     which reimplements a naive election that never calls `safety.zig`, so it
//!     runs today and MUST trip the live Election-Safety checker.
//!
//! Flip this to `true` once `safety.zig`'s decision functions are no longer
//! `@panic` stubs. The gated tests in `server.zig` will then actually drive
//! `RaftServer` through `netsim`'s partition/crash/reorder/clock-skew fuzzer and
//! enforce all five safety invariants against the real algorithm.
//!
//! Leaving it `false` makes those tests report **SKIP** (via
//! `error.SkipZigTest`), not PASS — a skip is not a green light. A skipped test
//! still compiles (so the `safety.zig` decision signatures are exercised by the
//! type checker via `RaftServer`'s call sites), it just never enters the
//! panicking bodies.
pub const fable_core_implemented = false;
