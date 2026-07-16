// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising the real,
//! stub-backed transactional core (`core.zig`'s `commit`, `recover` and
//! `reclaimGate`, reached transitively by any durable write / crash-recovery /
//! page-reuse path). Everything ELSE in this module — the page/node codecs and
//! B-tree mechanics (`format.zig`), the `Pager` + freelist container
//! (`pager.zig`), the read path (descend + cursor + ordered scan in
//! `root.zig`), and the whole property harness with its in-memory oracle and
//! deliberately-broken positive control (`harness.zig`) — is fully real today
//! and needs no gate. That is the proof the harness has teeth independent of
//! whether the transactional core is filled in yet.
//!
//! Flip this to `true` once `core.zig`'s three functions are no longer
//! `@panic` stubs. The gated tests in `harness.zig` will then drive a real
//! `Db` through randomized transaction/crash schedules on `kv.SimStorage` and
//! model-check snapshot isolation, serializability, sorted scans and
//! crash-recovery-to-a-committed-prefix against the live implementation.
//!
//! Leaving it `false` makes those tests report **SKIP** (via
//! `error.SkipZigTest`), not PASS — a skip is not a green light. A skipped
//! test still compiles (so the core's signatures are type-checked), it just
//! never calls into the panicking bodies.
pub const fable_core_implemented = false;
