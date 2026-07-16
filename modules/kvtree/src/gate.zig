// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising the real
//! transactional core (`core.zig`'s `commit`, `recover` and
//! `reclaimGate`, reached transitively by any durable write / crash-recovery /
//! page-reuse path). Everything ELSE in this module — the page/node codecs and
//! B-tree mechanics (`format.zig`), the `Pager` + freelist container
//! (`pager.zig`), the read path (descend + cursor + ordered scan in
//! `root.zig`), and the whole property harness with its in-memory oracle and
//! deliberately-broken positive control (`harness.zig`) — is fully real today
//! and needs no gate. That is the proof the harness has teeth independent of
//! whether the transactional core is filled in yet.
//!
//! FLIPPED `true`: `core.zig`'s three functions are implemented. The gated
//! tests in `harness.zig` now drive a real `Db` through transaction/snapshot
//! schedules and a crash-point sweep on `kv.SimStorage`, model-checking
//! snapshot isolation, serializability, sorted scans and
//! crash-recovery-to-a-committed-prefix against the live implementation.
//!
//! (While it was `false`, those tests reported **SKIP** via
//! `error.SkipZigTest`, not PASS — a skip is not a green light.)
pub const fable_core_implemented = true;
