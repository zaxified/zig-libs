// SPDX-License-Identifier: MIT

//! gate — the single switch enabling tests that call into the Fable-stub
//! core, `match.matchEcho` (`src/match.zig`). Everything else in this
//! module — `table.zig`'s bounded `TsTable` (full test suite of its own),
//! `parse.zig`'s TCP Timestamps option parser (KAT + fuzz-style tests), and
//! the `Estimator` shell itself (construction/reset/table-count accessors,
//! `root.zig`) — is fully real today and needs no gate; it is what proves
//! the harness has teeth independent of whether the matching core is filled
//! in yet.
//!
//! Flip this to `true` once `match.zig`'s `matchEcho()` is no longer a
//! `@panic` stub. The gated tests in `kat.zig` and `property.zig` will then
//! actually drive `Estimator.observe` through the KAT corpus and the
//! bounded-memory / no-spurious-sample properties against the real
//! algorithm.
//!
//! Leaving it `false` makes those tests report **SKIP** (via
//! `error.SkipZigTest`), not PASS — a skip is not a green light. A skipped
//! test still compiles (so `matchEcho`'s signature is exercised by the type
//! checker, and `Estimator.observe`'s call site typechecks against it), it
//! just never calls into the panicking body.
pub const fable_core_implemented = true;
