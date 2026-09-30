// SPDX-License-Identifier: MIT

//! gate — the switch that turns on the model-checking tests of the real
//! protocol (`protocol.zig`'s fuzz sweep over `DfElect`). Kept from the
//! scaffold era, when the election core was a `@panic` stub and these tests
//! had to report SKIP; the core is implemented, so it is `true`. Leaving it
//! `false` would make the sweep report SKIP, not PASS — a skip is not a
//! green light.
pub const fable_core_implemented = true;
