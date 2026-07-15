// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising the BN254
//! optimal-ate pairing core (`pairing.zig`'s `millerLoop` and
//! `finalExponentiation`). Both cores are now REAL (Part-4 Fable
//! crypto-core pass, 2026-07-15 — see those functions' doc comments for
//! the constructions and their independent numeric re-verification), so
//! the gate is flipped to `true`: the gated tests in `pairing.zig`
//! actually drive the `6x+2` Miller walk with its BN-specific
//! Frobenius-tail steps and the easy/hard final exponentiation, and check
//! every pinned KAT vector byte-exactly, plus the bilinearity /
//! non-degeneracy / `pairingCheck` property suite.
//!
//! Everything ELSE in `pairing.zig` — the `Gt`/`PairingPair` type shapes,
//! `multiMillerLoop`'s real infinity-skipping product wiring,
//! `bn_x`/`bn_ate_loop_param`'s comptime-derived-and-KAT-pinned constants,
//! and every pinned KAT hex string's own byte-parsing/round-trip — was
//! fully real (and ungated) already during the scaffold phase; that split
//! is the proof the harness had teeth independent of the two cores (same
//! split `df-elect`'s own `gate.zig` documents for its `election.decide`
//! stub, whose gate flipped the same way once its core landed).
//!
//! While this was `false`, the gated tests reported **SKIP** (via
//! `error.SkipZigTest`), not PASS — a skip is not a green light; flipping
//! to `true` converted all of them to real, executed assertions.
pub const pairing_core_implemented = true;
