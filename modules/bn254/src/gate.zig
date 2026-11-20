// SPDX-License-Identifier: MIT

//! gate — the switch for the tests exercising the BN254 optimal-ate pairing
//! core (`pairing.zig`'s `millerLoop` and `finalExponentiation`). Both cores
//! are implemented (see those functions' doc comments for the constructions
//! and their independent numeric re-verification), so the gate is the
//! constant `true`: the gated tests in `pairing.zig` drive the `6x+2` Miller
//! walk with its BN-specific Frobenius-tail steps and the easy/hard final
//! exponentiation, and check every pinned KAT vector byte-exactly, plus the
//! bilinearity / non-degeneracy / `pairingCheck` property suite.
//!
//! Everything else in `pairing.zig` — the `Gt`/`PairingPair` type shapes,
//! `multiMillerLoop`'s infinity-skipping product wiring,
//! `bn_x`/`bn_ate_loop_param`'s comptime-derived-and-KAT-pinned constants,
//! and every pinned KAT hex string's own byte-parsing/round-trip — is
//! independent of the two cores, so that part of the harness has teeth
//! without them.
//!
//! With the gate `false` the gated tests would report **SKIP** (via
//! `error.SkipZigTest`), not PASS: a skip is not a green light.
pub const pairing_core_implemented = true;
