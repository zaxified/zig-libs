// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising
//! Bulletproofs' two Fable-hard cores: the Inner-Product Argument
//! (`ipa.zig`'s `proveIpa`/`verifyIpa`) and the range-proof polynomial
//! construction/reduction (`rangeproof.zig`'s `prove`/`verify`, which
//! internally calls the IPA). One flag covers both: `rangeproof.prove`/
//! `.verify` cannot be exercised without `ipa.proveIpa`/`.verifyIpa`
//! already working (the range proof's LAST step IS a call into the IPA —
//! see `rangeproof.zig`'s module doc comment), so there is no
//! intermediate state where one core is done and the other isn't testable
//! yet; splitting this into two flags would only add bookkeeping with no
//! corresponding test-tier that could actually run early.
//!
//! Everything ELSE in this module — `generators.zig`'s NUMS derivation,
//! `transcript.zig`'s Fiat-Shamir transcript, `scalarvec.zig`'s scalar/
//! vector/multi-scalar-mult helpers, `ipa.InnerProductProof`'s struct +
//! byte codec, `rangeproof.RangeProof`'s struct + byte codec,
//! `rangeproof.commit`/`rangeproof.deltaYZ`, and `rangeproof.prove`'s
//! `error.ValueOutOfRange` construction-time guard — is fully real today
//! and needs no gate; it is what proves the harness has teeth independent
//! of whether the two ZK cores are filled in yet (see `kat_test.zig`'s
//! ungated tests).
//!
//! While this was `false`, the gated tests in `kat_test.zig` reported
//! **SKIP** (via `error.SkipZigTest`), never PASS — a skip is not a green
//! light. It is now `true`: the Fable core pass implemented
//! `proveIpa`/`verifyIpa`/`prove`/`verify` for real, converting them into
//! real, executed assertions — see `bn254`'s `gate.zig` /
//! `threshold_ecdsa`'s `gate.zig` for the identical convention this
//! follows.
pub const core_implemented = true;
