// SPDX-License-Identifier: MIT

//! timelock_envelope — a hybrid **two-lock sealed envelope**. `seal`
//! produces a ciphertext that `open` can decrypt only when BOTH locks
//! hold at once:
//!
//! 1. **Time gate** (`tlock`) — a target drand round `R` has published
//!    its beacon signature. Before round `R`, this lock is closed for
//!    everyone (a temporal secret — nobody holds the key early). `tlock`
//!    is pairing-based (BLS12-381), so this lock is **NOT post-quantum**;
//!    it enforces *timing* only.
//! 2. **Recipient PQ key** (`hqc`) — the opener holds the HQC code-based
//!    KEM secret key whose public key sealed the envelope. HQC is
//!    genuinely post-quantum, so this lock carries the envelope's
//!    long-term **confidentiality** against a future quantum adversary
//!    who records the ciphertext today.
//!
//! The composition is a true **AND**: the content key is
//! `HKDF-SHA256(s_time || s_pq, context)`, where `s_time` is recoverable
//! only via the time lock (at/after `R`) and `s_pq` only via the PQ lock
//! (with the recipient's secret key). Content is sealed with `chachapoly`
//! (ChaCha20-Poly1305) under that key, authenticating the whole header +
//! both lock ciphertexts as AAD. Neither lock alone suffices — see
//! `envelope.zig`'s module doc for how each is enforced, and `SPEC.md`
//! for the wire format, threat model, and the honest post-quantum caveat.
//!
//! This is a **composition module**: it wires together the already-
//! verified `tlock`, `hqc`, and `chachapoly` primitives exactly as they
//! ship and derives keys with `std.crypto.kdf.hkdf`. It reimplements no
//! cryptography, runs no drand beacon or DKG (`p_pub`/`round_signature`
//! are caller-supplied, as `tlock` requires), and is the crypto core of
//! the S5 dead-man-switch.

const std = @import("std");

/// The construction: the generic `Envelope(Kem)` plus the shared wire
/// constants, key-derivation, and error sets.
pub const envelope = @import("envelope.zig");

/// The hybrid two-lock envelope, generic over the HQC parameter set.
pub const Envelope = envelope.Envelope;
/// HQC-128 (NIST category 1) specialisation.
pub const Envelope128 = envelope.Envelope128;
/// HQC-192 (NIST category 3) specialisation.
pub const Envelope192 = envelope.Envelope192;
/// HQC-256 (NIST category 5) specialisation.
pub const Envelope256 = envelope.Envelope256;

/// Bind both locks' secrets into a content key + nonce (HKDF-SHA256).
pub const deriveKeys = envelope.deriveKeys;
pub const DerivedKeys = envelope.DerivedKeys;
pub const SealError = envelope.SealError;
pub const OpenError = envelope.OpenError;

pub const meta = .{
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "drand tlock + PQ-KEM hybrid envelope (age-style two-lock KDF)",
    .deps = .{ "tlock", "hqc", "chachapoly" },
};

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ─────────────────
//
// A bare `pub const x = @import("x.zig")` does NOT pull x's tests into
// the test binary — every submodule with tests must be named here.

test {
    _ = envelope;
    _ = @import("security_test.zig");
}

test "meta.deps is exactly {tlock, hqc, chachapoly}" {
    try std.testing.expectEqual(@as(usize, 3), meta.deps.len);
    try std.testing.expectEqualStrings("tlock", meta.deps[0]);
    try std.testing.expectEqualStrings("hqc", meta.deps[1]);
    try std.testing.expectEqualStrings("chachapoly", meta.deps[2]);
}
