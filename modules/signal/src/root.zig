// SPDX-License-Identifier: MIT
//! signal — the Signal Protocol's core cryptographic building blocks,
//! built entirely on `std.crypto`. A two-part arc, now BOTH complete —
//! together a usable Signal-style end-to-end-encrypted session:
//!
//!   - **Part 1: X3DH** (`x3dh.zig`) — Extended Triple Diffie-Hellman, the
//!     asynchronous initial key-agreement
//!     (signal.org/docs/specifications/x3dh), plus **XEdDSA**
//!     (`xeddsa.zig`) — the Montgomery-keypair signature scheme X3DH uses
//!     to sign a signed prekey (signal.org/docs/specifications/xeddsa).
//!   - **Part 2: Double Ratchet** (`ratchet.zig`) — the per-message
//!     forward-secret/post-compromise-secure ratchet
//!     (signal.org/docs/specifications/doubleratchet) that X3DH's output
//!     (`SK`, `AD`) seeds as its initial root key: `SK` becomes the
//!     initial root key `RK`, `AD` is mixed into every message's AEAD
//!     associated data.
//!
//! **Status: Part 1 + Part 2 COMPLETE.** X3DH's DH+HKDF composition, both
//! wire codecs (`PreKeyBundle`, `InitialMessage`), and XEdDSA
//! (`xeddsa.sign`/`xeddsa.verify` — the one genuinely novel piece of
//! cryptography here, a Montgomery->Edwards point conversion std does not
//! expose in the direction XEdDSA needs, `xeddsa.edwardsFromMontgomery`)
//! are all real and tested, including the fail-closed `x3dh.initiate` and
//! `x3dh.generateSignedPreKey`. The Double Ratchet (`ratchet.State` with
//! `initAlice`/`initBob`/`encrypt`/`decrypt`, `KDF_RK`/`KDF_CK`, the DH +
//! symmetric-key ratchets, `max_skip`-bounded out-of-order handling, and a
//! transactional fail-closed `decrypt`) is real and tested end-to-end
//! seeded from a live X3DH agreement. `xeddsa.sign`/`verify` follow the
//! SPEC's sign-0 convention; `xeddsa.libsignal.sign`/`verify` implement
//! deployed libsignal's documented deviation instead (natural-sign key,
//! sign bit smuggled in `s`'s top bit) — a caller names one or the other
//! explicitly, there is no default. See `xeddsa.zig`'s module doc comment
//! for the variant note and `src/kat_test.zig` for how the libsignal
//! known-answer vector anchors BOTH.
//!
//! Consumer: an end-to-end-encrypted messaging application — a client
//! fetches a recipient's `PreKeyBundle` from a directory/coordination
//! server, runs `x3dh.initiate` to get a shared `SK`/`AD`, seeds a
//! `ratchet.State` from it (`initAlice`/`initBob`), and then
//! `encrypt`/`decrypt`s the actual message stream. The server transport
//! itself is out of scope for this module — see `README.md`.
//!
//! Provenance: clean-room from the public X3DH and XEdDSA specifications
//! (signal.org/docs/specifications/{x3dh,xeddsa} — Signal Foundation /
//! Trevor Perrin, Moxie Marlinspike). See `NOTICE`.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util, // pure computation over caller-supplied keys/bytes — no owned socket/transport
    .concurrency = .reentrant, // no globals; every type here is a plain caller-owned value
    .model_after = "Signal X3DH (signal.org/docs/specifications/x3dh) + XEdDSA (signal.org/docs/specifications/xeddsa) + Double Ratchet (signal.org/docs/specifications/doubleratchet); std.crypto.dh.X25519 supplies the DH (agreement + ratchet), std.crypto.ecc.Edwards25519/std.crypto.hash.sha2.Sha512 supply XEdDSA's building blocks, std.crypto.kdf.hkdf.HkdfSha256 supplies the KDFs (X3DH + KDF_RK), std.crypto.auth.hmac.sha2.HmacSha256 supplies KDF_CK, std.crypto.aead.chacha_poly.ChaCha20Poly1305 supplies the ratchet AEAD",
    .deps = .{}, // std only
};

pub const xeddsa = @import("xeddsa.zig");
pub const x3dh = @import("x3dh.zig");
pub const ratchet = @import("ratchet.zig");

// Flat re-exports of the X3DH surface — the module most callers use.
pub const IdentityKey = x3dh.IdentityKey;
pub const EphemeralKey = x3dh.EphemeralKey;
pub const SignedPreKey = x3dh.SignedPreKey;
pub const OneTimePreKey = x3dh.OneTimePreKey;
pub const PreKeyBundle = x3dh.PreKeyBundle;
pub const InitialMessage = x3dh.InitialMessage;
pub const Agreement = x3dh.Agreement;
pub const initiate = x3dh.initiate;
pub const initiateUnverified = x3dh.initiateUnverified;
pub const respond = x3dh.respond;
pub const generateSignedPreKey = x3dh.generateSignedPreKey;

// Flat re-exports of the Double Ratchet surface (Part 2).
pub const RatchetState = ratchet.State;
pub const RatchetHeader = ratchet.Header;
pub const RatchetMessage = ratchet.Message;
pub const initAlice = ratchet.State.initAlice;
pub const initBob = ratchet.State.initBob;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too.
test {
    _ = xeddsa;
    _ = x3dh;
    _ = ratchet;
    _ = @import("kat_test.zig");
}

test "meta.deps is empty (std only)" {
    try std.testing.expectEqual(@as(usize, 0), meta.deps.len);
}

test "meta.role is .util (no owned transport/socket, unlike a .client/.server module)" {
    try std.testing.expectEqual(.util, meta.role);
}

test "key/shared-secret/associated-data length constants match X25519's 32-byte field" {
    try std.testing.expectEqual(@as(usize, 32), x3dh.key_length);
    try std.testing.expectEqual(@as(usize, 32), x3dh.shared_secret_length);
    try std.testing.expectEqual(@as(usize, 64), x3dh.associated_data_length);
    try std.testing.expectEqual(@as(usize, 64), x3dh.signature_length);
}
