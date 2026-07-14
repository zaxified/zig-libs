// SPDX-License-Identifier: MIT
//! signal — the Signal Protocol's core cryptographic building blocks,
//! built entirely on `std.crypto`. Planned as a two-part arc:
//!
//!   - **Part 1 (THIS pass): X3DH** (`x3dh.zig`) — Extended Triple
//!     Diffie-Hellman, the asynchronous initial key-agreement
//!     (signal.org/docs/specifications/x3dh), plus **XEdDSA**
//!     (`xeddsa.zig`) — the Montgomery-keypair signature scheme X3DH uses
//!     to sign a signed prekey (signal.org/docs/specifications/xeddsa).
//!   - **Part 2 (NOT in this pass): Double Ratchet** — the per-message
//!     forward-secret/post-compromise-secure ratchet
//!     (signal.org/docs/specifications/doubleratchet) that X3DH's output
//!     (`SK`, `AD`) seeds as its initial root key. See this file's
//!     "Part 2 boundary" note below — nothing in this module produces or
//!     consumes ratchet state; `x3dh.InitialMessage.ciphertext` is opaque
//!     bytes a Part-2 module would supply.
//!
//! **Status: Part 1 COMPLETE.** X3DH's DH+HKDF composition, both wire
//! codecs (`PreKeyBundle`, `InitialMessage`), and XEdDSA (`xeddsa.sign`/
//! `xeddsa.verify` — the one genuinely novel piece of cryptography here,
//! a Montgomery->Edwards point conversion std does not expose in the
//! direction XEdDSA needs, `xeddsa.edwardsFromMontgomery`) are all real
//! and tested, including the fail-closed `x3dh.initiate` and
//! `x3dh.generateSignedPreKey`. XEdDSA follows the SPEC's sign-0
//! convention, which deployed libsignal deliberately deviates from — see
//! `xeddsa.zig`'s module doc comment for the variant note and
//! `src/kat_test.zig` for how the libsignal known-answer vector is used
//! to validate both facts.
//!
//! Consumer: an end-to-end-encrypted messaging application's initial
//! session setup — a client fetches a recipient's `PreKeyBundle` from a
//! directory/coordination server, runs `x3dh.initiate` to get a shared
//! `SK`, and hands `SK` to a Part-2 Double Ratchet to actually encrypt
//! messages. Neither the server transport nor the ratchet itself is in
//! scope for this module — see `README.md`.
//!
//! Provenance: clean-room from the public X3DH and XEdDSA specifications
//! (signal.org/docs/specifications/{x3dh,xeddsa} — Signal Foundation /
//! Trevor Perrin, Moxie Marlinspike). See `NOTICE`.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util, // pure computation over caller-supplied keys/bytes — no owned socket/transport
    .concurrency = .reentrant, // no globals; every type here is a plain caller-owned value
    .model_after = "Signal X3DH (signal.org/docs/specifications/x3dh) + XEdDSA (signal.org/docs/specifications/xeddsa); std.crypto.dh.X25519 supplies the DH, std.crypto.ecc.Edwards25519/std.crypto.hash.sha2.Sha512 supply XEdDSA's building blocks, std.crypto.kdf.hkdf.HkdfSha256 supplies the KDF",
    .deps = .{}, // std only
};

pub const xeddsa = @import("xeddsa.zig");
pub const x3dh = @import("x3dh.zig");

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

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too.
test {
    _ = xeddsa;
    _ = x3dh;
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
