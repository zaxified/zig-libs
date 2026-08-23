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
//!   - **Part 3: PQXDH** (`pqxdh.zig`) — the post-quantum successor to X3DH
//!     (signal.org/docs/specifications/pqxdh): the same three-or-four
//!     Diffie-Hellman agreements plus one **ML-KEM-1024** encapsulation
//!     against a signed post-quantum prekey, so traffic recorded today
//!     survives a future quantum adversary. Signal has run PQXDH by default
//!     since 2023, which makes X3DH alone the legacy path rather than the
//!     current one. Note the algorithm: the spec text still names round-3
//!     Crystals-Kyber-1024 and cites a FIPS 203 *draft*, while deployments
//!     use FIPS 203 final ML-KEM-1024 — the two are not wire-compatible, and
//!     this file implements ML-KEM. `pqxdh.zig`'s own doc comment has the
//!     detail, including why there are no published vectors to anchor on.
//!   - **Part 2: Double Ratchet** (`ratchet.zig`) — the per-message
//!     forward-secret/post-compromise-secure ratchet
//!     (signal.org/docs/specifications/doubleratchet) that X3DH's output
//!     (`SK`, `AD`) seeds as its initial root key: `SK` becomes the
//!     initial root key `RK`, `AD` is mixed into every message's AEAD
//!     associated data.
//!
//! **Status: Parts 1-3 COMPLETE.** X3DH's DH+HKDF composition, both
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
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Signal Protocol — X3DH key agreement, XEdDSA signing, and the Double Ratchet: E2EE sessions with forward secrecy and post-compromise security.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure computation over caller-supplied keys/bytes — no owned socket/transport
    .concurrency = .reentrant, // no globals; every type here is a plain caller-owned value
    .model_after = "Signal X3DH (signal.org/docs/specifications/x3dh) + PQXDH (signal.org/docs/specifications/pqxdh, over std.crypto.kem.ml_kem.MLKem1024 -- FIPS 203 final, NOT the round-3 Kyber the spec text still names) + XEdDSA (signal.org/docs/specifications/xeddsa) + Double Ratchet (signal.org/docs/specifications/doubleratchet); std.crypto.dh.X25519 supplies the DH (agreement + ratchet), std.crypto.ecc.Edwards25519/std.crypto.hash.sha2.Sha512 supply XEdDSA's building blocks, std.crypto.kdf.hkdf.HkdfSha256 supplies the KDFs (X3DH + KDF_RK), std.crypto.auth.hmac.sha2.HmacSha256 supplies KDF_CK, the chachapoly sibling (byte-exact to std.crypto.aead.chacha_poly.ChaCha20Poly1305) supplies the ratchet AEAD",
    // chachapoly: the ratchet AEAD (byte-exact to std; one audited
    // ChaCha20-Poly1305 across the repo). ct25519: the constant-time
    // secret-scalar ladder XEdDSA signs on. entropy: the seed behind
    // `x3dh.generateKeyPair`, i.e. every private key this module mints.
    // Everything else is std.
    .deps = .{ "chachapoly", "ct25519", "entropy" },
};

pub const xeddsa = @import("xeddsa.zig");
pub const x3dh = @import("x3dh.zig");
pub const pqxdh = @import("pqxdh.zig");
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

// Flat re-exports of the PQXDH surface (Part 3). Deliberately prefixed rather
// than shadowing the X3DH names: the two protocols have DIFFERENT bundles,
// messages and associated data, and a caller who mixed them would get a
// bundle that silently fails to decode rather than a compile error.
pub const PqPreKeyBundle = pqxdh.PreKeyBundle;
pub const PqInitialMessage = pqxdh.InitialMessage;
pub const PqAgreement = pqxdh.Agreement;
pub const KemPreKey = pqxdh.KemPreKey;
pub const pqInitiate = pqxdh.initiate;
pub const pqInitiateUnverified = pqxdh.initiateUnverified;
pub const pqRespond = pqxdh.respond;
pub const generateKemPreKey = pqxdh.generateKemPreKey;

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
    _ = pqxdh;
    _ = ratchet;
    _ = @import("kat_test.zig");
}

test "meta.deps is exactly {chachapoly, ct25519, entropy} (the ratchet AEAD + the CT ladder + the fail-closed key draw)" {
    // `ct25519` is std's own Edwards25519 window ladder with the trailing
    // `rejectIdentity` removed — XEdDSA multiplies the base point by two
    // SECRET scalars (the sign-0 key scalar and the per-signature nonce),
    // and std's `mul` ends by branching on the result of exactly those.
    try std.testing.expectEqual(@as(usize, 3), meta.deps.len);
    try std.testing.expectEqualStrings("chachapoly", meta.deps[0]);
    try std.testing.expectEqualStrings("ct25519", meta.deps[1]);
    // `entropy` is the seed in `x3dh.generateKeyPair` — every identity,
    // signed-prekey, one-time-prekey, X3DH ephemeral and Double Ratchet DH
    // key this module mints. It does NOT reach the KAT seam, which takes
    // its randomness (`xeddsa.sign`'s `z`) as a parameter.
    try std.testing.expectEqualStrings("entropy", meta.deps[2]);
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
