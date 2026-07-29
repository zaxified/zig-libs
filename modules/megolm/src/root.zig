// SPDX-License-Identifier: MIT

//! megolm — Matrix's Megolm group ratchet
//! (https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/megolm.md):
//! a one-way hash ratchet for many-recipient group messaging, plus Ed25519
//! signatures for authenticity. The third real-world group-messaging
//! construction in this collection, alongside `signal` (pairwise Double
//! Ratchet) and `mls` (RFC 9420) — Megolm's own niche is "one sender, many
//! receivers, no peer-to-peer fan-out": a `GroupSession` (`OutboundSession`
//! here) encrypts once per message and every recipient with a copy of the
//! ratchet at-or-before that message's index can decrypt, INCLUDING
//! messages the recipient didn't see live (unlike a pairwise ratchet,
//! nothing needs replaying key-by-key — see ratchet.zig's module doc
//! comment for the fast-forward algorithm that makes this cheap).
//!
//! ## Layout
//!
//!   - `ratchet.zig` — the 128-byte, four-part hash ratchet: `advanceStep`
//!     (one message), the unconditional `advanceToUnchecked` (arbitrary
//!     fast-forward, including the 32-bit-counter wraparound edge case),
//!     and the guarded `advanceTo` (refuses to move backward).
//!   - `cipher.zig` — HKDF-SHA-256 key derivation (`AES_KEY || HMAC_KEY ||
//!     AES_IV` from the ratchet, spec's own "MEGOLM_KEYS" info string) and
//!     AES-256-CBC/PKCS#7 (over the sibling `aescbc` module) + HMAC-SHA-256
//!     (truncated to 8 bytes on the wire).
//!   - `message.zig` — the wire message codec (version + a minimal
//!     Protocol-Buffers-flavored payload + MAC + signature byte ranges);
//!     no key material, no crypto — see that file for why.
//!   - `session_key.zig` — the session-sharing (signed) and session-export
//!     (unsigned) formats megolm.md's "Data exchange formats" defines.
//!   - `session.zig` — `OutboundSession` (encrypt + sign + advance) and
//!     `InboundGroupSession` (verify signature, fast-forward, verify MAC,
//!     decrypt) — the only file holding both ratchet AND Ed25519 key
//!     material together.
//!   - `kat_test.zig` — external anchors: libolm's own ratchet-advance test
//!     vectors and a real libolm-produced session-key + message pair that
//!     decrypts byte-exactly; see SPEC.md for the anchoring grade of every
//!     area this module covers.
//!
//! Provenance: see NOTICE. See SPEC.md for the ratchet algorithm's
//! byte-layout and the threat-model notes (Message Replays, Lack of
//! Transcript Consistency, Lack of Backward Secrecy, Partial Forward
//! Secrecy — all named limitations in the spec itself, not gaps this
//! module introduces).

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util, // pure computation over caller-supplied bytes/keys -- no owned socket/transport
    .concurrency = .reentrant, // no globals; every type here is a plain caller-owned value
    .model_after = "Matrix Megolm (gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/megolm.md); libolm (megolm.c) and vodozemac (megolm/ratchet.rs) as design references + test-vector source -- see NOTICE",
    .deps = .{"aescbc"},
};

pub const ratchet = @import("ratchet.zig");
pub const cipher = @import("cipher.zig");
pub const message = @import("message.zig");
pub const session_key = @import("session_key.zig");
pub const session = @import("session.zig");

// Flat re-exports of the surface most callers use.
pub const Ratchet = ratchet.Ratchet;
pub const RatchetError = ratchet.RatchetError;
pub const Message = message.Message;
pub const SessionKey = session_key.SessionKey;
pub const ExportedSessionKey = session_key.ExportedSessionKey;
pub const OutboundSession = session.OutboundSession;
pub const InboundGroupSession = session.InboundGroupSession;
pub const DecryptedMessage = session.DecryptedMessage;
pub const DecryptError = session.DecryptError;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too.
test {
    _ = ratchet;
    _ = cipher;
    _ = message;
    _ = session_key;
    _ = session;
    _ = @import("kat_test.zig");
}

test "meta.deps names aescbc, the AES-CBC/PKCS7 primitive this composes" {
    try std.testing.expectEqualStrings("aescbc", meta.deps[0]);
    try std.testing.expectEqual(@as(usize, 1), meta.deps.len);
}

test "meta.role is .util (no owned transport/socket)" {
    try std.testing.expectEqual(.util, meta.role);
}

test "ratchet is 128 bytes, four 32-byte parts (spec: 256-bit parts)" {
    try std.testing.expectEqual(@as(usize, 128), ratchet.ratchet_len);
    try std.testing.expectEqual(@as(usize, 32), ratchet.part_len);
    try std.testing.expectEqual(@as(usize, 4), ratchet.num_parts);
}
