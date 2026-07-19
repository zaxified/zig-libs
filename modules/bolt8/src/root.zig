// SPDX-License-Identifier: MIT

//! bolt8 — Lightning BOLT#8 encrypted transport
//! (`Noise_XK_secp256k1_ChaChaPoly_SHA256`): the `act1`/`act2`/`act3`
//! Noise_XK handshake plus the post-handshake transport with key rotation.
//!
//! **Status: complete.** Built ON this repo's own `noise` module
//! (`noise.Suite(...).SymmetricState` — see `handshake.zig`'s module doc
//! comment for the exact reuse mechanism): `dh.zig` (the secp256k1 ECDH
//! adapter — plain elliptic-curve arithmetic + SHA-256), `act.zig` (the
//! fixed Act One/Two/Three wire framing), `handshake.zig` (the full
//! three-act `Noise_XK` driver, both sides — init's pre-Act-One
//! transcript plus the six act steps that each perform an ECDH +
//! `SymmetricState.mixKey` + `encryptAndHash`/`decryptAndHash` per
//! BOLT#8's "Sender Actions"/"Receiver Actions" lists), and all of
//! `transport.zig` (the post-handshake Lightning-message framing AND the
//! key-rotation ratchet). Everything is KAT-verified byte-exact against
//! BOLT#8 Appendix A, including all published negative vectors — see
//! `../SPEC.md`'s "TODO(fable) — done record".
//!
//! Provenance: clean-room from BOLT#8 ("Encrypted and Authenticated
//! Transport", `lightning/bolts`) — a public, open Lightning Network
//! specification (merger doctrine, see CONVENTIONS.md §5 — no NOTICE entry
//! strictly required for the spec citation alone). The official Appendix A
//! "Transport Test Vectors" are the spec's own published conformance
//! vectors, embedded verbatim in `kat_vectors.zig`/`dh.zig`/`act.zig`/
//! `transport.zig`'s own test blocks. See `NOTICE` / `README.md` /
//! `SPEC.md`.

const std = @import("std");

pub const dh = @import("dh.zig");
pub const act = @import("act.zig");
pub const handshake = @import("handshake.zig");
pub const transport = @import("transport.zig");

pub const meta = .{
    .platform = .any,
    .role = .both, // both sides of Noise_XK (initiator/responder) + transport
    // One Initiator/Responder/Transport instance = one caller-owned
    // connection with its own handshake/cipher state; nothing shared.
    .concurrency = .single_owner,
    .model_after = "BOLT#8 (lightning/bolts, 'Encrypted and Authenticated Transport') — Noise_XK_secp256k1_ChaChaPoly_SHA256; builds on this repo's own `noise` module (generic Noise Protocol Framework primitives)",
    .deps = .{ "noise", "k256" },
};

pub const Secp256k1DH = dh;
pub const Initiator = handshake.Initiator;
pub const Responder = handshake.Responder;
pub const HandshakeResult = handshake.HandshakeResult;
pub const Transport = transport.Transport;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too.
test {
    _ = dh;
    _ = act;
    _ = handshake;
    _ = transport;
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
}

test "meta.deps names the noise module" {
    try std.testing.expectEqualStrings("noise", meta.deps[0]);
}

test "act framing constants: 50/50/66 bytes per BOLT#8 'Handshake Exchange'" {
    try std.testing.expectEqual(@as(usize, 50), act.act1_len);
    try std.testing.expectEqual(@as(usize, 50), act.act2_len);
    try std.testing.expectEqual(@as(usize, 66), act.act3_len);
}

test "transport constants: max_message_len 65535, rotation_interval 1000" {
    try std.testing.expectEqual(@as(usize, 65535), transport.max_message_len);
    try std.testing.expectEqual(@as(u64, 1000), transport.rotation_interval);
}
