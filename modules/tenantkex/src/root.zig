//! tenantkex — per-tenant key exchange for the L2VPN fabric: run a Noise_IK
//! handshake (via the `noise` module) between two provider edges, binding the
//! tenant's I-SID into the handshake prologue so a session is cryptographically
//! scoped to one tenant, and derive the two directional channel keys that feed
//! `aeadframe`'s per-tenant record layer. Pure driver over `noise`'s
//! HandshakeState — the caller carries the two handshake messages over the WG
//! backbone; this module produces {send_key, recv_key, transcript_hash}. IK
//! (initiator knows the responder's static key from provisioning); XX fallback
//! and PSK details are later increments.
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "Noise_IK (WireGuard-style) session establishment, I-SID-bound",
    .deps = .{"noise"},
};

test "smoke" {
    try std.testing.expect(true);
}
