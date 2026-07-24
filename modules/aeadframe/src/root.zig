//! aeadframe — a per-key AEAD record/frame layer: seal/open messages under one
//! key with a monotonic counter nonce (never reused), epoch-based rekey, a
//! sliding-window anti-replay filter, and AAD binding (context/tenant). Generic
//! over the AEAD — ChaCha20-Poly1305 (via `chachapoly`) and AES-256-GCM (std).
//! The S1b consumer is per-tenant L2VPN confidentiality: one channel per I-SID
//! (the I-SID → channel map is the orchestrator's glue), giving cryptographic
//! tenant isolation over the shared encrypted backbone.
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .codec,
    .concurrency = .single_owner,
    .model_after = "IPsec ESP / DTLS record layer (seq nonce + replay window + rekey)",
    .deps = .{"chachapoly"},
};

test "smoke" {
    try std.testing.expect(true);
}
