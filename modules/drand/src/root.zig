//! drand — a drand randomness-beacon client core: parse chain-info, decode a
//! beacon round, and BLS-verify a round's threshold signature against the chain
//! public key (via `bls12_381`, reusing the quicknet ciphersuite that `tlock`
//! already pins so the two never drift). Transport-agnostic: the caller supplies
//! the fetched bytes (drand endpoints are HTTPS; TLS is the caller's concern),
//! mirroring how `tlock` consumes a round signature without fetching it.
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .client,
    .concurrency = .reentrant,
    .model_after = "drand/drand HTTP beacon + go-client verify (quicknet, unchained G1)",
    .deps = .{ "bls12_381", "tlock" },
};

test "smoke" {
    try std.testing.expect(true);
}
