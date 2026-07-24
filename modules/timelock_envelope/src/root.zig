//! timelock_envelope — a hybrid sealed envelope whose plaintext unlocks only
//! when BOTH conditions hold: a drand timelock round has published (time gate,
//! via `tlock`) AND the recipient holds the post-quantum KEM secret key
//! (long-term confidentiality, via `hqc`). Content is AEAD-sealed (`chachapoly`)
//! under a key bound to both locks. The crypto core of the S5 dead-man-switch.
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "drand tlock + PQ-KEM hybrid envelope (age-style two-lock KDF)",
    .deps = .{ "tlock", "hqc", "chachapoly" },
};

test "smoke" {
    try std.testing.expect(true);
}
