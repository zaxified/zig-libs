// SPDX-License-Identifier: MIT
//! Noise Protocol Framework message-pattern tokens (spec rev 34, §7).
//!
//! Each handshake message pattern (see `patterns.zig`) is a sequence of
//! these tokens describing what a `HandshakeState.writeMessage`/
//! `readMessage` step must do: emit/consume a DH public key (`e`, `s`),
//! perform a DH operation and mix its output into the chaining key (`ee`,
//! `es`, `se`, `ss`), or mix in the next pre-shared symmetric key (`psk`).

const std = @import("std");

/// A single message-pattern token (Noise spec rev 34 §7.2/§9).
pub const Token = enum {
    /// Emit/consume the sender's ephemeral public key.
    e,
    /// Emit/consume the sender's static public key.
    s,
    /// `DH(e, e)` — both parties' ephemeral keys.
    ee,
    /// `DH(e, s)` or `DH(s, e)` (direction depends on who holds `e` vs `s`
    /// at this point in the pattern) — an ephemeral key times a static key.
    es,
    /// The mirror of `es`: a static key times an ephemeral key.
    se,
    /// `DH(s, s)` — both parties' static keys.
    ss,
    /// Mix in the next pre-shared symmetric key (spec §9 PSK handshakes).
    psk,
};

test "Token: all seven spec tokens present, one enum tag each" {
    const all = [_]Token{ .e, .s, .ee, .es, .se, .ss, .psk };
    try std.testing.expectEqual(@as(usize, 7), all.len);
    // Round-trip through the tag name to catch accidental renames.
    try std.testing.expectEqualStrings("ee", @tagName(Token.ee));
    try std.testing.expectEqualStrings("psk", @tagName(Token.psk));
}
