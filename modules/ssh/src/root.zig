// SPDX-License-Identifier: MIT

//! ssh — SSH-2.0 transport layer (RFC 4253), CLIENT and SERVER. Implemented:
//! version exchange, KEXINIT negotiation, curve25519-sha256 key exchange
//! (RFC 8731), the Binary Packet Protocol, `chacha20-poly1305@openssh.com` +
//! `aes256-ctr`/`hmac-sha2-256` ciphers, and host-key verify (client) /
//! host-key signing (server) for ssh-ed25519, rsa-sha2-256/512 (via the `rsa`
//! module), and ecdsa-sha2-nistp256. `clientHandshake` (transport.zig) and
//! `serverHandshake`/`accept` (server.zig) each establish an encrypted,
//! host-authenticated `Transport`. Validated against live OpenSSH 10.2p1 both
//! ways (our client ↔ real sshd; real ssh client ↔ our server).
//!
//! Userauth (RFC 4252, part 2) and connection-protocol channels (RFC 4254,
//! part 3) are reserved top-level stubs below — NOT yet implemented. The RFC
//! 4251 §5 wire helpers are in `messages.zig`; the server reuses the client's
//! packet codec / `KexInit` / `deriveKeys` / `Transport` rather than
//! duplicating the protocol logic.
//!
//! Provenance: clean-room from RFC 4253/4251/8731 (+ RFC 4252/4254 for the
//! reserved parts); design reference ringtailsoftware/misshod (MIT) for
//! architecture SHAPE only — no source copied. Crypto via Zig `std.crypto`
//! (X25519, Ed25519, ChaCha20-Poly1305, P-256, SHA-2, HMAC) plus this repo's
//! `rsa` module for rsa-sha2. See `NOTICE` / `README.md` / `SPEC.md`.

const std = @import("std");

pub const transport = @import("transport.zig");
pub const messages = @import("messages.zig");
pub const server = @import("server.zig");

pub const meta = .{
    .platform = .any,
    .role = .both,
    // One Transport instance = one caller-owned connection with its own
    // sequence-number/cipher state; nothing shared/global.
    .concurrency = .single_owner,
    .model_after = "RFC 4253/4251/4252/4254 + RFC 8731 (curve25519-sha256); design ref ringtailsoftware/misshod (MIT) shape only, no source copied",
    .deps = .{"rsa"},
};

// ── part 2: userauth (RFC 4252) — reserved, NOT implemented in this pass ───

/// Reserved placeholder for RFC 4252 userauth (the `publickey`/`password`/
/// `keyboard-interactive` methods layered over the transport's
/// SSH_MSG_SERVICE_REQUEST/SSH_MSG_USERAUTH_* messages). Out of scope for
/// this scaffold (part 1 = transport only, see module doc comment above) —
/// reserved purely so the eventual API has a stable name to grow into.
pub fn userauth() noreturn {
    @panic("TODO(agent): RFC 4252 userauth (part 2 of this module) — not yet implemented; only the RFC 4253 transport layer (part 1) is scaffolded so far");
}

// ── part 3: channels (RFC 4254) — reserved, NOT implemented in this pass ───

/// Reserved placeholder for opening an RFC 4254 §6.1 session channel
/// (SSH_MSG_CHANNEL_OPEN "session" + window/flow-control bookkeeping). Out
/// of scope for this scaffold.
pub fn openSession() noreturn {
    @panic("TODO(agent): RFC 4254 SS6.1 session-channel open (part 3 of this module) — not yet implemented");
}

/// Reserved placeholder for running a remote command over an already-open
/// session channel (SSH_MSG_CHANNEL_REQUEST "exec", RFC 4254 §6.5). Out of
/// scope for this scaffold.
pub fn exec() noreturn {
    @panic("TODO(agent): RFC 4254 SS6.5 \"exec\" channel request (part 3 of this module) — not yet implemented");
}

// ── dark-tests aggregator (CONVENTIONS.md SS6 step 3) ───────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too.
test {
    _ = transport;
    _ = messages;
    _ = server;
}

test "meta.deps names the rsa module (rsa-sha2 host-key verification)" {
    try std.testing.expectEqualStrings("rsa", meta.deps[0]);
}
