// SPDX-License-Identifier: MIT

//! ssh — a complete SSH-2.0 client AND server: transport (RFC 4253), user
//! authentication (RFC 4252) and the connection protocol (RFC 4254), i.e.
//! everything needed to run a remote command over SSH.
//!
//! Part 1 — transport (`transport.zig` client, `server.zig` server): version
//! exchange, KEXINIT negotiation, mlkem768x25519 / curve25519-sha256 (RFC
//! 8731) / diffie-hellman-group14|16 key exchange, the Binary Packet
//! Protocol, `chacha20-poly1305@openssh.com` / `aes256-ctr`+`hmac-sha2-256` /
//! `aes{128,256}-gcm@openssh.com` ciphers, and host-key verify (client) /
//! signing (server) for ssh-ed25519, rsa-sha2-256/512 (via the `rsa` module)
//! and ecdsa-sha2-nistp256.
//!
//! Part 2 — userauth (`userauth.zig`): the `publickey` method (RFC 4252 §7,
//! including the two-phase query → SSH_MSG_USERAUTH_PK_OK → signed-request
//! flow, with the signature bound to the transport's session id) and the
//! `password` method (§8), both roles.
//!
//! Part 3 — connection protocol (`connection.zig`): `"session"` channels with
//! RFC 4254 §5.2 window/flow control, CHANNEL_DATA/_EXTENDED_DATA(stderr)/
//! _EOF/_CLOSE, and the `"exec"` / `"subsystem"` requests plus §6.10
//! `exit-status` — surfaced as `exec(...)` below.
//!
//! The RFC 4251 §5 wire helpers and the bounded `Cursor` every message parser
//! decodes with are in `messages.zig`; the server reuses the client's packet
//! codec / `KexInit` / `deriveKeys` / `Transport` rather than duplicating the
//! protocol logic. Validated against live OpenSSH 10.2p1 both ways (our
//! client ↔ real `sshd`, incl. publickey auth + remote command execution;
//! real `ssh` client ↔ our server, same).
//!
//! Provenance: clean-room from RFC 4253/4251/4252/4254/8731; design reference
//! ringtailsoftware/misshod (MIT) for architecture SHAPE only — no source
//! copied. Crypto via Zig `std.crypto` (X25519, Ed25519, ChaCha20-Poly1305,
//! P-256, SHA-2, HMAC) plus this repo's `rsa` module for rsa-sha2. See
//! `NOTICE` / `README.md` / `SPEC.md`.

const std = @import("std");

pub const transport = @import("transport.zig");
pub const messages = @import("messages.zig");
pub const server = @import("server.zig");
pub const userauth = @import("userauth.zig");
pub const connection = @import("connection.zig");

pub const meta = .{
    .platform = .any,
    .role = .both,
    // One Transport instance = one caller-owned connection with its own
    // sequence-number/cipher state; nothing shared/global.
    .concurrency = .single_owner,
    .model_after = "RFC 4253/4251/4252/4254 + RFC 8731 (curve25519-sha256) + RFC 8332/8709/5656 (host+user key algorithms); design ref ringtailsoftware/misshod (MIT) shape only, no source copied",
    .deps = .{"rsa"},
};

// ── top-level entry points (the three names parts 2 and 3 grew into) ───────

/// RFC 4252 §7 `publickey` authentication, client side: request the
/// `ssh-userauth` service and authenticate as `user` with `key`, binding the
/// signature to this transport's session id. See `userauth.zig` for the
/// per-step API (`authenticatePublickey`, `authenticatePassword`) and the
/// server side (`serveUserauth`).
///
///     try ssh.authenticate(&t, gpa, user, key);
pub const authenticate = userauth.authenticate;

/// Open an RFC 4254 §6.1 `"session"` channel on an authenticated transport
/// (SSH_MSG_CHANNEL_OPEN + window/flow-control bookkeeping), returning a
/// `connection.Session`.
///
///     var s = try ssh.openSession(&t, gpa, .{});
///     defer s.deinit();
pub const openSession = connection.Session.open;

/// Run a remote command over a fresh session channel (RFC 4254 §6.5 `"exec"`)
/// and collect stdout/stderr plus the §6.10 exit status.
///
///     var r = try ssh.exec(&t, gpa, "uname -a", .{});
///     defer r.deinit(gpa);
pub const exec = connection.exec;

// ── dark-tests aggregator (CONVENTIONS.md SS6 step 3) ───────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too.
test {
    _ = transport;
    _ = messages;
    _ = server;
    _ = userauth;
    _ = connection;
}

test "meta.deps names the rsa module (rsa-sha2 host-key verification)" {
    try std.testing.expectEqualStrings("rsa", meta.deps[0]);
}
