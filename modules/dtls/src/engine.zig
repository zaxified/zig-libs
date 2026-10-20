// SPDX-License-Identifier: MIT

//! dtls.engine — the running handshake transcript hash (RFC 8446 §4.4.1's
//! `Transcript-Hash`, reused unchanged by DTLS 1.3 — RFC 9147 §5.8/§5.9) the
//! flight engine feeds its key schedule from. Since 2026-10-20 the code lives
//! in the `tls13` module, generic over the suite hash
//! (`tls13.transcript.Transcript(Hash)`); every suite this module negotiates
//! is a SHA-256 suite, so `Transcript` is the SHA-256 instance. The tests
//! (framing, the PSK-binder truncation, the HelloRetryRequest message_hash
//! rewrite, now anchored on RFC 8448 §3/§5) moved with the code.
//!
//! The framing note stands: the hash runs over TLS 1.3's plain 4-byte
//! handshake header, never DTLS's 12-byte one (RFC 9147 §5.2).

const std = @import("std");
const transcript = @import("tls13").transcript;

pub const Transcript = transcript.Transcript(std.crypto.hash.sha2.Sha256);

/// RFC 8446 §4.4.1's synthetic handshake type (254), hashed but never sent.
pub const message_hash_type = transcript.message_hash_type;
