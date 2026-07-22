// SPDX-License-Identifier: MIT

//! websocket — RFC 6455 WebSocket protocol: the opening handshake (§1.3,
//! §4) and the frame layer (§5), transport-agnostic. This module does not
//! open sockets or speak TLS — it operates on byte buffers and
//! `std.Io.Writer`s the caller supplies, so it drops onto any transport
//! (raw TCP, `std.crypto.tls`, the `http` module's TLS-adapter seam) —
//! notably the P2 production HTTPS server's WSS endpoint and WebSocket
//! proxying.
//!
//! Layout: `handshake` is the HTTP-Upgrade opening handshake, built on
//! `http.h1.RequestHead`/`ResponseHead`; `frame` is the pure §5 wire codec
//! (`parseFrame`/`writeFrame`); `connection` is a small optional state
//! machine on top of `frame` that reassembles fragmented messages and
//! tracks the closing handshake. See SPEC.md for the security rules
//! (masking direction, size caps, UTF-8, RSV/opcode validation) and what's
//! deliberately out of scope (permessage-deflate).

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .both, // server (accept/parse-inbound-masked) + client (request/parse-inbound-unmasked)
    .concurrency = .reentrant, // no shared/global state; a `Connection` is single-owner if shared across calls
    .model_after = "RFC 6455 (The WebSocket Protocol) §1.3/§4 handshake, §5 framing",
    .deps = .{ "http", "std.crypto.hash.Sha1", "std.base64", "std.unicode" },
};

/// Opening handshake (§1.3/§4): server-side `acceptHandshake` +
/// `writeResponse`, client-side `generateKey` + `writeRequest` +
/// `verifyResponse`, and the shared `computeAcceptKey`.
pub const handshake = @import("handshake.zig");

/// The §5 frame codec: `Opcode`, `Frame`, `parseFrame` (streaming,
/// `.need_more`-aware), `writeFrame`, masking (`applyMask`), and the
/// close-body codec (`encodeCloseBody`/`decodeCloseBody`).
pub const frame = @import("frame.zig");

/// The optional per-connection state machine: fragmentation reassembly,
/// aggregate message-size cap, and close-handshake tracking. See
/// `connection.Connection`.
pub const connection = @import("connection.zig");
