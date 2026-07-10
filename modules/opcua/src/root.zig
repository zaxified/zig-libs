// SPDX-License-Identifier: MIT

//! opcua — an OPC-UA (IEC 62541 / OPC 10000) binary client: the opc.tcp wire
//! protocol (OPC 10000-6) over `SecurityPolicy#None` (no signing/encryption —
//! that's a separate later module, F9, layered on the `rsa` module).
//!
//! This is F1 "core": the built-in type codec (`encoding`, OPC 10000-6 §5.2)
//! and the opc.tcp transport framing (`transport`, OPC 10000-6 §7) are fully
//! scaffolded (real types, stubbed codec bodies). The service layer riding on
//! top — OpenSecureChannel/CloseSecureChannel (F1-b), CreateSession/
//! ActivateSession/CloseSession (F1-c), and Read/Write/Browse/Call (F1-d) — is
//! reserved here as one-line `@panic` stubs for a later implementing agent.
//!
//! Model: OPC 10000-6 (OPC UA Binary encoding + opc.tcp transport). Structure
//! references open62541 (MPL-2.0) and node-opcua (MIT) — behavioral/API-shape
//! only, no source copied. See `NOTICE` for the full provenance note.

const std = @import("std");

pub const meta = .{
    .platform = .any, // pure codec + a caller-supplied stream; no socket of its own
    .role = .client,
    .concurrency = .reentrant, // no shared state; Connection/Encoder/Decoder are caller-owned
    .model_after = "OPC 10000-6 (OPC UA Binary + opc.tcp); structure ref open62541 (MPL-2.0) / node-opcua (MIT) — behavioral only, no source copied",
    .deps = .{},
};

/// The built-in type codec (OPC 10000-6 §5.2): `Encoder`/`Decoder` over a
/// `std.Io.Writer`/`std.Io.Reader`, plus the `NodeId`/`Variant`/`DataValue`/…
/// types every OPC UA message body is built from.
pub const encoding = @import("encoding.zig");

/// The opc.tcp transport (OPC 10000-6 §7): the Hello/Acknowledge handshake,
/// the 8-byte message-chunk header, and the `Connection` wired over a
/// caller-supplied reader/writer pair (this module never opens a socket).
pub const transport = @import("transport.zig");

// Pull the submodules' tests into this module's test binary — a bare
// re-export does NOT drag in the imported file's `test` blocks (the
// dark-tests rule; see CONVENTIONS.md §6.3).
test {
    _ = encoding;
    _ = transport;
}

// ── F1-b: Secure Channel (SecurityPolicy#None) ──────────────────────────────

/// OpenSecureChannel / CloseSecureChannel (OPC 10000-4 §5.5.2/§5.5.3) over
/// `SecurityPolicy#None`: no signing/encryption (that's SecurityMode=None's
/// entire point), but the request/response envelope and channel-id/token
/// bookkeeping still need this type. Reserved for a later part — the field
/// list here is a placeholder, not a settled shape.
pub const SecureChannel = struct {
    conn: *transport.Connection,

    /// Perform the OpenSecureChannel request/response and return the opened
    /// channel.
    pub fn open(conn: *transport.Connection) SecureChannel {
        _ = conn;
        @panic("TODO(agent): OpenSecureChannel request/response, SecurityPolicy#None — OPC 10000-4 §5.5.2");
    }

    /// Perform the CloseSecureChannel request/response.
    pub fn close(ch: *SecureChannel) void {
        _ = ch;
        @panic("TODO(agent): CloseSecureChannel request/response — OPC 10000-4 §5.5.3");
    }
};

// ── F1-c: Session ────────────────────────────────────────────────────────────

/// CreateSession / ActivateSession / CloseSession (OPC 10000-4 §5.6). Reserved
/// for a later part — the field list here is a placeholder, not a settled
/// shape.
pub const Session = struct {
    channel: *SecureChannel,

    /// Perform the CreateSession request/response.
    pub fn create(channel: *SecureChannel) Session {
        _ = channel;
        @panic("TODO(agent): CreateSession request/response — OPC 10000-4 §5.6.2");
    }

    /// Perform the ActivateSession request/response.
    pub fn activate(session: *Session) void {
        _ = session;
        @panic("TODO(agent): ActivateSession request/response — OPC 10000-4 §5.6.3");
    }

    /// Perform the CloseSession request/response.
    pub fn close(session: *Session) void {
        _ = session;
        @panic("TODO(agent): CloseSession request/response — OPC 10000-4 §5.6.4");
    }
};

// ── F1-d: core services ──────────────────────────────────────────────────────

/// The Read service (OPC 10000-4 §5.10.2): fetch one or more attribute
/// values by NodeId.
pub fn read(session: *Session) noreturn {
    _ = session;
    @panic("TODO(agent): Read service — OPC 10000-4 §5.10.2");
}

/// The Write service (OPC 10000-4 §5.10.4): set one or more attribute values
/// by NodeId.
pub fn write(session: *Session) noreturn {
    _ = session;
    @panic("TODO(agent): Write service — OPC 10000-4 §5.10.4");
}

/// The Browse service (OPC 10000-4 §5.8.2): enumerate a node's references
/// (children/parents/type hierarchy).
pub fn browse(session: *Session) noreturn {
    _ = session;
    @panic("TODO(agent): Browse service — OPC 10000-4 §5.8.2");
}

/// The Call service (OPC 10000-4 §5.11.2): invoke a method node.
pub fn call(session: *Session) noreturn {
    _ = session;
    @panic("TODO(agent): Call service — OPC 10000-4 §5.11.2");
}

// ── tests ──

test "smoke" {
    try std.testing.expect(true);
}
