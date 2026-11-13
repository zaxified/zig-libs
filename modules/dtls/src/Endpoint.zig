// SPDX-License-Identifier: MIT

//! dtls.Endpoint — a DTLS connection whose VERSION is negotiated
//! (`Config.versions`): the 1.3 `Connection` or the 1.2 `Connection12`
//! behind the same methods.
//!
//! * `{.dtls13}` — exactly `Connection`.
//! * `{.dtls12}` — exactly `Connection12`.
//! * both — the 1.3 engine starts. Its ClientHello also offers DTLS 1.2
//!   (`supported_versions` {1.3, 1.2}, the 1.2 suites, extended master
//!   secret, `renegotiation_info`, `ec_point_formats`); a server preferring
//!   1.3 answers in 1.3. When the peer turns out to speak only 1.2 (a client
//!   sees a HelloVerifyRequest or a ServerHello without
//!   `supported_versions`; a server sees a ClientHello without 1.3), the 1.3
//!   engine reports the internal `error.NegotiatedDtls12` without changing
//!   anything, and this type hands the exchange to `Connection12`, which
//!   continues from the same ClientHello. Both 1.2 roles then enforce RFC
//!   8446 §4.1.3's downgrade sentinel (a 1.3-capable server marks its 1.2
//!   ServerHello.random, a 1.3-capable client refuses one so marked).

const std = @import("std");
const conn13 = @import("Connection.zig");
const c12 = @import("Connection12.zig");
const record = @import("record.zig");
const handshake = @import("handshake.zig");

pub const Connection = conn13.Connection;
pub const Connection12 = c12.Connection12;
pub const Config = conn13.Config;
pub const Entropy = conn13.Entropy;
pub const HandshakeError = conn13.HandshakeError;
pub const SendError = conn13.SendError;
pub const HandshakeResult = Connection.HandshakeResult;
pub const ProtocolVersion = conn13.ProtocolVersion;
pub const ExportError = Connection.ExportError || c12.ExportError;

pub const Endpoint = union(enum) {
    v13: Connection,
    v12: Connection12,

    pub fn clientInit(config: Config) conn13.ConfigError!Endpoint {
        try config.validate();
        if (config.allows(.dtls13)) return .{ .v13 = try Connection.clientInit(config) };
        return .{ .v12 = try Connection12.clientInit(config) };
    }

    pub fn serverInit(config: Config) conn13.ConfigError!Endpoint {
        try config.validate();
        if (config.allows(.dtls13)) return .{ .v13 = try Connection.serverInit(config) };
        return .{ .v12 = try Connection12.serverInit(config) };
    }

    /// The version in use — before negotiation, the one the engine started
    /// with (1.3 whenever it is allowed).
    pub fn version(self: *const Endpoint) ProtocolVersion {
        return switch (self.*) {
            .v13 => .dtls13,
            .v12 => .dtls12,
        };
    }

    pub fn isConnected(self: *const Endpoint) bool {
        return switch (self.*) {
            .v13 => |*c| c.state == .connected,
            .v12 => |*c| c.state == .connected,
        };
    }

    pub fn startHandshake(self: *Endpoint, entropy: Entropy, now_ms: u64, out: []u8) HandshakeError![]const u8 {
        return switch (self.*) {
            inline else => |*c| c.startHandshake(entropy, now_ms, out),
        };
    }

    pub fn handleFlight(self: *Endpoint, datagram: []const u8, entropy: Entropy, now_ms: u64, out: []u8) HandshakeError!HandshakeResult {
        switch (self.*) {
            .v12 => |*c| return c.handleFlight(datagram, entropy, now_ms, out),
            .v13 => |*c| {
                const prior = c.rx_flight_len;
                return c.handleFlight(datagram, entropy, now_ms, out) catch |err| {
                    if (err != error.NegotiatedDtls12) return err;
                    return self.handOver(prior, datagram, entropy, now_ms, out);
                };
            },
        }
    }

    fn handOver(self: *Endpoint, prior: usize, datagram: []const u8, entropy: Entropy, now_ms: u64, out: []u8) HandshakeError!HandshakeResult {
        const old = &self.v13;
        switch (old.role) {
            .client => {
                // The ClientHello is the cached last flight: one epoch-0
                // record holding one unfragmented handshake message.
                const rec = old.last_flight[0..old.last_flight_len];
                if (rec.len < record.plaintext_header_len + handshake.header_len) return error.Malformed;
                const hh = try handshake.decodeHeader(rec[record.plaintext_header_len..]);
                const body_start = record.plaintext_header_len + handshake.header_len;
                if (rec.len - body_start < hh.length) return error.Malformed;
                const next = try Connection12.fromDualClientHello(old.config, rec[body_start..][0..hh.length], old.hs0.send_seq, now_ms);
                old.deinit();
                self.* = .{ .v12 = next };
                return self.v12.handleFlight(datagram, entropy, now_ms, out);
            },
            .server => {
                // Everything the 1.3 engine buffered for the ClientHello
                // (still in its accumulator, see `NegotiatedDtls12`).
                var bytes: [old.rx_flight.len]u8 = undefined;
                const n = prior + datagram.len;
                if (n > bytes.len) return error.FlightTooLarge;
                @memcpy(bytes[0..n], old.rx_flight[0..n]);
                const next = Connection12.serverInit(old.config) catch return error.WrongState;
                old.deinit();
                self.* = .{ .v12 = next };
                return self.v12.handleFlight(bytes[0..n], entropy, now_ms, out);
            },
        }
    }

    pub fn poll(self: *Endpoint, now_ms: u64, out: []u8) HandshakeError!?[]const u8 {
        return switch (self.*) {
            inline else => |*c| c.poll(now_ms, out),
        };
    }

    pub fn send(self: *Endpoint, plaintext: []const u8, out: []u8) SendError![]const u8 {
        return switch (self.*) {
            inline else => |*c| c.send(plaintext, out),
        };
    }

    pub fn recv(self: *Endpoint, datagram: []const u8, out: []u8) SendError![]const u8 {
        return switch (self.*) {
            inline else => |*c| c.recv(datagram, out),
        };
    }

    pub fn exportKeyingMaterial(self: *const Endpoint, label: []const u8, context: ?[]const u8, out: []u8) ExportError!void {
        return switch (self.*) {
            inline else => |*c| c.exportKeyingMaterial(label, context, out),
        };
    }

    pub fn negotiatedAlpn(self: *const Endpoint) ?[]const u8 {
        return switch (self.*) {
            inline else => |*c| c.negotiatedAlpn(),
        };
    }

    pub fn deinit(self: *Endpoint) void {
        switch (self.*) {
            inline else => |*c| c.deinit(),
        }
    }
};
