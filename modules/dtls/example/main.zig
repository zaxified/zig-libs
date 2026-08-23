// SPDX-License-Identifier: MIT

//! What a constrained-device consumer does with `dtls`: bring up a DTLS 1.3
//! association between a field device and its fleet gateway from a
//! pre-shared key, survive the first datagram going missing, and exchange
//! application data over the keys the handshake installed.
//!
//! Both endpoints live in this process because that is what the module's
//! shape invites: `Connection` is sans-I/O — no socket, no clock, no
//! allocator. A datagram goes in, a datagram comes out, and `now_ms` is a
//! number the caller passes. A downstream project wires the same calls to a
//! UDP socket and its own timer; its tests wire them to each other, like
//! here, and get the real state machine either way.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`deps` only, no `test_deps`, no access to anything the module does
//! not export). If a type needed to call the API is not public, or an error
//! cannot be named from outside, this file stops compiling. The module's own
//! tests cannot notice either, because they live inside it.

const std = @import("std");
const dtls = @import("dtls");

/// Provisioned onto the device and known to the gateway. In `.psk` mode this
/// is the sole source of session-key material.
const psk_identity = "sensor-042.substation-7";
const psk = "a-provisioned-pre-shared-key";

pub fn main() !void {
    // The module has no hidden RNG (std 0.16 removed `std.crypto.random`), so
    // the caller supplies one AND says what kind it is. A shipping device
    // writes `.{ .csprng = ... }` over a `std.Random.DefaultCsprng` seeded
    // from `getrandom(2)`; naming that arm is the assertion that the source
    // is cryptographically secure, since the module cannot check it.
    //
    // This example names the other arm on purpose: it is a replayable
    // harness, and the type is what forces that admission to be written down
    // instead of inferred from whatever generator was in scope.
    var seeded: std.Random.DefaultCsprng = .init(@splat(0x2A));
    const entropy: dtls.Entropy = .{ .seeded_for_test = seeded.random() };

    const suite: dtls.CipherSuite = .aes_128_gcm_sha256;

    var device = dtls.Connection.clientInit(.{
        .role = .client,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{suite},
    }) catch |err| switch (err) {
        // Config validation fails closed before any key schedule runs: a
        // device shipped with its PSK slot unprovisioned finds out here, not
        // three flights later against a live gateway.
        error.EmptyPsk, error.EmptyPskIdentity => {
            std.debug.print("device is not provisioned, refusing to connect\n", .{});
            return;
        },
        else => return err,
    };
    // Key and secret material is zeroed on the way out; a device that keeps
    // an association struct around after tearing it down should not keep the
    // traffic keys with it.
    defer device.deinit();

    var gateway = try dtls.Connection.serverInit(.{
        .role = .server,
        .psk_identity = psk_identity,
        .psk = psk,
        .cipher_suites = &.{suite},
    });
    defer gateway.deinit();

    // Two buffers, alternated, so no step's input aliases its own output.
    var to_gateway: [1500]u8 = undefined;
    var to_device: [1500]u8 = undefined;

    // Flight 1. Pretend the datagram is lost on the way out — the common
    // case on a lossy field link, and the reason DTLS retransmits at all.
    _ = try device.startHandshake(entropy, 0, &to_gateway);
    std.debug.print("ClientHello sent at t=0 and dropped by the network\n", .{});

    // Retransmission is caller-clocked: nothing here sleeps or owns a timer,
    // so a device driving this from its own event loop decides when to ask.
    if (try device.poll(500, &to_gateway)) |_| {
        return error.RetransmittedBeforeTimeout;
    }
    const retry = (try device.poll(1_000, &to_gateway)) orelse {
        return error.NoRetransmissionAfterTimeout;
    };
    std.debug.print("retransmitted ClientHello at t=1000 ({d} bytes)\n", .{retry.len});

    // Both sides share the provisioned PSK and an overlapping cipher suite,
    // so this flight must be accepted — these arms exist to name what the
    // module reports for a wrong PSK or no shared suite, not to happen here.
    const flight2 = gateway.handleFlight(retry, entropy, 1_000, &to_device) catch |err| switch (err) {
        error.BinderVerifyFailed, error.NoMatchingPskIdentity => return error.HandshakeUnexpectedlyUnauthenticated,
        error.NoCipherSuiteOverlap => return error.HandshakeUnexpectedlyLackedCipherOverlap,
        else => return err,
    };
    // A flight split across datagrams is consumed but not yet complete: read
    // another datagram and feed the same connection. This is the field a
    // caller can ignore and still behave correctly, because an incomplete
    // flight also yields an empty `out`. Here the whole flight arrives in one
    // datagram, so this must never trigger.
    if (flight2.need_more_data) {
        return error.GatewayUnexpectedlyIncomplete;
    }

    const device_finished = try device.handleFlight(flight2.out, entropy, 1_000, &to_gateway);
    if (!device_finished.done) {
        return error.DeviceUnexpectedlyNotConnected;
    }

    const gateway_done = try gateway.handleFlight(device_finished.out, entropy, 1_000, &to_device);
    if (!gateway_done.done) {
        return error.GatewayUnexpectedlyNotConnected;
    }
    std.debug.print("handshake complete: device={s} gateway={s} (done={})\n", .{
        @tagName(device.state),
        @tagName(gateway.state),
        gateway_done.done,
    });

    // Application data, over the keys this handshake installed. Same shape as
    // the handshake: bytes in, bytes out, caller owns the socket.
    var wire: [256]u8 = undefined;
    var plain: [256]u8 = undefined;

    const reading = "{\"bay\":3,\"amps\":417.2}";
    const record = try device.send(reading, &wire);
    const received = try gateway.recv(record, &plain);
    std.debug.print("gateway read {d} bytes: {s}\n", .{ received.len, received });

    // What a device on a shared medium actually has to handle. Both of these
    // are typed errors, not panics, and neither disturbs the association:
    // the caller drops the datagram and reads the next one.
    var forged: [256]u8 = undefined;
    @memcpy(forged[0..record.len], record);
    forged[record.len - 1] ^= 0x80;
    if (gateway.recv(forged[0..record.len], &plain)) |_| {
        return error.ForgedRecordUnexpectedlyAccepted;
    } else |err| switch (err) {
        error.DecryptionFailed => std.debug.print("forged record rejected\n", .{}),
        else => return err,
    }

    // A verbatim replay of a record that was already delivered. The
    // anti-replay window is 64 records wide, so an attacker echoing a
    // captured measurement back cannot make it count twice.
    if (gateway.recv(record, &plain)) |_| {
        return error.ReplayedRecordUnexpectedlyAccepted;
    } else |err| switch (err) {
        error.ReplayedRecord => std.debug.print("replayed record rejected\n", .{}),
        else => return err,
    }
}
