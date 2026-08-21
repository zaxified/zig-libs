// SPDX-License-Identifier: MIT

//! What a consumer does with `mqtt`: drive the `Client` state machine over an
//! in-memory `Transport` (no socket — the broker side here is simulated by
//! hand-encoding the packets a real broker would send, with `packet`
//! directly). Proves the client is usable from OUTSIDE the module: connect,
//! observe the CONNACK, receive a QoS 1 PUBLISH and see the client
//! auto-acknowledge it, and reject an invalid topic by name before it ever
//! reaches the wire.
//!
//! Built against the PUBLISHED module (`@import("mqtt")`) only.

const std = @import("std");
const mqtt = @import("mqtt");

/// Captures every byte the client writes — stands in for a TCP socket.
const CapturingTransport = struct {
    sent: std.ArrayList(u8) = .empty,

    fn write(ctx: *anyopaque, bytes: []const u8) mqtt.TransportError!void {
        const self: *CapturingTransport = @ptrCast(@alignCast(ctx));
        self.sent.appendSlice(std.heap.page_allocator, bytes) catch return error.TransportFailed;
    }

    fn asTransport(self: *CapturingTransport) mqtt.Transport {
        return .{ .ctx = self, .writeFn = write };
    }
};

pub fn main() !void {
    var wire: CapturingTransport = .{};

    var rx_buf: [512]u8 = undefined;
    var tx_buf: [512]u8 = undefined;
    var client: mqtt.Client = .init(wire.asTransport(), .{ .rx = &rx_buf, .tx = &tx_buf });

    // ── connect ──────────────────────────────────────────────────────────
    try client.connect(0, .{ .client_id = "sensor-42", .keep_alive_s = 30 });

    // A real broker now answers with CONNACK; simulate that by encoding one
    // straight through the codec and feeding it to the client, exactly as
    // `feed` would receive it off a socket.
    var broker_buf: [64]u8 = undefined;
    const connack = try mqtt.packet.encodeConnack(&broker_buf, .{
        .session_present = false,
        .return_code = .accepted,
    });
    try client.feed(connack);

    const connack_event = (try client.poll(0)) orelse return error.NoEvent;
    switch (connack_event) {
        .connack => |ca| std.debug.print("connack: accepted={}\n", .{ca.return_code == .accepted}),
        else => return error.UnexpectedEvent,
    }

    // ── an invalid topic never reaches the wire ─────────────────────────
    // `publish` validates the topic name itself (spec 3.3.2.1 forbids
    // wildcards in a PUBLISH topic) — a consumer building topics from
    // untrusted input gets a typed rejection, not a malformed packet sent
    // to the broker.
    if (client.publish(0, "sensors/+/temp", "bad", .{})) |_| {
        return error.WildcardTopicShouldHaveBeenRejected;
    } else |err| switch (err) {
        error.InvalidTopic => std.debug.print("rejected wildcard topic before sending\n", .{}),
        else => return err,
    }

    // ── incoming QoS 1 PUBLISH: the client answers PUBACK on its own ────
    const sent_before = wire.sent.items.len;
    var incoming_buf: [64]u8 = undefined;
    const incoming = try mqtt.packet.encodePublish(&incoming_buf, .{
        .topic = "sensors/room1/temp",
        .payload = "21.5",
        .qos = .at_least_once,
        .packet_id = 7,
    });
    try client.feed(incoming);

    const message_event = (try client.poll(0)) orelse return error.NoEvent;
    switch (message_event) {
        .message => |m| std.debug.print(
            "message: topic={s} payload={s} qos1_id={d}\n",
            .{ m.topic, m.payload, m.packet_id },
        ),
        else => return error.UnexpectedEvent,
    }

    // The PUBACK the client owes for QoS 1 went out on the wire without the
    // caller having to ask for it — decode the tail of what was captured and
    // confirm it is exactly that.
    const puback_bytes = wire.sent.items[sent_before..];
    const decoded = (try mqtt.packet.decode(puback_bytes)) orelse return error.NoPuback;
    switch (decoded.packet) {
        .puback => |id| std.debug.print("client auto-acked PUBACK id={d}\n", .{id}),
        else => return error.UnexpectedAutoAck,
    }
}
