// SPDX-License-Identifier: MIT

//! What a consumer does with `btcp2p`: read one `version` message off a
//! captured byte stream (the Bitcoin wiki's own published "modern (60002)
//! protocol version" hex dump — externally anchored, not self-derived),
//! validate the envelope, decode the handshake payload, then build and
//! encode a `ping` to send back. Also shows the envelope's fail-closed
//! checksum check on a bit-flipped wire message, which is the boundary
//! every message this module decodes sits behind.
//!
//! Built against the PUBLISHED module (`@import("btcp2p")`) plus its
//! declared dep `bitcointx` only — no `test_deps`, no socket, no file.

const std = @import("std");
const btcp2p = @import("btcp2p");

// The wiki's "modern (60002) protocol version" example, byte-for-byte
// (en.bitcoin.it/wiki/Protocol_documentation) — a full wire message
// (envelope + payload), the same bytes `envelope.zig`'s own test decodes.
const version_wire = [_]u8{
    0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x64, 0x00, 0x00, 0x00, 0x35, 0x8d, 0x49, 0x32, 0x62, 0xea, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x11, 0xb2, 0xd0, 0x50, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x3b, 0x2e, 0xb3, 0x5d, 0x8c, 0xe6, 0x17, 0x65, 0x0f, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68,
    0x69, 0x3a, 0x30, 0x2e, 0x37, 0x2e, 0x32, 0x2f, 0xc0, 0x3e, 0x03, 0x00,
};

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── envelope: the untrusted-input boundary every decoder sits behind ──
    const decoded = try btcp2p.decodeMessage(&version_wire, .mainnet);
    std.debug.print("command={s} consumed={d} bytes\n", .{ decoded.message.commandName(), decoded.consumed });

    if (!std.mem.eql(u8, decoded.message.commandName(), "version")) {
        return error.UnexpectedCommand;
    }

    // ── handshake payload ───────────────────────────────────────────────
    var peer = try btcp2p.decodeVersion(decoded.message.payload);
    defer peer.deinit(gpa);
    std.debug.print("peer version={d} services={x} user_agent=\"{s}\" start_height={d}\n", .{
        peer.version, peer.services, peer.user_agent, peer.start_height,
    });

    // ── build a reply: a fresh ping, encoded as a full wire message ──────
    const ping_payload = try btcp2p.serializePing(gpa, .{ .nonce = 0xfeed_face_dead_beef });
    defer gpa.free(ping_payload);
    const ping_wire = try btcp2p.encodeMessage(gpa, .mainnet, "ping", ping_payload);
    defer gpa.free(ping_wire);

    const ping_decoded = try btcp2p.decodeMessage(ping_wire, .mainnet);
    const pong = try btcp2p.decodePing(ping_decoded.message.payload);
    std.debug.print("built and round-tripped ping, nonce={x}\n", .{pong.nonce});

    // ── the envelope's fail-closed checksum check ─────────────────────────
    // A byte flipped anywhere in the payload after the checksum was computed
    // must be rejected before any per-message decoder ever sees it — this is
    // what protects `decodeVersion`/`decodePing`/etc. from a corrupted or
    // tampered stream.
    var tampered = try gpa.dupe(u8, ping_wire);
    defer gpa.free(tampered);
    tampered[tampered.len - 1] ^= 0xff;
    _ = btcp2p.decodeMessage(tampered, .mainnet) catch |err| switch (err) {
        // Named, not `anyerror`: a caller reading a live stream disconnects
        // a peer that fails this check rather than propagating a panic.
        error.BadChecksum => {
            std.debug.print("tampered ping rejected: BadChecksum\n", .{});
            return;
        },
        else => return err,
    };
    return error.TamperNotDetected;
}
