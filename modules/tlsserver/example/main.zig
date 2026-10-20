// SPDX-License-Identifier: MIT

//! What the TLS 1.3 record layer of `tlsserver` does for an engine: install
//! one `Protection` per direction from a traffic secret, seal application
//! data in place (content first, header / type / padding / tag written around
//! it), open the peer's record in place, and refuse a tampered or replayed
//! record by name without advancing the sequence number.
//!
//! The traffic secret here is a fixed placeholder; a real engine takes it
//! from the key schedule (`tls13.keyschedule`).
//!
//! Built by `zig build check-examples` against the PUBLISHED module — no
//! access to anything `tlsserver` does not export.

const std = @import("std");
const record = @import("tlsserver").record;

pub fn main() !void {
    const secret: [48]u8 = @splat(0x5a); // TLS_AES_256_GCM_SHA384 → a 48-byte secret

    var tx: record.Protection = undefined;
    try tx.init(.aes_256_gcm_sha384, &secret);
    defer tx.wipe();
    var rx: record.Protection = undefined;
    try rx.init(.aes_256_gcm_sha384, &secret);
    defer rx.wipe();

    var buf: [record.max_record_len]u8 = undefined;
    const msg = "GET / HTTP/1.1\r\nHost: example\r\n\r\n";

    // Two records with 16 octets of padding each; the sequence number moves.
    for (0..2) |_| {
        @memcpy(buf[record.header_len..][0..msg.len], msg);
        const wire = try tx.seal(&buf, msg.len, .application_data, 16);
        const opened = try rx.open(wire);
        if (opened.content_type != .application_data or !std.mem.eql(u8, opened.content, msg))
            return error.RoundTripMismatch;
        std.debug.print("record #{d}: {d} octets on the wire, {d} of content\n", .{ rx.seq - 1, wire.len, opened.content.len });
    }

    // A flipped bit: refused by name, and the receiver stays where it was.
    @memcpy(buf[record.header_len..][0..msg.len], msg);
    const wire = try tx.seal(&buf, msg.len, .application_data, 0);
    var tampered: [record.max_record_len]u8 = undefined;
    @memcpy(tampered[0..wire.len], wire);
    tampered[wire.len - 1] ^= 0x01;
    const before = rx.seq;
    if (rx.open(tampered[0..wire.len])) |_| {
        return error.TamperedRecordAccepted;
    } else |err| switch (err) {
        error.BadRecordMac => std.debug.print("tampered record refused (BadRecordMac), sequence still {d}\n", .{rx.seq}),
        else => return err,
    }
    if (rx.seq != before) return error.SequenceMovedOnFailure;

    // The genuine record still opens afterwards; replaying it does not.
    var copy: [record.max_record_len]u8 = undefined;
    @memcpy(copy[0..wire.len], wire);
    _ = try rx.open(wire);
    if (rx.open(copy[0..wire.len])) |_| {
        return error.ReplayAccepted;
    } else |err| switch (err) {
        error.BadRecordMac => std.debug.print("replayed record refused (BadRecordMac)\n", .{}),
        else => return err,
    }
}
