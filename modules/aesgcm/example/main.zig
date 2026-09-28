// SPDX-License-Identifier: MIT

//! What a TLS 1.3 record layer does with `aesgcm`: one `Context` per
//! traffic key, built once when the key is installed, then used for every
//! record — the per-record nonce is the static IV XORed with the record
//! sequence number (RFC 8446 §5.3), the AD is the 5-byte record header. The
//! receiving side opens each record IN PLACE, as a record layer decrypting
//! into its read buffer does, rejects a record with one flipped bit BY NAME,
//! and the key is wiped when it is retired.
//!
//! Checked against the stateless, std-shaped API of the same module and
//! against `std.crypto.aead.aes_gcm` — two independent computations of every
//! record. Nothing here allocates: every buffer is caller-owned.

const std = @import("std");
const aesgcm = @import("aesgcm");

const Gcm = aesgcm.Aes256Gcm;

/// A check that survives every optimize mode (a debug assert would vanish in
/// the ReleaseFast lane, which runs this example too).
fn must(ok: bool, src: std.builtin.SourceLocation) void {
    if (!ok) std.debug.panic("example check failed at {s}:{d}", .{ src.file, src.line });
}

fn recordNonce(iv: [12]u8, seq: u64) [12]u8 {
    var n = iv;
    var s: [8]u8 = undefined;
    std.mem.writeInt(u64, &s, seq, .big);
    for (n[4..], s) |*b, x| b.* ^= x;
    return n;
}

pub fn main() !void {
    const key: [Gcm.key_length]u8 = @splat(0x5c);
    const iv: [Gcm.nonce_length]u8 = .{ 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c };

    // Once per traffic key, not per record: this is the setup std redoes
    // on every call.
    var tx = Gcm.init(key);
    defer tx.wipe();
    var rx = Gcm.init(key);
    defer rx.wipe();

    const bodies = [_][]const u8{
        "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello",
        "a second record, long enough to cross one eight-block batch of the stitched kernel: " ++
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "",
    };

    var wire: [512]u8 = undefined;
    for (bodies, 0..) |body, seq| {
        const nonce = recordNonce(iv, seq);
        const header = [5]u8{ 0x17, 0x03, 0x03, 0x00, @intCast(body.len + Gcm.tag_length) };
        const ct = wire[0..body.len];
        var tag: [Gcm.tag_length]u8 = undefined;
        tx.encrypt(ct, &tag, body, &header, nonce);

        // Two independent computations of the same record.
        var ct2: [512]u8 = undefined;
        var tag2: [16]u8 = undefined;
        Gcm.encrypt(ct2[0..body.len], &tag2, body, &header, nonce, key);
        must(std.mem.eql(u8, ct, ct2[0..body.len]) and std.mem.eql(u8, &tag, &tag2), @src());
        std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(ct2[0..body.len], &tag2, body, &header, nonce, key);
        must(std.mem.eql(u8, ct, ct2[0..body.len]) and std.mem.eql(u8, &tag, &tag2), @src());

        // A record with one flipped bit is refused by name, and the output
        // buffer holds no partial plaintext afterwards.
        if (body.len > 0) {
            var bad = ct2;
            bad[0] ^= 0x01;
            var out: [512]u8 = @splat(0xee);
            if (rx.decrypt(out[0..body.len], bad[0..body.len], tag, &header, nonce)) |_| {
                must(false, @src());
            } else |err| switch (err) {
                error.AuthenticationFailed => must(std.mem.allEqual(u8, out[0..body.len], 0), @src()),
            }
        }

        // The genuine record opens in place.
        try rx.decrypt(ct, ct, tag, &header, nonce);
        must(std.mem.eql(u8, ct, body), @src());
        std.debug.print("record {d}: {d} bytes sealed and opened on backend {t}\n", .{ seq, body.len, aesgcm.backend() });
    }
}
