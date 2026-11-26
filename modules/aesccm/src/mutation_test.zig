// SPDX-License-Identifier: MIT

//! Killing tests of the 2026-11-25 whole-module mutation run (first audit).
//! Each pins a behaviour the KAT set left to luck: the wipe in `deinit`, the
//! buffer-size refusal in both directions, the message-length bound on the
//! open side, and the CBC-MAC block alignment edges (additional data or
//! message ending exactly on a block boundary, one-byte additional data).

const std = @import("std");
const testing = std.testing;
const crypto = std.crypto;
const root = @import("root.zig");

test "mutation 2026-11-25: deinit zeroes the expanded key" {
    inline for (.{ root.Aes128Ccm, root.Aes256Ccm8 }) |C| {
        const key: [C.key_length]u8 = @splat(0x6b);
        var s = C.init(key);
        try testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&s.ctx), 0));
        s.deinit();
        try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&s.ctx), 0));
    }
}

test "mutation 2026-11-25: a ciphertext buffer longer than the message is refused too (seal and open)" {
    const C = root.Aes128Ccm8;
    const key: [16]u8 = @splat(1);
    const nonce: [12]u8 = @splat(2);
    var tag: [8]u8 = @splat(0);
    var long: [5]u8 = undefined;
    try testing.expectError(error.BufferSizeMismatch, C.encrypt(&long, &tag, "abcd", "", nonce, key));
    try testing.expectError(error.BufferSizeMismatch, C.decrypt(&long, "abcd", tag, "", nonce, key));
}

test "mutation 2026-11-25: open accepts a message of exactly max_message_len bytes" {
    const C = root.Aes128Ccm8Nonce13; // 2-byte length field: 65535
    const key: [16]u8 = @splat(3);
    const nonce: [13]u8 = @splat(4);
    const msg = try testing.allocator.alloc(u8, C.max_message_len);
    defer testing.allocator.free(msg);
    const ct = try testing.allocator.alloc(u8, C.max_message_len);
    defer testing.allocator.free(ct);
    const back = try testing.allocator.alloc(u8, C.max_message_len);
    defer testing.allocator.free(back);
    for (msg, 0..) |*b, i| b.* = @truncate(i *% 31);
    var tag: [8]u8 = undefined;
    try C.encrypt(ct, &tag, msg, "hdr", nonce, key);
    try C.decrypt(back, ct, tag, "hdr", nonce, key);
    try testing.expectEqualSlices(u8, msg, back);
}

test "mutation 2026-11-25: byte for byte std's 13-byte presets over every additional-data and message length 0..80" {
    // Lengths 14 / 30 / 46 (2-byte prefix + data = whole blocks) and 16 / 32 /
    // 48 ... end the CBC-MAC input exactly on a block boundary, 1 is the
    // shortest non-empty additional data: edges no KAT row has.
    const key: [16]u8 = @splat(0x42);
    const nonce: [13]u8 = @splat(0x17);
    var data: [80]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 11 +% 5);
    inline for (.{
        .{ root.Ccm(crypto.core.aes.Aes128, 16, 13), crypto.aead.aes_ccm.Aes128Ccm16 },
        .{ root.Ccm(crypto.core.aes.Aes128, 8, 13), crypto.aead.aes_ccm.Aes128Ccm8 },
    }) |pair| {
        const Ours = pair[0];
        const Std = pair[1];
        for (0..81) |ad_len| {
            for (0..81) |m_len| {
                var c1: [80]u8 = undefined;
                var c2: [80]u8 = undefined;
                var t1: [Ours.tag_length]u8 = undefined;
                var t2: [Ours.tag_length]u8 = undefined;
                try Ours.encrypt(c1[0..m_len], &t1, data[0..m_len], data[0..ad_len], nonce, key);
                Std.encrypt(c2[0..m_len], &t2, data[0..m_len], data[0..ad_len], nonce, key);
                try testing.expectEqualSlices(u8, c2[0..m_len], c1[0..m_len]);
                try testing.expectEqualSlices(u8, &t2, &t1);
            }
        }
    }
}
