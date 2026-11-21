// SPDX-License-Identifier: MIT

//! What a DTLS/TLS 1.3 `TLS_AES_128_CCM_8_SHA256` record layer does with
//! `aesccm`: expand the key once (`init`), seal a record under a 12-byte
//! nonce with the record header as additional data, open it back, and refuse
//! a tampered copy by name — with the plaintext buffer zeroed.
//!
//! External oracle: Python `cryptography`'s `AESCCM` (OpenSSL) on these exact
//! inputs gives `expected` below; the `must` right after `seal` checks it in
//! every optimize mode.

const std = @import("std");
const aesccm = @import("aesccm");

fn must(ok: bool, src: std.builtin.SourceLocation) void {
    if (!ok) std.debug.panic("example check failed at {s}:{d}", .{ src.file, src.line });
}

pub fn main() !void {
    var key: [16]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(0x60 + i);
    var nonce: [12]u8 = undefined;
    for (&nonce, 0..) |*b, i| b.* = @intCast(i);
    const msg = "constrained device reading 21.5C";
    const ad = "record header";
    var expected: [msg.len + 8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "76e2c237f364783986badf5479fb850c2110b5f182dc5fee9e10947bdd16144803999b06d304f2bb");

    var ctx = aesccm.Aes128Ccm8.init(key);
    defer ctx.deinit();
    var ct: [msg.len]u8 = undefined;
    var tag: [8]u8 = undefined;
    try ctx.seal(&ct, &tag, msg, ad, nonce);
    must(std.mem.eql(u8, &ct, expected[0..msg.len]) and std.mem.eql(u8, &tag, expected[msg.len..]), @src());

    var back: [msg.len]u8 = undefined;
    try ctx.open(&back, &ct, tag, ad, nonce);
    must(std.mem.eql(u8, &back, msg), @src());

    ct[0] ^= 1;
    if (ctx.open(&back, &ct, tag, ad, nonce)) |_| {
        must(false, @src());
    } else |err| {
        must(err == error.AuthenticationFailed, @src());
        must(std.mem.allEqual(u8, &back, 0), @src());
    }
    std.debug.print("aesccm example: sealed, opened, tamper refused\n", .{});
}
