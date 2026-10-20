// SPDX-License-Identifier: MIT

//! What an SSH transport does with `aes192-ctr` (RFC 4344): one encryption
//! context per direction, built once when the key is installed, and ONE
//! counter that runs on across packets — each packet (a whole number of
//! blocks) is encrypted from where the previous one stopped. The receiver
//! decrypts in place with its own context, and both keys are wiped when they
//! are retired.
//!
//! Checked against the SP 800-38A F.5.5 vector and against
//! `std.crypto.core.modes.ctr` over the same context, packet by packet.
//! Nothing here allocates.

const std = @import("std");
const aes192 = @import("aes192");

/// A check that survives every optimize mode (a debug assert would vanish in
/// the ReleaseFast lane, which runs this example too).
fn must(ok: bool, src: std.builtin.SourceLocation) void {
    if (!ok) std.debug.panic("example check failed at {s}:{d}", .{ src.file, src.line });
}

fn hex(comptime n: usize, comptime s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

/// The counter after `len` bytes (a whole number of blocks) at `iv`.
fn advance(iv: [16]u8, len: usize) [16]u8 {
    var out = iv;
    const c = std.mem.readInt(u128, &iv, .big) +% len / 16;
    std.mem.writeInt(u128, &out, c, .big);
    return out;
}

pub fn main() !void {
    // SP 800-38A F.5.5 (CTR-AES192.Encrypt), first two blocks.
    const key = hex(24, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    const iv0 = hex(16, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    const pt = hex(32, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
    const want = hex(32, "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e94");

    var tx = aes192.Aes192.initEnc(key);
    defer tx.wipe();
    var rx = aes192.Aes192.initEnc(key); // CTR decrypts with the forward cipher
    defer rx.wipe();

    var out: [32]u8 = undefined;
    tx.ctr(&out, &pt, iv0);
    must(std.mem.eql(u8, &out, &want), @src());

    // Three packets, the counter carried from one to the next.
    const packets = [_][]const u8{
        "SSH_MSG_CHANNEL_DATA, two blocks",
        "a packet crossing one eight-block batch of the wide path, " ++
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef......",
        "and a third, sixteen x3.........",
    };
    var tx_iv = iv0;
    var rx_iv = iv0;
    for (packets) |p| {
        must(p.len % 16 == 0, @src());
        var wire: [256]u8 = undefined;
        const ct = wire[0..p.len];
        tx.ctr(ct, p, tx_iv);

        var check: [256]u8 = undefined;
        std.crypto.core.modes.ctr(aes192.Aes192EncryptCtx, tx, check[0..p.len], p, tx_iv, .big);
        must(std.mem.eql(u8, ct, check[0..p.len]), @src());
        tx_iv = advance(tx_iv, p.len);

        rx.ctr(ct, ct, rx_iv); // in place
        must(std.mem.eql(u8, ct, p), @src());
        rx_iv = advance(rx_iv, p.len);
    }
    std.debug.print("aes192 example: {d} packets round-tripped under one running counter\n", .{packets.len});
}
