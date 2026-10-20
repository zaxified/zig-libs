// SPDX-License-Identifier: MIT

//! Dead-stack probe for the record layer's entry points (`testkit.stackprobe`):
//! residue below each burn, and the traffic secret / AEAD key state / IV as
//! needles in any frame. ReleaseFast only (`skipUnlessOptimized`, a runtime
//! skip, so the body is type-checked in every mode).

const std = @import("std");
const record = @import("record.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 128 * 1024 });

var secret32: [32]u8 = undefined;
var secret48: [48]u8 = undefined;
var prot: record.Protection = undefined;
var buf: [record.max_record_len]u8 = undefined;
var rec_len: usize = 0;

fn fill(out: []u8, label: []const u8) void {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &h, .{});
    for (out, 0..) |*b, i| b.* = h[i % 32] ^ @as(u8, @truncate(i / 32));
}

fn probeSuite(comptime label: []const u8, suite: record.CipherSuite) !void {
    const secret: []const u8 = if (suite == .aes_256_gcm_sha384) &secret48 else &secret32;
    prot.wipe(); // no stale key state from the previous suite in the needles
    _ = try P.run(label ++ " init", record.Protection.init, .{ &prot, suite, secret }, &[_][]const u8{ secret, std.mem.asBytes(&prot.aead), &prot.iv }, .{});
    for ([_]usize{ 32, record.max_plaintext_len }) |len| {
        fill(buf[record.header_len..][0..len], "record probe content");
        prot.seq = 0;
        _ = try P.run(label ++ " seal", record.Protection.seal, .{ &prot, &buf, len, .application_data, 0 }, &[_][]const u8{ std.mem.asBytes(&prot.aead), &prot.iv }, .{});
        rec_len = record.header_len + len + 1 + record.tag_len;
        prot.seq = 0;
        _ = try P.run(label ++ " open", record.Protection.open, .{ &prot, buf[0..rec_len] }, &[_][]const u8{ std.mem.asBytes(&prot.aead), &prot.iv }, .{});
    }
}

test "STACKPROBE: no traffic secret, key state or IV residue after any record entry point" {
    try sp.skipUnlessOptimized();
    fill(&secret32, "record probe secret 32");
    fill(&secret48, "record probe secret 48");
    try probeSuite("aes128", .aes_128_gcm_sha256);
    try probeSuite("aes256", .aes_256_gcm_sha384);
    try probeSuite("chacha", .chacha20_poly1305_sha256);
}
