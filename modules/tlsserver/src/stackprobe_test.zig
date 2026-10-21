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

// ── keys.CertKeyPair.fromPem ────────────────────────────────────────────

const keys = @import("keys.zig");
const key_vectors = @import("key_vectors.zig");

var heap_buf: [256 * 1024]u8 = undefined; // an expanded ML-DSA-87 key is ~110 KiB
/// Past the deepest `burn.mldsa_key_burn` (1.25 MiB) and the burn's own frame.
const PKey = sp.Probe(.{ .window = 1536 * 1024 });
var pair: keys.CertKeyPair = undefined;

test "STACKPROBE: no private-key residue after CertKeyPair.fromPem" {
    try sp.skipUnlessOptimized();
    inline for (key_vectors.cases) |c| {
        var fba: std.heap.FixedBufferAllocator = .init(&heap_buf);
        const gpa = fba.allocator();
        // The needles are the loaded secret's bytes, known only afterwards:
        // load once, copy the secret out, wipe, then probe a second load.
        try keys.CertKeyPair.fromPem(&pair, gpa, c.cert_pem, c.key_pem);
        var secret: [66]u8 = undefined;
        const n: usize = switch (pair.key) {
            .ecdsa_p256 => |k| blk: {
                secret[0..32].* = k.toBytes();
                break :blk 32;
            },
            .ecdsa_p384 => |k| blk: {
                secret[0..48].* = k.toBytes();
                break :blk 48;
            },
            .ed25519 => |k| blk: {
                secret[0..32].* = k.seed();
                break :blk 32;
            },
            .ecdsa_p521 => |k| blk: {
                secret[0..66].* = k.toBytes();
                break :blk 66;
            },
            .rsa => 0, // `rsa` burns its own parse; residue is still checked
            // The signing seed `K` of the expanded key.
            inline .mldsa44, .mldsa65, .mldsa87 => |k| blk: {
                secret[0..32].* = k.key;
                break :blk 32;
            },
        };
        pair.deinit(gpa);
        fba.reset();
        _ = try PKey.run("fromPem " ++ c.name, keys.CertKeyPair.fromPem, .{ &pair, gpa, c.cert_pem, c.key_pem }, &[_][]const u8{secret[0..n]}, .{});
        pair.deinit(gpa);
    }
}
