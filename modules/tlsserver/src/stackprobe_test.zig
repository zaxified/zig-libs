// SPDX-License-Identifier: MIT

//! Dead-stack probe for the record layer's entry points (`testkit.stackprobe`):
//! residue below each burn, and the traffic secret / AEAD key state as
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

// `prot.iv` (12 bytes) is not a needle: it is shorter than the 16-byte window,
// so listing it only made the probe warn; the key state and secret cover it.
fn probeSuite(comptime label: []const u8, suite: record.CipherSuite) !void {
    const secret: []const u8 = if (suite == .aes_256_gcm_sha384) &secret48 else &secret32;
    prot.wipe(); // no stale key state from the previous suite in the needles
    _ = try P.run(label ++ " init", record.Protection.init, .{ &prot, suite, secret }, &[_][]const u8{ secret, std.mem.asBytes(&prot.aead) }, .{});
    for ([_]usize{ 32, record.max_plaintext_len }) |len| {
        fill(buf[record.header_len..][0..len], "record probe content");
        prot.seq = 0;
        _ = try P.run(label ++ " seal", record.Protection.seal, .{ &prot, &buf, len, .application_data, 0 }, &[_][]const u8{std.mem.asBytes(&prot.aead)}, .{});
        rec_len = record.header_len + len + 1 + record.tag_len;
        prot.seq = 0;
        _ = try P.run(label ++ " open", record.Protection.open, .{ &prot, buf[0..rec_len] }, &[_][]const u8{std.mem.asBytes(&prot.aead)}, .{});
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

// ── the key and IV derived from a traffic secret (wave 2 of the 2026-11-06 mutation run) ──

var derived_key: [32]u8 = undefined;
var derived_iv: [12]u8 = undefined;
var out_key: [32]u8 = undefined;
var out_iv: [12]u8 = undefined;

test "STACKPROBE: no derived AEAD key residue after init, trafficKeyIv and initKeyIv" {
    try sp.skipUnlessOptimized();
    fill(&secret32, "record probe secret 32");
    fill(&secret48, "record probe secret 48");
    inline for (.{ record.CipherSuite.aes_128_gcm_sha256, record.CipherSuite.aes_256_gcm_sha384, record.CipherSuite.chacha20_poly1305_sha256 }) |suite| {
        const secret: []const u8 = if (suite == .aes_256_gcm_sha384) &secret48 else &secret32;
        const klen = try record.Protection.trafficKeyIv(suite, secret, &derived_key, &derived_iv);
        const key = derived_key[0..klen];
        prot.wipe();
        _ = try P.run(@tagName(suite) ++ " init", record.Protection.init, .{ &prot, suite, secret }, &[_][]const u8{ secret, key }, .{});
        _ = try P.run(@tagName(suite) ++ " trafficKeyIv", record.Protection.trafficKeyIv, .{ suite, secret, &out_key, &out_iv }, &[_][]const u8{ secret, key }, .{});
        prot.wipe();
        _ = try P.run(@tagName(suite) ++ " initKeyIv", record.Protection.initKeyIv, .{ &prot, suite, key, &derived_iv }, &[_][]const u8{key}, .{});
    }
}

// ── keys.CertKeyPair.fromPem ────────────────────────────────────────────

const keys = @import("keys.zig");
const key_vectors = @import("key_vectors.zig");

var heap_buf: [256 * 1024]u8 = undefined; // an expanded ML-DSA-87 key is ~110 KiB
/// Past the deepest `burn.mldsa_key_burn` (1.25 MiB) and the burn's own frame.
const PKey = sp.Probe(.{ .window = 1536 * 1024 });
var pair: keys.CertKeyPair = undefined;
var nd_s1: [8192]u8 = undefined;
var nd_s2: [8192]u8 = undefined;
var nd_len: [2]usize = .{ 0, 0 };

test "STACKPROBE: no private-key residue after CertKeyPair.fromPem" {
    try sp.skipUnlessOptimized();
    inline for (key_vectors.cases) |c| {
        nd_len = .{ 0, 0 };
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
                // The expanded secret vectors in the NTT domain (uniform mod q: they make needles).
                const a = std.mem.asBytes(&k.s1_hat);
                const b = std.mem.asBytes(&k.s2_hat);
                @memcpy(nd_s1[0..a.len], a);
                @memcpy(nd_s2[0..b.len], b);
                nd_len = .{ a.len, b.len };
                break :blk 32;
            },
        };
        pair.deinit(gpa);
        fba.reset();
        _ = try PKey.run("fromPem " ++ c.name, keys.CertKeyPair.fromPem, .{ &pair, gpa, c.cert_pem, c.key_pem }, &[_][]const u8{ secret[0..n], nd_s1[0..nd_len[0]], nd_s2[0..nd_len[1]] }, .{});
        pair.deinit(gpa);
    }
}

// ── keys.CertKeyPair.fromPemDelegated (wave 2 of the 2026-11-06 mutation run) ──

const x509 = @import("x509");

/// The loaded secret's bytes, for a needle (the scalar, the seed, `K`); 0 for RSA.
fn secretOf(p: *const keys.CertKeyPair, secret: *[66]u8) usize {
    return switch (p.key) {
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
        .rsa => 0,
        inline .mldsa44, .mldsa65, .mldsa87 => |k| blk: {
            secret[0..32].* = k.key;
            break :blk 32;
        },
    };
}

test "STACKPROBE: no private-key residue after CertKeyPair.fromPemDelegated" {
    try sp.skipUnlessOptimized();
    var cred: [4 + 2 + 3 + 4096 + 5]u8 = undefined;
    inline for (key_vectors.cases) |c| {
        var fba: std.heap.FixedBufferAllocator = .init(&heap_buf);
        const gpa = fba.allocator();
        try keys.CertKeyPair.fromPem(&pair, gpa, c.cert_pem, c.key_pem);
        var secret: [66]u8 = undefined;
        const n = secretOf(&pair, &secret);
        // A credential for the very key (parse and SPKI match only).
        const spki = (try x509.spkiOf(pair.chain[0])).der;
        std.mem.writeInt(u32, cred[0..4], 60, .big);
        std.mem.writeInt(u16, cred[4..6], 0x0807, .big);
        std.mem.writeInt(u24, cred[6..9], @intCast(spki.len), .big);
        @memcpy(cred[9..][0..spki.len], spki);
        const at = 9 + spki.len;
        std.mem.writeInt(u16, cred[at..][0..2], 0x0807, .big);
        std.mem.writeInt(u16, cred[at + 2 ..][0..2], 1, .big);
        cred[at + 4] = 0;
        pair.deinit(gpa);
        fba.reset();
        _ = try PKey.run("fromPemDelegated " ++ c.name, keys.CertKeyPair.fromPemDelegated, .{ &pair, gpa, c.cert_pem, c.key_pem, cred[0 .. at + 5] }, &[_][]const u8{secret[0..n]}, .{});
        pair.deinit(gpa);
    }
}
