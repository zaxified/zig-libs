// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for quic-crypto (added 2026-10-10).
//!
//! Four harnesses, each generic over its source of choices;
//! `QUIC_CRYPTO_FUZZ=<runs>[,<first seed>]` runs them (testkit's fuzz driver;
//! `_ONLY` selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as
//! documented there):
//! - `quic-hp-remove`: receive-side header unprotection on arbitrary packet
//!   bytes, offsets and masks (the first thing done to a packet off the wire,
//!   before its tag is checked); every pn_len 1..4 and the refusals are
//!   counted.
//! - `quic-hp-roundtrip`: a genuine packet through AES-128 / AES-256 /
//!   ChaCha20 header protection: `remove` after `apply` restores every octet
//!   and recovers the packet-number length; a mask of a different sample or a
//!   different key does not.
//! - `quic-protection`: AEAD packet protection (AES-128-GCM, AES-256-GCM,
//!   ChaCha20-Poly1305): a sealed packet opens; one flipped bit anywhere in
//!   the header, ciphertext or tag, a different packet number, key or iv, or
//!   a truncation is REFUSED.
//! - `quic-initial-retry`: Initial secrets and packet keys per version and
//!   DCID, the key-update chain, and the Retry Integrity Tag (a genuine Retry
//!   verifies; a flipped bit, a different ODCID or version is refused).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const root = @import("root.zig");
const headerprot = @import("headerprot.zig");
const retry = @import("retry.zig");
const Protection = root.Protection;
pub const fuzz_driver = testkit.fuzz.driver;

/// Reach counters for one harness file's labels (see jwt's fuzz_test.zig).
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

fn flipBit(src: anytype, buf: []u8) void {
    buf[src.index(buf.len)] ^= @as(u8, 1) << @intCast(src.valueRangeAtMost(u8, 0, 7));
}

// ── quic-hp-remove ──────────────────────────────────────────────────────────

const RemoveMark = Marker(enum { pn_len_1, pn_len_2, pn_len_3, pn_len_4, too_short, long_form });

pub fn fuzzHpRemove(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var raw: [7 + 64]u8 = undefined;
    var n: usize = 0;
    if (S == fuzz_driver.Rng) {
        // Half the time a structured draw: a real-looking first byte, an offset
        // near the packet's end, a mask that sets the low bits.
        n = src.index(raw.len + 1);
        src.bytes(raw[0..n]);
        if (n >= 2 and src.value(bool)) raw[1] = @intCast(src.index(if (n > 7) n - 7 + 4 else 4));
    } else n = src.slice(&raw);
    const form: headerprot.HeaderForm = if (n >= 1 and raw[0] & 1 == 1) .long else .short;
    const pn_offset: usize = if (n >= 2) raw[1] else 0;
    var mask: headerprot.Mask = .{ 0, 0, 0, 0, 0 };
    if (n >= 7) mask = raw[2..7].*;
    const packet = if (n > 7) raw[7..n] else raw[0..0];
    if (form == .long) RemoveMark.mark(.long_form);
    if (headerprot.remove(packet, form, pn_offset, mask)) |r| switch (r.pn_len) {
        1 => RemoveMark.mark(.pn_len_1),
        2 => RemoveMark.mark(.pn_len_2),
        3 => RemoveMark.mark(.pn_len_3),
        4 => RemoveMark.mark(.pn_len_4),
        else => return error.PnLenOutOfRange,
    } else |_| RemoveMark.mark(.too_short);
}

fn fuzzHpRemoveSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzHpRemove(std.testing.Smith, smith, testing.allocator);
}

test "fuzz: remove never panics on arbitrary packet bytes / offsets / masks (driver harness)" {
    try testing.fuzz({}, fuzzHpRemoveSmith, .{});
}

test "fuzz driver: QUIC_CRYPTO_FUZZ (hp remove)" {
    try fuzz_driver.run(fuzzHpRemove, .{ .prefix = "QUIC_CRYPTO_FUZZ", .name = "quic-hp-remove" });
}

test "fuzz harness: hp remove, 400 seeds, reaches every outcome" {
    try RemoveMark.reach(fuzzHpRemove, "quic-hp-remove", 400);
}

// ── quic-hp-roundtrip ───────────────────────────────────────────────────────

const RoundMark = Marker(enum { aes128, aes256, chacha, restored, other_sample_differs, other_key_differs });

pub fn fuzzHpRoundtrip(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var key: [32]u8 = undefined;
    src.bytes(&key);
    var packet: [96]u8 = undefined;
    src.bytes(&packet);
    const len = 24 + src.index(packet.len - 24 + 1);
    const form: headerprot.HeaderForm = if (src.value(bool)) .long else .short;
    const pn_len = 1 + src.index(4);
    // Sample = 16 octets starting 4 past the start of the packet number.
    const pn_offset = 1 + src.index(len - 20);
    packet[0] = (packet[0] & ~@as(u8, 0x03)) | @as(u8, @intCast(pn_len - 1));
    const original = packet;
    const sample: [16]u8 = packet[pn_offset + 4 ..][0..16].*;

    const kind = src.index(3);
    const mask: headerprot.Mask = switch (kind) {
        0 => headerprot.computeMaskAes(key[0..16], sample),
        1 => headerprot.computeMaskAes(key[0..32], sample),
        else => headerprot.computeMaskChaCha20(key[0..32], sample),
    };
    switch (kind) {
        0 => RoundMark.mark(.aes128),
        1 => RoundMark.mark(.aes256),
        else => RoundMark.mark(.chacha),
    }
    try headerprot.apply(packet[0..len], form, pn_offset, pn_len, mask);
    // What the sender produced is exactly the masked bits and nothing else.
    for (packet[0..len], original[0..len], 0..) |a, b, i| {
        const in_pn = i >= pn_offset and i < pn_offset + pn_len;
        if (i != 0 and !in_pn and a != b) return error.ApplyTouchedTheWrongOctet;
    }
    var rx = packet;
    const r = try headerprot.remove(rx[0..len], form, pn_offset, mask);
    if (r.pn_len != pn_len or !std.mem.eql(u8, rx[0..len], original[0..len])) return error.RemoveDidNotRestore;
    RoundMark.mark(.restored);

    // A mask from another sample (or another key) does not unmask it, unless the
    // two masks agree on every octet that matters.
    var other = sample;
    flipBit(src, &other);
    const m2: headerprot.Mask = switch (kind) {
        0 => headerprot.computeMaskAes(key[0..16], other),
        1 => headerprot.computeMaskAes(key[0..32], other),
        else => headerprot.computeMaskChaCha20(key[0..32], other),
    };
    if (!std.mem.eql(u8, &m2, &mask)) {
        var bad = packet;
        _ = headerprot.remove(bad[0..len], form, pn_offset, m2) catch {};
        if (std.mem.eql(u8, bad[0..len], original[0..len])) {
            // Equal after removal only if the two masks agree on the used part.
            const fb: u8 = if (form == .long) 0x0f else 0x1f;
            if ((m2[0] & fb) != (mask[0] & fb)) return error.WrongMaskUnmasked;
            for (0..pn_len) |i| if (m2[1 + i] != mask[1 + i]) return error.WrongMaskUnmasked;
        }
        RoundMark.mark(.other_sample_differs);
    }
    var key2 = key;
    flipBit(src, key2[0..if (kind == 0) 16 else 32]);
    const m3: headerprot.Mask = switch (kind) {
        0 => headerprot.computeMaskAes(key2[0..16], sample),
        1 => headerprot.computeMaskAes(key2[0..32], sample),
        else => headerprot.computeMaskChaCha20(key2[0..32], sample),
    };
    if (!std.mem.eql(u8, &m3, &mask)) RoundMark.mark(.other_key_differs);
}

fn fuzzHpRoundtripSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzHpRoundtrip(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

test "fuzz: header protection apply/remove round trip over all three mask primitives" {
    try testing.fuzz({}, fuzzHpRoundtripSmith, .{});
}

test "fuzz driver: QUIC_CRYPTO_FUZZ (hp roundtrip)" {
    try fuzz_driver.run(fuzzHpRoundtrip, .{ .prefix = "QUIC_CRYPTO_FUZZ", .name = "quic-hp-roundtrip" });
}

test "fuzz harness: hp roundtrip, 300 seeds, reaches every outcome" {
    try RoundMark.reach(fuzzHpRoundtrip, "quic-hp-roundtrip", 300);
}

// ── quic-protection ─────────────────────────────────────────────────────────

const ProtMark = Marker(enum {
    aes128,
    aes256,
    chacha,
    genuine_opened,
    header_flip_refused,
    ciphertext_flip_refused,
    pn_refused,
    key_refused,
    truncated_refused,
    random_refused,
    short_buffer,
});

fn protectionCase(comptime Aead: type, comptime tag: anytype, comptime S: type, src: *S) anyerror!void {
    const P = Protection(Aead);
    tag();
    var key: [P.key_length]u8 = undefined;
    var iv: [12]u8 = undefined;
    src.bytes(&key);
    src.bytes(&iv);
    const pn = src.value(u64) >> 2; // a 62-bit packet number
    var header: [40]u8 = undefined;
    var payload: [120]u8 = undefined;
    const hl = src.index(header.len + 1);
    const pl = src.index(payload.len + 1);
    src.bytes(header[0..hl]);
    src.bytes(payload[0..pl]);

    var ct: [120 + 16]u8 = undefined;
    const total = try P.seal(&key, iv, pn, header[0..hl], payload[0..pl], &ct);
    if (total != pl + P.tag_length) return error.SealLengthWrong;
    var out: [120]u8 = undefined;
    const got = try P.open(&key, iv, pn, header[0..hl], ct[0..total], &out);
    if (!std.mem.eql(u8, out[0..got], payload[0..pl])) return error.OpenedWrongPlaintext;
    ProtMark.mark(.genuine_opened);

    // Nonces of different packet numbers differ.
    const pn2 = pn ^ (@as(u64, 1) << @intCast(src.valueRangeAtMost(u8, 0, 61)));
    if (std.mem.eql(u8, &P.nonce(iv, pn), &P.nonce(iv, pn2))) return error.NonceCollision;

    // One flipped bit in the header: refused.
    if (hl > 0) {
        var h2 = header;
        flipBit(src, h2[0..hl]);
        if (P.open(&key, iv, pn, h2[0..hl], ct[0..total], &out)) |_| return error.FlippedHeaderAccepted else |_| ProtMark.mark(.header_flip_refused);
    }
    // One flipped bit in the ciphertext or tag.
    {
        var c2 = ct;
        flipBit(src, c2[0..total]);
        if (P.open(&key, iv, pn, header[0..hl], c2[0..total], &out)) |_| return error.FlippedCiphertextAccepted else |_| ProtMark.mark(.ciphertext_flip_refused);
    }
    // Another packet number, key or iv.
    if (P.open(&key, iv, pn2, header[0..hl], ct[0..total], &out)) |_| return error.WrongPacketNumberAccepted else |_| ProtMark.mark(.pn_refused);
    {
        var k2 = key;
        flipBit(src, &k2);
        if (P.open(&k2, iv, pn, header[0..hl], ct[0..total], &out)) |_| return error.WrongKeyAccepted else |_| ProtMark.mark(.key_refused);
        var iv2 = iv;
        flipBit(src, &iv2);
        if (P.open(&key, iv2, pn, header[0..hl], ct[0..total], &out)) |_| return error.WrongIvAccepted else |_| {}
    }
    // Truncated by 1..total octets (down to nothing).
    {
        const cut = 1 + src.index(total);
        if (P.open(&key, iv, pn, header[0..hl], ct[0 .. total - cut], &out)) |_| return error.TruncatedAccepted else |_| ProtMark.mark(.truncated_refused);
    }
    // Random bytes of the same length.
    {
        var rnd: [120 + 16]u8 = undefined;
        src.bytes(rnd[0..total]);
        if (!std.mem.eql(u8, rnd[0..total], ct[0..total])) {
            if (P.open(&key, iv, pn, header[0..hl], rnd[0..total], &out)) |_| return error.RandomAccepted else |_| ProtMark.mark(.random_refused);
        }
    }
    // A buffer that is too small for the packet is an error, not an overrun.
    if (pl > 0) {
        var small: [1]u8 = undefined;
        if (P.seal(&key, iv, pn, header[0..hl], payload[0..pl], small[0..0])) |_| return error.ShortSealBufferAccepted else |_| ProtMark.mark(.short_buffer);
    }
}

fn markAes128() void {
    ProtMark.mark(.aes128);
}
fn markAes256() void {
    ProtMark.mark(.aes256);
}
fn markChacha() void {
    ProtMark.mark(.chacha);
}

pub fn fuzzProtection(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    switch (src.index(3)) {
        0 => try protectionCase(std.crypto.aead.aes_gcm.Aes128Gcm, markAes128, S, src),
        1 => try protectionCase(std.crypto.aead.aes_gcm.Aes256Gcm, markAes256, S, src),
        else => try protectionCase(root.ChaCha20Poly1305, markChacha, S, src),
    }
}

fn fuzzProtectionSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzProtection(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

test "fuzz: a sealed packet opens, a damaged one is refused" {
    try testing.fuzz({}, fuzzProtectionSmith, .{});
}

test "fuzz driver: QUIC_CRYPTO_FUZZ (protection)" {
    try fuzz_driver.run(fuzzProtection, .{ .prefix = "QUIC_CRYPTO_FUZZ", .name = "quic-protection" });
}

test "fuzz harness: protection, 300 seeds, reaches every outcome" {
    try ProtMark.reach(fuzzProtection, "quic-protection", 300);
}

// ── quic-initial-retry ──────────────────────────────────────────────────────

const InitMark = Marker(enum {
    v1,
    v2,
    initial_opened,
    wrong_dcid_refused,
    versions_differ,
    key_chain_distinct,
    retry_verified,
    retry_flip_refused,
    retry_odcid_refused,
    retry_version_refused,
    retry_short,
});

pub fn fuzzInitialRetry(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    const ver: root.Version = if (src.value(bool)) .v1 else .v2;
    if (ver == .v1) InitMark.mark(.v1) else InitMark.mark(.v2);
    const other: root.Version = if (ver == .v1) .v2 else .v1;
    var dcid: [255]u8 = undefined;
    const dl = src.index(21);
    src.bytes(dcid[0..dl]);

    var s: root.InitialSecrets = undefined;
    root.deriveInitialSecretsFor(ver, &s, dcid[0..dl]);
    var s_other: root.InitialSecrets = undefined;
    root.deriveInitialSecretsFor(other, &s_other, dcid[0..dl]);
    if (std.mem.eql(u8, &s.client_initial_secret, &s_other.client_initial_secret)) return error.VersionsShareSecrets;
    InitMark.mark(.versions_differ);

    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    var keys: root.PacketKeys(16) = undefined;
    root.derivePacketKeysFor(ver, Hkdf, 16, &keys, &s.client_initial_secret);
    const P = Protection(std.crypto.aead.aes_gcm.Aes128Gcm);
    var header: [24]u8 = undefined;
    var payload: [64]u8 = undefined;
    const hl = src.index(header.len + 1);
    const pl = src.index(payload.len + 1);
    src.bytes(header[0..hl]);
    src.bytes(payload[0..pl]);
    const pn = src.value(u32);
    var ct: [64 + 16]u8 = undefined;
    const total = try P.seal(&keys.key, keys.iv, pn, header[0..hl], payload[0..pl], &ct);
    var out: [64]u8 = undefined;
    // The receiver derives from the DCID in the packet: same secrets, same keys.
    var s2: root.InitialSecrets = undefined;
    root.deriveInitialSecretsFor(ver, &s2, dcid[0..dl]);
    var keys2: root.PacketKeys(16) = undefined;
    root.derivePacketKeysFor(ver, Hkdf, 16, &keys2, &s2.client_initial_secret);
    const got = try P.open(&keys2.key, keys2.iv, pn, header[0..hl], ct[0..total], &out);
    if (!std.mem.eql(u8, out[0..got], payload[0..pl])) return error.InitialOpenedWrong;
    InitMark.mark(.initial_opened);
    // Another DCID: other keys, refused.
    var dcid2 = dcid;
    if (dl > 0) {
        flipBit(src, dcid2[0..dl]);
    } else dcid2[0] = 1;
    const dl2 = if (dl > 0) dl else 1;
    var s3: root.InitialSecrets = undefined;
    root.deriveInitialSecretsFor(ver, &s3, dcid2[0..dl2]);
    var keys3: root.PacketKeys(16) = undefined;
    root.derivePacketKeysFor(ver, Hkdf, 16, &keys3, &s3.client_initial_secret);
    if (P.open(&keys3.key, keys3.iv, pn, header[0..hl], ct[0..total], &out)) |_| return error.WrongDcidAccepted else |_| InitMark.mark(.wrong_dcid_refused);

    // The key-update chain never repeats a secret.
    var ku1: root.KeyUpdate(Hkdf, 16) = undefined;
    var ku2: root.KeyUpdate(Hkdf, 16) = undefined;
    root.advanceKeysFor(ver, Hkdf, 16, &ku1, &s.client_initial_secret);
    root.advanceKeysFor(ver, Hkdf, 16, &ku2, &ku1.next_secret);
    if (std.mem.eql(u8, &ku1.next_secret, &s.client_initial_secret) or std.mem.eql(u8, &ku2.next_secret, &ku1.next_secret) or std.mem.eql(u8, &ku1.key, &ku2.key)) return error.KeyUpdateRepeats;
    InitMark.mark(.key_chain_distinct);

    // Retry Integrity Tag.
    var pkt: [100 + 16]u8 = undefined;
    const body = 1 + src.index(100);
    src.bytes(pkt[0..body]);
    const tag = try root.computeRetryTag(ver, dcid[0..dl], pkt[0..body]);
    @memcpy(pkt[body..][0..16], &tag);
    const n = body + 16;
    try root.verifyRetryTag(ver, dcid[0..dl], pkt[0..n]);
    InitMark.mark(.retry_verified);
    var p2 = pkt;
    flipBit(src, p2[0..n]);
    if (root.verifyRetryTag(ver, dcid[0..dl], p2[0..n])) |_| return error.FlippedRetryAccepted else |_| InitMark.mark(.retry_flip_refused);
    if (root.verifyRetryTag(ver, dcid2[0..dl2], pkt[0..n])) |_| return error.WrongOdcidAccepted else |_| InitMark.mark(.retry_odcid_refused);
    if (root.verifyRetryTag(other, dcid[0..dl], pkt[0..n])) |_| return error.WrongVersionAccepted else |_| InitMark.mark(.retry_version_refused);
    if (root.verifyRetryTag(ver, dcid[0..dl], pkt[0..src.index(16)])) |_| return error.ShortRetryAccepted else |_| InitMark.mark(.retry_short);
}

fn fuzzInitialRetrySmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzInitialRetry(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

test "fuzz: initial secrets, key chain and the Retry Integrity Tag" {
    try testing.fuzz({}, fuzzInitialRetrySmith, .{});
}

test "fuzz driver: QUIC_CRYPTO_FUZZ (initial + retry)" {
    try fuzz_driver.run(fuzzInitialRetry, .{ .prefix = "QUIC_CRYPTO_FUZZ", .name = "quic-initial-retry" });
}

test "fuzz harness: initial + retry, 300 seeds, reaches every outcome" {
    try InitMark.reach(fuzzInitialRetry, "quic-initial-retry", 300);
}
