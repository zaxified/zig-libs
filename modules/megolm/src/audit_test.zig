// SPDX-License-Identifier: MIT

//! audit_test.zig — tests added by the 2026-11-17 whole-module mutation audit
//! (SPEC.md "Audit 2026-11-17"): boundary and error-value cases the KAT and
//! round-trip suites never reached (varint limits, missing-field errors, the
//! share-format guards, a differential `advanceTo` against repeated
//! `advanceStep`, the `deinit`/`secureZero` contracts, `exportAt` /
//! `forgetBefore` edges, the pickle header order).

const std = @import("std");
const aescbc = @import("aescbc");
const ratchet_mod = @import("ratchet.zig");
const cipher = @import("cipher.zig");
const message = @import("message.zig");
const session_key = @import("session_key.zig");
const pickle = @import("pickle.zig");
const shim = @import("test_shim.zig");

const testing = std.testing;
const Aes256 = std.crypto.core.aes.Aes256;

fn testIo() std.Io.Threaded {
    return std.Io.Threaded.init(testing.allocator, .{});
}

const seed: [ratchet_mod.ratchet_len]u8 = blk: {
    var s: [ratchet_mod.ratchet_len]u8 = undefined;
    for (&s, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);
    break :blk s;
};

fn allZero(bytes: []const u8) bool {
    return std.mem.allEqual(u8, bytes, 0);
}

// ── ratchet ─────────────────────────────────────────────────────────────

test "advanceTo equals repeated advanceStep, including byte differences above 127" {
    // A step count held in 7 bits, or not reduced to a byte, diverges from the
    // one-step-at-a-time ratchet as soon as one byte of the counter moves by
    // 128 or more.
    const targets = [_]u32{ 1, 127, 128, 200, 255, 256, 257, 0x80 * 256 + 5, 0x8000 };
    for (targets) |t| {
        var a = shim.ratchetInit(&seed, 0);
        var b = a;
        try a.advanceTo(t);
        var i: u32 = 0;
        while (i < t) : (i += 1) b.advanceStep();
        try testing.expectEqual(t, a.counter);
        try testing.expectEqual(b.counter, a.counter);
        try testing.expectEqualSlices(u8, &b.data, &a.data);
    }
}

test "Ratchet.secureZero zeroes the secret bytes and keeps the public counter" {
    var r = shim.ratchetInit(&seed, 77);
    try testing.expect(!allZero(&r.data));
    r.secureZero();
    try testing.expect(allZero(&r.data));
    try testing.expectEqual(@as(u32, 77), r.counter);
}

test "cipher.Keys.deinit zeroes the AES key, the HMAC key and the IV" {
    var k = shim.deriveKeys(&seed);
    try testing.expect(!allZero(&k.aes_key) and !allZero(&k.hmac_key) and !allZero(&k.iv));
    k.deinit();
    try testing.expect(allZero(&k.aes_key));
    try testing.expect(allZero(&k.hmac_key));
    try testing.expect(allZero(&k.iv));
}

test "decryptCbc refuses an empty or unaligned ciphertext with InvalidPadding" {
    var k = shim.deriveKeys(&seed);
    defer k.deinit();
    try testing.expectError(error.InvalidPadding, cipher.decryptCbc(testing.allocator, &k, &.{}));
    const odd17: [17]u8 = @splat(1);
    try testing.expectError(error.InvalidPadding, cipher.decryptCbc(testing.allocator, &k, &odd17));
    const odd31: [31]u8 = @splat(1);
    try testing.expectError(error.InvalidPadding, cipher.decryptCbc(testing.allocator, &k, &odd31));
}

// ── message codec ───────────────────────────────────────────────────────

/// `version || payload || 8 zero MAC bytes || 64 zero signature bytes`.
fn frame(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    const buf = try allocator.alloc(u8, 1 + payload.len + message.wire_mac_len + message.signature_len);
    @memset(buf, 0);
    buf[0] = message.version;
    @memcpy(buf[1..][0..payload.len], payload);
    return buf;
}

fn decodePayload(payload: []const u8) !message.Message {
    const raw = try frame(testing.allocator, payload);
    defer testing.allocator.free(raw);
    return message.Message.decode(testing.allocator, raw);
}

test "message index 0xFFFFFFFF decodes; 2^32 is VarintTooLong" {
    var m = try decodePayload(&.{ 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x12, 0x00 });
    defer m.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, 0xFFFF_FFFF), m.message_index);
    try testing.expectError(error.VarintTooLong, decodePayload(&.{ 0x08, 0x80, 0x80, 0x80, 0x80, 0x10, 0x12, 0x00 }));
}

test "a payload missing one field names the missing one" {
    try testing.expectError(error.MissingIndex, decodePayload(&.{ 0x12, 0x01, 0xAA }));
    try testing.expectError(error.MissingCiphertext, decodePayload(&.{ 0x08, 0x01 }));
}

test "a ten-byte length varint is Truncated, an eleven-byte one VarintTooLong" {
    // 2^64 - 1 as a LEB128 length: ten bytes, the largest a u64 needs.
    const ff9: [9]u8 = @splat(0xFF);
    const ff10: [10]u8 = @splat(0xFF);
    const ten = [_]u8{ 0x08, 0x00, 0x12 } ++ ff9 ++ [_]u8{0x01};
    try testing.expectError(error.Truncated, decodePayload(&ten));
    const eleven = [_]u8{ 0x08, 0x00, 0x12 } ++ ff10 ++ [_]u8{0x01};
    try testing.expectError(error.VarintTooLong, decodePayload(&eleven));
}

// ── session-key formats ─────────────────────────────────────────────────

test "ExportedSessionKey base64 round trip carries index, ratchet and signing key" {
    var threaded = testIo();
    defer threaded.deinit();
    var out = shim.outboundInit(threaded.io());
    defer out.deinit();
    var m = try out.encrypt(testing.allocator, "advance");
    m.deinit(testing.allocator);
    const key = try shim.sessionKey(&out);
    const b64 = try key.inner.toBase64(testing.allocator);
    defer testing.allocator.free(b64);
    const back = try shim.exportedFromBase64(testing.allocator, b64);
    try testing.expectEqual(@as(u32, 1), back.ratchet_index);
    try testing.expectEqualSlices(u8, &key.inner.ratchet, &back.ratchet);
    try testing.expectEqualSlices(u8, &key.inner.signing_key, &back.signing_key);
}

test "SessionKey.decode checks length, version and public key before the signature" {
    var threaded = testIo();
    defer threaded.deinit();
    var out = shim.outboundInit(threaded.io());
    defer out.deinit();
    const key = try shim.sessionKey(&out);
    const raw = shim.encodeShared(&key);

    var longer: [session_key.share_len + 1]u8 = undefined;
    @memcpy(longer[0..session_key.share_len], &raw);
    longer[session_key.share_len] = 0;
    try testing.expectError(error.WrongLength, shim.decodeShared(&longer));

    // The version byte is covered by the signature, so only the version check
    // itself can name the problem.
    var wrong_version = raw;
    wrong_version[0] = session_key.export_version;
    try testing.expectError(error.UnsupportedVersion, shim.decodeShared(&wrong_version));

    // y = 2^255 - 19 is a non-canonical point encoding: refused before the
    // signature is looked at.
    var bad_key = raw;
    bad_key[133] = 0xED;
    @memset(bad_key[134..164], 0xFF);
    bad_key[164] = 0x7F;
    try testing.expectError(error.InvalidPublicKey, shim.decodeShared(&bad_key));
}

// ── sessions ────────────────────────────────────────────────────────────

test "deinit zeroes the outbound ratchet and signing key and both inbound ratchets" {
    var threaded = testIo();
    defer threaded.deinit();
    var out = shim.outboundInit(threaded.io());
    var in = try shim.fromSessionKey(try shim.sessionKey(&out));
    var m = try out.encrypt(testing.allocator, "x");
    defer m.deinit(testing.allocator);
    var d = try in.decrypt(testing.allocator, &m);
    d.deinit(testing.allocator);
    try testing.expect(!allZero(&out.ratchet.data));
    try testing.expect(!allZero(&out.signing_key.secret_key.bytes));
    try testing.expect(!allZero(&in.initial_ratchet.data));
    try testing.expect(!allZero(&in.latest_ratchet.data));
    out.deinit();
    in.deinit();
    try testing.expect(allZero(&out.ratchet.data));
    try testing.expect(allZero(&out.signing_key.secret_key.bytes));
    try testing.expect(allZero(&in.initial_ratchet.data));
    try testing.expect(allZero(&in.latest_ratchet.data));
}

test "firstKnownIndex, forgetBefore and exportAt at their edges" {
    var threaded = testIo();
    defer threaded.deinit();
    var out = shim.outboundInit(threaded.io());
    defer out.deinit();
    var in = try shim.fromSessionKey(try shim.sessionKey(&out));
    defer in.deinit();
    var msgs: [3]message.Message = undefined;
    for (&msgs) |*m| m.* = try out.encrypt(testing.allocator, "m");
    defer for (&msgs) |*m| m.deinit(testing.allocator);

    // Decrypting a later message moves the cache, not the first known index.
    var d2 = try in.decrypt(testing.allocator, &msgs[2]);
    d2.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, 0), in.firstKnownIndex());
    var d1 = try in.decrypt(testing.allocator, &msgs[1]);
    d1.deinit(testing.allocator);

    // Forgetting up to the first known index changes nothing and says so.
    try testing.expect(!in.forgetBefore(0));
    try testing.expect(in.forgetBefore(2));
    try testing.expectEqual(@as(u32, 2), in.firstKnownIndex());
    try testing.expect(!in.forgetBefore(2));
    try testing.expect(!in.forgetBefore(1));
    try testing.expectError(error.MessageIndexTooOld, in.decrypt(testing.allocator, &msgs[1]));

    // exportAt below the first known index is unreachable and writes nothing.
    try testing.expect(shim.exportAt(&in, 1) == null);
    const at2 = shim.exportAt(&in, 2).?;
    try testing.expectEqual(@as(u32, 2), at2.ratchet_index);
}

test "decrypt reports InvalidPadding for an authentic message with badly padded plaintext" {
    var threaded = testIo();
    defer threaded.deinit();
    var out = shim.outboundInit(threaded.io());
    defer out.deinit();
    var in = try shim.fromSessionKey(try shim.sessionKey(&out));
    defer in.deinit();

    // Honest construction (the test holds the signing key, as the InvalidMac
    // test does): a correctly keyed, correctly MACed, correctly signed frame
    // whose one block decrypts to 16 zero bytes, which PKCS#7 refuses.
    var keys = shim.deriveKeys(&out.ratchet.data);
    defer keys.deinit();
    var block: [16]u8 = @splat(0);
    _ = try aescbc.encrypt(Aes256, &keys.aes_key, keys.iv, &block, &block);
    var msg: message.Message = .{
        .message_index = out.ratchet.counter,
        .ciphertext = try testing.allocator.dupe(u8, &block),
        .mac = undefined,
        .signature = undefined,
    };
    defer msg.deinit(testing.allocator);
    const mac_input = try msg.macBytes(testing.allocator);
    defer testing.allocator.free(mac_input);
    const full = cipher.fullMac(&keys.hmac_key, mac_input);
    msg.mac = full[0..message.wire_mac_len].*;
    const sig_input = try msg.signatureBytes(testing.allocator);
    defer testing.allocator.free(sig_input);
    msg.signature = (try out.signing_key.sign(sig_input, null)).toBytes();

    try testing.expectError(error.InvalidPadding, in.decrypt(testing.allocator, &msg));
}

// ── pickles ─────────────────────────────────────────────────────────────

test "a bare six-byte header is judged by magic, then kind, before its length" {
    const bad_magic = [_]u8{ 'X', 'G', 'P', 'K', pickle.version, 0x01 };
    try testing.expectError(error.BadMagic, shim.outboundFromPickle(&bad_magic));
    const inbound_kind = pickle.magic ++ [_]u8{ pickle.version, @backingInt(pickle.Kind.inbound) };
    try testing.expectError(error.WrongKind, shim.outboundFromPickle(&inbound_kind));
    const outbound_kind = pickle.magic ++ [_]u8{ pickle.version, @backingInt(pickle.Kind.outbound) };
    try testing.expectError(error.WrongKind, shim.inboundFromPickle(&outbound_kind));
    // And a header of the right kind but nothing after it is plainly short.
    try testing.expectError(error.Truncated, shim.outboundFromPickle(&outbound_kind));
}
