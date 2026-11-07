// SPDX-License-Identifier: MIT

//! `secure.zig` against cookie-rs-format vectors computed by pyca/cryptography
//! (`secure_vectors.zig`, `tools/secure_vectors.py`), plus the refusals no
//! vector can show: wrong name, wrong key, every tampered byte, truncation,
//! a bound value under the cookie-rs format and back, short buffers.

const std = @import("std");
const testing = std.testing;
const secure = @import("secure.zig");
const vectors = @import("secure_vectors.zig");
const root = @import("root.zig");
const Key = secure.Key;

fn vectorKey() Key {
    var k: Key = undefined;
    Key.fromBytesInto(&k, &vectors.derive[0].key) catch unreachable;
    return k;
}

fn otherKey(label: []const u8) Key {
    var m: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &m, .{});
    var k: Key = undefined;
    Key.deriveInto(&k, &m) catch unreachable;
    return k;
}

test "Key.deriveInto: cookie-rs derive_from (HKDF-SHA256 Expand) for 32..100-byte masters" {
    for (vectors.derive) |v| {
        var k: Key = undefined;
        try Key.deriveInto(&k, v.master);
        try testing.expectEqualSlices(u8, v.key[0..32], &k.signing);
        try testing.expectEqualSlices(u8, v.key[32..64], &k.encryption);
    }
    var k: Key = undefined;
    try testing.expectError(error.KeyTooShort, Key.deriveInto(&k, &@as([31]u8, @splat(1))));
    try testing.expectError(error.KeyTooShort, Key.fromBytesInto(&k, &@as([63]u8, @splat(1))));
    // fromBytesInto: first 32 sign, next 32 encrypt, the rest ignored.
    var bytes: [70]u8 = undefined;
    for (&bytes, 0..) |*b, i| b.* = @intCast(i);
    try Key.fromBytesInto(&k, &bytes);
    try testing.expectEqualSlices(u8, bytes[0..32], &k.signing);
    try testing.expectEqualSlices(u8, bytes[32..64], &k.encryption);
    k.wipe();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&k), 0));
}

test "signed: sign reproduces both formats byte for byte; verify returns the value" {
    const k = vectorKey();
    var buf: [2048]u8 = undefined;
    for (vectors.signed) |v| {
        const b = try secure.signed.sign(&k, v.name, v.value, &buf, .{});
        try testing.expectEqualStrings(v.bound, b);
        try testing.expectEqual(secure.signed.len(v.value.len), b.len);
        try testing.expectEqualStrings(v.value, secure.signed.verify(&.{k}, v.name, v.bound, .{}).?);

        const c = try secure.signed.sign(&k, v.name, v.value, &buf, .{ .format = .cookie_rs });
        try testing.expectEqualStrings(v.cookie_rs, c);
        try testing.expectEqualStrings(v.value, secure.signed.verify(&.{k}, v.name, v.cookie_rs, .{ .format = .cookie_rs }).?);
        // cookie-rs does not bind the name: any name verifies.
        try testing.expect(secure.signed.verify(&.{k}, "other", v.cookie_rs, .{ .format = .cookie_rs }) != null);
        // The two formats never accept each other's values.
        try testing.expect(secure.signed.verify(&.{k}, v.name, v.cookie_rs, .{}) == null);
        try testing.expect(secure.signed.verify(&.{k}, v.name, v.bound, .{ .format = .cookie_rs }) == null);
        // Bound: another name, a prefix/suffix of the name, refused.
        try testing.expect(secure.signed.verify(&.{k}, "other", v.bound, .{}) == null);
        try testing.expect(secure.signed.verify(&.{k}, v.name[0 .. v.name.len - 1], v.bound, .{}) == null);
    }
}

test "signed: every single-byte change, truncation, extension and foreign key is refused" {
    const k = vectorKey();
    const other = otherKey("other");
    var buf: [256]u8 = undefined;
    const v = vectors.signed[3];
    @memcpy(buf[0..v.bound.len], v.bound);
    const s = buf[0..v.bound.len];
    for (0..s.len) |i| {
        const orig = s[i];
        s[i] ^= 0x01;
        try testing.expect(secure.signed.verify(&.{k}, v.name, s, .{}) == null);
        s[i] = orig;
    }
    try testing.expect(secure.signed.verify(&.{k}, v.name, s, .{}) != null);
    for (0..s.len) |n| try testing.expect(secure.signed.verify(&.{k}, v.name, s[0..n], .{}) == null);
    buf[s.len] = 'x';
    try testing.expect(secure.signed.verify(&.{k}, v.name, buf[0 .. s.len + 1], .{}) == null);
    try testing.expect(secure.signed.verify(&.{other}, v.name, s, .{}) == null);
    // 44 tag characters with no padding decode to 33 bytes: refused, not an
    // out-of-bounds write (the fuzz harness's first find).
    var unpadded: [v.bound.len]u8 = undefined;
    @memcpy(&unpadded, s);
    try testing.expectEqual('=', unpadded[43]);
    unpadded[43] = 'A';
    try testing.expect(secure.signed.verify(&.{k}, v.name, &unpadded, .{}) == null);
    try testing.expect(secure.signed.verify(&.{}, v.name, s, .{}) == null);
}

test "signed: key rotation accepts any listed key, in any position" {
    const k = vectorKey();
    const a = otherKey("a");
    const b = otherKey("b");
    const v = vectors.signed[2];
    try testing.expect(secure.signed.verify(&.{ a, b, k }, v.name, v.bound, .{}) != null);
    try testing.expect(secure.signed.verify(&.{ k, a }, v.name, v.bound, .{}) != null);
    try testing.expect(secure.signed.verify(&.{ a, b }, v.name, v.bound, .{}) == null);
}

test "signed: refuses a value that is not cookie-octets, and a short buffer" {
    const k = vectorKey();
    var buf: [128]u8 = undefined;
    for ([_][]const u8{ "a b", "a;b", "a,b", "\"q\"", "a\\b", "\x7f", "\xc3\xa9", "\n" }) |bad|
        try testing.expectError(error.InvalidValue, secure.signed.sign(&k, "n", bad, &buf, .{}));
    try testing.expectError(error.NoSpaceLeft, secure.signed.sign(&k, "n", "abc", buf[0 .. secure.signed.len(3) - 1], .{}));
    _ = try secure.signed.sign(&k, "n", "abc", buf[0..secure.signed.len(3)], .{});
}

test "private: seal reproduces cookie-rs PrivateJar values; open returns the plaintext" {
    const k = vectorKey();
    var buf: [4096]u8 = undefined;
    var plain: [4096]u8 = undefined;
    for (vectors.private) |v| {
        const s = try secure.private.seal(&k, v.name, v.value, v.nonce, &buf);
        try testing.expectEqualStrings(v.sealed, s);
        try testing.expectEqual(secure.private.len(v.value.len), s.len);
        const p = secure.private.open(&.{k}, v.name, v.sealed, &plain).?;
        try testing.expectEqualSlices(u8, v.value, p);
        // The name is the AD: another name never opens it.
        try testing.expect(secure.private.open(&.{k}, "other", v.sealed, &plain) == null);
        // openBufLen is enough; the decoded length is the exact minimum.
        const exact = v.value.len + secure.private.overhead;
        try testing.expect(secure.private.openBufLen(v.sealed.len) >= exact);
        try testing.expect(secure.private.open(&.{k}, v.name, v.sealed, plain[0..secure.private.openBufLen(v.sealed.len)]) != null);
        try testing.expect(secure.private.open(&.{k}, v.name, v.sealed, plain[0..exact]) != null);
        try testing.expect(secure.private.open(&.{k}, v.name, v.sealed, plain[0 .. exact - 1]) == null);
        // A sealed value is a valid cookie value.
        var line: [4200]u8 = undefined;
        if (v.name.len + s.len <= 4096 and !std.mem.startsWith(u8, v.name, "__Host-"))
            _ = try (root.SetCookie{ .name = v.name, .value = s }).bufPrint(&line);
    }
}

test "private: every flipped bit of the decoded record, truncation and foreign key are refused" {
    const k = vectorKey();
    const other = otherKey("other");
    const v = vectors.private[2];
    var raw: [64]u8 = undefined;
    const raw_len = try std.base64.standard.Decoder.calcSizeForSlice(v.sealed);
    try std.base64.standard.Decoder.decode(raw[0..raw_len], v.sealed);
    var enc: [96]u8 = undefined;
    var plain: [96]u8 = undefined;
    for (0..raw_len * 8) |bit| {
        raw[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        const s = std.base64.standard.Encoder.encode(&enc, raw[0..raw_len]);
        try testing.expect(secure.private.open(&.{k}, v.name, s, &plain) == null);
        // On refusal no plaintext is left in `out`.
        try testing.expect(std.mem.allEqual(u8, plain[0..raw_len], 0));
        raw[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
    }
    for (0..raw_len) |n| {
        const s = std.base64.standard.Encoder.encode(&enc, raw[0..n]);
        try testing.expect(secure.private.open(&.{k}, v.name, s, &plain) == null);
    }
    try testing.expect(secure.private.open(&.{other}, v.name, v.sealed, &plain) == null);
    try testing.expect(secure.private.open(&.{}, v.name, v.sealed, &plain) == null);
    // Not base64 / bad padding / non-canonical trailing bits.
    for ([_][]const u8{ "", "!!!!", "AAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=", v.sealed[1..] }) |bad|
        try testing.expect(secure.private.open(&.{k}, v.name, bad, &plain) == null);
}

test "private: key rotation, and a failed key does not spoil the next one" {
    const k = vectorKey();
    const a = otherKey("a");
    const b = otherKey("b");
    var plain: [4096]u8 = undefined;
    for (vectors.private) |v| {
        try testing.expectEqualSlices(u8, v.value, secure.private.open(&.{ a, b, k }, v.name, v.sealed, &plain).?);
        try testing.expectEqualSlices(u8, v.value, secure.private.open(&.{ k, a }, v.name, v.sealed, &plain).?);
        try testing.expect(secure.private.open(&.{ a, b }, v.name, v.sealed, &plain) == null);
    }
}

test "private: sealRandom round trip, fresh nonce each time; short buffers" {
    const io = testing.io;
    var k: Key = undefined;
    try Key.generateInto(&k, io);
    defer k.wipe();
    var b1: [128]u8 = undefined;
    var b2: [128]u8 = undefined;
    var plain: [128]u8 = undefined;
    const s1 = try secure.private.sealRandom(io, &k, "sid", "user=42", &b1);
    const s2 = try secure.private.sealRandom(io, &k, "sid", "user=42", &b2);
    try testing.expect(!std.mem.eql(u8, s1, s2));
    try testing.expectEqualStrings("user=42", secure.private.open(&.{k}, "sid", s1, &plain).?);
    try testing.expectEqualStrings("user=42", secure.private.open(&.{k}, "sid", s2, &plain).?);
    try testing.expectError(error.NoSpaceLeft, secure.private.seal(&k, "sid", "user=42", @splat(0), b1[0 .. secure.private.len(7) - 1]));
    // A larger `out` is fine: the value is its prefix.
    const s3 = try secure.private.seal(&k, "sid", "", @splat(7), &b1);
    try testing.expectEqual(secure.private.len(0), s3.len);
    try testing.expectEqualStrings("", secure.private.open(&.{k}, "sid", s3, &plain).?);
}

test "private: seal over every length 0..200 round-trips (the in-place base64 encoder)" {
    const k = vectorKey();
    var value: [200]u8 = undefined;
    for (&value, 0..) |*c, i| c.* = @truncate(i *% 131 +% 7);
    var buf: [400]u8 = undefined;
    var plain: [400]u8 = undefined;
    var ref: [400]u8 = undefined;
    for (0..value.len + 1) |n| {
        const nonce: [12]u8 = @splat(@truncate(n));
        const s = try secure.private.seal(&k, "n", value[0..n], nonce, &buf);
        // Reference: the same record encoded out of place.
        var raw: [300]u8 = undefined;
        @memcpy(raw[0..12], &nonce);
        const Aes = @import("aesgcm").Aes256Gcm;
        Aes.encrypt(raw[12..][0..n], raw[12 + n ..][0..16], value[0..n], "n", nonce, k.encryption);
        try testing.expectEqualStrings(std.base64.standard.Encoder.encode(&ref, raw[0 .. n + 28]), s);
        try testing.expectEqualSlices(u8, value[0..n], secure.private.open(&.{k}, "n", s, &plain).?);
    }
}

test "signed timed: round trip, the max-age edge, future issue, and every refusal" {
    const k = vectorKey();
    var buf: [256]u8 = undefined;
    const t0: i64 = 1_760_000_000;
    const s = try secure.signed.signTimed(&k, "sid", "user=42", t0, &buf);
    try testing.expectEqual(secure.signed.timedLen(7, t0), s.len);
    try testing.expect(std.mem.endsWith(u8, s, "1760000000|user=42"));
    try testing.expectEqualStrings("user=42", secure.signed.verifyTimed(&.{k}, "sid", s, t0 + 3600, 3600).?);
    try testing.expect(secure.signed.verifyTimed(&.{k}, "sid", s, t0 + 3601, 3600) == null);
    try testing.expect(secure.signed.verifyTimed(&.{k}, "sid", s, t0 - 100, 3600) != null); // issued "in the future"
    try testing.expect(secure.signed.verifyTimed(&.{k}, "other", s, t0, 3600) == null);
    // Timed and untimed never accept each other's values.
    try testing.expect(secure.signed.verify(&.{k}, "sid", s, .{}) == null);
    try testing.expect(secure.signed.verify(&.{k}, "sid", s, .{ .format = .cookie_rs }) == null);
    const plain = try secure.signed.sign(&k, "sid", "1760000000|user=42", buf[128..], .{});
    try testing.expect(secure.signed.verifyTimed(&.{k}, "sid", plain, t0, 3600) == null);
    // A changed issue time (to look fresh) breaks the MAC.
    var forged: [256]u8 = undefined;
    @memcpy(forged[0..s.len], s);
    forged[44 + 3] = '9';
    try testing.expect(secure.signed.verifyTimed(&.{k}, "sid", forged[0..s.len], t0 + 1_000_000_000, 3600) == null);
    // Negative and extreme issue times round-trip; overflowing ages refuse.
    for ([_]i64{ 0, -5, std.math.minInt(i64), std.math.maxInt(i64) }) |t| {
        const v = try secure.signed.signTimed(&k, "a", "x", t, &buf);
        const got = secure.signed.verifyTimed(&.{k}, "a", v, t, 0);
        try testing.expectEqualStrings("x", got.?);
    }
    const old = try secure.signed.signTimed(&k, "a", "x", std.math.minInt(i64), &buf);
    try testing.expect(secure.signed.verifyTimed(&.{k}, "a", old, std.math.maxInt(i64), std.math.maxInt(i64)) == null);
    try testing.expectError(error.NoSpaceLeft, secure.signed.signTimed(&k, "a", "x", t0, buf[0 .. secure.signed.timedLen(1, t0) - 1]));
    try testing.expectError(error.InvalidValue, secure.signed.signTimed(&k, "a", "x y", t0, &buf));
}

test "private timed: round trip, the max-age edge, domain separation, rotation" {
    const k = vectorKey();
    const other = otherKey("other");
    var buf: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const t0: i64 = 1_760_000_000;
    var sb: [128]u8 = undefined;
    const s = try secure.private.sealTimedNonce(&k, "sid", "user=42", t0, @splat(3), &sb);
    try testing.expectEqual(secure.private.timedLen(7), s.len);
    try testing.expectEqualStrings("user=42", secure.private.openTimed(&.{ other, k }, "sid", s, t0 + 60, 60, &plain).?);
    try testing.expect(secure.private.openTimed(&.{k}, "sid", s, t0 + 61, 60, &plain) == null);
    try testing.expect(std.mem.allEqual(u8, plain[0 .. secure.private.overhead + 8 + 7], 0)); // no plaintext left
    try testing.expect(secure.private.openTimed(&.{k}, "other", s, t0, 60, &plain) == null);
    try testing.expect(secure.private.openTimed(&.{other}, "sid", s, t0, 60, &plain) == null);
    // Timed never opens as untimed (the AD differs) and back.
    try testing.expect(secure.private.open(&.{k}, "sid", s, &plain) == null);
    var ts: [8]u8 = undefined;
    std.mem.writeInt(i64, &ts, t0, .big);
    const untimed = try secure.private.seal(&k, "sid", &(ts ++ "user=42".*), @splat(3), &buf);
    try testing.expect(secure.private.openTimed(&.{k}, "sid", untimed, t0, 60, &plain) == null);
    // Name length bound for the AD buffer.
    const long_name: [secure.private.max_timed_name + 1]u8 = @splat('n');
    try testing.expectError(error.InvalidValue, secure.private.sealTimedNonce(&k, &long_name, "v", t0, @splat(0), &buf));
    try testing.expect(secure.private.openTimed(&.{k}, &long_name, s, t0, 60, &plain) == null);
    const max_name: [secure.private.max_timed_name]u8 = @splat('n');
    const s2 = try secure.private.sealTimedNonce(&k, &max_name, "v", t0, @splat(0), &buf);
    try testing.expectEqualStrings("v", secure.private.openTimed(&.{k}, &max_name, s2, t0, 0, &plain).?);
    // sealTimed draws its own nonce.
    var b2: [256]u8 = undefined;
    const r1 = try secure.private.sealTimed(testing.io, &k, "sid", "v", t0, &b2);
    try testing.expectEqualStrings("v", secure.private.openTimed(&.{k}, "sid", r1, t0, 0, &plain).?);
    // Every flipped bit of a timed record is refused.
    var raw: [64]u8 = undefined;
    const raw_len = try std.base64.standard.Decoder.calcSizeForSlice(s);
    try std.base64.standard.Decoder.decode(raw[0..raw_len], s);
    var enc: [96]u8 = undefined;
    for (0..raw_len * 8) |bit| {
        raw[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        try testing.expect(secure.private.openTimed(&.{k}, "sid", std.base64.standard.Encoder.encode(&enc, raw[0..raw_len]), t0, 60, &plain) == null);
        raw[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
    }
}

// ── audit 2026-10-23: tests asked for by mutation survivors ──────────────────

test "private timed: an exact-size out buffer is enough, sealTimed draws a fresh nonce" {
    const k = vectorKey();
    const t0: i64 = 1_760_000_000;
    var sb: [128]u8 = undefined;
    var s1b: [128]u8 = undefined;
    var s2b: [128]u8 = undefined;
    const s = try secure.private.sealTimedNonce(&k, "sid", "user=42", t0, @splat(3), &sb);
    // The decoded size is the exact minimum the doc promises (`openBufLen` is
    // only an upper bound of it); one byte less is refused.
    const raw_len = try std.base64.standard.Decoder.calcSizeForSlice(s);
    var plain: [128]u8 = undefined;
    try testing.expectEqualStrings("user=42", secure.private.openTimed(&.{k}, "sid", s, t0, 60, plain[0..raw_len]).?);
    try testing.expect(secure.private.openTimed(&.{k}, "sid", s, t0, 60, plain[0 .. raw_len - 1]) == null);
    // Same for the untimed form.
    const u = try secure.private.seal(&k, "sid", "user=42", @splat(3), &sb);
    const u_len = try std.base64.standard.Decoder.calcSizeForSlice(u);
    try testing.expectEqualStrings("user=42", secure.private.open(&.{k}, "sid", u, plain[0..u_len]).?);
    try testing.expect(secure.private.open(&.{k}, "sid", u, plain[0 .. u_len - 1]) == null);
    // Two sealTimed of one input differ (a fixed nonce would repeat under one key).
    const r1 = try secure.private.sealTimed(testing.io, &k, "sid", "v", t0, &s1b);
    const r2 = try secure.private.sealTimed(testing.io, &k, "sid", "v", t0, &s2b);
    try testing.expect(!std.mem.eql(u8, r1, r2));
}

test "private: an empty plaintext opens, timed and untimed" {
    const k = vectorKey();
    var b: [128]u8 = undefined;
    var plain: [128]u8 = undefined;
    const t0: i64 = 1_760_000_000;
    const e = try secure.private.seal(&k, "sid", "", @splat(1), &b);
    try testing.expectEqual(@as(usize, 0), secure.private.open(&.{k}, "sid", e, &plain).?.len);
    const et = try secure.private.sealTimedNonce(&k, "sid", "", t0, @splat(1), &b);
    try testing.expectEqual(@as(usize, 0), secure.private.openTimed(&.{k}, "sid", et, t0, 0, &plain).?.len);
    const st = try secure.signed.signTimed(&k, "sid", "", t0, &b);
    try testing.expectEqual(@as(usize, 0), secure.signed.verifyTimed(&.{k}, "sid", st, t0, 0).?.len);
    const sn = try secure.signed.sign(&k, "sid", "", &b, .{});
    try testing.expectEqual(@as(usize, 0), secure.signed.verify(&.{k}, "sid", sn, .{}).?.len);
}

// ── mutation run 2026-11-07: pins the survivors of the whole-module run ──

const b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

test "signed and private: non-canonical base64 (non-zero trailing bits) is refused" {
    const k = vectorKey();
    var buf: [128]u8 = undefined;
    // Signed: the 43rd tag character carries 4 data bits and 2 trailing zeros.
    const s = try secure.signed.sign(&k, "n", "v", &buf, .{});
    const ix = std.mem.indexOfScalar(u8, b64_alphabet, s[42]).?;
    try testing.expectEqual(@as(usize, 0), ix & 3);
    var forged: [128]u8 = undefined;
    @memcpy(forged[0..s.len], s);
    try testing.expect(secure.signed.verify(&.{k}, "n", forged[0..s.len], .{}) != null);
    for (1..4) |d| {
        forged[42] = b64_alphabet[ix + d];
        try testing.expect(secure.signed.verify(&.{k}, "n", forged[0..s.len], .{}) == null);
    }
    // Private, 28 raw bytes (empty plaintext) -> `..==`: the last data
    // character has 4 trailing zero bits.
    const nonce: [12]u8 = @splat(5);
    var plain: [64]u8 = undefined;
    var sealed_buf: [64]u8 = undefined;
    const e = try secure.private.seal(&k, "n", "", nonce, &sealed_buf);
    try testing.expectEqual(@as(usize, 40), e.len);
    try testing.expectEqualStrings("==", e[38..]);
    var alt: [64]u8 = undefined;
    @memcpy(alt[0..e.len], e);
    const ie = std.mem.indexOfScalar(u8, b64_alphabet, e[37]).?;
    try testing.expectEqual(@as(usize, 0), ie & 15);
    for (1..16) |d| {
        alt[37] = b64_alphabet[ie + d];
        try testing.expect(secure.private.open(&.{k}, "n", alt[0..e.len], &plain) == null);
    }
    // 29 raw bytes -> `...=`: 2 trailing zero bits.
    var sealed_buf2: [64]u8 = undefined;
    const e1 = try secure.private.seal(&k, "n", "x", nonce, &sealed_buf2);
    try testing.expectEqualStrings("=", e1[39..]);
    @memcpy(alt[0..e1.len], e1);
    const ix1 = std.mem.indexOfScalar(u8, b64_alphabet, e1[38]).?;
    try testing.expectEqual(@as(usize, 0), ix1 & 3);
    for (1..4) |d| {
        alt[38] = b64_alphabet[ix1 + d];
        try testing.expect(secure.private.open(&.{k}, "n", alt[0..e1.len], &plain) == null);
    }
}

test "exact-size outputs: seal, signTimed and sealTimed fit exactly, one byte less is NoSpaceLeft" {
    const k = vectorKey();
    const nonce: [12]u8 = @splat(7);
    var buf: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const n = secure.private.len(5);
    const s = try secure.private.seal(&k, "n", "hello", nonce, buf[0..n]);
    try testing.expectEqualStrings("hello", secure.private.open(&.{k}, "n", s, &plain).?);
    try testing.expectError(error.NoSpaceLeft, secure.private.seal(&k, "n", "hello", nonce, buf[0 .. n - 1]));

    const t: i64 = 1_760_000_000;
    const tn = secure.signed.timedLen(5, t);
    const ts = try secure.signed.signTimed(&k, "n", "hello", t, buf[0..tn]);
    try testing.expectEqualStrings("hello", secure.signed.verifyTimed(&.{k}, "n", ts, t, 10).?);

    const sn = secure.private.timedLen(5);
    const ss = try secure.private.sealTimedNonce(&k, "n", "hello", t, nonce, buf[0..sn]);
    try testing.expectEqualStrings("hello", secure.private.openTimed(&.{k}, "n", ss, t, 10, &plain).?);
    try testing.expectError(error.NoSpaceLeft, secure.private.sealTimedNonce(&k, "n", "hello", t, nonce, buf[0 .. sn - 1]));
}

test "signTimed: the value may already sit inside `out`, overlapping its final place" {
    const k = vectorKey();
    const t: i64 = 1_760_000_000;
    var buf: [128]u8 = undefined;
    // total = 44 + 10 + 1 + 9 = 64: the value moves to buf[55..64] from buf[50..59].
    @memcpy(buf[50..59], "abcdefghi");
    const s = try secure.signed.signTimed(&k, "n", buf[50..59], t, &buf);
    try testing.expectEqual(@as(usize, 64), s.len);
    try testing.expectEqualStrings("abcdefghi", secure.signed.verifyTimed(&.{k}, "n", s, t, 10).?);
}

test "seal: a value right before or after the record, and an empty one inside it, do not overlap it" {
    const k = vectorKey();
    const nonce: [12]u8 = @splat(3);
    var buf: [128]u8 = undefined;
    var plain: [128]u8 = undefined;
    // 14 bytes seal to 56 characters, the record being the last 42: the value
    // ends exactly where the record starts.
    try testing.expectEqual(@as(usize, 56), secure.private.len(14));
    @memcpy(buf[0..14], "0123456789abcd");
    const before = try secure.private.seal(&k, "n", buf[0..14], nonce, buf[0..56]);
    try testing.expectEqualStrings("0123456789abcd", secure.private.open(&.{k}, "n", before, &plain).?);
    // ... and starts exactly where the output ends.
    @memcpy(buf[56..70], "0123456789abcd");
    const after = try secure.private.seal(&k, "n", buf[56..70], nonce, buf[0..56]);
    try testing.expectEqualStrings("0123456789abcd", secure.private.open(&.{k}, "n", after, &plain).?);
    // An empty value is nowhere: even one whose address lies in the record.
    const empty = try secure.private.seal(&k, "n", buf[30..30], nonce, buf[0..40]);
    try testing.expectEqual(@as(usize, 0), secure.private.open(&.{k}, "n", empty, &plain).?.len);
}

test "seal, sealTimedNonce: a value overlapping the record's tail by one byte is NoSpaceLeft" {
    // Pins the overlap guards of both entry points (former panics, mutants
    // 723 and 742 of the 2026-11-07 run): without them the raw record would
    // be built over the plaintext it is reading.
    const k = vectorKey();
    const nonce: [12]u8 = @splat(3);
    var buf: [160]u8 = undefined;
    // 14 bytes seal to 56 characters, the raw record being buf[14..56].
    @memcpy(buf[1..15], "0123456789abcd");
    try testing.expectError(error.NoSpaceLeft, secure.private.seal(&k, "n", buf[1..15], nonce, buf[0..56]));
    @memcpy(buf[55..69], "0123456789abcd");
    try testing.expectError(error.NoSpaceLeft, secure.private.seal(&k, "n", buf[55..69], nonce, buf[0..56]));
    // Timed: the raw record (nonce, issued, value, tag = 12 + 8 + 14 + 16) is the
    // last 50 bytes of the encoded length.
    const t: i64 = 1_760_000_000;
    const tl = secure.private.timedLen(14);
    const start = tl - 50;
    @memcpy(buf[start - 13 .. start + 1], "0123456789abcd");
    try testing.expectError(error.NoSpaceLeft, secure.private.sealTimedNonce(&k, "n", buf[start - 13 .. start + 1], t, nonce, buf[0..tl]));
    @memcpy(buf[tl - 1 .. tl + 13], "0123456789abcd");
    try testing.expectError(error.NoSpaceLeft, secure.private.sealTimedNonce(&k, "n", buf[tl - 1 .. tl + 13], t, nonce, buf[0..tl]));
    // One byte further away, both seal.
    @memcpy(buf[0..14], "0123456789abcd");
    _ = try secure.private.seal(&k, "n", buf[0..14], nonce, buf[0..56]);
}

test "openTimed: every shorter-than-a-record input is refused without touching the arithmetic" {
    const k = vectorKey();
    var raw: [64]u8 = @splat(0x41);
    var enc: [96]u8 = undefined;
    var plain: [96]u8 = undefined;
    for (0..raw.len) |n| {
        const s = std.base64.standard.Encoder.encode(&enc, raw[0..n]);
        try testing.expect(secure.private.openTimed(&.{k}, "n", s, 0, 10, &plain) == null);
        try testing.expect(secure.private.open(&.{k}, "n", s, &plain) == null);
    }
}

test "private: after a successful open the rest of `out` (nonce and tag bytes) is zero" {
    const k = vectorKey();
    const v = vectors.private[2];
    var plain: [96]u8 = @splat(0xff);
    const raw_len = try std.base64.standard.Decoder.calcSizeForSlice(v.sealed);
    const got = secure.private.open(&.{k}, v.name, v.sealed, &plain).?;
    try testing.expectEqual(raw_len - 28, got.len);
    try testing.expect(std.mem.allEqual(u8, plain[got.len..raw_len], 0));
}
