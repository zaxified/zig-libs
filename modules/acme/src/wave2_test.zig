// SPDX-License-Identifier: MIT

//! Mutation run, wave 2 (2026-11-06): survivors that need no CA and no probe.

const std = @import("std");
const jws = @import("jws.zig");
const x509 = @import("x509.zig");
const storage = @import("storage.zig");
const rsa = @import("rsa");
const builtin = @import("builtin");

const testing = std.testing;
const b64 = std.base64.url_safe_no_pad;

test "wave 2: verifyEab refuses a MAC that is longer or shorter than HMAC-SHA256" {
    var kp: jws.KeyPair = undefined;
    try jws.Es256.KeyPair.generateDeterministicInto(&kp, &@as([32]u8, @splat(7)));
    const key = "0123456789abcdef0123456789abcdef";
    const good = try jws.signEab(testing.allocator, kp.public_key, "kid", key, "https://ca.example/new-acct");
    defer testing.allocator.free(good);
    var v = try jws.verifyEab(testing.allocator, good, key);
    v.deinit();

    const marker = "\"signature\":\"";
    const at = std.mem.find(u8, good, marker).? + marker.len;
    const end = std.mem.findPos(u8, good, at, "\"").?;
    var mac: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 32), try b64.Decoder.calcSizeForSlice(good[at..end]));
    try b64.Decoder.decode(mac[0..32], good[at..end]);
    mac[32] = 0; // a MAC with its right prefix and one octet too many
    for ([_]usize{ 33, 31, 16, 1 }) |n| {
        var enc: [96]u8 = undefined;
        const text = b64.Encoder.encode(&enc, mac[0..n]);
        const forged = try std.mem.concat(testing.allocator, u8, &.{ good[0..at], text, good[end..] });
        defer testing.allocator.free(forged);
        try testing.expectError(error.BadSignature, jws.verifyEab(testing.allocator, forged, key));
    }
}

test "wave 2: a malformed key DER leaves nothing in the caller's pair" {
    const pem = try x509.pemEncode(testing.allocator, "EC PRIVATE KEY", "this is not DER, but it is long enough: 0123456789");
    defer testing.allocator.free(pem);
    const pem8 = try x509.pemEncode(testing.allocator, "PRIVATE KEY", "neither is this one, 0123456789 0123456789");
    defer testing.allocator.free(pem8);

    var typed: jws.Es256.KeyPair = undefined;
    @memset(std.mem.asBytes(&typed), 0xAA);
    try testing.expectError(error.MalformedKey, x509.ecPrivateKeyFromPem(&typed, testing.allocator, pem));
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&typed), 0));

    @memset(std.mem.asBytes(&typed), 0xAA);
    try testing.expectError(error.MalformedKey, x509.pkcs8PrivateKeyFromPem(&typed, testing.allocator, pem8));
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&typed), 0));

    var any: jws.AnyKeyPair = undefined;
    @memset(std.mem.asBytes(&any), 0xAA);
    try testing.expectError(error.MalformedKey, x509.privateKeyFromPem(&any, testing.allocator, pem));
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&any), 0));
}

test "wave 2: a signature of no ECDSA length is Malformed before the kid/jwk rule is looked at" {
    // alg ES256, neither kid nor jwk (UnsupportedJws if reached), a 10-octet signature.
    var prot_b64: [128]u8 = undefined;
    const prot = b64.Encoder.encode(&prot_b64, "{\"alg\":\"ES256\",\"nonce\":\"n\",\"url\":\"https://ca.example/x\"}");
    var sig_b64: [32]u8 = undefined;
    const sig = b64.Encoder.encode(&sig_b64, "0123456789");
    var buf: [400]u8 = undefined;
    const text = try std.mem.print(&buf, "{{\"protected\":\"{s}\",\"payload\":\"\",\"signature\":\"{s}\"}}", .{ prot, sig });
    try testing.expectError(error.MalformedJws, jws.verifyFlattenedAny(testing.allocator, text, null));
}

test "wave 2: PEM output has no blank line when the base64 body fills its last line exactly" {
    const der48: [48]u8 = @splat(0x5a); // 64 base64 characters: exactly one full line
    const pem = try x509.pemEncode(testing.allocator, "TEST", &der48);
    defer testing.allocator.free(pem);
    try testing.expectEqualStrings(
        "-----BEGIN TEST-----\nWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpa\n-----END TEST-----\n",
        pem,
    );
    const der49: [49]u8 = @splat(0x5a); // 68 characters: a full line and a short one
    const pem2 = try x509.pemEncode(testing.allocator, "TEST", &der49);
    defer testing.allocator.free(pem2);
    try testing.expect(std.mem.find(u8, pem2, "\n\n") == null);
}

test "wave 2: a broken EC block with no PKCS#8 block behind it is InvalidPem, not MissingPemBlock" {
    var any: jws.AnyKeyPair = undefined;
    // A terminated EC block whose body is not base64: the EC step's own error stands.
    try testing.expectError(error.InvalidPem, x509.privateKeyFromPem(&any, testing.allocator, "-----BEGIN EC PRIVATE KEY-----\n!!!!\n-----END EC PRIVATE KEY-----\n"));
    try testing.expectError(error.MissingPemBlock, x509.privateKeyFromPem(&any, testing.allocator, "nothing here\n"));
}

/// A backend with its own `create`, counting what the interface calls.
const CreateProbe = struct {
    creates: u32 = 0,
    loads: u32 = 0,
    stores: u32 = 0,
    unlocks: u32 = 0,
    fn handle(p: *CreateProbe) storage.Storage {
        return .{ .ptr = p, .vtable = &vt };
    }
    const vt: storage.Storage.VTable = .{ .load = load, .store = store, .delete = del, .create = create, .tryLock = tryLock, .unlock = unlock };
    fn of(p: *anyopaque) *CreateProbe {
        return @ptrCast(@alignCast(p));
    }
    fn load(p: *anyopaque, _: std.mem.Allocator, _: []const u8) storage.Error![]u8 {
        of(p).loads += 1;
        return error.NotFound;
    }
    fn store(p: *anyopaque, _: []const u8, _: []const u8) storage.Error!void {
        of(p).stores += 1;
    }
    fn del(_: *anyopaque, _: []const u8) storage.Error!void {}
    fn create(p: *anyopaque, _: []const u8, _: []const u8) storage.Error!bool {
        of(p).creates += 1;
        return true;
    }
    fn tryLock(_: *anyopaque, _: []const u8, _: []const u8, _: i64, _: u32) storage.Error!bool {
        return true;
    }
    fn unlock(p: *anyopaque, _: []const u8, _: []const u8) void {
        of(p).unlocks += 1;
    }
};

test "wave 2: Storage.create uses the backend's create when it has one; unlock and tryLock refuse a bad owner" {
    var p: CreateProbe = .{};
    const s = p.handle();
    try testing.expect(try s.create(testing.allocator, "k", "v"));
    try testing.expectEqual(@as(u32, 1), p.creates);
    try testing.expectEqual(@as(u32, 0), p.loads);
    try testing.expectEqual(@as(u32, 0), p.stores);

    s.unlock("issue/x", "bad owner"); // a space is no key character: nothing reaches the backend
    s.unlock("issue/x", "a/b"); // nor is a slash
    s.unlock("issue/x", "");
    try testing.expectEqual(@as(u32, 0), p.unlocks);
    s.unlock("issue/x", "node-1");
    try testing.expectEqual(@as(u32, 1), p.unlocks);
    try testing.expectError(error.InvalidKey, s.tryLock("issue/x", "a/b", 0, 60));
    const long: [65]u8 = @splat('a');
    try testing.expectError(error.InvalidKey, s.tryLock("issue/x", &long, 0, 60));
    try testing.expect(try s.tryLock("issue/x", long[0..64], 0, 60));
}

fn rsaJwsWith(buf: []u8, n_b64: []const u8, e_b64: []const u8) ![]const u8 {
    var hdr: [2048]u8 = undefined;
    const h = try std.mem.print(&hdr, "{{\"alg\":\"RS256\",\"nonce\":\"n\",\"url\":\"u\",\"jwk\":{{\"kty\":\"RSA\",\"n\":\"{s}\",\"e\":\"{s}\"}}}}", .{ n_b64, e_b64 });
    var pb: [3000]u8 = undefined;
    const p = b64.Encoder.encode(&pb, h);
    const sig: [256]u8 = @splat(1); // one modulus long, wrong
    var sb: [400]u8 = undefined;
    const sg = b64.Encoder.encode(&sb, &sig);
    return std.mem.print(buf, "{{\"protected\":\"{s}\",\"payload\":\"\",\"signature\":\"{s}\"}}", .{ p, sg });
}

fn between(text: []const u8, open: []const u8) []const u8 {
    const at = std.mem.find(u8, text, open).? + open.len;
    return text[at..std.mem.findPos(u8, text, at, "\"").?];
}

test "wave 2: an RSA JWK with an empty or zero-led n or e is Malformed; the same key with a wrong signature is BadSignature; keys differing in e are not equal" {
    const kp = try testing.allocator.create(rsa.KeyPair);
    defer {
        std.crypto.secureZero(u8, std.mem.asBytes(kp));
        testing.allocator.destroy(kp);
    }
    try x509.rsaPrivateKeyFromPem(kp, x509.test_rsa_pkcs1_pem);
    var jwk_buf: [jws.max_canonical_jwk_len]u8 = undefined;
    const r = jws.canonicalJwk(&jwk_buf, kp.public_key);
    const jwk = if (comptime @typeInfo(@TypeOf(r)) == .error_union) try r else r;
    const n_b64 = between(jwk, "\"n\":\"");
    const e_b64 = between(jwk, "\"e\":\"");

    var n_bytes: [rsa.max_modulus_len + 1]u8 = undefined;
    n_bytes[0] = 0;
    const n_len = try b64.Decoder.calcSizeForSlice(n_b64);
    try b64.Decoder.decode(n_bytes[1..][0..n_len], n_b64);
    var n_zero_b64: [1500]u8 = undefined;
    const n_zero = b64.Encoder.encode(&n_zero_b64, n_bytes[0 .. n_len + 1]);

    var buf: [8192]u8 = undefined;
    try testing.expectError(error.BadSignature, jws.verifyFlattenedAny(testing.allocator, try rsaJwsWith(&buf, n_b64, e_b64), null)); // control
    try testing.expectError(error.MalformedJws, jws.verifyFlattenedAny(testing.allocator, try rsaJwsWith(&buf, "", e_b64), null));
    try testing.expectError(error.MalformedJws, jws.verifyFlattenedAny(testing.allocator, try rsaJwsWith(&buf, n_b64, ""), null));
    try testing.expectError(error.MalformedJws, jws.verifyFlattenedAny(testing.allocator, try rsaJwsWith(&buf, n_zero, e_b64), null));
    try testing.expectError(error.MalformedJws, jws.verifyFlattenedAny(testing.allocator, try rsaJwsWith(&buf, n_b64, "AAEAAQ"), null));

    // Same modulus, another exponent: not the same key.
    const a = try rsa.VerifyKey.fromBytes(n_bytes[1..][0..n_len], &.{ 1, 0, 1 });
    const same = try rsa.VerifyKey.fromBytes(n_bytes[1..][0..n_len], &.{ 1, 0, 1 });
    const b = try rsa.VerifyKey.fromBytes(n_bytes[1..][0..n_len], &.{3});
    try testing.expect((jws.AnyPublicKey{ .rs256 = a }).eql(.{ .rs256 = same }));
    try testing.expect(!(jws.AnyPublicKey{ .rs256 = a }).eql(.{ .rs256 = b }));
}

test "wave 2: RSA key sizes at the edges: the PEM reader and the CSR parser take 2048..4096 bits and nothing outside" {
    // Prime searches at 4096 bits take seconds: optimized modes only.
    if (builtin.mode == .debug or builtin.mode == .safe) return error.SkipZigTest;
    const kp = try testing.allocator.create(rsa.KeyPair);
    defer {
        std.crypto.secureZero(u8, std.mem.asBytes(kp));
        testing.allocator.destroy(kp);
    }
    const back = try testing.allocator.create(rsa.KeyPair);
    defer {
        std.crypto.secureZero(u8, std.mem.asBytes(back));
        testing.allocator.destroy(back);
    }
    const names: []const []const u8 = &.{"rsa.example"};
    var prng = std.Random.DefaultPrng.init(0x4096);
    for ([_]struct { bits: u16, ok: bool }{ .{ .bits = 1024, .ok = false }, .{ .bits = 4096, .ok = true }, .{ .bits = 4104, .ok = false } }) |c| {
        rsa.generate(kp, prng.random(), c.bits, 65537) catch unreachable;
        const pem = try x509.rsaPrivateKeyToPem(testing.allocator, kp);
        defer {
            std.crypto.secureZero(u8, pem);
            testing.allocator.free(pem);
        }
        if (c.ok) {
            try x509.rsaPrivateKeyFromPem(back, pem);
            try testing.expectEqual(@as(usize, c.bits), back.public_key.bits());
        } else {
            try testing.expectError(error.MalformedKey, x509.rsaPrivateKeyFromPem(back, pem));
        }
        var any: jws.AnyKeyPair = .{ .rs256 = kp };
        const der = try x509.csrDer(testing.allocator, &any, names);
        defer testing.allocator.free(der);
        if (c.ok) {
            var parsed = try x509.parseCsrAny(testing.allocator, der);
            parsed.deinit();
        } else {
            try testing.expectError(error.UnsupportedCsr, x509.parseCsrAny(testing.allocator, der));
        }
    }
}
