// SPDX-License-Identifier: MIT

//! No-panic sweep (2026-11-13): one test per finding, named "(sweep JWE-n)".

const std = @import("std");
const testing = std.testing;
const jwe = @import("root.zig");
const header = jwe.header;
const enc = jwe.enc;
const ecdhes = jwe.ecdhes;

fn seeded() jwe.Entropy {
    const S = struct {
        var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x5a)));
    };
    return .{ .fixed_for_test = S.csprng.random() };
}

test "header.encode refuses a byte member longer than max_member_len (sweep JWE-1)" {
    var buf: [header.max_header_json_len]u8 = undefined;
    const big = @as([header.max_member_len + 1]u8, @splat(7));
    const ok = @as([header.max_member_len]u8, @splat(7));
    try testing.expectError(error.BufferTooSmall, header.encode(&buf, .{ .alg = "a", .enc = "e", .iv = &big }));
    try testing.expectError(error.BufferTooSmall, header.encode(&buf, .{ .alg = "a", .enc = "e", .tag = &big }));
    try testing.expectError(error.BufferTooSmall, header.encode(&buf, .{ .alg = "a", .enc = "e", .p2s = &big }));
    try testing.expectError(error.BufferTooSmall, header.encode(&buf, .{ .alg = "a", .enc = "e", .apu = &big }));
    try testing.expectError(error.BufferTooSmall, header.encode(&buf, .{ .alg = "a", .enc = "e", .apv = &big }));
    try testing.expectError(error.BufferTooSmall, header.encode(&buf, .{ .alg = "a", .enc = "e", .epk = .{ .kty = "EC", .crv = "P-256", .x = &big } }));
    try testing.expectError(error.BufferTooSmall, header.encode(&buf, .{ .alg = "a", .enc = "e", .epk = .{ .kty = "EC", .crv = "P-256", .x = &ok, .y = &big } }));
    // The limit itself still encodes (the buffer holds all six members).
    var wide: [4096]u8 = undefined;
    _ = try header.encode(&wide, .{ .alg = "a", .enc = "e", .iv = &ok, .apu = &ok });
}

test "encryptCompact: an apu/apv longer than max_member_len is HeaderTooLarge, not a crash (sweep JWE-1)" {
    const sk = @as([32]u8, @splat(9));
    const pk: ecdhes.PublicKey = .{ .x25519 = std.crypto.dh.X25519.recoverPublicKey(sk) };
    const big = @as([header.max_member_len + 1]u8, @splat(1));
    for ([_]jwe.Alg{ .@"ECDH-ES", .@"ECDH-ES+A128KW" }) |a| {
        try testing.expectError(error.HeaderTooLarge, jwe.encryptCompact(testing.allocator, a, .A128GCM, .{ .ec_public = pk }, "x", "", seeded(), .{ .apu = &big }));
        try testing.expectError(error.HeaderTooLarge, jwe.encryptCompact(testing.allocator, a, .A128GCM, .{ .ec_public = pk }, "x", "", seeded(), .{ .apv = &big }));
    }
}

test "concatKdfSha256 with an empty output derives nothing (sweep JWE-2)" {
    const z = @as([32]u8, @splat(3));
    var none: [0]u8 = .{};
    ecdhes.concatKdfSha256(&z, "A128GCM", "", "", &none);
}

test "GCM encrypt of a message beyond 2^36 - 32 bytes is an error, not an aesgcm panic (sweep JWE-3)" {
    // A slice that is never dereferenced: the length is refused first.
    const phantom: [*]u8 = @ptrFromInt(0x10000);
    const n: usize = (1 << 36) - 31;
    const key = @as([16]u8, @splat(1));
    const iv = @as([12]u8, @splat(2));
    var tag: [16]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, enc.encrypt(.A128GCM, &key, &iv, "", phantom[0..n], phantom[0..n], &tag));
}

test "a header nested thousands of levels deep within the size cap is refused, not a stack overflow (sweep clean: header depth)" {
    const a = testing.allocator;
    const depth = 6000; // '[' x depth + ']' x depth + the object around it < 16 KiB of base64
    const json = try a.alloc(u8, depth * 2 + 16);
    defer a.free(json);
    @memcpy(json[0..6], "{\"a\":[");
    @memset(json[6..][0 .. depth - 1], '[');
    var pos: usize = 6 + depth - 1;
    @memset(json[pos..][0..depth], ']');
    pos += depth;
    json[pos] = '}';
    pos += 1;
    const b64 = std.base64.url_safe_no_pad;
    const seg = try a.alloc(u8, b64.Encoder.calcSize(pos));
    defer a.free(seg);
    _ = b64.Encoder.encode(seg, json[0..pos]);
    try testing.expect(seg.len <= header.max_header_b64_len);
    const token = try std.fmt.allocPrint(a, "{s}.AAAA.AAAA.AAAA.AAAA", .{seg});
    defer a.free(token);
    const key = @as([16]u8, @splat(1));
    const r = jwe.decryptCompact(a, .{ .symmetric = &key }, token, .{});
    try testing.expect(std.meta.isError(r));
}

test "decryptCompact: junk segments of odd lengths under every alg and enc never crash (sweep clean: decrypt shapes)" {
    const a = testing.allocator;
    const sym16 = @as([16]u8, @splat(1));
    const sym32 = @as([32]u8, @splat(1));
    const x_sk: ecdhes.PrivateKey = .{ .x25519 = @as([32]u8, @splat(9)) };
    const p_sk: ecdhes.PrivateKey = .{ .p256 = @as([32]u8, @splat(9)) };
    const b64 = std.base64.url_safe_no_pad;
    const x_pub = std.crypto.dh.X25519.recoverPublicKey(x_sk.x25519);
    var xb: [43]u8 = undefined;
    _ = b64.Encoder.encode(&xb, &x_pub);
    const junk = @as([1000]u8, @splat(0xa5));
    var junk_b64: [b64.Encoder.calcSize(1000)]u8 = undefined;
    _ = b64.Encoder.encode(&junk_b64, &junk);

    inline for (@typeInfo(jwe.Alg).@"enum".field_names) |an| {
        inline for (@typeInfo(jwe.Enc).@"enum".field_names) |en| {
            const hdr = try std.fmt.allocPrint(a, "{{\"alg\":\"{s}\",\"enc\":\"{s}\",\"iv\":\"AAAA\",\"tag\":\"AAAA\",\"p2s\":\"AAAA\",\"p2c\":0,\"epk\":{{\"crv\":\"X25519\",\"x\":\"{s}\"}}}}", .{ an, en, &xb });
            defer a.free(hdr);
            const hb = try a.alloc(u8, b64.Encoder.calcSize(hdr.len));
            defer a.free(hb);
            _ = b64.Encoder.encode(hb, hdr);
            for ([_][]const u8{ "", "A", "AAAA", &junk_b64 }) |ek| {
                for ([_][]const u8{ "", "AAAAAA", &junk_b64 }) |iv| {
                    const token = try std.fmt.allocPrint(a, "{s}.{s}.{s}.{s}.{s}", .{ hb, ek, iv, "AAAAAAAAAAAAAAAAAAAAAA", "AAA" });
                    defer a.free(token);
                    for ([_]jwe.KeyMaterial{
                        .{ .symmetric = &sym16 },
                        .{ .symmetric = &sym32 },
                        .{ .password = "pw" },
                        .{ .ec_private = &x_sk },
                        .{ .ec_private = &p_sk },
                    }) |k| {
                        if (jwe.decryptCompact(a, k, token, .{})) |pt| a.free(pt) else |_| {}
                    }
                }
            }
        }
    }
}
