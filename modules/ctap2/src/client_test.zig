// SPDX-License-Identifier: MIT
//! Behaviour tests for the command layer: status mapping through the client,
//! malformed and hostile responses, token-length rules, validation before any
//! I/O, transport failures. (Byte-exactness against python-fido2 lives in
//! `oracle_test.zig`.)

const std = @import("std");
const cbor = @import("cbor");
const ctap2pin = @import("ctap2pin");
const framing = @import("framing.zig");
const status = @import("status.zig");
const clientpin = @import("clientpin.zig");
const getinfo = @import("getinfo.zig");
const testutil = @import("testutil.zig");

const testing = std.testing;
const a = testing.allocator;
const Value = cbor.Value;
const MapEntry = cbor.MapEntry;

const platform_scalar: [32]u8 = .{ 0x47, 0xbb, 0xb5, 0x64, 0x78, 0xbe, 0x49, 0x2d, 0xd1, 0xda, 0xb6, 0xa5, 0xea, 0x00, 0xd3, 0x7b, 0x17, 0x8a, 0x07, 0x83, 0x63, 0x65, 0x2d, 0x04, 0x02, 0x79, 0x7a, 0xaa, 0xa0, 0xdf, 0x60, 0x3f };
const auth_scalar: [32]u8 = .{ 0x4f, 0x4d, 0x86, 0xa2, 0xe5, 0x42, 0x3b, 0x2f, 0x3f, 0xf5, 0x75, 0x29, 0x16, 0x5e, 0xc6, 0xb6, 0xce, 0x75, 0x44, 0x58, 0x5b, 0xe1, 0x6e, 0x32, 0x42, 0xa6, 0x75, 0xbf, 0xb1, 0xeb, 0x68, 0x55 };

fn enc(v: Value) ![]u8 {
    return cbor.encode(a, v, .{ .canonical = true });
}

/// `00 || CBOR {1: COSE_Key}` with the given key-map entries.
fn keyResp(entries: []const MapEntry) ![]u8 {
    const inner = [_]MapEntry{.{ .key = .{ .uint = 1 }, .value = .{ .map = entries } }};
    const body = try enc(.{ .map = &inner });
    defer a.free(body);
    return prependStatus(0, body);
}

fn prependStatus(code: u8, body: []const u8) ![]u8 {
    const out = try a.alloc(u8, body.len + 1);
    out[0] = code;
    @memcpy(out[1..], body);
    return out;
}

fn goodKeyEntries(pk: *const ctap2pin.PublicKey) [5]MapEntry {
    return .{
        .{ .key = Value.fromI64(1), .value = Value.fromI64(2) },
        .{ .key = Value.fromI64(3), .value = Value.fromI64(-25) },
        .{ .key = Value.fromI64(-1), .value = Value.fromI64(1) },
        .{ .key = Value.fromI64(-2), .value = .{ .bytes = &pk.x } },
        .{ .key = Value.fromI64(-3), .value = .{ .bytes = &pk.y } },
    };
}

fn authKey() ctap2pin.PublicKey {
    return ctap2pin.publicKeyFromScalar(&auth_scalar) catch unreachable;
}

/// `00 || {2: enc(token)}` under the secret both sides derive from the fixed scalars.
fn tokenResp(protocol: ctap2pin.Protocol, token: []const u8) ![]u8 {
    const platform_pub = try ctap2pin.publicKeyFromScalar(&platform_scalar);
    var ct: [64]u8 = undefined;
    var n: usize = 0;
    switch (protocol) {
        .one => {
            var e: ctap2pin.One.Encaps = undefined;
            try ctap2pin.One.encapsulate(&e, &auth_scalar, platform_pub);
            try ctap2pin.One.encrypt(&e.shared_secret, ct[0..token.len], token);
            n = token.len;
        },
        .two => {
            var e: ctap2pin.Two.Encaps = undefined;
            try ctap2pin.Two.encapsulate(&e, &auth_scalar, platform_pub);
            const iv: [16]u8 = @splat(7);
            n = ctap2pin.Two.encryptedLength(token.len);
            try ctap2pin.Two.encrypt(&e.shared_secret, iv, ct[0..n], token);
        },
    }
    const entries = [_]MapEntry{.{ .key = .{ .uint = 2 }, .value = .{ .bytes = ct[0..n] } }};
    const body = try enc(.{ .map = &entries });
    defer a.free(body);
    return prependStatus(0, body);
}

const Harness = struct {
    tr: testutil.ScriptTransport,
    rnd: testutil.ScriptRandom,

    fn client(self: *Harness, protocol: ctap2pin.Protocol) clientpin.Client {
        return clientpin.Client.init(a, self.tr.transport(), self.rnd.random(), protocol);
    }
    fn deinit(self: *Harness) void {
        self.tr.deinit();
    }
};

fn harness(responses: []const []const u8, rnd_script: []const u8) Harness {
    return .{ .tr = testutil.ScriptTransport.init(a, responses), .rnd = .{ .bytes = rnd_script } };
}

// ── status codes through the client ─────────────────────────────────────────

test "every status code, answered to any client call, becomes its typed error" {
    inline for (status.table) |row| {
        const resp = [_]u8{row.code};
        var h = harness(&.{&resp}, "");
        defer h.deinit();
        try testing.expectError(@field(status.StatusError, row.name), h.client(.two).getPinRetries());
    }
    const unknown = [_]u8{0xF3};
    var h = harness(&.{&unknown}, "");
    defer h.deinit();
    try testing.expectError(error.UnknownStatus, h.client(.one).getUvRetries());
}

test "PIN errors after a good key agreement: invalid, blocked, auth blocked, policy" {
    const pk = authKey();
    const ke = goodKeyEntries(&pk);
    const kr = try keyResp(&ke);
    defer a.free(kr);
    const cases = [_]struct { code: u8, err: anyerror }{
        .{ .code = 0x31, .err = error.PinInvalid },
        .{ .code = 0x32, .err = error.PinBlocked },
        .{ .code = 0x34, .err = error.PinAuthBlocked },
        .{ .code = 0x35, .err = error.PinNotSet },
        .{ .code = 0x37, .err = error.PinPolicyViolation },
        .{ .code = 0x36, .err = error.PuatRequired },
    };
    for (cases) |c| {
        const resp = [_]u8{c.code};
        var h = harness(&.{ kr, &resp }, &platform_scalar);
        defer h.deinit();
        try testing.expectError(c.err, h.client(.one).getPinToken("1234"));
        try testing.expectEqual(@as(usize, 2), h.tr.requests.items.len);
    }
    // ... and for changePIN / setPIN / the UV token (protocol Two draws an IV).
    const iv_script = platform_scalar ++ [_]u8{9} ** 32;
    {
        const resp = [_]u8{0x33};
        var h = harness(&.{ kr, &resp }, &iv_script);
        defer h.deinit();
        try testing.expectError(error.PinAuthInvalid, h.client(.two).changePin("1234", "5678"));
    }
    {
        const resp = [_]u8{0x37};
        var h = harness(&.{ kr, &resp }, &iv_script);
        defer h.deinit();
        try testing.expectError(error.PinPolicyViolation, h.client(.two).setPin("1234"));
    }
    {
        const resp = [_]u8{0x3F};
        var h = harness(&.{ kr, &resp }, &iv_script);
        defer h.deinit();
        try testing.expectError(error.UvInvalid, h.client(.two).getPinUvAuthTokenUsingUv(.{ .ga = true }, null));
    }
}

// ── validation happens before any I/O ───────────────────────────────────────

test "PIN and permission validation fail before anything is sent" {
    var h = harness(&.{}, "");
    defer h.deinit();
    const c = h.client(.two);
    try testing.expectError(error.PinTooShort, c.setPin("abc"));
    try testing.expectError(error.PinTooLong, c.setPin("a" ** 64));
    try testing.expectError(error.PinNotUtf8, c.setPin("ab\xffcd"));
    try testing.expectError(error.PinTooShort, c.changePin("1234", "\u{20ac}\u{20ac}\u{20ac}"));
    try testing.expectError(error.PinTooLong, c.changePin("a" ** 64, "5678"));
    try testing.expectError(error.PinTooLong, c.getPinToken("a" ** 64));
    try testing.expectError(error.InvalidPermissions, c.getPinUvAuthTokenUsingPin("1234", .{}, null));
    try testing.expectError(error.InvalidPermissions, c.getPinUvAuthTokenUsingUv(.{}, null));
    try testing.expectEqual(@as(usize, 0), h.tr.requests.items.len);
}

test "the authenticator's minPINLength raises the bar before I/O" {
    var h = harness(&.{}, "");
    defer h.deinit();
    var c = h.client(.two);
    c.min_pin_length = 8;
    try testing.expectError(error.PinTooShort, c.setPin("1234567"));
    try testing.expectEqual(@as(usize, 0), h.tr.requests.items.len);
}

// ── malformed responses ─────────────────────────────────────────────────────

test "getPinRetries / getUvRetries: malformed responses are typed errors" {
    const cases = [_]struct { resp: []const u8, err: anyerror }{
        .{ .resp = &.{}, .err = error.EmptyResponse }, // no status byte at all
        .{ .resp = &.{0x00}, .err = error.EmptyResponse }, // OK but no body
        .{ .resp = &.{ 0x00, 0xa0 }, .err = error.MissingField }, // empty map
        .{ .resp = &.{ 0x00, 0xa1, 0x03, 0x61, 'x' }, .err = error.UnexpectedType }, // retries = "x"
        .{ .resp = &.{ 0x00, 0xa1, 0x03, 0x38, 0x00 }, .err = error.UnexpectedType }, // negative
        .{ .resp = &.{ 0x00, 0xa1, 0x03, 0x1b, 1, 0, 0, 0, 0, 0, 0, 0 }, .err = error.ValueOutOfRange },
        .{ .resp = &.{ 0x00, 0xa2, 0x03, 0x08, 0x04, 0x01 }, .err = error.UnexpectedType }, // powerCycleState = 1
        .{ .resp = &.{ 0x00, 0xa2, 0x03, 0x08, 0x03, 0x09 }, .err = error.DuplicateKey },
        .{ .resp = &.{ 0x00, 0x80 }, .err = error.UnexpectedType }, // an array, not a map
        .{ .resp = &.{ 0x00, 0xa1, 0x03 }, .err = error.MalformedCbor }, // truncated
        .{ .resp = &.{ 0x00, 0xa1, 0x03, 0x08, 0xff }, .err = error.MalformedCbor }, // trailing byte
        .{ .resp = &.{ 0x00, 0xff }, .err = error.MalformedCbor },
    };
    for (cases) |c| {
        var h = harness(&.{c.resp}, "");
        defer h.deinit();
        try testing.expectError(c.err, h.client(.one).getPinRetries());
    }
    // getUVRetries wants key 5.
    var h = harness(&.{&.{ 0x00, 0xa1, 0x03, 0x08 }}, "");
    defer h.deinit();
    try testing.expectError(error.MissingField, h.client(.one).getUvRetries());
}

test "getPinRetries: success, with and without powerCycleState; unknown keys ignored" {
    var h = harness(&.{ &.{ 0x00, 0xa1, 0x03, 0x05 }, &.{ 0x00, 0xa3, 0x03, 0x00, 0x04, 0xf5, 0x18, 0x63, 0x01 } }, "");
    defer h.deinit();
    const c = h.client(.two);
    const r1 = try c.getPinRetries();
    try testing.expectEqual(@as(u32, 5), r1.retries);
    try testing.expectEqual(@as(?bool, null), r1.power_cycle_required);
    const r2 = try c.getPinRetries();
    try testing.expectEqual(@as(u32, 0), r2.retries);
    try testing.expectEqual(@as(?bool, true), r2.power_cycle_required);
}

test "getKeyAgreement: a valid key decodes; every deviation is rejected" {
    const pk = authKey();
    {
        const good = goodKeyEntries(&pk);
        const r = try keyResp(&good);
        defer a.free(r);
        var h = harness(&.{r}, "");
        defer h.deinit();
        const got = try h.client(.one).getKeyAgreement();
        try testing.expectEqualSlices(u8, &pk.x, &got.x);
        try testing.expectEqualSlices(u8, &pk.y, &got.y);
    }
    const x31 = pk.x[0..31];
    const bad_x: [32]u8 = @splat(0x11);
    const Case = struct { entries: []const MapEntry, err: anyerror };
    const g = goodKeyEntries(&pk);
    const cases = [_]Case{
        // kty OKP (1) with EC2-shaped fields
        .{ .entries = &.{ .{ .key = Value.fromI64(1), .value = Value.fromI64(1) }, g[1], g[2], g[3], g[4] }, .err = error.InvalidKeyAgreement },
        // crv P-384 (2)
        .{ .entries = &.{ g[0], g[1], .{ .key = Value.fromI64(-1), .value = Value.fromI64(2) }, g[3], g[4] }, .err = error.InvalidKeyAgreement },
        // alg ES256 (-7) instead of -25
        .{ .entries = &.{ g[0], .{ .key = Value.fromI64(3), .value = Value.fromI64(-7) }, g[2], g[3], g[4] }, .err = error.InvalidKeyAgreement },
        // alg absent
        .{ .entries = &.{ g[0], g[2], g[3], g[4] }, .err = error.InvalidKeyAgreement },
        // x one byte short
        .{ .entries = &.{ g[0], g[1], g[2], .{ .key = Value.fromI64(-2), .value = .{ .bytes = x31 } }, g[4] }, .err = error.InvalidKeyAgreement },
        // y missing
        .{ .entries = &.{ g[0], g[1], g[2], g[3] }, .err = error.MissingField },
        // x is text
        .{ .entries = &.{ g[0], g[1], g[2], .{ .key = Value.fromI64(-2), .value = .{ .text = "xx" } }, g[4] }, .err = error.UnexpectedType },
        // duplicate label
        .{ .entries = &.{ g[0], g[0], g[1], g[2], g[3], g[4] }, .err = error.InvalidKeyAgreement },
        // not on the curve
        .{ .entries = &.{ g[0], g[1], g[2], .{ .key = Value.fromI64(-2), .value = .{ .bytes = &bad_x } }, g[4] }, .err = error.InvalidPublicKey },
    };
    for (cases) |c| {
        const r = try keyResp(c.entries);
        defer a.free(r);
        var h = harness(&.{r}, "");
        defer h.deinit();
        try testing.expectError(c.err, h.client(.one).getKeyAgreement());
    }
    // The point at infinity in affine form (0, 1) is not a key.
    const zero: [32]u8 = @splat(0);
    var one: [32]u8 = @splat(0);
    one[31] = 1;
    const inf = [_]MapEntry{ g[0], g[1], g[2], .{ .key = Value.fromI64(-2), .value = .{ .bytes = &zero } }, .{ .key = Value.fromI64(-3), .value = .{ .bytes = &one } } };
    const r = try keyResp(&inf);
    defer a.free(r);
    var h = harness(&.{r}, "");
    defer h.deinit();
    try testing.expectError(error.InvalidPublicKey, h.client(.one).getKeyAgreement());
}

test "getKeyAgreement: response that is not {1: map}" {
    const cases = [_]struct { resp: []const u8, err: anyerror }{
        .{ .resp = &.{ 0x00, 0xa0 }, .err = error.MissingField },
        .{ .resp = &.{ 0x00, 0xa1, 0x01, 0x01 }, .err = error.UnexpectedType }, // {1: 1}
        .{ .resp = &.{ 0x00, 0xa1, 0x01, 0xa0 }, .err = error.MissingField }, // {1: {}}
        .{ .resp = &.{ 0x00, 0xa1, 0x02, 0xa0 }, .err = error.MissingField }, // {2: {}}
    };
    for (cases) |c| {
        var h = harness(&.{c.resp}, "");
        defer h.deinit();
        try testing.expectError(c.err, h.client(.two).getKeyAgreement());
    }
}

// ── tokens ──────────────────────────────────────────────────────────────────

fn getToken(protocol: ctap2pin.Protocol, token_resp: []const u8) clientpin.ClientPinError!clientpin.Token {
    const pk = authKey();
    const ke = goodKeyEntries(&pk);
    const kr = keyResp(&ke) catch return error.OutOfMemory;
    defer a.free(kr);
    const script = platform_scalar ++ [_]u8{5} ** 16;
    var h = harness(&.{ kr, token_resp }, &script);
    defer h.deinit();
    return h.client(protocol).getPinUvAuthTokenUsingPin("1234", .{ .mc = true }, "example.org");
}

test "token lengths: One takes 16 or 32, Two exactly 32" {
    const t16 = [_]u8{0xA1} ** 16;
    const t32 = [_]u8{0xB2} ** 32;
    const t48 = [_]u8{0xC3} ** 48;
    {
        const r = try tokenResp(.one, &t16);
        defer a.free(r);
        var t = try getToken(.one, r);
        defer t.deinit();
        try testing.expectEqualSlices(u8, &t16, t.slice());
    }
    {
        const r = try tokenResp(.one, &t32);
        defer a.free(r);
        var t = try getToken(.one, r);
        defer t.deinit();
        try testing.expectEqualSlices(u8, &t32, t.slice());
    }
    {
        const r = try tokenResp(.one, &t48);
        defer a.free(r);
        try testing.expectError(error.BadTokenLength, getToken(.one, r));
    }
    {
        const r = try tokenResp(.two, &t32);
        defer a.free(r);
        var t = try getToken(.two, r);
        defer t.deinit();
        try testing.expectEqualSlices(u8, &t32, t.slice());
    }
    {
        const r = try tokenResp(.two, &t16);
        defer a.free(r);
        try testing.expectError(error.BadTokenLength, getToken(.two, r));
    }
    {
        const r = try tokenResp(.two, &t48);
        defer a.free(r);
        try testing.expectError(error.BadTokenLength, getToken(.two, r));
    }
    // Ciphertext of a length no protocol can decrypt (not whole blocks / too short).
    const odd = [_]u8{0x00} ++ [_]u8{ 0xa1, 0x02, 0x58, 0x1f } ++ [_]u8{0} ** 31;
    try testing.expectError(error.BadTokenLength, getToken(.one, &odd));
    try testing.expectError(error.BadTokenLength, getToken(.two, &odd));
    const empty_bytes = [_]u8{ 0x00, 0xa1, 0x02, 0x40 };
    try testing.expectError(error.BadTokenLength, getToken(.one, &empty_bytes));
    try testing.expectError(error.BadTokenLength, getToken(.two, &empty_bytes));
}

test "token response: missing and mistyped fields" {
    try testing.expectError(error.MissingField, getToken(.one, &.{ 0x00, 0xa1, 0x01, 0x01 }));
    try testing.expectError(error.UnexpectedType, getToken(.one, &.{ 0x00, 0xa1, 0x02, 0x61, 'x' }));
    try testing.expectError(error.EmptyResponse, getToken(.two, &.{0x00}));
    try testing.expectError(error.MalformedCbor, getToken(.two, &.{ 0x00, 0xa1, 0x02, 0x58, 0x30, 1, 2 }));
}

test "Token.authenticate reproduces ctap2pin's python-fido2 pinUvAuthParam" {
    // Values from ctap2pin's oracle vectors (authenticate(pin_uv_token, clientDataHash)).
    var cdh: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&cdh, "1b84a09dfa3810244f8c86b0457fd7066e958690ea1f4527f38140078b3ed49e");
    var t1: clientpin.Token = .{ .protocol = .one, .len = 16 };
    _ = try std.fmt.hexToBytes(t1.bytes[0..16], "9b9fa85bad3af39ef391c1de54348d54");
    const s1 = t1.authenticate(&cdh);
    var want1: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want1, "2ebaa478ec17fd822a95ff8a4210861e");
    try testing.expectEqualSlices(u8, &want1, s1.slice());

    var t2: clientpin.Token = .{ .protocol = .two, .len = 32 };
    _ = try std.fmt.hexToBytes(&t2.bytes, "b09aa8ff4768554814c16bdef13dd14822d090d4663fd19f1138df09809603d8");
    const s2 = t2.authenticate(&cdh);
    var want2: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want2, "655feb200692083b2578b594028fe5d0c3fd2261f8a9f26572052cbf1df89694");
    try testing.expectEqualSlices(u8, &want2, s2.slice());

    t1.deinit();
    t2.deinit();
    try testing.expectEqual(@as(u8, 0), t1.bytes[0]);
    try testing.expectEqual(@as(u8, 0), t2.bytes[31]);
}

// ── transport and randomness ────────────────────────────────────────────────

test "transport failure and an oversized response are typed" {
    var h = harness(&.{&.{ 0x00, 0xa1, 0x03, 0x05 }}, "");
    defer h.deinit();
    h.tr.fail = true;
    try testing.expectError(error.TransportFailed, h.client(.one).getPinRetries());

    var h2 = harness(&.{&.{ 0x00, 0xa1, 0x03, 0x05 }}, "");
    defer h2.deinit();
    var c = h2.client(.one);
    c.max_response = 2; // smaller than the 4-byte answer
    try testing.expectError(error.ResponseBufferTooSmall, c.getPinRetries());
}

test "a random source that yields no usable ECDH scalar is EntropyFailure, not a hang" {
    const pk = authKey();
    const ke = goodKeyEntries(&pk);
    const kr = try keyResp(&ke);
    defer a.free(kr);
    var h = harness(&.{kr}, ""); // an empty script yields all-zero scalars forever
    defer h.deinit();
    try testing.expectError(error.EntropyFailure, h.client(.two).getPinToken("1234"));
    try testing.expect(h.rnd.overrun);
}

test "fromInfo picks the preferred protocol, minPINLength and the buffer size" {
    var info: getinfo.Info = .{};
    info.pin_uv_auth_protocols = .{};
    info.pin_uv_auth_protocols.?.items[0] = .two;
    info.pin_uv_auth_protocols.?.items[1] = .one;
    info.pin_uv_auth_protocols.?.len = 2;
    info.min_pin_length = 8;
    info.max_msg_size = 1 << 30;
    var h = harness(&.{}, "");
    defer h.deinit();
    const c = clientpin.Client.fromInfo(a, h.tr.transport(), h.rnd.random(), info).?;
    try testing.expectEqual(ctap2pin.Protocol.two, c.protocol);
    try testing.expectEqual(@as(u32, 8), c.min_pin_length);
    try testing.expectEqual(@as(usize, 16 * 1024), c.max_response);

    var none: getinfo.Info = .{};
    none.pin_uv_auth_protocols = .{};
    try testing.expect(clientpin.Client.fromInfo(a, h.tr.transport(), h.rnd.random(), none) == null);
}

test "SharedSecret encrypt/decryptToken round trip and wipe" {
    const pk = authKey();
    var s: clientpin.SharedSecret = .{ .protocol = .two, .platform_key = pk };
    @memset(&s.bytes, 0x5a);
    var ct: [48]u8 = undefined;
    var rnd: testutil.ScriptRandom = .{ .bytes = &([_]u8{3} ** 16) };
    const token = [_]u8{0x77} ** 32;
    try s.encrypt(rnd.random(), &ct, &token);
    var t = try s.decryptToken(&ct);
    defer t.deinit();
    try testing.expectEqualSlices(u8, &token, t.slice());
    s.deinit();
    for (s.bytes) |b| try testing.expectEqual(@as(u8, 0), b);
}

// ── audit 2026-10-03 additions ──────────────────────────────────────────────

test "Token.authenticate, protocol One: the whole 32-byte token is the HMAC key, output 16 bytes" {
    const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
    var t: clientpin.Token = .{ .protocol = .one, .len = 32 };
    for (&t.bytes, 0..) |*b, i| b.* = @intCast(0x40 + i);
    const msg = "client data hash stand-in";
    var full: [32]u8 = undefined;
    Hmac.create(&full, msg, &t.bytes);
    const sig = t.authenticate(msg);
    try testing.expectEqual(@as(u8, 16), sig.len);
    try testing.expectEqualSlices(u8, full[0..16], sig.slice());
    // A 16-byte token keys with those 16 bytes only.
    var t16: clientpin.Token = .{ .protocol = .one, .len = 16 };
    @memcpy(t16.bytes[0..16], t.bytes[0..16]);
    var full16: [32]u8 = undefined;
    Hmac.create(&full16, msg, t.bytes[0..16]);
    try testing.expectEqualSlices(u8, full16[0..16], t16.authenticate(msg).slice());
}

test "Token.deinit wipes the bytes and the length" {
    var t: clientpin.Token = .{ .protocol = .two, .len = 32 };
    @memset(&t.bytes, 0xee);
    t.deinit();
    try testing.expectEqual(@as(u8, 0), t.len);
    try testing.expectEqual(@as(usize, 0), t.slice().len);
    for (t.bytes) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "getKeyAgreement: a y coordinate of 31 bytes is rejected, not read past" {
    const pk = authKey();
    const g = goodKeyEntries(&pk);
    const y31 = pk.y[0..31];
    const entries = [_]MapEntry{ g[0], g[1], g[2], g[3], .{ .key = Value.fromI64(-3), .value = .{ .bytes = y31 } } };
    const r = try keyResp(&entries);
    defer a.free(r);
    var h = harness(&.{r}, "");
    defer h.deinit();
    try testing.expectError(error.InvalidKeyAgreement, h.client(.one).getKeyAgreement());
}

/// A random source that counts how many times it is asked for bytes.
const CountingRandom = struct {
    calls: usize = 0,
    fn random(self: *CountingRandom) std.Random {
        return std.Random.init(self, fill);
    }
    fn fill(self: *CountingRandom, buf: []u8) void {
        self.calls += 1;
        @memset(buf, 0);
    }
};

test "an unusable ECDH scalar is redrawn exactly 8 times, then EntropyFailure" {
    const pk = authKey();
    const ke = goodKeyEntries(&pk);
    const kr = try keyResp(&ke);
    defer a.free(kr);
    var tr = testutil.ScriptTransport.init(a, &.{kr});
    defer tr.deinit();
    var cr: CountingRandom = .{};
    const c = clientpin.Client.init(a, tr.transport(), cr.random(), .one);
    try testing.expectError(error.EntropyFailure, c.getPinToken("1234"));
    try testing.expectEqual(@as(usize, 8), cr.calls);
}

test "fromInfo: maxMsgSize is clamped from below as well as above" {
    var h = harness(&.{}, "");
    defer h.deinit();
    var info: getinfo.Info = .{};
    info.max_msg_size = 10;
    try testing.expectEqual(@as(usize, 64), clientpin.Client.fromInfo(a, h.tr.transport(), h.rnd.random(), info).?.max_response);
    info.max_msg_size = 0;
    try testing.expectEqual(@as(usize, 64), clientpin.Client.fromInfo(a, h.tr.transport(), h.rnd.random(), info).?.max_response);
    info.max_msg_size = 4000;
    try testing.expectEqual(@as(usize, 4000), clientpin.Client.fromInfo(a, h.tr.transport(), h.rnd.random(), info).?.max_response);
    info.max_msg_size = null;
    try testing.expectEqual(@as(usize, 2048), clientpin.Client.fromInfo(a, h.tr.transport(), h.rnd.random(), info).?.max_response);
}
