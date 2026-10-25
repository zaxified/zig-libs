// SPDX-License-Identifier: MIT
//! Grade-1 audit tests (axis A1, 2026-10-25): the review findings, pinned at
//! today's behaviour behind `fN_fixed = false` flags, and the tests that kill
//! the mutants the existing suite let through (alg pinning, key selection,
//! claim-option plumbing, the verified-token cache, the OAuth2 error character
//! sets, percent-encoding). Public API only; every test builds its own tokens.

const std = @import("std");
const jwt = @import("root.zig");
const http = @import("http");
const router = @import("router");

const testing = std.testing;
const gpa = testing.allocator;
const enc = std.base64.url_safe_no_pad.Encoder;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

const ISS = "https://issuer.example";
const AUD = "api://svc";
const JWKS_URL = "https://issuer.example/jwks";

// Findings: flip a flag to true when the fix lands, and the pinned test then
// asserts the fixed behaviour instead.
const f3_fixed = false; // verify() accepts a 1-byte HMAC secret (sign refuses < hash size)

const f6_fixed = true; // encodeJson reports an OOM inside the claims validator as InvalidClaims (fix: isOneObject returns an error union, encodeJson propagates OutOfMemory)

// ── helpers ────────────────────────────────────────────────────────────────

fn b64(a: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try a.alloc(u8, enc.calcSize(bytes.len));
    _ = enc.encode(out, bytes);
    return out;
}

/// `b64(header).b64(payload).b64(sig)` from raw parts.
fn rawToken(a: std.mem.Allocator, header: []const u8, payload: []const u8, sig: []const u8) ![]u8 {
    const h = try b64(a, header);
    defer a.free(h);
    const p = try b64(a, payload);
    defer a.free(p);
    const s = try b64(a, sig);
    defer a.free(s);
    return std.fmt.allocPrint(a, "{s}.{s}.{s}", .{ h, p, s });
}

/// An HS256 token over raw JSON parts, MACed here (independent of encode.zig).
fn hsToken(a: std.mem.Allocator, header: []const u8, payload: []const u8, secret: []const u8) ![]u8 {
    const h = try b64(a, header);
    defer a.free(h);
    const p = try b64(a, payload);
    defer a.free(p);
    const si = try std.fmt.allocPrint(a, "{s}.{s}", .{ h, p });
    defer a.free(si);
    var mac: [32]u8 = undefined;
    HmacSha256.create(&mac, si, secret);
    const s = try b64(a, &mac);
    defer a.free(s);
    return std.fmt.allocPrint(a, "{s}.{s}", .{ si, s });
}

fn edKp(seed: u8) !jwt.Ed25519.KeyPair {
    return jwt.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(seed)));
}

fn edJwks(a: std.mem.Allocator, kp: *const jwt.Ed25519.KeyPair, kid: []const u8) ![]u8 {
    const pk = kp.public_key.toBytes();
    const x = try b64(a, &pk);
    defer a.free(x);
    return std.fmt.allocPrint(a, "{{\"keys\":[{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"{s}\",\"x\":\"{s}\"}}]}}", .{ kid, x });
}

fn edTok(a: std.mem.Allocator, kp: *const jwt.Ed25519.KeyPair, kid: ?[]const u8, typ: ?[]const u8, claims: []const u8) ![]u8 {
    return jwt.encodeJson(a, claims, .{ .ed25519 = kp }, .{ .typ = typ, .kid = kid });
}

fn clockAt(now: *const i64) jwt.Clock {
    return .{ .ctx = @constCast(now), .nowFn = readNow };
}

fn readNow(ctx: ?*anyopaque) i64 {
    return @as(*const i64, @ptrCast(@alignCast(ctx.?))).*;
}

/// A fetcher answering the well-known URL and everything else (the JWKS)
/// from canned bodies, counting both.
const Routed = struct {
    jwks_body: []const u8 = "",
    disco_body: []const u8 = "",
    disco_calls: usize = 0,
    jwks_calls: usize = 0,

    fn fetcher(self: *Routed) jwt.Fetcher {
        return .{ .ctx = self, .fetchFn = fetchFn };
    }

    fn fetchFn(ctx: *anyopaque, url: []const u8, buf: []u8) jwt.FetchError!jwt.Fetcher.Result {
        const self: *Routed = @ptrCast(@alignCast(ctx));
        var body: []const u8 = undefined;
        if (std.mem.endsWith(u8, url, jwt.well_known_path)) {
            self.disco_calls += 1;
            body = self.disco_body;
        } else {
            self.jwks_calls += 1;
            body = self.jwks_body;
        }
        if (body.len > buf.len) return error.ResponseTooLarge;
        @memcpy(buf[0..body.len], body);
        return .{ .status = 200, .body_len = body.len };
    }
};

// ── review findings, pinned ────────────────────────────────────────────────

test "F1: duplicate JSON members are refused (InvalidJson) in the header and in the claims -- no first/last-wins parser differential (stricter than RFC 7515 §4 / RFC 7519 §4 require)" {
    const secret = "0123456789abcdef0123456789abcdef";
    const cases = [_]struct { header: []const u8, payload: []const u8 }{
        .{ .header = "{\"alg\":\"none\",\"alg\":\"HS256\"}", .payload = "{\"exp\":2000}" },
        .{ .header = "{\"alg\":\"HS256\",\"alg\":\"none\"}", .payload = "{\"exp\":2000}" },
        .{ .header = "{\"alg\":\"HS256\",\"kid\":\"a\",\"kid\":\"b\"}", .payload = "{\"exp\":2000}" },
        .{ .header = "{\"alg\":\"HS256\"}", .payload = "{\"exp\":1,\"exp\":2000}" },
        .{ .header = "{\"alg\":\"HS256\"}", .payload = "{\"exp\":2000,\"exp\":1}" },
        .{ .header = "{\"alg\":\"HS256\"}", .payload = "{\"exp\":2000,\"aud\":\"x\",\"aud\":\"y\"}" },
        .{ .header = "{\"alg\":\"HS256\"}", .payload = "{\"exp\":2000,\"iss\":\"a\",\"iss\":\"b\"}" },
    };
    for (cases) |c| {
        const t = try hsToken(gpa, c.header, c.payload, secret);
        defer gpa.free(t);
        try testing.expectError(error.InvalidJson, jwt.parse(gpa, t));
    }
}

test "F2: base64url is canonical -- nonzero padding bits, '=' and the standard alphabet are InvalidBase64 in every segment (SPEC's 'unused base64url tail bits' flooding remark is stale)" {
    const secret = "0123456789abcdef0123456789abcdef";
    // Two trailing spaces and one trailing space make the segment lengths
    // 1 and 2 (mod 3), so each of header and payload ends in a partial group.
    const tok = try hsToken(gpa, "{\"alg\":\"HS256\"} ", "{\"exp\":2000}  ", secret);
    defer gpa.free(tok);
    {
        var p = try jwt.parse(gpa, tok);
        p.deinit();
    }
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const dot1 = std.mem.findScalar(u8, tok, '.').?;
    const dot2 = std.mem.findScalarPos(u8, tok, dot1 + 1, '.').?;
    // The last character of each segment carries unused low bits: flip the lowest.
    for ([_]usize{ dot1 - 1, dot2 - 1, tok.len - 1 }) |at| {
        const copy = try gpa.dupe(u8, tok);
        defer gpa.free(copy);
        const idx = std.mem.findScalar(u8, alphabet, copy[at]).?;
        copy[at] = alphabet[idx ^ 1];
        try testing.expectError(error.InvalidBase64, jwt.parse(gpa, copy));
    }
    // Padding is not allowed.
    const padded = try std.fmt.allocPrint(gpa, "{s}=", .{tok});
    defer gpa.free(padded);
    try testing.expectError(error.InvalidBase64, jwt.parse(gpa, padded));
    // The standard alphabet is not the URL alphabet.
    for ([_]u8{ '+', '/' }) |bad| {
        const copy = try gpa.dupe(u8, tok);
        defer gpa.free(copy);
        copy[dot1 + 2] = bad;
        try testing.expectError(error.InvalidBase64, jwt.parse(gpa, copy));
    }
}

test "F3: verify() accepts a 1-byte HMAC secret while encode refuses anything shorter than the hash (RFC 7518 §3.2 binds the issuer; the asymmetry is the finding)" {
    const t = try hsToken(gpa, "{\"alg\":\"HS256\"}", "{\"exp\":2000}", "k");
    defer gpa.free(t);
    var parsed = try jwt.parse(gpa, t);
    defer parsed.deinit();
    if (f3_fixed) {
        try testing.expectError(error.InvalidKey, jwt.verify(&parsed, .{ .hmac = "k" }));
    } else {
        try jwt.verify(&parsed, .{ .hmac = "k" });
    }
    // The signing side refuses.
    try testing.expectError(error.InvalidKey, jwt.encodeJson(gpa, "{}", .{ .hs256 = "k" }, .{}));
    // A local JWKS may carry the short secret too (network ones never carry oct keys).
    var set = try jwt.parseJwks(gpa, "{\"keys\":[{\"kty\":\"oct\",\"k\":\"aw\"}]}");
    defer set.deinit();
    try testing.expectEqual(@as(usize, 1), set.keys.len);
}

test "F4: ES256 signatures are malleable (s and n-s both verify), as the SPEC's flooding paragraph says -- a pin, not a defect" {
    const kp = try jwt.EcdsaP256Sha256.KeyPair.generateDeterministic(@as([jwt.EcdsaP256Sha256.KeyPair.seed_length]u8, @splat(0x42)));
    const key: jwt.Key = .{ .ecdsa_p256 = kp.public_key };
    const h = try b64(gpa, "{\"alg\":\"ES256\"}");
    defer gpa.free(h);
    const pl = try b64(gpa, "{\"exp\":2000}");
    defer gpa.free(pl);
    const si = try std.fmt.allocPrint(gpa, "{s}.{s}", .{ h, pl });
    defer gpa.free(si);
    var raw = (try kp.sign(si, null)).toBytes();

    const s1 = try b64(gpa, &raw);
    defer gpa.free(s1);
    const tok1 = try std.fmt.allocPrint(gpa, "{s}.{s}", .{ si, s1 });
    defer gpa.free(tok1);
    const neg = std.crypto.ecc.P256.scalar.neg(raw[32..64].*, .big) catch unreachable;
    @memcpy(raw[32..64], &neg);
    const s2 = try b64(gpa, &raw);
    defer gpa.free(s2);
    const tok2 = try std.fmt.allocPrint(gpa, "{s}.{s}", .{ si, s2 });
    defer gpa.free(tok2);

    try testing.expect(!std.mem.eql(u8, tok1, tok2));
    for ([_][]const u8{ tok1, tok2 }) |t| {
        var p = try jwt.parse(gpa, t);
        defer p.deinit();
        try jwt.verify(&p, key);
    }
}

test "F5: NumericDate edge shapes -- 2^64, 1e400 and non-numbers are refused, i64 max never expires, fractions truncate" {
    const secret = "0123456789abcdef0123456789abcdef";
    const bad = [_][]const u8{
        "{\"exp\":18446744073709551616}",
        "{\"exp\":\"1700000000\"}",
        "{\"exp\":true}",
        "{\"exp\":null}",
        "{\"exp\":[2000]}",
        "{\"exp\":2000,\"nbf\":\"1\"}",
        "{\"exp\":2000,\"iat\":{}}",
    };
    for (bad) |payload| {
        const t = try hsToken(gpa, "{\"alg\":\"HS256\"}", payload, secret);
        defer gpa.free(t);
        try testing.expectError(error.InvalidClaim, jwt.parse(gpa, t));
    }
    // A float too large for any i64, or infinite after parsing: refused as a claim
    // (or as JSON), never converted.
    for ([_][]const u8{ "{\"exp\":1e400}", "{\"exp\":-1e400}", "{\"exp\":1e19}" }) |payload| {
        const t = try hsToken(gpa, "{\"alg\":\"HS256\"}", payload, secret);
        defer gpa.free(t);
        if (jwt.parse(gpa, t)) |ok| {
            var o = ok;
            o.deinit();
            return error.TestUnexpectedResult;
        } else |err| try testing.expect(err == error.InvalidClaim or err == error.InvalidJson);
    }
    const t_max = try hsToken(gpa, "{\"alg\":\"HS256\"}", "{\"exp\":9223372036854775807}", secret);
    defer gpa.free(t_max);
    var pm = try jwt.parseAndVerify(gpa, t_max, .{ .hmac = secret }, .{ .now_s = std.math.maxInt(i64) - 1, .leeway_s = 4_000_000_000, .issuer = .any, .audience = .any });
    pm.deinit();
    const t_frac = try hsToken(gpa, "{\"alg\":\"HS256\"}", "{\"exp\":2000.9,\"nbf\":-0.5}", secret);
    defer gpa.free(t_frac);
    var pf = try jwt.parse(gpa, t_frac);
    defer pf.deinit();
    try testing.expectEqual(@as(?i64, 2000), pf.claims.exp);
    try testing.expectEqual(@as(?i64, 0), pf.claims.nbf);
}

// ── parse / claims ─────────────────────────────────────────────────────────

test "header cty is read, and a non-string cty is InvalidClaim" {
    const secret = "0123456789abcdef0123456789abcdef";
    const t = try hsToken(gpa, "{\"alg\":\"HS256\",\"cty\":\"JWT\",\"typ\":\"at+jwt\",\"kid\":\"k1\"}", "{\"exp\":2000}", secret);
    defer gpa.free(t);
    var p = try jwt.parse(gpa, t);
    defer p.deinit();
    try testing.expectEqualStrings("JWT", p.header.cty.?);
    try testing.expectEqualStrings("at+jwt", p.header.typ.?);
    try testing.expectEqualStrings("k1", p.header.kid.?);
    const t2 = try hsToken(gpa, "{\"alg\":\"HS256\",\"cty\":5}", "{\"exp\":2000}", secret);
    defer gpa.free(t2);
    try testing.expectError(error.InvalidClaim, jwt.parse(gpa, t2));
}

test "Audience.contains and validateClaims compare iss/aud exactly: no case folding, no prefix" {
    try testing.expect(!(jwt.Audience{ .single = "API" }).contains("api"));
    try testing.expect(!(jwt.Audience{ .single = "api" }).contains("API"));
    try testing.expect(!(jwt.Audience{ .many = &.{ "abc", "xyz" } }).contains("ab"));
    try testing.expect(!(jwt.Audience{ .many = &.{"ABC"} }).contains("abc"));
    try testing.expect((jwt.Audience{ .many = &.{ "abc", "xyz" } }).contains("xyz"));

    const secret = "0123456789abcdef0123456789abcdef";
    const t = try hsToken(gpa, "{\"alg\":\"HS256\"}", "{\"exp\":2000,\"iss\":\"Https://Issuer.Example\"}", secret);
    defer gpa.free(t);
    var p = try jwt.parse(gpa, t);
    defer p.deinit();
    try testing.expectError(error.IssuerMismatch, jwt.validateClaims(p.claims, .{ .now_s = 1000, .issuer = .{ .required = "https://issuer.example" }, .audience = .any }));
    try jwt.validateClaims(p.claims, .{ .now_s = 1000, .issuer = .{ .required = "Https://Issuer.Example" }, .audience = .any });
}

// ── verify: alg / key class ────────────────────────────────────────────────

test "verify: every non-HMAC alg against an HMAC key is AlgKeyMismatch (nothing is accepted without a check), and HS256 against an Ed25519 key too" {
    const algs = [_][]const u8{ "ES256", "ES384", "ES512", "EdDSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512" };
    inline for (algs) |alg| {
        const t = try rawToken(gpa, "{\"alg\":\"" ++ alg ++ "\"}", "{\"exp\":2000}", &(@as([64]u8, @splat(0))));
        defer gpa.free(t);
        var p = try jwt.parse(gpa, t);
        defer p.deinit();
        try testing.expectError(error.AlgKeyMismatch, jwt.verify(&p, .{ .hmac = "secret-secret-secret-secret-1234" }));
    }
    const kp = try edKp(0x24);
    const key = try jwt.Key.ed25519FromBytes(kp.public_key.toBytes());
    inline for (.{ "HS256", "HS384", "HS512" }) |alg| {
        const t = try rawToken(gpa, "{\"alg\":\"" ++ alg ++ "\"}", "{\"exp\":2000}", &(@as([64]u8, @splat(0))));
        defer gpa.free(t);
        var p = try jwt.parse(gpa, t);
        defer p.deinit();
        try testing.expectError(error.AlgKeyMismatch, jwt.verify(&p, key));
    }
}

test "RSA keys: 2047 bits is below the floor, 2048 is the floor; a hand-assembled modulus_len is InvalidKey, not a length verdict" {
    var n: [256]u8 = @splat(0);
    n[255] = 1;
    n[0] = 0x40; // 2047 bits
    try testing.expectError(error.InvalidKey, jwt.Key.rsaFromModExp(&n, &[_]u8{ 1, 0, 1 }));
    n[0] = 0x80; // 2048 bits
    const key = try jwt.Key.rsaFromModExp(&n, &[_]u8{ 1, 0, 1 });
    try testing.expectEqual(@as(usize, 256), key.rsa.modulus_len);

    const vk = try jwt.rsa.VerifyKey.fromBytes(&n, &[_]u8{ 1, 0, 1 });
    const lying: jwt.Key = .{ .rsa = .{ .inner = vk, .modulus_len = 255 } };
    const t = try rawToken(gpa, "{\"alg\":\"RS256\"}", "{\"exp\":2000}", &(@as([255]u8, @splat(7))));
    defer gpa.free(t);
    var p = try jwt.parse(gpa, t);
    defer p.deinit();
    try testing.expectError(error.InvalidKey, jwt.verify(&p, lying));
}

// ── JWKS ───────────────────────────────────────────────────────────────────

test "JWKS selection: use=enc keys are never selected, kid matching is exact (no case folding, no prefix)" {
    const k0 = try b64(gpa, &(@as([32]u8, @splat(0))));
    defer gpa.free(k0);
    const k1 = try b64(gpa, &(@as([32]u8, @splat(1))));
    defer gpa.free(k1);
    const k2 = try b64(gpa, &(@as([32]u8, @splat(2))));
    defer gpa.free(k2);
    const doc = try std.fmt.allocPrint(gpa,
        \\{{"keys":[
        \\ {{"kty":"oct","kid":"Key","use":"enc","k":"{s}"}},
        \\ {{"kty":"oct","kid":"Key","use":"sig","k":"{s}"}},
        \\ {{"kty":"oct","kid":"key-2","k":"{s}"}}
        \\]}}
    , .{ k0, k1, k2 });
    defer gpa.free(doc);
    var set = try jwt.parseJwks(gpa, doc);
    defer set.deinit();
    try testing.expectEqual(@as(usize, 3), set.keys.len);
    try testing.expectEqual(&set.keys[1], set.keyForKid("Key").?);
    try testing.expectEqual(&set.keys[1], set.selectKey(.{ .alg = "HS256", .kid = "Key" }).?);
    try testing.expectEqual(&set.keys[2], set.selectKey(.{ .alg = "HS256", .kid = "key-2" }).?);
    for ([_][]const u8{ "key", "KEY", "Ke", "Key-", "key-", "" }) |kid| {
        try testing.expectEqual(@as(?jwt.ResolvedKey, null), set.keyForKid(kid));
        try testing.expectEqual(@as(?jwt.ResolvedKey, null), set.selectKey(.{ .alg = "HS256", .kid = kid }));
    }
    // A kid-less token with a set of several usable keys resolves nothing.
    try testing.expectEqual(@as(?jwt.ResolvedKey, null), set.selectKey(.{ .alg = "HS256" }));
}

test "JWK key material: every coordinate one octet short or long is invalid_key (x and y independently), for P-256, P-384, P-521" {
    const kp256 = try jwt.EcdsaP256Sha256.KeyPair.generateDeterministic(@as([jwt.EcdsaP256Sha256.KeyPair.seed_length]u8, @splat(7)));
    const kp384 = try jwt.EcdsaP384Sha384.KeyPair.generateDeterministic(@as([jwt.EcdsaP384Sha384.KeyPair.seed_length]u8, @splat(7)));
    var kp521: jwt.EcdsaP521Sha512.KeyPair = undefined;
    try jwt.EcdsaP521Sha512.KeyPair.generateDeterministicInto(&kp521, &(@as([jwt.EcdsaP521Sha512.KeyPair.seed_length]u8, @splat(7))));
    const s256 = kp256.public_key.toUncompressedSec1();
    const s384 = kp384.public_key.toUncompressedSec1();
    const s521 = kp521.public_key.toUncompressedSec1();
    const curves = [_]struct { crv: []const u8, sec1: []const u8 }{
        .{ .crv = "P-256", .sec1 = &s256 },
        .{ .crv = "P-384", .sec1 = &s384 },
        .{ .crv = "P-521", .sec1 = &s521 },
    };
    for (curves) |c| {
        const len = (c.sec1.len - 1) / 2;
        const x = c.sec1[1 .. 1 + len];
        const y = c.sec1[1 + len ..];
        try expectEcJwk(c.crv, x, y, 1);
        var xl: [80]u8 = undefined;
        var yl: [80]u8 = undefined;
        @memcpy(xl[0..len], x);
        xl[len] = 0;
        @memcpy(yl[0..len], y);
        yl[len] = 0;
        try expectEcJwk(c.crv, xl[0 .. len + 1], y, 0);
        try expectEcJwk(c.crv, x, yl[0 .. len + 1], 0);
        try expectEcJwk(c.crv, x[0 .. len - 1], y, 0);
        try expectEcJwk(c.crv, x, y[0 .. len - 1], 0);
    }
}

fn expectEcJwk(crv: []const u8, x: []const u8, y: []const u8, want_keys: usize) !void {
    const xs = try b64(gpa, x);
    defer gpa.free(xs);
    const ys = try b64(gpa, y);
    defer gpa.free(ys);
    const doc = try std.fmt.allocPrint(gpa, "{{\"keys\":[{{\"kty\":\"EC\",\"crv\":\"{s}\",\"x\":\"{s}\",\"y\":\"{s}\"}}]}}", .{ crv, xs, ys });
    defer gpa.free(doc);
    var set = try jwt.parseJwks(gpa, doc);
    defer set.deinit();
    try testing.expectEqual(want_keys, set.keys.len);
    if (want_keys == 0) {
        try testing.expectEqual(@as(usize, 1), set.skipped.len);
        try testing.expectEqual(jwt.JwkSkipReason.invalid_key, set.skipped[0].reason);
    }
}

test "AKP keys: pub one octet too long is invalid_key for ML-DSA-44, -65 and -87" {
    const seed = @as([32]u8, @splat(0x55));
    const kp44 = try jwt.MlDsa44.KeyPair.generateDeterministic(seed);
    const kp65 = try jwt.MlDsa65.KeyPair.generateDeterministic(seed);
    const kp87 = try jwt.MlDsa87.KeyPair.generateDeterministic(seed);
    try expectAkp("ML-DSA-44", &kp44.public_key.toBytes());
    try expectAkp("ML-DSA-65", &kp65.public_key.toBytes());
    try expectAkp("ML-DSA-87", &kp87.public_key.toBytes());
}

fn expectAkp(alg: []const u8, pk: []const u8) !void {
    for ([_]usize{ 1, 0 }) |extra| {
        const buf = try gpa.alloc(u8, pk.len + extra);
        defer gpa.free(buf);
        @memcpy(buf[0..pk.len], pk);
        if (extra == 1) buf[pk.len] = 0;
        const s = try b64(gpa, buf);
        defer gpa.free(s);
        const doc = try std.fmt.allocPrint(gpa, "{{\"keys\":[{{\"kty\":\"AKP\",\"alg\":\"{s}\",\"pub\":\"{s}\"}}]}}", .{ alg, s });
        defer gpa.free(doc);
        var set = try jwt.parseJwks(gpa, doc);
        defer set.deinit();
        if (extra == 0) {
            try testing.expectEqual(@as(usize, 1), set.keys.len);
        } else {
            try testing.expectEqual(@as(usize, 0), set.keys.len);
            try testing.expectEqual(jwt.JwkSkipReason.invalid_key, set.skipped[0].reason);
        }
    }
}

// ── fetch / discovery / Provider ───────────────────────────────────────────

test "Fetcher.fetch: a body that exactly fills the buffer is a body; one byte more than the buffer is FetchFailed" {
    var want: usize = 16;
    const F = struct {
        fn f(ctx: *anyopaque, _: []const u8, buf: []u8) jwt.FetchError!jwt.Fetcher.Result {
            const n: *usize = @ptrCast(@alignCast(ctx));
            @memset(buf, 'x');
            return .{ .status = 200, .body_len = n.* };
        }
    };
    const fetcher: jwt.Fetcher = .{ .ctx = &want, .fetchFn = F.f };
    var buf: [16]u8 = undefined;
    const r = try fetcher.fetch("https://x", &buf);
    try testing.expectEqual(@as(usize, 16), r.body.len);
    want = 17;
    try testing.expectError(error.FetchFailed, fetcher.fetch("https://x", &buf));
}

test "key sources: only https:// URLs qualify -- https:/x and https:x are refused before any fetch" {
    var fx: Routed = .{ .jwks_body = "{\"keys\":[]}" };
    for ([_][]const u8{ "https:/x", "https:x", "https:", "http://x", "ftp://x", "" }) |url| {
        try testing.expectError(error.InsecureKeySource, jwt.fetchJwks(gpa, fx.fetcher(), url));
    }
    try testing.expectEqual(@as(usize, 0), fx.jwks_calls);
    var ok = try jwt.fetchJwks(gpa, fx.fetcher(), "HTTPS://x/jwks");
    ok.deinit();
    try testing.expectEqual(@as(usize, 1), fx.jwks_calls);
}

test "Provider by issuer: discovery runs once, however many refreshes follow" {
    const kp = try edKp(0x24);
    const jwks_json = try edJwks(gpa, &kp, "a");
    defer gpa.free(jwks_json);
    var fx: Routed = .{
        .jwks_body = jwks_json,
        .disco_body = "{\"issuer\":\"https://issuer.example\",\"jwks_uri\":\"https://issuer.example/jwks\"}",
    };
    var provider = jwt.Provider.init(gpa, fx.fetcher(), .{ .issuer = ISS, .ttl_s = 0 });
    defer provider.deinit();
    const tok = try edTok(gpa, &kp, "a", "JWT", "{\"iss\":\"https://issuer.example\",\"aud\":\"api\",\"exp\":2000}");
    defer gpa.free(tok);
    for (0..3) |_| {
        var t = try provider.verify(gpa, tok, 1000, .{ .audience = .{ .required = "api" } });
        t.deinit();
    }
    try testing.expectEqual(@as(usize, 1), fx.disco_calls);
    try testing.expectEqual(@as(usize, 3), fx.jwks_calls);
}

test "Provider.verify hands leeway, require_exp and reject_future_iat to the claim check" {
    const kp = try edKp(0x24);
    const jwks_json = try edJwks(gpa, &kp, "a");
    defer gpa.free(jwks_json);
    var fx: Routed = .{ .jwks_body = jwks_json };
    var provider = jwt.Provider.init(gpa, fx.fetcher(), .{ .jwks_uri = JWKS_URL, .issuer = ISS, .ttl_s = 1_000_000 });
    defer provider.deinit();
    const aud: jwt.AudiencePolicy = .{ .required = "api" };

    const t_exp = try edTok(gpa, &kp, "a", "JWT", "{\"iss\":\"https://issuer.example\",\"aud\":\"api\",\"exp\":1000}");
    defer gpa.free(t_exp);
    var ok = try provider.verify(gpa, t_exp, 1030, .{ .audience = aud }); // default leeway 60
    ok.deinit();
    try testing.expectError(error.Expired, provider.verify(gpa, t_exp, 1030, .{ .audience = aud, .leeway_s = 0 }));
    var ok_b = try provider.verify(gpa, t_exp, 1030, .{ .audience = aud, .leeway_s = 31 });
    ok_b.deinit();

    const t_noexp = try edTok(gpa, &kp, "a", "JWT", "{\"iss\":\"https://issuer.example\",\"aud\":\"api\"}");
    defer gpa.free(t_noexp);
    try testing.expectError(error.MissingExp, provider.verify(gpa, t_noexp, 1000, .{ .audience = aud }));
    var ok2 = try provider.verify(gpa, t_noexp, 1000, .{ .audience = aud, .require_exp = false });
    ok2.deinit();

    const t_iat = try edTok(gpa, &kp, "a", "JWT", "{\"iss\":\"https://issuer.example\",\"aud\":\"api\",\"exp\":9000,\"iat\":5000}");
    defer gpa.free(t_iat);
    var ok3 = try provider.verify(gpa, t_iat, 1000, .{ .audience = aud });
    ok3.deinit();
    try testing.expectError(error.IssuedInFuture, provider.verify(gpa, t_iat, 1000, .{ .audience = aud, .reject_future_iat = true }));
}

// ── ID token entry points ──────────────────────────────────────────────────

test "acceptIdToken / acceptIdTokenJwks / acceptIdTokenProvider hand leeway, issuer and audience to the claim check" {
    const kp = try edKp(0x24);
    const jwks_json = try edJwks(gpa, &kp, "a");
    defer gpa.free(jwks_json);
    var set = try jwt.parseJwks(gpa, jwks_json);
    defer set.deinit();
    const key: jwt.Key = .{ .ed25519 = kp.public_key };
    const tok = try edTok(gpa, &kp, "a", "JWT", "{\"iss\":\"https://issuer.example\",\"aud\":\"client\",\"nonce\":\"n1\",\"exp\":1000}");
    defer gpa.free(tok);
    const base: jwt.IdTokenOptions = .{ .now_s = 1030, .issuer = ISS, .client_id = "client", .nonce = "n1" };

    var a1 = try jwt.acceptIdToken(gpa, tok, key, base);
    a1.deinit();
    var a2 = try jwt.acceptIdTokenJwks(gpa, tok, set, base);
    a2.deinit();
    var strict0 = base;
    strict0.leeway_s = 0;
    try testing.expectError(error.Expired, jwt.acceptIdToken(gpa, tok, key, strict0));
    try testing.expectError(error.Expired, jwt.acceptIdTokenJwks(gpa, tok, set, strict0));
    var evil = base;
    evil.issuer = "https://evil.example";
    try testing.expectError(error.IssuerMismatch, jwt.acceptIdToken(gpa, tok, key, evil));
    try testing.expectError(error.IssuerMismatch, jwt.acceptIdTokenJwks(gpa, tok, set, evil));
    var other = base;
    other.client_id = "someone-else";
    try testing.expectError(error.AudienceMismatch, jwt.acceptIdToken(gpa, tok, key, other));
    try testing.expectError(error.AudienceMismatch, jwt.acceptIdTokenJwks(gpa, tok, set, other));

    var fx: Routed = .{ .jwks_body = jwks_json };
    var provider = jwt.Provider.init(gpa, fx.fetcher(), .{ .jwks_uri = JWKS_URL, .issuer = ISS, .ttl_s = 1_000_000 });
    defer provider.deinit();
    var a3 = try jwt.acceptIdTokenProvider(&provider, gpa, tok, 1030, .{ .client_id = "client", .nonce = "n1" });
    a3.deinit();
    try testing.expectError(error.Expired, jwt.acceptIdTokenProvider(&provider, gpa, tok, 1030, .{ .leeway_s = 0, .client_id = "client", .nonce = "n1" }));
}

// ── Guard over a static JwkSet, through a real router ──────────────────────

var g_guard: ?*jwt.Guard = null;

fn guardHandler(ctx: *router.Ctx) anyerror!void {
    const g = g_guard.?;
    var actx = g.authenticate(gpa, ctx.req) catch |err| {
        ctx.res.setStatus(jwt.authStatus(err));
        try ctx.res.writeAll("denied");
        return;
    };
    defer actx.deinit();
    ctx.res.setStatus(200);
    try ctx.res.writeAll("ok");
}

fn guardStatus(g: *jwt.Guard, auth: ?[]const u8) !u16 {
    g_guard = g;
    defer g_guard = null;
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.get("/d", guardHandler);
    var req_buf: [4096]u8 = undefined;
    var out_buf: [1024]u8 = undefined;
    const wire = if (auth) |a|
        try std.mem.print(&req_buf, "GET /d HTTP/1.1\r\nHost: t\r\nAuthorization: {s}\r\nConnection: close\r\n\r\n", .{a})
    else
        try std.mem.print(&req_buf, "GET /d HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", .{});
    var in: std.Io.Reader = .fixed(wire);
    var out: std.Io.Writer = .fixed(&out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [512]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = &r,
        .server_name = null,
        .peer = null,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    const got = out.buffered();
    return std.fmt.parseInt(u16, got["HTTP/1.1 ".len..][0..3], 10);
}

const GCase = struct {
    claim_opts: jwt.Provider.ClaimOptions = .{ .issuer = .{ .required = ISS }, .audience = .{ .required = AUD } },
    at_jwt: bool = false,
    now: i64 = 1000,
};

fn staticStatus(set: *const jwt.JwkSet, c: GCase, scheme: []const u8, token: []const u8) !u16 {
    var now = c.now;
    var g = try jwt.Guard.init(gpa, .{ .jwks = set, .claim_opts = c.claim_opts, .require_at_jwt_typ = c.at_jwt, .clock = clockAt(&now) });
    defer g.deinit();
    const hdr = try std.fmt.allocPrint(gpa, "{s} {s}", .{ scheme, token });
    defer gpa.free(hdr);
    return guardStatus(&g, hdr);
}

test "Guard over a static set: an unknown kid, a foreign signature, a wrong audience and every claim option are honoured" {
    const kp = try edKp(0x24);
    const other = try edKp(0x25);
    const jwks_json = try edJwks(gpa, &kp, "a");
    defer gpa.free(jwks_json);
    var set = try jwt.parseJwks(gpa, jwks_json);
    defer set.deinit();

    const good_claims = "{\"iss\":\"https://issuer.example\",\"aud\":\"api://svc\",\"exp\":2000}";
    const good = try edTok(gpa, &kp, "a", "JWT", good_claims);
    defer gpa.free(good);
    try testing.expectEqual(@as(u16, 200), try staticStatus(&set, .{}, "Bearer", good));

    // Unknown kid (even though signed by a key of the same class) and a kid
    // the set knows but a foreign signature: both refused.
    const unknown = try edTok(gpa, &other, "zzz", "JWT", good_claims);
    defer gpa.free(unknown);
    try testing.expectEqual(@as(u16, 401), try staticStatus(&set, .{}, "Bearer", unknown));
    const forged = try edTok(gpa, &other, "a", "JWT", good_claims);
    defer gpa.free(forged);
    try testing.expectEqual(@as(u16, 401), try staticStatus(&set, .{}, "Bearer", forged));

    // Audience.
    const wrong_aud = try edTok(gpa, &kp, "a", "JWT", "{\"iss\":\"https://issuer.example\",\"aud\":\"api://other\",\"exp\":2000}");
    defer gpa.free(wrong_aud);
    try testing.expectEqual(@as(u16, 401), try staticStatus(&set, .{}, "Bearer", wrong_aud));

    // leeway: exp 1000, now 1030.
    const t_exp = try edTok(gpa, &kp, "a", "JWT", "{\"iss\":\"https://issuer.example\",\"aud\":\"api://svc\",\"exp\":1000}");
    defer gpa.free(t_exp);
    try testing.expectEqual(@as(u16, 200), try staticStatus(&set, .{ .now = 1030 }, "Bearer", t_exp));
    var c0: GCase = .{ .now = 1030 };
    c0.claim_opts.leeway_s = 0;
    try testing.expectEqual(@as(u16, 401), try staticStatus(&set, c0, "Bearer", t_exp));

    // require_exp.
    const t_noexp = try edTok(gpa, &kp, "a", "JWT", "{\"iss\":\"https://issuer.example\",\"aud\":\"api://svc\"}");
    defer gpa.free(t_noexp);
    try testing.expectEqual(@as(u16, 401), try staticStatus(&set, .{}, "Bearer", t_noexp));
    var c1: GCase = .{};
    c1.claim_opts.require_exp = false;
    try testing.expectEqual(@as(u16, 200), try staticStatus(&set, c1, "Bearer", t_noexp));

    // reject_future_iat.
    const t_iat = try edTok(gpa, &kp, "a", "JWT", "{\"iss\":\"https://issuer.example\",\"aud\":\"api://svc\",\"exp\":9000,\"iat\":5000}");
    defer gpa.free(t_iat);
    try testing.expectEqual(@as(u16, 200), try staticStatus(&set, .{}, "Bearer", t_iat));
    var c2: GCase = .{};
    c2.claim_opts.reject_future_iat = true;
    try testing.expectEqual(@as(u16, 401), try staticStatus(&set, c2, "Bearer", t_iat));
}

test "Bearer extraction: the scheme is case-insensitive, extra blanks around the token are fine, anything else is no credential" {
    const kp = try edKp(0x24);
    const jwks_json = try edJwks(gpa, &kp, "a");
    defer gpa.free(jwks_json);
    var set = try jwt.parseJwks(gpa, jwks_json);
    defer set.deinit();
    const good = try edTok(gpa, &kp, "a", "JWT", "{\"iss\":\"https://issuer.example\",\"aud\":\"api://svc\",\"exp\":2000}");
    defer gpa.free(good);
    for ([_][]const u8{ "Bearer", "bearer", "BEARER", "bEaReR" }) |scheme| {
        try testing.expectEqual(@as(u16, 200), try staticStatus(&set, .{}, scheme, good));
    }
    const spaced = try std.fmt.allocPrint(gpa, " {s}", .{good});
    defer gpa.free(spaced);
    try testing.expectEqual(@as(u16, 200), try staticStatus(&set, .{}, "Bearer", spaced));
    for ([_][]const u8{ "Basic", "Bearerx", "Token", "Bear" }) |scheme| {
        try testing.expectEqual(@as(u16, 401), try staticStatus(&set, .{}, scheme, good));
    }
}

test "RFC 9068 typ: at+jwt and application/at+jwt in any case qualify, anything else does not (when required)" {
    const kp = try edKp(0x24);
    const jwks_json = try edJwks(gpa, &kp, "a");
    defer gpa.free(jwks_json);
    var set = try jwt.parseJwks(gpa, jwks_json);
    defer set.deinit();
    const claims = "{\"iss\":\"https://issuer.example\",\"aud\":\"api://svc\",\"exp\":2000}";
    const cases = [_]struct { typ: ?[]const u8, status: u16 }{
        .{ .typ = "at+jwt", .status = 200 },
        .{ .typ = "AT+JWT", .status = 200 },
        .{ .typ = "At+Jwt", .status = 200 },
        .{ .typ = "application/at+jwt", .status = 200 },
        .{ .typ = "Application/AT+JWT", .status = 200 },
        .{ .typ = "JWT", .status = 401 },
        .{ .typ = "at+jwt ", .status = 401 },
        .{ .typ = "application/jwt", .status = 401 },
        .{ .typ = null, .status = 401 },
    };
    for (cases) |c| {
        const tok = try edTok(gpa, &kp, "a", c.typ, claims);
        defer gpa.free(tok);
        try testing.expectEqual(c.status, try staticStatus(&set, .{ .at_jwt = true }, "Bearer", tok));
        // Off by default: every typ passes.
        try testing.expectEqual(@as(u16, 200), try staticStatus(&set, .{}, "Bearer", tok));
    }
}

test "realm with NUL is InvalidRealm for both guards; authStatus maps all four errors" {
    try testing.expectError(error.InvalidRealm, jwt.Guard.init(gpa, .{ .claim_opts = .{ .audience = .any }, .realm = "a\x00b" }));
    var fx: Routed = .{};
    var provider = jwt.Provider.init(gpa, fx.fetcher(), .{ .jwks_uri = JWKS_URL, .issuer = ISS });
    defer provider.deinit();
    try testing.expectError(error.InvalidRealm, jwt.ResourceServer.init(gpa, .{ .provider = &provider, .claim_opts = .{ .audience = .any }, .realm = "a\x00b" }));
    try testing.expectEqual(@as(u16, 401), jwt.authStatus(error.MissingToken));
    try testing.expectEqual(@as(u16, 401), jwt.authStatus(error.InvalidToken));
    try testing.expectEqual(@as(u16, 403), jwt.authStatus(error.InsufficientScope));
    try testing.expectEqual(@as(u16, 500), jwt.authStatus(error.OutOfMemory));
}

test "scopeGranted over `scp`: whole tokens only, as a string and as an array element" {
    const t = try rawToken(gpa, "{\"alg\":\"none\"}", "{\"scp\":\"readwrite admin\"}", "");
    defer gpa.free(t);
    var p = try jwt.parse(gpa, t);
    defer p.deinit();
    try testing.expect(!jwt.scopeGranted(p.claims, "read"));
    try testing.expect(!jwt.scopeGranted(p.claims, "adm"));
    try testing.expect(jwt.scopeGranted(p.claims, "readwrite"));
    try testing.expect(jwt.scopeGranted(p.claims, "admin"));

    const t2 = try rawToken(gpa, "{\"alg\":\"none\"}", "{\"scp\":[\"readwrite\",\"admin\",5]}", "");
    defer gpa.free(t2);
    var p2 = try jwt.parse(gpa, t2);
    defer p2.deinit();
    try testing.expect(!jwt.scopeGranted(p2.claims, "read"));
    try testing.expect(!jwt.scopeGranted(p2.claims, "readwritex"));
    try testing.expect(jwt.scopeGranted(p2.claims, "admin"));
}

// ── RP request building / OAuth2 errors ────────────────────────────────────

test "buildTokenRequest percent-encodes every byte but the RFC 3986 unreserved set" {
    var all: [256]u8 = undefined;
    for (&all, 0..) |*b, i| b.* = @intCast(i);
    var req = try jwt.buildTokenRequest(gpa, "https://t/token", .{ .code = &all, .redirect_uri = "r", .client_id = "c", .code_verifier = "v" });
    defer req.deinit(gpa);
    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(gpa);
    try want.appendSlice(gpa, "grant_type=authorization_code&code=");
    const hex = "0123456789ABCDEF";
    for (all) |c| {
        const unreserved = (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '-' or c == '.' or c == '_' or c == '~';
        if (unreserved) {
            try want.append(gpa, c);
        } else {
            try want.appendSlice(gpa, &[_]u8{ '%', hex[c >> 4], hex[c & 15] });
        }
    }
    try want.appendSlice(gpa, "&redirect_uri=r&client_id=c&code_verifier=v");
    try testing.expectEqualStrings(want.items, req.body);
}

fn textOk(c: u8) bool {
    return c == 0x20 or c == 0x21 or (c >= 0x23 and c <= 0x5B) or (c >= 0x5D and c <= 0x7E);
}
fn uriOk(c: u8) bool {
    return c == 0x21 or (c >= 0x23 and c <= 0x5B) or (c >= 0x5D and c <= 0x7E);
}
fn stateOk(c: u8) bool {
    return c >= 0x20 and c <= 0x7E;
}

fn jsonChar(buf: *[8]u8, c: u8) []const u8 {
    if (c == '"') return "\\\"";
    if (c == '\\') return "\\\\";
    if (c < 0x20) return std.mem.print(buf, "\\u{x:0>4}", .{c}) catch unreachable;
    buf[0] = c;
    return buf[0..1];
}

test "OAuth2 error members: RFC 6749 §5.2 / §A character sets, byte by byte (error, error_description, error_uri, state)" {
    var c: u8 = 0;
    while (c < 0x80) : (c += 1) {
        var lit: [8]u8 = undefined;
        const s = jsonChar(&lit, c);

        const d1 = try std.fmt.allocPrint(gpa, "{{\"error\":\"x\",\"error_description\":\"{s}\"}}", .{s});
        defer gpa.free(d1);
        if (textOk(c)) {
            var e = try jwt.parseOAuthError(gpa, d1);
            defer e.deinit();
            try testing.expectEqual(c, e.description.?[0]);
        } else try testing.expectError(error.InvalidCharacter, jwt.parseOAuthError(gpa, d1));

        const d2 = try std.fmt.allocPrint(gpa, "{{\"error\":\"x\",\"error_uri\":\"{s}\"}}", .{s});
        defer gpa.free(d2);
        if (uriOk(c)) {
            var e = try jwt.parseOAuthError(gpa, d2);
            defer e.deinit();
            try testing.expectEqual(c, e.uri.?[0]);
        } else try testing.expectError(error.InvalidCharacter, jwt.parseOAuthError(gpa, d2));

        const d3 = try std.fmt.allocPrint(gpa, "{{\"error\":\"{s}\"}}", .{s});
        defer gpa.free(d3);
        if (textOk(c)) {
            var e = try jwt.parseOAuthError(gpa, d3);
            defer e.deinit();
            try testing.expectEqual(c, e.code_text[0]);
        } else try testing.expectError(error.InvalidCharacter, jwt.parseOAuthError(gpa, d3));

        const q = try std.fmt.allocPrint(gpa, "error=x&state=%{X:0>2}", .{c});
        defer gpa.free(q);
        if (stateOk(c)) {
            var e = (try jwt.parseAuthorizationError(gpa, q)).?;
            defer e.deinit();
            try testing.expectEqual(c, e.state.?[0]);
        } else try testing.expectError(error.InvalidCharacter, jwt.parseAuthorizationError(gpa, q));
    }
    // Non-ASCII bytes are never inside any set.
    try testing.expectError(error.InvalidCharacter, jwt.parseAuthorizationError(gpa, "error=x&state=%80"));
    try testing.expectError(error.InvalidCharacter, jwt.parseAuthorizationError(gpa, "error=x&error_description=%C3%A9"));
}

test "parseAuthorizationError: a repeated parameter keeps its first occurrence" {
    var e = (try jwt.parseAuthorizationError(gpa, "error=first&error=second&state=s1&state=s2&error_description=d1&error_description=d2")).?;
    defer e.deinit();
    try testing.expectEqualStrings("first", e.code_text);
    try testing.expectEqualStrings("s1", e.state.?);
    try testing.expectEqualStrings("d1", e.description.?);
}

// ── encode ─────────────────────────────────────────────────────────────────

test "encode: the HMAC floor is the hash size of THAT algorithm; a key pair whose halves disagree is SigningFailed" {
    const s40 = @as([40]u8, @splat(1));
    const s48 = @as([48]u8, @splat(1));
    const s63 = @as([63]u8, @splat(1));
    const s64 = @as([64]u8, @splat(1));
    try testing.expectError(error.InvalidKey, jwt.encodeJson(gpa, "{}", .{ .hs384 = &s40 }, .{}));
    try testing.expectError(error.InvalidKey, jwt.encodeJson(gpa, "{}", .{ .hs512 = &s63 }, .{}));
    for ([_]jwt.SigningKey{ .{ .hs384 = &s48 }, .{ .hs512 = &s64 } }) |k| {
        const t = try jwt.encodeJson(gpa, "{}", k, .{});
        gpa.free(t);
    }

    var kp = try edKp(0x11);
    const other = try edKp(0x12);
    kp.public_key = other.public_key;
    try testing.expectError(error.SigningFailed, jwt.encodeJson(gpa, "{}", .{ .ed25519 = &kp }, .{}));
}

// ── the verified-token cache ───────────────────────────────────────────────

const CV = struct { n: u32 = 0 };
const CDeriver = struct {
    pub fn derive(_: *CDeriver, _: *const jwt.ParsedToken) ?CV {
        return .{ .n = 1 };
    }
};
const Cache = jwt.VerifiedCache(CV);
const cache_secret = @as([32]u8, @splat(0x33));

fn cacheSet() !jwt.JwkSet {
    const k = try b64(gpa, &cache_secret);
    defer gpa.free(k);
    const doc = try std.fmt.allocPrint(gpa, "{{\"keys\":[{{\"kty\":\"oct\",\"kid\":\"k\",\"k\":\"{s}\"}}]}}", .{k});
    defer gpa.free(doc);
    return jwt.parseJwks(gpa, doc);
}

fn cacheTok(i: usize, exp: ?i64) ![]u8 {
    const claims = if (exp) |e|
        try std.fmt.allocPrint(gpa, "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"sub\":\"u{d}\",\"exp\":{d}}}", .{ ISS, AUD, i, e })
    else
        try std.fmt.allocPrint(gpa, "{{\"iss\":\"{s}\",\"aud\":\"{s}\",\"sub\":\"u{d}\"}}", .{ ISS, AUD, i });
    defer gpa.free(claims);
    return jwt.encodeJson(gpa, claims, .{ .hs256 = &cache_secret }, .{ .kid = "k" });
}

fn pol(now: i64) jwt.Options {
    return .{ .now_s = now, .issuer = .{ .required = ISS }, .audience = .{ .required = AUD } };
}

fn put(c: *Cache, set: *const jwt.JwkSet, tok: []const u8, now: i64) !void {
    var d: CDeriver = .{};
    _ = try c.verifyJwks(gpa, tok, set, pol(now), &d);
}

fn hit(c: *Cache, set: *const jwt.JwkSet, tok: []const u8, now: i64) !bool {
    return (try c.lookup(tok, set, pol(now))) != null;
}

test "VerifiedCache.init: a context of exactly max_context_len bytes is accepted, one more is not; capacity 0 is refused" {
    const ctx64: [64]u8 = @splat('x');
    const ctx65: [65]u8 = @splat('x');
    var c = try Cache.init(gpa, testing.io, .{ .capacity = 4, .context = &ctx64 });
    c.deinit();
    try testing.expectError(error.ContextTooLong, Cache.init(gpa, testing.io, .{ .capacity = 4, .context = &ctx65 }));
    try testing.expectError(error.InvalidCapacity, Cache.init(gpa, testing.io, .{ .capacity = 0 }));
}

test "VerifiedCache.insert stores only the parse of that very token" {
    var set = try cacheSet();
    defer set.deinit();
    var c = try Cache.init(gpa, testing.io, .{ .capacity = 16 });
    defer c.deinit();
    const tok = try cacheTok(1, 5000);
    defer gpa.free(tok);
    var parsed = try jwt.parse(gpa, tok);
    defer parsed.deinit();
    const si = parsed.signing_input;

    // The token IS the signing input (no signature part): nothing stored, and
    // no read past its end.
    c.insert(si, &parsed, &set, pol(1000), .{ .n = 1 });
    try testing.expect(!try hit(&c, &set, si, 1000));
    // The character after the signing input is not '.'.
    const bad_sep = try std.fmt.allocPrint(gpa, "{s}X{s}", .{ si, "sig" });
    defer gpa.free(bad_sep);
    c.insert(bad_sep, &parsed, &set, pol(1000), .{ .n = 1 });
    try testing.expect(!try hit(&c, &set, bad_sep, 1000));
    // Same length and separator, different prefix.
    const other = try gpa.dupe(u8, tok);
    defer gpa.free(other);
    other[0] = if (other[0] == 'A') 'B' else 'A';
    c.insert(other, &parsed, &set, pol(1000), .{ .n = 1 });
    try testing.expect(!try hit(&c, &set, other, 1000));
    // The real pair is stored.
    c.insert(tok, &parsed, &set, pol(1000), .{ .n = 7 });
    try testing.expectEqual(@as(u32, 7), (try c.lookup(tok, &set, pol(1000))).?.n);
}

test "VerifiedCache: the key folds require_exp (another policy is a miss, not a MissingExp answer)" {
    var set = try cacheSet();
    defer set.deinit();
    var c = try Cache.init(gpa, testing.io, .{ .capacity = 16 });
    defer c.deinit();
    const tok = try cacheTok(1, null);
    defer gpa.free(tok);
    var lenient = pol(1000);
    lenient.require_exp = false;
    var d: CDeriver = .{};
    _ = try c.verifyJwks(gpa, tok, &set, lenient, &d);
    try testing.expect((try c.lookup(tok, &set, lenient)) != null);
    var strict = lenient;
    strict.require_exp = true;
    try testing.expectEqual(@as(?CV, null), try c.lookup(tok, &set, strict));
    try testing.expectError(error.MissingExp, c.verifyJwks(gpa, tok, &set, strict, &d));
}

test "VerifiedCache: the same token under a second key set replaces the first entry" {
    var set1 = try cacheSet();
    defer set1.deinit();
    var set2 = try cacheSet();
    defer set2.deinit();
    try testing.expect(set1.id != set2.id);
    var c = try Cache.init(gpa, testing.io, .{ .capacity = 4 });
    defer c.deinit();
    const tok = try cacheTok(1, 5000);
    defer gpa.free(tok);
    try put(&c, &set1, tok, 1000);
    try testing.expect(try hit(&c, &set1, tok, 1000));
    try put(&c, &set2, tok, 1000);
    try testing.expect(try hit(&c, &set2, tok, 1000));
    try testing.expect(!try hit(&c, &set1, tok, 1000));
}

test "VerifiedCache eviction: a token inside its leeway window is live (live up to exp+leeway-1; the boundary second itself is not pinned here), and the CLOCK hand advances" {
    var set = try cacheSet();
    defer set.deinit();
    var toks: [6][]u8 = undefined;
    var made: usize = 0;
    defer for (toks[0..made]) |t| gpa.free(t);
    for (&toks, 0..) |*t, i| {
        t.* = try cacheTok(i, if (i == 0) 1000 else 9999);
        made += 1;
    }

    // exp 1000 + leeway 60: live at 1030 and at 1059 (the last second before the boundary).
    for ([_]i64{ 1030, 1059 }) |later| {
        var c = try Cache.init(gpa, testing.io, .{ .capacity = 4 });
        defer c.deinit();
        for (toks[0..4]) |t| try put(&c, &set, t, 1000);
        try testing.expect(try hit(&c, &set, toks[0], later)); // second chance for slot 0
        try put(&c, &set, toks[4], later); // full bucket: a victim is picked
        try testing.expect(try hit(&c, &set, toks[0], later));
    }

    // Nothing referenced: the hand walks 0, 1, ... so the 5th insert evicts
    // the 1st token and the 6th the 2nd.
    var c = try Cache.init(gpa, testing.io, .{ .capacity = 4 });
    defer c.deinit();
    for (toks[0..6]) |t| try put(&c, &set, t, 900);
    try testing.expect(!try hit(&c, &set, toks[0], 900));
    try testing.expect(!try hit(&c, &set, toks[1], 900));
    for (toks[2..6]) |t| try testing.expect(try hit(&c, &set, t, 900));
}

test "VerifiedCache eviction: a free slot is used before any live entry is evicted, also at a clock before the epoch" {
    var set = try cacheSet();
    defer set.deinit();
    var toks: [5][]u8 = undefined;
    var made: usize = 0;
    defer for (toks[0..made]) |t| gpa.free(t);
    for (&toks, 0..) |*t, i| {
        t.* = try cacheTok(i, if (i == 2) -4990 else -100);
        made += 1;
    }
    var c = try Cache.init(gpa, testing.io, .{ .capacity = 4 });
    defer c.deinit();
    for (toks[0..4]) |t| try put(&c, &set, t, -5000);
    // toks[2] is past exp+leeway at -4900: the hit refuses it and frees its slot.
    try testing.expectError(error.Expired, c.lookup(toks[2], &set, pol(-4900)));
    try put(&c, &set, toks[4], -4900);
    for ([_]usize{ 0, 1, 3, 4 }) |i| try testing.expect(try hit(&c, &set, toks[i], -4900));
}

test "VerifiedCache: the boundary second -- live at exp+leeway-1, Expired at exp+leeway (RFC 7519 §4.1.4), checked on the cached hit" {
    var set = try cacheSet();
    defer set.deinit();
    const tok = try cacheTok(0, 1000);
    defer gpa.free(tok);
    // Default leeway 60: the last live second is 1059.
    var c = try Cache.init(gpa, testing.io, .{ .capacity = 4 });
    defer c.deinit();
    try put(&c, &set, tok, 1000);
    try testing.expect(try hit(&c, &set, tok, 1058));
    try testing.expect(try hit(&c, &set, tok, 1059));
    try testing.expectError(error.Expired, c.lookup(tok, &set, pol(1060)));
    try testing.expectError(error.Expired, put(&c, &set, tok, 1060));
    // A fresh verify agrees on the same two seconds.
    try put(&c, &set, tok, 1059);
    // An exp so close to maxInt that exp + leeway saturates never expires.
    const forever = try cacheTok(1, std.math.maxInt(i64) - 5);
    defer gpa.free(forever);
    try put(&c, &set, forever, 1000);
    try testing.expect(try hit(&c, &set, forever, std.math.maxInt(i64) - 6));
}

test "VerifiedCache eviction: in a full bucket the entry whose exp+leeway equals the clock is the victim, not the CLOCK hand's" {
    var set = try cacheSet();
    defer set.deinit();
    var toks: [5][]u8 = undefined;
    var made: usize = 0;
    defer for (toks[0..made]) |t| gpa.free(t);
    for (&toks, 0..) |*t, i| {
        t.* = try cacheTok(i, if (i == 2) 1000 else 9999);
        made += 1;
    }
    var c = try Cache.init(gpa, testing.io, .{ .capacity = 4 });
    defer c.deinit();
    for (toks[0..4]) |t| try put(&c, &set, t, 1000);
    // exp 1000 + leeway 60 == now 1060: dead exactly now, so it goes first;
    // the hand (at slot 0, nothing referenced) would have taken toks[0].
    try put(&c, &set, toks[4], 1060);
    for ([_]usize{ 0, 1, 3, 4 }) |i| try testing.expect(try hit(&c, &set, toks[i], 1060));
    try testing.expect(!try hit(&c, &set, toks[2], 1000));
}

test "encodeJson: a header that overflows the 256-byte stack buffer (long kid / typ) round-trips, and deeply nested claims are one object" {
    // 400-byte kid: Stringify into the fixed buffer fails half-way, the heap path must start over.
    const kid: [400]u8 = @splat('k');
    const typ: [30]u8 = @splat('t');
    const tok = try jwt.encodeJson(gpa, "{\"sub\":\"x\"}", .{ .hs256 = &cache_secret }, .{ .kid = &kid, .typ = &typ });
    defer gpa.free(tok);
    var p = try jwt.parse(gpa, tok);
    defer p.deinit();
    try testing.expectEqualStrings(&kid, p.header.kid.?);
    try testing.expectEqualStrings(&typ, p.header.typ.?);
    try testing.expectEqualStrings("HS256", p.header.alg);
    // Short header, same call: the stack path.
    const tok2 = try jwt.encodeJson(gpa, "{\"sub\":\"x\"}", .{ .hs256 = &cache_secret }, .{ .kid = "k1" });
    defer gpa.free(tok2);
    var p2 = try jwt.parse(gpa, tok2);
    defer p2.deinit();
    try testing.expectEqualStrings("k1", p2.header.kid.?);
    // A 100-deep nesting fits the validator's 512-byte stack; 9000-deep spills to the heap fallback.
    for ([_]usize{ 100, 9000 }) |depth| {
        const claims = try gpa.alloc(u8, 6 + 2 * depth + 2);
        defer gpa.free(claims);
        @memcpy(claims[0..6], "{\"a\":[");
        @memset(claims[6 .. 6 + depth], '[');
        @memset(claims[6 + depth .. 6 + 2 * depth], ']');
        @memcpy(claims[6 + 2 * depth ..][0..2], "]}");
        const t = try jwt.encodeJson(gpa, claims[0 .. 6 + 2 * depth + 2], .{ .hs256 = &cache_secret }, .{});
        gpa.free(t);
    }
    try testing.expectError(error.InvalidClaims, jwt.encodeJson(gpa, "{\"a\":[}", .{ .hs256 = &cache_secret }, .{}));
}

test "encodeJson: when the claims validator runs out of memory the claims are refused, never passed through unvalidated" {
    // Nesting deeper than the 512-byte (4096-level) stack scratch needs the heap; with the
    // allocator failing from its first call, `validate` errors out.
    const depth = 9000;
    const claims = try gpa.alloc(u8, 6 + 2 * depth + 2);
    defer gpa.free(claims);
    @memcpy(claims[0..6], "{\"a\":[");
    @memset(claims[6 .. 6 + depth], '[');
    @memset(claims[6 + depth .. 6 + 2 * depth], ']');
    @memcpy(claims[6 + 2 * depth ..][0..2], "]}");
    var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
    // FailingAllocator keeps failing from its fail_index on, so a validator
    // that treated its OOM as "valid" would end in OutOfMemory further down
    // instead: the exact error is what tells the two apart.
    const want: anyerror = if (f6_fixed) error.OutOfMemory else error.InvalidClaims;
    try testing.expectError(want, jwt.encodeJson(failing.allocator(), claims, .{ .hs256 = &cache_secret }, .{}));
}
