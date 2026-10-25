// SPDX-License-Identifier: MIT

//! Live oracle for `jwt`: github.com/golang-jwt/jwt/v5 (the scope reference)
//! judges a table of tokens -- every algorithm both ways, and the shapes a
//! verifier must refuse or may disagree on -- and each verdict is compared
//! with this module's `parseAndVerify` under the same policy.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-jwt` runs it and
//! `zig build check-interop` compiles it. Needs `go` on PATH with golang-jwt
//! v5.3.1 in the Go module cache (`go mod download
//! github.com/golang-jwt/jwt/v5@v5.3.1`; GOPROXY=off, `tools/go_oracle/go.sum`
//! pins it); no network. Run from the repository root.
//!
//!   zig build interop-jwt              # judge and compare; exit 1 on any surprise
//!   zig build interop-jwt -- --write   # also rewrite src/go_oracle_vectors.zig
//!
//! The policy on both sides: issuer and audience required, `exp` required, no
//! leeway, the clock pinned per case; Go allows the methods of the key's
//! family (HS*, RS*+PS*, one ES curve, EdDSA), because this module fixes the
//! family by the key's type rather than by one `alg`. Each case carries an
//! expectation: `agree` (both accept or both reject) or `stricter` (this
//! module refuses what golang-jwt accepts -- the rows behind the card's
//! `**Ahead:**` line, each with the RFC sentence it follows). A row that
//! changes either way fails the run: a lead that disappeared is as much news
//! as a new disagreement.
//!
//! `--write` freezes the table, the public keys and both verdicts into
//! `src/go_oracle_vectors.zig`, which `src/go_oracle_test.zig` replays in
//! `test-jwt` without Go.

const std = @import("std");
const jwt = @import("jwt");
const bench = @import("testkit").bench;

const work_dir = ".zig-cache/interop-jwt";
const go_dir = "modules/jwt/tools/go_oracle";
const vectors_path = "modules/jwt/src/go_oracle_vectors.zig";

const issuer = "https://issuer.example.com";
const audience = "api.example.com";
const now: i64 = 1_800_000_000;
const base_claims =
    \\{"aud":"api.example.com","exp":2000000000,"iss":"https://issuer.example.com","nbf":1700000000,"sub":"u1"}
;

/// RFC 7520 §3.4 (Figure 4), base64url -- the same key bench-jwt uses.
const rsa_n = "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_" ++ "AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpP" ++ "e7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg" ++ "_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw";
const rsa_d = "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwM" ++ "SMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2M" ++ "UBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQ" ++ "fGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ";
const rsa_p = "3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9" ++ "JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k";
const rsa_q = "uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15v" ++ "MMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc";

/// P-256 group order n, big-endian.
const p256_n = [32]u8{ 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51 };
/// Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493, little-endian.
const ed_l = [32]u8{ 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 };

const b64 = std.base64.url_safe_no_pad;

const Family = enum { hmac, p256, p384, p521, ed, rsa };

const Expect = enum { agree, stricter };

const Case = struct {
    id: []const u8,
    family: Family,
    token: []const u8,
    now: i64 = now,
    expect: Expect = .agree,
    /// Why the row exists, or for `stricter` the rule this module follows.
    why: []const u8,
};

const Keys = struct {
    hmac: [64]u8,
    p256: jwt.EcdsaP256Sha256.KeyPair,
    p384: jwt.EcdsaP384Sha384.KeyPair,
    p521: jwt.EcdsaP521Sha512.KeyPair,
    ed: jwt.Ed25519.KeyPair,
    ed_seed: [32]u8,
    rsa: jwt.rsa.KeyPair,
    rsa_n: []const u8,
    csprng: std.Random.DefaultCsprng,

    fn verification(k: *const Keys, f: Family) !jwt.Key {
        return switch (f) {
            .hmac => .{ .hmac = &k.hmac },
            .p256 => .{ .ecdsa_p256 = k.p256.public_key },
            .p384 => .{ .ecdsa_p384 = k.p384.public_key },
            .p521 => .{ .ecdsa_p521 = k.p521.public_key },
            .ed => .{ .ed25519 = k.ed.public_key },
            .rsa => try jwt.Key.rsaFromPublicKey(&k.rsa.public_key),
        };
    }
};

fn b64Alloc(arena: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try arena.alloc(u8, try b64.Decoder.calcSizeForSlice(s));
    try b64.Decoder.decode(out, s);
    return out;
}

fn enc(arena: std.mem.Allocator, raw: []const u8) ![]u8 {
    const out = try arena.alloc(u8, b64.Encoder.calcSize(raw.len));
    return @constCast(b64.Encoder.encode(out, raw));
}

/// A compact token with `header` and `payload` verbatim, HMAC-SHA-`bits`
/// signed with `key` -- for the header/payload shapes `encodeJson` would
/// never produce.
fn hsRaw(arena: std.mem.Allocator, comptime bits: u16, header: []const u8, payload: []const u8, key: []const u8) ![]u8 {
    const Mac = switch (bits) {
        256 => std.crypto.auth.hmac.sha2.HmacSha256,
        384 => std.crypto.auth.hmac.sha2.HmacSha384,
        512 => std.crypto.auth.hmac.sha2.HmacSha512,
        else => @compileError("HS256/384/512 only"),
    };
    const input = try std.mem.concat(arena, u8, &.{ try enc(arena, header), ".", try enc(arena, payload) });
    var mac: [Mac.mac_length]u8 = undefined;
    Mac.create(&mac, input, key);
    return std.mem.concat(arena, u8, &.{ input, ".", try enc(arena, &mac) });
}

fn hs256(arena: std.mem.Allocator, keys: *const Keys, payload: []const u8) ![]u8 {
    return hsRaw(arena, 256, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}", payload, &keys.hmac);
}

/// `token` with its signature segment replaced by `sig`, encoded.
fn withSig(arena: std.mem.Allocator, token: []const u8, sig: []const u8) ![]u8 {
    const dot = std.mem.findScalarLast(u8, token, '.').?;
    return std.mem.concat(arena, u8, &.{ token[0 .. dot + 1], try enc(arena, sig) });
}

fn sigOf(arena: std.mem.Allocator, token: []const u8) ![]u8 {
    const dot = std.mem.findScalarLast(u8, token, '.').?;
    return b64Alloc(arena, token[dot + 1 ..]);
}

/// Big-endian a - b, same width, a >= b.
fn subBe(out: []u8, a: []const u8, b: []const u8) void {
    var borrow: u16 = 0;
    var i = a.len;
    while (i > 0) {
        i -= 1;
        const d = @as(i32, a[i]) - b[i] - borrow;
        out[i] = @truncate(@as(u32, @bitCast(d)));
        borrow = if (d < 0) 1 else 0;
    }
}

/// DER `SEQUENCE { INTEGER r, INTEGER s }` of a raw big-endian R‖S.
fn derSig(arena: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var body: std.ArrayList(u8) = .empty;
    const half = raw.len / 2;
    for ([_][]const u8{ raw[0..half], raw[half..] }) |int| {
        var v = int;
        while (v.len > 1 and v[0] == 0) v = v[1..];
        const pad: usize = if (v[0] & 0x80 != 0) 1 else 0;
        try body.appendSlice(arena, &.{ 0x02, @intCast(v.len + pad) });
        if (pad == 1) try body.append(arena, 0);
        try body.appendSlice(arena, v);
    }
    try out.appendSlice(arena, &.{ 0x30, @intCast(body.items.len) });
    try out.appendSlice(arena, body.items);
    return out.items;
}

fn makeKeys(arena: std.mem.Allocator, k: *Keys) !void {
    var prng = std.Random.DefaultPrng.init(0x1a7_0_7ac1e);
    const r = prng.random();
    r.bytes(&k.hmac);
    var s256: [jwt.EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    r.bytes(&s256);
    k.p256 = try jwt.EcdsaP256Sha256.KeyPair.generateDeterministic(s256);
    var s384: [jwt.EcdsaP384Sha384.KeyPair.seed_length]u8 = undefined;
    r.bytes(&s384);
    k.p384 = try jwt.EcdsaP384Sha384.KeyPair.generateDeterministic(s384);
    var s521: [jwt.EcdsaP521Sha512.KeyPair.seed_length]u8 = undefined;
    r.bytes(&s521);
    try jwt.EcdsaP521Sha512.KeyPair.generateDeterministicInto(&k.p521, &s521);
    r.bytes(&k.ed_seed);
    k.ed = try jwt.Ed25519.KeyPair.generateDeterministic(k.ed_seed);
    k.rsa_n = try b64Alloc(arena, rsa_n);
    try jwt.rsa.SecretKey.fromPrimes(&k.rsa.secret_key, try b64Alloc(arena, rsa_p), try b64Alloc(arena, rsa_q), &.{ 1, 0, 1 });
    k.rsa.public_key = try jwt.rsa.PublicKey.fromBytes(k.rsa_n, &.{ 1, 0, 1 });
    k.csprng = .init(@as([32]u8, @splat(0x7e)));
}

fn writeKeys(io: std.Io, arena: std.mem.Allocator, dir: std.Io.Dir, k: *const Keys) !void {
    try dir.writeFile(io, .{ .sub_path = "hmac.key", .data = &k.hmac });
    try dir.writeFile(io, .{ .sub_path = "es256.key", .data = &k.p256.secret_key.toBytes() });
    try dir.writeFile(io, .{ .sub_path = "es384.key", .data = &k.p384.secret_key.toBytes() });
    try dir.writeFile(io, .{ .sub_path = "es512.key", .data = &k.p521.secret_key.toBytes() });
    try dir.writeFile(io, .{ .sub_path = "eddsa.seed", .data = &k.ed_seed });
    try dir.writeFile(io, .{ .sub_path = "rsa.n", .data = k.rsa_n });
    try dir.writeFile(io, .{ .sub_path = "rsa.d", .data = try b64Alloc(arena, rsa_d) });
    try dir.writeFile(io, .{ .sub_path = "rsa.p", .data = try b64Alloc(arena, rsa_p) });
    try dir.writeFile(io, .{ .sub_path = "rsa.q", .data = try b64Alloc(arena, rsa_q) });
}

const Alg = struct { name: []const u8, family: Family };
const algs = [_]Alg{
    .{ .name = "HS256", .family = .hmac }, .{ .name = "HS384", .family = .hmac }, .{ .name = "HS512", .family = .hmac },
    .{ .name = "ES256", .family = .p256 }, .{ .name = "ES384", .family = .p384 }, .{ .name = "ES512", .family = .p521 },
    .{ .name = "EdDSA", .family = .ed },   .{ .name = "RS256", .family = .rsa },  .{ .name = "RS384", .family = .rsa },
    .{ .name = "RS512", .family = .rsa },  .{ .name = "PS256", .family = .rsa },  .{ .name = "PS384", .family = .rsa },
    .{ .name = "PS512", .family = .rsa },
};

fn signingKey(k: *Keys, name: []const u8) jwt.SigningKey {
    const eq = std.mem.eql;
    if (eq(u8, name, "HS256")) return .{ .hs256 = &k.hmac };
    if (eq(u8, name, "HS384")) return .{ .hs384 = &k.hmac };
    if (eq(u8, name, "HS512")) return .{ .hs512 = &k.hmac };
    if (eq(u8, name, "ES256")) return .{ .es256 = &k.p256 };
    if (eq(u8, name, "ES384")) return .{ .es384 = &k.p384 };
    if (eq(u8, name, "ES512")) return .{ .es512 = &k.p521 };
    if (eq(u8, name, "EdDSA")) return .{ .ed25519 = &k.ed };
    if (eq(u8, name, "RS256")) return .{ .rs256 = &k.rsa };
    if (eq(u8, name, "RS384")) return .{ .rs384 = &k.rsa };
    if (eq(u8, name, "RS512")) return .{ .rs512 = &k.rsa };
    const pss: jwt.SigningKey.RsaPss = .{ .key = &k.rsa, .random = k.csprng.random() };
    if (eq(u8, name, "PS256")) return .{ .ps256 = pss };
    if (eq(u8, name, "PS384")) return .{ .ps384 = pss };
    if (eq(u8, name, "PS512")) return .{ .ps512 = pss };
    unreachable;
}

fn claimsWith(arena: std.mem.Allocator, comptime fmt: []const u8, args: anytype) ![]u8 {
    return arena.print(fmt, args);
}

fn buildCases(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, k: *Keys) ![]Case {
    var cs: std.ArrayList(Case) = .empty;

    // Every algorithm, both directions, and a flipped signature bit.
    for (algs) |a| {
        const tok = try jwt.encodeJson(arena, base_claims, signingKey(k, a.name), .{});
        try cs.append(arena, .{ .id = try arena.print("ours-signed/{s}", .{a.name}), .family = a.family, .token = tok, .why = "this module's token, every algorithm" });
        const theirs = try dir.readFileAlloc(io, try arena.print("go_{s}.jwt", .{a.name}), arena, .limited(1 << 16));
        try cs.append(arena, .{ .id = try arena.print("go-signed/{s}", .{a.name}), .family = a.family, .token = theirs, .why = "golang-jwt's token, every algorithm" });
        const sig = try sigOf(arena, tok);
        sig[sig.len / 2] ^= 0x01;
        try cs.append(arena, .{ .id = try arena.print("flipped-bit/{s}", .{a.name}), .family = a.family, .token = try withSig(arena, tok, sig), .why = "one signature bit flipped" });
    }

    // Header shapes (HMAC key).
    try cs.append(arena, .{ .id = "alg-none", .family = .hmac, .token = try std.mem.concat(arena, u8, &.{ try enc(arena, "{\"alg\":\"none\"}"), ".", try enc(arena, base_claims), "." }), .why = "unsecured JWT (RFC 8725 §2.1)" });
    try cs.append(arena, .{ .id = "alg-missing", .family = .hmac, .token = try hsRaw(arena, 256, "{\"typ\":\"JWT\"}", base_claims, &k.hmac), .why = "no alg (RFC 7515 §4.1.1 REQUIRED)" });
    try cs.append(arena, .{ .id = "alg-confusion/hs-with-rsa-n", .family = .rsa, .token = try hsRaw(arena, 256, "{\"alg\":\"HS256\"}", base_claims, k.rsa_n), .why = "HS256 keyed with the RSA public modulus against an RSA key (RFC 8725 §2.1)" });
    try cs.append(arena, .{ .id = "alg-family/es256-token-p384-key", .family = .p384, .token = try jwt.encodeJson(arena, base_claims, signingKey(k, "ES256"), .{}), .why = "an ES256 token against a P-384 key" });
    try cs.append(arena, .{ .id = "typ-at+jwt", .family = .hmac, .token = try hsRaw(arena, 256, "{\"alg\":\"HS256\",\"typ\":\"at+jwt\"}", base_claims, &k.hmac), .why = "RFC 9068 typ is not a verifier's business here" });
    try cs.append(arena, .{ .id = "crit-unknown-extension", .family = .hmac, .token = try hsRaw(arena, 256, "{\"alg\":\"HS256\",\"crit\":[\"x-ext\"],\"x-ext\":true}", base_claims, &k.hmac), .expect = .stricter, .why = "RFC 7515 §4.1.11: a crit extension the recipient does not understand makes the JWS invalid" });
    try cs.append(arena, .{ .id = "crit-registered-name", .family = .hmac, .token = try hsRaw(arena, 256, "{\"alg\":\"HS256\",\"crit\":[\"alg\"]}", base_claims, &k.hmac), .expect = .stricter, .why = "RFC 7515 §4.1.11: crit MUST NOT list names defined by RFC 7515/7518" });
    try cs.append(arena, .{ .id = "crit-empty", .family = .hmac, .token = try hsRaw(arena, 256, "{\"alg\":\"HS256\",\"crit\":[]}", base_claims, &k.hmac), .expect = .stricter, .why = "RFC 7515 §4.1.11: crit MUST NOT be an empty list" });
    try cs.append(arena, .{ .id = "header-array", .family = .hmac, .token = try hsRaw(arena, 256, "[\"HS256\"]", base_claims, &k.hmac), .why = "header not a JSON object" });

    // Claims (HMAC key, valid signatures).
    const P = struct {
        id: []const u8,
        payload: []const u8,
        expect: Expect = .agree,
        why: []const u8,
    };
    const payloads = [_]P{
        .{ .id = "exp-past", .payload = try claimsWith(arena, "{{\"aud\":\"{s}\",\"exp\":{d},\"iss\":\"{s}\"}}", .{ audience, now - 1, issuer }), .why = "exp one second ago" },
        .{ .id = "exp-equals-now", .payload = try claimsWith(arena, "{{\"aud\":\"{s}\",\"exp\":{d},\"iss\":\"{s}\"}}", .{ audience, now, issuer }), .why = "RFC 7519 §4.1.4: now MUST be before exp" },
        .{ .id = "exp-next-second", .payload = try claimsWith(arena, "{{\"aud\":\"{s}\",\"exp\":{d},\"iss\":\"{s}\"}}", .{ audience, now + 1, issuer }), .why = "exp one second ahead" },
        .{ .id = "exp-missing", .payload = try claimsWith(arena, "{{\"aud\":\"{s}\",\"iss\":\"{s}\"}}", .{ audience, issuer }), .why = "exp required by policy" },
        .{ .id = "exp-string", .payload = try claimsWith(arena, "{{\"aud\":\"{s}\",\"exp\":\"2000000000\",\"iss\":\"{s}\"}}", .{ audience, issuer }), .why = "RFC 7519 §2: NumericDate is a JSON number" },
        .{ .id = "exp-fraction", .payload = try claimsWith(arena, "{{\"aud\":\"{s}\",\"exp\":2000000000.5,\"iss\":\"{s}\"}}", .{ audience, issuer }), .why = "RFC 7519 §2: NumericDate may be non-integer" },
        .{ .id = "exp-duplicate-last-valid", .payload = try claimsWith(arena, "{{\"aud\":\"{s}\",\"exp\":1,\"exp\":2000000000,\"iss\":\"{s}\"}}", .{ audience, issuer }), .expect = .stricter, .why = "RFC 7519 §4: a JWT with duplicate claim names is rejected or read as its lexically last; this module rejects it (one claims set, whichever parser reads it), golang-jwt takes the last" },
        .{ .id = "exp-duplicate-last-expired", .payload = try claimsWith(arena, "{{\"aud\":\"{s}\",\"exp\":2000000000,\"exp\":1,\"iss\":\"{s}\"}}", .{ audience, issuer }), .why = "RFC 7519 §4: reject duplicates or take the lexically last" },
        .{ .id = "nbf-next-second", .payload = try claimsWith(arena, "{{\"aud\":\"{s}\",\"exp\":2000000000,\"iss\":\"{s}\",\"nbf\":{d}}}", .{ audience, issuer, now + 1 }), .why = "nbf one second ahead" },
        .{ .id = "nbf-equals-now", .payload = try claimsWith(arena, "{{\"aud\":\"{s}\",\"exp\":2000000000,\"iss\":\"{s}\",\"nbf\":{d}}}", .{ audience, issuer, now }), .why = "RFC 7519 §4.1.5: now at or after nbf" },
        .{ .id = "iss-wrong", .payload = try claimsWith(arena, "{{\"aud\":\"{s}\",\"exp\":2000000000,\"iss\":\"https://evil.example.com\"}}", .{audience}), .why = "issuer pinned" },
        .{ .id = "iss-missing", .payload = try claimsWith(arena, "{{\"aud\":\"{s}\",\"exp\":2000000000}}", .{audience}), .why = "issuer pinned" },
        .{ .id = "iss-case", .payload = try claimsWith(arena, "{{\"aud\":\"{s}\",\"exp\":2000000000,\"iss\":\"https://ISSUER.example.com\"}}", .{audience}), .why = "RFC 7519 §4.1.1: case-sensitive" },
        .{ .id = "aud-array-hit", .payload = try claimsWith(arena, "{{\"aud\":[\"other\",\"{s}\"],\"exp\":2000000000,\"iss\":\"{s}\"}}", .{ audience, issuer }), .why = "RFC 7519 §4.1.3: aud may be an array" },
        .{ .id = "aud-array-miss", .payload = try claimsWith(arena, "{{\"aud\":[\"other\"],\"exp\":2000000000,\"iss\":\"{s}\"}}", .{issuer}), .why = "audience pinned" },
        .{ .id = "aud-missing", .payload = try claimsWith(arena, "{{\"exp\":2000000000,\"iss\":\"{s}\"}}", .{issuer}), .why = "audience pinned" },
        .{ .id = "aud-number", .payload = try claimsWith(arena, "{{\"aud\":7,\"exp\":2000000000,\"iss\":\"{s}\"}}", .{issuer}), .why = "aud of the wrong type" },
        .{ .id = "payload-array", .payload = "[1]", .why = "RFC 7519 §7.2: the claims set is a JSON object" },
        .{ .id = "payload-trailing-garbage", .payload = try std.mem.concat(arena, u8, &.{ base_claims, " x" }), .why = "not one JSON value" },
    };
    for (payloads) |p| try cs.append(arena, .{ .id = p.id, .family = .hmac, .token = try hs256(arena, k, p.payload), .expect = p.expect, .why = p.why });

    // Encoding of the compact form (HMAC key).
    const good = try hs256(arena, k, base_claims);
    try cs.append(arena, .{ .id = "b64-padding", .family = .hmac, .token = try std.mem.concat(arena, u8, &.{ good, "=" }), .why = "RFC 7515 §2: base64url without padding" });
    {
        // HS256's 32-byte MAC is 43 characters; the last carries 2 unused bits.
        const t = try arena.dupe(u8, good);
        const last = &t[t.len - 1];
        const v = std.mem.findScalar(u8, &b64.Encoder.alphabet_chars, last.*).?;
        last.* = b64.Encoder.alphabet_chars[v | 1];
        try cs.append(arena, .{ .id = "b64-noncanonical-signature", .family = .hmac, .token = t, .expect = .stricter, .why = "RFC 7515 §2 + RFC 4648 §3.5: unused bits set, so two strings name one signature (a token is not unique)" });
    }
    {
        // The payload segment's last character, same trick: a payload whose
        // length is not a multiple of 3 (base_claims is one), so the last
        // character carries unused bits.
        const odd_claims = try std.mem.replaceOwned(u8, arena, base_claims, "\"u1\"", "\"u12\"");
        if (odd_claims.len % 3 == 0) return error.PayloadLengthHasNoSpareBits;
        const odd = try hs256(arena, k, odd_claims);
        const header_payload = try arena.dupe(u8, odd[0..std.mem.findScalarLast(u8, odd, '.').?]);
        const last = &header_payload[header_payload.len - 1];
        const v = std.mem.findScalar(u8, &b64.Encoder.alphabet_chars, last.*).?;
        last.* = b64.Encoder.alphabet_chars[v | 1];
        var mac: [32]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, header_payload, &k.hmac);
        try cs.append(arena, .{ .id = "b64-noncanonical-payload", .family = .hmac, .token = try std.mem.concat(arena, u8, &.{ header_payload, ".", try enc(arena, &mac) }), .expect = .stricter, .why = "RFC 7515 §2 + RFC 4648 §3.5: unused bits set in a signed segment" });
    }
    try cs.append(arena, .{ .id = "two-segments", .family = .hmac, .token = good[0..std.mem.findScalarLast(u8, good, '.').?], .why = "not three segments" });
    try cs.append(arena, .{ .id = "four-segments", .family = .hmac, .token = try std.mem.concat(arena, u8, &.{ good, ".x" }), .why = "not three segments" });
    try cs.append(arena, .{ .id = "empty-signature", .family = .hmac, .token = try withSig(arena, good, ""), .why = "an HS256 token without its MAC" });
    try cs.append(arena, .{ .id = "leading-space", .family = .hmac, .token = try std.mem.concat(arena, u8, &.{ " ", good }), .why = "whitespace is not base64url" });

    // Signature encodings.
    {
        const tok = try jwt.encodeJson(arena, base_claims, signingKey(k, "ES256"), .{});
        const raw = try sigOf(arena, tok);
        try cs.append(arena, .{ .id = "es256-der-signature", .family = .p256, .token = try withSig(arena, tok, try derSig(arena, raw)), .why = "RFC 7518 §3.4: R‖S, not DER" });
        const high = try arena.dupe(u8, raw);
        subBe(high[32..], &p256_n, raw[32..]);
        try cs.append(arena, .{ .id = "es256-high-s", .family = .p256, .token = try withSig(arena, tok, high), .why = "n - s: ECDSA accepts both s (no low-S rule in JWS)" });
        const r0 = try arena.dupe(u8, raw);
        @memset(r0[0..32], 0);
        try cs.append(arena, .{ .id = "es256-r-zero", .family = .p256, .token = try withSig(arena, tok, r0), .why = "r = 0 is never valid" });
        const sn = try arena.dupe(u8, raw);
        @memcpy(sn[32..], &p256_n);
        try cs.append(arena, .{ .id = "es256-s-equals-n", .family = .p256, .token = try withSig(arena, tok, sn), .why = "s = n is out of range" });
    }
    {
        const tok = try jwt.encodeJson(arena, base_claims, signingKey(k, "EdDSA"), .{});
        const raw = try sigOf(arena, tok);
        var carry: u16 = 0;
        for (raw[32..], ed_l) |*b, l| {
            const s = @as(u16, b.*) + l + carry;
            b.* = @truncate(s);
            carry = s >> 8;
        }
        try cs.append(arena, .{ .id = "eddsa-s-plus-l", .family = .ed, .token = try withSig(arena, tok, raw), .why = "RFC 8032 §5.1.7: S must be below L" });
    }
    {
        const tok = try jwt.encodeJson(arena, base_claims, signingKey(k, "RS256"), .{});
        const raw = try sigOf(arena, tok);
        try cs.append(arena, .{ .id = "rs256-signature-one-byte-short", .family = .rsa, .token = try withSig(arena, tok, raw[1..]), .why = "RFC 7518 §3.3 / RFC 8017 §8.2.2: the signature is k octets" });
        const longer = try std.mem.concat(arena, u8, &.{ &.{0}, raw });
        try cs.append(arena, .{ .id = "rs256-signature-leading-zero", .family = .rsa, .token = try withSig(arena, tok, longer), .why = "k + 1 octets with a zero first" });
    }
    return cs.items;
}

const Verdict = struct { ok: bool, err: []const u8 };

fn ours(gpa: std.mem.Allocator, k: *const Keys, c: Case) !Verdict {
    const key = try k.verification(c.family);
    var t = jwt.parseAndVerify(gpa, c.token, key, .{
        .now_s = c.now,
        .leeway_s = 0,
        .issuer = .{ .required = issuer },
        .audience = .{ .required = audience },
        .require_exp = true,
    }) catch |e| return .{ .ok = false, .err = @errorName(e) };
    t.deinit();
    return .{ .ok = true, .err = "" };
}

fn zigString(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |ch| switch (ch) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        0x20...0x21, 0x23...0x5b, 0x5d...0x7e => try w.writeByte(ch),
        else => try w.print("\\x{x:0>2}", .{ch}),
    };
    try w.writeByte('"');
}

fn writeVectors(io: std.Io, arena: std.mem.Allocator, k: *const Keys, cases: []const Case, go: []const Verdict, us: []const Verdict, banner: []const u8) !void {
    var out: std.Io.Writer.Allocating = .init(arena);
    const w = &out.writer;
    try w.writeAll("// SPDX-License-Identifier: MIT\n// GENERATED by `zig build interop-jwt -- --write` (modules/jwt/tools/interop.zig)\n");
    try w.print("// against {s}. Do not edit: re-take it.\n\n", .{banner});
    try w.writeAll("//! golang-jwt's verdict and this module's on every row of the interop table,\n//! replayed by `go_oracle_test.zig`. Public keys only.\n\n");
    try w.print("pub const issuer = \"{s}\";\npub const audience = \"{s}\";\n\n", .{ issuer, audience });
    try w.print("pub const hmac_hex = \"{x}\";\n", .{&k.hmac});
    try w.print("pub const p256_sec1_hex = \"{x}\";\n", .{&k.p256.public_key.toUncompressedSec1()});
    try w.print("pub const p384_sec1_hex = \"{x}\";\n", .{&k.p384.public_key.toUncompressedSec1()});
    try w.print("pub const p521_sec1_hex = \"{x}\";\n", .{&k.p521.public_key.toUncompressedSec1()});
    try w.print("pub const ed25519_hex = \"{x}\";\n", .{&k.ed.public_key.toBytes()});
    try w.print("pub const rsa_n_hex = \"{x}\";\n\n", .{k.rsa_n});
    try w.writeAll(
        \\pub const Family = enum { hmac, p256, p384, p521, ed, rsa };
        \\pub const Expect = enum { agree, stricter };
        \\pub const Case = struct {
        \\    id: []const u8,
        \\    family: Family,
        \\    now: i64,
        \\    token: []const u8,
        \\    expect: Expect,
        \\    go_ok: bool,
        \\    /// golang-jwt's error text, empty when it accepted.
        \\    go_err: []const u8,
        \\    ours_ok: bool,
        \\    /// This module's error name, empty when it accepted.
        \\    ours_err: []const u8,
        \\};
        \\
        \\pub const cases = [_]Case{
        \\
    );
    for (cases, go, us) |c, g, u| {
        try w.print("    .{{ .id = \"{s}\", .family = .{t}, .now = {d}, .expect = .{t}, .go_ok = {}, .go_err = ", .{ c.id, c.family, c.now, c.expect, g.ok });
        try zigString(w, g.err);
        try w.print(", .ours_ok = {}, .ours_err = \"{s}\", .token = ", .{ u.ok, u.err });
        try zigString(w, c.token);
        try w.writeAll(" },\n");
    }
    try w.writeAll("};\n");
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = vectors_path, .data = out.written() });
    std.debug.print("interop-jwt: wrote {s} ({d} cases)\n", .{ vectors_path, cases.len });
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const gpa = std.heap.smp_allocator;
    const args = try init.minimal.args.toSlice(arena);
    var write = false;
    for (args[1..]) |a| {
        if (std.mem.eql(u8, a, "--write")) write = true else {
            std.debug.print("usage: zig build interop-jwt [-- --write]\n", .{});
            return 2;
        }
    }

    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);

    const k = try arena.create(Keys);
    try makeKeys(arena, k);
    try writeKeys(io, arena, dir, k);

    const exe = try bench.goBuild(arena, io, "interop-jwt", init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs, .out = "jwt_oracle" });
    const signed = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, "sign" } });
    if (signed.term != .exited or signed.term.exited != 0) {
        std.debug.print("interop-jwt: the Go side failed to sign:\n{s}\n", .{signed.stderr});
        return 1;
    }
    const banner = std.mem.trimEnd(u8, signed.stderr, "\n");

    const cases = try buildCases(arena, io, dir, k);
    var tsv: std.Io.Writer.Allocating = .init(arena);
    for (cases) |c| try tsv.writer.print("{s}\t{t}\t{d}\t{s}\t{s}\t{s}\n", .{ c.id, c.family, c.now, issuer, audience, c.token });
    try dir.writeFile(io, .{ .sub_path = "cases.tsv", .data = tsv.written() });
    const judged = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, "judge" }, .stdout_limit = .limited(1 << 22) });
    if (judged.term != .exited or judged.term.exited != 0) {
        std.debug.print("interop-jwt: the Go side failed to judge:\n{s}\n", .{judged.stderr});
        return 1;
    }

    const go = try arena.alloc(Verdict, cases.len);
    const us = try arena.alloc(Verdict, cases.len);
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, judged.stdout, "\n"), '\n');
    for (cases, go, us) |c, *g, *u| {
        const line = lines.next() orelse {
            std.debug.print("interop-jwt: the Go side stopped before {s}\n", .{c.id});
            return 1;
        };
        var cols = std.mem.splitScalar(u8, line, '\t');
        if (!std.mem.eql(u8, cols.next().?, c.id)) {
            std.debug.print("interop-jwt: out of step at {s}: {s}\n", .{ c.id, line });
            return 1;
        }
        const v = cols.next() orelse "";
        g.* = .{ .ok = std.mem.eql(u8, v, "ok"), .err = cols.rest() };
        u.* = try ours(gpa, k, c);
    }

    var surprises: usize = 0;
    var leads: usize = 0;
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<34} {s:<9} {s:<7} {s:<30} {s}\n", .{ "case", "expect", "go", "ours", "verdict" });
    for (cases, go, us) |c, g, u| {
        const as_expected = switch (c.expect) {
            .agree => g.ok == u.ok,
            .stricter => g.ok and !u.ok,
        };
        if (!as_expected) surprises += 1;
        if (c.expect == .stricter and as_expected) leads += 1;
        try w.print("{s:<34} {t:<9} {s:<7} {s:<30} {s}\n", .{ c.id, c.expect, if (g.ok) "ok" else "reject", if (u.ok) "ok" else u.err, if (as_expected) "" else "SURPRISE" });
        if (!as_expected) try w.print("    go: {s}\n    why: {s}\n", .{ if (g.ok) "accepted" else g.err, c.why });
    }
    try w.print("\n{d} cases against {s}; {d} where this module is stricter as expected; {d} surprise(s)\n", .{ cases.len, banner, leads, surprises });
    try w.flush();
    if (write) try writeVectors(io, arena, k, cases, go, us, banner);
    return if (surprises == 0) 0 else 1;
}
