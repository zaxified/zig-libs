// SPDX-License-Identifier: MIT

//! zig-libs tlsclient: Encrypted Client Hello (RFC 9849), the client side,
//! shaped as Go's `crypto/tls` (`Config.EncryptedClientHelloConfigList`).
//!
//! - **Config** (§4): the first `ECHConfig` of the list (version 0xfe0d;
//!   other versions are skipped, as Go does) with a valid DNS public name,
//!   no mandatory extension, DHKEM(X25519, HKDF-SHA256) and a suite of
//!   HKDF-SHA256 with AES-128-GCM, AES-256-GCM or ChaCha20-Poly1305 (Go
//!   `pickECHConfig`: the first usable config, its first usable suite).
//! - **Inner hello** (§5.1, §6.1.3): `EncodedClientHelloInner` is the inner
//!   ClientHello body with an empty `legacy_session_id`, no
//!   `ech_outer_extensions` compression (Go compresses none either), zero
//!   padding to a multiple of 32 octets after the name padding of §6.1.3.
//! - **Outer hello** (§5, §6.1.1): the `encrypted_client_hello` extension
//!   of type outer carries the HPKE `enc` (empty in the second hello after a
//!   HelloRetryRequest, §6.1.5) and the payload, sealed with the outer
//!   ClientHello body (payload zero) as additional data.
//! - **Confirmation** (§7.2): `confirmation` with "ech accept confirmation"
//!   (ServerHello) or "hrr ech accept confirmation" (HelloRetryRequest).

const std = @import("std");
const hpke = @import("hpke");
const aesgcm = @import("aesgcm");
const x509 = @import("x509");

pub const version: u16 = 0xfe0d;
pub const ext_encrypted_client_hello: u16 = 0xfe0d;

pub const kem_x25519: u16 = 0x0020;
pub const kdf_hkdf_sha256: u16 = 0x0001;
pub const aead_aes128_gcm: u16 = 0x0001;
pub const aead_aes256_gcm: u16 = 0x0002;
pub const aead_chacha20_poly1305: u16 = 0x0003;

/// The longest `ECHConfig` used (its HPKE `info` is built on the stack).
pub const max_config_len = 2048;

/// The `encrypted_client_hello` extension of an inner ClientHello (§5:
/// type inner, empty).
pub const inner_ext = [_]u8{ 0xfe, 0x0d, 0, 1, 1 };

/// The AEAD tag of every supported suite.
pub const tag_len = 16;

const X25519Kem = hpke.X25519Kem;

pub const Error = error{
    /// The `ECHConfigList` is malformed.
    EchConfigInvalid,
    /// No config of the list can be used (Go: "contains no valid configs").
    EchConfigUnsupported,
};

/// The config chosen from the list. Slices point into the caller's list.
pub const Picked = struct {
    /// The whole `ECHConfig` (version, length, contents): the HPKE `info`.
    raw: []const u8,
    config_id: u8,
    public_key: *const [32]u8,
    kdf: u16,
    aead: u16,
    maximum_name_length: u8,
    public_name: []const u8,
};

const Reader = struct {
    buf: []const u8,
    at: usize = 0,

    fn take(r: *Reader, n: usize) ?[]const u8 {
        if (r.buf.len - r.at < n) return null;
        defer r.at += n;
        return r.buf[r.at..][0..n];
    }
    fn int(r: *Reader, comptime T: type) ?T {
        const b = r.take(@sizeOf(T)) orelse return null;
        return std.mem.readInt(T, b[0..@sizeOf(T)], .big);
    }
    fn vec(r: *Reader, comptime L: type) ?[]const u8 {
        return r.take(r.int(L) orelse return null);
    }
    fn left(r: *const Reader) usize {
        return r.buf.len - r.at;
    }
};

/// RFC 9849 §6.1 / Go `validDNSName`: at most 253 octets, at least two
/// labels, each 1..63 LDH octets with no hyphen at either end; and not an
/// IPv4 address.
pub fn validPublicName(name: []const u8) bool {
    if (name.len == 0 or name.len > 253) return false;
    var labels: usize = 0;
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |l| {
        if (l.len == 0 or l.len > 63) return false;
        for (l, 0..) |c, i| {
            if (c == '-' and (i == 0 or i == l.len - 1)) return false;
            const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '-';
            if (!ok) return false;
        }
        labels += 1;
    }
    if (labels < 2) return false;
    const h = x509.hostname.parseHost(name) orelse return false;
    return h == .dns;
}

fn supported(kdf: u16, aead: u16) bool {
    return kdf == kdf_hkdf_sha256 and (aead == aead_aes128_gcm or aead == aead_aes256_gcm or aead == aead_chacha20_poly1305);
}

/// Go `parseECHConfigList` + `pickECHConfig`: a malformed list (or a
/// malformed config of version 0xfe0d) is `EchConfigInvalid`; a well-formed
/// list without a usable config is `EchConfigUnsupported`.
pub fn pick(list: []const u8) Error!Picked {
    var r: Reader = .{ .buf = list };
    const len = r.int(u16) orelse return error.EchConfigInvalid;
    if (len != r.left()) return error.EchConfigInvalid;
    var found: ?Picked = null;
    while (r.left() != 0) {
        const start = r.at;
        const v = r.int(u16) orelse return error.EchConfigInvalid;
        const contents = r.vec(u16) orelse return error.EchConfigInvalid;
        if (v != version) continue;
        const raw = list[start..r.at];
        var c: Reader = .{ .buf = contents };
        const id = c.int(u8) orelse return error.EchConfigInvalid;
        const kem = c.int(u16) orelse return error.EchConfigInvalid;
        const pk = c.vec(u16) orelse return error.EchConfigInvalid;
        const suites = c.vec(u16) orelse return error.EchConfigInvalid;
        if (suites.len % 4 != 0) return error.EchConfigInvalid;
        const max_name = c.int(u8) orelse return error.EchConfigInvalid;
        const name = c.vec(u8) orelse return error.EchConfigInvalid;
        const exts = c.vec(u16) orelse return error.EchConfigInvalid;
        var mandatory = false;
        var e: Reader = .{ .buf = exts };
        while (e.left() != 0) {
            const t = e.int(u16) orelse return error.EchConfigInvalid;
            _ = e.vec(u16) orelse return error.EchConfigInvalid;
            // §4.2: the high bit marks a mandatory extension; none is
            // supported, so such a config is skipped.
            if (t & 0x8000 != 0) mandatory = true;
        }
        if (found != null) continue; // the rest of the list is still checked
        if (mandatory or !validPublicName(name)) continue;
        if (kem != kem_x25519 or pk.len != 32 or raw.len > max_config_len) continue;
        var i: usize = 0;
        while (i < suites.len) : (i += 4) {
            const kdf = std.mem.readInt(u16, suites[i..][0..2], .big);
            const aead = std.mem.readInt(u16, suites[i + 2 ..][0..2], .big);
            if (!supported(kdf, aead)) continue;
            found = .{ .raw = raw, .config_id = id, .public_key = pk[0..32], .kdf = kdf, .aead = aead, .maximum_name_length = max_name, .public_name = name };
            break;
        }
    }
    return found orelse error.EchConfigUnsupported;
}

/// The HPKE sender context for the chosen config, kept for the second
/// ClientHello after a HelloRetryRequest. Holds a key: `wipe` it.
pub const Sealer = union(enum) {
    aes128: hpke.Setup(X25519Kem, aesgcm.Aes128Gcm, 32),
    aes256: hpke.Setup(X25519Kem, aesgcm.Aes256Gcm, 32),
    chacha: hpke.Setup(X25519Kem, hpke.ChaCha20Poly1305, 32),

    pub fn wipe(self: *Sealer) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    /// `SetupBaseS(pkR, "tls ech" ‖ 0x00 ‖ ECHConfig)` with the ephemeral
    /// key derived from `ikm` (secret randomness).
    // secret-api-ok: the ephemeral key pair is one local, wiped on return; hpke's setup runs under its own burn.
    pub fn setup(self: *Sealer, p: *const Picked, ikm: *const [32]u8) Error!void {
        var info: [8 + max_config_len]u8 = undefined;
        if (p.raw.len > max_config_len) return error.EchConfigUnsupported;
        @memcpy(info[0..8], "tls ech\x00");
        @memcpy(info[8..][0..p.raw.len], p.raw);
        const i = info[0 .. 8 + p.raw.len];
        var eph: X25519Kem.KeyPair = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&eph));
        X25519Kem.deriveKeyPair(&eph, ikm);
        const pk = p.public_key.*;
        switch (p.aead) {
            aead_aes128_gcm => {
                self.* = .{ .aes128 = undefined };
                hpke.schedule.setupBaseSDeterministic(X25519Kem, aesgcm.Aes128Gcm, 32, &self.aes128, pk, &eph, i) catch return error.EchConfigUnsupported;
            },
            aead_aes256_gcm => {
                self.* = .{ .aes256 = undefined };
                hpke.schedule.setupBaseSDeterministic(X25519Kem, aesgcm.Aes256Gcm, 32, &self.aes256, pk, &eph, i) catch return error.EchConfigUnsupported;
            },
            aead_chacha20_poly1305 => {
                self.* = .{ .chacha = undefined };
                hpke.schedule.setupBaseSDeterministic(X25519Kem, hpke.ChaCha20Poly1305, 32, &self.chacha, pk, &eph, i) catch return error.EchConfigUnsupported;
            },
            else => return error.EchConfigUnsupported,
        }
    }

    pub fn enc(self: *const Sealer) *const [32]u8 {
        return switch (self.*) {
            inline else => |*s| &s.enc,
        };
    }

    /// Seal `pt` with `aad` into `out` (`pt.len + tag_len` octets).
    pub fn seal(self: *Sealer, aad: []const u8, pt: []const u8, out: []u8) error{EchSealFailed}!void {
        switch (self.*) {
            inline else => |*s| s.context.seal(aad, pt, out) catch return error.EchSealFailed,
        }
    }
};

/// §5.1 and §6.1.3: the `EncodedClientHelloInner` of the inner ClientHello
/// message `inner` (header, body with a 32-octet session id) into `out`:
/// the body with an empty session id, then zero padding.
/// `sni_len`: the inner server_name's length (0: none).
pub fn encodeInner(out: []u8, inner: []const u8, sni_len: usize, maximum_name_length: u8) error{NoSpaceLeft}![]u8 {
    if (inner.len < 4 + 2 + 32 + 1 + 32) return error.NoSpaceLeft;
    const body = inner[4..];
    if (body[34] != 32) return error.NoSpaceLeft;
    const rest = body[2 + 32 + 1 + 32 ..];
    const len = 2 + 32 + 1 + rest.len;
    // §6.1.3: pad the name to maximum_name_length (or 9 + it without one),
    // then the whole to a multiple of 32.
    var pad: usize = if (sni_len != 0)
        (if (maximum_name_length > sni_len) maximum_name_length - sni_len else 0)
    else
        @as(usize, maximum_name_length) + 9;
    pad += 31 - ((len + pad + 31) % 32);
    if (out.len < len + pad) return error.NoSpaceLeft;
    @memcpy(out[0..34], body[0..34]);
    out[34] = 0;
    @memcpy(out[35..][0..rest.len], rest);
    @memset(out[len..][0..pad], 0);
    return out[0 .. len + pad];
}

/// The outer `encrypted_client_hello` extension (type, length, then
/// `ECHClientHello` of type outer) with a zero payload of `payload_len`
/// octets; `enc` empty in the second hello.
pub fn outerExt(out: []u8, p: *const Picked, enc: []const u8, payload_len: usize) error{NoSpaceLeft}![]u8 {
    const body_len = 1 + 2 + 2 + 1 + 2 + enc.len + 2 + payload_len;
    if (out.len < 4 + body_len or body_len > std.math.maxInt(u16)) return error.NoSpaceLeft;
    var w: std.Io.Writer = .fixed(out);
    w.writeInt(u16, ext_encrypted_client_hello, .big) catch unreachable;
    w.writeInt(u16, @intCast(body_len), .big) catch unreachable;
    w.writeByte(0) catch unreachable;
    w.writeInt(u16, p.kdf, .big) catch unreachable;
    w.writeInt(u16, p.aead, .big) catch unreachable;
    w.writeByte(p.config_id) catch unreachable;
    w.writeInt(u16, @intCast(enc.len), .big) catch unreachable;
    w.writeAll(enc) catch unreachable;
    w.writeInt(u16, @intCast(payload_len), .big) catch unreachable;
    w.splatByteAll(0, payload_len) catch unreachable;
    return w.buffered();
}

/// The data of extension `t` in the ClientHello message `m` (header
/// included), or null. `m` is one this module wrote.
pub fn findExt(m: []const u8, t: u16) ?[]const u8 {
    var i: usize = 4 + 2 + 32;
    if (m.len < i + 1) return null;
    i += 1 + @as(usize, m[i]); // session id
    if (m.len < i + 2) return null;
    i += 2 + @as(usize, std.mem.readInt(u16, m[i..][0..2], .big)); // cipher suites
    if (m.len < i + 1) return null;
    i += 1 + @as(usize, m[i]); // compression
    if (m.len < i + 2) return null;
    const end = i + 2 + @as(usize, std.mem.readInt(u16, m[i..][0..2], .big));
    if (end > m.len) return null;
    i += 2;
    while (i + 4 <= end) {
        const len = std.mem.readInt(u16, m[i + 2 ..][0..2], .big);
        if (i + 4 + len > end) return null;
        if (std.mem.readInt(u16, m[i..][0..2], .big) == t) return m[i + 4 ..][0..len];
        i += 4 + len;
    }
    return null;
}

/// §7.2: the 8 confirmation octets, `HKDF-Expand-Label(HKDF-Extract(0,
/// ClientHelloInner.random), label, transcript_hash, 8)`.
pub fn confirmation(comptime Hkdf: type, inner_random: *const [32]u8, label: []const u8, transcript_hash: []const u8) [8]u8 {
    const zeros: [Hkdf.prk_length]u8 = @splat(0);
    const prk = Hkdf.extract(&zeros, inner_random);
    return std.crypto.tls.hkdfExpandLabel(Hkdf, prk, label, transcript_hash, 8);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

/// An ECHConfig of the given parts.
fn testConfig(buf: []u8, v: u16, id: u8, kem: u16, pk: []const u8, suites: []const u8, name: []const u8, exts: []const u8) []u8 {
    var w: std.Io.Writer = .fixed(buf);
    const len = 1 + 2 + 2 + pk.len + 2 + suites.len + 1 + 1 + name.len + 2 + exts.len;
    w.writeInt(u16, v, .big) catch unreachable;
    w.writeInt(u16, @intCast(len), .big) catch unreachable;
    w.writeByte(id) catch unreachable;
    w.writeInt(u16, kem, .big) catch unreachable;
    w.writeInt(u16, @intCast(pk.len), .big) catch unreachable;
    w.writeAll(pk) catch unreachable;
    w.writeInt(u16, @intCast(suites.len), .big) catch unreachable;
    w.writeAll(suites) catch unreachable;
    w.writeByte(0) catch unreachable;
    w.writeByte(@intCast(name.len)) catch unreachable;
    w.writeAll(name) catch unreachable;
    w.writeInt(u16, @intCast(exts.len), .big) catch unreachable;
    w.writeAll(exts) catch unreachable;
    return w.buffered();
}

fn testList(buf: []u8, configs: []const []const u8) []u8 {
    var n: usize = 0;
    for (configs) |c| n += c.len;
    std.mem.writeInt(u16, buf[0..2], @intCast(n), .big);
    var at: usize = 2;
    for (configs) |c| {
        @memcpy(buf[at..][0..c.len], c);
        at += c.len;
    }
    return buf[0..at];
}

test "ech pick: the first usable config and its first usable suite; skipped versions, KEMs, names, mandatory extensions" {
    const pk: [32]u8 = @splat(7);
    var b1: [128]u8 = undefined;
    var b2: [128]u8 = undefined;
    var b3: [128]u8 = undefined;
    var b4: [128]u8 = undefined;
    var b5: [128]u8 = undefined;
    var b6: [128]u8 = undefined;
    const other_version = testConfig(&b1, 0xfe0c, 1, kem_x25519, &pk, &.{ 0, 1, 0, 1 }, "a.example", "");
    const p256_pk: [65]u8 = @splat(4);
    const p256 = testConfig(&b2, version, 2, 0x0010, &p256_pk, &.{ 0, 1, 0, 1 }, "a.example", "");
    const ip_name = testConfig(&b3, version, 3, kem_x25519, &pk, &.{ 0, 1, 0, 1 }, "192.0.2.1", "");
    const mandatory = testConfig(&b4, version, 4, kem_x25519, &pk, &.{ 0, 1, 0, 1 }, "a.example", &.{ 0x80, 0x01, 0, 0 });
    const good = testConfig(&b5, version, 5, kem_x25519, &pk, &.{ 0, 2, 0, 1, 0, 1, 0, 3, 0, 1, 0, 1 }, "public.example", &.{ 0x00, 0x01, 0, 1, 9 });
    const later = testConfig(&b6, version, 6, kem_x25519, &pk, &.{ 0, 1, 0, 1 }, "b.example", "");
    var lb: [1024]u8 = undefined;
    const list = testList(&lb, &.{ other_version, p256, ip_name, mandatory, good, later });
    const p = try pick(list);
    try testing.expectEqual(@as(u8, 5), p.config_id);
    try testing.expectEqual(aead_chacha20_poly1305, p.aead);
    try testing.expectEqualStrings("public.example", p.public_name);
    try testing.expectEqualSlices(u8, good, p.raw);
    // Nothing usable; a malformed list; a length that is not the list's.
    try testing.expectError(error.EchConfigUnsupported, pick(testList(&lb, &.{ other_version, p256, ip_name, mandatory })));
    try testing.expectError(error.EchConfigInvalid, pick(list[0 .. list.len - 1]));
    try testing.expectError(error.EchConfigInvalid, pick(&.{0}));
    try testing.expectError(error.EchConfigUnsupported, pick(&.{ 0, 0 }));
    // A malformed config behind the usable one still fails the list (Go).
    const bad = [_]u8{ 0xfe, 0x0d, 0, 1, 5 };
    var lb2: [1024]u8 = undefined;
    try testing.expectError(error.EchConfigInvalid, pick(testList(&lb2, &.{ good, &bad })));
}

test "ech validPublicName: Go's rules and no IPv4 address" {
    try testing.expect(validPublicName("public.example"));
    try testing.expect(validPublicName("a-b.c0.example"));
    const long: [64]u8 = @splat('a');
    try testing.expect(!validPublicName(&(long ++ ".b".*)));
    for ([_][]const u8{ "", "example", "a..b", "-a.b", "a-.b", "a_b.c", "192.0.2.1", "a.b." }) |n|
        try testing.expect(!validPublicName(n));
}

test "ech encodeInner: empty session id, §6.1.3 padding to a multiple of 32" {
    var msg: [200]u8 = undefined;
    @memset(&msg, 0xaa);
    msg[0] = 1;
    msg[4 + 34] = 32;
    var out: [512]u8 = undefined;
    for ([_]struct { usize, u8 }{ .{ 10, 0 }, .{ 10, 64 }, .{ 0, 0 }, .{ 0, 32 }, .{ 70, 64 } }) |case| {
        const e = try encodeInner(&out, &msg, case[0], case[1]);
        try testing.expectEqual(@as(usize, 0), e.len % 32);
        try testing.expectEqual(@as(u8, 0), e[34]);
        const unpadded = 196 - 32;
        const name_pad: usize = if (case[0] != 0) (if (case[1] > case[0]) case[1] - case[0] else 0) else @as(usize, case[1]) + 9;
        try testing.expect(e.len >= unpadded + name_pad and e.len < unpadded + name_pad + 32);
        try testing.expectEqualSlices(u8, msg[4 + 35 + 32 ..], e[35..unpadded]);
        try testing.expect(std.mem.allEqual(u8, e[unpadded..], 0));
    }
    try testing.expectError(error.NoSpaceLeft, encodeInner(out[0..100], &msg, 0, 0));
}

test "ech outerExt and findExt: the payload is the extension's tail" {
    const pk: [32]u8 = @splat(7);
    const p: Picked = .{ .raw = "", .config_id = 9, .public_key = &pk, .kdf = 1, .aead = 2, .maximum_name_length = 0, .public_name = "a.example" };
    var buf: [128]u8 = undefined;
    const enc: [32]u8 = @splat(3);
    const ext = try outerExt(&buf, &p, &enc, 40);
    try testing.expectEqual(@as(usize, 4 + 1 + 2 + 2 + 1 + 2 + 32 + 2 + 40), ext.len);
    try testing.expectEqualSlices(u8, &.{ 0xfe, 0x0d }, ext[0..2]);
    try testing.expectEqual(@as(u8, 9), ext[9]);
    try testing.expect(std.mem.allEqual(u8, ext[ext.len - 40 ..], 0));
    try testing.expectError(error.NoSpaceLeft, outerExt(buf[0..50], &p, &enc, 40));
    const second = try outerExt(&buf, &p, "", 40);
    try testing.expectEqual(@as(usize, 4 + 1 + 2 + 2 + 1 + 2 + 2 + 40), second.len);
}

test "ech Sealer: what the server side opens (hpke setupBaseR with the config's key)" {
    const kp = std.crypto.dh.X25519.KeyPair.generateDeterministic(@splat(3));
    var cb: [128]u8 = undefined;
    const cfg = testConfig(&cb, version, 5, kem_x25519, &kp.public_key, &.{ 0, 1, 0, 1 }, "public.example", "");
    var lb: [256]u8 = undefined;
    const p = try pick(testList(&lb, &.{cfg}));
    var s: Sealer = undefined;
    const ikm: [32]u8 = @splat(1);
    try s.setup(&p, &ikm);
    defer s.wipe();
    var ct: [5 + tag_len]u8 = undefined;
    try s.seal("aad", "hello", &ct);
    var info: [8 + 128]u8 = undefined;
    @memcpy(info[0..8], "tls ech\x00");
    @memcpy(info[8..][0..cfg.len], cfg);
    var r: hpke.Context(aesgcm.Aes128Gcm, 32) = undefined;
    const rkp: X25519Kem.KeyPair = .{ .public_key = kp.public_key, .secret_key = kp.secret_key };
    try hpke.setupBaseR(X25519Kem, aesgcm.Aes128Gcm, 32, &r, s.enc().*, &rkp, info[0 .. 8 + cfg.len]);
    var pt: [5]u8 = undefined;
    try r.open("aad", &ct, &pt);
    try testing.expectEqualStrings("hello", &pt);
}
