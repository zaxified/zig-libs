// SPDX-License-Identifier: MIT

//! tlsserver.ech — TLS Encrypted Client Hello (RFC 9849), the
//! client-facing server's part in shared mode: the client encrypts its real
//! ClientHello (the "inner", with the real SNI) to the server's ECH key and
//! sends it inside an innocuous "outer" one naming a public name.
//!
//! - **Config** (§4): `ECHConfig` version 0xfe0d — `HpkeKeyConfig`
//!   (config_id, KEM, public key, KDF/AEAD pairs), the maximum name length,
//!   the public name, extensions. Here: DHKEM(X25519, HKDF-SHA256) with
//!   HKDF-SHA256 and AES-128-GCM, AES-256-GCM or ChaCha20-Poly1305 (Go's
//!   and BoringSSL's set). `makeConfig` / `configList` build them.
//! - **Offer** (§5): the outer ClientHello's `encrypted_client_hello`
//!   (`ECHClientHello` of type outer: cipher suite, config_id, `enc`,
//!   payload); `parseOffer`.
//! - **Decryption** (§7.1): the key whose config_id and suite match; HPKE
//!   `SetupBaseR(enc, skR, "tls ech" ‖ 0x00 ‖ ECHConfig)`, then
//!   `Open(ClientHelloOuterAAD, payload)` — the outer ClientHello with the
//!   payload zeroed (`Opener`). After a HelloRetryRequest the second payload
//!   opens under the same context (sequence 1).
//! - **Reconstruction** (§5.1): `EncodedClientHelloInner` is a ClientHello
//!   body with an empty `legacy_session_id`, then zero padding; the outer's
//!   session id goes in, and `ech_outer_extensions` (0xfd00) is replaced by
//!   the outer extensions it names, which must exist, in the same relative
//!   order, once each, never `encrypted_client_hello` — in one forward pass
//!   over the outer list (linear, Appendix A).
//! - **Confirmation** (§7.2): `HKDF-Expand-Label(HKDF-Extract(0,
//!   ClientHelloInner.random), "ech accept confirmation", transcript, 8)`,
//!   in the ServerHello's last 8 random octets ("hrr ech accept
//!   confirmation" in a HelloRetryRequest's extension); `confirmation`.

const std = @import("std");
const hpke = @import("hpke");
const tls13 = @import("tls13");
const aesgcm = @import("aesgcm");
const chachapoly = @import("chachapoly");
const hello = @import("hello.zig");

pub const version: u16 = 0xfe0d;
pub const ext_encrypted_client_hello: u16 = 0xfe0d;
pub const ext_ech_outer_extensions: u16 = 0xfd00;

pub const kem_x25519: u16 = 0x0020;

/// The longest `ECHConfig` served (its HPKE `info` is built on the stack).
pub const max_config_len = 1024;
pub const kdf_hkdf_sha256: u16 = 0x0001;
pub const aead_aes128_gcm: u16 = 0x0001;
pub const aead_aes256_gcm: u16 = 0x0002;
pub const aead_chacha20_poly1305: u16 = 0x0003;

const X25519Kem = hpke.X25519Kem;

/// One ECH key: an `ECHConfig` as published (in DNS HTTPS records) and the
/// X25519 private key of its public key (Go `EncryptedClientHelloKey`,
/// BoringSSL `SSL_ECH_KEYS_add`).
pub const Key = struct {
    /// One `ECHConfig`: version, length, contents.
    config: []const u8,
    /// Borrowed: must outlive the connections.
    private_key: *const [32]u8,
    /// Sent in `retry_configs` when ECH is declined (Go `SendAsRetry`,
    /// BoringSSL `is_retry_config`).
    retry: bool = true,
};

/// `Config.ech`.
pub const Ech = struct {
    /// Tried in order for an offer's config_id (a repeated config_id is
    /// tried with each key: trial decryption among them).
    keys: []const Key,
    /// An outer ClientHello body longer than this is not decrypted (ECH
    /// declined, `retry_configs` sent). The server's ECH buffer is
    /// `bufferLen(max_client_hello_len)`.
    max_client_hello_len: u16 = 8192,

    pub const CheckError = ParseError || error{
        /// No key, or a config that is not X25519 / has no suite served /
        /// is over `max_config_len` octets.
        Unsupported,
        /// The private key's public half is not the config's.
        KeyMismatch,
        /// The retry list would overflow its 2-octet length.
        TooManyRetryConfigs,
    };

    /// What a handshake would find wrong with the keys, up front.
    // secret-api-ok: derives each private key's public half to compare with the config (burned by std's scalarmult frame; no copy kept).
    pub fn check(self: *const Ech) CheckError!void {
        if (self.keys.len == 0) return error.Unsupported;
        var retry_len: usize = 0;
        for (self.keys) |k| {
            const c = try parseConfig(k.config);
            if (c.kem_id != kem_x25519 or c.public_key.len != 32 or k.config.len > max_config_len) return error.Unsupported;
            var any = false;
            var it = c.suites();
            while (it.next()) |s| any = any or supported(s.kdf, s.aead);
            if (!any) return error.Unsupported;
            const public = std.crypto.dh.X25519.recoverPublicKey(k.private_key.*);
            if (!std.mem.eql(u8, &public, c.public_key)) return error.KeyMismatch;
            if (k.retry) retry_len += k.config.len;
        }
        if (retry_len > std.math.maxInt(u16)) return error.TooManyRetryConfigs;
    }
};

/// The server's ECH buffer for outer ClientHellos up to `max_len` octets:
/// the AAD copy, the decrypted payload and the rebuilt inner ClientHello.
pub fn bufferLen(max_len: usize) usize {
    return 4 + 4 * max_len;
}

pub fn supported(kdf: u16, aead: u16) bool {
    return kdf == kdf_hkdf_sha256 and (aead == aead_aes128_gcm or aead == aead_aes256_gcm or aead == aead_chacha20_poly1305);
}

pub const ParseError = error{
    /// Not a well-formed `ECHConfig` of version 0xfe0d.
    InvalidConfig,
};

pub const Suite = struct { kdf: u16, aead: u16 };

pub const SuiteIter = struct {
    rest: []const u8,

    pub fn next(it: *SuiteIter) ?Suite {
        if (it.rest.len < 4) return null;
        defer it.rest = it.rest[4..];
        return .{ .kdf = std.mem.readInt(u16, it.rest[0..2], .big), .aead = std.mem.readInt(u16, it.rest[2..4], .big) };
    }
};

pub const Config = struct {
    config_id: u8,
    kem_id: u16,
    public_key: []const u8,
    suites_raw: []const u8,
    maximum_name_length: u8,
    public_name: []const u8,

    pub fn suites(c: Config) SuiteIter {
        return .{ .rest = c.suites_raw };
    }
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

/// One `ECHConfig` (version, length, contents), exactly.
pub fn parseConfig(raw: []const u8) ParseError!Config {
    var r: Reader = .{ .buf = raw };
    if ((r.int(u16) orelse return error.InvalidConfig) != version) return error.InvalidConfig;
    const contents = r.vec(u16) orelse return error.InvalidConfig;
    if (r.left() != 0) return error.InvalidConfig;
    var c: Reader = .{ .buf = contents };
    const id = c.int(u8) orelse return error.InvalidConfig;
    const kem = c.int(u16) orelse return error.InvalidConfig;
    const pk = c.vec(u16) orelse return error.InvalidConfig;
    const suites = c.vec(u16) orelse return error.InvalidConfig;
    if (suites.len < 4 or suites.len % 4 != 0) return error.InvalidConfig;
    const max_name = c.int(u8) orelse return error.InvalidConfig;
    const name = c.vec(u8) orelse return error.InvalidConfig;
    if (name.len == 0) return error.InvalidConfig;
    const exts = c.vec(u16) orelse return error.InvalidConfig;
    _ = exts;
    if (c.left() != 0 or pk.len == 0) return error.InvalidConfig;
    return .{ .config_id = id, .kem_id = kem, .public_key = pk, .suites_raw = suites, .maximum_name_length = max_name, .public_name = name };
}

/// An `ECHConfig` for an X25519 public key, offering HKDF-SHA256 with
/// AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, no extensions.
pub fn makeConfig(out: []u8, config_id: u8, public_key: *const [32]u8, public_name: []const u8, maximum_name_length: u8) error{BufferTooSmall}![]u8 {
    if (public_name.len == 0 or public_name.len > 255) return error.BufferTooSmall;
    const contents_len = 1 + 2 + 2 + 32 + 2 + 12 + 1 + 1 + public_name.len + 2;
    if (out.len < 4 + contents_len) return error.BufferTooSmall;
    var w: std.Io.Writer = .fixed(out);
    w.writeInt(u16, version, .big) catch unreachable;
    w.writeInt(u16, @intCast(contents_len), .big) catch unreachable;
    w.writeByte(config_id) catch unreachable;
    w.writeInt(u16, kem_x25519, .big) catch unreachable;
    w.writeInt(u16, 32, .big) catch unreachable;
    w.writeAll(public_key) catch unreachable;
    w.writeInt(u16, 12, .big) catch unreachable;
    for ([_]u16{ aead_aes128_gcm, aead_aes256_gcm, aead_chacha20_poly1305 }) |a| {
        w.writeInt(u16, kdf_hkdf_sha256, .big) catch unreachable;
        w.writeInt(u16, a, .big) catch unreachable;
    }
    w.writeByte(maximum_name_length) catch unreachable;
    w.writeByte(@intCast(public_name.len)) catch unreachable;
    w.writeAll(public_name) catch unreachable;
    w.writeInt(u16, 0, .big) catch unreachable;
    return w.buffered();
}

/// An `ECHConfigList` (what a DNS HTTPS record's `ech` carries, and what
/// `retry_configs` is) of the given configs, in order.
pub fn configList(out: []u8, configs: []const []const u8) error{BufferTooSmall}![]u8 {
    var n: usize = 0;
    for (configs) |c| n += c.len;
    if (n > std.math.maxInt(u16) or out.len < 2 + n) return error.BufferTooSmall;
    std.mem.writeInt(u16, out[0..2], @intCast(n), .big);
    var at: usize = 2;
    for (configs) |c| {
        @memcpy(out[at..][0..c.len], c);
        at += c.len;
    }
    return out[0..at];
}

/// `retry_configs`: the keys marked `retry`, as an `ECHConfigList`.
// secret-api-ok: copies the public configs only, never a private key.
pub fn retryConfigs(out: []u8, e: *const Ech) error{BufferTooSmall}![]u8 {
    var n: usize = 0;
    for (e.keys) |k| {
        if (!k.retry) continue;
        if (out.len < 2 + n + k.config.len) return error.BufferTooSmall;
        @memcpy(out[2 + n ..][0..k.config.len], k.config);
        n += k.config.len;
    }
    if (n > std.math.maxInt(u16)) return error.BufferTooSmall;
    std.mem.writeInt(u16, out[0..2], @intCast(n), .big);
    return out[0 .. 2 + n];
}

pub const Error = error{
    /// Malformed offer or encoded inner hello (`decode_error`).
    DecodeError,
    /// An offer of an unknown type (`illegal_parameter`).
    IllegalParameter,
    /// An `ech_outer_extensions` reference to an extension the outer hello
    /// lacks, out of order, repeated, or to `encrypted_client_hello`
    /// (`illegal_parameter`; BoringSSL `INVALID_OUTER_EXTENSION`).
    InvalidOuterExtension,
    /// Non-zero padding after the encoded inner hello, or a session id in
    /// it (`illegal_parameter`).
    InvalidPadding,
    /// The second offer changed its suite or config_id, or carried an
    /// `enc` (`illegal_parameter`).
    OfferChanged,
    /// The second payload did not open (`decrypt_error`).
    DecryptError,
};

/// The outer ClientHello's `ECHClientHello` of type outer.
pub const Offer = struct {
    kdf: u16,
    aead: u16,
    config_id: u8,
    enc: []const u8,
    payload: []const u8,
};

pub const OfferKind = union(enum) {
    outer: Offer,
    /// `ECHClientHello` of type inner: valid only in an inner hello.
    inner,
};

/// RFC 9849 §5: type outer (0) or inner (1, empty); anything else is
/// `illegal_parameter`.
pub fn parseOffer(data: []const u8) Error!OfferKind {
    var r: Reader = .{ .buf = data };
    const t = r.int(u8) orelse return error.DecodeError;
    switch (t) {
        1 => {
            if (r.left() != 0) return error.DecodeError;
            return .inner;
        },
        0 => {},
        else => return error.IllegalParameter,
    }
    const kdf = r.int(u16) orelse return error.DecodeError;
    const aead = r.int(u16) orelse return error.DecodeError;
    const id = r.int(u8) orelse return error.DecodeError;
    const enc = r.vec(u16) orelse return error.DecodeError;
    const payload = r.vec(u16) orelse return error.DecodeError;
    if (r.left() != 0 or payload.len == 0) return error.DecodeError;
    return .{ .outer = .{ .kdf = kdf, .aead = aead, .config_id = id, .enc = enc, .payload = payload } };
}

/// The HPKE receiver context of an accepted offer, kept for the second
/// ClientHello. Holds a key: wipe it (`wipe`).
pub const Opener = union(enum) {
    aes128: hpke.Context(aesgcm.Aes128Gcm, 32),
    aes256: hpke.Context(aesgcm.Aes256Gcm, 32),
    chacha: hpke.Context(chachapoly.ChaCha20Poly1305, 32),

    pub fn wipe(self: *Opener) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    /// `SetupBaseR` for `offer` under `key` (whose config is `config`).
    // secret-api-ok: the private key is copied into one KeyPair local, wiped on return; hpke's decap runs under its own burn.
    fn setup(self: *Opener, key: *const Key, config: *const Config, offer: *const Offer) bool {
        if (offer.enc.len != @typeInfo(X25519Kem.EncappedKey).array.len) return false;
        var info: [8 + max_config_len]u8 = undefined;
        if (key.config.len > max_config_len) return false;
        @memcpy(info[0..8], "tls ech\x00");
        @memcpy(info[8..][0..key.config.len], key.config);
        var kp: X25519Kem.KeyPair = .{ .public_key = config.public_key[0..32].*, .secret_key = key.private_key.* };
        defer std.crypto.secureZero(u8, &kp.secret_key);
        const enc = offer.enc[0..32].*;
        const i = info[0 .. 8 + key.config.len];
        switch (offer.aead) {
            aead_aes128_gcm => {
                self.* = .{ .aes128 = undefined };
                hpke.setupBaseR(X25519Kem, aesgcm.Aes128Gcm, 32, &self.aes128, enc, &kp, i) catch return false;
            },
            aead_aes256_gcm => {
                self.* = .{ .aes256 = undefined };
                hpke.setupBaseR(X25519Kem, aesgcm.Aes256Gcm, 32, &self.aes256, enc, &kp, i) catch return false;
            },
            aead_chacha20_poly1305 => {
                self.* = .{ .chacha = undefined };
                hpke.setupBaseR(X25519Kem, chachapoly.ChaCha20Poly1305, 32, &self.chacha, enc, &kp, i) catch return false;
            },
            else => return false,
        }
        return true;
    }

    /// Open `payload` with `aad` into `out` (payload less the tag).
    fn open(self: *Opener, aad: []const u8, payload: []const u8, out: []u8) bool {
        switch (self.*) {
            inline else => |*c| c.open(aad, payload, out) catch return false,
        }
        return true;
    }
};

/// The outer ClientHello `body` with the offer's payload zeroed: the AAD
/// (§5.2), into `out`.
fn outerAad(body: []const u8, payload: []const u8, out: []u8) []u8 {
    const at = @intFromPtr(payload.ptr) - @intFromPtr(body.ptr);
    @memcpy(out[0..body.len], body);
    @memset(out[at..][0..payload.len], 0);
    return out[0..body.len];
}

/// The first ClientHello: try each key with the offer's config_id and a
/// suite it serves. The rebuilt inner ClientHello (a whole handshake
/// message) in `buf`, and `opener` set; null: none opened (ECH declined).
/// `buf` is `bufferLen(e.max_client_hello_len)` octets.
pub fn openFirst(e: *const Ech, outer: *const hello.ClientHello, body: []const u8, offer: *const Offer, buf: []u8, opener: *Opener) Error!?[]u8 {
    if (body.len > e.max_client_hello_len or buf.len < bufferLen(body.len)) return null;
    if (!supported(offer.kdf, offer.aead) or offer.payload.len <= 16) return null;
    const aad = outerAad(body, offer.payload, buf);
    const plain = buf[body.len..][0 .. offer.payload.len - 16];
    for (e.keys) |*k| {
        const c = parseConfig(k.config) catch continue;
        // `check` refuses these; a key that skipped it must not panic here.
        if (c.config_id != offer.config_id or c.kem_id != kem_x25519 or c.public_key.len != 32 or k.config.len > max_config_len) continue;
        var served = false;
        var it = c.suites();
        while (it.next()) |s| served = served or (s.kdf == offer.kdf and s.aead == offer.aead);
        if (!served) continue;
        if (!opener.setup(k, &c, offer)) continue;
        if (!opener.open(aad, offer.payload, plain)) {
            opener.wipe();
            continue;
        }
        return try reconstruct(plain, outer, buf[body.len + plain.len ..]);
    }
    return null;
}

/// The second ClientHello after a HelloRetryRequest, ECH accepted on the
/// first: the same config_id and suite, an empty `enc`
/// (`illegal_parameter` otherwise), the payload opened under the same
/// context (`decrypt_error`).
pub fn openSecond(first: *const Offer, opener: *Opener, outer: *const hello.ClientHello, body: []const u8, offer: *const Offer, buf: []u8) Error![]u8 {
    if (offer.kdf != first.kdf or offer.aead != first.aead or offer.config_id != first.config_id or offer.enc.len != 0)
        return error.OfferChanged;
    if (buf.len < bufferLen(body.len) or offer.payload.len <= 16) return error.DecryptError;
    const aad = outerAad(body, offer.payload, buf);
    const plain = buf[body.len..][0 .. offer.payload.len - 16];
    if (!opener.open(aad, offer.payload, plain)) return error.DecryptError;
    return reconstruct(plain, outer, buf[body.len + plain.len ..]);
}

/// §5.1: `EncodedClientHelloInner` → the ClientHelloInner message (with its
/// 4-octet header) in `out`.
pub fn reconstruct(encoded: []const u8, outer: *const hello.ClientHello, out: []u8) Error![]u8 {
    var r: Reader = .{ .buf = encoded };
    const fixed = r.take(2 + 32) orelse return error.DecodeError;
    const sid = r.vec(u8) orelse return error.DecodeError;
    if (sid.len != 0) return error.InvalidPadding;
    const suites_at = r.at;
    _ = r.vec(u16) orelse return error.DecodeError;
    _ = r.vec(u8) orelse return error.DecodeError;
    const suites_and_compression = encoded[suites_at..r.at];
    const exts = r.vec(u16) orelse return error.DecodeError;
    // Padding: zeros only.
    for (encoded[r.at..]) |b| if (b != 0) return error.InvalidPadding;

    var w: std.Io.Writer = .fixed(out);
    const put = struct {
        fn f(wr: *std.Io.Writer, bytes: []const u8) Error!void {
            wr.writeAll(bytes) catch return error.DecodeError;
        }
    }.f;
    try put(&w, &.{ 1, 0, 0, 0 });
    try put(&w, fixed);
    try put(&w, &.{@intCast(outer.legacy_session_id.len)});
    try put(&w, outer.legacy_session_id);
    try put(&w, suites_and_compression);
    const exts_len_at = w.end;
    try put(&w, &.{ 0, 0 });

    // The outer extensions, walked once, forward.
    var outer_rest = outer.extensions_raw;
    var e: Reader = .{ .buf = exts };
    while (e.left() != 0) {
        const t = e.int(u16) orelse return error.DecodeError;
        const data = e.vec(u16) orelse return error.DecodeError;
        if (t != ext_ech_outer_extensions) {
            try put(&w, encoded[@intFromPtr(data.ptr) - @intFromPtr(encoded.ptr) - 4 ..][0 .. 4 + data.len]);
            continue;
        }
        var refs: Reader = .{ .buf = data };
        const list = refs.vec(u8) orelse return error.DecodeError;
        if (refs.left() != 0 or list.len < 2 or list.len % 2 != 0) return error.DecodeError;
        var i: usize = 0;
        while (i < list.len) : (i += 2) {
            const want = std.mem.readInt(u16, list[i..][0..2], .big);
            if (want == ext_encrypted_client_hello) return error.InvalidOuterExtension;
            // Forward from the last reference: missing, repeated and out
            // of order all end up past the end.
            while (true) {
                if (outer_rest.len < 4) return error.InvalidOuterExtension;
                const ot = std.mem.readInt(u16, outer_rest[0..2], .big);
                const ol: usize = std.mem.readInt(u16, outer_rest[2..4], .big);
                const whole = outer_rest[0 .. 4 + ol];
                outer_rest = outer_rest[4 + ol ..];
                if (ot == want) {
                    try put(&w, whole);
                    break;
                }
            }
        }
    }
    const exts_len = w.end - exts_len_at - 2;
    if (exts_len > std.math.maxInt(u16)) return error.DecodeError;
    std.mem.writeInt(u16, out[exts_len_at..][0..2], @intCast(exts_len), .big);
    const body_len = w.end - 4;
    std.mem.writeInt(u24, out[1..4], @intCast(body_len), .big);
    return out[0..w.end];
}

/// §7.2: the 8 confirmation octets over `transcript_hash` (`label`: "ech
/// accept confirmation", or "hrr ech accept confirmation").
pub fn confirmation(comptime Hkdf: type, inner_random: *const [32]u8, label: []const u8, transcript_hash: []const u8) [8]u8 {
    const zeros: [Hkdf.prk_length]u8 = @splat(0);
    const prk = Hkdf.extract(&zeros, inner_random);
    var out: [8]u8 = undefined;
    tls13.keyschedule.expandLabel(Hkdf, "tls13 ", 8, &out, &prk, label, transcript_hash);
    return out;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "configs: make, parse, list; check refuses a key that is not the config's" {
    const kp = std.crypto.dh.X25519.KeyPair.generateDeterministic(@splat(3));
    var buf: [256]u8 = undefined;
    const cfg = try makeConfig(&buf, 42, &kp.public_key, "public.example", 0);
    const c = try parseConfig(cfg);
    try testing.expectEqual(@as(u8, 42), c.config_id);
    try testing.expectEqualStrings("public.example", c.public_name);
    try testing.expectEqualSlices(u8, &kp.public_key, c.public_key);
    var it = c.suites();
    try testing.expectEqual(Suite{ .kdf = 1, .aead = 1 }, it.next().?);
    const e: Ech = .{ .keys = &.{.{ .config = cfg, .private_key = &kp.secret_key }} };
    try e.check();
    const other: [32]u8 = @splat(9);
    try testing.expectError(error.KeyMismatch, (Ech{ .keys = &.{.{ .config = cfg, .private_key = &other }} }).check());
    try testing.expectError(error.InvalidConfig, parseConfig(cfg[0 .. cfg.len - 1]));
    var lb: [512]u8 = undefined;
    const list = try configList(&lb, &.{ cfg, cfg });
    try testing.expectEqual(@as(usize, 2 + 2 * cfg.len), list.len);
    try testing.expectEqualSlices(u8, list, try retryConfigs(&lb, &.{ .keys = &.{ .{ .config = cfg, .private_key = &kp.secret_key }, .{ .config = "x", .private_key = &kp.secret_key, .retry = false }, .{ .config = cfg, .private_key = &kp.secret_key } } }));
}

test "parseOffer: outer, inner, other types" {
    try testing.expectEqual(OfferKind.inner, try parseOffer(&.{1}));
    try testing.expectError(error.DecodeError, parseOffer(&.{ 1, 0 }));
    try testing.expectError(error.IllegalParameter, parseOffer(&.{2}));
    const o = (try parseOffer(&.{ 0, 0, 1, 0, 3, 42, 0, 2, 0xaa, 0xbb, 0, 1, 0xcc })).outer;
    try testing.expectEqual(@as(u8, 42), o.config_id);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, o.enc);
    try testing.expectError(error.DecodeError, parseOffer(&.{ 0, 0, 1, 0, 3, 42, 0, 0, 0, 0 }));
}

/// A ClientHello body with the given extensions (type, data).
fn helloBody(buf: []u8, session_id: []const u8, exts: []const struct { u16, []const u8 }) []u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.writeAll(&.{ 3, 3 }) catch unreachable;
    w.splatByteAll(5, 32) catch unreachable;
    w.writeByte(@intCast(session_id.len)) catch unreachable;
    w.writeAll(session_id) catch unreachable;
    w.writeAll(&.{ 0, 2, 0x13, 0x01, 1, 0 }) catch unreachable;
    var n: usize = 0;
    for (exts) |e| n += 4 + e[1].len;
    w.writeInt(u16, @intCast(n), .big) catch unreachable;
    for (exts) |e| {
        w.writeInt(u16, e[0], .big) catch unreachable;
        w.writeInt(u16, @intCast(e[1].len), .big) catch unreachable;
        w.writeAll(e[1]) catch unreachable;
    }
    return w.buffered();
}

test "reconstruct: outer extensions in relative order, the outer session id, padding" {
    var ob: [512]u8 = undefined;
    const outer_body = helloBody(&ob, &.{ 7, 7, 7 }, &.{ .{ 10, &.{ 0, 2, 0, 0x1d } }, .{ 0x1234, "abc" }, .{ 13, &.{ 0, 2, 4, 3 } }, .{ 0x5678, "z" } });
    const outer = try hello.parseClientHello(outer_body);
    var eb: [512]u8 = undefined;
    // Inner: an extension of its own, then references to 10 and 13, then
    // another of its own; padded.
    const enc = helloBody(&eb, "", &.{ .{ 43, &.{ 2, 3, 4 } }, .{ 0xfd00, &.{ 4, 0, 10, 0, 13 } }, .{ 0xfe0d, &.{1} } });
    const padded_len = enc.len + 5;
    @memset(eb[enc.len..padded_len], 0);
    var out: [1024]u8 = undefined;
    const msg = try reconstruct(eb[0..padded_len], &outer, &out);
    const inner = try hello.parseClientHello(msg[4..]);
    try testing.expectEqual(@as(u8, 1), msg[0]);
    try testing.expectEqualSlices(u8, &.{ 7, 7, 7 }, inner.legacy_session_id);
    try testing.expectEqual(@as(usize, 4), inner.extension_count);
    try testing.expect(inner.supportedGroups().?.contains(0x1d));
    try testing.expect(inner.signatureAlgorithms().?.contains(0x0403));
    // Non-zero padding; a session id in the encoded hello.
    eb[padded_len - 1] = 1;
    try testing.expectError(error.InvalidPadding, reconstruct(eb[0..padded_len], &outer, &out));
    const with_sid = helloBody(&eb, &.{1}, &.{.{ 43, &.{ 2, 3, 4 } }});
    try testing.expectError(error.InvalidPadding, reconstruct(with_sid, &outer, &out));
    // Wrong order, a repeat, a missing one, encrypted_client_hello itself.
    for ([_][]const u8{ &.{ 4, 0, 13, 0, 10 }, &.{ 4, 0, 10, 0, 10 }, &.{ 2, 0, 99 }, &.{ 2, 0xfe, 0x0d } }) |refs| {
        const bad = helloBody(&eb, "", &.{.{ 0xfd00, refs }});
        try testing.expectError(error.InvalidOuterExtension, reconstruct(bad, &outer, &out));
    }
    // Two reference lists continue where the first stopped.
    const two = helloBody(&eb, "", &.{ .{ 0xfd00, &.{ 2, 0x12, 0x34 } }, .{ 0xfd00, &.{ 2, 0x56, 0x78 } } });
    _ = try reconstruct(two, &outer, &out);
}
