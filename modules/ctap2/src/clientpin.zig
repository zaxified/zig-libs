// SPDX-License-Identifier: MIT
//! `authenticatorClientPIN` (0x06, CTAP 2.1 §6.5.5): the platform side of every
//! PIN subcommand, over a caller-supplied `Transport`.
//!
//! All cryptography is `ctap2pin`'s (ECDH-P256, KDFs, AES-256-CBC, HMAC); all
//! CBOR is `cbor`'s. This file owns only the command layer: which keys go in
//! which request, what is authenticated over which bytes, what a response must
//! contain, and the PIN rules of §6.5.5.5.
//!
//! One transaction = one fresh key agreement. Every method that needs a shared
//! secret runs `getKeyAgreement`, draws a fresh platform scalar from the
//! caller's `std.Random`, and wipes the secret before it returns.

const std = @import("std");
const cbor = @import("cbor");
const ctap2pin = @import("ctap2pin");
const framing = @import("framing.zig");
const getinfo = @import("getinfo.zig");

const Allocator = std.mem.Allocator;
const Protocol = ctap2pin.Protocol;
const PublicKey = ctap2pin.PublicKey;
const Value = cbor.Value;
const MapEntry = cbor.MapEntry;

/// `authenticatorClientPIN` subCommand numbers (§6.5.5).
pub const SubCommand = enum(u8) {
    get_pin_retries = 0x01,
    get_key_agreement = 0x02,
    set_pin = 0x03,
    change_pin = 0x04,
    /// Superseded by 0x06 / 0x09; kept for CTAP 2.0 authenticators.
    get_pin_token = 0x05,
    get_pin_uv_auth_token_using_uv_with_permissions = 0x06,
    get_uv_retries = 0x07,
    get_pin_uv_auth_token_using_pin_with_permissions = 0x09,
};

/// pinUvAuthToken permissions (§6.5.5.7). `rp_id` is required for `mc`/`ga`,
/// optional for `cm`, ignored for the rest.
pub const Permissions = packed struct(u8) {
    mc: bool = false,
    ga: bool = false,
    cm: bool = false,
    be: bool = false,
    lbw: bool = false,
    acfg: bool = false,
    _reserved: u2 = 0,

    pub fn toInt(self: Permissions) u8 {
        return @bitCast(self);
    }
};

// ── PIN rules (§6.5.5.5 / §6.5.5.6) ─────────────────────────────────────────

pub const PinError = error{
    /// Fewer Unicode code points than the platform minimum (4, or the
    /// authenticator's `minPINLength`).
    PinTooShort,
    /// More than 63 bytes of UTF-8.
    PinTooLong,
    /// The bytes are not valid UTF-8.
    PinNotUtf8,
};

/// The longest PIN in bytes of UTF-8; the wire block is one byte longer so
/// there is always a padding byte.
pub const max_pin_bytes = 63;
pub const padded_pin_len = 64;
/// The default minimum length in Unicode code points.
pub const default_min_pin_code_points = 4;

/// Check a NEW PIN: valid UTF-8, at least `min_code_points` code points
/// (the spec's default is 4; `Info.effectiveMinPinLength()` gives the
/// authenticator's) and at most 63 bytes.
///
/// The caller supplies the PIN in Normalization Form C, as the spec requires;
/// this module does not normalize (see SPEC.md, Backlog).
pub fn validateNewPin(pin: []const u8, min_code_points: u32) PinError!void {
    const count = std.unicode.utf8CountCodepoints(pin) catch return error.PinNotUtf8;
    if (pin.len > max_pin_bytes) return error.PinTooLong;
    if (count < @max(min_code_points, default_min_pin_code_points)) return error.PinTooShort;
}

/// Check the CURRENT PIN the user typed: at most 63 bytes (an older PIN may
/// be shorter than today's policy, so no minimum applies).
pub fn validateCurrentPin(pin: []const u8) PinError!void {
    if (pin.len > max_pin_bytes) return error.PinTooLong;
}

/// `newPin` right-padded with 0x00 to 64 bytes. The caller must have
/// validated `pin.len <= 63`. The result is secret: wipe it.
pub fn padPin(pin: []const u8) [padded_pin_len]u8 {
    std.debug.assert(pin.len <= max_pin_bytes);
    var out: [padded_pin_len]u8 = @splat(0);
    @memcpy(out[0..pin.len], pin);
    return out;
}

/// `LEFT(SHA-256(pin), 16)`.
pub fn pinHash(pin: []const u8) [16]u8 {
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(pin, &full, .{});
    defer std.crypto.secureZero(u8, &full);
    return full[0..16].*;
}

// ── errors ──────────────────────────────────────────────────────────────────

pub const ClientPinError = framing.CallError || PinError || ctap2pin.EcdhError || ctap2pin.CbcError || error{
    /// The authenticator's key-agreement COSE_Key is not EC2 / P-256 /
    /// alg -25 with 32-byte coordinates.
    InvalidKeyAgreement,
    /// The decrypted pinUvAuthToken has a length the protocol forbids
    /// (One: 16 or 32 bytes; Two: exactly 32).
    BadTokenLength,
    /// `permissions` was zero (the spec forbids it).
    InvalidPermissions,
    /// The random source produced no usable ECDH scalar after 8 draws.
    EntropyFailure,
};

// ── secrets ─────────────────────────────────────────────────────────────────

/// An HMAC output: 16 bytes (protocol One) or 32 (protocol Two).
pub const Signature = struct {
    bytes: [32]u8 = @splat(0),
    len: u8 = 0,

    pub fn slice(self: *const Signature) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// A pinUvAuthToken obtained from the authenticator. Wipe with `deinit`.
pub const Token = struct {
    protocol: Protocol,
    bytes: [32]u8 = @splat(0),
    len: u8 = 0,

    pub fn slice(self: *const Token) []const u8 {
        return self.bytes[0..self.len];
    }

    /// `authenticate(token, message)`: the `pinUvAuthParam` for a later
    /// command (e.g. over `clientDataHash` for makeCredential/getAssertion).
    pub fn authenticate(self: *const Token, message: []const u8) Signature {
        var out: Signature = .{};
        switch (self.protocol) {
            .one => {
                // The key is the whole token (16 or 32 bytes: never empty).
                const mac = ctap2pin.One.authenticate(self.slice(), message) catch unreachable;
                @memcpy(out.bytes[0..mac.len], &mac);
                out.len = mac.len;
            },
            .two => {
                const mac = ctap2pin.Two.authenticate(&self.bytes, message);
                @memcpy(out.bytes[0..mac.len], &mac);
                out.len = mac.len;
            },
        }
        return out;
    }

    pub fn deinit(self: *Token) void {
        std.crypto.secureZero(u8, &self.bytes);
        self.len = 0;
    }
};

/// One transaction's key agreement result. Wipe with `deinit`.
pub const SharedSecret = struct {
    protocol: Protocol,
    /// Protocol One uses the first 32 bytes; Two all 64 (`hmacKey || aesKey`).
    bytes: [64]u8 = @splat(0),
    /// Send this as `keyAgreement`.
    platform_key: PublicKey,

    pub fn deinit(self: *SharedSecret) void {
        std.crypto.secureZero(u8, &self.bytes);
    }

    /// `authenticate(sharedSecret, message)`.
    pub fn authenticate(self: *const SharedSecret, message: []const u8) Signature {
        var out: Signature = .{};
        switch (self.protocol) {
            .one => {
                const mac = ctap2pin.One.authenticate(self.bytes[0..32], message) catch unreachable;
                @memcpy(out.bytes[0..mac.len], &mac);
                out.len = mac.len;
            },
            .two => {
                const mac = ctap2pin.Two.authenticate(self.bytes[0..32], message);
                @memcpy(out.bytes[0..mac.len], &mac);
                out.len = mac.len;
            },
        }
        return out;
    }

    /// Size of `encrypt`'s output for a plaintext of `plain_len` bytes.
    pub fn encryptedLen(self: *const SharedSecret, plain_len: usize) usize {
        return switch (self.protocol) {
            .one => plain_len,
            .two => ctap2pin.Two.encryptedLength(plain_len),
        };
    }

    /// `encrypt(sharedSecret, plaintext)`; protocol Two draws its IV from
    /// `random`. `dst.len` must be `encryptedLen(plaintext.len)`.
    pub fn encrypt(self: *const SharedSecret, random: std.Random, dst: []u8, plaintext: []const u8) ctap2pin.CbcError!void {
        switch (self.protocol) {
            .one => try ctap2pin.One.encrypt(self.bytes[0..32].*, dst, plaintext),
            .two => {
                var iv: [ctap2pin.Two.iv_length]u8 = undefined;
                random.bytes(&iv);
                try ctap2pin.Two.encrypt(self.bytes, iv, dst, plaintext);
            },
        }
    }

    /// Decrypt a `pinUvAuthToken` from a response and check its length.
    pub fn decryptToken(self: *const SharedSecret, ciphertext: []const u8) ClientPinError!Token {
        var tok: Token = .{ .protocol = self.protocol };
        errdefer tok.deinit();
        switch (self.protocol) {
            .one => {
                if (ciphertext.len != 16 and ciphertext.len != 32) return error.BadTokenLength;
                try ctap2pin.One.decrypt(self.bytes[0..32].*, tok.bytes[0..ciphertext.len], ciphertext);
                tok.len = @intCast(ciphertext.len);
            },
            .two => {
                const n = ctap2pin.Two.decryptedLength(ciphertext.len) catch return error.BadTokenLength;
                if (n != 32) return error.BadTokenLength;
                try ctap2pin.Two.decrypt(self.bytes, tok.bytes[0..32], ciphertext);
                tok.len = 32;
            },
        }
        return tok;
    }
};

// ── response parsers (pure; fuzzed) ─────────────────────────────────────────

/// Parse a `getKeyAgreement` response body into a validated P-256 point.
/// The COSE_Key must be EC2 (kty 2), P-256 (crv 1), alg -25, with 32-byte x
/// and y that lie on the curve. `allocator` should be an arena.
pub fn parseKeyAgreementResponse(allocator: Allocator, body: []const u8) (framing.ParseError || Allocator.Error || error{ InvalidKeyAgreement, InvalidPublicKey })!PublicKey {
    const entries = try framing.decodeMap(allocator, body);
    const key_value = (try framing.find(entries, 0x01)) orelse return error.MissingField;
    const key = cbor.cose.parseKey(key_value) catch |e| switch (e) {
        error.NotAMap, error.WrongType => return error.UnexpectedType,
        error.MissingField => return error.MissingField,
        else => return error.InvalidKeyAgreement,
    };
    const ec2 = switch (key) {
        .ec2 => |k| k,
        else => return error.InvalidKeyAgreement,
    };
    if (ec2.crv != cbor.cose.crv_p256) return error.InvalidKeyAgreement;
    // CTAP 2.1 §6.5.5: the key MUST carry alg = ECDH-ES + HKDF-256 (-25).
    const alg = ec2.alg orelse return error.InvalidKeyAgreement;
    if (alg != -25) return error.InvalidKeyAgreement;
    if (ec2.x.len != 32 or ec2.y.len != 32) return error.InvalidKeyAgreement;
    const pk: PublicKey = .{ .x = ec2.x[0..32].*, .y = ec2.y[0..32].* };
    _ = pk.toPoint() catch return error.InvalidPublicKey; // on the curve, not the identity
    return pk;
}

pub const PinRetries = struct {
    retries: u32,
    /// `powerCycleState`: `null` = the authenticator said nothing.
    power_cycle_required: ?bool = null,
};

/// Parse a `getPINRetries` response body.
pub fn parsePinRetriesResponse(allocator: Allocator, body: []const u8) (framing.ParseError || Allocator.Error)!PinRetries {
    const entries = try framing.decodeMap(allocator, body);
    const retries = try framing.asU32((try framing.find(entries, 0x03)) orelse return error.MissingField);
    var out: PinRetries = .{ .retries = retries };
    if (try framing.find(entries, 0x04)) |v| out.power_cycle_required = try framing.asBool(v);
    return out;
}

/// Parse a `getUVRetries` response body.
pub fn parseUvRetriesResponse(allocator: Allocator, body: []const u8) (framing.ParseError || Allocator.Error)!u32 {
    const entries = try framing.decodeMap(allocator, body);
    return framing.asU32((try framing.find(entries, 0x05)) orelse return error.MissingField);
}

/// Parse a token response body into the still-encrypted `pinUvAuthToken`
/// (borrowed from `allocator`'s tree; use an arena).
pub fn parseTokenResponse(allocator: Allocator, body: []const u8) (framing.ParseError || Allocator.Error)![]const u8 {
    const entries = try framing.decodeMap(allocator, body);
    return framing.asBytes((try framing.find(entries, 0x02)) orelse return error.MissingField);
}

// ── request building ────────────────────────────────────────────────────────

const Params = struct {
    entries: [8]MapEntry = undefined,
    n: usize = 0,

    fn put(self: *Params, key: u64, v: Value) void {
        self.entries[self.n] = .{ .key = .{ .uint = key }, .value = v };
        self.n += 1;
    }

    fn value(self: *const Params) Value {
        return .{ .map = self.entries[0..self.n] };
    }
};

/// `keyAgreement`: EC2, alg -25, crv P-256, x, y — no other parameters.
fn coseKey(allocator: Allocator, pk: *const PublicKey) Allocator.Error!Value {
    const e = try allocator.alloc(MapEntry, 5);
    e[0] = .{ .key = Value.fromI64(1), .value = Value.fromI64(2) };
    e[1] = .{ .key = Value.fromI64(3), .value = Value.fromI64(-25) };
    e[2] = .{ .key = Value.fromI64(-1), .value = Value.fromI64(1) };
    e[3] = .{ .key = Value.fromI64(-2), .value = .{ .bytes = &pk.x } };
    e[4] = .{ .key = Value.fromI64(-3), .value = .{ .bytes = &pk.y } };
    return .{ .map = e };
}

// ── the client ──────────────────────────────────────────────────────────────

/// Drives `authenticatorClientPIN` against one authenticator.
///
/// `protocol` is the PIN/UV auth protocol to use (from `Info`:
/// `preferredProtocol()`); `random` supplies the ECDH scalar and the
/// protocol-Two IVs and must be cryptographically secure.
pub const Client = struct {
    allocator: Allocator,
    transport: framing.Transport,
    random: std.Random,
    protocol: Protocol,
    /// Minimum PIN length in code points enforced before `setPin`/`changePin`
    /// send anything (`Info.effectiveMinPinLength()`).
    min_pin_length: u32 = default_min_pin_code_points,
    /// Size of the response buffer per transaction.
    max_response: usize = 2048,

    pub fn init(allocator: Allocator, transport: framing.Transport, random: std.Random, protocol: Protocol) Client {
        return .{ .allocator = allocator, .transport = transport, .random = random, .protocol = protocol };
    }

    /// A client configured from a parsed `authenticatorGetInfo`: its preferred
    /// protocol, its `minPINLength`, and `maxMsgSize` (capped at 16 KiB) as
    /// the receive buffer size. `null` when the authenticator lists no
    /// protocol this module speaks.
    pub fn fromInfo(allocator: Allocator, transport: framing.Transport, random: std.Random, info: getinfo.Info) ?Client {
        const protocol = info.preferredProtocol() orelse return null;
        var c = init(allocator, transport, random, protocol);
        c.min_pin_length = info.effectiveMinPinLength();
        if (info.max_msg_size) |m| c.max_response = @intCast(std.math.clamp(m, 64, 16 * 1024));
        return c;
    }

    fn send(self: *const Client, arena: Allocator, params: *const Params) ClientPinError!framing.Response {
        return framing.call(arena, self.transport, @intFromEnum(framing.Command.client_pin), params.value(), self.max_response);
    }

    fn begin(self: *const Client, sub: SubCommand) Params {
        var p: Params = .{};
        p.put(0x01, .{ .uint = @intFromEnum(self.protocol) });
        p.put(0x02, .{ .uint = @intFromEnum(sub) });
        return p;
    }

    /// `getPINRetries` (0x01).
    pub fn getPinRetries(self: *const Client) ClientPinError!PinRetries {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const params = self.begin(.get_pin_retries);
        const resp = try self.send(a, &params);
        return parsePinRetriesResponse(a, resp.body);
    }

    /// `getUVRetries` (0x07).
    pub fn getUvRetries(self: *const Client) ClientPinError!u32 {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const params = self.begin(.get_uv_retries);
        const resp = try self.send(a, &params);
        return parseUvRetriesResponse(a, resp.body);
    }

    fn getKeyAgreementIn(self: *const Client, a: Allocator) ClientPinError!PublicKey {
        const params = self.begin(.get_key_agreement);
        const resp = try self.send(a, &params);
        return parseKeyAgreementResponse(a, resp.body);
    }

    /// `getKeyAgreement` (0x02): the authenticator's key-agreement key.
    pub fn getKeyAgreement(self: *const Client) ClientPinError!PublicKey {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        return self.getKeyAgreementIn(arena.allocator());
    }

    fn openSession(self: *const Client, a: Allocator) ClientPinError!SharedSecret {
        const peer = try self.getKeyAgreementIn(a);
        var attempts: u8 = 0;
        while (true) {
            var scalar: [32]u8 = undefined;
            defer std.crypto.secureZero(u8, &scalar);
            self.random.bytes(&scalar);
            var s: SharedSecret = .{ .protocol = self.protocol, .platform_key = undefined };
            errdefer s.deinit();
            switch (self.protocol) {
                inline else => |p| {
                    var enc = ctap2pin.Impl(p).encapsulate(scalar, peer) catch |e| switch (e) {
                        error.InvalidScalar => {
                            attempts += 1;
                            if (attempts >= 8) return error.EntropyFailure;
                            continue;
                        },
                        else => return e,
                    };
                    defer std.crypto.secureZero(u8, &enc.shared_secret);
                    @memcpy(s.bytes[0..enc.shared_secret.len], &enc.shared_secret);
                    s.platform_key = enc.platform_key_agreement;
                },
            }
            return s;
        }
    }

    /// `setPIN` (0x03): set the first PIN. `new_pin` is UTF-8 in NFC.
    pub fn setPin(self: *const Client, new_pin: []const u8) ClientPinError!void {
        try validateNewPin(new_pin, self.min_pin_length);
        var padded = padPin(new_pin);
        defer std.crypto.secureZero(u8, &padded);

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var secret = try self.openSession(a);
        defer secret.deinit();
        const new_pin_enc = try a.alloc(u8, secret.encryptedLen(padded_pin_len));
        try secret.encrypt(self.random, new_pin_enc, &padded);
        const param = secret.authenticate(new_pin_enc); // authenticate(secret, newPinEnc)

        var params = self.begin(.set_pin);
        params.put(0x03, try coseKey(a, &secret.platform_key));
        params.put(0x04, .{ .bytes = param.slice() });
        params.put(0x05, .{ .bytes = new_pin_enc });
        _ = try self.send(a, &params);
    }

    /// `changePIN` (0x04).
    pub fn changePin(self: *const Client, current_pin: []const u8, new_pin: []const u8) ClientPinError!void {
        try validateNewPin(new_pin, self.min_pin_length);
        try validateCurrentPin(current_pin);
        var padded = padPin(new_pin);
        defer std.crypto.secureZero(u8, &padded);
        var hash = pinHash(current_pin);
        defer std.crypto.secureZero(u8, &hash);

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var secret = try self.openSession(a);
        defer secret.deinit();
        // Draw order: pinHashEnc first, then newPinEnc (protocol-Two IVs).
        const pin_hash_enc = try a.alloc(u8, secret.encryptedLen(hash.len));
        try secret.encrypt(self.random, pin_hash_enc, &hash);
        const new_pin_enc = try a.alloc(u8, secret.encryptedLen(padded_pin_len));
        try secret.encrypt(self.random, new_pin_enc, &padded);
        // authenticate(secret, newPinEnc || pinHashEnc)
        const msg = try a.alloc(u8, new_pin_enc.len + pin_hash_enc.len);
        @memcpy(msg[0..new_pin_enc.len], new_pin_enc);
        @memcpy(msg[new_pin_enc.len..], pin_hash_enc);
        const param = secret.authenticate(msg);

        var params = self.begin(.change_pin);
        params.put(0x03, try coseKey(a, &secret.platform_key));
        params.put(0x04, .{ .bytes = param.slice() });
        params.put(0x05, .{ .bytes = new_pin_enc });
        params.put(0x06, .{ .bytes = pin_hash_enc });
        _ = try self.send(a, &params);
    }

    fn tokenWithPin(self: *const Client, sub: SubCommand, pin: []const u8, permissions: ?Permissions, rp_id: ?[]const u8) ClientPinError!Token {
        try validateCurrentPin(pin);
        if (permissions) |p| if (p.toInt() == 0) return error.InvalidPermissions;
        var hash = pinHash(pin);
        defer std.crypto.secureZero(u8, &hash);

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var secret = try self.openSession(a);
        defer secret.deinit();
        const pin_hash_enc = try a.alloc(u8, secret.encryptedLen(hash.len));
        try secret.encrypt(self.random, pin_hash_enc, &hash);

        var params = self.begin(sub);
        params.put(0x03, try coseKey(a, &secret.platform_key));
        params.put(0x06, .{ .bytes = pin_hash_enc });
        if (permissions) |p| params.put(0x09, .{ .uint = p.toInt() });
        if (rp_id) |r| params.put(0x0A, .{ .text = r });
        const resp = try self.send(a, &params);
        return secret.decryptToken(try parseTokenResponse(a, resp.body));
    }

    /// `getPinToken` (0x05, legacy): a token with the default mc + ga
    /// permissions.
    pub fn getPinToken(self: *const Client, pin: []const u8) ClientPinError!Token {
        return self.tokenWithPin(.get_pin_token, pin, null, null);
    }

    /// `getPinUvAuthTokenUsingPinWithPermissions` (0x09).
    pub fn getPinUvAuthTokenUsingPin(self: *const Client, pin: []const u8, permissions: Permissions, rp_id: ?[]const u8) ClientPinError!Token {
        return self.tokenWithPin(.get_pin_uv_auth_token_using_pin_with_permissions, pin, permissions, rp_id);
    }

    /// `getPinUvAuthTokenUsingUvWithPermissions` (0x06): built-in user
    /// verification (the authenticator prompts; this call blocks until it
    /// answers).
    pub fn getPinUvAuthTokenUsingUv(self: *const Client, permissions: Permissions, rp_id: ?[]const u8) ClientPinError!Token {
        if (permissions.toInt() == 0) return error.InvalidPermissions;
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var secret = try self.openSession(a);
        defer secret.deinit();
        var params = self.begin(.get_pin_uv_auth_token_using_uv_with_permissions);
        params.put(0x03, try coseKey(a, &secret.platform_key));
        params.put(0x09, .{ .uint = permissions.toInt() });
        if (rp_id) |r| params.put(0x0A, .{ .text = r });
        const resp = try self.send(a, &params);
        return secret.decryptToken(try parseTokenResponse(a, resp.body));
    }
};

// ── tests: PIN rules ────────────────────────────────────────────────────────

const testing = std.testing;

test "validateNewPin: 3 vs 4 code points, multi-byte UTF-8" {
    try testing.expectError(error.PinTooShort, validateNewPin("abc", 4));
    try validateNewPin("abcd", 4);
    // 3 code points of 3 bytes each: 9 bytes but still too short.
    try testing.expectError(error.PinTooShort, validateNewPin("\u{20ac}\u{20ac}\u{20ac}", 4));
    // 4 code points of 3 bytes: fine.
    try validateNewPin("\u{20ac}\u{20ac}\u{20ac}\u{20ac}", 4);
    // 4 code points that are 2 + 4 + 1 + 1 bytes.
    try validateNewPin("\u{e4}\u{1f600}ab", 4);
    // Combining sequence: "a" + U+0301 is 2 code points however it renders.
    try testing.expectError(error.PinTooShort, validateNewPin("a\u{301}b\u{301}", 5));
    try testing.expectError(error.PinTooShort, validateNewPin("", 4));
}

test "validateNewPin: minPINLength above 4 is honoured, below 4 is not" {
    try testing.expectError(error.PinTooShort, validateNewPin("12345", 6));
    try validateNewPin("123456", 6);
    try testing.expectError(error.PinTooShort, validateNewPin("123", 1)); // the spec floor stays 4
}

test "validateNewPin: 63 vs 64 bytes" {
    const p63 = "a" ** 63;
    const p64 = "a" ** 64;
    try validateNewPin(p63, 4);
    try testing.expectError(error.PinTooLong, validateNewPin(p64, 4));
    // 21 * 3 = 63 bytes of euro signs, 22 * 3 = 66.
    try validateNewPin("\u{20ac}" ** 21, 4);
    try testing.expectError(error.PinTooLong, validateNewPin("\u{20ac}" ** 22, 4));
    // 62 ASCII bytes + one 2-byte code point = 64 bytes although only 63 code points.
    try testing.expectError(error.PinTooLong, validateNewPin(("a" ** 62) ++ "\u{e4}", 4));
}

test "validateNewPin: invalid UTF-8 is rejected" {
    try testing.expectError(error.PinNotUtf8, validateNewPin("ab\xffcd", 4));
    try testing.expectError(error.PinNotUtf8, validateNewPin("\xc3", 4)); // truncated sequence
    try testing.expectError(error.PinNotUtf8, validateNewPin("ab\xed\xa0\x80cd", 4)); // surrogate
}

test "validateCurrentPin: only the 63-byte cap applies" {
    try validateCurrentPin("");
    try validateCurrentPin("1");
    try validateCurrentPin("a" ** 63);
    try testing.expectError(error.PinTooLong, validateCurrentPin("a" ** 64));
}

test "padPin and pinHash" {
    const p = padPin("1234");
    try testing.expectEqual(@as(usize, 64), p.len);
    try testing.expectEqualSlices(u8, "1234", p[0..4]);
    for (p[4..]) |b| try testing.expectEqual(@as(u8, 0), b);
    const full = padPin("a" ** 63);
    try testing.expectEqual(@as(u8, 0), full[63]); // always at least one padding byte
    // SHA-256("1234") starts 03ac674216f3e15c761ee1a5e255f067 (same value ctap2pin's vectors use).
    try testing.expectEqualSlices(u8, &.{ 0x03, 0xac, 0x67, 0x42, 0x16, 0xf3, 0xe1, 0x5c, 0x76, 0x1e, 0xe1, 0xa5, 0xe2, 0x55, 0xf0, 0x67 }, &pinHash("1234"));
}

test "Permissions bit values" {
    try testing.expectEqual(@as(u8, 0x01), (Permissions{ .mc = true }).toInt());
    try testing.expectEqual(@as(u8, 0x02), (Permissions{ .ga = true }).toInt());
    try testing.expectEqual(@as(u8, 0x04), (Permissions{ .cm = true }).toInt());
    try testing.expectEqual(@as(u8, 0x08), (Permissions{ .be = true }).toInt());
    try testing.expectEqual(@as(u8, 0x10), (Permissions{ .lbw = true }).toInt());
    try testing.expectEqual(@as(u8, 0x20), (Permissions{ .acfg = true }).toInt());
    try testing.expectEqual(@as(u8, 0x3f), (Permissions{ .mc = true, .ga = true, .cm = true, .be = true, .lbw = true, .acfg = true }).toInt());
}
