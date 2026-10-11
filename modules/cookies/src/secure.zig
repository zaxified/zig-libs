// SPDX-License-Identifier: MIT

//! Signed and encrypted ("private") cookie values — the server-side half of
//! cookie-rs's `SignedJar`/`PrivateJar` and gorilla/securecookie, as pure
//! codecs over the value string (no jar, no allocation).
//!
//! ```zig
//! var key: cookies.Key = undefined;
//! try cookies.Key.deriveInto(&key, master_secret); // >= 32 random bytes
//! defer key.wipe();
//!
//! // Encrypted + authenticated, bound to the cookie name (recommended):
//! var buf: [512]u8 = undefined;
//! const sealed = try cookies.private.sealRandom(io, &key, "sid", "user=42", &buf);
//! try cookies.set(res, .{ .name = "sid", .value = sealed, .secure = true, .http_only = true });
//! // … on the next request:
//! var plain: [512]u8 = undefined;
//! const v = cookies.private.open(&.{key}, "sid", cookies.get(req, "sid") orelse "", &plain) orelse return; // forged / foreign key
//!
//! // Authenticated only (value readable by the client):
//! const s = try cookies.signed.sign(&key, "theme", "dark", &buf, .{});
//! const t = cookies.signed.verify(&.{key}, "theme", s, .{}) orelse "light";
//! ```
//!
//! ## Construction (decided 2026-10-12)
//!
//! - `private`: AES-256-GCM, 96-bit random nonce, the cookie NAME as
//!   associated data, value = standard base64 (with padding) of
//!   `nonce ‖ ciphertext ‖ tag`. Byte-compatible with cookie-rs 0.16–0.18
//!   `PrivateJar` both ways (format read from its `src/secure/private.rs`,
//!   vectors from an independent AES-GCM, `secure_vectors.zig`).
//! - `signed`: HMAC-SHA256, value = base64(tag) ‖ value (44 + n bytes).
//!   Default `.bound` MACs `name "=" value`, so a value signed for one cookie
//!   is refused under another name; `.format = .cookie_rs` MACs the value
//!   alone, byte-compatible with cookie-rs `SignedJar`, which does not bind
//!   the name (a value can be replayed under any cookie the same key signs).
//! - `Key`: 32-byte signing key ‖ 32-byte encryption key, as cookie-rs's
//!   `Key`; `fromBytesInto` = `Key::from`, `deriveInto` = `Key::derive_from`
//!   (HKDF-SHA256 Expand, the master used as PRK, cookie-rs's info string).
//! - Rotation: `verify`/`open` take a list of keys and accept the first that
//!   authenticates; `sign`/`seal` use the one key given (the newest).
//!
//! Nothing here expires a value: a sealed or signed value stays valid for as
//! long as its key does. Put an issue time inside the value (or rotate keys)
//! when the server must refuse old values; `Max-Age` binds only the browser.
//!
//! Dead-stack: every entry point that touches a key runs its body under
//! `burn.run` (`stackprobe_test.zig`); keys are passed by pointer.

const std = @import("std");
const aesgcm = @import("aesgcm");
const burn = @import("burn.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const b64 = std.base64.standard;
const timing_safe = std.crypto.timing_safe;

/// cookie-rs's HKDF info string (`secure/key.rs` `KEYS_INFO`).
const keys_info = "COOKIE;SIGNED:HMAC-SHA256;PRIVATE:AEAD-AES-256-GCM";

pub const KeyError = error{
    /// `fromBytesInto` got fewer than 64 bytes, `deriveInto` fewer than 32.
    KeyTooShort,
};

/// A signing key and an encryption key, one master as cookie-rs's `Key`.
/// Holds secrets: keep it in one place, pass it by pointer, `wipe` it.
pub const Key = struct {
    signing: [32]u8,
    encryption: [32]u8,

    /// cookie-rs `Key::from`: the first 32 bytes sign, the next 32 encrypt.
    /// `bytes` must be at least 64 bytes of cryptographically random data.
    pub fn fromBytesInto(out: *Key, bytes: []const u8) KeyError!void {
        if (bytes.len < 64) return error.KeyTooShort;
        @memcpy(&out.signing, bytes[0..32]);
        @memcpy(&out.encryption, bytes[32..64]);
    }

    /// cookie-rs `Key::derive_from`: HKDF-SHA256 Expand of `master` (at
    /// least 32 random bytes, used directly as the PRK) to 64 bytes.
    pub fn deriveInto(out: *Key, master: []const u8) KeyError!void {
        if (master.len < 32) return error.KeyTooShort;
        burn.run(burn.mac_burn, void, deriveBody, .{ out, master });
    }

    fn deriveBody(out: *Key, master: []const u8) void {
        // RFC 5869 §2.3 for L = 64: T(1) = HMAC(PRK, info ‖ 0x01),
        // T(2) = HMAC(PRK, T(1) ‖ info ‖ 0x02).
        var h = HmacSha256.init(master);
        h.update(keys_info);
        h.update(&.{0x01});
        h.final(&out.signing);
        h = HmacSha256.init(master);
        h.update(&out.signing);
        h.update(keys_info);
        h.update(&.{0x02});
        h.final(&out.encryption);
        std.crypto.secureZero(u8, std.mem.asBytes(&h));
    }

    /// 64 bytes from the OS CSPRNG (cookie-rs `Key::generate`).
    pub fn generateInto(out: *Key, io: std.Io) std.Io.RandomSecureError!void {
        try io.randomSecure(std.mem.asBytes(out));
    }

    pub fn wipe(k: *Key) void {
        std.crypto.secureZero(u8, std.mem.asBytes(k));
    }
};

pub const SignError = error{
    /// The value has a byte outside RFC 6265 `cookie-octet` (or is a
    /// `"…"`-quoted value): the signed result could not be sent.
    InvalidValue,
    /// `out` is shorter than `signed.len(value.len)` / `private.len(value.len)`.
    NoSpaceLeft,
};

/// RFC 6265 §4.1.1 `cookie-octet`.
fn isCookieOctet(c: u8) bool {
    return c == 0x21 or (c >= 0x23 and c <= 0x2B) or (c >= 0x2D and c <= 0x3A) or
        (c >= 0x3C and c <= 0x5B) or (c >= 0x5D and c <= 0x7E);
}

pub const signed = struct {
    /// base64 of a 32-byte HMAC-SHA256 tag, padded.
    pub const tag_b64_len = 44;

    pub const Format = enum {
        /// MAC over `name "=" value`: a value is valid only under its name.
        bound,
        /// cookie-rs `SignedJar`: MAC over the value alone.
        cookie_rs,
    };

    pub const Options = struct { format: Format = .bound };

    /// Length of the signed value for a `value_len`-byte value.
    pub fn len(value_len: usize) usize {
        return tag_b64_len + value_len;
    }

    /// `out[0..len(value.len)]` ← base64(HMAC) ‖ value. `value` must be
    /// cookie-octets (so the result is a valid cookie value).
    pub fn sign(key: *const Key, name: []const u8, value: []const u8, out: []u8, opts: Options) SignError![]const u8 {
        for (value) |c| if (!isCookieOctet(c)) return error.InvalidValue;
        if (out.len < len(value.len)) return error.NoSpaceLeft;
        return burn.run(burn.mac_burn, []const u8, signBody, .{ key, name, value, out, opts.format });
    }

    fn signBody(key: *const Key, name: []const u8, value: []const u8, out: []u8, format: Format) []const u8 {
        var tag: [HmacSha256.mac_length]u8 = undefined;
        mac(&tag, key, name, value, format);
        // The tag goes to the client: declassified for ctgrind before the
        // table-driven base64 indexes by it (a no-op without `-fvalgrind`).
        std.valgrind.memcheck.makeMemDefined(&tag);
        _ = b64.Encoder.encode(out[0..tag_b64_len], &tag);
        // `value` may already sit at `out[tag_b64_len..]` (built in place);
        // it must not overlap the tag. Hence a forward copy, not @memcpy.
        std.mem.copyForwards(u8, out[tag_b64_len..][0..value.len], value);
        return out[0 .. tag_b64_len + value.len];
    }

    fn mac(tag: *[HmacSha256.mac_length]u8, key: *const Key, name: []const u8, value: []const u8, format: Format) void {
        var h = HmacSha256.init(&key.signing);
        if (format == .bound) {
            h.update(name);
            h.update("=");
        }
        h.update(value);
        h.final(tag);
        std.crypto.secureZero(u8, std.mem.asBytes(&h));
    }

    /// The original value (a slice of `signed_value`) when one of `keys`
    /// authenticates it under `name`; null when none does or the value is
    /// malformed. Never says which key matched or why it failed.
    pub fn verify(keys: []const Key, name: []const u8, signed_value: []const u8, opts: Options) ?[]const u8 {
        if (signed_value.len < tag_b64_len) return null;
        var presented: [HmacSha256.mac_length]u8 = undefined;
        // std's decoder wants `dest.len` to be exactly the decoded size: 44
        // characters without the padding `=` decode to 33 bytes (found by
        // the `secure` fuzz harness, 2026-10-12 — an out-of-bounds panic).
        const tag_text = signed_value[0..tag_b64_len];
        if ((b64.Decoder.calcSizeForSlice(tag_text) catch return null) != presented.len) return null;
        b64.Decoder.decode(&presented, tag_text) catch return null;
        return burn.run(burn.mac_burn, ?[]const u8, verifyBody, .{ keys, name, signed_value, &presented, opts.format });
    }

    fn verifyBody(keys: []const Key, name: []const u8, signed_value: []const u8, presented: *const [HmacSha256.mac_length]u8, format: Format) ?[]const u8 {
        const value = signed_value[tag_b64_len..];
        var ok = false;
        for (keys) |*k| {
            var tag: [HmacSha256.mac_length]u8 = undefined;
            mac(&tag, k, name, value, format);
            // Every key is tried, also after a match: the time depends on
            // the number of keys only, not on which one matched.
            ok = timing_safe.eql([HmacSha256.mac_length]u8, tag, presented.*) or ok;
        }
        return if (ok) value else null;
    }
};

pub const private = struct {
    const Aes = aesgcm.Aes256Gcm;
    pub const nonce_len = Aes.nonce_length;
    pub const tag_len = Aes.tag_length;
    pub const overhead = nonce_len + tag_len;

    /// Length of the sealed value for a `value_len`-byte plaintext.
    pub fn len(value_len: usize) usize {
        return b64.Encoder.calcSize(overhead + value_len);
    }

    /// A size of `out` that is always enough for `open` of a `sealed_len`-
    /// byte value (an upper bound of the decoded length, which is the exact
    /// minimum; the plaintext is `overhead` shorter than it).
    pub fn openBufLen(sealed_len: usize) usize {
        return sealed_len / 4 * 3;
    }

    pub const SealRandomError = SignError || std.Io.RandomSecureError;

    /// `seal` with a nonce from the OS CSPRNG — the normal entry point.
    pub fn sealRandom(io: std.Io, key: *const Key, name: []const u8, value: []const u8, out: []u8) SealRandomError![]const u8 {
        var nonce: [nonce_len]u8 = undefined;
        try io.randomSecure(&nonce);
        return seal(key, name, value, nonce, out);
    }

    /// `out[0..len(value.len)]` ← base64(nonce ‖ AES-256-GCM(value, ad = name)
    /// ‖ tag). `nonce` must never repeat under one key: use `sealRandom`
    /// unless the caller has a nonce source of its own (tests, vectors).
    /// `value` is any bytes; cookie-rs's `PrivateJar` opens only UTF-8.
    pub fn seal(key: *const Key, name: []const u8, value: []const u8, nonce: [nonce_len]u8, out: []u8) SignError![]const u8 {
        const enc_len = len(value.len);
        if (out.len < enc_len) return error.NoSpaceLeft;
        return burn.run(burn.msg_burn, []const u8, sealBody, .{ key, name, value, nonce, out[0..enc_len] });
    }

    fn sealBody(key: *const Key, name: []const u8, value: []const u8, nonce: [nonce_len]u8, out: []u8) []const u8 {
        // The raw record goes into the TAIL of `out`, then is base64-encoded
        // forward over itself one 3-byte group at a time. Group i reads
        // raw[3i..3i+3] at offset e-r+3i and writes out[4i..4i+4]; the
        // write stays below every unread group because e - r >= groups
        // (4g - r >= g as 3g >= r), so no scratch buffer is needed.
        const r = overhead + value.len;
        const raw = out[out.len - r ..];
        // The ciphertext may not overlap the plaintext from after it; a
        // caller sealing a value that lives inside `out` is not supported.
        std.debug.assert(!overlaps(raw, value));
        raw[0..nonce_len].* = nonce;
        const ct = raw[nonce_len..][0..value.len];
        const tag = raw[nonce_len + value.len ..][0..tag_len];
        Aes.encryptInto(ct, tag, value, name, nonce, &key.encryption);
        // Ciphertext and tag go to the client: declassified for ctgrind
        // before base64 indexes its table by them (no-op without -fvalgrind).
        std.valgrind.memcheck.makeMemDefined(raw);
        encodeInPlace(out, r);
        return out;
    }

    fn overlaps(a: []const u8, b: []const u8) bool {
        if (a.len == 0 or b.len == 0) return false;
        const a0 = @intFromPtr(a.ptr);
        const b0 = @intFromPtr(b.ptr);
        return a0 < b0 + b.len and b0 < a0 + a.len;
    }

    fn encodeInPlace(out: []u8, r: usize) void {
        const off = out.len - r;
        var i: usize = 0;
        var o: usize = 0;
        while (i < r) : ({
            i += 3;
            o += 4;
        }) {
            var group: [3]u8 = undefined;
            const n = @min(3, r - i);
            @memcpy(group[0..n], out[off + i ..][0..n]);
            _ = b64.Encoder.encode(out[o..][0..4], group[0..n]);
        }
    }

    /// The plaintext (a slice of `out`) when one of `keys` opens `sealed`
    /// under `name`; null when none does or the value is malformed.
    /// `out.len` must be at least `openBufLen(sealed.len)`, else null.
    /// On null, `out` holds no plaintext.
    pub fn open(keys: []const Key, name: []const u8, sealed: []const u8, out: []u8) ?[]const u8 {
        const raw_len = b64.Decoder.calcSizeForSlice(sealed) catch return null;
        if (raw_len < overhead or out.len < raw_len) return null;
        return burn.run(burn.msg_burn, ?[]const u8, openBody, .{ keys, name, sealed, out[0..raw_len] });
    }

    fn openBody(keys: []const Key, name: []const u8, sealed: []const u8, raw: []u8) ?[]const u8 {
        const n = raw.len - overhead;
        for (keys) |*k| {
            // Decoded afresh per key: a failed decrypt zeroes the plaintext
            // range, which overlaps the ciphertext it was decrypted from.
            b64.Decoder.decode(raw, sealed) catch return null;
            const nonce = raw[0..nonce_len].*;
            const tag = raw[nonce_len + n ..][0..tag_len].*;
            // In place, one nonce length down: `m` starts before `c` in the
            // same buffer, which `decryptInto` allows.
            Aes.decryptInto(raw[0..n], raw[nonce_len..][0..n], tag, name, nonce, &k.encryption) catch continue;
            std.crypto.secureZero(u8, raw[n..]);
            return raw[0..n];
        }
        std.crypto.secureZero(u8, raw);
        return null;
    }
};
