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
//! `seal`/`sign` values stay valid for as long as their key does; the
//! `*Timed` variants seal the issue time in (a `timed1` domain of their own)
//! and refuse a value older than the verifier's `max_age_s` — `Max-Age` binds
//! only the browser.
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
        return signMode(key, name, value, out, if (format == .bound) .bound else .cookie_rs);
    }

    /// What the MAC covers: `bound` = name "=" value; `cookie_rs` = value;
    /// `timed` = "timed1" 0x00 name "=" issued "|" value (its own domain, so
    /// a timed value never verifies as an untimed one and back).
    const Mode = enum { bound, cookie_rs, timed };

    fn signMode(key: *const Key, name: []const u8, value: []const u8, out: []u8, mode: Mode) []const u8 {
        var tag: [HmacSha256.mac_length]u8 = undefined;
        mac(&tag, key, name, value, mode);
        // The tag goes to the client: declassified for ctgrind before the
        // table-driven base64 indexes by it (a no-op without `-fvalgrind`).
        std.valgrind.memcheck.makeMemDefined(&tag);
        _ = b64.Encoder.encode(out[0..tag_b64_len], &tag);
        // `value` may already sit at `out[tag_b64_len..]` (built in place);
        // it must not overlap the tag. Hence a forward copy, not @memcpy.
        std.mem.copyForwards(u8, out[tag_b64_len..][0..value.len], value);
        return out[0 .. tag_b64_len + value.len];
    }

    fn mac(tag: *[HmacSha256.mac_length]u8, key: *const Key, name: []const u8, value: []const u8, mode: Mode) void {
        var h = HmacSha256.init(&key.signing);
        if (mode == .timed) h.update(timed_domain);
        if (mode != .cookie_rs) {
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
        var presented: [HmacSha256.mac_length]u8 = undefined;
        if (!decodeTag(signed_value, &presented)) return null;
        return burn.run(burn.mac_burn, ?[]const u8, verifyBody, .{ keys, name, signed_value, &presented, if (opts.format == .bound) Mode.bound else Mode.cookie_rs });
    }

    fn decodeTag(signed_value: []const u8, presented: *[HmacSha256.mac_length]u8) bool {
        if (signed_value.len < tag_b64_len) return false;
        // std's decoder wants `dest.len` to be exactly the decoded size: 44
        // characters without the padding `=` decode to 33 bytes (found by
        // the `secure` fuzz harness, 2026-10-12 — an out-of-bounds panic).
        const tag_text = signed_value[0..tag_b64_len];
        if ((b64.Decoder.calcSizeForSlice(tag_text) catch return false) != presented.len) return false;
        b64.Decoder.decode(presented, tag_text) catch return false;
        return true;
    }

    fn verifyBody(keys: []const Key, name: []const u8, signed_value: []const u8, presented: *const [HmacSha256.mac_length]u8, mode: Mode) ?[]const u8 {
        const value = signed_value[tag_b64_len..];
        var ok = false;
        for (keys) |*k| {
            var tag: [HmacSha256.mac_length]u8 = undefined;
            mac(&tag, k, name, value, mode);
            // Every key is tried, also after a match: the time depends on
            // the number of keys only, not on which one matched.
            ok = timing_safe.eql([HmacSha256.mac_length]u8, tag, presented.*) or ok;
        }
        return if (ok) value else null;
    }

    /// Length of `signTimed`'s result for a `value_len`-byte value issued at
    /// `issued_s`.
    pub fn timedLen(value_len: usize, issued_s: i64) usize {
        return tag_b64_len + decimalLen(issued_s) + 1 + value_len;
    }

    /// `sign` with the issue time inside the MAC: base64(HMAC) ‖ issued_s
    /// (decimal) ‖ "|" ‖ value. `verifyTimed` refuses it once it is older
    /// than its `max_age_s`, whatever the browser's `Max-Age` did. A format
    /// of this module's own (gorilla/securecookie's idea, not its bytes);
    /// cookie-rs has none. `issued_s` is the caller's clock (seconds).
    pub fn signTimed(key: *const Key, name: []const u8, value: []const u8, issued_s: i64, out: []u8) SignError![]const u8 {
        for (value) |c| if (!isCookieOctet(c)) return error.InvalidValue;
        const total = timedLen(value.len, issued_s);
        if (out.len < total) return error.NoSpaceLeft;
        // issued "|" value, built in place after the tag, then signed.
        std.mem.copyBackwards(u8, out[total - value.len .. total], value);
        const digits = std.mem.print(out[tag_b64_len..], "{d}|", .{issued_s}) catch unreachable;
        std.debug.assert(digits.len == total - value.len - tag_b64_len);
        return burn.run(burn.mac_burn, []const u8, signMode, .{ key, name, out[tag_b64_len..total], out[0..total], Mode.timed });
    }

    /// The value (a slice of `signed_value`) when one of `keys` authenticates
    /// a `signTimed` value under `name` AND `now_s - issued <= max_age_s`;
    /// null otherwise (forged, another name, untimed, too old, malformed).
    pub fn verifyTimed(keys: []const Key, name: []const u8, signed_value: []const u8, now_s: i64, max_age_s: i64) ?[]const u8 {
        var presented: [HmacSha256.mac_length]u8 = undefined;
        if (!decodeTag(signed_value, &presented)) return null;
        var verdict = burn.run(burn.mac_burn, ?[]const u8, verifyBody, .{ keys, name, signed_value, &presented, Mode.timed });
        // The accept/reject verdict is this function's public answer, and the
        // payload it points at is the client's own text: declassified for
        // ctgrind before parsing the (authenticated, public) issue time.
        std.valgrind.memcheck.makeMemDefined(std.mem.asBytes(&verdict));
        const payload = verdict orelse return null;
        const bar = std.mem.findScalar(u8, payload, '|') orelse return null;
        const issued = parseIssued(payload[0..bar]) orelse return null;
        if (!fresh(issued, now_s, max_age_s)) return null;
        return payload[bar + 1 ..];
    }
};

/// Domain prefix of every timed MAC input / AEAD associated data.
const timed_domain = "timed1\x00";

fn decimalLen(v: i64) usize {
    var buf: [24]u8 = undefined;
    return (std.mem.print(&buf, "{d}", .{v}) catch unreachable).len;
}

/// The decimal `signTimed` wrote: an optional '-', 1..19 digits, nothing else.
fn parseIssued(text: []const u8) ?i64 {
    if (text.len == 0 or text.len > 20) return null;
    for (text, 0..) |c, i| if (!(std.ascii.isDigit(c) or (c == '-' and i == 0 and text.len > 1))) return null;
    return std.fmt.parseInt(i64, text, 10) catch null;
}

/// `issued` is no older than `max_age_s` at `now_s` (a value from the future
/// — clocks of two servers — counts as fresh, as in gorilla/securecookie).
fn fresh(issued: i64, now_s: i64, max_age_s: i64) bool {
    const age = std.math.sub(i64, now_s, issued) catch return false;
    return age <= max_age_s;
}

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

    /// Longest cookie name `sealTimed`/`openTimed` take (it is copied into
    /// the associated data behind the timed domain prefix).
    pub const max_timed_name = 255;
    const issued_len = 8;

    /// Length of `sealTimed`'s result for a `value_len`-byte value.
    pub fn timedLen(value_len: usize) usize {
        return len(issued_len + value_len);
    }

    /// `sealRandom` with the issue time sealed in: plaintext = issued_s (i64
    /// big-endian) ‖ value, associated data = "timed1" 0x00 ‖ name, so a
    /// timed value never opens as an untimed one and back. `openTimed`
    /// refuses it once older than its `max_age_s`. This module's own format
    /// (gorilla/securecookie's idea); cookie-rs's `PrivateJar` cannot open it.
    pub fn sealTimed(io: std.Io, key: *const Key, name: []const u8, value: []const u8, issued_s: i64, out: []u8) SealRandomError![]const u8 {
        var nonce: [nonce_len]u8 = undefined;
        try io.randomSecure(&nonce);
        return sealTimedNonce(key, name, value, issued_s, nonce, out);
    }

    /// `sealTimed` with the caller's nonce (tests, vectors). Never repeat one
    /// under a key.
    pub fn sealTimedNonce(key: *const Key, name: []const u8, value: []const u8, issued_s: i64, nonce: [nonce_len]u8, out: []u8) SignError![]const u8 {
        if (name.len > max_timed_name) return error.InvalidValue;
        const enc_len = timedLen(value.len);
        if (out.len < enc_len) return error.NoSpaceLeft;
        return burn.run(burn.msg_burn, []const u8, sealTimedBody, .{ key, name, value, issued_s, nonce, out[0..enc_len] });
    }

    fn timedAd(buf: *[timed_domain.len + max_timed_name]u8, name: []const u8) []const u8 {
        @memcpy(buf[0..timed_domain.len], timed_domain);
        @memcpy(buf[timed_domain.len..][0..name.len], name);
        return buf[0 .. timed_domain.len + name.len];
    }

    fn sealTimedBody(key: *const Key, name: []const u8, value: []const u8, issued_s: i64, nonce: [nonce_len]u8, out: []u8) []const u8 {
        const m_len = issued_len + value.len;
        const r = overhead + m_len;
        const raw = out[out.len - r ..];
        std.debug.assert(!overlaps(raw, value));
        raw[0..nonce_len].* = nonce;
        // The plaintext is assembled where the ciphertext goes and encrypted
        // in place (`c == m` is allowed).
        const m = raw[nonce_len..][0..m_len];
        std.mem.writeInt(i64, m[0..issued_len], issued_s, .big);
        @memcpy(m[issued_len..], value);
        var ad_buf: [timed_domain.len + max_timed_name]u8 = undefined;
        const tag = raw[nonce_len + m_len ..][0..tag_len];
        Aes.encryptInto(m, tag, m, timedAd(&ad_buf, name), nonce, &key.encryption);
        std.valgrind.memcheck.makeMemDefined(raw);
        encodeInPlace(out, r);
        return out;
    }

    /// The value (a slice of `out`) when one of `keys` opens a `sealTimed`
    /// value under `name` AND `now_s - issued <= max_age_s`; null otherwise.
    /// `out.len >= openBufLen(sealed.len)`. On null, `out` holds no plaintext.
    pub fn openTimed(keys: []const Key, name: []const u8, sealed: []const u8, now_s: i64, max_age_s: i64, out: []u8) ?[]const u8 {
        if (name.len > max_timed_name) return null;
        const raw_len = b64.Decoder.calcSizeForSlice(sealed) catch return null;
        if (raw_len < overhead + issued_len or out.len < raw_len) return null;
        var ad_buf: [timed_domain.len + max_timed_name]u8 = undefined;
        const ad = timedAd(&ad_buf, name);
        const m = burn.run(burn.msg_burn, ?[]const u8, openBody, .{ keys, ad, sealed, out[0..raw_len] }) orelse return null;
        // Authenticated: the issue time is metadata, not the protected value.
        var issued_bytes: [issued_len]u8 = m[0..issued_len].*;
        std.valgrind.memcheck.makeMemDefined(&issued_bytes);
        if (!fresh(std.mem.readInt(i64, &issued_bytes, .big), now_s, max_age_s)) {
            std.crypto.secureZero(u8, out[0..raw_len]);
            return null;
        }
        return out[issued_len..m.len];
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
