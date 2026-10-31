// SPDX-License-Identifier: MIT

//! Transaction signatures (TSIG, RFC 8945): sign a DNS message with a shared
//! HMAC key and verify a signed one — the authentication RFC 2136 dynamic
//! updates (`update.zig`) are sent under, and what BIND, Knot, PowerDNS and
//! Windows DNS expect from `nsupdate`, certbot's rfc2136 plugin and lego.
//!
//! One message at a time: a request (`SignOptions.request_mac = null`) or the
//! response to one (the request's MAC chained in, RFC 8945 §4.3.1). Not done:
//! the multi-message chaining of a zone transfer (§5.3.1, AXFR/IXFR are not a
//! stub client's business), truncated MACs (§5.2.2.1 — the full MAC is
//! required, which every implementation above sends by default), HMAC-MD5
//! (deprecated by §6).
//!
//! Wire shape (§4.2): the TSIG record is the LAST record of the additional
//! section, owner = key name, TYPE 250, CLASS ANY, TTL 0, never compressed.
//! The MAC covers the message as it was before the record was added (original
//! id, ARCOUNT without it), then the "TSIG variables": key name and algorithm
//! name in canonical (lower-case, uncompressed) form, class, TTL, time signed,
//! fudge, error and other data (§4.3.3).
//!
//! Verification order follows §5.2: key → MAC → time. A response the peer
//! could not authenticate comes back UNSIGNED with the TSIG error set
//! (BADSIG/BADKEY, §5.3.2); that is reported as `error.PeerBadSig`/
//! `PeerBadKey` without a MAC to check — an off-path forger can produce it,
//! but no more than it could drop the reply.
//!
//! The secret is touched only inside `sign`/`verify`, each under a dead-stack
//! burn (`burn.zig`, CONVENTIONS.md §2.1.1); MACs are compared with
//! `std.crypto.timing_safe.eql`.

const std = @import("std");
const message = @import("message.zig");
const burn = @import("burn.zig");
const b64ct = @import("b64ct").standard;
const hmac = std.crypto.auth.hmac;

/// TSIG algorithms (RFC 8945 §6). HMAC-SHA256 is the one §6 makes mandatory
/// and the default of `tsig-keygen` and `knsupdate`.
pub const Algorithm = enum {
    hmac_sha1,
    hmac_sha224,
    hmac_sha256,
    hmac_sha384,
    hmac_sha512,

    /// The algorithm's domain name, as it goes on the wire (no trailing dot).
    pub fn name(a: Algorithm) []const u8 {
        return switch (a) {
            .hmac_sha1 => "hmac-sha1",
            .hmac_sha224 => "hmac-sha224",
            .hmac_sha256 => "hmac-sha256",
            .hmac_sha384 => "hmac-sha384",
            .hmac_sha512 => "hmac-sha512",
        };
    }

    /// Case-insensitive; one trailing dot allowed (`hmac-sha256.`).
    pub fn fromName(text: []const u8) ?Algorithm {
        const t = if (std.mem.endsWith(u8, text, ".")) text[0 .. text.len - 1] else text;
        inline for (@typeInfo(Algorithm).@"enum".field_values) |fv| {
            const a: Algorithm = @fromBackingInt(@intCast(fv));
            if (std.ascii.eqlIgnoreCase(t, a.name())) return a;
        }
        return null;
    }

    pub fn macLen(a: Algorithm) u8 {
        return switch (a) {
            inline else => |c| Hmac(c).mac_length,
        };
    }
};

fn Hmac(comptime a: Algorithm) type {
    return switch (a) {
        .hmac_sha1 => hmac.HmacSha1,
        .hmac_sha224 => hmac.sha2.HmacSha224,
        .hmac_sha256 => hmac.sha2.HmacSha256,
        .hmac_sha384 => hmac.sha2.HmacSha384,
        .hmac_sha512 => hmac.sha2.HmacSha512,
    };
}

/// A shared TSIG key, as configured on the server (BIND: `key "<name>" {
/// algorithm hmac-sha256; secret "<base64>"; };`).
pub const Key = struct {
    /// Key name, dotted text (case-insensitive, trailing dot optional).
    name: []const u8,
    algorithm: Algorithm = .hmac_sha256,
    /// The raw secret bytes — the base64 of the server's configuration,
    /// DECODED. Any length; HMAC hashes a secret longer than its block.
    secret: []const u8,
};

/// Decode a key's secret from the base64 a server configuration carries
/// (BIND `secret "...";`, `nsupdate -y alg:name:secret`, `tsig-keygen`
/// output) into `out` and return the written slice. Constant-time in the
/// secret's characters (the `b64ct` module); padded standard base64, no whitespace.
/// `out.len` must be at least `b64.len / 4 * 3`. On error `out` is zeroed.
pub fn decodeSecret(out: []u8, b64: []const u8) error{ InvalidSecret, BufferTooSmall }![]u8 {
    if (out.len < b64.len / 4 * 3) return error.BufferTooSmall;
    return b64ct.decode(out, b64) catch {
        std.crypto.secureZero(u8, out);
        return error.InvalidSecret;
    };
}

/// TSIG error field (RFC 8945 §5.3, IANA "DNS RCODEs" 16–22).
pub const TsigError = enum(u16) {
    no_error = 0,
    bad_sig = 16,
    bad_key = 17,
    bad_time = 18,
    bad_trunc = 22,
    _,
};

/// Seconds a signature stays valid either side of its time (§10: 300).
pub const default_fudge: u16 = 300;

pub const max_mac_len = 64;

/// A computed MAC: what `sign` produced, or what `verify` accepted. A request's
/// MAC is the `request_mac` its response is signed and verified against.
pub const Mac = struct {
    bytes: [max_mac_len]u8 = @splat(0),
    len: u8 = 0,

    pub fn slice(m: *const Mac) []const u8 {
        return m.bytes[0..m.len];
    }
};

pub const SignOptions = struct {
    /// Time signed, seconds since the Unix epoch.
    time: u48,
    fudge: u16 = default_fudge,
    /// Signing a response: the MAC of the request it answers (§4.3.1).
    request_mac: ?[]const u8 = null,
    /// Signing an error response (§5.3): the TSIG error to report.
    @"error": TsigError = .no_error,
    /// Other data (§4.2; BADTIME responses carry the server's time here).
    other: []const u8 = "",
};

pub const SignError = error{
    /// `buf` has no room for the TSIG record after the message.
    BufferTooSmall,
    /// Key name over 253 chars / bad label.
    NameTooLong,
    BadName,
    /// The message is shorter than a header, its ARCOUNT is already 65 535,
    /// or a request MAC / other data is longer than the wire allows.
    Malformed,
};

/// Wire size of the TSIG record `sign` appends for `key` (other data empty).
/// Size the message buffer as message + this.
pub fn recordLen(key: *const Key) usize {
    const owner = std.mem.trimEnd(u8, key.name, ".").len + 2;
    const alg = key.algorithm.name().len + 2;
    return owner + 10 + alg + 6 + 2 + 2 + key.algorithm.macLen() + 2 + 2 + 2;
}

/// Sign the message `buf[0..msg_len]`: append the TSIG record after it in
/// `buf`, bump ARCOUNT, and return the whole signed message (a slice of
/// `buf`). The MAC goes to `out_mac` — keep it to verify the response.
pub fn sign(buf: []u8, msg_len: usize, key: *const Key, options: SignOptions, out_mac: *Mac) SignError![]u8 {
    return burn.run(burn.tsig_burn, SignError![]u8, signBody, .{ buf, msg_len, key, &options, out_mac });
}

fn signBody(buf: []u8, msg_len: usize, key: *const Key, options: *const SignOptions, out_mac: *Mac) SignError![]u8 {
    out_mac.* = .{};
    if (msg_len < message.header_len or msg_len > buf.len) return error.Malformed;
    if (options.other.len > std.math.maxInt(u16)) return error.Malformed;
    if (options.request_mac) |rm| if (rm.len > std.math.maxInt(u16)) return error.Malformed;
    const arcount = std.mem.readInt(u16, buf[10..12], .big);
    if (arcount == std.math.maxInt(u16)) return error.Malformed;

    var owner_buf: [max_wire_name]u8 = undefined;
    const owner = try canonicalName(&owner_buf, key.name);
    var alg_buf: [max_wire_name]u8 = undefined;
    const alg = canonicalName(&alg_buf, key.algorithm.name()) catch unreachable;

    // The record's RDLENGTH is a u16 too: `other` alone may be 65 535 bytes,
    // and with the algorithm name, MAC and fixed fields the sum can pass it
    // (sweep DN-2: `writeRecord`'s `@intCast` trapped).
    const rdlen = alg.len + 6 + 2 + 2 + key.algorithm.macLen() + 2 + 2 + 2 + options.other.len;
    if (rdlen > std.math.maxInt(u16)) return error.Malformed;

    const fields: Fields = .{
        .time = options.time,
        .fudge = options.fudge,
        .err = @backingInt(options.@"error"),
        .other = options.other,
    };
    computeMac(key, options.request_mac, buf[0..message.header_len], buf[message.header_len..msg_len], owner, alg, &fields, out_mac);

    const mac = out_mac.slice();
    var w: std.Io.Writer = .fixed(buf[msg_len..]);
    writeRecord(&w, owner, alg, &fields, mac, std.mem.readInt(u16, buf[0..2], .big)) catch return error.BufferTooSmall;
    std.mem.writeInt(u16, buf[10..12], arcount + 1, .big);
    return buf[0 .. msg_len + w.end];
}

fn writeRecord(w: *std.Io.Writer, owner: []const u8, alg: []const u8, f: *const Fields, mac: []const u8, original_id: u16) error{WriteFailed}!void {
    const rdlen = alg.len + 6 + 2 + 2 + mac.len + 2 + 2 + 2 + f.other.len;
    try w.writeAll(owner);
    try w.writeInt(u16, @backingInt(message.Type.tsig), .big);
    try w.writeInt(u16, @backingInt(message.Class.any), .big);
    try w.writeInt(u32, 0, .big);
    try w.writeInt(u16, @intCast(rdlen), .big);
    try w.writeAll(alg);
    try w.writeInt(u48, f.time, .big);
    try w.writeInt(u16, f.fudge, .big);
    try w.writeInt(u16, @intCast(mac.len), .big);
    try w.writeAll(mac);
    try w.writeInt(u16, original_id, .big);
    try w.writeInt(u16, f.err, .big);
    try w.writeInt(u16, @intCast(f.other.len), .big);
    try w.writeAll(f.other);
}

pub const VerifyOptions = struct {
    /// The current time, seconds since the Unix epoch.
    now: u64,
    /// Verifying a response: the MAC of the request it answers (`sign`'s
    /// `out_mac`). Null: `msg` is a request.
    request_mac: ?[]const u8 = null,
};

pub const VerifyError = error{
    /// The message carries no TSIG record (its last additional record is not
    /// one) — a response to a signed request must be signed (§5.3).
    Unsigned,
    /// The message does not parse up to its TSIG record, a TSIG record sits
    /// anywhere but last, its name is compressed, or its RDATA is malformed;
    /// also a `request_mac` longer than the 65 535 bytes the wire allows.
    Malformed,
    /// Signed under another key name or algorithm than `key`.
    BadKey,
    /// The MAC does not match (or is empty without a TSIG error).
    BadSig,
    /// The MAC is shorter than the algorithm's: truncation (§5.2.2.1) is not
    /// accepted.
    BadTrunc,
    /// Correctly signed, but outside time ± fudge of `now` (§5.2.3).
    BadTime,
    /// The peer could not verify OUR signature (unsigned BADSIG reply).
    PeerBadSig,
    /// The peer does not know our key (unsigned BADKEY reply).
    PeerBadKey,
    /// The peer rejected our time (signed BADTIME reply; clocks apart).
    PeerBadTime,
    /// The peer returned another TSIG error code.
    PeerError,
};

/// Verify the TSIG record that ends `msg` against `key`. On success the
/// record's MAC is written to `out_mac` (a server signs its response with it
/// as `request_mac`).
pub fn verify(msg: []const u8, key: *const Key, options: VerifyOptions, out_mac: *Mac) VerifyError!void {
    return burn.run(burn.tsig_burn, VerifyError!void, verifyBody, .{ msg, key, &options, out_mac });
}

fn verifyBody(msg: []const u8, key: *const Key, options: *const VerifyOptions, out_mac: *Mac) VerifyError!void {
    out_mac.* = .{};
    // The MAC covers the request MAC behind a 16-bit length (sweep DN-3: a
    // longer one trapped in `computeMac`'s `@intCast`); no real MAC is that long.
    if (options.request_mac) |rm| if (rm.len > std.math.maxInt(u16)) return error.Malformed;
    const rec = try findRecord(msg);

    var owner_buf: [max_wire_name]u8 = undefined;
    const owner = canonicalName(&owner_buf, key.name) catch return error.BadKey;
    var alg_buf: [max_wire_name]u8 = undefined;
    const alg = canonicalName(&alg_buf, key.algorithm.name()) catch unreachable;
    if (!std.ascii.eqlIgnoreCase(rec.owner, owner) or !std.ascii.eqlIgnoreCase(rec.alg, alg)) return error.BadKey;

    const peer_error: TsigError = @fromBackingInt(@intCast(rec.fields.err));
    if (rec.mac.len == 0) return switch (peer_error) {
        .no_error => error.BadSig,
        .bad_sig => error.PeerBadSig,
        .bad_key => error.PeerBadKey,
        .bad_time => error.PeerBadTime,
        else => error.PeerError,
    };
    const want_len = key.algorithm.macLen();
    if (rec.mac.len < want_len) return error.BadTrunc;
    if (rec.mac.len > want_len) return error.Malformed;

    // The message as it was signed: original id, ARCOUNT without the TSIG
    // record, body up to where the record starts.
    var header: [message.header_len]u8 = msg[0..message.header_len].*;
    std.mem.writeInt(u16, header[0..2], rec.original_id, .big);
    std.mem.writeInt(u16, header[10..12], std.mem.readInt(u16, header[10..12], .big) - 1, .big);

    var computed: Mac = .{};
    computeMac(key, options.request_mac, &header, msg[message.header_len..rec.start], owner, alg, &rec.fields, &computed);
    var got: [max_mac_len]u8 = @splat(0);
    @memcpy(got[0..rec.mac.len], rec.mac);
    if (!std.crypto.timing_safe.eql([max_mac_len]u8, got, computed.bytes)) return error.BadSig;

    const signed: u64 = rec.fields.time;
    const skew = if (options.now > signed) options.now - signed else signed - options.now;
    if (skew > rec.fields.fudge) return error.BadTime;

    switch (peer_error) {
        .no_error => {},
        .bad_time => return error.PeerBadTime,
        .bad_sig => return error.PeerBadSig,
        .bad_key => return error.PeerBadKey,
        else => return error.PeerError,
    }
    out_mac.* = computed;
}

// ── internals ───────────────────────────────────────────────────────────────

/// Wire-format name cap (RFC 1035: 255 octets).
const max_wire_name = 255;

/// The TSIG fields the MAC covers besides the names (§4.3.3).
const Fields = struct {
    time: u48,
    fudge: u16,
    err: u16,
    other: []const u8,
};

/// `text` in canonical wire form (§4.3.3 / RFC 4034 §6.2): uncompressed,
/// ASCII letters lower-cased.
fn canonicalName(out: *[max_wire_name]u8, text: []const u8) error{ NameTooLong, BadName }![]const u8 {
    var w: std.Io.Writer = .fixed(out);
    message.writeName(&w, text) catch |err| switch (err) {
        error.NameTooLong => return error.NameTooLong,
        error.BadName => return error.BadName,
        // 253 text chars = 255 wire octets: `out` always fits.
        error.WriteFailed, error.BufferTooSmall => unreachable,
    };
    const wire = w.buffered();
    for (wire) |*c| c.* = std.ascii.toLower(c.*);
    return wire;
}

fn computeMac(
    key: *const Key,
    request_mac: ?[]const u8,
    header: *const [message.header_len]u8,
    body: []const u8,
    owner: []const u8,
    alg: []const u8,
    f: *const Fields,
    out: *Mac,
) void {
    switch (key.algorithm) {
        inline else => |a| {
            const H = Hmac(a);
            var h = H.init(key.secret);
            var be: [6]u8 = undefined;
            if (request_mac) |rm| {
                std.mem.writeInt(u16, be[0..2], @intCast(rm.len), .big);
                h.update(be[0..2]);
                h.update(rm);
            }
            h.update(header);
            h.update(body);
            h.update(owner);
            std.mem.writeInt(u16, be[0..2], @backingInt(message.Class.any), .big);
            h.update(be[0..2]);
            h.update(&[4]u8{ 0, 0, 0, 0 }); // TTL
            h.update(alg);
            std.mem.writeInt(u48, be[0..6], f.time, .big);
            h.update(be[0..6]);
            std.mem.writeInt(u16, be[0..2], f.fudge, .big);
            h.update(be[0..2]);
            std.mem.writeInt(u16, be[0..2], f.err, .big);
            h.update(be[0..2]);
            std.mem.writeInt(u16, be[0..2], @intCast(f.other.len), .big);
            h.update(be[0..2]);
            h.update(f.other);
            h.final(out.bytes[0..H.mac_length]);
            out.len = H.mac_length;
        },
    }
}

/// A parsed TSIG record; slices point into the message.
const Record = struct {
    /// Offset of the record (= end of the message it signs).
    start: usize,
    owner: []const u8,
    alg: []const u8,
    fields: Fields,
    mac: []const u8,
    original_id: u16,
};

/// Walk the message to its last record and parse that as TSIG. Any TSIG
/// record before it, or bytes after it, is `Malformed`.
fn findRecord(msg: []const u8) VerifyError!Record {
    if (msg.len < message.header_len) return error.Malformed;
    const qd = std.mem.readInt(u16, msg[4..6], .big);
    const an = std.mem.readInt(u16, msg[6..8], .big);
    const ns = std.mem.readInt(u16, msg[8..10], .big);
    const ar = std.mem.readInt(u16, msg[10..12], .big);
    if (ar == 0) return error.Unsigned;

    var pos: usize = message.header_len;
    for (0..qd) |_| {
        pos = try skipName(msg, pos);
        if (msg.len - pos < 4) return error.Malformed;
        pos += 4;
    }
    const before_last = @as(usize, an) + ns + ar - 1;
    for (0..before_last) |_| {
        pos = try skipName(msg, pos);
        if (msg.len - pos < 10) return error.Malformed;
        if (std.mem.readInt(u16, msg[pos..][0..2], .big) == @backingInt(message.Type.tsig)) return error.Malformed;
        const rdlen = std.mem.readInt(u16, msg[pos + 8 ..][0..2], .big);
        pos += 10;
        if (msg.len - pos < rdlen) return error.Malformed;
        pos += rdlen;
    }

    const start = pos;
    const owner_end = try skipName(msg, pos);
    if (msg.len - owner_end < 10) return error.Malformed;
    if (std.mem.readInt(u16, msg[owner_end..][0..2], .big) != @backingInt(message.Type.tsig)) return error.Unsigned;
    const owner = msg[start..owner_end];
    if (!isUncompressed(owner)) return error.Malformed;
    var p = owner_end + 2;
    if (std.mem.readInt(u16, msg[p..][0..2], .big) != @backingInt(message.Class.any)) return error.Malformed;
    p += 2;
    if (std.mem.readInt(u32, msg[p..][0..4], .big) != 0) return error.Malformed;
    p += 4;
    const rdlen = std.mem.readInt(u16, msg[p..][0..2], .big);
    p += 2;
    if (msg.len - p != rdlen) return error.Malformed; // the record ends the message

    const alg_start = p;
    p = try skipName(msg, p);
    const alg = msg[alg_start..p];
    if (!isUncompressed(alg)) return error.Malformed;
    if (msg.len - p < 6 + 2 + 2) return error.Malformed;
    const time = std.mem.readInt(u48, msg[p..][0..6], .big);
    const fudge = std.mem.readInt(u16, msg[p + 6 ..][0..2], .big);
    const mac_len = std.mem.readInt(u16, msg[p + 8 ..][0..2], .big);
    p += 10;
    if (msg.len - p < @as(usize, mac_len) + 6) return error.Malformed;
    const mac = msg[p..][0..mac_len];
    p += mac_len;
    const original_id = std.mem.readInt(u16, msg[p..][0..2], .big);
    const err = std.mem.readInt(u16, msg[p + 2 ..][0..2], .big);
    const other_len = std.mem.readInt(u16, msg[p + 4 ..][0..2], .big);
    p += 6;
    if (msg.len - p != other_len) return error.Malformed;
    return .{
        .start = start,
        .owner = owner,
        .alg = alg,
        .fields = .{ .time = time, .fudge = fudge, .err = err, .other = msg[p..] },
        .mac = mac,
        .original_id = original_id,
    };
}

/// Position after the (possibly compressed) name at `pos`. Bounds only — the
/// skipped names are never interpreted.
fn skipName(msg: []const u8, start: usize) VerifyError!usize {
    var pos = start;
    var octets: usize = 0;
    while (true) {
        if (pos >= msg.len) return error.Malformed;
        const b = msg[pos];
        switch (b & 0xc0) {
            0x00 => {
                if (b == 0) return pos + 1;
                octets += 1 + @as(usize, b);
                if (octets > max_wire_name - 1) return error.Malformed;
                if (msg.len - pos - 1 < b) return error.Malformed;
                pos += 1 + b;
            },
            0xc0 => {
                if (msg.len - pos < 2) return error.Malformed;
                return pos + 2;
            },
            else => return error.Malformed,
        }
    }
}

/// A name as `skipName` delimited it, without a compression pointer.
fn isUncompressed(wire: []const u8) bool {
    return wire.len > 0 and wire[wire.len - 1] == 0;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// RFC 8945 has no test vectors; these are pinned against dnspython 2.8.0
/// (`tools/tsig_oracle.py` regenerates them) — see `tsig_vectors.zig`.
const vectors = @import("tsig_vectors.zig");

test "sign: byte-identical to dnspython for every algorithm" {
    for (vectors.signed) |v| {
        var buf: [1024]u8 = undefined;
        @memcpy(buf[0..v.unsigned.len], v.unsigned);
        const key: Key = .{ .name = v.key_name, .algorithm = v.algorithm, .secret = v.secret };
        var mac: Mac = undefined;
        const out = try sign(&buf, v.unsigned.len, &key, .{ .time = v.time, .fudge = v.fudge, .request_mac = v.request_mac }, &mac);
        try testing.expectEqualSlices(u8, v.signed, out);
        try testing.expectEqual(v.signed.len - v.unsigned.len, recordLen(&key));
    }
}

test "verify: accepts dnspython's signatures, returns their MAC" {
    for (vectors.signed) |v| {
        const key: Key = .{ .name = v.key_name, .algorithm = v.algorithm, .secret = v.secret };
        var mac: Mac = undefined;
        try verify(v.signed, &key, .{ .now = v.time, .request_mac = v.request_mac }, &mac);
        try testing.expectEqual(@as(usize, v.algorithm.macLen()), mac.len);
        // The MAC sits right before original id, error and other len (other empty).
        try testing.expectEqualSlices(u8, v.signed[v.signed.len - 6 - mac.len ..][0..mac.len], mac.slice());
    }
}

test "verify: every single-bit flip of a signed message is rejected" {
    const v = vectors.signed[2];
    const key: Key = .{ .name = v.key_name, .algorithm = v.algorithm, .secret = v.secret };
    var buf: [1024]u8 = undefined;
    for (0..v.signed.len * 8) |bit| {
        @memcpy(buf[0..v.signed.len], v.signed);
        buf[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        var mac: Mac = undefined;
        if (verify(buf[0..v.signed.len], &key, .{ .now = v.time, .request_mac = v.request_mac }, &mac)) |_| {
            // Invisible to the MAC by design: the header id (the MAC covers the
            // record's original id, §4.3.2), and a case flip inside the TSIG
            // key or algorithm name (compared and hashed in canonical form).
            const at = bit / 8;
            const c = v.signed[at];
            const case_flip = at >= v.unsigned.len and bit % 8 == 5 and std.ascii.isAlphabetic(c);
            try testing.expect(at < 2 or case_flip);
        } else |_| {}
    }
}

test "verify: key, time, truncation, chaining" {
    const v = vectors.signed[2]; // hmac-sha256 request
    var key: Key = .{ .name = v.key_name, .algorithm = v.algorithm, .secret = v.secret };
    var mac: Mac = undefined;
    const opts: VerifyOptions = .{ .now = v.time, .request_mac = v.request_mac };

    // Time: the fudge edge is inside, one second past it is not.
    try verify(v.signed, &key, .{ .now = v.time + v.fudge, .request_mac = v.request_mac }, &mac);
    try verify(v.signed, &key, .{ .now = v.time - v.fudge, .request_mac = v.request_mac }, &mac);
    try testing.expectError(error.BadTime, verify(v.signed, &key, .{ .now = v.time + v.fudge + 1, .request_mac = v.request_mac }, &mac));
    try testing.expectError(error.BadTime, verify(v.signed, &key, .{ .now = v.time - v.fudge - 1, .request_mac = v.request_mac }, &mac));
    try testing.expectEqual(@as(u8, 0), mac.len);

    // Another secret, another key name, another algorithm.
    key.secret = "not the secret";
    try testing.expectError(error.BadSig, verify(v.signed, &key, opts, &mac));
    key = .{ .name = "other.key", .algorithm = v.algorithm, .secret = v.secret };
    try testing.expectError(error.BadKey, verify(v.signed, &key, opts, &mac));
    key = .{ .name = v.key_name, .algorithm = .hmac_sha512, .secret = v.secret };
    try testing.expectError(error.BadKey, verify(v.signed, &key, opts, &mac));
    key = .{ .name = v.key_name, .algorithm = v.algorithm, .secret = v.secret };

    // A request MAC where none was signed, and the other way round.
    try testing.expectError(error.BadSig, verify(v.signed, &key, .{ .now = v.time, .request_mac = "x" }, &mac));
    const resp = vectors.signed[5];
    try testing.expect(resp.request_mac != null);
    const rkey: Key = .{ .name = resp.key_name, .algorithm = resp.algorithm, .secret = resp.secret };
    try testing.expectError(error.BadSig, verify(resp.signed, &rkey, .{ .now = resp.time }, &mac));

    // Unsigned: no additional records; and an additional that is not TSIG.
    try testing.expectError(error.Unsigned, verify(v.unsigned, &key, opts, &mac));
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.writeAll(v.unsigned);
    try w.writeAll(&.{ 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0 }); // OPT
    buf[11] += 1;
    try testing.expectError(error.Unsigned, verify(w.buffered(), &key, opts, &mac));

    // Truncated MAC: shorten the MAC field by 16 bytes, fix the lengths.
    const n = v.signed.len;
    const mac_at = n - 6 - 32;
    @memcpy(buf[0..mac_at], v.signed[0..mac_at]);
    std.mem.writeInt(u16, buf[mac_at - 2 ..][0..2], 16, .big);
    @memcpy(buf[mac_at..][0..16], v.signed[mac_at..][0..16]);
    @memcpy(buf[mac_at + 16 ..][0..6], v.signed[n - 6 ..]);
    const tlen = n - 16;
    // rdlength, then algorithm name, time (6), fudge (2), MAC size (2), MAC.
    const rdlen_at = mac_at - 2 - 2 - 6 - (Algorithm.hmac_sha256.name().len + 2) - 2;
    std.mem.writeInt(u16, buf[rdlen_at..][0..2], std.mem.readInt(u16, v.signed[rdlen_at..][0..2], .big) - 16, .big);
    try testing.expectError(error.BadTrunc, verify(buf[0..tlen], &key, opts, &mac));
}

test "sign then verify: request/response chain, peer errors" {
    const key: Key = .{ .name = "update-key.example.", .algorithm = .hmac_sha384, .secret = "0123456789abcdef0123456789abcdef" };
    var qbuf: [message.max_query_len]u8 = undefined;
    const q = try message.encodeQuery(&qbuf, "example.org", .soa, .{ .id = 0x1234, .edns_udp_size = null });
    var buf: [512]u8 = undefined;
    @memcpy(buf[0..q.len], q);
    var req_mac: Mac = undefined;
    const req = try sign(&buf, q.len, &key, .{ .time = 1_700_000_000 }, &req_mac);
    var seen: Mac = undefined;
    try verify(req, &key, .{ .now = 1_700_000_100 }, &seen);
    try testing.expectEqualSlices(u8, req_mac.slice(), seen.slice());

    // The server answers: QR set, signed with the request MAC chained in.
    var rbuf: [512]u8 = undefined;
    @memcpy(rbuf[0..q.len], q);
    rbuf[2] |= 0x80;
    var resp_mac: Mac = undefined;
    const resp = try sign(&rbuf, q.len, &key, .{ .time = 1_700_000_001, .request_mac = req_mac.slice() }, &resp_mac);
    try verify(resp, &key, .{ .now = 1_700_000_002, .request_mac = req_mac.slice() }, &seen);
    try testing.expectError(error.BadSig, verify(resp, &key, .{ .now = 1_700_000_002 }, &seen));

    // A signed BADTIME reply verifies, then reports the peer's verdict.
    std.mem.writeInt(u16, rbuf[10..12], 0, .big); // drop the TSIG record signed above
    const bt = try sign(&rbuf, q.len, &key, .{ .time = 1_700_000_001, .request_mac = req_mac.slice(), .@"error" = .bad_time, .other = &.{ 0, 0, 0x65, 0x53, 0xf1, 0x00 } }, &resp_mac);
    try testing.expectError(error.PeerBadTime, verify(bt, &key, .{ .now = 1_700_000_002, .request_mac = req_mac.slice() }, &seen));

    // An unsigned BADKEY / BADSIG reply (MAC size 0, §5.3.2).
    for ([_]struct { TsigError, VerifyError }{ .{ .bad_key, error.PeerBadKey }, .{ .bad_sig, error.PeerBadSig }, .{ .no_error, error.BadSig } }) |c| {
        var ebuf: [512]u8 = undefined;
        @memcpy(ebuf[0..q.len], q);
        var ew: std.Io.Writer = .fixed(ebuf[q.len..]);
        var ob: [max_wire_name]u8 = undefined;
        var ab: [max_wire_name]u8 = undefined;
        try writeRecord(&ew, try canonicalName(&ob, key.name), try canonicalName(&ab, key.algorithm.name()), &.{ .time = 1_700_000_001, .fudge = 300, .err = @backingInt(c[0]), .other = "" }, "", 0x1234);
        std.mem.writeInt(u16, ebuf[10..12], 1, .big);
        try testing.expectError(c[1], verify(ebuf[0 .. q.len + ew.end], &key, .{ .now = 1_700_000_002, .request_mac = req_mac.slice() }, &seen));
    }
}

test "sign: buffer, ARCOUNT and name errors" {
    const key: Key = .{ .name = "k", .secret = "s" };
    var buf: [128]u8 = undefined;
    const q = try message.encodeQuery(&buf, "a.example", .a, .{ .edns_udp_size = null });
    var mac: Mac = undefined;
    try testing.expectError(error.BufferTooSmall, sign(buf[0 .. q.len + recordLen(&key) - 1], q.len, &key, .{ .time = 1 }, &mac));
    _ = try sign(buf[0 .. q.len + recordLen(&key)], q.len, &key, .{ .time = 1 }, &mac);
    try testing.expectError(error.Malformed, sign(&buf, 11, &key, .{ .time = 1 }, &mac));
    std.mem.writeInt(u16, buf[10..12], 0xffff, .big);
    try testing.expectError(error.Malformed, sign(&buf, q.len, &key, .{ .time = 1 }, &mac));
    std.mem.writeInt(u16, buf[10..12], 0, .big);
    try testing.expectError(error.BadName, sign(&buf, q.len, &.{ .name = "a..b", .secret = "s" }, .{ .time = 1 }, &mac));
}

test "verify: never panics on a truncated or corrupted signed message" {
    for (vectors.signed) |v| {
        const key: Key = .{ .name = v.key_name, .algorithm = v.algorithm, .secret = v.secret };
        var mac: Mac = undefined;
        for (0..v.signed.len) |cut| {
            if (verify(v.signed[0..cut], &key, .{ .now = v.time, .request_mac = v.request_mac }, &mac)) |_| {
                return error.TestUnexpectedResult;
            } else |_| {}
        }
    }
}

test "decodeSecret: tsig-keygen output, and garbage refused" {
    var out: [64]u8 = undefined;
    // `tsig-keygen -a hmac-sha256` prints 44 base64 characters for 32 bytes.
    const secret = try decodeSecret(&out, "qlITL/7KKX2IHxzOvaHp/EAOqNEo78ZbNtUvaEN707Q=");
    var want: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("hmac-sha256.key.", &want, .{});
    try testing.expectEqualSlices(u8, &want, secret);
    try testing.expectError(error.InvalidSecret, decodeSecret(&out, "qlITL/7KKX2IHxzOvaHp/EAOqNEo78ZbNtUvaEN707Q"));
    try testing.expectError(error.InvalidSecret, decodeSecret(&out, "qlIT*/7K"));
    try testing.expect(std.mem.allEqual(u8, out[0..6], 0));
    try testing.expectError(error.BufferTooSmall, decodeSecret(out[0..2], "qlITL/7K"));
}

test "Algorithm.fromName" {
    try testing.expectEqual(Algorithm.hmac_sha256, Algorithm.fromName("HMAC-SHA256.").?);
    try testing.expectEqual(Algorithm.hmac_sha1, Algorithm.fromName("hmac-sha1").?);
    try testing.expect(Algorithm.fromName("hmac-md5.sig-alg.reg.int") == null);
    try testing.expect(Algorithm.fromName("hmac-sha256..") == null);
}
