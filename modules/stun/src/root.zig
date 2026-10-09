// SPDX-License-Identifier: MIT
//! stun — STUN client (RFC 8489): transport-agnostic Binding message
//! encode/decode/verify + XOR-MAPPED-ADDRESS, FINGERPRINT, MESSAGE-INTEGRITY.
//!
//! Session Traversal Utilities for NAT (STUN, RFC 8489, née RFC 5389) lets a
//! host behind a NAT discover its public "reflexive" address by sending a
//! Binding request to a STUN server and reading the XOR-MAPPED-ADDRESS the
//! server reflects back. This module is the **transport-agnostic core**:
//! build/parse/verify STUN messages over caller-provided byte buffers, with no
//! I/O of its own. A small optional `query` helper drives one Binding exchange
//! over `std.Io.net` UDP for callers that want the batteries included.
//!
//! ## Wire model
//!
//! Every STUN message is a 20-byte header — a 16-bit type (2-bit class +
//! 12-bit method, interleaved per RFC 8489 §5), a 16-bit attribute-region
//! length, the 32-bit magic cookie `0x2112A442`, and a 96-bit transaction id —
//! followed by a sequence of TLV attributes, each padded to a 4-byte boundary.
//!
//! - `Builder` writes a message into a caller buffer: header, generic
//!   attributes, then the two "special" trailing attributes whose value
//!   depends on the bytes before them — MESSAGE-INTEGRITY (HMAC-SHA1-20 keyed
//!   by a short-term credential) and FINGERPRINT (CRC-32 ⊕ `0x5354554E`). Both
//!   are computed with the header length field temporarily set to *include*
//!   the attribute being added, exactly as the RFC requires.
//! - `Message` parses a buffer: it validates the header and cookie, then hands
//!   out an `AttributeIterator`. `xorMappedAddress` / `mappedAddress` decode the
//!   reflexive address to a `netaddr.Ip` + port; `verifyFingerprint` and
//!   `verifyMessageIntegrity` re-derive the trailing attributes over the exact
//!   same byte regions (streamed, no copy) and compare — the MAC in
//!   **constant time** via `std.crypto.timing_safe.eql`.
//!
//! ## Provenance & scope
//!
//! Clean-room from RFC 8489 and the RFC 5769 test vectors; the attribute
//! TLV (de)serialization structure is modelled after Corendos/ztun (MIT) — no
//! third-party code copied. v1 implements the Binding method and short-term
//! credentials only. The long-term credential mechanism (RFC 8489 §9.2:
//! username/realm/nonce, MD5/SHA-256 PASSWORD-ALGORITHMS, USERHASH), the
//! server side, ICE/TURN, and TCP/TLS transport are out of scope — see the
//! module README.

const std = @import("std");
const netaddr = @import("netaddr");
const burn = @import("burn.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "STUN client (RFC 8489) — NAT reflexive-address discovery: XOR-MAPPED-ADDRESS + MESSAGE-INTEGRITY + FINGERPRINT",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{ .linux64, .linux32 },
    .platform = .any, // core is pure; only the optional `query` helper does I/O
    .role = .codec,
    .concurrency = .reentrant, // no shared state; every call is over caller buffers
    .model_after = "RFC 8489 STUN; design after Corendos/ztun; RFC 5769 test vectors",
    .deps = .{"netaddr"},
};

// ── constants ────────────────────────────────────────────────────────────────

/// The STUN magic cookie (RFC 8489 §5), fixed in the header at bytes 4..8.
pub const magic_cookie: u32 = 0x2112A442;

/// The magic cookie as big-endian bytes — the per-byte XOR key for an IPv4
/// XOR-MAPPED-ADDRESS, and the first four bytes of the IPv6 XOR key.
pub const magic_cookie_bytes = [4]u8{ 0x21, 0x12, 0xA4, 0x42 };

/// Fixed size of the STUN message header in bytes.
pub const header_len = 20;

/// The 96-bit transaction id that ties a response to its request.
pub const TransactionId = [12]u8;

/// Value XORed into the CRC-32 to form the FINGERPRINT (RFC 8489 §14.7); it is
/// the ASCII "STUN" (`0x53 0x54 0x55 0x4E`) so a FINGERPRINT can never collide
/// with a genuine CRC of the same message.
pub const fingerprint_xor: u32 = 0x5354554E;

// ── message class & method ───────────────────────────────────────────────────

/// The two-bit message class (RFC 8489 §5). The numeric values are the on-wire
/// C1..C0 bits, so `@intFromEnum` feeds `encodeType` directly.
pub const Class = enum(u2) {
    request = 0b00,
    indication = 0b01,
    success_response = 0b10,
    error_response = 0b11,
};

/// The 12-bit message method. Non-exhaustive: only Binding is defined by the
/// base spec, but the wire carries a full 12-bit space (TURN, etc.).
pub const Method = enum(u12) {
    binding = 0x001,
    _,
};

/// Interleave a class and method into the 16-bit STUN message type (RFC 8489
/// §5): method bits M11..M0 are split around the two class bits C1/C0.
pub fn encodeType(class: Class, method: Method) u16 {
    const m: u16 = @intFromEnum(method);
    const c: u16 = @intFromEnum(class);
    return ((m & 0x0F80) << 2) | ((m & 0x0070) << 1) | (m & 0x000F) |
        ((c & 0x2) << 7) | ((c & 0x1) << 4);
}

/// Recover the class from a 16-bit message type.
pub fn decodeClass(t: u16) Class {
    const c: u2 = @intCast(((t >> 4) & 0x1) | ((t >> 7) & 0x2));
    return @enumFromInt(c);
}

/// Recover the 12-bit method from a 16-bit message type.
pub fn decodeMethod(t: u16) u12 {
    return @intCast((t & 0x000F) | ((t >> 1) & 0x0070) | ((t >> 2) & 0x0F80));
}

// ── attribute types ──────────────────────────────────────────────────────────

/// The registered STUN attribute type codes used by v1. The comprehension-
/// required range is `0x0000..0x8000`; `0x8000..` is comprehension-optional.
pub const AttributeType = enum(u16) {
    mapped_address = 0x0001,
    username = 0x0006,
    message_integrity = 0x0008,
    error_code = 0x0009,
    unknown_attributes = 0x000A,
    realm = 0x0014,
    nonce = 0x0015,
    message_integrity_sha256 = 0x001C,
    password_algorithm = 0x001D,
    userhash = 0x001E,
    xor_mapped_address = 0x0020,
    software = 0x8022,
    alternate_server = 0x8023,
    fingerprint = 0x8028,
    _,
};

fn attrCode(t: AttributeType) u16 {
    return @intFromEnum(t);
}

// ── errors ───────────────────────────────────────────────────────────────────

pub const DecodeError = error{
    /// Buffer shorter than the header, or an attribute runs past the end.
    Truncated,
    /// The two most-significant bits of the type were not zero (not STUN).
    NotStun,
    /// The magic cookie did not match `magic_cookie`.
    BadCookie,
    /// The header length field was not a multiple of 4.
    BadLength,
    /// An attribute value was too short for its declared meaning.
    MalformedAttribute,
    /// A MAPPED-ADDRESS family byte was neither IPv4 (0x01) nor IPv6 (0x02).
    UnknownAddressFamily,
};

pub const BuildError = error{
    /// The caller buffer could not hold the next attribute.
    BufferTooSmall,
    /// An attribute value longer than its field allows (ERROR-CODE reason
    /// over 763 bytes, a value over 65535, an UNKNOWN-ATTRIBUTES list that
    /// cannot fit one attribute).
    ValueTooLong,
    /// An ERROR-CODE outside 300-699 (RFC 8489 §14.8).
    InvalidErrorCode,
};

// ── decoded address ──────────────────────────────────────────────────────────

/// A reflexive transport address decoded from a (XOR-)MAPPED-ADDRESS attribute.
pub const AddressPort = struct {
    ip: netaddr.Ip,
    port: u16,
};

// ── builder (encode) ─────────────────────────────────────────────────────────

/// Writes a STUN message into a caller-provided buffer. Append generic
/// attributes with `addAttribute` (and the typed helpers), then — last, and in
/// this order if both are present — `addMessageIntegrity` and `addFingerprint`,
/// whose values cover every byte written before them. `finish` returns the
/// message slice.
pub const Builder = struct {
    buf: []u8,
    /// Bytes written so far = the total message length (header + attributes).
    len: usize,
    /// The byte padding fills an attribute value to a 4-byte boundary with.
    /// RFC 8489 §14: receivers MUST ignore it, senders may put anything — 0
    /// here; RFC 5769's sample messages use 0x20, and setting it reproduces
    /// them byte for byte.
    pad: u8 = 0,

    /// Start a message: writes the 20-byte header (type, zero length, cookie,
    /// transaction id). Fails if `buf` cannot hold the header.
    pub fn init(buf: []u8, class: Class, method: Method, txid: TransactionId) BuildError!Builder {
        if (buf.len < header_len) return error.BufferTooSmall;
        std.mem.writeInt(u16, buf[0..2], encodeType(class, method), .big);
        std.mem.writeInt(u16, buf[2..4], 0, .big); // attribute-region length
        std.mem.writeInt(u32, buf[4..8], magic_cookie, .big);
        @memcpy(buf[8..20], &txid);
        return .{ .buf = buf, .len = header_len };
    }

    /// Length of the attribute region (message length minus the header).
    fn attrRegionLen(self: *const Builder) u16 {
        return @intCast(self.len - header_len);
    }

    fn setLengthField(self: *Builder, region_len: u16) void {
        std.mem.writeInt(u16, self.buf[2..4], region_len, .big);
    }

    /// Append one TLV attribute: 2-byte type, 2-byte value length, the value,
    /// then zero padding to the next 4-byte boundary. Updates the header length.
    pub fn addAttribute(self: *Builder, typ: u16, value: []const u8) BuildError!void {
        const padded = (value.len + 3) & ~@as(usize, 3);
        if (self.len + 4 + padded > self.buf.len) return error.BufferTooSmall;
        std.mem.writeInt(u16, self.buf[self.len..][0..2], typ, .big);
        std.mem.writeInt(u16, self.buf[self.len + 2 ..][0..2], @intCast(value.len), .big);
        @memcpy(self.buf[self.len + 4 ..][0..value.len], value);
        if (value.len > std.math.maxInt(u16)) return error.ValueTooLong;
        @memset(self.buf[self.len + 4 + value.len ..][0 .. padded - value.len], self.pad);
        self.len += 4 + padded;
        self.setLengthField(self.attrRegionLen());
    }

    /// Append ERROR-CODE (RFC 8489 §14.8): class (hundreds) and number, then
    /// a UTF-8 reason phrase of at most 763 bytes.
    pub fn addErrorCode(self: *Builder, code: u16, reason: []const u8) BuildError!void {
        if (code < 300 or code > 699) return error.InvalidErrorCode;
        if (reason.len > 763) return error.ValueTooLong;
        var v: [4 + 763]u8 = undefined;
        v[0] = 0;
        v[1] = 0;
        v[2] = @intCast(code / 100);
        v[3] = @intCast(code % 100);
        @memcpy(v[4..][0..reason.len], reason);
        return self.addAttribute(attrCode(.error_code), v[0 .. 4 + reason.len]);
    }

    /// Append UNKNOWN-ATTRIBUTES (RFC 8489 §14.9): the 16-bit types a 420
    /// response names.
    pub fn addUnknownAttributes(self: *Builder, types: []const u16) BuildError!void {
        var v: [128]u8 = undefined;
        if (types.len * 2 > v.len) return error.ValueTooLong;
        for (types, 0..) |t, i| std.mem.writeInt(u16, v[i * 2 ..][0..2], t, .big);
        return self.addAttribute(attrCode(.unknown_attributes), v[0 .. types.len * 2]);
    }

    /// Append USERNAME / REALM / NONCE (RFC 8489 §14.3/§14.9/§14.10).
    pub fn addUsername(self: *Builder, name: []const u8) BuildError!void {
        return self.addAttribute(attrCode(.username), name);
    }
    pub fn addRealm(self: *Builder, realm: []const u8) BuildError!void {
        return self.addAttribute(attrCode(.realm), realm);
    }
    pub fn addNonce(self: *Builder, nonce: []const u8) BuildError!void {
        return self.addAttribute(attrCode(.nonce), nonce);
    }

    /// Append a SOFTWARE attribute (a human-readable agent description).
    pub fn addSoftware(self: *Builder, text: []const u8) BuildError!void {
        return self.addAttribute(attrCode(.software), text);
    }

    /// Append an (optionally XOR-encoded) MAPPED-ADDRESS-style attribute for
    /// the given transport address. `xor` selects XOR-MAPPED-ADDRESS (0x0020)
    /// vs plain MAPPED-ADDRESS (0x0001).
    pub fn addMappedAddress(self: *Builder, ip: netaddr.Ip, port: u16, xor: bool) BuildError!void {
        var value: [4 + 16]u8 = undefined;
        const n = encodeAddress(&value, ip, port, self.transactionId(), xor);
        return self.addAttribute(if (xor) attrCode(.xor_mapped_address) else attrCode(.mapped_address), value[0..n]);
    }

    fn transactionId(self: *const Builder) TransactionId {
        return self.buf[8..20].*;
    }

    /// Append MESSAGE-INTEGRITY (RFC 8489 §14.5): HMAC-SHA1-20 over the message
    /// so far, with the header length field first set to include this
    /// attribute. `key` is the short-term credential (the SASLprep'd password).
    pub fn addMessageIntegrity(self: *Builder, key: []const u8) BuildError!void {
        return burn.run(burn.mi_burn, BuildError!void, addMessageIntegrityBody, .{ self, key });
    }

    fn addMessageIntegrityBody(self: *Builder, key: []const u8) BuildError!void {
        if (self.len + 24 > self.buf.len) return error.BufferTooSmall;
        // Length must point past this attribute before the MAC is taken.
        self.setLengthField(@intCast(self.attrRegionLen() + 24));
        var mac: [HmacSha1.mac_length]u8 = undefined;
        var h = HmacSha1.init(key);
        h.update(self.buf[0..self.len]);
        h.final(&mac);
        std.mem.writeInt(u16, self.buf[self.len..][0..2], attrCode(.message_integrity), .big);
        std.mem.writeInt(u16, self.buf[self.len + 2 ..][0..2], HmacSha1.mac_length, .big);
        @memcpy(self.buf[self.len + 4 ..][0..HmacSha1.mac_length], &mac);
        self.len += 24; // length field already correct
    }

    /// Append FINGERPRINT (RFC 8489 §14.7): CRC-32 of the message so far ⊕
    /// `fingerprint_xor`, with the header length field first set to include
    /// this attribute. Must be the final attribute.
    pub fn addFingerprint(self: *Builder) BuildError!void {
        if (self.len + 8 > self.buf.len) return error.BufferTooSmall;
        self.setLengthField(@intCast(self.attrRegionLen() + 8));
        var c = Crc32.init();
        c.update(self.buf[0..self.len]);
        const fp = c.final() ^ fingerprint_xor;
        std.mem.writeInt(u16, self.buf[self.len..][0..2], attrCode(.fingerprint), .big);
        std.mem.writeInt(u16, self.buf[self.len + 2 ..][0..2], 4, .big);
        std.mem.writeInt(u32, self.buf[self.len + 4 ..][0..4], fp, .big);
        self.len += 8;
    }

    /// The finished message bytes (a sub-slice of the caller buffer).
    pub fn finish(self: *const Builder) []const u8 {
        return self.buf[0..self.len];
    }
};

/// The long-term credential key (RFC 8489 §9.2.2, the MD5 password
/// algorithm): MD5(username ":" realm ":" password). Pass it to
/// `Builder.addMessageIntegrity` / `Message.verifyMessageIntegrity`. The key
/// is written to `out` (a result is never returned by value: the caller's
/// frame would keep a copy); the caller wipes `out` when done. Runs under a
/// dead-stack burn.
///
/// The three strings must already be processed as RFC 8489 requires —
/// username and password through the OpaqueString profile (RFC 8265), realm
/// as received. For printable ASCII that processing changes nothing, so
/// ASCII credentials can be passed as they are; this module carries no
/// Unicode tables and does not do it for anything else.
pub fn longTermKey(out: *[16]u8, username: []const u8, realm: []const u8, password: []const u8) void {
    return burn.run(burn.key_burn, void, longTermKeyBody, .{ out, username, realm, password });
}

fn longTermKeyBody(out: *[16]u8, username: []const u8, realm: []const u8, password: []const u8) void {
    var h = std.crypto.hash.Md5.init(.{});
    h.update(username);
    h.update(":");
    h.update(realm);
    h.update(":");
    h.update(password);
    h.final(out);
}

// ── server side: the Binding responder ──────────────────────────────────────

pub const ResponderOptions = struct {
    /// SOFTWARE to include, if any.
    software: ?[]const u8 = null,
    /// Short-term credential: when set, the request must carry USERNAME and
    /// a MESSAGE-INTEGRITY that verifies under this key (400 if either is
    /// missing, 401 if the MAC fails), and the success response is signed
    /// with it.
    integrity_key: ?[]const u8 = null,
    /// Append FINGERPRINT (RFC 8489 §14.7) to every response.
    fingerprint: bool = true,
    /// Comprehension-required attribute types (below 0x8000) the caller
    /// understands beyond the STUN ones — e.g. ICE's PRIORITY (0x0024) and
    /// USE-CANDIDATE (0x0025). Any other one gets a 420.
    known_attributes: []const u16 = &.{},
    /// See `Builder.pad`.
    pad: u8 = 0,
};

pub const RespondError = BuildError || error{
    /// Not a Binding request (an indication, a response, another method):
    /// RFC 8489 §6.3 — drop it, send nothing.
    NotBindingRequest,
};

/// Answer a Binding request received from `from` (RFC 8489 §6.3): a success
/// response carrying XOR-MAPPED-ADDRESS = `from`, or the error response the
/// request earns (420 with UNKNOWN-ATTRIBUTES for comprehension-required
/// attributes the server does not understand, 400/401 for short-term
/// credential failures). The response echoes the request's transaction id.
pub fn bindingResponse(request: Message, from: AddressPort, out: []u8, opts: ResponderOptions) RespondError![]const u8 {
    if (request.class != .request or request.method != .binding) return error.NotBindingRequest;

    // §6.3.1: unknown comprehension-required attributes → 420.
    var unknown: [32]u16 = undefined;
    var n_unknown: usize = 0;
    var it = request.attributes();
    while (it.next()) |a| {
        if (a.type >= 0x8000 or stunUnderstands(a.type)) continue;
        if (std.mem.indexOfScalar(u16, opts.known_attributes, a.type) != null) continue;
        if (std.mem.indexOfScalar(u16, unknown[0..n_unknown], a.type) != null) continue;
        if (n_unknown < unknown.len) {
            unknown[n_unknown] = a.type;
            n_unknown += 1;
        }
    }
    if (n_unknown > 0) {
        var b = try Builder.init(out, .error_response, .binding, request.transaction_id);
        b.pad = opts.pad;
        try b.addErrorCode(420, "Unknown Attribute");
        try b.addUnknownAttributes(unknown[0..n_unknown]);
        if (opts.fingerprint) try b.addFingerprint();
        return b.finish();
    }

    if (opts.integrity_key) |key| {
        const has_user = request.find(attrCode(.username)) != null;
        const has_mi = request.find(attrCode(.message_integrity)) != null;
        if (!has_user or !has_mi) return errorResponse(request, out, 400, "Bad Request", opts);
        if (!request.verifyMessageIntegrity(key)) return errorResponse(request, out, 401, "Unauthorized", opts);
    }

    var b = try Builder.init(out, .success_response, .binding, request.transaction_id);
    b.pad = opts.pad;
    if (opts.software) |sw| try b.addSoftware(sw);
    try b.addMappedAddress(from.ip, from.port, true);
    if (opts.integrity_key) |key| try b.addMessageIntegrity(key);
    if (opts.fingerprint) try b.addFingerprint();
    return b.finish();
}

fn errorResponse(request: Message, out: []u8, code: u16, reason: []const u8, opts: ResponderOptions) RespondError![]const u8 {
    var b = try Builder.init(out, .error_response, .binding, request.transaction_id);
    b.pad = opts.pad;
    try b.addErrorCode(code, reason);
    if (opts.fingerprint) try b.addFingerprint();
    return b.finish();
}

/// Comprehension-required STUN attributes a Binding server handles itself.
fn stunUnderstands(t: u16) bool {
    return switch (t) {
        attrCode(.username),
        attrCode(.message_integrity),
        attrCode(.message_integrity_sha256),
        attrCode(.realm),
        attrCode(.nonce),
        attrCode(.password_algorithm),
        attrCode(.userhash),
        => true,
        else => false,
    };
}

// ── STUN / TURN URIs (RFC 7064, RFC 7065) ───────────────────────────────────

pub const Uri = struct {
    scheme: Scheme,
    /// Host as written: a registered name, an IPv4 literal, or an IPv6
    /// literal WITHOUT its brackets.
    host: []const u8,
    /// The explicit port, or the scheme's default (3478 / 5349).
    port: u16,
    /// TURN only: `?transport=` (RFC 7065 §3.1), null when absent.
    transport: ?Transport = null,

    pub const Scheme = enum { stun, stuns, turn, turns };
    pub const Transport = enum { udp, tcp };

    pub fn secure(u: Uri) bool {
        return u.scheme == .stuns or u.scheme == .turns;
    }
};

pub const UriError = error{InvalidUri};

/// Parse `stun:` / `stuns:` (RFC 7064) and `turn:` / `turns:` (RFC 7065)
/// URIs: scheme ":" host [":" port], and for TURN ["?transport=" (udp|tcp)].
/// Default ports: 3478 for stun/turn, 5349 for stuns/turns (RFC 8489 §6.2.2,
/// §6.2.3 — the TLS port). No userinfo, path or fragment is allowed.
pub fn parseUri(text: []const u8) UriError!Uri {
    const colon = std.mem.indexOfScalar(u8, text, ':') orelse return error.InvalidUri;
    const scheme_text = text[0..colon];
    const scheme: Uri.Scheme = inline for (@typeInfo(Uri.Scheme).@"enum".fields) |f| {
        if (std.ascii.eqlIgnoreCase(scheme_text, f.name)) break @enumFromInt(f.value);
    } else return error.InvalidUri;
    var rest = text[colon + 1 ..];
    var out: Uri = .{
        .scheme = scheme,
        .host = undefined,
        .port = if (scheme == .stuns or scheme == .turns) 5349 else 3478,
    };
    if (std.mem.indexOfScalar(u8, rest, '?')) |q| {
        if (scheme == .stun or scheme == .stuns) return error.InvalidUri; // RFC 7064 has no query
        const query_part = rest[q + 1 ..];
        const prefix = "transport=";
        if (!std.ascii.startsWithIgnoreCase(query_part, prefix)) return error.InvalidUri;
        const tv = query_part[prefix.len..];
        out.transport = if (std.ascii.eqlIgnoreCase(tv, "udp")) .udp else if (std.ascii.eqlIgnoreCase(tv, "tcp")) .tcp else return error.InvalidUri;
        rest = rest[0..q];
    }
    if (rest.len == 0) return error.InvalidUri;
    var host_end: usize = undefined;
    if (rest[0] == '[') {
        const close = std.mem.indexOfScalar(u8, rest, ']') orelse return error.InvalidUri;
        out.host = rest[1..close];
        if (out.host.len == 0) return error.InvalidUri;
        for (out.host) |c| if (!(std.ascii.isHex(c) or c == ':' or c == '.')) return error.InvalidUri;
        host_end = close + 1;
    } else {
        host_end = std.mem.indexOfScalar(u8, rest, ':') orelse rest.len;
        out.host = rest[0..host_end];
        if (out.host.len == 0) return error.InvalidUri;
        // RFC 3986 reg-name / IPv4address: unreserved, pct-encoded,
        // sub-delims. "@" (userinfo), "/" (path), "#" (fragment) are not.
        for (out.host) |c| {
            const ok = std.ascii.isAlphanumeric(c) or switch (c) {
                '-', '.', '_', '~', '%', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => true,
                else => false,
            };
            if (!ok) return error.InvalidUri;
        }
    }
    const tail = rest[host_end..];
    if (tail.len > 0) {
        if (tail[0] != ':' or tail.len == 1) return error.InvalidUri;
        out.port = std.fmt.parseInt(u16, tail[1..], 10) catch return error.InvalidUri;
        if (out.port == 0) return error.InvalidUri;
    }
    return out;
}

/// Build a bare Binding request (just the header) into `out`. The convenience
/// entry point named in the module scope.
pub fn bindingRequest(txid: TransactionId, out: []u8) BuildError![]const u8 {
    var b = try Builder.init(out, .request, .binding, txid);
    return b.finish();
}

/// Encode a transport address into a (XOR-)MAPPED-ADDRESS value; returns the
/// number of bytes written (8 for IPv4, 20 for IPv6).
fn encodeAddress(out: *[4 + 16]u8, ip: netaddr.Ip, port: u16, txid: TransactionId, xor: bool) usize {
    out[0] = 0;
    const xport = if (xor) port ^ @as(u16, @truncate(magic_cookie >> 16)) else port;
    std.mem.writeInt(u16, out[2..4], xport, .big);
    switch (ip) {
        .v4 => |q| {
            out[1] = 0x01;
            out[4..8].* = q;
            if (xor) for (out[4..8], 0..) |*b, i| {
                b.* ^= magic_cookie_bytes[i];
            };
            return 8;
        },
        .v6 => |b6| {
            out[1] = 0x02;
            out[4..20].* = b6;
            if (xor) {
                const key = v6XorKey(txid);
                for (out[4..20], 0..) |*b, i| b.* ^= key[i];
            }
            return 20;
        },
    }
}

/// The 16-byte XOR key for an IPv6 (XOR-)MAPPED-ADDRESS: cookie ‖ transaction id.
fn v6XorKey(txid: TransactionId) [16]u8 {
    var key: [16]u8 = undefined;
    @memcpy(key[0..4], &magic_cookie_bytes);
    @memcpy(key[4..16], &txid);
    return key;
}

// ── message (decode) ─────────────────────────────────────────────────────────

const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
const Crc32 = std.hash.Crc32;

/// A parsed STUN message. Holds a slice of the original buffer (`bytes`,
/// trimmed to `header_len + length`) plus the decoded header fields. All
/// accessors are read-only and allocation-free.
pub const Message = struct {
    bytes: []const u8,
    class: Class,
    method: Method,
    /// The attribute-region length from the header (bytes after the header).
    length: u16,
    transaction_id: TransactionId,

    /// Iterate the attributes in wire order.
    pub fn attributes(self: Message) AttributeIterator {
        return .{ .msg = self.bytes };
    }

    /// The first attribute of type `code`, or null. Later duplicates are
    /// ignored (STUN takes the first occurrence of most attributes).
    pub fn find(self: Message, code: u16) ?Attribute {
        var it = self.attributes();
        while (it.next()) |a| if (a.type == code) return a;
        return null;
    }

    /// Decode XOR-MAPPED-ADDRESS (0x0020) to an address+port, or null if the
    /// attribute is absent. Errors on a malformed/short value.
    pub fn xorMappedAddress(self: Message) DecodeError!?AddressPort {
        const a = self.find(attrCode(.xor_mapped_address)) orelse return null;
        return try decodeAddress(a.value, self.transaction_id, true);
    }

    /// Decode plain MAPPED-ADDRESS (0x0001), or null if absent.
    pub fn plainMappedAddress(self: Message) DecodeError!?AddressPort {
        const a = self.find(attrCode(.mapped_address)) orelse return null;
        return try decodeAddress(a.value, self.transaction_id, false);
    }

    /// The reflexive address, preferring XOR-MAPPED-ADDRESS and falling back to
    /// MAPPED-ADDRESS; null if neither is present.
    pub fn mappedAddress(self: Message) DecodeError!?AddressPort {
        if (try self.xorMappedAddress()) |ap| return ap;
        return self.plainMappedAddress();
    }

    /// Parse an ERROR-CODE (0x0009) attribute, or null if absent.
    pub fn errorCode(self: Message) DecodeError!?ErrorCode {
        const a = self.find(attrCode(.error_code)) orelse return null;
        return try decodeErrorCode(a.value);
    }

    /// Verify FINGERPRINT (0x8028): recompute CRC-32 ⊕ `fingerprint_xor` over
    /// the message up to the attribute, with the header length field patched to
    /// point just past it. False if the attribute is absent or malformed.
    pub fn verifyFingerprint(self: Message) bool {
        const fp = self.find(attrCode(.fingerprint)) orelse return false;
        if (fp.value.len != 4) return false;
        const stored = std.mem.readInt(u32, fp.value[0..4], .big);
        var c = Crc32.init();
        self.hashHeaderWithLength(Crc32, &c, @intCast(fp.offset - header_len + 8));
        c.update(self.bytes[4..fp.offset]);
        return (c.final() ^ fingerprint_xor) == stored;
    }

    /// Verify MESSAGE-INTEGRITY (0x0008) against short-term credential `key`:
    /// recompute HMAC-SHA1-20 over the message up to the attribute, with the
    /// header length field patched to point just past it, and compare in
    /// constant time. False if the attribute is absent or malformed.
    pub fn verifyMessageIntegrity(self: Message, key: []const u8) bool {
        return burn.run(burn.mi_burn, bool, verifyMessageIntegrityBody, .{ self, key });
    }

    fn verifyMessageIntegrityBody(self: Message, key: []const u8) bool {
        const mi = self.find(attrCode(.message_integrity)) orelse return false;
        if (mi.value.len != HmacSha1.mac_length) return false;
        var h = HmacSha1.init(key);
        self.hashHeaderWithLength(HmacSha1, &h, @intCast(mi.offset - header_len + 24));
        h.update(self.bytes[4..mi.offset]);
        var mac: [HmacSha1.mac_length]u8 = undefined;
        h.final(&mac);
        const got: [HmacSha1.mac_length]u8 = mi.value[0..HmacSha1.mac_length].*;
        return std.crypto.timing_safe.eql([HmacSha1.mac_length]u8, mac, got);
    }

    /// Feed the header type (2 bytes) then a *patched* 2-byte length into a
    /// streaming hasher, without mutating the buffer. Both `Crc32` and the HMAC
    /// context expose `update`, so `Ctx` is duck-typed.
    fn hashHeaderWithLength(self: Message, comptime Ctx: type, ctx: *Ctx, patched_len: u16) void {
        ctx.update(self.bytes[0..2]);
        var lb: [2]u8 = undefined;
        std.mem.writeInt(u16, &lb, patched_len, .big);
        ctx.update(&lb);
    }
};

/// Parse a STUN message from `bytes`. Validates length, the two zero MSBs, the
/// magic cookie, and 4-byte length alignment; the returned `Message.bytes` is
/// trimmed to exactly `header_len + length`.
pub fn decode(bytes: []const u8) DecodeError!Message {
    if (bytes.len < header_len) return error.Truncated;
    const t = std.mem.readInt(u16, bytes[0..2], .big);
    if (t & 0xC000 != 0) return error.NotStun;
    const length = std.mem.readInt(u16, bytes[2..4], .big);
    if (length % 4 != 0) return error.BadLength;
    if (std.mem.readInt(u32, bytes[4..8], .big) != magic_cookie) return error.BadCookie;
    if (@as(usize, header_len) + length > bytes.len) return error.Truncated;
    return .{
        .bytes = bytes[0 .. @as(usize, header_len) + length],
        .class = decodeClass(t),
        .method = @enumFromInt(decodeMethod(t)),
        .length = length,
        .transaction_id = bytes[8..20].*,
    };
}

/// One TLV attribute, its value unpadded, plus its byte offset within the
/// message (needed for FINGERPRINT / MESSAGE-INTEGRITY region math).
pub const Attribute = struct {
    type: u16,
    value: []const u8,
    offset: usize,
};

/// Walks the attribute region of a message. Stops (returns null) at the end or
/// on a truncated attribute — a malformed tail is treated as end-of-message.
pub const AttributeIterator = struct {
    msg: []const u8,
    pos: usize = header_len,

    pub fn next(self: *AttributeIterator) ?Attribute {
        if (self.pos + 4 > self.msg.len) return null;
        const typ = std.mem.readInt(u16, self.msg[self.pos..][0..2], .big);
        const vlen = std.mem.readInt(u16, self.msg[self.pos + 2 ..][0..2], .big);
        const vstart = self.pos + 4;
        if (vstart + vlen > self.msg.len) return null;
        const attr: Attribute = .{ .type = typ, .value = self.msg[vstart .. vstart + vlen], .offset = self.pos };
        const padded = (@as(usize, vlen) + 3) & ~@as(usize, 3);
        self.pos = vstart + padded;
        return attr;
    }
};

/// Decode a (XOR-)MAPPED-ADDRESS attribute value.
fn decodeAddress(value: []const u8, txid: TransactionId, xor: bool) DecodeError!AddressPort {
    if (value.len < 4) return error.MalformedAttribute;
    const family = value[1];
    const raw_port = std.mem.readInt(u16, value[2..4], .big);
    const port = if (xor) raw_port ^ @as(u16, @truncate(magic_cookie >> 16)) else raw_port;
    switch (family) {
        0x01 => {
            if (value.len < 8) return error.MalformedAttribute;
            var a: [4]u8 = value[4..8].*;
            if (xor) for (&a, 0..) |*b, i| {
                b.* ^= magic_cookie_bytes[i];
            };
            return .{ .ip = .{ .v4 = a }, .port = port };
        },
        0x02 => {
            if (value.len < 20) return error.MalformedAttribute;
            var a: [16]u8 = value[4..20].*;
            if (xor) {
                const key = v6XorKey(txid);
                for (&a, 0..) |*b, i| b.* ^= key[i];
            }
            return .{ .ip = .{ .v6 = a }, .port = port };
        },
        else => return error.UnknownAddressFamily,
    }
}

/// A decoded ERROR-CODE attribute (RFC 8489 §14.8).
pub const ErrorCode = struct {
    /// The numeric error, class*100 + number (e.g. 401, 420, 438).
    code: u16,
    /// The UTF-8 reason phrase (a slice into the message buffer).
    reason: []const u8,
};

fn decodeErrorCode(value: []const u8) DecodeError!ErrorCode {
    if (value.len < 4) return error.MalformedAttribute;
    const class = value[2] & 0x07;
    const number = value[3];
    return .{ .code = @as(u16, class) * 100 + number, .reason = value[4..] };
}

// ── optional live query over std.Io.net UDP ──────────────────────────────────

/// Options for `query`. Shape mirrors `sntp.QueryOptions` — same field name,
/// same unit, same "0 = wait indefinitely" convention — since both are one
/// UDP request/response exchange with the identical bounding need.
pub const QueryOptions = struct {
    /// Overall budget in ms; 0 = no cap beyond the retransmission schedule
    /// below (which ends after `max_requests` sends and a final wait).
    timeout_ms: u32 = 0,
    /// Initial retransmission timeout (RFC 8489 §6.2.1 RECOMMENDS 500 ms
    /// when nothing better is known); doubles after every send.
    rto_ms: u32 = 500,
    /// Rc: requests sent in total (RFC 8489 default 7). 1 = no
    /// retransmission (the pre-2026-10-04 behaviour).
    max_requests: u8 = 7,
    /// Rm: after the last request, wait `last_wait_factor * rto_ms` more
    /// (RFC 8489 default 16).
    last_wait_factor: u8 = 16,
};

/// The RFC 8489 §6.2.1 schedule: when (ms after the first send) each request
/// goes out, and when the client gives up. With the defaults: 0, 500, 1500,
/// 3500, 7500, 15500, 31500, giving up at 39500 — the RFC's own example.
pub const Schedule = struct {
    opts: QueryOptions,
    sent: u8 = 0,
    at_ms: u64 = 0,
    rto_ms: u64,

    pub fn init(opts: QueryOptions) Schedule {
        return .{ .opts = opts, .rto_ms = opts.rto_ms };
    }

    /// Offset of the next send, or null when every request has gone out.
    pub fn nextSend(s: *Schedule) ?u64 {
        if (s.sent >= @max(s.opts.max_requests, 1)) return null;
        const at = s.at_ms;
        s.sent += 1;
        // Saturating: `max_requests` up to 255 doubles the RTO past u64 —
        // the schedule then just never comes due (timeout_ms still caps it).
        s.at_ms +|= s.rto_ms;
        s.rto_ms *|= 2;
        return at;
    }

    /// When to stop waiting after send number `sent` (1-based): the next
    /// send's time, or — after the last — that send plus Rm × the initial RTO.
    pub fn waitUntil(s: *const Schedule) u64 {
        if (s.sent < @max(s.opts.max_requests, 1)) return s.at_ms;
        const last = s.at_ms - (s.rto_ms / 2);
        return last + @as(u64, s.opts.last_wait_factor) * s.opts.rto_ms;
    }
};

/// Send one Binding request to `server` over UDP and return the reflexive
/// address the server reflects back (its view of our public transport address).
///
/// A batteries-included convenience for callers that just want their public
/// address; the pure `Builder` / `Message` API above is the real interface and
/// needs no `Io`. `buf` receives the raw response bytes and must outlive the
/// returned `AddressPort` only if you keep the (unrelated) reason slices — the
/// address is copied out.
///
/// Retransmits per RFC 8489 §6.2.1 (`Schedule`: RTO doubling from
/// `options.rto_ms`, `max_requests` sends, then `last_wait_factor` × RTO);
/// `options.timeout_ms` caps the whole exchange (0 = only the schedule). A
/// datagram that is not STUN or carries another transaction id is discarded
/// and the wait goes on (§6.3.4); if nothing better arrives, the give-up error
/// is that stray's (`TransactionMismatch`, `BadCookie`, …) instead of
/// `error.Timeout`, the error a silent server earns. A STUN error response for
/// our transaction stops the exchange with `error.ErrorResponse`.
pub fn query(
    io: std.Io,
    server: std.Io.net.IpAddress,
    txid: TransactionId,
    buf: []u8,
    options: QueryOptions,
) !AddressPort {
    const IpAddress = std.Io.net.IpAddress;
    const local: IpAddress = switch (server) {
        .ip4 => try IpAddress.parse("0.0.0.0", 0),
        .ip6 => try IpAddress.parse("[::]", 0),
    };
    var sock = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer sock.close(io);

    var req_buf: [header_len]u8 = undefined;
    const req = try bindingRequest(txid, &req_buf);

    const clock: std.Io.Clock = .awake;
    const start = std.Io.Clock.Timestamp.now(io, clock);
    const cap_ms: ?u64 = if (options.timeout_ms == 0) null else options.timeout_ms;
    var sched = Schedule.init(options);
    // What arrived instead of our answer, if anything: reported on give-up
    // in place of `error.Timeout`, so "the server answered garbage" stays
    // distinguishable from "nothing came back" (the errors the pre-2026-10-04
    // single-shot `query` returned at once).
    var stray: ?(DecodeError || error{TransactionMismatch}) = null;
    while (sched.nextSend()) |send_at| {
        if (cap_ms) |c| if (send_at >= c) break;
        try sock.send(io, &server, req);
        var until = sched.waitUntil();
        if (cap_ms) |c| until = @min(until, c);
        const deadline: std.Io.Timeout = .{ .deadline = start.addDuration(.{
            .raw = .fromMilliseconds(@intCast(until)),
            .clock = clock,
        }) };
        // RFC 8489 §6.3.4: a response whose transaction id does not match,
        // or a datagram that is not STUN at all, is discarded — keep
        // waiting for ours until this send's window ends, then retransmit.
        while (true) {
            const msg = sock.receiveTimeout(io, buf, deadline) catch |e| switch (e) {
                error.Timeout => break,
                else => return e,
            };
            const parsed = decode(msg.data) catch |e| {
                stray = e;
                continue;
            };
            if (!std.mem.eql(u8, &parsed.transaction_id, &txid)) {
                stray = error.TransactionMismatch;
                continue;
            }
            if (parsed.class == .error_response) {
                // A definitive answer (RFC 8489 §6.3.4): stop retransmitting.
                return error.ErrorResponse;
            }
            if (parsed.class != .success_response) continue;
            return (try parsed.mappedAddress()) orelse error.NoMappedAddress;
        }
    }
    if (stray) |e| return e;
    return error.Timeout;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

// RFC 5769 §2.1 — Sample Request. Short-term credential password below.
const rfc5769_password = "VOkJxbRl1RmTxUk/WvJxBt";

const rfc5769_txid = TransactionId{
    0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
};

const req_2_1 = [_]u8{
    // header: Binding request, length 0x58, cookie, transaction id
    0x00, 0x01, 0x00, 0x58,
    0x21, 0x12, 0xa4, 0x42,
    0xb7, 0xe7, 0xa7, 0x01,
    0xbc, 0x34, 0xd6, 0x86,
    0xfa, 0x87, 0xdf, 0xae,
    // SOFTWARE "STUN test client"
    0x80, 0x22, 0x00, 0x10,
    0x53, 0x54, 0x55, 0x4e,
    0x20, 0x74, 0x65, 0x73,
    0x74, 0x20, 0x63, 0x6c,
    0x69, 0x65, 0x6e, 0x74,
    // PRIORITY
    0x00, 0x24, 0x00, 0x04,
    0x6e, 0x00, 0x01, 0xff,
    // ICE-CONTROLLED
    0x80, 0x29, 0x00, 0x08,
    0x93, 0x2f, 0xf9, 0xb1,
    0x51, 0x26, 0x3b, 0x36,
    // USERNAME "evtj:h6vY" (9 bytes + 3 pad)
    0x00, 0x06, 0x00, 0x09,
    0x65, 0x76, 0x74, 0x6a,
    0x3a, 0x68, 0x36, 0x76,
    0x59, 0x20, 0x20, 0x20,
    // MESSAGE-INTEGRITY
    0x00, 0x08, 0x00, 0x14,
    0x9a, 0xea, 0xa7, 0x0c,
    0xbf, 0xd8, 0xcb, 0x56,
    0x78, 0x1e, 0xf2, 0xb5,
    0xb2, 0xd3, 0xf2, 0x49,
    0xc1, 0xb5, 0x71, 0xa2,
    // FINGERPRINT
    0x80, 0x28, 0x00, 0x04,
    0xe5, 0x7a, 0x3b, 0xcf,
};

const resp_2_2 = [_]u8{
    // header: Binding success response, length 0x3c
    0x01, 0x01, 0x00, 0x3c,
    0x21, 0x12, 0xa4, 0x42,
    0xb7, 0xe7, 0xa7, 0x01,
    0xbc, 0x34, 0xd6, 0x86,
    0xfa, 0x87, 0xdf, 0xae,
    // SOFTWARE "test vector " (11 bytes + 1 pad)
    0x80, 0x22, 0x00, 0x0b,
    0x74, 0x65, 0x73, 0x74,
    0x20, 0x76, 0x65, 0x63,
    0x74, 0x6f, 0x72, 0x20,
    // XOR-MAPPED-ADDRESS (IPv4)
    0x00, 0x20, 0x00, 0x08,
    0x00, 0x01, 0xa1, 0x47,
    0xe1, 0x12, 0xa6, 0x43,
    // MESSAGE-INTEGRITY
    0x00, 0x08, 0x00, 0x14,
    0x2b, 0x91, 0xf5, 0x99,
    0xfd, 0x9e, 0x90, 0xc3,
    0x8c, 0x74, 0x89, 0xf9,
    0x2a, 0xf9, 0xba, 0x53,
    0xf0, 0x6b, 0xe7, 0xd7,
    // FINGERPRINT
    0x80, 0x28, 0x00, 0x04,
    0xc0, 0x7d, 0x4c, 0x96,
};

const resp_2_3 = [_]u8{
    // header: Binding success response, length 0x48
    0x01, 0x01, 0x00, 0x48,
    0x21, 0x12, 0xa4, 0x42,
    0xb7, 0xe7, 0xa7, 0x01,
    0xbc, 0x34, 0xd6, 0x86,
    0xfa, 0x87, 0xdf, 0xae,
    // SOFTWARE "test vector "
    0x80, 0x22, 0x00, 0x0b,
    0x74, 0x65, 0x73, 0x74,
    0x20, 0x76, 0x65, 0x63,
    0x74, 0x6f, 0x72, 0x20,
    // XOR-MAPPED-ADDRESS (IPv6)
    0x00, 0x20, 0x00, 0x14,
    0x00, 0x02, 0xa1, 0x47,
    0x01, 0x13, 0xa9, 0xfa,
    0xa5, 0xd3, 0xf1, 0x79,
    0xbc, 0x25, 0xf4, 0xb5,
    0xbe, 0xd2, 0xb9, 0xd9,
    // MESSAGE-INTEGRITY
    0x00, 0x08, 0x00, 0x14,
    0xa3, 0x82, 0x95, 0x4e,
    0x4b, 0xe6, 0x7b, 0xf1,
    0x17, 0x84, 0xc9, 0x7c,
    0x82, 0x92, 0xc2, 0x75,
    0xbf, 0xe3, 0xed, 0x41,
    // FINGERPRINT
    0x80, 0x28, 0x00, 0x04,
    0xc8, 0xfb, 0x0b, 0x4c,
};

test "message type class/method encode+decode round-trip" {
    // Binding request = 0x0001, Binding success response = 0x0101 (RFC 5769).
    try testing.expectEqual(@as(u16, 0x0001), encodeType(.request, .binding));
    try testing.expectEqual(@as(u16, 0x0101), encodeType(.success_response, .binding));
    try testing.expectEqual(@as(u16, 0x0111), encodeType(.error_response, .binding));
    inline for (.{ Class.request, .indication, .success_response, .error_response }) |cls| {
        const t = encodeType(cls, .binding);
        try testing.expectEqual(cls, decodeClass(t));
        try testing.expectEqual(@as(u12, 0x001), decodeMethod(t));
    }
}

test "RFC 5769 §2.1: decode the sample request" {
    const m = try decode(&req_2_1);
    try testing.expectEqual(Class.request, m.class);
    try testing.expectEqual(Method.binding, m.method);
    try testing.expectEqual(@as(u16, 0x58), m.length);
    try testing.expectEqualSlices(u8, &rfc5769_txid, &m.transaction_id);

    // Attribute order and types as documented.
    var it = m.attributes();
    const want = [_]u16{ 0x8022, 0x0024, 0x8029, 0x0006, 0x0008, 0x8028 };
    var i: usize = 0;
    while (it.next()) |a| : (i += 1) try testing.expectEqual(want[i], a.type);
    try testing.expectEqual(want.len, i);

    // SOFTWARE and USERNAME values.
    try testing.expectEqualStrings("STUN test client", m.find(0x8022).?.value);
    try testing.expectEqualStrings("evtj:h6vY", m.find(0x0006).?.value);

    // The sample request's MESSAGE-INTEGRITY and FINGERPRINT verify.
    try testing.expect(m.verifyMessageIntegrity(rfc5769_password));
    try testing.expect(m.verifyFingerprint());
}

test "encode → decode → re-encode is stable, with MI + FINGERPRINT recomputed" {
    // Note: the RFC 5769 §2.1 vector pads its USERNAME with spaces (0x20), an
    // allowed-but-unusual quirk; our encoder zero-pads per RFC 8489 §14. So we
    // do NOT byte-match the vector here (its MI/FINGERPRINT cover those space
    // pads — that exact-bytes oracle is the `verify*` checks above, which pass).
    // Instead we prove the codec is self-consistent: build a request replaying
    // the sample's attributes (zero-padded), then decode and re-encode it and
    // assert an identical result, with MI/FINGERPRINT recomputed each time.
    const m0 = try decode(&req_2_1);
    var buf_a: [req_2_1.len]u8 = undefined;
    var b0 = try Builder.init(&buf_a, .request, .binding, m0.transaction_id);
    var it0 = m0.attributes();
    while (it0.next()) |a| switch (a.type) {
        0x0008 => try b0.addMessageIntegrity(rfc5769_password),
        0x8028 => try b0.addFingerprint(),
        else => try b0.addAttribute(a.type, a.value),
    };
    const canonical = b0.finish();

    // Our own encoding must verify against the same credential.
    const m1 = try decode(canonical);
    try testing.expect(m1.verifyMessageIntegrity(rfc5769_password));
    try testing.expect(m1.verifyFingerprint());

    // Re-encoding the decoded message reproduces it byte-for-byte.
    var buf_b: [req_2_1.len]u8 = undefined;
    var b1 = try Builder.init(&buf_b, m1.class, m1.method, m1.transaction_id);
    var it1 = m1.attributes();
    while (it1.next()) |a| switch (a.type) {
        0x0008 => try b1.addMessageIntegrity(rfc5769_password),
        0x8028 => try b1.addFingerprint(),
        else => try b1.addAttribute(a.type, a.value),
    };
    try testing.expectEqualSlices(u8, canonical, b1.finish());
}

test "RFC 5769 §2.2: IPv4 XOR-MAPPED-ADDRESS + MI + FINGERPRINT" {
    const m = try decode(&resp_2_2);
    try testing.expectEqual(Class.success_response, m.class);

    const ap = (try m.xorMappedAddress()).?;
    try testing.expectEqual(@as(u16, 32853), ap.port);
    var buf: [netaddr.max_ip_text_len]u8 = undefined;
    try testing.expectEqualStrings("192.0.2.1", netaddr.formatIp(ap.ip, &buf));
    // mappedAddress() prefers XOR-MAPPED-ADDRESS and yields the same answer.
    try testing.expect((try m.mappedAddress()).?.ip.eql(ap.ip));

    try testing.expect(m.verifyFingerprint());
    try testing.expect(m.verifyMessageIntegrity(rfc5769_password));
}

test "RFC 5769 §2.3: IPv6 XOR-MAPPED-ADDRESS" {
    const m = try decode(&resp_2_3);
    const ap = (try m.xorMappedAddress()).?;
    try testing.expectEqual(@as(u16, 32853), ap.port);
    var buf: [netaddr.max_ip_text_len]u8 = undefined;
    try testing.expectEqualStrings("2001:db8:1234:5678:11:2233:4455:6677", netaddr.formatIp(ap.ip, &buf));

    try testing.expect(m.verifyFingerprint());
    try testing.expect(m.verifyMessageIntegrity(rfc5769_password));
}

test "FINGERPRINT tamper: flipping any covered byte fails verification" {
    var bytes = resp_2_2;
    // Flip a byte inside SOFTWARE (before the fingerprint) → CRC mismatch.
    bytes[24] ^= 0x01;
    const m = try decode(&bytes);
    try testing.expect(!m.verifyFingerprint());
}

test "MESSAGE-INTEGRITY tamper: flipped body byte and flipped MAC both fail" {
    // A byte inside XOR-MAPPED-ADDRESS is covered by the MAC.
    {
        var bytes = resp_2_2;
        bytes[52] ^= 0x01; // somewhere in the XMA value region
        const m = try decode(&bytes);
        try testing.expect(!m.verifyMessageIntegrity(rfc5769_password));
    }
    // Flip a byte inside the MAC itself → still rejected (full compare).
    {
        var bytes = resp_2_2;
        const mi = (try decode(&bytes)).find(0x0008).?;
        bytes[mi.offset + 4] ^= 0x01;
        const m = try decode(&bytes);
        try testing.expect(!m.verifyMessageIntegrity(rfc5769_password));
    }
    // Wrong key also fails.
    {
        const m = try decode(&resp_2_2);
        try testing.expect(!m.verifyMessageIntegrity("wrong-password"));
    }
}

test "MAPPED-ADDRESS (plain) and XMA encode round-trip" {
    // Build a response carrying plain + XOR mapped address, decode it back.
    const ip = netaddr.parseIp("203.0.113.7").?;
    var out: [64]u8 = undefined;
    var b = try Builder.init(&out, .success_response, .binding, rfc5769_txid);
    try b.addMappedAddress(ip, 4242, false); // MAPPED-ADDRESS
    try b.addMappedAddress(ip, 4242, true); // XOR-MAPPED-ADDRESS
    const m = try decode(b.finish());

    const plain = (try m.plainMappedAddress()).?;
    try testing.expect(plain.ip.eql(ip));
    try testing.expectEqual(@as(u16, 4242), plain.port);
    const xored = (try m.xorMappedAddress()).?;
    try testing.expect(xored.ip.eql(ip));
    try testing.expectEqual(@as(u16, 4242), xored.port);
}

test "mappedAddress() prefers XOR-MAPPED-ADDRESS over plain MAPPED-ADDRESS (mutation guard)" {
    // Regression: the existing round-trip test built both attributes with the
    // SAME address, so a comparator/preference swap (plain-first instead of
    // XOR-first) would still pass it -- an oracle blind to the answer. Here
    // the two attributes carry DIFFERENT addresses so the preference is
    // actually observable.
    const plain_ip = netaddr.parseIp("198.51.100.9").?;
    const xor_ip = netaddr.parseIp("203.0.113.7").?;
    var out: [64]u8 = undefined;
    var b = try Builder.init(&out, .success_response, .binding, rfc5769_txid);
    try b.addMappedAddress(plain_ip, 1111, false); // MAPPED-ADDRESS
    try b.addMappedAddress(xor_ip, 2222, true); // XOR-MAPPED-ADDRESS
    const m = try decode(b.finish());

    const preferred = (try m.mappedAddress()).?;
    try testing.expect(preferred.ip.eql(xor_ip));
    try testing.expectEqual(@as(u16, 2222), preferred.port);
}

test "find() returns the FIRST occurrence of a duplicated attribute type (mutation guard)" {
    // Message.find's doc comment: "Later duplicates are ignored" -- no
    // existing test ever put two attributes of the same type in one message,
    // so a first-vs-last swap in find() had nothing to catch it.
    var out: [64]u8 = undefined;
    var b = try Builder.init(&out, .success_response, .binding, rfc5769_txid);
    try b.addSoftware("first");
    try b.addSoftware("second");
    const m = try decode(b.finish());
    try testing.expectEqualStrings("first", m.find(attrCode(.software)).?.value);
}

test "bindingRequest builds a bare 20-byte Binding request" {
    var out: [32]u8 = undefined;
    const req = try bindingRequest(rfc5769_txid, &out);
    try testing.expectEqual(@as(usize, header_len), req.len);
    const m = try decode(req);
    try testing.expectEqual(Class.request, m.class);
    try testing.expectEqual(Method.binding, m.method);
    try testing.expectEqual(@as(u16, 0), m.length);
}

test "ERROR-CODE parse (class*100 + number + reason)" {
    var out: [64]u8 = undefined;
    var b = try Builder.init(&out, .error_response, .binding, rfc5769_txid);
    // 401 Unauthorized: class=4, number=1.
    const val = [_]u8{ 0, 0, 4, 1 } ++ "Unauthorized".*;
    try b.addAttribute(attrCode(.error_code), &val);
    const m = try decode(b.finish());
    const ec = (try m.errorCode()).?;
    try testing.expectEqual(@as(u16, 401), ec.code);
    try testing.expectEqualStrings("Unauthorized", ec.reason);
}

test "decode rejects non-STUN, bad cookie, and truncation" {
    try testing.expectError(error.Truncated, decode(&[_]u8{0} ** 8));
    // Wrong cookie.
    var bad_cookie = req_2_1;
    bad_cookie[4] = 0x00;
    try testing.expectError(error.BadCookie, decode(&bad_cookie));
    // Top two type bits set → not STUN.
    var not_stun = req_2_1;
    not_stun[0] = 0xC0;
    try testing.expectError(error.NotStun, decode(&not_stun));
    // Length (kept a multiple of 4) points past the buffer.
    var short = req_2_1;
    short[2] = 0x01; // length 0x0158 ≫ available bytes
    try testing.expectError(error.Truncated, decode(&short));
}

test "decode: length near u16 max does not overflow header_len + length" {
    // Regression for a crash: `bytes[0 .. header_len + length]` computed
    // `header_len + length` in u16 (header_len is untyped `20`, length is
    // u16), overflowing for length >= 65516 even though the line 413 guard
    // above it correctly widens to usize first. length = 65532 = 0xFFFC
    // (still a multiple of 4, so it clears the `% 4 != 0` check) plus
    // header_len (20) overflows a u16 by design here.
    const length: u16 = 65532;
    const total = @as(usize, header_len) + length;
    const buf = try testing.allocator.alloc(u8, total);
    defer testing.allocator.free(buf);
    @memset(buf, 0);
    std.mem.writeInt(u16, buf[0..2], 0x0101, .big); // Binding response
    std.mem.writeInt(u16, buf[2..4], length, .big);
    std.mem.writeInt(u32, buf[4..8], magic_cookie, .big);

    const msg = try decode(buf);
    try testing.expectEqual(total, msg.bytes.len);
    try testing.expectEqual(length, msg.length);
}

// ── query bounded-wait tests (loopback only, no live network needed) ───────
//
// Before this, `query` called `sock.receive` with no timeout at all — a
// consumer that needed a bounded probe against a dark/unresponsive STUN
// server could not use it and kept its own UDP plumbing instead. `timeout_ms`
// (mirroring `sntp.QueryOptions`) fixes that; these two tests prove the fix
// without needing internet access: a "dark server" is just a UDP socket this
// process itself binds and never answers from.

/// Deadlock guard: panics if `done` is not set within `timeout_ms`, converting
/// a regression that makes `query` ignore its bound into a loud, bounded test
/// failure instead of a silent CI hang. Same shape as `workerpool`'s test
/// watchdog (`modules/workerpool/src/root.zig`).
const Watchdog = struct {
    io: std.Io,
    timeout_ms: i64,
    done: std.atomic.Value(u32) = .init(0),
    thread: std.Thread = undefined,

    fn run(wd: *Watchdog) void {
        const start_ns = std.Io.Timestamp.now(wd.io, .awake).nanoseconds;
        const deadline = start_ns + @as(i96, wd.timeout_ms) * std.time.ns_per_ms;
        while (wd.done.load(.seq_cst) == 0) {
            wd.io.futexWaitTimeout(u32, &wd.done.raw, 0, .{ .duration = .{
                .raw = .fromMilliseconds(50),
                .clock = .awake,
            } }) catch {};
            if (wd.done.load(.seq_cst) != 0) return;
            if (std.Io.Timestamp.now(wd.io, .awake).nanoseconds >= deadline)
                @panic("stun query test watchdog: no-responder query did not return within the bound (regressed to unbounded receive?)");
        }
    }
    fn start(wd: *Watchdog) !void {
        wd.thread = try std.Thread.spawn(.{}, run, .{wd});
    }
    fn finish(wd: *Watchdog) void {
        wd.done.store(1, .seq_cst);
        wd.io.futexWake(u32, &wd.done.raw, std.math.maxInt(u32));
        wd.thread.join();
    }
};

test "query: no responder returns error.Timeout, bounded (cannot hang the suite)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // A live but silent UDP endpoint: this process binds it but never calls
    // receive on it or replies — the "dark server" a bounded probe needs to
    // survive.
    const dark_local = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var dark = try dark_local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer dark.close(io);

    // Watchdog bounds the test itself: if `query` regressed to the old
    // unbounded `sock.receive` and ignored `timeout_ms`, this panics loudly
    // well before the test binary would otherwise hang forever.
    var wd: Watchdog = .{ .io = io, .timeout_ms = 5000 };
    try wd.start();
    defer wd.finish();

    var buf: [512]u8 = undefined;
    const txid: TransactionId = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    const result = query(io, dark.address, txid, &buf, .{ .timeout_ms = 150 });
    try testing.expectError(error.Timeout, result);
}

/// Context for the loopback fake-server thread used by the answered-path
/// test below.
const FakeStunServer = struct {
    io: std.Io,
    sock: std.Io.net.Socket,
    reply_ip: netaddr.Ip,
    reply_port: u16,

    /// Receive one Binding request, echo its transaction id back inside a
    /// success response carrying `reply_ip`/`reply_port` as an XOR-MAPPED-ADDRESS.
    fn respondOnce(self: *FakeStunServer) void {
        var req_buf: [512]u8 = undefined;
        const incoming = self.sock.receive(self.io, &req_buf) catch return;
        const req_msg = decode(incoming.data) catch return;

        var resp_buf: [64]u8 = undefined;
        var b = Builder.init(&resp_buf, .success_response, .binding, req_msg.transaction_id) catch return;
        b.addMappedAddress(self.reply_ip, self.reply_port, true) catch return;
        self.sock.send(self.io, &incoming.from, b.finish()) catch return;
    }
};

test "query: normal answered path still works, unaffected by the bound" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const bind_addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    const server_sock = try bind_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer server_sock.close(io);

    const want_ip = netaddr.parseIp("203.0.113.9").?;
    var fake: FakeStunServer = .{ .io = io, .sock = server_sock, .reply_ip = want_ip, .reply_port = 4989 };
    var th = try std.Thread.spawn(.{}, FakeStunServer.respondOnce, .{&fake});
    defer th.join();

    var buf: [512]u8 = undefined;
    const txid: TransactionId = .{ 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 11, 22 };
    // A generous but still-bounded timeout — the point of this test is that
    // an answered exchange behaves exactly as before, not that it is fast.
    const result = try query(io, server_sock.address, txid, &buf, .{ .timeout_ms = 5000 });
    try testing.expect(result.ip.eql(want_ip));
    try testing.expectEqual(@as(u16, 4989), result.port);
}

// ── 2026-10-04: retransmission, responder, URIs, long-term credentials ─────

test "Schedule: the RFC 8489 §6.2.1 example — 0, 500, 1500, 3500, 7500, 15500, 31500, give up at 39500" {
    // RFC 8489 §6.2.1: "if RTO is 500 ms, requests would be sent at times
    // 0 ms, 500 ms, 1500 ms, 3500 ms, 7500 ms, 15500 ms, and 31500 ms. If
    // the client has not received a response after 39500 ms, the client
    // will consider the transaction to have timed out."
    var sch = Schedule.init(.{});
    const want = [_]u64{ 0, 500, 1500, 3500, 7500, 15500, 31500 };
    for (want, 0..) |w, i| {
        try testing.expectEqual(@as(?u64, w), sch.nextSend());
        const until: u64 = if (i + 1 < want.len) want[i + 1] else 39500;
        try testing.expectEqual(until, sch.waitUntil());
    }
    try testing.expectEqual(@as(?u64, null), sch.nextSend());
    // No retransmission: one send, then Rm × RTO.
    var one = Schedule.init(.{ .max_requests = 1, .rto_ms = 100, .last_wait_factor = 3 });
    try testing.expectEqual(@as(?u64, 0), one.nextSend());
    try testing.expectEqual(@as(u64, 300), one.waitUntil());
    try testing.expectEqual(@as(?u64, null), one.nextSend());
}

test "Schedule: 255 requests saturate instead of overflowing" {
    var sch = Schedule.init(.{ .max_requests = 255, .rto_ms = std.math.maxInt(u32) });
    var n: usize = 0;
    while (sch.nextSend()) |_| n += 1;
    try testing.expectEqual(@as(usize, 255), n);
    _ = sch.waitUntil();
}

test "bindingResponse reproduces RFC 5769 §2.2 and §2.3 byte for byte" {
    // The §2.1 request carries USERNAME "evtj:h6vY", ICE's PRIORITY (0x0024,
    // comprehension-required — the caller declares it known) and
    // ICE-CONTROLLED (optional), a MESSAGE-INTEGRITY under the §2.1 password
    // and a FINGERPRINT. §2.2/§2.3 are its success responses for a client at
    // 192.0.2.1:32853 / [2001:db8:1234:5678:11:2233:4455:6677]:32853, with
    // SOFTWARE "test vector" whose pad byte is 0x20 (RFC 5769 §2: "padding
    // bytes are set to 0x20").
    const req = try decode(&req_2_1);
    const opts: ResponderOptions = .{
        .software = "test vector",
        .integrity_key = rfc5769_password,
        .known_attributes = &.{0x0024},
        .pad = 0x20,
    };
    var out: [128]u8 = undefined;
    const r4 = try bindingResponse(req, .{ .ip = netaddr.parseIp("192.0.2.1").?, .port = 32853 }, &out, opts);
    try testing.expectEqualSlices(u8, &resp_2_2, r4);
    const r6 = try bindingResponse(req, .{ .ip = netaddr.parseIp("2001:db8:1234:5678:11:2233:4455:6677").?, .port = 32853 }, &out, opts);
    try testing.expectEqualSlices(u8, &resp_2_3, r6);
}

test "bindingResponse: 420 for unknown comprehension-required attributes, 400/401 for credentials" {
    const req = try decode(&req_2_1);
    const from: AddressPort = .{ .ip = netaddr.parseIp("192.0.2.1").?, .port = 32853 };
    var out: [128]u8 = undefined;
    // PRIORITY (0x0024) is comprehension-required and not declared known:
    // RFC 8489 §6.3.1 — 420 with UNKNOWN-ATTRIBUTES naming it, and no
    // XOR-MAPPED-ADDRESS.
    const e = try decode(try bindingResponse(req, from, &out, .{}));
    try testing.expectEqual(Class.error_response, e.class);
    try testing.expectEqualSlices(u8, &rfc5769_txid, &e.transaction_id);
    try testing.expectEqual(@as(u16, 420), (try e.errorCode()).?.code);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x24 }, e.find(attrCode(.unknown_attributes)).?.value);
    try testing.expect((try e.mappedAddress()) == null);
    try testing.expect(e.verifyFingerprint());
    // A wrong short-term key: 401 (RFC 8489 §9.1.3).
    const u = try decode(try bindingResponse(req, from, &out, .{ .integrity_key = "wrong", .known_attributes = &.{0x0024} }));
    try testing.expectEqual(@as(u16, 401), (try u.errorCode()).?.code);
    // No USERNAME / MESSAGE-INTEGRITY at all while credentials are required: 400.
    var bare_buf: [header_len]u8 = undefined;
    const bare = try decode(try bindingRequest(rfc5769_txid, &bare_buf));
    const b = try decode(try bindingResponse(bare, from, &out, .{ .integrity_key = rfc5769_password }));
    try testing.expectEqual(@as(u16, 400), (try b.errorCode()).?.code);
    // Without credentials the bare request gets its address, nothing else
    // required; FINGERPRINT on by default, off on request.
    const ok = try decode(try bindingResponse(bare, from, &out, .{}));
    try testing.expectEqual(Class.success_response, ok.class);
    try testing.expectEqual(from.port, (try ok.mappedAddress()).?.port);
    try testing.expect(ok.verifyFingerprint());
    const nofp = try decode(try bindingResponse(bare, from, &out, .{ .fingerprint = false }));
    try testing.expect(nofp.find(attrCode(.fingerprint)) == null);
    // Responses and indications are not answered.
    try testing.expectError(error.NotBindingRequest, bindingResponse(try decode(&resp_2_2), from, &out, .{}));
    // A duplicated unknown attribute is named once.
    var dbuf: [64]u8 = undefined;
    var db = try Builder.init(&dbuf, .request, .binding, rfc5769_txid);
    try db.addAttribute(0x7001, "a");
    try db.addAttribute(0x7001, "b");
    try db.addAttribute(0x0006, "user"); // USERNAME: understood
    const d = try decode(try bindingResponse(try decode(db.finish()), from, &out, .{}));
    try testing.expectEqualSlices(u8, &.{ 0x70, 0x01 }, d.find(attrCode(.unknown_attributes)).?.value);
}

test "Builder: ERROR-CODE and UNKNOWN-ATTRIBUTES encode per RFC 8489 §14.8/§14.9" {
    var buf: [64]u8 = undefined;
    var b = try Builder.init(&buf, .error_response, .binding, rfc5769_txid);
    try b.addErrorCode(438, "Stale Nonce");
    // Class 4 in the low 3 bits of the third byte, number 38 in the fourth.
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x09, 0x00, 0x0f, 0, 0, 4, 38 }, buf[20..28]);
    try testing.expectEqual(@as(u16, 438), (try (try decode(b.finish())).errorCode()).?.code);
    try testing.expectError(error.InvalidErrorCode, b.addErrorCode(299, "x"));
    try testing.expectError(error.InvalidErrorCode, b.addErrorCode(700, "x"));
    try testing.expectError(error.ValueTooLong, b.addErrorCode(500, &([_]u8{'x'} ** 764)));
    try testing.expectError(error.ValueTooLong, b.addUnknownAttributes(&([_]u16{1} ** 65)));
}

test "STUN/TURN URIs: RFC 7064 and RFC 7065 examples" {
    // RFC 7064 §3.2 / RFC 7065 §3.2 examples, with the default ports of
    // RFC 8489 §6.2.2/§6.2.3 (3478 UDP/TCP, 5349 TLS).
    const S = Uri.Scheme;
    for ([_]struct { []const u8, S, []const u8, u16, ?Uri.Transport }{
        .{ "stun:example.org", .stun, "example.org", 3478, null },
        .{ "stuns:example.org", .stuns, "example.org", 5349, null },
        .{ "stun:example.org:8000", .stun, "example.org", 8000, null },
        .{ "turn:example.org", .turn, "example.org", 3478, null },
        .{ "turns:example.org", .turns, "example.org", 5349, null },
        .{ "turn:example.org:8000", .turn, "example.org", 8000, null },
        .{ "turn:example.org?transport=udp", .turn, "example.org", 3478, .udp },
        .{ "turn:example.org?transport=tcp", .turn, "example.org", 3478, .tcp },
        .{ "turns:example.org?transport=tcp", .turns, "example.org", 5349, .tcp },
        .{ "stun:192.0.2.1:19302", .stun, "192.0.2.1", 19302, null },
        .{ "stun:[2001:db8::1]:3479", .stun, "2001:db8::1", 3479, null },
        .{ "STUN:Example.ORG", .stun, "Example.ORG", 3478, null }, // scheme is case-insensitive (RFC 3986 §3.1)
    }) |c| {
        const u = try parseUri(c[0]);
        try testing.expectEqual(c[1], u.scheme);
        try testing.expectEqualStrings(c[2], u.host);
        try testing.expectEqual(c[3], u.port);
        try testing.expectEqual(c[4], u.transport);
    }
    try testing.expect((try parseUri("stuns:example.org")).secure());
    try testing.expect(!(try parseUri("turn:example.org")).secure());
    for ([_][]const u8{
        "example.org",              "http:example.org",   "stun:",                  "stun:user@example.org",          "stun:example.org/path",
        "stun:example.org:",        "stun:example.org:0", "stun:example.org:65536", "stun:example.org?transport=udp", "turn:example.org?transport=sctp",
        "turn:example.org?foo=udp", "stun:[]",            "stun:[2001:db8::1",      "stun:[g::1]",                    "stun:example.org#frag",
    }) |bad| {
        testing.expectError(error.InvalidUri, parseUri(bad)) catch |e| {
            std.debug.print("accepted: {s}\n", .{bad});
            return e;
        };
    }
}

test "long-term credentials: RFC 5769 §2.4's request verifies under MD5(user:realm:pass)" {
    // RFC 5769 §2.4 "Sample Request with Long-Term Authentication": USERNAME
    // "マトリックス" (U+30DE U+30C8 U+30EA U+30C3 U+30AF U+30B9, 18 bytes of
    // UTF-8), NONCE "f//499k954d6OL34oL9FSTvy64sA", REALM "example.org",
    // password "The<U+00AD>M<U+00AA>tr<U+2168>" which SASLprep maps to
    // "TheMatrIX" (the RFC gives the prepared form).
    const req_2_4 = [_]u8{
        0x00, 0x01, 0x00, 0x60, 0x21, 0x12, 0xa4, 0x42, 0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72, 0xc0, 0x29, 0xda, 0x41, 0x2e,
        0x00, 0x06, 0x00, 0x12, 0xe3, 0x83, 0x9e, 0xe3, 0x83, 0x88, 0xe3, 0x83, 0xaa, 0xe3, 0x83, 0x83, 0xe3, 0x82, 0xaf, 0xe3,
        0x82, 0xb9, 0x00, 0x00, 0x00, 0x15, 0x00, 0x1c, 0x66, 0x2f, 0x2f, 0x34, 0x39, 0x39, 0x6b, 0x39, 0x35, 0x34, 0x64, 0x36,
        0x4f, 0x4c, 0x33, 0x34, 0x6f, 0x4c, 0x39, 0x46, 0x53, 0x54, 0x76, 0x79, 0x36, 0x34, 0x73, 0x41, 0x00, 0x14, 0x00, 0x0b,
        0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x08, 0x00, 0x14, 0xf6, 0x70, 0x24, 0x65,
        0x6d, 0xd6, 0x4a, 0x3e, 0x02, 0xb8, 0xe0, 0x71, 0x2e, 0x85, 0xc9, 0xa2, 0x8c, 0xa8, 0x96, 0x66,
    };
    const m = try decode(&req_2_4);
    const user = m.find(attrCode(.username)).?.value;
    try testing.expectEqualStrings("マトリックス", user);
    const realm = m.find(attrCode(.realm)).?.value;
    try testing.expectEqualStrings("example.org", realm);
    try testing.expectEqualStrings("f//499k954d6OL34oL9FSTvy64sA", m.find(attrCode(.nonce)).?.value);
    var key: [16]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    longTermKey(&key, user, realm, "TheMatrIX");
    try testing.expect(m.verifyMessageIntegrity(&key));
    // The unprepared password gives another key, which does not verify.
    var raw: [16]u8 = undefined;
    defer std.crypto.secureZero(u8, &raw);
    longTermKey(&raw, user, realm, "The\u{00AD}M\u{00AA}tr\u{2168}");
    try testing.expect(!m.verifyMessageIntegrity(&raw));
    // Builder round trip: the same attributes signed with the key verify.
    var buf: [128]u8 = undefined;
    var b = try Builder.init(&buf, .request, .binding, m.transaction_id);
    try b.addUsername(user);
    try b.addNonce("f//499k954d6OL34oL9FSTvy64sA");
    try b.addRealm(realm);
    try b.addMessageIntegrity(&key);
    try testing.expectEqualSlices(u8, &req_2_4, b.finish());
}

/// A loopback STUN server that misbehaves on purpose: it drops the first
/// `drop` requests, sends a stray reply with a foreign transaction id before
/// answering, or answers only with an error response.
const RetransServer = struct {
    io: std.Io,
    sock: std.Io.net.Socket,
    drop: usize,
    mode: enum { answer, stray_only, error_response } = .answer,
    seen: usize = 0,

    fn run(self: *RetransServer) void {
        while (true) {
            var req_buf: [512]u8 = undefined;
            const incoming = self.sock.receiveTimeout(self.io, &req_buf, .{ .duration = .{ .raw = .fromMilliseconds(1000), .clock = .awake } }) catch return;
            const req = decode(incoming.data) catch return;
            self.seen += 1;
            if (self.seen <= self.drop) continue;
            var out: [64]u8 = undefined;
            // A stray first: same shape, another transaction id.
            var stray_id = req.transaction_id;
            stray_id[0] ^= 0xff;
            var sb = Builder.init(&out, .success_response, .binding, stray_id) catch return;
            sb.addMappedAddress(netaddr.parseIp("198.51.100.66").?, 1, true) catch return;
            self.sock.send(self.io, &incoming.from, sb.finish()) catch return;
            if (self.mode == .stray_only) continue;
            var b = Builder.init(&out, if (self.mode == .answer) .success_response else .error_response, .binding, req.transaction_id) catch return;
            if (self.mode == .answer) {
                b.addMappedAddress(netaddr.parseIp("203.0.113.9").?, 4989, true) catch return;
            } else {
                b.addErrorCode(420, "Unknown Attribute") catch return;
            }
            self.sock.send(self.io, &incoming.from, b.finish()) catch return;
            return;
        }
    }
};

fn retransRun(mode: @FieldType(RetransServer, "mode"), drop: usize, opts: QueryOptions) !struct { result: anyerror!AddressPort, seen: usize } {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const bind_addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    const server_sock = try bind_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer server_sock.close(io);
    var srv: RetransServer = .{ .io = io, .sock = server_sock, .drop = drop, .mode = mode };
    var th = try std.Thread.spawn(.{}, RetransServer.run, .{&srv});
    var buf: [512]u8 = undefined;
    const txid: TransactionId = .{ 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7 };
    const result = query(io, server_sock.address, txid, &buf, opts);
    th.join();
    return .{ .result = result, .seen = srv.seen };
}

test "query retransmits until answered and ignores a stray reply on the way (RFC 8489 §6.2.1, §6.3.4)" {
    // Two requests are dropped; the third gets a foreign-transaction stray,
    // then the real answer. RTO 40 ms: sends at 0, 40, 120 ms.
    const r = try retransRun(.answer, 2, .{ .rto_ms = 40, .timeout_ms = 3000 });
    const ap = try r.result;
    try testing.expect(ap.ip.eql(netaddr.parseIp("203.0.113.9").?));
    try testing.expectEqual(@as(u16, 4989), ap.port);
    try testing.expectEqual(@as(usize, 3), r.seen);
}

test "query: max_requests = 1 sends once (the old behaviour), and a lone stray is reported, not a Timeout" {
    const once = try retransRun(.answer, 1, .{ .rto_ms = 40, .max_requests = 1, .last_wait_factor = 4, .timeout_ms = 3000 });
    try testing.expectError(error.Timeout, once.result);
    try testing.expectEqual(@as(usize, 1), once.seen);
    // Only strays come back: after the schedule ends, the error names what
    // arrived instead of pretending nothing did.
    const stray = try retransRun(.stray_only, 0, .{ .rto_ms = 20, .max_requests = 2, .last_wait_factor = 4, .timeout_ms = 3000 });
    try testing.expectError(error.TransactionMismatch, stray.result);
    try testing.expectEqual(@as(usize, 2), stray.seen);
}

test "query: timeout_ms caps a single long retransmission window too" {
    // RTO 10 s, cap 100 ms: the first window must end at the cap, not at the
    // RTO. The 5 s bound below is 50x the cap — slack for a loaded machine,
    // still far short of the 10 s an uncapped window would take.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const dark_local = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var dark = try dark_local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer dark.close(io);
    var buf: [512]u8 = undefined;
    const t0 = std.Io.Clock.Timestamp.now(io, .awake);
    const r = query(io, dark.address, .{ 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3 }, &buf, .{ .timeout_ms = 100, .rto_ms = 10_000 });
    try testing.expectError(error.Timeout, r);
    const elapsed = t0.durationTo(std.Io.Clock.Timestamp.now(io, .awake));
    try testing.expect(elapsed.raw.toMilliseconds() < 5000);
}

test "query: an error response for our transaction ends the exchange" {
    const r = try retransRun(.error_response, 0, .{ .rto_ms = 40, .timeout_ms = 3000 });
    try testing.expectError(error.ErrorResponse, r.result);
    try testing.expectEqual(@as(usize, 1), r.seen);
}

/// `testkit.fuzz.seed`: a corpus entry is NOT the packet. `Smith.slice` reads a
/// little-endian `u32` length first, so a raw STUN message handed to the corpus
/// would reach `decode` minus its own first four octets — that is, with its
/// message type and length shorn off, which decodes as garbage every time.
const seed = @import("testkit").fuzz.seed;

// The three mutants `decode rejects non-STUN, bad cookie, and truncation`
// builds at run time, lifted to comptime so the corpus can carry them.
const req_bad_cookie = blk: {
    var b = req_2_1;
    b[4] = 0x00;
    break :blk b;
};
const req_not_stun = blk: {
    var b = req_2_1;
    b[0] = 0xC0; // top two type bits set
    break :blk b;
};
const req_length_past_end = blk: {
    var b = req_2_1;
    b[2] = 0x01; // length 0x0158, far past the 108 octets present
    break :blk b;
};

/// STUN messages in the format `Smith.slice` reads (see `testkit.fuzz`).
///
/// `decode` demands a 20-octet header whose top two type bits are clear, whose
/// magic cookie is exactly `0x2112A442` and whose length is a multiple of four
/// that lands inside the buffer: uniform random octets clear all of that with
/// probability under 2^-34 per draw, so without a corpus this target proves
/// only that the cookie check rejects noise, and the accessors, the attribute
/// walk and both verifiers — the code the test's own name promises to cover —
/// are never reached at all.
///
/// ⚠ One fixture is deliberately absent. The `length near u16 max does not
/// overflow` regression needs a 65 552-octet message; no stack-sized harness
/// buffer can carry it, so that path stays covered by its own value test and
/// is out of this harness's reach by construction, not by oversight.
const decode_seeds = [_][]const u8{
    seed(&req_2_1), // RFC 5769 §2.1 request: 6 attributes, MI + FINGERPRINT both verify
    seed(&resp_2_2), // §2.2 success response: IPv4 XOR-MAPPED-ADDRESS
    seed(&resp_2_3), // §2.3 success response: IPv6 XOR-MAPPED-ADDRESS
    seed(&req_bad_cookie), // BadCookie
    seed(&req_not_stun), // NotStun
    seed(&req_length_past_end), // Truncated: declared length past the buffer
    seed(&[_]u8{0} ** 8), // Truncated: shorter than the header
    // A bare 20-octet Binding request: header only, zero attributes. Decodes,
    // and every accessor below must cope with an empty attribute list.
    seed(&[_]u8{ 0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42 } ++ rfc5769_txid),
    // Binding error response carrying ERROR-CODE 401 Unauthorized.
    seed(&[_]u8{ 0x01, 0x11, 0x00, 0x14, 0x21, 0x12, 0xa4, 0x42 } ++ rfc5769_txid ++
        [_]u8{ 0x00, 0x09, 0x00, 0x10, 0x00, 0x00, 0x04, 0x01 } ++ "Unauthorized".*),
    // An attribute whose declared value length runs past the message: the
    // attribute walk must stop, not read off the end.
    seed(&[_]u8{ 0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xa4, 0x42 } ++ rfc5769_txid ++
        [_]u8{ 0x80, 0x22, 0xFF, 0xF0, 0xAA, 0xBB, 0xCC, 0xDD }),
};

test "fuzz: decode + every accessor never crash on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecode, .{ .corpus = &decode_seeds });
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length (the ranged draw would find fewer than eight octets and return the
    // range MINIMUM, so the message was never read; measured 2026-09-07).
    // The harness body lives in `fuzz_test.zig`, generic over its source.
    const ft = @import("fuzz_test.zig");
    var script: [1024]u8 = undefined;
    const n: usize = smith.slice(&script);
    var src: ft.ScriptSource = .{ .cur = .{ .bytes = script[0..n] } };
    try ft.decodeHarness(ft.ScriptSource, &src, testing.allocator);
}

test "corpus: every seed reaches decode, and the walk/accessor counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment. A seed
    // longer than the harness's buffer reads back EMPTY (`Smith.slice` falls
    // back to the range minimum) and nothing else in the tree would notice.
    //
    // ⚠ `accepted` alone would be a weak guard, so `attrs` is pinned beside it:
    // the empty input cannot walk a single attribute, and neither can the bare
    // header seed, so a non-zero `attrs` is a statement about REACH rather than
    // about what `decode` happens to consider legal.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var attrs: usize = 0;
    var verified: usize = 0;
    for (decode_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var packet: [1024]u8 = undefined;
        const len: usize = smith.slice(&packet);
        if (len != 0) nonempty += 1;
        const msg = decode(packet[0..len]) catch continue;
        accepted += 1;
        var it = msg.attributes();
        while (it.next()) |_| attrs += 1;
        if (msg.verifyFingerprint() and msg.verifyMessageIntegrity(rfc5769_password)) verified += 1;
    }
    try testing.expectEqual(decode_seeds.len, nonempty);
    // Measured 2026-09-07: with the collapsing draw, 0 of 10 seeds non-empty,
    // 0 decoded, 0 attributes walked and 0 verified — one empty slice, ten
    // times. After:
    try testing.expectEqual(@as(usize, 6), accepted);
    try testing.expectEqual(@as(usize, 15), attrs);
    try testing.expectEqual(@as(usize, 3), verified);
}

test {
    _ = @import("fuzz_test.zig");
    _ = @import("stackprobe_test.zig");
}
