// SPDX-License-Identifier: MIT

//! dtls.messages — ClientHello / ServerHello / EncryptedExtensions /
//! Finished message-BODY framing (the bytes after `handshake.zig`'s 12-byte
//! header has been stripped/reassembled). These bodies are structurally
//! identical to TLS 1.3's (RFC 8446 §4.1) — DTLS 1.3 reuses them verbatim
//! (RFC 9147 §5.3/§5.4); only the record and handshake HEADERS differ
//! between TLS and DTLS, never these message shapes.
//!
//! PSK-mode only (RFC 8446 §4.2.11 `pre_shared_key`/`psk_key_exchange_modes`
//! extensions — no certificate path). Fields whose meaning is entirely
//! cryptographic (the PSK binder value, Finished's `verify_data`) are
//! modeled as opaque `[]const u8`: real bytes flow through so framing
//! round-trips, but this file never computes or interprets them — that's
//! `keyschedule.zig`'s job.

const std = @import("std");

pub const MessageError = error{
    BufferTooShort,
    Malformed,
    TooManyExtensions,
    ListTooLong,
    /// `decodeCertificate`'s `entries_out` is smaller than the number of
    /// `CertificateEntry` values the wire message declares.
    TooManyCertificateEntries,
    /// RFC 8446 §4.2: "There MUST NOT be more than one extension of the same
    /// type in a given extension block ... a receiver MUST ... abort the
    /// handshake with an `illegal_parameter` alert." See `decodeExtensions`
    /// for why this is a security property here, not pedantry.
    DuplicateExtension,
};

/// RFC 8446 §4 handshake message types. `certificate`/`certificate_request`/
/// `certificate_verify` (RFC 8446 §4.4.2/§4.3.2/§4.4.3) back the certificate-
/// mode handshake extension (see `Connection.zig`'s "certificate mode"
/// section and `root.zig`'s module doc) — layered ADDITIVELY onto the
/// PSK-only message set below; PSK-mode framing is unchanged.
pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    _,
};

pub const ExtensionType = enum(u16) {
    server_name = 0,
    supported_groups = 10,
    signature_algorithms = 13,
    supported_versions = 43,
    cookie = 44,
    pre_shared_key = 41,
    psk_key_exchange_modes = 45,
    key_share = 51,
    _,
};

/// RFC 8446 §4.2.7 `NamedGroup` code points for the (EC)DHE groups this
/// module's cert-only-DHE handshake mode can offer/select. BOTH are wired
/// end-to-end in `Connection.zig` (see its `ecdheGenerate`/`ecdheSharedSecret`):
///   * `x25519` — `KeyShareEntry.key_exchange` is the raw 32-byte X25519
///     public key (RFC 8446 §4.2.8.1 / RFC 7748); shared secret = the 32-byte
///     scalarmult output;
///   * `secp256r1` — `key_exchange` is the 65-byte UNCOMPRESSED SEC1 point
///     `0x04 || X || Y` (RFC 8446 §4.2.8.2); shared secret = the 32-byte X
///     coordinate of the shared point ONLY, not the point encoding.
/// An earlier version of this module advertised `secp256r1` in
/// `supported_groups` while being unable to compute a share for it — which
/// is exactly what makes a server answer with a HelloRetryRequest naming it.
pub const NamedGroup = enum(u16) {
    secp256r1 = 0x0017,
    x25519 = 0x001d,
    _,
};

/// RFC 9147 §5.3: DTLS 1.3's ClientHello.legacy_version stays {254, 253}
/// ("DTLS 1.2") on the wire, for backward/middlebox compatibility — actual
/// version negotiation happens via the `supported_versions` extension
/// (mirrors TLS 1.3's ClientHello.legacy_version = {3, 3}, RFC 8446 §4.1.2).
pub const legacy_version_dtls12 = [2]u8{ 0xFE, 0xFD };

/// DTLS 1.3's real wire version, {254, 252}. It appears ONLY inside the
/// `supported_versions` extension — never in a record or Hello version field.
pub const version_dtls13 = [2]u8{ 0xFE, 0xFC };

/// `supported_versions` in its ClientHello form: a 1-byte-length-prefixed
/// list of versions (RFC 8446 §4.2.1).
///
/// Without this extension a peer has nothing to negotiate on — every version
/// field on the wire says DTLS 1.2 — so it either downgrades or, as wolfSSL
/// does, rejects the handshake outright. Sending it is not optional for a
/// 1.3 client.
pub fn encodeSupportedVersionsClientHello(versions: []const [2]u8, out: []u8) MessageError![]u8 {
    const body_len = versions.len * 2;
    if (body_len > std.math.maxInt(u8)) return error.ListTooLong;
    if (out.len < 1 + body_len) return error.BufferTooShort;
    out[0] = @intCast(body_len);
    var i: usize = 1;
    for (versions) |v| {
        out[i..][0..2].* = v;
        i += 2;
    }
    return out[0..i];
}

/// `supported_versions` in its ServerHello/HelloRetryRequest form: a single
/// selected version, no list prefix (RFC 8446 §4.2.1).
pub fn encodeSupportedVersionsServerHello(version: [2]u8, out: []u8) MessageError![]u8 {
    if (out.len < 2) return error.BufferTooShort;
    out[0..2].* = version;
    return out[0..2];
}

/// Decodes the ServerHello form. Returns `error.Malformed` on any other length
/// — a 1.3 server's answer is exactly two bytes.
pub fn decodeSupportedVersionsServerHello(data: []const u8) MessageError![2]u8 {
    if (data.len != 2) return error.Malformed;
    return data[0..2].*;
}

/// RFC 8446 §4.1.3: the ServerHello.random magic value that means "this is
/// actually a HelloRetryRequest" (same message type, distinguished only by
/// this field). RFC 9147 does not redefine it, so it's reused directly from
/// Zig std's own TLS 1.3 client rather than re-transcribed by hand — a
/// spec-mandated public constant, not an implementation detail worth
/// duplicating: `std.crypto.tls.hello_retry_request_sequence`.
pub const hello_retry_request_random = std.crypto.tls.hello_retry_request_sequence;

pub fn isHelloRetryRequest(random: [32]u8) bool {
    return std.mem.eql(u8, &random, &hello_retry_request_random);
}

// ── generic extension list (RFC 8446 §4.2) ───────────────────────────────

pub const Extension = struct {
    ext_type: u16,
    data: []const u8,
};

/// Encodes `exts` as a u16-length-prefixed list of `{type: u16, length:
/// u16, data}` entries (RFC 8446 §4.2). Returns the slice of `out` used,
/// including the outer 2-byte list length.
pub fn encodeExtensions(exts: []const Extension, out: []u8) MessageError![]u8 {
    var body_len: usize = 0;
    for (exts) |e| body_len += 4 + e.data.len;
    if (body_len > std.math.maxInt(u16)) return error.ListTooLong;
    if (out.len < 2 + body_len) return error.BufferTooShort;

    std.mem.writeInt(u16, out[0..2], @intCast(body_len), .big);
    var i: usize = 2;
    for (exts) |e| {
        std.mem.writeInt(u16, out[i..][0..2], e.ext_type, .big);
        std.mem.writeInt(u16, out[i + 2 ..][0..2], @intCast(e.data.len), .big);
        @memcpy(out[i + 4 ..][0..e.data.len], e.data);
        i += 4 + e.data.len;
    }
    return out[0..i];
}

/// Decodes an extension list into caller-supplied `out`. Each returned
/// `Extension.data` aliases into `buf` — no copy.
///
/// A repeated extension type is `error.DuplicateExtension` (RFC 8446 §4.2 /
/// RFC 6347 §4.2: "There MUST NOT be more than one extension of the same
/// type in a given extension block ... abort ... with an
/// `illegal_parameter` alert"). This is not spec pedantry: with duplicates
/// accepted, WHICH copy takes effect is a property of each consumer's loop
/// rather than of the message — this module's own consumers used to disagree
/// (last-wins for `pre_shared_key`, the HRR `cookie` and
/// `signature_algorithms`; first-wins for `key_share`), so an attacker who
/// can append to an extension block picks the winner per field. Rejecting
/// the block is the only resolution that cannot be gamed.
///
/// The scan is O(n²) over `n <= out.len`, and every caller in this module
/// passes a fixed, small `out` array (the `TooManyExtensions` cap), so the
/// work is bounded by our own buffer, not by the peer.
pub fn decodeExtensions(buf: []const u8, out: []Extension) MessageError![]Extension {
    if (buf.len < 2) return error.BufferTooShort;
    const body_len: usize = std.mem.readInt(u16, buf[0..2], .big);
    if (buf.len < 2 + body_len) return error.BufferTooShort;

    var i: usize = 2;
    const end = 2 + body_len;
    var n: usize = 0;
    while (i < end) {
        if (i + 4 > end) return error.Malformed;
        const ext_type = std.mem.readInt(u16, buf[i..][0..2], .big);
        const len: usize = std.mem.readInt(u16, buf[i + 2 ..][0..2], .big);
        i += 4;
        if (i + len > end) return error.Malformed;
        if (n >= out.len) return error.TooManyExtensions;
        for (out[0..n]) |prev| {
            if (prev.ext_type == ext_type) return error.DuplicateExtension;
        }
        out[n] = .{ .ext_type = ext_type, .data = buf[i..][0..len] };
        n += 1;
        i += len;
    }
    return out[0..n];
}

// ── cookie extension (RFC 8446 §4.2.2, framing reused by DTLS 1.3's
// HelloRetryRequest-based cookie exchange — RFC 9147 §5.3) ──────────────

pub fn encodeCookieExtension(cookie: []const u8, out: []u8) MessageError![]u8 {
    if (cookie.len > std.math.maxInt(u16)) return error.ListTooLong;
    if (out.len < 2 + cookie.len) return error.BufferTooShort;
    std.mem.writeInt(u16, out[0..2], @intCast(cookie.len), .big);
    @memcpy(out[2..][0..cookie.len], cookie);
    return out[0 .. 2 + cookie.len];
}

pub fn decodeCookieExtension(data: []const u8) MessageError![]const u8 {
    if (data.len < 2) return error.BufferTooShort;
    const len: usize = std.mem.readInt(u16, data[0..2], .big);
    if (data.len < 2 + len) return error.Malformed;
    return data[2..][0..len];
}

// ── psk_key_exchange_modes extension (RFC 8446 §4.2.9) ───────────────────

pub const PskKeyExchangeMode = enum(u8) {
    psk_ke = 0,
    psk_dhe_ke = 1,
    _,
};

pub fn encodePskKeyExchangeModes(modes: []const PskKeyExchangeMode, out: []u8) MessageError![]u8 {
    if (modes.len == 0 or modes.len > 255) return error.Malformed;
    if (out.len < 1 + modes.len) return error.BufferTooShort;
    out[0] = @intCast(modes.len);
    for (modes, 0..) |m, i| out[1 + i] = @intFromEnum(m);
    return out[0 .. 1 + modes.len];
}

pub fn decodePskKeyExchangeModes(data: []const u8, out: []PskKeyExchangeMode) MessageError![]PskKeyExchangeMode {
    if (data.len < 1) return error.BufferTooShort;
    const n = data[0];
    if (data.len < 1 + @as(usize, n)) return error.Malformed;
    if (n > out.len) return error.TooManyExtensions;
    for (0..n) |i| out[i] = @enumFromInt(data[1 + i]);
    return out[0..n];
}

// ── pre_shared_key extension, ClientHello form (RFC 8446 §4.2.11) ───────
//
// The binder VALUE is crypto-core (`keyschedule.zig`'s `pskBinder`); this
// file only frames whatever binder bytes it's handed.

pub const PskIdentity = struct {
    identity: []const u8,
    obfuscated_ticket_age: u32,
};

pub const OfferedPsks = struct {
    identities: []const PskIdentity,
    binders: []const []const u8,
};

pub fn encodeOfferedPsks(psks: OfferedPsks, out: []u8) MessageError![]u8 {
    var ids_len: usize = 0;
    for (psks.identities) |id| ids_len += 2 + id.identity.len + 4;
    var binders_len: usize = 0;
    for (psks.binders) |b| binders_len += 1 + b.len;
    if (ids_len > std.math.maxInt(u16) or binders_len > std.math.maxInt(u16)) return error.ListTooLong;

    const needed = 2 + ids_len + 2 + binders_len;
    if (out.len < needed) return error.BufferTooShort;

    std.mem.writeInt(u16, out[0..2], @intCast(ids_len), .big);
    var i: usize = 2;
    for (psks.identities) |id| {
        std.mem.writeInt(u16, out[i..][0..2], @intCast(id.identity.len), .big);
        i += 2;
        @memcpy(out[i..][0..id.identity.len], id.identity);
        i += id.identity.len;
        std.mem.writeInt(u32, out[i..][0..4], id.obfuscated_ticket_age, .big);
        i += 4;
    }

    std.mem.writeInt(u16, out[i..][0..2], @intCast(binders_len), .big);
    i += 2;
    for (psks.binders) |b| {
        if (b.len > 255) return error.ListTooLong;
        out[i] = @intCast(b.len);
        i += 1;
        @memcpy(out[i..][0..b.len], b);
        i += b.len;
    }
    return out[0..i];
}

pub const DecodedOfferedPsks = struct {
    identities: []PskIdentity,
    binders: [][]const u8,
};

pub fn decodeOfferedPsks(
    buf: []const u8,
    identities_out: []PskIdentity,
    binders_out: [][]const u8,
) MessageError!DecodedOfferedPsks {
    if (buf.len < 2) return error.BufferTooShort;
    const ids_len: usize = std.mem.readInt(u16, buf[0..2], .big);
    if (buf.len < 2 + ids_len + 2) return error.BufferTooShort;

    var i: usize = 2;
    const ids_end = 2 + ids_len;
    var n_ids: usize = 0;
    while (i < ids_end) {
        if (i + 2 > ids_end) return error.Malformed;
        const id_len: usize = std.mem.readInt(u16, buf[i..][0..2], .big);
        i += 2;
        if (i + id_len + 4 > ids_end) return error.Malformed;
        if (n_ids >= identities_out.len) return error.TooManyExtensions;
        identities_out[n_ids] = .{
            .identity = buf[i..][0..id_len],
            .obfuscated_ticket_age = std.mem.readInt(u32, buf[i + id_len ..][0..4], .big),
        };
        i += id_len + 4;
        n_ids += 1;
    }

    if (buf.len < i + 2) return error.BufferTooShort;
    const binders_len: usize = std.mem.readInt(u16, buf[i..][0..2], .big);
    i += 2;
    if (buf.len < i + binders_len) return error.BufferTooShort;

    const binders_end = i + binders_len;
    var n_binders: usize = 0;
    while (i < binders_end) {
        const b_len = buf[i];
        i += 1;
        if (i + b_len > binders_end) return error.Malformed;
        if (n_binders >= binders_out.len) return error.TooManyExtensions;
        binders_out[n_binders] = buf[i..][0..b_len];
        i += b_len;
        n_binders += 1;
    }

    return .{
        .identities = identities_out[0..n_ids],
        .binders = binders_out[0..n_binders],
    };
}

/// Server's `pre_shared_key` extension response (RFC 8446 §4.2.11): just
/// the selected identity's index into the ClientHello's list.
pub fn encodeSelectedIdentity(index: u16, out: *[2]u8) void {
    std.mem.writeInt(u16, out, index, .big);
}

pub fn decodeSelectedIdentity(buf: *const [2]u8) u16 {
    return std.mem.readInt(u16, buf, .big);
}

// ── u16-list extensions: supported_groups (RFC 8446 §4.2.7) and
// signature_algorithms (RFC 8446 §4.2.3) ────────────────────────────────
//
// Both are wire-identical: a 2-byte outer length prefix (byte count, not
// element count) followed by a sequence of big-endian u16 values. The
// module performs NO negotiation over these (see `Connection.zig`'s
// "certificate mode" deferred notes) — they are advertised so a compliant
// peer's parser accepts the ClientHello, and (server side) the offered
// group list is scanned only to confirm the one group this module speaks
// (x25519) is present.

/// Encodes a `<2..2^16-1>`-framed list of big-endian u16 values (the shared
/// shape of `supported_groups` and `signature_algorithms`).
pub fn encodeU16ListExtension(values: []const u16, out: []u8) MessageError![]u8 {
    const body = values.len * 2;
    if (body > std.math.maxInt(u16)) return error.ListTooLong;
    if (out.len < 2 + body) return error.BufferTooShort;
    std.mem.writeInt(u16, out[0..2], @intCast(body), .big);
    var i: usize = 2;
    for (values) |v| {
        std.mem.writeInt(u16, out[i..][0..2], v, .big);
        i += 2;
    }
    return out[0..i];
}

/// Decodes a `<2..2^16-1>`-framed list of big-endian u16 values into
/// caller-supplied `out`.
pub fn decodeU16ListExtension(data: []const u8, out: []u16) MessageError![]u16 {
    if (data.len < 2) return error.BufferTooShort;
    const body: usize = std.mem.readInt(u16, data[0..2], .big);
    if (data.len < 2 + body) return error.BufferTooShort;
    if (body % 2 != 0) return error.Malformed;
    const n = body / 2;
    if (n > out.len) return error.TooManyExtensions;
    var i: usize = 2;
    for (0..n) |k| {
        out[k] = std.mem.readInt(u16, data[i..][0..2], .big);
        i += 2;
    }
    return out[0..n];
}

/// Copies out only those entries of a u16-list extension that appear in
/// `wanted`, preserving the peer's order, and reports how many were kept.
///
/// A plain "decode the whole list" needs a buffer sized for the PEER's list,
/// which makes any fixed buffer a hard interop cliff: wolfSSL offers 18
/// `signature_algorithms` entries and OpenSSL a similar number, so a
/// receiver with room for 8 rejects the handshake outright — with a decode
/// error, as if the peer had sent garbage. Nothing about a long list is
/// malformed. Sizing the buffer by OUR OWN list instead removes the cliff:
/// entries we could never select are exactly the ones we do not need to
/// remember.
pub fn filterU16ListExtension(data: []const u8, wanted: []const u16, out: []u16) MessageError![]u16 {
    if (data.len < 2) return error.BufferTooShort;
    const body_len: usize = std.mem.readInt(u16, data[0..2], .big);
    if (body_len % 2 != 0) return error.Malformed;
    if (data.len < 2 + body_len) return error.BufferTooShort;

    var n: usize = 0;
    var i: usize = 2;
    while (i < 2 + body_len) : (i += 2) {
        const v = std.mem.readInt(u16, data[i..][0..2], .big);
        for (wanted) |w| {
            if (w != v) continue;
            // `wanted` is the caller's own list, so `out` sized to it always
            // has room — unless the peer repeated an entry, which is not
            // worth failing over.
            if (n < out.len) {
                out[n] = v;
                n += 1;
            }
            break;
        }
    }
    return out[0..n];
}

/// `supported_groups` (RFC 8446 §4.2.7) — alias of `encodeU16ListExtension`.
pub fn encodeSupportedGroups(groups: []const u16, out: []u8) MessageError![]u8 {
    return encodeU16ListExtension(groups, out);
}
/// `signature_algorithms` (RFC 8446 §4.2.3) — alias of `encodeU16ListExtension`.
pub fn encodeSignatureAlgorithms(schemes: []const u16, out: []u8) MessageError![]u8 {
    return encodeU16ListExtension(schemes, out);
}

// ── key_share extension (RFC 8446 §4.2.8) ────────────────────────────────
//
// struct {
//     NamedGroup group;                 // u16
//     opaque key_exchange<1..2^16-1>;   // the raw public share
// } KeyShareEntry;
//
// ClientHello form is a `KeyShareEntry client_shares<0..2^16-1>` list; the
// ServerHello form is a single bare `KeyShareEntry server_share` (no outer
// list-length prefix). The `key_exchange` bytes are opaque here (for x25519,
// the 32-byte public key) — this file frames them, `Connection.zig` computes
// them (`std.crypto.dh.X25519`).

pub const KeyShareEntry = struct {
    group: u16,
    key_exchange: []const u8,
};

/// ClientHello `key_share` (RFC 8446 §4.2.8.1): the `client_shares` list.
pub fn encodeKeyShareClientHello(entries: []const KeyShareEntry, out: []u8) MessageError![]u8 {
    var list_len: usize = 0;
    for (entries) |e| list_len += 4 + e.key_exchange.len;
    if (list_len > std.math.maxInt(u16)) return error.ListTooLong;
    if (out.len < 2 + list_len) return error.BufferTooShort;
    std.mem.writeInt(u16, out[0..2], @intCast(list_len), .big);
    var i: usize = 2;
    for (entries) |e| {
        if (e.key_exchange.len > std.math.maxInt(u16)) return error.ListTooLong;
        std.mem.writeInt(u16, out[i..][0..2], e.group, .big);
        std.mem.writeInt(u16, out[i + 2 ..][0..2], @intCast(e.key_exchange.len), .big);
        @memcpy(out[i + 4 ..][0..e.key_exchange.len], e.key_exchange);
        i += 4 + e.key_exchange.len;
    }
    return out[0..i];
}

/// Decodes a ClientHello `key_share` list into caller-supplied `out`. Each
/// returned `KeyShareEntry.key_exchange` aliases into `data` — no copy.
pub fn decodeKeyShareClientHello(data: []const u8, entries_out: []KeyShareEntry) MessageError![]KeyShareEntry {
    if (data.len < 2) return error.BufferTooShort;
    const list_len: usize = std.mem.readInt(u16, data[0..2], .big);
    if (data.len < 2 + list_len) return error.BufferTooShort;
    var i: usize = 2;
    const end = 2 + list_len;
    var n: usize = 0;
    while (i < end) {
        if (i + 4 > end) return error.Malformed;
        const group = std.mem.readInt(u16, data[i..][0..2], .big);
        const klen: usize = std.mem.readInt(u16, data[i + 2 ..][0..2], .big);
        i += 4;
        if (i + klen > end) return error.Malformed;
        if (n >= entries_out.len) return error.TooManyExtensions;
        entries_out[n] = .{ .group = group, .key_exchange = data[i..][0..klen] };
        n += 1;
        i += klen;
    }
    return entries_out[0..n];
}

/// ServerHello `key_share` (RFC 8446 §4.2.8): a single bare `KeyShareEntry`
/// (no outer list-length prefix).
pub fn encodeKeyShareServerHello(entry: KeyShareEntry, out: []u8) MessageError![]u8 {
    if (entry.key_exchange.len > std.math.maxInt(u16)) return error.ListTooLong;
    if (out.len < 4 + entry.key_exchange.len) return error.BufferTooShort;
    std.mem.writeInt(u16, out[0..2], entry.group, .big);
    std.mem.writeInt(u16, out[2..4], @intCast(entry.key_exchange.len), .big);
    @memcpy(out[4..][0..entry.key_exchange.len], entry.key_exchange);
    return out[0 .. 4 + entry.key_exchange.len];
}

pub fn decodeKeyShareServerHello(data: []const u8) MessageError!KeyShareEntry {
    if (data.len < 4) return error.BufferTooShort;
    const group = std.mem.readInt(u16, data[0..2], .big);
    const klen: usize = std.mem.readInt(u16, data[2..4], .big);
    if (data.len < 4 + klen) return error.Malformed;
    return .{ .group = group, .key_exchange = data[4..][0..klen] };
}

/// The THIRD `key_share` form (RFC 8446 §4.2.8): inside a
/// HelloRetryRequest the extension body is a bare `NamedGroup
/// selected_group` — two bytes, no share, no length prefix — because the
/// server is naming the group it wants a share IN, not supplying one.
///
/// Decoding this with `decodeKeyShareServerHello` would read the two bytes
/// after the group as a length and run off the end; they are not
/// interchangeable, which is why this exists as its own pair.
pub fn encodeKeyShareHelloRetryRequest(selected_group: u16, out: []u8) MessageError![]u8 {
    if (out.len < 2) return error.BufferTooShort;
    std.mem.writeInt(u16, out[0..2], selected_group, .big);
    return out[0..2];
}

/// Exact-length: a HelloRetryRequest `key_share` is two bytes and nothing
/// else. Anything longer is either the ServerHello form (a real share) in
/// the wrong message or a malformed extension — both must be refused rather
/// than silently truncated to the first two bytes.
pub fn decodeKeyShareHelloRetryRequest(data: []const u8) MessageError!u16 {
    if (data.len != 2) return error.Malformed;
    return std.mem.readInt(u16, data[0..2], .big);
}

// ── ClientHello (RFC 8446 §4.1.2, reused by DTLS 1.3 — RFC 9147 §5.3) ────

pub const ClientHello = struct {
    random: [32]u8,
    /// <= 32 bytes.
    legacy_session_id: []const u8,
    cipher_suites: []const u16,
    extensions: []const Extension,
};

/// DTLS's `legacy_cookie<0..2^8-1>`, which sits between `legacy_session_id`
/// and `cipher_suites` in the ClientHello and has no TLS counterpart (RFC
/// 9147 §5.3). DTLS 1.3 moved the cookie into a HelloRetryRequest extension
/// and requires the legacy field to be **present and empty** — a client that
/// drops the field entirely produces a body a real peer cannot parse, since
/// the next byte is then read as the first half of `cipher_suites`' length.
///
/// This module emitted no cookie field at all until a live wolfSSL 5.9.1 peer
/// answered our ClientHello with `alert(fatal, decode_error)`. Self-interop
/// could never have caught it: our own decoder omitted the field to match.
const legacy_cookie_len_bytes = 1;

pub fn encodeClientHello(ch: ClientHello, out: []u8) MessageError![]u8 {
    if (ch.legacy_session_id.len > 32) return error.Malformed;
    var i: usize = 0;
    if (out.len < 2 + 32 + 1) return error.BufferTooShort;
    out[0..2].* = legacy_version_dtls12;
    i = 2;
    @memcpy(out[i..][0..32], &ch.random);
    i += 32;

    if (out.len < i + 1 + ch.legacy_session_id.len) return error.BufferTooShort;
    out[i] = @intCast(ch.legacy_session_id.len);
    i += 1;
    @memcpy(out[i..][0..ch.legacy_session_id.len], ch.legacy_session_id);
    i += ch.legacy_session_id.len;

    // `legacy_cookie<0..2^8-1>` — always empty in DTLS 1.3, never absent.
    if (out.len < i + legacy_cookie_len_bytes) return error.BufferTooShort;
    out[i] = 0;
    i += legacy_cookie_len_bytes;

    const cs_len = ch.cipher_suites.len * 2;
    if (cs_len > std.math.maxInt(u16)) return error.ListTooLong;
    if (out.len < i + 2 + cs_len + 2) return error.BufferTooShort;
    std.mem.writeInt(u16, out[i..][0..2], @intCast(cs_len), .big);
    i += 2;
    for (ch.cipher_suites) |cs| {
        std.mem.writeInt(u16, out[i..][0..2], cs, .big);
        i += 2;
    }

    out[i] = 1; // legacy_compression_methods length
    out[i + 1] = 0; // "null" compression, the only value TLS 1.3/DTLS 1.3 allow
    i += 2;

    const ext_slice = try encodeExtensions(ch.extensions, out[i..]);
    i += ext_slice.len;
    return out[0..i];
}

pub const DecodedClientHello = struct {
    legacy_version: [2]u8,
    random: [32]u8,
    legacy_session_id: []const u8,
    /// Raw 2-bytes-per-entry (big-endian) blob — iterate with `CipherSuiteIter`.
    cipher_suites_raw: []const u8,
    extensions: []Extension,
};

pub const CipherSuiteIter = struct {
    raw: []const u8,
    pos: usize = 0,

    pub fn next(self: *CipherSuiteIter) ?u16 {
        if (self.pos + 2 > self.raw.len) return null;
        const v = std.mem.readInt(u16, self.raw[self.pos..][0..2], .big);
        self.pos += 2;
        return v;
    }
};

pub fn decodeClientHello(buf: []const u8, extensions_out: []Extension) MessageError!DecodedClientHello {
    if (buf.len < 2 + 32 + 1) return error.BufferTooShort;
    const legacy_version = buf[0..2].*;
    const random = buf[2..34].*;
    var i: usize = 34;

    const sid_len = buf[i];
    i += 1;
    if (sid_len > 32) return error.Malformed;
    if (buf.len < i + sid_len + 2) return error.BufferTooShort;
    const legacy_session_id = buf[i..][0..sid_len];
    i += sid_len;

    // `legacy_cookie<0..2^8-1>` (RFC 9147 §5.3). DTLS 1.3 requires it empty,
    // but a peer is free to send a non-empty one (e.g. a DTLS 1.2 client
    // retrying with a HelloVerifyRequest cookie); skip whatever is there
    // rather than assume the length byte is zero.
    if (buf.len < i + legacy_cookie_len_bytes) return error.BufferTooShort;
    const cookie_len = buf[i];
    i += legacy_cookie_len_bytes;
    if (buf.len < i + cookie_len + 2) return error.BufferTooShort;
    i += cookie_len;

    const cs_len: usize = std.mem.readInt(u16, buf[i..][0..2], .big);
    i += 2;
    if (cs_len % 2 != 0) return error.Malformed;
    if (buf.len < i + cs_len + 1) return error.BufferTooShort;
    const cipher_suites_raw = buf[i..][0..cs_len];
    i += cs_len;

    const comp_len = buf[i];
    i += 1;
    if (buf.len < i + comp_len) return error.BufferTooShort;
    i += comp_len;

    const extensions = try decodeExtensions(buf[i..], extensions_out);

    return .{
        .legacy_version = legacy_version,
        .random = random,
        .legacy_session_id = legacy_session_id,
        .cipher_suites_raw = cipher_suites_raw,
        .extensions = extensions,
    };
}

// ── ServerHello (RFC 8446 §4.1.3, reused by DTLS 1.3 — RFC 9147 §5.4) ────

pub const ServerHello = struct {
    random: [32]u8,
    /// <= 32 bytes; echoes the ClientHello's `legacy_session_id`.
    legacy_session_id_echo: []const u8,
    cipher_suite: u16,
    extensions: []const Extension,
};

pub fn encodeServerHello(sh: ServerHello, out: []u8) MessageError![]u8 {
    if (sh.legacy_session_id_echo.len > 32) return error.Malformed;
    var i: usize = 0;
    if (out.len < 2 + 32 + 1) return error.BufferTooShort;
    out[0..2].* = legacy_version_dtls12;
    i = 2;
    @memcpy(out[i..][0..32], &sh.random);
    i += 32;

    if (out.len < i + 1 + sh.legacy_session_id_echo.len + 2 + 1) return error.BufferTooShort;
    out[i] = @intCast(sh.legacy_session_id_echo.len);
    i += 1;
    @memcpy(out[i..][0..sh.legacy_session_id_echo.len], sh.legacy_session_id_echo);
    i += sh.legacy_session_id_echo.len;

    std.mem.writeInt(u16, out[i..][0..2], sh.cipher_suite, .big);
    i += 2;
    out[i] = 0; // legacy_compression_method
    i += 1;

    const ext_slice = try encodeExtensions(sh.extensions, out[i..]);
    i += ext_slice.len;
    return out[0..i];
}

pub const DecodedServerHello = struct {
    legacy_version: [2]u8,
    random: [32]u8,
    legacy_session_id_echo: []const u8,
    cipher_suite: u16,
    extensions: []Extension,
};

pub fn decodeServerHello(buf: []const u8, extensions_out: []Extension) MessageError!DecodedServerHello {
    if (buf.len < 2 + 32 + 1) return error.BufferTooShort;
    const legacy_version = buf[0..2].*;
    const random = buf[2..34].*;
    var i: usize = 34;

    const sid_len = buf[i];
    i += 1;
    if (sid_len > 32) return error.Malformed;
    if (buf.len < i + sid_len + 3) return error.BufferTooShort;
    const legacy_session_id_echo = buf[i..][0..sid_len];
    i += sid_len;

    const cipher_suite = std.mem.readInt(u16, buf[i..][0..2], .big);
    i += 2;
    i += 1; // skip legacy_compression_method

    const extensions = try decodeExtensions(buf[i..], extensions_out);

    return .{
        .legacy_version = legacy_version,
        .random = random,
        .legacy_session_id_echo = legacy_session_id_echo,
        .cipher_suite = cipher_suite,
        .extensions = extensions,
    };
}

// ── EncryptedExtensions (RFC 8446 §4.3.1) ────────────────────────────────

pub fn encodeEncryptedExtensions(exts: []const Extension, out: []u8) MessageError![]u8 {
    return encodeExtensions(exts, out);
}

pub fn decodeEncryptedExtensions(buf: []const u8, out: []Extension) MessageError![]Extension {
    return decodeExtensions(buf, out);
}

// ── Finished (RFC 8446 §4.4.4) ───────────────────────────────────────────

pub const Finished = struct {
    /// Opaque — crypto-core value (HMAC(finished_key, transcript_hash),
    /// RFC 8446 §4.4.4 / `keyschedule.zig`'s `computeFinishedVerifyData`).
    /// Length equals the negotiated hash's digest length (32 for SHA-256,
    /// 48 for SHA-384); the wrapping handshake header's `length` field is
    /// what tells a decoder how many bytes to expect, so this body carries
    /// no length prefix of its own.
    verify_data: []const u8,
};

pub fn encodeFinished(f: Finished, out: []u8) MessageError![]u8 {
    if (out.len < f.verify_data.len) return error.BufferTooShort;
    @memcpy(out[0..f.verify_data.len], f.verify_data);
    return out[0..f.verify_data.len];
}

pub fn decodeFinished(buf: []const u8) Finished {
    return .{ .verify_data = buf };
}

// ── u24 helpers (same wire shape as `handshake.zig`'s private ones — kept
// local here rather than exported from there, since the two files' u24
// fields mean different things: handshake.zig's are fragment offsets/
// lengths, these are certificate/list byte lengths) ──────────────────────

fn writeU24(out: *[3]u8, v: u24) void {
    out[0] = @truncate(v >> 16);
    out[1] = @truncate(v >> 8);
    out[2] = @truncate(v);
}

fn readU24(buf: *const [3]u8) u24 {
    return (@as(u24, buf[0]) << 16) | (@as(u24, buf[1]) << 8) | buf[2];
}

// ── Certificate (RFC 8446 §4.4.2, reused by DTLS 1.3 — RFC 9147 does not
// redefine it) ────────────────────────────────────────────────────────────
//
// struct {
//     opaque cert_data<1..2^24-1>;
//     Extension extensions<0..2^16-1>;
// } CertificateEntry;
// struct {
//     opaque certificate_request_context<0..2^8-1>;
//     CertificateEntry certificate_list<0..2^24-1>;
// } Certificate;
//
// Each `CertificateEntry`'s own extensions (OCSP stapling, SCT, ...) are OUT
// OF SCOPE: `encodeCertificate` always emits an empty extensions list per
// entry, and `decodeCertificate` validates their framing (length-prefix
// bounds-checked, never trusted blindly) but does not parse or surface their
// contents — this module has no use for them (see root.zig's "deferred"
// list).

pub const CertificateEntry = struct {
    cert_data: []const u8,
};

/// Encodes a `Certificate` message body: `context` (<= 255 bytes) followed
/// by `certs` (each a raw DER-encoded X.509 certificate, leaf first per RFC
/// 8446 §4.4.2), each wrapped as a `CertificateEntry` with an empty
/// extensions list.
pub fn encodeCertificate(context: []const u8, certs: []const []const u8, out: []u8) MessageError![]u8 {
    if (context.len > 255) return error.Malformed;
    if (out.len < 1 + context.len + 3) return error.BufferTooShort;
    var i: usize = 0;
    out[i] = @intCast(context.len);
    i += 1;
    @memcpy(out[i..][0..context.len], context);
    i += context.len;

    const list_len_pos = i;
    i += 3; // certificate_list<0..2^24-1> length, patched below
    const list_start = i;
    for (certs) |cert_data| {
        if (cert_data.len == 0 or cert_data.len > 0xFFFFFF) return error.Malformed;
        if (out.len < i + 3 + cert_data.len + 2) return error.BufferTooShort;
        writeU24(out[i..][0..3], @intCast(cert_data.len));
        i += 3;
        @memcpy(out[i..][0..cert_data.len], cert_data);
        i += cert_data.len;
        // Per-entry extensions<0..2^16-1>: always empty (see doc comment above).
        std.mem.writeInt(u16, out[i..][0..2], 0, .big);
        i += 2;
    }
    const list_len = i - list_start;
    if (list_len > 0xFFFFFF) return error.ListTooLong;
    writeU24(out[list_len_pos..][0..3], @intCast(list_len));
    return out[0..i];
}

pub const DecodedCertificate = struct {
    certificate_request_context: []const u8,
    entries: []CertificateEntry,
};

pub fn decodeCertificate(buf: []const u8, entries_out: []CertificateEntry) MessageError!DecodedCertificate {
    if (buf.len < 1) return error.BufferTooShort;
    const ctx_len = buf[0];
    if (buf.len < 1 + @as(usize, ctx_len) + 3) return error.BufferTooShort;
    const context = buf[1..][0..ctx_len];
    var i: usize = 1 + ctx_len;

    const list_len: usize = readU24(buf[i..][0..3]);
    i += 3;
    if (buf.len < i + list_len) return error.BufferTooShort;
    const list_end = i + list_len;

    var n: usize = 0;
    while (i < list_end) {
        if (i + 3 > list_end) return error.Malformed;
        const cert_len: usize = readU24(buf[i..][0..3]);
        i += 3;
        if (cert_len == 0 or i + cert_len + 2 > list_end) return error.Malformed;
        const cert_data = buf[i..][0..cert_len];
        i += cert_len;
        const ext_len: usize = std.mem.readInt(u16, buf[i..][0..2], .big);
        i += 2;
        if (i + ext_len > list_end) return error.Malformed;
        i += ext_len; // entry extensions: length-validated, contents discarded (see doc comment above)

        if (n >= entries_out.len) return error.TooManyCertificateEntries;
        entries_out[n] = .{ .cert_data = cert_data };
        n += 1;
    }
    if (i != list_end) return error.Malformed;

    return .{ .certificate_request_context = context, .entries = entries_out[0..n] };
}

// ── CertificateVerify (RFC 8446 §4.4.3) ──────────────────────────────────
//
// struct {
//     SignatureScheme algorithm;
//     opaque signature<0..2^16-1>;
// } CertificateVerify;
//
// `algorithm` is an opaque `u16` here (not `certverify.SignatureScheme`) —
// this file has no dependency on `certverify.zig`; the handshake state
// machine (`Connection.zig`) is what interprets the wire value against that
// enum. The signature bytes themselves are likewise opaque — this file only
// frames whatever `certverify.sign` produced.

pub const CertificateVerifyMsg = struct {
    algorithm: u16,
    signature: []const u8,
};

pub fn encodeCertificateVerify(msg: CertificateVerifyMsg, out: []u8) MessageError![]u8 {
    if (msg.signature.len > std.math.maxInt(u16)) return error.ListTooLong;
    if (out.len < 4 + msg.signature.len) return error.BufferTooShort;
    std.mem.writeInt(u16, out[0..2], msg.algorithm, .big);
    std.mem.writeInt(u16, out[2..4], @intCast(msg.signature.len), .big);
    @memcpy(out[4..][0..msg.signature.len], msg.signature);
    return out[0 .. 4 + msg.signature.len];
}

pub fn decodeCertificateVerify(buf: []const u8) MessageError!CertificateVerifyMsg {
    if (buf.len < 4) return error.BufferTooShort;
    const algorithm = std.mem.readInt(u16, buf[0..2], .big);
    const sig_len: usize = std.mem.readInt(u16, buf[2..4], .big);
    if (buf.len < 4 + sig_len) return error.Malformed;
    return .{ .algorithm = algorithm, .signature = buf[4..][0..sig_len] };
}

// ── CertificateRequest (RFC 8446 §4.3.2) ─────────────────────────────────
//
// struct {
//     opaque certificate_request_context<0..2^8-1>;
//     Extension extensions<2..2^16-1>;
// } CertificateRequest;
//
// RFC 8446 mandates a non-empty `extensions` list (MUST include
// `signature_algorithms`) for real interop; this module performs no
// signature_algorithms NEGOTIATION (see `Connection.zig`'s "deferred" list),
// so `encodeCertificateRequest` permits an empty list (matching this
// module's established "self-interop only" scope, not third-party interop).

pub const CertificateRequestMsg = struct {
    certificate_request_context: []const u8,
    extensions: []const Extension,
};

pub fn encodeCertificateRequest(msg: CertificateRequestMsg, out: []u8) MessageError![]u8 {
    if (msg.certificate_request_context.len > 255) return error.Malformed;
    if (out.len < 1 + msg.certificate_request_context.len) return error.BufferTooShort;
    var i: usize = 0;
    out[i] = @intCast(msg.certificate_request_context.len);
    i += 1;
    @memcpy(out[i..][0..msg.certificate_request_context.len], msg.certificate_request_context);
    i += msg.certificate_request_context.len;
    const ext_slice = try encodeExtensions(msg.extensions, out[i..]);
    i += ext_slice.len;
    return out[0..i];
}

pub fn decodeCertificateRequest(buf: []const u8, extensions_out: []Extension) MessageError!CertificateRequestMsg {
    if (buf.len < 1) return error.BufferTooShort;
    const ctx_len = buf[0];
    if (buf.len < 1 + @as(usize, ctx_len)) return error.BufferTooShort;
    const context = buf[1..][0..ctx_len];
    const extensions = try decodeExtensions(buf[1 + @as(usize, ctx_len) ..], extensions_out);
    return .{ .certificate_request_context = context, .extensions = extensions };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "hello_retry_request_random matches std's TLS 1.3 constant, 32 bytes" {
    try testing.expectEqual(@as(usize, 32), hello_retry_request_random.len);
    try testing.expectEqualSlices(u8, &std.crypto.tls.hello_retry_request_sequence, &hello_retry_request_random);
}

test "isHelloRetryRequest: true for the magic value, false otherwise" {
    try testing.expect(isHelloRetryRequest(hello_retry_request_random));
    try testing.expect(!isHelloRetryRequest([_]u8{0} ** 32));
}

test "extension list round-trip" {
    const exts = [_]Extension{
        .{ .ext_type = 44, .data = "cookie-bytes" },
        .{ .ext_type = 45, .data = &.{ 0, 1 } },
    };
    var buf: [64]u8 = undefined;
    const enc = try encodeExtensions(&exts, &buf);

    var out: [4]Extension = undefined;
    const dec = try decodeExtensions(enc, &out);
    try testing.expectEqual(@as(usize, 2), dec.len);
    try testing.expectEqual(@as(u16, 44), dec[0].ext_type);
    try testing.expectEqualSlices(u8, "cookie-bytes", dec[0].data);
    try testing.expectEqual(@as(u16, 45), dec[1].ext_type);
    try testing.expectEqualSlices(u8, &.{ 0, 1 }, dec[1].data);
}

test "extension list: too many for caller's buffer" {
    const exts = [_]Extension{
        .{ .ext_type = 1, .data = "" },
        .{ .ext_type = 2, .data = "" },
    };
    var buf: [16]u8 = undefined;
    const enc = try encodeExtensions(&exts, &buf);
    var out: [1]Extension = undefined;
    try testing.expectError(error.TooManyExtensions, decodeExtensions(enc, &out));
}

test "extension list: a repeated extension type is rejected (RFC 8446 §4.2 illegal_parameter)" {
    // Two `key_share` (51) extensions, exactly as an attacker appending to a
    // ClientHello would produce them. Accepting this block made "which copy
    // wins" a per-consumer accident: first-wins in `clientHelloShare`/
    // `serverHelloShare`, last-wins for `pre_shared_key`, the HRR `cookie`
    // and `signature_algorithms`.
    const dup = [_]Extension{
        .{ .ext_type = 51, .data = "first-copy" },
        .{ .ext_type = 51, .data = "second-copy" },
    };
    var buf: [128]u8 = undefined;
    const enc = try encodeExtensions(&dup, &buf);
    var out: [8]Extension = undefined;
    try testing.expectError(error.DuplicateExtension, decodeExtensions(enc, &out));

    // Non-adjacent duplicates too — a scan that only compared with the
    // previous entry would miss this one.
    const spread = [_]Extension{
        .{ .ext_type = 43, .data = "supported_versions" },
        .{ .ext_type = 13, .data = "signature_algorithms" },
        .{ .ext_type = 43, .data = "supported_versions again" },
    };
    const enc2 = try encodeExtensions(&spread, &buf);
    try testing.expectError(error.DuplicateExtension, decodeExtensions(enc2, &out));

    // ...and a block of DISTINCT types is unaffected (this is a rejection of
    // duplicates, not of extension blocks).
    const distinct = [_]Extension{
        .{ .ext_type = 43, .data = "a" },
        .{ .ext_type = 13, .data = "b" },
        .{ .ext_type = 51, .data = "c" },
        .{ .ext_type = 41, .data = "d" },
    };
    const enc3 = try encodeExtensions(&distinct, &buf);
    try testing.expectEqual(@as(usize, 4), (try decodeExtensions(enc3, &out)).len);
}

test "ClientHello with a duplicated extension is rejected by the decoder the handshake uses" {
    // The same check as it is actually reached on the wire — through
    // `decodeClientHello`, the first thing a server does with an
    // unauthenticated datagram.
    const dup = [_]Extension{
        .{ .ext_type = @intFromEnum(ExtensionType.supported_versions), .data = &.{ 2, 0xFE, 0xFC } },
        .{ .ext_type = @intFromEnum(ExtensionType.supported_versions), .data = &.{ 2, 0xFE, 0xFD } },
    };
    var ch_buf: [256]u8 = undefined;
    const ch = try encodeClientHello(.{
        .random = [_]u8{0x11} ** 32,
        .legacy_session_id = &.{},
        .cipher_suites = &.{0x1301},
        .extensions = &dup,
    }, &ch_buf);

    var out: [8]Extension = undefined;
    try testing.expectError(error.DuplicateExtension, decodeClientHello(ch, &out));
}

test "cookie extension round-trip" {
    var buf: [32]u8 = undefined;
    const enc = try encodeCookieExtension("a-stateless-cookie", &buf);
    const dec = try decodeCookieExtension(enc);
    try testing.expectEqualSlices(u8, "a-stateless-cookie", dec);
}

test "psk_key_exchange_modes round-trip" {
    const modes = [_]PskKeyExchangeMode{ .psk_ke, .psk_dhe_ke };
    var buf: [8]u8 = undefined;
    const enc = try encodePskKeyExchangeModes(&modes, &buf);
    try testing.expectEqualSlices(u8, &.{ 2, 0, 1 }, enc);

    var out: [4]PskKeyExchangeMode = undefined;
    const dec = try decodePskKeyExchangeModes(enc, &out);
    try testing.expectEqualSlices(PskKeyExchangeMode, &modes, dec);
}

test "OfferedPsks round-trip with opaque binders" {
    const identities = [_]PskIdentity{
        .{ .identity = "device-042", .obfuscated_ticket_age = 0 },
    };
    const binder = [_]u8{0xAB} ** 32; // opaque; real value is crypto-core
    const binders = [_][]const u8{&binder};
    const psks = OfferedPsks{ .identities = &identities, .binders = &binders };

    var buf: [128]u8 = undefined;
    const enc = try encodeOfferedPsks(psks, &buf);

    var ids_out: [4]PskIdentity = undefined;
    var binders_out: [4][]const u8 = undefined;
    const dec = try decodeOfferedPsks(enc, &ids_out, &binders_out);
    try testing.expectEqual(@as(usize, 1), dec.identities.len);
    try testing.expectEqualSlices(u8, "device-042", dec.identities[0].identity);
    try testing.expectEqual(@as(u32, 0), dec.identities[0].obfuscated_ticket_age);
    try testing.expectEqual(@as(usize, 1), dec.binders.len);
    try testing.expectEqualSlices(u8, &binder, dec.binders[0]);
}

test "selected identity round-trip" {
    var buf: [2]u8 = undefined;
    encodeSelectedIdentity(3, &buf);
    try testing.expectEqual(@as(u16, 3), decodeSelectedIdentity(&buf));
}

test "ClientHello round-trip incl. cipher-suite iteration" {
    const exts = [_]Extension{.{ .ext_type = 45, .data = &.{0} }};
    const ch = ClientHello{
        .random = [_]u8{0x11} ** 32,
        .legacy_session_id = &.{},
        .cipher_suites = &.{ 0x1304, 0x1305 }, // AES_128_CCM_SHA256, AES_128_CCM_8_SHA256
        .extensions = &exts,
    };
    var buf: [128]u8 = undefined;
    const enc = try encodeClientHello(ch, &buf);

    var ext_out: [4]Extension = undefined;
    const dec = try decodeClientHello(enc, &ext_out);
    try testing.expectEqual(legacy_version_dtls12, dec.legacy_version);
    try testing.expectEqualSlices(u8, &ch.random, &dec.random);
    try testing.expectEqual(@as(usize, 0), dec.legacy_session_id.len);

    var iter = CipherSuiteIter{ .raw = dec.cipher_suites_raw };
    try testing.expectEqual(@as(u16, 0x1304), iter.next().?);
    try testing.expectEqual(@as(u16, 0x1305), iter.next().?);
    try testing.expectEqual(@as(?u16, null), iter.next());

    try testing.expectEqual(@as(usize, 1), dec.extensions.len);
    try testing.expectEqual(@as(u16, 45), dec.extensions[0].ext_type);
}

test "ServerHello round-trip and HelloRetryRequest detection" {
    const sh = ServerHello{
        .random = [_]u8{0x22} ** 32,
        .legacy_session_id_echo = &.{ 1, 2, 3 },
        .cipher_suite = 0x1305,
        .extensions = &.{},
    };
    var buf: [128]u8 = undefined;
    const enc = try encodeServerHello(sh, &buf);

    var ext_out: [4]Extension = undefined;
    const dec = try decodeServerHello(enc, &ext_out);
    try testing.expectEqualSlices(u8, &sh.random, &dec.random);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, dec.legacy_session_id_echo);
    try testing.expectEqual(sh.cipher_suite, dec.cipher_suite);
    try testing.expect(!isHelloRetryRequest(dec.random));

    const hrr = ServerHello{
        .random = hello_retry_request_random,
        .legacy_session_id_echo = &.{},
        .cipher_suite = 0x1305,
        .extensions = &.{},
    };
    var hrr_buf: [128]u8 = undefined;
    const hrr_enc = try encodeServerHello(hrr, &hrr_buf);
    var hrr_ext_out: [4]Extension = undefined;
    const hrr_dec = try decodeServerHello(hrr_enc, &hrr_ext_out);
    try testing.expect(isHelloRetryRequest(hrr_dec.random));
}

test "EncryptedExtensions round-trip" {
    const exts = [_]Extension{.{ .ext_type = 0, .data = "example.iot" }};
    var buf: [64]u8 = undefined;
    const enc = try encodeEncryptedExtensions(&exts, &buf);
    var out: [4]Extension = undefined;
    const dec = try decodeEncryptedExtensions(enc, &out);
    try testing.expectEqual(@as(usize, 1), dec.len);
    try testing.expectEqualSlices(u8, "example.iot", dec[0].data);
}

test "Finished round-trip (opaque verify_data)" {
    const verify_data = [_]u8{0xEE} ** 32; // opaque; real value is crypto-core
    var buf: [32]u8 = undefined;
    const enc = try encodeFinished(.{ .verify_data = &verify_data }, &buf);
    const dec = decodeFinished(enc);
    try testing.expectEqualSlices(u8, &verify_data, dec.verify_data);
}

// ── Certificate / CertificateVerify / CertificateRequest (cert-mode) ────

test "Certificate round-trip: single entry, empty context" {
    const cert_a = "fake-DER-bytes-of-a-certificate-not-really-x509";
    var buf: [128]u8 = undefined;
    const enc = try encodeCertificate(&.{}, &.{cert_a}, &buf);

    var entries_out: [4]CertificateEntry = undefined;
    const dec = try decodeCertificate(enc, &entries_out);
    try testing.expectEqual(@as(usize, 0), dec.certificate_request_context.len);
    try testing.expectEqual(@as(usize, 1), dec.entries.len);
    try testing.expectEqualSlices(u8, cert_a, dec.entries[0].cert_data);
}

test "Certificate round-trip: multiple entries, non-empty context" {
    const leaf = "leaf-cert-bytes";
    const intermediate = "intermediate-cert-bytes-a-bit-longer";
    var buf: [256]u8 = undefined;
    const enc = try encodeCertificate("req-ctx", &.{ leaf, intermediate }, &buf);

    var entries_out: [4]CertificateEntry = undefined;
    const dec = try decodeCertificate(enc, &entries_out);
    try testing.expectEqualSlices(u8, "req-ctx", dec.certificate_request_context);
    try testing.expectEqual(@as(usize, 2), dec.entries.len);
    try testing.expectEqualSlices(u8, leaf, dec.entries[0].cert_data);
    try testing.expectEqualSlices(u8, intermediate, dec.entries[1].cert_data);
}

test "Certificate round-trip: empty certificate_list (RFC 8446 §4.4.2 'no certificate' answer)" {
    var buf: [16]u8 = undefined;
    const enc = try encodeCertificate("ctx", &.{}, &buf);
    var entries_out: [4]CertificateEntry = undefined;
    const dec = try decodeCertificate(enc, &entries_out);
    try testing.expectEqualSlices(u8, "ctx", dec.certificate_request_context);
    try testing.expectEqual(@as(usize, 0), dec.entries.len);
}

test "Certificate decode: too many entries for caller's buffer is a typed error" {
    var buf: [64]u8 = undefined;
    const enc = try encodeCertificate(&.{}, &.{ "a", "b", "c" }, &buf);
    var entries_out: [2]CertificateEntry = undefined;
    try testing.expectError(error.TooManyCertificateEntries, decodeCertificate(enc, &entries_out));
}

test "Certificate decode: buffer shorter than the declared certificate_list is a typed error" {
    var buf: [64]u8 = undefined;
    const enc = try encodeCertificate(&.{}, &.{"hello-cert"}, &buf);
    var truncated = enc;
    truncated.len -= 3; // chop off the tail (part of cert_data + extensions length)
    var entries_out: [4]CertificateEntry = undefined;
    try testing.expectError(error.BufferTooShort, decodeCertificate(truncated, &entries_out));
}

test "Certificate decode: internally inconsistent cert_data length is a typed error, never a panic" {
    // A cert_data length that overruns the (still-fully-present) declared
    // certificate_list -- the "peer is lying about an inner length, not
    // just handing us a short buffer" case, distinct from the BufferTooShort
    // test above.
    var buf: [64]u8 = undefined;
    const enc = try encodeCertificate(&.{}, &.{"hello-cert"}, &buf);
    var corrupted: [64]u8 = undefined;
    @memcpy(corrupted[0..enc.len], enc);
    // Byte layout: [0]=ctx_len(0), [1..4)=list_len(u24), [4..7)=cert_len(u24),
    // [7..]=cert_data. Inflate cert_len far beyond what's actually present.
    corrupted[6] = 0xFF;
    var entries_out: [4]CertificateEntry = undefined;
    try testing.expectError(error.Malformed, decodeCertificate(corrupted[0..enc.len], &entries_out));
}

test "CertificateVerify round-trip (opaque algorithm + signature)" {
    const sig = [_]u8{0x77} ** 64; // opaque; real value is certverify.sign's output
    var buf: [128]u8 = undefined;
    const enc = try encodeCertificateVerify(.{ .algorithm = 0x0403, .signature = &sig }, &buf);
    const dec = try decodeCertificateVerify(enc);
    try testing.expectEqual(@as(u16, 0x0403), dec.algorithm);
    try testing.expectEqualSlices(u8, &sig, dec.signature);
}

test "CertificateVerify decode: buffer too short is a typed error" {
    const buf = [_]u8{ 0x04, 0x03, 0x00 }; // declares a 2-byte header but only 1 more byte
    try testing.expectError(error.BufferTooShort, decodeCertificateVerify(&buf));
}

test "CertificateVerify decode: declared signature length exceeds buffer is a typed error" {
    const buf = [_]u8{ 0x04, 0x03, 0x00, 0x10 }; // claims a 16-byte signature, has 0
    try testing.expectError(error.Malformed, decodeCertificateVerify(&buf));
}

test "CertificateRequest round-trip" {
    const exts = [_]Extension{.{ .ext_type = 13, .data = &.{ 0, 4, 0x04, 0x03, 0x08, 0x04 } }}; // signature_algorithms
    var buf: [64]u8 = undefined;
    const enc = try encodeCertificateRequest(.{ .certificate_request_context = "ctx-bytes", .extensions = &exts }, &buf);

    var ext_out: [4]Extension = undefined;
    const dec = try decodeCertificateRequest(enc, &ext_out);
    try testing.expectEqualSlices(u8, "ctx-bytes", dec.certificate_request_context);
    try testing.expectEqual(@as(usize, 1), dec.extensions.len);
    try testing.expectEqual(@as(u16, 13), dec.extensions[0].ext_type);
}

test "CertificateRequest round-trip: empty context and extensions" {
    var buf: [16]u8 = undefined;
    const enc = try encodeCertificateRequest(.{ .certificate_request_context = &.{}, .extensions = &.{} }, &buf);
    var ext_out: [4]Extension = undefined;
    const dec = try decodeCertificateRequest(enc, &ext_out);
    try testing.expectEqual(@as(usize, 0), dec.certificate_request_context.len);
    try testing.expectEqual(@as(usize, 0), dec.extensions.len);
}

// ── key_share / supported_groups / signature_algorithms (cert-DHE mode) ──

test "supported_groups / signature_algorithms u16-list round-trip" {
    const groups = [_]u16{ @intFromEnum(NamedGroup.x25519), @intFromEnum(NamedGroup.secp256r1) };
    var buf: [16]u8 = undefined;
    const enc = try encodeSupportedGroups(&groups, &buf);
    // 2-byte outer length (4) + two u16s.
    try testing.expectEqualSlices(u8, &.{ 0, 4, 0x00, 0x1d, 0x00, 0x17 }, enc);
    var out: [4]u16 = undefined;
    const dec = try decodeU16ListExtension(enc, &out);
    try testing.expectEqualSlices(u16, &groups, dec);
}

test "signature_algorithms odd-length body is a typed error" {
    const bad = [_]u8{ 0, 3, 0x08, 0x04, 0x08 }; // declares 3 body bytes (odd)
    var out: [4]u16 = undefined;
    try testing.expectError(error.Malformed, decodeU16ListExtension(&bad, &out));
}

test "key_share ClientHello round-trip (x25519 32-byte share)" {
    const share = [_]u8{0xAB} ** 32;
    const entries = [_]KeyShareEntry{.{ .group = @intFromEnum(NamedGroup.x25519), .key_exchange = &share }};
    var buf: [64]u8 = undefined;
    const enc = try encodeKeyShareClientHello(&entries, &buf);

    var out: [4]KeyShareEntry = undefined;
    const dec = try decodeKeyShareClientHello(enc, &out);
    try testing.expectEqual(@as(usize, 1), dec.len);
    try testing.expectEqual(@as(u16, 0x001d), dec[0].group);
    try testing.expectEqualSlices(u8, &share, dec[0].key_exchange);
}

test "key_share ClientHello: multiple entries decode independently" {
    const s1 = [_]u8{0x11} ** 32;
    const s2 = [_]u8{0x22} ** 65; // secp256r1 uncompressed point size
    const entries = [_]KeyShareEntry{
        .{ .group = 0x001d, .key_exchange = &s1 },
        .{ .group = 0x0017, .key_exchange = &s2 },
    };
    var buf: [160]u8 = undefined;
    const enc = try encodeKeyShareClientHello(&entries, &buf);
    var out: [4]KeyShareEntry = undefined;
    const dec = try decodeKeyShareClientHello(enc, &out);
    try testing.expectEqual(@as(usize, 2), dec.len);
    try testing.expectEqualSlices(u8, &s1, dec[0].key_exchange);
    try testing.expectEqualSlices(u8, &s2, dec[1].key_exchange);
}

test "key_share ServerHello round-trip (single bare entry, no list prefix)" {
    const share = [_]u8{0xCD} ** 32;
    var buf: [64]u8 = undefined;
    const enc = try encodeKeyShareServerHello(.{ .group = 0x001d, .key_exchange = &share }, &buf);
    // group(2) + len(2) + 32 = 36 bytes, no outer list length.
    try testing.expectEqual(@as(usize, 36), enc.len);
    const dec = try decodeKeyShareServerHello(enc);
    try testing.expectEqual(@as(u16, 0x001d), dec.group);
    try testing.expectEqualSlices(u8, &share, dec.key_exchange);
}

test "key_share HelloRetryRequest form: exactly two bytes, and NOT interchangeable with the ServerHello form" {
    var buf: [8]u8 = undefined;
    const enc = try encodeKeyShareHelloRetryRequest(@intFromEnum(NamedGroup.secp256r1), &buf);
    try testing.expectEqual(@as(usize, 2), enc.len);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x17 }, enc);
    try testing.expectEqual(@as(u16, 0x0017), try decodeKeyShareHelloRetryRequest(enc));

    // The two forms must not be confusable. A real ServerHello key_share
    // (group + length + share) fed to the HRR decoder is rejected outright
    // rather than silently read as "selected_group = x25519": a decoder that
    // took only the first two bytes would turn a server's real share into a
    // group name and the client would retry against a group the server never
    // asked for.
    const share = [_]u8{0xCD} ** 32;
    var sh_buf: [64]u8 = undefined;
    const sh_form = try encodeKeyShareServerHello(.{ .group = 0x001d, .key_exchange = &share }, &sh_buf);
    try testing.expectError(error.Malformed, decodeKeyShareHelloRetryRequest(sh_form));
    // ...and in the other direction the HRR form has no share to hand back.
    try testing.expectError(error.BufferTooShort, decodeKeyShareServerHello(enc));
}

test "key_share ClientHello: inner length overrunning the list is a typed error, never a panic" {
    const share = [_]u8{0xAB} ** 32;
    const entries = [_]KeyShareEntry{.{ .group = 0x001d, .key_exchange = &share }};
    var buf: [64]u8 = undefined;
    const enc = try encodeKeyShareClientHello(&entries, &buf);
    var corrupted: [64]u8 = undefined;
    @memcpy(corrupted[0..enc.len], enc);
    // Byte layout: [0..2)=list_len, [2..4)=group, [4..6)=key_len. Inflate the
    // key length past the still-fully-present list.
    corrupted[5] = 0xFF;
    var out: [4]KeyShareEntry = undefined;
    try testing.expectError(error.Malformed, decodeKeyShareClientHello(corrupted[0..enc.len], &out));
}

test "HandshakeType: RFC 8446 §4 wire code points for the cert-mode types" {
    try testing.expectEqual(@as(u8, 11), @intFromEnum(HandshakeType.certificate));
    try testing.expectEqual(@as(u8, 13), @intFromEnum(HandshakeType.certificate_request));
    try testing.expectEqual(@as(u8, 15), @intFromEnum(HandshakeType.certificate_verify));
}

// ── fuzz: handshake message bodies off the wire, never panic ───────────────
//
// Every function in this file decodes a DTLS 1.3 handshake message BODY —
// received from an unauthenticated peer (the record/handshake-fragmentation
// layers above only reassemble bytes; these are what interpret them).
// `decodeClientHello`/`decodeServerHello`/`decodeCertificate` are the three
// highest-value targets: build a structurally valid message via the
// existing `encode*` counterpart (so the fuzzer reaches every field
// extraction instead of bouncing off the first length check), then
// sometimes flip one byte to probe the bounds-checked paths against a
// message that looks valid until one field disagrees. The remaining
// extension-family sub-decoders have no magic-number gate at all (only
// length fields), so plain random bytes at a plausible length already
// reach their interior loops.

test "fuzz: decodeClientHello never panics on a structurally-plausible, possibly-mutated message" {
    try testing.fuzz({}, fuzzDecodeClientHello, .{});
}

fn fuzzDecodeClientHello(_: void, smith: *std.testing.Smith) !void {
    var random: [32]u8 = undefined;
    smith.bytes(&random);
    var sid_buf: [32]u8 = undefined;
    const sid_len = smith.valueRangeAtMost(u8, 0, 32);
    smith.bytes(sid_buf[0..sid_len]);

    var cs_buf: [32]u16 = undefined;
    const n_cs = smith.valueRangeAtMost(u8, 0, cs_buf.len);
    for (cs_buf[0..n_cs]) |*c| c.* = smith.value(u16);

    var ext_data: [4][32]u8 = undefined;
    var exts: [4]Extension = undefined;
    const n_ext = smith.valueRangeAtMost(u8, 0, 4);
    for (0..n_ext) |k| {
        const dl = smith.valueRangeAtMost(u8, 0, 32);
        smith.bytes(ext_data[k][0..dl]);
        exts[k] = .{ .ext_type = smith.value(u16), .data = ext_data[k][0..dl] };
    }

    const ch = ClientHello{
        .random = random,
        .legacy_session_id = sid_buf[0..sid_len],
        .cipher_suites = cs_buf[0..n_cs],
        .extensions = exts[0..n_ext],
    };
    var wire: [1024]u8 = undefined;
    const enc = encodeClientHello(ch, &wire) catch return;
    if (enc.len > 0 and smith.boolWeighted(1, 2)) {
        wire[smith.index(enc.len)] = smith.value(u8);
    }

    var out: [8]Extension = undefined;
    _ = decodeClientHello(enc, &out) catch return;
}

test "fuzz: decodeServerHello never panics on a structurally-plausible, possibly-mutated message" {
    try testing.fuzz({}, fuzzDecodeServerHello, .{});
}

fn fuzzDecodeServerHello(_: void, smith: *std.testing.Smith) !void {
    var random: [32]u8 = undefined;
    smith.bytes(&random);
    var sid_buf: [32]u8 = undefined;
    const sid_len = smith.valueRangeAtMost(u8, 0, 32);
    smith.bytes(sid_buf[0..sid_len]);

    var ext_data: [4][32]u8 = undefined;
    var exts: [4]Extension = undefined;
    const n_ext = smith.valueRangeAtMost(u8, 0, 4);
    for (0..n_ext) |k| {
        const dl = smith.valueRangeAtMost(u8, 0, 32);
        smith.bytes(ext_data[k][0..dl]);
        exts[k] = .{ .ext_type = smith.value(u16), .data = ext_data[k][0..dl] };
    }

    const sh = ServerHello{
        .random = random,
        .legacy_session_id_echo = sid_buf[0..sid_len],
        .cipher_suite = smith.value(u16),
        .extensions = exts[0..n_ext],
    };
    var wire: [1024]u8 = undefined;
    const enc = encodeServerHello(sh, &wire) catch return;
    if (enc.len > 0 and smith.boolWeighted(1, 2)) {
        wire[smith.index(enc.len)] = smith.value(u8);
    }

    var out: [8]Extension = undefined;
    _ = decodeServerHello(enc, &out) catch return;
}

test "fuzz: decodeCertificate never panics on a structurally-plausible, possibly-mutated message" {
    try testing.fuzz({}, fuzzDecodeCertificate, .{});
}

fn fuzzDecodeCertificate(_: void, smith: *std.testing.Smith) !void {
    var ctx_buf: [64]u8 = undefined;
    const ctx_len = smith.valueRangeAtMost(u8, 0, 64);
    smith.bytes(ctx_buf[0..ctx_len]);

    var cert_bufs: [4][128]u8 = undefined;
    var certs: [4][]const u8 = undefined;
    const n_certs = smith.valueRangeAtMost(u8, 0, 4);
    for (0..n_certs) |k| {
        const cl = smith.valueRangeAtMost(u8, 1, 128);
        smith.bytes(cert_bufs[k][0..cl]);
        certs[k] = cert_bufs[k][0..cl];
    }

    var wire: [1024]u8 = undefined;
    const enc = encodeCertificate(ctx_buf[0..ctx_len], certs[0..n_certs], &wire) catch return;
    if (enc.len > 0 and smith.boolWeighted(1, 2)) {
        wire[smith.index(enc.len)] = smith.value(u8);
    }

    var out: [8]CertificateEntry = undefined;
    _ = decodeCertificate(enc, &out) catch return;
}

test "fuzz: decodeExtensions never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeExtensions, .{});
}

fn fuzzDecodeExtensions(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var out: [16]Extension = undefined;
    _ = decodeExtensions(buf[0..len], &out) catch return;
}

test "fuzz: decodeCookieExtension never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeCookieExtension, .{});
}

fn fuzzDecodeCookieExtension(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = decodeCookieExtension(buf[0..len]) catch return;
}

test "fuzz: decodePskKeyExchangeModes never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodePskModes, .{});
}

fn fuzzDecodePskModes(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var out: [256]PskKeyExchangeMode = undefined;
    _ = decodePskKeyExchangeModes(buf[0..len], &out) catch return;
}

test "fuzz: decodeOfferedPsks never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeOfferedPsks, .{});
}

fn fuzzDecodeOfferedPsks(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var ids: [16]PskIdentity = undefined;
    var binders: [16][]const u8 = undefined;
    _ = decodeOfferedPsks(buf[0..len], &ids, &binders) catch return;
}

test "fuzz: decodeU16ListExtension never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeU16List, .{});
}

fn fuzzDecodeU16List(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var out: [128]u16 = undefined;
    _ = decodeU16ListExtension(buf[0..len], &out) catch return;
}

test "fuzz: decodeKeyShareClientHello never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeKeyShareClientHello, .{});
}

fn fuzzDecodeKeyShareClientHello(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var out: [16]KeyShareEntry = undefined;
    _ = decodeKeyShareClientHello(buf[0..len], &out) catch return;
}

test "fuzz: decodeKeyShareServerHello never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeKeyShareServerHello, .{});
}

fn fuzzDecodeKeyShareServerHello(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = decodeKeyShareServerHello(buf[0..len]) catch return;
}

test "fuzz: decodeCertificateVerify never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeCertificateVerify, .{});
}

fn fuzzDecodeCertificateVerify(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = decodeCertificateVerify(buf[0..len]) catch return;
}

test "fuzz: decodeCertificateRequest never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeCertificateRequest, .{});
}

fn fuzzDecodeCertificateRequest(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var out: [16]Extension = undefined;
    _ = decodeCertificateRequest(buf[0..len], &out) catch return;
}
