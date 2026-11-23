// SPDX-License-Identifier: MIT

//! IS-IS Authentication TLV (#10): the typed value, the placeholder a builder
//! emits, and HMAC compute (`sign`) / verify over a whole PDU.
//!
//! | Auth type | Value after the type octet            | Source                 |
//! |-----------|---------------------------------------|------------------------|
//! | 1         | cleartext password                    | ISO/IEC 10589 §9.5     |
//! | 54        | 16-octet HMAC-MD5                     | RFC 5304 §2            |
//! | 3         | Key ID (2) + HMAC-SHA-1/224/256/384/512 | RFC 5310 §3.1        |
//!
//! ## What the digest covers
//!
//! The whole PDU, `[0, PDU Length)`, with these fields replaced by constants
//! while hashing (the wire bytes are not touched):
//!
//! - the Authentication Value: zeros for HMAC-MD5 (RFC 5304 §2: "with the
//!   Authentication Value field ... set to zero"), `Apad` = 0x878FE1F3
//!   repeated L/4 times for RFC 5310 (§3.3, §3.5);
//! - in an LSP, Remaining Lifetime and Checksum: zeros (RFC 5304 §2, RFC 5310
//!   §3.4/§3.5), so routers in between can age the LSP and the checksum can
//!   be computed over the finished digest.
//!
//! Hellos are hashed as sent, padding TLVs included (RFC 5310 §3.2: "after
//! the PDU is padded to the MTU size"): the caller signs the final bytes.
//!
//! ## Key preparation (RFC 5310)
//!
//! RFC 5310 §3.3 sets `Ko = H(K)` for a key longer than the hash OUTPUT
//! length L. Deployed routers do not: plain RFC 2104 HMAC (hash only a key
//! longer than the block size B) is what holo-isis (`auth.rs`, the `hmac`
//! crate), Cisco IOS XR, Arista EOS and FRR isisd by default do (FRR pull
//! request 23715, which also reports an IOS XR hello signed with a 22-octet
//! HMAC-SHA-1 key that verified only with plain HMAC). The RFC 5709 erratum
//! proposes the same block-size reading for OSPF's identical text. So the
//! default here is plain RFC 2104, and `Key.strict_rfc5310` selects the
//! §3.3 rule (FRR's `strict-rfc5310`). The two agree for every key of at most
//! L octets; they differ only for L < |K| <= B.
//!
//! ## Receive side
//!
//! `verify` finds the first Authentication TLV (a second one is ordinary
//! hashed payload, as in holo-isis, which skips duplicates), picks the key and
//! compares in constant time. HMAC-MD5 and cleartext try every configured key
//! of that type (RFC 5304 §2: "MAY check a set of passwords"); RFC 5310 picks
//! the key by Key ID (§3.5). A missing TLV, an unknown key, an unknown type
//! and a wrong value are distinct errors (holo: `AuthTypeMismatch`,
//! `AuthKeyNotFound`, `AuthError`); what to do with each is the caller's
//! policy — `isis-adj` and `isis-lsdb` discard the PDU on all of them.
//!
//! Cleartext (type 1) is supported in both directions, as in holo-isis and
//! FRR, but it is not authentication against anyone who can read the link:
//! the password travels in the clear and anyone who saw one PDU can forge
//! the next. Choose it only for interop with a peer that offers nothing else.
//!
//! No replay protection: neither RFC provides any (RFC 5310 §4).
//!
//! Provenance: clean-room from RFC 5304 and RFC 5310; the behaviour choices
//! were checked against holo-isis `packet/auth.rs` and `packet/pdu.rs`
//! (MIT) and FRR documentation and pull-request text (no FRR source read).

const std = @import("std");
const burn = @import("burn.zig");

/// Bytes zeroed below `sign`, `verify` and `addPlaceholder`: the HMAC frames
/// (SHA-512 the deepest) and the 255-byte TLV value buffer. Sized from
/// `stackprobe_test.zig`.
const auth_burn = 4 * 1024;
const header = @import("header.zig");
const tlv = @import("tlv.zig");
const pdu = @import("pdu.zig");

const hmac = std.crypto.auth.hmac;
const timing_safe = std.crypto.timing_safe;

/// TLV code of the Authentication TLV (ISO 10589 §9.5).
pub const tlv_code: u8 = 10;

/// Authentication Type octets.
pub const auth_type = struct {
    pub const cleartext: u8 = 1;
    /// RFC 5310 generic cryptographic authentication.
    pub const crypto: u8 = 3;
    /// RFC 5304 HMAC-MD5 (0x36).
    pub const hmac_md5: u8 = 54;
};

/// RFC 5310 §3.3: "Apad is the hexadecimal value 0x878FE1F3 repeated (L/4)
/// times." The longest L is 64 (SHA-512).
const apad_word = [4]u8{ 0x87, 0x8F, 0xE1, 0xF3 };
const apad: [64]u8 = blk: {
    var a: [64]u8 = undefined;
    for (&a, 0..) |*b, i| b.* = apad_word[i % 4];
    break :blk a;
};

const zeros: [64]u8 = @splat(0);

/// The longest digest any algorithm here produces (HMAC-SHA-512).
pub const max_digest_len: usize = 64;

pub const Algorithm = enum {
    cleartext,
    /// RFC 5304, auth type 54.
    hmac_md5,
    /// RFC 5310, auth type 3, with a Key ID.
    hmac_sha1,
    hmac_sha224,
    hmac_sha256,
    hmac_sha384,
    hmac_sha512,

    /// The Authentication Type octet this algorithm is carried under.
    pub fn authType(a: Algorithm) u8 {
        return switch (a) {
            .cleartext => auth_type.cleartext,
            .hmac_md5 => auth_type.hmac_md5,
            .hmac_sha1, .hmac_sha224, .hmac_sha256, .hmac_sha384, .hmac_sha512 => auth_type.crypto,
        };
    }

    /// Digest length L in octets; 0 for cleartext (its value is the password).
    pub fn digestLen(a: Algorithm) usize {
        return switch (a) {
            .cleartext => 0,
            .hmac_md5 => 16,
            .hmac_sha1 => 20,
            .hmac_sha224 => 28,
            .hmac_sha256 => 32,
            .hmac_sha384 => 48,
            .hmac_sha512 => 64,
        };
    }
};

/// One configured key.
///
/// `secret` is caller-owned (CONVENTIONS §2.1 Z2): this module copies it into
/// nothing that outlives a call, and the caller must `std.crypto.secureZero`
/// its storage when the key is retired.
pub const Key = struct {
    algorithm: Algorithm,
    /// RFC 5310 Key ID (§2); on the wire only for the SHA family, ignored for
    /// HMAC-MD5 and cleartext.
    id: u16 = 0,
    /// The password (cleartext) or the HMAC key.
    secret: []const u8,
    /// RFC 5310 §3.3 key preparation (`Ko = H(K)` for a key longer than L)
    /// instead of plain RFC 2104 HMAC. Only matters for the SHA family and a
    /// key with L < len <= block size; see the file comment for why the
    /// default is off.
    strict_rfc5310: bool = false,
};

/// A decoded Authentication TLV value. Every slice is a subslice of the input.
pub const Tlv = union(enum) {
    cleartext: []const u8,
    hmac_md5: *const [16]u8,
    crypto: struct { key_id: u16, digest: []const u8 },
    /// An authentication type this module does not model (0, 255 = routing
    /// domain private, anything unassigned); `value` follows the type octet.
    other: struct { auth_type: u8, value: []const u8 },
};

pub const ParseError = error{
    /// The value is empty, an HMAC-MD5 value is not exactly 17 octets (RFC
    /// 5304 §2: "the length field in the TLV is 17"), or an RFC 5310 value is
    /// shorter than its type and Key ID.
    MalformedAuth,
};

/// Decode the value of an Authentication TLV (the bytes after code/length).
pub fn parse(value: []const u8) ParseError!Tlv {
    if (value.len < 1) return error.MalformedAuth;
    const body = value[1..];
    return switch (value[0]) {
        auth_type.cleartext => .{ .cleartext = body },
        auth_type.hmac_md5 => if (body.len != 16) error.MalformedAuth else .{ .hmac_md5 = body[0..16] },
        auth_type.crypto => if (body.len < 2) error.MalformedAuth else .{ .crypto = .{
            .key_id = std.mem.readInt(u16, body[0..2], .big),
            .digest = body[2..],
        } },
        else => .{ .other = .{ .auth_type = value[0], .value = body } },
    };
}

/// Append the Authentication TLV for `key` with the digest still to be filled
/// in by `sign` (zeros for HMAC-MD5, `Apad` for RFC 5310, as both RFCs and
/// holo-isis initialise it). For cleartext this is the final TLV. Add it
/// before any other TLV — holo-isis and FRR put it first, and a receiver that
/// stops walking at a malformed later TLV still finds it.
///
/// Runs one frame down under a dead-stack burn (`auth_burn`).
pub fn addPlaceholder(b: *tlv.Builder, key: Key) tlv.BuildError!void {
    return burn.run(auth_burn, tlv.BuildError!void, addPlaceholderBody, .{ b, key });
}

fn addPlaceholderBody(b: *tlv.Builder, key: Key) tlv.BuildError!void {
    var value: [tlv.max_value_len]u8 = undefined;
    value[0] = key.algorithm.authType();
    const len: usize = switch (key.algorithm) {
        .cleartext => blk: {
            if (key.secret.len > tlv.max_value_len - 1) return error.ValueTooLong;
            @memcpy(value[1..][0..key.secret.len], key.secret);
            break :blk 1 + key.secret.len;
        },
        .hmac_md5 => blk: {
            @memset(value[1..17], 0);
            break :blk 17;
        },
        .hmac_sha1, .hmac_sha224, .hmac_sha256, .hmac_sha384, .hmac_sha512 => blk: {
            const l = key.algorithm.digestLen();
            std.mem.writeInt(u16, value[1..3], key.id, .big);
            @memcpy(value[3..][0..l], apad[0..l]);
            break :blk 3 + l;
        },
    };
    try b.addTlv(tlv_code, value[0..len]);
}

/// Where the Authentication TLV sits in a PDU.
pub const Located = struct {
    tlv: Tlv,
    /// Offset in the PDU of the Authentication Type octet.
    value_off: usize,
    /// The PDU Length field: the digest covers `bytes[0..pdu_len]`.
    pdu_len: usize,
    /// LSPs hash Remaining Lifetime and Checksum as zero.
    is_lsp: bool,
};

pub const FindError = pdu.DecodeError || tlv.Error || ParseError || error{
    /// A well-formed common header of a PDU type that carries no TLVs this
    /// module models (authentication is defined for IIH, LSP and SNPs).
    UnsupportedPduType,
};

/// Decode the PDU body and return its first Authentication TLV, or `null`.
/// The walk stops at the first #10: a malformed TLV after it is the PDU
/// decoder's concern, not this one's.
pub fn find(bytes: []const u8) FindError!?Located {
    const h = try header.decode(bytes);
    var fixed: usize = undefined;
    var region: []const u8 = undefined;
    var is_lsp = false;
    switch (h.pdu_type) {
        .l1_lan_iih, .l2_lan_iih => {
            region = (try pdu.LanHello.decode(bytes)).tlv_bytes;
            fixed = pdu.lan_iih_fixed_len;
        },
        .p2p_iih => {
            region = (try pdu.P2pHello.decode(bytes)).tlv_bytes;
            fixed = pdu.p2p_iih_fixed_len;
        },
        .l1_lsp, .l2_lsp => {
            region = (try pdu.Lsp.decode(bytes)).tlv_bytes;
            fixed = pdu.lsp_fixed_len;
            is_lsp = true;
        },
        .l1_csnp, .l2_csnp => {
            region = (try pdu.Csnp.decode(bytes)).tlv_bytes;
            fixed = pdu.csnp_fixed_len;
        },
        .l1_psnp, .l2_psnp => {
            region = (try pdu.Psnp.decode(bytes)).tlv_bytes;
            fixed = pdu.psnp_fixed_len;
        },
        else => return error.UnsupportedPduType,
    }
    var it = tlv.TlvIterator.init(region);
    while (true) {
        const start = it.pos;
        const t = (try it.next()) orelse return null;
        if (t.code != tlv_code) continue;
        return .{
            .tlv = try parse(t.value),
            .value_off = fixed + start + 2,
            .pdu_len = fixed + region.len,
            .is_lsp = is_lsp,
        };
    }
}

/// The digest `key` gives the PDU whose Authentication Value starts at
/// `digest_off` (L octets). `out` receives `key.algorithm.digestLen()` octets.
fn digest(key: Key, bytes: []const u8, digest_off: usize, is_lsp: bool, out: *[max_digest_len]u8) void {
    switch (key.algorithm) {
        .cleartext => unreachable,
        .hmac_md5 => macOver(std.crypto.hash.Md5, false, key, bytes, digest_off, is_lsp, zeros[0..16], out[0..16]),
        .hmac_sha1 => macOver(std.crypto.hash.Sha1, true, key, bytes, digest_off, is_lsp, apad[0..20], out[0..20]),
        .hmac_sha224 => macOver(std.crypto.hash.sha2.Sha224, true, key, bytes, digest_off, is_lsp, apad[0..28], out[0..28]),
        .hmac_sha256 => macOver(std.crypto.hash.sha2.Sha256, true, key, bytes, digest_off, is_lsp, apad[0..32], out[0..32]),
        .hmac_sha384 => macOver(std.crypto.hash.sha2.Sha384, true, key, bytes, digest_off, is_lsp, apad[0..48], out[0..48]),
        .hmac_sha512 => macOver(std.crypto.hash.sha2.Sha512, true, key, bytes, digest_off, is_lsp, apad[0..64], out[0..64]),
    }
}

fn macOver(
    comptime Hash: type,
    comptime rfc5310: bool,
    key: Key,
    bytes: []const u8,
    digest_off: usize,
    is_lsp: bool,
    replacement: *const [Hash.digest_length]u8,
    out: *[Hash.digest_length]u8,
) void {
    const Mac = hmac.Hmac(Hash);
    const l = Hash.digest_length;
    // RFC 5310 §3.3 (1): "If the Authentication Key (K) is more than L octets
    // long, then Ko is set to H(K)". A shorter key zero-padded to L and then
    // to B is what RFC 2104 already does with it.
    var ko: [l]u8 = undefined;
    defer std.crypto.secureZero(u8, &ko);
    const k: []const u8 = if (rfc5310 and key.strict_rfc5310 and key.secret.len > l) blk: {
        Hash.hash(key.secret, &ko, .{});
        break :blk &ko;
    } else key.secret;

    var m = Mac.init(k);
    var pos: usize = 0;
    if (is_lsp) {
        // Remaining Lifetime [10, 12) and Checksum [24, 26) hash as zero.
        m.update(bytes[0..10]);
        m.update(zeros[0..2]);
        m.update(bytes[12..pdu.lsp_checksum_off]);
        m.update(zeros[0..2]);
        pos = pdu.lsp_checksum_off + 2;
    }
    m.update(bytes[pos..digest_off]);
    m.update(replacement);
    m.update(bytes[digest_off + l ..]);
    m.final(out);
}

pub const SignError = FindError || error{
    /// The PDU carries no Authentication TLV (add one with `addPlaceholder`).
    AuthMissing,
    /// The Authentication TLV's type, Key ID or length is not `key`'s.
    KeyMismatch,
};

/// Fill in the digest of the PDU's Authentication TLV for `key`, in place.
/// The digest field's current contents do not matter (they hash as the
/// placeholder), so signing twice gives the same bytes. For an LSP the
/// Checksum is then re-stamped (ISO 10589 §7.3.11), because it covers the
/// digest; Remaining Lifetime is left as it is. Cleartext needs no digest:
/// the TLV is only checked against `key`.
///
/// Runs one frame down under a dead-stack burn (`auth_burn`).
pub fn sign(bytes: []u8, key: Key) SignError!void {
    return burn.run(auth_burn, SignError!void, signBody, .{ bytes, key });
}

fn signBody(bytes: []u8, key: Key) SignError!void {
    const loc = (try find(bytes)) orelse return error.AuthMissing;
    const pdu_bytes = bytes[0..loc.pdu_len];
    const l = key.algorithm.digestLen();
    const digest_off: usize = switch (loc.tlv) {
        .cleartext => |pw| {
            if (key.algorithm != .cleartext or !std.mem.eql(u8, pw, key.secret)) return error.KeyMismatch;
            return;
        },
        .hmac_md5 => if (key.algorithm != .hmac_md5) return error.KeyMismatch else loc.value_off + 1,
        .crypto => |c| blk: {
            if (key.algorithm.authType() != auth_type.crypto or c.key_id != key.id or c.digest.len != l)
                return error.KeyMismatch;
            break :blk loc.value_off + 3;
        },
        .other => return error.KeyMismatch,
    };
    var out: [max_digest_len]u8 = undefined;
    digest(key, pdu_bytes, digest_off, loc.is_lsp, &out);
    @memcpy(pdu_bytes[digest_off..][0..l], out[0..l]);
    if (loc.is_lsp) _ = try pdu.stampLspChecksum(pdu_bytes);
}

pub const VerifyError = FindError || error{
    /// No Authentication TLV in the PDU (holo-isis: `AuthTypeMismatch`).
    AuthMissing,
    /// No configured key for the TLV's type (or, RFC 5310, its Key ID).
    KeyNotFound,
    /// An authentication type this module does not verify (0, 255, ...).
    UnsupportedAuthType,
    /// The value does not match any candidate key (RFC 5304 §2 / RFC 5310
    /// §3.5: "the PDU is discarded").
    AuthFailed,
};

/// Verify the PDU's authentication against `keys`; returns the index of the
/// key that matched. Comparison is constant-time in the received value and
/// the computed one (the lengths and which key is tried are public).
///
/// Runs one frame down under a dead-stack burn (`auth_burn`).
pub fn verify(bytes: []const u8, keys: []const Key) VerifyError!usize {
    return burn.run(auth_burn, VerifyError!usize, verifyBody, .{ bytes, keys });
}

fn verifyBody(bytes: []const u8, keys: []const Key) VerifyError!usize {
    const loc = (try find(bytes)) orelse return error.AuthMissing;
    const pdu_bytes = bytes[0..loc.pdu_len];
    var any_key = false;
    switch (loc.tlv) {
        .cleartext => |pw| for (keys, 0..) |k, i| {
            if (k.algorithm != .cleartext) continue;
            any_key = true;
            if (declassified(ctEql(pw, k.secret))) return i;
        },
        .hmac_md5 => |received| for (keys, 0..) |k, i| {
            if (k.algorithm != .hmac_md5) continue;
            any_key = true;
            var out: [max_digest_len]u8 = undefined;
            digest(k, pdu_bytes, loc.value_off + 1, loc.is_lsp, &out);
            if (declassified(timing_safe.eql([16]u8, received.*, out[0..16].*))) return i;
        },
        .crypto => |c| for (keys, 0..) |k, i| {
            if (k.algorithm.authType() != auth_type.crypto or k.id != c.key_id) continue;
            any_key = true;
            const l = k.algorithm.digestLen();
            if (c.digest.len != l) continue;
            var out: [max_digest_len]u8 = undefined;
            digest(k, pdu_bytes, loc.value_off + 3, loc.is_lsp, &out);
            if (declassified(ctEql(c.digest, out[0..l]))) return i;
        },
        .other => return error.UnsupportedAuthType,
    }
    return if (any_key) error.AuthFailed else error.KeyNotFound;
}

/// The accept/refuse verdict is public by design (the PDU is either acted on
/// or dropped, which any peer observes), so it is marked defined for memcheck
/// and ctgrind does not count the branch on it. A no-op outside a
/// `-fvalgrind` build. Only the bool is declassified, never the digest or
/// key bytes it came from (the same helper as `ssh`'s `declassified`).
fn declassified(verdict: bool) bool {
    var v = verdict;
    std.valgrind.memcheck.makeMemDefined(std.mem.asBytes(&v));
    return v;
}

/// Constant-time equality of two byte strings whose LENGTHS are public.
fn ctEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var d: u8 = 0;
    for (a, b) |x, y| d |= x ^ y;
    const vd: *volatile u8 = &d;
    return vd.* == 0;
}
