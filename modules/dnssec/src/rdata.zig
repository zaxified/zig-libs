// SPDX-License-Identifier: MIT

//! DNSSEC record RDATA parsing: DNSKEY (RFC 4034 §2), RRSIG (RFC 4034 §3),
//! DS (RFC 4034 §5), NSEC (RFC 4034 §4), NSEC3 + NSEC3PARAM (RFC 5155 §3-4),
//! plus the shared Type Bit Maps field (RFC 4034 §4.1.2) and the DNSKEY key
//! tag algorithm (RFC 4034 Appendix B).
//!
//! Input is the raw RDATA byte slice `dns.Record.data.unknown` already gives
//! us for any record type the `dns` module's codec doesn't decode natively
//! (DNSSEC types are not in `dns.message.Type` — see this module's README
//! "Recon notes" for why extending it wasn't necessary). All bounds are
//! checked; malformed RDATA is a typed error, never a panic — same
//! robustness discipline as `dns.message`.
//!
//! No cryptography in this file: parsing structure and computing the key tag
//! (a checksum, not a hash) are purely mechanical.

const std = @import("std");
const wire = @import("wire.zig");

pub const ParseError = error{
    Truncated,
    BadRecord,
} || wire.NameError;

// ── DNSKEY (RFC 4034 §2.1) ──────────────────────────────────────────────────

pub const Dnskey = struct {
    flags: u16,
    protocol: u8,
    algorithm: u8,
    /// Algorithm-specific public key material (RFC 4034 §2.1.4), raw —
    /// decoding it (RFC 3110 RSA / RFC 6605 ECDSA / RFC 8080 Ed25519) is
    /// `keys.zig`'s job, not this parser's.
    public_key: []const u8,

    pub const flag_zone_key: u16 = 0x0100;
    pub const flag_secure_entry_point: u16 = 0x0001;

    pub fn isZoneKey(k: Dnskey) bool {
        return k.flags & flag_zone_key != 0;
    }

    pub fn isSecureEntryPoint(k: Dnskey) bool {
        return k.flags & flag_secure_entry_point != 0;
    }
};

/// Parse a DNSKEY RDATA (RFC 4034 §2.1): Flags(2) Protocol(1) Algorithm(1)
/// PublicKey(rest). `rdata` is not retained; `public_key` is a subslice of it
/// (caller must keep `rdata` alive as long as the result is used — the same
/// arena-owned-by-Message convention `dns.decode` already establishes).
pub fn parseDnskey(rdata: []const u8) ParseError!Dnskey {
    if (rdata.len < 4) return error.Truncated;
    return .{
        .flags = std.mem.readInt(u16, rdata[0..2], .big),
        .protocol = rdata[2],
        .algorithm = rdata[3],
        .public_key = rdata[4..],
    };
}

/// DNSKEY key tag (RFC 4034 Appendix B): a 16-bit checksum over the whole
/// RDATA, used to narrow down which DNSKEY an RRSIG's `key_tag` refers to
/// (several keys can collide on the same tag — it is a hint, not a unique
/// id; the algorithm + a full signature-verify attempt is what actually
/// disambiguates). Not a hash, no crypto — a big-endian-pair running sum with
/// one carry fold, straight out of the RFC's own pseudocode.
pub fn keyTag(rdata: []const u8, alg: u8) u16 {
    // RFC 4034 Appendix B.1: algorithm 1 (RSA/MD5, long deprecated) uses the
    // last two octets of the public key as the tag instead of the checksum.
    if (alg == 1) {
        if (rdata.len < 2) return 0;
        return std.mem.readInt(u16, rdata[rdata.len - 2 ..][0..2], .big);
    }
    var ac: u32 = 0;
    for (rdata, 0..) |b, i| {
        ac += if (i & 1 == 1) @as(u32, b) else @as(u32, b) << 8;
    }
    ac += (ac >> 16) & 0xffff;
    return @truncate(ac & 0xffff);
}

// ── RRSIG (RFC 4034 §3.1) ───────────────────────────────────────────────────

pub const Rrsig = struct {
    type_covered: u16,
    algorithm: u8,
    /// Number of labels in the original owner name, NOT counting the root
    /// label — RFC 4034 §3.1.3. When this is less than the actual owner
    /// name's label count, the RRset was synthesized from a wildcard and the
    /// canonical signed form must use the wildcard name (`*.<suffix>`), not
    /// the expanded query name — this is exactly the substitution
    /// `canonical.zig`'s stub must perform.
    labels: u8,
    original_ttl: u32,
    expiration: u32,
    inception: u32,
    key_tag: u16,
    signer_name: []const u8,
    signature: []const u8,
};

/// Parse an RRSIG RDATA (RFC 4034 §3.1): TypeCovered(2) Algorithm(1)
/// Labels(1) OriginalTTL(4) SignatureExpiration(4) SignatureInception(4)
/// KeyTag(2) SignerName(uncompressed name) Signature(rest). `gpa` allocates
/// the decoded `signer_name` text (owned by the caller; `signature` remains a
/// subslice of `rdata`).
pub fn parseRrsig(gpa: std.mem.Allocator, rdata: []const u8) (ParseError || error{OutOfMemory})!Rrsig {
    if (rdata.len < 18) return error.Truncated;
    var name_buf: [wire.max_name_text_len]u8 = undefined;
    const name_res = try wire.decodeUncompressedName(rdata, 18, &name_buf);
    if (name_res.next_pos > rdata.len) return error.BadRecord;
    return .{
        .type_covered = std.mem.readInt(u16, rdata[0..2], .big),
        .algorithm = rdata[2],
        .labels = rdata[3],
        .original_ttl = std.mem.readInt(u32, rdata[4..8], .big),
        .expiration = std.mem.readInt(u32, rdata[8..12], .big),
        .inception = std.mem.readInt(u32, rdata[12..16], .big),
        .key_tag = std.mem.readInt(u16, rdata[16..18], .big),
        .signer_name = try gpa.dupe(u8, name_buf[0..name_res.text_len]),
        .signature = rdata[name_res.next_pos..],
    };
}

// ── DS (RFC 4034 §5.1) ──────────────────────────────────────────────────────

pub const Ds = struct {
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: []const u8,

    pub const digest_sha1: u8 = 1;
    pub const digest_sha256: u8 = 2;
    pub const digest_gost: u8 = 3;
    pub const digest_sha384: u8 = 4;
};

/// Parse a DS RDATA (RFC 4034 §5.1): KeyTag(2) Algorithm(1) DigestType(1)
/// Digest(rest).
pub fn parseDs(rdata: []const u8) ParseError!Ds {
    if (rdata.len < 4) return error.Truncated;
    return .{
        .key_tag = std.mem.readInt(u16, rdata[0..2], .big),
        .algorithm = rdata[2],
        .digest_type = rdata[3],
        .digest = rdata[4..],
    };
}

// ── Type Bit Maps (RFC 4034 §4.1.2, shared by NSEC and NSEC3) ──────────────

/// A parsed-but-not-copied Type Bit Maps field: a sequence of windows
/// `(window_number:u8, bitmap_length:u8, bitmap[bitmap_length])`, each window
/// covering RR types `window_number*256 .. window_number*256+255`. Validated
/// once at parse time (`parseTypeBitMap`); `contains` after that never
/// re-validates and cannot go out of bounds.
pub const TypeBitMap = struct {
    raw: []const u8,

    /// Whether RR type `wanted_type` is asserted present in this bitmap.
    pub fn contains(self: TypeBitMap, wanted_type: u16) bool {
        const window: u8 = @truncate(wanted_type >> 8);
        const bit: u8 = @truncate(wanted_type & 0xff);
        var i: usize = 0;
        while (i + 2 <= self.raw.len) {
            const w = self.raw[i];
            const len = self.raw[i + 1];
            const bitmap = self.raw[i + 2 ..][0..len];
            if (w == window) {
                const byte_idx = bit / 8;
                if (byte_idx >= len) return false;
                return bitmap[byte_idx] & (@as(u8, 0x80) >> @intCast(bit % 8)) != 0;
            }
            i += 2 + len;
        }
        return false;
    }

    /// Iterate every RR type this bitmap asserts present, in ascending
    /// order (matches the order the windows/bytes are required to be in on
    /// the wire — RFC 4034 §4.1.2 "the type bit map ... window blocks are
    /// present in increasing numerical order").
    pub const Iterator = struct {
        raw: []const u8,
        i: usize = 0,
        window: u8 = 0,
        len: u8 = 0,
        bit: usize = 0,

        pub fn next(it: *Iterator) ?u16 {
            while (true) {
                if (it.bit >= @as(usize, it.len) * 8) {
                    if (it.i + 2 > it.raw.len) return null;
                    it.window = it.raw[it.i];
                    it.len = it.raw[it.i + 1];
                    it.i += 2 + it.len;
                    it.bit = 0;
                    continue;
                }
                const byte_idx = it.bit / 8;
                const bitmap = it.raw[it.i - it.len ..][0..it.len];
                const set = bitmap[byte_idx] & (@as(u8, 0x80) >> @intCast(it.bit % 8)) != 0;
                const ty: u16 = (@as(u16, it.window) << 8) | @as(u16, @intCast(it.bit));
                it.bit += 1;
                if (set) return ty;
            }
        }
    };

    pub fn iterator(self: TypeBitMap) Iterator {
        return .{ .raw = self.raw };
    }
};

/// Validate a Type Bit Maps field (bounds-check every window) and wrap it.
pub fn parseTypeBitMap(raw: []const u8) ParseError!TypeBitMap {
    var i: usize = 0;
    var last_window: i32 = -1;
    while (i < raw.len) {
        if (i + 2 > raw.len) return error.Truncated;
        const w = raw[i];
        const len = raw[i + 1];
        if (len == 0 or len > 32) return error.BadRecord;
        if (i + 2 + len > raw.len) return error.Truncated;
        if (@as(i32, w) <= last_window) return error.BadRecord; // strictly increasing (RFC 4034 §4.1.2)
        last_window = w;
        i += 2 + len;
    }
    return .{ .raw = raw };
}

// ── NSEC (RFC 4034 §4.1) ────────────────────────────────────────────────────

pub const Nsec = struct {
    next_domain_name: []const u8,
    types: TypeBitMap,
};

/// Parse an NSEC RDATA: NextDomainName(uncompressed name) TypeBitMaps(rest).
pub fn parseNsec(gpa: std.mem.Allocator, rdata: []const u8) (ParseError || error{OutOfMemory})!Nsec {
    var name_buf: [wire.max_name_text_len]u8 = undefined;
    const name_res = try wire.decodeUncompressedName(rdata, 0, &name_buf);
    if (name_res.next_pos > rdata.len) return error.BadRecord;
    return .{
        .next_domain_name = try gpa.dupe(u8, name_buf[0..name_res.text_len]),
        .types = try parseTypeBitMap(rdata[name_res.next_pos..]),
    };
}

// ── NSEC3 / NSEC3PARAM (RFC 5155 §3-4) ─────────────────────────────────────

pub const Nsec3 = struct {
    hash_algorithm: u8,
    flags: u8,
    iterations: u16,
    salt: []const u8,
    /// Binary digest (NOT base32hex text) — compare directly against a
    /// binary hash computed by `nsec3.iteratedHash`.
    next_hashed_owner_name: []const u8,
    types: TypeBitMap,

    pub const flag_opt_out: u8 = 0x01;

    pub fn optOut(n: Nsec3) bool {
        return n.flags & flag_opt_out != 0;
    }
};

/// Parse an NSEC3 RDATA (RFC 5155 §3.2): HashAlgorithm(1) Flags(1)
/// Iterations(2) SaltLength(1) Salt(SaltLength) HashLength(1)
/// NextHashedOwnerName(HashLength) TypeBitMaps(rest).
pub fn parseNsec3(rdata: []const u8) ParseError!Nsec3 {
    if (rdata.len < 5) return error.Truncated;
    const salt_len = rdata[4];
    var pos: usize = 5;
    if (rdata.len < pos + salt_len) return error.Truncated;
    const salt = rdata[pos..][0..salt_len];
    pos += salt_len;
    if (rdata.len < pos + 1) return error.Truncated;
    const hash_len = rdata[pos];
    pos += 1;
    if (rdata.len < pos + hash_len) return error.Truncated;
    const next_hash = rdata[pos..][0..hash_len];
    pos += hash_len;
    return .{
        .hash_algorithm = rdata[0],
        .flags = rdata[1],
        .iterations = std.mem.readInt(u16, rdata[2..4], .big),
        .salt = salt,
        .next_hashed_owner_name = next_hash,
        .types = try parseTypeBitMap(rdata[pos..]),
    };
}

pub const Nsec3Param = struct {
    hash_algorithm: u8,
    flags: u8,
    iterations: u16,
    salt: []const u8,
};

/// Parse an NSEC3PARAM RDATA (RFC 5155 §4.2): HashAlgorithm(1) Flags(1)
/// Iterations(2) SaltLength(1) Salt(SaltLength).
pub fn parseNsec3Param(rdata: []const u8) ParseError!Nsec3Param {
    if (rdata.len < 5) return error.Truncated;
    const salt_len = rdata[4];
    if (rdata.len != 5 + salt_len) return error.BadRecord;
    return .{
        .hash_algorithm = rdata[0],
        .flags = rdata[1],
        .iterations = std.mem.readInt(u16, rdata[2..4], .big),
        .salt = rdata[5..],
    };
}

// ── RR type numbers this module cares about (dns.Type has no tags for
//    these — see README "Recon notes" for why they weren't added there) ────

pub const rr_type = struct {
    pub const ds: u16 = 43;
    pub const rrsig: u16 = 46;
    pub const nsec: u16 = 47;
    pub const dnskey: u16 = 48;
    pub const nsec3: u16 = 50;
    pub const nsec3param: u16 = 51;
    pub const cds: u16 = 59;
    pub const cdnskey: u16 = 60;
};

// ── algorithm numbers this module targets (IANA DNSSEC Algorithm Numbers) ──

pub const algorithm = struct {
    pub const rsasha1: u8 = 5;
    pub const rsasha1_nsec3_sha1: u8 = 7;
    pub const rsasha256: u8 = 8;
    pub const rsasha512: u8 = 10;
    pub const ecdsap256sha256: u8 = 13;
    pub const ecdsap384sha384: u8 = 14;
    pub const ed25519: u8 = 15;
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "parseDnskey: flags/protocol/algorithm/public_key split" {
    const rdata = "\x01\x01" ++ "\x03" ++ "\x08" ++ "\xde\xad\xbe\xef";
    const k = try parseDnskey(rdata);
    try testing.expectEqual(@as(u16, 0x0101), k.flags);
    try testing.expect(k.isZoneKey());
    try testing.expect(k.isSecureEntryPoint());
    try testing.expectEqual(@as(u8, 3), k.protocol);
    try testing.expectEqual(@as(u8, 8), k.algorithm);
    try testing.expectEqualSlices(u8, "\xde\xad\xbe\xef", k.public_key);
}

test "parseDnskey: truncated errors" {
    try testing.expectError(error.Truncated, parseDnskey("\x01"));
}

test "keyTag: RFC 4034 Appendix B algorithm, hand-computed vector" {
    // rdata = 0x01 0x02 0x03 0x04. Per RFC 4034 Appendix B pseudocode:
    // ac = (0x01<<8) + 0x02 + (0x03<<8) + 0x04 = 0x0100+0x02+0x0300+0x04 = 0x0406.
    // ac>>16 == 0, so the tag is ac itself: 0x0406 = 1030.
    try testing.expectEqual(@as(u16, 0x0406), keyTag("\x01\x02\x03\x04", 8));
}

test "keyTag: algorithm 1 (RSA/MD5) uses the last two public-key octets" {
    const rdata = "\x00\x00" ++ "\x03" ++ "\x01" ++ "\xaa\xbb\xcc\xdd";
    try testing.expectEqual(@as(u16, 0xccdd), keyTag(rdata, 1));
}

test "parseRrsig: fields split correctly" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const rdata = "\x00\x01" ++ "\x08" ++ "\x02" ++ "\x00\x00\x0e\x10" ++
        "\x00\x00\x00\x02" ++ "\x00\x00\x00\x01" ++ "\x30\x39" ++
        "\x07example\x03com\x00" ++ "\xde\xad\xbe\xef";
    const sig = try parseRrsig(arena.allocator(), rdata);
    try testing.expectEqual(@as(u16, 1), sig.type_covered);
    try testing.expectEqual(@as(u8, 8), sig.algorithm);
    try testing.expectEqual(@as(u8, 2), sig.labels);
    try testing.expectEqual(@as(u32, 3600), sig.original_ttl);
    try testing.expectEqual(@as(u32, 2), sig.expiration);
    try testing.expectEqual(@as(u32, 1), sig.inception);
    try testing.expectEqual(@as(u16, 0x3039), sig.key_tag);
    try testing.expectEqualStrings("example.com", sig.signer_name);
    try testing.expectEqualSlices(u8, "\xde\xad\xbe\xef", sig.signature);
}

test "parseDs: fields split correctly" {
    const rdata = "\x30\x39" ++ "\x08" ++ "\x02" ++ "\xaa\xbb\xcc";
    const ds = try parseDs(rdata);
    try testing.expectEqual(@as(u16, 0x3039), ds.key_tag);
    try testing.expectEqual(@as(u8, 8), ds.algorithm);
    try testing.expectEqual(Ds.digest_sha256, ds.digest_type);
    try testing.expectEqualSlices(u8, "\xaa\xbb\xcc", ds.digest);
}

test "TypeBitMap: contains + iterator over A, RRSIG, NSEC" {
    // Window 0: A(1), RRSIG(46), NSEC(47) — matches the RFC 4034 §4.1.2
    // worked example's window-0 bitmap shape (bytes differ; types chosen
    // for a compact test).
    var bitmap = [_]u8{0} ** 6; // covers bits up to 47
    bitmap[0] |= 0x40; // bit 1 (A)
    bitmap[5] |= 0x03; // bits 46,47 (RRSIG, NSEC)
    const raw = [_]u8{ 0, 6 } ++ bitmap;
    const tbm = try parseTypeBitMap(&raw);
    try testing.expect(tbm.contains(1));
    try testing.expect(tbm.contains(46));
    try testing.expect(tbm.contains(47));
    try testing.expect(!tbm.contains(2));
    try testing.expect(!tbm.contains(48));

    var it = tbm.iterator();
    try testing.expectEqual(@as(?u16, 1), it.next());
    try testing.expectEqual(@as(?u16, 46), it.next());
    try testing.expectEqual(@as(?u16, 47), it.next());
    try testing.expectEqual(@as(?u16, null), it.next());
}

test "TypeBitMap: multiple windows, non-increasing window rejected" {
    const raw = [_]u8{ 1, 1, 0x80 } ++ [_]u8{ 0, 1, 0x80 }; // window 1 then 0 — invalid
    try testing.expectError(error.BadRecord, parseTypeBitMap(&raw));
}

test "TypeBitMap: truncated bitmap errors" {
    const raw = [_]u8{ 0, 5, 0x80 }; // claims 5 bytes, has 1
    try testing.expectError(error.Truncated, parseTypeBitMap(&raw));
}

test "parseNsec: next name + bitmap" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const rdata = "\x03www\x07example\x03com\x00" ++ [_]u8{ 0, 1, 0x40 };
    const n = try parseNsec(arena.allocator(), rdata);
    try testing.expectEqualStrings("www.example.com", n.next_domain_name);
    try testing.expect(n.types.contains(1));
}

test "parseNsec3: full field split, opt-out flag" {
    // hash_alg=1 flags=1(opt-out) iterations=12 salt="\xab\xcd" hash=20 zero bytes, empty bitmap
    var rdata_buf: [5 + 2 + 1 + 20]u8 = undefined;
    rdata_buf[0] = 1;
    rdata_buf[1] = 1;
    std.mem.writeInt(u16, rdata_buf[2..4], 12, .big);
    rdata_buf[4] = 2;
    rdata_buf[5] = 0xab;
    rdata_buf[6] = 0xcd;
    rdata_buf[7] = 20;
    @memset(rdata_buf[8..28], 0x11);
    const n = try parseNsec3(&rdata_buf);
    try testing.expectEqual(@as(u8, 1), n.hash_algorithm);
    try testing.expect(n.optOut());
    try testing.expectEqual(@as(u16, 12), n.iterations);
    try testing.expectEqualSlices(u8, "\xab\xcd", n.salt);
    try testing.expectEqual(@as(usize, 20), n.next_hashed_owner_name.len);
    try testing.expectEqual(@as(u8, 0x11), n.next_hashed_owner_name[0]);
}

test "parseNsec3Param: fields split correctly" {
    const rdata = "\x01" ++ "\x00" ++ "\x00\x0a" ++ "\x02" ++ "\xab\xcd";
    const p = try parseNsec3Param(rdata);
    try testing.expectEqual(@as(u8, 1), p.hash_algorithm);
    try testing.expectEqual(@as(u16, 10), p.iterations);
    try testing.expectEqualSlices(u8, "\xab\xcd", p.salt);
}

test "parseNsec3Param: trailing garbage rejected" {
    const rdata = "\x01" ++ "\x00" ++ "\x00\x0a" ++ "\x00" ++ "\xff";
    try testing.expectError(error.BadRecord, parseNsec3Param(rdata));
}
