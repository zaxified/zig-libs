// SPDX-License-Identifier: MIT
//! Zone signing primitives: DNSKEY and DS record data, and RRSIG creation (RFC 4034 §3, §5; RFC 4035 §2.2;
//! RFC 6605 for ECDSA; RFC 8080 for Ed25519). The counterpart of `canonical.buildSignedData` + `keys.verifySignature`:
//! the RRSIG signed data is built by the same function the validator uses, so a signature made here verifies
//! through `validate` by construction (and the tests run exactly that).
//!
//! No clock and no randomness: inception and expiration are the caller's, and ECDSA signatures are
//! deterministic (std's construction, `noise` null); RSA PKCS#1 v1.5 and Ed25519 are deterministic anyway.
//! Algorithms: RSASHA256 (8), RSASHA512 (10), ECDSAP256SHA256 (13), ECDSAP384SHA384 (14), ED25519 (15). RSASHA1
//! is not offered (RFC 8624: MUST NOT sign), and Ed448 (16) has no signer in the `ed448` module yet.

const std = @import("std");
const dns = @import("dns");
const rsa = @import("rsa");
const rdata = @import("rdata.zig");
const wire = @import("wire.zig");
const canonical = @import("canonical.zig");
const ds = @import("ds.zig");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = std.crypto.sign.Ed25519;

/// A zone key pair for signing, by algorithm. Held by pointer (an RSA secret key is large).
pub const SigningKey = union(enum) {
    rsa_sha256: *const rsa.SecretKey,
    rsa_sha512: *const rsa.SecretKey,
    ecdsa_p256: *const EcdsaP256.KeyPair,
    ecdsa_p384: *const EcdsaP384.KeyPair,
    ed25519: *const Ed25519.KeyPair,

    /// The DNSSEC algorithm number (`rdata.algorithm`).
    pub fn algorithm(self: SigningKey) u8 {
        return switch (self) {
            .rsa_sha256 => rdata.algorithm.rsasha256,
            .rsa_sha512 => rdata.algorithm.rsasha512,
            .ecdsa_p256 => rdata.algorithm.ecdsap256sha256,
            .ecdsa_p384 => rdata.algorithm.ecdsap384sha384,
            .ed25519 => rdata.algorithm.ed25519,
        };
    }
};

pub const SignError = canonical.BuildSignedDataError || error{
    /// The key could not sign (an RSA key too small for the padded hash, a fault check).
    SigningFailed,
    /// `signer_name` is not a valid domain name.
    InvalidName,
};

pub const SignParams = struct {
    /// The zone apex that owns the signing DNSKEY.
    signer_name: []const u8,
    /// `rdata.keyTag` of the signing DNSKEY's RDATA.
    key_tag: u16,
    /// Seconds since the epoch (RFC 4034 §3.1.5; the wire field is 32 bits).
    inception: u32,
    expiration: u32,
    /// The TTL the RRset was published with; null takes the first record's TTL.
    original_ttl: ?u32 = null,
    /// RRSIG Labels (§3.1.3: the owner's label count without the root, and without a leading `*`). Null counts
    /// the owner name; give it explicitly to sign a wildcard owner or an RRset that was expanded from one.
    labels: ?u8 = null,
};

/// RRSIG RDATA (owned by `gpa`) covering `rrset` (one owner name, type and class; `owner_name` is its text name)
/// signed with `key`. The RRset's records are canonicalized and sorted exactly as `validate` expects.
pub fn signRrset(
    gpa: std.mem.Allocator,
    rrset: []const dns.Record,
    owner_name: []const u8,
    key: SigningKey,
    params: SignParams,
) SignError![]u8 {
    if (rrset.len == 0) return error.InconsistentRrset;
    const owner = canonical.stripDot(owner_name);
    const labels: u8 = params.labels orelse blk: {
        if (owner.len == 0) break :blk 0;
        var n: u8 = 1;
        for (owner) |c| {
            if (c == '.') n +|= 1;
        }
        break :blk n;
    };
    const proto: rdata.Rrsig = .{
        .type_covered = @backingInt(rrset[0].ty),
        .algorithm = key.algorithm(),
        .labels = labels,
        .original_ttl = params.original_ttl orelse rrset[0].ttl,
        .expiration = params.expiration,
        .inception = params.inception,
        .key_tag = params.key_tag,
        .signer_name = params.signer_name,
        .signature = &.{},
    };
    const signed = try canonical.buildSignedData(gpa, rrset, proto, owner_name);
    defer gpa.free(signed);

    var signer_buf: [wire.max_canonical_wire_len]u8 = undefined;
    const signer_wire = wire.encodeCanonicalName(params.signer_name, &signer_buf) catch return error.InvalidName;
    const prefix_len = 18 + signer_wire.len;

    var sig_buf: [rsa.max_modulus_len]u8 = undefined;
    const sig: []const u8 = switch (key) {
        .rsa_sha256 => |sk| rsa.signPkcs1v15(sk, std.crypto.hash.sha2.Sha256, signed, &sig_buf) catch return error.SigningFailed,
        .rsa_sha512 => |sk| rsa.signPkcs1v15(sk, std.crypto.hash.sha2.Sha512, signed, &sig_buf) catch return error.SigningFailed,
        .ecdsa_p256 => |kp| blk: {
            const s = kp.sign(signed, null) catch return error.SigningFailed;
            const raw = s.toBytes();
            @memcpy(sig_buf[0..raw.len], &raw);
            break :blk sig_buf[0..raw.len];
        },
        .ecdsa_p384 => |kp| blk: {
            const s = kp.sign(signed, null) catch return error.SigningFailed;
            const raw = s.toBytes();
            @memcpy(sig_buf[0..raw.len], &raw);
            break :blk sig_buf[0..raw.len];
        },
        .ed25519 => |kp| blk: {
            const s = kp.sign(signed, null) catch return error.SigningFailed;
            const raw = s.toBytes();
            @memcpy(sig_buf[0..raw.len], &raw);
            break :blk sig_buf[0..raw.len];
        },
    };
    const out = try gpa.alloc(u8, prefix_len + sig.len);
    @memcpy(out[0..prefix_len], signed[0..prefix_len]);
    @memcpy(out[prefix_len..], sig);
    return out;
}

/// DNSKEY RDATA (owned by `gpa`): flags, protocol 3, `algorithm`, `public_key` (RFC 3110 RSA / RFC 6605 ECDSA
/// `x || y` / RFC 8080 Ed25519 raw key — the encoding `keys.decodePublicKey` reads).
pub fn encodeDnskey(gpa: std.mem.Allocator, flags: u16, algorithm: u8, public_key: []const u8) std.mem.Allocator.Error![]u8 {
    const out = try gpa.alloc(u8, 4 + public_key.len);
    std.mem.writeInt(u16, out[0..2], flags, .big);
    out[2] = 3;
    out[3] = algorithm;
    @memcpy(out[4..], public_key);
    return out;
}

/// RFC 3110 RSA public key encoding (exponent length, exponent, modulus; both without leading zeros) for a
/// DNSKEY of algorithm 8 or 10. Owned by `gpa`.
pub fn encodeRsaPublicKey(gpa: std.mem.Allocator, exponent: []const u8, modulus: []const u8) std.mem.Allocator.Error![]u8 {
    const e = std.mem.trimStart(u8, exponent, "\x00");
    const n = std.mem.trimStart(u8, modulus, "\x00");
    const lead: usize = if (e.len < 256) 1 else 3;
    const out = try gpa.alloc(u8, lead + e.len + n.len);
    if (e.len < 256) {
        out[0] = @intCast(e.len);
    } else {
        out[0] = 0;
        std.mem.writeInt(u16, out[1..3], @intCast(e.len), .big);
    }
    @memcpy(out[lead..][0..e.len], e);
    @memcpy(out[lead + e.len ..], n);
    return out;
}

/// DS RDATA (owned by `gpa`) for the DNSKEY `dnskey_rdata` of zone `owner_name`: key tag, algorithm, `digest_type`
/// (`rdata.Ds.digest_sha256` / `_sha384`; SHA-1 is computable but RFC 8624 says not to publish it), digest.
pub fn encodeDs(gpa: std.mem.Allocator, owner_name: []const u8, dnskey_rdata: []const u8, digest_type: u8) (ds.DigestError || error{ OutOfMemory, BadRecord })![]u8 {
    const key = rdata.parseDnskey(dnskey_rdata) catch return error.BadRecord;
    var buf: [ds.max_digest_len]u8 = undefined;
    const digest = try ds.computeDigest(owner_name, dnskey_rdata, digest_type, &buf);
    const out = try gpa.alloc(u8, 4 + digest.len);
    std.mem.writeInt(u16, out[0..2], rdata.keyTag(dnskey_rdata, key.algorithm), .big);
    out[2] = key.algorithm;
    out[3] = digest_type;
    @memcpy(out[4..], digest);
    return out;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const keys = @import("keys.zig");

fn aRecord(name: []const u8, last: u8) dns.Record {
    return .{ .name = name, .ty = .a, .class = .in, .ttl = 300, .data = .{ .a = .{ 192, 0, 2, last } } };
}

fn checkRoundTrip(key: SigningKey, public_key: []const u8, flags: u16) !void {
    const gpa = testing.allocator;
    const rrset = [_]dns.Record{ aRecord("www.example.org", 2), aRecord("www.example.org", 1) };
    const dnskey = try encodeDnskey(gpa, flags, key.algorithm(), public_key);
    defer gpa.free(dnskey);
    const tag = rdata.keyTag(dnskey, key.algorithm());
    const rrsig_rdata = try signRrset(gpa, &rrset, "www.example.org", key, .{
        .signer_name = "example.org",
        .key_tag = tag,
        .inception = 1_000_000,
        .expiration = 2_000_000,
    });
    defer gpa.free(rrsig_rdata);
    const rrsig = try rdata.parseRrsig(gpa, rrsig_rdata);
    defer gpa.free(rrsig.signer_name);
    try testing.expectEqual(key.algorithm(), rrsig.algorithm);
    try testing.expectEqual(@as(u8, 3), rrsig.labels);
    try testing.expectEqual(@as(u32, 300), rrsig.original_ttl);
    try testing.expectEqual(tag, rrsig.key_tag);
    // The validator accepts it: DS built from the DNSKEY is the trust anchor.
    const parsed_key = try rdata.parseDnskey(dnskey);
    const signed = try canonical.buildSignedData(gpa, &rrset, rrsig, "www.example.org");
    defer gpa.free(signed);
    const decoded = try keys.decodePublicKey(parsed_key.algorithm, parsed_key.public_key);
    try keys.verifySignature(rrsig.algorithm, decoded, signed, rrsig.signature);
    // Another RRset does not verify under the same signature.
    const other = [_]dns.Record{aRecord("www.example.org", 9)};
    const other_signed = try canonical.buildSignedData(gpa, &other, rrsig, "www.example.org");
    defer gpa.free(other_signed);
    try testing.expectError(error.SignatureVerificationFailed, keys.verifySignature(rrsig.algorithm, decoded, other_signed, rrsig.signature));
}

test "signRrset: ECDSA P-256 and P-384 and Ed25519 signatures verify under keys.verifySignature" {
    const kp256 = try EcdsaP256.KeyPair.generateDeterministic(@as([32]u8, @splat(0x21)));
    try checkRoundTrip(.{ .ecdsa_p256 = &kp256 }, kp256.public_key.toUncompressedSec1()[1..], 0x0101);
    const kp384 = try EcdsaP384.KeyPair.generateDeterministic(@as([48]u8, @splat(0x22)));
    try checkRoundTrip(.{ .ecdsa_p384 = &kp384 }, kp384.public_key.toUncompressedSec1()[1..], 0x0101);
    const ed = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x23)));
    try checkRoundTrip(.{ .ed25519 = &ed }, &ed.public_key.toBytes(), 0x0101);
}

test "signRrset: RSASHA256 and RSASHA512 verify; the RFC 3110 key encoding round-trips" {
    var prng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x24)));
    var kp: rsa.KeyPair = undefined;
    try rsa.generate(&kp, prng.random(), 1024, 65537);
    var nbuf: [128]u8 = undefined;
    try kp.public_key.n.toBytes(&nbuf, .big);
    const e = [_]u8{ 0x01, 0x00, 0x01 };
    const pk = try encodeRsaPublicKey(testing.allocator, &e, &nbuf);
    defer testing.allocator.free(pk);
    try checkRoundTrip(.{ .rsa_sha256 = &kp.secret_key }, pk, 0x0100);
    try checkRoundTrip(.{ .rsa_sha512 = &kp.secret_key }, pk, 0x0100);
}

test "encodeDs: the DS digest matches the DNSKEY it was built from" {
    const gpa = testing.allocator;
    const ed = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x25)));
    const dnskey = try encodeDnskey(gpa, 0x0101, rdata.algorithm.ed25519, &ed.public_key.toBytes());
    defer gpa.free(dnskey);
    const ds_rdata = try encodeDs(gpa, "example.org", dnskey, rdata.Ds.digest_sha256);
    defer gpa.free(ds_rdata);
    const parsed = try rdata.parseDs(ds_rdata);
    try testing.expectEqual(rdata.keyTag(dnskey, rdata.algorithm.ed25519), parsed.key_tag);
    try testing.expect(try ds.matches(parsed, "example.org", dnskey));
    try testing.expect(!(try ds.matches(parsed, "example.com", dnskey)));
}
