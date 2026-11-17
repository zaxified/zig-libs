// SPDX-License-Identifier: MIT

//! Tests added by the 2026-11-17 whole-module mutation audit. Every test here
//! kills a mutant that survived the first run against the older suite (a
//! boundary nobody pinned, a field nobody compared, a branch only a
//! non-default input reaches). They use the public API only, so a test here
//! also states what a caller may rely on.

const std = @import("std");
const testing = std.testing;
const dns = @import("dns");
const rsa = @import("rsa");
const base32 = @import("base32");

const root = @import("root.zig");
const wire = @import("wire.zig");
const rdata = @import("rdata.zig");
const ds = @import("ds.zig");
const keys = @import("keys.zig");
const policy = @import("policy.zig");
const canonical = @import("canonical.zig");
const chain = @import("chain.zig");
const nsec = @import("nsec.zig");
const nsec3 = @import("nsec3.zig");

// ── wire ────────────────────────────────────────────────────────────────────

test "wire: a 253-character name encodes to the 255-octet maximum" {
    var name: [253]u8 = undefined;
    @memset(&name, 'a');
    name[63] = '.';
    name[127] = '.';
    name[191] = '.';
    var out: [wire.max_canonical_wire_len]u8 = undefined;
    const w = try wire.encodeCanonicalName(&name, &out);
    try testing.expectEqual(@as(usize, 255), w.len);
    // 254 characters is one too many, with or without a trailing dot.
    var longer: [254]u8 = undefined;
    @memset(&longer, 'a');
    longer[63] = '.';
    longer[127] = '.';
    longer[191] = '.';
    try testing.expectError(error.NameTooLong, wire.encodeCanonicalName(&longer, &out));
}

test "wire: an empty interior or leading label is refused" {
    var out: [wire.max_canonical_wire_len]u8 = undefined;
    try testing.expectError(error.BadLabel, wire.encodeCanonicalName("a..b", &out));
    try testing.expectError(error.BadLabel, wire.encodeCanonicalName(".a", &out));
}

// ── ds ──────────────────────────────────────────────────────────────────────

test "ds: SHA-384 digest is over the canonical owner name then the DNSKEY rdata" {
    const dnskey_rdata = "\x01\x01\x03\x0e\xaa\xbb\xcc\xdd";
    var st = std.crypto.hash.sha2.Sha384.init(.{});
    st.update("\x03www\x07example\x00");
    st.update(dnskey_rdata);
    var expected: [48]u8 = undefined;
    st.final(&expected);
    var out: [ds.max_digest_len]u8 = undefined;
    const got = try ds.computeDigest("WWW.Example.", dnskey_rdata, rdata.Ds.digest_sha384, &out);
    try testing.expectEqualSlices(u8, &expected, got);
}

test "ds: matches refuses a digest padded with zero octets" {
    const dnskey_rdata = "\x01\x01\x03\x08\xaa";
    var out: [ds.max_digest_len]u8 = undefined;
    const digest = try ds.computeDigest("example", dnskey_rdata, rdata.Ds.digest_sha256, &out);
    var padded: [33]u8 = undefined;
    @memcpy(padded[0..32], digest);
    padded[32] = 0;
    const good: rdata.Ds = .{ .key_tag = 1, .algorithm = 8, .digest_type = rdata.Ds.digest_sha256, .digest = digest };
    const bad: rdata.Ds = .{ .key_tag = 1, .algorithm = 8, .digest_type = rdata.Ds.digest_sha256, .digest = &padded };
    try testing.expect(try ds.matches(good, "example", dnskey_rdata));
    try testing.expect(!(try ds.matches(bad, "example", dnskey_rdata)));
}

// ── policy ──────────────────────────────────────────────────────────────────

test "policy: the RFC 8624 validation tables, row by row" {
    const L = policy.Level;
    const alg_rows = [_]struct { u8, L }{
        .{ 0, .must_not },     .{ 1, .must_not }, .{ 3, .must_not },     .{ 6, .must_not },
        .{ 5, .must },         .{ 7, .must },     .{ 8, .must },         .{ 10, .must },
        .{ 13, .must },        .{ 12, .may },     .{ 14, .recommended }, .{ 15, .recommended },
        .{ 16, .recommended },
    };
    for (alg_rows) |r| try testing.expectEqual(@as(?L, r[1]), policy.algorithmLevel(r[0]));
    const dig_rows = [_]struct { u8, L }{ .{ 0, .must_not }, .{ 1, .must }, .{ 2, .must }, .{ 3, .may }, .{ 4, .recommended } };
    for (dig_rows) |r| try testing.expectEqual(@as(?L, r[1]), policy.digestLevel(r[0]));
    // The default policy refuses exactly the MUST NOT rows, on the allowed table itself
    // (an unimplemented algorithm is unsupported for a second reason, which hides this).
    for (0..256) |i| {
        const a: u8 = @intCast(i);
        const refused = policy.algorithmLevel(a) == .must_not;
        try testing.expectEqual(!refused, policy.Policy.rfc8624.algorithm_allowed[i]);
        const d_refused = policy.digestLevel(a) == .must_not;
        try testing.expectEqual(!d_refused, policy.Policy.rfc8624.digest_allowed[i]);
    }
}

test "policy: implemented sets and overrides" {
    for ([_]u8{ 5, 7, 8, 10, 13, 14, 15, 16 }) |a| try testing.expect(policy.algorithmImplemented(a));
    for ([_]u8{ 0, 1, 3, 6, 12, 200 }) |a| try testing.expect(!policy.algorithmImplemented(a));
    for ([_]u8{ 1, 2, 4 }) |d| try testing.expect(policy.digestImplemented(d));
    for ([_]u8{ 0, 3, 5 }) |d| try testing.expect(!policy.digestImplemented(d));
    // withAlgorithm / withDigest set exactly the asked value, both ways.
    const p = policy.Policy.rfc8624.withAlgorithm(8, false).withAlgorithm(6, true).withDigest(2, false).withDigest(0, true);
    try testing.expect(!p.algorithm_allowed[8]);
    try testing.expect(p.algorithm_allowed[6]);
    try testing.expect(!p.digest_allowed[2]);
    try testing.expect(p.digest_allowed[0]);
    // Support needs BOTH the allowance and the implementation.
    try testing.expect(!p.isAlgorithmSupported(8));
    try testing.expect(!p.isAlgorithmSupported(6));
    try testing.expect(!p.isDigestSupported(2));
    try testing.expect(!p.isDigestSupported(0));
    try testing.expect(p.isDigestSupported(1));
}

// ── rdata ───────────────────────────────────────────────────────────────────

test "rdata: the zone-key and secure-entry-point bits are read apart" {
    const zsk = try rdata.parseDnskey("\x01\x00\x03\x08\xaa");
    try testing.expect(zsk.isZoneKey() and !zsk.isSecureEntryPoint());
    const sep_only = try rdata.parseDnskey("\x00\x01\x03\x08\xaa");
    try testing.expect(!sep_only.isZoneKey() and sep_only.isSecureEntryPoint());
}

test "rdata: keyTag of a two-octet algorithm-1 key is those two octets" {
    try testing.expectEqual(@as(u16, 0xabcd), rdata.keyTag("\xab\xcd", 1));
    try testing.expectEqual(@as(u16, 0), rdata.keyTag("\xab", 1));
}

test "rdata: an RRSIG with an empty signature parses" {
    const raw = "\x00\x01\x08\x02\x00\x00\x0e\x10\x00\x00\x07\xd0\x00\x00\x03\xe8\x00\x07" ++ "\x00";
    const s = try rdata.parseRrsig(testing.allocator, raw);
    defer testing.allocator.free(s.signer_name);
    try testing.expectEqual(@as(usize, 0), s.signature.len);
    try testing.expectEqual(@as(usize, 0), s.signer_name.len);
}

test "rdata: type bit maps over several windows (contains, iterator, parse limits)" {
    // Window 0: type 1 (A); window 1: type 257 (CAA = 0x0101); window 3: type 769.
    const raw = "\x00\x01\x40" ++ "\x01\x01\x40" ++ "\x03\x01\x40";
    const map = try rdata.parseTypeBitMap(raw);
    try testing.expect(map.contains(1));
    try testing.expect(map.contains(257));
    try testing.expect(map.contains(769));
    try testing.expect(!map.contains(2));
    try testing.expect(!map.contains(258));
    try testing.expect(!map.contains(513)); // window 2 is absent
    var it = map.iterator();
    try testing.expectEqual(@as(?u16, 1), it.next());
    try testing.expectEqual(@as(?u16, 257), it.next());
    try testing.expectEqual(@as(?u16, 769), it.next());
    try testing.expectEqual(@as(?u16, null), it.next());
    // A window with zero length is not a valid encoding; neither is a truncated header.
    try testing.expectError(error.BadRecord, rdata.parseTypeBitMap("\x00\x00"));
    try testing.expectError(error.Truncated, rdata.parseTypeBitMap("\x00"));
    // The longest legal window (32 octets) parses, 33 does not.
    const w33 = [_]u8{ 0, 33 } ++ @as([33]u8, @splat(0));
    try testing.expectError(error.BadRecord, rdata.parseTypeBitMap(&w33));
    const w32 = [_]u8{ 0, 32 } ++ @as([32]u8, @splat(0x80));
    _ = try rdata.parseTypeBitMap(&w32);
}

test "rdata: NSEC with no type bit map, NSEC3 with an empty next hash" {
    const n = try rdata.parseNsec(testing.allocator, "\x01a\x00");
    defer testing.allocator.free(n.next_domain_name);
    try testing.expectEqualStrings("a", n.next_domain_name);
    try testing.expectEqual(@as(usize, 0), n.types.raw.len);
    const n3 = try rdata.parseNsec3("\x01\x00\x00\x0a\x00" ++ "\x00");
    try testing.expectEqual(@as(usize, 0), n3.next_hashed_owner_name.len);
    try testing.expectEqual(@as(u16, 10), n3.iterations);
    // Exactly the hash and no bitmap.
    const n3b = try rdata.parseNsec3("\x01\x01\x00\x00\x00" ++ "\x02ab");
    try testing.expectEqualStrings("ab", n3b.next_hashed_owner_name);
    try testing.expect(n3b.optOut());
    try testing.expect(!(try rdata.parseNsec3("\x01\x02\x00\x00\x00\x00")).optOut());
}

test "rdata: NSEC3PARAM exact length, iterations and salt offsets" {
    const p = try rdata.parseNsec3Param("\x01\x00\x01\x02\x02\xaa\xbb");
    try testing.expectEqual(@as(u16, 0x0102), p.iterations);
    try testing.expectEqualSlices(u8, "\xaa\xbb", p.salt);
    const empty = try rdata.parseNsec3Param("\x01\x00\x00\x00\x00");
    try testing.expectEqual(@as(usize, 0), empty.salt.len);
    try testing.expectError(error.BadRecord, rdata.parseNsec3Param("\x01\x00\x00\x00\x01\xaa\xbb"));
}

// ── keys ────────────────────────────────────────────────────────────────────

fn rsaWireKey(e_form_long: bool, buf: *[70]u8) []const u8 {
    var n: usize = 0;
    if (e_form_long) {
        buf[0] = 0;
        std.mem.writeInt(u16, buf[1..3], 3, .big);
        @memcpy(buf[3..6], "\x00\x01\x01");
        n = 6;
    } else {
        buf[0] = 1;
        buf[1] = 3;
        n = 2;
    }
    @memset(buf[n .. n + 64], 0xab);
    return buf[0 .. n + 64];
}

test "keys: every RSA algorithm number decodes an RSA key, the long form keeps its exponent" {
    var buf: [70]u8 = undefined;
    const short = rsaWireKey(false, &buf);
    for ([_]u8{ 5, 7, 8, 10 }) |a| {
        const k = try keys.decodePublicKey(a, short);
        try testing.expectEqual(@as(u32, 3), try k.rsa.e.toPrimitive(u32));
    }
    var buf2: [70]u8 = undefined;
    const long = rsaWireKey(true, &buf2);
    const lk = try keys.decodePublicKey(8, long);
    try testing.expectEqual(@as(u32, 257), try lk.rsa.e.toPrimitive(u32));
    // No modulus at all.
    try testing.expectError(error.InvalidKeyEncoding, keys.decodePublicKey(8, "\x01\x03"));
    try testing.expectError(error.InvalidKeyEncoding, keys.decodePublicKey(8, ""));
    try testing.expectError(error.InvalidKeyEncoding, keys.decodePublicKey(8, "\x00\x00"));
}

test "keys: a key one octet too long is refused for every fixed-length algorithm" {
    const zeros: [97]u8 = @splat(0);
    try testing.expectError(error.InvalidKeyEncoding, keys.decodePublicKey(13, zeros[0..65]));
    try testing.expectError(error.InvalidKeyEncoding, keys.decodePublicKey(14, zeros[0..97]));
    try testing.expectError(error.InvalidKeyEncoding, keys.decodePublicKey(15, zeros[0..33]));
}

test "keys: ECDSA and Ed25519 error classes and signature lengths" {
    {
        const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
        const kp = try Ecdsa.KeyPair.generateDeterministic(@as([32]u8, @splat(7)));
        const sig = (try kp.sign("msg", null)).toBytes();
        const c = kp.public_key.p.affineCoordinates();
        var wk: [64]u8 = undefined;
        @memcpy(wk[0..32], &c.x.toBytes(.big));
        @memcpy(wk[32..64], &c.y.toBytes(.big));
        const key = try keys.decodePublicKey(13, &wk);
        try keys.verifySignature(13, key, "msg", &sig);
        try testing.expectError(error.SignatureVerificationFailed, keys.verifySignature(13, key, "other", &sig));
        var longer: [65]u8 = undefined;
        @memcpy(longer[0..64], &sig);
        longer[64] = 0;
        try testing.expectError(error.InvalidSignatureEncoding, keys.verifySignature(13, key, "msg", &longer));
    }
    {
        const Ecdsa = std.crypto.sign.ecdsa.EcdsaP384Sha384;
        const kp = try Ecdsa.KeyPair.generateDeterministic(@as([48]u8, @splat(9)));
        const sig = (try kp.sign("msg", null)).toBytes();
        const c = kp.public_key.p.affineCoordinates();
        var wk: [96]u8 = undefined;
        @memcpy(wk[0..48], &c.x.toBytes(.big));
        @memcpy(wk[48..96], &c.y.toBytes(.big));
        const key = try keys.decodePublicKey(14, &wk);
        try keys.verifySignature(14, key, "msg", &sig);
        try testing.expectError(error.SignatureVerificationFailed, keys.verifySignature(14, key, "other", &sig));
        var longer: [97]u8 = undefined;
        @memcpy(longer[0..96], &sig);
        longer[96] = 0;
        try testing.expectError(error.InvalidSignatureEncoding, keys.verifySignature(14, key, "msg", &longer));
    }
    {
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(3)));
        const sig = (try kp.sign("msg", null)).toBytes();
        const pk = kp.public_key.toBytes();
        const key = try keys.decodePublicKey(15, &pk);
        var longer: [65]u8 = undefined;
        @memcpy(longer[0..64], &sig);
        longer[64] = 0;
        try testing.expectError(error.InvalidSignatureEncoding, keys.verifySignature(15, key, "msg", &longer));
    }
}

test "keys: RSA PKCS#1 v1.5 under SHA-1, SHA-256 and SHA-512 (algorithms 5, 7, 8, 10)" {
    // 768 bits: the smallest size that fits SHA-512's 83-octet DigestInfo.
    const kp = try testing.allocator.create(rsa.KeyPair);
    defer {
        std.crypto.secureZero(u8, std.mem.asBytes(kp));
        testing.allocator.destroy(kp);
    }
    var prng = std.Random.DefaultPrng.init(0x5eed_d551);
    try rsa.generate(kp, prng.random(), 768, 65537);
    const key: keys.DecodedKey = .{ .rsa = kp.public_key };
    var out: [96]u8 = undefined;

    const s1 = try rsa.signPkcs1v15(&kp.secret_key, std.crypto.hash.Sha1, "signed data", &out);
    var sig1: [96]u8 = undefined;
    @memcpy(sig1[0..s1.len], s1);
    const s256 = try rsa.signPkcs1v15(&kp.secret_key, std.crypto.hash.sha2.Sha256, "signed data", &out);
    var sig256: [96]u8 = undefined;
    @memcpy(sig256[0..s256.len], s256);
    const s512 = try rsa.signPkcs1v15(&kp.secret_key, std.crypto.hash.sha2.Sha512, "signed data", &out);
    var sig512: [96]u8 = undefined;
    @memcpy(sig512[0..s512.len], s512);

    for ([_]struct { u8, []const u8 }{ .{ 5, sig1[0..s1.len] }, .{ 7, sig1[0..s1.len] }, .{ 8, sig256[0..s256.len] }, .{ 10, sig512[0..s512.len] } }) |c| {
        try keys.verifySignature(c[0], key, "signed data", c[1]);
        try testing.expectError(error.SignatureVerificationFailed, keys.verifySignature(c[0], key, "other data", c[1]));
    }
    // A signature made under another hash does not verify.
    try testing.expectError(error.SignatureVerificationFailed, keys.verifySignature(5, key, "signed data", sig256[0..s256.len]));
    try testing.expectError(error.SignatureVerificationFailed, keys.verifySignature(8, key, "signed data", sig512[0..s512.len]));
    try testing.expectError(error.SignatureVerificationFailed, keys.verifySignature(10, key, "signed data", sig256[0..s256.len]));
}

// ── canonical ───────────────────────────────────────────────────────────────

const rrsig_hdr_len = 18;
const signer_example = "\x07example\x00";

fn sigFor(ty: dns.Type, labels: u8) rdata.Rrsig {
    return .{
        .type_covered = @backingInt(ty),
        .algorithm = 8,
        .labels = labels,
        .original_ttl = 0x01020304,
        .expiration = 0,
        .inception = 0,
        .key_tag = 0,
        .signer_name = "example",
        .signature = "",
    };
}

fn expectRdata(ty: dns.Type, data: dns.Record.Data, want_rdata: []const u8) !void {
    const owner = "www.Example";
    const rr = [_]dns.Record{.{ .name = owner, .ty = ty, .class = .in, .ttl = 7, .data = data }};
    const got = try canonical.buildSignedData(testing.allocator, &rr, sigFor(ty, 2), owner);
    defer testing.allocator.free(got);
    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(testing.allocator);
    const t: u16 = @backingInt(ty);
    try want.appendSlice(testing.allocator, &.{ @intCast(t >> 8), @intCast(t & 0xff), 8, 2, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
    try want.appendSlice(testing.allocator, signer_example);
    try want.appendSlice(testing.allocator, "\x03www\x07example\x00");
    try want.appendSlice(testing.allocator, &.{ @intCast(t >> 8), @intCast(t & 0xff), 0, 1, 1, 2, 3, 4 });
    try want.appendSlice(testing.allocator, &.{ @intCast(want_rdata.len >> 8), @intCast(want_rdata.len & 0xff) });
    try want.appendSlice(testing.allocator, want_rdata);
    try testing.expectEqualSlices(u8, want.items, got);
}

test "canonical: AAAA, CNAME, PTR, NS, TXT, SRV and CAA rdata, byte for byte" {
    try expectRdata(.aaaa, .{ .aaaa = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 } }, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10");
    try expectRdata(.cname, .{ .cname = "Foo.Example." }, "\x03foo\x07example\x00");
    try expectRdata(.ptr, .{ .ptr = "P.Example" }, "\x01p\x07example\x00");
    try expectRdata(.ns, .{ .ns = "NS1.Example" }, "\x03ns1\x07example\x00");
    try expectRdata(.txt, .{ .txt = &.{ "ab", "c", "" } }, "\x02ab\x01c\x00");
    try expectRdata(.srv, .{ .srv = .{ .priority = 1, .weight = 2, .port = 3, .target = "T.Example" } }, "\x00\x01\x00\x02\x00\x03\x01t\x07example\x00");
    try expectRdata(.caa, .{ .caa = .{ .flags = 128, .tag = "issue", .value = "ca.example" } }, "\x80\x05issueca.example");
    try expectRdata(.caa, .{ .caa = .{ .flags = 0, .tag = "iodef", .value = "" } }, "\x00\x05iodef");
}

test "canonical: TXT strings and CAA tags of 255 octets are signable, 256 are not" {
    const s255: [255]u8 = @splat('x');
    const s256: [256]u8 = @splat('x');
    const owner = "a.example";
    const one: [1][]const u8 = .{&s255};
    const rr_ok = [_]dns.Record{.{ .name = owner, .ty = .txt, .class = .in, .ttl = 1, .data = .{ .txt = &one } }};
    const ok = try canonical.buildSignedData(testing.allocator, &rr_ok, sigFor(.txt, 2), owner);
    testing.allocator.free(ok);
    const two: [1][]const u8 = .{&s256};
    const rr_bad = [_]dns.Record{.{ .name = owner, .ty = .txt, .class = .in, .ttl = 1, .data = .{ .txt = &two } }};
    try testing.expectError(error.InconsistentRrset, canonical.buildSignedData(testing.allocator, &rr_bad, sigFor(.txt, 2), owner));

    const caa_ok = [_]dns.Record{.{ .name = owner, .ty = .caa, .class = .in, .ttl = 1, .data = .{ .caa = .{ .flags = 0, .tag = &s255, .value = "" } } }};
    const c = try canonical.buildSignedData(testing.allocator, &caa_ok, sigFor(.caa, 2), owner);
    testing.allocator.free(c);
    const caa_bad = [_]dns.Record{.{ .name = owner, .ty = .caa, .class = .in, .ttl = 1, .data = .{ .caa = .{ .flags = 0, .tag = &s256, .value = "" } } }};
    try testing.expectError(error.InconsistentRrset, canonical.buildSignedData(testing.allocator, &caa_bad, sigFor(.caa, 2), owner));
}

test "canonical: an RDATA of 65535 octets is signable, 65536 is not; OPT never is" {
    const big = try testing.allocator.alloc(u8, 65536);
    defer testing.allocator.free(big);
    @memset(big, 0x42);
    const owner = "a.example";
    const rr_ok = [_]dns.Record{.{ .name = owner, .ty = @fromBackingInt(99), .class = .in, .ttl = 1, .data = .{ .unknown = big[0..65535] } }};
    const ok = try canonical.buildSignedData(testing.allocator, &rr_ok, sigFor(@fromBackingInt(99), 2), owner);
    testing.allocator.free(ok);
    const rr_bad = [_]dns.Record{.{ .name = owner, .ty = @fromBackingInt(99), .class = .in, .ttl = 1, .data = .{ .unknown = big } }};
    try testing.expectError(error.InconsistentRrset, canonical.buildSignedData(testing.allocator, &rr_bad, sigFor(@fromBackingInt(99), 2), owner));
    const rr_opt = [_]dns.Record{.{ .name = owner, .ty = .opt, .class = .in, .ttl = 1, .data = .{ .opt = .{ .udp_payload_size = 1232, .extended_rcode = 0, .version = 0, .dnssec_ok = true, .options = "" } } }};
    try testing.expectError(error.NotSignable, canonical.buildSignedData(testing.allocator, &rr_opt, sigFor(.opt, 2), owner));
}

test "canonical: RRset consistency (empty, type, class, owner) and the label cross-check" {
    const owner = "a.example";
    const a: dns.Record = .{ .name = owner, .ty = .a, .class = .in, .ttl = 1, .data = .{ .a = .{ 1, 1, 1, 1 } } };
    try testing.expectError(error.InconsistentRrset, canonical.buildSignedData(testing.allocator, &.{}, sigFor(.a, 2), owner));

    var other_type = a;
    other_type.ty = .aaaa;
    other_type.data = .{ .aaaa = @as([16]u8, @splat(0)) };
    try testing.expectError(error.InconsistentRrset, canonical.buildSignedData(testing.allocator, &.{ a, other_type }, sigFor(.a, 2), owner));

    var other_class = a;
    other_class.class = .ch;
    try testing.expectError(error.InconsistentRrset, canonical.buildSignedData(testing.allocator, &.{ a, other_class }, sigFor(.a, 2), owner));

    var other_owner = a;
    other_owner.name = "b.example";
    try testing.expectError(error.InconsistentRrset, canonical.buildSignedData(testing.allocator, &.{other_owner}, sigFor(.a, 2), owner));

    // Owners compare without case and without one trailing dot.
    var shouting = a;
    shouting.name = "A.EXAMPLE.";
    const ok = try canonical.buildSignedData(testing.allocator, &.{shouting}, sigFor(.a, 2), owner);
    testing.allocator.free(ok);

    // A populated label list must count what the text counts, in BOTH directions.
    const too_many = [_][]const u8{ "a", "b", "c" };
    var l = a;
    l.name = "a.b";
    l.labels = &too_many;
    try testing.expectError(error.InconsistentRrset, canonical.buildSignedData(testing.allocator, &.{l}, sigFor(.a, 2), "a.b"));
    // ... and a root record (no labels) with a populated empty list is the root, not "unknown".
    const none: []const []const u8 = &.{};
    var root_rec = a;
    root_rec.name = ".";
    root_rec.labels = none;
    const rt = try canonical.buildSignedData(testing.allocator, &.{root_rec}, sigFor(.a, 0), ".");
    testing.allocator.free(rt);
}

test "canonical: stripDot removes exactly one trailing dot" {
    try testing.expectEqualStrings("example", canonical.stripDot("example."));
    try testing.expectEqualStrings("a.", canonical.stripDot("a.."));
    try testing.expectEqualStrings("", canonical.stripDot("."));
    try testing.expectEqualStrings("", canonical.stripDot(""));
}

test "canonical: wildcard and root owners are signed under the right name" {
    // Root owner, zero labels: the owner is "." (one zero octet), not a wildcard.
    const root_rr = [_]dns.Record{.{ .name = ".", .ty = .a, .class = .in, .ttl = 1, .data = .{ .a = .{ 1, 2, 3, 4 } } }};
    const r = try canonical.buildSignedData(testing.allocator, &root_rr, sigFor(.a, 0), ".");
    defer testing.allocator.free(r);
    try testing.expectEqual(@as(usize, rrsig_hdr_len + signer_example.len + 1 + 2 + 2 + 4 + 2 + 4), r.len);
    try testing.expectEqual(@as(u8, 0), r[rrsig_hdr_len + signer_example.len]);

    // A name synthesized from a wildcard at the root: "*" and nothing else.
    const w0 = [_]dns.Record{.{ .name = "a.b", .ty = .a, .class = .in, .ttl = 1, .data = .{ .a = .{ 1, 2, 3, 4 } } }};
    const g0 = try canonical.buildSignedData(testing.allocator, &w0, sigFor(.a, 0), "a.b");
    defer testing.allocator.free(g0);
    try testing.expectEqualSlices(u8, "\x01*\x00", g0[rrsig_hdr_len + signer_example.len ..][0..3]);
    // One label kept: "*.b".
    const g1 = try canonical.buildSignedData(testing.allocator, &w0, sigFor(.a, 1), "a.b");
    defer testing.allocator.free(g1);
    try testing.expectEqualSlices(u8, "\x01*\x01b\x00", g1[rrsig_hdr_len + signer_example.len ..][0..5]);
}

// ── signing helpers for validate / chain ────────────────────────────────────

const Ed = struct {
    kp: std.crypto.sign.Ed25519.KeyPair,
    raw: [36]u8,

    fn init(seed_byte: u8, flags: u16) !Ed {
        var s: [32]u8 = undefined;
        for (&s, 0..) |*b, i| b.* = seed_byte +% @as(u8, @intCast(i));
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(s);
        var raw: [36]u8 = undefined;
        std.mem.writeInt(u16, raw[0..2], flags, .big);
        raw[2] = 3;
        raw[3] = 15;
        const pk = kp.public_key.toBytes();
        @memcpy(raw[4..], &pk);
        return .{ .kp = kp, .raw = raw };
    }

    fn dnskey(self: *const Ed) rdata.Dnskey {
        return rdata.parseDnskey(&self.raw) catch unreachable;
    }
};

const ValidateFixture = struct {
    rrset: [1]dns.Record,
    rrsig: rdata.Rrsig,
    sig: [64]u8,
};

/// An A RRset at `owner`, signed by `ed` as `signer` with `labels`, covering `covered`.
fn signA(ed: *const Ed, owner: []const u8, signer: []const u8, labels: u8, covered: u16, out: *ValidateFixture) !void {
    out.rrset[0] = .{ .name = owner, .ty = .a, .class = .in, .ttl = 300, .data = .{ .a = .{ 1, 2, 3, 4 } } };
    out.rrsig = .{
        .type_covered = covered,
        .algorithm = 15,
        .labels = labels,
        .original_ttl = 300,
        .expiration = 2000,
        .inception = 1000,
        .key_tag = rdata.keyTag(&ed.raw, 15),
        .signer_name = signer,
        .signature = "",
    };
    const signed = try canonical.buildSignedData(testing.allocator, &out.rrset, out.rrsig, owner);
    defer testing.allocator.free(signed);
    out.sig = (try ed.kp.sign(signed, null)).toBytes();
    out.rrsig.signature = &out.sig;
}

fn validateWith(ed: *const Ed, f: *const ValidateFixture, owner: []const u8, anchor: chain.TrustAnchor) !root.ValidationResult {
    return root.validate(testing.allocator, &f.rrset, f.rrsig, owner, ed.dnskey(), anchor, .{ .now = 1500 });
}

test "validate: the positive control the next tests perturb" {
    const ed = try Ed.init(1, 0x0100);
    var f: ValidateFixture = undefined;
    try signA(&ed, "www.example.com", "example.com", 3, 1, &f);
    try testing.expectEqual(root.ValidationResult.secure, try validateWith(&ed, &f, "www.example.com", .{ .dnskey_rdata = &ed.raw }));
}

test "validate: each precondition refuses on its own" {
    const ed = try Ed.init(1, 0x0100);
    const anchor: chain.TrustAnchor = .{ .dnskey_rdata = &ed.raw };
    var f: ValidateFixture = undefined;

    // The RRSIG covers another type than the RRset holds (signature valid over what it claims).
    try signA(&ed, "www.example.com", "example.com", 3, 28, &f);
    try testing.expectEqual(root.ValidationResult.bogus, try validateWith(&ed, &f, "www.example.com", anchor));

    // A key without the zone-key bit.
    const nozone = try Ed.init(1, 0x0000);
    try signA(&nozone, "www.example.com", "example.com", 3, 1, &f);
    try testing.expectEqual(root.ValidationResult.bogus, try validateWith(&nozone, &f, "www.example.com", .{ .dnskey_rdata = &nozone.raw }));

    // A pinned anchor that is a different key.
    const other = try Ed.init(77, 0x0100);
    try signA(&ed, "www.example.com", "example.com", 3, 1, &f);
    try testing.expectEqual(root.ValidationResult.bogus, try validateWith(&ed, &f, "www.example.com", .{ .dnskey_rdata = &other.raw }));

    // An empty RRset has nothing to be secure.
    try testing.expectEqual(root.ValidationResult.bogus, try root.validate(testing.allocator, &.{}, f.rrsig, "www.example.com", ed.dnskey(), anchor, .{ .now = 1500 }));

    // The window is inclusive at both ends and refused one second outside.
    try testing.expectEqual(root.ValidationResult.secure, try root.validate(testing.allocator, &f.rrset, f.rrsig, "www.example.com", ed.dnskey(), anchor, .{ .now = 1000 }));
    try testing.expectEqual(root.ValidationResult.secure, try root.validate(testing.allocator, &f.rrset, f.rrsig, "www.example.com", ed.dnskey(), anchor, .{ .now = 2000 }));
    try testing.expectEqual(root.ValidationResult.bogus, try root.validate(testing.allocator, &f.rrset, f.rrsig, "www.example.com", ed.dnskey(), anchor, .{ .now = 999 }));
    try testing.expectEqual(root.ValidationResult.bogus, try root.validate(testing.allocator, &f.rrset, f.rrsig, "www.example.com", ed.dnskey(), anchor, .{ .now = 2001 }));
}

test "validate: a DS anchor is the DS of the SIGNER's zone, not of the owner name" {
    const ed = try Ed.init(5, 0x0101);
    var f: ValidateFixture = undefined;
    try signA(&ed, "www.example.com", "example.com", 3, 1, &f);
    var dbuf: [ds.max_digest_len]u8 = undefined;
    const digest = try ds.computeDigest("example.com", &ed.raw, rdata.Ds.digest_sha256, &dbuf);
    const anchor: chain.TrustAnchor = .{ .ds = .{ .key_tag = rdata.keyTag(&ed.raw, 15), .algorithm = 15, .digest_type = rdata.Ds.digest_sha256, .digest = digest } };
    try testing.expectEqual(root.ValidationResult.secure, try validateWith(&ed, &f, "www.example.com", anchor));
}

test "validate: the Labels field may equal, never exceed, the owner's label count (trailing dot, root)" {
    const ed = try Ed.init(9, 0x0100);
    const anchor: chain.TrustAnchor = .{ .dnskey_rdata = &ed.raw };
    var f: ValidateFixture = undefined;
    // A trailing dot is not a label: three labels claimed over two.
    try signA(&ed, "example.com.", "example.com", 3, 1, &f);
    try testing.expectEqual(root.ValidationResult.bogus, try validateWith(&ed, &f, "example.com.", anchor));
    try signA(&ed, "example.com.", "example.com", 2, 1, &f);
    try testing.expectEqual(root.ValidationResult.secure, try validateWith(&ed, &f, "example.com.", anchor));
    // The root has no labels.
    try signA(&ed, ".", ".", 1, 1, &f);
    try testing.expectEqual(root.ValidationResult.bogus, try validateWith(&ed, &f, ".", anchor));
    try signA(&ed, ".", ".", 0, 1, &f);
    try testing.expectEqual(root.ValidationResult.secure, try validateWith(&ed, &f, ".", anchor));
}

// ── chain ───────────────────────────────────────────────────────────────────

/// Sign the one-key DNSKEY RRset of `zone` with that key; `labels` goes into the RRSIG.
fn selfSigned(ed: *const Ed, zone: []const u8, signer: []const u8, labels: u8, sig_out: *[64]u8) !rdata.Rrsig {
    var s: rdata.Rrsig = .{
        .type_covered = rdata.rr_type.dnskey,
        .algorithm = 15,
        .labels = labels,
        .original_ttl = 3600,
        .expiration = 2000,
        .inception = 1000,
        .key_tag = rdata.keyTag(&ed.raw, 15),
        .signer_name = signer,
        .signature = "",
    };
    const recs = [_]dns.Record{.{ .name = zone, .ty = @fromBackingInt(48), .class = .in, .ttl = 0, .data = .{ .unknown = &ed.raw } }};
    const signed = try canonical.buildSignedData(testing.allocator, &recs, s, zone);
    defer testing.allocator.free(signed);
    sig_out.* = (try ed.kp.sign(signed, null)).toBytes();
    s.signature = sig_out;
    return s;
}

test "chain: a self-signed DNSKEY set under a pinned anchor, and what refuses it" {
    const ed = try Ed.init(11, 0x0101);
    var sig: [64]u8 = undefined;
    const rrsig = try selfSigned(&ed, "example.com", "example.com", 2, &sig);
    const one_key = [_][]const u8{&ed.raw};
    const set: []const []const u8 = &one_key;
    const pinned: chain.TrustAnchor = .{ .dnskey_rdata = &ed.raw };
    try testing.expectEqual(chain.ChainResult.secure, try chain.validateDnskeySet(testing.allocator, "example.com", set, rrsig, pinned));

    // A prefix of the key is not the key.
    try testing.expectEqual(chain.ChainResult.bogus, try chain.validateDnskeySet(testing.allocator, "example.com", set, rrsig, .{ .dnskey_rdata = ed.raw[0..35] }));
    // An anchor too short to parse is not unsupported: the set just is not vouched for.
    try testing.expectEqual(chain.ChainResult.bogus, try chain.validateDnskeySet(testing.allocator, "example.com", set, rrsig, .{ .dnskey_rdata = "\x01" }));
    // An anchor of an unsupported algorithm: insecure, even before the empty-set check.
    const dsa: chain.TrustAnchor = .{ .ds = .{ .key_tag = 1, .algorithm = 3, .digest_type = 2, .digest = "" } };
    try testing.expectEqual(chain.ChainResult.insecure, try chain.validateDnskeySet(testing.allocator, "example.com", set, rrsig, dsa));
    try testing.expectEqual(chain.ChainResult.bogus, try chain.validateDnskeySet(testing.allocator, "example.com", &.{}, rrsig, dsa));
    // The same for a DS naming an unsupported digest type, with a supported algorithm.
    const gost: chain.TrustAnchor = .{ .ds = .{ .key_tag = 1, .algorithm = 15, .digest_type = 3, .digest = "" } };
    try testing.expectEqual(chain.ChainResult.insecure, try chain.validateDnskeySet(testing.allocator, "example.com", set, rrsig, gost));
    // ... and for a supported digest type with an unsupported algorithm (each half counts alone).
    const dsa_sha: chain.TrustAnchor = .{ .ds = .{ .key_tag = 1, .algorithm = 1, .digest_type = 2, .digest = "" } };
    try testing.expectEqual(chain.ChainResult.insecure, try chain.validateDnskeySet(testing.allocator, "example.com", set, rrsig, dsa_sha));
}

test "chain: a matched key without the zone-key bit does not vouch for the set" {
    const ed = try Ed.init(13, 0x0000);
    var sig: [64]u8 = undefined;
    const rrsig = try selfSigned(&ed, "example.com", "example.com", 2, &sig);
    const one_key = [_][]const u8{&ed.raw};
    const set: []const []const u8 = &one_key;
    try testing.expectEqual(chain.ChainResult.bogus, try chain.validateDnskeySet(testing.allocator, "example.com", set, rrsig, .{ .dnskey_rdata = &ed.raw }));
}

test "chain: apex labels count without the trailing dot, the root has none" {
    const ed = try Ed.init(15, 0x0101);
    var sig: [64]u8 = undefined;
    const one_key = [_][]const u8{&ed.raw};
    const set: []const []const u8 = &one_key;
    const pinned: chain.TrustAnchor = .{ .dnskey_rdata = &ed.raw };
    const a = try selfSigned(&ed, "example.com.", "example.com", 2, &sig);
    try testing.expectEqual(chain.ChainResult.secure, try chain.validateDnskeySet(testing.allocator, "example.com.", set, a, pinned));
    const r = try selfSigned(&ed, ".", ".", 0, &sig);
    try testing.expectEqual(chain.ChainResult.secure, try chain.validateDnskeySet(testing.allocator, ".", set, r, pinned));
    // Labels must equal the apex's count in both directions.
    const lo = try selfSigned(&ed, "example.com", "example.com", 1, &sig);
    try testing.expectEqual(chain.ChainResult.bogus, try chain.validateDnskeySet(testing.allocator, "example.com", set, lo, pinned));
    const hi = try selfSigned(&ed, "example.com", "example.com", 3, &sig);
    try testing.expectEqual(chain.ChainResult.bogus, try chain.validateDnskeySet(testing.allocator, "example.com", set, hi, pinned));
}

test "chain: a DS anchor needs the algorithm, the key tag and a supported, equal digest" {
    const ed = try Ed.init(17, 0x0101);
    var dbuf: [ds.max_digest_len]u8 = undefined;
    const digest = try ds.computeDigest("example.com", &ed.raw, rdata.Ds.digest_sha256, &dbuf);
    const tag = rdata.keyTag(&ed.raw, 15);
    const good: rdata.Ds = .{ .key_tag = tag, .algorithm = 15, .digest_type = rdata.Ds.digest_sha256, .digest = digest };
    try testing.expect(chain.anchorMatches(.{ .ds = good }, "example.com", &ed.raw));
    var bad_alg = good;
    bad_alg.algorithm = 14;
    try testing.expect(!chain.anchorMatches(.{ .ds = bad_alg }, "example.com", &ed.raw));
    var bad_tag = good;
    bad_tag.key_tag = tag +% 1;
    try testing.expect(!chain.anchorMatches(.{ .ds = bad_tag }, "example.com", &ed.raw));
    var bad_type = good;
    bad_type.digest_type = 99;
    try testing.expect(!chain.anchorMatches(.{ .ds = bad_type }, "example.com", &ed.raw));
    try testing.expect(!chain.anchorMatches(.{ .ds = good }, "example.com", "\x01"));
}

// ── nsec ────────────────────────────────────────────────────────────────────

/// A single-window (window 0) type bit map over `types` (each < 256).
fn tbm(buf: *[34]u8, types: []const u8) rdata.TypeBitMap {
    var maxb: u8 = 0;
    for (types) |t| maxb = @max(maxb, t);
    const nbytes: usize = maxb / 8 + 1;
    buf[0] = 0;
    buf[1] = @intCast(nbytes);
    @memset(buf[2 .. 2 + nbytes], 0);
    for (types) |t| buf[2 + t / 8] |= @as(u8, 0x80) >> @intCast(t % 8);
    return .{ .raw = buf[0 .. 2 + nbytes] };
}

fn nrec(owner: []const u8, next: []const u8, types: rdata.TypeBitMap) nsec.NsecRecord {
    return .{ .owner = owner, .rdata = .{ .next_domain_name = next, .types = types } };
}

test "nsec: a DS query at an unsigned delegation is insecure only with NS and neither SOA nor DS" {
    var b: [34]u8 = undefined;
    const ns_only = nrec("child.example", "z.example", tbm(&b, &.{2}));
    try testing.expectEqual(nsec.DenialResult.insecure, nsec.proveDenial("child.example", 43, .{ .records = &.{ns_only} }));
    var b2: [34]u8 = undefined;
    const none = nrec("child.example", "z.example", tbm(&b2, &.{ 46, 47 }));
    try testing.expectEqual(nsec.DenialResult.no_data, nsec.proveDenial("child.example", 43, .{ .records = &.{none} }));
    var b3: [34]u8 = undefined;
    const apex = nrec("child.example", "z.example", tbm(&b3, &.{ 2, 6 }));
    try testing.expectEqual(nsec.DenialResult.no_data, nsec.proveDenial("child.example", 43, .{ .records = &.{apex} }));
    // Another query type at the same delegation is an ordinary NODATA.
    try testing.expectEqual(nsec.DenialResult.no_data, nsec.proveDenial("child.example", 1, .{ .records = &.{ns_only} }));
}

test "nsec: the NODATA bitmap check looks at the queried type and at CNAME" {
    var b: [34]u8 = undefined;
    const has_a = nrec("x.example", "z.example", tbm(&b, &.{1}));
    try testing.expectEqual(nsec.DenialResult.bogus, nsec.proveDenial("x.example", 1, .{ .records = &.{has_a} }));
    try testing.expectEqual(nsec.DenialResult.no_data, nsec.proveDenial("x.example", 28, .{ .records = &.{has_a} }));
    var b2: [34]u8 = undefined;
    const has_cname = nrec("x.example", "z.example", tbm(&b2, &.{5}));
    try testing.expectEqual(nsec.DenialResult.bogus, nsec.proveDenial("x.example", 1, .{ .records = &.{has_cname} }));
}

test "nsec: a wildcard whose bitmap holds only CNAME answers the query" {
    var b: [34]u8 = undefined;
    // *.example covers nx.example itself (owner < qname < next) and matches the wildcard name.
    const w = nrec("*.example", "z.example", tbm(&b, &.{5}));
    try testing.expectEqual(nsec.DenialResult.wildcard_answer, nsec.proveDenial("nx.example", 1, .{ .records = &.{w} }));
    var b2: [34]u8 = undefined;
    const w_a = nrec("*.example", "z.example", tbm(&b2, &.{1}));
    try testing.expectEqual(nsec.DenialResult.wildcard_answer, nsec.proveDenial("nx.example", 1, .{ .records = &.{w_a} }));
    var b3: [34]u8 = undefined;
    const w_other = nrec("*.example", "z.example", tbm(&b3, &.{16}));
    try testing.expectEqual(nsec.DenialResult.no_data, nsec.proveDenial("nx.example", 1, .{ .records = &.{w_other} }));
}

test "nsec: the closest encloser is the longer of the two shared suffixes" {
    // Owner shares two labels with the query, next one: the wildcard under a.example decides.
    var b1: [34]u8 = undefined;
    var b2: [34]u8 = undefined;
    const r1 = nrec("a.example", "z.example", tbm(&b1, &.{2}));
    const w1 = nrec("*.a.example", "b.example", tbm(&b2, &.{1}));
    try testing.expectEqual(nsec.DenialResult.wildcard_answer, nsec.proveDenial("m.a.example", 1, .{ .records = &.{ r1, w1 } }));
    // Owner shares one label, next two: the wildcard under m.example decides.
    var b3: [34]u8 = undefined;
    var b4: [34]u8 = undefined;
    const r2 = nrec("b.example", "x.m.example", tbm(&b3, &.{2}));
    const w2 = nrec("*.m.example", "n.m.example", tbm(&b4, &.{1}));
    try testing.expectEqual(nsec.DenialResult.wildcard_answer, nsec.proveDenial("a.m.example", 1, .{ .records = &.{ r2, w2 } }));
}

test "nsec: a one-record chain (owner == next) covers every other name" {
    var b: [34]u8 = undefined;
    const only = nrec("example", "example", tbm(&b, &.{ 2, 6 }));
    try testing.expectEqual(nsec.DenialResult.name_error, nsec.proveDenial("nx.example", 1, .{ .records = &.{only} }));
}

test "nsec: names with a 63-octet label compare, a 64-octet label does not parse" {
    const l63: [63]u8 = @splat('a');
    const l64: [64]u8 = @splat('a');
    var n63: [80]u8 = undefined;
    const name63 = try std.fmt.bufPrint(&n63, "{s}.example", .{&l63});
    try testing.expect(nsec.namesEqual(name63, name63));
    try testing.expect(nsec.isNameOrDescendant(name63, "example"));
    var n64: [80]u8 = undefined;
    const name64 = try std.fmt.bufPrint(&n64, "{s}.example", .{&l64});
    try testing.expect(!nsec.namesEqual(name64, name64));
    // Case-folded, one trailing dot allowed.
    try testing.expect(nsec.namesEqual("WWW.Example.", "www.example"));
    try testing.expect(!nsec.namesEqual("a.example", "b.example"));
}

// ── nsec3 ───────────────────────────────────────────────────────────────────

fn hashOf(name: []const u8, salt: []const u8, iters: u16) [20]u8 {
    var buf: [wire.max_canonical_wire_len]u8 = undefined;
    const w = wire.encodeCanonicalName(name, &buf) catch unreachable;
    return nsec3.iteratedHash(w, salt, iters);
}

fn plus(h: [20]u8, delta: i8) [20]u8 {
    var out = h;
    var i: usize = out.len;
    if (delta > 0) {
        var carry: u16 = @intCast(delta);
        while (i > 0 and carry != 0) {
            i -= 1;
            const s: u16 = @as(u16, out[i]) + carry;
            out[i] = @intCast(s & 0xff);
            carry = s >> 8;
        }
    } else {
        var borrow: u16 = @intCast(-@as(i16, delta));
        while (i > 0 and borrow != 0) {
            i -= 1;
            const cur: u16 = out[i];
            if (cur >= borrow) {
                out[i] = @intCast(cur - borrow);
                borrow = 0;
            } else {
                out[i] = @intCast(cur + 256 - borrow);
                borrow = 1;
            }
        }
    }
    return out;
}

const Chain3 = struct {
    labels: [8][32]u8 = undefined,
    recs: [8]nsec3.Nsec3Record = undefined,
    types: [8][34]u8 = undefined,
    n: usize = 0,

    fn add(self: *Chain3, owner: [20]u8, next: []const u8, flags: u8, tys: []const u8, alg: u8, iters: u16, salt: []const u8) void {
        const i = self.n;
        const lab = base32.encode(&self.labels[i], &owner, .{ .alphabet = .hex, .pad = false }) catch unreachable;
        self.recs[i] = .{ .owner_hash_label = lab, .rdata = .{
            .hash_algorithm = alg,
            .flags = flags,
            .iterations = iters,
            .salt = salt,
            .next_hashed_owner_name = next,
            .types = tbm(&self.types[i], tys),
        } };
        self.n += 1;
    }

    fn set(self: *const Chain3) nsec3.Nsec3Set {
        return .{ .records = self.recs[0..self.n] };
    }
};

const salt3 = "\xca\xfe";
const iters3: u16 = 3;

/// The record matching `name` whose own gap covers nothing (next = owner + 1).
fn addMatch(c: *Chain3, nexts: *[8][20]u8, name: []const u8, tys: []const u8) void {
    const h = hashOf(name, salt3, iters3);
    nexts[c.n] = plus(h, 1);
    c.add(h, &nexts[c.n], 0, tys, 1, iters3, salt3);
}

/// A record whose gap covers exactly the hash of `name`.
fn addCover(c: *Chain3, nexts: *[8][20]u8, name: []const u8, flags: u8) void {
    const h = hashOf(name, salt3, iters3);
    nexts[c.n] = plus(h, 1);
    c.add(plus(h, -1), &nexts[c.n], flags, &.{}, 1, iters3, salt3);
}

test "nsec3: the next closer name is the one just below the closest encloser, not the query" {
    var c: Chain3 = .{};
    var nexts: [8][20]u8 = undefined;
    addMatch(&c, &nexts, "example", &.{2});
    addCover(&c, &nexts, "c.example", 0); // the next closer name
    addCover(&c, &nexts, "*.example", 0); // the wildcard
    try testing.expectEqual(nsec3.DenialResult.name_error, nsec3.proveDenial("a.b.c.example", 1, c.set(), salt3, iters3));
    // Without the cover of the next closer name (only the wildcard's) it is no proof.
    var d: Chain3 = .{};
    var nexts2: [8][20]u8 = undefined;
    addMatch(&d, &nexts2, "example", &.{2});
    addCover(&d, &nexts2, "*.example", 0);
    try testing.expectEqual(nsec3.DenialResult.bogus, nsec3.proveDenial("a.b.c.example", 1, d.set(), salt3, iters3));
}

test "nsec3: opt-out downgrades, a missing wildcard cover is no proof" {
    var c: Chain3 = .{};
    var nexts: [8][20]u8 = undefined;
    addMatch(&c, &nexts, "example", &.{2});
    addCover(&c, &nexts, "nx.example", 1);
    addCover(&c, &nexts, "*.example", 0);
    try testing.expectEqual(nsec3.DenialResult.insecure, nsec3.proveDenial("nx.example", 1, c.set(), salt3, iters3));
    var d: Chain3 = .{};
    var nexts2: [8][20]u8 = undefined;
    addMatch(&d, &nexts2, "example", &.{2});
    addCover(&d, &nexts2, "nx.example", 0);
    try testing.expectEqual(nsec3.DenialResult.bogus, nsec3.proveDenial("nx.example", 1, d.set(), salt3, iters3));
}

test "nsec3: a next hash equal to the name's hash does not cover it; a short next hash covers nothing" {
    const h_nc = hashOf("nx.example", salt3, iters3);
    // owner far below, next == H(nx.example): the gap is open at the top.
    var c: Chain3 = .{};
    var nexts: [8][20]u8 = undefined;
    addMatch(&c, &nexts, "example", &.{2});
    nexts[1] = h_nc;
    c.add(plus(h_nc, -9), &nexts[1], 0, &.{}, 1, iters3, salt3);
    addCover(&c, &nexts, "*.example", 0);
    try testing.expectEqual(nsec3.DenialResult.bogus, nsec3.proveDenial("nx.example", 1, c.set(), salt3, iters3));
    // A 19-octet next hash is not an NSEC3 next hash, whatever it compares to.
    var d: Chain3 = .{};
    var nexts2: [8][20]u8 = undefined;
    addMatch(&d, &nexts2, "example", &.{2});
    const short: [19]u8 = @splat(0xff);
    d.add(plus(h_nc, -1), &short, 0, &.{}, 1, iters3, salt3);
    addCover(&d, &nexts2, "*.example", 0);
    try testing.expectEqual(nsec3.DenialResult.bogus, nsec3.proveDenial("nx.example", 1, d.set(), salt3, iters3));
}

test "nsec3: only records of the zone's own algorithm, iterations and salt take part" {
    const h = hashOf("www.example", salt3, iters3);
    const next = plus(h, 1);
    const cases = [_]struct { alg: u8, iters: u16, salt: []const u8 }{
        .{ .alg = 2, .iters = iters3, .salt = salt3 },
        .{ .alg = 1, .iters = iters3 + 1, .salt = salt3 },
        .{ .alg = 1, .iters = iters3, .salt = "\xca\xff" },
    };
    for (cases) |k| {
        var c: Chain3 = .{};
        c.add(h, &next, 0, &.{}, k.alg, k.iters, k.salt);
        try testing.expectEqual(nsec3.DenialResult.bogus, nsec3.proveDenial("www.example", 1, c.set(), salt3, iters3));
    }
    // The control: the same record with the zone's parameters is a NODATA.
    var ok: Chain3 = .{};
    ok.add(h, &next, 0, &.{}, 1, iters3, salt3);
    try testing.expectEqual(nsec3.DenialResult.no_data, nsec3.proveDenial("www.example", 1, ok.set(), salt3, iters3));
}

test "nsec3: direct-match NODATA reads the queried type, CNAME, and the delegation shape" {
    var c: Chain3 = .{};
    var nexts: [8][20]u8 = undefined;
    addMatch(&c, &nexts, "www.example", &.{1});
    try testing.expectEqual(nsec3.DenialResult.bogus, nsec3.proveDenial("www.example", 1, c.set(), salt3, iters3));
    try testing.expectEqual(nsec3.DenialResult.no_data, nsec3.proveDenial("www.example", 28, c.set(), salt3, iters3));
    var d: Chain3 = .{};
    addMatch(&d, &nexts, "www.example", &.{5});
    try testing.expectEqual(nsec3.DenialResult.bogus, nsec3.proveDenial("www.example", 1, d.set(), salt3, iters3));
    // DS query: NS alone is an unsigned delegation; no NS, or NS with SOA, is plain NODATA.
    var e1: Chain3 = .{};
    addMatch(&e1, &nexts, "child.example", &.{2});
    try testing.expectEqual(nsec3.DenialResult.insecure, nsec3.proveDenial("child.example", 43, e1.set(), salt3, iters3));
    var e2: Chain3 = .{};
    addMatch(&e2, &nexts, "child.example", &.{ 46, 47 });
    try testing.expectEqual(nsec3.DenialResult.no_data, nsec3.proveDenial("child.example", 43, e2.set(), salt3, iters3));
    var e3: Chain3 = .{};
    addMatch(&e3, &nexts, "child.example", &.{ 2, 6 });
    try testing.expectEqual(nsec3.DenialResult.no_data, nsec3.proveDenial("child.example", 43, e3.set(), salt3, iters3));
}

test "nsec3: a wildcard that exists answers, by type or by CNAME, or is NODATA" {
    var nexts: [8][20]u8 = undefined;
    var c: Chain3 = .{};
    addMatch(&c, &nexts, "example", &.{2});
    addCover(&c, &nexts, "nx.example", 0);
    addMatch(&c, &nexts, "*.example", &.{5});
    try testing.expectEqual(nsec3.DenialResult.wildcard_answer, nsec3.proveDenial("nx.example", 1, c.set(), salt3, iters3));
    var d: Chain3 = .{};
    addMatch(&d, &nexts, "example", &.{2});
    addCover(&d, &nexts, "nx.example", 0);
    addMatch(&d, &nexts, "*.example", &.{1});
    try testing.expectEqual(nsec3.DenialResult.wildcard_answer, nsec3.proveDenial("nx.example", 1, d.set(), salt3, iters3));
    var e: Chain3 = .{};
    addMatch(&e, &nexts, "example", &.{2});
    addCover(&e, &nexts, "nx.example", 0);
    addMatch(&e, &nexts, "*.example", &.{16});
    try testing.expectEqual(nsec3.DenialResult.no_data, nsec3.proveDenial("nx.example", 1, e.set(), salt3, iters3));
}

test "nsec3: the iteration cap is inclusive and one more hash is one more round" {
    const empty: nsec3.Nsec3Set = .{ .records = &.{} };
    try testing.expectEqual(nsec3.DenialResult.bogus, nsec3.proveDenial("a.example", 1, empty, "", 100));
    try testing.expectEqual(nsec3.DenialResult.insecure, nsec3.proveDenial("a.example", 1, empty, "", 101));
    // iteratedHash(k) hashes k+1 times.
    var once: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash("nm", &once, .{});
    var twice: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(&once, &twice, .{});
    try testing.expectEqualSlices(u8, &once, &nsec3.iteratedHash("nm", "", 0));
    try testing.expectEqualSlices(u8, &twice, &nsec3.iteratedHash("nm", "", 1));
}
