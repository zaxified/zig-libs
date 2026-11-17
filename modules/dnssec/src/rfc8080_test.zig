// SPDX-License-Identifier: MIT

//! RFC 8080 §6.2 Ed448 examples (algorithm 16): the two DNSKEY/DS/RRSIG sets
//! for `example.com. MX 10 mail.example.com.` published in the RFC, checked
//! through the public API (key tag, DS digest, `keys` decode + verify and the
//! top-level `validate`). The RFC is the independent oracle: its signatures
//! were produced by other implementations.
//!
//! ⚠ The RFC's RRSIG prints `MX 3 3600 ...` (the algorithm is missing from the
//! presentation form) and the signature was made over Labels = 3 although
//! `example.com` has 2 labels. That value only verifies byte-exactly; RFC 4035
//! §5.3.1 makes it invalid ("Labels ... MUST be less than or equal to the
//! owner name's label count"), so `validate` answers `.bogus` for the RFC's own
//! RRSIG (as Unbound/ldns would), while `keys.verifySignature` over the signed
//! data of that RRSIG confirms the Ed448 arithmetic. Checked independently with
//! OpenSSL 3.5 (`cryptography` Ed448) over the same bytes.

const std = @import("std");
const testing = std.testing;
const dns = @import("dns");

const root = @import("root.zig");
const rdata = @import("rdata.zig");
const chain = @import("chain.zig");
const keys = @import("keys.zig");
const canonical = @import("canonical.zig");
const ds = @import("ds.zig");

const Example = struct {
    /// DNSKEY RDATA: flags 257, protocol 3, algorithm 16, 57-octet key.
    key: [4 + 57]u8,
    key_tag: u16,
    /// DS digest (SHA-256, digest type 2) as printed in the RFC.
    ds_digest: [32]u8,
    sig: [114]u8,
};

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

const ex1: Example = .{
    .key = hex("01010310" ++ "de481139a0e3ae1d07da2ba2c5606b73c8361290412c2746cc79a7f86d8ca533e1a63fce8815471d27cfa1dc751586147092a6d4c0e926d200"),
    .key_tag = 9713,
    .ds_digest = hex("6ccf18d5bc5d7fc2fceb1d59d17321402f2aa8d368048db93dd811f5cb2b19c7"),
    .sig = hex("366734ae018aa6bdc62985dc075266aaa4b8358c2199e721bc94ea573b778d1f90cbf9522c5a089352fef5edfd18f2fee6d5730cf3777fd900c22bbc282b8f3e3b65db6edac9a099b51299b896b1ee7f4db98959248bac5f448e20e2811b31bec9662dcf5fe38dbce5e461a45af444502500"),
};

const ex2: Example = .{
    .key = hex("01010310" ++ "924ade196a1c7120e65011807bbfb3b1b1ba640150a7eb323e6614bab05141cded0e378c0897153110e681c34ba791e51c0332d76568212b00"),
    .key_tag = 38353,
    .ds_digest = hex("645ff078b3568f5852b70cb60e8e696cc77b75bfaaffc118cf79cbda1ba28af4"),
    .sig = hex("f898c0362a3f2c8ce9ee8b263181395c3dc7fd8112f245ece556fd1fc3233d2f0e00664c0f7efe2ec0887238398afb747783a6fd46aa113100b098da61ee7a08440fe658515ae0f68af06a134cdfc094f2a785aabe950b6e9bdaba4b30beffd6344171cc46101089bdfb10e55e3e29300300"),
};

const mx_rrset = [_]dns.Record{.{
    .name = "example.com",
    .ty = @fromBackingInt(@intCast(15)),
    .class = .in,
    .ttl = 3600,
    .data = .{ .mx = .{ .preference = 10, .exchange = "mail.example.com" } },
}};

fn rrsigFor(e: *const Example) rdata.Rrsig {
    return .{
        .type_covered = 15,
        .algorithm = rdata.algorithm.ed448,
        .labels = 3, // as signed in the RFC (see the module comment)
        .original_ttl = 3600,
        .expiration = 1440021600,
        .inception = 1438207200,
        .key_tag = e.key_tag,
        .signer_name = "example.com",
        .signature = &e.sig,
    };
}

test "RFC 8080 §6.2: key tag and DS digest of both Ed448 DNSKEYs" {
    for ([_]*const Example{ &ex1, &ex2 }) |e| {
        try testing.expectEqual(e.key_tag, rdata.keyTag(&e.key, rdata.algorithm.ed448));
        var out: [ds.max_digest_len]u8 = undefined;
        const d = try ds.computeDigest("example.com", &e.key, rdata.Ds.digest_sha256, &out);
        try testing.expectEqualSlices(u8, &e.ds_digest, d);
    }
}

test "RFC 8080 §6.2: both Ed448 RRSIGs verify over the canonical signed data" {
    for ([_]*const Example{ &ex1, &ex2 }) |e| {
        const dnskey = try rdata.parseDnskey(&e.key);
        const rrsig = rrsigFor(e);
        const signed = try canonical.buildSignedData(testing.allocator, &mx_rrset, rrsig, "example.com");
        defer testing.allocator.free(signed);
        const key = try keys.decodePublicKey(dnskey.algorithm, dnskey.public_key);
        try keys.verifySignature(rrsig.algorithm, key, signed, rrsig.signature);
        // The RFC's Labels = 3 on a 2-label owner is invalid (RFC 4035 §5.3.1).
        const anchor: chain.TrustAnchor = .{ .dnskey_rdata = &e.key };
        const r = try root.validate(testing.allocator, &mx_rrset, rrsig, "example.com", dnskey, anchor, .{ .now = 1439000000 });
        try testing.expectEqual(root.ValidationResult.bogus, r);
    }
}

test "RFC 8080 §6.2: Ed448 verify rejects a damaged signature, another key's signature, another RRset" {
    const e = &ex1;
    const dnskey = try rdata.parseDnskey(&e.key);
    const key = try keys.decodePublicKey(dnskey.algorithm, dnskey.public_key);
    const rrsig = rrsigFor(e);
    const signed = try canonical.buildSignedData(testing.allocator, &mx_rrset, rrsig, "example.com");
    defer testing.allocator.free(signed);

    // A flipped signature bit (in R, and in S).
    for ([_]usize{ 0, 60 }) |pos| {
        var sig = e.sig;
        sig[pos] ^= 0x01;
        try testing.expectError(error.SignatureVerificationFailed, keys.verifySignature(rrsig.algorithm, key, signed, &sig));
    }
    // The other example's signature under this key.
    try testing.expectError(error.SignatureVerificationFailed, keys.verifySignature(rrsig.algorithm, key, signed, &ex2.sig));
    // A different RRset (preference 11).
    const mx11 = [_]dns.Record{.{
        .name = "example.com",
        .ty = @fromBackingInt(@intCast(15)),
        .class = .in,
        .ttl = 3600,
        .data = .{ .mx = .{ .preference = 11, .exchange = "mail.example.com" } },
    }};
    const signed11 = try canonical.buildSignedData(testing.allocator, &mx11, rrsig, "example.com");
    defer testing.allocator.free(signed11);
    try testing.expectError(error.SignatureVerificationFailed, keys.verifySignature(rrsig.algorithm, key, signed11, &e.sig));
}

test "validate: a freshly signed Ed448 RRset is secure, a flipped bit bogus (end to end)" {
    const ed448 = @import("ed448").ed448;
    var seed: [57]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i + 1);
    const kp = ed448.KeyPair.create(&seed);
    const pk = kp.public_key.toBytes();
    var raw: [4 + 57]u8 = undefined;
    std.mem.writeInt(u16, raw[0..2], rdata.Dnskey.flag_zone_key, .big);
    raw[2] = 3;
    raw[3] = rdata.algorithm.ed448;
    @memcpy(raw[4..], &pk);
    const dnskey = try rdata.parseDnskey(&raw);
    var rrsig = rrsigFor(&ex1);
    rrsig.labels = 2;
    rrsig.key_tag = rdata.keyTag(&raw, rdata.algorithm.ed448);
    const signed = try canonical.buildSignedData(testing.allocator, &mx_rrset, rrsig, "example.com");
    defer testing.allocator.free(signed);
    var sig = (try ed448.sign(&kp, signed, "")).toBytes();
    rrsig.signature = &sig;
    const anchor: chain.TrustAnchor = .{ .dnskey_rdata = &raw };
    const opts: root.ValidateOptions = .{ .now = 1439000000 };
    try testing.expectEqual(root.ValidationResult.secure, try root.validate(testing.allocator, &mx_rrset, rrsig, "example.com", dnskey, anchor, opts));
    sig[3] ^= 0x10;
    try testing.expectEqual(root.ValidationResult.bogus, try root.validate(testing.allocator, &mx_rrset, rrsig, "example.com", dnskey, anchor, opts));
}

test "keys: Ed448 decode and verify error classes" {
    const e = &ex1;
    const pk = e.key[4..];
    const key = try keys.decodePublicKey(rdata.algorithm.ed448, pk);

    // Key encoding: wrong length either way, and a 57-octet string that is not a curve point.
    try testing.expectError(error.InvalidKeyEncoding, keys.decodePublicKey(rdata.algorithm.ed448, pk[0..56]));
    var long: [58]u8 = undefined;
    @memcpy(long[0..57], pk);
    long[57] = 0;
    try testing.expectError(error.InvalidKeyEncoding, keys.decodePublicKey(rdata.algorithm.ed448, &long));
    try testing.expectError(error.InvalidKeyEncoding, keys.decodePublicKey(rdata.algorithm.ed448, &@as([57]u8, @splat(0xff))));

    // Signature encoding: a wrong length is an encoding error; a non-canonical S (all ones) fails verification.
    const msg = "x";
    try testing.expectError(error.InvalidSignatureEncoding, keys.verifySignature(rdata.algorithm.ed448, key, msg, e.sig[0..113]));
    var sig_long: [115]u8 = undefined;
    @memcpy(sig_long[0..114], &e.sig);
    sig_long[114] = 0;
    try testing.expectError(error.InvalidSignatureEncoding, keys.verifySignature(rdata.algorithm.ed448, key, msg, &sig_long));
    var bad_s = e.sig;
    @memset(bad_s[57..], 0xff);
    try testing.expectError(error.SignatureVerificationFailed, keys.verifySignature(rdata.algorithm.ed448, key, msg, &bad_s));
    try testing.expectError(error.SignatureVerificationFailed, keys.verifySignature(rdata.algorithm.ed448, key, msg, &e.sig));
}

test "keys: Ed448 sign/verify round trip uses the empty context" {
    const ed448 = @import("ed448").ed448;
    var seed: [57]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i);
    const kp = ed448.KeyPair.create(&seed);
    const pk = kp.public_key.toBytes();
    const key = try keys.decodePublicKey(rdata.algorithm.ed448, &pk);
    const msg = "signed data";
    const sig = try ed448.sign(&kp, msg, "");
    try keys.verifySignature(rdata.algorithm.ed448, key, msg, &sig.toBytes());
    // A signature made under a non-empty context must NOT verify as DNSSEC.
    const ctx_sig = try ed448.sign(&kp, msg, "dnssec");
    try testing.expectError(error.SignatureVerificationFailed, keys.verifySignature(rdata.algorithm.ed448, key, msg, &ctx_sig.toBytes()));
}
