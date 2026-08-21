// SPDX-License-Identifier: MIT

//! What a resolver does with `dnssec`: given a zone's DNSKEY RRset, its
//! RRSIG self-signature, and a trust anchor that vouches for the key
//! directly (RFC 5011 "trusted-keys" style — a pinned key rather than a
//! parent-zone DS record), call `validate` and get back a `.secure`/
//! `.bogus`/`.insecure`/`.indeterminate` verdict. This is the exact
//! single-zone-cut step `chain.zig`'s module doc comment describes a
//! resolver repeating from a trust anchor down to the name being resolved.
//!
//! Signing happens here too (with `std.crypto.sign.Ed25519` directly, not
//! anything `dnssec` provides — this module only VERIFIES) so the example
//! is self-contained: no network, no real zone file, just enough of a
//! DNSKEY RRset to exercise `validate`'s real canonicalization + signature
//! path (`canonical.buildSignedData` + `keys.verifySignature`), not a
//! stub of it.
//!
//! Built against the PUBLISHED module (`@import("dnssec")`) plus its
//! declared dep `dns` (for `dns.Record`) — `rsa`, the other declared dep,
//! backs the RSA algorithms this example doesn't reach.

const std = @import("std");
const dnssec = @import("dnssec");
const dns = @import("dns");

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // A zone's Ed25519 zone-signing key. Deterministic seed so this example
    // has no entropy dependency and reproduces the same run every time — a
    // real zone's key comes from `ldns-keygen`/`dnssec-keygen` and never
    // touches example code.
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i);
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const pub_bytes = kp.public_key.toBytes();

    const dnskey: dnssec.rdata.Dnskey = .{
        .flags = dnssec.rdata.Dnskey.flag_zone_key,
        .protocol = 3,
        .algorithm = dnssec.rdata.algorithm.ed25519,
        .public_key = &pub_bytes,
    };

    // The raw DNSKEY RDATA (RFC 4034 §2.1) — what actually goes on the
    // wire, and what a directly-pinned trust anchor compares against.
    var raw_dnskey: [4 + 32]u8 = undefined;
    std.mem.writeInt(u16, raw_dnskey[0..2], dnskey.flags, .big);
    raw_dnskey[2] = dnskey.protocol;
    raw_dnskey[3] = dnskey.algorithm;
    @memcpy(raw_dnskey[4..], &pub_bytes);

    const owner = "example.com";
    const rrset = [_]dns.Record{.{
        .name = owner,
        .ty = @enumFromInt(dnssec.rdata.rr_type.dnskey),
        .class = .in,
        .ttl = 3600,
        .data = .{ .unknown = &raw_dnskey },
    }};

    var rrsig: dnssec.rdata.Rrsig = .{
        .type_covered = dnssec.rdata.rr_type.dnskey,
        .algorithm = dnssec.rdata.algorithm.ed25519,
        .labels = 2, // "example.com" has two labels, not counting the root
        .original_ttl = 3600,
        .expiration = 2_000_000_000,
        .inception = 1_700_000_000,
        .key_tag = 0, // not checked by `validate` itself; a resolver's own bookkeeping
        .signer_name = owner,
        .signature = &.{}, // filled in below, after signing
    };

    // Sign exactly what a real validator will verify against: the RFC 4034
    // §3.1.8.1 canonical signed-data construction, not the raw RDATA.
    const signed_data = try dnssec.canonical.buildSignedData(gpa, &rrset, rrsig, owner);
    defer gpa.free(signed_data);
    const sig = kp.sign(signed_data, null) catch return error.SigningFailed;
    const sig_bytes = sig.toBytes();
    rrsig.signature = &sig_bytes;

    const anchor: dnssec.chain.TrustAnchor = .{ .dnskey_rdata = &raw_dnskey };
    const verdict = try dnssec.validate(gpa, &rrset, rrsig, owner, dnskey, anchor, .{ .now = 1_800_000_000 });
    std.debug.print("verdict for a correctly self-signed DNSKEY RRset: {s}\n", .{@tagName(verdict)});
    if (verdict != .secure) return error.ExpectedSecure;

    // ── fail-closed: a signature that doesn't cover the actual data must
    // never validate — flip one byte of the signed RRSIG's signature.
    var tampered_sig = sig_bytes;
    tampered_sig[0] ^= 0xff;
    var bogus_rrsig = rrsig;
    bogus_rrsig.signature = &tampered_sig;
    const bogus_verdict = try dnssec.validate(gpa, &rrset, bogus_rrsig, owner, dnskey, anchor, .{ .now = 1_800_000_000 });
    std.debug.print("verdict for a tampered signature: {s}\n", .{@tagName(bogus_verdict)});
    if (bogus_verdict != .bogus) return error.ExpectedBogus;
}
