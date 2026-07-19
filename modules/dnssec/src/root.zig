// SPDX-License-Identifier: MIT

//! dnssec — resolver-side DNSSEC validation (RFC 4033/4034/4035, RFC 5155
//! NSEC3, RFC 6605 ECDSA, RFC 8080 Ed25519), built on the `dns` module's
//! wire codec and this repo's own `rsa` module.
//!
//! Implemented and oracle-verified: DNSKEY/RRSIG/DS/NSEC/NSEC3/NSEC3PARAM
//! RDATA parsing (`rdata.zig`), the Type Bit Maps field, the DNSKEY key tag
//! checksum, canonical name encoding (`wire.zig`), NSEC3's base32hex +
//! iterated-SHA-1 owner hash (`nsec3.zig`), DS digest computation (`ds.zig`),
//! per-algorithm DNSKEY decode + signature verification (`keys.zig`, wrapping
//! `std.crypto.sign.ecdsa`/`std.crypto.sign.Ed25519` and this repo's
//! `rsa.verifyPkcs1v15` — no crypto primitive is reimplemented), the
//! RFC 4034 §3.1.8.1 canonical signed-data construction with wildcard +
//! original-TTL handling (`canonical.buildSignedData`), the DS-to-DNSKEY
//! delegation link (`chain.validateDnskeySet`), the NSEC3 closest-encloser /
//! next-closer denial-of-existence proof incl. Opt-Out (`nsec3.proveDenial`),
//! and the top-level per-RRset verdict (`validate`).
//!
//! Oracle: the signature/denial cores are validated against real zones signed
//! by `ldns-signzone` across algorithms 8/13/14/15 (RSA-SHA256, ECDSA-P256,
//! ECDSA-P384, Ed25519) with both NSEC and NSEC3 (including an Opt-Out span)
//! and a wildcard, each source zone independently cross-checked with
//! `ldns-verify-zone`. A valid RRSIG only verifies over byte-exact canonical
//! data, so signature verification is itself the byte-exactness oracle; the
//! matching tampered cases yield `.bogus`. See `oracle_test.zig` +
//! `oracle_vectors.zig`. Not yet covered: plain-NSEC (non-NSEC3) denial-proof
//! logic (only NSEC *signatures* are validated), RFC 8624 algorithm-downgrade
//! policy, and RFC 9276 NSEC3 iteration caps — see SPEC.md.
//!
//! Consumer: a secure-resolver module in the net family (not yet built),
//! which would call `validate` once per zone cut while walking the
//! delegation chain from a trust anchor down to the name being resolved
//! (see `chain.zig`'s doc comment for that scope split).

const std = @import("std");
const dns = @import("dns");

pub const meta = .{
    .platform = .any,
    .role = .util, // pure validation logic; no I/O, no socket of its own
    .concurrency = .reentrant, // no shared/global state
    .model_after = "RFC 4033/4034/4035 (DNSSEC core), RFC 5155 (NSEC3), RFC 6605 (ECDSA), RFC 8080 (Ed25519); structure cross-checked vs. Go miekg/dns's dnssec.go and NLnet Labs' unbound/ldns validator behavior — design/behavioral reference only, no source copied",
    .deps = .{ "dns", "rsa" },
};

/// Uncompressed-name decoding + canonical name encoding (RFC 4034 §6.2) —
/// real, tested.
pub const wire = @import("wire.zig");

/// DNSKEY/RRSIG/DS/NSEC/NSEC3/NSEC3PARAM RDATA parsing + Type Bit Maps +
/// key tag — real, tested.
pub const rdata = @import("rdata.zig");

/// NSEC3 base32hex + iterated-SHA-1 hash + closest-encloser
/// denial-of-existence proof (`proveDenial`) — real, oracle-verified.
pub const nsec3 = @import("nsec3.zig");

/// Per-algorithm DNSKEY decode + signature verification — real, tested.
pub const keys = @import("keys.zig");

/// DS digest computation + DNSKEY matching — real, tested.
pub const ds = @import("ds.zig");

/// RFC 4034 §3.1.8.1 canonical signed-data construction — real,
/// oracle-verified.
pub const canonical = @import("canonical.zig");

/// DS-to-DNSKEY delegation-chain link — real, oracle-verified.
pub const chain = @import("chain.zig");

test {
    _ = wire;
    _ = rdata;
    _ = nsec3;
    _ = keys;
    _ = ds;
    _ = canonical;
    _ = chain;
    _ = @import("oracle_test.zig");
}

// ── RRSIG validity window (RFC 4034 §3.1.5) ────────────────────────────────
//
// Mechanical, not crypto: RFC 1982 serial-number arithmetic on the
// inception/expiration timestamps, so a wraparound past 2^32 seconds
// (year 2106) compares correctly instead of overflowing naively.

/// Whether `now` (seconds since the Unix epoch, truncated to u32 — matching
/// the RRSIG wire field's own width) falls within `[inception, expiration]`
/// under RFC 1982 serial arithmetic (handles the eventual wraparound
/// correctly; a naive `inception <= now <= expiration` integer compare does
/// not).
pub fn rrsigTimeValid(rrsig: rdata.Rrsig, now: u32) bool {
    const since_inception: i32 = @bitCast(now -% rrsig.inception);
    const until_expiration: i32 = @bitCast(rrsig.expiration -% now);
    return since_inception >= 0 and until_expiration >= 0;
}

// ── top-level validation entry point ───────────────────────────────────────

pub const ValidationResult = enum {
    /// The RRset's signature verified against a DNSKEY whose trust chains
    /// to the supplied trust anchor.
    secure,
    /// The zone is provably unsigned (no DS at the parent, confirmed by a
    /// validated NSEC/NSEC3 denial of a DS record) — DNSSEC opts out here by
    /// design, not by attack.
    insecure,
    /// Something that should have validated didn't: missing/expired/
    /// mismatched signature, broken chain, or a denial-of-existence proof
    /// that doesn't hold up. Treat exactly like SERVFAIL — never serve the
    /// answer.
    bogus,
    /// Validation could not be attempted (e.g. no trust anchor configured
    /// for this zone at all).
    indeterminate,
};

pub const ValidateOptions = struct {
    /// Seconds since the Unix epoch, for the RRSIG validity window
    /// (`rrsigTimeValid`). Callers should NOT use wall-clock time from an
    /// unauthenticated source (NTP without its own auth) as the sole input
    /// in a security-critical deployment; that caveat is the resolver's
    /// concern, not this module's.
    now: u32,
};

pub const ValidateError = error{OutOfMemory};

/// Validate `rrset` (all sharing one owner name/type/class) against `rrsig`
/// under `dnskey`, where `trust_anchor` DIRECTLY vouches for `dnskey` (a
/// pinned DNSKEY, or a DS naming this exact key). Returns `.secure` iff the
/// RRSIG is inside its validity window, the covered type matches the RRset,
/// the trust anchor vouches for `dnskey`, and the signature verifies over the
/// RFC 4034 §3.1.8.1 canonical signed data; `.bogus` on any failure.
///
/// Single-zone-cut scope (see `chain.zig`): this proves an RRset secure when
/// its signing key is itself the anchor — the canonical case being the apex
/// DNSKEY RRset against a DS/pinned trust anchor. For a ZSK-signed RRset a
/// resolver first establishes the zone's DNSKEY set with
/// `chain.validateDnskeySet`, then calls this with the now-trusted signing
/// key as a `.dnskey_rdata` anchor. Fails closed: parse/decode/verify errors
/// on attacker bytes become `.bogus`, never a panic (only OOM propagates).
pub fn validate(
    gpa: std.mem.Allocator,
    rrset: []const dns.Record,
    rrsig: rdata.Rrsig,
    owner_name: []const u8,
    dnskey: rdata.Dnskey,
    trust_anchor: chain.TrustAnchor,
    opts: ValidateOptions,
) ValidateError!ValidationResult {
    if (rrset.len == 0) return .bogus;
    if (!rrsigTimeValid(rrsig, opts.now)) return .bogus;
    if (rrsig.type_covered != @intFromEnum(rrset[0].ty)) return .bogus;
    if (!dnskey.isZoneKey()) return .bogus;
    // The key is decoded per `dnskey.algorithm` but the signature is verified
    // per `rrsig.algorithm`; `keys.verifySignature` then reads the field of the
    // `DecodedKey` union tagged for `rrsig.algorithm`. If the two disagree that
    // is an inactive-field access (union type confusion) — reject the algorithm
    // mismatch here, before the dispatch (RFC 4035: the RRSIG and the DNSKEY
    // that signed it necessarily share one algorithm).
    if (rrsig.algorithm != dnskey.algorithm) return .bogus;

    // Reconstruct the raw DNSKEY RDATA (RFC 4034 §2.1) so the trust anchor
    // (which digests/compares raw bytes) can be checked against this key.
    const raw_dnskey = try gpa.alloc(u8, 4 + dnskey.public_key.len);
    defer gpa.free(raw_dnskey);
    std.mem.writeInt(u16, raw_dnskey[0..2], dnskey.flags, .big);
    raw_dnskey[2] = dnskey.protocol;
    raw_dnskey[3] = dnskey.algorithm;
    @memcpy(raw_dnskey[4..], dnskey.public_key);

    // The DS is published at the zone apex = the RRSIG's signer name.
    if (!chain.anchorMatches(trust_anchor, rrsig.signer_name, raw_dnskey)) return .bogus;

    const signed = canonical.buildSignedData(gpa, rrset, rrsig, owner_name) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .bogus,
    };
    defer gpa.free(signed);

    const key = keys.decodePublicKey(dnskey.algorithm, dnskey.public_key) catch return .bogus;
    keys.verifySignature(rrsig.algorithm, key, signed, rrsig.signature) catch return .bogus;
    return .secure;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "rrsigTimeValid: ordinary window, now inside/before/after" {
    const sig: rdata.Rrsig = .{
        .type_covered = 1,
        .algorithm = 8,
        .labels = 2,
        .original_ttl = 3600,
        .expiration = 2000,
        .inception = 1000,
        .key_tag = 1,
        .signer_name = "example.com",
        .signature = "",
    };
    try testing.expect(rrsigTimeValid(sig, 1500));
    try testing.expect(rrsigTimeValid(sig, 1000)); // inclusive lower bound
    try testing.expect(rrsigTimeValid(sig, 2000)); // inclusive upper bound
    try testing.expect(!rrsigTimeValid(sig, 999));
    try testing.expect(!rrsigTimeValid(sig, 2001));
}

test "rrsigTimeValid: RFC 1982 wraparound near the u32 boundary" {
    const sig: rdata.Rrsig = .{
        .type_covered = 1,
        .algorithm = 8,
        .labels = 2,
        .original_ttl = 3600,
        .expiration = 100, // wrapped past 2^32
        .inception = 0xffffff00,
        .key_tag = 1,
        .signer_name = "example.com",
        .signature = "",
    };
    try testing.expect(rrsigTimeValid(sig, 0xffffffff)); // just before wrap
    try testing.expect(rrsigTimeValid(sig, 50)); // just after wrap
    try testing.expect(!rrsigTimeValid(sig, 0x80000000)); // far outside either side
}

test "regression: algorithm-mismatched DNSKEY/RRSIG is rejected, not union-confused" {
    // The DNSKEY is Ed25519 (algorithm 15) but the RRSIG claims RSA/SHA-256
    // (algorithm 8). Previously `validate` decoded the key per `dnskey.algorithm`
    // (yielding `DecodedKey.ed25519`) yet `verifySignature` dispatched on
    // `rrsig.algorithm` (reading the inactive `key.rsa` field), an
    // inactive-union-field access that panicked inside keys.zig. The guard must
    // now reject the mismatch up front and return `.bogus`.
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(31 - i);
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const pub_bytes = kp.public_key.toBytes();

    const dnskey: rdata.Dnskey = .{
        .flags = rdata.Dnskey.flag_zone_key,
        .protocol = 3,
        .algorithm = rdata.algorithm.ed25519, // Ed25519 key ...
        .public_key = &pub_bytes,
    };
    // The raw RDATA `validate` reconstructs internally, for a pinned anchor
    // that matches — so WITHOUT the guard execution reaches the crashing
    // dispatch rather than failing the anchor check first.
    var raw: [4 + 32]u8 = undefined;
    std.mem.writeInt(u16, raw[0..2], dnskey.flags, .big);
    raw[2] = dnskey.protocol;
    raw[3] = dnskey.algorithm;
    @memcpy(raw[4..], &pub_bytes);

    const owner = "example.com";
    const rrset = [_]dns.Record{.{
        .name = owner,
        .ty = @enumFromInt(rdata.rr_type.dnskey),
        .class = .in,
        .ttl = 3600,
        .data = .{ .unknown = &raw },
    }};
    const rrsig: rdata.Rrsig = .{
        .type_covered = rdata.rr_type.dnskey,
        .algorithm = rdata.algorithm.rsasha256, // ... but RRSIG claims RSA/SHA-256
        .labels = 2,
        .original_ttl = 3600,
        .expiration = 2000,
        .inception = 0,
        .key_tag = 0,
        .signer_name = owner,
        .signature = &[_]u8{0} ** 64,
    };
    const anchor: chain.TrustAnchor = .{ .dnskey_rdata = &raw };
    const r = try validate(testing.allocator, &rrset, rrsig, owner, dnskey, anchor, .{ .now = 1000 });
    try testing.expectEqual(ValidationResult.bogus, r);
}
