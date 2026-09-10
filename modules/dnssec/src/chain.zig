// SPDX-License-Identifier: MIT

//! Delegation chain-of-trust walking (RFC 4035 §5.2-§5.3): proving a zone's
//! DNSKEY set is authentic by climbing DS records from a configured trust
//! anchor down through each zone cut to the zone being validated.
//!
//! Scope note: this module's `validate` (see `root.zig`) validates ONE
//! zone's RRset against that SAME zone's already-established DNSKEY set —
//! matching how real validators (unbound, BIND, Knot Resolver) factor the
//! problem: each zone cut is one `validate`-style call, and the RESOLVER
//! (this repo's future "secure resolver" net-family consumer) is what walks
//! the chain root -> tld -> ... -> target zone, calling this module once per
//! cut and feeding the previous
//! cut's now-trusted DNSKEY forward as the next cut's context. This file is
//! the one link in that chain — "does DS match DNSKEY, and is the DNSKEY
//! RRset itself validly self-signed" — not the multi-round-trip resolver
//! orchestration above it.
//!
//! `ds.matches` does the actual digest comparison; this file glues that
//! together with the DNSKEY-RRset RRSIG self-signature check (via
//! `canonical.buildSignedData` + `keys.verifySignature`) into one "is this
//! DNSKEY set trustworthy" verdict, and bootstraps from either a DS record or
//! a directly pinned (RFC 5011-style) trusted DNSKEY.

const std = @import("std");
const dns = @import("dns");
const rdata = @import("rdata.zig");
const ds_mod = @import("ds.zig");
const keys = @import("keys.zig");
const canonical = @import("canonical.zig");
const nsec = @import("nsec.zig");

/// Number of labels in a dotted name, per RFC 4034 §3.1.3 (the root has 0).
/// Duplicated from `root.zig`'s `ownerLabelCount` (private to that file, and
/// `root.zig` imports this file, so the reverse import would cycle) — see
/// that copy's doc comment for why this is one small function rather than a
/// shared export three files would fight over.
fn ownerLabelCount(name: []const u8) u8 {
    const n = if (std.mem.endsWith(u8, name, ".")) name[0 .. name.len - 1] else name;
    if (n.len == 0) return 0;
    var count: u8 = 1;
    for (n) |c| {
        if (c == '.') count +|= 1;
    }
    return count;
}

/// A configured trust anchor for a zone: either a DS record (the normal
/// case, verified against a candidate DNSKEY via `ds.matches`) or a
/// directly pinned DNSKEY (RFC 5011 "trusted-keys"/"managed-keys" style
/// bootstrap, e.g. for a private zone with no parent DS, or the root zone's
/// well-known KSK).
pub const TrustAnchor = union(enum) {
    ds: rdata.Ds,
    dnskey_rdata: []const u8,
};

pub const ChainResult = enum { secure, insecure, bogus, indeterminate };

pub const ChainError = error{OutOfMemory};

/// Validate that `dnskey_rrset` (a zone's full DNSKEY RRset, each entry's
/// raw RDATA) is trustworthy: some key in it matches `trust_anchor`
/// (directly, or via a DS digest), AND the RRset carries a valid RRSIG
/// self-signature from that same matching key (RFC 4035 §5.2 step 2 — a
/// DNSKEY matching the DS is not enough on its own; it must also have
/// actually signed the RRset it's part of).
///
/// Returns `.secure` if some DNSKEY matches `trust_anchor` (directly, or via
/// a DS digest) AND the DNSKEY RRset carries a valid self-signature by an
/// anchor-matched zone key; `.bogus` if an anchor-matched key exists but no
/// self-signature verifies, or if the parent published a DS with no matching
/// DNSKEY at all. Fails closed: any parse/decode/verify error on
/// attacker-controlled bytes collapses to `.bogus`, never a panic.
pub fn validateDnskeySet(
    gpa: std.mem.Allocator,
    zone_name: []const u8,
    dnskey_rrset: []const []const u8,
    dnskey_rrsig: rdata.Rrsig,
    trust_anchor: TrustAnchor,
) ChainError!ChainResult {
    if (dnskey_rrset.len == 0) return .bogus;
    // RFC 4035 §5.3.1, the two guards `root.zig`'s `validate` applies to
    // every other RRset type but this entry point skipped for the DNSKEY
    // RRset itself: the RRSIG must cover the DNSKEY type (not some other
    // type whose signature happens to verify against a matched key — a
    // union/dispatch confusion one level up from the algorithm-mismatch
    // guard already below) and must be signed by the zone name itself, not
    // a descendant (a subdomain's DNSKEY RRSIG must never vouch for the
    // parent's key set). DNSKEY RRsets sit at the zone apex and are never
    // wildcard-synthesized, so `labels` must equal the apex's own label
    // count exactly — not merely "not greater than", the looser bound that
    // is all a synthesizable RRset (root.zig's F6) can require (audit F5).
    if (dnskey_rrsig.type_covered != rdata.rr_type.dnskey) return .bogus;
    if (!nsec.namesEqual(dnskey_rrsig.signer_name, zone_name)) return .bogus;
    if (dnskey_rrsig.labels != ownerLabelCount(zone_name)) return .bogus;

    // Which keys in the set are vouched for by the trust anchor?
    var any_matched = false;
    var matched = std.ArrayList(usize).empty;
    defer matched.deinit(gpa);
    for (dnskey_rrset, 0..) |raw, i| {
        if (anchorMatches(trust_anchor, zone_name, raw)) {
            any_matched = true;
            try matched.append(gpa, i);
        }
    }
    if (!any_matched) return .bogus;

    // Reconstruct the DNSKEY RRset as raw records for the canonical signed
    // data (DNSKEY RDATA is already in canonical wire form → `.unknown`).
    const records = try gpa.alloc(dns.Record, dnskey_rrset.len);
    defer gpa.free(records);
    for (dnskey_rrset, 0..) |raw, i| records[i] = .{
        .name = zone_name,
        .ty = @enumFromInt(rdata.rr_type.dnskey),
        .class = .in,
        .ttl = 0,
        .data = .{ .unknown = raw },
    };

    const signed = canonical.buildSignedData(gpa, records, dnskey_rrsig, zone_name) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .bogus,
    };
    defer gpa.free(signed);

    // The self-signature must verify under an anchor-matched zone key
    // (RFC 4035 §5.2): a key matching the DS is not enough — it must also
    // have signed the RRset it belongs to.
    for (matched.items) |i| {
        const raw = dnskey_rrset[i];
        const dnskey = rdata.parseDnskey(raw) catch continue;
        if (!dnskey.isZoneKey()) continue;
        // The key is decoded per `dnskey.algorithm` but verified per
        // `dnskey_rrsig.algorithm`; a mismatch makes `keys.verifySignature`
        // read the inactive field of the `DecodedKey` union (type confusion).
        // Skip any key whose algorithm differs from the RRSIG's before the
        // dispatch (RFC 4035: signer and signature share one algorithm).
        if (dnskey.algorithm != dnskey_rrsig.algorithm) continue;
        const key = keys.decodePublicKey(dnskey.algorithm, dnskey.public_key) catch continue;
        keys.verifySignature(dnskey_rrsig.algorithm, key, signed, dnskey_rrsig.signature) catch continue;
        return .secure;
    }
    return .bogus;
}

/// Whether `trust_anchor` vouches for the DNSKEY with raw RDATA
/// `dnskey_rdata` at `zone_name`: a directly-pinned key matches by bytes, a
/// DS matches by algorithm + key tag + recomputed digest (RFC 4034 §5.1.4).
pub fn anchorMatches(trust_anchor: TrustAnchor, zone_name: []const u8, dnskey_rdata: []const u8) bool {
    switch (trust_anchor) {
        .dnskey_rdata => |pinned| return std.mem.eql(u8, pinned, dnskey_rdata),
        .ds => |ds| {
            const dnskey = rdata.parseDnskey(dnskey_rdata) catch return false;
            // The DS is issued for a specific DNSKEY algorithm (RFC 4034
            // §5.1.2) — a digest collision across algorithms must not match.
            if (ds.algorithm != dnskey.algorithm) return false;
            if (ds.key_tag != rdata.keyTag(dnskey_rdata, dnskey.algorithm)) return false;
            return ds_mod.matches(ds, zone_name, dnskey_rdata) catch false;
        },
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "regression: algorithm-mismatched DNSKEY/RRSIG is rejected, not union-confused" {
    // The DNSKEY is Ed25519 (algorithm 15) but the RRSIG claims RSA/SHA-256
    // (algorithm 8). Previously the key was decoded per the DNSKEY's algorithm
    // (yielding `DecodedKey.ed25519`) yet `verifySignature` dispatched on the
    // RRSIG's algorithm (reading the inactive `key.rsa` field), an
    // inactive-union-field access that panicked inside keys.zig. The guard must
    // now skip the mismatched key so the set fails closed to `.bogus`.
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i);
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const pub_bytes = kp.public_key.toBytes();

    // Raw DNSKEY RDATA: flags=0x0100 (zone key), protocol=3, algorithm=15
    // (Ed25519), then the 32-byte public key.
    var raw: [4 + 32]u8 = undefined;
    std.mem.writeInt(u16, raw[0..2], rdata.Dnskey.flag_zone_key, .big);
    raw[2] = 3;
    raw[3] = rdata.algorithm.ed25519;
    @memcpy(raw[4..], &pub_bytes);

    const zone = "example.com";
    const rrset = [_][]const u8{&raw};
    const rrsig: rdata.Rrsig = .{
        .type_covered = rdata.rr_type.dnskey,
        .algorithm = rdata.algorithm.rsasha256, // MISMATCH vs the Ed25519 key
        .labels = 2,
        .original_ttl = 3600,
        .expiration = 2000,
        .inception = 0,
        .key_tag = 0,
        .signer_name = zone,
        .signature = &[_]u8{0} ** 64,
    };
    // A pinned trust anchor equal to the key's raw RDATA makes `anchorMatches`
    // pass, so WITHOUT the guard execution would reach the crashing dispatch.
    const anchor: TrustAnchor = .{ .dnskey_rdata = &raw };
    try testing.expectEqual(ChainResult.bogus, try validateDnskeySet(testing.allocator, zone, &rrset, rrsig, anchor));
}

/// Shared rig for the three audit-F5 regression tests below: a real Ed25519
/// key pinned as the trust anchor, and a real signature over whatever bytes
/// `validateDnskeySet` itself would build for the given (possibly bogus)
/// `rrsig` — so each test reproduces the actual exploit (a genuinely
/// verifying signature the pre-fix code accepted), not a shape check.
const F5Rig = struct {
    raw: [4 + 32]u8,
    kp: std.crypto.sign.Ed25519.KeyPair,

    fn init(seed_byte: u8) !F5Rig {
        var seed: [32]u8 = undefined;
        for (&seed, 0..) |*b, i| b.* = seed_byte +% @as(u8, @intCast(i));
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
        const pub_bytes = kp.public_key.toBytes();
        var raw: [4 + 32]u8 = undefined;
        std.mem.writeInt(u16, raw[0..2], rdata.Dnskey.flag_zone_key, .big);
        raw[2] = 3;
        raw[3] = rdata.algorithm.ed25519;
        @memcpy(raw[4..], &pub_bytes);
        return .{ .raw = raw, .kp = kp };
    }

    /// Sign the exact bytes `validateDnskeySet` itself would build for
    /// `rrsig` (whose `.signature` field is ignored by `buildSignedData` —
    /// it is excluded from the signed data by RFC 4034 §3.1.8.1 — so it need
    /// not be filled in yet). Returns the real signature bytes; the caller
    /// stores them in a local and points `rrsig.signature` at that local
    /// (this function's own stack frame does not outlive the call).
    fn sign(self: F5Rig, zone_name: []const u8, rrsig: rdata.Rrsig) ![64]u8 {
        const records = [_]dns.Record{.{
            .name = zone_name,
            .ty = @enumFromInt(rdata.rr_type.dnskey),
            .class = .in,
            .ttl = 0,
            .data = .{ .unknown = &self.raw },
        }};
        const signed = try canonical.buildSignedData(testing.allocator, &records, rrsig, zone_name);
        defer testing.allocator.free(signed);
        const sig = try self.kp.sign(signed, null);
        return sig.toBytes();
    }
};

test "regression: DNSKEY RRSIG covering the wrong type is not authenticated (audit F5)" {
    // A genuinely-verifying RRSIG whose `type_covered` is TXT, not DNSKEY,
    // must not authenticate the DNSKEY set (RFC 4035 §5.2 step 2: the key
    // must have signed the DNSKEY RRset it is being used to vouch for).
    var rig = try F5Rig.init(0);
    const zone = "example.com"; // 2 labels
    var rrsig: rdata.Rrsig = .{
        .type_covered = 16, // TXT, NOT dnskey
        .algorithm = rdata.algorithm.ed25519,
        .labels = 2,
        .original_ttl = 3600,
        .expiration = 2000,
        .inception = 0,
        .key_tag = 0,
        .signer_name = zone,
        .signature = &[_]u8{0} ** 64,
    };
    const sig_bytes = try rig.sign(zone, rrsig);
    rrsig.signature = &sig_bytes;
    const rrset = [_][]const u8{&rig.raw};
    const anchor: TrustAnchor = .{ .dnskey_rdata = &rig.raw };
    try testing.expectEqual(ChainResult.bogus, try validateDnskeySet(testing.allocator, zone, &rrset, rrsig, anchor));
}

test "regression: DNSKEY RRSIG signed by a different zone is not authenticated (audit F5)" {
    // Real signature, real matched key — but `rrsig.signer_name` names a
    // DIFFERENT zone than the `zone_name` `validateDnskeySet` was asked to
    // validate. RFC 4035 §5.2: a DNSKEY RRSIG must be signed by the zone
    // itself. `labels` still matches the REAL owner (`example.com`, 2
    // labels) so this isolates the signer_name check from the labels one.
    var rig = try F5Rig.init(10);
    const zone = "example.com"; // 2 labels — the zone actually being validated
    var rrsig: rdata.Rrsig = .{
        .type_covered = rdata.rr_type.dnskey,
        .algorithm = rdata.algorithm.ed25519,
        .labels = 2, // matches `zone`'s real label count
        .original_ttl = 3600,
        .expiration = 2000,
        .inception = 0,
        .key_tag = 0,
        .signer_name = "sub.example.com", // a DIFFERENT zone
        .signature = &[_]u8{0} ** 64,
    };
    const sig_bytes = try rig.sign(zone, rrsig);
    rrsig.signature = &sig_bytes;
    const rrset = [_][]const u8{&rig.raw};
    const anchor: TrustAnchor = .{ .dnskey_rdata = &rig.raw };
    try testing.expectEqual(ChainResult.bogus, try validateDnskeySet(testing.allocator, zone, &rrset, rrsig, anchor));
}

test "regression: DNSKEY RRSIG with the wrong labels count is not authenticated (audit F5)" {
    // Real signature, real matched key, correct signer_name — but `labels`
    // does not match the zone apex's own label count. A DNSKEY RRset is
    // never wildcard-synthesized, so unlike root.zig's F6 guard (which only
    // rejects an OVER-large `labels`, because a smaller one can be a
    // legitimate wildcard expansion for other RR types) this one must be
    // exact.
    var rig = try F5Rig.init(20);
    const zone = "example.com"; // 2 labels
    var rrsig: rdata.Rrsig = .{
        .type_covered = rdata.rr_type.dnskey,
        .algorithm = rdata.algorithm.ed25519,
        .labels = 1, // wrong: example.com has 2 labels
        .original_ttl = 3600,
        .expiration = 2000,
        .inception = 0,
        .key_tag = 0,
        .signer_name = zone,
        .signature = &[_]u8{0} ** 64,
    };
    const sig_bytes = try rig.sign(zone, rrsig);
    rrsig.signature = &sig_bytes;
    const rrset = [_][]const u8{&rig.raw};
    const anchor: TrustAnchor = .{ .dnskey_rdata = &rig.raw };
    try testing.expectEqual(ChainResult.bogus, try validateDnskeySet(testing.allocator, zone, &rrset, rrsig, anchor));
}
