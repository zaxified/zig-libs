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
