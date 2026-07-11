// SPDX-License-Identifier: MIT

//! DS (Delegation Signer) digest computation and matching — RFC 4034 §5.1.4.
//! Pure hashing (SHA-1/SHA-256/SHA-384), no asymmetric cryptography: this is
//! the "does this DNSKEY match the DS record the parent zone published"
//! check, one link of the delegation chain. Walking the FULL chain from a
//! trust anchor down through multiple zone cuts is `chain.zig`'s job; this
//! file only computes one digest and compares it.

const std = @import("std");
const wire = @import("wire.zig");
const rdata = @import("rdata.zig");

pub const DigestError = error{
    UnsupportedDigestType,
    NameTooLong,
};

/// Longest digest this module computes (SHA-384, digest type 4).
pub const max_digest_len = 48;

/// Compute the DS digest (RFC 4034 §5.1.4) for the DNSKEY named `owner_name`
/// with RDATA `dnskey_rdata`, using `digest_type` (`rdata.Ds.digest_*`):
///
///   digest = H(canonical_owner_name || DNSKEY_RDATA)
///
/// where the owner name is in canonical wire form (RFC 4034 §6.2 —
/// lowercased, uncompressed; see `wire.encodeCanonicalName`). Returns the
/// written prefix of a `max_digest_len`-byte buffer.
pub fn computeDigest(owner_name: []const u8, dnskey_rdata: []const u8, digest_type: u8, out: *[max_digest_len]u8) DigestError![]const u8 {
    var name_buf: [wire.max_canonical_wire_len]u8 = undefined;
    const canonical_name = wire.encodeCanonicalName(owner_name, &name_buf) catch return error.NameTooLong;
    switch (digest_type) {
        rdata.Ds.digest_sha1 => {
            var st = std.crypto.hash.Sha1.init(.{});
            st.update(canonical_name);
            st.update(dnskey_rdata);
            st.final(out[0..std.crypto.hash.Sha1.digest_length]);
            return out[0..std.crypto.hash.Sha1.digest_length];
        },
        rdata.Ds.digest_sha256 => {
            var st = std.crypto.hash.sha2.Sha256.init(.{});
            st.update(canonical_name);
            st.update(dnskey_rdata);
            st.final(out[0..std.crypto.hash.sha2.Sha256.digest_length]);
            return out[0..std.crypto.hash.sha2.Sha256.digest_length];
        },
        rdata.Ds.digest_sha384 => {
            var st = std.crypto.hash.sha2.Sha384.init(.{});
            st.update(canonical_name);
            st.update(dnskey_rdata);
            st.final(out[0..std.crypto.hash.sha2.Sha384.digest_length]);
            return out[0..std.crypto.hash.sha2.Sha384.digest_length];
        },
        else => return error.UnsupportedDigestType,
    }
}

/// Whether `ds` (a DS record parsed with `rdata.parseDs`) matches the DNSKEY
/// named `owner_name` with RDATA `dnskey_rdata`: same key tag/algorithm as a
/// cheap pre-filter, then a constant-time digest comparison. `ds.algorithm`
/// is the DNSKEY algorithm the DS was issued for (RFC 4034 §5.1.2) — callers
/// should also check it equals the candidate DNSKEY's own algorithm byte
/// (this function does not have the DNSKEY's algorithm field split out, only
/// its raw RDATA, so that check stays the caller's responsibility, same as
/// the `key_tag` hint discussed in `rdata.keyTag`'s doc comment).
pub fn matches(ds: rdata.Ds, owner_name: []const u8, dnskey_rdata: []const u8) DigestError!bool {
    var buf: [max_digest_len]u8 = undefined;
    const digest = try computeDigest(owner_name, dnskey_rdata, ds.digest_type, &buf);
    if (digest.len != ds.digest.len) return false;
    return std.crypto.timing_safe.eql([max_digest_len]u8, padDigest(digest), padDigest(ds.digest));
}

fn padDigest(d: []const u8) [max_digest_len]u8 {
    var out = std.mem.zeroes([max_digest_len]u8);
    @memcpy(out[0..d.len], d);
    return out;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "computeDigest: SHA-1 matches a manually hashed canonical form" {
    const dnskey_rdata = "\x01\x01" ++ "\x03" ++ "\x08" ++ "\xaa\xbb\xcc\xdd";
    var name_buf: [wire.max_canonical_wire_len]u8 = undefined;
    const canonical = try wire.encodeCanonicalName("Example.COM", &name_buf);
    var expected: [20]u8 = undefined;
    var st = std.crypto.hash.Sha1.init(.{});
    st.update(canonical);
    st.update(dnskey_rdata);
    st.final(&expected);

    var out: [max_digest_len]u8 = undefined;
    const got = try computeDigest("Example.COM", dnskey_rdata, rdata.Ds.digest_sha1, &out);
    try testing.expectEqualSlices(u8, &expected, got);
}

test "computeDigest: SHA-256 produces 32 bytes, SHA-384 produces 48" {
    const dnskey_rdata = "\x01\x01\x03\x08\xaa";
    var out: [max_digest_len]u8 = undefined;
    const sha256 = try computeDigest("example.com", dnskey_rdata, rdata.Ds.digest_sha256, &out);
    try testing.expectEqual(@as(usize, 32), sha256.len);
    const sha384 = try computeDigest("example.com", dnskey_rdata, rdata.Ds.digest_sha384, &out);
    try testing.expectEqual(@as(usize, 48), sha384.len);
}

test "computeDigest: unsupported digest type errors" {
    var out: [max_digest_len]u8 = undefined;
    try testing.expectError(error.UnsupportedDigestType, computeDigest("example.com", "\x00", 99, &out));
}

test "matches: true for the exact digest, false when tampered" {
    const dnskey_rdata = "\x01\x01" ++ "\x03" ++ "\x08" ++ "\xaa\xbb\xcc\xdd";
    var out: [max_digest_len]u8 = undefined;
    const digest = try computeDigest("example.com", dnskey_rdata, rdata.Ds.digest_sha1, &out);
    const ds: rdata.Ds = .{ .key_tag = 1, .algorithm = 8, .digest_type = rdata.Ds.digest_sha1, .digest = digest };
    try testing.expect(try matches(ds, "example.com", dnskey_rdata));

    var tampered = std.mem.zeroes([20]u8);
    @memcpy(&tampered, digest);
    tampered[0] ^= 0xff;
    const bad_ds: rdata.Ds = .{ .key_tag = 1, .algorithm = 8, .digest_type = rdata.Ds.digest_sha1, .digest = &tampered };
    try testing.expect(!(try matches(bad_ds, "example.com", dnskey_rdata)));
}

test "matches: length mismatch is a clean false, not a crash" {
    const dnskey_rdata = "\x01\x01\x03\x08\xaa";
    const ds: rdata.Ds = .{ .key_tag = 1, .algorithm = 8, .digest_type = rdata.Ds.digest_sha256, .digest = "\x01\x02" };
    try testing.expect(!(try matches(ds, "example.com", dnskey_rdata)));
}
