// SPDX-License-Identifier: MIT

//! RFC 8624 algorithm policy: which DNSKEY algorithms (§3.1) and DS digest
//! types (§3.3) a validator accepts. A `Policy` is consulted by
//! `root.validate` (`ValidateOptions.policy`) and by
//! `chain.validateDnskeySetPolicy`; an algorithm or digest the policy does not
//! support makes the anchor "unsupported", which RFC 4035 §5.2 says renders the
//! zone *insecure* (no validation attempted), not bogus.
//!
//! RFC 8624 §3.1, "Implementing DNSSEC Validation" column (signing column
//! omitted, it does not matter for a validator):
//!
//!     Number  Mnemonic            Validation
//!       0     DELETE              MUST NOT
//!       1     RSAMD5              MUST NOT
//!       3     DSA                 MUST NOT
//!       5     RSASHA1             MUST
//!       6     DSA-NSEC3-SHA1      MUST NOT
//!       7     RSASHA1-NSEC3-SHA1  MUST
//!       8     RSASHA256           MUST
//!      10     RSASHA512           MUST
//!      12     ECC-GOST            MAY
//!      13     ECDSAP256SHA256     MUST
//!      14     ECDSAP384SHA384     RECOMMENDED
//!      15     ED25519             RECOMMENDED
//!      16     ED448               RECOMMENDED
//!
//! RFC 8624 §3.3, DS digest types, "Implementing DNSSEC Validation" column:
//!
//!     Number  Mnemonic    Validation
//!       0     NULL        MUST NOT
//!       1     SHA-1       MUST
//!       2     SHA-256     MUST
//!       3     GOST R 34.11-94  MAY
//!       4     SHA-384     RECOMMENDED
//!
//! The default policy (`Policy.rfc8624`) refuses exactly the "MUST NOT" rows
//! (algorithms 0, 1, 3, 6; digest 0). Numbers absent from the tables are not
//! refused by the policy (the RFC says nothing about them). Independently of
//! the policy, an algorithm or digest this module cannot verify (ECC-GOST,
//! GOST digest, unassigned numbers) is unsupported: `isAlgorithmSupported`
//! / `isDigestSupported` require BOTH "policy allows" and "implemented here".

const rdata = @import("rdata.zig");

/// RFC 8624 requirement level for validators (tables above).
pub const Level = enum { must_not, may, recommended, must };

/// RFC 8624 §3.1, validation column. `null` = number not in the table.
pub fn algorithmLevel(alg: u8) ?Level {
    return switch (alg) {
        0, 1, 3, 6 => .must_not,
        5, 7, 8, 10, 13 => .must,
        12 => .may,
        14, 15, 16 => .recommended,
        else => null,
    };
}

/// RFC 8624 §3.3, validation column. `null` = number not in the table.
pub fn digestLevel(digest: u8) ?Level {
    return switch (digest) {
        0 => .must_not,
        1, 2 => .must,
        3 => .may,
        4 => .recommended,
        else => null,
    };
}

/// Whether `keys.decodePublicKey`/`verifySignature` can verify `alg`.
pub fn algorithmImplemented(alg: u8) bool {
    return switch (alg) {
        rdata.algorithm.rsasha1,
        rdata.algorithm.rsasha1_nsec3_sha1,
        rdata.algorithm.rsasha256,
        rdata.algorithm.rsasha512,
        rdata.algorithm.ecdsap256sha256,
        rdata.algorithm.ecdsap384sha384,
        rdata.algorithm.ed25519,
        rdata.algorithm.ed448,
        => true,
        else => false,
    };
}

/// Whether `ds.computeDigest` implements `digest`.
pub fn digestImplemented(digest: u8) bool {
    return switch (digest) {
        rdata.Ds.digest_sha1, rdata.Ds.digest_sha256, rdata.Ds.digest_sha384 => true,
        else => false,
    };
}

/// Which DNSKEY algorithms and DS digest types the validator accepts. Value
/// type: build a variant with `withAlgorithm` / `withDigest`.
pub const Policy = struct {
    algorithm_allowed: [256]bool,
    digest_allowed: [256]bool,

    /// RFC 8624: refuse the validation "MUST NOT" rows, allow everything else.
    pub const rfc8624: Policy = blk: {
        var p: Policy = .{ .algorithm_allowed = @splat(true), .digest_allowed = @splat(true) };
        for (0..256) |i| {
            if (algorithmLevel(@intCast(i)) == .must_not) p.algorithm_allowed[i] = false;
            if (digestLevel(@intCast(i)) == .must_not) p.digest_allowed[i] = false;
        }
        break :blk p;
    };

    /// No policy restriction: only what this module can verify is supported.
    /// For interoperability tests and legacy zones; not for production.
    pub const permissive: Policy = .{ .algorithm_allowed = @splat(true), .digest_allowed = @splat(true) };

    /// A copy of `self` with algorithm `alg` allowed or refused (e.g.
    /// `.rfc8624.withAlgorithm(5, false)` also refuses RSASHA1). Allowing an
    /// algorithm this module cannot verify has no effect.
    pub fn withAlgorithm(self: Policy, alg: u8, allowed: bool) Policy {
        var p = self;
        p.algorithm_allowed[alg] = allowed;
        return p;
    }

    /// A copy of `self` with DS digest type `digest` allowed or refused
    /// (e.g. refuse SHA-1 digests with `withDigest(1, false)`).
    pub fn withDigest(self: Policy, digest: u8, allowed: bool) Policy {
        var p = self;
        p.digest_allowed[digest] = allowed;
        return p;
    }

    pub fn isAlgorithmSupported(self: Policy, alg: u8) bool {
        return self.algorithm_allowed[alg] and algorithmImplemented(alg);
    }

    pub fn isDigestSupported(self: Policy, digest: u8) bool {
        return self.digest_allowed[digest] and digestImplemented(digest);
    }
};

const testing = @import("std").testing;

test "rfc8624 table: MUST NOT rows are refused, everything the table allows (and we implement) is supported" {
    const p = Policy.rfc8624;
    for ([_]u8{ 0, 1, 3, 6 }) |a| try testing.expect(!p.isAlgorithmSupported(a));
    for ([_]u8{ 5, 7, 8, 10, 13, 14, 15, 16 }) |a| try testing.expect(p.isAlgorithmSupported(a));
    // MAY / RECOMMENDED but not implemented here: unsupported, but not by policy.
    try testing.expect(p.algorithm_allowed[12] and !p.isAlgorithmSupported(12));
    try testing.expect(!p.isAlgorithmSupported(200));
    try testing.expect(!p.isDigestSupported(0));
    for ([_]u8{ 1, 2, 4 }) |d| try testing.expect(p.isDigestSupported(d));
    try testing.expect(!p.isDigestSupported(3)); // GOST: not implemented
    try testing.expect(!p.isDigestSupported(99));
}

test "levels match the RFC tables" {
    try testing.expectEqual(@as(?Level, .must_not), algorithmLevel(1));
    try testing.expectEqual(@as(?Level, .must), algorithmLevel(8));
    try testing.expectEqual(@as(?Level, .recommended), algorithmLevel(15));
    try testing.expectEqual(@as(?Level, .may), algorithmLevel(12));
    try testing.expectEqual(@as(?Level, null), algorithmLevel(2));
    try testing.expectEqual(@as(?Level, .must_not), digestLevel(0));
    try testing.expectEqual(@as(?Level, .may), digestLevel(3));
    try testing.expectEqual(@as(?Level, null), digestLevel(5));
}

test "overrides: refuse RSASHA1 / SHA-1 digest; permissive allows MUST NOT rows but they stay unimplemented" {
    const strict = Policy.rfc8624.withAlgorithm(5, false).withDigest(1, false);
    try testing.expect(!strict.isAlgorithmSupported(5));
    try testing.expect(!strict.isDigestSupported(1));
    try testing.expect(strict.isAlgorithmSupported(8));
    // Original unchanged (value semantics).
    try testing.expect(Policy.rfc8624.isAlgorithmSupported(5));
    try testing.expect(Policy.permissive.algorithm_allowed[1]);
    try testing.expect(!Policy.permissive.isAlgorithmSupported(1));
}
