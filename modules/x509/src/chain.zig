// SPDX-License-Identifier: MIT
//! RFC 5280 §6 certification-path validation — the multi-certificate,
//! policy-aware layer `std.crypto.Certificate` does not provide (std parses
//! ONE certificate and verifies ONE link against ONE candidate issuer; it has
//! no path builder, no basicConstraints/keyUsage/nameConstraints/EKU policy
//! engine, and no trust-anchor search over multiple candidates — see this
//! module's root.zig doc comment for the full recon).
//!
//! **Implemented.** `verifyChain` performs an RFC 4158-style depth-first
//! path search (leaf toward a trust anchor) with backtracking over multiple
//! same-subject-DN candidate issuers (`buildPath`/`findIssuerAndVerify`),
//! then two linear passes over the resulting path: leaf-to-anchor for
//! `pathLenConstraint` bookkeeping with the self-issued-certificate
//! exception (`checkPathLength`), and anchor-to-leaf for accumulated
//! `nameConstraints` (`checkNameConstraints`) and extended-key-usage
//! chaining (`checkExtendedKeyUsage`). Per-link signature verification
//! reuses `std.crypto.Certificate.Parsed.verify` for every algorithm std can
//! parse (RSA PKCS1v15, ECDSA P-256/P-384, Ed25519). Three algorithms std
//! cannot even parse are filled in here, all through the same raw-DER walk
//! (`parseShape`) and all for the same underlying reason — std's OID table
//! is closed and none of the three OIDs is in it: RSASSA-PSS (RFC 4055) via
//! `verifyPssLink` and this repo's `rsa.verifyPss`, ML-DSA (RFC 9881) via
//! `verifyMlDsaLink` and std's own `std.crypto.sign.mldsa`, and SLH-DSA
//! (RFC 9882, all twelve FIPS 205 parameter sets) via `verifySlhDsaLink` and
//! this repo's `slhdsa`. Which OIDs this module recognises is
//! `algorithm.zig`, not std.
//!
//! **Revocation (opt-in).** With `Options.revocation` set, every link the path
//! builder accepts is also checked against the caller-supplied CRLs
//! (`crl.checkRevocation`, RFC 5280 §6.3; see `Revocation`). Fetching stays the
//! caller's; OCSP is the sibling `ocsp` module and is not wired in here.
//!
//! **Go `Verify` parity (2026-10-11).** Name constraints of every RFC type
//! (`names.zig`), SAN-only hostname matching (`hostname.zig`), certificate
//! policies (`policy.zig`), refusal of unhandled critical and repeated
//! extensions, trust-anchor validity, SHA-1 refusal, Go's `KeyUsages` list,
//! a constraint-comparison budget — each pinned against Go 1.26 through the
//! replayed corpus in `s2_oracle_test.zig`; options and differences in
//! SPEC.md § "Go Verify parity".
//!
//! **Out of scope, by design, not silently skipped:** OCSP in the path
//! (a separate online data-fetching concern; the sibling `ocsp` module).

const std = @import("std");
const Certificate = std.crypto.Certificate;
const der = Certificate.der;
const extensions = @import("extensions.zig");
const algorithm = @import("algorithm.zig");
const rsa = @import("rsa");
const p521 = @import("p521");
const p256 = @import("p256");
const crl = @import("crl.zig");
const safe = @import("safe.zig");
const names = @import("names.zig");
const hostname = @import("hostname.zig");
const policy = @import("policy.zig");

/// One certificate's DER bytes. A bare `[]const u8` alias rather than a
/// wrapper struct: every std/rsa API in this collection that touches a
/// certificate already takes raw DER, and `Certificate.buffer` is a
/// `[]const u8` too — no value in a new wrapper type here.
pub const CertDer = []const u8;

pub const Options = struct {
    /// Unix seconds; checked against every certificate's notBefore/notAfter
    /// (RFC 5280 §6.1.3 (a)(2)). Caller-supplied rather than read from a
    /// clock — this module does no I/O of its own (`meta.role = .util`).
    now_sec: i64,
    /// When set, the leaf's subjectAltName must cover this host — a DNS name,
    /// or an IP address (IPv6 optionally in brackets). `hostname.verify`:
    /// RFC 9525 / Go `VerifyHostname` rules, never the subject commonName.
    expected_host: ?[]const u8 = null,
    /// When set, the leaf certificate's `extKeyUsage` (if present at all)
    /// must list this purpose or `anyExtendedKeyUsage` (RFC 5280 §4.2.1.12).
    /// Leave `null` for protocols that don't mandate an EKU (e.g. OPC-UA
    /// application certificates, OPC 10000-6).
    required_eku: ?extensions.Purpose = null,
    /// Upper bound on the number of CA certificates between the leaf and
    /// the trust anchor (a local safety cap independent of any
    /// `pathLenConstraint` found in the certificates themselves, which is
    /// also enforced separately). Guards against a pathological/malicious
    /// long chain before path building even starts.
    max_intermediates: u32 = 8,
    /// CRL revocation checking (RFC 5280 §6.3) of the certificates on the
    /// path. `null` (the default) checks nothing — revocation is opt-in and the
    /// call behaves exactly as it did before this field existed.
    revocation: ?Revocation = null,
    /// Check the trust anchor's own notBefore/notAfter against `now_sec`, as
    /// Go ("CurrentTime is used to check the validity of all certificates in
    /// the chain") and OpenSSL do. An expired root in the store then fails the
    /// path through it (`CertificateExpired`/`CertificateNotYetValid`, or
    /// `NoTrustedPath` when another same-subject candidate also failed) instead
    /// of vouching for a chain past its own lifetime. `false` restores the
    /// RFC 5280 §6.1.1 reading, where the anchor is trusted input with no window.
    check_anchor_validity: bool = true,
    /// Accept certificate signatures made with SHA-1 (`sha1WithRSAEncryption`,
    /// RSASSA-PSS over SHA-1). Off by default, as in Go ("Certificates that use
    /// SHA1WithRSA and ECDSAWithSHA1 signatures are not supported") and OpenSSL
    /// at security level ≥ 1: SHA-1 collisions are practical (SHAttered, 2017;
    /// chosen-prefix 2020), and a chosen-prefix collision forges a CA
    /// certificate. A trust anchor's self-signature is never verified, so a
    /// SHA-1 self-signed root still works. On only for legacy closed PKIs.
    allow_sha1_signatures: bool = false,
    /// Go's `VerifyOptions.KeyUsages`: the path is accepted when it permits ANY
    /// of these purposes, and EKU is enforced nested — every certificate that
    /// carries `extKeyUsage` (leaf, intermediates, anchor) narrows the set to
    /// what it lists itself (`anyExtendedKeyUsage` narrows nothing); an empty
    /// result is `ExtendedKeyUsageMismatch`. Listing `.any_extended_key_usage`
    /// here accepts every path. `required_eku`, if also set, is one more member.
    /// Empty (the default) with `required_eku == null` checks no EKU at all —
    /// a deliberate difference from Go, whose default is serverAuth: this
    /// module is protocol-agnostic (OPC-UA, IEC 62351 leaves need no EKU).
    usages_any_of: []const extensions.Purpose = &.{},
    /// Cap on (name, constraint) comparisons over the whole path's
    /// nameConstraints check (Go's `MaxConstraintComparisions`); past it the
    /// call fails with `TooManyConstraints`. A certificate is bounded only by
    /// its size, and N SAN entries against M accumulated subtrees cost N·M:
    /// a few thousand of each fit in a 64 KiB post-quantum certificate.
    max_constraint_comparisons: u64 = 250_000,
    /// Critical extensions to accept in addition to
    /// `extensions.handled_critical_oids` (OID content bytes, e.g.
    /// `&.{ 0x2b, 0x06, 0x01, 0x04, 0x01, … }`), for a caller that processes
    /// them itself — Go's equivalent is clearing `UnhandledCriticalExtensions`
    /// before `Verify`. Every certificate on the path, anchor included, is
    /// checked; an unknown critical extension anywhere else is
    /// `UnhandledCriticalExtension`, a repeated extension `DuplicateExtension`.
    ignore_critical_oids: []const []const u8 = &.{},
    /// Certificate policy processing (RFC 5280 §6.1, `policy.zig`). Always
    /// on, as in Go: with the defaults no particular policy is asked for,
    /// but a CA's requireExplicitPolicy / inhibitPolicyMapping /
    /// inhibitAnyPolicy is enforced. `acceptable` is Go's
    /// `CertificatePolicies`.
    policy: policy.Options = .{},
};

/// Revocation policy for `verifyChain` (`Options.revocation`). Every link the
/// path builder accepts is checked per certificate against `crls`, with the
/// link's issuer certificate as the CRL issuer — so a revoked intermediate
/// fails that candidate and `buildPath` backtracks to another same-subject
/// candidate (cross-signed or re-issued CA), exactly as it does for a bad
/// signature. Trust anchors are never checked: they are trusted inputs (RFC
/// 5280 §6.1). The per-certificate rules:
///
/// - a `.revoked` verdict from ANY CRL rejects (`error.CertificateRevoked`);
///   `certificateHold` counts as revoked — the chain API has no "suspended
///   is fine" mode, a caller wanting that uses `crl.checkRevocation` itself;
/// - otherwise one `.good` from any CRL is a verdict of "not revoked";
/// - a CRL that is not about this certificate (other issuer name or key,
///   other scope) is skipped, and so is one that cannot vouch for it (expired,
///   not yet valid, bad signature, malformed, delta / indirect / reason-limited,
///   issuer without `cRLSign`, …): it yields no verdict, never `.good`;
/// - no verdict at all is `unknown`.
pub const Revocation = struct {
    /// DER CRLs supplied by the caller (this module fetches nothing).
    crls: []const []const u8,
    /// Which certificates of the path must have a verdict: only the leaf, or
    /// every non-anchor certificate.
    scope: enum { leaf_only, full_chain } = .full_chain,
    /// What "no CRL gives a verdict for a certificate in scope" means: reject
    /// (`error.RevocationStatusUnknown`, fail closed) or accept.
    unknown: enum { reject, allow } = .reject,
    /// Passed through to `crl.Options.max_age_sec` (CRLs without nextUpdate).
    max_age_sec: ?i64 = null,
};

pub const VerifiedChain = struct {
    /// Number of certificates from (and including) the leaf up to (and
    /// including) the certificate whose issuer matched a trust anchor.
    depth: u32,
    /// The verified leaf, in std's own parse. `null` — and only null — when
    /// the leaf uses an algorithm `std.crypto.Certificate` has no name for
    /// (RSASSA-PSS, ML-DSA), because `Certificate.parse` fails outright on
    /// those and there is no honest `Parsed` to hand back: its
    /// `signature_algorithm` field is an exhaustive enum with no variant for
    /// them. The chain is fully verified either way, `expected_host`
    /// included — this field is a convenience view, not the result.
    ///
    /// Null here is deliberately loud. The alternative was a `Parsed` whose
    /// `signature_algorithm` names an algorithm the certificate does not
    /// use, which a caller cannot tell from the truth.
    leaf: ?Certificate.Parsed,
    /// The leaf's DER, always present — what `leaf` would have described.
    leaf_der: CertDer,
    /// The leaf's SubjectPublicKeyInfo algorithm, in this module's own union,
    /// which unlike std's can name every algorithm this module verifies.
    leaf_pub_key_algo: algorithm.PubKeyAlgo,
    /// Index into the `trust_anchors` slice passed to `verifyChain` that
    /// terminated the path.
    trust_anchor_index: usize,
};

pub const VerifyChainError = error{
    EmptyChain,
    ChainTooLong,
    /// No certificate in `trust_anchors` could complete the path (no subject
    /// match, or every candidate failed signature/policy checks).
    NoTrustedPath,
    /// A non-leaf certificate in the path has `basicConstraints.cA` false,
    /// or has no `basicConstraints` extension at all (RFC 5280 §4.2.1.9: a
    /// v3 CA certificate MUST have this extension with `cA` true).
    NotACertificateAuthority,
    /// A CA certificate's `keyUsage` extension is present but does not
    /// assert `keyCertSign` (RFC 5280 §4.2.1.3).
    KeyUsageForbidsCertSigning,
    /// `pathLenConstraint` on some CA in the path was violated by the
    /// number of non-self-issued CA certificates below it (RFC 5280
    /// §6.1.4 (h), (l)).
    PathLenConstraintExceeded,
    /// The leaf's `extKeyUsage` is present but lacks `Options.required_eku`
    /// and `anyExtendedKeyUsage`, or an intermediate CA's `extKeyUsage` is
    /// present but does not permit `Options.required_eku`.
    ExtendedKeyUsageMismatch,
    /// A subject name or SAN entry fell outside an accumulated
    /// `nameConstraints` permitted subtree, or inside an excluded one
    /// (RFC 5280 §6.1.4 (g), §4.2.1.10).
    NameConstraintViolated,
    /// An RSASSA-PSS `signatureAlgorithm` parameter field (RFC 4055 §3.1)
    /// used a hash/MGF the `rsa` module cannot express (this collection's
    /// `rsa.verifyPss` uses one `Hash` for both the digest and MGF1 inner
    /// hash — a certificate with mismatched digest/MGF hashes, a non-MGF1
    /// mask generation function, or `trailerField != 1` is rejected here
    /// rather than silently misverified).
    UnsupportedPssParams,
    /// A certificate in the path is listed as revoked (or on hold) in one of
    /// `Options.revocation.crls` (RFC 5280 §6.3.3).
    CertificateRevoked,
    /// `Options.revocation.unknown == .reject` and no CRL in `crls` gave a
    /// verdict (good or revoked) for a certificate in scope. (`crl.CheckError`
    /// includes this whole set, but `crl.checkRevocation` never returns
    /// either of these two.)
    RevocationStatusUnknown,
    /// A certificate in the path is signed with SHA-1 and
    /// `Options.allow_sha1_signatures` is off.
    WeakSignatureAlgorithm,
    /// Checking nameConstraints would take more than
    /// `Options.max_constraint_comparisons` comparisons.
    TooManyConstraints,
} ||
    std.mem.Allocator.Error ||
    Certificate.ParseError ||
    Certificate.Parsed.VerifyError ||
    hostname.Error ||
    extensions.FindExtensionsError ||
    extensions.ParseBasicConstraintsError ||
    extensions.ParseKeyUsageError ||
    extensions.ParseExtKeyUsageError ||
    extensions.ParseNameConstraintsError ||
    extensions.HygieneError ||
    policy.Error ||
    rsa.PublicKey.FromDerError;

/// Top-level RFC 5280 §6.1 path-validation entry point. `chain` is the
/// leaf-first certificate list as presented by the peer (leaf, then zero or
/// more intermediates — NOT including a trust anchor, though an anchor
/// accidentally included as the last element is harmless: it will simply
/// also be found in `trust_anchors`). `trust_anchors` is the caller's trust
/// store (e.g. an OS bundle via `std.crypto.Certificate.Bundle`'s backing
/// `bytes`, split per-certificate, or an OPC-UA trust list's DER files).
///
/// Algorithm: `buildPath` searches for a path from `chain[0]` to some
/// `trust_anchors` entry, verifying every link's signature and
/// basicConstraints/keyUsage as it goes (backtracking over alternate
/// same-subject-DN candidates on failure — see `buildPath`'s doc comment).
/// Once a path exists, this function makes two more passes over it:
/// `checkPathLength` leaf-to-anchor (pathLenConstraint bookkeeping) and
/// `checkNameConstraints`/`policy.check`/`checkExtendedKeyUsage`
/// anchor-to-leaf (accumulated name constraints, certificate policies, EKU
/// chaining), and the leaf's extension hygiene. Finally `expected_host`, if
/// set, is checked by `hostname.verify`, and the leaf is parsed via
/// `std.crypto.Certificate.parse` for `VerifiedChain.leaf`.
///
/// A leaf whose algorithm std cannot name (RSASSA-PSS, ML-DSA, SLH-DSA) no longer
/// fails the whole call the way it did before `algorithm.zig` existed: it is
/// verified like any other and `VerifiedChain.leaf` is `null`; the hostname
/// check reads the SAN itself, the same for every algorithm.
///
/// With `opts.revocation` set, revocation is checked inside `buildPath`, per
/// link, right after that link's signature and CA checks (see `Revocation`);
/// failures are `error.CertificateRevoked` / `error.RevocationStatusUnknown`
/// (or `NoTrustedPath` when several same-subject candidates all failed).
pub fn verifyChain(
    gpa: std.mem.Allocator,
    chain: []const CertDer,
    trust_anchors: []const CertDer,
    opts: Options,
) VerifyChainError!VerifiedChain {
    if (chain.len == 0) return error.EmptyChain;

    var memo: Memo = .{};
    var checks: u32 = 0;
    const path = try buildPathMemo(gpa, chain, trust_anchors, opts, &checks, &memo);
    defer gpa.free(path);
    return checkBuiltPath(gpa, path, opts, &memo);
}

/// `verifyChain`'s result plus the path it verified — Go's `Verify` returns
/// the chain; a caller that logs, pins or staples per intermediate needs to
/// know which of the presented (or stored) certificates were used. One path,
/// the first the depth-first search completes, not every valid one.
pub const VerifiedPath = struct {
    summary: VerifiedChain,
    /// Leaf first, trust anchor last. The slice is owned (`deinit`); its
    /// elements borrow the caller's `chain`/`trust_anchors` buffers.
    certs: []const CertDer,

    pub fn deinit(p: *VerifiedPath, gpa: std.mem.Allocator) void {
        gpa.free(p.certs);
        p.* = undefined;
    }
};

/// `verifyChain` that also returns the verified path (`VerifiedPath`).
pub fn verifyChainPath(
    gpa: std.mem.Allocator,
    chain: []const CertDer,
    trust_anchors: []const CertDer,
    opts: Options,
) VerifyChainError!VerifiedPath {
    if (chain.len == 0) return error.EmptyChain;

    var memo: Memo = .{};
    var checks: u32 = 0;
    const path = try buildPathMemo(gpa, chain, trust_anchors, opts, &checks, &memo);
    defer gpa.free(path);
    const summary = try checkBuiltPath(gpa, path, opts, &memo);
    const certs = try gpa.alloc(CertDer, path.len);
    for (path, certs) |entry, *c| c.* = entry.der;
    return .{ .summary = summary, .certs = certs };
}

/// The passes `verifyChain` runs once `buildPath` has a path (see there).
fn checkBuiltPath(gpa: std.mem.Allocator, path: []const PathEntry, opts: Options, memo: *Memo) VerifyChainError!VerifiedChain {
    // RFC 5280 §4.2 / §6.1.4 (o): no repeated extension, no critical one
    // this module would silently not enforce. The CAs were checked as
    // candidates in `acceptCandidate`, so a bad one could be backtracked over.
    try extensions.checkHygiene(.{ .buffer = path[0].der, .index = 0 }, opts.ignore_critical_oids);

    // RFC 5280 §6.1.4 (h)/(i)/(l): pathLenConstraint, leaf-to-anchor order,
    // with the self-issued-certificate exception. `path[1..]` is every CA
    // certificate in the path (everything except the leaf at path[0]).
    var non_self_issued_below: u32 = 0;
    for (path[1..]) |entry| {
        const bc = try findBasicConstraints(entry.der);
        try checkPathLength(bc.path_len_constraint, non_self_issued_below);
        const shape = try memo.shape(entry.der);
        if (!std.mem.eql(u8, shape.subject, shape.issuer)) non_self_issued_below += 1;
    }

    // RFC 5280 §6.1.4 (g): nameConstraints, anchor-to-leaf order (subtrees
    // accumulate top-down; `path`'s natural order is leaf-to-anchor, so walk
    // it in reverse).
    {
        var permitted: std.ArrayList([]const u8) = .empty;
        defer permitted.deinit(gpa);
        var excluded: std.ArrayList([]const u8) = .empty;
        defer excluded.deinit(gpa);
        var budget: u64 = opts.max_constraint_comparisons;

        var i: usize = path.len;
        while (i > 0) {
            i -= 1;
            const entry = path[i];
            const shape = try memo.shape(entry.der);
            const san = try findSan(entry.der);
            try checkNameConstraintsBudget(permitted.items, excluded.items, shape.subject, san, &budget);
            if (i != 0) {
                // Every non-leaf path entry is a CA (buildPath already
                // required this) — its own nameConstraints, if any, apply
                // to everything below it (entries with smaller `i`,
                // processed in later loop iterations).
                if (try findNameConstraintsExt(entry.der)) |nc| {
                    if (nc.permitted) |p| try permitted.append(gpa, p);
                    if (nc.excluded) |x| try excluded.append(gpa, x);
                }
            }
        }
    }

    // RFC 5280 §6.1.3 (d)–(f), §6.1.4 (a)/(b)/(h)–(j), §6.1.5: policies,
    // anchor-to-leaf without the anchor itself.
    {
        const top_down = try gpa.alloc([]const u8, path.len - 1);
        defer gpa.free(top_down);
        for (top_down, 0..) |*c, k| c.* = path[path.len - 2 - k].der;
        try policy.check(gpa, top_down, opts.policy);
    }

    // RFC 5280 §4.2.1.12-adjacent EKU chaining, plus the leaf's own
    // required-purpose check.
    {
        const eku_list = try gpa.alloc(?[]const u8, path.len - 1);
        defer gpa.free(eku_list);
        for (path[1..], 0..) |entry, idx| eku_list[idx] = try findEku(entry.der);
        const leaf_eku = try findEku(path[0].der);
        if (opts.usages_any_of.len == 0) {
            try checkExtendedKeyUsage(eku_list, leaf_eku, opts.required_eku);
        } else {
            var wanted: PurposeSet = .empty;
            for (opts.usages_any_of) |u| wanted.insert(u);
            if (opts.required_eku) |r| wanted.insert(r);
            try checkExtendedKeyUsageAnyOf(eku_list, leaf_eku, wanted);
        }
    }

    const leaf_shape = try memo.shape(path[0].der);
    // Own walk of the SAN, the same for every leaf algorithm (std cannot
    // parse PSS/ML-DSA/SLH-DSA leaves) and without std's commonName fallback.
    if (opts.expected_host) |host| try hostname.verify(path[0].der, host);
    const leaf_parsed: ?Certificate.Parsed = memo.parse(path[0].der) catch |err| switch (err) {
        error.CertificateHasUnrecognizedObjectId => null,
        else => |e| return e,
    };

    return .{
        .depth = @intCast(path.len - 1),
        .leaf = leaf_parsed,
        .leaf_der = path[0].der,
        .leaf_pub_key_algo = leaf_shape.pub_key_algo,
        .trust_anchor_index = path[path.len - 1].anchor_index.?,
    };
}

/// One resolved link in a built path: `der` is the certificate, and
/// `anchor_index` is set (indexing the `trust_anchors` slice passed to
/// `buildPath`) iff this entry is the path's terminus.
pub const PathEntry = struct {
    der: CertDer,
    anchor_index: ?usize,
};

/// Path-building sub-algorithm (RFC 5280 has no normative algorithm for
/// this — RFC 4158 "Internet X.509 Public Key Infrastructure: Certification
/// Path Building" is the closest reference). Given the peer-supplied
/// `chain` (leaf-first) and a `trust_anchors` store where more than one
/// certificate MAY share a subject DN (cross-signed roots, rolled-over
/// intermediates), finds an ordered, leaf-first path from `chain[0]` to some
/// trust anchor such that every adjacent pair's issuer/subject DNs match,
/// every link's signature verifies (delegating to `std.crypto.Certificate`
/// for every algorithm it supports, `verifyPssLink` for RSASSA-PSS), and
/// every non-leaf certificate is a valid CA (basicConstraints `cA` +
/// `keyUsage.keyCertSign` if present — `checkIsCaSigner`).
///
/// Returns a `gpa`-allocated, leaf-first slice (caller frees with
/// `gpa.free`); the last entry is always the trust-anchor terminus
/// (`anchor_index` set).
///
/// At each step, EVERY certificate (remaining in `chain`, or in
/// `trust_anchors`) whose subject DN equals the current certificate's
/// issuer DN is a *candidate*; when its authorityKeyIdentifier and a
/// candidate's subjectKeyIdentifier are both present and differ, that
/// candidate is excluded outright (a definitive mismatch — RFC 4158's
/// "match on issuer/subject DN + AKI/SKI" hint). If exactly one candidate
/// remains, its outcome (success or a *specific* typed error — e.g.
/// `error.NotACertificateAuthority`, `error.PathLenConstraintExceeded`) is
/// returned directly, not swallowed — most real chains have no ambiguity,
/// and a caller diagnosing a broken chain needs the real reason, not a
/// generic `error.NoTrustedPath`. Only when MULTIPLE candidates share the
/// DN does this function actually backtrack: try each in turn, and only
/// report `error.NoTrustedPath` once every candidate has failed.
pub fn buildPath(
    gpa: std.mem.Allocator,
    chain: []const CertDer,
    trust_anchors: []const CertDer,
    opts: Options,
) VerifyChainError![]PathEntry {
    var checks: u32 = 0;
    return buildPathCounted(gpa, chain, trust_anchors, opts, &checks);
}

/// The most link signatures one `buildPath` call verifies (Go's
/// `maxChainSignatureChecks`, crypto/x509/verify.go). The search backtracks
/// over every same-subject candidate, so without a bound a peer-supplied
/// chain of n intermediates sharing one DN and one key (self-made, nothing
/// trusted needed) costs about e·n! verifications — leaf + 8 such CAs, about
/// 10^5 per handshake. Past the bound the candidate fails with
/// `ChainTooLong` (`NoTrustedPath` where several candidates failed). A real
/// chain needs one check per link plus one per rejected cross-sign.
const max_signature_checks: u32 = 100;

/// `buildPath` with the running signature-check count in `checks` (read by
/// the tests).
fn buildPathCounted(
    gpa: std.mem.Allocator,
    chain: []const CertDer,
    trust_anchors: []const CertDer,
    opts: Options,
    checks: *u32,
) VerifyChainError![]PathEntry {
    var memo: Memo = .{};
    return buildPathMemo(gpa, chain, trust_anchors, opts, checks, &memo);
}

/// `buildPathCounted` filling `memo`, which `checkBuiltPath` then reads.
fn buildPathMemo(
    gpa: std.mem.Allocator,
    chain: []const CertDer,
    trust_anchors: []const CertDer,
    opts: Options,
    checks: *u32,
    memo: *Memo,
) VerifyChainError![]PathEntry {
    if (chain.len == 0) return error.EmptyChain;
    // The chain is the peer's: nothing in it reaches std's parser (which
    // `verifyLink` and `verifyChain` call) or this module's walks before
    // x509's own guard has seen it. Without this a malformed intermediate
    // made std index far out of bounds (fuzz driver, 2026-10-10: a safety
    // panic in `Certificate.parse` via `verifyLink`; an out-of-bounds read in
    // ReleaseFast). Trust anchors are the caller's own configuration.
    for (chain) |cert_der| {
        if (cert_der.len > safe.max_pq_certificate_len) return error.CertificateFieldHasInvalidLength;
        safe.validateForStdParse(cert_der) catch |err| return switch (err) {
            error.EmptyBitString => error.CertificateHasInvalidBitString,
            else => error.CertificateFieldHasInvalidLength,
        };
    }

    var path: std.ArrayList(PathEntry) = .empty;
    errdefer path.deinit(gpa);

    const used_chain = try gpa.alloc(bool, chain.len);
    defer gpa.free(used_chain);
    @memset(used_chain, false);
    used_chain[0] = true; // the leaf itself is never its own issuer candidate

    try path.append(gpa, .{ .der = chain[0], .anchor_index = null });
    const leaf_shape = try memo.shape(chain[0]);
    try findIssuerAndVerify(gpa, chain, trust_anchors, opts, chain[0], leaf_shape, used_chain, 0, &path, checks, memo);

    return try path.toOwnedSlice(gpa);
}

const Candidate = struct {
    der: CertDer,
    is_anchor: bool,
    anchor_index: usize,
    chain_index: ?usize,
};

/// Finds every candidate issuer of `cur_der` (subject DN == `cur_shape`'s
/// issuer DN, AKI/SKI-filtered) among the unused `chain` entries and
/// `trust_anchors`, then tries them per the backtracking policy documented
/// on `buildPath`.
fn findIssuerAndVerify(
    gpa: std.mem.Allocator,
    chain: []const CertDer,
    trust_anchors: []const CertDer,
    opts: Options,
    cur_der: CertDer,
    cur_shape: Shape,
    used_chain: []bool,
    depth: u32,
    path: *std.ArrayList(PathEntry),
    checks: *u32,
    memo: *Memo,
) VerifyChainError!void {
    var candidates: std.ArrayList(Candidate) = .empty;
    defer candidates.deinit(gpa);

    const cur_aki: ?[]const u8 = findAki(cur_der) catch null;

    for (chain, 0..) |c_der, i| {
        if (used_chain[i]) continue;
        const shape = memo.shape(c_der) catch continue;
        if (!std.mem.eql(u8, shape.subject, cur_shape.issuer)) continue;
        if (cur_aki) |aki| {
            if (findSki(c_der) catch null) |ski| {
                if (!std.mem.eql(u8, aki, ski)) continue;
            }
        }
        try candidates.append(gpa, .{ .der = c_der, .is_anchor = false, .anchor_index = 0, .chain_index = i });
    }
    for (trust_anchors, 0..) |a_der, i| {
        const shape = memo.shape(a_der) catch continue;
        if (!std.mem.eql(u8, shape.subject, cur_shape.issuer)) continue;
        if (cur_aki) |aki| {
            if (findSki(a_der) catch null) |ski| {
                if (!std.mem.eql(u8, aki, ski)) continue;
            }
        }
        try candidates.append(gpa, .{ .der = a_der, .is_anchor = true, .anchor_index = i, .chain_index = null });
    }

    if (candidates.items.len == 0) return error.NoTrustedPath;

    if (candidates.items.len == 1) {
        return acceptCandidate(gpa, chain, trust_anchors, opts, cur_der, candidates.items[0], used_chain, depth, path, checks, memo);
    }

    for (candidates.items) |cand| {
        if (acceptCandidate(gpa, chain, trust_anchors, opts, cur_der, cand, used_chain, depth, path, checks, memo)) {
            return;
        } else |_| {}
    }
    return error.NoTrustedPath;
}

/// Verifies `cur_der`'s signature against `cand`, checks `cand` is a valid
/// CA signer, pushes it onto `path`, and (unless `cand` is the trust-anchor
/// terminus) recurses to resolve `cand`'s own issuer. Every mutation
/// (`used_chain`, `path`) is unwound via `errdefer` on any failure, so the
/// backtracking loop in `findIssuerAndVerify` can simply retry the next
/// candidate.
fn acceptCandidate(
    gpa: std.mem.Allocator,
    chain: []const CertDer,
    trust_anchors: []const CertDer,
    opts: Options,
    cur_der: CertDer,
    cand: Candidate,
    used_chain: []bool,
    depth: u32,
    path: *std.ArrayList(PathEntry),
    checks: *u32,
    memo: *Memo,
) VerifyChainError!void {
    // Bounded work on a peer-supplied chain (`max_signature_checks`).
    if (checks.* >= max_signature_checks) return error.ChainTooLong;
    checks.* += 1;
    try verifyLink(cur_der, cand.der, opts.now_sec, opts.allow_sha1_signatures, memo);
    // A v1 certificate cannot carry basicConstraints; as a trust anchor it is
    // the caller's configuration, and Go and OpenSSL both trust one (probe
    // O-roots, 2026-10-11). A v3 anchor must still be a CA.
    if (!(cand.is_anchor and try isV1(cand.der))) try checkIsCaSigner(cand.der);
    try extensions.checkHygiene(.{ .buffer = cand.der, .index = 0 }, opts.ignore_critical_oids);
    if (cand.is_anchor and opts.check_anchor_validity) {
        // Every other certificate's window is checked as the subject of its
        // link (`verifyLink`); the anchor is never a subject, so it is here.
        const anchor_shape = try memo.shape(cand.der);
        if (opts.now_sec < anchor_shape.not_before) return error.CertificateNotYetValid;
        if (opts.now_sec > anchor_shape.not_after) return error.CertificateExpired;
    }
    if (opts.revocation) |rev| {
        if (rev.scope == .full_chain or depth == 0) try checkRevocation(rev, opts.now_sec, trust_anchors, cur_der, cand.der);
    }

    if (cand.chain_index) |ci| used_chain[ci] = true;
    errdefer if (cand.chain_index) |ci| {
        used_chain[ci] = false;
    };

    try path.append(gpa, .{ .der = cand.der, .anchor_index = if (cand.is_anchor) cand.anchor_index else null });
    errdefer _ = path.pop();

    if (cand.is_anchor) return;

    const next_depth = depth + 1;
    if (next_depth > opts.max_intermediates) return error.ChainTooLong;

    const next_shape = try memo.shape(cand.der);
    try findIssuerAndVerify(gpa, chain, trust_anchors, opts, cand.der, next_shape, used_chain, next_depth, path, checks, memo);
}

/// One certificate's revocation verdict under `rev` (rules on `Revocation`):
/// every CRL is consulted, any `.revoked` wins over any `.good`. `issuer_der`
/// is the CRL issuer certificate (the certificate's path issuer). A
/// certificate that is itself a trust anchor is trusted input and is not
/// checked (this also keeps a chain that carries its anchor working).
fn checkRevocation(
    rev: Revocation,
    now_sec: i64,
    trust_anchors: []const CertDer,
    cert_der: CertDer,
    issuer_der: CertDer,
) VerifyChainError!void {
    for (trust_anchors) |a| if (std.mem.eql(u8, a, cert_der)) return;
    var have_good = false;
    for (rev.crls) |crl_der| {
        const st = crl.checkRevocation(crl_der, cert_der, issuer_der, .{
            .now_sec = now_sec,
            .max_age_sec = rev.max_age_sec,
        }) catch |err| switch (err) {
            // Not a property of the CRL: propagate. (`checkRevocation` does not
            // allocate; the variant is in the set only through `VerifyChainError`.)
            error.OutOfMemory => return error.OutOfMemory,
            // Not about this certificate, or unable to vouch for it: no verdict
            // from this CRL (the other CRLs may still give one).
            else => continue,
        };
        switch (st) {
            .revoked => return error.CertificateRevoked,
            .good => have_good = true,
        }
    }
    if (!have_good and rev.unknown == .reject) return error.RevocationStatusUnknown;
}

fn isV1(cert_der: CertDer) Certificate.ParseError!bool {
    const certificate = try extensions.parseElement(cert_der, 0);
    const tbs = try extensions.parseElement(cert_der, certificate.slice.start);
    const version_elem = try extensions.parseElement(cert_der, tbs.slice.start);
    return try Certificate.parseVersion(cert_der, version_elem) == .v1;
}

/// Verifies that `cand_der` is a certificate authority eligible to sign
/// another certificate: `basicConstraints.cA` (RFC 5280 §4.2.1.9) must be
/// true, and if `keyUsage` is present, `keyCertSign` must be asserted (RFC
/// 5280 §4.2.1.3). Uses `extensions.zig` directly (not
/// `std.crypto.Certificate.Parsed`) so this works even for a PSS-signed
/// certificate, which std cannot parse at all.
fn checkIsCaSigner(cand_der: CertDer) VerifyChainError!void {
    const bc = try findBasicConstraints(cand_der);
    if (!bc.is_ca) return error.NotACertificateAuthority;
    if (try findExtensionValue(cand_der, .key_usage)) |v| {
        const ku = try extensions.parseKeyUsage(v);
        if (!ku.key_cert_sign) return error.KeyUsageForbidsCertSigning;
    }
}

/// Verifies `subject_der`'s signature was made by `issuer_der`'s key
/// (`+` time validity — RFC 5280 §6.1.3 (a)(1)/(2)/(3)). Dispatches on
/// `subject_der`'s own `signatureAlgorithm`: RSASSA-PSS (which
/// `std.crypto.Certificate` cannot even parse) routes to `verifyPssLink`;
/// a P-521 issuer key routes to `verifyP521Link` (std refuses the curve);
/// everything std supports (RSA PKCS1v15, ECDSA P-256/P-384, Ed25519)
/// routes to `std.crypto.Certificate.Parsed.verify`. For that std path, the
/// issuer only needs to supply its public key and subject DN — fields that
/// parse independently of whether the issuer's OWN signature is PSS — so a
/// PSS-signed issuer whose `Certificate.parse()` fails outright is handled
/// via `partialIssuerParsed` rather than giving up (this matters: in a
/// chain where an intermediate is PSS-signed by the root but itself signs
/// the leaf with a std-supported algorithm, the leaf link needs exactly
/// this fallback).
fn verifyLink(subject_der: CertDer, issuer_der: CertDer, now_sec: i64, allow_sha1: bool, memo: *Memo) VerifyChainError!void {
    const subject_shape = try memo.shape(subject_der);
    if (!allow_sha1 and try signedWithSha1(subject_shape)) return error.WeakSignatureAlgorithm;

    if (algorithm.MlDsa.map.get(subject_shape.sig_alg_oid) != null) {
        return verifyMlDsaLink(subject_der, issuer_der, now_sec);
    }

    if (algorithm.SlhDsa.map.get(subject_shape.sig_alg_oid) != null) {
        return verifySlhDsaLink(subject_der, issuer_der, now_sec);
    }

    if (Certificate.AlgorithmCategory.map.get(subject_shape.sig_alg_oid) == .rsassa_pss) {
        const issuer_shape = try memo.shape(issuer_der);
        const issuer_pub_key = try rsa.PublicKey.fromDer(issuer_shape.spki);
        return verifyPssLink(subject_der, issuer_pub_key, now_sec);
    }

    // ECDSA under a P-521 issuer key: std names the curve but its
    // `Parsed.verify` refuses it (`CertificateSignatureNamedCurveUnsupported`),
    // so this link is checked here, through the `p521` module.
    {
        const issuer_shape = try memo.shape(issuer_der);
        if (isP521(issuer_shape.pub_key_algo)) return verifyP521Link(subject_shape, issuer_der, issuer_shape, now_sec);
    }

    const subject_parsed = try memo.parse(subject_der);

    const issuer_cert: Certificate = .{ .buffer = issuer_der, .index = 0 };
    const issuer_parsed = memo.parse(issuer_der) catch |err| switch (err) {
        error.CertificateHasUnrecognizedObjectId => try partialIssuerParsed(issuer_cert, try memo.shape(issuer_der)),
        else => |e| return e,
    };

    try verifyParsed(subject_parsed, issuer_parsed, now_sec);
}

const oid_sha1_with_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05 };

/// Whether a certificate's own signature uses SHA-1: PKCS#1 v1.5
/// `sha1WithRSAEncryption`, or RSASSA-PSS whose hash is SHA-1 — including the
/// RFC 4055 all-defaults parameters. `ecdsa-with-SHA1` needs no case: neither
/// std's table nor `algorithm.zig` names it, so it never verifies at all.
fn signedWithSha1(shape: Shape) ParsePssParamsError!bool {
    if (std.mem.eql(u8, shape.sig_alg_oid, &oid_sha1_with_rsa)) return true;
    if (Certificate.AlgorithmCategory.map.get(shape.sig_alg_oid) == .rsassa_pss)
        return (try parsePssParams(shape.sig_alg_params)).hash == .sha1;
    return false;
}

/// `std.crypto.Certificate.Parsed.verify`, check for check and error for
/// error, with the signature mathematics of its two hot cases swapped for
/// this repository's: PKCS#1 v1.5 through `rsa.VerifyKey` and ECDSA under a
/// P-256 key through `p256`. std's own RSA path builds an `ff.Modulus` per
/// call and its P-256 is the portable `pcurves` code; the two were 6.4–7.3×
/// Go's `crypto/x509` on a three-certificate chain (bench-x509, 2026-10-11).
/// P-384 and Ed25519 stay on std. One deliberate difference: std accepts an
/// RSA exponent of 1, under which any `EM` is its own signature; `rsa`
/// refuses `e < 3` and the link fails with `CertificateSignatureInvalid`.
fn verifyParsed(subject: Certificate.Parsed, issuer: Certificate.Parsed, now_sec: i64) Certificate.Parsed.VerifyError!void {
    if (!std.mem.eql(u8, subject.issuer(), issuer.subject())) return error.CertificateIssuerMismatch;
    if (now_sec < subject.validity.not_before) return error.CertificateNotYetValid;
    if (now_sec > subject.validity.not_after) return error.CertificateExpired;

    switch (subject.signature_algorithm) {
        inline .sha1WithRSAEncryption,
        .sha224WithRSAEncryption,
        .sha256WithRSAEncryption,
        .sha384WithRSAEncryption,
        .sha512WithRSAEncryption,
        => |alg| return verifyRsaPkcs1(alg.Hash(), subject.message(), subject.signature(), issuer.pub_key_algo, issuer.pubKey()),
        inline .ecdsa_with_SHA224,
        .ecdsa_with_SHA256,
        .ecdsa_with_SHA384,
        .ecdsa_with_SHA512,
        => |alg| switch (issuer.pub_key_algo) {
            .X9_62_id_ecPublicKey => |curve| if (curve == .X9_62_prime256v1)
                return verifyEcdsaP256(alg.Hash(), subject.message(), subject.signature(), issuer.pubKey()),
            else => {},
        },
        else => {},
    }
    return subject.verify(issuer, now_sec);
}

/// std's `verifyRsa` gates (algorithm, key DER, exponent ≤ modulus length,
/// signature length, modulus of 1024/2048/3072/4096 bits) in std's order and
/// with std's errors, then `rsa.VerifyKey`.
fn verifyRsaPkcs1(comptime Hash: type, msg: []const u8, sig: []const u8, pub_key_algo: Certificate.Parsed.PubKeyAlgo, pub_key: []const u8) Certificate.Parsed.VerifyError!void {
    if (pub_key_algo != .rsaEncryption) return error.CertificateSignatureAlgorithmMismatch;
    const parts = try Certificate.rsa.PublicKey.parseDer(pub_key);
    if (parts.exponent.len > parts.modulus.len) return error.CertificatePublicKeyInvalid;
    if (sig.len != parts.modulus.len) return error.CertificateSignatureInvalidLength;
    switch (parts.modulus.len) {
        128, 256, 384, 512 => {},
        else => return error.CertificateSignatureUnsupportedBitCount,
    }
    const vk = rsa.VerifyKey.fromBytes(parts.modulus, parts.exponent) catch return error.CertificateSignatureInvalid;
    vk.verifyPkcs1v15(Hash, msg, sig) catch return error.CertificateSignatureInvalid;
}

/// std's `verify_ecdsa` for a P-256 key: a DER signature std's parser
/// accepts, then `p256.sign.ecdsaVerifyDigest` over the message's digest.
/// Every failure is `CertificateSignatureInvalid`, as in std.
fn verifyEcdsaP256(comptime Hash: type, msg: []const u8, sig_der: []const u8, sec1_key: []const u8) Certificate.Parsed.VerifyError!void {
    const Sig = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P256, Hash).Signature;
    const sig = Sig.fromDer(sig_der) catch return error.CertificateSignatureInvalid;
    var digest: [Hash.digest_length]u8 = undefined;
    Hash.hash(msg, &digest, .{});
    if (!p256.sign.ecdsaVerifyDigest(sec1_key, &digest, sig.toBytes())) return error.CertificateSignatureInvalid;
}

fn isP521(algo: algorithm.PubKeyAlgo) bool {
    return switch (algo) {
        .X9_62_id_ecPublicKey => |curve| curve == .secp521r1,
        else => false,
    };
}

/// A link whose issuer key is ECDSA P-521, in std's `Parsed.verify` order:
/// issuer DN, validity window, then the signature.
fn verifyP521Link(subject_shape: Shape, issuer_der: CertDer, issuer_shape: Shape, now_sec: i64) VerifyChainError!void {
    if (!std.mem.eql(u8, subject_shape.issuer, issuer_shape.subject)) return error.CertificateIssuerMismatch;
    if (now_sec < @as(i64, @intCast(subject_shape.not_before))) return error.CertificateNotYetValid;
    if (now_sec > @as(i64, @intCast(subject_shape.not_after))) return error.CertificateExpired;
    const key = issuer_der[issuer_shape.pub_key_slice.start..issuer_shape.pub_key_slice.end];
    return verifyP521Signature(subject_shape.sig_alg_oid, subject_shape.message, subject_shape.signature, key);
}

/// ECDSA-with-SHA224/256/384/512 under a P-521 SEC1 key, with std's error
/// mapping (`verify_ecdsa`): a non-ECDSA signature algorithm is an algorithm
/// mismatch, a bad key / signature encoding or a failed check is
/// `CertificateSignatureInvalid`. The DER signature is parsed strictly
/// (`p521.Ecdsa.Signature.fromDer`).
fn verifyP521Signature(sig_alg_oid: []const u8, message: []const u8, signature: []const u8, sec1_key: []const u8) VerifyChainError!void {
    const alg = Certificate.Algorithm.map.get(sig_alg_oid) orelse
        return error.CertificateSignatureAlgorithmUnsupported;
    switch (alg) {
        inline .ecdsa_with_SHA224, .ecdsa_with_SHA256, .ecdsa_with_SHA384, .ecdsa_with_SHA512 => |a| {
            const E = p521.Ecdsa(a.Hash());
            const pk = E.PublicKey.fromSec1(sec1_key) catch return error.CertificateSignatureInvalid;
            const sig = E.Signature.fromDer(signature) catch return error.CertificateSignatureInvalid;
            sig.verify(message, pk) catch return error.CertificateSignatureInvalid;
        },
        else => return error.CertificateSignatureAlgorithmMismatch,
    }
}

/// Verifies an ML-DSA link (RFC 9881) — the second algorithm this module
/// verifies itself rather than delegating, for the same reason as
/// RSASSA-PSS: `std.crypto.Certificate` cannot name the OID, so
/// `Certificate.parse()` fails on such a certificate before returning
/// anything. Unlike PSS the obstacle is only the *table* — the signature
/// mathematics is `std.crypto.sign.mldsa`, std's own and measured faster
/// than OpenSSL 3.5 on every operation.
///
/// Public for the same reason `verifyPssLink` is: a consumer holding one
/// certificate and its issuer should be able to check that link without
/// building a path — and it is what makes the parameter-set check directly
/// testable, which through `verifyChain` alone it is not (path building
/// collapses a failed trust-anchor candidate into `NoTrustedPath`).
pub fn verifyMlDsaLink(
    subject_der: CertDer,
    issuer_der: CertDer,
    now_sec: i64,
) VerifyChainError!void {
    const subject_shape = try parseShape(.{ .buffer = subject_der, .index = 0 });
    const set = algorithm.MlDsa.map.get(subject_shape.sig_alg_oid) orelse
        return error.CertificateSignatureAlgorithmUnsupported;

    // Same `@intCast` reasoning as `verifyPssLink`: real certificate dates
    // are well inside i64, and this asserts it rather than truncating.
    if (now_sec < @as(i64, @intCast(subject_shape.not_before))) return error.CertificateNotYetValid;
    if (now_sec > @as(i64, @intCast(subject_shape.not_after))) return error.CertificateExpired;

    const issuer_shape = try parseShape(.{ .buffer = issuer_der, .index = 0 });

    // The subject's signatureAlgorithm names a parameter set; the issuer's
    // key must BE that parameter set. ML-DSA sizes differ per level, so a
    // mismatch would otherwise surface as a length error and read like a
    // corrupt certificate instead of the algorithm confusion it is.
    switch (issuer_shape.pub_key_algo) {
        .ml_dsa => |issuer_set| if (issuer_set != set) return error.CertificateSignatureAlgorithmMismatch,
        else => return error.CertificateSignatureAlgorithmMismatch,
    }

    // RFC 5280 §6.1.3 (a)(4): the issuer's subject DN must be the subject's
    // issuer DN. `verifyChain` already guarantees it — `findIssuerAndVerify`
    // only offers candidates whose subject matches — but these two functions
    // are public and documented as the way to check a single link without
    // building a path, and their std counterpart (`Parsed.verify`) makes the
    // check. Without it they are not the parity that doc comment claims.
    // Ordered after the parameter-set comparison so an algorithm mismatch is
    // still reported as one rather than being masked by a name mismatch.
    if (!std.mem.eql(u8, subject_shape.issuer, issuer_shape.subject))
        return error.CertificateIssuerMismatch;

    const key_bytes = issuer_der[issuer_shape.pub_key_slice.start..issuer_shape.pub_key_slice.end];

    switch (set) {
        inline else => |comptime_set| {
            const Impl = algorithm.MlDsa.Impl(comptime_set);
            // Both lengths are fixed by the parameter set, so a certificate
            // that disagrees is rejected before any slice is reinterpreted.
            if (key_bytes.len != Impl.PublicKey.encoded_length) return error.CertificatePublicKeyInvalid;
            if (subject_shape.signature.len != Impl.Signature.encoded_length) return error.CertificateSignatureInvalidLength;

            const pub_key = Impl.PublicKey.fromBytes(key_bytes[0..Impl.PublicKey.encoded_length].*) catch
                return error.CertificatePublicKeyInvalid;
            const sig = Impl.Signature.fromBytes(subject_shape.signature[0..Impl.Signature.encoded_length].*) catch
                return error.CertificateSignatureInvalid;
            // Pure ML-DSA with an empty context string, which is what
            // RFC 9881 §4 specifies for certificate signatures.
            sig.verify(subject_shape.message, pub_key) catch return error.CertificateSignatureInvalid;
        },
    }
}

/// Verifies an SLH-DSA link (RFC 9882) — the third algorithm this module
/// verifies itself, for the same reason as the other two: the OID is not in
/// `std.crypto.Certificate`'s closed table. Structurally identical to
/// `verifyMlDsaLink`; the differences are twelve parameter sets instead of
/// three, and this repo's own `slhdsa` module instead of std (std has no
/// SLH-DSA at all).
///
/// `slhdsa`'s `verify` returns `bool` rather than an error union and is
/// documented never to panic on a wrong-length signature — the length checks
/// below are still made explicitly, so a size mismatch is reported as one
/// instead of arriving as a bare `false` indistinguishable from a forgery.
pub fn verifySlhDsaLink(
    subject_der: CertDer,
    issuer_der: CertDer,
    now_sec: i64,
) VerifyChainError!void {
    const subject_shape = try parseShape(.{ .buffer = subject_der, .index = 0 });
    const set = algorithm.SlhDsa.map.get(subject_shape.sig_alg_oid) orelse
        return error.CertificateSignatureAlgorithmUnsupported;

    if (now_sec < @as(i64, @intCast(subject_shape.not_before))) return error.CertificateNotYetValid;
    if (now_sec > @as(i64, @intCast(subject_shape.not_after))) return error.CertificateExpired;

    const issuer_shape = try parseShape(.{ .buffer = issuer_der, .index = 0 });

    // Same reasoning as the ML-DSA path: the subject's signatureAlgorithm
    // names a parameter set and the issuer's key must BE it. Here it matters
    // more, not less — two sets share a public-key length for every security
    // category (`s` and `f` differ only in signature size), so a length check
    // alone would let an `s` key through for an `f` signature.
    switch (issuer_shape.pub_key_algo) {
        .slh_dsa => |issuer_set| if (issuer_set != set) return error.CertificateSignatureAlgorithmMismatch,
        else => return error.CertificateSignatureAlgorithmMismatch,
    }

    // RFC 5280 §6.1.3 (a)(4): the issuer's subject DN must be the subject's
    // issuer DN. `verifyChain` already guarantees it — `findIssuerAndVerify`
    // only offers candidates whose subject matches — but these two functions
    // are public and documented as the way to check a single link without
    // building a path, and their std counterpart (`Parsed.verify`) makes the
    // check. Without it they are not the parity that doc comment claims.
    // Ordered after the parameter-set comparison so an algorithm mismatch is
    // still reported as one rather than being masked by a name mismatch.
    if (!std.mem.eql(u8, subject_shape.issuer, issuer_shape.subject))
        return error.CertificateIssuerMismatch;

    const key_bytes = issuer_der[issuer_shape.pub_key_slice.start..issuer_shape.pub_key_slice.end];

    switch (set) {
        inline else => |comptime_set| {
            const Impl = algorithm.SlhDsa.Impl(comptime_set);
            if (key_bytes.len != Impl.public_key_length) return error.CertificatePublicKeyInvalid;
            if (subject_shape.signature.len != Impl.signature_length) return error.CertificateSignatureInvalidLength;

            const pub_key = Impl.PublicKey.fromBytes(key_bytes[0..Impl.public_key_length].*);
            // Pure SLH-DSA with an empty context string (RFC 9882 §4), the
            // same convention RFC 9881 sets for ML-DSA.
            if (!Impl.verify(subject_shape.signature, subject_shape.message, pub_key, "")) {
                return error.CertificateSignatureInvalid;
            }
        },
    }
}

// ── signed objects other than certificates (CRLs) ───────────────────────────

/// A signed structure with the certificate's outer shape — `SEQUENCE { tbs,
/// signatureAlgorithm, signatureValue }` — that is not a certificate: a CRL
/// (RFC 5280 §5.1). Offsets are into `buffer`.
pub const SignedData = struct {
    buffer: []const u8,
    /// The `tbs…` TLV (tag+length+content): what was signed.
    message_slice: der.Element.Slice,
    /// `signatureValue` BIT STRING content, unused-bits octet stripped.
    signature_slice: der.Element.Slice,
    /// Outer `signatureAlgorithm` OID bytes and its `parameters` TLV.
    sig_alg_oid: []const u8,
    sig_alg_params: ?[]const u8,
    /// The object's issuer `Name` (RDNSequence content), which must equal
    /// the issuer certificate's subject.
    issuer_slice: der.Element.Slice,
};

/// Verify `data`'s signature under `issuer_der`'s key, with the same
/// algorithm dispatch `verifyLink` applies to a certificate: ML-DSA,
/// SLH-DSA and RSASSA-PSS here, everything std names through
/// `Certificate.Parsed.verify`. Checks that `data`'s issuer name equals the
/// issuer certificate's subject. Validity windows are the caller's (a CRL has
/// thisUpdate/nextUpdate, not notBefore/notAfter).
pub fn verifySignedBy(data: SignedData, issuer_der: CertDer) VerifyChainError!void {
    const issuer_cert: Certificate = .{ .buffer = issuer_der, .index = 0 };
    const issuer_shape = try parseShape(issuer_cert);
    const data_issuer = data.buffer[data.issuer_slice.start..data.issuer_slice.end];
    const message = data.buffer[data.message_slice.start..data.message_slice.end];
    const signature = data.buffer[data.signature_slice.start..data.signature_slice.end];

    if (algorithm.MlDsa.map.get(data.sig_alg_oid)) |set| {
        switch (issuer_shape.pub_key_algo) {
            .ml_dsa => |issuer_set| if (issuer_set != set) return error.CertificateSignatureAlgorithmMismatch,
            else => return error.CertificateSignatureAlgorithmMismatch,
        }
        if (!std.mem.eql(u8, data_issuer, issuer_shape.subject)) return error.CertificateIssuerMismatch;
        const key_bytes = issuer_der[issuer_shape.pub_key_slice.start..issuer_shape.pub_key_slice.end];
        switch (set) {
            inline else => |comptime_set| {
                const Impl = algorithm.MlDsa.Impl(comptime_set);
                if (key_bytes.len != Impl.PublicKey.encoded_length) return error.CertificatePublicKeyInvalid;
                if (signature.len != Impl.Signature.encoded_length) return error.CertificateSignatureInvalidLength;
                const pub_key = Impl.PublicKey.fromBytes(key_bytes[0..Impl.PublicKey.encoded_length].*) catch
                    return error.CertificatePublicKeyInvalid;
                const sig = Impl.Signature.fromBytes(signature[0..Impl.Signature.encoded_length].*) catch
                    return error.CertificateSignatureInvalid;
                sig.verify(message, pub_key) catch return error.CertificateSignatureInvalid;
            },
        }
        return;
    }

    if (algorithm.SlhDsa.map.get(data.sig_alg_oid)) |set| {
        switch (issuer_shape.pub_key_algo) {
            .slh_dsa => |issuer_set| if (issuer_set != set) return error.CertificateSignatureAlgorithmMismatch,
            else => return error.CertificateSignatureAlgorithmMismatch,
        }
        if (!std.mem.eql(u8, data_issuer, issuer_shape.subject)) return error.CertificateIssuerMismatch;
        const key_bytes = issuer_der[issuer_shape.pub_key_slice.start..issuer_shape.pub_key_slice.end];
        switch (set) {
            inline else => |comptime_set| {
                const Impl = algorithm.SlhDsa.Impl(comptime_set);
                if (key_bytes.len != Impl.public_key_length) return error.CertificatePublicKeyInvalid;
                if (signature.len != Impl.signature_length) return error.CertificateSignatureInvalidLength;
                const pub_key = Impl.PublicKey.fromBytes(key_bytes[0..Impl.public_key_length].*);
                if (!Impl.verify(signature, message, pub_key, "")) return error.CertificateSignatureInvalid;
            },
        }
        return;
    }

    if (Certificate.AlgorithmCategory.map.get(data.sig_alg_oid) == .rsassa_pss) {
        if (!std.mem.eql(u8, data_issuer, issuer_shape.subject)) return error.CertificateIssuerMismatch;
        const issuer_pub_key = try rsa.PublicKey.fromDer(issuer_shape.spki);
        const params = try parsePssParams(data.sig_alg_params);
        switch (params.hash) {
            inline else => |h| {
                const Hash = switch (h) {
                    .sha1 => std.crypto.hash.Sha1,
                    .sha224 => std.crypto.hash.sha2.Sha224,
                    .sha256 => std.crypto.hash.sha2.Sha256,
                    .sha384 => std.crypto.hash.sha2.Sha384,
                    .sha512 => std.crypto.hash.sha2.Sha512,
                };
                rsa.verifyPss(issuer_pub_key, Hash, message, signature, params.salt_len) catch
                    return error.CertificateSignatureInvalid;
            },
        }
        return;
    }

    if (isP521(issuer_shape.pub_key_algo)) {
        if (!std.mem.eql(u8, data_issuer, issuer_shape.subject)) return error.CertificateIssuerMismatch;
        const key = issuer_der[issuer_shape.pub_key_slice.start..issuer_shape.pub_key_slice.end];
        return verifyP521Signature(data.sig_alg_oid, message, signature, key);
    }

    // Everything std names: a `Parsed` view of the signed object carrying
    // exactly what `Parsed.verify` reads from its subject argument — issuer
    // name, validity (made unbounded: the caller checks the object's own
    // window), algorithm, message, signature.
    const sig_alg = Certificate.Algorithm.map.get(data.sig_alg_oid) orelse
        return error.CertificateSignatureAlgorithmUnsupported;
    const subject: Certificate.Parsed = .{
        .certificate = .{ .buffer = data.buffer, .index = 0 },
        .issuer_slice = data.issuer_slice,
        .subject_slice = der.Element.Slice.empty,
        .common_name_slice = der.Element.Slice.empty,
        .signature_slice = data.signature_slice,
        .signature_algorithm = sig_alg,
        .pub_key_algo = .rsaEncryption, // not read from the subject side
        .pub_key_slice = der.Element.Slice.empty,
        .message_slice = data.message_slice,
        .subject_alt_name_slice = der.Element.Slice.empty,
        .validity = .{ .not_before = 0, .not_after = std.math.maxInt(u64) },
        .version = .v3,
    };
    const issuer_parsed = issuer_cert.parse() catch |err| switch (err) {
        error.CertificateHasUnrecognizedObjectId => try partialIssuerParsed(issuer_cert, issuer_shape),
        else => |e| return e,
    };
    try verifyParsed(subject, issuer_parsed, 0);
}

/// The certificate's `serialNumber` (INTEGER content) and issuer `Name`
/// (RDNSequence content), read with the same bounded walk as path
/// validation — for revocation lookups.
pub fn certSerialAndIssuer(cert_der: CertDer) Certificate.ParseError!struct { serial: []const u8, issuer: []const u8 } {
    const shape = try parseShape(.{ .buffer = cert_der, .index = 0 });
    return .{ .serial = shape.serial, .issuer = shape.issuer };
}

/// The certificate's validity window (epoch seconds, UTC), read with the
/// same bounded walk — for renewal timing on a certificate a CA just sent.
pub fn certValidity(cert_der: CertDer) Certificate.ParseError!struct { not_before: u64, not_after: u64 } {
    const shape = try parseShape(.{ .buffer = cert_der, .index = 0 });
    return .{ .not_before = shape.not_before, .not_after = shape.not_after };
}

/// The `keyIdentifier` of the certificate's authorityKeyIdentifier, or null
/// when the extension or that field is absent (ACME ARI's CertID, RFC 9773).
pub fn certAuthorityKeyId(cert_der: CertDer) VerifyChainError!?[]const u8 {
    return findAki(cert_der);
}

/// The raw extnValue of the certificate's extension `id`, or null.
pub fn certExtensionValue(cert_der: CertDer, id: Certificate.ExtensionId) VerifyChainError!?[]const u8 {
    return findExtensionValue(cert_der, id);
}

/// `basicConstraints.cA` of a certificate (false when the extension is absent).
pub fn certIsCa(cert_der: CertDer) VerifyChainError!bool {
    return (try findBasicConstraints(cert_der)).is_ca;
}

// ── raw-DER structural walk (PSS-safe: never calls Certificate.parse) ──────

/// Everything `chain.zig` needs from a certificate's structure that
/// `std.crypto.Certificate.Parsed` either doesn't expose or (for a
/// PSS-signed certificate) cannot produce at all, since
/// `Certificate.parse()` itself fails on one before returning anything.
/// Mirrors the exact same field-by-field walk `std.crypto.Certificate.parse`
/// and `extensions.findExtensions` already perform (version → serialNumber
/// → signature → issuer → validity → subject → subjectPublicKeyInfo →
/// [extensions]) — reusing that established pattern rather than a fresh
/// invention, per this repo's convention of not re-deriving DER structure
/// twice — carried one step further to also expose the outer
/// `signatureAlgorithm`/`signatureValue` fields extensions.zig has no need
/// for.
const Shape = struct {
    /// `serialNumber` INTEGER content bytes, as encoded.
    serial: []const u8,
    /// Raw `RDNSequence` content bytes — same convention as
    /// `Certificate.Parsed.issuer()`/`.subject()` (no outer SEQUENCE
    /// tag/length), so byte-equality comparisons between the two are valid.
    issuer: []const u8,
    subject: []const u8,
    issuer_slice: der.Element.Slice,
    subject_slice: der.Element.Slice,
    not_before: u64,
    not_after: u64,
    /// The full `tbsCertificate` TLV (tag+length+content) — what's actually
    /// signed.
    message: []const u8,
    /// Raw `signatureValue` bytes (BIT STRING content, unused-bits octet
    /// already stripped).
    signature: []const u8,
    /// Raw OID bytes of the OUTER `signatureAlgorithm` (how THIS
    /// certificate was signed by its issuer) — not the SubjectPublicKeyInfo
    /// algorithm, a different field.
    sig_alg_oid: []const u8,
    /// The outer `signatureAlgorithm`'s `parameters` field, full TLV, when
    /// present (`null` when the AlgorithmIdentifier has no second field at
    /// all). For RSASSA-PSS this is the `RSASSA-PSS-params` SEQUENCE
    /// `parsePssParams` decodes; for every other algorithm it's usually a
    /// NULL and unused.
    sig_alg_params: ?[]const u8,
    /// Full `SubjectPublicKeyInfo` TLV — feed directly to
    /// `rsa.PublicKey.fromDer`.
    spki: []const u8,
    /// This module's own algorithm union, not std's: std's cannot name
    /// ML-DSA, and `parseShape` must be able to describe a certificate std
    /// declines to parse at all (that is already true for RSASSA-PSS).
    /// `algorithm.PubKeyAlgo.toStd` converts back for the delegated paths.
    pub_key_algo: algorithm.PubKeyAlgo,
    pub_key_slice: der.Element.Slice,
};

/// `std.crypto.Certificate.parseBitString` with the precondition it is missing.
///
/// std reads the BIT STRING's unused-bits octet as `cert.buffer[elem.slice.start]`
/// without first checking the element has any content, and returns
/// `.{ .start = start + 1, .end = end }` regardless. On a zero-length BIT
/// STRING that is either an index past the buffer (when the element ends the
/// buffer) or a returned slice whose start is one past its end — and the
/// caller then slices with it, which panics in safe modes and yields a `len`
/// of 2^32-1 in ReleaseFast. Same bug class as the two zero-length-BOOLEAN
/// reads `extensions.zig` guards against; the guard has to live here because
/// the unchecked primitive is std's.
///
/// X.690 §8.6.2.3 requires the initial octet to be present even for an empty
/// bitstring, so zero content octets is malformed encoding, not an edge case.
fn parseBitStringSafe(cert: Certificate, elem: der.Element) Certificate.ParseError!der.Element.Slice {
    if (elem.slice.start >= elem.slice.end) return error.CertificateHasInvalidBitString;
    return Certificate.parseBitString(cert, elem);
}

/// `e`'s identifier octet must be exactly `byte`. The positions below are
/// fixed by RFC 5280 §4.1; std's reader descends by position and never looks.
/// Checking matters even where the bytes are outside the signed
/// tbsCertificate: an unchecked tag there (the outer SEQUENCE, the signature
/// BIT STRING) lets one signature verify under several encodings, i.e. under
/// several certificate fingerprints (found by the x509 fuzz driver,
/// 2026-10-10: octet 0 `30` -> `0e`, the signature's `03` -> `c3`).
fn expectTag(e: der.Element, byte: u8) Certificate.ParseError!void {
    if (@as(u8, @bitCast(e.identifier)) != byte) return error.CertificateFieldHasWrongDataType;
}

const tag_sequence: u8 = 0x30;
const tag_bit_string: u8 = 0x03;

/// `parseShape` and std's `Certificate.parse` results for the certificates
/// one `verifyChain` call looks at, keyed by the DER slice (the same slice
/// of `chain` / `trust_anchors` every time). A link parsed its issuer and the
/// next link the same certificate as subject again, and the leaf was parsed
/// once more for `VerifiedChain.leaf` (2026-10-26: 5 std parses for a
/// three-certificate chain, now 3). Failures are not kept; past `cap`
/// certificates it parses without keeping.
const Memo = struct {
    const cap = 12;
    ders: [cap]CertDer = undefined,
    shapes: [cap]?Shape = @splat(null),
    parsed: [cap]?Certificate.Parsed = @splat(null),
    len: usize = 0,

    fn slot(m: *Memo, cert_der: CertDer) ?usize {
        for (m.ders[0..m.len], 0..) |d, i| {
            if (d.ptr == cert_der.ptr and d.len == cert_der.len) return i;
        }
        if (m.len == cap) return null;
        m.ders[m.len] = cert_der;
        m.len += 1;
        return m.len - 1;
    }

    fn shape(m: *Memo, cert_der: CertDer) Certificate.ParseError!Shape {
        const i = m.slot(cert_der) orelse return parseShape(.{ .buffer = cert_der, .index = 0 });
        if (m.shapes[i]) |s| return s;
        const s = try parseShape(.{ .buffer = cert_der, .index = 0 });
        m.shapes[i] = s;
        return s;
    }

    fn parse(m: *Memo, cert_der: CertDer) Certificate.ParseError!Certificate.Parsed {
        const cert: Certificate = .{ .buffer = cert_der, .index = 0 };
        const i = m.slot(cert_der) orelse return cert.parse();
        if (m.parsed[i]) |p| return p;
        const p = try cert.parse();
        m.parsed[i] = p;
        return p;
    }
};

fn parseShape(cert: Certificate) Certificate.ParseError!Shape {
    const bytes = cert.buffer;
    const certificate = try extensions.parseElement(bytes, cert.index);
    try expectTag(certificate, tag_sequence);
    const tbs_certificate = try extensions.parseElement(bytes, certificate.slice.start);
    try expectTag(tbs_certificate, tag_sequence);
    const version_elem = try extensions.parseElement(bytes, tbs_certificate.slice.start);
    _ = try Certificate.parseVersion(bytes, version_elem);
    const serial_number = if (@as(u8, @bitCast(version_elem.identifier)) == 0xa0)
        try extensions.parseElement(bytes, version_elem.slice.end)
    else
        version_elem;
    const tbs_signature = try extensions.parseElement(bytes, serial_number.slice.end);
    try expectTag(tbs_signature, tag_sequence);
    const issuer = try extensions.parseElement(bytes, tbs_signature.slice.end);
    try expectTag(issuer, tag_sequence);
    const validity = try extensions.parseElement(bytes, issuer.slice.end);
    try expectTag(validity, tag_sequence);
    const not_before_elem = try extensions.parseElement(bytes, validity.slice.start);
    const not_before = try Certificate.parseTime(cert, not_before_elem);
    const not_after_elem = try extensions.parseElement(bytes, not_before_elem.slice.end);
    const not_after = try Certificate.parseTime(cert, not_after_elem);
    const subject = try extensions.parseElement(bytes, validity.slice.end);
    try expectTag(subject, tag_sequence);
    const pub_key_info = try extensions.parseElement(bytes, subject.slice.end);
    try expectTag(pub_key_info, tag_sequence);

    const pub_key_alg_seq = try extensions.parseElement(bytes, pub_key_info.slice.start);
    try expectTag(pub_key_alg_seq, tag_sequence);
    const pub_key_alg_oid = try extensions.parseElement(bytes, pub_key_alg_seq.slice.start);
    if (pub_key_alg_oid.identifier.tag != .object_identifier) return error.CertificateFieldHasWrongDataType;
    const pub_key_alg_oid_bytes = bytes[pub_key_alg_oid.slice.start..pub_key_alg_oid.slice.end];
    const pub_key_algo: algorithm.PubKeyAlgo = switch (algorithm.fromOid(pub_key_alg_oid_bytes) orelse
        return error.CertificateHasUnrecognizedObjectId) {
        // Neither post-quantum AlgorithmIdentifier carries parameters at
        // all (RFC 9881 §3, RFC 9882 §3), so unlike the EC branch there is
        // nothing to read after the OID.
        .ml_dsa => |set| .{ .ml_dsa = set },
        .slh_dsa => |set| .{ .slh_dsa = set },
        .std_category => |category| switch (category) {
            inline .rsaEncryption, .rsassa_pss, .curveEd25519 => |tag| @unionInit(algorithm.PubKeyAlgo, @tagName(tag), {}),
            .X9_62_id_ecPublicKey => pk: {
                const params_elem = try extensions.parseElement(bytes, pub_key_alg_oid.slice.end);
                break :pk .{ .X9_62_id_ecPublicKey = try Certificate.parseNamedCurve(bytes, params_elem) };
            },
        },
    };
    const pub_key_elem = try extensions.parseElement(bytes, pub_key_alg_seq.slice.end);
    try expectTag(pub_key_elem, tag_bit_string);
    const pub_key_slice = try parseBitStringSafe(cert, pub_key_elem);

    const sig_algo = try extensions.parseElement(bytes, tbs_certificate.slice.end);
    try expectTag(sig_algo, tag_sequence);
    const algo_oid_elem = try extensions.parseElement(bytes, sig_algo.slice.start);
    if (algo_oid_elem.identifier.tag != .object_identifier) return error.CertificateFieldHasWrongDataType;
    const sig_alg_params: ?[]const u8 = if (algo_oid_elem.slice.end < sig_algo.slice.end) params: {
        const params_elem = try extensions.parseElement(bytes, algo_oid_elem.slice.end);
        break :params bytes[algo_oid_elem.slice.end..params_elem.slice.end];
    } else null;
    const sig_elem = try extensions.parseElement(bytes, sig_algo.slice.end);
    try expectTag(sig_elem, tag_bit_string);
    // tbsCertificate, signatureAlgorithm and signatureValue tile the outer
    // SEQUENCE exactly. `parseElement` bounds each element by the buffer only,
    // so without this a damaged outer length (unsigned) still verified
    // (fuzz driver, 2026-10-10: octet 3 `68` -> `1a`).
    if (sig_elem.slice.end != certificate.slice.end) return error.CertificateFieldHasInvalidLength;
    // RFC 5280 §4.1.1.2: signatureAlgorithm "MUST contain the same algorithm
    // identifier as the signature field in the sequence tbsCertificate". The
    // inner copy is signed, so byte equality pins the outer one (fuzz driver,
    // 2026-10-10: its NULL parameters `05` -> `4b` still verified).
    if (!std.mem.eql(u8, bytes[tbs_certificate.slice.end..sig_algo.slice.end], bytes[serial_number.slice.end..tbs_signature.slice.end]))
        return error.CertificateFieldHasWrongDataType;
    const signature_slice = try parseBitStringSafe(cert, sig_elem);

    if (serial_number.identifier.tag != .integer) return error.CertificateFieldHasWrongDataType;
    return .{
        .serial = bytes[serial_number.slice.start..serial_number.slice.end],
        .issuer = bytes[issuer.slice.start..issuer.slice.end],
        .subject = bytes[subject.slice.start..subject.slice.end],
        .issuer_slice = issuer.slice,
        .subject_slice = subject.slice,
        .not_before = not_before,
        .not_after = not_after,
        .message = bytes[certificate.slice.start..tbs_certificate.slice.end],
        .signature = bytes[signature_slice.start..signature_slice.end],
        .sig_alg_oid = bytes[algo_oid_elem.slice.start..algo_oid_elem.slice.end],
        .sig_alg_params = sig_alg_params,
        .spki = bytes[subject.slice.end..pub_key_info.slice.end],
        .pub_key_algo = pub_key_algo,
        .pub_key_slice = pub_key_slice,
    };
}

/// Builds a `Certificate.Parsed` good enough to pass as the *issuer*
/// argument to `Parsed.verify` — which only ever reads `.subject()` (via
/// `subject_slice`) and `.pubKey()`/`.pub_key_algo` (via `pub_key_slice`)
/// from that argument — without requiring `Certificate.parse()` to succeed
/// on it (it fails outright for a PSS-signed certificate, even though its
/// SubjectPublicKeyInfo, a wholly separate field, parses fine on its own).
/// The other fields are never read through this value and are set to inert
/// placeholders.
fn partialIssuerParsed(cert: Certificate, shape: Shape) error{CertificateSignatureAlgorithmUnsupported}!Certificate.Parsed {
    return .{
        .certificate = cert,
        .issuer_slice = shape.issuer_slice,
        .subject_slice = shape.subject_slice,
        .common_name_slice = der.Element.Slice.empty,
        .signature_slice = der.Element.Slice.empty,
        .signature_algorithm = .sha256WithRSAEncryption,
        // An ML-DSA issuer never reaches here: `verifyLink` routes those to
        // `verifyMlDsaLink` before any std parse is attempted, and this value
        // exists only to be handed to `Certificate.Parsed.verify`.
        .pub_key_algo = shape.pub_key_algo.toStd() orelse return error.CertificateSignatureAlgorithmUnsupported,
        .pub_key_slice = shape.pub_key_slice,
        .message_slice = der.Element.Slice.empty,
        .subject_alt_name_slice = der.Element.Slice.empty,
        .validity = .{ .not_before = 0, .not_after = 0 },
        .version = .v3,
    };
}

// ── small extension lookups shared by the algorithm above ──────────────────

fn findExtensionValue(cert_der: CertDer, id: Certificate.ExtensionId) VerifyChainError!?[]const u8 {
    const cert: Certificate = .{ .buffer = cert_der, .index = 0 };
    const slice = (try extensions.findExtensions(cert)) orelse return null;
    var it = extensions.iterate(slice, cert);
    while (try it.next()) |entry| {
        if (entry.id == id) return entry.value;
    }
    return null;
}

/// `nameConstraints` (2.5.29.30) is not among the OIDs
/// `std.crypto.Certificate.ExtensionId` recognizes, so `entry.id` is always
/// `null` for it — this looks it up by raw OID bytes instead (`entry.oid`
/// is always populated, recognized or not).
const oid_name_constraints = [_]u8{ 0x55, 0x1d, 0x1e };

fn findNameConstraintsExt(cert_der: CertDer) VerifyChainError!?extensions.NameConstraints {
    const cert: Certificate = .{ .buffer = cert_der, .index = 0 };
    const slice = (try extensions.findExtensions(cert)) orelse return null;
    var it = extensions.iterate(slice, cert);
    while (try it.next()) |entry| {
        if (std.mem.eql(u8, entry.oid, &oid_name_constraints)) {
            return try extensions.parseNameConstraints(entry.value);
        }
    }
    return null;
}

fn findBasicConstraints(cert_der: CertDer) VerifyChainError!extensions.BasicConstraints {
    if (try findExtensionValue(cert_der, .basic_constraints)) |v| return try extensions.parseBasicConstraints(v);
    return .{};
}

fn findEku(cert_der: CertDer) VerifyChainError!?[]const u8 {
    return findExtensionValue(cert_der, .ext_key_usage);
}

fn findSan(cert_der: CertDer) VerifyChainError![]const u8 {
    return (try findExtensionValue(cert_der, .subject_alt_name)) orelse &.{};
}

fn findAki(cert_der: CertDer) VerifyChainError!?[]const u8 {
    if (try findExtensionValue(cert_der, .authority_key_identifier)) |v| {
        return (try extensions.parseAuthorityKeyIdentifier(v)).key_identifier;
    }
    return null;
}

fn findSki(cert_der: CertDer) VerifyChainError!?[]const u8 {
    if (try findExtensionValue(cert_der, .subject_key_identifier)) |v| {
        return try extensions.parseSubjectKeyIdentifier(v);
    }
    return null;
}

// ── name constraints (RFC 5280 §6.1.4 (g) / §4.2.1.10) ─────────────────────

/// RFC 5280 §6.1.4 (g) / §4.2.1.10 name-constraint enforcement. `permitted`/
/// `excluded` are the accumulated `GeneralSubtrees` blobs (walk each with
/// `extensions.subtreeIterator`) collected from every CA certificate above
/// this one in the path; `subject_dn` is the raw RDNSequence content of the
/// certificate being checked (always checked against `directoryName`
/// constraints — RFC 5280 §4.2.1.10, verbatim: "Restrictions apply to the
/// subject distinguished name and apply to subject alternative names."; the
/// shorter string quoted here before audit BD-26 was not the RFC's wording)
/// and `subject_san` is its raw `subjectAltName` extnValue (or an
/// empty slice when absent — every entry in it is checked against the
/// constraint of its own `GeneralName` type).
///
/// Per name-type: an EXCLUDED match is an immediate violation regardless of
/// anything else ("excluded wins"). A PERMITTED set is default-deny *only
/// for the types it actually restricts*: if `permitted` contains no
/// `dNSName` entry anywhere, a certificate with no `dNSName`-type permitted
/// constraint applied to it is not restricted at all for that type — the
/// common bug this guards against is treating "empty/absent permitted set"
/// as "nothing permitted" globally rather than per-type.
///
/// Matching rules are `names.match`, one per type: `dNSName`, `rfc822Name`
/// and `uniformResourceIdentifier` by the shared domain rule (an empty
/// constraint matches all, `.example.com` subdomains only, `example.com`
/// itself and its subdomains; an rfc822 constraint with `@` is one mailbox),
/// `directoryName` as an element-wise RDN prefix, `iPAddress` as address ‖
/// mask. A name or constraint a rule cannot read (malformed domain, quoted
/// mailbox, URI without a host or with an IP host) and the four types RFC
/// 5280 gives no rule for (otherName, x400Address, ediPartyName,
/// registeredID) fail CLOSED: an excluded subtree that cannot be evaluated
/// rejects, a permitted one does not admit.
pub const CheckNameConstraintsError = error{NameConstraintViolated} || names.GeneralNameIterator.Error;

pub fn checkNameConstraints(
    permitted: []const []const u8,
    excluded: []const []const u8,
    subject_dn: []const u8,
    subject_san: []const u8,
) CheckNameConstraintsError!void {
    var unlimited: u64 = std.math.maxInt(u64);
    return checkNameConstraintsBudget(permitted, excluded, subject_dn, subject_san, &unlimited) catch |err| switch (err) {
        error.TooManyConstraints => unreachable,
        else => |e| e,
    };
}

/// `checkNameConstraints` charging every (name, constraint) pair it looks at
/// to `budget` (Go's `MaxConstraintComparisions`; `Options.max_constraint_comparisons`).
fn checkNameConstraintsBudget(
    permitted: []const []const u8,
    excluded: []const []const u8,
    subject_dn: []const u8,
    subject_san: []const u8,
    budget: *u64,
) (CheckNameConstraintsError || error{TooManyConstraints})!void {
    try checkOneName(permitted, excluded, .directoryName, subject_dn, budget);
    var it = try names.GeneralNameIterator.init(subject_san);
    while (try it.next()) |gn| try checkOneName(permitted, excluded, gn.tag, gn.value, budget);
}

fn checkOneName(
    permitted: []const []const u8,
    excluded: []const []const u8,
    tag: Certificate.GeneralNameTag,
    value: []const u8,
    budget: *u64,
) (CheckNameConstraintsError || error{TooManyConstraints})!void {
    var it_ex: SubtreeSetIterator = .init(excluded);
    while (try it_ex.next()) |entry| {
        if (entry.tag != tag) continue;
        try charge(budget);
        // Excluded wins; one we cannot evaluate cannot be proven not to
        // contain `value`, so it rejects too (RFC 5280 §6.1.4).
        if (names.match(tag, value, entry.value) != .outside) return error.NameConstraintViolated;
    }

    // Permitted subtrees INTERSECT down the path (RFC 5280 §6.1.4 (g)(1)):
    // every CA's own set that restricts this type must admit the name. Until
    // 2026-10-19 the blobs were walked as one union, so a constrained CA could
    // widen its own constraint by issuing a sub-CA that permits more.
    for (permitted) |blob| {
        var saw_type = false;
        var matched = false;
        var it_perm = extensions.subtreeIterator(blob);
        while (try it_perm.next()) |entry| {
            if (entry.tag != tag) continue;
            try charge(budget);
            saw_type = true;
            if (names.match(tag, value, entry.value) == .inside) matched = true;
        }
        if (saw_type and !matched) return error.NameConstraintViolated;
    }
}

fn charge(budget: *u64) error{TooManyConstraints}!void {
    if (budget.* == 0) return error.TooManyConstraints;
    budget.* -= 1;
}

/// Walks a whole SET of accumulated `GeneralSubtrees` blobs (one per
/// contributing CA) as a single logical sequence of `SubtreeEntry`.
const SubtreeSetIterator = struct {
    blobs: []const []const u8,
    blob_i: usize = 0,
    cur: ?extensions.SubtreeIterator = null,

    fn init(blobs: []const []const u8) SubtreeSetIterator {
        return .{ .blobs = blobs };
    }

    fn next(it: *SubtreeSetIterator) der.Element.ParseError!?extensions.SubtreeEntry {
        while (true) {
            if (it.cur == null) {
                if (it.blob_i >= it.blobs.len) return null;
                it.cur = extensions.subtreeIterator(it.blobs[it.blob_i]);
                it.blob_i += 1;
            }
            if (try it.cur.?.next()) |e| return e;
            it.cur = null;
        }
    }
};

// ── pathLenConstraint (RFC 5280 §6.1.4 (h)/(i)/(l)) ────────────────────────

pub const CheckPathLengthError = error{PathLenConstraintExceeded};

/// RFC 5280 §6.1.4 (h)/(i)/(l) pathLenConstraint bookkeeping.
/// `non_self_issued_ca_count_below` is the number of non-self-issued CA
/// certificates strictly between the leaf and (not including) the
/// certificate that carries `path_len_constraint` — a self-issued
/// certificate (subject == issuer, byte-for-byte — NOT the same test as
/// "is self-signed", which additionally requires the signature to verify
/// against its own key) is exempt from ever incrementing this count
/// (§6.1.4 (l)) — the single most commonly-gotten-wrong part of this whole
/// algorithm: a naive implementation counts every intermediate CA
/// regardless of self-issuance and rejects otherwise-valid rollover
/// chains.
pub fn checkPathLength(path_len_constraint: ?u32, non_self_issued_ca_count_below: u32) CheckPathLengthError!void {
    if (path_len_constraint) |max| {
        if (non_self_issued_ca_count_below > max) return error.PathLenConstraintExceeded;
    }
}

// ── extended key usage (RFC 5280 §4.2.1.12-adjacent) ───────────────────────

pub const CheckExtendedKeyUsageError = error{ExtendedKeyUsageMismatch} || extensions.ParseExtKeyUsageError;

/// EKU consistency/chaining across a path plus the leaf's required-purpose
/// check. `intermediate_ekus` is the raw `extKeyUsage` extnValue (or `null`
/// if the extension is absent — absence means unrestricted, not "no
/// purposes") for every CA certificate in the path from the first
/// intermediate up to and including the trust anchor; `leaf_eku` is the
/// same for the leaf. When `required` is `null` (the protocol doesn't
/// mandate an EKU — e.g. OPC-UA application certificates), this is a no-op:
/// RFC 5280 itself does not require EKU chaining at all, this function only
/// enforces it once the caller has opted in via `Options.required_eku`.
/// `extensions.hasPurpose` already treats `anyExtendedKeyUsage` as
/// satisfying any request.
pub fn checkExtendedKeyUsage(
    intermediate_ekus: []const ?[]const u8,
    leaf_eku: ?[]const u8,
    required: ?extensions.Purpose,
) CheckExtendedKeyUsageError!void {
    const want = required orelse return;

    if (leaf_eku) |v| {
        if (!try extensions.hasPurpose(v, want)) return error.ExtendedKeyUsageMismatch;
    }
    for (intermediate_ekus) |maybe_eku| {
        const v = maybe_eku orelse continue;
        if (!try extensions.hasPurpose(v, want)) return error.ExtendedKeyUsageMismatch;
    }
}

pub const PurposeSet = std.EnumSet(extensions.Purpose);

/// `Options.usages_any_of` (Go `KeyUsages` semantics, see there): `wanted`
/// narrowed by every certificate's `extKeyUsage` on the path, leaf and
/// `intermediate_ekus` (first intermediate up to and including the anchor,
/// `null` = extension absent = unrestricted). A wanted set holding
/// `.any_extended_key_usage` accepts without looking; a certificate listing
/// `anyExtendedKeyUsage` keeps the set as it is. Unknown purpose OIDs on a
/// certificate permit nothing this set can name.
pub fn checkExtendedKeyUsageAnyOf(
    intermediate_ekus: []const ?[]const u8,
    leaf_eku: ?[]const u8,
    wanted: PurposeSet,
) CheckExtendedKeyUsageError!void {
    if (wanted.contains(.any_extended_key_usage)) return;
    var left = wanted;
    if (leaf_eku) |v| left = try narrowByEku(left, v);
    for (intermediate_ekus) |maybe_eku| {
        if (maybe_eku) |v| left = try narrowByEku(left, v);
    }
    if (left.count() == 0) return error.ExtendedKeyUsageMismatch;
}

fn narrowByEku(set: PurposeSet, eku_value: []const u8) extensions.ParseExtKeyUsageError!PurposeSet {
    var listed: PurposeSet = .empty;
    var it = try extensions.parseExtKeyUsage(eku_value);
    while (try it.next()) |entry| {
        const p = entry.known orelse continue;
        if (p == .any_extended_key_usage) return set;
        listed.insert(p);
    }
    return set.intersectWith(listed);
}

// ── RSASSA-PSS certificate-link signature verification (RFC 4055) ─────────

const oid_sha1 = [_]u8{ 0x2b, 0x0e, 0x03, 0x02, 0x1a };
const oid_sha224 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04 };
const oid_sha256 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
const oid_sha384 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
const oid_sha512 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
const oid_mgf1 = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08 };

const PssHashAlg = enum { sha1, sha224, sha256, sha384, sha512 };

fn hashAlgFromOid(oid: []const u8) ?PssHashAlg {
    if (std.mem.eql(u8, oid, &oid_sha1)) return .sha1;
    if (std.mem.eql(u8, oid, &oid_sha224)) return .sha224;
    if (std.mem.eql(u8, oid, &oid_sha256)) return .sha256;
    if (std.mem.eql(u8, oid, &oid_sha384)) return .sha384;
    if (std.mem.eql(u8, oid, &oid_sha512)) return .sha512;
    return null;
}

const PssParams = struct {
    /// RFC 4055 §3.1 DEFAULT: sha1, when `hashAlgorithm [0]` is omitted.
    hash: PssHashAlg = .sha1,
    /// RFC 4055 §3.1 DEFAULT: 20 (SHA-1's digest length), when
    /// `saltLength [2]` is omitted. This module does not implement
    /// salt-length auto-detection (`rsa.verifyPss` requires an exact
    /// value) — a certificate must state (or, via this default, imply) the
    /// salt length its signer actually used.
    salt_len: usize = 20,
};

pub const ParsePssParamsError = Certificate.ParseError || error{UnsupportedPssParams};

/// Parses `RSASSA-PSS-params` (RFC 4055 §3.1): `SEQUENCE { hashAlgorithm
/// [0] EXPLICIT HashAlgorithm DEFAULT sha1Identifier, maskGenAlgorithm [1]
/// EXPLICIT MaskGenAlgorithm DEFAULT mgf1SHA1Identifier, saltLength [2]
/// EXPLICIT INTEGER DEFAULT 20, trailerField [3] EXPLICIT INTEGER DEFAULT 1
/// }`. `params` is the outer signatureAlgorithm's `parameters` field (full
/// TLV) as extracted by `parseShape`, or `null` when the AlgorithmIdentifier
/// omitted it entirely (a valid, if unusual, encoding meaning ALL fields
/// take their RFC 4055 defaults).
///
/// **Every field is independently OPTIONAL with its own DEFAULT — this is
/// exactly the part that is easy to get wrong.** A missing field means "use
/// the default", not "the certificate doesn't specify a hash/salt length
/// and this check should be skipped" — silently treating an omitted field
/// as "nothing to check" would let a signer that specifies (say) only
/// `saltLength` skip the hash check entirely, when RFC 4055 says the hash
/// is `sha1Identifier` in that case. This function always returns a fully
/// resolved `PssParams`, explicit or defaulted, never a partial one.
///
/// This collection's `rsa.verifyPss` takes one `Hash` type used for both
/// the digest and the MGF1 inner hash (the conventional/near-universal
/// profile); a certificate specifying `maskGenAlgorithm`'s inner hash
/// different from `hashAlgorithm`, a non-MGF1 mask generation function, or
/// `trailerField != 1` is rejected with `error.UnsupportedPssParams` rather
/// than silently misverified.
pub fn parsePssParams(params: ?[]const u8) ParsePssParamsError!PssParams {
    var result: PssParams = .{};
    const bytes = params orelse return result;

    const seq = try extensions.parseElement(bytes, 0);
    if (seq.identifier.tag != .sequence) return error.CertificateFieldHasWrongDataType;

    var pos = seq.slice.start;
    while (pos < seq.slice.end) {
        const tagged = try extensions.parseElement(bytes, pos);
        pos = tagged.slice.end;
        switch (@as(u8, @bitCast(tagged.identifier))) {
            0xa0 => { // [0] EXPLICIT hashAlgorithm AlgorithmIdentifier
                const alg_seq = try extensions.parseElement(bytes, tagged.slice.start);
                const oid_elem = try extensions.parseElement(bytes, alg_seq.slice.start);
                const oid = bytes[oid_elem.slice.start..oid_elem.slice.end];
                result.hash = hashAlgFromOid(oid) orelse return error.UnsupportedPssParams;
            },
            0xa1 => { // [1] EXPLICIT maskGenAlgorithm AlgorithmIdentifier (must be MGF1)
                const alg_seq = try extensions.parseElement(bytes, tagged.slice.start);
                const oid_elem = try extensions.parseElement(bytes, alg_seq.slice.start);
                const oid = bytes[oid_elem.slice.start..oid_elem.slice.end];
                if (!std.mem.eql(u8, oid, &oid_mgf1)) return error.UnsupportedPssParams;
                const mgf_params_elem = try extensions.parseElement(bytes, oid_elem.slice.end);
                const inner_oid_elem = try extensions.parseElement(bytes, mgf_params_elem.slice.start);
                const inner_oid = bytes[inner_oid_elem.slice.start..inner_oid_elem.slice.end];
                const mgf_hash = hashAlgFromOid(inner_oid) orelse return error.UnsupportedPssParams;
                // Deferred to after the whole SEQUENCE is parsed: DER field
                // order guarantees [0] (if present) was already seen.
                if (mgf_hash != result.hash) return error.UnsupportedPssParams;
            },
            0xa2 => { // [2] EXPLICIT saltLength INTEGER
                const int_elem = try extensions.parseElement(bytes, tagged.slice.start);
                result.salt_len = try parseUintContent(bytes, int_elem);
            },
            0xa3 => { // [3] EXPLICIT trailerField INTEGER, MUST be 1 (trailerFieldBC)
                const int_elem = try extensions.parseElement(bytes, tagged.slice.start);
                if ((try parseUintContent(bytes, int_elem)) != 1) return error.UnsupportedPssParams;
            },
            else => {},
        }
    }
    return result;
}

fn parseUintContent(bytes: []const u8, elem: der.Element) ParsePssParamsError!usize {
    if (elem.identifier.tag != .integer) return error.CertificateFieldHasWrongDataType;
    const content = bytes[elem.slice.start..elem.slice.end];
    if (content.len == 0 or content.len > 8) return error.UnsupportedPssParams;
    var acc: usize = 0;
    for (content) |b| acc = (acc << 8) | b;
    return acc;
}

/// RSA-PSS certificate-link signature verification. `std.crypto.Certificate`
/// cannot even PARSE a certificate signed with RSASSA-PSS (RFC 4055 §3.1,
/// OID 1.2.840.113549.1.1.10) — `Certificate.Algorithm.map` (the outer
/// `signatureAlgorithm` enum std recognizes) has no entry for it, only
/// `AlgorithmCategory.rsassa_pss`, which governs the UNRELATED
/// SubjectPublicKeyInfo algorithm identifier — so this walks `subject_der`
/// independently via `parseShape` (this file's shared raw-DER structural
/// walk) to recover the signed message and raw signature bytes, parses the
/// PSS parameters (`parsePssParams`, applying RFC 4055's DEFAULTs exactly
/// where a field is omitted), and calls this repo's `rsa.verifyPss`
/// (already implemented and KAT-tested against OpenSSL).
pub fn verifyPssLink(subject_der: CertDer, issuer_pub_key: rsa.PublicKey, now_sec: i64) VerifyChainError!void {
    const shape = try parseShape(.{ .buffer = subject_der, .index = 0 });

    // Real certificate dates are always well within i64 range; `@intCast`
    // here is a safety-checked assertion of that, not a silent truncation.
    if (now_sec < @as(i64, @intCast(shape.not_before))) return error.CertificateNotYetValid;
    if (now_sec > @as(i64, @intCast(shape.not_after))) return error.CertificateExpired;

    const params = try parsePssParams(shape.sig_alg_params);
    switch (params.hash) {
        inline else => |h| {
            const Hash = switch (h) {
                .sha1 => std.crypto.hash.Sha1,
                .sha224 => std.crypto.hash.sha2.Sha224,
                .sha256 => std.crypto.hash.sha2.Sha256,
                .sha384 => std.crypto.hash.sha2.Sha384,
                .sha512 => std.crypto.hash.sha2.Sha512,
            };
            rsa.verifyPss(issuer_pub_key, Hash, shape.message, shape.signature, params.salt_len) catch return error.CertificateSignatureInvalid;
        },
    }
}

// ── fuzz: parsePssParams, this file's own bounded RFC 4055 walk ────────────
//
// `parsePssParams` walks `params` (the certificate's signatureAlgorithm
// `parameters` field — attacker-controlled DER) entirely through
// `extensions.parseElement`, the same bounds-safe wrapper `extensions.zig`
// fuzzes directly; no call to `std.crypto.Certificate.parse` sits in front
// of it.
//
// `parseShape` (the other raw-DER walk in this file) is private, but it is
// NOT hard to reach: `verifyMlDsaLink`, `verifySlhDsaLink` and `verifyPssLink`
// are all public and all call it as their first statement, before any key
// material is looked at, and `verifyChain` runs it over every entry of the
// peer-supplied chain before a single signature is checked. An earlier version
// of this comment claimed it was "not independently reachable without a live
// `rsa.PublicKey`/hash comparison" and used that to justify leaving it
// unfuzzed — the post-quantum additions made the claim false, and the two
// zero-length BIT STRING regressions in `chain_test.zig` are what it missed.
// It is still exercised mainly through the higher-level chain tests.
const testing = std.testing;

// ⚠ This harness used to open with
//
//     smith.bytes(&buf);
//     const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
//
// which reads the input and throws it away: `bytes` consumes
// `@min(buf.len, in.len)` octets and the ranged draw then finds fewer than the
// eight it reads as a little-endian u64, so `len` was 0 on every input. With
// no corpus the lane ran exactly one round: `parsePssParams("")`, refused at
// the first tag. Not one `RSASSA-PSS-params` structure had ever gone through
// it, which for a four-field all-OPTIONAL-with-DEFAULTS grammar is the whole
// point of the function.
const testkit = @import("testkit");

/// RFC 4055 §3.1 `RSASSA-PSS-params`, the encodings this module's own tests
/// build. Arbitrary bytes reach none of these: every field is a context tag
/// wrapping a nested AlgorithmIdentifier whose OID has to match.
const pss_seeds = [_][]const u8{
    // All fields omitted: the defaults (sha1, MGF1-sha1, salt 20).
    testkit.fuzz.seedHex("3000"),
    // openssl's own sha256 / MGF1-sha256 / saltLength 32 encoding.
    testkit.fuzz.seedHex(
        "3030a00d300b0609608648016503040201" ++
            "a11a301806092a864886f70d010108300b0609608648016503040201" ++
            "a203020120",
    ),
    // sha384 / MGF1-sha384, saltLength left to its default of 20.
    testkit.fuzz.seedHex(
        "302ba00d300b0609608648016503040202" ++
            "a11a301806092a864886f70d010108300b0609608648016503040202",
    ),
    // saltLength alone: every other field defaults.
    testkit.fuzz.seedHex("3005a203020140"),
    // hashAlgorithm sha256 with an MGF1 inner hash of sha1 — the mismatch this
    // module documents as `error.UnsupportedPssParams` rather than verifying.
    testkit.fuzz.seedHex(
        "3027a00d300b0609608648016503040201" ++
            "a116301406092a864886f70d010108300706052b0e03021a",
    ),
    // trailerField = 2, which RFC 4055 does not define.
    testkit.fuzz.seedHex("3005a303020102"),
    // The outer SEQUENCE claims one octet more than it has.
    testkit.fuzz.seedHex("3006a203020120"),
    // An ASN.1 NULL where a SEQUENCE belongs — the shape a certificate that
    // says PSS but carries RSA-PKCS#1 parameters presents.
    testkit.fuzz.seedHex("0500"),
    // The one input this target actually ran, for ever.
    testkit.fuzz.seed(""),
};

const fz = @import("fuzz_test.zig");
const PssMark = fz.Marker(enum { accepted, refused, explicit_salt });

test "fuzz: parsePssParams never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzPssParamsSmith, .{ .corpus = &pss_seeds });
}

test "fuzz driver: X509_FUZZ (parsePssParams)" {
    try fz.fuzz_driver.run(fuzzPssParams, .{ .prefix = "X509_FUZZ", .name = "x509-pss" });
}

test "fuzz harness: parsePssParams, 500 seeds, reaches every outcome" {
    try PssMark.reach(fuzzPssParams, "x509-pss", 500);
}

fn fuzzPssParamsSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzPssParams(std.testing.Smith, smith, testing.allocator);
}

fn fuzzPssParams(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    // 256 against a 60-octet longest real encoding.
    var buf: [256]u8 = undefined;
    // ⚠ One `slice` (under `Smith`), never `bytes` followed by a ranged length.
    const len: usize = fz.drawInput(S, src, &buf, &pss_seeds);
    if (parsePssParams(buf[0..len])) |p| {
        PssMark.mark(.accepted);
        if (p.salt_len != 20) PssMark.mark(.explicit_salt);
    } else |_| PssMark.mark(.refused);
}

test "corpus: the parsePssParams seeds reach the parser, counts pinned" {
    // The second number is how many DISTINCT salt lengths came back. Every
    // field of this structure has a DEFAULT, so a parse that walked nothing
    // still returns `salt_len = 20` — an accepted count cannot tell a seed
    // that carried an explicit `saltLength` from one that carried nothing.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var salts: [8]usize = undefined;
    var n_salts: usize = 0;
    for (pss_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const p = parsePssParams(buf[0..len]) catch continue;
        accepted += 1;
        for (salts[0..n_salts]) |s| {
            if (s == p.salt_len) break;
        } else {
            salts[n_salts] = p.salt_len;
            n_salts += 1;
        }
    }
    try testing.expectEqual(pss_seeds.len - 1, nonempty); // all but seed("")
    try testing.expectEqual(@as(usize, 4), accepted);
    try testing.expectEqual(@as(usize, 3), n_salts);
}

// ── signature-check budget (audit 2026-10-19) ───────────────────────────────

const Ed25519 = std.crypto.sign.Ed25519;

/// DER length octets for `n < 256`.
fn budgetDerLen(w: *std.Io.Writer, n: usize) !void {
    if (n < 0x80) return w.writeByte(@intCast(n));
    try w.writeAll(&.{ 0x81, @intCast(n) });
}

/// A minimal v3 Ed25519 certificate: CN `subject` with key `subject_pk`,
/// issued and signed by CN `issuer` / `signer`; `ca` adds a critical
/// basicConstraints cA=TRUE. Valid 2020-01-01 .. 2049-12-31.
fn budgetCert(buf: []u8, serial: u8, subject: u8, issuer: u8, ca: bool, subject_pk: [32]u8, signer: Ed25519.KeyPair) ![]const u8 {
    const alg = [_]u8{ 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70 };
    const validity = [_]u8{ 0x30, 0x1e, 0x17, 0x0d } ++ "200101000000Z".* ++ [_]u8{ 0x17, 0x0d } ++ "491231235959Z".*;
    const bc_ext = [_]u8{ 0xa3, 0x13, 0x30, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff };
    var body_buf: [200]u8 = undefined;
    var b: std.Io.Writer = .fixed(&body_buf);
    try b.writeAll(&.{ 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, serial });
    try b.writeAll(&alg);
    try b.writeAll(&.{ 0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x01, issuer });
    try b.writeAll(&validity);
    try b.writeAll(&.{ 0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x01, subject });
    try b.writeAll(&([_]u8{ 0x30, 0x2a } ++ alg ++ [_]u8{ 0x03, 0x21, 0x00 }));
    try b.writeAll(&subject_pk);
    if (ca) try b.writeAll(&bc_ext);
    var tbs_buf: [208]u8 = undefined;
    var t: std.Io.Writer = .fixed(&tbs_buf);
    try t.writeByte(0x30);
    try budgetDerLen(&t, b.buffered().len);
    try t.writeAll(b.buffered());
    const sig = try signer.sign(t.buffered(), null);
    var w: std.Io.Writer = .fixed(buf);
    try w.writeByte(0x30);
    try budgetDerLen(&w, t.buffered().len + alg.len + 3 + 64);
    try w.writeAll(t.buffered());
    try w.writeAll(&alg);
    try w.writeAll(&.{ 0x03, 0x41, 0x00 });
    try w.writeAll(&sig.toBytes());
    return w.buffered();
}

test "buildPath: same-DN, same-key intermediates are refused after a bounded number of signature checks (Go maxChainSignatureChecks)" {
    // A peer-made chain: leaf "L" issued by "X", six CAs all subject = issuer
    // = "X" under one key, no AKI/SKI. Every link verifies, so the search
    // backtracked over every ordering: 6 + 30 + 120 + 360 + 720 + 720 = 1956
    // signature checks for one call (leaf + 8 such CAs: ~10^5). Negative
    // control (budget check removed): `checks` is 1956 and the test fails.
    const k = try Ed25519.KeyPair.generateDeterministic(@splat(1));
    const kr = try Ed25519.KeyPair.generateDeterministic(@splat(2));
    var bufs: [8][256]u8 = undefined;
    var chain: [7]CertDer = undefined;
    chain[0] = try budgetCert(&bufs[0], 1, 'L', 'X', false, k.public_key.toBytes(), k);
    for (1..7) |i| chain[i] = try budgetCert(&bufs[i], @intCast(i + 1), 'X', 'X', true, k.public_key.toBytes(), k);
    const root = try budgetCert(&bufs[7], 9, 'R', 'R', true, kr.public_key.toBytes(), kr);
    const opts: Options = .{ .now_sec = 1_800_000_000 };

    var checks: u32 = 0;
    const r = buildPathCounted(std.testing.allocator, &chain, &.{root}, opts, &checks);
    if (r) |p| {
        std.testing.allocator.free(p);
        return error.TestUnexpectedResult;
    } else |e| try std.testing.expect(e == error.ChainTooLong or e == error.NoTrustedPath);
    try std.testing.expect(checks <= max_signature_checks);
    try std.testing.expect(checks > 6); // the search did run
    if (verifyChain(std.testing.allocator, &chain, &.{root}, opts)) |_| return error.TestUnexpectedResult else |_| {}
}

test "buildPath: a chain that needs backtracking past a failing same-DN candidate still verifies within the budget" {
    // "X" twice in the chain: the first under a key that did not sign the
    // leaf (its link fails), the second the real issuer; both issued by root
    // "R". One rejected candidate, then leaf -> X -> R.
    const k = try Ed25519.KeyPair.generateDeterministic(@splat(1));
    const k_other = try Ed25519.KeyPair.generateDeterministic(@splat(3));
    const kr = try Ed25519.KeyPair.generateDeterministic(@splat(2));
    var bufs: [4][256]u8 = undefined;
    const leaf = try budgetCert(&bufs[0], 1, 'L', 'X', false, k.public_key.toBytes(), k);
    const x_bad = try budgetCert(&bufs[1], 2, 'X', 'R', true, k_other.public_key.toBytes(), kr);
    const x_good = try budgetCert(&bufs[2], 3, 'X', 'R', true, k.public_key.toBytes(), kr);
    const root = try budgetCert(&bufs[3], 4, 'R', 'R', true, kr.public_key.toBytes(), kr);
    const chain = [_]CertDer{ leaf, x_bad, x_good };
    const opts: Options = .{ .now_sec = 1_800_000_000 };

    var checks: u32 = 0;
    const path = try buildPathCounted(std.testing.allocator, &chain, &.{root}, opts, &checks);
    defer std.testing.allocator.free(path);
    try std.testing.expectEqual(@as(usize, 3), path.len);
    try std.testing.expectEqual(x_good.ptr, path[1].der.ptr);
    try std.testing.expectEqual(@as(u32, 3), checks); // x_bad, x_good, root
    const v = try verifyChain(std.testing.allocator, &chain, &.{root}, opts);
    try std.testing.expectEqual(@as(usize, 0), v.trust_anchor_index);
}

test {
    _ = @import("chain_test.zig");
    _ = @import("fuzz_test.zig");
}
