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
//! **Out of scope, by design, not silently skipped:** CRL/OCSP revocation
//! checking (RFC 5280 §6.3 — a separate online/offline data-fetching
//! concern) and certificate policy processing (§6.1.5's explicit-policy /
//! policy-mapping state machine — most TLS/mTLS/OPC-UA deployments don't
//! rely on policy OIDs). A consumer needing either must add it explicitly.
//! `rfc822Name`/`uniformResourceIdentifier`/other `GeneralName` types are
//! recognized by `checkNameConstraints` but have no matching rule implemented
//! (only `dNSName`, `directoryName`, `iPAddress` per RFC 5280 §4.2.1.10) — a
//! constraint of one of those types is parsed but never matched, which is a
//! fail-*open* gap for that specific name type; flagged here and in SPEC.md.

const std = @import("std");
const Certificate = std.crypto.Certificate;
const der = Certificate.der;
const extensions = @import("extensions.zig");
const algorithm = @import("algorithm.zig");
const rsa = @import("rsa");

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
    /// When set, the leaf certificate's subject/SAN must match this hostname
    /// (delegates to `std.crypto.Certificate.Parsed.verifyHostName`, already
    /// implemented and RFC 6125-tested by std — not reimplemented here).
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
} ||
    std.mem.Allocator.Error ||
    Certificate.ParseError ||
    Certificate.Parsed.VerifyError ||
    Certificate.Parsed.VerifyHostNameError ||
    extensions.FindExtensionsError ||
    extensions.ParseBasicConstraintsError ||
    extensions.ParseKeyUsageError ||
    extensions.ParseExtKeyUsageError ||
    extensions.ParseNameConstraintsError ||
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
/// `checkNameConstraints`/`checkExtendedKeyUsage` anchor-to-leaf
/// (accumulated name constraints and EKU chaining). Finally `expected_host`,
/// if set, is checked via `Parsed.verifyHostName`, and the leaf is parsed via
/// `std.crypto.Certificate.parse` for `VerifiedChain.leaf`.
///
/// A leaf whose algorithm std cannot name (RSASSA-PSS, ML-DSA, SLH-DSA) no longer
/// fails the whole call the way it did before `algorithm.zig` existed: it is
/// verified like any other, `VerifiedChain.leaf` is `null`, and the hostname
/// check runs against `hostNameView` — this module's own walk of the two name
/// fields `verifyHostName` reads — so it is neither skipped nor weakened.
pub fn verifyChain(
    gpa: std.mem.Allocator,
    chain: []const CertDer,
    trust_anchors: []const CertDer,
    opts: Options,
) VerifyChainError!VerifiedChain {
    if (chain.len == 0) return error.EmptyChain;

    const path = try buildPath(gpa, chain, trust_anchors, opts);
    defer gpa.free(path);

    // RFC 5280 §6.1.4 (h)/(i)/(l): pathLenConstraint, leaf-to-anchor order,
    // with the self-issued-certificate exception. `path[1..]` is every CA
    // certificate in the path (everything except the leaf at path[0]).
    var non_self_issued_below: u32 = 0;
    for (path[1..]) |entry| {
        const bc = try findBasicConstraints(entry.der);
        try checkPathLength(bc.path_len_constraint, non_self_issued_below);
        const shape = try parseShape(.{ .buffer = entry.der, .index = 0 });
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

        var i: usize = path.len;
        while (i > 0) {
            i -= 1;
            const entry = path[i];
            const shape = try parseShape(.{ .buffer = entry.der, .index = 0 });
            const san = try findSan(entry.der);
            try checkNameConstraints(permitted.items, excluded.items, shape.subject, san);
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

    // RFC 5280 §4.2.1.12-adjacent EKU chaining, plus the leaf's own
    // required-purpose check.
    {
        const eku_list = try gpa.alloc(?[]const u8, path.len - 1);
        defer gpa.free(eku_list);
        for (path[1..], 0..) |entry, idx| eku_list[idx] = try findEku(entry.der);
        const leaf_eku = try findEku(path[0].der);
        try checkExtendedKeyUsage(eku_list, leaf_eku, opts.required_eku);
    }

    const leaf_cert: Certificate = .{ .buffer = path[0].der, .index = 0 };
    const leaf_shape = try parseShape(leaf_cert);
    // std can parse most leaves; for the ones it cannot name at all, the
    // hostname check runs against a `Parsed` synthesized from this module's
    // own walk. `verifyHostName` reads only the two name fields, and
    // `synthesizeParsed` fills both from the certificate — so the check is
    // the same check, not a weakened one.
    const leaf_parsed: ?Certificate.Parsed = leaf_cert.parse() catch |err| switch (err) {
        error.CertificateHasUnrecognizedObjectId => null,
        else => |e| return e,
    };
    if (opts.expected_host) |host| {
        const for_host = leaf_parsed orelse try hostNameView(leaf_cert, leaf_shape);
        try for_host.verifyHostName(host);
    }

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
    if (chain.len == 0) return error.EmptyChain;

    var path: std.ArrayList(PathEntry) = .empty;
    errdefer path.deinit(gpa);

    const used_chain = try gpa.alloc(bool, chain.len);
    defer gpa.free(used_chain);
    @memset(used_chain, false);
    used_chain[0] = true; // the leaf itself is never its own issuer candidate

    try path.append(gpa, .{ .der = chain[0], .anchor_index = null });
    const leaf_shape = try parseShape(.{ .buffer = chain[0], .index = 0 });
    try findIssuerAndVerify(gpa, chain, trust_anchors, opts, chain[0], leaf_shape, used_chain, 0, &path);

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
) VerifyChainError!void {
    var candidates: std.ArrayList(Candidate) = .empty;
    defer candidates.deinit(gpa);

    const cur_aki: ?[]const u8 = findAki(cur_der) catch null;

    for (chain, 0..) |c_der, i| {
        if (used_chain[i]) continue;
        const shape = parseShape(.{ .buffer = c_der, .index = 0 }) catch continue;
        if (!std.mem.eql(u8, shape.subject, cur_shape.issuer)) continue;
        if (cur_aki) |aki| {
            if (findSki(c_der) catch null) |ski| {
                if (!std.mem.eql(u8, aki, ski)) continue;
            }
        }
        try candidates.append(gpa, .{ .der = c_der, .is_anchor = false, .anchor_index = 0, .chain_index = i });
    }
    for (trust_anchors, 0..) |a_der, i| {
        const shape = parseShape(.{ .buffer = a_der, .index = 0 }) catch continue;
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
        return acceptCandidate(gpa, chain, trust_anchors, opts, cur_der, candidates.items[0], used_chain, depth, path);
    }

    for (candidates.items) |cand| {
        if (acceptCandidate(gpa, chain, trust_anchors, opts, cur_der, cand, used_chain, depth, path)) {
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
) VerifyChainError!void {
    try verifyLink(cur_der, cand.der, opts.now_sec);
    try checkIsCaSigner(cand.der);

    if (cand.chain_index) |ci| used_chain[ci] = true;
    errdefer if (cand.chain_index) |ci| {
        used_chain[ci] = false;
    };

    try path.append(gpa, .{ .der = cand.der, .anchor_index = if (cand.is_anchor) cand.anchor_index else null });
    errdefer _ = path.pop();

    if (cand.is_anchor) return;

    const next_depth = depth + 1;
    if (next_depth > opts.max_intermediates) return error.ChainTooLong;

    const next_shape = try parseShape(.{ .buffer = cand.der, .index = 0 });
    try findIssuerAndVerify(gpa, chain, trust_anchors, opts, cand.der, next_shape, used_chain, next_depth, path);
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
/// everything std supports (RSA PKCS1v15, ECDSA P-256/P-384, Ed25519)
/// routes to `std.crypto.Certificate.Parsed.verify`. For that std path, the
/// issuer only needs to supply its public key and subject DN — fields that
/// parse independently of whether the issuer's OWN signature is PSS — so a
/// PSS-signed issuer whose `Certificate.parse()` fails outright is handled
/// via `partialIssuerParsed` rather than giving up (this matters: in a
/// chain where an intermediate is PSS-signed by the root but itself signs
/// the leaf with a std-supported algorithm, the leaf link needs exactly
/// this fallback).
fn verifyLink(subject_der: CertDer, issuer_der: CertDer, now_sec: i64) VerifyChainError!void {
    const subject_shape = try parseShape(.{ .buffer = subject_der, .index = 0 });

    if (algorithm.MlDsa.map.get(subject_shape.sig_alg_oid) != null) {
        return verifyMlDsaLink(subject_der, issuer_der, now_sec);
    }

    if (algorithm.SlhDsa.map.get(subject_shape.sig_alg_oid) != null) {
        return verifySlhDsaLink(subject_der, issuer_der, now_sec);
    }

    if (Certificate.AlgorithmCategory.map.get(subject_shape.sig_alg_oid) == .rsassa_pss) {
        const issuer_shape = try parseShape(.{ .buffer = issuer_der, .index = 0 });
        const issuer_pub_key = try rsa.PublicKey.fromDer(issuer_shape.spki);
        return verifyPssLink(subject_der, issuer_pub_key, now_sec);
    }

    const subject_cert: Certificate = .{ .buffer = subject_der, .index = 0 };
    const subject_parsed = try subject_cert.parse();

    const issuer_cert: Certificate = .{ .buffer = issuer_der, .index = 0 };
    const issuer_parsed = issuer_cert.parse() catch |err| switch (err) {
        error.CertificateHasUnrecognizedObjectId => try partialIssuerParsed(issuer_cert, try parseShape(issuer_cert)),
        else => |e| return e,
    };

    try subject_parsed.verify(issuer_parsed, now_sec);
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

fn parseShape(cert: Certificate) Certificate.ParseError!Shape {
    const bytes = cert.buffer;
    const certificate = try extensions.parseElement(bytes, cert.index);
    const tbs_certificate = try extensions.parseElement(bytes, certificate.slice.start);
    const version_elem = try extensions.parseElement(bytes, tbs_certificate.slice.start);
    _ = try Certificate.parseVersion(bytes, version_elem);
    const serial_number = if (@as(u8, @bitCast(version_elem.identifier)) == 0xa0)
        try extensions.parseElement(bytes, version_elem.slice.end)
    else
        version_elem;
    const tbs_signature = try extensions.parseElement(bytes, serial_number.slice.end);
    const issuer = try extensions.parseElement(bytes, tbs_signature.slice.end);
    const validity = try extensions.parseElement(bytes, issuer.slice.end);
    const not_before_elem = try extensions.parseElement(bytes, validity.slice.start);
    const not_before = try Certificate.parseTime(cert, not_before_elem);
    const not_after_elem = try extensions.parseElement(bytes, not_before_elem.slice.end);
    const not_after = try Certificate.parseTime(cert, not_after_elem);
    const subject = try extensions.parseElement(bytes, validity.slice.end);
    const pub_key_info = try extensions.parseElement(bytes, subject.slice.end);

    const pub_key_alg_seq = try extensions.parseElement(bytes, pub_key_info.slice.start);
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
    const pub_key_slice = try Certificate.parseBitString(cert, pub_key_elem);

    const sig_algo = try extensions.parseElement(bytes, tbs_certificate.slice.end);
    const algo_oid_elem = try extensions.parseElement(bytes, sig_algo.slice.start);
    if (algo_oid_elem.identifier.tag != .object_identifier) return error.CertificateFieldHasWrongDataType;
    const sig_alg_params: ?[]const u8 = if (algo_oid_elem.slice.end < sig_algo.slice.end) params: {
        const params_elem = try extensions.parseElement(bytes, algo_oid_elem.slice.end);
        break :params bytes[algo_oid_elem.slice.end..params_elem.slice.end];
    } else null;
    const sig_elem = try extensions.parseElement(bytes, sig_algo.slice.end);
    const signature_slice = try Certificate.parseBitString(cert, sig_elem);

    return .{
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

/// A `Certificate.Parsed` carrying ONLY what `Parsed.verifyHostName` reads:
/// the certificate buffer, the subject DN, the commonName attribute inside
/// it, and the raw `subjectAltName` extnValue. For a leaf whose algorithm
/// `Certificate.parse` refuses to name (RSASSA-PSS, ML-DSA), this is how the
/// hostname check still runs against the real fields instead of being
/// skipped — skipping it would be a fail-open hole exactly where a
/// post-quantum deployment would first notice it.
///
/// Every other field is an inert placeholder, so this value must never be
/// handed to `Parsed.verify` (`partialIssuerParsed` exists for that, and
/// refuses rather than placeholder an algorithm it cannot name). It does not
/// escape this file.
fn hostNameView(cert: Certificate, shape: Shape) VerifyChainError!Certificate.Parsed {
    return .{
        .certificate = cert,
        .issuer_slice = shape.issuer_slice,
        .subject_slice = shape.subject_slice,
        .common_name_slice = try findCommonNameSlice(cert, shape.subject_slice),
        .subject_alt_name_slice = try findSanSlice(cert),
        .signature_slice = der.Element.Slice.empty,
        .signature_algorithm = .sha256WithRSAEncryption,
        .pub_key_algo = .rsaEncryption,
        .pub_key_slice = shape.pub_key_slice,
        .message_slice = der.Element.Slice.empty,
        .validity = .{ .not_before = shape.not_before, .not_after = shape.not_after },
        .version = .v3,
    };
}

/// The `commonName` AttributeTypeAndValue inside an already-located subject
/// `RDNSequence`, as offsets into the certificate. Mirrors the walk
/// `std.crypto.Certificate.parse` performs over the same bytes (RDNSequence
/// -> RelativeDistinguishedName SET -> AttributeTypeAndValue SEQUENCE), and
/// like std keeps the LAST commonName when a DN carries several. An empty
/// slice when there is none — `verifyHostName` then has nothing to fall back
/// on and rejects, which is the fail-closed direction.
fn findCommonNameSlice(cert: Certificate, subject_slice: der.Element.Slice) VerifyChainError!der.Element.Slice {
    const bytes = cert.buffer;
    var common_name = der.Element.Slice.empty;
    var name_i = subject_slice.start;
    while (name_i < subject_slice.end) {
        const rdn = try extensions.parseElement(bytes, name_i);
        name_i = rdn.slice.end;
        var rdn_i = rdn.slice.start;
        while (rdn_i < rdn.slice.end) {
            const atav = try extensions.parseElement(bytes, rdn_i);
            rdn_i = atav.slice.end;
            var atav_i = atav.slice.start;
            while (atav_i < atav.slice.end) {
                const ty_elem = try extensions.parseElement(bytes, atav_i);
                const val = try extensions.parseElement(bytes, ty_elem.slice.end);
                atav_i = val.slice.end;
                const ty = Certificate.parseAttribute(bytes, ty_elem) catch |err| switch (err) {
                    error.CertificateHasUnrecognizedObjectId => continue,
                    else => |e| return e,
                };
                if (ty == .commonName) common_name = val.slice;
            }
        }
    }
    return common_name;
}

/// `findSan`'s answer as offsets rather than bytes — `Certificate.Parsed`
/// stores slices into the certificate, not pointers.
fn findSanSlice(cert: Certificate) VerifyChainError!der.Element.Slice {
    const slice = (try extensions.findExtensions(cert)) orelse return der.Element.Slice.empty;
    var it = extensions.iterate(slice, cert);
    while (try it.next()) |entry| {
        if (entry.id == .subject_alt_name) return entry.value_slice;
    }
    return der.Element.Slice.empty;
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
/// Matching rules implemented: `dNSName` (case-insensitive label-suffix,
/// e.g. `www.example.com` matches base `example.com` but `evilexample.com`
/// does not), `directoryName` (the base RDNSequence must be an exact
/// element-wise PREFIX of the name's RDNSequence — compared per encoded RDN
/// element, not as a raw byte prefix, so an RDN can't accidentally
/// straddle a match boundary), `iPAddress` (base = address||netmask,
/// contains iff `(name & mask) == (addr & mask)`). Other `GeneralName`
/// types (`rfc822Name`, `uniformResourceIdentifier`, etc.) are not matched
/// at all — see this file's module doc comment.
pub const CheckNameConstraintsError = error{NameConstraintViolated} || der.Element.ParseError;

pub fn checkNameConstraints(
    permitted: []const []const u8,
    excluded: []const []const u8,
    subject_dn: []const u8,
    subject_san: []const u8,
) CheckNameConstraintsError!void {
    try checkOneName(permitted, excluded, .directoryName, subject_dn);

    if (subject_san.len != 0) {
        // `subject_san` is the raw `subjectAltName` extnValue, i.e. the full
        // `GeneralNames ::= SEQUENCE OF GeneralName` TLV (same shape
        // `std.crypto.Certificate.Parsed.verifyHostName` unwraps) — parse
        // the outer SEQUENCE first, then walk its content.
        const general_names = try extensions.parseElement(subject_san, 0);
        var pos = general_names.slice.start;
        const end = general_names.slice.end;
        while (pos < end) {
            const elem = try extensions.parseElement(subject_san, pos);
            pos = elem.slice.end;
            const tag: Certificate.GeneralNameTag = @enumFromInt(@intFromEnum(elem.identifier.tag));
            const value = subject_san[elem.slice.start..elem.slice.end];
            try checkOneName(permitted, excluded, tag, value);
        }
    }
}

fn checkOneName(
    permitted: []const []const u8,
    excluded: []const []const u8,
    tag: Certificate.GeneralNameTag,
    value: []const u8,
) CheckNameConstraintsError!void {
    var it_ex: SubtreeSetIterator = .init(excluded);
    while (try it_ex.next()) |entry| {
        if (entry.tag != tag) continue;
        // An excluded constraint whose type we cannot match (rfc822Name/URI/…)
        // means we cannot prove `value` is OUTSIDE the excluded subtree — fail
        // closed rather than let a possibly-excluded name through (RFC 5280
        // §6.1.4). This mirrors the permitted side's default-deny for its types.
        if (!constraintTypeSupported(tag)) return error.NameConstraintViolated;
        if (nameMatchesBase(tag, value, entry.value)) return error.NameConstraintViolated;
    }

    var saw_type = false;
    var matched = false;
    var it_perm: SubtreeSetIterator = .init(permitted);
    while (try it_perm.next()) |entry| {
        if (entry.tag != tag) continue;
        saw_type = true;
        if (nameMatchesBase(tag, value, entry.value)) matched = true;
    }
    if (saw_type and !matched) return error.NameConstraintViolated;
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

fn nameMatchesBase(tag: Certificate.GeneralNameTag, name: []const u8, base: []const u8) bool {
    return switch (tag) {
        .dNSName => dnsNameMatches(name, base),
        .directoryName => dnMatchesPrefix(name, base),
        .iPAddress => ipMatchesSubnet(name, base),
        else => false,
    };
}

/// Whether `nameMatchesBase` can actually evaluate a constraint of this type.
/// For any other type (rfc822Name, uniformResourceIdentifier, otherName, …) a
/// match cannot be computed, so an *excluded* constraint of that type must fail
/// closed rather than silently pass (see `checkOneName`).
fn constraintTypeSupported(tag: Certificate.GeneralNameTag) bool {
    return switch (tag) {
        .dNSName, .directoryName, .iPAddress => true,
        else => false,
    };
}

fn dnsNameMatches(name: []const u8, base: []const u8) bool {
    if (base.len == 0 or name.len == 0) return false;
    if (std.ascii.eqlIgnoreCase(name, base)) return true;
    if (name.len <= base.len) return false;
    const suffix = name[name.len - base.len ..];
    if (!std.ascii.eqlIgnoreCase(suffix, base)) return false;
    return name[name.len - base.len - 1] == '.';
}

fn dnMatchesPrefix(name: []const u8, base: []const u8) bool {
    if (base.len == 0) return true;
    var name_pos: u32 = 0;
    var base_pos: u32 = 0;
    const name_end: u32 = @intCast(name.len);
    const base_end: u32 = @intCast(base.len);
    while (base_pos < base_end) {
        const base_elem = extensions.parseElement(base, base_pos) catch return false;
        if (name_pos >= name_end) return false;
        const name_elem = extensions.parseElement(name, name_pos) catch return false;
        if (!std.mem.eql(u8, base[base_pos..base_elem.slice.end], name[name_pos..name_elem.slice.end])) return false;
        base_pos = base_elem.slice.end;
        name_pos = name_elem.slice.end;
    }
    return true;
}

fn ipMatchesSubnet(name: []const u8, base: []const u8) bool {
    const half = base.len / 2;
    if (half == 0 or base.len != half * 2) return false;
    if (name.len != half) return false;
    const addr = base[0..half];
    const mask = base[half..];
    for (name, 0..) |b, i| {
        if ((b & mask[i]) != (addr[i] & mask[i])) return false;
    }
    return true;
}

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
// of it. `parseShape` (the other raw-DER walk in this file, used by
// `verifyPssLink`) is private and not independently reachable without a
// live `rsa.PublicKey`/hash comparison, so it is exercised only indirectly
// through the higher-level chain tests in `chain_test.zig`, not fuzzed here.
const testing = std.testing;

test "fuzz: parsePssParams never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzPssParams, .{});
}

fn fuzzPssParams(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = parsePssParams(buf[0..len]) catch {};
}

test {
    _ = @import("chain_test.zig");
}
