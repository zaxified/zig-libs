// SPDX-License-Identifier: MIT
//! Differential test against Go `crypto/x509` (go1.26.0): every verify and
//! hostname case of the S2 probe corpus (`data/s2/corpus.bin`, written by
//! `tools/gen_names_fixtures.py` with Go's verdict per case from
//! `tools/go_oracle`) is replayed through `verifyChain` / `hostname.verify`,
//! and our accept/reject must equal Go's — except the cases listed in
//! `deliberate`, where it must DIFFER (so the list cannot go stale).
//!
//! Go defaults are mapped as Go applies them: `KeyUsages == nil` is
//! `{serverAuth}`; `DNSName` is `expected_host`.

const std = @import("std");
const chain = @import("chain.zig");
const hostname = @import("hostname.zig");
const extensions = @import("extensions.zig");

const corpus = @embedFile("data/s2/corpus.bin");
/// The lead rows of `tools/interop.zig` (`-- --write`): chains Go 1.26
/// accepts and this module refuses, or Go refuses as an unhandled critical
/// extension and this module processes. Version 3 of the corpus format.
const leads = @embedFile("data/s2/leads.bin");

/// Where we disagree with Go on purpose, with the reason.
const deliberate = [_]struct { id: []const u8, why: []const u8 }{
    // `*.com`: Go matches it against any `x.com`; OpenSSL refuses and RFC 9525
    // §6.3 leaves a wildcard over a public suffix to the client. We refuse.
    .{ .id = "wild-s1-h1", .why = "*.com wildcard" },
    .{ .id = "wild-s1-h3", .why = "*.com wildcard" },
};

fn isDeliberate(id: []const u8) bool {
    for (deliberate) |d| if (std.mem.eql(u8, d.id, id)) return true;
    return false;
}

const Reader = struct {
    b: []const u8,
    i: usize = 0,

    fn bytes(r: *Reader, n: usize) []const u8 {
        defer r.i += n;
        return r.b[r.i..][0..n];
    }
    fn int(r: *Reader, comptime T: type) T {
        return std.mem.readInt(T, r.bytes(@sizeOf(T))[0..@sizeOf(T)], .little);
    }
    fn der(r: *Reader) []const u8 {
        return r.bytes(r.int(u16));
    }
};

/// One corpus record (format: the comment block of `tools/gen_names_fixtures.py`).
const Case = struct {
    id: []const u8,
    mode: u8,
    time: i64,
    host: []const u8,
    usage_bits: u8,
    policies: [16][]const u8,
    n_policies: usize,
    go_ok: bool,
    /// Version 3 only: 1 = we refuse what Go accepts, 2 = Go refuses a
    /// critical extension we process; 0 in versions 1 and 2.
    expect: u8,
    roots: [8][]const u8,
    n_roots: usize,
    /// Leaf first, then the intermediates.
    presented: [9][]const u8,
    n_presented: usize,

    fn chainCerts(c: *const Case) []const []const u8 {
        return c.presented[0..c.n_presented];
    }
    fn anchors(c: *const Case) []const []const u8 {
        return c.roots[0..c.n_roots];
    }
};

const Corpus = struct {
    r: Reader,
    version: u8,
    left: u32,

    fn open() !Corpus {
        return openBlob(corpus);
    }

    fn openBlob(blob: []const u8) !Corpus {
        var r: Reader = .{ .b = blob };
        const magic = r.bytes(8);
        if (!std.mem.eql(u8, magic[0..7], "X509S2\x00")) return error.BadCorpus;
        const version = magic[7];
        if (version < 1 or version > 3) return error.BadCorpus;
        const count = r.int(u32);
        return .{ .r = r, .version = version, .left = count };
    }

    fn next(cp: *Corpus) ?Case {
        if (cp.left == 0) return null;
        cp.left -= 1;
        const r = &cp.r;
        var c: Case = undefined;
        c.id = r.bytes(r.int(u8));
        c.mode = r.int(u8);
        c.time = r.int(i64);
        c.host = r.bytes(r.int(u8));
        c.usage_bits = r.int(u8);
        c.n_policies = if (cp.version >= 2) r.int(u8) else 0;
        for (c.policies[0..c.n_policies]) |*p| p.* = r.bytes(r.int(u8));
        c.go_ok = r.int(u8) == 1;
        c.expect = if (cp.version >= 3) r.int(u8) else 0;
        c.n_roots = r.int(u8);
        const n_inters = r.int(u8);
        for (c.roots[0..c.n_roots]) |*x| x.* = r.der();
        for (c.presented[1..][0..n_inters]) |*x| x.* = r.der();
        c.presented[0] = r.der();
        c.n_presented = 1 + n_inters;
        return c;
    }
};

fn find(id: []const u8) !Case {
    var cp = try Corpus.open();
    while (cp.next()) |c| if (std.mem.eql(u8, c.id, id)) return c;
    return error.CaseNotFound;
}

/// The `Options` the case's Go call corresponds to.
fn goOptions(c: *const Case, usages: *[3]extensions.Purpose) chain.Options {
    var nu: usize = 0;
    if (c.usage_bits == 0) {
        usages[0] = .server_auth;
        nu = 1;
    } else {
        inline for (.{ .{ 1, .server_auth }, .{ 2, .client_auth }, .{ 4, .any_extended_key_usage } }) |b| {
            if (c.usage_bits & b[0] != 0) {
                usages[nu] = b[1];
                nu += 1;
            }
        }
    }
    return .{
        .now_sec = c.time,
        .expected_host = if (c.host.len == 0) null else c.host,
        .usages_any_of = usages[0..nu],
        .policy = .{ .acceptable = c.policies[0..c.n_policies] },
    };
}

test "S2 corpus: verifyChain / hostname agree with Go crypto/x509" {
    const gpa = std.testing.allocator;
    var cp = try Corpus.open();
    var mismatches: usize = 0;
    var checked: usize = 0;
    while (cp.next()) |c| {
        const deliberate_case = isDeliberate(c.id);
        const ours_ok = switch (c.mode) {
            0 => ok: {
                var usages: [3]extensions.Purpose = undefined;
                _ = chain.verifyChain(gpa, c.chainCerts(), c.anchors(), goOptions(&c, &usages)) catch |err| {
                    if (c.go_ok != deliberate_case) std.debug.print("  {s}: ours rejects ({s}), Go accepts\n", .{ c.id, @errorName(err) });
                    break :ok false;
                };
                break :ok true;
            },
            1 => ok: {
                hostname.verify(c.presented[0], c.host) catch break :ok false;
                break :ok true;
            },
            else => return error.BadCorpus,
        };
        checked += 1;
        const want = if (deliberate_case) !c.go_ok else c.go_ok;
        if (ours_ok != want) {
            mismatches += 1;
            if (ours_ok) std.debug.print("  {s}: ours accepts, Go rejects\n", .{c.id});
            if (!ours_ok and c.mode == 1) std.debug.print("  {s}: ours rejects host, Go accepts\n", .{c.id});
        }
    }
    try std.testing.expectEqual(corpus.len, cp.r.i);
    if (mismatches != 0) {
        std.debug.print("S2 corpus: {d} of {d} cases disagree with Go\n", .{ mismatches, checked });
        return error.TestUnexpectedResult;
    }
}

// ── the opt-outs and additions, on corpus chains ─────────────────────────

fn verifyWith(id: []const u8, patch: anytype) chain.VerifyChainError!void {
    const c = find(id) catch |err| std.debug.panic("corpus case {s}: {t}", .{ id, err });
    var usages: [3]extensions.Purpose = undefined;
    var opts = goOptions(&c, &usages);
    inline for (@typeInfo(@TypeOf(patch)).@"struct".field_names) |f_name| @field(opts, f_name) = @field(patch, f_name);
    _ = try chain.verifyChain(std.testing.allocator, c.chainCerts(), c.anchors(), opts);
}

test "check_anchor_validity: an expired or not-yet-valid root fails; the flag restores RFC 5280 §6.1.1" {
    try std.testing.expectError(error.CertificateExpired, verifyWith("anchor-root-expired", .{}));
    try std.testing.expectError(error.CertificateNotYetValid, verifyWith("anchor-root-notyet", .{}));
    try verifyWith("anchor-root-expired", .{ .check_anchor_validity = false });
    try verifyWith("anchor-root-notyet", .{ .check_anchor_validity = false });
    // The flag is about the anchor only.
    try std.testing.expectError(error.CertificateExpired, verifyWith("anchor-inter-expired", .{ .check_anchor_validity = false }));
}

test "allow_sha1_signatures: SHA-1 links refused by default, accepted on request; a root's own SHA-1 self-signature never matters" {
    try std.testing.expectError(error.WeakSignatureAlgorithm, verifyWith("sha1-leaf-rsa", .{}));
    try std.testing.expectError(error.WeakSignatureAlgorithm, verifyWith("sha1-inter-rsa", .{}));
    try verifyWith("sha1-leaf-rsa", .{ .allow_sha1_signatures = true });
    try verifyWith("sha1-inter-rsa", .{ .allow_sha1_signatures = true });
    try verifyWith("sha1-root-self", .{});
    try verifyWith("sha1-control", .{});
}

test "ignore_critical_oids: an unknown critical extension rejects unless the caller handles it; duplicates always reject" {
    const unknown = [_]u8{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8d, 0x1f, 0x01 }; // 1.3.6.1.4.1.99999.1
    try std.testing.expectError(error.UnhandledCriticalExtension, verifyWith("crit-leaf-unknown-crit", .{}));
    try std.testing.expectError(error.UnhandledCriticalExtension, verifyWith("crit-inter-unknown-crit", .{}));
    try verifyWith("crit-leaf-unknown-crit", .{ .ignore_critical_oids = &[_][]const u8{&unknown} });
    try verifyWith("crit-inter-unknown-crit", .{ .ignore_critical_oids = &[_][]const u8{&unknown} });
    try verifyWith("crit-leaf-unknown-noncrit", .{});
    try std.testing.expectError(error.DuplicateExtension, verifyWith("dup-leaf-san", .{}));
    try std.testing.expectError(error.DuplicateExtension, verifyWith("dup-inter-bc", .{}));
}

test "max_constraint_comparisons: the budget is charged per (name, constraint) pair" {
    try verifyWith("dns-perm-c0-s1", .{});
    try verifyWith("dns-perm-c0-s1", .{ .max_constraint_comparisons = 1 });
    try std.testing.expectError(error.TooManyConstraints, verifyWith("dns-perm-c0-s1", .{ .max_constraint_comparisons = 0 }));
    // Without any constraint nothing is charged.
    try verifyWith("anchor-control", .{ .max_constraint_comparisons = 0 });
}

test "a v1 root is trusted as an anchor; a v3 root still needs basicConstraints cA" {
    try verifyWith("roots-v1", .{});
    try std.testing.expectError(error.NotACertificateAuthority, verifyWith("roots-v3-nobc", .{}));
}

test "verifyChainPath returns the path: leaf, intermediate, anchor" {
    const c = try find("anchor-control");
    var usages: [3]extensions.Purpose = undefined;
    var p = try chain.verifyChainPath(std.testing.allocator, c.chainCerts(), c.anchors(), goOptions(&c, &usages));
    defer p.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), p.certs.len);
    try std.testing.expectEqual(c.presented[0].ptr, p.certs[0].ptr);
    try std.testing.expectEqual(c.presented[1].ptr, p.certs[1].ptr);
    try std.testing.expectEqual(c.roots[0].ptr, p.certs[2].ptr);
    try std.testing.expectEqual(@as(u32, 2), p.summary.depth);
    // The same summary as verifyChain.
    const v = try chain.verifyChain(std.testing.allocator, c.chainCerts(), c.anchors(), goOptions(&c, &usages));
    try std.testing.expectEqual(v.depth, p.summary.depth);
    try std.testing.expectEqual(v.trust_anchor_index, p.summary.trust_anchor_index);
}

test "usages_any_of: Go KeyUsages semantics on corpus chains" {
    // Leaf serverAuth under an intermediate restricted to clientAuth: no usage
    // survives the whole chain, even when both are asked for.
    try std.testing.expectError(error.ExtendedKeyUsageMismatch, verifyWith("eku-lserver-iclient-kclient+server", .{}));
    // `any` asked: everything passes.
    try verifyWith("eku-lserver-iclient-kclient+server", .{ .usages_any_of = &[_]extensions.Purpose{.any_extended_key_usage} });
    // No usage asked and no required_eku: no EKU check at all (our default, not Go's).
    try verifyWith("eku-lserver-iclient-kclient+server", .{ .usages_any_of = &[_]extensions.Purpose{} });
}

test "lead: directoryName constraints and an empty extendedKeyUsage -- Go 1.26 accepts chains this module refuses" {
    // Go 1.26.8 verdicts, frozen by `zig build interop-x509 -- --write`.
    // stricter (1): Go accepts, we refuse -- RFC 5280 §4.2.1.10 / §6.1.3 (b)(c)
    // directoryName subtrees on the subject and on SAN directoryNames (Go does
    // not process them), and §4.2.1.12 `SIZE (1..MAX)` on extendedKeyUsage (Go
    // reads an empty one as no restriction). processes (2): a critical
    // nameConstraints with a directoryName subtree, which Go refuses as an
    // unhandled critical extension and we process.
    const gpa = std.testing.allocator;
    var cp = try Corpus.openBlob(leads);
    try std.testing.expectEqual(@as(u8, 3), cp.version);
    var n: usize = 0;
    while (cp.next()) |c| : (n += 1) {
        var usages: [3]extensions.Purpose = undefined;
        const ours_ok = if (chain.verifyChain(gpa, c.chainCerts(), c.anchors(), goOptions(&c, &usages))) |_| true else |_| false;
        switch (c.expect) {
            1 => {
                try std.testing.expect(c.go_ok);
                if (ours_ok) std.debug.print("  {s}: ours accepts, the lead is gone\n", .{c.id});
                try std.testing.expect(!ours_ok);
            },
            2 => {
                try std.testing.expect(!c.go_ok);
                if (!ours_ok) std.debug.print("  {s}: ours refuses a chain it should process\n", .{c.id});
                try std.testing.expect(ours_ok);
            },
            else => return error.BadCorpus,
        }
    }
    try std.testing.expectEqual(leads.len, cp.r.i);
    try std.testing.expectEqual(@as(usize, 15), n);
}
