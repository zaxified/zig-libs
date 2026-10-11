// SPDX-License-Identifier: MIT
//! Certificate policy processing (RFC 5280 §6.1.2–§6.1.5), with the
//! valid_policy_tree kept as the graph of RFC 9618 so that policy mappings
//! cannot make it grow exponentially. `chain.verifyChain` runs it on every
//! path, as Go's `Verify` does since Go 1.22: a CA that sets
//! `requireExplicitPolicy` gets it enforced even when the caller asked for no
//! particular policy (probe O-policy, 2026-10-11).
//!
//! The path is processed top-down without the trust anchor (§6.1: the
//! anchor is input, not certificate 1). Every policy is identified by the
//! content bytes of its OID.

const std = @import("std");
const Certificate = std.crypto.Certificate;
const der = Certificate.der;
const extensions = @import("extensions.zig");

pub const Error = error{
    /// No policy is valid for the path where one is required: a CA's
    /// `requireExplicitPolicy` (or `Options.require_explicit`) was in force and
    /// no policy — no `acceptable` one, when given — survived (RFC 5280
    /// §6.1.3 (f), §6.1.5 (g)–(i)).
    PolicyViolation,
    /// A certificatePolicies / policyMappings / policyConstraints /
    /// inhibitAnyPolicy extension that does not decode, repeats a policy (Go
    /// refuses that at parse), or maps to or from anyPolicy (§4.2.1.5).
    CertificatePolicyInvalid,
    /// The policy graph outgrew `Options.max_graph_edges`.
    PolicyGraphTooLarge,
} || std.mem.Allocator.Error || extensions.FindExtensionsError || extensions.IterateError;

/// Caller policy, all defaults = RFC 5280 §6.1.1 defaults (= Go's defaults).
pub const Options = struct {
    /// user-initial-policy-set: the policies the caller accepts (OID content
    /// bytes). Empty = any policy (Go: empty `CertificatePolicies`). As in
    /// RFC 5280 §6.1.5 and Go, it decides only once an explicit policy is
    /// required — by a CA's requireExplicitPolicy or by `require_explicit`;
    /// a caller that wants "one of these, or fail" sets both.
    acceptable: []const []const u8 = &.{},
    /// initial-explicit-policy.
    require_explicit: bool = false,
    /// initial-policy-mapping-inhibit.
    inhibit_mapping: bool = false,
    /// initial-any-policy-inhibit.
    inhibit_any: bool = false,
    /// Cap on parent→child edges in the policy graph. Each certificate is at
    /// most 64 KiB, so policies and mappings per level are bounded, but edges
    /// between two levels are their product.
    max_graph_edges: u32 = 100_000,
};

pub const oid_any_policy = [_]u8{ 0x55, 0x1d, 0x20, 0x00 };
const oid_certificate_policies = [_]u8{ 0x55, 0x1d, 0x20 };
const oid_policy_mappings = [_]u8{ 0x55, 0x1d, 0x21 };
const oid_policy_constraints = [_]u8{ 0x55, 0x1d, 0x24 };
const oid_inhibit_any_policy = [_]u8{ 0x55, 0x1d, 0x36 };

fn isAny(oid: []const u8) bool {
    return std.mem.eql(u8, oid, &oid_any_policy);
}

const Node = struct {
    policy: []const u8,
    expected: []const []const u8,
    parents: std.ArrayList(u32) = .empty,
    /// Every ancestor, and the node itself, is anyPolicy.
    pure_any: bool = false,
    /// The first non-anyPolicy node on some path down to this one is in
    /// `acceptable` (computed only when `acceptable` is non-empty).
    authorized: bool = false,
};

const Level = struct {
    nodes: std.ArrayList(Node) = .empty,
    index: std.StringHashMapUnmanaged(u32) = .empty,

    fn find(l: *const Level, policy: []const u8) ?u32 {
        return l.index.get(policy);
    }

    fn add(l: *Level, a: std.mem.Allocator, policy: []const u8, expected: []const []const u8) !u32 {
        const i: u32 = @intCast(l.nodes.items.len);
        try l.nodes.append(a, .{ .policy = policy, .expected = expected });
        try l.index.put(a, policy, i);
        return i;
    }

    fn remove(l: *Level, policy: []const u8) void {
        // Removed nodes keep their slot (indexes stay valid) but lose their
        // parents, which takes them out of every later step.
        const i = l.index.get(policy) orelse return;
        _ = l.index.remove(policy);
        l.nodes.items[i].parents.clearRetainingCapacity();
        l.nodes.items[i].policy = "";
    }
};

/// One certificate's policy extensions, decoded.
const CertPolicies = struct {
    /// `null` = no certificatePolicies extension.
    policies: ?[]const []const u8 = null,
    has_any: bool = false,
    mappings: []const [2][]const u8 = &.{},
    require_explicit: ?u64 = null,
    inhibit_mapping: ?u64 = null,
    inhibit_any: ?u64 = null,
    self_issued: bool,
};

/// Validates the policies of `path`, top-down: `path[0]` is the certificate
/// the trust anchor issued, `path[path.len - 1]` the leaf.
pub fn check(gpa: std.mem.Allocator, path: []const []const u8, opts: Options) Error!void {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const n: u64 = path.len;
    var explicit_policy: u64 = if (opts.require_explicit) 0 else n + 1;
    var policy_mapping: u64 = if (opts.inhibit_mapping) 0 else n + 1;
    var inhibit_any: u64 = if (opts.inhibit_any) 0 else n + 1;
    var edges: u32 = 0;

    // §6.1.2 (a): one anyPolicy node. `prev` is the level of certificate i-1.
    var prev: Level = .{};
    const root = try prev.add(a, &oid_any_policy, try a.dupe([]const u8, &.{&oid_any_policy}));
    prev.nodes.items[root].pure_any = true;
    var graph_null = false;

    for (path, 0..) |cert_der, idx| {
        const i: u64 = idx + 1;
        const cp = try decode(a, cert_der);

        // §6.1.3 (d)/(e): the next level of the graph.
        var cur: Level = .{};
        if (!graph_null) if (cp.policies) |pols| {
            for (pols) |p| {
                if (isAny(p)) continue;
                // (d)(1)(i): children of every node expecting `p` ...
                var matched = false;
                for (prev.nodes.items, 0..) |pn, pi| {
                    if (!alive(pn) or !contains(pn.expected, p)) continue;
                    matched = true;
                    try link(a, &cur, p, @intCast(pi), &edges, opts);
                }
                // (d)(1)(ii): ... else of the anyPolicy node.
                if (!matched) for (prev.nodes.items, 0..) |pn, pi| {
                    if (!alive(pn) or !isAny(pn.policy)) continue;
                    try link(a, &cur, p, @intCast(pi), &edges, opts);
                };
            }
            // (d)(2): anyPolicy stands in for every expected policy of a
            // parent that (d)(1) did not produce.
            if (cp.has_any and (inhibit_any > 0 or (i < n and cp.self_issued))) {
                const from_d1 = cur.nodes.items.len;
                for (prev.nodes.items, 0..) |pn, pi| {
                    if (!alive(pn)) continue;
                    for (pn.expected) |e| {
                        if (cur.find(e)) |ci| if (ci < from_d1) continue;
                        try link(a, &cur, e, @intCast(pi), &edges, opts);
                    }
                }
            }
        };
        mark(&cur, &prev, opts);
        prev = cur;
        if (!hasAlive(&prev)) graph_null = true;

        // §6.1.3 (f).
        if (explicit_policy == 0 and graph_null) return error.PolicyViolation;

        if (i == n) {
            // §6.1.5 (a), (b).
            if (explicit_policy != 0) explicit_policy -= 1;
            if (cp.require_explicit) |r| if (r == 0) {
                explicit_policy = 0;
            };
            break;
        }

        // §6.1.4 (a), (b): mappings rewrite the expected sets of this level.
        if (!graph_null) for (cp.mappings) |m| {
            if (policy_mapping > 0) {
                const mapped = try mappedSet(a, cp.mappings, m[0]);
                if (prev.find(m[0])) |ni| {
                    prev.nodes.items[ni].expected = mapped;
                } else if (prev.find(&oid_any_policy)) |ai| {
                    // A node for the issuer-domain policy, as a sibling of
                    // anyPolicy (same parents, which are all anyPolicy).
                    const parents = prev.nodes.items[ai].parents.items;
                    const ni = try prev.add(a, m[0], mapped);
                    const node = &prev.nodes.items[ni];
                    for (parents) |pp| {
                        try charge(&edges, opts);
                        try node.parents.append(a, pp);
                    }
                    node.authorized = contains(opts.acceptable, m[0]);
                }
            } else prev.remove(m[0]);
        };
        if (!hasAlive(&prev)) graph_null = true;

        // §6.1.4 (h)–(j).
        if (!cp.self_issued) {
            if (explicit_policy != 0) explicit_policy -= 1;
            if (policy_mapping != 0) policy_mapping -= 1;
            if (inhibit_any != 0) inhibit_any -= 1;
        }
        if (cp.require_explicit) |r| explicit_policy = @min(explicit_policy, r);
        if (cp.inhibit_mapping) |m| policy_mapping = @min(policy_mapping, m);
        if (cp.inhibit_any) |q| inhibit_any = @min(inhibit_any, q);
    }

    // §6.1.5 (g): the caller's set. With none, any surviving node is a valid
    // policy; with one, a leaf-level node must be authorized, or be anyPolicy
    // reached through anyPolicy only (which stands for every acceptable one).
    const valid = !graph_null and (opts.acceptable.len == 0 or for (prev.nodes.items) |node| {
        if (alive(node) and (node.pure_any or node.authorized)) break true;
    } else false);
    // §6.1.5 (h)/(i). `acceptable` alone does not make a policy required
    // (initial-explicit-policy is separate), exactly as in Go.
    if (explicit_policy == 0 and !valid) return error.PolicyViolation;
}

/// `pure_any` and `authorized` for the new level `cur`, from `prev`.
fn mark(cur: *Level, prev: *const Level, opts: Options) void {
    for (cur.nodes.items) |*node| {
        for (node.parents.items) |pi| {
            const p = prev.nodes.items[pi];
            if (!alive(p)) continue;
            if (isAny(node.policy)) {
                // anyPolicy only ever descends from anyPolicy.
                if (p.pure_any) node.pure_any = true;
            } else if (p.pure_any) {
                // The first non-anyPolicy node on this path.
                if (contains(opts.acceptable, node.policy)) node.authorized = true;
            } else if (p.authorized) node.authorized = true;
        }
    }
}

fn hasAlive(l: *const Level) bool {
    for (l.nodes.items) |node| if (alive(node)) return true;
    return false;
}

fn alive(node: Node) bool {
    return node.policy.len != 0;
}

fn contains(set: []const []const u8, p: []const u8) bool {
    for (set) |x| if (std.mem.eql(u8, x, p)) return true;
    return false;
}

fn charge(edges: *u32, opts: Options) error{PolicyGraphTooLarge}!void {
    edges.* += 1;
    if (edges.* > opts.max_graph_edges) return error.PolicyGraphTooLarge;
}

/// Adds `parent` to the node for `policy` in `level`, creating the node with
/// expected set {policy}.
fn link(a: std.mem.Allocator, level: *Level, policy: []const u8, parent: u32, edges: *u32, opts: Options) !void {
    try charge(edges, opts);
    const ni = level.find(policy) orelse try level.add(a, policy, try a.dupe([]const u8, &.{policy}));
    const parents = &level.nodes.items[ni].parents;
    for (parents.items) |p| if (p == parent) return;
    try parents.append(a, parent);
}

fn mappedSet(a: std.mem.Allocator, mappings: []const [2][]const u8, issuer_p: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (mappings) |m| {
        if (!std.mem.eql(u8, m[0], issuer_p)) continue;
        if (!contains(out.items, m[1])) try out.append(a, m[1]);
    }
    return out.items;
}

// ── decoding the four extensions (RFC 5280 §4.2.1.4/.5/.11/.14) ───────────

fn decode(a: std.mem.Allocator, cert_der: []const u8) Error!CertPolicies {
    const cert: Certificate = .{ .buffer = cert_der, .index = 0 };
    var out: CertPolicies = .{ .self_issued = try selfIssued(cert_der) };
    const exts = (try extensions.findExtensions(cert)) orelse return out;
    var it = extensions.iterate(exts, cert);
    while (try it.next()) |e| {
        if (std.mem.eql(u8, e.oid, &oid_certificate_policies)) {
            var list: std.ArrayList([]const u8) = .empty;
            var pit = try seqOf(e.value);
            while (try pit.next()) |info| {
                // PolicyInformation ::= SEQUENCE { policyIdentifier OID, policyQualifiers … OPTIONAL }
                if (info.tag != 0x30) return error.CertificatePolicyInvalid;
                const oid = try firstOid(info.content);
                if (contains(list.items, oid)) return error.CertificatePolicyInvalid;
                if (isAny(oid)) out.has_any = true;
                try list.append(a, oid);
            }
            out.policies = list.items;
        } else if (std.mem.eql(u8, e.oid, &oid_policy_mappings)) {
            var list: std.ArrayList([2][]const u8) = .empty;
            var mit = try seqOf(e.value);
            while (try mit.next()) |pair| {
                if (pair.tag != 0x30) return error.CertificatePolicyInvalid;
                var pit: Seq = .{ .b = pair.content };
                const issuer_p = try oidOf(try pit.next() orelse return error.CertificatePolicyInvalid);
                const subject_p = try oidOf(try pit.next() orelse return error.CertificatePolicyInvalid);
                if (try pit.next() != null) return error.CertificatePolicyInvalid;
                if (isAny(issuer_p) or isAny(subject_p)) return error.CertificatePolicyInvalid;
                try list.append(a, .{ issuer_p, subject_p });
            }
            if (list.items.len == 0) return error.CertificatePolicyInvalid;
            out.mappings = list.items;
        } else if (std.mem.eql(u8, e.oid, &oid_policy_constraints)) {
            var cit = try seqOf(e.value);
            while (try cit.next()) |f| {
                switch (f.tag) {
                    0x80 => if (out.require_explicit != null or out.inhibit_mapping != null) return error.CertificatePolicyInvalid else {
                        out.require_explicit = try uintOf(f.content);
                    },
                    0x81 => if (out.inhibit_mapping != null) return error.CertificatePolicyInvalid else {
                        out.inhibit_mapping = try uintOf(f.content);
                    },
                    else => return error.CertificatePolicyInvalid,
                }
            }
            // §4.2.1.11 forbids issuing an empty SEQUENCE; Go accepts it as
            // constraining nothing (probe pol2-bad-polcons-empty), and so do we.
        } else if (std.mem.eql(u8, e.oid, &oid_inhibit_any_policy)) {
            var s: Seq = .{ .b = e.value };
            const v = try s.next() orelse return error.CertificatePolicyInvalid;
            if (v.tag != 0x02 or try s.next() != null) return error.CertificatePolicyInvalid;
            out.inhibit_any = try uintOf(v.content);
        }
    }
    return out;
}

fn selfIssued(cert_der: []const u8) error{CertificateFieldHasInvalidLength}!bool {
    // tbsCertificate fields: [version] serial signature issuer validity subject.
    var s: Seq = .{ .b = cert_der };
    const cert = (s.next() catch return error.CertificateFieldHasInvalidLength) orelse return error.CertificateFieldHasInvalidLength;
    var c: Seq = .{ .b = cert.content };
    const tbs = (c.next() catch return error.CertificateFieldHasInvalidLength) orelse return error.CertificateFieldHasInvalidLength;
    var t: Seq = .{ .b = tbs.content };
    var fields: [6]Tlv = undefined;
    var k: usize = 0;
    while (k < 6) : (k += 1) fields[k] = (t.next() catch return error.CertificateFieldHasInvalidLength) orelse return error.CertificateFieldHasInvalidLength;
    const off: usize = if (fields[0].tag == 0xa0) 1 else 0;
    if (off == 0) {
        // v1: serial signature issuer validity subject in fields[0..5].
        return std.mem.eql(u8, fields[2].content, fields[4].content);
    }
    return std.mem.eql(u8, fields[3].content, fields[5].content);
}

const Tlv = struct { tag: u8, content: []const u8 };

/// Minimal DER walker over one level (definite lengths up to 4 octets).
const Seq = struct {
    b: []const u8,
    i: usize = 0,

    fn next(s: *Seq) error{CertificatePolicyInvalid}!?Tlv {
        if (s.i >= s.b.len) return null;
        if (s.b.len - s.i < 2) return error.CertificatePolicyInvalid;
        const tag = s.b[s.i];
        var len: usize = s.b[s.i + 1];
        var j = s.i + 2;
        if (len & 0x80 != 0) {
            const k = len & 0x7f;
            if (k == 0 or k > 4 or s.b.len - j < k) return error.CertificatePolicyInvalid;
            len = 0;
            for (s.b[j..][0..k]) |x| len = (len << 8) | x;
            j += k;
        }
        if (s.b.len - j < len) return error.CertificatePolicyInvalid;
        s.i = j + len;
        return .{ .tag = tag, .content = s.b[j..][0..len] };
    }
};

fn seqOf(value: []const u8) error{CertificatePolicyInvalid}!Seq {
    var outer: Seq = .{ .b = value };
    const seq = try outer.next() orelse return error.CertificatePolicyInvalid;
    if (seq.tag != 0x30 or outer.i != value.len) return error.CertificatePolicyInvalid;
    return .{ .b = seq.content };
}

fn oidOf(t: Tlv) error{CertificatePolicyInvalid}![]const u8 {
    if (t.tag != 0x06 or t.content.len == 0) return error.CertificatePolicyInvalid;
    return t.content;
}

fn firstOid(content: []const u8) error{CertificatePolicyInvalid}![]const u8 {
    var s: Seq = .{ .b = content };
    return oidOf(try s.next() orelse return error.CertificatePolicyInvalid);
}

/// SkipCerts ::= INTEGER (0..MAX), here capped at what fits a u64.
fn uintOf(content: []const u8) error{CertificatePolicyInvalid}!u64 {
    if (content.len == 0 or content[0] & 0x80 != 0) return error.CertificatePolicyInvalid;
    if (content.len > 1 and content[0] == 0 and content[1] & 0x80 == 0) return error.CertificatePolicyInvalid;
    var v: u64 = 0;
    for (content) |b| {
        if (v > std.math.maxInt(u64) >> 8) return std.math.maxInt(u64);
        v = (v << 8) | b;
    }
    return v;
}
