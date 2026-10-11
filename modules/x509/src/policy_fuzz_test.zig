// SPDX-License-Identifier: MIT
//! Fuzz harness `x509-policy` (driver `X509_FUZZ`, see `fuzz_test.zig`):
//! `policy.check`, which keeps RFC 5280's valid_policy_tree as the graph of
//! RFC 9618, against a literal transcription of RFC 5280 §6.1 that builds the
//! TREE. RFC 9618 §4 states the two give the same verdict; random paths of
//! one to four certificates with random policy, mapping, constraint and
//! inhibit extensions (and random caller options) check that ours do.
//!
//! The certificates are skeletons — only what `policy.check` reads: the
//! version, issuer and subject names (self-issued or not) and the extensions.

const std = @import("std");
const policy = @import("policy.zig");
const fz = @import("fuzz_test.zig");

const Mark = fz.Marker(enum {
    valid,
    violation,
    invalid,
    mapping_used,
    any_expanded,
    acceptable_set,
    self_issued,
});

test "fuzz driver: X509_FUZZ (policy)" {
    try fz.fuzz_driver.run(harness, .{ .prefix = "X509_FUZZ", .name = "x509-policy", .scale = 4 });
}

test "fuzz harness: policy graph vs RFC 5280 tree, 600 seeds, reaches every outcome" {
    try Mark.reach(harness, "x509-policy", 600);
}

/// Policy pool: index 0 is anyPolicy, 1..3 ordinary OIDs (2.16.840.1.101.3.2.1.48.N).
const pool = [_][]const u8{
    &policy.oid_any_policy,
    &.{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x02, 0x01, 0x30, 0x01 },
    &.{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x02, 0x01, 0x30, 0x02 },
    &.{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x02, 0x01, 0x30, 0x03 },
};

const CertCfg = struct {
    has_policies: bool = false,
    policies: [4]u8 = undefined, // pool indexes
    n_policies: u8 = 0,
    mappings: [3][2]u8 = undefined,
    n_mappings: u8 = 0,
    require_explicit: ?u8 = null,
    inhibit_mapping: ?u8 = null,
    inhibit_any: ?u8 = null,
    self_issued: bool = false,
    /// A defect `policy.check` must refuse as `CertificatePolicyInvalid`.
    invalid: bool = false,
};

fn draw(comptime S: type, src: *S) [4]CertCfg {
    var cfgs: [4]CertCfg = @splat(.{});
    for (&cfgs) |*c| {
        c.has_policies = src.valueRangeAtMost(u8, 0, 4) != 0;
        if (c.has_policies) {
            const k = src.valueRangeAtMost(u8, 1, 3);
            var used: [4]bool = @splat(false);
            for (0..k) |_| {
                const p = src.valueRangeAtMost(u8, 0, 3);
                if (used[p]) {
                    if (src.valueRangeAtMost(u8, 0, 15) == 0) c.invalid = true else continue;
                }
                used[p] = true;
                c.policies[c.n_policies] = p;
                c.n_policies += 1;
            }
        }
        if (src.valueRangeAtMost(u8, 0, 2) == 0) {
            c.n_mappings = src.valueRangeAtMost(u8, 1, 3);
            for (c.mappings[0..c.n_mappings]) |*m| {
                m[0] = src.valueRangeAtMost(u8, 1, 3);
                m[1] = src.valueRangeAtMost(u8, 1, 3);
                if (src.valueRangeAtMost(u8, 0, 15) == 0) {
                    m[src.index(2)] = 0;
                    c.invalid = true;
                }
            }
        }
        if (src.valueRangeAtMost(u8, 0, 2) == 0) {
            if (src.value(bool)) c.require_explicit = src.valueRangeAtMost(u8, 0, 3);
            if (src.value(bool)) c.inhibit_mapping = src.valueRangeAtMost(u8, 0, 3);
        }
        if (src.valueRangeAtMost(u8, 0, 3) == 0) c.inhibit_any = src.valueRangeAtMost(u8, 0, 2);
        c.self_issued = src.valueRangeAtMost(u8, 0, 4) == 0;
    }
    return cfgs;
}

fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const n = src.valueRangeAtMost(u8, 1, 4);
    const cfgs = draw(S, src);
    var opts: policy.Options = .{
        .require_explicit = src.valueRangeAtMost(u8, 0, 3) == 0,
        .inhibit_mapping = src.valueRangeAtMost(u8, 0, 3) == 0,
        .inhibit_any = src.valueRangeAtMost(u8, 0, 3) == 0,
    };
    var acceptable: [3][]const u8 = undefined;
    var n_acc: usize = 0;
    if (src.value(bool)) {
        for (1..4) |p| if (src.value(bool)) {
            acceptable[n_acc] = pool[p];
            n_acc += 1;
        };
        if (n_acc != 0) Mark.mark(.acceptable_set);
    }
    opts.acceptable = acceptable[0..n_acc];

    var bufs: [4][512]u8 = undefined;
    var ders: [4][]const u8 = undefined;
    for (0..n) |i| ders[i] = build(&bufs[i], cfgs[i], i);

    const got = policy.check(gpa, ders[0..n], opts);
    const want = try reference(gpa, cfgs[0..n], opts);
    const got_v: Verdict = if (got) |_| .valid else |err| switch (err) {
        error.PolicyViolation => .violation,
        error.CertificatePolicyInvalid => .invalid,
        else => return err,
    };
    // The literal tree can grow exponentially under mappings; past
    // `max_tree` nodes there is no reference verdict.
    if (want == .too_big) return;
    if (got_v != want) {
        std.debug.print("policy.check = {t}, RFC 5280 tree = {t}; n={d} opts={any}\n", .{ got_v, want, n, opts });
        for (cfgs[0..n], 0..) |c, i| std.debug.print("  cert {d}: {any}\n", .{ i + 1, c });
        return error.PolicyGraphDisagreesWithTree;
    }
    switch (got_v) {
        .valid => Mark.mark(.valid),
        .violation => Mark.mark(.violation),
        .invalid => Mark.mark(.invalid),
        .too_big => unreachable,
    }
    for (cfgs[0..n]) |c| {
        if (c.self_issued) Mark.mark(.self_issued);
        if (c.n_mappings != 0 and !c.invalid) Mark.mark(.mapping_used);
        if (c.has_policies and c.n_policies != 0 and c.policies[0] == 0) Mark.mark(.any_expanded);
    }
}

// ── a skeleton certificate carrying the configured extensions ────────────

const Out = struct {
    buf: []u8,
    n: usize = 0,

    fn byte(o: *Out, b: u8) void {
        o.buf[o.n] = b;
        o.n += 1;
    }
    fn bytes(o: *Out, s: []const u8) void {
        @memcpy(o.buf[o.n..][0..s.len], s);
        o.n += s.len;
    }
    /// Opens a TLV with a 2-octet long-form length to patch in `close`.
    fn open(o: *Out, tag: u8) usize {
        o.byte(tag);
        o.byte(0x82);
        o.byte(0);
        o.byte(0);
        return o.n;
    }
    fn close(o: *Out, at: usize) void {
        const len = o.n - at;
        o.buf[at - 2] = @intCast(len >> 8);
        o.buf[at - 1] = @intCast(len & 0xff);
    }
    fn oid(o: *Out, content: []const u8) void {
        o.byte(0x06);
        o.byte(@intCast(content.len));
        o.bytes(content);
    }
    fn uint(o: *Out, tag: u8, v: u8) void {
        o.byte(tag);
        if (v >= 0x80) {
            o.byte(2);
            o.byte(0);
        } else o.byte(1);
        o.byte(v);
    }
};

fn name(o: *Out, id: u8) void {
    const seq = o.open(0x30);
    const set = o.open(0x31);
    const atv = o.open(0x30);
    o.oid(&.{ 0x55, 0x04, 0x03 });
    o.bytes(&.{ 0x0c, 0x01, id });
    o.close(atv);
    o.close(set);
    o.close(seq);
}

fn ext(o: *Out, oid_content: []const u8, critical: bool) usize {
    const e = o.open(0x30);
    o.oid(oid_content);
    if (critical) o.bytes(&.{ 0x01, 0x01, 0xff });
    const v = o.open(0x04);
    _ = e;
    return v;
}

fn build(buf: []u8, c: CertCfg, idx: usize) []const u8 {
    var o: Out = .{ .buf = buf };
    const cert = o.open(0x30);
    const tbs = o.open(0x30);
    o.bytes(&.{ 0xa0, 0x03, 0x02, 0x01, 0x02 }); // v3
    o.bytes(&.{ 0x02, 0x01, 0x01 });
    o.bytes(&.{ 0x30, 0x00 });
    // Issuer is the certificate above (named by index), subject this one;
    // a self-issued one repeats its issuer's name.
    const issuer_id: u8 = 'A' + @as(u8, @intCast(idx));
    name(&o, issuer_id);
    o.bytes(&.{ 0x30, 0x00 }); // validity: not read by policy.check
    name(&o, if (c.self_issued) issuer_id else issuer_id + 1);
    o.bytes(&.{ 0x30, 0x00 }); // spki: not read
    const x3 = o.open(0xa3);
    const exts = o.open(0x30);
    if (c.has_policies) {
        const e_start = o.n;
        const v = ext(&o, &.{ 0x55, 0x1d, 0x20 }, false);
        const seq = o.open(0x30);
        for (c.policies[0..c.n_policies]) |p| {
            const info = o.open(0x30);
            o.oid(pool[p]);
            o.close(info);
        }
        o.close(seq);
        o.close(v);
        o.close(e_start + 4);
    }
    if (c.n_mappings != 0) {
        const e_start = o.n;
        const v = ext(&o, &.{ 0x55, 0x1d, 0x21 }, false);
        const seq = o.open(0x30);
        for (c.mappings[0..c.n_mappings]) |m| {
            const pair = o.open(0x30);
            o.oid(pool[m[0]]);
            o.oid(pool[m[1]]);
            o.close(pair);
        }
        o.close(seq);
        o.close(v);
        o.close(e_start + 4);
    }
    if (c.require_explicit != null or c.inhibit_mapping != null) {
        const e_start = o.n;
        const v = ext(&o, &.{ 0x55, 0x1d, 0x24 }, true);
        const seq = o.open(0x30);
        if (c.require_explicit) |r| o.uint(0x80, r);
        if (c.inhibit_mapping) |m| o.uint(0x81, m);
        o.close(seq);
        o.close(v);
        o.close(e_start + 4);
    }
    if (c.inhibit_any) |q| {
        const e_start = o.n;
        const v = ext(&o, &.{ 0x55, 0x1d, 0x36 }, true);
        o.uint(0x02, q);
        o.close(v);
        o.close(e_start + 4);
    }
    o.close(exts);
    o.close(x3);
    o.close(tbs);
    o.bytes(&.{ 0x30, 0x00, 0x03, 0x01, 0x00 });
    o.close(cert);
    return buf[0..o.n];
}

// ── RFC 5280 §6.1, the tree, transcribed ─────────────────────────────────

const Verdict = enum { valid, violation, invalid, too_big };

const TNode = struct {
    policy: u8, // pool index
    expected: std.ArrayList(u8) = .empty,
    parent: ?u32,
    depth: u8,
    alive: bool = true,
};

const max_tree = 4000;

fn reference(gpa: std.mem.Allocator, cfgs: []const CertCfg, opts: policy.Options) !Verdict {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var t: std.ArrayList(TNode) = .empty;

    const n: u32 = @intCast(cfgs.len);
    var explicit: u32 = if (opts.require_explicit) 0 else n + 1;
    var mapping: u32 = if (opts.inhibit_mapping) 0 else n + 1;
    var inhibit: u32 = if (opts.inhibit_any) 0 else n + 1;

    try t.append(a, .{ .policy = 0, .parent = null, .depth = 0 });
    try t.items[0].expected.append(a, 0);
    var tree_null = false;

    for (cfgs, 1..) |c, i_usize| {
        const i: u8 = @intCast(i_usize);
        if (c.invalid) return .invalid;
        if (!tree_null and c.has_policies) {
            const before = t.items.len;
            // (d)(1)
            for (c.policies[0..c.n_policies]) |p| {
                if (p == 0) continue;
                var matched = false;
                for (0..before) |k| {
                    const node = t.items[k];
                    if (!node.alive or node.depth != i - 1) continue;
                    if (std.mem.indexOfScalar(u8, node.expected.items, p) == null) continue;
                    matched = true;
                    try child(a, &t, @intCast(k), p, &.{p});
                }
                if (!matched) for (0..before) |k| {
                    const node = t.items[k];
                    if (!node.alive or node.depth != i - 1 or node.policy != 0) continue;
                    try child(a, &t, @intCast(k), p, &.{p});
                };
            }
            // (d)(2)
            const has_any = std.mem.indexOfScalar(u8, c.policies[0..c.n_policies], 0) != null;
            if (has_any and (inhibit > 0 or (i < n and c.self_issued))) {
                const after_d1 = t.items.len;
                for (0..before) |k| {
                    const node = t.items[k];
                    if (!node.alive or node.depth != i - 1) continue;
                    for (node.expected.items) |e| {
                        var exists = false;
                        for (before..after_d1) |j| {
                            const ch = t.items[j];
                            if (ch.alive and ch.parent.? == k and ch.policy == e) exists = true;
                        }
                        // ... nor created by this (d)(2) step for this parent.
                        for (after_d1..t.items.len) |j| {
                            const ch = t.items[j];
                            if (ch.alive and ch.parent.? == k and ch.policy == e) exists = true;
                        }
                        if (!exists) try child(a, &t, @intCast(k), e, &.{e});
                    }
                }
            }
            if (t.items.len > max_tree) return .too_big;
            prune(&t, i);
            if (!hasDepth(&t, i)) tree_null = true;
        } else tree_null = true;

        // (f)
        if (explicit == 0 and tree_null) return .violation;

        if (i == n) {
            if (explicit != 0) explicit -= 1;
            if (c.require_explicit) |r| if (r == 0) {
                explicit = 0;
            };
            break;
        }

        // §6.1.4 (b)
        if (!tree_null) for (c.mappings[0..c.n_mappings]) |m| {
            const id = m[0];
            if (mapping > 0) {
                var mapped: std.ArrayList(u8) = .empty;
                for (c.mappings[0..c.n_mappings]) |mm| if (mm[0] == id and std.mem.indexOfScalar(u8, mapped.items, mm[1]) == null) try mapped.append(a, mm[1]);
                var found = false;
                for (t.items) |*node| if (node.alive and node.depth == i and node.policy == id) {
                    node.expected = try mapped.clone(a);
                    found = true;
                };
                if (!found) {
                    const len = t.items.len;
                    for (0..len) |k| {
                        const node = t.items[k];
                        if (!node.alive or node.depth != i or node.policy != 0) continue;
                        // Already generated for this ID by an earlier mapping entry?
                        var dup = false;
                        for (t.items) |x| if (x.alive and x.depth == i and x.policy == id) {
                            dup = true;
                        };
                        if (!dup) try child(a, &t, node.parent.?, id, mapped.items);
                    }
                }
            } else {
                for (t.items) |*node| if (node.alive and node.depth == i and node.policy == id) killSubtree(&t, node);
                prune(&t, i);
            }
        };
        if (!tree_null and !hasDepth(&t, i)) tree_null = true;

        if (!c.self_issued) {
            if (explicit != 0) explicit -= 1;
            if (mapping != 0) mapping -= 1;
            if (inhibit != 0) inhibit -= 1;
        }
        if (c.require_explicit) |r| explicit = @min(explicit, r);
        if (c.inhibit_mapping) |m| mapping = @min(mapping, m);
        if (c.inhibit_any) |q| inhibit = @min(inhibit, q);
    }

    // §6.1.5 (g)
    var valid = !tree_null;
    if (valid and opts.acceptable.len != 0) {
        const user = struct {
            fn has(acc: []const []const u8, p: u8) bool {
                for (acc) |x| if (std.mem.eql(u8, x, pool[p])) return true;
                return false;
            }
        };
        // (ii) nodes whose parent is anyPolicy and that are neither anyPolicy
        // nor in the user set go, with their subtrees.
        for (t.items) |*node| {
            if (!node.alive or node.parent == null or node.policy == 0) continue;
            if (t.items[node.parent.?].policy != 0) continue;
            if (!user.has(opts.acceptable, node.policy)) killSubtree(&t, node);
        }
        // (iii) an anyPolicy leaf stands for every user policy (we only need
        // to know whether something survives at depth n).
        valid = false;
        for (t.items) |node| if (node.alive and node.depth == n) {
            valid = true;
        };
    }
    if (explicit == 0 and !valid) return .violation;
    return .valid;
}

fn child(a: std.mem.Allocator, t: *std.ArrayList(TNode), parent: u32, p: u8, expected: []const u8) !void {
    var node: TNode = .{ .policy = p, .parent = parent, .depth = t.items[parent].depth + 1 };
    try node.expected.appendSlice(a, expected);
    try t.append(a, node);
}

fn hasDepth(t: *const std.ArrayList(TNode), d: u8) bool {
    for (t.items) |node| if (node.alive and node.depth == d) return true;
    return false;
}

/// Removes every node above depth `d` left without a live child.
fn prune(t: *std.ArrayList(TNode), d: u8) void {
    var changed = true;
    while (changed) {
        changed = false;
        for (t.items, 0..) |*node, k| {
            if (!node.alive or node.depth >= d) continue;
            var has_child = false;
            for (t.items) |x| if (x.alive and x.parent != null and x.parent.? == k) {
                has_child = true;
            };
            if (!has_child) {
                node.alive = false;
                changed = true;
            }
        }
    }
}

fn killSubtree(t: *std.ArrayList(TNode), node: *TNode) void {
    node.alive = false;
    const k = (@intFromPtr(node) - @intFromPtr(t.items.ptr)) / @sizeOf(TNode);
    for (t.items) |*x| if (x.alive and x.parent != null and x.parent.? == k) killSubtree(t, x);
}
