// SPDX-License-Identifier: MIT

//! OFFLINE anchor for the RFC 6724 half: glibc's getaddrinfo (destination
//! order) and the Linux kernel (IPv6 source choice), both taken as black boxes
//! by `tools/rfc6724_oracle.py` into `rfc6724_vectors.zig` and replayed here
//! with no namespace and no socket. Neither is this module's model (that is
//! Go's addrselect.go), so an agreement is evidence and not an echo.
//!
//! glibc ran with /etc/gai.conf holding exactly the RFC 6724 §2.1 table, and
//! every source it used is recorded next to its destination, so
//! `sortDestinationsWithSources` gets the same input glibc's rfc3484_sort
//! had. The kernel chose among IPv6 candidates on one interface, each a /64;
//! a choice that moved when the candidates were added in reverse order is a
//! tie, and either answer is accepted.
//!
//! An oracle is not an authority: every class of case where this module
//! answers differently is listed in `divergences` with the judgement. A
//! differing case no entry explains fails, and so does an entry that no
//! longer explains any case.

const std = @import("std");
const testing = std.testing;
const netaddr = @import("root.zig");
const vectors = @import("rfc6724_vectors.zig");

const Ip = netaddr.Ip;

fn ip(text: []const u8) Ip {
    return netaddr.parseIp(text) orelse std.debug.panic("vector address {s} does not parse", .{text});
}

/// One class of case where glibc's order differs from ours. `explains` is a
/// narrow, black-box statement about the case (addresses, what glibc
/// answered for the case's pairs) -- never a model of glibc's code.
const Divergence = struct {
    name: []const u8,
    why: []const u8,
    explains: *const fn (w: vectors.World, in: []const u8, want: []const u8, ours: []const u8) bool,
};

const divergences = [_]Divergence{
    .{
        .name = "mapped-v4-scope",
        .why = "glibc ranks an IPv6 result written as ::ffff:127.x or ::ffff:169.254.x (or such a source) as global scope, as though it were not IPv4 at all -- its IPv4 scope rules (127/8 and 169.254/16 link-local) apply to AF_INET results only. RFC 6724 §3.2 gives IPv4 loopback and link-local addresses link-local scope however they are written, and so do Go and this module",
        .explains = involvesMappedLocalV4,
    },
    .{
        .name = "ipv4-rule9",
        .why = "between two usable plain-IPv4 destinations that tie through rule 8, glibc still reorders (its rule 9 on IPv4 looks at the source's own subnet: 127.0.0.2 from 127.0.0.1/8 beats 169.254.0.9 from 169.254.0.1/32). This module and Go apply rule 9 to IPv6 only, on purpose: on IPv4 a shared prefix says nothing about proximity (Go issues 13283, 18518), and a pure function has no subnet masks",
        .explains = ipv4TieGlibcReorders,
    },
    .{
        .name = "follows-from-pairs",
        .why = "a list whose every inversion against glibc is a pair that differs on its own, for one of the reasons above",
        .explains = inversionsArePairDivergences,
    },
    .{
        .name = "not-a-weak-order",
        .why = "RFC 6724's pairwise rules are not transitive. When glibc's own verdicts on the list's pairs (taken in both orders) do not form a strict weak ordering, every sort answers differently: glibc's qsort gives one order, this module's stable insertion sort (the same as Go's for up to 20 entries) another, and no order satisfies every pair",
        .explains = glibcPairsNotWeakOrder,
    },
};

fn isMappedLocalV4(text: []const u8) bool {
    const a = ip(text);
    if (!a.isIpv4Mapped()) return false;
    return a.isLoopback() or a.isLinkLocalUnicast();
}

fn involvesMappedLocalV4(w: vectors.World, in: []const u8, _: []const u8, _: []const u8) bool {
    if (in.len != 2) return false;
    for (in) |x| {
        const e = w.entries[x];
        if (isMappedLocalV4(e.dst)) return true;
        if (e.src) |t| if (isMappedLocalV4(t)) return true;
    }
    return false;
}

fn ipv4TieGlibcReorders(w: vectors.World, in: []const u8, want: []const u8, ours: []const u8) bool {
    if (in.len != 2) return false;
    for (in) |x| {
        const e = w.entries[x];
        if (ip(e.dst) != .v4 or e.src == null) return false;
    }
    // We left the pair as given (a tie through rule 8); glibc swapped it.
    return std.mem.eql(u8, ours, in) and !std.mem.eql(u8, want, in);
}

/// Every pair the two list orders put the other way round is a pair whose
/// own verdict differs from glibc's, explained by a pair-level entry.
fn inversionsArePairDivergences(w: vectors.World, in: []const u8, want: []const u8, ours: []const u8) bool {
    if (in.len < 3) return false;
    for (want, 0..) |x, a| for (want[a + 1 ..]) |y| {
        if (std.mem.indexOfScalar(u8, ours, x).? < std.mem.indexOfScalar(u8, ours, y).?) continue;
        var pair_explained = false;
        for ([2][2]u8{ .{ x, y }, .{ y, x } }) |pin| {
            var got: [2]u8 = undefined;
            ourOrder(w, &pin, &got);
            const k = pairIndex(w.entries.len, pin[0], pin[1]);
            const pw = if (w.pairs[k] == '1') [2]u8{ pin[1], pin[0] } else pin;
            if (std.mem.eql(u8, &got, &pw)) continue;
            if (involvesMappedLocalV4(w, &pin, &pw, &got) or ipv4TieGlibcReorders(w, &pin, &pw, &got))
                pair_explained = true;
        }
        if (!pair_explained) return false;
    };
    return true;
}

fn pairIndex(n: usize, i: usize, j: usize) usize {
    return i * (n - 1) + (if (j > i) j - 1 else j);
}

/// glibc's strict preference: x first whichever order the pair was given in.
fn glibcPrefers(w: vectors.World, x: usize, y: usize) bool {
    const n = w.entries.len;
    return w.pairs[pairIndex(n, x, y)] == '0' and w.pairs[pairIndex(n, y, x)] == '1';
}

fn glibcPairsNotWeakOrder(w: vectors.World, in: []const u8, _: []const u8, _: []const u8) bool {
    if (in.len < 3) return false;
    // A strict weak ordering: preference is transitive and so is
    // indifference (neither preferred). Any violated triple suffices.
    for (in) |a| for (in) |b| for (in) |c| {
        if (a == b or b == c or a == c) continue;
        if (glibcPrefers(w, a, b) and glibcPrefers(w, b, c) and !glibcPrefers(w, a, c)) return true;
        const ind_ab = !glibcPrefers(w, a, b) and !glibcPrefers(w, b, a);
        const ind_bc = !glibcPrefers(w, b, c) and !glibcPrefers(w, c, b);
        const ind_ac = !glibcPrefers(w, a, c) and !glibcPrefers(w, c, a);
        if (ind_ab and ind_bc and !ind_ac) return true;
    };
    return false;
}

fn src(e: vectors.Entry) ?Ip {
    return if (e.src) |t| ip(t) else null;
}

/// Sort the world's entries `idx` with `sortDestinationsWithSources`; write
/// the resulting order of indices into `out`. Destinations within a world are
/// distinct, so each output slot maps back to exactly one input.
fn ourOrder(w: vectors.World, idx: []const u8, out: []u8) void {
    var d: [16]Ip = undefined;
    var s: [16]?Ip = undefined;
    for (idx, 0..) |x, i| {
        d[i] = ip(w.entries[x].dst);
        s[i] = src(w.entries[x]);
    }
    netaddr.sortDestinationsWithSources(d[0..idx.len], s[0..idx.len]) catch unreachable;
    for (d[0..idx.len], out) |dd, *o| {
        for (idx) |x| if (ip(w.entries[x].dst).eql(dd)) {
            o.* = x;
            break;
        };
    }
}

fn explain(w: vectors.World, in: []const u8, want: []const u8, ours: []const u8, hits: []usize) bool {
    for (divergences, 0..) |dv, di| if (dv.explains(w, in, want, ours)) {
        hits[di] += 1;
        return true;
    };
    return false;
}

test "rfc6724 oracle: destination order as glibc gives it (every ordered pair, then longer lists)" {
    var hits = [_]usize{0} ** divergences.len;
    var unexplained: usize = 0;
    var cases: usize = 0;
    var agreed: usize = 0;
    var got: [16]u8 = undefined;
    for (vectors.worlds, 0..) |w, wi| {
        const n = w.entries.len;
        try testing.expectEqual(n * (n - 1), w.pairs.len);
        var k: usize = 0;
        for (0..n) |i| for (0..n) |j| {
            if (i == j) continue;
            defer k += 1;
            cases += 1;
            const in = [2]u8{ @intCast(i), @intCast(j) };
            const want = if (w.pairs[k] == '1') [2]u8{ in[1], in[0] } else in;
            ourOrder(w, &in, got[0..2]);
            if (std.mem.eql(u8, got[0..2], &want)) {
                agreed += 1;
                continue;
            }
            if (explain(w, &in, &want, got[0..2], &hits)) continue;
            unexplained += 1;
            const a = w.entries[want[0]];
            const b = w.entries[want[1]];
            std.debug.print("world {d}: glibc puts {s} (src {?s}) before {s} (src {?s}); we do not\n", .{ wi, a.dst, a.src, b.dst, b.src });
        };
        for (w.lists, 0..) |l, li| {
            cases += 1;
            ourOrder(w, l.in, got[0..l.in.len]);
            if (std.mem.eql(u8, got[0..l.in.len], l.out)) {
                agreed += 1;
                continue;
            }
            if (explain(w, l.in, l.out, got[0..l.in.len], &hits)) continue;
            unexplained += 1;
            std.debug.print("world {d} list {d}: glibc {any}, we {any}\n", .{ wi, li, l.out, got[0..l.in.len] });
        }
    }
    for (divergences, hits) |dv, h| if (h == 0) {
        std.debug.print("divergence '{s}' explains no case any more: delete it\n", .{dv.name});
        unexplained += 1;
    };
    // Most of the evidence must be agreement, not explained difference
    // (2026-10-05: 5906 of 6240 agree; mapped-v4-scope 266, ipv4-rule9 1,
    // follows-from-pairs 65, not-a-weak-order 2).
    if (unexplained != 0 or agreed * 100 < cases * 90) {
        std.debug.print("{d} unexplained, {d} agreed of {d}; explained:", .{ unexplained, agreed, cases });
        for (divergences, hits) |dv, h| std.debug.print(" {s}={d}", .{ dv.name, h });
        std.debug.print("\n", .{});
    }
    try testing.expectEqual(@as(usize, 0), unexplained);
    try testing.expect(agreed * 100 >= cases * 90);
}

test "rfc6724 oracle: IPv6 source as the kernel chooses it" {
    var bad: usize = 0;
    var cases: usize = 0;
    for (vectors.src_sets, 0..) |set, si| {
        var cands: [8]Ip = undefined;
        for (set.cands, 0..) |c, i| cands[i] = ip(c);
        for (set.answers) |a| {
            cases += 1;
            const got = netaddr.selectSource(cands[0..set.cands.len], ip(a.dst));
            if (got != null and std.mem.indexOfScalar(u8, a.ok, @intCast(got.?)) != null) continue;
            bad += 1;
            if (bad <= 40) std.debug.print("set {d} dst {s}: kernel picks {s}, we pick {?d}\n", .{
                si, a.dst, set.cands[a.ok[0]], got,
            });
        }
    }
    if (bad != 0) std.debug.print("{d} of {d} source cases differ\n", .{ bad, cases });
    try testing.expectEqual(@as(usize, 0), bad);
    try testing.expect(cases >= 2000); // 2026-10-05: 160 candidate sets x up to 22 destinations
}
